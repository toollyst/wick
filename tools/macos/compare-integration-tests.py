#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Compares upstream's integration tests on macOS with their results on Linux.

    tools/macos/compare-integration-tests.py OUT [--full] [--summary FILE] [--summary-txt FILE]

OUT comes from tools/macos/integration-tests.sh (test-report.json, mode). The
Linux results are tools/macos/integration-linux-baseline.txt; tests are
matched by pytest node id. Every test that passes on Linux must pass on
macOS, or be listed in tools/macos/integration-test-differences.txt with its
reason. It fails when:

- a test passes on Linux and does not pass on macOS, unlisted;
- a test of a file the run collected passes on Linux and did not run on
  macOS, unlisted;
- a test that exists only on macOS fails, unlisted;
- a listed test passed (the entry is stale), or an entry names no test of a
  file the run collected;
- a file failed to collect (pytest's --continue-on-collection-errors goes
  on without it) and is not listed: its Linux-passing tests count as not
  run, and the file itself is a difference;
- there is no report, or pytest failed without a failing test;
- the run was a diagnostic run (provenance.txt says DIAGNOSTIC RUN:
  integration-tests.sh, WICK_IT_DIAG_MEMORY or WICK_IT_DEFER_MEMORY_ERROR):
  what it shows is to read, not a result.

An entry names a test (a test function, a file) or a failure:
`failure:<exception>` excuses a test that did not pass only because of that
exception: every phase of it that failed (setup, call, teardown) failed with
it. Such an entry cannot be stale for a test that passed; in a full run, a
`bug` entry of either form that excused nothing is reported.

A test entry may carry its cause, a signature, after ` ~ `:
`<mode> <kind> <test> ~ <regex>[ @<file>:<line>]`. The regex is searched in
the crash message of a phase that failed (pytest-json-report), and the
location, if given, is the last traceback entry in the test's own file. A
test listed with a signature is excused only if a failed phase matches it and
every other failed phase matches it or a `failure:` entry; otherwise it is a
problem that names the message and the location it failed with, so a new
cause cannot hide under an old entry. In a full run, a signature that
excused nothing is reported as a `bug` entry is. --suggest-signatures prints
each listed failure's messages and locations, to write signatures from.

    tools/macos/compare-integration-tests.py --selftest
"""

import argparse
import json
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
GOOD = {"passed", "skipped", "xfailed"}
KINDS = ("bug", "arch", "root", "impossible")


def baseline(path=None):
    out = {}
    for line in (path or HERE / "integration-linux-baseline.txt").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            outcome, nodeid = line.split(None, 1)
            out[nodeid] = outcome
    return out


def matches(nodeid, entry):
    """An entry names a test, a test function with all its parameters, or a file."""
    return (
        nodeid == entry
        or nodeid.startswith(entry + "[")
        or nodeid.startswith(entry + "::")
    )


def parse_signature(text, where):
    """(compiled regex, (file, line) or None) of a signature's text."""
    loc = None
    m = re.search(r" @([\w.-]+\.py):(\d+)$", text)
    if m:
        loc = (m.group(1), int(m.group(2)))
        text = text[: m.start()]
    try:
        return re.compile(text.strip()), loc
    except re.error as e:
        raise SystemExit(f"{where}: signature is not a regex ({e}): {text}")


def signature_text(sig):
    regex, loc = sig
    return regex.pattern + (f" @{loc[0]}:{loc[1]}" if loc else "")


def differences(mode, path=None):
    """(entry, kind, reason, signature or None) for the entries that apply to
    `mode`."""
    path = path or HERE / "integration-test-differences.txt"
    entries, reason = [], []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#"):
            text = line.lstrip("#").strip()
            if not text:
                reason = []
            elif not text.startswith("Copyright") and not text.startswith("SPDX"):
                reason.append(text)
            continue
        if not line:
            reason = []  # a blank line ends a comment: the header is no reason
            continue
        m, kind, entry = line.split(None, 2)
        if m not in ("all", "user", "jailer"):
            raise SystemExit(f"{path.name}: mode must be all, user or jailer: {raw}")
        if kind not in KINDS and not kind.startswith("row-"):
            raise SystemExit(f"{path.name}: kind must be {', '.join(KINDS)} or row-N: {raw}")
        if not reason:
            raise SystemExit(f"{path.name}: no reason above {raw}")
        sig = None
        if " ~ " in entry:
            entry, text = entry.split(" ~ ", 1)
            if entry.strip().startswith("failure:"):
                raise SystemExit(f"{path.name}: a failure: entry takes no signature: {raw}")
            sig = parse_signature(text, path.name)
        if m in ("all", mode):
            entries.append((entry.strip(), kind, " ".join(reason), sig))
    return entries


def failed_phases(test):
    """(phase, crash message, (file, line) or None) of each phase of a test of
    pytest-json-report that failed; the location is the last traceback entry
    in the test's own file."""
    own = test["nodeid"].split("::", 1)[0]
    out = []
    for phase in ("setup", "call", "teardown"):
        p = test.get(phase, {})
        if p.get("outcome") != "failed":
            continue
        loc = None
        for tb in p.get("traceback") or []:
            if tb.get("path") == own or str(tb.get("path", "")).endswith("/" + own):
                loc = (Path(own).name, tb.get("lineno"))
        out.append((phase, (p.get("crash") or {}).get("message", ""), loc))
    return out


def signature_matches(sig, message, loc):
    regex, want = sig
    return bool(regex.search(message)) and (want is None or want == loc)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("out", type=Path)
    ap.add_argument(
        "--full",
        action="store_true",
        help="the run was upstream's whole functional and security suites: a test of a file "
        "it ran that has a Linux result and did not run is a difference",
    )
    ap.add_argument("--summary", type=Path)
    ap.add_argument("--summary-txt", type=Path)
    ap.add_argument("--differences", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--baseline", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--suggest-signatures", action="store_true",
                    help="print each listed failure's messages and locations, to write signatures from")
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    return run(ap.parse_args())


def selftest():
    """The signature rules on synthetic reports (design: agent-state's
    compare-signatures-design.md, point 5)."""
    T = "integration_tests/functional/test_x.py"

    def phase(message, line):
        return {"outcome": "failed", "crash": {"message": message},
                "traceback": [{"path": T, "lineno": line, "message": "in test_a"},
                              {"path": "framework/microvm.py", "lineno": 9, "message": "in kill"}]}

    def report(**ph):
        t = {"nodeid": f"{T}::test_a", "outcome": "failed", "setup": {"outcome": "passed"},
             "call": {"outcome": "passed"}, "teardown": {"outcome": "passed"}}
        t.update(ph)
        return {"tests": [t], "collectors": []}

    entry = f"all row-6 {T}::test_a ~ DID NOT RAISE.*RuntimeError @test_x.py:395"
    mem = "all bug failure:MemoryUsageExceededError"
    cases = [
        ("same id, listed cause", [entry], report(call=phase("Failed: DID NOT RAISE <class 'RuntimeError'>", 395)), 0),
        ("same id, other message", [entry], report(call=phase("RemoteDisconnected: Remote end closed", 395)), 1),
        ("same id, right message, wrong line", [entry],
         report(call=phase("Failed: DID NOT RAISE <class 'RuntimeError'>", 401)), 1),
        ("call matched, teardown memory error", [entry, mem],
         report(call=phase("Failed: DID NOT RAISE <class 'RuntimeError'>", 395),
                teardown=phase("MemoryUsageExceededError: 5.2 MiB", 12)), 0),
        ("call matched, teardown another error", [entry, mem],
         report(call=phase("Failed: DID NOT RAISE <class 'RuntimeError'>", 395),
                teardown=phase("ProcessLookupError: no such process", 12)), 1),
        ("teardown only, entry for the call", [entry, mem],
         report(teardown=phase("MemoryUsageExceededError: 5.2 MiB", 12)), 1),
        ("no signature: the id alone", [f"all row-6 {T}::test_a"],
         report(call=phase("RemoteDisconnected: Remote end closed", 395)), 0),
    ]
    fails = 0
    for name, entries, rep, want in cases:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "test-report.json").write_text(json.dumps(rep))
            (d / "status").write_text("1\n")
            (d / "mode").write_text("user\n")
            (d / "differences.txt").write_text("".join(f"# reason\n{e}\n\n" for e in entries))
            (d / "baseline.txt").write_text(f"passed {T}::test_a\n")
            ns = argparse.Namespace(out=d, full=False, summary=None, summary_txt=d / "summary.txt",
                                    differences=d / "differences.txt", baseline=d / "baseline.txt",
                                    suggest_signatures=False)
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()):
                run(ns)
            got = int((d / "summary.txt").read_text().splitlines()[1].split(", ")[1].split()[0])
            if got != want:
                fails += 1
                print(f"selftest FAIL: {name}: {got} problem(s), wanted {want}")
    if fails:
        return 1
    print(f"selftest: ok ({len(cases)} cases)")
    return 0


def run(args):
    mode = (args.out / "mode").read_text().strip() if (args.out / "mode").exists() else "user"

    problems = []
    provenance = args.out / "provenance.txt"
    if provenance.exists():
        problems += [
            f"{line.strip()} (provenance.txt)"
            for line in provenance.read_text(encoding="utf-8").splitlines()
            if line.startswith("DIAGNOSTIC RUN")
        ]
    report = args.out / "test-report.json"
    mac = {}
    failures = {}  # node id: the crash message of each phase that failed
    phases = {}  # node id: failed_phases()
    uncollected = {}  # a file that failed to collect: the last line of its error
    if report.exists():
        data = json.loads(report.read_text())
        for c in data.get("collectors", []):
            if c.get("outcome") == "failed" and c.get("nodeid", "").endswith(".py"):
                lines = [ln for ln in str(c.get("longrepr", "")).splitlines() if ln.strip()]
                uncollected[c["nodeid"]] = lines[-1].strip().removeprefix("E").strip() if lines else "no error text"
        for t in data["tests"]:
            mac[t["nodeid"]] = t["outcome"]
            phases[t["nodeid"]] = failed_phases(t)
            failures[t["nodeid"]] = [msg for _, msg, _ in phases[t["nodeid"]]]
    else:
        problems.append("no test-report.json")
    linux = baseline(args.baseline)
    listed = differences(mode, args.differences)
    files = {n.split("::", 1)[0] for n in mac} | set(uncollected)

    def entry_for(nodeid):
        for e in listed:
            if e[0].startswith("failure:"):
                continue
            if matches(nodeid, e[0]):
                return e
        return None

    def failure_entry_for(nodeid):
        """The failure entry that excuses a test that did not pass, if any."""
        msgs = failures.get(nodeid)
        if not msgs:
            return None
        for e in listed:
            if e[0].startswith("failure:"):
                exc = e[0][len("failure:"):]
                if all(m.startswith(exc + ":") or m == exc for m in msgs):
                    return e
        return None

    def failure_entry_for_message(msg):
        for e in listed:
            if e[0].startswith("failure:"):
                exc = e[0][len("failure:"):]
                if msg.startswith(exc + ":") or msg == exc:
                    return e
        return None

    def explained(nodeid, e, mo):
        """None if entry `e` (with a signature) excuses the test that did not
        pass, else the problem. Each failed phase must match the signature
        or a failure: entry, and one must match the signature."""
        got = phases.get(nodeid, [])
        sig = e[3]
        if not got:
            return f"{nodeid}: listed ({e[1]}) for '{signature_text(sig)}', but {mo} with no failed phase"
        hit = False
        for phase, msg, loc in got:
            if signature_matches(sig, msg, loc):
                hit = True
            elif failure_entry_for_message(msg) is None:
                at = f"{loc[0]}:{loc[1]}" if loc else "no line in the test's file"
                first = msg.splitlines()[0] if msg else "no message"
                return (f"{nodeid}: listed ({e[1]}) for '{signature_text(sig)}', but its {phase} failed with "
                        f"'{first}' at {at}")
        if not hit:
            return f"{nodeid}: listed ({e[1]}) for '{signature_text(sig)}', but no phase failed so"
        return None

    if args.suggest_signatures:
        for nodeid in sorted(phases):
            e = entry_for(nodeid)
            if e is None or not phases[nodeid]:
                continue
            print(f"{nodeid}  [{e[1]} {e[0]}" + (f" ~ {signature_text(e[3])}" if e[3] else "") + "]")
            for phase, msg, loc in phases[nodeid]:
                at = f" @{loc[0]}:{loc[1]}" if loc else ""
                print(f"    {phase}: {(msg.splitlines() or [''])[0][:200]}{at}")
        return 0

    excused = defaultdict(list)
    used = set()
    agree = 0
    for nodeid, lo in sorted(linux.items()):
        if nodeid.split("::", 1)[0] not in files:
            continue
        if nodeid not in mac and not args.full and nodeid.split("::", 1)[0] not in uncollected:
            continue
        mo = mac.get(nodeid, "not run")
        e = entry_for(nodeid)
        if e is None and mo not in GOOD:
            e = failure_entry_for(nodeid)
        if lo != "passed":
            if mo == "passed" or mo in GOOD:
                agree += 1
            elif e:
                why = explained(nodeid, e, mo) if e[3] else None
                if why:
                    problems.append(why)
                else:
                    used.add(e[0])
                    excused[e].append(f"{nodeid}: {mo} (Linux: {lo})")
            else:
                agree += 1  # what fails on Linux is not compared
            continue
        if mo == "passed":
            agree += 1
            if e and e[1] != "arch":
                problems.append(f"{nodeid}: passes, but listed ({e[1]}): remove the entry")
            continue
        if e:
            why = explained(nodeid, e, mo) if e[3] else None
            if why:
                problems.append(why)
            else:
                used.add(e[0])
                excused[e].append(f"{nodeid}: {mo}")
        else:
            problems.append(f"{nodeid}: passes on Linux, {mo} on macOS")
    for nodeid, mo in sorted(mac.items()):
        if nodeid in linux:
            continue
        e = entry_for(nodeid)
        if e is None and mo not in GOOD:
            e = failure_entry_for(nodeid)
        if mo in GOOD:
            agree += 1
            if e and mo == "passed" and e[1] != "arch":
                problems.append(f"{nodeid}: passes, but listed ({e[1]}): remove the entry")
        elif e:
            why = explained(nodeid, e, mo) if e[3] else None
            if why:
                problems.append(why)
            else:
                used.add(e[0])
                excused[e].append(f"{nodeid}: {mo} (no Linux result)")
        else:
            problems.append(f"{nodeid}: {mo} on macOS, no Linux result")
    for entry, kind, _, sig in listed:
        module = entry.split("::", 1)[0]
        if not args.full:
            continue
        if entry.startswith("failure:"):
            if kind == "bug" and entry not in used:
                problems.append(f"entry '{entry}' (bug) matched nothing that failed")
            continue
        if module in files and not any(matches(n, entry) for n in list(mac) + list(linux)):
            problems.append(f"entry '{entry}' ({kind}) names no test")
        elif module in files and entry not in used and kind == "bug":
            problems.append(f"entry '{entry}' (bug) matched nothing that failed")
        elif module in files and entry not in used and sig:
            problems.append(f"entry '{entry}' ({kind}) for '{signature_text(sig)}' excused nothing")

    for path, why in sorted(uncollected.items()):
        e = entry_for(path)
        if e:
            used.add(e[0])
        else:
            problems.append(f"{path}: failed to collect ({why}), unlisted")

    status = (args.out / "status").read_text().strip() if (args.out / "status").exists() else "?"
    if status not in ("0", "1") and not problems:
        problems.append(f"pytest exited with {status}")

    c = Counter(mac.values())
    lines = [f"## Upstream's integration tests on macOS ({mode} mode) against Linux", ""]
    lines.append("| | " + " | ".join(("passed", "failed", "error", "skipped")) + " |")
    lines.append("|---|---|---|---|---|")
    lines.append("| macOS | " + " | ".join(str(c[k]) for k in ("passed", "failed", "error", "skipped")) + " |")
    lc = Counter(o for n, o in linux.items() if n.split("::", 1)[0] in files)
    lines.append("| Linux, same files | " + " | ".join(str(lc[k]) for k in ("passed", "failed", "error", "skipped")) + " |")
    lines.append("")
    if uncollected:
        lines.append(f"### Files that failed to collect ({len(uncollected)})")
        for path, why in sorted(uncollected.items()):
            e = entry_for(path)
            lines.append(f"- `{path}`: {why}" + (f" (listed: {e[1]})" if e else " (unlisted)"))
        lines.append("")
    by_kind = defaultdict(list)
    for e, items in excused.items():
        by_kind[e[1]].append((e, items))
    for kind in sorted(by_kind):
        n = sum(len(i) for _, i in by_kind[kind])
        lines.append(f"### Listed: {kind} ({n})")
        for (entry, _, reason, _), items in by_kind[kind]:
            lines.append(f"- `{entry}` ({len(items)}): {reason}")
        lines.append("")
    if problems:
        lines.append(f"**{len(problems)} problem(s):**")
        lines += [f"- {p}" for p in problems]
    else:
        lines.append("Every test that passes on Linux passes on macOS or is listed with its reason.")
    text = "\n".join(lines) + "\n"
    print(text)
    if args.summary:
        args.summary.write_text(text, encoding="utf-8")
    if args.summary_txt:
        args.summary_txt.write_text(
            "pytest: " + ", ".join(f"{v} {k}" for k, v in sorted(c.items())) + "\n"
            f"{agree} passed, {len(problems)} failed\n",
            encoding="utf-8",
        )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
