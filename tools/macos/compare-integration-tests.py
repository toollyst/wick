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
- there is no report, or pytest failed without a failing test.

An entry names a test (a test function, a file) or a failure:
`failure:<exception>` excuses a test that did not pass only because of that
exception: every phase of it that failed (setup, call, teardown) failed with
it. Such an entry cannot be stale for a test that passed; in a full run, a
`bug` entry of either form that excused nothing is reported.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
GOOD = {"passed", "skipped", "xfailed"}
KINDS = ("bug", "arch", "root", "impossible")


def baseline():
    out = {}
    for line in (HERE / "integration-linux-baseline.txt").read_text(encoding="utf-8").splitlines():
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


def differences(mode):
    """(mode, entry, kind, reason) for the entries that apply to `mode`."""
    path = HERE / "integration-test-differences.txt"
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
        if m in ("all", mode):
            entries.append((entry.strip(), kind, " ".join(reason)))
    return entries


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
    args = ap.parse_args()
    mode = (args.out / "mode").read_text().strip() if (args.out / "mode").exists() else "user"

    problems = []
    report = args.out / "test-report.json"
    mac = {}
    failures = {}  # node id: the crash message of each phase that failed
    if report.exists():
        for t in json.loads(report.read_text())["tests"]:
            mac[t["nodeid"]] = t["outcome"]
            failures[t["nodeid"]] = [
                (t[phase].get("crash") or {}).get("message", "")
                for phase in ("setup", "call", "teardown")
                if t.get(phase, {}).get("outcome") == "failed"
            ]
    else:
        problems.append("no test-report.json")
    linux = baseline()
    listed = differences(mode)
    files = {n.split("::", 1)[0] for n in mac}

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

    excused = defaultdict(list)
    used = set()
    agree = 0
    for nodeid, lo in sorted(linux.items()):
        if nodeid.split("::", 1)[0] not in files:
            continue
        if nodeid not in mac and not args.full:
            continue
        mo = mac.get(nodeid, "not run")
        e = entry_for(nodeid)
        if e is None and mo not in GOOD:
            e = failure_entry_for(nodeid)
        if lo != "passed":
            if mo == "passed" or mo in GOOD:
                agree += 1
            elif e:
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
            used.add(e[0])
            excused[e].append(f"{nodeid}: {mo} (no Linux result)")
        else:
            problems.append(f"{nodeid}: {mo} on macOS, no Linux result")
    for entry, kind, _ in listed:
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
    by_kind = defaultdict(list)
    for e, items in excused.items():
        by_kind[e[1]].append((e, items))
    for kind in sorted(by_kind):
        n = sum(len(i) for _, i in by_kind[kind])
        lines.append(f"### Listed: {kind} ({n})")
        for (entry, _, reason), items in by_kind[kind]:
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
