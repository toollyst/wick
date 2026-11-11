#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Compares upstream's integration tests on Windows with their results on Linux.

    python -I tools/windows/compare-integration-tests.py OUT [--full] [--summary FILE] [--summary-txt FILE]

OUT comes from tools/windows/integration-tests.ps1 (test-report.json,
status). The Linux results are tools/macos/integration-linux-baseline.txt
(Linux on x86_64, as this host); tests are matched by pytest node id. Every
test that passes on Linux must pass on Windows, or be listed in
tools/windows/integration-test-differences.txt with its reason. It fails
when:

- a test passes on Linux and does not pass on Windows, unlisted;
- a test of a file the run collected passes on Linux and did not run on
  Windows, unlisted (--full);
- a test that exists only on Windows fails, unlisted;
- a listed test passed (the entry is stale), or an entry names no test of a
  file the run collected (--full);
- there is no report, or pytest failed without a failing test.

The same rules as tools/macos/compare-integration-tests.py, for Windows.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASELINE = HERE.parent / "macos" / "integration-linux-baseline.txt"
DIFFERENCES = HERE / "integration-test-differences.txt"
GOOD = {"passed", "skipped", "xfailed"}
KINDS = ("bug", "impossible", "error-text")


def baseline():
    out = {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            outcome, nodeid = line.split(None, 1)
            out[nodeid] = outcome
    return out


def matches(nodeid, entry):
    """An entry names a test, a test function with all its parameters, or a file."""
    return nodeid == entry or nodeid.startswith(entry + "[") or nodeid.startswith(entry + "::")


def differences():
    """(entry, kind, reason) for each entry."""
    entries, reason, in_comment = [], [], False
    for raw in DIFFERENCES.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#"):
            # A comment block starts a reason; the header is a block too.
            if not in_comment:
                reason = []
            in_comment = True
            text = line.lstrip("#").strip()
            if text and not text.startswith("Copyright") and not text.startswith("SPDX"):
                reason.append(text)
            continue
        in_comment = False
        if not line:
            reason = []
            continue
        kind, entry = line.split(None, 1)
        if kind not in KINDS and not kind.startswith("row-"):
            raise SystemExit(f"{DIFFERENCES.name}: kind must be {', '.join(KINDS)} or row-N: {raw}")
        if not reason:
            raise SystemExit(f"{DIFFERENCES.name}: no reason above {raw}")
        entries.append((entry.strip(), kind, " ".join(reason)))
    return entries


def main():  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("out", type=Path)
    ap.add_argument("--full", action="store_true",
                    help="the run was upstream's whole functional and security suites")
    ap.add_argument("--summary", type=Path)
    ap.add_argument("--summary-txt", type=Path)
    args = ap.parse_args()

    problems = []
    report = args.out / "test-report.json"
    win = {}
    if report.exists():
        win = {t["nodeid"]: t["outcome"] for t in json.loads(report.read_text(encoding="utf-8"))["tests"]}
    else:
        problems.append("no test-report.json")
    linux = baseline()
    listed = differences()
    files = {n.split("::", 1)[0] for n in win}

    def entry_for(nodeid):
        return next((e for e in listed if matches(nodeid, e[0])), None)

    excused = defaultdict(list)
    used = set()
    agree = 0
    for nodeid, lo in sorted(linux.items()):
        if nodeid.split("::", 1)[0] not in files or (nodeid not in win and not args.full):
            continue
        wo = win.get(nodeid, "not run")
        e = entry_for(nodeid)
        if lo != "passed":
            if wo in GOOD or not e:
                agree += 1  # what does not pass on Linux is not compared
            else:
                used.add(e[0])
                excused[e].append(f"{nodeid}: {wo} (Linux: {lo})")
            continue
        if wo == "passed":
            agree += 1
            if e:
                problems.append(f"{nodeid}: passes, but listed ({e[1]}): remove the entry")
        elif e:
            used.add(e[0])
            excused[e].append(f"{nodeid}: {wo}")
        else:
            problems.append(f"{nodeid}: passes on Linux, {wo} on Windows")
    for nodeid, wo in sorted(win.items()):
        if nodeid in linux:
            continue
        e = entry_for(nodeid)
        if wo in GOOD:
            agree += 1
            if e and wo == "passed":
                problems.append(f"{nodeid}: passes, but listed ({e[1]}): remove the entry")
        elif e:
            used.add(e[0])
            excused[e].append(f"{nodeid}: {wo} (no Linux result)")
        else:
            problems.append(f"{nodeid}: {wo} on Windows, no Linux result")
    if args.full:
        for entry, kind, _ in listed:
            module = entry.split("::", 1)[0]
            if module in files and not any(matches(n, entry) for n in list(win) + list(linux)):
                problems.append(f"entry '{entry}' ({kind}) names no test")
            elif module in files and entry not in used and kind == "bug":
                problems.append(f"entry '{entry}' (bug) matched nothing that failed")

    status = (args.out / "status").read_text().strip() if (args.out / "status").exists() else "?"
    if status not in ("0", "1") and not problems:
        problems.append(f"pytest exited with {status}")

    c = Counter(win.values())
    cols = ("passed", "failed", "error", "skipped")
    lines = ["## Upstream's integration tests on Windows against Linux", ""]
    lines.append("| | " + " | ".join(cols) + " |")
    lines.append("|---|---|---|---|---|")
    lines.append("| Windows | " + " | ".join(str(c[k]) for k in cols) + " |")
    lc = Counter(o for n, o in linux.items() if n.split("::", 1)[0] in files)
    lines.append("| Linux, same files | " + " | ".join(str(lc[k]) for k in cols) + " |")
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
        lines.append("Every test that passes on Linux passes on Windows or is listed with its reason.")
    text = "\n".join(lines) + "\n"
    sys.stdout.reconfigure(encoding="utf-8")
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
