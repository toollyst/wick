#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Compares wick's integration test results with those of plain upstream.

    tools/linux/compare-integration-tests.py UPSTREAM_OUT WICK_OUT [--summary FILE]

Both directories come from tools/linux/integration-tests.sh, run with the same
pytest arguments on the same machine; tests are matched by pytest node id. It
fails when:

- a test passes on upstream and does not pass on wick (a wick regression),
- a test upstream ran is missing from wick's run,
- a test fails on upstream too but is not in
  tools/linux/integration-test-exclusions.txt,
- an exclusion names no test of a file the run ran,
- either run has no report, or pytest failed without a failing test.

Excluded tests still run in both: their results are listed, a failure on
upstream is expected, and a pass on upstream with a failure on wick is still
a regression.
"""

import argparse
import json
import platform
import sys
from collections import Counter
from pathlib import Path

GOOD = {"passed", "skipped", "xfailed"}


def load(out):
    path = out / "test-report.json"
    if not path.exists():
        return None
    report = json.loads(path.read_text(encoding="utf-8"))
    return {t["nodeid"]: t["outcome"] for t in report.get("tests", [])}


def matches(nodeid, entry):
    """An entry names a test, or a test function with all its parameters."""
    return nodeid == entry or nodeid.startswith(entry + "[") or nodeid.startswith(entry + "::")


def exclusions(arch):
    path = Path(__file__).with_name("integration-test-exclusions.txt")
    ids = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            a, nodeid = line.split(None, 1)
            if a in ("all", arch):
                ids.append(nodeid.strip())
    return ids


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("upstream", type=Path)
    ap.add_argument("wick", type=Path)
    ap.add_argument("--summary", type=Path)
    args = ap.parse_args()
    arch_file = args.wick / "arch"
    arch = arch_file.read_text().strip() if arch_file.exists() else platform.machine()

    problems, notes, excused = [], [], []
    up = load(args.upstream)
    wk = load(args.wick)
    if up is None or wk is None:
        problems.append(
            "no test-report.json from "
            + " and ".join(n for n, r in (("upstream", up), ("wick", wk)) if r is None)
        )
        up, wk = up or {}, wk or {}
    excluded = exclusions(arch)

    for nodeid, us in sorted(up.items()):
        ws = wk.get(nodeid)
        if ws is None:
            problems.append(f"{nodeid}: {us} on upstream, missing from wick's run")
        elif us == "passed" and ws != "passed":
            problems.append(f"REGRESSION {nodeid}: passed on upstream, {ws} on wick")
        elif us not in GOOD and any(matches(nodeid, e) for e in excluded):
            excused.append(f"{nodeid}: {us} on upstream, {ws} on wick")
        elif us not in GOOD and ws not in GOOD:
            problems.append(
                f"{nodeid}: {us} on upstream, {ws} on wick: an environment failure; "
                "explain it in tools/linux/integration-test-exclusions.txt"
            )
        elif us not in GOOD:
            notes.append(f"{nodeid}: {us} on upstream, {ws} on wick")
        elif us != ws:
            (problems if ws not in GOOD else notes).append(
                f"{nodeid}: {us} on upstream, {ws} on wick"
            )
    for nodeid, ws in sorted(wk.items()):
        if nodeid not in up and ws not in GOOD:
            problems.append(f"{nodeid}: {ws} on wick, not run on upstream")

    for e in excluded:
        # Only entries for test files this run ran (the subset leaves some out).
        module = e.split("::", 1)[0]
        if any(n.startswith(module + "::") for n in up) and not any(matches(n, e) for n in up):
            problems.append(f"exclusion '{e}' ({arch}) names no test that ran")

    for who, out, results in (("upstream", args.upstream, up), ("wick", args.wick, wk)):
        status = (out / "status").read_text().strip() if (out / "status").exists() else "?"
        if status != "0" and all(s in GOOD for s in results.values()):
            problems.append(f"{who}: pytest exited with {status} but no test failed")

    lines = [f"## Integration tests on {arch}: wick vs upstream", ""]
    lines.append("| | " + " | ".join(("passed", "failed", "error", "skipped", "xfailed")) + " |")
    lines.append("|---|---|---|---|---|---|")
    for who, results in (("upstream", up), ("wick", wk)):
        c = Counter(results.values())
        lines.append(
            f"| {who} | "
            + " | ".join(str(c[k]) for k in ("passed", "failed", "error", "skipped", "xfailed"))
            + " |"
        )
    lines.append("")
    if excused:
        lines.append(
            "Failing on plain upstream on this runner, explained in "
            f"tools/linux/integration-test-exclusions.txt ({len(excused)}):"
        )
        lines += [f"- {n}" for n in excused]
        lines.append("")
    if notes:
        lines.append(f"Notes ({len(notes)}):")
        lines += [f"- {n}" for n in notes]
        lines.append("")
    if problems:
        lines.append(f"**{len(problems)} problem(s):**")
        lines += [f"- {p}" for p in problems]
    else:
        lines.append("No differences: every test has upstream's result on wick.")
    text = "\n".join(lines) + "\n"
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(text)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
