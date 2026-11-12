#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Per upstream test file: Linux's results and the differences each host lists.

    python3 -I tools/compat-counts.py                       # print the table
    python3 -I tools/compat-counts.py --check docs/COMPATIBILITY.md
    python3 -I tools/compat-counts.py --write docs/COMPATIBILITY.md

It reads the Linux results (tools/macos/integration-linux-baseline.txt) and
the differences files (tools/macos/integration-test-differences.txt,
tools/windows/integration-test-differences.txt), and matches entries to
tests as tools/macos/compare-integration-tests.py and
tools/windows/compare-integration-tests.py do: an entry names a test, a test
function with all its parameters, or a file, and a test takes the first
entry that names it.

The table counts the Linux-passing tests an entry names, by kind. It is a
count of listed differences, not a measured pass rate: no run report is
committed. A `failure:<exception>` entry names no test (it excuses whatever
fails only with that exception), so it is a footnote, never a count.

--check FILE fails when the table between FILE's
<!-- compat-counts:begin --> and <!-- compat-counts:end --> markers is not
what this prints; --write FILE replaces it.
"""

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tools/macos/integration-linux-baseline.txt"
MACOS = ROOT / "tools/macos/integration-test-differences.txt"
WINDOWS = ROOT / "tools/windows/integration-test-differences.txt"
BEGIN = "<!-- compat-counts:begin -->"
END = "<!-- compat-counts:end -->"
PREFIX = "integration_tests/"

# The mode of macOS's differences file the counts are for: the functional
# suites have run as the user (docs/PORTING.md row 12), not as root.
MACOS_MODE = "user"

# Suites a host has not run in full (docs/PORTING.md row 12, "To do"). Their
# cells say so, rather than a 0 that would read as "no difference".
NOT_RUN = {
    "macOS": ("integration_tests/security/",),
    "Windows": (),
}


def baseline():
    out = {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            outcome, nodeid = line.split(None, 1)
            out[nodeid.strip()] = outcome
    return out


def macos_entries():
    """(entry, kind, mode) of the macOS file, in order (its comparator's parsing)."""
    entries, reason = [], []
    for raw in MACOS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#"):
            text = line.lstrip("#").strip()
            if not text:
                reason = []
            elif not text.startswith("Copyright") and not text.startswith("SPDX"):
                reason.append(text)
            continue
        if not line:
            reason = []
            continue
        mode, kind, entry = line.split(None, 2)
        if mode not in ("all", "user", "jailer"):
            raise SystemExit(f"{MACOS.name}: mode must be all, user or jailer: {raw}")
        if not reason:
            raise SystemExit(f"{MACOS.name}: no reason above {raw}")
        entries.append((entry.strip(), kind, mode))
    return entries


def windows_entries():
    """(entry, kind, "all") of the Windows file, in order (its comparator's parsing)."""
    entries, reason, in_comment = [], [], False
    for raw in WINDOWS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#"):
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
        if not reason:
            raise SystemExit(f"{WINDOWS.name}: no reason above {raw}")
        entries.append((entry.strip(), kind, "all"))
    return entries


def matches(nodeid, entry):
    return nodeid == entry or nodeid.startswith(entry + "[") or nodeid.startswith(entry + "::")


def module(nodeid):
    return nodeid.split("::", 1)[0]


def kinds_cell(counter):
    if not counter:
        return "–"
    parts = ", ".join(f"{k} {counter[k]}" for k in sorted(counter))
    return f"{sum(counter.values())} ({parts})"


def tally(host, entries, linux):
    """Per file, the kinds of the Linux-passing tests listed; and the footnotes."""
    named = [e for e in entries if not e[0].startswith("failure:")]
    per_file = defaultdict(Counter)
    not_passing = Counter()
    hit = set()
    for nodeid, outcome in linux.items():
        e = next((e for e in named if matches(nodeid, e[0])), None)
        if e is None:
            continue
        hit.add(e[0])
        if outcome == "passed":
            per_file[module(nodeid)][e[1]] += 1
        else:
            not_passing[outcome] += 1
    notes = []
    for entry, kind, _ in entries:
        if entry.startswith("failure:"):
            notes.append(
                f"{host}: `{entry}` ({kind}) excuses any test whose every failing phase failed with "
                "that exception, in any file; the tests it excuses are not counted above."
            )
    unmatched = [e for e in named if e[0] not in hit]
    for entry, kind, _ in unmatched:
        notes.append(f"{host}: `{entry}` ({kind}) names no test with a Linux result.")
    if not_passing:
        parts = ", ".join(f"{n} {o}" for o, n in sorted(not_passing.items()))
        notes.append(f"{host}: entries also name tests Linux did not pass ({parts}); not counted.")
    return per_file, notes


def table():
    linux = baseline()
    mac = [e for e in macos_entries() if e[2] in ("all", MACOS_MODE)]
    mac_other = [e for e in macos_entries() if e[2] not in ("all", MACOS_MODE)]
    win = windows_entries()
    mac_files, mac_notes = tally("macOS", mac, linux)
    win_files, win_notes = tally("Windows", win, linux)

    outcomes = defaultdict(Counter)
    for nodeid, outcome in linux.items():
        outcomes[module(nodeid)][outcome] += 1

    def cell(host, files, name):
        if any(name.startswith(p) for p in NOT_RUN[host]):
            return "not run"
        return kinds_cell(files.get(name, Counter()))

    lines = [
        "| Upstream test file | Linux passed | Linux skipped | Linux failed "
        "| macOS: Linux-passing tests listed | Windows: Linux-passing tests listed |",
        "| --- | ---: | ---: | ---: | --- | --- |",
    ]
    total = Counter()
    for name in sorted(outcomes):
        o = outcomes[name]
        total.update(o)
        lines.append(
            f"| `{name[len(PREFIX):] if name.startswith(PREFIX) else name}` | {o['passed']} | {o['skipped']} "
            f"| {o['failed']} | {cell('macOS', mac_files, name)} | {cell('Windows', win_files, name)} |"
        )

    def host_total(host, files):
        c = Counter()
        for name, k in files.items():
            if not any(name.startswith(p) for p in NOT_RUN[host]):
                c.update(k)
        return kinds_cell(c)

    lines.append(
        f"| **Total** | **{total['passed']}** | **{total['skipped']}** | **{total['failed']}** "
        f"| **{host_total('macOS', mac_files)}** | **{host_total('Windows', win_files)}** |"
    )
    notes = mac_notes + win_notes
    notes.append(
        f"macOS: counts are for `{MACOS_MODE}` mode (`tools/macos/integration-tests.sh` without `--jailer`)"
        + (f"; {len(mac_other)} entries for other modes are left out." if mac_other else
           "; the file has no entry for other modes.")
    )
    for host, prefixes in NOT_RUN.items():
        for p in prefixes:
            notes.append(f"{host}: `{p[len(PREFIX):]}` has not been run (docs/PORTING.md row 12), so it has no count.")
    notes.append(
        "An entry for a test function names all its parameters. Windows' comparator lets some of them pass "
        "(macOS' only for `arch`), so a Windows count is an upper bound on the tests that did not pass."
    )
    lines.append("")
    lines += [f"- {n}" for n in notes]
    return "\n".join(lines) + "\n"


def embedded(path):
    text = path.read_text(encoding="utf-8")
    try:
        head, rest = text.split(BEGIN, 1)
        body, tail = rest.split(END, 1)
    except ValueError:
        raise SystemExit(f"{path}: no {BEGIN} ... {END} markers")
    return head, body, tail


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--check", type=Path, metavar="FILE", help="fail if FILE's embedded table is stale")
    group.add_argument("--write", type=Path, metavar="FILE", help="replace FILE's embedded table")
    args = ap.parse_args()
    out = table()
    if args.check:
        _, body, _ = embedded(args.check)
        if body.strip() != out.strip():
            print(f"{args.check}: the integration test counts are stale; run "
                  f"python3 -I tools/compat-counts.py --write {args.check}", file=sys.stderr)
            return 1
        print(f"{args.check}: integration test counts are current")
        return 0
    if args.write:
        head, _, tail = embedded(args.write)
        args.write.write_text(f"{head}{BEGIN}\n{out}{END}{tail}", encoding="utf-8")
        return 0
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
