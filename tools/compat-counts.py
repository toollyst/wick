#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The generated parts of docs/COMPATIBILITY.md: progress per host, and per
upstream test file Linux's results and the differences each host lists.

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
fails only with that exception), so its reason must say how many tests it
excused in which run, in a comment line of its own, which the comparators
ignore:

    # excused: 19 (run m2-parts at 8d577b7): pass their own assertions and fail only the memory budget of the VMM's own part
    # excused: at least 19 (run m2-parts at 8d577b7): ...

the number from that run's comparison.md, "at least" when the run was not
the full suites. The progress block takes them out of the tests that agree
(so its count is then "at most"), and both blocks say how many and why.
Without the line, every mode fails.

The progress block counts the status icons of every feature table in the
document (a table with macOS and Windows columns): each cell must start with
one of 🟢 🟡 🔴 ⚪ ❔, and a 🔴 cell must say whether the host cannot do it
("impossible") or it is "not done yet". A host's progress is the rows that
work (🟢 or 🟡) out of the rows it can do: all rows but the ⚪ and the
impossible ones. Untested (❔) and not done yet rows count against it.

--check FILE fails when a block between FILE's markers
(<!-- compat-progress:begin --> ... end, <!-- compat-counts:begin --> ...
end) is not what this makes of FILE; --write FILE replaces them.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tools/macos/integration-linux-baseline.txt"
MACOS = ROOT / "tools/macos/integration-test-differences.txt"
WINDOWS = ROOT / "tools/windows/integration-test-differences.txt"
BEGIN = "<!-- compat-counts:begin -->"
END = "<!-- compat-counts:end -->"
PROGRESS_BEGIN = "<!-- compat-progress:begin -->"
PROGRESS_END = "<!-- compat-progress:end -->"
HOSTS = ("macOS", "Windows")
STATUSES = {"🟢": "same", "🟡": "differs", "🔴": "red", "⚪": "na", "❔": "untested"}
# Sections whose tables are not feature tables.
NOT_FEATURES = {"Summary", "Progress", "Upstream integration tests"}
PREFIX = "integration_tests/"

# The mode of macOS's differences file the counts are for: the functional
# suites have run as the user (docs/PORTING.md row 12), not as root.
MACOS_MODE = "user"

# Suites a host has not run in full (docs/PORTING.md row 12, "To do"). Their
# cells say so, rather than a 0 that would read as "no difference".
NOT_RUN = {
    # The security suite has run as the user (build/integration-tests/
    # mac2-security-20261113-060224, 604dce4: 15 passed; test_fips.py and
    # test_nv.py before it, build/integration-tests/fips-nv, 2026-11-12).
    "macOS": (),
    "Windows": (),
}


# (file, failure: entry, mode) -> (at_least, n, run, what), filled as the files are read.
EXCUSES = {}
# "excused: [at least] N (run ID): what the tests do", in a failure: entry's reason.
EXCUSED = re.compile(r"^excused:\s+(at least\s+)?(\d+)\s+\(run\s+([^)]+)\):\s*(\S.*)$")


def excused_line(path, raw, entry, reason):
    """(at_least, n, run, what) from a failure: entry's reason, or exit naming the entry."""
    for text in reason:
        m = EXCUSED.match(text)
        if m:
            return bool(m.group(1)), int(m.group(2)), m.group(3).strip(), m.group(4).strip()
    raise SystemExit(
        f"{path.relative_to(ROOT)}: `{entry}` excuses tests no entry names, so its reason must say how many and in which "
        f"run: a comment line `# excused: [at least] N (run ID): what they do` ({raw.strip()})"
    )


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
        if entry.strip().startswith("failure:"):
            EXCUSES[(MACOS, entry.strip(), mode)] = excused_line(MACOS, raw, entry.strip(), reason)
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
        if entry.strip().startswith("failure:"):
            EXCUSES[(WINDOWS, entry.strip(), "all")] = excused_line(WINDOWS, raw, entry.strip(), reason)
        entries.append((entry.strip(), kind, "all"))
    return entries


def matches(nodeid, entry):
    return nodeid == entry or nodeid.startswith(entry + "[") or nodeid.startswith(entry + "::")


def module(nodeid):
    return nodeid.split("::", 1)[0]


def excuses(host, entries):
    """(entry, kind, at_least, n, run, what) of the failure: entries among `entries`."""
    path = MACOS if host == "macOS" else WINDOWS
    return [(e, k) + EXCUSES[(path, e, m)] for e, k, m in entries if e.startswith("failure:")]


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
    for entry, kind, at_least, n, run, what in excuses(host, entries):
        notes.append(
            f"{host}: `{entry}` ({kind}) excuses any test whose every failing phase failed with that exception, "
            f"in any file: {'at least ' if at_least else ''}{n} in run {run}, which {what}. They are not in "
            "the counts above (no entry names them by file), and the progress block counts them as not agreeing."
        )
    unmatched = [e for e in named if e[0] not in hit]
    for entry, kind, _ in unmatched:
        notes.append(f"{host}: `{entry}` ({kind}) names no test with a Linux result.")
    if not_passing:
        parts = ", ".join(f"{n} {o}" for o, n in sorted(not_passing.items()))
        notes.append(f"{host}: entries also name tests Linux did not pass ({parts}); not counted.")
    return per_file, notes


def feature_rows(text):
    """(area, feature, {host: status}) of each row of the document's feature tables."""
    rows = []
    area, header = None, None
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("## "):
            area, header = line[3:].strip(), None
            continue
        if line.startswith("#") or not line.startswith("|"):
            header = None
            continue
        cells = [c.strip() for c in line.replace("\\|", "\0").strip().strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if all(set(c) <= set("-: ") for c in cells) or area in NOT_FEATURES:
            continue
        if not all(h in header for h in HOSTS):
            continue
        status = {}
        for host in HOSTS:
            cell = cells[header.index(host)]
            icon = cell[:1]
            if icon not in STATUSES:
                raise SystemExit(f"docs line {n}: the {host} cell starts with no status icon: {cell[:60]!r}")
            kind = STATUSES[icon]
            if kind == "red":
                if re.match(r"🔴\s*impossible", cell):
                    kind = "impossible"
                elif re.match(r"🔴\s*not done yet", cell):
                    kind = "not yet"
                else:
                    raise SystemExit(f"docs line {n}: a {host} 🔴 cell says neither impossible nor not done yet: "
                                     f"{cell[:60]!r}")
            status[host] = kind
        rows.append((area, cells[0], status))
    return rows


def bar(done, of):
    pct = 100 * done / of if of else 0
    full = round(pct / 10)
    return f"`{'█' * full}{'░' * (10 - full)}` {pct:.0f}%"


def progress_cell(counts):
    of = sum(counts.values()) - counts["na"] - counts["impossible"]
    done = counts["same"] + counts["differs"]
    return bar(done, of) + f" ({done} of {of})"


def integration(linux, files, host, failures):
    """Linux-passing tests in the suites `host` has run: all, listed by name or excused by a failure:
    entry, listed as impossible or arch, and whether the excused count is only a lower bound."""
    passed = [n for n, o in linux.items() if o == "passed" and not any(n.startswith(p) for p in NOT_RUN[host])]
    listed = Counter()
    for name, kinds in files.items():
        if not any(name.startswith(p) for p in NOT_RUN[host]):
            listed.update(kinds)
    excused = sum(f[3] for f in failures)
    at_least = any(f[2] for f in failures)
    return len(passed), sum(listed.values()) + excused, listed["impossible"] + listed["arch"], at_least


def progress(text):
    rows = feature_rows(text)
    linux = baseline()
    mac = [e for e in macos_entries() if e[2] in ("all", MACOS_MODE)]
    win = windows_entries()
    mac_files, _ = tally("macOS", mac, linux)
    win_files, _ = tally("Windows", win, linux)
    files = {"macOS": mac_files, "Windows": win_files}
    failures = {"macOS": excuses("macOS", mac), "Windows": excuses("Windows", win)}
    per_host = {h: Counter(r[2][h] for r in rows) for h in HOSTS}
    areas = []
    for area, _, _ in rows:
        if area not in areas:
            areas.append(area)

    out = [f"Generated by `tools/compat-counts.py` from the {len(rows)} feature rows below and the differences "
           "files; CI fails when it is stale.", ""]
    out += ["| | macOS | Windows |", "| --- | --- | --- |"]
    out.append("| **Works (🟢 or 🟡), of what the host can do** | "
               + " | ".join(f"**{progress_cell(per_host[h])}**" for h in HOSTS) + " |")
    for label, key in (("🟢 Same as Linux", "same"), ("🟡 Works, with differences", "differs"),
                       ("🔴 Not done yet", "not yet"), ("❔ Not tested", "untested"),
                       ("🔴 Impossible on the host (refused)", "impossible"), ("⚪ Not applicable", "na")):
        out.append(f"| {label} | " + " | ".join(str(per_host[h][key]) for h in HOSTS) + " |")
    cells = []
    for h in HOSTS:
        total, listed, impossible, at_least = integration(linux, files[h], h, failures[h])
        suites = "functional" if NOT_RUN[h] else "functional and security"
        cells.append(f"{bar(total - listed, total - impossible)} ({'at most ' if at_least else ''}"
                     f"{total - listed} of {total - impossible}; {suites})")
    out.append("| **Upstream integration tests that agree with Linux**, of those the host can run | "
               + " | ".join(cells) + " |")
    out += ["", "| Area | macOS | Windows |", "| --- | --- | --- |"]
    for area in areas:
        anchor = re.sub(r"[^a-z0-9 -]", "", area.lower()).replace(" ", "-")
        counts = {h: Counter(r[2][h] for r in rows if r[0] == area) for h in HOSTS}
        out.append(f"| [{area}](#{anchor}) | " + " | ".join(progress_cell(counts[h]) for h in HOSTS) + " |")
    excused = []
    for h in HOSTS:
        for entry, _, at_least, n, run, what in failures[h]:
            excused.append(f"{h}: {'at least ' if at_least else ''}{n} more {what} (`{entry}`, run {run}); "
                           "they are counted as not agreeing.")
    out += ["", "Integration tests: Linux's passing tests in the suites the host has run, less the ones its "
            "differences file lists by name and the ones a `failure:` entry excused in its last run; tests "
            "listed as impossible or x86_64-only are left out of the total. \"At most\" when an excused count "
            "is a lower bound (a run of part of the suites). macOS runs them as the user (its tests that need "
            "the jailer as root are listed `root`; see [Upstream integration tests](#upstream-integration-tests))." + "".join(" " + e for e in excused)]
    for h in HOSTS:
        left = [(a, f, s[h]) for a, f, s in rows if s[h] in ("not yet", "untested")]
        out += ["", f"<details><summary>{h}: {len(left)} rows left (🔴 not done yet or ❔ not tested)</summary>", ""]
        for kind, icon in (("not yet", "🔴"), ("untested", "❔")):
            for a, f, k in left:
                if k == kind:
                    out.append(f"- {icon} {a}: {f}")
        out += ["", "</details>"]
    return "\n".join(out) + "\n"


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


def embedded(text, begin, end, path):
    try:
        head, rest = text.split(begin, 1)
        body, tail = rest.split(end, 1)
    except ValueError:
        raise SystemExit(f"{path}: no {begin} ... {end} markers")
    return head, body, tail


def blocks(text):
    """Each generated block: (begin, end, what it should hold)."""
    return [(PROGRESS_BEGIN, PROGRESS_END, progress(text)), (BEGIN, END, table())]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--check", type=Path, metavar="FILE", help="fail if FILE's embedded table is stale")
    group.add_argument("--write", type=Path, metavar="FILE", help="replace FILE's embedded table")
    args = ap.parse_args()
    if args.check:
        text = args.check.read_text(encoding="utf-8")
        for begin, end, out in blocks(text):
            _, body, _ = embedded(text, begin, end, args.check)
            if body.strip() != out.strip():
                print(f"{args.check}: the block {begin} is stale; run "
                      f"python3 -I tools/compat-counts.py --write {args.check}", file=sys.stderr)
                return 1
        print(f"{args.check}: progress and integration test counts are current")
        return 0
    if args.write:
        text = args.write.read_text(encoding="utf-8")
        for begin, end, out in blocks(text):
            head, _, tail = embedded(text, begin, end, args.write)
            text = f"{head}{begin}\n{out}{end}{tail}"
        args.write.write_text(text, encoding="utf-8")
        return 0
    sys.stdout.write(table())
    return 0


if __name__ == "__main__":
    sys.exit(main())
