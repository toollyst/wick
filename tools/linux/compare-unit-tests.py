#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Compares the unit test results of wick with those of plain upstream.

    tools/linux/compare-unit-tests.py UPSTREAM_OUT WICK_OUT [--summary FILE]

Both directories come from tools/linux/unit-tests.sh, run on the same machine.
Tests are matched by package, test target and full name (doc tests without
their line numbers, which the patches move). It fails when:

- an upstream test passes on upstream and fails, does not run or is ignored on
  wick (a wick regression),
- an upstream test is missing from wick,
- a test fails on upstream too but is not in tools/linux/unit-test-exclusions.txt
  (an environment failure nobody has explained yet),
- an exclusion names no upstream test,
- a test only wick has (overlay modules, compatibility crates) fails,
- a cargo test run failed without a failing test to show for it,
- a crate upstream's build compiles is not compiled by wick's at the same
  version with the same features (the dependency graph moved under
  upstream's code), unless tools/linux/dependency-moves.txt moves that crate
  to wick's version for a security advisory or a backported upstream commit
  (an entry that matches no unit fails too).

Prints a table per package, the problems found, and writes the same as
Markdown to --summary (e.g. $GITHUB_STEP_SUMMARY).
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

RUNS = ("lib", "examples")
RUNNING = re.compile(r"^\s*Running (?:unittests )?(.+?) \((.+)\)\s*$")
DOCTESTS = re.compile(r"^\s*Doc-tests (\S+)\s*$")
LISTED = re.compile(r"^(.+): (test|benchmark)$")
RESULT = re.compile(r"^test (.+?)(?: - should panic)? \.\.\. (ok|FAILED|ignored(?:, .*)?)$")
STARTED = re.compile(r"^test (.+?)(?: - should panic)? \.\.\. ?(.*)$")
# libtest's result word ends the line, after anything a test wrote to the
# terminal itself (a guest's serial output, say: "test x ... HHok").
LATE_RESULT = re.compile(r"(ok|FAILED|ignored(?:, .*)?)$")
LINE_NO = re.compile(r"\s*\(line \d+\)$")


def package_name(package_id):
    """`path+file:///x/src/vmm#0.1.0` -> vmm, `...#name@1.0` -> name."""
    head, _, frag = package_id.partition("#")
    if "@" in frag:
        return frag.split("@")[0]
    return head.split("?")[0].rstrip("/").rsplit("/", 1)[-1]


def package_version(package_id):
    return package_id.partition("#")[2].split("@")[-1]


def compiled_units(build_json):
    """(package, version, target kind, target, test build) -> set of feature sets.

    `default` is dropped: it only names other features, which cargo lists too,
    and the compatibility crates turn the original crate's default features
    into the same explicit ones."""
    units = defaultdict(set)
    for line in build_json.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") != "compiler-artifact":
            continue
        pid = msg["package_id"]
        key = (
            package_name(pid),
            package_version(pid),
            "/".join(msg["target"]["kind"]),
            msg["target"]["name"],
            msg["profile"]["test"],
        )
        units[key].add(frozenset(f for f in msg["features"] if f != "default"))
    return units


def dependency_moves():
    """(crate, upstream version) -> (wick version, reason), from
    dependency-moves.txt."""
    path = Path(__file__).with_name("dependency-moves.txt")
    moves = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        crate, frm, to, advisory = line.split()
        moves[(crate, frm)] = (to, advisory)
    return moves


def compare_builds(up_out, wk_out, problems, notes):
    """Every crate upstream compiles, wick compiles with the same features.

    The compatibility crates add a unit of the same name (the wrapper) next to
    the original crate; a match with either is enough. A crate moved for an
    advisory or a backported upstream commit (dependency-moves.txt) matches
    at wick's version. Returns the
    number of upstream units checked."""
    checked = 0
    moves = dependency_moves()
    used = set()
    for run in RUNS:
        up = compiled_units(up_out / f"{run}.build.json")
        wk = compiled_units(wk_out / f"{run}.build.json")
        for key, feature_sets in sorted(up.items()):
            checked += 1
            moved = moves.get((key[0], key[1]))
            wkey = (key[0], moved[0], *key[2:]) if moved else key
            for features in feature_sets:
                if moved and features in wk.get(wkey, set()):
                    used.add((key[0], key[1]))
                    continue
                if features not in wk.get(key, set()):
                    have = sorted(sorted(f) for f in wk.get(wkey, set()) | wk.get(key, set()))
                    problems.append(
                        f"build ({run}): {key[0]} {key[1]} {key[2]}:{key[3]}"
                        f"{' (test)' if key[4] else ''} has features {sorted(features)} "
                        f"on upstream, {have or 'is not built'} on wick"
                    )
    for (crate, frm), (to, advisory) in sorted(moves.items()):
        if (crate, frm) in used:
            notes.append(f"build: {crate} {frm} is {to} on wick ({advisory}, dependency-moves.txt)")
        else:
            problems.append(f"dependency-moves.txt: {crate} {frm} -> {to} ({advisory}) matches no unit")
    return checked


def executables(build_json):
    """Test executable file name -> 'package/kind:target'."""
    found = {}
    for line in build_json.read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") != "compiler-artifact" or not msg.get("executable"):
            continue
        target = msg["target"]
        kind = "/".join(target["kind"])
        key = f"{package_name(msg['package_id'])}/{kind}:{target['name']}"
        found[os.path.basename(msg["executable"])] = key
    return found


class Namer:
    """Doc test names carry line numbers that patches shift: drop them and
    number the tests that then share a name, in order."""

    def __init__(self):
        self.seen = defaultdict(int)

    def __call__(self, binary, name):
        if " - " not in name or not LINE_NO.search(name):
            return name
        base = LINE_NO.sub("", name)
        self.seen[(binary, base)] += 1
        n = self.seen[(binary, base)]
        return base if n == 1 else f"{base} #{n}"


def binary_of(line, exes):
    m = RUNNING.match(line)
    if m:
        exe = os.path.basename(m.group(2))
        return exes.get(exe, f"?/{m.group(1)}:{exe}")
    m = DOCTESTS.match(line)
    if m:
        return f"{m.group(1)}/doc"
    return None


def parse_list(path, exes):
    tests = defaultdict(list)
    binary = None
    name = Namer()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        b = binary_of(line, exes)
        if b:
            binary = b
            continue
        m = LISTED.match(line)
        if m and binary and m.group(2) == "test":
            tests[binary].append(name(binary, m.group(1)))
    return tests


SUMMARY = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def parse_run(path, exes):
    """binary -> {test: ok|FAILED|ignored}, and binary -> libtest's own
    (passed, failed, ignored) counts."""
    results = defaultdict(dict)
    summaries = defaultdict(lambda: [0, 0, 0])
    binary = None
    pending = None
    in_failures = False
    failed = []
    name = Namer()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.rstrip("\r")
        b = binary_of(line, exes)
        if b:
            binary, pending, in_failures = b, None, False
            continue
        if binary is None:
            continue
        m = RESULT.match(line)
        if m:
            results[binary][name(binary, m.group(1))] = m.group(2).split(",")[0]
            pending = None
            continue
        m = STARTED.match(line)
        if m:
            # The test wrote to the terminal itself, past libtest's capture:
            # its result follows that output, on this line or a later one.
            pending = name(binary, m.group(1))
            late = LATE_RESULT.search(m.group(2))
            if late:
                results[binary][pending] = late.group(1).split(",")[0]
                pending = None
            continue
        if pending:
            m = LATE_RESULT.search(line)
            if m:
                results[binary][pending] = m.group(1).split(",")[0]
                pending = None
                continue
        # libtest ends a binary with "failures:" (each failed test's output),
        # "failures:" again (the names, indented) and "test result:". The
        # names catch a failure whose result word was lost in a test's output.
        if line == "failures:":
            in_failures = True
            failed = []
            continue
        if in_failures and re.match(r"^    \S", line):
            failed.append(line.strip())
        m = SUMMARY.match(line)
        if m:
            for i in range(3):
                summaries[binary][i] += int(m.group(i + 1))
        if line.startswith("test result:"):
            if in_failures:
                for t in failed:
                    if not LINE_NO.search(t):
                        results[binary][t] = "FAILED"
            in_failures = False
    return results, summaries


def exclusions(arch):
    path = Path(__file__).with_name("unit-test-exclusions.txt")
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        a, name = line.split(None, 1)
        if a in ("all", arch):
            names.add(name.strip())
    return names


def load(out, excluded):
    """(run, binary) -> {test: pass|fail|ignored|notrun|excluded}, exit codes."""
    status = {}
    codes = {}
    mismatches = []
    for run in RUNS:
        exes = executables(out / f"{run}.build.json")
        listed = parse_list(out / f"{run}.list.log", exes)
        results, summaries = parse_run(out / f"{run}.run.log", exes)
        codes[run] = int((out / f"{run}.status").read_text().strip())
        for binary, tests in listed.items():
            s = {}
            for t in tests:
                r = results.get(binary, {}).get(t)
                if t in excluded:
                    s[t] = "excluded"
                elif r == "ok":
                    s[t] = "pass"
                elif r == "FAILED":
                    s[t] = "fail"
                elif r == "ignored":
                    s[t] = "ignored"
                else:
                    s[t] = "notrun"
            status[(run, binary)] = s
            # The parse must agree with libtest's own count for the binary.
            if binary in summaries:
                values = list(s.values())
                parsed = [values.count(k) for k in ("pass", "fail", "ignored")]
                if parsed != summaries[binary]:
                    mismatches.append(
                        f"{out.name}: {run}: {binary}: parsed pass/fail/ignored {parsed}, "
                        f"libtest says {summaries[binary]}"
                    )
    return status, codes, mismatches


def package(binary):
    return binary.split("/", 1)[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("upstream", type=Path)
    ap.add_argument("wick", type=Path)
    ap.add_argument("--summary", type=Path)
    args = ap.parse_args()

    arch = (args.wick / "arch").read_text().strip()
    up_arch = (args.upstream / "arch").read_text().strip()
    if arch != up_arch:
        sys.exit(f"upstream ran on {up_arch}, wick on {arch}: not comparable")
    excluded = exclusions(arch)
    up, up_codes, up_mismatches = load(args.upstream, excluded)
    wk, wk_codes, wk_mismatches = load(args.wick, excluded)

    problems = up_mismatches + wk_mismatches
    notes = []
    counts = defaultdict(lambda: defaultdict(int))
    up_names = set()

    for key, tests in up.items():
        run, binary = key
        pkg = package(binary)
        wtests = wk.get(key)
        if wtests is None:
            problems.append(f"{run}: test target {binary} ({len(tests)} tests) is missing from wick")
            wtests = {}
        for t, us in tests.items():
            up_names.add(t)
            counts[pkg][f"up_{us}"] += 1
            ws = wtests.get(t)
            if ws is None:
                problems.append(f"{binary}: {t}: in upstream ({us}), missing from wick")
                continue
            counts[pkg][f"wick_{ws}"] += 1
            bad_up = us in ("fail", "notrun")
            bad_wk = ws in ("fail", "notrun")
            if us == "pass" and ws != "pass":
                problems.append(f"REGRESSION {binary}: {t}: passes on upstream, {ws} on wick")
            elif bad_up and bad_wk:
                problems.append(
                    f"{binary}: {t}: {us} on upstream, {ws} on wick: an environment "
                    "failure; explain it in tools/linux/unit-test-exclusions.txt"
                )
            elif bad_up:
                notes.append(f"{binary}: {t}: {us} on upstream, {ws} on wick")
            elif us == "ignored" and ws != "ignored":
                (problems if bad_wk else notes).append(
                    f"{binary}: {t}: ignored on upstream, {ws} on wick"
                )
        for t, ws in wtests.items():
            if t in tests:
                continue
            counts[pkg][f"only_{ws}"] += 1
            if ws in ("fail", "notrun"):
                problems.append(f"{binary}: {t} (wick only): {ws}")

    for key, tests in wk.items():
        if key in up:
            continue
        run, binary = key
        pkg = package(binary)
        for t, ws in tests.items():
            counts[pkg][f"only_{ws}"] += 1
            if ws in ("fail", "notrun"):
                problems.append(f"{binary}: {t} (wick only): {ws}")

    for name in sorted(excluded - up_names):
        problems.append(f"exclusion '{name}' ({arch}) names no upstream test")

    def explain(codes, statuses, who):
        for run, code in codes.items():
            failing = any(
                s in ("fail", "notrun")
                for (r, _), tests in statuses.items()
                if r == run
                for s in tests.values()
            )
            if code != 0 and not failing:
                problems.append(f"{who}: cargo test ({run}) exited with {code} but no test failed")

    explain(up_codes, up, "upstream")
    explain(wk_codes, wk, "wick")
    units = compare_builds(args.upstream, args.wick, problems, notes)
    if not up_names:
        problems.append("no upstream tests were found in the logs")

    cpu = (args.wick / "cpu").read_text().strip() if (args.wick / "cpu").exists() else ""
    lines = [f"## Unit tests on {arch}: wick vs upstream {cpu}".rstrip(), ""]
    lines.append(
        "| package | upstream pass / fail / ignored / excluded | wick pass / fail / ignored / excluded | wick only (pass / fail) |"
    )
    lines.append("|---|---|---|---|")
    total = defaultdict(int)

    def cell(c, who):
        return " / ".join(
            str(c[f"{who}_{s}"] + (c[f"{who}_notrun"] if s == "fail" else 0))
            for s in ("pass", "fail", "ignored", "excluded")
        )

    for pkg in sorted(counts):
        c = counts[pkg]
        for k, v in c.items():
            total[k] += v
        only = f"{c['only_pass']} / {c['only_fail'] + c['only_notrun']}"
        if not any(c[f"only_{s}"] for s in ("pass", "fail", "notrun", "ignored")):
            only = ""
        lines.append(f"| {pkg} | {cell(c, 'up')} | {cell(c, 'wick')} | {only} |")
    only = f"{total['only_pass']} / {total['only_fail'] + total['only_notrun']}"
    lines.append(f"| **total** | {cell(total, 'up')} | {cell(total, 'wick')} | {only} |")
    lines.append("")
    lines.append(
        f"Compiled units: wick builds each of upstream's {units} (crate, target, profile) "
        "units at the same version with the same features, unless a problem below says otherwise."
    )
    lines.append("")
    if notes:
        lines.append(f"Notes ({len(notes)}):")
        lines += [f"- {n}" for n in notes]
        lines.append("")
    if problems:
        lines.append(f"**{len(problems)} problem(s):**")
        lines += [f"- {p}" for p in problems]
    else:
        lines.append(
            "No differences: every upstream test runs on wick with upstream's result."
        )
    text = "\n".join(lines) + "\n"
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(text)
    report = {"arch": arch, "upstream": {}, "wick": {}}
    for who, data in (("upstream", up), ("wick", wk)):
        for (run, binary), tests in data.items():
            report[who][f"{run}:{binary}"] = tests
    (args.wick / "comparison.json").write_text(json.dumps(report, indent=1, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
