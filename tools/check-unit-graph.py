#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""wick's Linux and macOS builds compile upstream's crates with upstream's features.

    tools/check-unit-graph.py [--fetch]          check (lib/firecracker with the series applied)
    tools/check-unit-graph.py --write-baseline   rewrite the macOS baselines from this tree
    tools/check-unit-graph.py --selftest         the comparison on recorded graphs

For each target, `cargo tree --workspace -e normal,build,dev` lists every
package the workspace's builds compile, with its features (cargo's feature
resolver: one line per package and feature set). No build is made; with
`--offline` (the default) cargo reads only what `cargo fetch --locked` put in
its cache, and `--fetch` runs that first in both trees (the only network use).

- Linux (x86_64 and aarch64, gnu and musl): every line of upstream's graph
  (`patches/base`, its own Cargo.lock, no patch) is in wick's, at the version
  tools/linux/dependency-moves.txt moves it to, if it does (a move that
  matches no line of upstream's fails, as in compare-unit-tests.py). wick may
  add packages of its own (the compatibility crates); a package upstream
  compiles with other features, or not at all, fails. CI's linux-unit-tests
  comparison checks the same on built units; this check needs no build, so it
  runs before a push and in CI's patches job.
- macOS (aarch64 and x86_64): there is no plain upstream to compare with
  (upstream does not build there), so wick's graph must be the baseline in
  tools/unit-graph/<target>.txt line for line. The baseline is the graph of
  the commit that last wrote it; a commit that changes the macOS build's
  packages or features rewrites it with `--write-baseline`, so the change is
  in that commit's diff for review.

A line is `name version [features]`; the source (registry, git, path) and
cargo's `(proc-macro)` mark are dropped, so that wick's wrapper of a crate
(a path source) and the original (registry or git) compare by name, version
and features.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FC = ROOT / "lib" / "firecracker"
BASELINES = ROOT / "tools" / "unit-graph"
MOVES = ROOT / "tools" / "linux" / "dependency-moves.txt"
LINUX = [
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
]
MACOS = ["aarch64-apple-darwin", "x86_64-apple-darwin"]
# `name vX.Y.Z`, then any number of `(...)` (a source, `proc-macro`), then
# `[features]`; cargo marks a repeat with `(*)` at the end.
LINE = re.compile(r"^(\S+) v(\S+)((?: \([^()]*\))*) \[([^\]]*)\](?: \(\*\))?$")


def normalize(text):
    """cargo tree's lines -> the set of `name version [features]`."""
    out = set()
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        m = LINE.match(raw)
        if not m:
            raise SystemExit(f"check-unit-graph: cannot read cargo tree's line {raw!r}")
        name, version, _, features = m.groups()
        feats = ",".join(sorted(f for f in features.split(",") if f))
        out.add(f"{name} {version} [{feats}]")
    return out


def tree(workspace, target):
    """The normalized graph of `workspace`'s builds for `target`."""
    cmd = [
        "cargo", "tree", "--offline", "--locked", "--workspace", "--target", target,
        "-e", "normal,build,dev", "-f", "{p} [{f}]", "--prefix", "none",
    ]
    r = subprocess.run(cmd, cwd=workspace, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(
            f"check-unit-graph: cargo tree for {target} in {workspace} failed "
            f"(run with --fetch if crates are missing from cargo's cache):\n{r.stderr.strip()}"
        )
    return normalize(r.stdout)


def moves():
    """(crate, upstream version) -> (wick version, reason)."""
    found = {}
    for line in MOVES.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            crate, frm, to, why = line.split()
            found[(crate, frm)] = (to, why)
    return found


def compare_linux(target, upstream, wick, mv, used):
    """Problems: upstream's lines missing from wick's, after the moves."""
    problems = []
    for line in sorted(upstream):
        name, version, feats = line.split(" ", 2)
        want = line
        if (name, version) in mv:
            used.add((name, version))
            want = f"{name} {mv[(name, version)][0]} {feats}"
        if want not in wick:
            have = sorted(w for w in wick if w.split(" ", 1)[0] == name)
            problems.append(f"{target}: upstream compiles {line}; wick: {', '.join(have) or 'not at all'}")
    return problems


def compare_baseline(target, baseline, wick):
    """Problems: lines added to or gone from the macOS baseline."""
    problems = [f"{target}: not in the baseline: {line}" for line in sorted(wick - baseline)]
    problems += [f"{target}: in the baseline, not built: {line}" for line in sorted(baseline - wick)]
    return problems


def read_baseline(target):
    path = BASELINES / f"{target}.txt"
    if not path.exists():
        raise SystemExit(f"check-unit-graph: no baseline {path}; write it with --write-baseline")
    return {l for l in path.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")}


def write_baseline(target, lines):
    BASELINES.mkdir(exist_ok=True)
    head = (
        f"# wick's build graph for {target}: `name version [features]` of every package\n"
        "# the workspace's builds compile (cargo tree --workspace -e normal,build,dev).\n"
        "# Written by tools/check-unit-graph.py --write-baseline in the commit that\n"
        "# changes the build (`git log -- tools/unit-graph` names it); the check\n"
        "# fails when the build differs from it.\n"
    )
    (BASELINES / f"{target}.txt").write_text(head + "".join(f"{l}\n" for l in sorted(lines)), encoding="utf-8")


def upstream_tree():
    """A temporary checkout of patches/base (upstream with its own lock)."""
    base = (ROOT / "patches" / "base").read_text(encoding="utf-8").strip()
    tmp = tempfile.TemporaryDirectory(prefix="wick-unit-graph-")
    archive = subprocess.run(["git", "-C", str(FC), "archive", f"refs/tags/{base}"], capture_output=True, check=True)
    subprocess.run(["tar", "-x", "-C", tmp.name], input=archive.stdout, check=True)
    return tmp


def check(fetch):
    up = upstream_tree()
    if fetch:
        for ws in (up.name, FC):
            subprocess.run(["cargo", "fetch", "--locked", "-q"], cwd=ws, check=True)
    mv = moves()
    used = set()
    problems = []
    for target in LINUX:
        problems += compare_linux(target, tree(up.name, target), tree(FC, target), mv, used)
    for (crate, frm), (to, why) in sorted(mv.items()):
        if (crate, frm) not in used:
            problems.append(f"dependency-moves.txt: {crate} {frm} -> {to} ({why}) matches no line of upstream's")
    for target in MACOS:
        problems += compare_baseline(target, read_baseline(target), tree(FC, target))
    up.cleanup()
    if problems:
        print(f"check-unit-graph: {len(problems)} problem(s):")
        for p in problems:
            print(f"- {p}")
        sys.exit(1)
    print(f"check-unit-graph: Linux ({len(LINUX)} targets) has upstream's packages and features; "
          f"macOS ({len(MACOS)} targets) is its baseline")


# Recorded for the selftest: lines of cargo tree's output on x86_64-unknown-linux-musl.
UPSTREAM_SAMPLE = """\
libc v0.2.189 [default,std]
linux-raw-sys v0.12.1 [auxvec,elf,errno,general,ioctl,no_std]
log-instrument-macros v0.1.0 (proc-macro) (/u/src/log-instrument-macros) []
rustix v1.1.4 [alloc,default,fs,std]
vm-superio v0.8.1 []
vmm-sys-util v0.15.0 [serde,serde_derive,with-serde]
"""
# wick at dae9b2fc (and after 7104b1f6): its own crates added, the moves made.
WICK_GOOD = """\
libc v0.2.189 (/w/crates/compat/libc) []
libc v0.2.189 [default,std]
linux-raw-sys v0.12.1 [auxvec,elf,errno,general,ioctl,no_std]
log-instrument-macros v0.1.0 (proc-macro) (/w/lib/firecracker/src/log-instrument-macros) []
polling v3.11.0 (/w/crates/compat/polling) []
rustix v1.1.6 [alloc,default,fs,std]
rustix v1.1.6 [alloc,default,fs,std] (*)
vm-superio v0.8.2 []
vmm-sys-util v0.15.0 (/w/crates/compat/vmm-sys-util) []
vmm-sys-util v0.15.0 (https://github.com/rust-vmm/vmm-sys-util?tag=v0.15.0#3f1d7e9e) [serde,serde_derive,with-serde]
"""
# wick at 6e561e24: the compatibility polling's re-export unified rustix's
# features with polling's (CI run 43790310601).
WICK_6E561E24 = WICK_GOOD.replace(
    "linux-raw-sys v0.12.1 [auxvec,elf,errno,general,ioctl,no_std]",
    "linux-raw-sys v0.12.1 [auxvec,elf,errno,general,ioctl,no_std,prctl]",
).replace(
    "rustix v1.1.6 [alloc,default,fs,std]",
    "rustix v1.1.6 [alloc,default,event,fs,pipe,process,std,time]",
) + "polling v3.11.0 []\n"


def selftest():
    mv = {("rustix", "1.1.4"): ("1.1.6", "RUSTSEC-2026-0486"), ("vm-superio", "0.8.1"): ("0.8.2", "upstream-18b08295a82a")}
    up = normalize(UPSTREAM_SAMPLE)
    fails = 0

    def case(name, got, want):
        nonlocal fails
        if got != want:
            fails += 1
            print(f"selftest FAIL: {name}:\n  got  {got}\n  want {want}")

    used = set()
    case("dae9b2fc's graph passes", compare_linux("t", up, normalize(WICK_GOOD), mv, used), [])
    case("both moves are used", used, set(mv))
    got = compare_linux("t", up, normalize(WICK_6E561E24), mv, set())
    case("6e561e24's graph fails with CI's two crates", [p.split(";")[0] for p in got], [
        "t: upstream compiles linux-raw-sys 0.12.1 [auxvec,elf,errno,general,ioctl,no_std]",
        "t: upstream compiles rustix 1.1.4 [alloc,default,fs,std]",
    ])
    case("a proc-macro with its path reads as name, version and features",
         normalize("log-instrument-macros v0.1.0 (proc-macro) (/x/y) []"), {"log-instrument-macros 0.1.0 []"})
    case("features compare as a set", normalize("a v1.0.0 [b,a]"), {"a 1.0.0 [a,b]"})
    case("a crate wick does not build fails",
         compare_linux("t", normalize("gone v1.0.0 []"), set(), {}, set()),
         ["t: upstream compiles gone 1.0.0 []; wick: not at all"])
    base = normalize(WICK_GOOD)
    case("the baseline itself passes", compare_baseline("m", base, base), [])
    case("a feature added on macOS fails",
         compare_baseline("m", base, normalize(WICK_GOOD + "errno v0.3.14 [std]\n")),
         ["m: not in the baseline: errno 0.3.14 [std]"])
    try:
        normalize("not a cargo tree line")
        fails += 1
        print("selftest FAIL: an unreadable line passed")
    except SystemExit:
        pass
    if fails:
        sys.exit(f"selftest: {fails} failed")
    print("selftest: ok (9 cases)")


def main():
    args = sys.argv[1:]
    if args == ["--selftest"]:
        selftest()
    elif args == ["--write-baseline"]:
        for target in MACOS:
            write_baseline(target, tree(FC, target))
            print(f"wrote {BASELINES / (target + '.txt')}")
    elif args in ([], ["--fetch"]):
        check(bool(args))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
