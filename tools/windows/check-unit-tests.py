#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The workspace's unit tests on Windows, against their known differences.

    python -I tools/windows/check-unit-tests.py [--whp] [--out DIR] [--summary FILE]

Runs, in lib/firecracker, each package's tests as upstream's CI runs them on
Linux (tests/host_tools/cargo_build.py, cargo_test: RUST_TEST_THREADS=1,
RUST_BACKTRACE=1, --no-fail-fast; tools/linux/unit-tests.sh does the same),
and compares every test's result with tools/windows/unit-test-differences.txt.
It fails on a failure the file does not list, on an entry whose test passes
(an entry is a test that fails, so a fixed test leaves the list), and on an
entry that names no test of the run. A whp-pc entry fails on CI's runner
for its listed reason; with --whp (the WHP PC) it must pass.

Each package's output is kept in DIR (default: a temporary directory) as
<package>.log.
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
LIST = ROOT / "tools" / "windows" / "unit-test-differences.txt"
KINDS = {"whp-pc", "whp-limit", "error-text", "linux-path", "bug"}

# Each package and its cargo test arguments. firecracker: its example
# seccomp_jailer uses std::os::unix and does not build on Windows, so its
# binaries' and integration tests' targets only.
RUNS = [
    ("vmm", ["--lib"]),
    ("firecracker", ["--bins", "--tests"]),
    ("cpu-template-helper", []),
    ("clippy-tracing", []),
    ("acpi_tables", []),
    ("utils", []),
    ("wick-ext", []),
    ("wick-version", []),
    ("seccompiler", []),
    ("log-instrument", []),
    ("log-instrument-macros", []),
]

RESULT = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)\b")


def read_list(path):
    """(kind, package, test) -> line number."""
    entries = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 3 or parts[0] not in KINDS:
            sys.exit(f"{path}:{n}: not '<kind> <package> <test>' with a kind of {sorted(KINDS)}: {line}")
        kind, package, test = parts
        if any(p == package and t == test for (_, p, t) in entries):
            sys.exit(f"{path}:{n}: {package} {test} is listed twice")
        entries[(kind, package, test)] = n
    return entries


def run(package, args, out_dir):
    """The package's test results, {test: ok|FAILED|ignored}, and whether
    cargo built and ran them."""
    env = dict(os.environ, RUST_TEST_THREADS="1", RUST_BACKTRACE="1")
    cmd = ["cargo", "test", "--locked", "--no-fail-fast", "-p", package, *args]
    print("+ " + " ".join(cmd), flush=True)
    # The test binaries write to the log file itself, not to a pipe: a test
    # that builds a microVM with the serial on standard output makes that
    # output non-blocking (upstream's set_stdout_nonblocking), on Windows
    # PIPE_NOWAIT on standard output's pipe handle (the compatibility
    # fcntl). A full non-blocking pipe then takes part of a write and
    # libtest's next write_all fails with WriteZero, losing the failures'
    # messages (run 43277608081, cpu-template-helper). O_NONBLOCK on a file
    # changes nothing, on Windows as on Linux.
    log = out_dir / f"{package}.log"
    with open(log, "wb") as f:
        proc = subprocess.run(
            cmd,
            cwd=ROOT / "lib" / "firecracker",
            env=env,
            stdout=f,
            stderr=subprocess.STDOUT,
            check=False,
        )
    output = log.read_bytes().decode("utf-8", errors="replace")
    results = {}
    for line in output.splitlines():
        m = RESULT.match(line)
        if m:
            name = m.group(1).removesuffix(" - should panic")
            # The same name in two test binaries of a package: a failure
            # in either is the test's result.
            if results.get(name) != "FAILED":
                results[name] = m.group(2)
    built = "error: could not compile" not in output and "error[E" not in output
    # libtest could not write its report (it says "listing" for any run):
    # results it did not print are lost, so the run cannot be compared.
    cut = "error: io error when listing tests" in output
    return results, built, proc.returncode, cut


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--whp", action="store_true", help="the WHP PC: whp-pc entries must pass")
    ap.add_argument("--out", type=pathlib.Path, help="where each package's output is kept")
    ap.add_argument("--summary", type=pathlib.Path, help="append a Markdown summary here")
    opts = ap.parse_args()
    entries = read_list(LIST)
    out_dir = opts.out or pathlib.Path(tempfile.mkdtemp(prefix="wick-unit-"))
    out_dir.mkdir(parents=True, exist_ok=True)

    problems = []
    counts = []
    for package, args in RUNS:
        results, built, code, cut = run(package, args, out_dir)
        if not built:
            problems.append(f"{package}: did not build (see {out_dir / (package + '.log')})")
            continue
        if cut:
            problems.append(f"{package}: libtest's output was cut short, results lost (see {out_dir / (package + '.log')})")
        listed = {t: k for (k, p, t) in entries if p == package}
        n = {"ok": 0, "FAILED": 0, "ignored": 0}
        for test, result in sorted(results.items()):
            n[result] += 1
            kind = listed.get(test)
            if result == "FAILED" and kind is None:
                problems.append(f"{package} {test}: fails, and is not listed")
            elif result == "FAILED" and kind == "whp-pc" and opts.whp:
                problems.append(f"{package} {test}: whp-pc, and fails on this WHP machine")
            elif result == "ok" and kind is not None and not (kind == "whp-pc" and opts.whp):
                problems.append(f"{package} {test}: listed as {kind}, and passes: remove its entry")
        for test, kind in sorted(listed.items()):
            if test not in results:
                problems.append(f"{package} {test}: listed as {kind}, and the run has no such test")
        if code != 0 and n["FAILED"] == 0:
            problems.append(f"{package}: cargo test exited {code} with no failed test (see its log)")
        counts.append((package, n))
        print(f"{package}: {n['ok']} passed, {n['FAILED']} failed, {n['ignored']} ignored", flush=True)

    lines = ["## Windows unit tests" + (" (WHP)" if opts.whp else ""), ""]
    lines += [f"- {p}: {n['ok']} passed, {n['FAILED']} failed, {n['ignored']} ignored" for p, n in counts]
    lines += ["", f"{len(entries)} listed differences; {len(problems)} problem(s)."]
    lines += [f"- {p}" for p in problems]
    text = "\n".join(lines) + "\n"
    print(text)
    if opts.summary:
        with open(opts.summary, "a", encoding="utf-8") as f:
            f.write(text)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
