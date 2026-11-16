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
for its listed reason; with --whp (the WHP PC) it must pass. A test process
that ended before its tests did (an abort, a fast fail, a stack overflow)
is named with the test it ended in and its exit code: the tests after that
one did not run, which is not the same as their not being there (run
43392627996 reported seven listed tests as "no such test" when vmm's
process had ended in test_vcpu_save_state_events). Results are read per
test binary, checked against the counts of its "test result:" line, as a
test that runs its binary again as a child has the child's lines in the
same output (results_of).

Each package's output is kept in DIR (default: a temporary directory) as
<package>.log.
"""

import argparse
import importlib.util
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
# One test thread: a test's name is printed before it runs and its result
# after, so a name with something else behind it is where the process ended.
STARTED = re.compile(r"^test (.+?) \.\.\. (?!ok\b|FAILED\b|ignored\b)")
DIED = re.compile(r"process didn't exit successfully: .*\((exit code: [^)]*|signal: [^)]*)\)")
# cargo's line before each test binary's output.
SECTION = re.compile(r"^\s+(Running|Doc-tests) ")


def reader():
    """tools/libtest-results.py, the one reader of a test binary's results
    (as tools/linux/compare-unit-tests.py and tools/macos/check-unit-tests.py
    load it)."""
    spec = importlib.util.spec_from_file_location("libtest_results", ROOT / "tools" / "libtest-results.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def results_of(output):
    """{test: ok|FAILED|ignored} of `output`, and a line for each test
    binary whose results it could not tell.

    A test that runs its own test binary again as a child (the API process,
    the sandbox's and the jail's children) has the child's libtest write to
    the same output, between the parent's "test <name> ... " and its result:
    in CI run 43881982686 the child's "test ...::api_process_child ... ok"
    came after the parent's "... ignored" line for that name, and the
    parent's own result for the test that ran the child, which libtest
    writes after "... ", was in no line. So each binary's section (cargo's
    "Running" or "Doc-tests" line) is read as its own process gave it, by
    libtest-results.py's `section_results` (the first result of a name is
    the parent's, a name in the parent's failures list failed, a test begun
    with no result of its own passed if that adds up to the parent's "test
    result:" counts); a section whose lines do not add up is named, its
    tests begun with no result left with none. A name in two binaries of a
    package: a failure in either is the test's result.
    """
    section_results = reader().section_results
    results = {}
    unknown = []
    sections = [[]]
    for line in output.splitlines():
        if SECTION.match(line):
            sections.append([])
        sections[-1].append(line)
    for lines in sections:
        found, _, problem = section_results(lines)
        if problem:
            head = next((line.strip() for line in lines if SECTION.match(line)), "the first test binary")
            unknown.append(f"{head}: {problem}")
        for name, r in found.items():
            if results.get(name) != "FAILED":
                results[name] = r
    return results, unknown


def died(output):
    """(test, how) for each test process of `output` that ended before its
    tests did: the test it was in ("" if none had begun) and cargo's words
    for how it ended."""
    found = []
    unfinished = ""
    for line in output.splitlines():
        m = STARTED.match(line)
        if m:
            unfinished = m.group(1).removesuffix(" - should panic")
        elif RESULT.match(line):
            unfinished = ""
        d = DIED.search(line)
        # cargo says the same of a process whose tests failed (exit code
        # 101): that one ended after its last test.
        if d and "exit code: 101" not in d.group(1):
            found.append((unfinished, d.group(1)))
            unfinished = ""
    return found


def selftest():
    """died() on a process that ended in a test, and on one whose tests failed."""
    aborted = (
        "test a::ok ... ok\n"
        "test a::dies ... error: test failed, to rerun pass `-p vmm --lib`\n\n"
        "Caused by:\n"
        "  process didn't exit successfully: `D:\\x\\vmm-0b.exe` (exit code: 0xc0000409, STATUS_STACK_BUFFER_OVERRUN)\n"
    )
    assert died(aborted) == [("a::dies", "exit code: 0xc0000409, STATUS_STACK_BUFFER_OVERRUN")], died(aborted)
    failed = (
        "test a::ok ... ok\ntest a::bad ... FAILED\n\ntest result: FAILED. 1 passed; 1 failed\n"
        "error: test failed, to rerun pass `-p vmm --lib`\n\nCaused by:\n"
        "  process didn't exit successfully: `D:\\x\\vmm-0b.exe` (exit code: 101)\n"
    )
    assert died(failed) == [], died(failed)
    assert died("test a::ok ... ok\n") == []
    # CI run 43881982686's vmm: a child's line for a name the parent
    # listed as ignored, and the parent's result for the test that ran the
    # child in no line.
    child = (
        "     Running unittests src\\lib.rs (vmm-0b.exe)\n\nrunning 3 tests\n"
        "test a::api_child ... ignored, run by test_serves as the API process\n"
        "test a::test_serves ... \nrunning 1 test\n"
        "test a::api_child ... ok\n"
        "test a::z ... ok\n\n"
        "test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s\n"
    )
    assert results_of(child) == ({"a::api_child": "ignored", "a::test_serves": "ok", "a::z": "ok"}, []), results_of(child)
    # A test that runs itself as its child: the child's "ok" is the only
    # line of the name, and the parent's FAILED is in its failures list.
    itself = (
        "     Running unittests src\\lib.rs (vmm-0b.exe)\n\nrunning 2 tests\n"
        "test a::test_t ... \nrunning 1 test\ntest a::test_t ... ok\n\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.10s\n\n"
        "test a::z ... ok\n\nfailures:\n\n---- a::test_t stdout ----\nthe child said ok\n\n"
        "failures:\n    a::test_t\n\n"
        "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s\n"
    )
    assert results_of(itself) == ({"a::test_t": "FAILED", "a::z": "ok"}, []), results_of(itself)
    # Lines that do not add up to the counts: the section is named.
    lost = "     Running tests\\x.rs (x-1.exe)\n\nrunning 2 tests\ntest b::y ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored;\n"
    assert results_of(lost)[1] == ["Running tests\\x.rs (x-1.exe): libtest counted 2 passed, 0 failed, 0 ignored, its lines 1, 0, 0"], results_of(lost)
    print("check-unit-tests: selftest ok")


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
    # fcntl). A non-blocking pipe then takes nothing of a write that does
    # not fit in the room it has left (0 bytes written, run 43323860314),
    # and libtest's write_all fails with WriteZero, losing the failures'
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
    results, unknown = results_of(output)
    built = "error: could not compile" not in output and "error[E" not in output
    # libtest could not write its report (it says "listing" for any run):
    # results it did not print are lost, so the run cannot be compared.
    cut = "error: io error when listing tests" in output
    return results, built, proc.returncode, cut, died(output), unknown


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--whp", action="store_true", help="the WHP PC: whp-pc entries must pass")
    ap.add_argument("--out", type=pathlib.Path, help="where each package's output is kept")
    ap.add_argument("--summary", type=pathlib.Path, help="append a Markdown summary here")
    ap.add_argument("--selftest", action="store_true", help="test this script's reading of a run, and stop")
    opts = ap.parse_args()
    if opts.selftest:
        selftest()
        return 0
    entries = read_list(LIST)
    out_dir = opts.out or pathlib.Path(tempfile.mkdtemp(prefix="wick-unit-"))
    out_dir.mkdir(parents=True, exist_ok=True)

    problems = []
    counts = []
    for package, args in RUNS:
        results, built, code, cut, ended, unknown = run(package, args, out_dir)
        if not built:
            problems.append(f"{package}: did not build (see {out_dir / (package + '.log')})")
            continue
        if cut:
            problems.append(f"{package}: libtest's output was cut short, results lost (see {out_dir / (package + '.log')})")
        problems += [f"{package}: {u} (see {out_dir / (package + '.log')})" for u in unknown]
        for test, how in ended:
            where = f"in {test}" if test else "before a test began"
            problems.append(
                f"{package}: the test process ended {where} ({how}): the tests after it did not run "
                f"(see {out_dir / (package + '.log')})"
            )
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
            # A process that ended early ran no test after the one it ended
            # in: which listed tests are there is then unknown.
            if test not in results and not ended:
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
    # Output never fails on a character: a console or a file the output is
    # redirected to has the ANSI code page (cp949, cp1252) unless Python is
    # run with -X utf8, which -I does not give (PYTHONUTF8 is an environment
    # variable), and a symbol name, a path or a program's output can hold
    # what that page has not (a WinHvPlatform symbol from dbghelp, U+A390,
    # ended vmm-memory-record.py on a PC). UTF-8, and what is not text
    # escaped.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    sys.exit(main())
