#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Runs the workspace's unit tests on macOS and checks them against a list of
the tests that do not pass there (tools/macos/unit-test-differences.txt).

Every test of every crate below runs (one thread, each binary under a time
limit), and the check fails on:
  - a failure the list does not name;
  - a listed test that passes (or is ignored, or did not run);
  - a listed name that is not a test of its crate;
  - a test binary that does not finish in time, or does not build;
  - a file a crate's tests leave in their endpoint directory that
    tools/macos/unit-test-litter.txt does not list, or a listed one they no
    longer leave. Each test binary is given an empty directory of its own
    for the endpoints of interfaces named without `/` (WICK_TEST_ENDPOINT_DIR,
    which only vmm's own tests read: overlay/vmm/platform/macos/net.rs), in
    place of the user's, and it is removed after the binary has run;
  - in the crates DEFAULT_MODE names, run a second time with no endpoint
    directory given, as a plain `cargo test` runs them (each test process
    then uses $DARWIN_USER_TEMP_DIR/fcnet-test-<pid> and removes it as it
    exits): a failure the list does not name, and any fcnet-test-<pid> the
    run leaves, its own or a child's.
So nothing goes unrun silently, nothing is left behind unnoticed, and the
lists cannot rot.

    python3 -I tools/macos/check-unit-tests.py [--crate NAME ...] [--out DIR] [--summary FILE]

With --out, DIR keeps each crate's output (<crate>.log, every test binary's
in turn) and every test's result (tests.tsv: crate, test, result, and whether
libtest printed the test's `test <name> ...` line); --summary appends the
counts and the errors to FILE in Markdown (CI's step summary). Neither
changes what the check asserts.

The binaries run unsigned, as on CI's runners, which have no
Hypervisor.framework: a test that creates a VM fails (`no-hvf`). On a Mac,
tools/macos/test.sh runs them signed, each in a process of its own (one VM per
process), signing them in place: after it, a binary cargo did not link
again is still signed here (see test.sh). Runs cargo in lib/firecracker.
The jailer's tests need root and run
in their own CI step.
"""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKSPACE = os.path.join(ROOT, "lib", "firecracker")
DIFFERENCES = os.path.join(ROOT, "tools", "macos", "unit-test-differences.txt")
LITTER = os.path.join(ROOT, "tools", "macos", "unit-test-litter.txt")
# What vmm's tests read for their endpoint directory (net.rs, TEST_ENDPOINT_DIR).
ENDPOINT_DIR_ENV = "WICK_TEST_ENDPOINT_DIR"
KINDS = {"no-hvf", "linux-path", "error-text", "bug"}
# The crates whose binaries run a second time, whole, with no endpoint
# directory given: vmm's, whose tests make endpoints and run the binary again
# (platform::net::test_binary). Whole, as it takes 274 s on CI's runner
# (libtest's "finished in 273.83s" in run 43833851623's macos-unit-tests
# vmm.log), so a test added later is covered too.
DEFAULT_MODE = {"vmm"}
# Seconds a test binary may take (the longest, vmm --lib, takes about 6
# minutes on an M1 Pro).
BINARY_LIMIT = 1800


def crates():
    """The crates and the cargo arguments that build their tests."""
    out = {
        "vmm": ["-p", "vmm", "--lib"],
        "acpi-tables": ["-p", "acpi_tables"],
        "clippy-tracing": ["-p", "clippy-tracing"],
        "cpu-template-helper": ["-p", "cpu-template-helper"],
        "firecracker": ["-p", "firecracker"],
        "log-instrument": ["-p", "log-instrument"],
        "log-instrument-macros": ["-p", "log-instrument-macros"],
        "rebase-snap": ["-p", "rebase-snap"],
        "seccompiler": ["-p", "seccompiler"],
        "snapshot-editor": ["-p", "snapshot-editor"],
        "utils": ["-p", "utils"],
        "wick-ext": ["-p", "wick-ext"],
        "wick-version": ["-p", "wick-version"],
    }
    compat = os.path.join(ROOT, "crates", "compat")
    for name in sorted(os.listdir(compat)):
        manifest = os.path.join(compat, name, "Cargo.toml")
        if os.path.exists(manifest):
            out[f"compat-{name}"] = ["--manifest-path", manifest]
    return out


def read_differences(path):
    """{(crate, test): kind}, and the errors of the file itself."""
    entries, errors = {}, []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3 or parts[0] not in KINDS:
                errors.append(f"{path}:{n}: not '<kind> <crate> <test>' with a kind of {sorted(KINDS)}: {line}")
                continue
            kind, crate, test = parts
            if (crate, test) in entries:
                errors.append(f"{path}:{n}: listed twice: {crate} {test}")
            entries[(crate, test)] = kind
    return entries, errors


def read_litter(path):
    """{crate: {path: test}} of the files a crate's tests are known to leave
    in their endpoint directory, and the errors of the file itself."""
    entries, errors = {}, []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3 or parts[1].startswith("/") or ".." in parts[1].split("/"):
                errors.append(f"{path}:{n}: not '<crate> <relative path> <test>': {line}")
                continue
            crate, rel, test = parts
            if rel in entries.setdefault(crate, {}):
                errors.append(f"{path}:{n}: listed twice: {crate} {rel}")
            entries[crate][rel] = test
    return entries, errors


def left_files(directory):
    """The paths, relative to `directory`, of what is in it but directories."""
    out = set()
    for dirpath, dirnames, filenames in os.walk(directory):
        for name in filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            out.add(os.path.relpath(os.path.join(dirpath, name), directory))
    return out


def build(args):
    """The test executables cargo builds for `args`, each with its package's
    directory, or the build's error."""
    cmd = ["cargo", "test", "--locked", "--no-run", "--message-format=json"] + args
    p = subprocess.run(cmd, cwd=WORKSPACE, capture_output=True, text=True)
    exes = []
    for line in p.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("profile", {}).get("test") and msg.get("executable"):
            exes.append((msg["executable"], os.path.dirname(msg["manifest_path"])))
    if p.returncode != 0:
        return None, p.stderr.strip().splitlines()[-20:]
    return exes, None


def environment():
    """What `cargo test` gives every test binary beyond the caller's
    environment: the toolchain's libraries, for a proc-macro crate's tests,
    which link libstd dynamically."""
    def rustc(*args):
        return subprocess.run(["rustc", *args], cwd=WORKSPACE, capture_output=True, text=True,
                              check=True).stdout
    sysroot = rustc("--print", "sysroot").strip()
    host = re.search(r"^host: (\S+)$", rustc("-vV"), re.M).group(1)
    env = dict(os.environ)
    paths = [os.path.join(sysroot, "lib", "rustlib", host, "lib")]
    paths += [p for p in env.get("DYLD_FALLBACK_LIBRARY_PATH", "").split(":") if p]
    env["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(paths)
    return env


def package_env(env, cwd):
    """And what it gives one binary: its package's directory, which tests
    read at run time too (firecracker's verify_dependencies)."""
    return dict(env, CARGO_MANIFEST_DIR=cwd)


def listed(exe, cwd, env, ignored=False):
    args = [exe, "--list"] + (["--ignored"] if ignored else [])
    out = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True).stdout
    return {line[: -len(": test")] for line in out.splitlines() if line.endswith(": test")}


def run(exe, cwd, env, endpoints):
    """(failed names, output), or (None, why) if it did not finish. Run as
    `cargo test` runs it: in its package's directory, with `endpoints` its
    endpoint directory."""
    try:
        p = subprocess.run([exe, "--test-threads=1"], cwd=cwd, env=dict(env, **{ENDPOINT_DIR_ENV: endpoints}),
                           capture_output=True, text=True, timeout=BINARY_LIMIT)
    except subprocess.TimeoutExpired:
        return None, f"did not finish in {BINARY_LIMIT} s"
    return failures(p.stdout, p.stderr, p.returncode)


def libtest_results():
    """tools/libtest-results.py, the reader of one test binary's results."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("libtest_results", os.path.join(ROOT, "tools", "libtest-results.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def failures(stdout, stderr, returncode):
    """(failed names, output) of a binary's run, or (None, why): the tests
    libtest's own process failed, read from its standard output as it gave
    them (tools/libtest-results.py), not a child's lines in a failure
    message, which a test that runs its binary again as a child prints."""
    out = stdout + stderr
    found, _, _ = libtest_results().section_results(stdout.splitlines())
    failed = {name for name, result in found.items() if result == "FAILED"}
    if returncode != 0 and not failed:
        return None, f"exit {returncode} with no failure named:\n" + "\n".join(out.splitlines()[-20:])
    return failed, out


def pid_alive(pid):
    """Whether process `pid` exists (kill -0, as tools/clean.sh decides)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def own_endpoint_dirs(temp):
    """{name: pid} of the fcnet-test-<pid> directories in `temp`."""
    out = {}
    for name in os.listdir(temp):
        m = re.fullmatch(r"fcnet-test-(\d+)", name)
        if m:
            out[name] = int(m.group(1))
    return out


def run_default_mode(exe, cwd, env):
    """(failed names, output, left), or (None, why, left): `exe` run with no
    endpoint directory given, as a plain `cargo test` runs it (net.rs
    `user_endpoint_dir`: each process's $DARWIN_USER_TEMP_DIR/fcnet-test-<pid>,
    removed by that process as it exits). `left` names each fcnet-test-<pid>
    there after the run that was not before it and whose pid is gone, the
    run's own or a child's (one a child killed before its exit leaves); a
    directory of a process still running, another checkout's test run on a
    developer's Mac, is not counted. Each one counted is removed here."""
    env = {k: v for k, v in env.items() if k != ENDPOINT_DIR_ENV}
    temp = subprocess.run(["getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True,
                          check=True).stdout.strip()
    before = own_endpoint_dirs(temp)
    try:
        p = subprocess.run([exe, "--test-threads=1"], cwd=cwd, env=env, capture_output=True, text=True,
                           timeout=BINARY_LIMIT)
        failed, out = failures(p.stdout, p.stderr, p.returncode)
    except subprocess.TimeoutExpired:
        failed, out = None, f"did not finish in {BINARY_LIMIT} s"
    left = sorted(n for n, pid in own_endpoint_dirs(temp).items() if n not in before and not pid_alive(pid))
    for name in left:
        shutil.rmtree(os.path.join(temp, name), ignore_errors=True)
    return failed, out, left


def failure_output(out, test):
    """What libtest printed for the failed `test`: its section between
    `---- <test> stdout ----` and the next section."""
    head = f"---- {test} stdout ----\n"
    at = out.find(head)
    if at < 0:
        return ""
    body = out[at + len(head):]
    end = min(i for i in (body.find("\n---- "), body.find("\nfailures:\n"), len(body)) if i >= 0)
    return body[:end].rstrip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crate", action="append", help="only these crates (names as in the list)")
    ap.add_argument("--differences", default=DIFFERENCES)
    ap.add_argument("--litter", default=LITTER)
    ap.add_argument("--out", type=pathlib.Path, help="where each crate's output and every test's result are kept")
    ap.add_argument("--summary", type=pathlib.Path, help="append a Markdown summary here")
    a = ap.parse_args()
    if a.out:
        a.out.mkdir(parents=True, exist_ok=True)
    rows = []
    counts = []
    entries, errors = read_differences(a.differences)
    litter, litter_errors = read_litter(a.litter)
    errors += litter_errors
    all_crates = crates()
    for crate in litter:
        if crate not in all_crates:
            errors.append(f"{a.litter}: crate {crate} is not one this check runs")
    for crate, test in entries:
        if crate not in all_crates:
            errors.append(f"listed crate {crate} is not one this check runs ({', '.join(all_crates)})")
    selected = a.crate or list(all_crates)
    env = environment()
    totals = {"pass": 0, "listed": 0, "ignored": 0}
    for crate in selected:
        if crate not in all_crates:
            errors.append(f"unknown crate {crate}")
            continue
        exes, err = build(all_crates[crate])
        if exes is None:
            errors.append(f"{crate}: the tests do not build:\n    " + "\n    ".join(err))
            continue
        names, failed, ignored, outputs, left = set(), set(), set(), {}, set()
        log = []
        finished = True
        for exe, cwd in exes:
            exe_env = package_env(env, cwd)
            names |= listed(exe, cwd, exe_env)
            ignored |= listed(exe, cwd, exe_env, ignored=True)
            # Short, as the user's (firecracker-net) is: a socket's path must
            # fit sun_path (104 bytes).
            endpoints = tempfile.mkdtemp(prefix="fcnet")
            try:
                f, out = run(exe, cwd, exe_env, endpoints)
                left |= left_files(endpoints)
            finally:
                shutil.rmtree(endpoints, ignore_errors=True)
            log.append(f"==== {os.path.basename(exe)} (in {cwd})\n{out}\n")
            if f is None:
                finished = False
                errors.append(f"{crate}: {os.path.basename(exe)} {out}")
                continue
            failed |= f
            for test in f:
                outputs[test] = failure_output(out, test)
            if crate in DEFAULT_MODE:
                df, dout, dleft = run_default_mode(exe, cwd, exe_env)
                log.append(f"==== {os.path.basename(exe)} again, with no endpoint directory given\n{dout}\n")
                if df is None:
                    errors.append(f"{crate}: {os.path.basename(exe)} with no endpoint directory given: {dout}")
                want_here = {test for (c, test) in entries if c == crate}
                for test in sorted((df or set()) - want_here):
                    said = "\n    ".join(failure_output(dout, test).splitlines()[-30:])
                    errors.append(f"{crate}: {test} fails with no endpoint directory given and is not listed"
                                  + (f":\n    {said}" if said else ""))
                for name in dleft:
                    errors.append(f"{crate}: {os.path.basename(exe)} with no endpoint directory given left {name}")
        if a.out:
            text = "".join(log)
            (a.out / f"{crate}.log").write_text(text)
            want_here = {test for (c, test) in entries if c == crate}
            for test in sorted(names):
                if test in ignored:
                    result = "ignored"
                elif test in failed:
                    result = "fail-listed" if test in want_here else "fail-unlisted"
                else:
                    result = "pass"
                # libtest's line, which a test's own output may follow on
                # the same line (one thread): "test <name> ... ", or
                # "test <name> - should panic ... ".
                said = (f"test {test} ... ", f"test {test} - should panic ... ")
                started = "yes" if any(s in text for s in said) else "no"
                rows.append(f"{crate}\t{test}\t{result}\t{started}")
        want = {test for (c, test) in entries if c == crate}
        for test in sorted(want - names):
            errors.append(f"{crate}: listed {test} is not a test of the crate")
        for test in sorted(failed - want):
            # What it printed: a runner's failure is read from the log alone.
            said = "\n    ".join(outputs.get(test, "").splitlines()[-30:])
            errors.append(f"{crate}: {test} fails and is not listed" + (f":\n    {said}" if said else ""))
        for test in sorted((want & names) - failed):
            why = "is ignored" if test in ignored else "passes"
            errors.append(f"{crate}: listed {test} ({entries[(crate, test)]}) {why}")
        known = litter.get(crate, {})
        for rel in sorted(left - set(known)):
            shown = os.path.relpath(a.litter, ROOT)
            errors.append(f"{crate}: its tests left {rel} in their endpoint directory "
                          f"({a.litter if shown.startswith('..') else shown} does not list it)")
        if finished:
            for rel in sorted(set(known) - left):
                errors.append(f"{crate}: listed litter {rel} ({known[rel]}) was not left")
        ran = names - ignored
        totals["pass"] += len(ran - failed)
        totals["listed"] += len(failed & want)
        totals["ignored"] += len(ignored)
        line = (f"{crate}: {len(ran - failed)} pass, {len(failed & want)} fail as listed, "
                f"{len(failed - want)} fail unlisted, {len(ignored)} ignored")
        counts.append(line)
        print(line, flush=True)
    total = f"all: {totals['pass']} pass, {totals['listed']} fail as listed, {totals['ignored']} ignored"
    print(total)
    for e in errors:
        print(f"error: {e}")
    if a.out:
        (a.out / "tests.tsv").write_text("crate\ttest\tresult\tstarted\n" + "".join(r + "\n" for r in rows))
    if a.summary:
        md = ["## macOS unit tests", ""] + [f"- {c}" for c in counts] + ["", total, ""]
        md += [f"{len(errors)} error(s)."] + [f"- {e.splitlines()[0]}" for e in errors]
        with open(a.summary, "a") as f:
            f.write("\n".join(md) + "\n")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
