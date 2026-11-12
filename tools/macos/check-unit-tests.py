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
  - a test binary that does not finish in time, or does not build.
So nothing goes unrun silently, and the list cannot rot.

    python3 -I tools/macos/check-unit-tests.py [--crate NAME ...]

The binaries run unsigned, as on CI's runners, which have no
Hypervisor.framework: a test that creates a VM fails (`no-hvf`). On a Mac,
tools/macos/test.sh runs them signed, each in a process of its own (one VM per
process). Runs cargo in lib/firecracker. The jailer's tests need root and run
in their own CI step.
"""

import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKSPACE = os.path.join(ROOT, "lib", "firecracker")
DIFFERENCES = os.path.join(ROOT, "tools", "macos", "unit-test-differences.txt")
KINDS = {"no-hvf", "linux-path", "error-text", "bug"}
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


def run(exe, cwd, env):
    """(failed names, output), or (None, why) if it did not finish. Run as
    `cargo test` runs it: in its package's directory."""
    try:
        p = subprocess.run([exe, "--test-threads=1"], cwd=cwd, env=env, capture_output=True, text=True,
                           timeout=BINARY_LIMIT)
    except subprocess.TimeoutExpired:
        return None, f"did not finish in {BINARY_LIMIT} s"
    out = p.stdout + p.stderr
    failed = set()
    section = out.rfind("\nfailures:\n")
    if section >= 0:
        for line in out[section:].splitlines()[1:]:
            m = re.match(r"^    (\S+)$", line)
            if m:
                failed.add(m.group(1))
    if p.returncode != 0 and not failed:
        return None, f"exit {p.returncode} with no failure named:\n" + "\n".join(out.splitlines()[-20:])
    return failed, out


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
    a = ap.parse_args()
    entries, errors = read_differences(a.differences)
    all_crates = crates()
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
        names, failed, ignored, outputs = set(), set(), set(), {}
        for exe, cwd in exes:
            exe_env = package_env(env, cwd)
            names |= listed(exe, cwd, exe_env)
            ignored |= listed(exe, cwd, exe_env, ignored=True)
            f, out = run(exe, cwd, exe_env)
            if f is None:
                errors.append(f"{crate}: {os.path.basename(exe)} {out}")
                continue
            failed |= f
            for test in f:
                outputs[test] = failure_output(out, test)
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
        ran = names - ignored
        totals["pass"] += len(ran - failed)
        totals["listed"] += len(failed & want)
        totals["ignored"] += len(ignored)
        print(f"{crate}: {len(ran - failed)} pass, {len(failed & want)} fail as listed, "
              f"{len(failed - want)} fail unlisted, {len(ignored)} ignored", flush=True)
    print(f"all: {totals['pass']} pass, {totals['listed']} fail as listed, {totals['ignored']} ignored")
    for e in errors:
        print(f"error: {e}")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
