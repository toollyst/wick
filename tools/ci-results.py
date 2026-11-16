#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A run's test results in one format, results.tsv, from what each job
already writes.

    tools/ci-results.py add READER INPUT... --out FILE [--suite S] [--tree T] [--kind K] [--alias NAME=SHORT]...
    tools/ci-results.py validate FILE...
    tools/ci-results.py --selftest

Readers, one per output shape (no job's output changes for them):
- libtest: cargo test's output (`test X ... ok|FAILED|ignored`, the
  `Running` lines that name each test binary), read with
  tools/linux/compare-unit-tests.py's parser, so there is one parser of
  libtest's output; a test that started and has no result (its process
  ended: an abort, a stack overflow) is `crash`;
- pytest-json: pytest-json-report's test-report.json
  (tools/linux/integration-tests.sh);
- summary: a scenario script's summary.txt, as tools/macos/boot-test.py and
  jailer-test.py write it (`PASS  stage: detail`) or tools/linux/boot-test.sh
  (`<vm> <check> PASS <detail>`);
- unit-tsv: tools/macos/check-unit-tests.py's tests.tsv (fail-listed is
  `xfail`, a failure the listed differences give);
- lines: a shell selftest's `ok: X` and `FAIL: X` lines.

results.tsv: the header `# wick-results 1`, the column names, then one row
per test, stage or record: run, commit, job, host, cpu, tree, kind, suite,
name, alias, result, detail. result is pass, fail, skip, xfail or crash. A
test the run did not execute has no row: there is no "not run" value, so
nothing can claim it. Inside a field, a tab, a newline and a backslash are
written \\t, \\n and \\\\. One run, commit, job, host and cpu per file.

The run's context comes from the environment: WICK_RESULTS_RUN (default
GITHUB_RUN_ID), WICK_RESULTS_COMMIT (default GITHUB_SHA), WICK_RESULTS_JOB
(default GITHUB_JOB), WICK_RESULTS_HOST and WICK_RESULTS_CPU (default read
from the host). A run outside CI names itself `local:<machine>:<UTC time>`
in WICK_RESULTS_RUN; there is no default from the host's name.
"""
import argparse
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tools" / "ci-results-fixtures"
HEADER = "# wick-results 1"
COLUMNS = ("run", "commit", "job", "host", "cpu", "tree", "kind", "suite", "name", "alias", "result", "detail")
RESULTS = {"pass", "fail", "skip", "xfail", "crash"}
KINDS = {"unit", "integration", "stage", "record", "selftest"}
TREES = {"wick", "upstream"}
RUN = re.compile(r"^(?:[0-9]{6,}|local:[A-Za-z0-9._-]+:[0-9]{8}T[0-9]{6})$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DETAIL_MAX = 200


def escape(s):
    return s.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "")


def unescape(s):
    return re.sub(r"\\(.)", lambda m: {"t": "\t", "n": "\n", "\\": "\\"}.get(m.group(1), m.group(0)), s)


def compare_unit_tests():
    spec = importlib.util.spec_from_file_location("compare_unit_tests", ROOT / "tools/linux/compare-unit-tests.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Crates(dict):
    """compare-unit-tests.py's executable map without a build list: the test
    binary's crate from its file name (`kvm_ioctls-73d88cf5a82df648.exe`),
    whichever host's separators its path has."""

    def get(self, exe, default=None):
        return re.sub(r"-[0-9a-f]{16}(?:\.exe)?$", "", re.split(r"[\\/]", exe)[-1])


def read_libtest(path):
    cut = compare_unit_tests()
    results, _ = cut.parse_run(Path(path), Crates())
    rows = []
    word = {"ok": "pass", "FAILED": "fail", "ignored": "skip"}
    for binary, tests in results.items():
        for name, result in tests.items():
            rows.append((binary, name, word[result], ""))
    # A test libtest started and never gave a result for: its process ended.
    binary = None
    started = []
    name = cut.Namer()  # the parser's names: a doc test's without its line number
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.rstrip("\r")
        b = cut.binary_of(line, Crates())
        if b:
            binary = b
            continue
        m = cut.STARTED.match(line)
        if m and binary:
            started.append((binary, name(binary, m.group(1))))
    seen = {(b, n) for b, n, _, _ in rows}
    for b, n in started:
        if (b, n) not in seen:
            rows.append((b, n, "crash", "started, no result: its test process ended"))
            seen.add((b, n))
    return rows


def read_pytest_json(path):
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    word = {"passed": "pass", "failed": "fail", "error": "fail", "skipped": "skip", "xfailed": "xfail",
            "xpassed": "fail"}
    rows = []
    for t in report.get("tests", []):
        file, _, _ = t["nodeid"].partition("::")
        detail = ""
        for phase in ("setup", "call", "teardown"):
            p = t.get(phase) or {}
            if p.get("outcome") in ("failed", "skipped"):
                crash = (p.get("crash") or {}).get("message")
                detail = crash or str(p.get("longrepr", "")).strip().splitlines()[-1]
                break
        rows.append((file, t["nodeid"], word[t["outcome"]], detail))
    return rows


MAC_SUMMARY = re.compile(r"^(PASS|FAIL)  (.+?): ?(.*)$")
LINUX_SUMMARY = re.compile(r"^(\S+)\s+(.+?)\s+(PASS|FAIL)(?: (.*))?$")


def read_summary(path, suite):
    rows = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = MAC_SUMMARY.match(line)
        if m:
            rows.append((suite, m.group(2), "pass" if m.group(1) == "PASS" else "fail", m.group(3)))
            continue
        m = LINUX_SUMMARY.match(line)
        if m:
            rows.append((suite, f"{m.group(1)}/{m.group(2)}", "pass" if m.group(3) == "PASS" else "fail",
                         m.group(4) or ""))
    return rows


def read_unit_tsv(path):
    rows = []
    word = {"pass": "pass", "fail-listed": "xfail", "fail-unlisted": "fail", "ignored": "skip"}
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].split("\t") != ["crate", "test", "result", "started"]:
        raise SystemExit(f"{path}: not check-unit-tests.py's tests.tsv")
    for line in lines[1:]:
        crate, test, result, _started = line.split("\t")
        rows.append((crate, test, word[result], ""))
    return rows


SELFTEST_LINE = re.compile(r"^(ok|FAIL): (.+?)(?:: (.*))?$")


def read_lines(path, suite):
    rows = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = SELFTEST_LINE.match(line)
        if m:
            rows.append((suite, m.group(2), "pass" if m.group(1) == "ok" else "fail", m.group(3) or ""))
    return rows


def run_cmd(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def host_and_cpu():
    host = os.environ.get("WICK_RESULTS_HOST")
    cpu = os.environ.get("WICK_RESULTS_CPU")
    system = platform.system()
    if not host:
        if system == "Darwin":
            host = f"macOS {run_cmd('sw_vers', '-productVersion')} {run_cmd('sw_vers', '-buildVersion')}"
        elif system == "Linux":
            name = ""
            try:
                for line in Path("/etc/os-release").read_text().splitlines():
                    if line.startswith("PRETTY_NAME="):
                        name = line.split("=", 1)[1].strip('"')
            except OSError:
                pass
            host = f"{name or 'Linux'} {platform.release()}"
        else:
            host = f"{system} {platform.version()}"
    if not cpu:
        if system == "Darwin":
            cpu = run_cmd("sysctl", "-n", "machdep.cpu.brand_string")
        elif system == "Linux":
            try:
                cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                            if line.startswith("model name")), "")
            except OSError:
                cpu = ""
        cpu = cpu or platform.machine()
    return host, cpu


def context():
    run = os.environ.get("WICK_RESULTS_RUN") or os.environ.get("GITHUB_RUN_ID") or ""
    commit = os.environ.get("WICK_RESULTS_COMMIT") or os.environ.get("GITHUB_SHA") or ""
    job = os.environ.get("WICK_RESULTS_JOB") or os.environ.get("GITHUB_JOB") or ""
    if not RUN.match(run):
        raise SystemExit("ci-results: no run: set WICK_RESULTS_RUN (a CI run id, or local:<machine>:<yyyymmddThhmmss>)")
    if not COMMIT.match(commit):
        raise SystemExit("ci-results: no commit: set WICK_RESULTS_COMMIT to the full sha the run built")
    if not job:
        raise SystemExit("ci-results: no job: set WICK_RESULTS_JOB")
    host, cpu = host_and_cpu()
    return run, commit, job, host, cpu


def write_rows(out, ctx, tree, kind, rows, aliases=None):
    out = Path(out)
    new = not out.exists() or out.stat().st_size == 0
    with out.open("a", encoding="utf-8") as f:
        if new:
            f.write(HEADER + "\n" + "\t".join(COLUMNS) + "\n")
        for suite, name, result, detail in rows:
            detail = detail.strip().splitlines()[0] if detail.strip() else ""
            fields = (*ctx, tree, kind, suite, name, (aliases or {}).get(name, ""), result, detail[:DETAIL_MAX])
            f.write("\t".join(escape(x) for x in fields) + "\n")
    return len(rows)


def validate(text, name="results.tsv"):
    """The format's errors in `text`, as messages."""
    errors = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != HEADER:
        return [f"{name}:1: the first line is not {HEADER!r}"]
    if len(lines) < 2 or lines[1].split("\t") != list(COLUMNS):
        return [f"{name}:2: the second line is not the column names"]
    shared = None
    for n, line in enumerate(lines[2:], 3):
        f = line.split("\t")
        if len(f) != len(COLUMNS):
            errors.append(f"{name}:{n}: {len(f)} fields, not {len(COLUMNS)}")
            continue
        row = dict(zip(COLUMNS, (unescape(x) for x in f)))
        if not RUN.match(row["run"]):
            errors.append(f"{name}:{n}: run {row['run']!r} is neither a CI run id nor local:<machine>:<time>")
        if not COMMIT.match(row["commit"]):
            errors.append(f"{name}:{n}: commit {row['commit']!r} is not a full sha")
        for col, allowed in (("tree", TREES), ("kind", KINDS), ("result", RESULTS)):
            if row[col] not in allowed:
                errors.append(f"{name}:{n}: {col} {row[col]!r} is not one of {', '.join(sorted(allowed))}")
        for col in ("job", "host", "cpu", "suite", "name"):
            if not row[col]:
                errors.append(f"{name}:{n}: {col} is empty")
        if len(row["detail"]) > DETAIL_MAX or "\n" in row["detail"]:
            errors.append(f"{name}:{n}: detail is longer than {DETAIL_MAX} characters or more than one line")
        this = tuple(row[c] for c in ("run", "commit", "job", "host", "cpu"))
        if shared is None:
            shared = this
        elif this != shared:
            errors.append(f"{name}:{n}: another run, commit, job, host or cpu than line 3's: one of each per file")
    return errors


READERS = {
    "libtest": lambda p, s: read_libtest(p),
    "pytest-json": lambda p, s: read_pytest_json(p),
    "summary": read_summary,
    "unit-tsv": lambda p, s: read_unit_tsv(p),
    "lines": read_lines,
}
DEFAULT_KIND = {"libtest": "unit", "pytest-json": "integration", "summary": "stage", "unit-tsv": "unit",
                "lines": "selftest"}


def selftest():
    def rows_of(reader, fixture, suite=""):
        return {(r[0], r[1]): r[2] for r in READERS[reader](FIXTURES / fixture, suite)}

    fails = []

    def expect(what, got, want):
        if got != want:
            fails.append(f"{what}: got {got!r}, want {want!r}")

    # Audit 5's finding: MOVEUNDERVCPU was said not to have run while CI runs
    # 43784960688 and 43790310601 ran it and it failed. Its libtest line has
    # no result word (the stack overflow's lines follow it), and the result
    # comes as a late FAILED and the failures list: a reader of `... ok|FAILED`
    # lines alone has no row for it, which a doc check would take as "not run".
    moved = "whp::vcpu::fpu_tests::test_a_chunk_moved_under_a_vcpu_keeps_its_memory_and_dirty_pages"
    got = rows_of("libtest", "libtest-windows-43790310601.log")
    expect("MOVEUNDERVCPU", got.get(("kvm_ioctls", moved)), "fail")
    # The same run with the test's late FAILED and failures list cut, as when
    # its process ends in the test: started, no result.
    with tempfile.TemporaryDirectory() as tmp:
        cut = Path(tmp) / "cut.log"
        text = (FIXTURES / "libtest-windows-43790310601.log").read_text()
        cut.write_text(text[:text.index("\nFAILED\n")] + "\n")
        expect("crash", {(r[0], r[1]): r[2] for r in read_libtest(cut)}.get(("kvm_ioctls", moved)), "crash")
    got = rows_of("libtest", "libtest-linux-43790310601.log")
    expect("linux libtest", (len(got), got.get(("acpi_tables", "aml::tests::test_buffer"))), (5, "pass"))
    got = rows_of("pytest-json", "pytest-linux-43790310601.json")
    expect("pytest", sorted(got.values()), ["pass", "pass", "skip"])
    got = rows_of("summary", "summary-macos-jailer-43784960688.txt", "tools/macos/jailer-test.py")
    expect("macOS summary", (len(got), got.get(("tools/macos/jailer-test.py", "freeze"))), (6, "pass"))
    got = rows_of("summary", "summary-linux-boot-43784960688.txt", "tools/linux/boot-test.sh")
    expect("Linux summary", got.get(("tools/linux/boot-test.sh", "boot/seccomp filter on every thread")), "pass")
    got = rows_of("unit-tsv", "tests-macos-43790310601.tsv")
    expect("tests.tsv", sorted(got.values()), ["pass", "pass", "skip", "xfail", "xfail"])
    got = {r[1]: r[2] for r in read_lines_text("ok: live owner: session and its screen kept\n"
                                               "FAIL: dead owner: want taken, screen kept\nnoise\n")}
    expect("lines", got, {"live owner": "pass", "dead owner": "fail"})

    # The format: what add writes validates; what breaks it does not.
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "results.tsv"
        ctx = ("43790310601", "6e561e24a8bb77070a734c6e1c1396c792b4ca56", "windows", "Windows Server 2025 26100",
               "AMD EPYC 7763 64-Core Processor")
        write_rows(out, ctx, "wick", "unit", read_libtest(FIXTURES / "libtest-windows-43790310601.log"),
                   {moved: "MOVEUNDERVCPU"})
        write_rows(out, ctx, "wick", "selftest", [("x", "a\tb\\c", "pass", "line one\nline two")])
        text = out.read_text()
        expect("valid", validate(text), [])
        expect("alias", "\tMOVEUNDERVCPU\tfail\t" in text, True)
        expect("escaped", "a\\tb\\\\c" in text and "line two" not in text, True)
        broken = text.replace("\tfail\t", "\tnot-run\t", 1)
        expect("result vocabulary", len(validate(broken)), 1)
        other = text + text.splitlines()[-1].replace("\twindows\t", "\tmacos\t") + "\n"
        expect("one job per file", len(validate(other)), 1)
        expect("header", validate("x\n")[0].endswith(f"is not {HEADER!r}"), True)
    if fails:
        sys.exit("ci-results: selftest failed:\n  " + "\n  ".join(fails))
    print("ci-results: selftest ok")


def read_lines_text(text):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "lines.log"
        p.write_text(text)
        return read_lines(p, "selftest")


def main():
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        return 0
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add")
    add.add_argument("reader", choices=sorted(READERS))
    add.add_argument("inputs", nargs="+")
    add.add_argument("--out", required=True)
    add.add_argument("--suite", default="")
    add.add_argument("--tree", default="wick", choices=sorted(TREES))
    add.add_argument("--kind", choices=sorted(KINDS))
    add.add_argument("--alias", action="append", default=[], metavar="NAME=SHORT",
                     help="the short name the docs use for a test (MOVEUNDERVCPU)")
    val = sub.add_parser("validate")
    val.add_argument("files", nargs="+")
    a = ap.parse_args()
    if a.cmd == "validate":
        errors = [e for f in a.files for e in validate(Path(f).read_text(encoding="utf-8"), f)]
        for e in errors:
            print(f"error: {e}")
        print(f"ci-results: {len(a.files)} file(s), {len(errors)} errors")
        return 1 if errors else 0
    if a.reader in ("summary", "lines") and not a.suite:
        ap.error(f"{a.reader} needs --suite (the tool's path)")
    aliases = {}
    for a_ in a.alias:
        name, sep, short = a_.rpartition("=")
        if not sep or not name or not short:
            ap.error(f"--alias {a_!r}: NAME=SHORT")
        aliases[name] = short
    ctx = context()
    total = 0
    for p in a.inputs:
        if not Path(p).is_file():
            raise SystemExit(f"ci-results: {p}: no such file (a step that did not run writes none; "
                             "run this step only when it did)")
        total += write_rows(a.out, ctx, a.tree, a.kind or DEFAULT_KIND[a.reader], READERS[a.reader](p, a.suite),
                            aliases)
    print(f"ci-results: {total} rows from {len(a.inputs)} file(s) into {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
