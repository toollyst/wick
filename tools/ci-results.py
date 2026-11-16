#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A run's test results in one format, results.tsv, from what each job
already writes.

    tools/ci-results.py add READER INPUT... --out FILE [--suite S] [--tree T] [--kind K] [--alias NAME=SHORT]...
                            [--xfail NAME=REASON]...
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

A stage or test the job expects to fail on its host (the vmnet stage on a
runner without Hypervisor.framework) is `--xfail NAME=REASON`: its `fail`
row becomes `xfail`, its detail starting `expected: REASON`. REASON is the
job's own evidence (the line it printed), not a remark. A NAME with no row,
or whose row did not fail, is an error: the expectation was wrong.

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
    problems = []
    results, _ = cut.parse_run(Path(path), Crates(), problems)
    for problem in problems:
        # A binary whose lines do not add up to libtest's counts: its tests
        # begun with no result of their own are "crash" rows below
        # (tools/libtest-results.py).
        print(f"ci-results: {problem}", file=sys.stderr)
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


def expect_failures(rows, xfails):
    """`rows` with the failures `xfails` ({name: reason}) expects as
    `xfail`; an expected failure with no row, or a row that did not fail,
    stops with the reason."""
    seen = set()
    out = []
    for suite, name, result, detail in rows:
        if name in xfails:
            seen.add(name)
            if result != "fail":
                raise SystemExit(f"ci-results: {name} was to fail ({xfails[name]}) and is {result}")
            detail = f"expected: {xfails[name]}" + (f" | {detail.strip()}" if detail.strip() else "")
            result = "xfail"
        out.append((suite, name, result, detail))
    missing = sorted(set(xfails) - seen)
    if missing:
        raise SystemExit(f"ci-results: no result for {', '.join(missing)}, which --xfail expects to fail")
    return out


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


# --- the evidence: docs/evidence/runs.tsv, written by collect only ---------
# A run's line in runs-index.tsv stays for good, also when its rows are gone:
# a run no sentence cites shrinks to no rows when a newer one is collected,
# its rows_sha256 that of no rows. The line records that the run was
# collected (collect refuses a run twice), and a claim that cites the run
# finds no row for its test and fails. A historical claim is checked for
# each test it names (claim_units: an alias and its test's name are one).

EVIDENCE = "docs/evidence/runs.tsv"
INDEX = "docs/evidence/runs-index.tsv"
GRAMMAR = "tools/run-claims.txt"
INDEX_COLUMNS = ("run", "commit", "rows_sha256", "inputs_sha256")
RUN_ID = re.compile(r"(?<![\d.])[1-9]\d{10}(?!\d|\.\d)")
TEST_NAMED = re.compile(r"`(test_[A-Za-z0-9_]+)`")
ALIAS_NAMED = re.compile(r"\b[A-Z][A-Z0-9]{3,}(?:-[A-Za-z0-9]+)?\b")
# A scenario script's stage as the documents name it (`boot-test net`,
# `jailer-test.ps1 nofile`; check-claims checks the stage exists): its rows
# have the script as suite and the stage as name.
STAGE_REF = re.compile(r"`(?:tools/(?:macos|windows)/)?(boot-test|jailer-test)(\.ps1|\.sh|\.py)? ([a-z][a-z0-9-]*)")


def stage_suite(script, ext):
    """The suite a stage's rows carry: the Windows script for `.ps1`, else
    the macOS one (tools/macos/boot-test.sh runs boot-test.py)."""
    return f"tools/windows/{script}.ps1" if ext == ".ps1" else f"tools/macos/{script}.py"


def subjects(sentence, aliases):
    """What a sentence's claim can be about: ("name", a backquoted test_ name
    or an alias some row has) or ("stage", suite, stage). An upstream test
    file (COMPATIBILITY's table names each) is not one: it would keep every
    integration row of every run, and no claim is made of a whole file."""
    out = {("name", t) for t in TEST_NAMED.findall(sentence)}
    out |= {("name", a) for a in ALIAS_NAMED.findall(sentence) if a in aliases}
    out |= {("stage", stage_suite(script, ext), stage) for script, ext, stage in STAGE_REF.findall(sentence)}
    return out


def subject_label(subject, rows=()):
    """A subject as an error names it."""
    if subject[0] == "stage":
        script = subject[1].rsplit("/", 1)[-1]
        return f"{script.removesuffix('.py')} {subject[2]}"
    return subject[1]


def sha256(data):
    import hashlib
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def parse_rows(text, name):
    """The rows of a results.tsv or of the evidence file, as dicts."""
    errors = []
    rows = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) < 2 or lines[0] != HEADER or lines[1].split("\t") != list(COLUMNS):
        return [], [f"{name}: not a results file (header {HEADER!r} and the column names)"]
    for n, line in enumerate(lines[2:], 3):
        f = line.split("\t")
        if len(f) != len(COLUMNS):
            errors.append(f"{name}:{n}: {len(f)} fields, not {len(COLUMNS)}")
            continue
        rows.append(dict(zip(COLUMNS, (unescape(x) for x in f))))
    return rows, errors


def run_block(rows, run):
    """A run's rows as the evidence file holds them, sorted: what its hash covers."""
    lines = sorted("\t".join(escape(r[c]) for c in COLUMNS) for r in rows if r["run"] == run)
    return "\n".join(lines) + "\n"


def load_grammar(root):
    g = {"not-run": [], "historical": [], "near-miss": [], "severity": ["warning"], "evidence-since": ["0"]}
    for line in (root / GRAMMAR).read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            kind, _, pat = line.partition("\t")
            if kind in ("severity", "evidence-since"):
                g[kind] = [pat.strip()]
            elif kind in g:
                g[kind].append(re.compile(pat, re.I))
            else:
                raise SystemExit(f"{GRAMMAR}: unknown kind {kind!r}")
    return g


def load_evidence(root):
    """(rows, {run: commit}, errors): the evidence file and its index, each
    run's block checked against the hash collect recorded."""
    ev, idx = root / EVIDENCE, root / INDEX
    if not ev.is_file() and not idx.is_file():
        return [], {}, []
    rows, errors = parse_rows(ev.read_text(encoding="utf-8"), EVIDENCE) if ev.is_file() else ([], [])
    runs = {}
    lines = idx.read_text(encoding="utf-8").splitlines() if idx.is_file() else []
    if not lines or lines[0].split("\t") != list(INDEX_COLUMNS):
        return rows, runs, errors + [f"{INDEX}: its first line is not the column names"]
    for n, line in enumerate(lines[1:], 2):
        f = line.split("\t")
        if len(f) != len(INDEX_COLUMNS):
            errors.append(f"{INDEX}:{n}: {len(f)} fields")
            continue
        run, commit, rows_hash, _ = f
        runs[run] = commit
        if sha256(run_block(rows, run)) != rows_hash:
            errors.append(f"{EVIDENCE}: run {run}'s rows are not what collect wrote (their hash differs from "
                          f"{INDEX}:{n}): rows are written by tools/ci-results.py collect only")
    for r in {r["run"] for r in rows} - set(runs):
        errors.append(f"{EVIDENCE}: run {r} has rows but no line in {INDEX}")
    return rows, runs, errors


def doc_subjects(texts, rows):
    """The subjects the documents mention that results rows can carry
    ([`subjects`])."""
    aliases = {r["alias"] for r in rows if r["alias"]}
    names = set()
    for text in texts:
        names |= subjects(text if isinstance(text, str) else text.decode(), aliases)
    return names


def row_is(row, subject):
    """Whether results row `row` is of `subject` ([`subjects`]; a plain
    string is a name). A name is the row's alias, its name, or its name's
    last `::` part, with or without pytest's `[parameters]`."""
    if isinstance(subject, str):
        subject = ("name", subject)
    if subject[0] == "stage":
        return row["suite"] == subject[1] and row["name"] == subject[2]
    s, name = subject[1], row["name"]
    last = name.rsplit("::", 1)[-1] if "::" in name else None
    return row["alias"] == s or name == s or last == s or (last is not None and last.startswith(s + "["))


def host_family(row):
    h = row["host"]
    return "Windows" if h.startswith("Windows") else "macOS" if h.startswith("macOS") else "Linux"


HOSTS = ("Linux", "macOS", "Windows")
SCOPE_WORDS = re.compile(r"\bon (Linux|macOS|Windows)\b|\b(WHP)\b")


def split_sentences(text):
    """`text`'s sentences: a break after `.` or `;` and spaces, before a
    capital, `(` or a backquote, outside parentheses (a run's "(commit;
    Host ...)" is part of its sentence)."""
    out, depth, start = [], 0, 0
    for m in re.finditer(r"[()]|(?<=[.;])\s+(?=[A-Z(`])", text):
        tok = m.group(0)
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(text[start:m.start()])
            start = m.end()
    out.append(text[start:])
    return out


def sentences(name, text):
    """(line, sentence, hosts) of a document: a table cell's host is its
    column's (COMPATIBILITY's Linux, macOS and Windows columns), elsewhere the
    sentence's "on <host>" words, or every host."""
    out = []
    header = None
    for n, line in enumerate(text.splitlines(), 1):
        cells = None
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if header is None:
                header = cells
                continue
        else:
            header = None
        parts = [(c, header[i] if header and i < len(header) else "") for i, c in enumerate(cells)] if cells \
            else [(line, "")]
        for cell, column in parts:
            col_hosts = [h for h in HOSTS if h.lower() in column.lower()]
            for sentence in split_sentences(cell):
                words = SCOPE_WORDS.findall(sentence)
                said = {w[0] or "Windows" for w in words}
                hosts = col_hosts or sorted(said) or list(HOSTS)
                out.append((n, sentence, hosts))
    return out


def blame_commit(repo, name, line):
    """The commit that wrote a line of a document, or None for a line not
    committed yet."""
    out = subprocess.run(["git", "-C", str(repo), "blame", "--porcelain", "-L", f"{line},{line}", "--", name],
                         capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout:
        return None
    c = out.stdout.split()[0]
    return None if set(c) == {"0"} else c


def is_ancestor(repo, a, b):
    out = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", a, b], capture_output=True)
    if out.returncode not in (0, 1):
        raise SystemExit(f"ci-results: {b} (a run's commit) is not in {repo}: the evidence names a commit this clone "
                         f"lacks")
    return out.returncode == 0


def claim_units(subs, rows):
    """A historical claim's subjects, each checked by itself, except names
    one row answers to together (an alias and its test's name, MOVEUNDERVCPU
    and `test_a_chunk_moved_...`): those are one test, checked once."""
    units = []
    for s in sorted(subs):
        joined = [u for u in units
                  if s[0] == "name" and any(t[0] == "name" and any(row_is(r, s) and row_is(r, t) for r in rows)
                                            for t in u)]
        for u in joined:
            units.remove(u)
        units.append(set().union({s}, *joined))
    return units


def check_run_claims(root, repo, documents, evidence_since=None):
    """(errors, warnings) of the documents' run claims against the evidence:
    a not-run claim on a test a run after the sentence ran, and a historical
    claim against its run's rows; a run cited after evidence_since must be in
    the evidence."""
    g = load_grammar(root)
    if evidence_since is None:
        evidence_since = int(g["evidence-since"][0])
    rows, runs, errors = load_evidence(root)
    warnings = []
    aliases = {r["alias"] for r in rows if r["alias"]}
    blame_cache = {}
    for name, text in documents.items():
        for cited in sorted(set(RUN_ID.findall(text)), key=int):
            if int(cited) > evidence_since and cited not in runs:
                errors.append(f"{name} cites run {cited}, which {INDEX} does not have: "
                              f"tools/ci-results.py collect {cited}, in the same commit")
        for n, sentence, hosts in sentences(name, text):
            subs = subjects(sentence, aliases)
            if not subs:
                if any(p.search(sentence) for p in g["near-miss"]):
                    warnings.append(f"{name}:{n}: a near miss of a run claim (tools/run-claims.txt): {sentence[:80]}")
                continue
            for p in g["near-miss"]:
                if p.search(sentence):
                    msg = f"{name}:{n}: a near miss of a run claim (tools/run-claims.txt): {sentence[:80]}"
                    (errors if g["severity"][0] == "error" else warnings).append(msg)
            if any(p.search(sentence) for p in g["not-run"]):
                ran = [(r, s) for r in rows for s in subs if row_is(r, s) and host_family(r) in hosts]
                if ran:
                    key = (name, n)
                    if key not in blame_cache:
                        blame_cache[key] = blame_commit(repo, name, n)
                    written = blame_cache[key]
                    after = [(r, s) for r, s in ran if written and is_ancestor(repo, written, r["commit"])]
                    for r, s in after[:1]:
                        said = subject_label(s) if s[0] == "stage" else r["alias"] or r["name"].rsplit("::", 1)[-1]
                        errors.append(f"{name}:{n} says {said} has not run, "
                                      f"but run {r['run']} ({r['commit'][:8]}, {r['job']}) ran it: {r['result']}")
            for p in g["historical"]:
                for m in p.finditer(sentence):
                    verb = m.group("verb").lower()
                    for tests in claim_units(subs, rows):
                        for run in RUN_ID.findall(m.group("runs")):
                            if run not in runs:
                                continue
                            got = [r for r in rows if r["run"] == run and any(row_is(r, s) for s in tests)
                                   and host_family(r) in hosts]
                            said = " / ".join(sorted(subject_label(t) for t in tests))
                            results = {r["result"] for r in got}
                            # passed: one passed and none failed (a parametrised
                            # test's rows); failed: one failed; ran: any row.
                            right = {"passed": "pass" in results and not results & {"fail", "crash"},
                                     "failed": bool(results & {"fail", "crash"}), "ran": bool(results)}[verb]
                            if not got:
                                errors.append(f"{name}:{n} says {said} {verb} in run {run}, which has no row for it")
                            elif not right:
                                errors.append(f"{name}:{n} says {said} {verb} in run {run}, "
                                              f"which has it {', '.join(sorted(results))}")
    return errors, warnings


def cited_and_claimed(docs, aliases, grammar):
    """({run: subjects a sentence names with that run's id}, the subjects of
    every "not run" claim: those a newer run answers. A historical claim names
    its run, so it is in the first.)"""
    cited, claimed = {}, set()
    for text in docs:
        for _, sentence, _ in sentences("", text):
            subs = subjects(sentence, aliases)
            if not subs:
                continue
            for rid in RUN_ID.findall(sentence):
                cited.setdefault(rid, set()).update(subs)
            if any(p.search(sentence) for p in grammar["not-run"]):
                claimed |= subs
    return cited, claimed


def collect(root, run, inputs, docs):
    """Adds run's rows (from its results-* files) to the evidence and its line
    to the index. What is kept is bounded by what is cited: a run's rows are
    those of the subjects a document sentence names together with that run's
    id, and the newest run collected (the index's last line) keeps also the
    subjects of every "not run" claim, since it is the run that answers them. When a newer run is collected, the one before it shrinks to
    its cited rows, and its rows_sha256 is written anew (a hand edit of the
    rows still fails it; inputs_sha256 stays the hash of the results files
    the run's rows came from)."""
    texts = []
    new = []
    for p in inputs:
        r, errs = parse_rows(Path(p).read_text(encoding="utf-8"), str(p))
        if errs or validate(Path(p).read_text(encoding="utf-8"), str(p)):
            raise SystemExit(f"collect: {p}: " + "; ".join(errs or validate(Path(p).read_text(encoding="utf-8"), str(p))))
        new += r
        texts.append(Path(p).read_bytes())
    if {r["run"] for r in new} - {run}:
        raise SystemExit(f"collect: the inputs hold rows of runs other than {run}")
    commits = {r["commit"] for r in new}
    if len(commits) != 1:
        raise SystemExit(f"collect: run {run}'s rows name {len(commits)} commits")
    commit = next(iter(commits))
    if not is_ancestor(root, commit, "HEAD"):
        raise SystemExit(f"collect: run {run}'s commit {commit[:12]} is not an ancestor of HEAD")
    old, runs, errors = load_evidence(root)
    if errors:
        raise SystemExit("collect: the evidence does not check: " + "; ".join(errors))
    if run in runs:
        raise SystemExit(f"collect: run {run} is in the evidence already")
    docs = list(docs)
    aliases = {r["alias"] for r in new + old if r["alias"]}
    cited, claimed = cited_and_claimed(docs, aliases, load_grammar(root))
    names = cited.get(run, set()) | claimed
    keep = [r for r in new if any(row_is(r, s) for s in names)]
    ev, idx = root / EVIDENCE, root / INDEX
    lines = idx.read_text(encoding="utf-8").splitlines() if idx.is_file() else ["\t".join(INDEX_COLUMNS)]
    # The newest run before this one shrinks to its cited rows.
    if len(lines) > 1:
        prev = lines[-1].split("\t")[0]
        old = [r for r in old if r["run"] != prev or any(row_is(r, s) for s in cited.get(prev, ()))]
        f = lines[-1].split("\t")
        f[2] = sha256(run_block(old, prev))
        lines[-1] = "\t".join(f)
    allrows = old + keep
    ev.parent.mkdir(parents=True, exist_ok=True)
    order = [line.split("\t")[0] for line in lines[1:]] + [run]
    body = "".join(run_block(allrows, r) for r in order if any(x["run"] == r for x in allrows))
    ev.write_text(HEADER + "\n" + "\t".join(COLUMNS) + "\n" + body, encoding="utf-8")
    lines.append("\t".join((run, commits.pop(), sha256(run_block(allrows, run)),
                            sha256(b"".join(sorted(texts))))))
    idx.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(keep), len(new)


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
    # A test that runs its binary again as a child (tools/libtest-results.py):
    # the child's lines stand for no result of the parent's.
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "child.log"
        log.write_text(
            "     Running unittests src/lib.rs (target/debug/deps/vmm-0b)\n\nrunning 3 tests\n"
            "test a::api_child ... ignored\ntest a::test_serves ... \nrunning 1 test\ntest a::api_child ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.10s\n\n"
            "test a::z ... ok\n\n"
            "test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s\n")
        expect("a child's lines", {r[1]: r[2] for r in read_libtest(log)},
               {"a::api_child": "skip", "a::test_serves": "pass", "a::z": "pass"})
    got = rows_of("libtest", "libtest-linux-43790310601.log")
    expect("linux libtest", (len(got), got.get(("acpi_tables", "aml::tests::test_buffer"))), (22, "pass"))
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

    # An expected failure: macos-15-root-vmnet's vmnet stage, which fails on
    # a runner without Hypervisor.framework (CI run 43800980377).
    vmnet = [("tools/macos/boot-test.py", "vmnet", "fail", "the API's first answer: GET / -> 500"),
             ("tools/macos/boot-test.py", "other", "pass", "")]
    why = "kern.hv_support: no such oid (a kernel without HYPERVISOR)"
    got = expect_failures(vmnet, {"vmnet": why})
    expect("xfail", got[0], ("tools/macos/boot-test.py", "vmnet", "xfail", f"expected: {why} | the API's first answer: "
                                                                           "GET / -> 500"))
    expect("xfail leaves the rest", got[1], vmnet[1])
    for case, rows, names in (("passed", [vmnet[1]], {"other": why}), ("no row", vmnet, {"vmnet": why, "gone": why})):
        try:
            expect_failures(rows, names)
            fails.append(f"xfail {case}: no error")
        except SystemExit:
            pass

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
    claims_selftest(expect)
    if fails:
        sys.exit("ci-results: selftest failed:\n  " + "\n  ".join(fails))
    print("ci-results: selftest ok")


def claims_selftest(expect):
    """Collect and the offline check of run claims, in a repository of their own."""
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
           "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

    def git(*args, cwd):
        return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()

    moved = "test_a_chunk_moved_under_a_vcpu_keeps_its_memory_and_dirty_pages"
    # Audit 5's finding, in the words docs/COMPATIBILITY.md's memory.max row had
    # at 70f7b405 (its Windows cell): not run yet, while CI runs 43784960688
    # and 43790310601, on later commits, had run it and it failed.
    said = ("MOVEUNDERVCPU (`" + moved + "`: the chunk a vCPU reads, then writes, moved under it at the limit) needs "
            "WHP: in CI runs 43680983973 and 43688550565 it moved 0 of 40 rounds; with a fresh page's fill since, not "
            "run yet: it stands on the next CI or PC run.")
    table = "| Control | Linux | macOS | Windows |\n| --- | --- | --- | --- |\n| memory.max | a | b | " + said + " |\n"
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "tools").mkdir()
        (repo / GRAMMAR).write_text((ROOT / GRAMMAR).read_text())
        git("init", "-q", "-b", "main", cwd=repo)
        (repo / "x").write_text("before")
        git("add", "-A", cwd=repo)
        git("commit", "-q", "-m", "before the sentence", cwd=repo)
        before = git("rev-parse", "HEAD", cwd=repo)
        (repo / "COMPATIBILITY.md").write_text(table)
        (repo / "s.md").write_text(STAGE_DOC)
        git("add", "-A", cwd=repo)
        git("commit", "-q", "-m", "the sentence", cwd=repo)
        (repo / "x").write_text("after")
        git("add", "x", cwd=repo)
        git("commit", "-q", "-m", "a later commit, which the run built", cwd=repo)
        after = git("rev-parse", "HEAD", cwd=repo)
        docs = {"COMPATIBILITY.md": table}

        def results(run, commit):
            out = repo / f"results-{run}.tsv"
            ctx = (run, commit, "windows", "Windows Server 2025 26100", "AMD EPYC 7763 64-Core Processor")
            write_rows(out, ctx, "wick", "unit", read_libtest(FIXTURES / "libtest-windows-43790310601.log")
                       + [("kvm_ioctls", "tests::test_no_doc_names_it", "pass", "")],
                       {"whp::vcpu::fpu_tests::" + moved: "MOVEUNDERVCPU"})
            return out

        # A run of a commit before the sentence: no contradiction.
        kept, total = collect(repo, "43688550565", [results("43688550565", before)], docs.values())
        expect("collect keeps the rows the docs name", (kept, total), (1, 2))
        errors, _ = check_run_claims(repo, repo, docs, 43688550565)
        expect("a run before the sentence", errors, [])
        # The runs after it: "not run yet" is contradicted.
        collect(repo, "43790310601", [results("43790310601", after)], docs.values())
        errors, _ = check_run_claims(repo, repo, docs, 43688550565)
        expect("audit 5: MOVEUNDERVCPU said not run", errors,
               ["COMPATIBILITY.md:3 says MOVEUNDERVCPU has not run, but run 43790310601 (" + after[:8]
                + ", windows) ran it: fail"])
        # Historical claims against their run's rows.
        for text, want in (("MOVEUNDERVCPU (`" + moved + "`) failed in CI runs 43790310601 (6e561e24).", []),
                           ("MOVEUNDERVCPU (`" + moved + "`) passed in run 43790310601.",
                            ["h.md:1 says MOVEUNDERVCPU / " + moved + " passed in run 43790310601, which has it fail"]),
                           ("`test_other` failed in run 43790310601.",
                            ["h.md:1 says test_other failed in run 43790310601, which has no row for it"]),
                           ("Seen in run 43790310601 and run 43799999999.",
                            ["h.md cites run 43799999999, which " + INDEX + " does not have: tools/ci-results.py "
                             "collect 43799999999, in the same commit"])):
            errors, _ = check_run_claims(repo, repo, {"h.md": text}, 43790310601)
            expect(f"historical: {text[:40]}", errors, want)
        # Stages and pytest tests (docs name `boot-test vmnet`, `jailer-test
        # freeze`, `test_api_happy_start`; rows carry the script as suite and
        # pytest's parametrised node id), and the run-first form of a
        # historical claim. Run 43800980377's own rows, cut.
        mac = repo / "results-mac.tsv"
        ctx = ("43800980377", after, "macos", "macOS 26.7.2 25G332", "Apple M2 Pro (Virtual)")
        write_rows(mac, ctx, "wick", "stage", [("tools/macos/boot-test.py", "vmnet", "xfail", "expected: no HVF"),
                                                ("tools/macos/jailer-test.py", "freeze", "pass", ""),
                                                ("tools/macos/jailer-test.py", "limits", "pass", "")])
        write_rows(mac, ctx, "wick", "integration", [
            ("integration_tests/functional/test_api.py",
             "integration_tests/functional/test_api.py::test_api_happy_start[kvm-PCI_ON-vmlinux-6.1.188]", "pass", ""),
            ("integration_tests/functional/test_api.py",
             "integration_tests/functional/test_api.py::test_api_happy_start[kvm-PCI_OFF-vmlinux-6.1.188]", "pass", ""),
            ("integration_tests/functional/test_api.py",
             "integration_tests/functional/test_api.py::test_drive_io_engine[kvm]", "pass", "")])
        kept, total = collect(repo, "43800980377", [mac], {"s.md": STAGE_DOC}.values())
        expect("collect keeps named stages and pytest tests", (kept, total), (4, 6))
        errors, _ = check_run_claims(repo, repo, {"s.md": STAGE_DOC}, 43688550565)
        expect("stages and pytest tests", [e[:len(w)] for e, w in zip(errors, STAGE_ERRORS)] + errors[3:],
               STAGE_ERRORS)
        # What collect keeps is bounded by what is cited: a run keeps the rows
        # a sentence names with its id, and the newest run also those of the
        # status claims; collecting a newer run shrinks the one before to its
        # cited rows, and never removes one of them.
        bound = {"c.md": "`test_cited` failed in run 43900000001.\n`test_claimed` has not run yet.\n"}

        def one(run, names):
            out = repo / f"results-{run}.tsv"
            ctx = (run, after, "macos", "macOS 26.7.2 25G332", "Apple M2 Pro (Virtual)")
            write_rows(out, ctx, "wick", "unit", [("c", f"t::{n}", "fail", "") for n in names])
            return out

        kept, _ = collect(repo, "43900000001", [one("43900000001", ["test_cited", "test_claimed", "test_other"])],
                          bound.values())
        expect("the newest run keeps cited and claimed rows", kept, 2)
        kept, _ = collect(repo, "43900000002", [one("43900000002", ["test_cited", "test_claimed"])], bound.values())
        rows, _, errs = load_evidence(repo)
        expect("the run before shrinks to its cited rows",
               sorted(r["name"] for r in rows if r["run"] == "43900000001"), ["t::test_cited"])
        expect("the newest keeps the claimed row", (kept, sorted(r["name"] for r in rows if r["run"] == "43900000002")),
               (1, ["t::test_claimed"]))
        expect("the shrunk evidence checks", errs, [])
        errors, _ = check_run_claims(repo, repo, {"c.md": bound["c.md"].splitlines()[0]}, 43688550565)
        expect("a cited row answers its claim after the shrink", errors, [])
        # A run no sentence cites shrinks to no rows and keeps its index line
        # (it was collected: collect refuses it again), and a claim citing it
        # finds no row: one subject or several, each subject is checked.
        collect(repo, "43900000003", [one("43900000003", ["test_cited"])], bound.values())
        rows, runs, errs = load_evidence(repo)
        expect("an uncited run keeps its index line and no rows",
               ("43900000002" in runs, [r for r in rows if r["run"] == "43900000002"], errs), (True, [], []))
        for text, want in (
                ("`test_claimed` failed in run 43900000002.",
                 ["z.md:1 says test_claimed failed in run 43900000002, which has no row for it"]),
                ("`test_cited` and `test_claimed` failed in run 43900000002.",
                 ["z.md:1 says test_cited failed in run 43900000002, which has no row for it",
                  "z.md:1 says test_claimed failed in run 43900000002, which has no row for it"]),
                ("`test_cited` and `test_other` failed in run 43900000001.",
                 ["z.md:1 says test_other failed in run 43900000001, which has no row for it"]),
                ("`test_cited` and `test_claimed` passed in run 43900000001.",
                 ["z.md:1 says test_cited passed in run 43900000001, which has it fail",
                  "z.md:1 says test_claimed passed in run 43900000001, which has no row for it"])):
            errors, _ = check_run_claims(repo, repo, {"z.md": text}, 43688550565)
            expect(f"zero rows, subjects one by one: {text[:50]}", sorted(errors), sorted(want))
        # A row edited by hand fails its run's hash.
        ev = repo / EVIDENCE
        ev.write_text(ev.read_text().replace("\tfail\t", "\tpass\t"))
        expect("hand edit", any("not what collect wrote" in e for e in load_evidence(repo)[2]), True)


# claims_selftest's document of stage and pytest claims, and what the check
# says of it against run 43800980377's rows there.
STAGE_DOC = ("`jailer-test freeze` has not run yet on macOS.\n"
             "`boot-test vmnet` failed in run 43800980377.\n"
             "`test_api_happy_start` passed in run 43800980377.\n"
             "In CI run 43800980377 (36ef73da; Apple M2 Pro, macOS 26.7.2): `boot-test vmnet` passed.\n"
             "`boot-test.ps1 vmnet` has not run yet.\n")
STAGE_ERRORS = ["s.md:1 says jailer-test freeze has not run, but run 43800980377 (",
                "s.md:2 says boot-test vmnet failed in run 43800980377, which has it xfail",
                "s.md:4 says boot-test vmnet passed in run 43800980377, which has it xfail"]


def read_lines_text(text):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "lines.log"
        p.write_text(text)
        return read_lines(p, "selftest")


def tracked_documents(root):
    out = subprocess.run(["git", "-C", str(root), "ls-files", "*.md"], capture_output=True, text=True, check=True)
    return {d: (root / d).read_text(encoding="utf-8") for d in out.stdout.split()
            if not d.startswith("lib/") and not d.startswith("docs/design-") and (root / d).is_file()}


def collect_cmd(run, src):
    if not RUN.match(run):
        raise SystemExit(f"collect: {run!r} is neither a CI run id nor local:<machine>:<time>")
    with tempfile.TemporaryDirectory() as tmp:
        if src is None:
            if not run.isdigit():
                raise SystemExit("collect: a local run comes with --from DIR")
            got = subprocess.run(["gh", "run", "download", run, "-R", "toollyst/wick", "-p", "results-*", "-D", tmp],
                                 capture_output=True, text=True)
            if got.returncode != 0:
                raise SystemExit(f"collect: gh run download {run}: {got.stderr.strip()} (artifacts last 14 days; a "
                                 f"run older than that cannot be collected)")
            src = tmp
        inputs = sorted(Path(src).rglob("results.tsv")) or sorted(Path(src).rglob("*.tsv"))
        if not inputs:
            raise SystemExit(f"collect: no results.tsv under {src}")
        kept, total = collect(ROOT, run, inputs, tracked_documents(ROOT).values())
    print(f"ci-results: run {run}: {kept} of {total} rows kept (the names the documents mention) in {EVIDENCE}")
    return 0


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
    add.add_argument("--xfail", action="append", default=[], metavar="NAME=REASON",
                     help="a failure the job expects, with the job's own evidence for it")
    val = sub.add_parser("validate")
    val.add_argument("files", nargs="+")
    collect_rule = ("add a run's results to docs/evidence (the only writer); a run keeps the rows a document "
                    "sentence cites with its id, the newest run also those of every \"not run\" claim, and the run "
                    "before it shrinks to its cited rows")
    col = sub.add_parser("collect", help=collect_rule, description=collect_rule)
    col.add_argument("run")
    col.add_argument("--from", dest="src", metavar="DIR",
                     help="the run's results-* files already here (a PC run's results.tsv); default: download "
                          "them with gh (read-only)")
    a = ap.parse_args()
    if a.cmd == "collect":
        return collect_cmd(a.run, a.src)
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
    xfails = {}
    for x in a.xfail:
        name, sep, reason = x.partition("=")
        if not sep or not name or not reason.strip():
            ap.error(f"--xfail {x!r}: NAME=REASON")
        xfails[name] = reason.strip()
    rows = []
    for p in a.inputs:
        if not Path(p).is_file():
            raise SystemExit(f"ci-results: {p}: no such file (a step that did not run writes none; "
                             "run this step only when it did)")
        rows.append(READERS[a.reader](p, a.suite))
    flat = expect_failures([r for rs in rows for r in rs], xfails)
    ctx = context()
    total = write_rows(a.out, ctx, a.tree, a.kind or DEFAULT_KIND[a.reader], flat, aliases)
    print(f"ci-results: {total} rows from {len(a.inputs)} file(s) into {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
