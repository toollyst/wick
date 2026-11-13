#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Every status claim in the docs' tables names the test that checks it.

A table cell in README.md, SECURITY.md, docs/ROADMAP.md or docs/PORTING.md that says a control
is "in place", "verified" or "measured" must also name, in backticks, the
test that shows it: a boot-test or jailer-test stage (`boot-test snapshot`,
`jailer-test.ps1 cpu`), a unit test (`test_cpu_limit_holds`, `ext::sandbox`),
or another test script (`tools/linux/integration-tests.sh`). A claim nobody
can rerun is how a doc ends up describing what a probe once showed rather
than what the product does.

    tools/check-claims.py [--strict-windows]

Cells of a Windows column are reported as warnings unless --strict-windows
is given (docs/ROADMAP.md, M5, tracks making them errors); all other cells
are errors.

Every test these files and docs/COMPATIBILITY.md name in backquotes
(`test_...`) must exist: a function of that name in the repository's Rust,
Python or PowerShell sources or in the patch series, an upstream test file of
that name, or a test of the Linux baseline. A renamed test leaves a claim
that names nothing.

Every scenario stage these files, CONTRIBUTING.md, docs/*.md and
tools/windows/README.md name in backquotes (`boot-test snapshot`,
`jailer-test.ps1 nofile`) must be a stage of that script: a key of STAGES in
tools/macos/boot-test.py or jailer-test.py, of $Stages in
tools/windows/boot-test.ps1, of -Stage's default in jailer-test.ps1, or one
of the result lines a script always reports (STAGE_RESULTS below).

Every commit of this repository a document cites (any tracked .md or .txt
outside lib/) must be an ancestor of HEAD: landings cherry-pick, so a
branch's hash never reaches main, and a doc citing one names a commit no
clone has. A citation is a lower-case token of 7 to 40 hex digits with at
least one digit and one letter (an English word such as "defaced" has no
digit, a CI run number no letter), not after "0x" (the docs write HRESULTs,
addresses and register values that way) and not part of a longer word, path,
URL or run label ("mac1-vsock-balloon-ff84c70"). Not this repository's:
- another project's commit: the clause it is in (back to the last ". ",
  ";", "|" or blank line) names the project (FOREIGN), the table row's
  first cell does, or the paragraph starts with the project's bold label;
- upstream Firecracker's, written "upstream's commits <hash>, <hash>".

A branch's hash followed in its clause by "main's <hash>" (a run's own
commit and the same change on main) is accepted when that hash is an
ancestor. Any other hash that is unknown or not an ancestor is an error; if
the clone has it and main has a commit of the same subject, the error names
it. The check needs the whole history: in a shallow clone it is an error
("history too shallow"), never a pass. `--repo PATH` names the clone to ask
when the files are a copy outside it.

    tools/check-claims.py --selftest    checks the commit check on a fake repository
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ["README.md", "SECURITY.md", "docs/ROADMAP.md", "docs/PORTING.md"]
# Also checked for the tests they name.
NAMING = FILES + ["docs/COMPATIBILITY.md"]
SOURCES = ["crates", "overlay", "tools", "fuzz", "patches", "lib/firecracker/src", "lib/firecracker/tests"]
SKIP_DIRS = {"target", "build", ".git", "__pycache__"}
DEFINED = re.compile(r"\b(?:fn|def|function)\s+(test_[A-Za-z0-9_]+)")
NAMED = re.compile(r"`([^`]*)`")
# Documents whose `boot-test <stage>` and `jailer-test <stage>` are checked.
STAGE_DOCS = NAMING + ["CONTRIBUTING.md", "docs/README.md", "docs/ARCHITECTURE.md", "docs/getting-started.md",
                       "tools/windows/README.md"]
# A result line a script reports on every run, named like a stage.
STAGE_RESULTS = {"jailer-test.ps1": {"drives"}}
STAGE_NAMED = re.compile(r"^(?:tools/(?:macos|windows)/)?(boot-test|jailer-test)(\.ps1|\.sh|\.py)?\s+(.+)$")
CLAIM = re.compile(r"\bverified\b|\bmeasured\b|\bin place\b(?! of)", re.I)
EVIDENCE = re.compile(
    r"`[^`]*(boot-test|jailer-test|test_[a-z0-9_]+|ext::[a-z_:]+|cargo test|integration-tests|"
    r"unit-tests|compare-[a-z-]+)[^`]*`"
)


def cells(path):
    """(line number, column header, cell text) of every table body cell."""
    header = None
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.startswith("|"):
            header = None
            continue
        row = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            header = row
            continue
        if all(set(c) <= set("-: ") for c in row):
            continue
        for i, text in enumerate(row[1:], 1):
            yield n, header[i] if i < len(header) else str(i), text


def known_tests():
    """Every test name defined in the sources, upstream's test files, and the Linux baseline."""
    known = set()
    for top in SOURCES:
        for path in (ROOT / top).rglob("*"):
            if SKIP_DIRS & set(path.relative_to(ROOT).parts) or not path.is_file():
                continue
            if path.name.startswith("test_") and path.suffix == ".py":
                known.add(path.stem)
            if path.suffix in (".rs", ".py", ".patch", ".ps1", ".sh"):
                known.update(DEFINED.findall(path.read_text(errors="replace")))
    baseline = ROOT / "tools/macos/integration-linux-baseline.txt"
    known.update(re.findall(r"::(test_[A-Za-z0-9_]+)", baseline.read_text()))
    return known


def stages():
    """Each scenario script's stage names, by the name a document uses for it."""
    def table(path, pattern, key):
        text = (ROOT / path).read_text()
        block = re.search(pattern, text, re.S)
        if not block:
            sys.exit(f"check-claims: no stage table found in {path}")
        return set(re.findall(key, block.group(1), re.M))

    boot = table("tools/macos/boot-test.py", r"\nSTAGES = \{(.*?)\n\}", r'^\s*"([a-z-]+)":')
    jail = table("tools/macos/jailer-test.py", r"\nSTAGES = \{(.*?)\n\}", r'^\s*"([a-z-]+)":')
    boot_win = table("tools/windows/boot-test.ps1", r"\n\$Stages = \[ordered\]@\{(.*?)\n\}", r"^\s*'?([a-z-]+)'?\s*=")
    jail_win = table("tools/windows/jailer-test.ps1", r"\[string\[\]\]\$Stage = @\(([^)]*)\)", r"'([a-z-]+)'")
    named = {"boot-test": boot, "jailer-test": jail, "boot-test.ps1": boot_win, "jailer-test.ps1": jail_win}
    for script, results in STAGE_RESULTS.items():
        named[script] = named[script] | results
    for macos in ("boot-test", "jailer-test"):
        named[macos + ".sh"] = named[macos + ".py"] = named[macos]
    return named


HASH = re.compile(r"(?<![0-9A-Za-z_\-./:#])([0-9a-f]{7,40})(?![0-9A-Za-z_\-])")
# Projects whose commits the design notes cite.
FOREIGN = re.compile(r"\b(virtiofsd|crosvm|libkrun|krunkit|crun|hcsshim|QEMU|qemu)\b")
UPSTREAM = re.compile(r"\b[Uu]pstream's commits? ([0-9a-f]{7,40}(?:(?:,\s+(?:and\s+)?|\s+and\s+)[0-9a-f]{7,40})*)")
CLAUSE_END = re.compile(r"[.;|!?](?:\s|$)|\n\s*\n")
MAINS = re.compile(r"\bmain's ([0-9a-f]{7,40})\b")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def cited_commits(text):
    """(offset, hash, alias) of each commit of this repository a document's
    text cites; `alias` is the "main's <hash>" after it in its clause."""
    upstream = set()
    for m in UPSTREAM.finditer(text):
        upstream.update(range(m.start(1), m.end(1)))
    out = []
    for m in HASH.finditer(text):
        h, at = m.group(1), m.start()
        if not re.search(r"[a-f]", h) or not re.search(r"[0-9]", h) or text[max(0, at - 2):at] == "0x":
            continue
        if at in upstream:
            continue
        before = text[max(0, at - 300):at]
        ends = [e.end() for e in CLAUSE_END.finditer(before)]
        if FOREIGN.search(before[ends[-1]:] if ends else before):
            continue
        start = text.rfind("\n", 0, at) + 1
        line = text[start:text.find("\n", at) if "\n" in text[at:] else len(text)]
        if line.startswith("|") and FOREIGN.search(line.strip("|").split("|")[0]):
            continue
        para = text.rfind("\n\n", 0, at)
        head = text[para + 2 if para >= 0 else 0:][:40]
        if re.match(r"\s*\*\*", head) and FOREIGN.search(head):
            continue
        after = text[m.end():m.end() + 200]
        cut = CLAUSE_END.search(after)
        alias = MAINS.search(after[:cut.start()] if cut else after)
        out.append((at, h, alias.group(1) if alias else None))
    return out


def check_commits(repo, docs):
    """Errors for the commits `docs` ((name, text) pairs) cite that are not
    ancestors of the repository's HEAD."""
    shallow = git(repo, "rev-parse", "--git-path", "shallow")
    if shallow.returncode != 0:
        return [f"error: {repo} is not a git repository, so the commits the docs cite cannot be checked "
                f"(--repo names the clone): {shallow.stderr.strip()}"]
    # A shallow clone's boundary commits; HEAD's history is cut if one of
    # them is HEAD or an ancestor of it (a clone can be shallow only in a
    # fetched ref HEAD does not reach).
    path = Path(shallow.stdout.strip())
    path = path if path.is_absolute() else Path(repo) / path
    bounds = path.read_text().split() if path.is_file() else []
    if any(git(repo, "merge-base", "--is-ancestor", b, "HEAD").returncode == 0 for b in bounds):
        return [f"error: history too shallow in {repo}: the commits the docs cite cannot be checked against "
                f"HEAD's ancestors (fetch the whole history: actions/checkout's fetch-depth: 0, or git fetch --unshallow)"]
    subjects = {}
    for line in git(repo, "log", "--format=%h %s", "HEAD").stdout.splitlines():
        h, _, s = line.partition(" ")
        subjects.setdefault(s, h)
    verdicts = {}

    def ancestor(h):
        if h not in verdicts:
            full = git(repo, "rev-parse", "--verify", "--quiet", f"{h}^{{commit}}")
            if full.returncode != 0:
                verdicts[h] = (False, "which this clone does not have (a branch's, or another project's)", None)
            elif git(repo, "merge-base", "--is-ancestor", full.stdout.strip(), "HEAD").returncode == 0:
                verdicts[h] = (True, "", None)
            else:
                subject = git(repo, "log", "-1", "--format=%s", full.stdout.strip()).stdout.strip()
                verdicts[h] = (False, f"which is not an ancestor of HEAD (\"{subject[:80]}\")", subjects.get(subject))
        return verdicts[h]

    errors = []
    for name, text in docs:
        for at, h, alias in cited_commits(text):
            ok, why, same = ancestor(h)
            if ok:
                continue
            n = text.count("\n", 0, at) + 1
            if alias and ancestor(alias)[0]:
                continue
            hint = f"; main has the same change as {same}" if same else ""
            errors.append(f"error: {name}:{n} cites commit {h}, {why}{hint}")
    return errors


def commit_docs(root, repo):
    """(name, text) of every tracked .md and .txt outside lib/."""
    listed = git(repo, "ls-files", "*.md", "*.txt").stdout.split()
    return [(name, (root / name).read_text(errors="replace")) for name in listed
            if not name.startswith("lib/") and (root / name).is_file()]


def selftest():
    def run(*args, cwd):
        subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                       env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                            "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        run("git", "init", "-q", "-b", "main", cwd=repo)
        (repo / "a").write_text("a")
        run("git", "add", "a", cwd=repo)
        run("git", "commit", "-q", "-m", "first", cwd=repo)
        run("git", "switch", "-q", "-c", "side", cwd=repo)
        (repo / "b").write_text("b")
        run("git", "add", "b", cwd=repo)
        run("git", "commit", "-q", "-m", "the change", cwd=repo)
        side = git(repo, "rev-parse", "--short=7", "HEAD").stdout.strip()
        run("git", "switch", "-q", "main", cwd=repo)
        # Another commit first, so that the pick is a commit of its own.
        (repo / "c").write_text("c")
        run("git", "add", "c", cwd=repo)
        run("git", "commit", "-q", "-m", "second", cwd=repo)
        run("git", "cherry-pick", side, cwd=repo)
        first = git(repo, "rev-parse", "--short=7", "HEAD~2").stdout.strip()
        picked = git(repo, "rev-parse", "--short=9", "HEAD").stdout.strip()
        # Hashes that cannot be of the repository: they have a digit and a letter.
        unknown, other = "1abcdef", "2bcdef0"
        doc = (f"| Row | passed at {first}, kit {picked}; HRESULT 0x800703e6, rip 0xffffffff8124f971 |\n"
               f"| Other | at {side}, on a branch |\n"
               f"| Third | runs at {side} (main's {picked}) and fixed by {unknown}. |\n"
               f"| virtiofsd | since 2026-11-06 (commits {other}) |\n\n"
               f"virtiofsd 1.14.0 ({other}, 2026-11-12), crosvm ({other}); upstream's commits 214314d30, 80abdb211.\n"
               f"A label mac1-vsock-balloon-{unknown} and a [crun {other}](https://example.com/{other}); "
               f"defaced, 43442912128, {'f' * 6}0.\n")
        errors = check_commits(repo, [("fake.md", doc)])
        assert errors == [
            f"error: fake.md:2 cites commit {side}, which is not an ancestor of HEAD (\"the change\"); "
            f"main has the same change as {picked[:7]}",
            f"error: fake.md:3 cites commit {unknown}, which this clone does not have (a branch's, or another "
            f"project's)",
            f"error: fake.md:7 cites commit {'f' * 6}0, which this clone does not have (a branch's, or another "
            f"project's)",
        ], errors
        shallow = Path(tmp) / "shallow"
        run("git", "clone", "-q", "--depth", "1", repo.as_uri(), str(shallow), cwd=tmp)
        errors = check_commits(shallow, [("fake.md", doc)])
        assert len(errors) == 1 and errors[0].startswith("error: history too shallow"), errors
        errors = check_commits(Path(tmp) / "none", [("fake.md", doc)])
        assert len(errors) == 1 and "is not a git repository" in errors[0], errors
    print("check-claims: selftest ok")


def main():
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        return 0
    strict_windows = "--strict-windows" in sys.argv[1:]
    repo = ROOT
    if "--repo" in sys.argv[1:]:
        repo = Path(sys.argv[sys.argv.index("--repo") + 1]).resolve()
    errors = warnings = 0
    for line in check_commits(repo, commit_docs(ROOT, repo)):
        print(line)
        errors += 1
    named_stages = stages()
    for name in STAGE_DOCS:
        for n, line in enumerate((ROOT / name).read_text().splitlines(), 1):
            for quoted in NAMED.findall(line):
                m = STAGE_NAMED.match(quoted)
                if not m:
                    continue
                script = m.group(1) + (m.group(2) or "")
                for word in re.split(r"[ ,/]+", m.group(3)):
                    if re.fullmatch(r"[a-z][a-z-]*", word) and word not in ("and", "or", "all") \
                            and word not in named_stages[script]:
                        print(f"error: {name}:{n} names `{quoted}`, but {script} has no stage {word}")
                        errors += 1
    known = known_tests()
    for name in NAMING:
        for n, line in enumerate((ROOT / name).read_text().splitlines(), 1):
            for quoted in NAMED.findall(line):
                for test in re.findall(r"\b(test_[a-z0-9_]+)", quoted):
                    # `test_api_profile_*`: a prefix.
                    if test in known or test.endswith("_") and any(k.startswith(test) for k in known):
                        continue
                    print(f"error: {name}:{n} names {test}, which no source, test file or baseline defines")
                    errors += 1
    for name in FILES:
        for n, column, text in cells(ROOT / name):
            claim = CLAIM.search(text)
            if not claim or EVIDENCE.search(text):
                continue
            windows = "windows" in column.lower()
            kind = "error" if strict_windows or not windows else "warning"
            print(f"{kind}: {name}:{n} [{column}] says \"{claim.group(0)}\" without naming the test that "
                  f"checks it: {text[:90]}...")
            if kind == "error":
                errors += 1
            else:
                warnings += 1
    print(f"check-claims: {errors} errors, {warnings} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
