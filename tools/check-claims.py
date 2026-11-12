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
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ["README.md", "SECURITY.md", "docs/ROADMAP.md", "docs/PORTING.md"]
# Also checked for the tests they name.
NAMING = FILES + ["docs/COMPATIBILITY.md"]
SOURCES = ["crates", "overlay", "tools", "fuzz", "patches", "lib/firecracker/src", "lib/firecracker/tests"]
SKIP_DIRS = {"target", "build", ".git", "__pycache__"}
DEFINED = re.compile(r"\b(?:fn|def|function)\s+(test_[A-Za-z0-9_]+)")
NAMED = re.compile(r"`([^`]*)`")
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


def main():
    strict_windows = "--strict-windows" in sys.argv[1:]
    errors = warnings = 0
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
