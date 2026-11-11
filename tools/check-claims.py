#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Every status claim in the docs' tables names the test that checks it.

A table cell in README.md, SECURITY.md or docs/ROADMAP.md that says a control
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
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ["README.md", "SECURITY.md", "docs/ROADMAP.md"]
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


def main():
    strict_windows = "--strict-windows" in sys.argv[1:]
    errors = warnings = 0
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
