#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""What a tracked file may not say, and the shape of the docs' tables.

    tools/check-tree.py              (CI's patches job)
    tools/check-tree.py --selftest

- No tracked file (patches/*.patch included) names the directory the
  agents keep their notes in (NOTES below), which is not in the
  repository: a pointer there sends a reader to a file they cannot open.
  A measurement says what it was (a test's name, a standalone probe, by
  hand) instead.
- Every row of a Markdown table in a tracked .md file has its header's
  number of cells and ends in `|`. A row cut short, or one whose cell
  lost its closing `|` (5859a449's docs/COMPATIBILITY.md :229, the
  self-test's fixture), renders
  as a different table, or as no table, while every check that reads the
  row's text still passes. Cells are split as GitHub splits them: at
  every `|` not escaped as `\\|`, inside code spans too. Rows in fenced
  code blocks are not tables.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Spelled in two pieces so that this file does not name it.
NOTES = "agent" + "-state"


def tracked(root):
    """The tracked files, as paths relative to `root`."""
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


def cells(row):
    """The cells of a table row, as GitHub splits them; None if the row does
    not end in `|`."""
    row = row.strip()
    if not row.endswith("|") or row.endswith("\\|"):
        return None
    return re.split(r"(?<!\\)\|", row[1:-1])


def table_errors(name, text):
    """(line, message) for each table row of `text` whose shape is wrong."""
    errors = []
    header = None
    fence = None
    for n, line in enumerate(text.split("\n"), 1):
        stripped = line.lstrip()
        m = re.match(r"(`{3,}|~{3,})", stripped)
        if m:
            if fence is None:
                fence = m.group(1)[0] * len(m.group(1))
            elif stripped.startswith(fence):
                fence = None
            header = None
            continue
        if fence is not None or not stripped.startswith("|"):
            header = None
            continue
        got = cells(stripped)
        if header is None:
            header = (n, len(got) if got is not None else None)
            if got is None:
                errors.append((n, f"{name}:{n}: a table's header row does not end in `|`"))
            continue
        if got is None:
            errors.append((n, f"{name}:{n}: a table row does not end in `|`"))
        elif header[1] is not None and len(got) != header[1]:
            errors.append(
                (n, f"{name}:{n}: a table row has {len(got)} cells where its header (line {header[0]}) has {header[1]}")
            )
    return errors


def check(root):
    errors = []
    for path in tracked(root):
        p = root / path
        if not p.is_file() or p.is_symlink():
            continue
        data = p.read_bytes()
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", errors="replace")
        for n, line in enumerate(text.split("\n"), 1):
            if NOTES in line:
                errors.append(f"{path}:{n}: names {NOTES}, which is not in the repository: {line.strip()[:160]}")
        if path.endswith(".md"):
            errors += [e for _, e in table_errors(path, text)]
    return errors


def selftest():
    good = "| a | b |\n| --- | --- |\n| `x \\| y` | z |\n"
    cases = [
        ("a well-formed table, an escaped `|` in a code span", good, []),
        ("a row with a cell too many", good + "| p | q | r |\n", [4]),
        ("a row with a cell too few", good + "| p |\n", [4]),
        ("a row that does not end in `|`", good + "| p | q\n", [4]),
        ("an unescaped `|` in a code span splits the cell, as on GitHub", good + "| `p | q` | r |\n", [4]),
        ("a fenced block is not a table", good + "```\n| p |\n```\n", []),
        ("a blank line starts another table", good + "\n| p |\n| --- |\n| q |\n", []),
    ]
    fails = 0
    for name, text, want in cases:
        got = [n for n, _ in table_errors("selftest.md", text)]
        if got != want:
            fails += 1
            print(f"selftest FAIL: {name}: rows {got}, wanted {want}")
    # The row this check was written for, cut to a few words a cell: the
    # header, the separator and docs/COMPATIBILITY.md :229 as they stood in
    # 5859a449 (lines 225, 226 and 229 there), with its pipes where they
    # were: the Windows cell's text went on past its closing `|` with a
    # sentence of its own and no `|` at the end.
    row = (
        "| Feature | macOS | Windows |\n"
        "| --- | --- | --- |\n"
        "| `mem_backend: Uffd` | 🟡 the kernel side of userfaultfd is rebuilt in user space "
        "| 🟡 the same, on Windows (`boot-test.ps1 uffd`) passed. "
        "| Not as Linux yet, fix in progress (SECURITY.md, \"Not at parity yet\"): "
        "`test_a_cut_of_a_registered_huge_page_is_einval` has nothing to cut.\n"
    )
    got = table_errors("COMPATIBILITY.md", row)
    if [n for n, _ in got] != [3] or "does not end in `|`" not in got[0][1]:
        fails += 1
        print(f"selftest FAIL: 5859a449's row: {got}")
    # The name, in a tracked file and in a patch.
    with __import__("tempfile").TemporaryDirectory() as tmp:
        t = Path(tmp)
        subprocess.run(["git", "init", "-q", str(t)], check=True)
        (t / "patches").mkdir()
        (t / "patches" / "0001-x.patch").write_text(f"+// see {NOTES}/x.c\n")
        (t / "a.rs").write_text("// fine\n")
        (t / "b.md").write_text(f"measured ({NOTES} probe)\n")
        subprocess.run(["git", "-C", str(t), "add", "."], check=True)
        got = sorted(e.split(":")[0] for e in check(t))
        if got != ["b.md", "patches/0001-x.patch"]:
            fails += 1
            print(f"selftest FAIL: the name in tracked files: {got}")
    if fails:
        sys.exit(f"check-tree: selftest: {fails} failed")
    print(f"check-tree: selftest ok ({len(cases) + 2} cases)")


def main():
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        return
    if sys.argv[1:]:
        sys.exit(__doc__.split("\n")[2].strip())
    errors = check(ROOT)
    for e in errors:
        print(f"::error::{e}")
    print(f"check-tree: {len(errors)} errors")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
