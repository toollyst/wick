#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Every number a document derives from the tree says what the tree says.

    tools/check-derived.py              (CI's patches job)
    tools/check-derived.py --selftest

Numbers other checks already keep (tools/patches.sh: README.md's and
docs/ARCHITECTURE.md's patch and file counts; tools/compat-counts.py:
docs/COMPATIBILITY.md's progress and test counts) are not checked again.
Here:
- README.md's "about N lines": the lines the patch series adds (each
  patches/*.patch's added lines), rounded to the hundred as written;
- docs/PORTING.md row 1's "N system calls, N Mach traps and N MIG routines":
  the entries of SYSCALLS, MACH_TRAPS and MIG_ROUTINES in
  overlay/vmm/ext/sandbox.rs.
A document that no longer says the number at all fails too, so the check
cannot pass by the sentence going away. A number a run measured is not one
of these: it names its run (docs drift kind a), not the tree.
"""

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def patch_added_lines(root):
    """The lines the series adds: every `+` line of patches/*.patch but the
    `+++` file headers."""
    total = 0
    for p in sorted((root / "patches").glob("*.patch")):
        for line in p.read_text(errors="replace").splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                total += 1
    return total


def sandbox_table(root, name):
    """The quoted entries of the `pub const NAME: &[&str]` table in
    overlay/vmm/ext/sandbox.rs, comments left out."""
    text = (root / "overlay/vmm/ext/sandbox.rs").read_text()
    m = re.search(r"pub const " + name + r": &\[&str\] = &\[(.*?)\n\s*\];", text, re.S)
    if not m:
        return None
    return len(re.findall(r'"[^"]*"', re.sub(r"//[^\n]*", "", m.group(1))))


def check(root):
    errors = []
    readme = (root / "README.md").read_text()
    said = re.search(r"\babout ([0-9][0-9,]*) lines in [0-9]+ files\b", readme)
    added = patch_added_lines(root)
    if not said:
        errors.append("README.md no longer says how many lines the patch series adds (\"about N lines in M files\")")
    else:
        n = int(said.group(1).replace(",", ""))
        if n != round(added, -2):
            errors.append(f"README.md says about {said.group(1)} lines, but the series adds {added} "
                          f"(about {round(added, -2):,})")
    porting = (root / "docs/PORTING.md").read_text()
    row = re.search(r"^\| 1 \|.*$", porting, re.M)
    said = row and re.search(r"(\d+) system calls, (\d+) Mach traps and (\d+) MIG routines", row.group(0))
    if not said:
        errors.append("docs/PORTING.md row 1 no longer says \"N system calls, N Mach traps and N MIG routines\"")
    else:
        for got, name, what in zip(said.groups(), ("SYSCALLS", "MACH_TRAPS", "MIG_ROUTINES"),
                                   ("system calls", "Mach traps", "MIG routines")):
            want = sandbox_table(root, name)
            if want is None:
                errors.append(f"overlay/vmm/ext/sandbox.rs has no table {name}")
            elif int(got) != want:
                errors.append(f"docs/PORTING.md row 1 says {got} {what}, but {name} in overlay/vmm/ext/sandbox.rs "
                              f"has {want}")
    return errors


def selftest():
    tmp = tempfile.TemporaryDirectory()

    def tree(readme, porting, syscalls, patches):
        d = Path(tempfile.mkdtemp(dir=tmp.name))
        (d / "patches").mkdir()
        (d / "overlay/vmm/ext").mkdir(parents=True)
        (d / "docs").mkdir()
        (d / "README.md").write_text(readme)
        (d / "docs/PORTING.md").write_text(porting)
        table = lambda name, n: f"    pub const {name}: &[&str] = &[\n" + "".join(
            f'        "c{i}", // why\n' for i in range(n)) + "    ];\n"
        (d / "overlay/vmm/ext/sandbox.rs").write_text(table("SYSCALLS", syscalls) + table("MACH_TRAPS", 2)
                                                     + table("MIG_ROUTINES", 1))
        for i, n in enumerate(patches):
            (d / "patches" / f"{i:04}-x.patch").write_text("+++ b/f\n" + "+x\n" * n + "-y\n")
        return d

    row = "| 1 | Allows | narrowed to {} system calls, 2 Mach traps and 1 MIG routines | x |\n"
    cases = [
        # Audit 3's left-open finding: README's "about 2,400 lines" was not
        # re-verified after patch edits; the series had grown.
        ("stale line count", tree("49 small patches (about 2,400 lines in 88 files)", row.format(3), 3,
                                  [1500, 1595]), 1),
        ("line count right", tree("(about 3,100 lines in 88 files)", row.format(3), 3, [1500, 1595]), 0),
        # A table that grew without the row.
        ("stale syscall count", tree("(about 100 lines in 1 files)", row.format(3), 4, [100]), 1),
        ("sentence gone", tree("small patches", row.format(3), 3, [100]), 1),
    ]
    fails = 0
    for name, root, want in cases:
        got = check(root)
        if len(got) != want:
            fails += 1
            print(f"selftest FAIL: {name}: {got}")
    tmp.cleanup()
    if fails:
        sys.exit(f"check-derived: selftest: {fails} failed")
    print(f"check-derived: selftest ok ({len(cases)} cases)")


def main():
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        return 0
    errors = check(ROOT)
    for e in errors:
        print(f"error: {e}")
    print(f"check-derived: {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
