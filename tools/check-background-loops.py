#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Every loop a shell tool starts in the background has an end.

    tools/check-background-loops.py [FILE...]     (default: the shell scripts under tools/)
    tools/check-background-loops.py --selftest

A loop left behind by a killed run keeps forking: on 2026-11-15 a shutdown
stall caught 375 orphaned bash loops (parent launchd) and about 1,600 sleep
processes alive within one second. So a background loop in tools/ must:

- carry a `# background loop:` comment in the six lines above it that says
  when it ends and its bound;
- test, in its loop condition, something that ends with its owner: the
  owner's pid (`kill -0`) or the owner's directory (`-d`);
- have a numeric bound in that condition (`-le N`, `-lt N`, `< N`).

A background block is a `( ... ) &` subshell, a loop ending `done &`, or a
`sh -c '...' ... &` script; a block that holds no `while`/`until` loop is
not a loop and is not checked. Grep-level, not a shell parser: what it cannot
place is reported as an error, never passed.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKGROUND = re.compile(r"(?<![&|])&\s*$")
LOOP = re.compile(r"\b(while|until)\b")
LIVENESS = re.compile(r"kill -0|\[\[? -d |\[ -d ")
BOUND = re.compile(r"(-le|-lt)\s+\"?\d+|<\s*\d+")


def shell_scripts():
    """The shell scripts under tools/ (by extension or shebang), Windows' excluded."""
    out = []
    for path in sorted((ROOT / "tools").rglob("*")):
        if not path.is_file() or "windows" in path.relative_to(ROOT).parts:
            continue
        if path.suffix in (".sh", ".bash"):
            out.append(path)
            continue
        if path.suffix == "":
            try:
                head = path.read_bytes()[:64]
            except OSError:
                continue
            if head.startswith(b"#!") and re.match(rb"#![^\n]*\b(ba)?sh\b", head):
                out.append(path)
    return out


def block_start(lines, end):
    """The first line of the background block that ends at `end`, or None."""
    text = lines[end].strip()
    indent = len(lines[end]) - len(lines[end].lstrip())
    if text.count("'") % 2:
        # The end of a quoted `sh -c '...'` script: back to the line that opens it.
        for i in range(end - 1, max(-1, end - 200), -1):
            if re.search(r"\bsh -c '", lines[i]):
                return i
        return None
    if text.startswith(")") or text.startswith("done"):
        opener = re.compile(r"^\s*\($" if text.startswith(")") else r"\b(while|until|for)\b")
        for i in range(end - 1, max(-1, end - 200), -1):
            line = lines[i]
            if len(line) - len(line.lstrip()) == indent and opener.search(line):
                return i
        return None
    return end  # one line: `cmd &`, `( ... ) &`, `sh -c '...' &`


def check_file(path, text=None):
    """Errors for the background loops of one script."""
    lines = (text if text is not None else path.read_text(errors="replace")).split("\n")
    errors = []
    for end, line in enumerate(lines):
        if line.lstrip().startswith("#") or not BACKGROUND.search(line):
            continue
        start = block_start(lines, end)
        name = f"{path}:{end + 1}"
        if start is None:
            errors.append(f"{name}: a background block whose start this check cannot find")
            continue
        block = lines[start:end + 1]
        loops = [l for l in block if LOOP.search(l) and not l.lstrip().startswith("#")]
        if not loops:
            continue
        above = "\n".join(lines[max(0, start - 6):start])
        if "# background loop:" not in above:
            errors.append(f"{name}: a background loop with no `# background loop:` comment above it (when it "
                          "ends, its bound)")
        for loop in loops:
            if not LIVENESS.search(loop):
                errors.append(f"{name}: background loop `{loop.strip()}` tests neither its owner's pid "
                              "(kill -0) nor its owner's directory (-d)")
            if not BOUND.search(loop):
                errors.append(f"{name}: background loop `{loop.strip()}` has no numeric bound")
    return errors


def selftest():
    cases = {
        "unbounded": ("(\n    while :; do sleep 0.2; done\n) &\n", 3),
        "no comment": ("(\n    while kill -0 $p && ((n++ < 5)); do sleep 1; done\n) &\n", 1),
        "no bound": ("# background loop: ends with p\n(\n    while kill -0 $p; do sleep 1; done\n) &\n", 1),
        "good": ("# background loop: ends with p; 5 rounds\n(\n    while kill -0 $p && ((n++ < 5)); do sleep 1; "
                 "done\n) &\n", 0),
        "one-line good": ("# background loop: ends with the batch; 720 rounds\n(n=0; while kill -0 $$ && "
                          "((n++ < 720)); do sleep 60; done) &\n", 0),
        "sh -c": ("# background loop: ends with the session; 3600 rounds\nnohup /bin/sh -c '\n  while [ -d \"$s\" ] "
                  "&& [ \"$((n += 1))\" -le 3600 ]; do sleep 1; done' x &\n", 0),
        "sh -c unbounded": ("nohup /bin/sh -c '\n  while true; do sleep 1; done' x &\n", 3),
        "done &": ("while :; do\n    sleep 1\ndone &\n", 3),
        "not a loop": ("sleep 600 &\npython3 -c 'print(1)' &\n", 0),
        "and-list": ("a && b\nc || d\n", 0),
    }
    fails = 0
    for name, (text, want) in cases.items():
        got = check_file(Path(name), text)
        if len(got) != want:
            fails += 1
            print(f"selftest FAIL: {name}: {len(got)} errors, wanted {want}: {got}")
    # The tree's own scripts pass, and a file under tools/ is found by its shebang.
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "x"
        p.write_text("#!/bin/sh\nwhile :; do sleep 1; done &\n")
        if len(check_file(p)) != 3:
            fails += 1
            print("selftest FAIL: a shebang script's loop")
    if fails:
        sys.exit(f"selftest: {fails} failed")
    print(f"selftest: ok ({len(cases) + 1} cases)")


def main():
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        return
    files = [Path(a) for a in sys.argv[1:]] or shell_scripts()
    errors = [e for f in files for e in check_file(f)]
    for e in errors:
        print(f"error: {e}")
    print(f"check-background-loops: {len(files)} scripts, {len(errors)} errors")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
