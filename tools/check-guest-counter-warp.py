#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Rebuilds the machine code tools/guest-counter-warp.py carries (its CODE
# table) from tools/guest-counter-warp-loop.c and compares, byte for byte,
# for each machine: clang with the command below, then the .text section of
# the ELF object (read here; the object must have no relocation section, as
# the code runs wherever it is mapped).
#
#   clang -target <machine>-linux-gnu [-mno-outline-atomics] -O2
#         -fno-stack-protector -ffreestanding -fPIC
#         -fno-asynchronous-unwind-tables -c guest-counter-warp-loop.c
#
# -mno-outline-atomics is for aarch64 only: upstream clang's default for
# aarch64-linux-gnu turns the atomic exchange into a call to libgcc's
# __aarch64_swp8_acq, which the blob, run alone wherever it is mapped,
# cannot have; Apple clang's default does not, so the flag leaves its bytes
# as they were (the same object with and without it; with
# -moutline-atomics it makes that call too).
#
# The bytes were made with RECORDED_CLANG below. Another clang may emit other
# instructions for the same source: its bytes are then not comparable.
#   exit 0  every machine's bytes are the ones carried
#   exit 1  bytes differ though made by the recorded clang, or the object
#           has relocations, or the table cannot be read
#   exit 3  not checked, said on standard error: no clang on PATH, or a
#           clang other than the recorded one whose bytes differ or whose
#           object has relocations. Ubuntu clang version 18.1.3 (1ubuntu1),
#           the clang of Ubuntu 24.04 (in Docker, 2026-11-14), is such a
#           one: 297 x86_64 bytes, not 307, and 268 aarch64 bytes, not
#           276 (with no relocation now; without -mno-outline-atomics its
#           aarch64 object called __aarch64_swp8_acq, R_AARCH64_CALL26),
#           so CI's Linux runners cannot check the bytes and the check is
#           not a CI step; run it on a Mac with the recorded clang.
#   python3 tools/check-guest-counter-warp.py [--clang PATH]
import os
import re
import struct
import subprocess
import sys
import tempfile

RECORDED_CLANG = "Apple clang version 21.0.0 (clang-2100.4.1.1)"
MACHINE_FLAGS = {"x86_64": [], "aarch64": ["-mno-outline-atomics"]}
FLAGS = ["-O2", "-fno-stack-protector", "-ffreestanding", "-fPIC", "-fno-asynchronous-unwind-tables", "-c"]
TOOLS = os.path.dirname(os.path.abspath(__file__))


def sections(obj):
    """The ELF64 object's sections, by name: (offset, size)."""
    shoff = struct.unpack_from("<Q", obj, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", obj, 0x3A)
    heads = [struct.unpack_from("<IIQQQQIIQQ", obj, shoff + i * shentsize) for i in range(shnum)]
    names = heads[shstrndx][4]
    out = {}
    for h in heads:
        name = obj[names + h[0]:obj.index(b"\0", names + h[0])].decode()
        out[name] = (h[4], h[5])
    return out


def main(argv):
    clang = argv[argv.index("--clang") + 1] if "--clang" in argv else "clang"
    try:
        version = subprocess.run([clang, "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0].strip()
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"check-guest-counter-warp: SKIP: no clang ({clang}: {e}); the carried bytes are not checked", file=sys.stderr)
        return 3
    text = open(os.path.join(TOOLS, "guest-counter-warp.py"), encoding="utf-8").read()
    carried = dict(re.findall(r'"(x86_64|aarch64)": \("[A-Z_0-9]+", "([0-9a-f]+)"\)', text))
    if set(carried) != {"x86_64", "aarch64"}:
        print(f"check-guest-counter-warp: FAIL: the CODE table of guest-counter-warp.py has {sorted(carried)}")
        return 1
    differ = []
    other = version != RECORDED_CLANG
    with tempfile.TemporaryDirectory() as tmp:
        for machine in ("x86_64", "aarch64"):
            obj_path = os.path.join(tmp, machine + ".o")
            subprocess.run([clang, "-target", machine + "-linux-gnu", *MACHINE_FLAGS[machine], *FLAGS, os.path.join(TOOLS, "guest-counter-warp-loop.c"), "-o", obj_path], check=True)
            obj = open(obj_path, "rb").read()
            secs = sections(obj)
            relocs = [n for n in secs if n.startswith(".rel")]
            if relocs and other:
                print(f"check-guest-counter-warp: SKIP: {version} is not the recorded {RECORDED_CLANG} and its {machine} object has relocations {relocs}; not comparable", file=sys.stderr)
                return 3
            if relocs:
                print(f"check-guest-counter-warp: FAIL: {machine}: the object has relocations {relocs}")
                return 1
            off, size = secs[".text"]
            built = obj[off:off + size].hex()
            same = built == carried[machine]
            print(f"check-guest-counter-warp: {machine}: {size} bytes built, {len(carried[machine]) // 2} carried, {'the same' if same else 'DIFFERENT'}")
            if not same:
                differ.append(machine)
    if not differ:
        print(f"check-guest-counter-warp: pass: {version} builds the bytes carried")
        return 0
    if other:
        print(f"check-guest-counter-warp: SKIP: {version} is not the recorded {RECORDED_CLANG} and builds other bytes for {', '.join(differ)}; not comparable", file=sys.stderr)
        return 3
    print(f"check-guest-counter-warp: FAIL: the recorded clang builds other bytes for {', '.join(differ)}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
