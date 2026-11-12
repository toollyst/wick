#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The harness's memory readings without a VM.

    build/integration/venv/bin/python tools/macos/integration/memory-selftest.py [--wait-compressed SECONDS]

A helper process maps 64 MiB of private memory and writes every page; the
harness (wick_macos) reads it as upstream's tests would read a Firecracker:

- get_resident_memory is the task's resident size plus its compressed pages
  (TASK_VM_INFO) less the platform part (the dyld shared cache's pages,
  shared_cache_part, which the memory monitor counts apart), and the resident
  size is psutil's RSS;
- the platform part is held to its ceiling: over it, or with no ceiling
  measured for the macOS, get_resident_memory raises (the helper is Python,
  not Firecracker, so the ceiling is set from its own part for the other
  checks);
- each of memory_maps' mappings counts its present and its compressed pages
  (`rss` = `present` + `swapped`), and the helper's 64 MiB are in one;
- after the helper replaces the 64 MiB with fresh pages (mmap MAP_FIXED, as
  wick's MADV_DONTNEED of private memory does), both readings fall by them.

With --wait-compressed, the helper first waits, up to SECONDS, for the host
to compress at least half of the 64 MiB (nothing here makes memory pressure:
the host's own), and the checks also run while the pages are compressed: the
mapping's compressed pages and the ledger's agree, get_resident_memory still
counts the 64 MiB, and the replacement takes them out of the ledger too. A
host that compresses nothing in the time fails that check, saying so.
"""

import argparse
import ctypes
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TESTS = ROOT / "lib/firecracker/tests"
MIB = 1 << 20
SIZE = 64 * MIB

# The helper: maps SIZE private bytes, writes each page, reports, then
# waits for a line on stdin: "replace" maps fresh pages over them (as
# wick's MADV_DONTNEED of private memory does), "exit" ends.
HELPER = r"""
import ctypes, mmap, sys, time
lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
lib.mmap.restype = ctypes.c_void_p
lib.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
SIZE = @SIZE@
PROT = mmap.PROT_READ | mmap.PROT_WRITE
FLAGS = mmap.MAP_PRIVATE | mmap.MAP_ANON
addr = lib.mmap(None, SIZE, PROT, FLAGS, -1, 0)
page = mmap.PAGESIZE
buf = (ctypes.c_uint64 * (SIZE // 8)).from_address(addr)
for off in range(0, SIZE, page):
    for i in range(0, page // 8, 64):
        buf[(off // 8) + i] = off * 0x9E3779B97F4A7C15 % (1 << 64) + i
print(f"{addr:#x}", flush=True)
for line in sys.stdin:
    if line.strip() == "replace":
        new = lib.mmap(addr, SIZE, PROT, FLAGS | 0x10, -1, 0)  # MAP_FIXED
        print("replaced" if new == addr else f"mmap failed {ctypes.get_errno()}", flush=True)
    else:
        break
""".replace("@SIZE@", str(SIZE))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--wait-compressed", type=int, metavar="SECONDS")
    args = ap.parse_args()
    work = tempfile.mkdtemp(prefix="wick-memory-selftest.")
    os.environ.setdefault("WICK_IT_ROOT", work)
    os.environ.setdefault("WICK_IT_BINARY_DIR", os.path.join(work, "bin"))
    os.chdir(TESTS)
    sys.path[:0] = [str(TESTS), str(ROOT / "tools/macos/integration")]
    import psutil  # pylint: disable=import-outside-toplevel
    import wick_macos as w  # pylint: disable=import-outside-toplevel

    failures = []

    def check(what, ok, detail):
        print(f"{'ok  ' if ok else 'FAIL'} {what}: {detail}")
        if not ok:
            failures.append(what)

    helper = subprocess.Popen([sys.executable, "-I", "-c", HELPER], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        addr = int(helper.stdout.readline(), 16)
        proc = psutil.Process(helper.pid)

        cache = w.shared_cache_part(w.memory_maps(proc, grouped=False))
        check("the helper maps the dyld shared cache", cache > 0, f"{cache >> 10} KiB")
        for ceiling, error, what in ((None, RuntimeError, "no ceiling measured"),
                                     (cache - (64 << 10), w._memory.MemoryUsageExceededError, "over the ceiling")):  # pylint: disable=protected-access
            w.SHARED_CACHE_CEILING = ceiling
            try:
                w.get_resident_memory(proc)
                raised = None
            except Exception as err:  # pylint: disable=broad-except
                raised = err
            check(f"{what}: get_resident_memory raises", isinstance(raised, error), repr(raised)[:160])
        w.SHARED_CACHE_CEILING = cache + MIB

        def readings(label):
            for _ in range(5):
                maps = w.memory_maps(proc, grouped=False)
                info = w._task_vm_info(helper.pid)  # pylint: disable=protected-access
                rss = w.get_resident_memory(proc)
                again = w.memory_maps(proc, grouped=False)
                if w.shared_cache_part(again) == w.shared_cache_part(maps):
                    break
            part = w.shared_cache_part(maps)
            region = next((m for m in maps if m.addr <= addr < m.addr + m.size), None)
            check(f"{label}: get_resident_memory is resident + compressed - the shared cache's part",
                  rss == (info["resident"] + info["compressed"] - part) // 1024,
                  f"{rss} KiB; resident {info['resident'] >> 10}, compressed {info['compressed'] >> 10}, "
                  f"shared cache {part >> 10} KiB")
            check(f"{label}: every mapping's rss is present + swapped", all(m.rss == m.present + m.swapped for m in maps),
                  f"{len(maps)} mappings")
            return info, rss, region

        info, rss, region = readings("written")
        check("written: psutil's RSS is the resident size", proc.memory_info().rss == info["resident"],
              f"{proc.memory_info().rss >> 10} KiB")
        check("written: the 64 MiB are held", region is not None and region.rss >= SIZE,
              f"mapping rss {region.rss >> 10 if region else None} KiB")
        if args.wait_compressed:
            deadline = time.monotonic() + args.wait_compressed
            while w._task_vm_info(helper.pid)["compressed"] < SIZE // 2 and time.monotonic() < deadline:  # pylint: disable=protected-access
                time.sleep(5)
            cinfo, crss, cregion = readings("compressed")
            check("compressed: the host compressed at least half of the 64 MiB", cinfo["compressed"] >= SIZE // 2,
                  f"{cinfo['compressed'] >> 10} KiB compressed after up to {args.wait_compressed} s")
            cmaps = w.memory_maps(proc, grouped=False)
            check("compressed: the mappings' compressed pages are the ledger's",
                  abs(sum(m.swapped for m in cmaps) - cinfo["compressed"]) <= 4 * MIB,
                  f"mappings {sum(m.swapped for m in cmaps) >> 10} KiB (the 64 MiB's "
                  f"{cregion.swapped >> 10 if cregion else None}), ledger {cinfo['compressed'] >> 10} KiB")
            check("compressed: get_resident_memory still counts the 64 MiB", crss >= SIZE // 1024,
                  f"{crss} KiB (resident {cinfo['resident'] >> 10})")
            check("compressed: the mapping's rss still counts the 64 MiB", cregion is not None and cregion.rss >= SIZE,
                  f"{cregion.rss >> 10 if cregion else None} KiB")
            rss, info, region = crss, cinfo, cregion
        helper.stdin.write("replace\n")
        helper.stdin.flush()
        check("replace: the helper mapped fresh pages", helper.stdout.readline().strip() == "replaced", "mmap MAP_FIXED")
        rinfo, rrss, rregion = readings("replaced")
        check("replaced: get_resident_memory fell by the 64 MiB", rss - rrss >= SIZE // 1024 - 1024,
              f"{rss} -> {rrss} KiB")
        check("replaced: the 64 MiB's compressed pages left the ledger with them",
              info["compressed"] - rinfo["compressed"] >= region.swapped - MIB,
              f"ledger {info['compressed'] >> 10} -> {rinfo['compressed'] >> 10} KiB, "
              f"the 64 MiB held {region.swapped >> 10} KiB compressed")
        check("replaced: the mapping holds nothing", rregion is not None and rregion.rss < MIB,
              f"{rregion.rss >> 10 if rregion else None} KiB")
    finally:
        helper.kill()
        helper.wait()
    if failures:
        sys.exit(f"FAIL: {len(failures)} check(s): {', '.join(failures)}")
    print("memory-selftest: all checks passed")


if __name__ == "__main__":
    main()
