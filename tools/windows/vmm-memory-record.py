# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A record of what Firecracker's own memory is made of on Windows.

Upstream's integration tests allow the VMM 5 MiB of resident memory besides
its guest's (tests/host_tools/memory.py). On Windows it is 5.0 to 5.6 MiB with
16 vCPUs (tools/windows/integration-test-differences.txt, "Firecracker's
memory beyond its guest's"), counted as tools/windows/integration/
wick_windows_mem.py counts it: every page in the working set of every
allocation that is neither guest memory nor a file of the Windows directory.
This script prints that count by what the pages are, for a started microVM
with 1, 2 and 16 vCPUs, so that what can be cut is read, not guessed:

    python -I tools/windows/vmm-memory-record.py <firecracker.exe> [vcpus ...]

It needs WHP and nothing else: the guest is a kernel of its own making, an
ELF of one segment whose code is `hlt` in a loop, started with `--no-api
--config-file` (no drive, no network interface). So the figures are those of
a guest that has touched no device; a booted Linux guest adds what its
devices' queues take. A record: it prints VMMMEM lines and fails only when
Firecracker does not start.

Kinds:
  image       firecracker.exe's own pages: code (executable), private (pages
              it wrote: data and relocations, not shared with the file) and
              the rest (read-only data, shared)
  stacks      the allocations that are a thread's stack (TEB DeallocationStack)
  heaps       the allocations a heap of the process starts in (PEB ProcessHeaps)
  private     other private memory: later heap segments, large allocations,
              VirtualAlloc'd buffers, TEBs and the PEB
  mapped      sections that are neither the guest's memory nor a system file
Not counted by the tests, printed beside them: the guest's memory, and the
system's DLLs and files (their private pages too).
"""

import ctypes
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes

PAGE = 4096
GUEST_MIB = 128
MEM_COMMIT, MEM_FREE = 0x1000, 0x10000
MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE = 0x20000, 0x40000, 0x1000000
PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x400, 0x10
THREAD_QUERY_INFORMATION = 0x40
TH32CS_SNAPTHREAD = 0x4
# QueryWorkingSetEx's attributes (PSAPI_WORKING_SET_EX_BLOCK).
WS_VALID, WS_SHARED = 1, 1 << 15
# Win32Protection values that can execute (PAGE_EXECUTE*), in bits 4 to 14.
EXECUTE = 0x10 | 0x20 | 0x40 | 0x80


def kernel_elf():
    """An ELF64 x86-64 executable of one PT_LOAD segment at 1 MiB, where
    Firecracker's loader wants a kernel (linux-loader's Elf::load: at or
    above the start of high memory), whose entry is `hlt; jmp -3`."""
    code = b"\xf4\xeb\xfd" + b"\x90" * 13
    load = 0x100000
    ehdr_size, phdr_size = 64, 56
    offset = ehdr_size + phdr_size
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,  # ELF64, little endian, version 1
        2,       # ET_EXEC
        62,      # EM_X86_64
        1, load, ehdr_size, 0, 0, ehdr_size, phdr_size, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, offset, load, load, len(code), len(code), 0x1000)  # PT_LOAD, R+X
    return ehdr + phdr + code


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]


class WSEX(ctypes.Structure):
    _fields_ = [("VirtualAddress", ctypes.c_void_p), ("VirtualAttributes", ctypes.c_size_t)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD), ("tpBasePri", wintypes.LONG),
                ("tpDeltaPri", wintypes.LONG), ("dwFlags", wintypes.DWORD)]


class THREAD_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("ExitStatus", wintypes.LONG), ("TebBaseAddress", ctypes.c_void_p),
                ("UniqueProcess", ctypes.c_void_p), ("UniqueThread", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_size_t), ("Priority", wintypes.LONG), ("BasePriority", wintypes.LONG)]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p), ("BasePriority", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_void_p), ("InheritedFromUniqueProcessId", ctypes.c_void_p)]


def bind():
    """The Windows calls used, with their types."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenThread.restype = wintypes.HANDLE
    k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    k32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    k32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    psapi.QueryWorkingSetEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    psapi.GetMappedFileNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    ntdll.NtQueryInformationThread.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                               ctypes.POINTER(wintypes.ULONG)]
    ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                ctypes.POINTER(wintypes.ULONG)]
    return k32, psapi, ntdll


def system_dir_device(k32):
    """The Windows directory as a mapped file's name gives it (\\Device\\...),
    as wick_windows_mem.py's."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    buf = ctypes.create_unicode_buffer(1024)
    if not k32.QueryDosDeviceW(root[:2], buf, 1024):
        return root.lower()
    return (buf.value + root[2:]).lower() + "\\"


def read(k32, handle, addr, size):
    """`size` bytes of the process at `addr`, or None."""
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)) or got.value != size:
        return None
    return buf.raw


def thread_ids(k32, pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    ids = []
    ok = k32.Thread32First(snap, ctypes.byref(entry))
    while ok:
        if entry.th32OwnerProcessID == pid:
            ids.append(entry.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(entry))
    k32.CloseHandle(snap)
    return ids


def stacks_and_tebs(k32, ntdll, handle, pid):
    """Each thread's stack allocation (TEB.DeallocationStack, offset 0x1478
    on x86-64) and its TEB's address."""
    stacks, tebs = set(), set()
    for tid in thread_ids(k32, pid):
        t = k32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
        if not t:
            continue
        info = THREAD_BASIC_INFORMATION()
        status = ntdll.NtQueryInformationThread(t, 0, ctypes.byref(info), ctypes.sizeof(info), None)
        k32.CloseHandle(t)
        if status != 0 or not info.TebBaseAddress:
            continue
        tebs.add(info.TebBaseAddress)
        raw = read(k32, handle, info.TebBaseAddress + 0x1478, 8)
        if raw:
            stacks.add(struct.unpack("<Q", raw)[0])
    return stacks, tebs


def heap_bases(k32, ntdll, handle):
    """The process's heaps (PEB.NumberOfHeaps at 0xE8, PEB.ProcessHeaps at
    0xF0 on x86-64): each is the address its first segment starts at."""
    info = PROCESS_BASIC_INFORMATION()
    if ntdll.NtQueryInformationProcess(handle, 0, ctypes.byref(info), ctypes.sizeof(info), None) != 0:
        return set(), 0
    peb = info.PebBaseAddress or 0
    raw = read(k32, handle, peb + 0xE8, 16)
    if not raw:
        return set(), peb
    count, _, array = struct.unpack("<IIQ", raw)
    raw = read(k32, handle, array, 8 * count) if 0 < count < 4096 else None
    return (set(struct.unpack(f"<{count}Q", raw)) if raw else set()), peb


def allocations(k32, psapi, handle):
    """Every allocation of the process: (base, size, type, path, pages), with
    `pages` the attributes of each page in the working set."""
    out, addr, mbi = [], 0, MBI()
    current = None
    while k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base, size = mbi.BaseAddress or 0, mbi.RegionSize
        if mbi.State != MEM_FREE:
            alloc = mbi.AllocationBase or 0
            if current is None or current[0] != alloc:
                if current is not None:
                    out.append(current)
                current = [alloc, base + size, mbi.Type, []]
            current[1] = base + size
            if mbi.State == MEM_COMMIT:
                current[3].append((base, size))
        addr = base + size
        if addr >= 1 << 47:
            break
    if current is not None:
        out.append(current)
    name = ctypes.create_unicode_buffer(1024)
    result = []
    for alloc, end, kind, committed in out:
        path = name.value if psapi.GetMappedFileNameW(handle, ctypes.c_void_p(alloc), name, 1024) else ""
        pages = []
        # The guest's memory is not walked page by page: it is not counted.
        if end - alloc < GUEST_MIB << 20:
            for base, size in committed:
                n = size // PAGE
                entries = (WSEX * n)()
                for i in range(n):
                    entries[i].VirtualAddress = base + i * PAGE
                if psapi.QueryWorkingSetEx(handle, entries, ctypes.sizeof(entries)):
                    pages += [e.VirtualAttributes for e in entries if e.VirtualAttributes & WS_VALID]
        result.append((alloc, end - alloc, kind, path, pages))
    return result


def measure(k32, psapi, ntdll, pid, system):
    """The working set by kind, in bytes, and the allocations behind it."""
    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess")
    try:
        stacks, tebs = stacks_and_tebs(k32, ntdll, handle, pid)
        heaps, _peb = heap_bases(k32, ntdll, handle)
        kinds = {k: 0 for k in ("image code", "image private", "image rest", "stacks", "heaps", "private",
                                "mapped", "system image private", "system rest", "guest")}
        rows = []
        for base, size, kind, path, pages in allocations(k32, psapi, handle):
            rss = len(pages) * PAGE
            system_file = path.lower().startswith(system)
            if size >= GUEST_MIB << 20:
                what = "guest"
            elif kind == MEM_IMAGE and not system_file:
                for a in pages:
                    if not a & WS_SHARED:
                        kinds["image private"] += PAGE
                    elif (a >> 4) & 0x7FF & EXECUTE:
                        kinds["image code"] += PAGE
                    else:
                        kinds["image rest"] += PAGE
                rows.append((rss, "image", base, size, path))
                continue
            elif system_file:
                private = sum(PAGE for a in pages if not a & WS_SHARED)
                kinds["system image private"] += private
                kinds["system rest"] += rss - private
                continue
            elif kind == MEM_PRIVATE and base in stacks:
                what = "stacks"
            elif kind == MEM_PRIVATE and base in heaps:
                what = "heaps"
            elif kind == MEM_PRIVATE:
                what = "private"
            else:
                what = "mapped"
            kinds[what] += rss
            rows.append((rss, what, base, size, path))
        return kinds, rows, len(stacks), len(tebs)
    finally:
        k32.CloseHandle(handle)


COUNTED = ("image code", "image private", "image rest", "stacks", "heaps", "private", "mapped")


def run_case(binds, firecracker, vcpus, work, system):
    k32, psapi, ntdll = binds
    kernel = os.path.join(work, "hlt-kernel.elf")
    with open(kernel, "wb") as f:
        f.write(kernel_elf())
    config = os.path.join(work, f"config-{vcpus}.json")
    with open(config, "w", encoding="utf-8") as f:
        json.dump({"boot-source": {"kernel_image_path": kernel},
                   "machine-config": {"vcpu_count": vcpus, "mem_size_mib": GUEST_MIB},
                   "drives": []}, f)
    err_path = os.path.join(work, f"stderr-{vcpus}.txt")
    with open(err_path, "wb") as err:
        proc = subprocess.Popen([firecracker, "--no-api", "--config-file", config],
                                stdin=subprocess.PIPE, stdout=err, stderr=err)
    try:
        # Started: one thread per vCPU besides the main one, and the count
        # the same over a second. A state that is waited for, up to 30 s.
        deadline, last, same = time.monotonic() + 30, -1, 0
        while same < 10:
            if proc.poll() is not None or time.monotonic() > deadline:
                with open(err_path, "r", encoding="utf-8", errors="replace") as f:
                    tail = " | ".join(f.read().splitlines()[-5:])
                state = f"exited with {proc.returncode}" if proc.poll() is not None else "did not settle in 30 s"
                print(f"VMMMEM vcpus={vcpus}: Firecracker {state}: {tail}")
                return None
            n = len(thread_ids(k32, proc.pid))
            same = same + 1 if (n == last and n > vcpus) else 0
            last = n
            time.sleep(0.1)
        kinds, rows, stacks, threads = measure(k32, psapi, ntdll, proc.pid, system)
        counted = sum(kinds[k] for k in COUNTED)
        parts = ", ".join(f"{k} {kinds[k] // 1024}" for k in COUNTED)
        print(f"VMMMEM vcpus={vcpus} threads={threads} stacks={stacks} counted={counted // 1024} KiB: {parts}; "
              f"not counted: system image private {kinds['system image private'] // 1024}, "
              f"system rest {kinds['system rest'] // 1024}")
        for rss, what, base, size, path in sorted(rows, reverse=True)[:12]:
            print(f"VMMMEM vcpus={vcpus}   {what:8} {base:#014x} size {size // 1024:8} KiB resident {rss // 1024:6} KiB"
                  f" {os.path.basename(path)}")
        return kinds
    finally:
        proc.kill()
        proc.wait()


def main():
    if os.name != "nt":
        raise SystemExit("vmm-memory-record.py runs on Windows")
    firecracker = os.path.abspath(sys.argv[1])
    counts = [int(a) for a in sys.argv[2:]] or [1, 2, 16]
    binds = bind()
    system = system_dir_device(binds[0])
    results = {}
    with tempfile.TemporaryDirectory(prefix="wick-vmmmem-") as work:
        for vcpus in counts:
            results[vcpus] = run_case(binds, firecracker, vcpus, work, system)
    if any(r is None for r in results.values()):
        raise SystemExit("VMMMEM: a Firecracker did not start")
    lo, hi = min(counts), max(counts)
    if hi > lo:
        per = ", ".join(f"{k} {(results[hi][k] - results[lo][k]) / 1024 / (hi - lo):.1f}" for k in COUNTED)
        print(f"VMMMEM each vCPU from {lo} to {hi} adds, KiB: {per}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--kernel":
        # The guest alone, for a look at it: python vmm-memory-record.py --kernel out.elf
        with open(sys.argv[2], "wb") as out:
            out.write(kernel_elf())
    else:
        main()
