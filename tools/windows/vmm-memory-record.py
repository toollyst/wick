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
              and the heaps' later segments (an allocation that starts with
              a heap segment's header naming one of those heaps)
  private     other private memory: large allocations, VirtualAlloc'd
              buffers, TEBs and the PEB (an allocation that holds threads'
              TEBs is marked with their number)
  mapped      sections that are neither the guest's memory nor a system file
Not counted by the tests, printed beside them: the guest's memory, and the
system's DLLs and files (their private pages too).

The `hlt` guest runs one vCPU: the others wait for a start-up IPI that never
comes, and no device is touched. The tests that fail boot Linux with a
network interface, and there each vCPU costs about 147 KiB (78 of it stack)
where the `hlt` guest's cost 60 (16.5 of stack). What a running vCPU's thread
does with its stack is the second mode's record:

    python -I tools/windows/vmm-memory-record.py --boot <dir> <firecracker.exe> [vcpus ...]

It boots upstream's CI kernel and root file system (the ones boot-test.ps1
boots; downloaded into <dir> when not there, about 145 MB) with a network
interface nothing is connected to, waits for the guest's shell on the serial
console, has it count its processors and send a few frames, and then prints,
besides the VMMMEM lines:

  VMMSTACK ... thread=   one line per thread: its name, the stack reserved,
              committed and resident, how deep the lowest resident page is
              and how deep the thread is now (its stack pointer)
  VMMSTACK ... frame     for the deepest thread of each kind and the median
              one: every value on the resident pages of its stack that is an
              address in an image right after a call instruction, that is
              each return address a call left there, live or stale, from the
              stack's base down: its depth, the distance from the one above
              (the size of the frame of the function it returns into), the
              module and offset, and the nearest symbol when dbghelp finds
              one (firecracker.pdb beside firecracker.exe names
              Firecracker's own; a system DLL has its exports). A release
              build has no PDB of Firecracker's own functions: `--map
              <file>` before the other arguments names them from the
              linker's map of the same build (link.exe /MAP), whose
              addresses are the image's

After the cases, VMMGROW lines say which allocations the per-vCPU growth is
in: the allocations of each kind grouped by size (and mark), with their
number and resident memory in the case with the fewest vCPUs and in the one
with the most, for every group that differs.

The offsets are symbolized again anywhere with the PDB beside the binary:
`llvm-symbolizer --relative-address -f -C -e firecracker.exe 0x<offset>`.
A value that only looks like a return address is listed too: the chain is
read by a person. `--selftest` checks the parts that need no Windows.
"""

import ctypes
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from ctypes import wintypes

PAGE = 4096
GUEST_MIB = 128
# Upstream's CI artifacts, as tools/windows/boot-test.ps1 has them.
S3 = "https://s3.amazonaws.com/spec.ccfc.min"
PREFIX = "firecracker-ci/20261105-6ea6634994fa-0/x86_64"
KERNEL_NAME, ROOTFS_NAME = "vmlinux-6.1.188", "ubuntu-24.04.squashfs"
BOOT_ARGS = ("console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd "
             "root=/dev/vda ro rootfstype=squashfs init=/bin/sh")
GUEST_MAC = "06:00:ac:10:00:02"
THREAD_SUSPEND_RESUME, THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION = 0x2, 0x8, 0x800
# CONTEXT on x86-64 (winnt.h): 1232 bytes, 16-byte aligned; ContextFlags at
# 0x30, Rsp at 0x98, Rip at 0xF8. CONTEXT_CONTROL of CONTEXT_AMD64.
CONTEXT_SIZE, CONTEXT_FLAGS_AT, CONTEXT_RSP_AT, CONTEXT_RIP_AT = 1232, 0x30, 0x98, 0xF8
CONTEXT_CONTROL = 0x100001
# TEB on x86-64: NT_TIB.StackBase, NT_TIB.StackLimit, DeallocationStack.
TEB_STACK_BASE, TEB_STACK_LIMIT, TEB_DEALLOCATION_STACK = 0x8, 0x10, 0x1478
FRAME_LINES = 400
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
    k32.SuspendThread.restype = wintypes.DWORD
    k32.SuspendThread.argtypes = [wintypes.HANDLE]
    k32.ResumeThread.restype = wintypes.DWORD
    k32.ResumeThread.argtypes = [wintypes.HANDLE]
    k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.LocalFree.restype = ctypes.c_void_p
    k32.LocalFree.argtypes = [ctypes.c_void_p]
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


# An NT heap's later segments start with a _HEAP_SEGMENT: its signature
# 0xFFEEFFEE at offset 0x10 and its heap's address at 0x18 (x86-64; the
# public symbols of ntdll, as WinDbg's `dt ntdll!_HEAP_SEGMENT` prints
# them). The heap's first segment is the heap itself, with the same header.
HEAP_SEGMENT_SIGNATURE = 0xFFEEFFEE


def heap_of_segment(header, heaps):
    """The heap a private allocation is a segment of, from the allocation's
    first 0x20 bytes, or None: the signature, and a heap of the process."""
    if not header or len(header) < 0x20:
        return None
    signature, = struct.unpack_from("<I", header, 0x10)
    heap, = struct.unpack_from("<Q", header, 0x18)
    return heap if signature == HEAP_SEGMENT_SIGNATURE and heap in heaps else None


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
            elif kind == MEM_PRIVATE and heap_of_segment(read(k32, handle, base, 0x20), heaps) is not None:
                what = "heaps"
                path = f"(a later segment of the heap at {heap_of_segment(read(k32, handle, base, 0x20), heaps):#x})"
            elif kind == MEM_PRIVATE:
                what = "private"
                held = sum(1 for t in tebs if base <= t < base + size)
                if held:
                    path = f"({held} TEBs)"
            else:
                what = "mapped"
            kinds[what] += rss
            rows.append((rss, what, base, size, path))
        return kinds, rows, len(stacks), len(tebs)
    finally:
        k32.CloseHandle(handle)


COUNTED = ("image code", "image private", "image rest", "stacks", "heaps", "private", "mapped")
# The allocations of each case, for the VMMGROW lines.
ROWS = {}


def mark_of(path):
    """A row's mark without what differs from case to case: an address, a
    count."""
    return re.sub(r"0x[0-9a-f]+|\d+", "N", os.path.basename(path))


def growth_lines(low, high, vcpus):
    """Which allocations differ between two cases' rows: per kind, size and
    mark, the number of allocations and their resident bytes in each, for
    the groups that differ, the largest difference first."""
    def groups(rows):
        out = {}
        for rss, what, _base, size, path in rows:
            n, total = out.get((what, size, mark_of(path)), (0, 0))
            out[(what, size, mark_of(path))] = (n + 1, total + rss)
        return out

    a, b = groups(low), groups(high)
    lines = []
    for key in set(a) | set(b):
        (n0, r0), (n1, r1) = a.get(key, (0, 0)), b.get(key, (0, 0))
        if (n0, r0) != (n1, r1):
            what, size, mark = key
            lines.append((abs(r1 - r0), f"{what} of {size // 1024} KiB{' ' + mark if mark else ''}: {n0} with "
                          f"{r0 // 1024} KiB resident, then {n1} with {r1 // 1024} KiB: each vCPU adds "
                          f"{(n1 - n0) / vcpus:.2f} allocations and {(r1 - r0) / 1024 / vcpus:.1f} KiB"))
    return [line for _d, line in sorted(lines, reverse=True)]


# --- a thread's stack: what is resident and which calls left it so ----------

def call_length(modrm, sib):
    """The length of an indirect call `FF /2` with this ModRM byte (and SIB
    byte, where it has one), or 0 if the ModRM is not a call's."""
    if (modrm >> 3) & 7 != 2:
        return 0
    mod, rm = modrm >> 6, modrm & 7
    if mod == 3:
        return 2
    length = 2 + (1 if rm == 4 else 0) + (0, 1, 4)[mod]
    if mod == 0 and (rm == 5 or (rm == 4 and sib & 7 == 5)):
        length += 4
    return length


def after_a_call(before):
    """Whether the bytes right before an address end in a call instruction:
    `E8 rel32`, or `FF /2` in any of its forms. A return address is such an
    address; a value that is one by chance passes too."""
    if len(before) >= 5 and before[-5] == 0xE8:
        return True
    for n in (2, 3, 4, 6, 7):
        if len(before) >= n and before[-n] == 0xFF:
            sib = before[-n + 2] if n > 2 else 0
            if call_length(before[-n + 1], sib) == n:
                return True
    return False


def module_of(modules, value):
    """The image (base, end, name) an address is in, or None. `modules` is
    sorted by base."""
    lo, hi = 0, len(modules)
    while lo < hi:
        mid = (lo + hi) // 2
        if modules[mid][0] <= value:
            lo = mid + 1
        else:
            hi = mid
    if lo and value < modules[lo - 1][1]:
        return modules[lo - 1]
    return None


def return_addresses(pages, modules, code_before):
    """Every 8-byte value on a stack's pages that is an address in an image
    right after a call: (slot, value, module name, offset in the module),
    from the highest slot down. `pages` maps a page's address to its bytes;
    `code_before(value)` gives the 7 bytes before an address, or None."""
    found = []
    for base in sorted(pages, reverse=True):
        data = pages[base]
        values = struct.unpack(f"<{len(data) // 8}Q", data[:len(data) // 8 * 8])
        for i in range(len(values) - 1, -1, -1):
            value = values[i]
            module = module_of(modules, value)
            if module is None:
                continue
            before = code_before(value)
            if before and after_a_call(before):
                found.append((base + i * 8, value, module[2], value - module[0]))
    return found


def kind_of(name):
    """A thread's kind: its name without its number ("fc_vcpu 3" and
    "fc_vcpu 11" are one kind)."""
    return re.sub(r"[\s_-]*\d+$", "", name) or "(unnamed)"


def thread_name(k32, tid):
    """The thread's description (SetThreadDescription, which Rust's std
    calls with a thread's name), or ""."""
    get = getattr(k32, "GetThreadDescription", None)
    if get is None:
        return ""
    t = k32.OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, tid)
    if not t:
        return ""
    try:
        text = ctypes.c_void_p()
        get.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
        get.restype = ctypes.c_long
        if get(t, ctypes.byref(text)) < 0 or not text.value:
            return ""
        name = ctypes.wstring_at(text.value)
        k32.LocalFree(text)
        return name
    finally:
        k32.CloseHandle(t)


def stack_pointer(k32, tid):
    """The thread's (Rsp, Rip) now, read while it is suspended for the read,
    or None."""
    t = k32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, tid)
    if not t:
        return None
    try:
        if k32.SuspendThread(t) == 0xFFFFFFFF:
            return None
        try:
            buf = ctypes.create_string_buffer(CONTEXT_SIZE + 16)
            at = (-ctypes.addressof(buf)) % 16
            struct.pack_into("<I", buf, at + CONTEXT_FLAGS_AT, CONTEXT_CONTROL)
            if not k32.GetThreadContext(t, ctypes.c_void_p(ctypes.addressof(buf) + at)):
                return None
            return (struct.unpack_from("<Q", buf, at + CONTEXT_RSP_AT)[0],
                    struct.unpack_from("<Q", buf, at + CONTEXT_RIP_AT)[0])
        finally:
            k32.ResumeThread(t)
    finally:
        k32.CloseHandle(t)


def thread_stacks(k32, psapi, ntdll, handle, pid):
    """Every thread's stack: a dict per thread with its id, name, the
    stack's allocation (`low`), base (`high`, where it starts) and limit
    (the lowest committed address), the addresses of its resident pages,
    and its stack pointer."""
    out = []
    for tid in thread_ids(k32, pid):
        t = k32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
        if not t:
            continue
        info = THREAD_BASIC_INFORMATION()
        status = ntdll.NtQueryInformationThread(t, 0, ctypes.byref(info), ctypes.sizeof(info), None)
        k32.CloseHandle(t)
        teb = info.TebBaseAddress
        if status != 0 or not teb:
            continue
        tib = read(k32, handle, teb, 0x18)
        low = read(k32, handle, teb + TEB_DEALLOCATION_STACK, 8)
        if not tib or not low:
            continue
        high, limit = struct.unpack_from("<QQ", tib, TEB_STACK_BASE)
        low = struct.unpack("<Q", low)[0]
        if not low < high or high - low > 1 << 30:
            continue
        n = (high - low) // PAGE
        entries = (WSEX * n)()
        for i in range(n):
            entries[i].VirtualAddress = low + i * PAGE
        resident = []
        if psapi.QueryWorkingSetEx(handle, entries, ctypes.sizeof(entries)):
            resident = [low + i * PAGE for i, e in enumerate(entries) if e.VirtualAttributes & WS_VALID]
        out.append({"tid": tid, "name": thread_name(k32, tid), "low": low, "high": high, "limit": limit,
                    "resident": resident, "context": stack_pointer(k32, tid)})
    return out


def dos_paths(k32):
    """Each drive's device name ("\\Device\\HarddiskVolume3") to its letter,
    to turn a mapped file's name into a path."""
    out, buf = {}, ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if k32.QueryDosDeviceW(letter + ":", buf, 1024):
            out[buf.value.lower()] = letter + ":"
    return out


def dos_path(drives, device_path):
    lower = device_path.lower()
    for device, letter in drives.items():
        if lower.startswith(device + "\\"):
            return letter + device_path[len(device):]
    return device_path


class SYMBOL_INFOW(ctypes.Structure):
    # dbghelp.h; ULONG and WCHAR by their Windows sizes, so that the layout
    # is the same wherever the self-test runs.
    _fields_ = [("SizeOfStruct", ctypes.c_uint32), ("TypeIndex", ctypes.c_uint32),
                ("Reserved", ctypes.c_uint64 * 2), ("Index", ctypes.c_uint32), ("Size", ctypes.c_uint32),
                ("ModBase", ctypes.c_uint64), ("Flags", ctypes.c_uint32), ("Value", ctypes.c_uint64),
                ("Address", ctypes.c_uint64), ("Register", ctypes.c_uint32), ("Scope", ctypes.c_uint32),
                ("Tag", ctypes.c_uint32), ("NameLen", ctypes.c_uint32), ("MaxNameLen", ctypes.c_uint32),
                ("Name", ctypes.c_uint16 * 1)]


# The image's functions from link.exe's map of it: `--map`.
MAP = []


def parse_map(text):
    """link.exe /MAP: the symbols with their addresses relative to the
    image's base, sorted. A line is ` 0001:00000010  name  0000000140001010
    f  lib:object`; the base is the "Preferred load address"."""
    base = re.search(r"Preferred load address is ([0-9A-Fa-f]+)", text)
    if not base:
        return []
    base = int(base.group(1), 16)
    out = []
    for m in re.finditer(r"^ [0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s", text, re.M):
        rva = int(m.group(2), 16) - base
        if rva > 0:
            out.append((rva, m.group(1)))
    return sorted(out)


def map_name(symbols, rva):
    """The symbol at or below `rva`, as `name+0x<distance>`; "" before the first."""
    import bisect  # pylint: disable=import-outside-toplevel

    i = bisect.bisect_right(symbols, (rva, "\U0010ffff")) - 1
    return f"{symbols[i][1]}+{rva - symbols[i][0]:#x}" if i >= 0 else ""


def symbol_text(chars, name_len, max_len):
    """SYMBOL_INFO's name from the `max_len` characters of its Name buffer:
    `NameLen` of them, "not including the null-terminating character"
    (Microsoft Learn, SYMBOL_INFO), at most the buffer's `MaxNameLen`, and
    ended at the first NUL. A name longer than the buffer (a vm-memory
    iterator's, on a PC) came back with a NameLen past the buffer, and the
    characters read past it were whatever the memory there held, which a
    cp949 console could not print."""
    return chars[:min(name_len, max_len)].split("\0", 1)[0]


class Symbols:
    """dbghelp's nearest symbol for an address in one of the process's
    images: a PDB beside the image names its functions (firecracker.pdb),
    and an image without one has its exports. Without dbghelp, or for an
    address it has nothing for, the answer is ""."""

    MAX_NAME = 1024

    def __init__(self, k32, modules):
        self.handle, self.dbghelp, self.note = ctypes.c_void_p(0x5749434B), None, ""
        self.mapped = next(((base, end) for base, end, name, _path in modules
                            if MAP and name.lower() == "firecracker.exe"), None)
        try:
            dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
            dbghelp.SymSetOptions.restype = wintypes.DWORD
            dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
            dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
            dbghelp.SymLoadModuleExW.restype = ctypes.c_uint64
            dbghelp.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR,
                                                 wintypes.LPCWSTR, ctypes.c_uint64, wintypes.DWORD,
                                                 ctypes.c_void_p, wintypes.DWORD]
            dbghelp.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
                                             ctypes.c_void_p]
            dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
            # SYMOPT_UNDNAME, SYMOPT_DEFERRED_LOADS, SYMOPT_FAIL_CRITICAL_ERRORS, SYMOPT_NO_PROMPTS.
            dbghelp.SymSetOptions(0x2 | 0x4 | 0x200 | 0x80000)
            if not dbghelp.SymInitializeW(self.handle, None, False):
                self.note = f"SymInitializeW failed, error {ctypes.get_last_error()}"
                return
            drives, loaded = dos_paths(k32), 0
            for base, end, _name, path in modules:
                if dbghelp.SymLoadModuleExW(self.handle, None, dos_path(drives, path), None, base, end - base, None, 0):
                    loaded += 1
            self.dbghelp = dbghelp
            self.note = f"dbghelp loaded {loaded} of {len(modules)} images"
        except (OSError, AttributeError) as e:
            self.note = f"no dbghelp: {e}"

    def name(self, address):
        if self.mapped and self.mapped[0] <= address < self.mapped[1]:
            return map_name(MAP, address - self.mapped[0])
        if self.dbghelp is None:
            return ""
        buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + 2 * self.MAX_NAME)
        info = SYMBOL_INFOW.from_buffer(buf)
        info.SizeOfStruct, info.MaxNameLen = ctypes.sizeof(SYMBOL_INFOW), self.MAX_NAME
        displacement = ctypes.c_uint64()
        if not self.dbghelp.SymFromAddrW(self.handle, address, ctypes.byref(displacement), ctypes.addressof(buf)):
            return ""
        chars = ctypes.wstring_at(ctypes.addressof(buf) + SYMBOL_INFOW.Name.offset, self.MAX_NAME)
        return f"{symbol_text(chars, info.NameLen, self.MAX_NAME)}+{displacement.value:#x}"

    def close(self):
        if self.dbghelp is not None:
            self.dbghelp.SymCleanup(self.handle)


def frame_lines(found, high, rsp, symbol):
    """The lines of a stack's return addresses, from its base down: depth
    below the base, distance from the one above (about the frame of the
    function this one returns into), whether the slot is above the stack
    pointer (live) or below it (left by an earlier, deeper call), module and
    offset, symbol."""
    lines, above = [], high
    for slot, value, module, offset in found:
        state = "" if rsp is None else (" live" if slot >= rsp else " stale")
        name = symbol(value)
        lines.append(f"depth {high - slot:#8x} frame {above - slot:#7x}{state} {module}+{offset:#x}"
                     + (f" {name}" if name else ""))
        above = slot
    return lines


def largest_frames(found, high, symbol, count=12):
    """The largest distances between a return address and the one above it:
    (bytes, depth, module+offset, symbol), largest first."""
    out, above = [], high
    for slot, value, module, offset in found:
        out.append((above - slot, high - slot, f"{module}+{offset:#x}", symbol(value)))
        above = slot
    return sorted(out, reverse=True)[:count]


def record_stacks(binds, pid, vcpus, rows, chains):
    """The VMMSTACK lines of a process: every thread's stack, and the return
    addresses on the stacks of the deepest and the median thread of each
    kind when `chains`."""
    k32, psapi, ntdll = binds
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    handle = k32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess")
    try:
        threads = thread_stacks(k32, psapi, ntdll, handle, pid)
        by_kind = {}
        for t in threads:
            by_kind.setdefault(kind_of(t["name"]), []).append(t)
        tag = f"VMMSTACK vcpus={vcpus}"
        for kind in sorted(by_kind):
            group = sorted(by_kind[kind], key=lambda t: len(t["resident"]))
            total = sum(len(t["resident"]) for t in group) * PAGE // 1024
            print(f"{tag} kind={kind!r}: {len(group)} threads, {total} KiB resident")
            for t in group:
                lowest = min(t["resident"]) if t["resident"] else t["high"]
                now = "not read" if t["context"] is None else f"{(t['high'] - t['context'][0]) / 1024:.1f} KiB"
                print(f"{tag} thread={t['name'] or '(unnamed)'!r} tid={t['tid']} reserved "
                      f"{(t['high'] - t['low']) // 1024} KiB, committed {(t['high'] - t['limit']) // 1024} KiB, "
                      f"resident {len(t['resident']) * PAGE // 1024} KiB, lowest resident page "
                      f"{(t['high'] - lowest) // 1024} KiB deep, stack pointer {now} deep")
        if not chains:
            return
        modules = sorted((base, base + size, os.path.basename(path), path)
                         for _rss, what, base, size, path in rows if what == "image" and path)
        modules += sorted((base, base + size, os.path.basename(path), path)
                          for base, size, path in system_images(k32, psapi, handle))
        modules.sort()
        symbols = Symbols(k32, modules)
        print(f"{tag} symbols: {symbols.note}"
              + (f"; firecracker.exe from the linker's map, {len(MAP)} symbols" if symbols.mapped else ""))
        code = {}

        def code_before(value):
            if value not in code:
                code[value] = read(k32, handle, value - 7, 7)
            return code[value]

        try:
            for kind in sorted(by_kind):
                group = sorted(by_kind[kind], key=lambda t: len(t["resident"]))
                chosen = [group[-1]] + ([group[len(group) // 2]] if len(group) > 2 else [])
                for which, t in zip(("deepest", "median"), chosen):
                    pages = {}
                    for page in t["resident"]:
                        data = read(k32, handle, page, PAGE)
                        if data:
                            pages[page] = data
                    found = return_addresses(pages, [m[:3] for m in modules], code_before)
                    rsp = t["context"][0] if t["context"] else None
                    head = f"{tag} thread={t['name'] or '(unnamed)'!r} ({which} of {kind!r})"
                    print(f"{head}: {len(found)} return addresses on {len(pages)} resident pages")
                    for size, depth, where, name in largest_frames(found, t["high"], symbols.name):
                        print(f"{head} largest frame {size:#x} at depth {depth:#x} {where} {name}")
                    lines = frame_lines(found, t["high"], rsp, symbols.name)
                    for line in lines[:FRAME_LINES]:
                        print(f"{head} frame {line}")
                    if len(lines) > FRAME_LINES:
                        print(f"{head}: {len(lines) - FRAME_LINES} more, not printed")
        finally:
            symbols.close()
    finally:
        k32.CloseHandle(handle)


def system_images(k32, psapi, handle):
    """The images `measure` leaves out of its rows (the Windows directory's
    DLLs): (base, size, path)."""
    system = system_dir_device(k32)
    return [(base, size, path) for base, size, kind, path, _pages in allocations(k32, psapi, handle)
            if kind == MEM_IMAGE and path.lower().startswith(system)]


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
        ROWS[vcpus] = rows
        for rss, what, base, size, path in sorted(rows, reverse=True)[:12]:
            print(f"VMMMEM vcpus={vcpus}   {what:8} {base:#014x} size {size // 1024:8} KiB resident {rss // 1024:6} KiB"
                  f" {os.path.basename(path)}")
        return kinds
    finally:
        proc.kill()
        proc.wait()


def asset(directory, name):
    """Upstream's CI artifact `name` in `directory`, downloaded if not there."""
    path = os.path.join(directory, name)
    if not os.path.exists(path):
        print(f"VMMMEM downloading {S3}/{PREFIX}/{name}", flush=True)
        with urllib.request.urlopen(f"{S3}/{PREFIX}/{name}", timeout=120) as src, open(path + ".part", "wb") as dst:
            while True:
                block = src.read(1 << 20)
                if not block:
                    break
                dst.write(block)
        os.replace(path + ".part", path)
    return path


class Console:
    """The guest's serial console: Firecracker's standard input and the file
    its standard output goes to."""

    def __init__(self, proc, path):
        self.proc, self.path = proc, path

    def text(self):
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def send(self, line):
        try:
            self.proc.stdin.write(line.encode() + b"\n")
            self.proc.stdin.flush()
        except OSError:
            # Firecracker has exited: the wait that follows says so.
            pass

    def wait(self, pattern, seconds, again=None):
        """The match of `pattern` in the console's text, waited for up to
        `seconds`; `again`, a line, is sent each second until then (a shell
        that is not reading yet loses what it is sent). None when the time
        is up or Firecracker has exited."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and self.proc.poll() is None:
            found = re.search(pattern, self.text())
            if found:
                return found
            if again is not None:
                self.send(again)
            time.sleep(1)
        return re.search(pattern, self.text())


def run_boot_case(binds, firecracker, vcpus, work, system, kernel, rootfs, chains):
    """A microVM that boots Linux with a network interface: the VMMMEM lines
    of `run_case`, then the VMMSTACK lines. The kinds, or None when
    Firecracker exits or the guest's shell does not answer."""
    endpoint = os.path.join(work, f"n{vcpus}.ep")
    config = os.path.join(work, f"boot-{vcpus}.json")
    with open(config, "w", encoding="utf-8") as f:
        json.dump({"boot-source": {"kernel_image_path": kernel, "boot_args": BOOT_ARGS},
                   "machine-config": {"vcpu_count": vcpus, "mem_size_mib": GUEST_MIB},
                   "drives": [{"drive_id": "rootfs", "path_on_host": rootfs, "is_root_device": True,
                               "is_read_only": True}],
                   "network-interfaces": [{"iface_id": "eth0", "host_dev_name": endpoint,
                                           "guest_mac": GUEST_MAC}]}, f)
    out_path, err_path = os.path.join(work, f"serial-{vcpus}.txt"), os.path.join(work, f"stderr-{vcpus}.txt")
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        proc = subprocess.Popen([firecracker, "--no-api", "--config-file", config],
                                stdin=subprocess.PIPE, stdout=out, stderr=err)
    tag = f"VMMMEM boot vcpus={vcpus}"

    def tail(path, lines=6):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return " | ".join(line.strip() for line in f.read().splitlines()[-lines:])

    def reports_and_traces():
        # What Firecracker itself reported while the guest ran (a report is
        # made on the thread it is about, and costs that thread stack): on
        # its standard error, and in its log, which without a log file is
        # on its standard output, among the console's lines.
        reports = []
        for path in (err_path, out_path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                reports += [line for line in f.read().splitlines()
                            if "whp:" in line or ":WARN:" in line or ":ERROR:" in line]
        print(f"{tag} Firecracker's own reports: {len(reports)} lines with whp:, :WARN: or :ERROR:"
              + "".join(f" | {line.strip()[:200]}" for line in reports[:5]))
        # A build with kvm-ioctls' whp-trace feature prints each WHP call
        # that committed 16 KiB or more of its thread's stack; any other
        # build prints none (0 lines).
        with open(err_path, "r", encoding="utf-8", errors="replace") as f:
            traces = [line.strip() for line in f.read().splitlines() if line.startswith("WHPTRACE")]
        print(f"{tag} WHPTRACE lines: {len(traces)}")
        for line in traces[:64]:
            print(f"{tag} {line[:800]}")

    reported = False
    try:
        console = Console(proc, out_path)
        # The shell answers: the sum is the shell's, not the line's echo.
        started = time.monotonic()
        up = console.wait(r"WICK-42-UP", 300, again="echo WICK-$((6*7))-UP")
        if not up:
            state = f"exited with {proc.returncode}" if proc.poll() is not None else "has no shell after 300 s"
            print(f"{tag}: the guest {state}; serial: {tail(out_path)}; stderr: {tail(err_path)}")
            return None
        booted = time.monotonic() - started
        console.send("mount -t proc proc /proc; echo WICK-CPUS=$(grep -c ^processor /proc/cpuinfo)")
        cpus = console.wait(r"WICK-CPUS=(\d+)", 60)
        # Frames with nobody to take them: the interface up, an address, a
        # few pings of a neighbour that is not there (each an ARP request).
        console.send("ip link set eth0 up; ip addr add 192.168.241.2/30 dev eth0; "
                     "ping -c 3 -W 1 192.168.241.1; echo WICK-$((6*7))-SENT")
        sent = console.wait(r"WICK-42-SENT", 60)
        time.sleep(2)
        if proc.poll() is not None:
            print(f"{tag}: Firecracker exited with {proc.returncode}; stderr: {tail(err_path)}")
            return None
        kinds, rows, stacks, threads = measure(binds[0], binds[1], binds[2], proc.pid, system)
        counted = sum(kinds[k] for k in COUNTED)
        parts = ", ".join(f"{k} {kinds[k] // 1024}" for k in COUNTED)
        print(f"{tag} threads={threads} stacks={stacks} counted={counted // 1024} KiB: {parts}; "
              f"not counted: system image private {kinds['system image private'] // 1024}, "
              f"system rest {kinds['system rest'] // 1024}; the guest's shell after {booted:.0f} s, "
              f"processors online {cpus.group(1) if cpus else 'not read'}, frames sent: {bool(sent)}")
        ROWS[vcpus] = rows
        for rss, what, base, size, path in sorted(rows, reverse=True)[:12]:
            print(f"{tag}   {what:8} {base:#014x} size {size // 1024:8} KiB resident {rss // 1024:6} KiB"
                  f" {os.path.basename(path)}")
        # Read before the stacks, whose walk can fail: the work directory
        # goes with this run, and with it Firecracker's output.
        reported = True
        reports_and_traces()
        record_stacks(binds, proc.pid, vcpus, rows, chains)
        return kinds
    finally:
        # On every way out, a failure's included, if not read yet.
        if not reported:
            reports_and_traces()
        proc.kill()
        proc.wait()


def selftest():
    """The parts that need no Windows."""
    assert kernel_elf()[:4] == b"\x7fELF"
    # call rel32; call rax; call [rax]; call [rip+d32]; call [rax+d8]; call [rsp+d8]; call [rax+d32];
    # call [rsp+d32]; call [r12] (REX.B before FF); and bytes that are no call.
    calls = ["e8 00 00 00 00", "ff d0", "ff 10", "ff 15 00 00 00 00", "ff 50 08", "ff 54 24 08",
             "ff 90 00 01 00 00", "ff 94 24 00 01 00 00", "41 ff 14 24"]
    for text in calls:
        assert after_a_call(bytes.fromhex("90 90 90 90 90 90" + text)[-7:]), text
    for text in ["90 90 90 90 90 90 90", "ff e0", "ff 30", "48 89 c8", "ff 15 00 00"]:
        assert not after_a_call(bytes.fromhex("31 c0 31 c0 31 c0 31" + text)[-7:]), text
    assert kind_of("fc_vcpu 11") == kind_of("fc_vcpu 3") == "fc_vcpu"
    assert kind_of("whp-tsc-deadline") == "whp-tsc-deadline" and kind_of("") == "(unnamed)"
    modules = [(0x1000, 0x3000, "a.exe"), (0x7000, 0x8000, "b.dll")]
    assert module_of(modules, 0x1000) == modules[0] and module_of(modules, 0x2fff) == modules[0]
    assert module_of(modules, 0x3000) is None and module_of(modules, 0x7abc) == modules[1]
    assert module_of(modules, 0xfff) is None and module_of([], 5) is None
    # A stack of two pages: a return address into each module, a pointer
    # into a.exe that follows no call, and other values.
    code = {0x1234: bytes.fromhex("90 90 e8 00 00 00 00"), 0x7abc: bytes.fromhex("90 90 90 90 90 ff d0"),
            0x2000: bytes(7)}
    high = 0x90000
    top, deep = bytearray(PAGE), bytearray(PAGE)
    struct.pack_into("<Q", top, PAGE - 0x28, 0x1234)
    struct.pack_into("<Q", top, PAGE - 0x100, 0x2000)
    struct.pack_into("<Q", top, 0x10, 0xdeadbeef)
    struct.pack_into("<Q", deep, 0x800, 0x7abc)
    pages = {high - PAGE: bytes(top), high - 3 * PAGE: bytes(deep)}
    found = return_addresses(pages, modules, code.get)
    assert found == [(high - 0x28, 0x1234, "a.exe", 0x234), (high - 3 * PAGE + 0x800, 0x7abc, "b.dll", 0xabc)], found
    lines = frame_lines(found, high, high - 0x1000, lambda value: "f+0x4" if value == 0x1234 else "")
    assert lines == ["depth     0x28 frame    0x28 live a.exe+0x234 f+0x4",
                     "depth   0x2800 frame  0x27d8 stale b.dll+0xabc"], lines
    assert largest_frames(found, high, lambda value: "")[0] == (0x27d8, 0x2800, "b.dll+0xabc", "")
    assert dos_path({"\\device\\harddiskvolume3": "C:"}, "\\Device\\HarddiskVolume3\\x\\a.exe") == "C:\\x\\a.exe"
    assert ctypes.sizeof(SYMBOL_INFOW) == 88 and SYMBOL_INFOW.Name.offset == 84
    # A name within the buffer; one longer than it, cut there; a NameLen
    # past a NUL, cut at the NUL.
    assert symbol_text("abc\0zzz", 3, 8) == "abc"
    assert symbol_text("abcdefgh", 4000, 8) == "abcdefgh"
    assert symbol_text("ab\0\ua390\u3000", 6, 8) == "ab"
    # A heap's later segment: the signature and a heap of the process.
    header = bytes(0x10) + struct.pack("<IIQ", HEAP_SEGMENT_SIGNATURE, 0, 0x1b935590000)
    assert heap_of_segment(header, {0x1b935590000}) == 0x1b935590000
    assert heap_of_segment(header, {0x5000}) is None and heap_of_segment(bytes(0x20), {0}) is None
    assert heap_of_segment(None, {0}) is None and heap_of_segment(header[:0x18], {0x1b935590000}) is None
    # What grows: a second stack-sized private allocation per vCPU, a heap segment that fills.
    one = [(40 << 10, "private", 0x1000, 64 << 10, ""), (96 << 10, "heaps", 0x2000, 1 << 20, "(a later segment of the heap at 0x9000)"),
           (8 << 10, "private", 0x3000, 2 << 20, "(10 TEBs)"), (4 << 10, "mapped", 0x4000, 4 << 10, "")]
    many = [(40 << 10, "private", 0x1000, 64 << 10, ""), (16 << 10, "private", 0x7000, 64 << 10, ""),
            (552 << 10, "heaps", 0x2000, 1 << 20, "(a later segment of the heap at 0x8000)"),
            (128 << 10, "private", 0x3000, 2 << 20, "(25 TEBs)"), (4 << 10, "mapped", 0x4000, 4 << 10, "")]
    assert growth_lines(one, many, 15) == [
        "heaps of 1024 KiB (a later segment of the heap at N): 1 with 96 KiB resident, then 1 with 552 KiB: "
        "each vCPU adds 0.00 allocations and 30.4 KiB",
        "private of 2048 KiB (N TEBs): 1 with 8 KiB resident, then 1 with 128 KiB: each vCPU adds 0.00 allocations and 8.0 KiB",
        "private of 64 KiB: 1 with 40 KiB resident, then 2 with 56 KiB: each vCPU adds 0.07 allocations and 1.1 KiB",
    ], growth_lines(one, many, 15)
    # link.exe's map.
    text = (" firecracker\n\n Preferred load address is 0000000140000000\n\n"
            "  Address         Publics by Value              Rva+Base               Lib:Object\n\n"
            " 0000:00000000       __guard_flags              0000000000000000     <absolute>\n"
            " 0001:00000000       _ZN3vmm7builder13build_microvm17h0123456789abcdefE 0000000140001000 f   vmm.o\n"
            " 0001:00000340       main                       0000000140001340 f   firecracker.o\n")
    symbols = parse_map(text)
    assert symbols == [(0x1000, "_ZN3vmm7builder13build_microvm17h0123456789abcdefE"), (0x1340, "main")], symbols
    assert map_name(symbols, 0x1000).endswith("E+0x0") and map_name(symbols, 0x133f).endswith("E+0x33f")
    assert map_name(symbols, 0x2000) == "main+0xcc0" and map_name(symbols, 0xfff) == "" and parse_map("x") == []
    print("vmm-memory-record.py: selftest ok")


def main(args):
    boot = None
    if args and args[0] == "--map":
        with open(args[1], "r", encoding="utf-8", errors="replace") as f:
            MAP[:] = parse_map(f.read())
        if not MAP:
            raise SystemExit(f"VMMMEM: {args[1]} is not a linker's map with symbols")
        args = args[2:]
    if args and args[0] == "--boot":
        boot, args = os.path.abspath(args[1]), args[2:]
    if not args:
        raise SystemExit(__doc__)
    if os.name != "nt":
        raise SystemExit("vmm-memory-record.py runs on Windows")
    firecracker = os.path.abspath(args[0])
    counts = [int(a) for a in args[1:]] or [1, 2, 16]
    binds = bind()
    system = system_dir_device(binds[0])
    results = {}
    with tempfile.TemporaryDirectory(prefix="wick-vmmmem-") as work:
        if boot is None:
            for vcpus in counts:
                results[vcpus] = run_case(binds, firecracker, vcpus, work, system)
        else:
            os.makedirs(boot, exist_ok=True)
            kernel, rootfs = asset(boot, KERNEL_NAME), asset(boot, ROOTFS_NAME)
            for vcpus in counts:
                # The return addresses of the case with the most vCPUs only.
                results[vcpus] = run_boot_case(binds, firecracker, vcpus, work, system, kernel, rootfs,
                                               chains=vcpus == max(counts))
    if any(r is None for r in results.values()):
        raise SystemExit("VMMMEM: a Firecracker did not start" if boot is None
                         else "VMMMEM: a guest did not boot to its shell")
    lo, hi = min(counts), max(counts)
    if hi > lo:
        per = ", ".join(f"{k} {(results[hi][k] - results[lo][k]) / 1024 / (hi - lo):.1f}" for k in COUNTED)
        print(f"VMMMEM{' boot' if boot else ''} each vCPU from {lo} to {hi} adds, KiB: {per}")
        for line in growth_lines(ROWS[lo], ROWS[hi], hi - lo):
            print(f"VMMGROW{' boot' if boot else ''} from {lo} to {hi} vCPUs: {line}")


if __name__ == "__main__":
    # Output never fails on a character: a console or a file the output is
    # redirected to has the ANSI code page (cp949, cp1252) unless Python is
    # run with -X utf8, which -I does not give (PYTHONUTF8 is an environment
    # variable), and a symbol name, a path or a program's output can hold
    # what that page has not (a WinHvPlatform symbol from dbghelp, U+A390,
    # ended vmm-memory-record.py on a PC). UTF-8, and what is not text
    # escaped.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    if len(sys.argv) > 1 and sys.argv[1] == "--kernel":
        # The guest alone, for a look at it: python vmm-memory-record.py --kernel out.elf
        with open(sys.argv[2], "wb") as out:
            out.write(kernel_elf())
    elif len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        selftest()
    else:
        main(sys.argv[1:])
