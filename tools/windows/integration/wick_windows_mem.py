# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""psutil's `Process.memory_maps` as upstream's memory monitor reads it.

Linux: /proc/<pid>/smaps, one entry per mapping (an mmap) with its size and
its resident size. psutil's Windows `memory_maps` lists file-backed regions
only, without a size. Here a mapping is a Windows allocation (one
VirtualAlloc or MapViewOfFile: the regions that share an AllocationBase),
its size what the allocation spans, its resident size the pages of it in
the process's working set (QueryWorkingSetEx).

Linux's Firecracker is one static binary; on Windows it runs with the
system's DLLs (ntdll, kernel32, ws2_32, WinHvPlatform) and the system's
files they map (the locale's NLS tables). Their pages, the ones a process
writes too (a DLL's data), count as the system's, not Firecracker's, as
Linux counts no page of a library Firecracker does not have: a mapping
whose file is in the Windows directory is left out. Measured on a booted
guest with a network interface: 4.1 MiB with them, of which 1.8 MiB is
Firecracker's own image and 0.5 MiB the system's.
"""

import ctypes
import os
from ctypes import wintypes

import psutil

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x400, 0x10
MEM_COMMIT, MEM_FREE, MEM_IMAGE = 0x1000, 0x10000, 0x1000000
PAGE = 4096


class _MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]


class _WSEX(ctypes.Structure):
    _fields_ = [("VirtualAddress", ctypes.c_void_p), ("VirtualAttributes", ctypes.c_size_t)]


_k32.OpenProcess.restype = wintypes.HANDLE
_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(_MBI), ctypes.c_size_t]
_k32.VirtualQueryEx.restype = ctypes.c_size_t
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_psapi.QueryWorkingSetEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
_psapi.GetMappedFileNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]


def _system_dir_device():
    """The Windows directory as a mapped file's name gives it (\\Device\\...)."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    buf = ctypes.create_unicode_buffer(1024)
    if not _k32.QueryDosDeviceW(root[:2], buf, 1024):
        return root.lower()
    return (buf.value + root[2:]).lower() + "\\"


_SYSTEM = _system_dir_device()


class MemoryMap:
    """What psutil's memory_maps(grouped=False) gives on Linux, for one mapping."""

    def __init__(self, handle, path, addr, size, committed, image, kind=0):
        self.path, self.addr, self.size = path, addr, size
        self._handle, self._committed, self._image = handle, committed, image
        self.kind = kind  # MEM_PRIVATE, MEM_MAPPED or MEM_IMAGE
        self._rss = None

    @property
    def rss(self):
        """Resident bytes (Linux: smaps' Rss), measured when asked: the
        monitor asks only for what is not guest memory."""
        if self._rss is None:
            self._rss = self._resident()
        return self._rss

    def _resident(self):
        if self.path.lower().startswith(_SYSTEM):
            return 0
        total = 0
        for base, size in self._committed:
            n = size // PAGE
            entries = (_WSEX * n)()
            for i in range(n):
                entries[i].VirtualAddress = base + i * PAGE
            if not _psapi.QueryWorkingSetEx(self._handle, entries, ctypes.sizeof(entries)):
                continue
            for e in entries:
                if e.VirtualAttributes & 1:  # Valid: in the working set
                    total += PAGE
        return total


class _Maps(list):
    """The list, and the process handle its entries measure through."""

    def __init__(self, handle, maps):
        super().__init__(maps)
        self._handle = handle

    def __del__(self):
        _k32.CloseHandle(self._handle)


def memory_maps(self, grouped=True):
    """`psutil.Process.memory_maps` with Linux's sizes (see the module)."""
    if grouped:
        raise NotImplementedError("memory_maps(grouped=True): upstream reads the ungrouped list only")
    handle = _k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid)
    if not handle:
        if not psutil.pid_exists(self.pid):
            raise psutil.NoSuchProcess(self.pid)
        raise psutil.AccessDenied(self.pid)
    maps, addr, mbi = [], 0, _MBI()
    current = None  # [base, end, committed regions, type]
    name = ctypes.create_unicode_buffer(1024)
    while _k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base, size = mbi.BaseAddress or 0, mbi.RegionSize
        if mbi.State != MEM_FREE:
            alloc = mbi.AllocationBase or 0
            if current is None or current[0] != alloc:
                if current is not None:
                    maps.append(current)
                current = [alloc, base + size, [], mbi.Type]
            current[1] = base + size
            if mbi.State == MEM_COMMIT:
                current[2].append((base, size))
        addr = base + size
        if addr >= 1 << 47:
            break
    if current is not None:
        maps.append(current)
    out = []
    for alloc, end, committed, kind in maps:
        path = ""
        if _psapi.GetMappedFileNameW(handle, ctypes.c_void_p(alloc), name, 1024):
            path = name.value
        out.append(MemoryMap(handle, path, alloc, end - alloc, committed, kind == MEM_IMAGE, kind))
    return _Maps(handle, out)


def resident_kib(pid):
    """What upstream's `utils.get_resident_memory` reads on Linux: the
    process's resident memory (VmRSS) plus its hugetlbfs pages
    (HugetlbPages, which Linux counts apart), in KiB. Here every page of the
    process in its working set, large pages included (QueryWorkingSetEx
    reports each 4 KiB of one as valid), the system's files too, as VmRSS
    counts every mapping."""
    total = 0
    maps = memory_maps(psutil.Process(pid), grouped=False)
    for m in maps:
        system, m.path = m.path, ""  # count the system's files too
        total += m.rss
        m.path = system
    return total // 1024


MEM_PRIVATE, MEM_MAPPED = 0x20000, 0x40000


def proc_status(pid):
    """Linux's /proc/<pid>/status, the fields upstream's tests read, from the
    process's mappings: RssAnon is resident private memory, RssShmem shared
    memory no file backs (a memfd), RssFile what images and files back. A
    Windows process has no seccomp mode or PID namespace to show."""
    p = psutil.Process(pid)
    anon = shmem = files = 0
    for m in memory_maps(p, grouped=False):
        system, m.path = m.path, ""  # count the system's files too, as Linux does
        rss = m.rss
        m.path = system
        if m.kind == MEM_PRIVATE:
            anon += rss
        elif m.kind == MEM_MAPPED and not system:
            shmem += rss
        else:
            files += rss
    name = p.name().removesuffix(".exe")
    kib = lambda n: f"{n // 1024} kB"  # noqa: E731
    return "".join([
        f"Name:\t{name}\n",
        f"Pid:\t{pid}\n",
        f"PPid:\t{p.ppid()}\n",
        f"VmRSS:\t{kib(anon + shmem + files)}\n",
        f"RssAnon:\t{kib(anon)}\n",
        f"RssFile:\t{kib(files)}\n",
        f"RssShmem:\t{kib(shmem)}\n",
        f"Threads:\t{p.num_threads()}\n",
    ])


def install():
    """Makes psutil.Process.memory_maps this one, and upstream's resident
    memory reading (framework.utils.get_resident_memory) read it."""
    psutil.Process.memory_maps = memory_maps
    try:
        import framework.utils as utils  # pylint: disable=import-outside-toplevel
    except ImportError:  # outside upstream's tests (selftest.py)
        return
    utils.get_resident_memory = lambda process: resident_kib(process.pid)
