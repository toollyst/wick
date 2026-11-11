# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""`resource` for upstream's test framework on Windows, which has none.

Windows keeps no per-process resource limits (`getrlimit`, `setrlimit`):
a process's limits are its job's, which the jailer sets (`--cgroup`). What
upstream's tests limit in another process is its memory, `prlimit(pid,
RLIMIT_AS, ...)`, so that a large guest memory fails to map: here a job of
its own around that process (nested in the jailer's) with that much memory
per process. Windows limits the memory a process commits, not its address
space (it has no limit on that); Firecracker commits its guest memory as the
guest touches it (crates/compat/libc/src/windows_mm.rs), and maps what it
cannot reserve with ENOMEM, as on Linux. Every other call fails naming
what Windows lacks, as on macOS a call macOS cannot make does
(tools/macos/integration/wick_macos.py, `prlimit`).
"""

import ctypes
import errno
from ctypes import wintypes

RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK, RLIMIT_CORE = 0, 1, 2, 3, 4
RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_MEMLOCK, RLIMIT_AS = 5, 6, 7, 8, 9
RLIM_INFINITY = -1


class error(OSError):  # pylint: disable=invalid-name
    """resource.error."""


def _none(name):
    raise OSError(errno.ENOSYS, f"{name}: Windows has no per-process resource limits "
                  "(a process's limits are its job's, which the jailer sets with --cgroup)")


def getrlimit(which):  # pylint: disable=unused-argument
    """No resource limits on Windows."""
    _none("getrlimit")


def setrlimit(which, limits):  # pylint: disable=unused-argument
    """No resource limits on Windows."""
    _none("setrlimit")


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("r", "w", "o", "rb", "wb", "ob")]


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


_JOBS = {}  # pid -> job handle: the job lives as long as the session


def prlimit(pid, which, limits=None):
    """`prlimit(pid, RLIMIT_AS, (soft, hard))`: the process's own job with
    `soft` bytes of memory per process. Returns the limits before."""
    if which != RLIMIT_AS:
        _none("prlimit")
    if limits is None:
        return (RLIM_INFINITY, RLIM_INFINITY)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    soft = limits[0]
    job = _JOBS.get(pid) or k32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    info = _ExtendedLimits()
    if soft != RLIM_INFINITY:
        info.BasicLimitInformation.LimitFlags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
        info.ProcessMemoryLimit = soft
    # JobObjectExtendedLimitInformation = 9
    if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if pid not in _JOBS:
        # PROCESS_SET_QUOTA | PROCESS_TERMINATE
        proc = k32.OpenProcess(0x0100 | 0x0001, False, pid)
        if not proc:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not k32.AssignProcessToJobObject(job, proc):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            k32.CloseHandle(proc)
        _JOBS[pid] = job
    return (RLIM_INFINITY, RLIM_INFINITY)


def getpagesize():
    """The page size."""
    return 4096
