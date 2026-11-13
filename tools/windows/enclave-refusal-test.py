#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""A Nitro Enclave's configuration and start on Windows.

    python -I tools/windows/enclave-refusal-test.py FIRECRACKER.EXE

Runs tools/macos/enclave-refusal-test.py unchanged, with the same checks
in the same order, through the AF_UNIX sockets of
tools/windows/integration/wick_windows_unix.py (CPython's Windows build
cannot connect an AF_UNIX socket to a path). Needs no WHP: only the API
before a boot.

Firecracker drives an enclave only through Linux's nitro_enclaves driver,
by ioctls on /dev/nitro_enclaves (src/vmm/src/nitro_enclave). Windows has
no such device: the start opens that path as Linux's does and is refused
in the same place, with the same message up to the host's error. Where
Linux says "No such file or directory (os error 2)" (ENOENT), Windows
gives its error for a path whose directory \\dev does not exist on the
drive: "The system cannot find the path specified. (os error 3)"
(ERROR_PATH_NOT_FOUND).
"""

import ctypes
import importlib.util
import os
import subprocess
import sys
from ctypes import wintypes

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "integration"))

import wick_windows_unix  # pylint: disable=wrong-import-position

NO_DEVICE = (
    "Start microvm error: Enclave builder error: Failed to open /dev/nitro_enclaves: "
    "The system cannot find the path specified. (os error 3)"
)

_SYNCHRONIZE = 0x00100000
_QUERY_LIMITED = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
_WAIT_OBJECT_0 = 0
_END_LIMIT_MS = 10_000


class _Entry(ctypes.Structure):
    """PROCESSENTRY32W."""

    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _kernel32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    return k32


def _created(k32, handle):
    times = [wintypes.FILETIME() for _ in range(4)]
    if not k32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
        raise ctypes.WinError(ctypes.get_last_error())
    return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime


def _children(k32, parent, parent_created):
    """Handles to the running children of `parent`: processes that name it
    as their parent and were created after it (an older one names an
    earlier process that had the pid)."""
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if snap in (None, wintypes.HANDLE(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    found = []
    try:
        entry = _Entry(dwSize=ctypes.sizeof(_Entry))
        more = k32.Process32FirstW(snap, ctypes.byref(entry))
        while more:
            if entry.th32ParentProcessID == parent and entry.th32ProcessID != parent:
                h = k32.OpenProcess(_SYNCHRONIZE | _QUERY_LIMITED, False, entry.th32ProcessID)
                if h:
                    if _created(k32, h) >= parent_created:
                        found.append((entry.th32ProcessID, entry.szExeFile, h))
                    else:
                        k32.CloseHandle(h)
            more = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return found


class _Popen(subprocess.Popen):
    """Firecracker's process, whose end includes its API server's.

    Firecracker's API server runs in a second process on Windows
    (vmm/ext/api_process.rs), Firecracker's child, which inherits the output
    file and ends when it sees Firecracker's end: after it, 20 to 40 ms after
    Firecracker was killed and waited for (measured on Windows Server 2022,
    5 runs), so the output file could not yet be removed. On Linux the API
    thread ends with the process. The kill takes a handle to each child
    while Firecracker runs, and the wait waits for each, failing if one
    outlives Firecracker by 10 s."""

    _children = ()

    def kill(self):
        if self.returncode is None:
            k32 = _kernel32()
            created = _created(k32, int(self._handle))
            self._children = _children(k32, self.pid, created)
        super().kill()

    def wait(self, timeout=None):
        code = super().wait(timeout)
        k32 = _kernel32()
        children, self._children = self._children, ()
        try:
            for pid, exe, h in children:
                if k32.WaitForSingleObject(h, _END_LIMIT_MS) != _WAIT_OBJECT_0:
                    raise RuntimeError(f"{exe} ({pid}), Firecracker's child, still runs {_END_LIMIT_MS} ms after it")
        finally:
            for _, _, h in children:
                k32.CloseHandle(h)
        return code


def main():
    wick_windows_unix.install()
    path = os.path.join(HERE, "..", "macos", "enclave-refusal-test.py")
    spec = importlib.util.spec_from_file_location("enclave_refusal_test", path)
    test = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(test)
    # Windows' text for the missing device, measured; every other check is
    # the Linux one.
    test.NO_DEVICE = NO_DEVICE
    test.subprocess.Popen = _Popen
    test.main()


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
    main()
