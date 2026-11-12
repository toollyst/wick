# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Processes for the Windows plugin (wick_windows.py): ending one, and
waiting, by handle, for what of a jail ends after Firecracker.

On Linux the jailer execs Firecracker and the API server is one of its
threads, so the end of Firecracker's pid is the end of everything of its
jail. On Windows a jail has three processes: the jailer, which waits for
Firecracker, then for the API process, and exits last
(overlay/jailer/platform/windows/mod.rs), Firecracker and the API process.
Unjailed, the API process is Firecracker's child (vmm/ext/api_process.rs).
Upstream's harness kills Firecracker, waits for its pid, kills the screen
around the jailer and removes the jail's directory: here each of those
waits also waits for what ends after it.
"""

import ctypes
import errno
import os

import psutil

_SYNCHRONIZE = 0x00100000
_QUERY_LIMITED = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
_TERMINATE = 0x0001
_WAIT_OBJECT_0 = 0
_INVALID_PARAMETER = 87


class _BasicInformation(ctypes.Structure):
    """PROCESS_BASIC_INFORMATION (winternl.h)."""

    _fields_ = [
        ("ExitStatus", ctypes.c_long),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_size_t),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_size_t),
        ("InheritedFromUniqueProcessId", ctypes.c_size_t),
    ]


def _k32():
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    k32.WaitForSingleObject.restype = ctypes.c_uint32
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    k32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    k32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4
    k32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
    return k32


def open_process(pid):
    """A handle to `pid` to wait on and query, or None."""
    return _k32().OpenProcess(_SYNCHRONIZE | _QUERY_LIMITED, False, pid) or None


def close_all(handles):
    """Closes the handles of a list of (what, handle)."""
    for _, h in handles:
        _k32().CloseHandle(h)


def _created(h):
    times = [ctypes.c_uint64() for _ in range(4)]
    if not _k32().GetProcessTimes(h, *[ctypes.byref(t) for t in times]):
        raise ctypes.WinError(ctypes.get_last_error())
    return times[0].value


def _image(h):
    size = ctypes.c_uint32(32768)
    buf = ctypes.create_unicode_buffer(size.value)
    if not _k32().QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return os.path.normcase(buf.value)


def _creator(h):
    """The pid of the process that created the process of `h`, read through
    the handle, not from a snapshot, so that a pid reused since is not taken
    for it."""
    info = _BasicInformation()
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtQueryInformationProcess.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    status = ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(info), ctypes.sizeof(info), None)
    if status:
        raise OSError(errno.EPERM, f"NtQueryInformationProcess: NTSTATUS {status & 0xFFFFFFFF:#x}")
    return info.InheritedFromUniqueProcessId


def children(pid, h, same_image=None):
    """Handles to the processes that `pid` (handle `h`) created, as
    (what, handle): each checked through its own handle (created by `pid`,
    after it) and, with `same_image`, running that image."""
    found = []
    try:
        created = _created(h)
        candidates = [c.pid for c in psutil.Process(pid).children()]
    except (OSError, psutil.Error):
        return found
    for cpid in candidates:
        ch = open_process(cpid)
        if not ch:
            continue
        try:
            ok = _creator(ch) == pid and _created(ch) >= created
            ok = ok and (same_image is None or _image(ch) == same_image)
        except OSError:
            ok = False
        if ok:
            found.append((f"process {cpid}", ch))
        else:
            _k32().CloseHandle(ch)
    return found


def jail_after(pid, firecracker="firecracker.exe", jailer="jailer.exe"):
    """What ends after `pid` as part of its end, as (what, handle) to wait
    on: for a Firecracker (an image named firecracker.exe), its children of
    the same image (unjailed, its API process) and its creator if that is a
    jailer.exe created before it (the jailer, which exits once every process
    of the jail has ended). Nothing for any other process. The names are
    parameters for the self-test."""
    h = open_process(pid)
    if not h:
        return []
    found = []
    try:
        image = _image(h)
        if os.path.basename(image) != firecracker:
            return found
        found += children(pid, h, same_image=image)
        ph = open_process(_creator(h))
        if ph:
            try:
                keep = os.path.basename(_image(ph)) == jailer and _created(ph) <= _created(h)
            except OSError:
                keep = False
            if keep:
                found.append(("its jailer", ph))
            else:
                _k32().CloseHandle(ph)
    except OSError:
        pass
    finally:
        _k32().CloseHandle(h)
    return found


def wait_all(handles, timeout, whose):
    """Waits for each of a list of (what, handle), raising TimeoutError for
    the first that does not end within `timeout` seconds."""
    for what, h in handles:
        if _k32().WaitForSingleObject(h, int(timeout * 1000)) != _WAIT_OBJECT_0:
            raise TimeoutError(f"{what}, which ends after {whose}, did not exit within {timeout}s")


def ended(pid):
    """Whether no running process has `pid`."""
    h = open_process(pid)
    if not h:
        return ctypes.get_last_error() == _INVALID_PARAMETER
    try:
        return _k32().WaitForSingleObject(h, 0) == _WAIT_OBJECT_0
    finally:
        _k32().CloseHandle(h)


def terminate(pid, code):
    """TerminateProcess with `code`, as CPython's os.kill, opening the
    process for PROCESS_TERMINATE alone (CPython's opens it for every right,
    more than a jailed process's DACL may give). ProcessLookupError for a pid
    no running process has."""
    k32 = _k32()
    h = k32.OpenProcess(_TERMINATE, False, pid)
    if not h:
        err = ctypes.get_last_error()
        if err == _INVALID_PARAMETER or ended(pid):
            raise ProcessLookupError(errno.ESRCH, f"kill({pid}): no such process")
        raise ctypes.WinError(err)
    try:
        if not k32.TerminateProcess(h, code):
            err = ctypes.get_last_error()
            if ended(pid):
                raise ProcessLookupError(errno.ESRCH, f"kill({pid}): no such process")
            raise ctypes.WinError(err)
    finally:
        k32.CloseHandle(h)


def end_stand_in(pid, code, limit, resume=None):
    """Ends a screen stand-in (hosttools.py `screen`) after the processes it
    started (the jailer), waited for by handle: the stand-in holds the
    jailer's output pipe, and on Linux screen's end follows Firecracker's,
    which the jailer's is here. Once they have ended, the stand-in copies
    what is left in the pipe and exits by itself, as screen does when its
    last window closes: it is waited for, and a stand-in that has ended
    gives ProcessLookupError, as screen's pid does on Linux. `resume`, if
    given, is called first (a stopped stand-in then copies the jailer's last
    output rather than blocking the jailer on it). What runs on past
    `limit` seconds is a TimeoutError, raised after the stand-in is ended
    all the same."""
    h = open_process(pid)
    if not h:
        return terminate(pid, code)
    started = []
    try:
        started = children(pid, h)
        if resume is not None:
            resume()
        late = None
        try:
            wait_all(started, limit, f"the kill of the screen stand-in {pid}")
            wait_all([(f"the screen stand-in {pid}", h)], limit, "what it started")
        except TimeoutError as err:
            late = err
        try:
            terminate(pid, code)
        except ProcessLookupError:
            if late is None:
                raise
        if late is not None:
            raise late
        return None
    finally:
        close_all(started)
        _k32().CloseHandle(h)
