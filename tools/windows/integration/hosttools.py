# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Linux host tools upstream's framework runs, on Windows.

procps (`ps`, `pgrep`, `pidof`): Linux's reads /proc; Git for Windows's
`ps` lists MSYS processes only, with options of its own. These are the
forms upstream's tests use, on Windows's processes and threads (psutil; a
thread's name is the description Rust's std gives it, SetThreadDescription):

    ps ax --no-headers -o pid,cmd -ww
    ps -T --no-headers -p PID          (PID SPID TTY TIME CMD per thread)
    pgrep NAME
    pidof NAME

`dmesg`: Windows's System log (below).

e2fsprogs (`mkfs.ext4`, `resize2fs`, `e2fsck`, `fsck.ext4`, `debugfs`) and
util-linux's `sfdisk`: Windows has no tool that writes ext4 or a Linux
partition table on an image file; these are the Linux tools, run in
the WSL distribution the artifacts were prepared with (WICK_IT_WSL,
tools/windows/integration/setup-artifacts.ps1), on the same file
(C:\\x -> /mnt/c/x).

    python hosttools.py TOOL ARGS...
"""

import ctypes
import os
import re
import subprocess
import sys
from ctypes import wintypes

import psutil

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenThread.restype = wintypes.HANDLE
_k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_k32.GetThreadDescription.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.LocalFree.argtypes = [ctypes.c_void_p]
THREAD_QUERY_LIMITED_INFORMATION = 0x800


def _name(p):
    """The name Linux gives a process: its executable's, without `.exe`."""
    try:
        name = p.name()
    except psutil.Error:
        return ""
    return name[:-4] if name.lower().endswith(".exe") else name


def thread_name(tid):
    """A thread's name (its description), or "" if it has none."""
    h = _k32.OpenThread(THREAD_QUERY_LIMITED_INFORMATION, False, tid)
    if not h:
        return ""
    try:
        text = ctypes.c_wchar_p()
        if _k32.GetThreadDescription(h, ctypes.byref(text)) < 0:
            return ""
        value = text.value or ""
        _k32.LocalFree(text)
        return value
    finally:
        _k32.CloseHandle(h)


def _cmdline(p):
    try:
        return " ".join(p.cmdline()) or f"[{_name(p)}]"
    except psutil.Error:
        return f"[{_name(p)}]"


def ps(args):
    """The two `ps` forms above."""
    headers = "--no-headers" not in args
    if "-T" in args:
        pid = int(args[args.index("-p") + 1])
        try:
            proc = psutil.Process(pid)
            threads = proc.threads()
        except psutil.Error:
            return 1
        if headers:
            print("    PID    SPID TTY          TIME CMD")
        main = _name(proc)
        for t in threads:
            name = thread_name(t.id) or main
            secs = int(t.user_time + t.system_time)
            print(f"{pid:7d} {t.id:7d} ?        {secs // 3600:02d}:{secs // 60 % 60:02d}:{secs % 60:02d} {name}")
        return 0
    if "-o" in args and args[args.index("-o") + 1] == "pid,cmd":
        if headers:
            print("    PID CMD")
        for p in psutil.process_iter():
            print(f"{p.pid:7d} {_cmdline(p)}")
        return 0
    print(f"ps {' '.join(args)}: only upstream's forms are provided (tools/windows/integration/procps.py)",
          file=sys.stderr)
    return 1


def _matching(name):
    return [p.pid for p in psutil.process_iter() if _name(p) == name]


def pgrep(args):
    """`pgrep NAME`: the pids whose name is NAME (procps matches a pattern
    against the name; upstream gives a name)."""
    pids = _matching(args[-1])
    for pid in pids:
        print(pid)
    return 0 if pids else 1


def pidof(args):
    """`pidof NAME`: the pids on one line."""
    pids = _matching(args[-1])
    if pids:
        print(" ".join(str(p) for p in pids))
    return 0 if pids else 1


def dmesg(_args):
    """Linux's kernel log: Windows's System log, where the kernel and the
    hypervisor write, newest first, in UTF-8 (wevtutil writes the console's
    code page)."""
    out = subprocess.run(["wevtutil", "qe", "System", "/c:200", "/rd:true", "/f:text", "/l:en-US"],
                         capture_output=True, check=False)
    sys.stdout.write(out.stdout.decode("oem", errors="replace").replace("\r\n", "\n").replace("\x00", ""))
    return out.returncode


E2FSPROGS = ("mkfs.ext4", "resize2fs", "e2fsck", "fsck.ext4", "debugfs", "sfdisk")
_DRIVE_PATH = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def wsl_path(arg):
    """A Windows path as WSL mounts it; any other argument as it is."""
    m = _DRIVE_PATH.match(arg)
    return f"/mnt/{m.group(1).lower()}/{m.group(2).replace(chr(92), '/')}" if m else arg


def e2fsprogs(tool, args):
    """e2fsprogs in WSL, on the Windows file."""
    distro = os.environ.get("WICK_IT_WSL", "Ubuntu-24.04")
    out = subprocess.run(["wsl.exe", "-d", distro, "-u", "root", "--", tool, *map(wsl_path, args)],
                         capture_output=True, check=False)
    sys.stdout.write(out.stdout.decode("utf-8", errors="replace"))
    sys.stderr.write(out.stderr.decode("utf-8", errors="replace"))
    return out.returncode


TOOLS = ("ps", "pgrep", "pidof", "dmesg", *E2FSPROGS)


def main():
    tool, args = sys.argv[1], sys.argv[2:]
    sys.stdout.reconfigure(newline="\n", encoding="utf-8")  # Linux's line ends
    sys.stderr.reconfigure(newline="\n", encoding="utf-8")
    if tool in E2FSPROGS:
        return e2fsprogs(tool, args)
    return {"ps": ps, "pgrep": pgrep, "pidof": pidof, "dmesg": dmesg}[tool](args)


if __name__ == "__main__":
    sys.exit(main())
