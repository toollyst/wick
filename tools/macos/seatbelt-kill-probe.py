#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""What Seatbelt's `(with send-signal SIGKILL)` does to a denied call, on
this macOS major: a probe for how a denied call could end Firecracker
(docs/COMPATIBILITY.md, "A denied call ends Firecracker with the bad-syscall
exit code"), run by CI's macos-seatbelt job on macOS 15 and 26, where no guest
runs and no Mac of ours is. It decides nothing in the
product; it prints, and exits 1 only if the action does not do what macOS
27.2 measured.

    python3 -I tools/macos/seatbelt-kill-probe.py [--runs N]

Each run forks a child that applies a profile denying one call with the
action (`getppid`, a system call; `swtch_pri`, a Mach trap), then makes the
call on a thread of its own, which stamps a shared page as the call returns.
The parent reads the child's exit reason before it reaps it
(`proc_pidinfo` PROC_PIDEXITREASONBASICINFO, flavour 25, which only the
parent may read: xnu bsd/kern/proc_info.c `proc_pidexitreasoninfo`).
Measured on macOS 27.2: the profile compiles, the child dies by SIGKILL with
namespace 25 (OS_REASON_SANDBOX, xnu bsd/sys/reason.h) and code 0xdd, and
the denied call never returns to the thread (50 of 50 runs of each call; a
process-directed signal in its place, SIGUSR2, lets it return).
"""

import argparse
import ctypes
import ctypes.util
import mmap
import os
import platform
import signal
import struct
import sys
import threading

OS_REASON_SANDBOX = 25
PROC_PIDEXITREASONBASICINFO = 25

libc = ctypes.CDLL(None, use_errno=True)
sandbox = ctypes.CDLL("/usr/lib/libsandbox.1.dylib")
libproc = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")
sandbox.sandbox_compile_string.restype = ctypes.c_void_p
sandbox.sandbox_compile_string.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)]
sandbox.sandbox_apply.argtypes = [ctypes.c_void_p]
libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]

PROFILES = {
    "syscall": "(version 1)(allow default)(deny syscall-unix (syscall-number SYS_getppid) (with send-signal SIGKILL))",
    "machtrap": "(version 1)(allow default)(deny syscall-mach (machtrap-number MSC_swtch_pri) (with send-signal SIGKILL))",
}


def compiles(profile):
    err = ctypes.c_char_p()
    compiled = sandbox.sandbox_compile_string(profile.encode(), None, ctypes.byref(err))
    return compiled, (err.value or b"").decode(errors="replace")


def denied_call(kind):
    if kind == "syscall":
        libc.getppid()
    else:
        libc.swtch_pri(0)


def run_once(kind, page):
    page[:8] = b"\0" * 8
    pid = os.fork()
    if pid == 0:
        try:
            compiled, err = compiles(PROFILES[kind])
            if not compiled or sandbox.sandbox_apply(compiled) != 0:
                os._exit(3)

            def caller():
                denied_call(kind)
                page[:8] = b"RETURNED"

            t = threading.Thread(target=caller)
            t.start()
            t.join()
            os._exit(0)
        finally:
            os._exit(4)
    # waitid(P_PID, pid, WEXITED | WNOWAIT): the child stays a zombie, whose
    # exit reason its parent can read (<sys/wait.h>: P_PID 1, WEXITED 4,
    # WNOWAIT 0x20; os has no waitid on macOS).
    info = ctypes.create_string_buffer(128)
    if libc.waitid(1, pid, info, 0x4 | 0x20) != 0:
        raise OSError(ctypes.get_errno(), "waitid")
    buf = ctypes.create_string_buffer(24)
    n = libproc.proc_pidinfo(pid, PROC_PIDEXITREASONBASICINFO, 0, buf, 24)
    namespace, code, flags = struct.unpack("<IQQ", buf.raw[:20]) if n >= 20 else (None, None, None)
    _, status = os.waitpid(pid, 0)
    sig = os.WTERMSIG(status) if os.WIFSIGNALED(status) else None
    return sig, bytes(page[:8]) == b"RETURNED", namespace, code, flags


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=50)
    args = parser.parse_args()
    print(f"macOS {platform.mac_ver()[0]}")
    page = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED | mmap.MAP_ANON)
    ok = True
    for kind, profile in PROFILES.items():
        compiled, err = compiles(profile)
        if not compiled:
            print(f"{kind}: the profile does not compile: {err}")
            ok = False
            continue
        results = [run_once(kind, page) for _ in range(args.runs)]
        killed = sum(1 for r in results if r[0] == signal.SIGKILL)
        returned = sum(1 for r in results if r[1])
        reasons = sorted({(r[2], hex(r[3] or 0), hex(r[4] or 0)) for r in results})
        print(
            f"{kind}: {args.runs} runs: killed by SIGKILL {killed}, the denied call returned {returned}, "
            f"exit reasons (namespace, code, flags) {reasons}"
        )
        if killed != args.runs or returned != 0 or any(r[2] != OS_REASON_SANDBOX for r in results):
            ok = False
    print("as measured on macOS 27.2" if ok else "NOT as measured on macOS 27.2")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
