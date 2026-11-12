#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""How late this process's 50 ms timers fire, by kind of wait: the evidence
of whether the host coalesces its timers, and by how much.

macOS may fire a timer late to coalesce it with others, by an amount set by
the waiting thread's policy (XNU osfmk/kern/timer_call.c
timer_compute_leeway; the limits are the kern.timer_coalesce_* sysctls): up
to 1 ms for an ordinary process, up to 100 ms for a background one. A kqueue
timer marked NOTE_CRITICAL is fired when due, which is how the compat
timerfd waits (crates/compat/libc/src/timerfd.rs). Printed, as
min/median/max lateness in microseconds over the samples:

  cond      a condition variable's timed wait (pthread_cond_timedwait)
  kevent    a kevent() timeout (the compat epoll_wait's timeout)
  timer     a kqueue timer with default flags
  critical  a kqueue timer marked NOTE_CRITICAL

and the kern.timer_coalesce_* sysctls. Informational: it never fails.

  tools/macos/timer-coalescing.py [SAMPLES]
"""

import select
import subprocess
import sys
import threading
import time

NOTE_CRITICAL = 0x20  # <sys/event.h>
WAIT_S = 0.050


def late_us(start):
    return (time.monotonic() - start - WAIT_S) * 1e6


def measure(kind, kq):
    start = time.monotonic()
    if kind == "cond":
        c = threading.Condition()
        with c:
            c.wait(WAIT_S)
    elif kind == "kevent":
        kq.control(None, 1, WAIT_S)
    else:
        flags = NOTE_CRITICAL if kind == "critical" else 0
        ev = select.kevent(1, select.KQ_FILTER_TIMER, select.KQ_EV_ADD | select.KQ_EV_ONESHOT, flags,
                           int(WAIT_S * 1000))
        kq.control([ev], 1, None)
    return late_us(start)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    kq = select.kqueue()
    for kind in ("cond", "kevent", "timer", "critical"):
        v = sorted(measure(kind, kq) for _ in range(n))
        print(f"timer-coalescing: {kind:8} late min {v[0]:9.0f}  median {v[n // 2]:9.0f}  max {v[-1]:9.0f} us")
    out = subprocess.run(["sysctl", "kern.timer_coalesce_ts_ns_max", "kern.timer_coalesce_bg_ns_max"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        print(f"timer-coalescing: {line}")


if __name__ == "__main__":
    main()
