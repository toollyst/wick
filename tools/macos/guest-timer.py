#!/usr/bin/env python3
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""How late a guest's own timers fire: the guest's view of the host's timer
coalescing.

Boots upstream's CI kernel and rootfs as boot-test's boot stage does (no
root) and runs, in the guest, python3's time.sleep (clock_nanosleep) 500
times for 1 ms and 50 times for 20 ms. Printed: how much longer than asked
each kind of sleep took (median, p90, p99 and maximum, in microseconds),
and the host's load average before and after.

A sleeping guest waits in WFI for its virtual timer, inside hv_vcpu_run on
its vCPU thread, and macOS fires that wait late by the thread's latency
tier (crates/compat/kvm-ioctls/src/hvf/latency.rs has the bound and its
sources). The tier in effect is also the launcher's: run this under
`taskpolicy -b` or `taskpolicy -c background` to see a background
Firecracker's guest, which the vCPU threads' own tier does not help.

Informational: it never fails on a number. The asserting test is
test_a_wfi_ends_when_its_timer_is_due.

  tools/macos/guest-timer.py FIRECRACKER [VCPUS]

FIRECRACKER is a signed binary (tools/macos/run.sh builds and signs one).
The guest's files are boot-test's (~/Library/Caches/wick/boot-test; run
tools/macos/boot-test.sh once to fetch them).
"""
import importlib.util
import os
import sys
import tempfile
import types
from pathlib import Path

PROBE = r'''python3 -c "
import time
def run(n, s):
    v = []
    for _ in range(n):
        t = time.monotonic_ns(); time.sleep(s); v.append((time.monotonic_ns() - t) // 1000 - int(s * 1e6))
    v.sort()
    print('GUEST sleep', int(s * 1000), 'ms, longer by (us): median', v[n // 2], 'p90', v[n * 9 // 10], 'p99', v[n * 99 // 100], 'max', v[-1])
run(500, 0.001)
run(50, 0.02)
"'''


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    spec = importlib.util.spec_from_file_location("boot_test", Path(__file__).resolve().parent / "boot-test.py")
    bt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bt)
    vcpus = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    args = types.SimpleNamespace(
        firecracker=sys.argv[1], snapshot_editor="", rebase_snap="", uffd_handler="", vhost_user_blk="",
        cpu_template_helper="",
        cache=os.path.expanduser("~/Library/Caches/wick/boot-test"), out=tempfile.mkdtemp(prefix="guest-timer-"))
    ctx = bt.Context(args)
    try:
        vm = ctx.vm("timer", [], bt.config(ctx, vcpus=vcpus))
        vm.wait_for(r"Run /bin/sh as init process", 60)
        vm.shell()
        print("guest-timer: host load average", " ".join(f"{x:.1f}" for x in os.getloadavg()))
        _, res = vm.sh(PROBE, timeout=120)
        for line in res.splitlines():
            if "GUEST" in line:
                print("guest-timer:", line[line.index("GUEST"):])
        print("guest-timer: host load average", " ".join(f"{x:.1f}" for x in os.getloadavg()))
    finally:
        ctx.cleanup()


if __name__ == "__main__":
    main()
