# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""jailer-test stages for cgroup options measured against Linux
(tools/linux/jailer-cgroup-check.py records what upstream's jailer does
there). Loaded by tools/macos/jailer-test.py, which passes itself as `jt`;
run as root like every jailer-test stage, with no VM.
"""

import os
import subprocess


def stage_cgroup_devices(ctx, jt):
    """`devices.*` refused at the start, as upstream's jailer refuses it on Linux: exit 1, before the jail exists."""
    check = jt.check
    cases = [
        # v1: Linux fails reading the parent cgroup's write-only file (EINVAL),
        # or writing the read-only devices.list.
        (["--cgroup-version", "1", "--cgroup", "devices.deny=a"],
         "upstream's jailer cannot set it on Linux either"),
        (["--cgroup-version", "1", "--cgroup", "devices.allow=c 1:3 rwm"],
         "devices.allow and devices.deny are write-only (EINVAL)"),
        (["--cgroup-version", "1", "--cgroup", "devices.list=a *:* rwm"], "devices.list read-only"),
        # v2: no devices controller; upstream's own error.
        (["--cgroup-version", "2", "--cgroup", "devices.deny=a"], "Controller devices is unavailable"),
        (["--cgroup-version", "2", "--cgroup", "devices.allow=c 1:3 rwm"], "Controller devices is unavailable"),
    ]
    for i, (extra, want) in enumerate(cases):
        vm_id = f"cgroup-devices{i}"
        jail_dir = os.path.join(ctx.base, os.path.basename(ctx.firecracker), vm_id)
        rc, out = jt.run_jailer(ctx, jt.jailer_base(ctx, vm_id) + extra + [
            "--", "--api-sock", "/run/firecracker.socket"])
        print(f"   {' '.join(extra)}: exit {rc}: {out!r}", flush=True)
        check(rc == 1 and want in out, f"{extra}: exit {rc}, {out!r}")
        # macOS refuses while parsing the options: no jail directory (Linux,
        # for v1, has made <id>/root and copied the binary into it by then).
        check(not os.path.exists(jail_dir), f"{extra}: {jail_dir} was made")
        running = subprocess.run(["pgrep", "-f", f"--id {vm_id} "], capture_output=True, text=True).stdout.split()
        check(not running, f"{extra}: processes of the jail: {running}")
    return f"{len(cases)} devices options refused, exit 1, no jail made"
