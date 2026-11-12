# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""What upstream's jailer does on Linux with the freezer and devices cgroup
options, measured: the reference the macOS and Windows jailers follow
(docs/COMPATIBILITY.md, the cgroup rows `cgroup.freeze`, `freezer` and
`devices`).

Runs as root on a cgroup v2 host (GitHub's Ubuntu runners). It mounts a v1
`devices` and a v1 `freezer` hierarchy (both controllers are v1 only, so a
v2 host leaves them free), runs the jailer built from lib/firecracker (on
Linux wick's jailer is upstream's) with a static payload in Firecracker's
place, and asserts, case by case, the exit code and the error text, and for
`freezer.state=FROZEN` that the jailer stops before its chroot and pid file
and goes on once `THAWED` is written from outside. Prints every text, so the
log is the record.

    sudo python3 -I tools/linux/jailer-cgroup-check.py --jailer PATH [--workdir DIR]
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

# A static program the jailer execs in its chroot as uid:gid: it marks that it
# runs, then sleeps until killed.
PAYLOAD_C = r"""
#include <fcntl.h>
#include <unistd.h>
int main(void) {
    int fd = open("/run/payload-started", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);
    for (;;) pause();
}
"""

UID = GID = 4271
FAILED = []


def check(ok, what):
    print(f"   {'PASS' if ok else 'FAIL'}: {what}", flush=True)
    if not ok:
        FAILED.append(what)


def mount_v1(where, controller):
    os.makedirs(where, exist_ok=True)
    p = subprocess.run(["mount", "-t", "cgroup", "-o", controller, "cgroup", where],
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"cannot mount a v1 {controller} hierarchy at {where}: {p.stderr.strip()}")
    print(f"mounted v1 {controller} at {where}")


class Run:
    """One jailer run with its own id under the chroot base."""

    def __init__(self, ctx, vm_id, args, daemonize=False):
        self.ctx = ctx
        self.id = vm_id
        self.jail = os.path.join(ctx.base, "firecracker", vm_id)
        self.root = os.path.join(self.jail, "root")
        cmd = [ctx.jailer, "--id", vm_id, "--exec-file", ctx.payload, "--uid", str(UID),
               "--gid", str(GID), "--chroot-base-dir", ctx.base] + args
        if daemonize:
            cmd.append("--daemonize")
        print(f"$ {' '.join(cmd)}", flush=True)
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)

    def finish(self, timeout=20):
        out, _ = self.proc.communicate(timeout=timeout)
        out = out.strip()
        print(f"   exit {self.proc.returncode}: {out!r}", flush=True)
        return self.proc.returncode, out

    def started(self):
        return os.path.exists(os.path.join(self.root, "run", "payload-started"))

    def pid_file(self):
        return os.path.exists(os.path.join(self.root, "firecracker.pid"))


def wait_for(cond, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def payload_pid(run):
    with open(os.path.join(run.root, "firecracker.pid")) as f:
        return int(f.read())


def kill_payload(run):
    if run.pid_file():
        try:
            os.kill(payload_pid(run), signal.SIGKILL)
        except ProcessLookupError:
            pass


def refused(ctx, vm_id, args, want):
    run = Run(ctx, vm_id, args)
    rc, out = run.finish()
    check(rc != 0 and want in out, f"{args}: refused with {want!r}")
    check(not run.started(), f"{args}: the payload never ran")


def case_devices(ctx):
    print("== v1 devices", flush=True)
    for i, value in enumerate(["devices.deny=a", "devices.allow=c 1:3 rwm", "devices.deny=c 1:3 w"]):
        prop = value.split("=", 1)[0]
        parent = os.path.join(ctx.devices, "firecracker", prop)
        # The jailer first reads the parent's file (inherit_from_parent): a
        # write-only file, whose read fails with EINVAL.
        refused(ctx, f"devices{i}", ["--cgroup-version", "1", "--cgroup", value],
                f"Failed to read file {parent} into a string: Invalid argument")
    refused(ctx, "devices-list", ["--cgroup-version", "1", "--cgroup", "devices.list=a *:* rwm"],
            "Invalid argument")


def case_freezer_values(ctx):
    print("== v1 freezer.state values", flush=True)
    for i, value in enumerate(["FREEZING", "bogus", "frozen"]):
        vm_id = f"freezer-bad{i}"
        path = os.path.join(ctx.freezer, "firecracker", vm_id, "freezer.state")
        refused(ctx, vm_id, ["--cgroup-version", "1", "--cgroup", f"freezer.state={value}"],
                f"Failed to write to {path}: Invalid argument")
    for i, prop in enumerate(["freezer.self_freezing=1", "freezer.parent_freezing=0"]):
        refused(ctx, f"freezer-ro{i}", ["--cgroup-version", "1", "--cgroup", prop], "Failed to write to")
    # THAWED: a no-op, the payload runs.
    run = Run(ctx, "freezer-thawed", ["--cgroup-version", "1", "--cgroup", "freezer.state=THAWED"])
    check(wait_for(run.started, 10), "freezer.state=THAWED: the payload runs")
    kill_payload(run)
    run.finish()


def frozen_at_start(ctx, vm_id, daemonize):
    what = f"freezer.state=FROZEN{' --daemonize' if daemonize else ''}"
    print(f"== v1 {what}", flush=True)
    cg = os.path.join(ctx.freezer, "firecracker", vm_id)
    run = Run(ctx, vm_id, ["--cgroup-version", "1", "--cgroup", "freezer.state=FROZEN"], daemonize)
    check(wait_for(lambda: os.path.exists(os.path.join(cg, "tasks")), 10), f"{what}: the cgroup is made")
    time.sleep(2)
    with open(os.path.join(cg, "tasks")) as f:
        tasks = [int(t) for t in f.read().split()]
    with open(os.path.join(cg, "freezer.state")) as f:
        state = f.read().strip()
    print(f"   cgroup tasks {tasks}, freezer.state {state}", flush=True)
    check(tasks == [run.proc.pid], f"{what}: the jailer itself ({run.proc.pid}) is the cgroup's task")
    check(state == "FROZEN", f"{what}: freezer.state reads FROZEN")
    check(run.proc.poll() is None, f"{what}: the jailer command has not returned")
    check(os.readlink(f"/proc/{run.proc.pid}/root") == "/", f"{what}: the jailer has not chrooted")
    check(not run.pid_file() and not run.started(), f"{what}: no pid file, the payload has not run")
    with open(os.path.join(cg, "freezer.state"), "w") as f:
        f.write("THAWED\n")
    if daemonize:
        rc, _ = run.finish()
        check(rc == 0, f"{what}: after THAWED the jailer returns 0")
    check(wait_for(run.started, 10), f"{what}: after THAWED the payload runs")
    check(run.pid_file(), f"{what}: after THAWED the pid file is written")
    kill_payload(run)
    if not daemonize:
        run.finish()


def case_v2(ctx):
    print("== v2 cgroup.freeze", flush=True)
    for i, value in enumerate(["cgroup.freeze=1", "cgroup.freeze=0", "cgroup.procs=1"]):
        refused(ctx, f"v2-{i}", ["--cgroup-version", "2", "--cgroup", value], "Controller cgroup is unavailable")


class Ctx:
    pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--jailer", required=True)
    p.add_argument("--workdir", default=None)
    args = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("needs root (the jailer and the cgroup mounts)")
    print(subprocess.run(["uname", "-a"], capture_output=True, text=True).stdout.strip())
    with open("/proc/mounts") as f:
        print("cgroup mounts before:", [l.split()[:3] for l in f if "cgroup" in l.split()[2]])
    ctx = Ctx()
    ctx.jailer = os.path.abspath(args.jailer)
    work = args.workdir or tempfile.mkdtemp(prefix="jailer-cgroup-")
    os.makedirs(work, exist_ok=True)
    ctx.base = os.path.join(work, "jails")
    os.makedirs(ctx.base, exist_ok=True)
    build = os.path.join(work, "build")
    os.makedirs(build, exist_ok=True)
    with open(os.path.join(build, "payload.c"), "w") as f:
        f.write(PAYLOAD_C)
    ctx.payload = os.path.join(build, "firecracker")
    subprocess.run(["cc", "-static", "-O2", "-o", ctx.payload, os.path.join(build, "payload.c")], check=True)
    ctx.devices = os.path.join(work, "cg-devices")
    ctx.freezer = os.path.join(work, "cg-freezer")
    mount_v1(ctx.devices, "devices")
    mount_v1(ctx.freezer, "freezer")
    try:
        case_devices(ctx)
        case_freezer_values(ctx)
        frozen_at_start(ctx, "frozen", daemonize=False)
        frozen_at_start(ctx, "frozen-daemon", daemonize=True)
        case_v2(ctx)
    finally:
        subprocess.run(["pkill", "-9", "-f", ctx.base], check=False)
        time.sleep(0.5)
        for mnt in (ctx.devices, ctx.freezer):
            # Empty cgroups first (deepest first), then the hierarchy.
            for d, _, _ in sorted(os.walk(mnt), key=lambda w: -w[0].count("/")):
                if d != mnt:
                    try:
                        with open(os.path.join(d, "freezer.state"), "w") as f:
                            f.write("THAWED\n")
                    except OSError:
                        pass
                    try:
                        os.rmdir(d)
                    except OSError:
                        pass
            subprocess.run(["umount", mnt], check=False)
        shutil.rmtree(ctx.base, ignore_errors=True)
    if FAILED:
        print(f"{len(FAILED)} checks failed:", *FAILED, sep="\n  ")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
