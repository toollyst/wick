# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The jailer's --fs-server and --fs-share on Linux, as root (docs/design-fs.md
§8, Jailer; overlay/jailer/fs_share.rs), with a static payload in
Firecracker's place, as tools/linux/jailer-cgroup-check.py runs it:

- each refusal starts nothing: no process names the share's socket after;
- a server that is never ready is killed at the jailer's 10 s, one that ends
  first is named, and neither is left;
- a real wick-fsd: the payload's child (forked by the process that execs
  it), still root in stage 0 before its connection, in the jail's cgroup (a
  v1 freezer hierarchy mounted here, as the jailer attaches itself to it),
  with its socket in the jail's root, 0600 and the jail's uid:gid, and its
  descriptor limit, soft and hard, its own need, not the jail's no-file;
- on record: whether it still waits after the payload's end (the known
  limit of this version: it does, until killed).

    sudo python3 -I tools/linux/jailer-fs-check.py --jailer PATH --wick-fsd PATH [--workdir DIR]
"""

import argparse
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

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
FS_UID = 4272
FAILED = []


def check(ok, what):
    print(f"   {'PASS' if ok else 'FAIL'}: {what}", flush=True)
    if not ok:
        FAILED.append(what)


def processes_naming(text):
    """(pid, ppid, uid) of each process whose command line contains `text`."""
    rows = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace")
            with open(f"/proc/{pid}/status") as f:
                status = dict(line.split(":", 1) for line in f if ":" in line)
        except OSError:
            continue
        if text in cmd:
            rows.append((int(pid), int(status["PPid"].strip()), int(status["Uid"].split()[1])))
    return rows


def wait_for(cond, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def jailer(ctx, vm_id, args):
    cmd = [ctx.jailer, "--id", vm_id, "--exec-file", ctx.payload, "--uid", str(UID), "--gid", str(GID),
           "--chroot-base-dir", ctx.base] + args
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def finish(proc, timeout):
    out, _ = proc.communicate(timeout=timeout)
    out = out.strip()
    print(f"   exit {proc.returncode}: {out!r}", flush=True)
    return proc.returncode, out


def socket_of(ctx, vm_id):
    return os.path.join(ctx.base, "firecracker", vm_id, "root", "fs-docs.sock")


def case_refusals(ctx):
    print("== refusals start nothing", flush=True)
    share = ctx.share
    ok = f"id=docs,dir={share},uid={FS_UID},gid={FS_UID}"
    fsd = ctx.wick_fsd
    cases = [
        (["--fs-share", ok], "--fs-share needs --fs-server"),
        (["--fs-server", fsd], "without any --fs-share"),
        (["--fs-server", fsd, "--fs-share", ok, "--daemonize"], "--daemonize"),
        (["--fs-server", fsd, "--fs-share", ok, "--new-pid-ns"], "--new-pid-ns"),
        (["--fs-server", fsd, "--fs-share", f"id=docs,dir={share},uid={UID},gid={GID}"], "must not be the jail's"),
        (["--fs-server", fsd, "--fs-share", f"id=docs,dir={share}/none,uid={FS_UID},gid={FS_UID}"], "/none"),
    ]
    for i, (extra, want) in enumerate(cases):
        rc, out = finish(jailer(ctx, f"fs-refuse{i}", extra), 20)
        check(rc != 0 and want in out, f"{extra}: refused with {want!r}")
        left = processes_naming(socket_of(ctx, f"fs-refuse{i}"))
        check(not left, f"{extra}: no process left ({left})")


def case_failing_servers(ctx):
    print("== a server never ready, and one that ends first", flush=True)
    scripts = os.path.join(ctx.work, "scripts")
    os.makedirs(scripts, exist_ok=True)
    ok = f"id=docs,dir={ctx.share},uid={FS_UID},gid={FS_UID}"
    for name, body, want, limit in [
        ("never", "while :; do sleep 1; done", "no ready byte in 10 s", 30),
        ("ends", "exit 3", "ended before it was ready", 20),
    ]:
        script = os.path.join(scripts, name)
        with open(script, "w") as f:
            f.write(f"#!/bin/sh\n{body}\n")
        os.chmod(script, 0o755)
        rc, out = finish(jailer(ctx, f"fs-{name}", ["--fs-server", script, "--fs-share", ok]), limit)
        check(rc != 0 and want in out and "id=docs" in out, f"{name}: the jailer fails naming it ({want!r})")
        left = processes_naming(socket_of(ctx, f"fs-{name}"))
        check(not left, f"{name}: no server left ({left})")


def case_server(ctx):
    print("== a real wick-fsd under the jailer", flush=True)
    ok = f"id=docs,dir={ctx.share},uid={FS_UID},gid={FS_UID}"
    proc = jailer(ctx, "fs", ["--cgroup-version", "1", "--cgroup", "freezer.state=THAWED",
                              "--resource-limit", "no-file=1024", "--fs-server", ctx.wick_fsd, "--fs-share", ok])
    root = os.path.join(ctx.base, "firecracker", "fs", "root")
    sock = socket_of(ctx, "fs")
    pid = None
    try:
        started = wait_for(lambda: os.path.exists(os.path.join(root, "run", "payload-started")), 20)
        check(started, "the payload runs")
        if not started:
            return
        st = os.lstat(sock)
        check(stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600 and (st.st_uid, st.st_gid) == (UID, GID),
              f"{sock}: a socket, mode {stat.S_IMODE(st.st_mode):o}, owner {st.st_uid}:{st.st_gid} "
              f"(wanted 600 {UID}:{GID})")
        servers = processes_naming(f"--socket {sock}")
        check(len(servers) == 1, f"one wick-fsd for the share: {servers}")
        if len(servers) != 1:
            return
        pid, ppid, uid = servers[0]
        check(ppid == proc.pid and uid == 0,
              f"wick-fsd pid {pid}: parent {ppid}, uid {uid} (wanted the payload, {proc.pid}, and root in stage 0)")
        tasks_file = os.path.join(ctx.freezer, "firecracker", "fs", "tasks")
        with open(tasks_file) as f:
            tasks = sorted(int(t) for t in f.read().split())
        print(f"   {tasks_file}: {tasks}", flush=True)
        check(pid in tasks and proc.pid in tasks, f"wick-fsd ({pid}) and the payload ({proc.pid}) in the jail's cgroup")
        with open(f"/proc/{pid}/limits") as f:
            line = next(l for l in f if l.startswith("Max open files"))
        need = 1024 + 1024 + 64
        check(line.split()[3:5] == [str(need), str(need)],
              f"wick-fsd's descriptor limit, soft and hard, its need ({need}), not the jail's 1024: {line.strip()!r}")
        with open(f"/proc/{proc.pid}/limits") as f:
            line = next(l for l in f if l.startswith("Max open files"))
        check(line.split()[3:5] == ["1024", "1024"], f"the payload's is the jail's: {line.strip()!r}")
    finally:
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        time.sleep(1)
        if pid is not None:
            still = [r for r in processes_naming(f"--socket {sock}") if r[0] == pid]
            print(f"   on record: after the payload's end, wick-fsd pid {pid} "
                  f"{'still waits for its connection (the known limit)' if still else 'ended'}", flush=True)
            if still:
                os.kill(pid, signal.SIGKILL)
        proc.stdout.close()


class Ctx:
    pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--jailer", required=True)
    p.add_argument("--wick-fsd", required=True)
    p.add_argument("--workdir", default=None)
    args = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("needs root (the jailer and the cgroup mount)")
    ctx = Ctx()
    ctx.jailer = os.path.abspath(args.jailer)
    ctx.wick_fsd = os.path.abspath(args.wick_fsd)
    ctx.work = args.workdir or tempfile.mkdtemp(prefix="jailer-fs-")
    os.makedirs(ctx.work, exist_ok=True)
    os.chmod(ctx.work, 0o755)
    ctx.base = os.path.join(ctx.work, "jails")
    os.makedirs(ctx.base, exist_ok=True)
    ctx.share = os.path.join(ctx.work, "share")
    os.makedirs(ctx.share, exist_ok=True)
    os.chown(ctx.share, FS_UID, FS_UID)
    build = os.path.join(ctx.work, "build")
    os.makedirs(build, exist_ok=True)
    with open(os.path.join(build, "payload.c"), "w") as f:
        f.write(PAYLOAD_C)
    ctx.payload = os.path.join(build, "firecracker")
    subprocess.run(["cc", "-static", "-O2", "-o", ctx.payload, os.path.join(build, "payload.c")], check=True)
    ctx.freezer = os.path.join(ctx.work, "cg-freezer")
    os.makedirs(ctx.freezer, exist_ok=True)
    m = subprocess.run(["mount", "-t", "cgroup", "-o", "freezer", "cgroup", ctx.freezer], capture_output=True, text=True)
    if m.returncode != 0:
        sys.exit(f"cannot mount a v1 freezer hierarchy at {ctx.freezer}: {m.stderr.strip()}")
    try:
        case_refusals(ctx)
        case_failing_servers(ctx)
        case_server(ctx)
    finally:
        subprocess.run(["pkill", "-9", "-f", ctx.base], check=False)
        time.sleep(0.5)
        for d, _, _ in sorted(os.walk(ctx.freezer), key=lambda w: -w[0].count("/")):
            if d != ctx.freezer:
                try:
                    os.rmdir(d)
                except OSError:
                    pass
        subprocess.run(["umount", ctx.freezer], check=False)
        shutil.rmtree(ctx.work, ignore_errors=True)
    if FAILED:
        print(f"{len(FAILED)} checks failed:", *FAILED, sep="\n  ")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
