# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""Scenario tests of the macOS jailer. Needs root (run through
tools/macos/jailer-test.sh, which builds as the invoking user and runs this
with sudo).

Each stage starts Firecracker through the jailer, the way an operator would,
and checks from the outside what the jail holds: the process's user, group and
root directory, which files and sockets it can reach, the memory limit and its
jetsam priority, the CPU limit, daemonization and the options the jailer must
refuse. The
stages marked "VM" boot upstream's aarch64 CI guest and need
Hypervisor.framework; the others run on any Mac (CI runs them on GitHub's
macOS runners, which have no Hypervisor.framework).
"""

import argparse
import ctypes
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("boot_test", os.path.join(HERE, "boot-test.py"))
bt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bt)
Failure, check = bt.Failure, bt.check

# The jailed user: no account, no files of its own outside the jail.
UID = 4271
GID = 4271


class Jail:
    """A jail directory, populated before the jailer runs, as an operator does."""

    def __init__(self, ctx, vm_id, files=()):
        self.id = vm_id
        self.root = os.path.join(ctx.base, "firecracker", vm_id, "root")
        os.makedirs(self.root)
        for src in files:
            dst = os.path.join(self.root, os.path.basename(src))
            subprocess.run(["cp", "-c", src, dst], check=True)
            os.chown(dst, UID, GID)

    def host(self, path):
        """The host path of `path` inside the jail."""
        return os.path.join(self.root, path.lstrip("/"))


class JailedVm(bt.Vm):
    """A Firecracker process started by the jailer, its console on a pipe."""

    def __init__(self, ctx, name, jail, jailer_args=(), fc_args=(), config=None, wait_api=True):
        self.ctx = ctx
        self.name = name
        self.jail = jail
        self.log_path = os.path.join(ctx.out, f"{name}.log")
        self.api_sock = jail.host("/run/firecracker.socket")
        cmd = [ctx.jailer, "--id", jail.id, "--exec-file", ctx.firecracker,
               "--uid", str(UID), "--gid", str(GID), "--chroot-base-dir", ctx.base]
        cmd += list(jailer_args)
        cmd += ["--", "--api-sock", "/run/firecracker.socket"] + list(fc_args)
        if config is not None:
            with open(jail.host("/vm.json"), "w") as f:
                json.dump(config, f, indent=1)
            cmd += ["--config-file", "/vm.json"]
        self.buf = ""
        self.cond = bt.threading.Condition()
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        self.pump = bt.threading.Thread(target=self._pump, daemon=True)
        self.pump.start()
        ctx.vms.append(self)
        self.seq = 0
        if wait_api:
            deadline = time.time() + 10
            while not os.path.exists(self.api_sock):
                if self.proc.poll() is not None or time.time() > deadline:
                    raise Failure(f"no API socket ({self.exit_reason()})")
                time.sleep(0.02)


def jail_config(vcpus=1, mem=256, **extra):
    cfg = {
        "boot-source": {"kernel_image_path": "/" + bt.KERNEL, "boot_args": bt.BOOT_ARGS},
        "drives": [{"drive_id": "rootfs", "path_on_host": "/" + bt.ROOTFS,
                    "is_root_device": True, "is_read_only": True}],
        "machine-config": {"vcpu_count": vcpus, "mem_size_mib": mem},
    }
    cfg.update({k.replace("_", "-"): v for k, v in extra.items()})
    return cfg


def proc_ids(pid):
    out = subprocess.run(["ps", "-o", "uid=,gid=,ppid=", "-p", str(pid)],
                         capture_output=True, text=True).stdout.split()
    check(len(out) == 3, f"ps for pid {pid}: {out}")
    return tuple(int(x) for x in out)


def proc_root(pid):
    """The process's root directory, from lsof (`rtd`, or `cwd` if no chroot)."""
    out = subprocess.run(["lsof", "-a", "-p", str(pid), "-d", "rtd,cwd", "-Fn"],
                         capture_output=True, text=True).stdout
    names = [line[1:] for line in out.splitlines() if line.startswith("n")]
    return names


class MemoryStatusEntry(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_int32), ("priority", ctypes.c_int32),
                ("user_data", ctypes.c_uint64), ("limit", ctypes.c_int32), ("state", ctypes.c_uint32)]


class CpuUsageAttr(ctypes.Structure):
    """proc_policy_cpuusage_attr_t (sys/process_policy.h)."""
    _fields_ = [("action", ctypes.c_uint32), ("percentage", ctypes.c_uint32),
                ("interval", ctypes.c_uint64), ("deadline", ctypes.c_uint64)]


def cpu_limit(pid):
    """(action, percent of one CPU, interval in s) of `pid`'s CPU limit (PROC_POLICY_ACTION_GET)."""
    libc = ctypes.CDLL(None, use_errno=True)
    f = libc.__process_policy
    f.argtypes = [ctypes.c_int] * 4 + [ctypes.POINTER(CpuUsageAttr), ctypes.c_int, ctypes.c_uint64]
    a = CpuUsageAttr()
    # SCOPE_PROCESS, ACTION_GET, RESOURCE_USAGE, RUSAGE_CPU.
    r = f(1, 11, 4, 3, ctypes.byref(a), pid, 0)
    check(r == 0, f"process_policy GET for {pid}: errno {ctypes.get_errno()}")
    return a.action, a.percentage, a.interval


def cpu_seconds(pid):
    """User plus system CPU time of `pid`, from ps (10 ms resolution)."""
    out = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True).stdout
    check(out.strip() != "", f"ps time for {pid}")
    total = 0.0
    for part in out.strip().split(":"):
        total = total * 60 + float(part)
    return total


def jetsam(pid):
    """(priority, limit in MiB) of `pid` (MEMORYSTATUS_CMD_GET_PRIORITY_LIST)."""
    libc = ctypes.CDLL(None, use_errno=True)
    e = MemoryStatusEntry()
    r = libc.memorystatus_control(1, pid, 0, ctypes.byref(e), ctypes.sizeof(e))
    check(r >= 0 and e.pid == pid, f"memorystatus_control for {pid}: {r}, errno {ctypes.get_errno()}")
    return e.priority, e.limit


def run_jailer(ctx, args, timeout=20):
    p = subprocess.run([ctx.jailer] + args, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def jailer_base(ctx, vm_id, exec_file=None):
    return ["--id", vm_id, "--exec-file", exec_file or ctx.firecracker, "--uid", str(UID),
            "--gid", str(GID), "--chroot-base-dir", ctx.base]


# ---------------------------------------------------------------- stages


def stage_refuse(ctx):
    """Options the jailer cannot enforce on macOS, and binaries that cannot take a jail over."""
    cases = [
        (["--netns", "/var/run/netns/x"], "--netns is not supported on macOS"),
        (["--new-pid-ns"], "--new-pid-ns is not supported on macOS"),
        (["--cgroup", "cpuset.cpus=0"], "--cgroup cpuset.cpus=0 is not supported on macOS"),
        (["--cgroup-version", "2", "--cgroup", "cpu.weight=100"], "is not supported on macOS"),
        (["--cgroup", "cpu.shares=512"], "is not supported on macOS"),
        # CPU limits macOS cannot enforce as asked: never loosened.
        (["--cgroup-version", "2", "--cgroup", "cpu.max=1000 1000000"], "below 1% of one CPU"),
        (["--cgroup-version", "2", "--cgroup", "cpu.max=300000 100000"], "above 255% of one CPU"),
    ]
    for i, (extra, want) in enumerate(cases):
        rc, out = run_jailer(ctx, jailer_base(ctx, f"refuse{i}") + extra)
        check(rc != 0 and want in out, f"{extra}: exit {rc}, {out!r}")
    # A binary without the hand-over would run unjailed as root.
    rc, out = run_jailer(ctx, jailer_base(ctx, "refuse-exec", "/bin/sleep") + ["--", "60"])
    check(rc != 0 and "cannot take the jail over" in out, f"/bin/sleep: exit {rc}, {out!r}")
    # Without the sandbox Firecracker could lift its own CPU limit.
    rc, out = run_jailer(ctx, jailer_base(ctx, "refuse-cpu") + [
        "--cgroup", "cpu.cfs_quota_us=50000", "--", "--api-sock", "/run/firecracker.socket", "--no-seccomp"])
    check(rc != 0 and "holds only with the sandbox" in out, f"CPU limit, --no-seccomp: exit {rc}, {out!r}")
    # Firecracker refuses a hand-over it cannot complete (not root).
    fc = os.path.join(ctx.base, "fc-nobody")
    shutil.copy(ctx.firecracker, fc)
    os.chmod(fc, 0o755)
    p = subprocess.run(["sudo", "-n", "-u", "nobody", "/usr/bin/env", f"WICK_JAIL={UID}:{GID}:/var/empty",
                        fc, "--no-api"], capture_output=True, text=True, timeout=20)
    out = (p.stdout + p.stderr).strip()
    check(p.returncode != 0 and "NotRoot" in out, f"WICK_JAIL as nobody: exit {p.returncode}, {out!r}")
    return (f"{len(cases)} options, a CPU limit without the sandbox and a binary without the "
            "hand-over refused; hand-over needs root")


def stage_jail(ctx):
    """The jailed process: user, group, root directory, files and sockets it can reach (no VM)."""
    jail = Jail(ctx, "jail", [ctx.kernel])
    secret = os.path.join(ctx.base, "secret")
    with open(secret, "w") as f:
        f.write("outside")
    os.symlink("/etc/hosts", jail.host("/hosts-link"))
    vm = JailedVm(ctx, "jail", jail)
    pid = vm.proc.pid
    uid, gid, _ = proc_ids(pid)
    check((uid, gid) == (UID, GID), f"uid/gid {uid}/{gid}")
    with open(jail.host("/firecracker.pid")) as f:
        check(int(f.read()) == pid, "pid file")
    st = os.lstat(jail.host("/tmp"))
    check(os.path.stat.S_ISDIR(st.st_mode) and (st.st_uid, st.st_mode & 0o777) == (UID, 0o700),
          f"jail /tmp {st.st_uid} {oct(st.st_mode)}")
    roots = proc_root(pid)
    check(os.path.realpath(jail.root) in roots, f"lsof root/cwd {roots}")
    st = os.stat(jail.root)
    check((st.st_uid, st.st_gid, st.st_mode & 0o777) == (UID, GID, 0o700),
          f"jail root {st.st_uid}:{st.st_gid} {oct(st.st_mode)}")
    # Firecracker started as root from a root-owned, read-only copy next to
    # the jail, which the jailed user never could write.
    exe = os.path.join(os.path.dirname(jail.root), "firecracker")
    st = os.stat(exe)
    check(st.st_uid == 0 and st.st_mode & 0o222 == 0, f"exec'd copy {st.st_uid} {oct(st.st_mode)}")
    txt = subprocess.run(["lsof", "-a", "-p", str(pid), "-d", "txt", "-Fn"], capture_output=True,
                         text=True).stdout
    check(f"n{exe}" in txt.splitlines(), f"executable of {pid} is not {exe}: {txt!r}")
    # Inside the jail: the kernel by its jailed path.
    vm.api("PUT", "/boot-source", {"kernel_image_path": "/" + bt.KERNEL, "boot_args": bt.BOOT_ARGS})
    # Outside it: by an absolute path, by `..`, by a link planted in the jail.
    for path in [secret, "/../../../../../../" + secret.lstrip("/"), "/hosts-link", "/etc/hosts"]:
        vm.api("PUT", "/drives/x", {"drive_id": "x", "path_on_host": path, "is_root_device": False,
                                    "is_read_only": True}, expect=(400,))
    # A Unix socket the operator listens on inside the jail is reachable
    # (vsock's guest-to-host connections, a network endpoint).
    vm.api("PUT", "/vsock", {"guest_cid": 3, "uds_path": "/v.sock"})
    vm.kill()
    return "uid/gid, pid file, chroot, exec'd from a root-owned copy; outside files unreachable"


def stage_daemonize(ctx):
    jail = Jail(ctx, "daemon")
    rc, out = run_jailer(ctx, jailer_base(ctx, "daemon") + ["--daemonize", "--", "--api-sock",
                                                             "/run/firecracker.socket"])
    check(rc == 0, f"jailer exit {rc}: {out!r}")
    deadline = time.time() + 10
    while not os.path.exists(jail.host("/firecracker.pid")) and time.time() < deadline:
        time.sleep(0.05)
    with open(jail.host("/firecracker.pid")) as f:
        pid = int(f.read())
    try:
        deadline = time.time() + 10
        while not os.path.exists(jail.host("/run/firecracker.socket")) and time.time() < deadline:
            time.sleep(0.05)
        uid, gid, ppid = proc_ids(pid)
        check((uid, gid, ppid) == (UID, GID, 1), f"daemon uid/gid/ppid {uid}/{gid}/{ppid}")
        conn = bt.UnixHTTPConnection(jail.host("/run/firecracker.socket"))
        conn.request("GET", "/")
        check(conn.getresponse().status == 200, "API of the daemon")
        conn.close()
        sid = subprocess.run(["ps", "-o", "sess=,tty=", "-p", str(pid)], capture_output=True,
                             text=True).stdout.split()
        check(sid[-1] in ("??", "-"), f"daemon has a terminal: {sid}")
    finally:
        os.kill(pid, signal.SIGKILL)
    return "double fork, setsid, no terminal, pid file, API answers"


def stage_limits(ctx):
    """The memory cgroup becomes a jetsam limit (the jailer's jetsam priority kept), the CPU cgroup a CPU limit."""
    jail = Jail(ctx, "limits")
    vm = JailedVm(ctx, "limits", jail, ["--cgroup", "memory.limit_in_bytes=314572800",
                                        "--cgroup", "cpu.cfs_quota_us=150000",
                                        "--cgroup", "cpu.cfs_period_us=200000",
                                        "--resource-limit", "no-file=512"])
    prio, limit = jetsam(vm.proc.pid)
    own_prio, _ = jetsam(os.getpid())
    check(limit == 300, f"jetsam limit {limit} MiB")
    check(prio == own_prio, f"jetsam priority {prio}, the jailer's parent has {own_prio}")
    # THROTTLE (1), 75% of one CPU, refilled every second.
    check(cpu_limit(vm.proc.pid) == (1, 75, 1), f"v1 CPU limit {cpu_limit(vm.proc.pid)}")
    vm.kill()
    jail = Jail(ctx, "limits2")
    vm = JailedVm(ctx, "limits2", jail, ["--cgroup-version", "2", "--cgroup", "memory.max=209715200",
                                         "--cgroup", "cpu.max=250000 100000"])
    check(jetsam(vm.proc.pid)[1] == 200, f"v2 jetsam limit {jetsam(vm.proc.pid)[1]} MiB")
    check(cpu_limit(vm.proc.pid) == (1, 250, 1), f"v2 CPU limit {cpu_limit(vm.proc.pid)}")
    vm.kill()
    return f"jetsam limit 300 MiB (v1), 200 MiB (v2), priority {prio} kept; CPU 75% (v1), 250% (v2)"


def stage_boot(ctx):
    """VM: a guest boots in the jail; block, vsock both ways, snapshot and restore in a second jail."""
    jail = Jail(ctx, "boot", [ctx.kernel, ctx.rootfs])
    cfg = jail_config(vcpus=2, vsock={"guest_cid": 3, "uds_path": "/v.sock"})
    vm = JailedVm(ctx, "boot", jail, config=cfg)
    vm.wait_for(r"Run /bin/sh as init process", 60)
    vm.shell()
    _, out = vm.sh("echo WICK-$((6*7)); nproc")
    check(out.split() == ["WICK-42", "2"], f"guest: {out!r}")
    uds = jail.host("/v.sock")
    bt.guest_vsock_services(vm, uds)
    bt.vsock_host_to_guest(uds, 1 << 20)
    # The jailed user connects to the socket the host listens on: writable by it.
    old = os.umask(0)
    try:
        bt.vsock_guest_to_host(vm, uds)
    finally:
        os.umask(old)
    vm.sh("A=before-$((6*7))")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": "/vm.state",
                                       "mem_file_path": "/vm.mem"})
    vm.kill()
    for f in ("vm.state", "vm.mem"):
        st = os.stat(jail.host(f))
        check(st.st_uid == UID, f"{f} owned by {st.st_uid}")
    jail2 = Jail(ctx, "restore", [ctx.kernel, ctx.rootfs, jail.host("vm.state"), jail.host("vm.mem")])
    vm = JailedVm(ctx, "restore", jail2)
    vm.api("PUT", "/snapshot/load", {"snapshot_path": "/vm.state",
                                     "mem_backend": {"backend_type": "File", "backend_path": "/vm.mem"},
                                     "resume_vm": True})
    _, out = vm.sh("echo restored $A")
    check(out == "restored before-42", f"after restore: {out!r}")
    bt.vsock_host_to_guest(jail2.host("/v.sock"), 1 << 20)
    vm.reboot()
    return "boot, 2 vCPUs, vsock both ways, snapshot in the jail, restore in another jail"


def stage_memory(ctx):
    """VM: the guest using memory past the cgroup limit kills the VMM, as the cgroup OOM killer does."""
    results = []
    for limit_mib, expect_kill in ((300, True), (3000, False)):
        jail = Jail(ctx, f"mem{limit_mib}", [ctx.kernel, ctx.rootfs])
        vm = JailedVm(ctx, f"mem{limit_mib}", jail,
                      ["--cgroup", f"memory.limit_in_bytes={limit_mib << 20}"], config=jail_config(mem=1024))
        vm.shell()
        vm.sh("mount -t tmpfs -o size=900m tmpfs /run")
        try:
            vm.sh("dd if=/dev/zero of=/run/x bs=1M count=700 2>/dev/null; echo done", timeout=120)
            killed = False
        except Failure:
            killed = vm.proc.wait(10) == -signal.SIGKILL
        check(killed == expect_kill, f"limit {limit_mib} MiB, guest wrote 700 MiB: killed={killed} "
                                     f"({vm.exit_reason()})")
        results.append(f"{limit_mib} MiB: {'killed' if killed else 'survived'}")
        vm.kill()
    return "guest writes 700 MiB; " + ", ".join(results)


def stage_cpu(ctx):
    """VM: two guest vCPUs spinning use no more of the host than the CPU cgroup allows."""
    used = {}
    for name, percent in (("cpu-free", None), ("cpu50", 50)):
        jail = Jail(ctx, name, [ctx.kernel, ctx.rootfs])
        cg = ["--cgroup-version", "2", "--cgroup", f"cpu.max={percent * 1000} 100000"] if percent else []
        vm = JailedVm(ctx, name, jail, cg, config=jail_config(vcpus=2))
        vm.shell()
        vm.sh("for i in 1 2; do (while :; do :; done) & done; echo spinning")
        time.sleep(2)
        t0, c0 = time.time(), cpu_seconds(vm.proc.pid)
        time.sleep(8)
        used[name] = 100 * (cpu_seconds(vm.proc.pid) - c0) / (time.time() - t0)
        vm.kill()
    free, limited = used["cpu-free"], used["cpu50"]
    # The unlimited VM shows the guest could use more than the limit.
    check(free > 120, f"unlimited VM used {free:.0f}% of one CPU: the host is too busy to measure")
    check(limited <= 60, f"VM limited to 50% used {limited:.0f}% of one CPU")
    return f"2 vCPUs spinning: {free:.0f}% of one CPU unlimited, {limited:.0f}% with cpu.max 50%"


STAGES = {
    "refuse": stage_refuse,
    "jail": stage_jail,
    "daemonize": stage_daemonize,
    "limits": stage_limits,
    "boot": stage_boot,
    "memory": stage_memory,
    "cpu": stage_cpu,
}
VM_STAGES = ("boot", "memory", "cpu")


class Context:
    def __init__(self, args):
        self.jailer = args.jailer
        self.firecracker = args.firecracker
        self.out = args.out
        # Unix socket paths must be shorter than 104 bytes: a short base.
        self.base = tempfile.mkdtemp(prefix="wick-jt-", dir="/private/tmp")
        os.chmod(self.base, 0o755)
        self.kernel = bt.fetch(args.cache, bt.KERNEL)
        self.rootfs = bt.fetch(args.cache, bt.ROOTFS)
        self.vms = []
        self.sock = self.base

    def cleanup(self):
        for vm in self.vms:
            vm.kill()
        self.vms = []


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--jailer", required=True)
    p.add_argument("--firecracker", required=True)
    p.add_argument("--cache", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--no-vm", action="store_true", help="skip the stages that boot a VM")
    p.add_argument("stages", nargs="*", help=f"stages (default: all): {', '.join(STAGES)}")
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error("needs root (the jailer chroots and changes user)")
    stages = args.stages or [s for s in STAGES if not (args.no_vm and s in VM_STAGES)]
    for s in stages:
        if s not in STAGES:
            p.error(f"unknown stage {s}")
    os.makedirs(args.out, exist_ok=True)
    bt.exit_on_signals()
    ctx = Context(args)
    results = []
    try:
        for name in stages:
            print(f"== {name}", flush=True)
            t0 = time.time()
            try:
                results.append((name, True, STAGES[name](ctx)))
            except Failure as e:
                results.append((name, False, str(e)))
            except Exception:
                results.append((name, False, traceback.format_exc()))
            ok, detail = results[-1][1:]
            print(f"   {'PASS' if ok else 'FAIL'} ({time.time() - t0:.1f}s): {detail}", flush=True)
    finally:
        subprocess.run(["pkill", "-9", "-f", ctx.base], check=False)
        leftover = []
        # onerror: sudo's python3 can be the system's 3.9, without onexc.
        shutil.rmtree(ctx.base, onerror=lambda _f, path, _e: leftover.append(path))
        if leftover:
            # Reported, never left silently: tools/clean.sh removes them later.
            print(f"cleanup: could not remove {len(leftover)} paths, e.g. {leftover[0]}", file=sys.stderr)
    failed = bt.summarize(args.out, results)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
