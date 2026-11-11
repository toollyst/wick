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

    def __init__(self, ctx, name, jail, jailer_args=(), fc_args=(), config=None, wait_api=True,
                 pass_fds=()):
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
                                     stderr=subprocess.STDOUT, pass_fds=pass_fds)
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
        (["--netns", "/var/run/netns/x"], "The jail's network \"/var/run/netns/x\" (--netns)"),
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
    # Descriptors the jailer inherits: a file and a directory outside the
    # jail (fchdir to one would leave the chroot). Upstream's
    # close_fds_by_close_range closes them before the exec.
    outside = os.path.join(ctx.base, "outside-dir")
    os.mkdir(outside)
    leaked = [os.open(secret, os.O_RDONLY), os.open(outside, os.O_RDONLY)]
    for fd in leaked:
        os.set_inheritable(fd, True)
    try:
        vm = JailedVm(ctx, "jail", jail, pass_fds=leaked)
    finally:
        for fd in leaked:
            os.close(fd)
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
    names = subprocess.run(["lsof", "-a", "-p", str(pid), "-Fn"], capture_output=True,
                           text=True).stdout.splitlines()
    for path in (secret, outside):
        check(f"n{os.path.realpath(path)}" not in names and f"n{path}" not in names,
              f"Firecracker holds the jailer's descriptor for {path}")
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
    return ("uid/gid, pid file, chroot, exec'd from a root-owned copy, no inherited descriptors; "
            "outside files unreachable")


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


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def api_ok(sock):
    conn = bt.UnixHTTPConnection(sock)
    try:
        conn.request("GET", "/")
        return conn.getresponse().status == 200
    finally:
        conn.close()


def stage_pidns(ctx):
    """--new-pid-ns: upstream's process tree (the jailer exits 0, the pid file names its child), and
    signals from outside: only the handled ones (and SIGKILL) reach Firecracker, as for a namespace's init."""
    jail = Jail(ctx, "pidns")
    # Firecracker runs on with the jailer's standard descriptors: a file,
    # which the jailer's exit does not wait for.
    log = os.path.join(ctx.out, "pidns.log")
    with open(log, "w") as f:
        p = subprocess.Popen([ctx.jailer] + jailer_base(ctx, "pidns") + [
            "--new-pid-ns", "--", "--api-sock", "/run/firecracker.socket"],
            stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)
        rc = p.wait(timeout=20)
    with open(log) as f:
        out = f.read()
    check(rc == 0, f"jailer exit {rc}: {out!r}")
    with open(jail.host("/firecracker.pid")) as f:
        pid = int(f.read())
    try:
        check(pid != p.pid, f"pid file names the jailer ({pid})")
        deadline = time.time() + 10
        while not os.path.exists(jail.host("/run/firecracker.socket")) and time.time() < deadline:
            time.sleep(0.05)
        uid, gid, _ = proc_ids(pid)
        check((uid, gid) == (UID, GID), f"uid/gid {uid}/{gid}")
        check(api_ok(jail.host("/run/firecracker.socket")), "API of Firecracker in its namespace")
        dropped = [signal.SIGTERM, signal.SIGINT, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2,
                   signal.SIGALRM, signal.SIGTSTP, signal.SIGVTALRM, signal.SIGPROF]
        for sig in dropped:
            os.kill(pid, sig)
        time.sleep(0.5)
        check(alive(pid) and api_ok(jail.host("/run/firecracker.socket")),
              "Firecracker ended by a signal it does not handle")
        # A handled signal reaches it: upstream's SIGHUP handler ends it.
        os.kill(pid, signal.SIGHUP)
        deadline = time.time() + 5
        while alive(pid) and time.time() < deadline:
            time.sleep(0.05)
        check(not alive(pid), "SIGHUP (handled) did not reach Firecracker")
    finally:
        if alive(pid):
            os.kill(pid, signal.SIGKILL)
    # Control: without --new-pid-ns, SIGTERM ends Firecracker.
    jail = Jail(ctx, "pidns-control")
    rc, out = run_jailer(ctx, jailer_base(ctx, "pidns-control") + ["--daemonize", "--", "--api-sock",
                                                                    "/run/firecracker.socket"])
    check(rc == 0, f"control jailer exit {rc}: {out!r}")
    deadline = time.time() + 10
    while not os.path.exists(jail.host("/run/firecracker.socket")) and time.time() < deadline:
        time.sleep(0.05)
    with open(jail.host("/firecracker.pid")) as f:
        control = int(f.read())
    try:
        os.kill(control, signal.SIGTERM)
        deadline = time.time() + 5
        while alive(control) and time.time() < deadline:
            time.sleep(0.05)
        check(not alive(control), "control: SIGTERM did not end Firecracker outside a namespace")
    finally:
        if alive(control):
            os.kill(control, signal.SIGKILL)
    return (f"jailer exits 0, pid file names its child; {len(dropped)} unhandled signals dropped, "
            "SIGHUP (handled) delivered; control without the flag ended by SIGTERM")


# The API process's share of a jail's limits (vmm::ext::jail::API_MEMORY_MIB,
# API_CPU_PERCENT): with the API on, Firecracker and its API process together
# stay within the jail's limits, as one cgroup on Linux holds both.
API_MIB, API_CPU = 32, 1


def api_process(vm):
    kids = bt.children(vm.proc.pid)
    check(len(kids) == 1, f"Firecracker's child processes: {kids}")
    return kids[0]


def stage_limits(ctx):
    """The memory cgroup becomes a jetsam limit (the jailer's jetsam priority kept), the CPU cgroup a CPU limit,
    shared with the API process so that together they stay within the jail's."""
    jail = Jail(ctx, "limits")
    vm = JailedVm(ctx, "limits", jail, ["--cgroup", "memory.limit_in_bytes=314572800",
                                        "--cgroup", "cpu.cfs_quota_us=150000",
                                        "--cgroup", "cpu.cfs_period_us=200000",
                                        "--resource-limit", "no-file=512"])
    api = api_process(vm)
    prio, limit = jetsam(vm.proc.pid)
    own_prio, _ = jetsam(os.getpid())
    check(limit == 300 - API_MIB, f"jetsam limit {limit} MiB")
    check(jetsam(api)[1] == API_MIB, f"the API process's jetsam limit {jetsam(api)[1]} MiB")
    check(prio == own_prio, f"jetsam priority {prio}, the jailer's parent has {own_prio}")
    # THROTTLE (1), 75% of one CPU in all, refilled every second.
    check(cpu_limit(vm.proc.pid) == (1, 75 - API_CPU, 1), f"v1 CPU limit {cpu_limit(vm.proc.pid)}")
    check(cpu_limit(api) == (1, API_CPU, 1), f"the API process's CPU limit {cpu_limit(api)}")
    check(proc_ids(api)[:2] == (UID, GID), f"the API process runs as {proc_ids(api)[:2]}")
    vm.kill()
    jail = Jail(ctx, "limits2")
    vm = JailedVm(ctx, "limits2", jail, ["--cgroup-version", "2", "--cgroup", "memory.max=209715200",
                                         "--cgroup", "cpu.max=250000 100000"])
    api = api_process(vm)
    check(jetsam(vm.proc.pid)[1] == 200 - API_MIB, f"v2 jetsam limit {jetsam(vm.proc.pid)[1]} MiB")
    check(jetsam(api)[1] == API_MIB, f"v2: the API process's jetsam limit {jetsam(api)[1]} MiB")
    check(cpu_limit(vm.proc.pid) == (1, 250 - API_CPU, 1), f"v2 CPU limit {cpu_limit(vm.proc.pid)}")
    check(cpu_limit(api) == (1, API_CPU, 1), f"v2: the API process's CPU limit {cpu_limit(api)}")
    vm.kill()
    return (f"jetsam 300 MiB = {300 - API_MIB} + {API_MIB} (API process) (v1), 200 = {200 - API_MIB} + {API_MIB} "
            f"(v2), priority {prio} kept; CPU 75% = {75 - API_CPU} + {API_CPU} (v1), 250% (v2)")


def stage_no_api(ctx):
    """VM: without the API there is no API process, and Firecracker has the jail's whole memory limit."""
    jail = Jail(ctx, "limits3", [ctx.kernel, ctx.rootfs])
    vm = JailedVm(ctx, "limits3", jail, ["--cgroup", "memory.limit_in_bytes=314572800"],
                  fc_args=["--no-api"], config=jail_config(), wait_api=False)
    vm.wait_for(r"Run /bin/sh as init process", 60)
    check(bt.children(vm.proc.pid) == [], f"--no-api: child processes {bt.children(vm.proc.pid)}")
    check(jetsam(vm.proc.pid)[1] == 300, f"--no-api: jetsam limit {jetsam(vm.proc.pid)[1]} MiB")
    vm.kill()
    return "--no-api: all 300 MiB, no API process"


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
        # Firecracker and its API process, as one cgroup holds both on Linux.
        procs = [vm.proc.pid] + bt.children(vm.proc.pid)
        t0, c0 = time.time(), sum(cpu_seconds(p) for p in procs)
        time.sleep(8)
        used[name] = 100 * (sum(cpu_seconds(p) for p in procs) - c0) / (time.time() - t0)
        vm.kill()
    free, limited = used["cpu-free"], used["cpu50"]
    # The unlimited VM shows the guest could use more than the limit.
    check(free > 120, f"unlimited VM used {free:.0f}% of one CPU: the host is too busy to measure")
    check(limited <= 60, f"VM limited to 50% used {limited:.0f}% of one CPU")
    return f"2 vCPUs spinning: {free:.0f}% of one CPU unlimited, {limited:.0f}% with cpu.max 50%"


class Network:
    """A jail's network (--netns): a directory of endpoints. Behind each
    interface name, a host socket in the directory that attaches to the
    jail's endpoint of that name once it is there, answers ARP and ICMP echo
    for its address and records every frame it gets."""

    def __init__(self, path, host_ip, names=("tap0",)):
        import socket as so
        self.so = so
        self.path = path
        self.host_ip = so.inet_aton(host_ip)
        os.makedirs(path)
        self.frames = []
        self.stop = False
        self.hosts = {}
        for name in names:
            sock = so.socket(so.AF_UNIX, so.SOCK_DGRAM)
            sock.bind(os.path.join(path, f"host-{name}"))
            sock.settimeout(0.2)
            self.hosts[name] = sock
            bt.threading.Thread(target=self._host, args=(sock, os.path.join(path, name)), daemon=True).start()

    def _host(self, sock, endpoint):
        import struct
        mac = bytes.fromhex("02000a0000fe")
        attached = False
        while not self.stop:
            if not attached:
                # An empty datagram attaches to the endpoint once it exists.
                try:
                    sock.sendto(b"", endpoint)
                    attached = True
                except OSError:
                    time.sleep(0.1)
                    continue
            try:
                frame, _ = sock.recvfrom(65536)
            except self.so.timeout:
                continue
            except OSError:
                return
            if not frame:
                continue
            self.frames.append(frame)
            src, ethertype = frame[6:12], struct.unpack("!H", frame[12:14])[0]
            body = frame[14:]
            reply = None
            if ethertype == 0x0806 and body[24:28] == self.host_ip and body[6:8] == b"\0\1":
                arp = body[:6] + b"\0\2" + mac + self.host_ip + body[8:18]
                reply = src + mac + b"\x08\x06" + arp
            elif ethertype == 0x0800 and body[16:20] == self.host_ip and body[9] == 1:
                ihl = (body[0] & 0xF) * 4
                total = struct.unpack("!H", body[2:4])[0]
                icmp = body[ihl:total]
                if icmp[0] != 8:
                    continue
                icmp = b"\0\0\0\0" + icmp[4:]
                icmp = icmp[:2] + struct.pack("!H", bt.csum(icmp)) + icmp[4:]
                hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0x4000, 64, 1, 0,
                                  self.host_ip, body[12:16])
                hdr = hdr[:10] + struct.pack("!H", bt.csum(hdr)) + hdr[12:]
                reply = src + mac + b"\x08\x00" + hdr + icmp
            if reply:
                try:
                    sock.sendto(reply, endpoint)
                except OSError:
                    attached = False

    def frames_from(self, mac):
        return [f for f in self.frames if f[6:12] == bytes.fromhex(mac.replace(":", ""))]

    def close(self):
        self.stop = True
        for s in self.hosts.values():
            s.close()


def stage_netns(ctx):
    """VM: two jails, each with a network of its own, reach only their own network; jails given one share it."""
    nets = {"a": ("10.0.1", "06:00:0a:00:01:02"), "b": ("10.0.2", "06:00:0a:00:02:02")}
    spaces = {n: Network(os.path.join(ctx.base, f"net-{n}"), f"{net}.1", ("tap0", "tap1"))
              for n, (net, _) in nets.items()}
    try:
        vms = {}
        for n, (net, mac) in nets.items():
            jail = Jail(ctx, f"netns-{n}", [ctx.kernel, ctx.rootfs])
            cfg = jail_config(network_interfaces=[{"iface_id": "eth0", "host_dev_name": "tap0",
                                                   "guest_mac": mac}])
            vms[n] = JailedVm(ctx, f"netns-{n}", jail, ["--netns", spaces[n].path], config=cfg)
        for n, (net, _) in nets.items():
            vm = vms[n]
            vm.shell()
            vm.sh(f"ip addr add {net}.2/24 dev eth0 && ip link set eth0 up")
            _, out = vm.sh(f"ping -c 3 -i 0.3 -W 3 {net}.1")
            check(" 0% packet loss" in out, f"jail {n}: ping its own host {net}.1: {out}")
            check(os.path.exists(os.path.join(spaces[n].path, "tap0")), f"jail {n}: no endpoint in its network")
        # Negative control: jail a, given an address on b's network, does
        # not reach b's host, and b's network never sees a frame of a's.
        a, b = vms["a"], spaces["b"]
        a.sh("ip addr add 10.0.2.9/24 dev eth0")
        _, out = a.sh("ping -c 3 -i 0.3 -W 2 10.0.2.1", ok=False)
        check(" 100% packet loss" in out, f"jail a reached b's network: {out}")
        check(not b.frames_from(nets["a"][1]), f"b's network got {len(b.frames_from(nets['a'][1]))} frames of a's")
        check(spaces["a"].frames_from(nets["a"][1]), "a's network saw none of a's frames")
        # A third jail given a's directory shares a's network, as a second
        # Firecracker in one namespace does: its tap1 reaches a's host.
        jail = Jail(ctx, "netns-c", [ctx.kernel, ctx.rootfs])
        cfg = jail_config(network_interfaces=[{"iface_id": "eth0", "host_dev_name": "tap1",
                                               "guest_mac": "06:00:0a:00:01:03"}])
        c = JailedVm(ctx, "netns-c", jail, ["--netns", spaces["a"].path], config=cfg)
        c.shell()
        c.sh("ip addr add 10.0.1.3/24 dev eth0 && ip link set eth0 up")
        _, out = c.sh("ping -c 3 -i 0.3 -W 3 10.0.1.1")
        check(" 0% packet loss" in out, f"jail c in a's network: ping a's host: {out}")
        c.reboot()
        # In a network, vmnet (the host's own) is refused, and so is a name
        # in use (jail a holds tap0), as a busy TAP.
        jail = Jail(ctx, "netns-refuse")
        vm = JailedVm(ctx, "netns-refuse", jail, ["--netns", spaces["a"].path])
        for name, want in (("vmnet-shared", "not the jail's"), ("tap0", "os error 16")):
            r = vm.api("PUT", "/network-interfaces/eth0", {"iface_id": "eth0", "host_dev_name": name},
                       expect=(400,))
            check(want in json.dumps(r), f"{name}: {r}")
        vm.kill()
        for vm in vms.values():
            vm.reboot()
        # Not a directory: the jailer fails before anything runs.
        bogus = os.path.join(ctx.base, "not-a-network")
        open(bogus, "w").close()
        rc, out = run_jailer(ctx, jailer_base(ctx, "netns-bogus") + ["--netns", bogus])
        check(rc != 0 and "a network is a directory of endpoints" in out, f"--netns {bogus}: {rc} {out!r}")
    finally:
        for s in spaces.values():
            s.close()
    return ("two jails ping their own network's host; a on b's subnet: 100% loss, b saw no frame of a; "
            "a third jail in a's directory reaches a's host; vmnet and a busy name refused; a file refused")


STAGES = {
    "refuse": stage_refuse,
    "jail": stage_jail,
    "daemonize": stage_daemonize,
    "pidns": stage_pidns,
    "limits": stage_limits,
    "no-api": stage_no_api,
    "boot": stage_boot,
    "netns": stage_netns,
    "memory": stage_memory,
    "cpu": stage_cpu,
}
VM_STAGES = ("no-api", "boot", "netns", "memory", "cpu")


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
