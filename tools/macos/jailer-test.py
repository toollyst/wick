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
import errno as errno_mod
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


def jail_config(vcpus=1, mem=256, machine=None, drives=(), **extra):
    cfg = {
        "boot-source": {"kernel_image_path": "/" + bt.KERNEL, "boot_args": bt.BOOT_ARGS},
        "drives": [{"drive_id": "rootfs", "path_on_host": "/" + bt.ROOTFS,
                    "is_root_device": True, "is_read_only": True}] + list(drives),
        "machine-config": {"vcpu_count": vcpus, "mem_size_mib": mem, **(machine or {})},
    }
    cfg.update({k.replace("_", "-"): v for k, v in extra.items()})
    return cfg


class OperatorServer:
    """A process of the operator outside the jail (a uffd handler, a vhost-user
    backend) listening on a Unix socket placed in the jail, as on Linux, where
    the jailed Firecracker reaches only sockets in its chroot. The socket is
    made connectable by the jail's user (umask 0), as an operator does."""

    def __init__(self, ctx, name, cmd, sock):
        self.name = name
        self.log_path = os.path.join(ctx.out, f"{name}.log")
        self.log = open(self.log_path, "w")
        old = os.umask(0)
        try:
            self.proc = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT)
        finally:
            os.umask(old)
        deadline = time.time() + 10
        while not os.path.exists(sock):
            check(self.proc.poll() is None and time.time() < deadline,
                  f"{name} did not listen ({self.proc.poll()}; log {self.log_path})")
            time.sleep(0.05)

    def alive(self):
        check(self.proc.poll() is None, f"{self.name} exited {self.proc.poll()}; log {self.log_path}")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


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


# ---------------------------------------------------------------- resource limits

# A program the jailer runs in Firecracker's place (it carries the hand-over
# mark, vmm::ext::jail::HANDOVER_MARK, so the jailer takes it): the process the
# jailer execs (POSIX_SPAWN_SETEXEC, same PID) reports its RLIMIT_NOFILE and
# RLIMIT_FSIZE, then opens descriptors until one fails, and with SIGXFSZ
# ignored writes past the file size limit, as upstream's test_jail.py reads
# Firecracker's limits with prlimit, which macOS lacks (a process reads only
# its own). Its last argument is the file to write.
RLIMIT_PROBE_C = r"""
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
__attribute__((used)) static const char mark[] = "wick-jail-handover:v1";
static long long lim(rlim_t v) { return v == RLIM_INFINITY ? -1 : (long long)v; }
int main(int argc, char **argv) {
    struct rlimit nofile, fsize;
    getrlimit(RLIMIT_NOFILE, &nofile);
    getrlimit(RLIMIT_FSIZE, &fsize);
    int open_before = 0;
    for (int fd = 0; fd < 65536; fd++) if (fcntl(fd, F_GETFD) != -1) open_before++;
    int opened = 0, err = 0;
    for (;;) { if (open("/dev/null", O_RDONLY) < 0) { err = errno; break; } opened++; }
    long long written = -1; int werr = 0, oerr = 0;
    if (fsize.rlim_cur != RLIM_INFINITY && argc > 1) {
        signal(SIGXFSZ, SIG_IGN);
        close(3);  /* a descriptor for the file */
        int f = open(argv[argc - 1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (f < 0) {
            oerr = errno;
        } else {
            char buf[4096]; memset(buf, 7, sizeof buf); written = 0;
            for (;;) { ssize_t n = write(f, buf, sizeof buf); if (n < 0) { werr = errno; break; } written += n; }
        }
    }
    char cwd[1024] = "?"; getcwd(cwd, sizeof cwd);
    printf("RLIMITS nofile %lld %lld fsize %lld %lld open_before %d opened %d errno %d written %lld werrno %d "
           "oerrno %d uid %d mark %c cwd %s file %s\n",
           lim(nofile.rlim_cur), lim(nofile.rlim_max), lim(fsize.rlim_cur), lim(fsize.rlim_max),
           open_before, opened, err, written, werr, oerr, (int)getuid(), mark[0], cwd, argc > 1 ? argv[argc - 1] : "-");
    return 0;
}
"""


def build_rlimit_probe(directory):
    """Compiles the probe into `directory`; returns its path."""
    src = os.path.join(directory, "rlimit-probe.c")
    exe = os.path.join(directory, "rlimit-probe")
    with open(src, "w") as f:
        f.write(RLIMIT_PROBE_C)
    subprocess.run(["/usr/bin/cc", "-O2", "-o", exe, src], check=True)
    with open(exe, "rb") as f:
        check(b"wick-jail-handover:v1\0" in f.read(), "the probe does not carry the hand-over mark")
    return exe


def parse_probe(out):
    """The probe's report: {name: int}."""
    line = next((l for l in out.splitlines() if l.startswith("RLIMITS ")), None)
    check(line is not None, f"no report from the probe: {out!r}")
    words = line.split()[1:]
    vals = {}
    i = 0
    while i < len(words):
        name = words[i]
        if name in ("nofile", "fsize"):
            vals[name] = (int(words[i + 1]), int(words[i + 2]))
            i += 3
        elif name in ("mark", "cwd", "file"):
            vals[name] = words[i + 1]
            i += 2
        else:
            vals[name] = int(words[i + 1])
            i += 2
    return vals


def check_probe(vals, nofile, fsize, what):
    """Linux's rules (upstream's test_jail.py check_limits and
    test_args_default_resource_limits): soft and hard both the limit; the
    descriptor past it fails with EMFILE; a write past the file size limit
    fails with EFBIG (SIGXFSZ ignored) at the limit."""
    check(vals["nofile"] == (nofile, nofile), f"{what}: RLIMIT_NOFILE {vals['nofile']}, wanted {nofile}")
    check(vals["fsize"] == (fsize, fsize), f"{what}: RLIMIT_FSIZE {vals['fsize']}, wanted {fsize}")
    check(vals["open_before"] + vals["opened"] == nofile and vals["errno"] == errno_mod.EMFILE,
          f"{what}: {vals['open_before']} open + {vals['opened']} opened before errno {vals['errno']}, "
          f"wanted EMFILE at descriptor {nofile + 1}")
    if fsize != -1:
        check(vals["oerrno"] == 0, f"{what}: opening {vals['file']} (uid {vals['uid']}, cwd {vals['cwd']}) "
              f"failed with errno {vals['oerrno']}")
        check(vals["written"] == fsize and vals["werrno"] == errno_mod.EFBIG,
              f"{what}: {vals['written']} bytes written before errno {vals['werrno']}, wanted EFBIG at {fsize}")


def self_check_probe():
    """What runs without root: the probe builds, carries the mark, and
    measures limits set on it (here by this process, not by a jailer)."""
    import resource
    d = tempfile.mkdtemp(prefix="wick-jt-probe-")
    try:
        exe = build_rlimit_probe(d)

        def limits():
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))

        out = subprocess.run([exe, os.path.join(d, "big")], preexec_fn=limits, capture_output=True,
                             text=True, check=True, close_fds=True).stdout
        check_probe(parse_probe(out), 64, 1 << 20, "self-check")
        # The layout the limits stage gives the jailer: the probe outside
        # every jail it is run in, no file on a jail's path.
        base = os.path.join(d, "base")
        os.makedirs(probe_dir(base))
        exe = build_rlimit_probe(probe_dir(base))
        for name in ("rlimit-default", "rlimit-set"):
            root = chroot_of(base, exe, name)
            os.makedirs(root)
        # And the layout the first version had is caught.
        try:
            chroot_of(d, os.path.join(d, "rlimit-probe"), "rlimit-default")
            raise Failure("a probe built in the chroot base under its own name was not caught")
        except Failure as e:
            check("is a file where the jailer makes the jail" in str(e), str(e))
        print(f"probe self-check passed: {out.strip()}; jail paths free of files")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def chroot_of(base, exec_file, vm_id):
    """The jail's root the jailer makes: <base>/<exec file name>/<id>/root.
    Fails if a file in `base` stands on that path (the jailer would fail
    with ENOTDIR creating it), as the probe did when it was built in `base`
    under its own name."""
    root = os.path.join(base, os.path.basename(exec_file), vm_id, "root")
    path = base
    for part in os.path.relpath(root, base).split(os.sep):
        path = os.path.join(path, part)
        check(not os.path.exists(path) or os.path.isdir(path),
              f"{path} is a file where the jailer makes the jail of {exec_file}")
    check(os.path.commonpath([exec_file, root]) != root, f"{exec_file} is inside its own jail")
    return root


def probe_dir(base):
    """Where the probe is built: a directory of `base` no jail is made in
    (jails are <base>/<exec file name>/...)."""
    return os.path.join(base, "probe-build")


def jailed_probe(ctx, name, limits_args):
    """Runs the probe through the jailer with `limits_args`; returns its report.
    The macOS jailer sets the limits, leaves its chroot and execs the binary
    as root outside the jail (overlay/jailer/platform/macos exec): Firecracker
    takes the jail over itself (WICK_JAIL), the probe does not. So it runs as
    root with the host's paths and writes the file at the jail root's host
    path (a path in the jail would be the host's read-only /)."""
    if ctx.rlimit_probe is None:
        os.makedirs(probe_dir(ctx.base))
        ctx.rlimit_probe = build_rlimit_probe(probe_dir(ctx.base))
    root = chroot_of(ctx.base, ctx.rlimit_probe, name)
    big = os.path.join(root, "big")
    rc, out = run_jailer(ctx, jailer_base(ctx, name, ctx.rlimit_probe) + list(limits_args) + ["--", big])
    check(rc == 0, f"{name}: the jailed probe exited {rc}: {out!r}")
    print(f"   {name}: {out.strip()}", flush=True)
    if os.path.exists(big):
        os.unlink(big)
    return parse_probe(out)


# ---------------------------------------------------------------- stages


def stage_refuse(ctx):
    """Options the jailer cannot enforce on macOS, and binaries that cannot take a jail over."""
    cases = [
        (["--netns", "/var/run/netns/x"], "The jail's network \"/var/run/netns/x\" (--netns)"),
        # One per controller macOS cannot enforce, each with its reason.
        (["--cgroup", "cpuset.cpus=0"], "--cgroup cpuset.cpus=0 is not supported on macOS: Apple silicon has no CPU affinity"),
        (["--cgroup", "cpuset.mems=1"], "names one the host does not have"),
        (["--cgroup-version", "2", "--cgroup", "cpu.weight=100"], "no proportional share"),
        (["--cgroup", "cpu.shares=512"], "no proportional share"),
        (["--cgroup-version", "2", "--cgroup", "pids.max=10"], "no limit on a process's threads"),
        (["--cgroup-version", "2", "--cgroup", "io.weight=default 200"], "no per-process I/O"),
        (["--cgroup-version", "2", "--cgroup", "memory.high=268435456"], "hard limit only"),
        (["--cgroup-version", "2", "--cgroup", "hugetlb.2MB.max=0"], "no hugetlb page pool"),
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
    # Every CPU and memory node is no restriction: accepted (the jailer gets
    # as far as the exec, which the binary without the hand-over fails).
    ncpu = os.cpu_count()
    rc, out = run_jailer(ctx, jailer_base(ctx, "cpuset-all", "/bin/sleep") + [
        "--cgroup", f"cpuset.cpus=0-{ncpu - 1}", "--cgroup", "cpuset.mems=0", "--", "60"])
    check(rc != 0 and "cannot take the jail over" in out, f"cpuset of every CPU: exit {rc}, {out!r}")
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
    # --resource-limit, read back from the process the jailer execs, as
    # upstream's test_jail.py reads Firecracker's: by default no-file is 2048
    # and fsize unlimited; set, both are what was asked.
    check_probe(jailed_probe(ctx, "rlimit-default", []), 2048, -1, "default")
    check_probe(jailed_probe(ctx, "rlimit-set", ["--resource-limit", "no-file=512",
                                                 "--resource-limit", f"fsize={1 << 20}"]),
                512, 1 << 20, "no-file=512, fsize=1 MiB")
    # Firecracker itself with too few descriptors does not start
    # (upstream's test_negative_no_file_limit).
    Jail(ctx, "nofile3")
    rc, out = run_jailer(ctx, jailer_base(ctx, "nofile3") + ["--resource-limit", "no-file=3", "--",
                                                             "--api-sock", "/run/firecracker.socket"])
    # EMFILE is errno 24 on both; upstream's musl build words it "No file
    # descriptors available", macOS's libc "Too many open files".
    check(rc != 0 and "Too many open files (os error 24)" in out, f"no-file=3: exit {rc}, {out!r}")
    return (f"jetsam 300 MiB = {300 - API_MIB} + {API_MIB} (API process) (v1), 200 = {200 - API_MIB} + {API_MIB} "
            f"(v2), priority {prio} kept; CPU 75% = {75 - API_CPU} + {API_CPU} (v1), 250% (v2); "
            "no-file 2048 by default and 512 set (EMFILE past it), fsize unlimited by default and 1 MiB set "
            "(EFBIG at it); no-file=3 stops Firecracker with EMFILE")


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


def stage_fsize(ctx):
    """VM: a snapshot past the jail's file size limit raises SIGXFSZ, on which
    Firecracker stops as upstream's test_negative_file_size_limit asserts
    ("intercepting signal 25"); under the limit the microVM starts
    (test_positive_file_size_limit)."""
    jail = Jail(ctx, "fsize-ok", [ctx.kernel, ctx.rootfs])
    vm = JailedVm(ctx, "fsize-ok", jail, ["--resource-limit", f"fsize={(128 + 1) << 20}"],
                  config=jail_config(mem=128))
    vm.shell()
    vm.kill()
    jail = Jail(ctx, "fsize", [ctx.kernel, ctx.rootfs])
    vm = JailedVm(ctx, "fsize", jail, ["--resource-limit", f"fsize={1 << 20}"], config=jail_config())
    vm.shell()
    vm.api("PATCH", "/vm", {"state": "Paused"})
    try:
        vm.api("PUT", "/snapshot/create", {"mem_file_path": "/vm.mem", "snapshot_path": "/vm.vmstate"})
        raise Failure("a 256 MiB snapshot under a 1 MiB fsize limit was written")
    except (OSError, bt.http.client.HTTPException):
        pass
    vm.wait_exit(10)
    vm.pump.join(5)
    check("Shutting down VM after intercepting signal 25, code 0" in vm.buf, f"fsize: {vm.exit_reason()}")
    return "a 128 MiB guest starts under a 129 MiB fsize limit; a snapshot past 1 MiB: SIGXFSZ, Firecracker stops"


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


ZEROS_64M_MD5 = "7f614da9329cd3aebf59b91aadc30bf0"


def uffd_round(ctx, name, machine):
    """A jailed guest (`machine` settings) snapshotted, then restored in another
    jail with its memory served by upstream's uffd_on_demand_handler, a process
    of the operator outside the jail: the jailed Firecracker hands it the
    userfaultfd over the handler's socket in the jail (SCM_RIGHTS), and the
    handler fills the guest's pages from the memory file."""
    jail = Jail(ctx, f"{name}-snap", [ctx.kernel, ctx.rootfs])
    vm = JailedVm(ctx, f"{name}-snap", jail, config=jail_config(vcpus=2, machine=machine))
    vm.shell()
    _, bash_md5 = vm.sh("md5sum /usr/bin/bash")
    # 160 MiB in guest memory: what the handler must give back after restore.
    vm.sh("mount -t tmpfs -o size=200m tmpfs /tmp && head -c 160m /dev/urandom > /tmp/f && md5sum /tmp/f > /tmp/a", 120)
    vm.sh("A=before-$((6*7))")
    vm.api("PATCH", "/vm", {"state": "Paused"})
    vm.api("PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": "/vm.state",
                                       "mem_file_path": "/vm.mem"})
    vm.kill()
    check(os.path.getsize(jail.host("vm.mem")) == 256 << 20,
          f"memory file is {os.path.getsize(jail.host('vm.mem'))} bytes")
    jail2 = Jail(ctx, f"{name}-restore", [ctx.kernel, ctx.rootfs, jail.host("vm.state"), jail.host("vm.mem")])
    sock = jail2.host("/uffd.sock")
    handler = OperatorServer(ctx, f"{name}-handler", [ctx.uffd_handler, sock, jail2.host("vm.mem")], sock)
    try:
        vm = JailedVm(ctx, f"{name}-restore", jail2)
        vm.api("PUT", "/snapshot/load", {"snapshot_path": "/vm.state",
                                         "mem_backend": {"backend_type": "Uffd", "backend_path": "/uffd.sock"},
                                         "resume_vm": True})
        bt.restored_checks(vm, bash_md5, None)
        _, out = vm.sh("md5sum /tmp/f | cmp - /tmp/a && echo same", 120)
        check(out == "same", f"160 MiB after the uffd restore: {out!r}")
        _, out = vm.sh("head -c 64m /dev/zero | md5sum", 120)  # fresh pages after restore
        check(out.split()[0] == ZEROS_64M_MD5, f"64 MiB of zeros: {out!r}")
        handler.alive()
        vm.reboot()
    finally:
        handler.stop()


def vhost_user_round(ctx, name, machine):
    """A jailed guest (`machine` settings) with a vhost-user-blk drive served by
    tools/vhost-user-blk, a process of the operator outside the jail: the jailed
    Firecracker hands it guest memory (a memfd, a huge page one on huge pages)
    and eventfds over the backend's socket in the jail. The guest reads the
    image's md5 and its write reaches the image."""
    img = os.path.join(ctx.out, f"{name}.img")
    bt.random_file(img, 8 << 20)
    want = bt.md5(img)
    jail = Jail(ctx, name, [ctx.kernel, ctx.rootfs])
    sock = jail.host("/vub.sock")
    backend = OperatorServer(ctx, f"{name}-backend", [ctx.vub, sock, img], sock)
    try:
        drives = [{"drive_id": "vub", "socket": "/vub.sock", "is_root_device": False}]
        vm = JailedVm(ctx, name, jail, config=jail_config(vcpus=2, machine=machine, drives=drives))
        vm.shell()
        _, out = vm.sh("md5sum /dev/vdb", 120)
        check(out.split()[0] == want, f"guest md5 over vhost-user {out!r}, the image's {want}")
        vm.sh("echo vhost-user-$((6*7)) | dd of=/dev/vdb bs=512 seek=8 conv=fsync,notrunc 2>/dev/null")
        backend.alive()
        vm.reboot()
        with open(img, "rb") as f:
            f.seek(4096)
            check(f.read(14) == b"vhost-user-42\n", "guest write not in the backend's image")
    finally:
        backend.stop()


def stage_uffd(ctx):
    """VM: a jailed guest restored in another jail from a snapshot served by a uffd handler outside it."""
    uffd_round(ctx, "uffd", {})
    return ("a jailed guest snapshotted, restored in another jail through uffd_on_demand_handler outside it: "
            "shell state, 160 MiB of memory, fresh pages")


def stage_vhost_user(ctx):
    """VM: a jailed guest on a vhost-user-blk drive whose backend runs outside the jail."""
    vhost_user_round(ctx, "vhost-user", {})
    return "a jailed guest reads and writes a vhost-user-blk drive served by a backend outside the jail"


def stage_hugepages(ctx):
    """VM: a jailed guest on 2 MiB pages: boots, limited by the memory cgroup, restores through uffd, vhost-user.

    docs/PORTING.md row 10: macOS gives user space no superpage, so huge
    pages are host pages in Linux's hugetlb layout. There is no hugetlb pool
    either (`hugetlb.2MB.max` is refused: `refuse`), so the jail's memory
    limit is what limits a guest on huge pages: checked here, since on Linux
    the memory cgroup does not count hugetlb pages."""
    huge = {"huge_pages": "2M"}
    # A size that is not whole huge pages is refused, as on Linux.
    jail = Jail(ctx, "huge-odd", [ctx.kernel, ctx.rootfs])
    vm = JailedVm(ctx, "huge-odd", jail, config=jail_config(mem=255, machine=huge), wait_api=False)
    code = vm.wait_exit(15)
    vm.pump.join(5)
    check(code not in (None, 0), f"255 MiB on 2 MiB pages accepted: exit {code}")
    check("not a multiple of the configured page size" in vm.buf,
          f"the refusal does not name the page size: {vm.exit_reason()}")
    jail = Jail(ctx, "huge", [ctx.kernel, ctx.rootfs])
    vm = JailedVm(ctx, "huge", jail, config=jail_config(vcpus=2, machine=huge))
    vm.shell()
    _, mem = vm.sh("awk '/MemTotal/ {print $2}' /proc/meminfo")
    check(200_000 < int(mem) <= 262_144, f"MemTotal {mem} kB for 256 MiB")
    _, out = vm.sh("mount -t tmpfs -o size=200m tmpfs /tmp && head -c 160m /dev/urandom > /tmp/f && "
                   "md5sum /tmp/f > /tmp/a && md5sum /tmp/f | cmp - /tmp/a && echo same", 120)
    check(out == "same", f"160 MiB in guest memory read back differently: {out!r}")
    vm.reboot()
    killed = {}
    for limit_mib, expect_kill in ((300, True), (3000, False)):
        name = f"huge-mem{limit_mib}"
        jail = Jail(ctx, name, [ctx.kernel, ctx.rootfs])
        vm = JailedVm(ctx, name, jail, ["--cgroup", f"memory.limit_in_bytes={limit_mib << 20}"],
                      config=jail_config(mem=1024, machine=huge))
        vm.shell()
        vm.sh("mount -t tmpfs -o size=900m tmpfs /run")
        try:
            vm.sh("dd if=/dev/zero of=/run/x bs=1M count=700 2>/dev/null; echo done", timeout=120)
            killed[limit_mib] = False
        except Failure:
            killed[limit_mib] = vm.proc.wait(10) == -signal.SIGKILL
        check(killed[limit_mib] == expect_kill, f"limit {limit_mib} MiB, guest on 2 MiB pages wrote 700 MiB: "
                                                f"killed={killed[limit_mib]} ({vm.exit_reason()})")
        vm.kill()
    uffd_round(ctx, "huge-uffd", huge)
    vhost_user_round(ctx, "huge-vub", huge)
    return ("a jailed 2 vCPU guest on 2 MiB pages boots and keeps 160 MiB written; an odd size is refused; "
            "700 MiB written: killed at a 300 MiB memory limit, not at 3000; restored in another jail through "
            "a uffd handler outside it; a vhost-user drive on a huge page memfd, its backend outside the jail")


STAGES = {
    "refuse": stage_refuse,
    "jail": stage_jail,
    "daemonize": stage_daemonize,
    "pidns": stage_pidns,
    "limits": stage_limits,
    "fsize": stage_fsize,
    "no-api": stage_no_api,
    "boot": stage_boot,
    "netns": stage_netns,
    "memory": stage_memory,
    "cpu": stage_cpu,
    "hugepages": stage_hugepages,
    "uffd": stage_uffd,
    "vhost-user": stage_vhost_user,
}
VM_STAGES = ("no-api", "fsize", "boot", "netns", "memory", "cpu", "hugepages", "uffd", "vhost-user")


class Context:
    def __init__(self, args):
        self.jailer = args.jailer
        self.firecracker = args.firecracker
        self.uffd_handler = args.uffd_handler
        self.vub = args.vhost_user_blk
        self.out = args.out
        self.rlimit_probe = None
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
    p.add_argument("--uffd-handler", required=True)
    p.add_argument("--vhost-user-blk", required=True)
    p.add_argument("--cache", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--no-vm", action="store_true", help="skip the stages that boot a VM")
    p.add_argument("--probe-self-check", action="store_true",
                   help="build the resource limit probe and check it without root, then exit")
    p.add_argument("stages", nargs="*", help=f"stages (default: all): {', '.join(STAGES)}")
    if "--probe-self-check" in sys.argv[1:]:
        self_check_probe()
        return
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
