# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""jailer-test stages for cgroup options measured against Linux
(tools/linux/jailer-cgroup-check.py records what upstream's jailer does
there). Loaded by tools/macos/jailer-test.py, which passes itself as `jt`;
run as root like every jailer-test stage, with no VM.
"""

import errno
import fcntl
import os
import signal
import socket
import subprocess
import sys
import time


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


# ---------------------------------------------------------------- freeze

# A program the jailer runs in Firecracker's place (it carries the hand-over
# mark, so the jailer takes it, and runs it unjailed as root: it does not take
# the jail over). It marks that it started, drops to the jail's uid, forks a
# child that stands for the API process (and ends when its parent does, as
# the API process ends with Firecracker), and both spin.
SPINNER_C = r"""
#include <fcntl.h>
#include <unistd.h>
__attribute__((used)) static const char mark[] = "wick-jail-handover:v1";
static void spin(void) { for (volatile long i = 0; i < 2000000; i++) {} }
int main(int argc, char **argv) {
    int fd = open(argv[argc - 1], O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);
    if (setgid(GID) != 0 || setuid(UID) != 0) return 2;
    pid_t parent = getpid();
    if (fork() == 0) { for (;;) { spin(); if (getppid() != parent) _exit(0); } }
    for (;;) spin();
}
"""

# pid_resume of a pid, printing the result and errno.
PID_RESUME_C = r"""
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
int pid_resume(int pid);
int main(int argc, char **argv) {
    int r = pid_resume(atoi(argv[1]));
    printf("%d %d\n", r, r ? errno : 0);
    return 0;
}
"""

# What a process of the jail's uid, outside the jail (so with more reach than
# the jail), can do to a frozen jail: write the control file, SIGCONT it,
# pid_resume it. Run as root; drops to the uid first.
AS_JAIL_UID_PY = r"""
import os, signal, subprocess, sys
uid, gid, path, pid, resumer = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5]
os.setgroups([gid]); os.setgid(gid); os.setuid(uid)
res = []
try:
    with open(path, "w") as f:
        f.write("0\n")
    res.append("write ok")
except OSError as e:
    res.append(f"write {e.errno}")
try:
    os.kill(pid, signal.SIGCONT)
    res.append("sigcont ok")
except OSError as e:
    res.append(f"sigcont {e.errno}")
res.append("pid_resume " + subprocess.run([resumer, str(pid)], capture_output=True, text=True).stdout.strip())
print("; ".join(res))
"""


class Freeze:
    """Helpers of the freeze stage."""

    def __init__(self, ctx, jt):
        self.ctx, self.jt, self.check = ctx, jt, jt.check
        build = os.path.join(ctx.base, "freeze-build")
        os.makedirs(build, exist_ok=True)
        os.chmod(build, 0o755)
        self.spinner = self.cc(build, "spinner", SPINNER_C, [f"-DUID={jt.UID}", f"-DGID={jt.GID}"])
        self.resumer = self.cc(build, "pid-resume", PID_RESUME_C, [])

    @staticmethod
    def cc(build, name, src, flags):
        c = os.path.join(build, f"{name}.c")
        with open(c, "w") as f:
            f.write(src)
        exe = os.path.join(build, name)
        subprocess.run(["/usr/bin/cc", "-O1", *flags, "-o", exe, c], check=True)
        os.chmod(exe, 0o755)
        return exe

    def start(self, vm_id, extra=(), daemonize=False, new_pid_ns=False):
        """Starts the spinner through the jailer; returns (the jailer's Popen, the jail's directory)."""
        jd = os.path.join(self.ctx.base, os.path.basename(self.spinner), vm_id)
        cmd = [self.ctx.jailer] + self.jt.jailer_base(self.ctx, vm_id, self.spinner) + list(extra)
        cmd += ["--daemonize"] if daemonize else []
        cmd += ["--new-pid-ns"] if new_pid_ns else []
        cmd += ["--", os.path.join(jd, "root", "started")]
        with open(os.path.join(self.ctx.out, f"{vm_id}.log"), "w") as f:
            p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)
        return p, jd

    def wait(self, what, cond, timeout=10):
        deadline = time.time() + timeout
        while not cond():
            self.check(time.time() < deadline, f"timed out: {what}")
            time.sleep(0.05)

    @staticmethod
    def started(jd):
        return os.path.exists(os.path.join(jd, "root", "started"))

    @staticmethod
    def has_pid(jd):
        return os.path.exists(os.path.join(jd, "root", "spinner.pid"))

    @staticmethod
    def pid(jd):
        with open(os.path.join(jd, "root", "spinner.pid")) as f:
            return int(f.read())

    def kids(self, pid):
        return self.jt.bt.children(pid)

    def cpu(self, pids, seconds=1.5):
        """CPU seconds each of `pids` used over `seconds` (ps: 10 ms steps)."""
        before = [self.jt.cpu_seconds(p) for p in pids]
        time.sleep(seconds)
        return [round(self.jt.cpu_seconds(p) - b, 2) for p, b in zip(pids, before)]

    def frozen(self, pids, what):
        used = self.cpu(pids)
        print(f"   {what}: CPU seconds over 1.5 s {used}", flush=True)
        self.check(all(u == 0 for u in used), f"{what}: CPU time while frozen {used}")

    def running(self, pids, what):
        used = self.cpu(pids)
        print(f"   {what}: CPU seconds over 1.5 s {used}", flush=True)
        self.check(all(u > 0.3 for u in used), f"{what}: too little CPU time while thawed {used}")

    def supervisor(self, vm_id):
        """The jail's supervisor: root, parent launchd, the jailer's command line."""
        out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,uid=,pgid=,tty=,rss=,command="],
                             capture_output=True, text=True).stdout
        found = []
        for line in out.splitlines():
            f = line.split(None, 6)
            if (len(f) == 7 and f[1] == "1" and f[2] == "0" and f"--id {vm_id} " in f[6] + " "
                    and os.path.basename(f[6].split()[0]) == "jailer"):
                found.append({"pid": int(f[0]), "pgid": int(f[3]), "tty": f[4], "rss_kib": int(f[5])})
        self.check(len(found) == 1, f"{vm_id}: supervisors {found}")
        return found[0]

    @staticmethod
    def maintained(jd):
        """Whether a supervisor keeps the files: it holds the directory's lock."""
        fd = os.open(jd, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        except BlockingIOError:
            return True
        finally:
            os.close(fd)

    @staticmethod
    def read(jd, name):
        with open(os.path.join(jd, name)) as f:
            return f.read()

    @staticmethod
    def write(jd, name, value):
        with open(os.path.join(jd, name), "w") as f:
            f.write(value)

    def as_jail_uid(self, jd, name, pid):
        p = subprocess.run([sys.executable, "-I", "-c", AS_JAIL_UID_PY, str(self.jt.UID), str(self.jt.GID),
                            os.path.join(jd, name), str(pid), self.resumer], capture_output=True, text=True)
        return (p.stdout + p.stderr).strip()

    def gone(self, pid):
        return not self.jt.alive(pid)


def api_answers(sock, timeout=1.5):
    """Whether Firecracker's API answers GET / within `timeout`."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock)
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        return s.recv(64).startswith(b"HTTP/1.1 200")
    except OSError:
        return False
    finally:
        s.close()


def stage_freeze(ctx, jt):
    """The freezer: upstream's cgroup files next to the jail, kept by a supervisor per jail."""
    fz = Freeze(ctx, jt)
    check = jt.check
    os_version = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
    print(f"   macOS {os_version}", flush=True)

    # v1, upstream's default: freezer.state.
    p, jd = fz.start("fz-v1")
    fz.wait("the spinner runs", lambda: fz.started(jd) and fz.has_pid(jd))
    pid = fz.pid(jd)
    check(pid == p.pid, f"pid file {pid}, jailer {p.pid}: the exec keeps the jailer's pid")
    fz.wait("the API stand-in", lambda: len(fz.kids(pid)) == 1)
    kid = fz.kids(pid)[0]
    st = os.stat(os.path.join(jd, "freezer.state"))
    check((st.st_uid, st.st_mode & 0o777) == (0, 0o644), f"freezer.state {st.st_uid} {oct(st.st_mode)}")
    check(fz.read(jd, "freezer.state") == "THAWED\n", "freezer.state at the start")
    check(not os.path.exists(os.path.join(jd, "cgroup.events")), "a v1 jail has no cgroup.events")
    sup = fz.supervisor("fz-v1")
    print(f"   supervisor {sup}", flush=True)
    check(sup["pgid"] == sup["pid"] and sup["tty"] in ("??", "-"), f"the supervisor's session {sup}")
    check(fz.maintained(jd), "the supervisor holds the jail directory's lock")
    fz.running([pid, kid], "thawed")
    fz.write(jd, "freezer.state", "FROZEN\n")
    time.sleep(0.3)
    fz.frozen([pid, kid], "FROZEN")
    check(fz.read(jd, "freezer.state") == "FROZEN\n", "freezer.state reads FROZEN")
    stat = subprocess.run(["ps", "-o", "stat=", "-p", f"{pid},{kid}"], capture_output=True, text=True).stdout.split()
    print(f"   ps state while frozen: {stat}", flush=True)
    # The same value again changes nothing.
    fz.write(jd, "freezer.state", "FROZEN\n")
    time.sleep(0.3)
    fz.frozen([pid, kid], "FROZEN twice")
    # The jail's uid cannot thaw it.
    got = fz.as_jail_uid(jd, "freezer.state", pid)
    print(f"   as the jail's uid: {got}", flush=True)
    check(f"write {errno.EACCES}" in got and "sigcont ok" in got and f"pid_resume -1 {errno.EPERM}" in got,
          f"as the jail's uid: {got}")
    fz.frozen([pid, kid], "after the jail's uid tried")
    # An invalid value: ignored, the file restored to the state.
    fz.write(jd, "freezer.state", "FREEZING\n")
    time.sleep(0.6)
    check(fz.read(jd, "freezer.state") == "FROZEN\n", f"invalid value kept: {fz.read(jd, 'freezer.state')!r}")
    fz.frozen([pid, kid], "after an invalid value")
    # SIGTERM to the supervisor is ignored: it still thaws.
    os.kill(sup["pid"], signal.SIGTERM)
    time.sleep(0.3)
    check(jt.alive(sup["pid"]), "the supervisor ended on SIGTERM")
    fz.write(jd, "freezer.state", "THAWED\n")
    time.sleep(0.3)
    fz.running([pid, kid], "THAWED")
    # SIGKILL ends a frozen jail; the API stand-in ends with it (resumed by
    # the supervisor), and the supervisor with the jail.
    fz.write(jd, "freezer.state", "FROZEN\n")
    time.sleep(0.3)
    fz.frozen([pid, kid], "FROZEN again")
    os.kill(pid, signal.SIGKILL)
    fz.wait("the frozen jail ends on SIGKILL", lambda: p.poll() is not None)
    check(p.returncode == -signal.SIGKILL, f"exit {p.returncode}")
    fz.wait("the API stand-in ends", lambda: fz.gone(kid))
    fz.wait("the supervisor ends with the jail", lambda: fz.gone(sup["pid"]))
    check(not fz.maintained(jd), "the lock is released")

    # v2: cgroup.freeze and cgroup.events.
    p, jd = fz.start("fz-v2", ["--cgroup-version", "2"])
    fz.wait("the spinner runs", lambda: fz.has_pid(jd))
    pid = fz.pid(jd)
    fz.wait("the API stand-in", lambda: len(fz.kids(pid)) == 1)
    kid = fz.kids(pid)[0]
    check(fz.read(jd, "cgroup.freeze") == "0\n", "cgroup.freeze at the start")
    check(fz.read(jd, "cgroup.events") == "populated 1\nfrozen 0\n", "cgroup.events at the start")
    fz.write(jd, "cgroup.freeze", "1\n")
    fz.wait("frozen 1", lambda: fz.read(jd, "cgroup.events") == "populated 1\nfrozen 1\n", 3)
    fz.frozen([pid, kid], "cgroup.freeze 1")
    fz.write(jd, "cgroup.freeze", "2\n")
    time.sleep(0.6)
    check(fz.read(jd, "cgroup.freeze") == "1\n", "invalid value restored")
    check(fz.read(jd, "cgroup.events") == "populated 1\nfrozen 1\n", "still frozen")
    # What a supervisor costs: every jail has one.
    sup = fz.supervisor("fz-v2")
    fz.write(jd, "cgroup.freeze", "0\n")
    fz.wait("frozen 0", lambda: fz.read(jd, "cgroup.events") == "populated 1\nfrozen 0\n", 3)
    fz.running([pid, kid], "cgroup.freeze 0")
    sup_cpu = fz.cpu([sup["pid"]], 1.0)[0]
    print(f"   supervisor: {sup['rss_kib']} KiB resident, {sup_cpu} s CPU over 1 s", flush=True)
    # The supervisor killed (root only) while the jail is frozen: the jail is
    # left frozen, the lock is gone, the file no longer acts, root can still
    # kill the jail.
    fz.write(jd, "cgroup.freeze", "1\n")
    fz.wait("frozen 1", lambda: fz.read(jd, "cgroup.events") == "populated 1\nfrozen 1\n", 3)
    os.kill(sup["pid"], signal.SIGKILL)
    fz.wait("the supervisor ends", lambda: fz.gone(sup["pid"]))
    check(not fz.maintained(jd), "a dead supervisor's lock is released")
    fz.write(jd, "cgroup.freeze", "0\n")
    time.sleep(0.5)
    fz.frozen([pid, kid], "supervisor killed: the jail is left frozen")
    os.kill(pid, signal.SIGKILL)
    os.kill(kid, signal.SIGKILL)
    fz.wait("the frozen jail ends on SIGKILL", lambda: p.poll() is not None and fz.gone(kid))

    # At the start, as upstream's jailer: v2 cgroup.* is refused, v1
    # freezer.state takes FROZEN or THAWED only.
    for i, (extra, want) in enumerate([
        (["--cgroup-version", "2", "--cgroup", "cgroup.freeze=1"], "Controller cgroup is unavailable"),
        (["--cgroup-version", "2", "--cgroup", "cgroup.freeze=0"], "Controller cgroup is unavailable"),
        (["--cgroup-version", "1", "--cgroup", "freezer.state=FREEZING"], "only FROZEN or THAWED"),
    ]):
        rc, out = jt.run_jailer(ctx, jt.jailer_base(ctx, f"fz-refuse{i}", fz.spinner) + extra + ["--", "/x"])
        check(rc == 1 and want in out, f"{extra}: exit {rc}, {out!r}")
    p, jd = fz.start("fz-thawed", ["--cgroup", "freezer.state=THAWED"])
    fz.wait("THAWED at the start: it runs", lambda: fz.has_pid(jd) and fz.started(jd))
    os.kill(fz.pid(jd), signal.SIGKILL)
    p.wait(10)

    # FROZEN at the start: the jailer stops at the cgroup step (no chroot, no
    # fork, no pid file) until THAWED; with --daemonize and --new-pid-ns too,
    # its command not returning meanwhile.
    for name, kw in [("fz-start", {}), ("fz-start-daemon", {"daemonize": True}),
                     ("fz-start-pidns", {"new_pid_ns": True})]:
        p, jd = fz.start(name, ["--cgroup", "freezer.state=FROZEN"], **kw)
        fz.wait(f"{name}: freezer.state", lambda: os.path.exists(os.path.join(jd, "freezer.state")))
        time.sleep(1.5)
        check(p.poll() is None, f"{name}: the jailer returned while frozen ({p.returncode})")
        check(not fz.started(jd) and not fz.has_pid(jd), f"{name}: ran or wrote its pid file while frozen")
        check(fz.read(jd, "freezer.state") == "FROZEN\n" and fz.maintained(jd), f"{name}: FROZEN and kept")
        check(fz.kids(p.pid) == [], f"{name}: the jailer forked while frozen: {fz.kids(p.pid)}")
        roots = jt.proc_root(p.pid)
        check(os.path.realpath(os.path.join(jd, "root")) not in roots, f"{name}: chrooted while frozen: {roots}")
        fz.frozen([p.pid], f"{name}: the jailer")
        fz.write(jd, "freezer.state", "THAWED\n")
        fz.wait(f"{name}: it runs once thawed", lambda: fz.has_pid(jd) and fz.started(jd))
        pid = fz.pid(jd)
        if kw:
            p.wait(10)
            check(p.returncode == 0, f"{name}: jailer exit {p.returncode}")
        fz.wait(f"{name}: the API stand-in", lambda: len(fz.kids(pid)) == 1)
        fz.running([pid], f"{name}: thawed")
        os.kill(pid, signal.SIGKILL)
        if not kw:
            p.wait(10)

    # Firecracker itself (no VM): frozen, its API does not answer; thawed, it does.
    jail = jt.Jail(ctx, "fz-fc")
    vm = jt.JailedVm(ctx, "fz-fc", jail)
    jd = os.path.dirname(jail.root)
    sock = jail.host("/run/firecracker.socket")
    api = jt.api_process(vm)
    check(api_answers(sock), "Firecracker's API before the freeze")
    fz.write(jd, "freezer.state", "FROZEN\n")
    time.sleep(0.3)
    check(not api_answers(sock), "the API answered while frozen")
    stat = subprocess.run(["ps", "-o", "pid=,stat=", "-p", f"{vm.proc.pid},{api}"],
                          capture_output=True, text=True).stdout.split()
    print(f"   Firecracker and its API process, frozen: {stat}", flush=True)
    fz.write(jd, "freezer.state", "THAWED\n")
    time.sleep(0.3)
    check(api_answers(sock), "Firecracker's API after the thaw")
    vm.kill()
    return (f"macOS {os_version}: a jail and its child frozen (no CPU time) and thawed, the same value twice "
            "a no-op, the jail's uid cannot thaw it, an invalid value restored, SIGTERM to the supervisor ignored, "
            "SIGKILL ends a frozen jail; the supervisor "
            f"{sup['rss_kib']} KiB resident and {sup_cpu} s CPU per idle second; killed, it leaves the jail frozen "
            "and its lock released; v2 cgroup.freeze refused at the start; FROZEN at the start holds the jailer "
            "(plain, --daemonize, --new-pid-ns) until THAWED; Firecracker's API silent while frozen")
