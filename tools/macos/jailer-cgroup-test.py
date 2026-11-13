# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""jailer-test stages for cgroup options measured against Linux
(tools/linux/jailer-cgroup-check.py records what upstream's jailer does
there). Loaded by tools/macos/jailer-test.py, which passes itself as `jt`;
run as root like every jailer-test stage, with no VM.
"""

import ctypes
import errno
import fcntl
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import types


def stage_cgroup_devices(ctx, jt):
    """`devices.*` refused with exit 1 where upstream's jailer refuses it on Linux: v1 at the cgroup step, with the
    jail's root made and the binary copied into it; v2 while the options are read, before the jail exists."""
    check = jt.check
    cases = [
        # v1: Linux fails reading the parent cgroup's write-only file (EINVAL),
        # or writing the read-only devices.list, at Env::run's cgroup step.
        ("1", "devices.deny=a", "upstream's jailer cannot set it on Linux either"),
        ("1", "devices.allow=c 1:3 rwm", "devices.allow and devices.deny are write-only (EINVAL)"),
        ("1", "devices.list=a *:* rwm", "devices.list read-only"),
        # v2: no devices controller; upstream's own error.
        ("2", "devices.deny=a", "Controller devices is unavailable"),
        ("2", "devices.allow=c 1:3 rwm", "Controller devices is unavailable"),
    ]
    for i, (version, value, want) in enumerate(cases):
        vm_id = f"cgroup-devices{i}"
        extra = ["--cgroup-version", version, "--cgroup", value]
        jail_dir = os.path.join(ctx.base, os.path.basename(ctx.firecracker), vm_id)
        rc, out = jt.run_jailer(ctx, jt.jailer_base(ctx, vm_id) + extra + [
            "--", "--api-sock", "/run/firecracker.socket"])
        left = sorted(os.path.relpath(os.path.join(d, f), jail_dir)
                      for d, ds, fs in os.walk(jail_dir) for f in ds + fs) if os.path.isdir(jail_dir) else None
        print(f"   {' '.join(extra)}: exit {rc}: {out!r}; left in the jail: {left}", flush=True)
        check(rc == 1 and want in out, f"{extra}: exit {rc}, {out!r}")
        if version == "1":
            # What Linux leaves at this step (tools/linux/jailer-cgroup-check.py
            # case_devices): the jail's root and the copied binary; Linux has
            # made the cgroup too, which macOS has no counterpart of.
            exe = os.path.join("root", os.path.basename(ctx.firecracker))
            check(left == ["root", exe], f"{extra}: the jail holds {left}, not the copied binary only")
        else:
            check(left is None, f"{extra}: {jail_dir} was made")
        # pgrep: 0 with matches, 1 without; anything else (a usage error) is
        # no answer.
        pg = subprocess.run(["pgrep", "-f", "--", f"--id {vm_id} "], capture_output=True, text=True)
        check(pg.returncode in (0, 1) and not pg.stderr, f"pgrep: {pg.returncode} {pg.stderr!r}")
        running = pg.stdout.split()
        check(not running, f"{extra}: processes of the jail: {running}")
    return f"{len(cases)} devices options refused, exit 1; v1 at the cgroup step (the binary copied), v2 with no jail"


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

# The flag the supervisor closes the control file with while it writes it
# back (UF_IMMUTABLE, `chflags uchg`), as the jail's uid, which does not own
# the file (root does): setting it, and lifting it. Run as root; drops to
# the uid first. Each call that would change the flags fails with EACCES;
# the one that would leave them as they are succeeds and changes nothing.
# xnu bsd/vfs/vfs_subr.c vnode_authattr: only "if (fdelta != 0)", the flags
# that would change, is KAUTH_VNODE_WRITE_SECURITY required, which a file's
# owner has and another uid has only from an ACL (vnode_authorize_simple);
# with no change nothing is asked (chflags0 authorizes only "if (action
# ...)"). The denial is EACCES, not EPERM: vnode_authorize turns kauth's
# EPERM into EACCES ("traditional behaviour"); vnode_authattr's own EPERM
# is for a flag outside UF_SETTABLE, which UF_IMMUTABLE is not. Measured
# the same as a plain user on a root-owned file on macOS 27.2, and by this
# stage on CI's macOS 26. macOS 15: from the source only, no run.
CHFLAGS_AS_JAIL_UID_PY = r"""
import os, sys
uid, gid, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
os.setgroups([gid]); os.setgid(gid); os.setuid(uid)
res = []
flags = os.stat(path).st_flags
for what, new in (("uchg", flags | 2), ("nouchg", flags & ~2)):
    try:
        os.chflags(path, new)
        res.append(f"chflags {what} ok")
    except OSError as e:
        res.append(f"chflags {what} {e.errno}")
res.append(f"flag {'set' if os.stat(path).st_flags & 2 else 'unset'}")
print("; ".join(res))
"""


class ProcTaskInfo(ctypes.Structure):
    """struct proc_taskinfo (bsd/sys/proc_info.h, xnu-12377.1.9, :127)."""
    _fields_ = [(n, ctypes.c_uint64) for n in ("virtual_size", "resident_size", "total_user", "total_system",
                                               "threads_user", "threads_system")] + \
               [(n, ctypes.c_int32) for n in ("policy", "faults", "pageins", "cow_faults", "messages_sent",
                                              "messages_received", "syscalls_mach", "syscalls_unix", "csw",
                                              "threadnum", "numrunning", "priority")]


class MachTimebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


_libc = ctypes.CDLL(None, use_errno=True)
_libc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
_timebase = MachTimebase()
_libc.mach_timebase_info(ctypes.byref(_timebase))
PROC_PIDTASKINFO = 4


def task_state(pid):
    """(CPU seconds, runnable threads) of `pid`, from the kernel, or None if
    it is gone: proc_pidinfo(PROC_PIDTASKINFO). XNU's fill_taskprocinfo
    (osfmk/kern/bsd_kern.c, xnu-12377.1.9, :1067 to :1117) gives the task's
    user and system time in Mach time units (recount_task_times) and counts
    in pti_numrunning the threads whose state has TH_RUN: on a CPU or
    waiting for one. A thread held by a suspension (pid_suspend's
    place_task_hold, osfmk/kern/task.c :4092, as SIGSTOP's) or blocked is
    not TH_RUN; a runnable one is, however long the CPUs are taken."""
    info = ProcTaskInfo()
    size = ctypes.sizeof(info)
    if _libc.proc_pidinfo(pid, PROC_PIDTASKINFO, 0, ctypes.byref(info), size) != size:
        return None
    ticks = info.total_user + info.total_system
    return ticks * _timebase.numer / _timebase.denom / 1e9, info.numrunning


class Freeze:
    """Helpers of the freeze stage."""

    def __init__(self, ctx, jt):
        self.ctx, self.jt, self.check = ctx, jt, jt.check
        build = os.path.join(ctx.base, "freeze-build")
        os.makedirs(build, exist_ok=True)
        os.chmod(build, 0o755)
        self.spinner = self.cc(build, "spinner", SPINNER_C, [f"-DUID={jt.UID}", f"-DGID={jt.GID}"])
        self.resumer = self.cc(build, "pid-resume", PID_RESUME_C, [])
        self.last = None

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
        self.last = (p, jd)
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

    # When the stage last wrote a control file (time.monotonic()).
    written_at = None

    def control(self):
        """An unjailed spinner of the same binary, with its child: [pid,
        child]. It runs beside a jail's through a CPU window, as its
        concurrent control: what CPU a process that nothing holds gets on
        this machine meanwhile."""
        marker = os.path.join(self.ctx.base, "freeze-build", f"control-{time.monotonic_ns()}")
        p = subprocess.Popen([self.spinner, marker], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        self.wait("the control spinner and its child", lambda: os.path.exists(marker) and len(self.kids(p.pid)) == 1)
        return p, [p.pid, self.kids(p.pid)[0]]

    def cpu(self, pids, seconds=1.5, control=True):
        """What each of `pids` did over `seconds`, from the kernel
        (`task_state`), beside a control spinner (`control`):
        {"used": CPU seconds of each, "control": the control's two,
        "runnable": per pid, how many of the window's reads found a thread
        runnable, "reads": how many reads}. Also keeps, in self.trace, the
        CPU each used in every 100 ms of the window, with the time since the
        stage's last write: a jail thawed late shows no CPU and then full
        CPU, one starved by other processes a low rate throughout."""
        ctl, ctl_pids = self.control() if control else (None, [])
        try:
            every = list(pids) + ctl_pids
            start = time.monotonic()
            before = [task_state(p) for p in every]
            self.check(all(before), f"cannot read the CPU time of {every}: {before}")
            last, self.trace = before, []
            runnable, reads = [0] * len(every), 0
            while time.monotonic() - start < seconds:
                time.sleep(max(0.0, min(0.1, seconds - (time.monotonic() - start))))
                now = [task_state(p) for p in every]
                self.check(all(now), f"a process ended in the window: {list(zip(every, now))}")
                reads += 1
                runnable = [r + (n[1] > 0) for r, n in zip(runnable, now)]
                since = time.monotonic() - (self.written_at or start)
                self.trace.append((round(since * 1000), [round((n[0] - l[0]) * 1000) for n, l in zip(now, last)]))
                last = now
        finally:
            if ctl:
                ctl.kill()
                ctl.wait()
        used = [round(n[0] - b[0], 3) for n, b in zip(last, before)]
        k = len(pids)
        return {"used": used[:k], "control": used[k:], "runnable": runnable[:k], "reads": reads}

    def explain_cpu(self, what):
        """The window's trace, the load and the top CPU users, for a check
        on the CPU a jail got."""
        print(f"   {what}: CPU ms per 100 ms, as (ms since the last write, [per pid, then the control's]): "
              f"{self.trace}", flush=True)
        print(f"   {what}: load average {os.getloadavg()}", flush=True)
        top = subprocess.run(["ps", "-A", "-r", "-o", "pid=,pcpu=,comm="], capture_output=True, text=True).stdout
        print(f"   {what}: top CPU users: {top.splitlines()[:8]}", flush=True)

    def frozen(self, pids, what):
        """Frozen: no read of the window finds a thread of `pids` runnable
        (the kernel's answer), and they use no CPU time while the unjailed
        control beside them does (so the window had CPU to give)."""
        m = self.cpu(pids)
        print(f"   {what}: over 1.5 s, CPU seconds {m['used']}, the control's {m['control']}; "
              f"reads with a runnable thread {m['runnable']} of {m['reads']}", flush=True)
        ok = all(r == 0 for r in m["runnable"]) and all(u == 0 for u in m["used"]) and all(
            c > 0 for c in m["control"])
        if not ok:
            self.explain_cpu(what)
        self.check(all(r == 0 for r in m["runnable"]), f"{what}: runnable while frozen {m}")
        self.check(all(u == 0 for u in m["used"]), f"{what}: CPU time while frozen {m}")
        self.check(all(c > 0 for c in m["control"]), f"{what}: the control got no CPU either, so a frozen "
                                                     f"jail cannot be told from a starved one {m}")

    # A thawed spinner's share of the CPU against the unjailed control's:
    # both spin at the same priority, so the scheduler gives them alike;
    # this leaves room for the window's 100 ms of luck.
    SHARE = 1 / 3

    def running(self, pids, what):
        """Thawed: every read of the window finds a thread of each of `pids`
        runnable (the kernel's answer, whatever the load), and each gets CPU
        time, at least a third of what the unjailed control beside it gets
        (a share alike, not a number of seconds, so a loaded machine does
        not fail it)."""
        m = self.cpu(pids)
        ctl = sum(m["control"]) / len(m["control"])
        print(f"   {what}: over 1.5 s, CPU seconds {m['used']}, the control's {m['control']}; "
              f"reads with a runnable thread {m['runnable']} of {m['reads']}", flush=True)
        ok = all(r == m["reads"] for r in m["runnable"]) and all(u > 0 and u >= ctl * self.SHARE for u in m["used"])
        if not ok:
            self.explain_cpu(what)
        self.check(m["reads"] > 0 and all(r == m["reads"] for r in m["runnable"]),
                   f"{what}: not runnable while thawed {m}")
        self.check(all(u > 0 for u in m["used"]), f"{what}: no CPU time while thawed {m}")
        self.check(all(u >= ctl * self.SHARE for u in m["used"]),
                   f"{what}: less than a third of the control's CPU time while thawed {m}")

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
        # While the supervisor writes the file back (after a value not in
        # canonical form, or an invalid one), an open for writing is refused
        # with EPERM for those microseconds: tried again, and said.
        for attempt in range(1000):
            try:
                with open(os.path.join(jd, name), "w") as f:
                    f.write(value)
                break
            except PermissionError as e:
                if e.errno != errno.EPERM:
                    raise
                print(f"   write of {name}: refused with EPERM (the supervisor is writing it back), try {attempt + 2}",
                      flush=True)
        else:
            raise PermissionError(errno.EPERM, f"{name}: an open for writing was refused with EPERM 1000 times: "
                                               f"left immutable? (chflags nouchg {os.path.join(jd, name)})")
        Freeze.written_at = time.monotonic()

    def as_jail_uid(self, jd, name, pid):
        p = subprocess.run([sys.executable, "-I", "-c", AS_JAIL_UID_PY, str(self.jt.UID), str(self.jt.GID),
                            os.path.join(jd, name), str(pid), self.resumer], capture_output=True, text=True)
        return (p.stdout + p.stderr).strip()

    def chflags_as_jail_uid(self, jd, name):
        p = subprocess.run([sys.executable, "-I", "-c", CHFLAGS_AS_JAIL_UID_PY, str(self.jt.UID), str(self.jt.GID),
                            os.path.join(jd, name)], capture_output=True, text=True)
        return (p.stdout + p.stderr).strip()

    def gone(self, pid):
        return not self.jt.alive(pid)


def self_check_freeze(jt):
    """What runs without root: the freeze stage's judgement of frozen and
    thawed (`Freeze.frozen`, `Freeze.running`) on spinners of this user
    held and released with SIGSTOP and SIGCONT, whose hold is the one
    pid_suspend places (bsd/kern/kern_sig.c's SIGSTOP and kern_proc.c's
    pid_suspend both reach place_task_hold, osfmk/kern/task.c :4092): on
    the machine as it is, and again with twice as many extra spinners as
    CPUs taking them. Each time a held spinner judged thawed (what a
    supervisor that does not resume leaves) and a running one judged frozen
    must fail, by name."""
    base = tempfile.mkdtemp(prefix="wick-jt-freeze-")
    procs = []
    try:
        ctx = types.SimpleNamespace(base=base, out=base)
        me = types.SimpleNamespace(UID=os.getuid(), GID=os.getgid(), check=jt.check, bt=jt.bt)
        fz = Freeze(ctx, me)

        def spinner():
            p, pids = fz.control()
            procs.append(p)
            return pids

        def fails(judge, pids, what, want):
            try:
                judge(pids, what)
            except jt.Failure as e:
                jt.check(want in str(e), f"{what}: failed for another reason: {e}")
                print(f"   {what}: fails, as it must: {e}", flush=True)
                return
            raise jt.Failure(f"{what}: passed")

        for load in (0, 2 * os.cpu_count()):
            loaders = [spinner() for _ in range(load // 2)]
            print(f"   {load} extra spinners, load average {os.getloadavg()}", flush=True)
            jail = spinner()
            fz.running(jail, "running")
            fails(fz.frozen, jail, "running, judged frozen", "runnable while frozen")
            for pid in jail:
                os.kill(pid, signal.SIGSTOP)
            time.sleep(0.3)
            fz.frozen(jail, "held")
            fails(fz.running, jail, "held and not resumed, judged thawed", "not runnable while thawed")
            for pid in jail:
                os.kill(pid, signal.SIGCONT)
            fz.running(jail, "resumed")
            for pid in jail + [q for pids in loaders for q in pids]:
                os.kill(pid, signal.SIGKILL)
        print(f"freeze self-check passed, load average {os.getloadavg()}")
    finally:
        for p in procs:
            p.kill()
            p.wait()
        shutil.rmtree(base, ignore_errors=True)


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


def diagnose(fz, name, jd, p):
    """What a jail that did not start shows: its files, its processes (with
    their stacks: the stage runs as root) and the jailer's output, so that one
    run names the stuck process and where it is."""
    print(f"   -- {name}: diagnosis", flush=True)
    print(f"      jailer {p.pid}: {'running' if p.poll() is None else f'exit {p.returncode}'}", flush=True)
    files = sorted(os.path.relpath(os.path.join(d, f), jd) for d, ds, fs in os.walk(jd) for f in ds + fs) \
        if os.path.isdir(jd) else None
    print(f"      in the jail's directory: {files}", flush=True)
    for f in ("freezer.state", "cgroup.freeze", "cgroup.events", "root/spinner.pid"):
        path = os.path.join(jd, f)
        if os.path.exists(path):
            with open(path) as fh:
                print(f"      {f}: {fh.read()!r}", flush=True)
    if os.path.isdir(jd):
        print(f"      the directory's lock held: {fz.maintained(jd)}", flush=True)
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,pgid=,sess=,uid=,stat=,time=,command="],
                         capture_output=True, text=True).stdout
    procs = []
    for line in out.splitlines():
        f = line.split(None, 7)
        if len(f) == 8 and (f" --id {name} " in f" {f[7]} " or f"/{name}/" in f[7]):
            procs.append(int(f[0]))
            print(f"      ps: {line.strip()[:300]}", flush=True)
    if not procs:
        print("      ps: no process of the jail", flush=True)
    for pid in procs:
        kids = fz.kids(pid)
        if kids:
            print(f"      children of {pid}: {kids}", flush=True)
        report = os.path.join(fz.ctx.out, f"{name}-{pid}.sample")
        subprocess.run(["/usr/bin/sample", str(pid), "1", "-file", report], capture_output=True, timeout=30)
        if os.path.exists(report):
            with open(report) as fh:
                text = fh.read()
            graph = text[text.find("Call graph:"):].split("\n\n")[0].splitlines()[1:40]
            print(f"      stack of {pid}:", *[g[:160] for g in graph], sep="\n        ", flush=True)
    log = os.path.join(fz.ctx.out, f"{name}.log")
    if os.path.exists(log):
        with open(log) as fh:
            print(f"      jailer output: {fh.read()[-1500:]!r}", flush=True)


def stage_freeze(ctx, jt):
    """The freezer: upstream's cgroup files next to the jail, kept by a supervisor per jail.

    Its cases do not depend on each other: each runs, a failed one is
    diagnosed and its processes ended, and the stage reports every case."""
    fz = Freeze(ctx, jt)
    check = jt.check
    os_version = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True).stdout.strip()
    print(f"   macOS {os_version}", flush=True)
    facts = {}

    def case_v1():
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
        # (SIGCONT is delivered, one uid to its own process, and resumes
        # nothing: the jail stays frozen, checked below.)
        check(f"write {errno.EACCES}" in got and "sigcont ok" in got and f"pid_resume -1 {errno.EPERM}" in got,
              f"as the jail's uid: {got}")
        # Nor can it set or lift the flag the supervisor closes the file
        # with while it writes it back (CHFLAGS_AS_JAIL_UID_PY has the
        # rule). With the flag unset: setting it is refused; "lifting" it
        # changes nothing, so nothing is asked and nothing happens.
        state = os.path.join(jd, "freezer.state")
        got = fz.chflags_as_jail_uid(jd, "freezer.state")
        print(f"   as the jail's uid, the flag unset: {got}", flush=True)
        check(got == f"chflags uchg {errno.EACCES}; chflags nouchg ok; flag unset",
              f"as the jail's uid, the flag unset: {got}")
        # With the flag set, as the supervisor holds it during a write-back
        # (set here by root, the file's owner, on the jail's own control
        # file, which nothing writes meanwhile): lifting it is refused and
        # the flag stays; "setting" it changes nothing.
        flags = os.stat(state).st_flags
        os.chflags(state, flags | 2)
        try:
            got = fz.chflags_as_jail_uid(jd, "freezer.state")
        finally:
            os.chflags(state, flags)
        print(f"   as the jail's uid, the flag set: {got}", flush=True)
        check(got == f"chflags uchg ok; chflags nouchg {errno.EACCES}; flag set",
              f"as the jail's uid, the flag set (it must not lift it): {got}")
        check(os.stat(state).st_flags & 2 == 0, "freezer.state is not immutable")
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

    def case_v2():
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
        sup_cpu = fz.cpu([sup["pid"]], 1.0, control=False)["used"][0]
        print(f"   supervisor: {sup['rss_kib']} KiB resident, {sup_cpu} s CPU over 1 s", flush=True)
        facts["supervisor"] = f"the supervisor {sup['rss_kib']} KiB resident and {sup_cpu} s CPU per idle second"
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

    def case_refused():
        # At the start, as upstream's jailer: v2 cgroup.* is refused, v1
        # freezer.state takes FROZEN or THAWED only.
        for i, (extra, want) in enumerate([
            (["--cgroup-version", "2", "--cgroup", "cgroup.freeze=1"], "Controller cgroup is unavailable"),
            (["--cgroup-version", "2", "--cgroup", "cgroup.freeze=0"], "Controller cgroup is unavailable"),
            (["--cgroup-version", "1", "--cgroup", "freezer.state=FREEZING"], "only FROZEN or THAWED"),
        ]):
            rc, out = jt.run_jailer(ctx, jt.jailer_base(ctx, f"fz-refuse{i}", fz.spinner) + extra + ["--", "/x"])
            check(rc == 1 and want in out, f"{extra}: exit {rc}, {out!r}")

    def runs(name, extra, **kw):
        """A jail started with `extra` (and --daemonize or --new-pid-ns): the
        spinner runs, with its pid file and its API stand-in."""
        p, jd = fz.start(name, extra, **kw)
        fz.wait(f"{name}: it runs", lambda: fz.has_pid(jd) and fz.started(jd))
        pid = fz.pid(jd)
        if kw:
            p.wait(10)
            check(p.returncode == 0, f"{name}: jailer exit {p.returncode}")
        fz.wait(f"{name}: the API stand-in", lambda: len(fz.kids(pid)) == 1)
        fz.running([pid], f"{name}: running")
        os.kill(pid, signal.SIGKILL)
        if not kw:
            p.wait(10)

    # FROZEN at the start: the jailer stops at the cgroup step (no chroot, no
    # fork, no pid file) until THAWED; with --daemonize and --new-pid-ns too,
    # its command not returning meanwhile.
    def frozen_at_start(name, **kw):
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
        fz.wait(f"{name}: the pid file once thawed", lambda: fz.has_pid(jd))
        fz.wait(f"{name}: Firecracker's stand-in runs once thawed", lambda: fz.started(jd))
        pid = fz.pid(jd)
        if kw:
            p.wait(10)
            check(p.returncode == 0, f"{name}: jailer exit {p.returncode}")
        fz.wait(f"{name}: the API stand-in", lambda: len(fz.kids(pid)) == 1)
        fz.running([pid], f"{name}: thawed")
        os.kill(pid, signal.SIGKILL)
        if not kw:
            p.wait(10)

    def case_firecracker():
        # Firecracker itself (no VM): frozen, its API does not answer; thawed, it does.
        jail = jt.Jail(ctx, "fz-fc")
        vm = jt.JailedVm(ctx, "fz-fc", jail)
        jd = os.path.dirname(jail.root)
        sock = jail.host("/run/firecracker.socket")
        api = jt.api_process(vm)
        try:
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
        finally:
            vm.kill()

    def case_many_starts():
        # Starts without a freezer option, many of each kind: a start that
        # fails only now and then (as --daemonize and --new-pid-ns starts
        # did) shows its rate, and with --new-pid-ns its error (the forked
        # jailer keeps the log as its standard error; --daemonize gives it
        # /dev/null).
        tally, errors = {}, []
        for i in range(30):
            mode = ("plain", "daemonize", "new-pid-ns")[i % 3]
            kw = {"daemonize": {"daemonize": True}, "new-pid-ns": {"new_pid_ns": True}}.get(mode, {})
            name = f"fz-many{i}"
            p, jd = fz.start(name, [], **kw)
            deadline = time.time() + 5
            while not (fz.has_pid(jd) and fz.started(jd)) and time.time() < deadline:
                time.sleep(0.02)
            ok = fz.has_pid(jd) and fz.started(jd)
            tally.setdefault(mode, [0, 0])[0 if ok else 1] += 1
            if ok:
                pid = fz.pid(jd)
                os.kill(pid, signal.SIGKILL)
                p.wait(10)
            else:
                errors.append(f"{name} ({mode})")
                diagnose(fz, name, jd, p)
                subprocess.run(["pkill", "-9", "-f", "--", f"--id {name} "], check=False)
                p.wait(10)
        print(f"   starts that ran / failed: {tally}", flush=True)
        check(not errors, f"starts failed: {errors} of {tally}")

    cases = [
        ("v1", "freezer.state: frozen (no CPU time) and thawed, the same value twice a no-op, the jail's uid "
               "cannot thaw it, an invalid value restored, SIGTERM to the supervisor ignored, SIGKILL ends a "
               "frozen jail", case_v1),
        ("v2", "cgroup.freeze and cgroup.events; the supervisor killed leaves the jail frozen, its lock released",
         case_v2),
        ("refused", "v2 cgroup.freeze=0/1 and freezer.state=FREEZING refused at the start", case_refused),
        ("thawed-start", "freezer.state=THAWED at the start: a no-op",
         lambda: runs("fz-thawed", ["--cgroup", "freezer.state=THAWED"])),
        ("start", "FROZEN at the start holds the jailer until THAWED", lambda: frozen_at_start("fz-start")),
        # What --daemonize alone and with the freezer files made at the cgroup
        # step do, beside FROZEN: which of them a failure needs.
        ("daemon", "--daemonize, the spinner, no freezer option",
         lambda: runs("fz-daemon", [], daemonize=True)),
        ("daemon-thawed", "--daemonize with freezer.state=THAWED at the start",
         lambda: runs("fz-daemon-thawed", ["--cgroup", "freezer.state=THAWED"], daemonize=True)),
        ("start-daemon", "FROZEN at the start with --daemonize holds the jailer until THAWED",
         lambda: frozen_at_start("fz-start-daemon", daemonize=True)),
        ("start-pidns", "FROZEN at the start with --new-pid-ns holds the jailer until THAWED",
         lambda: frozen_at_start("fz-start-pidns", new_pid_ns=True)),
        ("firecracker", "Firecracker's API silent while frozen, answering once thawed", case_firecracker),
        ("many-starts", "30 starts without a freezer option: plain, --daemonize, --new-pid-ns",
         case_many_starts),
    ]
    results = []
    for key, what, run in cases:
        fz.last = None
        try:
            run()
            results.append((key, True, what))
            print(f"   case {key}: PASS: {what}", flush=True)
        except jt.Failure as e:
            results.append((key, False, f"{what}: {e}"))
            print(f"   case {key}: FAIL: {e}", flush=True)
            if fz.last:
                p, jd = fz.last
                name = os.path.basename(jd)
                diagnose(fz, name, jd, p)
                # Independent cases: what this one left is ended.
                subprocess.run(["pkill", "-9", "-f", "--", f"--id {name} "], check=False)
                time.sleep(0.5)
    failed = [f"{k}: {d}" for k, ok, d in results if not ok]
    passed = [k for k, ok, _ in results if ok]
    summary = (f"macOS {os_version}: {len(passed)} of {len(results)} cases pass ({', '.join(passed)})"
               + (f"; {facts['supervisor']}" if "supervisor" in facts else ""))
    check(not failed, summary + "; FAILED: " + " | ".join(failed))
    return summary
