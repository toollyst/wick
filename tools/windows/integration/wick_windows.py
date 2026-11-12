# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The Windows host side of upstream's integration test framework.

A pytest plugin, loaded by tools/windows/integration-tests.ps1 (`-p
wick_windows`) before upstream's conftest.py, as tools/macos/integration/
wick_macos.py is on macOS. Upstream's framework drives Firecracker the same
way on every host; what it does on the Linux host itself is supplied here
for Windows, so that upstream's tests run unchanged. Every substitution
says what it stands for on Linux.
"""

import ctypes
import errno
import os
import platform
import re
import sys

SESSION_ROOT = os.environ.get("WICK_IT_ROOT")
if sys.platform != "win32" or not SESSION_ROOT:
    raise SystemError("wick_windows: run through tools/windows/integration-tests.ps1 on Windows")

# AF_UNIX (Firecracker's API socket, vsock, the userfaultfd handler), before
# anything imports socket's names (tools/windows/integration/wick_windows_unix.py).
import wick_windows_unix  # noqa: E402  pylint: disable=wrong-import-position

wick_windows_unix.install()

# ------------------------------------------------------------------ the host

# Linux calls this architecture x86_64; Windows AMD64. Upstream's framework
# names its artifacts, parameters and checks after the Linux name.
_machine = platform.machine
platform.machine = lambda: "x86_64" if _machine() in ("AMD64", "x86_64") else _machine()

# Upstream's conftest.py: "the session needs to be run as root", then the
# child subreaper through libc's prctl. On Windows the session runs as the
# user, who is the jail's user (the jailer's tokens are made from the
# user's: platform/windows), and there is no subreaper: Windows keeps no
# zombie, so a pid is waited for by its process handle (psutil).
os.geteuid = lambda: 0
os.getegid = lambda: 0
# Descriptors are not inherited unless asked for (O_NOINHERIT): O_CLOEXEC.
if not hasattr(os, "O_CLOEXEC"):
    os.O_CLOEXEC = getattr(os, "O_NOINHERIT", 0)


class _NoPrctlLibc:
    """libc.so.6 for conftest.py's PR_SET_CHILD_SUBREAPER: nothing to do."""

    @staticmethod
    def prctl(*_args):
        return 0


_real_cdll = ctypes.CDLL


def _cdll(name, *args, **kwargs):
    if name == "libc.so.6":
        return _NoPrctlLibc()
    return _real_cdll(name, *args, **kwargs)


ctypes.CDLL = _cdll

# Linux: a file given to the jail is chowned to the jail's uid:gid. Windows
# has no numeric ids (the jailer records --uid/--gid only); what the jail may
# open is what its directory grants (the jail's SID) at its integrity label,
# which the jailer sets on the directory, inherited
# (overlay/jailer/platform/windows/mod.rs). JailerContext.jailed_path gives
# the file that security, below.
if not hasattr(os, "chown"):
    os.chown = lambda path, uid, gid, **kwargs: None

_advapi = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_SE_FILE_OBJECT = 1
_DACL_INFO, _LABEL_INFO, _UNPROTECTED_DACL = 0x4, 0x10, 0x20000000
_advapi.GetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_advapi.SetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p]
_advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
_advapi.GetSecurityDescriptorSacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                              ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
_advapi.InitializeAcl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]


def _sddl(path, info):
    sd = ctypes.c_void_p()
    rc = _advapi.GetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, info, None, None, None, None, ctypes.byref(sd))
    if rc:
        raise OSError(rc, f"GetNamedSecurityInfo({path})", None, rc)
    text = ctypes.c_wchar_p()
    try:
        if not _advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        value = text.value
        _kernel32.LocalFree(text)
        return value
    finally:
        _kernel32.LocalFree(sd)


_PROTECTED_DACL = 0x80000000


class _SessionLock:
    """The jailers' DACL lock (a named mutex, ACL_LOCK in
    overlay/jailer/platform/windows/mod.rs), which the session's workers
    share with them: a DACL is read, changed and written back, and six
    workers and their jailers grant the same hard-linked artifacts to their
    jails at once."""

    def __enter__(self):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.restype = ctypes.c_void_p
        name = "Local\\wick-jailer-acl"
        self._h = k32.CreateMutexW(None, False, name)
        if not self._h:
            raise ctypes.WinError(ctypes.get_last_error())
        k32.WaitForSingleObject(ctypes.c_void_p(self._h), 0xFFFFFFFF)
        self._k32 = k32

    def __exit__(self, *_):
        self._k32.ReleaseMutex(ctypes.c_void_p(self._h))
        self._k32.CloseHandle(ctypes.c_void_p(self._h))


def _set_dacl(path, edit):
    """Sets `path`'s DACL to `edit(aces)`, the DACL's ACEs as SDDL strings
    in order (icacls cannot name a SID no account has, as a jail's: 1332).
    Explicit denies come first, then explicit allows, as Windows orders an
    ACL; inherited ACEs are recomputed from the parent. One worker at a time."""
    with _SessionLock():
        _set_dacl_locked(path, edit)


def _set_dacl_locked(path, edit):
    dacl = _sddl(path, _DACL_INFO)
    m = re.match(r"D:([A-Z]*)(.*)$", dacl)
    flags, aces = m.group(1), re.findall(r"\([^)]*\)", m.group(2))
    aces = [a for a in edit(aces) if ";ID;" not in a and not re.match(r"\([AD];[A-Z]*ID", a)]
    aces.sort(key=lambda a: 0 if a.startswith("(D;") else 1)
    sd = ctypes.c_void_p()
    if not _advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"D:{flags}{''.join(aces)}", 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted, acl = ctypes.c_int(), ctypes.c_int(), ctypes.c_void_p()
        _advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                                      ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
        if not _advapi.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        info = _DACL_INFO | (_PROTECTED_DACL if "P" in flags else _UNPROTECTED_DACL)
        rc = _advapi.SetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, info, None, None, acl, None)
        if rc:
            raise OSError(rc, f"SetNamedSecurityInfo({path})", None, rc)
    finally:
        _kernel32.LocalFree(sd)


_real_chmod = os.chmod


def _chmod(path, mode, *args, **kwargs):
    """`os.chmod`. Windows's sets the read-only attribute only, which keeps
    no one from writing a directory. Linux's mode bits bind the jail's uid,
    the files' owner, and not root (the test session): a file or directory
    granted to jails (S-1-9-... in its DACL, `give_to_jail`) also denies
    those SIDs what `mode` leaves the owner without (write, read), and has
    that taken back by a mode that gives it."""
    _real_chmod(path, mode, *args, **kwargs)
    if not isinstance(path, (str, os.PathLike)) or not os.path.exists(path):
        return
    try:
        sids = sorted(set(re.findall(r"S-1-9-[0-9-]+", _sddl(path, _DACL_INFO))))
    except OSError:
        return
    # FILE_GENERIC_WRITE and FILE_GENERIC_READ less SYNCHRONIZE (a denied
    # SYNCHRONIZE would keep the owner from waiting on its own handles).
    denied = (0x116 if not mode & 0o200 else 0) | (0x89 if not mode & 0o400 else 0)

    def edit(aces):
        kept = [a for a in aces if not (a.startswith("(D;") and any(a.endswith(f";{s})") for s in sids))]
        return kept + ([f"(D;;{denied:#x};;;{s})" for s in sids] if denied else [])

    if sids:
        _set_dacl(path, edit)


os.chmod = _chmod


_USER_SID = []


def _user_sid():
    """The session user's SID (S-1-5-21-...)."""
    if not _USER_SID:
        out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
        _USER_SID.append(out.stdout.strip().split(",")[-1].strip('"'))
    return _USER_SID[0]


def give_to_jail(path, root):
    """`chown(path, uid, gid)` for a jail: `path` is granted to the jail's
    SID, the one the jail directory `root` grants (S-1-9-..., the jailer's
    per-microVM SID), and gets the directory's integrity label. Added to what
    the file grants already: a file that is a hard link shares its security
    with the source and with every jail it is linked into (a read-only
    artifact is), and on Linux every jail of the session is the same uid, so
    each keeps its access. Before the jailer has made `root` the jail's,
    nothing: the jailer passes its security down to what is in the directory
    already."""
    dacl = _sddl(root, _DACL_INFO)
    sid = re.search(r"S-1-9-[0-9-]+", dacl)
    if not dacl.startswith("D:P") or sid is None:
        return
    # A jailed process's access is checked twice (a restricted token): for
    # its restricting SIDs, the jail's, and for its normal ones, the user's.
    # A file that grants the user only as OWNER RIGHTS (Python makes 0o700
    # directories so: pytest's tmp_path) passes the second check for nothing
    # (measured: access denied, then opened once the user's SID was added).
    grants = [f"(A;;FA;;;{sid.group(0)})", f"(A;;FA;;;{_user_sid()})"]

    def edit(aces):
        # A read-only artifact is linked into every jail of every session: an
        # ACE per jail outgrew the ACL (ERROR 1340, an ACL is at most 64
        # KiB). A jailer takes its jail's entries off the files it shares
        # when Firecracker ends (unshare, overlay/jailer/platform/windows);
        # those of jailers that were killed are what this bounds. Far more
        # than run at once: an entry is not dropped by its age, and one
        # dropped was a running jail's (access denied at its next open).
        jails = [a for a in aces if a.startswith("(A;") and "S-1-9-" in a and a != grants[0]]
        old = set(jails[:-256])
        return [a for a in aces if a not in old] + [g for g in grants if g not in aces]

    _set_dacl(path, edit)
    label = _sddl(root, _LABEL_INFO)
    if "ML;" not in label:
        return
    # The label itself, not inherited: a file inherits no label once made.
    label = label.replace(";OICI;", ";;").replace(";OICIID;", ";;").replace(";ID;", ";;")
    sd = ctypes.c_void_p()
    if not _advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(label, 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted, sacl = ctypes.c_int(), ctypes.c_int(), ctypes.c_void_p()
        if not _advapi.GetSecurityDescriptorSacl(sd, ctypes.byref(present), ctypes.byref(sacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        rc = _advapi.SetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, _LABEL_INFO, None, None, None, sacl)
        if rc:
            raise OSError(rc, f"SetNamedSecurityInfo({path}) label", None, rc)
    finally:
        _kernel32.LocalFree(sd)

# The test session root (upstream: /srv, a tmpfs devtool makes).
import framework.defs as _defs  # noqa: E402  pylint: disable=wrong-import-position

_defs.DEFAULT_TEST_SESSION_ROOT_PATH = SESSION_ROOT

# Upstream's commands are a POSIX shell's (`cat`, `grep`, `awk`, pipes): on
# Linux `subprocess` with `shell=True` runs /bin/sh. Here they run in Git for
# Windows's bash, whose MSYS layer has those tools (and a /proc).
BASH = os.environ.get("WICK_IT_BASH", r"C:\Program Files\Git\bin\bash.exe")
if not os.path.exists(BASH):
    raise SystemError(f"wick_windows: no POSIX shell at {BASH} (install Git for Windows, or set WICK_IT_BASH)")

import subprocess  # noqa: E402  pylint: disable=wrong-import-position

import framework.utils as _utils  # noqa: E402  pylint: disable=wrong-import-position

_real_popen = subprocess.Popen


# The Linux host tools Git's bash lacks or has otherwise (procps, dmesg,
# e2fsprogs): tools/windows/integration/hosttools.py, for a command line and,
# through BASH_ENV, for bash's commands.
import hosttools  # noqa: E402  pylint: disable=wrong-import-position

_HOSTTOOLS = os.path.abspath(hosttools.__file__)
_TOOLS = hosttools.TOOLS
_SUBSTITUTES = {t: [sys.executable, _HOSTTOOLS, t] for t in _TOOLS}
# A Windows path in a shell command (upstream joins paths with os.path):
# bash takes a backslash for an escape, MSYS takes C:/x for C:\x.
_WIN_PATH = re.compile(r"\b[A-Za-z]:\\[^\s'\"|;&<>()]*")


def _msys(path):
    """A Windows path as bash names it (C:\\x -> /c/x)."""
    path = os.path.abspath(path).replace("\\", "/")
    return f"/{path[0].lower()}{path[2:]}" if path[1:2] == ":" else path


def _shims():
    shims = os.path.join(SESSION_ROOT, "shims")
    os.makedirs(shims, exist_ok=True)
    for tool in _TOOLS:
        with open(os.path.join(shims, tool), "w", newline="\n", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\nexec "{_msys(sys.executable)}" "{_msys(_HOSTTOOLS)}" {tool} "$@"\n')
    env = os.path.join(shims, "bash_env")
    with open(env, "w", newline="\n", encoding="utf-8") as f:
        # A UTF-8 locale, as a Linux host's shell has (grep -P wants one).
        f.write(f'PATH="{_msys(shims)}:$PATH"\nexport LC_ALL=C.UTF-8\n')
        # /proc/<pid>/status of a Windows process (MSYS's /proc has its own
        # processes only): hosttools.py's procstatus.
        f.write(
            "cat() {\n"
            '  if [ "$#" -eq 1 ] && [ ! -e "$1" ]; then\n'
            '    case "$1" in /proc/[0-9]*/status)\n'
            '      local p="${1#/proc/}"; p="${p%/status}"\n'
            f'      "{_msys(sys.executable)}" "{_msys(_HOSTTOOLS)}" procstatus "$p"; return $?;;\n'
            "    esac\n"
            "  fi\n"
            '  command cat "$@"\n'
            "}\n"
        )
    os.environ["BASH_ENV"] = _msys(env)


_shims()


class _Popen(_real_popen):
    """`subprocess.Popen` whose `shell=True` is bash's `-c`, as /bin/sh's on Linux."""

    def __init__(self, args, *a, shell=False, **kw):
        if shell and isinstance(args, str):
            args = _WIN_PATH.sub(lambda m: m.group(0).replace("\\", "/"), args)
            args, shell = [BASH, "-c", args], False
        elif isinstance(args, list) and args and args[0] in _SUBSTITUTES:
            args = _SUBSTITUTES[args[0]] + list(args[1:])
        super().__init__(args, *a, shell=shell, **kw)


    # Linux: terminate() sends SIGTERM and kill() SIGKILL; a process that
    # dies of them exits with 128 + the signal, as tests check (socat's 143).
    # Windows ends a process (TerminateProcess) with the status it is given.
    def terminate(self):
        self._end(128 + 15)

    def kill(self):
        self._end(128 + 9)

    def _end(self, status):
        import _winapi  # pylint: disable=import-outside-toplevel

        if self.returncode is None:
            try:
                _winapi.TerminateProcess(self._handle, status)
            except PermissionError:
                if _winapi.GetExitCodeProcess(self._handle) == _winapi.STILL_ACTIVE:
                    raise


subprocess.Popen = _Popen

# The host's processor, which Linux's lscpu and /proc/cpuinfo name: from the
# registry, where Windows keeps the CPUID vendor and brand strings.
import winreg  # noqa: E402  pylint: disable=wrong-import-position

import framework.utils_cpuid as _cpuid  # noqa: E402  pylint: disable=wrong-import-position


def _processor(value):
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
        return str(winreg.QueryValueEx(k, value)[0]).strip()


_cpuid.get_cpu_vendor = lambda: (
    _cpuid.CpuVendor.AMD if _processor("VendorIdentifier") == "AuthenticAMD" else _cpuid.CpuVendor.INTEL
)
_cpuid.get_cpu_model_name = lambda: _processor("ProcessorNameString")

import contextlib  # noqa: E402  pylint: disable=wrong-import-position
import pathlib  # noqa: E402  pylint: disable=wrong-import-position


def _cpu_list(cpus):
    """CPUs in Linux's list syntax (0-3,6)."""
    out, cpus = [], sorted(cpus)
    while cpus:
        start = end = cpus.pop(0)
        while cpus and cpus[0] == end + 1:
            end = cpus.pop(0)
        out.append(f"{start}-{end}" if end != start else f"{start}")
    return ",".join(out)


def _node_cpus(node):
    """The logical CPUs of a NUMA node (GetNumaNodeProcessorMaskEx, group 0)."""

    class _GroupAffinity(ctypes.Structure):
        _fields_ = [("Mask", ctypes.c_size_t), ("Group", ctypes.c_ushort), ("Reserved", ctypes.c_ushort * 3)]

    aff = _GroupAffinity()
    if not ctypes.windll.kernel32.GetNumaNodeProcessorMaskEx(ctypes.c_ushort(node), ctypes.byref(aff)):
        raise FileNotFoundError(2, f"no NUMA node {node}")
    return [c for c in range(64) if aff.Mask >> c & 1]


# Linux files the framework reads on the host, from Windows's own data.
_VIRTUAL_FILES = {
    "/etc/os-release": lambda: f'PRETTY_NAME="Windows {platform.release()} {platform.version()}"\n',
    "/sys/devices/system/cpu/online": lambda: _cpu_list(range(os.cpu_count())) + "\n",
}
_real_read_text = pathlib.Path.read_text


def _read_text(self, *args, **kwargs):
    name = self.as_posix()
    if name in _VIRTUAL_FILES:
        return _VIRTUAL_FILES[name]()
    m = re.fullmatch(r"/sys/devices/system/node/node(\d+)/cpulist", name)
    if m:
        return _cpu_list(_node_cpus(int(m.group(1)))) + "\n"
    return _real_read_text(self, *args, **kwargs)


pathlib.Path.read_text = _read_text


class _Stat:
    """`os.stat_result` with st_blocks, which Windows's lacks: the 512-byte
    blocks the file has on disk, what a sparse file's holes do not take
    (GetCompressedFileSizeW, the allocated size)."""

    def __init__(self, path, st):
        self._path, self._st = path, st

    def __getattr__(self, name):
        if name == "st_blocks":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.GetCompressedFileSizeW.restype = ctypes.c_uint32
            high = ctypes.c_uint32()
            low = k32.GetCompressedFileSizeW(str(self._path), ctypes.byref(high))
            if low == 0xFFFFFFFF and ctypes.get_last_error():
                raise ctypes.WinError(ctypes.get_last_error())
            return ((high.value << 32) | low) // 512
        return getattr(self._st, name)

    def __getitem__(self, i):
        return self._st[i]

    def __iter__(self):
        return iter(self._st)

    def __len__(self):
        return len(self._st)

    def __eq__(self, other):
        return self._st == (other._st if isinstance(other, _Stat) else other)

    def __repr__(self):
        return repr(self._st)


_real_path_stat = pathlib.Path.stat


def _path_stat(self, *, follow_symlinks=True):
    return _Stat(self, _real_path_stat(self, follow_symlinks=follow_symlinks))


pathlib.Path.stat = _path_stat

_real_os_stat = os.stat


def _os_stat(path, *args, **kwargs):
    """`os.stat` with st_blocks (`_Stat`) for a path; a descriptor's as it is."""
    st = _real_os_stat(path, *args, **kwargs)
    return _Stat(path, st) if isinstance(path, (str, os.PathLike)) else st


os.stat = _os_stat

import framework.properties  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import

# Signals. Windows's os.kill ends a process (TerminateProcess) for any signal
# but its console events: what SIGKILL does on Linux. SIGALRM stays undefined
# (pytest-timeout then times out with a thread); utils.Timeout, which uses it
# on Linux, is a timer thread that interrupts the main thread.
import signal  # noqa: E402  pylint: disable=wrong-import-position
import threading  # noqa: E402  pylint: disable=wrong-import-position
import _thread  # noqa: E402  pylint: disable=wrong-import-position

for _name, _num in (("SIGKILL", 9), ("SIGHUP", 1), ("SIGQUIT", 3), ("SIGTRAP", 5), ("SIGBUS", 7),
                    ("SIGUSR1", 10), ("SIGUSR2", 12), ("SIGPIPE", 13), ("SIGCHLD", 17),
                    ("SIGCONT", 18), ("SIGSTOP", 19), ("SIGXCPU", 24), ("SIGXFSZ", 25), ("SIGVTALRM", 26),
                    ("SIGPROF", 27), ("SIGWINCH", 28), ("SIGSYS", 31)):
    if not hasattr(signal, _name):
        setattr(signal, _name, _num)


class _Timeout:
    """`utils.Timeout` without SIGALRM: a timer interrupts the main thread
    (KeyboardInterrupt there), turned into TimeoutError on the way out."""

    def __init__(self, seconds, msg="Timed out"):
        self.seconds = seconds
        self.msg = msg
        self._timer = None
        self._fired = False

    def _fire(self):
        self._fired = True
        _thread.interrupt_main()

    def __enter__(self):
        self._timer = threading.Timer(self.seconds, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def __exit__(self, kind, _value, _traceback):
        self._timer.cancel()
        if self._fired and kind is KeyboardInterrupt:
            raise TimeoutError(self.msg)


_utils.Timeout = _Timeout

# ------------------------------------------------------ waiting for exits

# Linux: the session is the subreaper of what the jailer leaves behind and
# waits for pids with waitpid(WNOHANG). Windows keeps no zombie and has no
# reparenting: a pid is waited for through its process handle (psutil), and
# there is nothing to reap (waitpid(-1) finds no child).
import time  # noqa: E402  pylint: disable=wrong-import-position

os.WNOHANG = getattr(os, "WNOHANG", 1)
_real_waitpid = os.waitpid


def _waitpid(pid, options):
    if pid == -1:
        raise ChildProcessError("no child to reap: Windows reparents no process")
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        raise ChildProcessError(f"no process {pid}") from None
    try:
        code = p.wait(0 if options & os.WNOHANG else None)
    except psutil.TimeoutExpired:
        return 0, 0
    return pid, (code or 0) << 8


def wait_process_termination(p_pid, timeout=10.0):
    """`utils.wait_process_termination` through the process handle."""
    try:
        psutil.Process(p_pid).wait(timeout)
    except psutil.NoSuchProcess:
        return
    except psutil.TimeoutExpired:
        raise TimeoutError(f"Process {p_pid} did not exit within {timeout}s") from None


import psutil  # noqa: E402  pylint: disable=wrong-import-position

import wick_windows_mem  # noqa: E402  pylint: disable=wrong-import-position

# os.kill: Linux raises ProcessLookupError (ESRCH) for a pid no process has.
# Windows's os.kill fails with ERROR_INVALID_PARAMETER for one, and with
# access denied for a process that has ended while a handle keeps its pid.
_real_kill = os.kill
_SYNCHRONIZE = 0x00100000


def _ended(pid):
    """Whether no running process has `pid`."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    h = k32.OpenProcess(_SYNCHRONIZE | 0x1000, False, pid)  # | PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ctypes.get_last_error() == 87
    try:
        return k32.WaitForSingleObject(ctypes.c_void_p(h), 0) == 0
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


def _kill(pid, sig):
    if sig in (signal.CTRL_C_EVENT, signal.CTRL_BREAK_EVENT):
        return _real_kill(pid, sig)
    # CPython's os.kill opens the process for every access right, more than a
    # jailed process's DACL may give its user (which grants terminating it):
    # PROCESS_TERMINATE alone, then TerminateProcess with the signal's
    # number, as CPython's.
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    if sig in (signal.SIGSTOP, signal.SIGCONT):
        # Stopping and continuing a process: suspending and resuming all its
        # threads (NtSuspendProcess, NtResumeProcess).
        h = k32.OpenProcess(0x0800, False, pid)  # PROCESS_SUSPEND_RESUME
        if not h:
            raise ProcessLookupError(3, f"kill({pid}): no such process")
        try:
            ntdll = ctypes.WinDLL("ntdll")
            call = ntdll.NtSuspendProcess if sig == signal.SIGSTOP else ntdll.NtResumeProcess
            status = call(ctypes.c_void_p(h))
            if status:
                raise OSError(errno.EPERM, f"kill({pid}, {sig}): NTSTATUS {status & 0xFFFFFFFF:#x}")
        finally:
            k32.CloseHandle(ctypes.c_void_p(h))
        return None
    h = k32.OpenProcess(0x0001, False, pid)  # PROCESS_TERMINATE
    if not h:
        err = ctypes.get_last_error()
        if err == 87 or _ended(pid):
            raise ProcessLookupError(3, f"kill({pid}): no such process")
        raise ctypes.WinError(err)
    try:
        if not k32.TerminateProcess(ctypes.c_void_p(h), sig):
            err = ctypes.get_last_error()
            if _ended(pid):
                raise ProcessLookupError(3, f"kill({pid}): no such process")
            raise ctypes.WinError(err)
        return None
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


os.kill = _kill


def _killpg(pgid, sig):
    """`os.killpg`: the process and what it started (Windows has no process
    groups to signal; a process group's leader and its descendants)."""
    try:
        leader = psutil.Process(pgid)
    except psutil.NoSuchProcess:
        raise ProcessLookupError(3, f"killpg({pgid}): no such process group") from None
    for p in [*leader.children(recursive=True), leader]:
        try:
            _kill(p.pid, sig)
        except ProcessLookupError:
            pass


os.killpg = _killpg

# Threads. Linux names a thread in /proc/<tid>/comm, and a tid is a pid
# psutil can open (utils.get_threads, set_cpu_affinity). Windows's thread
# ids are not processes: a thread's name is its description (Rust's std sets
# it), its CPUs its affinity mask (SetThreadAffinityMask).


def get_threads(pid):
    """`utils.get_threads`: thread name -> thread ids."""
    from collections import defaultdict  # pylint: disable=import-outside-toplevel

    try:
        out = defaultdict(list)
        for t in psutil.Process(pid).threads():
            out[hosttools.thread_name(t.id) or psutil.Process(pid).name().removesuffix(".exe")].append(t.id)
        return out
    except psutil.NoSuchProcess:
        return {}


def _thread_affinity(tid, cpus=None):
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenThread.restype = ctypes.c_void_p
    k32.SetThreadAffinityMask.restype = ctypes.c_size_t
    k32.SetThreadAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    # THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION
    h = k32.OpenThread(0x0020 | 0x0040, False, tid)
    if not h:
        return None
    try:
        allowed = psutil.Process().cpu_affinity()
        mask = sum(1 << c for c in (cpus if cpus is not None else allowed))
        old = k32.SetThreadAffinityMask(ctypes.c_void_p(h), mask)
        if not old:
            raise ctypes.WinError(ctypes.get_last_error())
        if cpus is None:  # a read: put the old mask back
            k32.SetThreadAffinityMask(ctypes.c_void_p(h), old)
            return [c for c in range(64) if old >> c & 1]
        return cpus
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


def get_cpu_affinity(pid):
    """`utils.get_cpu_affinity` for a process or a thread."""
    got = None if psutil.pid_exists(pid) else _thread_affinity(pid)
    return got if got is not None else psutil.Process(pid).cpu_affinity()


def set_cpu_affinity(pid, cpulist):
    """`utils.set_cpu_affinity` for a process or a thread."""
    real = list(map(_utils.CpuMap, cpulist))
    if not psutil.pid_exists(pid):
        got = _thread_affinity(pid, real)
        if got is not None:
            return got
    return psutil.Process(pid).cpu_affinity(real)


_utils.get_threads = get_threads
_utils.get_cpu_affinity = get_cpu_affinity
_utils.set_cpu_affinity = set_cpu_affinity

# Removing a jail: a process of it that has just ended may still hold a file
# there for a moment (the jailer's keeper, which waits for Firecracker); Linux
# unlinks open files. Retried for a few seconds.
import shutil  # noqa: E402  pylint: disable=wrong-import-position

_real_rmtree = shutil.rmtree


def rmtree(path, *args, **kwargs):
    """`shutil.rmtree`, retried while a file is in use (WinError 32)."""
    deadline = time.time() + 10
    while True:
        try:
            return _real_rmtree(path, *args, **kwargs)
        except PermissionError as err:
            if getattr(err, "winerror", None) != 32 or time.time() > deadline:
                raise
            time.sleep(0.2)


shutil.rmtree = rmtree

# Upstream's memory monitor reads Linux's smaps through psutil
# (tools/windows/integration/wick_windows_mem.py).
wick_windows_mem.install()

os.waitpid = _waitpid
_utils.wait_process_termination = wait_process_termination


# --------------------------------------------------------------- binaries

# Linux binaries have no extension; Windows's are `.exe`. The framework names
# them as on Linux (host_tools/cargo_build.py `get_binary`).
import host_tools.cargo_build as _cargo_build  # noqa: E402  pylint: disable=wrong-import-position

_real_get_binary = _cargo_build.get_binary


def get_binary(name, *, binary_dir=_cargo_build.DEFAULT_BINARY_DIR, example=None):
    """`get_binary`, with the `.exe` Windows gives the file. Upstream's default
    directory is Linux's musl target's; the session's binaries are in its
    bin directory (WICK_IT_BIN, tools/windows/integration-tests.ps1)."""
    if pathlib.Path(binary_dir) == pathlib.Path(_cargo_build.DEFAULT_BINARY_DIR) and os.environ.get("WICK_IT_BIN"):
        binary_dir = pathlib.Path(os.environ["WICK_IT_BIN"])
    return hosttools.windows_binary(_real_get_binary(name, binary_dir=binary_dir, example=example))


_cargo_build.get_binary = get_binary

_real_cargo = _cargo_build.cargo


def cargo(subcommand, cargo_args="", subcommand_args="", *, env=None, cwd=None, nightly=False, timeout=None):
    """`cargo`, building for the Windows target where a test asks for
    Linux's musl one (test_fuzzing, test_gdb, test_instrumented_firecracker
    build Firecracker themselves), with the output also under the musl
    target's directory name (a junction), where the test looks for it."""
    cargo_args, musl = hosttools.windows_cargo_args(cargo_args)
    out = _real_cargo(subcommand, cargo_args, subcommand_args, env=env, cwd=cwd, nightly=nightly, timeout=timeout)
    if musl and subcommand == "build":
        target_dir = pathlib.Path((env or {}).get("CARGO_TARGET_DIR") or "build/cargo_target")
        if not target_dir.is_absolute():
            target_dir = pathlib.Path(cwd or os.getcwd()) / target_dir
        linked = target_dir / musl
        if not linked.exists():
            subprocess.run(["cmd", "/c", "mklink", "/J", str(linked), str(target_dir / hosttools.WINDOWS_TARGET)],
                           check=True, capture_output=True)
    return out


_cargo_build.cargo = cargo

# --------------------------------------------------------------- the jail

import framework.jailer as _jailer  # noqa: E402  pylint: disable=wrong-import-position

_real_jailed_path = _jailer.JailerContext.jailed_path


def jailed_path(self, file_path, create=False, subdir="."):
    """`JailerContext.jailed_path`, with the chown done (`give_to_jail`).
    The path in the jail is upstream's, `/name`: the jail's root is a drive
    of its own, where Firecracker takes `/` for the root
    (overlay/jailer/platform/windows/mod.rs); Python's WindowsPath would
    write `\\name`."""
    jailed = _real_jailed_path(self, file_path, create, subdir)
    if create:
        root = pathlib.Path(self.chroot_path())
        give_to_jail(root / subdir / pathlib.Path(file_path).name, root)
    return jailed.replace("\\", "/")


_jailer.JailerContext.jailed_path = jailed_path

# WICK_IT_NO_DAEMONIZE=1 (a debugging aid): jailers run in the foreground, so
# what Firecracker writes to its standard error (the host sandbox's NTSTATUS
# when it denies an operation) is in the screen log, as without --daemonize.
if os.environ.get("WICK_IT_NO_DAEMONIZE") == "1":
    _real_jailer_init = _jailer.JailerContext.__init__

    def _jailer_init(self, *args, **kwargs):
        _real_jailer_init(self, *args, **kwargs)
        self.daemonize = False

    _jailer.JailerContext.__init__ = _jailer_init

import framework.microvm as _microvm  # noqa: E402  pylint: disable=wrong-import-position

_real_copy_to_chroot = _microvm.Snapshot.copy_to_chroot


def copy_to_chroot(self, chroot):
    """`Snapshot.copy_to_chroot`: the snapshot's files linked into the jail,
    given to it as `jailed_path` gives a file. On Linux every jail of the
    session runs as the same uid (1234), which owns the files the first
    jail's Firecracker wrote; on Windows each jail has a SID of its own."""
    snap = _real_copy_to_chroot(self, chroot)
    for path in (snap.mem, snap.vmstate):
        give_to_jail(path, pathlib.Path(chroot))
    return snap


_microvm.Snapshot.copy_to_chroot = copy_to_chroot

# The factory names its binaries as on Linux too (`binary_path / "firecracker"`),
# and asserts they exist: in a directory a test built itself (test_fuzzing,
# test_gdb) there is only the `.exe`.
_microvm.MicroVMFactory.fc_binary_path = property(
    lambda self: hosttools.windows_binary(self.binary_path / "firecracker"),
    doc=_microvm.MicroVMFactory.fc_binary_path.__doc__,
)
_microvm.MicroVMFactory.jailer_binary_path = property(
    lambda self: hosttools.windows_binary(self.binary_path / "jailer"),
    doc=_microvm.MicroVMFactory.jailer_binary_path.__doc__,
)

# The uffd page fault handler. Linux: started chrooted in the jail, so its
# socket (/firecracker-uffd.sock) is where the jailed Firecracker connects,
# then chowned to the jail. Windows has no chroot: the handler starts in the
# jail directory with the jail's paths spelled out, and its socket is given
# to the jail (`give_to_jail`).
import framework.utils_uffd as _utils_uffd  # noqa: E402  pylint: disable=wrong-import-position


def _uffd_spawn(self, uid, gid):  # pylint: disable=unused-argument
    """`UffdHandler.spawn` without chroot."""
    root = pathlib.Path(self._chroot)  # pylint: disable=protected-access
    socket_path = root / self.socket_path.lstrip("/")
    with open(root / self._log_file, "w", encoding="utf-8") as logfile:  # pylint: disable=protected-access
        # Paths relative to the jail, as the chrooted handler's are: its
        # command line names no jail (the framework looks for processes left
        # with a jail's id in theirs).
        args = [f"/{self._handler_name}", self.socket_path.lstrip("/"), self.snapshot.mem.name]  # pylint: disable=protected-access
        # The file as named (CreateProcess would look for <name>.exe).
        self._proc = subprocess.Popen(args, executable=str(root / self._handler_name), cwd=root,  # pylint: disable=protected-access,consider-using-with
                                      stdout=logfile, stderr=subprocess.STDOUT)
    time.sleep(1)
    if not self.is_running():
        print(self.log_data)
        assert False, "Could not start PF handler!"
    give_to_jail(socket_path, root)


_utils_uffd.UffdHandler.spawn = _uffd_spawn

# ----------------------------------------------------------- the backends

# The "kvm" backend of upstream's framework is Firecracker's KVM API, which
# wick provides on WHP (crates/compat/kvm-ioctls/src/whp). Nitro Enclaves has
# no Windows host.


def whp_available():
    """Whether this host runs WHP partitions (Linux: /dev/kvm)."""
    try:
        whp = ctypes.WinDLL("WinHvPlatform.dll")
    except OSError:
        return False
    present = ctypes.c_uint32(0)
    written = ctypes.c_uint32(0)
    # WHvCapabilityCodeHypervisorPresent = 0
    hr = whp.WHvGetCapability(0, ctypes.byref(present), 4, ctypes.byref(written))
    return hr == 0 and present.value != 0


import framework.kvm as _kvm  # noqa: E402  pylint: disable=wrong-import-position
import framework.vm_backend as _vm_backend  # noqa: E402  pylint: disable=wrong-import-position
import framework.enclave as _enclave  # noqa: E402  pylint: disable=wrong-import-position

_kvm.has_kvm = whp_available
_kvm.kvm_probe_details = lambda: {"hypervisor": "Windows Hypervisor Platform", "present": whp_available()}
_vm_backend.has_kvm = whp_available
_vm_backend.kvm_probe_details = _kvm.kvm_probe_details
_enclave.enclave_host_available = lambda: False
_vm_backend.enclave_host_available = lambda: False

# ------------------------------------------------------- the serial console

# Linux: Firecracker runs in a screen session; its output goes to the
# session's log file, input is `screen -X stuff`. Here the jailer runs with
# its standard input a pipe (the jailer relays it to Firecracker:
# platform/windows/console.rs) and its output appended to the same log file.
import psutil  # noqa: E402  pylint: disable=wrong-import-position

import framework.microvm as _microvm  # noqa: E402  pylint: disable=wrong-import-position

_SESSIONS = {}


def start_screen_process(screen_log, session_name, binary_path, binary_params):
    """`utils.start_screen_process`: the binary under a stand-in for screen
    (hosttools.py's `screen`), its input a pipe from this session and its
    output copied to `screen_log`; returns the stand-in's pid (the "screen"
    pid, which tests stop and the framework kills with Firecracker's)."""
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, _HOSTTOOLS, "screen", str(screen_log), str(binary_path),
         *[str(p) for p in binary_params]],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _SESSIONS[session_name] = (proc, None)
    _utils.wait_process_running(psutil.Process(proc.pid))
    return _interpreter(proc.pid)


def _interpreter(pid):
    """The pid of the interpreter a Python process started as `pid` runs in.
    A virtual environment's python.exe is a launcher that runs the base
    interpreter as its child and waits for it: stopping the launcher
    (SIGSTOP, NtSuspendProcess) would leave the interpreter copying."""
    if os.path.normcase(sys.executable) == os.path.normcase(getattr(sys, "_base_executable", sys.executable)):
        return pid
    import time  # pylint: disable=import-outside-toplevel

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            children = psutil.Process(pid).children()
        except psutil.Error:
            return pid
        if children:
            return children[0].pid
        time.sleep(0.02)
    raise RuntimeError(f"{sys.executable} (pid {pid}) started no interpreter")


_utils.start_screen_process = start_screen_process


def serial_input(self, input_string):
    """`Microvm.serial_input` (screen's `stuff`): written to the pipe."""
    proc, _ = _SESSIONS[self.screen_session]
    proc.stdin.write(input_string.encode())
    proc.stdin.flush()


_microvm.Microvm.serial_input = serial_input

# The screen log's directory (Linux: /tmp).
_tmp = os.path.join(SESSION_ROOT, "tmp")
os.makedirs(_tmp, exist_ok=True)
_microvm.Microvm.screen_log = property(lambda self: os.path.join(_tmp, f"screen-{self.screen_session}.log"))


class _Serial(_microvm.Serial):
    """`microvm.Serial` reading the log file as it grows (Linux: poll(2) on it)."""

    def open(self):
        if self._poller is not None:
            return
        attempt = 0
        while not os.path.exists(self._vm.screen_log) and attempt < 5:
            import time  # pylint: disable=import-outside-toplevel

            time.sleep(0.2)
            attempt += 1
        self._poller = open(self._vm.screen_log, "rb")  # pylint: disable=consider-using-with

    def rx_char(self):
        import time  # pylint: disable=import-outside-toplevel

        c = self._poller.read(1)
        if not c:
            time.sleep(0.01)
            return ""
        return c.decode("utf-8", errors="ignore")


_microvm.Serial = _Serial

# ---------------------------------------------------------------- networks

# Linux: `ip netns`, a network namespace with TAP devices in it. Windows: a
# network, a directory of endpoints (tools/windows/integration/
# wick_windows_net.py).
import host_tools.network as _network  # noqa: E402  pylint: disable=wrong-import-position

from wick_windows_net import NetNs, Tap, network  # noqa: E402  pylint: disable=wrong-import-position

_network.NetNs = NetNs
_network.Tap = Tap

# ssh and scp: Git for Windows's OpenSSH, whose MSYS layer has the Unix
# sockets ControlMaster multiplexes over (Windows's own OpenSSH has none).
GIT_USR_BIN = os.path.join(os.path.dirname(os.path.dirname(BASH)), "usr", "bin")
_real_ssh_init = _network.SSHConnection.__init__


def _ssh_init(self, netns, ssh_key, control_path, host, user, *, on_error=None):
    """`SSHConnection.__init__`. Upstream asserts the key's mode is 0400
    after chmod; Windows keeps only a read-only bit, which reads as 0444.
    What ssh asks of the key (no one else may read it) is the file's ACL."""
    real_stat = type(ssh_key).stat

    def stat(path, *a, **kw):
        st = real_stat(path, *a, **kw)
        if path == ssh_key:
            return os.stat_result((st.st_mode & ~0o777 | 0o400, *tuple(st)[1:]))
        return st

    type(ssh_key).stat = stat
    try:
        _restrict_to_user(ssh_key)
        ssh_key.chmod(0o400)
        _real_ssh_init(self, netns, ssh_key, control_path, host, user, on_error=on_error)
    finally:
        type(ssh_key).stat = real_stat


def _restrict_to_user(path):
    """The key readable by the user alone (`chmod 0400` on Linux)."""
    # Full control (the owner keeps chmod), no one else.
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{os.environ['USERNAME']}:F"],
                   check=True, capture_output=True)


_real_ssh_exec = _network.SSHConnection._exec  # pylint: disable=protected-access


def _split_options(args):
    """ssh's options in `args` (pairs: -o X, -i X, -c X; flags alone), and
    what follows them (host, command; scp's paths)."""
    opts, rest, i = [], [], 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "-i", "-c", "-p", "-P", "-O") and i + 1 < len(args):
            opts += [a, args[i + 1]]
            i += 2
        elif a.startswith("-") and not rest:
            opts.append(a)
            i += 1
        else:
            rest.append(a)
            i += 1
    return opts, rest


def _without_control(opts):
    """`opts` without the control master's options (ControlMaster,
    ControlPersist, ControlPath)."""
    out, i = [], 0
    while i < len(opts):
        if opts[i] == "-o" and opts[i + 1].split("=", 1)[0] in ("ControlMaster", "ControlPersist", "ControlPath"):
            i += 2
            continue
        out.append(opts[i])
        i += 1
    return out


def _ssh_exec(self, cmd, timeout=100, check=False):
    """`SSHConnection._exec`. Linux: `ip netns exec <ns> ssh|scp ...`. Here
    ssh and scp run on the host and reach the guest through the network's
    forward, a port on 127.0.0.1 that leads to <guest>:22.

    Upstream multiplexes every command over one connection (ControlMaster).
    Git's ssh cannot: Cygwin's AF_UNIX sockets carry no descriptors, so the
    master resets each session it is handed (measured: "mux_client_request_
    session: read from master failed: Connection reset by peer"; `-O check`,
    which passes none, works). Each command is a connection of its own,
    with the options and key the master was made with, and the master is a
    process that stands for the connection from its establishment to `-O
    stop`, so that the framework's checks (`-O check`'s pid, waiting for the
    master to end) are Linux's."""
    net = network(self.netns) if self.netns is not None else None
    if net is None:
        raise RuntimeError(f"network {self.netns} was not made by this session")
    port = net.forward(self.host, 22)
    tool, args = cmd[0], list(cmd[1:])
    user_host = f"{self.user}@{self.host}"
    local = f"{self.user}@127.0.0.1"
    args = [local if a == user_host else local + a[len(user_host):] if a.startswith(user_host + ":") else a
            for a in args]
    opts, rest = _split_options(args)
    master = getattr(self, "_wick_master", None)
    if "-O" in opts:
        op = opts[opts.index("-O") + 1]
        if master is None or master.poll() is not None:
            out = _utils.CommandReturn(255, "", f"Control socket connect({self._control_path}): No such file or directory\n")
            if check:
                raise ChildProcessError(out.stderr)
            return out
        if op == "check":
            return _utils.CommandReturn(0, "", f"Master running (pid={master.pid})\n")
        master.stdin.close()
        self._wick_master = None
        self._control_path.unlink(missing_ok=True)
        return _utils.CommandReturn(0, "", "Stop listening request sent.\n")
    establish = any(o.startswith("ControlMaster=") for o in opts)
    if establish:
        # The connection's options for every later command, but its
        # ConnectTimeout: on Linux that bounds the one connection the master
        # makes, and later commands ride it; here each makes its own, whose
        # key exchange takes longer than 2 s on a loaded host (measured:
        # "Connection timed out during banner exchange" at six VMs at once).
        kept = [o for o in _without_control(opts) if o != "-vvv"]
        self._wick_options = []
        i = 0
        while i < len(kept):
            if kept[i] == "-o" and kept[i + 1].startswith("ConnectTimeout="):
                i += 2
                continue
            self._wick_options.append(kept[i])
            i += 1
    base = getattr(self, "_wick_options", [])
    opts = _without_control(opts)
    # The connection's options (key, algorithms) first; ssh takes the first
    # value of an option given twice.
    full = opts if establish else base + opts
    port_flag = "-P" if tool == "scp" else "-p"
    final = [os.path.join(GIT_USR_BIN, tool + ".exe"), port_flag, str(port), "-o", f"HostKeyAlias={self.host}",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "LogLevel=ERROR",
             *full, *rest]
    saved = self.netns
    self.netns = None
    try:
        result = _real_ssh_exec(self, final, timeout, check)
    finally:
        self.netns = saved
    if establish and result.returncode == 0:
        self._wick_master = subprocess.Popen(  # pylint: disable=consider-using-with
            [sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
        self._control_path.touch()
    return _utils.CommandReturn(*result)


_real_scp_put = _network.SSHConnection.scp_put


def _scp_put(self, local_path, remote_path, recursive=False):
    """`SSHConnection.scp_put`. scp gives the guest's copy the host file's
    mode; a Windows file has no execute bit, so a Linux program built for
    the guest (an ELF file, built in WSL: hosttools.py) arrives without it.
    It is set in the guest, as the file's mode is on Linux."""
    _real_scp_put(self, local_path, remote_path, recursive)
    if recursive or not os.path.isfile(local_path):
        return
    with open(local_path, "rb") as f:
        if f.read(4) != b"\x7fELF":
            return
    name = os.path.basename(str(local_path))
    self.check_output(f"if [ -d {remote_path} ]; then chmod a+x {remote_path}/{name}; "
                      f"else chmod a+x {remote_path}; fi")


_network.SSHConnection.scp_put = _scp_put
_network.SSHConnection.__init__ = _ssh_init
_network.SSHConnection._exec = _ssh_exec  # pylint: disable=protected-access


def pytest_report_header():
    """What runs where."""
    return [f"wick Windows host: session root {SESSION_ROOT}, Windows {platform.version()}"]
