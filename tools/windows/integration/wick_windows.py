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


def give_to_jail(path, root):
    """`chown(path, uid, gid)` for a jail: `path` gets the security the jail
    directory `root` hands down (its DACL, its integrity label). A file
    that is a hard link shares it with the source, as a chown does on Linux.
    Before the jailer has protected `root`, nothing: the jailer passes its
    security down to what is in the directory already."""
    if not _sddl(root, _DACL_INFO).startswith("D:P"):
        return
    acl = ctypes.create_string_buffer(64)
    if not _advapi.InitializeAcl(acl, 64, 2):
        raise ctypes.WinError(ctypes.get_last_error())
    # An empty DACL, unprotected: what the parent hands down, nothing else.
    rc = _advapi.SetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, _DACL_INFO | _UNPROTECTED_DACL,
                                       None, None, acl, None)
    if rc:
        raise OSError(rc, f"SetNamedSecurityInfo({path})", None, rc)
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
        f.write(f'PATH="{_msys(shims)}:$PATH"\n')
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


@contextlib.contextmanager
def _os_release():
    """`/etc/os-release` as Windows's own, while framework.properties reads it."""
    name = f'PRETTY_NAME="Windows {platform.release()} {platform.version()}"\n'
    real = pathlib.Path.read_text

    def read_text(self, *args, **kwargs):
        if self.as_posix() in ("/etc/os-release", "\\etc\\os-release") or str(self) == "\\etc\\os-release":
            return name
        return real(self, *args, **kwargs)

    pathlib.Path.read_text = read_text
    try:
        yield
    finally:
        pathlib.Path.read_text = real


with _os_release():
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
    """`get_binary`, with the `.exe` Windows gives the file."""
    path = _real_get_binary(name, binary_dir=binary_dir, example=example)
    exe = path.with_name(path.name + ".exe")
    return exe if not path.exists() and exe.exists() else path


_cargo_build.get_binary = get_binary

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
    """`utils.start_screen_process`: the binary with its input a pipe and its
    output in `screen_log`; returns its pid (the "screen" pid, which the
    framework kills with Firecracker's)."""
    log = open(screen_log, "ab", buffering=0)  # pylint: disable=consider-using-with
    proc = subprocess.Popen(  # pylint: disable=consider-using-with
        [str(binary_path), *[str(p) for p in binary_params]],
        stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
    )
    _SESSIONS[session_name] = (proc, log)
    _utils.wait_process_running(psutil.Process(proc.pid))
    return proc.pid


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
        self._wick_options = [o for o in _without_control(opts) if o != "-vvv"]
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


_network.SSHConnection.__init__ = _ssh_init
_network.SSHConnection._exec = _ssh_exec  # pylint: disable=protected-access


def pytest_report_header():
    """What runs where."""
    return [f"wick Windows host: session root {SESSION_ROOT}, Windows {platform.version()}"]
