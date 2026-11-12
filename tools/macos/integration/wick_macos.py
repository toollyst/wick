# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The macOS host side of upstream's integration test framework.

A pytest plugin, loaded by tools/macos/integration-tests.sh (`-p wick_macos`)
before upstream's conftest.py. Upstream's framework drives Firecracker the
same way on every host; what it does on the Linux host itself (KVM's device
file, `/proc`, `/etc/os-release`, the child subreaper, the commands' GNU
options) is supplied here for macOS, so that upstream's tests run unchanged.

Two modes (WICK_IT_MODE):

- `jailer`: as root, with wick's jailer, as upstream's CI runs the suite.
- `user`: as the user who runs it, without the jailer (tools/macos/integration/
  jailer, a stand-in that starts Firecracker as the jailer's process tree
  does, with the jail's directory as its root for every path). It shows what
  Firecracker does on macOS without root; what only the jailer does (chroot,
  uid, cgroups, the jailer's own arguments) is checked by the `jailer` mode.

Every substitution here says what it stands for on Linux.
"""

import contextlib
import ctypes
import errno
import fcntl
import json
import os
import pathlib
import platform
import re
import select
import shutil
import subprocess
import sys
import time
from collections import defaultdict

MODE = os.environ.get("WICK_IT_MODE", "user")
if MODE not in ("user", "jailer"):
    raise SystemError(f"WICK_IT_MODE={MODE}: must be user or jailer")
# Read by upstream's conftest.py (patched): the session does not need root.
RUNS_AS_USER = MODE == "user"
SESSION_ROOT = os.environ.get("WICK_IT_ROOT")
if sys.platform != "darwin" or not SESSION_ROOT:
    raise SystemError("wick_macos: run through tools/macos/integration-tests.sh on macOS")
if MODE == "jailer" and os.geteuid() != 0:
    raise PermissionError("WICK_IT_MODE=jailer runs as root, as upstream's suite does")

# ------------------------------------------------------------------ the host

# Linux calls this architecture aarch64, and upstream's framework names its
# artifacts, parameters and checks after that name.
_machine = platform.machine
platform.machine = lambda: "aarch64" if _machine() == "arm64" else _machine()


def _sysctl(name):
    return subprocess.check_output(["/usr/sbin/sysctl", "-n", name], text=True).strip()


def hvf_available():
    """Whether this host runs Hypervisor.framework guests (Linux: /dev/kvm)."""
    try:
        return _sysctl("kern.hv_support") == "1"
    except (OSError, subprocess.CalledProcessError):
        return False


# The test session root (upstream: /srv, a tmpfs devtool makes). Unix socket
# paths are limited to 104 bytes on macOS, and the jail's API socket sits five
# levels below this directory, so it is short (tools/macos/integration-tests.sh).
import framework.defs as _defs  # noqa: E402  pylint: disable=wrong-import-position

_defs.DEFAULT_TEST_SESSION_ROOT_PATH = SESSION_ROOT
# Where tests find the binaries they do not take from --binary-dir (upstream:
# build/cargo_target/<arch>-unknown-linux-musl/release, the build devtool
# makes): the same directory, the release build signed for macOS
# (tools/macos/integration-tests.sh).
if os.environ.get("WICK_IT_BINARY_DIR"):
    _defs.DEFAULT_BINARY_DIR = pathlib.Path(os.environ["WICK_IT_BINARY_DIR"])

import framework.utils as _utils  # noqa: E402  pylint: disable=wrong-import-position
import framework.utils_cpuid as _cpuid  # noqa: E402  pylint: disable=wrong-import-position


def _cpu_model():
    # Linux: the MIDR part number from /proc/cpuinfo, named by upstream's
    # table of the Neoverse cores it knows. Apple's cores are not in it.
    return "Unknown"


_cpuid.get_cpu_vendor = lambda: _cpuid.CpuVendor.ARM
_cpuid.get_cpu_model_name = _cpu_model
_cpuid.get_cpu_codename = lambda default="Unknown": _cpu_model()


@contextlib.contextmanager
def _os_release():
    """`/etc/os-release` as macOS's own, while framework.properties reads it."""
    name = f'PRETTY_NAME="macOS {platform.mac_ver()[0]}"\n'
    real = pathlib.Path.read_text

    def read_text(self, *args, **kwargs):
        if str(self) == "/etc/os-release":
            return name
        return real(self, *args, **kwargs)

    pathlib.Path.read_text = read_text
    try:
        yield
    finally:
        pathlib.Path.read_text = real


with _os_release():
    import framework.properties  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import


def wait_process_termination(p_pid, timeout=10.0):
    """`utils.wait_process_termination` without a subreaper.

    Linux: the session is the subreaper of every process the jailer leaves
    behind and waits for them with waitpid. On macOS they go to launchd, so
    the wait is kqueue's NOTE_EXIT, which works for any process the session
    may signal; a child of the session is reaped as well.
    """
    deadline = time.time() + timeout
    kq = select.kqueue()
    try:
        ev = select.kevent(p_pid, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                           select.KQ_NOTE_EXIT)
        try:
            kq.control([ev], 0, 0)
        except ProcessLookupError:
            _reap(p_pid)
            return
        while True:
            # A child that exited earlier is a zombie: no NOTE_EXIT any more.
            if _reap(p_pid):
                return
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError(f"Process {p_pid} did not exit within {timeout}s")
            if kq.control(None, 1, min(left, 0.2)):
                _reap(p_pid)
                return
    finally:
        kq.close()


def _reap(pid):
    """True if `pid` is a child of the session that has exited (and is reaped now)."""
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return done == pid


_utils.wait_process_termination = wait_process_termination

_libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
PROC_PIDLISTTHREADIDS = 28
PROC_PIDTHREADID64INFO = 15
PROC_PIDTBSDINFO = 3


def get_threads(pid):
    """{thread name: [thread id]} of `pid` (upstream: psutil's threads, which
    on macOS needs the process's task port, and each thread's name from
    /proc). proc_pidinfo lists a process's threads and names to its user.

    The main thread: on Linux its name (comm) is the executable's, cut to 15
    bytes (TASK_COMM_LEN), which is how Microvm.pin_vmm finds Firecracker's
    ("firecracker"). On macOS Rust's runtime names a program's main thread
    "main" before `main` runs, on Apple targets only (library/std/src/sys/
    pal/unix/mod.rs: "We only do this on Apple targets"; measured: a
    Firecracker started alone has the one thread "main"). The main thread
    (the oldest: the lowest thread id) named "main" or unnamed is given the
    process's name (p_comm, PROC_PIDTBSDINFO) cut to 15 bytes, Linux's.
    Another unnamed thread is too: on Linux it would carry its creator's
    name, which macOS does not record; Firecracker names every thread it
    starts."""
    ids = (ctypes.c_uint64 * 1024)()
    n = _libsystem.proc_pidinfo(pid, PROC_PIDLISTTHREADIDS, ctypes.c_uint64(0), ids, ctypes.sizeof(ids))
    if n <= 0:
        return {}
    bsd = ctypes.create_string_buffer(136)  # struct proc_bsdinfo; pbi_comm at 48, 16 bytes
    comm = ""
    if _libsystem.proc_pidinfo(pid, PROC_PIDTBSDINFO, ctypes.c_uint64(0), bsd, 136) == 136:
        comm = bsd.raw[48:64].split(b"\0", 1)[0].decode(errors="replace")[:15]
    threads = defaultdict(list)
    info = ctypes.create_string_buffer(112)  # struct proc_threadinfo
    tids = list(ids[: n // 8])
    main = min(tids) if tids else None
    for tid in tids:
        if _libsystem.proc_pidinfo(pid, PROC_PIDTHREADID64INFO, ctypes.c_uint64(tid), info, 112) <= 0:
            continue
        name = info.raw[48:112].split(b"\0", 1)[0].decode(errors="replace")
        if not name or (tid == main and name == "main"):
            name = comm
        threads[name].append(tid)
    return dict(threads)


_utils.get_threads = get_threads


def _online_cpus():
    """The CPUs the session may run on (Linux: its affinity mask and the
    online CPUs). macOS has neither CPU sets nor CPU affinity: every thread
    may run on every logical CPU."""
    return list(range(int(_sysctl("hw.logicalcpu"))))


_utils.CpuMap._cpus = classmethod(lambda cls: _online_cpus())


def _no_affinity(pid, *args):
    """`utils.get_cpu_affinity` and `set_cpu_affinity` (psutil's
    cpu_affinity, Linux only): macOS cannot pin a thread to a CPU; its
    affinity tags (thread_policy_set) are a scheduling hint, not a CPU set."""
    raise OSError(errno.ENOSYS, f"CPU affinity of {pid}: macOS has no CPU affinity "
                  "(thread_policy_set's affinity tag is a hint, not a CPU set)")


# The functional tests whose pinning only reduces noise: test_vsock.py's
# `vsock_uvm` fixture (boot_vsock_vm(pin_threads=True)), the only pinning in
# integration_tests/functional, used by test_vsock_transport_reset_h2g,
# _g2h and test_snapshot_restore_with_inflight_vsock_tx. What they assert is
# that vsock connections are reset by a snapshot and work after a restore;
# nothing is timed or counted per CPU. Upstream ran them unpinned until
# e7a459f74 ("refactor fixtures") gave them the fixture its vsock latency
# test (0a0cdb147, performance/test_vsock.py) pins for. For them pinning is
# skipped, and said so in the test's log and report; everywhere else (the
# performance tests, which pin to measure) it still fails with ENOSYS.
NOISE_ONLY_PINNING = {
    "integration_tests/functional/test_vsock.py::test_vsock_transport_reset_h2g",
    "integration_tests/functional/test_vsock.py::test_vsock_transport_reset_g2h",
    "integration_tests/functional/test_vsock.py::test_snapshot_restore_with_inflight_vsock_tx",
}
_unpinned_test = None


def set_cpu_affinity(pid, cpulist):
    """`utils.set_cpu_affinity`: a no-op, logged, in a test of
    NOISE_ONLY_PINNING; `_no_affinity` everywhere else."""
    if _unpinned_test is None:
        _no_affinity(pid, cpulist)
    msg = (f"CPU affinity of {pid} not set to {cpulist}: macOS has no CPU affinity, and "
           f"this test's pinning only reduces noise (wick_macos.NOISE_ONLY_PINNING)")
    _unpinned_test.user_properties.append(("wick_unpinned", msg))
    import logging  # pylint: disable=import-outside-toplevel
    logging.getLogger("wick_macos").warning(msg)


_utils.get_cpu_affinity = _no_affinity
_utils.set_cpu_affinity = set_cpu_affinity

# ------------------------------------------------------- programs it builds

import host_tools.cargo_build as _cargo_build  # noqa: E402  pylint: disable=wrong-import-position
from framework.with_filelock import with_filelock as _with_filelock  # noqa: E402  pylint: disable=wrong-import-position

# Linux: `gcc -static`, as the host and the guest are the same Linux on the
# same architecture. Here the programs a guest runs are built for it
# (aarch64 Linux, static, with zig's C toolchain), and the one the host runs
# for macOS. A source not listed fails, naming it.
GUEST_PROGRAMS = {"host_tools/vsock_helper.c", "host_tools/sysgenid.c", "host_tools/vmclock.c",
                  "host_tools/devmem.c", "host_tools/waitpkg.c", "data/msr/msr_reader.c"}
HOST_PROGRAMS = {"host_tools/jailer_time.c"}
@_with_filelock
def gcc_compile(src_file, output_file, extra_flags="-static -O3"):
    """`cargo_build.gcc_compile` for the machine that runs the program."""
    out = pathlib.Path(output_file)
    if out.exists():
        return
    if src_file in GUEST_PROGRAMS:
        cmd = f"zig cc -target aarch64-linux-musl {src_file} -o {out} {extra_flags}"
    elif src_file in HOST_PROGRAMS:
        flags = " ".join(f for f in extra_flags.split() if f != "-static")
        cmd = f"cc {src_file} -o {out} {flags}"
    else:
        raise NotImplementedError(f"{src_file}: not known to run in the guest or on the host")
    _utils.check_output(cmd)


_cargo_build.gcc_compile = gcc_compile

# Linux: a build for the host's musl target. On macOS the host's target is
# aarch64-apple-darwin, and Firecracker runs only signed with the
# Hypervisor.framework entitlement (tools/macos/integration-tests.sh).
HOST_TARGET = "aarch64-apple-darwin"
ENTITLEMENTS = pathlib.Path(__file__).resolve().parent.parent / "hypervisor.entitlements"


def _host_build(real):
    def build(*args, **kwargs):
        target = _cargo_build.DEFAULT_TARGET
        _cargo_build.DEFAULT_TARGET = HOST_TARGET
        try:
            out = real(*args, **kwargs)
        finally:
            _cargo_build.DEFAULT_TARGET = target
        _utils.check_output(f"codesign --force --sign - --entitlements {ENTITLEMENTS} "
                            f"{pathlib.Path(out) / 'firecracker'}")
        return out
    return build


_cargo_build.build_fuzzing = _host_build(_cargo_build.build_fuzzing)
_cargo_build.build_gdb = _host_build(_cargo_build.build_gdb)

_real_cargo = _cargo_build.cargo
LINUX_HOST_TARGET = re.compile(r"--target\s+(\S+)-unknown-linux-musl\b")


def cargo(subcommand, cargo_args="", subcommand_args="", **kwargs):
    """`cargo_build.cargo`; a build for the host's musl target (as
    test_instrumented_firecracker.py asks for one) is a build for the host's
    target here, signed as tools/macos/integration-tests.sh signs Firecracker,
    and found where the test looks: `<target dir>/<arch>-unknown-linux-musl`
    names the host target's directory."""
    m = LINUX_HOST_TARGET.search(cargo_args)
    if subcommand != "build" or not m:
        return _real_cargo(subcommand, cargo_args, subcommand_args, **kwargs)
    out = _real_cargo(subcommand, LINUX_HOST_TARGET.sub(f"--target {HOST_TARGET}", cargo_args),
                      subcommand_args, **kwargs)
    env = kwargs.get("env") or {}
    target_dir = pathlib.Path(kwargs.get("cwd") or ".") / env.get(
        "CARGO_TARGET_DIR", os.environ.get("CARGO_TARGET_DIR", "target"))
    linux = target_dir / f"{m.group(1)}-unknown-linux-musl"
    if not linux.exists():
        linux.symlink_to(HOST_TARGET)
    profile = "release" if "--release" in cargo_args else "debug"
    fc = target_dir / HOST_TARGET / profile / "firecracker"
    if fc.exists():
        _utils.check_output(f"codesign --force --sign - --entitlements {ENTITLEMENTS} {fc}")
    return out


_cargo_build.cargo = cargo

# ------------------------------------------------------- process memory

_libsystem._dyld_get_shared_cache_range.restype = ctypes.c_void_p
_libsystem._dyld_get_shared_cache_range.argtypes = [ctypes.POINTER(ctypes.c_size_t)]
PROC_PIDREGIONPATHINFO = 8


class _RegionInfo(ctypes.Structure):
    """<sys/proc_info.h> struct proc_regioninfo."""

    _fields_ = [
        ("protection", ctypes.c_uint32), ("max_protection", ctypes.c_uint32),
        ("inheritance", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("offset", ctypes.c_uint64), ("behavior", ctypes.c_uint32),
        ("user_wired_count", ctypes.c_uint32), ("user_tag", ctypes.c_uint32),
        ("pages_resident", ctypes.c_uint32), ("pages_shared_now_private", ctypes.c_uint32),
        ("pages_swapped_out", ctypes.c_uint32), ("pages_dirtied", ctypes.c_uint32),
        ("ref_count", ctypes.c_uint32), ("shadow_depth", ctypes.c_uint32),
        ("share_mode", ctypes.c_uint32), ("private_pages_resident", ctypes.c_uint32),
        ("shared_pages_resident", ctypes.c_uint32), ("obj_id", ctypes.c_uint32),
        ("depth", ctypes.c_uint32), ("address", ctypes.c_uint64), ("size", ctypes.c_uint64),
    ]


class _RegionPathInfo(ctypes.Structure):
    """<sys/proc_info.h> struct proc_regionwithpathinfo."""

    _fields_ = [("info", _RegionInfo), ("vnode_info", ctypes.c_char * 152),
                ("path", ctypes.c_char * 1024)]


class _MemoryMap:
    """What psutil's memory_maps(grouped=False) gives on Linux, for one mapping."""

    def __init__(self, path, addr, size, rss):
        self.path, self.addr, self.size, self.rss = path, addr, size, rss


def _shared_cache():
    length = ctypes.c_size_t()
    base = _libsystem._dyld_get_shared_cache_range(ctypes.byref(length))
    return (base or 0), (base or 0) + length.value


def memory_maps(self, grouped=True):
    """psutil's `Process.memory_maps` on macOS (psutil has it on Linux only).

    Linux: /proc/<pid>/smaps, one entry per mapping with its resident size.
    macOS: the process's regions from proc_pidinfo(PROC_PIDREGIONPATHINFO).
    The dyld shared cache is left out: every process on macOS maps the
    system libraries from it and shares their pages (upstream's Firecracker is
    a static binary on Linux, so it has no such mapping). XNU splits a large
    mapping of memory into regions of at most 128 MiB (ANON_CHUNK_SIZE);
    adjacent regions alike in everything but their object are one mapping
    here, as Linux merges such areas into one.
    """
    if grouped:
        raise NotImplementedError("grouped memory maps")
    page = os.sysconf("SC_PAGE_SIZE")
    lo, hi = _shared_cache()
    maps, addr, last = [], 0, None
    while True:
        info = _RegionPathInfo()
        n = _libsystem.proc_pidinfo(self.pid, PROC_PIDREGIONPATHINFO, ctypes.c_uint64(addr),
                                    ctypes.byref(info), ctypes.sizeof(info))
        if n <= 0:
            err = ctypes.get_errno()
            if err == errno.ESRCH:
                raise psutil.NoSuchProcess(self.pid)
            break
        r = info.info
        addr = r.address + r.size
        if lo <= r.address < hi:
            continue
        path = info.path.decode(errors="replace")
        kind = (r.protection, r.max_protection, r.share_mode, r.user_tag, path)
        if last and last[0] == kind and maps[-1].addr + maps[-1].size == r.address:
            maps[-1].size += r.size
            maps[-1].rss += r.pages_resident * page
            continue
        maps.append(_MemoryMap(path, r.address, r.size, r.pages_resident * page))
        last = (kind,)
    if not maps and not psutil.pid_exists(self.pid):
        raise psutil.NoSuchProcess(self.pid)
    return maps


import psutil  # noqa: E402  pylint: disable=wrong-import-position

psutil.Process.memory_maps = memory_maps


def prlimit(pid, which, limits=None):
    """`resource.prlimit` (Linux only): macOS has no interface to read or
    set another process's resource limits; a process sets only its own."""
    raise OSError(errno.ENOSYS, f"prlimit({pid}, {which}, {limits}): macOS has no prlimit; "
                  "only a process itself reads or sets its resource limits")


import resource  # noqa: E402  pylint: disable=wrong-import-position

if not hasattr(resource, "prlimit"):
    resource.prlimit = prlimit


def get_resident_memory(process):
    """`framework.utils.get_resident_memory` (KiB) on macOS: what the balloon
    tests read through `get_stable_rss_mem` (test_balloon.py, the performance
    balloon and memory hot-plug tests, test_snapshot_restore_cross_kernel).

    Linux (tests/framework/utils.py): `psutil.Process.memory_info().rss`,
    which is VmRSS from /proc/<pid>/statm (RssAnon + RssFile + RssShmem:
    every page present in the process's page tables, anonymous or file-backed
    or shared, the static binary's own text among them, and the guest pages
    KVM faulted in with get_user_pages; not pages swapped out, not the pages
    of a mapped file the process has not touched), plus `HugetlbPages:` of
    /proc/<pid>/status, which VmRSS leaves out.

    macOS: the task's resident_size, which is what psutil's RSS reads: the
    pages present in the process's page tables, the pages a vCPU wrote
    through Hypervisor.framework among them (measured on a 256 MiB guest:
    62,112 KiB idle, 217,664 after the guest wrote 150 MiB, as its regions'
    resident pages went 36,880 to 192,272). Hugetlb: none on macOS, a huge
    page mapping is host pages (docs/PORTING.md row 10), present like the
    rest. Its one difference from Linux's is a fixed offset: the pages of
    the dyld shared cache the process touched, 19 MiB here (RSS 62,112 KiB
    against 43,136 of resident pages in the other regions), the system
    libraries where upstream's static Firecracker on Linux carries 1.6 MiB of
    its own text.

    Not the resident pages of the regions `memory_maps` reads (c8d26ac):
    pages_resident is the mapped object's residency, not the page tables',
    so a mapped file counts whole once it is in the buffer cache: after a
    restore from a snapshot file the 256 MiB guest reads 267,792 KiB whether
    the guest has touched a page or not, and test_balloon_snapshot's reading
    cannot rise when the guest dirties 60 MiB (measured: `assert 267792 >
    267792`), where Linux's rises with every page faulted in. Not
    phys_footprint (56,592 KiB idle): it leaves out the clean file-backed
    pages VmRSS counts (4,400 KiB: the binary's text, the kernel image) and
    counts what VmRSS does not (compressed pages, the kernel's page-table
    and IOKit ledgers). Measured side by side, idle / after the guest wrote
    150 MiB / after a full snapshot: RSS 62,112 / 217,664 / 461,936 KiB; the
    regions' resident pages without the shared cache 43,136 / 198,528 /
    268,688; phys_footprint 56,592 / 212,208 / 456,193. (After the full
    snapshot every guest page is present: the snapshot read the pages the
    guest never touched, and macOS gives real zero pages where Linux reads
    its shared zero page uncharged, as docs/PORTING.md row 15 notes for
    Windows.)"""
    return process.memory_info().rss // 1024


_utils.get_resident_memory = get_resident_memory

import framework.kvm as _kvm  # noqa: E402  pylint: disable=wrong-import-position

# The "kvm" backend of upstream's framework is Firecracker's KVM API, which
# wick provides on Hypervisor.framework (crates/compat/kvm-ioctls).
_kvm.has_kvm = hvf_available
_kvm.kvm_probe_details = lambda: {"hypervisor": "Hypervisor.framework", "kern.hv_support": hvf_available()}

import framework.jailer as _jailer  # noqa: E402  pylint: disable=wrong-import-position
import framework.microvm as _microvm  # noqa: E402  pylint: disable=wrong-import-position
import framework.http_api as _http_api  # noqa: E402  pylint: disable=wrong-import-position
import host_tools.network as _network  # noqa: E402  pylint: disable=wrong-import-position

from wick_macos_net import NetNs, Tap  # noqa: E402  pylint: disable=wrong-import-position

def _remove_tree(path):
    """shutil.rmtree, also through what a test left without its owner's
    permissions (test_negative_snapshot_permissions makes a jail read-only
    and, when it fails, leaves it so)."""
    def again(func, failed, _exc):
        parent = os.path.dirname(failed)
        for p in (parent, failed):
            with contextlib.suppress(OSError):
                os.chmod(p, 0o700, follow_symlinks=False)
        func(failed)
    shutil.rmtree(path, onexc=again)


def remove_jails(factory):
    """`MicroVMFactory.kill`, removing every microVM's jail even when killing
    one fails. Upstream removes a jail after its microVM's kill returns; a
    kill that raises (the memory monitor's MemoryUsageExceededError is raised
    there) leaves that jail and every later one, with the microVMs' memory,
    snapshots and disk copies, until the session ends: a session's runs
    filled the disk that way. Each microVM is killed and its jail removed
    as upstream does; the first error is raised after all of them."""
    first = None
    for vm in list(factory.vms):
        try:
            vm.kill()
        except Exception as err:  # pylint: disable=broad-exception-caught
            first = first or err
        for step in (vm.jailer.cleanup,
                     lambda vm=vm: vm.jailer.jailer_id and vm.jailer.chroot_base_with_id().exists()
                     and _remove_tree(vm.jailer.chroot_base_with_id()),
                     vm.netns.cleanup):
            try:
                step()
            except Exception as err:  # pylint: disable=broad-exception-caught
                first = first or err
    factory.vms.clear()
    if first is not None:
        raise first


_microvm.MicroVMFactory.kill = remove_jails

# Linux: `ip netns`, a network namespace with TAP devices in it. macOS:
# a network, a directory of endpoints (tools/macos/integration/wick_macos_net.py).
_network.NetNs = NetNs
_network.Tap = Tap

# ------------------------------------------------------------ user mode


if RUNS_AS_USER:
    import framework.utils_drive as _utils_drive  # noqa: E402  pylint: disable=wrong-import-position

    @contextlib.contextmanager
    def _jail_user_is_session_user():
        """No chown to the jail's user: the user who runs the session is the
        jail's user here."""
        real_chown = os.chown
        os.chown = lambda path, uid, gid: None
        try:
            yield
        finally:
            os.chown = real_chown

    _real_jailed_path = _jailer.JailerContext.jailed_path

    def jailed_path(self, file_path, create=False, subdir="."):
        """`JailerContext.jailed_path` without the chown to the jail's user;
        everything else is upstream's."""
        with _jail_user_is_session_user():
            return _real_jailed_path(self, file_path, create, subdir)

    _jailer.JailerContext.jailed_path = jailed_path

    _real_backend_spawn = _utils_drive.VhostUserBlkBackend.spawn

    def backend_spawn(self, uid, gid):
        """`VhostUserBlkBackend.spawn` without the chown of its socket to the
        jail's user; everything else is upstream's."""
        with _jail_user_is_session_user():
            return _real_backend_spawn(self, uid, gid)

    _utils_drive.VhostUserBlkBackend.spawn = backend_spawn

    # Paths in API requests are the jail's: absolute ones start at the jail's
    # root, as Firecracker sees them after chroot. Without a chroot they are
    # given to Firecracker relative to its working directory, which the
    # stand-in makes the jail's directory (JAIL_RELATIVE, `.//<path>`), and
    # taken back to the jail's form in what Firecracker sends back
    # (configurations, error messages). Relative, they resolve as the chroot
    # resolves them: a snapshot keeps the paths of its devices, and a microVM
    # restored in another jail opens them in its own jail, not in the jail the
    # snapshot was taken in (which an absolute host path would name).
    PATH_FIELDS = {
        "kernel_image_path", "initrd_path", "path_on_host", "socket", "uds_path",
        "log_path", "metrics_path", "snapshot_path", "mem_file_path", "backend_path",
        "serial_out_path",
    }
    JAIL_RELATIVE = ".//"
    # A path given as JAIL_RELATIVE, where it starts in a text.
    _JAIL_RELATIVE_IN_TEXT = re.compile(r"(?:^|(?<=[\s'\"(\[=:,]))\.//")

    def _chroot_of(api):
        m = re.match(r"^(.*/jailer/[^/]+/[^/]+/root)/", api.socket)
        if not m:
            raise AssertionError(f"API socket {api.socket} is not in a jail directory")
        return m.group(1)

    def _to_host(value, key=None):
        if isinstance(value, dict):
            return {k: _to_host(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [_to_host(v, key) for v in value]
        if key in PATH_FIELDS and isinstance(value, str) and value.startswith("/"):
            return JAIL_RELATIVE + value.lstrip("/")
        return value

    def _to_jail(value, root):
        if isinstance(value, dict):
            return {k: _to_jail(v, root) for k, v in value.items()}
        if isinstance(value, list):
            return [_to_jail(v, root) for v in value]
        if isinstance(value, str):
            value = value.replace(root + "/", "/").replace(root, "/")
            return _JAIL_RELATIVE_IN_TEXT.sub("/", value)
        return value

    class _JailView:
        """A response whose body shows the jail's paths."""

        def __init__(self, res, root):
            self._res = res
            self._root = root

        def __getattr__(self, name):
            return getattr(self._res, name)

        def json(self, **kwargs):
            return _to_jail(self._res.json(**kwargs), self._root)

        @property
        def content(self):
            return _to_jail(self._res.content.decode(errors="surrogateescape"), self._root).encode(
                errors="surrogateescape")

        @property
        def text(self):
            return _to_jail(self._res.text, self._root)

    _real_request = _http_api.Resource.request
    _real_get = _http_api.Resource.get

    def request(self, method, path, **kwargs):
        root = _chroot_of(self._api)
        try:
            res = _real_request(self, method, path, **_to_host(kwargs))
        except RuntimeError as err:
            raise RuntimeError(*(_to_jail(a, root) if isinstance(a, str) else a for a in err.args)) from None
        return _JailView(res, root)

    def get(self):
        return _JailView(_real_get(self), _chroot_of(self._api))

    _http_api.Resource.request = request
    _http_api.Resource.get = get

    import framework.utils_uffd as _utils_uffd  # noqa: E402  pylint: disable=wrong-import-position

    def uffd_spawn(self, uid, gid):
        """`UffdHandler.spawn` without the chroot (root's): the handler runs
        in the jail's directory, as the stand-in runs Firecracker, and the
        paths it is given as the jail's (`/<name>`) are given relative to it
        (JAIL_RELATIVE), where Firecracker's own `/firecracker-uffd.sock`
        resolves. Upstream's chroot would leave the worker's root and working
        directory changed when it is refused."""
        del uid, gid  # the jail's user is the session's user
        root = pathlib.Path(self._chroot)  # pylint: disable=protected-access
        handler = root / self._handler_name  # pylint: disable=protected-access
        handler.chmod(handler.stat().st_mode | 0o111)
        log = root / self._log_file  # pylint: disable=protected-access
        with open(log, "w", encoding="utf-8") as logfile:
            # The handler's own path is the host's: the session's cleanup
            # finds what it started by its root in the command line.
            self._proc = subprocess.Popen(  # pylint: disable=protected-access,consider-using-with
                [str(handler), JAIL_RELATIVE + self.socket_path.lstrip("/"), self.snapshot.mem.name],
                stdout=logfile,
                stderr=subprocess.STDOUT,
                cwd=root,
            )
        # As upstream: time to start, or to fail.
        time.sleep(1)
        if not self.is_running():
            print(log.read_text(encoding="utf-8"))
            assert False, "Could not start PF handler!"

    _utils_uffd.UffdHandler.spawn = uffd_spawn

# ------------------------------------------------- files Firecracker maps

# Upstream's memory monitor counts the pages each mapping has resident: on
# Linux, the pages Firecracker mapped. For a file, an observer on macOS sees
# the file's pages in the buffer cache, all of them for a file the test has
# just written. A pmem backing file, the one file Firecracker maps besides its
# binary (tools/macos/integration-tests.sh), is rewritten in place without
# caching before Firecracker is given it, so its resident pages are those its
# guest touches. Its contents and inode stay the same.
F_NOCACHE = 48


def evict_cached_pages(path):
    """Drops `path`'s pages from the buffer cache (an in-place rewrite
    through F_NOCACHE)."""
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.fcntl(fd, F_NOCACHE, 1)
        size, off = os.fstat(fd).st_size, 0
        while off < size:
            chunk = os.pread(fd, 1 << 20, off)
            if not chunk:
                break
            os.pwrite(fd, chunk, off)
            off += len(chunk)
        os.fsync(fd)
    finally:
        os.close(fd)


_request_mapping_files = _http_api.Resource.request


def request_mapping_files(self, method, path, **kwargs):
    """Resource.request, with a pmem backing file out of the buffer cache."""
    backing = kwargs.get("path_on_host")
    if self.resource == "/pmem" and method.upper() == "PUT" and isinstance(backing, str):
        m = re.match(r"^(.*/jailer/[^/]+/[^/]+/root)/", self._api.socket)
        host = m.group(1) + backing if m and backing.startswith("/") else backing
        if os.path.isfile(host):
            evict_cached_pages(host)
    return _request_mapping_files(self, method, path, **kwargs)


_http_api.Resource.request = request_mapping_files


def rss_anon_kib(pid):
    """`RssAnon:` of /proc/<pid>/status (KiB) on macOS: what test_pmem's
    `outside_rssanon` reads with `cat /proc/<pid>/status`.

    Linux: the resident pages of the process's anonymous mappings (private
    or shared anonymous memory; guest memory not backed by a file is one).
    macOS: the resident pages of the regions that map no file (no vnode
    path in proc_pidinfo(PROC_PIDREGIONPATHINFO)), without the dyld shared
    cache, as `memory_maps` reads them. For an anonymous region the object's
    resident pages are the process's (a mapped file's are the buffer
    cache's, which is why `get_resident_memory` does not use this)."""
    return sum(m.rss for m in memory_maps(psutil.Process(pid), grouped=False) if not m.path) // 1024


def _outside_rssanon(vm):
    return rss_anon_kib(vm.firecracker_pid)


# ------------------------------------------------------ a small tmpfs

RAM_DISK_MIB = 512


def _run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120).stdout


@contextlib.contextmanager
def small_tmpfs(worker_id, mib=RAM_DISK_MIB):
    """`mount -o size=512M -t tmpfs none /mnt/<worker>`, as
    test_snapshot_not_losing_dirty_pages.py's mount_tmpfs_small makes it.

    macOS has no tmpfs, and its root is the sealed, read-only system volume
    (no /mnt). Its counterpart, without root: a RAM disk (`hdiutil attach
    -nomount ram://<sectors>`: memory, given back when it is detached, as a
    tmpfs's), erased as an APFS volume (`diskutil erasevolume`: sparse files,
    as tmpfs has, where HFS+ allocates every block up to a write's offset)
    and mounted on a directory of the session (`diskutil mount -mountPoint`).
    All three work as the user (measured: the disk's device nodes are the
    user's, the volume is "mounted by" the user). A user's APFS volume
    ignores ownership (noowners); as root (the jailer's mode, which chowns
    the jail to its user) ownership is enabled, as on tmpfs. Its free space
    is APFS's: some of the 512 MiB holds the container's own metadata."""
    num = re.sub(r"\D", "", str(worker_id)) or "0"
    mnt = pathlib.Path(SESSION_ROOT) / f"t{num}"
    # Unique among the session's and any other session's volumes.
    name = f"{pathlib.Path(SESSION_ROOT).name}-t{num}"
    mnt.mkdir(parents=True)
    disk = _run("hdiutil", "attach", "-nomount", f"ram://{mib * 2048}").split()[0]
    # Recorded for the session's end (tools/macos/integration-tests.sh),
    # which detaches what a killed test left attached.
    record = pathlib.Path(SESSION_ROOT) / ".attached" / disk.removeprefix("/dev/")
    record.parent.mkdir(exist_ok=True)
    record.touch()
    try:
        _run("diskutil", "erasevolume", "APFS", name, disk)
        info = _run("diskutil", "info", f"/Volumes/{name}")
        volume = re.search(r"Device Node:\s*(\S+)", info).group(1)
        _run("diskutil", "unmount", volume)
        _run("diskutil", "mount", "-mountPoint", str(mnt), volume)
        if os.geteuid() == 0:
            _run("diskutil", "enableOwnership", str(mnt))
        yield mnt
    finally:
        # Detached whatever happened above; a disk that will not detach
        # stays recorded, for the session's end, and fails the test here.
        detach = subprocess.run(["hdiutil", "detach", "-force", disk], check=False,
                                capture_output=True, text=True, timeout=120)
        with contextlib.suppress(OSError):
            mnt.rmdir()
        if detach.returncode != 0:
            raise OSError(errno.EBUSY, f"RAM disk {disk} did not detach: {detach.stderr.strip()}")
        record.unlink()


def _mount_tmpfs_small(worker_id):
    """mount_tmpfs_small (test_snapshot_not_losing_dirty_pages.py) on macOS."""
    with small_tmpfs(worker_id) as mnt:
        yield mnt


def pytest_pycollect_makemodule(module_path, parent):  # pylint: disable=unused-argument
    """test_snapshot_not_losing_dirty_pages.py's mount_tmpfs_small fixture
    mounts a tmpfs at /mnt/<worker>: here it is `small_tmpfs`. The module's
    fixture is replaced before pytest reads the module's fixtures."""
    if module_path.name != "test_snapshot_not_losing_dirty_pages.py":
        return None
    import pytest  # pylint: disable=import-outside-toplevel
    mod = pytest.Module.from_parent(parent, path=module_path)
    assert hasattr(mod.obj, "mount_tmpfs_small"), "upstream's mount_tmpfs_small is gone"
    mod.obj.mount_tmpfs_small = pytest.fixture(name="mount_tmpfs_small")(_mount_tmpfs_small)
    return mod


def pytest_runtest_setup(item):
    """test_pmem reads RssAnon from /proc, which macOS does not have: its
    helper reads it as `rss_anon_kib` does. A test of NOISE_ONLY_PINNING
    runs unpinned (`set_cpu_affinity`)."""
    global _unpinned_test  # pylint: disable=global-statement
    _unpinned_test = item if item.nodeid.split("[", 1)[0] in NOISE_ONLY_PINNING else None
    module = getattr(item, "module", None)
    if module is not None and module.__name__.endswith("test_pmem") and hasattr(module, "outside_rssanon"):
        module.outside_rssanon = _outside_rssanon


def pytest_report_header():
    """What runs where."""
    return [
        f"wick macOS host: mode {MODE}, session root {SESSION_ROOT}, "
        f"macOS {platform.mac_ver()[0]}, Hypervisor.framework {'yes' if hvf_available() else 'no'}"
    ]
