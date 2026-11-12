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
import threading
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
        self.tag, self.shared_cache, self.writable = 0, False, False
        # Bytes of the region's pages compressed or swapped out, and its
        # share mode (<mach/vm_region.h> SM_*): what a diagnostic run logs
        # (WICK_IT_DIAG_MEMORY).
        self.swapped, self.share_mode = 0, 0


def _shared_cache():
    length = ctypes.c_size_t()
    base = _libsystem._dyld_get_shared_cache_range(ctypes.byref(length))
    return (base or 0), (base or 0) + length.value


# A process's regions as this process reads them with proc_pidinfo: by
# default each region's resident pages are its object's (XNU
# osfmk/vm/vm_map.c vm_map_region_look_for_page: vm_page_lookup in the
# object), so a mapped file counts its pages in the buffer cache, whoever
# read them. With vm.self_region_footprint set, which a process sets for
# itself (bsd/vm/vm_unix.c sysctl_vm_self_region_footprint, CTLFLAG_ANYBODY;
# osfmk/kern/task.c task_self_region_footprint reads the caller's flag, and
# a new task starts without it), vm_map_region_walk asks the target's pmap
# for each page instead (vm_map_footprint_query_page_info_exclusive ->
# pmap_query_page_info): a page counts when the process has it mapped, as
# Linux's smaps Rss counts present page-table entries (fs/proc/task_mmu.c
# smaps_pte_entry). Measured, as the user, on another process: a 4 MiB
# file in the cache with 2 pages touched, 4096 KiB by default and 32 KiB
# with the flag; an idle Firecracker run from a binary all in the cache,
# its binary's mappings 3.84 MiB by default and 0.92 MiB with the flag.
VM_SELF_REGION_FOOTPRINT = b"vm.self_region_footprint"
# The region the footprint mode adds after the last one (bsd_vm.c
# fill_procregioninfo): the purgeable and ledger-tagged memory the task
# owns, mapped or not, whose mapped pages its regions report already.
# Linux has no such mapping.
_FOOTPRINT_REGION_TAG = 0xFFFFFFFF


def _set_self_region_footprint(value=1):
    want, now, size = ctypes.c_int(value), ctypes.c_int(-1), ctypes.c_size_t(ctypes.sizeof(ctypes.c_int))
    if _libsystem.sysctlbyname(VM_SELF_REGION_FOOTPRINT, None, None, ctypes.byref(want), ctypes.sizeof(want)):
        raise OSError(ctypes.get_errno(), f"sysctl {VM_SELF_REGION_FOOTPRINT.decode()}={value}")
    if _libsystem.sysctlbyname(VM_SELF_REGION_FOOTPRINT, ctypes.byref(now), ctypes.byref(size), None, 0) \
            or now.value != value:
        raise OSError(errno.EINVAL, f"sysctl {VM_SELF_REGION_FOOTPRINT.decode()} did not take {value}")


_set_self_region_footprint()
# The mode is the process's: region_breakdown leaves it for one read.
_FOOTPRINT_LOCK = threading.Lock()


def memory_maps(self, grouped=True):
    """psutil's `Process.memory_maps` on macOS (psutil has it on Linux only).

    Linux: /proc/<pid>/smaps, one entry per mapping with its resident size
    (Rss: the pages present in the process's page tables).
    macOS: the process's regions from proc_pidinfo(PROC_PIDREGIONPATHINFO),
    in the footprint mode (VM_SELF_REGION_FOOTPRINT above): the pages the
    process has mapped. The footprint mode's region of owned memory is left
    out (_FOOTPRINT_REGION_TAG).
    The dyld shared cache's entries are in, marked `shared_cache`: the
    system libraries every macOS process runs (no static binaries: Apple
    QA1118), whose pages count as those of any other mapping, by this
    process's page tables. Measured on an idle Firecracker: 4.48 MiB there,
    unchanged when other processes ran library code Firecracker never runs,
    so the count is the process's own, as Linux's Rss of a dynamically linked
    process counts its libraries' pages; task RSS (the phys_mem ledger) is
    the sum, 6.89 MiB against 2.27 + 4.48. Upstream's Firecracker is a static
    binary on Linux, its libc inside its own text. XNU splits a large
    mapping of memory into regions of at most 128 MiB (ANON_CHUNK_SIZE);
    adjacent regions alike in everything but their object are one mapping
    here, as Linux merges such areas into one.
    """
    if grouped:
        raise NotImplementedError("grouped memory maps")
    with _FOOTPRINT_LOCK:
        return _memory_maps(self)


def _memory_maps(self):
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
        if r.user_tag == _FOOTPRINT_REGION_TAG:
            continue
        in_cache = lo <= r.address < hi
        path = info.path.decode(errors="replace")
        kind = (r.protection, r.max_protection, r.share_mode, r.user_tag, path, in_cache)
        if last and last[0] == kind and maps[-1].addr + maps[-1].size == r.address:
            maps[-1].size += r.size
            maps[-1].rss += r.pages_resident * page
            maps[-1].swapped += r.pages_swapped_out * page
            continue
        maps.append(_MemoryMap(path, r.address, r.size, r.pages_resident * page))
        maps[-1].tag, maps[-1].shared_cache = r.user_tag, in_cache
        maps[-1].swapped, maps[-1].share_mode = r.pages_swapped_out * page, r.share_mode
        maps[-1].writable = bool(r.protection & 2)  # VM_PROT_WRITE
        last = (kind,)
    if not maps and not psutil.pid_exists(self.pid):
        raise psutil.NoSuchProcess(self.pid)
    _LAST_SHARED_CACHE_RSS[0] = sum(m.rss for m in maps if m.shared_cache)
    return maps


# The shared cache's part of the last `memory_maps`, for
# test_memory_overhead's metrics (pytest_runtest_call).
_LAST_SHARED_CACHE_RSS = [None]


import psutil  # noqa: E402  pylint: disable=wrong-import-position

psutil.Process.memory_maps = memory_maps


def region_breakdown(pid, skip=lambda m: False):
    """[(name, KiB mapped, KiB present in the page tables, KiB resident in
    the object)] of `pid`'s regions but those `skip` names, largest first:
    what the memory monitor counted, and what proc_pidinfo's default mode
    would have, to name what holds the memory when the monitor trips. A
    region is named by its file, or by its VM tag (<mach/vm_statistics.h>
    VM_MEMORY_*: 1 malloc, 2 malloc small, 3 malloc large, 7 malloc tiny,
    11 malloc nano, 30 stack)."""
    with _FOOTPRINT_LOCK:
        mapped = _memory_maps(psutil.Process(pid))
        _set_self_region_footprint(0)
        try:
            cached = _memory_maps(psutil.Process(pid))
        finally:
            _set_self_region_footprint(1)
    rows = defaultdict(lambda: [0, 0, 0])
    for maps, col in ((mapped, 1), (cached, 2)):
        for m in maps:
            if skip(m):
                continue
            name = os.path.basename(m.path) if m.path else f"tag {m.tag}"
            if m.shared_cache:
                name = "shared cache " + name
            if col == 1:
                rows[name][0] += m.size
            rows[name][col] += m.rss
    return sorted(((k, v[0] >> 10, v[1] >> 10, v[2] >> 10) for k, v in rows.items()),
                  key=lambda r: -r[2])


import host_tools.memory as _memory  # noqa: E402  pylint: disable=wrong-import-position

# Upstream's monitor holds the VMM's resident memory besides the guest to
# 5 MiB (7 while a snapshot is taken), measured on a static binary. On macOS
# that memory has two parts:
# - the VMM's own: its binary, its heap, its stacks, every mapping outside the
#   dyld shared cache. The budget applies to this part, as upstream's does.
# - the platform's: the system libraries' pages it mapped from the dyld
#   shared cache, which a macOS process cannot do without (QA1118) and a
#   static Linux binary carries inside its own text. This part is held to
#   SHARED_CACHE_CEILING, so that it is bounded and a rise shows, and
#   reported beside the other (memory-parts.jsonl in the run's directory,
#   one line per microVM).
# The ceiling: measured on macOS 27.2 (m2-parts, 77 microVMs of the
# balloon, vsock, snapshot and CPU tests), the part is 4.64 MiB in every
# microVM with a guest (4.48 idle, without one); the ceiling is that
# maximum plus 0.36 MiB, 5 MiB. The part is flat to the KiB, so more
# system-library code or data mapped (a framework newly linked, a library
# path newly run) shows past 0.36 MiB. Another macOS major lays out its
# shared cache differently, so the ceiling is per major, and a major not
# measured fails every monitored test, saying so, rather than take another
# major's number (WICK_IT_SHARED_CACHE_CEILING_MIB sets one for a measuring
# run; memory-parts.jsonl has the parts).
SHARED_CACHE_CEILING_MIB = {27: 5.0}  # macOS major: MiB (27: measured on 27.2, m2-parts)
MACOS_MAJOR = int(platform.mac_ver()[0].split(".")[0])
if "WICK_IT_SHARED_CACHE_CEILING_MIB" in os.environ:
    SHARED_CACHE_CEILING = float(os.environ["WICK_IT_SHARED_CACHE_CEILING_MIB"]) * (1 << 20)
elif MACOS_MAJOR in SHARED_CACHE_CEILING_MIB:
    SHARED_CACHE_CEILING = SHARED_CACHE_CEILING_MIB[MACOS_MAJOR] * (1 << 20)
else:
    SHARED_CACHE_CEILING = None  # not measured on this macOS: check_samples fails
_MEMORY_PARTS = pathlib.Path(os.environ.get("WICK_IT_BINARY_DIR", SESSION_ROOT)).parent / "memory-parts.jsonl"

# A diagnostic run: one with any of these switches on, which
# integration-tests.sh passes on and names in provenance.txt
# ("DIAGNOSTIC RUN"), and which compare-integration-tests.py then reports as
# no result. What a switch adds is to read, never to count: its runs feed
# no excused count and no "passes" in the docs.
# - WICK_IT_DIAG_MEMORY: each reading get_stable_rss_mem takes logs its parts
#   to memory-diag.jsonl (diag_get_resident_memory), and each stable reading
#   the guest's view (diag_get_stable_rss_mem).
# - WICK_IT_DEFER_MEMORY_ERROR: the memory monitor's error at a kill inside a
#   test (upstream raises it there, microvm.py kill -> check_samples, and the
#   test's later steps do not run) is held to the test's end and raised
#   then, the same error, so the test still fails; the steps after the kill
#   run, and memory-diag.jsonl records how they ended.
DIAGNOSTIC_SWITCHES = ("WICK_IT_DIAG_MEMORY", "WICK_IT_DEFER_MEMORY_ERROR")
DIAGNOSTIC = [s for s in DIAGNOSTIC_SWITCHES if os.environ.get(s, "") not in ("", "0")]
_MEMORY_DIAG = _MEMORY_PARTS.with_name("memory-diag.jsonl")
# While a test's call runs with WICK_IT_DEFER_MEMORY_ERROR: the errors held.
_DEFERRED = {"active": False, "errors": []}


def monitor_run(self):
    """MemoryMonitor.run (host_tools/memory.py) with the VMM's memory in its
    two parts: upstream's loop, whose sum is the part outside the shared
    cache, with the shared cache's part held to SHARED_CACHE_CEILING. When
    it stops on a sample over a limit, the process's regions as they are
    then (region_breakdown), for check_samples to log."""
    # pylint: disable=protected-access
    guest = self._vm.mem_size_bytes
    self.wick_breakdown = None
    self.wick_peak = {"own": 0, "shared_cache": 0}
    try:
        ps = psutil.Process(self._vm.firecracker_pid)
    except (psutil.NoSuchProcess, FileNotFoundError):
        return
    while not self._should_stop:
        try:
            mmaps = ps.memory_maps(grouped=False)
        except psutil.NoSuchProcess:
            return
        own = cache = 0
        for m in mmaps:
            # Upstream skips a mapping by its size as guest memory; the
            # shared cache's are never guest memory, and some are larger.
            if m.shared_cache:
                cache += m.rss
            elif "nitro_enclaves" not in m.path and not self.is_guest_mem(m.size, guest):
                own += m.rss
        self._current_rss = own
        self.wick_shared_cache_rss = cache
        self.wick_peak = {"own": max(own, self.wick_peak["own"]),
                          "shared_cache": max(cache, self.wick_peak["shared_cache"])}
        if own > self.threshold or (SHARED_CACHE_CEILING is not None and cache > SHARED_CACHE_CEILING):
            self._exceeded = ps
            with contextlib.suppress(psutil.NoSuchProcess, ProcessLookupError):
                self.wick_breakdown = region_breakdown(
                    ps.pid, skip=lambda m: not m.shared_cache and self.is_guest_mem(m.size, guest))
            return
        time.sleep(self._period_s)


def check_samples(self):
    """MemoryMonitor.check_samples, with the two parts' peaks recorded and,
    when it raises, the regions logged."""
    # pylint: disable=protected-access
    import json as _json  # pylint: disable=import-outside-toplevel
    import logging  # pylint: disable=import-outside-toplevel
    if SHARED_CACHE_CEILING is None:
        raise RuntimeError(
            f"memory monitor: the shared cache's ceiling is not measured on this macOS ({MACOS_MAJOR}); "
            f"measured on {sorted(SHARED_CACHE_CEILING_MIB)}. Measure it (memory-parts.jsonl, "
            "WICK_IT_SHARED_CACHE_CEILING_MIB) and add it to wick_macos.SHARED_CACHE_CEILING_MIB")
    peak = getattr(self, "wick_peak", None)
    if peak is not None:
        with contextlib.suppress(OSError), open(_MEMORY_PARTS, "a", encoding="utf-8") as f:
            f.write(_json.dumps({"test": os.environ.get("PYTEST_CURRENT_TEST", "").split(" ")[0],
                                 "pid": self._vm.firecracker_pid, "own_mib": round(peak["own"] / 2**20, 2),
                                 "shared_cache_mib": round(peak["shared_cache"] / 2**20, 2),
                                 "exceeded": self._exceeded is not None,
                                 **({"diagnostic": DIAGNOSTIC} if DIAGNOSTIC else {})}) + "\n")
    if self._exceeded is not None:
        log = logging.getLogger("wick_macos")
        cache = getattr(self, "wick_shared_cache_rss", 0)
        if cache > SHARED_CACHE_CEILING:
            log.warning("memory monitor: the shared cache's part %.2f MiB is over its ceiling %.2f MiB "
                        "for macOS %d (memory-parts.jsonl has the parts of every microVM)",
                        cache / 2**20, SHARED_CACHE_CEILING / 2**20, MACOS_MAJOR)
        rows = getattr(self, "wick_breakdown", None)
        if rows is None:
            log.warning("memory monitor tripped at %.2f MiB; the process was gone before its regions were read",
                        self._current_rss / (1 << 20))
        else:
            log.warning("memory monitor tripped at %.2f MiB of the VMM's own, %.2f MiB of the shared cache "
                        "(KiB: mapped, in the page tables, resident in the object): %s",
                        self._current_rss / (1 << 20), cache / (1 << 20),
                        "; ".join(f"{n} {s}/{f}/{c}" for n, s, f, c in rows if f or c))
    try:
        _real_check_samples(self)
    except _memory.MemoryUsageExceededError as err:
        if not _DEFERRED["active"]:
            raise
        _DEFERRED["errors"].append(err)
        logging.getLogger("wick_macos").warning(
            "diagnostic (WICK_IT_DEFER_MEMORY_ERROR): %s at a kill inside the test; held to the test's end, "
            "and the test goes on", err)


_real_check_samples = _memory.MemoryMonitor.check_samples
_memory.MemoryMonitor.run = monitor_run
_memory.MemoryMonitor.check_samples = check_samples


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
    rest. Its one difference from Linux's is an offset: the system
    libraries' pages the process mapped from the dyld shared cache, where
    upstream's static Firecracker carries 1.6 MiB of its own text: 4.64 MiB
    in the page tables in every microVM of run m2-parts (the memory
    monitor's platform part). (A reading of 19 MiB here set the RSS against
    the other regions' residency in their objects, not their pages in the
    page tables.)

    Not the regions' resident pages as proc_pidinfo gives them by default
    (c8d26ac; `memory_maps` reads them in the footprint mode since):
    pages_resident is then the mapped object's residency, not the page tables',
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

# --------------------------------------- diagnostic runs: memory readings

# <mach/vm_region.h> share modes.
_SHARE_MODES = {1: "cow", 2: "private", 3: "empty", 4: "shared", 5: "trueshared",
                6: "private aliased", 7: "shared aliased", 8: "large page"}
# The vm_stat lines a reading keeps, in pages of vm_stat's page size.
_VM_STAT_KEYS = ("Pages free", "Pages active", "Pages inactive", "Pages speculative", "Pages wired down",
                 "File-backed pages", "Anonymous pages", "Pages stored in compressor",
                 "Pages occupied by compressor", "Decompressions", "Compressions", "Pageins", "Pageouts",
                 "Swapins", "Swapouts")
# The guest's /proc/meminfo lines a stable reading keeps (kB).
_MEMINFO_KEYS = ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "AnonPages", "Mapped",
                 "Shmem", "Slab", "KernelStack", "PageTables")
# The get_stable_rss_mem call a reading belongs to (diag_get_stable_rss_mem).
_DIAG_CALL = [0, None]


def _diag_write(record):
    record = {"test": os.environ.get("PYTEST_CURRENT_TEST", "").split(" ")[0], "time": round(time.time(), 3),
              "diagnostic": DIAGNOSTIC, **record}
    with open(_MEMORY_DIAG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def _task_memory(pid):
    """KiB: the task's resident size and phys_footprint (proc_pid_rusage,
    RUSAGE_INFO_V0: ri_resident_size, ri_phys_footprint, the 9th and 10th
    64-bit words). phys_footprint counts the task's compressed pages, which
    the resident size does not. And its compressed, internal and external
    pages: task_info(TASK_VM_INFO) on the task's name port, which
    task_name_for_pid gives the user for a process of the same user
    (measured); `compressed` is the internal_compressed ledger (XNU
    osfmk/kern/task.c task_info, TASK_VM_INFO)."""
    buf = (ctypes.c_uint64 * 12)()
    if _libsystem.proc_pid_rusage(pid, 0, ctypes.byref(buf)):
        return {"error": os.strerror(ctypes.get_errno())}
    out = {"resident_kib": buf[8] >> 10, "phys_footprint_kib": buf[9] >> 10}
    port = ctypes.c_uint(0)
    kr = _libsystem.task_name_for_pid(ctypes.c_uint.in_dll(_libsystem, "mach_task_self_"), pid, ctypes.byref(port))
    if kr:
        out["vm_info_error"] = f"task_name_for_pid: {kr}"
        return out
    # struct task_vm_info as 64-bit words: [2] resident_size, [6] internal,
    # [8] external, [15] compressed, [18] phys_footprint.
    info, count = (ctypes.c_uint64 * 100)(), ctypes.c_uint32(200)
    kr = _libsystem.task_info(port, 22, ctypes.byref(info), ctypes.byref(count))  # TASK_VM_INFO
    _libsystem.mach_port_deallocate(ctypes.c_uint.in_dll(_libsystem, "mach_task_self_"), port)
    if kr:
        out["vm_info_error"] = f"task_info: {kr}"
        return out
    out.update(internal_kib=info[6] >> 10, external_kib=info[8] >> 10, compressed_kib=info[15] >> 10)
    return out


def _region_groups(pid):
    """The process's regions in the footprint mode, as the memory monitor
    reads them, grouped: the shared cache; every mapping of at least 16 MiB
    (guest memory and its pieces after discards) by its file or VM tag and
    share mode; and the rest. KiB mapped, present in the page tables, and
    compressed or swapped out, and the number of mappings."""
    with _FOOTPRINT_LOCK:
        maps = _memory_maps(psutil.Process(pid))
    groups = defaultdict(lambda: [0, 0, 0, 0])
    for m in maps:
        if m.shared_cache:
            key = "shared cache"
        elif m.size >= 16 << 20:
            name = os.path.basename(m.path) if m.path else f"tag {m.tag}"
            key = f"{name} ({_SHARE_MODES.get(m.share_mode, m.share_mode)})"
        else:
            key = "other mappings"
        g = groups[key]
        g[0], g[1], g[2], g[3] = g[0] + (m.size >> 10), g[1] + (m.rss >> 10), g[2] + (m.swapped >> 10), g[3] + 1
    return {k: {"mapped_kib": v[0], "present_kib": v[1], "swapped_kib": v[2], "mappings": v[3]}
            for k, v in groups.items()}


def _host_memory():
    """The host's paging: vm_stat's counters (in its pages) and the memory
    pressure level (kern.memorystatus_vm_pressure_level: 1 normal, 2 warn,
    4 critical)."""
    out = {}
    try:
        text = subprocess.run(["/usr/bin/vm_stat"], capture_output=True, text=True, timeout=10, check=True).stdout
    except (OSError, subprocess.SubprocessError) as err:
        return {"error": str(err)}
    m = re.search(r"page size of (\d+) bytes", text)
    out["page_size"] = int(m[1]) if m else None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().strip('"')
        if key in _VM_STAT_KEYS:
            out[key] = int(value.strip().rstrip("."))
    level, size = ctypes.c_int(-1), ctypes.c_size_t(ctypes.sizeof(ctypes.c_int))
    if not _libsystem.sysctlbyname(b"kern.memorystatus_vm_pressure_level", ctypes.byref(level),
                                   ctypes.byref(size), None, 0):
        out["pressure_level"] = level.value
    return out


def _guest_memory(uvm):
    """The guest's /proc/meminfo (kB) and the balloon's statistics, read
    after a stable reading (over ssh and the API: they touch the guest, so
    a reading is never taken between them)."""
    out = {}
    try:
        rc, text, err = uvm.ssh.run("cat /proc/meminfo", timeout=20)
        if rc == 0:
            for line in text.splitlines():
                key, _, value = line.partition(":")
                if key in _MEMINFO_KEYS:
                    out[key] = int(value.split()[0])
        else:
            out["meminfo_error"] = f"rc {rc}: {err.strip()[:200]}"
    except Exception as exc:  # pylint: disable=broad-exception-caught
        out["meminfo_error"] = repr(exc)[:200]
    try:
        stats = uvm.api.balloon_stats.get().json()
        out["balloon"] = {k: stats.get(k) for k in ("target_mib", "actual_mib", "free_memory",
                                                   "available_memory", "total_memory")}
    except Exception as exc:  # pylint: disable=broad-exception-caught
        out["balloon_error"] = repr(exc)[:200]
    return out


def diag_get_resident_memory(process):
    """get_resident_memory, and in a get_stable_rss_mem call of a diagnostic
    run (WICK_IT_DIAG_MEMORY) the reading's parts, logged to
    memory-diag.jsonl: the task's resident size and phys_footprint, its
    regions (_region_groups) and the host's paging (_host_memory)."""
    rss = get_resident_memory(process)
    if _DIAG_CALL[1] is not None:
        record = {"kind": "reading", "call": _DIAG_CALL[1], "pid": process.pid, "rss_kib": rss}
        try:
            record.update(task=_task_memory(process.pid), regions=_region_groups(process.pid))
        except psutil.NoSuchProcess:
            record["error"] = "process gone"
        record["host"] = _host_memory()
        _diag_write(record)
    return rss


_real_get_stable_rss_mem = _utils.get_stable_rss_mem


def diag_get_stable_rss_mem(uvm, percentage_delta=1):
    """get_stable_rss_mem in a diagnostic run (WICK_IT_DIAG_MEMORY): its
    readings logged (diag_get_resident_memory), then the stable reading with
    the guest's view (_guest_memory)."""
    _DIAG_CALL[0] += 1
    _DIAG_CALL[1] = _DIAG_CALL[0]
    try:
        rss = _real_get_stable_rss_mem(uvm, percentage_delta)
    finally:
        _DIAG_CALL[1] = None
    _diag_write({"kind": "stable", "call": _DIAG_CALL[0], "rss_kib": rss, "guest": _guest_memory(uvm)})
    return rss


if "WICK_IT_DIAG_MEMORY" in DIAGNOSTIC:
    _libsystem.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _utils.get_resident_memory = diag_get_resident_memory
    _utils.get_stable_rss_mem = diag_get_stable_rss_mem

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


# The jail of each API socket, as the jail named it: Microvm.spawn makes
# its Api from JailerContext.api_socket_path() (framework/microvm.py),
# which is chroot_path() joined with the socket's name, and chroot_path()
# is <chroot_base>/<exec file>/<id>/root (framework/jailer.py) for any
# chroot_base a test gives (test_diff_snapshot_works_after_error's is its
# tmpfs), so the jail is not read back from the socket's path.
_CHROOT_OF_SOCKET = {}
_real_api_socket_path = _jailer.JailerContext.api_socket_path


def api_socket_path(self):
    """`JailerContext.api_socket_path`, its jail recorded."""
    path = _real_api_socket_path(self)
    _CHROOT_OF_SOCKET[str(path)] = str(self.chroot_path())
    return path


_jailer.JailerContext.api_socket_path = api_socket_path


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
        everything else is upstream's, but for a block device: upstream
        makes a node of the same device in the jail (mknod), which macOS
        allows only root (measured as the user: EPERM). The user-mode jail
        is no chroot, and a symbolic link in it to the device's node names
        the same device for Firecracker, which opens it through the link."""
        src = pathlib.Path(file_path)
        if create and src.is_block_device():
            dst = pathlib.Path(self.chroot_path()) / subdir / src.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.unlink(missing_ok=True)
            dst.symlink_to(src)
            return str(pathlib.Path("/") / subdir / src.name)
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
        root = _CHROOT_OF_SOCKET.get(str(api.socket))
        if root is None:
            raise AssertionError(f"API socket {api.socket} is not one of a jail's")
        return root

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
# Linux, the pages Firecracker mapped. For a file, proc_pidinfo's default
# mode shows the file's pages in the buffer cache, all of them for a file the
# test has just written. A pmem backing file, the one file Firecracker maps
# besides its binary (tools/macos/integration-tests.sh), is rewritten in
# place without caching before Firecracker is given it, so its resident
# pages are those its guest touches. Its contents and inode stay the same.
# `memory_maps` now reads in the footprint mode, where a cached page that is
# not mapped does not count; the rewrite stays until a pmem run shows the
# footprint mode alone gives the same counts.
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
        root = _CHROOT_OF_SOCKET.get(str(self._api.socket))
        host = root + backing if root and backing.startswith("/") else backing
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
    path in proc_pidinfo(PROC_PIDREGIONPATHINFO)), as `memory_maps` reads
    them, and of the dyld shared cache's the writable ones (the libraries'
    data, which Linux counts as anonymous once copied on write; their text
    is RssFile there): the pages the process has mapped
    (the footprint mode), as Linux's RssAnon counts its anonymous pages
    (fs/proc/task_mmu.c task_mem: get_mm_counter(mm, MM_ANONPAGES), the
    anonymous pages mapped in its page tables)."""
    return sum(m.rss for m in memory_maps(psutil.Process(pid), grouped=False)
               if not m.path and (m.writable or not m.shared_cache)) // 1024


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


PROC_PIDFDVNODEPATHINFO = 2
_VNODE_FDINFOWITHPATH = 24 + 152 + 1024  # proc_fileinfo, vnode_info, vip_path[MAXPATHLEN]
_PROC_FD = re.compile(r"^/proc/(\d+)/fd/(\d+)$")


def proc_fd_path(pid, fd):
    """The file `pid`'s descriptor `fd` names, which Linux's /proc/<pid>/fd/<fd>
    opens: proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO), <sys/proc_info.h> struct
    vnode_fdinfowithpath's vip_path. Measured: a child's stdin on a pty gives
    its /dev/ttysNNN."""
    buf = ctypes.create_string_buffer(_VNODE_FDINFOWITHPATH)
    if _libsystem.proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, buf, len(buf)) != len(buf):
        err = ctypes.get_errno() or errno.ENOENT
        raise OSError(err, f"/proc/{pid}/fd/{fd}: {os.strerror(err)} (proc_pidfdinfo)")
    return buf.raw[176:].split(b"\0", 1)[0].decode()


class _ProcFdOs:
    """The `os` module, but `open` of /proc/<pid>/fd/<fd> opens the file the
    descriptor names (proc_fd_path), as Linux's /proc does for a terminal."""

    def __getattr__(self, name):
        return getattr(os, name)

    @staticmethod
    def open(path, flags, mode=0o777, **kwargs):
        m = _PROC_FD.match(os.fspath(path))
        return os.open(proc_fd_path(int(m[1]), int(m[2])) if m else path, flags, mode, **kwargs)


def pytest_runtest_setup(item):
    """test_pmem reads RssAnon from /proc, which macOS does not have: its
    helper reads it as `rss_anon_kib` does. test_serial_io opens Firecracker's
    terminal through /proc/<pid>/fd/0: its `os.open` opens it by its device
    (_ProcFdOs). A test of NOISE_ONLY_PINNING runs unpinned
    (`set_cpu_affinity`)."""
    global _unpinned_test  # pylint: disable=global-statement
    _unpinned_test = item if item.nodeid.split("[", 1)[0] in NOISE_ONLY_PINNING else None
    module = getattr(item, "module", None)
    if module is not None and module.__name__.endswith("test_pmem") and hasattr(module, "outside_rssanon"):
        module.outside_rssanon = _outside_rssanon
    if module is not None and module.__name__.endswith("test_serial_io") and getattr(module, "os", None) is os:
        module.os = _ProcFdOs()
    # A diagnostic run's readings (WICK_IT_DIAG_MEMORY): the test modules
    # that import get_stable_rss_mem by name.
    if module is not None and "WICK_IT_DIAG_MEMORY" in DIAGNOSTIC \
            and getattr(module, "get_stable_rss_mem", None) is _real_get_stable_rss_mem:
        module.get_stable_rss_mem = diag_get_stable_rss_mem


import pytest as _pytest  # noqa: E402  pylint: disable=wrong-import-position


@_pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    """test_memory_overhead publishes the VMM's resident memory besides the
    guest (overhead_rss), which on macOS includes the system libraries'
    pages from the dyld shared cache (`memory_maps`): beside it the test also
    publishes the two parts, overhead_rss_shared_cache and overhead_rss_own,
    so that a change in the VMM's own memory shows on its own.

    In a diagnostic run with WICK_IT_DEFER_MEMORY_ERROR, the memory
    monitor's errors at a kill inside the test are held (check_samples):
    when the test's call ends, how the steps after the kill ended goes to
    memory-diag.jsonl, and a call that passed fails with the first held
    error; a call that failed keeps its own failure."""
    metrics = item.funcargs.get("metrics") if item.name.startswith("test_memory_overhead") else None
    if metrics is not None:
        put = metrics.put_metric

        def put_metric(key, value, unit=None, *args, **kwargs):
            put(key, value, unit, *args, **kwargs)
            if key == "overhead_rss" and _LAST_SHARED_CACHE_RSS[0] is not None:
                cache = _LAST_SHARED_CACHE_RSS[0]
                put("overhead_rss_shared_cache", cache, unit)
                put("overhead_rss_own", value - cache, unit)

        metrics.put_metric = put_metric
    defer = "WICK_IT_DEFER_MEMORY_ERROR" in DIAGNOSTIC
    _DEFERRED.update(active=defer, errors=[])
    outcome = yield
    _DEFERRED["active"] = False
    if defer and _DEFERRED["errors"]:
        # The steps after the kill ran: how they ended, then the held error.
        excinfo = outcome.excinfo
        _diag_write({"kind": "deferred", "errors": [str(e) for e in _DEFERRED["errors"]],
                     "after": "passed" if excinfo is None else f"{excinfo[0].__name__}: {str(excinfo[1])[:500]}"})
        if excinfo is None:
            outcome.force_exception(_DEFERRED["errors"][0])


def pytest_report_header():
    """What runs where."""
    return [
        f"wick macOS host: mode {MODE}, session root {SESSION_ROOT}, "
        f"macOS {platform.mac_ver()[0]}, Hypervisor.framework {'yes' if hvf_available() else 'no'}"
    ]
