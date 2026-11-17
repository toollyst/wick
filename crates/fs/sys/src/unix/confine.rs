// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Linux's confinement calls for wick-fsd's stage 0 → stage 1 step
//! (docs/design-fs.md §6.1): namespaces, the share as the root, the ids and
//! capabilities dropped, `no_new_privs`, Landlock and the seccomp filter of
//! [`SERVER_SYSCALLS`]. `wick_fsd::confine` calls them in order; each
//! failure is the caller's refusal to serve.

use std::ffi::CString;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use libc::{c_int, c_long, c_ulong, c_void};

use super::{HostErrno, Result, check, last, owned};

fn path_c(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| HostErrno(libc::EINVAL))
}

fn check_long(ret: c_long) -> Result<c_long> {
    if ret < 0 { Err(last()) } else { Ok(ret) }
}

/// `unshare(2)` of a mount, pid, network and IPC namespace, and, for a
/// server that is not root, a user namespace first (in the same call).
pub fn unshare(user: bool) -> Result<()> {
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWNET | libc::CLONE_NEWIPC;
    if user {
        flags |= libc::CLONE_NEWUSER;
    }
    // SAFETY: unshare takes flags only.
    check(unsafe { libc::unshare(flags) }).map(drop)
}

/// The threads of this process, from `/proc/self/task`.
fn threads() -> Result<usize> {
    let dir = std::fs::read_dir("/proc/self/task").map_err(|e| HostErrno(e.raw_os_error().unwrap_or(libc::EIO)))?;
    Ok(dir.count())
}

/// What [`fork`] returned in this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forked {
    /// The new process.
    Child,
    /// The process that forked, with the child's pid.
    Parent(i32),
}

/// `fork(2)`, only in a process with one thread (EBUSY otherwise): a child
/// of a threaded process may only call async-signal-safe functions, and the
/// server's child goes on to run Rust. The pid namespace of [`unshare`]
/// takes effect for this child, which is its pid 1.
pub fn fork() -> Result<Forked> {
    if threads()? != 1 {
        return Err(HostErrno(libc::EBUSY));
    }
    // SAFETY: the process has one thread (checked just above, and nothing
    // here starts one), so the child is a whole copy of it.
    match unsafe { libc::fork() } {
        -1 => Err(last()),
        0 => Ok(Forked::Child),
        pid => Ok(Forked::Parent(pid)),
    }
}

/// How a child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It exited with this code.
    Exited(i32),
    /// A signal ended it.
    Signaled(i32),
}

/// Waits for the child `pid` to end.
pub fn wait(pid: i32) -> Result<Ended> {
    loop {
        let mut status: c_int = 0;
        // SAFETY: status is a valid int for waitpid to fill.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = last();
            if e.0 == libc::EINTR {
                continue;
            }
            return Err(e);
        }
        if libc::WIFEXITED(status) {
            return Ok(Ended::Exited(libc::WEXITSTATUS(status)));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(Ended::Signaled(libc::WTERMSIG(status)));
        }
    }
}

fn prctl(option: c_int, arg: c_ulong) -> Result<()> {
    // SAFETY: the options used here take integer arguments only.
    check(unsafe { libc::prctl(option, arg, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong) }).map(drop)
}

/// A pipe whose write end the parent keeps across [`fork`] and whose read
/// end the child gives [`die_with_parent`]: (read, write).
pub fn parent_watch() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for the two descriptors pipe2 returns.
    check(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    Ok((owned(fds[0])?, owned(fds[1])?))
}

/// SIGKILL when the parent (the waiting stage 0 process) ends, so killing
/// wick-fsd kills its confined child; EIDRM if the parent ended already
/// (its end of the [`parent_watch`] pipe is closed). The parent is outside
/// the child's pid namespace, where `getppid` says 0, hence the pipe.
pub fn die_with_parent(watch: OwnedFd) -> Result<()> {
    prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as c_ulong)?;
    let mut p = libc::pollfd {
        fd: watch.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd, no wait.
    check(unsafe { libc::poll(&mut p, 1, 0) })?;
    if p.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
        return Err(HostErrno(libc::EIDRM));
    }
    Ok(())
}

/// The pid of this process.
pub fn pid() -> i32 {
    // SAFETY: getpid cannot fail.
    unsafe { libc::getpid() }
}

/// Not dumpable: no core file, and the host's processes of the same uid
/// can neither ptrace it nor open its `/proc/<pid>` files.
pub fn not_dumpable() -> Result<()> {
    prctl(libc::PR_SET_DUMPABLE, 0)
}

/// `PR_SET_NO_NEW_PRIVS`.
pub fn no_new_privs() -> Result<()> {
    prctl(libc::PR_SET_NO_NEW_PRIVS, 1)
}

fn mount(src: Option<&Path>, target: &Path, fstype: Option<&str>, flags: c_ulong) -> Result<()> {
    let src = src.map(path_c).transpose()?;
    let target = path_c(target)?;
    let fstype = fstype.map(|t| CString::new(t).map_err(|_| HostErrno(libc::EINVAL))).transpose()?;
    let p = |c: &Option<CString>| c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: each pointer is a NUL-terminated string that lives across the
    // call, or null where mount(2) allows it; no data argument.
    check(unsafe { libc::mount(p(&src), target.as_ptr(), p(&fstype), flags, std::ptr::null::<c_void>()) }).map(drop)
}

/// Makes every mount in this mount namespace private, so nothing done here
/// reaches the host's.
pub fn mounts_private() -> Result<()> {
    mount(None, Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE)
}

/// Bind-mounts `dir` onto itself, without what is mounted beneath it.
pub fn bind_self(dir: &Path) -> Result<()> {
    mount(Some(dir), dir, None, libc::MS_BIND)
}

/// The `MS_*` flags of the mount `dir` is on that a bind remount must keep
/// (Linux refuses, in a user namespace, a remount that clears a flag the
/// mount was locked with).
pub fn locked_flags(dir: &Path) -> Result<c_ulong> {
    let c = path_c(dir)?;
    // SAFETY: an all-zero statvfs is valid for statvfs to fill.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a NUL-terminated path and s a valid statvfs.
    check(unsafe { libc::statvfs(c.as_ptr(), &mut s) })?;
    let pairs = [
        (libc::ST_RDONLY, libc::MS_RDONLY),
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ];
    Ok(pairs.iter().filter(|(st, _)| s.f_flag & st != 0).fold(0, |a, (_, ms)| a | ms))
}

/// The mount flags a bind remount adds.
pub mod ms {
    /// `MS_RDONLY`.
    pub const RDONLY: libc::c_ulong = libc::MS_RDONLY;
    /// `MS_NOSUID`.
    pub const NOSUID: libc::c_ulong = libc::MS_NOSUID;
    /// `MS_NODEV`.
    pub const NODEV: libc::c_ulong = libc::MS_NODEV;
    /// `MS_NOEXEC`.
    pub const NOEXEC: libc::c_ulong = libc::MS_NOEXEC;
}

/// Remounts the bind mount at `dir` with `flags` (`MS_RDONLY`, `MS_NOSUID`,
/// ...).
pub fn remount_bind(dir: &Path, flags: c_ulong) -> Result<()> {
    mount(None, dir, None, libc::MS_REMOUNT | libc::MS_BIND | flags)
}

/// Makes `dir` the root: `chdir(dir)`, `pivot_root(".", ".")`, the old root
/// detached, `chdir("/")`.
pub fn pivot_to(dir: &Path) -> Result<()> {
    std::env::set_current_dir(dir).map_err(|e| HostErrno(e.raw_os_error().unwrap_or(libc::EIO)))?;
    let dot = c".";
    // SAFETY: both arguments are the NUL-terminated string ".".
    check_long(unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) })?;
    // SAFETY: "." is a NUL-terminated string; MNT_DETACH is a valid flag.
    check(unsafe { libc::umount2(dot.as_ptr(), libc::MNT_DETACH) })?;
    std::env::set_current_dir("/").map_err(|e| HostErrno(e.raw_os_error().unwrap_or(libc::EIO)))
}

/// Drops to `uid`/`gid` with no supplementary groups, and checks that every
/// id (real, effective, saved) is that one.
pub fn drop_ids(uid: u32, gid: u32) -> Result<()> {
    // SAFETY: an empty group list (null pointer, length 0).
    check(unsafe { libc::setgroups(0, std::ptr::null()) })?;
    // SAFETY: setresgid takes ids only.
    check(unsafe { libc::setresgid(gid, gid, gid) })?;
    // SAFETY: setresuid takes ids only.
    check(unsafe { libc::setresuid(uid, uid, uid) })?;
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: three valid uid_t for getresuid to fill.
    check(unsafe { libc::getresuid(&mut r, &mut e, &mut s) })?;
    let (mut gr, mut ge, mut gs) = (0, 0, 0);
    // SAFETY: three valid gid_t for getresgid to fill.
    check(unsafe { libc::getresgid(&mut gr, &mut ge, &mut gs) })?;
    if (r, e, s, gr, ge, gs) != (uid, uid, uid, gid, gid, gid) {
        return Err(HostErrno(libc::EPERM));
    }
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Drops every capability: the bounding set (while `CAP_SETPCAP` is still
/// held; EPERM without it is ignored, as a process without capabilities
/// has nothing to drop), the ambient set, then effective, permitted and
/// inheritable to nothing.
pub fn drop_capabilities() -> Result<()> {
    for cap in 0..64 {
        match prctl(libc::PR_CAPBSET_DROP, cap) {
            Ok(()) => {}
            // Past the last capability this kernel has.
            Err(e) if e.0 == libc::EINVAL => break,
            Err(e) if e.0 == libc::EPERM => break,
            Err(e) => return Err(e),
        }
    }
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL takes integer arguments only.
    check(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong,
            0 as c_ulong,
            0 as c_ulong,
            0 as c_ulong,
        )
    })?;
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset reads a version-3 header and two data structs, which
    // live across the call.
    check_long(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) })?;
    Ok(())
}

/// Landlock's access rights (`include/uapi/linux/landlock.h`).
pub mod landlock {
    /// `LANDLOCK_ACCESS_FS_*`.
    pub const EXECUTE: u64 = 1 << 0;
    /// Opens a file for writing.
    pub const WRITE_FILE: u64 = 1 << 1;
    /// Opens a file for reading.
    pub const READ_FILE: u64 = 1 << 2;
    /// Lists a directory.
    pub const READ_DIR: u64 = 1 << 3;
    /// Removes an empty directory or renames one.
    pub const REMOVE_DIR: u64 = 1 << 4;
    /// Unlinks or renames a file.
    pub const REMOVE_FILE: u64 = 1 << 5;
    /// Makes a character device.
    pub const MAKE_CHAR: u64 = 1 << 6;
    /// Makes or renames a directory into place.
    pub const MAKE_DIR: u64 = 1 << 7;
    /// Makes, renames or links a regular file into place.
    pub const MAKE_REG: u64 = 1 << 8;
    /// Makes a socket.
    pub const MAKE_SOCK: u64 = 1 << 9;
    /// Makes a FIFO.
    pub const MAKE_FIFO: u64 = 1 << 10;
    /// Makes a block device.
    pub const MAKE_BLOCK: u64 = 1 << 11;
    /// Makes a symlink.
    pub const MAKE_SYM: u64 = 1 << 12;
    /// Links or renames a file to another directory (ABI 2).
    pub const REFER: u64 = 1 << 13;
    /// Truncates a file (ABI 3).
    pub const TRUNCATE: u64 = 1 << 14;
    /// ioctl on a device file (ABI 5).
    pub const IOCTL_DEV: u64 = 1 << 15;
    /// `LANDLOCK_ACCESS_NET_BIND_TCP` (ABI 4).
    pub const NET_BIND_TCP: u64 = 1 << 0;
    /// `LANDLOCK_ACCESS_NET_CONNECT_TCP` (ABI 4).
    pub const NET_CONNECT_TCP: u64 = 1 << 1;
    /// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6).
    pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    /// `LANDLOCK_SCOPE_SIGNAL` (ABI 6).
    pub const SCOPE_SIGNAL: u64 = 1 << 1;
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: c_int = 1;

/// The Landlock ABI version this kernel has, `None` without Landlock
/// (ENOSYS: not built; EOPNOTSUPP: built but not enabled at boot).
pub fn landlock_abi() -> Result<Option<u32>> {
    // SAFETY: the version query takes a null attribute of size 0.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r < 0 {
        let e = last();
        return if e.0 == libc::ENOSYS || e.0 == libc::EOPNOTSUPP { Ok(None) } else { Err(e) };
    }
    Ok(u32::try_from(r).ok())
}

/// Restricts this process with Landlock (ABI `abi`): the file system
/// rights `handled_fs`, of which only `allowed_fs` beneath `root`; with ABI
/// 4 or later TCP bind and connect handled with no rule (so none allowed);
/// with ABI 6 or later abstract Unix sockets and signals scoped to the
/// domain. Needs `no_new_privs` first.
pub fn landlock_restrict(abi: u32, root: BorrowedFd<'_>, handled_fs: u64, allowed_fs: u64) -> Result<()> {
    let attr = RulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: landlock::NET_BIND_TCP | landlock::NET_CONNECT_TCP,
        scoped: landlock::SCOPE_ABSTRACT_UNIX_SOCKET | landlock::SCOPE_SIGNAL,
    };
    // The attribute's size names the fields this ABI knows.
    let size = match abi {
        1..=3 => 8usize,
        4 | 5 => 16,
        _ => 24,
    };
    // SAFETY: attr is a ruleset attribute whose first `size` bytes are the
    // fields of this ABI; it lives across the call.
    let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr, size, 0u32) };
    let fd = c_int::try_from(fd).map_err(|_| HostErrno(libc::EOVERFLOW))?;
    let ruleset: OwnedFd = owned(fd)?;
    let rule = PathBeneathAttr {
        allowed_access: allowed_fs,
        parent_fd: root.as_raw_fd(),
    };
    // SAFETY: rule is a path-beneath attribute that lives across the call;
    // ruleset is the descriptor create_ruleset returned.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &rule,
            0u32,
        )
    })?;
    // SAFETY: ruleset is a valid ruleset descriptor; no flags.
    check_long(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) })?;
    Ok(())
}

/// One classic BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// The operation.
    pub code: u16,
    /// Jump offset if true.
    pub jt: u8,
    /// Jump offset if false.
    pub jf: u8,
    /// The constant.
    pub k: u32,
}

/// Installs `program` as this process's seccomp filter (after
/// `no_new_privs`, or with `CAP_SYS_ADMIN`). With `SECCOMP_FILTER_FLAG_TSYNC`
/// every thread gets it.
pub fn seccomp_install(program: &[Insn]) -> Result<()> {
    let filters: Vec<libc::sock_filter> = program
        .iter()
        .map(|i| libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect();
    let prog = libc::sock_fprog {
        len: u16::try_from(filters.len()).map_err(|_| HostErrno(libc::EINVAL))?,
        filter: filters.as_ptr().cast_mut(),
    };
    // SAFETY: prog points at `len` instructions that live across the call;
    // the kernel copies them.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog,
        )
    })?;
    Ok(())
}

/// Classic BPF's codes and seccomp's return values and data offsets.
pub mod bpf {
    /// `BPF_LD | BPF_W | BPF_ABS`.
    pub const LD_W_ABS: u16 = 0x20;
    /// `BPF_JMP | BPF_JEQ | BPF_K`.
    pub const JEQ: u16 = 0x15;
    /// `BPF_JMP | BPF_JGE | BPF_K`.
    pub const JGE: u16 = 0x35;
    /// `BPF_JMP | BPF_JSET | BPF_K`.
    pub const JSET: u16 = 0x45;
    /// `BPF_RET | BPF_K`.
    pub const RET: u16 = 0x06;
    /// `SECCOMP_RET_KILL_PROCESS`.
    pub const KILL_PROCESS: u32 = 0x8000_0000;
    /// `SECCOMP_RET_ERRNO` (or the errno into it).
    pub const ERRNO: u32 = 0x0005_0000;
    /// `SECCOMP_RET_ALLOW`.
    pub const ALLOW: u32 = 0x7fff_0000;
    /// `seccomp_data.nr`.
    pub const NR: u32 = 0;
    /// `seccomp_data.arch`.
    pub const ARCH: u32 = 4;
    /// The low 32 bits of `seccomp_data.args[i]` (little-endian).
    pub const fn arg_lo(i: u32) -> u32 {
        16 + 8 * i
    }
    /// The high 32 bits of `seccomp_data.args[i]`.
    pub const fn arg_hi(i: u32) -> u32 {
        20 + 8 * i
    }
    /// This build's `AUDIT_ARCH_*`.
    #[cfg(target_arch = "x86_64")]
    pub const AUDIT_ARCH: u32 = 0xc000_003e;
    /// This build's `AUDIT_ARCH_*`.
    #[cfg(target_arch = "aarch64")]
    pub const AUDIT_ARCH: u32 = 0xc000_00b7;
    /// x86_64's x32 system calls have this bit; refused.
    pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
}

/// A system call's argument rule in [`SERVER_SYSCALLS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Args {
    /// Any arguments.
    Any,
    /// Argument `i` (its low 32 bits) is one of these.
    OneOf(u32, &'static [u32]),
    /// Argument `i` (low 32 bits) has none of these bits.
    NoneOf(u32, u32),
    /// Argument `i` is 0 (all 64 bits).
    Zero(u32),
}

fn nr(n: c_long) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// `FS_IOC_GETFLAGS`: a directory's casefold flag, read when the server
/// holds a directory.
pub const FS_IOC_GETFLAGS: u32 = 0x8008_6601;

/// Every system call the confined server makes (stage 1), each with why and
/// its argument rule; anything else kills it (`SECCOMP_RET_KILL_PROCESS`).
/// Like crosvm's `fs_device.policy`, without `mknodat`, `setresuid`,
/// `setresgid` and `capset` (ownership is emulated; ids are dropped before
/// the filter), and without `openat`, `socket`, `clone` and `execve`: the
/// server opens only through `openat2` beneath a held directory, makes no
/// socket, no thread and no process.
pub const SERVER_SYSCALLS: &[(c_long, &str, Args)] = &[
    (libc::SYS_read, "frames from the VMM (and std's reads)", Args::Any),
    (libc::SYS_write, "replies to the VMM, the log", Args::Any),
    (libc::SYS_readv, "std's vectored reads", Args::Any),
    (libc::SYS_writev, "std's vectored writes (the log, a panic message)", Args::Any),
    (libc::SYS_recvfrom, "std's read of a socket, no address", Args::Zero(4)),
    (libc::SYS_sendto, "std's write to a socket, no address", Args::Zero(4)),
    (libc::SYS_pread64, "READ", Args::Any),
    (libc::SYS_pwrite64, "WRITE", Args::Any),
    (libc::SYS_lseek, "a listing's position", Args::Any),
    (libc::SYS_close, "descriptors the server is done with", Args::Any),
    (libc::SYS_openat2, "every open: beneath a held directory, no link", Args::Any),
    (libc::SYS_newfstatat, "fstatat(AT_SYMLINK_NOFOLLOW) of one name; libc's fstat", Args::Any),
    (libc::SYS_fstat, "fstat of an opened object", Args::Any),
    (libc::SYS_statx, "libc's fstat on some versions", Args::Any),
    (libc::SYS_getdents64, "READDIR", Args::Any),
    (libc::SYS_fgetxattr, "the record and guest attributes", Args::Any),
    (libc::SYS_fsetxattr, "the record and guest attributes", Args::Any),
    (libc::SYS_flistxattr, "LISTXATTR", Args::Any),
    (libc::SYS_fremovexattr, "REMOVEXATTR", Args::Any),
    (libc::SYS_mkdirat, "MKDIR", Args::Any),
    (libc::SYS_unlinkat, "UNLINK, RMDIR", Args::Any),
    (libc::SYS_renameat2, "RENAME, NOREPLACE, EXCHANGE", Args::Any),
    (libc::SYS_linkat, "LINK", Args::Any),
    (libc::SYS_readlinkat, "READLINK of a host symlink", Args::Any),
    (libc::SYS_fchmod, "SETATTR mode", Args::Any),
    (libc::SYS_utimensat, "SETATTR times (futimens)", Args::Any),
    (libc::SYS_ftruncate, "SETATTR size", Args::Any),
    (libc::SYS_fallocate, "FALLOCATE", Args::Any),
    (libc::SYS_fsync, "FSYNC", Args::Any),
    (libc::SYS_fdatasync, "FSYNC with the data-only flag", Args::Any),
    (libc::SYS_fstatfs, "STATFS", Args::Any),
    (libc::SYS_ioctl, "FS_IOC_GETFLAGS only (casefold)", Args::OneOf(1, &[FS_IOC_GETFLAGS])),
    (
        libc::SYS_fcntl,
        "F_GETFL, F_GETFD only",
        Args::OneOf(1, &[libc::F_GETFL as u32, libc::F_GETFD as u32]),
    ),
    (libc::SYS_mmap, "the allocator, never executable", Args::NoneOf(2, libc::PROT_EXEC as u32)),
    (libc::SYS_mprotect, "the allocator, never executable", Args::NoneOf(2, libc::PROT_EXEC as u32)),
    (libc::SYS_munmap, "the allocator", Args::Any),
    (libc::SYS_mremap, "the allocator", Args::Any),
    (libc::SYS_brk, "the allocator", Args::Any),
    (libc::SYS_madvise, "the allocator", Args::Any),
    (libc::SYS_futex, "std's locks", Args::Any),
    (libc::SYS_sched_yield, "std's locks", Args::Any),
    (libc::SYS_getrandom, "std's hash keys", Args::Any),
    (libc::SYS_clock_gettime, "SETATTR to now (without the vDSO)", Args::Any),
    (libc::SYS_rt_sigreturn, "return from a signal", Args::Any),
    (libc::SYS_rt_sigprocmask, "abort's signal mask", Args::Any),
    (libc::SYS_sigaltstack, "std's stack guard at exit", Args::Any),
    (libc::SYS_getpid, "abort", Args::Any),
    (libc::SYS_gettid, "abort", Args::Any),
    (libc::SYS_tgkill, "abort: SIGABRT to itself only", Args::OneOf(2, &[libc::SIGABRT as u32])),
    (libc::SYS_restart_syscall, "a call restarted after a signal", Args::Any),
    (libc::SYS_exit, "the end", Args::Any),
    (libc::SYS_exit_group, "the end", Args::Any),
];

/// The server's seccomp program: this architecture only (x32 refused),
/// [`SERVER_SYSCALLS`] with their argument rules, anything else
/// `SECCOMP_RET_KILL_PROCESS`.
pub fn server_program() -> Vec<Insn> {
    allow_list(SERVER_SYSCALLS, bpf::KILL_PROCESS)
}

fn insn(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code, jt, jf, k }
}

/// A filter that allows `list` (with their argument rules) and returns
/// `otherwise` for anything else.
pub fn allow_list(list: &[(c_long, &str, Args)], otherwise: u32) -> Vec<Insn> {
    use bpf::*;
    let mut p = vec![
        insn(LD_W_ABS, ARCH, 0, 0),
        insn(JEQ, AUDIT_ARCH, 1, 0),
        insn(RET, KILL_PROCESS, 0, 0),
        insn(LD_W_ABS, NR, 0, 0),
        insn(JGE, X32_SYSCALL_BIT, 0, 1),
        insn(RET, KILL_PROCESS, 0, 0),
    ];
    for &(n, _, args) in list {
        // Each entry: compare the number, skip the entry's body if not it.
        let body: Vec<Insn> = match args {
            Args::Any => vec![insn(RET, ALLOW, 0, 0)],
            Args::OneOf(i, values) => {
                let mut b = vec![insn(LD_W_ABS, arg_lo(i), 0, 0)];
                let count = u8::try_from(values.len()).unwrap_or(u8::MAX);
                for (j, &v) in values.iter().enumerate() {
                    let left = count - u8::try_from(j).unwrap_or(0) - 1;
                    // Equal: jump past the remaining compares to the allow.
                    b.push(insn(JEQ, v, left + 1, 0));
                }
                b.push(insn(RET, otherwise, 0, 0));
                b.push(insn(RET, ALLOW, 0, 0));
                b
            }
            Args::NoneOf(i, bits) => vec![
                insn(LD_W_ABS, arg_lo(i), 0, 0),
                insn(JSET, bits, 0, 1),
                insn(RET, otherwise, 0, 0),
                insn(RET, ALLOW, 0, 0),
            ],
            Args::Zero(i) => vec![
                insn(LD_W_ABS, arg_lo(i), 0, 0),
                insn(JEQ, 0, 1, 0),
                insn(RET, otherwise, 0, 0),
                insn(LD_W_ABS, arg_hi(i), 0, 0),
                insn(JEQ, 0, 1, 0),
                insn(RET, otherwise, 0, 0),
                insn(RET, ALLOW, 0, 0),
            ],
        };
        // The body is reached only for this number and ends in a return, so
        // past it the accumulator still holds the number.
        let skip = u8::try_from(body.len()).unwrap_or(u8::MAX);
        p.push(insn(JEQ, nr(n), 0, skip));
        p.extend(body);
    }
    p.push(insn(RET, otherwise, 0, 0));
    p
}

/// A filter that returns `errno` for each system call of `deny` (and, with
/// `Some((i, v))`, only when its argument `i` is `v`) and allows everything
/// else: the refusal tests run wick-fsd under one, so a confinement step
/// fails for real (docs/design-fs.md §6.1).
pub fn deny_program(deny: &[(c_long, Option<(u32, u32)>)], errno: i32) -> Vec<Insn> {
    use bpf::*;
    let ret = insn(RET, ERRNO | (u32::try_from(errno).unwrap_or(1) & 0xffff), 0, 0);
    let mut p = vec![insn(LD_W_ABS, NR, 0, 0)];
    for &(n, arg) in deny {
        match arg {
            None => {
                p.push(insn(JEQ, nr(n), 0, 1));
                p.push(ret);
            }
            Some((i, v)) => {
                p.push(insn(JEQ, nr(n), 0, 4));
                p.push(insn(LD_W_ABS, arg_lo(i), 0, 0));
                p.push(insn(JEQ, v, 0, 1));
                p.push(ret);
                p.push(insn(LD_W_ABS, NR, 0, 0));
            }
        }
    }
    p.push(insn(RET, ALLOW, 0, 0));
    p
}

/// System call numbers the tests deny to make a step fail.
pub mod nr {
    use libc::c_long;
    /// `unshare`.
    pub const UNSHARE: c_long = libc::SYS_unshare;
    /// `clone`.
    pub const CLONE: c_long = libc::SYS_clone;
    /// `clone3`.
    pub const CLONE3: c_long = libc::SYS_clone3;
    /// `mount`.
    pub const MOUNT: c_long = libc::SYS_mount;
    /// `pivot_root`.
    pub const PIVOT_ROOT: c_long = libc::SYS_pivot_root;
    /// `setresuid`.
    pub const SETRESUID: c_long = libc::SYS_setresuid;
    /// `capset`.
    pub const CAPSET: c_long = libc::SYS_capset;
    /// `prctl`.
    pub const PRCTL: c_long = libc::SYS_prctl;
    /// `seccomp`.
    pub const SECCOMP: c_long = libc::SYS_seccomp;
    /// `landlock_create_ruleset`.
    pub const LANDLOCK_CREATE_RULESET: c_long = libc::SYS_landlock_create_ruleset;
    /// `landlock_restrict_self`.
    pub const LANDLOCK_RESTRICT_SELF: c_long = libc::SYS_landlock_restrict_self;
}

/// Has `cmd`'s child install `program` (after `no_new_privs`) before it
/// runs its program: the tests' way to make one of wick-fsd's steps fail.
pub fn command_with_filter(cmd: &mut std::process::Command, program: Vec<Insn>) {
    use std::os::unix::process::CommandExt;
    let filters: Vec<libc::sock_filter> = program
        .iter()
        .map(|i| libc::sock_filter {
            code: i.code,
            jt: i.jt,
            jf: i.jf,
            k: i.k,
        })
        .collect();
    let len = u16::try_from(filters.len()).unwrap_or(0);
    let closure = move || {
        let prog = libc::sock_fprog {
            len,
            filter: filters.as_ptr().cast_mut(),
        };
        // SAFETY: prctl and seccomp are async-signal-safe system calls; prog
        // points at the filters, which the closure owns.
        let r = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as c_ulong, 0 as c_ulong, 0 as c_ulong, 0 as c_ulong)
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: as above.
        let r = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0u32, &prog) };
        if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
    };
    // SAFETY: the closure makes only async-signal-safe system calls and
    // allocates nothing (the program was built before the fork).
    unsafe {
        cmd.pre_exec(closure);
    }
}

/// The uid and pid of the peer of a connected Unix socket (`SO_PEERCRED`):
/// who connected, as the kernel recorded it at `connect`.
pub fn peer(sock: BorrowedFd<'_>) -> Result<(u32, i32)> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
    // SAFETY: cred is a ucred of `len` bytes for getsockopt to fill.
    check(unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<c_void>(),
            &mut len,
        )
    })?;
    Ok((cred.uid, cred.pid))
}

/// System calls the confined server never makes, for the tests that check
/// the filter kills it: each returns what the kernel answered, if the
/// process is still alive.
pub mod probe {
    use super::*;

    /// `open_by_handle_at(AT_FDCWD, <empty handle>, O_RDONLY)` (row 8).
    pub fn open_by_handle() -> Result<()> {
        let handle = [0u8; 16];
        // SAFETY: an 8-byte handle header (size 0) followed by spare bytes.
        check_long(unsafe { libc::syscall(libc::SYS_open_by_handle_at, libc::AT_FDCWD, handle.as_ptr(), 0) })
            .map(drop)
    }

    /// `openat(AT_FDCWD, path, O_RDONLY)`.
    pub fn openat(path: &Path) -> Result<OwnedFd> {
        let c = path_c(path)?;
        // SAFETY: c is a NUL-terminated path.
        owned(unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) })
    }

    /// `socket(AF_INET, SOCK_STREAM, 0)`.
    pub fn socket_inet() -> Result<OwnedFd> {
        // SAFETY: socket takes integers only.
        owned(unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })
    }

    /// `execve("/bin/true")`.
    pub fn execve_true() -> Result<()> {
        let prog = c"/bin/true";
        let argv = [prog.as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        // SAFETY: NUL-terminated program and null-terminated argv and envp.
        check(unsafe { libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr()) }).map(drop)
    }

    /// `ptrace(PTRACE_TRACEME)`.
    pub fn ptrace_traceme() -> Result<()> {
        // SAFETY: TRACEME takes no pointers.
        check_long(unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) }).map(drop)
    }

    /// `mmap` of one anonymous executable page.
    pub fn mmap_exec() -> Result<()> {
        // SAFETY: an anonymous mapping at no fixed address; unmapped at once.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(last());
        }
        // SAFETY: p is the page just mapped.
        unsafe { libc::munmap(p, 4096) };
        Ok(())
    }
}
