// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::fmt;
#[cfg(target_os = "macos")]
use std::os::fd::IntoRawFd;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use libc::{c_int, c_void};

/// A host errno, as the host numbers it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HostErrno(pub i32);

impl fmt::Debug for HostErrno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, std::io::Error::from_raw_os_error(self.0))
    }
}

#[cfg(target_os = "linux")]
pub mod confine;
#[cfg(target_os = "macos")]
pub mod seatbelt;
pub mod launch;

/// What every call here returns.
pub type Result<T> = std::result::Result<T, HostErrno>;

fn last() -> HostErrno {
    HostErrno(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
}

/// `name` as a C string: EINVAL if it holds a NUL (a checked name never
/// does).
fn cstr(name: &[u8]) -> Result<CString> {
    CString::new(name).map_err(|_| HostErrno(libc::EINVAL))
}

/// A system call's `int` result: the value, or errno.
fn check(ret: c_int) -> Result<c_int> {
    if ret < 0 { Err(last()) } else { Ok(ret) }
}

/// A descriptor a call returned, owned from here on.
fn owned(fd: c_int) -> Result<OwnedFd> {
    let fd = check(fd)?;
    // SAFETY: the call just returned this descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn u64_of_i64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn nsec(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(0)
}

/// Host errno values the caller compares against.
pub mod errno {
    pub use libc::{
        EACCES, EBADF, EEXIST, EINVAL, EIO, EISDIR, ELOOP, ENAMETOOLONG, ENODATA, ENOENT, ENOSPC,
        ENOSYS, ENOTDIR, ENOTEMPTY, ENOTSUP, EOPNOTSUPP, EPERM, ERANGE, EXDEV,
    };
    /// What an open that would leave its directory returns: Linux's
    /// `openat2(RESOLVE_BENEATH)` EXDEV, macOS's `O_RESOLVE_BENEATH`
    /// ENOTCAPABLE.
    #[cfg(target_os = "linux")]
    pub const BENEATH_REFUSAL: i32 = libc::EXDEV;
    /// What an open that would leave its directory returns: Linux's
    /// `openat2(RESOLVE_BENEATH)` EXDEV, macOS's `O_RESOLVE_BENEATH`
    /// ENOTCAPABLE, from macOS 26 (xnu-12377). macOS 15 (xnu-11417, the
    /// first with the flag) gives EACCES instead, which is also a plain
    /// permission refusal's ([`super::probe_beneath`]): there a refusal by
    /// the flag is not told apart, and the guest gets EACCES either way.
    #[cfg(target_os = "macos")]
    pub const BENEATH_REFUSAL: i32 = libc::ENOTCAPABLE;
    /// macOS's "no such attribute".
    #[cfg(target_os = "macos")]
    pub use libc::ENOATTR;
}

/// The number Linux gives the error `e` (`include/uapi/asm-generic/errno*.h`),
/// for the guest. Linux: the same number. macOS: its counterpart; an error
/// with none is EIO (5). `ENOTCAPABLE` is not here: it is a layer-2 refusal,
/// which the caller reports as one before mapping.
pub fn linux_errno(e: HostErrno) -> i32 {
    #[cfg(target_os = "linux")]
    return e.0;
    #[cfg(target_os = "macos")]
    MAC_TO_LINUX.iter().find(|&&(m, _)| m == e.0).map_or(5, |&(_, l)| l)
}

/// macOS errno → Linux errno, each pair checked against libc's macOS value
/// (`test_mac_errno_table`). Errors the backends can see; the rest are EIO.
#[cfg(target_os = "macos")]
pub const MAC_TO_LINUX: &[(i32, i32)] = &[
    (libc::EPERM, 1),
    (libc::ENOENT, 2),
    (libc::EINTR, 4),
    (libc::EIO, 5),
    (libc::ENXIO, 6),
    (libc::E2BIG, 7),
    (libc::EBADF, 9),
    (libc::EAGAIN, 11),
    (libc::ENOMEM, 12),
    (libc::EACCES, 13),
    (libc::EBUSY, 16),
    (libc::EEXIST, 17),
    (libc::EXDEV, 18),
    (libc::ENODEV, 19),
    (libc::ENOTDIR, 20),
    (libc::EISDIR, 21),
    (libc::EINVAL, 22),
    (libc::ENFILE, 23),
    (libc::EMFILE, 24),
    (libc::ENOTTY, 25),
    (libc::ETXTBSY, 26),
    (libc::EFBIG, 27),
    (libc::ENOSPC, 28),
    (libc::ESPIPE, 29),
    (libc::EROFS, 30),
    (libc::EMLINK, 31),
    (libc::ERANGE, 34),
    (libc::ENAMETOOLONG, 36),
    (libc::ENOSYS, 38),
    (libc::ENOTEMPTY, 39),
    (libc::ELOOP, 40),
    // macOS's "no such attribute" is Linux's ENODATA.
    (libc::ENOATTR, 61),
    (libc::EOVERFLOW, 75),
    (libc::EILSEQ, 84),
    // Both of macOS's "not supported" are Linux's EOPNOTSUPP (= ENOTSUP).
    (libc::ENOTSUP, 95),
    (libc::EOPNOTSUPP, 95),
    (libc::ETIMEDOUT, 110),
    (libc::ESTALE, 116),
    (libc::EDQUOT, 122),
    // "Inappropriate file type or format": an argument of the wrong kind.
    (libc::EFTYPE, 22),
];

/// File type bits of [`Stat::mode`] (macOS's `mode_t` is 16 bits, Linux's
/// 32).
#[allow(clippy::unnecessary_cast)]
pub mod mode {
    /// The type mask.
    pub const S_IFMT: u32 = libc::S_IFMT as u32;
    /// A directory.
    pub const S_IFDIR: u32 = libc::S_IFDIR as u32;
    /// A regular file.
    pub const S_IFREG: u32 = libc::S_IFREG as u32;
    /// A symbolic link.
    pub const S_IFLNK: u32 = libc::S_IFLNK as u32;
}

/// What `fstat` says of an object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    /// Its device.
    pub dev: u64,
    /// Its inode number.
    pub ino: u64,
    /// Type and permission bits.
    pub mode: u32,
    /// Links.
    pub nlink: u64,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Size in bytes.
    pub size: u64,
    /// 512-byte blocks allocated.
    pub blocks: u64,
    /// Access time (seconds, nanoseconds).
    pub atime: (i64, u32),
    /// Modification time.
    pub mtime: (i64, u32),
    /// Status change time.
    pub ctime: (i64, u32),
}

impl Stat {
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    fn from_raw(st: &libc::stat) -> Stat {
        Stat {
            dev: dev_of(st),
            ino: u64::from(st.st_ino),
            mode: u32::from(st.st_mode),
            nlink: u64::from(st.st_nlink),
            uid: st.st_uid,
            gid: st.st_gid,
            size: u64_of_i64(st.st_size),
            blocks: u64_of_i64(st.st_blocks),
            atime: (st.st_atime, nsec(st.st_atime_nsec)),
            mtime: (st.st_mtime, nsec(st.st_mtime_nsec)),
            ctime: (st.st_ctime, nsec(st.st_ctime_nsec)),
        }
    }
}

/// Linux's `dev_t` is a u64.
#[cfg(target_os = "linux")]
fn dev_of(st: &libc::stat) -> u64 {
    st.st_dev
}

/// macOS's `dev_t` is an i32: its bits, not its value.
#[cfg(target_os = "macos")]
fn dev_of(st: &libc::stat) -> u64 {
    u64::from(u32::from_ne_bytes(st.st_dev.to_ne_bytes()))
}

/// `fstat(fd)`.
pub fn fstat(fd: BorrowedFd<'_>) -> Result<Stat> {
    // SAFETY: `stat` is plain data; fstat fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and output buffer.
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(Stat::from_raw(&st))
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`: the object `name` names
/// beneath `dir`, a link itself rather than what it names.
pub fn fstatat(dir: BorrowedFd<'_>, name: &[u8]) -> Result<Stat> {
    let name = cstr(name)?;
    // SAFETY: as in `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor, C string and output buffer.
    check(unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(Stat::from_raw(&st))
}

/// Linux's `struct open_how` (`include/uapi/linux/openat2.h`); libc's is
/// `non_exhaustive`, so it cannot be built here.
#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Opens `name` beneath `dir` with `flags`, never following a link and
/// never leaving `dir`; always close-on-exec, non-blocking (a FIFO a host
/// swapped in never blocks the server) and without a controlling terminal.
#[cfg(target_os = "linux")]
fn open_beneath(dir: BorrowedFd<'_>, name: &[u8], flags: c_int, mode: u32) -> Result<OwnedFd> {
    let name = cstr(name)?;
    let flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_NONBLOCK;
    let how = OpenHow {
        flags: u64::from(u32::from_ne_bytes(flags.to_ne_bytes())),
        mode: if flags & libc::O_CREAT != 0 { u64::from(mode) } else { 0 },
        resolve: libc::RESOLVE_BENEATH
            | libc::RESOLVE_NO_SYMLINKS
            | libc::RESOLVE_NO_MAGICLINKS
            | libc::RESOLVE_NO_XDEV,
    };
    // SAFETY: openat2 with a valid descriptor, C string and `open_how` of
    // the size passed; it returns a new descriptor or -1.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    owned(c_int::try_from(ret).map_err(|_| HostErrno(libc::EIO))?)
}

/// `O_RESOLVE_BENEATH` (macOS SDK `sys/fcntl.h`: xnu-11417 and later; not
/// in the libc crate).
#[cfg(target_os = "macos")]
const O_RESOLVE_BENEATH: c_int = 0x0000_1000;

/// Opens `name` beneath `dir` with `flags`, never following a link and
/// never leaving `dir`; always close-on-exec, non-blocking (a FIFO a host
/// swapped in never blocks the server) and without a controlling terminal.
#[cfg(target_os = "macos")]
fn open_beneath(dir: BorrowedFd<'_>, name: &[u8], flags: c_int, mode: u32) -> Result<OwnedFd> {
    let name = cstr(name)?;
    // O_NOFOLLOW_ANY covers the last component too; with O_NOFOLLOW as
    // well, macOS 27.2 refuses the open (EINVAL).
    let flags = flags
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW_ANY
        | O_RESOLVE_BENEATH
        | libc::O_NOCTTY
        | libc::O_NONBLOCK;
    // SAFETY: openat with a valid descriptor and C string; the mode is
    // passed as the variadic `int` it is read as.
    owned(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, libc::c_uint::from(mode)) })
}

/// Opens the share's root, `path`, for reading: a directory, and not a
/// link at its last component (stage 0 passes the canonical path, which has
/// none elsewhere).
pub fn open_root(path: &std::path::Path) -> Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let path = cstr(path.as_os_str().as_bytes())?;
    // SAFETY: a valid C string; open returns a new descriptor or -1.
    owned(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    })
}

/// Opens the directory `name` beneath `dir` for reading.
pub fn open_dir(dir: BorrowedFd<'_>, name: &[u8]) -> Result<OwnedFd> {
    open_beneath(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

/// Opens `dir` itself again, for reading (`.` beneath it).
pub fn reopen_dir(dir: BorrowedFd<'_>) -> Result<OwnedFd> {
    open_beneath(dir, b".", libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

/// Opens the non-directory `name` beneath `dir`: for reading, writing or
/// both (neither is reading). Never with the guest's other flags: no
/// `O_APPEND`, `O_TRUNC`, `O_DIRECT` or `O_SYNC` reaches the host.
pub fn open_file(dir: BorrowedFd<'_>, name: &[u8], read: bool, write: bool) -> Result<OwnedFd> {
    let access = match (read, write) {
        (_, false) => libc::O_RDONLY,
        (false, true) => libc::O_WRONLY,
        (true, true) => libc::O_RDWR,
    };
    open_beneath(dir, name, access, 0)
}

/// Creates (or, unless `exclusive`, opens) the regular file `name` beneath
/// `dir`, read-write, with `mode` (less the umask) if it is new.
pub fn create_file(dir: BorrowedFd<'_>, name: &[u8], exclusive: bool, mode: u32) -> Result<OwnedFd> {
    let excl = if exclusive { libc::O_EXCL } else { 0 };
    open_beneath(dir, name, libc::O_RDWR | libc::O_CREAT | excl, mode)
}

/// Whether this host's beneath-resolution is there: an open of `..` beneath
/// `dir` must be refused. The error it is refused with is returned:
/// [`errno::BENEATH_REFUSAL`], or on macOS 15 EACCES. Linux before 5.6 (or
/// a seccomp filter without `openat2`) gives ENOSYS; a macOS without
/// `O_RESOLVE_BENEATH` ignores the flag and opens the parent, which is
/// returned as EINVAL here. Either way the caller refuses to serve.
///
/// xnu-11417 (macOS 15) refuses `..` at the starting directory, an absolute
/// path and a link to one with EACCES; xnu-12377 (macOS 26) made each
/// ENOTCAPABLE (bsd/vfs/vfs_lookup.c, `lookup` and `namei`) [src]. EACCES
/// for `..` could also be a permission refusal, so on macOS 15 the flag is
/// confirmed by an absolute path, which `namei` refuses before it looks
/// anything up or checks any permission: an EACCES there is the flag's.
pub fn probe_beneath(dir: BorrowedFd<'_>) -> Result<i32> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    match open_beneath(dir, b"..", flags, 0) {
        Err(e) if e.0 == errno::BENEATH_REFUSAL => Ok(e.0),
        #[cfg(target_os = "macos")]
        Err(e) if e.0 == libc::EACCES => match open_beneath(dir, b"/", flags, 0) {
            Err(abs) if abs.0 == libc::EACCES => Ok(libc::EACCES),
            Err(abs) => Err(abs),
            Ok(_) => Err(HostErrno(libc::EINVAL)),
        },
        Err(e) => Err(e),
        Ok(_) => Err(HostErrno(libc::EINVAL)),
    }
}

/// `mkdirat(dir, name, mode)`.
pub fn mkdirat(dir: BorrowedFd<'_>, name: &[u8], mode: u32) -> Result<()> {
    let name = cstr(name)?;
    let mode = libc::mode_t::try_from(mode).map_err(|_| HostErrno(libc::EINVAL))?;
    // SAFETY: a valid descriptor and C string.
    check(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) }).map(drop)
}

/// `unlinkat(dir, name)`, with `AT_REMOVEDIR` for a directory.
pub fn unlinkat(dir: BorrowedFd<'_>, name: &[u8], is_dir: bool) -> Result<()> {
    let name = cstr(name)?;
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: a valid descriptor and C string.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) }).map(drop)
}

/// Renames `from` beneath `from_dir` to `to` beneath `to_dir`: with
/// `noreplace`, EEXIST if `to` exists; with `exchange`, the two swap
/// atomically. Linux `renameat2(RENAME_NOREPLACE / RENAME_EXCHANGE)`, macOS
/// `renameatx_np(RENAME_EXCL / RENAME_SWAP)`. A file system without the flag
/// gives EINVAL on Linux and ENOTSUP on macOS.
pub fn rename(
    from_dir: BorrowedFd<'_>,
    from: &[u8],
    to_dir: BorrowedFd<'_>,
    to: &[u8],
    noreplace: bool,
    exchange: bool,
) -> Result<()> {
    let from = cstr(from)?;
    let to = cstr(to)?;
    rename_raw(from_dir.as_raw_fd(), &from, to_dir.as_raw_fd(), &to, noreplace, exchange)
}

#[cfg(target_os = "linux")]
fn rename_raw(fd: c_int, from: &CString, td: c_int, to: &CString, noreplace: bool, exchange: bool) -> Result<()> {
    const RENAME_NOREPLACE: libc::c_uint = 1;
    const RENAME_EXCHANGE: libc::c_uint = 2;
    let flags = if noreplace { RENAME_NOREPLACE } else { 0 } | if exchange { RENAME_EXCHANGE } else { 0 };
    // SAFETY: renameat2 with valid descriptors and C strings.
    let ret = unsafe { libc::syscall(libc::SYS_renameat2, fd, from.as_ptr(), td, to.as_ptr(), flags) };
    check(c_int::try_from(ret).map_err(|_| HostErrno(libc::EIO))?).map(drop)
}

#[cfg(target_os = "macos")]
fn rename_raw(fd: c_int, from: &CString, td: c_int, to: &CString, noreplace: bool, exchange: bool) -> Result<()> {
    let flags = if noreplace { libc::RENAME_EXCL } else { 0 } | if exchange { libc::RENAME_SWAP } else { 0 };
    // SAFETY: renameatx_np with valid descriptors and C strings.
    check(unsafe { libc::renameatx_np(fd, from.as_ptr(), td, to.as_ptr(), flags) }).map(drop)
}

/// `linkat(from_dir, from, to_dir, to, 0)`: a new name for `from` itself,
/// a link never followed.
pub fn linkat(from_dir: BorrowedFd<'_>, from: &[u8], to_dir: BorrowedFd<'_>, to: &[u8]) -> Result<()> {
    let from = cstr(from)?;
    let to = cstr(to)?;
    // SAFETY: valid descriptors and C strings.
    check(unsafe { libc::linkat(from_dir.as_raw_fd(), from.as_ptr(), to_dir.as_raw_fd(), to.as_ptr(), 0) })
        .map(drop)
}

/// The target of the symlink `name` beneath `dir`: at most `max` bytes,
/// ENAMETOOLONG beyond.
pub fn readlinkat(dir: BorrowedFd<'_>, name: &[u8], max: usize) -> Result<Vec<u8>> {
    let name = cstr(name)?;
    let mut buf = vec![0u8; max.saturating_add(1)];
    // SAFETY: a valid descriptor, C string and a buffer of the length passed.
    let n = unsafe { libc::readlinkat(dir.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    let n = usize::try_from(n).map_err(|_| last())?;
    if n > max {
        return Err(HostErrno(libc::ENAMETOOLONG));
    }
    buf.truncate(n);
    Ok(buf)
}

/// `symlinkat(target, dir, name)`: tests, which put host-made links in a
/// share. The server never makes one.
pub fn symlinkat(target: &[u8], dir: BorrowedFd<'_>, name: &[u8]) -> Result<()> {
    let target = cstr(target)?;
    let name = cstr(name)?;
    // SAFETY: valid C strings and descriptor.
    check(unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), name.as_ptr()) }).map(drop)
}

/// `mkfifoat(dir, name, mode)`: tests, which put a host-made FIFO in a
/// share. The server never makes one.
pub fn mkfifoat(dir: BorrowedFd<'_>, name: &[u8], mode: u32) -> Result<()> {
    let name = cstr(name)?;
    let mode = libc::mode_t::try_from(mode).map_err(|_| HostErrno(libc::EINVAL))?;
    // SAFETY: a valid descriptor and C string.
    check(unsafe { libc::mkfifoat(dir.as_raw_fd(), name.as_ptr(), mode) }).map(drop)
}

/// `fchmod(fd, mode)`, permission bits only: a mode with set-user-id,
/// set-group-id or sticky is refused (EINVAL) before the call. The server
/// keeps a guest's special bits in its record and never gives them to a
/// host object; confined, Linux's filter kills such an `fchmod` and macOS's
/// profile (`file-write-setugid`) drops the bit without an error, so a call
/// that relied on it would differ by host, silently on one.
pub fn fchmod(fd: BorrowedFd<'_>, mode: u32) -> Result<()> {
    if mode & !0o777 != 0 {
        return Err(HostErrno(libc::EINVAL));
    }
    let mode = libc::mode_t::try_from(mode).map_err(|_| HostErrno(libc::EINVAL))?;
    // SAFETY: a valid descriptor.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode) }).map(drop)
}

/// The file status flags of `fd` (`F_GETFL`): tests check that no guest
/// flag reached the host.
pub fn status_flags(fd: BorrowedFd<'_>) -> Result<i32> {
    // SAFETY: F_GETFL on a valid descriptor.
    check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })
}

/// The host's `O_APPEND`, `O_SYNC` and (Linux) `O_DIRECT`, for those tests.
pub fn guest_only_flags() -> i32 {
    #[cfg(target_os = "linux")]
    let direct = libc::O_DIRECT;
    #[cfg(target_os = "macos")]
    let direct = 0;
    libc::O_APPEND | libc::O_SYNC | libc::O_TRUNC | direct
}

fn timespec(t: Option<(i64, u32)>) -> libc::timespec {
    match t {
        Some((secs, nsecs)) => libc::timespec {
            tv_sec: secs,
            tv_nsec: libc::c_long::from(nsecs),
        },
        None => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    }
}

/// `futimens(fd, [atime, mtime])`; `None` leaves that time as it is.
pub fn futimens(fd: BorrowedFd<'_>, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<()> {
    let times = [timespec(atime), timespec(mtime)];
    // SAFETY: a valid descriptor and two timespecs.
    check(unsafe { libc::futimens(fd.as_raw_fd(), times.as_ptr()) }).map(drop)
}

/// `fsync`/`fdatasync`. On macOS both are `F_FULLFSYNC`, which asks the
/// drive to write its cache to stable storage, as Linux's fsync does;
/// macOS's own `fsync` only hands the data to the drive (fsync(2)). A file
/// system without `F_FULLFSYNC` (ENOTSUP) gets `fsync`, the most it has.
pub fn fsync(fd: BorrowedFd<'_>, data_only: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a valid descriptor.
        let ret = unsafe {
            if data_only {
                libc::fdatasync(fd.as_raw_fd())
            } else {
                libc::fsync(fd.as_raw_fd())
            }
        };
        check(ret).map(drop)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = data_only;
        // SAFETY: F_FULLFSYNC on a valid descriptor.
        match check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_FULLFSYNC) }) {
            Err(HostErrno(libc::ENOTSUP)) => {
                // SAFETY: a valid descriptor.
                check(unsafe { libc::fsync(fd.as_raw_fd()) }).map(drop)
            }
            r => r.map(drop),
        }
    }
}

/// Linux `fallocate` with mode `0`, `FALLOC_FL_KEEP_SIZE` or
/// `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`.
#[cfg(target_os = "linux")]
pub fn fallocate(fd: BorrowedFd<'_>, offset: u64, len: u64, keep_size: bool, punch: bool) -> Result<()> {
    let offset = i64::try_from(offset).map_err(|_| HostErrno(libc::EFBIG))?;
    let len = i64::try_from(len).map_err(|_| HostErrno(libc::EFBIG))?;
    let mut mode = if keep_size { libc::FALLOC_FL_KEEP_SIZE } else { 0 };
    if punch {
        mode |= libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
    }
    // SAFETY: a valid descriptor.
    check(unsafe { libc::fallocate(fd.as_raw_fd(), mode, offset, len) }).map(drop)
}

/// macOS: Linux's `fallocate` semantics for mode `0`, `FALLOC_FL_KEEP_SIZE`
/// and `PUNCH_HOLE | KEEP_SIZE`, as `crates/compat/libc`'s `fallocate` does
/// it for the VMM: holes inside the range filled with zeros and the space
/// past the end reserved with `F_PREALLOCATE`; a punch frees whole blocks
/// with `F_PUNCHHOLE` and zeroes the partial ones at the edges.
#[cfg(target_os = "macos")]
pub fn fallocate(fd: BorrowedFd<'_>, offset: u64, len: u64, keep_size: bool, punch: bool) -> Result<()> {
    let offset = i64::try_from(offset).map_err(|_| HostErrno(libc::EFBIG))?;
    let len = i64::try_from(len).map_err(|_| HostErrno(libc::EFBIG))?;
    let end = offset.checked_add(len).ok_or(HostErrno(libc::EFBIG))?;
    if punch {
        mac::punch_hole(fd.as_raw_fd(), offset, end)
    } else {
        mac::allocate(fd.as_raw_fd(), offset, end, keep_size)
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use super::{Result, check, last};
    use libc::{c_int, off_t};

    #[repr(C)]
    struct FPunchHole {
        fp_flags: u32,
        reserved: u32,
        fp_offset: off_t,
        fp_length: off_t,
    }

    #[repr(C)]
    struct FStore {
        fst_flags: u32,
        fst_posmode: c_int,
        fst_offset: off_t,
        fst_length: off_t,
        fst_bytesalloc: off_t,
    }

    const F_PUNCHHOLE: c_int = 99;
    const F_PREALLOCATE: c_int = 42;
    const F_ALLOCATEALL: u32 = 4;
    const F_PEOFPOSMODE: c_int = 3;

    fn size(fd: c_int) -> Result<off_t> {
        // SAFETY: plain data, filled by fstat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and buffer.
        check(unsafe { libc::fstat(fd, &mut st) })?;
        Ok(st.st_size)
    }

    fn write_zeros(fd: c_int, mut start: off_t, end: off_t) -> Result<()> {
        static ZEROS: [u8; 65536] = [0; 65536];
        while start < end {
            let n = usize::try_from(end - start).unwrap_or(usize::MAX).min(ZEROS.len());
            // SAFETY: reads `n` bytes of a static buffer.
            let ret = unsafe { libc::pwrite(fd, ZEROS.as_ptr().cast(), n, start) };
            if ret < 0 {
                let e = last();
                if e.0 == libc::EINTR {
                    continue;
                }
                return Err(e);
            }
            start += off_t::try_from(ret).unwrap_or(0);
        }
        Ok(())
    }

    pub(super) fn punch_hole(fd: c_int, offset: off_t, end: off_t) -> Result<()> {
        let end = end.min(size(fd)?);
        if offset >= end {
            return Ok(());
        }
        // SAFETY: plain data, filled by fstatfs.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and buffer.
        check(unsafe { libc::fstatfs(fd, &mut fs) })?;
        let bs = off_t::from(fs.f_bsize.max(1));
        let first = (offset + bs - 1) / bs * bs;
        let last = end / bs * bs;
        if first >= last {
            return write_zeros(fd, offset, end);
        }
        let arg = FPunchHole {
            fp_flags: 0,
            reserved: 0,
            fp_offset: first,
            fp_length: last - first,
        };
        // SAFETY: a valid descriptor and argument.
        check(unsafe { libc::fcntl(fd, F_PUNCHHOLE, &arg as *const FPunchHole) })?;
        write_zeros(fd, offset, first)?;
        write_zeros(fd, last, end)
    }

    /// The holes of `[from, to)` (within the file) as data: zeros.
    fn fill_holes(fd: c_int, from: off_t, to: off_t) -> Result<()> {
        let mut pos = from;
        while pos < to {
            // SAFETY: lseek on a valid descriptor; the server never uses
            // the file offset (it reads and writes at offsets).
            let hole = unsafe { libc::lseek(fd, pos, libc::SEEK_HOLE) };
            if hole < 0 {
                return Err(last());
            }
            if hole >= to {
                return Ok(());
            }
            // SAFETY: as above.
            let data = unsafe { libc::lseek(fd, hole, libc::SEEK_DATA) };
            let hole_end = if data >= 0 {
                data.min(to)
            } else if last().0 == libc::ENXIO {
                to
            } else {
                return Err(last());
            };
            write_zeros(fd, hole, hole_end)?;
            pos = hole_end;
        }
        Ok(())
    }

    pub(super) fn allocate(fd: c_int, offset: off_t, end: off_t, keep_size: bool) -> Result<()> {
        let size = size(fd)?;
        fill_holes(fd, offset, end.min(size))?;
        if end > size {
            let mut store = FStore {
                fst_flags: F_ALLOCATEALL,
                fst_posmode: F_PEOFPOSMODE,
                fst_offset: 0,
                fst_length: end - size,
                fst_bytesalloc: 0,
            };
            // SAFETY: a valid descriptor and argument.
            check(unsafe { libc::fcntl(fd, F_PREALLOCATE, &mut store as *mut FStore) })?;
            if !keep_size {
                // SAFETY: a valid descriptor.
                check(unsafe { libc::ftruncate(fd, end) })?;
            }
        }
        Ok(())
    }
}

/// Extended attribute calls by descriptor (macOS has no `*at` forms, and a
/// descriptor never follows a link).
pub mod xattr {
    use super::{HostErrno, Result, check, cstr, last};
    use libc::{c_int, c_void};
    use std::os::fd::{AsRawFd, BorrowedFd};

    /// "No such attribute": Linux's ENODATA, macOS's ENOATTR.
    #[cfg(target_os = "linux")]
    pub const NO_ATTR: i32 = libc::ENODATA;
    /// "No such attribute": Linux's ENODATA, macOS's ENOATTR.
    #[cfg(target_os = "macos")]
    pub const NO_ATTR: i32 = libc::ENOATTR;

    #[cfg(target_os = "linux")]
    fn get_raw(fd: c_int, name: *const libc::c_char, buf: *mut c_void, len: usize) -> isize {
        // SAFETY: the caller passes a valid name and a buffer of `len` bytes
        // (or null with 0).
        unsafe { libc::fgetxattr(fd, name, buf, len) }
    }

    #[cfg(target_os = "macos")]
    fn get_raw(fd: c_int, name: *const libc::c_char, buf: *mut c_void, len: usize) -> isize {
        // SAFETY: as above; position 0, no options.
        unsafe { libc::fgetxattr(fd, name, buf, len, 0, 0) }
    }

    #[cfg(target_os = "linux")]
    fn list_raw(fd: c_int, buf: *mut libc::c_char, len: usize) -> isize {
        // SAFETY: a buffer of `len` bytes (or null with 0).
        unsafe { libc::flistxattr(fd, buf, len) }
    }

    #[cfg(target_os = "macos")]
    fn list_raw(fd: c_int, buf: *mut libc::c_char, len: usize) -> isize {
        // SAFETY: as above.
        unsafe { libc::flistxattr(fd, buf, len, 0) }
    }

    /// The value of `name`, or `None` if `fd` has none.
    pub fn get(fd: BorrowedFd<'_>, name: &[u8]) -> Result<Option<Vec<u8>>> {
        let name = cstr(name)?;
        // The size may change between the two calls: retry on ERANGE.
        for _ in 0..8 {
            let len = get_raw(fd.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0);
            let Ok(len) = usize::try_from(len) else {
                let e = last();
                return if e.0 == NO_ATTR { Ok(None) } else { Err(e) };
            };
            let mut buf = vec![0u8; len];
            let n = get_raw(fd.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len());
            match usize::try_from(n) {
                Ok(n) => {
                    buf.truncate(n);
                    return Ok(Some(buf));
                }
                Err(_) => {
                    let e = last();
                    match e.0 {
                        libc::ERANGE => continue,
                        x if x == NO_ATTR => return Ok(None),
                        _ => return Err(e),
                    }
                }
            }
        }
        Err(HostErrno(libc::ERANGE))
    }

    /// Sets `name`: with `create`, EEXIST if it exists; with `replace`,
    /// [`NO_ATTR`] if it does not.
    pub fn set(fd: BorrowedFd<'_>, name: &[u8], value: &[u8], create: bool, replace: bool) -> Result<()> {
        let name = cstr(name)?;
        let flags = if create { libc::XATTR_CREATE } else { 0 } | if replace { libc::XATTR_REPLACE } else { 0 };
        #[cfg(target_os = "linux")]
        // SAFETY: a valid name and a value of the length passed.
        let ret = unsafe { libc::fsetxattr(fd.as_raw_fd(), name.as_ptr(), value.as_ptr().cast(), value.len(), flags) };
        #[cfg(target_os = "macos")]
        // SAFETY: as above; position 0.
        let ret = unsafe { libc::fsetxattr(fd.as_raw_fd(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0, flags) };
        check(ret).map(drop)
    }

    /// Every attribute name of `fd`.
    pub fn list(fd: BorrowedFd<'_>) -> Result<Vec<Vec<u8>>> {
        for _ in 0..8 {
            let len = list_raw(fd.as_raw_fd(), std::ptr::null_mut(), 0);
            let len = usize::try_from(len).map_err(|_| last())?;
            let mut buf = vec![0u8; len];
            let n = list_raw(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len());
            match usize::try_from(n) {
                Ok(n) => {
                    buf.truncate(n);
                    return Ok(buf
                        .split(|&b| b == 0)
                        .filter(|n| !n.is_empty())
                        .map(<[u8]>::to_vec)
                        .collect());
                }
                Err(_) if last().0 == libc::ERANGE => continue,
                Err(_) => return Err(last()),
            }
        }
        Err(HostErrno(libc::ERANGE))
    }

    /// Removes `name` ([`NO_ATTR`] if absent).
    pub fn remove(fd: BorrowedFd<'_>, name: &[u8]) -> Result<()> {
        let name = cstr(name)?;
        #[cfg(target_os = "linux")]
        // SAFETY: a valid name.
        let ret = unsafe { libc::fremovexattr(fd.as_raw_fd(), name.as_ptr()) };
        #[cfg(target_os = "macos")]
        // SAFETY: a valid name; no options.
        let ret = unsafe { libc::fremovexattr(fd.as_raw_fd(), name.as_ptr(), 0) };
        check(ret).map(drop)
    }
}

/// A file system's sizes (`fstatvfs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatVfs {
    /// Blocks of `frsize` bytes.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks for an unprivileged user.
    pub bavail: u64,
    /// Inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Preferred I/O size.
    pub bsize: u64,
    /// The unit of the block counts.
    pub frsize: u64,
}

/// `fstatvfs(fd)`.
#[allow(clippy::useless_conversion)]
pub fn fstatvfs(fd: BorrowedFd<'_>) -> Result<StatVfs> {
    // SAFETY: plain data, filled by fstatvfs.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and buffer.
    check(unsafe { libc::fstatvfs(fd.as_raw_fd(), &mut s) })?;
    Ok(StatVfs {
        blocks: u64::from(s.f_blocks),
        bfree: u64::from(s.f_bfree),
        bavail: u64::from(s.f_bavail),
        files: u64::from(s.f_files),
        ffree: u64::from(s.f_ffree),
        bsize: u64::from(s.f_bsize),
        frsize: u64::from(s.f_frsize),
    })
}

/// The file system's type: Linux `statfs`'s `f_type` magic as hex, macOS
/// `f_fstypename` (`apfs`, `hfs`, `msdos`, ...).
pub fn fs_type(fd: BorrowedFd<'_>) -> Result<String> {
    // SAFETY: plain data, filled by fstatfs.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and buffer.
    check(unsafe { libc::fstatfs(fd.as_raw_fd(), &mut s) })?;
    #[cfg(target_os = "linux")]
    return Ok(format!("{:#x}", s.f_type));
    #[cfg(target_os = "macos")]
    {
        let name: Vec<u8> = s
            .f_fstypename
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| u8::from_ne_bytes(c.to_ne_bytes()))
            .collect();
        Ok(String::from_utf8_lossy(&name).into_owned())
    }
}

/// Whether names in the directory `fd` are compared case-sensitively.
/// macOS: `fpathconf(_PC_CASE_SENSITIVE)`. Linux: false for a directory
/// with ext4's or f2fs's casefold flag (`FS_CASEFOLD_FL`) and for vfat and
/// exfat, which fold case on every directory.
pub fn case_sensitive(fd: BorrowedFd<'_>) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: fpathconf on a valid descriptor.
        let v = unsafe { libc::fpathconf(fd.as_raw_fd(), libc::_PC_CASE_SENSITIVE) };
        if v < 0 {
            return Err(last());
        }
        Ok(v == 1)
    }
    #[cfg(target_os = "linux")]
    {
        const MSDOS_SUPER_MAGIC: &str = "0x4d44";
        const EXFAT_SUPER_MAGIC: &str = "0x2011bab0";
        let ty = fs_type(fd)?;
        if ty == MSDOS_SUPER_MAGIC || ty == EXFAT_SUPER_MAGIC {
            return Ok(false);
        }
        Ok(!casefold(fd)?)
    }
}

/// Linux: whether the directory `fd` has the casefold flag
/// (`FS_IOC_GETFLAGS`, `FS_CASEFOLD_FL`). A file system without inode
/// flags (ENOTTY, EINVAL, ENOTSUP) has none.
#[cfg(target_os = "linux")]
pub fn casefold(fd: BorrowedFd<'_>) -> Result<bool> {
    // _IOR('f', 1, long) (include/uapi/linux/fs.h).
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
    const FS_CASEFOLD_FL: libc::c_long = 0x4000_0000;
    let mut flags: libc::c_long = 0;
    // SAFETY: FS_IOC_GETFLAGS writes an int into the (larger, zeroed) long.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags as *mut libc::c_long) };
    if ret < 0 {
        let e = last();
        return match e.0 {
            libc::ENOTTY | libc::EINVAL | libc::ENOTSUP => Ok(false),
            _ => Err(e),
        };
    }
    Ok(flags & FS_CASEFOLD_FL != 0)
}

/// macOS: the name `name` beneath `dir` is stored as (`getattrlistat`,
/// `ATTR_CMN_NAME`, not following a link): on a volume that folds case or
/// normalization (APFS always folds normalization) a lookup by one name
/// finds an object stored under another.
#[cfg(target_os = "macos")]
pub fn stored_name(dir: BorrowedFd<'_>, name: &[u8]) -> Result<Vec<u8>> {
    // FSOPT_NOFOLLOW (sys/attr.h).
    const FSOPT_NOFOLLOW: libc::c_ulong = 0x1;
    let cname = cstr(name)?;
    let mut list = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_NAME,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    // u32 length, attrreference_t, then up to NAME_MAX * 3 + 1 bytes.
    let mut buf = vec![0u8; 4 + 8 + 1024 * 3 + 1];
    // SAFETY: a valid descriptor, C string, attribute list and a buffer of
    // the length passed.
    check(unsafe {
        libc::getattrlistat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            (&mut list as *mut libc::attrlist).cast::<c_void>(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            FSOPT_NOFOLLOW,
        )
    })?;
    // The reference is relative to its own position (offset 4).
    let field = |at: usize| buf.get(at..at + 4).map(|b| [b[0], b[1], b[2], b[3]]);
    let bad = HostErrno(libc::EIO);
    let off = i32::from_ne_bytes(field(4).ok_or(bad)?);
    let len = u32::from_ne_bytes(field(8).ok_or(bad)?);
    let start = usize::try_from(4i64 + i64::from(off)).map_err(|_| bad)?;
    let len = usize::try_from(len).map_err(|_| bad)?;
    // The length counts the NUL.
    let stored = buf.get(start..start + len.saturating_sub(1)).ok_or(bad)?;
    Ok(stored.to_vec())
}

/// macOS: the volume's interface capabilities (`fgetattrlist`,
/// `ATTR_VOL_CAPABILITIES`): those it has, of those it reports on.
#[cfg(target_os = "macos")]
fn interfaces(fd: BorrowedFd<'_>) -> Result<(u32, u32)> {
    let mut list = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    // u32 length, then vol_capabilities_attr_t: capabilities[4], valid[4].
    let mut buf = [0u8; 4 + 32];
    // SAFETY: a valid descriptor, attribute list and buffer of the length
    // passed.
    check(unsafe {
        libc::fgetattrlist(
            fd.as_raw_fd(),
            (&mut list as *mut libc::attrlist).cast::<c_void>(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
        )
    })?;
    let word = |i: usize| u32::from_ne_bytes([buf[4 + i * 4], buf[5 + i * 4], buf[6 + i * 4], buf[7 + i * 4]]);
    Ok((word(libc::VOL_CAPABILITIES_INTERFACES), word(4 + libc::VOL_CAPABILITIES_INTERFACES)))
}

/// Whether the file system of `fd` stores extended attributes itself.
/// macOS: the volume's `VOL_CAP_INT_EXTENDED_ATTR`, as on a volume without
/// it (msdos, exfat) the kernel emulates them in `._` AppleDouble files next
/// to each file, which host tools and the share's listings would see. Linux:
/// an attribute read on `fd` is not ENOTSUP/EOPNOTSUPP.
pub fn xattr_native(fd: BorrowedFd<'_>, probe_name: &[u8]) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let _ = probe_name;
        let (caps, valid) = interfaces(fd)?;
        let bit = libc::VOL_CAP_INT_EXTENDED_ATTR;
        Ok(valid & bit != 0 && caps & bit != 0)
    }
    #[cfg(target_os = "linux")]
    {
        match xattr::get(fd, probe_name) {
            Ok(_) => Ok(true),
            Err(e) if e.0 == libc::ENOTSUP || e.0 == libc::EOPNOTSUPP => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Whether [`rename`]'s `exchange` may be asked of the file system of `fd`.
/// macOS: the volume reports `VOL_CAP_INT_RENAME_SWAP` and has it. xnu hands
/// `RENAME_SWAP` to the file system (`vn_rename`), which answers for it: a
/// volume without it may refuse it (msdos and exfat on macOS 27.2, served by
/// FSKit modules whose `renameItem` takes no swap: ENOTSUP) or, as msdos on
/// macOS 26.7.2 (25G332) did in CI run 44199005130, return 0 after a plain
/// rename that destroys the target, so the flag is never passed to a volume
/// that does not report it. `RENAME_EXCL` needs no such check: xnu's
/// `renameat_internal` refuses an existing target itself.
/// Linux: true, the file system refuses a flag it lacks (EINVAL).
pub fn rename_swap(fd: BorrowedFd<'_>) -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let (caps, valid) = interfaces(fd)?;
        let bit = libc::VOL_CAP_INT_RENAME_SWAP;
        Ok(valid & bit != 0 && caps & bit != 0)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = fd;
        Ok(true)
    }
}

/// Takes the inherited descriptor `fd` (a command line's `--ready-fd`):
/// EBADF unless it is open, and never one of the standard streams.
pub fn take_inherited(fd: i32) -> Result<OwnedFd> {
    if fd <= 2 {
        return Err(HostErrno(libc::EBADF));
    }
    // SAFETY: F_GETFD takes no pointer; it fails with EBADF if fd is not open.
    check(unsafe { libc::fcntl(fd, libc::F_GETFD) })?;
    // SAFETY: fd is open (checked above), was inherited for this process to
    // use, and nothing else in it owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The effective uid of this process.
pub fn euid() -> u32 {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() }
}

/// The real uid of this process.
pub fn uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

/// The real gid of this process.
pub fn gid() -> u32 {
    // SAFETY: getgid cannot fail.
    unsafe { libc::getgid() }
}

/// One directory entry as the host lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawEntry {
    /// The name's bytes.
    pub name: Vec<u8>,
    /// Its inode number.
    pub ino: u64,
    /// `DT_*`, as the host gives it (`DT_UNKNOWN` on some file systems).
    pub dtype: u8,
    /// Where a listing after this entry continues: 1 or more.
    pub cookie: u64,
}

/// `DT_*` values (the same on Linux and macOS).
pub mod dtype {
    /// Unknown: ask `fstatat`.
    pub const DT_UNKNOWN: u8 = libc::DT_UNKNOWN;
    /// A directory.
    pub const DT_DIR: u8 = libc::DT_DIR;
    /// A regular file.
    pub const DT_REG: u8 = libc::DT_REG;
    /// A symbolic link.
    pub const DT_LNK: u8 = libc::DT_LNK;
}

/// A directory being listed. Linux: `getdents64` from the entry's `d_off`
/// (`lseek`), so a cookie is the file system's own position. macOS: a
/// `readdir` stream, a cookie the count of entries read; a listing that does
/// not continue where the last stopped starts again and skips that many.
pub struct DirReader {
    #[cfg(target_os = "linux")]
    fd: OwnedFd,
    #[cfg(target_os = "linux")]
    buf: Vec<u8>,
    #[cfg(target_os = "macos")]
    dir: std::ptr::NonNull<libc::DIR>,
    #[cfg(target_os = "macos")]
    pos: u64,
}

impl fmt::Debug for DirReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirReader").field("fd", &self.raw_fd()).finish()
    }
}

#[cfg(target_os = "linux")]
impl DirReader {
    /// A listing of the directory `fd` (opened for reading).
    pub fn new(fd: OwnedFd) -> Result<DirReader> {
        Ok(DirReader {
            fd,
            buf: vec![0u8; 32 << 10],
        })
    }

    fn raw_fd(&self) -> c_int {
        self.fd.as_raw_fd()
    }

    /// The directory's descriptor.
    pub fn fd(&self) -> BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.fd.as_fd()
    }

    /// Up to `max` entries after the one whose cookie is `after` (0: from
    /// the start), `.` and `..` left out.
    pub fn read(&mut self, after: u64, max: usize, out: &mut Vec<RawEntry>) -> Result<()> {
        let pos = libc::off_t::try_from(after).map_err(|_| HostErrno(libc::EINVAL))?;
        // SAFETY: lseek on a valid directory descriptor to a position the
        // file system gave (or 0).
        if unsafe { libc::lseek(self.fd.as_raw_fd(), pos, libc::SEEK_SET) } < 0 {
            return Err(last());
        }
        while out.len() < max {
            // SAFETY: getdents64 into a buffer of the length passed.
            let n = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast::<c_void>(),
                    self.buf.len(),
                )
            };
            let n = usize::try_from(n).map_err(|_| last())?;
            if n == 0 {
                return Ok(());
            }
            let mut at = 0;
            while at < n && out.len() < max {
                let e = parse_dirent64(&self.buf[at..n]).ok_or(HostErrno(libc::EIO))?;
                at += e.0;
                if let Some(entry) = e.1 {
                    out.push(entry);
                }
            }
        }
        Ok(())
    }
}

/// One `linux_dirent64` at the start of `b`: its length, and the entry
/// unless it is `.` or `..`. `None` for a record that does not fit.
#[cfg(target_os = "linux")]
fn parse_dirent64(b: &[u8]) -> Option<(usize, Option<RawEntry>)> {
    let ino = u64::from_ne_bytes(b.get(0..8)?.try_into().ok()?);
    let off = i64::from_ne_bytes(b.get(8..16)?.try_into().ok()?);
    let reclen = usize::from(u16::from_ne_bytes(b.get(16..18)?.try_into().ok()?));
    let dtype = *b.get(18)?;
    let rec = b.get(..reclen)?;
    let name = rec.get(19..)?;
    let name = &name[..name.iter().position(|&c| c == 0)?];
    if reclen < 20 {
        return None;
    }
    if name == b"." || name == b".." {
        return Some((reclen, None));
    }
    let cookie = u64::try_from(off).ok().filter(|&c| c > 0)?;
    Some((
        reclen,
        Some(RawEntry {
            name: name.to_vec(),
            ino,
            dtype,
            cookie,
        }),
    ))
}

#[cfg(target_os = "macos")]
impl DirReader {
    /// A listing of the directory `fd` (opened for reading).
    pub fn new(fd: OwnedFd) -> Result<DirReader> {
        let raw = fd.into_raw_fd();
        // SAFETY: fdopendir takes over a valid directory descriptor.
        let dir = unsafe { libc::fdopendir(raw) };
        match std::ptr::NonNull::new(dir) {
            Some(dir) => Ok(DirReader { dir, pos: 0 }),
            None => {
                let e = last();
                // SAFETY: fdopendir failed, so the descriptor is still ours.
                drop(unsafe { OwnedFd::from_raw_fd(raw) });
                Err(e)
            }
        }
    }

    fn raw_fd(&self) -> c_int {
        // SAFETY: a live DIR.
        unsafe { libc::dirfd(self.dir.as_ptr()) }
    }

    /// The directory's descriptor.
    pub fn fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the DIR owns this descriptor and lives as long as the
        // borrow.
        unsafe { BorrowedFd::borrow_raw(self.raw_fd()) }
    }

    fn next(&mut self) -> Result<Option<(Vec<u8>, u64, u8)>> {
        // SAFETY: errno is this thread's.
        unsafe { *libc::__error() = 0 };
        // SAFETY: a live DIR, used by this thread only.
        let e = unsafe { libc::readdir(self.dir.as_ptr()) };
        if e.is_null() {
            let err = last();
            return if err.0 == 0 { Ok(None) } else { Err(err) };
        }
        // SAFETY: readdir returned a valid dirent, read before the next call.
        let e = unsafe { &*e };
        let len = usize::from(e.d_namlen).min(e.d_name.len());
        let name: Vec<u8> = e.d_name[..len].iter().map(|&c| u8::from_ne_bytes(c.to_ne_bytes())).collect();
        self.pos += 1;
        Ok(Some((name, e.d_ino, e.d_type)))
    }

    /// Up to `max` entries after the one whose cookie is `after` (0: from
    /// the start), `.` and `..` left out.
    pub fn read(&mut self, after: u64, max: usize, out: &mut Vec<RawEntry>) -> Result<()> {
        if after != self.pos {
            // SAFETY: a live DIR.
            unsafe { libc::rewinddir(self.dir.as_ptr()) };
            self.pos = 0;
            while self.pos < after {
                if self.next()?.is_none() {
                    return Ok(());
                }
            }
        }
        while out.len() < max {
            let Some((name, ino, dtype)) = self.next()? else {
                return Ok(());
            };
            if name == b"." || name == b".." {
                continue;
            }
            out.push(RawEntry {
                name,
                ino,
                dtype,
                cookie: self.pos,
            });
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for DirReader {
    fn drop(&mut self) {
        // SAFETY: the DIR is ours and closed once.
        unsafe { libc::closedir(self.dir.as_ptr()) };
    }
}

/// The descriptors this process may have open: the soft and hard
/// `RLIMIT_NOFILE` as the kernel enforces them. macOS: each at most
/// `kern.maxfilesperproc`, as xnu enforces the lower of the two
/// (`proc_limitgetcur_nofile`) and keeps a larger `RLIMIT_NOFILE` without
/// complaint (measured: a soft limit of 200000 stops at 122880 descriptors
/// where `kern.maxfilesperproc` is 122880).
pub fn nofile() -> Result<(u64, u64)> {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid output buffer.
    check(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) })?;
    #[allow(clippy::useless_conversion)]
    let (soft, hard) = (u64::from(r.rlim_cur), u64::from(r.rlim_max));
    #[cfg(target_os = "macos")]
    {
        let per_proc = maxfilesperproc()?;
        Ok((soft.min(per_proc), hard.min(per_proc)))
    }
    #[cfg(target_os = "linux")]
    Ok((soft, hard))
}

/// macOS: `kern.maxfilesperproc`.
#[cfg(target_os = "macos")]
pub fn maxfilesperproc() -> Result<u64> {
    let mut v: c_int = 0;
    let mut len = std::mem::size_of::<c_int>();
    // SAFETY: a NUL-terminated name and an output buffer of the length
    // passed.
    check(unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut v as *mut c_int).cast::<c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    })?;
    u64::try_from(v).map_err(|_| HostErrno(libc::EINVAL))
}

/// Makes the program `cmd` runs start with its standard streams and no
/// other descriptor, whatever this process holds or was left by its own
/// launcher: in the child, after std has set up 0 to 2 and before the exec,
/// every descriptor above 2 is marked close-on-exec (std's own pipe for an
/// exec failure is already). For a test whose bound is on the process's
/// descriptor table: `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, each
/// descriptor below `getdtablesize()` where the kernel has no `close_range`.
/// Linux only, as are the other `command_with_*`: they fork in user space
/// (std's `pre_exec`), which on macOS can abort the child when another
/// thread is in a first-time `os_once` ([`launch`] says how; there it
/// starts the program with `posix_spawn`).
#[cfg(target_os = "linux")]
pub fn command_with_only_stdio(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    let closure = || {
        // SAFETY: no pointer; marks the range close-on-exec.
        if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) } == 0 {
            return Ok(());
        }
        // SAFETY: async-signal-safe calls on descriptor numbers only.
        let top = unsafe { libc::getdtablesize() };
        for fd in 3..top {
            // SAFETY: as above; a descriptor not open is EBADF, skipped.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                continue;
            }
            // SAFETY: as above, on a descriptor that is open.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    };
    // SAFETY: the closure makes only async-signal-safe system calls and
    // allocates nothing.
    unsafe {
        cmd.pre_exec(closure);
    }
}

/// The descriptors this process has open, ascending, as the kernel lists
/// them, whatever their numbers: Linux, `/proc/self/fd` (the listing's own
/// descriptor, closed when the listing ends, left out); macOS,
/// `proc_pidinfo(PROC_PIDLISTFDS)`, the process's file table.
pub fn open_descriptors() -> Result<Vec<c_int>> {
    #[cfg(target_os = "linux")]
    let listed: Vec<c_int> = {
        let dir = std::fs::read_dir("/proc/self/fd").map_err(|e| HostErrno(e.raw_os_error().unwrap_or(libc::EIO)))?;
        let mut v = Vec::new();
        for e in dir {
            let e = e.map_err(|e| HostErrno(e.raw_os_error().unwrap_or(libc::EIO)))?;
            v.push(e.file_name().to_str().and_then(|n| n.parse().ok()).ok_or(HostErrno(libc::EIO))?);
        }
        v
    };
    #[cfg(target_os = "macos")]
    let listed: Vec<c_int> = {
        let size = std::mem::size_of::<libc::proc_fdinfo>();
        // SAFETY: a null buffer of size 0 asks for the size the list needs.
        let need = unsafe { libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if need <= 0 {
            return Err(last());
        }
        // Room for more than asked: nothing else runs in this process
        // while it lists, but the list is only as long as the buffer.
        let room = usize::try_from(need).unwrap_or(0) / size + 32;
        let mut buf = vec![libc::proc_fdinfo { proc_fd: 0, proc_fdtype: 0 }; room];
        let bytes = c_int::try_from(room * size).map_err(|_| HostErrno(libc::EOVERFLOW))?;
        // SAFETY: buf holds `bytes` bytes of proc_fdinfo records.
        let got = unsafe {
            libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast::<c_void>(), bytes)
        };
        if got <= 0 {
            return Err(last());
        }
        let n = usize::try_from(got).unwrap_or(0) / size;
        if n == room {
            // As long as the buffer: there may be more than it held.
            return Err(HostErrno(libc::EOVERFLOW));
        }
        buf[..n].iter().map(|i| i.proc_fd).collect()
    };
    let mut open: Vec<c_int> = listed
        .into_iter()
        // SAFETY: F_GETFD takes no pointer.
        .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0)
        .collect();
    open.sort_unstable();
    Ok(open)
}

/// The descriptors open below `bound`, by asking each number (`F_GETFD`):
/// for a process that can no longer list its table (Linux, once `/proc` is
/// not in its root). The kernel gives a new descriptor the lowest free
/// number below the soft `RLIMIT_NOFILE`, so with that limit as `bound`
/// every descriptor the process opened itself is found.
pub fn descriptors_below(bound: u64) -> Vec<c_int> {
    let top = c_int::try_from(bound).unwrap_or(c_int::MAX);
    // SAFETY: F_GETFD takes no pointer; a number not open is EBADF.
    (0..top).filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0).collect()
}

/// Closes every descriptor above the standard streams but `keep`, whatever
/// its number: Linux, `close_range` around `keep` (Linux 5.9; where the
/// kernel has none, each descriptor [`open_descriptors`] lists); macOS, each
/// one the process's file table lists. For a process's first step, before
/// it opens anything: what its launcher left open is not its own.
pub fn close_inherited(keep: Option<c_int>) -> Result<()> {
    let keep = keep.filter(|&k| k > 2);
    #[cfg(target_os = "linux")]
    {
        let ranges = match keep.and_then(|k| u32::try_from(k).ok()) {
            Some(k) if k > 3 => vec![(3, k - 1), (k.saturating_add(1), u32::MAX)],
            Some(k) => vec![(k.saturating_add(1), u32::MAX)],
            None => vec![(3, u32::MAX)],
        };
        for (first, last) in ranges {
            // SAFETY: close_range takes numbers only.
            if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) } < 0 {
                let e = self::last();
                if e.0 == libc::ENOSYS {
                    return close_listed(keep);
                }
                return Err(e);
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    close_listed(keep)
}

/// [`close_inherited`] by the kernel's list.
fn close_listed(keep: Option<c_int>) -> Result<()> {
    for fd in open_descriptors()? {
        if fd > 2 && Some(fd) != keep {
            // SAFETY: fd is open (listed) and nothing in this process owns
            // it yet.
            check(unsafe { libc::close(fd) })?;
        }
    }
    Ok(())
}

/// Makes standard input `/dev/null`, read-only, for a process that reads
/// none: what its launcher gave as input (a terminal, a file) is not kept.
pub fn stdin_from_null() -> Result<()> {
    // SAFETY: a NUL-terminated path; the flags take no pointer.
    let null = owned(unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY) })?;
    // SAFETY: both are descriptors of this process; dup2 replaces 0.
    check(unsafe { libc::dup2(null.as_raw_fd(), 0) }).map(drop)
}

/// Whether `fd` is a channel for a byte and nothing else: a pipe or FIFO
/// open for writing only, or a socket.
#[allow(clippy::useless_conversion, reason = "mode_t is u16 on macOS, u32 on Linux")]
pub fn is_write_channel(fd: BorrowedFd<'_>) -> Result<bool> {
    let st = fstat(fd)?;
    // SAFETY: F_GETFL takes no pointer.
    let flags = check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
    let kind = st.mode & u32::from(libc::S_IFMT);
    Ok(kind == u32::from(libc::S_IFSOCK) || (kind == u32::from(libc::S_IFIFO) && flags & libc::O_ACCMODE == libc::O_WRONLY))
}

/// Has `cmd`'s child start with each of `fds` closed, as a launcher that
/// runs it with `>&-` does: for the tests of what a process that finds a
/// standard stream closed is given.
#[cfg(target_os = "linux")]
pub fn command_with_closed(cmd: &mut std::process::Command, fds: Vec<c_int>) {
    use std::os::unix::process::CommandExt;
    let closure = move || {
        for &fd in &fds {
            // SAFETY: async-signal-safe; closes a descriptor of the child.
            unsafe { libc::close(fd) };
        }
        Ok(())
    };
    // SAFETY: the closure makes only async-signal-safe system calls and
    // allocates nothing.
    unsafe {
        cmd.pre_exec(closure);
    }
}

/// Has `cmd`'s child start with each of `fds` at its number (not
/// close-on-exec), as a launcher that leaves descriptors open does: for the
/// tests of a server that must not keep what it was started with.
#[cfg(target_os = "linux")]
pub fn command_with_inherited(cmd: &mut std::process::Command, fds: Vec<(OwnedFd, c_int)>) {
    use std::os::unix::process::CommandExt;
    let closure = move || {
        for (fd, at) in &fds {
            // SAFETY: async-signal-safe; both are descriptors of the child,
            // and dup2 leaves the new one not close-on-exec.
            if unsafe { libc::dup2(fd.as_raw_fd(), *at) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    };
    // SAFETY: the closure makes only async-signal-safe system calls and
    // allocates nothing.
    unsafe {
        cmd.pre_exec(closure);
    }
}

/// What descriptor `fd` of this process is, for a message: its file type
/// (`fstat`) alone, for a process whose sandbox does not let it ask for the
/// path (macOS: wick-fsd's profile kills `F_GETPATH`).
pub fn descriptor_kind(fd: c_int) -> String {
    match kind_of(fd) {
        Ok(kind) => format!("{fd}: {kind}"),
        Err(e) => format!("{fd}: {e:?}"),
    }
}

fn kind_of(fd: c_int) -> Result<&'static str> {
    // SAFETY: an output buffer of the right type.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    check(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => "file",
        libc::S_IFDIR => "directory",
        libc::S_IFCHR => "character device",
        libc::S_IFBLK => "block device",
        libc::S_IFIFO => "pipe",
        libc::S_IFSOCK => "socket",
        libc::S_IFLNK => "link",
        _ => "other",
    })
}

/// What descriptor `fd` of this process is, for a message: its file type
/// and where the host can say it, its path (macOS `F_GETPATH`, Linux the
/// `/proc/self/fd` link, which names a pipe or socket by its inode).
pub fn descriptor_described(fd: c_int) -> String {
    let kind = match kind_of(fd) {
        Ok(kind) => kind,
        Err(e) => return format!("{fd}: {e:?}"),
    };
    #[cfg(target_os = "macos")]
    let path = {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH writes at most MAXPATHLEN bytes, the buffer's.
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } < 0 {
            format!("no path ({:?})", last())
        } else {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..end]).into_owned()
        }
    };
    #[cfg(target_os = "linux")]
    let path = std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map_or_else(|e| format!("no path ({e})"), |p| p.display().to_string());
    format!("{fd}: {kind} {path}")
}

/// Sets the soft `RLIMIT_NOFILE` to `soft` (at most the hard limit). The
/// caller reads [`nofile`] back: on macOS the kernel keeps a value above
/// `kern.maxfilesperproc` and enforces the lower one.
pub fn set_nofile(soft: u64) -> Result<()> {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid output buffer.
    check(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) })?;
    #[allow(clippy::useless_conversion)]
    {
        let soft = soft.min(u64::from(r.rlim_max));
        r.rlim_cur = soft.try_into().map_err(|_| HostErrno(libc::EINVAL))?;
    }
    // SAFETY: a valid input buffer.
    check(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) }).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    /// In a process of its own (the test binary again, with descriptors at
    /// 140 and 141 left open as a launcher leaves them): every descriptor
    /// above the standard streams but the one kept is closed, and standard
    /// input is `/dev/null`.
    /// How a child of a test ended, for its failure: the status (its exit
    /// code or signal) and its standard output and error in full.
    fn ended(out: &std::process::Output) -> String {
        format!(
            "in a process of its own: {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// A program started while another thread of this process makes its
    /// first libnotify registration starts every time (macOS): `launch`
    /// makes no fork in this process, so the child cannot meet libnotify's
    /// `os_once` gate half-taken, which aborts a forked child in libSystem's
    /// fork child handler (`_notify_fork_child`, "os_once_t is corrupt";
    /// CI run 44375259298, macOS 15.8.2, this file's
    /// test_close_inherited_..., whose parent's other thread was libsandbox's
    /// first `os_log`). Each round is a fresh copy of this test binary, as
    /// the registration is a process's first only once; a round runs the
    /// registration on a thread of its own while the main thread starts
    /// `/usr/bin/true` with `launch`, all its descriptors set up.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_a_launch_while_another_thread_first_registers_with_libnotify() {
        const ALONE: &str = "WICK_FS_SYS_TEST_LAUNCH_RACE";
        const NAME: &str = "unix::tests::test_a_launch_while_another_thread_first_registers_with_libnotify";
        const ROUNDS: usize = 100;
        const RECORD_ROUNDS: usize = 10;
        const FORK: &str = "WICK_FS_SYS_TEST_LAUNCH_RACE_FORK";
        if std::env::var_os(ALONE).is_none() {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([NAME, "--exact", "--test-threads=1", "--nocapture"]).env(ALONE, "1");
            for round in 0..ROUNDS {
                let out = launch::output(&cmd, launch::Descriptors::default()).unwrap();
                assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("1 passed"), "round {round}: {}", ended(&out));
            }
            // On record, never checked: the same rounds with std's fork
            // (`Command` with a `pre_exec` closure that does nothing).
            let lost = (0..RECORD_ROUNDS)
                .filter(|_| {
                    let mut forking = std::process::Command::new(std::env::current_exe().unwrap());
                    forking.args([NAME, "--exact", "--test-threads=1", "--nocapture"]).env(ALONE, "1").env(FORK, "1");
                    let out = launch::output(&forking, launch::Descriptors::default()).unwrap();
                    !String::from_utf8_lossy(&out.stdout).contains("forked child: exit status: 0")
                })
                .count();
            println!("record: with std's fork (pre_exec), {lost} of {RECORD_ROUNDS} children lost");
            return;
        }
        unsafe extern "C" {
            fn notify_register_check(name: *const libc::c_char, token: *mut c_int) -> u32;
        }
        let go = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first = {
            let go = go.clone();
            std::thread::spawn(move || {
                while !go.load(std::sync::atomic::Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                let mut token = 0;
                // SAFETY: a NUL-terminated name and an out-parameter.
                unsafe { notify_register_check(c"org.toollyst.wick.test.launch".as_ptr(), &mut token) }
            })
        };
        let (r, w) = std::io::pipe().unwrap();
        let fds = launch::Descriptors { inherited: vec![(r.into(), 140), (w.into(), 141)], closed: vec![1], only_stdio: true };
        let true_ = std::process::Command::new("/usr/bin/true");
        if std::env::var_os(FORK).is_some() {
            use std::os::unix::process::CommandExt;
            let mut forked = true_;
            // SAFETY: the closure does nothing.
            unsafe { forked.pre_exec(|| Ok(())) };
            go.store(true, std::sync::atomic::Ordering::Release);
            let status = forked.status();
            first.join().unwrap();
            println!("forked child: {}", status.map_or_else(|e| e.to_string(), |s| s.to_string()));
            return;
        }
        go.store(true, std::sync::atomic::Ordering::Release);
        let out = launch::output(&true_, fds).unwrap();
        assert_eq!(first.join().unwrap(), 0, "notify_register_check");
        assert!(out.status.success(), "/usr/bin/true: {}", ended(&out));
    }

    #[test]
    fn test_close_inherited_leaves_the_standard_streams_and_the_one_kept() {
        const ALONE: &str = "WICK_FS_SYS_TEST_CLOSE_ALONE";
        const NAME: &str = "unix::tests::test_close_inherited_leaves_the_standard_streams_and_the_one_kept";
        if std::env::var_os(ALONE).is_none() {
            let (r, w) = std::io::pipe().unwrap();
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([NAME, "--exact", "--test-threads=1", "--nocapture"]).env(ALONE, "1");
            let fds = launch::Descriptors { inherited: vec![(r.into(), 140), (w.into(), 141)], ..Default::default() };
            let out = launch::output(&cmd, fds).unwrap();
            assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("1 passed"), "{}", ended(&out));
            return;
        }
        let before = open_descriptors().unwrap();
        // On stderr, so that a failure shows them with the rest.
        eprintln!("before: {:?}", before.iter().map(|&fd| descriptor_described(fd)).collect::<Vec<_>>());
        assert!(before.contains(&140) && before.contains(&141), "{before:?}");
        close_inherited(Some(141)).unwrap();
        stdin_from_null().unwrap();
        let after = open_descriptors().unwrap();
        eprintln!("after: {:?}", after.iter().map(|&fd| descriptor_described(fd)).collect::<Vec<_>>());
        assert_eq!(after, [0, 1, 2, 141], "{:?}", after.iter().map(|&fd| descriptor_described(fd)).collect::<Vec<_>>());
        assert!(descriptor_described(0).ends_with(" /dev/null"), "{}", descriptor_described(0));
        close_inherited(None).unwrap();
        assert_eq!(open_descriptors().unwrap(), [0, 1, 2]);
    }

    /// A process started with its standard output closed (`>&-`) finds
    /// `/dev/null` there at its first step: Rust's start opens it for any
    /// of 0 to 2 that is closed, before `main`, on Linux and macOS alike.
    #[test]
    fn test_a_closed_standard_stream_is_dev_null_at_the_first_step() {
        const ALONE: &str = "WICK_FS_SYS_TEST_CLOSED_STDOUT";
        const NAME: &str = "unix::tests::test_a_closed_standard_stream_is_dev_null_at_the_first_step";
        if std::env::var_os(ALONE).is_none() {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([NAME, "--exact", "--test-threads=1", "--nocapture"]).env(ALONE, "1");
            let out = launch::output(&cmd, launch::Descriptors { closed: vec![1], ..Default::default() }).unwrap();
            // Its stdout is /dev/null: what it says is on stderr only.
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success() && out.stdout.is_empty(), "{}", ended(&out));
            assert!(err.contains("1: character device /dev/null"), "{err}");
            return;
        }
        let one = descriptor_described(1);
        eprintln!("{one}");
        assert!(one.ends_with(" /dev/null") && one.starts_with("1: character device"), "{one}");
    }

    #[test]
    fn test_descriptors_are_listed_and_found_by_number() {
        let f = std::fs::File::open("/dev/null").unwrap();
        let fd = f.as_raw_fd();
        assert!(open_descriptors().unwrap().contains(&fd));
        let (soft, _) = nofile().unwrap();
        assert!(descriptors_below(soft).contains(&fd));
        assert!(!descriptors_below(u64::try_from(fd).unwrap()).contains(&fd));
    }

    #[test]
    fn test_a_write_channel_is_a_pipe_s_write_end_or_a_socket() {
        let (r, w) = std::io::pipe().unwrap();
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(is_write_channel(w.as_fd()).unwrap());
        assert!(is_write_channel(a.as_fd()).unwrap());
        assert!(!is_write_channel(r.as_fd()).unwrap());
        assert!(!is_write_channel(f.as_fd()).unwrap());
    }

    #[test]
    fn test_a_command_with_only_stdio_inherits_nothing_else() {
        // A descriptor this process would pass on (dup's copy is not
        // close-on-exec), well above the low ones as a CI runner's are.
        // SAFETY: plain descriptor calls on a descriptor this test owns.
        let fd = unsafe { libc::dup(std::io::stdin().as_fd().as_raw_fd()) };
        assert!(fd >= 0);
        // SAFETY: as above.
        let high = unsafe { libc::fcntl(fd, libc::F_DUPFD, 140) };
        assert!(high >= 140);
        // SAFETY: as above.
        unsafe { libc::close(fd) };
        let listed = |only: bool| {
            let mut cmd = std::process::Command::new("/bin/ls");
            cmd.arg("/dev/fd/");
            let out = if only {
                launch::output(&cmd, launch::Descriptors { only_stdio: true, ..Default::default() }).unwrap()
            } else {
                cmd.output().unwrap()
            };
            assert!(out.status.success(), "{}", ended(&out));
            String::from_utf8(out.stdout).unwrap().split_whitespace().map(|n| n.parse::<i32>().unwrap()).collect::<Vec<_>>()
        };
        let plain = listed(false);
        let only = listed(true);
        // SAFETY: as above.
        unsafe { libc::close(high) };
        assert!(plain.contains(&high), "{plain:?}");
        // The standard streams and what ls opens itself (the lowest free
        // descriptors, from 3 up): nothing inherited, which would stand
        // apart, as 140 does.
        let dense: Vec<i32> = (0..i32::try_from(only.len()).unwrap()).collect();
        assert!(only == dense && only.len() <= 6, "{only:?}");
        assert!(descriptor_described(0).starts_with("0: "));
        assert!(descriptor_described(-1).contains(&format!("{}", libc::EBADF)), "{}", descriptor_described(-1));
    }

    /// Permission bits only: the special bits and anything above are
    /// refused before the call, the file's mode unchanged.
    #[test]
    fn test_fchmod_takes_permission_bits_only() {
        let d = tmp("fchmod");
        let f = std::fs::File::create(d.join("f")).unwrap();
        fchmod(f.as_fd(), 0o640).unwrap();
        for mode in [0o4640, 0o2640, 0o1640, 0o10_0640] {
            assert_eq!(fchmod(f.as_fd(), mode), Err(HostErrno(libc::EINVAL)), "{mode:o}");
        }
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&f.metadata().unwrap().permissions()) & 0o7777, 0o640);
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("wick-fs-sys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn dirfd(p: &std::path::Path) -> OwnedFd {
        OwnedFd::from(std::fs::File::open(p).unwrap())
    }

    /// The error an escape gets on this host, by its kernel's source: Linux
    /// EXDEV; macOS EACCES on Darwin 24 (macOS 15, xnu-11417), ENOTCAPABLE
    /// from Darwin 25 (macOS 26, xnu-12377).
    fn expected_beneath_refusal() -> i32 {
        #[cfg(target_os = "linux")]
        return libc::EXDEV;
        #[cfg(target_os = "macos")]
        {
            let out = std::process::Command::new("/usr/bin/uname").arg("-r").output().unwrap();
            let release = String::from_utf8(out.stdout).unwrap();
            let darwin: u32 = release.split('.').next().unwrap().trim().parse().unwrap();
            if darwin <= 24 { libc::EACCES } else { libc::ENOTCAPABLE }
        }
    }

    #[test]
    fn test_open_never_follows_a_link_or_leaves_the_directory() {
        let p = tmp("beneath");
        std::fs::create_dir(p.join("d")).unwrap();
        std::fs::write(p.join("f"), b"x").unwrap();
        let d = dirfd(&p.join("d"));
        let refusal = probe_beneath(d.as_fd()).unwrap();
        assert_eq!(refusal, expected_beneath_refusal());
        symlinkat(b"../f", d.as_fd(), b"up").unwrap();
        symlinkat(b"/", d.as_fd(), b"root").unwrap();
        for name in [&b"up"[..], b"root"] {
            let e = open_file(d.as_fd(), name, true, false).unwrap_err();
            assert_eq!(e.0, libc::ELOOP, "{}", String::from_utf8_lossy(name));
        }
        let e = open_dir(d.as_fd(), b"..").unwrap_err();
        assert_eq!(e.0, refusal);
        let e = open_file(d.as_fd(), b"../f", true, false).unwrap_err();
        assert_eq!(e.0, refusal);
        let e = open_dir(d.as_fd(), b"/").unwrap_err();
        assert_eq!(e.0, refusal);
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn test_opens_carry_no_guest_flag() {
        let p = tmp("flags");
        let d = dirfd(&p);
        let f = create_file(d.as_fd(), b"f", true, 0o600).unwrap();
        assert_eq!(status_flags(f.as_fd()).unwrap() & guest_only_flags(), 0);
        let f = open_file(d.as_fd(), b"f", true, true).unwrap();
        assert_eq!(status_flags(f.as_fd()).unwrap() & guest_only_flags(), 0);
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn test_rename_flags() {
        let p = tmp("rename");
        let d = dirfd(&p);
        std::fs::write(p.join("a"), b"a").unwrap();
        std::fs::write(p.join("b"), b"b").unwrap();
        assert_eq!(rename(d.as_fd(), b"a", d.as_fd(), b"b", true, false).unwrap_err().0, libc::EEXIST);
        rename(d.as_fd(), b"a", d.as_fd(), b"b", false, true).unwrap();
        assert_eq!(std::fs::read(p.join("a")).unwrap(), b"b");
        assert_eq!(std::fs::read(p.join("b")).unwrap(), b"a");
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn test_xattr_round_trip_and_listing() {
        let p = tmp("xattr");
        let d = dirfd(&p);
        let f = create_file(d.as_fd(), b"f", true, 0o600).unwrap();
        #[cfg(target_os = "linux")]
        let name = &b"user.wick.test"[..];
        #[cfg(target_os = "macos")]
        let name = &b"wick.test"[..];
        assert_eq!(xattr::get(f.as_fd(), name).unwrap(), None);
        xattr::set(f.as_fd(), name, b"v", true, false).unwrap();
        assert_eq!(xattr::set(f.as_fd(), name, b"w", true, false).unwrap_err().0, libc::EEXIST);
        assert_eq!(xattr::get(f.as_fd(), name).unwrap(), Some(b"v".to_vec()));
        assert!(xattr::list(f.as_fd()).unwrap().contains(&name.to_vec()));
        xattr::remove(f.as_fd(), name).unwrap();
        assert_eq!(xattr::remove(f.as_fd(), name).unwrap_err().0, xattr::NO_ATTR);
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn test_dir_reader_cookies_continue_a_listing() {
        let p = tmp("readdir");
        for i in 0..300 {
            std::fs::write(p.join(format!("n{i}")), b"").unwrap();
        }
        let mut r = DirReader::new(reopen_dir(dirfd(&p).as_fd()).unwrap()).unwrap();
        let mut all = Vec::new();
        let mut after = 0;
        loop {
            let mut batch = Vec::new();
            r.read(after, 7, &mut batch).unwrap();
            if batch.is_empty() {
                break;
            }
            for e in &batch {
                assert!(e.cookie > after, "cookies move forward");
                after = e.cookie;
            }
            all.extend(batch);
        }
        let mut names: Vec<String> = all.iter().map(|e| String::from_utf8(e.name.clone()).unwrap()).collect();
        names.sort();
        let mut want: Vec<String> = (0..300).map(|i| format!("n{i}")).collect();
        want.sort();
        assert_eq!(names, want);
        // From a cookie in the middle: the rest, as before.
        let mid = all[100].cookie;
        let mut rest = Vec::new();
        r.read(mid, 1000, &mut rest).unwrap();
        assert_eq!(rest, all[101..].to_vec());
        std::fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn test_errno_table() {
        // Linux's numbers (include/uapi/asm-generic/errno-base.h, errno.h).
        for (host, linux) in [
            (libc::ENOENT, 2),
            (libc::ENAMETOOLONG, 36),
            (libc::ENOSYS, 38),
            (libc::ENOTEMPTY, 39),
            (libc::ELOOP, 40),
            (libc::EOVERFLOW, 75),
            (libc::EILSEQ, 84),
            (libc::ENOTSUP, 95),
            (libc::EDQUOT, 122),
            (xattr::NO_ATTR, 61),
        ] {
            assert_eq!(linux_errno(HostErrno(host)), linux, "host errno {host}");
        }
        #[cfg(target_os = "macos")]
        {
            let mut seen = std::collections::HashSet::new();
            for &(m, _) in MAC_TO_LINUX {
                assert!(seen.insert(m), "macOS errno {m} twice");
            }
            // One the table does not name.
            assert_eq!(linux_errno(HostErrno(libc::EAUTH)), 5);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_stored_name_is_the_name_on_disk() {
        let p = tmp("stored");
        let d = dirfd(&p);
        // NFD é stored; looked up by NFC (APFS folds normalization).
        std::fs::write(p.join("e\u{301}"), b"").unwrap();
        assert_eq!(stored_name(d.as_fd(), "\u{e9}".as_bytes()).unwrap(), "e\u{301}".as_bytes());
        assert_eq!(stored_name(d.as_fd(), "e\u{301}".as_bytes()).unwrap(), "e\u{301}".as_bytes());
        std::fs::remove_dir_all(&p).unwrap();
    }
}
