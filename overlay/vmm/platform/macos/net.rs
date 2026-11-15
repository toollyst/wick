// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`TapDevice`] on macOS: a vmnet.framework interface or a Unix datagram
//! endpoint (see [`crate::platform::net`] for the names), carrying plain
//! Ethernet frames; the virtio-net header is handled by [`vnet`]. A vmnet
//! interface in virtio-header mode (macOS 15.4 and later,
//! [`vmnet::Interface::vnet`]) carries a header too: the guest's TCP
//! superframes are handed over with theirs ([`vnet::tx_offload`]), and what
//! vmnet delivers is given to the guest as a TAP gives it
//! ([`vnet::rx_offload`], [`vnet::rx_segment`]).
//!
//! In a jail given a network (`--netns`, [`crate::ext::jail::netns`]),
//! endpoints named without `/` are made in the network's directory, which
//! the chroot hides: the jail reaches it through the descriptor it opened
//! before the chroot ([`crate::ext::jail::netns_dir`]), by making it the
//! working directory of the calling thread alone for each call that names
//! a path ([`in_dir`]). vmnet, the host's own network, is not the jail's.
//!
//! A jail's directory is its own, inside the network directory the operator
//! named (`<network>/<id>`, made by the jailer), and the operator's switch
//! binds its sockets directly in the network directory, where no jail can
//! make one. So a jailed endpoint sends the guest's frames only to senders
//! whose address is such a socket, owned by the network directory's owner
//! or root ([`Switch`]), and drops what any other sender sends it. That is
//! not an identity check: a datagram's sender address is the path its
//! sender bound, as it wrote it (measured), and Unix datagram sockets have
//! no peer credentials (xnu bsd/kern/uipc_usrreq.c, `LOCAL_PEERCRED`: a
//! stream's only). What keeps another jail from sending here at all is the
//! kernel's file check on this directory (another uid) and the sender's
//! own sandbox profile (the same uid).

use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::io;
use std::mem;
use std::os::raw::{c_int, c_uint};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::fd::BorrowedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use super::vmnet::{self, Mode};
use crate::devices::virtio::iovec::IoVecBuffer;
use crate::platform::net::{TapDevice, TapError};
use crate::platform::vnet::{self, VnetHdr};

/// `IFNAMSIZ`: interface names are shorter.
const IFACE_NAME_MAX_LEN: usize = 16;
/// `_CS_DARWIN_USER_TEMP_DIR`.
const CS_DARWIN_USER_TEMP_DIR: c_int = 65537;
/// Buffer sizes of endpoints; the send buffer bounds the datagram size.
const SNDBUF: c_int = 1 << 20;
const RCVBUF: c_int = 4 << 20;
/// Most interfaces a `%d` name is tried with.
const MAX_UNITS: u32 = 1 << 15;
/// The largest frame read from vmnet in virtio-header mode: the most the
/// net device takes (upstream's `MAX_BUFFER_SIZE`, 65562 bytes); vmnet's
/// coalesced frames were at most 65238 bytes (macOS 27.2).
const RX_ROOM: usize = 65562;

unsafe extern "C" {
    /// Sets the calling thread's working directory to `fd`, or back to the
    /// process's with -1 (libsystem_pthread; fts uses it).
    fn pthread_fchdir_np(fd: c_int) -> c_int;
}

/// Runs `f`, which names paths, with relative paths resolved in `dir` (the
/// jail's network) on this thread only; without `dir`, as the process
/// resolves them.
fn in_dir<T>(dir: Option<BorrowedFd<'_>>, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let Some(dir) = dir else {
        return f();
    };
    // SAFETY: a directory descriptor; changes this thread's working directory.
    if unsafe { pthread_fchdir_np(dir.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = f();
    // SAFETY: -1 returns this thread to the process's working directory.
    let back = unsafe { pthread_fchdir_np(-1) };
    // Failing to would leave every relative path of this thread resolved in
    // the network: not survivable.
    assert_eq!(back, 0, "cannot leave the network directory: {}", io::Error::last_os_error());
    result
}

/// Where endpoints named without `/` are made: the jail's network, as its
/// path outside the jail and the descriptor that reaches it.
fn network() -> Option<(&'static Path, BorrowedFd<'static>)> {
    Some((crate::ext::jail::netns()?, crate::ext::jail::netns_dir()?))
}

/// Whether this Firecracker may make an interface nobody made, as root may
/// make a TAP on Linux (CAP_NET_ADMIN): its effective uid is 0, read once
/// while the microVM is built ([`find_user_endpoint_dir`]), as a running
/// microVM may not call geteuid (upstream's filter has none) and a device
/// hot-plugged then asks (`test_a_hotplugged_interface_asks_no_uid`). Unit
/// tests run with that right by default, as upstream's run as root; the
/// tests of the refusal take it away, and [`tests_as::real`] asks the
/// process ([`tests_as`]).
pub fn may_create() -> bool {
    #[cfg(test)]
    if let Some(creator) = tests_as::CREATOR.with(std::cell::Cell::get) {
        return creator;
    }
    #[cfg(test)]
    if !tests_as::REAL.with(std::cell::Cell::get) {
        return true;
    }
    euid() == 0
}

/// This process's credentials, read once while the microVM is built
/// ([`find_user_endpoint_dir`]): its effective uid, and the groups it is in
/// (its effective group and the supplementary ones the kernel's credential
/// holds, as Linux's `in_egroup_p` asks), as a running microVM may not ask
/// (upstream's filter has neither geteuid nor getgroups).
struct Creds {
    euid: libc::uid_t,
    groups: Vec<libc::gid_t>,
}

fn creds() -> &'static Creds {
    static CREDS: std::sync::OnceLock<Creds> = std::sync::OnceLock::new();
    CREDS.get_or_init(|| {
        // SAFETY: no arguments.
        let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let mut groups = vec![egid];
        // SAFETY: a count query (no buffer), then a buffer of that many.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if let Ok(len) = usize::try_from(count)
            && len > 0
        {
            let mut more: Vec<libc::gid_t> = vec![0; len];
            // SAFETY: a buffer of `count` entries.
            let got = unsafe { libc::getgroups(count, more.as_mut_ptr()) };
            if let Ok(got) = usize::try_from(got) {
                more.truncate(got);
                groups.extend(more);
            }
        }
        Creds { euid, groups }
    })
}

/// This process's effective uid ([`creds`]).
fn euid() -> libc::uid_t {
    #[cfg(test)]
    if let Some((euid, _)) = tests_as::CREDS.with(|c| c.borrow().clone()) {
        return euid;
    }
    creds().euid
}

/// Whether this process is in the group `gid` ([`creds`]).
fn in_group(gid: libc::gid_t) -> bool {
    #[cfg(test)]
    if let Some((_, groups)) = tests_as::CREDS.with(|c| c.borrow().clone()) {
        return groups.contains(&gid);
    }
    creds().groups.contains(&gid)
}

/// Whether this Firecracker is jailed: given a network (`--netns`) or in a
/// chroot jail. A test may say so for its thread ([`tests_as`]).
fn jailed() -> bool {
    #[cfg(test)]
    if let Some(jailed) = tests_as::JAILED.with(std::cell::Cell::get) {
        return jailed;
    }
    network().is_some() || crate::ext::jail::root().is_some()
}

/// What the unit tests run this thread's opens as: without the creator's
/// right ([`may_create`]), or as a jailed Firecracker ([`jailed`]).
#[cfg(test)]
pub(crate) mod tests_as {
    use std::cell::Cell;

    thread_local! {
        pub(super) static CREATOR: Cell<Option<bool>> = const { Cell::new(None) };
        pub(super) static JAILED: Cell<Option<bool>> = const { Cell::new(None) };
        pub(super) static REAL: Cell<bool> = const { Cell::new(false) };
        pub(super) static CREDS: std::cell::RefCell<Option<(libc::uid_t, Vec<libc::gid_t>)>> =
            const { std::cell::RefCell::new(None) };
        pub(super) static AFTER_LOCK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Runs `f` with `between` run once in this thread's next take of an
    /// interface's lock, between its open and its look at the name
    /// ([`super::IfaceLock::take`]): where another's removal or replacement
    /// of the file can fall.
    pub(crate) fn after_lock<T>(between: impl FnOnce() + 'static, f: impl FnOnce() -> T) -> T {
        AFTER_LOCK.with(|c| *c.borrow_mut() = Some(Box::new(between)));
        let out = f();
        AFTER_LOCK.with(|c| *c.borrow_mut() = None);
        out
    }

    /// Runs `f` with this thread's opens judged as the effective uid
    /// `euid` in `groups` would be ([`super::capable`]); the kernel's own
    /// check of the open is still this process's.
    pub(crate) fn creds<T>(euid: libc::uid_t, groups: &[libc::gid_t], f: impl FnOnce() -> T) -> T {
        let before = CREDS.with(|c| c.replace(Some((euid, groups.to_vec()))));
        let out = f();
        CREDS.with(|c| *c.borrow_mut() = before);
        out
    }

    /// Runs `f` with this thread's opens made with the process's own right
    /// to make an interface (its effective uid), as Firecracker's are.
    pub(crate) fn real<T>(f: impl FnOnce() -> T) -> T {
        let before = REAL.with(|c| c.replace(true));
        let out = f();
        REAL.with(|c| c.set(before));
        out
    }

    /// Runs `f` with this thread's opens made as a user who is not root.
    pub(crate) fn user<T>(f: impl FnOnce() -> T) -> T {
        let before = CREATOR.with(|c| c.replace(Some(false)));
        let out = f();
        CREATOR.with(|c| c.set(before));
        out
    }

    /// Runs `f` with this thread's opens made as a jailed Firecracker's.
    pub(crate) fn jailed<T>(f: impl FnOnce() -> T) -> T {
        let before = JAILED.with(|c| c.replace(Some(true)));
        let out = f();
        JAILED.with(|c| c.set(before));
        out
    }
}

/// The directory of this instance's endpoints named without `/`: the jail's
/// own directory in its network (by its path outside the jail), or, without
/// a network, `<id>` in `firecracker-net` in the user's temporary directory
/// (`<id>` Firecracker's `--id`). Either way the network directory, where
/// the operator's switch makes the interfaces ([`operator_made`]), is its
/// parent.
pub fn endpoint_dir() -> io::Result<PathBuf> {
    if let Some((path, _)) = network() {
        return Ok(path.to_owned());
    }
    let id = crate::logger::INSTANCE_ID.get().map_or(crate::logger::DEFAULT_INSTANCE_ID, String::as_str);
    let dir = user_endpoint_dir()?.join(id);
    // Made as the sandbox's profile is ([`find_user_endpoint_dir`]): the
    // sandbox denies mkdir from the time it is applied.
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

/// Whether the operator made the interface `name`: a socket `name` directly
/// in the network directory, the parent of this instance's directory `dir`
/// (reached through `network` in a jail), owned by the network directory's
/// owner or root. No jail can make a name in the network directory (the
/// jailer's permissions on it, docs/PORTING.md row 6), so a jail cannot make
/// its own interface. The operator's switch makes it, and its socket there is
/// the one the endpoint takes as its peer, as on Linux the operator makes a
/// TAP (`ip tuntap add`) and Firecracker opens it.
fn operator_made(dir: &Path, network: Option<BorrowedFd<'_>>, name: &str) -> io::Result<bool> {
    let stat = |path: &Path| -> io::Result<libc::stat> {
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: plain data, filled by fstatat.
        let mut st: libc::stat = unsafe { mem::zeroed() };
        let at = network.map_or(libc::AT_FDCWD, |fd| fd.as_raw_fd());
        // SAFETY: a directory descriptor (or AT_FDCWD) and a NUL-terminated
        // path; no link followed at its last name.
        if unsafe { libc::fstatat(at, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    };
    let (parent, entry) = match network {
        Some(_) => (PathBuf::from(".."), Path::new("..").join(name)),
        None => {
            let parent = dir.parent().ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
            (parent.to_owned(), parent.join(name))
        }
    };
    let owner = stat(&parent)?.st_uid;
    match stat(&entry) {
        Ok(st) => Ok(st.st_mode & libc::S_IFMT == libc::S_IFSOCK && (st.st_uid == owner || st.st_uid == 0)),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Whether this Firecracker may open the interface whose lock file has the
/// status `st`, by Linux's rule for a TAP (v6.1 drivers/net/tun.c
/// `tun_not_capable` :577 to :585, which `tun_set_iff` asks before it
/// attaches, :2750): one with an owner (TUNSETOWNER) opens only for that
/// effective uid, one with a group (TUNSETGROUP) only for a member of it,
/// one with both only for both, one with neither for anyone, and any of
/// them for root (CAP_NET_ADMIN). The lock file says which by its mode, so
/// that the kernel's permission check on the open is the owner's check:
/// readable by others (0444) it has neither; else readable by its owner
/// (0400) its owner is the interface's, readable by its group (0040) its
/// group is. Only "both" (0440) asks more than the kernel's check, which
/// lets the owner or a member in: that is decided here.
fn capable(st: &libc::stat) -> bool {
    let mode = st.st_mode & 0o777;
    if euid() == 0 || mode & 0o004 != 0 {
        return true;
    }
    let owner = mode & 0o400 != 0;
    let group = mode & 0o040 != 0;
    !((owner && euid() != st.st_uid) || (group && !in_group(st.st_gid)))
}

/// The status of `path` relative to `at` (`AT_FDCWD`: as given), its last
/// name not followed.
fn lstat_at(at: RawFd, path: &CStr) -> io::Result<libc::stat> {
    // SAFETY: plain data, filled by fstatat.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: a directory descriptor (or AT_FDCWD) and a NUL-terminated path.
    if unsafe { libc::fstatat(at, path.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// The status of the file `fd` is open on.
fn fstat_fd(fd: &OwnedFd) -> io::Result<libc::stat> {
    // SAFETY: plain data, filled by fstat.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    // SAFETY: a descriptor we own.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// The interface `name` in use: EBUSY, as a second TUNSETIFF on a TAP
/// another file holds (drivers/net/tun.c, v6.1, `tun_attach` :769 to :771).
fn busy(name: &str) -> TapError {
    TapError::IfreqExecuteError(io::Error::from_raw_os_error(libc::EBUSY), name.to_owned())
}

/// Whether `err` is [`busy`]'s.
fn is_busy(err: &TapError) -> bool {
    matches!(err, TapError::IfreqExecuteError(e, _) if e.raw_os_error() == Some(libc::EBUSY))
}

/// What makes an interface one opener's, as an attached TAP is (a second
/// open is `EBUSY`, `tun_attach`): an exclusive lock on its lock file
/// `<name>.lock`, beside the switch's socket `<name>` directly in the
/// network directory, held for the device's life. The kernel arbitrates it
/// (open(2) with `O_EXLOCK | O_NONBLOCK`, xnu bsd/vfs/vfs_syscalls.c
/// `open1`: an flock(2) lock taken in the open, so no flock call, which
/// upstream's VMM filter has not, in the run phase a hot-plug opens in), and
/// it goes with the descriptor however Firecracker ends, a kill too. The
/// operator's switch makes the file, mode 0444 for an interface anyone may
/// open, 0400 owned by the uid it is for, 0040 with the group it is for, or
/// 0440 with both ([`capable`]); no jail can make, replace or change it, as
/// no jail makes a name in the network directory (`ext::sandbox`
/// files_in_jail). A creator ([`may_create`]) opening a name without one
/// makes it, 0644 (writable by its owner: what tells a creator's from the
/// operator's, which are read-only), and removes it when the device goes,
/// as a TAP root made without TUNSETPERSIST goes at its close.
struct IfaceLock {
    fd: OwnedFd,
    /// The network's descriptor in a jail, where `path` is relative.
    at: Option<BorrowedFd<'static>>,
    path: CString,
    /// A creator's, removed when the device goes.
    made: bool,
}

impl fmt::Debug for IfaceLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IfaceLock").field("path", &self.path).field("made", &self.made).finish_non_exhaustive()
    }
}

impl IfaceLock {
    /// Takes the lock of the interface `name` of the network whose
    /// directory is the parent of `dir` (reached through `network` in a
    /// jail): `EBUSY` if another holds it ([`busy`]), `EPERM` in upstream's
    /// text ([`refuse`]) if this Firecracker may not open the interface
    /// ([`capable`]) or there is no lock file and it may not make one.
    fn take(dir: &Path, network: Option<BorrowedFd<'static>>, name: &str) -> Result<Self, TapError> {
        let file = format!("{name}.lock");
        let path = match network {
            Some(_) => Path::new("..").join(&file),
            None => dir.parent().unwrap_or(dir).join(&file),
        };
        let shown = dir.parent().unwrap_or(dir).join(&file);
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| TapError::InvalidIfname)?;
        let at = network.map_or(libc::AT_FDCWD, |fd| fd.as_raw_fd());
        let creator = may_create();
        let mut flags = libc::O_RDONLY | libc::O_EXLOCK | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        if creator {
            flags |= libc::O_CREAT;
        }
        // SAFETY: a directory descriptor (or AT_FDCWD), a NUL-terminated
        // path and a mode for a file made.
        let fd = unsafe { libc::openat(at, c.as_ptr(), flags, libc::c_uint::from(0o644u16)) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                // Held: busy, unless this Firecracker could not have it
                // anyway, as tun_set_iff asks tun_not_capable first.
                Some(libc::EAGAIN) => match lstat_at(at, &c) {
                    Ok(st) if !capable(&st) => refuse(name, format_args!("{shown:?} is another's interface")),
                    _ => busy(name),
                },
                Some(libc::ENOENT) => refuse(
                    name,
                    format_args!(
                        "no interface lock {shown:?}: the network's switch makes it beside its socket, and only \
                         root makes an interface nobody made"
                    ),
                ),
                Some(libc::EACCES) => refuse(
                    name,
                    format_args!("{shown:?} opens for its owner or its group only: the interface is another's"),
                ),
                Some(libc::ELOOP) => refuse(name, format_args!("{shown:?} is a link")),
                // A socket (or a FIFO's like) opens as no file.
                Some(libc::EOPNOTSUPP) => refuse(name, format_args!("{shown:?} is not a regular file")),
                Some(libc::EPERM) => refuse(name, format_args!("{shown:?} is no interface lock (the sandbox's rule)")),
                _ => TapError::IfreqExecuteError(err, name.to_owned()),
            });
        }
        // SAFETY: a descriptor just opened, ours.
        let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let failed = |err: io::Error| TapError::IfreqExecuteError(err, name.to_owned());
        let st = fstat_fd(&fd).map_err(failed)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(refuse(name, format_args!("{shown:?} is not a regular file")));
        }
        #[cfg(test)]
        if let Some(between) = tests_as::AFTER_LOCK.with(|c| c.borrow_mut().take()) {
            between();
        }
        // The lock is on the file the name is: one removed or replaced
        // after this open found it is another opener's to have.
        let named = lstat_at(at, &c).ok().map(|n| (n.st_dev, n.st_ino));
        if st.st_nlink == 0 || named != Some((st.st_dev, st.st_ino)) {
            return Err(busy(name));
        }
        if !capable(&st) {
            return Err(refuse(name, format_args!("{shown:?} is another's interface")));
        }
        Ok(IfaceLock {
            fd,
            at: network,
            path: c,
            made: creator && st.st_mode & 0o200 != 0,
        })
    }
}

/// A creator's lock file goes with its device, while the lock is still
/// held, and only the file the lock is on (by its device and inode), so
/// that a later opener finds no name left and never a half state: an
/// opener that found the name before it went fails with `EBUSY` (the lock,
/// then the identity check of [`IfaceLock::take`]), one after makes it
/// anew. A running microVM's sandbox lets a creator remove only such files
/// (`ext::sandbox` unlink_rule: `.lock` files in the network directory
/// writable by their owner).
impl Drop for IfaceLock {
    fn drop(&mut self) {
        if !self.made {
            return;
        }
        let at = self.at.map_or(libc::AT_FDCWD, |fd| fd.as_raw_fd());
        if let (Ok(named), Ok(own)) = (lstat_at(at, &self.path), fstat_fd(&self.fd))
            && (named.st_dev, named.st_ino) == (own.st_dev, own.st_ino)
        {
            // SAFETY: a directory descriptor (or AT_FDCWD) and a
            // NUL-terminated path.
            unsafe { libc::unlinkat(at, self.path.as_ptr(), 0) };
        }
    }
}

/// The refusal of an interface this Firecracker may not open: EPERM, as
/// TUNSETIFF's for a name that is no TAP of the caller's without
/// CAP_NET_ADMIN (Linux v6.1 drivers/net/tun.c tun_set_iff :2781,
/// tun_not_capable :577), so upstream's text; why is logged.
fn refuse(name: &str, why: fmt::Arguments<'_>) -> TapError {
    crate::logger::warn!("net: {name:?} refused: {why}");
    TapError::IfreqExecuteError(io::Error::from_raw_os_error(libc::EPERM), name.to_owned())
}

/// `firecracker-net` in the user's temporary directory (not made here):
/// where endpoints named without `/` are made outside a jail. Found once,
/// before the sandbox is in place ([`find_user_endpoint_dir`]): confstr's
/// `_CS_DARWIN_USER_TEMP_DIR` calls geteuid, which the sandbox denies a
/// running microVM (upstream's filter has no geteuid), and a device
/// hot-plugged into one looks the directory up
/// (`test_a_bare_name_hotplugged_without_a_network_opens`).
pub fn user_endpoint_dir() -> io::Result<PathBuf> {
    static DIR: std::sync::OnceLock<Result<PathBuf, i32>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let mut buf = vec![0u8; usize::try_from(libc::PATH_MAX).unwrap()];
        // SAFETY: confstr into a buffer of the given size.
        let len = unsafe { libc::confstr(CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), buf.len()) };
        if len == 0 || len > buf.len() {
            return Err(io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL));
        }
        let dir = CStr::from_bytes_until_nul(&buf).map_err(|_| libc::EINVAL)?;
        Ok(Path::new(OsStr::from_bytes(dir.to_bytes())).join("firecracker-net"))
    })
    .clone()
    .map_err(io::Error::from_raw_os_error)
}

/// Finds the user's directory of endpoints ([`user_endpoint_dir`]), and
/// makes it and this instance's in it ([`endpoint_dir`]) if `make` (the
/// profile is for them: outside a jail and a network), while nothing
/// denies it: called as the sandbox's profile is made, before it is applied
/// (the sandbox denies mkdir; the instance's `--id` is known by then), so
/// that a device hot-plugged into a running microVM finds them
/// (`test_a_bare_name_hotplugged_without_a_network_opens`). An error is
/// kept, and given to each opener of a bare name as before.
pub fn find_user_endpoint_dir(make: bool) {
    // The right to make an interface, and who may open which (may_create,
    // capable), which an open asks.
    creds();
    if make {
        let _ = endpoint_dir();
    }
}

/// How long an opener waits for its turn in a directory ([`bind`]): far
/// longer than any turn takes (a bind, a connect and an unlink).
const TURN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// An exclusive flock(2) on the directory of a path (its parent, or the
/// working directory for a bare name), held until dropped.
struct DirTurn {
    /// Read by nothing: closing it releases the lock.
    _dir: OwnedFd,
}

impl DirTurn {
    /// Takes the lock, waiting at most `wait`; past it, fails with
    /// [`io::ErrorKind::TimedOut`] and a message that names the directory.
    fn take(path: &Path, wait: std::time::Duration) -> io::Result<Self> {
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let name = std::ffi::CString::new(dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: open of a NUL-terminated path.
        let fd = unsafe {
            libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor was just opened and is owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let start = std::time::Instant::now();
        loop {
            // SAFETY: flock of a descriptor owned here.
            if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(DirTurn { _dir: fd });
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EWOULDBLOCK) | Some(libc::EINTR) => {}
                _ => return Err(err),
            }
            if start.elapsed() >= wait {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{}: another opener of an endpoint there has held the directory's lock for \
                         {wait:?} (flock); an endpoint is opened in turn with the others there",
                        dir.display()
                    ),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

fn sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: sockaddr_un is plain data.
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    addr.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).unwrap();
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = src.cast_signed();
    }
    let len = mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    // A sockaddr_un is far smaller than 256 bytes.
    addr.sun_len = u8::try_from(len).unwrap();
    Ok((addr, libc::socklen_t::from(addr.sun_len)))
}

fn cvt(ret: isize) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret.cast_unsigned())
    }
}

/// A non-blocking Unix datagram socket with large buffers.
pub(crate) fn dgram_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket call; the result is checked.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just created and is owned here.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    for (opt, size) in [(libc::SO_SNDBUF, SNDBUF), (libc::SO_RCVBUF, RCVBUF)] {
        // SAFETY: setsockopt with an int option.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                std::ptr::from_ref(&size).cast(),
                libc::socklen_t::try_from(mem::size_of::<c_int>()).unwrap(),
            );
        }
    }
    // SAFETY: fcntl on a descriptor owned here.
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok(sock)
}

/// Binds `sock` at `path`. A socket file nobody listens on any more is
/// replaced; one in use fails with `EBUSY`, as a TAP opened twice does
/// (drivers/net/tun.c, v6.1, `tun_attach` :769 to :771).
///
/// Openers of names in one directory take turns, under an flock(2) on the
/// directory, so that the bind, the probe of a file in the way and its
/// replacement are one step to every other opener: of openers of one stale
/// name at once, one replaces it and the others find it in use (`EBUSY`),
/// and openers of `name%d` each get a unit of their own. Without the turns
/// two openers could both find the file stale, and one remove the socket
/// the other had just bound (`test_openers_of_a_stale_name_take_turns`: 1
/// opener of 8 got the name, 6 `EADDRINUSE` and 1 `ENOENT`); in a jail's
/// own directory of its network the turns are [`OWN_DIR_TURN`]'s. The lock is
/// the directory's open file, released however its holder ends; an opener
/// waits for it at most [`TURN_WAIT`] and then fails, naming the directory,
/// so that a stuck holder cannot hold Firecracker's start for ever.
///
/// Once the sandbox is narrowed (a device hot-plugged into a running
/// microVM), a stale socket file is not replaced: removing it is setup's
/// (`vmm::ext::sandbox`'s unlink rule), so the bind fails with
/// `EADDRINUSE`, which the API reports, and the microVM runs on; a name in
/// use is still `EBUSY`, as a TAP opened twice
/// (`test_a_hotplugged_name_in_use_is_busy`); that bind replaces nothing,
/// so it takes no turn.
pub(crate) fn bind(sock: &OwnedFd, path: &Path) -> io::Result<()> {
    bind_at(sock, path, false)
}

/// The turns of openers in a jail's own directory of its network, which is
/// this process's alone: the jailer holds its lock (an flock of the
/// directory) for Firecracker's life, and Firecracker in a network without
/// the jailer takes it at its start (`ext::jail::enter`), so another
/// process given the directory is refused it (EBUSY). A turn on the
/// directory's own flock would wait for that lock, held on another open of
/// the directory (an flock is the open file's), until it fails; so the
/// openers there, this process's threads, take turns on this.
static OWN_DIR_TURN: Mutex<()> = Mutex::new(());

/// [`bind`]; `own`: `path` is in the jail's own directory of its network
/// ([`OWN_DIR_TURN`]), relative to it.
fn bind_at(sock: &OwnedFd, path: &Path, own: bool) -> io::Result<()> {
    let (addr, len) = sockaddr(path)?;
    let (_turn, _own_turn) = if crate::ext::sandbox::narrowed() {
        (None, None)
    } else if own {
        (None, Some(OWN_DIR_TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner)))
    } else {
        (Some(DirTurn::take(path, TURN_WAIT)?), None)
    };
    let try_bind = || {
        // SAFETY: bind with a valid address.
        let ret = unsafe { libc::bind(sock.as_raw_fd(), std::ptr::from_ref(&addr).cast(), len) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    match try_bind() {
        Err(err) if err.raw_os_error() == Some(libc::EADDRINUSE) => {
            let probe = dgram_socket()?;
            // SAFETY: connect with a valid address.
            let ret =
                unsafe { libc::connect(probe.as_raw_fd(), std::ptr::from_ref(&addr).cast(), len) };
            if ret == 0 {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            // A running microVM replaces no stale name (removing it is
            // setup's): a name in use is busy as above, a stale one fails
            // the bind (`test_a_hotplugged_name_in_use_is_busy`).
            if crate::ext::sandbox::narrowed() {
                return Err(err);
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ECONNREFUSED) => std::fs::remove_file(path)?,
                // Removed since by the endpoint that had it, as it went
                // (Drop): the name is free.
                Some(libc::ENOENT) => {}
                _ => return Err(err),
            }
            try_bind()
        }
        other => other,
    }
}

/// A socket address, as received.
#[derive(Clone, Copy)]
struct Peer(libc::sockaddr_un, libc::socklen_t);

impl Peer {
    fn path(&self) -> &[u8] {
        let off = mem::offset_of!(libc::sockaddr_un, sun_path);
        let len = usize::try_from(self.1).unwrap_or(0).saturating_sub(off);
        let path = &self.0.sun_path[..len.min(self.0.sun_path.len())];
        // SAFETY: c_char and u8 have the same layout.
        let path: &[u8] = unsafe { &*(std::ptr::from_ref(path) as *const [u8]) };
        path.split(|b| *b == 0).next().unwrap_or(&[])
    }
}

/// Who a jailed endpoint's peers may be: the sockets directly in the
/// network directory, the parent of the jail's own, that its owner or root
/// owns.
#[derive(Debug)]
struct Switch {
    /// The network directory's path outside the jail.
    network: PathBuf,
    /// Its owner.
    owner: libc::uid_t,
}

impl Switch {
    /// For an endpoint in the jail's directory `dir`, at `path` outside
    /// the jail.
    fn of(path: &Path, dir: BorrowedFd<'_>) -> io::Result<Self> {
        let network = path
            .parent()
            .ok_or_else(|| io::Error::other("the jail's network directory has no parent"))?;
        Ok(Switch { network: network.to_owned(), owner: Self::stat(dir, c"..")?.st_uid })
    }

    fn stat(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<libc::stat> {
        // SAFETY: plain data, filled by fstatat.
        let mut st: libc::stat = unsafe { mem::zeroed() };
        // SAFETY: a directory descriptor and a NUL-terminated name; no link
        // followed at its last name.
        if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }

    /// The address a sender named `sender` is sent to from the jail's
    /// directory (`../<name>`), if it names one name directly in the
    /// network directory, by its path outside the jail.
    fn address(&self, sender: &Peer) -> Option<Peer> {
        let name = Path::new(OsStr::from_bytes(sender.path())).strip_prefix(&self.network).ok()?;
        let mut names = name.components();
        let (Some(std::path::Component::Normal(name)), None) = (names.next(), names.next()) else {
            return None;
        };
        let (addr, len) = sockaddr(&Path::new("..").join(name)).ok()?;
        Some(Peer(addr, len))
    }

    /// Whether `address` (of [`Switch::address`]) is a socket of the
    /// network directory's owner or root.
    fn owns(&self, dir: BorrowedFd<'_>, address: &Peer) -> bool {
        let Ok(name) = std::ffi::CString::new(address.path()) else {
            return false;
        };
        Self::stat(dir, &name).is_ok_and(|st| {
            st.st_mode & libc::S_IFMT == libc::S_IFSOCK && (st.st_uid == 0 || st.st_uid == self.owner)
        })
    }
}

/// A Unix datagram endpoint.
struct Endpoint {
    sock: OwnedFd,
    /// Its path: relative to `dir` when it is in the jail's network.
    path: PathBuf,
    /// The jail's network, where relative paths resolve ([`in_dir`]).
    dir: Option<BorrowedFd<'static>>,
    /// The network's path outside the jail: a peer that names itself by it
    /// is reached relative to `dir`.
    dir_path: Option<PathBuf>,
    /// In a jail: who may be a peer. Elsewhere any sender is one.
    switch: Option<Switch>,
    /// The socket file it bound (device and inode), which it removes when
    /// it goes ([`Drop`]).
    bound: (u64, u64),
    /// Named without a path, so in the directory of endpoints, whose
    /// sockets a running microVM may remove (`ext::sandbox` unlink_rule).
    named: bool,
    /// The interface's lock ([`IfaceLock`]), for an endpoint named without
    /// a path: held until the endpoint has gone (dropped after it).
    lock: Option<IfaceLock>,
    /// Where frames from the guest go: every host-side socket that sent a
    /// datagram here (in a jail: of the switch's).
    peers: Vec<Peer>,
    /// Datagrams dropped because their sender may not be a peer.
    refused: u64,
    /// The senders whose refusal was logged (each once), by the address
    /// they gave; at most [`REFUSED_LOGGED`], so that a sender that keeps
    /// changing its name fills neither the log nor memory.
    refused_senders: Vec<Vec<u8>>,
}

/// How many refused senders are logged by name; one more line says that
/// further ones are not.
const REFUSED_LOGGED: usize = 8;

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("path", &self.path)
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Binds an endpoint at `path`, relative to the network `dir` (with its
    /// path outside the jail) if given. `jail`: `dir` is a jail's own
    /// directory in its network, whose peers are the switch's ([`Switch`]).
    fn open(path: &Path, dir: Option<(&Path, BorrowedFd<'static>)>, jail: bool) -> io::Result<Self> {
        let sock = dgram_socket()?;
        let fd = dir.map(|(_, fd)| fd);
        let switch = match dir {
            Some((dir_path, fd)) if jail => Some(Switch::of(dir_path, fd)?),
            _ => None,
        };
        let bound = in_dir(fd, || {
            bind_at(&sock, path, fd.is_some())?;
            let meta = std::fs::symlink_metadata(path)?;
            Ok((meta.dev(), meta.ino()))
        })?;
        Ok(Endpoint {
            sock,
            path: path.to_owned(),
            dir: fd,
            dir_path: dir.map(|(p, _)| p.to_owned()),
            switch,
            bound,
            named: false,
            lock: None,
            peers: Vec::new(),
            refused: 0,
            refused_senders: Vec::new(),
        })
    }

    /// Notes the sender of a datagram as a peer. `false`: it may not be
    /// one (in a jail, anything but a socket of the switch's), and its
    /// datagram is not a frame.
    fn note_peer(&mut self, addr: libc::sockaddr_un, len: libc::socklen_t) -> bool {
        let mut peer = Peer(addr, len);
        if let (Some(switch), Some(dir)) = (&self.switch, self.dir) {
            let admitted = switch.address(&peer).filter(|address| {
                // A peer already taken is not looked at again: a name in
                // the network directory is replaced only by who may write
                // there, its owner.
                self.peers.iter().any(|p| p.path() == address.path()) || switch.owns(dir, address)
            });
            let Some(address) = admitted else {
                // Said once for each sender, so that an operator whose
                // switch is bound by another name than its real path in
                // the network directory sees why nothing flows.
                self.refused += 1;
                let sender = peer.path();
                if self.refused_senders.len() <= REFUSED_LOGGED
                    && !self.refused_senders.iter().any(|s| s == sender)
                {
                    if self.refused_senders.len() < REFUSED_LOGGED {
                        crate::logger::warn!(
                            "net: {:?} dropped a datagram from {:?}: its peers are the sockets directly in {:?}, \
                             bound by that path, that the directory's owner or root owns ({} dropped so far; \
                             said once for this sender)",
                            self.path,
                            OsStr::from_bytes(sender),
                            switch.network,
                            self.refused
                        );
                    } else {
                        crate::logger::warn!(
                            "net: {:?} dropped a datagram from one more sender that is no peer; further senders \
                             are not logged ({} dropped so far)",
                            self.path,
                            self.refused
                        );
                    }
                    self.refused_senders.push(sender.to_vec());
                }
                return false;
            };
            if !self.peers.iter().any(|p| p.path() == address.path()) {
                self.peers.push(address);
            }
            return true;
        }
        // A peer in the network naming itself by its path outside the jail
        // is reached by its name in the network's directory.
        if let Some(dir) = &self.dir_path
            && let Ok(rel) = Path::new(OsStr::from_bytes(peer.path())).strip_prefix(dir)
            && let Ok((addr, len)) = sockaddr(rel)
        {
            peer = Peer(addr, len);
        }
        if !peer.path().is_empty() && !self.peers.iter().any(|p| p.path() == peer.path()) {
            self.peers.push(peer);
        }
        true
    }

    /// `recvmsg` into `iovs`, noting the sender: the datagram's length, and
    /// whether its sender may be a peer ([`Endpoint::note_peer`]).
    fn recvmsg(&mut self, iovs: &mut [libc::iovec], flags: c_int) -> io::Result<(usize, bool)> {
        // SAFETY: plain data.
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        // SAFETY: plain data.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = std::ptr::from_mut(&mut addr).cast();
        msg.msg_namelen = libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_un>()).unwrap();
        msg.msg_iov = iovs.as_mut_ptr();
        msg.msg_iovlen =
            c_int::try_from(iovs.len()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        loop {
            // SAFETY: the message names buffers the caller owns.
            match cvt(unsafe { libc::recvmsg(self.sock.as_raw_fd(), &mut msg, flags) }) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
                Ok(n) => return Ok((n, self.note_peer(addr, msg.msg_namelen))),
            }
        }
    }

    /// Reads one frame; `None` if none is waiting. Empty datagrams only
    /// attach their sender; a datagram whose sender may not be a peer is
    /// dropped.
    fn recv(&mut self, iovs: &mut [libc::iovec]) -> io::Result<Option<usize>> {
        loop {
            match self.recvmsg(iovs, 0) {
                Ok((0, _) | (_, false)) => continue,
                Ok((n, true)) => return Ok(Some(n)),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }
        }
    }

    /// Learns the senders of the datagrams waiting, without taking frames
    /// meant for the guest: attach datagrams in front are consumed, and so
    /// are datagrams whose sender may not be a peer.
    fn learn_peers(&mut self) -> io::Result<()> {
        // macOS refuses a receive without buffers (EMSGSIZE): peek one byte.
        let mut byte = 0u8;
        let mut iov = [libc::iovec {
            iov_base: std::ptr::from_mut(&mut byte).cast(),
            iov_len: 1,
        }];
        loop {
            match self.recvmsg(&mut iov, libc::MSG_PEEK) {
                // An empty datagram attaches; one that is no peer's goes.
                Ok((0, _) | (_, false)) => {
                    self.recvmsg(&mut iov, 0)?;
                }
                // A frame, left for the guest.
                Ok((_, true)) => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    }

    /// Sends a frame to every peer. Peers that went away are forgotten.
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if self.peers.is_empty() {
            self.learn_peers()?;
        }
        let fd = self.sock.as_raw_fd();
        let mut result = Ok(());
        let peers = &mut self.peers;
        in_dir(self.dir, || {
            Self::send_to_peers(fd, peers, frame, &mut result);
            Ok(())
        })?;
        result
    }

    fn send_to_peers(fd: RawFd, peers: &mut Vec<Peer>, frame: &[u8], result: &mut io::Result<()>) {
        peers.retain(|peer| {
            // SAFETY: sendto with a valid buffer and address.
            let ret = unsafe {
                libc::sendto(
                    fd,
                    frame.as_ptr().cast(),
                    frame.len(),
                    0,
                    std::ptr::from_ref(&peer.0).cast(),
                    peer.1,
                )
            };
            if ret >= 0 {
                return true;
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ECONNREFUSED | libc::ENOENT) => false,
                _ => {
                    if result.is_ok() {
                        *result = Err(err);
                    }
                    true
                }
            }
        });
    }
}

/// A device that goes frees its interface's name, as closing a TAP does on
/// Linux (drivers/net/tun.c, v6.1: `tun_chr_close`, whose `__tun_detach`
/// unregisters a TAP nobody made persistent): the endpoint removes the
/// socket file it bound, and only that one: a file at the name that is not
/// it (another's, put there after) is left alone
/// (`test_a_dropped_endpoint_frees_its_name`). The file is looked at and
/// removed while the socket is still open, so to any other opener the name
/// is in use until it is gone (`bind`). A running microVM removes only an
/// endpoint named without a path, in the directory whose sockets its sandbox
/// lets it remove (`ext::sandbox` unlink_rule: a refused or unplugged
/// hot-plugged device, `test_a_hotplugged_endpoint_frees_its_name_when_it_goes`);
/// one at a path stays, and the next bind at the path while a microVM is
/// built replaces it. A process that ends without dropping its devices (a
/// kill) leaves its files too: the next opener of the name replaces a stale
/// one while its microVM is built (`test_stale_endpoint_replaced`), and the
/// jailer removes a dead jail's at the next start of its id
/// (jailer `test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint`).
impl Drop for Endpoint {
    fn drop(&mut self) {
        if crate::ext::sandbox::narrowed() && !(self.named && run_may_remove_endpoints()) {
            return;
        }
        // In a jail's own directory, the openers' turn (`bind_at`).
        let _turn = self
            .dir
            .map(|_| OWN_DIR_TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        let _ = in_dir(self.dir, || {
            let meta = std::fs::symlink_metadata(&self.path)?;
            if meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.bound {
                std::fs::remove_file(&self.path)?;
            }
            Ok(())
        });
    }
}

/// Whether a running microVM's sandbox lets it remove the sockets of its
/// directory of endpoints (`ext::sandbox` unlink_rule, which names that
/// directory): with a network, or outside a jail.
fn run_may_remove_endpoints() -> bool {
    network().is_some() || crate::ext::jail::root().is_none()
}

#[derive(Debug)]
enum Backend {
    Endpoint(Endpoint),
    Vmnet(vmnet::Interface),
}

impl Backend {
    fn recv(&mut self, iovs: &mut [libc::iovec]) -> io::Result<Option<usize>> {
        match self {
            Backend::Endpoint(ep) => ep.recv(iovs),
            Backend::Vmnet(iface) => {
                if let Some(n) = iface.read(iovs)? {
                    return Ok(Some(n));
                }
                // Consume the notifications, then look once more: a packet
                // that arrives later notifies again.
                iface.drain_notifications();
                iface.read(iovs)
            }
        }
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        match self {
            Backend::Endpoint(ep) => ep.send(frame),
            Backend::Vmnet(iface) => iface.write(None, frame),
        }
    }
}

/// Open interfaces by index, for the host side used in tests.
static INDEXES: Mutex<Vec<(i32, PathBuf)>> = Mutex::new(Vec::new());
static NEXT_INDEX: AtomicI32 = AtomicI32::new(1);

/// A network interface for a virtio-net device.
#[derive(Debug)]
pub struct Tap {
    name: String,
    backend: Backend,
    index: i32,
    hdr_len: AtomicUsize,
    offload: AtomicU32,
    /// The frame being written, and the segments made of it.
    tx: Vec<u8>,
    scratch: Vec<u8>,
    /// vmnet in virtio-header mode: the packet being read, the frames made
    /// of a superframe the guest's offloads do not take, waiting to be
    /// read, and the frames dropped as a TAP is never given them.
    rx: Vec<u8>,
    pending: VecDeque<(VnetHdr, Vec<u8>)>,
    dropped: u64,
}

/// What an interface name refers to.
enum Target {
    Vmnet(Mode),
    /// An endpoint path; `%d` in its last component is a unit number.
    Endpoint {
        dir: Option<PathBuf>,
        /// The jail's network, which `dir` is (reached by this descriptor).
        network: Option<BorrowedFd<'static>>,
        name: String,
    },
}

fn parse_name(if_name: &str) -> Result<Target, TapError> {
    let invalid = || TapError::InvalidIfname;
    if if_name.starts_with("vmnet-") && network().is_some() {
        // vmnet is the host's network, as a host interface is outside a
        // network namespace on Linux.
        return Err(TapError::IfreqExecuteError(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "vmnet is the host's network, not the jail's (--netns)",
            ),
            if_name.to_owned(),
        ));
    }
    match if_name {
        "vmnet-shared" => return Ok(Target::Vmnet(Mode::Shared)),
        "vmnet-host" => return Ok(Target::Vmnet(Mode::Host)),
        _ => {}
    }
    if let Some(dev) = if_name.strip_prefix("vmnet-br-") {
        if dev.is_empty() || if_name.len() >= IFACE_NAME_MAX_LEN {
            return Err(invalid());
        }
        return Ok(Target::Vmnet(Mode::Bridged(dev.to_owned())));
    }
    let percent = if_name.matches('%').count();
    if percent > 1 || (percent == 1 && !if_name.contains("%d")) {
        return Err(invalid());
    }
    if if_name.contains('/') {
        // A wick extension: the endpoint the caller named, made where it
        // says. Not in a jail, whose interfaces are the operator's only.
        if jailed() {
            return Err(refuse(
                if_name,
                format_args!(
                    "a path name is for a Firecracker without a jail; a jailed one opens only the \
                     interfaces of its network"
                ),
            ));
        }
        return Ok(Target::Endpoint {
            dir: None,
            network: None,
            name: if_name.to_owned(),
        });
    }
    // The rules of `dev_valid_name`.
    let name = if if_name.is_empty() { "tap%d" } else { if_name };
    if name.len() >= IFACE_NAME_MAX_LEN
        || name == "."
        || name == ".."
        || name.contains(|c: char| c == ':' || c.is_whitespace())
    {
        return Err(invalid());
    }
    if network().is_none() && crate::ext::jail::root().is_some() {
        return Err(refuse(
            name,
            format_args!("a jail without a network (--netns) has no interfaces but vmnet's"),
        ));
    }
    let dir = endpoint_dir().map_err(TapError::OpenTun)?;
    Ok(Target::Endpoint {
        dir: Some(dir),
        network: network().map(|(_, fd)| fd),
        name: name.to_owned(),
    })
}

/// Opens the endpoint `name` in `dir` (`None`: `name` is the path), which
/// is the network reached by `network` if given.
fn open_endpoint(
    dir: Option<&Path>,
    network: Option<BorrowedFd<'static>>,
    name: &str,
) -> Result<(String, Endpoint), TapError> {
    // In a jail the network is the jail's own directory in it.
    let jail = crate::ext::jail::root().is_some();
    let failed = |err: io::Error, name: &str| match err.raw_os_error() {
        Some(libc::ENAMETOOLONG) => TapError::InvalidIfname,
        _ => TapError::IfreqExecuteError(err, name.to_owned()),
    };
    let open = |name: &str| {
        // The interface's lock first ([`IfaceLock`]): a busy one is left
        // before anything of it is touched.
        let lock = dir.map(|dir| IfaceLock::take(dir, network, name)).transpose()?;
        let mut ep = match (dir, network) {
            (Some(dir), Some(fd)) => Endpoint::open(Path::new(name), Some((dir, fd)), jail),
            (Some(dir), None) => Endpoint::open(&dir.join(name), None, false),
            (None, _) => Endpoint::open(Path::new(name), None, false),
        }
        .map_err(|e| failed(e, name))?;
        ep.named = dir.is_some();
        ep.lock = lock;
        Ok::<_, TapError>(ep)
    };
    // A name without a path: the operator's interface, unless this
    // Firecracker may make one ([`may_create`]); a unit name is always one
    // to make, as on Linux.
    if let Some(dir) = dir
        && !may_create()
    {
        let network_dir = dir.parent().unwrap_or(dir);
        if name.contains("%d") {
            return Err(refuse(
                name,
                format_args!("a unit name (%d) is made, and only root makes an interface; the network's switch makes `X` in {network_dir:?}"),
            ));
        }
        if !operator_made(dir, network, name).map_err(|e| failed(e, name))? {
            return Err(refuse(
                name,
                format_args!(
                    "no interface {name:?} in {network_dir:?}: the network's switch makes it (bind its socket \
                     {:?} before configuring the interface)",
                    network_dir.join(name)
                ),
            ));
        }
    }
    if !name.contains("%d") {
        return open(name).map(|ep| (name.to_owned(), ep));
    }
    for unit in 0..MAX_UNITS {
        let candidate = name.replacen("%d", &unit.to_string(), 1);
        if dir.is_some() && candidate.len() >= IFACE_NAME_MAX_LEN {
            break;
        }
        match open(&candidate) {
            Ok(ep) => return Ok((candidate, ep)),
            Err(err) if is_busy(&err) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(TapError::IfreqExecuteError(
        io::Error::from_raw_os_error(libc::ENFILE),
        name.to_owned(),
    ))
}

impl Tap {
    /// See [`TapDevice::open_named`].
    pub fn open_named(if_name: &str) -> Result<Tap, TapError> {
        let (name, backend) = match parse_name(if_name)? {
            Target::Vmnet(_) if crate::ext::sandbox::narrowed() => {
                // A vmnet start makes setup's calls (a pipe, the lookup of
                // NetworkSharing, the root daemon behind vmnet, over XPC),
                // which the narrowed sandbox denies: refused before
                // any of them, so the API reports it and the microVM runs on
                // (sandbox::tests::test_vmnet_hotplug_after_narrow_is_refused).
                return Err(TapError::Backend(
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "a vmnet interface is started while the microVM is built; the sandbox \
                         refuses one hot-plugged into a running microVM (a Unix endpoint can be \
                         hot-plugged)",
                    ),
                    if_name.to_owned(),
                ));
            }
            Target::Vmnet(mode) => {
                let iface = vmnet::Interface::start(&mode)
                    .map_err(|err| TapError::Backend(err, if_name.to_owned()))?;
                (if_name.to_owned(), Backend::Vmnet(iface))
            }
            Target::Endpoint { dir, network, name } => {
                let (name, ep) = open_endpoint(dir.as_deref(), network, &name)?;
                (name, Backend::Endpoint(ep))
            }
        };
        let index = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
        if let Backend::Endpoint(ep) = &backend {
            let path = match &ep.dir_path {
                Some(dir) => dir.join(&ep.path),
                None => ep.path.clone(),
            };
            INDEXES.lock().unwrap().push((index, path));
        }
        Ok(Tap {
            name,
            backend,
            index,
            hdr_len: AtomicUsize::new(vnet::MIN_HDR_LEN),
            offload: AtomicU32::new(0),
            tx: Vec::new(),
            scratch: Vec::new(),
            rx: Vec::new(),
            pending: VecDeque::new(),
            dropped: 0,
        })
    }

    /// See [`TapDevice::if_name_as_str`].
    pub fn if_name_as_str(&self) -> &str {
        &self.name
    }

    /// See [`TapDevice::set_offload`]. The host hands the guest offloaded
    /// frames only from vmnet in virtio-header mode, and then only those the
    /// flags allow ([`vnet::rx_offload`]); otherwise complete frames, which
    /// every setting allows.
    pub fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        vnet::check_offload(flags).map_err(TapError::SetOffloadFlags)?;
        self.offload.store(flags, Ordering::Relaxed);
        Ok(())
    }

    /// See [`TapDevice::set_vnet_hdr_size`].
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        let len = vnet::check_hdr_len(size).map_err(TapError::SetSizeOfVnetHdr)?;
        self.hdr_len.store(len, Ordering::Relaxed);
        Ok(())
    }

    /// See [`TapDevice::write_iovec`].
    pub fn write_iovec(&mut self, buffer: &IoVecBuffer) -> io::Result<usize> {
        let total = buffer.len() as usize;
        let hdr_len = self.hdr_len.load(Ordering::Relaxed);
        self.tx.clear();
        buffer
            .read_volatile_at(&mut self.tx, 0, total)
            .map_err(io::Error::other)?;
        // As the TUN driver: a header and at least an Ethernet header.
        if self.tx.len() < hdr_len + 14 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let (hdr, frame) = self.tx.split_at_mut(hdr_len);
        let hdr = VnetHdr::parse(hdr).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        if let Backend::Vmnet(iface) = &self.backend
            && iface.vnet
            && vnet::tx_offload(&hdr, frame)? == vnet::Tx::Offload
        {
            let mut out = [0u8; vmnet::VNET_HDR_LEN];
            hdr.write(&mut out);
            iface.write(Some(&out), frame)?;
            return Ok(total);
        }
        let backend = &mut self.backend;
        vnet::segment(&hdr, frame, &mut self.scratch, &mut |seg| backend.send(seg))?;
        Ok(total)
    }

    /// See [`TapDevice::read_iovec`]. The header is zeroed (a complete
    /// frame, no offloads), but from vmnet in virtio-header mode
    /// ([`Tap::read_vnet`]).
    pub fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        if matches!(&self.backend, Backend::Vmnet(iface) if iface.vnet) {
            return self.read_vnet(buffer);
        }
        let hdr_len = self.hdr_len.load(Ordering::Relaxed);
        let mut skip = hdr_len;
        let mut first = 0;
        while first < buffer.len() && skip >= buffer[first].iov_len && skip > 0 {
            let len = buffer[first].iov_len;
            // SAFETY: the iovec names memory the caller lets us write.
            unsafe { std::ptr::write_bytes(buffer[first].iov_base.cast::<u8>(), 0, len) };
            skip -= len;
            first += 1;
        }
        if skip > 0 && first == buffer.len() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let saved = buffer.get(first).copied();
        if let Some(iov) = buffer.get_mut(first) {
            // SAFETY: as above; `skip` is within this iovec.
            unsafe { std::ptr::write_bytes(iov.iov_base.cast::<u8>(), 0, skip) };
            // SAFETY: `skip` is below `iov_len`.
            iov.iov_base = unsafe { iov.iov_base.cast::<u8>().add(skip) }.cast();
            iov.iov_len -= skip;
        }
        let result = self.backend.recv(&mut buffer[first..]);
        if let Some(saved) = saved {
            buffer[first] = saved;
        }
        match result? {
            Some(n) => Ok(hdr_len + n),
            None => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
        }
    }

    /// A frame from vmnet in virtio-header mode, given as a TAP gives it
    /// ([`vnet::rx_offload`]): one frame with its header, or the next of the
    /// frames a superframe was split into ([`vnet::rx_segment`]); a frame a
    /// TAP is never given is dropped, counted and logged, and the next one
    /// read.
    fn read_vnet(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        let hdr_len = self.hdr_len.load(Ordering::Relaxed);
        let offloads = self.offload.load(Ordering::Relaxed);
        loop {
            if let Some((hdr, frame)) = self.pending.pop_front() {
                return copy_out(buffer, hdr_len, &hdr, &frame);
            }
            let size = vmnet::VNET_HDR_LEN + RX_ROOM;
            self.rx.resize(size, 0);
            let mut iov = [libc::iovec {
                iov_base: self.rx.as_mut_ptr().cast(),
                iov_len: size,
            }];
            let Some(n) = self.backend.recv(&mut iov)? else {
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            };
            let Backend::Vmnet(iface) = &mut self.backend else {
                unreachable!("read_vnet of an endpoint");
            };
            let mtu = usize::try_from(iface.mtu).unwrap_or(usize::MAX);
            let host = iface.host_addresses();
            let (theirs, frame) = self.rx[..n].split_at_mut(vmnet::VNET_HDR_LEN.min(n));
            let data_valid = theirs.first().is_some_and(|flags| flags & vnet::F_DATA_VALID != 0);
            let mut segments = Vec::new();
            let kept = match vnet::rx_offload(frame, data_valid, mtu, offloads, &|a| host.contains(&a)) {
                vnet::Rx::Frame(hdr) => return copy_out(buffer, hdr_len, &hdr, frame),
                // All the segments or none: a superframe the kernel fails
                // to segment is dropped whole and counted
                // (`validate_xmit_skb`, net/core/dev.c, v6.1, :3671 to
                // :3673 and :3703 to :3706), never a read error. rx_offload
                // answers Segment only for what rx_segment splits
                // (test_rx_tcp_header_under_20_bytes_is_no_tcp_header).
                vnet::Rx::Segment => {
                    let mut keep = |hdr: &VnetHdr, seg: &[u8]| {
                        segments.push((*hdr, seg.to_vec()));
                        Ok(())
                    };
                    vnet::rx_segment(frame, mtu, offloads, &mut self.scratch, &mut keep).is_ok()
                }
                vnet::Rx::Drop => false,
            };
            if kept {
                self.pending.extend(segments);
            } else {
                self.dropped += 1;
                let count = self.dropped.to_string();
                if count.starts_with('1') && count[1..].chars().all(|c| c == '0') {
                    crate::logger::warn!(
                        "{}: dropped a {}-byte frame vmnet delivered that a TAP is never given (over \
                         the MTU {mtu}, not a TCP superframe with a checksum vmnet or this side \
                         checked); {} so far",
                        self.name,
                        frame.len(),
                        self.dropped
                    );
                }
            }
        }
    }
}

/// Writes a header of `hdr_len` bytes (`hdr`, then zeros) and `frame` into
/// `buffer`, as the TUN driver's read does (`tun_put_user`, drivers/net/
/// tun.c, v6.1): EINVAL if the header does not fit (:2108); a frame longer
/// than the rest is cut, and the length is still the whole one (:2152,
/// :2160).
fn copy_out(
    buffer: &mut [libc::iovec],
    hdr_len: usize,
    hdr: &VnetHdr,
    frame: &[u8],
) -> io::Result<usize> {
    if buffer.iter().map(|iov| iov.iov_len).sum::<usize>() < hdr_len {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let total = hdr_len + frame.len();
    let mut head = vec![0u8; hdr_len];
    hdr.write(&mut head);
    let mut parts = [head.as_slice(), frame];
    for iov in buffer.iter() {
        let mut at = 0;
        while at < iov.iov_len {
            let Some(part) = parts.iter_mut().find(|p| !p.is_empty()) else {
                return Ok(total);
            };
            let n = part.len().min(iov.iov_len - at);
            // SAFETY: the iovec names memory the caller lets us write; `at + n`
            // is within it.
            unsafe { std::ptr::copy_nonoverlapping(part.as_ptr(), iov.iov_base.cast::<u8>().add(at), n) };
            *part = &part[n..];
            at += n;
        }
    }
    Ok(total)
}

impl TapDevice for Tap {
    fn open_named(if_name: &str) -> Result<Self, TapError> {
        Tap::open_named(if_name)
    }

    fn if_name_as_str(&self) -> &str {
        Tap::if_name_as_str(self)
    }

    fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        Tap::set_offload(self, flags)
    }

    fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        Tap::set_vnet_hdr_size(self, size)
    }

    fn write_iovec(&mut self, buffer: &IoVecBuffer) -> io::Result<usize> {
        Tap::write_iovec(self, buffer)
    }

    fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        Tap::read_iovec(self, buffer)
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        match &self.backend {
            Backend::Endpoint(ep) => ep.sock.as_raw_fd(),
            Backend::Vmnet(iface) => iface.as_raw_fd(),
        }
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        INDEXES.lock().unwrap().retain(|(i, _)| *i != self.index);
    }
}

#[doc(hidden)]
pub mod simulator {
    //! The host side of an endpoint [`Tap`]: what the Linux tests do with a
    //! packet socket bound to the TAP.

    use super::*;

    /// The index of an open interface.
    pub fn if_index(tap: &Tap) -> i32 {
        tap.index
    }

    /// Brings the interface up. Endpoints are always up.
    pub fn enable(_tap: &Tap) {}

    /// A host-side socket attached to an endpoint.
    #[derive(Debug)]
    pub struct TapTrafficSimulator {
        sock: OwnedFd,
        path: PathBuf,
        tap: (libc::sockaddr_un, libc::socklen_t),
    }

    impl TapTrafficSimulator {
        /// Attaches to the interface with index `tap_index`.
        pub fn new(tap_index: i32) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let tap_path = INDEXES
                .lock()
                .unwrap()
                .iter()
                .find(|(i, _)| *i == tap_index)
                .map(|(_, p)| p.clone())
                .expect("no endpoint interface with this index");
            let path = endpoint_dir().unwrap().join(format!(
                "sim-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let sock = dgram_socket().unwrap();
            bind(&sock, &path).unwrap();
            let sim = TapTrafficSimulator {
                sock,
                path,
                tap: sockaddr(&tap_path).unwrap(),
            };
            sim.push_tx_packet(&[]);
            sim
        }

        /// Sends a frame to the interface.
        pub fn push_tx_packet(&self, buf: &[u8]) {
            // SAFETY: sendto with a valid buffer and address.
            let ret = unsafe {
                libc::sendto(
                    self.sock.as_raw_fd(),
                    buf.as_ptr().cast(),
                    buf.len(),
                    0,
                    std::ptr::from_ref(&self.tap.0).cast(),
                    self.tap.1,
                )
            };
            assert!(
                ret >= 0,
                "Can't inject tx_packet: {}",
                io::Error::last_os_error()
            );
        }

        /// Receives a frame from the interface, if one is waiting.
        pub fn pop_rx_packet(&self, buf: &mut [u8]) -> bool {
            // macOS returns at once from a receive into nothing; take the
            // frame through a byte, as Linux truncates it to nothing.
            let mut byte = [0u8];
            let buf = if buf.is_empty() { &mut byte[..] } else { buf };
            // SAFETY: recv into a buffer owned by the caller.
            let ret =
                unsafe { libc::recv(self.sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            ret != -1
        }
    }

    impl Drop for TapTrafficSimulator {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use std::os::unix::fs::FileTypeExt;

    use super::simulator::*;
    use super::*;

    fn frame(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 253) as u8).collect()
    }

    #[test]
    fn test_names() {
        assert!(matches!(
            parse_name("vmnet-shared"),
            Ok(Target::Vmnet(Mode::Shared))
        ));
        assert!(matches!(
            parse_name("vmnet-host"),
            Ok(Target::Vmnet(Mode::Host))
        ));
        assert!(
            matches!(parse_name("vmnet-br-en0"), Ok(Target::Vmnet(Mode::Bridged(ref d))) if d == "en0")
        );
        for bad in [
            "vmnet-br-",
            "a:b",
            "a b",
            ".",
            "..",
            "x%d%d",
            "x%s",
            "0123456789abcdef",
        ] {
            assert!(
                matches!(parse_name(bad), Err(TapError::InvalidIfname)),
                "{bad}"
            );
        }
        assert!(matches!(
            parse_name("/tmp/x.sock"),
            Ok(Target::Endpoint { dir: None, .. })
        ));
    }

    /// The refusal of a name, as Linux's TUNSETIFF refuses one without
    /// CAP_NET_ADMIN (drivers/net/tun.c tun_set_iff :2781): EPERM, in
    /// upstream's text.
    fn refused(got: Result<Tap, TapError>, name: &str) {
        match got {
            Err(err @ TapError::IfreqExecuteError(..)) => {
                let TapError::IfreqExecuteError(ref e, ref n) = err else { unreachable!() };
                assert_eq!((e.raw_os_error(), n.as_str()), (Some(libc::EPERM), name), "{err}");
                let text = crate::devices::virtio::net::NetError::TapOpen(err).to_string();
                assert_eq!(
                    text,
                    format!(
                        "Open tap device failed: Error while creating ifreq structure: Operation not permitted \
                         (os error 1). Invalid TUN/TAP Backend provided by {name}. Check our documentation on \
                         setting up the network devices."
                    )
                );
            }
            other => panic!("{name}: {other:?}"),
        }
    }

    /// The operator's entry for `name`: the switch's socket, directly in the
    /// network directory (outside a jail, the user's directory of
    /// endpoints, the parent of this instance's), and the interface's lock
    /// file beside it, mode 0444 (anyone's: [`lock_file`]).
    fn operator_entry(name: &str) -> (std::os::unix::net::UnixDatagram, PathBuf) {
        let path = user_endpoint_dir().unwrap().join(name);
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        lock_file(name, 0o444);
        (std::os::unix::net::UnixDatagram::bind(&path).unwrap(), path)
    }

    /// The lock file of the interface `name` in the user's directory of
    /// endpoints, made anew with `mode` (the operator's: [`IfaceLock`]).
    fn lock_file(name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = user_endpoint_dir().unwrap().join(format!("{name}.lock"));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// The interface `name` busy, in upstream's text: EBUSY, as a second
    /// TUNSETIFF on a TAP another file holds.
    fn busy_text(got: Result<Tap, TapError>, name: &str) {
        match got {
            Err(err @ TapError::IfreqExecuteError(..)) => {
                let text = crate::devices::virtio::net::NetError::TapOpen(err).to_string();
                assert_eq!(
                    text,
                    format!(
                        "Open tap device failed: Error while creating ifreq structure: Resource busy (os error \
                         16). Invalid TUN/TAP Backend provided by {name}. Check our documentation on setting up \
                         the network devices."
                    )
                );
            }
            other => panic!("{name}: {other:?}"),
        }
    }

    /// This instance's directory of endpoints outside a jail.
    fn instance_dir() -> PathBuf {
        user_endpoint_dir().unwrap().join(crate::logger::DEFAULT_INSTANCE_ID)
    }

    // As a user, a name the operator did not make is refused, as a TAP that
    // does not exist is for a user on Linux, and nothing is made; one the
    // operator made opens, its endpoint in this instance's own directory.
    #[test]
    fn test_only_the_operators_interface_opens() {
        let name = format!("fcop{}", std::process::id());
        let _ = std::fs::remove_file(user_endpoint_dir().unwrap().join(&name));
        tests_as::user(|| refused(Tap::open_named(&name), &name));
        assert!(!instance_dir().join(&name).exists());
        assert!(!user_endpoint_dir().unwrap().join(&name).exists());
        let (switch, entry) = operator_entry(&name);
        let tap = tests_as::user(|| Tap::open_named(&name)).unwrap();
        assert_eq!(tap.if_name_as_str(), name);
        let endpoint = instance_dir().join(&name);
        assert!(std::fs::symlink_metadata(&endpoint).unwrap().file_type().is_socket());
        // The switch reaches it there.
        switch.send_to(b"", &endpoint).unwrap();
        // Gone with its device; the operator's interface stays, its lock
        // file too.
        drop(tap);
        assert!(!endpoint.exists());
        assert!(entry.exists());
        let lock = user_endpoint_dir().unwrap().join(format!("{name}.lock"));
        assert!(lock.exists());
        std::fs::remove_file(&entry).unwrap();
        std::fs::remove_file(&lock).unwrap();
    }

    // An interface has one holder at a time, as a TAP: a second open, by
    // another process or this one, is EBUSY in upstream's text
    // (drivers/net/tun.c, v6.1, tun_attach :769 to :771), arbitrated by the
    // kernel (the lock file's lock), and the name opens again once its
    // holder is gone, a SIGKILLed one too.
    #[test]
    fn test_an_interface_held_is_busy_until_its_holder_goes() {
        use std::io::BufRead;
        let name = format!("fcbz{}", std::process::id());
        let (_switch, entry) = operator_entry(&name);
        let mut holder = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "platform::macos::net::tests::iface_holder_child", "--ignored", "--nocapture"])
            .env("WICK_TEST_CASE", &name)
            // Its end of this pipe closes with this process, however it
            // ends, and the holder with it (no child left behind).
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = std::io::BufReader::new(holder.stdout.take().unwrap()).lines();
        // libtest may print the test's name on the line first.
        let held = lines.find(|l| l.as_ref().is_ok_and(|l| l.contains("HELD") || l.contains("FAILED")));
        let held = held.unwrap().unwrap();
        assert!(held.ends_with("HELD"), "{held}");
        tests_as::user(|| busy_text(Tap::open_named(&name), &name));
        holder.kill().unwrap();
        holder.wait().unwrap();
        let tap = tests_as::user(|| Tap::open_named(&name)).unwrap();
        // And this process's second open.
        tests_as::user(|| busy_text(Tap::open_named(&name), &name));
        drop(tap);
        tests_as::user(|| Tap::open_named(&name)).unwrap();
        std::fs::remove_file(&entry).unwrap();
        std::fs::remove_file(user_endpoint_dir().unwrap().join(format!("{name}.lock"))).unwrap();
    }

    #[test]
    #[ignore = "run by test_an_interface_held_is_busy_until_its_holder_goes in a separate process"]
    fn iface_holder_child() {
        let name = std::env::var("WICK_TEST_CASE").unwrap();
        match tests_as::user(|| Tap::open_named(&name)) {
            Ok(tap) => {
                use std::io::Read;
                println!("HELD");
                // Held until the parent's end of stdin closes.
                let _ = std::io::stdin().read(&mut [0u8]);
                drop(tap);
            }
            Err(err) => println!("FAILED {err}"),
        }
    }

    // Who may open an interface is its lock file's mode and owner, as a
    // TAP's owner and group (TUNSETOWNER, TUNSETGROUP) say on Linux
    // (drivers/net/tun.c, v6.1, tun_not_capable :577): the kernel's check
    // of the open refuses a uid the file is not for, and the rest of
    // tun_not_capable's rule (an owner and a group both: both needed) is
    // capable's. A refusal is EPERM in upstream's text. Here the file is
    // this user's, so another uid is the one the check is made as
    // (tests_as::creds); what the kernel refuses another uid is in
    // test_the_lock_file_is_the_owner_check and `jailer-test netns`.
    #[test]
    fn test_an_interface_opens_for_whom_its_lock_file_says() {
        // SAFETY: no arguments.
        let (me, my_group) = unsafe { (libc::geteuid(), libc::getegid()) };
        let (other, other_group) = (me + 1, my_group + 1);
        let name = format!("fcow{}", std::process::id());
        let (_switch, entry) = operator_entry(&name);
        let opens = |mode: u32, euid: u32, groups: &[u32]| {
            lock_file(&name, mode);
            tests_as::user(|| tests_as::creds(euid, groups, || Tap::open_named(&name)))
        };
        // Anyone's.
        drop(opens(0o444, other, &[other_group]).unwrap());
        // The owner's: this uid, not another; root, whoever owns it.
        drop(opens(0o400, me, &[]).unwrap());
        refused(opens(0o400, other, &[my_group]), &name);
        drop(opens(0o400, 0, &[]).unwrap());
        // Owner and group both: only both.
        drop(opens(0o440, me, &[my_group]).unwrap());
        refused(opens(0o440, me, &[other_group]), &name);
        refused(opens(0o440, other, &[my_group]), &name);
        drop(opens(0o440, 0, &[]).unwrap());
        std::fs::remove_file(&entry).unwrap();
        std::fs::remove_file(user_endpoint_dir().unwrap().join(format!("{name}.lock"))).unwrap();
    }

    // tun_not_capable's rule, case by case, as capable reads a lock file's
    // status: for each of no owner and no group, an owner, a group, and
    // both, the uids and groups it opens for (the group alone cannot be had
    // through the kernel here: a file's owner is judged by its owner bits,
    // and a user can give a file no other owner).
    #[test]
    fn test_capable_is_tun_not_capables_rule() {
        let (owner, group) = (501, 20);
        let st = |mode: u16| {
            // SAFETY: plain data.
            let mut st: libc::stat = unsafe { mem::zeroed() };
            st.st_mode = libc::S_IFREG | mode;
            st.st_uid = owner;
            st.st_gid = group;
            st
        };
        let can = |mode: u16, euid: u32, groups: &[u32]| tests_as::creds(euid, groups, || capable(&st(mode)));
        for (euid, groups) in [(owner, &[][..]), (600, &[group][..]), (600, &[][..]), (0, &[][..])] {
            assert!(can(0o444, euid, groups), "unowned, {euid} {groups:?}");
        }
        assert!(can(0o400, owner, &[]) && !can(0o400, 600, &[group]) && can(0o400, 0, &[]));
        assert!(can(0o040, 600, &[group]) && !can(0o040, owner, &[]) && can(0o040, 0, &[]));
        assert!(can(0o440, owner, &[group]) && !can(0o440, owner, &[]) && !can(0o440, 600, &[group]));
        assert!(can(0o440, 0, &[]));
    }

    // The kernel's check is the owner's: a lock file this user may not read
    // (another's, as far as the kernel is concerned) is refused, EPERM in
    // upstream's text, whoever the capable check would let in.
    #[test]
    fn test_the_lock_file_is_the_owner_check() {
        let name = format!("fcnr{}", std::process::id());
        let (_switch, entry) = operator_entry(&name);
        lock_file(&name, 0o000);
        tests_as::user(|| refused(Tap::open_named(&name), &name));
        assert!(!instance_dir().join(&name).exists());
        std::fs::remove_file(&entry).unwrap();
        std::fs::remove_file(user_endpoint_dir().unwrap().join(format!("{name}.lock"))).unwrap();
    }

    // A network directory this Firecracker may not search fails the open
    // with its errno (EACCES), in upstream's text for TUNSETIFF's errors,
    // where on Linux an unreachable network fails earlier, in the jailer's
    // setns of the namespace's file; in a jail the jailer lets the jail's
    // uid search the directory (its ACL), so it is outside one.
    #[test]
    fn test_a_network_that_cannot_be_searched_fails_with_its_errno() {
        use std::os::unix::fs::PermissionsExt;
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let net = dir.as_path().join("n");
        std::fs::create_dir_all(net.join("inst")).unwrap();
        std::fs::set_permissions(&net, std::fs::Permissions::from_mode(0o000)).unwrap();
        let got = tests_as::user(|| open_endpoint(Some(&net.join("inst")), None, "x"));
        std::fs::set_permissions(&net, std::fs::Permissions::from_mode(0o700)).unwrap();
        let Err(err) = got else { panic!("opened") };
        assert_eq!(
            crate::devices::virtio::net::NetError::TapOpen(err).to_string(),
            "Open tap device failed: Error while creating ifreq structure: Permission denied (os error 13). \
             Invalid TUN/TAP Backend provided by x. Check our documentation on setting up the network devices."
        );
    }

    // An interface without its lock file is none the operator made: EPERM,
    // as is a lock file that is a link (to a lock file too), a directory or
    // a socket.
    #[test]
    fn test_an_interface_needs_its_lock_file() {
        let dir = user_endpoint_dir().unwrap();
        let name = format!("fcnl{}", std::process::id());
        let (_switch, entry) = operator_entry(&name);
        let lock = dir.join(format!("{name}.lock"));
        let other = lock_file(&format!("{name}o"), 0o444);
        std::fs::remove_file(&lock).unwrap();
        tests_as::user(|| refused(Tap::open_named(&name), &name));
        std::os::unix::fs::symlink(&other, &lock).unwrap();
        tests_as::user(|| refused(Tap::open_named(&name), &name));
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        tests_as::user(|| refused(Tap::open_named(&name), &name));
        std::fs::remove_dir(&lock).unwrap();
        let sock = std::os::unix::net::UnixDatagram::bind(&lock).unwrap();
        tests_as::user(|| refused(Tap::open_named(&name), &name));
        drop(sock);
        std::fs::remove_file(&lock).unwrap();
        assert!(!instance_dir().join(&name).exists());
        std::fs::remove_file(&entry).unwrap();
        std::fs::remove_file(&other).unwrap();
    }

    // What is not a socket is no entry, however named: a file, a directory,
    // and a symbolic link to the operator's socket.
    #[test]
    fn test_an_entry_is_a_socket() {
        let dir = user_endpoint_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        let pid = std::process::id();
        let (file, folder, link, target) =
            (format!("fcf{pid}"), format!("fcd{pid}"), format!("fcl{pid}"), format!("fct{pid}"));
        std::fs::write(dir.join(&file), b"").unwrap();
        std::fs::create_dir_all(dir.join(&folder)).unwrap();
        let (_switch, target_path) = operator_entry(&target);
        let _ = std::fs::remove_file(dir.join(&link));
        std::os::unix::fs::symlink(&target_path, dir.join(&link)).unwrap();
        for name in [&file, &folder, &link] {
            tests_as::user(|| refused(Tap::open_named(name), name));
            assert!(!instance_dir().join(name).exists(), "{name}");
        }
        std::fs::remove_file(dir.join(&file)).unwrap();
        std::fs::remove_dir(dir.join(&folder)).unwrap();
        std::fs::remove_file(dir.join(&link)).unwrap();
        std::fs::remove_file(&target_path).unwrap();
        std::fs::remove_file(dir.join(format!("{target}.lock"))).unwrap();
    }

    // A unit name (`%d`) is always one to make, as on Linux: refused for a
    // user, made for root, in this instance's directory.
    #[test]
    fn test_a_unit_name_is_made_only_by_the_creator() {
        let name = format!("fcu{}x%d", std::process::id() % 100_000);
        tests_as::user(|| refused(Tap::open_named(&name), &name));
        let tap = Tap::open_named(&name).unwrap();
        let made = instance_dir().join(tap.if_name_as_str());
        assert!(made.exists(), "{made:?}");
        drop(tap);
        assert!(!made.exists(), "{made:?}");
    }

    // Root makes a name nobody made, as root makes a TAP on Linux; it is
    // attached to nothing until a switch attaches. Its lock file, made with
    // it (writable by its owner: a creator's), goes with it, as a TAP root
    // made without TUNSETPERSIST goes at its close, so that nothing of the
    // name is left; while it is held the name is busy.
    #[test]
    fn test_the_creator_makes_a_name_nobody_made() {
        let name = format!("fcmk{}", std::process::id());
        let lock = user_endpoint_dir().unwrap().join(format!("{name}.lock"));
        let _ = std::fs::remove_file(user_endpoint_dir().unwrap().join(&name));
        let _ = std::fs::remove_file(&lock);
        let tap = Tap::open_named(&name).unwrap();
        let made = instance_dir().join(&name);
        assert!(made.exists());
        assert!(!user_endpoint_dir().unwrap().join(&name).exists());
        let mode = std::fs::metadata(&lock).unwrap().mode();
        assert_eq!(mode & 0o200, 0o200, "{mode:o}");
        busy_text(Tap::open_named(&name), &name);
        drop(tap);
        assert!(!made.exists());
        assert!(!lock.exists());
    }

    // A lock file replaced between an opener's open and its look at the
    // name (a switch that makes its interface anew; another creator's
    // removal) is not that opener's: it fails with EBUSY, and the next
    // opener gets the interface by the file there now, so that two never
    // hold one name.
    #[test]
    fn test_a_lock_file_replaced_under_an_opener_is_not_its() {
        let name = format!("fcrp{}", std::process::id());
        let (_switch, entry) = operator_entry(&name);
        let lock = user_endpoint_dir().unwrap().join(format!("{name}.lock"));
        let replace = {
            let lock = lock.clone();
            move || {
                let new = lock.with_extension("new");
                std::fs::write(&new, b"").unwrap();
                std::fs::rename(&new, &lock).unwrap();
            }
        };
        tests_as::user(|| busy_text(tests_as::after_lock(replace, || Tap::open_named(&name)), &name));
        let tap = tests_as::user(|| Tap::open_named(&name)).unwrap();
        drop(tap);
        std::fs::remove_file(&entry).unwrap();
        std::fs::remove_file(&lock).unwrap();
    }

    // Creators that open and drop one name at once, as many as can: each
    // gets the interface or EBUSY, never anything else, and never two hold
    // it at once, however the removal of the lock file a holder made falls
    // between another's open and its lock (the identity check of
    // IfaceLock::take); nothing of the name is left after.
    #[test]
    fn test_creators_racing_a_lock_files_removal_never_both_hold_it() {
        use std::sync::atomic::AtomicUsize;
        let name = format!("fcrc{}", std::process::id());
        let lock = user_endpoint_dir().unwrap().join(format!("{name}.lock"));
        let _ = std::fs::remove_file(&lock);
        let holders = AtomicUsize::new(0);
        let (opened, busy) = (AtomicUsize::new(0), AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..300 {
                        match Tap::open_named(&name) {
                            Ok(tap) => {
                                assert_eq!(holders.fetch_add(1, Ordering::SeqCst), 0, "two holders");
                                opened.fetch_add(1, Ordering::Relaxed);
                                holders.fetch_sub(1, Ordering::SeqCst);
                                drop(tap);
                            }
                            Err(err) if is_busy(&err) => {
                                busy.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(err) => panic!("{err}"),
                        }
                    }
                });
            }
        });
        assert!(opened.load(Ordering::Relaxed) > 0 && busy.load(Ordering::Relaxed) > 0);
        assert!(!lock.exists());
        assert!(!instance_dir().join(&name).exists());
    }

    // A path name is for an unjailed Firecracker: in a jail it is refused,
    // whatever it names, and nothing is made (a jail's names are the
    // operator's interfaces only).
    #[test]
    fn test_a_jail_opens_no_path_name() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let abs = dir.as_path().join("x");
        for name in [abs.to_str().unwrap(), "../x", "a/b", "./x", "x/"] {
            tests_as::jailed(|| refused(Tap::open_named(name), name));
        }
        assert!(!abs.exists());
        // Unjailed, the same absolute path opens.
        let tap = Tap::open_named(abs.to_str().unwrap()).unwrap();
        assert!(abs.exists());
        drop(tap);
    }

    #[test]
    fn test_path_endpoint() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().join("ep%d");
        let tap = Tap::open_named(path.to_str().unwrap()).unwrap();
        let name = dir.as_path().join("ep0");
        assert_eq!(tap.if_name_as_str(), name.to_str().unwrap());
        assert!(name.exists());
        // The name goes with the endpoint, and opens again.
        drop(tap);
        assert!(!name.exists());
        drop(Tap::open_named(path.to_str().unwrap()).unwrap());

        let long = format!("/{}", "x".repeat(200));
        assert!(matches!(
            Tap::open_named(&long),
            Err(TapError::InvalidIfname)
        ));
    }

    #[test]
    fn test_stale_endpoint_replaced() {
        // This process's own name: a test run beside another (another
        // worktree's) shares the user's endpoint directory.
        let name = format!("fcstale{}", std::process::id());
        let path = endpoint_dir().unwrap().join(&name);
        let _ = std::fs::remove_file(&path);
        // A process that died leaves its socket file behind.
        let sock = dgram_socket().unwrap();
        bind(&sock, &path).unwrap();
        drop(sock);
        assert!(path.exists());
        let tap = Tap::open_named(&name).unwrap();
        // A live one is busy, as a TAP opened twice.
        let busy = Tap::open_named(&name).unwrap_err();
        assert!(matches!(&busy, TapError::IfreqExecuteError(e, _) if e.raw_os_error() == Some(libc::EBUSY)), "{busy:?}");
        // Gone with its device, as a TAP's name with its close.
        drop(tap);
        assert!(!path.exists());
        drop(Tap::open_named(&name).unwrap());
        assert!(!path.exists());
    }

    // A device that goes frees its interface's name, as closing a TAP does
    // on Linux (drivers/net/tun.c, v6.1: tun_chr_close, __tun_detach
    // unregisters a TAP nobody made persistent): the endpoint removes the
    // socket file it bound, by a bare name and by a path alike. A file
    // another put at the name after (its own socket, a regular file) is
    // left alone.
    #[test]
    fn test_a_dropped_endpoint_frees_its_name() {
        use std::os::unix::net::UnixDatagram;
        let name = format!("fcfree{}", std::process::id());
        let path = endpoint_dir().unwrap().join(&name);
        let _ = std::fs::remove_file(&path);
        drop(Tap::open_named(&name).unwrap());
        assert!(!path.exists(), "a bare name's socket file stayed");
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let at = dir.as_path().join("ep");
        drop(Tap::open_named(at.to_str().unwrap()).unwrap());
        assert!(!at.exists(), "a path's socket file stayed");
        // Replaced by another while open: a socket, then a regular file.
        let tap = Tap::open_named(&name).unwrap();
        std::fs::remove_file(&path).unwrap();
        let other = UnixDatagram::bind(&path).unwrap();
        drop(tap);
        assert!(path.exists(), "another's socket at the name was removed");
        drop(other);
        std::fs::remove_file(&path).unwrap();
        let tap = Tap::open_named(&name).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"x").unwrap();
        drop(tap);
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
        std::fs::remove_file(&path).unwrap();
    }

    /// Openers of one name at once, on a socket file a VM that ended left:
    /// one gets it and every other one EBUSY, as a second TUNSETIFF on a TAP
    /// another file holds (drivers/net/tun.c, v6.1, tun_attach :769 to :771);
    /// and openers of `name%d` each get a unit of their own, as the kernel
    /// numbers TAPs. Never AddrInUse, and never two holders of one name.
    #[test]
    fn test_openers_of_a_stale_name_take_turns() {
        use std::sync::{Arc, Barrier};
        const OPENERS: usize = 8;
        let dir = std::env::temp_dir().join(format!("fc-turns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stale = |name: &str| {
            let sock = dgram_socket().unwrap();
            bind(&sock, &dir.join(name)).unwrap();
        };
        for round in 0..40 {
            for (name, units) in [("one", false), ("unit%d", true)] {
                if units {
                    (0..4).for_each(|u| stale(&format!("unit{u}")));
                } else {
                    stale("one");
                }
                let start = Arc::new(Barrier::new(OPENERS));
                let hold = Arc::new(Barrier::new(OPENERS));
                let path = dir.join(name);
                let results: Vec<Result<String, String>> = (0..OPENERS)
                    .map(|_| {
                        let (start, hold, path) = (start.clone(), hold.clone(), path.clone());
                        std::thread::spawn(move || {
                            start.wait();
                            let got = Tap::open_named(path.to_str().unwrap());
                            hold.wait();
                            got.map(|tap| tap.if_name_as_str().to_owned()).map_err(|e| match &e {
                                TapError::IfreqExecuteError(err, _) if err.raw_os_error() == Some(libc::EBUSY) => {
                                    "EBUSY".to_owned()
                                }
                                other => format!("{other:?}"),
                            })
                        })
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|t| t.join().unwrap())
                    .collect();
                let held: Vec<&String> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
                let other: Vec<&String> = results.iter().filter_map(|r| r.as_ref().err()).filter(|e| *e != "EBUSY").collect();
                assert!(other.is_empty(), "round {round}, {name}: {results:?}");
                if units {
                    let mut names = held.clone();
                    names.sort();
                    names.dedup();
                    assert_eq!(names.len(), OPENERS, "round {round}, {name}: {results:?}");
                } else {
                    assert_eq!(held.len(), 1, "round {round}, {name}: {results:?}");
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An opener waits for its turn only so long, then fails naming the
    /// directory: a stuck holder of the directory's lock does not hold
    /// Firecracker's start for ever.
    #[test]
    fn test_a_held_turn_fails_the_opener_by_name() {
        let dir = std::env::temp_dir().join(format!("fc-held-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("held");
        let holder = DirTurn::take(&path, TURN_WAIT).unwrap();
        let start = std::time::Instant::now();
        let err = DirTurn::take(&path, std::time::Duration::from_millis(200)).err().unwrap();
        assert!(start.elapsed() >= std::time::Duration::from_millis(200));
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains(&*dir.to_string_lossy()), "{err}");
        drop(holder);
        drop(DirTurn::take(&path, std::time::Duration::from_millis(200)).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // An endpoint in a jail's network: made, reached and removed in the
    // network's directory through its descriptor, whatever the process's
    // working directory (in the jail, the chroot hides the directory).
    #[test]
    fn test_endpoint_in_network_directory() {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixDatagram;

        let net = user_endpoint_dir().unwrap().join(format!("net-{}", std::process::id()));
        std::fs::create_dir_all(&net).unwrap();
        let dir: &'static OwnedFd = Box::leak(Box::new(OwnedFd::from(std::fs::File::open(&net).unwrap())));
        let mut ep = Endpoint::open(Path::new("tap0"), Some((&net, dir.as_fd())), false).unwrap();
        assert!(net.join("tap0").exists());
        // Relative to the network, not to the process's working directory.
        assert!(!Path::new("tap0").exists());
        // A peer naming itself by its path outside the jail, and one by its
        // name in the network.
        let outer = UnixDatagram::bind(net.join("outer")).unwrap();
        outer.send_to(b"", net.join("tap0")).unwrap();
        let inner_path = net.join("inner");
        let inner = UnixDatagram::bind(&inner_path).unwrap();
        inner.send_to(b"", net.join("tap0")).unwrap();
        ep.learn_peers().unwrap();
        let names: Vec<_> = ep.peers.iter().map(|p| p.path().to_vec()).collect();
        assert_eq!(names, [b"outer".to_vec(), b"inner".to_vec()]);
        ep.send(&frame(60)).unwrap();
        let mut buf = [0u8; 100];
        assert_eq!(outer.recv(&mut buf).unwrap(), 60);
        assert_eq!(inner.recv(&mut buf).unwrap(), 60);
        // This thread resolves relative paths as the process does again.
        std::fs::metadata("tap0").unwrap_err();
        // A second endpoint of the name is busy, as a TAP opened twice.
        let busy = Endpoint::open(Path::new("tap0"), Some((&net, dir.as_fd())), false).unwrap_err();
        assert_eq!(busy.raw_os_error(), Some(libc::EBUSY));
        drop(ep);
        assert!(!net.join("tap0").exists());
        std::fs::remove_dir_all(&net).unwrap();
    }

    // An endpoint opens in a jail's own directory of its network while the
    // directory's lock is held on another open of it, as the jailer holds
    // it for the jail's life (and Firecracker without the jailer): before,
    // the opener's turn waited for that lock 10 s and failed, so no jailed
    // interface opened. Openers there still take turns: 8 threads on one
    // stale name, one gets it and the others EBUSY.
    #[test]
    fn test_an_endpoint_opens_in_a_directory_its_jail_holds_locked() {
        use std::os::fd::AsFd;
        use std::sync::{Arc, Barrier};

        let net = user_endpoint_dir().unwrap().join(format!("lk{}", std::process::id()));
        let own = net.join("jail");
        std::fs::create_dir_all(&own).unwrap();
        let held = std::fs::File::open(&own).unwrap();
        // SAFETY: a descriptor owned here.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        let dir: &'static OwnedFd = Box::leak(Box::new(OwnedFd::from(std::fs::File::open(&own).unwrap())));
        let started = std::time::Instant::now();
        let ep = Endpoint::open(Path::new("tap0"), Some((&own, dir.as_fd())), true).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(own.join("tap0").exists());
        drop(ep);
        assert!(!own.join("tap0").exists());
        // A stale name, left by a VMM that ended without its drop: of 8
        // openers at once, one replaces it.
        in_dir(Some(dir.as_fd()), || bind_at(&dgram_socket()?, Path::new("tap0"), true)).unwrap();
        let start = Arc::new(Barrier::new(8));
        let results: Vec<_> = (0..8)
            .map(|_| {
                let (start, own) = (start.clone(), own.clone());
                std::thread::spawn(move || {
                    start.wait();
                    Endpoint::open(Path::new("tap0"), Some((&own, dir.as_fd())), true)
                        .map(|ep| {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            drop(ep);
                        })
                        .map_err(|e| e.raw_os_error())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        let got = results.iter().filter(|r| r.is_ok()).count();
        assert!(got >= 1 && results.iter().all(|r| r.is_ok() || *r == Err(Some(libc::EBUSY))), "{results:?}");
        drop(held);
        std::fs::remove_dir_all(&net).unwrap();
    }

    // A jail's endpoint, in the jail's own directory of a network: its
    // peers are the sockets directly in the network directory that the
    // directory's owner owns (the operator's switch). Any other sender is
    // not sent the guest's frames, and what it sends is not a frame: a
    // socket in the jail's own directory, one in another jail's, one that
    // names itself as the switch does but by a relative name or through
    // `..`, and one with no name. Linux: a second opener of a TAP never
    // becomes a party to it (drivers/net/tun.c tun_attach: EBUSY).
    #[test]
    fn test_a_jails_endpoint_takes_only_the_switch_as_a_peer() {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixDatagram;

        let net = user_endpoint_dir().unwrap().join(format!("jn{}", std::process::id()));
        let (a, b) = (net.join("a"), net.join("b"));
        for dir in [&a, &b] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let open = |dir: &Path| -> &'static OwnedFd { Box::leak(Box::new(OwnedFd::from(std::fs::File::open(dir).unwrap()))) };
        let (dir, other) = (open(&a), open(&b));
        let mut ep = Endpoint::open(Path::new("tap0"), Some((&a, dir.as_fd())), true).unwrap();
        let tap0 = a.join("tap0");
        let switch = UnixDatagram::bind(net.join("switch")).unwrap();
        let inside = UnixDatagram::bind(a.join("inside")).unwrap();
        let theirs = UnixDatagram::bind(b.join("tap0")).unwrap();
        // Named "switch", as the real one's last name, by a relative name
        // bound in another directory; and one reached through `..`.
        let relative = dgram_socket().unwrap();
        in_dir(Some(other.as_fd()), || bind(&relative, Path::new("switch"))).unwrap();
        let relative = UnixDatagram::from(relative);
        let dotted = UnixDatagram::bind(b.join("../b/switch2")).unwrap();
        let unnamed = UnixDatagram::unbound().unwrap();
        let strangers = [&inside, &theirs, &relative, &dotted, &unnamed];
        for sock in strangers.iter().copied().chain([&switch]) {
            sock.set_nonblocking(true).unwrap();
        }
        // Each stranger attaches and sends a frame; then the switch does.
        for (n, stranger) in strangers.iter().enumerate() {
            stranger.send_to(b"", &tap0).unwrap();
            stranger.send_to(&[u8::try_from(n).unwrap() + 1; 60], &tap0).unwrap();
        }
        switch.send_to(&[0xee; 64], &tap0).unwrap();
        // The guest gets the switch's frame, and that one only.
        let mut buf = [0u8; 100];
        let mut iov = [libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() }];
        assert_eq!(ep.recv(&mut iov).unwrap(), Some(64));
        assert_eq!(buf[..64], [0xee; 64]);
        assert_eq!(ep.recv(&mut iov).unwrap(), None);
        assert_eq!(ep.refused, 10, "two datagrams from each of five strangers");
        // Each stranger is said once, by the address it gave (none, for the
        // socket without a name).
        let said: Vec<_> = ep.refused_senders.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect();
        let want = [a.join("inside"), b.join("tap0"), PathBuf::from("switch"), b.join("../b/switch2"), PathBuf::new()];
        assert_eq!(said, want.map(|p| p.to_str().unwrap().to_owned()));
        // The guest's frames go to the switch, and to it only.
        let names: Vec<_> = ep.peers.iter().map(|p| p.path().to_vec()).collect();
        assert_eq!(names, [b"../switch".to_vec()]);
        ep.send(&frame(60)).unwrap();
        assert_eq!(switch.recv(&mut buf).unwrap(), 60);
        for stranger in strangers {
            assert_eq!(stranger.recv(&mut buf).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        // A stranger's frame in front of the queue is not left there for
        // the guest when peers are learned.
        ep.peers.clear();
        inside.send_to(&[1; 60], &tap0).unwrap();
        switch.send_to(b"", &tap0).unwrap();
        ep.send(&frame(60)).unwrap();
        assert_eq!(switch.recv(&mut buf).unwrap(), 60);
        assert_eq!(ep.recv(&mut iov).unwrap(), None);
        std::fs::remove_dir_all(&net).unwrap();
    }

    #[test]
    fn test_peers() {
        let mut tap = Tap::open_named("fcpeer%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let a = TapTrafficSimulator::new(if_index(&tap));
        let b = TapTrafficSimulator::new(if_index(&tap));

        // Every attached peer gets the guest's frames.
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&frame(100));
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        let mut buf = vec![0u8; 200];
        assert!(a.pop_rx_packet(&mut buf));
        assert_eq!(&buf[..100], &out[12..]);
        assert!(b.pop_rx_packet(&mut buf));
        assert!(!a.pop_rx_packet(&mut buf));

        // A peer that went away is forgotten.
        drop(b);
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        assert!(a.pop_rx_packet(&mut buf));
        assert_eq!(
            match &tap.backend {
                Backend::Endpoint(ep) => ep.peers.len(),
                Backend::Vmnet(_) => unreachable!(),
            },
            1
        );

        // Frames shorter than an Ethernet header are refused.
        let short = vec![0u8; 12 + 13];
        let err = tap
            .write_iovec(&IoVecBuffer::from(short.as_slice()))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn test_header_split_across_buffers() {
        let mut tap = Tap::open_named("fcsplit%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let sim = TapTrafficSimulator::new(if_index(&tap));
        let sent = frame(300);
        sim.push_tx_packet(&sent);
        let mut a = vec![0xffu8; 4];
        let mut b = vec![0xffu8; 4];
        let mut c = vec![0xffu8; 400];
        let mut iovs = [&mut a, &mut b, &mut c].map(|v| libc::iovec {
            iov_base: v.as_mut_ptr().cast(),
            iov_len: v.len(),
        });
        assert_eq!(tap.read_iovec(&mut iovs).unwrap(), 312);
        assert_eq!(iovs[2].iov_len, 400);
        assert_eq!(a, [0; 4]);
        assert_eq!(b, [0; 4]);
        assert_eq!(&c[..4], &[0; 4]);
        assert_eq!(&c[4..304], sent.as_slice());

        // Buffers smaller than the header.
        sim.push_tx_packet(&sent);
        let mut small = [libc::iovec {
            iov_base: a.as_mut_ptr().cast(),
            iov_len: 4,
        }];
        let err = tap.read_iovec(&mut small).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn test_offloaded_write_is_segmented() {
        // A TSO frame from the guest leaves as MSS-sized segments.
        let mut tap = Tap::open_named("fctso%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let sim = TapTrafficSimulator::new(if_index(&tap));
        let payload = frame(3000);
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00]);
        let total = u16::try_from(20 + 20 + payload.len()).unwrap();
        pkt.extend_from_slice(&[0x45, 0]);
        pkt.extend_from_slice(&total.to_be_bytes());
        pkt.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        pkt.extend_from_slice(&[0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff]);
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(&payload);
        VnetHdr {
            gso_type: vnet::GSO_TCPV4,
            gso_size: 1000,
            ..Default::default()
        }
        .write(&mut pkt);
        tap.write_iovec(&IoVecBuffer::from(pkt.as_slice())).unwrap();
        let mut got = Vec::new();
        let mut buf = vec![0u8; 2000];
        for _ in 0..3 {
            assert!(sim.pop_rx_packet(&mut buf));
            got.extend_from_slice(&buf[54..1054]);
        }
        assert!(!sim.pop_rx_packet(&mut buf));
        assert_eq!(got, payload);
    }

    #[test]
    fn test_copy_out_writes_the_header_and_frame_across_buffers() {
        let hdr = VnetHdr {
            flags: vnet::F_NEEDS_CSUM,
            gso_type: vnet::GSO_TCPV4,
            hdr_len: 66,
            gso_size: 1448,
            csum_start: 34,
            csum_offset: 16,
        };
        let frame: Vec<u8> = (0..100u8).collect();
        let mut want = vec![0u8; 12];
        hdr.write(&mut want);
        want.extend_from_slice(&frame);
        // Buffers that split the header and the frame anywhere.
        for split in [1, 5, 12, 13, 50] {
            let mut a = vec![0xaa; split];
            let mut b = vec![0xaa; 200];
            let mut iovs = [
                libc::iovec {
                    iov_base: a.as_mut_ptr().cast(),
                    iov_len: a.len(),
                },
                libc::iovec {
                    iov_base: b.as_mut_ptr().cast(),
                    iov_len: b.len(),
                },
            ];
            assert_eq!(copy_out(&mut iovs, 12, &hdr, &frame).unwrap(), 112);
            let mut got = a.clone();
            got.extend_from_slice(&b[..112 - split]);
            assert_eq!(got, want, "split {split}");
            assert!(b[112 - split..].iter().all(|&x| x == 0xaa));
        }
        // Cut where the buffers end, the whole length returned, as
        // tun_put_user does; a buffer shorter than the header is refused.
        let mut a = vec![0u8; 40];
        let mut iovs = [libc::iovec {
            iov_base: a.as_mut_ptr().cast(),
            iov_len: a.len(),
        }];
        assert_eq!(copy_out(&mut iovs, 12, &hdr, &frame).unwrap(), 112);
        assert_eq!(a, want[..40]);
        iovs[0].iov_len = 11;
        let err = copy_out(&mut iovs, 12, &hdr, &frame).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }
}
