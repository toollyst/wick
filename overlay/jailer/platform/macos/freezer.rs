// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The jail's freezer: upstream's cgroup freezer files, for every jail.
//!
//! On Linux a jail's cgroup has the freezer's files: `cgroup.freeze` (write
//! `1` or `0`) and `cgroup.events` (`frozen 0|1`) with cgroup v2,
//! `freezer.state` (`FROZEN`, `THAWED`) with v1. Root writes them at any time;
//! the kernel stops every task of the cgroup, invisibly to them, and starts
//! them again. macOS has no cgroups, so the jailer makes the same files next
//! to the jail's root, in `<chroot-base>/<exec>/<id>/` (outside the chroot,
//! root-owned: the jail can neither see nor write them), for the cgroup
//! version of the jail (`--cgroup-version`, upstream's default 1), and a
//! supervisor process keeps them:
//!
//! - just before the exec ([`start_supervisor`]) the jailer forks twice; the
//!   grandchild is the supervisor (root, parent launchd, a session of its
//!   own), and the jailer goes on to exec Firecracker, which keeps the pid
//!   upstream gives it (with `--daemonize` and `--new-pid-ns` too: the fork
//!   is made by the process that execs);
//! - the jailer waits until the supervisor is ready: it watches the files
//!   (kqueue), checked that the OS's suspend call works (a throwaway child is
//!   suspended, its CPU time read twice, and resumed), and read the control
//!   file. If the jail is frozen by then, the supervisor holds the exec back
//!   until it is thawed;
//! - freezing suspends every process of the jail (`pid_suspend`, measured as
//!   root: the process stops, its parent's `waitpid` sees nothing, SIGCONT
//!   does not undo it; one resume resumes it, calls are not nested), each
//!   one before its children are listed, as a suspended process cannot fork;
//!   one caught forking is suspended on its fork event. Thawing resumes them.
//!   A process is known by its pid and start time, so no other process is
//!   ever suspended or resumed for a reused pid. XNU's source says why
//!   (apple-oss-distributions/xnu): `pid_suspend` (bsd/kern/kern_proc.c)
//!   calls `task_pidsuspend` (osfmk/kern/task.c), which sets the task's one
//!   `pidsuspended` flag (a second call fails, EPERM) and holds its threads,
//!   waiting until they leave user code (`place_task_hold`); SIGCONT's
//!   `task_resume_internal` releases a normal hold only, never that one
//!   (`release_task_hold`); SIGKILL aborts the held threads (`psignal`'s
//!   SIGKILL case, bsd/kern/kern_sig.c). An exec, `POSIX_SPAWN_SETEXEC`'s
//!   too, makes a new task (`cloneproc(..., CLONEPROC_EXEC)`,
//!   bsd/kern/kern_exec.c) whose flag starts clear, so a freeze asked for
//!   while Firecracker's exec is under way is applied once the exec is seen
//!   (`NOTE_EXEC`, which kqueue reports for a SETEXEC spawn: measured);
//! - when Firecracker exits the supervisor resumes what is left of the jail
//!   (the API process ends with Firecracker, as it does without the
//!   supervisor), and exits once the jail is empty.
//!
//! Where the supervisor cannot do as the kernel does, it says so:
//!
//! - a write of an invalid value cannot fail as on Linux (EINVAL). It is
//!   ignored and, once the file has kept it for [`fv::SETTLE_MS`], the file is
//!   restored to the current state with a line on the supervisor's stderr
//!   (Firecracker's, /dev/null with `--daemonize`): the value read back is
//!   always the state;
//! - the files are plain files, not kernfs ones, whose content the kernel
//!   makes at each read (`cgroup_freeze_show`, `freezer_read`) and whose
//!   size no open changes (`kernfs_iop_setattr`: "this ignores size
//!   changes"), so that a read there is never empty and a write
//!   (`cgroup_freeze_write`, under `cgroup_kn_lock_live`) is never undone.
//!   Here ([`Files::restore`], [`Files::write_events`]):
//!   - what the supervisor writes is never read empty or in part: a file is
//!     made aside and given its name whole, and written in place after
//!     that, never cut first. A reader finds what the file held, or the
//!     state's value, followed by newlines alone for the moment in which a
//!     longer value is written over (a value longer than [`MAX_FILE`] bytes,
//!     which is invalid, can be read half written over);
//!   - the supervisor writes the control file only where Linux would read
//!     another text than the one written: a valid value not in the kernel's
//!     form, and an invalid one after the settle. It reads the file again
//!     through the descriptor it writes with, under `flock(LOCK_EX)` on the
//!     file, and writes nothing if the file holds another text than the one
//!     it handled: that write is handled as any, from its own event. So a
//!     write that lands before that second read is never lost, and a writer
//!     that holds the file's `flock` for its write (`open` with `O_EXLOCK`,
//!     which XNU's `open1` takes before it truncates, bsd/vfs/
//!     vfs_syscalls.c) never loses one. `flock` is advisory and macOS has no
//!     lock a writer cannot ignore: a writer that takes none (the shell's
//!     `>`) can still lose a write that lands whole between the
//!     supervisor's second read and its write, two system calls in a row,
//!     and only when the supervisor is writing the file back at all;
//!   - an operator's own write through `open(O_TRUNC)` (the shell's `>`)
//!     empties the file before it writes: a reader can read it empty
//!     between the two, which the supervisor cannot prevent (it never
//!     takes an empty file for a value);
//! - the supervisor ends only with the jail: it ignores every signal it can.
//!   Killed with SIGKILL (root only), it leaves the jail as it is: frozen
//!   stays frozen until root kills the jail, and nothing thaws it through the
//!   file. It holds an exclusive lock (`flock`) on the jail's directory while
//!   it keeps the files, so a reader tells a kept file from a stale one
//!   ([`maintained`]);
//! - if it cannot freeze a process of the jail, or fails otherwise, it kills
//!   the jail rather than leave a request undone.
//!
//! `--cgroup freezer.state=FROZEN` (v1) stops the jailer at the cgroup step,
//! before the chroot, the forks of `--daemonize` and `--new-pid-ns` and the
//! pid file, as on Linux, where the jailer freezes itself there: the files are
//! made first and the jailer itself waits until they say `THAWED`
//! ([`at_cgroup_step`]).
//!
//! The supervisor is root code that reads a file root alone can write: it
//! reads it by name in a directory it holds open (never by a path), never
//! follows a link, takes it only if it is a regular, root-owned file with one
//! link that only root can write, reads at most [`MAX_FILE`] bytes into a
//! fixed buffer, allocates nothing from its content, uses no environment and
//! execs nothing. It runs in `/var/empty` (chroot) with only its standard
//! descriptors, the jail's directory and the pipe to the jailer.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) use super::super::freezer_values::{MAX_FILE, Request, State, Version, parse};
use super::super::freezer_values as fv;

/// The most processes a jail may have (Firecracker, its API process, the
/// short-lived child that compiles its sandbox profile); more fail the jail.
const MAX_MEMBERS: usize = 16;
/// The supervisor's working root.
const EMPTY_ROOT: &CStr = c"/var/empty";

/// The control file's name ([`Version::control`]) for the calls that take a
/// C string.
fn control(version: Version) -> &'static CStr {
    match version {
        Version::V1 => c"freezer.state",
        Version::V2 => c"cgroup.freeze",
    }
}

/// [`fv::EVENTS`], as a C string.
const EVENTS: &CStr = c"cgroup.events";
const EVENTS_TMP: &CStr = c".cgroup.events.tmp";

/// The name the control file is written under before it gets its own.
fn control_tmp(version: Version) -> &'static CStr {
    match version {
        Version::V1 => c".freezer.state.tmp",
        Version::V2 => c".cgroup.freeze.tmp",
    }
}

/// What a file of the freezer holds, up to [`MAX_FILE`] + 1 bytes (a longer
/// one is invalid whatever follows).
#[derive(Clone, Copy)]
pub(crate) struct Content {
    buf: [u8; MAX_FILE + 1],
    len: usize,
}

impl Content {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn none() -> Content {
        Content { buf: [0; MAX_FILE + 1], len: 0 }
    }

    /// Reads `file` from its start.
    fn of(file: &OwnedFd) -> io::Result<Content> {
        let mut content = Content::none();
        while content.len < content.buf.len() {
            let rest = &mut content.buf[content.len..];
            // SAFETY: the rest of the buffer.
            let n = unsafe {
                libc::pread(
                    file.as_raw_fd(),
                    rest.as_mut_ptr().cast(),
                    rest.len(),
                    libc::off_t::try_from(content.len).expect("a short file"),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if errno(&err) == libc::EINTR {
                    continue;
                }
                return Err(err);
            }
            if n == 0 {
                break;
            }
            content.len += n.unsigned_abs();
        }
        Ok(content)
    }
}

/// What writing the control file back came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Restored {
    /// It holds the state's value (written, or there already).
    Done,
    /// A writer wrote it after the supervisor read it: left as that writer
    /// left it, to be handled as written.
    Changed,
    /// A writer holds its lock: tried again after [`fv::SETTLE_MS`].
    Busy,
}

/// Whether C string `c` holds `s`.
const fn same_name(c: &CStr, s: &str) -> bool {
    let (a, b) = (c.to_bytes(), s.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
const _: () = assert!(same_name(EVENTS, fv::EVENTS));

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 { Err(io::Error::last_os_error()) } else { Ok(ret) }
}

fn errno(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(0)
}

/// The jail's freezer files, by the directory that holds them.
#[derive(Debug)]
pub(crate) struct Files {
    dir: OwnedFd,
    path: PathBuf,
    version: Version,
    /// The uid that must own them: root (another only in tests).
    owner: u32,
}

/// A file's identity.
type Ident = (u64, u64);

impl Files {
    /// Makes the files in `jail_dir` for a jail in `state` and takes the
    /// directory's lock. Fails if a file is there already (the jailer never
    /// takes over files it did not make) or the lock is held.
    pub(crate) fn create(jail_dir: &Path, version: Version, state: State, owner: u32) -> io::Result<Files> {
        let c_path = CString::new(jail_dir.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: a NUL-terminated path.
        let fd = check(unsafe {
            libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        })?;
        // SAFETY: a descriptor we own from here on.
        let dir = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: a descriptor of ours.
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::other(format!(
                "{}: another jailer keeps this jail's freezer files ({})",
                jail_dir.display(),
                io::Error::last_os_error()
            )));
        }
        let files = Files { dir, path: jail_dir.to_owned(), version, owner };
        files.make(control(version), control_tmp(version), version.canonical(state), true)?;
        if version == Version::V2 {
            files.make(EVENTS, EVENTS_TMP, &fv::events(true, state == State::Frozen), true)?;
        }
        Ok(files)
    }

    /// `name` with `content`: written as `tmp`, which no one else opens,
    /// then given its name, so that it is whole from the moment it is there.
    /// `exclusive`: fails if `name` is there (a link is made, which never
    /// replaces a file); else `name` is replaced, whatever it is (a link, not
    /// what it names).
    fn make(&self, name: &CStr, tmp: &CStr, content: &[u8], exclusive: bool) -> io::Result<()> {
        let dir = self.dir.as_raw_fd();
        let unlink_tmp = || {
            // SAFETY: a directory descriptor and a NUL-terminated name.
            let ret = unsafe { libc::unlinkat(dir, tmp.as_ptr(), 0) };
            if ret != 0 && errno(&io::Error::last_os_error()) != libc::ENOENT {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        unlink_tmp()?;
        self.create_file(tmp, content)?;
        // SAFETY: a directory descriptor and NUL-terminated names.
        let named = check(unsafe {
            if exclusive {
                libc::linkat(dir, tmp.as_ptr(), dir, name.as_ptr(), 0)
            } else {
                libc::renameat(dir, tmp.as_ptr(), dir, name.as_ptr())
            }
        })
        .map_err(|e| io::Error::new(e.kind(), format!("{}/{}: {e}", self.path.display(), name.to_string_lossy())));
        if exclusive || named.is_err() {
            let removed = unlink_tmp();
            named?;
            removed?;
        }
        Ok(())
    }

    fn create_file(&self, name: &CStr, content: &[u8]) -> io::Result<()> {
        // SAFETY: a directory descriptor and a NUL-terminated name.
        let fd = check(unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            )
        })
        .map_err(|e| io::Error::new(e.kind(), format!("{}/{}: {e}", self.path.display(), name.to_string_lossy())))?;
        // SAFETY: a descriptor we own from here on.
        let file = unsafe { OwnedFd::from_raw_fd(fd) };
        write_all_at(&file, content)?;
        // SAFETY: a descriptor of ours; the umask does not decide the mode.
        check(unsafe { libc::fchmod(file.as_raw_fd(), 0o644) })?;
        Ok(())
    }

    /// `name`'s identity if it is a file only `owner` controls: a regular
    /// file (not a link), owned by `owner`, one link, written by its owner
    /// only. Looked at without opening it, and again once open.
    fn trusted(&self, st: &libc::stat) -> bool {
        st.st_mode & libc::S_IFMT == libc::S_IFREG
            && st.st_uid == self.owner
            && st.st_nlink == 1
            && st.st_mode & 0o022 == 0
    }

    fn stat_at(&self, name: &CStr) -> io::Result<libc::stat> {
        // SAFETY: zeroed is a valid stat to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a directory descriptor, a NUL-terminated name, an out-pointer.
        check(unsafe { libc::fstatat(self.dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
        Ok(st)
    }

    /// Opens `name` with `flags` if it is a trusted file; `None` if it is
    /// not (or not there).
    fn open_trusted(&self, name: &CStr, flags: libc::c_int) -> io::Result<Option<(OwnedFd, Ident)>> {
        let before = match self.stat_at(name) {
            Ok(st) => st,
            Err(e) if errno(&e) == libc::ENOENT => return Ok(None),
            Err(e) => return Err(e),
        };
        if !self.trusted(&before) {
            return Ok(None);
        }
        // SAFETY: a directory descriptor and a NUL-terminated name.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return if errno(&err) == libc::ENOENT { Ok(None) } else { Err(err) };
        }
        // SAFETY: a descriptor we own from here on.
        let file = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zeroed is a valid stat to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a descriptor of ours, an out-pointer.
        check(unsafe { libc::fstat(file.as_raw_fd(), &mut st) })?;
        if !self.trusted(&st) || (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino) {
            return Ok(None);
        }
        Ok(Some((file, (u64::from(st.st_dev.cast_unsigned()), st.st_ino))))
    }

    /// Reads the control file: the request, whether the file holds the
    /// request's canonical form, and what it holds (what
    /// [`restore`](Self::restore) is given).
    pub(crate) fn read(&self) -> io::Result<(Request, bool, Content)> {
        let Some((file, _)) = self.open_trusted(control(self.version), libc::O_RDONLY)? else {
            return Ok((Request::Invalid, false, Content::none()));
        };
        let content = Content::of(&file)?;
        let request = parse(self.version, content.bytes());
        let canonical = matches!(request, Request::Set(s) if content.bytes() == self.version.canonical(s));
        Ok((request, canonical, content))
    }

    /// Writes the control file back to `state`, in place (a writer that has
    /// it open writes to the same file; a file renamed over it would take
    /// that write away unseen), unless it holds another text than `seen`,
    /// what the supervisor read from it: then a writer wrote it since, and
    /// it is left as it is ([`Restored::Changed`]). It is read again through
    /// the descriptor that writes it, under the file's `flock`: a writer
    /// that holds that lock for its write makes this [`Restored::Busy`] or
    /// waits for it, and never loses a write; no lock on macOS stops a
    /// writer that takes none (the module's text says what is left). One
    /// that is not a trusted file is replaced.
    pub(crate) fn restore(&self, state: State, seen: &[u8]) -> io::Result<Restored> {
        let name = control(self.version);
        let canonical = self.version.canonical(state);
        let Some((file, _)) = self.open_trusted(name, libc::O_RDWR)? else {
            // Not there, or not a file root alone controls: replaced (a
            // link is replaced, not what it names).
            self.make(name, control_tmp(self.version), canonical, false)?;
            return Ok(Restored::Done);
        };
        // SAFETY: a descriptor of ours.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = io::Error::last_os_error();
            return if errno(&err) == libc::EWOULDBLOCK { Ok(Restored::Busy) } else { Err(err) };
        }
        let restored = Self::write_over(&file, canonical, Some(seen));
        // Released now, not with the last copy of the descriptor.
        // SAFETY: a descriptor of ours.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        restored
    }

    /// Writes `content` into `file` in place, only while it holds `seen` if
    /// given. Never cut first (a reader would find it empty): what it holds
    /// beyond `content` is first written over with newlines, in the one
    /// write that writes `content`, then cut, so that a reader finds what
    /// it held, or `content` and newlines.
    fn write_over(file: &OwnedFd, content: &[u8], seen: Option<&[u8]>) -> io::Result<Restored> {
        let held = Content::of(file)?;
        if seen.is_some_and(|seen| held.bytes() != seen) {
            return Ok(Restored::Changed);
        }
        if held.bytes() == content {
            return Ok(Restored::Done);
        }
        let mut padded = [b'\n'; MAX_FILE + 1];
        padded[..content.len()].copy_from_slice(content);
        let len = held.len.max(content.len());
        write_all_at(file, &padded[..len])?;
        if len > content.len() {
            // SAFETY: a descriptor of ours.
            check(unsafe { libc::ftruncate(file.as_raw_fd(), libc::off_t::try_from(content.len()).expect("a short file")) })?;
        }
        Ok(Restored::Done)
    }

    /// v2: writes `cgroup.events`, in place: one write of a text as long as
    /// the one it holds, so a reader never sees half of it and one that
    /// keeps it open reads the new state from its start, as on Linux.
    pub(crate) fn write_events(&self, populated: bool, frozen: bool) -> io::Result<()> {
        if self.version != Version::V2 {
            return Ok(());
        }
        let content = fv::events(populated, frozen);
        match self.open_trusted(EVENTS, libc::O_RDWR)? {
            Some((file, _)) => Self::write_over(&file, &content, None).map(|_| ()),
            None => self.make(EVENTS, EVENTS_TMP, &content, false),
        }
    }

    fn watch_fd(&self) -> io::Result<Option<(OwnedFd, Ident)>> {
        self.open_trusted(control(self.version), libc::O_EVTONLY)
    }
}

fn write_all_at(file: &OwnedFd, content: &[u8]) -> io::Result<()> {
    let mut off = 0;
    while off < content.len() {
        // SAFETY: the rest of `content`.
        let n = unsafe {
            libc::pwrite(
                file.as_raw_fd(),
                content[off..].as_ptr().cast(),
                content.len() - off,
                libc::off_t::try_from(off).expect("a short file"),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if errno(&err) == libc::EINTR {
                continue;
            }
            return Err(err);
        }
        off += n.unsigned_abs();
    }
    Ok(())
}

/// Whether the freezer files in `jail_dir` are kept: a supervisor (or the
/// jailer waiting at the cgroup step) holds the directory's lock.
#[cfg(test)]
pub(crate) fn maintained(jail_dir: &Path) -> io::Result<bool> {
    let c_path = CString::new(jail_dir.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: a NUL-terminated path.
    let fd = check(unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
    // SAFETY: a descriptor we own from here on.
    let dir = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: a descriptor of ours; a shared lock is dropped with it.
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        // Released now, not with the last copy of the descriptor (a fork
        // made meanwhile would hold it).
        // SAFETY: as above.
        unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_UN) };
        return Ok(false);
    }
    let err = io::Error::last_os_error();
    if errno(&err) == libc::EWOULDBLOCK { Ok(true) } else { Err(err) }
}

// ---------------------------------------------------------------- kqueue

fn kev(ident: usize, filter: i16, flags: u16, fflags: u32, data: isize) -> libc::kevent {
    libc::kevent { ident, filter, flags, fflags, data, udata: std::ptr::null_mut() }
}

const TIMER_SETTLE: usize = 1;

/// A descriptor as a kevent identifier.
fn fd_ident(fd: RawFd) -> usize {
    usize::try_from(fd).expect("a valid descriptor")
}
const VNODE_FLAGS: u32 =
    libc::NOTE_WRITE | libc::NOTE_EXTEND | libc::NOTE_ATTRIB | libc::NOTE_DELETE | libc::NOTE_RENAME | libc::NOTE_REVOKE | libc::NOTE_LINK;
const PROC_FLAGS: u32 = libc::NOTE_EXIT | libc::NOTE_FORK | libc::NOTE_EXEC;

/// The kqueue that watches the files (and, in the supervisor, the jail).
pub(crate) struct Watch {
    kq: OwnedFd,
    control: Option<(OwnedFd, Ident)>,
}

/// What woke a [`Watch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// The control file or the directory changed.
    File,
    /// The control file stayed empty or invalid for [`fv::SETTLE_MS`].
    Settled,
    /// A process event (`NOTE_EXIT`, `NOTE_FORK`, `NOTE_EXEC` bits).
    Proc(libc::pid_t, u32),
}

impl Watch {
    pub(crate) fn new(files: &Files) -> io::Result<Watch> {
        // SAFETY: no arguments.
        let kq = check(unsafe { libc::kqueue() })?;
        // SAFETY: a descriptor we own from here on.
        let kq = unsafe { OwnedFd::from_raw_fd(kq) };
        // SAFETY: a descriptor of ours.
        check(unsafe { libc::fcntl(kq.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
        let mut watch = Watch { kq, control: None };
        let dir = files.dir.as_raw_fd();
        watch.change(&[kev(fd_ident(dir), libc::EVFILT_VNODE, libc::EV_ADD | libc::EV_CLEAR, VNODE_FLAGS, 0)])?;
        watch.rearm(files)?;
        Ok(watch)
    }

    fn change(&self, changes: &[libc::kevent]) -> io::Result<()> {
        // SAFETY: `changes` is a valid array; no output.
        check(unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                changes.as_ptr(),
                libc::c_int::try_from(changes.len()).expect("few changes"),
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        })?;
        Ok(())
    }

    /// Watches the control file there now, if it is another file than the
    /// one watched (an editor that writes a new file and renames it).
    fn rearm(&mut self, files: &Files) -> io::Result<()> {
        let now = files.watch_fd()?;
        let same = matches!((&now, &self.control), (Some((_, a)), Some((_, b))) if a == b);
        if same {
            return Ok(());
        }
        // Closing the old descriptor removes its event.
        self.control = None;
        if let Some((fd, ident)) = now {
            self.change(&[kev(
                fd_ident(fd.as_raw_fd()),
                libc::EVFILT_VNODE,
                libc::EV_ADD | libc::EV_CLEAR,
                VNODE_FLAGS,
                0,
            )])?;
            self.control = Some((fd, ident));
        }
        Ok(())
    }

    fn settle_later(&self) -> io::Result<()> {
        self.change(&[kev(TIMER_SETTLE, libc::EVFILT_TIMER, libc::EV_ADD | libc::EV_ONESHOT, 0, isize::try_from(fv::SETTLE_MS).unwrap_or(isize::MAX))])
    }

    fn settle_cancel(&self) {
        // Not armed is fine.
        let _ = self.change(&[kev(TIMER_SETTLE, libc::EVFILT_TIMER, libc::EV_DELETE, 0, 0)]);
    }

    /// Watches process `pid`; false if it is gone.
    pub(crate) fn watch_proc(&self, pid: libc::pid_t) -> io::Result<bool> {
        let ident = usize::try_from(pid).map_err(io::Error::other)?;
        match self.change(&[kev(ident, libc::EVFILT_PROC, libc::EV_ADD | libc::EV_CLEAR, PROC_FLAGS, 0)]) {
            Ok(()) => Ok(true),
            Err(e) if errno(&e) == libc::ESRCH => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Waits for the next events (`timeout_ms` none: no limit).
    pub(crate) fn wait(&self, timeout_ms: Option<u32>, out: &mut Vec<Event>) -> io::Result<()> {
        out.clear();
        // SAFETY: zeroed kevents are valid output slots.
        let mut evs: [libc::kevent; 16] = unsafe { std::mem::zeroed() };
        let ts = timeout_ms.map(|ms| libc::timespec {
            tv_sec: libc::time_t::from(ms / 1000),
            tv_nsec: libc::c_long::from(ms % 1000) * 1_000_000,
        });
        let n = loop {
            // SAFETY: an output array of 16 and an optional timeout.
            let n = unsafe {
                libc::kevent(
                    self.kq.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    evs.as_mut_ptr(),
                    16,
                    ts.as_ref().map_or(std::ptr::null(), |t| t),
                )
            };
            if n >= 0 {
                break n.unsigned_abs() as usize;
            }
            let err = io::Error::last_os_error();
            if errno(&err) != libc::EINTR {
                return Err(err);
            }
        };
        for ev in &evs[..n] {
            if ev.flags & libc::EV_ERROR != 0 {
                return Err(io::Error::from_raw_os_error(i32::try_from(ev.data).unwrap_or(libc::EIO)));
            }
            out.push(match ev.filter {
                libc::EVFILT_VNODE => Event::File,
                libc::EVFILT_TIMER => Event::Settled,
                _ => Event::Proc(libc::pid_t::try_from(ev.ident).unwrap_or(-1), ev.fflags),
            });
        }
        Ok(())
    }
}

/// The control file's side of the protocol, shared by the jailer waiting at
/// the cgroup step and the supervisor.
pub(crate) struct Control {
    /// The state the jail is in (or is being put in).
    pub(crate) state: State,
    /// An empty or invalid file waits for [`fv::SETTLE_MS`] to be restored.
    settling: bool,
}

impl Control {
    pub(crate) fn new(state: State) -> Control {
        Control { state, settling: false }
    }

    /// Handles a file event or the settle timer: the state the file now asks
    /// for (`None`: nothing to do). Logs to `log` what it restores.
    pub(crate) fn handle(
        &mut self,
        files: &Files,
        watch: &mut Watch,
        event: Event,
        log: &mut dyn FnMut(&str),
    ) -> io::Result<Option<State>> {
        watch.rearm(files)?;
        let (request, canonical, seen) = files.read()?;
        match request {
            Request::Set(state) => {
                if self.settling {
                    watch.settle_cancel();
                    self.settling = false;
                }
                self.state = state;
                if !canonical {
                    // As Linux reads the file back; nothing is written when
                    // it holds that already.
                    self.write_back(files, watch, seen.bytes())?;
                }
                Ok(Some(state))
            }
            Request::Empty | Request::Invalid if event == Event::Settled => {
                self.settling = false;
                if self.write_back(files, watch, seen.bytes())? == Restored::Done {
                    log(&fv::ignored(files.version, request));
                }
                watch.rearm(files)?;
                Ok(None)
            }
            Request::Empty | Request::Invalid => {
                if !self.settling {
                    watch.settle_later()?;
                    self.settling = true;
                }
                Ok(None)
            }
        }
    }

    /// Writes the control file back to the state, `seen` being what was
    /// read from it. Written since by a writer: left as it is, and handled
    /// from that write's own event (the watch was armed before the read),
    /// so that write is not undone. Its lock held by a writer: tried again
    /// after [`fv::SETTLE_MS`], the file holding meanwhile what was written.
    fn write_back(&mut self, files: &Files, watch: &mut Watch, seen: &[u8]) -> io::Result<Restored> {
        let restored = files.restore(self.state, seen)?;
        if restored == Restored::Busy {
            watch.settle_later()?;
            self.settling = true;
        }
        Ok(restored)
    }
}

// ---------------------------------------------------------------- the jail's processes

/// What the supervisor needs of the OS, so the logic is tested without
/// root.
pub(crate) trait Os {
    /// `pid`'s start time; `None` if it is gone.
    fn start_time(&self, pid: libc::pid_t) -> Option<(u64, u64)>;
    fn children(&self, pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>>;
    fn suspend(&mut self, pid: libc::pid_t) -> io::Result<()>;
    fn resume(&mut self, pid: libc::pid_t) -> io::Result<()>;
    fn kill(&mut self, pid: libc::pid_t);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Member {
    pid: libc::pid_t,
    start: (u64, u64),
    suspended: bool,
}

/// The jail's processes and whether they are frozen.
#[derive(Debug)]
pub(crate) struct Jail {
    /// Firecracker (first, while it runs), then the processes it made.
    members: Vec<Member>,
    pub(crate) frozen: bool,
}

/// Why the jail must be ended.
#[derive(Debug)]
pub(crate) enum Failure {
    TooMany,
    Os(&'static str, libc::pid_t, io::Error),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::TooMany => write!(f, "the jail has more than {MAX_MEMBERS} processes"),
            Failure::Os(what, pid, err) => write!(f, "{what} of process {pid} failed: {err}"),
        }
    }
}

impl Jail {
    pub(crate) fn new(pid: libc::pid_t, start: (u64, u64)) -> Jail {
        let mut members = Vec::with_capacity(MAX_MEMBERS);
        members.push(Member { pid, start, suspended: false });
        Jail { members, frozen: false }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub(crate) fn pids(&self) -> Vec<libc::pid_t> {
        self.members.iter().map(|m| m.pid).collect()
    }

    pub(crate) fn exited(&mut self, pid: libc::pid_t) {
        self.members.retain(|m| m.pid != pid);
    }

    /// The member `pid`, if it is still the process it was.
    fn live(&mut self, os: &dyn Os, pid: libc::pid_t) -> Option<usize> {
        let i = self.members.iter().position(|m| m.pid == pid)?;
        if os.start_time(pid) == Some(self.members[i].start) {
            Some(i)
        } else {
            // Gone (its pid may be another process's by now).
            self.members.remove(i);
            None
        }
    }

    /// Adds the children of every member that are not members yet (and
    /// freezes them if the jail is frozen); returns them, to be watched.
    pub(crate) fn discover(&mut self, os: &mut dyn Os) -> Result<Vec<libc::pid_t>, Failure> {
        let mut new = Vec::new();
        let mut i = 0;
        while i < self.members.len() {
            let pid = self.members[i].pid;
            if self.frozen {
                self.suspend(os, pid)?;
            }
            if self.members.get(i).map(|m| m.pid) != Some(pid) {
                // Gone: the next member is at `i` now.
                continue;
            }
            i += 1;
            let Ok(kids) = os.children(pid) else { continue };
            for kid in kids {
                if self.members.iter().any(|m| m.pid == kid) {
                    continue;
                }
                let Some(start) = os.start_time(kid) else { continue };
                if self.members.len() == MAX_MEMBERS {
                    return Err(Failure::TooMany);
                }
                self.members.push(Member { pid: kid, start, suspended: false });
                new.push(kid);
            }
        }
        Ok(new)
    }

    fn suspend(&mut self, os: &mut dyn Os, pid: libc::pid_t) -> Result<(), Failure> {
        let Some(i) = self.live(os, pid) else { return Ok(()) };
        if self.members[i].suspended {
            return Ok(());
        }
        match os.suspend(pid) {
            // EPERM as root: already suspended (pid_suspend does not nest).
            Ok(()) => {}
            Err(e) if errno(&e) == libc::EPERM => {}
            Err(e) if errno(&e) == libc::ESRCH => {
                self.exited(pid);
                return Ok(());
            }
            Err(e) => return Err(Failure::Os("pid_suspend", pid, e)),
        }
        self.members[i].suspended = true;
        Ok(())
    }

    /// Suspends every process of the jail, each before its children are
    /// listed (a suspended process cannot fork); returns the processes
    /// found, to be watched.
    pub(crate) fn freeze(&mut self, os: &mut dyn Os) -> Result<Vec<libc::pid_t>, Failure> {
        self.frozen = true;
        self.discover(os)
    }

    /// Resumes every process of the jail.
    pub(crate) fn thaw(&mut self, os: &mut dyn Os) -> Result<(), Failure> {
        self.frozen = false;
        for pid in self.pids() {
            let Some(i) = self.live(os, pid) else { continue };
            if !self.members[i].suspended {
                continue;
            }
            match os.resume(pid) {
                // EPERM as root: not suspended (any more).
                Ok(()) => {}
                Err(e) if matches!(errno(&e), libc::EPERM | libc::ESRCH) => {}
                Err(e) => return Err(Failure::Os("pid_resume", pid, e)),
            }
            self.members[i].suspended = false;
        }
        Ok(())
    }

    /// Kills every process of the jail (and resumes it, so a suspended one
    /// ends whether or not the kill does that by itself).
    pub(crate) fn kill_all(&mut self, os: &mut dyn Os) {
        for pid in self.pids() {
            if self.live(os, pid).is_some() {
                os.kill(pid);
                let _ = os.resume(pid);
            }
        }
        self.members.clear();
    }
}

/// The OS's calls, as root.
pub(crate) struct RealOs;

unsafe extern "C" {
    fn pid_suspend(pid: libc::c_int) -> libc::c_int;
    fn pid_resume(pid: libc::c_int) -> libc::c_int;
}

pub(crate) fn start_time(pid: libc::pid_t) -> Option<(u64, u64)> {
    // SAFETY: zeroed is a valid proc_bsdinfo to fill.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    // SAFETY: an output buffer of `size` bytes.
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    (n == size).then_some((info.pbi_start_tvsec, info.pbi_start_tvusec))
}

/// `pid`'s CPU time so far, in the kernel's units.
pub(crate) fn cpu_time(pid: libc::pid_t) -> Option<u64> {
    // SAFETY: zeroed is a valid proc_taskinfo to fill.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_taskinfo>()).ok()?;
    // SAFETY: an output buffer of `size` bytes.
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTASKINFO, 0, (&raw mut info).cast(), size) };
    (n == size).then_some(info.pti_total_user + info.pti_total_system)
}

impl Os for RealOs {
    fn start_time(&self, pid: libc::pid_t) -> Option<(u64, u64)> {
        start_time(pid)
    }

    fn children(&self, pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
        let mut buf = [0 as libc::pid_t; MAX_MEMBERS + 1];
        let size = libc::c_int::try_from(std::mem::size_of_val(&buf)).expect("a small buffer");
        // SAFETY: an output buffer of `size` bytes.
        let n = check(unsafe { libc::proc_listchildpids(pid, buf.as_mut_ptr().cast(), size) })?;
        let n = usize::try_from(n).map_err(io::Error::other)?.min(buf.len());
        Ok(buf[..n].iter().copied().filter(|&p| p > 0).collect())
    }

    fn suspend(&mut self, pid: libc::pid_t) -> io::Result<()> {
        // SAFETY: no pointers.
        check(unsafe { pid_suspend(pid) }).map(drop)
    }

    fn resume(&mut self, pid: libc::pid_t) -> io::Result<()> {
        // SAFETY: no pointers.
        check(unsafe { pid_resume(pid) }).map(drop)
    }

    fn kill(&mut self, pid: libc::pid_t) {
        // SAFETY: no pointers.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// `PROC_PIDLISTTHREADS` (sys/proc_info.h): a process's thread handles.
const PROC_PIDLISTTHREADS: libc::c_int = 6;

/// Whether no thread of `pid` is runnable (`None`: it cannot be read).
///
/// A suspended thread stops accruing CPU time only once it has parked.
/// `pid_suspend` returns when every thread is off its CPU (osfmk/kern/task.c
/// `place_task_hold` -> `task_wait_locked(task, FALSE)`; sched_prim.c
/// `thread_wait`: "Wait until not running on a CPU"), and a thread that is
/// off its CPU but still runnable (preempted) runs again, in the kernel
/// only, to take the hold: the AST on its way back to user code
/// (thread_act.c `thread_apc_ast`) parks it, waiting on its suspend count,
/// so that path's system time is charged after the call returned. A parked
/// thread is not `TH_RUN` and reads `TH_STATE_WAITING` (thread.c
/// `retrieve_thread_basic_info`); only `TH_RUN` reads `TH_STATE_RUNNING`.
pub(crate) fn no_thread_runs(pid: libc::pid_t) -> Option<bool> {
    let mut handles = [0u64; 64];
    let size = libc::c_int::try_from(std::mem::size_of_val(&handles)).ok()?;
    // SAFETY: an output buffer of `size` bytes.
    let n = unsafe { libc::proc_pidinfo(pid, PROC_PIDLISTTHREADS, 0, handles.as_mut_ptr().cast(), size) };
    let n = usize::try_from(n).ok()? / std::mem::size_of::<u64>();
    if n == 0 || n == handles.len() {
        return None;
    }
    let info_size = libc::c_int::try_from(std::mem::size_of::<libc::proc_threadinfo>()).ok()?;
    for &handle in &handles[..n] {
        // SAFETY: zeroed is a valid proc_threadinfo to fill.
        let mut info: libc::proc_threadinfo = unsafe { std::mem::zeroed() };
        // SAFETY: an output buffer of `info_size` bytes.
        let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTHREADINFO, handle, (&raw mut info).cast(), info_size) };
        if got != info_size {
            return None;
        }
        if info.pth_run_state == libc::TH_STATE_RUNNING {
            return Some(false);
        }
    }
    Some(true)
}

/// `pid`'s CPU time once its threads have settled: no thread runs, now and
/// [`SETTLE_GAP_MS`] later, and the time has not changed between the two.
/// From then on a suspended process's time stands still.
///
/// One not-running read is not enough: on its way to park (see
/// [`no_thread_runs`]) a held thread can wait briefly in the kernel (for
/// its thread mutex in `thread_apc_ast`, or, held by SIGSTOP, in the stop
/// signal's path), reading not-running, and then run on to park. Those
/// waits are short and end in the park; the park lasts until the hold is
/// released. A thread that spins in user code cannot read not-running at
/// both ends of the gap with no CPU time between them, so a process that is
/// not held fails here (after a second) or in the window that follows.
pub(crate) fn parked_cpu_time(pid: libc::pid_t) -> Result<u64, String> {
    let t0 = std::time::Instant::now();
    let unreadable = || "cannot read the child's threads or CPU time".to_owned();
    loop {
        if no_thread_runs(pid).ok_or_else(unreadable)? {
            let before = cpu_time(pid).ok_or_else(unreadable)?;
            std::thread::sleep(std::time::Duration::from_millis(SETTLE_GAP_MS));
            if no_thread_runs(pid).ok_or_else(unreadable)? && cpu_time(pid).ok_or_else(unreadable)? == before {
                return Ok(before);
            }
        } else {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if t0.elapsed() > std::time::Duration::from_secs(1) {
            return Err("pid_suspend returned 0, but the child's threads did not stop within 1 s".to_owned());
        }
    }
}

/// The gap over which a suspended process's threads must stay stopped
/// before its CPU time is taken as settled ([`parked_cpu_time`]).
const SETTLE_GAP_MS: u64 = 5;

/// Checks that suspending works on this host: a throwaway child that spins
/// is suspended, uses no CPU time for 30 ms once its threads have parked,
/// and is resumed.
pub(crate) fn self_check(os: &mut dyn Os) -> Result<(), String> {
    // SAFETY: no arguments.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the supervisor has one thread; the child only spins.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if child == 0 {
        // Spins until killed, or until its parent is gone (a supervisor
        // killed mid-check leaves no spinner).
        loop {
            for _ in 0..100_000 {
                std::hint::spin_loop();
            }
            // SAFETY: no arguments.
            if unsafe { libc::getppid() } != parent {
                // SAFETY: ends the child of a fork.
                unsafe { libc::_exit(0) };
            }
        }
    }
    let result = (|| {
        std::thread::sleep(std::time::Duration::from_millis(5));
        os.suspend(child).map_err(|e| format!("pid_suspend of a child: {e}"))?;
        let held = (|| {
            let before = parked_cpu_time(child)?;
            std::thread::sleep(std::time::Duration::from_millis(30));
            let after = cpu_time(child).ok_or("cannot read the child's CPU time")?;
            if before == after {
                Ok(())
            } else {
                Err(format!("pid_suspend returned 0, but the child used CPU time while parked ({before} -> {after})"))
            }
        })();
        os.resume(child).map_err(|e| format!("pid_resume of a child: {e}"))?;
        held
    })();
    // SAFETY: our child.
    unsafe { libc::kill(child, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: our child; an out-pointer.
    while unsafe { libc::waitpid(child, &mut status, 0) } < 0 && errno(&io::Error::last_os_error()) == libc::EINTR {}
    result.map_err(|e| format!("{}: {e}", fv::CANNOT_WORK))
}

// ---------------------------------------------------------------- the supervisor

/// Where the jail's start is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Frozen before the exec: the jailer waits for the word to go on.
    Held,
    /// Told to go on; a freeze is applied once Firecracker's exec is seen.
    Starting,
    Running,
    /// Firecracker has exited: what is left of the jail runs, to end with
    /// it; a request is shown, not applied (Linux's cgroup would hold
    /// nothing of Firecracker's any more).
    Ending,
}

/// The supervisor's state: the files, the jail, the watch.
pub(crate) struct Supervisor<'a> {
    files: Files,
    watch: Watch,
    control: Control,
    jail: Jail,
    /// Firecracker's pid (before the exec: the jailer's, the same).
    root: libc::pid_t,
    phase: Phase,
    /// The pipe to the jailer, until it has the word.
    pub(crate) go: Option<OwnedFd>,
    os: &'a mut dyn Os,
    log: &'a mut dyn FnMut(&str),
    /// What `cgroup.events` says.
    shown: Option<(bool, bool)>,
}

/// How the supervisor ends.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// The jail ended.
    Empty,
    /// It killed the jail.
    Killed,
}

impl<'a> Supervisor<'a> {
    /// Watches the files and the jailer `root` (started at `start`); `None`
    /// if the jailer is gone. Its word goes to `go`, once set.
    pub(crate) fn new(
        files: Files,
        root: libc::pid_t,
        start: (u64, u64),
        os: &'a mut dyn Os,
        log: &'a mut dyn FnMut(&str),
    ) -> io::Result<Option<Supervisor<'a>>> {
        let watch = Watch::new(&files)?;
        if !watch.watch_proc(root)? || os.start_time(root) != Some(start) {
            return Ok(None);
        }
        let control = Control::new(State::Thawed);
        Ok(Some(Supervisor {
            files,
            watch,
            control,
            jail: Jail::new(root, start),
            root,
            phase: Phase::Held,
            go: None,
            os,
            log,
            shown: None,
        }))
    }

    fn show(&mut self) -> io::Result<()> {
        let now = (!self.jail.is_empty(), self.control.state == State::Frozen
                && (self.jail.frozen || matches!(self.phase, Phase::Held | Phase::Ending)));
        if self.shown != Some(now) {
            self.files.write_events(now.0, now.1)?;
            self.shown = Some(now);
        }
        Ok(())
    }

    /// Lets the jailer go on, `cgroup.events` saying thawed first.
    fn send_go(&mut self) -> io::Result<()> {
        self.phase = Phase::Starting;
        self.show()?;
        if let Some(go) = self.go.take() {
            write_all_at_pipe(&go, b"g")?;
        }
        Ok(())
    }

    fn apply(&mut self, state: State) -> Result<(), Failure> {
        match (self.phase, state) {
            (Phase::Held, State::Thawed) => self.send_go().map_err(|e| Failure::Os("telling the jailer to go on", self.root, e)),
            (Phase::Held | Phase::Starting | Phase::Ending, _) => Ok(()),
            (Phase::Running, State::Frozen) => {
                let new = self.jail.freeze(self.os)?;
                self.watch_new(new)
            }
            (Phase::Running, State::Thawed) => self.jail.thaw(self.os),
        }
    }

    fn watch_new(&mut self, pids: Vec<libc::pid_t>) -> Result<(), Failure> {
        for pid in pids {
            match self.watch.watch_proc(pid) {
                Ok(true) => {}
                Ok(false) => self.jail.exited(pid),
                Err(e) => return Err(Failure::Os("watching", pid, e)),
            }
        }
        Ok(())
    }

    fn step(&mut self, event: Event) -> Result<(), Failure> {
        match event {
            Event::File | Event::Settled => {
                let log = &mut *self.log;
                let wanted = self
                    .control
                    .handle(&self.files, &mut self.watch, event, log)
                    .map_err(|e| Failure::Os("reading the control file", self.root, e))?;
                if let Some(state) = wanted {
                    self.apply(state)?;
                }
            }
            Event::Proc(pid, flags) => {
                if flags & libc::NOTE_EXEC != 0 && pid == self.root && self.phase == Phase::Starting {
                    self.phase = Phase::Running;
                    self.apply(self.control.state)?;
                }
                if flags & libc::NOTE_FORK != 0 && self.phase == Phase::Running {
                    let new = self.jail.discover(self.os)?;
                    self.watch_new(new)?;
                }
                if flags & libc::NOTE_EXIT != 0 {
                    self.jail.exited(pid);
                    if pid == self.root {
                        // What is left ends with Firecracker, as without
                        // the supervisor: it must run to do so.
                        self.phase = Phase::Ending;
                        if self.jail.frozen {
                            self.jail.thaw(self.os)?;
                        }
                    }
                }
            }
        }
        self.show().map_err(|e| Failure::Os("writing cgroup.events", self.root, e))
    }

    /// Reads the control file, then serves until the jail is empty.
    pub(crate) fn run(&mut self) -> End {
        let mut events = Vec::new();
        let result = (|| -> Result<(), Failure> {
            self.step(Event::File)?;
            if self.control.state == State::Thawed {
                self.apply(State::Thawed)?;
            }
            self.show().map_err(|e| Failure::Os("writing cgroup.events", self.root, e))?;
            while !self.jail.is_empty() {
                self.watch.wait(None, &mut events).map_err(|e| Failure::Os("kevent", self.root, e))?;
                for &event in &events {
                    self.step(event)?;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => End::Empty,
            Err(failure) => {
                (self.log)(&format!("{failure}: {}", fv::KILLED));
                self.jail.kill_all(self.os);
                let _ = self.files.write_events(false, self.control.state == State::Frozen);
                End::Killed
            }
        }
    }
}

fn write_all_at_pipe(fd: &OwnedFd, bytes: &[u8]) -> io::Result<()> {
    let mut off = 0;
    while off < bytes.len() {
        // SAFETY: the rest of `bytes`.
        let n = unsafe { libc::write(fd.as_raw_fd(), bytes[off..].as_ptr().cast(), bytes.len() - off) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if errno(&err) == libc::EINTR {
                continue;
            }
            return Err(err);
        }
        off += n.unsigned_abs();
    }
    Ok(())
}

// ---------------------------------------------------------------- the jailer's side

/// The files the jailer made at the cgroup step, for the exec.
static FILES: Mutex<Option<Files>> = Mutex::new(None);
/// The cgroup version of the jail: the builder's, else upstream's default.
static VERSION: Mutex<Option<Version>> = Mutex::new(None);

pub(crate) fn set_version(version: Version) {
    *VERSION.lock().unwrap() = Some(version);
}

fn version() -> Version {
    VERSION.lock().unwrap().unwrap_or(Version::V1)
}

/// `--cgroup freezer.state=<state>` at the cgroup step: the files now, and
/// for `FROZEN` the jailer waits there until they say `THAWED`.
pub(crate) fn at_cgroup_step(jail_dir: &Path, state: State) -> io::Result<()> {
    let files = Files::create(jail_dir, Version::V1, state, 0)?;
    if state == State::Frozen {
        wait_until_thawed(&files)?;
    }
    *FILES.lock().unwrap() = Some(files);
    Ok(())
}

/// Waits until the control file says thawed (the jailer at the cgroup step).
pub(crate) fn wait_until_thawed(files: &Files) -> io::Result<()> {
    let mut watch = Watch::new(files)?;
    let mut control = Control::new(State::Frozen);
    let mut log = |line: &str| eprintln!("jailer: freezer of {}: {line}", files.path.display());
    let mut events = vec![Event::File];
    loop {
        for &event in &events {
            if control.handle(files, &mut watch, event, &mut log)? == Some(State::Thawed) {
                files.write_events(true, false)?;
                return Ok(());
            }
        }
        watch.wait(None, &mut events)?;
    }
}

/// The files for the exec of the jail in `jail_dir`: those the cgroup step
/// made, or new ones.
pub(crate) fn files_for_exec(jail_dir: &Path) -> io::Result<Files> {
    if let Some(files) = FILES.lock().unwrap().take() {
        if files.path == jail_dir {
            return Ok(files);
        }
        return Err(io::Error::other(format!(
            "the freezer files are in {}, the jail in {}",
            files.path.display(),
            jail_dir.display()
        )));
    }
    Files::create(jail_dir, version(), State::Thawed, 0)
}

/// Starts the jail's supervisor (see the module's documentation) and waits
/// until it says to go on: it is ready and the jail is not frozen. The
/// jailer has one thread here.
pub(crate) fn start_supervisor(files: Files) -> Result<(), String> {
    let mut fds = [-1; 2];
    // SAFETY: an array of two descriptors.
    check(unsafe { libc::pipe(fds.as_mut_ptr()) }).map_err(|e| format!("pipe: {e}"))?;
    // SAFETY: descriptors we own from here on.
    let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&rd, &wr] {
        // SAFETY: a descriptor of ours.
        check(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) }).map_err(|e| format!("fcntl: {e}"))?;
    }
    // SAFETY: no arguments.
    let root = unsafe { libc::getpid() };
    let start = start_time(root).ok_or("cannot read the jailer's start time")?;
    // SAFETY: the jailer has one thread.
    let first = unsafe { libc::fork() };
    if first < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if first == 0 {
        drop(rd);
        // SAFETY: the first child has one thread.
        match unsafe { libc::fork() } {
            0 => supervisor(files, root, start, wr),
            // SAFETY: ends the first child; the supervisor's parent is launchd.
            pid => unsafe {
                if pid < 0 {
                    let msg = format!("efork: {}", io::Error::last_os_error());
                    let _ = write_all_at_pipe(&wr, msg.as_bytes());
                }
                libc::_exit(0)
            },
        }
    }
    drop(wr);
    drop(files);
    let mut status = 0;
    // SAFETY: our child; an out-pointer.
    while unsafe { libc::waitpid(first, &mut status, 0) } < 0 {
        let err = io::Error::last_os_error();
        if errno(&err) != libc::EINTR {
            return Err(format!("waitpid: {err}"));
        }
    }
    // The supervisor's word: `g`, or `e` and why it failed.
    let mut word = [0u8; 512];
    let mut len = 0;
    while len < word.len() {
        // SAFETY: the rest of the buffer.
        let n = unsafe { libc::read(rd.as_raw_fd(), word[len..].as_mut_ptr().cast(), word.len() - len) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if errno(&err) == libc::EINTR {
                continue;
            }
            return Err(format!("reading the supervisor's word: {err}"));
        }
        if n == 0 || word[0] == b'g' {
            len += n.unsigned_abs();
            break;
        }
        len += n.unsigned_abs();
    }
    match word[..len].split_first() {
        Some((b'g', _)) => Ok(()),
        Some((b'e', why)) => Err(String::from_utf8_lossy(why).into_owned()),
        _ => Err("the supervisor ended without a word".to_owned()),
    }
}

/// The supervisor process (the jailer's grandchild).
fn supervisor(files: Files, root: libc::pid_t, start: (u64, u64), go: OwnedFd) -> ! {
    let path = files.path.clone();
    let mut log = |line: &str| eprintln!("jailer: freezer of {}: {line}", path.display());
    // SAFETY: no arguments.
    unsafe { libc::setsid() };
    ignore_signals();
    if let Err(e) = null_stdio() {
        fail_start(&go, &format!("/dev/null: {e}"));
    }
    if let Err(e) = close_others(&[files.dir.as_raw_fd(), go.as_raw_fd()]) {
        fail_start(&go, &format!("closing descriptors: {e}"));
    }
    let mut os = RealOs;
    if let Err(why) = self_check(&mut os) {
        fail_start(&go, &why);
    }
    let mut sup = match Supervisor::new(files, root, start, &mut os, &mut log) {
        Ok(Some(sup)) => sup,
        // The jailer is gone: nothing to keep.
        // SAFETY: ends this process.
        Ok(None) => unsafe { libc::_exit(0) },
        Err(e) => fail_start(&go, &format!("watching the jail: {e}")),
    };
    // Nothing is opened by path from here on.
    // SAFETY: NUL-terminated paths.
    if unsafe { libc::chroot(EMPTY_ROOT.as_ptr()) } != 0 || unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        fail_start(&go, &format!("chroot to {}: {err}", EMPTY_ROOT.to_string_lossy()));
    }
    sup.go = Some(go);
    let end = sup.run();
    // SAFETY: ends this process.
    unsafe { libc::_exit(i32::from(end != End::Empty)) }
}

/// Tells the jailer why the supervisor could not start, and ends.
fn fail_start(go: &OwnedFd, why: &str) -> ! {
    let mut msg = b"e".to_vec();
    msg.extend_from_slice(why.as_bytes());
    let _ = write_all_at_pipe(go, &msg);
    // SAFETY: ends this process.
    unsafe { libc::_exit(1) }
}

/// Every signal that can be ignored is: the supervisor ends with the jail.
/// SIGCHLD keeps its default (the self-check waits for its child).
fn ignore_signals() {
    for sig in 1..32 {
        if matches!(sig, libc::SIGKILL | libc::SIGSTOP | libc::SIGCHLD) {
            continue;
        }
        // SAFETY: a valid signal number; SIG_IGN is no handler.
        unsafe { libc::signal(sig, libc::SIG_IGN) };
    }
    // SAFETY: an empty set unblocks every signal.
    unsafe {
        let mut set: libc::sigset_t = 0;
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
    }
}

/// Standard input and output from and to /dev/null; standard error is
/// kept (Firecracker's).
fn null_stdio() -> io::Result<()> {
    // SAFETY: a NUL-terminated path.
    let fd = check(unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) })?;
    // SAFETY: a descriptor we own from here on.
    let null = unsafe { OwnedFd::from_raw_fd(fd) };
    for std in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        // SAFETY: valid descriptors.
        check(unsafe { libc::dup2(null.as_raw_fd(), std) })?;
    }
    Ok(())
}

/// Closes every descriptor above the standard ones but `keep`.
fn close_others(keep: &[RawFd]) -> io::Result<()> {
    for fd in super::open_fds()? {
        if !keep.contains(&fd) {
            // SAFETY: a descriptor nothing else here uses.
            unsafe { libc::close(fd) };
        }
    }
    let left: Vec<_> = super::open_fds()?.into_iter().filter(|fd| !keep.contains(fd)).collect();
    if left.is_empty() { Ok(()) } else { Err(io::Error::other(format!("descriptors {left:?} still open"))) }
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::platform::freezer_values::parse_start;

    fn uid() -> u32 {
        // SAFETY: no arguments.
        unsafe { libc::getuid() }
    }

    #[test]
    fn test_parse_as_the_kernel_does() {
        use Request::{Empty, Invalid, Set};
        use State::{Frozen, Thawed};
        // v1 freezer_write: strstrip, then FROZEN or THAWED exactly.
        for (content, want) in [
            (&b"FROZEN\n"[..], Set(Frozen)),
            (b"THAWED", Set(Thawed)),
            (b" \tFROZEN \n\n", Set(Frozen)),
            (b"", Empty),
            (b"\n", Invalid),
            (b"frozen\n", Invalid),
            (b"FREEZING\n", Invalid),
            (b"FROZEN THAWED", Invalid),
            (b"0\n", Invalid),
        ] {
            assert_eq!(parse(Version::V1, content), want, "{:?}", String::from_utf8_lossy(content));
        }
        // v2 cgroup_freeze_write: kstrtoint(strstrip(buf), 0) of 0 or 1.
        for (content, want) in [
            (&b"1\n"[..], Set(Frozen)),
            (b"0", Set(Thawed)),
            (b" 1 ", Set(Frozen)),
            (b"0x1", Set(Frozen)),
            (b"0X0", Set(Thawed)),
            (b"01", Set(Frozen)),
            (b"00", Set(Thawed)),
            (b"+1", Set(Frozen)),
            (b"-0", Set(Thawed)),
            (b"", Empty),
            (b"2", Invalid),
            (b"-1", Invalid),
            (b"08", Invalid),
            (b"0x", Invalid),
            (b"1 1", Invalid),
            (b"one", Invalid),
            (b"99999999999999999999", Invalid),
            (b"FROZEN", Invalid),
        ] {
            assert_eq!(parse(Version::V2, content), want, "{:?}", String::from_utf8_lossy(content));
        }
        // Longer than a read takes: invalid, whatever it holds.
        let mut long = vec![b' '; MAX_FILE];
        long.push(b'1');
        assert_eq!(parse(Version::V2, &long), Invalid);
        // At the start (the jailer writes `<value>\n`, as upstream does).
        assert_eq!(parse_start("FROZEN"), Some(Frozen));
        assert_eq!(parse_start("THAWED"), Some(Thawed));
        for bad in ["", "FREEZING", "bogus", "1"] {
            assert_eq!(parse_start(bad), None, "{bad}");
        }
    }

    // The C string names are the shared module's.
    #[test]
    fn test_c_names() {
        for v in [Version::V1, Version::V2] {
            assert!(same_name(control(v), v.control()), "{v:?}");
        }
        assert!(!same_name(c"cgroup.event", fv::EVENTS));
    }

    fn content(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// The request and whether it is canonical.
    fn request(files: &Files) -> (Request, bool) {
        let (request, canonical, _) = files.read().unwrap();
        (request, canonical)
    }

    /// Restores the control file after reading it.
    fn restore(files: &Files, state: State) -> Restored {
        let (_, _, seen) = files.read().unwrap();
        files.restore(state, seen.bytes()).unwrap()
    }

    // The files: made exclusive, root-owned (here: the test's user), 0644,
    // the directory locked while they are kept; only a regular file with one
    // link that only its owner writes is read, and one that is not is
    // replaced, never written through.
    #[test]
    fn test_files() {
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let dir = tmp.as_path();
        assert!(!maintained(dir).unwrap());
        let files = Files::create(dir, Version::V2, State::Thawed, uid()).unwrap();
        assert!(maintained(dir).unwrap());
        assert_eq!(content(&dir.join("cgroup.freeze")), "0\n");
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 0\n");
        for name in ["cgroup.freeze", "cgroup.events"] {
            let md = std::fs::metadata(dir.join(name)).unwrap();
            assert_eq!((md.uid(), md.mode() & 0o777), (uid(), 0o644), "{name}");
        }
        // Not twice: the lock is held, and the files are there.
        Files::create(dir, Version::V2, State::Thawed, uid()).unwrap_err();
        assert_eq!(request(&files), (Request::Set(State::Thawed), true));
        std::fs::write(dir.join("cgroup.freeze"), "0x1").unwrap();
        assert_eq!(request(&files), (Request::Set(State::Frozen), false));
        assert_eq!(restore(&files, State::Frozen), Restored::Done);
        assert_eq!(content(&dir.join("cgroup.freeze")), "1\n");
        // Written in place: the same file, and a reader that keeps
        // cgroup.events open reads the new state from its start.
        let ino = |name: &str| std::fs::metadata(dir.join(name)).unwrap().ino();
        let (control_ino, events_ino) = (ino("cgroup.freeze"), ino("cgroup.events"));
        let holder = std::fs::File::open(dir.join("cgroup.events")).unwrap();
        files.write_events(true, true).unwrap();
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 1\n");
        let mut held = [0u8; 64];
        let n = std::os::unix::fs::FileExt::read_at(&holder, &mut held, 0).unwrap();
        assert_eq!(&held[..n], b"populated 1\nfrozen 1\n");
        assert!(!dir.join(".cgroup.events.tmp").exists() && !dir.join(".cgroup.freeze.tmp").exists());
        // A longer value written over, valid or not: cut after the value.
        for longer in ["  1  \n\n", "frozen, please\n"] {
            std::fs::write(dir.join("cgroup.freeze"), longer).unwrap();
            assert_eq!(restore(&files, State::Frozen), Restored::Done);
            assert_eq!(content(&dir.join("cgroup.freeze")), "1\n");
        }
        // Longer than a value can be: the same.
        std::fs::write(dir.join("cgroup.freeze"), "1".repeat(4 * MAX_FILE)).unwrap();
        assert_eq!(request(&files), (Request::Invalid, false));
        assert_eq!(restore(&files, State::Thawed), Restored::Done);
        assert_eq!(content(&dir.join("cgroup.freeze")), "0\n");
        assert_eq!((ino("cgroup.freeze"), ino("cgroup.events")), (control_ino, events_ino));
        // It holds the value already: nothing is written.
        let mtime = |name: &str| std::fs::metadata(dir.join(name)).unwrap().modified().unwrap();
        let before = mtime("cgroup.freeze");
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(restore(&files, State::Thawed), Restored::Done);
        assert_eq!(mtime("cgroup.freeze"), before);
        std::fs::write(dir.join("cgroup.freeze"), "1\n").unwrap();

        // Writable by others: not taken.
        std::fs::set_permissions(dir.join("cgroup.freeze"), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(files.read().unwrap().0, Request::Invalid);
        assert_eq!(restore(&files, State::Frozen), Restored::Done);
        assert_eq!(std::fs::metadata(dir.join("cgroup.freeze")).unwrap().mode() & 0o777, 0o644);
        // A link to another file: not followed, and replaced, the file it
        // names left alone (as a hard link: one with two links).
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep\n").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        for link in [
            |v: &Path, c: &Path| std::os::unix::fs::symlink(v, c).unwrap(),
            |v: &Path, c: &Path| std::fs::hard_link(v, c).unwrap(),
        ] {
            std::fs::remove_file(dir.join("cgroup.freeze")).unwrap();
            link(&victim, &dir.join("cgroup.freeze"));
            assert_eq!(files.read().unwrap().0, Request::Invalid);
            assert_eq!(restore(&files, State::Thawed), Restored::Done);
            assert_eq!(content(&victim), "keep\n");
            assert_eq!(content(&dir.join("cgroup.freeze")), "0\n");
            let md = std::fs::symlink_metadata(dir.join("cgroup.freeze")).unwrap();
            assert!(md.is_file() && md.nlink() == 1);
        }
        // A FIFO is not opened (no read blocks), and is replaced.
        std::fs::remove_file(dir.join("cgroup.freeze")).unwrap();
        let c = CString::new(dir.join("cgroup.freeze").as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert_eq!(files.read().unwrap().0, Request::Invalid);
        assert_eq!(restore(&files, State::Thawed), Restored::Done);
        assert!(std::fs::symlink_metadata(dir.join("cgroup.freeze")).unwrap().is_file());
        // Gone: made again.
        std::fs::remove_file(dir.join("cgroup.freeze")).unwrap();
        assert_eq!(files.read().unwrap().0, Request::Invalid);
        assert_eq!(restore(&files, State::Thawed), Restored::Done);
        assert_eq!(content(&dir.join("cgroup.freeze")), "0\n");
        // Another owner than the one required: not taken.
        let other = Files { dir: files.dir.try_clone().unwrap(), path: dir.to_owned(), version: Version::V2, owner: uid() + 1 };
        assert_eq!(other.read().unwrap().0, Request::Invalid);
        drop(other);
        drop(files);
        // (A process another test forks holds the descriptor until its exec.)
        wait_until("the lock is released", || !maintained(dir).unwrap());

        // v1: one file, freezer.state.
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let files = Files::create(tmp.as_path(), Version::V1, State::Frozen, uid()).unwrap();
        assert_eq!(content(&tmp.as_path().join("freezer.state")), "FROZEN\n");
        assert!(!tmp.as_path().join("cgroup.events").exists());
        files.write_events(false, false).unwrap();
        assert!(!tmp.as_path().join("cgroup.events").exists());
    }

    // A write that lands after the supervisor's read is not written over:
    // the file is left as that writer left it. A writer that holds the
    // file's lock is waited for, and its write is the file's.
    #[test]
    fn test_a_write_after_the_read_is_applied() {
        for (version, first, second) in [(Version::V1, "FROZEN", "THAWED"), (Version::V2, "1", "0")] {
            let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
            let files = Files::create(tmp.as_path(), version, State::Thawed, uid()).unwrap();
            let path = tmp.as_path().join(version.control());
            std::fs::write(&path, first).unwrap();
            let (got, canonical, seen) = files.read().unwrap();
            assert_eq!((got, canonical), (Request::Set(State::Frozen), false));
            std::fs::write(&path, second).unwrap();
            assert_eq!(files.restore(State::Frozen, seen.bytes()).unwrap(), Restored::Changed);
            assert_eq!(content(&path), second);
            assert_eq!(request(&files), (Request::Set(State::Thawed), false));

            // Emptied by a writer that has not written yet: left to it.
            std::fs::write(&path, first).unwrap();
            let (_, _, seen) = files.read().unwrap();
            let writer = std::fs::OpenOptions::new().write(true).truncate(true).open(&path).unwrap();
            assert_eq!(files.restore(State::Frozen, seen.bytes()).unwrap(), Restored::Changed);
            std::os::unix::fs::FileExt::write_all_at(&writer, second.as_bytes(), 0).unwrap();
            drop(writer);
            assert_eq!(content(&path), second);

            // A writer holds the lock: busy, then its write is what is read.
            std::fs::write(&path, first).unwrap();
            let (_, _, seen) = files.read().unwrap();
            let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            // SAFETY: a descriptor of the test's.
            assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX) }, 0);
            assert_eq!(files.restore(State::Frozen, seen.bytes()).unwrap(), Restored::Busy);
            assert_eq!(content(&path), first);
            drop(writer);
            assert_eq!(files.restore(State::Frozen, seen.bytes()).unwrap(), Restored::Done);
            assert_eq!(content(&path), String::from_utf8_lossy(version.canonical(State::Frozen)));
        }
    }

    // While a writer holds the control file's lock the state it asked for
    // is applied at once and the write-back waits: tried again every
    // SETTLE_MS, done once the lock is free.
    #[test]
    fn test_a_held_lock_delays_the_write_back_only() {
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let dir = tmp.as_path();
        let files = Files::create(dir, Version::V1, State::Thawed, uid()).unwrap();
        let mut watch = Watch::new(&files).unwrap();
        let mut control = Control::new(State::Thawed);
        let mut log = Vec::new();
        let state = dir.join("freezer.state");
        let writer = std::fs::OpenOptions::new().write(true).open(&state).unwrap();
        // SAFETY: a descriptor of the test's.
        assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX) }, 0);
        std::os::unix::fs::FileExt::write_all_at(&writer, b"FROZEN  ", 0).unwrap();
        expect(&files, &mut watch, &mut control, &mut log, State::Frozen);
        assert_eq!(control.state, State::Frozen);
        // Two settles later: still the writer's text.
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_millis(u64::from(fv::SETTLE_MS) * 2 + 50) {
            next(&files, &mut watch, &mut control, &mut log);
        }
        assert_eq!(content(&state), "FROZEN  ");
        drop(writer);
        let t0 = Instant::now();
        while content(&state) != "FROZEN\n" {
            assert!(t0.elapsed() < Duration::from_secs(3), "not written back: {:?}", content(&state));
            next(&files, &mut watch, &mut control, &mut log);
        }
        assert_eq!(control.state, State::Frozen);
        assert!(log.is_empty(), "{log:?}");
    }

    /// Waits for the watch's next events, handling file ones with `control`.
    fn next(
        files: &Files,
        watch: &mut Watch,
        control: &mut Control,
        log: &mut Vec<String>,
    ) -> Vec<(Event, Option<State>)> {
        let mut events = Vec::new();
        watch.wait(Some(2000), &mut events).unwrap();
        events
            .into_iter()
            .map(|e| {
                let got = control.handle(files, watch, e, &mut |l: &str| log.push(l.to_owned())).unwrap();
                (e, got)
            })
            .collect()
    }

    /// Handles events until one asks for `want` (or 3 s pass).
    fn expect(files: &Files, watch: &mut Watch, control: &mut Control, log: &mut Vec<String>, want: State) {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(3) {
            if next(files, watch, control, log).iter().any(|&(_, s)| s == Some(want)) {
                return;
            }
        }
        panic!("no request for {want:?}");
    }

    /// Handles what is pending until nothing comes for 300 ms.
    fn drain(files: &Files, watch: &mut Watch, control: &mut Control) {
        let mut events = Vec::new();
        loop {
            watch.wait(Some(300), &mut events).unwrap();
            if events.is_empty() {
                return;
            }
            for &e in &events {
                control.handle(files, watch, e, &mut |_: &str| {}).unwrap();
            }
        }
    }

    // A write is seen as it lands; an empty or invalid file is restored to
    // the current state once it has stayed so for SETTLE_MS, with a line; a
    // valid write meanwhile wins; an editor's new file renamed over the old
    // one is seen too.
    #[test]
    fn test_control_protocol() {
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let dir = tmp.as_path();
        let files = Files::create(dir, Version::V1, State::Thawed, uid()).unwrap();
        let mut watch = Watch::new(&files).unwrap();
        let mut control = Control::new(State::Thawed);
        let mut log = Vec::new();
        let state = dir.join("freezer.state");

        std::fs::write(&state, "FROZEN\n").unwrap();
        expect(&files, &mut watch, &mut control, &mut log, State::Frozen);
        assert_eq!(control.state, State::Frozen);
        drain(&files, &mut watch, &mut control);

        // Invalid: nothing at once, then restored to FROZEN.
        let t0 = Instant::now();
        std::fs::write(&state, "FREEZING\n").unwrap();
        let mut restored = false;
        while !restored && t0.elapsed() < Duration::from_secs(3) {
            for (e, s) in next(&files, &mut watch, &mut control, &mut log) {
                // Only the restored file asks for something: FROZEN.
                assert!(s.is_none() || s == Some(State::Frozen), "{s:?}");
                restored |= e == Event::Settled;
            }
        }
        assert!(restored && t0.elapsed() >= Duration::from_millis(u64::from(fv::SETTLE_MS)), "{:?}", t0.elapsed());
        assert_eq!(content(&state), "FROZEN\n");
        assert_eq!(control.state, State::Frozen);
        assert_eq!(log.len(), 1, "{log:?}");
        assert!(log[0].contains("freezer.state: not a valid value"), "{log:?}");

        // Empty (a write's truncation), then the value: no restore.
        drain(&files, &mut watch, &mut control);
        std::fs::write(&state, "").unwrap();
        let got = next(&files, &mut watch, &mut control, &mut log);
        assert!(got.iter().all(|&(_, s)| s.is_none()), "{got:?}");
        std::fs::write(&state, "THAWED\n").unwrap();
        let t0 = Instant::now();
        let mut thawed = false;
        while t0.elapsed() < Duration::from_millis(u64::from(fv::SETTLE_MS) * 2) {
            let mut events = Vec::new();
            watch.wait(Some(50), &mut events).unwrap();
            for e in events {
                assert_ne!(e, Event::Settled, "the settle timer outlived a valid write");
                thawed |= control.handle(&files, &mut watch, e, &mut |_: &str| {}).unwrap() == Some(State::Thawed);
            }
        }
        assert!(thawed);
        assert_eq!(content(&state), "THAWED\n");

        // An editor: a new file renamed over the old one.
        let new = dir.join("freezer.state.new");
        std::fs::write(&new, "FROZEN\n").unwrap();
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::rename(&new, &state).unwrap();
        expect(&files, &mut watch, &mut control, &mut log, State::Frozen);
        drain(&files, &mut watch, &mut control);
        // ... and the new file is the one watched now.
        std::fs::write(&state, "THAWED\n").unwrap();
        expect(&files, &mut watch, &mut control, &mut log, State::Thawed);
        drain(&files, &mut watch, &mut control);
        // Not canonical: written back as Linux reads it.
        std::fs::write(&state, "  FROZEN").unwrap();
        expect(&files, &mut watch, &mut control, &mut log, State::Frozen);
        assert_eq!(content(&state), "FROZEN\n");
    }

    /// The control side of the files, served on a thread as the supervisor
    /// serves it: the state it was last asked for is in `state` (0 thawed,
    /// 1 frozen).
    fn serve(files: &Files, state: &std::sync::atomic::AtomicU8, stop: &std::sync::atomic::AtomicBool) {
        use std::sync::atomic::Ordering::SeqCst;
        let mut watch = Watch::new(files).unwrap();
        let mut control = Control::new(State::Thawed);
        let mut events = vec![Event::File];
        while !stop.load(SeqCst) {
            for &e in &events {
                if let Some(s) = control.handle(files, &mut watch, e, &mut |_: &str| {}).unwrap() {
                    state.store(u8::from(s == State::Frozen), SeqCst);
                }
            }
            watch.wait(Some(20), &mut events).unwrap();
        }
    }

    /// Writes `text` into `path` in one write, in place, as a writer that
    /// keeps the file open does (no truncation: nothing of the writer's own
    /// for a reader to find empty).
    fn write_in_place(path: &Path, text: &[u8]) {
        use std::os::unix::fs::FileExt;
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.write_all_at(text, 0).unwrap();
    }

    /// Whether `text` is `canonical` followed by newlines alone.
    fn canonical_and_newlines(text: &[u8], canonical: &[u8]) -> bool {
        text.starts_with(canonical) && text[canonical.len()..].iter().all(|&b| b == b'\n')
    }

    /// Four readers read the control file as fast as they can while a writer
    /// flips the state 500 times, each time in a form that is written back
    /// (and longer than the canonical one, so the write-back shortens the
    /// file). A reader must find the writer's text or the state's canonical
    /// one (with newlines alone after it), never an empty file and never a
    /// mix; every flip must be applied and written back. The writer's text
    /// cut at the length the file had is its own too: macOS shows a reader
    /// a file that one write is making longer at its old length (measured
    /// here, macOS 27.2, APFS: " FROZEN" for " FROZEN\n" written over
    /// "THAWED\n", nothing else), where a write to a kernfs file has no
    /// reader in its middle.
    fn readers_read_whole_values(version: Version, forms: [&'static [u8]; 2]) {
        use std::sync::atomic::Ordering::SeqCst;
        use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
        const FLIPS: usize = 2000;
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let files = Files::create(tmp.as_path(), version, State::Thawed, uid()).unwrap();
        let path = tmp.as_path().join(version.control());
        let (state, stop) = (AtomicU8::new(0), AtomicBool::new(false));
        let (reads, empty) = (AtomicU64::new(0), AtomicU64::new(0));
        let torn = Mutex::new(Vec::<String>::new());
        let canon = [version.canonical(State::Thawed), version.canonical(State::Frozen)];
        std::thread::scope(|scope| {
            scope.spawn(|| serve(&files, &state, &stop));
            for _ in 0..4 {
                scope.spawn(|| {
                    while !stop.load(SeqCst) {
                        let text = std::fs::read(&path).unwrap();
                        reads.fetch_add(1, SeqCst);
                        if text.is_empty() {
                            empty.fetch_add(1, SeqCst);
                        } else if !forms.contains(&text.as_slice())
                            && !canon.iter().any(|c| canonical_and_newlines(&text, c))
                            && !forms.iter().any(|f| text == f[..canon[0].len()])
                        {
                            let mut torn = torn.lock().unwrap();
                            if torn.len() < 10 {
                                torn.push(String::from_utf8_lossy(&text).into_owned());
                            }
                        }
                    }
                });
            }
            let mut lost = Vec::new();
            for flip in 0..FLIPS {
                let want = (flip + 1) % 2;
                write_in_place(&path, forms[want]);
                let t0 = Instant::now();
                while usize::from(state.load(SeqCst)) != want || std::fs::read(&path).unwrap() != canon[want] {
                    if t0.elapsed() > Duration::from_secs(3) {
                        lost.push((flip, state.load(SeqCst), content(&path)));
                        break;
                    }
                    std::thread::yield_now();
                }
            }
            stop.store(true, SeqCst);
            let (reads, empty) = (reads.load(SeqCst), empty.load(SeqCst));
            let torn = torn.lock().unwrap();
            println!("{version:?}: {FLIPS} flips, {reads} reads, {empty} empty, torn {torn:?}, flips not applied or not written back {lost:?}");
            assert!(reads > 1000, "the readers did not read: {reads}");
            assert!(empty == 0 && torn.is_empty() && lost.is_empty(), "{empty} empty reads of {reads}, torn {torn:?}, lost {lost:?}");
        });
    }

    #[test]
    fn test_readers_read_whole_values_v1() {
        readers_read_whole_values(Version::V1, [b" THAWED\n", b" FROZEN\n"]);
    }

    #[test]
    fn test_readers_read_whole_values_v2() {
        readers_read_whole_values(Version::V2, [b"0 \n\n", b"1 \n\n"]);
    }

    /// A writer's way to write the control file.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Writer {
        /// `open(O_WRONLY | O_TRUNC | O_EXLOCK)`, one write, close: the
        /// file's `flock` held from before the truncation to the close.
        Locked,
        /// `open(O_WRONLY | O_TRUNC)`, one write, close: the shell's `>`.
        Plain,
    }

    impl Writer {
        fn write(self, path: &Path, text: &[u8]) {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let lock = if self == Writer::Locked { libc::O_EXLOCK } else { 0 };
            let mut f = std::fs::OpenOptions::new().write(true).truncate(true).custom_flags(lock).open(path).unwrap();
            f.write_all(text).unwrap();
        }
    }

    /// `ROUNDS` times: a value that is written back (not canonical), then,
    /// 0 to 60 us later, the other state's. The second write is the last:
    /// the state must become it and the file must read its canonical text.
    /// Returns the rounds in which it was lost (the file read the first
    /// write's state for 2 s; at most 5 are waited for).
    fn lost_writes(version: Version, writer: Writer, forms: [&'static [u8]; 2]) -> Vec<(usize, String)> {
        use std::sync::atomic::Ordering::SeqCst;
        use std::sync::atomic::{AtomicBool, AtomicU8};
        const ROUNDS: usize = 3000;
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let files = Files::create(tmp.as_path(), version, State::Thawed, uid()).unwrap();
        let path = tmp.as_path().join(version.control());
        let (state, stop) = (AtomicU8::new(0), AtomicBool::new(false));
        let canon = [version.canonical(State::Thawed), version.canonical(State::Frozen)];
        let mut lost = Vec::new();
        let mut ran = 0;
        std::thread::scope(|scope| {
            scope.spawn(|| serve(&files, &state, &stop));
            for round in 0..ROUNDS {
                ran += 1;
                let (first, last) = (round % 2, (round + 1) % 2);
                writer.write(&path, forms[first]);
                let gap = Duration::from_micros(u64::try_from(round % 61).unwrap());
                let t0 = Instant::now();
                while t0.elapsed() < gap {
                    std::hint::spin_loop();
                }
                writer.write(&path, forms[last]);
                let t0 = Instant::now();
                while usize::from(state.load(SeqCst)) != last || std::fs::read(&path).unwrap() != canon[last] {
                    if t0.elapsed() > Duration::from_secs(2) {
                        lost.push((round, content(&path)));
                        break;
                    }
                    std::thread::yield_now();
                }
                if lost.len() == 5 {
                    break;
                }
            }
            stop.store(true, SeqCst);
        });
        println!("{version:?} {writer:?}: lost {} (rounds {lost:?}) of {ran}", lost.len());
        lost
    }

    // No write of a writer that holds the file's lock is lost. One that
    // takes no lock can lose a write that lands whole between two system
    // calls of the supervisor (the module's text): its count is printed, not
    // held to zero.
    #[test]
    fn test_no_write_is_lost() {
        for (version, forms) in [(Version::V1, [b"THAWED".as_slice(), b"FROZEN".as_slice()]), (Version::V2, [b"0".as_slice(), b"1".as_slice()])] {
            let plain = lost_writes(version, Writer::Plain, forms);
            let locked = lost_writes(version, Writer::Locked, forms);
            assert!(locked.is_empty(), "{version:?}: writes lost under the lock: {locked:?} (without it: {plain:?})");
        }
    }

    /// An OS for the jail's logic: a process table, and the calls made.
    #[derive(Default)]
    struct FakeOs {
        procs: HashMap<libc::pid_t, ((u64, u64), libc::pid_t)>,
        calls: Vec<String>,
        fail: HashMap<(&'static str, libc::pid_t), i32>,
    }

    impl FakeOs {
        fn spawn(&mut self, pid: libc::pid_t, parent: libc::pid_t) {
            self.procs.insert(pid, ((u64::try_from(pid).unwrap(), 0), parent));
        }

        fn result(&mut self, what: &'static str, pid: libc::pid_t) -> io::Result<()> {
            self.calls.push(format!("{what} {pid}"));
            match self.fail.get(&(what, pid)) {
                Some(&e) => Err(io::Error::from_raw_os_error(e)),
                None => Ok(()),
            }
        }
    }

    impl Os for FakeOs {
        fn start_time(&self, pid: libc::pid_t) -> Option<(u64, u64)> {
            self.procs.get(&pid).map(|p| p.0)
        }

        fn children(&self, pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
            let mut kids: Vec<_> = self.procs.iter().filter(|(_, p)| p.1 == pid).map(|(&k, _)| k).collect();
            kids.sort_unstable();
            Ok(kids)
        }

        fn suspend(&mut self, pid: libc::pid_t) -> io::Result<()> {
            self.result("suspend", pid)
        }

        fn resume(&mut self, pid: libc::pid_t) -> io::Result<()> {
            self.result("resume", pid)
        }

        fn kill(&mut self, pid: libc::pid_t) {
            self.calls.push(format!("kill {pid}"));
        }
    }

    fn calls(os: &mut FakeOs) -> String {
        std::mem::take(&mut os.calls).join(", ")
    }

    // Every process is suspended once, before its children are listed;
    // writes of the current state change nothing; a process found later
    // while frozen is frozen too; thawing resumes each once; a pid that is
    // another process now is never touched.
    #[test]
    fn test_jail_logic() {
        let mut os = FakeOs::default();
        os.spawn(100, 1);
        os.spawn(101, 100);
        os.spawn(102, 101);
        let mut jail = Jail::new(100, (100, 0));
        assert_eq!(jail.discover(&mut os).unwrap(), [101, 102]);
        assert_eq!(calls(&mut os), "");
        jail.freeze(&mut os).unwrap();
        assert_eq!(calls(&mut os), "suspend 100, suspend 101, suspend 102");
        jail.freeze(&mut os).unwrap();
        assert_eq!(calls(&mut os), "");
        // A fork caught while frozen.
        os.spawn(103, 100);
        assert_eq!(jail.discover(&mut os).unwrap(), [103]);
        assert_eq!(calls(&mut os), "suspend 103");
        jail.thaw(&mut os).unwrap();
        assert_eq!(calls(&mut os), "resume 100, resume 101, resume 102, resume 103");
        jail.thaw(&mut os).unwrap();
        assert_eq!(calls(&mut os), "");
        // 102 ended and its pid is another process's now.
        os.procs.insert(102, ((9, 9), 1));
        jail.freeze(&mut os).unwrap();
        assert_eq!(calls(&mut os), "suspend 100, suspend 101, suspend 103");
        assert_eq!(jail.pids(), [100, 101, 103]);
        // Ended in between: dropped.
        jail.exited(101);
        os.procs.remove(&101);
        jail.thaw(&mut os).unwrap();
        assert_eq!(calls(&mut os), "resume 100, resume 103");
        // EPERM (as root: already suspended) and ESRCH are no failure;
        // another error is.
        os.fail.insert(("suspend", 100), libc::EPERM);
        os.fail.insert(("suspend", 103), libc::ESRCH);
        jail.freeze(&mut os).unwrap();
        assert_eq!(jail.pids(), [100]);
        jail.thaw(&mut os).unwrap();
        os.calls.clear();
        os.fail.insert(("suspend", 100), libc::EINVAL);
        let err = jail.freeze(&mut os).unwrap_err();
        assert!(err.to_string().contains("pid_suspend of process 100 failed"), "{err}");
        os.fail.clear();
        // Killed: each is killed, then resumed (a suspended one ends either way).
        os.calls.clear();
        jail.kill_all(&mut os);
        assert_eq!(calls(&mut os), "kill 100, resume 100");
        assert!(jail.is_empty());
        // More processes than a jail can have: a failure.
        let mut os = FakeOs::default();
        os.spawn(1000, 1);
        for i in 0..MAX_MEMBERS {
            os.spawn(1001 + i32::try_from(i).unwrap(), 1000);
        }
        let mut jail = Jail::new(1000, (1000, 0));
        assert!(matches!(jail.discover(&mut os), Err(Failure::TooMany)));
    }

    /// The real start times and children, with the suspend calls recorded
    /// (they need root) and kills made.
    struct Recorded(Vec<String>);

    impl Os for Recorded {
        fn start_time(&self, pid: libc::pid_t) -> Option<(u64, u64)> {
            start_time(pid)
        }

        fn children(&self, pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
            RealOs.children(pid)
        }

        fn suspend(&mut self, pid: libc::pid_t) -> io::Result<()> {
            self.0.push(format!("suspend {pid}"));
            Ok(())
        }

        fn resume(&mut self, pid: libc::pid_t) -> io::Result<()> {
            self.0.push(format!("resume {pid}"));
            Ok(())
        }

        fn kill(&mut self, pid: libc::pid_t) {
            RealOs.kill(pid);
        }
    }

    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let t0 = Instant::now();
        while !cond() {
            assert!(t0.elapsed() < Duration::from_secs(10), "timed out: {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn reap(pid: libc::pid_t) {
        let mut status = 0;
        // SAFETY: our child; an out-pointer.
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }

    // The supervisor's whole protocol on real processes, its suspend calls
    // recorded: frozen before the exec it holds the jailer back; thawed it
    // says go; a freeze is applied once the exec is seen, a fork caught while
    // frozen is frozen too; cgroup.events follows; Firecracker's exit thaws
    // what is left, and the supervisor ends once the jail is empty.
    #[test]
    fn test_supervisor_protocol() {
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let dir = tmp.as_path().to_owned();
        let files = Files::create(&dir, Version::V2, State::Thawed, uid()).unwrap();
        std::fs::write(dir.join("cgroup.freeze"), "1\n").unwrap();
        // The jailer's stand-in: waits for a byte, then execs a shell that
        // forks once after a while.
        let mut release = [-1; 2];
        // SAFETY: an array of two descriptors.
        assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
        let sh = c"/bin/sh";
        let argv = [sh.as_ptr(), c"-c".as_ptr(), c"/bin/sleep 30 & wait".as_ptr(), std::ptr::null()];
        // SAFETY: the child only reads and execs (async-signal-safe).
        let root = unsafe { libc::fork() };
        if root == 0 {
            let mut b = 0u8;
            // SAFETY: async-signal-safe calls in the child of a fork.
            unsafe {
                // The test's end (a panic too) closes the pipe: no orphan.
                libc::close(release[1]);
                if libc::read(release[0], (&raw mut b).cast(), 1) != 1 {
                    libc::_exit(1);
                }
                libc::execv(sh.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
        }
        // SAFETY: our descriptor.
        unsafe { libc::close(release[0]) };
        let start = start_time(root).unwrap();
        let mut go = [-1; 2];
        // SAFETY: an array of two descriptors.
        assert_eq!(unsafe { libc::pipe(go.as_mut_ptr()) }, 0);
        // SAFETY: descriptors we own from here on.
        let (go_rd, go_wr) = unsafe { (OwnedFd::from_raw_fd(go[0]), OwnedFd::from_raw_fd(go[1])) };
        let sup = std::thread::spawn(move || {
            let mut os = Recorded(Vec::new());
            let mut log = |_: &str| {};
            let end = {
                let mut sup = Supervisor::new(files, root, start, &mut os, &mut log).unwrap().unwrap();
                sup.go = Some(go_wr);
                sup.run()
            };
            (end, os.0)
        });
        let events = || content(&dir.join("cgroup.events"));
        let word = |timeout_ms: i32| {
            let mut pfd = libc::pollfd { fd: go_rd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: one pollfd.
            let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if n == 0 {
                return None;
            }
            let mut b = 0u8;
            // SAFETY: a one-byte buffer.
            unsafe { libc::read(go_rd.as_raw_fd(), (&raw mut b).cast(), 1) };
            Some(b)
        };
        // Frozen before the exec: held back, and reported frozen.
        wait_until("frozen 1 while held", || events() == "populated 1\nfrozen 1\n");
        assert_eq!(word(300), None);
        std::fs::write(dir.join("cgroup.freeze"), "0\n").unwrap();
        assert_eq!(word(5000), Some(b'g'));
        assert_eq!(events(), "populated 1\nfrozen 0\n");
        // Frozen between the word and the exec: applied at the exec.
        std::fs::write(dir.join("cgroup.freeze"), "1\n").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(events(), "populated 1\nfrozen 0\n");
        // SAFETY: our descriptor and a one-byte buffer.
        unsafe {
            libc::write(release[1], b"x".as_ptr().cast(), 1);
            libc::close(release[1]);
        }
        wait_until("frozen 1 after the exec", || events() == "populated 1\nfrozen 1\n");
        // The shell's fork, caught while frozen (in the walk or on its fork
        // event); then thaw.
        wait_until("the shell's child", || RealOs.children(root).is_ok_and(|k| !k.is_empty()));
        let kid = RealOs.children(root).unwrap()[0];
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(dir.join("cgroup.freeze"), "0\n").unwrap();
        wait_until("frozen 0", || events() == "populated 1\nfrozen 0\n");
        // Frozen again, then Firecracker ends: the rest is thawed, then ends.
        std::fs::write(dir.join("cgroup.freeze"), "1\n").unwrap();
        wait_until("frozen 1 again", || events() == "populated 1\nfrozen 1\n");
        // SAFETY: our child.
        unsafe { libc::kill(root, libc::SIGKILL) };
        reap(root);
        std::thread::sleep(Duration::from_millis(200));
        assert!(start_time(kid).is_some(), "the shell's child ended with it");
        // SAFETY: a process of this test.
        unsafe { libc::kill(kid, libc::SIGKILL) };
        let (end, calls) = sup.join().unwrap();
        assert_eq!(end, End::Empty);
        assert_eq!(events(), "populated 0\nfrozen 1\n");
        let want = [
            format!("suspend {root}"),
            format!("suspend {kid}"),
            format!("resume {root}"),
            format!("resume {kid}"),
            format!("suspend {root}"),
            format!("suspend {kid}"),
            format!("resume {kid}"),
        ];
        assert_eq!(calls, want);
    }

    // The supervisor kills the jail rather than leave a request undone.
    #[test]
    fn test_supervisor_fails_closed() {
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let dir = tmp.as_path().to_owned();
        let files = Files::create(&dir, Version::V1, State::Thawed, uid()).unwrap();
        let mut child = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let root = libc::pid_t::try_from(child.id()).unwrap();
        let start = start_time(root).unwrap();
        struct Failing;
        impl Os for Failing {
            fn start_time(&self, pid: libc::pid_t) -> Option<(u64, u64)> {
                start_time(pid)
            }
            fn children(&self, pid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
                RealOs.children(pid)
            }
            fn suspend(&mut self, _: libc::pid_t) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::EINVAL))
            }
            fn resume(&mut self, _: libc::pid_t) -> io::Result<()> {
                Ok(())
            }
            fn kill(&mut self, pid: libc::pid_t) {
                RealOs.kill(pid);
            }
        }
        let mut os = Failing;
        let mut lines = Vec::new();
        let mut log = |l: &str| lines.push(l.to_owned());
        let mut sup = Supervisor::new(files, root, start, &mut os, &mut log).unwrap().unwrap();
        // Past the exec already (the stand-in does not exec).
        sup.phase = Phase::Running;
        std::fs::write(dir.join("freezer.state"), "FROZEN\n").unwrap();
        assert_eq!(sup.run(), End::Killed);
        drop(sup);
        assert!(child.wait().unwrap().code().is_none(), "killed by a signal");
        assert!(lines.iter().any(|l| l.contains("pid_suspend of process") && l.contains("the jail is killed")), "{lines:?}");
    }

    // posix_spawn with POSIX_SPAWN_SETEXEC, as the jailer execs Firecracker,
    // reports NOTE_EXEC on the process (the supervisor's cue that
    // Firecracker runs).
    #[test]
    fn test_setexec_reports_note_exec() {
        let tmp = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let files = Files::create(tmp.as_path(), Version::V1, State::Thawed, uid()).unwrap();
        let watch = Watch::new(&files).unwrap();
        let mut release = [-1; 2];
        // SAFETY: an array of two descriptors.
        assert_eq!(unsafe { libc::pipe(release.as_mut_ptr()) }, 0);
        let path = c"/usr/bin/true";
        let argv = [path.as_ptr().cast_mut(), std::ptr::null_mut()];
        let envp = [std::ptr::null_mut::<libc::c_char>()];
        let mut attr = std::mem::MaybeUninit::<libc::posix_spawnattr_t>::uninit();
        // SAFETY: initialises the attributes (before the fork: it allocates).
        unsafe {
            libc::posix_spawnattr_init(attr.as_mut_ptr());
            libc::posix_spawnattr_setflags(attr.as_mut_ptr(), libc::c_short::try_from(libc::POSIX_SPAWN_SETEXEC).unwrap());
        }
        // SAFETY: the child reads, then replaces itself.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: the child of a fork; posix_spawn with SETEXEC replaces it.
            unsafe {
                let mut b = 0u8;
                libc::close(release[1]);
                if libc::read(release[0], (&raw mut b).cast(), 1) != 1 {
                    libc::_exit(1);
                }
                libc::posix_spawn(std::ptr::null_mut(), path.as_ptr(), std::ptr::null(), attr.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        assert!(watch.watch_proc(pid).unwrap());
        // SAFETY: our descriptor.
        unsafe { libc::write(release[1], b"x".as_ptr().cast(), 1) };
        let mut flags = 0;
        let mut events = Vec::new();
        let t0 = Instant::now();
        while flags & libc::NOTE_EXIT == 0 && t0.elapsed() < Duration::from_secs(5) {
            watch.wait(Some(1000), &mut events).unwrap();
            for e in &events {
                if let Event::Proc(p, f) = *e {
                    assert_eq!(p, pid);
                    flags |= f;
                }
            }
        }
        reap(pid);
        assert_eq!(flags & (libc::NOTE_EXEC | libc::NOTE_EXIT), libc::NOTE_EXEC | libc::NOTE_EXIT, "{flags:#x}");
    }

    // The real calls: as a user pid_suspend is refused (EPERM), even for
    // one's own child, and the self-check says the freezer cannot work; as
    // root (CI runs these tests with sudo) a spinning child stops using CPU
    // time while suspended and uses it again once resumed, and the
    // self-check passes.
    // Spinners keeping every CPU busy, so that threads are preempted (the
    // case that made the check fail before it waited for the parked state).
    struct Load(Vec<std::process::Child>);

    impl Drop for Load {
        fn drop(&mut self) {
            for c in &mut self.0 {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    fn load() -> Load {
        let cpus = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        Load(
            (0..cpus * 2)
                // Each ends with the test process, even one that aborts.
                .map(|_| {
                    std::process::Command::new("/bin/sh")
                        .args(["-c", "while kill -0 $PPID 2>/dev/null; do :; done"])
                        .spawn()
                        .unwrap()
                })
                .collect(),
        )
    }

    // The parked state, as a user (SIGSTOP holds a task the same way:
    // kern_sig.c, SIGSTOP -> task_suspend_internal -> place_task_hold): once
    // no thread runs, the CPU time stands still, every time, under load.
    #[test]
    fn test_parked_cpu_time_stands_still() {
        let busy = load();
        for i in 0..40 {
            // Killed and reaped when dropped, a failed round too.
            let child = Load(vec![std::process::Command::new("/usr/bin/yes").stdout(std::process::Stdio::null()).spawn().unwrap()]);
            let pid = libc::pid_t::try_from(child.0[0].id()).unwrap();
            std::thread::sleep(Duration::from_millis(5));
            // SAFETY: our child.
            unsafe { libc::kill(pid, libc::SIGSTOP) };
            let a = parked_cpu_time(pid).unwrap();
            assert_eq!(no_thread_runs(pid), Some(true));
            std::thread::sleep(Duration::from_millis(30));
            assert_eq!(cpu_time(pid).unwrap(), a, "round {i}: CPU time once parked");
            drop(child);
        }
        drop(busy);
    }

    // The self-check in a loop, under load: before it waited for the parked
    // state, about one start in six failed it on CI's runner (5 of 30 starts,
    // run 50435b5, macOS 26.7.2: "pid_suspend returned 0, but the child used
    // CPU time", 72 to 147 Mach time units more). As root only (pid_suspend);
    // also counts how often the time read right after pid_suspend returned
    // differs from the parked one (the old check), which is not asserted.
    #[test]
    fn test_self_check_under_load() {
        // SAFETY: no arguments.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let busy = load();
        let mut os = RealOs;
        let mut early = 0;
        for i in 0..200 {
            self_check(&mut os).unwrap_or_else(|e| panic!("round {i}: {e}"));
            // Killed and reaped when dropped, a failed round too.
            let child = Load(vec![std::process::Command::new("/usr/bin/yes").stdout(std::process::Stdio::null()).spawn().unwrap()]);
            let pid = libc::pid_t::try_from(child.0[0].id()).unwrap();
            std::thread::sleep(Duration::from_millis(5));
            os.suspend(pid).unwrap();
            let right_after = cpu_time(pid).unwrap();
            let parked = parked_cpu_time(pid).unwrap();
            early += usize::from(right_after != parked);
            std::thread::sleep(Duration::from_millis(30));
            assert_eq!(cpu_time(pid).unwrap(), parked, "round {i}: CPU time once parked");
            os.resume(pid).unwrap();
            drop(child);
        }
        eprintln!("test_self_check_under_load: 200 self-checks passed; the time right after pid_suspend \
                   differed from the parked one {early} times in 200");
        drop(busy);
    }

    #[test]
    fn test_pid_suspend_binding() {
        let mut child = std::process::Command::new("/usr/bin/yes").stdout(std::process::Stdio::null()).spawn().unwrap();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let mut os = RealOs;
        // SAFETY: no arguments.
        if unsafe { libc::geteuid() } != 0 {
            let err = os.suspend(pid).unwrap_err();
            assert_eq!(errno(&err), libc::EPERM, "{err}");
            assert_eq!(errno(&os.resume(pid).unwrap_err()), libc::EPERM);
            let err = self_check(&mut os).unwrap_err();
            assert!(err.contains("the freezer cannot work on this host: pid_suspend of a child"), "{err}");
        } else {
            std::thread::sleep(Duration::from_millis(100));
            os.suspend(pid).unwrap();
            let a = parked_cpu_time(pid).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            let b = cpu_time(pid).unwrap();
            assert_eq!(a, b, "CPU time while suspended and parked");
            // Not nested: a second suspend is refused, one resume resumes.
            assert_eq!(errno(&os.suspend(pid).unwrap_err()), libc::EPERM);
            os.resume(pid).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            assert!(cpu_time(pid).unwrap() > b, "no CPU time once resumed");
            assert_eq!(errno(&os.resume(pid).unwrap_err()), libc::EPERM);
            // SIGKILL ends a suspended process.
            os.suspend(pid).unwrap();
            child.kill().unwrap();
            let t0 = Instant::now();
            while child.try_wait().unwrap().is_none() {
                assert!(t0.elapsed() < Duration::from_secs(5), "a suspended process outlived SIGKILL");
                std::thread::sleep(Duration::from_millis(10));
            }
            self_check(&mut os).unwrap();
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}
