// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `userfaultfd` on Windows, with the API and semantics of the Linux crate;
//! the macOS module ([`macos.rs`]) with Windows means.
//!
//! The kernel side (fault capture, waiting threads, filling pages) is
//! `libc::wick_uffd`. A [`Uffd`] made by [`UffdBuilder::create`] owns a
//! userfaultfd of this process and calls it directly. A [`Uffd`] made with
//! `from_raw_fd` (typically in a page fault handler process that received the
//! descriptor over a Unix socket) reads events from the descriptor and sends
//! its requests over a private channel: one end of a socket pair it
//! duplicates into the userfaultfd's process (`WSADuplicateSocketW`, for the
//! peer of the descriptor, `SIO_AF_UNIX_GETPEERPID`) and announces with a
//! `HELLO` record.

use std::fmt;
use std::io;
use std::mem;
use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use bitflags::bitflags;
use libc::wick_uffd::{self, proto};
use wick_os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};
use windows_sys::Win32::Networking::WinSock::{WSADuplicateSocketW, WSAGetLastError, WSAPROTOCOL_INFOW};

/// An errno value, as the Linux crate's `nix::errno::Errno` (Windows codes
/// with the Linux names, as the compatibility `libc` defines them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Errno(i32);

impl Errno {
    /// Invalid argument.
    pub const EINVAL: Errno = Errno(libc::EINVAL);
    /// Try again.
    pub const EAGAIN: Errno = Errno(libc::EAGAIN);
    /// Interrupted.
    pub const EINTR: Errno = Errno(libc::EINTR);
    /// Broken pipe.
    pub const EPIPE: Errno = Errno(libc::EPIPE);
    /// Already exists (a page that is present).
    pub const EEXIST: Errno = Errno(libc::EEXIST);
    /// Not found (not a registered range).
    pub const ENOENT: Errno = Errno(libc::ENOENT);
    /// Busy (pages another userfaultfd has registered).
    pub const EBUSY: Errno = Errno(libc::EBUSY);
    /// A record the kernel side never writes (a waiter-mirror tag whose slot
    /// is past the table), as the macOS twin's `Errno::EBADMSG`.
    pub const EBADMSG: Errno = Errno(libc::EBADMSG);
    /// A reply that is no mirror: another size, or no handle.
    pub const EPROTO: Errno = Errno(libc::EPROTO);

    /// The value of the last error of this thread.
    pub fn last() -> Errno {
        Errno(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// The errno with this value.
    pub fn from_i32(e: i32) -> Errno {
        Errno(e)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", io::Error::from_raw_os_error(self.0))
    }
}

impl std::error::Error for Errno {}

impl From<Errno> for io::Error {
    fn from(e: Errno) -> io::Error {
        io::Error::from_raw_os_error(e.0)
    }
}

/// Errors from this crate (the same as the Linux crate's).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Copy failed.
    #[error("Copy failed")]
    CopyFailed(Errno),
    /// Copy partially succeeded.
    #[error("Copy partially succeeded")]
    PartiallyCopied(usize),
    /// A short event record.
    #[error("Incomplete uffd_msg; read only {read}/{expected} bytes")]
    IncompleteMsg {
        /// Bytes read.
        read: usize,
        /// Bytes expected.
        expected: usize,
    },
    /// A system call failed.
    #[error("System error")]
    SystemError(#[source] Errno),
    /// The descriptor was closed.
    #[error("EOF when reading file descriptor")]
    ReadEof,
    /// An event of unknown type.
    #[error("Unrecognized event in uffd_msg: {0}")]
    UnrecognizedEvent(u8),
    /// Requested ioctls are not supported.
    #[error("Requested ioctls unsupported; supported: {0:?}")]
    UnsupportedIoctls(IoctlFlags),
    /// Zeropage failed.
    #[error("Zeropage failed: {0}")]
    ZeropageFailed(Errno),
    /// The userfaultfd could not be opened.
    #[error("Error accessing /dev/userfaultfd: {0}")]
    OpenDevUserfaultfd(io::Error),
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Error {
        Error::SystemError(e)
    }
}

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

type SysResult<T> = std::result::Result<T, Errno>;

fn errno(e: i32) -> Errno {
    Errno::from_i32(e)
}

bitflags! {
    /// Optional userfaultfd features (Linux values). Supported here:
    /// `EVENT_REMOVE`; requesting others fails as on a kernel without them.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct FeatureFlags: u64 {
        /// Write-protect faults.
        const PAGEFAULT_FLAG_WP = 1 << 0;
        /// fork events.
        const EVENT_FORK = 1 << 1;
        /// mremap events.
        const EVENT_REMAP = 1 << 2;
        /// madvise(MADV_DONTNEED/MADV_REMOVE) events.
        const EVENT_REMOVE = 1 << 3;
        /// Missing faults on hugetlbfs.
        const MISSING_HUGETLBFS = 1 << 4;
        /// Missing faults on shared memory.
        const MISSING_SHMEM = 1 << 5;
        /// munmap events.
        const EVENT_UNMAP = 1 << 6;
    }
}

const SUPPORTED_FEATURES: FeatureFlags = FeatureFlags::EVENT_REMOVE;

bitflags! {
    /// The ioctls available on a userfaultfd or a registered range (Linux bits).
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct IoctlFlags: u64 {
        /// UFFDIO_REGISTER.
        const REGISTER = 1 << 0x00;
        /// UFFDIO_UNREGISTER.
        const UNREGISTER = 1 << 0x01;
        /// UFFDIO_WAKE.
        const WAKE = 1 << 0x02;
        /// UFFDIO_COPY.
        const COPY = 1 << 0x03;
        /// UFFDIO_ZEROPAGE.
        const ZEROPAGE = 1 << 0x04;
        /// UFFDIO_API.
        const API = 1 << 0x3f;
        /// Unknown bits are kept.
        const _ = !0;
    }
}

const API_IOCTLS: IoctlFlags = IoctlFlags::REGISTER
    .union(IoctlFlags::UNREGISTER)
    .union(IoctlFlags::API);
const RANGE_IOCTLS: IoctlFlags = IoctlFlags::WAKE
    .union(IoctlFlags::COPY)
    .union(IoctlFlags::ZEROPAGE);

bitflags! {
    /// How a range is registered.
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct RegisterMode: u64 {
        /// Missing page faults.
        const MISSING = 1 << 0;
    }
}

/// Whether a page fault was a read or a write.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReadWrite {
    /// A read.
    Read,
    /// A write.
    Write,
}

/// The kind of a page fault.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FaultKind {
    /// A read or write of a missing page.
    Missing,
}

/// An event read with [`Uffd::read_event`].
#[derive(Debug)]
pub enum Event {
    /// A page fault.
    Pagefault {
        /// The kind of fault.
        kind: FaultKind,
        /// Read or write.
        rw: ReadWrite,
        /// The faulting address.
        addr: *mut c_void,
    },
    /// Not generated on this host (no `EVENT_FORK`).
    Fork {
        /// The child's userfaultfd.
        uffd: Uffd,
    },
    /// Not generated on this host (no `EVENT_REMAP`).
    Remap {
        /// Original start.
        from: *mut c_void,
        /// New start.
        to: *mut c_void,
        /// Length.
        len: usize,
    },
    /// Pages of a registered range were released (`madvise(MADV_DONTNEED)`).
    Remove {
        /// Start of the range.
        start: *mut c_void,
        /// End of the range.
        end: *mut c_void,
    },
    /// Not generated on this host (no `EVENT_UNMAP`).
    Unmap {
        /// Start of the range.
        start: *mut c_void,
        /// End of the range.
        end: *mut c_void,
    },
}

impl Event {
    fn from_record(w: [u64; 4]) -> Result<Event> {
        match w[0] {
            // The mirror era's page fault (`[EVENT_PAGEFAULT2, addr, flags,
            // tag]`): a reader from before the mirror knew only
            // `EVENT_PAGEFAULT` (1) and fails on this type loudly, and this
            // reader fails on that older type the same way (version skew is an
            // error, never a silent misread): the loud-fail test below.
            proto::EVENT_PAGEFAULT2 => Ok(Event::Pagefault {
                kind: FaultKind::Missing,
                rw: if w[2] & proto::FLAG_WRITE != 0 {
                    ReadWrite::Write
                } else {
                    ReadWrite::Read
                },
                addr: w[1] as *mut c_void,
            }),
            proto::EVENT_REMOVE => Ok(Event::Remove {
                start: w[1] as *mut c_void,
                end: w[2] as *mut c_void,
            }),
            #[allow(clippy::cast_possible_truncation)]
            other => Err(Error::UnrecognizedEvent(other as u8)),
        }
    }
}

/// A buffer for [`Uffd::read_events`].
#[derive(Debug)]
pub struct EventBuffer(Vec<[u8; proto::RECORD]>);

impl EventBuffer {
    /// A buffer for up to `size` events.
    pub fn new(size: usize) -> Self {
        Self(vec![[0; proto::RECORD]; size])
    }
}

/// A userfaultfd.
#[derive(Debug)]
pub struct Uffd {
    fd: RawFd,
    /// The userfaultfd of this process this object made, if it made one.
    owner: Option<usize>,
    /// The request channel of an object made with `from_raw_fd`.
    channel: OnceLock<Mutex<Channel>>,
    /// The waiter mirror as this object reads it, set up at the first read.
    mirror: OnceLock<Mirror>,
}

/// The waiter mirror as this object reads it (the macOS twin's `Mirror`): the
/// read-only words a reader checks a page fault record's waiter against.
#[derive(Debug)]
struct Mirror {
    words: *const AtomicU64,
    /// The read-only view this object mapped (`OP_MIRROR`), to unmap on drop;
    /// null for the mapping of this process's own userfaultfd (`wick_uffd`
    /// owns and frees that one).
    view: *const AtomicU64,
}

// SAFETY: read-only shared memory, read with atomic loads only.
unsafe impl Send for Mirror {}
// SAFETY: as above.
unsafe impl Sync for Mirror {}

impl Mirror {
    /// Whether a page fault record's waiter still waits: its tag is the slot's
    /// word, waiting, at one load of it. A slot past the table is a record the
    /// kernel side never writes: an error, never a read past the table.
    fn waits(&self, tag: u64) -> Result<bool> {
        let slot = proto::tag_slot(tag);
        if slot >= proto::MIRROR_WORDS {
            return Err(Error::SystemError(Errno::EBADMSG));
        }
        // SAFETY: `slot` is within the mapping's `MIRROR_WORDS` words.
        let word = unsafe { &*self.words.add(slot) }.load(Ordering::Acquire);
        Ok(tag & proto::TAG_WAITING != 0 && word == tag)
    }

    fn unmap(&self) {
        if !self.view.is_null() {
            // SAFETY: the read-only view this object mapped (`OP_MIRROR`).
            unsafe { wick_uffd::unmap_mirror(self.view) };
        }
    }
}

/// A request channel to the serving thread.
#[derive(Debug)]
struct Channel {
    /// Our end.
    fd: RawFd,
    /// The end duplicated for the serving thread, until it has answered a
    /// request: a socket duplicated with `WSADuplicateSocketW` must stay open
    /// until the target process has made its own from the information.
    sent: Option<RawFd>,
}

impl Channel {
    fn close(&mut self) {
        // SAFETY: descriptors this channel owns.
        unsafe {
            libc::close(self.fd);
            if let Some(fd) = self.sent.take() {
                libc::close(fd);
            }
        }
    }
}

impl Drop for Uffd {
    fn drop(&mut self) {
        // SAFETY: the descriptor this object owns.
        unsafe { libc::close(self.fd) };
        if let Some(channel) = self.channel.get() {
            channel.lock().unwrap().close();
        }
        if let Some(mirror) = self.mirror.get() {
            mirror.unmap();
        }
    }
}

impl AsFd for Uffd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the descriptor lives as long as `self`.
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl AsRawFd for Uffd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for Uffd {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        if let Some(channel) = self.channel.get() {
            channel.lock().unwrap().close();
        }
        if let Some(mirror) = self.mirror.get() {
            mirror.unmap();
        }
        mem::forget(self);
        fd
    }
}

impl FromRawFd for Uffd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Uffd {
            fd,
            owner: None,
            channel: OnceLock::new(),
            mirror: OnceLock::new(),
        }
    }
}

fn record(words: [u64; 4]) -> [u8; proto::RECORD] {
    let mut b = [0u8; proto::RECORD];
    for (i, w) in words.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    b
}

fn words(b: &[u8; proto::RECORD]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for (i, v) in w.iter_mut().enumerate() {
        *v = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

fn write_all(fd: RawFd, mut buf: &[u8]) -> SysResult<()> {
    while !buf.is_empty() {
        // SAFETY: writes from a valid buffer.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = Errno::last();
            if e == Errno::EINTR {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n.unsigned_abs()..];
    }
    Ok(())
}

fn read_all(fd: RawFd, buf: &mut [u8]) -> SysResult<()> {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: reads into a valid buffer.
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
        if n < 0 {
            let e = Errno::last();
            if e == Errno::EINTR {
                continue;
            }
            // A non-blocking descriptor in the middle of a record: wait.
            if e == Errno::EAGAIN {
                std::thread::yield_now();
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(Errno::EPIPE);
        }
        done += n.unsigned_abs();
    }
    Ok(())
}

/// A reply: `Ok(count)` or `Err((errno, count))`.
type Reply = std::result::Result<u64, (i32, u64)>;

impl Uffd {
    /// The request channel, set up on first use: a socket pair whose other
    /// end is duplicated into the userfaultfd's process and announced with
    /// `HELLO`.
    fn channel(&self) -> SysResult<&Mutex<Channel>> {
        if let Some(c) = self.channel.get() {
            return Ok(c);
        }
        let (mine, theirs) = wick_os::unix::net::UnixStream::pair()
            .map_err(|e| errno(e.raw_os_error().unwrap_or(libc::EIO)))?;
        let mut channel = Channel {
            fd: mine.into_raw_fd(),
            sent: Some(theirs.into_raw_fd()),
        };
        let pid = match wick_os::windows::peer_pid(self.fd) {
            Ok(pid) => pid,
            Err(e) => {
                channel.close();
                return Err(errno(e.raw_os_error().unwrap_or(libc::EIO)));
            }
        };
        // SAFETY: plain data, filled by the call.
        let mut info: WSAPROTOCOL_INFOW = unsafe { mem::zeroed() };
        #[allow(clippy::cast_sign_loss)]
        let theirs = channel.sent.unwrap() as u32 as usize;
        // SAFETY: a socket we own and an output structure.
        if unsafe { WSADuplicateSocketW(theirs, pid, &mut info) } != 0 {
            // SAFETY: plain call.
            let e = unsafe { WSAGetLastError() };
            channel.close();
            return Err(errno(e));
        }
        // SAFETY: the structure's bytes.
        let raw = unsafe {
            std::slice::from_raw_parts((&raw const info).cast::<u8>(), mem::size_of::<WSAPROTOCOL_INFOW>())
        };
        let mut hello = record([proto::HELLO, 0, 0, 0]).to_vec();
        hello.extend_from_slice(raw);
        if let Err(e) = write_all(self.fd, &hello) {
            channel.close();
            return Err(e);
        }
        if let Err(other) = self.channel.set(Mutex::new(channel)) {
            // Another thread set one up first.
            other.into_inner().unwrap().close();
        }
        Ok(self.channel.get().unwrap())
    }

    /// Sends a request (with `payload`) and returns the reply.
    fn request(&self, head: [u64; 4], payload: &[u8]) -> SysResult<Reply> {
        let mut channel = self.channel()?.lock().unwrap();
        write_all(channel.fd, &record(head))?;
        write_all(channel.fd, payload)?;
        let mut reply = [0u8; proto::RECORD];
        read_all(channel.fd, &mut reply)?;
        if let Some(fd) = channel.sent.take() {
            // SAFETY: the serving thread holds its own socket now.
            unsafe { libc::close(fd) };
        }
        let [result, count, _, _] = words(&reply);
        let result = result.cast_signed();
        #[allow(clippy::cast_possible_truncation)]
        Ok(if result < 0 {
            Err(((-result) as i32, count))
        } else {
            Ok(result.cast_unsigned())
        })
    }

    /// A request served here (owner) or by the serving thread.
    fn call(
        &self,
        op: u64,
        a: u64,
        b: u64,
        c: u64,
        local: impl FnOnce(usize) -> Reply,
    ) -> SysResult<Reply> {
        match self.owner {
            Some(ctx) => Ok(local(ctx)),
            None => self.request([op, a, b, c], &[]),
        }
    }

    /// `OP_MIRROR`: the reply words. Word 0 is the mirror's size or `-errno`;
    /// word 1, on success, the section handle [`serve_mirror`](wick_uffd)
    /// duplicated into this process read-only. Where the macOS twin receives a
    /// descriptor over the socket (`SCM_RIGHTS`), the Windows kernel side has
    /// already placed the handle in the reader's table, so the value stands
    /// alone and no control message is read.
    fn request_mirror(&self) -> SysResult<[u64; 4]> {
        let mut channel = self.channel()?.lock().unwrap();
        write_all(channel.fd, &record([proto::OP_MIRROR, 0, 0, 0]))?;
        let mut reply = [0u8; proto::RECORD];
        read_all(channel.fd, &mut reply)?;
        if let Some(fd) = channel.sent.take() {
            // SAFETY: the serving thread holds its own socket now.
            unsafe { libc::close(fd) };
        }
        Ok(words(&reply))
    }

    /// The waiter mirror, set up at the first call: the kernel side's own
    /// mapping for the object that made the userfaultfd, else the section
    /// `OP_MIRROR` answers with, mapped read-only. Every failure is an error
    /// (a kernel side that predates the mirror answers `EINVAL`; a reply of
    /// another size is `EPROTO`), never a read without the check.
    fn mirror(&self) -> Result<&Mirror> {
        if let Some(m) = self.mirror.get() {
            return Ok(m);
        }
        let mirror = match self.owner {
            Some(ctx) => Mirror {
                words: wick_uffd::mirror(ctx)
                    .ok_or(Error::SystemError(Errno::from_i32(libc::EBADF)))?,
                view: ptr::null(),
            },
            None => {
                let [result, handle, _, _] = self.request_mirror()?;
                let result = result.cast_signed();
                #[allow(clippy::cast_possible_truncation)]
                if result < 0 {
                    return Err(Error::SystemError(errno((-result) as i32)));
                }
                // SAFETY: `handle` is the section `serve_mirror` duplicated
                // into this process read-only; `map_mirror_handle` checks its
                // size against the table's and consumes it either way.
                let view =
                    unsafe { wick_uffd::map_mirror_handle(handle, result.cast_unsigned()) }
                        .map_err(|e| {
                            Error::SystemError(errno(e.raw_os_error().unwrap_or(libc::EIO)))
                        })?;
                Mirror { words: view, view }
            }
        };
        if let Err(other) = self.mirror.set(mirror) {
            // Another thread set it up first.
            other.unmap();
        }
        Ok(self.mirror.get().unwrap())
    }

    /// Registers a range for missing page faults; returns the range's ioctls.
    pub fn register(&self, start: *mut c_void, len: usize) -> Result<IoctlFlags> {
        self.register_with_mode(start, len, RegisterMode::MISSING)
    }

    /// Registers a range; only `RegisterMode::MISSING` exists on this host.
    pub fn register_with_mode(
        &self,
        start: *mut c_void,
        len: usize,
        mode: RegisterMode,
    ) -> Result<IoctlFlags> {
        if mode != RegisterMode::MISSING {
            return Err(Error::SystemError(Errno::EINVAL));
        }
        let (start, len) = (start as u64, len as u64);
        let reply = self.call(proto::OP_REGISTER, start, len, 0, |ctx| {
            wick_uffd::register(ctx, start, len)
                .map(|()| 0)
                .map_err(|e| (e.raw_os_error().unwrap_or(libc::EINVAL), 0))
        })?;
        reply.map_err(|(e, _)| Error::SystemError(errno(e)))?;
        Ok(RANGE_IOCTLS)
    }

    /// Unregisters a range: its missing pages become ordinary memory.
    pub fn unregister(&self, start: *mut c_void, len: usize) -> Result<()> {
        let (start, len) = (start as u64, len as u64);
        let reply = self.call(proto::OP_UNREGISTER, start, len, 0, |ctx| {
            wick_uffd::unregister(ctx, start, len)
                .map(|()| 0)
                .map_err(|e| (e, 0))
        })?;
        reply.map_err(|(e, _)| Error::SystemError(errno(e)))?;
        Ok(())
    }

    /// Fills missing pages at `dst` with `len` bytes from `src`; returns the
    /// count copied. If `wake`, wakes the threads waiting for them.
    ///
    /// # Safety
    /// `src` must be readable for `len` bytes.
    pub unsafe fn copy(
        &self,
        src: *const c_void,
        dst: *mut c_void,
        len: usize,
        wake: bool,
    ) -> Result<usize> {
        let mode = if wake { 0 } else { proto::MODE_DONTWAKE };
        let reply = match self.owner {
            // SAFETY: the caller's contract.
            Some(ctx) => unsafe { wick_uffd::copy(ctx, src.cast(), dst as u64, len as u64, wake) },
            None => {
                // SAFETY: the caller's contract.
                let data = unsafe { std::slice::from_raw_parts(src.cast::<u8>(), len) };
                self.request([proto::OP_COPY, dst as u64, len as u64, mode], data)?
            }
        };
        #[allow(clippy::cast_possible_truncation)]
        match reply {
            Ok(n) => Ok(n as usize),
            Err((e, n)) if e == libc::EAGAIN => Err(Error::PartiallyCopied(n as usize)),
            Err((e, _)) => Err(Error::CopyFailed(errno(e))),
        }
    }

    /// Fills missing pages at `start` with zeros; returns the count.
    ///
    /// # Safety
    /// As for the Linux crate: `start` must be a registered range.
    pub unsafe fn zeropage(&self, start: *mut c_void, len: usize, wake: bool) -> Result<usize> {
        let mode = if wake { 0 } else { proto::MODE_DONTWAKE };
        let (start, len) = (start as u64, len as u64);
        let reply = self.call(proto::OP_ZEROPAGE, start, len, mode, |ctx| {
            wick_uffd::zeropage(ctx, start, len, wake)
        })?;
        #[allow(clippy::cast_possible_truncation)]
        match reply {
            Ok(n) => Ok(n as usize),
            Err((e, _)) => Err(Error::ZeropageFailed(errno(e))),
        }
    }

    /// Wakes the threads waiting for pages in the range.
    pub fn wake(&self, start: *mut c_void, len: usize) -> Result<()> {
        let (start, len) = (start as u64, len as u64);
        let reply = self.call(proto::OP_WAKE, start, len, 0, |ctx| {
            wick_uffd::wake_range(ctx, start, len)
                .map(|()| 0)
                .map_err(|e| (e, 0))
        })?;
        reply.map_err(|(e, _)| Error::SystemError(errno(e)))?;
        Ok(())
    }

    /// Reads one event; `None` if the descriptor is non-blocking and there is
    /// none.
    pub fn read_event(&self) -> Result<Option<Event>> {
        let mut buf = EventBuffer::new(1);
        let mut events = self.read_events(&mut buf)?;
        events.next().transpose()
    }

    /// Reads up to `buf`'s size of events. A page fault whose waiter was woken
    /// before this read checked it is dropped (Linux's wake takes the record
    /// off the queue unread, v6.12 fs/userfaultfd.c `userfaultfd_wake_function`
    /// :141); with only such records read, it reads again: a blocking
    /// descriptor waits for an event, a non-blocking one returns none once the
    /// socket is empty.
    pub fn read_events<'a>(
        &self,
        buf: &'a mut EventBuffer,
    ) -> Result<impl Iterator<Item = Result<Event>> + 'a> {
        let mirror = self.mirror()?;
        let bytes = buf.0.len() * proto::RECORD;
        let count = loop {
            // SAFETY: the buffer is `bytes` long.
            let n = unsafe { libc::read(self.fd, buf.0.as_mut_ptr().cast(), bytes) };
            let count = if n < 0 {
                let e = Errno::last();
                if e != Errno::EAGAIN {
                    return Err(Error::SystemError(e));
                }
                break 0;
            } else if n == 0 {
                return Err(Error::ReadEof);
            } else {
                let n = n.unsigned_abs();
                let rest = n % proto::RECORD;
                if rest != 0 {
                    // Records are written whole; finish the last one.
                    let last = n / proto::RECORD;
                    let slice = &mut buf.0[last][rest..];
                    read_all(self.fd, slice).map_err(|_| Error::IncompleteMsg {
                        read: rest,
                        expected: proto::RECORD,
                    })?;
                    last + 1
                } else {
                    n / proto::RECORD
                }
            };
            // Drop the records of woken waiters, compacting the live ones down.
            let mut live = 0;
            for i in 0..count {
                let w = words(&buf.0[i]);
                if w[0] == proto::EVENT_PAGEFAULT2 && !mirror.waits(w[3])? {
                    continue;
                }
                buf.0[live] = buf.0[i];
                live += 1;
            }
            if live > 0 {
                break live;
            }
        };
        Ok(buf
            .0
            .iter()
            .take(count)
            .map(|b| Event::from_record(words(b))))
    }
}

/// Builder for [`Uffd`].
#[derive(Debug, Default)]
pub struct UffdBuilder {
    close_on_exec: bool,
    non_blocking: bool,
    req_features: Option<FeatureFlags>,
    req_ioctls: Option<IoctlFlags>,
}

impl UffdBuilder {
    /// A builder with no options set.
    pub fn new() -> UffdBuilder {
        UffdBuilder::default()
    }

    /// Sets `O_CLOEXEC` on the descriptor (Windows handles are not inherited
    /// unless asked for).
    pub fn close_on_exec(&mut self, close_on_exec: bool) -> &mut Self {
        self.close_on_exec = close_on_exec;
        self
    }

    /// Sets `O_NONBLOCK` on the descriptor.
    pub fn non_blocking(&mut self, non_blocking: bool) -> &mut Self {
        self.non_blocking = non_blocking;
        self
    }

    /// Only user-mode faults: every fault this host reports comes from user
    /// space (the process's own accesses and its guests'), so this changes
    /// nothing.
    pub fn user_mode_only(&mut self, _user_mode_only: bool) -> &mut Self {
        self
    }

    /// Requires optional features.
    pub fn require_features(&mut self, feature: FeatureFlags) -> &mut Self {
        self.req_features = Some(self.req_features.unwrap_or(FeatureFlags::empty()) | feature);
        self
    }

    /// Requires ioctls.
    pub fn require_ioctls(&mut self, ioctls: IoctlFlags) -> &mut Self {
        self.req_ioctls = Some(self.req_ioctls.unwrap_or(IoctlFlags::empty()) | ioctls);
        self
    }

    /// Creates the userfaultfd.
    pub fn create(&self) -> Result<Uffd> {
        let features = self.req_features.unwrap_or(FeatureFlags::empty());
        // As UFFDIO_API on a kernel without a requested feature.
        if !SUPPORTED_FEATURES.contains(features) {
            return Err(Error::SystemError(Errno::EINVAL));
        }
        let (ctx, fd) = wick_uffd::create(features.bits(), self.non_blocking, self.close_on_exec)
            .map_err(|e| Error::SystemError(errno(e.raw_os_error().unwrap_or(libc::EIO))))?;
        let uffd = Uffd {
            fd,
            owner: Some(ctx),
            channel: OnceLock::new(),
            mirror: OnceLock::new(),
        };
        if let Some(ioctls) = self.req_ioctls {
            if !API_IOCTLS.contains(ioctls) {
                return Err(Error::UnsupportedIoctls(API_IOCTLS));
            }
        }
        Ok(uffd)
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;
    use std::thread;

    use super::*;

    const PAGE: usize = 4096;

    fn map(len: usize) -> *mut u8 {
        // SAFETY: a fresh anonymous mapping.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        p.cast()
    }

    /// Records queued on the reader socket, counted without consuming them
    /// (`FIONREAD`), as macOS's `pending` does with its `ioctl`. The crate's
    /// `RawFd` on Windows is the socket value itself (`WSADuplicateSocketW`
    /// above casts it so), so the winsock query takes it directly.
    fn pending(fd: RawFd) -> usize {
        use windows_sys::Win32::Networking::WinSock::{FIONREAD, ioctlsocket};
        let mut n: u32 = 0;
        #[allow(clippy::cast_sign_loss)]
        let sock = fd as u32 as usize;
        // SAFETY: `FIONREAD` writes a `u32`; the socket is ours.
        assert_eq!(unsafe { ioctlsocket(sock, FIONREAD, &mut n) }, 0);
        n as usize / proto::RECORD
    }

    /// Waits until at least `records` events are queued on `fd`, as macOS's
    /// `until_pending`.
    fn until_pending(fd: RawFd, records: usize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while pending(fd) < records {
            assert!(std::time::Instant::now() < deadline, "{} of {records} records after 10 s", pending(fd));
            thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// A thread whose read of `addr` faults and blocks until the page is
    /// served or its waiter woken; returns the byte read, as macOS's
    /// `reader_of`.
    fn reader_of(addr: usize) -> thread::JoinHandle<u8> {
        // SAFETY: registered memory; the read waits for its page.
        thread::spawn(move || unsafe { ptr::read_volatile(addr as *const u8) })
    }

    fn fault_addr(event: Option<Event>) -> usize {
        match event {
            Some(Event::Pagefault { addr, .. }) => addr as usize,
            other => panic!("{other:?}"),
        }
    }

    /// How a test ends the wait of the second of two unread faults
    /// (`Ioctl`: `UFFDIO_WAKE`).
    #[derive(Clone, Copy, Debug)]
    enum Wake {
        Unregister,
        Fill,
        Ioctl,
    }

    /// Two faults posted and not read, as a handler finds them in its socket;
    /// the first returned; then the second's waiter woken without its event
    /// read: an unregister of its page, a fill with a wake, or `UFFDIO_WAKE`.
    /// Linux's wake took that event off the queue unread (v6.12
    /// fs/userfaultfd.c `userfaultfd_wake_function` :141), so the next read has
    /// nothing of it: `None` here (non-blocking), where before the mirror it
    /// returned the event and a `UFFDIO_COPY` to its now-unregistered page
    /// failed with `ENOENT` (`Wake::Unregister`). After `UFFDIO_WAKE` the
    /// thread runs its access again on a page still missing and faults again:
    /// one new event, and no other.
    fn second_unread_fault_woken(how: Wake) {
        let ps = PAGE;
        let owner = UffdBuilder::new().non_blocking(true).create().unwrap();
        // SAFETY: duplicates a descriptor this test owns.
        let handler = unsafe { Uffd::from_raw_fd(libc::dup(owner.as_raw_fd())) };
        let mem = map(2 * ps) as usize;
        owner.register(mem as *mut c_void, 2 * ps).unwrap();
        let first = reader_of(mem);
        until_pending(owner.as_raw_fd(), 1);
        let second = reader_of(mem + ps);
        until_pending(owner.as_raw_fd(), 2);
        assert_eq!(fault_addr(handler.read_event().unwrap()), mem, "{how:?}: the first fault");
        let page2 = (mem + ps) as *mut c_void;
        let src = vec![0x77u8; ps];
        match how {
            Wake::Unregister => handler.unregister(page2, ps).unwrap(),
            // SAFETY: `src` is a page; the second, registered page.
            Wake::Fill => assert_eq!(unsafe { handler.copy(src.as_ptr().cast(), page2, ps, true) }.unwrap(), ps),
            Wake::Ioctl => {
                handler.wake(page2, ps).unwrap();
                // The stale record and the new fault's.
                until_pending(owner.as_raw_fd(), 2);
                assert_eq!(fault_addr(handler.read_event().unwrap()), mem + ps, "{how:?}: the new fault");
                // SAFETY: as above.
                assert_eq!(unsafe { handler.copy(src.as_ptr().cast(), page2, ps, true) }.unwrap(), ps);
            }
        }
        let next = handler.read_event().unwrap();
        assert!(next.is_none(), "{how:?}: an event whose waiter was woken before it was read: {next:?}");
        let byte = second.join().unwrap();
        assert_eq!(byte, if matches!(how, Wake::Unregister) { 0 } else { 0x77 }, "{how:?}");
        let ones = vec![1u8; ps];
        // SAFETY: a page; the first, registered page.
        assert_eq!(unsafe { handler.copy(ones.as_ptr().cast(), mem as *mut c_void, ps, true) }.unwrap(), ps);
        assert_eq!(first.join().unwrap(), 1);
        let registered = if matches!(how, Wake::Unregister) { ps } else { 2 * ps };
        owner.unregister(mem as *mut c_void, registered).unwrap();
    }

    /// The failing-first case (the mirror turns it green): the unread fault's
    /// page is unregistered, so acting on its stale record would be an
    /// `ENOENT` copy.
    #[test]
    fn test_an_unread_fault_unregistered_is_not_read() {
        second_unread_fault_woken(Wake::Unregister);
    }

    #[test]
    fn test_an_unread_fault_filled_with_a_wake_is_not_read() {
        second_unread_fault_woken(Wake::Fill);
    }

    #[test]
    fn test_an_unread_fault_woken_is_read_once_as_its_new_fault() {
        second_unread_fault_woken(Wake::Ioctl);
    }

    /// The control: a fill with `DONTWAKE` wakes nothing (the wake is skipped,
    /// as Linux's, fs/userfaultfd.c v6.12 :1626 to :1627), so the unread fault
    /// is still read.
    #[test]
    fn test_an_unread_fault_filled_without_a_wake_is_still_read() {
        let ps = PAGE;
        let owner = UffdBuilder::new().non_blocking(true).create().unwrap();
        // SAFETY: duplicates a descriptor this test owns.
        let handler = unsafe { Uffd::from_raw_fd(libc::dup(owner.as_raw_fd())) };
        let mem = map(ps) as usize;
        owner.register(mem as *mut c_void, ps).unwrap();
        let reader = reader_of(mem);
        until_pending(owner.as_raw_fd(), 1);
        let src = vec![0x33u8; ps];
        // SAFETY: a page; the registered page.
        assert_eq!(unsafe { handler.copy(src.as_ptr().cast(), mem as *mut c_void, ps, false) }.unwrap(), ps);
        assert_eq!(fault_addr(handler.read_event().unwrap()), mem);
        handler.wake(mem as *mut c_void, ps).unwrap();
        assert_eq!(reader.join().unwrap(), 0x33);
        assert!(handler.read_event().unwrap().is_none());
        owner.unregister(mem as *mut c_void, ps).unwrap();
    }

    /// A blocking read with only a woken waiter's record in the socket waits
    /// on for an event, as Linux's blocking read waits while no fault is
    /// pending (fs/userfaultfd.c v6.12 :1064 to :1076), and returns the next
    /// fault.
    #[test]
    fn test_a_blocking_read_waits_past_a_woken_waiters_record() {
        let ps = PAGE;
        let owner = UffdBuilder::new().non_blocking(false).create().unwrap();
        // SAFETY: duplicates a descriptor this test owns.
        let handler = std::sync::Arc::new(unsafe { Uffd::from_raw_fd(libc::dup(owner.as_raw_fd())) });
        let mem = map(2 * ps) as usize;
        owner.register(mem as *mut c_void, 2 * ps).unwrap();
        let stale = reader_of(mem);
        until_pending(owner.as_raw_fd(), 1);
        handler.unregister(mem as *mut c_void, ps).unwrap();
        assert_eq!(stale.join().unwrap(), 0);
        let h = handler.clone();
        let read = thread::spawn(move || fault_addr(h.read_event().unwrap()));
        thread::sleep(std::time::Duration::from_millis(200));
        assert!(!read.is_finished(), "the blocking read returned with only a woken waiter's record");
        let live = reader_of(mem + ps);
        assert_eq!(read.join().unwrap(), mem + ps);
        let src = vec![5u8; ps];
        // SAFETY: a page; the second, registered page.
        assert_eq!(unsafe { handler.copy(src.as_ptr().cast(), (mem + ps) as *mut c_void, ps, true) }.unwrap(), ps);
        assert_eq!(live.join().unwrap(), 5);
        owner.unregister((mem + ps) as *mut c_void, ps).unwrap();
    }

    /// `Mirror::waits` reads the slot's word: a tag that is the word, waiting,
    /// still waits; a word with the waiting bit cleared (woken) or a slot
    /// holding another tag does not; a tag naming a slot past the table is an
    /// error (`EBADMSG`), never a read past the table, as the macOS twin's
    /// `test_a_tag_past_the_mirror_is_an_error`.
    #[test]
    fn test_waits_reads_the_mirror_word() {
        let table: Box<[AtomicU64]> = (0..proto::MIRROR_WORDS).map(|_| AtomicU64::new(0)).collect();
        let m = Mirror { words: table.as_ptr(), view: ptr::null() };
        // A tag past the table: an error.
        let e = m.waits(proto::tag(1, proto::MIRROR_WORDS + 44));
        assert!(matches!(e, Err(Error::SystemError(Errno::EBADMSG))), "{e:?}");
        // A waiting tag stored in its slot: still waits.
        let tag = proto::tag(2, 3);
        table[3].store(tag, Ordering::Release);
        assert!(m.waits(tag).unwrap(), "a waiting tag in its slot");
        // Its waiting bit cleared (woken): no longer waits.
        table[3].store(tag & !proto::TAG_WAITING, Ordering::Release);
        assert!(!m.waits(tag).unwrap(), "a woken tag");
        // The slot holds a later waiter's tag: this one does not wait.
        table[3].store(proto::tag(5, 3), Ordering::Release);
        assert!(!m.waits(tag).unwrap(), "the slot taken by a later waiter");
        // A zero slot (no waiter): does not wait.
        assert!(!m.waits(proto::tag(1, 7)).unwrap(), "an empty slot");
    }

    /// Version skew the other way, a reader that predates the mirror with this
    /// kernel side: its crate decoded types 1 (page fault) and 2 (remove) and
    /// failed on any other (`Error::UnrecognizedEvent`), and a page fault is
    /// now type 3 (`EVENT_PAGEFAULT2`), so it fails on the first one; this
    /// crate fails on a type 1 record the same way.
    #[test]
    fn test_a_page_fault_record_is_no_type_a_reader_before_the_mirror_decodes() {
        assert!(![1, 2].contains(&proto::EVENT_PAGEFAULT2));
        assert!(matches!(Event::from_record([1, 0x1000, 0, 0]), Err(Error::UnrecognizedEvent(1))));
    }

    /// A stand-in for the kernel side: an AF_UNIX socket pair whose user end a
    /// `Uffd` reads, the other end receiving the reader's `HELLO` (with the
    /// `WSAPROTOCOL_INFOW` of its channel, as the real serving thread does,
    /// `windows_uffd::recv_hello`), reconstructing the channel socket and
    /// answering its `OP_MIRROR` with `answer(channel)`; `records` are queued
    /// on the user end first, as faults a handler would find.
    fn stand_in(answer: impl FnOnce(RawFd) + Send + 'static, records: Vec<[u64; 4]>) -> (Uffd, RawFd) {
        use windows_sys::Win32::Networking::WinSock::{
            FROM_PROTOCOL_INFO, INVALID_SOCKET, WSAPROTOCOL_INFOW, WSASocketW, WSA_FLAG_NO_HANDLE_INHERIT,
            WSA_FLAG_OVERLAPPED,
        };
        let (user, kernel) = wick_os::unix::net::UnixStream::pair().unwrap();
        let user = user.into_raw_fd();
        let kernel = kernel.into_raw_fd();
        for r in records {
            write_all(kernel, &record(r)).unwrap();
        }
        thread::spawn(move || {
            // The HELLO and the channel's protocol information.
            let mut hello = [0u8; proto::RECORD];
            read_all(kernel, &mut hello).unwrap();
            assert_eq!(words(&hello)[0], proto::HELLO);
            // SAFETY: plain data, filled by the read below.
            let mut info: WSAPROTOCOL_INFOW = unsafe { mem::zeroed() };
            // SAFETY: the structure's bytes.
            let raw = unsafe {
                std::slice::from_raw_parts_mut((&raw mut info).cast::<u8>(), mem::size_of::<WSAPROTOCOL_INFOW>())
            };
            read_all(kernel, raw).unwrap();
            // SAFETY: a socket from the peer's protocol information.
            let s = unsafe {
                WSASocketW(
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    &info,
                    0,
                    WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                )
            };
            assert_ne!(s, INVALID_SOCKET, "WSASocketW: {}", Errno::last());
            let channel = wick_os::windows::fd::from_socket(s);
            let mut head = [0u8; proto::RECORD];
            read_all(channel, &mut head).unwrap();
            assert_eq!(words(&head)[0], proto::OP_MIRROR);
            answer(channel);
            // Held until the reader has its answer.
            thread::sleep(std::time::Duration::from_millis(500));
            // SAFETY: the channel's end reconstructed above.
            unsafe { libc::close(channel) };
        });
        // SAFETY: the user end, owned by the object.
        (unsafe { Uffd::from_raw_fd(user) }, kernel)
    }

    /// The reply to `OP_MIRROR`: `[result, handle, 0, 0]`.
    fn answer_with(channel: RawFd, result: i64, handle: u64) {
        #[allow(clippy::cast_sign_loss)]
        write_all(channel, &record([result as u64, handle, 0, 0])).unwrap();
    }

    /// Version skew, this crate with a kernel side that predates the mirror:
    /// it answers `OP_MIRROR` as any unknown request, `-EINVAL`
    /// (`windows_uffd::serve_request`), and the read fails with that error,
    /// the record left unread, where reading without the check would return a
    /// woken waiter's record.
    #[test]
    fn test_a_kernel_side_without_the_mirror_fails_the_read() {
        let (uffd, kernel) = stand_in(
            |c| answer_with(c, -i64::from(libc::EINVAL), 0),
            vec![[proto::EVENT_PAGEFAULT2, 0x1000, 0, proto::tag(1, 3)]],
        );
        let e = uffd.read_event();
        assert!(matches!(e, Err(Error::SystemError(Errno::EINVAL))), "{e:?}");
        assert_eq!(pending(uffd.as_raw_fd()), 1, "the record was read");
        // SAFETY: the stand-in's end.
        unsafe { libc::close(kernel) };
    }

    /// A thread reading registered memory blocks until the page is copied in.
    fn fault_and_serve(server: &Uffd, owner: &Uffd) {
        let ps = PAGE;
        let len = 16 * ps;
        let mem = map(len);
        assert_eq!(owner.register(mem.cast(), len).unwrap(), RANGE_IOCTLS);
        let addr = mem as usize;
        let reader = thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the page.
            let v = unsafe { ptr::read_volatile((addr + ps + 8) as *const u64) };
            // Writing to the same page needs no new fault.
            // SAFETY: as above.
            unsafe { ptr::write_volatile((addr + ps + 16) as *mut u64, 7) };
            v
        });
        let event = loop {
            if let Some(e) = server.read_event().unwrap() {
                break e;
            }
            thread::yield_now();
        };
        let Event::Pagefault {
            rw, addr: fault, ..
        } = event
        else {
            panic!("{event:?}");
        };
        assert_eq!(rw, ReadWrite::Read);
        assert_eq!(fault as usize, addr + ps + 8);
        let src = vec![0x5au8; ps];
        // SAFETY: `src` is a page; the destination is the faulting page.
        let n = unsafe { server.copy(src.as_ptr().cast(), (addr + ps) as *mut c_void, ps, true) };
        assert_eq!(n.unwrap(), ps);
        assert_eq!(reader.join().unwrap(), 0x5a5a_5a5a_5a5a_5a5a);
        // A present page: EEXIST.
        // SAFETY: as above.
        let e = unsafe { server.copy(src.as_ptr().cast(), (addr + ps) as *mut c_void, ps, true) };
        assert!(matches!(e, Err(Error::CopyFailed(Errno::EEXIST))), "{e:?}");
        // Zero fill of the first page; then the host reads it without a fault.
        // SAFETY: a registered page.
        assert_eq!(unsafe { server.zeropage(mem.cast(), ps, true) }.unwrap(), ps);
        // SAFETY: present now.
        assert_eq!(unsafe { ptr::read_volatile(mem.cast::<u64>()) }, 0);
        // SAFETY: present.
        assert_eq!(unsafe { ptr::read_volatile((addr + ps + 16) as *const u64) }, 7);
        owner.unregister(mem.cast(), len).unwrap();
    }

    #[test]
    fn test_owner_serves_faults() {
        let uffd = UffdBuilder::new()
            .close_on_exec(true)
            .non_blocking(true)
            .require_features(FeatureFlags::EVENT_REMOVE)
            .create()
            .unwrap();
        fault_and_serve(&uffd, &uffd);
    }

    #[test]
    fn test_client_serves_faults() {
        // A handler holding the descriptor (as one in another process would).
        let owner = UffdBuilder::new().non_blocking(true).create().unwrap();
        // SAFETY: duplicates a descriptor this test owns.
        let client = unsafe { Uffd::from_raw_fd(libc::dup(owner.as_raw_fd())) };
        fault_and_serve(&client, &owner);
    }

    #[test]
    fn test_remove_event() {
        let ps = PAGE;
        let len = 16 * ps;
        let uffd = UffdBuilder::new()
            .non_blocking(true)
            .require_features(FeatureFlags::EVENT_REMOVE)
            .create()
            .unwrap();
        let mem = map(len);
        uffd.register(mem.cast(), len).unwrap();
        let src = vec![1u8; 4 * ps];
        // SAFETY: four registered pages.
        unsafe { uffd.copy(src.as_ptr().cast(), mem.cast(), 4 * ps, true) }.unwrap();
        // SAFETY: present.
        assert_eq!(unsafe { ptr::read_volatile(mem.add(ps)) }, 1);
        // SAFETY: pages of the mapping above.
        assert_eq!(
            unsafe { libc::madvise(mem.add(ps).cast(), 2 * ps, libc::MADV_DONTNEED) },
            0
        );
        match uffd.read_event().unwrap() {
            Some(Event::Remove { start, end }) => {
                assert_eq!(start as usize, mem as usize + ps);
                assert_eq!(end as usize, mem as usize + 3 * ps);
            }
            other => panic!("{other:?}"),
        }
        // Missing again: refilled with new contents, the old ones are gone.
        let two = vec![2u8; 2 * ps];
        // SAFETY: two registered pages.
        let n = unsafe { uffd.copy(two.as_ptr().cast(), mem.add(ps).cast(), 2 * ps, true) };
        assert_eq!(n.unwrap(), 2 * ps);
        // SAFETY: present.
        assert_eq!(unsafe { ptr::read_volatile(mem.add(ps)) }, 2);
        // SAFETY: present, untouched by the madvise.
        assert_eq!(unsafe { ptr::read_volatile(mem) }, 1);
    }

    #[test]
    fn test_unsupported_feature_and_errors() {
        let e = UffdBuilder::new()
            .require_features(FeatureFlags::EVENT_FORK)
            .create()
            .unwrap_err();
        assert!(matches!(e, Error::SystemError(Errno::EINVAL)), "{e:?}");
        let uffd = UffdBuilder::new().non_blocking(true).create().unwrap();
        // Nothing queued.
        assert!(uffd.read_event().unwrap().is_none());
        let len = 16 * PAGE;
        let mem = map(len);
        // Not registered.
        let src = vec![0u8; PAGE];
        // SAFETY: a valid source.
        let e = unsafe { uffd.copy(src.as_ptr().cast(), mem.cast(), PAGE, true) };
        assert!(matches!(e, Err(Error::CopyFailed(Errno::ENOENT))), "{e:?}");
        // Unaligned.
        let e = uffd.register(mem.wrapping_add(1).cast(), PAGE);
        assert!(matches!(e, Err(Error::SystemError(Errno::EINVAL))), "{e:?}");
        let first = uffd.register(mem.cast(), len).unwrap();
        // Registered again with the same userfaultfd: nothing to do, with the
        // same ioctls, as Linux's register of a vma that context has
        // already (v6.12 mm/userfaultfd.c `userfaultfd_register_range`
        // :1848 to :1853); with another userfaultfd, EBUSY (v6.12
        // fs/userfaultfd.c `userfaultfd_register` :1363 to :1366).
        let again = uffd.register(mem.cast(), len);
        assert_eq!(again.as_ref().ok(), Some(&first), "{again:?}");
        let other = UffdBuilder::new().create().unwrap();
        let e = other.register(mem.cast(), len);
        assert!(matches!(e, Err(Error::SystemError(Errno::EBUSY))), "{e:?}");
        // Part of the range too.
        let e = other.register(mem.wrapping_add(PAGE).cast(), PAGE);
        assert!(matches!(e, Err(Error::SystemError(Errno::EBUSY))), "{e:?}");
    }
}
