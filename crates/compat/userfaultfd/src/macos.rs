// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `userfaultfd` on macOS, with the API and semantics of the Linux crate.
//!
//! The kernel side (fault capture, waiting threads, filling pages) is
//! `libc::wick_uffd`. A [`Uffd`] made by [`UffdBuilder::create`] owns a
//! userfaultfd of this process and calls it directly. A [`Uffd`] made with
//! `from_raw_fd` (typically in a page fault handler process that received the
//! descriptor over a Unix socket) reads events from the descriptor and sends
//! its requests over a private channel set up through it.

use std::io;
use std::mem;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::raw::c_void;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::{Mutex, OnceLock};

use bitflags::bitflags;
use libc::wick_uffd::{self, proto};
use nix::errno::Errno;

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
    SystemError(#[source] nix::Error),
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

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Error {
        Error::SystemError(e)
    }
}

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

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
            proto::EVENT_PAGEFAULT => Ok(Event::Pagefault {
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
}

/// A request channel to the serving thread.
#[derive(Debug)]
struct Channel {
    /// Our end.
    fd: RawFd,
    /// The end sent to the serving thread with `HELLO`, until it has answered
    /// a request. While only the message in flight refers to a socket, and the
    /// message waits on a socket that was never in flight itself, XNU's
    /// collector (`unp_gc`, bsd/kern/uipc_usrreq.c) does not reach it and
    /// flushes it (`sorflush`: its data discarded, its receive side shut), so
    /// the serving thread would get a socket that reads end of file; Linux
    /// keeps it (net/unix/garbage.c `unix_vertex_dead`). The sender keeps it
    /// open until the receiver certainly holds it (`test_inflight_socket_is_flushed`).
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

fn write_all(fd: RawFd, mut buf: &[u8]) -> nix::Result<()> {
    while !buf.is_empty() {
        // SAFETY: writes from a valid buffer, to the channel's socket.
        // MSG_NOSIGNAL: a userfaultfd is no socket on Linux, and a write to
        // it raises no SIGPIPE (the compatibility libc's send raises it as
        // Linux does for a socket's, without the flag).
        let n = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
        if n < 0 {
            let e = Errno::last();
            if e == Errno::EINTR {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn read_all(fd: RawFd, buf: &mut [u8]) -> nix::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: reads into a valid buffer.
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
        if n < 0 {
            let e = Errno::last();
            if e == Errno::EINTR {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(Errno::EPIPE);
        }
        done += n as usize;
    }
    Ok(())
}

/// A reply: `Ok(count)` or `Err((errno, count))`.
type Reply = std::result::Result<u64, (i32, u64)>;

impl Uffd {
    /// The request channel, set up on first use: a socket pair whose other
    /// end is sent to the serving thread with `HELLO`.
    fn channel(&self) -> nix::Result<&Mutex<Channel>> {
        if let Some(c) = self.channel.get() {
            return Ok(c);
        }
        let mut fds = [0; 2];
        // SAFETY: creates two descriptors.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(Errno::last());
        }
        let [mine, theirs] = fds;
        let one: libc::c_int = 1;
        let hello = record([proto::HELLO, 0, 0, 0]);
        // SAFETY: plain socket options; a msghdr with one descriptor.
        let sent = unsafe {
            libc::setsockopt(
                mine,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&one as *const i32).cast(),
                4,
            );
            libc::fcntl(mine, libc::F_SETFD, libc::FD_CLOEXEC);
            let mut iov = libc::iovec {
                iov_base: hello.as_ptr() as *mut c_void,
                iov_len: hello.len(),
            };
            let space = libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) as usize;
            let mut control = vec![0u8; space];
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
            *(libc::CMSG_DATA(c).cast::<RawFd>()) = theirs;
            libc::sendmsg(self.fd, &msg, libc::MSG_NOSIGNAL)
        };
        let mut channel = Channel {
            fd: mine,
            sent: Some(theirs),
        };
        if sent != proto::RECORD as isize {
            let e = Errno::last();
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
    fn request(&self, head: [u64; 4], payload: &[u8]) -> nix::Result<Reply> {
        let mut channel = self.channel()?.lock().unwrap();
        write_all(channel.fd, &record(head))?;
        write_all(channel.fd, payload)?;
        let mut reply = [0u8; proto::RECORD];
        read_all(channel.fd, &mut reply)?;
        if let Some(fd) = channel.sent.take() {
            // SAFETY: the serving thread holds its own copy now.
            unsafe { libc::close(fd) };
        }
        let [result, count, _, _] = words(&reply);
        let result = result as i64;
        Ok(if result < 0 {
            Err((-result as i32, count))
        } else {
            Ok(result as u64)
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
    ) -> nix::Result<Reply> {
        match self.owner {
            Some(ctx) => Ok(local(ctx)),
            None => self.request([op, a, b, c], &[]),
        }
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
        match reply {
            Ok(n) => Ok(n as usize),
            Err((libc::EAGAIN, n)) => Err(Error::PartiallyCopied(n as usize)),
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

    /// Reads up to `buf`'s size of events.
    pub fn read_events<'a>(
        &self,
        buf: &'a mut EventBuffer,
    ) -> Result<impl Iterator<Item = Result<Event>> + 'a> {
        let bytes = buf.0.len() * proto::RECORD;
        // SAFETY: the buffer is `bytes` long.
        let n = unsafe { libc::read(self.fd, buf.0.as_mut_ptr().cast(), bytes) };
        let count = if n < 0 {
            let e = Errno::last();
            if e != Errno::EAGAIN {
                return Err(Error::SystemError(e));
            }
            0
        } else if n == 0 {
            return Err(Error::ReadEof);
        } else {
            let n = n as usize;
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

    /// Sets `O_CLOEXEC` on the descriptor.
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

    fn page() -> usize {
        // SAFETY: sysconf has no preconditions.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    fn map(len: usize) -> *mut u8 {
        // SAFETY: a fresh anonymous mapping.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        p.cast()
    }

    /// A thread reading registered memory blocks until the page is copied in.
    fn fault_and_serve(server: &Uffd, owner: &Uffd) {
        let ps = page();
        let mem = map(2 * ps);
        assert_eq!(owner.register(mem.cast(), 2 * ps).unwrap(), RANGE_IOCTLS);
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
        // Zero fill of the other page; then the host reads it without a fault.
        // SAFETY: a registered page.
        assert_eq!(
            unsafe { server.zeropage(mem.cast(), ps, true) }.unwrap(),
            ps
        );
        // SAFETY: present now.
        assert_eq!(unsafe { ptr::read_volatile(mem.cast::<u64>()) }, 0);
        // SAFETY: present.
        assert_eq!(
            unsafe { ptr::read_volatile((addr + ps + 16) as *const u64) },
            7
        );
        owner.unregister(mem.cast(), 2 * ps).unwrap();
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
        let ps = page();
        let uffd = UffdBuilder::new()
            .non_blocking(true)
            .require_features(FeatureFlags::EVENT_REMOVE)
            .create()
            .unwrap();
        let mem = map(4 * ps);
        uffd.register(mem.cast(), 4 * ps).unwrap();
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
        let ps = page();
        let mem = map(ps);
        // Not registered.
        let src = vec![0u8; ps];
        // SAFETY: a valid source.
        let e = unsafe { uffd.copy(src.as_ptr().cast(), mem.cast(), ps, true) };
        assert!(matches!(e, Err(Error::CopyFailed(Errno::ENOENT))), "{e:?}");
        // Unaligned.
        // SAFETY: a valid pointer, rejected anyway.
        let e = uffd.register(mem.wrapping_add(1).cast(), ps);
        assert!(matches!(e, Err(Error::SystemError(Errno::EINVAL))), "{e:?}");
        uffd.register(mem.cast(), ps).unwrap();
        // Registered twice.
        let e = uffd.register(mem.cast(), ps);
        assert!(matches!(e, Err(Error::SystemError(Errno::EBUSY))), "{e:?}");
    }

    fn socket_pair() -> [RawFd; 2] {
        let mut fds = [0; 2];
        // SAFETY: creates two descriptors.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "{}", Errno::last());
        fds
    }

    /// Sends one byte over `fd` with `right` as SCM_RIGHTS, as `channel`
    /// sends `HELLO`; with no `right`, receives one and returns its descriptor.
    fn byte_with_right(fd: RawFd, right: Option<RawFd>) -> Option<RawFd> {
        let mut byte = *b"h";
        // SAFETY: arithmetic on a size.
        let space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
        let mut control = vec![0u8; space];
        // SAFETY: a msghdr over local buffers, with room for one descriptor.
        unsafe {
            let mut iov = libc::iovec {
                iov_base: byte.as_mut_ptr().cast(),
                iov_len: 1,
            };
            let mut msg: libc::msghdr = mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            if let Some(right) = right {
                let h = libc::CMSG_FIRSTHDR(&msg);
                (*h).cmsg_level = libc::SOL_SOCKET;
                (*h).cmsg_type = libc::SCM_RIGHTS;
                (*h).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
                *(libc::CMSG_DATA(h).cast::<RawFd>()) = right;
                assert_eq!(libc::sendmsg(fd, &msg, 0), 1, "{}", Errno::last());
                return None;
            }
            assert_eq!(libc::recvmsg(fd, &mut msg, 0), 1, "{}", Errno::last());
            let h = libc::CMSG_FIRSTHDR(&msg);
            assert!(!h.is_null(), "no descriptor received");
            Some(*(libc::CMSG_DATA(h).cast::<RawFd>()))
        }
    }

    /// Reads one byte from a received socket and closes it: whether it was
    /// the byte its peer wrote (a flushed socket reads end of file).
    fn kept_its_byte(fd: RawFd) -> bool {
        let mut got = [0u8];
        // SAFETY: a one-byte buffer; a descriptor this test owns.
        let n = unsafe { libc::read(fd, got.as_mut_ptr().cast(), 1) };
        // SAFETY: as above.
        unsafe { libc::close(fd) };
        n == 1 && got == *b"x"
    }

    /// One round: sockets `kept` and `closed` are sent over `a` to `b`, which
    /// is in this process's table and never in flight; `closed` is closed
    /// after sending, as `channel` closed its end before `sent` stayed open,
    /// and `kept` stays open. A byte is written into each one's queue, a Unix
    /// socket is freed (`unp_unlock` then queues `unp_gc`), and both are
    /// received and read. Returns whether each kept its byte.
    fn inflight_round() -> (bool, bool) {
        let [a, b] = socket_pair();
        let [kept_peer, kept] = socket_pair();
        let [closed_peer, closed] = socket_pair();
        byte_with_right(a, Some(kept));
        byte_with_right(a, Some(closed));
        // SAFETY: descriptors this test owns; one-byte writes.
        unsafe {
            libc::close(closed);
            assert_eq!(libc::write(kept_peer, b"x".as_ptr().cast(), 1), 1);
            assert_eq!(libc::write(closed_peer, b"x".as_ptr().cast(), 1), 1);
            let [x, y] = socket_pair();
            libc::close(x);
            libc::close(y);
        }
        // unp_gc runs as a thread call, which nothing here can wait for; with
        // 20 ms it had run in 100 of 100 rounds of the probe this test comes
        // from (macOS 27.2), and the test needs it in one round of ROUNDS.
        thread::sleep(std::time::Duration::from_millis(20));
        let kept_got = kept_its_byte(byte_with_right(b, None).unwrap());
        let closed_got = kept_its_byte(byte_with_right(b, None).unwrap());
        // SAFETY: descriptors this test owns.
        unsafe {
            for fd in [a, b, kept_peer, closed_peer, kept] {
                libc::close(fd);
            }
        }
        (kept_got, closed_got)
    }

    /// Why `Channel::sent` stays open: XNU's collector flushes a socket that
    /// only a message waiting on a never-in-flight socket refers to (Linux
    /// keeps it), and keeps one this process still has open. A round where
    /// the closed socket was flushed is one where the collector ran after
    /// both were in flight, so the kept one was judged in that same pass.
    #[test]
    fn test_inflight_socket_is_flushed() {
        const ROUNDS: usize = 10;
        let rounds: Vec<(bool, bool)> = (0..ROUNDS).map(|_| inflight_round()).collect();
        let flushed = rounds.iter().filter(|(_, closed)| !closed).count();
        assert!(flushed > 0, "XNU's unp_gc flushed no in-flight socket in {ROUNDS} rounds");
        assert!(
            rounds.iter().all(|(kept, _)| *kept),
            "a socket kept open was flushed: {rounds:?}"
        );
    }
}
