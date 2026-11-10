// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `sock_ctrl_msg` for Windows: descriptors passed over `AF_UNIX` stream
//! sockets, as `SCM_RIGHTS` does on Linux.
//!
//! Winsock has no ancillary data, so [`ScmSocket`] frames what it sends:
//!
//! ```text
//! header   magic "FCSM" u32 | descriptor count u32 | entries length u32 |
//!          reserved u32 | data length u64                (little endian)
//! entries  per descriptor: kind u32 | payload length u32 | payload
//! data     the bytes of the call
//! ```
//!
//! Before sending, each descriptor is duplicated into the peer process (its
//! pid comes from `SIO_AF_UNIX_GETPEERPID`), so the entries carry values that
//! are valid in the receiver:
//! - a handle: its value there;
//! - an eventfd ([`crate::eventfd`]): the event and its section and space
//!   handles, which the receiver adopts, so both processes share the counter;
//! - a socket: `WSADuplicateSocketW` protocol info, which the receiver turns
//!   into its own socket, as Winsock requires;
//! - a sealed memfd (a file with a `libc::wick_mm::Section`): the file, the
//!   section, its size and whether it is sealed against growth; the
//!   receiver attaches the section, so its mappings have the sealed size.
//!
//! Receiving follows Linux stream semantics: the descriptors come with the
//! first byte of their call's data; a receive returns data of consecutive
//! calls that are queued, and ends with the call it took descriptors from;
//! the rest of a call is returned by the next receives. When there is not
//! room for all the descriptors, they are closed, the data is received all
//! the same, and the receive fails with `ENOBUFS` (`WSAENOBUFS`), as
//! upstream does on `MSG_CTRUNC`.
//!
//! Both ends of a socket that carries descriptors use [`ScmSocket`] for all
//! of its traffic (the framing is the Windows wire format). The vhost-user
//! crates and Firecracker's userfaultfd protocol do.
//!
//! A peer that sends plain bytes (an HTTP client of the API socket, which
//! micro-http reads with [`ScmSocket::recv_with_fds`]) is read as a plain
//! stream with no descriptors, as `recvmsg` reads a Linux peer that sends no
//! `SCM_RIGHTS`: at each call boundary, what is queued is a frame only if it
//! begins with a valid header (magic, reserved zero, at most `SCM_MAX_FD`
//! descriptors, entry lengths that fit them); bytes that only begin like the
//! magic are waited for until they tell.

use std::collections::HashMap;
use std::fs::File;
use std::mem::size_of;
use std::sync::{Mutex, OnceLock};

use wick_os::fd::{AsRawFd, FromRawFd, RawFd, from_handle, from_socket, handle, socket};
use wick_os::unix::net::UnixStream;
use libc::{c_void, iovec};
use windows_sys::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS,
    DuplicateHandle, ERROR_INVALID_DATA, HANDLE,
};
use windows_sys::Win32::Networking::WinSock::{
    FROM_PROTOCOL_INFO, INVALID_SOCKET, MSG_PEEK, SOCKET_ERROR, WSA_FLAG_NO_HANDLE_INHERIT,
    WSA_FLAG_OVERLAPPED, WSADuplicateSocketW, WSAENOBUFS, WSAEWOULDBLOCK, WSAGetLastError, WSAPROTOCOL_INFOW,
    WSASocketW, recv, send,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

use crate::errno::{Error, Result};

const MAGIC: u32 = u32::from_le_bytes(*b"FCSM");
const HEADER: usize = 24;
const KIND_HANDLE: u32 = 1;
const KIND_EVENTFD: u32 = 2;
const KIND_SOCKET: u32 = 3;
const KIND_SECTION: u32 = 4;
/// Linux's limit of descriptors in one message.
const SCM_MAX_FD: usize = 253;

#[allow(clippy::cast_possible_wrap)]
fn win_error(code: u32) -> Error {
    Error::new(code as i32)
}

fn wsa_error() -> Error {
    // SAFETY: reads the thread's last Winsock error.
    Error::new(unsafe { WSAGetLastError() })
}

/// Waits a moment for a peer that is in the middle of sending a frame.
fn backoff(round: &mut u32) {
    *round += 1;
    if *round < 100 {
        std::thread::yield_now();
    } else {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// An open process handle, closed on drop.
struct Process(HANDLE);

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: closes the handle this object opened.
        unsafe { CloseHandle(self.0) };
    }
}

/// Handles duplicated into the peer, closed there again unless the frame
/// was sent.
struct InFlight<'a> {
    peer: &'a Process,
    handles: Vec<u64>,
    sent: bool,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if self.sent {
            return;
        }
        for &h in &self.handles {
            // SAFETY: closes, in the peer, a handle duplicated there above.
            unsafe {
                DuplicateHandle(
                    self.peer.0,
                    h as usize as HANDLE,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    DUPLICATE_CLOSE_SOURCE,
                )
            };
        }
    }
}

fn dup_into(peer: &Process, h: HANDLE, flight: &mut InFlight<'_>) -> Result<u64> {
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process into the peer.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            h,
            peer.0,
            &mut out,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(Error::last());
    }
    let v = out as usize as u64;
    flight.handles.push(v);
    Ok(v)
}

fn put_entry(out: &mut Vec<u8>, kind: u32, payload: &[u8]) {
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    out.extend_from_slice(payload);
}

fn send_all(sock: usize, mut buf: &[u8], started: &mut bool) -> Result<()> {
    let mut round = 0;
    while !buf.is_empty() {
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: the buffer is valid for `len` bytes.
        let n = unsafe { send(sock, buf.as_ptr(), len, 0) };
        if n == SOCKET_ERROR {
            let err = wsa_error();
            // A frame that started goes out whole, or the peer would lose
            // its place in the stream.
            if err.errno() == WSAEWOULDBLOCK && *started {
                backoff(&mut round);
                continue;
            }
            return Err(err);
        }
        *started = true;
        buf = &buf[usize::try_from(n).unwrap()..];
    }
    Ok(())
}

fn raw_sendmsg<D: IntoIovec>(sock: RawFd, out_data: &[D], out_fds: &[RawFd]) -> Result<usize> {
    let data_len: usize = out_data.iter().map(IntoIovec::size).sum();
    let mut entries = Vec::new();
    let peer;
    let mut flight = None;
    if !out_fds.is_empty() {
        let pid = wick_os::windows::peer_pid(sock).map_err(Error::from)?;
        // SAFETY: opens the peer for handle duplication; checked below.
        let h = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
        if h.is_null() {
            return Err(Error::last());
        }
        peer = Process(h);
        let f = flight.insert(InFlight {
            peer: &peer,
            handles: Vec::new(),
            sent: false,
        });
        for &fd in out_fds {
            if let Some([section, space]) = super::eventfd::companions(fd) {
                let mut payload = Vec::with_capacity(24);
                for h in [fd, section, space] {
                    payload.extend_from_slice(&dup_into(&peer, handle(h), f)?.to_le_bytes());
                }
                put_entry(&mut entries, KIND_EVENTFD, &payload);
            } else if let Some(sec) = libc::wick_fd::attached::<libc::wick_mm::Section>(fd) {
                let mut payload = Vec::with_capacity(32);
                for h in [handle(fd), sec.handle as HANDLE] {
                    payload.extend_from_slice(&dup_into(&peer, h, f)?.to_le_bytes());
                }
                payload.extend_from_slice(&sec.size.to_le_bytes());
                payload.extend_from_slice(&u64::from(sec.grow_sealed()).to_le_bytes());
                put_entry(&mut entries, KIND_SECTION, &payload);
            } else if is_socket(fd) {
                // SAFETY: an all-zero WSAPROTOCOL_INFOW is valid.
                let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
                // SAFETY: fills `info` for the peer.
                if unsafe { WSADuplicateSocketW(socket(fd), pid, &mut info) } != 0 {
                    return Err(wsa_error());
                }
                // SAFETY: plain data, read as bytes.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        (&raw const info).cast::<u8>(),
                        size_of::<WSAPROTOCOL_INFOW>(),
                    )
                };
                put_entry(&mut entries, KIND_SOCKET, bytes);
            } else {
                let v = dup_into(&peer, handle(fd), f)?;
                put_entry(&mut entries, KIND_HANDLE, &v.to_le_bytes());
            }
        }
    }
    let mut frame = Vec::with_capacity(HEADER + entries.len() + data_len);
    frame.extend_from_slice(&MAGIC.to_le_bytes());
    frame.extend_from_slice(&u32::try_from(out_fds.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes());
    frame.extend_from_slice(&(data_len as u64).to_le_bytes());
    frame.extend_from_slice(&entries);
    for d in out_data {
        // SAFETY: the trait guarantees the pointer is valid for `size` bytes.
        frame.extend_from_slice(unsafe { std::slice::from_raw_parts(d.as_ptr().cast(), d.size()) });
    }
    let mut started = false;
    send_all(socket(sock), &frame, &mut started)?;
    if let Some(f) = flight.as_mut() {
        f.sent = true;
    }
    Ok(data_len)
}

fn is_socket(fd: RawFd) -> bool {
    let mut ty: i32 = 0;
    let mut len = 4;
    // SAFETY: the option value is an `i32`; a non-socket fails.
    unsafe {
        windows_sys::Win32::Networking::WinSock::getsockopt(
            socket(fd),
            windows_sys::Win32::Networking::WinSock::SOL_SOCKET,
            windows_sys::Win32::Networking::WinSock::SO_TYPE,
            (&raw mut ty).cast(),
            &mut len,
        ) == 0
    }
}

/// The rest of a call's data still to be received on a socket.
struct Pending {
    left: u64,
    /// Our own handle of the socket, to tell whether the descriptor value
    /// still names it.
    same: HANDLE,
}

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Pending {}

impl Drop for Pending {
    fn drop(&mut self) {
        // SAFETY: closes the handle this entry duplicated.
        unsafe { CloseHandle(self.same) };
    }
}

/// Locked only to read or record a socket's state, never across a wait.
fn pending() -> &'static Mutex<HashMap<RawFd, Pending>> {
    static PENDING: OnceLock<Mutex<HashMap<RawFd, Pending>>> = OnceLock::new();
    PENDING.get_or_init(Mutex::default)
}

/// Serializes the receives on one socket (by descriptor value), as the
/// socket's own lock does on Linux; a receive that waits holds up only the
/// other receives on its socket.
fn recv_lock(sock: RawFd) -> std::sync::Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<RawFd, std::sync::Arc<Mutex<()>>>>> = OnceLock::new();
    LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap()
        .entry(sock)
        .or_default()
        .clone()
}

/// Receives up to `buf.len()` bytes; `peek` leaves them queued. With
/// `progress`, a non-blocking socket waits for the sender instead of failing
/// with `EAGAIN`, because the bytes are part of a frame already started.
fn recv_bytes(sock: usize, buf: &mut [u8], peek: bool, progress: bool) -> Result<usize> {
    let mut round = 0;
    loop {
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        let flags = if peek { MSG_PEEK } else { 0 };
        // SAFETY: the buffer is valid for `len` bytes.
        let n = unsafe { recv(sock, buf.as_mut_ptr(), len, flags) };
        if n != SOCKET_ERROR {
            return Ok(usize::try_from(n).unwrap());
        }
        let err = wsa_error();
        if err.errno() == WSAEWOULDBLOCK && progress {
            backoff(&mut round);
            continue;
        }
        return Err(err);
    }
}

fn recv_exact(sock: usize, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = recv_bytes(sock, buf, false, true)?;
        if n == 0 {
            return Err(win_error(ERROR_INVALID_DATA));
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Where the next received byte goes in a list of iovecs.
struct Cursor<'a> {
    iovecs: &'a [iovec],
    idx: usize,
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(iovecs: &'a [iovec]) -> Self {
        Cursor {
            iovecs,
            idx: 0,
            off: 0,
        }
    }

    fn room(&self) -> usize {
        self.iovecs[self.idx.min(self.iovecs.len())..]
            .iter()
            .map(|v| v.iov_len)
            .sum::<usize>()
            - self.off
    }

    /// The rest of the current iovec, at most `max` bytes.
    ///
    /// # Safety
    ///
    /// The iovecs must be valid for writes.
    unsafe fn chunk(&mut self, max: usize) -> Option<&'a mut [u8]> {
        while self.idx < self.iovecs.len() && self.off == self.iovecs[self.idx].iov_len {
            self.idx += 1;
            self.off = 0;
        }
        let v = self.iovecs.get(self.idx)?;
        let len = (v.iov_len - self.off).min(max);
        // SAFETY: the caller guarantees the iovec is writable.
        Some(unsafe { std::slice::from_raw_parts_mut(v.iov_base.cast::<u8>().add(self.off), len) })
    }

    fn advance(&mut self, n: usize) {
        self.off += n;
    }
}

/// Receives up to `left` bytes of a call's data that is being received. The
/// first receive waits only with `progress`; then the bytes are known to be
/// on their way (the sender writes a frame at once), so it waits for them
/// until the iovecs or the call's data are full.
///
/// # Safety
///
/// The iovecs must be valid for writes.
unsafe fn recv_data(sock: usize, cur: &mut Cursor<'_>, left: u64, progress: bool) -> Result<usize> {
    let mut total = 0usize;
    loop {
        let want = usize::try_from(left - total as u64).unwrap_or(usize::MAX);
        if want == 0 {
            break;
        }
        // SAFETY: the caller's contract.
        let Some(buf) = (unsafe { cur.chunk(want) }) else {
            break;
        };
        let n = recv_bytes(sock, buf, false, progress || total > 0)?;
        if n == 0 {
            // The sender closed in the middle of a call.
            return if total == 0 {
                Err(win_error(ERROR_INVALID_DATA))
            } else {
                Ok(total)
            };
        }
        cur.advance(n);
        total += n;
    }
    Ok(total)
}

/// Receives what is queued of a plain stream into `iovecs`, as `readv`:
/// whatever is there, without waiting for more once something is read.
///
/// # Safety
///
/// The iovecs must be valid for writes.
unsafe fn recv_plain(sock: usize, iovecs: &mut [iovec]) -> Result<usize> {
    let mut total = 0usize;
    for iov in iovecs.iter() {
        if iov.iov_len == 0 {
            continue;
        }
        // SAFETY: the caller guarantees the iovec is writable.
        let buf = unsafe { std::slice::from_raw_parts_mut(iov.iov_base.cast::<u8>(), iov.iov_len) };
        let n = match recv_bytes(sock, buf, false, false) {
            Ok(n) => n,
            Err(e) if total > 0 && e.errno() == WSAEWOULDBLOCK => break,
            Err(e) => return Err(e),
        };
        total += n;
        if n < buf.len() {
            break;
        }
    }
    Ok(total)
}

fn close_received(handles: &[(u32, RawFd)]) {
    for &(kind, fd) in handles {
        if kind == KIND_SOCKET {
            // SAFETY: closes a socket received above.
            unsafe { windows_sys::Win32::Networking::WinSock::closesocket(socket(fd)) };
        } else {
            libc::wick_fd::detach(fd);
            // SAFETY: closes a handle received above.
            unsafe { CloseHandle(handle(fd)) };
        }
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[allow(clippy::cast_possible_truncation)]
fn value(v: u64) -> RawFd {
    from_handle(v as usize as HANDLE)
}

/// Decodes the entries of a frame into received descriptors.
fn decode(entries: &[u8], count: usize) -> Result<Vec<(u32, RawFd)>> {
    let mut out: Vec<(u32, RawFd)> = Vec::with_capacity(count);
    let mut at = 0;
    let bad = |out: &[(u32, RawFd)]| {
        close_received(out);
        win_error(ERROR_INVALID_DATA)
    };
    while out.len() < count {
        if entries.len() < at + 8 {
            return Err(bad(&out));
        }
        let kind = u32_at(entries, at);
        let len = u32_at(entries, at + 4) as usize;
        at += 8;
        if entries.len() < at + len {
            return Err(bad(&out));
        }
        let p = &entries[at..at + len];
        at += len;
        match (kind, len) {
            (KIND_HANDLE, 8) => out.push((kind, value(u64_at(p, 0)))),
            (KIND_EVENTFD, 24) => {
                let (fd, section, space) =
                    (value(u64_at(p, 0)), value(u64_at(p, 8)), value(u64_at(p, 16)));
                // SAFETY: the sender duplicated these three handles of one
                // eventfd into this process for us.
                if let Err(e) = unsafe { super::eventfd::adopt(fd, section, space) } {
                    close_received(&[(KIND_HANDLE, fd)]);
                    close_received(&out);
                    return Err(e.into());
                }
                out.push((kind, fd));
            }
            (KIND_SECTION, 32) => {
                let (fd, section) = (value(u64_at(p, 0)), value(u64_at(p, 8)));
                let sec = libc::wick_mm::Section {
                    handle: handle(section) as usize,
                    size: u64_at(p, 16),
                    grow_sealed: std::sync::atomic::AtomicBool::new(u64_at(p, 24) != 0),
                };
                // The section is owned by `sec` from here.
                if let Err(e) = libc::wick_fd::attach(fd, std::sync::Arc::new(sec)) {
                    close_received(&[(KIND_HANDLE, fd)]);
                    close_received(&out);
                    return Err(e.into());
                }
                out.push((KIND_HANDLE, fd));
            }
            (KIND_SOCKET, n) if n == size_of::<WSAPROTOCOL_INFOW>() => {
                // SAFETY: an all-zero WSAPROTOCOL_INFOW is valid.
                let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
                // SAFETY: copies plain data of the right size.
                unsafe {
                    std::ptr::copy_nonoverlapping(p.as_ptr(), (&raw mut info).cast::<u8>(), n)
                };
                // SAFETY: creates our socket from the sender's protocol info.
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
                if s == INVALID_SOCKET {
                    let err = wsa_error();
                    close_received(&out);
                    return Err(err);
                }
                out.push((kind, from_socket(s)));
            }
            _ => return Err(bad(&out)),
        }
    }
    Ok(out)
}

/// Whether `header` is the header of a frame (see the module docs).
fn is_frame_header(header: &[u8; HEADER]) -> bool {
    let count = u32_at(header, 4) as usize;
    let entries_len = u32_at(header, 8) as usize;
    let largest = 8 + size_of::<WSAPROTOCOL_INFOW>();
    u32_at(header, 0) == MAGIC
        && u32_at(header, 12) == 0
        && count <= SCM_MAX_FD
        && entries_len >= count * 8
        && entries_len <= count * largest
}

/// # Safety
///
/// The iovecs must be valid for writes.
unsafe fn raw_recvmsg(sock: RawFd, iovecs: &mut [iovec], in_fds: &mut [RawFd]) -> Result<(usize, usize)> {
    // SAFETY: the caller's contract.
    let r = unsafe { recvmsg_inner(sock, iovecs, in_fds) };
    if matches!(&r, Err(e) if e.errno() == WSAEWOULDBLOCK) {
        // Nothing left: an edge-triggered epoll registration re-arms.
        libc::wick_fd::drained(sock);
    }
    r
}

/// How many bytes are queued on the socket (0 if it cannot tell).
fn queued(sock: usize) -> usize {
    let mut n: u32 = 0;
    // SAFETY: FIONREAD writes one u32.
    let r = unsafe {
        windows_sys::Win32::Networking::WinSock::ioctlsocket(
            sock,
            windows_sys::Win32::Networking::WinSock::FIONREAD,
            &mut n,
        )
    };
    if r == 0 { n as usize } else { 0 }
}

/// Records how much of the call being received on `sock` is left.
fn set_left(sock: RawFd, left: u64) -> Result<()> {
    let mut table = pending().lock().unwrap();
    if left == 0 {
        table.remove(&sock);
        return Ok(());
    }
    if let Some(p) = table.get_mut(&sock) {
        p.left = left;
        return Ok(());
    }
    let mut same: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates our own socket handle, used only to compare.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle(sock),
            GetCurrentProcess(),
            &mut same,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(Error::last());
    }
    table.insert(sock, Pending { left, same });
    Ok(())
}

/// Receives as Linux `recvmsg` on a stream socket does: data of consecutive
/// calls in one receive, until the iovecs are full, nothing more is queued,
/// or a call that carries descriptors was read from (its descriptors come
/// with its first byte). Descriptors that do not fit are closed, their
/// call's data is still received, and the receive fails with `ENOBUFS`.
///
/// # Safety
///
/// The iovecs must be valid for writes.
unsafe fn recvmsg_inner(sock: RawFd, iovecs: &mut [iovec], in_fds: &mut [RawFd]) -> Result<(usize, usize)> {
    let s = socket(sock);
    let lock = recv_lock(sock);
    let _receiving = lock.lock().unwrap();
    let mut cur = Cursor::new(iovecs);
    let mut total = 0usize;

    // The rest of a call that is being received.
    let left = {
        let mut table = pending().lock().unwrap();
        match table.get(&sock) {
            // SAFETY: compares two handle values.
            Some(p) if unsafe { CompareObjectHandles(handle(sock), p.same) } != 0 => p.left,
            Some(_) => {
                table.remove(&sock);
                0
            }
            None => 0,
        }
    };
    if left > 0 {
        // SAFETY: the caller's contract.
        let n = unsafe { recv_data(s, &mut cur, left, false)? };
        total = n;
        set_left(sock, left - n as u64)?;
        if (n as u64) < left || cur.room() == 0 {
            return Ok((total, 0));
        }
    }

    let magic = MAGIC.to_le_bytes();
    loop {
        let mut header = [0u8; HEADER];
        if total == 0 {
            // A frame, or plain bytes: a frame's whole header is on its way
            // once its first byte is there.
            let mut round = 0;
            loop {
                let n = recv_bytes(s, &mut header, true, false)?;
                if n == 0 {
                    return Ok((0, 0));
                }
                let m = n.min(magic.len());
                if header[..m] != magic[..m] || (n == HEADER && !is_frame_header(&header)) {
                    // Plain bytes from a peer that sends no descriptors.
                    // SAFETY: the caller's contract.
                    return unsafe { recv_plain(s, iovecs) }.map(|n| (n, 0));
                }
                if n == HEADER {
                    break;
                }
                backoff(&mut round);
            }
        } else {
            // Continue into the next call only if it is already queued.
            if queued(s) < HEADER {
                return Ok((total, 0));
            }
            match recv_bytes(s, &mut header, true, false) {
                Ok(HEADER) if is_frame_header(&header) => {}
                _ => return Ok((total, 0)),
            }
            if u64_at(&header, 16) == 0 {
                // Descriptors with no data start a receive of their own.
                return Ok((total, 0));
            }
        }
        recv_exact(s, &mut header)?;
        let count = u32_at(&header, 4) as usize;
        let entries_len = u32_at(&header, 8) as usize;
        let data_len = u64_at(&header, 16);
        let mut entries = vec![0u8; entries_len];
        recv_exact(s, &mut entries)?;
        let received = decode(&entries, count)?;
        let fits = received.len() <= in_fds.len();
        if fits {
            for (slot, (_, fd)) in in_fds.iter_mut().zip(&received) {
                *slot = *fd;
            }
        } else {
            close_received(&received);
        }
        let n = if data_len > 0 && cur.room() > 0 {
            // SAFETY: the caller's contract.
            unsafe { recv_data(s, &mut cur, data_len, true)? }
        } else {
            0
        };
        total += n;
        set_left(sock, data_len - n as u64)?;
        if !fits {
            return Err(Error::new(WSAENOBUFS));
        }
        if !received.is_empty() || (n as u64) < data_len || cur.room() == 0 {
            return Ok((total, received.len()));
        }
    }
}

/// Trait for sockets that can send and receive descriptors with data.
pub trait ScmSocket {
    /// Gets the file descriptor of this socket.
    fn socket_fd(&self) -> RawFd;

    /// Sends the given data and file descriptor over the socket.
    ///
    /// On success, returns the number of bytes sent.
    fn send_with_fd<D: IntoIovec>(&self, buf: D, fd: RawFd) -> Result<usize> {
        self.send_with_fds(&[buf], &[fd])
    }

    /// Sends the given data and file descriptors over the socket.
    ///
    /// On success, returns the number of bytes sent.
    fn send_with_fds<D: IntoIovec>(&self, bufs: &[D], fds: &[RawFd]) -> Result<usize> {
        raw_sendmsg(self.socket_fd(), bufs, fds)
    }

    /// Receives data and potentially a file descriptor from the socket.
    fn recv_with_fd(&self, buf: &mut [u8]) -> Result<(usize, Option<File>)> {
        let mut fd = [0];
        let mut iovecs = [iovec {
            iov_base: buf.as_mut_ptr().cast::<c_void>(),
            iov_len: buf.len(),
        }];
        // SAFETY: the iovec is the borrowed `buf`.
        let (read_count, fd_count) = unsafe { self.recv_with_fds(&mut iovecs[..], &mut fd)? };
        let file = if fd_count == 0 {
            None
        } else {
            // SAFETY: the received descriptor is ours.
            Some(unsafe { File::from_raw_fd(fd[0]) })
        };
        Ok((read_count, file))
    }

    /// Receives data and file descriptors from the socket. Returns the number
    /// of bytes and of descriptors received; the caller owns the descriptors.
    ///
    /// # Safety
    ///
    /// It is the callers responsibility to ensure it is safe for arbitrary
    /// data to be written to the iovec pointers.
    unsafe fn recv_with_fds(&self, iovecs: &mut [iovec], fds: &mut [RawFd]) -> Result<(usize, usize)> {
        // SAFETY: the caller's contract.
        unsafe { raw_recvmsg(self.socket_fd(), iovecs, fds) }
    }
}

impl ScmSocket for UnixStream {
    fn socket_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

/// Trait for types that can be converted into an `iovec` that can be
/// referenced by a call for the lifetime of this object.
///
/// # Safety
///
/// The returned pointer and size must be valid for the lifetime of the object.
pub unsafe trait IntoIovec {
    /// Gets the base pointer of this `iovec`.
    fn as_ptr(&self) -> *const c_void;

    /// Gets the size in bytes of this `iovec`.
    fn size(&self) -> usize;
}

// SAFETY: a shared slice is valid for its length.
unsafe impl IntoIovec for &[u8] {
    fn as_ptr(&self) -> *const c_void {
        <[u8]>::as_ptr(self).cast()
    }

    fn size(&self) -> usize {
        self.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::io::{Read, Seek, SeekFrom, Write};

    use super::*;
    use crate::eventfd::{EFD_NONBLOCK, EventFd};

    fn iov(buf: &mut [u8]) -> iovec {
        iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        }
    }

    #[test]
    fn test_plain_peer() {
        // An HTTP client writes plain bytes; they are read as a stream.
        let (mut a, b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 64];
        let mut fds = [0; 4];
        let e = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds) }.unwrap_err();
        assert_eq!(e.errno(), WSAEWOULDBLOCK);
        a.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let mut got = Vec::new();
        while got.len() < 18 {
            match unsafe { b.recv_with_fds(&mut [iov(&mut buf[..5])], &mut fds) } {
                Ok((n, 0)) => got.extend_from_slice(&buf[..n]),
                Err(e) if e.errno() == WSAEWOULDBLOCK => std::thread::yield_now(),
                r => panic!("{r:?}"),
            }
        }
        assert_eq!(got, b"GET / HTTP/1.1\r\n\r\n");
        // Bytes that only start like the magic are still plain.
        a.write_all(b"FCSMx").unwrap();
        a.write_all(&[0xff; 32]).unwrap();
        let mut got = 0;
        while got < 37 {
            match unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds) } {
                Ok((n, 0)) => got += n,
                Err(e) if e.errno() == WSAEWOULDBLOCK => std::thread::yield_now(),
                r => panic!("{r:?}"),
            }
        }
        a.shutdown(std::net::Shutdown::Write).unwrap();
        loop {
            match unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds) } {
                Ok((0, 0)) => break,
                Err(e) if e.errno() == WSAEWOULDBLOCK => std::thread::yield_now(),
                r => panic!("{r:?}"),
            }
        }
    }

    #[test]
    fn test_send_recv_no_fd() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(a.send_with_fds(&[[1u8, 2].as_ref(), [3u8].as_ref()], &[]).unwrap(), 3);
        let mut buf = [0u8; 8];
        let (n, nfds) = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut []).unwrap() };
        assert_eq!((n, nfds), (3, 0));
        assert_eq!(&buf[..3], &[1, 2, 3]);
    }

    #[test]
    fn test_send_recv_file() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut file = crate::tempfile::TempFile::new().unwrap().into_file();
        file.write_all(b"handle passed").unwrap();
        a.send_with_fd([7u8].as_ref(), file.as_raw_fd()).unwrap();
        let mut buf = [0u8; 1];
        let (n, received) = b.recv_with_fd(&mut buf).unwrap();
        assert_eq!((n, buf[0]), (1, 7));
        let mut received = received.unwrap();
        received.seek(SeekFrom::Start(0)).unwrap();
        let mut s = String::new();
        received.read_to_string(&mut s).unwrap();
        assert_eq!(s, "handle passed");
    }

    #[test]
    fn test_send_recv_sealed_section() {
        use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};
        let (a, b) = UnixStream::pair().unwrap();
        let file = crate::tempfile::TempFile::new().unwrap().into_file();
        file.set_len(1 << 16).unwrap();
        let section = unsafe {
            CreateFileMappingW(
                handle(file.as_raw_fd()),
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                1 << 16,
                std::ptr::null(),
            )
        };
        assert!(!section.is_null());
        let sec = libc::wick_mm::Section {
            handle: section as usize,
            size: 1 << 16,
            grow_sealed: std::sync::atomic::AtomicBool::new(true),
        };
        libc::wick_fd::attach(file.as_raw_fd(), std::sync::Arc::new(sec)).unwrap();
        a.send_with_fd([1u8].as_ref(), file.as_raw_fd()).unwrap();
        let mut buf = [0u8; 1];
        let (_, received) = b.recv_with_fd(&mut buf).unwrap();
        let received = received.unwrap();
        let got = libc::wick_fd::attached::<libc::wick_mm::Section>(received.as_raw_fd()).unwrap();
        assert_eq!(got.size, 1 << 16);
        assert!(got.grow_sealed());
        assert_ne!(got.handle, section as usize, "the receiver's own handle");
        // The receiver's libc refuses to resize it.
        assert_eq!(unsafe { libc::ftruncate(received.as_raw_fd(), 1 << 17) }, -1);
    }

    #[test]
    fn test_send_recv_eventfd() {
        let (a, b) = UnixStream::pair().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        a.send_with_fd([0u8].as_ref(), evt.as_raw_fd()).unwrap();
        let mut fds = [0; 1];
        let mut buf = [0u8; 1];
        let (_, nfds) = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap() };
        assert_eq!(nfds, 1);
        let received = unsafe { EventFd::from_raw_fd(fds[0]) };
        received.write(5).unwrap();
        assert_eq!(evt.read().unwrap(), 5);
        evt.write(2).unwrap();
        assert_eq!(received.read().unwrap(), 2);
    }

    #[test]
    fn test_send_more_recv_less() {
        let (a, b) = UnixStream::pair().unwrap();
        let evt = EventFd::new(0).unwrap();
        a.send_with_fd([1u8, 2, 3, 4].as_ref(), evt.as_raw_fd()).unwrap();
        a.send_with_fds(&[[5u8].as_ref()], &[]).unwrap();
        let mut fds = [0; 1];
        let mut buf = [0u8; 2];
        let (n, nfds) = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap() };
        assert_eq!((n, nfds, buf), (2, 1, [1, 2]));
        drop(unsafe { EventFd::from_raw_fd(fds[0]) });
        // The rest of the call, and the next one that is queued, as Linux
        // reads a stream.
        let mut buf = [0u8; 8];
        let mut got = std::vec::Vec::new();
        while got.len() < 3 {
            let (n, nfds) = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap() };
            assert_eq!(nfds, 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, [3, 4, 5]);
        // A receive ends with the call it takes descriptors from, and one
        // with no room for them fails, its data received all the same.
        a.send_with_fds(&[[6u8].as_ref()], &[]).unwrap();
        a.send_with_fd([7u8, 8].as_ref(), evt.as_raw_fd()).unwrap();
        a.send_with_fds(&[[9u8].as_ref()], &[]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let (n, nfds) = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap() };
        assert_eq!((n, nfds, &buf[..3]), (3, 1, &[6u8, 7, 8][..]));
        drop(unsafe { EventFd::from_raw_fd(fds[0]) });
        let (n, nfds) = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap() };
        assert_eq!((n, nfds, buf[0]), (1, 0, 9));
        a.send_with_fd([10u8, 11].as_ref(), evt.as_raw_fd()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let err = unsafe { b.recv_with_fds(&mut [iov(&mut buf[..2])], &mut []).unwrap_err() };
        assert_eq!(err.errno(), WSAENOBUFS);
        // Both bytes were received by the failed receive, as on Linux.
        b.set_nonblocking(true).unwrap();
        let err = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap_err() };
        assert_eq!(err.errno(), WSAEWOULDBLOCK);
    }

    #[test]
    fn test_too_many_fds() {
        let (a, b) = UnixStream::pair().unwrap();
        let e1 = EventFd::new(0).unwrap();
        let e2 = EventFd::new(0).unwrap();
        a.send_with_fds(&[[9u8].as_ref()], &[e1.as_raw_fd(), e2.as_raw_fd()]).unwrap();
        let mut fds = [0; 1];
        let mut buf = [0u8; 1];
        let err = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap_err() };
        assert_eq!(err.errno(), WSAENOBUFS);
    }

    #[test]
    fn test_send_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let (c, mut d) = UnixStream::pair().unwrap();
        a.send_with_fd([0u8].as_ref(), c.as_raw_fd()).unwrap();
        drop(c);
        let mut fds = [0; 1];
        let mut buf = [0u8; 1];
        let (_, nfds) = unsafe { b.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap() };
        assert_eq!(nfds, 1);
        let mut c = unsafe { UnixStream::from_raw_fd(fds[0]) };
        c.write_all(b"via passed socket").unwrap();
        let mut s = [0u8; 17];
        d.read_exact(&mut s).unwrap();
        assert_eq!(&s, b"via passed socket");
    }
}
