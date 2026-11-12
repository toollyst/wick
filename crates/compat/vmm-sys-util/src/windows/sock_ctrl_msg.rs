// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `sock_ctrl_msg` for Windows: descriptors passed over `AF_UNIX` stream
//! sockets, as `SCM_RIGHTS` does on Linux.
//!
//! Winsock has no ancillary data, so [`ScmSocket`] frames what it sends:
//!
//! ```text
//! header   magic "FCSM" u32 | descriptor count u32 | entries length u32 |
//!          flags u32 | data length u64                   (little endian)
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
//! A sender that may not open the peer for duplication (a jailed Firecracker
//! sending to a userfaultfd handler or a vhost-user backend of the operator:
//! the jail's token opens no process outside the jail) instead makes a
//! private copy of each handle in itself and sends the copies' values with
//! the [`FLAG_PULL`] flag; the receiver, which may open the sender, pulls
//! each copy out of it (`DuplicateHandle` with `DUPLICATE_CLOSE_SOURCE`, so
//! the copy is gone from the sender once taken). A socket is pulled the same
//! way, as a handle: `WSADuplicateSocketW` itself duplicates into the target
//! process, which such a sender cannot open, and a socket handle duplicated
//! into the receiver is usable there (as an inherited one is). A receiver
//! that cannot open the sender either fails the receive with the error,
//! never silently without the descriptors.
//!
//! Two processes that may open neither each other nor be pulled from (a
//! jailed Firecracker and its API process, of one jail) need a third that
//! may: the jailer, which made both, gives Firecracker a handle to the API
//! process, and Firecracker names it for the link ([`set_peer_process`]);
//! the descriptors are then duplicated into that handle's process, sockets
//! as handles too (`WSADuplicateSocketW` opens its target by pid).
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

use wick_os::fd::{AsRawFd, FromRawFd, RawFd, from_handle, handle, socket, socket_fd};
use wick_os::unix::net::UnixStream;
use libc::{c_void, iovec};
use windows_sys::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS,
    DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_DATA, HANDLE,
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
/// Header flag: the handle values are the sender's, for the receiver to pull.
const FLAG_PULL: u32 = 1;
const KIND_HANDLE: u32 = 1;
const KIND_EVENTFD: u32 = 2;
const KIND_SOCKET: u32 = 3;
const KIND_SECTION: u32 = 4;
/// A socket, as a handle value: the sender's ([`FLAG_PULL`] frames), or
/// one duplicated into the receiver (a peer named by [`set_peer_process`]).
const KIND_SOCKET_HANDLE: u32 = 5;
/// Linux's limit of descriptors in one message.
const SCM_MAX_FD: usize = 253;

#[allow(clippy::cast_possible_wrap)]
fn win_error(code: u32) -> Error {
    Error::new(code as i32)
}

/// `WSAESHUTDOWN`.
const WSAESHUTDOWN: i32 = 10058;
/// `WSAECONNABORTED`.
const WSAECONNABORTED: i32 = 10053;
/// `WSAECONNRESET`, the compat libc's ECONNRESET.
const WSAECONNRESET: i32 = 10054;
/// `ERROR_BROKEN_PIPE`, the compat libc's EPIPE.
const ERROR_BROKEN_PIPE: i32 = 109;

/// A send's Winsock error as Linux's AF_UNIX send gives it: after a
/// shutdown, or on a connection Winsock aborted (the peer gone), EPIPE, as
/// a send to a peer that closed. vhost-user (and any caller) then sees the
/// errno it classifies as a broken socket, as on Linux.
fn send_error(err: Error) -> Error {
    match err.errno() {
        WSAESHUTDOWN | WSAECONNABORTED => Error::new(ERROR_BROKEN_PIPE),
        _ => err,
    }
}

/// A recv's Winsock error as Linux's AF_UNIX recv gives it: after a
/// shutdown of this side's reading, the end (`None`: 0 bytes); on a
/// connection Winsock aborted, ECONNRESET, Linux's when the peer went away
/// with data unread (`unix_release_sock`, net/unix/af_unix.c).
fn recv_error(err: Error) -> Option<Error> {
    match err.errno() {
        WSAESHUTDOWN => None,
        WSAECONNABORTED => Some(Error::new(WSAECONNRESET)),
        _ => Some(err),
    }
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

// SAFETY: a kernel handle may be used and closed from any thread.
unsafe impl Send for Process {}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: closes the handle this object opened.
        unsafe { CloseHandle(self.0) };
    }
}

impl Process {
    /// A handle of its own to the process `h` (a handle this process holds,
    /// which stays the caller's) names.
    fn duplicate(h: HANDLE) -> Result<Process> {
        let mut out: HANDLE = std::ptr::null_mut();
        // SAFETY: duplicates a handle we hold into this process.
        let ok = unsafe {
            DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mut out, 0, 0, DUPLICATE_SAME_ACCESS)
        };
        if ok == 0 {
            return Err(Error::last());
        }
        Ok(Process(out))
    }
}

/// The peer process of each socket named by [`set_peer_process`].
static PEER_PROCESSES: Mutex<Option<HashMap<RawFd, Process>>> = Mutex::new(None);

/// Names the process at the other end of `sock`: a handle to it with
/// `PROCESS_DUP_HANDLE`, which the descriptors sent over `sock` are then
/// duplicated into, instead of a handle opened by the peer's pid. For a
/// peer the sender may not open: a jailed Firecracker and its API process,
/// two processes of one jail, which may not open each other (measured by
/// `jailer-test.ps1 api`), so the jailer, which made both, gives
/// Firecracker the handle. Sockets are sent to such a peer as handles. The
/// registry keeps a duplicate; the caller keeps `process`.
pub fn set_peer_process(sock: RawFd, process: HANDLE) -> Result<()> {
    let own = Process::duplicate(process)?;
    PEER_PROCESSES.lock().unwrap().get_or_insert_with(HashMap::new).insert(sock, own);
    Ok(())
}

/// Forgets the peer process of `sock` ([`set_peer_process`]).
pub fn clear_peer_process(sock: RawFd) {
    if let Some(map) = PEER_PROCESSES.lock().unwrap().as_mut() {
        map.remove(&sock);
    }
}

/// A handle of this call's own to the peer process named for `sock`, if one is.
fn named_peer(sock: RawFd) -> Result<Option<Process>> {
    PEER_PROCESSES.lock().unwrap().as_ref().and_then(|m| m.get(&sock)).map(|p| Process::duplicate(p.0)).transpose()
}

/// Handles duplicated for a frame: into the peer, or, when the peer cannot
/// be opened, as private copies in this process for the peer to pull. Closed
/// again (there, or here) unless the frame was sent.
struct InFlight<'a> {
    /// The peer the handles are duplicated into; `None` for private copies.
    peer: Option<&'a Process>,
    handles: Vec<u64>,
    sent: bool,
}

impl InFlight<'_> {
    /// The process that holds the duplicates.
    fn holder(&self) -> HANDLE {
        match self.peer {
            Some(peer) => peer.0,
            // SAFETY: a pseudo handle of this process.
            None => unsafe { GetCurrentProcess() },
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if self.sent {
            return;
        }
        for &h in &self.handles {
            // SAFETY: closes, where it was made, a handle duplicated above.
            unsafe {
                DuplicateHandle(
                    self.holder(),
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

/// Duplicates `h` for the frame: into the peer, or as a private copy here
/// (not inheritable, so a child process cannot take it) for the peer to
/// pull. Returns the duplicate's value where it was made.
fn dup_for_peer(h: HANDLE, flight: &mut InFlight<'_>) -> Result<u64> {
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process into the holder.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            h,
            flight.holder(),
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
            let err = send_error(wsa_error());
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
    let mut flags = 0u32;
    let mut named = false;
    if !out_fds.is_empty() {
        let pid = wick_os::windows::peer_pid(sock).map_err(Error::from)?;
        peer = if let Some(p) = named_peer(sock)? {
            named = true;
            #[cfg(test)]
            tests::PUSHED_TO_NAMED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(p)
        } else {
            // SAFETY: opens the peer for handle duplication; checked below.
            let h = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
            if h.is_null() {
                let err = Error::last();
                if err.errno() != ERROR_ACCESS_DENIED as i32 {
                    return Err(err);
                }
                // The peer is out of this process's reach (a jail): the peer
                // pulls private copies out of this process instead.
                flags |= FLAG_PULL;
                None
            } else {
                Some(Process(h))
            }
        };
        let f = flight.insert(InFlight {
            peer: peer.as_ref(),
            handles: Vec::new(),
            sent: false,
        });
        for &fd in out_fds {
            if let Some([section, space]) = super::eventfd::companions(fd) {
                let mut payload = Vec::with_capacity(24);
                for h in [fd, section, space] {
                    payload.extend_from_slice(&dup_for_peer(handle(h), f)?.to_le_bytes());
                }
                put_entry(&mut entries, KIND_EVENTFD, &payload);
            } else if let Some(sec) = libc::wick_fd::attached::<libc::wick_mm::Section>(fd) {
                let mut payload = Vec::with_capacity(32);
                for h in [handle(fd), sec.handle as HANDLE] {
                    payload.extend_from_slice(&dup_for_peer(h, f)?.to_le_bytes());
                }
                payload.extend_from_slice(&sec.size.to_le_bytes());
                payload.extend_from_slice(&u64::from(sec.grow_sealed()).to_le_bytes());
                put_entry(&mut entries, KIND_SECTION, &payload);
            } else if is_socket(fd) && (f.peer.is_none() || named) {
                // A private copy to pull, or, for a named peer, a handle in
                // it: `WSADuplicateSocketW` would open the peer by its pid.
                let v = dup_for_peer(handle(fd), f)?;
                put_entry(&mut entries, KIND_SOCKET_HANDLE, &v.to_le_bytes());
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
                let v = dup_for_peer(handle(fd), f)?;
                put_entry(&mut entries, KIND_HANDLE, &v.to_le_bytes());
            }
        }
    }
    let mut frame = Vec::with_capacity(HEADER + entries.len() + data_len);
    frame.extend_from_slice(&MAGIC.to_le_bytes());
    frame.extend_from_slice(&u32::try_from(out_fds.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&flags.to_le_bytes());
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
        let Some(err) = recv_error(wsa_error()) else {
            return Ok(0);
        };
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

/// The sender of a frame with [`FLAG_PULL`], open for handle duplication.
fn open_sender(sock: RawFd) -> Result<Process> {
    let pid = wick_os::windows::peer_pid(sock).map_err(Error::from)?;
    // SAFETY: opens the sender for handle duplication; checked below.
    let h = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    if h.is_null() {
        return Err(Error::last());
    }
    Ok(Process(h))
}

/// A received handle value as a descriptor of this process: the value
/// itself (duplicated into this process by the sender), or, from a sender
/// whose handles are pulled, a duplicate taken out of it, which closes the
/// sender's copy.
#[allow(clippy::cast_possible_truncation)]
fn take(sender: Option<&Process>, v: u64) -> Result<RawFd> {
    let h = v as usize as HANDLE;
    let Some(sender) = sender else {
        return Ok(from_handle(h));
    };
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of the sender into this process, closing
    // the sender's; the result is checked.
    let ok = unsafe {
        DuplicateHandle(
            sender.0,
            h,
            GetCurrentProcess(),
            &mut out,
            0,
            0,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
        )
    };
    if ok == 0 {
        return Err(Error::last());
    }
    Ok(from_handle(out))
}

/// Decodes the entries of a frame into received descriptors; `sender` is
/// the process to pull handle values from, for a frame with [`FLAG_PULL`].
fn decode(entries: &[u8], count: usize, sender: Option<&Process>) -> Result<Vec<(u32, RawFd)>> {
    let mut out: Vec<(u32, RawFd)> = Vec::with_capacity(count);
    let mut at = 0;
    let bad = |out: &[(u32, RawFd)]| {
        close_received(out);
        win_error(ERROR_INVALID_DATA)
    };
    // Takes `n` handle values at the payload's start; closes what it took
    // and everything received before on an error.
    let taken = |p: &[u8], n: usize, out: &[(u32, RawFd)]| -> Result<Vec<RawFd>> {
        let mut got = Vec::with_capacity(n);
        for i in 0..n {
            match take(sender, u64_at(p, i * 8)) {
                Ok(fd) => got.push(fd),
                Err(e) => {
                    close_received(&got.iter().map(|&fd| (KIND_HANDLE, fd)).collect::<Vec<_>>());
                    close_received(out);
                    return Err(e);
                }
            }
        }
        Ok(got)
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
            (KIND_HANDLE, 8) => out.push((kind, taken(p, 1, &out)?[0])),
            (KIND_SOCKET_HANDLE, 8) => {
                out.push((KIND_SOCKET, taken(p, 1, &out)?[0]));
            }
            (KIND_EVENTFD, 24) => {
                let [fd, section, space] = taken(p, 3, &out)?[..] else {
                    unreachable!("three handles taken");
                };
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
                let [fd, section] = taken(p, 2, &out)?[..] else {
                    unreachable!("two handles taken");
                };
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
                match socket_fd(s) {
                    Ok(fd) => out.push((kind, fd)),
                    Err(err) => {
                        // Said on stderr: the errno alone cannot carry why.
                        eprintln!("recvmsg: a received {err}");
                        close_received(&out);
                        return Err(Error::new(libc::EINVAL));
                    }
                }
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
        && u32_at(header, 12) <= FLAG_PULL
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
        let sender = if count > 0 && u32_at(&header, 12) & FLAG_PULL != 0 {
            match open_sender(sock) {
                Ok(p) => Some(p),
                Err(e) => {
                    // The call's data is still the stream's next bytes.
                    set_left(sock, data_len)?;
                    return Err(e);
                }
            }
        } else {
            None
        };
        let received = decode(&entries, count, sender.as_ref())?;
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

    // A peer gone reads as on Linux, whatever Winsock calls it: a send's
    // EPIPE, a recv's end or ECONNRESET; vhost-user's classifier then calls
    // the socket broken, as it does on Linux.
    #[test]
    fn test_a_gone_peer_reads_as_linux() {
        for code in [WSAESHUTDOWN, WSAECONNABORTED] {
            assert_eq!(send_error(Error::new(code)).errno(), ERROR_BROKEN_PIPE, "{code}");
        }
        assert_eq!(send_error(Error::new(WSAEWOULDBLOCK)).errno(), WSAEWOULDBLOCK);
        assert!(recv_error(Error::new(WSAESHUTDOWN)).is_none());
        assert_eq!(recv_error(Error::new(WSAECONNABORTED)).unwrap().errno(), WSAECONNRESET);
        assert_eq!(recv_error(Error::new(WSAEWOULDBLOCK)).unwrap().errno(), WSAEWOULDBLOCK);
        assert_eq!(libc::EPIPE, ERROR_BROKEN_PIPE);
        assert_eq!(libc::ECONNRESET, WSAECONNRESET);
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
        let (a, b) = UnixStream::pair().unwrap();
        let file = sealed_section(1 << 16);
        let section = libc::wick_fd::attached::<libc::wick_mm::Section>(file.as_raw_fd()).unwrap().handle;
        a.send_with_fd([1u8].as_ref(), file.as_raw_fd()).unwrap();
        let mut buf = [0u8; 1];
        let (_, received) = b.recv_with_fd(&mut buf).unwrap();
        let received = received.unwrap();
        let got = libc::wick_fd::attached::<libc::wick_mm::Section>(received.as_raw_fd()).unwrap();
        assert_eq!(got.size, 1 << 16);
        assert!(got.grow_sealed());
        assert_ne!(got.handle, section, "the receiver's own handle");
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

    /// A sealed memfd stand-in: a file with a section attached, as the
    /// compatibility libc makes for `memfd_create`.
    fn sealed_section(size: u32) -> File {
        use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};
        let file = crate::tempfile::TempFile::new().unwrap().into_file();
        file.set_len(u64::from(size)).unwrap();
        let section = unsafe {
            CreateFileMappingW(
                handle(file.as_raw_fd()),
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                size,
                std::ptr::null(),
            )
        };
        assert!(!section.is_null());
        let sec = libc::wick_mm::Section {
            handle: section as usize,
            size: u64::from(size),
            grow_sealed: std::sync::atomic::AtomicBool::new(true),
        };
        libc::wick_fd::attach(file.as_raw_fd(), std::sync::Arc::new(sec)).unwrap();
        file
    }

    // A sender that may not open the receiver (a jailed Firecracker sending
    // to a handler process of the operator): the receiver pulls the handles
    // out of the sender. The receiver is a child process whose process
    // object admits nobody, so that this process, the sender, cannot open it
    // for duplication (checked: otherwise the test would prove nothing).
    #[test]
    fn test_a_sender_that_cannot_open_the_receiver_is_pulled_from() {
        use std::process::{Command, Stdio};

        let path = std::env::temp_dir().join(format!("wick-scm-pull-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = wick_os::unix::net::UnixListener::bind(&path).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::sock_ctrl_msg::tests::locked_receiver_child",
                "--ignored",
                "--nocapture",
            ])
            .env("WICK_TEST_SOCK", &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (mut s, _) = listener.accept().unwrap();
        let _ = std::fs::remove_file(&path);
        let mut b = [0u8; 1];
        s.read_exact(&mut b).unwrap();
        assert_eq!(b, [b'L'], "the child did not lock its process object");
        // An administrator's debug privilege, where it is enabled (as on
        // some CI machines), opens any process: a jailed sender has no
        // privilege, so this process drops it for the test.
        disable_debug_privilege();
        // SAFETY: plain call; the result is checked.
        let h = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, child.id()) };
        assert!(h.is_null(), "the receiver can be opened, so the test proves nothing");
        assert_eq!(Error::last().errno(), ERROR_ACCESS_DENIED as i32);

        let mut file = crate::tempfile::TempFile::new().unwrap().into_file();
        file.write_all(b"handle pulled").unwrap();
        let evt = EventFd::new(0).unwrap();
        let section = sealed_section(1 << 16);
        let (c, mut d) = UnixStream::pair().unwrap();
        s.send_with_fds(
            &[[b'D'].as_ref()],
            &[file.as_raw_fd(), evt.as_raw_fd(), section.as_raw_fd(), c.as_raw_fd()],
        )
        .unwrap();
        drop(c);
        let mut answer = String::new();
        s.read_to_string(&mut answer).unwrap();
        let out = child.wait_with_output().unwrap();
        let text = format!(
            "{}\n{}\n{}",
            answer,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        for expected in ["file: handle pulled", "eventfd: 5", "section: 65536 sealed", "socket: sent"] {
            assert!(answer.lines().any(|l| l == expected), "{expected}: {text}");
        }
        // The eventfd is shared, and the socket is the pair's other end.
        assert_eq!(evt.read().unwrap(), 5);
        let mut got = [0u8; 17];
        d.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"via pulled socket");
    }

    /// Frames sent to a peer named by [`set_peer_process`].
    pub(super) static PUSHED_TO_NAMED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    // A receiver that cannot be opened by its pid, as a jailed process
    // cannot be by its jailed sibling, takes descriptors pushed into a
    // handle its maker holds and named for the socket.
    #[test]
    fn test_a_named_peer_is_pushed_into_without_being_opened() {
        use std::os::windows::io::AsRawHandle;
        use std::process::{Command, Stdio};

        let path = std::env::temp_dir().join(format!("wick-scm-named-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = wick_os::unix::net::UnixListener::bind(&path).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::sock_ctrl_msg::tests::locked_receiver_child",
                "--ignored",
                "--nocapture",
            ])
            .env("WICK_TEST_SOCK", &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (mut s, _) = listener.accept().unwrap();
        let _ = std::fs::remove_file(&path);
        let mut b = [0u8; 1];
        s.read_exact(&mut b).unwrap();
        assert_eq!(b, [b'L'], "the child did not lock its process object");
        disable_debug_privilege();
        // SAFETY: plain call; the result is checked.
        let h = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, child.id()) };
        assert!(h.is_null(), "the receiver can be opened, so the test proves nothing");
        // The handle from making the process, as the jailer's.
        set_peer_process(s.as_raw_fd(), child.as_raw_handle()).unwrap();
        // The caller's handle is still its own (a closed one is fatal under
        // strict handle checks, and the child is waited on through it).
        // SAFETY: plain call on the child's handle.
        let alive = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(child.as_raw_handle(), 0) };
        assert_eq!(alive, windows_sys::Win32::Foundation::WAIT_TIMEOUT, "the child's handle was closed by set_peer_process");

        let mut file = crate::tempfile::TempFile::new().unwrap().into_file();
        file.write_all(b"handle pulled").unwrap();
        let evt = EventFd::new(0).unwrap();
        let section = sealed_section(1 << 16);
        let (c, mut d) = UnixStream::pair().unwrap();
        let before = PUSHED_TO_NAMED.load(std::sync::atomic::Ordering::SeqCst);
        s.send_with_fds(
            &[[b'D'].as_ref()],
            &[file.as_raw_fd(), evt.as_raw_fd(), section.as_raw_fd(), c.as_raw_fd()],
        )
        .unwrap();
        assert_eq!(PUSHED_TO_NAMED.load(std::sync::atomic::Ordering::SeqCst), before + 1, "not pushed into the named peer");
        drop(c);
        clear_peer_process(s.as_raw_fd());
        let mut answer = String::new();
        s.read_to_string(&mut answer).unwrap();
        let out = child.wait_with_output().unwrap();
        let text = format!(
            "{}\n{}\n{}",
            answer,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        for expected in ["file: handle pulled", "eventfd: 5", "section: 65536 sealed", "socket: sent"] {
            assert!(answer.lines().any(|l| l == expected), "{expected}: {text}");
        }
        assert_eq!(evt.read().unwrap(), 5);
        let mut got = [0u8; 17];
        d.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"via pulled socket");
    }

    /// Disables `SeDebugPrivilege` in this process's token, if it holds it.
    fn disable_debug_privilege() {
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::OpenProcessToken;

        let name: Vec<u16> = "SeDebugPrivilege".encode_utf16().chain(Some(0)).collect();
        let mut token: HANDLE = std::ptr::null_mut();
        let mut privileges: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
        privileges.PrivilegeCount = 1;
        unsafe {
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token),
                0
            );
            assert_ne!(
                LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut privileges.Privileges[0].Luid),
                0
            );
            privileges.Privileges[0] = LUID_AND_ATTRIBUTES { Luid: privileges.Privileges[0].Luid, Attributes: 0 };
            // Fails only for a malformed call; a privilege the token lacks
            // is reported as not all assigned, which is fine.
            assert_ne!(
                AdjustTokenPrivileges(token, 0, &privileges, 0, std::ptr::null_mut(), std::ptr::null_mut()),
                0
            );
            CloseHandle(token);
        }
    }

    #[test]
    #[ignore = "run by test_a_sender_that_cannot_open_the_receiver_is_pulled_from in a separate process"]
    fn locked_receiver_child() {
        use windows_sys::Win32::Security::{
            ACL, ACL_REVISION, DACL_SECURITY_INFORMATION, InitializeAcl, InitializeSecurityDescriptor,
            SECURITY_DESCRIPTOR, SetKernelObjectSecurity, SetSecurityDescriptorDacl,
        };

        let path = std::env::var("WICK_TEST_SOCK").unwrap();
        let mut s = UnixStream::connect(&path).unwrap();
        // An empty DACL: no process may open this one from here on.
        let mut acl = [0u64; 1];
        let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let sd_ptr = (&raw mut sd).cast::<c_void>();
        unsafe {
            assert_ne!(InitializeAcl(acl.as_mut_ptr().cast::<ACL>(), 8, ACL_REVISION), 0);
            assert_ne!(InitializeSecurityDescriptor(sd_ptr, 1), 0);
            assert_ne!(SetSecurityDescriptorDacl(sd_ptr, 1, acl.as_ptr().cast::<ACL>(), 0), 0);
            assert_ne!(
                SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, sd_ptr),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
        }
        s.write_all(b"L").unwrap();

        let mut buf = [0u8; 1];
        let mut fds = [0; 4];
        let (n, nfds) = unsafe { s.recv_with_fds(&mut [iov(&mut buf)], &mut fds).unwrap() };
        assert_eq!((n, nfds, buf[0]), (1, 4, b'D'));
        let mut file = unsafe { File::from_raw_fd(fds[0]) };
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        let evt = unsafe { EventFd::from_raw_fd(fds[1]) };
        evt.write(5).unwrap();
        let section = unsafe { File::from_raw_fd(fds[2]) };
        let sec = libc::wick_fd::attached::<libc::wick_mm::Section>(section.as_raw_fd()).unwrap();
        let mut sock = unsafe { UnixStream::from_raw_fd(fds[3]) };
        sock.write_all(b"via pulled socket").unwrap();
        let answer = format!(
            "file: {text}\neventfd: 5\nsection: {} {}\nsocket: sent\n",
            sec.size,
            if sec.grow_sealed() { "sealed" } else { "unsealed" }
        );
        s.write_all(answer.as_bytes()).unwrap();
    }
}
