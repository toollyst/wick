// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `std::os::unix::net` on Windows: stream sockets of Winsock's `AF_UNIX`
//! (Windows 10 1803 and later), which have the same filesystem names and
//! connection semantics as Unix domain stream sockets.
//!
//! Differences the type takes care of:
//! - Winsock has no `socketpair`: [`UnixStream::pair`] binds a listener on a
//!   unique path in the temporary directory, connects, accepts and removes
//!   the path, which gives two connected sockets like `socketpair` does.
//! - `SCM_RIGHTS` does not exist; `vmm-sys-util`'s `sock_ctrl_msg` passes
//!   handles with `DuplicateHandle` into the peer named by [`peer_pid`].


use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::Shutdown;
use std::path::Path;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{fmt, mem, ptr};

use windows_sys::Win32::Networking::WinSock::{
    AF_UNIX, FIONBIO, INVALID_SOCKET, SD_BOTH, SD_RECEIVE, SD_SEND, SIO_AF_UNIX_GETPEERPID,
    SO_ERROR, SO_RCVTIMEO, SO_SNDTIMEO, SOCK_STREAM, SOCKADDR, SOCKADDR_UN, SOCKET, SOCKET_ERROR,
    SOL_SOCKET, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED, WSADATA, WSAGetLastError,
    WSAIoctl, WSASocketW, WSAStartup, accept, bind, connect, getpeername, getsockname, getsockopt,
    MSG_PEEK, ioctlsocket, listen, recv, send, setsockopt, shutdown,
};

use super::fd::{
    AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd, socket, socket_fd,
};

/// Starts Winsock once per process.
pub fn startup() {
    static START: Once = Once::new();
    START.call_once(|| {
        // SAFETY: plain FFI call with an out-parameter.
        let mut data: WSADATA = unsafe { mem::zeroed() };
        // SAFETY: as above.
        let r = unsafe { WSAStartup(0x0202, &mut data) };
        assert_eq!(r, 0, "WSAStartup failed: {r}");
    });
}

fn last_error() -> io::Error {
    // SAFETY: reads the thread's last Winsock error.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

/// `WSAESHUTDOWN`: the socket's direction was shut down.
const WSAESHUTDOWN: i32 = 10058;
/// `ERROR_BROKEN_PIPE`, the compat libc's `EPIPE`.
const EPIPE: i32 = 109;

fn cvt(r: i32) -> io::Result<i32> {
    if r == SOCKET_ERROR {
        Err(last_error())
    } else {
        Ok(r)
    }
}

fn raw(fd: &OwnedFd) -> SOCKET {
    socket(fd.as_raw_fd())
}

fn new_socket() -> io::Result<OwnedFd> {
    startup();
    // SAFETY: plain FFI call.
    let s = unsafe {
        WSASocketW(
            i32::from(AF_UNIX),
            SOCK_STREAM,
            0,
            ptr::null(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if s == INVALID_SOCKET {
        return Err(last_error());
    }
    // SAFETY: a new socket owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(socket_fd(s)?) })
}

/// The address of an `AF_UNIX` socket.
#[derive(Clone)]
pub struct SocketAddr {
    addr: SOCKADDR_UN,
    len: i32,
}

const PATH_OFFSET: usize = mem::offset_of!(SOCKADDR_UN, sun_path);

impl SocketAddr {
    fn from_path(path: &Path) -> io::Result<SocketAddr> {
        let bytes = path
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))?
            .as_bytes();
        // SAFETY: an all-zero `SOCKADDR_UN` is valid.
        let mut addr: SOCKADDR_UN = unsafe { mem::zeroed() };
        if bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "paths must not contain interior null bytes",
            ));
        }
        if bytes.len() >= addr.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path must be shorter than SUN_LEN",
            ));
        }
        addr.sun_family = AF_UNIX;
        for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
            *d = i8::from_ne_bytes([*s]);
        }
        let len = i32::try_from(PATH_OFFSET + bytes.len() + 1).unwrap();
        Ok(SocketAddr { addr, len })
    }

    fn query(
        fd: SOCKET,
        f: unsafe extern "system" fn(SOCKET, *mut SOCKADDR, *mut i32) -> i32,
    ) -> io::Result<SocketAddr> {
        // SAFETY: an all-zero `SOCKADDR_UN` is valid.
        let mut addr: SOCKADDR_UN = unsafe { mem::zeroed() };
        let mut len = i32::try_from(mem::size_of::<SOCKADDR_UN>()).unwrap();
        // SAFETY: the buffer and its length are valid.
        cvt(unsafe { f(fd, (&raw mut addr).cast(), &mut len) })?;
        Ok(SocketAddr { addr, len })
    }

    fn path_bytes(&self) -> &[u8] {
        let n = usize::try_from(self.len).unwrap_or(0).saturating_sub(PATH_OFFSET);
        // SAFETY: `sun_path` is `i8`, which has the layout of `u8`.
        let path: &[u8] = unsafe {
            std::slice::from_raw_parts(self.addr.sun_path.as_ptr().cast(), self.addr.sun_path.len())
        };
        let path = &path[..n.min(path.len())];
        let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
        &path[..end]
    }

    /// Whether the address is unnamed.
    pub fn is_unnamed(&self) -> bool {
        self.path_bytes().is_empty()
    }

    /// The path the socket is bound to.
    pub fn as_pathname(&self) -> Option<&Path> {
        let bytes = self.path_bytes();
        if bytes.is_empty() {
            return None;
        }
        std::str::from_utf8(bytes).ok().map(Path::new)
    }
}

impl fmt::Debug for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_pathname() {
            Some(p) => write!(f, "{p:?} (pathname)"),
            None => f.write_str("(unnamed)"),
        }
    }
}

/// The process id of the peer of a connected `AF_UNIX` socket.
pub fn peer_pid(fd: RawFd) -> io::Result<u32> {
    let mut pid: u32 = 0;
    let mut n: u32 = 0;
    // SAFETY: the output buffer is a `u32`.
    cvt(unsafe {
        WSAIoctl(
            socket(fd),
            SIO_AF_UNIX_GETPEERPID,
            ptr::null(),
            0,
            (&raw mut pid).cast(),
            4,
            &mut n,
            ptr::null_mut(),
            None,
        )
    })?;
    Ok(pid)
}

fn set_timeout(fd: SOCKET, opt: i32, dur: Option<Duration>) -> io::Result<()> {
    let ms: u32 = match dur {
        Some(d) if d.is_zero() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot set a 0 duration timeout",
            ));
        }
        Some(d) => u32::try_from(d.as_millis()).unwrap_or(u32::MAX).max(1),
        None => 0,
    };
    // SAFETY: the option value is a `u32`.
    cvt(unsafe { setsockopt(fd, SOL_SOCKET, opt, (&raw const ms).cast(), 4) })?;
    Ok(())
}

fn timeout(fd: SOCKET, opt: i32) -> io::Result<Option<Duration>> {
    let mut ms: u32 = 0;
    let mut len = 4;
    // SAFETY: the option value is a `u32`.
    cvt(unsafe { getsockopt(fd, SOL_SOCKET, opt, (&raw mut ms).cast(), &mut len) })?;
    Ok((ms != 0).then(|| Duration::from_millis(u64::from(ms))))
}

fn set_nonblocking(fd: SOCKET, on: bool) -> io::Result<()> {
    let mut arg = u32::from(on);
    // SAFETY: `FIONBIO` takes a `u32`.
    cvt(unsafe { ioctlsocket(fd, FIONBIO, &mut arg) })?;
    Ok(())
}

fn take_error(fd: SOCKET) -> io::Result<Option<io::Error>> {
    let mut err: i32 = 0;
    let mut len = 4;
    // SAFETY: the option value is an `i32`.
    cvt(unsafe { getsockopt(fd, SOL_SOCKET, SO_ERROR, (&raw mut err).cast(), &mut len) })?;
    Ok((err != 0).then(|| io::Error::from_raw_os_error(err)))
}

/// What a write to a stream whose peer is gone does besides failing. Linux
/// sends the writing thread `SIGPIPE` (a `write(2)` without `MSG_NOSIGNAL`,
/// as std's `UnixStream` writes), which Firecracker counts; Windows raises no
/// signal. A write to a pipe without a reader does the same on Linux (fs/pipe.c
/// `anon_pipe_write`: `send_sig(SIGPIPE, current, 0)` when `!pipe->readers`),
/// which here is [`crate::stdio::Stdout`]'s write to a standard output pipe.
/// wick's signal emulation sets the hook when a `SIGPIPE` handler is
/// registered (vmm-sys-util's `register_signal_handler`).
static BROKEN_PIPE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Sets what a write to a stream whose peer is gone calls (see above).
pub fn set_broken_pipe_hook(hook: fn()) {
    BROKEN_PIPE.store(hook as usize, Ordering::Release);
}

pub(crate) fn broken_pipe() {
    let f = BROKEN_PIPE.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: only `fn()` values are stored, as `usize`.
        let f: fn() = unsafe { std::mem::transmute::<usize, fn()>(f) };
        f();
    }
}

/// A Unix domain stream socket.
pub struct UnixStream(OwnedFd);

impl fmt::Debug for UnixStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixStream").field("fd", &self.0.as_raw_fd()).finish()
    }
}

impl UnixStream {
    fn sock(&self) -> SOCKET {
        raw(&self.0)
    }

    /// Connects to the socket named by `path`.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<UnixStream> {
        let addr = SocketAddr::from_path(path.as_ref())?;
        let fd = new_socket()?;
        // SAFETY: the address and its length are valid.
        if let Err(e) = cvt(unsafe { connect(raw(&fd), (&raw const addr.addr).cast(), addr.len) }) {
            // Linux fails a connect to a path where no socket file is with
            // ENOENT, and to a socket file nothing listens on with
            // ECONNREFUSED. Winsock refuses both (WSAECONNREFUSED, measured);
            // a missing path is ERROR_FILE_NOT_FOUND here, of kind NotFound
            // as ENOENT is.
            if std::fs::symlink_metadata(path.as_ref())
                .is_err_and(|m| m.kind() == io::ErrorKind::NotFound)
            {
                return Err(io::Error::from_raw_os_error(2));
            }
            return Err(e);
        }
        Ok(UnixStream(fd))
    }

    /// Two connected sockets, like `socketpair(AF_UNIX, SOCK_STREAM)`.
    pub fn pair() -> io::Result<(UnixStream, UnixStream)> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir();
        loop {
            let name = format!(
                "wick-pair-{}-{}.sock",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let path = dir.join(name);
            let listener = match UnixListener::bind(&path) {
                Ok(l) => l,
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
                Err(e) => return Err(e),
            };
            let result = UnixStream::connect(&path)
                .and_then(|a| listener.accept().map(|(b, _)| (a, b)));
            let _ = std::fs::remove_file(&path);
            return result;
        }
    }

    /// A new socket for the same connection.
    pub fn try_clone(&self) -> io::Result<UnixStream> {
        self.0.try_clone().map(UnixStream)
    }

    /// The address of this end.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        SocketAddr::query(self.sock(), getsockname)
    }

    /// The address of the peer.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        SocketAddr::query(self.sock(), getpeername)
    }

    /// `SO_RCVTIMEO`.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        set_timeout(self.sock(), SO_RCVTIMEO, dur)
    }

    /// `SO_SNDTIMEO`.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        set_timeout(self.sock(), SO_SNDTIMEO, dur)
    }

    /// The read timeout.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        timeout(self.sock(), SO_RCVTIMEO)
    }

    /// The write timeout.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        timeout(self.sock(), SO_SNDTIMEO)
    }

    /// Non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        set_nonblocking(self.sock(), nonblocking)
    }

    /// `SO_ERROR`.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        take_error(self.sock())
    }

    /// Shuts down one or both directions.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => SD_RECEIVE,
            Shutdown::Write => SD_SEND,
            Shutdown::Both => SD_BOTH,
        };
        // SAFETY: plain FFI call.
        cvt(unsafe { shutdown(self.sock(), how) })?;
        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with(buf, 0)
    }

    /// Reads what is waiting without taking it (`recv` with `MSG_PEEK`), as
    /// std's `UnixStream::peek` does on Unix.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_with(buf, MSG_PEEK)
    }

    fn recv_with(&self, buf: &mut [u8], flags: i32) -> io::Result<usize> {
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: the buffer is valid for `len` bytes.
        match cvt(unsafe { recv(self.sock(), buf.as_mut_ptr(), len, flags) }) {
            Ok(n) => Ok(usize::try_from(n).unwrap()),
            // After `shutdown(Read)` Linux's recv reads the end; Winsock's
            // fails with WSAESHUTDOWN.
            Err(e) if e.raw_os_error() == Some(WSAESHUTDOWN) => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: the buffer is valid for `len` bytes.
        let n = cvt(unsafe { send(self.sock(), buf.as_ptr(), len, 0) })
            .inspect_err(|e| {
                // WSAESHUTDOWN, WSAECONNRESET, WSAECONNABORTED: the peer is gone.
                if matches!(e.raw_os_error(), Some(WSAESHUTDOWN | 10054 | 10053)) {
                    broken_pipe();
                }
            })
            // A send after `shutdown(Write)` is Linux's EPIPE.
            .map_err(|e| if e.raw_os_error() == Some(WSAESHUTDOWN) { io::Error::from_raw_os_error(EPIPE) } else { e })?;
        Ok(usize::try_from(n).unwrap())
    }
}

impl Read for UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&*self).read_vectored(bufs)
    }
}

impl Read for &UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match bufs.iter_mut().find(|b| !b.is_empty()) {
            Some(b) => self.recv(b),
            None => Ok(0),
        }
    }
}

impl Write for UnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&*self).write_vectored(bufs)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &UnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match bufs.iter().find(|b| !b.is_empty()) {
            Some(b) => self.send(b),
            None => Ok(0),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A Unix domain socket listening for connections.
pub struct UnixListener(OwnedFd);

impl fmt::Debug for UnixListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixListener").field("fd", &self.0.as_raw_fd()).finish()
    }
}

impl UnixListener {
    fn sock(&self) -> SOCKET {
        raw(&self.0)
    }

    /// Binds a socket to `path` and listens on it.
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<UnixListener> {
        let addr = SocketAddr::from_path(path.as_ref())?;
        let fd = new_socket()?;
        // SAFETY: the address and its length are valid.
        cvt(unsafe { bind(raw(&fd), (&raw const addr.addr).cast(), addr.len) })?;
        // SAFETY: plain FFI call; std uses the same backlog.
        cvt(unsafe { listen(raw(&fd), 128) })?;
        Ok(UnixListener(fd))
    }

    /// Accepts a connection.
    pub fn accept(&self) -> io::Result<(UnixStream, SocketAddr)> {
        // SAFETY: an all-zero `SOCKADDR_UN` is valid.
        let mut addr: SOCKADDR_UN = unsafe { mem::zeroed() };
        let mut len = i32::try_from(mem::size_of::<SOCKADDR_UN>()).unwrap();
        // SAFETY: the buffer and its length are valid.
        let s = unsafe { accept(self.sock(), (&raw mut addr).cast(), &mut len) };
        if s == INVALID_SOCKET {
            return Err(last_error());
        }
        // SAFETY: a new socket owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(socket_fd(s)?) };
        Ok((UnixStream(fd), SocketAddr { addr, len }))
    }

    /// The incoming connections.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// A new socket for the same listener.
    pub fn try_clone(&self) -> io::Result<UnixListener> {
        self.0.try_clone().map(UnixListener)
    }

    /// The bound address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        SocketAddr::query(self.sock(), getsockname)
    }

    /// Non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        set_nonblocking(self.sock(), nonblocking)
    }

    /// `SO_ERROR`.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        take_error(self.sock())
    }
}

/// The iterator of [`UnixListener::incoming`].
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a UnixListener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<UnixStream>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept().map(|(s, _)| s))
    }
}

impl<'a> IntoIterator for &'a UnixListener {
    type Item = io::Result<UnixStream>;
    type IntoIter = Incoming<'a>;
    fn into_iter(self) -> Incoming<'a> {
        self.incoming()
    }
}

macro_rules! fd_type {
    ($($t:ident),*) => {$(
        impl AsRawFd for $t {
            fn as_raw_fd(&self) -> RawFd {
                self.0.as_raw_fd()
            }
        }
        impl AsFd for $t {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.0.as_fd()
            }
        }
        impl FromRawFd for $t {
            unsafe fn from_raw_fd(fd: RawFd) -> Self {
                startup();
                // SAFETY: the caller's contract.
                $t(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        }
        impl IntoRawFd for $t {
            fn into_raw_fd(self) -> RawFd {
                self.0.into_raw_fd()
            }
        }
        impl From<$t> for OwnedFd {
            fn from(s: $t) -> OwnedFd {
                s.0
            }
        }
        impl From<OwnedFd> for $t {
            fn from(fd: OwnedFd) -> $t {
                startup();
                $t(fd)
            }
        }
    )*};
}
fd_type!(UnixStream, UnixListener);

