// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Socket options on Windows, with the Linux interface: descriptors, Linux
//! option numbers and Linux values (`SO_DOMAIN` answers `AF_INET6` as 10).
//! Each option is translated to its Winsock one; options with no Winsock
//! equivalent fail with `ENOPROTOOPT`, as Linux does for unknown ones.

use windows_sys::Win32::Networking::WinSock::{
    self as ws, SOCKADDR_STORAGE, SOCKET_ERROR, WSAGetLastError, getsockname,
};

use crate::windows_fd::{wick_wsa_startup as startup, handle, set_errno};
use crate::{c_int, c_void};

/// Socket address and option lengths.
#[allow(non_camel_case_types)]
pub type socklen_t = u32;

/// Unspecified family.
pub const AF_UNSPEC: c_int = 0;
/// Unix domain sockets.
pub const AF_UNIX: c_int = 1;
/// IPv4.
pub const AF_INET: c_int = 2;
/// IPv6 (Linux value).
pub const AF_INET6: c_int = 10;
/// Stream sockets.
pub const SOCK_STREAM: c_int = 1;
/// Datagram sockets.
pub const SOCK_DGRAM: c_int = 2;
/// Sequenced packet sockets.
pub const SOCK_SEQPACKET: c_int = 5;
/// Socket-level options.
pub const SOL_SOCKET: c_int = 1;
/// Address reuse.
pub const SO_REUSEADDR: c_int = 2;
/// The socket type.
pub const SO_TYPE: c_int = 3;
/// The pending error, cleared.
pub const SO_ERROR: c_int = 4;
/// Send buffer size.
pub const SO_SNDBUF: c_int = 7;
/// Receive buffer size.
pub const SO_RCVBUF: c_int = 8;
/// Keep-alive.
pub const SO_KEEPALIVE: c_int = 9;
/// The address family.
pub const SO_DOMAIN: c_int = 39;
/// The credentials of the peer of an `AF_UNIX` socket ([`ucred`]).
pub const SO_PEERCRED: c_int = 17;

/// `struct ucred`: the peer's process id; Windows has no user and group
/// ids, reported as 0.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ucred {
    /// Process id.
    pub pid: crate::pid_t,
    /// User id.
    pub uid: crate::uid_t,
    /// Group id.
    pub gid: crate::gid_t,
}

/// `SO_PEERCRED`, from `SIO_AF_UNIX_GETPEERPID`.
unsafe fn peer_cred(fd: c_int, value: *mut c_void, len: *mut socklen_t) -> c_int {
    let size = socklen_t::try_from(std::mem::size_of::<ucred>()).unwrap();
    // SAFETY: the caller's contract.
    if value.is_null() || len.is_null() || unsafe { *len } < size {
        set_errno(crate::EINVAL);
        return -1;
    }
    let (mut pid, mut n) = (0u32, 0u32);
    // SAFETY: the output buffer is a `u32`.
    let rc = unsafe {
        ws::WSAIoctl(
            socket(fd),
            ws::SIO_AF_UNIX_GETPEERPID,
            std::ptr::null(),
            0,
            (&raw mut pid).cast(),
            4,
            &mut n,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        return wsa_fail();
    }
    let cred = ucred { pid: pid.cast_signed(), uid: 0, gid: 0 };
    // SAFETY: the caller's contract; checked above.
    unsafe {
        value.cast::<ucred>().write_unaligned(cred);
        *len = size;
    }
    0
}

/// `nfds_t` (Linux: 64 bits).
#[allow(non_camel_case_types)]
pub type nfds_t = u64;

/// `struct pollfd`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct pollfd {
    /// The descriptor; negative: ignored.
    pub fd: c_int,
    /// Requested events.
    pub events: crate::c_short,
    /// Returned events.
    pub revents: crate::c_short,
}

/// Readable.
pub const POLLIN: crate::c_short = 0x1;
/// Urgent data.
pub const POLLPRI: crate::c_short = 0x2;
/// Writable.
pub const POLLOUT: crate::c_short = 0x4;
/// Error.
pub const POLLERR: crate::c_short = 0x8;
/// Hang-up.
pub const POLLHUP: crate::c_short = 0x10;
/// Not an open descriptor (here: not a socket).
pub const POLLNVAL: crate::c_short = 0x20;

/// `poll`, over `WSAPoll`: sockets, with the Linux event bits. Windows can
/// wait for the readiness of sockets only; any other descriptor is reported
/// `POLLNVAL` (epoll serves the others, see `vmm-sys-util`).
///
/// # Safety
/// `fds` must be valid for `nfds` entries.
pub unsafe fn poll(fds: *mut pollfd, nfds: nfds_t, timeout: c_int) -> c_int {
    startup();
    let Ok(n) = usize::try_from(nfds) else {
        set_errno(crate::EINVAL);
        return -1;
    };
    // SAFETY: the caller's contract.
    let fds = unsafe { std::slice::from_raw_parts_mut(fds, n) };
    let mut ready = 0;
    let mut polled = std::vec::Vec::new();
    let mut at = std::vec::Vec::new();
    for (i, p) in fds.iter_mut().enumerate() {
        p.revents = 0;
        if p.fd < 0 {
            continue;
        }
        if !crate::windows_fd::is_socket(p.fd) {
            p.revents = POLLNVAL;
            ready += 1;
            continue;
        }
        let mut events = 0;
        if p.events & (POLLIN | POLLPRI) != 0 {
            events |= ws::POLLRDNORM;
        }
        if p.events & POLLOUT != 0 {
            events |= ws::POLLWRNORM;
        }
        polled.push(ws::WSAPOLLFD { fd: socket(p.fd), events, revents: 0 });
        at.push(i);
    }
    let wait = if ready > 0 { 0 } else { timeout };
    if polled.is_empty() {
        if wait != 0 {
            let ms = if wait < 0 { u32::MAX } else { wait.cast_unsigned() };
            // SAFETY: plain call.
            unsafe { windows_sys::Win32::System::Threading::Sleep(ms) };
        }
        return ready;
    }
    // SAFETY: a valid array.
    let rc = unsafe { ws::WSAPoll(polled.as_mut_ptr(), u32::try_from(polled.len()).unwrap(), wait) };
    if rc == SOCKET_ERROR {
        return wsa_fail();
    }
    for (w, &i) in polled.iter().zip(&at) {
        let mut r = 0;
        if w.revents & (ws::POLLRDNORM | ws::POLLRDBAND) != 0 {
            r |= POLLIN;
        }
        if w.revents & ws::POLLWRNORM != 0 {
            r |= POLLOUT;
        }
        if w.revents & ws::POLLERR != 0 {
            r |= POLLERR;
        }
        if w.revents & ws::POLLHUP != 0 {
            r |= POLLHUP;
        }
        if w.revents & ws::POLLNVAL != 0 {
            r |= POLLNVAL;
        }
        fds[i].revents = r;
        if r != 0 {
            ready += 1;
        }
    }
    ready
}

fn winsock_option(name: c_int) -> Option<c_int> {
    Some(match name {
        SO_REUSEADDR => ws::SO_REUSEADDR,
        SO_TYPE => ws::SO_TYPE,
        SO_ERROR => ws::SO_ERROR,
        SO_SNDBUF => ws::SO_SNDBUF,
        SO_RCVBUF => ws::SO_RCVBUF,
        SO_KEEPALIVE => ws::SO_KEEPALIVE,
        _ => return None,
    })
}

fn linux_family(family: u16) -> c_int {
    match family {
        ws::AF_UNIX => AF_UNIX,
        ws::AF_INET => AF_INET,
        ws::AF_INET6 => AF_INET6,
        other => c_int::from(other),
    }
}

fn socket(fd: c_int) -> usize {
    handle(fd) as usize
}

fn wsa_fail() -> c_int {
    // SAFETY: plain call.
    set_errno(unsafe { WSAGetLastError() });
    -1
}

/// `getsockopt`.
///
/// # Safety
/// `value` must be valid for `*len` bytes of writes, and `len` for a read
/// and a write.
pub unsafe fn getsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    value: *mut c_void,
    len: *mut socklen_t,
) -> c_int {
    startup();
    if level != SOL_SOCKET {
        set_errno(crate::ENOPROTOOPT);
        return -1;
    }
    if name == SO_PEERCRED {
        // SAFETY: the caller's contract.
        return unsafe { peer_cred(fd, value, len) };
    }
    // SAFETY: the caller's contract.
    if value.is_null() || len.is_null() || unsafe { *len } < 4 {
        set_errno(crate::EINVAL);
        return -1;
    }
    let v: c_int = if name == SO_DOMAIN {
        // SAFETY: an all-zero SOCKADDR_STORAGE is a valid output buffer.
        let mut addr: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
        let mut n = c_int::try_from(std::mem::size_of_val(&addr)).unwrap();
        // SAFETY: valid output buffers.
        if unsafe { getsockname(socket(fd), (&raw mut addr).cast(), &mut n) } == SOCKET_ERROR {
            return wsa_fail();
        }
        linux_family(addr.ss_family)
    } else {
        let Some(opt) = winsock_option(name) else {
            set_errno(crate::ENOPROTOOPT);
            return -1;
        };
        let (mut v, mut n): (c_int, c_int) = (0, 4);
        // SAFETY: the option value is an `int`.
        if unsafe { ws::getsockopt(socket(fd), ws::SOL_SOCKET, opt, (&raw mut v).cast(), &mut n) }
            == SOCKET_ERROR
        {
            return wsa_fail();
        }
        v
    };
    // SAFETY: the caller's contract; at least 4 bytes, checked above.
    unsafe {
        value.cast::<c_int>().write_unaligned(v);
        *len = 4;
    }
    0
}

/// `setsockopt`.
///
/// # Safety
/// `value` must be valid for `len` bytes of reads.
pub unsafe fn setsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    value: *const c_void,
    len: socklen_t,
) -> c_int {
    startup();
    if level != SOL_SOCKET {
        set_errno(crate::ENOPROTOOPT);
        return -1;
    }
    let Some(opt) = winsock_option(name).filter(|_| name != SO_TYPE && name != SO_ERROR) else {
        set_errno(crate::ENOPROTOOPT);
        return -1;
    };
    let Ok(n) = c_int::try_from(len) else {
        set_errno(crate::EINVAL);
        return -1;
    };
    // SAFETY: the caller's contract.
    if unsafe { ws::setsockopt(socket(fd), ws::SOL_SOCKET, opt, value.cast(), n) } == SOCKET_ERROR {
        return wsa_fail();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::cast_possible_truncation)]
    fn fd_of(s: &impl std::os::windows::io::AsRawSocket) -> c_int {
        s.as_raw_socket() as u32 as c_int
    }

    #[test]
    fn test_poll_sockets() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut a = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (b, _) = listener.accept().unwrap();
        let mut fds = [
            pollfd { fd: fd_of(&b), events: POLLIN, revents: 0 },
            pollfd { fd: -1, events: POLLIN, revents: 7 },
        ];
        // Nothing to read yet.
        // SAFETY: a valid array.
        assert_eq!(unsafe { poll(fds.as_mut_ptr(), 2, 0) }, 0);
        assert_eq!(fds[1].revents, 0, "negative descriptors are ignored");
        a.write_all(b"x").unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { poll(fds.as_mut_ptr(), 2, 5000) }, 1);
        assert_eq!(fds[0].revents & POLLIN, POLLIN);
        // Writable.
        let mut w = [pollfd { fd: fd_of(&a), events: POLLOUT, revents: 0 }];
        // SAFETY: as above.
        assert_eq!(unsafe { poll(w.as_mut_ptr(), 1, 0) }, 1);
        assert_eq!(w[0].revents, POLLOUT);
        // A peer that closed: hang-up or readable at end of file.
        drop(a);
        // SAFETY: as above.
        assert_eq!(unsafe { poll(fds.as_mut_ptr(), 1, 5000) }, 1);
        assert_ne!(fds[0].revents & (POLLIN | POLLHUP), 0);
        // A file is not pollable.
        let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let mut nv = [pollfd {
            fd: crate::windows_fd::to_fd_pub(std::os::windows::io::AsRawHandle::as_raw_handle(&f)),
            events: POLLIN,
            revents: 0,
        }];
        // SAFETY: as above.
        assert_eq!(unsafe { poll(nv.as_mut_ptr(), 1, -1) }, 1);
        assert_eq!(nv[0].revents, POLLNVAL);
    }

    #[test]
    fn test_kill() {
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        let pid = crate::pid_t::try_from(child.id()).unwrap();
        // SAFETY: plain calls.
        unsafe {
            assert_eq!(crate::kill(pid, 0), 0);
            assert_eq!(crate::kill(pid, crate::SIGUSR1), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EINVAL));
            assert_eq!(crate::kill(pid, crate::SIGKILL), 0);
        }
        assert_eq!(child.wait().unwrap().code(), Some(137));
    }

    #[test]
    fn test_options_have_linux_numbers_and_values() {
        use std::os::windows::io::AsRawSocket;
        let l = std::net::TcpListener::bind("[::1]:0").unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let fd = l.as_raw_socket() as c_int;
        let (mut v, mut n): (c_int, socklen_t) = (0, 4);
        // SAFETY: valid buffers.
        unsafe {
            assert_eq!(
                getsockopt(fd, SOL_SOCKET, SO_DOMAIN, (&raw mut v).cast(), &mut n),
                0
            );
            assert_eq!(v, AF_INET6);
            assert_eq!(
                getsockopt(fd, SOL_SOCKET, SO_TYPE, (&raw mut v).cast(), &mut n),
                0
            );
            assert_eq!(v, SOCK_STREAM);
            assert_eq!(
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (&raw mut v).cast(), &mut n),
                0
            );
            assert_eq!(v, 0);
            assert_eq!(
                getsockopt(fd, SOL_SOCKET, 999, (&raw mut v).cast(), &mut n),
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(crate::ENOPROTOOPT)
            );
            let one: c_int = 1;
            assert_eq!(
                setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (&raw const one).cast(), 4),
                0
            );
        }
    }
}
