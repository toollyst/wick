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
