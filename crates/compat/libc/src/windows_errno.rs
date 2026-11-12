// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `errno` values on Windows.
//!
//! The POSIX layer of wick reports errors as Windows does, through
//! `GetLastError` (`std::io::Error::last_os_error`, `vmm_sys_util::errno`),
//! so each `E*` constant is the Win32 or Winsock code with the same meaning,
//! chosen so that `io::Error::from_raw_os_error(libc::EX).kind()` is the kind
//! Linux gives where Windows has that kind (it has no `Interrupted`: nothing
//! in the layer is interrupted, as signals do not interrupt Windows calls).
//! The CRT's own values (`EINVAL` = 22, ...) are not used: no
//! CRT function is called on wick descriptors.

use crate::c_int;

macro_rules! errnos {
    ($($(#[$doc:meta])* $name:ident = $value:expr;)*) => {
        $($(#[$doc])* pub const $name: c_int = $value;)*
    };
}

errnos! {
    /// `WSAEACCES`: permission denied, distinct from `EACCES`.
    EPERM = 10013;
    /// `ERROR_FILE_NOT_FOUND`.
    ENOENT = 2;
    /// `ERROR_INVALID_THREAD_ID`.
    ESRCH = 1444;
    /// `WSAEINTR`.
    EINTR = 10004;
    /// `ERROR_IO_DEVICE`.
    EIO = 1117;
    /// `ERROR_NOT_READY`.
    ENXIO = 21;
    /// `ERROR_BAD_LENGTH`.
    E2BIG = 24;
    /// `ERROR_BAD_EXE_FORMAT`.
    ENOEXEC = 193;
    /// `ERROR_INVALID_HANDLE`.
    EBADF = 6;
    /// `ERROR_WAIT_NO_CHILDREN`.
    ECHILD = 128;
    /// `WSAEWOULDBLOCK`.
    EAGAIN = 10035;
    /// `WSAEWOULDBLOCK`, as `EAGAIN` on Linux.
    EWOULDBLOCK = 10035;
    /// `ERROR_NOT_ENOUGH_MEMORY`.
    ENOMEM = 8;
    /// `ERROR_ACCESS_DENIED`.
    EACCES = 5;
    /// `ERROR_NOACCESS`.
    EFAULT = 998;
    /// `ERROR_BUSY`.
    EBUSY = 170;
    /// `ERROR_ALREADY_EXISTS`.
    EEXIST = 183;
    /// `ERROR_NOT_SAME_DEVICE`.
    EXDEV = 17;
    /// `ERROR_DEV_NOT_EXIST`.
    ENODEV = 55;
    /// `ERROR_DIRECTORY`.
    ENOTDIR = 267;
    /// `ERROR_DIRECTORY_NOT_SUPPORTED`.
    EISDIR = 336;
    /// `ERROR_INVALID_PARAMETER`.
    EINVAL = 87;
    /// `ERROR_TOO_MANY_OPEN_FILES`.
    ENFILE = 4;
    /// `WSAEMFILE`.
    EMFILE = 10024;
    /// `ERROR_INVALID_FUNCTION`: the descriptor does not support the request.
    ENOTTY = 1;
    /// `ERROR_FILE_TOO_LARGE`.
    EFBIG = 223;
    /// `ERROR_DISK_FULL`.
    ENOSPC = 112;
    /// `ERROR_SEEK_ON_DEVICE`.
    ESPIPE = 132;
    /// `ERROR_WRITE_PROTECT`.
    EROFS = 19;
    /// `ERROR_TOO_MANY_LINKS`.
    EMLINK = 1142;
    /// `ERROR_BROKEN_PIPE`.
    EPIPE = 109;
    /// `ERROR_ARITHMETIC_OVERFLOW`.
    ERANGE = 534;
    /// `ERROR_POSSIBLE_DEADLOCK`.
    EDEADLK = 1131;
    /// `ERROR_FILENAME_EXCED_RANGE`.
    ENAMETOOLONG = 206;
    /// `ERROR_CALL_NOT_IMPLEMENTED`.
    ENOSYS = 120;
    /// `ERROR_DIR_NOT_EMPTY`.
    ENOTEMPTY = 145;
    /// `ERROR_BUFFER_OVERFLOW`.
    EOVERFLOW = 111;
    /// `ERROR_OPERATION_ABORTED`.
    ECANCELED = 995;
    /// `ERROR_NOT_SUPPORTED`.
    EOPNOTSUPP = 50;
    /// `ERROR_NOT_SUPPORTED`, as `EOPNOTSUPP` on Linux.
    ENOTSUP = 50;
    /// `ERROR_INVALID_DATA`.
    EPROTO = 13;
    /// `WSAETIMEDOUT`.
    ETIMEDOUT = 10060;
    /// `WSAEADDRINUSE`.
    EADDRINUSE = 10048;
    /// `WSAEADDRNOTAVAIL`.
    EADDRNOTAVAIL = 10049;
    /// `WSAECONNREFUSED`.
    ECONNREFUSED = 10061;
    /// `WSAECONNRESET`.
    ECONNRESET = 10054;
    /// `WSAECONNABORTED`.
    ECONNABORTED = 10053;
    /// `WSAENOTCONN`.
    ENOTCONN = 10057;
    /// `WSAEISCONN`.
    EISCONN = 10056;
    /// `WSAENOBUFS`.
    ENOBUFS = 10055;
    /// `WSAEMSGSIZE`.
    EMSGSIZE = 10040;
    /// `WSAEINPROGRESS`.
    EINPROGRESS = 10036;
    /// `WSAEALREADY`.
    EALREADY = 10037;
    /// `WSAENOTSOCK`.
    ENOTSOCK = 10038;
    /// `WSAEAFNOSUPPORT`.
    EAFNOSUPPORT = 10047;
    /// `WSAENETUNREACH`.
    ENETUNREACH = 10051;
    /// `WSAEHOSTUNREACH`.
    EHOSTUNREACH = 10065;
    /// `WSAEPROTONOSUPPORT`.
    EPROTONOSUPPORT = 10043;
    /// `WSAENOPROTOOPT`.
    ENOPROTOOPT = 10042;
}

/// The `E*` constant of a Win32 or Winsock error code: the code itself when
/// it is one, else the constant of the same meaning for a code Windows uses
/// beside it (a synonym), so that what upstream code compares with
/// `libc::EX` matches whichever of them a Windows call gave. A code with no
/// Linux counterpart is kept as it is: it matches no `E*`, as an errno
/// Firecracker does not expect matches none of its arms.
pub fn wick_errno_from_win32(code: c_int) -> c_int {
    match code {
        // ERROR_PATH_NOT_FOUND, ERROR_INVALID_DRIVE, ERROR_BAD_NETPATH,
        // ERROR_BAD_NET_NAME, ERROR_BAD_PATHNAME, ERROR_MOD_NOT_FOUND,
        // ERROR_NOT_FOUND: no such file, directory or object.
        3 | 15 | 53 | 67 | 161 | 126 | 1168 => ENOENT,
        // ERROR_FILE_EXISTS (CreateFile's CREATE_NEW).
        80 => EEXIST,
        // ERROR_OUTOFMEMORY, ERROR_COMMITMENT_LIMIT.
        14 | 1455 => ENOMEM,
        // ERROR_HANDLE_DISK_FULL.
        39 => ENOSPC,
        // ERROR_NO_DATA: a pipe being closed at the other end.
        232 => EPIPE,
        // ERROR_SEM_TIMEOUT, WAIT_TIMEOUT, ERROR_TIMEOUT.
        121 | 258 | 1460 => ETIMEDOUT,
        // ERROR_PRIVILEGE_NOT_HELD: Linux's EPERM for a missing capability.
        1314 => EPERM,
        // ERROR_INVALID_FLAGS.
        1004 => EINVAL,
        // ERROR_INVALID_USER_BUFFER.
        1784 => EFAULT,
        // Winsock's codes for what Win32 codes name elsewhere: WSAEBADF,
        // WSAEFAULT, WSAEINVAL, WSAENAMETOOLONG, WSAENOTEMPTY.
        10009 => EBADF,
        10014 => EFAULT,
        10022 => EINVAL,
        10063 => ENAMETOOLONG,
        10066 => ENOTEMPTY,
        _ => code,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::*;

    // Every E* constant is its own value; each synonym gives the constant of
    // its meaning; an unknown code is kept.
    #[test]
    fn test_synonyms_give_the_constant() {
        for e in [ENOENT, EEXIST, ENOMEM, EINVAL, EBADF, EFAULT, EPIPE, ETIMEDOUT, EPERM, EACCES, EBUSY, EAGAIN, EINTR] {
            assert_eq!(wick_errno_from_win32(e), e);
        }
        for (code, e) in [
            (3, ENOENT), (15, ENOENT), (53, ENOENT), (67, ENOENT), (161, ENOENT), (126, ENOENT), (1168, ENOENT),
            (80, EEXIST), (14, ENOMEM), (1455, ENOMEM), (39, ENOSPC), (232, EPIPE),
            (121, ETIMEDOUT), (258, ETIMEDOUT), (1460, ETIMEDOUT), (1314, EPERM), (1004, EINVAL), (1784, EFAULT),
            (10009, EBADF), (10014, EFAULT), (10022, EINVAL), (10063, ENAMETOOLONG), (10066, ENOTEMPTY),
        ] {
            assert_eq!(wick_errno_from_win32(code), e, "code {code}");
        }
        assert_eq!(wick_errno_from_win32(0x1234), 0x1234);
    }

    #[test]
    fn test_kinds_match_linux() {
        let kind = |e: c_int| Error::from_raw_os_error(e).kind();
        assert_eq!(kind(EPERM), ErrorKind::PermissionDenied);
        assert_eq!(kind(EACCES), ErrorKind::PermissionDenied);
        assert_eq!(kind(ENOENT), ErrorKind::NotFound);
        assert_eq!(kind(EAGAIN), ErrorKind::WouldBlock);
        assert_eq!(kind(ENOMEM), ErrorKind::OutOfMemory);
        assert_eq!(kind(EEXIST), ErrorKind::AlreadyExists);
        assert_eq!(kind(EINVAL), ErrorKind::InvalidInput);
        assert_eq!(kind(EPIPE), ErrorKind::BrokenPipe);
        assert_eq!(kind(ENOSYS), ErrorKind::Unsupported);
        assert_eq!(kind(ETIMEDOUT), ErrorKind::TimedOut);
        assert_eq!(kind(ECONNRESET), ErrorKind::ConnectionReset);
        assert_eq!(kind(ECONNREFUSED), ErrorKind::ConnectionRefused);
        assert_eq!(kind(EADDRINUSE), ErrorKind::AddrInUse);
        assert_eq!(kind(ENOTCONN), ErrorKind::NotConnected);
        assert_eq!(kind(ENOSPC), ErrorKind::StorageFull);
        assert_eq!(kind(EFBIG), ErrorKind::FileTooLarge);
        assert_eq!(kind(ENOTEMPTY), ErrorKind::DirectoryNotEmpty);
        assert_eq!(kind(EBUSY), ErrorKind::ResourceBusy);
    }
}
