// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! Errors in the Windows error space, which is what `io::Error` and
//! `vmm_sys_util::errno` use on Windows.

use std::io;

use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};
use windows_sys::Win32::Networking::WinSock::WSAEWOULDBLOCK;

/// `EINVAL`.
pub(crate) fn einval() -> io::Error {
    io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32)
}

/// `EAGAIN`.
pub(crate) fn ewouldblock() -> io::Error {
    io::Error::from_raw_os_error(WSAEWOULDBLOCK)
}

/// `EBADF`.
#[allow(dead_code)]
pub(crate) fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32)
}
