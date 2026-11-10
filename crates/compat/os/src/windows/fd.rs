// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `std::os::fd` on Windows. A descriptor is the value of a kernel handle:
//! a `HANDLE` (files, pipes, events, consoles, processes) or a `SOCKET`.
//! Windows guarantees handle values fit in 32 bits, and conversions back
//! sign-extend, so `-1` is `INVALID_HANDLE_VALUE` and `INVALID_SOCKET`.

use std::fmt;
use std::fs::File;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::os::windows::io::{
    AsRawHandle, AsRawSocket, FromRawHandle, FromRawSocket, IntoRawHandle, IntoRawSocket,
    RawHandle,
};

use windows_sys::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows_sys::Win32::Networking::WinSock::{
    FROM_PROTOCOL_INFO, INVALID_SOCKET, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
    WSADuplicateSocketW, WSAENOTSOCK, WSAGetLastError, WSAPROTOCOL_INFOW, WSASocketW, closesocket,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId};

/// A file descriptor: a handle value.
pub type RawFd = i32;

// The conversions below are where handle values become descriptors and
// back. They cannot lose bits: Windows keeps handle and socket values in 32
// bits (sign-extended), so 64-bit values convert to `i32` and back exactly.

/// The handle a descriptor names. `0`, `1` and `2` (`STDIN_FILENO`,
/// `STDOUT_FILENO`, `STDERR_FILENO`) name this process's standard handles,
/// as in the compatibility libc: no kernel handle has those values (handles
/// are multiples of 4 and 0 is `NULL`), so the mapping is unambiguous.
#[allow(clippy::as_conversions)]
pub fn handle(fd: RawFd) -> HANDLE {
    let std = match fd {
        0 => STD_INPUT_HANDLE,
        1 => STD_OUTPUT_HANDLE,
        2 => STD_ERROR_HANDLE,
        _ => return fd as isize as HANDLE,
    };
    // SAFETY: plain call.
    unsafe { GetStdHandle(std) }
}

/// The descriptor of a handle.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
pub fn from_handle(h: RawHandle) -> RawFd {
    h as isize as RawFd
}

/// The socket a descriptor names.
#[allow(clippy::as_conversions, clippy::cast_sign_loss)]
pub fn socket(fd: RawFd) -> usize {
    fd as isize as usize
}

/// The descriptor of a socket.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
pub fn from_socket(s: usize) -> RawFd {
    s as isize as RawFd
}

/// Closes a descriptor: a socket with `closesocket`, any other handle with
/// `CloseHandle`. Returns whether it was closed.
pub fn close(fd: RawFd) -> bool {
    super::net::startup();
    // SAFETY: closes the caller's descriptor.
    unsafe {
        if closesocket(socket(fd)) == 0 {
            return true;
        }
        if WSAGetLastError() != WSAENOTSOCK {
            return false;
        }
        CloseHandle(handle(fd)) != 0
    }
}

/// Duplicates a descriptor in this process (`dup`). Sockets are duplicated
/// through Winsock, as Microsoft requires; other handles with
/// `DuplicateHandle`.
pub fn dup(fd: RawFd) -> std::io::Result<RawFd> {
    super::net::startup();
    // SAFETY: an all-zero `WSAPROTOCOL_INFOW` is valid.
    let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
    // SAFETY: duplicates a socket of this process into this process.
    if unsafe { WSADuplicateSocketW(socket(fd), GetCurrentProcessId(), &mut info) } == 0 {
        // SAFETY: plain FFI call with the protocol info from above.
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
            // SAFETY: reads the thread's last Winsock error.
            return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
        return Ok(from_socket(s));
    }
    // SAFETY: reads the thread's last Winsock error.
    if unsafe { WSAGetLastError() } != WSAENOTSOCK {
        // SAFETY: as above.
        return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process into this process.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle(fd),
            GetCurrentProcess(),
            &mut out,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(from_handle(out))
}

/// `AsRawFd`.
pub trait AsRawFd {
    /// The descriptor.
    fn as_raw_fd(&self) -> RawFd;
}

/// `FromRawFd`.
pub trait FromRawFd {
    /// Takes ownership of `fd`.
    ///
    /// # Safety
    /// `fd` must be an open descriptor owned by the caller.
    unsafe fn from_raw_fd(fd: RawFd) -> Self;
}

/// `IntoRawFd`.
pub trait IntoRawFd {
    /// Gives up ownership of the descriptor.
    fn into_raw_fd(self) -> RawFd;
}

impl AsRawFd for RawFd {
    fn as_raw_fd(&self) -> RawFd {
        *self
    }
}

/// An owned descriptor, closed on drop.
#[repr(transparent)]
pub struct OwnedFd {
    fd: RawFd,
}

impl fmt::Debug for OwnedFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedFd").field("fd", &self.fd).finish()
    }
}

impl OwnedFd {
    /// A new descriptor for the same object.
    pub fn try_clone(&self) -> std::io::Result<OwnedFd> {
        Ok(OwnedFd { fd: dup(self.fd)? })
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        close(self.fd);
    }
}

impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl FromRawFd for OwnedFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        OwnedFd { fd }
    }
}

impl IntoRawFd for OwnedFd {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

/// A borrowed descriptor.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct BorrowedFd<'a> {
    fd: RawFd,
    _life: PhantomData<&'a OwnedFd>,
}

impl fmt::Debug for BorrowedFd<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedFd").field("fd", &self.fd).finish()
    }
}

impl BorrowedFd<'_> {
    /// Borrows `fd`.
    ///
    /// # Safety
    /// `fd` must stay open for the borrow's lifetime.
    pub const unsafe fn borrow_raw(fd: RawFd) -> Self {
        BorrowedFd {
            fd,
            _life: PhantomData,
        }
    }

    /// A new owned descriptor for the same object.
    pub fn try_clone_to_owned(&self) -> std::io::Result<OwnedFd> {
        Ok(OwnedFd { fd: dup(self.fd)? })
    }
}

impl AsRawFd for BorrowedFd<'_> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// `AsFd`.
pub trait AsFd {
    /// Borrows the descriptor.
    fn as_fd(&self) -> BorrowedFd<'_>;
}

impl AsFd for OwnedFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: lives as long as `self`.
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl AsFd for BorrowedFd<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        *self
    }
}

impl<T: AsFd + ?Sized> AsFd for &T {
    fn as_fd(&self) -> BorrowedFd<'_> {
        T::as_fd(self)
    }
}

impl<T: AsFd + ?Sized> AsFd for &mut T {
    fn as_fd(&self) -> BorrowedFd<'_> {
        T::as_fd(self)
    }
}

// Smart pointers, as std provides them.
macro_rules! pointer_type {
    ($($p:ident),*) => {$(
        impl<T: AsRawFd + ?Sized> AsRawFd for $p<T> {
            fn as_raw_fd(&self) -> RawFd {
                (**self).as_raw_fd()
            }
        }
        impl<T: AsFd + ?Sized> AsFd for $p<T> {
            fn as_fd(&self) -> BorrowedFd<'_> {
                (**self).as_fd()
            }
        }
    )*};
}
pointer_type!(Arc, Box, Rc);

impl From<File> for OwnedFd {
    fn from(f: File) -> OwnedFd {
        OwnedFd {
            fd: from_handle(f.into_raw_handle()),
        }
    }
}

impl From<OwnedFd> for File {
    fn from(fd: OwnedFd) -> File {
        // SAFETY: the descriptor is an owned handle.
        unsafe { File::from_raw_handle(handle(fd.into_raw_fd())) }
    }
}

macro_rules! handle_type {
    ($($t:ty),*) => {$(
        impl AsRawFd for $t {
            fn as_raw_fd(&self) -> RawFd {
                from_handle(self.as_raw_handle())
            }
        }
        impl AsFd for $t {
            fn as_fd(&self) -> BorrowedFd<'_> {
                // SAFETY: lives as long as `self`.
                unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
            }
        }
    )*};
}
handle_type!(
    File,
    std::io::Stdin,
    std::io::Stdout,
    std::io::Stderr,
    std::io::StdinLock<'_>,
    std::io::StdoutLock<'_>,
    std::io::StderrLock<'_>,
    std::process::ChildStdin,
    std::process::ChildStdout,
    std::process::ChildStderr
);

impl FromRawFd for File {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY: the caller's contract.
        unsafe { File::from_raw_handle(handle(fd)) }
    }
}

impl IntoRawFd for File {
    fn into_raw_fd(self) -> RawFd {
        from_handle(self.into_raw_handle())
    }
}

macro_rules! socket_type {
    ($($t:ty),*) => {$(
        impl AsRawFd for $t {
            fn as_raw_fd(&self) -> RawFd {
                from_socket(usize::try_from(self.as_raw_socket()).unwrap())
            }
        }
        impl AsFd for $t {
            fn as_fd(&self) -> BorrowedFd<'_> {
                // SAFETY: lives as long as `self`.
                unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
            }
        }
        impl FromRawFd for $t {
            unsafe fn from_raw_fd(fd: RawFd) -> Self {
                // SAFETY: the caller's contract.
                unsafe { <$t>::from_raw_socket(socket(fd) as u64) }
            }
        }
        impl IntoRawFd for $t {
            fn into_raw_fd(self) -> RawFd {
                from_socket(usize::try_from(self.into_raw_socket()).unwrap())
            }
        }
    )*};
}
socket_type!(std::net::TcpStream, std::net::TcpListener, std::net::UdpSocket);
