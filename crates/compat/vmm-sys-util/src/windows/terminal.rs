// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `terminal` for Windows: the same trait on console input modes.
//!
//! - canonical mode: line input, echo and Ctrl+C processing (`ICANON`,
//!   `ECHO`, `ISIG`), and keys as the console's own editing sees them;
//! - raw mode: none of those, and virtual terminal input, so keys read as the
//!   bytes a Unix terminal would send (arrow keys as escape sequences).
//!
//! A handle that is not a console is left alone and the mode calls succeed,
//! as the original does for a descriptor that is not a TTY.
//!
//! `set_non_block` sets `O_NONBLOCK` with the compatibility `fcntl`, as the
//! original does: pipes become non-blocking; consoles have no non-blocking
//! mode, and their readiness comes from [`crate::epoll`].

use std::io::StdinLock;

use wick_os::fd::{RawFd, from_handle, handle};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};

use crate::errno::{Error, Result};

fn modify_mode<F: FnOnce(CONSOLE_MODE) -> CONSOLE_MODE>(fd: RawFd, f: F) -> Result<()> {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: queries a console handle; fails on anything else.
    if unsafe { GetConsoleMode(handle(fd), &mut mode) } == 0 {
        // Not a console (a pipe, a file, NUL): nothing to change, as the
        // original returns `Ok` when `isatty` is false.
        return Ok(());
    }
    let new = f(mode);
    // SAFETY: as above.
    if new != mode && unsafe { SetConsoleMode(handle(fd), new) } == 0 {
        return Err(Error::last());
    }
    Ok(())
}

/// Trait for a console input that can be set into raw and canonical modes.
///
/// # Safety
///
/// [`Terminal::tty_fd`] must return a console handle that lives as long as
/// the object.
pub unsafe trait Terminal {
    /// Gets the console handle.
    fn tty_fd(&self) -> RawFd;

    /// Sets the console to canonical mode.
    fn set_canon_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |m| {
            (m | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
                & !ENABLE_VIRTUAL_TERMINAL_INPUT
        })
    }

    /// Sets the console to raw mode.
    fn set_raw_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), |m| {
            (m & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT
        })
    }

    /// Sets `O_NONBLOCK` as the original does, with the compatibility
    /// `fcntl`: a pipe becomes non-blocking (`PIPE_NOWAIT`), and a read with
    /// nothing to read fails with `EAGAIN`; on a console the flag is kept but
    /// a console read still waits for input (consoles have no non-blocking
    /// mode; readiness comes from [`crate::epoll`]).
    fn set_non_block(&self, non_block: bool) -> Result<()> {
        let fd = self.tty_fd();
        // SAFETY: plain calls on the caller's descriptor.
        let old = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if old < 0 {
            return Err(Error::last());
        }
        let new = if non_block {
            old | libc::O_NONBLOCK
        } else {
            old & !libc::O_NONBLOCK
        };
        // SAFETY: as above.
        if new != old && unsafe { libc::fcntl(fd, libc::F_SETFL, new) } < 0 {
            return Err(Error::last());
        }
        Ok(())
    }

    /// Reads up to `out.len()` bytes, with the compatibility `read`
    /// (`EAGAIN` from a non-blocking pipe with nothing to read).
    fn read_raw(&self, out: &mut [u8]) -> Result<usize> {
        // SAFETY: the buffer is valid for `out.len()` bytes.
        let n = unsafe { libc::read(self.tty_fd(), out.as_mut_ptr().cast(), out.len()) };
        if n < 0 {
            return Err(Error::last());
        }
        Ok(n.unsigned_abs())
    }
}

// SAFETY: the standard input handle lives as long as the process.
unsafe impl Terminal for StdinLock<'_> {
    fn tty_fd(&self) -> RawFd {
        // SAFETY: plain call.
        from_handle(unsafe { GetStdHandle(STD_INPUT_HANDLE) })
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::RawHandle;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Pipes::CreatePipe;

    use super::*;

    struct Fd(RawFd);

    // SAFETY: the tests keep the handle open while it is used.
    unsafe impl Terminal for Fd {
        fn tty_fd(&self) -> RawFd {
            self.0
        }
    }

    #[test]
    fn test_not_a_console_is_left_alone() {
        // A pipe, as a standard input redirected by another process.
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out-pointers to handles.
        assert_ne!(unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 0) }, 0);
        let pipe = Fd(from_handle(r as RawHandle));
        pipe.set_raw_mode().unwrap();
        pipe.set_canon_mode().unwrap();
        // Non-blocking, as Firecracker sets its standard input before the
        // vCPUs start: nothing to read is EAGAIN, data reads.
        pipe.set_non_block(true).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(pipe.read_raw(&mut buf).unwrap_err().errno(), libc::EAGAIN);
        let mut n = 0u32;
        // SAFETY: writes from a valid buffer to the pipe created above.
        assert_ne!(
            unsafe {
                windows_sys::Win32::Storage::FileSystem::WriteFile(w, b"hi".as_ptr(), 2, &mut n, std::ptr::null_mut())
            },
            0
        );
        assert_eq!(pipe.read_raw(&mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"hi");
        pipe.set_non_block(false).unwrap();
        // SAFETY: closes the handles the test created.
        unsafe {
            CloseHandle(r);
            CloseHandle(w);
        }

        // A regular file.
        let file = crate::tempfile::TempFile::new().unwrap();
        let file = Fd(from_handle(std::os::windows::io::AsRawHandle::as_raw_handle(file.as_file())));
        file.set_raw_mode().unwrap();
        file.set_canon_mode().unwrap();
    }
}
