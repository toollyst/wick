// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `terminal` for Windows: the same trait on console input modes.
//!
//! - canonical mode: line input, echo and Ctrl+C processing (`ICANON`,
//!   `ECHO`, `ISIG`), and keys as the console's own editing sees them;
//! - raw mode: none of those, and virtual terminal input, so keys read as the
//!   bytes a Unix terminal would send (arrow keys as escape sequences).
//!
//! Console handles have no non-blocking mode; `set_non_block(true)` fails
//! with `ERROR_NOT_SUPPORTED`. Readiness comes from [`crate::epoll`].

use std::io::StdinLock;

use wick_os::fd::{RawFd, from_handle, handle};
use windows_sys::Win32::Foundation::ERROR_NOT_SUPPORTED;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};

use crate::errno::{Error, Result};

fn modify_mode<F: FnOnce(CONSOLE_MODE) -> CONSOLE_MODE>(fd: RawFd, f: F) -> Result<()> {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: queries a console handle; fails on anything else.
    if unsafe { GetConsoleMode(handle(fd), &mut mode) } == 0 {
        return Err(Error::last());
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

    /// Sets the console to blocking (`false`) mode; non-blocking does not
    /// exist for consoles.
    #[allow(clippy::cast_possible_wrap)]
    fn set_non_block(&self, non_block: bool) -> Result<()> {
        if non_block {
            return Err(Error::new(ERROR_NOT_SUPPORTED as i32));
        }
        Ok(())
    }

    /// Reads up to `out.len()` bytes from the console.
    fn read_raw(&self, out: &mut [u8]) -> Result<usize> {
        let mut n = 0u32;
        let len = u32::try_from(out.len()).unwrap_or(u32::MAX);
        // SAFETY: the buffer is valid for `len` bytes.
        let ok = unsafe {
            ReadFile(handle(self.tty_fd()), out.as_mut_ptr(), len, &mut n, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(Error::last());
        }
        Ok(n as usize)
    }
}

// SAFETY: the standard input handle lives as long as the process.
unsafe impl Terminal for StdinLock<'_> {
    fn tty_fd(&self) -> RawFd {
        // SAFETY: plain call.
        from_handle(unsafe { GetStdHandle(STD_INPUT_HANDLE) })
    }
}
