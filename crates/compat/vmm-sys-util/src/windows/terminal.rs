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
//! as the original does for a descriptor that is not a TTY. One exception: a
//! jailed Firecracker's standard input is a pipe the jailer relays the
//! console through (the jailer's `console` module), and the jailer gives it
//! the write end of a second pipe in [`MODE_ENV`]. Changing the standard
//! input's mode writes the request there (`r` for raw, `c` for canonical),
//! and the jailer sets its console to that mode. So the console turns raw
//! when Firecracker starts the microVM's vCPUs and canonical when it stops,
//! as a Linux terminal does under a jailed Firecracker.
//!
//! `set_non_block` sets `O_NONBLOCK` with the compatibility `fcntl`, as the
//! original does: pipes become non-blocking; consoles have no non-blocking
//! mode, and their readiness comes from [`crate::epoll`].

use std::io::StdinLock;
use std::sync::OnceLock;

use wick_os::fd::{RawFd, from_handle, handle};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
};

use crate::errno::{Error, Result};

/// The variable that names, as a handle value, the pipe to the jailer that
/// relays this process's standard input from its console (set by the
/// jailer for a jailed Firecracker only).
pub const MODE_ENV: &str = "WICK_CONSOLE_MODE";

/// The request byte for raw mode on [`MODE_ENV`]'s pipe.
pub const RAW_REQUEST: u8 = b'r';
/// The request byte for canonical mode.
pub const CANON_REQUEST: u8 = b'c';

/// [`MODE_ENV`]'s pipe, read once.
fn jailer_pipe() -> Option<HANDLE> {
    static PIPE: OnceLock<Option<usize>> = OnceLock::new();
    PIPE.get_or_init(|| std::env::var(MODE_ENV).ok()?.parse().ok())
        .map(|h| h as HANDLE)
}

/// Writes `request` to the jailer's pipe; an error if the jailer cannot be
/// told (it ended), as a refused `tcsetattr` is one.
fn tell_jailer(pipe: HANDLE, request: u8) -> Result<()> {
    let mut n = 0u32;
    // SAFETY: one byte from a valid buffer to the handle the jailer gave.
    if unsafe { WriteFile(pipe, &request, 1, &mut n, std::ptr::null_mut()) } == 0 || n != 1 {
        return Err(Error::last());
    }
    Ok(())
}

fn modify_mode<F: FnOnce(CONSOLE_MODE) -> CONSOLE_MODE>(fd: RawFd, request: u8, f: F) -> Result<()> {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: queries a console handle; fails on anything else.
    if unsafe { GetConsoleMode(handle(fd), &mut mode) } == 0 {
        // Not a console (a pipe, a file, NUL): nothing to change, as the
        // original returns `Ok` when `isatty` is false; unless it is the
        // standard input a jailer relays from its console.
        // SAFETY: plain call.
        let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        return match jailer_pipe() {
            Some(pipe) if handle(fd) == stdin => tell_jailer(pipe, request),
            _ => Ok(()),
        };
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
        modify_mode(self.tty_fd(), CANON_REQUEST, |m| {
            (m | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
                & !ENABLE_VIRTUAL_TERMINAL_INPUT
        })
    }

    /// Sets the console to raw mode.
    fn set_raw_mode(&self) -> Result<()> {
        modify_mode(self.tty_fd(), RAW_REQUEST, |m| {
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

    /// A jailed Firecracker, as `start_vcpus` and `Vmm::stop` change its
    /// standard input's mode (run by `test_a_jailed_stdin_tells_the_jailer`).
    #[test]
    #[ignore = "the child of test_a_jailed_stdin_tells_the_jailer"]
    fn jailed_child() {
        if std::env::var_os(MODE_ENV).is_none() {
            return;
        }
        let stdin = std::io::stdin().lock();
        stdin.set_raw_mode().unwrap();
        stdin.set_canon_mode().unwrap();
        // Another handle that is not a console tells the jailer nothing.
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out-pointers to handles.
        assert_ne!(unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 0) }, 0);
        Fd(from_handle(r as RawHandle)).set_raw_mode().unwrap();
        // SAFETY: the handles made above.
        unsafe {
            CloseHandle(r);
            CloseHandle(w);
        }
    }

    /// A process whose standard input is a pipe and that has the jailer's
    /// mode pipe (this test is the jailer): its standard input's raw and
    /// canonical modes reach the jailer, in order, and nothing else does.
    #[test]
    fn test_a_jailed_stdin_tells_the_jailer() {
        use std::io::Read;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        if std::env::var_os(MODE_ENV).is_some() {
            return;
        }
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out-pointers to handles.
        assert_ne!(unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 0) }, 0);
        // SAFETY: our handle; the child's end only is inherited.
        assert_ne!(unsafe { SetHandleInformation(w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }, 0);
        let exe = std::env::current_exe().unwrap();
        let child = std::process::Command::new(exe)
            .args(["--exact", "windows::terminal::tests::jailed_child", "--ignored", "--nocapture"])
            .env(MODE_ENV, (w as usize).to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // SAFETY: the child has its copy; ours is closed, so the read ends
        // when the child does.
        unsafe { CloseHandle(w) };
        // SAFETY: our read end, owned from here.
        let mut requests = std::fs::File::from(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(r as RawHandle) });
        let mut got = Vec::new();
        requests.read_to_end(&mut got).unwrap();
        let out = child.wait_with_output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
        assert_eq!(got, [RAW_REQUEST, CANON_REQUEST]);
    }
}
