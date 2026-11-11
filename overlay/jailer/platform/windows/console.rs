// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The jailed Firecracker's terminal.
//!
//! On Linux the jailed Firecracker inherits the jailer's terminal, and a
//! terminal gives a process no way to signal another one or type into the
//! shell (its seccomp filter has no `TIOCSTI`). A Windows console does both
//! for every process attached to it, whatever its token: a console control
//! event (`GenerateConsoleCtrlEvent`) reaches every process of the console
//! (measured: a jailed process ended a process of the user that way), and
//! `WriteConsoleInput` on its input handle types into the console. So
//! Firecracker is never attached to the jailer's console: it is started with
//! a console of its own, hidden (`CREATE_NO_WINDOW`), and each of the
//! jailer's standard handles that is a console is given to it as a pipe
//! that the jailer relays: console input to Firecracker's standard input,
//! its standard output and error (one pipe when both are the console, so
//! their order is kept) to the console. The bytes are those Firecracker
//! would have read and written on the console itself (`ReadFile` and
//! `WriteFile` on it, as the compatibility libc does).
//!
//! Firecracker puts its standard input in raw mode for the guest's serial
//! console; on a pipe that changes nothing, so the jailer sets the console
//! to that mode (`vmm_sys_util::terminal`'s raw mode: no line input, echo or
//! Ctrl+C processing, virtual terminal input) while it relays, and restores
//! it when Firecracker ends. Ctrl+C is then a byte for the guest, as it is
//! once Firecracker has set raw mode on Linux; there the terminal is raw
//! from the microVM's start rather than Firecracker's.
//!
//! Standard handles that are not consoles (pipes, files, `NUL`) are passed
//! on as they are.

use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode,
};

/// `vmm_sys_util::terminal::Terminal::set_raw_mode` on Windows.
fn raw(mode: CONSOLE_MODE) -> CONSOLE_MODE {
    (mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
        | ENABLE_VIRTUAL_TERMINAL_INPUT
}

fn is_console(h: HANDLE) -> bool {
    let mut mode = 0;
    // SAFETY: a mode query; it fails on a handle that is not a console.
    !h.is_null() && h != INVALID_HANDLE_VALUE && unsafe { GetConsoleMode(h, &mut mode) } != 0
}

/// A handle value that may cross to a thread (a standard handle, open for
/// the jailer's life).
#[derive(Clone, Copy)]
struct Std(HANDLE);
// SAFETY: a kernel handle value; the console calls on it are thread-safe.
unsafe impl Send for Std {}

/// An anonymous pipe: (the jailer's end, Firecracker's end, inheritable).
fn pipe(child_reads: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
    let (r, w) = io::pipe()?;
    let (r, w) = (OwnedHandle::from(r), OwnedHandle::from(w));
    let (mine, child) = if child_reads { (w, r) } else { (r, w) };
    // SAFETY: a handle we own.
    if unsafe { SetHandleInformation(child.as_raw_handle(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((mine, child))
}

/// The relays' buffer size.
const BUF: u32 = 4096;

/// Copies console input to `to` until either end fails.
fn relay_input(console: Std, to: OwnedHandle) {
    let mut to = std::fs::File::from(to);
    let mut buf = [0u8; BUF as usize];
    loop {
        let mut n = 0u32;
        // SAFETY: a console handle open for the jailer's life and a buffer
        // of the size passed.
        if unsafe { ReadFile(console.0, buf.as_mut_ptr(), BUF, &mut n, std::ptr::null_mut()) } == 0 {
            return;
        }
        if to.write_all(&buf[..n as usize]).is_err() {
            return;
        }
    }
}

/// Copies `from` to the console until `from` ends (Firecracker's ends of the
/// pipe are closed: it exited).
fn relay_output(from: OwnedHandle, console: Std) {
    let mut from = std::fs::File::from(from);
    let mut buf = [0u8; BUF as usize];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut rest = &buf[..n];
        while !rest.is_empty() {
            let (mut w, len) = (0u32, u32::try_from(rest.len()).unwrap_or(BUF));
            // SAFETY: as in `relay_input`; `len` is at most `rest`'s length.
            if unsafe { WriteFile(console.0, rest.as_ptr(), len, &mut w, std::ptr::null_mut()) } == 0 {
                return;
            }
            rest = &rest[w as usize..];
        }
    }
}

/// Firecracker's standard handles and the relays behind those that are
/// pipes to the jailer's console.
pub(super) struct Terminal {
    /// Firecracker's standard input, output and error.
    handles: [HANDLE; 3],
    /// Firecracker's ends of the pipes, closed once it has its own copies.
    child_ends: Vec<OwnedHandle>,
    /// The output relay, which ends when Firecracker's output pipe does.
    output: Option<JoinHandle<()>>,
    /// The console input and its mode before the relay set raw mode.
    restore: Option<(Std, CONSOLE_MODE)>,
}

impl Terminal {
    /// Firecracker's standard handles: the jailer's, each that is a console
    /// replaced by a relayed pipe. Sets the console's input to raw mode.
    pub(super) fn new() -> io::Result<Self> {
        // SAFETY: plain calls.
        let own = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].map(|w| unsafe { GetStdHandle(w) });
        let mut t = Terminal { handles: own, child_ends: Vec::new(), output: None, restore: None };
        if is_console(own[0]) {
            let mut mode = 0;
            // SAFETY: a console handle (checked above).
            unsafe { GetConsoleMode(own[0], &mut mode) };
            // SAFETY: as above.
            if unsafe { SetConsoleMode(own[0], raw(mode)) } == 0 {
                return Err(io::Error::last_os_error());
            }
            t.restore = Some((Std(own[0]), mode));
            let (mine, child) = pipe(true)?;
            t.handles[0] = child.as_raw_handle();
            t.child_ends.push(child);
            let console = Std(own[0]);
            std::thread::spawn(move || relay_input(console, mine));
        }
        let (out, err) = (is_console(own[1]), is_console(own[2]));
        if out || err {
            let (mine, child) = pipe(false)?;
            // Output and error to the console share one pipe, in order.
            if out {
                t.handles[1] = child.as_raw_handle();
            }
            if err {
                t.handles[2] = child.as_raw_handle();
            }
            t.child_ends.push(child);
            let console = Std(if out { own[1] } else { own[2] });
            t.output = Some(std::thread::spawn(move || relay_output(mine, console)));
        }
        Ok(t)
    }

    /// Firecracker's standard input, output and error.
    pub(super) fn handles(&self) -> [HANDLE; 3] {
        self.handles
    }

    /// Closes the jailer's copies of Firecracker's pipe ends, once it has
    /// its own: its output then ends when it exits.
    pub(super) fn started(&mut self) {
        self.child_ends.clear();
    }

    /// After Firecracker exited: copies the rest of its output to the
    /// console and restores the console's input mode.
    pub(super) fn finish(mut self) {
        self.child_ends.clear();
        if let Some(output) = self.output.take() {
            let _ = output.join();
        }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if let Some((console, mode)) = self.restore.take() {
            // SAFETY: the console input handle, open for the jailer's life.
            unsafe { SetConsoleMode(console.0, mode) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_mode_is_firecrackers() {
        let canon = ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | 0x80;
        assert_eq!(raw(canon), 0x80 | ENABLE_VIRTUAL_TERMINAL_INPUT);
    }

    #[test]
    fn test_pipes_are_inheritable_on_the_child_side_only() {
        let flags = |h: &OwnedHandle| {
            let mut f = 0;
            // SAFETY: a handle we own.
            unsafe { windows_sys::Win32::Foundation::GetHandleInformation(h.as_raw_handle(), &mut f) };
            f & HANDLE_FLAG_INHERIT
        };
        for child_reads in [true, false] {
            let (mine, child) = pipe(child_reads).unwrap();
            assert_eq!(flags(&mine), 0);
            assert_eq!(flags(&child), HANDLE_FLAG_INHERIT);
        }
    }

    #[test]
    fn test_output_relay_copies_until_the_writer_closes() {
        // The relay's console end is a file here: what it writes there is
        // what reached the "console".
        let dir = std::env::temp_dir().join(format!("wick-relay-{}", std::process::id()));
        let out = std::fs::File::create(&dir).unwrap();
        let (mine, child) = pipe(false).unwrap();
        let console = Std(out.as_raw_handle());
        let relay = std::thread::spawn(move || relay_output(mine, console));
        let mut w = std::fs::File::from(child);
        w.write_all(b"guest\r\n").unwrap();
        drop(w);
        relay.join().unwrap();
        drop(out);
        assert_eq!(std::fs::read(&dir).unwrap(), b"guest\r\n");
        std::fs::remove_file(&dir).unwrap();
    }
}
