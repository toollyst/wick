// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `std::io::stdin` with Linux's non-blocking reads; wick-std puts it in
//! place of std's on Windows.
//!
//! Firecracker makes its standard input non-blocking (`O_NONBLOCK`, which
//! the compatibility `fcntl` makes `PIPE_NOWAIT` on a pipe), and its serial
//! reads it with `std::io::stdin()` whenever the guest has room, also when
//! nothing came. On Linux that read fails with `EAGAIN` and the serial waits
//! for input again. std's own reader on Windows returns `Ok(0)` for an empty
//! non-blocking pipe (`ReadFile`'s `ERROR_NO_DATA` is
//! `ErrorKind::BrokenPipe` in std's `decode_error_kind`, and `Handle::read`
//! returns a `BrokenPipe` as the end), which the serial takes as the end of
//! its input. This one reads:
//! - a pipe or a file with `ReadFile`: `ERROR_NO_DATA` (an empty
//!   non-blocking pipe whose writer is open) is [`WOULD_BLOCK`], which is the
//!   compatibility libc's `EWOULDBLOCK`/`EAGAIN` and std's
//!   `ErrorKind::WouldBlock`; `ERROR_BROKEN_PIPE` (every writer gone) and
//!   `ERROR_HANDLE_EOF` are the end, `Ok(0)`;
//! - a console with std's own console reader (UTF-16 to UTF-8), once a key
//!   record that reads as a character is waiting. With none, [`WOULD_BLOCK`]:
//!   a console read waits for input, and consoles have no non-blocking mode.
//!   Records that read as nothing (key releases, mouse, focus and window
//!   events) are dropped first, as `vmm_sys_util`'s epoll drops them before
//!   it reports a console readable. In line input mode (canonical, before
//!   Firecracker sets raw mode) the read still waits for the end of the line,
//!   as a blocking read of a canonical terminal does on Linux;
//! - no standard input (`NULL`, or a handle that is not valid) as the end,
//!   as std does (its `handle_ebadf`).
//!
//! Like std's, it is buffered, in one buffer for the process. [`Stdin::lock`]
//! gives std's own lock, for what upstream does with it: the terminal modes
//! (`vmm_sys_util::terminal::Terminal`). A read through that lock reads std's
//! buffer, not this one; upstream reads through [`Stdin`].

use std::fmt;
use std::io::{self, BufReader, Read};
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{Mutex, OnceLock, PoisonError};

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_INVALID_HANDLE, ERROR_NO_DATA, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, INPUT_RECORD, KEY_EVENT, PeekConsoleInputW, ReadConsoleInputW,
    STD_INPUT_HANDLE,
};

use super::fd::{AsFd, AsRawFd, BorrowedFd, RawFd, from_handle};

/// `WSAEWOULDBLOCK`: what a read with nothing to read fails with. It is the
/// compatibility libc's `EWOULDBLOCK` and `EAGAIN`, so upstream's comparison
/// with `libc::EWOULDBLOCK` matches, and std's `ErrorKind::WouldBlock`.
pub const WOULD_BLOCK: i32 = 10035;

/// The buffer's size. At least std's own standard input buffer
/// (`STDIN_BUF_SIZE`, 12 KiB on Windows: library/std/src/sys/stdio/windows.rs),
/// so that a console read through std's reader, which is always given a
/// buffer this large, bypasses std's buffer (`BufReader::read` does for a
/// read at least as large as its buffer) and no input waits there unseen by
/// the console check.
const BUF_SIZE: usize = 64 * 1024;

fn would_block() -> io::Error {
    io::Error::from_raw_os_error(WOULD_BLOCK)
}

/// Reads from `h`, a pipe or a file, with Linux's results (module docs).
pub(crate) fn read_handle(h: HANDLE, buf: &mut [u8]) -> io::Result<usize> {
    let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    let mut n = 0u32;
    // SAFETY: the buffer is valid for `len` bytes; a synchronous read.
    if unsafe { ReadFile(h, buf.as_mut_ptr(), len, &mut n, std::ptr::null_mut()) } == 0 {
        // SAFETY: plain call.
        return match unsafe { GetLastError() } {
            ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF | ERROR_INVALID_HANDLE => Ok(0),
            ERROR_NO_DATA => Err(would_block()),
            e => Err(io::Error::from_raw_os_error(e.cast_signed())),
        };
    }
    Ok(usize::try_from(n).unwrap_or(usize::MAX))
}

/// Whether console input `h` has a record that reads as a character; drops
/// the records in front of it that do not. A console that cannot be asked
/// counts as ready, so that the read reports its error.
pub(crate) fn console_ready(h: HANDLE) -> bool {
    loop {
        // SAFETY: an all-zero INPUT_RECORD is valid.
        let mut rec: INPUT_RECORD = unsafe { std::mem::zeroed() };
        let mut n = 0u32;
        // SAFETY: room for one record.
        if unsafe { PeekConsoleInputW(h, &mut rec, 1, &mut n) } == 0 {
            return true;
        }
        if n == 0 {
            return false;
        }
        if u32::from(rec.EventType) == KEY_EVENT {
            // SAFETY: the record is a key event.
            let key = unsafe { rec.Event.KeyEvent };
            // SAFETY: a union of u16 and i8; both read as the code unit.
            if key.bKeyDown != 0 && unsafe { key.uChar.UnicodeChar } != 0 {
                return true;
            }
        }
        // SAFETY: removes the record peeked above.
        if unsafe { ReadConsoleInputW(h, &mut rec, 1, &mut n) } == 0 {
            return true;
        }
    }
}

/// The standard input handle, read on each call as std does; `None` when the
/// process has none.
fn std_input() -> Option<HANDLE> {
    // SAFETY: plain call.
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(h)
}

/// The unbuffered reader under [`Stdin`]'s buffer.
struct Raw;

impl Read for Raw {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(h) = std_input() else {
            return Ok(0);
        };
        let mut mode = 0;
        // SAFETY: queries a handle; fails on anything but a console.
        if unsafe { GetConsoleMode(h, &mut mode) } == 0 {
            return read_handle(h, buf);
        }
        if !console_ready(h) {
            return Err(would_block());
        }
        // `buf` is this module's whole buffer, or a larger one (see
        // `BUF_SIZE`), so std's own buffer keeps nothing back.
        std::io::stdin().lock().read(buf)
    }
}

/// A handle to the process's standard input, as `std::io::Stdin`, with the
/// reads described in the module documentation.
pub struct Stdin {
    inner: &'static Mutex<BufReader<Raw>>,
}

/// The process's standard input, as `std::io::stdin`.
pub fn stdin() -> Stdin {
    static INNER: OnceLock<Mutex<BufReader<Raw>>> = OnceLock::new();
    Stdin {
        inner: INNER.get_or_init(|| Mutex::new(BufReader::with_capacity(BUF_SIZE, Raw))),
    }
}

impl Stdin {
    /// std's lock of the standard input, for the terminal modes
    /// (`vmm_sys_util::terminal::Terminal` is implemented for it). Reads
    /// through it bypass this reader's buffer.
    pub fn lock(&self) -> std::io::StdinLock<'static> {
        std::io::stdin().lock()
    }

    fn read_locked(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .read(buf)
    }
}

impl Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_locked(buf)
    }
}

impl Read for &Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_locked(buf)
    }
}

impl fmt::Debug for Stdin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stdin").finish_non_exhaustive()
    }
}

impl AsRawHandle for Stdin {
    fn as_raw_handle(&self) -> RawHandle {
        std::io::stdin().as_raw_handle()
    }
}

impl AsRawFd for Stdin {
    fn as_raw_fd(&self) -> RawFd {
        from_handle(self.as_raw_handle())
    }
}

impl AsFd for Stdin {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the standard input handle lives as long as the process.
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::windows::io::FromRawHandle;

    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, WriteFile,
    };
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, FOCUS_EVENT,
        FOCUS_EVENT_RECORD, GetConsoleWindow, GetNumberOfConsoleInputEvents, INPUT_RECORD_0,
        KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, STD_INPUT_HANDLE, SetConsoleMode, SetStdHandle,
        WriteConsoleInputW,
    };
    use windows_sys::Win32::System::Pipes::{
        CreatePipe, PIPE_NOWAIT, PIPE_READMODE_BYTE, SetNamedPipeHandleState,
    };

    use super::*;

    fn pipe() -> (HANDLE, HANDLE) {
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out-pointers to handles.
        assert_ne!(unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 0) }, 0);
        (r, w)
    }

    fn write_all(w: HANDLE, bytes: &[u8]) {
        let mut n = 0u32;
        // SAFETY: a valid buffer.
        let ok = unsafe {
            WriteFile(
                w,
                bytes.as_ptr(),
                u32::try_from(bytes.len()).unwrap(),
                &mut n,
                std::ptr::null_mut(),
            )
        };
        assert!(ok != 0 && n as usize == bytes.len());
    }

    // A pipe: data reads; empty and non-blocking with its writer open it is
    // WSAEWOULDBLOCK (EAGAIN on Linux, fs/pipe.c pipe_read), where std reads
    // Ok(0) (the libc's test_pipe); once the writer is gone, the end.
    #[test]
    fn test_a_pipe_reads_as_on_linux() {
        let (r, w) = pipe();
        let mut buf = [0u8; 8];
        write_all(w, b"ab");
        assert_eq!(read_handle(r, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"ab");
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        // SAFETY: our pipe's read end.
        assert_ne!(
            unsafe { SetNamedPipeHandleState(r, &mode, std::ptr::null(), std::ptr::null()) },
            0
        );
        let err = read_handle(r, &mut buf).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK));
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        // std's reader on the same handle: the end, which is what this
        // module is for.
        let file = std::mem::ManuallyDrop::new(
            // SAFETY: borrowed; ManuallyDrop keeps it from closing the handle.
            unsafe { std::fs::File::from_raw_handle(r) },
        );
        assert_eq!((&*file).read(&mut buf).unwrap(), 0, "std's read of an empty pipe");
        write_all(w, b"c");
        assert_eq!(read_handle(r, &mut buf).unwrap(), 1);
        // SAFETY: the writer, ours.
        unsafe { CloseHandle(w) };
        // ERROR_BROKEN_PIPE: the end.
        assert_eq!(read_handle(r, &mut buf).unwrap(), 0);
        // SAFETY: the reader, ours.
        unsafe { CloseHandle(r) };
    }

    // A file at its end reads 0 bytes (a synchronous ReadFile returns
    // success there; ERROR_HANDLE_EOF, also the end, is what a read at an
    // offset past the end gives, ReadFile docs).
    #[test]
    fn test_a_file_at_its_end_reads_as_the_end() {
        let p = std::env::temp_dir().join(format!("wick-os-stdio-{}", std::process::id()));
        std::fs::File::create(&p).unwrap().write_all(b"xyz").unwrap();
        let f = std::fs::File::open(&p).unwrap();
        let mut buf = [0u8; 8];
        let h = f.as_raw_handle() as HANDLE;
        assert_eq!(read_handle(h, &mut buf).unwrap(), 3);
        assert_eq!(read_handle(h, &mut buf).unwrap(), 0);
        drop(f);
        std::fs::remove_file(p).unwrap();
    }

    // No standard input (a NULL handle: ERROR_INVALID_HANDLE) reads as the
    // end, as std's handle_ebadf makes it.
    #[test]
    fn test_no_input_reads_as_the_end() {
        let mut buf = [0u8; 8];
        assert_eq!(read_handle(std::ptr::null_mut(), &mut buf).unwrap(), 0);
    }

    /// Tells the child of `test_a_console_without_characters_reads_as_eagain`
    /// that it is the child.
    const CONSOLE_CHILD_ENV: &str = "WICK_TEST_STDIO_CONSOLE_CHILD";

    fn key(down: bool, c: u8) -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: 1, // KEY_EVENT
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: i32::from(down),
                    wRepeatCount: 1,
                    wVirtualKeyCode: 0,
                    wVirtualScanCode: 0,
                    uChar: KEY_EVENT_RECORD_0 {
                        UnicodeChar: u16::from(c),
                    },
                    dwControlKeyState: 0,
                },
            },
        }
    }

    fn focus() -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: 16, // FOCUS_EVENT
            Event: INPUT_RECORD_0 {
                FocusEvent: FOCUS_EVENT_RECORD { bSetFocus: 1 },
            },
        }
    }

    /// A process with a console of its own and no window (its parent made it
    /// with CREATE_NO_WINDOW): [`stdin`] on that console, in raw mode as
    /// Firecracker sets it when the vCPUs start. Run by
    /// `test_a_console_without_characters_reads_as_eagain`.
    #[test]
    #[ignore = "the child of test_a_console_without_characters_reads_as_eagain"]
    fn console_child() {
        if std::env::var_os(CONSOLE_CHILD_ENV).is_none() {
            return;
        }
        assert_eq!(u32::from(key(true, b'a').EventType), KEY_EVENT);
        assert_eq!(u32::from(focus().EventType), FOCUS_EVENT);
        // Records are written below: never into a console someone sees.
        // SAFETY: plain call.
        assert!(unsafe { GetConsoleWindow() }.is_null(), "a console with a window");
        let name: Vec<u16> = "CONIN$".encode_utf16().chain([0]).collect();
        // SAFETY: a NUL-terminated name; no security attributes or template.
        let conin = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(conin, INVALID_HANDLE_VALUE, "CONIN$: {}", io::Error::last_os_error());
        let mut mode = 0;
        // SAFETY: our console input handle.
        unsafe {
            assert_ne!(GetConsoleMode(conin, &mut mode), 0);
            let raw = mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
            assert_ne!(SetConsoleMode(conin, raw), 0);
            assert_ne!(SetStdHandle(STD_INPUT_HANDLE, conin), 0);
        }
        let write = |recs: &[INPUT_RECORD]| {
            let mut n = 0u32;
            // SAFETY: valid records.
            let ok = unsafe {
                WriteConsoleInputW(conin, recs.as_ptr(), u32::try_from(recs.len()).unwrap(), &mut n)
            };
            assert!(ok != 0 && n as usize == recs.len());
        };
        let pending = || {
            let mut n = 0u32;
            // SAFETY: our console input handle.
            assert_ne!(unsafe { GetNumberOfConsoleInputEvents(conin, &mut n) }, 0);
            n
        };
        let mut input = stdin();
        let mut buf = [0u8; 16];
        // Nothing at all.
        let err = input.read(&mut buf).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK));
        // A key release and a focus event read as nothing, and are dropped.
        write(&[key(false, b'a'), focus()]);
        let err = input.read(&mut buf).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK));
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(pending(), 0);
        // Characters read.
        write(&[key(true, b'h'), key(false, b'h'), key(true, b'i')]);
        let mut got = Vec::new();
        while got.len() < 2 {
            match input.read(&mut buf) {
                Ok(n) => {
                    assert!(n > 0, "the end of a console");
                    got.extend_from_slice(&buf[..n]);
                }
                Err(e) => panic!("after {got:?}: {e}"),
            }
        }
        assert_eq!(got, b"hi");
        // And then nothing again.
        assert_eq!(input.read(&mut buf).unwrap_err().raw_os_error(), Some(WOULD_BLOCK));
    }

    #[test]
    fn test_a_console_without_characters_reads_as_eagain() {
        use std::os::windows::process::CommandExt;
        if std::env::var_os(CONSOLE_CHILD_ENV).is_some() {
            return;
        }
        /// A console of its own without a window (CreateProcess flags).
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::stdio::tests::console_child",
                "--ignored",
                "--nocapture",
            ])
            .env(CONSOLE_CHILD_ENV, "1")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
    }

    #[test]
    fn test_stdin_is_the_standard_input() {
        let s = stdin();
        // SAFETY: plain call.
        let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        assert_eq!(s.as_raw_handle() as HANDLE, h);
        assert_eq!(s.as_raw_fd(), from_handle(h as RawHandle));
        assert_eq!(s.as_fd().as_raw_fd(), s.as_raw_fd());
        assert!(format!("{s:?}").starts_with("Stdin"));
        fn send_sync<T: Send + Sync + 'static>(_: &T) {}
        send_sync(&s);
    }
}
