// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `std::io::stdin` with Linux's non-blocking reads and `std::io::stdout`
//! with Linux's non-blocking writes ([`Stdout`]); wick-std puts them in place
//! of std's on Windows.
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
//!   Firecracker sets raw mode and after it sets canonical mode back) a
//!   read with no whole line typed is [`WOULD_BLOCK`] too, and takes
//!   nothing, as Linux's canonical terminal gives `EAGAIN` until the line is
//!   complete (`line_ready`); once Enter is among the records the line
//!   reads, and ends in one newline as on Linux (`line_end`);
//! - no standard input (`NULL`, or a handle that is not valid) as the end,
//!   as std does (its `handle_ebadf`).
//!
//! Like std's, it is buffered, in one buffer for the process. [`Stdin::lock`]
//! gives std's own lock, for what upstream does with it: the terminal modes
//! (`vmm_sys_util::terminal::Terminal`). A read through that lock reads std's
//! buffer, not this one; upstream reads through [`Stdin`].

use std::fmt;
use std::io::{self, BufReader, LineWriter, Read, Write};
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_INVALID_HANDLE, ERROR_NO_DATA, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode, GetNumberOfConsoleInputEvents,
    GetStdHandle, INPUT_RECORD, KEY_EVENT, PeekConsoleInputW, ReadConsoleInputW, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
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

/// In line input mode: whether the Enter that ends a line is among the
/// records waiting. Nothing is removed.
///
/// Linux's terminal in canonical mode has input only once a line is
/// complete (drivers/tty/n_tty.c `input_available_p`: `canon_head !=
/// read_tail`); until then a non-blocking read fails with `EAGAIN`
/// (`n_tty_read`: `tty_io_nonblock`) and poll does not report it readable
/// (`n_tty_poll`). A console read in line input mode returns "only when a
/// carriage return is read" (ENABLE_LINE_INPUT,
/// learn.microsoft.com/windows/console/setconsolemode) and has no
/// non-blocking form, so a read begun with part of a line typed would hold
/// its thread until Enter. A console that cannot be asked counts as ready,
/// so that the read reports its error.
fn line_ready(h: HANDLE) -> bool {
    let mut count = 0u32;
    // SAFETY: an out-pointer to a u32.
    if unsafe { GetNumberOfConsoleInputEvents(h, &mut count) } == 0 {
        return true;
    }
    if count == 0 {
        return false;
    }
    // SAFETY: an all-zero INPUT_RECORD is valid.
    let mut recs: Vec<INPUT_RECORD> = vec![unsafe { std::mem::zeroed() }; count as usize];
    let mut n = 0u32;
    // SAFETY: room for `count` records.
    if unsafe { PeekConsoleInputW(h, recs.as_mut_ptr(), count, &mut n) } == 0 {
        return true;
    }
    recs.iter().take(n as usize).any(|rec| {
        if u32::from(rec.EventType) != KEY_EVENT {
            return false;
        }
        // SAFETY: the record is a key event.
        let key = unsafe { rec.Event.KeyEvent };
        // SAFETY: a union of u16 and i8; both read as the code unit.
        key.bKeyDown != 0 && unsafe { key.uChar.UnicodeChar } == 0x0d
    })
}

/// Whether a read of console input `h` would return at once. In line input
/// mode: a whole line waits ([`line_ready`]). Otherwise: a record that
/// reads as a character waits; the records in front of it that do not are
/// dropped. A console that cannot be asked counts as ready, so that the
/// read reports its error.
pub(crate) fn console_ready(h: HANDLE) -> bool {
    let mut mode = 0u32;
    // SAFETY: an out-pointer to a u32; fails on anything but a console.
    if unsafe { GetConsoleMode(h, &mut mode) } != 0 && mode & ENABLE_LINE_INPUT != 0 {
        return line_ready(h);
    }
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
        let n = std::io::stdin().lock().read(buf)?;
        if mode & ENABLE_LINE_INPUT != 0 {
            return Ok(line_end(&mut buf[..n], mode & ENABLE_PROCESSED_INPUT != 0));
        }
        Ok(n)
    }
}

/// The end of a line read in line input mode made Linux's: a console read
/// ends the line with the Enter key's carriage return, followed by a line
/// feed in processed input mode only (ENABLE_PROCESSED_INPUT: "carriage
/// return, and line feed characters are handled by the system",
/// learn.microsoft.com/windows/console/setconsolemode; conhost's
/// `COOKED_READ_DATA::_handlePostCharInputLoop` appends `\r\n` with it and
/// `\r` without, microsoft/terminal src/host/readDataCooked.cpp; measured
/// without it, CI run 43323860314: "ok" and Enter read as `ok\r`). A Linux
/// terminal gives the Enter key's carriage return as one newline
/// (drivers/tty/n_tty.c `n_tty_receive_char_special`: `if (I_ICRNL(tty)) c
/// = '\n';`, and ICRNL is set on a terminal as the kernel makes it,
/// drivers/tty/tty_io.c `tty_std_termios`). Returns the length of `read`
/// after the change. A line longer than one read ends in a later read, and
/// is changed there; one cut between its carriage return and line feed
/// keeps both.
fn line_end(read: &mut [u8], processed: bool) -> usize {
    let n = read.len();
    if processed && read.ends_with(b"\r\n") {
        read[n - 2] = b'\n';
        return n - 1;
    }
    if !processed && read.ends_with(b"\r") {
        read[n - 1] = b'\n';
    }
    n
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

/// std's standard output buffer: `LineWriter::new`, 1024 bytes
/// (library/std/src/io/stdio.rs `stdout`; library/std/src/io/buffered/
/// linewriter.rs `LineWriter::new`).
const OUT_BUF_SIZE: usize = 1024;

/// Linux's `PIPE_BUF`: a write of at most this many bytes to a pipe is
/// taken whole or not at all (pipe(7); include/uapi/linux/limits.h).
const PIPE_BUF: usize = 4096;

/// One `WriteFile` of `buf`: the bytes taken.
fn write_file(h: HANDLE, buf: &[u8]) -> io::Result<usize> {
    let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    let mut n = 0u32;
    // SAFETY: the buffer is valid for `len` bytes; a synchronous write.
    if unsafe { WriteFile(h, buf.as_ptr(), len, &mut n, std::ptr::null_mut()) } == 0 {
        // SAFETY: plain call.
        return match unsafe { GetLastError() } {
            // std's handle_ebadf: no standard output takes everything.
            ERROR_INVALID_HANDLE => Ok(buf.len()),
            e @ (ERROR_BROKEN_PIPE | ERROR_NO_DATA) => {
                super::net::broken_pipe();
                Err(io::Error::from_raw_os_error(e.cast_signed()))
            }
            e => Err(io::Error::from_raw_os_error(e.cast_signed())),
        };
    }
    Ok(usize::try_from(n).unwrap_or(usize::MAX))
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtQueryInformationFile(
        h: HANDLE,
        io: *mut [usize; 2],
        info: *mut std::ffi::c_void,
        len: u32,
        class: u32,
    ) -> i32;
}

/// The most bytes a non-blocking write to the pipe `h` is taken whole or
/// not at all: `PIPE_BUF`, or what the pipe holds if that is less, which no
/// Linux pipe does (fs/pipe.c `round_pipe_size`: at least a page). A
/// Windows pipe holds exactly the bytes it was made with, the quota of the
/// queue this end writes to (`FILE_PIPE_LOCAL_INFORMATION`, ntifs.h:
/// `OutboundQuota` at the server end, `InboundQuota` at the client end;
/// measured, CI run 43341846250: `CreatePipe` with nSize 512 holds 512
/// bytes), and refuses whole a write larger than that while no read waits
/// for it. A handle that cannot be asked (no `FILE_READ_ATTRIBUTES`: the
/// server end of an outbound named pipe, in the same run) is taken to be
/// of a pipe that holds a page. The compatibility libc's `write` has the
/// same rule.
fn pipe_atom(h: HANDLE) -> usize {
    PIPE_BUF.min(pipe_quota(h).unwrap_or(PIPE_BUF))
}

/// What the pipe `h` writes to holds at most, in bytes: the quota of the
/// queue this end writes to (see [`pipe_atom`]); `None` for a handle that
/// cannot be asked.
pub(crate) fn pipe_quota(h: HANDLE) -> Option<usize> {
    let (mut io, mut info) = ([0usize; 2], [0u32; 10]);
    // SAFETY: a pipe handle and out-buffers of the sizes given (class 24,
    // FilePipeLocalInformation, 40 bytes).
    if unsafe { NtQueryInformationFile(h, &mut io, info.as_mut_ptr().cast(), 40, 24) } != 0 {
        return None;
    }
    // NamedPipeEnd: FILE_PIPE_SERVER_END is 1.
    let quota = if info[9] == 1 { info[6] } else { info[4] };
    Some(usize::try_from(quota).unwrap_or(usize::MAX))
}

/// Writes to `h`, a pipe or a file, with Linux's results (see [`Stdout`]).
pub(crate) fn write_handle(h: HANDLE, buf: &[u8]) -> io::Result<usize> {
    let mut total = write_file(h, buf)?;
    // SAFETY: plain call.
    if total == buf.len() || unsafe { GetFileType(h) } != FILE_TYPE_PIPE {
        return Ok(total);
    }
    // A non-blocking pipe that did not take the write (see [`Stdout`]): up
    // to PIPE_BUF bytes that is Linux's result too; a larger write goes in
    // pieces of PIPE_BUF, each taken whole or refused, until one is
    // refused, as Linux takes what fits page by page. On a pipe that holds
    // less than PIPE_BUF the pieces are of what it holds (`pipe_atom`).
    let atom = pipe_atom(h);
    if buf.len() > atom && atom > 0 {
        while total < buf.len() {
            let rest = &buf[total..];
            let piece = &rest[..rest.len().min(atom)];
            match write_file(h, piece) {
                // The reader went away meanwhile: the error if nothing was
                // written, else the count (fs/pipe.c anon_pipe_write, `if
                // (!ret) ret = -EPIPE;`).
                Err(e) if total == 0 => return Err(e),
                Err(_) => break,
                Ok(n) => {
                    total += n;
                    if n < piece.len() {
                        break;
                    }
                }
            }
        }
    }
    if total == 0 {
        return Err(would_block());
    }
    Ok(total)
}

/// The standard output handle, read on each call as std does; `None` when the
/// process has none.
fn std_output() -> Option<HANDLE> {
    // SAFETY: plain call.
    let h = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(h)
}

/// The unbuffered writer under [`Stdout`]'s buffer.
struct RawOut;

impl Write for RawOut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(h) = std_output() else {
            return Ok(buf.len());
        };
        let mut mode = 0;
        // SAFETY: queries a handle; fails on anything but a console.
        if unsafe { GetConsoleMode(h, &mut mode) } == 0 {
            return write_handle(h, buf);
        }
        // A console: std's writer (UTF-8 to UTF-16), flushed at once, as
        // this writer is unbuffered under [`Stdout`]'s buffer.
        let mut out = std::io::stdout().lock();
        let n = out.write(buf)?;
        out.flush()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A handle to the process's standard output, as `std::io::Stdout`, whose
/// writes give Linux's results where std's differ on Windows.
///
/// Firecracker makes its standard output non-blocking when the serial writes
/// there (`set_stdout_nonblocking`; the compatibility `fcntl` makes a pipe
/// `PIPE_NOWAIT`). A non-blocking pipe without room for a write: on Linux a
/// write of at most `PIPE_BUF` (4096) bytes fails with `EAGAIN`,
/// `ErrorKind::WouldBlock`, and nothing of it is taken, and a larger one is
/// taken as far as it fits (pipe(7); fs/pipe.c `anon_pipe_write`, `if (!ret)
/// ret = -EAGAIN`); on Windows `WriteFile` takes nothing of a write of any
/// size that does not fit whole and returns success with 0 bytes written
/// (measured, CI run 43323860314; the compatibility libc's module
/// documentation has the numbers), and std's writer passes the 0 on, which
/// `write_all` and the buffer's flush report as `ErrorKind::WriteZero`. This
/// one writes:
/// - a pipe or a file with `WriteFile`: 0 bytes of a non-empty write to a
///   pipe is [`WOULD_BLOCK`] (a pipe in blocking mode completes a write only
///   once all of it is written, `SetNamedPipeHandleState`, so it is a
///   non-blocking pipe without room, whichever handle made it
///   non-blocking), after a write of more than `PIPE_BUF` bytes was tried in
///   pieces of `PIPE_BUF`, which gives the count of those taken
///   (`test_a_write_that_does_not_fit_takes_nothing`,
///   `test_a_large_write_is_taken_as_far_as_it_fits`);
///   `ERROR_BROKEN_PIPE`/`ERROR_NO_DATA` (no reader) fails with
///   `ErrorKind::BrokenPipe` and calls the `SIGPIPE` hook
///   ([`super::set_broken_pipe_hook`]), as Linux sends `SIGPIPE` there;
/// - a console with std's own console writer;
/// - no standard output as std does: everything is taken (`handle_ebadf`).
///
/// It is buffered as std's is, a `LineWriter` of 1024 bytes, so that a failed
/// write leaves the same bytes buffered as on Linux, where std's buffer sits
/// on `write(2)`. Differences, both from the separate buffer:
/// `print!`/`println!` write through std's buffer, so the two interleave by
/// line, not by byte; and std flushes its buffer at exit
/// (`std::process::exit` and the return from `main` call `rt::cleanup`, which
/// replaces the buffer), this one is not, so bytes left in it by a write that
/// failed are not written at exit.
pub struct Stdout {
    inner: &'static Mutex<LineWriter<RawOut>>,
}

/// The process's standard output, as `std::io::stdout`.
pub fn stdout() -> Stdout {
    static INNER: OnceLock<Mutex<LineWriter<RawOut>>> = OnceLock::new();
    Stdout {
        inner: INNER.get_or_init(|| Mutex::new(LineWriter::with_capacity(OUT_BUF_SIZE, RawOut))),
    }
}

impl Stdout {
    fn locked(&self) -> MutexGuard<'static, LineWriter<RawOut>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// As std's `Stdout`, each call holds the lock throughout, so `write_all`
// and `write_fmt` are the buffer's own (a `LineWriter` writes whole lines).
impl Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        (&*self).write_all(buf)
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> io::Result<()> {
        (&*self).write_fmt(args)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

impl Write for &Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.locked().write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.locked().write_all(buf)
    }

    fn write_fmt(&mut self, args: fmt::Arguments<'_>) -> io::Result<()> {
        self.locked().write_fmt(args)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.locked().flush()
    }
}

impl fmt::Debug for Stdout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stdout").finish_non_exhaustive()
    }
}

impl AsRawHandle for Stdout {
    fn as_raw_handle(&self) -> RawHandle {
        std::io::stdout().as_raw_handle()
    }
}

impl AsRawFd for Stdout {
    fn as_raw_fd(&self) -> RawFd {
        from_handle(self.as_raw_handle())
    }
}

impl AsFd for Stdout {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the standard output handle lives as long as the process.
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::FromRawHandle;

    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, FOCUS_EVENT, FOCUS_EVENT_RECORD,
        GetConsoleProcessList, INPUT_RECORD_0, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0,
        SetConsoleMode, SetStdHandle, WriteConsoleInputW,
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
        key_vk(down, c, 0)
    }

    fn key_vk(down: bool, c: u8, vk: u16) -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: 1, // KEY_EVENT
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: i32::from(down),
                    wRepeatCount: 1,
                    wVirtualKeyCode: vk,
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

    /// [`stdin`] on a console of this process's own, in raw mode as
    /// Firecracker sets it when the vCPUs start. Run by
    /// `test_a_console_without_characters_reads_as_eagain`, which gives it
    /// that console.
    #[test]
    #[ignore = "the child of test_a_console_without_characters_reads_as_eagain"]
    fn console_child() {
        if std::env::var_os(CONSOLE_CHILD_ENV).is_none() {
            return;
        }
        assert_eq!(u32::from(key(true, b'a').EventType), KEY_EVENT);
        assert_eq!(u32::from(focus().EventType), FOCUS_EVENT);
        // Records are written below: only into a console no other process
        // is attached to.
        let mut ids = [0u32; 4];
        // SAFETY: room for 4 process ids.
        let attached = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), 4) };
        assert_eq!(attached, 1, "a console shared with other processes: {ids:?}");
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

        // Line input mode. First as vmm_sys_util's `set_canon_mode` leaves
        // the console (line input, echo and processed input: a console's
        // mode before Firecracker sets raw mode and after it sets canonical
        // mode back); then line input alone, which run 43323860314 had.
        // Part of a line typed is EAGAIN, as on a canonical terminal on
        // Linux (n_tty_read), and nothing of it is taken; Enter (VK_RETURN)
        // ends the line, and it reads with one newline at its end, as on
        // Linux (`line_end`), where the console gives `\r\n` in the first
        // mode and `\r` in the second.
        let raw = mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        let canon = (mode | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
            & !ENABLE_VIRTUAL_TERMINAL_INPUT;
        // The records waiting, for a failure's message: (event type, key
        // down, repeat count, virtual key, character, control keys).
        let records = || {
            // SAFETY: an all-zero INPUT_RECORD is valid.
            let mut recs: [INPUT_RECORD; 32] = unsafe { std::mem::zeroed() };
            let mut n = 0u32;
            // SAFETY: room for 32 records.
            if unsafe { PeekConsoleInputW(conin, recs.as_mut_ptr(), 32, &mut n) } == 0 {
                return format!("PeekConsoleInputW: {}", io::Error::last_os_error());
            }
            let mut text = format!("{n} records");
            for rec in &recs[..n as usize] {
                if u32::from(rec.EventType) == KEY_EVENT {
                    // SAFETY: the record is a key event; the union's u16.
                    let (k, c) = unsafe { (rec.Event.KeyEvent, rec.Event.KeyEvent.uChar.UnicodeChar) };
                    text += &format!(
                        " (key, {}, {}, {:#x}, {c:#x}, {:#x})",
                        k.bKeyDown, k.wRepeatCount, k.wVirtualKeyCode, k.dwControlKeyState
                    );
                } else {
                    text += &format!(" (type {})", rec.EventType);
                }
            }
            text
        };
        for (name, line_mode, a, b) in [
            ("line, echo and processed input", canon, b'o', b'k'),
            ("line input alone", raw | ENABLE_LINE_INPUT, b'n', b'o'),
        ] {
            let mut now = 0;
            // SAFETY: our console input handle.
            unsafe {
                assert_ne!(SetConsoleMode(conin, line_mode), 0, "{name}");
                assert_ne!(GetConsoleMode(conin, &mut now), 0);
            }
            write(&[key(true, a), key(false, a), key(true, b)]);
            let err = input.read(&mut buf).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK), "{name}: part of a line");
            assert_eq!(pending(), 3, "{name}: the records of the unfinished line stay");
            write(&[key_vk(true, b'\r', 0x0d)]);
            let before = records();
            let mut got = Vec::new();
            while !got.ends_with(b"\n") {
                match input.read(&mut buf) {
                    Ok(n) => {
                        assert!(n > 0, "{name}: the end of a console");
                        got.extend_from_slice(&buf[..n]);
                    }
                    Err(e) => panic!(
                        "{name} (mode {now:#x}), after {got:?}: {e}; before the read {before}; \
                         now {}",
                        records()
                    ),
                }
            }
            assert_eq!(got, [a, b, b'\n'], "{name} (mode {now:#x}); before the read {before}");
            // On record: what the console itself gives for a line in this
            // mode (std's reader, without `line_end`).
            write(&[key(true, b'x'), key_vk(true, b'\r', 0x0d)]);
            let mut line = [0u8; 64];
            let n = std::io::stdin().lock().read(&mut line).unwrap();
            println!("CONSOLETEST {name} (mode {now:#x}): the console reads \"x\" and Enter as {:?}", &line[..n]);
        }
    }

    // The end of a line read in line input mode: one newline, as on Linux.
    #[test]
    fn test_a_line_ends_in_one_newline() {
        let end = |bytes: &[u8], processed: bool| {
            let mut b = bytes.to_vec();
            let n = line_end(&mut b, processed);
            b.truncate(n);
            b
        };
        assert_eq!(end(b"ok\r\n", true), b"ok\n");
        assert_eq!(end(b"ok\r", false), b"ok\n");
        assert_eq!(end(b"\r\n", true), b"\n");
        assert_eq!(end(b"\r", false), b"\n");
        // Not a line's end as that mode gives it: left as read.
        assert_eq!(end(b"ok\r", true), b"ok\r");
        assert_eq!(end(b"ok", true), b"ok");
        assert_eq!(end(b"ok", false), b"ok");
        assert_eq!(end(b"", true), b"");
        assert_eq!(end(b"", false), b"");
    }

    /// Runs `console_child` with a console of its own, hidden:
    /// CREATE_NEW_CONSOLE ("The new process has a new console, instead of
    /// inheriting its parent's console", Microsoft's Process Creation Flags,
    /// learn.microsoft.com/windows/win32/procthread/process-creation-flags)
    /// with STARTF_USESHOWWINDOW and SW_HIDE (the STARTUPINFO given to
    /// CreateProcess "affects a console created if the CREATE_NEW_CONSOLE
    /// flag is specified", Creation of a Console,
    /// learn.microsoft.com/windows/console/creation-of-a-console). Not
    /// CREATE_NO_WINDOW: "run without a console window. Therefore, the
    /// console handle for the application is not set" (Process Creation
    /// Flags) does not say a console is made. The child's output comes back
    /// through a pipe (STARTF_USESTDHANDLES). Ignored in `cargo test`: the
    /// windows job of ci.yml runs it alone, in a step after the binaries'
    /// upload, so that a runner without a console cannot cost the kit.
    #[test]
    #[ignore = "needs a console: CI's post-upload step runs it"]
    fn test_a_console_without_characters_reads_as_eagain() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStrExt as _;
        use std::os::windows::io::OwnedHandle;

        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        use windows_sys::Win32::System::Threading::{
            CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess,
            PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW,
            WaitForSingleObject,
        };

        if std::env::var_os(CONSOLE_CHILD_ENV).is_some() {
            return;
        }
        let (r, w) = pipe();
        // SAFETY: our handle; the child's end only is inherited.
        assert_ne!(unsafe { SetHandleInformation(w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }, 0);
        let exe = std::env::current_exe().unwrap();
        let mut cmd: Vec<u16> = vec![u16::from(b'"')];
        cmd.extend(exe.as_os_str().encode_wide());
        cmd.extend(
            "\" --exact windows::stdio::tests::console_child --ignored --nocapture".encode_utf16(),
        );
        cmd.push(0);
        // This process's environment and the child's marker, sorted by name
        // as CreateProcess expects, two NULs at the end.
        let mut vars: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(k, _)| k.to_str() != Some(CONSOLE_CHILD_ENV))
            .collect();
        vars.push((CONSOLE_CHILD_ENV.into(), "1".into()));
        vars.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
        let mut env: Vec<u16> = Vec::new();
        for (k, v) in &vars {
            env.extend(k.encode_wide());
            env.push(u16::from(b'='));
            env.extend(v.encode_wide());
            env.push(0);
        }
        env.push(0);
        let si = STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap(),
            dwFlags: STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES,
            wShowWindow: 0, // SW_HIDE
            hStdInput: std::ptr::null_mut(),
            hStdOutput: w,
            hStdError: w,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: a writable NUL-terminated command line, a Unicode
        // environment block ending in two NULs, valid structures.
        let ok = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                env.as_ptr().cast(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        assert_ne!(ok, 0, "CreateProcessW: {}", io::Error::last_os_error());
        // SAFETY: our copies; the child has its own.
        unsafe {
            CloseHandle(w);
            CloseHandle(pi.hThread);
        }
        let mut out = Vec::new();
        // SAFETY: the read end, owned from here; it ends when the child does.
        std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(r) })
            .read_to_end(&mut out)
            .unwrap();
        let mut code = 0u32;
        // SAFETY: the child's process handle, ours to wait on and close.
        unsafe {
            WaitForSingleObject(pi.hProcess, u32::MAX);
            assert_ne!(GetExitCodeProcess(pi.hProcess, &mut code), 0);
            CloseHandle(pi.hProcess);
        }
        let text = String::from_utf8_lossy(&out);
        // The child's CONSOLETEST lines, for the log (--nocapture).
        println!("{text}");
        assert!(code == 0 && text.contains("1 passed"), "exit {code}: {text}");
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

    // A full non-blocking pipe: a write fails with WSAEWOULDBLOCK (EAGAIN on
    // Linux, fs/pipe.c anon_pipe_write), where std's writer returns Ok(0) and
    // write_all WriteZero; after a read there is room again; with the reader
    // gone, BrokenPipe (EPIPE on Linux).
    #[test]
    fn test_a_full_pipe_writes_as_on_linux() {
        let (r, w) = pipe();
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        // SAFETY: our pipe's write end.
        assert_ne!(
            unsafe { SetNamedPipeHandleState(w, &mode, std::ptr::null(), std::ptr::null()) },
            0
        );
        let chunk = [7u8; 1000];
        let mut total = 0usize;
        let err = loop {
            match write_handle(w, &chunk) {
                Ok(n) => {
                    assert!(n > 0, "a write that takes nothing fails");
                    total += n;
                    assert!(total < 64 << 20, "the pipe never filled");
                }
                Err(e) => break e,
            }
        };
        assert!(total > 0);
        assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK));
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        // std's writer on the same handle: 0 bytes, which write_all reports
        // as WriteZero; what this module is for.
        let file = std::mem::ManuallyDrop::new(
            // SAFETY: borrowed; ManuallyDrop keeps it from closing the handle.
            unsafe { std::fs::File::from_raw_handle(w) },
        );
        assert_eq!((&*file).write(&chunk).unwrap(), 0, "std's write to a full pipe");
        let err = (&*file).write_all(&chunk).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero, "{err:?}");
        let mut buf = [0u8; 4096];
        assert!(read_handle(r, &mut buf).unwrap() > 0);
        assert_eq!(write_handle(w, &chunk[..1]).unwrap(), 1);
        // SAFETY: the reader, ours.
        unsafe { CloseHandle(r) };
        let err = write_handle(w, &chunk[..1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{err:?}");
        // SAFETY: the writer, ours.
        unsafe { CloseHandle(w) };
    }

    fn nowait_pipe() -> (HANDLE, HANDLE) {
        let (r, w) = pipe();
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        // SAFETY: our pipe's write end.
        assert_ne!(
            unsafe { SetNamedPipeHandleState(w, &mode, std::ptr::null(), std::ptr::null()) },
            0
        );
        (r, w)
    }

    /// Reads the pipe to its end, once its writers are closed.
    fn read_to_end(r: HANDLE) -> Vec<u8> {
        let mut all = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = read_handle(r, &mut buf).unwrap();
            if n == 0 {
                return all;
            }
            all.extend_from_slice(&buf[..n]);
        }
    }

    // A line that does not fit in a non-blocking pipe is refused whole, as
    // on Linux for up to PIPE_BUF bytes (pipe(7), "O_NONBLOCK enabled, n <=
    // PIPE_BUF"): the reader never gets the first part of it. Two pipes,
    // filled in lines of 1000 and of 999 bytes after one byte: whatever a
    // pipe holds, it is not full to the byte in both, so one refused line
    // at least had room for a part (CI run 43323860314: a pipe of 4096
    // bytes with 4000 in it refused 1000).
    #[test]
    fn test_a_write_that_does_not_fit_takes_nothing() {
        let fill = |len: usize| {
            let (r, w) = nowait_pipe();
            let line = vec![b'.'; len];
            assert_eq!(write_handle(w, b"1").unwrap(), 1);
            let mut total = 1usize;
            let err = loop {
                match write_handle(w, &line) {
                    Ok(n) => {
                        assert_eq!(n, len, "a line is taken whole or refused");
                        total += n;
                        assert!(total < 64 << 20, "the pipe never filled");
                    }
                    Err(e) => break e,
                }
            };
            assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK));
            let room_left = write_handle(w, b"2").is_ok();
            // SAFETY: the writer, ours.
            unsafe { CloseHandle(w) };
            let held = read_to_end(r);
            // SAFETY: the reader, ours.
            unsafe { CloseHandle(r) };
            assert_eq!(held.len(), total + usize::from(room_left), "nothing of the refused line");
            println!("lines of {len}: {total} bytes taken, then one refused; room for a byte more: {room_left}");
            room_left
        };
        let (a, b) = (fill(1000), fill(999));
        assert!(a || b, "neither refused line had room for a part of it");
    }

    // A write of more than PIPE_BUF bytes is taken as far as it fits, as on
    // Linux (pipe(7), "n > PIPE_BUF": "from 1 to n bytes may be written"),
    // where Windows refuses it whole (CI run 43323860314: 1 MiB into an
    // empty pipe takes 0 bytes): 70 KiB into an empty pipe, as upstream's
    // unix test of a full pipe writes them (the vmm's
    // nonblocking_pipe_tests).
    #[test]
    fn test_a_large_write_is_taken_as_far_as_it_fits() {
        const LEN: usize = 70 * 1024;
        let (r, w) = nowait_pipe();
        let big = vec![7u8; LEN];
        let taken = write_handle(w, &big).unwrap();
        println!("a write of {LEN} bytes into the empty pipe took {taken}");
        assert!(taken > 0 && taken < LEN, "{taken}");
        assert_eq!(taken % PIPE_BUF, 0, "whole pieces");
        let err = write_handle(w, &big).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK));
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        // SAFETY: the writer, ours.
        unsafe { CloseHandle(w) };
        let held = read_to_end(r);
        assert!(held.len() == taken && held.iter().all(|&b| b == 7), "{}", held.len());
        // SAFETY: the reader, ours.
        unsafe { CloseHandle(r) };
    }

    // A pipe that holds less than a page, which Linux has none of
    // (CreatePipe with nSize 512 holds 512 bytes, CI run 43341846250): a
    // write larger than the pipe goes in pieces of what it holds; up to
    // that, a write is whole or refused.
    #[test]
    fn test_a_write_larger_than_a_small_pipe_goes_in_pieces() {
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out-pointers to handles.
        assert_ne!(unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 512) }, 0);
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        // SAFETY: our pipe's write end.
        assert_ne!(
            unsafe { SetNamedPipeHandleState(w, &mode, std::ptr::null(), std::ptr::null()) },
            0
        );
        let data = [7u8; 1000];
        let mut buf = [0u8; 4096];
        assert_eq!(write_handle(w, &data).unwrap(), 512, "the first piece");
        let err = write_handle(w, &data).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK));
        assert_eq!(read_handle(r, &mut buf).unwrap(), 512);
        assert_eq!(write_handle(w, &data[..300]).unwrap(), 300);
        let err = write_handle(w, &data[..300]).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(WOULD_BLOCK), "212 bytes of room");
        assert_eq!(write_handle(w, &data[..212]).unwrap(), 212);
        assert_eq!(read_handle(r, &mut buf).unwrap(), 512);
        // SAFETY: our handles.
        unsafe {
            CloseHandle(w);
            CloseHandle(r);
        }
    }

    // No standard output (a NULL handle: ERROR_INVALID_HANDLE) takes the
    // whole write, as std's handle_ebadf makes it.
    #[test]
    fn test_no_output_takes_everything() {
        assert_eq!(write_handle(std::ptr::null_mut(), b"abc").unwrap(), 3);
    }

    #[test]
    fn test_stdout_is_the_standard_output() {
        let s = stdout();
        // SAFETY: plain call.
        let h = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        assert_eq!(s.as_raw_handle() as HANDLE, h);
        assert_eq!(s.as_raw_fd(), from_handle(h as RawHandle));
        assert_eq!(s.as_fd().as_raw_fd(), s.as_raw_fd());
        assert!(format!("{s:?}").starts_with("Stdout"));
        fn send_sync<T: Send + Sync + 'static>(_: &T) {}
        send_sync(&s);
        // An empty write, and a flush with nothing buffered, write nothing.
        assert_eq!((&s).write(b"").unwrap(), 0);
        (&s).flush().unwrap();
    }
}
