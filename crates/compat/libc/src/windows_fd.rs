// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! File descriptor calls on Windows.
//!
//! A descriptor is the value of a kernel handle (see `wick-os`); 0, 1
//! and 2 are the standard input, output and error handles, as kernel handle
//! values are never below 4. The calls go to Win32 or Winsock with Linux
//! semantics:
//! - `read`/`write` (and the vectored and positioned forms) on sockets use
//!   `recv`/`send`, on other handles `ReadFile`/`WriteFile`; a pipe whose
//!   writer is gone reads as end of file, a pipe whose reader is gone fails
//!   with `EPIPE`; `pread`/`pwrite` leave the file position alone;
//! - `write`/`writev` to a non-blocking pipe (`PIPE_NOWAIT`) follow Linux
//!   (pipe(7), "O_NONBLOCK enabled"; fs/pipe.c `anon_pipe_write`,
//!   `pipe_write` before v6.15): a write of at most `PIPE_BUF` (4096)
//!   bytes is taken whole, or fails with `EAGAIN` and nothing of it is
//!   taken; a larger one is taken as far as it fits, or fails with `EAGAIN`
//!   if nothing fits. Windows takes a non-blocking write to a byte pipe
//!   whole or not at all, whatever its size: when it does not fit in the
//!   room left, `WriteFile` returns TRUE with 0 bytes written (measured with
//!   no read waiting at the other end, CI
//!   run 43323860314: with 96 bytes free, 1000 bytes are refused and 16
//!   taken; 1 MiB into an empty pipe of 4096 or of 65536 bytes is refused).
//!   That is within `WriteFile`'s "returns TRUE with *lpNumberOfBytesWritten
//!   < nNumberOfBytesToWrite", and is not "after writing as many bytes as
//!   the buffer holds" (Named Pipe Type, Read, and Wait Modes). So up to
//!   `PIPE_BUF` the two agree
//!   (`test_a_small_write_that_does_not_fit_takes_nothing`), and a larger
//!   write that Windows refused whole is written here in pieces of
//!   `PIPE_BUF` until one is refused, each piece whole, as Linux fills a
//!   pipe page by page (`test_a_large_write_is_taken_as_far_as_it_fits`).
//!   With a read waiting at the other end Windows gives it its bytes
//!   first, and takes the rest whole or not at all (CI run 43341846250: a
//!   read of 10 waiting on a pipe of 4096, a write of 4106 is taken, of
//!   4107 only 10), so up to `PIPE_BUF` nothing changes, and the pieces
//!   go on from what the read took. One difference, in the pipe and not
//!   in the call: a Windows pipe can hold less than a page, which no Linux
//!   pipe does (`CreatePipe` with a size under 4096, in the same run), and
//!   a write of up to `PIPE_BUF` bytes that is larger than such a pipe
//!   could never be taken whole; it goes in pieces of what the pipe
//!   holds, so it can be taken in part
//!   (`test_a_write_larger_than_a_small_pipe_goes_in_pieces`).
//!   `test_non_blocking_pipe_writes_on_record` prints what `WriteFile`
//!   takes for each size, room, kind of pipe and with a read waiting;
//! - `read` on a timerfd returns its expiration count;
//! - `close`, `dup` and `dup2` keep the [`wick_fd`] attachments of a
//!   descriptor (an eventfd's counter, a timer's schedule) with every handle
//!   of it, as a duplicated descriptor shares its open file on Linux;
//! - `fcntl` supports `F_GETFD`/`F_SETFD` (`FD_CLOEXEC` is "not inherited"),
//!   `F_GETFL`/`F_SETFL` (`O_NONBLOCK` on sockets and pipes; on files, as on
//!   Linux, it changes nothing) and `F_DUPFD(_CLOEXEC)`;
//! - `fstat` fills a Linux `struct stat`: the file type, size, allocated
//!   blocks, links, volume and file index, and times.
//!
//! What Windows cannot do fails: `dup2` onto a value other than 0, 1 or 2
//! (handle values cannot be chosen) with `EBADF`, other `fcntl` commands with
//! `EINVAL`.

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use windows_sys::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE,
    ERROR_HANDLE_EOF, ERROR_NO_DATA, FILETIME, GetHandleInformation, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, SetHandleInformation, SetLastError,
};
use windows_sys::Win32::Networking::WinSock::{
    FIONBIO, FIONREAD, SO_TYPE, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, closesocket, getsockopt,
    ioctlsocket, recv, send,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_BEGIN, FILE_CURRENT, FILE_END,
    FILE_STANDARD_INFO, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, FileStandardInfo,
    FlushFileBuffers, GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileSizeEx,
    GetFileType, ReadFile, SetEndOfFile, SetFilePointerEx, WriteFile,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    SetStdHandle,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Pipes::{
    CreatePipe, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_WAIT, PeekNamedPipe, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::{c_int, c_void, iovec, size_t, ssize_t};

/// `off_t` with the Linux size.
pub type off_t = i64;

/// Standard input: descriptors 0-2 are the process's standard handles.
pub const STDIN_FILENO: c_int = 0;
/// Standard output.
pub const STDOUT_FILENO: c_int = 1;
/// Standard error.
pub const STDERR_FILENO: c_int = 2;

/// Read only (Linux value).
pub const O_RDONLY: c_int = 0;
/// Write only (Linux value).
pub const O_WRONLY: c_int = 1;
/// Read and write (Linux value).
pub const O_RDWR: c_int = 2;
/// Create (Linux value).
pub const O_CREAT: c_int = 0o100;
/// Exclusive create (Linux value).
pub const O_EXCL: c_int = 0o200;
/// Truncate (Linux value).
pub const O_TRUNC: c_int = 0o1000;
/// Append (Linux value).
pub const O_APPEND: c_int = 0o2000;
/// Non-blocking (Linux value).
pub const O_NONBLOCK: c_int = 0o4000;
/// Close on exec: not inherited (Linux value).
pub const O_CLOEXEC: c_int = 0o2_000_000;
/// Do not follow a final symbolic link (Linux value).
pub const O_NOFOLLOW: c_int = 0o400_000;

/// `fcntl`: duplicate.
pub const F_DUPFD: c_int = 0;
/// `fcntl`: get descriptor flags.
pub const F_GETFD: c_int = 1;
/// `fcntl`: set descriptor flags.
pub const F_SETFD: c_int = 2;
/// `fcntl`: get status flags.
pub const F_GETFL: c_int = 3;
/// `fcntl`: set status flags.
pub const F_SETFL: c_int = 4;
/// `fcntl`: duplicate, close on exec.
pub const F_DUPFD_CLOEXEC: c_int = 1030;
/// Descriptor flag: close on exec.
pub const FD_CLOEXEC: c_int = 1;

/// File type mask (Linux value).
pub const S_IFMT: u32 = 0o170_000;
/// Socket.
pub const S_IFSOCK: u32 = 0o140_000;
/// Regular file.
pub const S_IFREG: u32 = 0o100_000;
/// Directory.
pub const S_IFDIR: u32 = 0o040_000;
/// Character device.
pub const S_IFCHR: u32 = 0o020_000;
/// FIFO.
pub const S_IFIFO: u32 = 0o010_000;

/// `lseek` from the start.
pub const SEEK_SET: c_int = 0;
/// `lseek` from the position.
pub const SEEK_CUR: c_int = 1;
/// `lseek` from the end.
pub const SEEK_END: c_int = 2;
/// `lseek`: the next data at or after the offset.
pub const SEEK_DATA: c_int = 3;
/// `lseek`: the next hole at or after the offset (the end of the file is one).
pub const SEEK_HOLE: c_int = 4;

/// Sets errno to `e`, or to the `E*` constant of its meaning where `e` is
/// a Win32 or Winsock code Windows uses beside it
/// ([`crate::wick_errno_from_win32`]: `WSAEINVAL` is `EINVAL`,
/// `ERROR_HANDLE_DISK_FULL` `ENOSPC`), so that what upstream compares with
/// `libc::EX` matches whichever code the Windows call gave.
pub(crate) fn set_errno(e: c_int) {
    #[allow(clippy::cast_sign_loss)]
    // SAFETY: sets the thread's last error.
    unsafe {
        SetLastError(crate::wick_errno_from_win32(e) as u32)
    };
}

fn last_error() -> c_int {
    // SAFETY: reads the thread's last error.
    #[allow(clippy::cast_possible_wrap)]
    let e = unsafe { GetLastError() } as c_int;
    e
}

/// `-1`, with errno the error the last Windows call left as the `E*`
/// constant of its meaning ([`set_errno`]).
pub(crate) fn raw_failed<T: From<i8>>() -> T {
    set_errno(last_error());
    T::from(-1)
}

/// The handle `fd` names.
pub(crate) fn handle(fd: c_int) -> HANDLE {
    let std = match fd {
        0 => STD_INPUT_HANDLE,
        1 => STD_OUTPUT_HANDLE,
        2 => STD_ERROR_HANDLE,
        _ => return fd as isize as HANDLE,
    };
    // SAFETY: plain call.
    unsafe { GetStdHandle(std) }
}

#[allow(clippy::cast_possible_truncation)]
fn to_fd(h: HANDLE) -> c_int {
    h as isize as c_int
}

/// The descriptor of a handle.
pub(crate) fn to_fd_pub(h: HANDLE) -> c_int {
    to_fd(h)
}

fn socket(fd: c_int) -> usize {
    handle(fd) as usize
}

pub(crate) fn is_socket(fd: c_int) -> bool {
    socket_type(fd).is_some()
}

/// The socket's type (Winsock's `SO_TYPE`: 1 stream, 2 datagram, ...), or
/// `None` for a descriptor that is no socket.
fn socket_type(fd: c_int) -> Option<c_int> {
    wick_wsa_startup();
    let mut ty: c_int = 0;
    let mut len: c_int = 4;
    // SAFETY: the option value is an `i32`; a non-socket fails.
    let ok = unsafe {
        getsockopt(
            socket(fd),
            SOL_SOCKET,
            SO_TYPE,
            (&raw mut ty).cast(),
            &mut len,
        ) == 0
    };
    ok.then_some(ty)
}

/// Starts Winsock once, for calls on descriptors this process did not make.
pub(crate) fn wick_wsa_startup() {
    use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        // SAFETY: an all-zero WSADATA is a valid out-parameter.
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: plain call.
        unsafe { WSAStartup(0x0202, &mut data) };
    });
}

fn wsa_errno() {
    // SAFETY: reads the thread's last Winsock error.
    set_errno(unsafe { WSAGetLastError() });
}

/// Signals Windows does not raise, raised by this layer.
pub mod wick_signal {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BROKEN_PIPE: AtomicUsize = AtomicUsize::new(0);

    /// Sets what a write to a pipe or stream socket whose other end is gone
    /// calls besides failing: Linux sends the writing thread `SIGPIPE`
    /// (`write(2)`, `send(2)` without `MSG_NOSIGNAL`). wick's signal emulation
    /// (vmm-sys-util) sets it when a `SIGPIPE` handler is registered.
    pub fn set_broken_pipe_hook(hook: fn()) {
        BROKEN_PIPE.store(hook as usize, Ordering::Release);
    }

    /// Calls the hook, keeping the thread's error for the failed write.
    pub(crate) fn broken_pipe() {
        let f = BROKEN_PIPE.load(Ordering::Acquire);
        if f != 0 {
            let err = super::last_error();
            // SAFETY: only `fn()` values are stored, as `usize`.
            let f: fn() = unsafe { std::mem::transmute::<usize, fn()>(f) };
            f();
            super::set_errno(err);
        }
    }
}

/// `WSAESHUTDOWN`.
const WSAESHUTDOWN: c_int = 10058;

/// A Winsock error of a write whose peer is gone (WSAESHUTDOWN,
/// WSAECONNRESET, WSAECONNABORTED).
fn peer_gone(err: c_int) -> bool {
    matches!(err, WSAESHUTDOWN | crate::ECONNRESET | crate::ECONNABORTED)
}

/// Descriptor attachments: state that belongs to the object a descriptor
/// names (an eventfd's counter, a timer's schedule, status flags) and goes
/// with every descriptor of it.
pub mod wick_fd {
    use super::*;

    struct Entry {
        /// Our own handle of the object, to tell whether a descriptor value
        /// still names it after a close we did not see.
        own: HANDLE,
        state: Option<Arc<dyn Any + Send + Sync>>,
        flags: Arc<AtomicI32>,
    }

    // SAFETY: kernel handles may be used from any thread.
    unsafe impl Send for Entry {}

    impl Drop for Entry {
        fn drop(&mut self) {
            // SAFETY: closes the handle this entry owns.
            unsafe { CloseHandle(self.own) };
        }
    }

    fn table() -> &'static Mutex<HashMap<c_int, Entry>> {
        static T: OnceLock<Mutex<HashMap<c_int, Entry>>> = OnceLock::new();
        T.get_or_init(Mutex::default)
    }

    fn own(h: HANDLE) -> Option<HANDLE> {
        let mut out: HANDLE = std::ptr::null_mut();
        // SAFETY: duplicates a handle of this process.
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                h,
                GetCurrentProcess(),
                &mut out,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        (ok != 0).then_some(out)
    }

    std::thread_local! {
        static PROBING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Whether this thread is asking about a descriptor that may have been
    /// closed behind this table's back (by std, which closes handles
    /// itself): the question is meant to fail for one, as on Linux a closed
    /// descriptor answers `EBADF`. Under strict handle checks (a jailed
    /// Firecracker's sandbox) the reference raises `STATUS_INVALID_HANDLE`,
    /// which the sandbox lets the call return from (measured: continuable,
    /// the call then fails with `ERROR_INVALID_HANDLE`).
    pub fn probing() -> bool {
        PROBING.with(std::cell::Cell::get)
    }

    /// Runs `f`, which asks about a handle that may be closed (see
    /// [`probing`]).
    pub fn probe<T>(f: impl FnOnce() -> T) -> T {
        let was = PROBING.with(|p| p.replace(true));
        let r = f();
        PROBING.with(|p| p.set(was));
        r
    }

    /// Whether descriptor `fd` still names `own`'s object.
    fn same_object(fd: c_int, own: HANDLE) -> bool {
        // SAFETY: compares two handle values; `fd`'s may be closed.
        probe(|| unsafe { CompareObjectHandles(handle(fd), own) } != 0)
    }

    fn live(map: &mut HashMap<c_int, Entry>, fd: c_int) -> bool {
        let Some(e) = map.get(&fd) else {
            return false;
        };
        if same_object(fd, e.own) {
            true
        } else {
            map.remove(&fd);
            false
        }
    }

    /// The table's size at which [`insert`] next sweeps it.
    static NEXT_SWEEP: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(64);

    /// The table's size at which it is next swept, for the tests: the
    /// table is the process's, which tests running at once share.
    #[cfg(test)]
    pub(crate) fn next_sweep() -> usize {
        NEXT_SWEEP.load(Ordering::Relaxed)
    }

    /// Inserts an entry. Entries of descriptors closed without `close` here
    /// (by std, say) are swept whenever the table has doubled since the
    /// last sweep, so the table stays proportional to the live descriptors
    /// and closed objects are released.
    fn insert(map: &mut HashMap<c_int, Entry>, fd: c_int, entry: Entry) {
        map.insert(fd, entry);
        if map.len() >= NEXT_SWEEP.load(Ordering::Relaxed) {
            map.retain(|&fd, e| same_object(fd, e.own));
            NEXT_SWEEP.store((map.len() * 2).max(64), Ordering::Relaxed);
        }
    }

    /// Attaches `state` to `fd` (replacing what it had).
    pub fn attach(fd: c_int, state: Arc<dyn Any + Send + Sync>) -> std::io::Result<()> {
        let mut map = table().lock().unwrap();
        if live(&mut map, fd) {
            map.get_mut(&fd).unwrap().state = Some(state);
            return Ok(());
        }
        let own = own(handle(fd)).ok_or_else(std::io::Error::last_os_error)?;
        insert(
            &mut map,
            fd,
            Entry {
                own,
                state: Some(state),
                flags: Arc::default(),
            },
        );
        Ok(())
    }

    /// The state attached to `fd`, if it is a `T`.
    pub fn attached<T: Any + Send + Sync>(fd: c_int) -> Option<Arc<T>> {
        let mut map = table().lock().unwrap();
        if !live(&mut map, fd) {
            return None;
        }
        map.get(&fd)?.state.clone()?.downcast::<T>().ok()
    }

    /// Forgets `fd` (it is being closed).
    pub fn detach(fd: c_int) {
        table().lock().unwrap().remove(&fd);
    }

    /// Whether `fd` is `O_NONBLOCK` as this library knows it (`fcntl`'s
    /// `F_SETFL`, `SOCK_NONBLOCK`), without making it an entry.
    pub(crate) fn nonblocking(fd: c_int) -> bool {
        let mut map = table().lock().unwrap();
        live(&mut map, fd) && map[&fd].flags.load(Ordering::Relaxed) & crate::O_NONBLOCK != 0
    }

    /// The status flags (`O_NONBLOCK`) of `fd`'s open file.
    pub(crate) fn flags(fd: c_int) -> Arc<AtomicI32> {
        let mut map = table().lock().unwrap();
        if live(&mut map, fd) {
            return map[&fd].flags.clone();
        }
        let flags: Arc<AtomicI32> = Arc::default();
        if let Some(own) = own(handle(fd)) {
            insert(
                &mut map,
                fd,
                Entry {
                    own,
                    state: None,
                    flags: flags.clone(),
                },
            );
        }
        flags
    }

    fn drains() -> &'static Mutex<HashMap<c_int, Arc<std::sync::atomic::AtomicU64>>> {
        static D: OnceLock<Mutex<HashMap<c_int, Arc<std::sync::atomic::AtomicU64>>>> =
            OnceLock::new();
        D.get_or_init(Mutex::default)
    }

    /// The drain counter of `fd`, for edge-triggered polling (the Windows
    /// `epoll` of vmm-sys-util): bumped each time a reader of `fd` finds
    /// nothing to read. An edge-triggered registration that fired is armed
    /// again when it changes, which is when an edge-triggered reader (one
    /// that reads until `EAGAIN`) is done.
    pub fn drain_counter(fd: c_int) -> Arc<std::sync::atomic::AtomicU64> {
        drains().lock().unwrap().entry(fd).or_default().clone()
    }

    /// A reader of `fd` found nothing to read (`read` and `recv` here call it
    /// on `EAGAIN`; a reader that buffers, such as a framed stream, calls it
    /// when it has nothing left).
    pub fn drained(fd: c_int) {
        // Callers have just set errno (EAGAIN): keep it. Locking can reset the
        // thread's last error (TLS access does on some builds).
        // SAFETY: plain calls.
        let e = unsafe { GetLastError() };
        if let Some(c) = drains().lock().unwrap().get(&fd) {
            c.fetch_add(1, Ordering::Release);
        }
        // SAFETY: as above.
        unsafe { SetLastError(e) };
    }

    /// Stops counting drains of `fd` (its edge-triggered registration ended).
    pub fn forget_drains(fd: c_int) {
        drains().lock().unwrap().remove(&fd);
    }

    /// `new` is a duplicate of `old`: it shares its attachments.
    pub(crate) fn duplicated(old: c_int, new: c_int) {
        let mut map = table().lock().unwrap();
        if !live(&mut map, old) {
            return;
        }
        let (state, flags) = {
            let e = &map[&old];
            (e.state.clone(), e.flags.clone())
        };
        if let Some(own) = own(handle(new)) {
            insert(&mut map, new, Entry { own, state, flags });
        }
    }
}

fn read_handle(h: HANDLE, buf: *mut c_void, count: usize, at: Option<i64>) -> ssize_t {
    let len = u32::try_from(count).unwrap_or(u32::MAX);
    let mut n = 0u32;
    // SAFETY: an all-zero OVERLAPPED is valid.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ovp = match at {
        Some(off) => {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            {
                ov.Anonymous.Anonymous.Offset = off as u32;
                ov.Anonymous.Anonymous.OffsetHigh = (off >> 32) as u32;
            }
            &raw mut ov
        }
        None => std::ptr::null_mut(),
    };
    // SAFETY: the buffer is valid for `len` bytes (caller's contract).
    if unsafe { ReadFile(h, buf.cast(), len, &mut n, ovp) } == 0 {
        // SAFETY: plain call.
        match unsafe { GetLastError() } {
            ERROR_BROKEN_PIPE | ERROR_HANDLE_EOF => return 0,
            ERROR_NO_DATA => {
                set_errno(crate::EAGAIN);
                return -1;
            }
            _ => return raw_failed(),
        }
    }
    n as ssize_t
}

/// Linux's `PIPE_BUF`: a write of at most this many bytes to a pipe is
/// taken whole or not at all (pipe(7); include/uapi/linux/limits.h).
const PIPE_BUF: usize = 4096;

/// One `WriteFile` of `len` bytes: the bytes taken, or `None` with errno
/// set (`EPIPE`, and the `SIGPIPE` hook, when the pipe's reader is gone).
fn write_file(h: HANDLE, buf: *const u8, len: u32, ovp: *mut OVERLAPPED) -> Option<u32> {
    let mut n = 0u32;
    // SAFETY: the buffer is valid for `len` bytes (caller's contract).
    if unsafe { WriteFile(h, buf, len, &mut n, ovp) } == 0 {
        // SAFETY: plain call.
        if matches!(unsafe { GetLastError() }, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
            set_errno(crate::EPIPE);
            wick_signal::broken_pipe();
        }
        let _: ssize_t = raw_failed();
        return None;
    }
    Some(n)
}

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQueryInformationFile(
        h: HANDLE,
        io: *mut [usize; 2],
        info: *mut c_void,
        len: u32,
        class: u32,
    ) -> i32;
}

/// The most bytes a non-blocking write to the pipe `h` is taken whole or
/// not at all: `PIPE_BUF`, or what the pipe holds if that is less.
///
/// A Linux pipe holds at least a page (fs/pipe.c `pipe_set_size`,
/// `round_pipe_size`: a size is rounded up to whole pages), so a write of
/// `PIPE_BUF` bytes fits an empty one. A Windows pipe holds exactly the
/// bytes it was made with, also fewer than 4096 (measured, CI run
/// 43341846250: `CreatePipe` with nSize 1 holds 1 byte and with 512 holds
/// 512, a named pipe with buffers of 512 holds 512 and with 0 holds
/// nothing), and refuses whole a write larger than that for as long as no
/// read waits for it. What it holds is the quota of the queue this end
/// writes to (`FILE_PIPE_LOCAL_INFORMATION`, ntifs.h: `OutboundQuota` at
/// the server end, `InboundQuota` at the client end, by `NamedPipeEnd`).
/// A handle without `FILE_READ_ATTRIBUTES` cannot be asked (the server end
/// of an outbound named pipe: STATUS_ACCESS_DENIED in the same run); its
/// pipe is taken to hold a page, as a Linux pipe does.
fn pipe_atom(h: HANDLE) -> usize {
    let (mut io, mut info) = ([0usize; 2], [0u32; 10]);
    // SAFETY: a pipe handle and out-buffers of the sizes given (class 24,
    // FilePipeLocalInformation, 40 bytes).
    if unsafe { NtQueryInformationFile(h, &mut io, info.as_mut_ptr().cast(), 40, 24) } != 0 {
        return PIPE_BUF;
    }
    // NamedPipeEnd: FILE_PIPE_SERVER_END is 1.
    let quota = if info[9] == 1 { info[6] } else { info[4] };
    PIPE_BUF.min(quota as usize)
}

fn write_handle(h: HANDLE, buf: *const c_void, count: usize, at: Option<i64>) -> ssize_t {
    let len = u32::try_from(count).unwrap_or(u32::MAX);
    // SAFETY: an all-zero OVERLAPPED is valid.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ovp = match at {
        Some(off) => {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            {
                ov.Anonymous.Anonymous.Offset = off as u32;
                ov.Anonymous.Anonymous.OffsetHigh = (off >> 32) as u32;
            }
            &raw mut ov
        }
        None => std::ptr::null_mut(),
    };
    // SAFETY: the buffer is valid for `len` bytes (caller's contract).
    let Some(n) = write_file(h, buf.cast(), len, ovp) else {
        return -1;
    };
    let mut total = n as usize;
    // SAFETY: plain call.
    if total == count || at.is_some() || unsafe { GetFileType(h) } != FILE_TYPE_PIPE {
        return total as ssize_t;
    }
    // A pipe took less than it was given. A pipe in blocking mode does not
    // complete a write before all is written (SetNamedPipeHandleState,
    // PIPE_WAIT), so this is PIPE_NOWAIT, whoever set it: this descriptor,
    // a duplicate or another process, as the mode is the pipe end's
    // (test_pipe_wait_mode_is_shared_with_a_child_process), not only what
    // this process's flags table knows. Windows refused the write whole
    // (the module docs have the measurement).
    //
    // Linux takes what fits, page by page, and with O_NONBLOCK and no room
    // left returns what it has taken, or EAGAIN for nothing (fs/pipe.c
    // anon_pipe_write: `if (!ret) ret = -EAGAIN; break;`), never 0. Up to
    // PIPE_BUF that is all or nothing, which Windows has just done. Above
    // it, the write goes in pieces of PIPE_BUF, each taken whole or
    // refused, until one is refused. On a pipe that holds less than
    // PIPE_BUF the pieces are of what it holds, and so is the largest
    // write that is all or nothing (`pipe_atom`); one that holds nothing
    // takes only what a waiting read took.
    let atom = pipe_atom(h);
    if count > atom && atom > 0 {
        while total < count {
            #[allow(clippy::cast_possible_truncation)]
            let piece = (count - total).min(atom) as u32;
            // SAFETY: `total < count`: the piece lies in the caller's buffer.
            let rest = unsafe { buf.cast::<u8>().add(total) };
            match write_file(h, rest, piece, std::ptr::null_mut()) {
                // The reader went away meanwhile: EPIPE if nothing was
                // written, else the count (Linux sends SIGPIPE in both:
                // anon_pipe_write, `send_sig(SIGPIPE, current, 0); if (!ret)
                // ret = -EPIPE;`).
                None if total == 0 => return -1,
                None => break,
                Some(n) => {
                    total += n as usize;
                    if n < piece {
                        break;
                    }
                }
            }
        }
    }
    if total == 0 {
        set_errno(crate::EAGAIN);
        return -1;
    }
    total as ssize_t
}

#[cfg(test)]
std::thread_local! {
    /// The one test seam of the calls that copy guest memory: when set, run
    /// on the calling thread once the buffer's pages are faulted in and
    /// right before the system call (the window in which a discard of the
    /// buffer fails the call, docs/COMPATIBILITY.md, the `mem_backend: Uffd`
    /// row).
    pub(crate) static BEFORE_CALL: std::cell::RefCell<Option<std::boxed::Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

/// Runs [`BEFORE_CALL`] in a test build; nothing otherwise.
fn before_call() {
    #[cfg(test)]
    BEFORE_CALL.with(|hook| {
        if let Some(f) = hook.borrow_mut().as_mut() {
            f();
        }
    });
}

/// Whether a call on `fd` may wait without end: not a regular file's
/// (`FILE_TYPE_DISK`), and not `O_NONBLOCK` as this library knows it. A
/// socket made non-blocking past this library (wick_os's `ioctlsocket`) is
/// taken as blocking: its calls on mapped memory go through a buffer of
/// their own, a copy more, and never hold a discard
/// ([`crate::windows_mm::copying`]).
fn may_block(fd: c_int) -> bool {
    // SAFETY: plain call; a closed descriptor's call fails after.
    if !is_socket(fd) && unsafe { GetFileType(handle(fd)) } == FILE_TYPE_DISK {
        return false;
    }
    !wick_fd::nonblocking(fd)
}

/// Whether a read of `fd` returns at once, with what has arrived: bytes
/// waiting on a socket (`FIONREAD`) or in a pipe (`PeekNamedPipe`). Such a
/// read on mapped memory is counted in flight ([`read`]) rather than made
/// through a copy: vsock's reads, on sockets made non-blocking through
/// wick_os ([`may_block`]), come when its event loop finds them readable.
/// A second reader of the same descriptor taking the bytes first leaves
/// this read waiting, and a discard of its buffer with it, until more come.
fn has_data(fd: c_int) -> bool {
    if is_socket(fd) {
        let mut n = 0u32;
        // SAFETY: `FIONREAD` takes a `u32`.
        return unsafe { ioctlsocket(socket(fd), FIONREAD, &mut n) } == 0 && n > 0;
    }
    let mut avail = 0u32;
    // SAFETY: plain calls; the peek reads nothing.
    unsafe {
        GetFileType(handle(fd)) == FILE_TYPE_PIPE
            && PeekNamedPipe(handle(fd), std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut()) != 0
            && avail > 0
    }
}

std::thread_local! {
    /// This thread's buffer for the calls through a copy, kept between them.
    static COPY: core::cell::Cell<std::vec::Vec<u8>> = const { core::cell::Cell::new(std::vec::Vec::new()) };
}

/// Runs `f` on `n` bytes of this thread's [`COPY`] (taken out while `f`
/// runs, so that a call within `f` gets a buffer of its own).
fn with_copy<T>(n: usize, f: impl FnOnce(&mut [u8]) -> T) -> T {
    let mut v = COPY.take();
    if v.len() < n {
        v.resize(n, 0);
    }
    let r = f(&mut v[..n]);
    COPY.set(v);
    r
}

/// The most a call through a buffer of its own moves at once
/// ([`read_through_copy`], [`write_through_copy`]): a read of a pipe or a
/// socket gives what has arrived, so a shorter read is one Linux gives too;
/// a write goes on in pieces of this size.
const COPY_MAX: usize = 1 << 20;

/// A read on a descriptor that may wait without end ([`may_block`]) into
/// mapped memory: into a buffer of its own, copied into the caller's after,
/// as the guest's own access, which faults missing and lazy pages in. A
/// discard of the caller's buffer meanwhile ([`crate::windows_mm::copying`])
/// neither waits for the call nor fails it, as Linux's copy faults the page
/// in again. The buffer's pages are faulted in first and asked about
/// ([`crate::windows_mm::accessible`]), so that one Linux's copy would fail
/// fails with `EFAULT` before the call takes anything.
///
/// # Safety
/// `buf` must be valid for `count` bytes of writes.
unsafe fn read_through_copy(buf: *mut c_void, count: usize, call: impl FnOnce(*mut c_void, usize) -> ssize_t) -> ssize_t {
    let n = count.min(COPY_MAX);
    crate::wick_uffd::prefault(buf as u64, n as u64, true);
    if !crate::windows_mm::accessible(buf as usize, n, true) {
        set_errno(crate::EFAULT);
        return -1;
    }
    with_copy(n, |copy| {
        before_call();
        let r = call(copy.as_mut_ptr().cast(), n);
        if r > 0 {
            // SAFETY: `r` bytes of `copy` were read, and the caller's buffer
            // holds `n >= r`.
            unsafe { std::ptr::copy_nonoverlapping(copy.as_ptr(), buf.cast::<u8>(), r.unsigned_abs()) };
        }
        r
    })
}

/// A write on a descriptor that may wait without end ([`may_block`]) from
/// mapped memory: from a copy of the caller's buffer, made as the guest's
/// own access (the untouched lazy memory as the zeros it reads as, without
/// committing it, as [`from_lazy`]), in pieces of up to [`COPY_MAX`], each
/// one `emit`, stopping at a short piece or an error as a short write does.
/// A part of the buffer Linux's copy would fail (not readable once faulted
/// in) fails the write with `EFAULT`, or ends it short after what was
/// written.
///
/// # Safety
/// `buf` must be valid for `count` bytes of reads.
unsafe fn write_through_copy(buf: *const c_void, count: usize, emit: impl FnMut(*const c_void, usize) -> ssize_t) -> ssize_t {
    // SAFETY: the caller's contract.
    with_copy(count.min(COPY_MAX), |copy| unsafe { write_from_copy(buf, count, copy, emit) })
}

/// [`write_through_copy`] through `copy`.
///
/// # Safety
/// `buf` must be valid for `count` bytes of reads.
unsafe fn write_from_copy(buf: *const c_void, count: usize, copy: &mut [u8], mut emit: impl FnMut(*const c_void, usize) -> ssize_t) -> ssize_t {
    let mut total = 0usize;
    while total < count {
        let n = (count - total).min(COPY_MAX);
        let at = buf as usize + total;
        crate::wick_uffd::prefault_registered(at as u64, n as u64, false);
        let mut runs = std::vec::Vec::new();
        crate::windows_mm::zero_runs(at, n, |s, l, zeros| runs.push((s, l, zeros)));
        for (s, l, zeros) in runs {
            let piece = &mut copy[s - at..s - at + l];
            if zeros {
                piece.fill(0);
                continue;
            }
            crate::windows_mm::prefault_lazy(s, l);
            if !crate::windows_mm::accessible(s, l, false) {
                set_errno(crate::EFAULT);
                return if total > 0 { total as ssize_t } else { -1 };
            }
            // SAFETY: `[s, s + l)` is part of the caller's buffer, readable.
            unsafe { std::ptr::copy_nonoverlapping(s as *const u8, piece.as_mut_ptr(), l) };
        }
        before_call();
        let r = emit(copy.as_ptr().cast(), n);
        if r < 0 {
            return if total > 0 { total as ssize_t } else { -1 };
        }
        total += r.unsigned_abs();
        if r.unsigned_abs() < n {
            break;
        }
    }
    total as ssize_t
}

/// `read`. Into mapped memory, a call that ends (a regular file's, an
/// `O_NONBLOCK` descriptor's, one with bytes waiting: [`has_data`]) is
/// counted in flight on its buffer ([`crate::windows_mm::copying`]), and one
/// that may wait without end reads through a buffer of its own
/// ([`read_through_copy`]).
///
/// # Safety
/// `buf` must be valid for `count` bytes of writes.
pub unsafe fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    let mapped = crate::windows_mm::mapped(buf as usize, count);
    if mapped && may_block(fd) && !has_data(fd) {
        // SAFETY: `read_now` gets the copy, valid for its length.
        let call = |b, n| unsafe { read_now(fd, b, n) };
        // SAFETY: the caller's contract.
        return unsafe { read_through_copy(buf, count, call) };
    }
    // From before the prefault to the call's end.
    let _call = mapped.then(|| crate::windows_mm::copying(buf as usize, count));
    // Windows fails a read into missing userfaultfd pages; Linux waits.
    crate::wick_uffd::prefault(buf as u64, count as u64, true);
    before_call();
    // SAFETY: the caller's contract.
    unsafe { read_now(fd, buf, count) }
}

/// [`read`] into a buffer whose pages a system call can write.
///
/// # Safety
/// `buf` must be valid for `count` bytes of writes.
unsafe fn read_now(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    if let Some(timer) = crate::windows_time::lookup(fd) {
        // SAFETY: the caller's contract.
        let b = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), count) };
        return crate::windows_time::read(fd, &timer, b);
    }
    if is_socket(fd) {
        let len = i32::try_from(count).unwrap_or(i32::MAX);
        // SAFETY: the caller's contract.
        let n = unsafe { recv(socket(fd), buf.cast(), len, 0) };
        if n == SOCKET_ERROR {
            // WSAESHUTDOWN: this end's receiving was shut down, which
            // Linux's recv reads as the end (0).
            // SAFETY: reads the thread's last Winsock error.
            if unsafe { WSAGetLastError() } == WSAESHUTDOWN {
                return 0;
            }
            wsa_errno();
            if errno() == crate::EWOULDBLOCK {
                wick_fd::drained(fd);
            }
            return -1;
        }
        return n as ssize_t;
    }
    read_handle(handle(fd), buf, count, None)
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Zeros for the untouched lazy memory of a write's buffer ([`from_lazy`]).
static ZEROS: [u8; 64 << 10] = [0; 64 << 10];

/// A write of `count` bytes at `buf` through `emit` (one write call of the
/// target: a pointer and a length in, bytes written or -1 out), taking the
/// buffer's lazy memory that was never committed as the zeros it reads as,
/// without committing it. Linux's copy of a write's buffer maps its zero
/// page for an untouched anonymous page and charges nothing (mm/memory.c
/// v6.1 4088-4091, `do_anonymous_page`); here a system call fails on a page
/// that is only reserved, and committing it charged the whole of a guest a
/// snapshot wrote (the host-read plan's W1). The rest of the buffer is
/// committed where lazy, as before ([`crate::windows_mm::prefault_lazy`]).
///
/// A buffer with no such page is one write, as before. Else a write of up
/// to [`ZEROS`]' length, and a datagram, is one write of a copy (the zeros
/// and the buffer's other bytes), so that it stays whole as Linux's is (a
/// pipe's `PIPE_BUF`, a message); a longer one goes in pieces, the zeros
/// from [`ZEROS`], each piece where the one before ended (`emit` moves its
/// own offset), and stops at a short piece or an error, giving what was
/// written or -1, as a short write does. Pieces are separate writes: a
/// writer to the same file at the same time may land between them, where
/// Linux's write of a regular file holds the inode's lock for the whole.
fn from_lazy(fd: c_int, buf: *const c_void, count: usize, mut emit: impl FnMut(*const c_void, usize) -> ssize_t) -> ssize_t {
    crate::wick_uffd::prefault_registered(buf as u64, count as u64, false);
    before_call();
    let mut any = false;
    crate::windows_mm::zero_runs(buf as usize, count, |_, _, zeros| any |= zeros);
    if !any {
        crate::windows_mm::prefault_lazy(buf as usize, count);
        return emit(buf, count);
    }
    let mut runs = std::vec::Vec::new();
    crate::windows_mm::zero_runs(buf as usize, count, |s, n, zeros| runs.push((s, n, zeros)));
    // Winsock's SOCK_DGRAM.
    if count <= ZEROS.len() || socket_type(fd) == Some(2) {
        let mut copy = std::vec![0u8; count];
        for &(s, n, zeros) in &runs {
            if !zeros {
                crate::windows_mm::prefault_lazy(s, n);
                // SAFETY: `[s, s + n)` is part of the caller's buffer, valid
                // for reads, and of `copy` at the same offset.
                unsafe { std::ptr::copy_nonoverlapping(s as *const u8, copy.as_mut_ptr().add(s - buf as usize), n) };
            }
        }
        return emit(copy.as_ptr().cast(), count);
    }
    let mut total = 0usize;
    for (s, n, zeros) in runs {
        let mut at = 0;
        while at < n {
            let (p, len) = if zeros {
                (ZEROS.as_ptr().cast::<c_void>(), (n - at).min(ZEROS.len()))
            } else {
                crate::windows_mm::prefault_lazy(s + at, n - at);
                ((s + at) as *const c_void, n - at)
            };
            let r = emit(p, len);
            if r < 0 {
                return if total > 0 { total as ssize_t } else { -1 };
            }
            total += r.unsigned_abs();
            at += r.unsigned_abs();
            if r.unsigned_abs() < len {
                return total as ssize_t;
            }
        }
    }
    total as ssize_t
}

/// `write`. From mapped memory, a call that ends is counted in flight on
/// its buffer ([`crate::windows_mm::copying`]), and one that may wait
/// without end writes from a copy ([`write_through_copy`]).
///
/// # Safety
/// `buf` must be valid for `count` bytes of reads.
pub unsafe fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    let emit = |buf, count| {
        // SAFETY: a part of the caller's buffer, or a copy of it.
        unsafe { write_now(fd, buf, count) }
    };
    let mapped = crate::windows_mm::mapped(buf as usize, count);
    if mapped && may_block(fd) {
        // SAFETY: the caller's contract.
        return unsafe { write_through_copy(buf, count, emit) };
    }
    let _call = mapped.then(|| crate::windows_mm::copying(buf as usize, count));
    from_lazy(fd, buf, count, emit)
}

/// [`write`] of a buffer whose pages a system call can read.
///
/// # Safety
/// `buf` must be valid for `count` bytes of reads.
unsafe fn write_now(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    if let Some(limit) = grow_limit(fd) {
        let mut pos = 0i64;
        // SAFETY: queries the position.
        if unsafe { SetFilePointerEx(handle(fd), 0, &mut pos, FILE_CURRENT) } == 0 {
            return raw_failed();
        }
        let Some(count) = within(limit, pos, count) else {
            return -1;
        };
        return write_handle(handle(fd), buf, count, None);
    }
    if is_socket(fd) {
        let len = i32::try_from(count).unwrap_or(i32::MAX);
        // SAFETY: the caller's contract.
        let n = unsafe { send(socket(fd), buf.cast(), len, 0) };
        if n == SOCKET_ERROR {
            wsa_errno();
            if peer_gone(last_error()) {
                // WSAESHUTDOWN: Linux's send after a shutdown is EPIPE.
                if last_error() == WSAESHUTDOWN {
                    set_errno(crate::EPIPE);
                }
                wick_signal::broken_pipe();
            }
            return -1;
        }
        return n as ssize_t;
    }
    write_handle(handle(fd), buf, count, None)
}

/// Runs `f` and puts the file position back, as `pread`/`pwrite` do not
/// move it.
fn keeping_position(h: HANDLE, f: impl FnOnce() -> ssize_t) -> ssize_t {
    let mut pos = 0i64;
    // SAFETY: queries the position.
    if unsafe { SetFilePointerEx(h, 0, &mut pos, FILE_CURRENT) } == 0 {
        return raw_failed();
    }
    let r = f();
    let err = last_error();
    // SAFETY: restores the position.
    unsafe { SetFilePointerEx(h, pos, std::ptr::null_mut(), FILE_BEGIN) };
    set_errno(err);
    r
}

/// `pread`, as [`read`] for mapped memory.
///
/// # Safety
/// `buf` must be valid for `count` bytes of writes.
pub unsafe fn pread(fd: c_int, buf: *mut c_void, count: size_t, offset: off_t) -> ssize_t {
    let mapped = crate::windows_mm::mapped(buf as usize, count);
    if mapped && may_block(fd) && !has_data(fd) {
        // SAFETY: `pread_now` gets the copy, valid for its length.
        let call = |b, n| unsafe { pread_now(fd, b, n, offset) };
        // SAFETY: the caller's contract.
        return unsafe { read_through_copy(buf, count, call) };
    }
    let _call = mapped.then(|| crate::windows_mm::copying(buf as usize, count));
    crate::wick_uffd::prefault(buf as u64, count as u64, true);
    before_call();
    // SAFETY: the caller's contract.
    unsafe { pread_now(fd, buf, count, offset) }
}

/// [`pread`] into a buffer whose pages a system call can write, not counted
/// in flight: for `windows_mm`, which holds its table, filling its own
/// memory.
///
/// # Safety
/// `buf` must be valid for `count` bytes of writes.
pub(crate) unsafe fn pread_now(fd: c_int, buf: *mut c_void, count: size_t, offset: off_t) -> ssize_t {
    if offset < 0 {
        set_errno(crate::EINVAL);
        return -1;
    }
    let h = handle(fd);
    keeping_position(h, || read_handle(h, buf, count, Some(offset)))
}

/// `pwrite`.
///
/// # Safety
/// `buf` must be valid for `count` bytes of reads.
pub unsafe fn pwrite(fd: c_int, buf: *const c_void, count: size_t, offset: off_t) -> ssize_t {
    if offset < 0 {
        set_errno(crate::EINVAL);
        return -1;
    }
    let count = match grow_limit(fd) {
        Some(limit) => match within(limit, offset, count) {
            Some(n) => n,
            None => return -1,
        },
        None => count,
    };
    let h = handle(fd);
    let mut at = offset;
    let emit = |buf, count| {
        let n = write_handle(h, buf, count, Some(at));
        at += n.max(0) as i64;
        n
    };
    let mapped = crate::windows_mm::mapped(buf as usize, count);
    if mapped && may_block(fd) {
        // SAFETY: the caller's contract.
        return keeping_position(h, || unsafe { write_through_copy(buf, count, emit) });
    }
    let _call = mapped.then(|| crate::windows_mm::copying(buf as usize, count));
    keeping_position(h, || from_lazy(fd, buf, count, emit))
}

/// The size a memfd sealed against growing may not exceed.
fn grow_limit(fd: c_int) -> Option<u64> {
    wick_fd::attached::<crate::wick_mm::Section>(fd)
        .filter(|s| s.grow_sealed())
        .map(|s| s.size)
}

/// How much of a write of `count` at `pos` stays within `limit`: a write
/// that starts at or past it fails with `EPERM`, one that crosses it is
/// short, as Linux writes a sealed memfd page by page.
fn within(limit: u64, pos: i64, count: size_t) -> Option<size_t> {
    let pos = u64::try_from(pos).unwrap_or(0);
    if count > 0 && pos >= limit {
        set_errno(crate::EPERM);
        return None;
    }
    Some(count.min(usize::try_from(limit - pos.min(limit)).unwrap_or(usize::MAX)))
}

/// `readv`: fills the buffers in order, stopping at a short read.
///
/// # Safety
/// The buffers must be valid for writes.
pub unsafe fn readv(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    let Ok(cnt) = usize::try_from(iovcnt) else {
        set_errno(crate::EINVAL);
        return -1;
    };
    let mut total: ssize_t = 0;
    for i in 0..cnt {
        // SAFETY: the caller's contract.
        let v = unsafe { *iov.add(i) };
        if v.iov_len == 0 {
            continue;
        }
        // SAFETY: the caller's contract.
        let n = unsafe { read(fd, v.iov_base, v.iov_len) };
        if n < 0 {
            return if total > 0 { total } else { -1 };
        }
        total += n;
        if n.unsigned_abs() < v.iov_len {
            break;
        }
    }
    total
}

/// `writev`: writes the buffers in order, stopping at a short write.
///
/// # Safety
/// The buffers must be valid for reads.
pub unsafe fn writev(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    let Ok(cnt) = usize::try_from(iovcnt) else {
        set_errno(crate::EINVAL);
        return -1;
    };
    let mut total: ssize_t = 0;
    for i in 0..cnt {
        // SAFETY: the caller's contract.
        let v = unsafe { *iov.add(i) };
        if v.iov_len == 0 {
            continue;
        }
        // SAFETY: the caller's contract.
        let n = unsafe { write(fd, v.iov_base, v.iov_len) };
        if n < 0 {
            return if total > 0 { total } else { -1 };
        }
        total += n;
        if n.unsigned_abs() < v.iov_len {
            break;
        }
    }
    total
}

/// A handle of the file `h` opened for reading, closed when dropped.
struct Readable(HANDLE);

impl Drop for Readable {
    fn drop(&mut self) {
        // SAFETY: a handle opened by `readable`.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// Opens again the file `h` for reading only (`None`, with errno, if it
/// cannot be).
fn readable(h: HANDLE) -> Option<Readable> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    // SAFETY: reopens an open handle; the result is owned by `Readable`.
    let r = unsafe {
        ReOpenFile(
            h,
            FILE_READ_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if r == INVALID_HANDLE_VALUE || r.is_null() {
        set_errno(crate::EACCES);
        return None;
    }
    Some(Readable(r))
}

/// The allocated ranges of the file `h` in [from, to), in order.
fn allocated_ranges(h: HANDLE, from: i64, to: i64) -> Option<std::vec::Vec<(i64, i64)>> {
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES,
    };
    let mut out = std::vec::Vec::new();
    let mut at = from;
    while at < to {
        let query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: at,
            Length: to - at,
        };
        let mut buf = [FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: 0,
            Length: 0,
        }; 64];
        let mut n = 0u32;
        // SAFETY: valid input and output buffers.
        let ok = unsafe {
            DeviceIoControl(
                h,
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&raw const query).cast(),
                u32::try_from(std::mem::size_of_val(&query)).unwrap(),
                buf.as_mut_ptr().cast(),
                u32::try_from(std::mem::size_of_val(&buf)).unwrap(),
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 && last_error() == ERROR_ACCESS_DENIED.cast_signed() {
            // The query needs read access, which `lseek` does not on Linux
            // (a snapshot memory file is opened write-only): ask a handle of
            // the same file opened for reading.
            return readable(h).and_then(|r| allocated_ranges(r.0, from, to));
        }
        if ok == 0 && last_error() != ERROR_MORE_DATA.cast_signed() {
            return None;
        }
        let count = n as usize / std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        for r in &buf[..count] {
            out.push((r.FileOffset, r.FileOffset + r.Length));
        }
        if ok != 0 || count == 0 {
            break;
        }
        at = out.last().map_or(to, |r| r.1);
    }
    Some(out)
}

/// `SEEK_DATA`/`SEEK_HOLE`: from the file's allocated ranges (a file that is
/// not sparse is all data). `ENXIO` at or past the end, as on Linux.
fn seek_data_hole(h: HANDLE, offset: i64, data: bool) -> Option<i64> {
    let mut size = 0i64;
    // SAFETY: valid out-parameter.
    if unsafe { GetFileSizeEx(h, &mut size) } == 0 {
        return None;
    }
    if offset < 0 || offset >= size {
        set_errno(if offset < 0 {
            crate::EINVAL
        } else {
            crate::ENXIO
        });
        return None;
    }
    let ranges = allocated_ranges(h, offset, size)?;
    let found = if data {
        ranges
            .iter()
            .find(|r| r.1 > offset)
            .map(|r| r.0.max(offset))
    } else {
        let mut at = offset;
        for r in &ranges {
            if r.0 > at {
                break;
            }
            at = at.max(r.1);
        }
        Some(at.min(size))
    };
    if found.is_none() {
        set_errno(crate::ENXIO);
    }
    found
}

/// `lseek`, with `SEEK_DATA` and `SEEK_HOLE`.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t {
    if whence == SEEK_DATA || whence == SEEK_HOLE {
        let h = handle(fd);
        let Some(to) = seek_data_hole(h, offset, whence == SEEK_DATA) else {
            return raw_failed();
        };
        // SAFETY: plain call.
        if unsafe { SetFilePointerEx(h, to, std::ptr::null_mut(), FILE_BEGIN) } == 0 {
            return raw_failed();
        }
        return to;
    }
    let method = match whence {
        SEEK_SET => FILE_BEGIN,
        SEEK_CUR => FILE_CURRENT,
        SEEK_END => FILE_END,
        _ => {
            set_errno(crate::EINVAL);
            return -1;
        }
    };
    let h = handle(fd);
    // SAFETY: plain call.
    let ty = unsafe { GetFileType(h) };
    if ty == FILE_TYPE_PIPE || ty == FILE_TYPE_CHAR {
        set_errno(crate::ESPIPE);
        return -1;
    }
    let mut pos = 0i64;
    // SAFETY: plain call.
    if unsafe { SetFilePointerEx(h, offset, &mut pos, method) } == 0 {
        return raw_failed();
    }
    pos
}

/// Whether the handle `h` was opened to write: its granted access
/// (`NtQueryObject`, `ObjectBasicInformation`) has `FILE_WRITE_DATA` or
/// `FILE_APPEND_DATA`. `None` if it cannot be queried.
fn may_write(h: HANDLE) -> Option<bool> {
    use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
    use windows_sys::Win32::Storage::FileSystem::{FILE_APPEND_DATA, FILE_WRITE_DATA};
    use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;
    let mut info = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    // SAFETY: an output buffer of the size passed.
    let status = unsafe {
        NtQueryObject(
            h,
            ObjectBasicInformation,
            (&raw mut info).cast(),
            u32::try_from(std::mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>()).unwrap(),
            std::ptr::null_mut(),
        )
    };
    (status >= 0).then_some(info.GrantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0)
}

/// `fsync`. Linux asks no write access of the descriptor (fs/sync.c:
/// `do_fsync`, `vfs_fsync_range`), so a file opened read-only (a read-only
/// drive) syncs; `FlushFileBuffers` fails on a handle without
/// `GENERIC_WRITE` (Microsoft's documentation of it) with
/// `ERROR_ACCESS_DENIED`. Through a handle of a file that cannot write
/// nothing was written, so it succeeds here without a flush. (Linux would
/// also write back what other descriptors of the file wrote; Windows lets
/// no handle without write access flush.)
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn fsync(fd: c_int) -> c_int {
    let h = handle(fd);
    // SAFETY: plain call.
    if unsafe { GetFileType(h) } == FILE_TYPE_DISK && may_write(h) == Some(false) {
        return 0;
    }
    // SAFETY: plain call.
    if unsafe { FlushFileBuffers(h) } == 0 {
        return raw_failed();
    }
    0
}

/// `fdatasync`: as `fsync`; Windows has no data-only flush.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn fdatasync(fd: c_int) -> c_int {
    // SAFETY: as above.
    unsafe { fsync(fd) }
}

/// `ftruncate`; the file position is left alone.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn ftruncate(fd: c_int, length: off_t) -> c_int {
    if length < 0 {
        set_errno(crate::EINVAL);
        return -1;
    }
    if let Some(s) = wick_fd::attached::<crate::wick_mm::Section>(fd) {
        // A sealed memfd: no shrinking (Windows also refuses below the
        // section), and no growing under F_SEAL_GROW.
        let mut size = 0i64;
        // SAFETY: valid out-parameter.
        if unsafe { GetFileSizeEx(handle(fd), &mut size) } == 0 {
            return raw_failed();
        }
        if length < size || (length > size && s.grow_sealed()) {
            set_errno(crate::EPERM);
            return -1;
        }
    }
    let h = handle(fd);
    let r = keeping_position(h, || {
        // SAFETY: plain calls on the caller's handle.
        unsafe {
            if SetFilePointerEx(h, length, std::ptr::null_mut(), FILE_BEGIN) == 0
                || SetEndOfFile(h) == 0
            {
                raw_failed()
            } else {
                0
            }
        }
    });
    #[allow(clippy::cast_possible_truncation)]
    let r = r as c_int;
    r
}

/// `close`.
///
/// # Safety
/// `fd` must be a descriptor the caller owns.
pub unsafe fn close(fd: c_int) -> c_int {
    wick_fd::detach(fd);
    if is_socket(fd) {
        // SAFETY: the caller's contract.
        if unsafe { closesocket(socket(fd)) } != 0 {
            wsa_errno();
            return -1;
        }
        return 0;
    }
    // SAFETY: the caller's contract.
    if unsafe { CloseHandle(handle(fd)) } == 0 {
        set_errno(crate::EBADF);
        return -1;
    }
    0
}

fn dup_inherit(fd: c_int, inherit: bool) -> c_int {
    // A new descriptor: refused past the jail's no-file limit.
    if !crate::wick_nofile::room(1) {
        return -1;
    }
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process. Sockets are duplicated
    // the same way: Winsock duplicates in-process handles correctly for the
    // base providers, which are the only ones wick uses.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle(fd),
            GetCurrentProcess(),
            &mut out,
            0,
            i32::from(inherit),
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        set_errno(crate::EBADF);
        return -1;
    }
    let new = to_fd(out);
    wick_fd::duplicated(fd, new);
    new
}

/// `dup`: the new descriptor is inherited by children, as on Linux.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn dup(fd: c_int) -> c_int {
    dup_inherit(fd, true)
}

/// `dup2`: only onto the standard descriptors 0, 1 and 2, as Windows does
/// not let handle values be chosen; other targets fail with `EBADF`, and so
/// does a target at or past the no-file limit, as Linux's `ksys_dup3` checks
/// (linux v6.12 fs/file.c). It fills a slot that exists, so it is not
/// refused with `EMFILE` (`crate::wick_nofile`).
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let std = match newfd {
        0 => STD_INPUT_HANDLE,
        1 => STD_OUTPUT_HANDLE,
        2 => STD_ERROR_HANDLE,
        _ => {
            set_errno(crate::EBADF);
            return -1;
        }
    };
    if crate::wick_nofile::limit().is_some_and(|limit| u64::try_from(newfd).unwrap_or(0) >= limit) {
        set_errno(crate::EBADF);
        return -1;
    }
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process, inherited by children.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle(oldfd),
            GetCurrentProcess(),
            &mut out,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        set_errno(crate::EBADF);
        return -1;
    }
    // Not `dup_inherit`: the slot exists, so no EMFILE (above).
    let new = to_fd(out);
    wick_fd::duplicated(oldfd, new);
    // SAFETY: plain call; the duplicate becomes the standard handle.
    if unsafe { SetStdHandle(std, handle(new)) } == 0 {
        return raw_failed();
    }
    newfd
}

fn inherits(fd: c_int) -> Option<bool> {
    let mut flags = 0u32;
    // SAFETY: plain call.
    if unsafe { GetHandleInformation(handle(fd), &mut flags) } == 0 {
        return None;
    }
    Some(flags & HANDLE_FLAG_INHERIT != 0)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn fcntl_impl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    let arg = arg as c_int;
    match cmd {
        F_GETFD => match inherits(fd) {
            Some(inherit) => {
                if inherit {
                    0
                } else {
                    FD_CLOEXEC
                }
            }
            None => {
                set_errno(crate::EBADF);
                -1
            }
        },
        F_SETFD => {
            let flags = if arg & FD_CLOEXEC != 0 {
                0
            } else {
                HANDLE_FLAG_INHERIT
            };
            // SAFETY: plain call.
            if unsafe { SetHandleInformation(handle(fd), HANDLE_FLAG_INHERIT, flags) } == 0 {
                set_errno(crate::EBADF);
                return -1;
            }
            0
        }
        F_GETFL => {
            if inherits(fd).is_none() {
                set_errno(crate::EBADF);
                return -1;
            }
            O_RDWR | wick_fd::flags(fd).load(Ordering::Relaxed)
        }
        F_SETFL => {
            let nonblock = arg & O_NONBLOCK != 0;
            if is_socket(fd) {
                let mut on = u32::from(nonblock);
                // SAFETY: `FIONBIO` takes a `u32`.
                if unsafe { ioctlsocket(socket(fd), FIONBIO, &mut on) } != 0 {
                    wsa_errno();
                    return -1;
                }
            } else {
                // SAFETY: plain call.
                if unsafe { GetFileType(handle(fd)) } == FILE_TYPE_PIPE {
                    // The wait mode belongs to the pipe end, so duplicates
                    // and inherited copies of the handle share it, as
                    // Linux's O_NONBLOCK is the open file description's
                    // (test_pipe_wait_mode_is_shared_by_duplicated_handles,
                    // test_pipe_wait_mode_is_shared_with_a_child_process).
                    let mode = PIPE_READMODE_BYTE | if nonblock { PIPE_NOWAIT } else { PIPE_WAIT };
                    // SAFETY: changes the mode of the caller's pipe handle.
                    if unsafe {
                        SetNamedPipeHandleState(
                            handle(fd),
                            &mode,
                            std::ptr::null(),
                            std::ptr::null(),
                        )
                    } == 0
                    {
                        return raw_failed();
                    }
                }
            }
            let flags = wick_fd::flags(fd);
            let mut v = flags.load(Ordering::Relaxed);
            v = if nonblock {
                v | O_NONBLOCK
            } else {
                v & !O_NONBLOCK
            };
            flags.store(v, Ordering::Relaxed);
            0
        }
        F_DUPFD | F_DUPFD_CLOEXEC => dup_inherit(fd, cmd == F_DUPFD),
        _ => {
            set_errno(crate::EINVAL);
            -1
        }
    }
}

// Windows passes variadic arguments like fixed ones on x86_64 and arm64, so
// the variadic `fcntl` binds to a fixed-argument function.
#[unsafe(no_mangle)]
extern "C" fn wick_compat_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    fcntl_impl(fd, cmd, arg)
}

unsafe extern "C" {
    /// `fcntl`; see the module documentation for the commands.
    #[link_name = "wick_compat_fcntl"]
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

/// `isatty`: 1 for a console, else 0 with `ENOTTY`.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn isatty(fd: c_int) -> c_int {
    let mut mode = 0u32;
    // SAFETY: plain call.
    if unsafe { GetConsoleMode(handle(fd), &mut mode) } != 0 {
        1
    } else {
        set_errno(crate::ENOTTY);
        0
    }
}

/// `struct stat` with the Linux x86_64 layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct stat {
    /// Device (volume serial number).
    pub st_dev: u64,
    /// Inode (file index).
    pub st_ino: u64,
    /// Hard links.
    pub st_nlink: u64,
    /// Type and permissions.
    pub st_mode: u32,
    /// Owner (0).
    pub st_uid: u32,
    /// Group (0).
    pub st_gid: u32,
    __pad0: i32,
    /// Device of a special file (0).
    pub st_rdev: u64,
    /// Size in bytes.
    pub st_size: i64,
    /// Preferred I/O size.
    pub st_blksize: i64,
    /// Allocated 512-byte blocks.
    pub st_blocks: i64,
    /// Access time, seconds.
    pub st_atime: i64,
    /// Access time, nanoseconds.
    pub st_atime_nsec: i64,
    /// Modification time, seconds.
    pub st_mtime: i64,
    /// Modification time, nanoseconds.
    pub st_mtime_nsec: i64,
    /// Change time, seconds.
    pub st_ctime: i64,
    /// Change time, nanoseconds.
    pub st_ctime_nsec: i64,
    __unused: [i64; 3],
}

fn unix_time(ft: FILETIME) -> (i64, i64) {
    #[allow(clippy::cast_possible_wrap)]
    let t = ((u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)) as i64;
    let t = t - 116_444_736_000_000_000;
    (t.div_euclid(10_000_000), t.rem_euclid(10_000_000) * 100)
}

/// `fstat`.
///
/// # Safety
/// `buf` must be valid for writes.
pub unsafe fn fstat(fd: c_int, buf: *mut stat) -> c_int {
    let h = handle(fd);
    let mut st = stat {
        st_blksize: 4096,
        ..stat::default()
    };
    if is_socket(fd) {
        st.st_mode = S_IFSOCK | 0o600;
    } else {
        // SAFETY: plain call.
        match unsafe { GetFileType(h) } {
            FILE_TYPE_PIPE => st.st_mode = S_IFIFO | 0o600,
            FILE_TYPE_CHAR => st.st_mode = S_IFCHR | 0o600,
            FILE_TYPE_DISK => {
                // SAFETY: an all-zero info is a valid out-parameter.
                let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
                // SAFETY: plain call.
                if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
                    return raw_failed();
                }
                // SAFETY: an all-zero info is a valid out-parameter.
                let mut std_info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
                // SAFETY: plain call with the size of the buffer.
                if unsafe {
                    GetFileInformationByHandleEx(
                        h,
                        FileStandardInfo,
                        (&raw mut std_info).cast(),
                        u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>()).unwrap(),
                    )
                } == 0
                {
                    return raw_failed();
                }
                let dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
                st.st_mode = if dir {
                    S_IFDIR | 0o755
                } else {
                    S_IFREG | 0o644
                };
                st.st_dev = u64::from(info.dwVolumeSerialNumber);
                st.st_ino = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
                st.st_nlink = u64::from(info.nNumberOfLinks);
                st.st_size = std_info.EndOfFile;
                st.st_blocks = (std_info.AllocationSize + 511) / 512;
                (st.st_atime, st.st_atime_nsec) = unix_time(info.ftLastAccessTime);
                (st.st_mtime, st.st_mtime_nsec) = unix_time(info.ftLastWriteTime);
                (st.st_ctime, st.st_ctime_nsec) = unix_time(info.ftLastWriteTime);
            }
            _ => {
                if inherits(fd).is_none() {
                    set_errno(crate::EBADF);
                    return -1;
                }
                // Events, timers, sections: no file type of their own on
                // Linux either (anonymous inodes).
                st.st_mode = 0o600;
            }
        }
    }
    // SAFETY: the caller's contract.
    unsafe { *buf = st };
    0
}

/// `pipe`: an anonymous pipe, read end first. Both ends are inherited by
/// children, as on Linux without `O_CLOEXEC`. `EMFILE` unless both fit
/// under the no-file limit (`crate::wick_nofile`).
///
/// # Safety
/// `fds` must be valid for two writes.
pub unsafe fn pipe(fds: *mut c_int) -> c_int {
    // Two new descriptors: refused past the jail's no-file limit.
    if !crate::wick_nofile::room(2) {
        return -1;
    }
    let mut r: HANDLE = std::ptr::null_mut();
    let mut w: HANDLE = std::ptr::null_mut();
    // SAFETY: plain call with out-parameters.
    if unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), 0) } == 0 {
        return raw_failed();
    }
    for h in [r, w] {
        // SAFETY: our new handles.
        unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
    }
    // SAFETY: the caller's contract.
    unsafe {
        *fds = to_fd(r);
        *fds.add(1) = to_fd(w);
    }
    0
}

/// `sysconf`: page size.
pub const _SC_PAGESIZE: c_int = 30;
/// `sysconf`: page size.
pub const _SC_PAGE_SIZE: c_int = 30;
/// `sysconf`: clock ticks per second.
pub const _SC_CLK_TCK: c_int = 2;
/// `sysconf`: open descriptor limit.
pub const _SC_OPEN_MAX: c_int = 4;
/// `sysconf`: configured processors.
pub const _SC_NPROCESSORS_CONF: c_int = 83;
/// `sysconf`: online processors.
pub const _SC_NPROCESSORS_ONLN: c_int = 84;
/// `sysconf`: physical pages.
pub const _SC_PHYS_PAGES: c_int = 85;

/// Most handles a Windows process can have.
const HANDLE_LIMIT: u64 = crate::wick_nofile::MAX;

/// `sysconf`.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn sysconf(name: c_int) -> crate::c_long {
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
    };
    use windows_sys::Win32::System::Threading::GetActiveProcessorCount;
    // SAFETY: an all-zero SYSTEM_INFO is a valid out-parameter.
    let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: plain call.
    unsafe { GetSystemInfo(&mut si) };
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    match name {
        _SC_PAGESIZE => si.dwPageSize as crate::c_long,
        _SC_CLK_TCK => 100,
        _SC_OPEN_MAX => crate::wick_nofile::limit().unwrap_or(HANDLE_LIMIT) as crate::c_long,
        _SC_NPROCESSORS_CONF => si.dwNumberOfProcessors as crate::c_long,
        // SAFETY: plain call; all processor groups.
        _SC_NPROCESSORS_ONLN => (unsafe { GetActiveProcessorCount(0xffff) }) as crate::c_long,
        _SC_PHYS_PAGES => {
            // SAFETY: an all-zero MEMORYSTATUSEX with its length is valid.
            let mut ms: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
            ms.dwLength = u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).unwrap();
            // SAFETY: plain call.
            if unsafe { GlobalMemoryStatusEx(&mut ms) } == 0 {
                return raw_failed();
            }
            (ms.ullTotalPhys / u64::from(si.dwPageSize)) as crate::c_long
        }
        _ => {
            set_errno(crate::EINVAL);
            -1
        }
    }
}

/// `rlim_t`.
pub type rlim_t = u64;
/// No limit.
pub const RLIM_INFINITY: rlim_t = u64::MAX;
/// `getrlimit` resource: open descriptors (Linux value).
pub const RLIMIT_NOFILE: c_int = 7;
/// `getrlimit` resource: the size of files written (Linux value). Windows has
/// no such limit: `getrlimit` reports `RLIM_INFINITY`.
pub const RLIMIT_FSIZE: c_int = 1;

/// `struct rlimit`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct rlimit {
    /// Soft limit.
    pub rlim_cur: rlim_t,
    /// Hard limit.
    pub rlim_max: rlim_t,
}

/// `getrlimit`: `RLIMIT_NOFILE` is the jail's no-file limit, soft and hard
/// (`crate::wick_nofile`), else Windows' per-process handle limit; the
/// other Linux resources (0..=15) have no Windows limit outside a job
/// object, so they report `RLIM_INFINITY`.
///
/// # Safety
/// `rlim` must be valid for writes.
pub unsafe fn getrlimit(resource: c_int, rlim: *mut rlimit) -> c_int {
    let v = match resource {
        RLIMIT_NOFILE => crate::wick_nofile::limit().unwrap_or(HANDLE_LIMIT),
        0..=15 => RLIM_INFINITY,
        _ => {
            set_errno(crate::EINVAL);
            return -1;
        }
    };
    // SAFETY: the caller's contract.
    unsafe {
        *rlim = rlimit {
            rlim_cur: v,
            rlim_max: v,
        }
    };
    0
}

/// `struct utsname` with the Linux layout.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct utsname {
    /// "Windows".
    pub sysname: [crate::c_char; 65],
    /// Computer name.
    pub nodename: [crate::c_char; 65],
    /// "major.minor.build".
    pub release: [crate::c_char; 65],
    /// Empty.
    pub version: [crate::c_char; 65],
    /// "x86_64" or "aarch64".
    pub machine: [crate::c_char; 65],
    /// Empty.
    pub domainname: [crate::c_char; 65],
}

fn put(dst: &mut [crate::c_char; 65], s: &[u8]) {
    for (d, b) in dst.iter_mut().zip(s.iter().take(64)) {
        *d = *b as crate::c_char;
    }
}

/// `uname`.
///
/// # Safety
/// `buf` must be valid for writes.
pub unsafe fn uname(buf: *mut utsname) -> c_int {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsHostname, GetComputerNameExA, OSVERSIONINFOW,
    };
    let mut u = utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    put(&mut u.sysname, b"Windows");
    let mut name = [0u8; 65];
    let mut len = 64u32;
    // SAFETY: the buffer holds `len` bytes.
    if unsafe { GetComputerNameExA(ComputerNameDnsHostname, name.as_mut_ptr(), &mut len) } != 0 {
        put(&mut u.nodename, &name[..len as usize]);
    }
    // SAFETY: an all-zero OSVERSIONINFOW with its size is valid.
    let mut vi: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    vi.dwOSVersionInfoSize = u32::try_from(std::mem::size_of::<OSVERSIONINFOW>()).unwrap();
    // SAFETY: plain call.
    unsafe { RtlGetVersion(&mut vi) };
    let release = std::format!(
        "{}.{}.{}",
        vi.dwMajorVersion,
        vi.dwMinorVersion,
        vi.dwBuildNumber
    );
    put(&mut u.release, release.as_bytes());
    put(&mut u.machine, std::env::consts::ARCH.as_bytes());
    // SAFETY: the caller's contract.
    unsafe { *buf = u };
    0
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::System::Pipes::GetNamedPipeInfo;

    use super::*;

    fn fd_of(f: &std::fs::File) -> c_int {
        to_fd(f.as_raw_handle())
    }

    /// `ioctl(FIONBIO)` sets and clears `O_NONBLOCK` as Linux's does (v6.1
    /// fs/ioctl.c:341-361 `ioctl_fionbio`, reached for any descriptor from
    /// `do_vfs_ioctl`, 788: the open file's `f_flags`), so `F_GETFL` shows
    /// it, on a pipe and on a socket, and the descriptor's calls stop
    /// waiting: a read of the empty pipe fails with `EAGAIN`.
    #[test]
    #[ignore = "written before ioctl(FIONBIO), which it tests; fails until it lands"]
    fn test_fionbio_sets_and_clears_o_nonblocking() {
        let mut fds = [0 as c_int; 2];
        // SAFETY: two descriptors' room.
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: plain call.
        let sock = unsafe { crate::socket(crate::AF_INET, crate::SOCK_STREAM, 0) };
        assert!(sock >= 0);
        for fd in [fds[0], sock] {
            for on in [1, 0, 1] {
                let mut arg: c_int = on;
                // SAFETY: `FIONBIO` takes an `int`.
                let r = unsafe { crate::ioctl(fd, crate::FIONBIO, &raw mut arg) };
                let error = std::io::Error::last_os_error();
                assert_eq!(r, 0, "ioctl(FIONBIO, {on}) of {fd}: {error}");
                // SAFETY: plain call.
                let flags = unsafe { fcntl(fd, F_GETFL) };
                assert_eq!(flags & O_NONBLOCK, if on == 1 { O_NONBLOCK } else { 0 }, "F_GETFL of {fd} after FIONBIO {on}");
            }
        }
        let mut b = [0u8; 1];
        // SAFETY: the pipe's read end, non-blocking now.
        let n = unsafe { read(fds[0], b.as_mut_ptr().cast(), 1) };
        assert_eq!((n, std::io::Error::last_os_error().raw_os_error()), (-1, Some(crate::EAGAIN)));
        // SAFETY: our descriptors.
        unsafe {
            close(fds[0]);
            close(fds[1]);
            close(sock);
        }
    }

    /// A blocking pipe's read into mapped memory it cannot write, and its
    /// write from mapped memory it cannot read, go through a copy
    /// ([`read_through_copy`], [`write_through_copy`]) and fail with
    /// `EFAULT` before the call, as Linux's copy fails them (v6.1
    /// fs/pipe.c `pipe_read`: `copy_page_to_iter` short, `-EFAULT`, the
    /// pipe's bytes left in it), not in a fault of the copy: the bytes stay
    /// in the pipe, and a read into a buffer of the heap then takes them.
    #[test]
    fn test_a_copy_through_unusable_mapped_memory_is_efault() {
        let mut fds = [0 as c_int; 2];
        // SAFETY: two descriptors' room.
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        let len = 64 * 1024;
        // SAFETY: new anonymous mappings.
        let (ro, none) = unsafe {
            (
                crate::mmap(std::ptr::null_mut(), len, crate::PROT_READ, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0),
                crate::mmap(std::ptr::null_mut(), len, crate::PROT_NONE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0),
            )
        };
        assert!(ro != crate::MAP_FAILED && none != crate::MAP_FAILED);
        let data = [7u8; 4];
        // SAFETY: the pipe's ends; the buffers as above.
        unsafe {
            assert_eq!(write(wr, data.as_ptr().cast(), 4), 4);
            let r = read(rd, ro, 4);
            assert_eq!((r, std::io::Error::last_os_error().raw_os_error()), (-1, Some(crate::EFAULT)), "a read into read-only memory");
            let w = write(wr, none, 4);
            assert_eq!((w, std::io::Error::last_os_error().raw_os_error()), (-1, Some(crate::EFAULT)), "a write from PROT_NONE memory");
            let mut got = [0u8; 8];
            assert_eq!(read(rd, got.as_mut_ptr().cast(), 8), 4, "the bytes left in the pipe");
            assert_eq!(got[..4], data);
            crate::munmap(ro, len);
            crate::munmap(none, len);
            close(rd);
            close(wr);
        }
    }

    fn temp(name: &str) -> (std::path::PathBuf, std::fs::File) {
        let p = std::env::temp_dir().join(std::format!("wick-libc-{}-{name}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        (p, f)
    }

    /// W1: `write`, `pwrite` and `writev` take the lazy memory of their
    /// buffer that was never committed as the zeros it reads as, without
    /// committing it, as Linux's copy maps its zero page for it and charges
    /// nothing: in pieces for a file (a buffer longer than the zeros' copy),
    /// as one copy for a short write and through a pipe. The bytes written
    /// are the buffer's, zeros where untouched; the memory's commit is what
    /// the test touched, before and after.
    #[test]
    fn test_a_write_from_lazy_memory_commits_nothing() {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, VirtualQuery};
        const PAGES: usize = 256;
        const PAGE: usize = 4096;
        let len = PAGES * PAGE;
        // SAFETY: lazy anonymous memory for the test, unmapped below.
        let m = unsafe {
            crate::windows_mm::mmap(
                std::ptr::null_mut(),
                len,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(m, crate::MAP_FAILED);
        let m = m as usize;
        let mut want = std::vec![0u8; len];
        for i in (0..PAGES).step_by(16) {
            let at = i * PAGE + 7;
            want[at] = u8::try_from(i / 16 + 1).unwrap();
            // SAFETY: our mapping.
            unsafe { *((m + at) as *mut u8) = want[at] };
        }
        let committed = || {
            let (mut at, mut n) = (m, 0);
            while at < m + len {
                // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                assert_ne!(unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
                let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(m + len) - at;
                if mbi.State == MEM_COMMIT {
                    n += run;
                }
                at += run;
            }
            n
        };
        assert_eq!(committed(), 16 * PAGE);
        let (p, f) = temp("lazy-write");
        let fd = fd_of(&f);
        let iov = [
            iovec { iov_base: (m + 100 * PAGE + 5) as *mut c_void, iov_len: 50 * PAGE },
            iovec { iov_base: m as *mut c_void, iov_len: 3 * PAGE },
        ];
        // SAFETY: our mapping and descriptor.
        unsafe {
            assert_eq!(write(fd, m as *const c_void, len), len as ssize_t, "a write in pieces");
            assert_eq!(pwrite(fd, (m + 30 * PAGE) as *const c_void, 8 * PAGE, (2 * len) as i64), (8 * PAGE) as ssize_t, "a copy");
            assert_eq!(lseek(fd, len as i64, SEEK_SET), len as i64);
            assert_eq!(writev(fd, iov.as_ptr(), 2), (53 * PAGE) as ssize_t);
        }
        assert_eq!(committed(), 16 * PAGE, "a write committed its buffer's untouched memory");
        let mut file = std::vec::Vec::new();
        std::io::Read::read_to_end(&mut std::fs::File::open(&p).unwrap(), &mut file).unwrap();
        assert_eq!(&file[..len], &want[..], "write");
        let at = 100 * PAGE + 5;
        assert_eq!(&file[len..len + 50 * PAGE], &want[at..at + 50 * PAGE], "writev's first buffer");
        assert_eq!(&file[len + 50 * PAGE..len + 53 * PAGE], &want[..3 * PAGE], "writev's second");
        assert_eq!(&file[2 * len..], &want[30 * PAGE..38 * PAGE], "pwrite");
        drop(f);
        std::fs::remove_file(p).unwrap();
        // Through a pipe, read on another thread.
        let mut fds = [0; 2];
        // SAFETY: a valid buffer.
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        let reader = fds[0];
        let got = std::thread::spawn(move || {
            let mut b = std::vec![0u8; 12 * PAGE];
            let mut n = 0;
            while n < b.len() {
                // SAFETY: our descriptor and buffer.
                let r = unsafe { read(reader, b[n..].as_mut_ptr().cast(), b.len() - n) };
                assert!(r > 0, "read {r}");
                n += r.unsigned_abs();
            }
            b
        });
        // SAFETY: our mapping and descriptor.
        assert_eq!(unsafe { write(fds[1], (m + 60 * PAGE) as *const c_void, 12 * PAGE) }, (12 * PAGE) as ssize_t);
        assert_eq!(got.join().unwrap(), &want[60 * PAGE..72 * PAGE], "the pipe");
        assert_eq!(committed(), 16 * PAGE);
        // SAFETY: our descriptors and mapping.
        unsafe {
            close(fds[0]);
            close(fds[1]);
            assert_eq!(crate::windows_mm::munmap(m as *mut c_void, len), 0);
        }
    }

    #[test]
    fn test_read_write_pread_lseek() {
        let (p, mut f) = temp("rw");
        f.write_all(b"0123456789").unwrap();
        let fd = fd_of(&f);
        // SAFETY: valid descriptor and buffers below.
        unsafe {
            assert_eq!(lseek(fd, 2, SEEK_SET), 2);
            let mut b = [0u8; 3];
            assert_eq!(pread(fd, b.as_mut_ptr().cast(), 3, 6), 3);
            assert_eq!(&b, b"678");
            assert_eq!(lseek(fd, 0, SEEK_CUR), 2, "pread keeps the position");
            assert_eq!(read(fd, b.as_mut_ptr().cast(), 3), 3);
            assert_eq!(&b, b"234");
            assert_eq!(pwrite(fd, b"ab".as_ptr().cast(), 2, 0), 2);
            assert_eq!(lseek(fd, 0, SEEK_CUR), 5);
            assert_eq!(
                pread(fd, b.as_mut_ptr().cast(), 3, 9),
                1,
                "short at the end"
            );
            assert_eq!(pread(fd, b.as_mut_ptr().cast(), 3, 20), 0, "end of file");
            // Not sparse: all data, the end is the only hole.
            // As on Linux and macOS, SEEK_DATA/SEEK_HOLE move the position to
            // the offset they return; a failed one leaves it alone.
            assert_eq!(lseek(fd, 1, SEEK_DATA), 1);
            assert_eq!(lseek(fd, 0, SEEK_CUR), 1, "SEEK_DATA moves the position");
            assert_eq!(lseek(fd, 1, SEEK_HOLE), 10);
            assert_eq!(lseek(fd, 0, SEEK_CUR), 10, "SEEK_HOLE moves the position");
            assert_eq!(lseek(fd, 10, SEEK_DATA), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(crate::ENXIO)
            );
            assert_eq!(lseek(fd, 0, SEEK_CUR), 10, "a failed SEEK_DATA keeps the position");
            assert_eq!(lseek(fd, 5, SEEK_SET), 5);
            assert_eq!(ftruncate(fd, 4), 0);
            let mut st = stat::default();
            assert_eq!(fstat(fd, &mut st), 0);
            assert_eq!(st.st_mode & S_IFMT, S_IFREG);
            assert_eq!(st.st_size, 4);
            assert_eq!(lseek(fd, 0, SEEK_CUR), 5, "ftruncate keeps the position");
        }
        drop(f);
        std::fs::remove_file(p).unwrap();
    }

    // A drive opened read-only syncs, as fsync(2) on an O_RDONLY descriptor
    // does on Linux; FlushFileBuffers itself refuses that handle (the
    // reason for the check); a writable file still flushes.
    #[test]
    fn test_fsync_of_a_read_only_file() {
        let (p, mut f) = temp("fsync");
        f.write_all(b"0123456789").unwrap();
        let fd = fd_of(&f);
        // SAFETY: a valid descriptor.
        unsafe {
            assert_eq!(fsync(fd), 0);
            assert_eq!(fdatasync(fd), 0);
        }
        drop(f);
        let r = std::fs::File::open(&p).unwrap();
        let fd = fd_of(&r);
        // SAFETY: a valid descriptor.
        unsafe {
            assert_eq!(FlushFileBuffers(handle(fd)), 0, "FlushFileBuffers on a read-only handle");
            assert_eq!(GetLastError(), ERROR_ACCESS_DENIED);
            assert_eq!(fsync(fd), 0, "fsync of a read-only file: {}", std::io::Error::last_os_error());
            assert_eq!(fdatasync(fd), 0);
        }
        assert_eq!(may_write(handle(fd)), Some(false));
        drop(r);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn test_seek_hole_write_only() {
        let (p, mut f) = temp("wo");
        f.write_all(b"0123456789").unwrap();
        drop(f);
        // A snapshot memory file is opened like this.
        let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        let fd = fd_of(&f);
        // SAFETY: a valid descriptor.
        unsafe {
            assert_eq!(lseek(fd, 1, SEEK_HOLE), 10);
            assert_eq!(lseek(fd, 1, SEEK_DATA), 1);
        }
        drop(f);
        std::fs::remove_file(p).unwrap();
    }

    // errno is the constant of what the Windows call meant: a synonym set
    // (WSAEINVAL) or left by a call (ERROR_HANDLE_DISK_FULL) is the constant.
    #[test]
    fn test_errno_is_the_constant_of_its_meaning() {
        set_errno(10022);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EINVAL));
        // SAFETY: sets the thread's last error.
        unsafe { SetLastError(39) };
        assert_eq!(raw_failed::<ssize_t>(), -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::ENOSPC));
        // SAFETY: as above.
        unsafe { SetLastError(1816) };
        assert_eq!(raw_failed::<c_int>(), -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::ENOMEM));
        set_errno(crate::EPIPE);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EPIPE));
    }

    #[test]
    fn test_pipe() {
        let mut fds = [0; 2];
        // SAFETY: valid buffers and descriptors.
        unsafe {
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let mut st = stat::default();
            assert_eq!(fstat(fds[0], &mut st), 0);
            assert_eq!(st.st_mode & S_IFMT, S_IFIFO);
            assert_eq!(lseek(fds[0], 0, SEEK_CUR), -1);
            assert_eq!(write(fds[1], b"hi".as_ptr().cast(), 2), 2);
            let mut b = [0u8; 8];
            assert_eq!(read(fds[0], b.as_mut_ptr().cast(), 8), 2);
            // Non-blocking read of an empty pipe.
            assert_eq!(fcntl(fds[0], F_SETFL, O_NONBLOCK), 0);
            assert_eq!(fcntl(fds[0], F_GETFL) & O_NONBLOCK, O_NONBLOCK);
            assert_eq!(read(fds[0], b.as_mut_ptr().cast(), 8), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(crate::EAGAIN)
            );
            // std reads the same empty non-blocking pipe as its end, Ok(0)
            // (measured: CI run 43277608081): ReadFile's ERROR_NO_DATA (232)
            // is ErrorKind::BrokenPipe (std sys/io/error/windows.rs,
            // decode_error_kind), which Handle::read returns as Ok(0)
            // (sys/pal/windows/handle.rs), as it does a closed writer's
            // ERROR_BROKEN_PIPE. A reader through std cannot tell an empty
            // pipe from a closed one; Firecracker's serial input reads
            // wick-std's Stdin (wick_os::stdio), which can.
            let reader = std::mem::ManuallyDrop::new(<std::fs::File as std::os::windows::io::FromRawHandle>::from_raw_handle(
                handle(fds[0]),
            ));
            let got = std::io::Read::read(&mut &*reader, &mut b).unwrap();
            assert_eq!(got, 0, "std's read of an empty non-blocking pipe");
            // End of file once the writer is gone.
            assert_eq!(close(fds[1]), 0);
            assert_eq!(fcntl(fds[0], F_SETFL, 0), 0);
            assert_eq!(read(fds[0], b.as_mut_ptr().cast(), 8), 0);
            assert_eq!(close(fds[0]), 0);
        }
    }

    // A full non-blocking pipe, as Firecracker leaves its standard output
    // when the serial writes there (upstream's set_stdout_nonblocking):
    // `write` here fails with EAGAIN, as on Linux. std on the same handle
    // gets a write of 0 bytes, which write_all reports as WriteZero, "failed
    // to write whole buffer": a non-blocking byte pipe takes nothing of a
    // write that does not fit and returns success (WriteFile, "Pipes":
    // "WriteFile returns TRUE with *lpNumberOfBytesWritten <
    // nNumberOfBytesToWrite"), and std's
    // Handle::write passes that on. How libtest lost its report in CI run
    // 43277608081 (cpu-template-helper; tools/windows/check-unit-tests.py).
    #[test]
    fn test_a_full_non_blocking_pipe() {
        let mut fds = [0; 2];
        // SAFETY: valid buffers and descriptors.
        unsafe {
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            assert_eq!(fcntl(fds[1], F_SETFL, O_NONBLOCK), 0);
            let chunk = [7u8; 4096];
            let mut total = 0usize;
            loop {
                let n = write(fds[1], chunk.as_ptr().cast(), chunk.len());
                if n < 0 {
                    break;
                }
                assert!(n > 0, "a write that takes nothing fails");
                total += n.unsigned_abs();
                assert!(total < 64 << 20, "the pipe never filled");
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(crate::EAGAIN)
            );
            assert!(total > 0);
            let writer = std::mem::ManuallyDrop::new(<std::fs::File as std::os::windows::io::FromRawHandle>::from_raw_handle(
                handle(fds[1]),
            ));
            let err = std::io::Write::write_all(&mut &*writer, b"more").unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::WriteZero, "{err:?}");
            assert_eq!(close(fds[1]), 0);
            assert_eq!(close(fds[0]), 0);
        }
    }

    // A pipe made non-blocking through another handle of its write end (a
    // duplicate here; in CI's case another process's inherited copy), which
    // this descriptor's flags do not show: once full, `write` and `writev`
    // still fail with EAGAIN as on Linux, never return 0. The pipe is filled
    // to its last byte first: a write of 1000 bytes is refused with less
    // room than that, and 16 bytes still fit then (CI run 43323860314: 4000
    // bytes in, 1000 refused, 16 taken).
    #[test]
    fn test_a_pipe_made_non_blocking_elsewhere_is_eagain_when_full() {
        let mut fds = [0; 2];
        // SAFETY: valid buffers, descriptors and handles.
        unsafe {
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let mut other: HANDLE = std::ptr::null_mut();
            assert_ne!(
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle(fds[1]),
                    GetCurrentProcess(),
                    &mut other,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                ),
                0
            );
            set_nowait(other);
            assert_eq!(fcntl(fds[1], F_GETFL) & O_NONBLOCK, 0, "this descriptor's flags do not know");
            let chunk = [7u8; 1000];
            let mut total = 0usize;
            for len in [chunk.len(), 1] {
                loop {
                    let n = write(fds[1], chunk.as_ptr().cast(), len);
                    if n < 0 {
                        break;
                    }
                    assert_eq!(n.unsigned_abs(), len, "a write of {len} is taken whole or fails");
                    total += len;
                    assert!(total < 64 << 20, "the pipe never filled");
                }
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EAGAIN));
                std::println!("{total} bytes in when a write of {len} was refused");
            }
            let iov = [iovec {
                iov_base: chunk.as_ptr().cast_mut().cast(),
                iov_len: 16,
            }];
            assert_eq!(writev(fds[1], iov.as_ptr(), 1), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EAGAIN));
            // Room again after a read, and the write goes through.
            let mut b = [0u8; 4096];
            assert!(read(fds[0], b.as_mut_ptr().cast(), b.len()) > 0);
            assert!(write(fds[1], chunk.as_ptr().cast(), 16) > 0);
            CloseHandle(other);
            assert_eq!(close(fds[1]), 0);
            assert_eq!(close(fds[0]), 0);
        }
    }

    #[test]
    fn test_cloexec_and_dup() {
        let (p, f) = temp("dup");
        let fd = fd_of(&f);
        // SAFETY: valid descriptors.
        unsafe {
            assert_eq!(fcntl(fd, F_SETFD, FD_CLOEXEC), 0);
            assert_eq!(fcntl(fd, F_GETFD), FD_CLOEXEC);
            assert_eq!(fcntl(fd, F_SETFD, 0), 0);
            assert_eq!(fcntl(fd, F_GETFD), 0);
            let d = dup(fd);
            assert!(d > 2);
            assert_eq!(write(d, b"x".as_ptr().cast(), 1), 1);
            assert_eq!(close(d), 0);
            assert_eq!(dup2(fd, 7), -1);
            assert_eq!(fcntl(fd, 999), -1);
        }
        drop(f);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn test_attachments_follow_dup() {
        let (p, f) = temp("attach");
        let fd = fd_of(&f);
        wick_fd::attach(fd, Arc::new(42u32)).unwrap();
        // SAFETY: valid descriptor.
        let d = unsafe { dup(fd) };
        assert_eq!(wick_fd::attached::<u32>(d).as_deref(), Some(&42));
        assert!(wick_fd::attached::<u64>(d).is_none(), "wrong type");
        // SAFETY: we own `d`.
        unsafe { close(d) };
        assert!(wick_fd::attached::<u32>(d).is_none());
        assert_eq!(wick_fd::attached::<u32>(fd).as_deref(), Some(&42));
        drop(f);
        // Closed behind our back: the value no longer names the object.
        assert!(wick_fd::attached::<u32>(fd).is_none());
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn test_attachments_of_std_closed_descriptors_are_released() {
        let state = Arc::new(7u32);
        let weak = Arc::downgrade(&state);
        let (p, f) = temp("swept");
        wick_fd::attach(fd_of(&f), state).unwrap();
        // Closed by std, never looked up again.
        drop(f);
        // The table grows (all open at once, so no value is reused and
        // replaces an entry), which sweeps entries of closed descriptors.
        let open: std::vec::Vec<_> = (0..200)
            .map(|_| {
                let g = std::fs::File::open(&p).unwrap();
                wick_fd::attach(fd_of(&g), Arc::new(0u8)).unwrap();
                g
            })
            .collect();
        assert!(weak.upgrade().is_none(), "swept");
        drop(open);
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn test_sysconf_getrlimit_uname() {
        // SAFETY: plain calls with valid out-parameters.
        unsafe {
            assert_eq!(sysconf(_SC_PAGESIZE), 4096);
            assert!(sysconf(_SC_NPROCESSORS_ONLN) >= 1);
            assert_eq!(sysconf(-5), -1);
            let mut r = rlimit::default();
            assert_eq!(getrlimit(RLIMIT_NOFILE, &mut r), 0);
            assert_eq!(r.rlim_cur, HANDLE_LIMIT);
            let mut u: utsname = std::mem::zeroed();
            assert_eq!(uname(&mut u), 0);
            assert_eq!(
                u.sysname[..7]
                    .iter()
                    .map(|c| *c as u8)
                    .collect::<std::vec::Vec<_>>(),
                b"Windows"
            );
        }
    }

    // --- Measurements of the pipe modes F_SETFL sets (PIPE_NOWAIT), which
    // the docs cite. The numbers are printed (--nocapture shows them); the
    // asserts are what the docs say of them.

    /// An anonymous pipe: (read end, write end), not inheritable.
    fn raw_pipe(size: u32) -> (HANDLE, HANDLE) {
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out-pointers to handles.
        assert_ne!(unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), size) }, 0);
        (r, w)
    }

    /// `FILE_PIPE_INFORMATION` of a pipe handle (ntifs.h; class 23 of
    /// `NtQueryInformationFile`): `(ReadMode, CompletionMode)`. A
    /// completion mode of 1 (FILE_PIPE_COMPLETE_OPERATION) is PIPE_NOWAIT.
    fn pipe_modes(h: HANDLE) -> (u32, u32) {
        let (mut io, mut info) = ([0usize; 2], [0u32; 2]);
        // SAFETY: a pipe handle and out-buffers of the sizes given.
        let status = unsafe { NtQueryInformationFile(h, &mut io, info.as_mut_ptr().cast(), 8, 23) };
        assert_eq!(status, 0, "NtQueryInformationFile(FilePipeInformation): {status:#x}");
        (info[0], info[1])
    }

    fn set_nowait(h: HANDLE) {
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        // SAFETY: a pipe handle of this process.
        let ok = unsafe { SetNamedPipeHandleState(h, &mode, std::ptr::null(), std::ptr::null()) };
        assert_ne!(ok, 0, "SetNamedPipeHandleState: {}", std::io::Error::last_os_error());
    }

    // Is the wait mode a handle's, or the pipe end's? PIPE_NOWAIT set on a
    // write end shows on a duplicate of that handle (the same file object),
    // and not on the read end.
    #[test]
    fn test_pipe_wait_mode_is_shared_by_duplicated_handles() {
        let (r, w) = raw_pipe(0);
        let mut w2: HANDLE = std::ptr::null_mut();
        // SAFETY: duplicates our handle.
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    w,
                    GetCurrentProcess(),
                    &mut w2,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let before = (pipe_modes(w), pipe_modes(w2), pipe_modes(r));
        set_nowait(w);
        let after = (pipe_modes(w), pipe_modes(w2), pipe_modes(r));
        std::println!(
            "(read mode, completion mode) of the write end, its duplicate, the read end: \
             {before:?}, then after PIPE_NOWAIT on the write end {after:?}"
        );
        assert_eq!(before, ((0, 0), (0, 0), (0, 0)));
        assert_eq!(after.0 .1, 1);
        assert_eq!(after.1 .1, 1, "the duplicate has the write end's PIPE_NOWAIT");
        assert_eq!(after.2 .1, 0, "the read end keeps its own wait mode");
        // SAFETY: our handles.
        unsafe {
            CloseHandle(w2);
            CloseHandle(w);
            CloseHandle(r);
        }
    }

    /// Tells `pipe_mode_child` the inherited handle to set PIPE_NOWAIT on.
    const MODE_CHILD_ENV: &str = "WICK_TEST_PIPE_MODE_CHILD";

    /// Sets PIPE_NOWAIT on a pipe handle it inherited, as a test binary
    /// does on the standard output cargo gave it. Run by
    /// `test_pipe_wait_mode_is_shared_with_a_child_process`.
    #[test]
    #[ignore = "the child of test_pipe_wait_mode_is_shared_with_a_child_process"]
    fn pipe_mode_child() {
        let Ok(h) = std::env::var(MODE_CHILD_ENV) else {
            return;
        };
        set_nowait(h.parse::<usize>().unwrap() as HANDLE);
        std::println!("PIPE-MODE-CHILD-OK");
    }

    // Across CreateProcess inheritance: a child sets PIPE_NOWAIT on its copy
    // of the write end, and the parent's handle has it after the child is
    // gone.
    #[test]
    fn test_pipe_wait_mode_is_shared_with_a_child_process() {
        if std::env::var_os(MODE_CHILD_ENV).is_some() {
            return;
        }
        let (r, w) = raw_pipe(0);
        // SAFETY: our handle, inherited by the child.
        assert_ne!(unsafe { SetHandleInformation(w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }, 0);
        let before = pipe_modes(w);
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "windows_fd::tests::pipe_mode_child", "--ignored", "--nocapture"])
            .env(MODE_CHILD_ENV, std::format!("{}", w as usize))
            .output()
            .unwrap();
        let text = std::string::String::from_utf8_lossy(&out.stdout).into_owned()
            + &std::string::String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && text.contains("PIPE-MODE-CHILD-OK"), "{text}");
        let after = pipe_modes(w);
        std::println!(
            "(read mode, completion mode) of the parent's write end: {before:?}, then after the \
             child's PIPE_NOWAIT on its inherited copy {after:?}"
        );
        assert_eq!(before.1, 0);
        assert_eq!(after.1, 1, "the child's PIPE_NOWAIT is the parent's too");
        // SAFETY: our handles.
        unsafe {
            CloseHandle(w);
            CloseHandle(r);
        }
    }

    // Linux's rule for a write of at most PIPE_BUF (4096) bytes to a
    // non-blocking pipe: taken whole, or EAGAIN and nothing of it taken
    // (pipe(7), "O_NONBLOCK enabled, n <= PIPE_BUF"; fs/pipe.c
    // anon_pipe_write, pipe_write before v6.15: a write of at most a page
    // merges whole into the last buffer or takes a buffer of its own, and
    // with none free returns EAGAIN with nothing written). Two pipes,
    // filled in writes of 3000 and of 2999 bytes after one byte: whatever a
    // pipe holds, it cannot be full to the byte in both, so in one at least
    // the refused write had room for part of it, and took none (CI run
    // 43323860314: a pipe of 4096 bytes took 1 + 3000, then refused 3000
    // with 1095 free).
    #[test]
    fn test_a_small_write_that_does_not_fit_takes_nothing() {
        let fill = |len: usize| {
            let mut fds = [0; 2];
            let chunk = std::vec![7u8; len];
            let mut total = 1usize;
            // SAFETY: valid buffers and descriptors.
            let room_left = unsafe {
                assert_eq!(pipe(fds.as_mut_ptr()), 0);
                assert_eq!(fcntl(fds[1], F_SETFL, O_NONBLOCK), 0);
                assert_eq!(write(fds[1], chunk.as_ptr().cast(), 1), 1);
                loop {
                    let n = write(fds[1], chunk.as_ptr().cast(), len);
                    if n < 0 {
                        break;
                    }
                    assert_eq!(n.unsigned_abs(), len, "a write of {len} is taken whole or fails");
                    total += len;
                    assert!(total < 64 << 20, "the pipe never filled");
                }
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(crate::EAGAIN)
                );
                // Whether the refused write had room for a part of it.
                let room_left = write(fds[1], chunk.as_ptr().cast(), 1) == 1;
                // Everything the pipe holds, to its end.
                assert_eq!(close(fds[1]), 0);
                let mut held = 0usize;
                let mut b = [0u8; 4096];
                loop {
                    let n = read(fds[0], b.as_mut_ptr().cast(), b.len());
                    assert!(n >= 0, "{}", std::io::Error::last_os_error());
                    if n == 0 {
                        break;
                    }
                    held += n.unsigned_abs();
                }
                assert_eq!(close(fds[0]), 0);
                assert_eq!(
                    held,
                    total + usize::from(room_left),
                    "the pipe holds the whole writes and nothing of the refused one"
                );
                room_left
            };
            std::println!(
                "writes of {len}: the pipe took {total} bytes, then refused {len}; room for \
                 one byte more: {room_left}"
            );
            room_left
        };
        let (a, b) = (fill(3000), fill(2999));
        assert!(a || b, "neither refused write had room for a part of it");
    }

    // Linux's rule for a larger write: taken as far as it fits, or EAGAIN
    // if nothing fits (pipe(7), "O_NONBLOCK enabled, n > PIPE_BUF": "from 1
    // to n bytes may be written"; fs/pipe.c: a page at a time while a
    // buffer is free, then `if (!ret) ret = -EAGAIN`). 70 KiB into an empty
    // pipe, more than Linux's 64 KiB and than CreatePipe's default: Windows
    // refuses it whole (CI run 43323860314: 1 MiB into an empty pipe takes
    // 0 bytes), and `write` gives it in pieces of PIPE_BUF.
    #[test]
    fn test_a_large_write_is_taken_as_far_as_it_fits() {
        const LEN: usize = 70 * 1024;
        let mut fds = [0; 2];
        let big = std::vec![7u8; LEN];
        // SAFETY: valid buffers and descriptors.
        unsafe {
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            assert_eq!(fcntl(fds[1], F_SETFL, O_NONBLOCK), 0);
            let n = write(fds[1], big.as_ptr().cast(), LEN);
            std::println!("a write of {LEN} bytes into the empty pipe took {n}");
            assert!(n > 0, "{}", std::io::Error::last_os_error());
            let taken = n.unsigned_abs();
            assert!(taken < LEN, "the pipe holds less than 70 KiB");
            assert_eq!(taken % PIPE_BUF, 0, "whole pieces");
            // Full for a write of this size now: EAGAIN, through writev too.
            assert_eq!(write(fds[1], big.as_ptr().cast(), LEN), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EAGAIN));
            let iov = [iovec {
                iov_base: big.as_ptr().cast_mut().cast(),
                iov_len: LEN,
            }];
            assert_eq!(writev(fds[1], iov.as_ptr(), 1), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EAGAIN));
            // What was taken is what the reader gets, and there is room again.
            let mut got = std::vec![0u8; LEN];
            let mut held = 0usize;
            while held < taken {
                let r = read(fds[0], got.as_mut_ptr().cast(), LEN);
                assert!(r > 0, "{}", std::io::Error::last_os_error());
                assert!(got[..r.unsigned_abs()].iter().all(|&b| b == 7));
                held += r.unsigned_abs();
            }
            assert_eq!(held, taken);
            assert_eq!(write(fds[1], big.as_ptr().cast(), LEN).unsigned_abs(), taken);
            assert_eq!(close(fds[1]), 0);
            assert_eq!(close(fds[0]), 0);
        }
    }

    // A pipe that holds less than a page, which Linux has none of
    // (fs/pipe.c round_pipe_size: `if (size < PAGE_SIZE) return
    // PAGE_SIZE;`): CreatePipe with nSize 512 holds 512 bytes (CI run
    // 43341846250). A write larger than the pipe could never be taken
    // whole, so it goes in pieces of what the pipe holds; up to that, a
    // write is whole or EAGAIN, as up to PIPE_BUF on a pipe of a page.
    #[test]
    fn test_a_write_larger_than_a_small_pipe_goes_in_pieces() {
        let (r, w) = raw_pipe(512);
        set_nowait(w);
        let (rfd, wfd) = (to_fd(r), to_fd(w));
        let data = [7u8; 1000];
        let mut b = [0u8; 4096];
        // SAFETY: valid buffers and descriptors.
        unsafe {
            assert_eq!(write(wfd, data.as_ptr().cast(), 1000), 512, "the first piece");
            assert_eq!(write(wfd, data.as_ptr().cast(), 1000), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EAGAIN));
            assert_eq!(read(rfd, b.as_mut_ptr().cast(), b.len()), 512);
            assert_eq!(write(wfd, data.as_ptr().cast(), 300), 300);
            assert_eq!(write(wfd, data.as_ptr().cast(), 300), -1, "212 bytes of room");
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EAGAIN));
            assert_eq!(write(wfd, data.as_ptr().cast(), 212), 212);
            assert_eq!(read(rfd, b.as_mut_ptr().cast(), b.len()), 512);
            assert_eq!(close(wfd), 0);
            assert_eq!(close(rfd), 0);
        }
    }

    // --- A record of what WriteFile takes on a non-blocking byte pipe
    // (PIPETEST lines): nothing here asserts a size. CI's last step runs it
    // alone with --nocapture. What `write` builds on is in the module docs;
    // these lines are where its numbers come from and what a change in
    // Windows would show in.

    /// `FILE_PIPE_LOCAL_INFORMATION` of a pipe handle (ntifs.h; class 24 of
    /// `NtQueryInformationFile`), as text; the status if the query fails.
    fn pipe_local(h: HANDLE) -> std::string::String {
        let (mut io, mut i) = ([0usize; 2], [0u32; 10]);
        // SAFETY: a pipe handle and out-buffers of the sizes given.
        let status = unsafe { NtQueryInformationFile(h, &mut io, i.as_mut_ptr().cast(), 40, 24) };
        if status != 0 {
            return std::format!("(local information: status {status:#x})");
        }
        std::format!(
            "(type {} configuration {} instances {}/{} InboundQuota {} ReadDataAvailable {} \
             OutboundQuota {} WriteQuotaAvailable {} state {} end {})",
            i[0], i[1], i[3], i[2], i[4], i[5], i[6], i[7], i[8], i[9]
        )
    }

    /// `GetNamedPipeInfo` of a pipe handle, as text.
    fn pipe_info(h: HANDLE) -> std::string::String {
        let (mut flags, mut out, mut inb, mut max) = (0u32, 0u32, 0u32, 0u32);
        // SAFETY: out-pointers to u32s.
        if unsafe { GetNamedPipeInfo(h, &mut flags, &mut out, &mut inb, &mut max) } == 0 {
            return std::format!("(GetNamedPipeInfo: {})", std::io::Error::last_os_error());
        }
        std::format!("(flags {flags:#x} OutBufferSize {out} InBufferSize {inb})")
    }

    /// One `WriteFile` of `len` bytes: the bytes taken, or -(error code).
    fn raw_write(h: HANDLE, len: usize) -> i64 {
        let data = std::vec![7u8; len];
        let mut taken = 0u32;
        // SAFETY: a valid buffer of `len` bytes.
        let ok = unsafe {
            WriteFile(h, data.as_ptr(), u32::try_from(len).unwrap(), &mut taken, std::ptr::null_mut())
        };
        if ok == 0 {
            // SAFETY: plain call.
            return -i64::from(unsafe { GetLastError() });
        }
        i64::from(taken)
    }

    /// One `ReadFile` of up to `len` bytes: the bytes read, or -(error code).
    fn raw_read(h: HANDLE, len: usize) -> i64 {
        let mut data = std::vec![0u8; len];
        let mut got = 0u32;
        // SAFETY: a valid buffer of `len` bytes.
        let ok = unsafe {
            ReadFile(h, data.as_mut_ptr(), u32::try_from(len).unwrap(), &mut got, std::ptr::null_mut())
        };
        if ok == 0 {
            // SAFETY: plain call.
            return -i64::from(unsafe { GetLastError() });
        }
        i64::from(got)
    }

    /// Fills the non-blocking write end `w` in writes of 1024 bytes, then
    /// of one: the bytes it took (at most 64 MiB are tried).
    fn raw_fill(w: HANDLE) -> i64 {
        let mut total = 0i64;
        for len in [1024usize, 1] {
            while total < 64 << 20 {
                let n = raw_write(w, len);
                if n <= 0 {
                    break;
                }
                total += n;
            }
        }
        total
    }

    /// Sets the wait mode (`PIPE_NOWAIT` or `PIPE_WAIT`) of a pipe handle.
    fn set_wait_mode(h: HANDLE, wait: u32) -> std::io::Result<()> {
        let mode = PIPE_READMODE_BYTE | wait;
        // SAFETY: a pipe handle of this process.
        if unsafe { SetNamedPipeHandleState(h, &mode, std::ptr::null(), std::ptr::null()) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// What a pipe whose write end `w` is non-blocking takes, on record.
    fn record_writes(name: &str, r: HANDLE, w: HANDLE) {
        std::println!(
            "PIPETEST {name}: read end {} {}; write end {} {}",
            pipe_info(r),
            pipe_local(r),
            pipe_info(w),
            pipe_local(w)
        );
        if let Err(e) = set_wait_mode(w, PIPE_NOWAIT) {
            std::println!("PIPETEST {name}: PIPE_NOWAIT on the write end: {e}");
            return;
        }
        let mib = raw_write(w, 1 << 20);
        let held = raw_fill(w) + mib.max(0);
        let full = pipe_local(w);
        let (over, one) = (raw_write(w, 1000), raw_write(w, 1));
        // 96 bytes of room, as in CI run 43323860314 (the read end waits
        // for data, so it is read only when the pipe took some).
        let read = if held > 0 { raw_read(r, 96) } else { 0 };
        let room = pipe_local(w);
        let (r1000, r97, r96, r1) = (raw_write(w, 1000), raw_write(w, 97), raw_write(w, 96), raw_write(w, 1));
        std::println!(
            "PIPETEST {name}: non-blocking: 1 MiB into the empty pipe takes {mib}; filled, it \
             holds {held} {full}; then 1000 takes {over}, 1 takes {one}; after a read of {read} \
             {room}: 1000 takes {r1000}, 97 takes {r97}, 96 takes {r96}, then 1 takes {r1}"
        );
    }

    #[test]
    #[ignore = "records; CI's last step runs it with --nocapture"]
    fn test_non_blocking_pipe_writes_on_record() {
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_READ_ATTRIBUTES, OPEN_EXISTING, PIPE_ACCESS_INBOUND,
            PIPE_ACCESS_OUTBOUND,
        };
        use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE};

        let close = |hs: &[HANDLE]| {
            for &h in hs {
                // SAFETY: our handles.
                unsafe { CloseHandle(h) };
            }
        };

        // (a) CreatePipe, by the size asked. nSize 0 is the system's
        // default, and what Python's subprocess asks for (Lib/subprocess.py,
        // `_winapi.CreatePipe(None, 0)`) and `pipe` here. Linux's pipe holds
        // 64 KiB (16 pages, PIPE_DEF_BUFFERS).
        for size in [0u32, 1, 512, 4096, 65536] {
            let (r, w) = raw_pipe(size);
            record_writes(&std::format!("CreatePipe nSize {size}"), r, w);
            close(&[w, r]);
        }

        // (b) A named pipe, by its buffer sizes, written from the server
        // end (outbound) and from the client end (inbound).
        for (i, size) in [0u32, 512, 4096, 65536].into_iter().enumerate() {
            for outbound in [true, false] {
                let name = std::format!(
                    r"\\.\pipe\wick-pipetest-{}-{i}-{}",
                    std::process::id(),
                    u8::from(outbound)
                );
                let wide: std::vec::Vec<u16> = name.encode_utf16().chain([0]).collect();
                let label = std::format!(
                    "CreateNamedPipe {} buffers {size}",
                    if outbound { "outbound, server writes," } else { "inbound, client writes," }
                );
                let (open, access) = if outbound {
                    (PIPE_ACCESS_OUTBOUND, GENERIC_READ)
                } else {
                    (PIPE_ACCESS_INBOUND, GENERIC_WRITE | FILE_READ_ATTRIBUTES)
                };
                // SAFETY: a NUL-terminated name; no security attributes.
                let server = unsafe {
                    CreateNamedPipeW(wide.as_ptr(), open, PIPE_TYPE_BYTE, 1, size, size, 0, std::ptr::null())
                };
                if server == INVALID_HANDLE_VALUE {
                    std::println!("PIPETEST {label}: CreateNamedPipeW: {}", std::io::Error::last_os_error());
                    continue;
                }
                // SAFETY: a NUL-terminated name; no security attributes or template.
                let client = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        access,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    )
                };
                if client == INVALID_HANDLE_VALUE {
                    std::println!("PIPETEST {label}: CreateFileW: {}", std::io::Error::last_os_error());
                    close(&[server]);
                    continue;
                }
                if outbound {
                    record_writes(&label, client, server);
                } else {
                    record_writes(&label, server, client);
                }
                close(&[client, server]);
            }
        }

        // (c) With a read waiting at the other end (a blocking ReadFile of
        // `want` bytes, begun 200 ms before; the write end's
        // WriteQuotaAvailable, printed, is below the pipe's quota while one
        // waits: vmm-sys-util's
        // test_pipe_write_room_reads_0_while_a_read_waits). The write end
        // is closed after the write, which ends a read still waiting.
        for size in [0u32, 65536] {
            for (want, len) in [
                (10usize, 5usize),
                (10, 10),
                (10, 3000),
                (10, 4096),
                (10, 4106),
                (10, 4107),
                (10, 70 * 1024),
                (10, 1 << 20),
                (100_000, 3000),
                (100_000, 8192),
                (100_000, 1 << 20),
            ] {
                let (r, w) = raw_pipe(size);
                set_nowait(w);
                let rv = r as usize;
                let reader = std::thread::spawn(move || raw_read(rv as HANDLE, want));
                std::thread::sleep(std::time::Duration::from_millis(200));
                let before = pipe_local(w);
                let taken = raw_write(w, len);
                close(&[w]);
                let got = reader.join().unwrap();
                let mut left = 0i64;
                loop {
                    let n = raw_read(r, 65536);
                    if n <= 0 {
                        break;
                    }
                    left += n;
                }
                close(&[r]);
                std::println!(
                    "PIPETEST CreatePipe nSize {size}, a read of {want} waiting {before}: a \
                     non-blocking write of {len} takes {taken}; the read got {got}, {left} more \
                     were in the pipe"
                );
            }
        }

        // (d) Whose wait mode a write follows: PIPE_NOWAIT on the read end
        // only, and one byte written to the full pipe from a thread. If the
        // write waits (the write end's own mode counts), reading lets it go.
        // (Filled without waiting, then the write end waits again.)
        let (r, w) = raw_pipe(0);
        set_nowait(w);
        let held = raw_fill(w);
        set_wait_mode(w, PIPE_WAIT).unwrap();
        set_nowait(r);
        let wv = w as usize;
        let writer = std::thread::spawn(move || raw_write(wv as HANDLE, 1));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let waited = !writer.is_finished();
        let mut drained = 0i64;
        loop {
            let n = raw_read(r, 65536);
            if n <= 0 {
                break;
            }
            drained += n;
        }
        let taken = writer.join().unwrap();
        std::println!(
            "PIPETEST PIPE_NOWAIT on the read end only, {held} bytes in a CreatePipe nSize 0 \
             pipe: a write of 1 byte from the blocking write end waited: {waited}; after {drained} \
             bytes were read it had taken {taken}; modes (read mode, completion mode) read end \
             {:?}, write end {:?}",
            pipe_modes(r),
            pipe_modes(w)
        );
        close(&[w, r]);
    }
}
