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
//! - `write`/`writev` to a full non-blocking pipe fail with `EAGAIN`, as on
//!   Linux. One difference: Linux writes at most `PIPE_BUF` (4096) bytes
//!   all or nothing (pipe(7)), and here a write that does not fit is
//!   written in part, whatever its size (a non-blocking byte pipe takes "as
//!   many bytes as the buffer holds", Named Pipe Type, Read, and Wait
//!   Modes; `test_a_small_write_that_does_not_fit_is_written_in_part`), and
//!   what was written cannot be taken back. The room left cannot be told
//!   beforehand: the write end's
//!   `WriteQuotaAvailable` (FILE_PIPE_LOCAL_INFORMATION) reads 0 while the
//!   reader waits in a read, though a write then completes at once
//!   (vmm-sys-util's `test_pipe_write_room_reads_0_while_a_read_waits`), so
//!   refusing on it would refuse every write while a reader waits; and
//!   `PeekNamedPipe` takes only a read end ("a handle to the read end of an
//!   anonymous pipe");
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
    FIONBIO, SO_TYPE, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, closesocket, getsockopt,
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
    CreatePipe, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_WAIT, SetNamedPipeHandleState,
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
    wick_wsa_startup();
    let mut ty: c_int = 0;
    let mut len: c_int = 4;
    // SAFETY: the option value is an `i32`; a non-socket fails.
    unsafe {
        getsockopt(
            socket(fd),
            SOL_SOCKET,
            SO_TYPE,
            (&raw mut ty).cast(),
            &mut len,
        ) == 0
    }
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

fn write_handle(h: HANDLE, buf: *const c_void, count: usize, at: Option<i64>) -> ssize_t {
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
    if unsafe { WriteFile(h, buf.cast(), len, &mut n, ovp) } == 0 {
        // SAFETY: plain call.
        if matches!(unsafe { GetLastError() }, ERROR_BROKEN_PIPE | ERROR_NO_DATA) {
            set_errno(crate::EPIPE);
            wick_signal::broken_pipe();
        }
        return raw_failed();
    }
    // A full non-blocking pipe takes nothing and returns success with 0
    // written (WriteFile, "Pipes"): EAGAIN, as Linux's pipe write gives
    // with O_NONBLOCK and the pipe full (fs/pipe.c anon_pipe_write: `if
    // (!ret) ret = -EAGAIN; break;`), never 0. A pipe in blocking mode does
    // not complete a write before all is written (SetNamedPipeHandleState,
    // PIPE_WAIT), so 0 of a non-zero count is PIPE_NOWAIT, whoever set it:
    // this descriptor, a duplicate or another process, as the mode is the
    // pipe end's (test_pipe_wait_mode_is_shared_with_a_child_process), not
    // only what this process's flags table knows.
    // SAFETY: plain call.
    if n == 0 && count > 0 && at.is_none() && unsafe { GetFileType(h) } == FILE_TYPE_PIPE {
        set_errno(crate::EAGAIN);
        return -1;
    }
    n as ssize_t
}

/// `read`.
///
/// # Safety
/// `buf` must be valid for `count` bytes of writes.
pub unsafe fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    // Windows fails a read into missing userfaultfd pages; Linux waits.
    crate::wick_uffd::prefault(buf as u64, count as u64, true);
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

/// `write`.
///
/// # Safety
/// `buf` must be valid for `count` bytes of reads.
pub unsafe fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    crate::wick_uffd::prefault(buf as u64, count as u64, false);
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

/// `pread`.
///
/// # Safety
/// `buf` must be valid for `count` bytes of writes.
pub unsafe fn pread(fd: c_int, buf: *mut c_void, count: size_t, offset: off_t) -> ssize_t {
    if offset < 0 {
        set_errno(crate::EINVAL);
        return -1;
    }
    crate::wick_uffd::prefault(buf as u64, count as u64, true);
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
    crate::wick_uffd::prefault(buf as u64, count as u64, false);
    let h = handle(fd);
    keeping_position(h, || write_handle(h, buf, count, Some(offset)))
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
/// not let handle values be chosen; other targets fail with `EBADF`.
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
    let new = dup_inherit(oldfd, true);
    if new < 0 {
        return raw_failed();
    }
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
/// children, as on Linux without `O_CLOEXEC`.
///
/// # Safety
/// `fds` must be valid for two writes.
pub unsafe fn pipe(fds: *mut c_int) -> c_int {
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
const HANDLE_LIMIT: u64 = 1 << 24;

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
        _SC_OPEN_MAX => HANDLE_LIMIT as crate::c_long,
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

/// `getrlimit`: `RLIMIT_NOFILE` is Windows' per-process handle limit; the
/// other Linux resources (0..=15) have no Windows limit outside a job
/// object, so they report `RLIM_INFINITY`.
///
/// # Safety
/// `rlim` must be valid for writes.
pub unsafe fn getrlimit(resource: c_int, rlim: *mut rlimit) -> c_int {
    let v = match resource {
        RLIMIT_NOFILE => HANDLE_LIMIT,
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
    // to write whole buffer": a full non-blocking byte pipe takes what fits
    // and returns success (WriteFile, "Pipes": "WriteFile returns TRUE with
    // *lpNumberOfBytesWritten < nNumberOfBytesToWrite"), and std's
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
    // still fail with EAGAIN as on Linux, never return 0. A write that does
    // not fit is written in part, whatever its size (the module docs say
    // why Linux's all-or-nothing for PIPE_BUF bytes is not kept).
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
            let mut last = 0usize;
            loop {
                let n = write(fds[1], chunk.as_ptr().cast(), chunk.len());
                if n < 0 {
                    break;
                }
                assert!(n > 0, "a write that takes nothing fails");
                last = n.unsigned_abs();
                total += last;
                assert!(total < 64 << 20, "the pipe never filled");
            }
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EAGAIN));
            std::println!("filled with {total} bytes; the last write took {last} of 1000");
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
        #[link(name = "ntdll", kind = "raw-dylib")]
        extern "system" {
            fn NtQueryInformationFile(
                h: HANDLE,
                io: *mut [usize; 2],
                info: *mut [u32; 2],
                len: u32,
                class: u32,
            ) -> i32;
        }
        let (mut io, mut info) = ([0usize; 2], [0u32; 2]);
        // SAFETY: a pipe handle and out-buffers of the sizes given.
        let status = unsafe { NtQueryInformationFile(h, &mut io, &mut info, 8, 23) };
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

    // CreatePipe's buffer: GetNamedPipeInfo's sizes of each end, and what
    // one non-blocking write of 1 MiB puts into the empty pipe ("as many
    // bytes as the buffer holds", Named Pipe Type, Read, and Wait Modes).
    // nSize 0 is the system's default, and what Python's subprocess asks
    // for (Lib/subprocess.py, `_winapi.CreatePipe(None, 0)`), the pipe of
    // tools/windows/check-unit-tests.py before it gave the tests a file.
    // Linux's pipe holds 64 KiB (16 pages, PIPE_DEF_BUFFERS).
    #[test]
    fn test_create_pipe_sizes() {
        let measure = |size: u32| {
            let (r, w) = raw_pipe(size);
            let info = |h: HANDLE| {
                let (mut flags, mut out, mut inb, mut max) = (0u32, 0u32, 0u32, 0u32);
                // SAFETY: out-pointers to u32s.
                let ok = unsafe { GetNamedPipeInfo(h, &mut flags, &mut out, &mut inb, &mut max) };
                if ok == 0 {
                    std::format!("GetNamedPipeInfo failed: {}", std::io::Error::last_os_error())
                } else {
                    std::format!("OutBufferSize {out}, InBufferSize {inb}")
                }
            };
            let (read_info, write_info) = (info(r), info(w));
            set_nowait(w);
            let big = std::vec![7u8; 1 << 20];
            let mut taken = 0u32;
            // SAFETY: a valid buffer.
            let ok = unsafe {
                WriteFile(w, big.as_ptr(), 1 << 20, &mut taken, std::ptr::null_mut())
            };
            assert_ne!(ok, 0, "WriteFile: {}", std::io::Error::last_os_error());
            std::println!(
                "CreatePipe nSize {size}: read end {read_info}; write end {write_info}; \
                 a non-blocking 1 MiB write into the empty pipe takes {taken} bytes"
            );
            // SAFETY: our handles.
            unsafe {
                CloseHandle(w);
                CloseHandle(r);
            }
            taken
        };
        let default = measure(0);
        let asked_64k = measure(65536);
        assert!(default > 0 && default < 64 * 1024, "nSize 0 holds {default} bytes");
        assert!(asked_64k > 0, "nSize 65536 holds {asked_64k} bytes");
    }

    // The difference from Linux the module docs state, as what `write`
    // does: a non-blocking write of at most PIPE_BUF (4096) bytes into a
    // pipe with less room is taken in part. Linux takes such a write whole
    // or fails it with EAGAIN (pipe(7), "O_NONBLOCK enabled, n <=
    // PIPE_BUF"; fs/pipe.c pipe_write, anon_pipe_write since v6.15: a
    // write of at most a page merges whole into the last buffer or takes a
    // buffer of its own, and with none free returns EAGAIN with nothing
    // written). Windows: "When writing to a non-blocking, byte-mode pipe
    // handle with insufficient buffer space, WriteFile returns TRUE with
    // *lpNumberOfBytesWritten < nNumberOfBytesToWrite" (WriteFile,
    // learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-writefile).
    // Two pipes, filled in writes of 3000 and of 2999 bytes after one
    // byte: whatever a pipe holds, the last write that takes anything
    // cannot be whole in both.
    #[test]
    fn test_a_small_write_that_does_not_fit_is_written_in_part() {
        let fill = |len: usize| {
            let mut fds = [0; 2];
            let chunk = std::vec![7u8; len];
            let mut total = 0usize;
            let mut last = 0usize;
            // SAFETY: valid buffers and descriptors.
            unsafe {
                assert_eq!(pipe(fds.as_mut_ptr()), 0);
                assert_eq!(fcntl(fds[1], F_SETFL, O_NONBLOCK), 0);
                assert_eq!(write(fds[1], chunk.as_ptr().cast(), 1), 1);
                loop {
                    let n = write(fds[1], chunk.as_ptr().cast(), len);
                    if n < 0 {
                        break;
                    }
                    last = n.unsigned_abs();
                    assert!(last > 0 && last <= len);
                    total += last;
                    assert!(total < 64 << 20, "the pipe never filled");
                }
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(crate::EAGAIN)
                );
                assert_eq!(close(fds[1]), 0);
                assert_eq!(close(fds[0]), 0);
            }
            std::println!("writes of {len}: the pipe took 1 + {total} bytes, the last write {last}");
            last < len
        };
        let (a, b) = (fill(3000), fill(2999));
        assert!(a || b, "a write of at most PIPE_BUF bytes was taken in part");
    }
}
