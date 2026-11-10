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
    CloseHandle, CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_BROKEN_PIPE,
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

pub(crate) fn set_errno(e: c_int) {
    #[allow(clippy::cast_sign_loss)]
    // SAFETY: sets the thread's last error.
    unsafe {
        SetLastError(e as u32)
    };
}

fn last_error() -> c_int {
    // SAFETY: reads the thread's last error.
    #[allow(clippy::cast_possible_wrap)]
    let e = unsafe { GetLastError() } as c_int;
    e
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

    fn live(map: &mut HashMap<c_int, Entry>, fd: c_int) -> bool {
        let Some(e) = map.get(&fd) else {
            return false;
        };
        // SAFETY: compares two handle values.
        if unsafe { CompareObjectHandles(handle(fd), e.own) } != 0 {
            true
        } else {
            map.remove(&fd);
            false
        }
    }

    /// Inserts an entry. Entries of descriptors closed without `close` here
    /// (by std, say) are swept whenever the table has doubled since the
    /// last sweep, so the table stays proportional to the live descriptors
    /// and closed objects are released.
    fn insert(map: &mut HashMap<c_int, Entry>, fd: c_int, entry: Entry) {
        static NEXT_SWEEP: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(64);
        map.insert(fd, entry);
        if map.len() >= NEXT_SWEEP.load(Ordering::Relaxed) {
            // SAFETY: compares two handle values.
            map.retain(|&fd, e| unsafe { CompareObjectHandles(handle(fd), e.own) } != 0);
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
        if let Some(c) = drains().lock().unwrap().get(&fd) {
            c.fetch_add(1, Ordering::Release);
        }
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
            _ => return -1,
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
        }
        return -1;
    }
    // A non-blocking pipe that is full takes nothing.
    if n == 0 && count > 0 && wick_fd::flags(to_fd(h)).load(Ordering::Relaxed) & O_NONBLOCK != 0 {
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
    if let Some(limit) = grow_limit(fd) {
        let mut pos = 0i64;
        // SAFETY: queries the position.
        if unsafe { SetFilePointerEx(handle(fd), 0, &mut pos, FILE_CURRENT) } == 0 {
            return -1;
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
        return -1;
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
            return -1;
        };
        // SAFETY: plain call.
        if unsafe { SetFilePointerEx(h, to, std::ptr::null_mut(), FILE_BEGIN) } == 0 {
            return -1;
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
        return -1;
    }
    pos
}

/// `fsync`.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn fsync(fd: c_int) -> c_int {
    // SAFETY: plain call.
    if unsafe { FlushFileBuffers(handle(fd)) } == 0 {
        return -1;
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
            return -1;
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
                -1
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
        return -1;
    }
    // SAFETY: plain call; the duplicate becomes the standard handle.
    if unsafe { SetStdHandle(std, handle(new)) } == 0 {
        return -1;
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
                        return -1;
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
                    return -1;
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
                    return -1;
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
        return -1;
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
                return -1;
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
            // End of file once the writer is gone.
            assert_eq!(close(fds[1]), 0);
            assert_eq!(fcntl(fds[0], F_SETFL, 0), 0);
            assert_eq!(read(fds[0], b.as_mut_ptr().cast(), 8), 0);
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
}
