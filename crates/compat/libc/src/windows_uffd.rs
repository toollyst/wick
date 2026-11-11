// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The kernel side of Linux's userfaultfd, on Windows: `libc::wick_uffd`,
//! with the API and the wire format of the macOS module (`wick_uffd.rs`).
//!
//! On Linux, an access to a missing page of memory registered with a
//! userfaultfd queues a page fault event on the descriptor and puts the
//! faulting thread to sleep until a handler fills the page (`UFFDIO_COPY`,
//! `UFFDIO_ZEROPAGE`) and wakes it (`UFFDIO_WAKE`). KVM takes the same path
//! for guest accesses. This module gives the process those semantics:
//!
//! - Host threads: missing pages are `PAGE_NOACCESS`. A vectored exception
//!   handler, first in the chain, turns an access violation on one into a
//!   page fault event and waits in a waiter slot; other exceptions go on
//!   down the chain.
//! - Guests: the Windows Hypervisor Platform honours the host protection of
//!   memory mapped into a partition: a guest access to a `PAGE_NOACCESS`
//!   page exits with `WHvRunVpExitReasonMemoryAccess` at the instruction,
//!   which re-runs once the page is accessible (measured on WHP hardware).
//!   The WHP backend resolves those exits with [`fault`].
//! - Registered memory is moved into a pagefile-backed section mapped twice:
//!   at its address, and as an alias that is always writable. Pages are
//!   filled through the alias and only then made accessible, so no thread
//!   sees a page half filled.
//! - `madvise(MADV_DONTNEED)` on registered pages makes them missing again
//!   and queues a remove event ([`discarding`]); their memory is discarded.
//! - System calls that copy to or from missing pages fail on Windows
//!   (`ERROR_NOACCESS`) instead of waiting: the compatibility `read`, `pread`
//!   and friends fault the pages in first ([`prefault`]).
//!
//! A userfaultfd is one end of a pair of connected `AF_UNIX` sockets. Events
//! are [`proto::RECORD`]-byte records read from it. Another process holding
//! the descriptor sends a `HELLO` record followed by the `WSAPROTOCOL_INFOW`
//! of a socket it duplicated for this process (`WSADuplicateSocketW`): its
//! private request channel. A thread per userfaultfd serves the channels.

use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::boxed::Box;
use std::io;
use std::sync::{Mutex, Once};
use std::vec::Vec;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Networking::WinSock::{
    self as ws, AF_UNIX, INVALID_SOCKET, POLLERR, POLLHUP, POLLRDNORM, SOCKET, SOCKET_ERROR,
    SOCK_STREAM, WSAPOLLFD, WSAPROTOCOL_INFOW, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
    EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Memory::{
    DiscardVirtualMemory, PAGE_NOACCESS, PAGE_READWRITE, VirtualProtect,
};
use windows_sys::Win32::System::Threading::{
    CreateSemaphoreW, INFINITE, ReleaseSemaphore, Sleep, WaitForSingleObject,
};

use crate::windows_fd::wick_wsa_startup;

/// Wire format shared with the `userfaultfd` crate (as on macOS).
pub mod proto {
    /// Size of an event, a request header and a reply: four `u64` words.
    pub const RECORD: usize = 32;
    /// Event: `[EVENT_PAGEFAULT, addr, flags, 0]`.
    pub const EVENT_PAGEFAULT: u64 = 1;
    /// Event: `[EVENT_REMOVE, start, end, 0]`.
    pub const EVENT_REMOVE: u64 = 2;
    /// Page fault flag: the access was a write.
    pub const FLAG_WRITE: u64 = 1;
    /// Sent on the userfaultfd: `[HELLO, 0, 0, 0]`, then the
    /// `WSAPROTOCOL_INFOW` of the sender's end of its request channel,
    /// duplicated for the userfaultfd's process.
    pub const HELLO: u64 = 0x10;
    /// Request: `[OP_COPY, dst, len, mode]`, then `len` bytes.
    pub const OP_COPY: u64 = 1;
    /// Request: `[OP_ZEROPAGE, start, len, mode]`.
    pub const OP_ZEROPAGE: u64 = 2;
    /// Request: `[OP_WAKE, start, len, 0]`.
    pub const OP_WAKE: u64 = 3;
    /// Request: `[OP_REGISTER, start, len, 0]`.
    pub const OP_REGISTER: u64 = 4;
    /// Request: `[OP_UNREGISTER, start, len, 0]`.
    pub const OP_UNREGISTER: u64 = 5;
    /// Copy and zeropage mode: do not wake the waiting threads.
    pub const MODE_DONTWAKE: u64 = 1;
    // Reply: `[result, count, 0, 0]`: `result` is the byte count, or a
    // negative errno; for a partial copy `-EAGAIN` with the count copied.
}

/// The feature bit (`UFFD_FEATURE_EVENT_REMOVE`) for remove events.
pub const FEATURE_EVENT_REMOVE: u64 = 1 << 3;

const PAGE: u64 = 4096;
const MAX_RANGES: usize = 64;
const MAX_CTX: usize = 16;
const MAX_WAITERS: usize = 256;
/// `STATUS_ACCESS_VIOLATION`.
const ACCESS_VIOLATION: i32 = 0xC000_0005_u32 as i32;

/// A registered range. Its bitmaps are never freed: the exception handler
/// may be reading them.
struct Range {
    /// 0: free.
    start: AtomicU64,
    end: AtomicU64,
    ctx: AtomicUsize,
    /// Second view of `[start, end)`, always readable and writable.
    alias: AtomicU64,
    /// One bit per page: the page is missing.
    missing: AtomicPtr<AtomicU64>,
    /// One bit per page: the page is registered (cleared by unregister).
    tracked: AtomicPtr<AtomicU64>,
}

impl Range {
    const fn new() -> Self {
        Range {
            start: AtomicU64::new(0),
            end: AtomicU64::new(0),
            ctx: AtomicUsize::new(0),
            alias: AtomicU64::new(0),
            missing: AtomicPtr::new(ptr::null_mut()),
            tracked: AtomicPtr::new(ptr::null_mut()),
        }
    }

    fn bit(map: &AtomicPtr<AtomicU64>, page: u64) -> &AtomicU64 {
        // SAFETY: the bitmap covers every page of the range and is never freed.
        unsafe { &*map.load(Ordering::Acquire).add((page / 64) as usize) }
    }

    fn test(map: &AtomicPtr<AtomicU64>, page: u64) -> bool {
        Self::bit(map, page).load(Ordering::SeqCst) & (1 << (page % 64)) != 0
    }

    fn set(map: &AtomicPtr<AtomicU64>, page: u64, on: bool) {
        let mask = 1 << (page % 64);
        if on {
            Self::bit(map, page).fetch_or(mask, Ordering::SeqCst);
        } else {
            Self::bit(map, page).fetch_and(!mask, Ordering::SeqCst);
        }
    }
}

/// A userfaultfd: the kernel end of its socket pair (-1: free).
struct Ctx {
    fd: AtomicI32,
    features: AtomicU64,
}

/// A thread waiting for a page.
struct Waiter {
    /// The page address; 0: free.
    page: AtomicU64,
    woken: AtomicBool,
    /// A semaphore handle.
    sem: AtomicUsize,
}

static RANGES: [Range; MAX_RANGES] = [const { Range::new() }; MAX_RANGES];
static CTXS: [Ctx; MAX_CTX] = [const {
    Ctx {
        fd: AtomicI32::new(-1),
        features: AtomicU64::new(0),
    }
}; MAX_CTX];
static WAITERS: [Waiter; MAX_WAITERS] = [const {
    Waiter {
        page: AtomicU64::new(0),
        woken: AtomicBool::new(false),
        sem: AtomicUsize::new(0),
    }
}; MAX_WAITERS];
/// Number of registered ranges (the I/O wrappers skip all work at 0).
static REGISTERED: AtomicUsize = AtomicUsize::new(0);
/// Serializes changes to the ranges.
static LOCK: Mutex<()> = Mutex::new(());
static INIT: Once = Once::new();
static READY: AtomicBool = AtomicBool::new(false);

fn errno_err(errno: c_int) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

fn init() -> io::Result<()> {
    INIT.call_once(|| {
        for w in WAITERS.iter() {
            // SAFETY: an unnamed semaphore, initially unsignalled.
            let sem = unsafe { CreateSemaphoreW(ptr::null(), 0, i32::MAX, ptr::null()) };
            if sem.is_null() {
                return;
            }
            w.sem.store(sem as usize, Ordering::Release);
        }
        // SAFETY: first in the chain; the handler stays for the process.
        if unsafe { AddVectoredExceptionHandler(1, Some(on_exception)) }.is_null() {
            return;
        }
        READY.store(true, Ordering::Release);
    });
    if READY.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(errno_err(crate::ENOMEM))
    }
}

/// The range and page index of `addr`, if it is registered memory.
fn find(addr: u64) -> Option<(&'static Range, u64)> {
    for r in RANGES.iter() {
        let start = r.start.load(Ordering::Acquire);
        if start != 0 && addr >= start && addr < r.end.load(Ordering::Acquire) {
            return Some((r, (addr - start) / PAGE));
        }
    }
    None
}

/// Whether `addr` is in a registered page that is missing.
pub fn is_missing(addr: u64) -> bool {
    match find(addr) {
        Some((r, page)) => Range::test(&r.tracked, page) && Range::test(&r.missing, page),
        None => false,
    }
}

fn sock(fd: c_int) -> SOCKET {
    #[allow(clippy::cast_sign_loss)]
    let s = fd as u32 as SOCKET;
    s
}

#[allow(clippy::cast_possible_truncation)]
fn to_fd(s: SOCKET) -> c_int {
    s as u32 as c_int
}

fn send_all(fd: c_int, buf: &[u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        let want = i32::try_from(buf.len() - done).unwrap_or(i32::MAX);
        // SAFETY: sends from a valid buffer.
        let n = unsafe { ws::send(sock(fd), buf[done..].as_ptr(), want, 0) };
        if n <= 0 {
            return false;
        }
        done += n.unsigned_abs() as usize;
    }
    true
}

fn recv_all(fd: c_int, buf: &mut [u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        let want = i32::try_from(buf.len() - done).unwrap_or(i32::MAX);
        // SAFETY: receives into a valid buffer.
        let n = unsafe { ws::recv(sock(fd), buf[done..].as_mut_ptr(), want, 0) };
        if n <= 0 {
            return false;
        }
        done += n.unsigned_abs() as usize;
    }
    true
}

fn post(ctx: usize, record: [u64; 4]) {
    let fd = CTXS[ctx].fd.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    let mut bytes = [0u8; proto::RECORD];
    for (i, w) in record.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    // If the handler side is gone, nobody will serve the fault.
    let _ = send_all(fd, &bytes);
}

/// Resolves an access to `addr`: if it is a missing registered page, queues
/// a page fault event and waits until the page is filled and the waiters are
/// woken. Returns false if `addr` is not a missing registered page.
pub fn fault(addr: u64, write: bool) -> bool {
    let Some((range, page)) = find(addr) else {
        return false;
    };
    if !Range::test(&range.tracked, page) || !Range::test(&range.missing, page) {
        return false;
    }
    let page_addr = range.start.load(Ordering::Acquire) + page * PAGE;
    // Claim a waiter slot.
    let slot = loop {
        if let Some(w) = WAITERS.iter().find(|w| {
            w.page
                .compare_exchange(0, page_addr, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        }) {
            break w;
        }
        // All slots busy: wait a little.
        // SAFETY: plain call.
        unsafe { Sleep(1) };
    };
    slot.woken.store(false, Ordering::SeqCst);
    // Filled while the slot was claimed: no fault to report.
    if Range::test(&range.missing, page) && Range::test(&range.tracked, page) {
        let flags = if write { proto::FLAG_WRITE } else { 0 };
        post(
            range.ctx.load(Ordering::Acquire),
            [proto::EVENT_PAGEFAULT, addr, flags, 0],
        );
        while !slot.woken.load(Ordering::SeqCst) {
            // SAFETY: a semaphore created at init.
            unsafe { WaitForSingleObject(slot.sem.load(Ordering::Acquire) as HANDLE, INFINITE) };
        }
    }
    slot.page.store(0, Ordering::SeqCst);
    true
}

/// Wakes the threads waiting for pages in `[start, start + len)`.
pub fn wake(start: u64, len: u64) {
    let end = start.saturating_add(len);
    for w in WAITERS.iter() {
        let page = w.page.load(Ordering::SeqCst);
        if page != 0 && page >= start && page < end {
            w.woken.store(true, Ordering::SeqCst);
            // SAFETY: a semaphore created at init.
            unsafe { ReleaseSemaphore(w.sem.load(Ordering::Acquire) as HANDLE, 1, ptr::null_mut()) };
        }
    }
}

unsafe extern "system" fn on_exception(info: *mut EXCEPTION_POINTERS) -> i32 {
    // SAFETY: the system passes valid exception pointers.
    let rec = unsafe { &*(*info).ExceptionRecord };
    if rec.ExceptionCode == ACCESS_VIOLATION && rec.NumberParameters >= 2 {
        // [0]: 0 read, 1 write, 8 execute; [1]: the address.
        let addr = rec.ExceptionInformation[1] as u64;
        if is_missing(addr) && fault(addr, rec.ExceptionInformation[0] == 1) {
            // Re-run the access.
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    EXCEPTION_CONTINUE_SEARCH
}

/// Calls `f(start, len)` for each run of missing registered pages in
/// `[start, start + len)`.
pub fn for_each_missing(start: u64, len: u64, mut f: impl FnMut(u64, u64)) {
    let end = start.saturating_add(len);
    let mut run: Option<u64> = None;
    let mut addr = start - start % PAGE;
    while addr < end {
        let missing = is_missing(addr);
        match (missing, run) {
            (true, None) => run = Some(addr),
            (false, Some(s)) => {
                f(s, addr - s);
                run = None;
            }
            _ => {}
        }
        addr += PAGE;
    }
    if let Some(s) = run {
        f(s, end.min(addr) - s);
    }
}

fn protect(addr: u64, len: u64, accessible: bool) -> io::Result<()> {
    let prot = if accessible { PAGE_READWRITE } else { PAGE_NOACCESS };
    let mut old = 0;
    // SAFETY: changes the protection of registered memory only.
    if unsafe { VirtualProtect(addr as *mut c_void, len as usize, prot, &mut old) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A connected pair of `AF_UNIX` stream sockets (Windows has no
/// `socketpair`): a listener on a temporary path, connected to and removed.
fn socket_pair() -> io::Result<(c_int, c_int)> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    wick_wsa_startup();
    let new = || {
        // SAFETY: creates a socket.
        let s = unsafe {
            ws::WSASocketW(
                i32::from(AF_UNIX),
                SOCK_STREAM,
                0,
                ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if s == INVALID_SOCKET {
            Err(io::Error::from_raw_os_error(
                // SAFETY: plain call.
                unsafe { ws::WSAGetLastError() },
            ))
        } else {
            Ok(s)
        }
    };
    let close = |s: SOCKET| {
        // SAFETY: closes a socket made here.
        unsafe { ws::closesocket(s) };
    };
    let path = std::env::temp_dir().join(std::format!(
        "wick-uffd-{}-{}.sock",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let bytes = path.to_string_lossy().into_owned().into_bytes();
    if bytes.len() >= 108 {
        return Err(errno_err(crate::ENAMETOOLONG));
    }
    let mut addr = [0u8; 110];
    addr[0] = 1; // AF_UNIX
    addr[2..2 + bytes.len()].copy_from_slice(&bytes);
    let addr_len = i32::try_from(addr.len()).unwrap();
    let listener = new()?;
    // SAFETY: a valid AF_UNIX address.
    let bound = unsafe {
        ws::bind(listener, addr.as_ptr().cast(), addr_len) == 0 && ws::listen(listener, 1) == 0
    };
    if !bound {
        // SAFETY: plain call.
        let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
        close(listener);
        return Err(e);
    }
    let result = new().and_then(|a| {
        // SAFETY: a valid AF_UNIX address.
        if unsafe { ws::connect(a, addr.as_ptr().cast(), addr_len) } != 0 {
            // SAFETY: plain call.
            let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
            close(a);
            return Err(e);
        }
        // SAFETY: accepts the connection just made.
        let b = unsafe { ws::accept(listener, ptr::null_mut(), ptr::null_mut()) };
        if b == INVALID_SOCKET {
            // SAFETY: plain call.
            let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
            close(a);
            return Err(e);
        }
        Ok((to_fd(b), to_fd(a)))
    });
    close(listener);
    let _ = std::fs::remove_file(&path);
    result
}

/// Creates a userfaultfd. Returns its index and the user's descriptor (the
/// other end stays with the serving thread).
pub fn create(features: u64, nonblocking: bool, cloexec: bool) -> io::Result<(usize, c_int)> {
    // Windows handles are not inherited by the processes this one starts
    // unless asked for: every descriptor here is close-on-exec.
    let _ = cloexec;
    init()?;
    let (kernel, user) = socket_pair()?;
    let buf: c_int = 1 << 20;
    // SAFETY: plain socket options on the sockets made above.
    unsafe {
        ws::setsockopt(
            sock(kernel),
            ws::SOL_SOCKET,
            ws::SO_SNDBUF,
            (&raw const buf).cast(),
            4,
        );
        if nonblocking {
            let fl = crate::fcntl(user, crate::F_GETFL);
            crate::fcntl(user, crate::F_SETFL, fl | crate::O_NONBLOCK);
        }
    }
    let _guard = LOCK.lock().unwrap();
    let Some(index) = CTXS.iter().position(|c| {
        c.fd.compare_exchange(-1, kernel, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        // SAFETY: closes the sockets created above.
        unsafe {
            ws::closesocket(sock(kernel));
            ws::closesocket(sock(user));
        }
        return Err(errno_err(crate::EMFILE));
    };
    CTXS[index].features.store(features, Ordering::Release);
    std::thread::Builder::new()
        .name("userfaultfd".into())
        .spawn(move || serve(index, kernel))
        .inspect_err(|_| {
            CTXS[index].fd.store(-1, Ordering::Release);
        })?;
    Ok((index, user))
}

fn alloc_bitmap(pages: u64, on: bool) -> *mut AtomicU64 {
    let words = pages.div_ceil(64) as usize;
    let v: Vec<AtomicU64> = (0..words)
        .map(|_| AtomicU64::new(if on { !0 } else { 0 }))
        .collect();
    Box::into_raw(v.into_boxed_slice()).cast()
}

/// Registers `[start, start + len)` (page aligned; one whole anonymous
/// private mapping) with userfaultfd `ctx`. Pages that are not resident are
/// missing from now on.
pub fn register(ctx: usize, start: u64, len: u64) -> io::Result<()> {
    if len == 0 || !start.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) || start == 0 {
        return Err(errno_err(crate::EINVAL));
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| errno_err(crate::EINVAL))?;
    let _guard = LOCK.lock().unwrap();
    if RANGES.iter().any(|r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    }) {
        return Err(errno_err(crate::EBUSY));
    }
    let Some(range) = RANGES.iter().find(|r| r.start.load(Ordering::Acquire) == 0) else {
        return Err(errno_err(crate::ENOMEM));
    };
    let pages = len / PAGE;
    // Residency decides what is missing.
    let mut resident = std::vec![0u8; pages as usize];
    // SAFETY: `resident` has one byte per page of the range.
    if unsafe { crate::mincore(start as *mut _, len as usize, resident.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let alias = crate::windows_mm::uffd_alias(start as usize, len as usize, &resident)
        .map_err(errno_err)? as u64;
    let missing = alloc_bitmap(pages, false);
    let tracked = alloc_bitmap(pages, true);
    range.end.store(end, Ordering::Release);
    range.ctx.store(ctx, Ordering::Release);
    range.alias.store(alias, Ordering::Release);
    range.missing.store(missing, Ordering::Release);
    range.tracked.store(tracked, Ordering::Release);
    // Trailing bits of the last word stay set in `tracked`; they are past `end`.
    for page in 0..pages {
        if resident[page as usize] & 1 == 0 {
            Range::set(&range.missing, page, true);
        }
    }
    range.start.store(start, Ordering::Release);
    REGISTERED.fetch_add(1, Ordering::AcqRel);
    // Missing pages fault from now on.
    let mut runs = Vec::new();
    for_each_missing(start, len, |s, l| runs.push((s, l)));
    for (s, l) in runs {
        protect(s, l, false)?;
    }
    Ok(())
}

/// The registered range holding all of `[start, start + len)`, which must be
/// page aligned.
fn range_of(ctx: usize, start: u64, len: u64) -> Result<&'static Range, c_int> {
    if !start.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) || len == 0 {
        return Err(crate::EINVAL);
    }
    let (range, _) = find(start).ok_or(crate::ENOENT)?;
    if range.ctx.load(Ordering::Acquire) != ctx || start + len > range.end.load(Ordering::Acquire) {
        return Err(crate::ENOENT);
    }
    Ok(range)
}

/// Unregisters `[start, start + len)`: its missing pages become ordinary
/// (zero-filled) memory and their waiters are woken.
pub fn unregister(ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    let _guard = LOCK.lock().unwrap();
    let range = range_of(ctx, start, len)?;
    let base = range.start.load(Ordering::Acquire);
    let alias = range.alias.load(Ordering::Acquire);
    let mut runs = Vec::new();
    for_each_missing(start, len, |s, l| runs.push((s, l)));
    for page in (start - base) / PAGE..(start + len - base) / PAGE {
        Range::set(&range.tracked, page, false);
    }
    for (s, l) in runs {
        // Missing pages may hold discarded data: zeros, as Linux gives.
        // SAFETY: the alias of registered memory.
        unsafe { ptr::write_bytes((alias + (s - base)) as *mut u8, 0, l as usize) };
        protect(s, l, true).map_err(|e| e.raw_os_error().unwrap_or(crate::EIO))?;
        for page in (s - base) / PAGE..(s + l - base) / PAGE {
            Range::set(&range.missing, page, false);
        }
    }
    wake(start, len);
    Ok(())
}

/// Fills missing pages from `dst` on with `fill(alias_dst, len)`: stops at
/// the first page that is present. Returns the byte count; `EEXIST` if the
/// first page is present, `EAGAIN` with the count when only some were filled.
fn fill(
    ctx: usize,
    dst: u64,
    len: u64,
    wake_up: bool,
    mut fill: impl FnMut(*mut u8, usize),
) -> Result<u64, (c_int, u64)> {
    let _guard = LOCK.lock().unwrap();
    let range = range_of(ctx, dst, len).map_err(|e| (e, 0))?;
    let base = range.start.load(Ordering::Acquire);
    let alias = range.alias.load(Ordering::Acquire);
    let first = (dst - base) / PAGE;
    let mut n = 0;
    while n < len / PAGE {
        let page = first + n;
        if !Range::test(&range.tracked, page) || !Range::test(&range.missing, page) {
            break;
        }
        n += 1;
    }
    if n == 0 {
        return Err((crate::EEXIST, 0));
    }
    let bytes = n * PAGE;
    fill((alias + (dst - base)) as *mut u8, bytes as usize);
    protect(dst, bytes, true).map_err(|e| (e.raw_os_error().unwrap_or(crate::EIO), 0))?;
    for page in first..first + n {
        Range::set(&range.missing, page, false);
    }
    if wake_up {
        wake(dst, bytes);
    }
    if bytes < len {
        Err((crate::EAGAIN, bytes))
    } else {
        Ok(bytes)
    }
}

/// `UFFDIO_COPY`: fills missing pages from `dst` on with `src`.
///
/// # Safety
/// `src` must be readable for `len` bytes.
pub unsafe fn copy(
    ctx: usize,
    src: *const u8,
    dst: u64,
    len: u64,
    wake_up: bool,
) -> Result<u64, (c_int, u64)> {
    fill(ctx, dst, len, wake_up, |to, n| {
        // SAFETY: `to` is the alias of missing pages; `src` per the contract.
        unsafe { ptr::copy_nonoverlapping(src, to, n) }
    })
}

/// `UFFDIO_ZEROPAGE`: fills missing pages from `start` on with zeros.
pub fn zeropage(ctx: usize, start: u64, len: u64, wake_up: bool) -> Result<u64, (c_int, u64)> {
    fill(ctx, start, len, wake_up, |to, n| {
        // SAFETY: `to` is the alias of missing pages.
        unsafe { ptr::write_bytes(to, 0, n) }
    })
}

/// `UFFDIO_WAKE`.
pub fn wake_range(ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    range_of(ctx, start, len)?;
    wake(start, len);
    Ok(())
}

/// Wraps a `MADV_DONTNEED` of `[start, start + len)`: `discard` runs on the
/// memory that is not registered; registered pages are missing again, their
/// memory discarded, and a remove event is queued (with `EVENT_REMOVE`).
pub fn discarding(start: u64, len: u64, discard: impl FnOnce() -> c_int) -> c_int {
    let end = start.saturating_add(len);
    let touches = RANGES.iter().any(|r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    });
    if !touches {
        return discard();
    }
    let _guard = LOCK.lock().unwrap();
    let ret = discard();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let (from, to) = (start.max(s) - start.max(s) % PAGE, end.min(e));
        let alias = r.alias.load(Ordering::Acquire);
        let mut any = false;
        let mut addr = from;
        while addr < to {
            let page = (addr - s) / PAGE;
            if Range::test(&r.tracked, page) {
                Range::set(&r.missing, page, true);
                any = true;
            }
            addr += PAGE;
        }
        if !any {
            continue;
        }
        let mut runs = Vec::new();
        for_each_missing(from, to - from, |a, l| runs.push((a, l)));
        for (a, l) in runs {
            let _ = protect(a, l, false);
            // Filling a missing page writes all of it: its content can go.
            // SAFETY: the alias of registered memory.
            unsafe { DiscardVirtualMemory((alias + (a - s)) as *mut c_void, l as usize) };
        }
        let ctx = r.ctx.load(Ordering::Acquire);
        if CTXS[ctx].features.load(Ordering::Acquire) & FEATURE_EVENT_REMOVE != 0 {
            post(ctx, [proto::EVENT_REMOVE, from, to, 0]);
        }
    }
    ret
}

/// Releases userfaultfd `ctx`: its ranges become ordinary memory and every
/// waiter is woken, as when Linux releases a userfaultfd.
fn destroy(ctx: usize) {
    let _guard = LOCK.lock().unwrap();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        if s == 0 || r.ctx.load(Ordering::Acquire) != ctx {
            continue;
        }
        let e = r.end.load(Ordering::Acquire);
        let alias = r.alias.load(Ordering::Acquire);
        let mut runs = Vec::new();
        for_each_missing(s, e - s, |a, l| runs.push((a, l)));
        for (a, l) in runs {
            // SAFETY: the alias of registered memory.
            unsafe { ptr::write_bytes((alias + (a - s)) as *mut u8, 0, l as usize) };
            let _ = protect(a, l, true);
            for page in (a - s) / PAGE..(a + l - s) / PAGE {
                Range::set(&r.missing, page, false);
            }
        }
        r.start.store(0, Ordering::Release);
        REGISTERED.fetch_sub(1, Ordering::AcqRel);
        let alias = r.alias.swap(0, Ordering::AcqRel);
        if alias != 0 {
            crate::windows_mm::uffd_unalias(alias as usize);
        }
        wake(s, e - s);
    }
    let fd = CTXS[ctx].fd.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        // SAFETY: the kernel end owned by the serving thread.
        unsafe { ws::closesocket(sock(fd)) };
    }
}

fn words(buf: &[u8; proto::RECORD]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for (i, v) in w.iter_mut().enumerate() {
        *v = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

/// Receives a `HELLO` and its channel on the kernel end. `None`: the end is
/// closed; `Some(None)`: a record that is not a `HELLO`, ignored.
fn recv_hello(fd: c_int) -> Option<Option<c_int>> {
    let mut buf = [0u8; proto::RECORD];
    if !recv_all(fd, &mut buf) {
        return None;
    }
    if words(&buf)[0] != proto::HELLO {
        return Some(None);
    }
    // SAFETY: plain data; filled below.
    let mut info: WSAPROTOCOL_INFOW = unsafe { core::mem::zeroed() };
    // SAFETY: the structure's bytes, filled by the peer's WSADuplicateSocketW.
    let raw = unsafe {
        core::slice::from_raw_parts_mut(
            (&raw mut info).cast::<u8>(),
            core::mem::size_of::<WSAPROTOCOL_INFOW>(),
        )
    };
    if !recv_all(fd, raw) {
        return None;
    }
    // SAFETY: a socket from the peer's protocol information.
    let s = unsafe {
        ws::WSASocketW(
            ws::FROM_PROTOCOL_INFO,
            ws::FROM_PROTOCOL_INFO,
            ws::FROM_PROTOCOL_INFO,
            &info,
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    Some((s != INVALID_SOCKET).then(|| to_fd(s)))
}

/// Serves one request from a client channel; false when the channel closed.
fn serve_request(ctx: usize, fd: c_int) -> bool {
    let mut head = [0u8; proto::RECORD];
    if !recv_all(fd, &mut head) {
        return false;
    }
    let [op, a, b, c] = words(&head);
    let wake_up = c & proto::MODE_DONTWAKE == 0;
    let to_reply = |r: Result<u64, (c_int, u64)>| match r {
        Ok(n) => [n, n],
        Err((e, n)) => [(-i64::from(e)).cast_unsigned(), n],
    };
    let reply = match op {
        proto::OP_COPY => {
            let Ok(len) = usize::try_from(b) else {
                return false;
            };
            let mut data = std::vec![0u8; len];
            if !recv_all(fd, &mut data) {
                return false;
            }
            // SAFETY: `data` holds `len` bytes.
            to_reply(unsafe { copy(ctx, data.as_ptr(), a, b, wake_up) })
        }
        proto::OP_ZEROPAGE => to_reply(zeropage(ctx, a, b, wake_up)),
        proto::OP_WAKE => to_reply(wake_range(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        proto::OP_REGISTER => to_reply(
            register(ctx, a, b)
                .map(|()| 0)
                .map_err(|e| (e.raw_os_error().unwrap_or(crate::EINVAL), 0)),
        ),
        proto::OP_UNREGISTER => to_reply(unregister(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        _ => to_reply(Err((crate::EINVAL, 0))),
    };
    let mut out = [0u8; proto::RECORD];
    out[..8].copy_from_slice(&reply[0].to_le_bytes());
    out[8..16].copy_from_slice(&reply[1].to_le_bytes());
    send_all(fd, &out)
}

/// The serving thread of userfaultfd `ctx`: accepts request channels sent on
/// the kernel end and serves them. Ends when every user descriptor is closed.
fn serve(ctx: usize, kernel: c_int) {
    let mut clients: Vec<c_int> = Vec::new();
    loop {
        let mut fds: Vec<WSAPOLLFD> = core::iter::once(kernel)
            .chain(clients.iter().copied())
            .map(|fd| WSAPOLLFD {
                fd: sock(fd),
                events: POLLRDNORM,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is a valid array.
        let n = unsafe { ws::WSAPoll(fds.as_mut_ptr(), u32::try_from(fds.len()).unwrap(), -1) };
        if n == SOCKET_ERROR {
            break;
        }
        let ready = POLLRDNORM | POLLHUP | POLLERR;
        if fds[0].revents & ready != 0 {
            match recv_hello(kernel) {
                None => break,
                Some(Some(client)) => clients.push(client),
                Some(None) => {}
            }
        }
        let mut closed = Vec::new();
        for p in &fds[1..] {
            if p.revents & ready != 0 && !serve_request(ctx, to_fd(p.fd)) {
                closed.push(to_fd(p.fd));
            }
        }
        for fd in closed {
            clients.retain(|c| *c != fd);
            // SAFETY: a client channel received above.
            unsafe { ws::closesocket(sock(fd)) };
        }
    }
    for fd in clients {
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(fd)) };
    }
    destroy(ctx);
}

/// Faults in the missing registered pages of `[addr, addr + len)`, as the
/// Linux kernel does when a system call copies to or from them (`write`: the
/// call writes the memory). Returns whether any page was missing.
pub fn prefault(addr: u64, len: u64, write: bool) -> bool {
    // Lazy memory too: a system call fails on pages not committed (the
    // kernel's copy takes no exception this process could resolve).
    #[allow(clippy::cast_possible_truncation)]
    crate::windows_mm::prefault_lazy(addr as usize, len as usize);
    if REGISTERED.load(Ordering::Acquire) == 0 || len == 0 {
        return false;
    }
    let end = addr.saturating_add(len);
    let mut page = addr - addr % PAGE;
    let mut any = false;
    while page < end {
        // The first byte of the buffer in this page.
        let at = page.max(addr);
        if is_missing(at) && fault(at, write) {
            any = true;
        }
        page += PAGE;
    }
    any
}

/// Whether any memory is registered: the I/O paths skip [`prefault`] when
/// none is.
pub fn active() -> bool {
    REGISTERED.load(Ordering::Acquire) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(len: usize) -> u64 {
        // SAFETY: a new anonymous mapping.
        let p = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, crate::MAP_FAILED);
        p as u64
    }

    /// The handler side, in this process: reads events from the user end
    /// and fills pages directly.
    fn serve_one(user: c_int, ctx: usize, fill: u8) -> [u64; 4] {
        let mut buf = [0u8; proto::RECORD];
        assert!(recv_all(user, &mut buf));
        let event = words(&buf);
        if event[0] == proto::EVENT_PAGEFAULT {
            let page = event[1] - event[1] % PAGE;
            let data = std::vec![fill; PAGE as usize];
            // SAFETY: `data` holds a page.
            unsafe { copy(ctx, data.as_ptr(), page, PAGE, true) }.unwrap();
        }
        event
    }

    #[test]
    fn test_host_fault_copy_zeropage() {
        let (ctx, user) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        // A resident page keeps its content.
        // SAFETY: our mapping.
        unsafe { *(mem as *mut u8) = 7 };
        register(ctx, mem, len as u64).unwrap();
        assert!(!is_missing(mem));
        assert!(is_missing(mem + PAGE));

        // A host thread faults on a missing page and waits for the handler.
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        let event = serve_one(user, ctx, 0xab);
        assert_eq!(event[0], proto::EVENT_PAGEFAULT);
        assert_eq!(event[1], mem + PAGE + 5);
        assert_eq!(event[2] & proto::FLAG_WRITE, 0);
        assert_eq!(reader.join().unwrap(), 0xab);
        // SAFETY: our mapping.
        assert_eq!(unsafe { *(mem as *const u8) }, 7);

        // A present page is refused; zeropage fills the next one.
        // SAFETY: a page of zeros.
        let zeros = std::vec![0u8; PAGE as usize];
        assert_eq!(unsafe { copy(ctx, zeros.as_ptr(), mem + PAGE, PAGE, true) }.unwrap_err().0, crate::EEXIST);
        assert_eq!(zeropage(ctx, mem + 2 * PAGE, PAGE, true).unwrap(), PAGE);
        // SAFETY: filled now.
        assert_eq!(unsafe { *((mem + 2 * PAGE) as *const u8) }, 0);

        // A write fault is flagged as one.
        let writer = std::thread::spawn(move || {
            // SAFETY: registered memory; the write waits for the fill.
            unsafe { core::ptr::write_volatile((mem + 3 * PAGE) as *mut u8, 9) }
        });
        let event = serve_one(user, ctx, 0);
        assert_eq!(event[2] & proto::FLAG_WRITE, proto::FLAG_WRITE);
        writer.join().unwrap();
        // SAFETY: filled now.
        assert_eq!(unsafe { *((mem + 3 * PAGE) as *const u8) }, 9);

        // MADV_DONTNEED makes registered pages missing again, with an event.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        let mut buf = [0u8; proto::RECORD];
        assert!(recv_all(user, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, mem + PAGE, mem + 2 * PAGE]);
        assert!(is_missing(mem + PAGE));

        // Unregistered: missing pages read as zeros, nothing faults.
        unregister(ctx, mem, len as u64).unwrap();
        // SAFETY: ordinary memory now.
        assert_eq!(unsafe { *((mem + PAGE) as *const u8) }, 0);
        assert_eq!(unsafe { *((mem + 4 * PAGE) as *const u8) }, 0);
        // SAFETY: closes the user end; the serving thread ends.
        unsafe { ws::closesocket(sock(user)) };
    }

    #[test]
    fn test_prefault_before_system_calls() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        let handler = std::thread::spawn(move || serve_one(user, ctx, 0x11));
        // A read into missing pages: the pages are faulted in first.
        let path = std::env::temp_dir().join(std::format!("wick-uffd-read-{}", std::process::id()));
        std::fs::write(&path, [0x22u8; 16]).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let fd = crate::windows_fd::to_fd_pub(std::os::windows::io::AsRawHandle::as_raw_handle(&f));
        // SAFETY: a valid descriptor and registered memory.
        let n = unsafe { crate::read(fd, (mem + 8) as *mut c_void, 16) };
        assert_eq!(n, 16);
        assert_eq!(handler.join().unwrap()[0], proto::EVENT_PAGEFAULT);
        // SAFETY: filled and read into.
        unsafe {
            assert_eq!(*(mem as *const u8), 0x11);
            assert_eq!(*((mem + 8) as *const u8), 0x22);
        }
        drop(f);
        let _ = std::fs::remove_file(&path);
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(user)) };
    }

    #[test]
    fn test_register_errors() {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map(64 * 1024);
        assert_eq!(register(ctx, mem + 1, PAGE).unwrap_err().raw_os_error(), Some(crate::EINVAL));
        // Part of a mapping.
        assert_eq!(register(ctx, mem, PAGE).unwrap_err().raw_os_error(), Some(crate::EINVAL));
        register(ctx, mem, 64 * 1024).unwrap();
        assert_eq!(register(ctx, mem, 64 * 1024).unwrap_err().raw_os_error(), Some(crate::EBUSY));
        assert_eq!(wake_range(ctx, mem + 64 * 1024, PAGE), Err(crate::ENOENT));
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(user)) };
    }
}
