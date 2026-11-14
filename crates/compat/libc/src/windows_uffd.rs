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
//!   sees a page half filled. With the lazy-memory exception handler the
//!   section is reserved: a missing page is not committed, and faults as a
//!   `PAGE_NOACCESS` one does; a fill commits it first, charged to the
//!   job's memory limit, through the view at its address with no access
//!   (`windows_mm::uffd_commit`), as Linux charges the page a `UFFDIO_COPY`
//!   allocates (`ENOMEM` when refused). A page never filled becomes lazy
//!   memory when it is unregistered (`windows_mm::uffd_lazy`).
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
    /// The section is reserved: missing pages that were never filled are
    /// not committed (`windows_mm::uffd_alias`).
    reserved: AtomicBool,
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
            reserved: AtomicBool::new(false),
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

/// The descriptor of a socket made or accepted here: `None` (the socket
/// closed, `EINVAL` set, the reason on stderr) when its value is no
/// descriptor, never truncated. [`to_fd`] is for sockets adopted so.
fn adopt(s: SOCKET) -> Option<c_int> {
    crate::windows_linux::socket_fd(s, crate::windows_linux::socket_fits)
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
        let (missing, next) = match find(addr) {
            Some((r, page)) => (Range::test(&r.tracked, page) && Range::test(&r.missing, page), addr + PAGE),
            // Unregistered memory holds no missing page: on to the next
            // range (a walk by pages over a span as large as a
            // `MADV_DONTNEED` may name would not end).
            None => {
                let next = RANGES
                    .iter()
                    .map(|r| r.start.load(Ordering::Acquire))
                    .filter(|&s| s > addr)
                    .min()
                    .unwrap_or(end)
                    .min(end);
                (false, next.max(addr + PAGE))
            }
        };
        match (missing, run) {
            (true, None) => run = Some(addr),
            (false, Some(s)) => {
                f(s, addr - s);
                run = None;
            }
            _ => {}
        }
        addr = next;
    }
    if let Some(s) = run {
        f(s, end.min(addr) - s);
    }
}

/// The runs of `[addr, addr + len)` of `range` that have memory: all of it,
/// or, in a reserved section, its committed runs (an uncommitted page
/// faults already, and has no protection to change or memory to discard).
fn with_memory(range: &Range, addr: u64, len: u64) -> Vec<(u64, u64)> {
    if !range.reserved.load(Ordering::Acquire) {
        return std::vec![(addr, len)];
    }
    #[allow(clippy::cast_possible_truncation)]
    crate::windows_mm::committed_runs(addr as usize, len as usize)
        .into_iter()
        .map(|(s, l)| (s as u64, l as u64))
        .collect()
}

/// Missing pages `[s, s + len)` of `range`, whose alias is at `alias` and
/// which starts at `base`, become ordinary memory: those with memory
/// (filled once, then discarded) read zeros, as Linux gives: in a reserved
/// section zeroed at their first access
/// (`windows_mm::uffd_stale`), elsewhere zeroed and made accessible now;
/// those never filled, in a reserved section, become lazy memory
/// (`windows_mm::uffd_lazy`).
fn release_missing(range: &Range, base: u64, alias: u64, s: u64, len: u64) -> io::Result<()> {
    let runs = with_memory(range, s, len);
    let mut at = s;
    for &(a, l) in runs.iter().chain([(s + len, 0)].iter()) {
        if a > at {
            #[allow(clippy::cast_possible_truncation)]
            crate::windows_mm::uffd_lazy(at as usize, (a - at) as usize);
        }
        if l > 0 {
            if range.reserved.load(Ordering::Acquire) {
                // Discarded, its commit and charge kept (`discarding`): lazy,
                // zeroed at its first access, as Linux gives a zapped page as
                // zeros at its next touch.
                #[allow(clippy::cast_possible_truncation)]
                crate::windows_mm::uffd_stale(a as usize, l as usize, (alias + (a - base)) as usize);
            } else {
                // SAFETY: the alias of registered memory.
                unsafe { ptr::write_bytes((alias + (a - base)) as *mut u8, 0, l as usize) };
                protect(a, l, true)?;
            }
        }
        at = a + l;
    }
    Ok(())
}

/// Changes the protection of committed registered memory, a view at a time
/// (`VirtualProtect` stays within one allocation; a reserved section is a
/// view per chunk, `windows_mm::UFFD_CHUNK`).
fn protect(addr: u64, len: u64, accessible: bool) -> io::Result<()> {
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
    let prot = if accessible { PAGE_READWRITE } else { PAGE_NOACCESS };
    let (mut at, end) = (addr as usize, (addr + len) as usize);
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(end) - at;
        let mut old = 0;
        // SAFETY: changes the protection of registered memory only.
        if unsafe { VirtualProtect(at as *mut c_void, run, prot, &mut old) } == 0 {
            return Err(io::Error::last_os_error());
        }
        at += run;
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
        // Both made, or neither: a refused one is closed already.
        match (adopt(b), adopt(a)) {
            (Some(b), Some(a)) => Ok((b, a)),
            (b, a) => {
                for fd in [b, a].into_iter().flatten() {
                    close(sock(fd));
                }
                Err(errno_err(crate::EINVAL))
            }
        }
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
    // One descriptor for the user, as Linux's userfaultfd returns: refused
    // past the jail's no-file limit (the serving end is this layer's own).
    crate::wick_nofile::check(1)?;
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
    let (alias, reserved) = crate::windows_mm::uffd_alias(start as usize, len as usize, &resident).map_err(errno_err)?;
    let alias = alias as u64;
    range.reserved.store(reserved, Ordering::Release);
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
    // Missing pages fault from now on (in a reserved section they are not
    // committed, and fault already).
    if !reserved {
        let mut runs = Vec::new();
        for_each_missing(start, len, |s, l| runs.push((s, l)));
        for (s, l) in runs {
            protect(s, l, false)?;
        }
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
        release_missing(range, base, alias, s, l).map_err(|e| e.raw_os_error().unwrap_or(crate::EIO))?;
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
    // A reserved section's pages are committed, and charged, first; the job's
    // limit refuses with ENOMEM, as the memory cgroup refuses Linux's copy.
    #[allow(clippy::cast_possible_truncation)]
    if range.reserved.load(Ordering::Acquire) && !crate::windows_mm::uffd_commit(dst as usize, bytes as usize) {
        return Err((crate::ENOMEM, 0));
    }
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
/// memory that is not registered and reports the pieces it reached (all of
/// the mapped memory, or what it reached before an error); the registered
/// pages of those pieces are missing again, their memory discarded, a whole
/// 2 MiB chunk of a reserved section given a new section and its commit and
/// charge given back (`windows_mm::uffd_swap_chunk`), and a remove event is
/// queued for each piece (with `EVENT_REMOVE`). Pages the
/// discard did not reach keep their contents, as on Linux when it stops at
/// an error.
pub fn discarding(start: u64, len: u64, discard: impl FnOnce(&mut Vec<(u64, u64)>) -> c_int) -> c_int {
    let end = start.saturating_add(len);
    let mut done = Vec::new();
    let touches = RANGES.iter().any(|r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    });
    if !touches {
        return discard(&mut done);
    }
    let _guard = LOCK.lock().unwrap();
    let ret = discard(&mut done);
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let alias = r.alias.load(Ordering::Acquire);
        let ctx = r.ctx.load(Ordering::Acquire);
        let remove = CTXS[ctx].features.load(Ordering::Acquire) & FEATURE_EVENT_REMOVE != 0;
        for &(a, b) in &done {
            // The range's whole pages inside the piece.
            let (first, last) = ((a.max(s) - s).div_ceil(PAGE), (b.min(e).max(s) - s) / PAGE);
            let mut any = false;
            for page in first..last {
                if Range::test(&r.tracked, page) {
                    Range::set(&r.missing, page, true);
                    any = true;
                }
            }
            if !any {
                continue;
            }
            let (from, to) = (s + first * PAGE, s + last * PAGE);
            // Whole chunks of a reserved section, all registered: a new
            // section in their place, the old one's commit given back
            // (`windows_mm::uffd_swap_chunk`); they then have no memory for
            // the runs below.
            if r.reserved.load(Ordering::Acquire) {
                let chunk = crate::windows_mm::UFFD_CHUNK as u64 / PAGE;
                let pages = (e - s) / PAGE;
                let mut c = first.div_ceil(chunk) * chunk;
                while c < last {
                    let c_end = (c + chunk).min(pages);
                    if c_end > last {
                        break;
                    }
                    if (c..c_end).all(|p| Range::test(&r.tracked, p)) {
                        #[allow(clippy::cast_possible_truncation)]
                        crate::windows_mm::uffd_swap_chunk((s + c * PAGE) as usize, ((c_end - c) * PAGE) as usize, (alias + c * PAGE) as usize);
                    }
                    c += chunk;
                }
            }
            let mut runs = Vec::new();
            for_each_missing(from, to - from, |a, l| runs.extend(with_memory(r, a, l)));
            for (a, l) in runs {
                let _ = protect(a, l, false);
                // Filling a missing page writes all of it: its content can go.
                // SAFETY: the alias of registered memory.
                unsafe { DiscardVirtualMemory((alias + (a - s)) as *mut c_void, l as usize) };
                // Its charge stays, as its section page does (a section's
                // page cannot be decommitted: SECTREC-h): the charge pays for
                // the host commit, so that the job and the jailer's count
                // (private commit plus section commit less the charge) agree
                // and neither refuses a VMM whose live memory is under
                // memory.max. Where Linux would uncharge it, this counts it
                // until its chunk is discarded whole (`uffd_swap_chunk`, which
                // gives both back) or unmapped.
            }
            if remove {
                post(ctx, [proto::EVENT_REMOVE, from, to, 0]);
            }
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
            let _ = release_missing(r, s, alias, a, l);
            for page in (a - s) / PAGE..(a + l - s) / PAGE {
                Range::set(&r.missing, page, false);
            }
        }
        r.start.store(0, Ordering::Release);
        REGISTERED.fetch_sub(1, Ordering::AcqRel);
        let alias = r.alias.swap(0, Ordering::AcqRel);
        if alias != 0 {
            // Kept with the mapping while its discarded pages are still to
            // be zeroed through it (`windows_mm::uffd_stale`).
            #[allow(clippy::cast_possible_truncation)]
            crate::windows_mm::uffd_unalias(s as usize, (e - s) as usize, alias as usize, r.reserved.load(Ordering::Acquire));
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
    Some((s != INVALID_SOCKET).then(|| adopt(s)).flatten())
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
    prefault_registered(addr, len, write)
}

/// [`prefault`] of the registered pages alone: a write that takes the lazy
/// memory of its buffer as it is (`windows_fd`'s, which reads untouched lazy
/// pages as zeros without committing them) still has the missing pages of
/// a userfaultfd's range filled first, as Linux's copy faults them.
pub fn prefault_registered(addr: u64, len: u64, write: bool) -> bool {
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
        // A refused discard (an unaligned start) makes nothing missing.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + 2 * PAGE + 1) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, -1);
        assert!(!is_missing(mem + 2 * PAGE));
        // The missing runs of a span as large as the address space, found
        // without a walk by pages over the memory nobody registered.
        // Other tests' registrations can lie right next to this one, and a
        // run of missing pages goes on across them
        // (`test_adjacent_ranges_stay_apart`): only the part of each run in
        // this range is this test's.
        let mut runs = Vec::new();
        for_each_missing(PAGE, u64::MAX / 2, |a, l| runs.push((a, l)));
        let end = mem + len as u64;
        let runs: Vec<_> = runs
            .into_iter()
            .filter_map(|(a, l)| {
                let (s, e) = (a.max(mem), (a + l).min(end));
                (s < e).then(|| (s, e - s))
            })
            .collect();
        assert_eq!(runs, [(mem + PAGE, PAGE), (mem + 4 * PAGE, len as u64 - 4 * PAGE)]);

        // Unregistered: missing pages read as zeros, nothing faults.
        unregister(ctx, mem, len as u64).unwrap();
        // SAFETY: ordinary memory now.
        assert_eq!(unsafe { *((mem + PAGE) as *const u8) }, 0);
        assert_eq!(unsafe { *((mem + 4 * PAGE) as *const u8) }, 0);
        // SAFETY: closes the user end; the serving thread ends.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The bytes of `[mem, mem + len)` committed.
    fn committed(mem: u64, len: u64) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::committed_runs(mem as usize, len as usize).iter().map(|r| r.1 as u64).sum()
    }

    /// Registered memory is a reserved section, charged a page at a time as
    /// the handler fills it, as Linux charges the page a `UFFDIO_COPY`
    /// allocates to the memory cgroup (v6.1 mm/userfaultfd.c,
    /// `mcopy_atomic_pte`, `mem_cgroup_charge` at :205): at the registration
    /// only the resident page is committed and charged; each page filled is
    /// committed and charged; a discarded page keeps its commit (a
    /// section's page cannot be decommitted: SECTREC-h, error 87) and with it
    /// its charge, which pays for that commit, where Linux uncharges it; a
    /// refill charges it once; once unregistered, the discarded page is
    /// zeroed at its first access, and a page never filled is committed and
    /// charged at its first access, a read included, as a shmem page is; the
    /// charge goes with the mapping. Before, the whole section was committed at the
    /// registration and charged to no job.
    #[test]
    fn test_registered_memory_is_charged_as_it_is_filled() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * PAGE;
        let mem = map(len as usize);
        // SAFETY: our mapping.
        unsafe { *(mem as *mut u8) = 7 };
        register(ctx, mem, len).unwrap();
        assert!(range_of(ctx, mem, len).unwrap().reserved.load(Ordering::Acquire), "the section is not reserved");
        let charged = || crate::windows_mm::charged(mem as usize).expect("no charge for the range");
        assert_eq!(committed(mem, len), PAGE, "committed at the registration");
        assert_eq!(charged(), PAGE as usize, "charged at the registration");
        let data = std::vec![0x5au8; 3 * PAGE as usize];
        // SAFETY: `data` holds three pages.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + PAGE, 3 * PAGE, true) }.unwrap(), 3 * PAGE);
        assert_eq!(zeropage(ctx, mem + 8 * PAGE, PAGE, true).unwrap(), PAGE);
        assert_eq!(committed(mem, len), 5 * PAGE);
        assert_eq!(charged(), 5 * PAGE as usize);
        // SAFETY: filled pages.
        unsafe {
            assert_eq!(*(mem as *const u8), 7);
            assert_eq!(*((mem + 3 * PAGE + 9) as *const u8), 0x5a);
            assert_eq!(*((mem + 8 * PAGE) as *const u8), 0);
        }
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert!(is_missing(mem + PAGE));
        // Its charge kept, as its section page stays committed (SECTREC-h):
        // the charge pays for the host commit a page holds, so that no layer
        // counts more than wick's charge (in a chunk discarded whole both go,
        // `test_a_wholly_discarded_chunk_gives_its_section_commit_back`).
        assert_eq!(charged(), 5 * PAGE as usize, "a discarded page's charge");
        assert_eq!(committed(mem, len), 5 * PAGE);
        // Filled again and discarded again: charged once.
        assert_eq!(zeropage(ctx, mem + PAGE, PAGE, true).unwrap(), PAGE);
        assert_eq!(charged(), 5 * PAGE as usize, "a refilled page's charge");
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(charged(), 5 * PAGE as usize, "a page discarded twice");
        unregister(ctx, mem, len).unwrap();
        assert_eq!(charged(), 5 * PAGE as usize, "the discarded page's charge at the unregister");
        // SAFETY: ordinary memory now: the discarded page reads zeros, and
        // a page never filled is committed at its read.
        unsafe {
            assert_eq!(*((mem + PAGE) as *const u8), 0);
            assert_eq!(charged(), 5 * PAGE as usize, "the discarded page's charge after its first read");
            assert!(std::slice::from_raw_parts((mem + PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0));
            assert_eq!(*((mem + 3 * PAGE + 9) as *const u8), 0x5a);
            assert_eq!(*((mem + 20 * PAGE) as *const u8), 0);
            *((mem + 21 * PAGE) as *mut u8) = 1;
        }
        assert_eq!(committed(mem, len), 7 * PAGE);
        assert_eq!(charged(), 7 * PAGE as usize);
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, len as usize) }, 0);
        assert!(crate::windows_mm::charged(mem as usize).is_none(), "the charge outlived the mapping");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A discard of whole 2 MiB chunks of registered memory gives their
    /// section commit back, as Linux frees the pages `MADV_DONTNEED` zaps
    /// (a balloon's free page reporting gives 2 MiB blocks: v6.1
    /// mm/page_reporting.c, `pageblock_order`): the registration maps one
    /// section per chunk (`windows_mm::UFFD_CHUNK`), and a chunk discarded
    /// whole has a new, empty section put in its place in both views
    /// (UFFDCHUNK b: 8.7 us; WHP follows the host's address, UFFDCHUNK a).
    /// Two chunks and a part, filled by one copy across them (the fill split
    /// at each chunk's views): chunk 0 and half of chunk 1 discarded; chunk
    /// 0 then has no page committed nor charged, chunk 1 keeps its section's
    /// pages and their charge, its discarded half's included; each
    /// discarded page is missing again and a refill reads back; the last,
    /// partial chunk discarded whole has none committed either; the charge
    /// follows each step.
    #[test]
    fn test_a_wholly_discarded_chunk_gives_its_section_commit_back() {
        const CHUNK: u64 = 2 << 20;
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK + 16 * PAGE;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        assert!(range_of(ctx, mem, len).unwrap().reserved.load(Ordering::Acquire), "the section is not reserved");
        #[allow(clippy::cast_possible_truncation)]
        let charged = || -> u64 {
            [mem, mem + CHUNK, mem + 2 * CHUNK]
                .iter()
                .map(|&c| crate::windows_mm::charged(c as usize).expect("no charge for a chunk") as u64)
                .sum()
        };
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        assert_eq!(committed(mem, len), len);
        assert_eq!(charged(), len);
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise(mem as *mut c_void, (CHUNK + CHUNK / 2) as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(committed(mem, CHUNK), 0, "a chunk discarded whole keeps its section commit");
        assert_eq!(committed(mem + CHUNK, CHUNK), CHUNK, "a chunk discarded in part");
        // Chunk 0's charge goes with its section; chunk 1's discarded half
        // keeps its charge, as it keeps its section pages.
        assert_eq!(charged(), len - CHUNK);
        for at in [mem, mem + CHUNK - PAGE, mem + CHUNK, mem + CHUNK + CHUNK / 2 - PAGE] {
            assert!(is_missing(at), "{:#x} is not missing", at - mem);
        }
        assert!(!is_missing(mem + CHUNK + CHUNK / 2));
        // A refill of chunk 0, through its new section.
        let seven = std::vec![7u8; PAGE as usize];
        // SAFETY: a page-sized buffer.
        assert_eq!(unsafe { copy(ctx, seven.as_ptr(), mem + 5 * PAGE, PAGE, true) }.unwrap(), PAGE);
        // SAFETY: a filled page.
        assert_eq!(unsafe { *((mem + 5 * PAGE + 9) as *const u8) }, 7);
        assert_eq!(committed(mem, CHUNK), PAGE);
        assert_eq!(charged(), len - CHUNK + PAGE);
        // SAFETY: a page of chunk 1 not discarded.
        assert_eq!(unsafe { *((mem + CHUNK + CHUNK / 2) as *const u8) }, 0x5a);
        // The last chunk, of 16 pages, discarded whole.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + 2 * CHUNK) as *mut c_void, 16 * PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(committed(mem + 2 * CHUNK, 16 * PAGE), 0, "the last chunk discarded whole");
        assert_eq!(charged(), CHUNK + PAGE);
        unregister(ctx, mem, len).unwrap();
        // SAFETY: our mapping, unregistered: every page reads, the
        // discarded ones as zeros.
        unsafe {
            assert_eq!(*((mem + 6 * PAGE) as *const u8), 0);
            assert_eq!(*((mem + CHUNK) as *const u8), 0);
            assert_eq!(*((mem + 2 * CHUNK + 3 * PAGE) as *const u8), 0);
            assert_eq!(*((mem + 5 * PAGE) as *const u8), 7);
            assert_eq!(*((mem + 2 * CHUNK - PAGE) as *const u8), 0x5a);
        }
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, len as usize) }, 0);
        for c in [mem, mem + CHUNK, mem + 2 * CHUNK] {
            assert!(crate::windows_mm::charged(c as usize).is_none(), "a chunk's charge outlived the mapping");
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// In a process whose job may commit 64 MiB, 256 MiB are registered and
    /// filled 1 MiB at a time: a fill past the limit fails with `ENOMEM`,
    /// as Linux's `UFFDIO_COPY` does when the memory cgroup refuses the
    /// page's charge, and the process goes on. Before, the 256 MiB were
    /// committed at the registration and no job charged them.
    #[test]
    fn test_a_fill_past_the_job_limit_fails_with_enomem() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        let exe = std::env::current_exe().unwrap();
        // The child's name as libtest knows it: this module is the crate's
        // `wick_uffd` (lib.rs's `#[path]`), not its file's name (CI run
        // 43528910212 ran "windows_uffd::tests::fill_limit_child": no test).
        let name = std::format!("{}::fill_limit_child", module_path!().split_once("::").unwrap().1);
        let child = std::process::Command::new(exe)
            .args(["--exact", name.as_str(), "--ignored", "--nocapture"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // The job is set before the child registers anything (it sleeps 300 ms first).
        // SAFETY: a new unnamed job.
        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        assert!(!job.is_null());
        // SAFETY: plain data.
        let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
        limit.JobMemoryLimit = 64 << 20;
        // SAFETY: a structure of the size passed; the child's handle.
        unsafe {
            #[allow(clippy::cast_possible_truncation)]
            let size = std::mem::size_of_val(&limit) as u32;
            assert_ne!(SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const limit).cast(), size), 0);
            use std::os::windows::io::AsRawHandle;
            assert_ne!(AssignProcessToJobObject(job, child.as_raw_handle()), 0, "{}", io::Error::last_os_error());
        }
        let out = child.wait_with_output().unwrap();
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        // SAFETY: our job handle.
        unsafe { CloseHandle(job) };
        assert!(text.contains("running 1 test"), "the child {name} ran no test (status {}): {text}", out.status);
        assert!(text.contains("registered 256 MiB"), "the child did not register (status {}): {text}", out.status);
        assert!(text.contains("refused with ENOMEM after"), "the job's limit did not hold: {text}");
        assert!(text.contains("test result: ok. 1 passed"), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_past_the_job_limit_fails_with_enomem in a job of its own"]
    fn fill_limit_child() {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (ctx, user) = create(0, false, true).unwrap();
        let len: u64 = 256 << 20;
        // As Firecracker maps guest memory: committed at first touch, so the
        // mapping itself fits the job.
        // SAFETY: a new anonymous mapping.
        let mem = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        register(ctx, mem, len).unwrap();
        std::println!("registered 256 MiB");
        let mib: u64 = 1 << 20;
        let mut done = 0;
        let refused = loop {
            assert!(done < len, "256 MiB filled under a 64 MiB limit");
            match zeropage(ctx, mem + done, mib, false) {
                Ok(n) => done += n,
                Err((e, n)) => break (e, n),
            }
        };
        std::println!("refused with {} after {} MiB", if refused.0 == crate::ENOMEM { "ENOMEM" } else { "another error" }, done >> 20);
        assert_eq!(refused, (crate::ENOMEM, 0));
        assert!((16 << 20..64 << 20).contains(&done), "{} MiB filled under a 64 MiB limit", done >> 20);
        // The pages filled are there, the refused ones still missing.
        // SAFETY: filled.
        assert_eq!(unsafe { *(mem as *const u8) }, 0);
        assert!(is_missing(mem + done));
        // SAFETY: closes the user end.
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

    /// Two registrations side by side, of two userfaultfds (as two tests'
    /// mappings, or two of Firecracker's, can be): a run of missing pages
    /// goes on across the boundary, but nothing is reported past the span
    /// asked for, and a discard of one range never touches the other or
    /// tells the other's userfaultfd.
    #[test]
    fn test_adjacent_ranges_stay_apart() {
        let len = 64 * 1024usize;
        let ulen = len as u64;
        // SAFETY: a reservation, then two mappings over it, as Firecracker maps guest memory.
        let base = unsafe {
            crate::mmap(ptr::null_mut(), 2 * len, crate::PROT_NONE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(base, crate::MAP_FAILED);
        let (a, b) = (base as u64, base as u64 + ulen);
        for m in [a, b] {
            // SAFETY: over our reservation.
            let p = unsafe {
                crate::mmap(
                    m as *mut c_void,
                    len,
                    crate::PROT_READ | crate::PROT_WRITE,
                    crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED,
                    -1,
                    0,
                )
            };
            assert_eq!(p as u64, m);
        }
        let (ca, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let (cb, ub) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        register(ca, a, ulen).unwrap();
        register(cb, b, ulen).unwrap();

        // All pages of both are missing: one run across the boundary, as the
        // CI failure of test_host_fault_copy_zeropage saw it (28 pages from
        // its range's 12 and a neighbour's 16) ...
        let mut runs = Vec::new();
        for_each_missing(PAGE, u64::MAX / 2, |s, l| runs.push((s, l)));
        assert!(runs.iter().any(|&(s, l)| s <= a && s + l >= b + ulen), "{runs:x?}");
        // ... but never past the span asked for.
        let mut runs = Vec::new();
        for_each_missing(a, ulen, |s, l| runs.push((s, l)));
        assert_eq!(runs, [(a, ulen)]);
        let mut runs = Vec::new();
        for_each_missing(b + PAGE, PAGE, |s, l| runs.push((s, l)));
        assert_eq!(runs, [(b + PAGE, PAGE)]);

        // B's first page filled, with content.
        let five = std::vec![5u8; PAGE as usize];
        // SAFETY: a page-sized buffer into B's missing first page.
        assert_eq!(unsafe { copy(cb, five.as_ptr(), b, PAGE, true) }.unwrap(), PAGE);
        // A discard of A alone: A's event only; B's page is still there.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise(a as *mut c_void, len, crate::MADV_DONTNEED) }, 0);
        let mut buf = [0u8; proto::RECORD];
        assert!(recv_all(ua, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, a, b]);
        assert!(!is_missing(b));
        // SAFETY: B's present page.
        assert_eq!(unsafe { *(b as *const u8) }, 5);
        // B's first event is its own discard, not A's.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise(b as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert!(recv_all(ub, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, b, b + PAGE]);
        // A discard of both: each userfaultfd hears of its own range only.
        // SAFETY: our mappings.
        assert_eq!(unsafe { crate::madvise(a as *mut c_void, 2 * len, crate::MADV_DONTNEED) }, 0);
        assert!(recv_all(ua, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, a, b]);
        assert!(recv_all(ub, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, b, b + ulen]);

        unregister(ca, a, ulen).unwrap();
        unregister(cb, b, ulen).unwrap();
        // SAFETY: closes the user ends; our mappings.
        unsafe {
            ws::closesocket(sock(ua));
            ws::closesocket(sock(ub));
            crate::munmap(base, 2 * len);
        }
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
