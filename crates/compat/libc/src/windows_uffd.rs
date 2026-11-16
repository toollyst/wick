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
//!   allocates (`ENOMEM` when refused). A page missing when it leaves the
//!   registration (unregistered, or the userfaultfd released) is resolved
//!   at its first access: committed if never filled, zeroed if discarded
//!   (its range's record, `windows_mm::released_pend`).
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
use std::sync::Once;
#[cfg(test)]
use std::sync::Mutex;

use crate::windows_stacklock::ProbedMutex;
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
    DiscardVirtualMemory, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, VirtualProtect,
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
    /// One bit per page: its protection (`mprotect`) denies reads, and so
    /// every access (`PROT_NONE`).
    noread: AtomicPtr<AtomicU64>,
    /// One bit per page: its protection denies writes (`PROT_READ`, or
    /// `PROT_NONE`).
    nowrite: AtomicPtr<AtomicU64>,
    /// The record its released pages go to, taken at the register
    /// (`windows_mm::released_reserve`; a reserved section's only).
    record: AtomicUsize,
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
            noread: AtomicPtr::new(ptr::null_mut()),
            nowrite: AtomicPtr::new(ptr::null_mut()),
            record: AtomicUsize::new(0),
        }
    }

    /// The protection `mprotect` gave `page`, as Windows' (read-write until
    /// one is given).
    fn prot(&self, page: u64) -> PAGE_PROTECTION_FLAGS {
        if Self::test(&self.noread, page) {
            PAGE_NOACCESS
        } else if Self::test(&self.nowrite, page) {
            PAGE_READONLY
        } else {
            PAGE_READWRITE
        }
    }

    /// Whether `page`'s protection denies the access (a write if `write`):
    /// then it is no userfault.
    fn denies(&self, page: u64, write: bool) -> bool {
        Self::test(&self.noread, page) || (write && Self::test(&self.nowrite, page))
    }

    /// Calls `f(start, len, prot)` for each run of `[s, s + len)` (pages of
    /// this range, whose first page is at `base`) of one protection.
    fn by_prot(&self, base: u64, s: u64, len: u64, mut f: impl FnMut(u64, u64, PAGE_PROTECTION_FLAGS)) {
        let mut run: Option<(u64, PAGE_PROTECTION_FLAGS)> = None;
        let mut at = s;
        while at < s + len {
            let prot = self.prot((at - base) / PAGE);
            match run {
                Some((_, p)) if p == prot => {}
                Some((r, p)) => {
                    f(r, at - r, p);
                    run = Some((at, prot));
                }
                None => run = Some((at, prot)),
            }
            at += PAGE;
        }
        if let Some((r, p)) = run {
            f(r, s + len - r, p);
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
/// Serializes changes to the ranges. Taken through [`lock`].
static LOCK: ProbedMutex<()> = ProbedMutex::new("the userfaultfd ranges' LOCK", ());

std::thread_local! {
    /// This thread holds [`LOCK`]: a reclaim it would start (a lazy page a
    /// fill's source buffer touches) cannot take it again.
    static HOLDS_LOCK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// [`LOCK`], held until the guard drops.
struct Locked(#[allow(dead_code)] crate::windows_stacklock::Probed<std::sync::MutexGuard<'static, ()>>);

impl Drop for Locked {
    fn drop(&mut self) {
        HOLDS_LOCK.set(false);
    }
}

#[track_caller]
fn lock() -> Locked {
    let g = LOCK.lock().unwrap();
    HOLDS_LOCK.set(true);
    Locked(g)
}

/// The chunk a reclaim is moving (`[start, end)`, start 0 when none,
/// [`move_chunk`]): an access to it waits for the move ([`fault`]).
static MOVING_START: AtomicU64 = AtomicU64::new(0);
static MOVING_END: AtomicU64 = AtomicU64::new(0);

/// Whether `addr` is in the chunk being moved.
pub fn is_moving(addr: u64) -> bool {
    let s = MOVING_START.load(Ordering::SeqCst);
    s != 0 && addr >= s && addr < MOVING_END.load(Ordering::SeqCst)
}
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
    // A chunk being moved by a reclaim: closed for the move's time (a few
    // hundred microseconds), then open in its new section; the access runs
    // again.
    if is_moving(addr) {
        let t = std::time::Instant::now();
        while is_moving(addr) {
            std::thread::yield_now();
        }
        MOVE_WAITS.fetch_add(1, Ordering::Relaxed);
        MOVE_WAITED_US.fetch_add(u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX), Ordering::Relaxed);
        return true;
    }
    let Some((range, page)) = find(addr) else {
        return false;
    };
    if !Range::test(&range.tracked, page) || !Range::test(&range.missing, page) {
        return false;
    }
    // An access its protection denies is the access fault, not a userfault:
    // Linux checks the vma's protection first (v6.1 arch/x86/mm/fault.c,
    // `do_user_addr_fault`: `access_error` at :1410, before
    // `handle_mm_fault` at :1428, where `do_anonymous_page` hands a missing
    // page to userfaultfd).
    if range.denies(page, write) {
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

/// Called first in [`on_exception`] at an access violation, for tests: it
/// holds the handler between the fault and its checks
/// (`test_a_host_access_that_faulted_before_its_fill_runs_again`). An
/// `fn()` as a `usize`, 0 for none.
#[cfg(test)]
static EXCEPTION_HOOK: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" fn on_exception(info: *mut EXCEPTION_POINTERS) -> i32 {
    // SAFETY: the system passes valid exception pointers.
    let rec = unsafe { &*(*info).ExceptionRecord };
    if rec.ExceptionCode == ACCESS_VIOLATION && rec.NumberParameters >= 2 {
        #[cfg(test)]
        {
            let hook = EXCEPTION_HOOK.load(Ordering::SeqCst);
            if hook != 0 {
                // SAFETY: only `fn()` values are stored.
                unsafe { core::mem::transmute::<usize, fn()>(hook)() };
            }
        }
        // [0]: 0 read, 1 write, 8 execute; [1]: the address.
        let addr = rec.ExceptionInformation[1] as u64;
        let write = rec.ExceptionInformation[0] == 1;
        if (is_moving(addr) || is_missing(addr)) && fault(addr, write) {
            // Re-run the access.
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // Registered memory that faulted while missing or moving and is
        // accessible by now (filled, or its move over, before this handler
        // looked: the thread preempted in between): the access runs again,
        // as Linux's fault returns for it when it finds the page no longer
        // missing (v6.1 mm/userfaultfd.c, `userfaultfd_must_wait`). Not an
        // execution (8): guest RAM is never executable here.
        #[allow(clippy::cast_possible_truncation)]
        if rec.ExceptionInformation[0] != 8 && find(addr).is_some() && crate::windows_mm::accessible(addr as usize, 1, write) {
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

/// Calls `f(start, len)` for each run of `[addr, addr + len)` of `range`
/// that has memory, in order: all of it, or, in a reserved section, its
/// committed runs (an uncommitted page faults already, and has no
/// protection to change or memory to discard). Allocates nothing.
fn with_memory(range: &Range, addr: u64, len: u64, mut f: impl FnMut(u64, u64)) {
    if !range.reserved.load(Ordering::Acquire) {
        f(addr, len);
        return;
    }
    #[allow(clippy::cast_possible_truncation)]
    crate::windows_mm::for_each_committed_run(addr as usize, len as usize, |s, l| f(s as u64, l as u64));
}

/// Missing pages `[s, s + len)` of `range`, whose alias is at `alias` and
/// which starts at `base`, become ordinary memory: in a reserved section
/// they are pending in the range's record, each resolved at its first
/// access (committed if never filled; zeroed through the alias if filled
/// once and discarded, its commit and charge kept by `discarding`, as Linux
/// gives a zapped page as zeros at its next touch), with the protection
/// `mprotect` gave it, which stays with the memory as a vma's does on
/// Linux; elsewhere zeroed and made accessible now. Allocates nothing (the
/// release runs at the job's limit).
fn release_missing(range: &Range, base: u64, alias: u64, s: u64, len: u64) -> io::Result<()> {
    if range.reserved.load(Ordering::Acquire) {
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::released_pend(range.record.load(Ordering::Acquire), alias as usize, s as usize, len as usize, |at| {
            range.prot((at as u64 - base) / PAGE)
        });
        return Ok(());
    }
    // SAFETY: the alias of registered memory.
    unsafe { ptr::write_bytes((alias + (s - base)) as *mut u8, 0, len as usize) };
    let mut result = Ok(());
    range.by_prot(base, s, len, |r, n, prot| {
        if result.is_ok() {
            result = protect_as(r, n, prot);
        }
    });
    result
}

/// Changes the protection of committed registered memory, a view at a time
/// (`VirtualProtect` stays within one allocation; a reserved section is a
/// view per chunk, `windows_mm::UFFD_CHUNK`).
fn protect(addr: u64, len: u64, accessible: bool) -> io::Result<()> {
    protect_as(addr, len, if accessible { PAGE_READWRITE } else { PAGE_NOACCESS })
}

/// [`protect`] with the protection `prot`.
fn protect_as(addr: u64, len: u64, prot: PAGE_PROTECTION_FLAGS) -> io::Result<()> {
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
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
    let _guard = lock();
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
    let _guard = lock();
    if RANGES.iter().any(|r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    }) {
        return Err(errno_err(crate::EBUSY));
    }
    let Some(range) = RANGES.iter().find(|r| r.start.load(Ordering::Acquire) == 0) else {
        return Err(errno_err(crate::ENOMEM));
    };
    // The record its released pages go to, with its bitmaps, taken now: the
    // release runs at the job's limit and cannot fail.
    #[allow(clippy::cast_possible_truncation)]
    let record = crate::windows_mm::released_reserve(start as usize, len as usize).map_err(errno_err)?;
    let undo = |e: io::Error| {
        crate::windows_mm::released_unreserve(record);
        e
    };
    // The reclaim's working memory for every chunk registered with this one,
    // reserved now, so that a reclaim at the limit allocates nothing.
    let chunks = usize::try_from(len.div_ceil(crate::windows_mm::UFFD_CHUNK as u64)).unwrap_or(usize::MAX);
    reserve_reclaim(registered_chunks().saturating_add(chunks)).map_err(undo)?;
    let pages = len / PAGE;
    // Residency decides what is missing.
    let mut resident = std::vec![0u8; pages as usize];
    // SAFETY: `resident` has one byte per page of the range.
    if unsafe { crate::mincore(start as *mut _, len as usize, resident.as_mut_ptr()) } != 0 {
        return Err(undo(io::Error::last_os_error()));
    }
    let (alias, reserved) = crate::windows_mm::uffd_alias(start as usize, len as usize, &resident).map_err(|e| undo(errno_err(e)))?;
    if !reserved {
        // Its missing pages are zeroed and opened at their release.
        crate::windows_mm::released_unreserve(record);
    }
    let alias = alias as u64;
    range.record.store(record, Ordering::Release);
    range.reserved.store(reserved, Ordering::Release);
    let missing = alloc_bitmap(pages, false);
    let tracked = alloc_bitmap(pages, true);
    range.noread.store(alloc_bitmap(pages, false), Ordering::Release);
    range.nowrite.store(alloc_bitmap(pages, false), Ordering::Release);
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
    let _guard = lock();
    let range = range_of(ctx, start, len)?;
    let base = range.start.load(Ordering::Acquire);
    let alias = range.alias.load(Ordering::Acquire);
    // The missing runs, walked in place: a run is reported once the walk is
    // past it, so its bits may change in the call.
    let mut result = Ok(());
    for_each_missing(start, len, |s, l| {
        if result.is_err() {
            return;
        }
        // Missing pages may hold discarded data: zeros, as Linux gives.
        result = release_missing(range, base, alias, s, l).map_err(|e| e.raw_os_error().unwrap_or(crate::EIO));
        if result.is_ok() {
            for page in (s - base) / PAGE..(s + l - base) / PAGE {
                Range::set(&range.missing, page, false);
            }
        }
    });
    for page in (start - base) / PAGE..(start + len - base) / PAGE {
        Range::set(&range.tracked, page, false);
    }
    result?;
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
    let _guard = lock();
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
    // Refused, dead pages are reclaimed first and the commit made again, as
    // Linux's memory cgroup reclaims before it refuses the copy's charge
    // (`reclaim_for_a_fill`).
    #[allow(clippy::cast_possible_truncation)]
    if range.reserved.load(Ordering::Acquire)
        && !crate::windows_mm::uffd_commit(dst as usize, bytes as usize)
        && !(reclaim_for_a_fill(bytes as usize).freed > 0 && crate::windows_mm::uffd_commit(dst as usize, bytes as usize))
    {
        return Err((crate::ENOMEM, 0));
    }
    fill((alias + (dst - base)) as *mut u8, bytes as usize);
    // Each page with the protection `mprotect` gave it (one filled while
    // `PROT_NONE` stays closed, as Linux's copy fills a page of a
    // `PROT_NONE` vma).
    let mut result = Ok(());
    range.by_prot(base, dst, bytes, |r, n, prot| {
        if result.is_ok() {
            result = protect_as(r, n, prot);
        }
    });
    result.map_err(|e| (e.raw_os_error().unwrap_or(crate::EIO), 0))?;
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

/// `mprotect` of the registered pages of `[start, end)` (page aligned) to
/// `prot` (Windows' `wprot`, `mprotect`'s `prot` given as `read`/`write`):
/// each page's protection is kept in its range, and given now to the
/// pages that hold their memory (filled, not missing); a missing page,
/// reserved or closed, takes it when it is filled ([`fill`]), and an access
/// it denies is no userfault ([`fault`]), as Linux's `mprotect` changes the
/// vma's protection and leaves its pages as they are. The registered spans
/// done, for `mprotect` to leave alone; `Err(errno)` if a protection could
/// not be given. Under [`LOCK`], which `mprotect` takes before the region
/// table, as `register` and the fills do.
pub(crate) fn mprotect_registered(start: u64, end: u64, read: bool, write: bool, wprot: PAGE_PROTECTION_FLAGS) -> Result<Vec<(u64, u64)>, c_int> {
    let mut done = Vec::new();
    if REGISTERED.load(Ordering::Acquire) == 0 {
        return Ok(done);
    }
    let _guard = lock();
    // The registered pages, and those of them that hold memory, by range.
    let mut live: Vec<(&'static Range, u64, u64, u64)> = Vec::new();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let (a, b) = (start.max(s), end.min(e));
        let (mut tracked_run, mut live_run): (Option<u64>, Option<u64>) = (None, None);
        let mut at = a;
        while at <= b {
            let page = (at - s) / PAGE;
            let tracked = at < b && Range::test(&r.tracked, page);
            let holds = tracked && !Range::test(&r.missing, page);
            match (tracked, tracked_run) {
                (true, None) => tracked_run = Some(at),
                (false, Some(t)) => {
                    done.push((t, at - t));
                    tracked_run = None;
                }
                _ => {}
            }
            match (holds, live_run) {
                (true, None) => live_run = Some(at),
                (false, Some(l)) => {
                    live.push((r, s, l, at - l));
                    live_run = None;
                }
                _ => {}
            }
            at += PAGE;
        }
    }
    // All or nothing within the registered pages: the pages with memory get
    // the protection first; if one cannot (a protection the view does not
    // allow, such as execute), those changed get theirs back, from the
    // bitmaps not yet changed, and nothing is changed. Linux changes a vma
    // whole or not at all (mm/mprotect.c, `mprotect_fixup`), and a failure
    // leaves the vmas before it changed: so do the spans `mprotect` does
    // after these.
    for (n, &(_, _, l, len)) in live.iter().enumerate() {
        if protect_as(l, len, wprot).is_err() {
            for &(r, s, l, len) in &live[..n] {
                r.by_prot(s, l, len, |a, k, prot| {
                    let _ = protect_as(a, k, prot);
                });
            }
            return Err(crate::EACCES);
        }
    }
    for &(a, len) in &done {
        let Some((r, _)) = find(a) else { continue };
        let s = r.start.load(Ordering::Acquire);
        for page in (a - s) / PAGE..(a + len - s) / PAGE {
            Range::set(&r.noread, page, !read && !write);
            Range::set(&r.nowrite, page, !write);
        }
    }
    Ok(done)
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
    let _guard = lock();
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
            for_each_missing(from, to - from, |a, l| with_memory(r, a, l, |a, l| {
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
            }));
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
    let _guard = lock();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        if s == 0 || r.ctx.load(Ordering::Acquire) != ctx {
            continue;
        }
        let e = r.end.load(Ordering::Acquire);
        let alias = r.alias.load(Ordering::Acquire);
        // Walked in place (no list of the runs: this runs at the job's limit,
        // `test_a_userfaultfd_released_at_the_limit_allocates_nothing`); a
        // run is reported once the walk is past it.
        for_each_missing(s, e - s, |a, l| {
            let _ = release_missing(r, s, alias, a, l);
            for page in (a - s) / PAGE..(a + l - s) / PAGE {
                Range::set(&r.missing, page, false);
            }
        });
        r.start.store(0, Ordering::Release);
        REGISTERED.fetch_sub(1, Ordering::AcqRel);
        let alias = r.alias.swap(0, Ordering::AcqRel);
        let reserved = r.reserved.load(Ordering::Acquire);
        if alias != 0 {
            // Kept with the mapping while its discarded pages are still to
            // be zeroed through it (pending in its record).
            #[allow(clippy::cast_possible_truncation)]
            crate::windows_mm::uffd_unalias(s as usize, (e - s) as usize, alias as usize, reserved);
        }
        // The record's pages are published before the waiters wake: a
        // thread that faulted on a missing page runs its access again and
        // finds it pending there.
        if reserved {
            crate::windows_mm::released_end(r.record.load(Ordering::Acquire));
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
    #[cfg(test)]
    tests::KIND.with(|k| k.set(tests::SERVE));
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

/// What a reclaim did ([`reclaim_at_touch`], [`reclaim_for_a_fill`]): the
/// chunks it moved, the live pages it copied, the bytes of dead pages it
/// gave back (their section commit and their charge), and the chunks it
/// passed over for a system call in flight on them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reclaimed {
    pub chunks: usize,
    pub copied: usize,
    pub freed: usize,
    pub skipped: usize,
}

impl Reclaimed {
    fn add(&mut self, o: Reclaimed) {
        self.chunks += o.chunks;
        self.copied += o.copied;
        self.freed += o.freed;
    }
}

/// A chunk with dead pages ([`find_candidates`]): its guest view, its
/// length, its alias, and the bytes of its dead pages.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    view: usize,
    len: usize,
    alias: usize,
    dead: usize,
}

/// The reclaim's working memory, reserved when a range is registered
/// ([`reserve_reclaim`]) for every chunk registered then, so that a reclaim
/// allocates nothing: it runs when the job has refused commit, where a heap
/// that must grow would end the process instead (Linux's reclaim takes no
/// memory on that path either; `test_a_reclaim_allocates_nothing`).
/// `CANDIDATES` is a reclaim's list, under [`LOCK`]; `TOUCH_SKIPPED` the
/// chunks a touch's reclaim passed over and waits for, under its own lock,
/// which one touch's wait holds ([`reclaim_at_touch`]).
static CANDIDATES: ProbedMutex<Vec<Candidate>> = ProbedMutex::new("CANDIDATES", Vec::new());
static TOUCH_SKIPPED: ProbedMutex<Vec<Candidate>> = ProbedMutex::new("TOUCH_SKIPPED", Vec::new());

/// Reserves the reclaim's working memory for `chunks` chunks registered at
/// once ([`CANDIDATES`], [`TOUCH_SKIPPED`]) and room for its discard guards
/// (`windows_mm::reserve_discards`): `ENOMEM` if it cannot be had, as a
/// registration whose memory cannot be charged is refused.
fn reserve_reclaim(chunks: usize) -> io::Result<()> {
    for list in [&CANDIDATES, &TOUCH_SKIPPED] {
        let mut l = list.lock().unwrap();
        if l.capacity() < chunks {
            let more = chunks - l.len();
            l.try_reserve_exact(more).map_err(|_| errno_err(crate::ENOMEM))?;
        }
    }
    if !crate::windows_mm::reserve_discards() {
        return Err(errno_err(crate::ENOMEM));
    }
    start_the_reclaimer()
}

/// The reclaim's own thread's stack, committed whole when it is made
/// (`CreateThread` without `STACK_SIZE_PARAM_IS_A_RESERVATION` takes the
/// size as the commit: Learn, CreateThread, `dwStackSize`), so that the
/// reclaim never grows a stack at the limit, where a stack that must grow
/// ends the process with `STATUS_STACK_OVERFLOW`
/// (`test_a_stack_that_grows_at_the_limit_on_record`). Learn, CreateThread:
/// "If this flag is not specified, dwStackSize specifies the commit size";
/// the record test reads the stack's committed region with `VirtualQuery`
/// at the thread's start. At least four times the deepest a reclaim took on
/// record, rounded up: 8592 bytes, a fill's and a touch's with no room
/// left, a debug build on Windows Server 2022 20348
/// (`test_the_reclaimers_stack_on_record`, which fails past a quarter).
const RECLAIMER_STACK: usize = 64 << 10;

/// A reclaim asked of [`reclaimer`], by a thread that holds [`LOCK`] for it
/// and waits for the answer: a fill's pass ([`reclaim_for_a_fill`]), a
/// touch's pass, with the list of the chunks it passes over
/// ([`reclaim_at_touch`]), or one chunk's move.
#[derive(Clone, Copy)]
enum Ask {
    None,
    Fill(usize),
    Touch(usize, *mut Vec<Candidate>),
    Move(Candidate),
    /// For `test_an_ask_of_a_reclaimer_that_has_ended_aborts`: the
    /// reclaimer returns, its thread ends.
    #[cfg(test)]
    End,
}

/// The request and its answer, between a thread that asks and [`reclaimer`].
struct Mailbox {
    ask: Ask,
    answer: Reclaimed,
    /// For `test_a_reclaim_allocates_nothing`: the reclaimer counts its
    /// allocations while it answers, and gives the count back.
    #[cfg(test)]
    count: bool,
    #[cfg(test)]
    allocations: u64,
}

// SAFETY: the list pointer in `Ask::Touch` is used only by the reclaimer
// while the thread that owns it waits for the answer.
unsafe impl Send for Mailbox {}

static MAILBOX: ProbedMutex<Mailbox> = ProbedMutex::new("MAILBOX", Mailbox {
    ask: Ask::None,
    answer: Reclaimed { chunks: 0, copied: 0, freed: 0, skipped: 0 },
    #[cfg(test)]
    count: false,
    #[cfg(test)]
    allocations: 0,
});
/// The events a request is made and answered with (auto-reset), and
/// whether [`reclaimer`] runs.
static ASKED: AtomicUsize = AtomicUsize::new(0);
static ANSWERED: AtomicUsize = AtomicUsize::new(0);
static RECLAIMER: Once = Once::new();
static RECLAIMER_RUNS: AtomicBool = AtomicBool::new(false);
/// [`reclaimer`]'s thread handle, which is signalled if it ends.
static RECLAIMER_THREAD: AtomicUsize = AtomicUsize::new(0);

/// Starts [`reclaimer`] once, at the first registration: `ENOMEM` if its
/// stack's commit or its events cannot be had, as a registration whose
/// reclaim could not run is refused.
fn start_the_reclaimer() -> io::Result<()> {
    use windows_sys::Win32::System::Threading::{CreateEventW, CreateThread};
    RECLAIMER.call_once(|| {
        // SAFETY: unnamed auto-reset events, not signalled.
        let (asked, answered) = unsafe { (CreateEventW(ptr::null(), 0, 0, ptr::null()), CreateEventW(ptr::null(), 0, 0, ptr::null())) };
        if asked.is_null() || answered.is_null() {
            return;
        }
        ASKED.store(asked as usize, Ordering::Release);
        ANSWERED.store(answered as usize, Ordering::Release);
        // SAFETY: a thread of ours that runs for the process; its stack's
        // size is its commit.
        let t = unsafe { CreateThread(ptr::null(), RECLAIMER_STACK, Some(reclaimer), ptr::null(), 0, ptr::null_mut()) };
        if !t.is_null() {
            // Kept for the process: an asker waits on it too.
            RECLAIMER_THREAD.store(t as usize, Ordering::Release);
            RECLAIMER_RUNS.store(true, Ordering::Release);
        }
    });
    if RECLAIMER_RUNS.load(Ordering::Acquire) { Ok(()) } else { Err(errno_err(crate::ENOMEM)) }
}

/// The reclaim's thread: each request answered on a stack committed whole
/// ([`RECLAIMER_STACK`]), under the [`LOCK`] its asker holds for it.
unsafe extern "system" fn reclaimer(_: *mut c_void) -> u32 {
    use windows_sys::Win32::System::Threading::{INFINITE, SetEvent, WaitForSingleObject};
    #[cfg(test)]
    paint_the_stack();
    #[cfg(test)]
    tests::KIND.with(|k| k.set(tests::RECLAIMER));
    // The asker holds the lock: a reclaim a fault here would start takes
    // nothing ([`reclaim_at_touch`]).
    HOLDS_LOCK.set(true);
    loop {
        // SAFETY: our event.
        unsafe { WaitForSingleObject(ASKED.load(Ordering::Acquire) as HANDLE, INFINITE) };
        let mut m = MAILBOX.lock().unwrap();
        #[cfg(test)]
        tests::COUNTING_ALLOCATIONS.with(|c| c.set(m.count));
        #[cfg(test)]
        tests::ALLOCATIONS.with(|a| a.set(0));
        m.answer = match m.ask {
            Ask::None => Reclaimed::default(),
            Ask::Fill(need) => fill_pass(need),
            // SAFETY: the asker's list, which it does not touch until the
            // answer (`Mailbox`).
            Ask::Touch(need, skipped) => touch_pass(need, unsafe { skipped.as_mut() }),
            Ask::Move(d) => move_again(&d),
            #[cfg(test)]
            Ask::End => return 0,
        };
        m.ask = Ask::None;
        #[cfg(test)]
        {
            tests::COUNTING_ALLOCATIONS.with(|c| c.set(false));
            m.allocations = tests::ALLOCATIONS.with(core::cell::Cell::get);
        }
        drop(m);
        // SAFETY: our event.
        unsafe { SetEvent(ANSWERED.load(Ordering::Acquire) as HANDLE) };
    }
}

/// Asks [`reclaimer`] for `ask` and waits for the answer; the caller holds
/// [`LOCK`] (which so serialises the asks). Shallow on the caller's stack:
/// a lock, two event calls. The wait is for the answer or the reclaimer's
/// end, which would leave the asker waiting for good: the process is
/// aborted then, named. The reclaimer does not return (a panic there
/// aborts the process, `panic = "abort"`, and a panic would not unwind
/// out of an `extern "system"` function either), so that end is the test's
/// only (`test_an_ask_of_a_reclaimer_that_has_ended_aborts`).
fn ask_the_reclaimer(ask: Ask) -> Reclaimed {
    use windows_sys::Win32::System::Threading::{INFINITE, SetEvent, WaitForMultipleObjects};
    RECLAIM_ASKS.fetch_add(1, Ordering::Relaxed);
    if !RECLAIMER_RUNS.load(Ordering::Acquire) {
        return Reclaimed::default();
    }
    {
        let mut m = MAILBOX.lock().unwrap();
        m.ask = ask;
        #[cfg(test)]
        {
            m.count = tests::COUNTING_ALLOCATIONS.with(core::cell::Cell::get);
        }
    }
    let both = [ANSWERED.load(Ordering::Acquire) as HANDLE, RECLAIMER_THREAD.load(Ordering::Acquire) as HANDLE];
    // SAFETY: our event and thread handles.
    let woken = unsafe {
        SetEvent(ASKED.load(Ordering::Acquire) as HANDLE);
        WaitForMultipleObjects(2, both.as_ptr(), 0, INFINITE)
    };
    if woken != 0 {
        crate::windows_mm::say_at_the_limit(format_args!(
            "wick: reclaim: the reclaim's thread has ended (wait {woken:#x}), so no reclaim can be answered: aborting"
        ));
        std::process::abort();
    }
    let m = MAILBOX.lock().unwrap();
    #[cfg(test)]
    tests::ALLOCATIONS.with(|a| a.set(a.get() + m.allocations));
    m.answer
}

/// The reclaimer's stack, painted below where it starts, for the record of
/// how deep a reclaim goes (`test_the_reclaimers_stack_on_record`).
#[cfg(test)]
const PAINT: u8 = 0xA5;
#[cfg(test)]
static PAINTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static STACK_BASE: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
#[inline(never)]
fn paint_the_stack() {
    let (base, limit): (usize, usize);
    // SAFETY: reads of the thread's own TEB.
    unsafe { core::arch::asm!("mov {0}, gs:[0x8]", "mov {1}, gs:[0x10]", out(reg) base, out(reg) limit, options(nostack, readonly, preserves_flags)) };
    let here = core::hint::black_box(&base) as *const usize as usize;
    let top = (here - 4096) & !15;
    // SAFETY: the thread's own committed stack below its frames.
    unsafe { core::ptr::write_bytes(limit as *mut u8, PAINT, top - limit) };
    PAINTED.store(limit, Ordering::Release);
    STACK_BASE.store(base, Ordering::Release);
    // What `VirtualQuery` says is committed from the thread's lowest
    // committed page up, before it is used.
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    let n = unsafe { windows_sys::Win32::System::Memory::VirtualQuery(limit as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) };
    let committed = if n != 0 && mbi.State == windows_sys::Win32::System::Memory::MEM_COMMIT { mbi.RegionSize } else { 0 };
    STACK_QUERIED.store(committed, Ordering::Release);
}

/// The reclaimer's stack committed at its start, by `VirtualQuery`.
#[cfg(test)]
static STACK_QUERIED: AtomicUsize = AtomicUsize::new(0);

/// What `VirtualQuery` found committed of the reclaimer's stack at its
/// start (`test_the_reclaimers_stack_on_record`).
#[cfg(test)]
pub(crate) fn reclaimer_stack_queried() -> usize {
    STACK_QUERIED.load(Ordering::Acquire)
}

/// The most of the reclaimer's stack used so far, and its committed size
/// (`test_the_reclaimers_stack_on_record`).
#[cfg(test)]
pub(crate) fn reclaimer_stack() -> (usize, usize) {
    let (limit, base) = (PAINTED.load(Ordering::Acquire), STACK_BASE.load(Ordering::Acquire));
    if limit == 0 {
        return (0, 0);
    }
    let mut at = limit;
    // SAFETY: the reclaimer's committed stack, read while it waits.
    while at < base && unsafe { core::ptr::read_volatile(at as *const u8) } == PAINT {
        at += 1;
    }
    (base - at, base - limit)
}

/// The chunks (`windows_mm::UFFD_CHUNK`) of the registered ranges, as
/// [`reserve_reclaim`] counts them: whole and part chunks of each range.
fn registered_chunks() -> usize {
    let chunk = crate::windows_mm::UFFD_CHUNK as u64;
    RANGES
        .iter()
        .filter(|r| r.start.load(Ordering::Acquire) != 0)
        .map(|r| usize::try_from((r.end.load(Ordering::Acquire) - r.start.load(Ordering::Acquire)).div_ceil(chunk)).unwrap_or(usize::MAX))
        .sum()
}

/// Whether the page at `at` of `range` (whose first page is at `s`) is
/// missing: for a committed page, dead.
fn missing_at(range: &Range, s: u64, at: usize) -> bool {
    Range::test(&range.missing, (at as u64 - s) / PAGE)
}

/// The bytes of the dead pages of `[view, view + len)` in `range` (whose
/// first page is at `s`): committed and missing.
fn dead_bytes(range: &Range, s: u64, view: usize, len: usize) -> usize {
    let mut dead = 0;
    crate::windows_mm::for_each_committed(view, len, |a, n| {
        dead += (a..a + n).step_by(PAGE as usize).filter(|&at| missing_at(range, s, at)).count() * PAGE as usize;
    });
    dead
}

/// Fills `out` (cleared first, never grown: the chunks past its capacity are
/// left out) with the chunks of reserved ranges, every page registered,
/// that hold dead pages: missing (discarded) but committed, a section page
/// and a charge each (a chunk discarded whole has none:
/// `windows_mm::uffd_swap_chunk`), the most dead first; a chunk with none
/// is never one. While a chunk owes its dead pages' charge
/// (`windows_mm::OWED`), only that one. Under [`LOCK`].
fn find_candidates(out: &mut Vec<Candidate>) {
    out.clear();
    let owing = crate::windows_mm::owing();
    let chunk = crate::windows_mm::UFFD_CHUNK as u64 / PAGE;
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        if s == 0 || !r.reserved.load(Ordering::Acquire) {
            continue;
        }
        let (e, alias) = (r.end.load(Ordering::Acquire), r.alias.load(Ordering::Acquire));
        let pages = (e - s) / PAGE;
        for c in (0..pages).step_by(chunk as usize) {
            let c_end = (c + chunk).min(pages);
            if !(c..c_end).all(|p| Range::test(&r.tracked, p)) {
                continue;
            }
            // A move maps the new section's view read-write: a live page
            // `mprotect` closed (`PROT_NONE`, `PROT_READ`) would be open
            // until its protection is given back, so its chunk is not moved.
            if (c..c_end).any(|p| !Range::test(&r.missing, p) && r.prot(p) != PAGE_READWRITE) {
                continue;
            }
            #[allow(clippy::cast_possible_truncation)]
            let (view, len) = ((s + c * PAGE) as usize, ((c_end - c) * PAGE) as usize);
            if owing.is_some_and(|p| !(view..view + len).contains(&p)) {
                continue;
            }
            let dead = dead_bytes(r, s, view, len);
            if dead > 0 && out.len() < out.capacity() {
                #[allow(clippy::cast_possible_truncation)]
                out.push(Candidate { view, len, alias: (alias + c * PAGE) as usize, dead });
            }
        }
    }
    // Unstable: a stable sort takes a buffer.
    out.sort_unstable_by_key(|d| core::cmp::Reverse(d.dead));
}

/// The range a chunk's view is in, and that range's first page.
fn range_of_view(view: usize) -> Option<(&'static Range, u64)> {
    find(view as u64).map(|(r, _)| (r, r.start.load(Ordering::Acquire)))
}

/// The moves made, for the record (RECLAIMREC): each one's live pages
/// copied (high 32 bits) and its time in microseconds (low 32), the first
/// [`MOVES_KEPT`]; fixed, as the reclaim allocates nothing.
const MOVES_KEPT: usize = 4096;
static MOVES: [AtomicU64; MOVES_KEPT] = [const { AtomicU64::new(0) }; MOVES_KEPT];
static MOVES_MADE: AtomicUsize = AtomicUsize::new(0);
/// The accesses that waited for a move ([`fault`]), and how long in all.
static MOVE_WAITS: AtomicU64 = AtomicU64::new(0);
static MOVE_WAITED_US: AtomicU64 = AtomicU64::new(0);
/// The reclaims asked for (a fill or a touch refused at the job's limit),
/// the candidate chunks their passes found, and the view of the chunk moved
/// last ([`reclaim_counts`]).
static RECLAIM_ASKS: AtomicU64 = AtomicU64::new(0);
static CANDIDATES_FOUND: AtomicU64 = AtomicU64::new(0);
static LAST_MOVED: AtomicUsize = AtomicUsize::new(0);

/// What the reclaim at the job's memory limit has done in this process
/// ([`reclaim_counts`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReclaimCounts {
    /// Reclaims asked for: each a fill or a first touch the job's limit
    /// refused.
    pub asks: u64,
    /// The chunks holding dead pages their passes found, summed.
    pub candidates: u64,
    /// The chunks moved into new sections.
    pub moves: u64,
    /// The moves begun and not made (`windows_mm::uffd_move_chunk`'s
    /// refusals: a view not mapped, live pages not committed).
    pub refused: u64,
    /// The address of the chunk moved last (its guest view), 0 for none.
    pub last_moved: usize,
}

/// The reclaim's counts so far: read-only, for a record of what it did
/// (MOVEUNDERVCPU). Each is bumped only where a reclaim is asked for, on
/// the reclaim's thread, or by a move; a fill or touch the limit does not
/// refuse reaches none of them.
pub fn reclaim_counts() -> ReclaimCounts {
    ReclaimCounts {
        asks: RECLAIM_ASKS.load(Ordering::Relaxed),
        candidates: CANDIDATES_FOUND.load(Ordering::Relaxed),
        moves: MOVES_MADE.load(Ordering::Relaxed) as u64,
        refused: crate::windows_mm::moves_refused(),
        last_moved: LAST_MOVED.load(Ordering::Relaxed),
    }
}

/// Moves one chunk (`windows_mm::uffd_move_chunk`), marked moving for its
/// time: an access to it meanwhile waits in [`fault`] until the mark goes
/// (the waiters of its missing pages wait on for their fill). Its dead
/// pages are its committed pages missing now (`d.dead` is what
/// [`find_candidates`] counted). Under [`LOCK`], with a discard's guard on
/// the chunk.
fn move_chunk(d: &Candidate) -> Reclaimed {
    let Some((range, s)) = range_of_view(d.view) else {
        return Reclaimed::default();
    };
    MOVING_END.store((d.view + d.len) as u64, Ordering::SeqCst);
    MOVING_START.store(d.view as u64, Ordering::SeqCst);
    let t = std::time::Instant::now();
    let moved = crate::windows_mm::uffd_move_chunk(d.view, d.len, d.alias, &|at| missing_at(range, s, at));
    let us = u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX);
    MOVING_START.store(0, Ordering::SeqCst);
    MOVING_END.store(0, Ordering::SeqCst);
    let Some((copied, freed)) = moved else {
        return Reclaimed::default();
    };
    let copied = copied / PAGE as usize;
    LAST_MOVED.store(d.view, Ordering::Relaxed);
    let n = MOVES_MADE.fetch_add(1, Ordering::Relaxed);
    if n < MOVES_KEPT {
        MOVES[n].store((copied as u64) << 32 | us.min(u64::from(u32::MAX)), Ordering::Relaxed);
    }
    Reclaimed { chunks: 1, copied, freed, skipped: 0 }
}

/// One pass over `chunks` until `need` bytes are given back: a chunk with a
/// system call in flight on it is passed over (`windows_mm::try_discard`)
/// and, if `skipped` is given, kept there (never grown). Under [`LOCK`].
fn reclaim_pass(need: usize, chunks: &[Candidate], mut skipped: Option<&mut Vec<Candidate>>) -> Reclaimed {
    let mut r = Reclaimed::default();
    for d in chunks {
        if r.freed >= need {
            break;
        }
        let Some(_guard) = crate::windows_mm::try_discard(d.view, d.len) else {
            r.skipped += 1;
            if let Some(s) = skipped.as_deref_mut() {
                if s.len() < s.capacity() {
                    s.push(*d);
                }
            }
            continue;
        };
        r.add(move_chunk(d));
    }
    r
}

/// The reclaim of a fill refused at the limit (under [`LOCK`], which the
/// fill holds): one pass, and no wait for the calls in flight on a chunk it
/// passed over. Such a call may be in its prefault, waiting for a fill
/// (`windows_mm::copying` counts it from before its prefault) that the
/// handler sends only once this one is answered, so the wait would not end;
/// the fill is refused instead (`ENOMEM`), as it was before.
fn reclaim_for_a_fill(need: usize) -> Reclaimed {
    ask_the_reclaimer(Ask::Fill(need))
}

/// [`reclaim_for_a_fill`]'s pass, on [`reclaimer`].
fn fill_pass(need: usize) -> Reclaimed {
    let mut c = CANDIDATES.lock().unwrap();
    find_candidates(&mut c);
    CANDIDATES_FOUND.fetch_add(c.len() as u64, Ordering::Relaxed);
    let r = reclaim_pass(need.max(crate::windows_mm::UFFD_CHUNK), &c, None);
    c.clear();
    r
}

/// [`reclaim_at_touch`]'s first pass, on [`reclaimer`].
fn touch_pass(need: usize, skipped: Option<&mut Vec<Candidate>>) -> Reclaimed {
    let mut c = CANDIDATES.lock().unwrap();
    find_candidates(&mut c);
    CANDIDATES_FOUND.fetch_add(c.len() as u64, Ordering::Relaxed);
    let r = reclaim_pass(need, &c, skipped);
    c.clear();
    r
}

/// A chunk [`reclaim_at_touch`] passed over and waited for, moved if it
/// still holds dead pages (it may have changed meanwhile: moved by a
/// fill's reclaim, filled, unregistered), on [`reclaimer`].
fn move_again(d: &Candidate) -> Reclaimed {
    if range_of_view(d.view).is_some_and(|(range, s)| dead_bytes(range, s, d.view, d.len) > 0) {
        move_chunk(d)
    } else {
        Reclaimed::default()
    }
}

/// Reclaims at least `need` bytes of dead pages (a chunk's worth at least)
/// at a charge refused at the job's memory limit, as Linux's memory cgroup
/// reclaims before it refuses one (v6.1 mm/memcontrol.c, `try_charge_memcg`:
/// `try_to_free_mem_cgroup_pages` before `mem_cgroup_oom`; there a page
/// discarded was freed and uncharged at once). For a lazy, discarded or
/// recharged page's first access (`windows_mm::commit_on_access`,
/// `prefault_lazy`), by a host thread or a vCPU. The chunks holding dead
/// pages are moved into new sections, the most dead first
/// (`windows_mm::uffd_move_chunk`). Those passed over for a system call in
/// flight on them are waited for, one at a time and without [`LOCK`] (the
/// call may be in its prefault, waiting for a fill that needs it), and
/// moved; never by a thread in a call itself (its own call would be among
/// them, `windows_mm::in_a_call`) or one holding [`LOCK`] (which reclaims
/// nothing). The calls end: only calls that do are counted (`windows_fd`).
/// Allocates nothing ([`CANDIDATES`]).
pub(crate) fn reclaim_at_touch(need: usize) -> Reclaimed {
    if HOLDS_LOCK.get() || REGISTERED.load(Ordering::Acquire) == 0 {
        return Reclaimed::default();
    }
    let need = need.max(crate::windows_mm::UFFD_CHUNK);
    let wait = !crate::windows_mm::in_a_call();
    // The skipped list is one touch's at a time: a second touch waits here
    // for the first's waits, which end as the calls end.
    let mut skipped = wait.then(|| TOUCH_SKIPPED.lock().unwrap());
    if let Some(s) = skipped.as_deref_mut() {
        s.clear();
    }
    let mut r = {
        let _guard = lock();
        let list = skipped.as_deref_mut().map_or(ptr::null_mut(), |s| s as *mut Vec<Candidate>);
        ask_the_reclaimer(Ask::Touch(need, list))
    };
    let Some(s) = skipped else {
        return r;
    };
    for d in s.iter() {
        if r.freed >= need {
            break;
        }
        let Some(_waited) = crate::windows_mm::discard_waiting_within(d.view, d.len) else {
            continue;
        };
        let _guard = lock();
        r.add(ask_the_reclaimer(Ask::Move(*d)));
    }
    r.skipped = 0;
    r
}

/// The moves made so far (RECLAIMREC): each one's live pages copied and its
/// microseconds; the accesses that waited for one and their microseconds.
#[cfg(test)]
pub(crate) fn moves_on_record() -> (Vec<(usize, u64)>, u64, u64) {
    let n = MOVES_MADE.load(Ordering::Relaxed).min(MOVES_KEPT);
    let moves = MOVES[..n]
        .iter()
        .map(|m| {
            let v = m.load(Ordering::Relaxed);
            #[allow(clippy::cast_possible_truncation)]
            ((v >> 32) as usize, v & u64::from(u32::MAX))
        })
        .collect();
    (moves, MOVE_WAITS.load(Ordering::Relaxed), MOVE_WAITED_US.load(Ordering::Relaxed))
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

    /// PROBECOST: the fill path's time per page with the stack probe of its
    /// locks as the stack reclaim's step 3 will have it (`windows_stacklock::probe`,
    /// which writes nothing; in tests only until then) and with the probe
    /// that zeroed its 16 KiB frame, no watch
    /// in either. Per round, 4 MiB of a registered range not yet used: a
    /// fill (`copy`) of each page by this thread; or a host thread's read of
    /// each page, each filled by this thread as its handler (the fault, the
    /// event, the fill, the wake). 5 rounds of each kind in turn; the least
    /// and the median round printed, in microseconds a page. One range is
    /// registered for all rounds: a range unregistered keeps its slot until
    /// the userfaultfd is released, so the same addresses mapped again
    /// cannot be registered before that. Asserted only that the fills went
    /// on. Run with `--release --ignored --nocapture`.
    #[test]
    #[ignore = "a record: run alone, with --release --ignored --nocapture"]
    fn test_the_fills_cost_on_record() {
        use crate::windows_stacklock::{PROBING, Probing};
        const ROUND: u64 = 4 << 20;
        const PAGES: u64 = ROUND / PAGE;
        const ROUNDS: u64 = 5;
        let len = 2 * 2 * ROUNDS * ROUND;
        let (ctx, user) = create(0, false, true).unwrap();
        // SAFETY: a new anonymous mapping, committed at first touch, as a
        // guest's memory is.
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
        let next = core::cell::Cell::new(mem);
        let slice = || {
            let at = next.get();
            next.set(at + ROUND);
            at
        };
        let page = std::vec![0x5au8; PAGE as usize];
        let fills = |kind: Probing| {
            PROBING.with(|p| p.set(kind));
            let at = slice();
            let t = std::time::Instant::now();
            for p in 0..PAGES {
                // SAFETY: `page` holds a page.
                unsafe { copy(ctx, page.as_ptr(), at + p * PAGE, PAGE, false) }.unwrap();
            }
            t.elapsed().as_secs_f64() * 1e6 / PAGES as f64
        };
        let faults = |kind: Probing| {
            PROBING.with(|p| p.set(kind));
            let at = slice();
            let t = std::time::Instant::now();
            let reader = std::thread::spawn(move || {
                PROBING.with(|p| p.set(kind));
                for p in 0..PAGES {
                    // SAFETY: registered memory; the read waits for the fill.
                    assert_eq!(unsafe { core::ptr::read_volatile((at + p * PAGE) as *const u8) }, 0x6b);
                }
            });
            for _ in 0..PAGES {
                assert_eq!(serve_one(user, ctx, 0x6b)[0], proto::EVENT_PAGEFAULT);
            }
            reader.join().unwrap();
            t.elapsed().as_secs_f64() * 1e6 / PAGES as f64
        };
        let was = PROBING.with(core::cell::Cell::get);
        for (what, run) in [("fill", &fills as &dyn Fn(Probing) -> f64), ("fault", &faults)] {
            let (mut probe, mut zeroing) = (std::vec::Vec::new(), std::vec::Vec::new());
            for _ in 0..ROUNDS {
                probe.push(run(Probing::Probe));
                zeroing.push(run(Probing::Zeroing));
            }
            for (name, v) in [("probe", &mut probe), ("zeroing", &mut zeroing)] {
                v.sort_by(f64::total_cmp);
                std::println!("PROBECOST {what} {name}: {:.2} us a page least, {:.2} median, of {ROUNDS} rounds of {PAGES} pages", v[0], v[2]);
            }
        }
        PROBING.with(|p| p.set(was));
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Anonymous private memory committed at first touch, as Firecracker
    /// maps guest memory (`MAP_NORESERVE`).
    fn map_noreserve(len: usize) -> u64 {
        // SAFETY: a new anonymous mapping.
        let p = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(p, crate::MAP_FAILED);
        p as u64
    }

    fn mprotect_of(addr: u64, len: u64, prot: c_int) -> Result<(), io::Error> {
        // SAFETY: registered memory of the test's.
        if unsafe { crate::mprotect(addr as *mut c_void, len as usize, prot) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    /// `mprotect` of registered memory whose pages are missing changes their
    /// protection and leaves them missing, as Linux's `mprotect` changes the
    /// vma's protection and leaves its pages unpopulated: made accessible
    /// again, a page's first access is a userfault, filled by the handler;
    /// a page filled while `PROT_NONE` is filled, and keeps its protection
    /// until it is changed; a `PROT_READ` page's read is a userfault too.
    /// `VirtualProtect` changes committed pages only (Learn: "If the state of
    /// any page in the specified region is not committed, the function
    /// fails"), so a missing page's protection is kept in its range
    /// (`mprotect_registered`) until it is filled.
    #[test]
    fn test_mprotect_of_registered_missing_pages_keeps_them_missing() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 4 << 20;
        let mem = map_noreserve(len as usize);
        register(ctx, mem, len).unwrap();
        let slot = mem + (2 << 20);
        mprotect_of(slot, 2 << 20, crate::PROT_NONE).expect("PROT_NONE over missing registered pages");
        assert!(is_missing(slot) && is_missing(slot + PAGE));
        mprotect_of(slot, 2 << 20, crate::PROT_READ | crate::PROT_WRITE).expect("read-write again");
        assert!(is_missing(slot) && is_missing(slot + PAGE));
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { core::ptr::read_volatile((slot + 5) as *const u8) }
        });
        let event = serve_one(user, ctx, 0x33);
        assert_eq!((event[0], event[1]), (proto::EVENT_PAGEFAULT, slot + 5));
        assert_eq!(reader.join().unwrap(), 0x33);
        // Filled while PROT_NONE: filled, and closed until made accessible.
        mprotect_of(slot + PAGE, PAGE, crate::PROT_NONE).unwrap();
        let page = std::vec![0x44u8; PAGE as usize];
        // SAFETY: `page` holds a page.
        assert_eq!(unsafe { copy(ctx, page.as_ptr(), slot + PAGE, PAGE, true) }, Ok(PAGE));
        assert!(!is_missing(slot + PAGE));
        mprotect_of(slot + PAGE, PAGE, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        // SAFETY: filled and accessible.
        assert_eq!(unsafe { core::ptr::read_volatile((slot + PAGE) as *const u8) }, 0x44);
        // A read-only missing page: its read is a userfault.
        mprotect_of(slot + 2 * PAGE, PAGE, crate::PROT_READ).unwrap();
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { core::ptr::read_volatile((slot + 2 * PAGE) as *const u8) }
        });
        let event = serve_one(user, ctx, 0x55);
        assert_eq!((event[0], event[1] & proto::FLAG_WRITE), (proto::EVENT_PAGEFAULT, 0));
        assert_eq!(reader.join().unwrap(), 0x55);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Firecracker's memory hotplug after a restore from a userfaultfd: the
    /// whole region registered (`persist.rs`, `guest_memory_from_uffd`), an
    /// unplugged slot made `PROT_NONE` (`vm.rs`, `register_memory_region` →
    /// `slot.protect(true)`), a plugged one read through the handler, the
    /// slot plugged (`protect(false)`) and read through the handler, then
    /// unplugged again (discarded, `MADV_DONTNEED`, and `PROT_NONE`), its
    /// pages missing again. Before the per-page protection, the first
    /// `protect(true)` failed with `EACCES`, and so did the restore.
    #[test]
    fn test_plug_after_a_uffd_restore() {
        let (ctx, user) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let slot_len: u64 = 2 << 20;
        let mem = map_noreserve(2 * slot_len as usize);
        register(ctx, mem, 2 * slot_len).unwrap();
        let unplugged = mem + slot_len;
        mprotect_of(unplugged, slot_len, crate::PROT_NONE).expect("protect(true) of an unplugged slot");
        let read_through_the_handler = |addr: u64, fill: u8| {
            let reader = std::thread::spawn(move || {
                // SAFETY: registered memory; the read waits for the fill.
                unsafe { core::ptr::read_volatile(addr as *const u8) }
            });
            let event = serve_one(user, ctx, fill);
            assert_eq!((event[0], event[1]), (proto::EVENT_PAGEFAULT, addr));
            assert_eq!(reader.join().unwrap(), fill);
        };
        read_through_the_handler(mem + 3 * PAGE, 0x61);
        mprotect_of(unplugged, slot_len, crate::PROT_READ | crate::PROT_WRITE).expect("protect(false) at plug");
        read_through_the_handler(unplugged + 7 * PAGE, 0x62);
        // Unplug: discarded, then closed; its pages missing again.
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise(unplugged as *mut c_void, slot_len as usize, crate::MADV_DONTNEED) }, 0);
        let mut removed = [0u8; proto::RECORD];
        assert!(recv_all(user, &mut removed));
        assert_eq!(words(&removed)[0], proto::EVENT_REMOVE);
        mprotect_of(unplugged, slot_len, crate::PROT_NONE).expect("protect(true) at unplug");
        assert!(is_missing(unplugged + 7 * PAGE));
        // Plugged again: a userfault again.
        mprotect_of(unplugged, slot_len, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        read_through_the_handler(unplugged + 7 * PAGE, 0x63);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The protection of a committed page, from `VirtualQuery`.
    fn page_protection(addr: u64) -> u32 {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_ne!(unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
        mbi.Protect
    }

    /// An `mprotect` of registered memory that cannot be done changes none of
    /// its pages: here an executable protection, which the views of a
    /// range's sections do not allow (`EACCES`). The filled pages keep the
    /// protection they had, and a missing page filled afterwards takes the
    /// one given before, not the refused one.
    #[test]
    fn test_a_refused_mprotect_of_registered_memory_changes_nothing() {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(64 << 10);
        register(ctx, mem, 64 << 10).unwrap();
        let page = std::vec![0x5au8; PAGE as usize];
        for p in [0, 2] {
            // SAFETY: `page` holds a page.
            unsafe { copy(ctx, page.as_ptr(), mem + p * PAGE, PAGE, false) }.unwrap();
        }
        mprotect_of(mem, 4 * PAGE, crate::PROT_READ).unwrap();
        assert_eq!(page_protection(mem), PAGE_READONLY);
        let refused = mprotect_of(mem, 4 * PAGE, crate::PROT_READ | crate::PROT_WRITE | crate::PROT_EXEC).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(crate::EACCES), "{refused}");
        assert_eq!((page_protection(mem), page_protection(mem + 2 * PAGE)), (PAGE_READONLY, PAGE_READONLY));
        // SAFETY: `page` holds a page.
        unsafe { copy(ctx, page.as_ptr(), mem + PAGE, PAGE, false) }.unwrap();
        assert_eq!(page_protection(mem + PAGE), PAGE_READONLY);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The reclaim at the memory limit moves no chunk holding a live page
    /// `mprotect` closed: a move maps the chunk's new view read-write, which
    /// would open that page until its protection is given back. Two chunks
    /// with dead pages (every other page discarded): with a live page of the
    /// second made `PROT_READ`, only the first is a candidate; read-write
    /// again, both are.
    #[test]
    fn test_a_chunk_with_a_closed_live_page_is_not_moved() {
        let (ctx, user) = create(0, false, true).unwrap();
        let chunk = crate::windows_mm::UFFD_CHUNK as u64;
        let mem = map_noreserve(2 * chunk as usize);
        register(ctx, mem, 2 * chunk).unwrap();
        let page = std::vec![0x5au8; PAGE as usize];
        for p in (0..2 * chunk).step_by(PAGE as usize) {
            // SAFETY: `page` holds a page.
            unsafe { copy(ctx, page.as_ptr(), mem + p, PAGE, false) }.unwrap();
        }
        for p in (0..2 * chunk).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        let candidates = || {
            let _guard = lock();
            let mut c = Vec::with_capacity(256);
            find_candidates(&mut c);
            c.iter().map(|d| d.view as u64).filter(|v| (mem..mem + 2 * chunk).contains(v)).collect::<Vec<_>>()
        };
        assert_eq!(candidates().len(), 2, "both chunks hold dead pages");
        mprotect_of(mem + chunk + PAGE, PAGE, crate::PROT_READ).unwrap();
        assert_eq!(candidates(), std::vec![mem], "the chunk with a read-only live page is not moved");
        mprotect_of(mem + chunk + PAGE, PAGE, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        assert_eq!(candidates().len(), 2);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// An access its protection denies to a missing page of registered
    /// memory is the access fault (SIGSEGV on Linux; here the process ends
    /// with `STATUS_ACCESS_VIOLATION`), not a userfault: Linux checks the
    /// vma's protection before it faults the page in (v6.1
    /// arch/x86/mm/fault.c, `do_user_addr_fault`: `access_error` and
    /// `bad_area_access_error` at :1410 and :1411, before `handle_mm_fault`
    /// at :1428, where `do_anonymous_page` hands a missing page to
    /// userfaultfd). A read of a `PROT_NONE` page, and a write of a
    /// `PROT_READ` one, each in a child whose handler would say any event.
    #[test]
    fn test_a_registered_page_its_protection_denies_is_no_userfault() {
        for child in ["denied_read_child", "denied_write_child"] {
            let (code, text) = run_child(child, None);
            assert!(text.contains("UFFDDENIED accessing"), "{child}: {text}");
            assert!(!text.contains("UFFDDENIED event"), "{child}: a userfault for an access its protection denies: {text}");
            assert_eq!(code, Some(0xC000_0005_u32.cast_signed()), "{child}: {text}");
        }
    }

    fn denied_access(prot: c_int, write: bool) {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(64 << 10);
        register(ctx, mem, 64 << 10).unwrap();
        mprotect_of(mem, 64 << 10, prot).unwrap();
        std::thread::spawn(move || loop {
            let mut buf = [0u8; proto::RECORD];
            if !recv_all(user, &mut buf) {
                return;
            }
            let event = words(&buf);
            std::println!("UFFDDENIED event {:#x} at {:#x}", event[0], event[1]);
            let page = std::vec![0u8; PAGE as usize];
            // SAFETY: `page` holds a page.
            let _ = unsafe { copy(ctx, page.as_ptr(), event[1] - event[1] % PAGE, PAGE, true) };
        });
        std::println!("UFFDDENIED accessing");
        if write {
            // SAFETY: registered memory, which the access is to fault on.
            unsafe { core::ptr::write_volatile((mem + PAGE) as *mut u8, 1) };
        } else {
            // SAFETY: as above.
            core::hint::black_box(unsafe { core::ptr::read_volatile((mem + PAGE) as *const u8) });
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        std::println!("UFFDDENIED the access went on");
    }

    #[test]
    #[ignore = "run by test_a_registered_page_its_protection_denies_is_no_userfault"]
    fn denied_read_child() {
        denied_access(crate::PROT_NONE, false);
    }

    #[test]
    #[ignore = "run by test_a_registered_page_its_protection_denies_is_no_userfault"]
    fn denied_write_child() {
        denied_access(crate::PROT_READ, true);
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

    /// Runs the child test `child` (this module's, `#[ignore]`d) in a
    /// process of its own, in a job that may commit `limit` bytes if one is
    /// given (set before the child registers anything: it sleeps 300 ms
    /// first): its exit status and output.
    fn run_child(child: &str, limit: Option<usize>) -> (Option<i32>, std::string::String) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        let name = std::format!("{}::{child}", module_path!().split_once("::").unwrap().1);
        let process = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name.as_str(), "--ignored", "--nocapture"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut job = ptr::null_mut();
        if let Some(limit) = limit {
            // SAFETY: a new unnamed job.
            job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            assert!(!job.is_null());
            // SAFETY: plain data.
            let mut l: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            l.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
            l.JobMemoryLimit = limit;
            // SAFETY: a structure of the size passed; the child's handle.
            unsafe {
                #[allow(clippy::cast_possible_truncation)]
                let size = std::mem::size_of_val(&l) as u32;
                assert_ne!(SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const l).cast(), size), 0);
                use std::os::windows::io::AsRawHandle;
                assert_ne!(AssignProcessToJobObject(job, process.as_raw_handle()), 0, "{}", io::Error::last_os_error());
            }
        }
        let out = process.wait_with_output().unwrap();
        if !job.is_null() {
            // SAFETY: our job handle.
            unsafe { CloseHandle(job) };
        }
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        assert!(text.contains("running 1 test"), "the child {name} ran no test (status {}): {text}", out.status);
        (out.status.code(), text)
    }

    const CHUNK: u64 = 2 << 20;

    /// The reclaim tests' start, in a child under a job limit: 128 MiB
    /// registered and filled with 0x5a 1 MiB at a time until the job
    /// refuses, then every other page of its first 8 chunks discarded (8
    /// MiB of dead pages, no chunk whole, so each keeps its section commit
    /// and charge, as (A) has them). The range and the bytes filled.
    fn fill_to_the_limit_and_discard_in_part() -> (usize, c_int, u64, u64) {
        let (ctx, user, mem, done) = fill_to_the_limit();
        assert!(done >= 8 * CHUNK + (8 << 20), "only {} MiB filled", done >> 20);
        for p in (0..8 * CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        (ctx, user, mem, done)
    }

    /// 128 MiB registered and filled with 0x5a 1 MiB at a time until the
    /// job refuses: the range and the bytes filled.
    fn fill_to_the_limit() -> (usize, c_int, u64, u64) {
        fill_to_the_limit_from(0)
    }

    /// [`fill_to_the_limit`], the fill begun `from` bytes in: the pages
    /// before are never filled.
    fn fill_to_the_limit_from(from: u64) -> (usize, c_int, u64, u64) {
        std::thread::sleep(std::time::Duration::from_millis(300));
        make_the_slack_region();
        let (ctx, user) = create(0, false, true).unwrap();
        let len: u64 = 128 << 20;
        // SAFETY: a new anonymous mapping, committed at first touch.
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
        let mib = std::vec![0x5au8; 1 << 20];
        let mut done = from;
        loop {
            assert!(done < len, "128 MiB filled under the limit");
            // SAFETY: `mib` holds 1 MiB.
            match unsafe { copy(ctx, mib.as_ptr(), mem + done, 1 << 20, false) } {
                Ok(n) => done += n,
                Err((e, _)) => {
                    assert_eq!(e, crate::ENOMEM);
                    break;
                }
            }
        }
        std::println!("filled {} MiB", done >> 20);
        (ctx, user, mem, done)
    }

    /// The process's private commit (`PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`),
    /// which the job's memory limit counts.
    fn private_commit() -> usize {
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_faults: u32,
            sizes: [usize; 10],
        }
        let mut c = Counters { cb: u32::try_from(std::mem::size_of::<Counters>()).unwrap(), ..Counters::default() };
        // SAFETY: this process's pseudo handle and a structure of the size
        // given (PROCESS_MEMORY_COUNTERS_EX).
        let ok = unsafe {
            windows_sys::Win32::System::ProcessStatus::K32GetProcessMemoryInfo(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                (&raw mut c).cast(),
                c.cb,
            )
        };
        assert_ne!(ok, 0);
        c.sizes[8]
    }

    /// Takes every 4 KiB of the job's room left, each page a commit of its
    /// own so that the caller can give it back a page at a time; the pages.
    fn take_every_page() -> std::vec::Vec<usize> {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        let mut held = std::vec::Vec::with_capacity(1 << 16);
        // From here the job has no room: the locks are taken as the product
        // takes them. The watch's frames and its record's lines are deeper
        // than the product's, and a thread whose committed stack ends just
        // below the product's path (the userfaultfd's serve thread in
        // `destroy`, through the release's lazy pages and the region
        // table's search)
        // needed a new page for them, which the limit refused: 10 of 480
        // fills at the limit ended so with the watch (9 with 137, 1 with
        // STATUS_HEAP_CORRUPTION), 0 of 480 with the watch off for the whole
        // test, and 2 of 480 with it off from here (Windows Server 2022
        // 20348, STACK137FRAMES). Those two are the product's own: the same
        // thread in `destroy`, growing its Vec of missing runs, was refused
        // a stack page inside ntdll's heap code (RtlpAllocateHeap under
        // RtlReAllocateHeap). That end is open (COMPATIBILITY.md, the
        // memory.max row); the watch is off here so that it is the
        // product's frames this test runs at the limit.
        crate::windows_stacklock::WATCHING.store(false, Ordering::SeqCst);
        while held.len() < held.capacity() {
            // SAFETY: new private memory of ours.
            let p = unsafe { VirtualAlloc(ptr::null(), PAGE as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
            if p.is_null() {
                break;
            }
            held.push(p as usize);
        }
        held
    }

    /// A region of 2 MiB reserved, its first page committed (so its page
    /// table is there) before the limit is reached, for [`no_room_left`]'s
    /// last pages: a page that `VirtualAlloc` refuses at the limit, as a new
    /// allocation needs a page table too, may still be committed where one
    /// is, as a fill's page in a mapped view is (on Windows Server 2022
    /// 20348, fc-win: a fill made with every `VirtualAlloc` of a page
    /// refused). Its base, and the pages past the first committed.
    static SLACK: AtomicUsize = AtomicUsize::new(0);
    static SLACK_TAKEN: AtomicUsize = AtomicUsize::new(0);

    fn make_the_slack_region() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        // SAFETY: new memory of ours.
        let p = unsafe { VirtualAlloc(ptr::null(), CHUNK as usize, MEM_RESERVE, PAGE_READWRITE) };
        assert!(!p.is_null());
        // SAFETY: the first page of the region just reserved.
        assert!(!unsafe { VirtualAlloc(p, PAGE as usize, MEM_COMMIT, PAGE_READWRITE) }.is_null());
        SLACK.store(p as usize, Ordering::SeqCst);
    }

    /// Commits the slack region's pages ([`SLACK`]) one at a time until the
    /// job refuses; how many.
    fn take_the_slack() -> usize {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, PAGE_READWRITE, VirtualAlloc};
        let base = SLACK.load(Ordering::SeqCst);
        if base == 0 {
            return 0;
        }
        let mut n = SLACK_TAKEN.load(Ordering::SeqCst);
        while (n + 2) * (PAGE as usize) <= CHUNK as usize {
            // SAFETY: a page of our region.
            if unsafe { VirtualAlloc((base + (n + 1) * PAGE as usize) as *const c_void, PAGE as usize, MEM_COMMIT, PAGE_READWRITE) }.is_null() {
                break;
            }
            n += 1;
        }
        SLACK_TAKEN.store(n, Ordering::SeqCst);
        n
    }

    /// Gives back what [`take_the_slack`] took.
    fn give_back_the_slack() {
        use windows_sys::Win32::System::Memory::{MEM_DECOMMIT, VirtualFree};
        let (base, n) = (SLACK.load(Ordering::SeqCst), SLACK_TAKEN.swap(0, Ordering::SeqCst));
        if base != 0 && n != 0 {
            // SAFETY: pages of our region.
            unsafe { VirtualFree((base + PAGE as usize) as *mut c_void, n * PAGE as usize, MEM_DECOMMIT) };
        }
    }

    /// Gives back one page [`take_every_page`] took.
    fn give_back_a_page(held: &mut std::vec::Vec<usize>) {
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
        let p = held.pop().expect("a page held");
        // SAFETY: a page of ours.
        unsafe { VirtualFree(p as *mut c_void, 0, MEM_RELEASE) };
    }

    /// No room left in the job (the lesson of CI run 43640510155: a reclaim
    /// that moved with room left was never tried where it runs): this
    /// thread's stack grown first (a stack that must grow at the limit ends
    /// the process: `test_a_stack_that_grows_at_the_limit_on_record`), then
    /// every page of the job's room taken ([`take_every_page`]), said on
    /// standard error without allocating. The pages, to give back.
    fn no_room_left() -> std::vec::Vec<usize> {
        core::hint::black_box(deep(32));
        let held = take_every_page();
        let slack = take_the_slack();
        crate::windows_mm::say_at_the_limit(format_args!(
            "room left before the reclaim: 0 KiB ({} pages taken, and {slack} where a page table was)",
            held.len()
        ));
        held
    }

    /// Gives back every page [`take_every_page`] took, and the slack
    /// region's ([`take_the_slack`]).
    fn give_back_every_page(held: &mut std::vec::Vec<usize>) {
        give_back_the_slack();
        while !held.is_empty() {
            give_back_a_page(held);
        }
    }

    /// VIEWCHARGE: what mapping a view of a pagefile-backed section takes of
    /// the process's private commit, which the job's memory limit counts
    /// (Learn, JOBOBJECT_EXTENDED_LIMIT_INFORMATION: JobMemoryLimit is "the
    /// limit for the virtual memory that can be committed for the job",
    /// with no list of what counts; that a view's page tables count is
    /// measured, not documented): a, under 1 GiB, a section of 64 KiB, 2 MiB
    /// and 16 MiB, `SEC_RESERVE` and `SEC_COMMIT`, read-write and read-only:
    /// the section, a view anywhere, a second view, a view into a
    /// placeholder, all three unmapped; b, at the job's limit with all its
    /// room taken a page at a time, then given back 4 KiB at a time: whether
    /// a 2 MiB `SEC_RESERVE` view is mapped anywhere and into a
    /// placeholder, the error, and what the map took. On Windows Server
    /// 2022 20348 (fc-win): 4 KiB a 2 MiB view and 32 KiB a 16 MiB one (a
    /// page table a 2 MiB), in every case, given back at the unmap; at the
    /// limit, error 1455 with no room, a view anywhere with 4 KiB, a view
    /// into a placeholder made apart from any other mapping from 8 KiB in
    /// one run and 12 KiB in another (a page directory's page as well). It is why the reclaim's move could not start at a real job
    /// limit (CI run 43640510155). Printed, not asserted, but for the
    /// children ending well.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_what_a_view_mapping_charges_on_record() {
        let (code, text) = run_child("view_charge_child", Some(1 << 30));
        std::eprintln!("{text}");
        assert_eq!(code, Some(0), "{text}");
        let (code, text) = run_child("view_limit_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_what_a_view_mapping_charges_on_record in a job of its own"]
    fn view_charge_child() {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER, MEM_RELEASE, MapViewOfFile3,
            PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, SEC_COMMIT, SEC_RESERVE, UnmapViewOfFile, VirtualAlloc2, VirtualFree,
        };
        // SAFETY: this process's pseudo handle.
        let me = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        let kib = |a: usize, b: usize| (b as i64 - a as i64) / 1024;
        for len in [64usize << 10, 2 << 20, 16 << 20] {
            for (kind, flag) in [("SEC_RESERVE", SEC_RESERVE), ("SEC_COMMIT", SEC_COMMIT)] {
                let p0 = private_commit();
                #[allow(clippy::cast_possible_truncation)]
                // SAFETY: a new pagefile-backed section.
                let sec = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | flag, 0, len as u32, ptr::null()) };
                assert!(!sec.is_null());
                let p1 = private_commit();
                for (access, prot) in [("read-write", PAGE_READWRITE), ("read-only", PAGE_READONLY)] {
                    let a = private_commit();
                    // SAFETY: maps our section anywhere.
                    let v1 = unsafe { MapViewOfFile3(sec, me, ptr::null(), 0, len, 0, prot, ptr::null_mut(), 0) };
                    let b = private_commit();
                    // SAFETY: as above.
                    let v2 = unsafe { MapViewOfFile3(sec, me, ptr::null(), 0, len, 0, prot, ptr::null_mut(), 0) };
                    let c = private_commit();
                    // SAFETY: reserves a placeholder of ours.
                    let ph = unsafe { VirtualAlloc2(me, ptr::null(), len, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, ptr::null_mut(), 0) };
                    let d = private_commit();
                    // SAFETY: maps our section into our placeholder.
                    let v3 = unsafe { MapViewOfFile3(sec, me, ph, 0, len, MEM_REPLACE_PLACEHOLDER, prot, ptr::null_mut(), 0) };
                    let e = private_commit();
                    assert!(!v1.Value.is_null() && !v2.Value.is_null() && v3.Value == ph);
                    // SAFETY: the views mapped here.
                    unsafe {
                        UnmapViewOfFile(v1);
                        UnmapViewOfFile(v2);
                        UnmapViewOfFile(v3);
                    }
                    let f = private_commit();
                    std::println!(
                        "VIEWCHARGE a {} KiB {kind} {access}: the section {:+} KiB, a view anywhere {:+} KiB, a second view {:+} KiB, \
                         a placeholder {:+} KiB, a view into it {:+} KiB; after the three unmapped {:+} KiB",
                        len >> 10,
                        kib(p0, p1),
                        kib(a, b),
                        kib(b, c),
                        kib(c, d),
                        kib(d, e),
                        kib(a, f)
                    );
                    // SAFETY: the placeholder the view left.
                    unsafe { VirtualFree(ph, 0, MEM_RELEASE) };
                }
                // SAFETY: our section's handle.
                unsafe { CloseHandle(sec) };
            }
        }
    }

    #[test]
    #[ignore = "run by test_what_a_view_mapping_charges_on_record in a job of its own"]
    fn view_limit_child() {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER,
            MapViewOfFile3, PAGE_NOACCESS, PAGE_READWRITE, SEC_RESERVE, UnmapViewOfFile, UnmapViewOfFile2, VirtualAlloc2, VirtualFree,
        };
        const STEPS: [usize; 12] = [0, 4, 8, 12, 16, 24, 32, 64, 256, 1024, 2048, 4096];
        // SAFETY: this process's pseudo handle.
        let me = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        // Made, and the results' room kept, before the room is taken: at
        // the limit nothing may allocate, nor print (a stack that grows
        // there cannot: test_a_stack_that_grows_at_the_limit_on_record).
        // SAFETY: new pagefile-backed sections and placeholders.
        let made: std::vec::Vec<_> = (0..STEPS.len())
            .map(|_| unsafe {
                (
                    CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, 2 << 20, ptr::null()),
                    CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, 2 << 20, ptr::null()),
                    VirtualAlloc2(me, ptr::null(), 2 << 20, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, ptr::null_mut(), 0),
                )
            })
            .collect();
        assert!(made.iter().all(|m| !m.0.is_null() && !m.1.is_null() && !m.2.is_null()));
        let mut results = [(0usize, false, 0u32, 0i64, false, 0u32); STEPS.len()];
        let mut held = take_every_page();
        let taken = held.len();
        let mut given = 0;
        for (i, &room) in STEPS.iter().enumerate() {
            while given < room {
                give_back_a_page(&mut held);
                given += 4;
            }
            let a = private_commit();
            // SAFETY: maps our section anywhere.
            let v = unsafe { MapViewOfFile3(made[i].0, me, ptr::null(), 0, 2 << 20, 0, PAGE_READWRITE, ptr::null_mut(), 0) };
            // SAFETY: plain call.
            let e1 = if v.Value.is_null() { unsafe { GetLastError() } } else { 0 };
            let b = private_commit();
            // SAFETY: maps our section into our placeholder.
            let w = unsafe { MapViewOfFile3(made[i].1, me, made[i].2, 0, 2 << 20, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, ptr::null_mut(), 0) };
            // SAFETY: plain call.
            let e2 = if w.Value == made[i].2 { 0 } else { unsafe { GetLastError() } };
            results[i] = (room, !v.Value.is_null(), e1, (b as i64 - a as i64) / 1024, w.Value == made[i].2, e2);
            // SAFETY: the views mapped here.
            unsafe {
                if !v.Value.is_null() {
                    UnmapViewOfFile(v);
                }
                if w.Value == made[i].2 {
                    UnmapViewOfFile2(me, w, MEM_PRESERVE_PLACEHOLDER);
                }
            }
        }
        while !held.is_empty() {
            give_back_a_page(&mut held);
        }
        std::println!("VIEWCHARGE b: the job's room taken, {taken} pages, then given back 4 KiB at a time");
        for (room, any, e1, took, ph, e2) in results {
            std::println!(
                "VIEWCHARGE b room {room} KiB: a 2 MiB view anywhere {} (took {took:+} KiB), into a placeholder {}",
                if any { "mapped".into() } else { std::format!("refused, error {e1}") },
                if ph { "mapped".into() } else { std::format!("refused, error {e2}") }
            );
        }
        for (s1, s2, ph) in made {
            // SAFETY: ours.
            unsafe {
                CloseHandle(s1);
                CloseHandle(s2);
                VirtualFree(ph, 0, MEM_RELEASE);
            }
        }
    }

    /// MOVEROOM: the room the reclaim's move needs at the job's limit: the
    /// reclaim tests' start (8 chunks with half their pages dead), then all
    /// the room taken a page at a time and a fill's reclaim
    /// (`reclaim_for_a_fill`) tried with 0 KiB of room, then 4 KiB more each
    /// time, until it moves a chunk: how many chunks each try moved, the
    /// bytes it freed and what the process's private commit did. On Windows
    /// Server 2022 20348 (fc-win), before a move gave back part of its dead
    /// pages' charge for its maps (fc102ff6): none with no room (the move's
    /// map of its new section's view refused, 1455), 2 chunks and 2 MiB with
    /// 4 KiB: one page table, its own view's (the alias's and the guest
    /// view's swaps give back what they take); since, 2 chunks and 2 MiB
    /// with 0 KiB. Printed, not asserted, but for the child ending well.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_the_room_a_move_needs_on_record() {
        let (code, text) = run_child("move_room_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_room_a_move_needs_on_record in a job of its own"]
    fn move_room_child() {
        let (ctx, user, _mem, _) = fill_to_the_limit_and_discard_in_part();
        let mut tries = [(0usize, Reclaimed::default(), 0i64); 16];
        let mut held = take_every_page();
        let taken = held.len();
        let mut n = 0;
        while n < tries.len() {
            let before = private_commit();
            let r = {
                let _guard = lock();
                reclaim_for_a_fill(PAGE as usize)
            };
            tries[n] = (n * 4, r, (private_commit() as i64 - before as i64) / 1024);
            n += 1;
            if r.chunks > 0 || held.is_empty() {
                break;
            }
            give_back_a_page(&mut held);
        }
        while !held.is_empty() {
            give_back_a_page(&mut held);
        }
        std::println!("MOVEROOM the job's room taken, {taken} pages, then given back 4 KiB at a time");
        for (room, r, delta) in &tries[..n] {
            std::println!("MOVEROOM room {room} KiB: {} chunks moved, {} KiB freed, private commit {delta:+} KiB", r.chunks, r.freed >> 10);
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let _ = ctx;
    }

    /// The calling thread's stack from its TEB (x86-64): its base, the
    /// lowest committed address, the reserve's low end (DeallocationStack,
    /// 0x1478) and the stack guarantee (GuaranteedStackBytes, 0x1748).
    fn stack_of_this_thread() -> (usize, usize, usize, u32) {
        let (base, limit, reserve, guarantee): (usize, usize, usize, u32);
        // SAFETY: reads of the thread's own TEB.
        unsafe {
            core::arch::asm!(
                "mov {0}, gs:[0x8]",
                "mov {1}, gs:[0x10]",
                "mov {2}, gs:[0x1478]",
                "mov {3:e}, gs:[0x1748]",
                out(reg) base,
                out(reg) limit,
                out(reg) reserve,
                out(reg) guarantee,
                options(nostack, readonly, preserves_flags)
            );
        }
        (base, limit, reserve, guarantee)
    }

    const STACK_PAINT: u8 = 0x5c;

    /// This thread's stack grown 128 KiB below here and painted from its
    /// lowest committed byte to 256 bytes below here: the painted range.
    #[inline(never)]
    fn paint_below_here() -> (usize, usize) {
        core::hint::black_box(deep(32));
        let (_, limit, _, _) = stack_of_this_thread();
        let here = core::hint::black_box(&limit) as *const usize as usize;
        let top = (here - 256) & !15;
        // SAFETY: the thread's own committed stack below its frames.
        unsafe { core::ptr::write_bytes(limit as *mut u8, STACK_PAINT, top - limit) };
        (limit, top)
    }

    /// How far below the top of [`paint_below_here`]'s range the paint was
    /// written over.
    fn used_below((limit, top): (usize, usize)) -> usize {
        let mut at = limit;
        // SAFETY: the thread's own committed stack.
        while at < top && unsafe { core::ptr::read_volatile(at as *const u8) } == STACK_PAINT {
            at += 1;
        }
        top - at
    }

    /// 64 KiB of stack, a page a frame: a thread whose stack must grow.
    #[inline(never)]
    fn deep(n: usize) -> u8 {
        let a = core::hint::black_box([n as u8; 4096]);
        if n == 0 { a[7] } else { a[9].wrapping_add(deep(n - 1)) }
    }

    /// STACKZERO: a thread whose stack must grow at the job's limit, the
    /// room taken a page at a time, against the same thread with room
    /// (the control) and a stack overflowed with room (its reserve used
    /// up): how each child ended, and the threads' stacks from their TEB
    /// before. Learn, "Thread Stack Size": the system commits stack pages
    /// as needed "until either the stack reaches the reserved size minus
    /// one page (which is used as a guard page to prevent stack overflow)
    /// or the system is so low on memory that the operation fails"; both
    /// raise STATUS_STACK_OVERFLOW. On Windows Server 2022 20348 (fc-win):
    /// the thread at the limit ended its process with 0xC00000FD, 32 KiB of
    /// its stack committed, where Linux charges a stack page as any other
    /// and its memory cgroup's out-of-memory kill ends the process (137).
    /// Its children map no lazy memory, so the stack filter that ends such a
    /// process with 137 is not in place (`windows_mm::stack_filter`,
    /// `test_a_stack_that_must_grow_at_the_limit_ends_with_137`): the record
    /// of what Windows does by itself. Printed, not asserted, but for the
    /// control ending well.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_a_stack_that_grows_at_the_limit_on_record() {
        for (child, limit) in [("stack_at_the_limit_child", Some(96 << 20)), ("stack_with_room_child", None), ("stack_overflowed_child", None)] {
            let (code, text) = run_child(child, limit);
            #[allow(clippy::cast_sign_loss)]
            let ended = code.map_or_else(|| "no exit code".into(), |c| std::format!("{:#x}", c as u32));
            std::eprintln!("STACKZERO {child}: ended with {ended}; {}", text.trim().replace('\n', " | "));
            if child == "stack_with_room_child" {
                assert_eq!(code, Some(0), "{text}");
            }
        }
    }

    fn a_thread_that_goes_deep(go_at_once: bool, depth: usize) -> (std::thread::JoinHandle<u8>, std::sync::mpsc::Sender<()>) {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (said, heard) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let (base, limit, reserve, guarantee) = stack_of_this_thread();
            std::println!(
                "the thread's stack: {} KiB committed of a {} KiB reserve, a guarantee of {guarantee} bytes",
                (base - limit) >> 10,
                (base - reserve) >> 10
            );
            said.send(()).unwrap();
            if !go_at_once {
                rx.recv().unwrap();
            }
            deep(depth)
        });
        heard.recv().unwrap();
        (t, tx)
    }

    #[test]
    #[ignore = "run by test_a_stack_that_grows_at_the_limit_on_record in a job of its own"]
    fn stack_at_the_limit_child() {
        let (t, go) = a_thread_that_goes_deep(false, 16);
        let held = take_every_page();
        go.send(()).unwrap();
        let _ = t.join();
        drop(held);
        std::println!("the thread at the limit went 64 KiB deep and the process went on");
    }

    #[test]
    #[ignore = "run by test_a_stack_that_grows_at_the_limit_on_record"]
    fn stack_with_room_child() {
        let (t, _go) = a_thread_that_goes_deep(true, 16);
        assert_eq!(t.join().map(|_| ()).ok(), Some(()));
        std::println!("the thread with room went 64 KiB deep");
    }

    #[test]
    #[ignore = "run by test_a_stack_that_grows_at_the_limit_on_record"]
    fn stack_overflowed_child() {
        let (t, _go) = a_thread_that_goes_deep(true, usize::MAX);
        let _ = t.join();
        std::println!("the unbounded thread came back");
    }

    /// Which kind of thread a stack test runs on: one of Rust's
    /// (`std::thread`, whose stack guarantee Rust sets), one made with
    /// `CreateThread` as a system DLL or the reclaim makes one (no
    /// guarantee set), and a thread of the process's thread pool
    /// (`TrySubmitThreadpoolCallback`), which the system makes.
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Rust,
        CreateThread,
        Pool,
    }

    /// Runs `body` on a thread of `kind`: it prints its stack (from its
    /// TEB), says it is ready, waits for the go, and goes `depth` frames
    /// deep ([`deep`]); the go, and a receiver told when it came back.
    fn a_thread_of(kind: Kind, depth: usize) -> (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>) {
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let (ready, heard) = std::sync::mpsc::channel::<()>();
        let (back, came_back) = std::sync::mpsc::channel::<()>();
        let body: std::boxed::Box<dyn FnOnce() + Send> = std::boxed::Box::new(move || {
            let (base, limit, reserve, guarantee) = stack_of_this_thread();
            std::println!(
                "the {kind:?} thread's stack: {} KiB committed of a {} KiB reserve, a guarantee of {guarantee} bytes",
                (base - limit) >> 10,
                (base - reserve) >> 10
            );
            ready.send(()).unwrap();
            wait.recv().unwrap();
            core::hint::black_box(deep(depth));
            let _ = back.send(());
        });
        on_a_thread_of(kind, body);
        heard.recv().unwrap();
        (go, came_back)
    }

    /// Runs `body` on a new thread of `kind`.
    fn on_a_thread_of(kind: Kind, body: std::boxed::Box<dyn FnOnce() + Send>) {
        let raw = std::boxed::Box::into_raw(std::boxed::Box::new(body)).cast::<c_void>();
        unsafe extern "system" fn start(raw: *mut c_void) -> u32 {
            // SAFETY: the box made above, given to this thread alone.
            let body = unsafe { std::boxed::Box::from_raw(raw.cast::<std::boxed::Box<dyn FnOnce() + Send>>()) };
            body();
            0
        }
        unsafe extern "system" fn pooled(_: windows_sys::Win32::System::Threading::PTP_CALLBACK_INSTANCE, raw: *mut c_void) {
            // SAFETY: as `start`.
            unsafe { start(raw) };
        }
        match kind {
            Kind::Rust => {
                let raw = raw as usize;
                // Named as Rust names a thread (`SetThreadDescription`).
                std::thread::Builder::new()
                    .name("wick-stack-test".into())
                    .spawn(move || {
                        // SAFETY: the box made above.
                        unsafe { start(raw as *mut c_void) };
                    })
                    .unwrap();
            }
            Kind::CreateThread => {
                // SAFETY: a thread of ours with the default stack.
                let t = unsafe { windows_sys::Win32::System::Threading::CreateThread(ptr::null(), 0, Some(start), raw, 0, ptr::null_mut()) };
                assert!(!t.is_null());
            }
            Kind::Pool => {
                // SAFETY: the process's default pool runs the callback once.
                assert_ne!(unsafe { windows_sys::Win32::System::Threading::TrySubmitThreadpoolCallback(Some(pooled), raw, ptr::null()) }, 0);
            }
        }
    }

    /// A mapping committed at first touch, so that the lazy-memory handler,
    /// and the stack filter with it, are in place (`windows_mm::lazy_handler`),
    /// as in a VMM with guest memory.
    fn lazy_memory_is_mapped() {
        // SAFETY: a new anonymous mapping, committed at first touch.
        let p = unsafe {
            crate::mmap(ptr::null_mut(), 1 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_ne!(p, crate::MAP_FAILED);
    }

    /// A thread whose stack must grow when the job's limit has no room left
    /// ends the process as the limit's other ends do, with 137 and the line
    /// that says so (`windows_mm::stack_filter`), where it ended with
    /// `STATUS_STACK_OVERFLOW` (STACKZERO), on each kind of thread
    /// ([`Kind`]); Linux's memory cgroup ends a process whose stack page
    /// cannot be charged with its out-of-memory kill.
    #[test]
    fn test_a_stack_that_must_grow_at_the_limit_ends_with_137() {
        for child in ["stack_at_the_limit_rust_child", "stack_at_the_limit_createthread_child", "stack_at_the_limit_pool_child"] {
            let (code, text) = run_child(child, Some(96 << 20));
            std::eprintln!("STACK137 {child}: {code:?}; {}", text.trim().replace('\n', " | "));
            assert!(text.contains("wick: a thread's stack could not grow"), "{child}: {text}");
            assert_eq!(code, Some(137), "{child}: {text}");
        }
    }

    /// The line of a stack that could not grow names its thread, by its ID
    /// and its description (which Rust sets to a thread's name), so that a
    /// run says which thread it was (MOVEUNDERVCPU, CI runs 43784960688 and
    /// 43790310601, did not); the ID is the one Rust's own overflow line
    /// gives.
    #[test]
    fn test_the_line_of_a_stack_that_could_not_grow_names_its_thread() {
        let (code, text) = run_child("stack_at_the_limit_rust_child", Some(96 << 20));
        assert_eq!(code, Some(137), "{text}");
        let line = text.lines().find(|l| l.starts_with("wick: a thread's stack could not grow")).unwrap_or_default();
        let rust = text
            .lines()
            .find_map(|l| l.split_once("thread 'wick-stack-test' (")?.1.split_once(") has overflowed").map(|(id, _)| id))
            .expect("Rust's overflow line with the thread's ID");
        assert!(line.contains(&std::format!("thread {rust} \"wick-stack-test\"")), "{text}");
    }

    fn stack_at_the_limit(kind: Kind) {
        lazy_memory_is_mapped();
        make_the_slack_region();
        let (go, came_back) = a_thread_of(kind, 32);
        let held = no_room_left();
        go.send(()).unwrap();
        let _ = came_back.recv_timeout(std::time::Duration::from_secs(10));
        drop(held);
        std::println!("the {kind:?} thread at the limit went 128 KiB deep and the process went on");
    }

    #[test]
    #[ignore = "run by test_a_stack_that_must_grow_at_the_limit_ends_with_137 in a job of its own"]
    fn stack_at_the_limit_rust_child() {
        stack_at_the_limit(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_a_stack_that_must_grow_at_the_limit_ends_with_137 in a job of its own"]
    fn stack_at_the_limit_createthread_child() {
        stack_at_the_limit(Kind::CreateThread);
    }

    #[test]
    #[ignore = "run by test_a_stack_that_must_grow_at_the_limit_ends_with_137 in a job of its own"]
    fn stack_at_the_limit_pool_child() {
        stack_at_the_limit(Kind::Pool);
    }

    /// A stack overflow at the reserve's end is still one, with the stack
    /// filter in place: passed on (its test line, STACKFILTER, with how
    /// much of the reserve was left and the thread's guarantee), it ends the
    /// process with `STATUS_STACK_OVERFLOW` (0xC00000FD) as before, through
    /// Windows' own handling (Windows Error Reporting), on each kind of
    /// thread ([`Kind`]), with room left.
    ///
    /// Its record, STACKENDHOST: the host's build and revision, its
    /// just-in-time debugger (AeDebug) and Windows Error Reporting's keys;
    /// and for each child when it ended after the filter's line, with what
    /// status, and, if it still runs 12 s after its start, the processes it
    /// started or that report its fault, and its threads' stacks (cdb, where
    /// the host has it), as Windows Server 2025's pool thread went on for
    /// 10 s in CI runs 43784960688 and 43790310601.
    #[test]
    fn test_a_stack_overflow_at_the_reserves_end_is_still_one() {
        stack_end_host_record();
        for child in ["stack_overflow_rust_child", "stack_overflow_createthread_child", "stack_overflow_pool_child"] {
            let (code, text, ended) = run_child_watched(child, &[]);
            std::eprintln!("STACKEND {child}: {code:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
            assert!(text.contains("STACKFILTER a stack overflow at the reserve's end"), "{child}: {text}");
            assert_eq!(code, Some(0xC000_00FD_u32.cast_signed()), "{child}: {text}");
        }
    }

    fn stack_overflow(kind: Kind) {
        lazy_memory_is_mapped();
        let (go, came_back) = a_thread_of(kind, usize::MAX);
        go.send(()).unwrap();
        // Long enough for STACKENDHOST to see who holds a process that has
        // not ended; an overflow that ends it does so at once.
        let back = came_back.recv_timeout(std::time::Duration::from_secs(60));
        std::println!("the {kind:?} thread's unbounded recursion: {}", if back.is_ok() { "came back" } else { "the process went on for 60 s" });
    }

    /// STACKENDHOST's host part: `reg query` of what decides how a process
    /// with an unhandled exception ends.
    fn stack_end_host_record() {
        const NT: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        const WER: &str = "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting";
        let keys: [(std::string::String, &[&str]); 7] = [
            (NT.into(), &["/v", "CurrentBuild"]),
            (NT.into(), &["/v", "UBR"]),
            (std::format!("{NT}\\AeDebug"), &["/s"]),
            ("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug".into(), &["/s"]),
            (std::format!("HKLM\\{WER}"), &["/s"]),
            (std::format!("HKCU\\{WER}"), &["/s"]),
            ("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting".into(), &["/s"]),
        ];
        for (path, rest) in &keys {
            let mut args = std::vec!["query", path.as_str()];
            args.extend_from_slice(rest);
            let out = std::process::Command::new("reg").args(&args).output();
            let text = match out {
                Ok(o) => std::format!("{}{}", std::string::String::from_utf8_lossy(&o.stdout), std::string::String::from_utf8_lossy(&o.stderr)),
                Err(e) => std::format!("reg: {e}"),
            };
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                std::eprintln!("STACKENDHOST {path}: {line}");
            }
        }
    }

    /// [`run_child`] without a job, which also says when the child ended,
    /// and, if it still runs 12 s after its start, what holds it
    /// (STACKENDHOST).
    fn run_child_watched(child: &str, env: &[(&str, &str)]) -> (Option<i32>, std::string::String, std::time::Duration) {
        use std::io::Read;
        let name = std::format!("{}::{child}", module_path!().split_once("::").unwrap().1);
        let start = std::time::Instant::now();
        let mut process = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name.as_str(), "--ignored", "--nocapture"])
            .envs(env.iter().copied())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = process.stdout.take().unwrap();
        let mut err = process.stderr.take().unwrap();
        let readers = [
            std::thread::spawn(move || { let mut v = Vec::new(); let _ = out.read_to_end(&mut v); v }),
            std::thread::spawn(move || { let mut v = Vec::new(); let _ = err.read_to_end(&mut v); v }),
        ];
        let mut looked = false;
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            if !looked && start.elapsed() >= std::time::Duration::from_secs(12) {
                looked = true;
                stack_end_who_holds(child, process.id());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let ended = start.elapsed();
        let [o, e] = readers.map(|r| r.join().unwrap());
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&o), std::string::String::from_utf8_lossy(&e));
        assert!(text.contains("running 1 test"), "the child {name} ran no test (status {status}): {text}");
        (status.code(), text, ended)
    }

    /// STACKENDHOST's look at a child that has not ended: the processes it
    /// started and those that report faults or debug (by name), then its
    /// threads' stacks.
    fn stack_end_who_holds(child: &str, pid: u32) {
        let script = std::format!(
            "Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {pid} -or $_.ProcessId -eq {pid} -or $_.Name -match 'WerFault|WerSvc|vsjitdebugger|dwwin|drwtsn|windbg|cdb|ntsd|procdump' }} | ForEach-Object {{ \"$($_.ProcessId) parent $($_.ParentProcessId) $($_.Name): $($_.CommandLine)\" }}"
        );
        if let Ok(o) = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &script]).output() {
            for line in std::string::String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.trim().is_empty()) {
                std::eprintln!("STACKENDHOST {child} at 12 s: {line}");
            }
        }
        let cdb = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe";
        if !std::path::Path::new(cdb).exists() {
            std::eprintln!("STACKENDHOST {child} at 12 s: no cdb at {cdb}");
            return;
        }
        let pid = std::format!("{pid}");
        if let Ok(o) = std::process::Command::new(cdb).args(["-p", pid.as_str(), "-pv", "-c", "~*kn 40; qd"]).output() {
            for line in std::string::String::from_utf8_lossy(&o.stdout).lines() {
                let l = line.trim();
                if l.starts_with(|c: char| c.is_ascii_hexdigit()) || l.contains(" Id: ") {
                    std::eprintln!("STACKENDHOST {child} stack: {l}");
                }
            }
        }
    }

    #[test]
    #[ignore = "run by test_a_stack_overflow_at_the_reserves_end_is_still_one"]
    fn stack_overflow_rust_child() {
        stack_overflow(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_a_stack_overflow_at_the_reserves_end_is_still_one"]
    fn stack_overflow_createthread_child() {
        stack_overflow(Kind::CreateThread);
    }

    #[test]
    #[ignore = "run by test_a_stack_overflow_at_the_reserves_end_is_still_one"]
    fn stack_overflow_pool_child() {
        stack_overflow(Kind::Pool);
    }

    /// A host thread's first access to lazy memory near its stack reserve's
    /// end is either served or a stack overflow at the reserve's end, said
    /// as one: never a silent end. The access is served on the thread's own
    /// stack (`windows_mm::lazy_on_exception`, below the exception
    /// dispatcher's frames), and its commit takes the region table and
    /// commits the page, so near the reserve's end the handler's own frames
    /// meet the end inside it: the stack overflow then raised there must be
    /// dispatched as any other,
    /// Rust's "has overflowed its stack" line, the stack filter's
    /// STACKFILTER line (the reserve's end, passed on) and 0xC00000FD. A
    /// child per case: a thread recurses until 64, 63, ... 4 KiB are left
    /// above its reserve's low end (DeallocationStack), then reads a lazy
    /// page; a Rust thread (a 20 KiB guarantee) and a `CreateThread` thread
    /// (none; a pool thread's stack is the same, and its overflow's end on
    /// Windows Server 2025 is a question of its own). Asserted per case:
    /// the read served and the child ended 0, or the overflow said, as
    /// above; and for each kind, that some case met the reserve's end in
    /// the handler's commit (STACKASK says where the overflow was raised),
    /// so that the window is tested, not only its edges.
    #[test]
    fn test_a_lazy_touch_at_the_reserves_end_is_a_loud_overflow() {
        let mut in_the_handler = [false; 2];
        for (k, kind) in ["rust", "createthread"].into_iter().enumerate() {
            for left in (4..=64).rev() {
                let left_kib = std::format!("{left}");
                let child = std::format!("lazy_at_the_reserves_end_{kind}_child");
                let (code, text, _) = run_child_watched(&child, &[("WICK_TEST_LEFT_KIB", left_kib.as_str())]);
                std::eprintln!("LAZYEND {kind} at {left} KiB left: {code:?}; {}", text.trim().replace('\n', " | "));
                let served = code == Some(0) && text.contains("LAZYEND the read gave 0");
                let loud = code == Some(0xC000_00FD_u32.cast_signed())
                    && text.contains("has overflowed its stack")
                    && text.contains("STACKFILTER a stack overflow at the reserve's end");
                assert!(served || loud, "{kind} at {left} KiB left: neither served nor an overflow said as one ({code:?}): {text}");
                in_the_handler[k] |= loud && text.contains("raised in the lazy handler's commit");
            }
        }
        assert!(in_the_handler.iter().all(|&b| b), "no case met the reserve's end in the lazy handler's commit (rust, createthread): {in_the_handler:?}");
    }

    /// Recurses until `left` bytes are left above `reserve`, then reads the
    /// lazy page at `mem`, saying so before and after, without allocating.
    #[inline(never)]
    fn down_to_then_read(left: usize, reserve: usize, mem: u64) -> u8 {
        let pad = core::hint::black_box([0u8; 256]);
        let here = core::ptr::addr_of!(pad) as usize;
        let v = if here - reserve > left {
            down_to_then_read(left, reserve, mem)
        } else {
            crate::windows_mm::say_at_the_limit(format_args!("LAZYEND reading at {} B above the reserve's end", here - reserve));
            // SAFETY: a lazy page of ours, never touched.
            let v = unsafe { core::ptr::read_volatile(mem as *const u8) };
            crate::windows_mm::say_at_the_limit(format_args!("LAZYEND the read gave {v}"));
            v
        };
        v.wrapping_add(core::hint::black_box(&pad)[0])
    }

    fn lazy_at_the_reserves_end(kind: Kind) {
        let left = std::env::var("WICK_TEST_LEFT_KIB").unwrap().parse::<usize>().unwrap() << 10;
        // SAFETY: a new anonymous mapping, committed at first touch (lazy).
        let mem = unsafe {
            crate::mmap(ptr::null_mut(), 1 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        let (done, came_back) = std::sync::mpsc::channel::<u8>();
        on_a_thread_of(
            kind,
            std::boxed::Box::new(move || {
                let (_, _, reserve, _) = stack_of_this_thread();
                let _ = done.send(down_to_then_read(left, reserve, mem));
            }),
        );
        let v = came_back.recv_timeout(std::time::Duration::from_secs(60)).expect("the thread neither came back nor ended the process");
        assert_eq!(v, 0);
    }

    #[test]
    #[ignore = "run by test_a_lazy_touch_at_the_reserves_end_is_a_loud_overflow"]
    fn lazy_at_the_reserves_end_rust_child() {
        lazy_at_the_reserves_end(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_a_lazy_touch_at_the_reserves_end_is_a_loud_overflow"]
    fn lazy_at_the_reserves_end_createthread_child() {
        lazy_at_the_reserves_end(Kind::CreateThread);
    }

    /// An unhandled exception the stack filter does not take goes to the
    /// filter it replaced: one set before the lazy-memory handler came is
    /// called for an exception no handler takes, and ends the process its
    /// own way (exit 7, its line).
    #[test]
    fn test_the_filter_the_stack_filter_replaced_is_called() {
        let (code, text) = run_child("filter_replaced_child", None);
        assert!(text.contains("the earlier filter: exception 0xe0001234"), "{text}");
        assert_eq!(code, Some(7), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_filter_the_stack_filter_replaced_is_called"]
    fn filter_replaced_child() {
        use windows_sys::Win32::System::Diagnostics::Debug::{EXCEPTION_POINTERS, RaiseException, SetUnhandledExceptionFilter};
        unsafe extern "system" fn earlier(info: *const EXCEPTION_POINTERS) -> i32 {
            // SAFETY: the system's exception pointers.
            let code = unsafe { (*(*info).ExceptionRecord).ExceptionCode };
            crate::windows_mm::say_at_the_limit(format_args!("the earlier filter: exception {:#x}", code.cast_unsigned()));
            // SAFETY: ends this process.
            unsafe { windows_sys::Win32::System::Threading::TerminateProcess(windows_sys::Win32::System::Threading::GetCurrentProcess(), 7) };
            0
        }
        // SAFETY: the filter stays for the process.
        unsafe { SetUnhandledExceptionFilter(Some(earlier)) };
        lazy_memory_is_mapped();
        // SAFETY: an exception no handler takes.
        unsafe { RaiseException(0xE000_1234, 0, 0, ptr::null()) };
        std::println!("the exception was taken");
    }

    /// The pages of the first 8 chunks: the discarded ones missing, the
    /// others still 0x5a.
    fn the_live_pages_read_back(mem: u64) {
        for p in (0..8 * CHUNK).step_by(PAGE as usize) {
            if (p / PAGE).is_multiple_of(2) {
                assert!(is_missing(mem + p), "{p:#x} is not missing");
            } else {
                // SAFETY: a filled page.
                assert_eq!(unsafe { *((mem + p + 9) as *const u8) }, 0x5a, "{p:#x}");
            }
        }
    }

    /// What a guest that gives back scattered pages (a balloon's 4 KiB
    /// pages, no chunk whole) gets back, and when, in a child under a job
    /// limit: the discard of every other page of a chunk gives none of the
    /// process's private commit back (the dead pages keep their section
    /// commit and its charge: the job and the jailer's count read that much
    /// more than Linux's memory.current, which uncharged them at the
    /// discard); with no room left in the job ([`no_room_left`]) each dead
    /// page is filled again, as its commit and charge are still there,
    /// with no reclaim asked and no chunk moved (`reclaim_counts`). The
    /// commit goes back to the job only when the chunk moves
    /// (`test_a_chunk_with_one_dead_page_at_the_limit`) or is discarded
    /// whole (`test_a_wholly_discarded_chunk_gives_its_section_commit_back`).
    /// SCATTERED line.
    #[test]
    fn test_a_scattered_discard_keeps_its_charge_and_its_refill_takes_none() {
        let (code, text) = run_child("scattered_discard_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert!(text.contains("SCATTERED "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_scattered_discard_keeps_its_charge_and_its_refill_takes_none in a job of its own"]
    fn scattered_discard_child() {
        let (ctx, user, mem, _) = fill_to_the_limit();
        let before = private_commit();
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        let after = private_commit();
        let dead = CHUNK / (2 * PAGE);
        let mut held = no_room_left();
        let counts = reclaim_counts();
        let mut made = 0;
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            if fill_a_page(ctx, mem + p) == "made" {
                made += 1;
            }
        }
        let filled = reclaim_counts();
        give_back_every_page(&mut held);
        std::println!(
            "SCATTERED the discard of {dead} pages gave back {} KiB of the process's private commit (Linux: {} KiB); with no \
             room left, {made} of {dead} dead pages filled again, {} reclaims asked, {} chunks moved",
            (before as i64 - after as i64) / 1024,
            dead * PAGE / 1024,
            filled.asks - counts.asks,
            filled.moves - counts.moves
        );
        // Within 64 KiB: the heap's own blocks for the lines may move it.
        assert!(before.abs_diff(after) < 64 << 10, "the discard moved the private commit by {} KiB", (before as i64 - after as i64) / 1024);
        assert_eq!((made, filled.asks - counts.asks, filled.moves - counts.moves), (dead, 0, 0));
        for p in (0..CHUNK).step_by(PAGE as usize) {
            // SAFETY: a filled page.
            assert_eq!(unsafe { *((mem + p + 9) as *const u8) }, 0x5a, "{p:#x}");
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A fill refused at the job's limit while partly discarded chunks hold
    /// dead pages (their section commit and charge, as (A) keeps them)
    /// reclaims them first and succeeds, as Linux's memory cgroup reclaims
    /// before it refuses a charge (v6.1 mm/memcontrol.c `try_charge_memcg`:
    /// `try_to_free_mem_cgroup_pages` before `mem_cgroup_oom`; there the
    /// discarded pages were freed at the discard already). The live pages
    /// read back, the discarded ones are missing, and a fill past what the
    /// dead pages gave back is still `ENOMEM`. Before, the fill was refused
    /// with 8 MiB of dead pages charged. With no room left in the job
    /// ([`no_room_left`]): in CI run 43640510155 no move was made there, its
    /// map refused (`test_the_room_a_move_needs_on_record`).
    #[test]
    fn test_a_fill_at_the_limit_reclaims_partly_discarded_chunks() {
        let (code, text) = run_child("reclaim_fill_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        assert!(text.contains("filled 4096 KiB more"), "the fill was not reclaimed for: {text}");
        assert!(text.contains("refused with ENOMEM after"), "the limit did not hold past the dead pages: {text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_at_the_limit_reclaims_partly_discarded_chunks in a job of its own"]
    fn reclaim_fill_child() {
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let page = std::vec![0x5au8; PAGE as usize];
        let held = no_room_left();
        let fill_pages = |from: u64, most: u64| -> (u64, Option<c_int>) {
            let mut n = 0;
            while n < most {
                // SAFETY: `page` holds a page.
                match unsafe { copy(ctx, page.as_ptr(), mem + from + n, PAGE, false) } {
                    Ok(k) => n += k,
                    Err((e, _)) => return (n, Some(e)),
                }
            }
            (n, None)
        };
        let (more, _) = fill_pages(done, 4 << 20);
        std::println!("filled {} KiB more", more >> 10);
        assert_eq!(more, 4 << 20, "a fill at the limit was refused with 8 MiB of dead pages charged");
        the_live_pages_read_back(mem);
        // Past what the dead pages gave back (8 MiB less the 4 just
        // filled, and a little of the job's room left before them).
        let (rest, refused) = fill_pages(done + more, 16 << 20);
        std::println!("refused with {} after {} KiB more", if refused == Some(crate::ENOMEM) { "ENOMEM" } else { "no error" }, rest >> 10);
        assert_eq!(refused, Some(crate::ENOMEM));
        assert!(rest < (4 << 20) + (2 << 20), "{} KiB filled past the dead pages", rest >> 10);
        drop(held);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let _ = ctx;
    }

    /// A first touch of lazy memory refused at the job's limit reclaims the
    /// dead pages of partly discarded chunks first, and the access goes on,
    /// where it ended the process with 137 before: Linux reclaims before
    /// its out-of-memory kill (as above). With no room left in the job
    /// ([`no_room_left`]).
    #[test]
    fn test_a_lazy_touch_at_the_limit_reclaims_before_it_ends_the_vmm() {
        let (code, text) = run_child("reclaim_touch_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        assert!(text.contains("touched 4096 KiB"), "the touch was not reclaimed for (status {code:?}): {text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_lazy_touch_at_the_limit_reclaims_before_it_ends_the_vmm in a job of its own"]
    fn reclaim_touch_child() {
        let (_ctx, user, mem, _) = fill_to_the_limit_and_discard_in_part();
        // SAFETY: a new anonymous mapping, committed at first touch.
        let lazy = unsafe {
            crate::mmap(
                ptr::null_mut(),
                16 << 20,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, crate::MAP_FAILED);
        let held = no_room_left();
        for p in (0..4usize << 20).step_by(PAGE as usize) {
            // SAFETY: our mapping; the first touch commits the page.
            unsafe { core::ptr::write_volatile((lazy as *mut u8).add(p), 1) };
        }
        std::println!("touched 4096 KiB");
        drop(held);
        the_live_pages_read_back(mem);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The pages [`take_the_room_given_up`] takes, room for them made
    /// before (the hook runs at the limit, where nothing may allocate), and
    /// whether it has run (it takes the room once).
    static ROOM_TAKEN: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());
    static ROOM_TAKEN_ONCE: AtomicBool = AtomicBool::new(false);

    /// Another commit taking the room a move just made by giving back part
    /// of its dead pages' charge (`windows_mm::AFTER_DEAD_UNCHARGED`), the
    /// first time only: all the job has.
    fn take_the_room_given_up() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        if ROOM_TAKEN_ONCE.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut held = ROOM_TAKEN.lock().unwrap();
        while held.len() < held.capacity() {
            // SAFETY: new private memory of ours.
            let p = unsafe { VirtualAlloc(ptr::null(), PAGE as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
            if p.is_null() {
                break;
            }
            held.push(p as usize);
        }
    }

    /// One page filled at `at`: "made", "ENOMEM" or "another errno".
    fn fill_a_page(ctx: usize, at: u64) -> &'static str {
        let page = [0x5au8; PAGE as usize];
        // SAFETY: `page` holds a page.
        match unsafe { copy(ctx, page.as_ptr(), at, PAGE, false) } {
            Ok(_) => "made",
            Err((e, _)) if e == crate::ENOMEM => "ENOMEM",
            Err(_) => "another errno",
        }
    }

    /// A move whose room another commit takes between the giving back of
    /// part of its dead pages' charge (12 KiB, `windows_mm::MOVE_ROOM`) and
    /// its first map (`windows_mm::AFTER_DEAD_UNCHARGED`), with no room left
    /// in the job ([`no_room_left`]): its map is refused, the charge cannot
    /// be taken again, and the chunk owes it (`windows_mm::OWED`), said in
    /// one line on standard error; the chunk as it was. While it owes, the
    /// job's limit and the jailer's count are 12 KiB below what the process
    /// holds, no more: no other chunk is moved, so the fill that needed the
    /// reclaim is refused (`ENOMEM`), and so is the next. Once the other
    /// commit gives its room back, the next fill takes the owed charge again
    /// first (nothing owed then) and goes on through the reclaim, its moves
    /// made: 4 MiB filled, the live pages read back, the discarded ones
    /// missing.
    #[test]
    fn test_a_move_whose_room_is_taken_owes_its_charge() {
        let (code, text) = run_child("room_taken_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        assert!(
            text.contains("could not map its new section (error 1455) with its dead pages' charge given back for its maps"),
            "no line for the refused map: {text}"
        );
        assert!(text.contains("not taken again (another commit holds the room): owed"), "{text}");
        assert!(text.contains("while owed: the fill ENOMEM, 12 KiB owed; again ENOMEM, 12 KiB owed"), "{text}");
        assert!(text.contains("the room given back: 0 KiB owed, the fill made: 4096 KiB"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_move_whose_room_is_taken_owes_its_charge in a job of its own"]
    fn room_taken_child() {
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        ROOM_TAKEN.lock().unwrap().reserve_exact(4096);
        let mut held = no_room_left();
        *crate::windows_mm::AFTER_DEAD_UNCHARGED.lock().unwrap() = Some(take_the_room_given_up);
        let first = fill_a_page(ctx, mem + done);
        let owed = crate::windows_mm::owed_bytes();
        let again = fill_a_page(ctx, mem + done);
        let still = crate::windows_mm::owed_bytes();
        *crate::windows_mm::AFTER_DEAD_UNCHARGED.lock().unwrap() = None;
        crate::windows_mm::say_at_the_limit(format_args!(
            "while owed: the fill {first}, {} KiB owed; again {again}, {} KiB owed",
            owed >> 10,
            still >> 10
        ));
        {
            let mut t = ROOM_TAKEN.lock().unwrap();
            while !t.is_empty() {
                give_back_a_page(&mut t);
            }
        }
        let mut n = 0;
        while n < 4 << 20 {
            if fill_a_page(ctx, mem + done + n) != "made" {
                break;
            }
            n += PAGE;
        }
        let owed = crate::windows_mm::owed_bytes();
        give_back_every_page(&mut held);
        std::println!("the room given back: {} KiB owed, the fill made: {} KiB", owed >> 10, n >> 10);
        the_live_pages_read_back(mem);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A chunk with one dead page, the least a move gives back for its maps
    /// (4 KiB, where its new section's view mapped anywhere took 4 KiB on
    /// record, VIEWCHARGE, and one into a placeholder made apart up to 12),
    /// with no room left in the job ([`no_room_left`]): a fill's reclaim
    /// moves it or fails cleanly (its charge taken again, nothing owed);
    /// which one, what the fill then got, what the move did to the process's
    /// private commit, and where its view was mapped (its offset in 2 MiB),
    /// printed; then chunks with 2, 3 and 4 dead pages the same way. Before
    /// the discards, at the same limit with no dead page
    /// anywhere, the reclaim moves nothing and tries no move: a chunk with no
    /// dead pages is never a candidate. Nothing is owed, no other chunk is
    /// moved, and the live pages read back.
    #[test]
    fn test_a_chunk_with_one_dead_page_at_the_limit() {
        let (code, text) = run_child("one_dead_page_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert!(text.contains("no dead page: the fill ENOMEM, 0 moves made, 0 tried"), "{text}");
        assert!(text.contains("ONEDEAD 1 dead page(s): "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_chunk_with_one_dead_page_at_the_limit in a job of its own"]
    fn one_dead_page_child() {
        let (ctx, user, mem, done) = fill_to_the_limit();
        let moves = || moves_on_record().0.len();
        let mut held = no_room_left();
        let (m0, refused0) = (moves(), crate::windows_mm::moves_refused());
        let none = fill_a_page(ctx, mem + done);
        let (m1, refused1) = (moves(), crate::windows_mm::moves_refused());
        crate::windows_mm::say_at_the_limit(format_args!(
            "no dead page: the fill {none}, {} moves made, {} tried",
            m1 - m0,
            (m1 - m0) as u64 + refused1 - refused0
        ));
        give_back_every_page(&mut held);
        // Chunk k - 1 with k dead pages (its odd pages from 1), each tried
        // with no room left.
        let mut wrong = std::vec::Vec::new();
        for k in 1..=4u64 {
            let chunk = mem + (k - 1) * CHUNK;
            for i in 0..k {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((chunk + (2 * i + 1) * PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
            let mut held = no_room_left();
            let (m1, refused1) = (moves(), crate::windows_mm::moves_refused());
            let before = private_commit();
            let one = fill_a_page(ctx, mem + done + k * PAGE);
            let after = private_commit();
            let (m2, refused2) = (moves(), crate::windows_mm::moves_refused());
            let owed = crate::windows_mm::owed_bytes();
            let view = crate::windows_mm::LAST_MOVE_VIEW.load(Ordering::Relaxed);
            give_back_every_page(&mut held);
            std::println!(
                "ONEDEAD {k} dead page(s): the fill {one}, {} moves made, {} not made, {} KiB owed; the process's private \
                 commit {:+} KiB over the fill; the move's view at {view:#x}, {:#x} into its 2 MiB",
                m2 - m1,
                refused2 - refused1,
                owed >> 10,
                (after as i64 - before as i64) / 1024,
                view % CHUNK as usize
            );
            // The chunks with dead pages now: this one, and those before it
            // not moved yet.
            if owed != 0 || m2 - m1 > usize::try_from(k).unwrap() {
                wrong.push(k);
            }
            for p in (0..CHUNK).step_by(PAGE as usize) {
                if p % (2 * PAGE) == PAGE && p < (2 * k + 1) * PAGE {
                    assert!(is_missing(chunk + p), "{k}: {p:#x} is not missing");
                } else {
                    // SAFETY: a filled page.
                    assert_eq!(unsafe { *((chunk + p + 9) as *const u8) }, 0x5a, "{k}: {p:#x}");
                }
            }
        }
        assert!(wrong.is_empty(), "a charge owed with no other commit, or a chunk with no dead pages moved, for {wrong:?}");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let _ = ctx;
    }

    /// The room a move gives back for its maps is its dead pages' charge,
    /// not its missing pages': a chunk whose first half was never filled
    /// (missing, no commit and no charge) and whose last page is dead, with
    /// no room left in the job ([`no_room_left`]), is moved by a fill's
    /// reclaim, the fill made with what it gave back, nothing owed; the
    /// pages read back as they were.
    #[test]
    fn test_a_chunk_whose_dead_pages_lie_above_unfilled_ones_moves() {
        let (code, text) = run_child("dead_above_unfilled_child", Some(96 << 20));
        assert!(text.contains("dead above unfilled: the fill made, 1 moves made, 0 not made, 0 KiB owed"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_chunk_whose_dead_pages_lie_above_unfilled_ones_moves in a job of its own"]
    fn dead_above_unfilled_child() {
        let (ctx, user, mem, done) = fill_to_the_limit_from(CHUNK / 2);
        let last = mem + CHUNK - PAGE;
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise(last as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        let mut held = no_room_left();
        let (m1, refused1) = (moves_on_record().0.len(), crate::windows_mm::moves_refused());
        let fill = fill_a_page(ctx, mem + done);
        let (m2, refused2) = (moves_on_record().0.len(), crate::windows_mm::moves_refused());
        let owed = crate::windows_mm::owed_bytes();
        give_back_every_page(&mut held);
        std::println!(
            "dead above unfilled: the fill {fill}, {} moves made, {} not made, {} KiB owed",
            m2 - m1,
            refused2 - refused1,
            owed >> 10
        );
        for p in (0..CHUNK).step_by(PAGE as usize) {
            if p < CHUNK / 2 || mem + p == last {
                assert!(is_missing(mem + p), "{p:#x} is not missing");
            } else {
                // SAFETY: a filled page.
                assert_eq!(unsafe { *((mem + p + 9) as *const u8) }, 0x5a, "{p:#x}");
            }
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A charge owed (`windows_mm::OWED`, as in
    /// [`test_a_move_whose_room_is_taken_owes_its_charge`]) goes with its
    /// range: once the range is unregistered and unmapped, nothing is owed,
    /// before any commit; memory committed at the same address afterwards
    /// is no charged view's, and a fill of another range is made, with no
    /// charge taken for the old one's pages.
    #[test]
    fn test_an_owed_charge_goes_with_its_range() {
        let (code, text) = run_child("owed_goes_child", Some(96 << 20));
        assert!(text.contains("owed: 12 KiB; unregistered and unmapped: 0 KiB owed; the same address committed, charged false; another fill made"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_an_owed_charge_goes_with_its_range in a job of its own"]
    fn owed_goes_child() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        ROOM_TAKEN.lock().unwrap().reserve_exact(4096);
        let mut held = no_room_left();
        *crate::windows_mm::AFTER_DEAD_UNCHARGED.lock().unwrap() = Some(take_the_room_given_up);
        let _ = fill_a_page(ctx, mem + done);
        *crate::windows_mm::AFTER_DEAD_UNCHARGED.lock().unwrap() = None;
        let owed = crate::windows_mm::owed_bytes();
        {
            let mut t = ROOM_TAKEN.lock().unwrap();
            while !t.is_empty() {
                give_back_a_page(&mut t);
            }
        }
        give_back_every_page(&mut held);
        // Registered before the old range's addresses are free: a range
        // stays in the table, unregistered, until its userfaultfd is closed.
        // SAFETY: a new anonymous mapping, committed at first touch (the
        // job is near its limit).
        let other = unsafe {
            crate::mmap(
                ptr::null_mut(),
                CHUNK as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(other, crate::MAP_FAILED);
        let other = other as u64;
        register(ctx, other, CHUNK).unwrap();
        unregister(ctx, mem, 128 << 20).unwrap();
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 128 << 20) }, 0);
        let after = crate::windows_mm::owed_bytes();
        // SAFETY: new memory of ours, where the range was if it is free.
        let at = unsafe { VirtualAlloc(mem as *const c_void, 1 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert_eq!(at as u64, mem, "the range's address was not free again");
        let charged = crate::windows_mm::charged_view_at_for_tests(mem as usize);
        let made = fill_a_page(ctx, other);
        std::println!(
            "owed: {} KiB; unregistered and unmapped: {} KiB owed; the same address committed, charged {charged}; another fill {made}",
            owed >> 10,
            after >> 10
        );
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// An ask of a reclaimer whose thread has ended (`Ask::End`, the test's
    /// only way to end it) does not wait for good: the asker's wait is for
    /// the answer or the thread's end (`ask_the_reclaimer`), and the process
    /// is aborted with a named line.
    #[test]
    fn test_an_ask_of_a_reclaimer_that_has_ended_aborts() {
        let (code, text) = run_child("ended_reclaimer_child", None);
        assert!(text.contains("wick: reclaim: the reclaim's thread has ended"), "{text}");
        assert_eq!(code, Some(0xC000_0409_u32.cast_signed()), "not aborted: {text}");
    }

    #[test]
    #[ignore = "run by test_an_ask_of_a_reclaimer_that_has_ended_aborts in a process of its own"]
    fn ended_reclaimer_child() {
        let (ctx, _user) = create(0, false, true).unwrap();
        let mem = map(CHUNK as usize);
        register(ctx, mem, CHUNK).unwrap();
        let _lock = lock();
        let r = ask_the_reclaimer(Ask::End);
        std::println!("answered: {r:?}");
    }

    /// How deep the reclaim's thread goes (`reclaimer`, its stack painted
    /// below where it starts and committed whole, `RECLAIMER_STACK`): the
    /// most of it a fill's reclaim and a touch's used, with no room left in
    /// the job, against its committed size; and the most of a host thread's
    /// stack committed when the lazy-memory handler took its touch there
    /// (`wick_mm::host_faults_on_this_thread`), the faulting thread's own
    /// frames up to the hand-off, and how deep that path went below the
    /// touching frame (the thread's stack painted first). Printed
    /// (RECLAIMSTACK); asserted that the reclaimer's stack was committed
    /// whole at its start (`VirtualQuery`) and it used no more than a
    /// quarter of it.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_the_reclaimers_stack_on_record() {
        let (code, text) = run_child("reclaimer_stack_child", Some(96 << 20));
        for line in text.lines().filter(|l| l.starts_with("RECLAIMSTACK")) {
            std::eprintln!("{line}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_reclaimers_stack_on_record in a job of its own"]
    fn reclaimer_stack_child() {
        // The locks as the product takes them: a watch's paint below a lock
        // would count as the reclaimer's use.
        crate::windows_stacklock::WATCHING.store(false, Ordering::SeqCst);
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let page = std::vec![0x5au8; PAGE as usize];
        // SAFETY: a new anonymous mapping, committed at first touch.
        let lazy = unsafe {
            crate::mmap(ptr::null_mut(), 4 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_ne!(lazy, crate::MAP_FAILED);
        let mut held = no_room_left();
        let mut n = 0;
        while n < 2 << 20 {
            // SAFETY: `page` holds a page.
            match unsafe { copy(ctx, page.as_ptr(), mem + done + n, PAGE, false) } {
                Ok(k) => n += k,
                Err(_) => break,
            }
        }
        let after_fill = reclaimer_stack();
        // This thread's committed stack below here painted: how deep the
        // touch's path goes on the touching thread (the lazy-memory
        // handler, the commit, the hand-off to the reclaimer).
        let painted = paint_below_here();
        for p in (0..4usize << 20).step_by(PAGE as usize) {
            // SAFETY: our mapping; the first touch commits the page.
            unsafe { core::ptr::write_volatile((lazy as *mut u8).add(p), 1) };
        }
        let path = used_below(painted);
        let after_touch = reclaimer_stack();
        let (faults, deepest) = crate::windows_mm::wick_mm::host_faults_on_this_thread();
        give_back_every_page(&mut held);
        let (moves, _, _) = moves_on_record();
        std::println!(
            "RECLAIMSTACK {} chunks moved; the reclaimer's stack: {} bytes used by the fills' reclaims, {} by the touches' too, \
             of {} committed ({} by VirtualQuery at its start); this thread's {faults} lazy touches, their path {path} bytes \
             deep below the touching frame (of {} painted), its stack {deepest} bytes committed at the deepest",
            moves.len(),
            after_fill.0,
            after_touch.0,
            after_touch.1,
            reclaimer_stack_queried(),
            painted.1 - painted.0
        );
        assert!(reclaimer_stack_queried() >= RECLAIMER_STACK, "the reclaimer's stack was not committed whole");
        assert!(after_touch.0 > 0 && after_touch.0 <= after_touch.1 / 4, "the reclaimer used {after_touch:?}");
        assert!(path < painted.1 - painted.0, "the touch's path went past the painted stack");
        let _ = ctx;
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A chunk moved by the reclaim while a host thread reads and writes
    /// its live pages, 100 rounds: the thread's writes are all kept, it
    /// never sees another value, and nothing faults for good. Each round
    /// discards the chunk's even pages, moves the chunk (its live pages
    /// copied into a new section, which both views then map: the dead
    /// pages' commit and charge given back), and fills the even pages
    /// again for the next. In a process of its own: a reclaim takes any
    /// registered chunk of the process with discarded pages, so it would
    /// move the chunks of the crate's other tests, running on other threads.
    /// The moves are made under no job limit; at one, with no room left,
    /// `test_a_fill_at_the_limit_reclaims_partly_discarded_chunks` and the
    /// others at the limit move chunks.
    #[test]
    fn test_a_moved_chunk_reads_and_writes_through() {
        let (code, text) = run_child("moved_chunk_child", None);
        assert!(text.contains("moved 100 times"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_moved_chunk_reads_and_writes_through in a process of its own"]
    fn moved_chunk_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let writer = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut round = 0u64;
                while !stop.load(Ordering::Acquire) {
                    round += 1;
                    for p in (PAGE..CHUNK).step_by(2 * PAGE as usize) {
                        let at = (mem + p + 64) as *mut u64;
                        // SAFETY: a live page of the registered range.
                        unsafe {
                            core::ptr::write_volatile(at, round ^ p);
                            assert_eq!(core::ptr::read_volatile(at), round ^ p, "a write to {p:#x} was lost");
                        }
                    }
                }
                round
            })
        };
        let mut moved = 0;
        for _ in 0..100 {
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
            let r = reclaim_at_touch(PAGE as usize);
            moved += r.chunks;
            assert_eq!(committed(mem, CHUNK), CHUNK / 2, "the moved chunk holds its live pages only");
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                assert_eq!(zeropage(ctx, mem + p, PAGE, true).unwrap(), PAGE);
            }
        }
        stop.store(true, Ordering::Release);
        let rounds = writer.join().expect("the writer failed");
        assert_eq!(moved, 100, "a reclaim did not move the chunk");
        assert!(rounds > 100, "the writer ran {rounds} rounds");
        std::println!("moved 100 times; the writer ran {rounds} rounds");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The test binary's allocator: the system's, counting the allocations
    /// a thread makes while [`COUNTING_ALLOCATIONS`] is set on it
    /// (`test_a_reclaim_allocates_nothing`), and, while [`COUNTING_KINDS`]
    /// is set, those of every thread marked with a kind ([`KIND`]: the
    /// userfaultfd's serve thread, the reclaimer, a test's own thread), with
    /// where the first few were made ([`KindCount`]).
    struct Counting;

    std::thread_local! {
        pub(super) static COUNTING_ALLOCATIONS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        pub(super) static ALLOCATIONS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
        /// This thread's kind for [`COUNTING_KINDS`]: 0 none, else an index
        /// of [`KINDS`] ([`SERVE`], [`RECLAIMER`], [`CALLER`]).
        pub(super) static KIND: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
    }

    /// The userfaultfd's serve thread (marked in `serve`).
    pub(super) const SERVE: u8 = 1;
    /// The reclaim's thread (marked in `reclaimer`).
    pub(super) const RECLAIMER: u8 = 2;
    /// A test's own thread, as the VMM's thread that fills or touches.
    pub(super) const CALLER: u8 = 3;
    const KIND_NAMES: [&str; 4] = ["", "the serve thread", "the reclaimer", "the caller"];
    /// The return addresses kept of each kind's first allocations.
    const SITES: usize = 8;
    const FRAMES: usize = 20;

    /// What a kind's thread allocated while [`COUNTING_KINDS`] was set.
    struct KindCount {
        allocations: AtomicU64,
        bytes: AtomicU64,
        /// Return addresses of its first [`SITES`] allocations, made in the
        /// allocator without allocating (`RtlCaptureStackBackTrace`).
        sites: [[AtomicUsize; FRAMES]; SITES],
    }

    static COUNTING_KINDS: AtomicBool = AtomicBool::new(false);
    static KINDS: [KindCount; 4] = [const {
        KindCount { allocations: AtomicU64::new(0), bytes: AtomicU64::new(0), sites: [const { [const { AtomicUsize::new(0) }; FRAMES] }; SITES] }
    }; 4];

    /// Counts an allocation of `size` bytes for this thread's kind.
    fn count_for_the_kind(size: usize) {
        if !COUNTING_KINDS.load(Ordering::Relaxed) {
            return;
        }
        let kind = usize::from(KIND.with(core::cell::Cell::get));
        if kind == 0 {
            return;
        }
        let k = &KINDS[kind];
        let n = k.allocations.fetch_add(1, Ordering::SeqCst);
        k.bytes.fetch_add(size as u64, Ordering::SeqCst);
        if let Some(site) = k.sites.get(usize::try_from(n).unwrap_or(SITES)) {
            let mut frames = [ptr::null_mut::<c_void>(); FRAMES];
            // SAFETY: room for FRAMES addresses.
            #[allow(clippy::cast_possible_truncation)]
            let got = unsafe { windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace(1, FRAMES as u32, frames.as_mut_ptr(), ptr::null_mut()) };
            for (slot, f) in site.iter().zip(&frames[..usize::from(got)]) {
                slot.store(*f as usize, Ordering::Relaxed);
            }
        }
    }

    /// Starts counting the allocations of every marked thread, from zero.
    fn count_the_kinds() {
        for k in &KINDS {
            k.allocations.store(0, Ordering::SeqCst);
            k.bytes.store(0, Ordering::SeqCst);
            for site in &k.sites {
                for f in site {
                    f.store(0, Ordering::Relaxed);
                }
            }
        }
        COUNTING_KINDS.store(true, Ordering::SeqCst);
    }

    /// Stops counting: each kind's allocations and bytes.
    fn counted_kinds() -> [(u64, u64); 4] {
        COUNTING_KINDS.store(false, Ordering::SeqCst);
        core::array::from_fn(|i| (KINDS[i].allocations.load(Ordering::SeqCst), KINDS[i].bytes.load(Ordering::SeqCst)))
    }

    /// ALLOCS: what `what` allocated on each kind's thread, and the return
    /// addresses of the first allocations, as offsets in this executable
    /// for a debugger to name (`cdb -z <exe>`, `ln`). Without allocating.
    fn say_the_allocations(what: &str, counts: &[(u64, u64); 4]) {
        unsafe extern "C" {
            static __ImageBase: u8;
        }
        let base = core::ptr::addr_of!(__ImageBase) as usize;
        for (kind, &(n, bytes)) in counts.iter().enumerate().skip(1) {
            crate::windows_mm::say_at_the_limit(format_args!("ALLOCS {what}: {} {n} allocations, {bytes} bytes", KIND_NAMES[kind]));
            for (i, site) in KINDS[kind].sites.iter().enumerate().take(usize::try_from(n).unwrap_or(SITES)) {
                for (j, f) in site.iter().enumerate() {
                    let a = f.load(Ordering::Relaxed);
                    if a == 0 {
                        break;
                    }
                    if a >= base && a - base < 64 << 20 {
                        crate::windows_mm::say_at_the_limit(format_args!("ALLOCSITE {} {i} {j} image+{:#x}", KIND_NAMES[kind], a - base));
                    } else {
                        crate::windows_mm::say_at_the_limit(format_args!("ALLOCSITE {} {i} {j} {a:#x}", KIND_NAMES[kind]));
                    }
                }
            }
        }
    }

    // SAFETY: the system allocator's calls, as they are; the counts are
    // thread-local cells and atomics, which allocate nothing.
    unsafe impl std::alloc::GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            if COUNTING_ALLOCATIONS.with(core::cell::Cell::get) {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
            count_for_the_kind(layout.size());
            // SAFETY: the caller's contract.
            unsafe { std::alloc::System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
            // SAFETY: the caller's contract.
            unsafe { std::alloc::System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
            if COUNTING_ALLOCATIONS.with(core::cell::Cell::get) {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
            count_for_the_kind(new_size);
            // SAFETY: the caller's contract.
            unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Counting = Counting;

    /// The allocations `f` makes on this thread, and its result.
    fn allocations_of<T>(f: impl FnOnce() -> T) -> (u64, T) {
        ALLOCATIONS.with(|a| a.set(0));
        COUNTING_ALLOCATIONS.with(|c| c.set(true));
        let r = f();
        COUNTING_ALLOCATIONS.with(|c| c.set(false));
        (ALLOCATIONS.with(core::cell::Cell::get), r)
    }

    /// A reclaim allocates nothing: it runs when the job has refused commit,
    /// where a heap that must grow would end the process instead (Linux's
    /// reclaim takes no memory on that path either). A fill's reclaim, and
    /// a touch's that passes over a chunk with a call in flight on it and
    /// then waits for that call (held 200 ms by another thread), each move
    /// their chunks with no allocation on the reclaiming thread. In a
    /// process of its own (a reclaim takes any chunk of the process).
    /// Its moves are made under no job limit (the reclaimer's asks are the
    /// same at one).
    #[test]
    fn test_a_reclaim_allocates_nothing() {
        let (code, text) = run_child("reclaim_allocations_child", None);
        assert!(text.contains("allocations: touch 0, fill 0"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_reclaim_allocates_nothing in a process of its own"]
    fn reclaim_allocations_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 3 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        let discard_even = |chunk: u64| {
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((mem + chunk * CHUNK + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
        };
        discard_even(0);
        discard_even(1);
        // A call in flight on the first chunk, for 200 ms.
        let held = std::sync::Arc::new(AtomicBool::new(false));
        let caller = {
            let held = held.clone();
            std::thread::spawn(move || {
                #[allow(clippy::cast_possible_truncation)]
                let call = crate::windows_mm::copying(mem as usize, PAGE as usize);
                held.store(true, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(200));
                drop(call);
            })
        };
        while !held.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        let (touch, r) = allocations_of(|| reclaim_at_touch(PAGE as usize));
        caller.join().unwrap();
        assert_eq!(r.chunks, 2, "the touch's reclaim moved {r:?}");
        discard_even(2);
        let (fill, r) = allocations_of(|| {
            let _lock = lock();
            reclaim_for_a_fill(PAGE as usize)
        });
        assert_eq!(r.chunks, 1, "the fill's reclaim moved {r:?}");
        std::println!("allocations: touch {touch}, fill {fill}");
        assert_eq!((touch, fill), (0, 0));
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The userfaultfd released at the job's limit allocates nothing: its
    /// serve thread, from the close of the user end through `destroy`
    /// (the missing pages made ordinary memory: lazy where never filled,
    /// zeroed at their next access where discarded, the alias given up),
    /// runs where a heap that must grow is refused, and where ntdll's heap
    /// code took a stack page the job refused (STACK137FRAMES: `destroy`
    /// growing a list of the missing runs, `RtlReAllocateHeap`); Linux's
    /// release of a userfaultfd needs no memory: it clears each vma's flags
    /// in place, a merge with the vma before (which may allocate) only tried
    /// (v6.1 fs/userfaultfd.c `userfaultfd_release`, 885-899). In a job of
    /// its own, with no room left ([`no_room_left`]).
    #[test]
    fn test_a_userfaultfd_released_at_the_limit_allocates_nothing() {
        let (code, text) = run_child("release_allocations_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        assert!(text.contains("ALLOCS the release at the limit: the serve thread 0 allocations"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_userfaultfd_released_at_the_limit_allocates_nothing and test_what_the_limit_paths_allocate_on_record in a job of their own"]
    fn release_allocations_child() {
        let (ctx, user, _mem, _done) = fill_to_the_limit_and_discard_in_part();
        let held = no_room_left();
        count_the_kinds();
        // SAFETY: closes the user end: the serve thread releases the
        // userfaultfd and ends.
        unsafe { ws::closesocket(sock(user)) };
        // `destroy` gives up the kernel end last. A bound for a failure only.
        let t = std::time::Instant::now();
        while CTXS[ctx].fd.load(Ordering::SeqCst) >= 0 {
            assert!(t.elapsed() < std::time::Duration::from_secs(60), "the userfaultfd was not released");
            std::thread::yield_now();
        }
        let counts = counted_kinds();
        say_the_allocations("the release at the limit", &counts);
        drop(held);
    }

    /// ALLOCS, on record: what the paths that run after the job's limit
    /// refused allocate, on each thread they run on: a fill refused and
    /// reclaimed for, then refused with `ENOMEM` (the caller's `copy` and
    /// the reclaimer); a first touch of lazy memory refused and reclaimed
    /// for (the touching thread, in the exception handler, and the
    /// reclaimer); the userfaultfd's release (its serve thread). With the
    /// first allocations' return addresses (ALLOCSITE), for a debugger to
    /// name. Each in a job of its own with no room left; a child that ends
    /// at the limit (a heap or a stack refused) is on record with its end.
    #[test]
    #[ignore = "a record: ALLOCS"]
    fn test_what_the_limit_paths_allocate_on_record() {
        for child in ["fill_allocations_child", "touch_allocations_child", "release_allocations_child"] {
            let (code, text) = run_child(child, Some(96 << 20));
            // Every line of the child's, its end included: a path that
            // allocates at the limit may end the process there.
            for line in text.lines() {
                std::println!("{child}: {line}");
            }
            std::println!("{child}: exit {code:?}");
            assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        }
    }

    #[test]
    #[ignore = "run by test_what_the_limit_paths_allocate_on_record in a job of its own"]
    fn fill_allocations_child() {
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let page = std::vec![0x5au8; PAGE as usize];
        let held = no_room_left();
        KIND.with(|k| k.set(CALLER));
        count_the_kinds();
        let (mut n, mut refused) = (0, None);
        while n < 16 << 20 {
            // SAFETY: `page` holds a page.
            match unsafe { copy(ctx, page.as_ptr(), mem + done + n, PAGE, false) } {
                Ok(k) => n += k,
                Err((e, _)) => {
                    refused = Some(e);
                    break;
                }
            }
        }
        let counts = counted_kinds();
        KIND.with(|k| k.set(0));
        say_the_allocations("fills at the limit", &counts);
        crate::windows_mm::say_at_the_limit(format_args!("filled {} KiB, then {:?}", n >> 10, refused));
        assert_eq!(refused, Some(crate::ENOMEM));
        drop(held);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    #[test]
    #[ignore = "run by test_what_the_limit_paths_allocate_on_record in a job of its own"]
    fn touch_allocations_child() {
        let (_ctx, user, _mem, _) = fill_to_the_limit_and_discard_in_part();
        // SAFETY: a new anonymous mapping, committed at first touch.
        let lazy = unsafe {
            crate::mmap(
                ptr::null_mut(),
                16 << 20,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, crate::MAP_FAILED);
        let held = no_room_left();
        KIND.with(|k| k.set(CALLER));
        count_the_kinds();
        for p in (0..4usize << 20).step_by(PAGE as usize) {
            // SAFETY: our mapping; the first touch commits the page.
            unsafe { core::ptr::write_volatile((lazy as *mut u8).add(p), 1) };
        }
        let counts = counted_kinds();
        KIND.with(|k| k.set(0));
        say_the_allocations("touches at the limit", &counts);
        drop(held);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Closes the user end of `ctx` and waits until its serve thread has
    /// released it (`destroy` gives up the kernel end last). A bound for a
    /// failure only.
    fn release(ctx: usize, user: c_int) {
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let t = std::time::Instant::now();
        while CTXS[ctx].fd.load(Ordering::SeqCst) >= 0 {
            assert!(t.elapsed() < std::time::Duration::from_secs(60), "the userfaultfd was not released");
            std::thread::yield_now();
        }
    }

    /// A range of four pages registered, its page 0 filled, page 1 filled
    /// and discarded, pages 2 and 3 never filled: released, so that page 1
    /// is a discarded page to zero at its first access and pages 2 and 3
    /// are lazy. Its address.
    fn released_with_pending_pages(fill: u8) -> u64 {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map(4 * PAGE as usize);
        register(ctx, mem, 4 * PAGE).unwrap();
        let data = std::vec![fill; 2 * PAGE as usize];
        // SAFETY: `data` holds two pages.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, 2 * PAGE, true) }.unwrap(), 2 * PAGE);
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        release(ctx, user);
        mem
    }

    /// A page discarded while registered reads zeros once its userfaultfd is
    /// released, all of it, at every read, and takes a write; a page never
    /// filled reads zeros and takes a write; a filled page keeps its data;
    /// as Linux's released range, whose zapped and never-faulted pages are
    /// anonymous memory's zero-filled pages (a control for the released
    /// ranges' records, design-released-ranges.md).
    #[test]
    fn test_a_stale_page_read_after_release_reads_zeros() {
        let mem = released_with_pending_pages(0x5a);
        // SAFETY: our mapping, released: ordinary memory.
        unsafe {
            for _ in 0..2 {
                assert!(std::slice::from_raw_parts((mem + PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "the discarded page");
                assert!(std::slice::from_raw_parts((mem + 2 * PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "a page never filled");
            }
            assert_eq!(*((mem + 9) as *const u8), 0x5a, "the filled page");
            *((mem + PAGE + 9) as *mut u8) = 7;
            *((mem + 3 * PAGE + 9) as *mut u8) = 8;
            assert_eq!((*((mem + PAGE + 9) as *const u8), *((mem + 3 * PAGE + 9) as *const u8)), (7, 8));
        }
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
    }

    /// A fixed mapping over a released range while a first access resolves
    /// its discarded page waits for the resolve: the view stays until the
    /// page is zeroed and given its protection (the resolve holds the
    /// records' lock from its check that the page is committed, and a view
    /// leaves the records before it goes), so the resolve's protection
    /// change cannot be refused for a view gone under it, which left the
    /// page charged, zeroed and still pending; the new mapping reads zeros,
    /// as Linux's fault and `mmap` serialise on the mm's lock. The resolve
    /// is parked after zeroing the page, for the mapping to come while it
    /// is (`windows_mm::resolve_pause_arm`). In a process of its own (the
    /// park is the process's).
    #[test]
    #[ignore = "until a view leaves the released ranges' records before it goes"]
    fn test_a_fixed_mapping_over_a_page_being_resolved_waits_for_it() {
        let (code, text) = run_child("resolve_under_a_fixed_mapping_child", None);
        assert!(text.contains("RESOLVE the view while parked: committed"), "{text}");
        assert!(text.contains("RESOLVE access: Committed"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fixed_mapping_over_a_page_being_resolved_waits_for_it in a process of its own"]
    fn resolve_under_a_fixed_mapping_child() {
        let mem = released_with_pending_pages(0x5a);
        let page = (mem + PAGE) as usize;
        crate::windows_mm::resolve_pause_arm();
        let resolver = std::thread::spawn(move || crate::windows_mm::wick_mm::commit_on_access(page, false));
        let t = std::time::Instant::now();
        while !crate::windows_mm::resolve_parked() {
            assert!(t.elapsed() < std::time::Duration::from_secs(10), "the resolve did not park");
            std::thread::yield_now();
        }
        let mapper = std::thread::spawn(move || {
            // SAFETY: a fixed anonymous mapping over our released range.
            let p = unsafe {
                crate::mmap(
                    mem as *mut c_void,
                    4 * PAGE as usize,
                    crate::PROT_READ | crate::PROT_WRITE,
                    crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED,
                    -1,
                    0,
                )
            };
            p as u64
        });
        // The mapping's time to unmap the view, were it not to wait.
        std::thread::sleep(std::time::Duration::from_millis(300));
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe { windows_sys::Win32::System::Memory::VirtualQuery(page as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) };
        let view = if mbi.State == windows_sys::Win32::System::Memory::MEM_COMMIT { "committed" } else { "gone" };
        std::println!("RESOLVE the view while parked: {view} (state {:#x})", mbi.State);
        crate::windows_mm::resolve_go();
        let access = resolver.join().unwrap();
        std::println!("RESOLVE access: {access:?}");
        assert_eq!(mapper.join().unwrap(), mem, "the fixed mapping");
        // SAFETY: the new mapping, ours.
        assert!(unsafe { std::slice::from_raw_parts(page as *const u8, PAGE as usize) }.iter().all(|&b| b == 0));
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
    }

    /// A poisoned lock on the path of a first access (here the released
    /// ranges' records', poisoned by a thread that panicked holding it) ends
    /// the process with a line naming it and an abort (0xC0000409), never a
    /// panic inside the exception's dispatch: the access is resolved in the
    /// vectored handler, which cannot unwind. A bug's end, named. In a
    /// process of its own.
    #[test]
    #[ignore = "until a poisoned lock ends the process, named"]
    fn test_a_poisoned_lock_on_the_access_path_aborts_named() {
        let (code, text) = run_child("poisoned_access_child", None);
        assert!(text.contains("wick: the lock RELEASED was poisoned"), "{text}");
        assert!(!text.contains("reached the page"), "{text}");
        assert_eq!(code, Some(0xC000_0409_u32.cast_signed()), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_poisoned_lock_on_the_access_path_aborts_named in a process of its own"]
    fn poisoned_access_child() {
        let mem = released_with_pending_pages(0x5a);
        crate::windows_mm::poison_released();
        // SAFETY: our mapping, released: its discarded page is resolved at
        // this first read.
        let b = unsafe { core::ptr::read_volatile((mem + PAGE) as *const u8) };
        std::println!("reached the page: {b}");
    }

    /// Two threads touching one page of a released range at once, each
    /// writing at its own offset, both keep their writes: the page is
    /// resolved once (a discarded page zeroed once, a page never filled
    /// committed once), as Linux faults a page in once under its page table
    /// lock. For the discarded page and for a page never filled, 200 rounds
    /// each (a control for the released ranges' records).
    #[test]
    fn test_a_page_touched_by_two_threads_after_release_keeps_both_writes() {
        for round in 0..200u32 {
            let mem = released_with_pending_pages(0x5a);
            for page in [1u64, 2] {
                let at = mem + page * PAGE;
                let go = std::sync::Arc::new(std::sync::Barrier::new(2));
                let threads: std::vec::Vec<_> = [(0u64, 0x11u8), (8, 0x22)]
                    .into_iter()
                    .map(|(off, v)| {
                        let go = go.clone();
                        std::thread::spawn(move || {
                            go.wait();
                            // SAFETY: our mapping, released.
                            unsafe { core::ptr::write_volatile((at + off) as *mut u8, v) };
                        })
                    })
                    .collect();
                for t in threads {
                    t.join().expect("a toucher failed");
                }
                // SAFETY: as above.
                let got = unsafe { (*(at as *const u8), *((at + 8) as *const u8)) };
                assert_eq!(got, (0x11, 0x22), "round {round}, page {page}: a write was lost");
            }
            // SAFETY: our mapping.
            assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
        }
    }

    /// An unregister of part of a range leaves that part's discarded and
    /// never-filled pages as released ones (zeros at their first access,
    /// then ordinary memory) and the rest registered: its missing pages
    /// still missing and filled through the userfaultfd (a control for the
    /// released ranges' records).
    #[test]
    fn test_a_partial_unregister_keeps_its_pages_pending() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 12 * PAGE;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; 8 * PAGE as usize];
        // SAFETY: `data` holds eight pages.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, 8 * PAGE, true) }.unwrap(), 8 * PAGE);
        for page in [2u64, 5] {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + page * PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        // Pages 4 to 9: 4 filled, 5 discarded, 6 and 7 filled, 8 and 9 never filled.
        unregister(ctx, mem + 4 * PAGE, 6 * PAGE).unwrap();
        // SAFETY: the unregistered part: ordinary memory.
        unsafe {
            assert_eq!(*((mem + 4 * PAGE) as *const u8), 0x5a);
            assert!(std::slice::from_raw_parts((mem + 5 * PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "the discarded page");
            assert!(std::slice::from_raw_parts((mem + 8 * PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "a page never filled");
            *((mem + 9 * PAGE) as *mut u8) = 3;
            assert_eq!(*((mem + 9 * PAGE) as *const u8), 3);
        }
        // The rest is still registered: page 2 and pages 10 and 11 missing.
        assert!(is_missing(mem + 2 * PAGE) && is_missing(mem + 10 * PAGE) && is_missing(mem + 11 * PAGE));
        assert!(!is_missing(mem + 5 * PAGE) && !is_missing(mem + 8 * PAGE));
        let seven = std::vec![7u8; PAGE as usize];
        // SAFETY: a page-sized buffer.
        assert_eq!(unsafe { copy(ctx, seven.as_ptr(), mem + 10 * PAGE, PAGE, true) }.unwrap(), PAGE);
        // SAFETY: a filled page.
        assert_eq!(unsafe { *((mem + 10 * PAGE + 9) as *const u8) }, 7);
        release(ctx, user);
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, len as usize) }, 0);
    }

    /// Ranges registered and released while other threads touch the pending
    /// pages of those released before: records freed and taken again under
    /// touching threads (design-released-ranges.md, the reader protocol).
    /// One thread makes 200 ranges of 4 pages (`released_with_pending_pages`,
    /// filled with the round's byte) and unmaps the one of two rounds
    /// before; four threads touch the pending pages of the ranges still
    /// mapped, each its own pages, and check that a page reads zeros before
    /// their write and their write after it; the filled pages keep their
    /// round's byte. In a process of its own (the slots and records are
    /// the process's).
    #[test]
    fn test_released_records_reused_under_touching_threads() {
        let (code, text) = run_child("released_reuse_child", None);
        assert!(text.contains("REUSE 200 rounds"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_released_records_reused_under_touching_threads in a process of its own"]
    fn released_reuse_child() {
        // The ranges still mapped: (address, round), and whether the maker is done.
        let mapped = std::sync::Arc::new(std::sync::RwLock::new(std::vec::Vec::<(u64, u8)>::new()));
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let touchers: std::vec::Vec<_> = (0..4u64)
            .map(|me| {
                let (mapped, done) = (mapped.clone(), done.clone());
                std::thread::spawn(move || {
                    let mut touched = std::collections::BTreeSet::new();
                    while !done.load(Ordering::SeqCst) {
                        let ranges = mapped.read().unwrap();
                        for &(mem, round) in ranges.iter() {
                            // Pages 1 to 3 are pending; each toucher writes
                            // its own byte of them, at offset 64 * me.
                            for page in 1..4u64 {
                                let at = mem + page * PAGE + 64 * me;
                                // SAFETY: a mapped page of a released range.
                                unsafe {
                                    // By range too: a new range may be mapped where an old one was.
                                    if touched.insert((at, round)) {
                                        assert_eq!(core::ptr::read_volatile(at as *const u8), 0, "a pending page was not zeros");
                                        core::ptr::write_volatile(at as *mut u8, round);
                                    }
                                    assert_eq!(core::ptr::read_volatile(at as *const u8), round, "a write was lost");
                                }
                            }
                        }
                        drop(ranges);
                        std::thread::yield_now();
                    }
                })
            })
            .collect();
        for round in 0..200u32 {
            #[allow(clippy::cast_possible_truncation)]
            let fill = (round % 250 + 1) as u8;
            let mem = released_with_pending_pages(fill);
            let mut ranges = mapped.write().unwrap();
            ranges.push((mem, fill));
            if ranges.len() > 2 {
                let (old, old_fill) = ranges.remove(0);
                // SAFETY: a filled page of ours.
                assert_eq!(unsafe { *(old as *const u8) }, old_fill, "a filled page changed");
                // SAFETY: our mapping, which no toucher reads now.
                assert_eq!(unsafe { crate::munmap(old as *mut c_void, 4 * PAGE as usize) }, 0);
            }
        }
        done.store(true, Ordering::SeqCst);
        for t in touchers {
            t.join().expect("a toucher failed");
        }
        std::println!("REUSE 200 rounds");
    }

    /// The released ranges' records are as many as the slots, one taken at
    /// each register and held until the registration is released and its
    /// memory unmapped (design-released-ranges.md): with 64 ranges released
    /// and still mapped, a 65th register is refused with `ENOMEM` and
    /// changes nothing, as Linux refuses a register whose vma
    /// split would pass `vm.max_map_count` (mm/mmap.c `split_vma`); their
    /// pages read as before. In a process of its own.
    #[test]
    fn test_released_records_past_the_table_refuse_a_register() {
        let (code, text) = run_child("released_table_child", None);
        assert!(text.contains("TABLE the 65th register: ENOMEM"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    /// A record is freed when the last of its released range is unmapped:
    /// with the table full, an unmap of half of one released range (its
    /// discarded page) keeps the record, and the register is still refused;
    /// an unmap of the rest frees it, and the register is made. In a process
    /// of its own.
    #[test]
    fn test_release_then_munmap_frees_the_record() {
        let (code, text) = run_child("released_table_child", None);
        assert!(text.contains("TABLE after half unmapped: ENOMEM"), "{text}");
        assert!(text.contains("TABLE after the rest unmapped: registered"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_released_records_past_the_table_refuse_a_register and test_release_then_munmap_frees_the_record in a process of its own"]
    fn released_table_child() {
        let held: std::vec::Vec<u64> = (0..MAX_RANGES).map(|_| released_with_pending_pages(0x5a)).collect();
        let try_one = |what: &str| {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map(4 * PAGE as usize);
            let r = register(ctx, mem, 4 * PAGE);
            let said = match &r {
                Ok(()) => "registered".into(),
                Err(e) if e.raw_os_error() == Some(crate::ENOMEM) => "ENOMEM".into(),
                Err(e) => std::format!("{e}"),
            };
            std::println!("TABLE {what}: {said}");
            release(ctx, user);
            // SAFETY: our mapping.
            assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
        };
        try_one("the 65th register");
        // Nothing changed: each range's pages read as they did.
        for &mem in &held[1..] {
            // SAFETY: our mappings, released.
            unsafe {
                assert_eq!(*((mem + 9) as *const u8), 0x5a);
                assert_eq!(*((mem + PAGE + 9) as *const u8), 0);
            }
        }
        // SAFETY: our mapping: pages 0 and 1 (the discarded one) of the first.
        assert_eq!(unsafe { crate::munmap(held[0] as *mut c_void, 2 * PAGE as usize) }, 0);
        try_one("after half unmapped");
        // SAFETY: the rest of it.
        assert_eq!(unsafe { crate::munmap((held[0] + 2 * PAGE) as *mut c_void, 2 * PAGE as usize) }, 0);
        try_one("after the rest unmapped");
    }

    /// The jailer's count of this process (overlay/jailer/platform/windows
    /// commit.rs): private commit plus section commit less the committed,
    /// private, `PAGE_NOACCESS` memory that pays for sections (the cover),
    /// no more than the section commit.
    fn jailers_count() -> u64 {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, VirtualQuery};
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_faults: u32,
            sizes: [usize; 10],
            shared_commit: u64,
        }
        use windows_sys::Win32::System::ProcessStatus::K32GetProcessMemoryInfo;
        let mut c = Counters { cb: u32::try_from(std::mem::size_of::<Counters>()).unwrap(), ..Counters::default() };
        // SAFETY: this process's pseudo handle and a structure of the size
        // given (PROCESS_MEMORY_COUNTERS_EX2, which begins as the type the
        // binding names).
        assert_ne!(unsafe { K32GetProcessMemoryInfo(windows_sys::Win32::System::Threading::GetCurrentProcess(), (&raw mut c).cast(), c.cb) }, 0);
        let (private, shared) = (c.sizes[8] as u64, c.shared_commit);
        let (mut at, mut cover) = (0usize, 0u64);
        loop {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { VirtualQuery(at as *const c_void, &mut m, std::mem::size_of_val(&m)) } == 0 {
                break;
            }
            if m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && m.Protect == PAGE_NOACCESS {
                cover += m.RegionSize as u64;
            }
            match (m.BaseAddress as usize).checked_add(m.RegionSize) {
                Some(next) if next > at => at = next,
                _ => break,
            }
        }
        private + shared - cover.min(shared)
    }

    /// The jailer's count taken in the middle of a move
    /// (`windows_mm::MOVE_HOOK`, between the copy and the swap).
    static DURING: AtomicU64 = AtomicU64::new(u64::MAX);

    fn count_during_the_move() {
        DURING.store(jailers_count(), Ordering::SeqCst);
    }

    /// While a chunk is moved both sections hold its live pages; the move
    /// budget, committed private `PAGE_NOACCESS` memory made at the first
    /// registration (`windows_mm::uffd_budget`), is cover for them, so the
    /// jailer's count, taken in the middle of the move, is no higher than
    /// before it, and a VMM at its limit is not ended for a reclaim. Without
    /// the budget block (decommitted for the test) the same move raises the
    /// count by its live pages: the budget is what holds it.
    /// With no room left in the job at each move ([`no_room_left`]), where
    /// the move gives back 12 KiB of its dead pages' charge before its maps
    /// (`windows_mm::MOVE_ROOM`; a charge page is private commit and cover,
    /// so the count falls by it, and the maps' page tables, 4 KiB a view,
    /// take back part): the count during the move is below what it was
    /// before by no more than that (64 KiB allowed, against the 1 MiB of
    /// dead pages the chunk holds: it never counts a chunk's dead pages as
    /// gone before they are). The count needs `PROCESS_MEMORY_COUNTERS_EX2`'s
    /// `SharedCommitUsage` (Windows 10 or 11 22H2 with the September 2023
    /// update and later): on a host without it the jailer refuses
    /// memory.max (`test_a_memory_limit_on_this_host`), and the child says
    /// so and fails, naming the build and where the test runs.
    #[test]
    fn test_the_jailers_count_does_not_rise_during_a_move() {
        let (code, text) = run_child("move_count_child", Some(256 << 20));
        assert!(text.contains("with the budget: "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_jailers_count_does_not_rise_during_a_move in a process of its own"]
    fn move_count_child() {
        {
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE, SEC_COMMIT};
            let before = jailers_count();
            // SAFETY: a new pagefile-backed section of 1 MiB, closed below.
            let s = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | SEC_COMMIT, 0, 1 << 20, ptr::null()) };
            assert!(!s.is_null());
            let with = jailers_count();
            // SAFETY: ours.
            unsafe { CloseHandle(s) };
            if with < before + (1 << 20) {
                use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
                use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
                // SAFETY: an all-zero OSVERSIONINFOW with its size is valid.
                let mut vi: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
                vi.dwOSVersionInfoSize = u32::try_from(std::mem::size_of::<OSVERSIONINFOW>()).unwrap();
                // SAFETY: plain call.
                unsafe { RtlGetVersion(&mut vi) };
                panic!(
                    "not a regression: this host, Windows {}.{}.{}, cannot run this test: its SharedCommitUsage does not \
                     move with a section (a 1 MiB section moved the count from {before} to {with}). \
                     PROCESS_MEMORY_COUNTERS_EX2's SharedCommitUsage is in Windows 10 and 11 22H2 with the September 2023 \
                     update and later (Learn); measured in CI's Windows Server 2025 (26100) and the PC's Windows 11, absent \
                     in Windows Server 2022 (20348, fc-win). Here the jailer refuses memory.max, named \
                     (test_a_memory_limit_on_this_host), so its count during a move cannot be read; this test runs in CI \
                     and on the PC",
                    vi.dwMajorVersion,
                    vi.dwMinorVersion,
                    vi.dwBuildNumber
                );
            }
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        *crate::windows_mm::MOVE_HOOK.lock().unwrap() = Some(count_during_the_move);
        let moved = |budget: bool| -> (u64, u64) {
            assert!(crate::windows_mm::uffd_budget_for_tests(budget), "no move budget was made");
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
            DURING.store(u64::MAX, Ordering::SeqCst);
            let mut held = no_room_left();
            let before = jailers_count();
            let r = reclaim_at_touch(PAGE as usize);
            let during = DURING.load(Ordering::SeqCst);
            give_back_every_page(&mut held);
            assert_eq!(r.chunks, 1, "no chunk was moved");
            assert_ne!(during, u64::MAX, "the move's hook did not run");
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                assert_eq!(zeropage(ctx, mem + p, PAGE, true).unwrap(), PAGE);
            }
            (before, during)
        };
        let (before, during) = moved(true);
        std::println!("with the budget: {before} before the move, {during} during it");
        assert!(during <= before + (64 << 10), "the count rose by {} KiB during a move", (during - before) >> 10);
        assert!(during + (64 << 10) >= before, "the count fell by {} KiB during a move, before the dead pages went", (before - during) >> 10);
        let (before, during) = moved(false);
        std::println!("without it: {before} before the move, {during} during it");
        assert!(during >= before + (512 << 10), "without the budget the count rose by {} KiB only", during.saturating_sub(before) >> 10);
        assert!(crate::windows_mm::uffd_budget_for_tests(true));
        *crate::windows_mm::MOVE_HOOK.lock().unwrap() = None;
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// RECLAIMREC: the reclaim's cost at the job's limit (it runs only
    /// there). In a child under a job limit of 96 MiB: the range filled to
    /// the limit and every other page of its first 8 chunks discarded
    /// ([`fill_to_the_limit_and_discard_in_part`]), then 8 MiB filled a
    /// page at a time while a host thread reads the 8 chunks' live pages:
    /// the chunks moved, the live pages each copied and its microseconds
    /// (least, median, greatest), the reader's accesses that waited for a
    /// move and their time, and the job's commit (the process's private
    /// commit) and section commit before and after. Printed; asserted only
    /// that the fill went on.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture (CI's WHP step)"]
    fn test_the_reclaims_cost_on_record() {
        let (code, text) = run_child("reclaim_record_child", Some(96 << 20));
        for line in text.lines().filter(|l| l.starts_with("RECLAIMREC")) {
            std::println!("{line}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_reclaims_cost_on_record in a job of its own"]
    fn reclaim_record_child() {
        use windows_sys::Win32::System::ProcessStatus::K32GetProcessMemoryInfo;
        // The locks as the product takes them: the watch's paint is no
        // part of the reclaim's time.
        crate::windows_stacklock::WATCHING.store(false, Ordering::SeqCst);
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_faults: u32,
            sizes: [usize; 10],
            shared_commit: u64,
        }
        let counts = || {
            let mut c = Counters { cb: u32::try_from(std::mem::size_of::<Counters>()).unwrap(), ..Counters::default() };
            // SAFETY: this process's pseudo handle and a structure of the
            // size given (PROCESS_MEMORY_COUNTERS_EX2).
            unsafe { K32GetProcessMemoryInfo(windows_sys::Win32::System::Threading::GetCurrentProcess(), (&raw mut c).cast(), c.cb) };
            (c.sizes[8] >> 10, c.shared_commit >> 10)
        };
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let before = counts();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut reads = 0u64;
                while !stop.load(Ordering::Acquire) {
                    for p in (PAGE..8 * CHUNK).step_by(2 * PAGE as usize) {
                        // SAFETY: a live page of the registered range.
                        assert_eq!(unsafe { core::ptr::read_volatile((mem + p) as *const u8) }, 0x5a);
                        reads += 1;
                    }
                }
                reads
            })
        };
        let page = std::vec![0x5au8; PAGE as usize];
        let held = no_room_left();
        let mut more = 0;
        while more < 8 << 20 {
            // SAFETY: `page` holds a page.
            match unsafe { copy(ctx, page.as_ptr(), mem + done + more, PAGE, false) } {
                Ok(n) => more += n,
                Err(_) => break,
            }
        }
        stop.store(true, Ordering::Release);
        let reads = reader.join().unwrap();
        drop(held);
        let after = counts();
        let (moves, waits, waited) = moves_on_record();
        let mut us: Vec<u64> = moves.iter().map(|m| m.1).collect();
        us.sort_unstable();
        let copied: usize = moves.iter().map(|m| m.0).sum();
        std::println!(
            "RECLAIMREC {} chunks moved, {copied} live pages copied, {} us a chunk least, {} median, {} greatest",
            moves.len(),
            us.first().copied().unwrap_or(0),
            us.get(us.len() / 2).copied().unwrap_or(0),
            us.last().copied().unwrap_or(0)
        );
        std::println!("RECLAIMREC filled {} KiB past the limit; the reader's {reads} reads, {waits} of which waited for a move, {waited} us in all", more >> 10);
        std::println!(
            "RECLAIMREC private commit {} KiB before, {} KiB after; section commit {} KiB before, {} KiB after",
            before.0, after.0, before.1, after.1
        );
        assert!(more >= 4 << 20, "{} KiB filled past the limit", more >> 10);
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

    /// A discard (`MADV_DONTNEED`) of a read's buffer, made by another
    /// thread after the read faulted the buffer in and before its system
    /// call, waits for the read, as Linux's read completes into a page its
    /// copy faults in again (mm/userfaultfd.c `handle_userfault`): a
    /// regular file's read, whose call cannot block for ever, is counted in
    /// flight on its range, and the discard waits for it. The window is
    /// [`crate::windows_fd::BEFORE_CALL`]: it starts the discard and gives it
    /// 50 ms. Asserted: the discard is still waiting at the window's end, the
    /// read returns its 16 bytes, and the discard then leaves the pages
    /// missing again.
    #[test]
    fn test_a_discard_waits_for_a_read_in_flight_on_its_range() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        let handler = std::thread::spawn(move || serve_one(user, ctx, 0x11));
        let path = std::env::temp_dir().join(std::format!("wick-uffd-inflight-{}", std::process::id()));
        std::fs::write(&path, [0x22u8; 16]).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let fd = crate::windows_fd::to_fd_pub(std::os::windows::io::AsRawHandle::as_raw_handle(&f));
        let (go, went) = mpsc::channel::<()>();
        let done = Arc::new(AtomicBool::new(false));
        let ended = done.clone();
        let discarder = std::thread::spawn(move || {
            went.recv().unwrap();
            // SAFETY: the test's registered mapping.
            let r = unsafe { crate::madvise(mem as *mut c_void, len, crate::MADV_DONTNEED) };
            ended.store(true, Ordering::Release);
            r
        });
        let held = Arc::new(AtomicBool::new(false));
        let seen = held.clone();
        crate::windows_fd::BEFORE_CALL.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                go.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(50));
                seen.store(!done.load(Ordering::Acquire), Ordering::Release);
            }));
        });
        // SAFETY: a valid descriptor and registered memory.
        let n = unsafe { crate::read(fd, (mem + 8) as *mut c_void, 16) };
        let error = std::io::Error::last_os_error();
        crate::windows_fd::BEFORE_CALL.with(|h| *h.borrow_mut() = None);
        let discarded = discarder.join().unwrap();
        let held = held.load(Ordering::Acquire);
        std::println!(
            "INFLIGHT a file's read with a discard of its buffer started in its window: {n} ({error}); \
             the discard waiting at the window's end: {held}; the discard: {discarded}"
        );
        assert_eq!(handler.join().unwrap()[0], proto::EVENT_PAGEFAULT);
        assert!(held, "the discard did not wait for the read in flight");
        assert_eq!(n, 16, "the read failed: {error}");
        assert_eq!(discarded, 0);
        assert!(is_missing(mem + 8), "the discard did not happen");
        drop(f);
        let _ = std::fs::remove_file(&path);
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A read that can block for ever (a blocking pipe's) is not counted in
    /// flight, so that a discard never waits on it, and reads through a
    /// buffer of its own, copied into the caller's afterwards as a guest
    /// access is made, so that a discard of the caller's buffer meanwhile
    /// cannot fail it, as Linux's copy faults the page in again. The
    /// window ([`crate::windows_fd::BEFORE_CALL`]) starts the discard and
    /// waits until it is done, at most 2 s; the pipe's writer writes 100 ms
    /// later. Asserted: the discard ended in the window, and the read returns
    /// the writer's 16 bytes, which the buffer then holds (its page faulted
    /// in before the call, discarded, faulted in again at the copy, filled,
    /// and written over: two faults served).
    #[test]
    fn test_a_blocking_read_does_not_hold_a_discard() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        let handler = std::thread::spawn(move || [serve_one(user, ctx, 0x11), serve_one(user, ctx, 0x11)]);
        let mut fds = [0 as c_int; 2];
        // SAFETY: two descriptors' room.
        assert_eq!(unsafe { crate::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        let (go, went) = mpsc::channel::<()>();
        let (done, discarded) = mpsc::channel::<c_int>();
        std::thread::spawn(move || {
            went.recv().unwrap();
            // SAFETY: the test's registered mapping.
            let r = unsafe { crate::madvise(mem as *mut c_void, len, crate::MADV_DONTNEED) };
            let _ = done.send(r);
        });
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let data = [0x33u8; 16];
            // SAFETY: the pipe's write end and a buffer of 16 bytes.
            unsafe { crate::write(wr, data.as_ptr().cast(), 16) }
        });
        let in_window = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen = in_window.clone();
        crate::windows_fd::BEFORE_CALL.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                go.send(()).unwrap();
                *seen.lock().unwrap() = Some(discarded.recv_timeout(Duration::from_secs(2)).ok());
            }));
        });
        // SAFETY: the pipe's read end and registered memory.
        let n = unsafe { crate::read(rd, (mem + 8) as *mut c_void, 16) };
        let error = std::io::Error::last_os_error();
        crate::windows_fd::BEFORE_CALL.with(|h| *h.borrow_mut() = None);
        let window = *in_window.lock().unwrap();
        std::println!("INFLIGHT a blocking pipe's read with a discard of its buffer in its window: {n} ({error}); the discard in the window: {window:?}");
        assert_eq!(writer.join().unwrap(), 16);
        assert_eq!(window, Some(Some(0)), "the discard was held by a read that can block");
        assert_eq!(n, 16, "the read failed: {error}");
        let events = handler.join().unwrap();
        assert_eq!([events[0][0], events[1][0]], [proto::EVENT_PAGEFAULT; 2]);
        // SAFETY: read into, after the fill.
        unsafe {
            assert_eq!(*((mem + 8) as *const u8), 0x33);
            assert_eq!(*(mem as *const u8), 0x11, "the page was not filled again");
        }
        // SAFETY: the pipe's ends; closes the user end.
        unsafe {
            crate::close(rd);
            crate::close(wr);
            ws::closesocket(sock(user));
        }
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

    /// Set by the hooks of the two tests below and their threads.
    static HELD: AtomicBool = AtomicBool::new(false);
    static RELEASED: AtomicBool = AtomicBool::new(false);
    static READ_NOW: AtomicBool = AtomicBool::new(false);

    /// Waits, for up to 20 s, until `flag` is set.
    fn wait_for(flag: &AtomicBool, what: &str) {
        let t = std::time::Instant::now();
        while !flag.load(Ordering::SeqCst) {
            assert!(t.elapsed() < std::time::Duration::from_secs(20), "{what} did not happen");
            std::thread::yield_now();
        }
    }

    /// [`EXCEPTION_HOOK`]'s: says the handler is held and holds it until
    /// the test releases it.
    fn hold_the_handler() {
        HELD.store(true, Ordering::SeqCst);
        wait_for(&RELEASED, "the release of the handler");
    }

    /// A host thread's access that faulted on a missing page whose fill
    /// ends before the exception handler looks at the page (the thread
    /// preempted between the fault and the handler, or the handler slow):
    /// the access runs again and reads the fill, as Linux's fault, which
    /// finds the page present, returns and the access runs again. Before
    /// the fix the handler, finding the page not missing, passed the
    /// exception on and the process ended with an access violation. In a
    /// process of its own (the hook holds every access violation's
    /// handler).
    #[test]
    fn test_a_host_access_that_faulted_before_its_fill_runs_again() {
        let (code, text) = run_child("late_handler_fill_child", None);
        assert!(text.contains("read back 0xab"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_host_access_that_faulted_before_its_fill_runs_again in a process of its own"]
    fn late_handler_fill_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        assert!(is_missing(mem + PAGE));
        EXCEPTION_HOOK.store(hold_the_handler as fn() as usize, Ordering::SeqCst);
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read faults, and its handler
            // is held until the page is filled.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        wait_for(&HELD, "the reader's fault");
        let data = std::vec![0xabu8; PAGE as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + PAGE, PAGE, true) }.unwrap(), PAGE);
        assert!(!is_missing(mem + PAGE));
        RELEASED.store(true, Ordering::SeqCst);
        let got = reader.join().expect("the reader failed");
        EXCEPTION_HOOK.store(0, Ordering::SeqCst);
        std::println!("read back {got:#x}");
        assert_eq!(got, 0xab);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// [`windows_mm::MOVE_HOOK`]'s: lets the reader read the moving chunk
    /// and waits until its fault's handler is held.
    fn read_during_the_move() {
        READ_NOW.store(true, Ordering::SeqCst);
        wait_for(&HELD, "the reader's fault during the move");
    }

    /// The same for a live page of a chunk being moved: the access faults
    /// while the chunk is closed for the move and its handler looks once
    /// the move is over (not moving, not missing): the access runs again
    /// and reads the page's content. Before the fix the process ended
    /// with an access violation. In a process of its own.
    #[test]
    fn test_a_host_access_that_faulted_during_a_move_runs_again() {
        let (code, text) = run_child("late_handler_move_child", None);
        assert!(text.contains("read back 0x5a"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_host_access_that_faulted_during_a_move_runs_again in a process of its own"]
    fn late_handler_move_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        *crate::windows_mm::MOVE_HOOK.lock().unwrap() = Some(read_during_the_move);
        EXCEPTION_HOOK.store(hold_the_handler as fn() as usize, Ordering::SeqCst);
        let reader = std::thread::spawn(move || {
            wait_for(&READ_NOW, "the move");
            // SAFETY: a live page of the registered range, closed for the
            // move; the read faults, and its handler is held until the move
            // is over.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        let r = reclaim_at_touch(PAGE as usize);
        assert_eq!(r.chunks, 1, "no chunk was moved");
        assert!(!is_moving(mem + PAGE) && !is_missing(mem + PAGE));
        RELEASED.store(true, Ordering::SeqCst);
        let got = reader.join().expect("the reader failed");
        EXCEPTION_HOOK.store(0, Ordering::SeqCst);
        *crate::windows_mm::MOVE_HOOK.lock().unwrap() = None;
        std::println!("read back {got:#x}");
        assert_eq!(got, 0x5a);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }
}
