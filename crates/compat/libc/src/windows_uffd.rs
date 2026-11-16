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

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HANDLE};
use windows_sys::Win32::Networking::WinSock::{
    self as ws, AF_UNIX, INVALID_SOCKET, POLLERR, POLLHUP, POLLRDNORM, SOCKET, SOCKET_ERROR,
    SOCK_STREAM, WSAPOLLFD, WSAPROTOCOL_INFOW, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
};
use windows_sys::Win32::Storage::FileSystem::DeleteFileW;
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

/// Removes the socket path a dead process of this pid left at `path`,
/// before this process binds it (`bind` refuses a path that exists with
/// WSAEADDRINUSE: `test_af_unix_paths_and_abstract_addresses_on_record`).
/// Removing it cannot take anything live: the name carries this process's
/// pid, which no other live process has, and a sequence number this process
/// has not used yet (`socket_pair`'s only rises), so nothing of ours listens
/// there, and a file there was left by a dead process of this pid that was
/// killed between its bind and its removal of the path (cdb's quit left
/// `wick-uffd-3332-1.sock` on fc-win, and a later process with pid 3332 was
/// refused its userfaultfd). `DeleteFileW` deletes a symbolic link, not its
/// target (Learn, DeleteFileW: "If the path points to a symbolic link, the
/// symbolic link is deleted, not the target"), and removes no directory, so
/// whoever else may write in the temporary directory (the jail's `tmp`: the
/// jailed processes, the jailer, the user; unjailed, the user's processes)
/// cannot make it delete anything but this name. Microsoft's AF_UNIX
/// guidance asks the same: "DeleteFile (or any other file delete API) should
/// be used to delete the socket file prior to calling bind with the same
/// path" (devblogs.microsoft.com, "AF_UNIX comes to Windows"). A name that
/// is there and cannot be removed fails the userfaultfd, with a line naming
/// it; a second name is never tried in its place.
fn remove_left_path(path: &std::path::Path, wide: &[u16]) -> io::Result<()> {
    // SAFETY: a NUL-terminated path.
    if unsafe { DeleteFileW(wide.as_ptr()) } != 0 {
        std::eprintln!(
            "wick: userfaultfd: removed {}, a socket path a dead process of this pid left",
            path.display()
        );
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.cast_signed()) {
        return Ok(());
    }
    std::eprintln!(
        "wick: userfaultfd: the socket path {} could not be removed before its bind: {e}",
        path.display()
    );
    Err(e)
}

/// A connected pair of `AF_UNIX` stream sockets (Windows has no
/// `socketpair`): a listener on a temporary path, connected to. The path is
/// removed as soon as the connection is made, before it is accepted (a
/// queued connection is accepted without its path:
/// `test_af_unix_paths_and_abstract_addresses_on_record`), so it exists only
/// from the bind to the connect, and a process that dies in that window
/// leaves a path the next process of its pid removes (`remove_left_path`).
/// The accepted end must be this process's own connection: any writer of
/// the temporary directory may connect to the listener while its path
/// exists, and the first connection queued is the one accepted; an end
/// whose peer is another process fails the pair, loudly.
///
/// Not an abstract address (a NUL first in `sun_path`, no file): it has no
/// file and so no DACL, the one control Microsoft names for AF_UNIX ("can
/// be secured by controlling the file (or directory) permissions"), and no
/// namespace scopes it as a network namespace scopes Linux's; any process
/// that guessed the name could be the end accepted. (On 20348 such a bind
/// and listen worked and the connect was refused with WSAEINVAL, with the
/// length delimiting the name as on Linux: the same record.)
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
    let wide: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str().encode_wide().chain([0]).collect()
    };
    remove_left_path(&path, &wide)?;
    // Whether the path is removed already (at the connect).
    let mut removed = false;
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
        // The connection is queued on the listener; its path is no longer
        // needed.
        // SAFETY: a NUL-terminated path.
        removed = unsafe { DeleteFileW(wide.as_ptr()) } != 0;
        // SAFETY: accepts the connection just made.
        let b = unsafe { ws::accept(listener, ptr::null_mut(), ptr::null_mut()) };
        if b == INVALID_SOCKET {
            // SAFETY: plain call.
            let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
            close(a);
            return Err(e);
        }
        // The accepted end's peer: this process, whose connection it is.
        let (mut pid, mut n) = (0u32, 0u32);
        // SAFETY: a u32 out-buffer, on the socket accepted above.
        let asked = unsafe {
            ws::WSAIoctl(b, ws::SIO_AF_UNIX_GETPEERPID, ptr::null(), 0, (&raw mut pid).cast(), 4, &mut n, ptr::null_mut(), None)
        };
        if asked != 0 || pid != std::process::id() {
            let e = if asked != 0 {
                // SAFETY: plain call.
                io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
            } else {
                errno_err(crate::EPERM)
            };
            std::eprintln!(
                "wick: userfaultfd: the connection accepted on {} is not this process's (its peer: {}): {e}",
                path.display(),
                if asked != 0 { std::string::String::from("not known") } else { std::format!("pid {pid}") }
            );
            close(b);
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
    if !removed {
        // A pair not connected (or a path whose removal at the connect was
        // refused): removed now, as before.
        // SAFETY: a NUL-terminated path.
        unsafe { DeleteFileW(wide.as_ptr()) };
    }
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
            // Missing and inaccessible, so the read faults to the handler
            // (a page a call opened would read zeros, with no event to
            // serve: this test would wait for it instead of failing).
            assert!(is_missing(addr), "{addr:#x} is not missing");
            assert!(!host_readable(addr), "{addr:#x} is missing but accessible: a read would see zeros");
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

    /// The state and protection of the page at `addr` (`VirtualQuery`):
    /// `None` for a page not committed, else its protection.
    fn committed_protection(addr: u64) -> Option<u32> {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQuery};
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_ne!(unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
        (mbi.State == MEM_COMMIT).then_some(mbi.Protect)
    }

    /// Whether the host can read the page at `addr` without a fault: a
    /// committed page whose protection allows a read.
    fn host_readable(addr: u64) -> bool {
        matches!(committed_protection(addr), Some(p) if p == PAGE_READONLY || p == PAGE_READWRITE)
    }

    /// Registered memory of both kinds the backend has: an ordinary
    /// mapping (its missing pages `PAGE_NOACCESS`) and a `MAP_NORESERVE` one
    /// (a reserved section, its missing pages not committed), each with its
    /// userfaultfd; `f(kind, ctx, user, mem)` for each, 64 KiB registered.
    fn on_both_kinds(mut f: impl FnMut(&str, usize, c_int, u64)) {
        for (kind, mem) in [("ordinary", map(64 << 10)), ("reserved", map_noreserve(64 << 10))] {
            let (ctx, user) = create(0, false, true).unwrap();
            register(ctx, mem, 64 << 10).unwrap();
            f(kind, ctx, user, mem);
        }
    }

    /// The protection asked of a missing page is the one it has once
    /// filled: by a copy, by a zero page, and after a discard made it
    /// missing again and a copy filled it, as Linux's pages take their
    /// vma's protection (the macOS backend's test of the same name); while
    /// missing it stays inaccessible to the host, so an access is still a
    /// userfault.
    #[test]
    fn test_a_filled_page_takes_the_protection_asked_while_it_was_missing() {
        on_both_kinds(|kind, ctx, user, mem| {
            mprotect_of(mem, 2 * PAGE, crate::PROT_READ).unwrap();
            assert!(is_missing(mem) && !host_readable(mem), "{kind}: a missing page became accessible");
            let data = std::vec![0x5au8; PAGE as usize];
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}: copy");
            assert_eq!(zeropage(ctx, mem + PAGE, PAGE, true), Ok(PAGE));
            assert_eq!(committed_protection(mem + PAGE), Some(PAGE_READONLY), "{kind}: zeropage");
            // SAFETY: registered memory of the test's.
            assert_eq!(unsafe { crate::madvise(mem as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            assert!(is_missing(mem) && !host_readable(mem), "{kind}: discarded, the page is accessible");
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}: copy after a discard");
            // SAFETY: filled and readable.
            assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0x5a);
            release(ctx, user);
        });
    }

    /// A virtio-mem slot unplugged and plugged again after a restore through
    /// a userfaultfd, as Firecracker does it: a filled page made `PROT_NONE`
    /// (unplugged) or `PROT_READ`, then discarded (devices/virtio/mem
    /// `update_slot` before `discard_range`), then made read-write; the
    /// handler's next fill there lands, as on Linux, where the discard leaves
    /// the pages missing in their vma (the macOS backend's test of the same
    /// name, where the fill's alias had taken the page's protection and the
    /// process died by SIGBUS). Here the fill writes through the range's
    /// alias, a view of its own whose protection `mprotect` of the guest's
    /// view does not change; a fill made before the plug lands too and the
    /// page takes the protection asked.
    #[test]
    fn test_a_slot_unplugged_and_plugged_again_is_filled_through_its_alias() {
        for closed in [crate::PROT_NONE, crate::PROT_READ] {
            on_both_kinds(|kind, ctx, user, mem| {
                let data = std::vec![0x5au8; PAGE as usize];
                for p in 0..2 {
                    // SAFETY: `data` holds a page.
                    assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + p * PAGE, PAGE, true) }, Ok(PAGE));
                }
                mprotect_of(mem, 2 * PAGE, closed).unwrap();
                // SAFETY: registered memory of the test's.
                assert_eq!(unsafe { crate::madvise(mem as *mut c_void, 2 * PAGE as usize, crate::MADV_DONTNEED) }, 0);
                assert!(is_missing(mem) && is_missing(mem + PAGE), "{kind} {closed}: not missing after the discard");
                // The second page filled while still closed.
                let other = std::vec![0x6bu8; PAGE as usize];
                // SAFETY: `other` holds a page.
                assert_eq!(unsafe { copy(ctx, other.as_ptr(), mem + PAGE, PAGE, true) }, Ok(PAGE), "{kind} {closed}: a fill while closed");
                mprotect_of(mem, 2 * PAGE, crate::PROT_READ | crate::PROT_WRITE).unwrap();
                // SAFETY: `data` holds a page.
                assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, PAGE, true) }, Ok(PAGE), "{kind} {closed}: a fill after the plug");
                // SAFETY: filled just now, read-write.
                assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0x5a, "{kind} {closed}");
                // SAFETY: as above.
                assert_eq!(unsafe { core::ptr::read_volatile((mem + PAGE) as *const u8) }, 0x6b, "{kind} {closed}");
                assert_eq!(committed_protection(mem), Some(PAGE_READWRITE), "{kind} {closed}");
                assert_eq!(committed_protection(mem + PAGE), Some(PAGE_READWRITE), "{kind} {closed}");
                // SAFETY: filled and writable.
                unsafe { core::ptr::write_volatile((mem + PAGE) as *mut u8, 1) };
                release(ctx, user);
            });
        }
        // A whole chunk of a reserved section discarded: it gets a new
        // section, mapped anew in the guest's view and the alias
        // (`windows_mm::uffd_swap_chunk`).
        let chunk = crate::windows_mm::UFFD_CHUNK as u64;
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(2 * chunk as usize);
        register(ctx, mem, 2 * chunk).unwrap();
        let slot = mem + chunk;
        let data = std::vec![0x5au8; PAGE as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), slot, PAGE, true) }, Ok(PAGE));
        mprotect_of(slot, chunk, crate::PROT_NONE).unwrap();
        // SAFETY: registered memory of the test's.
        assert_eq!(unsafe { crate::madvise(slot as *mut c_void, chunk as usize, crate::MADV_DONTNEED) }, 0);
        assert!(is_missing(slot), "a discarded chunk's page is not missing");
        mprotect_of(slot, chunk, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), slot, PAGE, true) }, Ok(PAGE), "a fill after a whole chunk was discarded");
        // SAFETY: filled just now, read-write.
        assert_eq!(unsafe { core::ptr::read_volatile(slot as *const u8) }, 0x5a);
        assert_eq!(committed_protection(slot), Some(PAGE_READWRITE));
        release(ctx, user);
    }

    /// Unregistered, a missing page gets the protection asked of it, as a
    /// Linux page has its vma's once no userfaultfd has it (the macOS
    /// backend's test of the same name): in a reserved section at its first
    /// access, which a read-only page allows, reading zeros.
    #[test]
    fn test_an_unregistered_page_takes_the_protection_asked_while_it_was_missing() {
        on_both_kinds(|kind, ctx, user, mem| {
            mprotect_of(mem, PAGE, crate::PROT_READ).unwrap();
            assert!(!host_readable(mem), "{kind}: a missing page is accessible");
            assert_eq!(unregister(ctx, mem, 64 << 10), Ok(()));
            // SAFETY: unregistered memory the protection lets the host read.
            assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0, "{kind}");
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}");
            release(ctx, user);
        });
    }

    /// Released with its userfaultfd, a missing page gets the protection
    /// asked of it, as a Linux page has its vma's once the userfaultfd is
    /// gone (fs/userfaultfd.c `userfaultfd_release` clears each vma's
    /// userfaultfd flags only; the macOS backend's test of the same name).
    #[test]
    fn test_a_released_page_takes_the_protection_asked_while_it_was_missing() {
        on_both_kinds(|kind, ctx, user, mem| {
            mprotect_of(mem, PAGE, crate::PROT_READ).unwrap();
            assert!(!host_readable(mem), "{kind}: a missing page is accessible");
            release(ctx, user);
            // SAFETY: released memory the protection lets the host read.
            assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0, "{kind}");
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}");
        });
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

    /// The frames printed after the line of a stack that could not grow
    /// (STACK137FRAMES) name the module of each frame outside this
    /// executable with its offset in it: the exception dispatcher's frames
    /// are ntdll's, and CI run 43823078930's `vcpu-runner` died ten frames
    /// deep in a DLL `WHvRunVirtualProcessor` called, which the line gave
    /// as bare addresses (randomised per boot), so it could not be named
    /// after the run.
    #[test]
    fn test_the_frames_of_a_stack_that_could_not_grow_name_their_modules() {
        let (code, text) = run_child("stack_at_the_limit_rust_child", Some(96 << 20));
        assert_eq!(code, Some(137), "{text}");
        let frames: std::vec::Vec<&str> = text.lines().filter(|l| l.starts_with("STACK137FRAMES ")).collect();
        assert!(frames.iter().any(|l| l.to_ascii_lowercase().contains(" ntdll.dll+0x")), "{text}");
        for l in &frames {
            let what = l.split(' ').nth(2).unwrap_or_default();
            assert!(what.starts_with("image+0x") || what.contains(".dll+0x") || what.contains(".DLL+0x"), "a frame not named: {l}\n{text}");
        }
    }

    /// A frame in an image whose headers point outside it is given as a
    /// bare address, and the lines after it are written: the module's name
    /// is looked up in the headers of any `SEC_IMAGE` view
    /// (`windows_mm::module_of`), not only a module the loader checked, on
    /// the path that writes a process's last lines (STACK137FRAMES, then
    /// its 137), so an offset the headers give that leads outside the image
    /// must not be followed. A hand-made PE32+ image (one section holding an
    /// export directory and its name) mapped `SEC_IMAGE`, a child per case:
    /// as made, the frame is named (`damaged.dll+0x1010`); its export
    /// directory's RVA past the image, or its name's RVA past the image,
    /// the frame is the bare address. Each child then says it went on.
    #[test]
    fn test_a_frame_in_a_damaged_image_is_given_bare() {
        for (case, want) in [("control", Some("damaged.dll+0x1010")), ("exports", None), ("name", None)] {
            let (code, text, _) = run_child_watched("damaged_image_child", &[("WICK_TEST_IMAGE", case)], false);
            let line = text.lines().find(|l| l.starts_with("STACK137FRAMES 0 ")).unwrap_or_default();
            assert!(text.contains(&std::format!("DAMAGED {case}: after the frame")), "{case}: {code:?}: {text}");
            assert_eq!(code, Some(0), "{case}: {text}");
            match want {
                Some(w) => assert!(line.starts_with(&std::format!("STACK137FRAMES 0 {w} (0x")), "{case}: {line}\n{text}"),
                None => assert!(line.len() > 19 && line["STACK137FRAMES 0 0x".len()..].chars().all(|c| c.is_ascii_hexdigit()), "{case}: {line}\n{text}"),
            }
        }
    }

    /// A PE32+ image of 0x2000 bytes, made by hand: its headers, and a
    /// section at 0x1000 holding an export directory whose name,
    /// "damaged.dll", is at 0x1100; `case` "exports" points the export
    /// directory past the image, "name" the name.
    fn damaged_image(case: &str) -> std::vec::Vec<u8> {
        let mut b = std::vec![0u8; 0x400];
        let put16 = |b: &mut [u8], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        b[0..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3c, 0x40);
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        // The file header.
        put16(&mut b, 0x44, 0x8664);
        put16(&mut b, 0x46, 1);
        put16(&mut b, 0x54, 0xf0);
        put16(&mut b, 0x56, 0x2022);
        // The optional header (PE32+).
        let o = 0x58;
        put16(&mut b, o, 0x20b);
        put32(&mut b, o + 4, 0x200);
        put32(&mut b, o + 20, 0x1000);
        b[o + 24..o + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        put32(&mut b, o + 32, 0x1000);
        put32(&mut b, o + 36, 0x200);
        put16(&mut b, o + 40, 6);
        put16(&mut b, o + 48, 6);
        put32(&mut b, o + 56, 0x2000);
        put32(&mut b, o + 60, 0x200);
        put16(&mut b, o + 68, 3);
        put16(&mut b, o + 70, 0x160);
        b[o + 72..o + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
        b[o + 80..o + 88].copy_from_slice(&0x1000u64.to_le_bytes());
        b[o + 88..o + 96].copy_from_slice(&0x10_0000u64.to_le_bytes());
        b[o + 96..o + 104].copy_from_slice(&0x1000u64.to_le_bytes());
        put32(&mut b, o + 108, 16);
        put32(&mut b, o + 112, if case == "exports" { 0x10_0000 } else { 0x1000 });
        put32(&mut b, o + 116, 40);
        // The section header.
        let s = o + 0xf0;
        b[s..s + 8].copy_from_slice(b".edata\0\0");
        put32(&mut b, s + 8, 0x1000);
        put32(&mut b, s + 12, 0x1000);
        put32(&mut b, s + 16, 0x200);
        put32(&mut b, s + 20, 0x200);
        put32(&mut b, s + 36, 0x4000_0040);
        // The export directory at RVA 0x1000 (file 0x200), its name at 0x1100.
        put32(&mut b, 0x200 + 12, if case == "name" { 0x20_0000 } else { 0x1100 });
        b[0x300..0x30c].copy_from_slice(b"damaged.dll\0");
        b
    }

    #[test]
    #[ignore = "run by test_a_frame_in_a_damaged_image_is_given_bare"]
    fn damaged_image_child() {
        use std::os::windows::io::AsRawHandle;
        let case = std::env::var("WICK_TEST_IMAGE").unwrap();
        let path = std::env::temp_dir().join(std::format!("wick-damaged-{}-{case}.dll", std::process::id()));
        std::fs::write(&path, damaged_image(&case)).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: an image section of our file, read-only.
        let section = unsafe {
            windows_sys::Win32::System::Memory::CreateFileMappingW(
                file.as_raw_handle(),
                ptr::null(),
                windows_sys::Win32::System::Memory::PAGE_READONLY | windows_sys::Win32::System::Memory::SEC_IMAGE,
                0,
                0,
                ptr::null(),
            )
        };
        assert!(!section.is_null(), "SEC_IMAGE refused the hand-made image: {}", io::Error::last_os_error());
        // SAFETY: maps the section, anywhere.
        let view = unsafe { windows_sys::Win32::System::Memory::MapViewOfFile(section, windows_sys::Win32::System::Memory::FILE_MAP_READ, 0, 0, 0) };
        assert!(!view.Value.is_null(), "the image's view: {}", io::Error::last_os_error());
        let at = view.Value as usize;
        std::println!("DAMAGED {case}: mapped at {at:#x}");
        crate::windows_mm::say_frame_for_test(0, at + 0x1010);
        std::println!("DAMAGED {case}: after the frame");
        // SAFETY: our view and section.
        unsafe {
            windows_sys::Win32::System::Memory::UnmapViewOfFile(view);
            windows_sys::Win32::Foundation::CloseHandle(section);
        }
        drop(file);
        let _ = std::fs::remove_file(&path);
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
    /// filter in place: the filter says so (its line, with how much of the
    /// reserve was left, the thread and its guarantee) and the process ends
    /// with `STATUS_STACK_OVERFLOW` (0xC00000FD), on each kind of thread
    /// ([`Kind`]), with room left; each child alone (the error mode it
    /// inherits), where the filter passes it on and Windows Error Reporting
    /// ends it, and in a job as the jailer makes Firecracker's
    /// (`JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, which Learn says
    /// forces `SEM_NOGPFAULTERRORBOX` on each process of the job: Windows
    /// Error Reporting is not called, and the unhandled-exception filter's
    /// caller handles the exception), where the filter ends it itself and
    /// says so in its line. There a pool thread's overflow, passed on, was
    /// taken by its pool, which went on running callbacks, the process with
    /// it (exit 0, on Windows Server 2022 20348 and 2025 26100 alike), where
    /// a Rust or `CreateThread` thread's ended the process with 0xC00000FD.
    /// Each child waits for its thread by the thread's own
    /// structure, with no timeout ([`stack_overflow`]): a child whose
    /// process went on says how, and ends 0.
    ///
    /// Its record, STACKENDHOST: the host's build and revision, this
    /// process's error mode, its just-in-time debugger (AeDebug) and Windows
    /// Error Reporting's keys; and for each child when it ended after the
    /// filter's line, with what status, and, if it still runs 12 s after
    /// its start, the processes it started or that report its fault, and
    /// its threads' stacks (cdb, where the host has it).
    #[test]
    fn test_a_stack_overflow_at_the_reserves_end_is_still_one() {
        stack_end_host_record();
        let mut not_ended = std::vec::Vec::new();
        for child in ["stack_overflow_rust_child", "stack_overflow_createthread_child", "stack_overflow_pool_child"] {
            for jailed in [false, true] {
                let (code, text, ended) = run_child_watched(child, &[], jailed);
                let how = if jailed { "in a job as the jailer's" } else { "alone" };
                std::eprintln!("STACKEND {child} {how}: {code:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
                let said = text.contains("wick: a thread's stack overflowed at its reserve's end")
                    && (!jailed || text.contains("in a job that dies on unhandled exceptions, the process ends with STATUS_STACK_OVERFLOW"));
                if !said || code != Some(0xC000_00FD_u32.cast_signed()) {
                    not_ended.push(std::format!("{child} {how} ({code:?}): {text}"));
                }
            }
        }
        assert!(not_ended.is_empty(), "not ended by the filter with its line and 0xC00000FD: {not_ended:#?}");
    }

    /// An unbounded recursion on a new thread of `kind`, waited for by the
    /// thread's own structure ([`on_a_thread_and_wait`]): the overflow either
    /// ends the process or this returns and says how the process went on. A
    /// child run in a job waits until it is in that job first
    /// ([`in_the_job_if_asked`]).
    fn stack_overflow(kind: Kind) {
        fn said_then_deep(kind: Kind) {
            let (base, limit, reserve, guarantee) = stack_of_this_thread();
            std::println!(
                "the {kind:?} thread's stack: {} KiB committed of a {} KiB reserve, a guarantee of {guarantee} bytes",
                (base - limit) >> 10,
                (base - reserve) >> 10
            );
            core::hint::black_box(deep(usize::MAX));
        }
        in_the_job_if_asked();
        lazy_memory_is_mapped();
        let how = on_a_thread_and_wait(kind, said_then_deep);
        std::println!("the {kind:?} thread's unbounded recursion: {how}, and the process went on");
    }

    /// A child run in a job (WICK_TEST_JOB, its name) waits until it is in
    /// that job, and says its error mode.
    fn in_the_job_if_asked() {
        if let Ok(name) = std::env::var("WICK_TEST_JOB") {
            use windows_sys::Win32::System::JobObjects::{IsProcessInJob, OpenJobObjectW};
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            /// winnt.h's (windows-sys has it under System_SystemServices).
            const JOB_OBJECT_QUERY: u32 = 4;
            let wide: std::vec::Vec<u16> = name.encode_utf16().chain([0]).collect();
            // SAFETY: a NUL-terminated name.
            let job = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, wide.as_ptr()) };
            assert!(!job.is_null(), "the job {name}: {}", io::Error::last_os_error());
            // The parent assigns this process once it has started it.
            loop {
                let mut is = 0;
                // SAFETY: this process, a job handle with JOB_OBJECT_QUERY.
                assert_ne!(unsafe { IsProcessInJob(GetCurrentProcess(), job, &mut is) }, 0);
                if is != 0 {
                    break;
                }
                std::thread::yield_now();
            }
            // SAFETY: our handle.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            use windows_sys::Win32::System::JobObjects::{
                JOBOBJECT_BASIC_LIMIT_INFORMATION, JobObjectBasicLimitInformation, QueryInformationJobObject,
            };
            // SAFETY: plain data.
            let mut l: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
            // SAFETY: this process's job (Learn, QueryInformationJobObject:
            // with no handle, "the immediate job of the calling process").
            #[allow(clippy::cast_possible_truncation)]
            let ok = unsafe { QueryInformationJobObject(ptr::null_mut(), JobObjectBasicLimitInformation, (&raw mut l).cast(), core::mem::size_of_val(&l) as u32, ptr::null_mut()) };
            std::println!("the child's immediate job: query {ok}, limit flags {:#x}", l.LimitFlags);
        }
        // SAFETY: plain call.
        std::println!("the child's error mode: {:#x}", unsafe { windows_sys::Win32::System::Diagnostics::Debug::GetErrorMode() });
    }

    /// Runs `body` on a new thread of `kind` and waits for it by the
    /// thread's own structure, with no timeout; says how it went on if the
    /// process did. A Rust or `CreateThread` thread is waited for to its
    /// end (its handle); a pool thread is the only thread of a pool of its
    /// own (at most and at least one, Learn: SetThreadpoolThreadMaximum,
    /// SetThreadpoolThreadMinimum), and a second callback is queued once the
    /// first has started `body`, so it runs only once that thread is back in
    /// its pool (or a new one replaced it): as Windows Server 2025
    /// 26100.33674's pool took a stack overflow and went on waiting for work
    /// (CI run 43823078930's windows job: the child's process alive after
    /// 60 s, its overflowed thread back in `ntdll!TppWorkerThread`).
    fn on_a_thread_and_wait(kind: Kind, body: fn(Kind)) -> std::string::String {
        use windows_sys::Win32::System::Threading::{
            CloseThreadpool, CreateThread, CreateThreadpool, INFINITE, PTP_CALLBACK_INSTANCE, SetThreadpoolThreadMaximum,
            SetThreadpoolThreadMinimum, TP_CALLBACK_ENVIRON_V3, TP_CALLBACK_PRIORITY_NORMAL, TrySubmitThreadpoolCallback,
            WaitForSingleObject,
        };
        type Started = (std::sync::mpsc::Sender<()>, fn(Kind));
        unsafe extern "system" fn started(raw: *mut c_void) -> u32 {
            // SAFETY: the function pointer passed below.
            let body: fn(Kind) = unsafe { core::mem::transmute::<*mut c_void, fn(Kind)>(raw) };
            body(Kind::CreateThread);
            0
        }
        unsafe extern "system" fn pooled(_: PTP_CALLBACK_INSTANCE, raw: *mut c_void) {
            // SAFETY: the pair boxed below, given to this callback alone.
            let (said, body) = *unsafe { std::boxed::Box::from_raw(raw.cast::<Started>()) };
            said.send(()).unwrap();
            drop(said);
            body(Kind::Pool);
        }
        unsafe extern "system" fn next(_: PTP_CALLBACK_INSTANCE, tx: *mut c_void) {
            // SAFETY: the sender boxed below, given to this callback alone.
            let tx = unsafe { std::boxed::Box::from_raw(tx.cast::<std::sync::mpsc::Sender<()>>()) };
            let _ = tx.send(());
        }
        match kind {
            Kind::Rust => {
                let ended = std::thread::Builder::new().name("wick-stack-test".into()).spawn(move || body(Kind::Rust)).unwrap().join();
                std::format!("the thread ended ({})", if ended.is_ok() { "returned" } else { "panicked" })
            }
            Kind::CreateThread => {
                // SAFETY: a thread of ours with the default stack.
                let t = unsafe { CreateThread(ptr::null(), 0, Some(started), body as *mut c_void, 0, ptr::null_mut()) };
                assert!(!t.is_null());
                // SAFETY: our thread's handle.
                unsafe { WaitForSingleObject(t, INFINITE) };
                "the thread ended".into()
            }
            Kind::Pool => {
                // SAFETY: a pool of our own.
                let pool = unsafe { CreateThreadpool(ptr::null()) };
                assert_ne!(pool, 0);
                // SAFETY: our pool, of one thread.
                unsafe {
                    SetThreadpoolThreadMaximum(pool, 1);
                    assert_ne!(SetThreadpoolThreadMinimum(pool, 1), 0);
                }
                // As TpInitializeCallbackEnviron and TpSetCallbackThreadpool
                // (winnt.h) make it.
                let env = TP_CALLBACK_ENVIRON_V3 {
                    Version: 3,
                    Pool: pool,
                    CallbackPriority: TP_CALLBACK_PRIORITY_NORMAL,
                    #[allow(clippy::cast_possible_truncation)]
                    Size: core::mem::size_of::<TP_CALLBACK_ENVIRON_V3>() as u32,
                    ..Default::default()
                };
                let (said, has_started) = std::sync::mpsc::channel::<()>();
                let raw = std::boxed::Box::into_raw(std::boxed::Box::new((said, body))).cast::<c_void>();
                // SAFETY: a callback of this module, on our pool.
                assert_ne!(unsafe { TrySubmitThreadpoolCallback(Some(pooled), raw, &env) }, 0);
                // The next callback is queued once the pool's one thread has
                // started `body`, so it runs only once that thread is back.
                has_started.recv().unwrap();
                let (tx, rx) = std::sync::mpsc::channel::<()>();
                let tx = std::boxed::Box::into_raw(std::boxed::Box::new(tx)).cast::<c_void>();
                // SAFETY: as above.
                assert_ne!(unsafe { TrySubmitThreadpoolCallback(Some(next), tx, &env) }, 0);
                rx.recv().unwrap();
                // SAFETY: our pool, its callbacks done.
                unsafe { CloseThreadpool(pool) };
                "its pool ran the next callback".into()
            }
        }
    }

    /// The exceptions [`test_an_unhandled_exception_ends_the_process_with_its_code`]
    /// raises, and their codes: an access violation (a write to address 8),
    /// an illegal instruction (`ud2`) and software exceptions no signal
    /// stands for, one raised non-continuable and one continuable.
    const UNHANDLED: [(&str, u32); 4] = [("av", 0xC000_0005), ("ud2", 0xC000_001D), ("raise", 0xE057_1C4B), ("raise-continuable", 0xE057_1C4D)];

    /// An exception that nothing handles gets a line that names it, its
    /// address and its thread (the last unhandled-exception filter,
    /// `windows_mm::last_filter`), and ends the process with its code, on
    /// every kind of thread ([`Kind`]), alone and in a job of the jailer's
    /// limits, with lazy memory mapped (the stack filter above it, as in a
    /// VMM) and, for the access violation, without (as in the API process
    /// or the jailer): in the job the filter ends the process itself, where
    /// the end is left to the filters' caller, which for a pool thread's
    /// stack overflow was its pool, going on
    /// ([`test_a_stack_overflow_at_the_reserves_end_is_still_one`]); alone,
    /// Windows Error Reporting ends it, with its dump, as Linux's default
    /// action for a fault signal no handler is registered for ends a
    /// process with a core. No time is asserted.
    #[test]
    fn test_an_unhandled_exception_ends_the_process_with_its_code() {
        let mut not_ended = std::vec::Vec::new();
        for (fault, code) in UNHANDLED {
            for lazy in ["1", "0"] {
                if lazy == "0" && fault != "av" {
                    continue;
                }
                for child in ["unhandled_rust_child", "unhandled_createthread_child", "unhandled_pool_child"] {
                    for jailed in [false, true] {
                        let (got, text, ended) = run_child_watched(child, &[("WICK_TEST_FAULT", fault), ("WICK_TEST_LAZY", lazy)], jailed);
                        let how = if jailed { "in a job as the jailer's" } else { "alone" };
                        std::eprintln!("UNHANDLED {child} {fault} lazy {lazy} {how}: {got:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
                        let said = text.contains(&std::format!("wick: an unhandled exception {code:#x}"))
                            && (!jailed || text.contains("in a job that dies on unhandled exceptions, the process ends with its code"));
                        if !said || got != Some(code.cast_signed()) {
                            not_ended.push(std::format!("{child} {fault} lazy {lazy} {how} ({got:?}): {text}"));
                        }
                    }
                }
            }
        }
        assert!(not_ended.is_empty(), "not ended by the last filter with its line and the exception's code: {not_ended:#?}");
    }

    /// The last filter keeps the filter it replaced: in this executable,
    /// which the Visual C++ runtime starts, the runtime's own
    /// (`__scrt_unhandled_exception_filter`, installed by its
    /// `pre_cpp_initialization` in `.CRT$XCAA`, before the `.CRT$XCU`
    /// initializer that installs the last filter). LASTFILTER: where it is,
    /// as this executable plus an offset (named with cdb and the pdb).
    #[test]
    fn test_the_last_filter_keeps_the_filter_it_replaced() {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
        let replaced = crate::windows_mm::replaced_at_start();
        let base_of = |a: usize| {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
            // SAFETY: as above.
            assert_ne!(unsafe { VirtualQuery(a as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) }, 0);
            mbi.AllocationBase as usize
        };
        assert_ne!(replaced, 0, "the last filter replaced no filter");
        let exe = base_of(test_the_last_filter_keeps_the_filter_it_replaced as *const () as usize);
        std::eprintln!(
            "LASTFILTER the filter the last one replaced: {replaced:#x}, {}+{:#x} (this executable at {exe:#x})",
            if base_of(replaced) == exe { "this executable" } else { "another module" },
            replaced - base_of(replaced)
        );
        assert_eq!(base_of(replaced), exe, "the filter replaced is not this executable's");
    }

    /// An MSVC C++ exception nothing catches (`unhandled_fault`'s "cxx")
    /// reaches the last filter, which writes its line and calls the filter
    /// it replaced, the C runtime's, which ends the process with
    /// `terminate()`: with no terminate handler set, `abort()`
    /// (ucrt 10.0.26100.0 misc/terminate.cpp:38-58), which with no SIGABRT
    /// handler ends it by `__fastfail(FAST_FAIL_FATAL_APP_EXIT)`
    /// (startup/abort.cpp:71-77), exit 0xC0000409; on each kind of thread,
    /// alone and in a job of the jailer's limits (the last filter's own end
    /// in such a job is not reached). CXXEND: each child's end.
    #[test]
    fn test_a_cxx_exception_nothing_catches_ends_through_the_runtimes_filter() {
        let mut wrong = std::vec::Vec::new();
        for child in ["unhandled_rust_child", "unhandled_createthread_child", "unhandled_pool_child"] {
            for jailed in [false, true] {
                let (got, text, ended) = run_child_watched(child, &[("WICK_TEST_FAULT", "cxx"), ("WICK_TEST_LAZY", "1")], jailed);
                let how = if jailed { "in a job as the jailer's" } else { "alone" };
                std::eprintln!("CXXEND {child} {how}: {got:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
                let said = text.contains("wick: an unhandled exception 0xe06d7363")
                    && text.contains("a C++ exception, which the filter this one replaced (the C runtime's) ends with terminate()");
                if !said || got != Some(0xC000_0409_u32.cast_signed()) {
                    wrong.push(std::format!("{child} {how} ({got:?}): {text}"));
                }
            }
        }
        assert!(wrong.is_empty(), "not ended by the runtime's filter after the last filter's line: {wrong:#?}");
    }

    /// A process in a job without `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
    /// nested in one with it (an operator's job around an unjailed VMM)
    /// ends as one in no such job: the outer job's limit does not reach it.
    /// Its immediate job's query (what the filters ask) shows no flag;
    /// a pool thread's stack overflow and an access violation, on a pool
    /// thread and a `CreateThread` thread, end the process with their code
    /// through Windows Error Reporting, as with the inner job alone, where
    /// in a job with the flag the overflow passed on was taken by the pool
    /// ([`test_a_stack_overflow_at_the_reserves_end_is_still_one`]).
    /// NESTJOB: each child's end, nested and with the inner job alone.
    #[test]
    fn test_a_job_nested_in_one_that_dies_on_unhandled_exceptions_ends_by_its_own_limits() {
        use windows_sys::Win32::System::JobObjects::{JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
        let jobs = [JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE];
        let mut wrong = std::vec::Vec::new();
        for (child, env) in [
            ("stack_overflow_pool_child", &[][..]),
            ("unhandled_pool_child", &[("WICK_TEST_FAULT", "av"), ("WICK_TEST_LAZY", "1")][..]),
            ("unhandled_createthread_child", &[("WICK_TEST_FAULT", "av"), ("WICK_TEST_LAZY", "1")][..]),
        ] {
            let code: u32 = if child.starts_with("stack") { 0xC000_00FD } else { 0xC000_0005 };
            for nested in [false, true] {
                let (got, text, ended) = run_child_in_jobs(child, env, if nested { &jobs[..] } else { &jobs[1..] });
                let how = if nested { "inner job (no flag) in an outer one with the flag" } else { "one job, no flag" };
                std::eprintln!("NESTJOB {child} {how}: {got:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
                let flags = std::format!("the child's immediate job: query 1, limit flags {JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:#x}");
                if !text.contains(&flags) || !text.contains("Windows Error Reporting ends the process") || got != Some(code.cast_signed()) {
                    wrong.push(std::format!("{child} {how} ({got:?}): {text}"));
                }
            }
        }
        assert!(wrong.is_empty(), "not ended as in a job without the flag: {wrong:#?}");
    }

    fn unhandled_fault(kind: Kind) {
        let fault = std::env::var("WICK_TEST_FAULT").unwrap();
        std::println!("the {kind:?} thread raises {fault}");
        match fault.as_str() {
            // SAFETY: a write that faults, on purpose.
            "av" => unsafe { core::ptr::write_volatile(core::hint::black_box(8usize) as *mut u8, 1) },
            // SAFETY: an instruction that faults, on purpose.
            "ud2" => unsafe { core::arch::asm!("ud2", options(nomem, nostack)) },
            // SAFETY: a software exception with no arguments.
            "raise" => unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseException(UNHANDLED[2].1, 1 /* EXCEPTION_NONCONTINUABLE */, 0, ptr::null()) },
            // SAFETY: as above.
            "raise-continuable" => unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseException(UNHANDLED[3].1, 0, 0, ptr::null()) },
            // An MSVC C++ exception as the runtime's filter recognises it
            // (ehdata.h:568, `PER_IS_MSVC_PURE_OR_NATIVE_EH`: the code, four
            // parameters, EH_MAGIC_NUMBER1), with no object and no
            // `ThrowInfo` (what `throw;` raises with no current exception).
            "cxx" => {
                let parameters = [0x1993_0520usize, 0, 0, 0];
                // SAFETY: four parameters, as passed.
                unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseException(0xE06D_7363, 1, 4, parameters.as_ptr()) }
            }
            other => panic!("no fault {other}"),
        }
    }

    fn unhandled(kind: Kind) {
        in_the_job_if_asked();
        if std::env::var("WICK_TEST_LAZY").as_deref() == Ok("1") {
            lazy_memory_is_mapped();
        }
        let how = on_a_thread_and_wait(kind, unhandled_fault);
        std::println!("the {kind:?} thread's exception: {how}, and the process went on");
    }

    #[test]
    #[ignore = "run by test_an_unhandled_exception_ends_the_process_with_its_code"]
    fn unhandled_rust_child() {
        unhandled(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_an_unhandled_exception_ends_the_process_with_its_code"]
    fn unhandled_createthread_child() {
        unhandled(Kind::CreateThread);
    }

    #[test]
    #[ignore = "run by test_an_unhandled_exception_ends_the_process_with_its_code"]
    fn unhandled_pool_child() {
        unhandled(Kind::Pool);
    }

    /// STACKENDHOST's host part: this process's error mode, which its
    /// children inherit (Learn, SetErrorMode), and `reg query` of what
    /// decides how a process with an unhandled exception ends.
    fn stack_end_host_record() {
        // SAFETY: plain call.
        std::eprintln!("STACKENDHOST error mode: {:#x}", unsafe { windows_sys::Win32::System::Diagnostics::Debug::GetErrorMode() });
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

    /// [`run_child`] with no memory limit, which also says when the child
    /// ended, and, if it still runs 12 s after its start, what holds it
    /// (STACKENDHOST). `jailed`: in a job of the limits the jailer gives
    /// Firecracker's (overlay/jailer/platform/windows/mod.rs,
    /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
    /// JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`), named to the child in
    /// WICK_TEST_JOB.
    fn run_child_watched(child: &str, env: &[(&str, &str)], jailed: bool) -> (Option<i32>, std::string::String, std::time::Duration) {
        use windows_sys::Win32::System::JobObjects::{JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
        let jobs: &[u32] = if jailed { &[JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION] } else { &[] };
        run_child_in_jobs(child, env, jobs)
    }

    /// [`run_child_watched`] in nested jobs, each with the limit flags
    /// given, outermost first: the child is assigned to each in that order
    /// (Learn, "Nested Jobs": a process already in a job assigned to
    /// another makes the second a child job of the first), and is named
    /// the innermost (WICK_TEST_JOB).
    fn run_child_in_jobs(child: &str, env: &[(&str, &str)], jobs: &[u32]) -> (Option<i32>, std::string::String, std::time::Duration) {
        use std::io::Read;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        static JOBS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let name = std::format!("{}::{child}", module_path!().split_once("::").unwrap().1);
        let mut made = std::vec::Vec::new();
        let mut job_name = std::string::String::new();
        for &flags in jobs {
            job_name = std::format!(
                "Local\\wick-test-{}-{}",
                std::process::id(),
                JOBS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let wide: std::vec::Vec<u16> = job_name.encode_utf16().chain([0]).collect();
            // SAFETY: a new job of this name.
            let job = unsafe { CreateJobObjectW(ptr::null(), wide.as_ptr()) };
            assert!(!job.is_null(), "{}", io::Error::last_os_error());
            // SAFETY: plain data.
            let mut l: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            l.BasicLimitInformation.LimitFlags = flags;
            // SAFETY: a structure of the size passed.
            unsafe {
                #[allow(clippy::cast_possible_truncation)]
                let size = std::mem::size_of_val(&l) as u32;
                assert_ne!(SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const l).cast(), size), 0);
            }
            made.push(job);
        }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", name.as_str(), "--ignored", "--nocapture"]).envs(env.iter().copied());
        if !jobs.is_empty() {
            command.env("WICK_TEST_JOB", &job_name);
        }
        let start = std::time::Instant::now();
        let mut process = command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        for &job in &made {
            use std::os::windows::io::AsRawHandle;
            // SAFETY: our job; the child's handle.
            assert_ne!(unsafe { AssignProcessToJobObject(job, process.as_raw_handle()) }, 0, "{}", io::Error::last_os_error());
        }
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
        for job in made.into_iter().rev() {
            // SAFETY: our job handle.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
        }
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
    /// line (the reserve's end) and 0xC00000FD. A
    /// child per case: a thread recurses until 64, 63, ... 4 KiB are left
    /// above its reserve's low end (DeallocationStack), then reads a lazy
    /// page; a Rust thread (a 20 KiB guarantee) and a `CreateThread` thread
    /// (none; a pool thread's stack is the same, and its overflow's end is
    /// `test_a_stack_overflow_at_the_reserves_end_is_still_one`'s). Asserted
    /// per case:
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
                let (code, text, _) = run_child_watched(&child, &[("WICK_TEST_LEFT_KIB", left_kib.as_str())], false);
                std::eprintln!("LAZYEND {kind} at {left} KiB left: {code:?}; {}", text.trim().replace('\n', " | "));
                let served = code == Some(0) && text.contains("LAZYEND the read gave 0");
                let loud = code == Some(0xC000_00FD_u32.cast_signed())
                    && text.contains("has overflowed its stack")
                    && text.contains("wick: a thread's stack overflowed at its reserve's end");
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
        // The last pages where a page table is already, as [`no_room_left`]
        // takes them: a `VirtualAlloc` of a page that needs a new page table
        // needs 8 KiB, so with 4 KiB left it is refused and the room stays
        // for the move's map, which then is made and owes nothing (OWEDREC:
        // the one failing run of 20 alone on Windows Server 2022 20348 and the
        // one of 20 on 2025 26100 both said "the hook took 8 KiB; private
        // commit 98300 KiB" of a 98304 KiB limit, the move made, nothing
        // owed). With the slack taken too, 100 of 100 alone on each, the
        // 8 + 4 KiB case among them (0f751bc1's message).
        let before = SLACK_TAKEN.load(Ordering::SeqCst);
        let after = take_the_slack();
        HOOK_SLACK.store((before << 32) | after, Ordering::SeqCst);
        // OWEDREC: what the hook found to take (nothing allocated: it runs
        // at the limit).
        crate::windows_mm::say_at_the_limit(format_args!(
            "OWEDREC the move gave back its dead pages' charge; the hook took {} KiB in pages and {} KiB where a page table was; private commit {} KiB",
            held.len() * PAGE as usize / 1024,
            (after - before) * PAGE as usize / 1024,
            private_commit() / 1024
        ));
    }

    /// The slack pages [`take_the_room_given_up`] took: the count taken
    /// before it (high 32 bits) and after it (low).
    static HOOK_SLACK: AtomicUsize = AtomicUsize::new(0);

    /// Gives back all [`take_the_room_given_up`] took: its pages and its
    /// slack pages (the slack taken before it stays taken).
    fn give_back_the_room_taken() {
        use windows_sys::Win32::System::Memory::{MEM_DECOMMIT, VirtualFree};
        {
            let mut t = ROOM_TAKEN.lock().unwrap();
            while !t.is_empty() {
                give_back_a_page(&mut t);
            }
        }
        let v = HOOK_SLACK.swap(0, Ordering::SeqCst);
        let (before, after) = (v >> 32, v & 0xffff_ffff);
        let base = SLACK.load(Ordering::SeqCst);
        if base != 0 && after > before {
            // SAFETY: pages of our slack region the hook committed.
            unsafe { VirtualFree((base + (before + 1) * PAGE as usize) as *mut c_void, (after - before) * PAGE as usize, MEM_DECOMMIT) };
            SLACK_TAKEN.store(before, Ordering::SeqCst);
        }
    }

    /// OWEDREC: one line of [`owed_goes_child`]'s steps, without allocating
    /// (it is said at the limit): the step, the private commit, the reclaim's
    /// counts so far and the charge owed.
    fn owed_step(step: &str) {
        let c = reclaim_counts();
        crate::windows_mm::say_at_the_limit(format_args!(
            "OWEDREC {step}: private commit {} KiB; reclaims asked {}, candidates {}, moves made {}, not made {}; owed {} KiB; the hook ran {}",
            private_commit() / 1024,
            c.asks,
            c.candidates,
            c.moves,
            c.refused,
            crate::windows_mm::owed_bytes() / 1024,
            ROOM_TAKEN_ONCE.load(Ordering::SeqCst)
        ));
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
        give_back_the_room_taken();
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
        for l in text.lines().filter(|l| l.starts_with("OWEDREC") || l.starts_with("room left") || l.starts_with("wick: reclaim") || l.starts_with("filled")) {
            std::eprintln!("{l}");
        }
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
        owed_step("dead above unfilled, no room left");
        {
            // Whether the fill's page has a page table already: a committed
            // page in its 2 MiB-aligned region (one page table maps 2 MiB).
            let target = mem + done;
            let region = target - target % (2 << 20);
            let mut committed = 0;
            let mut at = region;
            while at < target {
                if committed_protection(at).is_some() {
                    committed += 1;
                }
                at += PAGE;
            }
            crate::windows_mm::say_at_the_limit(format_args!(
                "OWEDREC the fill's page is {} KiB into its 2 MiB-aligned region, {committed} pages committed below it there; the range at {mem:#x}, the page at {target:#x}",
                (target - region) / 1024
            ));
        }
        let (m1, refused1) = (moves_on_record().0.len(), crate::windows_mm::moves_refused());
        let fill = fill_a_page(ctx, mem + done);
        owed_step("dead above unfilled, after the fill");
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
        for l in text.lines().filter(|l| l.starts_with("OWEDREC") || l.starts_with("room left") || l.starts_with("wick: reclaim")) {
            std::eprintln!("{l}");
        }
        assert!(text.contains("owed: 12 KiB; unregistered and unmapped: 0 KiB owed; the same address committed, charged false; another fill made"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_an_owed_charge_goes_with_its_range in a job of its own"]
    fn owed_goes_child() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        ROOM_TAKEN.lock().unwrap().reserve_exact(4096);
        owed_step("filled to the limit, half of 8 chunks discarded");
        let mut held = no_room_left();
        owed_step("no room left");
        *crate::windows_mm::AFTER_DEAD_UNCHARGED.lock().unwrap() = Some(take_the_room_given_up);
        let fill = fill_a_page(ctx, mem + done);
        *crate::windows_mm::AFTER_DEAD_UNCHARGED.lock().unwrap() = None;
        crate::windows_mm::say_at_the_limit(format_args!("OWEDREC the fill at the limit: {fill}"));
        owed_step("after the fill");
        let owed = crate::windows_mm::owed_bytes();
        give_back_the_room_taken();
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

    /// A fill at the job's limit allocates nothing: fills of a page each,
    /// from no room left, refused, reclaimed for and made, until one is
    /// refused with `ENOMEM`, allocate nothing on the filling thread, the
    /// serve thread or the reclaimer, where a heap that must grow is refused
    /// there; Linux's fill takes only the page it fills and the page tables
    /// it needs (v6.1 mm/userfaultfd.c: `mcopy_atomic_pte`'s
    /// `alloc_page_vma`, 156, charged by `mem_cgroup_charge`, 205;
    /// `mm_alloc_pmd`'s `pmd_alloc`, 317, and `__pte_alloc`, 643, in
    /// `__mcopy_atomic`). In a job of its own, with no room left
    /// ([`no_room_left`]).
    #[test]
    fn test_a_fill_at_the_limit_allocates_nothing() {
        let (code, text) = run_child("fill_allocations_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        for kind in ["the serve thread", "the reclaimer", "the caller"] {
            assert!(text.contains(&std::format!("ALLOCS fills at the limit: {kind} 0 allocations")), "{text}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_at_the_limit_allocates_nothing and test_what_the_limit_paths_allocate_on_record in a job of their own"]
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
    /// ranges' records, docs/ARCHITECTURE.md, "Released userfaultfd ranges").
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
    /// touching threads (docs/ARCHITECTURE.md, "Released userfaultfd ranges":
    /// the readers).
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
    /// memory unmapped (docs/ARCHITECTURE.md, "Released userfaultfd ranges"):
    /// with 64 ranges released
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

    /// A plain AF_UNIX stream socket, for the tests below.
    fn unix_socket() -> SOCKET {
        wick_wsa_startup();
        // SAFETY: creates a socket.
        let s = unsafe {
            ws::WSASocketW(i32::from(AF_UNIX), SOCK_STREAM, 0, ptr::null(), 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT)
        };
        assert_ne!(s, INVALID_SOCKET, "WSASocketW: {}", io::Error::last_os_error());
        s
    }

    /// A `sockaddr_un` for `name` (a path, or an abstract name when it
    /// starts with NUL) and the length to pass: the family, then the name's
    /// bytes, with no terminator for an abstract name (Linux's rule for
    /// abstract names: the length delimits it).
    fn unix_addr(name: &[u8]) -> ([u8; 110], i32) {
        let mut a = [0u8; 110];
        a[0] = 1; // AF_UNIX
        a[2..2 + name.len()].copy_from_slice(name);
        let len = if name.first() == Some(&0) { 2 + name.len() } else { a.len() };
        (a, i32::try_from(len).unwrap())
    }

    fn wsa_error() -> i32 {
        // SAFETY: plain call.
        unsafe { ws::WSAGetLastError() }
    }

    /// The path of this process's userfaultfd socket number `seq`, as
    /// `socket_pair` names it.
    fn uffd_socket_path(seq: u64) -> std::path::PathBuf {
        std::env::temp_dir().join(std::format!("wick-uffd-{}-{seq}.sock", std::process::id()))
    }

    /// A process killed between `socket_pair`'s bind and its removal of
    /// the path leaves the path (cdb's quit left `wick-uffd-3332-1.sock` on
    /// fc-win, 2026-11-16, and a later test process with pid 3332 was
    /// refused its second userfaultfd: `bind` WSAEADDRINUSE, 10048). The
    /// next process of that pid must make its userfaultfds all the same, as
    /// Linux's `socketpair`, which has no path, always does; and no path of
    /// a userfaultfd it made may stay once `create` returned. In a process
    /// of its own (its sequence numbers start at 0).
    #[test]
    fn test_a_userfaultfd_is_made_over_paths_a_dead_process_of_this_pid_left() {
        let (code, out) = run_child("sockpath_leftover_child", None);
        std::eprintln!("{out}");
        assert_eq!(code, Some(0), "the child failed");
        assert!(out.contains("SOCKPATH made 4 userfaultfds over 4 left paths"), "the child did not get to its end");
    }

    #[test]
    #[ignore = "run by test_a_userfaultfd_is_made_over_paths_a_dead_process_of_this_pid_left"]
    fn sockpath_leftover_child() {
        // This child's paths, removed at its end however it ends.
        struct Paths;
        impl Drop for Paths {
            fn drop(&mut self) {
                for seq in 0..4 {
                    let _ = std::fs::remove_file(uffd_socket_path(seq));
                }
            }
        }
        let _paths = Paths;
        // Left as a killed process leaves them: a socket bound to the path
        // and closed, its file (an NTFS reparse point) still there.
        for seq in 0..4 {
            let path = uffd_socket_path(seq);
            let (a, len) = unix_addr(path.to_str().unwrap().as_bytes());
            let s = unix_socket();
            // SAFETY: a valid AF_UNIX address.
            assert_eq!(unsafe { ws::bind(s, a.as_ptr().cast(), len) }, 0, "bind {}: {}", path.display(), wsa_error());
            // SAFETY: our socket.
            unsafe { ws::closesocket(s) };
            assert!(path.exists(), "{} went with its socket", path.display());
        }
        for seq in 0..4 {
            let made = create(0, false, true);
            let (ctx, user) = made.unwrap_or_else(|e| panic!("userfaultfd {seq} over a path a dead process left: {e}"));
            assert!(!uffd_socket_path(seq).exists(), "{} stayed after create returned", uffd_socket_path(seq).display());
            release(ctx, user);
        }
        std::eprintln!("SOCKPATH made 4 userfaultfds over 4 left paths; none of their paths stayed");
    }

    /// SOCKPATH: what AF_UNIX on this host does with the cases
    /// `socket_pair` meets (note-uffd-sockpath.md): (a) an abstract address
    /// (a NUL first in `sun_path`): bind, listen, connect, accept; (b) the
    /// listener's path deleted (DeleteFileW) after a connect and before its
    /// accept: is the queued connection still accepted; (c) the pid
    /// `SIO_AF_UNIX_GETPEERPID` gives for each end of a pair this process
    /// made; (d) a bind over a path a closed socket left: its error, and the
    /// bind after DeleteFileW. On record: it prints what it saw and fails
    /// only on a call the cases need that it could not make.
    #[test]
    fn test_af_unix_paths_and_abstract_addresses_on_record() {
        let wide = |p: &std::path::Path| -> Vec<u16> {
            use std::os::windows::ffi::OsStrExt;
            p.as_os_str().encode_wide().chain([0]).collect()
        };
        let peer = |s: SOCKET| -> std::string::String {
            let (mut pid, mut n) = (0u32, 0u32);
            // SAFETY: a u32 out-buffer.
            let rc = unsafe {
                ws::WSAIoctl(s, ws::SIO_AF_UNIX_GETPEERPID, ptr::null(), 0, (&raw mut pid).cast(), 4, &mut n, ptr::null_mut(), None)
            };
            if rc == 0 { std::format!("pid {pid}") } else { std::format!("error {}", wsa_error()) }
        };
        let me = std::process::id();
        let close = |s: SOCKET| {
            // SAFETY: our socket.
            unsafe { ws::closesocket(s) };
        };
        // (a) An abstract address.
        let name = std::format!("\0wick-sockpath-rec-{me}");
        let (a, len) = unix_addr(name.as_bytes());
        let l = unix_socket();
        // SAFETY: valid addresses and our sockets, here and below.
        let bound = unsafe { ws::bind(l, a.as_ptr().cast(), len) };
        let bound_err = if bound == 0 { 0 } else { wsa_error() };
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let listened = if bound == 0 { unsafe { ws::listen(l, 1) } } else { -1 };
        let mut line = std::format!("SOCKPATH abstract: bind {bound} (error {bound_err}), listen {listened}");
        if listened == 0 {
            let c = unix_socket();
            // SAFETY: our sockets, valid addresses and NUL-terminated paths.
            let connected = unsafe { ws::connect(c, a.as_ptr().cast(), len) };
            let connect_err = if connected == 0 { 0 } else { wsa_error() };
            line.push_str(&std::format!(", connect {connected} (error {connect_err})"));
            if connected == 0 {
                // SAFETY: our sockets, valid addresses and NUL-terminated paths.
                let s = unsafe { ws::accept(l, ptr::null_mut(), ptr::null_mut()) };
                line.push_str(&std::format!(", accept {}", if s == INVALID_SOCKET { std::format!("error {}", wsa_error()) } else { std::format!("ok, its peer {}", peer(s)) }));
                if s != INVALID_SOCKET {
                    close(s);
                }
            }
            close(c);
        }
        close(l);
        std::eprintln!("{line}");
        // (b), (c): a path deleted between connect and accept.
        let path = std::env::temp_dir().join(std::format!("wick-sockpath-rec-{me}.sock"));
        let (a, len) = unix_addr(path.to_str().unwrap().as_bytes());
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::bind(l, a.as_ptr().cast(), len) }, 0, "bind {}: {}", path.display(), wsa_error());
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::listen(l, 1) }, 0);
        let c = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::connect(c, a.as_ptr().cast(), len) }, 0, "connect: {}", wsa_error());
        // SAFETY: a NUL-terminated path.
        let deleted = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        let delete_err = if deleted != 0 { 0 } else { io::Error::last_os_error().raw_os_error().unwrap_or(0) };
        let gone = !path.exists();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let s = unsafe { ws::accept(l, ptr::null_mut(), ptr::null_mut()) };
        let accepted = if s == INVALID_SOCKET { std::format!("error {}", wsa_error()) } else { "ok".into() };
        let mut moved = std::string::String::from("not tried");
        if s != INVALID_SOCKET {
            // SAFETY: our sockets, valid addresses and NUL-terminated paths.
            let sent = unsafe { ws::send(c, b"x".as_ptr(), 1, 0) };
            let mut b = [0u8; 1];
            // SAFETY: our sockets, valid addresses and NUL-terminated paths.
            let got = unsafe { ws::recv(s, b.as_mut_ptr(), 1, 0) };
            moved = std::format!("send {sent}, recv {got} ({:?})", b[0] as char);
        }
        std::eprintln!(
            "SOCKPATH path deleted after connect, before accept: DeleteFileW {deleted} (error {delete_err}), the path gone {gone}; accept {accepted}; a byte through it: {moved}"
        );
        if s != INVALID_SOCKET {
            std::eprintln!("SOCKPATH peers (this process is pid {me}): of the accepted end {}, of the connected end {}", peer(s), peer(c));
            close(s);
        }
        close(c);
        close(l);
        // (d) A bind over a path a closed socket left, then after DeleteFileW.
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::bind(l, a.as_ptr().cast(), len) }, 0, "bind {}: {}", path.display(), wsa_error());
        close(l);
        let left = path.exists();
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let again = unsafe { ws::bind(l, a.as_ptr().cast(), len) };
        let again_err = if again == 0 { 0 } else { wsa_error() };
        close(l);
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let deleted = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let after = unsafe { ws::bind(l, a.as_ptr().cast(), len) };
        let after_err = if after == 0 { 0 } else { wsa_error() };
        close(l);
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let deleted_last = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        std::eprintln!(
            "SOCKPATH a path a closed socket left: there {left}; bind over it {again} (error {again_err}); DeleteFileW {deleted}; bind after it {after} (error {after_err}); removed at the end {deleted_last}"
        );
        // (e) DeleteFileW of a name that is missing: its error.
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let missing = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        std::eprintln!("SOCKPATH DeleteFileW of a missing name: {missing} (error {})", io::Error::last_os_error().raw_os_error().unwrap_or(0));
        assert!(!path.exists());
    }

    // ---- munmap and MAP_FIXED of registered memory (the macOS backend's
    // tests of the same names; Linux's registration belongs to the vma and
    // goes with it: mm/vma.c, v6.12, `do_vmi_align_munmap` :1332, through
    // `vms_gather_munmap_vmas` :1180 and fs/userfaultfd.c
    // `userfaultfd_unmap_prep` :1267; `MAP_FIXED` unmaps what it maps over
    // first, mm/mmap.c `__mmap_region` :1361 and :1386). Each runs in a child
    // of its own (nothing else may map in the holes), whose checks are all
    // made and each failure said ("UNMAPCHECK fail: ..."), the copies that
    // may end the process last, under a watchdog.

    /// The checks of one child: each failure said as it is found, all of
    /// them asserted at the end.
    struct Checks(std::vec::Vec<std::string::String>);

    impl Checks {
        fn new() -> Self {
            Checks(std::vec::Vec::new())
        }

        fn check(&mut self, ok: bool, what: impl core::fmt::Display) {
            if !ok {
                std::println!("UNMAPCHECK fail: {what}");
                self.0.push(std::format!("{what}"));
            }
        }

        fn done(self) {
            std::println!("UNMAPCHECK done, {} failed", self.0.len());
            assert!(self.0.is_empty(), "{} checks failed: {:?}", self.0.len(), self.0);
        }
    }

    /// Ends the child with exit code 3 and a line after `secs`: a wait that
    /// would hang it.
    fn watchdog(secs: u64) {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            std::println!("WATCHDOG {secs} s passed: the child is ended");
            std::process::exit(3);
        });
    }

    /// Waits up to 10 s for `cond`; whether it held.
    fn holds_within(cond: impl Fn() -> bool) -> bool {
        let t = std::time::Instant::now();
        while !cond() {
            if t.elapsed() > std::time::Duration::from_secs(10) {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        true
    }

    const UNMAP_LEN: u64 = 64 << 10;

    /// The two kinds of registered memory ([`on_both_kinds`]): a fresh
    /// mapping of [`UNMAP_LEN`] bytes of `kind`.
    fn map_of(kind: &str) -> u64 {
        if kind == "reserved" { map_noreserve(UNMAP_LEN as usize) } else { map(UNMAP_LEN as usize) }
    }

    const MEM_KINDS: [&str; 2] = ["ordinary", "reserved"];

    fn munmap_of(at: u64, len: u64) -> c_int {
        // SAFETY: memory of the test's own, through this libc.
        unsafe { crate::munmap(at as *mut c_void, len as usize) }
    }

    /// An anonymous private mapping of `len` bytes at `at` with `MAP_FIXED`,
    /// through this libc: its address, or `MAP_FAILED` as a u64.
    fn map_fixed(at: u64, len: u64, prot: c_int) -> u64 {
        // SAFETY: the test's own addresses.
        (unsafe { crate::mmap(at as *mut c_void, len as usize, prot, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED, -1, 0) }) as u64
    }

    /// The state and protection of each page of `[at, at + len)`
    /// (`VirtualQuery`).
    fn states(at: u64, len: u64) -> std::vec::Vec<(u32, u32)> {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
        (at..at + len)
            .step_by(PAGE as usize)
            .map(|a| {
                // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                unsafe { VirtualQuery(a as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) };
                (mbi.State, mbi.Protect)
            })
            .collect()
    }

    fn page_of(b: u8) -> std::vec::Vec<u8> {
        std::vec![b; PAGE as usize]
    }

    /// A mapping made where registered memory was unmapped, before its
    /// userfaultfd is released, keeps its state and protection through the
    /// release: on Linux the registration went with the unmapped vma, and
    /// the release walks only the vmas its userfaultfd has (mm/userfaultfd.c,
    /// v6.12, `userfaultfd_release_all` :1918 to :1924), changing nothing
    /// else. Firecracker unmaps its guest memory so at teardown
    /// (vstate/memory.rs:308, before the VM's `uffd`, vstate/vm.rs:84 and
    /// :95), and another thread may map in the hole meanwhile: here this
    /// libc's `mmap` of a `PROT_NONE` reservation, and the system's own
    /// (`VirtualAlloc`, committed `PAGE_NOACCESS`, as a thread's stack guard
    /// is made). For both kinds of registered memory, pages missing and
    /// filled.
    #[test]
    fn test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is() {
        let (code, text, _) = run_child_in_jobs("release_after_unmap_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is in a process of its own"]
    fn release_after_unmap_child() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, VirtualAlloc, VirtualFree};
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            for how in ["this libc's mmap PROT_NONE", "VirtualAlloc PAGE_NOACCESS"] {
                let (ctx, user) = create(0, false, true).unwrap();
                let mem = map_of(kind);
                register(ctx, mem, UNMAP_LEN).unwrap();
                // SAFETY: a page.
                assert_eq!(unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
                assert_eq!(munmap_of(mem, UNMAP_LEN), 0, "{kind}");
                let made = if how.starts_with("VirtualAlloc") {
                    // SAFETY: the hole, reserved and committed by the system's call.
                    unsafe { VirtualAlloc(mem as *const c_void, UNMAP_LEN as usize, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS) as u64 }
                } else {
                    map_fixed(mem, UNMAP_LEN, crate::PROT_NONE)
                };
                if made != mem {
                    std::println!("UNMAP {kind}, {how}: the hole was not mapped ({made:#x}, {})", io::Error::last_os_error());
                    c.check(false, std::format!("{kind}, {how}: the hole could not be mapped"));
                    release(ctx, user);
                    continue;
                }
                let before = states(mem, 4 * PAGE);
                release(ctx, user);
                let after = states(mem, 4 * PAGE);
                std::println!("UNMAP {kind}, {how}: (state, protection) of its first 4 pages before the release {before:x?}, after {after:x?}");
                c.check(before == after, std::format!("{kind}, {how}: the release changed the new mapping: {before:x?} -> {after:x?}"));
                if how.starts_with("VirtualAlloc") {
                    // SAFETY: the reservation made above.
                    unsafe { VirtualFree(mem as *mut c_void, 0, MEM_RELEASE) };
                } else {
                    assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
                }
            }
        }
        c.done();
    }

    /// Registered memory unmapped while its userfaultfd is open leaves no
    /// registration behind (the registration went with the vma; a fill
    /// where no registered vma is is `ENOENT`, mm/userfaultfd.c, v6.12,
    /// `uffd_mfill_lock` :113, `validate_dst_vma` :34). Part of a range: the
    /// unmapped page is in no registration and stays unmapped, the
    /// userfaultfd's release included (an access to it is the process's
    /// fault, as an access where Linux has no vma); the rest is as it was.
    /// All of it: nothing is left of the range. For both kinds.
    #[test]
    #[ignore = "fails until munmap and MAP_FIXED of registered memory remove its registration on Windows (SECURITY.md, Not at parity yet)"]
    fn test_memory_unmapped_while_registered_leaves_no_registration_behind() {
        let (code, text, _) = run_child_in_jobs("unmapped_leaves_nothing_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_memory_unmapped_while_registered_leaves_no_registration_behind in a process of its own"]
    fn unmapped_leaves_nothing_child() {
        use crate::windows_mm::wick_mm::{Access, commit_on_access};
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            // Part: its second page.
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            assert_eq!(munmap_of(mem + PAGE, PAGE), 0, "{kind}");
            c.check(!is_missing(mem + PAGE), std::format!("{kind}, part: the unmapped page is still registered (missing)"));
            let z = zeropage(ctx, mem + PAGE, PAGE, true);
            c.check(z == Err((crate::ENOENT, 0)), std::format!("{kind}, part: a fill of the unmapped page: {z:?}"));
            c.check(is_missing(mem), std::format!("{kind}, part: the page left mapped is no longer missing"));
            // SAFETY: a page.
            let f = unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem, PAGE, true) };
            c.check(f == Ok(PAGE), std::format!("{kind}, part: a fill of the page left mapped: {f:?}"));
            if f == Ok(PAGE) {
                // SAFETY: filled just now.
                c.check(unsafe { ptr::read_volatile(mem as *const u8) } == 0x5a, std::format!("{kind}, part: the filled page"));
            }
            release(ctx, user);
            #[allow(clippy::cast_possible_truncation)]
            let a = commit_on_access((mem + PAGE) as usize, false);
            std::println!("UNMAP {kind}, part: after the release, a first access to the unmapped page: {a:?}; its state {:x?}", states(mem + PAGE, PAGE));
            c.check(
                matches!(a, Access::NotLazy) && !host_readable(mem + PAGE),
                std::format!("{kind}, part: after the release the unmapped page is opened: {a:?}, {:x?}", states(mem + PAGE, PAGE)),
            );
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
            // All of it, a page filled, the userfaultfd still open.
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            // SAFETY: a page.
            assert_eq!(unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0, "{kind}");
            c.check(find(mem).is_none() && find(mem + PAGE).is_none(), std::format!("{kind}, all: the unmapped range is still held"));
            let z = zeropage(ctx, mem + PAGE, PAGE, true);
            std::println!("UNMAP {kind}, all: a zero page into the unmapped range: {z:?}");
            c.check(z == Err((crate::ENOENT, 0)), std::format!("{kind}, all: a fill of the unmapped range: {z:?}"));
            release(ctx, user);
        }
        c.done();
    }

    /// How registered memory is replaced: unmapped and mapped again in the
    /// hole, or mapped over with `MAP_FIXED` (the macOS backend's
    /// `Replace`).
    const REPLACE_CASE: &str = "WICK_UFFD_REPLACE";

    /// [`UNMAP_LEN`] bytes registered with a fresh userfaultfd `a` (of the
    /// kind `WICK_UFFD_KIND` names), the first page filled with 0x5a, then
    /// replaced by new read-write memory at the same address as
    /// [`REPLACE_CASE`] says, through this libc. Returns (a, its user end,
    /// another userfaultfd b, its user end, the memory).
    fn replaced() -> (usize, c_int, usize, c_int, u64) {
        let how = std::env::var("WICK_UFFD_REPLACE").unwrap();
        let kind = std::env::var("WICK_UFFD_KIND").unwrap();
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let mem = map_of(&kind);
        register(a, mem, UNMAP_LEN).unwrap();
        // SAFETY: a page.
        assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
        if how == "UnmapThenMap" {
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        let p = map_fixed(mem, UNMAP_LEN, crate::PROT_READ | crate::PROT_WRITE);
        std::println!("UNMAP replaced ({how}, {kind}): the new mapping at {p:#x} (the old at {mem:#x}): {}", if p == mem { "made".into() } else { std::format!("{}", io::Error::last_os_error()) });
        assert_eq!(p, mem, "{how}, {kind}: the new mapping");
        (a, ua, b, ub, mem)
    }

    /// Runs `child` once for each replacement and kind, in a process of its
    /// own each; asserts that every one ended with 0, naming those that did
    /// not with their lines.
    fn replace_cases(child: &str) {
        let mut failed = std::vec::Vec::new();
        for how in ["UnmapThenMap", "MapFixedOver"] {
            for kind in MEM_KINDS {
                let (code, text, _) = run_child_in_jobs(child, &[(REPLACE_CASE, how), ("WICK_UFFD_KIND", kind)], &[]);
                for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
                    std::eprintln!("{how}, {kind}: {l}");
                }
                if code != Some(0) {
                    failed.push(std::format!("{how}, {kind}: exit {code:x?}"));
                }
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    /// The new memory is in no registration: not missing, an access there is
    /// no userfault, and a fill there is `ENOENT`, as Linux's for a
    /// destination in no registered vma (mm/userfaultfd.c, v6.12:
    /// `mfill_atomic` :700, `uffd_mfill_lock` :733, `ENOENT` at :113 when
    /// `validate_dst_vma` finds no userfaultfd on it, :34). The copy, which
    /// ended the process with an access violation on fc-win
    /// (as a probe on fc-win first found), last.
    #[test]
    #[ignore = "fails until munmap and MAP_FIXED of registered memory remove its registration on Windows (SECURITY.md, Not at parity yet)"]
    fn test_memory_replaced_while_registered_is_in_no_registration() {
        replace_cases("replaced_no_registration_child");
    }

    #[test]
    #[ignore = "run by test_memory_replaced_while_registered_is_in_no_registration in processes of its own"]
    fn replaced_no_registration_child() {
        watchdog(60);
        let mut c = Checks::new();
        let (a, _ua, _b, _ub, mem) = replaced();
        if let Some((r, _)) = find(mem) {
            let alias = r.alias.load(Ordering::Acquire);
            std::println!(
                "UNMAP the old range's alias at [{alias:#x}, {:#x}), the page a fill of {:#x} writes through at {:#x}",
                alias + (r.end.load(Ordering::Acquire) - r.start.load(Ordering::Acquire)),
                mem + PAGE,
                alias + PAGE
            );
        }
        c.check(!is_missing(mem) && !is_missing(mem + PAGE), "the new memory is missing");
        // An access fault there, as the handler sees it, on a thread of its
        // own: a userfault waits for a fill that never comes.
        let faulted = std::thread::spawn(move || fault(mem + 3 * PAGE, false));
        let waited = !holds_within(|| faulted.is_finished());
        std::println!("UNMAP an access fault on the new memory: {}", if waited { "waits as a userfault (10 s)" } else { "no userfault" });
        c.check(!waited, "an access fault on the new memory waits as a userfault");
        std::println!("UNMAP a zero page into the new memory follows");
        let z = zeropage(a, mem + PAGE, PAGE, true);
        std::println!("UNMAP a zero page into the new memory: {z:?}; the page now {:x?}", states(mem + PAGE, PAGE));
        c.check(z == Err((crate::ENOENT, 0)), std::format!("a zero page into the new memory: {z:?}"));
        std::println!("UNMAP the copy into the new memory follows");
        // SAFETY: a page.
        let f = unsafe { copy(a, page_of(0x77).as_ptr(), mem + 2 * PAGE, PAGE, true) };
        std::println!("UNMAP the copy into the new memory: {f:?}; the page now {:x?}", states(mem + 2 * PAGE, PAGE));
        c.check(f == Err((crate::ENOENT, 0)), std::format!("a copy into the new memory: {f:?}"));
        c.done();
    }

    /// The new memory registers anew, with the same userfaultfd or another
    /// (Linux's new vma has no userfaultfd: mm/mmap.c, v6.12,
    /// `__mmap_region` :1386 and `vm_area_alloc` :1435; `userfaultfd_register`
    /// refuses only a vma another userfaultfd has, fs/userfaultfd.c :1363 to
    /// :1366), and a fill lands in the new memory.
    #[test]
    #[ignore = "fails until munmap and MAP_FIXED of registered memory remove its registration on Windows (SECURITY.md, Not at parity yet)"]
    fn test_memory_replaced_while_registered_registers_anew() {
        replace_cases("replaced_registers_anew_child");
    }

    #[test]
    #[ignore = "run by test_memory_replaced_while_registered_registers_anew in processes of its own"]
    fn replaced_registers_anew_child() {
        watchdog(60);
        let mut c = Checks::new();
        let (a, _ua, b, _ub, mem) = replaced();
        let again = register(a, mem, UNMAP_LEN);
        c.check(again.is_ok(), std::format!("its userfaultfd's register of the new memory: {again:?}"));
        if again.is_ok() {
            c.check(is_missing(mem) && is_missing(mem + PAGE), "the new pages are not missing");
            // SAFETY: a page.
            let f = unsafe { copy(a, page_of(0x77).as_ptr(), mem + PAGE, PAGE, true) };
            c.check(f == Ok(PAGE), std::format!("a fill of the new memory: {f:?}"));
            if f == Ok(PAGE) {
                // SAFETY: filled just now.
                let got = unsafe { ptr::read_volatile((mem + PAGE) as *const u8) };
                c.check(got == 0x77, std::format!("the fill did not reach the new memory: {got:#x}"));
            }
            c.check(unregister(a, mem, UNMAP_LEN).is_ok(), "the unregister");
        }
        let other = register(b, mem, UNMAP_LEN);
        c.check(other.is_ok(), std::format!("another userfaultfd's register of the new memory: {other:?}"));
        c.done();
    }

    /// A discard of the new memory is an ordinary one: its pages read zeros
    /// and stay accessible, as Linux's `MADV_DONTNEED` of memory no
    /// userfaultfd has (mm/madvise.c, v6.12, `madvise_dontneed_free` :880,
    /// fs/userfaultfd.c :777 to :779, `madvise_dontneed_single_vma` :846).
    #[test]
    #[ignore = "fails until munmap and MAP_FIXED of registered memory remove its registration on Windows (SECURITY.md, Not at parity yet)"]
    fn test_a_discard_of_memory_replaced_while_registered_is_ordinary() {
        replace_cases("replaced_discard_child");
    }

    #[test]
    #[ignore = "run by test_a_discard_of_memory_replaced_while_registered_is_ordinary in processes of its own"]
    fn replaced_discard_child() {
        watchdog(60);
        let mut c = Checks::new();
        let (_a, _ua, _b, _ub, mem) = replaced();
        // SAFETY: the new memory, read-write.
        unsafe { ptr::write_volatile(mem as *mut u8, 7) };
        // SAFETY: the new memory.
        c.check(unsafe { crate::madvise(mem as *mut c_void, 2 * PAGE as usize, crate::MADV_DONTNEED) } == 0, "the discard");
        c.check(!is_missing(mem) && !is_missing(mem + PAGE), "the discard made the new memory missing");
        c.check(host_readable(mem), std::format!("the discarded new memory is closed: {:x?}", states(mem, PAGE)));
        if host_readable(mem) {
            // SAFETY: readable.
            c.check(unsafe { ptr::read_volatile(mem as *const u8) } == 0, "the discarded page is not zeros");
        }
        c.done();
    }

    /// A thread waiting on a page whose memory is mapped over waits on (no
    /// event or wake comes of the unmapping without
    /// `UFFD_FEATURE_EVENT_UNMAP`) until its userfaultfd's `UFFDIO_WAKE`,
    /// which checks the range only (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_wake` :1545 to :1575), or its release, which wakes every
    /// waiter (`userfaultfd_release` :873); it then runs its access again,
    /// here on new memory, which it reads.
    #[test]
    #[ignore = "fails until munmap and MAP_FIXED of registered memory remove its registration on Windows (SECURITY.md, Not at parity yet)"]
    fn test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd() {
        let (code, text, _) = run_child_in_jobs("waiter_mapped_over_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd in a process of its own"]
    fn waiter_mapped_over_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            let waiter = |at: u64| {
                std::thread::spawn(move || {
                    assert!(fault(at, false), "not missing");
                    // SAFETY: the memory mapped over it, readable.
                    unsafe { ptr::read_volatile(at as *const u8) }
                })
            };
            let (first, second) = (waiter(mem), waiter(mem + PAGE));
            let waiting = |at: u64| WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == at);
            assert!(holds_within(|| waiting(mem) && waiting(mem + PAGE)), "{kind}: the waiters");
            assert_eq!(map_fixed(mem, UNMAP_LEN, crate::PROT_READ | crate::PROT_WRITE), mem, "{kind}");
            // SAFETY: the new memory, read-write.
            unsafe { ptr::write_bytes(mem as *mut u8, 7, 2 * PAGE as usize) };
            c.check(find(mem).is_none(), std::format!("{kind}: the memory mapped over is still registered"));
            c.check(!first.is_finished() && !second.is_finished(), std::format!("{kind}: a waiter went on with no wake"));
            let w = wake_range(ctx, mem, PAGE);
            c.check(w == Ok(()), std::format!("{kind}: UFFDIO_WAKE of the first page: {w:?}"));
            let woke = holds_within(|| first.is_finished());
            c.check(woke, std::format!("{kind}: the wake did not wake the first waiter"));
            c.check(!second.is_finished(), std::format!("{kind}: the wake of one page woke the other"));
            release(ctx, user);
            let woke2 = holds_within(|| second.is_finished());
            c.check(woke2, std::format!("{kind}: the release did not wake the second waiter"));
            if woke {
                c.check(first.join().unwrap() == 7, std::format!("{kind}: the first read"));
            }
            if woke2 {
                c.check(second.join().unwrap() == 7, std::format!("{kind}: the second read"));
            }
            if !(woke && woke2) {
                std::println!("UNMAP {kind}: a waiter was left waiting; the child ends here");
                c.done();
                return;
            }
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// A thread waiting on a page whose memory is unmapped, once its
    /// userfaultfd wakes it, runs its access again and takes the process's
    /// own fault, as on Linux, where the address has no vma: here an access
    /// violation no handler takes, which ends the child (0xC0000005).
    #[test]
    #[ignore = "fails until munmap and MAP_FIXED of registered memory remove its registration on Windows (SECURITY.md, Not at parity yet)"]
    fn test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken() {
        for kind in MEM_KINDS {
            let (code, text, _) = run_child_in_jobs("waiter_unmapped_child", &[("WICK_UFFD_KIND", kind)], &[]);
            for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
                std::eprintln!("{kind}: {l}");
            }
            assert_eq!(code, Some(0xC000_0005_u32.cast_signed()), "{kind}: {text}");
        }
    }

    #[test]
    #[ignore = "run by test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken in a process of its own"]
    fn waiter_unmapped_child() {
        watchdog(20);
        let kind = std::env::var("WICK_UFFD_KIND").unwrap();
        let (ctx, _user) = create(0, false, true).unwrap();
        let mem = map_of(&kind);
        register(ctx, mem, UNMAP_LEN).unwrap();
        let _reader = std::thread::spawn(move || {
            // SAFETY: registered memory: the read waits, then runs again.
            unsafe { ptr::read_volatile(mem as *const u8) }
        });
        assert!(holds_within(|| WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == mem)), "the waiter");
        assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        let w = wake_range(ctx, mem, PAGE);
        std::println!("UNMAP UFFDIO_WAKE of the unmapped page: {w:?}");
        std::thread::sleep(std::time::Duration::from_secs(5));
        let again = WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == mem);
        std::println!("UNMAP 5 s after the wake the reader is {}", if again { "waiting again on the unmapped page" } else { "not waiting" });
        std::process::exit(4);
    }

    /// Memory mapped over one page of a registered range and registered
    /// again by the same userfaultfd is filled in the new memory.
    #[test]
    #[ignore = "fails until a slot holds only registered pages on Windows (SECURITY.md, Not at parity yet: MAP_FIXED over part of a registered mapping is EINVAL)"]
    fn test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory() {
        let (code, text, _) = run_child_in_jobs("page_mapped_over_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory in a process of its own"]
    fn page_mapped_over_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            // SAFETY: a page.
            assert_eq!(unsafe { copy(ctx, page_of(0x11).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            let p = map_fixed(mem + PAGE, PAGE, crate::PROT_READ | crate::PROT_WRITE);
            let err = io::Error::last_os_error();
            std::println!("UNMAP {kind}: MAP_FIXED over one registered page: {p:#x} ({})", if p == mem + PAGE { "made".into() } else { std::format!("{err}") });
            c.check(p == mem + PAGE, std::format!("{kind}: MAP_FIXED over one registered page: {err}"));
            if p == mem + PAGE {
                c.check(!is_missing(mem + PAGE) && !is_missing(mem), std::format!("{kind}: missing after the MAP_FIXED"));
                let z = zeropage(ctx, mem + PAGE, PAGE, true);
                c.check(z == Err((crate::ENOENT, 0)), std::format!("{kind}: a fill of the new page: {z:?}"));
                let r = register(ctx, mem + PAGE, PAGE);
                c.check(r.is_ok(), std::format!("{kind}: the register of the new page: {r:?}"));
                if r.is_ok() {
                    c.check(is_missing(mem + PAGE), std::format!("{kind}: the new page is not missing"));
                    // SAFETY: a page.
                    let f = unsafe { copy(ctx, page_of(0x77).as_ptr(), mem + PAGE, PAGE, true) };
                    c.check(f == Ok(PAGE), std::format!("{kind}: the fill of the new page: {f:?}"));
                    // SAFETY: filled pages.
                    unsafe {
                        c.check(ptr::read_volatile((mem + PAGE) as *const u8) == 0x77, std::format!("{kind}: the fill did not reach the new memory"));
                        c.check(ptr::read_volatile(mem as *const u8) == 0x11, std::format!("{kind}: the first page changed"));
                    }
                }
            }
            release(ctx, user);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// A munmap or a `MAP_FIXED` mapping that cuts a huge page of a
    /// registered huge page range is `EINVAL` with nothing changed (Linux
    /// refuses to split a hugetlb vma off a huge page boundary, mm/vma.c,
    /// v6.12, `__split_vma` :377 to :378, called by `vms_gather_munmap_vmas`
    /// at :1209 and :1230); on the boundaries, the huge pages leave the
    /// registration.
    #[test]
    #[ignore = "no registered huge page on Windows (docs/COMPATIBILITY.md, the mem_backend Uffd row: a huge page mapping is not registered)"]
    fn test_a_cut_of_a_registered_huge_page_is_einval() {
        let (code, text, _) = run_child_in_jobs("huge_cut_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_cut_of_a_registered_huge_page_is_einval in a process of its own"]
    fn huge_cut_child() {
        const HUGE: u64 = 2 << 20;
        watchdog(60);
        let mut c = Checks::new();
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * HUGE;
        // SAFETY: a huge page mapping of this libc.
        let mem = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_HUGETLB | crate::MAP_HUGE_2MB,
                -1,
                0,
            )
        } as u64;
        let err = io::Error::last_os_error();
        std::println!("UNMAP the huge page mapping: {}", if mem == crate::MAP_FAILED as u64 { std::format!("{err}") } else { std::format!("{mem:#x}") });
        assert_ne!(mem, crate::MAP_FAILED as u64, "the huge page mapping: {err}");
        let r = register(ctx, mem, len);
        std::println!("UNMAP the register of the huge page mapping: {r:?}");
        c.check(r.is_ok(), std::format!("the register of a huge page mapping: {r:?}"));
        if r.is_ok() {
            c.check(munmap_of(mem + PAGE, PAGE) == -1 && io::Error::last_os_error().raw_os_error() == Some(crate::EINVAL), "munmap of a page inside");
            c.check(map_fixed(mem + HUGE - PAGE, 2 * PAGE, crate::PROT_READ | crate::PROT_WRITE) == crate::MAP_FAILED as u64, "MAP_FIXED across a huge page boundary");
            for off in [0, PAGE, HUGE - PAGE, HUGE, len - PAGE] {
                c.check(is_missing(mem + off), std::format!("{off:#x}: changed by a refused call"));
            }
            c.check(munmap_of(mem + HUGE, HUGE) == 0, "munmap of the second huge page");
            c.check(is_missing(mem) && !is_missing(mem + HUGE), "the second huge page is still registered");
            let z = zeropage(ctx, mem + HUGE, HUGE, true);
            c.check(z == Err((crate::ENOENT, 0)), std::format!("a fill of the unmapped huge page: {z:?}"));
        }
        release(ctx, user);
        c.done();
    }

    /// A fill whose destination holds a page in no registration is
    /// `ENOENT` for the whole call, nothing filled (mm/userfaultfd.c, v6.12,
    /// `validate_dst_vma` :23 to :37, `uffd_mfill_lock` :113: the
    /// destination must lie in one vma this userfaultfd has; an unregister
    /// of a page in the middle splits the vma).
    #[test]
    #[ignore = "fails until munmap and MAP_FIXED of registered memory remove its registration on Windows (SECURITY.md, Not at parity yet)"]
    fn test_a_fill_of_an_unregistered_page_is_enoent() {
        for kind in MEM_KINDS {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            assert_eq!(unregister(ctx, mem + PAGE, PAGE), Ok(()));
            let data = std::vec![0x5au8; 3 * PAGE as usize];
            // SAFETY: `data` holds three pages.
            let f = unsafe { copy(ctx, data.as_ptr(), mem, 3 * PAGE, true) };
            let still = is_missing(mem);
            release(ctx, user);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
            assert_eq!(f, Err((crate::ENOENT, 0)), "{kind}: the fill across the unregistered page");
            assert!(still, "{kind}: the page before it was filled");
        }
    }
}
