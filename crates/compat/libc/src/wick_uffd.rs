// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The kernel side of Linux's userfaultfd, on macOS.
//!
//! On Linux, an access to a missing page of memory registered with a
//! userfaultfd queues a page fault event on the descriptor and puts the
//! faulting thread to sleep until a handler fills the page (`UFFDIO_COPY`,
//! `UFFDIO_ZEROPAGE`) and wakes it (`UFFDIO_WAKE`). KVM takes the same path for
//! guest accesses: it resolves stage-2 faults with `get_user_pages`, which
//! faults the host page. This module gives the process those semantics:
//!
//! - Host threads: missing pages are `PROT_NONE`. The `SIGBUS`/`SIGSEGV`
//!   handler queues a page fault event and waits in a waiter slot; signals on
//!   other addresses go to the previous handler.
//! - Guests: Hypervisor.framework does not honour host protections, so the HVF
//!   backend keeps missing pages inaccessible in stage 2
//!   ([`crate::wick_guest::Hooks::stage2`]) and resolves stage-2 faults with
//!   [`fault`].
//! - Pages are filled through a second mapping of the same memory
//!   (`mach_vm_remap`) and only then made accessible, so no thread sees a page
//!   half filled.
//! - `madvise(MADV_DONTNEED)` on registered pages makes them missing again and
//!   queues a remove event ([`discarding`]).
//!
//! A userfaultfd is one end of a socket pair. Events are [`RECORD`]-byte
//! records read from it ([`proto`]). Another process holding the descriptor
//! sends its requests over a private channel it sets up through it; a thread
//! per userfaultfd serves them.

use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::boxed::Box;
use std::io;
use std::sync::{Mutex, Once};
use std::vec::Vec;

use upstream as libc;

/// Wire format shared with the `userfaultfd` crate.
pub mod proto {
    /// Size of an event, a request header and a reply: four `u64` words.
    pub const RECORD: usize = 32;
    /// Event: `[EVENT_PAGEFAULT, addr, flags, 0]`.
    pub const EVENT_PAGEFAULT: u64 = 1;
    /// Event: `[EVENT_REMOVE, start, end, 0]`.
    pub const EVENT_REMOVE: u64 = 2;
    /// Page fault flag: the access was a write.
    pub const FLAG_WRITE: u64 = 1;
    /// Sent on the userfaultfd with a descriptor: `[HELLO, 0, 0, 0]`. The
    /// descriptor is the sender's end of its request channel.
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

const MAX_RANGES: usize = 64;
/// `VM_FLAGS_ANYWHERE`.
const VM_FLAGS_ANYWHERE: c_int = 1;
/// `VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE`: at the address given, replacing
/// what is mapped there.
const VM_FLAGS_FIXED_OVERWRITE: c_int = 0x4000;
const MAX_CTX: usize = 16;
const MAX_WAITERS: usize = 256;

/// A registered range. Its bitmaps are never freed: the signal handler may be
/// reading them.
struct Range {
    /// 0: free.
    start: AtomicU64,
    end: AtomicU64,
    ctx: AtomicUsize,
    /// The page size of the range: the host's, or the huge page's for a
    /// `MAP_HUGETLB` mapping ([`note_mapping`]), where a fault is reported
    /// for and a fill covers a whole huge page, as Linux's hugetlb does.
    page: AtomicU64,
    /// Second mapping of `[start, end)`, always readable and writable.
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
            page: AtomicU64::new(0),
            alias: AtomicU64::new(0),
            missing: AtomicPtr::new(ptr::null_mut()),
            tracked: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// The range's page size.
    fn page_size(&self) -> u64 {
        self.page.load(Ordering::Acquire)
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
    /// A Mach semaphore.
    sem: AtomicU64,
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
        sem: AtomicU64::new(0),
    }
}; MAX_WAITERS];
static PAGE: AtomicU64 = AtomicU64::new(0);
/// The `MAP_HUGETLB` mappings made through the compatibility `mmap`
/// (`[start, end)`): a userfaultfd registered on one works in huge pages.
/// A mapping made over one without the flag takes its place; an unmapped
/// one is forgotten when something is mapped over it.
static HUGE_MAPPINGS: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
/// Held by every test that makes huge page mappings: what [`huge_page_of`]
/// answers for an address next to a test's mapping is then that test's own,
/// not a huge mapping another test made there in the meantime.
#[cfg(test)]
pub(crate) fn huge_mapping_test() -> std::sync::MutexGuard<'static, ()> {
    static TESTS: Mutex<()> = Mutex::new(());
    TESTS.lock().unwrap_or_else(|e| e.into_inner())
}
/// Number of registered ranges (the I/O wrappers skip all work at 0).
static REGISTERED: AtomicUsize = AtomicUsize::new(0);
/// Serializes changes to the ranges.
static LOCK: Mutex<()> = Mutex::new(());
static INIT: Once = Once::new();
static OLD_SIGBUS: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());
static OLD_SIGSEGV: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" {
    static mach_task_self_: libc::mach_port_t;
    fn semaphore_create(
        task: libc::mach_port_t,
        semaphore: *mut u32,
        policy: c_int,
        value: c_int,
    ) -> c_int;
    fn semaphore_signal(semaphore: u32) -> c_int;
    fn semaphore_wait(semaphore: u32) -> c_int;
    fn mach_vm_region(
        target_task: libc::mach_port_t,
        address: *mut u64,
        size: *mut u64,
        flavor: c_int,
        info: *mut c_int,
        count: *mut u32,
        object_name: *mut libc::mach_port_t,
    ) -> c_int;
    fn mach_vm_remap(
        target_task: libc::mach_port_t,
        target_address: *mut u64,
        size: u64,
        mask: u64,
        flags: c_int,
        src_task: libc::mach_port_t,
        src_address: u64,
        copy: c_int,
        cur_protection: *mut c_int,
        max_protection: *mut c_int,
        inheritance: u32,
    ) -> c_int;
}

/// The host's page size.
fn page_size() -> u64 {
    PAGE.load(Ordering::Relaxed)
}

/// Records a mapping `[start, start + len)` the compatibility `mmap` made,
/// with or without `MAP_HUGETLB`.
pub fn note_mapping(start: u64, len: u64, huge: bool) {
    let end = start.saturating_add(len);
    let mut all = HUGE_MAPPINGS.lock().unwrap();
    let mut kept = Vec::with_capacity(all.len() + 2);
    for &(s, e) in all.iter() {
        if e <= start || s >= end {
            kept.push((s, e));
            continue;
        }
        if s < start {
            kept.push((s, start));
        }
        if e > end {
            kept.push((end, e));
        }
    }
    if huge {
        kept.push((start, end));
    }
    *all = kept;
}

/// The first part of `[start, end)` that is all huge page mappings or all
/// ordinary memory: its end, and whether it is huge.
pub fn huge_segment(start: u64, end: u64) -> (u64, bool) {
    let all = HUGE_MAPPINGS.lock().unwrap();
    if let Some(&(_, e)) = all.iter().find(|&&(s, e)| s <= start && start < e) {
        return (e.min(end), true);
    }
    let next = all.iter().map(|&(s, _)| s).filter(|&s| s > start).min().unwrap_or(end);
    (next.min(end), false)
}

/// Whether any of `[start, end)` is a huge page mapping.
pub fn touches_huge(start: u64, end: u64) -> bool {
    let all = HUGE_MAPPINGS.lock().unwrap();
    all.iter().any(|&(s, e)| s < end && start < e)
}

/// The page size of `[start, end)` if all of it is huge page mappings:
/// [`crate::linux_items::HUGE_PAGE`]; `None` for ordinary memory, or for a
/// range only part of which is huge (one range has one page size).
pub fn huge_page_of(start: u64, end: u64) -> Option<u64> {
    let all = HUGE_MAPPINGS.lock().unwrap();
    let mut at = start;
    while at < end {
        // Adjacent huge mappings (one made fixed over part of another) are
        // kept as separate entries.
        at = all.iter().find(|&&(s, e)| s <= at && at < e)?.1;
    }
    Some(crate::linux_items::HUGE_PAGE)
}

fn errno_err(errno: c_int) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

fn init() -> io::Result<()> {
    let mut result = Ok(());
    INIT.call_once(|| {
        // SAFETY: sysconf has no preconditions.
        PAGE.store(
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64,
            Ordering::Relaxed,
        );
        for w in WAITERS.iter() {
            let mut sem = 0u32;
            // SAFETY: creates a semaphore owned by this task.
            if unsafe { semaphore_create(mach_task_self_, &mut sem, 0, 0) } != 0 {
                result = Err(errno_err(libc::ENOMEM));
                return;
            }
            w.sem.store(u64::from(sem), Ordering::Release);
        }
        for (sig, old) in [(libc::SIGBUS, &OLD_SIGBUS), (libc::SIGSEGV, &OLD_SIGSEGV)] {
            // SAFETY: installs a handler; the previous one is kept for chaining.
            unsafe {
                let mut act: libc::sigaction = core::mem::zeroed();
                act.sa_sigaction = on_signal as *const () as usize;
                act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
                libc::sigemptyset(&mut act.sa_mask);
                let prev = Box::into_raw(Box::new(core::mem::zeroed::<libc::sigaction>()));
                if libc::sigaction(sig, &act, prev) != 0 {
                    result = Err(io::Error::last_os_error());
                    return;
                }
                old.store(prev, Ordering::Release);
            }
        }
    });
    if PAGE.load(Ordering::Relaxed) == 0 {
        return Err(errno_err(libc::ENOMEM));
    }
    result
}

/// The range and page index of `addr`, if it is registered memory.
fn find(addr: u64) -> Option<(&'static Range, u64)> {
    for r in RANGES.iter() {
        let start = r.start.load(Ordering::Acquire);
        if start != 0 && addr >= start && addr < r.end.load(Ordering::Acquire) {
            return Some((r, (addr - start) / r.page_size()));
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

fn post(ctx: usize, record: [u64; 4]) {
    let fd = CTXS[ctx].fd.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    let mut bytes = [0u8; proto::RECORD];
    for (i, w) in record.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    let mut done = 0;
    while done < bytes.len() {
        // SAFETY: async-signal-safe write of a local buffer.
        let n = unsafe { libc::write(fd, bytes[done..].as_ptr().cast(), bytes.len() - done) };
        if n <= 0 {
            // SAFETY: reads this thread's errno.
            if n < 0 && unsafe { *libc::__error() } == libc::EINTR {
                continue;
            }
            // The handler side is gone: nobody will serve the fault.
            return;
        }
        done += n as usize;
    }
}

/// Resolves an access to `addr`: if it is a missing registered page, queues
/// a page fault event and waits until the page is filled and the waiters are
/// woken. Returns false if `addr` is not a missing registered page.
/// Async-signal-safe.
pub fn fault(addr: u64, write: bool) -> bool {
    let Some((range, page)) = find(addr) else {
        return false;
    };
    if !Range::test(&range.tracked, page) || !Range::test(&range.missing, page) {
        return false;
    }
    let page_addr = range.start.load(Ordering::Acquire) + page * range.page_size();
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
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000,
        };
        // SAFETY: async-signal-safe sleep.
        unsafe { libc::nanosleep(&ts, ptr::null_mut()) };
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
            // SAFETY: a semaphore created at init; Mach traps are async-signal-safe.
            unsafe { semaphore_wait(slot.sem.load(Ordering::Acquire) as u32) };
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
            unsafe { semaphore_signal(w.sem.load(Ordering::Acquire) as u32) };
        }
    }
}

extern "C" fn on_signal(sig: c_int, info: *mut libc::siginfo_t, uctx: *mut libc::c_void) {
    // SAFETY: the kernel passes a valid siginfo.
    let addr = unsafe { (*info).si_addr } as u64;
    if is_missing(addr) {
        // ESR from the thread state: uc_mcontext (offset 48) -> __es.__esr (offset 8).
        // SAFETY: the Darwin arm64 ucontext and mcontext layout.
        let esr = unsafe {
            let mcontext = *(uctx.cast::<u8>().add(48).cast::<*const u8>());
            *(mcontext.add(8).cast::<u32>())
        };
        let ec = esr >> 26;
        let write = (ec == 0x24 || ec == 0x25) && esr & (1 << 6) != 0;
        if fault(addr, write) {
            // Retry the access.
            return;
        }
    }
    let old = if sig == libc::SIGBUS {
        &OLD_SIGBUS
    } else {
        &OLD_SIGSEGV
    };
    let old = old.load(Ordering::Acquire);
    // SAFETY: the action saved at init.
    let act = unsafe { &*old };
    if act.sa_flags & libc::SA_SIGINFO != 0 && act.sa_sigaction > 1 {
        // SAFETY: chaining to the previous handler with the same arguments.
        let f: extern "C" fn(c_int, *mut libc::siginfo_t, *mut libc::c_void) =
            unsafe { core::mem::transmute(act.sa_sigaction) };
        f(sig, info, uctx);
    } else if act.sa_sigaction == libc::SIG_IGN {
        // Returning would fault again forever: take the default action.
        // SAFETY: resets the disposition; the access faults again and dies.
        unsafe { libc::signal(sig, libc::SIG_DFL) };
    } else if act.sa_sigaction == libc::SIG_DFL {
        // SAFETY: as above.
        unsafe { libc::signal(sig, libc::SIG_DFL) };
    } else {
        // SAFETY: a plain handler.
        let f: extern "C" fn(c_int) = unsafe { core::mem::transmute(act.sa_sigaction) };
        f(sig);
    }
}

/// Tells the HVF backend ([`crate::wick_guest::Hooks::stage2`]) that
/// registered pages became present (they must be accessible to the guest)
/// or missing (they must fault).
fn stage2(start: u64, len: u64, present: bool) {
    crate::wick_guest::stage2(start, len, present);
}

/// Calls `f(start, len)` for each run of missing registered pages in
/// `[start, start + len)`, in the pages of each range (a huge page is
/// whole; host pages outside the ranges).
pub fn for_each_missing(start: u64, len: u64, mut f: impl FnMut(u64, u64)) {
    let ps = page_size();
    if ps == 0 {
        return;
    }
    let end = start.saturating_add(len);
    let mut run: Option<u64> = None;
    let mut addr = start - start % ps;
    while addr < end {
        // The page holding `addr`, the one after it, and whether it is missing.
        let (page_start, next, missing) = match find(addr) {
            Some((r, page)) => {
                let (base, rps) = (r.start.load(Ordering::Acquire), r.page_size());
                let page_start = base + page * rps;
                let missing = Range::test(&r.tracked, page) && Range::test(&r.missing, page);
                (page_start, page_start + rps, missing)
            }
            // Unregistered memory holds no missing page: on to the next
            // range (a walk by host pages over a span as large as a
            // `MADV_DONTNEED` may name would not end).
            None => {
                let next = RANGES
                    .iter()
                    .map(|r| r.start.load(Ordering::Acquire))
                    .filter(|&s| s > addr)
                    .min()
                    .unwrap_or(end)
                    .min(end);
                (addr, next.max(addr + ps), false)
            }
        };
        match (missing, run) {
            (true, None) => run = Some(page_start),
            (false, Some(s)) => {
                f(s, page_start - s);
                run = None;
            }
            _ => {}
        }
        addr = next;
    }
    if let Some(s) = run {
        f(s, addr - s);
    }
}

fn protect(addr: u64, len: u64, prot: c_int) -> io::Result<()> {
    // SAFETY: changes the protection of registered memory only.
    if unsafe { libc::mprotect(addr as *mut _, len as usize, prot) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Creates a userfaultfd. Returns its index and the user's descriptor (the
/// other end stays with the serving thread).
pub fn create(features: u64, nonblocking: bool, cloexec: bool) -> io::Result<(usize, c_int)> {
    init()?;
    let mut fds = [0 as c_int; 2];
    // SAFETY: creates two descriptors.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let [kernel, user] = fds;
    let one: c_int = 1;
    let buf: c_int = 1 << 20;
    // SAFETY: plain socket and descriptor options.
    unsafe {
        for fd in fds {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&one as *const c_int).cast(),
                4,
            );
        }
        libc::setsockopt(
            kernel,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&buf as *const c_int).cast(),
            4,
        );
        libc::fcntl(kernel, libc::F_SETFD, libc::FD_CLOEXEC);
        if cloexec {
            libc::fcntl(user, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        if nonblocking {
            let fl = libc::fcntl(user, libc::F_GETFL);
            libc::fcntl(user, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
    let _guard = LOCK.lock().unwrap();
    let Some(index) = CTXS.iter().position(|c| {
        c.fd.compare_exchange(-1, kernel, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        // SAFETY: closes the descriptors created above.
        unsafe {
            libc::close(kernel);
            libc::close(user);
        }
        return Err(errno_err(libc::EMFILE));
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

/// Whether any of `[start, end)` is the alias of a registered range. A fill
/// writes through the alias holding [`LOCK`]: were the alias registered
/// itself, the fill would fault on its missing pages and wait for a fill
/// of them, which needs [`LOCK`], forever. Linux fills page tables and has
/// no alias; this is memory a userfaultfd cannot take, refused with
/// `EINVAL` as Linux refuses such a vma (`vma_can_userfault`), not `EBUSY`,
/// which says another userfaultfd has the memory until it unregisters it.
fn overlaps_an_alias(start: u64, end: u64) -> bool {
    RANGES.iter().any(|r| {
        let s = r.start.load(Ordering::Acquire);
        let alias = r.alias.load(Ordering::Acquire);
        s != 0 && alias != 0 && start < alias + (r.end.load(Ordering::Acquire) - s) && alias < end
    })
}

/// One past the highest address a process maps: `MACH_VM_MAX_ADDRESS`
/// (mach/arm/vm_param.h, 128 TiB less 32 MiB), what Linux's
/// `validate_range` checks against its `TASK_SIZE`.
const TASK_SIZE: u64 = 0x0000_7FFF_FE00_0000;

/// Linux's `validate_range` (fs/userfaultfd.c): a start aligned to host
/// pages and not 0 (Linux: below `mmap_min_addr`), a length of whole host
/// pages and not 0, the range below [`TASK_SIZE`], else `EINVAL`. Returns
/// the range's end.
fn validate_range(start: u64, len: u64) -> Result<u64, c_int> {
    let host = page_size();
    if host == 0
        || start == 0
        || !start.is_multiple_of(host)
        || len == 0
        || !len.is_multiple_of(host)
        || start >= TASK_SIZE
        || len > TASK_SIZE - start
    {
        return Err(libc::EINVAL);
    }
    Ok(start + len)
}

/// The VM map entries in `[start, end)`, cut to it, in order: Linux's vmas
/// of the range, holes left out. Each with whether all of it is readable
/// and writable.
fn mapped_entries(start: u64, end: u64) -> Vec<(u64, u64, bool)> {
    const VM_REGION_BASIC_INFO_64: c_int = 9;
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let mut entries = Vec::new();
    let mut at = start;
    while at < end {
        let (mut addr, mut size, mut object) = (at, 0u64, 0);
        let mut info = [0 as c_int; 16];
        let mut count = 9u32;
        // SAFETY: valid output buffers, `info` larger than the flavor's 9
        // words. The entry at or after `addr`; KERN_INVALID_ADDRESS when
        // there is none.
        let kr = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut addr,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if kr != 0 || addr >= end || size == 0 {
            break;
        }
        // vm_region_basic_info_64 starts with the current protection
        // (VM_PROT_* bits are PROT_* bits).
        entries.push((addr.max(at), (addr + size).min(end), info[0] & rw == rw));
        at = addr + size;
    }
    entries
}

/// The occupied range slots that overlap `[start, end)`.
fn slots(start: u64, end: u64) -> impl Iterator<Item = &'static Range> {
    RANGES.iter().filter(move |r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    })
}

/// Which of the `len / ps` pages from `start` on are missing: a page is
/// when any host page of it is not resident. Residency is Linux's, where a
/// page the compressor or swap holds has data and is not missing
/// (crate::mincore).
fn missing_pages(start: u64, len: u64, ps: u64) -> io::Result<Vec<bool>> {
    let host = page_size();
    let mut resident = std::vec![0u8; (len / host) as usize];
    // SAFETY: `resident` has one byte per host page of the range.
    if unsafe { crate::mincore(start as *mut _, len as usize, resident.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(resident
        .chunks((ps / host) as usize)
        .map(|page| page.iter().any(|r| r & 1 == 0))
        .collect())
}

/// Whether all of `[start, end)` is in registered ranges, whose missing
/// pages are inaccessible only to make accesses fault: to the process they
/// are readable and writable memory.
fn all_registered(start: u64, end: u64) -> bool {
    let mut spans: Vec<(u64, u64)> = slots(start, end)
        .map(|r| (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire)))
        .collect();
    spans.sort_unstable();
    let mut at = start;
    for (s, e) in spans {
        if s > at {
            return false;
        }
        at = at.max(e);
    }
    at >= end
}

/// Whether any page of the range in slot `r` is still registered.
fn any_tracked(r: &Range) -> bool {
    let pages = (r.end.load(Ordering::Acquire) - r.start.load(Ordering::Acquire)) / r.page_size();
    (0..pages).any(|page| Range::test(&r.tracked, page))
}

/// Frees slot `r`: its range is no longer registered memory and its alias
/// goes. Its bitmaps stay (the signal handler may be reading them).
fn release(r: &Range) {
    let s = r.start.swap(0, Ordering::AcqRel);
    REGISTERED.fetch_sub(1, Ordering::AcqRel);
    let alias = r.alias.swap(0, Ordering::AcqRel);
    if alias != 0 {
        // SAFETY: unmaps the alias created at register.
        unsafe { libc::munmap(alias as *mut _, (r.end.load(Ordering::Acquire) - s) as usize) };
    }
}

/// Registers `[start, start + len)` with userfaultfd `ctx`, as Linux's
/// `userfaultfd_register` (fs/userfaultfd.c, v6.12): the range is checked
/// as `validate_range` checks it, then every VM map entry in it, in order
/// (holes are left out; none at all is `EINVAL`), and the first entry that
/// fails decides, with nothing registered:
///
/// - the alias of a registered range: `EINVAL` ([`overlaps_an_alias`]);
/// - not readable and writable: `EPERM` (Linux refuses only memory that can
///   never be written, and takes anonymous memory with other protections,
///   which fills here would change); registered memory is, whatever its
///   missing pages' protection ([`all_registered`]);
/// - a `MAP_HUGETLB` mapping ([`note_mapping`]) that holds the start or the
///   end of the range not at a huge page boundary: `EINVAL`;
/// - registered with another userfaultfd: `EBUSY`. Pages this one has are
///   left as they are, as Linux leaves a vma already registered with it.
///
/// Pages that are not resident are missing from now on. A `MAP_HUGETLB`
/// mapping is registered in huge pages: a huge page is missing when any
/// host page of it is, and faults and fills work on whole huge pages.
pub fn register(ctx: usize, start: u64, len: u64) -> io::Result<()> {
    let end = validate_range(start, len).map_err(errno_err)?;
    let huge = crate::linux_items::HUGE_PAGE;
    let _guard = LOCK.lock().unwrap();
    let entries = mapped_entries(start, end);
    let Some(&(first, first_end, _)) = entries.first() else {
        return Err(errno_err(libc::EINVAL));
    };
    if huge_segment(first, first_end).1 && !start.is_multiple_of(huge) {
        return Err(errno_err(libc::EINVAL));
    }
    // The parts to register: the entries, cut where huge page mappings
    // begin and end, adjacent ones of one page size joined.
    let mut parts: Vec<(u64, u64, u64)> = Vec::new();
    for &(s, e, rw) in &entries {
        if overlaps_an_alias(s, e) {
            return Err(errno_err(libc::EINVAL));
        }
        if !rw && !all_registered(s, e) {
            return Err(errno_err(libc::EPERM));
        }
        let mut at = s;
        while at < e {
            let (next, is_huge) = huge_segment(at, e);
            if is_huge && next == end && !end.is_multiple_of(huge) {
                return Err(errno_err(libc::EINVAL));
            }
            let ps = if is_huge { huge } else { page_size() };
            match parts.last_mut() {
                Some(last) if last.1 == at && last.2 == ps => last.1 = next,
                _ => parts.push((at, next, ps)),
            }
            at = next;
        }
        if slots(s, e).any(|r| r.ctx.load(Ordering::Acquire) != ctx) {
            return Err(errno_err(libc::EBUSY));
        }
    }
    // What this userfaultfd has not registered yet is new ranges; pages of
    // its ranges that were unregistered are registered again.
    let mut new = Vec::new();
    for &(s, e, ps) in &parts {
        let mut at = s;
        let mut mine: Vec<(u64, u64)> = slots(s, e)
            .map(|r| (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire)))
            .collect();
        mine.sort_unstable();
        for (a, b) in mine {
            if a > at {
                new.push((at, a, ps));
            }
            at = at.max(b);
        }
        if at < e {
            new.push((at, e, ps));
        }
    }
    // Pages of this userfaultfd's ranges that were unregistered, with
    // whether they are missing now.
    let mut again = Vec::new();
    for &(s, e, _) in &parts {
        for r in slots(s, e) {
            let base = r.start.load(Ordering::Acquire);
            let ps = r.page_size();
            let (a, b) = (s.max(base), e.min(r.end.load(Ordering::Acquire)));
            for page in (a - base) / ps..(b - base) / ps {
                if !Range::test(&r.tracked, page) {
                    let at = base + page * ps;
                    again.push((r, page, missing_pages(at, ps, ps)?[0]));
                }
            }
        }
    }
    if RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) == 0).count() < new.len() {
        return Err(errno_err(libc::ENOMEM));
    }
    let mut made: Vec<(u64, u64, u64, u64, Vec<bool>)> = Vec::new();
    let undo = |made: &[(u64, u64, u64, u64, Vec<bool>)]| {
        for &(s, e, _, alias, _) in made {
            // SAFETY: unmaps an alias made below.
            unsafe { libc::munmap(alias as *mut _, (e - s) as usize) };
        }
    };
    for &(s, e, ps) in &new {
        let mut alias = 0u64;
        let (mut cur, mut max) = (0, 0);
        // SAFETY: maps the same memory a second time, shared, anywhere.
        let kr = unsafe {
            mach_vm_remap(
                mach_task_self_,
                &mut alias,
                e - s,
                0,
                VM_FLAGS_ANYWHERE,
                mach_task_self_,
                s,
                0,
                &mut cur,
                &mut max,
                1, // VM_INHERIT_NONE
            )
        };
        if kr != 0 {
            undo(&made);
            return Err(errno_err(libc::ENOMEM));
        }
        made.push((s, e, ps, alias, Vec::new()));
        // The alias has the protection of the memory (the most restrictive
        // of the part), and pages are filled through it and then made
        // readable and writable: memory that is not would fault on a fill,
        // or change its protection. Guest memory always is.
        let rw = libc::PROT_READ | libc::PROT_WRITE;
        if cur & rw != rw {
            undo(&made);
            return Err(errno_err(libc::EPERM));
        }
        match missing_pages(s, e - s, ps) {
            Ok(missing) => made.last_mut().unwrap().4 = missing,
            Err(err) => {
                undo(&made);
                return Err(err);
            }
        }
    }
    for (s, e, ps, alias, missing) in made {
        let range = RANGES.iter().find(|r| r.start.load(Ordering::Acquire) == 0).unwrap();
        let pages = (e - s) / ps;
        range.end.store(e, Ordering::Release);
        range.ctx.store(ctx, Ordering::Release);
        range.page.store(ps, Ordering::Release);
        range.alias.store(alias, Ordering::Release);
        range.missing.store(alloc_bitmap(pages, false), Ordering::Release);
        // Trailing bits of the last word stay set; they are past `end`.
        range.tracked.store(alloc_bitmap(pages, true), Ordering::Release);
        for (page, &m) in missing.iter().enumerate() {
            if m {
                Range::set(&range.missing, page as u64, true);
            }
        }
        range.start.store(s, Ordering::Release);
        REGISTERED.fetch_add(1, Ordering::AcqRel);
    }
    let mut runs = Vec::new();
    for (r, page, missing) in again {
        Range::set(&r.missing, page, missing);
        Range::set(&r.tracked, page, true);
        if missing {
            let ps = r.page_size();
            runs.push((r.start.load(Ordering::Acquire) + page * ps, ps));
        }
    }
    for &(s, e, _) in &new {
        for_each_missing(s, e - s, |a, l| runs.push((a, l)));
    }
    // Missing pages fault from now on.
    for (a, l) in runs {
        protect(a, l, libc::PROT_NONE)?;
        stage2(a, l, false);
    }
    Ok(())
}

/// The registered range holding all of `[start, start + len)`, which must be
/// aligned to its pages (huge ones for a huge page range, as Linux's
/// hugetlb `UFFDIO_COPY` requires) and checked as Linux's `validate_range`
/// checks it (`EINVAL`).
fn range_of(ctx: usize, start: u64, len: u64) -> Result<&'static Range, c_int> {
    let end = validate_range(start, len)?;
    let (range, _) = find(start).ok_or(libc::ENOENT)?;
    if range.ctx.load(Ordering::Acquire) != ctx || end > range.end.load(Ordering::Acquire) {
        return Err(libc::ENOENT);
    }
    let ps = range.page_size();
    if !start.is_multiple_of(ps) || !len.is_multiple_of(ps) {
        return Err(libc::EINVAL);
    }
    Ok(range)
}

/// Unregisters `[start, start + len)`, as Linux's `userfaultfd_unregister`
/// (fs/userfaultfd.c, v6.12): the range is checked as `validate_range`
/// checks it; it must hold a VM map entry (holes are left out), none of
/// them the alias of a registered range, and a `MAP_HUGETLB` mapping at
/// its start, or a registered one cut by it, only at huge page boundaries
/// (`EINVAL`). Its registered pages, whichever userfaultfd has them (Linux
/// does not ask), become ordinary memory: missing ones zero pages, their
/// waiters woken. Memory not registered is left as it is. A range no page
/// of which is registered any more is freed.
pub fn unregister(_ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    let end = validate_range(start, len)?;
    let huge = crate::linux_items::HUGE_PAGE;
    let _guard = LOCK.lock().unwrap();
    let entries = mapped_entries(start, end);
    let Some(&(first, first_end, _)) = entries.first() else {
        return Err(libc::EINVAL);
    };
    if huge_segment(first, first_end).1 && !start.is_multiple_of(huge) {
        return Err(libc::EINVAL);
    }
    if entries.iter().any(|&(s, e, _)| overlaps_an_alias(s, e)) {
        return Err(libc::EINVAL);
    }
    // Linux cuts a registered hugetlb vma only at huge page boundaries.
    for r in slots(start, end) {
        let (s, e, ps) = (
            r.start.load(Ordering::Acquire),
            r.end.load(Ordering::Acquire),
            r.page_size(),
        );
        if !(start.max(s) - s).is_multiple_of(ps) || !(end.min(e) - s).is_multiple_of(ps) {
            return Err(libc::EINVAL);
        }
    }
    for &(s, e, _) in &entries {
        for r in slots(s, e) {
            let base = r.start.load(Ordering::Acquire);
            let ps = r.page_size();
            let (a, b) = (s.max(base), e.min(r.end.load(Ordering::Acquire)));
            // Accessible first, then not missing: a thread that faulted on
            // a page before it was accessible finds it missing and waits for
            // the wake below.
            let mut runs = Vec::new();
            for_each_missing(a, b - a, |x, l| runs.push((x, l)));
            for (x, l) in runs {
                protect(x, l, libc::PROT_READ | libc::PROT_WRITE)
                    .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                stage2(x, l, true);
            }
            for page in (a - base) / ps..(b - base) / ps {
                Range::set(&r.missing, page, false);
                Range::set(&r.tracked, page, false);
            }
            if !any_tracked(r) {
                release(r);
            }
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
    mut fill: impl FnMut(*mut u8, usize, usize),
) -> Result<u64, (c_int, u64)> {
    let _guard = LOCK.lock().unwrap();
    let range = range_of(ctx, dst, len).map_err(|e| (e, 0))?;
    let base = range.start.load(Ordering::Acquire);
    let alias = range.alias.load(Ordering::Acquire);
    let ps = range.page_size();
    let first = (dst - base) / ps;
    let mut n = 0;
    while n < len / ps {
        let page = first + n;
        if !Range::test(&range.tracked, page) || !Range::test(&range.missing, page) {
            break;
        }
        n += 1;
    }
    if n == 0 {
        return Err((libc::EEXIST, 0));
    }
    let bytes = n * ps;
    fill((alias + (dst - base)) as *mut u8, bytes as usize, 0);
    protect(dst, bytes, libc::PROT_READ | libc::PROT_WRITE)
        .map_err(|e| (e.raw_os_error().unwrap_or(libc::EIO), 0))?;
    stage2(dst, bytes, true);
    for page in first..first + n {
        Range::set(&range.missing, page, false);
    }
    if wake_up {
        wake(dst, bytes);
    }
    if bytes < len {
        Err((libc::EAGAIN, bytes))
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
    fill(ctx, dst, len, wake_up, |to, n, _| {
        // SAFETY: `to` is the alias of missing pages; `src` per the contract.
        unsafe { ptr::copy_nonoverlapping(src, to, n) }
    })
}

/// `UFFDIO_ZEROPAGE`: fills missing pages from `start` on with zeros.
pub fn zeropage(ctx: usize, start: u64, len: u64, wake_up: bool) -> Result<u64, (c_int, u64)> {
    fill(ctx, start, len, wake_up, |to, n, _| {
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

/// Wraps a `MADV_DONTNEED` of `[start, start + len)`: registered pages are
/// made accessible for `discard` to zero and release them, and the pages of
/// the pieces `discard` reports it discarded are missing again, with a
/// remove event queued for each (with `EVENT_REMOVE`). Pieces in a huge page
/// range are whole huge pages (Linux's hugetlb `MADV_DONTNEED` wants a huge
/// page aligned start and rounds the end down); pages the discard did not
/// reach keep their contents, as on Linux when it stops at an error.
pub fn discarding(start: u64, len: u64, discard: impl FnOnce(&mut Vec<(u64, u64)>) -> c_int) -> c_int {
    let ps = page_size();
    let end = start.saturating_add(len);
    let mut done = Vec::new();
    let touches = ps != 0
        && RANGES.iter().any(|r| {
            let s = r.start.load(Ordering::Acquire);
            s != 0 && start < r.end.load(Ordering::Acquire) && s < end
        });
    if !touches {
        return discard(&mut done);
    }
    let _guard = LOCK.lock().unwrap();
    let mut runs = Vec::new();
    for_each_missing(start, len, |s, l| runs.push((s, l)));
    for &(s, l) in &runs {
        // Missing pages hold zeros: let the discard reach them.
        let _ = protect(s, l, libc::PROT_READ | libc::PROT_WRITE);
    }
    let ret = discard(&mut done);
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let ps = r.page_size();
        let ctx = r.ctx.load(Ordering::Acquire);
        let remove = CTXS[ctx].features.load(Ordering::Acquire) & FEATURE_EVENT_REMOVE != 0;
        let alias = r.alias.load(Ordering::Acquire);
        for &(a, b) in &done {
            let (a, b) = (a.max(s), b.min(e));
            if a >= b {
                continue;
            }
            // A discard of private anonymous memory replaces its pages
            // (`linux_items::discard_piece`): the alias, through which
            // pages are filled, must share the new ones, or a fill would go
            // to the old pages, which the alias would also keep resident.
            let mut at = alias + (a - s);
            let (mut cur, mut max) = (0, 0);
            // SAFETY: maps `[a, b)` of the range, which is mapped, over the
            // same part of its alias, which is ours.
            let kr = unsafe {
                mach_vm_remap(
                    mach_task_self_,
                    &mut at,
                    b - a,
                    0,
                    VM_FLAGS_FIXED_OVERWRITE,
                    mach_task_self_,
                    a,
                    0,
                    &mut cur,
                    &mut max,
                    1, // VM_INHERIT_NONE
                )
            };
            if kr != 0 {
                // The alias would fill the old pages: the next fill would
                // corrupt the guest silently.
                std::eprintln!(
                    "wick: userfaultfd alias of {a:#x}+{:#x} cannot follow the discarded pages \
                     (mach_vm_remap: {kr})",
                    b - a
                );
                std::process::abort();
            }
            // The range's whole pages inside the piece.
            let (first, last) = ((a - s).div_ceil(ps), (b - s) / ps);
            for page in first..last {
                if Range::test(&r.tracked, page) {
                    Range::set(&r.missing, page, true);
                }
            }
            if first < last && remove {
                post(ctx, [proto::EVENT_REMOVE, s + first * ps, s + last * ps, 0]);
            }
        }
        // Every missing page of the range in reach is inaccessible again:
        // the ones just discarded and the ones made accessible above.
        let from = start.max(s) - (start.max(s) - s) % ps;
        let to = (s + (end.min(e) - s).next_multiple_of(ps)).min(e);
        let mut runs = Vec::new();
        for_each_missing(from, to - from, |a, l| runs.push((a, l)));
        for (a, l) in runs {
            let _ = protect(a, l, libc::PROT_NONE);
            stage2(a, l, false);
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
        let mut runs = Vec::new();
        for_each_missing(s, e - s, |a, l| runs.push((a, l)));
        let ps = r.page_size();
        for (a, l) in runs {
            let _ = protect(a, l, libc::PROT_READ | libc::PROT_WRITE);
            stage2(a, l, true);
            for page in (a - s) / ps..(a + l - s) / ps {
                Range::set(&r.missing, page, false);
            }
        }
        release(r);
        wake(s, e - s);
    }
    let fd = CTXS[ctx].fd.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        // SAFETY: the kernel end owned by the serving thread.
        unsafe { libc::close(fd) };
    }
}

fn read_full(fd: c_int, buf: &mut [u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: reads into a local buffer.
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    true
}

fn write_full(fd: c_int, buf: &[u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: writes a local buffer.
        let n = unsafe { libc::write(fd, buf[done..].as_ptr().cast(), buf.len() - done) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    true
}

fn words(buf: &[u8; proto::RECORD]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for (i, v) in w.iter_mut().enumerate() {
        *v = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

/// Receives a record on the kernel end: `None` when every user descriptor
/// is closed, else the descriptor of a `HELLO`. A record that is not a
/// `HELLO`, or comes without a descriptor, is ignored; descriptors not kept
/// are closed. A signal or a record sent in pieces does not end the
/// userfaultfd.
fn recv_hello(fd: c_int) -> Option<Option<c_int>> {
    let mut buf = [0u8; proto::RECORD];
    let mut fds: Vec<c_int> = Vec::new();
    let mut done = 0;
    while done < buf.len() {
        let mut cmsg = [0u64; 64];
        let mut iov = libc::iovec {
            iov_base: buf[done..].as_mut_ptr().cast(),
            iov_len: buf.len() - done,
        };
        // SAFETY: a zeroed msghdr is valid; the buffers outlive the call, and
        // the control messages read are those the kernel wrote.
        let n = unsafe {
            let mut msg: libc::msghdr = core::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg.as_mut_ptr().cast();
            msg.msg_controllen = core::mem::size_of_val(&cmsg) as _;
            let n = libc::recvmsg(fd, &mut msg, libc::MSG_WAITALL);
            let mut c = if n > 0 {
                libc::CMSG_FIRSTHDR(&msg)
            } else {
                ptr::null_mut()
            };
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c);
                    let len = ((*c).cmsg_len as usize).saturating_sub(data as usize - c as usize);
                    for i in 0..len / core::mem::size_of::<c_int>() {
                        fds.push(ptr::read_unaligned(data.cast::<c_int>().add(i)));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            n
        };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            for fd in fds {
                // SAFETY: descriptors received here and not kept.
                unsafe { libc::close(fd) };
            }
            return None;
        }
        done += n as usize;
    }
    let mut fds = fds.into_iter();
    let peer = if words(&buf)[0] == proto::HELLO {
        fds.next()
    } else {
        None
    };
    for fd in fds {
        // SAFETY: descriptors received here and not kept.
        unsafe { libc::close(fd) };
    }
    Some(peer)
}

/// Serves `[OP_COPY, dst, len, _]`, whose `len` bytes of data follow on
/// `fd`; `None` when the channel closed. The request is checked before the
/// data is read, and the data is read and copied a piece at a time, so a
/// length that names no registered memory costs no memory to refuse. As
/// Linux's `UFFDIO_COPY`, it stops at the first page that is not missing:
/// `EEXIST` if that is the first, else `EAGAIN` with the count copied.
fn serve_copy(
    ctx: usize,
    fd: c_int,
    dst: u64,
    len: u64,
    wake_up: bool,
) -> Option<Result<u64, (c_int, u64)>> {
    // Pieces of a mebibyte, or of the range's page when it is larger (a
    // huge page is filled whole).
    let range = range_of(ctx, dst, len);
    let piece = range.map_or(1 << 20, |r| r.page_size().max(1 << 20));
    let mut result = range.map(|_| 0).map_err(|e| (e, 0));
    let mut buf = Vec::new();
    let mut done = 0;
    while done < len {
        let n = (len - done).min(piece);
        buf.resize(n as usize, 0);
        if !read_full(fd, &mut buf) {
            return None;
        }
        // Once stopped, the rest of the data is read and dropped.
        if let Ok(copied) = result {
            // SAFETY: `buf` holds `n` bytes.
            result = match unsafe { copy(ctx, buf.as_ptr(), dst + done, n, wake_up) } {
                Ok(m) => Ok(copied + m),
                Err((_, m)) if copied + m > 0 => Err((libc::EAGAIN, copied + m)),
                Err(e) => Err(e),
            };
        }
        done += n;
    }
    Some(result)
}

/// Serves one request from a client channel; false when the channel closed.
fn serve_request(ctx: usize, fd: c_int) -> bool {
    let mut head = [0u8; proto::RECORD];
    if !read_full(fd, &mut head) {
        return false;
    }
    let [op, a, b, c] = words(&head);
    let wake_up = c & proto::MODE_DONTWAKE == 0;
    let to_reply = |r: Result<u64, (c_int, u64)>| match r {
        Ok(n) => [n, n],
        Err((e, n)) => [(-(e as i64)) as u64, n],
    };
    let reply = match op {
        proto::OP_COPY => match serve_copy(ctx, fd, a, b, wake_up) {
            Some(r) => to_reply(r),
            None => return false,
        },
        proto::OP_ZEROPAGE => to_reply(zeropage(ctx, a, b, wake_up)),
        proto::OP_WAKE => to_reply(wake_range(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        proto::OP_REGISTER => to_reply(
            register(ctx, a, b)
                .map(|()| 0)
                .map_err(|e| (e.raw_os_error().unwrap_or(libc::EINVAL), 0)),
        ),
        proto::OP_UNREGISTER => to_reply(unregister(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        _ => to_reply(Err((libc::EINVAL, 0))),
    };
    let mut out = [0u8; proto::RECORD];
    out[..8].copy_from_slice(&reply[0].to_le_bytes());
    out[8..16].copy_from_slice(&reply[1].to_le_bytes());
    write_full(fd, &out)
}

/// The serving thread of userfaultfd `ctx`: accepts request channels sent on
/// the kernel end and serves them. Ends when every user descriptor is closed.
fn serve(ctx: usize, kernel: c_int) {
    let mut clients: Vec<c_int> = Vec::new();
    loop {
        let mut fds: Vec<libc::pollfd> = core::iter::once(kernel)
            .chain(clients.iter().copied())
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is a valid array.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match recv_hello(kernel) {
                None => break,
                Some(Some(client)) => clients.push(client),
                Some(None) => {}
            }
        }
        let mut closed = Vec::new();
        for p in &fds[1..] {
            if p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                && !serve_request(ctx, p.fd)
            {
                closed.push(p.fd);
            }
        }
        for fd in closed {
            clients.retain(|c| *c != fd);
            // SAFETY: a client channel received above.
            unsafe { libc::close(fd) };
        }
    }
    for fd in clients {
        // SAFETY: as above.
        unsafe { libc::close(fd) };
    }
    destroy(ctx);
}

/// Faults in the missing registered pages of `[addr, addr + len)`, as the
/// Linux kernel does when a system call copies to or from them (`write`: the
/// call writes the memory). Returns whether any page was missing.
pub fn prefault(addr: u64, len: u64, write: bool) -> bool {
    if REGISTERED.load(Ordering::Acquire) == 0 || len == 0 {
        return false;
    }
    let ps = page_size();
    let end = addr.saturating_add(len);
    let mut page = addr - addr % ps;
    let mut any = false;
    while page < end {
        // The first byte of the buffer in this page.
        let at = page.max(addr);
        if is_missing(at) && fault(at, write) {
            any = true;
        }
        page += ps;
    }
    any
}

/// System calls that copy to or from user memory, with the Linux userfaultfd
/// semantics: Linux waits for missing pages a call touches; these fault them
/// in first, and again if the call fails with `EFAULT` because one was
/// released in between.
pub mod syscalls {
    use core::ffi::{c_int, c_void};

    use upstream::{self as libc, iovec, msghdr, off_t, size_t, sockaddr, socklen_t, ssize_t};

    use super::{prefault, REGISTERED};

    fn errno() -> c_int {
        // SAFETY: reads this thread's errno.
        unsafe { *libc::__error() }
    }

    /// Calls `call` with the buffers `fault` faults in.
    fn with_pages(fault: impl Fn() -> bool, mut call: impl FnMut() -> ssize_t) -> ssize_t {
        if REGISTERED.load(core::sync::atomic::Ordering::Acquire) == 0 {
            return call();
        }
        fault();
        loop {
            let ret = call();
            if ret >= 0 || errno() != libc::EFAULT || !fault() {
                return ret;
            }
        }
    }

    /// SIGPIPE as Linux raises it, after a write to `fd` that returned
    /// `ret`; returns `ret`, with errno as the call left it.
    ///
    /// Linux raises SIGPIPE on the calling thread when a write to a stream
    /// socket (a Unix one or TCP) fails with `EPIPE` having sent nothing, unless the call
    /// passed `MSG_NOSIGNAL` (net/unix/af_unix.c `unix_stream_sendmsg`,
    /// `pipe_err`: `send_sig(SIGPIPE, current, 0)`, which `send_sig_info`
    /// sends to the thread, `PIDTYPE_PID`); `write(2)` and `writev(2)` pass
    /// no flags. xnu raises it for the process (bsd/kern/sys_socket.c
    /// `soo_write`, bsd/kern/uipc_syscalls.c `sendit`), and not at all on a
    /// socket with `SO_NOSIGPIPE`, which Rust's std sets on every socket it
    /// makes on Apple systems (its own writes stand for Linux's, which pass
    /// `MSG_NOSIGNAL`; they do not come here). So only where xnu kept quiet
    /// for that flag alone, this raises it, once: a socket without the flag
    /// has had its signal from xnu, and a pipe (`ENOTSOCK`) too. As on
    /// Linux, a blocked SIGPIPE stays pending for the thread and an ignored
    /// one is dropped (`pthread_kill`).
    fn linux_sigpipe(fd: c_int, flags: c_int, ret: ssize_t) -> ssize_t {
        if ret >= 0 || errno() != libc::EPIPE || flags & libc::MSG_NOSIGNAL != 0 {
            return ret;
        }
        let mut on: c_int = 0;
        let mut len = core::mem::size_of::<c_int>() as socklen_t;
        // SAFETY: an int and its length, as SO_NOSIGPIPE takes.
        let got = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&raw mut on).cast(),
                &mut len,
            )
        };
        // Only a stream socket's write raises it on Linux (a datagram or
        // seqpacket socket's, unix_dgram_sendmsg, does not).
        let mut kind: c_int = 0;
        let mut kind_len = core::mem::size_of::<c_int>() as socklen_t;
        // SAFETY: as above, for SO_TYPE.
        let stream = got == 0
            && on != 0
            && unsafe {
                libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, (&raw mut kind).cast(), &mut kind_len)
            } == 0
            && kind == libc::SOCK_STREAM;
        if stream {
            // SAFETY: a signal to the calling thread.
            unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGPIPE) };
        }
        // SAFETY: this thread's errno, as the call left it.
        unsafe { *libc::__error() = libc::EPIPE };
        ret
    }

    fn iov_pages(iov: *const iovec, count: c_int, write: bool) -> bool {
        let mut any = false;
        for i in 0..count.max(0) as usize {
            // SAFETY: the caller's iovec array has `count` entries.
            let v = unsafe { &*iov.add(i) };
            any |= prefault(v.iov_base as u64, v.iov_len as u64, write);
        }
        any
    }

    /// `read(2)`.
    ///
    /// # Safety
    /// As `read(2)`.
    pub unsafe fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, count as u64, true),
            || unsafe { libc::read(fd, buf, count) },
        )
    }

    /// `write(2)`.
    ///
    /// # Safety
    /// As `write(2)`.
    pub unsafe fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || prefault(buf as u64, count as u64, false),
            || unsafe { libc::write(fd, buf, count) },
        );
        linux_sigpipe(fd, 0, ret)
    }

    /// `pread(2)`.
    ///
    /// # Safety
    /// As `pread(2)`.
    pub unsafe fn pread(fd: c_int, buf: *mut c_void, count: size_t, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, count as u64, true),
            || unsafe { libc::pread(fd, buf, count, offset) },
        )
    }

    /// `pwrite(2)`.
    ///
    /// # Safety
    /// As `pwrite(2)`.
    pub unsafe fn pwrite(fd: c_int, buf: *const c_void, count: size_t, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, count as u64, false),
            || unsafe { libc::pwrite(fd, buf, count, offset) },
        )
    }

    /// `readv(2)`.
    ///
    /// # Safety
    /// As `readv(2)`.
    pub unsafe fn readv(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, iovcnt, true),
            || unsafe { libc::readv(fd, iov, iovcnt) },
        )
    }

    /// `writev(2)`.
    ///
    /// # Safety
    /// As `writev(2)`.
    pub unsafe fn writev(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || iov_pages(iov, iovcnt, false),
            || unsafe { libc::writev(fd, iov, iovcnt) },
        );
        linux_sigpipe(fd, 0, ret)
    }

    /// `preadv(2)`.
    ///
    /// # Safety
    /// As `preadv(2)`.
    pub unsafe fn preadv(fd: c_int, iov: *const iovec, iovcnt: c_int, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, iovcnt, true),
            || unsafe { libc::preadv(fd, iov, iovcnt, offset) },
        )
    }

    /// `pwritev(2)`.
    ///
    /// # Safety
    /// As `pwritev(2)`.
    pub unsafe fn pwritev(fd: c_int, iov: *const iovec, iovcnt: c_int, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, iovcnt, false),
            || unsafe { libc::pwritev(fd, iov, iovcnt, offset) },
        )
    }

    /// `recv(2)`.
    ///
    /// # Safety
    /// As `recv(2)`.
    pub unsafe fn recv(socket: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, len as u64, true),
            || unsafe { libc::recv(socket, buf, len, flags) },
        )
    }

    /// `send(2)`.
    ///
    /// # Safety
    /// As `send(2)`.
    pub unsafe fn send(socket: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || prefault(buf as u64, len as u64, false),
            || unsafe { libc::send(socket, buf, len, flags) },
        );
        linux_sigpipe(socket, flags, ret)
    }

    /// `recvfrom(2)`.
    ///
    /// # Safety
    /// As `recvfrom(2)`.
    pub unsafe fn recvfrom(
        socket: c_int,
        buf: *mut c_void,
        len: size_t,
        flags: c_int,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
    ) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, len as u64, true),
            || unsafe { libc::recvfrom(socket, buf, len, flags, addr, addrlen) },
        )
    }

    /// `sendto(2)`.
    ///
    /// # Safety
    /// As `sendto(2)`.
    pub unsafe fn sendto(
        socket: c_int,
        buf: *const c_void,
        len: size_t,
        flags: c_int,
        addr: *const sockaddr,
        addrlen: socklen_t,
    ) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || prefault(buf as u64, len as u64, false),
            || unsafe { libc::sendto(socket, buf, len, flags, addr, addrlen) },
        );
        linux_sigpipe(socket, flags, ret)
    }

    /// `recvmsg(2)`.
    ///
    /// # Safety
    /// As `recvmsg(2)`.
    pub unsafe fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
        // SAFETY: the caller's msghdr.
        let (iov, n) = unsafe { ((*msg).msg_iov, (*msg).msg_iovlen) };
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, n, true),
            || unsafe { libc::recvmsg(fd, msg, flags) },
        )
    }

    /// `sendmsg(2)`.
    ///
    /// # Safety
    /// As `sendmsg(2)`.
    pub unsafe fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
        // SAFETY: the caller's msghdr.
        let (iov, n) = unsafe { ((*msg).msg_iov, (*msg).msg_iovlen) };
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || iov_pages(iov, n, false),
            || unsafe { libc::sendmsg(fd, msg, flags) },
        );
        linux_sigpipe(fd, flags, ret)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn map(pages: u64) -> u64 {
        init().unwrap();
        // SAFETY: a fresh anonymous mapping.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                (pages * page_size()) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        p as u64
    }

    fn socketpair() -> [c_int; 2] {
        let mut fds = [0; 2];
        // SAFETY: creates two descriptors.
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(r, 0);
        fds
    }

    /// Sends the first `len` bytes of a record with descriptors attached.
    fn send_record(fd: c_int, words: [u64; 4], len: usize, fds: &[c_int]) {
        let mut bytes = [0u8; proto::RECORD];
        for (i, w) in words.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let mut control = [0u64; 8];
        // SAFETY: a msghdr with one buffer and the descriptors.
        let n = unsafe {
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: len,
            };
            let mut msg: libc::msghdr = core::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if !fds.is_empty() {
                let size = core::mem::size_of_val(fds) as u32;
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = libc::CMSG_SPACE(size) as _;
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(size) as _;
                ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast(), fds.len());
            }
            libc::sendmsg(fd, &msg, 0)
        };
        assert_eq!(n, len as isize);
    }

    /// Waits up to five seconds for `fd` to be readable.
    fn readable(fd: c_int) -> bool {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd.
        unsafe { libc::poll(&mut p, 1, 5000) == 1 }
    }

    fn record(head: [u64; 4]) -> Vec<u8> {
        head.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// Sends a request and its data; returns the reply.
    fn request(chan: c_int, head: [u64; 4], data: &[u8]) -> (i64, u64) {
        let mut msg = record(head);
        msg.extend_from_slice(data);
        assert!(write_full(chan, &msg));
        assert!(readable(chan), "no reply to {head:x?}");
        let mut reply = [0u8; proto::RECORD];
        assert!(read_full(chan, &mut reply));
        let w = words(&reply);
        (w[0] as i64, w[1])
    }

    /// Whether the serving thread answers requests on `chan`.
    fn served(chan: c_int) -> bool {
        request(chan, [proto::OP_WAKE, 0, 0, 0], &[]).0 == err(libc::EINVAL)
    }

    /// A request channel to the serving thread of the userfaultfd `user`.
    fn channel(user: c_int) -> c_int {
        let [mine, theirs] = socketpair();
        send_record(user, [proto::HELLO, 0, 0, 0], proto::RECORD, &[theirs]);
        // The serving thread holds the descriptor once it answered.
        assert!(served(mine));
        // SAFETY: our copy of the end sent.
        unsafe { libc::close(theirs) };
        mine
    }

    fn err(e: c_int) -> i64 {
        -(e as i64)
    }

    /// Runs test `name` again in a process of its own (this binary, that
    /// test only) and checks that it passed there; true in that process,
    /// which goes on with the test.
    fn in_own_process(name: &str) -> bool {
        const CHILD: &str = "WICK_UFFD_TEST_ALONE";
        if std::env::var_os(CHILD).is_some() {
            return true;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let text = std::format!(
            "{:?}\n{}{}",
            out.status,
            std::string::String::from_utf8_lossy(&out.stdout),
            std::string::String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
        false
    }

    fn close(fds: &[c_int]) {
        for &fd in fds {
            // SAFETY: descriptors of the test.
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn test_ranges_that_wrap() {
        // A range whose end wraps around is EINVAL, as Linux's validate_range.
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        let wrap = 0u64.wrapping_sub(ps);
        assert_eq!(zeropage(ctx, mem, wrap, true), Err((libc::EINVAL, 0)));
        assert_eq!(wake_range(ctx, mem, wrap), Err(libc::EINVAL));
        assert_eq!(unregister(ctx, mem + ps, wrap), Err(libc::EINVAL));
        // SAFETY: refused before `src` is read.
        let r = unsafe { copy(ctx, ptr::null(), mem + ps, wrap, true) };
        assert_eq!(r, Err((libc::EINVAL, 0)));
        let chan = channel(user);
        let head = [proto::OP_ZEROPAGE, mem, wrap, 0];
        assert_eq!(request(chan, head, &[]), (err(libc::EINVAL), 0));
        // Still registered and missing.
        assert!(is_missing(mem) && is_missing(mem + ps));
        assert_eq!(zeropage(ctx, mem, 2 * ps, true), Ok(2 * ps));
        close(&[chan, user]);
    }

    #[test]
    fn test_register_checks_the_range_as_linux() {
        // Linux's validate_range: past the address space is EINVAL, before
        // anything sized by the length.
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(4);
        for len in [1 << 62, TASK_SIZE - mem + ps, (u64::MAX - mem) & !(ps - 1)] {
            let e = register(ctx, mem, len).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EINVAL), "{len:#x}");
            assert_eq!(unregister(ctx, mem, len), Err(libc::EINVAL), "{len:#x}");
        }
        let e = register(ctx, TASK_SIZE, ps).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        register(ctx, mem, 2 * ps).unwrap();
        assert!(is_missing(mem));
        // Through a handler's channel too.
        let chan = channel(user);
        let other = map(1);
        let (r, _) = request(chan, [proto::OP_REGISTER, other, 1 << 62, 0], &[]);
        assert_eq!(r, err(libc::EINVAL));
        let (r, _) = request(chan, [proto::OP_REGISTER, other, ps, 0], &[]);
        assert_eq!(r, 0);
        assert!(is_missing(other));
        close(&[chan, user]);
    }

    /// As Linux's `userfaultfd_register` and `userfaultfd_unregister`, the
    /// mapped parts of a range are registered and unregistered and its holes
    /// left out; a range of holes only is `EINVAL`. Nothing but this test
    /// may map memory while the holes are open, or a mapping can take them.
    /// Among other tests' threads, one did (their mappings, the aliases
    /// `register` makes), so it runs in a process of its own: this binary
    /// again, this test only. There the serving thread did (Rust's start of
    /// a thread maps its signal stack and guard page), so the holes are made
    /// only once that thread has answered a request.
    #[test]
    fn test_register_takes_the_mapped_parts_of_a_range() {
        if !in_own_process("wick_uffd::tests::test_register_takes_the_mapped_parts_of_a_range") {
            return;
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        // Parts of two pages, holes of one: no alias `register` makes (one
        // per part, its size) fits in a hole.
        let mem = map(8);
        let chan = channel(user);
        for page in [2, 5] {
            // SAFETY: a page of the mapping above.
            let r = unsafe { libc::munmap((mem + page * ps) as *mut _, ps as usize) };
            assert_eq!(r, 0);
        }
        let e = register(ctx, mem + 2 * ps, ps).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(unregister(ctx, mem + 5 * ps, ps), Err(libc::EINVAL));
        let (r, _) = request(chan, [proto::OP_UNREGISTER, mem + 2 * ps, ps, 0], &[]);
        assert_eq!(r, err(libc::EINVAL));
        register(ctx, mem, 8 * ps).unwrap();
        let mapped = [0, 1, 3, 4, 6, 7];
        for page in mapped {
            assert!(is_missing(mem + page * ps), "{page}");
        }
        // Memory mapped in a hole afterwards is not registered, as a new vma.
        assert!(mapped_entries(mem + 2 * ps, mem + 3 * ps).is_empty());
        // SAFETY: maps over the hole made above, still a hole.
        let p = unsafe {
            libc::mmap(
                (mem + 2 * ps) as *mut _,
                ps as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(p as u64, mem + 2 * ps);
        assert!(!is_missing(mem + 2 * ps));
        // SAFETY: the page just mapped.
        unsafe { ptr::write_volatile((mem + 2 * ps) as *mut u8, 7) };
        assert_eq!(zeropage(ctx, mem + 3 * ps, 2 * ps, true), Ok(2 * ps));
        // Over the hole left, the page mapped in the other, and memory
        // never registered.
        assert_eq!(unregister(ctx, mem, 8 * ps), Ok(()));
        for page in mapped {
            assert!(!is_missing(mem + page * ps), "{page}");
        }
        // SAFETY: mapped and no longer registered.
        unsafe {
            assert_eq!(ptr::read_volatile((mem + 2 * ps) as *const u8), 7);
            assert_eq!(ptr::read_volatile((mem + 7 * ps) as *const u8), 0);
        }
        close(&[chan, user]);
    }

    #[test]
    fn test_register_and_unregister_as_linux() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(3);
        register(a, mem, 2 * ps).unwrap();
        assert_eq!(zeropage(a, mem, ps, true), Ok(ps));
        // Again, and further: what the userfaultfd has stays as it is, as
        // Linux skips a vma registered with it; the rest is registered.
        register(a, mem, 3 * ps).unwrap();
        assert!(!is_missing(mem) && is_missing(mem + ps) && is_missing(mem + 2 * ps));
        // Another userfaultfd's: EBUSY, and nothing of the range registered.
        let next = map(1);
        for (start, len) in [(mem + 2 * ps, ps), (mem, 3 * ps)] {
            let e = register(b, start, len).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EBUSY));
        }
        // Linux's unregister clears a vma whichever userfaultfd has it.
        assert_eq!(unregister(b, mem + ps, ps), Ok(()));
        assert!(!is_missing(mem + ps));
        // Not Linux's, which would take it: part of a range of another
        // userfaultfd, until all of that range is unregistered.
        let e = register(b, mem + ps, ps).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EBUSY));
        // Registered again: not resident, so missing.
        register(a, mem, 3 * ps).unwrap();
        assert!(!is_missing(mem) && is_missing(mem + ps));
        // Unregistered whole, the memory is free for another userfaultfd.
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        register(b, mem, 3 * ps).unwrap();
        assert!(!is_missing(mem) && is_missing(mem + ps) && is_missing(mem + 2 * ps));
        assert_eq!(zeropage(b, mem + ps, 2 * ps, true), Ok(2 * ps));
        assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)));
        register(a, next, ps).unwrap();
        close(&[ua, ub]);
    }

    /// Not Linux's: a private file mapping is registered, where Linux's
    /// `vma_can_userfault` refuses it (`EINVAL`), as a memfd here is a file
    /// and Linux takes a memfd's mappings (shmem).
    #[test]
    fn test_register_takes_a_private_file_mapping() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let path = std::env::temp_dir().join(std::format!("wick-uffd-file-{}", std::process::id()));
        let file = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.set_len(2 * ps).unwrap();
        // SAFETY: a private mapping of the file above.
        let mem = unsafe {
            libc::mmap(
                ptr::null_mut(),
                (2 * ps) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                std::os::fd::AsRawFd::as_raw_fd(&file),
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED);
        register(ctx, mem as u64, 2 * ps).unwrap();
        assert_eq!(zeropage(ctx, mem as u64, 2 * ps, true), Ok(2 * ps));
        assert_eq!(unregister(ctx, mem as u64, 2 * ps), Ok(()));
        close(&[user]);
    }

    #[test]
    fn test_register_needs_read_write_memory() {
        // Fills write through the alias, which has the memory's protection.
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(3);
        for (page, prot) in [(1, libc::PROT_NONE), (2, libc::PROT_READ)] {
            // SAFETY: a page of the mapping above.
            let r = unsafe { libc::mprotect((mem + page * ps) as *mut _, ps as usize, prot) };
            assert_eq!(r, 0);
            let e = register(ctx, mem, (page + 1) * ps).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{prot}");
            let e = register(ctx, mem + page * ps, ps).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{prot}");
        }
        register(ctx, mem, ps).unwrap();
        assert_eq!(zeropage(ctx, mem, ps, true), Ok(ps));
        close(&[user]);
    }

    /// A range over the alias of a registered range is refused (`EINVAL`):
    /// its missing pages would be the alias's, and a fill of the first
    /// range, which writes through the alias holding [`LOCK`], would fault
    /// on them and wait for a fill of the second, which needs [`LOCK`]:
    /// forever. In a process of its own, under an alarm, so that the hang
    /// ends the process and fails the test: a fill of two pages takes
    /// microseconds, and 10 s is far beyond any wait for the CPU.
    #[test]
    fn test_register_refuses_another_ranges_alias() {
        if !in_own_process("wick_uffd::tests::test_register_refuses_another_ranges_alias") {
            return;
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(2);
        let chan = channel(user);
        register(ctx, mem, 2 * ps).unwrap();
        let alias = find(mem).unwrap().0.alias.load(Ordering::Acquire);
        let whole = register(ctx, alias, 2 * ps);
        let part = register(ctx, alias + ps, ps);
        // Through a handler's channel too, over the alias and what follows.
        let other = map(1);
        let (around, _) = request(chan, [proto::OP_REGISTER, alias + ps, 2 * ps, 0], &[]);
        // SAFETY: plain alarm; its default action ends the process.
        unsafe { libc::alarm(10) };
        assert_eq!(zeropage(ctx, mem, 2 * ps, true), Ok(2 * ps));
        // SAFETY: as above.
        unsafe { libc::alarm(0) };
        assert_eq!(whole.unwrap_err().raw_os_error(), Some(libc::EINVAL));
        assert_eq!(part.unwrap_err().raw_os_error(), Some(libc::EINVAL));
        assert_eq!(around, err(libc::EINVAL));
        assert!(!is_missing(alias) && !is_missing(alias + ps));
        // Other memory is taken.
        let (r, _) = request(chan, [proto::OP_REGISTER, other, ps, 0], &[]);
        assert_eq!(r, 0);
        close(&[chan, user]);
    }

    #[test]
    fn test_copy_from_a_handler() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        // More than two pieces of copied data.
        let pages = (2 << 20) / ps + 3;
        let mem = map(pages);
        register(ctx, mem, pages * ps).unwrap();
        let chan = channel(user);
        // Data for memory that is not registered is read and refused: the
        // next request is understood.
        let elsewhere = map(3);
        let data = std::vec![7u8; (3 * ps) as usize];
        let head = [proto::OP_COPY, elsewhere, 3 * ps, 0];
        assert_eq!(request(chan, head, &data), (err(libc::ENOENT), 0));
        // A page in the last piece is present: the copy stops there.
        let present = pages - 2;
        assert_eq!(zeropage(ctx, mem + present * ps, ps, true), Ok(ps));
        let data: Vec<u8> = (0..pages * ps).map(|i| (i / ps) as u8).collect();
        let head = [proto::OP_COPY, mem, pages * ps, 0];
        let partial = (err(libc::EAGAIN), present * ps);
        assert_eq!(request(chan, head, &data), partial);
        for p in 0..pages {
            let expect = match p {
                p if p < present => p as u8,
                p if p == present => 0,
                _ => {
                    assert!(is_missing(mem + p * ps), "page {p}");
                    continue;
                }
            };
            // SAFETY: a filled page.
            let got = unsafe { ptr::read_volatile((mem + p * ps + 5) as *const u8) };
            assert_eq!(got, expect, "page {p}");
        }
        // Present from the first page on: EEXIST.
        let page = &data[..ps as usize];
        let exists = (err(libc::EEXIST), 0);
        assert_eq!(request(chan, [proto::OP_COPY, mem, ps, 0], page), exists);
        let last = mem + (pages - 1) * ps;
        let whole = (ps as i64, ps);
        assert_eq!(request(chan, [proto::OP_COPY, last, ps, 0], page), whole);
        // A length no data follows: the channel closes, the userfaultfd stays.
        assert!(write_full(chan, &record([proto::OP_COPY, mem, 1 << 62, 0])));
        close(&[chan]);
        let chan = channel(user);
        assert_eq!(request(chan, [proto::OP_WAKE, mem, ps, 0], &[]), (0, 0));
        close(&[chan, user]);
    }

    /// A discard of registered memory replaces its pages
    /// (`linux_items::discard_piece`): the alias through which pages are
    /// filled follows, so a copy after the discard lands in the pages the
    /// memory now has, not in the old ones (which would also have kept the
    /// old pages resident).
    #[test]
    fn test_discarded_pages_are_filled_through_the_new_alias() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(4);
        register(ctx, mem, 4 * ps).unwrap();
        let page = mem + ps;
        let read = || {
            // SAFETY: a filled page.
            unsafe { ptr::read_volatile((page + 5) as *const u8) }
        };
        for (fill, expect) in [(0x11u8, 0x11u8), (0x22, 0x22)] {
            let data = std::vec![fill; ps as usize];
            // SAFETY: `data` holds a page; `page` is a missing page of the range.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), page, ps, true) }, Ok(ps));
            assert!(!is_missing(page));
            assert_eq!(read(), expect, "copy of {fill:#x}");
            // Missing again, with fresh pages; the copy above lands in them.
            // SAFETY: one page of the mapping, through the compatibility madvise.
            assert_eq!(unsafe { crate::linux_items::madvise(page as *mut _, ps as usize, libc::MADV_DONTNEED) }, 0);
            assert!(is_missing(page));
        }
        close(&[user]);
    }

    /// A huge page mapping is registered in huge pages (docs/PORTING.md
    /// row 10): a fault anywhere in one reports its address and waits for
    /// the whole page; a copy must be aligned to huge pages and fills a
    /// whole one; the other huge pages stay missing; a discard must start
    /// on a huge page and its end is rounded down to one, as Linux's.
    #[test]
    fn test_huge_page_ranges_fault_and_fill_whole_pages() {
        use crate::linux_items::{HUGE_PAGE, MAP_HUGETLB, MAP_HUGE_2MB};
        let _alone = huge_mapping_test();
        let (ctx, user) = create(0, false, true).unwrap();
        let host = page_size();
        let len = 3 * HUGE_PAGE;
        // SAFETY: a huge page mapping of the compatibility mmap, unmapped at the end.
        let mem = unsafe {
            crate::linux_items::mmap(
                ptr::null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGETLB | MAP_HUGE_2MB,
                -1,
                0,
            )
        } as u64;
        assert_ne!(mem, libc::MAP_FAILED as u64);
        // Aligned to host pages, not to huge ones: refused.
        let refused = register(ctx, mem + host, len - host).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EINVAL));
        register(ctx, mem, len).unwrap();
        for off in [0, host, HUGE_PAGE - host, HUGE_PAGE, 2 * HUGE_PAGE + 5 * host] {
            assert!(is_missing(mem + off), "{off:#x}");
        }
        let mut runs = Vec::new();
        for_each_missing(mem + host, len - 2 * host, |s, l| runs.push((s, l)));
        assert_eq!(runs, std::vec![(mem, len)], "whole huge pages");
        let chan = channel(user);
        // A copy aligned to host pages only: EINVAL, as Linux's hugetlb.
        let page = std::vec![3u8; HUGE_PAGE as usize];
        let short = (err(libc::EINVAL), 0);
        assert_eq!(request(chan, [proto::OP_COPY, mem + host, HUGE_PAGE, 0], &page), short);
        assert_eq!(request(chan, [proto::OP_COPY, mem, host, 0], &page[..host as usize]), short);
        // A read in the middle of the second huge page: the event names the
        // address, and the reader waits until the whole page is filled.
        let at = mem + HUGE_PAGE + 3 * host + 9;
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the fault is served below.
            unsafe { ptr::read_volatile(at as *const u8) }
        });
        assert!(readable(user), "no page fault event");
        let mut rec = [0u8; proto::RECORD];
        assert!(read_full(user, &mut rec));
        assert_eq!(words(&rec), [proto::EVENT_PAGEFAULT, at, 0, 0]);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!reader.is_finished(), "the reader went on before the fill");
        let whole = (HUGE_PAGE as i64, HUGE_PAGE);
        assert_eq!(request(chan, [proto::OP_COPY, mem + HUGE_PAGE, HUGE_PAGE, 0], &page), whole);
        assert_eq!(reader.join().unwrap(), 3);
        for off in [HUGE_PAGE, HUGE_PAGE + host, 2 * HUGE_PAGE - 1] {
            assert!(!is_missing(mem + off), "{off:#x}");
            // SAFETY: a filled page.
            assert_eq!(unsafe { ptr::read_volatile((mem + off) as *const u8) }, 3);
        }
        for off in [0, HUGE_PAGE - 1, 2 * HUGE_PAGE, 3 * HUGE_PAGE - 1] {
            assert!(is_missing(mem + off), "{off:#x}");
        }
        // Filled: EEXIST for the whole page.
        let exists = (err(libc::EEXIST), 0);
        assert_eq!(request(chan, [proto::OP_COPY, mem + HUGE_PAGE, HUGE_PAGE, 0], &page), exists);
        // Discards as Linux's hugetlb takes them (mm/madvise.c
        // madvise_dontneed_free_valid_vma): a start off the huge page is
        // EINVAL, an end inside it is rounded down (here to nothing), and
        // the page keeps its contents; a whole huge page is missing again.
        let dontneed = |at: u64, len: u64| {
            // SAFETY: registered memory.
            unsafe { crate::linux_items::madvise(at as *mut _, len as usize, libc::MADV_DONTNEED) }
        };
        assert_eq!(dontneed(mem + HUGE_PAGE + host, host), -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
        assert_eq!(dontneed(mem + HUGE_PAGE, HUGE_PAGE - host), 0);
        for off in [HUGE_PAGE, HUGE_PAGE + host, 2 * HUGE_PAGE - 1] {
            assert!(!is_missing(mem + off), "{off:#x}");
            // SAFETY: a filled page.
            assert_eq!(unsafe { ptr::read_volatile((mem + off) as *const u8) }, 3);
        }
        assert_eq!(dontneed(mem + HUGE_PAGE, HUGE_PAGE + host), 0, "{}", io::Error::last_os_error());
        for off in [HUGE_PAGE, HUGE_PAGE + host, 2 * HUGE_PAGE - 1] {
            assert!(is_missing(mem + off), "{off:#x}");
        }
        assert_eq!(request(chan, [proto::OP_ZEROPAGE, mem + HUGE_PAGE, HUGE_PAGE, 0], &[]), whole);
        // SAFETY: a page zeroed again.
        assert_eq!(unsafe { ptr::read_volatile((mem + HUGE_PAGE + host) as *const u8) }, 0);
        unregister(ctx, mem, len).unwrap();
        close(&[chan, user]);
        // SAFETY: the mapping made above, through the compatibility munmap,
        // which forgets the huge mapping (the system's would leave it in
        // HUGE_MAPPINGS, where another test's mapping at that address then
        // reads as huge).
        assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut _, len as usize) }, 0);
    }

    /// A system call that copies to or from missing registered pages waits
    /// for the handler to fill them and then completes, as Linux's
    /// `copy_to_user` and `copy_from_user` do for a userfaultfd made with
    /// `user_mode_only(false)` (upstream's `persist.rs`): their fault goes
    /// through mm/memory.c `do_anonymous_page` to `handle_userfault`.
    /// macOS's own `read` into such a page fails with `EFAULT` instead.
    #[test]
    fn test_system_calls_wait_for_missing_pages() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        let chan = channel(user);
        let [r, w] = {
            let mut fds = [0; 2];
            // SAFETY: creates two descriptors.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            fds
        };
        let data = [0x22u8; 16];
        // SAFETY: 16 bytes into the pipe; then the plain call into a missing page.
        unsafe {
            assert_eq!(libc::write(w, data.as_ptr().cast(), 16), 16);
            assert_eq!(libc::read(r, (mem + 8) as *mut core::ffi::c_void, 16), -1);
        }
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EFAULT));
        // A read into the first page (the call writes the memory, a write
        // fault as on Linux), then a write from the second (a read fault):
        // each call waits for its page.
        let page = std::vec![0x11u8; ps as usize];
        let (into, from) = (mem + 8, mem + ps + 8);
        type Call = Box<dyn FnOnce() -> isize + Send>;
        let calls: [(u64, u64, Call); 2] = [
            (into, proto::FLAG_WRITE, Box::new(move || {
                // SAFETY: registered memory; the fault is served below.
                unsafe { syscalls::read(r, into as *mut core::ffi::c_void, 16) }
            })),
            (from, 0, Box::new(move || {
                // SAFETY: as above.
                unsafe { syscalls::write(w, from as *const core::ffi::c_void, 16) }
            })),
        ];
        for (at, flags, call) in calls {
            let call = std::thread::spawn(call);
            assert!(readable(user), "no page fault event for {at:#x}");
            let mut rec = [0u8; proto::RECORD];
            assert!(read_full(user, &mut rec));
            assert_eq!(words(&rec), [proto::EVENT_PAGEFAULT, at, flags, 0]);
            std::thread::sleep(Duration::from_millis(50));
            assert!(!call.is_finished(), "the call went on before the fill");
            let base = at - at % ps;
            assert_eq!(request(chan, [proto::OP_COPY, base, ps, 0], &page), (ps as i64, ps));
            assert_eq!(call.join().unwrap(), 16);
        }
        // SAFETY: filled pages; the pipe holds what the write took.
        unsafe {
            assert_eq!(ptr::read_volatile(mem as *const u8), 0x11);
            assert_eq!(ptr::read_volatile(into as *const u8), 0x22);
            let mut back = [0u8; 16];
            assert_eq!(libc::read(r, back.as_mut_ptr().cast(), 16), 16);
            assert_eq!(back, [0x11u8; 16]);
        }
        unregister(ctx, mem, 2 * ps).unwrap();
        close(&[r, w, chan, user]);
    }

    /// Whether the peer of `fd` closed it, within five seconds.
    fn peer_closed(fd: c_int) -> bool {
        if !readable(fd) {
            return false;
        }
        let mut b = 0u8;
        // SAFETY: reads one byte.
        unsafe { libc::read(fd, (&mut b as *mut u8).cast(), 1) == 0 }
    }

    #[test]
    fn test_records_close_descriptors_not_kept() {
        let (_, user) = create(0, false, true).unwrap();
        // A record that is not a HELLO: its descriptor is closed.
        let [a, b] = socketpair();
        send_record(user, [0x99, 0, 0, 0], proto::RECORD, &[b]);
        // A HELLO with two: the first is the channel, the second is closed.
        let [c, d] = socketpair();
        let [e, f] = socketpair();
        send_record(user, [proto::HELLO, 0, 0, 0], proto::RECORD, &[d, f]);
        assert!(served(c));
        close(&[b, d, f]);
        assert!(peer_closed(a), "descriptor of a record not a HELLO kept");
        assert!(peer_closed(e), "second descriptor of a HELLO kept");
        assert!(served(c));
        close(&[a, c, e, user]);
    }

    unsafe extern "C" {
        fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> c_int;
    }

    /// Sends `sig` to every userfaultfd serving thread.
    fn signal_serving_threads(sig: c_int) {
        let mut list: libc::thread_act_array_t = ptr::null_mut();
        let mut count = 0;
        // SAFETY: lists this task's threads; the list and its ports are
        // released below.
        unsafe {
            let task = mach_task_self_;
            assert_eq!(libc::task_threads(task, &mut list, &mut count), 0);
            for i in 0..count as usize {
                let port = *list.add(i);
                let t = libc::pthread_from_mach_thread_np(port);
                let mut name = [0 as libc::c_char; 64];
                if t != 0 && libc::pthread_getname_np(t, name.as_mut_ptr(), name.len()) == 0 {
                    let name = core::ffi::CStr::from_ptr(name.as_ptr());
                    if name.to_bytes() == b"userfaultfd" {
                        libc::pthread_kill(t, sig);
                    }
                }
                mach_port_deallocate(task, port);
            }
            let size = count as usize * core::mem::size_of::<libc::thread_act_t>();
            libc::vm_deallocate(task, list as libc::vm_address_t, size as libc::vm_size_t);
        }
    }

    extern "C" fn ignore(_: c_int) {}

    #[test]
    fn test_signals_and_split_records() {
        // A handler that interrupts the serving threads' system calls.
        // SAFETY: installs a handler that does nothing, without SA_RESTART.
        unsafe {
            let mut act: libc::sigaction = core::mem::zeroed();
            act.sa_sigaction = ignore as *const () as usize;
            libc::sigemptyset(&mut act.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR2, &act, ptr::null_mut()), 0);
        }
        let (_, user) = create(0, false, true).unwrap();
        let [mine, theirs] = socketpair();
        // Half a HELLO, and signals while the serving thread waits for the rest.
        send_record(user, [proto::HELLO, 0, 0, 0], 16, &[theirs]);
        let until = Instant::now() + Duration::from_millis(200);
        while Instant::now() < until {
            signal_serving_threads(libc::SIGUSR2);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(write_full(user, &[0; 16]));
        // The HELLO arrived whole: the channel is served.
        assert!(served(mine));
        close(&[theirs, mine, user]);
    }
}
