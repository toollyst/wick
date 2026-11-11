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
//!   backend keeps missing pages inaccessible in stage 2 ([`set_stage2_hook`])
//!   and resolves stage-2 faults with [`fault`].
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
/// Number of registered ranges (the I/O wrappers skip all work at 0).
static REGISTERED: AtomicUsize = AtomicUsize::new(0);
/// Serializes changes to the ranges.
static LOCK: Mutex<()> = Mutex::new(());
static INIT: Once = Once::new();
/// `fn(host_addr, len, present)`, set by the HVF backend.
static STAGE2: AtomicUsize = AtomicUsize::new(0);
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

/// Sets the stage-2 hook of the HVF backend: called with
/// `(host_addr, len, present)` when registered pages become present (they
/// must be accessible to the guest) or missing (they must fault).
pub fn set_stage2_hook(hook: fn(u64, u64, bool)) {
    STAGE2.store(hook as usize, Ordering::Release);
}

fn stage2(start: u64, len: u64, present: bool) {
    let hook = STAGE2.load(Ordering::Acquire);
    if hook != 0 && len > 0 {
        // SAFETY: set by `set_stage2_hook` from a `fn(u64, u64, bool)`.
        let f: fn(u64, u64, bool) = unsafe { core::mem::transmute(hook) };
        f(start, len, present);
    }
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

/// Registers `[start, start + len)` (page aligned) with userfaultfd `ctx`.
/// Pages that are not resident are missing from now on. The range must be
/// mapped (`ENOMEM`) and readable and writable (`EPERM`; Linux also takes
/// anonymous memory with other protections, which fills here would change).
/// A `MAP_HUGETLB` mapping ([`note_mapping`]) is registered in huge pages:
/// the range must be aligned to them (`EINVAL`, as Linux's hugetlb
/// registration), a huge page is missing when any host page of it is, and
/// faults and fills work on whole huge pages.
pub fn register(ctx: usize, start: u64, len: u64) -> io::Result<()> {
    let host = page_size();
    if len == 0 || start == 0 || !start.is_multiple_of(host) || !len.is_multiple_of(host) {
        return Err(errno_err(libc::EINVAL));
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| errno_err(libc::EINVAL))?;
    let ps = huge_page_of(start, end).unwrap_or(host);
    if !start.is_multiple_of(ps) || !len.is_multiple_of(ps) {
        return Err(errno_err(libc::EINVAL));
    }
    let _guard = LOCK.lock().unwrap();
    if RANGES.iter().any(|r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    }) {
        return Err(errno_err(libc::EBUSY));
    }
    let Some(range) = RANGES.iter().find(|r| r.start.load(Ordering::Acquire) == 0) else {
        return Err(errno_err(libc::ENOMEM));
    };
    let pages = len / ps;
    let mut alias = 0u64;
    let (mut cur, mut max) = (0, 0);
    // SAFETY: maps the same memory a second time, shared, anywhere. It fails
    // unless all of the range is mapped, so it comes before anything sized
    // by `len`, which a handler process sends (macOS' mincore accepts
    // unmapped pages).
    let kr = unsafe {
        mach_vm_remap(
            mach_task_self_,
            &mut alias,
            len,
            0,
            VM_FLAGS_ANYWHERE,
            mach_task_self_,
            start,
            0,
            &mut cur,
            &mut max,
            1, // VM_INHERIT_NONE
        )
    };
    if kr != 0 {
        return Err(errno_err(libc::ENOMEM));
    }
    // The alias has the protection of the memory (the most restrictive of
    // the range), and pages are filled through it and then made readable and
    // writable: memory that is not would fault on a fill, or change its
    // protection. Guest memory always is.
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    if cur & rw != rw {
        // SAFETY: unmaps the alias made above.
        unsafe { libc::munmap(alias as *mut _, len as usize) };
        return Err(errno_err(libc::EPERM));
    }
    // Residency decides what is missing: Linux's, where a page the
    // compressor or swap holds has data and is not missing (crate::mincore).
    let mut resident = std::vec![0u8; (len / host) as usize];
    // SAFETY: `resident` has one byte per host page of the range.
    if unsafe { crate::mincore(start as *mut _, len as usize, resident.as_mut_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: unmaps the alias made above.
        unsafe { libc::munmap(alias as *mut _, len as usize) };
        return Err(err);
    }
    let missing = alloc_bitmap(pages, false);
    let tracked = alloc_bitmap(pages, true);
    range.end.store(end, Ordering::Release);
    range.ctx.store(ctx, Ordering::Release);
    range.page.store(ps, Ordering::Release);
    range.alias.store(alias, Ordering::Release);
    range.missing.store(missing, Ordering::Release);
    range.tracked.store(tracked, Ordering::Release);
    // Trailing bits of the last word stay set in `tracked`; they are past `end`.
    let per_page = (ps / host) as usize;
    for page in 0..pages {
        let host_pages = &resident[page as usize * per_page..(page as usize + 1) * per_page];
        if host_pages.iter().any(|r| r & 1 == 0) {
            Range::set(&range.missing, page, true);
        }
    }
    range.start.store(start, Ordering::Release);
    REGISTERED.fetch_add(1, Ordering::AcqRel);
    // Missing pages fault from now on.
    let mut runs = Vec::new();
    for_each_missing(start, len, |s, l| runs.push((s, l)));
    for (s, l) in runs {
        protect(s, l, libc::PROT_NONE)?;
        stage2(s, l, false);
    }
    Ok(())
}

/// The registered range holding all of `[start, start + len)`, which must be
/// aligned to its pages (huge ones for a huge page range, as Linux's
/// hugetlb `UFFDIO_COPY` requires) and must not wrap (`EINVAL`, as Linux's
/// `validate_range`).
fn range_of(ctx: usize, start: u64, len: u64) -> Result<&'static Range, c_int> {
    let host = page_size();
    if host == 0 || !start.is_multiple_of(host) || !len.is_multiple_of(host) || len == 0 {
        return Err(libc::EINVAL);
    }
    let end = start.checked_add(len).ok_or(libc::EINVAL)?;
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

/// Unregisters `[start, start + len)`: its missing pages become ordinary
/// (zero-filled) memory and their waiters are woken.
pub fn unregister(ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    let _guard = LOCK.lock().unwrap();
    let range = range_of(ctx, start, len)?;
    let base = range.start.load(Ordering::Acquire);
    let ps = range.page_size();
    let mut runs = Vec::new();
    for_each_missing(start, len, |s, l| runs.push((s, l)));
    for page in (start - base) / ps..(start + len - base) / ps {
        Range::set(&range.tracked, page, false);
    }
    for (s, l) in runs {
        protect(s, l, libc::PROT_READ | libc::PROT_WRITE)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        stage2(s, l, true);
        for page in (s - base) / ps..(s + l - base) / ps {
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
        for &(a, b) in &done {
            let (a, b) = (a.max(s), b.min(e));
            if a >= b {
                continue;
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
        r.start.store(0, Ordering::Release);
        REGISTERED.fetch_sub(1, Ordering::AcqRel);
        let alias = r.alias.swap(0, Ordering::AcqRel);
        if alias != 0 {
            // SAFETY: unmaps the alias created at register.
            unsafe { libc::munmap(alias as *mut _, (e - s) as usize) };
        }
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
        with_pages(
            || prefault(buf as u64, count as u64, false),
            || unsafe { libc::write(fd, buf, count) },
        )
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
        with_pages(
            || iov_pages(iov, iovcnt, false),
            || unsafe { libc::writev(fd, iov, iovcnt) },
        )
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
        with_pages(
            || prefault(buf as u64, len as u64, false),
            || unsafe { libc::send(socket, buf, len, flags) },
        )
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
        with_pages(
            || prefault(buf as u64, len as u64, false),
            || unsafe { libc::sendto(socket, buf, len, flags, addr, addrlen) },
        )
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
        with_pages(
            || iov_pages(iov, n, false),
            || unsafe { libc::sendmsg(fd, msg, flags) },
        )
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
    fn test_register_names_mapped_memory() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = page_size();
        let mem = map(4);
        // Lengths no mapping has fail, without memory sized by them.
        for len in [1 << 62, 1 << 40, (u64::MAX - mem) & !(ps - 1)] {
            assert!(register(ctx, mem, len).is_err(), "{len:#x}");
        }
        // Part of the range unmapped: refused, and nothing is registered.
        // SAFETY: the last two pages of the mapping above.
        let r = unsafe { libc::munmap((mem + 2 * ps) as *mut _, (2 * ps) as usize) };
        assert_eq!(r, 0);
        assert!(register(ctx, mem, 4 * ps).is_err());
        assert!(!is_missing(mem));
        register(ctx, mem, 2 * ps).unwrap();
        assert!(is_missing(mem));
        // Through a handler's channel too.
        let chan = channel(user);
        let other = map(1);
        let (r, _) = request(chan, [proto::OP_REGISTER, other, 1 << 62, 0], &[]);
        assert!(r < 0);
        let (r, _) = request(chan, [proto::OP_REGISTER, other, ps, 0], &[]);
        assert_eq!(r, 0);
        assert!(is_missing(other));
        close(&[chan, user]);
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

    /// A huge page mapping is registered in huge pages (docs/PORTING.md
    /// row 10): a fault anywhere in one reports its address and waits for
    /// the whole page; a copy must be aligned to huge pages and fills a
    /// whole one; the other huge pages stay missing; a discard must start
    /// on a huge page and its end is rounded down to one, as Linux's.
    #[test]
    fn test_huge_page_ranges_fault_and_fill_whole_pages() {
        use crate::linux_items::{HUGE_PAGE, MAP_HUGETLB, MAP_HUGE_2MB};
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
        // SAFETY: the mapping made above.
        assert_eq!(unsafe { libc::munmap(mem as *mut _, len as usize) }, 0);
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
