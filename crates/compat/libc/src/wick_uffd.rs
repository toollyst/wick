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

fn page_size() -> u64 {
    PAGE.load(Ordering::Relaxed)
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
            return Some((r, (addr - start) / page_size()));
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
    let page_addr = range.start.load(Ordering::Acquire) + page * page_size();
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
/// `[start, start + len)`.
pub fn for_each_missing(start: u64, len: u64, mut f: impl FnMut(u64, u64)) {
    let ps = page_size();
    if ps == 0 {
        return;
    }
    let end = start.saturating_add(len);
    let mut run: Option<u64> = None;
    let mut addr = start - start % ps;
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
        addr += ps;
    }
    if let Some(s) = run {
        f(s, end.min(addr) - s);
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
/// Pages that are not resident are missing from now on.
pub fn register(ctx: usize, start: u64, len: u64) -> io::Result<()> {
    let ps = page_size();
    if len == 0 || !start.is_multiple_of(ps) || !len.is_multiple_of(ps) || start == 0 {
        return Err(errno_err(libc::EINVAL));
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| errno_err(libc::EINVAL))?;
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
    // Residency decides what is missing.
    let mut resident = std::vec![0u8; pages as usize];
    // SAFETY: `resident` has one byte per page of the range.
    if unsafe { libc::mincore(start as *mut _, len as usize, resident.as_mut_ptr().cast()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut alias = 0u64;
    let (mut cur, mut max) = (0, 0);
    // SAFETY: maps the same memory a second time, shared, anywhere.
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
        protect(s, l, libc::PROT_NONE)?;
        stage2(s, l, false);
    }
    Ok(())
}

/// The registered range holding all of `[start, start + len)`, which must be
/// page aligned.
fn range_of(ctx: usize, start: u64, len: u64) -> Result<&'static Range, c_int> {
    let ps = page_size();
    if ps == 0 || !start.is_multiple_of(ps) || !len.is_multiple_of(ps) || len == 0 {
        return Err(libc::EINVAL);
    }
    let (range, _) = find(start).ok_or(libc::ENOENT)?;
    if range.ctx.load(Ordering::Acquire) != ctx || start + len > range.end.load(Ordering::Acquire) {
        return Err(libc::ENOENT);
    }
    Ok(range)
}

/// Unregisters `[start, start + len)`: its missing pages become ordinary
/// (zero-filled) memory and their waiters are woken.
pub fn unregister(ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    let _guard = LOCK.lock().unwrap();
    let range = range_of(ctx, start, len)?;
    let base = range.start.load(Ordering::Acquire);
    let ps = page_size();
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
    let ps = page_size();
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
/// made accessible for `discard` to zero and release them, then they are
/// missing again and a remove event is queued (with `EVENT_REMOVE`).
pub fn discarding(start: u64, len: u64, discard: impl FnOnce() -> c_int) -> c_int {
    let ps = page_size();
    let end = start.saturating_add(len);
    let touches = ps != 0
        && RANGES.iter().any(|r| {
            let s = r.start.load(Ordering::Acquire);
            s != 0 && start < r.end.load(Ordering::Acquire) && s < end
        });
    if !touches {
        return discard();
    }
    let _guard = LOCK.lock().unwrap();
    let mut runs = Vec::new();
    for_each_missing(start, len, |s, l| runs.push((s, l)));
    for &(s, l) in &runs {
        // Missing pages hold zeros: let the discard reach them.
        let _ = protect(s, l, libc::PROT_READ | libc::PROT_WRITE);
    }
    let ret = discard();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let (from, to) = (start.max(s) - start.max(s) % ps, end.min(e));
        let mut any = false;
        let mut addr = from;
        while addr < to {
            let page = (addr - s) / ps;
            if Range::test(&r.tracked, page) {
                Range::set(&r.missing, page, true);
                any = true;
            }
            addr += ps;
        }
        if !any {
            continue;
        }
        let mut runs = Vec::new();
        for_each_missing(from, to - from, |a, l| runs.push((a, l)));
        for (a, l) in runs {
            let _ = protect(a, l, libc::PROT_NONE);
            stage2(a, l, false);
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
        let mut runs = Vec::new();
        for_each_missing(s, e - s, |a, l| runs.push((a, l)));
        let ps = page_size();
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

/// Receives a `HELLO` and its descriptor on the kernel end.
fn recv_hello(fd: c_int) -> Option<Option<c_int>> {
    let mut buf = [0u8; proto::RECORD];
    let mut cmsg = [0u64; 8];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: a zeroed msghdr is valid; the buffers outlive the call.
    let n = unsafe {
        let mut msg: libc::msghdr = core::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr().cast();
        msg.msg_controllen = core::mem::size_of_val(&cmsg) as _;
        let n = libc::recvmsg(fd, &mut msg, libc::MSG_WAITALL);
        if n == proto::RECORD as isize {
            let c = libc::CMSG_FIRSTHDR(&msg);
            if !c.is_null() && (*c).cmsg_type == libc::SCM_RIGHTS {
                let peer = *(libc::CMSG_DATA(c).cast::<c_int>());
                return Some((words(&buf)[0] == proto::HELLO).then_some(peer));
            }
        }
        n
    };
    if n <= 0 {
        None
    } else {
        // A record without a descriptor: ignored.
        Some(None)
    }
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
        proto::OP_COPY => {
            let Ok(len) = usize::try_from(b) else {
                return false;
            };
            let mut data = std::vec![0u8; len];
            if !read_full(fd, &mut data) {
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
