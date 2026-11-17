// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Owned (purgeable) guest memory (a wick API, not part of `libc`).
//!
//! A compromised VMM can write anonymous memory that no per-process ledger
//! counts, so the jail's memory limit does not bound it (docs/macos-memory-limit.md).
//! The fix for the common case (boot and a userfaultfd restore, whose guest
//! memory is anonymous): make guest RAM out of *purgeable* (owned) objects.
//! The kernel charges a purgeable object's pages to its owner's
//! `phys_footprint` by the object, whoever writes them and through whatever
//! mapping (`task.c` ledger `purgeable_nonvolatile`), so the guest's memory
//! counts against the jail's limit the same way a KVM guest's does against a
//! Linux memory cgroup. Measured: a 64 MiB purgeable guest charged +64 MiB
//! when the guest wrote it, and the VMM's read through a second mapping added
//! nothing (`spike_chunk_purgeable_replace`; Revision 3 a; own.c).
//!
//! Guest memory is made of one purgeable object **per 2 MiB chunk**
//! ([`CHUNK`]), not one object for the whole range. This is a hard rule, not a
//! convenience: a whole chunk's charge is given back only when its object is
//! freed (its last mapping replaced), and a replace of a *sub-range* of a
//! larger purgeable object gives nothing back (own3.c; the first run of the
//! HVF spike measured a sub-range discard at +0). So a chunk is its own
//! object, and a discard (a later revision) replaces the whole object. The
//! chunk size matches the Windows registration's 2 MiB section, so the two
//! hosts reclaim on one granularity (the parity rule).
//!
//! Guest RAM is made purgeable at allocation ([`allocate`]), and its chunks
//! registered. A discard ([`discard`]) replaces a whole chunk's object (its
//! charge comes back) or zeroes part of one in place (its charge stays,
//! counted dead); a chunk half dead is reclaimed (`reclaim_chunk`): its
//! object replaced by one holding only its live pages. A page a userfaultfd
//! has not filled (missing, [`crate::wick_uffd`]) is never read and never
//! charged by any of these: it stays missing, with its protection and the
//! guest's stage 2 as they were.
//!
//! A system call copying to or from guest memory on a thread of its own
//! (the async block engine's workers' `pread` and `pwrite`) counts the
//! chunks it touches busy for the length of the call ([`copying`], from
//! `wick_uffd::syscalls`), and the reclaim leaves a busy chunk for a later
//! discard: the reclaim replaces the chunk's object, so a copy under it
//! would read the fresh object's pages or write into the old one, which is
//! freed. The guest's own vCPUs and the main thread need no count: stage 2
//! is unmapped for the reclaim's window (`wick_guest::replacing`), and the
//! main thread is the one that discards.
//!
//! Lock order: `wick_uffd`'s lock, then [`OWNED`]'s (a discard under a
//! userfaultfd holds the first, `wick_uffd::discarding_or_refusing`, and
//! takes the second, [`discard`]). [`OWNED`]'s is the innermost: a thread
//! holding it takes no other lock of these two and never waits for a page
//! fault, and the copy path holds it only to count and uncount, never over
//! the call itself (where a fault on a missing page waits for a handler
//! whose fill needs `wick_uffd`'s lock). Debug builds check it
//! ([`held_here`], asserted where `wick_uffd` takes its lock and waits for
//! a fault).

use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::vec::Vec;
use upstream::{self as libc, c_int};

/// The chunk (and object) size: 2 MiB. One purgeable object per chunk; a
/// discard frees a whole chunk's object. Matches the Windows registration's
/// section size so the two hosts reclaim on one granularity.
pub const CHUNK: u64 = 2 << 20;

// SAFETY: the Mach VM calls on the task's own address space. Declared here as
// `linux_items` and `wick_uffd` declare the ones they use.
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_vm_allocate(task: u32, addr: *mut u64, size: u64, flags: c_int) -> c_int;
    fn mach_vm_deallocate(task: u32, addr: u64, size: u64) -> c_int;
    fn mach_vm_protect(task: u32, addr: u64, size: u64, set_maximum: c_int, new_protection: c_int) -> c_int;
    fn mach_vm_map(
        task: u32,
        addr: *mut u64,
        size: u64,
        mask: u64,
        flags: c_int,
        object: u32,
        offset: u64,
        copy: c_int,
        cur_protection: c_int,
        max_protection: c_int,
        inheritance: u32,
    ) -> c_int;
}

/// `VM_FLAGS_PURGABLE`: the allocation is a purgeable (owned) object, charged
/// to the task by the object.
const VM_FLAGS_PURGABLE: c_int = 0x2;
/// `VM_FLAGS_OVERWRITE`: the fixed allocation may map over what is already
/// there (the reservation the caller made), as Linux's `MAP_FIXED` does.
/// `VM_FLAGS_FIXED` is 0, so `FIXED | OVERWRITE | PURGABLE` is just these two.
const VM_FLAGS_OVERWRITE: c_int = 0x4000;
/// `VM_PROT_READ | VM_PROT_WRITE`: a purgeable object's default protection,
/// and guest RAM's. `VM_PROT_*` share the `PROT_*` values (read 1, write 2,
/// execute 4), so a Linux `prot` is passed to `mach_vm_protect` unchanged.
const VM_PROT_RW: c_int = libc::PROT_READ | libc::PROT_WRITE;
/// `KERN_SUCCESS`.
const KERN_SUCCESS: c_int = 0;
/// `VM_PROT_ALL`: read, write and execute, the maximum protection
/// `mach_vm_allocate` gives an allocation.
const VM_PROT_ALL: c_int = 7;
/// `VM_INHERIT_DEFAULT` (`VM_INHERIT_COPY`), what `mach_vm_allocate` gives.
const VM_INHERIT_DEFAULT: u32 = 1;
/// `MADV_ZERO` (macOS `<sys/mman.h>`): zero the pages in place without
/// faulting new ones in. On a purgeable object the pages are zeroed and the
/// object keeps them (its charge stays; own3.c), so a partial discard zeroes
/// now and the charge returns only when the whole chunk is freed. Not
/// `MADV_FREE_REUSABLE`: a page it frees that the guest writes again is not
/// charged again, which would let a guest past the limit (linux_items `madvise`).
const MADV_ZERO: c_int = 11;

/// A chunk is reclaimed once at least this fraction of its pages have been
/// zeroed by partial discards. This is a TRIGGER heuristic only -- it decides
/// WHEN to consider a chunk, never WHICH pages to drop (that is by current
/// content; see [`reclaim_chunk`]). The mechanism (move the live pages to a
/// fresh object, free the old) mirrors the Windows dead-chunk reclaim
/// (`wick_uffd::reclaim_at_touch`, `windows_mm`). The TRIGGER differs by an OS
/// gap, not by choice: Windows (and Linux's memory cgroup) reclaim at the
/// commit/charge limit, when an allocation is refused; macOS has no refused
/// commit -- a purgeable charge grows until jetsam kills, with nothing to
/// react to -- so macOS reclaims proactively at this ratio. Keep the two in
/// step when either changes (the parity rule).
const RECLAIM_DEAD_RATIO_PERCENT: u64 = 50;

/// One range of guest memory made of purgeable chunks. The chunks are
/// `[base, base + len)` split every [`CHUNK`] bytes (the last chunk is shorter
/// when `len` is not a multiple of `CHUNK`). `dead[i]` counts the pages of
/// chunk `i` a partial discard has zeroed (`MADV_ZERO`) without giving their
/// charge back: the object still owns them, so the chunk's charge stays until
/// the whole chunk is discarded; the count is what the reclaim (a later
/// revision) triggers on. A whole-chunk discard frees the chunk's object and
/// resets its count to zero (the fresh object holds nothing).
struct Owned {
    base: u64,
    len: u64,
    dead: Vec<u32>,
    /// Per chunk, the system calls copying to or from it now ([`copying`]):
    /// the reclaim leaves a chunk whose count is not 0.
    busy: Vec<u32>,
    /// This registration's own number, never reused: a copy that outlives
    /// the range ([`forget`]) uncounts nothing of a range registered at the
    /// same address after it.
    id: u64,
}

impl Owned {
    /// The chunks of this range `[a, a + l)` touches, first and last.
    fn span(&self, a: u64, l: u64) -> Option<(usize, usize)> {
        let s = a.max(self.base);
        let e = a.saturating_add(l).min(self.base + self.len);
        (s < e).then(|| (((s - self.base) / CHUNK) as usize, ((e - 1 - self.base) / CHUNK) as usize))
    }
}

/// Every owned guest-memory range of this process. A VMM has a handful (one
/// per guest memory region), so a `Vec` under a lock is enough; the discard
/// path (a later revision) looks a host address up here.
static OWNED: Mutex<Vec<Owned>> = Mutex::new(Vec::new());

/// The lowest start and the highest end of every owned range this process
/// has registered, read with no lock by [`copying`] to pass over a buffer
/// that is in none (the VMM's own memory). They only ever widen, and are
/// widened before a range is registered: a range forgotten leaves them as
/// they were, so at every instant they hold every registered range (a
/// buffer that is in one is never passed over), at worst more.
static LOW: AtomicU64 = AtomicU64::new(u64::MAX);
static HIGH: AtomicU64 = AtomicU64::new(0);
/// The next [`Owned::id`].
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The thread that holds [`OWNED`]'s lock (its `pthread_self`), 0 when none
/// does ([`held_here`]). An atomic, not a thread-local: [`held_here`] is
/// asserted in `wick_uffd::fault`, which runs in a signal handler, where a
/// thread's first touch of a thread-local may allocate.
static HOLDER: AtomicU64 = AtomicU64::new(0);

/// This thread's `pthread_self`.
fn this_thread() -> u64 {
    // SAFETY: no preconditions; async-signal-safe.
    unsafe { libc::pthread_self() as u64 }
}

/// [`OWNED`] locked, with [`HOLDER`] set for as long.
struct Registry(MutexGuard<'static, Vec<Owned>>);

impl core::ops::Deref for Registry {
    type Target = Vec<Owned>;
    fn deref(&self) -> &Vec<Owned> {
        &self.0
    }
}

impl core::ops::DerefMut for Registry {
    fn deref_mut(&mut self) -> &mut Vec<Owned> {
        &mut self.0
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        HOLDER.store(0, Ordering::Release);
    }
}

/// Locks [`OWNED`].
fn registry() -> Registry {
    let guard = OWNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    HOLDER.store(this_thread(), Ordering::Release);
    Registry(guard)
}

/// Whether this thread holds the owned ranges' lock, which is the innermost
/// (the module's lock order): `wick_uffd` asserts it does not where it
/// takes its own lock and where it waits for a page fault.
pub(crate) fn held_here() -> bool {
    HOLDER.load(Ordering::Acquire) == this_thread()
}

/// The buffers of a system call: calls its argument with each one's start
/// and length.
pub(crate) type Buffers<'a> = &'a dyn Fn(&mut dyn FnMut(u64, u64));

/// Runs `call`, a system call that copies to or from `bufs`, with each
/// owned chunk they touch counted busy until it returns, so that no reclaim
/// replaces the chunk's object under the copy (the module's doc). A buffer
/// outside the span of the owned ranges costs two atomic loads ([`LOW`],
/// [`HIGH`]); one inside it, [`OWNED`]'s lock twice, briefly, never over the
/// call. A
/// call that starts while a discard holds the lock waits for it, and then
/// copies to or from the chunk as the reclaim left it. The count is undone
/// however the call ends, by its result or by a panic (a guard's drop).
pub(crate) fn copying<T>(bufs: Buffers<'_>, call: impl FnOnce() -> T) -> T {
    let (low, high) = (LOW.load(Ordering::Acquire), HIGH.load(Ordering::Acquire));
    let mut near = false;
    bufs(&mut |a, l| near |= l != 0 && a < high && a.saturating_add(l) > low);
    if !near {
        return call();
    }
    let _busy = Busy::count(bufs);
    #[cfg(test)]
    test_hook(&IN_FLIGHT);
    call()
}

/// The owned ranges a copy counted busy ([`copying`]), by [`Owned::id`].
struct Busy<'a> {
    bufs: Buffers<'a>,
    ids: [u64; 4],
    more: Vec<u64>,
}

impl<'a> Busy<'a> {
    fn count(bufs: Buffers<'a>) -> Self {
        #[cfg(test)]
        GATE_WAITERS.fetch_add(1, Ordering::SeqCst);
        let mut owned = registry();
        #[cfg(test)]
        GATE_WAITERS.fetch_sub(1, Ordering::SeqCst);
        let mut busy = Busy { bufs, ids: [0; 4], more: Vec::new() };
        bufs(&mut |a, l| {
            for o in owned.iter_mut() {
                if let Some((first, last)) = o.span(a, l) {
                    for c in first..=last {
                        o.busy[c] += 1;
                    }
                    busy.note(o.id);
                }
            }
        });
        busy
    }

    fn note(&mut self, id: u64) {
        if self.has(id) {
            return;
        }
        match self.ids.iter_mut().find(|i| **i == 0) {
            Some(slot) => *slot = id,
            None => self.more.push(id),
        }
    }

    fn has(&self, id: u64) -> bool {
        self.ids.contains(&id) || self.more.contains(&id)
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        let mut owned = registry();
        (self.bufs)(&mut |a, l| {
            for o in owned.iter_mut() {
                if !self.has(o.id) {
                    continue;
                }
                if let Some((first, last)) = o.span(a, l) {
                    for c in first..=last {
                        o.busy[c] -= 1;
                    }
                }
            }
        });
    }
}

/// A test's hook, run where the code names it.
#[cfg(test)]
pub(crate) type TestHook = Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>;

/// Run by [`copying`] once the chunks are counted, before the call.
#[cfg(test)]
pub(crate) static IN_FLIGHT: TestHook = Mutex::new(None);

/// Run by the reclaim between the replace of the chunk's object and the
/// copy back of its live pages.
#[cfg(test)]
pub(crate) static IN_RECLAIM: TestHook = Mutex::new(None);

/// The copies waiting for [`OWNED`]'s lock to count their chunks.
#[cfg(test)]
pub(crate) static GATE_WAITERS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
fn test_hook(hook: &TestHook) {
    let f = hook.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    if let Some(f) = f {
        f();
    }
}

/// The copies counted busy in the chunk that holds `start` (0 when it is in
/// no owned range).
#[cfg(test)]
pub(crate) fn busy(start: u64) -> u32 {
    let owned = registry();
    owned.iter().find_map(|o| o.span(start, 1).map(|(c, _)| o.busy[c])).unwrap_or(0)
}

/// The chunks of `[base, base + len)`: `(chunk_base, chunk_size)` for each,
/// the last shorter when `len` is not a multiple of [`CHUNK`].
fn chunks(base: u64, len: u64) -> impl Iterator<Item = (u64, u64)> {
    (0..len).step_by(CHUNK as usize).map(move |off| (base + off, CHUNK.min(len - off)))
}

/// Commits the guest-RAM reservation `[addr, addr + len)` as owned purgeable
/// 2 MiB chunks with protection `prot`, and registers them. The caller
/// ([`crate`]'s guest-memory allocator) has reserved and 2 MiB-aligned the
/// range (a `PROT_NONE` mapping) and has written nothing to it, so replacing
/// it chunk by chunk loses no data. Returns `addr` on success, or
/// [`libc::MAP_FAILED`] with `errno` set, having released any chunk it had
/// made, on failure — the same contract as the `mmap` it stands in for.
///
/// # Safety
/// `[addr, addr + len)` must be a reserved, `CHUNK`-aligned, page-sized range
/// of the caller's that nothing else maps, as a guest-memory reservation is.
pub unsafe fn allocate(addr: *mut c_void, len: usize, prot: c_int) -> *mut c_void {
    let base = addr as u64;
    let len = len as u64;
    debug_assert!(base.is_multiple_of(CHUNK), "owned guest memory must be chunk-aligned: {base:#x}");
    debug_assert!(len > 0, "owned guest memory must be non-empty");
    // The range must be freshly reserved: not already an owned range (so the
    // carve preserves nothing, and no earlier guest's chunks are overwritten).
    {
        let owned = registry();
        debug_assert!(
            !owned.iter().any(|o| o.base < base + len && base < o.base + o.len),
            "owned guest memory overlaps an existing owned range: {base:#x}+{len:#x}"
        );
    }

    // Carve: one purgeable object per chunk, fixed over the reservation.
    let mut made: u64 = 0;
    for (cbase, csize) in chunks(base, len) {
        let mut a = cbase;
        // SAFETY: a fixed allocation over the caller's reserved range.
        let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut a, csize, VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE) };
        if kr != KERN_SUCCESS || a != cbase {
            // Give back the chunks already made and fail as `mmap` would.
            unsafe { release(base, made) };
            crate::linux_items::set_errno(libc::ENOMEM);
            return libc::MAP_FAILED;
        }
        made += csize;
    }
    // A purgeable object starts read/write; set any other protection the
    // caller asked (guest RAM is read/write, so usually a no-op).
    if prot != VM_PROT_RW {
        // SAFETY: over the range just made.
        let kr = unsafe { mach_vm_protect(mach_task_self_, base, len, 0, prot) };
        if kr != KERN_SUCCESS {
            unsafe { release(base, len) };
            crate::linux_items::set_errno(libc::EACCES);
            return libc::MAP_FAILED;
        }
    }

    let nchunks = len.div_ceil(CHUNK) as usize;
    // The bounds first, so that a copy never passes over a registered range.
    LOW.fetch_min(base, Ordering::AcqRel);
    HIGH.fetch_max(base + len, Ordering::AcqRel);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    registry().push(Owned { base, len, dead: std::vec![0u32; nchunks], busy: std::vec![0u32; nchunks], id });
    // Parity with the `mmap` this stands in for: it clears any stale huge-page
    // record of the range (these chunks are not huge pages).
    crate::wick_uffd::note_mapping(base, len, false);
    addr
}

/// Releases the first `len` bytes of chunks of `[base, ...)` (every whole
/// chunk in `[base, base + len)`), for the failure unwind of [`allocate`].
///
/// # Safety
/// `[base, base + len)` must be chunks this module made and still owns.
unsafe fn release(base: u64, len: u64) {
    for (cbase, csize) in chunks(base, len) {
        // SAFETY: a chunk object made by `allocate`.
        unsafe { mach_vm_deallocate(mach_task_self_, cbase, csize) };
    }
}

/// Whether `[start, start + len)` lies in a registered owned guest-memory
/// range. The discard path ([`crate::linux_items`]'s `discard_piece`) uses it
/// to tell guest memory, which [`discard`] handles, from the VMM's own
/// anonymous memory, which the plain anonymous replace handles as before.
pub(crate) fn is_owned(start: u64, len: u64) -> bool {
    let end = start.saturating_add(len);
    registry()
        .iter()
        .any(|o| o.base <= start && end <= o.base + o.len)
}

/// Forgets every owned range that lies within `[start, start + len)`, called
/// when that memory is unmapped ([`crate::linux_items`]'s `munmap`): the
/// unmap frees the chunks' objects, so the registry must drop their entries
/// too. Without this the entry outlives the mapping, and when the kernel gives
/// the same address to the next guest region [`is_owned`] matches a range that
/// is no longer owned (routing its discard down the owned path) and
/// [`allocate`]'s overlap check trips. Returns whether it forgot any.
pub(crate) fn forget(start: u64, len: u64) -> bool {
    let end = start.saturating_add(len);
    let mut owned = registry();
    let before = owned.len();
    owned.retain(|o| !(start <= o.base && o.base + o.len <= end));
    owned.len() != before
}

/// The host page size.
fn page_size() -> u64 {
    // SAFETY: `sysconf` has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

/// The dead-page count of the chunk that contains `start` (0 when `start` is
/// in no owned range). The reclaim (a later revision) triggers on it; a test
/// reads it to check a partial discard counted the pages it zeroed.
pub fn dead_pages(start: u64) -> u32 {
    let owned = registry();
    for o in owned.iter() {
        if o.base <= start && start < o.base + o.len {
            return o.dead[((start - o.base) / CHUNK) as usize];
        }
    }
    0
}

/// Discards `[start, start + len)` of owned guest memory, per 2 MiB chunk,
/// through the backend's replace hook so the guest's stage 2 follows:
/// - a chunk the discard fully covers is freed and replaced by a fresh
///   purgeable object of the chunk's protection (its `purgeable_nonvolatile`
///   charge returned, the guest reads zero), as proven under a live guest by
///   the b-core spike (−CHUNK, stage 2 follows);
/// - a chunk only partly covered has the covered pages zeroed in place with
///   `MADV_ZERO` (the object keeps them, so the chunk's charge stays pinned
///   until the whole chunk goes) and those pages counted dead for the reclaim
///   (a later revision).
///
/// The caller has checked the range is owned ([`is_owned`]), so it lies in one
/// registered range. Returns 0, or -1 with `errno` set, as the `mmap` /
/// `madvise` discard it replaces.
///
/// # Safety
/// `[start, start + len)` must be a mapped sub-range of one owned range.
pub unsafe fn discard(start: u64, len: u64, prot: c_int) -> c_int {
    if len == 0 {
        return 0;
    }
    let end = start + len;
    let page = page_size();
    let mut owned = registry();
    let Some(o) = owned.iter_mut().find(|o| o.base <= start && end <= o.base + o.len) else {
        // The caller checked `is_owned`; a miss here is a straddle or a race.
        crate::linux_items::set_errno(libc::ENOMEM);
        return -1;
    };
    let base = o.base;
    let first = (start - base) / CHUNK;
    let last = (end - 1 - base) / CHUNK;
    for i in first..=last {
        let cbase = base + i * CHUNK;
        let csize = CHUNK.min(o.len - i * CHUNK);
        let cend = cbase + csize;
        let os = start.max(cbase);
        let oe = end.min(cend);
        if os == cbase && oe == cend {
            // Whole chunk: free its object, a fresh purgeable one in its place.
            // A system call copying to or from it now ([`copying`]) is the
            // guest's own doing, as on Linux, where `MADV_DONTNEED` zaps the
            // pages under a copy and the copy lands in the old page or the
            // new one: here in the old object or the fresh one.
            let ok = crate::wick_guest::replacing(cbase, csize, false, || {
                let mut a = cbase;
                // SAFETY: a fixed purgeable allocation over the chunk's range.
                unsafe {
                    mach_vm_allocate(mach_task_self_, &mut a, csize, VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE)
                        == KERN_SUCCESS
                        && a == cbase
                }
            });
            if !ok {
                crate::linux_items::set_errno(libc::ENOMEM);
                return -1;
            }
            if prot != VM_PROT_RW {
                // SAFETY: over the fresh chunk just made.
                unsafe { mach_vm_protect(mach_task_self_, cbase, csize, 0, prot) };
            }
            o.dead[i as usize] = 0;
        } else {
            // Partial: zero the covered pages; the object keeps them (charge pinned).
            let olen = oe - os;
            let ok = crate::wick_guest::replacing(os, olen, false, || {
                // SAFETY: a mapped sub-range of the chunk.
                unsafe { libc::madvise(os as *mut c_void, olen as usize, MADV_ZERO) == 0 }
            });
            if !ok {
                return -1; // `errno` set by `madvise`.
            }
            let per_chunk = (csize / page) as u32;
            o.dead[i as usize] = (o.dead[i as usize] + (olen / page) as u32).min(per_chunk);
            // Reclaim this chunk once enough of it is dead (a trigger only: the
            // move below drops pages by current content, not by this count).
            // A chunk a system call is copying to or from now is left for a
            // later discard ([`copying`]), its count kept.
            if o.dead[i as usize] as u64 * 100 >= per_chunk as u64 * RECLAIM_DEAD_RATIO_PERCENT && o.busy[i as usize] == 0 {
                // SAFETY: chunk `i` of this owned range.
                if unsafe { reclaim_chunk(cbase, csize, page) } {
                    o.dead[i as usize] = 0;
                }
                // A failed reclaim leaves the count; the next discard retries.
            }
        }
    }
    0
}

/// Whether the `len` bytes at `p` are all zero.
fn is_zero(p: u64, len: u64) -> bool {
    // SAFETY: `p` is a mapped, 8-byte-aligned page of the caller's.
    let words = unsafe { std::slice::from_raw_parts(p as *const u64, (len / 8) as usize) };
    words.iter().all(|&w| w == 0)
}

/// Reclaims chunk `[cbase, cbase + csize)`: under the quiesce the replace hook
/// gives ([`crate::wick_guest::replacing`] unmaps the chunk's guest slot, so a
/// guest access stalls and cannot write the old object), scans the chunk's
/// CURRENT content and replaces its object with a fresh purgeable one holding
/// only the pages that are not currently all-zero. The all-zero pages are
/// dropped -- they re-fault to zero, which the guest cannot tell from their
/// old value whatever its history -- so the pinned charge falls to the live
/// (non-zero) set.
///
/// The drop is decided by CONTENT, never by the dead marks: the guest can
/// re-write a zeroed page to non-zero without this library seeing it (it
/// writes the purgeable object through stage 2, not through a `libc` call), so
/// a dead mark is not a safe drop oracle -- trusting it would drop a
/// re-written live page and lose the guest's data. A page the move copies is
/// taken out before the object is replaced and written back after, all while
/// the chunk is quiesced, so no guest write can reach the freed object.
///
/// A page a userfaultfd has not filled (missing, [`crate::wick_uffd`]) is
/// never read: it holds nothing by definition (a fill writes the whole page),
/// so it is dropped without a look and stays missing, its host protection
/// (`PROT_NONE`) and the guest's stage 2 (no permission, `Slot::map` looks at
/// `is_missing`) as they were; its next access faults to the handler as
/// before. Reading it faulted on its `PROT_NONE`, and the fault waited for a
/// fill that needs [`crate::wick_uffd`]'s lock, which the discard that runs
/// this holds: the VMM hung (`test_a_reclaim_reads_no_missing_page`). The
/// fresh object is mapped with no access and each page then gets back the
/// protection it had, by runs, so no page is more accessible than before at
/// any time (a fresh object mapped read-write, as before, would make a
/// missing page read as zeros without a fault). A page that is not missing
/// and that this may not read (`PROT_NONE` guest memory) is given read
/// access for the scan and the save only, under the quiesce, and gets its
/// own protection back with the others (or on the old object, when the
/// replace is not made), its data kept
/// (`test_a_reclaim_keeps_an_unreadable_pages_data_and_protection`). This is
/// defensive: Firecracker never makes part of a chunk so, as virtio-mem
/// protects and discards whole slots, and a slot is whole chunks
/// (`vstate/memory.rs` `update_slot`; `memory_hotplug.rs`: blocks of at
/// least 2 MiB, slots a multiple of them). A chunk with a page in no
/// mapping is not reclaimed: its dead count stays and a later discard tries
/// again. Returns whether the chunk was replaced (`false` leaves it as it
/// was).
///
/// # Safety
/// `[cbase, cbase + csize)` is a chunk of a range this process owns. When a
/// userfaultfd registration may cover it, the caller holds its lock, so
/// that no page becomes missing or filled meanwhile (the discard path,
/// `wick_uffd::discarding_or_refusing`).
unsafe fn reclaim_chunk(cbase: u64, csize: u64, page: u64) -> bool {
    let npages = (csize / page) as usize;
    // The pages a userfaultfd has not filled: never read.
    let mut missing = std::vec![false; npages];
    crate::wick_uffd::for_each_missing(cbase, csize, |a, l| {
        for p in (a - cbase) / page..(a + l - cbase) / page {
            missing[p as usize] = true;
        }
    });
    // Each page's protection as it is now, given back after the replace.
    let prot = crate::wick_uffd::raw_protections(cbase, cbase + csize);
    if prot.iter().any(|&p| p < 0) {
        return false;
    }
    // The runs of pages that are not missing and may not be read: read
    // access for the scan and the save only.
    let mut unreadable: Vec<(usize, usize)> = Vec::new();
    for p in (0..npages).filter(|&p| !missing[p] && prot[p] & libc::PROT_READ == 0) {
        match unreadable.last_mut() {
            Some((_, e)) if *e == p && prot[p] == prot[p - 1] => *e = p + 1,
            _ => unreadable.push((p, p + 1)),
        }
    }
    // Gives the old object's unreadable pages their protection back.
    let undo = |upto: usize| {
        for &(s, e) in &unreadable[..upto] {
            restore(cbase + s as u64 * page, (e - s) as u64 * page, prot[s]);
        }
    };
    crate::wick_guest::replacing(cbase, csize, false, || {
        for (i, &(s, e)) in unreadable.iter().enumerate() {
            // SAFETY: pages of the chunk, quiesced.
            let kr = unsafe {
                mach_vm_protect(mach_task_self_, cbase + s as u64 * page, (e - s) as u64 * page, 0, prot[s] | libc::PROT_READ)
            };
            if kr != KERN_SUCCESS {
                undo(i);
                return false;
            }
        }
        // Scan: the offsets (in pages) of the chunk's live (non-zero) pages.
        let live: Vec<usize> = (0..npages).filter(|&p| !missing[p] && !is_zero(cbase + p as u64 * page, page)).collect();

        // The live pages are saved in a temporary mapping (not `malloc`, whose
        // `free` keeps the memory in its pool and so would hold the charge the
        // reclaim is giving back); `munmap` returns it to the kernel at once.
        let bytes = live.len() * page as usize;
        let tmp = if bytes == 0 {
            libc::MAP_FAILED.cast::<u8>()
        } else {
            // SAFETY: a fresh anonymous mapping for the live pages.
            let t = unsafe {
                libc::mmap(core::ptr::null_mut(), bytes, VM_PROT_RW, libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
            };
            if t == libc::MAP_FAILED {
                undo(unreadable.len());
                return false;
            }
            for (k, &p) in live.iter().enumerate() {
                // SAFETY: src a live page of the chunk, dst its slot in `t`.
                unsafe {
                    core::ptr::copy_nonoverlapping((cbase + p as u64 * page) as *const u8, t.cast::<u8>().add(k * page as usize), page as usize)
                };
            }
            t.cast::<u8>()
        };

        // A fresh purgeable object over the chunk, with no access yet.
        let mut a = cbase;
        // SAFETY: a fixed purgeable mapping over the chunk's range.
        let made = unsafe {
            mach_vm_map(
                mach_task_self_,
                &mut a,
                csize,
                0,
                VM_FLAGS_OVERWRITE | VM_FLAGS_PURGABLE,
                0,
                0,
                0,
                libc::PROT_NONE,
                VM_PROT_ALL,
                VM_INHERIT_DEFAULT,
            ) == KERN_SUCCESS
                && a == cbase
        };
        if made {
            #[cfg(test)]
            test_hook(&IN_RECLAIM);
            // Each run of one protection: its live pages written back through
            // read-write, then the protection it had.
            let mut k = 0;
            let mut s = 0;
            while s < npages {
                let mut e = s + 1;
                while e < npages && prot[e] == prot[s] {
                    e += 1;
                }
                let (at, len) = (cbase + s as u64 * page, (e - s) as u64 * page);
                let writes = k < live.len() && live[k] < e;
                if writes {
                    restore(at, len, VM_PROT_RW);
                    while k < live.len() && live[k] < e {
                        // SAFETY: src the saved page, dst the fresh page of the chunk.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                tmp.add(k * page as usize),
                                (cbase + live[k] as u64 * page) as *mut u8,
                                page as usize,
                            )
                        };
                        k += 1;
                    }
                }
                if if writes { prot[s] != VM_PROT_RW } else { prot[s] != libc::PROT_NONE } {
                    restore(at, len, prot[s]);
                }
                s = e;
            }
        } else {
            undo(unreadable.len());
        }
        if bytes != 0 {
            // SAFETY: the mapping from `mmap` above, of `bytes`.
            unsafe { libc::munmap(tmp.cast::<c_void>(), bytes) };
        }
        made
    })
}

/// Gives `[at, at + len)` of a chunk just replaced (or of one the replace
/// was not made over) protection `prot`. The chunk's pages hold the guest's memory and nothing else has them: a
/// protection that cannot be given would leave the guest's live pages
/// unreachable or its missing ones reachable, so the process ends with the
/// reason, as a guest range that cannot be mapped again does
/// ([`crate::wick_guest::replacing`]).
fn restore(at: u64, len: u64, prot: c_int) {
    // SAFETY: pages of the fresh chunk.
    if unsafe { mach_vm_protect(mach_task_self_, at, len, 0, prot) } != KERN_SUCCESS {
        std::eprintln!("wick: owned guest memory at {at:#x}+{len:#x} cannot get back its protection {prot} after a reclaim");
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reserves `len + CHUNK` bytes and returns a `CHUNK`-aligned base in them.
    fn reserve(len: u64) -> u64 {
        // SAFETY: a fresh anonymous reservation.
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                (len + CHUNK) as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED, "reserve");
        (raw as u64).next_multiple_of(CHUNK)
    }

    /// An owned range is forgotten when it is unmapped, so the kernel can give
    /// its address to the next guest region without the registry taking the new
    /// one for the old (the macOS CI regression: a dropped region's entry
    /// outlived it, and the upstream `vstate::memory` tests, which reuse the
    /// address, tripped `allocate`'s overlap check).
    #[test]
    fn an_owned_range_is_forgotten_on_munmap_so_its_address_reuses_cleanly() {
        let len = 2 * CHUNK;
        let base = reserve(len);
        // SAFETY: the reserved, chunk-aligned range.
        let p = unsafe { allocate(base as *mut c_void, len as usize, VM_PROT_RW) };
        assert_eq!(p as u64, base, "allocate returns its range");
        assert!(is_owned(base, len), "registered after allocate");

        // Unmap it as the guest region's `Drop` does: the entry is forgotten.
        // SAFETY: the owned range just made.
        assert_eq!(unsafe { crate::munmap(base as *mut c_void, len as usize) }, 0, "munmap");
        assert!(!is_owned(base, len), "forgotten on munmap");

        // The kernel reuses the address for the next region; a second owned
        // range there must allocate cleanly (before the fix a stale entry made
        // it overlap). Reserve the same address again, then allocate.
        // SAFETY: the address is free; a fixed reservation of it.
        let raw2 = unsafe {
            libc::mmap(
                base as *mut c_void,
                len as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_NORESERVE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(raw2 as u64, base, "the freed address is reusable");
        // SAFETY: the freshly reserved range at the reused address.
        let p2 = unsafe { allocate(base as *mut c_void, len as usize, VM_PROT_RW) };
        assert_eq!(p2 as u64, base, "the reused address allocates cleanly (no stale overlap)");
        assert!(is_owned(base, len));
        // SAFETY: the second owned range; cleans up.
        unsafe { crate::munmap(base as *mut c_void, len as usize) };
    }
}
