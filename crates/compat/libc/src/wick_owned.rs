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
//! This revision makes guest RAM purgeable at allocation ([`allocate`]) and
//! registers the chunks. The discard of a whole chunk, the partial discard
//! that zeroes without giving the charge back, and the dead-page reclaim
//! follow in later revisions; the registry built here is what they act on.

use core::ffi::c_void;
use std::sync::Mutex;
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
/// `MADV_ZERO` (macOS `<sys/mman.h>`): zero the pages in place without
/// faulting new ones in. On a purgeable object the pages are zeroed and the
/// object keeps them (its charge stays; own3.c), so a partial discard zeroes
/// now and the charge returns only when the whole chunk is freed. Not
/// `MADV_FREE_REUSABLE`: a page it frees that the guest writes again is not
/// charged again, which would let a guest past the limit (linux_items `madvise`).
const MADV_ZERO: c_int = 11;

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
}

/// Every owned guest-memory range of this process. A VMM has a handful (one
/// per guest memory region), so a `Vec` under a lock is enough; the discard
/// path (a later revision) looks a host address up here.
static OWNED: Mutex<Vec<Owned>> = Mutex::new(Vec::new());

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
    debug_assert!(base % CHUNK == 0, "owned guest memory must be chunk-aligned: {base:#x}");
    debug_assert!(len > 0, "owned guest memory must be non-empty");
    // The range must be freshly reserved: not already an owned range (so the
    // carve preserves nothing, and no earlier guest's chunks are overwritten).
    {
        let owned = OWNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
    OWNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Owned { base, len, dead: std::vec![0u32; nchunks] });
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
    OWNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|o| o.base <= start && end <= o.base + o.len)
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
    let owned = OWNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
    let mut owned = OWNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let dead = &mut o.dead[i as usize];
            *dead = (*dead + (olen / page) as u32).min((csize / page) as u32);
        }
    }
    0
}
