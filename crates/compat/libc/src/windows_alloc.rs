// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The heap's allocator for wick's Windows binaries: the system's
//! (`HeapAlloc`, [`std::alloc::System`]), and, when the memory limit (a
//! jail's job, or the host's commit limit) refuses an allocation, what
//! Linux's memory cgroup does at a charge it cannot make: a reclaim, then
//! the end of the VMM with 137 (v6.1 mm/memcontrol.c `try_charge_memcg`:
//! `try_to_free_mem_cgroup_pages` at :2681, a charge again after a reclaim
//! that freed pages at :2705 to :2706, then `mem_cgroup_oom` at :2729, whose
//! killer's SIGKILL ends the VMM). On Linux a heap allocation is never
//! refused so: the memory cgroup charges each page at its first touch and
//! kills there. Without this allocator a refused allocation of Rust's ends
//! the process with `std::process::abort` (0xC0000409), and no reclaim is
//! tried.
//!
//! A refused allocation, and only that, costs anything: on success the
//! allocator is the system's call and one check of its result
//! ([`Allocator`]). Refused:
//! - inside a [`fallible`] call (wick's own `try_reserve` sites, which
//!   answer `ENOMEM`), it returns null, as the system's would;
//! - on a thread that holds a lock of wick's memory layer
//!   (`windows_stacklock::held_here`, kept by every such lock), that runs the
//!   process's exception handler (`windows_mm::in_the_handler`), or that is
//!   the reclaim's own (`wick_uffd::on_the_reclaimer`), it ends the process
//!   at once: the reclaim takes those locks and that thread, and the
//!   handler and the reclaimer allocate nothing by design;
//! - else the reclaim runs (`wick_uffd::reclaim_at_touch`, as a lazy page's
//!   refused commit asks it), and the allocation is tried once more if it
//!   gave something back;
//! - still refused, the process ends with 137 and a line naming the size
//!   asked, whether a reclaim ran and what it gave back
//!   (`windows_mm::end_at_the_limit`, which allocates nothing).

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

/// The heap's allocator: [`System`]'s, with the end at the memory limit
/// the module's documentation gives. A binary makes it its own with
/// `#[global_allocator]`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Allocator;

// SAFETY: every call is `System`'s, with the same arguments; a refused one
// returns null or another of `System`'s results, or never returns.
unsafe impl GlobalAlloc for Allocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            return p;
        }
        // SAFETY: as above.
        refused(layout.size(), Kind::Alloc, || unsafe { System.alloc(layout) })
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            return p;
        }
        // SAFETY: as above.
        refused(layout.size(), Kind::Zeroed, || unsafe { System.alloc_zeroed(layout) })
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            return p;
        }
        // Refused, the block is as it was (`GlobalAlloc::realloc`): asked
        // again, the same.
        // SAFETY: as above.
        refused(new_size, Kind::Realloc(layout.size()), || unsafe { System.realloc(ptr, layout, new_size) })
    }
}

/// Which call was refused, for the line.
#[derive(Clone, Copy)]
enum Kind {
    Alloc,
    Zeroed,
    /// A reallocation, from a block of this size.
    Realloc(usize),
}

std::thread_local! {
    /// [`fallible`] calls this thread is in.
    static FALLIBLE: Cell<u32> = const { Cell::new(0) };
    /// [`installed`]'s question is asked on this thread: 1 asked, 2 seen.
    static ASKED: Cell<u8> = const { Cell::new(0) };
}

/// Runs `f`, in which a refused allocation returns null instead of ending
/// the process: for wick's own sites that ask with `try_reserve` and
/// answer `ENOMEM`, as they did before this allocator. Nested calls nest.
pub(crate) fn fallible<T>(f: impl FnOnce() -> T) -> T {
    struct Depth;
    impl Drop for Depth {
        fn drop(&mut self) {
            FALLIBLE.with(|d| d.set(d.get() - 1));
        }
    }
    FALLIBLE.with(|d| d.set(d.get() + 1));
    let _depth = Depth;
    f()
}

/// Whether the process's heap allocator is [`Allocator`]: an allocation no
/// heap can make (`isize::MAX` bytes less 7) is asked for with this thread
/// marked, and only [`Allocator`]'s refusal sees the mark. The system's
/// returns null. Allocates nothing.
pub fn installed() -> bool {
    ASKED.with(|a| a.set(1));
    let layout = Layout::from_size_align(isize::MAX.unsigned_abs() - 7, 8).expect("a valid layout");
    // SAFETY: a layout of non-zero size; the block, were it made, is freed.
    let p = unsafe { std::alloc::alloc(layout) };
    if !p.is_null() {
        // SAFETY: just allocated with this layout.
        unsafe { std::alloc::dealloc(p, layout) };
    }
    ASKED.with(|a| a.replace(0)) == 2
}

/// Why a refused allocation on this thread ends the process with no
/// reclaim, if it does: the reclaim takes the locks of wick's memory layer
/// and its own thread, and the exception handler's thread may be any.
fn no_reclaim_here() -> Option<&'static str> {
    if crate::windows_mm::in_the_handler() {
        Some("in the exception handler")
    } else if crate::wick_uffd::on_the_reclaimer() {
        Some("on the reclaim's own thread")
    } else if crate::windows_stacklock::held_here() > 0 {
        Some("with a lock of wick's memory layer held")
    } else {
        None
    }
}

/// An allocation of `size` bytes ([`Kind`]) the system refused; `again`
/// asks for it once more.
#[cold]
#[inline(never)]
fn refused(size: usize, kind: Kind, again: impl FnOnce() -> *mut u8) -> *mut u8 {
    if ASKED.with(|a| a.get()) == 1 {
        ASKED.with(|a| a.set(2));
        return core::ptr::null_mut();
    }
    if FALLIBLE.with(Cell::get) > 0 {
        return core::ptr::null_mut();
    }
    let what = match kind {
        Kind::Alloc => "an allocation",
        Kind::Zeroed => "a zeroed allocation",
        Kind::Realloc(_) => "a reallocation",
    };
    let from = match kind {
        Kind::Realloc(old) => old,
        _ => 0,
    };
    if let Some(why) = no_reclaim_here() {
        crate::windows_mm::end_at_the_limit(format_args!(
            "wick: heap: {what} of {size} bytes (from {from}) was refused at the memory limit (the jail's \
             memory.max, or the host's commit limit), {why}, so no reclaim ran; the VMM ends, as the cgroup OOM \
             killer ends it on Linux (exit {})",
            crate::windows_mm::OOM_EXIT
        ));
    }
    let freed = crate::wick_uffd::reclaim_at_touch(size).freed;
    if freed > 0 {
        let p = again();
        if !p.is_null() {
            return p;
        }
    }
    crate::windows_mm::end_at_the_limit(format_args!(
        "wick: heap: {what} of {size} bytes (from {from}) was refused at the memory limit (the jail's memory.max, or \
         the host's commit limit); the reclaim gave back {freed} bytes{}; the VMM ends, as the cgroup OOM \
         killer ends it on Linux (exit {})",
        if freed > 0 { ", and the allocation was refused again" } else { "" },
        crate::windows_mm::OOM_EXIT
    ));
}
