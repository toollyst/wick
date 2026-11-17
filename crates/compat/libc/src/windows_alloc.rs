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
//! What a refusal means depends on the size asked, as on Linux, where
//! malloc's mmap is refused only for a size above the host's RAM and swap
//! (v6.1 mm/util.c `__vm_enough_memory` :1002 to :1006, the default
//! `OVERCOMMIT_GUESS`), the memory cgroup not asked there (mm/mmap.c
//! `mmap_region` :2552 to :2554 asks `security_vm_enough_memory_mm` only),
//! and is charged at a page's first touch (mm/memory.c :4117). So, with the
//! host's commit limit (RAM and pagefile, [`host_commit_limit`]) as Linux's
//! RAM and swap and the job's memory limit ([`job_memory_limit`]) as
//! `memory.max`:
//! 1. a size above the host's commit limit: null, as the system's allocator
//!    answers: a `try_reserve` gets its error and an infallible allocation
//!    ends with Rust's allocation error, as malloc's NULL does on Linux;
//! 2. a size above the job's limit, not above the host's: the end with 137
//!    and a line saying the limit cannot hold it in all, no reclaim. Linux's
//!    malloc gives it and the cgroup kills the VMM at the touch of the page
//!    past the limit; Windows commits it at the allocation, so a
//!    reservation never touched, which lives on Linux, ends here;
//! 3. any other size: the limit is reached, and the reclaim may make room
//!    (below).
//! Not in a job (unjailed), the host's commit limit is the limit of 1 and 3,
//! and there is no 2. A limit that cannot be read is no limit for 1 and 2:
//! a refusal is never turned into an allocation error by a failed read.
//!
//! A refused allocation, and only that, costs anything: on success the
//! allocator is the system's call and one check of its result
//! ([`Allocator`]). Refused, with a size of the third kind:
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

/// The host's commit limit in bytes: `GlobalMemoryStatusEx`'s
/// `ullTotalPageFile`, which Learn (`MEMORYSTATUSEX`) gives as "the current
/// committed memory limit for the system or the current process, whichever
/// is smaller"; a job memory limit (the jailer's `memory.max`) does not
/// lower it (read 0x83fc5a000 in a job of 96 MiB at its limit, as out of a
/// job, on Windows Server 2022 20348, the same as `GetPerformanceInfo`'s
/// `CommitLimit` times `PageSize`), nor raise it: a job limit 2 GiB above
/// it reads the same (`test_a_heap_allocation_above_the_hosts_commit_limit_is_refused_as_the_systems`),
/// and a per-process limit of 768 MiB or 2 GiB above it neither (measured
/// by hand on 20348 and Windows Server 2025 26100). A system call into a buffer on the
/// stack, with no lock; `test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line`
/// reads it with the job's limit reached, which proves it does not fail
/// there, not that it never allocates. `GetPerformanceInfo` is not used:
/// at the job's limit it fails (error 1450, `ERROR_NO_SYSTEM_RESOURCES`)
/// unless something freed heap before, as its count of the host's
/// processes, threads and handles needs memory. `None` if it cannot be
/// read.
pub(crate) fn host_commit_limit() -> Option<usize> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: plain data.
    let mut status: MEMORYSTATUSEX = unsafe { core::mem::zeroed() };
    status.dwLength = u32::try_from(core::mem::size_of_val(&status)).ok()?;
    // SAFETY: a structure whose length is set.
    if unsafe { GlobalMemoryStatusEx(&raw mut status) } == 0 {
        return None;
    }
    usize::try_from(status.ullTotalPageFile).ok()
}

/// The memory limit of the job this process is in, in bytes: the least of
/// its job memory limit (the jailer's `memory.max`) and its per-process
/// one, those it has; `None` out of a job, with neither, or when the query
/// fails. Only the immediate job is asked (Learn, QueryInformationJobObject:
/// "If the job is nested, the immediate job of the calling process is
/// used"), the jail's own in the jailer's nesting. A system call into a
/// buffer on the stack: no lock, no heap.
pub(crate) fn job_memory_limit() -> Option<usize> {
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, QueryInformationJobObject,
    };
    // SAFETY: plain data.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: the job of this process; a buffer of the size given.
    let ok = unsafe {
        QueryInformationJobObject(
            core::ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            u32::try_from(core::mem::size_of_val(&info)).ok()?,
            core::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return None;
    }
    let flags = info.BasicLimitInformation.LimitFlags;
    let job = (flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0).then_some(info.JobMemoryLimit);
    let process = (flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY != 0).then_some(info.ProcessMemoryLimit);
    match (job, process) {
        (Some(j), Some(p)) => Some(j.min(p)),
        (j, p) => j.or(p),
    }
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

/// The band a refused allocation of `size` falls in (the module doc's 1, 2,
/// 3), from the two limits alone so it can be decided and tested without a
/// live allocation ([`test_band_decision`]): the live commit limit is not
/// static — the system-managed pagefile auto-grows it (Learn, `MEMORYSTATUSEX`
/// `ullTotalPageFile`) — so a live over-commit is not a reliable way to reach
/// band 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Band {
    /// 1: above the host's commit limit; null, whatever the job's limit.
    Null,
    /// 2: above the job's limit (`limit`), not the host's; end with 137.
    End137 { limit: usize },
    /// 3: within both limits (or neither is known); the reclaim may help.
    Reclaim,
}

/// Which band `size` is in, given the host's commit limit and the job's
/// memory limit (each `None` when it cannot be read). Band 1 is tested first:
/// a size above the host's commit limit is null under a job's limit, over one,
/// and out of a job, as Linux's malloc is null above RAM and swap whatever
/// `memory.max` is. A limit that cannot be read is no limit (a failed read
/// never turns a refusal into a 137).
fn band_decision(size: usize, commit_limit: Option<usize>, job_limit: Option<usize>) -> Band {
    if commit_limit.is_some_and(|total| size > total) {
        return Band::Null;
    }
    if let Some(limit) = job_limit.filter(|&limit| size > limit) {
        return Band::End137 { limit };
    }
    Band::Reclaim
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
    // The band the size falls in, from the host's commit limit and the job's
    // memory limit ([`band_decision`]). Band 1 (null) is tested first: a size
    // above the host's commit limit is null under a job's limit, over one (the
    // host, not the job, cannot hold it; Linux's malloc is null there too), and
    // out of a job. Measured, neither a job memory limit (`memory.max`) nor a
    // per-process one lowers the commit limit, on Windows Server 2022 20348 and
    // 2025 26100, and `SetInformationJobObject` accepts a job limit above it,
    // so a size above the host under such a job reaches band 1 (the HEAPABOVE
    // rows). A limit that cannot be read is no limit for 1 and 2.
    match band_decision(size, host_commit_limit(), job_memory_limit()) {
        // 1: more than the host can commit at all; null, as the system's
        // allocator answers and as Linux's malloc is above RAM and swap.
        Band::Null => return core::ptr::null_mut(),
        // 2: more than the job's limit holds in all: no reclaim can make room.
        Band::End137 { limit } => {
            crate::windows_mm::end_at_the_limit(format_args!(
                "wick: heap: {what} of {size} bytes (from {from}) is more than the memory limit of {limit} bytes (the \
                 jail's memory.max) holds in all, so no reclaim ran; Linux's malloc gives it and the cgroup OOM \
                 killer ends the VMM at the touch of the page past the limit, Windows commits it at the allocation; \
                 the VMM ends (exit {})",
                crate::windows_mm::OOM_EXIT
            ));
        }
        // 3: within both limits; the reclaim may make room (below).
        Band::Reclaim => {}
    }
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

#[cfg(test)]
mod tests {
    use super::{Band, band_decision};

    /// The band decision, with injected limits (no live allocation): band 1
    /// (null) when the size is above the host's commit limit, whatever the
    /// job's limit; band 2 (end 137) when it is above the job's limit but not
    /// the host's; band 3 (reclaim) within both or with neither known. This is
    /// the deterministic proof of band 1, which a live over-commit cannot give
    /// on a host whose system-managed pagefile auto-grows the commit limit
    /// (the HEAPABOVE live rows are best-effort for that reason).
    #[test]
    fn test_band_decision() {
        // Band 1: above the host's commit limit, whatever the job's limit.
        assert_eq!(band_decision(100, Some(50), None), Band::Null, "no job");
        assert_eq!(band_decision(100, Some(50), Some(200)), Band::Null, "job above the commit limit");
        assert_eq!(band_decision(100, Some(50), Some(10)), Band::Null, "the commit limit decides first");
        assert_eq!(band_decision(100, Some(99), Some(99)), Band::Null, "one byte above");
        // Band 2: above the job's limit, not the host's.
        assert_eq!(band_decision(100, Some(200), Some(50)), Band::End137 { limit: 50 });
        assert_eq!(band_decision(100, None, Some(50)), Band::End137 { limit: 50 }, "no commit limit read");
        // Band 3: within both limits, or neither known. Equal is not "above".
        assert_eq!(band_decision(100, Some(200), Some(200)), Band::Reclaim, "within both");
        assert_eq!(band_decision(100, None, None), Band::Reclaim, "neither known");
        assert_eq!(band_decision(100, Some(100), Some(100)), Band::Reclaim, "a size equal to the limits");
        assert_eq!(band_decision(100, Some(200), None), Band::Reclaim, "within the commit limit, no job");
    }
}
