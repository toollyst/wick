// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `mmap` and friends on Windows, with Linux semantics, on placeholder
//! virtual memory (Windows 10 1803 and later).
//!
//! Every mapping made here is one Windows allocation unit, recorded in a
//! table:
//! - a *placeholder*: reserved address space with nothing behind it. A fresh
//!   anonymous `PROT_NONE` mapping is one. Placeholders split and coalesce
//!   freely, which is what partial `munmap` and `MAP_FIXED` need;
//! - a *private* allocation (anonymous private memory, and private file
//!   mappings, which are filled from the file when mapped);
//! - a *view* of a section (shared mappings: anonymous shared memory, files,
//!   memfds).
//!
//! Linux operations map onto these:
//! - `mmap`: reserves a placeholder (or, with `MAP_FIXED`, turns what is in
//!   the range back into one) and replaces it with the mapping; with no
//!   usable hint, an anonymous private mapping whose length is a multiple of
//!   2 MiB is placed on a 2 MiB boundary, as Linux since 6.7 (v6.12
//!   mm/mmap.c :902 to :907; v6.1 and v5.10 do not), anywhere if no such
//!   address is free (`new_placeholder_aligned`). Offsets into
//!   files must be multiples of 64 KiB, Windows' allocation granularity, and
//!   shared file mappings must lie within the file; anything else fails with
//!   `EINVAL`;
//! - `munmap`: placeholders are released; whole allocations and views are
//!   released; part of a private allocation is decommitted, part of a view is
//!   made inaccessible (its memory is the section's, as on Linux it is the
//!   file's), and the unit is released once nothing of it is left;
//! - `MAP_FIXED` anonymous private memory over part of a private allocation
//!   recommits it zero-filled in place; over part of a view it fails with
//!   `EINVAL`, as Windows cannot replace part of a view;
//! - `mprotect`: `VirtualProtect`; making a placeholder accessible commits
//!   zero-filled memory, as Linux faults in zero pages; lazy memory's
//!   untouched pages stay uncommitted under any protection (`LAZY`);
//! - `madvise(MADV_DONTNEED)`: private memory is decommitted and recommitted,
//!   so it reads as zeros, or as the file again for a private file mapping;
//!   shared mappings keep their data, as on Linux. Advice without an effect
//!   on Windows is accepted;
//! - `mincore`: working-set residency (`QueryWorkingSetEx`);
//! - `msync`: `FlushViewOfFile`, and `FlushFileBuffers` for `MS_SYNC`.
//!
//! `MAP_HUGETLB` on anonymous private memory maps large pages
//! (`MEM_LARGE_PAGES`, which needs `SeLockMemoryPrivilege`); see
//! `map_large`. They are changed in whole large pages: `munmap` of part of
//! one mapping and a mapping without `MAP_HUGETLB` at a fixed address over
//! it fail with `EINVAL`; a `MAP_HUGETLB` mapping at a fixed address over
//! whole pages of it, and `MADV_DONTNEED`, zero them in place. Windows
//! changes no large page's protection, so a mapping keeps the one it was
//! made with: `mprotect` grants only that one (`EACCES` otherwise), and a
//! fixed `MAP_HUGETLB` mapping with another protection is made only over a
//! whole mapping, which is allocated again (`fixed_large`). Everything
//! else with `MAP_HUGETLB` fails with `ENOMEM`, as Linux does without huge
//! pages.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
#[cfg(test)]
use std::sync::Mutex;

use crate::windows_stacklock::{ProbedMutex, ProbedRwLock};
use std::vec::Vec;

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
use windows_sys::Win32::System::Memory::{
    GetLargePageMinimum, MEM_LARGE_PAGES,
    CreateFileMappingW, FlushViewOfFile, MEM_COMMIT, MEM_DECOMMIT, MEM_PRESERVE_PLACEHOLDER,
    MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER,
    MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile3, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PrefetchVirtualMemory, UnmapViewOfFile2, VirtualAlloc2, VirtualFree, VirtualProtect,
    VirtualQuery, WIN32_MEMORY_RANGE_ENTRY, DiscardVirtualMemory,
};
use windows_sys::Win32::System::ProcessStatus::{
    PSAPI_WORKING_SET_EX_INFORMATION, QueryWorkingSetEx,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::windows_fd::{wick_fd, handle, set_errno};
use crate::{c_int, c_uchar, c_void, off_t, size_t};

/// No access.
pub const PROT_NONE: c_int = 0;
/// Read.
pub const PROT_READ: c_int = 1;
/// Write.
pub const PROT_WRITE: c_int = 2;
/// Execute.
pub const PROT_EXEC: c_int = 4;
/// Shared mapping.
pub const MAP_SHARED: c_int = 0x01;
/// Private (copy-on-write) mapping.
pub const MAP_PRIVATE: c_int = 0x02;
/// At exactly `addr`, replacing what is there.
pub const MAP_FIXED: c_int = 0x10;
/// Not backed by a file.
pub const MAP_ANONYMOUS: c_int = 0x20;
/// Same as `MAP_ANONYMOUS`.
pub const MAP_ANON: c_int = MAP_ANONYMOUS;
/// No swap reservation (Windows commits lazily anyway).
pub const MAP_NORESERVE: c_int = 0x4000;
/// Prefault the mapping.
pub const MAP_POPULATE: c_int = 0x8000;
/// Huge pages.
pub const MAP_HUGETLB: c_int = 0x40000;
/// Shift of the huge page size in the flags.
pub const MAP_HUGE_SHIFT: c_int = 26;
/// 2 MiB huge pages.
pub const MAP_HUGE_2MB: c_int = 21 << MAP_HUGE_SHIFT;
/// 1 GiB huge pages.
pub const MAP_HUGE_1GB: c_int = 30 << MAP_HUGE_SHIFT;
/// What `mmap` returns on failure.
pub const MAP_FAILED: *mut c_void = !0 as *mut c_void;

/// No special treatment.
pub const MADV_NORMAL: c_int = 0;
/// Random access.
pub const MADV_RANDOM: c_int = 1;
/// Sequential access.
pub const MADV_SEQUENTIAL: c_int = 2;
/// Will be needed: prefetched.
pub const MADV_WILLNEED: c_int = 3;
/// Not needed: private memory is dropped.
pub const MADV_DONTNEED: c_int = 4;
/// May be freed: private memory is discarded.
pub const MADV_FREE: c_int = 8;
/// Free the backing store (not supported).
pub const MADV_REMOVE: c_int = 9;
/// Not inherited by `fork`.
pub const MADV_DONTFORK: c_int = 10;
/// Inherited by `fork`.
pub const MADV_DOFORK: c_int = 11;
/// KSM candidate.
pub const MADV_MERGEABLE: c_int = 12;
/// Not a KSM candidate.
pub const MADV_UNMERGEABLE: c_int = 13;
/// Transparent huge pages.
pub const MADV_HUGEPAGE: c_int = 14;
/// No transparent huge pages.
pub const MADV_NOHUGEPAGE: c_int = 15;
/// Not in core dumps.
pub const MADV_DONTDUMP: c_int = 16;
/// In core dumps.
pub const MADV_DODUMP: c_int = 17;

/// `msync`: asynchronous.
pub const MS_ASYNC: c_int = 1;
/// `msync`: invalidate other mappings.
pub const MS_INVALIDATE: c_int = 2;
/// `msync`: synchronous.
pub const MS_SYNC: c_int = 4;

/// `VirtualFree`: merge adjacent placeholders (in `SystemServices`).
const MEM_COALESCE_PLACEHOLDERS: u32 = 1;
const PAGE: usize = 4096;
const GRANULE: usize = 64 * 1024;

/// Fork mapping objects.
pub mod wick_mm {
    use super::*;

    /// What `mmap` and `mprotect` call when asked for `PROT_EXEC` once the
    /// host sandbox prohibits dynamic code (`vmm::ext::sandbox`): the
    /// counterpart of upstream's seccomp rules for both calls, which trap
    /// when the protection includes `PROT_EXEC`. The hook raises `SIGSYS`;
    /// if it returns, the call fails as Windows refuses the mapping.
    pub fn deny_exec(hook: extern "C" fn(c_int)) {
        EXEC_DENIED.store(hook as usize, std::sync::atomic::Ordering::Release);
    }

    pub(super) static EXEC_DENIED: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    pub use super::Access;

    /// The guest's access to `addr`, host memory of guest RAM, that the
    /// hypervisor reported (WHP's memory access exit): commits the pages of
    /// lazy memory there ([`super::LAZY`]). `write`: the access was a write.
    pub fn commit_on_access(addr: usize, write: bool) -> Access {
        super::commit_on_access(addr, write).0
    }

    /// [`commit_on_access`], with the range it committed (empty unless
    /// [`Access::Committed`]): a page, or the transparent huge page around
    /// `addr` in a range advised `MADV_HUGEPAGE` ([`HUGE_PAGE`]), which the
    /// caller can have the hypervisor map at once.
    pub fn commit_block_on_access(addr: usize, write: bool) -> (Access, core::ops::Range<usize>) {
        super::commit_access(addr, write, false)
    }

    /// [`commit_block_on_access`] for an access to a page an answer of the
    /// caller's committed before (WHP's run loop: the same page exited
    /// again): asks first whether what the access would commit in lazy
    /// memory (its page; a write's 2 MiB block where `MADV_HUGEPAGE` is) is
    /// committed already, and answers [`Access::Present`] if all of it is,
    /// where the commit would answer [`Access::Committed`] having committed
    /// nothing; else commits as [`commit_block_on_access`] does. A system
    /// call more than [`commit_block_on_access`], which a first access does
    /// not pay.
    pub fn commit_block_on_access_again(addr: usize, write: bool) -> (Access, core::ops::Range<usize>) {
        super::commit_access(addr, write, true)
    }

    /// The block a first access commits in a range advised
    /// `MADV_HUGEPAGE`: a transparent huge page of x86-64 Linux.
    pub const HUGE_PAGE: usize = super::HUGE_PAGE;

    /// Splits `[addr, addr + len)`, memory a host read takes, into runs that
    /// read as zeros without being touched (lazy memory not committed) and
    /// runs to read as they are: `f(start, len, zeros)` for each in order.
    /// So that a read of guest RAM the guest never touched commits nothing,
    /// as Linux maps its zero page for it.
    pub fn zero_runs(addr: usize, len: usize, f: impl FnMut(usize, usize, bool)) {
        super::zero_runs(addr, len, f);
    }

    /// Ends the process for memory that could not be committed
    /// ([`Access::Exhausted`]), as the cgroup OOM killer ends the VMM.
    pub fn out_of_memory(addr: usize, err: u32) -> ! {
        super::out_of_memory(addr, err)
    }

    pub use super::Settled;

    /// A guest access that the commit ([`commit_block_on_access`]) and the
    /// userfaultfd (`wick_uffd::fault`) both left, looked at once more under
    /// the locks every change of it takes: [`Settled`].
    pub fn settled_access(addr: usize, write: bool) -> Settled {
        super::settled_access(addr, write)
    }

    /// Runs `f` with the pages it asks about kept as they are, given
    /// whether each allows an access now: [`super::with_pages_still`].
    pub fn with_pages_still<T>(f: impl FnOnce(&dyn Fn(usize, bool) -> bool) -> T) -> T {
        super::with_pages_still(f)
    }

    /// This thread's own accesses to lazy memory that the exception
    /// handler committed (each an access violation the system dispatched
    /// on the thread's stack), and the most of the thread's stack that was
    /// committed when the handler was entered: a record for which code on
    /// a thread touches guest RAM before the guest does, and what its
    /// dispatch costs the thread's stack.
    pub fn host_faults_on_this_thread() -> (u64, usize) {
        super::HOST_FAULTS.get()
    }

    /// For a record only (kvm-ioctls' LAZYGRAIN): the lazy memory at
    /// `[addr, addr + len)` commits `grain` bytes at a first access (an
    /// aligned block wholly inside its lazy range, else a page), as
    /// `MADV_HUGEPAGE` sets [`HUGE_PAGE`]; `grain` 0 removes the setting
    /// from the range. `grain` is a power of two of at least a page.
    pub fn record_grain(addr: usize, len: usize, grain: usize) {
        assert!(grain == 0 || (grain.is_power_of_two() && grain >= PAGE), "grain {grain:#x}");
        super::set_grain(addr, len, grain);
    }

    /// Calls the [`deny_exec`] hook if `prot` asks for execution.
    pub(super) fn check_exec(prot: c_int) {
        if prot & PROT_EXEC == 0 {
            return;
        }
        let hook = EXEC_DENIED.load(std::sync::atomic::Ordering::Acquire);
        if hook != 0 {
            // SAFETY: only `extern "C" fn(c_int)` values are stored.
            let hook: extern "C" fn(c_int) = unsafe { std::mem::transmute(hook) };
            hook(prot);
        }
    }

    /// A section to map instead of the file a descriptor names: a memfd
    /// sealed against shrinking or growing attaches the section that fixes
    /// its size (see the `memfd` compatibility crate). While it exists,
    /// Windows refuses to truncate the file below its size; `ftruncate`,
    /// `write` and `pwrite` here refuse to grow it while `grow_sealed` is
    /// set, with `EPERM` as Linux does. Closed with the last descriptor.
    #[derive(Debug)]
    pub struct Section {
        /// The section handle (owned).
        pub handle: usize,
        /// Its size, the file's size when it was sealed.
        pub size: u64,
        /// `F_SEAL_GROW` is set.
        pub grow_sealed: std::sync::atomic::AtomicBool,
    }

    impl Section {
        /// Whether the file may not become larger than [`Self::size`].
        pub fn grow_sealed(&self) -> bool {
            self.grow_sealed.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    impl Drop for Section {
        fn drop(&mut self) {
            // SAFETY: closes the section this object owns.
            unsafe { CloseHandle(self.handle as HANDLE) };
        }
    }
}

/// An owned handle.
#[derive(Debug)]
struct Owned(HANDLE);

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Owned {}
// SAFETY: as above.
unsafe impl Sync for Owned {}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: closes the handle this object owns.
        unsafe { CloseHandle(self.0) };
    }
}

fn dup(h: HANDLE) -> Option<Owned> {
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            h,
            GetCurrentProcess(),
            &mut out,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    (ok != 0).then_some(Owned(out))
}

/// `SEC_RESERVE` (winnt.h): a pagefile-backed section whose pages are
/// reserved when it is made and committed with `VirtualAlloc` on a view.
const SEC_RESERVE: PAGE_PROTECTION_FLAGS = 0x0400_0000;

/// The commit charge that pays for the pages of an anonymous shared
/// mapping, as the cgroup is charged for a shmem page when it is touched
/// (Linux v6.1 mm/shmem.c:1738 and :1862, `charge_mm`; :691-710,
/// `mem_cgroup_charge`): a private reservation as long as the section, of
/// which the page at each offset is committed `PAGE_NOACCESS` (commit,
/// never memory) before that page of the section is ([`charge`]). A Job
/// Object charges no section, private commit it does: so the jail's
/// `memory.max` refuses the page's charge at once, and the VMM ends with
/// 137 as for private memory, where a section's own commit would go
/// unseen (SECTREC-a and SECTREC-b, `test_section_memory_and_a_charge_for_it_on_record`).
/// Released with the mapping's last view.
#[derive(Debug)]
struct Charge {
    base: usize,
}

impl Drop for Charge {
    fn drop(&mut self) {
        // SAFETY: releases the reservation this object made.
        unsafe { VirtualFree(self.base as *mut c_void, 0, MEM_RELEASE) };
    }
}

/// The views whose pages are charged ([`Charge`]): view start to `(len,
/// charge)`, the view's offset being its section's (a view of a whole
/// anonymous section). A leaf lock, held only around the charge's commits.
static CHARGES: ProbedMutex<BTreeMap<usize, (usize, Arc<Charge>)>> = ProbedMutex::new("CHARGES", BTreeMap::new());
/// Whether [`CHARGES`] has any: the commit's one look at it otherwise.
static CHARGES_SET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A charge reservation for `len` bytes of section, registered for the view
/// at `view`.
fn charge_add(view: usize, len: usize) -> Option<Arc<Charge>> {
    // SAFETY: reserves address space of our own.
    let base = unsafe { VirtualAlloc2(proc(), std::ptr::null(), len, MEM_RESERVE, PAGE_NOACCESS, std::ptr::null_mut(), 0) };
    if base.is_null() {
        return None;
    }
    let c = Arc::new(Charge { base: base as usize });
    let mut m = CHARGES.lock().unwrap();
    m.insert(view, (len, c.clone()));
    CHARGES_SET.store(true, std::sync::atomic::Ordering::Release);
    Some(c)
}

/// The view at `view` is gone: its charge is released with its last holder.
fn charge_remove(view: usize) {
    let mut m = CHARGES.lock().unwrap();
    m.remove(&view);
    CHARGES_SET.store(!m.is_empty(), std::sync::atomic::Ordering::Release);
}

/// Commits the charge of the pages of `[base, base + len)` that lie in
/// charged views ([`Charge`]); `false`, with the error for `GetLastError`,
/// if the commit is refused (the job's memory limit).
fn charge(base: usize, len: usize) -> bool {
    if !CHARGES_SET.load(std::sync::atomic::Ordering::Acquire) {
        return true;
    }
    let end = base.saturating_add(len);
    let m = CHARGES.lock().unwrap();
    let first = m.range(..=base).next_back().map_or(base, |(v, _)| *v);
    for (&v, (n, c)) in m.range(first..end) {
        let (s, e) = (base.max(v), end.min(v + n));
        if s >= e {
            continue;
        }
        // SAFETY: commits pages of our reservation, never accessed.
        let p = unsafe {
            VirtualAlloc2(proc(), (c.base + (s - v)) as *const c_void, e - s, MEM_COMMIT, PAGE_NOACCESS, std::ptr::null_mut(), 0)
        };
        if p.is_null() {
            return false;
        }
    }
    true
}

/// Gives back the charge of the pages of `[base, base + len)` that lie in
/// charged views ([`Charge`]): their charge pages are decommitted, which
/// returns a page of the job's count and of the private commit each
/// (UFFDCHUNK c, CI run 43528910212), as the memory cgroup uncharges a page
/// that is freed. Decommitting a page that is not committed is no error
/// (Learn, VirtualFree: "The function does not fail if you attempt to
/// decommit an uncommitted page").
fn uncharge(base: usize, len: usize) {
    if !CHARGES_SET.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    let end = base.saturating_add(len);
    let m = CHARGES.lock().unwrap();
    let first = m.range(..=base).next_back().map_or(base, |(v, _)| *v);
    for (&v, (n, c)) in m.range(first..end) {
        let (s, e) = (base.max(v), end.min(v + n));
        if s >= e {
            continue;
        }
        // SAFETY: decommits pages of our reservation, never accessed.
        unsafe { VirtualFree((c.base + (s - v)) as *mut c_void, e - s, MEM_DECOMMIT) };
    }
}

#[derive(Debug)]
enum Kind {
    Placeholder,
    /// Private memory; for a private file mapping, the file and offset it
    /// was filled from.
    Private {
        file: Option<(Arc<Owned>, i64)>,
    },
    /// A view of `section`, for shared file mappings with the file too.
    /// `charge`: for anonymous shared memory, the commit that pays for its
    /// pages ([`Charge`]).
    View {
        /// The section's handle, kept while the view stands; none for a
        /// chunked userfaultfd range's views ([`uffd_alias_chunked`]), which
        /// close it once mapped, so that a range holds no handle a chunk:
        /// "Mapped views of a file mapping object maintain internal
        /// references to the object, and a file mapping object does not
        /// close until all references to it are released" (Microsoft Learn,
        /// CreateFileMappingW). Whether a view is a userfaultfd range's is
        /// `uffd`, not this.
        _section: Option<Arc<Owned>>,
        /// Whether this is the view of a userfaultfd range's memory, put in
        /// place by [`uffd_alias`] or [`uffd_alias_chunked`] (and kept
        /// through [`uffd_swap_chunk`] and [`uffd_move_chunk`], which map
        /// another section into the same region); never set by `mmap`.
        /// [`uffd_pages_gone`] keeps in a registration only the pages of such
        /// a view.
        uffd: bool,
        file: Option<Arc<Owned>>,
        charge: Option<Arc<Charge>>,
        /// A released userfaultfd range's alias of the section, handed over
        /// by [`uffd_unalias`] while the view has discarded pages pending in
        /// its record ([`Record`]), which are zeroed through it at their
        /// first access; unmapped with the view.
        alias: Option<usize>,
    },
    /// Anonymous private memory on large pages of `page` bytes
    /// (`MAP_HUGETLB`): committed and locked when mapped, never a
    /// placeholder, and changed only in whole large pages, as Linux changes
    /// hugetlb mappings only in whole huge pages. `fresh`: never writable
    /// since mapped, so still the zeros Windows gave it. `wprot`: the
    /// protection it was allocated with, which is its protection for good:
    /// Windows changes no large page's protection (`VirtualProtect` to any
    /// other fails with `ERROR_INVALID_ADDRESS`, from and to every
    /// protection; measured on Windows 11 26H2).
    ///
    /// `brokered`: the pages are a pagefile-backed large-page section the
    /// jailer made ([`broker_section`]), mapped as a view (`section`), or,
    /// `PROT_NONE`, an address range reserved for one (`section` none: a
    /// large-page view takes no `PAGE_NOACCESS`).
    Large { page: usize, fresh: bool, wprot: u32, brokered: bool, section: Option<Arc<Owned>> },
}

/// Sorted, disjoint (offset, len) ranges.
type Ranges = Vec<(usize, usize)>;

fn ranges_overlap(v: &Ranges, off: usize, len: usize) -> bool {
    v.iter().any(|&(o, l)| o < off + len && off < o + l)
}

fn ranges_add(v: &mut Ranges, off: usize, len: usize) {
    v.push((off, len));
    v.sort_unstable();
    let mut merged: Ranges = Vec::new();
    for (o, l) in v.drain(..) {
        match merged.last_mut() {
            Some(last) if o <= last.0 + last.1 => last.1 = last.1.max(o + l - last.0),
            _ => merged.push((o, l)),
        }
    }
    *v = merged;
}

fn ranges_remove(v: &mut Ranges, off: usize, len: usize) {
    let mut out = Vec::new();
    for &(o, l) in v.iter() {
        let (e, ce) = (o + l, off + len);
        if ce <= o || e <= off {
            out.push((o, l));
            continue;
        }
        if o < off {
            out.push((o, off - o));
        }
        if ce < e {
            out.push((ce, e - ce));
        }
    }
    *v = out;
}

/// The parts of [off, off + len) that are in `v`. A part's length is worked
/// out only once it is known not to be empty: `then_some` would work it out
/// first, and a range wholly before `off` would overflow (a panic in a debug
/// build).
fn ranges_within(v: &Ranges, off: usize, len: usize) -> Ranges {
    v.iter()
        .filter_map(|&(o, l)| {
            let (s, e) = (o.max(off), (o + l).min(off + len));
            (s < e).then(|| (s, e - s))
        })
        .collect()
}

#[derive(Debug)]
struct Region {
    len: usize,
    kind: Kind,
    /// Unmapped parts (offset, len) of a private allocation or view.
    holes: Ranges,
    /// Parts of a private allocation mapped again `PROT_NONE` (anonymous,
    /// `MAP_FIXED`): decommitted, so they hold no memory and no commit
    /// charge (`MAP_NORESERVE`), and fault on access. Still mapped: an
    /// `mprotect` that allows access commits them again, zero-filled.
    noaccess: Ranges,
    /// Anonymous private `MAP_NORESERVE` memory whose pages are committed at
    /// their first access ([`LAZY`]).
    lazy: bool,
}

impl Region {
    fn new(len: usize, kind: Kind) -> Self {
        Region {
            len,
            kind,
            holes: Vec::new(),
            noaccess: Vec::new(),
            lazy: false,
        }
    }

    fn mapped_in(&self, off: usize, len: usize) -> bool {
        !ranges_overlap(&self.holes, off, len)
    }

    fn add_hole(&mut self, off: usize, len: usize) {
        ranges_add(&mut self.holes, off, len);
        ranges_remove(&mut self.noaccess, off, len);
    }

    fn remove_hole(&mut self, off: usize, len: usize) {
        ranges_remove(&mut self.holes, off, len);
    }

    fn all_holes(&self) -> bool {
        self.holes.first() == Some(&(0, self.len))
    }
}

type Table = BTreeMap<usize, Region>;

fn table() -> &'static ProbedMutex<Table> {
    static T: ProbedMutex<Table> = ProbedMutex::new("the region table", BTreeMap::new());
    &T
}

fn win_prot(prot: c_int) -> Option<PAGE_PROTECTION_FLAGS> {
    let rwx = (
        prot & PROT_READ != 0,
        prot & PROT_WRITE != 0,
        prot & PROT_EXEC != 0,
    );
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return None;
    }
    Some(match rwx {
        (false, false, false) => PAGE_NOACCESS,
        (_, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        (_, true, true) => PAGE_EXECUTE_READWRITE,
        (_, false, true) => PAGE_EXECUTE_READ,
    })
}

fn fail<T>(errno: c_int, value: T) -> T {
    set_errno(errno);
    value
}

fn proc() -> HANDLE {
    // SAFETY: plain call.
    unsafe { GetCurrentProcess() }
}

fn new_placeholder(addr: usize, len: usize) -> Option<usize> {
    // SAFETY: reserves address space.
    let p = unsafe {
        VirtualAlloc2(
            proc(),
            addr as *const c_void,
            len,
            MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
            PAGE_NOACCESS,
            std::ptr::null_mut(),
            0,
        )
    };
    (!p.is_null()).then_some(p as usize)
}

/// A new placeholder of `len` bytes on a 2 MiB boundary ([`HUGE_PAGE`]),
/// anywhere: where [`mmap`] puts an anonymous private mapping whose length
/// is a multiple of 2 MiB when no hint placed it. Linux has done so since
/// 6.7, for a length that is a multiple of the PMD size only ("Ensures that
/// larger anonymous mappings are THP aligned": v6.12 mm/mmap.c :902 to
/// :907, `IS_ALIGNED(len, PMD_SIZE)`); v6.1 and v5.10 place them anywhere.
/// An address is nothing a caller may rely on: this is a placement choice
/// with a kernel precedent, not a parity claim. It commits nothing, only
/// moves where the reservation lands; what it buys is that such a range's
/// 2 MiB chunks (a registered userfaultfd range's, `uffd_alias_chunked`)
/// each fill their 2 MiB regions, so none has a view alone in a region at
/// the range's edge. `None` if Windows has no such address free (or a
/// test refuses it, [`REFUSE_ALIGNED_PLACEMENT`]), and the caller places it
/// anywhere, as Linux retries without the alignment's padding (v6.12
/// mm/huge_memory.c :1092 to :1100, `__thp_get_unmapped_area`, then
/// `thp_get_unmapped_area_vmflags` :1125 to :1130).
fn new_placeholder_aligned(len: usize) -> Option<usize> {
    use windows_sys::Win32::System::Memory::{MEM_ADDRESS_REQUIREMENTS, MEM_EXTENDED_PARAMETER, MemExtendedParameterAddressRequirements};
    #[cfg(test)]
    if REFUSE_ALIGNED_PLACEMENT.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return None;
    }
    let mut need = MEM_ADDRESS_REQUIREMENTS { LowestStartingAddress: std::ptr::null_mut(), HighestEndingAddress: std::ptr::null_mut(), Alignment: HUGE_PAGE };
    let mut param: MEM_EXTENDED_PARAMETER = MEM_EXTENDED_PARAMETER::default();
    param.Anonymous1._bitfield = MemExtendedParameterAddressRequirements as u64;
    param.Anonymous2.Pointer = (&raw mut need).cast();
    // SAFETY: reserves address space, with the requirement above, which
    // outlives the call.
    let p = unsafe { VirtualAlloc2(proc(), std::ptr::null(), len, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, &raw mut param, 1) };
    (!p.is_null()).then_some(p as usize)
}

/// Tests: the next aligned placement ([`new_placeholder_aligned`]) is
/// refused, as if Windows had no 2 MiB-aligned address free.
#[cfg(test)]
pub(crate) static REFUSE_ALIGNED_PLACEMENT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Tests: [`uffd_alias`] makes the section of a process whose exception
/// handler could not be added (not reserved), though it was.
#[cfg(test)]
pub(crate) static UFFD_UNRESERVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The regions overlapping [start, end), by base.
fn overlapping(t: &Table, start: usize, end: usize) -> Vec<usize> {
    let mut v: Vec<usize> = t
        .range(..end)
        .rev()
        .take_while(|(b, r)| **b + r.len > start)
        .map(|(b, _)| *b)
        .collect();
    v.reverse();
    v
}

/// Whether [start, end) is all in the table, with no gaps.
fn covered(t: &Table, start: usize, end: usize) -> bool {
    let mut at = start;
    for b in overlapping(t, start, end) {
        if b > at {
            return false;
        }
        at = b + t[&b].len;
    }
    at >= end
}

/// Splits the placeholder at `base` so that a region starts at `at`.
fn split_placeholder(t: &mut Table, base: usize, at: usize) -> bool {
    let len = t[&base].len;
    if at <= base || at >= base + len {
        return true;
    }
    // SAFETY: splits our placeholder at `at`.
    if unsafe {
        VirtualFree(
            base as *mut c_void,
            at - base,
            MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
        )
    } == 0
    {
        return false;
    }
    t.get_mut(&base).unwrap().len = at - base;
    t.insert(
        at,
        Region::new(base + len - at, Kind::Placeholder),
    );
    true
}

/// Splits placeholders so that region boundaries fall on `start` and `end`.
fn carve(t: &mut Table, start: usize, end: usize) -> bool {
    for at in [start, end] {
        let split = t
            .range(..at)
            .next_back()
            .filter(|(b, r)| **b + r.len > at && matches!(r.kind, Kind::Placeholder))
            .map(|(b, _)| *b);
        if let Some(b) = split {
            if !split_placeholder(t, b, at) {
                return false;
            }
        }
    }
    true
}

/// Turns the whole region at `base` back into a placeholder.
fn to_placeholder(t: &mut Table, base: usize) -> bool {
    let r = t.get_mut(&base).unwrap();
    // A view's pages leave the released ranges' records before the view
    // goes, as in [`release`] and `munmap`: a first access resolving one of
    // them holds the records' lock from its check that the page is
    // committed to its protection, so the view stays while it does (the
    // view is counted out of its record by [`unalias`] once it is gone).
    if matches!(r.kind, Kind::View { .. }) && !is_chunk(&r.kind) {
        released_forget(base, r.len);
    }
    // A chunk's views ([`chunk_views`]) leave a placeholder each, made one
    // again; if that is refused, the table has the two. Their pages leave
    // the records with them ([`unmap_chunk_forgetting`]): a refused first
    // unmap changes nothing.
    let mut apart = None;
    // SAFETY: frees our allocation or view, keeping the address space.
    let ok = unsafe {
        match r.kind {
            Kind::Placeholder => return true,
            // Large pages cannot become a placeholder (MAP_FIXED over them).
            Kind::Large { .. } => return false,
            Kind::Private { .. } => VirtualFree(
                base as *mut c_void,
                r.len,
                MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
            ),
            Kind::View { .. } if is_chunk(&r.kind) => {
                if !unmap_chunk_forgetting(base, r.len, true) {
                    return false;
                }
                if !coalesce_chunk(base, r.len) {
                    apart = Some(chunk_half(r.len));
                }
                1
            }
            Kind::View { .. } => UnmapViewOfFile2(
                proc(),
                MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: base as *mut c_void,
                },
                MEM_PRESERVE_PLACEHOLDER,
            ),
        }
    };
    if ok == 0 {
        return false;
    }
    if r.lazy {
        lazy_remove(base, r.len);
        touched_remove(base);
        r.lazy = false;
    }
    if matches!(r.kind, Kind::View { charge: Some(_), .. }) {
        charge_remove(base);
    }
    if matches!(r.kind, Kind::View { .. }) {
        unalias(base, r.len, &r.kind);
    }
    r.kind = Kind::Placeholder;
    r.holes.clear();
    r.noaccess.clear();
    if let Some(h) = apart {
        let len = r.len;
        r.len = h;
        t.insert(base + h, Region::new(len - h, Kind::Placeholder));
    }
    true
}

/// Releases the region at `base` and its address space. A chunk's views
/// go first ([`unmap_chunk_forgetting`]): refused, nothing changed, the
/// region still in the table, and `false`.
fn release(t: &mut Table, base: usize) -> bool {
    let chunk = is_chunk(&t[&base].kind);
    if chunk && !unmap_chunk_forgetting(base, t[&base].len, false) {
        return false;
    }
    let r = t.remove(&base).unwrap();
    if r.lazy {
        lazy_remove(base, r.len);
        touched_remove(base);
    }
    if matches!(r.kind, Kind::View { charge: Some(_), .. }) {
        charge_remove(base);
    }
    if matches!(r.kind, Kind::View { .. }) {
        unalias(base, r.len, &r.kind);
    }
    // SAFETY: frees our allocation, view or placeholder.
    let ok = unsafe {
        match r.kind {
            Kind::Large { section: Some(_), .. } => UnmapViewOfFile2(
                proc(),
                MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: base as *mut c_void,
                },
                0,
            ),
            Kind::Placeholder | Kind::Private { .. } | Kind::Large { .. } => {
                VirtualFree(base as *mut c_void, 0, MEM_RELEASE)
            }
            Kind::View { .. } if chunk => 1,
            Kind::View { .. } => UnmapViewOfFile2(
                proc(),
                MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: base as *mut c_void,
                },
                0,
            ),
        }
    };
    ok != 0
}

/// Whether [start, end) is reserved address space with no page committed.
fn reserved_only(start: usize, end: usize) -> bool {
    let mut at = start;
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0
            || mbi.State != MEM_RESERVE
        {
            return false;
        }
        at = mbi.BaseAddress as usize + mbi.RegionSize;
    }
    true
}

/// The protection of the lazy private region at `base` if it can be split
/// at `start` and `end` (see [`split_lazy`]).
fn lazy_split_prot(t: &Table, base: usize, start: usize, end: usize) -> Option<PAGE_PROTECTION_FLAGS> {
    let r = &t[&base];
    if !r.lazy || !matches!(r.kind, Kind::Private { file: None }) || !r.holes.is_empty() || !r.noaccess.is_empty() {
        return None;
    }
    let (s, e) = (start.max(base), end.min(base + r.len));
    let lazies = lazy_within(base, r.len);
    let prot = lazies.first()?.2;
    let whole = lazies.iter().map(|l| l.1).sum::<usize>() == r.len;
    (whole && lazies.iter().all(|l| l.2 == prot) && reserved_only(base, s) && reserved_only(e, base + r.len))
        .then_some(prot)
}

/// Splits the lazy private region at `base` so that [start, end) is a
/// placeholder of its own. Windows splits a placeholder, not an allocation
/// (Linux splits any mapping): the allocation goes back to a placeholder
/// whole, and the parts outside the range are reserved again, lazy with the
/// region's protection. Only when no page outside the range was committed
/// ([`lazy_split_prot`]): nothing outside is lost. Firecracker maps a
/// virtio-pmem file so, over the start of anonymous memory rounded up to
/// 2 MiB.
fn split_lazy(t: &mut Table, base: usize, start: usize, end: usize, prot: PAGE_PROTECTION_FLAGS) -> bool {
    let rend = base + t[&base].len;
    let (s, e) = (start.max(base), end.min(rend));
    if !to_placeholder(t, base) || !carve(t, s, e) {
        return false;
    }
    for (a, b) in [(base, s), (e, rend)] {
        if b <= a {
            continue;
        }
        // SAFETY: reserves our placeholder again.
        let p = unsafe {
            VirtualAlloc2(
                proc(),
                a as *const c_void,
                b - a,
                MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
                prot,
                std::ptr::null_mut(),
                0,
            )
        };
        if p.is_null() {
            return false;
        }
        let r = t.get_mut(&a).unwrap();
        r.kind = Kind::Private { file: None };
        r.lazy = true;
        lazy_add(a, b - a, prot);
        touched_add(a, b - a);
    }
    true
}

/// Makes [start, end) one placeholder, from what the table has there, or
/// from free address space. `EINVAL` when it holds part of a private
/// allocation (but untouched lazy memory around it, [`split_lazy`]) or
/// view, or memory this module did not map.
fn make_placeholder(t: &mut Table, start: usize, end: usize) -> Result<(), c_int> {
    // Refused before anything changes: part of an allocation or view.
    let mut splits = Vec::new();
    for b in overlapping(t, start, end) {
        let r = &t[&b];
        if !matches!(r.kind, Kind::Placeholder) && (b < start || b + r.len > end) {
            splits.push((b, lazy_split_prot(t, b, start, end).ok_or(crate::EINVAL)?));
        }
    }
    for (b, prot) in splits {
        if !split_lazy(t, b, start, end, prot) {
            return Err(crate::EINVAL);
        }
    }
    // Free address space in the range becomes placeholders first.
    let mut at = start;
    for b in overlapping(t, start, end)
        .into_iter()
        .chain(std::iter::once(end))
    {
        let gap_end = b.min(end);
        if gap_end > at {
            let p = new_placeholder(at, gap_end - at).ok_or(crate::EINVAL)?;
            t.insert(
                p,
                Region::new(gap_end - at, Kind::Placeholder),
            );
        }
        if b < end {
            at = b + t[&b].len;
        }
    }
    if !carve(t, start, end) {
        return Err(crate::EINVAL);
    }
    let bases = overlapping(t, start, end);
    for &b in &bases {
        let r = &t[&b];
        if b < start || b + r.len > end {
            return Err(crate::EINVAL);
        }
        if !to_placeholder(t, b) {
            return Err(crate::EINVAL);
        }
    }
    // Counted again: a chunk whose two placeholders were not made one is
    // two regions now ([`to_placeholder`]), which [`fill`] cannot take as
    // one.
    let bases = overlapping(t, start, end);
    if bases.len() > 1 {
        // SAFETY: coalesces our adjacent placeholders covering the range.
        if unsafe {
            VirtualFree(
                start as *mut c_void,
                end - start,
                MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS,
            )
        } == 0
        {
            return Err(crate::EINVAL);
        }
        for b in &bases[1..] {
            t.remove(b);
        }
        t.get_mut(&start).unwrap().len = end - start;
    }
    Ok(())
}

/// Anonymous private `MAP_NORESERVE` memory that is reserved, not committed:
/// each range gets its pages committed, with its protection, at the first
/// access to them, as Linux gives an anonymous mapping its pages (and
/// charges a cgroup for them) when they are touched, not when they are
/// mapped. Windows charges a job's memory limit for what is committed, so
/// without this a guest is charged its whole memory at start-up: a jail's
/// `memory.max` below the guest's size ended the VMM before the guest booted
/// (measured: `jailer-test.ps1 memory`), where Linux kills it when the guest
/// has used that much.
///
/// An access is caught where it happens: a host thread's (a device's, a
/// snapshot's) by a vectored exception handler ([`on_exception`]), the
/// guest's by the hypervisor's run loop, which WHP leaves with a memory
/// access exit for a page that is not committed (measured: the exit, then
/// the commit, then the access re-run). Sorted, disjoint `(start, len,
/// protection)`. Locked briefly, never while memory is touched, so a fault
/// inside a call that holds the region table cannot deadlock on it. A leaf
/// of the lock order (the userfaultfd's `LOCK`, the region table,
/// [`RELEASED`], then [`CHARGES`] or this): every holder looks at or edits
/// the list and lets go, taking no other lock meanwhile ([`settled_access`]
/// takes it last of four).
///
/// An `mprotect` keeps memory lazy ([`protect_lazy`]): the protection of a
/// range is the one its pages get when committed, and a `PAGE_NOACCESS`
/// range (`PROT_NONE`) is committed by no access, which faults, as on Linux.
static LAZY: ProbedMutex<Vec<(usize, usize, PAGE_PROTECTION_FLAGS)>> = ProbedMutex::new("LAZY", Vec::new());

/// What a first access commits: a page, as Linux charges an anonymous
/// mapping a page at a time where it uses no transparent huge page
/// (mm/memory.c `do_anonymous_page`; a mapping not advised `MADV_HUGEPAGE`
/// on a host whose THP mode is `madvise`, Ubuntu's kernel configuration);
/// in a range advised `MADV_HUGEPAGE` ([`GRAINS`]), at a write, the aligned
/// [`HUGE_PAGE`] around the access if the lazy range holds all of it, as
/// Linux maps a huge page only where the mapping holds the aligned 2 MiB
/// (`thp_vma_suitable_order`), and charges it whole
/// (`__do_huge_pmd_anonymous_page`); else a page, as Linux falls back to
/// one.
const HUGE_PAGE: usize = 2 << 20;

/// The grains other than a page: `MADV_HUGEPAGE`'s [`HUGE_PAGE`] (as
/// Linux's `VM_HUGEPAGE`, kept by `mprotect` and dropped by `munmap`, a
/// `MAP_FIXED` mapping over the range and `MADV_NOHUGEPAGE`) and a
/// record's ([`wick_mm::record_grain`]). Sorted, disjoint
/// `(start, len, grain)`.
static GRAINS: ProbedMutex<Vec<(usize, usize, usize)>> = ProbedMutex::new("GRAINS", Vec::new());
/// Whether [`GRAINS`] has any: the commit's one look at it otherwise.
static GRAINS_SET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Sets the grain of `[start, start + len)`; 0 removes it.
fn set_grain(start: usize, len: usize, grain: usize) {
    let end = start.saturating_add(len);
    let mut g = GRAINS.lock().unwrap();
    if g.is_empty() && grain == 0 {
        return;
    }
    let mut out = Vec::with_capacity(g.len() + 2);
    for &(s, n, k) in g.iter() {
        let e = s + n;
        if e <= start || s >= end {
            out.push((s, n, k));
            continue;
        }
        if s < start {
            out.push((s, start - s, k));
        }
        if e > end {
            out.push((end, e - end, k));
        }
    }
    if grain != 0 && end > start {
        out.push((start, end - start, grain));
    }
    out.sort_unstable();
    GRAINS_SET.store(!out.is_empty(), std::sync::atomic::Ordering::Release);
    *g = out;
}

/// The grain at `addr`: a page, or the one [`GRAINS`] sets there.
fn lazy_grain(addr: usize) -> usize {
    if !GRAINS_SET.load(std::sync::atomic::Ordering::Acquire) {
        return PAGE;
    }
    let g = GRAINS.lock().unwrap();
    let i = g.partition_point(|&(s, _, _)| s <= addr);
    i.checked_sub(1).map(|i| g[i]).filter(|&(s, n, _)| addr < s + n).map_or(PAGE, |(_, _, grain)| grain)
}

/// The exit code of a VMM that reached its memory limit: what a shell shows
/// for a process the Linux OOM killer ended (`128 + SIGKILL`).
pub(crate) const OOM_EXIT: u32 = 137;

fn lazy_add(start: usize, len: usize, prot: PAGE_PROTECTION_FLAGS) {
    lazy_remove(start, len);
    let mut l = LAZY.lock().unwrap();
    let at = l.partition_point(|&(s, _, _)| s < start);
    l.insert(at, (start, len, prot));
}

fn lazy_remove(start: usize, len: usize) {
    let end = start + len;
    let mut l = LAZY.lock().unwrap();
    let mut out = Vec::with_capacity(l.len() + 1);
    for &(s, n, p) in l.iter() {
        let e = s + n;
        if e <= start || s >= end {
            out.push((s, n, p));
            continue;
        }
        if s < start {
            out.push((s, start - s, p));
        }
        if e > end {
            out.push((end, e - end, p));
        }
    }
    *l = out;
}

/// The lazy ranges inside `[start, start + len)`.
fn lazy_within(start: usize, len: usize) -> Vec<(usize, usize, PAGE_PROTECTION_FLAGS)> {
    let end = start + len;
    LAZY.lock()
        .unwrap()
        .iter()
        .filter_map(|&(s, n, p)| {
            let (a, b) = (s.max(start), (s + n).min(end));
            (a < b).then(|| (a, b - a, p))
        })
        .collect()
}

/// The pages of each lazy allocation that may be committed: a bit a page,
/// set when [`commit`] commits one and cleared before one is decommitted.
/// A hint for [`zero_runs`] only, which reads a page whose bit is set as it
/// is (a page wrongly set is committed by the read, as it was before) and
/// asks `VirtualQuery` and [`LAZY`] about a page whose bit is clear before it
/// takes the page as zeros (a page wrongly clear costs a query): a wrong bit
/// costs time, never data. Keyed by the allocation's base; `(len, bits)`.
static TOUCHED: ProbedRwLock<BTreeMap<usize, Arc<Touched>>> = ProbedRwLock::new("TOUCHED", BTreeMap::new());

#[derive(Debug)]
struct Touched {
    len: usize,
    bits: std::boxed::Box<[std::sync::atomic::AtomicU64]>,
}

impl Touched {
    fn new(len: usize) -> Self {
        let words = len.div_ceil(PAGE).div_ceil(64);
        Touched { len, bits: (0..words).map(|_| std::sync::atomic::AtomicU64::new(0)).collect() }
    }

    fn get(&self, page: usize) -> bool {
        self.bits[page / 64].load(std::sync::atomic::Ordering::Acquire) & (1 << (page % 64)) != 0
    }

    /// Sets (or clears) the bits of pages `[from, to)`.
    fn mark(&self, from: usize, to: usize, set: bool) {
        let mut i = from;
        while i < to {
            let n = (64 - i % 64).min(to - i);
            let mask = if n == 64 { u64::MAX } else { ((1u64 << n) - 1) << (i % 64) };
            if set {
                self.bits[i / 64].fetch_or(mask, std::sync::atomic::Ordering::AcqRel);
            } else {
                self.bits[i / 64].fetch_and(!mask, std::sync::atomic::Ordering::AcqRel);
            }
            i += n;
        }
    }
}

/// A new lazy allocation at `base`: no page committed.
fn touched_add(base: usize, len: usize) {
    TOUCHED.write().unwrap().insert(base, Arc::new(Touched::new(len)));
}

/// The lazy allocation at `base` is gone, or no longer lazy.
fn touched_remove(base: usize) {
    TOUCHED.write().unwrap().remove(&base);
}

/// Sets (or clears) the bits of the pages `[start, start + len)` overlaps,
/// in whichever lazy allocations it lies.
fn touched_mark(start: usize, len: usize, set: bool) {
    let end = start.saturating_add(len);
    let map = TOUCHED.read().unwrap();
    if map.is_empty() {
        return;
    }
    let first = map.range(..=start).next_back().map_or(start, |(b, _)| *b);
    for (&b, t) in map.range(first..end) {
        let (s, e) = (start.max(b), end.min(b + t.len));
        if s < e {
            t.mark((s - b) / PAGE, (e - b).div_ceil(PAGE), set);
        }
    }
}

/// Splits `[addr, addr + len)` into runs and calls `f(start, len, zeros)` for
/// each in order: `zeros` for a run of lazy memory that is accessible and not
/// committed, which reads as zeros, and which a host read can take as zeros
/// without touching it (a touch would commit and charge it, where Linux maps
/// its zero page for a read and charges nothing: mm/memory.c
/// `do_anonymous_page`); not `zeros` for everything else, which the caller
/// reads as it is (committed memory; memory that is not lazy; `PROT_NONE`
/// lazy memory and holes, which fault as on Linux). A page that another
/// thread commits during the call may be called zeros: what a read that came
/// before that thread's write gives.
pub(crate) fn zero_runs(addr: usize, len: usize, mut f: impl FnMut(usize, usize, bool)) {
    let end = addr.saturating_add(len);
    if len == 0 {
        return;
    }
    let mut cur: Option<(usize, usize, bool)> = None;
    let mut push = |s: usize, e: usize, zeros: bool| {
        if s >= e {
            return;
        }
        match &mut cur {
            Some((_, ce, cz)) if *ce == s && *cz == zeros => *ce = e,
            _ => {
                if let Some((cs, ce, cz)) = cur.take() {
                    f(cs, ce - cs, cz);
                }
                cur = Some((s, e, zeros));
            }
        }
    };
    {
        let map = TOUCHED.read().unwrap();
        let mut at = addr;
        while at < end {
            let found = map.range(..=at).next_back().filter(|(b, t)| at < **b + t.len);
            let Some((&b, t)) = found else {
                // Not lazy memory, up to the next lazy allocation.
                let next = map.range(at + 1..).next().map_or(end, |(b, _)| (*b).min(end));
                push(at, next, false);
                at = next;
                continue;
            };
            let stop = end.min(b + t.len);
            while at < stop {
                let next = (at - at % PAGE + PAGE).min(stop);
                if t.get((at - b) / PAGE) {
                    push(at, next, false);
                    at = next;
                    continue;
                }
                // Pages whose bits are clear, asked about.
                let mut q = next;
                while q < stop && !t.get((q - b) / PAGE) {
                    q = (q + PAGE).min(stop);
                }
                confirm(at, q, b, t, &mut push);
                at = q;
            }
        }
    }
    if let Some((cs, ce, cz)) = cur {
        f(cs, ce - cs, cz);
    }
}

/// [`zero_runs`] for `[s, e)`, whose bits in the lazy allocation at `b` are
/// clear: what is committed is read (and its bits set again), what is not is
/// zeros where [`LAZY`] has it with a protection that reads.
fn confirm(s: usize, e: usize, b: usize, t: &Touched, push: &mut impl FnMut(usize, usize, bool)) {
    let mut at = s;
    while at < e {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            push(at, e, false);
            return;
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
        if mbi.State == MEM_COMMIT {
            t.mark((at - b) / PAGE, (at + run - b).div_ceil(PAGE), true);
            push(at, at + run, false);
        } else {
            let mut p = at;
            for (ls, ln, prot) in lazy_within(at, run) {
                push(p, ls, false);
                push(ls, ls + ln, prot != PAGE_NOACCESS);
                p = ls + ln;
            }
            push(p, at + run, false);
        }
        at += run;
    }
}

/// What an access to `addr` found ([`wick_mm::commit_on_access`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Not lazy memory, or lazy memory already committed: the access is not
    /// this module's to resolve.
    NotLazy,
    /// The pages were committed now; the access can be run again.
    Committed,
    /// Nothing was committed: the page was there already and allows the
    /// access (a released range's page another access resolved, or, asked
    /// with [`wick_mm::commit_block_on_access_again`], a lazy page committed
    /// before), as Linux's fault finds the page present. The access can be
    /// run again; a caller that sees it again and again counts it
    /// (`exit::RamRetries` in kvm-ioctls' WHP run loop).
    Present,
    /// They could not be committed (the Windows error): the memory limit is
    /// reached.
    Exhausted(u32),
}

fn commit_on_access(addr: usize, write: bool) -> (Access, core::ops::Range<usize>) {
    commit_access(addr, write, false)
}

/// [`commit_on_access`]; `again`: what a lazy access would commit (its page,
/// or a write's block) is looked at first, and if all of it is committed
/// already the answer is [`Access::Present`] (a `VirtualQuery` a region).
fn commit_access(addr: usize, write: bool, again: bool) -> (Access, core::ops::Range<usize>) {
    // A released userfaultfd range's pending page ([`Record`]).
    if let Some((access, range)) = released_access(addr, write) {
        return (access, if access == Access::Committed { range } else { 0..0 });
    }
    let found = {
        let l = LAZY.lock().unwrap();
        let i = l.partition_point(|&(s, _, _)| s <= addr);
        i.checked_sub(1).map(|i| l[i]).filter(|&(s, n, _)| addr < s + n)
    };
    let Some((s, n, prot)) = found else {
        return (Access::NotLazy, 0..0);
    };
    // `PROT_NONE`: the access is a fault, as Linux's to a `PROT_NONE`
    // mapping; nothing is committed. A write to memory mapped without
    // write access is a protection fault too, committed or not, as Linux
    // gives `SIGSEGV` for it before any page is allocated.
    let writable = matches!(prot, PAGE_READWRITE | PAGE_EXECUTE_READWRITE);
    if prot == PAGE_NOACCESS || (write && !writable) {
        return (Access::NotLazy, 0..0);
    }
    // The block is committed whatever part of it is already: committing a
    // committed page leaves it as it is ("an attempt to commit a page that
    // is already committed does not cause the function to fail", Microsoft
    // Learn, VirtualAlloc), so no `VirtualQuery` comes first. Every page
    // of a lazy range has the range's protection (`protect_lazy`). An
    // access to a block another thread or vCPU committed first runs again
    // (two vCPUs touching one block: measured, the second's exit had been
    // emulated as MMIO and the guest took a bogus fault).
    let page = addr - addr % PAGE;
    // A read takes a page even where huge pages are advised: Linux maps its
    // huge zero page for a read fault there and allocates (and charges)
    // nothing until a write (mm/huge_memory.c `do_huge_pmd_anonymous_page`,
    // `use_zero_page`, on by default).
    let grain = if write { lazy_grain(addr) } else { PAGE };
    let block = addr - addr % grain;
    let whole = block >= s && block + grain <= s + n;
    let (from, to) = if whole { (block, block + grain) } else { (page, page + PAGE) };
    // Asked again: present only if all the access would commit is: a write
    // in a range advised `MADV_HUGEPAGE` after a read committed its page
    // alone commits the block still, as Linux's write after the huge zero
    // page allocates the huge page.
    if again && committed_run(from, to - from) {
        return (Access::Present, 0..0);
    }
    if commit(from, to - from, prot, false) {
        return (Access::Committed, from..to);
    }
    // SAFETY: plain call.
    let err = unsafe { GetLastError() };
    // A huge page that cannot be charged falls back to a page, as Linux's
    // does (mm/huge_memory.c, `THP_FAULT_FALLBACK_CHARGE`).
    if to - from > PAGE && commit(page, PAGE, prot, false) {
        (Access::Committed, page..page + PAGE)
    } else if crate::wick_uffd::reclaim_at_touch(PAGE).freed > 0 && commit(page, PAGE, prot, false) {
        // Refused at the limit: committed once dead pages were reclaimed, as
        // Linux's memory cgroup reclaims before its out-of-memory kill.
        (Access::Committed, page..page + PAGE)
    } else {
        (Access::Exhausted(err), 0..0)
    }
}

/// What a look at a guest access's page, made whole, finds
/// ([`settled_access`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// A page the commit or the userfaultfd resolves: a registered page
    /// missing or being moved, a released range's pending page, lazy memory;
    /// each with a protection that allows the access. Ask them again.
    Resolvable,
    /// The page allows the access now: committed, not a guard page, with a
    /// protection that allows it. Run it again.
    Allowed,
    /// None of these: the host refuses the access, as Linux's page fault
    /// for KVM finds no page it may map (v6.1 virt/kvm/kvm_main.c
    /// `hva_to_pfn`, `KVM_PFN_ERR_FAULT`).
    Refused,
}

/// A guest access to `addr` that the commit and the userfaultfd left,
/// decided on one view of the page: under the userfaultfd's lock
/// (`wick_uffd::with_registrations_still`), then the region table's, then
/// [`RELEASED`]'s and [`LAZY`]'s, the order every other path takes them in,
/// so that no fill, discard, move, release, `mprotect`, unmapping or mapping
/// of it runs between the looks. A page any of them would make resolvable
/// is [`Settled::Resolvable`], whatever it is now; one whose protection
/// allows the access [`Settled::Allowed`]; else [`Settled::Refused`]. An
/// execution is taken as a read, as KVM maps a host page for a guest
/// execution where it may read it. Called by a vCPU thread between run
/// calls, holding none of wick's locks; the waits are a fill's or a move's
/// (a move holds the userfaultfd's lock, about 4 ms on record: RECLAIMREC).
pub(crate) fn settled_access(addr: usize, write: bool) -> Settled {
    crate::wick_uffd::with_registrations_still(addr as u64, write, |resolvable| {
        if resolvable {
            return Settled::Resolvable;
        }
        let _t = table().lock().unwrap();
        let page = addr - addr % PAGE;
        if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) != 0
            && RELEASED.lock().unwrap().iter().any(|r| {
                r.holds(page) && r.get(PENDING, page) && {
                    let prot = r.prot(page);
                    prot != PAGE_NOACCESS && (!write || matches!(prot, PAGE_READWRITE | PAGE_EXECUTE_READWRITE))
                }
            })
        {
            return Settled::Resolvable;
        }
        let lazy = {
            let l = LAZY.lock().unwrap();
            let i = l.partition_point(|&(s, _, _)| s <= addr);
            i.checked_sub(1).map(|i| l[i]).filter(|&(s, n, _)| addr < s + n)
        };
        if lazy.is_some_and(|(_, _, prot)| prot != PAGE_NOACCESS && (!write || matches!(prot, PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            return Settled::Resolvable;
        }
        if accessible(addr, 1, write) { Settled::Allowed } else { Settled::Refused }
    })
}

/// A look at several pages, and what is done on it, with none of them
/// changing meanwhile: `f` runs under the userfaultfd's lock
/// (`wick_uffd::with_lock_held`), then the region table's, then
/// [`RELEASED`]'s and [`LAZY`]'s, the order every other path takes them in
/// (as [`settled_access`] takes them), and is given `allowed(addr, write)`:
/// whether the page of `addr` allows the access now (not in a chunk being
/// moved, not a missing registered page, committed, not a guard page, with
/// a protection that allows it). While `f` runs no fill, discard, move,
/// register, release, `mprotect`, unmapping or mapping changes a page, so
/// one `allowed` said yes to may be read by `f` and stays as it is until
/// `f` returns. `f` takes none of these locks and touches no page `allowed`
/// did not allow (an exception there would need them); it may make a call
/// that reads the memory without an exception of this process's (WHP's
/// walk of the guest's page tables, kvm-ioctls `whp/settle.rs`, for which
/// this is). Called holding none of wick's locks.
pub(crate) fn with_pages_still<T>(f: impl FnOnce(&dyn Fn(usize, bool) -> bool) -> T) -> T {
    crate::wick_uffd::with_lock_held(|| {
        let _t = table().lock().unwrap();
        let _r = RELEASED.lock().unwrap();
        let _l = LAZY.lock().unwrap();
        f(&|addr, write| {
            !crate::wick_uffd::is_moving(addr as u64) && !crate::wick_uffd::is_missing(addr as u64) && accessible(addr, 1, write)
        })
    })
}

/// Commits the lazy pages of `[addr, addr + len)` that are not committed: a
/// system call's buffer, which the kernel copies to or from without an
/// exception this process could resolve (`ReadFile` into a page that is only
/// reserved fails: measured, a guest kernel read into lazy memory). Linux
/// faults the pages in as the call copies.
pub(crate) fn prefault_lazy(addr: usize, len: usize) {
    if len == 0 {
        return;
    }
    released_prefault(addr, len);
    if LAZY.lock().unwrap().is_empty() {
        return;
    }
    let start = addr - addr % PAGE;
    for (s, n, prot) in lazy_within(start, (addr + len).div_ceil(PAGE) * PAGE - start) {
        // `PROT_NONE`: the call faults on it, as Linux's copy does
        // (`EFAULT`); nothing to commit.
        if prot == PAGE_NOACCESS {
            continue;
        }
        let end = s + n;
        let mut at = s;
        while at < end {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
                break;
            }
            let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(end) - at;
            // Refused at the limit: dead pages reclaimed first, then again
            // (`wick_uffd::reclaim_at_touch`; a thread in a call counted in
            // flight, `copying`, waits there for no other call).
            if mbi.State != MEM_COMMIT
                && !commit(at, run, prot, false)
                && !(crate::wick_uffd::reclaim_at_touch(run).freed > 0 && commit(at, run, prot, false))
            {
                // SAFETY: plain call.
                out_of_memory(at, unsafe { GetLastError() });
            }
            at += run;
        }
    }
}

/// Commit charge set aside when the first lazy memory is mapped and given
/// back when the limit is reached: then even a thread's stack cannot grow
/// (measured: the process ended with `STATUS_STACK_OVERFLOW` writing the
/// message below), and the message and the exit need some.
static RESCUE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const RESCUE_LEN: usize = 256 << 10;

/// A line on standard error written at the memory limit, where nothing may
/// allocate and a thread's stack may not grow (a stack that must grow there
/// ends the process with `STATUS_STACK_OVERFLOW`:
/// `test_a_stack_that_grows_at_the_limit_on_record`): formatted into a
/// fixed buffer on the stack (512 bytes, the rest cut) and written with one
/// `WriteFile`, no lock and no allocation, where `eprintln!` takes the
/// standard error's lock and formats through it.
pub(crate) fn say_at_the_limit(line: core::fmt::Arguments) {
    struct Buffer {
        bytes: [u8; 512],
        len: usize,
    }
    impl core::fmt::Write for Buffer {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.bytes.len() - 1 - self.len);
            self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
    let mut b = Buffer { bytes: [0; 512], len: 0 };
    let _ = core::fmt::write(&mut b, line);
    b.bytes[b.len] = b'\n';
    let mut written = 0;
    // SAFETY: the process's standard error handle (an invalid one fails the
    // call) and our buffer.
    unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            windows_sys::Win32::System::Console::GetStdHandle(windows_sys::Win32::System::Console::STD_ERROR_HANDLE),
            b.bytes.as_ptr(),
            u32::try_from(b.len + 1).unwrap_or(0),
            &mut written,
            std::ptr::null_mut(),
        )
    };
}

fn out_of_memory(addr: usize, err: u32) -> ! {
    end_at_the_limit(format_args!(
        "wick: guest memory: committing the pages at {addr:#x} failed with error {err}: the memory limit \
         (the jail's memory.max, or the host's commit limit) is reached; the VMM ends, as the cgroup OOM \
         killer ends it on Linux (exit {OOM_EXIT})"
    ))
}

/// Ends the VMM for a userfaultfd fill of `len` bytes at `dst` whose pages
/// the memory limit still refuses after the reclaim (`wick_uffd::fill`), as
/// Linux's memory cgroup kills the VMM at the copy it cannot charge: it
/// reclaims, then calls its out-of-memory killer, which kills a task of the
/// cgroup, and charges again; it returns `-ENOMEM` only when no task can be
/// killed (v6.1 mm/memcontrol.c, `try_charge_memcg` :2714 to :2743, the
/// killer's call at :2729), and a jailed VMM's cgroup holds the VMM. The
/// line names the fill, so that it is told from a lazy touch's
/// ([`out_of_memory`]), the bytes it had filled, and the chunks its reclaims
/// passed over for system calls in their copy, waited for and moved, and
/// how long it waited: the rest was refused with nothing reclaimable left.
pub(crate) fn fill_out_of_memory(dst: u64, len: u64, filled: u64, err: u32, waited: usize, us: u64) -> ! {
    end_at_the_limit(format_args!(
        "wick: userfaultfd: the fill of {len} bytes at {dst:#x} failed with error {err} after the reclaim, {filled} \
         bytes of it filled, {waited} chunks passed over for system calls copying them waited for ({us} us) and \
         reclaimed again, nothing reclaimable left: the memory limit (the jail's memory.max, or the host's commit \
         limit) is reached; the VMM ends, as the cgroup OOM killer ends it on Linux at the copy it cannot charge \
         (exit {OOM_EXIT})"
    ))
}

/// Says `line` on standard error, allocating nothing, and ends the process
/// with [`OOM_EXIT`], as the cgroup OOM killer's SIGKILL ends the VMM.
pub(crate) fn end_at_the_limit(line: core::fmt::Arguments<'_>) -> ! {
    let rescue = RESCUE.swap(0, std::sync::atomic::Ordering::SeqCst);
    if rescue != 0 {
        // SAFETY: frees the block set aside for this.
        unsafe { VirtualFree(rescue as *mut c_void, 0, MEM_RELEASE) };
    }
    say_at_the_limit(line);
    // SAFETY: ends this process at once, as SIGKILL does.
    unsafe { windows_sys::Win32::System::Threading::TerminateProcess(GetCurrentProcess(), OOM_EXIT) };
    // TerminateProcess of this process does not return; were it to, no
    // unwinding in an exception's dispatch (`__fastfail`, no allocation).
    std::process::abort();
}

std::thread_local! {
    /// How deep this thread is in [`on_exception`] (a fault in the handler
    /// nests): no destructor, a plain read of the thread's TLS.
    static IN_THE_HANDLER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// This thread in [`on_exception`] while it lives: two writes of the
/// thread's TLS an exception.
struct InTheHandler;

impl InTheHandler {
    fn new() -> Self {
        IN_THE_HANDLER.set(IN_THE_HANDLER.get() + 1);
        InTheHandler
    }
}

impl Drop for InTheHandler {
    fn drop(&mut self) {
        IN_THE_HANDLER.set(IN_THE_HANDLER.get() - 1);
    }
}

/// Whether this thread runs the process's exception handler now
/// ([`on_exception`]), which allocates nothing by design: the heap's
/// allocator ends the process at a refusal there with no reclaim
/// (`wick_alloc`).
pub(crate) fn in_the_handler() -> bool {
    IN_THE_HANDLER.get() > 0
}

/// Tests: runs `f` as if in the exception handler.
#[cfg(test)]
pub(crate) fn as_if_in_the_handler<T>(f: impl FnOnce() -> T) -> T {
    let _in = InTheHandler::new();
    f()
}

std::thread_local! {
    /// [`wick_mm::host_faults_on_this_thread`]: no destructor, so that the
    /// exception handler's access is a plain read of the thread's TLS.
    static HOST_FAULTS: std::cell::Cell<(u64, usize)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
std::thread_local! {
    /// Whether this thread is in [`on_exception`]'s commit of a lazy
    /// page: STACKASK says so of a stack overflow raised there.
    static IN_THE_LAZY_HANDLER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// How much of the calling thread's stack is committed, in bytes: the
/// TEB's `StackBase` less its `StackLimit` (`NT_TIB`, at `gs:[8]` and
/// `gs:[0x10]` on x86-64); 0 elsewhere.
fn stack_committed() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let (base, limit): (usize, usize);
        // SAFETY: two reads of the thread's own TEB.
        unsafe {
            core::arch::asm!(
                "mov {0}, gs:[0x8]",
                "mov {1}, gs:[0x10]",
                out(reg) base,
                out(reg) limit,
                options(nostack, readonly, preserves_flags)
            );
        }
        base - limit
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// The process's one vectored exception handler, first in the chain
/// ([`exception_handler`] adds it once, at the first lazy mapping, create
/// or register, whichever comes first): a host thread's access to memory
/// of ours that is to be resolved, and a stack overflow. Where there were
/// two handlers (this one and the userfaultfd's), their order was the order
/// they were added in, and a page that changed between the two looks went
/// to neither: with the lazy-memory handler first, a missing registered
/// page unregistered and resolved by another thread between its look and
/// the userfaultfd's ended the process with the access violation
/// (`test_a_host_access_that_faulted_before_an_unregister_runs_again`).
/// One handler, one order, each step leaving what it does not resolve to
/// the next and every change between two looks to the last:
/// 1. `STATUS_STACK_OVERFLOW`: [`stack_page_after_the_reclaim`]'s retry;
///    a page not had goes on to [`stack_filter`].
/// 2. An access violation (`ExceptionInformation[0]`: 0 read, 1 write, 8
///    execute; `[1]`: the address), the userfaultfd's step
///    ([`wick_uffd::resolve_access`](crate::wick_uffd::resolve_access)): a
///    chunk being moved waits for the move, a missing registered page
///    queues its fault and waits for its fill; run again. It leaves a page
///    not registered, not missing or moving at its look, or whose
///    protection denies the access.
/// 3. The released and lazy resolve ([`commit_on_access`]): a released
///    userfaultfd range's pending page is resolved (committed, or zeroed
///    and opened) and a lazy page committed; run again, or the VMM ends at
///    the limit. A released page found no longer pending (another thread
///    resolved it while this one waited for the records' lock) is answered
///    there with step 4's check, made under that lock, which the vCPU's
///    path (`commit_block_on_access`) needs as well. It leaves a page in no
///    record and not lazy (a registered page among them), and a lazy or
///    released page whose protection denies the access.
/// 4. One last check, for memory that is ours ([`ours`]: in a
///    registration, held by a released record, or lazy) and accessible to
///    this access now ([`runs_again`]): run again. That is a registered
///    page filled or moved after the fault and before step 2 looked
///    (`test_a_host_access_that_faulted_before_its_fill_runs_again`,
///    `test_a_host_access_that_faulted_during_a_move_runs_again`), and any
///    page of ours that changed after the step that would have resolved it
///    looked, as Linux's fault, finding the page present, returns and the
///    access runs again (v6.1 mm/userfaultfd.c, `userfaultfd_must_wait`).
///    Every other violation, on our memory or any other address, goes on
///    at once to the next handler, as before.
///
/// The last check cannot spin, so it needs no bound (macOS bounds its own
/// re-runs because its handler cannot read the page's state as the
/// processor does): it re-runs the access only when `VirtualQuery` says
/// the page is committed, not a guard page, and of a protection that
/// allows this access's kind (a write: a writable protection; a read: any
/// readable one, so a read of a `PAGE_EXECUTE` page goes on; an execution
/// (`ExceptionInformation[0]` 8, a DEP fault): an executable protection),
/// which is all a user-mode access to such memory is checked for: ours is
/// anonymous or pagefile-section memory mapped by this library with those
/// protections only, never a shadow stack, an enclave or a write-copy view
/// (`accessible`), and an address the processor refuses outright (not
/// canonical, the kernel's) is in no range of ours. The access faults
/// again only if that state changed after the check (a move, a discard, an
/// unmap), a new state for the next exception's steps. An access
/// violation raised by `RaiseException` on our memory continues after the
/// call and re-runs nothing.
unsafe extern "system" fn on_exception(
    info: *mut windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    const ACCESS_VIOLATION: i32 = 0xC000_0005_u32 as i32;
    #[cfg(test)]
    // SAFETY: the system passes valid exception pointers.
    if let Some(rec) = deeper_for(unsafe { (*info).ExceptionRecord } as usize) {
        // SAFETY: the system's exception pointers, passed on.
        return as_if_the_dispatch_were_deeper(rec, &mut || unsafe { on_exception(info) });
    }
    let _in_the_handler = InTheHandler::new();
    // SAFETY: the system passes valid exception pointers.
    let rec = unsafe { &*(*info).ExceptionRecord };
    #[cfg(all(test, target_arch = "x86_64"))]
    if rec.ExceptionCode == STACK_OVERFLOW {
        // SAFETY: as above; the faulting thread's context.
        let addr = if rec.NumberParameters >= 2 { rec.ExceptionInformation[1] } else { 0 };
        stack_ask_record(unsafe { (*(*info).ContextRecord).Rsp } as usize, addr);
        stack_use_paint();
    }
    #[cfg(target_arch = "x86_64")]
    if rec.ExceptionCode == STACK_OVERFLOW && stack_page_after_the_reclaim() {
        return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION;
    }
    if rec.ExceptionCode == ACCESS_VIOLATION && rec.NumberParameters >= 2 {
        #[cfg(test)]
        crate::wick_uffd::exception_hook();
        let (kind, addr) = (rec.ExceptionInformation[0], rec.ExceptionInformation[1]);
        let write = kind == 1;
        if crate::wick_uffd::resolve_access(addr as u64, write) {
            return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION;
        }
        #[cfg(test)]
        exception_hook_after_the_userfaultfd();
        let stack = stack_committed();
        #[cfg(test)]
        IN_THE_LAZY_HANDLER.set(true);
        let access = commit_on_access(addr, write).0;
        #[cfg(test)]
        IN_THE_LAZY_HANDLER.set(false);
        match access {
            // Present: a released page another thread resolved meanwhile.
            Access::Committed | Access::Present => {
                let (n, deepest) = HOST_FAULTS.get();
                HOST_FAULTS.set((n + 1, deepest.max(stack)));
                return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION;
            }
            Access::Exhausted(err) => out_of_memory(addr, err),
            Access::NotLazy => {}
        }
        if ours(addr) && runs_again(addr, kind) {
            return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH
}

/// Tests: called in [`on_exception`] between the userfaultfd's step and the
/// released and lazy resolve, for a change between those two looks
/// (`test_a_host_access_that_faulted_before_an_unregister_runs_again`). An
/// `fn()` as a `usize`, 0 for none; taken as it runs.
#[cfg(test)]
pub(crate) static HOOK_AFTER_THE_USERFAULTFD: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn exception_hook_after_the_userfaultfd() {
    let hook = HOOK_AFTER_THE_USERFAULTFD.swap(0, std::sync::atomic::Ordering::SeqCst);
    if hook != 0 {
        // SAFETY: only `fn()` values are stored.
        unsafe { core::mem::transmute::<usize, fn()>(hook)() };
    }
}

/// Whether `addr` is memory of ours that [`on_exception`] resolves: in a
/// userfaultfd registration, held by a released range's record, or lazy.
#[inline(never)]
fn ours(addr: usize) -> bool {
    crate::wick_uffd::registered(addr as u64)
        || (RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) != 0
            && RELEASED.lock().unwrap().iter().any(|r| r.holds(addr)))
        || {
            let l = LAZY.lock().unwrap();
            let i = l.partition_point(|&(s, _, _)| s <= addr);
            i.checked_sub(1).is_some_and(|i| addr < l[i].0 + l[i].1)
        }
}

/// Whether an access of `kind` (`ExceptionInformation[0]`: 0 read, 1
/// write, 8 execute) to `addr` is allowed now: committed, not a guard
/// page, and of a protection that allows it ([`accessible`]; for an
/// execution, an executable protection).
#[inline(never)]
fn runs_again(addr: usize, kind: usize) -> bool {
    if kind != 8 {
        return accessible(addr, 1, kind == 1);
    }
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
        return false;
    }
    let base = mbi.Protect & 0xff;
    mbi.State == MEM_COMMIT
        && mbi.Protect & PAGE_GUARD == 0
        && [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY].contains(&base)
}

/// STACKASK (tests): where a stack overflow's first-chance handler runs,
/// for the reclaim a refused stack commit is to ask from there
/// (agent design, condition A1): the faulting RSP's and the faulting
/// address's heights above the TEB's StackLimit (what is committed below
/// them; a frame that probes its pages faults below its RSP), how deep the dispatcher went
/// before this handler (the faulting RSP less this frame's), what is left
/// under this frame, the guarantee and the reserve left, and the page
/// below StackLimit (its state and protection). Measured before the line
/// is formatted; written without allocating.
#[cfg(all(test, target_arch = "x86_64"))]
#[inline(never)]
fn stack_ask_record(fault_rsp: usize, fault_addr: usize) {
    let here = core::ptr::addr_of!(fault_rsp) as usize;
    let (limit, reserve, guarantee) = this_threads_stack();
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut below: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    unsafe { VirtualQuery((limit - 1) as *const c_void, &mut below, std::mem::size_of_val(&below)) };
    // SAFETY: as above.
    let mut at: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    unsafe { VirtualQuery(limit as *const c_void, &mut at, std::mem::size_of_val(&at)) };
    say_at_the_limit(format_args!(
        "STACKASK committed below the faulting rsp {} B, below the faulting address {} B, the dispatcher's frames {} B, left under the handler {} B, \
         guarantee {guarantee} B, reserve left {} KiB; the page at StackLimit {:#x}/{:#x}, below it {:#x}/{:#x} \
         (state/protection; {} B committed there); the exception's context {} B, a larger XSAVE area simulated {} B{}",
        fault_rsp.saturating_sub(limit),
        fault_addr.saturating_sub(limit),
        fault_rsp.saturating_sub(here),
        here.saturating_sub(limit),
        limit.saturating_sub(reserve) >> 10,
        at.State,
        at.Protect,
        below.State,
        below.Protect,
        if below.State == MEM_COMMIT { below.RegionSize } else { 0 },
        exception_context_bytes(),
        simulated_xsave_extra(),
        if IN_THE_LAZY_HANDLER.get() { "; raised in the lazy handler's commit" } else { "" },
    ));
}

#[cfg(all(test, target_arch = "x86_64"))]
std::thread_local! {
    /// STACKUSE (tests): the low end of the stack [`stack_use_paint`]
    /// painted on this thread, and the frame it measures from; 0 for none.
    static STACK_USE: core::cell::Cell<(usize, usize)> = const { core::cell::Cell::new((0, 0)) };
}

/// STACKUSE (tests): at a stack overflow, in [`on_exception`] after
/// STACKASK, paints this thread's committed stack from StackLimit to 512
/// bytes under this frame (0xc3, as STACKWAIT paints), so that
/// [`stack_use_record`] can say how deep the handler and the filters went
/// under it before the process ends.
#[cfg(all(test, target_arch = "x86_64"))]
#[inline(never)]
fn stack_use_paint() {
    let marker = core::hint::black_box(0u8);
    let here = core::ptr::addr_of!(marker) as usize;
    let (limit, _, _) = this_threads_stack();
    let top = here.saturating_sub(512);
    if top > limit {
        // SAFETY: committed stack of this thread below every live frame.
        unsafe { core::ptr::write_bytes(limit as *mut u8, 0xc3, top - limit) };
        STACK_USE.set((limit, here));
    }
}

/// STACKUSE (tests): the stack the handler and the filters used under the
/// frame [`stack_use_paint`] measured from (the lowest byte no longer
/// painted), of what was left there; `at` says where. Written without
/// allocating.
#[cfg(all(test, target_arch = "x86_64"))]
#[inline(never)]
fn stack_use_record(at: &str) {
    let (low, here) = STACK_USE.get();
    if low == 0 {
        return;
    }
    let top = here - 512;
    let mut a = low;
    // SAFETY: the painted range; reads only.
    while a < top && unsafe { core::ptr::read_volatile(a as *const u8) } == 0xc3 {
        a += 1;
    }
    say_at_the_limit(format_args!(
        "STACKUSE {at}: the handler and the filters used {} B under the handler's frame, of {} B left there",
        here - a,
        here - low
    ));
}

/// Installs the process's one exception handler ([`on_exception`]) once,
/// and [`stack_filter`] with it; whether the handler is in place. Called by
/// the first lazy mapping, userfaultfd create or register, whichever comes
/// first: the handler is the same whichever does.
pub(crate) fn exception_handler() -> bool {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    *INSTALLED.get_or_init(|| {
        // SAFETY: a new allocation, committed; given back by `out_of_memory`.
        let rescue = unsafe {
            VirtualAlloc2(proc(), std::ptr::null(), RESCUE_LEN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, std::ptr::null_mut(), 0)
        };
        RESCUE.store(rescue as usize, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: the filter stays for the process; the one it replaces is
        // called for what it does not take.
        let previous = unsafe { windows_sys::Win32::System::Diagnostics::Debug::SetUnhandledExceptionFilter(Some(stack_filter)) };
        PREVIOUS_FILTER.store(previous.map_or(0, |f| f as usize), std::sync::atomic::Ordering::SeqCst);
        // SAFETY: first in the chain; the handler stays for the process.
        !unsafe { windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler(1, Some(on_exception)) }
            .is_null()
    })
}

/// What the exception handler ([`on_exception`]) and the filters
/// ([`stack_filter`], [`last_filter`]) may use of a thread's stack under
/// the exception dispatcher's frames, at most, on any of their paths at a
/// stack's end: the stack page's wait and retry, the lazy commit, the
/// lines and the frames of a VMM that ends. Each thread's stack guarantee
/// ([`stack_guarantee`]) keeps it free below the dispatcher's frames when
/// a stack overflows, and the tests hold both sides: what is left under the
/// handler (STACKASK) is at least this, and what the handler and the
/// filters used there (STACKUSE) is at most this, on each runner and each
/// kind of thread, also with a larger XSAVE area simulated
/// (`WICK_TEST_XSAVE_EXTRA`). Before the guarantee was sized, a thread with
/// none had 7.6 to 9.1 KiB left there where the XSAVE area was AVX-512's
/// (CI run 44177456759) and 4.9 KiB where it was AMX's (CI run 44225041771,
/// whose five stack tests ended with an access violation in the handler).
pub(crate) const HANDLER_STACK_BUDGET: usize = 16 << 10;

/// What the exception dispatcher puts on the faulting thread's stack above
/// the handler besides the exception's context ([`exception_context_bytes`]),
/// at most: the exception record, the dispatcher's own frames and the
/// handler's frame down to where STACKASK measures. Measured 1.6 to 1.9 KiB
/// (STACKASK's dispatcher's frames less the context; held by the tests).
pub(crate) const DISPATCH_OVERHEAD: usize = 4 << 10;

/// The bytes of the exception's context the dispatcher puts on the
/// faulting thread's stack: a `CONTEXT` with the XSAVE state of every
/// feature the system enables (`GetEnabledXStateFeatures`: AVX-512's, AMX's
/// 8 KiB tile data, CET's user state where enabled), as
/// `InitializeContext2` sizes it for `CONTEXT_ALL | CONTEXT_XSTATE`, the
/// documented size of the context `KiUserExceptionDispatcher` hands the
/// handlers (`EXCEPTION_POINTERS::ContextRecord` with its `CONTEXT_EX`).
/// The larger of the compacted form (the given features' mask, as the
/// system saves with `XSAVEC`/`XSAVES`) and the standard one (a mask of 0),
/// so that it holds whichever the system writes. Read once; a host where
/// neither answers is said once and taken as 64 KiB, more than any XSAVE
/// area there is (CPUID leaf 0xD).
pub(crate) fn exception_context_bytes() -> usize {
    static BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let known = BYTES.load(std::sync::atomic::Ordering::Relaxed);
    if known != 0 {
        return known;
    }
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CONTEXT_ALL_AMD64, CONTEXT_XSTATE_AMD64, GetEnabledXStateFeatures, InitializeContext2,
    };
    // SAFETY: plain call.
    let features = unsafe { GetEnabledXStateFeatures() };
    let size_of = |mask: u64| {
        let mut len = 0u32;
        // SAFETY: no buffer: the call only says the length it needs.
        unsafe {
            InitializeContext2(std::ptr::null_mut(), CONTEXT_ALL_AMD64 | CONTEXT_XSTATE_AMD64, std::ptr::null_mut(), &mut len, mask)
        };
        len as usize
    };
    let bytes = size_of(features).max(size_of(0));
    let bytes = if bytes == 0 {
        say_at_the_limit(format_args!(
            "wick: the size of an exception's context could not be read (InitializeContext2, XSAVE features {features:#x}); \
             64 KiB is taken for it in each thread's stack guarantee"
        ));
        64 << 10
    } else {
        bytes
    };
    BYTES.store(bytes, std::sync::atomic::Ordering::Relaxed);
    bytes
}

/// The stack guarantee each thread is given at its start
/// ([`at_thread_start`], `SetThreadStackGuarantee`): what a stack overflow
/// leaves the thread is first the dispatcher's (the exception's context and
/// [`DISPATCH_OVERHEAD`]), then the handler's ([`HANDLER_STACK_BUDGET`]),
/// rounded up to a page. By the sizes (a 1232-byte CONTEXT, its
/// CONTEXT_EX, the compacted XSAVE area), 24 KiB on a host without AMX and
/// 36 KiB with it, whose area is 10752 bytes (Rust's own is 20 KiB, `std`'s
/// `stack_overflow`); the STACKASK lines print this host's context. In the
/// tests, with a simulated larger area added.
pub(crate) fn stack_guarantee() -> usize {
    (exception_context_bytes() + simulated_xsave_extra() + DISPATCH_OVERHEAD + HANDLER_STACK_BUDGET).next_multiple_of(PAGE)
}

/// Gives each thread of the process its stack guarantee ([`stack_guarantee`])
/// as it starts: a TLS callback, which the loader calls on the main thread
/// before the program's entry (`DLL_PROCESS_ATTACH`) and on every thread
/// made after (`DLL_THREAD_ATTACH`), the threads of the process's thread
/// pool, the system's (WHP's, the runtime's) and Rust's alike, in the
/// thread before its own start routine (PE format, "The TLS Section",
/// TLS callback functions). Not reached: a thread made with
/// `THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH`, and the loader's own workers
/// that run before the program's callbacks (ntdll's parallel loader); the
/// tests list every thread of a process and its guarantee
/// (`test_every_thread_has_the_stack_guarantee`).
///
/// Why: when a stack overflows, the system dispatches the exception on the
/// thread's own stack, below the faulting frame, and what it puts there is
/// the exception's context with the thread's whole XSAVE area: about 4 KiB
/// with AVX-512, about 12 KiB with AMX's tile data, which leaves a thread
/// with no guarantee (one made by `CreateThread`, a pool's) too little for
/// the handler's line, its wait for the reclaim or the frames of a VMM that
/// ends at the memory limit: it faulted again in the handler and the
/// process ended with an access violation (0xC0000005) instead of 137 or
/// 0xC00000FD and wick's line (CI run 44225041771, an Intel Xeon Platinum
/// 8573C with AMX; SECURITY.md, Fixed defects).
///
/// What it costs: the guard region the guarantee sizes below a thread's
/// committed stack ([`guard_region_for`]: the guarantee and a page),
/// committed as guard pages, charged to the process and its job, and taken
/// from the thread's reserve; `SetThreadStackGuarantee` makes it
/// ([`set_the_stack_guarantee`]), so at the thread's start and not first
/// at the memory limit (`test_every_thread_has_the_stack_guarantee`, per
/// kind of thread, after the call, at the thread's own start and after it
/// grew; `test_a_stack_guarantee_is_charged_when_it_is_set`: a guarantee
/// raised by 64 KiB grew the process's commit by 65536 B, what the region
/// grew, CI run 44248573219's GUARDCHARGE). A
/// guarantee that cannot be set (a reserve too small for it, or, at the
/// memory limit, a refused commit:
/// `test_a_stack_guarantee_raised_at_the_limit_is_given_or_refused`) is
/// said, with the thread, and the thread runs without it.
#[cfg(target_arch = "x86_64")]
#[used]
#[link_section = ".CRT$XLW"]
static AT_THREAD_START: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) = at_thread_start;

/// [`AT_THREAD_START`]'s callback.
#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn at_thread_start(_module: *mut c_void, reason: u32, _reserved: *mut c_void) {
    const DLL_PROCESS_ATTACH: u32 = 1;
    const DLL_THREAD_ATTACH: u32 = 2;
    if reason == DLL_PROCESS_ATTACH {
        #[cfg(test)]
        read_simulated_xsave_extra();
        #[cfg(test)]
        // SAFETY: an out-pointer.
        unsafe {
            let mut now = 0u64;
            windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime((&raw mut now).cast());
            PROCESS_ATTACHED_AT.store(now, std::sync::atomic::Ordering::Relaxed);
        }
    }
    if reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH {
        set_the_stack_guarantee(reason);
    }
}

/// Sets the calling thread's stack guarantee to [`stack_guarantee`] (a
/// larger one already set stays: the system only raises it), and says so
/// if it could not be set, or reads back smaller. The call makes the
/// guard region below the thread's committed stack, measured, not
/// documented (Learn's page for the call gives no mechanism): 12288 B of
/// guard pages below StackLimit before it on a Rust and a pool thread, 0
/// on a `CreateThread` thread, and 28672 B after it on all three for a
/// guarantee of 24576 B, the guarantee and a page ([`guard_region_for`])
/// (CI run 44248573219's GUARDSEEN records, Windows Server 2025 26100;
/// `test_every_thread_has_the_stack_guarantee` asserts the region after
/// the call). At the job's memory limit the call is refused
/// (`ERROR_COMMITMENT_LIMIT`) and changes nothing (the same run's
/// GUARANTEELIMIT), which the line below says.
#[cfg(target_arch = "x86_64")]
fn set_the_stack_guarantee(#[allow(unused_variables)] reason: u32) {
    let want = stack_guarantee();
    #[cfg(test)]
    let before = {
        let (limit, _, guarantee) = this_threads_stack();
        (guard_below(limit, 64 * PAGE), guarantee)
    };
    let mut size = u32::try_from(want).unwrap_or(u32::MAX);
    // SAFETY: an in/out pointer to the size.
    let set = unsafe { windows_sys::Win32::System::Threading::SetThreadStackGuarantee(&mut size) } != 0;
    // SAFETY: plain call.
    let err = if set { 0 } else { unsafe { GetLastError() } };
    let (limit, reserve, now) = this_threads_stack();
    #[cfg(not(test))]
    let _ = limit;
    #[cfg(test)]
    guard_seen_record([reason as usize, limit, reserve, before.0, guard_below(limit, 64 * PAGE), before.1, now, err as usize]);
    if set && now >= want {
        return;
    }
    let base: usize;
    // SAFETY: a read of the thread's own TEB (StackBase).
    unsafe { core::arch::asm!("mov {0}, gs:[0x8]", out(reg) base, options(nostack, readonly, preserves_flags)) };
    say_at_the_limit(format_args!(
        "wick: thread {} could not be given a stack guarantee of {want} bytes ({}; its stack reserve {} KiB, its guarantee \
         {now} bytes): a stack overflow on it, or a stack that cannot grow at the memory limit, may end the process with an \
         access violation (0xC0000005) and no line of wick's",
        // SAFETY: plain call.
        unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() },
        GuaranteeCall(set, err),
        base.saturating_sub(reserve) >> 10,
    ));
}

/// The guard region below a thread's committed stack for `guarantee`: the
/// guarantee rounded up to a page and one page more, two pages at least,
/// as the UCRT's `_resetstkoflw` makes it again after an overflow
/// (misc/resetstk.cpp, Windows Kits 10.0.26100.0) and
/// [`stack_page_after_the_reclaim`] after a refused commit. It is the size
/// `SetThreadStackGuarantee` makes it and the system keeps as the stack
/// grows: 28672 B for 24576 B, after the call and after the stack grew
/// 64 KiB, on a Rust, a `CreateThread` and a pool thread and on the
/// process's main thread (CI runs 44241167637 and 44248573219,
/// [`set_the_stack_guarantee`]); not documented. A
/// guard-page hit moves the region down by the page hit (Learn,
/// `_resetstkoflw`: the system "allocates a new guard page that is located
/// one page below the last one"). Its pages are committed, so charged,
/// before the stack needs them, and a stack that cannot grow (a refused
/// commit, or the reserve's end) runs its exception's dispatch and handler
/// on them: STACKASK on a refused commit, a Rust thread with Rust's 20 KiB
/// guarantee that had grown before the limit: 20480 B committed below the
/// faulting address, the page below StackLimit reserved (CI run
/// 44225041771).
#[cfg(target_arch = "x86_64")]
pub(crate) fn guard_region_for(guarantee: usize) -> usize {
    let mut guard = guarantee.next_multiple_of(PAGE);
    if guard != 0 {
        guard += PAGE;
    }
    guard.max(2 * PAGE)
}

/// The bytes of guard pages (committed, `PAGE_GUARD`) right below `limit`
/// (a thread's StackLimit), walked down a page at a time to at most
/// `most`: one `VirtualQuery` cannot say it, as the region it describes
/// runs up from the page asked about (Learn, `MEMORY_BASIC_INFORMATION`:
/// "the region beginning at the base address in which all pages have
/// identical attributes"), so asked at `limit - PAGE` it ends at `limit`
/// and says one page whatever lies below (CI run 44233741878's
/// STACKGUARANTEE: "4096 B of guard pages" on every kind of thread).
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) fn guard_below(limit: usize, most: usize) -> usize {
    let mut n = 0;
    while n < most && limit >= n + 2 * PAGE {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery((limit - n - PAGE) as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0
            || mbi.State != MEM_COMMIT
            || mbi.Protect & PAGE_GUARD == 0
        {
            break;
        }
        n += PAGE;
    }
    n
}

/// Tests: what [`set_the_stack_guarantee`] saw on each thread at its
/// start (GUARDSEEN), in a ring of [`GUARD_SEEN_LEN`] kept apart from the thread's own
/// storage, so that a test reads it by the thread's ID: the ID (written
/// last), the loader's reason, StackLimit and the reserve's low end, the
/// guard bytes below StackLimit before and after `SetThreadStackGuarantee`
/// ([`guard_below`]), the guarantee before and after, and the call's error.
#[cfg(all(test, target_arch = "x86_64"))]
static GUARD_SEEN: [[std::sync::atomic::AtomicUsize; 9]; GUARD_SEEN_LEN] =
    [const { [const { std::sync::atomic::AtomicUsize::new(0) }; 9] }; GUARD_SEEN_LEN];

/// Tests: the records [`GUARD_SEEN`] keeps, the newest. With 256, CI run
/// 44248573219's listing found the test binary's main thread and three
/// test threads with the guarantee and no record; whether the ring had
/// gone round is now said beside the listing, with how many records were
/// written ([`guard_seen_written`]).
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) const GUARD_SEEN_LEN: usize = 4096;
#[cfg(all(test, target_arch = "x86_64"))]
static GUARD_SEEN_NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Tests: one thread's GUARDSEEN record ([`guard_seen`]).
#[cfg(all(test, target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct GuardSeen {
    pub(crate) reason: usize,
    pub(crate) limit: usize,
    pub(crate) reserve: usize,
    pub(crate) guard_before: usize,
    pub(crate) guard_after: usize,
    pub(crate) guarantee_before: usize,
    pub(crate) guarantee_after: usize,
    pub(crate) error: usize,
}

/// Tests: the GUARDSEEN record of the thread `id`, the newest if the ring
/// holds two.
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) fn guard_seen(id: u32) -> Option<GuardSeen> {
    use std::sync::atomic::Ordering::Acquire;
    let next = GUARD_SEEN_NEXT.load(Acquire);
    (0..next.min(GUARD_SEEN_LEN)).map(|k| (next - 1 - k) % GUARD_SEEN_LEN).find_map(|i| {
        let r = &GUARD_SEEN[i];
        (r[0].load(Acquire) == id as usize).then(|| GuardSeen {
            reason: r[1].load(Acquire),
            limit: r[2].load(Acquire),
            reserve: r[3].load(Acquire),
            guard_before: r[4].load(Acquire),
            guard_after: r[5].load(Acquire),
            guarantee_before: r[6].load(Acquire),
            guarantee_after: r[7].load(Acquire),
            error: r[8].load(Acquire),
        })
    })
}

/// Tests: how many GUARDSEEN records were written, one a thread's start
/// (the ring keeps the newest [`GUARD_SEEN_LEN`]).
#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) fn guard_seen_written() -> usize {
    GUARD_SEEN_NEXT.load(std::sync::atomic::Ordering::Acquire)
}

/// Tests: writes the calling thread's GUARDSEEN record; allocates nothing.
#[cfg(all(test, target_arch = "x86_64"))]
fn guard_seen_record(fields: [usize; 8]) {
    use std::sync::atomic::Ordering::{AcqRel, Release};
    let r = &GUARD_SEEN[GUARD_SEEN_NEXT.fetch_add(1, AcqRel) % GUARD_SEEN_LEN];
    r[0].store(0, Release);
    for (slot, v) in r[1..].iter().zip(fields) {
        slot.store(v, Release);
    }
    // SAFETY: plain call.
    r[0].store(unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() } as usize, Release);
}

/// How [`set_the_stack_guarantee`]'s line says what the call did.
struct GuaranteeCall(bool, u32);

impl core::fmt::Display for GuaranteeCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 { f.write_str("set, but read back smaller") } else { write!(f, "SetThreadStackGuarantee failed, error {}", self.1) }
    }
}

/// Tests: the system time (`FILETIME`) when the loader called
/// [`at_thread_start`] for the process: a thread made before it was not
/// given the guarantee.
#[cfg(test)]
pub(crate) static PROCESS_ATTACHED_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tests: bytes by which the handler behaves as if the exception's context
/// were larger (`WICK_TEST_XSAVE_EXTRA`, read once at the process's start):
/// the guarantee grows by them, and [`on_exception`] and [`stack_filter`]
/// run that much deeper ([`as_if_the_dispatch_were_deeper`]), so that a
/// runner whose XSAVE area is AVX-512's runs the overflow paths as one with
/// AMX's (8256 bytes more) or a larger one would.
#[cfg(test)]
static SIMULATED_XSAVE_EXTRA: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn simulated_xsave_extra() -> usize {
    SIMULATED_XSAVE_EXTRA.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(not(test))]
const fn simulated_xsave_extra() -> usize {
    0
}

/// Reads `WICK_TEST_XSAVE_EXTRA` (decimal bytes) without allocating, in
/// the loader's callback.
#[cfg(test)]
fn read_simulated_xsave_extra() {
    let name: [u16; 22] = {
        let mut n = [0u16; 22];
        for (i, b) in b"WICK_TEST_XSAVE_EXTRA".iter().enumerate() {
            n[i] = u16::from(*b);
        }
        n
    };
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetEnvironmentVariableW(name: *const u16, buffer: *mut u16, size: u32) -> u32;
    }
    let mut value = [0u16; 32];
    // SAFETY: a NUL-terminated name and a buffer of the length given.
    let len = unsafe { GetEnvironmentVariableW(name.as_ptr(), value.as_mut_ptr(), 32) } as usize;
    let extra = value[..len.min(32)].iter().take_while(|c| (u16::from(b'0')..=u16::from(b'9')).contains(c)).fold(0usize, |n, &c| {
        n.saturating_mul(10).saturating_add(usize::from(c - u16::from(b'0')))
    });
    SIMULATED_XSAVE_EXTRA.store(extra, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
std::thread_local! {
    /// Tests: the exception (its record's address) whose handler or filter
    /// [`as_if_the_dispatch_were_deeper`] is calling, already deeper; 0 for
    /// none. Keyed by the exception, so that one raised while the deeper
    /// call is made (a stack overflow in its frames) is made deeper as its
    /// own dispatch is: a flag set for the next call let such an overflow's
    /// handler run undeepened and its filter deepened, which STACKUSE then
    /// counted as the filter's use (CI run 44241167637: 23095 B "used", the
    /// handler's frames 5720 B with 16384 B simulated).
    static DEEPER_FOR: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Tests: the exception record `rec` when its handler or filter is to run
/// [`simulated_xsave_extra`] bytes deeper than called (a larger area is
/// simulated and the call is not the deeper one already).
#[cfg(test)]
fn deeper_for(rec: usize) -> Option<usize> {
    (simulated_xsave_extra() != 0 && DEEPER_FOR.get() != rec).then_some(rec)
}

/// Tests: runs `f`, the handler or filter of the exception `rec`,
/// [`simulated_xsave_extra`] bytes deeper in the stack than here, the stack
/// between written (so committed) as a dispatcher's frames would be.
#[cfg(test)]
#[inline(never)]
fn as_if_the_dispatch_were_deeper(rec: usize, f: &mut dyn FnMut() -> i32) -> i32 {
    let here = core::ptr::addr_of!(f) as usize;
    deeper_to(here.saturating_sub(simulated_xsave_extra()), rec, f)
}

#[cfg(test)]
#[inline(never)]
fn deeper_to(target: usize, rec: usize, f: &mut dyn FnMut() -> i32) -> i32 {
    let pad = core::hint::black_box([0x5au8; 256]);
    let r = if core::ptr::addr_of!(pad) as usize > target {
        deeper_to(target, rec, f)
    } else {
        let outer = DEEPER_FOR.replace(rec);
        let r = f();
        DEEPER_FOR.set(outer);
        r
    };
    core::hint::black_box(&pad);
    r
}

/// The unhandled-exception filter [`stack_filter`] replaced, called for
/// what it does not take; 0 for none.
static PREVIOUS_FILTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// `STATUS_STACK_OVERFLOW`.
const STACK_OVERFLOW: i32 = 0xC000_00FD_u32.cast_signed();

/// How much of a thread's stack reserve is left below its committed part
/// before the stack is used up, at most, when a stack overflow is the
/// reserve's end: the thread's stack guarantee (`SetThreadStackGuarantee`,
/// the TEB's GuaranteedStackBytes) and its guard page, with a margin of
/// three pages. More left is a commit the system refused ([`stack_filter`]).
fn reserve_at_its_end(guarantee: usize) -> usize {
    guarantee.next_multiple_of(PAGE).max(PAGE) + 4 * PAGE
}

/// How long a thread whose stack page the job's limit refused waits for the
/// reclaim under way at most ([`stack_page_after_the_reclaim`]): the wait is
/// for the reclaim's next step, the end of a move or of the reclaim, which
/// is a move's time (4435 and 4614 us a chunk median on record, RECLAIMREC),
/// so 1 s is over 200 of them; it is a backstop, for a wait that could not
/// end (the thread holding something the reclaim needs that is not one of
/// wick's memory locks, which it waits only without), and it ends as
/// without the wait, with 137.
pub(crate) const STACK_WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

/// The stack a wait for the reclaim needs under the exception handler's
/// frame: the wait and the retry use STACKWAIT's measured bytes of it
/// (`test_a_stack_page_refused_during_a_move_is_had_once_it_ends`); a
/// thread with less left (one the stack guarantee could not be given,
/// [`at_thread_start`]; before every thread had one, a thread with none had
/// about 2.7 KiB under the handler, STACKASK) is not made to wait and ends
/// as before.
const STACK_WAIT_ROOM: usize = 4096;

/// The stack [`stack_filter`]'s line of a stack that could not grow takes
/// under the filter's frame (the thread's description, a 512-byte line
/// formatted in place, one `WriteFile`), with a margin: with less, the
/// filter ends the process with 137 before it, so that it cannot fault
/// first.
const STACK137_LINE_ROOM: usize = 4096;

/// The stack STACK137FRAMES takes under the filter's frame
/// (`RtlCaptureStackBackTrace`'s unwind, 32 addresses, a line per frame
/// with its module's name), with a margin: with less, the line says they
/// were not taken, and the exit with 137 follows. STACKUSE measures the
/// whole path with them (`test_a_stack_that_must_grow_at_the_limit_ends_with_137`).
const STACK137_FRAMES_ROOM: usize = 8192;

/// Why a refused stack page was not had: for [`stack_filter`]'s line, set on
/// the thread by [`stack_page_after_the_reclaim`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum StackWait {
    /// No reclaim was under way (or not a refused commit): as before.
    NoReclaim,
    /// A reclaim was under way, not waited for: this thread held (or was
    /// taking) this many of wick's memory locks, which the reclaim takes.
    Held(u32),
    /// A reclaim was under way, not waited for: this thread is the reclaim's.
    Reclaimer,
    /// A reclaim was under way, not waited for: this many bytes of stack
    /// were left under the handler, less than [`STACK_WAIT_ROOM`].
    Room(usize),
    /// Waited for so many microseconds, the reclaim's step seen (`true`) or
    /// the bound reached, and the page refused again.
    Waited(u64, bool),
}

std::thread_local! {
    /// [`StackWait`] of this thread's last refused stack page: no
    /// destructor, a plain TLS access from the handler and the filter.
    static STACK_WAIT: core::cell::Cell<StackWait> = const { core::cell::Cell::new(StackWait::NoReclaim) };
}

/// Stack pages a refused commit had on the retry ([`stack_page_after_the_reclaim`]), after a wait or not.
static STACK_PAGES_HAD_AGAIN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tests: a thread is in [`stack_page_after_the_reclaim`]'s wait now (the
/// count of those that began one).
#[cfg(test)]
pub(crate) static STACK_WAITS_BEGUN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tests: called once (it is taken as it runs) in
/// [`stack_page_after_the_reclaim`] after the refused commit is told from
/// the reserve's end and before the reclaim's state is read: the window
/// between the refusal and that read
/// (`test_a_stack_page_refused_as_the_reclaim_ends_is_had`). An `fn()` as a
/// `usize`, 0 for none.
#[cfg(test)]
pub(crate) static STACK_HANDLER_HOOK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Tests: the retry after the wait is refused as at the limit, for the
/// line of a page refused again after a reclaim that ended
/// (`test_a_stack_page_refused_again_after_the_wait_ends_with_137`).
#[cfg(test)]
pub(crate) static REFUSE_STACK_RETRY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Stack pages a refused commit had on the retry so far.
pub(crate) fn stack_pages_had_again() -> u64 {
    STACK_PAGES_HAD_AGAIN.load(std::sync::atomic::Ordering::Relaxed)
}

/// A stack page the job's limit refused: asked for once more, after a wait
/// for the reclaim's next step while the reclaim moves a chunk; whether it
/// is had, and the access that overflowed runs again. For the vectored
/// handler ([`on_exception`]), first in the chain, at
/// `STATUS_STACK_OVERFLOW`; a page not had goes on as before, to
/// [`stack_filter`] and its 137, with [`STACK_WAIT`] saying why.
///
/// The retry is made for every refused commit (not the reserve's end) with
/// [`STACK_WAIT_ROOM`] under this frame, with a reclaim under way or not:
/// the refusal and this handler's read of the reclaim's state are not one
/// instant, and a page refused in the last move's middle whose handler
/// reads the state after the reclaim's answer was given finds no reclaim
/// under way with the room already back
/// (`test_a_stack_page_refused_as_the_reclaim_ends_is_had`, where it ended
/// with 137). With no room the retry changes nothing, and it takes no lock
/// and allocates nothing, so it is made on a thread that may not wait too
/// (a lock held, the reclaim's own). It cannot loop: one retry per overflow
/// exception, the access run again only when the page was had (so on
/// committed stack); a refused retry goes to the filter, which ends the
/// VMM, and a later page is a new exception.
///
/// Why: a move gives a chunk's dead pages back only at its end, and holds
/// its new section's commit before (`uffd_move_chunk`), so a thread whose
/// stack must grow in between finds no room, where Linux's memory cgroup
/// would reclaim and charge the page (v6.1 mm/memcontrol.c,
/// `try_charge_memcg` :2714 to :2743: reclaim, then charge again, before
/// its out-of-memory kill). After the step there is room, the moved
/// chunk's dead pages (RECLAIMREC: a reader of the moved chunks' live
/// pages was refused a stack page in a move's middle).
///
/// When it waits: only for a refused commit (not the reserve's end,
/// [`reserve_at_its_end`]), only while the reclaim's thread answers an ask
/// ([`wick_uffd::reclaim_in_flight`](crate::wick_uffd::reclaim_in_flight)), and only on a thread that holds none of wick's memory
/// locks (`windows_stacklock::held_here`: every lock of the crate's Windows
/// code, counted from before it is asked for), is not the reclaim's own
/// ([`wick_uffd::on_the_reclaimer`](crate::wick_uffd::on_the_reclaimer)),
/// and has [`STACK_WAIT_ROOM`] bytes of stack under this frame. The reclaim
/// takes those locks (the region table, `RELEASED`, `CHARGES`, ... after the
/// userfaultfd's `LOCK`, which its asker holds), so a thread holding one
/// could be what the reclaim waits for: such a thread does not wait. It
/// may hold locks that are not wick's (the process heap's, the loader's,
/// the standard streams', another crate's): the reclaim takes none, as it
/// allocates nothing (`test_a_reclaim_allocates_nothing`), writes its lines
/// with one `WriteFile` ([`say_at_the_limit`]) and calls only memory
/// functions of the system; for anything else the wait is bounded
/// ([`STACK_WAIT_BOUND`]).
///
/// The retry is what `_resetstkoflw` does after an overflow (the UCRT's
/// misc/resetstk.cpp, Windows Kits 10.0.26100.0): the guard region below
/// the committed stack made again, the thread's stack guarantee rounded up
/// to a page and one page more, two pages at least, committed read-write
/// and then made guard pages (`VirtualAlloc2`, then `VirtualProtect` with
/// `PAGE_GUARD`, as the UCRT's two calls), here below the TEB's StackLimit, where the system's
/// refused commit left the reserve (STACKASK: the page below StackLimit
/// reserved). The system had committed the guard region it held as the
/// thread's stack before it raised the overflow (STACKASK: below the
/// faulting address, the guarantee), so the access runs again on committed
/// stack, and the next growth goes through the new guard pages as any
/// other. One wait and one retry: a refusal of the retry ends the VMM with
/// 137, its line saying it waited ([`StackWait::Waited`]); with no reclaim
/// under way the line is as before.
///
/// The wait and the retry allocate nothing and take no lock; their stack is
/// STACKWAIT's, under [`STACK_WAIT_ROOM`] (the retry alone, and the wait
/// with it).
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn stack_page_after_the_reclaim() -> bool {
    STACK_WAIT.set(StackWait::NoReclaim);
    let (limit, reserve, guarantee) = this_threads_stack();
    if limit.saturating_sub(reserve) <= reserve_at_its_end(guarantee) {
        return false;
    }
    #[cfg(test)]
    {
        let hook = STACK_HANDLER_HOOK.swap(0, std::sync::atomic::Ordering::SeqCst);
        if hook != 0 {
            // SAFETY: only `fn()` values are stored.
            unsafe { core::mem::transmute::<usize, fn()>(hook)() };
        }
    }
    let reclaim = crate::wick_uffd::reclaim_in_flight();
    let here = core::ptr::addr_of!(reclaim) as usize;
    let left = here.saturating_sub(limit);
    if left < STACK_WAIT_ROOM {
        STACK_WAIT.set(if reclaim.is_some() { StackWait::Room(left) } else { StackWait::NoReclaim });
        return false;
    }
    let held = crate::windows_stacklock::held_here();
    // No wait (the retry alone) on the reclaim's own thread or one holding
    // one of wick's memory locks, and with no reclaim under way.
    let not = match reclaim {
        None => Some(StackWait::NoReclaim),
        Some(_) if crate::wick_uffd::on_the_reclaimer() => Some(StackWait::Reclaimer),
        Some(_) if held != 0 => Some(StackWait::Held(held)),
        Some(_) => None,
    };
    #[cfg(test)]
    let paint = stack_wait_paint(limit, here);
    let waited = match (not, reclaim) {
        (None, Some(seen)) => {
            #[cfg(test)]
            STACK_WAITS_BEGUN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(crate::wick_uffd::wait_for_the_reclaim(seen, STACK_WAIT_BOUND))
        }
        _ => None,
    };
    let guard = guard_region_for(guarantee);
    let at = limit - guard;
    #[cfg(test)]
    let refuse = REFUSE_STACK_RETRY.swap(false, std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(test))]
    let refuse = false;
    let mut old = 0;
    // SAFETY: the reserved pages of this thread's own stack below its
    // committed part: below every frame, and above the reserve's last page
    // (`left` is over the guard and four pages more, `reserve_at_its_end`).
    let had = !refuse
        && unsafe {
            !VirtualAlloc2(proc(), at as *const c_void, guard, MEM_COMMIT, PAGE_READWRITE, std::ptr::null_mut(), 0).is_null()
                && VirtualProtect(at as *const c_void, guard, PAGE_READWRITE | PAGE_GUARD, &mut old) != 0
        };
    #[cfg(test)]
    stack_wait_record(paint, here, left, waited, had);
    if had {
        STACK_PAGES_HAD_AGAIN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return true;
    }
    STACK_WAIT.set(match (waited, not) {
        (Some((ended, us)), _) => StackWait::Waited(us, ended),
        (None, Some(not)) => not,
        (None, None) => StackWait::NoReclaim,
    });
    false
}

/// STACKWAIT (tests): paints this thread's committed stack from `limit` to
/// 512 bytes under `here` before the wait, for [`stack_wait_record`]; the
/// painted range's low end.
#[cfg(all(test, target_arch = "x86_64"))]
#[inline(never)]
fn stack_wait_paint(limit: usize, here: usize) -> usize {
    let top = here - 512;
    // SAFETY: committed stack of this thread below every live frame.
    unsafe { core::ptr::write_bytes(limit as *mut u8, 0xc3, top - limit) };
    limit
}

/// STACKWAIT (tests): the stack the retry, and the wait before it if any,
/// used under [`stack_page_after_the_reclaim`]'s frame (from `here`, the
/// lowest byte no longer painted), of `left`; the wait's microseconds and
/// whether the reclaim's step ended it, or that there was none; and whether
/// the page was had. Written after the measure, without allocating.
#[cfg(all(test, target_arch = "x86_64"))]
#[inline(never)]
fn stack_wait_record(low: usize, here: usize, left: usize, waited: Option<(bool, u64)>, had: bool) {
    let top = here - 512;
    let mut a = low;
    // SAFETY: as `stack_wait_paint`'s range; reads only.
    while a < top && unsafe { core::ptr::read_volatile(a as *const u8) } == 0xc3 {
        a += 1;
    }
    let used = here - a;
    match waited {
        Some((ended, us)) => say_at_the_limit(format_args!(
            "STACKWAIT the wait and the retry used {used} B under the handler's frame, of {left} B left there; waited {us} us, {}; the page {}",
            if ended { "the reclaim's step seen" } else { "the bound reached" },
            if had { "had" } else { "refused again" }
        )),
        None => say_at_the_limit(format_args!(
            "STACKWAIT the retry alone (no wait) used {used} B under the handler's frame, of {left} B left there; the page {}",
            if had { "had" } else { "refused again" }
        )),
    }
}

/// The calling thread's stack from its TEB (x86-64): the lowest committed
/// address (StackLimit, `gs:[0x10]`), the reserve's low end
/// (DeallocationStack, `gs:[0x1478]`) and the stack guarantee
/// (GuaranteedStackBytes, `gs:[0x1748]`).
#[cfg(target_arch = "x86_64")]
fn this_threads_stack() -> (usize, usize, usize) {
    let (limit, reserve, guarantee): (usize, usize, u32);
    // SAFETY: reads of the thread's own TEB.
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:[0x10]",
            "mov {1}, gs:[0x1478]",
            "mov {2:e}, gs:[0x1748]",
            out(reg) limit,
            out(reg) reserve,
            out(reg) guarantee,
            options(nostack, readonly, preserves_flags)
        );
    }
    (limit, reserve, guarantee as usize)
}

/// The calling thread's description (`GetThreadDescription`; Rust sets it
/// to a thread's name), copied into `out`, cut at its length: its length,
/// 0 for none. The system's copy is allocated (`LocalAlloc`) and freed here;
/// at the memory limit [`stack_filter`] has given back [`RESCUE`] first.
fn this_threads_description(out: &mut [u16]) -> usize {
    let mut desc: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the calling thread's pseudo handle and an out-pointer.
    let hr = unsafe {
        windows_sys::Win32::System::Threading::GetThreadDescription(
            windows_sys::Win32::System::Threading::GetCurrentThread(),
            &mut desc,
        )
    };
    if hr < 0 || desc.is_null() {
        return 0;
    }
    let mut n = 0;
    // SAFETY: the system's NUL-terminated string, read up to its NUL or
    // `out`'s length.
    while n < out.len() && unsafe { *desc.add(n) } != 0 {
        out[n] = unsafe { *desc.add(n) };
        n += 1;
    }
    // SAFETY: frees the system's copy, as GetThreadDescription's
    // documentation asks (LocalFree).
    unsafe { windows_sys::Win32::Foundation::LocalFree(desc.cast()) };
    n
}

/// STACK137FRAMES: the return addresses on the stack of a thread whose
/// stack could not grow, printed after the filter's line, from the filter
/// down through the exception dispatcher into the frames that faulted
/// (`RtlCaptureStackBackTrace`), each as an offset in this executable
/// (`__ImageBase`) where it is one, for a debugger with the build's pdb to
/// name (`cdb -z <exe> -y <pdb dir>`, `ln <module>+<offset>`; CI's WHP
/// step names them so). A VMM's last lines then say where its stack had
/// to grow at the limit (the stack reclaim's step 3 and the stack
/// pre-commit are decided from them), where Linux's OOM kill prints the
/// task's memory, not its stack. A frame in another module is named with
/// its offset in it ([`module_of`]: CI run 43823078930's `vcpu-runner` died
/// ten frames deep in a system DLL that `WHvRunVirtualProcessor` called,
/// which the line could not name). Written without allocating, in 256
/// bytes of stack, on the 137 path only.
#[inline(never)]
fn stack_137_frames() {
    unsafe extern "C" {
        static __ImageBase: u8;
    }
    let mut frames = [core::ptr::null_mut::<c_void>(); 32];
    // SAFETY: room for 32 addresses.
    let n = unsafe { windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace(0, 32, frames.as_mut_ptr(), core::ptr::null_mut()) };
    // The linker's symbol for this image's base (its address only).
    let base = core::ptr::addr_of!(__ImageBase) as usize;
    for (i, f) in frames[..usize::from(n)].iter().enumerate() {
        say_frame(i, *f as usize, base);
    }
}

/// One STACK137FRAMES line: frame `i` at `a`, as an offset in this
/// executable (its base `own`), else in the module it lies in, else bare.
fn say_frame(i: usize, a: usize, own: usize) {
    say_frame_as("STACK137FRAMES", i, a, own);
}

/// [`say_frame`] under the record name `tag`.
fn say_frame_as(tag: &str, i: usize, a: usize, own: usize) {
    let mut name = [0u8; 64];
    if a >= own && a - own < 64 << 20 {
        say_at_the_limit(format_args!("{tag} {i} image+{:#x}", a - own));
    } else if let Some((at, len)) = module_of(a, &mut name) {
        say_at_the_limit(format_args!("{tag} {i} {}+{:#x} ({a:#x})", Ascii(&name[..len]), a - at));
    } else {
        say_at_the_limit(format_args!("{tag} {i} {a:#x}"));
    }
}

/// FILTERREC, set by a test's child: [`stack_filter`] and [`last_filter`]
/// say the frames they were called from (FILTERFRAMES), so that the
/// record names who called the unhandled-exception filters and so who
/// takes the exception once they return.
#[cfg(test)]
pub(crate) static SAY_FILTER_FRAMES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// FILTERREC, set by a test's child: the filters end the process with
/// `RaiseFailFastException` given the exception's own record and context
/// (Learn: it "bypasses all exception handlers (frame or vector based)",
/// terminates the process and invokes Windows Error Reporting "if Windows
/// Error Reporting is enabled"), in a job of the jailer's limits too, where
/// [`end_with`] uses `TerminateProcess`: the record of what that end would
/// give there.
#[cfg(test)]
pub(crate) static FAIL_FAST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// [`FAIL_FAST`]'s end, if it is set.
#[cfg(test)]
fn fail_fast_for_the_record(info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) {
    if FAIL_FAST.load(std::sync::atomic::Ordering::SeqCst) {
        say_at_the_limit(format_args!("FILTERREC RaiseFailFastException with the exception's record"));
        // SAFETY: the system's exception pointers.
        unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseFailFastException((*info).ExceptionRecord, (*info).ContextRecord, 0) };
    }
}

/// FAILFASTSTACK, set by a test's child (a KiB count, `usize::MAX` for
/// none): at a stack overflow at the reserve's end the stack filter first
/// takes that many KiB more of the thread's stack, in 1 KiB frames, says
/// how many bytes are then left above the reserve's low end
/// (DeallocationStack), and ends with `RaiseFailFastException` given a copy
/// of the record with the code [`FAIL_FAST_PROBE`]: the process ends with
/// that code only if the call had the stack it needs, so the least left at
/// which it does is what the call takes there.
#[cfg(test)]
pub(crate) static FAIL_FAST_EAT_KIB: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

/// [`FAIL_FAST_EAT_KIB`]'s code.
#[cfg(test)]
pub(crate) const FAIL_FAST_PROBE: u32 = 0xE057_1C4F;

/// [`FAIL_FAST_EAT_KIB`]'s end, if it is set.
#[cfg(test)]
fn fail_fast_after_eating(info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) {
    #[inline(never)]
    fn eat(n: usize, info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) {
        let frame = [0u8; 1024];
        core::hint::black_box(&frame);
        if n > 0 {
            eat(n - 1, info);
        } else {
            at_the_bottom(info);
        }
        core::hint::black_box(&frame);
    }
    #[inline(never)]
    fn at_the_bottom(info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) {
        let (_, reserve, _) = this_threads_stack();
        let sp: usize;
        // SAFETY: reads the stack pointer.
        unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
        say_at_the_limit(format_args!(
            "FAILFASTSTACK {} KiB taken, {} bytes left above the reserve's low end; RaiseFailFastException with code {FAIL_FAST_PROBE:#x}",
            FAIL_FAST_EAT_KIB.load(std::sync::atomic::Ordering::SeqCst),
            sp - reserve
        ));
        // SAFETY: a copy of the system's exception record, its code changed.
        let mut record = unsafe { *(*info).ExceptionRecord };
        record.ExceptionCode = FAIL_FAST_PROBE.cast_signed();
        // SAFETY: a record and the system's context; does not return.
        unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseFailFastException(&record, (*info).ContextRecord, 0) };
    }
    let k = FAIL_FAST_EAT_KIB.load(std::sync::atomic::Ordering::SeqCst);
    if k != usize::MAX {
        eat(k, info);
    }
}

/// FILTERREC: the frames above the filter that calls this, as
/// [`stack_137_frames`] says them, under FILTERFRAMES with `which` first.
#[cfg(test)]
fn filter_frames(which: &str) {
    unsafe extern "C" {
        static __ImageBase: u8;
    }
    if !SAY_FILTER_FRAMES.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    say_at_the_limit(format_args!("FILTERFRAMES {which}"));
    let mut frames = [core::ptr::null_mut::<c_void>(); 24];
    // SAFETY: room for 24 addresses.
    let n = unsafe { windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace(0, 24, frames.as_mut_ptr(), core::ptr::null_mut()) };
    let base = core::ptr::addr_of!(__ImageBase) as usize;
    for (i, f) in frames[..usize::from(n)].iter().enumerate() {
        say_frame_as("FILTERFRAMES", i, *f as usize, base);
    }
}

/// Tests: [`say_frame`] for `a`, this executable's frames given as such.
#[cfg(test)]
pub(crate) fn say_frame_for_test(i: usize, a: usize) {
    unsafe extern "C" {
        static __ImageBase: u8;
    }
    say_frame(i, a, core::ptr::addr_of!(__ImageBase) as usize);
}

/// Whether every page of `[at, at + n)` is committed and readable (not
/// `PAGE_NOACCESS`, execute-only or a guard page), each page asked of
/// `VirtualQuery` once; no allocation.
fn readable(at: usize, n: usize) -> bool {
    let Some(end) = at.checked_add(n) else {
        return false;
    };
    let mut p = at - at % PAGE;
    while p < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(p as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0
            || mbi.State != MEM_COMMIT
            || mbi.Protect & 0xee == 0
            || mbi.Protect & 0x100 != 0
        {
            return false;
        }
        p += PAGE;
    }
    true
}

/// The module an address lies in, for STACK137FRAMES: its base, and the
/// name its export directory gives (`WinHvPlatform.dll`, `ntdll.dll`)
/// copied into `name` (its length returned), read from the image's headers
/// in memory: `VirtualQuery`'s allocation base of an image mapping
/// (`MEM_IMAGE`) is the module's base, and no loader call is made, so no
/// loader lock is taken on the 137 path, and nothing is allocated. A
/// `MEM_IMAGE` view is any `SEC_IMAGE` mapping, not only a module the
/// loader checked, so every offset the headers give is bounded before it
/// is followed: each read lies below the image's `SizeOfImage` (the
/// optional header's, at 56) by checked arithmetic, and on pages that are
/// committed and readable ([`readable`]); a name is read up to 64 bytes or
/// the image's end. `None` for an address in no image, an image with no
/// export directory, or headers that point outside it
/// (`test_a_frame_in_a_damaged_image_is_given_bare`).
fn module_of(a: usize, name: &mut [u8; 64]) -> Option<(usize, usize)> {
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { VirtualQuery(a as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0
        || mbi.Type != windows_sys::Win32::System::Memory::MEM_IMAGE
    {
        return None;
    }
    let base = mbi.AllocationBase as usize;
    // The layout read: `IMAGE_DOS_HEADER.e_lfanew` (0x3c); at it the PE
    // signature (4), the file header (20) and the optional header, whose
    // magic (0x20b, PE32+), `SizeOfImage` (56) and export directory (data
    // directory 0, at 112) are read; then `IMAGE_EXPORT_DIRECTORY.Name`
    // (12), the RVA of a NUL-terminated name.
    const OPT: usize = 24;
    const HEADERS: usize = OPT + 112 + 8;
    let rd = |at: usize| -> u32 {
        // SAFETY: `at` lies in pages `readable` found committed and readable.
        unsafe { core::ptr::read_unaligned(at as *const u32) }
    };
    if !readable(base, 0x40) {
        return None;
    }
    // SAFETY: the image's first page, readable.
    if unsafe { core::ptr::read_unaligned(base as *const u16) } != 0x5a4d {
        return None;
    }
    let lfanew = rd(base + 0x3c) as usize;
    let nt = base.checked_add(lfanew)?;
    if !readable(nt, HEADERS) || rd(nt) != 0x4550 {
        return None;
    }
    // SAFETY: the optional header, readable.
    if unsafe { core::ptr::read_unaligned((nt + OPT) as *const u16) } != 0x20b {
        return None;
    }
    let size = rd(nt + OPT + 56) as usize;
    if lfanew.checked_add(HEADERS)? > size {
        return None;
    }
    let exports = rd(nt + OPT + 112) as usize;
    if exports == 0 || exports.checked_add(16)? > size || !readable(base + exports, 16) {
        return None;
    }
    let at = rd(base + exports + 12) as usize;
    if at >= size {
        return None;
    }
    let n = (size - at).min(name.len());
    if !readable(base + at, n) {
        return None;
    }
    // SAFETY: `n` bytes below the image's end, on readable pages.
    let src = unsafe { core::slice::from_raw_parts((base + at) as *const u8, n) };
    let len = src.iter().position(|&b| b == 0).unwrap_or(n);
    name[..len].copy_from_slice(&src[..len]);
    Some((base, len))
}

/// ASCII shown without allocating (a byte that is not printable as `?`).
struct Ascii<'a>(&'a [u8]);

impl core::fmt::Display for Ascii<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write;
        for &b in self.0 {
            f.write_char(if b.is_ascii_graphic() { char::from(b) } else { '?' })?;
        }
        Ok(())
    }
}

/// [`StackWait`] as [`stack_filter`]'s line says it, without allocating:
/// nothing when no reclaim was under way, so that line is as before.
struct WhyNotHad(StackWait);

impl core::fmt::Display for WhyNotHad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let under = "a reclaim was under way and was not waited for";
        match self.0 {
            StackWait::NoReclaim => Ok(()),
            StackWait::Held(n) => write!(f, "; {under}: the thread held {n} of wick's memory locks, which the reclaim takes"),
            StackWait::Reclaimer => write!(f, "; {under}: the thread is the reclaim's own, whose stack is committed whole at its start"),
            StackWait::Room(b) => write!(f, "; {under}: {b} B of stack were left under the handler, under the {STACK_WAIT_ROOM} B the wait needs"),
            StackWait::Waited(us, ended) => write!(
                f,
                "; a reclaim was under way and was waited for, {us} us ({}), and the page was still refused",
                if ended { "to its next step" } else { "its bound reached" }
            ),
        }
    }
}

/// UTF-16 shown without allocating (a character that is not valid as `?`).
struct Utf16<'a>(&'a [u16]);

impl core::fmt::Display for Utf16<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write;
        for c in char::decode_utf16(self.0.iter().copied()) {
            f.write_char(c.unwrap_or('?'))?;
        }
        Ok(())
    }
}

/// A thread's stack that could not grow because the job's memory limit (or
/// the host's commit limit) refused its next page ends the VMM as the
/// limit's other ends do (exit 137, [`out_of_memory`]), where it would end
/// with `STATUS_STACK_OVERFLOW` (0xC00000FD: STACKZERO,
/// `test_a_stack_that_grows_at_the_limit_on_record`). Learn, "Thread Stack
/// Size": the system commits stack pages "until either the stack reaches
/// the reserved size minus one page ... or the system is so low on memory
/// that the operation fails"; both raise the same exception, and the
/// thread's TEB tells them apart: at the reserve's end little of it is
/// left below the committed part ([`reserve_at_its_end`]), at a refused
/// commit the rest of the reserve is.
///
/// The unhandled-exception filter, so that a frame handler that takes a
/// stack overflow (`_resetstkoflw`) still does; Rust's own vectored handler
/// has printed "has overflowed its stack" by then, which this line
/// follows. Given back first: the commit set aside for the limit's end
/// ([`RESCUE`]), so that the line and the exit have room. The process then
/// ends with `TerminateProcess` at once, bypassing Windows Error Reporting
/// on purpose: an end at the memory limit is not a crash (Linux's
/// out-of-memory kill leaves no core either).
///
/// A stack overflow at the reserve's end gets its line here too (the
/// thread, the reserve left, its guarantee), on every kind of thread, and
/// the process ends here with `STATUS_STACK_OVERFLOW` (0xC00000FD)
/// ([`end_with`]): in a job of the jailer's limits
/// (`JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`,
/// [`in_a_job_that_dies_on_unhandled_exceptions`]) by `TerminateProcess`,
/// out of one by `RaiseFailFastException` with the exception's record,
/// which Windows Error Reporting reports if it is enabled, with its dump,
/// as Linux's SIGSEGV default action ends it with a core. Passed on, a
/// thread pool's worker took the overflow and went on running callbacks,
/// the process alive with whatever the callback held, wherever the process
/// had `SEM_NOGPFAULTERRORBOX`: in such a job (CI run 43823078930's windows
/// job), and alone at error mode 3, as CI's runner starts its children (CI
/// run 43881982686; `test_a_stack_overflow_at_the_reserves_end_is_still_one`,
/// at error mode 0 and 3). Either way the filter this one replaced is not called for
/// it, as on Linux Firecracker's SIGSEGV handler is not run for one:
/// vmm-sys-util registers it without `SA_ONSTACK` (0.15.0,
/// src/linux/signal.rs, `sa_flags = libc::SA_SIGINFO`), so the kernel
/// places the signal's frame on the overflowed stack (v6.1
/// arch/x86/kernel/signal.c:240, `get_sigframe`), fails to write it (:826,
/// :844) and kills the process with SIGSEGV's default action
/// (kernel/signal.c:2904 `force_sigsegv`, :1696, :1674 `HANDLER_SIG_DFL`):
/// Firecracker's log line and metric for it are not written there either.
/// Every other exception goes on to that filter (vmm-sys-util's, which
/// runs the handler registered for its fault signal), and one it does not
/// resume (`EXCEPTION_CONTINUE_EXECUTION`) to [`last_filter`], which ends
/// the process.
unsafe extern "system" fn stack_filter(info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) -> i32 {
    #[cfg(test)]
    // SAFETY: the system passes valid exception pointers.
    if let Some(rec) = deeper_for(unsafe { (*info).ExceptionRecord } as usize) {
        // SAFETY: the system's exception pointers, passed on.
        return as_if_the_dispatch_were_deeper(rec, &mut || unsafe { stack_filter(info) });
    }
    // SAFETY: the system passes valid exception pointers.
    let code = unsafe { (*(*info).ExceptionRecord).ExceptionCode };
    #[cfg(target_arch = "x86_64")]
    if code == STACK_OVERFLOW {
        let (limit, reserve, guarantee) = this_threads_stack();
        let left = limit.saturating_sub(reserve);
        if left > reserve_at_its_end(guarantee) {
            // The stack under this frame, read first: the line and the
            // frames are written only with room for them, so that nothing
            // here faults before the exit with 137. A thread with the
            // stack guarantee always has it (`at_thread_start`); one
            // without (one the guarantee could not be given, said at its
            // start) may not: it ends with 137 and no line.
            let room = (core::ptr::addr_of!(left) as usize).saturating_sub(limit);
            if room < STACK137_LINE_ROOM {
                // SAFETY: ends this process at once, as SIGKILL does.
                unsafe { windows_sys::Win32::System::Threading::TerminateProcess(GetCurrentProcess(), OOM_EXIT) };
                std::process::abort();
            }
            let rescue = RESCUE.swap(0, std::sync::atomic::Ordering::SeqCst);
            if rescue != 0 {
                // SAFETY: frees the block set aside for this.
                unsafe { VirtualFree(rescue as *mut c_void, 0, MEM_RELEASE) };
            }
            let mut name = [0u16; 64];
            let len = this_threads_description(&mut name);
            say_at_the_limit(format_args!(
                "wick: a thread's stack could not grow: the memory limit (the jail's memory.max, or the host's commit \
                 limit) refused its next page with {} KiB of its reserve left (thread {} \"{}\", its guarantee {guarantee} \
                 bytes){}; the VMM ends, as the cgroup OOM killer ends it on Linux (exit {OOM_EXIT}), not as a stack overflow",
                left >> 10,
                // SAFETY: plain call.
                unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() },
                Utf16(&name[..len]),
                WhyNotHad(STACK_WAIT.get()),
            ));
            if room >= STACK137_FRAMES_ROOM {
                stack_137_frames();
            } else {
                say_at_the_limit(format_args!(
                    "STACK137FRAMES not taken: {room} B of stack under the filter, under the {STACK137_FRAMES_ROOM} B they take"
                ));
            }
            #[cfg(all(test, target_arch = "x86_64"))]
            stack_use_record("at the exit with 137");
            // SAFETY: ends this process at once, as SIGKILL does.
            unsafe { windows_sys::Win32::System::Threading::TerminateProcess(GetCurrentProcess(), OOM_EXIT) };
            std::process::abort();
        }
        let jailed = in_a_job_that_dies_on_unhandled_exceptions();
        // Once: a pool's filter and the thread's start may each call the
        // filters for the one overflow.
        if !ENDING.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let mut name = [0u16; 64];
            let len = this_threads_description(&mut name);
            say_at_the_limit(format_args!(
                "wick: a thread's stack overflowed at its reserve's end, {} KiB of it left (thread {} \"{}\", its guarantee \
                 {guarantee} bytes); {} with STATUS_STACK_OVERFLOW (0xC00000FD){}",
                left >> 10,
                // SAFETY: plain call.
                unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() },
                Utf16(&name[..len]),
                if jailed { "in a job that dies on unhandled exceptions, the process ends" } else { "the process ends" },
                if jailed { "" } else { ", reported by Windows Error Reporting if it is enabled" }
            ));
        }
        #[cfg(test)]
        filter_frames("stack_filter, a stack overflow at the reserve's end");
        #[cfg(all(test, target_arch = "x86_64"))]
        stack_use_record("at the end of an overflow");
        #[cfg(test)]
        fail_fast_for_the_record(info);
        #[cfg(test)]
        fail_fast_after_eating(info);
        // SAFETY: the system's exception pointers.
        unsafe { end_with(info, STACK_OVERFLOW.cast_unsigned(), jailed) };
    }
    // SAFETY: the system's exception pointers, passed on.
    let r = unsafe { call_filter(PREVIOUS_FILTER.load(std::sync::atomic::Ordering::SeqCst), info) };
    if r == windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION {
        r
    } else {
        // Nothing above ended it nor resumes it: whatever the filters below
        // said (a chain that reached the last filter ends there, so this is
        // one that did not), the last filter ends it.
        // SAFETY: as above.
        unsafe { last_filter(info) }
    }
}

/// How the filters end the process for an exception nothing handles, with
/// `code`, its own: in a job of the jailer's limits
/// ([`in_a_job_that_dies_on_unhandled_exceptions`]) by `TerminateProcess`,
/// as before (the job forces `SEM_NOGPFAULTERRORBOX`: no Windows Error
/// Reporting, so no report and no dump of a jailed VMM's memory, which
/// holds its guest's; FILTERREC: `RaiseFailFastException` invoked it even
/// there, about 2 s); out of such a job by `RaiseFailFastException` with
/// the exception's own record and context, which Learn says "bypasses all
/// exception handlers (frame or vector based)", ends the process with the
/// record's code, and invokes Windows Error Reporting "if Windows Error
/// Reporting is enabled" (and a just-in-time debugger if one is set), so the
/// report, and the dump the host's settings ask for, are as a process
/// Windows Error Reporting ended has them; a frame handler below the filters
/// gets no second look at it. That second look is what kept a pool going:
/// the thread pool's worker calls `UnhandledExceptionFilter` from its own
/// exception filter (FILTERREC's frames: `ntdll!TppWorkerThread$filt$5`,
/// `TppWorkerpInnerExceptionFilter`, on Windows Server 2022 20348 then
/// `TppExceptionFilter`, `KernelBase!UnhandledExceptionFilter`), which under
/// `SEM_NOGPFAULTERRORBOX` (the job's, an inherited error mode, or the
/// process's own) does not invoke Windows Error Reporting and returns
/// `EXCEPTION_EXECUTE_HANDLER` (Learn, SetErrorMode and
/// UnhandledExceptionFilter); its handler then took a stack overflow and
/// went on running callbacks on that thread (FILTERREC, CI run 43881982686).
///
/// # Safety
/// `info` is the system's exception pointers.
unsafe fn end_with(info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS, code: u32, jailed: bool) -> ! {
    if !jailed {
        // SAFETY: the system's exception record and context; does not return.
        unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseFailFastException((*info).ExceptionRecord, (*info).ContextRecord, 0) };
    }
    // SAFETY: ends this process at once, as the job's limit asks.
    unsafe { windows_sys::Win32::System::Threading::TerminateProcess(GetCurrentProcess(), code) };
    std::process::abort();
}

/// Calls the unhandled-exception filter `f` (a value
/// `SetUnhandledExceptionFilter` returned, 0 for none) with `info`;
/// `EXCEPTION_CONTINUE_SEARCH` for none.
///
/// # Safety
/// `f` is 0 or such a filter; `info` the system's exception pointers.
unsafe fn call_filter(f: usize, info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) -> i32 {
    if f == 0 {
        return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: a filter SetUnhandledExceptionFilter returned, of this
    // signature.
    let f: windows_sys::Win32::System::Diagnostics::Debug::LPTOP_LEVEL_EXCEPTION_FILTER = unsafe { core::mem::transmute(f) };
    // SAFETY: the caller's exception pointers.
    f.map_or(windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH, |f| unsafe { f(info) })
}

/// Set once [`last_filter`] or [`stack_filter`] has written its line: a
/// second call of the filters meanwhile (another exception, on another
/// thread or in the filter itself, or a second caller of the filters for
/// the same one) writes none.
static ENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this process is in a job whose limits include
/// `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` (the jailer's), asked of
/// the job it is in (`QueryInformationJobObject` with no handle), a system
/// call that allocates nothing: there Windows Error Reporting is not called
/// for an unhandled exception, and how the process ends is left to the
/// filters' caller. Not in a job, or the query refused: no. Only the
/// immediate job is asked (Learn, QueryInformationJobObject: "If the job is
/// nested, the immediate job of the calling process is used"), which is
/// the jail's own in the jailer's nesting; a job with the flag around one
/// without it does not reach that job's processes either: they end as in
/// no job, by `RaiseFailFastException` with the exception's code
/// (`test_a_job_nested_in_one_that_dies_on_unhandled_exceptions_ends_by_its_own_limits`).
fn in_a_job_that_dies_on_unhandled_exceptions() -> bool {
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOBOBJECT_BASIC_LIMIT_INFORMATION, JobObjectBasicLimitInformation,
        QueryInformationJobObject,
    };
    // SAFETY: plain data.
    let mut info: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: the job of this process; a buffer of the size given.
    let ok = unsafe {
        QueryInformationJobObject(
            std::ptr::null_mut(),
            JobObjectBasicLimitInformation,
            (&raw mut info).cast(),
            u32::try_from(core::mem::size_of_val(&info)).unwrap_or(0),
            std::ptr::null_mut(),
        )
    };
    ok != 0 && info.LimitFlags & JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION != 0
}

/// The last unhandled-exception filter, installed before `main`
/// ([`LAST_FILTER_AT_START`]) in every process that links this crate (the
/// VMM, its API process, the jailer), so that every filter installed later
/// (vmm-sys-util's for the fault signals Firecracker registers handlers
/// for, [`stack_filter`]) has it below. An exception that no handler and no
/// filter above took gets a line here, written without allocating, that
/// names its code, its address and the thread. Then the process ends here
/// with the exception's code ([`end_with`]), whatever the error mode: in a
/// job of the jailer's limits ([`in_a_job_that_dies_on_unhandled_exceptions`])
/// by `TerminateProcess`, out of one by `RaiseFailFastException` with the
/// exception's record, which Windows Error Reporting reports if it is
/// enabled, with its dump, as Linux's default action for a fault signal
/// with no handler ends it with a core
/// (`test_an_unhandled_exception_ends_the_process_with_its_code`, at error
/// mode 0 and 3). The end is not left to the filters' caller: Learn,
/// `JOBOBJECT_BASIC_LIMIT_INFORMATION`, says of
/// `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` that
/// `UnhandledExceptionFilter` then returns `EXCEPTION_EXECUTE_HANDLER`,
/// and "Normally, this will cause termination of the process with the
/// exception code as the exit status", and so it does under any
/// `SEM_NOGPFAULTERRORBOX`; that leaves it to whoever called the filters,
/// and a thread pool's worker, which calls them from its own exception
/// filter, took a stack overflow so and went on running callbacks
/// (`test_a_stack_overflow_at_the_reserves_end_is_still_one`).
///
/// Before that, the filter it replaced ([`REPLACED_AT_START`]) is called
/// with the exception, as every filter here calls the one below it: the
/// Visual C++ runtime's, which its startup installs before the C++
/// initializers (MSVC 14.44.35207 crt/src/vcruntime/exe_common.inl:231,
/// `pre_cpp_initialization` in `.CRT$XCAA`, which sorts before `.CRT$XCU`,
/// calling `__scrt_set_unhandled_exception_filter`;
/// utility_desktop.cpp:86-102, `__scrt_unhandled_exception_filter`): it
/// calls `terminate()` for an MSVC C++ exception (code 0xE06D7363, four
/// parameters, an EH magic number: ehdata.h:568
/// `PER_IS_MSVC_PURE_OR_NATIVE_EH`) and passes on everything else
/// (`test_the_last_filter_keeps_the_filter_it_replaced`,
/// `test_a_cxx_exception_nothing_catches_ends_through_the_runtimes_filter`).
/// Of its answers only `EXCEPTION_CONTINUE_EXECUTION` (it resumed the
/// thread) is passed on; `EXCEPTION_CONTINUE_SEARCH` and
/// `EXCEPTION_EXECUTE_HANDLER` end the process here: the second is the
/// answer that lets the pool's worker go on, from
/// `ntdll!TppWorkerThread$filt$5` through `TppWorkerpInnerExceptionFilter`
/// (FILTERREC's frames, [`end_with`]). The line says which of the ends it is.
///
/// # Safety
/// `info` is the system's exception pointers.
unsafe extern "system" fn last_filter(info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS) -> i32 {
    // SAFETY: the system passes valid exception pointers.
    let rec = unsafe { &*(*info).ExceptionRecord };
    let code = rec.ExceptionCode.cast_unsigned();
    let jailed = in_a_job_that_dies_on_unhandled_exceptions();
    let replaced = REPLACED_AT_START.load(std::sync::atomic::Ordering::SeqCst);
    // ehdata.h's PER_IS_MSVC_PURE_OR_NATIVE_EH (x86-64: four parameters),
    // which the runtime's filter ends with terminate().
    let cxx = code == 0xE06D_7363
        && rec.NumberParameters == 4
        && matches!(rec.ExceptionInformation[0], 0x1993_0520 | 0x1993_0521 | 0x1993_0522 | 0x0199_4000);
    if !ENDING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        let mut name = [0u16; 64];
        let len = this_threads_description(&mut name);
        let touched = matches!(code, 0xC000_0005 | 0xC000_0006) && rec.NumberParameters >= 2;
        say_at_the_limit(format_args!(
            "wick: an unhandled exception {code:#x} at {:#x}{}{} (thread {} \"{}\"): no handler took it; {}",
            rec.ExceptionAddress as usize,
            if touched { ", touching " } else { "" },
            Hex(touched.then(|| rec.ExceptionInformation[1])),
            // SAFETY: plain call.
            unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() },
            Utf16(&name[..len]),
            if cxx && replaced != 0 {
                "a C++ exception, which the filter this one replaced (the C runtime's) ends with terminate()"
            } else if jailed {
                "in a job that dies on unhandled exceptions, the process ends with its code"
            } else {
                "the process ends with its code, reported by Windows Error Reporting if it is enabled"
            }
        ));
    }
    #[cfg(test)]
    filter_frames("last_filter");
    #[cfg(test)]
    fail_fast_for_the_record(info);
    // SAFETY: the system's exception pointers, passed on.
    let r = unsafe { call_filter(replaced, info) };
    if r == windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION {
        return r;
    }
    // EXCEPTION_EXECUTE_HANDLER is not passed on: it is the answer that
    // let a pool's worker go on (`end_with`).
    // SAFETY: the system's exception pointers.
    unsafe { end_with(info, code, jailed) }
}

/// A hexadecimal number shown without allocating; nothing for none.
struct Hex(Option<usize>);

impl core::fmt::Display for Hex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.map_or(Ok(()), |v| write!(f, "{v:#x}"))
    }
}

/// The filter [`install_last_filter`] replaced, called by [`last_filter`]
/// for every exception it gets (a value `SetUnhandledExceptionFilter`
/// returned, 0 for none): in an executable the Visual C++ runtime starts,
/// that runtime's (`__scrt_unhandled_exception_filter`, which ends an
/// unhandled C++ exception with `terminate()`).
static REPLACED_AT_START: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// [`REPLACED_AT_START`], for a test.
#[cfg(test)]
pub(crate) fn replaced_at_start() -> usize {
    REPLACED_AT_START.load(std::sync::atomic::Ordering::SeqCst)
}

extern "C" fn install_last_filter() {
    // SAFETY: a filter for the process's life; the one it replaces is kept
    // and called by it.
    let replaced = unsafe { windows_sys::Win32::System::Diagnostics::Debug::SetUnhandledExceptionFilter(Some(last_filter)) };
    REPLACED_AT_START.store(replaced.map_or(0, |f| f as usize), std::sync::atomic::Ordering::SeqCst);
}

/// Run by the C runtime before `main` (its `.CRT$XCU` initializers), so
/// that [`last_filter`] is below every filter installed after.
#[used]
#[link_section = ".CRT$XCU"]
static LAST_FILTER_AT_START: extern "C" fn() = install_last_filter;

/// `mprotect` of `[s, e)`, in the lazy region at `b`: committed pages get
/// the protection now, and the rest (Windows sets no protection on pages
/// not committed) stays reserved, getting it when its first access commits
/// it ([`LAZY`]); `PROT_NONE` ones are committed by no access. As Linux,
/// whose `mprotect` changes the entries of the pages present and brings in
/// none (mm/mprotect.c, `change_protection`), so that an anonymous mapping
/// is charged for what was touched, whatever its protection: Firecracker
/// makes each unplugged virtio-mem slot `PROT_NONE` at start-up, and
/// committing them then charged the whole hotplug region (measured on WHP:
/// a commit charge of 1182 MiB for a 512 MiB guest with 1024 MiB of
/// hotplug memory, unchanged by an unplug). Mapped `PROT_NONE` parts
/// left decommitted by a fixed mapping ([`Region::noaccess`]) become lazy
/// with the rest.
fn protect_lazy(t: &mut Table, b: usize, s: usize, e: usize, wprot: PAGE_PROTECTION_FLAGS) -> bool {
    let r = t.get_mut(&b).unwrap();
    ranges_remove(&mut r.noaccess, s - b, e - s);
    // A released userfaultfd range's pages keep theirs in its record.
    if !released_protect(s, e, wprot) {
        lazy_add(s, e - s, wprot);
    }
    let mut at = s;
    while at < e {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return false;
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
        if mbi.State == MEM_COMMIT {
            // A discarded page stays closed until its first access zeroes
            // it (pending in its record), which gives it the protection then
            // asked for.
            let mut p = at;
            for q in (at..at + run).step_by(PAGE).chain([at + run]) {
                if q == at + run || released_is_pending(q) {
                    if q > p && !protect(p, q - p, wprot) {
                        return false;
                    }
                    p = q + PAGE;
                }
            }
        }
        at += run;
    }
    true
}

fn commit(base: usize, len: usize, prot: PAGE_PROTECTION_FLAGS, replace: bool) -> bool {
    // A charged view's pages: their charge first, so that the job's limit
    // refuses before the section's page is taken ([`Charge`]).
    if !replace && !charge(base, len) {
        return false;
    }
    let done = commit_now(base, len, prot, replace);
    // Before the caller (and so the guest or the thread that faulted) can
    // write the pages: a page whose bit is clear is asked about, so a bit set
    // late would cost a query, not data; set here, it costs nothing.
    if done && !replace {
        touched_mark(base, len, true);
    }
    done
}

fn commit_now(base: usize, len: usize, prot: PAGE_PROTECTION_FLAGS, replace: bool) -> bool {
    let flags = if replace {
        MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER
    } else {
        MEM_COMMIT
    };
    // SAFETY: commits memory in our placeholder or allocation.
    let p = unsafe {
        VirtualAlloc2(
            proc(),
            base as *const c_void,
            len,
            flags,
            prot,
            std::ptr::null_mut(),
            0,
        )
    };
    !p.is_null()
}

fn protect(base: usize, len: usize, prot: PAGE_PROTECTION_FLAGS) -> bool {
    let mut old = 0;
    // SAFETY: changes the protection of our memory.
    unsafe { VirtualProtect(base as *const c_void, len, prot, &mut old) != 0 }
}

/// [`protect`] of the committed pages of `[s, e)`.
fn protect_committed(s: usize, e: usize, prot: PAGE_PROTECTION_FLAGS) -> bool {
    let mut at = s;
    while at < e {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return false;
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
        if mbi.State == MEM_COMMIT && !protect(at, run, prot) {
            return false;
        }
        at += run;
    }
    true
}

/// Reads the file into private memory; past the end it stays zero.
fn fill_from_file(base: usize, len: usize, file: HANDLE, off: i64) -> bool {
    let fd = crate::windows_fd::to_fd_pub(file);
    let mut done = 0usize;
    while done < len {
        // SAFETY: the destination is our committed, writable memory. Not
        // counted in flight ([`InFlight`]): the caller holds the table, and
        // no discard reaches this memory before the call returns.
        let n = unsafe {
            crate::windows_fd::pread_now(
                fd,
                (base + done) as *mut c_void,
                len - done,
                off + i64::try_from(done).unwrap(),
            )
        };
        if n < 0 {
            return false;
        }
        if n == 0 {
            break;
        }
        done += n.unsigned_abs();
    }
    true
}

/// Finds or creates the section to map `fd` with, and its size.
///
/// `need` is where the mapping ends. As with POSIX, it may end inside the
/// page that holds the end of the file (that page reads as zero past it);
/// whole pages past the end are refused (`EINVAL`), as Windows has no
/// `SIGBUS` page to give them.
fn section_of(fd: c_int, writable: bool, need: u64) -> Result<(Arc<Owned>, u64), c_int> {
    let page = PAGE as u64;
    let covers = |size: u64| need <= size.div_ceil(page) * page;
    if let Some(s) = wick_fd::attached::<wick_mm::Section>(fd) {
        if covers(s.size) {
            let size = s.size;
            return dup(s.handle as HANDLE)
                .map(|h| (Arc::new(h), size))
                .ok_or(crate::EBADF);
        }
        if s.grow_sealed() {
            return Err(crate::EINVAL);
        }
        // Sealed against shrinking only, and grown since: a section of the
        // file as it is now.
    }
    let mut st = crate::windows_fd::stat::default();
    // SAFETY: valid out-parameter.
    if unsafe { crate::windows_fd::fstat(fd, &mut st) } != 0 {
        return Err(crate::EBADF);
    }
    let size = u64::try_from(st.st_size).unwrap_or(0);
    if size == 0 || !covers(size) {
        // Whole pages past the end (an empty file has no section either).
        return Err(crate::EINVAL);
    }
    let prot = if writable {
        PAGE_READWRITE
    } else {
        PAGE_READONLY
    };
    // SAFETY: creates a section of the whole file.
    let s =
        unsafe { CreateFileMappingW(handle(fd), std::ptr::null(), prot, 0, 0, std::ptr::null()) };
    if s.is_null() {
        return Err(crate::EACCES);
    }
    Ok((Arc::new(Owned(s)), size))
}

/// Maps into the placeholder [base, base + len).
#[allow(clippy::too_many_arguments)]
fn fill(
    t: &mut Table,
    base: usize,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    off: i64,
) -> Result<(), c_int> {
    let wprot = win_prot(prot).ok_or(crate::EINVAL)?;
    let anon = flags & MAP_ANONYMOUS != 0;
    let shared = flags & MAP_SHARED != 0;
    let mut lazy = false;
    // An anonymous shared mapping whose pages are charged ([`Charge`]).
    let mut charged = false;
    let kind = if anon && !shared {
        if prot == PROT_NONE {
            Kind::Placeholder
        } else if flags & MAP_NORESERVE != 0 && flags & MAP_POPULATE == 0 && exception_handler() {
            // Reserved now, committed page block by page block at the first
            // access ([`LAZY`]).
            // SAFETY: reserves our placeholder.
            let p = unsafe {
                VirtualAlloc2(
                    proc(),
                    base as *const c_void,
                    len,
                    MEM_RESERVE | MEM_REPLACE_PLACEHOLDER,
                    wprot,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if p.is_null() {
                return Err(crate::ENOMEM);
            }
            lazy = true;
            Kind::Private { file: None }
        } else {
            if !commit(base, len, wprot, true) {
                return Err(crate::ENOMEM);
            }
            Kind::Private { file: None }
        }
    } else if !shared {
        // Private file mapping: a private copy of the file, committed and
        // read whole now, `MAP_NORESERVE` or not (a snapshot's memory file
        // restored with the File backend: the whole guest charged and read
        // at the load), where Linux charges by the page as it is touched
        // (mm/filemap.c `filemap_fault`: the page cache's folio for a read,
        // with read-around; mm/memory.c `do_cow_fault` for a write).
        //
        // Not filled by the page at its first access, as lazy anonymous
        // memory is committed: there is no race-free way to fill private
        // memory here. Committing a page makes it readable and writable to
        // every thread and to WHP's second-level tables at once, before the
        // file's bytes are in it, so another vCPU (whose access WHP then
        // resolves without an exit) or a device thread can read zeros, or
        // write what the fill then overwrites. Ruled out: committing it
        // `PAGE_NOACCESS` and filling through the kernel (`ReadFile` into a
        // page that is not accessible fails, as into one only reserved);
        // `WriteProcessMemory` (kernel32 opens the page's protection while it
        // copies); `PAGE_GUARD` (cleared by the filler's own first write);
        // a second mapping to fill through (private memory has none; only a
        // section does); AWE pages (`SeLockMemoryPrivilege`); and holding
        // the vCPUs out of the guest during each fill (the device threads
        // are left). A section filled through an alias and made accessible
        // after, as `windows_uffd` fills registered memory, is race-free, and
        // can be charged a page at a time as it is filled, as `windows_uffd`
        // charges its pages (a Job Object does not charge sections; the
        // jailer counts them: SECURITY.md, "Windows jailer: `memory.max`
        // bounds memory in sections at the jailer's next count, not at
        // once"): the way left for this mapping, not done yet.
        let file = dup(handle(fd)).map(Arc::new).ok_or(crate::EBADF)?;
        if !commit(base, len, PAGE_READWRITE, true) {
            return Err(crate::ENOMEM);
        }
        if !fill_from_file(base, len, file.0, off) || !protect(base, len, wprot) {
            // SAFETY: gives the allocation back as a placeholder.
            unsafe {
                VirtualFree(
                    base as *mut c_void,
                    len,
                    MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER,
                )
            };
            return Err(crate::EIO);
        }
        Kind::Private {
            file: Some((file, off)),
        }
    } else {
        let (section, file, view) = if anon {
            let hi = u32::try_from((len as u64) >> 32).unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let lo = len as u32;
            // Reserved, and committed a page at a time at its first access
            // with the page's charge ([`Charge`], [`LAZY`]), as Linux
            // allocates and charges a shmem page when it is touched. Without
            // the exception handler, committed whole, as before.
            charged = exception_handler();
            let reserve = if charged { SEC_RESERVE } else { 0 };
            // SAFETY: creates a pagefile-backed section.
            let s = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_EXECUTE_READWRITE | reserve,
                    hi,
                    lo,
                    std::ptr::null(),
                )
            };
            if s.is_null() {
                return Err(crate::ENOMEM);
            }
            (Arc::new(Owned(s)), None, len)
        } else {
            let start = u64::try_from(off).unwrap();
            let need = start + len as u64;
            let writable = prot & PROT_WRITE != 0;
            let (s, size) = section_of(fd, writable, need)?;
            // A view ends at the end of its section; Windows rounds it up to
            // the page, which then reads as zero past the file's end.
            let view = usize::try_from((size - start).min(len as u64)).unwrap();
            (s, dup(handle(fd)).map(Arc::new), view)
        };
        // SAFETY: maps the section over our placeholder.
        let v = unsafe {
            MapViewOfFile3(
                section.0,
                proc(),
                base as *const c_void,
                u64::try_from(off).unwrap(),
                view,
                MEM_REPLACE_PLACEHOLDER,
                wprot,
                std::ptr::null_mut(),
                0,
            )
        };
        if v.Value.is_null() {
            return Err(crate::EACCES);
        }
        let charge = if charged {
            let Some(c) = charge_add(base, len) else {
                // SAFETY: unmaps the view made above, keeping the placeholder.
                unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: base as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) };
                return Err(crate::ENOMEM);
            };
            Some(c)
        } else {
            None
        };
        Kind::View {
            _section: Some(section),
            uffd: false,
            file,
            charge,
            alias: None,
        }
    };
    t.get_mut(&base).unwrap().kind = kind;
    if lazy {
        t.get_mut(&base).unwrap().lazy = true;
        lazy_add(base, len, wprot);
        touched_add(base, len);
    }
    if charged {
        // Lazy, as private memory is, but not in [`TOUCHED`]: a host read of
        // an untouched page commits and charges it, as Linux's shmem fault
        // allocates and charges a page for a read (mm/shmem.c,
        // `shmem_fault`), where an anonymous private page reads as the zero
        // page.
        t.get_mut(&base).unwrap().lazy = true;
        lazy_add(base, len, wprot);
        if flags & MAP_POPULATE != 0 && prot != PROT_NONE && !commit(base, len, wprot, false) {
            // SAFETY: plain call.
            out_of_memory(base, unsafe { GetLastError() });
        }
    }
    if flags & MAP_POPULATE != 0 && prot != PROT_NONE {
        let range = WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: base as *mut c_void,
            NumberOfBytes: len,
        };
        // SAFETY: prefetches our mapping; advisory.
        unsafe { PrefetchVirtualMemory(proc(), 1, &range, 0) };
    }
    Ok(())
}

/// Enables `SeLockMemoryPrivilege` ("Lock pages in memory") in the process
/// token, once; large pages need it. An administrator grants it, as on
/// Linux an administrator reserves huge pages.
fn lock_memory_privilege() -> bool {
    static HELD: OnceLock<bool> = OnceLock::new();
    *HELD.get_or_init(|| {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: opens our own token.
        if unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)
        } == 0
        {
            return false;
        }
        // SAFETY: an all-zero TOKEN_PRIVILEGES is valid.
        let mut tp: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        let name: Vec<u16> = "SeLockMemoryPrivilege\0".encode_utf16().collect();
        // SAFETY: valid name, LUID and privilege structures; `token` is ours.
        let ok = unsafe {
            LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut tp.Privileges[0].Luid) != 0
                && AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut())
                    != 0
                // Succeeds without the privilege, and says so.
                && GetLastError() != ERROR_NOT_ALL_ASSIGNED
        };
        // SAFETY: closes the token we opened.
        unsafe { CloseHandle(token) };
        ok
    })
}

/// `GetCurrentProcessToken()` (processthreadsapi.h): a pseudo-handle that
/// queries this process's token without opening it, which a jailed process
/// may not do (`OpenProcessToken` is denied there: jail-probe `tokenopen`).
const CURRENT_PROCESS_TOKEN: HANDLE = -4isize as HANDLE;

/// This process's token's integrity level (the label's RID: medium is
/// `0x2000`), read through the pseudo-handle, or the error reading it.
fn integrity_level() -> Result<u32, u32> {
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
        TokenIntegrityLevel,
    };
    let mut buf = [0u64; 64];
    let mut len = 0u32;
    // SAFETY: a buffer of the size passed; the pseudo-handle needs no open.
    let ok = unsafe {
        let p = buf.as_mut_ptr().cast();
        GetTokenInformation(CURRENT_PROCESS_TOKEN, TokenIntegrityLevel, p, 512, &mut len) != 0
    };
    if !ok {
        // SAFETY: plain call.
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL whose SID is valid.
    unsafe {
        let sid = (*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return Err(0);
        }
        Ok(*GetSidSubAuthority(sid, u32::from(count) - 1))
    }
}

/// The size of a large page if `flags` asks for that size (or for the
/// default, `MAP_HUGE_*` bits 0), else `None`.
fn large_page(flags: c_int) -> Option<usize> {
    // SAFETY: plain query.
    let page = unsafe { GetLargePageMinimum() };
    let log2 = (flags >> MAP_HUGE_SHIFT) & 0x3f;
    (page != 0 && (log2 == 0 || 1usize.checked_shl(log2.cast_unsigned()) == Some(page))).then_some(page)
}

/// `mmap` with `MAP_HUGETLB`: anonymous private memory on large pages,
/// committed now (Windows has no lazily faulted large pages; Linux fails a
/// hugetlb mapping it cannot back at fault time instead). With `MAP_FIXED`
/// over whole large pages of a large-page mapping of the same size (as
/// Firecracker maps guest memory: `PROT_NONE` first, then `MAP_FIXED` over
/// it), the new mapping is those pages, zero-filled, with the new
/// protection. Shared and file-backed huge pages (hugetlbfs, `MFD_HUGETLB`
/// memfds), huge pages at a fixed address over other memory and sizes other
/// than the host's large page fail with `ENOMEM`, as Linux does without huge
/// pages of that kind; so does a process without `SeLockMemoryPrivilege`
/// (a jailed Firecracker, whose token is below medium integrity, where no
/// privilege can be enabled: said on stderr), or a host out of contiguous
/// memory. A fixed address that is not a whole
/// number of large pages fails with `EINVAL`, as on Linux.
fn map_large(addr: *mut c_void, len: size_t, prot: c_int, flags: c_int) -> Result<*mut c_void, c_int> {
    let wprot = win_prot(prot).ok_or(crate::EINVAL)?;
    if flags & MAP_ANONYMOUS == 0 || flags & MAP_SHARED != 0 {
        return Err(crate::ENOMEM);
    }
    let page = large_page(flags).ok_or(crate::ENOMEM)?;
    let len = len.div_ceil(page) * page;
    if flags & MAP_FIXED != 0 {
        return fixed_large(addr as usize, len, prot, page);
    }
    // Enables the privilege if this process may adjust its token. Without
    // it the allocation below fails.
    let _ = lock_memory_privilege();
    // With the protection asked for: it cannot be changed afterwards.
    let p = if force_broker() { std::ptr::null_mut() } else { alloc_large(std::ptr::null(), len, wprot) };
    if p.is_null() && broker().is_some() {
        // A jailed Firecracker: its large pages are the jailer's sections.
        return map_large_brokered(len, prot, wprot, page);
    }
    if p.is_null() {
        // SAFETY: plain call.
        let err = unsafe { GetLastError() };
        // A jailed Firecracker (docs/PORTING.md row 10): never silently.
        match integrity_level() {
            Ok(level) if level < 0x2000 => std::eprintln!(
                "wick: large pages: VirtualAlloc2 failed with error {err}; this process's token is at \
                 integrity level {level:#x}, below medium ({:#x}), where a privilege cannot be enabled \
                 (SeLockMemoryPrivilege, which large pages need): a jailed Firecracker gets its large \
                 pages from the jailer, which gives them only to a jail with hugetlb.2MB.max set and \
                 only with \"Lock pages in memory\" held by the operator's account",
                0x2000
            ),
            Ok(_) => {}
            Err(e) => std::eprintln!(
                "wick: large pages: VirtualAlloc2 failed with error {err}; integrity level unknown \
                 (GetTokenInformation error {e}): large pages need SeLockMemoryPrivilege enabled, \
                 which a token below medium integrity cannot have; a jailed Firecracker maps none"
            ),
        }
        return Err(crate::ENOMEM);
    }
    let fresh = prot & PROT_WRITE == 0;
    table().lock().unwrap().insert(p as usize, Region::new(len, Kind::Large { page, fresh, wprot, brokered: false, section: None }));
    Ok(p)
}

/// `len` bytes of large pages, committed and locked, with protection `wprot`
/// (theirs for good), at `at` or anywhere (null); null on failure.
fn alloc_large(at: *const c_void, len: usize, wprot: u32) -> *mut c_void {
    // SAFETY: a new allocation, or a failure.
    unsafe {
        VirtualAlloc2(proc(), at, len, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, wprot, std::ptr::null_mut(), 0)
    }
}

/// `MAP_FIXED` hugetlb mapping of [start, start + len) (whole large pages)
/// over whole pages of one large-page mapping of size `page`: zero-filled
/// pages with protection `prot`. Windows changes no large page's protection
/// ([`Kind::Large`]), so:
/// - over the whole mapping with another protection (Firecracker's guest
///   memory: read-write over its `PROT_NONE` reservation), the mapping is
///   released and allocated again at its address with the new protection.
///   If that fails the range is left unmapped and the call fails with
///   `ENOMEM`, as Linux leaves it when a `MAP_FIXED` mapping fails after
///   the old one is gone;
/// - with the mapping's own protection, the pages are zeroed in place;
/// - over part of the mapping with another protection, `ENOMEM`: one
///   allocation has one protection, and two allocations in its place could
///   not be unmapped as one mapping.
fn fixed_large(start: usize, len: usize, prot: c_int, page: usize) -> Result<*mut c_void, c_int> {
    if !start.is_multiple_of(page) {
        return Err(crate::EINVAL);
    }
    let wprot = win_prot(prot).ok_or(crate::EINVAL)?;
    let end = start + len;
    let mut t = table().lock().unwrap();
    let (b, fresh, old) = match overlapping(&t, start, end)[..] {
        [b] => match t[&b].kind {
            Kind::Large { page: p, fresh, wprot: old, .. } if p == page && b <= start && b + t[&b].len >= end => {
                (b, fresh, old)
            }
            _ => return Err(crate::ENOMEM),
        },
        _ => return Err(crate::ENOMEM),
    };
    let whole = b == start && t[&b].len == len;
    if old == wprot {
        if !fresh {
            zero_large(start, len);
        }
        return Ok(start as *mut c_void);
    }
    if !whole {
        return Err(crate::ENOMEM);
    }
    let brokered = matches!(t[&b].kind, Kind::Large { brokered: true, .. });
    // Releases the mapping, a view or an allocation; the table entry goes
    // with it (`release`).
    release(&mut t, b);
    if brokered {
        // A new section (zero pages, as a new mapping is), or, PROT_NONE, a
        // reservation for one.
        let p = if wprot == PAGE_NOACCESS {
            // SAFETY: reserves the range just released.
            let p = unsafe { VirtualAlloc2(proc(), b as *const c_void, len, MEM_RESERVE, PAGE_NOACCESS, std::ptr::null_mut(), 0) };
            if p as usize != b {
                return Err(crate::ENOMEM);
            }
            t.insert(b, Region::new(len, Kind::Large { page, fresh: true, wprot, brokered: true, section: None }));
            p
        } else {
            let s = broker_section(len).map_err(broker_refused)?;
            let p = map_section_view(&s, b, len, wprot);
            if p as usize != b {
                return Err(crate::ENOMEM);
            }
            t.insert(
                b,
                Region::new(len, Kind::Large { page, fresh: prot & PROT_WRITE == 0, wprot, brokered: true, section: Some(Arc::new(s)) }),
            );
            p
        };
        return Ok(p);
    }
    let p = alloc_large(b as *const c_void, len, wprot);
    if p.is_null() {
        return Err(crate::ENOMEM);
    }
    t.insert(b, Region::new(len, Kind::Large { page, fresh: prot & PROT_WRITE == 0, wprot, brokered: false, section: None }));
    Ok(p)
}

/// The jailer's large pages, for a jailed Firecracker, whose token cannot
/// have "Lock pages in memory" enabled (below medium integrity no privilege
/// can be; measured). The jailer, which holds the privilege, makes a
/// pagefile-backed large-page section of the size asked for
/// (`SEC_COMMIT | SEC_LARGE_PAGES`) and duplicates it into this process,
/// which maps it with `MEM_LARGE_PAGES`: a process without the privilege,
/// at the jail's integrity level, gets large pages so (measured). The
/// channel is two pipes the jailer gives Firecracker (`WICK_LARGE_PAGES`,
/// `<request handle>,<reply handle>`): a request is the size (u64), a reply
/// the section's handle in this process (u64, 0 when refused) and the
/// Windows error (u32). As on Linux, where huge pages come from a pool the
/// administrator reserved and the hugetlb controller (not `memory.max`)
/// limits them, the jailer refuses past the jail's `hugetlb.2MB.max`.
struct Broker {
    request: HANDLE,
    reply: HANDLE,
}

// SAFETY: pipe handles may be used from any thread; behind a lock.
unsafe impl Send for Broker {}

fn broker() -> Option<&'static ProbedMutex<Broker>> {
    static BROKER: OnceLock<Option<ProbedMutex<Broker>>> = OnceLock::new();
    BROKER
        .get_or_init(|| {
            let v = std::env::var("WICK_LARGE_PAGES").ok()?;
            let (a, b) = v.split_once(',')?;
            Some(ProbedMutex::new("the large-page broker", Broker {
                request: a.trim().parse::<usize>().ok()? as HANDLE,
                reply: b.trim().parse::<usize>().ok()? as HANDLE,
            }))
        })
        .as_ref()
}

/// Tests take the broker's path in a process that could map large pages
/// itself.
#[cfg(test)]
static FORCE_BROKER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn force_broker() -> bool {
    #[cfg(test)]
    return FORCE_BROKER.load(std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(test))]
    false
}

/// A large-page section of `len` bytes from the jailer, or the Windows
/// error it refused with.
fn broker_section(len: usize) -> Result<Owned, u32> {
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    let Some(b) = broker() else {
        return Err(0);
    };
    let b = b.lock().unwrap();
    let request = (len as u64).to_le_bytes();
    let mut done = 0u32;
    // SAFETY: writes our buffer to the jailer's pipe.
    if unsafe { WriteFile(b.request, request.as_ptr(), 8, &mut done, std::ptr::null_mut()) } == 0 || done != 8 {
        // SAFETY: plain call.
        return Err(unsafe { GetLastError() });
    }
    let mut reply = [0u8; 12];
    let mut got = 0usize;
    while got < reply.len() {
        let mut n = 0u32;
        // SAFETY: reads into the rest of our buffer.
        let ok = unsafe {
            ReadFile(b.reply, reply[got..].as_mut_ptr(), (reply.len() - got) as u32, &mut n, std::ptr::null_mut())
        };
        if ok == 0 || n == 0 {
            // SAFETY: plain call.
            return Err(unsafe { GetLastError() });
        }
        got += n as usize;
    }
    let handle = u64::from_le_bytes(reply[..8].try_into().unwrap());
    let err = u32::from_le_bytes(reply[8..].try_into().unwrap());
    if handle == 0 {
        return Err(err);
    }
    Ok(Owned(handle as usize as HANDLE))
}

fn broker_refused(err: u32) -> c_int {
    std::eprintln!(
        "wick: large pages: the jailer refused a large-page section (error {err}): the jail's \
         hugetlb.2MB.max is reached, or the host has no contiguous memory for it"
    );
    crate::ENOMEM
}

/// A view of a large-page section at `at` (0: anywhere), or null.
fn map_section_view(section: &Owned, at: usize, len: usize, wprot: u32) -> *mut c_void {
    // SAFETY: maps our section's view into free address space.
    unsafe {
        MapViewOfFile3(section.0, proc(), at as *const c_void, 0, len, MEM_LARGE_PAGES, wprot, std::ptr::null_mut(), 0)
    }
    .Value
}

/// `mmap` with `MAP_HUGETLB` from the jailer's sections ([`Broker`]).
fn map_large_brokered(len: usize, prot: c_int, wprot: u32, page: usize) -> Result<*mut c_void, c_int> {
    let (p, section) = if wprot == PAGE_NOACCESS {
        // A large-page view takes no PAGE_NOACCESS: the range is reserved,
        // aligned to the large page, for the view a MAP_FIXED maps over it.
        // SAFETY: reserves free address space, released again below.
        let over = unsafe { VirtualAlloc2(proc(), std::ptr::null(), len + page, MEM_RESERVE, PAGE_NOACCESS, std::ptr::null_mut(), 0) };
        if over.is_null() {
            return Err(crate::ENOMEM);
        }
        let at = (over as usize).div_ceil(page) * page;
        // SAFETY: releases what was just reserved, then reserves its aligned part.
        let p = unsafe {
            VirtualFree(over, 0, MEM_RELEASE);
            VirtualAlloc2(proc(), at as *const c_void, len, MEM_RESERVE, PAGE_NOACCESS, std::ptr::null_mut(), 0)
        };
        if p as usize != at {
            return Err(crate::ENOMEM);
        }
        (p, None)
    } else {
        let s = broker_section(len).map_err(broker_refused)?;
        let p = map_section_view(&s, 0, len, wprot);
        if p.is_null() {
            return Err(crate::ENOMEM);
        }
        (p, Some(Arc::new(s)))
    };
    let fresh = prot & PROT_WRITE == 0;
    table().lock().unwrap().insert(p as usize, Region::new(len, Kind::Large { page, fresh, wprot, brokered: true, section }));
    Ok(p)
}

/// Zeroes [base, base + len) of a writable large-page mapping (a mapping
/// that is not `fresh` is writable: its protection never changed).
fn zero_large(base: usize, len: usize) {
    // SAFETY: our committed, locked, writable memory.
    unsafe { std::ptr::write_bytes(base as *mut u8, 0, len) };
}

/// `mmap`. With `MAP_FIXED`, the memory it maps over leaves any
/// userfaultfd registration in the same step (`wick_uffd::unmapping`), as
/// Linux's `MAP_FIXED` unmaps what it maps over first.
///
/// # Safety
/// Same contract as `mmap(2)`.
pub unsafe fn mmap(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    if flags & MAP_FIXED == 0 {
        // SAFETY: the caller's contract.
        return unsafe { mmap_now(addr, len, prot, flags, fd, offset) };
    }
    // A mapping over memory discards it: it waits for the system calls in
    // flight on the range ([`InFlight`]), before the userfaultfd's lock is
    // taken: a call in flight may be waiting on a fill, which takes that
    // lock.
    let _discard = discard_waiting(addr as usize, len.div_ceil(PAGE).saturating_mul(PAGE));
    // SAFETY: the caller's contract.
    crate::wick_uffd::unmapping(addr as u64, len as u64, || unsafe { mmap_now(addr, len, prot, flags, fd, offset) })
}

/// [`mmap`] once the memory it maps over is out of any userfaultfd
/// registration's reach and no system call in flight copies it.
///
/// # Safety
/// Same contract as `mmap(2)`.
unsafe fn mmap_now(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    wick_mm::check_exec(prot);
    let ty = flags & (MAP_SHARED | MAP_PRIVATE);
    if len == 0 || offset < 0 || (ty != MAP_SHARED && ty != MAP_PRIVATE) || win_prot(prot).is_none()
    {
        return fail(crate::EINVAL, MAP_FAILED);
    }
    if flags & MAP_HUGETLB != 0 {
        return match map_large(addr, len, prot, flags) {
            Ok(p) => p,
            Err(e) => fail(e, MAP_FAILED),
        };
    }
    let anon = flags & MAP_ANONYMOUS != 0;
    #[allow(clippy::cast_sign_loss)]
    let offset_u = offset as usize;
    if !anon && !offset_u.is_multiple_of(PAGE) {
        return fail(crate::EINVAL, MAP_FAILED);
    }
    // Windows maps a view of a file from a 64 KiB boundary of the file. A
    // shared mapping from a page between those starts the view at the
    // boundary below, `lead` bytes earlier, which are left unmapped for the
    // caller; with `MAP_FIXED` those bytes would cover the caller's memory
    // before `addr`, so that is refused.
    let lead = if !anon && ty == MAP_SHARED {
        offset_u % GRANULE
    } else {
        0
    };
    if lead != 0 && flags & MAP_FIXED != 0 {
        return fail(crate::EINVAL, MAP_FAILED);
    }
    let len = len.div_ceil(PAGE) * PAGE;
    let mut t = table().lock().unwrap();
    let base = if flags & MAP_FIXED != 0 {
        let base = addr as usize;
        if !base.is_multiple_of(PAGE) {
            return fail(crate::EINVAL, MAP_FAILED);
        }
        // A new mapping, without the old one's `MADV_HUGEPAGE`, as Linux's
        // new VMA has no `VM_HUGEPAGE`.
        set_grain(base, len, 0);
        // Anonymous private memory over part of one private allocation, as
        // Firecracker does to plug and unplug memory slots: the old pages are
        // dropped in place. Accessible memory is recommitted zero-filled;
        // `PROT_NONE` stays decommitted (no memory, no commit charge) and is
        // committed again by an `mprotect` that allows access (lazy
        // memory: at its first access after that, [`protect_lazy`]).
        if anon && ty == MAP_PRIVATE {
            let inside = t
                .range(..=base)
                .next_back()
                .filter(|(b, r)| {
                    matches!(r.kind, Kind::Private { .. })
                        && **b + r.len >= base + len
                        && (**b != base || r.len != len)
                })
                .map(|(b, _)| *b);
            if let Some(b) = inside {
                // Cleared first: a bit set after that is a page committed
                // since, which the hint must not lose.
                touched_mark(base, len, false);
                // SAFETY: decommits part of our allocation.
                unsafe { VirtualFree(base as *mut c_void, len, MEM_DECOMMIT) };
                let r = t.get_mut(&b).unwrap();
                if prot == PROT_NONE {
                    ranges_add(&mut r.noaccess, base - b, len);
                    lazy_remove(base, len);
                } else {
                    // Lazy memory stays lazy: zero pages at the next access.
                    if r.lazy && flags & MAP_NORESERVE != 0 {
                        lazy_add(base, len, win_prot(prot).unwrap());
                    } else if !commit(base, len, win_prot(prot).unwrap(), false) {
                        return fail(crate::ENOMEM, MAP_FAILED);
                    }
                    ranges_remove(&mut r.noaccess, base - b, len);
                }
                r.remove_hole(base - b, len);
                return base as *mut c_void;
            }
        }
        if let Err(e) = make_placeholder(&mut t, base, base + len) {
            return fail(e, MAP_FAILED);
        }
        base
    } else {
        // A free hint is taken as it is, as Linux takes it before any
        // alignment (v6.12 mm/huge_memory.c :1102 to :1107); then an
        // anonymous private mapping of a multiple of 2 MiB goes on a 2 MiB
        // boundary ([`new_placeholder_aligned`]), lazy (`MAP_NORESERVE`) or
        // not, as its placement comes before its memory; `MAP_HUGETLB`'s
        // large pages are placed apart ([`map_large`]), on their own
        // boundary ("The size and alignment must be a multiple of the
        // large-page minimum", Learn, Large-Page Support).
        let hint = addr as usize;
        let p = (hint != 0 && lead == 0 && hint.is_multiple_of(GRANULE))
            .then(|| new_placeholder(hint, len))
            .flatten()
            .or_else(|| (anon && ty == MAP_PRIVATE && len.is_multiple_of(HUGE_PAGE)).then(|| new_placeholder_aligned(len)).flatten())
            .or_else(|| new_placeholder(0, lead + len));
        let Some(p) = p else {
            return fail(crate::ENOMEM, MAP_FAILED);
        };
        t.insert(p, Region::new(lead + len, Kind::Placeholder));
        p
    };
    #[allow(clippy::cast_possible_wrap)]
    match fill(&mut t, base, lead + len, prot, flags, fd, offset - lead as i64) {
        Ok(()) if lead != 0 => {
            t.get_mut(&base).unwrap().add_hole(0, lead);
            (base + lead) as *mut c_void
        }
        Ok(()) => base as *mut c_void,
        Err(e) => {
            if flags & MAP_FIXED == 0 {
                release(&mut t, base);
            }
            fail(e, MAP_FAILED)
        }
    }
}

/// `munmap`. The memory leaves any userfaultfd registration in the same
/// step (`wick_uffd::unmapping`), as Linux's registration goes with the vma.
///
/// # Safety
/// Same contract as `munmap(2)`.
pub unsafe fn munmap(addr: *mut c_void, len: size_t) -> c_int {
    // SAFETY: the caller's contract.
    crate::wick_uffd::unmapping(addr as u64, len as u64, || unsafe { munmap_now(addr, len) })
}

/// [`munmap`] once the memory is out of any userfaultfd registration's
/// reach.
///
/// # Safety
/// Same contract as `munmap(2)`.
unsafe fn munmap_now(addr: *mut c_void, len: size_t) -> c_int {
    let start = addr as usize;
    if !start.is_multiple_of(PAGE) || len == 0 {
        return fail(crate::EINVAL, -1);
    }
    let end = start + len.div_ceil(PAGE) * PAGE;
    let mut t = table().lock().unwrap();
    // Large pages go back whole: refused before anything changes.
    for b in overlapping(&t, start, end) {
        let r = &t[&b];
        if matches!(r.kind, Kind::Large { .. }) && (start > b || end < b + r.len) {
            return fail(crate::EINVAL, -1);
        }
    }
    if !carve(&mut t, start, end) {
        return fail(crate::EINVAL, -1);
    }
    set_grain(start, end - start, 0);
    for b in overlapping(&t, start, end) {
        let r = &t[&b];
        let (s, e) = (start.max(b), end.min(b + r.len));
        if s == b && e == b + r.len {
            if !release(&mut t, b) && t.contains_key(&b) {
                return refused_unmap(b);
            }
            continue;
        }
        match r.kind {
            Kind::Placeholder | Kind::Large { .. } => unreachable!("carved or refused"),
            Kind::Private { .. } => {
                touched_mark(s, e - s, false);
                // SAFETY: decommits part of our allocation.
                unsafe { VirtualFree(s as *mut c_void, e - s, MEM_DECOMMIT) };
                lazy_remove(s, e - s);
            }
            Kind::View { .. } => {
                if r.lazy || released_overlaps(s, e) {
                    // Its pages not committed fault already; the committed
                    // ones are made to (Windows protects no page that is only
                    // reserved). A discarded page's stays unopened.
                    lazy_remove(s, e - s);
                    released_forget(s, e - s);
                    protect_committed(s, e, PAGE_NOACCESS);
                } else {
                    either_side(s, e - s, view_cut(b, r.len, &r.kind), |a, n| protect(a, n, PAGE_NOACCESS));
                }
            }
        }
        let r = t.get_mut(&b).unwrap();
        r.add_hole(s - b, e - s);
        if r.all_holes() && !release(&mut t, b) && t.contains_key(&b) {
            return refused_unmap(b);
        }
    }
    0
}

/// `munmap`'s end when Windows refused the first view of the chunk at `b`
/// ([`release`]): the chunk is as it was, `EINVAL`, said in a line; the
/// regions before it in the range are unmapped. Linux's `munmap` changes
/// nothing or all, its refusals all before it unmaps anything (v6.1
/// mm/mmap.c, `do_mas_align_munmap`: its failures at :2331 to :2375,
/// before "Point of no return" at :2403); this differs from it only here,
/// where Windows refused the unmap of a view of our own, which it should
/// never do.
fn refused_unmap(b: usize) -> c_int {
    // SAFETY: plain call.
    let err = unsafe { GetLastError() };
    say_at_the_limit(format_args!("wick: munmap: Windows refused the unmap of the chunk at {b:#x} (error {err}): it stays mapped, EINVAL"));
    fail(crate::EINVAL, -1)
}

/// `mprotect`.
///
/// # Safety
/// Same contract as `mprotect(2)`.
pub unsafe fn mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> c_int {
    wick_mm::check_exec(prot);
    let start = addr as usize;
    let Some(wprot) = win_prot(prot) else {
        return fail(crate::EINVAL, -1);
    };
    if !start.is_multiple_of(PAGE) {
        return fail(crate::EINVAL, -1);
    }
    let end = start + len.div_ceil(PAGE) * PAGE;
    if !covered(&table().lock().unwrap(), start, end) {
        return fail(crate::ENOMEM, -1);
    }
    // Registered userfaultfd memory keeps each page's protection in its
    // range, given to its pages that hold memory and to its missing ones
    // when they are filled (`wick_uffd::protecting`); the spans done are
    // left alone here. The rest is changed under the userfaultfd's lock, or
    // counted as a change without it, so that no register takes the memory
    // in between; that lock comes before the table.
    crate::wick_uffd::protecting(start as u64, end as u64, prot & PROT_READ != 0, prot & PROT_WRITE != 0, wprot, |registered| match registered {
        Ok(done) => mprotect_rest(start, end, prot, wprot, &done),
        Err(errno) => fail(errno, -1),
    })
}

/// [`mprotect`] of `[start, end)` past the registered spans `registered`.
fn mprotect_rest(start: usize, end: usize, prot: c_int, wprot: PAGE_PROTECTION_FLAGS, registered: &[(u64, u64)]) -> c_int {
    let mut t = table().lock().unwrap();
    if !covered(&t, start, end) {
        return fail(crate::ENOMEM, -1);
    }
    if prot != PROT_NONE && !carve(&mut t, start, end) {
        return fail(crate::ENOMEM, -1);
    }
    for b in overlapping(&t, start, end) {
        let r = &t[&b];
        let (rs, re) = (start.max(b), end.min(b + r.len));
        match r.kind {
            Kind::Placeholder => {
                if prot != PROT_NONE {
                    if !commit(b, r.len, wprot, true) {
                        return fail(crate::ENOMEM, -1);
                    }
                    t.get_mut(&b).unwrap().kind = Kind::Private { file: None };
                }
            }
            Kind::Large { page, wprot: old, .. } => {
                if !(rs - b).is_multiple_of(page) || !(re - b).is_multiple_of(page) {
                    return fail(crate::EINVAL, -1);
                }
                // Windows changes no large page's protection (`Kind::Large`):
                // only the protection it has is granted.
                if old != wprot {
                    return fail(crate::EACCES, -1);
                }
            }
            Kind::Private { .. } | Kind::View { .. } => {
                if !r.mapped_in(rs - b, re - rs) {
                    return fail(crate::ENOMEM, -1);
                }
                for (s, e) in spans_outside(rs, re, registered) {
                    // Lazy memory stays lazy: its pages not committed get the
                    // protection when they are.
                    if t[&b].lazy || released_overlaps(s, e) {
                        if !protect_lazy(&mut t, b, s, e, wprot) {
                            return fail(crate::EACCES, -1);
                        }
                        continue;
                    }
                    let r = &t[&b];
                    // A chunk's commits and protections, a view at a time.
                    let cut = view_cut(b, r.len, &r.kind);
                    let decommitted = ranges_within(&r.noaccess, s - b, e - s);
                    if prot != PROT_NONE {
                        // Mapped `PROT_NONE` parts get their (zero) pages now.
                        for &(o, l) in &decommitted {
                            if !either_side(b + o, l, cut, |a, n| commit(a, n, wprot, false)) {
                                return fail(crate::ENOMEM, -1);
                            }
                        }
                        let r = t.get_mut(&b).unwrap();
                        ranges_remove(&mut r.noaccess, s - b, e - s);
                        if !either_side(s, e - s, cut, |a, n| protect(a, n, wprot)) {
                            return fail(crate::EACCES, -1);
                        }
                    } else {
                        // Decommitted parts already fault; protect the rest.
                        let mut at = s;
                        for (o, l) in decommitted.into_iter().chain([(e - b, 0)]) {
                            if b + o > at && !either_side(at, b + o - at, cut, |a, n| protect(a, n, wprot)) {
                                return fail(crate::EACCES, -1);
                            }
                            at = b + o + l;
                        }
                    }
                }
            }
        }
    }
    0
}

/// The parts of `[s, e)` outside every span of `done` (start, length).
fn spans_outside(s: usize, e: usize, done: &[(u64, u64)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = s;
    let mut inside: Vec<(usize, usize)> = done
        .iter()
        .map(|&(a, l)| (a as usize, (a + l) as usize))
        .filter(|&(a, z)| a < e && z > s)
        .collect();
    inside.sort_unstable();
    for (a, z) in inside {
        if a > at {
            out.push((at, a));
        }
        at = at.max(z);
    }
    if at < e {
        out.push((at, e));
    }
    out
}

/// Moves the anonymous private mapping `[start, start + len)` (all of one
/// mapping) into a pagefile-backed section mapped at the same address, and
/// maps the section a second time: the alias, returned, through which
/// `wick_uffd` fills pages. The pages `resident` marks (one byte per page,
/// bit 0) keep their content; the others read as zeros.
///
/// With the exception handler (as anonymous shared memory, [`fill`]) the
/// section is reserved (`SEC_RESERVE`, the second value returned), one per
/// [`UFFD_CHUNK`] ([`uffd_alias_chunked`]), and charged ([`Charge`], one
/// registered for each chunk's view): the resident
/// pages are committed here with their charge, and every other page when
/// it is filled ([`uffd_commit`]), as Linux charges the page a
/// `UFFDIO_COPY` allocates to the memory cgroup (v6.1 mm/userfaultfd.c,
/// `mcopy_atomic_pte`: `mem_cgroup_charge` at :205; at the limit the memory
/// cgroup kills the VMM, as a fill here still refused after the reclaim
/// ends it: [`fill_out_of_memory`]).
/// Before, the whole section was committed here and charged to no job. A
/// resident page is charged before the private page it is copied from is
/// freed, so it counts twice for that moment.
///
/// The mapping is closed to writes for the move ([`close_for_the_move`]):
/// its read-write committed runs are made read-only before the copy, so
/// that no write lands in a private page after it is copied (it would be
/// lost with the allocation). The caller (`wick_uffd`'s register) has the
/// mapping marked moving meanwhile, so a thread whose write faults on it,
/// or whose access faults in the gap while the mapping is a placeholder,
/// waits and runs again on the views, and has claimed it against system
/// calls' copies ([`claim_move`]), which no exception reaches. A failure
/// before the private allocation is given back gives its runs their
/// protection back ([`reopen_after_the_move`], which ends the process if
/// it cannot); one after it leaves a placeholder, which holds no memory to
/// reopen.
///
/// `pages` holds a byte a page, whose bits 1 and 2 the caller set
/// (`uffd_protections`); bit 0 is set here for each page in the working
/// set, the pages copied, and read only once the mapping is closed: from
/// then on a write to a committed page faults and waits, and a lazy page's
/// first touch faults and waits, so no page takes data after its residency
/// is read. Read before (as it was), a write in between to a committed page
/// not in the working set, or a first touch of a lazy page, made a page
/// that was taken as missing and not copied, and the write was lost
/// (`test_a_write_made_as_a_register_starts_its_move_is_kept`).
///
/// A page holds memory if it is in the working set, or committed, readable
/// and not all zeros though out of it (trimmed to the pagefile or the
/// standby list: [`written_out_of_the_working_set`] reads it once); in the
/// registered range any other page is missing, and outside it (the rest of
/// the mapping, in no registration) it reads zeros at its first access. So
/// a page that holds data is never missing, as Linux's register takes as
/// missing only a page with no pte (v6.1 mm/memory.c `handle_pte_fault`
/// :4950 to :4952, `do_anonymous_page`'s `userfaultfd_missing` at :4103),
/// never a swapped one, whose pte holds its swap entry (:4957 to :4958,
/// `do_swap_page`). What remains: a page out of the working set that
/// cannot be read (`PROT_NONE`) is taken as missing (opening it for the
/// read would let another thread read it meanwhile), and one that holds
/// only zeros is taken as never touched, which reads the same.
pub(crate) fn uffd_alias(start: usize, len: usize, pages: &mut [u8]) -> Result<(usize, bool), c_int> {
    let mut t = table().lock().unwrap();
    match t.get(&start) {
        Some(r)
            if r.len == len
                && matches!(r.kind, Kind::Private { file: None })
                && r.holes.is_empty()
                && r.noaccess.is_empty() => {}
        _ => return Err(crate::EINVAL),
    }
    #[cfg(test)]
    run_hook(&NARROW_HOOK);
    let narrowed = close_for_the_move(start, len).ok_or(crate::ENOMEM)?;
    if !working_set_bits(start, pages) {
        reopen_after_the_move(&narrowed);
        return Err(crate::ENOMEM);
    }
    #[cfg(test)]
    for at in OUT_OF_THE_WORKING_SET.lock().unwrap().drain(..) {
        if at >= start && at < start + len {
            pages[(at - start) / PAGE] &= !1;
        }
    }
    written_out_of_the_working_set(start, pages);
    let moved = uffd_alias_closed(&mut t, start, len, pages);
    // The private allocation is still there if the move failed before it
    // was given back; after, the table holds placeholders there.
    if moved.is_err() && t.get(&start).is_some_and(|r| matches!(r.kind, Kind::Private { .. })) {
        reopen_after_the_move(&narrowed);
    }
    moved
}

/// Tests: the private allocation's release in [`uffd_alias`]'s move taken
/// as refused, once (the move fails with its memory still there), and the
/// protection [`reopen_after_the_move`] gives back taken as refused, once.
#[cfg(test)]
pub(crate) static MOVE_RELEASE_REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(crate) static REOPEN_REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// [`uffd_alias`]'s release of the private allocation as a placeholder:
/// whether it was made.
fn release_for_the_move(start: usize, len: usize) -> bool {
    #[cfg(test)]
    if MOVE_RELEASE_REFUSED.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return false;
    }
    // SAFETY: gives the private allocation back as a placeholder.
    unsafe { VirtualFree(start as *mut c_void, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) != 0 }
}

/// The private anonymous mapping that holds all of `[start, start + len)`,
/// as its start and length: the memory a register of that part moves into
/// its sections whole ([`uffd_alias`] takes a whole mapping), as Linux's
/// register splits the vma and leaves the rest of it as it was. `None` if
/// the part is not inside one such mapping (two mappings, a view, a file's
/// memory, a placeholder), which the register refuses as before.
pub(crate) fn uffd_mapping_of(start: usize, len: usize) -> Option<(usize, usize)> {
    let t = table().lock().unwrap();
    let b = *overlapping(&t, start, start + len).first()?;
    let r = &t[&b];
    (b <= start && start + len <= b + r.len && matches!(r.kind, Kind::Private { file: None })).then_some((b, r.len))
}

/// Sets bit 0 of `pages[i]` (page `i` from `start`) for each page that is
/// not in the working set (bit 0 clear) but committed,
/// readable (bit 1 clear, no `PAGE_GUARD`) and not all zeros: a page that
/// holds data the working set does not show (trimmed to the pagefile or the
/// standby list), which a read brings back. A page never touched reads as
/// zeros, as does one whose data is zeros, and is left clear: missing in
/// the registered range, zeros at its next access outside it. One read of
/// each such page, counted for the tests ([`PAGES_READ_AT_A_MOVE`]); a page
/// read is brought into the working set until the private allocation is
/// given back. Under the region table's lock, with the mapping closed to
/// writes ([`uffd_alias`]).
fn written_out_of_the_working_set(start: usize, pages: &mut [u8]) {
    let end = start + pages.len() * PAGE;
    let mut at = start;
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return;
        }
        let run_end = (mbi.BaseAddress as usize + mbi.RegionSize).min(end);
        let readable = mbi.State == MEM_COMMIT && mbi.Protect & PAGE_GUARD == 0 && !matches!(mbi.Protect & 0xff, 0 | PAGE_NOACCESS | PAGE_EXECUTE);
        if readable {
            for a in (at..run_end).step_by(PAGE) {
                let i = (a - start) / PAGE;
                if pages[i] & 1 != 0 || pages[i] & 2 != 0 {
                    continue;
                }
                #[cfg(test)]
                PAGES_READ_AT_A_MOVE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // SAFETY: a committed, readable page of our mapping.
                let page = unsafe { std::slice::from_raw_parts(a as *const u64, PAGE / 8) };
                if page.iter().any(|&w| w != 0) {
                    pages[i] |= 1;
                }
            }
        }
        at = run_end;
    }
}

/// Tests: pages [`uffd_alias`]'s next move takes as out of the working set
/// whatever the query said (as trimmed to the pagefile), taken as it runs.
#[cfg(test)]
pub(crate) static OUT_OF_THE_WORKING_SET: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Tests: the pages [`written_out_of_the_working_set`] read.
#[cfg(test)]
pub(crate) static PAGES_READ_AT_A_MOVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Tests: a function run inside [`uffd_alias`] once the resident pages are
/// copied and before the private allocation is given back (a write landing
/// in a private page there would be lost with it), as an `fn()` in a
/// `usize`, 0 for none; taken as it runs.
#[cfg(any(test, feature = "wick-test-hooks"))]
pub(crate) static ALIAS_HOOK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Tests: as [`ALIAS_HOOK`], run inside [`uffd_alias`] right before the
/// mapping is closed for the move (and its residency read).
#[cfg(test)]
pub(crate) static NARROW_HOOK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(any(test, feature = "wick-test-hooks"))]
fn alias_hook() {
    run_hook(&ALIAS_HOOK);
}

/// Runs the `fn()` in `hook`, if any, and takes it.
#[cfg(any(test, feature = "wick-test-hooks"))]
fn run_hook(hook: &std::sync::atomic::AtomicUsize) {
    let hook = hook.swap(0, std::sync::atomic::Ordering::SeqCst);
    if hook != 0 {
        // SAFETY: only `fn()` values are stored.
        unsafe { core::mem::transmute::<usize, fn()>(hook)() };
    }
}

/// Makes the committed read-write runs of `[start, start + len)` read-only
/// (an executable one executable and read-only), keeping every other
/// protection, `PROT_NONE` and read-only ones included, as it is: a
/// [`uffd_alias`] copy reads the pages it copies and opens none. The runs
/// changed, with their protection before, or `None` with nothing changed
/// if a query or a change was refused: the runs narrowed until then get
/// their protection back ([`reopen_after_the_move`]), and a refusal of that
/// ends the process, named.
fn close_for_the_move(start: usize, len: usize) -> Option<Vec<(usize, usize, PAGE_PROTECTION_FLAGS)>> {
    let mut narrowed = Vec::new();
    let end = start + len;
    let mut at = start;
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            reopen_after_the_move(&narrowed);
            return None;
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(end) - at;
        let read_only = match mbi.Protect & 0xff {
            PAGE_READWRITE => Some(PAGE_READONLY),
            PAGE_EXECUTE_READWRITE => Some(PAGE_EXECUTE_READ),
            _ => None,
        };
        if let (MEM_COMMIT, Some(base)) = (mbi.State, read_only) {
            let mut old = 0;
            // SAFETY: narrows the protection of committed pages of ours.
            if unsafe { VirtualProtect(at as *mut c_void, run, (mbi.Protect & !0xff) | base, &mut old) } == 0 {
                reopen_after_the_move(&narrowed);
                return None;
            }
            narrowed.push((at, run, mbi.Protect));
        }
        at += run;
    }
    Some(narrowed)
}

/// Gives the runs [`close_for_the_move`] narrowed their protection back,
/// the private allocation still there. A refusal ends the process at once,
/// naming the run, as macOS's reclaim does when a chunk cannot get its
/// protection back (`wick_owned::restore`): the run would stay read-only
/// while the process holds it read-write, so a later write would fault
/// outside any move and end the process far from the cause, and a system
/// call's copy into it would fail or come back short.
fn reopen_after_the_move(narrowed: &[(usize, usize, PAGE_PROTECTION_FLAGS)]) {
    for &(at, run, prot) in narrowed {
        #[cfg(test)]
        let refused = REOPEN_REFUSED.swap(false, std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let refused = false;
        let mut old = 0;
        // SAFETY: committed pages of our private allocation, which the move
        // narrowed.
        if refused || unsafe { VirtualProtect(at as *mut c_void, run, prot, &mut old) } == 0 {
            // SAFETY: plain call.
            let err = if refused { 0 } else { unsafe { GetLastError() } };
            std::eprintln!(
                "wick: userfaultfd: a register's move could not give its pages {at:#x}+{run:#x} back their protection {prot:#x} \
                 (error {err}): they would stay read-only while the process holds them writable, so the process ends"
            );
            std::process::abort();
        }
    }
}

/// [`uffd_alias`]'s move, the mapping closed to writes.
fn uffd_alias_closed(t: &mut Table, start: usize, len: usize, resident: &[u8]) -> Result<(usize, bool), c_int> {
    #[cfg(test)]
    let unreserved = UFFD_UNRESERVED.load(std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(test))]
    let unreserved = false;
    if exception_handler() && !unreserved {
        return uffd_alias_chunked(t, start, len, resident).map(|alias| (alias, true));
    }
    let hi = u32::try_from((len as u64) >> 32).unwrap();
    #[allow(clippy::cast_possible_truncation)]
    let lo = len as u32;
    let reserved = false;
    let reserve = 0;
    // SAFETY: creates a pagefile-backed section.
    let s = unsafe {
        CreateFileMappingW(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE | reserve, hi, lo, std::ptr::null())
    };
    if s.is_null() {
        return Err(crate::ENOMEM);
    }
    let section = Arc::new(Owned(s));
    let view = |base: usize, flags| {
        // SAFETY: maps our section, anywhere (`base` 0) or over a placeholder.
        unsafe {
            MapViewOfFile3(
                s,
                proc(),
                base as *const c_void,
                0,
                len,
                flags,
                PAGE_READWRITE,
                std::ptr::null_mut(),
                0,
            )
        }
        .Value as usize
    };
    let alias = view(0, 0);
    if alias == 0 {
        return Err(crate::ENOMEM);
    }
    let unmap = |a: usize| {
        // SAFETY: unmaps a view made here.
        unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void }, 0) };
    };
    let paid = if reserved {
        let Some(c) = charge_add(start, len) else {
            unmap(alias);
            return Err(crate::ENOMEM);
        };
        Some(c)
    } else {
        None
    };
    let mut i = 0;
    while i < resident.len() {
        if resident[i] & 1 == 0 {
            i += 1;
            continue;
        }
        let first = i;
        while i < resident.len() && resident[i] & 1 != 0 {
            i += 1;
        }
        let (off, n) = (first * PAGE, (i - first) * PAGE);
        // The charge of the run (registered at `start`), then the section's
        // pages through the alias.
        if reserved && (!charge(start + off, n) || !commit_now(alias + off, n, PAGE_READWRITE, false)) {
            charge_remove(start);
            unmap(alias);
            return Err(crate::ENOMEM);
        }
        // SAFETY: resident pages of the mapping, into the alias.
        unsafe { std::ptr::copy_nonoverlapping((start + off) as *const u8, (alias + off) as *mut u8, n) };
    }
    #[cfg(any(test, feature = "wick-test-hooks"))]
    alias_hook();
    if !release_for_the_move(start, len) {
        if reserved {
            charge_remove(start);
        }
        unmap(alias);
        return Err(crate::EINVAL);
    }
    if view(start, MEM_REPLACE_PLACEHOLDER) != start {
        // The address space stays reserved; the memory is gone.
        t.get_mut(&start).unwrap().kind = Kind::Placeholder;
        if reserved {
            charge_remove(start);
        }
        unmap(alias);
        return Err(crate::ENOMEM);
    }
    let r = t.get_mut(&start).unwrap();
    r.kind = Kind::View {
        _section: Some(section),
        uffd: true,
        file: None,
        charge: paid,
        alias: None,
    };
    // A section is committed when it is touched, as the userfaultfd fills it.
    if r.lazy {
        lazy_remove(start, len);
        touched_remove(start);
        r.lazy = false;
    }
    Ok((alias, reserved))
}

/// Calls `gone(page)` for each page of `[s, e)` (page aligned) that is no
/// longer the memory a userfaultfd range registered there: not in a view
/// that [`uffd_alias`] made (or [`uffd_swap_chunk`] or [`uffd_move_chunk`]
/// put in its place), or in a hole of one. Memory mapped anew at the
/// address (`MAP_FIXED`, or `mmap` in a hole) is never such a view: only
/// those views are marked `uffd` ([`Kind::View`]). Under the
/// region table's lock; allocates only the list of the regions.
pub(crate) fn uffd_pages_gone(s: usize, e: usize, mut gone: impl FnMut(usize)) {
    let t = table().lock().unwrap();
    let mut at = s;
    for b in overlapping(&t, s, e) {
        let r = &t[&b];
        while at < b.min(e) {
            gone(at);
            at += PAGE;
        }
        let ours = matches!(r.kind, Kind::View { uffd: true, .. });
        let end = (b + r.len).min(e);
        while at < end {
            if !ours || !r.mapped_in(at - b, PAGE) {
                gone(at);
            }
            at += PAGE;
        }
    }
    while at < e {
        gone(at);
        at += PAGE;
    }
}

/// The protection `mprotect` gave each page of `[start, start + len)`, the
/// private memory a register is about to take ([`uffd_alias`] maps its view
/// read-write): bit 1 of `out[i]` set if page `i` denies reads
/// (`PAGE_NOACCESS`), bit 2 if it denies writes (that or `PAGE_READONLY`).
/// A committed page's is its own (`VirtualQuery`); a lazy page not yet
/// committed has the one its allocation records ([`LAZY`]).
pub(crate) fn uffd_protections(start: usize, len: usize, out: &mut [u8]) {
    let lazy = lazy_within(start, len);
    let end = start + len;
    let mut at = start;
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return;
        }
        let run_end = (mbi.BaseAddress as usize + mbi.RegionSize).min(end);
        for page in (at..run_end).step_by(PAGE) {
            let prot = if mbi.State == MEM_COMMIT {
                mbi.Protect & 0xff
            } else {
                lazy.iter().find(|&&(s, n, _)| page >= s && page < s + n).map_or(PAGE_READWRITE, |l| l.2)
            };
            let i = (page - start) / PAGE;
            if prot == PAGE_NOACCESS {
                out[i] |= 2 | 4;
            } else if prot == PAGE_READONLY {
                out[i] |= 4;
            }
        }
        at = run_end;
    }
}

/// The grain of a userfaultfd range's reserved section ([`uffd_alias`]):
/// one section per 2 MiB chunk, the block a balloon's free page reporting
/// gives back on x86 (v6.1 mm/page_reporting.c, `pageblock_order`), so that
/// a chunk discarded whole can give its section commit back
/// ([`uffd_swap_chunk`]), which a section's pages cannot (SECTREC-h).
pub(crate) const UFFD_CHUNK: usize = 2 << 20;

/// Where a chunk of `len` bytes (a [`UFFD_CHUNK`], or a range's shorter
/// last one) is split into the two views that map it, in its guest view's
/// placeholder, its alias's and its section: the offset of the second,
/// half of `len` rounded down to the allocation granularity, as a view's
/// offset in its section must be ("a multiple of the allocation
/// granularity", Learn, MapViewOfFile3); 0 for a chunk of less than two
/// granules, mapped as one view. While one view is out (unmapped, its
/// placeholder kept), the other still maps the 2 MiB region and the 1 GiB
/// they share, so the unmap gives back no page table and the map needs
/// none (VIEWCOST: a view's unmap gives back the page table of each 2 MiB
/// region only it maps, and a page-directory page of each 1 GiB).
pub(crate) const fn chunk_half(len: usize) -> usize {
    len / 2 / GRANULE * GRANULE
}

/// The views of the chunk at `at` of `len` bytes ([`chunk_half`]): (address,
/// offset in its section, length), the first and, if there is one, the
/// second.
fn chunk_views(at: usize, len: usize) -> impl Iterator<Item = (usize, usize, usize)> {
    let h = chunk_half(len);
    let first = if h == 0 { len } else { h };
    [(at, 0, first), (at + h, h, len - h)].into_iter().take(if h == 0 { 1 } else { 2 })
}

/// Whether a region of this kind is a chunk of a reserved userfaultfd range
/// ([`uffd_alias_chunked`]): mapped as the views [`chunk_views`] gives.
fn is_chunk(kind: &Kind) -> bool {
    matches!(kind, Kind::View { _section: None, uffd: true, charge: Some(_), file: None, .. })
}

/// Where the region at `b` of `len` bytes and `kind` is split between two
/// views: `b` for none (a region that is no chunk, or a chunk of one view).
fn view_cut(b: usize, len: usize, kind: &Kind) -> usize {
    if is_chunk(kind) { b + chunk_half(len) } else { b }
}

/// Calls `f` with the part of `[a, a + n)` below `cut` and the part from it,
/// those that are not empty, in order, until one gives `false`; whether
/// every call gave `true`. A commit or a protection change is refused across
/// two views (each is an allocation of its own: "All pages in the specified
/// region must be within the same reserved region", Learn, VirtualProtect).
fn either_side(a: usize, n: usize, cut: usize, mut f: impl FnMut(usize, usize) -> bool) -> bool {
    if cut > a && cut < a + n { f(a, cut - a) && f(cut, a + n - cut) } else { f(a, n) }
}

/// Maps `section`'s views of the chunk at `at` of `len` bytes into their
/// placeholders ([`chunk_views`]); how many were mapped, in order.
fn map_chunk(section: &Owned, at: usize, len: usize) -> usize {
    chunk_views(at, len).take_while(|&(a, o, n)| view_into(section, a, o, n)).count()
}

/// Unmaps the views of the chunk at `at` of `len` bytes, in order, keeping
/// their placeholders if `keep`: whether they were. The first refused,
/// nothing changed. The second refused once the first is gone, the chunk
/// is half mapped, which no caller can undo (the first view's placeholder
/// cannot take its view back while the record of what it held is the
/// caller's) or account for: the VMM ends, named (review B1).
fn unmap_chunk(at: usize, len: usize, keep: bool) -> bool {
    let flags = if keep { MEM_PRESERVE_PLACEHOLDER } else { 0 };
    for (i, (a, _, _)) in chunk_views(at, len).enumerate() {
        #[cfg(test)]
        let refused = REFUSE_CHUNK_UNMAP.lock().unwrap().take_if(|&mut (c, v)| c == at && v == i).is_some();
        #[cfg(not(test))]
        let refused = false;
        // SAFETY: unmaps a view of our chunk.
        if refused || unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void }, flags) } == 0 {
            if i == 0 {
                return false;
            }
            // SAFETY: plain call.
            let err = if refused { 0 } else { unsafe { GetLastError() } };
            say_at_the_limit(format_args!(
                "wick: guest memory: the second view of the chunk at {at:#x} ({len:#x} bytes), at {a:#x}, could not be \
                 unmapped once its first was (error {err}): the VMM aborts"
            ));
            std::process::abort();
        }
    }
    true
}

/// Tests: the next unmap of view `.1` (0 or 1) of the chunk at `.0` is
/// refused ([`unmap_chunk`]), as if Windows refused it.
#[cfg(test)]
pub(crate) static REFUSE_CHUNK_UNMAP: Mutex<Option<(usize, usize)>> = Mutex::new(None);

/// [`unmap_chunk`] with the released ranges' records locked, the chunk's
/// pages forgotten in them once its views are gone: a first access
/// resolving one of them holds the lock from its check that the page is
/// committed to its protection, so the views stay while it does, and a
/// refused first unmap leaves the records as they were (with
/// [`released_forget`] before the unmap, a refusal left the chunk mapped
/// and its pending pages no longer pending). The table's lock is the
/// caller's, taken before the records'.
fn unmap_chunk_forgetting(at: usize, len: usize, keep: bool) -> bool {
    let mut records = (RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) != 0).then(|| RELEASED.lock().unwrap());
    if !unmap_chunk(at, len, keep) {
        return false;
    }
    if let Some(records) = records.as_mut() {
        forget_in(&mut records[..], at, len);
    }
    true
}

/// The placeholders of the chunk at `at` of `len` bytes, one per view
/// ([`chunk_views`]), made one again; whether they are.
fn coalesce_chunk(at: usize, len: usize) -> bool {
    #[cfg(test)]
    if REFUSE_COALESCE.lock().unwrap().take_if(|&mut c| c == at).is_some() {
        return false;
    }
    // SAFETY: coalesces our adjacent placeholders, the chunk's ("To coalesce
    // two placeholders", Learn, VirtualFree).
    chunk_half(len) == 0 || unsafe { VirtualFree(at as *mut c_void, len, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS) } != 0
}

/// Tests: the next coalesce of the chunk at this address is refused
/// ([`coalesce_chunk`]), as if Windows refused it.
#[cfg(test)]
pub(crate) static REFUSE_COALESCE: Mutex<Option<usize>> = Mutex::new(None);

/// A new reserved (`SEC_RESERVE`) pagefile-backed section of `len` bytes.
fn reserved_section(len: usize) -> Option<Owned> {
    let hi = u32::try_from((len as u64) >> 32).unwrap();
    #[allow(clippy::cast_possible_truncation)]
    let lo = len as u32;
    // SAFETY: creates a pagefile-backed section.
    let s = unsafe {
        CreateFileMappingW(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE | SEC_RESERVE, hi, lo, std::ptr::null())
    };
    (!s.is_null()).then(|| Owned(s))
}

/// Maps `len` bytes of `section` from `offset` into the placeholder of the
/// same size at `at`; whether it is.
fn view_into(section: &Owned, at: usize, offset: usize, len: usize) -> bool {
    // SAFETY: maps our section over our placeholder.
    let v = unsafe {
        MapViewOfFile3(
            section.0,
            proc(),
            at as *const c_void,
            offset as u64,
            len,
            MEM_REPLACE_PLACEHOLDER,
            PAGE_READWRITE,
            std::ptr::null_mut(),
            0,
        )
    };
    v.Value as usize == at
}

/// Splits the placeholder at `base` into the placeholders of `chunks`
/// (offset, len), in order: how many were split off (all of them but the
/// last when it is done).
fn split_into(base: usize, chunks: &[(usize, usize)]) -> usize {
    chunks
        .iter()
        .take(chunks.len().saturating_sub(1))
        .take_while(|&&(o, n)| {
            // SAFETY: splits our placeholder ("To split a placeholder into
            // two placeholders", Learn, VirtualFree).
            unsafe { VirtualFree((base + o) as *mut c_void, n, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) != 0 }
        })
        .count()
}

/// [`uffd_alias`] with the exception handler: the mapping moved into one
/// reserved section per [`UFFD_CHUNK`] (the last one shorter if the length
/// is not a multiple), each mapped as two views ([`chunk_views`]) into
/// placeholders of the mapping's and of the alias's, its handle closed then
/// (the views keep the section: "Mapped views of a file mapping object
/// maintain internal references to the object", Learn, CreateFileMappingW),
/// so no handle is held for it (UFFDCHUNK b, CI run 43528910212: 1 GiB as
/// 512 chunks, one view each, in 5.43 us a chunk, commit and paged pool as
/// one section's, handles +0). The alias is reserved on a 2 MiB boundary,
/// as Firecracker allocates guest memory (src/vmm/src/vstate/memory.rs,
/// `GUEST_MEMORY_ALIGNMENT`), so that each of its chunks fills its 2 MiB
/// region and its two views keep the region's page table between them.
/// Each chunk is a view of the table's, one region, with a charge of its
/// own ([`Charge`]). WHP maps the guest's range over the views in one call
/// (UFFDCHUNK a).
fn uffd_alias_chunked(t: &mut Table, start: usize, len: usize, resident: &[u8]) -> Result<usize, c_int> {
    use windows_sys::Win32::System::Memory::{MEM_ADDRESS_REQUIREMENTS, MEM_EXTENDED_PARAMETER, MemExtendedParameterAddressRequirements};
    // The move budget, charged at the first registration as a page filled
    // is: refused, the registration fails as one that cannot be charged.
    if !uffd_budget() {
        return Err(crate::ENOMEM);
    }
    let chunks: Vec<(usize, usize)> = (0..len).step_by(UFFD_CHUNK).map(|o| (o, UFFD_CHUNK.min(len - o))).collect();
    // Every view of every chunk: (offset in the range, offset in its
    // chunk's section, length).
    let views: Vec<(usize, usize, usize)> = chunks.iter().flat_map(|&(o, n)| chunk_views(o, n)).collect();
    let pieces: Vec<(usize, usize)> = views.iter().map(|&(o, _, n)| (o, n)).collect();
    // The chunk of each view.
    let chunk_of = |v: usize| views[v].0 / UFFD_CHUNK;
    #[cfg(test)]
    let at = ALIAS_AT.swap(0, std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(test))]
    let at = 0;
    // On a 2 MiB boundary, anywhere ("a power-of-2 alignment restriction for
    // new allocations", Learn, VirtualAlloc2); an address asked for (a
    // test's) takes no requirement ("any provided MEM_ADDRESS_REQUIREMENTS
    // structure must consist of all zeroes", ibid.).
    let mut need = MEM_ADDRESS_REQUIREMENTS {
        LowestStartingAddress: std::ptr::null_mut(),
        HighestEndingAddress: std::ptr::null_mut(),
        Alignment: if at == 0 { HUGE_PAGE } else { 0 },
    };
    let mut param: MEM_EXTENDED_PARAMETER = MEM_EXTENDED_PARAMETER::default();
    param.Anonymous1._bitfield = MemExtendedParameterAddressRequirements as u64;
    param.Anonymous2.Pointer = (&raw mut need).cast();
    // SAFETY: reserves address space of our own, as a placeholder, with the
    // requirement above, which outlives the call.
    let alias = unsafe {
        VirtualAlloc2(proc(), at as *const c_void, len, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, &raw mut param, 1)
    } as usize;
    if alias == 0 {
        return Err(crate::ENOMEM);
    }
    let mut sections = Vec::with_capacity(chunks.len());
    let mut charges = Vec::with_capacity(chunks.len());
    // Undoes the alias's views and placeholders (a placeholder not split
    // off is freed at its own start, a later view's) and the charges.
    let undo = |mapped: usize, charged: usize| {
        for (v, &(o, _, _)) in views.iter().enumerate() {
            // SAFETY: frees the alias's view or placeholder made here.
            unsafe {
                if v < mapped {
                    UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: (alias + o) as *mut c_void }, 0);
                } else {
                    VirtualFree((alias + o) as *mut c_void, 0, MEM_RELEASE);
                }
            }
        }
        for &(o, _) in &chunks[..charged] {
            charge_remove(start + o);
        }
    };
    if split_into(alias, &pieces) + 1 != pieces.len() {
        undo(0, 0);
        return Err(crate::ENOMEM);
    }
    let mut mapped = 0;
    for &(o, n) in &chunks {
        let Some(section) = reserved_section(n) else {
            undo(mapped, charges.len());
            return Err(crate::ENOMEM);
        };
        let views_here = chunk_views(o, n).count();
        let done = map_chunk(&section, alias + o, n);
        mapped += done;
        if done != views_here {
            undo(mapped, charges.len());
            return Err(crate::ENOMEM);
        }
        sections.push(section);
        let Some(c) = charge_add(start + o, n) else {
            undo(mapped, charges.len());
            return Err(crate::ENOMEM);
        };
        charges.push(c);
    }
    // The resident pages: their charge, then the section's pages through the
    // alias, a view at a time (a commit stays within one view), then their
    // content.
    let view_start = |off: usize| pieces.binary_search_by_key(&off, |&(o, _)| o).is_ok();
    let mut i = 0;
    while i < resident.len() {
        if resident[i] & 1 == 0 {
            i += 1;
            continue;
        }
        let first = i;
        while i < resident.len() && resident[i] & 1 != 0 && (i == first || !view_start(i * PAGE)) {
            i += 1;
        }
        let (off, n) = (first * PAGE, (i - first) * PAGE);
        if !charge(start + off, n) || !commit_now(alias + off, n, PAGE_READWRITE, false) {
            undo(mapped, charges.len());
            return Err(crate::ENOMEM);
        }
        // SAFETY: resident pages of the mapping, into the alias.
        unsafe { std::ptr::copy_nonoverlapping((start + off) as *const u8, (alias + off) as *mut u8, n) };
    }
    #[cfg(any(test, feature = "wick-test-hooks"))]
    alias_hook();
    if !release_for_the_move(start, len) {
        undo(mapped, charges.len());
        return Err(crate::EINVAL);
    }
    let r = t.remove(&start).unwrap();
    if r.lazy {
        lazy_remove(start, len);
        touched_remove(start);
    }
    // From here the private memory is gone: a failure leaves the range a
    // placeholder of the table's.
    let split = split_into(start, &pieces);
    let mut guest = 0;
    if split + 1 == pieces.len() {
        while guest < views.len() && view_into(&sections[chunk_of(guest)], start + views[guest].0, views[guest].1, views[guest].2) {
            guest += 1;
        }
    }
    if guest < views.len() {
        for &(o, _, _) in &views[..guest] {
            // SAFETY: unmaps a view made here, keeping its placeholder.
            unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: (start + o) as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) };
        }
        // SAFETY: coalesces the placeholders split here back into one.
        if split == 0 || unsafe { VirtualFree(start as *mut c_void, len, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS) } != 0 {
            t.insert(start, Region::new(len, Kind::Placeholder));
        } else {
            for (k, &(o, n)) in pieces.iter().enumerate().take(split + 1) {
                t.insert(start + o, Region::new(if k < split { n } else { len - o }, Kind::Placeholder));
            }
        }
        undo(mapped, charges.len());
        return Err(crate::ENOMEM);
    }
    drop(sections);
    for (&(o, n), c) in chunks.iter().zip(charges) {
        t.insert(start + o, Region::new(n, Kind::View { _section: None, uffd: true, file: None, charge: Some(c), alias: None }));
    }
    Ok(alias)
}

/// A chunk `[view, view + len)` of a registered userfaultfd range, all of it
/// discarded and missing (`wick_uffd::discarding`), whose alias is at
/// `alias`: a new, empty reserved section put in its place in both views,
/// so that the old one, and its commit, goes with its last view, and its
/// charge given back ([`uncharge`]), as Linux frees the pages. The views
/// keep their addresses: WHP follows the host's (UFFDCHUNK a, CI run
/// 43528910212: the guest read the new section with no remap, its writes
/// landed there and were in the dirty bitmap), and a vCPU's access while
/// a view is a placeholder is a memory access exit, which waits as for any
/// missing page. 8.7 us a swap (UFFDCHUNK b). `false`, nothing changed, if
/// the chunk is not one of [`uffd_alias`]'s, has a view alone in a 2 MiB
/// region of its range `[start, end)` ([`at_a_ranges_edge`], said in a
/// line), or no section can be made; a failure once a view is unmapped ends
/// the VMM, named, as a commit past the host's limit does ([`out_of_memory`]).
pub(crate) fn uffd_swap_chunk(view: usize, len: usize, alias: usize, (start, end): (usize, usize)) -> bool {
    let t = table().lock().unwrap();
    match t.get(&view) {
        Some(r)
            if r.len == len
                && r.holes.is_empty()
                && !r.lazy
                && matches!(r.kind, Kind::View { _section: None, uffd: true, charge: Some(_), file: None, alias: None }) => {}
        _ => return false,
    }
    if at_a_ranges_edge(view, len, alias, start, end) {
        edge_refused(view, "swapped for a new section at its discard", "its pages are discarded in place and keep their charge until it is unmapped");
        return false;
    }
    let Some(section) = reserved_section(len) else {
        return false;
    };
    // The chunk's alias's first view, unmapped keeping its placeholder: a
    // refusal changes nothing. The guest's views keep the old section until
    // they are swapped too.
    if !unmap_alias(alias, len) {
        return false;
    }
    if !swap_views(&section, view, alias, len, 2) {
        // SAFETY: plain call.
        out_of_memory(view, unsafe { GetLastError() });
    }
    drop(t);
    // Given back after the table's lock, with no page of the new section
    // committed between: the caller (`wick_uffd::discarding`) holds the
    // userfaultfd ranges' lock, which every fill of a page of a registered
    // range takes (UFFDIO_COPY, UFFDIO_ZEROPAGE, the unregister that would
    // make its pages released), and every page of the chunk is missing, so
    // a first access waits for the handler's fill rather than committing
    // one (as [`released_swap`]'s pending pages would; it gives the charge
    // back under the records' lock for that).
    uncharge(view, len);
    true
}

/// The move budget: one [`UFFD_CHUNK`] of private commit, `PAGE_NOACCESS`
/// and never touched, made at the first registration of a reserved
/// userfaultfd range ([`uffd_alias_chunked`]) and kept for the process. A
/// chunk's move ([`uffd_move_chunk`]) holds its live pages in two sections
/// for the copy's time, up to a chunk more of section commit; to the
/// jailer's count (overlay/jailer/platform/windows commit.rs: private
/// commit plus section commit, less the committed private `PAGE_NOACCESS`
/// memory that pays for sections, no more than the section commit) the
/// budget is cover for it, so the count does not rise during a move and a
/// VMM at its limit is not ended for a reclaim
/// (`test_the_jailers_count_does_not_rise_during_a_move`). The job charges
/// it once, at the registration: 2 MiB of memory.max as commit, no RAM (the
/// memory.max row).
static UFFD_BUDGET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Makes the move budget ([`UFFD_BUDGET`]) and the move slot
/// ([`MOVE_SLOT`]) if there are none; whether there are (the job may refuse
/// their commit). Called under the table's lock.
fn uffd_budget() -> bool {
    if UFFD_BUDGET.load(std::sync::atomic::Ordering::Acquire) == 0 {
        // SAFETY: a new allocation of our own, committed, never accessed.
        let b = unsafe {
            VirtualAlloc2(proc(), std::ptr::null(), UFFD_CHUNK, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS, std::ptr::null_mut(), 0)
        };
        if b.is_null() {
            return false;
        }
        UFFD_BUDGET.store(b as usize, std::sync::atomic::Ordering::Release);
    }
    MOVE_SLOT.load(std::sync::atomic::Ordering::Acquire) != 0 || SLOT_LOST.load(std::sync::atomic::Ordering::Acquire) || move_slot()
}

/// The move slot: a [`UFFD_CHUNK`] placeholder, 64 KiB past a 2 MiB boundary
/// so that it spans two 2 MiB regions, with an anchor beside it in each, a
/// reservation with one page committed (`PAGE_NOACCESS`, never touched),
/// made at the first registration of a reserved userfaultfd range
/// ([`uffd_budget`]) and kept for the process, outside the region table. A
/// move's view of its new section is mapped into it ([`slot_view`]) and
/// unmapped keeping it ([`slot_unmap`]): the anchors keep the two regions'
/// page tables (and the 1 GiB's page-directory page), so the map takes no
/// commit and the unmap gives none back (MAPCOST2 (b), Windows Server 2022
/// 20348: the anchors and placeholders +20 KiB once, each map and unmap +0,
/// where the same slot with no anchors took 12 KiB, MAPCOST2 (a), and a
/// view mapped anywhere 4: `test_a_moves_temporary_view_takes_no_commit`,
/// which asserts the 0 and failed so before the slot), and no commit of
/// another thread can take the room a move's map needs. One move at a time
/// uses it: a move holds the table's lock throughout. 0 for none: not made
/// yet, or out of use ([`SLOT_LOST`]).
static MOVE_SLOT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The move slot is out of use for the process: a move's view in it could
/// not be unmapped ([`slot_unmap`]), so it keeps that view's section. No
/// slot is made again and no chunk is moved after (each reclaim's move
/// refused, said in a line): a view of ours that would not unmap means
/// something is wrong that a second slot does not mend. Apart from
/// [`MOVE_SLOT`]'s 0 before the first registration makes it.
static SLOT_LOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The length of the slot's first placeholder: [`UFFD_CHUNK`], or a shorter
/// last chunk's length for its move, the rest of the slot a placeholder of
/// its own ([`slot_view`]). Under the table's lock.
static MOVE_SLOT_CUT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Makes the move slot ([`MOVE_SLOT`]): 4 MiB of placeholder on a 2 MiB
/// boundary, split into anchor A (64 KiB), the slot and anchor B, each anchor
/// reserved in its placeholder's place with a page committed (A's first, B's
/// last, so each lies in a 2 MiB region the slot spans). Whether it was
/// made; refused, nothing is left.
fn move_slot() -> bool {
    use windows_sys::Win32::System::Memory::{MEM_ADDRESS_REQUIREMENTS, MEM_EXTENDED_PARAMETER, MemExtendedParameterAddressRequirements};
    let mut need = MEM_ADDRESS_REQUIREMENTS { LowestStartingAddress: std::ptr::null_mut(), HighestEndingAddress: std::ptr::null_mut(), Alignment: HUGE_PAGE };
    let mut param: MEM_EXTENDED_PARAMETER = MEM_EXTENDED_PARAMETER::default();
    param.Anonymous1._bitfield = MemExtendedParameterAddressRequirements as u64;
    param.Anonymous2.Pointer = (&raw mut need).cast();
    let whole = 2 * UFFD_CHUNK;
    // SAFETY: reserves address space of our own, as a placeholder, with the
    // requirement above, which outlives the call.
    let g = unsafe { VirtualAlloc2(proc(), std::ptr::null(), whole, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, &raw mut param, 1) } as usize;
    if g == 0 {
        return false;
    }
    let slot = g + GRANULE;
    let b = slot + UFFD_CHUNK;
    // The pieces as they stand, (start, len), each freed whole if a step is
    // refused (a placeholder or a reservation alike: MEM_RELEASE, size 0).
    let mut pieces = [(g, whole), (0, 0), (0, 0)];
    let made = (|| {
        // SAFETY: splits our placeholder ("To split a placeholder into two
        // placeholders", Learn, VirtualFree).
        if unsafe { VirtualFree(g as *mut c_void, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
            return false;
        }
        pieces = [(g, GRANULE), (slot, whole - GRANULE), (0, 0)];
        // SAFETY: as above.
        if unsafe { VirtualFree(slot as *mut c_void, UFFD_CHUNK, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
            return false;
        }
        pieces = [(g, GRANULE), (slot, UFFD_CHUNK), (b, g + whole - b)];
        for (k, page) in [(0, g), (2, g + whole - PAGE)] {
            let (a, n) = pieces[k];
            // SAFETY: our placeholder made a reservation, then a page of it
            // committed, never touched.
            unsafe {
                if VirtualAlloc2(proc(), a as *const c_void, n, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_NOACCESS, std::ptr::null_mut(), 0).is_null() {
                    return false;
                }
                if VirtualAlloc2(proc(), page as *const c_void, PAGE, MEM_COMMIT, PAGE_NOACCESS, std::ptr::null_mut(), 0).is_null() {
                    return false;
                }
            }
        }
        true
    })();
    if !made {
        for &(a, _) in pieces.iter().filter(|p| p.1 != 0) {
            // SAFETY: frees a reservation or a placeholder made here.
            unsafe { VirtualFree(a as *mut c_void, 0, MEM_RELEASE) };
        }
        return false;
    }
    MOVE_SLOT_CUT.store(UFFD_CHUNK, std::sync::atomic::Ordering::Release);
    MOVE_SLOT.store(slot, std::sync::atomic::Ordering::Release);
    true
}

/// `section`'s view of `len` bytes (a chunk's, [`UFFD_CHUNK`] or a shorter
/// last one) mapped into the move slot ([`MOVE_SLOT`]), its first
/// placeholder split to that length or made whole again first: the view's
/// address, 0 if a step was refused (the slot as it was, or a placeholder
/// of its own split at another length, which the next use mends).
fn slot_view(section: &Owned, len: usize) -> usize {
    use std::sync::atomic::Ordering::{Acquire, Release};
    #[cfg(test)]
    if refused_for_tests(2) {
        return 0;
    }
    let slot = MOVE_SLOT.load(Acquire);
    if slot == 0 || len > UFFD_CHUNK {
        return 0;
    }
    if MOVE_SLOT_CUT.load(Acquire) != len {
        // SAFETY: coalesces our slot's two placeholders, then splits it
        // again ("To coalesce two placeholders", "To split a placeholder",
        // Learn, VirtualFree).
        unsafe {
            if MOVE_SLOT_CUT.load(Acquire) != UFFD_CHUNK {
                if VirtualFree(slot as *mut c_void, UFFD_CHUNK, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS) == 0 {
                    return 0;
                }
                MOVE_SLOT_CUT.store(UFFD_CHUNK, Release);
            }
            if len != UFFD_CHUNK {
                if VirtualFree(slot as *mut c_void, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) == 0 {
                    return 0;
                }
                MOVE_SLOT_CUT.store(len, Release);
            }
        }
    }
    if view_into(section, slot, 0, len) { slot } else { 0 }
}

/// Tests: the next move's step refused, as if Windows refused it, with
/// error 0 (a test's): 1 its new section's making ([`reserved_section`]),
/// 2 its view's map into the move slot ([`slot_view`]), 3 its alias's
/// first view's unmap ([`unmap_alias`]); 0 none. A move not made leaves
/// its chunk and its charge as they were
/// (`test_a_move_not_made_leaves_its_chunk_as_it_was`).
#[cfg(test)]
pub(crate) static REFUSE_MOVE_STEP: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether [`REFUSE_MOVE_STEP`] refuses step `n` now (once).
#[cfg(test)]
fn refused_for_tests(n: usize) -> bool {
    use std::sync::atomic::Ordering::SeqCst;
    let refused = REFUSE_MOVE_STEP.compare_exchange(n, 0, SeqCst, SeqCst).is_ok();
    if refused {
        // SAFETY: plain call.
        unsafe { windows_sys::Win32::Foundation::SetLastError(0) };
    }
    refused
}

/// Unmaps the move's view in the slot ([`slot_view`]), keeping its
/// placeholder. Refused, the slot is out of use for the process
/// ([`SLOT_LOST`]: no move is made after, each saying so) and a line says
/// why: the view would keep its section, which no move may map over.
fn slot_unmap(tmp: usize) {
    // SAFETY: unmaps the view made by `slot_view`, keeping its placeholder.
    if unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: tmp as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) } == 0 {
        // SAFETY: plain call.
        let err = unsafe { GetLastError() };
        SLOT_LOST.store(true, std::sync::atomic::Ordering::Release);
        MOVE_SLOT.store(0, std::sync::atomic::Ordering::Release);
        say_at_the_limit(format_args!(
            "wick: reclaim: the move slot's view at {tmp:#x} could not be unmapped (error {err}): the slot is out of use, no \
             chunk is moved after it, each reclaim at the limit refused"
        ));
    }
}

/// Where a move's view of its new section was mapped, the last one: for
/// the record of its alignment (`test_a_chunk_with_one_dead_page_at_the_limit`).
#[cfg(test)]
pub(crate) static LAST_MOVE_VIEW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// MOVEREC, for tests: the last move's steps ([`uffd_move_chunk`]), each
/// the process's private commit in bytes unless said: [0] at the start,
/// [1] after the dead pages' charge was given back, [2] the temporary view's
/// address, [3] after it was mapped, [4] the pages committed in the 2 MiB
/// regions it spans, outside it, when it was mapped (a page table there
/// already), [5] after the live pages were committed in it, [6] after the
/// copy, [7] after both views were swapped, [8] after it was unmapped, [9]
/// the step it ended at: 1 its map refused, 2 the commit, 3 the close, 4
/// the alias's unmap, 5 made; [4] is the 2 MiB region below its start
/// (outside it) and [10] the one above its end; [11] how many 2 MiB regions
/// it spans.
#[cfg(test)]
pub(crate) static MOVEREC: [std::sync::atomic::AtomicUsize; 12] = [const { std::sync::atomic::AtomicUsize::new(0) }; 12];

/// MOVEREC: the charge page of the page at `at` of a charged view
/// ([`Charge`]), if it has one.
#[cfg(test)]
pub(crate) fn charge_page_of(at: usize) -> Option<usize> {
    let m = CHARGES.lock().unwrap();
    let (&v, (n, c)) = m.range(..=at).next_back()?;
    (at < v + n).then(|| c.base + (at - v))
}

/// MOVEREC: the process's private commit, allocating nothing.
#[cfg(test)]
pub(crate) fn moverec_commit() -> usize {
    use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
    // SAFETY: an all-zero counters structure is valid.
    let mut c: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    let cb = std::mem::size_of_val(&c) as u32;
    c.cb = cb;
    // SAFETY: this process's pseudo handle and a structure of the size given.
    if unsafe { K32GetProcessMemoryInfo(proc(), (&raw mut c).cast(), cb) } == 0 {
        return 0;
    }
    c.PrivateUsage
}

#[cfg(test)]
fn moverec(i: usize, v: usize) {
    MOVEREC[i].store(v, std::sync::atomic::Ordering::SeqCst);
}

/// VIEWCOST, for tests: the last swap of a chunk's views in the alias and
/// the guest's view, two each, one at a time ([`chunk_views`];
/// [`unmap_alias`] and [`swap_views`], by [`uffd_move_chunk`],
/// [`uffd_swap_chunk`] or [`released_swap`]), the process's private commit
/// in bytes: [0] before the alias's first view's unmap, [1] after it, [2]
/// after the new section's first view's map there, [3] after the alias's
/// second view's unmap, [4] after its map; [5] to [8] the same for the
/// guest's view (0 where a step was not reached; a chunk of one view has
/// its second steps as its first's map); [9] 1 for a move, 2 for a swap.
#[cfg(test)]
pub(crate) static VIEWREC: [std::sync::atomic::AtomicUsize; 10] = [const { std::sync::atomic::AtomicUsize::new(0) }; 10];

/// Run by [`swap_views`] between each of the guest view's views' unmap and
/// its map, with the view's index (0, 1): for the tests of another commit
/// taking the room the unmap gave
/// (`test_a_move_whose_guest_view_room_is_taken_is_made`).
#[cfg(test)]
pub(crate) static BETWEEN_GUEST_UNMAP_AND_MAP: Mutex<Option<fn(usize)>> = Mutex::new(None);

/// The same between each of the alias's views' unmap and its map
/// (`test_a_move_whose_alias_room_is_taken_is_made`).
#[cfg(test)]
pub(crate) static BETWEEN_ALIAS_UNMAP_AND_MAP: Mutex<Option<fn(usize)>> = Mutex::new(None);

/// Where [`uffd_alias_chunked`] reserves the next alias (0: anywhere,
/// as the product does), taken by that call: for the record of the
/// views' costs by placement (VIEWCOST).
#[cfg(test)]
pub(crate) static ALIAS_AT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The chunk's alias's first view ([`chunk_views`]) unmapped keeping its
/// placeholder, the first step of a chunk's swap ([`uffd_swap_chunk`],
/// [`uffd_move_chunk`], [`released_swap`]; the rest is [`swap_views`]),
/// apart because a refusal there changes nothing and the caller can give
/// up: whether it was unmapped.
fn unmap_alias(alias: usize, len: usize) -> bool {
    #[cfg(test)]
    {
        for v in &VIEWREC {
            v.store(0, std::sync::atomic::Ordering::SeqCst);
        }
        viewrec(0);
    }
    let Some((a, _, _)) = chunk_views(alias, len).next() else {
        return false;
    };
    // SAFETY: unmaps a view of the chunk's alias, keeping its placeholder.
    let unmapped = unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) } != 0;
    #[cfg(test)]
    if unmapped {
        viewrec(1);
    }
    unmapped
}

/// The rest of a chunk's swap once its alias's first view is out
/// ([`unmap_alias`]): `section`'s first view mapped in its placeholder, the
/// alias's second view unmapped keeping its placeholder and `section`'s
/// mapped there, then the guest's two views the same, one at a time
/// ([`chunk_views`]; [`uffd_swap_chunk`], [`uffd_move_chunk`],
/// [`released_swap`]). While one of a chunk's views is out, its other, of the
/// old section or the new, still maps the 2 MiB region and the 1 GiB they
/// share, so no step gives back a page table or needs one (VIEWCOST: a
/// view's unmap gives back the page table of each 2 MiB region only it
/// maps, and its map takes it again), and no commit of another thread
/// meanwhile can take the room a map needs
/// (`test_a_move_whose_guest_view_room_is_taken_is_made`,
/// `test_a_move_whose_alias_room_is_taken_is_made`,
/// `test_a_discard_whose_guest_view_room_is_taken_is_made`). A view alone
/// in a 2 MiB region of its range would give back that region's table and
/// need it again: such a chunk, at a range's edge, is not swapped
/// ([`at_a_ranges_edge`]). Whether every step was made. `kind` is for
/// the record (VIEWREC: 1 a move, 2 a swap).
fn swap_views(section: &Owned, view: usize, alias: usize, len: usize, #[cfg_attr(not(test), allow(unused_variables))] kind: usize) -> bool {
    #[cfg(test)]
    VIEWREC[9].store(kind, std::sync::atomic::Ordering::SeqCst);
    for (side, base) in [(0, alias), (1, view)] {
        for (i, (a, o, n)) in chunk_views(base, len).enumerate() {
            #[cfg(test)]
            let step = 1 + 4 * side + 2 * i;
            // The alias's first view is out already.
            if side == 1 || i == 1 {
                // SAFETY: unmaps a view of the chunk, keeping its placeholder.
                if unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) } == 0 {
                    return false;
                }
                #[cfg(test)]
                viewrec(step);
            }
            #[cfg(test)]
            {
                let hooks = if side == 0 { &BETWEEN_ALIAS_UNMAP_AND_MAP } else { &BETWEEN_GUEST_UNMAP_AND_MAP };
                if let Some(hook) = *hooks.lock().unwrap() {
                    hook(i);
                }
            }
            if !view_into(section, a, o, n) {
                return false;
            }
            #[cfg(test)]
            viewrec(step + 1);
        }
        #[cfg(test)]
        {
            viewrec_same(4 * side + 2, 4 * side + 3);
            viewrec_same(4 * side + 3, 4 * side + 4);
        }
    }
    true
}

/// VIEWCOST: the private commit now, as step `i`.
#[cfg(test)]
fn viewrec(i: usize) {
    VIEWREC[i].store(moverec_commit(), std::sync::atomic::Ordering::SeqCst);
}

/// VIEWCOST: step `second` as step `first` if a chunk of one view did not
/// reach it.
#[cfg(test)]
fn viewrec_same(first: usize, second: usize) {
    if VIEWREC[second].load(std::sync::atomic::Ordering::SeqCst) == 0 {
        VIEWREC[second].store(VIEWREC[first].load(std::sync::atomic::Ordering::SeqCst), std::sync::atomic::Ordering::SeqCst);
    }
}

/// How many moves were not made ([`uffd_move_chunk`]: the move slot out of
/// use, their new section not made or its view not mapped, its live pages
/// not committed or closed, the alias not unmapped); the line is printed
/// for the first 16 and every 1024th after, as a reclaim at the limit can
/// be tried at every touch.
static MOVE_MAPS_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many moves and swaps were refused for a chunk at a range's edge
/// ([`at_a_ranges_edge`]); the line is printed for the first 16 and every
/// 1024th after.
static EDGE_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Whether a 2 MiB region that `[a, z)` touches holds no other part of the
/// range `[s, e)`: a view's unmap there, with the rest of the range mapped,
/// gives back the region's page table (VIEWCOST), and its map takes one.
pub(crate) fn alone_in_a_region(a: usize, z: usize, s: usize, e: usize) -> bool {
    (a - a % HUGE_PAGE..z).step_by(HUGE_PAGE).any(|r| r.max(s) >= a && (r + HUGE_PAGE).min(e) <= z)
}

/// Whether a view of the chunk at `view` of `len` bytes ([`chunk_views`]),
/// in the guest's range `[start, end)` or in its alias (at `alias`, the
/// range's alias as long at `alias - (view - start)`), is alone in a 2 MiB
/// region of its range ([`alone_in_a_region`]): its swap, one view at a
/// time ([`swap_views`]), would give back that region's page table at the
/// view's unmap and need it again at its map, room another thread's commit
/// can take between. Only at a range's edge, where the range's part of
/// the first or last 2 MiB region it touches lies in one view: a range
/// that starts 1 MiB or more past a 2 MiB boundary, or that ends past one
/// within its last chunk's last view (as a whole chunk's range 64 KiB past
/// a boundary does, or a short last chunk of one view, under 128 KiB);
/// never Firecracker's guest memory, on 2 MiB boundaries and in whole MiB
/// (src/vmm/src/vstate/memory.rs, `GUEST_MEMORY_ALIGNMENT`).
pub(crate) fn at_a_ranges_edge(view: usize, len: usize, alias: usize, start: usize, end: usize) -> bool {
    let off = view - start;
    [(view, start), (alias, alias - off)].into_iter().any(|(base, s)| {
        let e = s + (end - start);
        chunk_views(base, len).any(|(a, _, n)| alone_in_a_region(a, a + n, s, e))
    })
}

/// The line for a chunk at a range's edge ([`at_a_ranges_edge`]) not
/// `what`, and what follows (`then`); counted ([`EDGE_REFUSED`]).
fn edge_refused(view: usize, what: &str, then: &str) {
    let n = EDGE_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    EDGE_REFUSED_HERE.set(EDGE_REFUSED_HERE.get() + 1);
    if n < 16 || n.is_multiple_of(1024) {
        say_at_the_limit(format_args!(
            "wick: reclaim: the chunk at {view:#x} has a view alone in a 2 MiB region at its range's edge, whose swap would \
             need a page table between its unmap and its map: not {what}; {then} ({} such)",
            n + 1
        ));
    }
}

/// Moves and swaps refused at a range's edge ([`EDGE_REFUSED`]), for tests.
#[cfg(test)]
pub(crate) fn edge_refused_for_tests() -> u64 {
    EDGE_REFUSED.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
std::thread_local! {
    /// [`EDGE_REFUSED`]'s refusals made on this thread: a discard's swap
    /// is refused on the discarding thread, so a test reads its own there,
    /// whatever the suite's other tests refuse meanwhile.
    static EDGE_REFUSED_HERE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Moves and swaps refused at a range's edge on this thread
/// ([`EDGE_REFUSED_HERE`]), for tests.
#[cfg(test)]
pub(crate) fn edge_refused_on_this_thread_for_tests() -> u64 {
    EDGE_REFUSED_HERE.get()
}

/// How many moves were not made ([`MOVE_MAPS_REFUSED`]): the tests', and
/// `wick_uffd::reclaim_counts`.
pub(crate) fn moves_refused() -> u64 {
    MOVE_MAPS_REFUSED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Called in the middle of a chunk's move, between the copy and the swap:
/// for tests (`test_the_jailers_count_does_not_rise_during_a_move`; other
/// crates' through `wick_uffd::test_hooks`). An `fn()` in a `usize`, 0 for
/// none, as [`ALIAS_HOOK`], and kept until set again: no lock, so the move
/// takes none the stack reclaim does not cover (a `Mutex` here was one,
/// `test_wicks_memory_locks_are_all_probed`).
#[cfg(any(test, feature = "wick-test-hooks"))]
static MOVE_HOOK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Sets [`MOVE_HOOK`]; `None` takes it away.
#[cfg(any(test, feature = "wick-test-hooks"))]
pub(crate) fn set_move_hook(hook: Option<fn()>) {
    MOVE_HOOK.store(hook.map_or(0, |f| f as usize), std::sync::atomic::Ordering::SeqCst);
}

/// The move slot ([`MOVE_SLOT`]) and the move budget ([`UFFD_BUDGET`]),
/// 0 for none, for tests.
#[cfg(test)]
pub(crate) fn move_slot_and_budget_for_tests() -> (usize, usize) {
    (MOVE_SLOT.load(std::sync::atomic::Ordering::Acquire), UFFD_BUDGET.load(std::sync::atomic::Ordering::Acquire))
}

/// [`uffd_budget`], as the first registration makes it, for tests.
#[cfg(test)]
pub(crate) fn uffd_budget_now_for_tests() -> bool {
    let _t = table().lock().unwrap();
    uffd_budget()
}

/// The move budget decommitted (`on` false) or committed again, for tests;
/// whether there is one and the change was made.
#[cfg(test)]
pub(crate) fn uffd_budget_for_tests(on: bool) -> bool {
    let b = UFFD_BUDGET.load(std::sync::atomic::Ordering::Acquire);
    if b == 0 {
        return false;
    }
    // SAFETY: the budget's own pages.
    unsafe {
        if on {
            !VirtualAlloc2(proc(), b as *const c_void, UFFD_CHUNK, MEM_COMMIT, PAGE_NOACCESS, std::ptr::null_mut(), 0).is_null()
        } else {
            VirtualFree(b as *mut c_void, UFFD_CHUNK, MEM_DECOMMIT) != 0
        }
    }
}

/// Calls `f(start, len)` for each committed run of `[s, s + len)`, in
/// order, allocating nothing (the reclaim's walk: [`uffd_move_chunk`]).
pub(crate) fn for_each_committed(s: usize, len: usize, mut f: impl FnMut(usize, usize)) {
    let (mut at, e) = (s, s + len);
    while at < e {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            break;
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
        if mbi.State == MEM_COMMIT {
            f(at, run);
        }
        at += run;
    }
}

/// Calls `f(start, len)` for each run of `[s, s + len)` that is committed
/// and for which `pick(page)` holds, page by page, in order.
fn for_each_picked(s: usize, len: usize, pick: &dyn Fn(usize) -> bool, mut f: impl FnMut(usize, usize)) {
    for_each_committed(s, len, |a, n| {
        let mut run: Option<usize> = None;
        for at in (a..a + n).step_by(PAGE) {
            match (pick(at), run) {
                (true, None) => run = Some(at),
                (false, Some(r)) => {
                    f(r, at - r);
                    run = None;
                }
                _ => {}
            }
        }
        if let Some(r) = run {
            f(r, a + n - r);
        }
    });
}

/// Moves the chunk `[view, view + len)` of a registered userfaultfd range,
/// whose alias is at `alias`, into a new reserved section, to give back the
/// section commit and the charge of its dead pages (committed and
/// `missing(page)`: discarded inside a chunk not discarded whole,
/// `wick_uffd::discarding`): the reclaim at the memory limit
/// (`wick_uffd::reclaim_at_touch`), as Linux's memory cgroup reclaims before
/// it refuses a charge. The caller holds the userfaultfd's lock (so the
/// missing pages and the commit do not change) and a move's guard on the
/// chunk (no system call is in its copy on it: [`try_move`]) and has marked it
/// moving, so that a host thread's or a vCPU's access to it waits for the
/// move (`wick_uffd::fault`). The live pages are committed in the new
/// section through a view of its own, closed to the guest's view
/// (`PAGE_NOACCESS`, which WHP honours), copied from the alias, and the new
/// section put in the place of the old one in both views
/// ([`uffd_swap_chunk`]'s steps), so that the old one, and its commit, goes
/// with its last view; once it is made, the dead pages' charge is given back
/// ([`uncharge`]) and the live pages' kept (it is indexed by the view's
/// offset, which does not move). The dead pages are not committed in the new
/// section: missing, they fault as missing. The bytes of live pages copied
/// and of dead pages given back, or `None`, the chunk and its charge as they
/// were, if the chunk is not one of [`uffd_alias`]'s or has no dead pages;
/// or, with one line on standard error, if it has a view alone in a 2 MiB
/// region of its range `[start, end)` ([`at_a_ranges_edge`], refused before
/// any step), the move slot is out of use ([`SLOT_LOST`]), or the new
/// section cannot be made, mapped into the slot or committed, the live
/// pages closed, or the alias's first view unmapped
/// (`test_a_move_not_made_leaves_its_chunk_as_it_was`); a failure once a
/// view is unmapped ends the VMM, named ([`out_of_memory`]).
///
/// The job's limit counts none of a move's steps: its view of the new
/// section is mapped into the move slot ([`slot_view`]) and the chunk's
/// views swapped one at a time ([`swap_views`]), which take no page table
/// (VIEWCOST, MOVESLOT), and section commit is not the process's private
/// commit; at the end it is the dead pages' D bytes below. The jailer's
/// count (overlay/jailer/platform/windows commit.rs: private commit plus
/// section commit, less the committed private `PAGE_NOACCESS` memory, no
/// more than the section commit) sees the process hold L more for the
/// copy's time (both sections, for L live bytes), which the move budget
/// ([`UFFD_BUDGET`]) covers, and at the end D below. Allocates nothing: it
/// runs at the limit.
pub(crate) fn uffd_move_chunk(view: usize, len: usize, alias: usize, (start, end): (usize, usize), missing: &dyn Fn(usize) -> bool) -> Option<(usize, usize)> {
    let t = table().lock().unwrap();
    match t.get(&view) {
        Some(r)
            if r.len == len
                && r.holes.is_empty()
                && !r.lazy
                && matches!(r.kind, Kind::View { _section: None, uffd: true, charge: Some(_), file: None, alias: None }) => {}
        _ => return None,
    }
    let live = |at: usize| !missing(at);
    let mut dead = 0;
    for_each_picked(view, len, missing, |_, n| dead += n);
    // A chunk with no dead pages is no candidate (`find_candidates`): it
    // would give back nothing, and has no room to give for its maps.
    if dead == 0 {
        return None;
    }
    if at_a_ranges_edge(view, len, alias, start, end) {
        edge_refused(view, "moved", "its dead pages keep their charge until it is unmapped");
        return None;
    }
    // A move not made leaves the chunk and its charge as they were, which
    // the line says.
    let not_made = |what: &str, err: u32| {
        let n = MOVE_MAPS_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < 16 || n.is_multiple_of(1024) {
            say_at_the_limit(format_args!(
                "wick: reclaim: the move of the chunk at {view:#x} could not {what} (error {err}): the chunk is left as it was, \
                 its charge whole; the commit that needed the reclaim goes on or is refused, as without it ({} such moves)",
                n + 1
            ));
        }
    };
    if MOVE_SLOT.load(std::sync::atomic::Ordering::Acquire) == 0 {
        not_made("be made, the move slot out of use", 0);
        return None;
    }
    #[cfg(test)]
    let refused = refused_for_tests;
    #[cfg(not(test))]
    let refused = |_: usize| false;
    let Some(section) = (if refused(1) { None } else { reserved_section(len) }) else {
        // SAFETY: plain call.
        not_made("make its new section", unsafe { GetLastError() });
        return None;
    };
    #[cfg(test)]
    {
        for m in &MOVEREC {
            m.store(0, std::sync::atomic::Ordering::SeqCst);
        }
        moverec(0, moverec_commit());
        moverec(1, moverec_commit());
    }
    // Into the move slot, where the map needs no room.
    let tmp = slot_view(&section, len);
    if tmp == 0 {
        #[cfg(test)]
        {
            moverec(3, moverec_commit());
            moverec(9, 1);
        }
        // SAFETY: plain call.
        not_made("map its new section", unsafe { GetLastError() });
        return None;
    }
    #[cfg(test)]
    {
        LAST_MOVE_VIEW.store(tmp, std::sync::atomic::Ordering::Relaxed);
        moverec(2, tmp);
        moverec(3, moverec_commit());
        let (lo, hi) = (tmp - tmp % HUGE_PAGE, (tmp + len).next_multiple_of(HUGE_PAGE));
        let (mut below, mut above) = (0, 0);
        if tmp > lo {
            for_each_committed_run(lo, tmp - lo, |_, n| below += n / PAGE);
        }
        if hi > tmp + len {
            for_each_committed_run(tmp + len, hi - (tmp + len), |_, n| above += n / PAGE);
        }
        moverec(4, below);
        moverec(10, above);
        moverec(11, (hi - lo) / HUGE_PAGE);
    }
    let unmap_tmp = |what: &str| {
        // SAFETY: plain call.
        let err = unsafe { GetLastError() };
        slot_unmap(tmp);
        not_made(what, err);
    };
    let mut committed = true;
    for_each_picked(view, len, &live, |a, n| committed &= commit_now(tmp + (a - view), n, PAGE_READWRITE, false));
    #[cfg(test)]
    moverec(5, moverec_commit());
    if !committed {
        #[cfg(test)]
        moverec(9, 2);
        unmap_tmp("commit its live pages in the new section");
        return None;
    }
    let cut = view + chunk_half(len);
    let protect_live = |prot| {
        let mut ok = true;
        for_each_picked(view, len, &live, |a, n| ok &= either_side(a, n, cut, |a, n| protect(a, n, prot)));
        ok
    };
    if !protect_live(PAGE_NOACCESS) {
        protect_live(PAGE_READWRITE);
        #[cfg(test)]
        moverec(9, 3);
        unmap_tmp("close its live pages");
        return None;
    }
    let mut copied = 0;
    for_each_picked(view, len, &live, |a, n| {
        let o = a - view;
        // SAFETY: the chunk's live pages, through its alias, into the new
        // section's view; no thread or vCPU writes them meanwhile.
        unsafe { std::ptr::copy_nonoverlapping((alias + o) as *const u8, (tmp + o) as *mut u8, n) };
        copied += n;
    });
    #[cfg(test)]
    moverec(6, moverec_commit());
    #[cfg(any(test, feature = "wick-test-hooks"))]
    {
        let hook = MOVE_HOOK.load(std::sync::atomic::Ordering::SeqCst);
        if hook != 0 {
            // SAFETY: only `fn()` values are stored (`set_move_hook`).
            unsafe { core::mem::transmute::<usize, fn()>(hook)() };
        }
    }
    // The chunk's alias's first view, unmapped keeping its placeholder: a
    // refusal changes nothing. The guest's views keep the old section until
    // they are swapped too.
    if refused(3) || !unmap_alias(alias, len) {
        protect_live(PAGE_READWRITE);
        #[cfg(test)]
        moverec(9, 4);
        unmap_tmp("unmap its alias");
        return None;
    }
    if !swap_views(&section, view, alias, len, 1) {
        // SAFETY: plain call.
        out_of_memory(view, unsafe { GetLastError() });
    }
    #[cfg(test)]
    moverec(7, moverec_commit());
    slot_unmap(tmp);
    #[cfg(test)]
    {
        moverec(8, moverec_commit());
        moverec(9, 5);
    }
    // Made: the old section and its dead pages are gone with its last view;
    // their charge given back (the live pages' kept: it is indexed by the
    // view's offset, which does not move). The dead pages are not committed
    // in the new section, so they are found as missing: those never filled
    // have no charge, which is no error to give back (Learn, VirtualFree).
    let mut run: Option<usize> = None;
    for at in (view..view + len).step_by(PAGE).chain(core::iter::once(view + len)) {
        match (at < view + len && missing(at), run) {
            (true, None) => run = Some(at),
            (false, Some(r)) => {
                uncharge(r, at - r);
                run = None;
            }
            _ => {}
        }
    }
    drop(t);
    Some((copied, dead))
}

/// Calls `f` with the part of `[s, s + len)` in each region of the table,
/// and in each view of a chunk's ([`chunk_views`]), in order (the whole of
/// it if no region holds any of it), until `f` gives `false`; whether every
/// call gave `true`. A commit or protection change stays within one view. Each part is found under the table's lock
/// and `f` runs without it, as the parts were listed before (a fill at the
/// job's limit allocates nothing: `test_a_fill_at_the_limit_allocates_nothing`).
fn each_region_piece(s: usize, len: usize, mut f: impl FnMut(usize, usize) -> bool) -> bool {
    let e = s + len;
    let mut at = s;
    let mut any = false;
    while at < e {
        let piece = {
            let t = table().lock().unwrap();
            // The region holding `at`, else the first one after it.
            t.range(..=at)
                .next_back()
                .filter(|(b, r)| **b + r.len > at)
                .or_else(|| t.range(at..e).next())
                .map(|(b, r)| {
                    let (a, z) = (at.max(*b), e.min(*b + r.len));
                    let cut = view_cut(*b, r.len, &r.kind);
                    (a, if cut > a && cut < z { cut } else { z })
                })
        };
        let Some((a, z)) = piece else {
            break;
        };
        any = true;
        if !f(a, z - a) {
            return false;
        }
        at = z;
    }
    any || f(s, len)
}

/// Commits the pages `[s, s + len)` of a userfaultfd range's reserved
/// section ([`uffd_alias`]) through its view at their address, with no
/// access and their charge first, before they are filled through the alias
/// and made accessible: a commit through one view leaves the other's
/// protection as it was, so the alias stays writable and no thread sees
/// the page before it is filled (SECTREC-h, CI run 43521200989: committed
/// `PAGE_NOACCESS` through A, B read committed and `PAGE_READWRITE`, B's
/// write read back through A once A was opened). `false` if the charge or
/// the commit is refused (the job's memory limit).
///
pub(crate) fn uffd_commit(s: usize, len: usize) -> bool {
    each_region_piece(s, len, |a, n| commit(a, n, PAGE_NOACCESS, false))
}


/// A userfaultfd range's record of its released pages (docs/ARCHITECTURE.md,
/// "Released userfaultfd ranges"): the pages that were missing when
/// they left the registration (at its release, `wick_uffd::destroy`, or an
/// unregister of them) and are still to be resolved at their first access:
/// one never filled is not committed and is committed then, with the
/// protection `mprotect` gave it; one discarded is committed, closed and
/// still charged (`wick_uffd::discarding`), and is zeroed through the
/// range's alias then and opened, as Linux gives a zapped page as zeros at
/// its next touch. A record is taken at the register ([`released_reserve`])
/// with its bitmaps, so that the release, which runs at the job's limit and
/// cannot fail, allocates nothing and needs no new record: it sets bits.
/// Linux's release clears each vma's flags in place (v6.1 fs/userfaultfd.c
/// `userfaultfd_release`, 885-899) and the pages stay in its page tables.
/// Every look at a record is made under [`RELEASED`]'s lock (a reader never
/// holds a record across its reuse); [`RELEASED_LIVE`] is the only thing
/// read without it, a hint that no record is in use.
struct Record {
    /// The registration's span; 0 when free.
    start: usize,
    end: usize,
    state: RecordState,
    /// Three bitmaps of a bit a page, one after another: pending, its
    /// protection denies reads (`PROT_NONE`), denies writes.
    bits: Option<std::boxed::Box<[u64]>>,
    /// The range's alias: a pending committed page is zeroed through it.
    alias: usize,
    /// Pending pages.
    left: usize,
    /// The registration's views still mapped (one a [`UFFD_CHUNK`]): the
    /// record is freed once it is released and none is (a thread that
    /// faulted on a page another thread resolved meanwhile finds the record
    /// still holding the page, and runs its access again).
    views: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordState {
    Free,
    /// Its registration lives (pages an unregister released may be pending).
    Reserved,
    /// Its registration is released; freed once its views are gone.
    Released,
}

const PENDING: usize = 0;
const NOREAD: usize = 1;
const NOWRITE: usize = 2;

impl Record {
    const FREE: Record = Record { start: 0, end: 0, state: RecordState::Free, bits: None, alias: 0, left: 0, views: 0 };

    fn words(&self) -> usize {
        ((self.end - self.start) / PAGE).div_ceil(64)
    }

    fn get(&self, map: usize, addr: usize) -> bool {
        let page = (addr - self.start) / PAGE;
        self.bits.as_ref().is_some_and(|b| b[map * self.words() + page / 64] & (1 << (page % 64)) != 0)
    }

    fn put(&mut self, map: usize, addr: usize, on: bool) {
        let (page, words) = ((addr - self.start) / PAGE, self.words());
        if let Some(b) = self.bits.as_mut() {
            let w = &mut b[map * words + page / 64];
            if on {
                *w |= 1 << (page % 64);
            } else {
                *w &= !(1 << (page % 64));
            }
        }
    }

    fn holds(&self, addr: usize) -> bool {
        self.state != RecordState::Free && self.start <= addr && addr < self.end
    }

    /// The protection the page at `addr` takes when it is resolved.
    fn prot(&self, addr: usize) -> PAGE_PROTECTION_FLAGS {
        if self.get(NOREAD, addr) {
            PAGE_NOACCESS
        } else if self.get(NOWRITE, addr) {
            PAGE_READONLY
        } else {
            PAGE_READWRITE
        }
    }

    /// The page at `addr` is no longer pending. The record keeps its
    /// bitmaps until it is freed, for a discard of its released pages to
    /// make them pending again ([`released_discard`]): 3 bits a page, 96
    /// KiB a GiB, while the registration's memory is mapped.
    fn resolved(&mut self, addr: usize) {
        if self.get(PENDING, addr) {
            self.put(PENDING, addr, false);
            self.left -= 1;
        }
    }

    /// The page at `addr` is pending again, to be resolved with
    /// protection `prot`.
    fn pend(&mut self, addr: usize, prot: PAGE_PROTECTION_FLAGS) {
        self.set_prot(addr, prot);
        self.pend_as_set(addr);
    }

    /// The protection the page at `addr` takes when it is resolved.
    fn set_prot(&mut self, addr: usize, prot: PAGE_PROTECTION_FLAGS) {
        self.put(NOREAD, addr, prot == PAGE_NOACCESS);
        self.put(NOWRITE, addr, !matches!(prot, PAGE_READWRITE | PAGE_EXECUTE_READWRITE));
    }

    /// The page at `addr` is pending again, with the protection its bits
    /// hold.
    fn pend_as_set(&mut self, addr: usize) {
        if !self.get(PENDING, addr) {
            self.put(PENDING, addr, true);
            self.left += 1;
        }
    }

    fn free(&mut self) {
        *self = Record::FREE;
        RELEASED_LIVE.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// The records, as many as the userfaultfd's ranges (`wick_uffd::MAX_RANGES`).
/// Taken after the region table's lock and before [`CHARGES`].
static RELEASED: ProbedMutex<[Record; 64]> = ProbedMutex::new("RELEASED", [const { Record::FREE }; 64]);

/// Tests: runs `f` with [`RELEASED`]'s lock held, as `released_resolve`
/// holds it over its charge and commit, where a stack page can be needed
/// (`test_a_stack_page_refused_with_a_lock_held_is_not_waited_for`).
#[cfg(test)]
pub(crate) fn with_released_held<T>(f: impl FnOnce() -> T) -> T {
    let _records = RELEASED.lock().unwrap();
    f()
}
/// The records not free: 0, and no access needs [`RELEASED`]'s lock.
static RELEASED_LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A record for a registration of `[start, start + len)`, taken with its
/// bitmaps before the registration is made: its index, or `ENOMEM` with no
/// record free or no memory for its bitmaps (the 65th registration whose
/// earlier ranges' released pages are all still mapped; Linux refuses a
/// register whose vma split would pass `vm.max_map_count`, mm/mmap.c
/// `split_vma`).
pub(crate) fn released_reserve(start: usize, len: usize) -> Result<usize, c_int> {
    let words = (len / PAGE).div_ceil(64);
    let mut bits = Vec::new();
    crate::wick_alloc::fallible(|| bits.try_reserve_exact(3 * words)).map_err(|_| crate::ENOMEM)?;
    bits.resize(3 * words, 0u64);
    let mut records = RELEASED.lock().unwrap();
    let i = records.iter().position(|r| r.state == RecordState::Free).ok_or(crate::ENOMEM)?;
    records[i] = Record {
        start,
        end: start + len,
        state: RecordState::Reserved,
        bits: Some(bits.into_boxed_slice()),
        alias: 0,
        left: 0,
        views: len.div_ceil(UFFD_CHUNK),
    };
    RELEASED_LIVE.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    Ok(i)
}

/// The registration record `i` was taken for was not made, or needs none
/// (a range not on a reserved section): freed.
pub(crate) fn released_unreserve(i: usize) {
    let mut records = RELEASED.lock().unwrap();
    if records[i].state != RecordState::Free {
        records[i].free();
    }
}

/// Pages `[s, s + len)` of the range of record `i` left the registration
/// while missing: pending, each with the protection `prot` gives its
/// address, `alias` the range's alias (`mprotect` and `munmap` ask the
/// record about them: [`released_overlaps`]). Allocates nothing, and takes
/// no other lock: the release runs at the job's limit, on the userfaultfd's
/// serve thread, whose stack must not grow there.
pub(crate) fn released_pend(i: usize, alias: usize, s: usize, len: usize, prot: impl Fn(usize) -> PAGE_PROTECTION_FLAGS) {
    let e = s + len;
    let mut records = RELEASED.lock().unwrap();
    let r = &mut records[i];
    r.alias = alias;
    for at in (s..e).step_by(PAGE) {
        r.pend(at, prot(at));
    }
}

/// Pages `[s, s + len)` of record `i`'s range are registered again
/// (`wick_uffd::register` over a range whose slot was kept): `each(at,
/// pending)` is called for each page in order, with the protection a page
/// pending here would have taken at its resolution, or `None` for a page
/// not pending (resident: resolved, or never missing); then the page is no
/// longer pending. A pending page so goes back to its range missing, its
/// commit and charge (a discarded one's) kept, and its content never shown:
/// a fill writes all of it. `each` runs under [`RELEASED`]'s lock and must
/// take no lock: the caller marks the page missing there, before it leaves
/// the record, so that an access between finds it one or the other.
/// Allocates nothing.
pub(crate) fn released_take(i: usize, s: usize, len: usize, mut each: impl FnMut(usize, Option<PAGE_PROTECTION_FLAGS>)) {
    let mut records = RELEASED.lock().unwrap();
    let r = &mut records[i];
    for at in (s..s + len).step_by(PAGE) {
        let pending = (r.holds(at) && r.get(PENDING, at)).then(|| r.prot(at));
        each(at, pending);
        if pending.is_some() {
            r.resolved(at);
        }
    }
}

/// The alias of record `i`'s registration (`uffd_alias`), through which
/// its pending committed pages are zeroed: set at the register, so that a
/// discard of pages unregistered while the range lives
/// ([`released_discard`]) has it as a release's has.
pub(crate) fn released_alias(i: usize, alias: usize) {
    RELEASED.lock().unwrap()[i].alias = alias;
}

/// The registration of record `i` is released: the record is freed once
/// its views are gone ([`released_view_gone`]).
pub(crate) fn released_end(i: usize) {
    let mut records = RELEASED.lock().unwrap();
    let r = &mut records[i];
    r.state = RecordState::Released;
    if r.views == 0 {
        r.free();
    }
}

/// The view `[base, base + len)` is going (unmapped, or mapped over): its
/// pages are no longer pending, and a released record left with no view is
/// freed. Before the view and its alias go.
fn released_view_gone(base: usize, len: usize) {
    if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return;
    }
    released_forget(base, len);
    let mut records = RELEASED.lock().unwrap();
    if let Some(r) = records.iter_mut().find(|r| r.holds(base)) {
        r.views = r.views.saturating_sub(1);
        if r.views == 0 && r.state == RecordState::Released {
            r.free();
        }
    }
}

/// `[s, s + len)` is unmapped or mapped over: none of it is pending any
/// longer. Before its view and alias go, so that no access resolves a page
/// through an alias that is gone.
fn released_forget(s: usize, len: usize) {
    if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return;
    }
    forget_in(&mut RELEASED.lock().unwrap()[..], s, len);
}

/// [`released_forget`] in `records`, locked by the caller.
fn forget_in(records: &mut [Record], s: usize, len: usize) {
    let e = s.saturating_add(len);
    for r in records.iter_mut().filter(|r| r.state != RecordState::Free && r.start < e && s < r.end) {
        for at in (s.max(r.start)..e.min(r.end)).step_by(PAGE) {
            if r.left == 0 {
                break;
            }
            r.resolved(at);
        }
    }
}

/// Whether a record holds a page of `[s, e)`: released memory, lazy where
/// its pages are pending (`mprotect` keeps them so, `munmap` forgets them).
fn released_overlaps(s: usize, e: usize) -> bool {
    RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) != 0
        && RELEASED.lock().unwrap().iter().any(|r| r.state != RecordState::Free && r.start < e && s < r.end)
}

/// Whether a pending page of `[s, s + len)` is committed: a discarded page
/// still to be zeroed through the alias.
fn released_has_stale(s: usize, len: usize) -> bool {
    if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return false;
    }
    let e = s.saturating_add(len);
    let records = RELEASED.lock().unwrap();
    records.iter().filter(|r| r.state != RecordState::Free && r.start < e && s < r.end).any(|r| {
        (s.max(r.start)..e.min(r.end)).step_by(PAGE).any(|at| r.get(PENDING, at) && committed_page(at))
    })
}

/// Whether every page of `[s, s + len)` is committed (`VirtualQuery`, a
/// region at a time).
fn committed_run(s: usize, len: usize) -> bool {
    let end = s + len;
    let mut at = s;
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 || mbi.State != MEM_COMMIT {
            return false;
        }
        at = mbi.BaseAddress as usize + mbi.RegionSize;
    }
    true
}

fn committed_page(at: usize) -> bool {
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let found = unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) };
    found != 0 && mbi.State == MEM_COMMIT
}

/// `mprotect` of `[s, e)` where a record holds it: the protection its
/// pending pages take when resolved, set in place. Whether a record holds
/// all of it (the caller then gives the protection to the pages that are
/// committed and not pending, [`released_is_pending`]).
fn released_protect(s: usize, e: usize, wprot: PAGE_PROTECTION_FLAGS) -> bool {
    if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return false;
    }
    let mut records = RELEASED.lock().unwrap();
    let Some(r) = records.iter_mut().find(|r| r.holds(s) && e <= r.end) else {
        return false;
    };
    for at in (s..e).step_by(PAGE) {
        r.put(NOREAD, at, wprot == PAGE_NOACCESS);
        r.put(NOWRITE, at, !matches!(wprot, PAGE_READWRITE | PAGE_EXECUTE_READWRITE));
    }
    true
}

pub(crate) fn released_is_pending(at: usize) -> bool {
    RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) != 0 && RELEASED.lock().unwrap().iter().any(|r| r.holds(at) && r.get(PENDING, at))
}

/// The first access to `addr` (a write if `write`) if a record has its
/// page pending: resolved, and the range resolved; `None` if no record has
/// it. A page never filled is committed with its protection (the
/// `grain`'s block around it when all of it is pending and none of it is
/// committed: `MADV_HUGEPAGE`, as [`commit_on_access`] for lazy memory); a
/// discarded one is charged, zeroed through the alias while still closed,
/// then given its protection. `PROT_NONE`, or a write the protection
/// denies: [`Access::NotLazy`], the fault as on Linux. Refused (the job's
/// limit): [`Access::Exhausted`], nothing changed but the regions of a
/// block committed before the refusal (resolved, [`commit_regions`]), for
/// the caller to reclaim and ask again. The bit is cleared once the page is open, under
/// the lock, so a thread that faulted on it meanwhile finds it open.
fn released_resolve(addr: usize, write: bool, grain: usize) -> Option<(Access, core::ops::Range<usize>)> {
    let page = addr - addr % PAGE;
    let mut records = RELEASED.lock().unwrap();
    // Its record (a page is pending in one record at most: a span the
    // records held before it was unmapped is forgotten in them).
    let Some(r) = records.iter_mut().find(|r| r.holds(page) && r.get(PENDING, page)) else {
        // Resolved by another access (another thread's, or this one's
        // before): the access runs again if the page allows it now, nothing
        // committed.
        let held = records.iter().any(|r| r.holds(page));
        return (held && accessible(page, 1, write)).then_some((Access::Present, 0..0));
    };
    let prot = r.prot(page);
    let writable = matches!(prot, PAGE_READWRITE | PAGE_EXECUTE_READWRITE);
    if prot == PAGE_NOACCESS || (write && !writable) {
        return Some((Access::NotLazy, 0..0));
    }
    if committed_page(page) {
        if !charge(page, PAGE) {
            // SAFETY: plain call.
            return Some((Access::Exhausted(unsafe { GetLastError() }), 0..0));
        }
        // SAFETY: the alias of the page, mapped while a pending page of its
        // chunk is committed (`uffd_unalias`; `released_forget` before it
        // goes).
        unsafe { std::ptr::write_bytes((r.alias + (page - r.start)) as *mut u8, 0, PAGE) };
        #[cfg(test)]
        resolve_pause();
        // `PAGE_READONLY` or `PAGE_READWRITE` (`PAGE_NOACCESS` returned
        // above), for a page found committed under the records' lock in a
        // read-write view of its section: no view goes while the lock is
        // held (every unmap and map-over forgets the view's pages first:
        // `munmap`, [`release`], [`to_placeholder`]), so the change cannot be
        // refused. The charge taken above is no extra: a committed section
        // page is charged (`wick_uffd::discarding` keeps a discarded page's
        // charge), and committing a committed charge page charges nothing
        // more ("an attempt to commit a page that is already committed does
        // not cause the function to fail", Microsoft Learn, VirtualAlloc).
        // Refused all the same, the invariant is broken, and the VMM
        // ends, named, where a return would fault an access to a page that
        // is still pending.
        if !protect(page, PAGE, prot) {
            // SAFETY: plain call.
            let err = unsafe { GetLastError() };
            say_at_the_limit(format_args!(
                "wick: guest memory: a released userfaultfd page at {page:#x}, committed in its view, could not be \
                 given its protection {prot:#x} (error {err}): the VMM aborts"
            ));
            std::process::abort();
        }
        touched_mark(page, PAGE, true);
        r.resolved(page);
        return Some((Access::Committed, page..page + PAGE));
    }
    let block = addr - addr % grain;
    let whole = grain > PAGE
        && block >= r.start
        && block + grain <= r.end
        && (block..block + grain).step_by(PAGE).all(|a| r.get(PENDING, a) && r.prot(a) == prot)
        && reserved_only(block, block + grain);
    let (from, to) = if whole { (block, block + grain) } else { (page, page + PAGE) };
    // A region at a time: the block is reserved only, so each region lies
    // in one view, and a chunk's 2 MiB is two views (review B1), which one
    // commit cannot span (refused, and before this a page committed in
    // place of the huge one: test_a_released_chunks_huge_page_is_committed_whole).
    let (done, err) = commit_regions(from, to, prot);
    // What was committed is resolved, all of it or the regions before a
    // refusal: each page of the block was pending, never filled and
    // reserved (`whole` checks all three), so a commit made it a new zero
    // page of the reserved section, with the block's protection (each
    // page's is `prot`, checked) and its charge taken by [`commit`]: what
    // its own first access would have given it.
    for at in (from..done).step_by(PAGE) {
        r.resolved(at);
    }
    if done == to {
        return Some((Access::Committed, from..to));
    }
    // Refused part way: the regions committed before the refusal stay
    // committed (a section's page cannot be decommitted: SECTREC-h), and
    // are resolved above. A huge page that cannot be
    // charged falls back to a page, as Linux's does (mm/huge_memory.c,
    // `THP_FAULT_FALLBACK_CHARGE`); the error reported is the first
    // refusal's.
    if page < done {
        return Some((Access::Committed, from..done));
    }
    if to - from == PAGE || !commit(page, PAGE, prot, false) {
        return Some((Access::Exhausted(err), 0..0));
    }
    r.resolved(page);
    Some((Access::Committed, page..page + PAGE))
}

/// Commits `[from, to)`, reserved memory, with `prot` and its charge
/// ([`commit`]), one `VirtualQuery` region at a time, which stays within one
/// allocation (a view), in order, up to the first refusal: the end of the
/// part committed, and that refusal's error (0 if none).
fn commit_regions(from: usize, to: usize, prot: PAGE_PROTECTION_FLAGS) -> (usize, u32) {
    let mut at = from;
    while at < to {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let run = if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            to - at
        } else {
            (mbi.BaseAddress as usize + mbi.RegionSize).min(to) - at
        };
        if !commit(at, run, prot, false) {
            // SAFETY: plain call.
            return (at, unsafe { GetLastError() });
        }
        at += run;
    }
    (to, 0)
}

/// Tests: a resolve of a discarded page parks after zeroing it, holding the
/// records' lock, while [`RESOLVE_PAUSE`] is armed: 0 off, 1 armed, 2
/// parked, 3 let go.
#[cfg(test)]
static RESOLVE_PAUSE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(test)]
fn resolve_pause() {
    use std::sync::atomic::Ordering::SeqCst;
    if RESOLVE_PAUSE.compare_exchange(1, 2, SeqCst, SeqCst).is_ok() {
        while RESOLVE_PAUSE.load(SeqCst) != 3 {
            std::thread::yield_now();
        }
        RESOLVE_PAUSE.store(0, SeqCst);
    }
}

/// Tests: the next resolve of a discarded page parks ([`RESOLVE_PAUSE`]).
#[cfg(test)]
pub(crate) fn resolve_pause_arm() {
    RESOLVE_PAUSE.store(1, std::sync::atomic::Ordering::SeqCst);
}

/// Tests: whether a resolve is parked.
#[cfg(test)]
pub(crate) fn resolve_parked() -> bool {
    RESOLVE_PAUSE.load(std::sync::atomic::Ordering::SeqCst) == 2
}

/// Tests: lets the parked resolve go on.
#[cfg(test)]
pub(crate) fn resolve_go() {
    RESOLVE_PAUSE.store(3, std::sync::atomic::Ordering::SeqCst);
}

/// Tests: poisons the released ranges' records' lock, a thread panicking
/// while it holds it, as a bug would.
#[cfg(test)]
pub(crate) fn poison_released() {
    let _ = std::thread::spawn(|| {
        let _g = RELEASED.lock().unwrap();
        panic!("poisoning RELEASED on purpose");
    })
    .join();
}

/// [`released_resolve`] with the reclaim asked once when refused, as a
/// first touch of lazy memory reclaims before the VMM ends
/// (`wick_uffd::reclaim_at_touch`).
fn released_access(addr: usize, write: bool) -> Option<(Access, core::ops::Range<usize>)> {
    if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return None;
    }
    let grain = if write { lazy_grain(addr) } else { PAGE };
    let (access, range) = released_resolve(addr, write, grain)?;
    if matches!(access, Access::Exhausted(_)) && crate::wick_uffd::reclaim_at_touch(PAGE).freed > 0 {
        return Some(released_resolve(addr, write, PAGE).unwrap_or((Access::NotLazy, 0..0)));
    }
    Some((access, range))
}

/// The pending pages of `[addr, addr + len)`, resolved: a system call's
/// buffer ([`prefault_lazy`]). Refused even after a reclaim: the VMM ends
/// as at the limit ([`out_of_memory`]).
fn released_prefault(addr: usize, len: usize) {
    if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return;
    }
    let (s, e) = (addr - addr % PAGE, (addr + len).div_ceil(PAGE) * PAGE);
    if !RELEASED.lock().unwrap().iter().any(|r| r.state != RecordState::Free && r.start < e && s < r.end) {
        return;
    }
    for page in (s..e).step_by(PAGE) {
        if let Some((Access::Exhausted(err), _)) = released_access(page, false) {
            out_of_memory(page, err);
        }
    }
}

/// `MADV_DONTNEED` or `MADV_FREE` of `[s, s + len)` (whole pages) where it
/// is a released userfaultfd range's: the pages a record holds and no
/// registration tracks (`registered`), in a chunk's views
/// ([`wick_uffd::discarding`], after the plain discard, which keeps a
/// view's pages). On Linux that memory is anonymous private memory again,
/// whose discarded pages read as zeros at their next touch (mm/madvise.c);
/// here they are the record's pending pages again, as a registered
/// discard makes its pages missing:
/// - a chunk discarded whole gets a new, empty reserved section in its
///   views and its alias's ([`released_swap`]), its commit and charge
///   given back, as a registered chunk's ([`uffd_swap_chunk`]) and as
///   Linux frees the pages; every page of it pending, each committed at
///   its first access with the protection it had;
/// - a part of a chunk is closed (`PAGE_NOACCESS`, a region at a time,
///   which stays in one view), pending with the protection it had, and its
///   content dropped through the alias (`DiscardVirtualMemory`): its first
///   access zeroes it through the alias and opens it
///   ([`released_resolve`]). Its commit and charge stay until the chunk
///   is discarded whole or unmapped, as a registered partial discard's
///   (a section's page cannot be decommitted: SECTREC-h).
///
/// Under the region table's lock and the records', which a first access
/// resolving a released page holds from its check of the page to its
/// protection: a page is not closed under a resolve, and an access meets
/// the page open with its old data, or closed and then pending, which its
/// resolve gives as zeros, as a Linux access meets the page before the zap
/// or the zero page after it. A page `PROT_NONE` gave no access stays so.
pub(crate) fn released_discard(s: usize, len: usize, registered: impl Fn(usize) -> bool) {
    if RELEASED_LIVE.load(std::sync::atomic::Ordering::Acquire) == 0 {
        return;
    }
    let e = s.saturating_add(len);
    {
        let t = table().lock().unwrap();
        for b in overlapping(&t, s, e) {
            let r = &t[&b];
            if !is_chunk(&r.kind) {
                continue;
            }
            let (n, whole) = (r.len, s <= b && b + r.len <= e && r.holes.is_empty() && !r.lazy);
            let parts = mapped_parts(r, b, s.max(b), e.min(b + r.len));
            let mut records = RELEASED.lock().unwrap();
            let Some(rec) = records.iter_mut().find(|x| x.holds(b) && x.alias != 0) else {
                continue;
            };
            let alias = rec.alias + (b - rec.start);
            if whole && (b..b + n).step_by(PAGE).all(|p| !registered(p)) && released_swap(rec, b, n, alias) {
                continue;
            }
            for (a, z) in parts {
                released_close(rec, b, alias, a, z, &registered);
            }
        }
    }
    #[cfg(test)]
    if let Some(hook) = *AFTER_RELEASED_DISCARD_LOCKS.lock().unwrap() {
        hook();
    }
}

/// Run by [`released_discard`] once it has dropped its locks: for a test
/// of a page resolved then ([`released_swap`]'s charge, given back before).
#[cfg(test)]
pub(crate) static AFTER_RELEASED_DISCARD_LOCKS: Mutex<Option<fn()>> = Mutex::new(None);

/// [`released_discard`] of the chunk at `view` (`len` bytes, its alias at
/// `alias`) discarded whole: a new reserved section in its alias's views
/// and then its own ([`swap_views`], as [`uffd_swap_chunk`]), every page
/// of it pending in `rec`, with the protection it had (read before the
/// views go, into its bits only: they are read for a pending page alone),
/// and then its charge given back ([`uncharge`]), as [`uffd_swap_chunk`]'s.
/// `false`, nothing changed, if the chunk has a view alone in a 2 MiB
/// region of its range ([`at_a_ranges_edge`], said in a line); `false`,
/// nothing changed but those bits, if no section can be made or the alias's
/// first view's unmap is refused; a failure once a view is unmapped ends
/// the VMM, named ([`out_of_memory`]).
///
/// The charge is given back under the records' lock, the caller's, once
/// every page is pending: a first access to a page of the chunk on
/// another thread resolves it under that lock ([`released_resolve`]), so
/// it comes after and charges its page again. Given back after the lock,
/// it decommitted the charge of a page resolved between (a committed
/// section page with none; test_a_page_resolved_as_its_released_chunk_is
/// _discarded_keeps_its_charge). Locks: the table's, then the records',
/// then [`CHARGES`]' ([`uncharge`]); nothing takes the records' lock while
/// it holds that.
fn released_swap(rec: &mut Record, view: usize, len: usize, alias: usize) -> bool {
    if at_a_ranges_edge(view, len, alias, rec.start, rec.end) {
        edge_refused(view, "swapped for a new section at its discard", "its pages are closed and discarded in place and keep their charge until it is unmapped");
        return false;
    }
    let Some(section) = reserved_section(len) else {
        return false;
    };
    let mut at = view;
    while at < view + len {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let run = if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            // No answer for the rest of our own chunk's views (which a
            // query of mapped memory of ours does not give): its protection
            // is not read, so its open pages keep the bits they have, and
            // `mbi` (zeroed: no MEM_COMMIT) records none below. They are
            // pending after the swap all the same, as the rest.
            view + len - at
        } else {
            (mbi.BaseAddress as usize + mbi.RegionSize).min(view + len) - at
        };
        if mbi.State == MEM_COMMIT {
            for p in (at..at + run).step_by(PAGE) {
                if !rec.get(PENDING, p) {
                    rec.set_prot(p, mbi.Protect);
                }
            }
        }
        at += run;
    }
    if !unmap_alias(alias, len) {
        return false;
    }
    if !swap_views(&section, view, alias, len, 2) {
        // SAFETY: plain call.
        out_of_memory(view, unsafe { GetLastError() });
    }
    for p in (view..view + len).step_by(PAGE) {
        rec.pend_as_set(p);
    }
    uncharge(view, len);
    true
}

/// [`released_discard`] of `[a, z)`, a mapped part of the chunk at `view`
/// (its alias at `alias`): each run of committed pages `rec` has open and
/// no registration tracks is closed, pending with the protection it had,
/// and its content dropped through the alias. Windows refusing to close
/// a run of our own view, the page would keep its data while pending: the
/// VMM ends, named.
fn released_close(rec: &mut Record, view: usize, alias: usize, a: usize, z: usize, registered: &impl Fn(usize) -> bool) {
    let mut at = a;
    while at < z {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return;
        }
        let end = (mbi.BaseAddress as usize + mbi.RegionSize).min(z);
        let mut p = at;
        while mbi.State == MEM_COMMIT && p < end {
            if registered(p) || rec.get(PENDING, p) {
                p += PAGE;
                continue;
            }
            let q = (p..end).step_by(PAGE).find(|&q| registered(q) || rec.get(PENDING, q)).unwrap_or(end);
            if !protect(p, q - p, PAGE_NOACCESS) {
                // SAFETY: plain call.
                let err = unsafe { GetLastError() };
                say_at_the_limit(format_args!(
                    "wick: guest memory: released userfaultfd pages at {p:#x} ({:#x} bytes) could not be closed for their \
                     discard (error {err}): the VMM aborts",
                    q - p
                ));
                std::process::abort();
            }
            for x in (p..q).step_by(PAGE) {
                rec.pend(x, mbi.Protect);
            }
            // SAFETY: the alias of those pages, closed now in the view; its
            // content goes, as each is zeroed at its next access.
            unsafe { DiscardVirtualMemory((alias + (p - view)) as *mut c_void, q - p) };
            p = q;
        }
        at = end;
    }
}

/// The view at `base` (`len` bytes, `kind`) is going: its pages out of
/// the records, then the alias it was handed, if any, unmapped.
fn unalias(base: usize, len: usize, kind: &Kind) {
    released_view_gone(base, len);
    if let Kind::View { alias: Some(alias), .. } = kind {
        if is_chunk(kind) {
            unmap_chunk(*alias, len, false);
        } else {
            // SAFETY: unmaps the alias view made by `uffd_alias`.
            unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: *alias as *mut c_void }, 0) };
        }
    }
}

/// A userfaultfd range `[start, start + len)` is released, its alias at
/// `alias` ([`uffd_alias`]) no longer the userfaultfd's: in a reserved
/// section, each chunk's alias handed to its view, which keeps it until it
/// goes: a discarded page still to zero (pending and committed in its
/// record) is zeroed through it, and so is a page a discard after the
/// release makes pending again ([`released_discard`]), whose chunk, if
/// discarded whole, gets a new section in both ([`released_swap`]). It
/// costs address space only (the section's pages are the view's). Else
/// unmapped now, and the view keeps no alias if it has no page to zero.
/// `reserved`: the alias is a chunk's views per [`UFFD_CHUNK`]
/// ([`chunk_views`]), else one view; `record`, a reserved range's record,
/// which zeroes its pages through the alias.
pub(crate) fn uffd_unalias(start: usize, len: usize, alias: usize, reserved: bool, record: Option<usize>) {
    let step = if reserved { UFFD_CHUNK } else { len };
    let mut guard = table().lock().unwrap();
    let t: &mut Table = &mut guard;
    if let Some(i) = record {
        RELEASED.lock().unwrap()[i].alias = alias;
    }
    for o in (0..len).step_by(step) {
        let n = step.min(len - o);
        // A chunk view at the range's address is the range's own: no other
        // registration overlaps it while it lives (`EBUSY`), and a view
        // mapped over it since is no userfaultfd chunk.
        if let Some(r) = t.get_mut(&(start + o)).filter(|r| r.len == n) {
            let chunk = is_chunk(&r.kind);
            if (reserved && chunk) || released_has_stale(start + o, n) {
                if let Kind::View { alias: kept @ None, .. } = &mut r.kind {
                    *kept = Some(alias + o);
                    continue;
                }
            }
        }
        if reserved {
            unmap_chunk(alias + o, n, false);
        } else {
            // SAFETY: unmaps an alias view made by `uffd_alias`.
            unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: (alias + o) as *mut c_void }, 0) };
        }
    }
}

/// The bytes of the charge registered for the view at `view` that are
/// committed, if one is registered ([`Charge`]): for tests.
#[cfg(test)]
pub(crate) fn charged(view: usize) -> Option<usize> {
    let (base, n) = CHARGES.lock().unwrap().get(&view).map(|(n, c)| (c.base, *n))?;
    Some(committed_runs(base, n).iter().map(|r| r.1).sum())
}

/// The committed runs of `[s, s + len)`, as `(start, len)`.
#[cfg(test)]
pub(crate) fn committed_runs(s: usize, len: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for_each_committed_run(s, len, |a, n| out.push((a, n)));
    out
}

/// Calls `f(start, len)` for each committed run of `[s, s + len)`, in
/// order, without allocating (the userfaultfd's release runs at the job's
/// limit: `wick_uffd::release_missing`).
pub(crate) fn for_each_committed_run(s: usize, len: usize, mut f: impl FnMut(usize, usize)) {
    let (mut at, e) = (s, s + len);
    while at < e {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            break;
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
        if mbi.State == MEM_COMMIT {
            f(at, run);
        }
        at += run;
    }
}

/// The system calls in flight that copy memory of this module's mappings,
/// the discards waiting for them, and the reclaim's moves. The kernel's copy
/// of a system call cannot fault a page in here, so a page discarded after
/// the call's prefault and before its copy reaches it fails the call, where
/// Linux's copy faults the page in again (v6.1 mm/userfaultfd.c
/// `handle_userfault`, mm/memory.c `do_anonymous_page`) and completes. A
/// call that ends (a regular file's, an `O_NONBLOCK` descriptor's:
/// `windows_fd::read`, `write`, `pread`, `pwrite`) is counted on its
/// buffer's range from before its prefault to its end ([`copying`]), in two
/// phases: its prefault, which faults the buffer's pages in and may wait for
/// a userfaultfd's fills without end, and its copy, from right before its
/// system call ([`Copying::copy_now`]) to its end, which waits for nothing
/// of this process's.
///
/// A discard of an overlapping range (`MADV_DONTNEED`, `MADV_FREE`, a
/// `MAP_FIXED` mapping over it, as Firecracker's `discard_range` does for a
/// private file mapping) waits for the call in either phase
/// ([`discard_waiting`]), and a call that starts while a discard of its
/// range waits waits for that discard, so a stream of calls cannot hold a
/// discard off. A reclaim's move of a chunk (`windows_uffd`) is held off by
/// calls in their copy alone ([`try_move`]): a move keeps every page that is
/// present present, so what a prefault faulted in stays there, and an
/// access during the move waits for it; a call's turn to its copy waits
/// while a move of its range is under way or claimed ([`claim_move`]). Both
/// are decided under this lock, so a call never turns to its copy on a chunk
/// whose move has begun, and a move never begins on a chunk a call copies.
/// A call that can wait without end (a blocking socket's or pipe's) goes
/// through a buffer of its own instead (`windows_fd`), so nothing waits on
/// it. A userfaultfd handler in the same process that discards a range a
/// call is waiting on it to fill would wait for that call (Firecracker's
/// handler is another process).
struct InFlight {
    calls: Vec<Call>,
    discards: Vec<(usize, usize)>,
    /// The reclaim's moves under way and claimed: preallocated
    /// ([`reserve_discards`]), as they are taken at the job's limit.
    moves: Vec<(usize, usize)>,
    /// The next call's number.
    next: u64,
}

/// A system call in flight on `[s, e)`, numbered, and whether it is in its
/// copy ([`InFlight`]).
#[derive(Clone, Copy)]
struct Call {
    s: usize,
    e: usize,
    id: u64,
    copy: bool,
}

static IN_FLIGHT: ProbedMutex<InFlight> =
    ProbedMutex::new("IN_FLIGHT", InFlight { calls: Vec::new(), discards: Vec::new(), moves: Vec::new(), next: 0 });
static IN_FLIGHT_CHANGED: std::sync::Condvar = std::sync::Condvar::new();

fn any_overlaps(ranges: &[(usize, usize)], s: usize, e: usize) -> bool {
    ranges.iter().any(|&(a, z)| a < e && s < z)
}

/// Whether a call in its copy overlaps `[s, e)`.
fn any_copy_overlaps(calls: &[Call], s: usize, e: usize) -> bool {
    calls.iter().any(|c| c.copy && c.s < e && s < c.e)
}

/// Whether a call in either phase overlaps `[s, e)`.
fn any_call_overlaps(calls: &[Call], s: usize, e: usize) -> bool {
    calls.iter().any(|c| c.s < e && s < c.e)
}

fn forget(ranges: &mut Vec<(usize, usize)>, range: (usize, usize)) {
    if let Some(i) = ranges.iter().position(|&r| r == range) {
        ranges.swap_remove(i);
    }
}

/// A system call in flight on `[.0, .1)`, number `.2` ([`copying`]), until
/// dropped.
pub(crate) struct Copying(usize, usize, u64);

impl Copying {
    /// The call's turn to its copy, right before its system call: from here
    /// a move of a chunk its buffer overlaps is passed over (the reclaim's,
    /// [`try_move`]) or waits for it (a fill's or a touch's, which claim the
    /// chunk first, [`Moving::wait_for_copies`]). Waits first while a move
    /// of an overlapping range is under way or claimed, so the copy never
    /// runs on a chunk's view while it is a placeholder for the move's swap,
    /// and a claim's wait is only for the calls that were in their copy when
    /// it was made. The check and the mark are made under one lock, with the
    /// move's check and its mark ([`try_move`], [`claim_move`]).
    pub(crate) fn copy_now(&self) {
        let mut f = IN_FLIGHT.lock().unwrap();
        while any_overlaps(&f.moves, self.0, self.1) {
            #[cfg(test)]
            TURNS_THAT_WAITED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            f = f.wait_on(&IN_FLIGHT_CHANGED).unwrap();
        }
        let id = self.2;
        if let Some(c) = f.calls.iter_mut().find(|c| c.id == id) {
            c.copy = true;
        }
    }
}

/// The claims that waited for a call in its copy
/// ([`Moving::wait_for_copies`]), for the tests.
#[cfg(test)]
pub(crate) static CLAIMS_THAT_WAITED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The turns to a copy that waited for a move ([`Copying::copy_now`]), for
/// the tests.
#[cfg(test)]
pub(crate) static TURNS_THAT_WAITED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

impl Drop for Copying {
    fn drop(&mut self) {
        IN_CALL.set(IN_CALL.get() - 1);
        let mut f = IN_FLIGHT.lock().unwrap();
        let id = self.2;
        if let Some(i) = f.calls.iter().position(|c| c.id == id) {
            f.calls.swap_remove(i);
        }
        drop(f);
        IN_FLIGHT_CHANGED.notify_all();
    }
}

/// A discard of `[.0, .1)` that no call in flight overlaps
/// ([`discard_waiting`]), until dropped.
pub(crate) struct Discarding(usize, usize);

impl Drop for Discarding {
    fn drop(&mut self) {
        forget(&mut IN_FLIGHT.lock().unwrap().discards, (self.0, self.1));
        IN_FLIGHT_CHANGED.notify_all();
    }
}

/// A move of `[.0, .1)` under way or claimed ([`try_move`],
/// [`claim_move`]), until dropped: a call's turn to its copy on that range
/// waits meanwhile ([`Copying::copy_now`]).
pub(crate) struct Moving(usize, usize);

impl Moving {
    /// Waits until no call in its copy overlaps the claimed range. The
    /// calls in their copy when the claim was made end on their own (only
    /// calls that end are counted: `windows_fd`), and no call turns to its
    /// copy on the range while the claim lives, so the wait is for those
    /// calls' copies at most. Allocates nothing; the caller holds none of
    /// the userfaultfd's locks.
    pub(crate) fn wait_for_copies(&self) {
        let mut f = IN_FLIGHT.lock().unwrap();
        #[cfg(test)]
        if any_copy_overlaps(&f.calls, self.0, self.1) {
            CLAIMS_THAT_WAITED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
        while any_copy_overlaps(&f.calls, self.0, self.1) {
            f = f.wait_on(&IN_FLIGHT_CHANGED).unwrap();
        }
    }
}

impl Drop for Moving {
    fn drop(&mut self) {
        forget(&mut IN_FLIGHT.lock().unwrap().moves, (self.0, self.1));
        IN_FLIGHT_CHANGED.notify_all();
    }
}

/// Counts a system call copying `[addr, addr + len)` in flight ([`InFlight`]),
/// in its prefault, once no discard of an overlapping range waits.
pub(crate) fn copying(addr: usize, len: usize) -> Copying {
    let (s, e) = (addr, addr.saturating_add(len));
    let mut f = IN_FLIGHT.lock().unwrap();
    while any_overlaps(&f.discards, s, e) {
        f = f.wait_on(&IN_FLIGHT_CHANGED).unwrap();
    }
    let id = f.next;
    f.next += 1;
    f.calls.push(Call { s, e, id, copy: false });
    IN_CALL.set(IN_CALL.get() + 1);
    Copying(s, e, id)
}

/// A move's guard for `[addr, addr + len)`, if no system call copying
/// memory of it is in its copy now (one in its prefault does not hold a
/// move: [`InFlight`]); `None` without waiting if one is. Allocates nothing
/// (the reclaim's: [`reserve_discards`]): with no room left for a guard,
/// `None` as for a call in its copy.
pub(crate) fn try_move(addr: usize, len: usize) -> Option<Moving> {
    let (s, e) = (addr, addr.saturating_add(len));
    let mut f = IN_FLIGHT.lock().unwrap();
    if any_copy_overlaps(&f.calls, s, e) || f.moves.len() == f.moves.capacity() {
        return None;
    }
    f.moves.push((s, e));
    Some(Moving(s, e))
}

/// Claims a move of `[addr, addr + len)` without waiting: from here no call
/// turns to its copy on it ([`Copying::copy_now`]); the calls already in
/// their copy are waited for with [`Moving::wait_for_copies`]. Allocates
/// nothing ([`reserve_discards`]): `None` with no room left for a guard.
pub(crate) fn claim_move(addr: usize, len: usize) -> Option<Moving> {
    let (s, e) = (addr, addr.saturating_add(len));
    let mut f = IN_FLIGHT.lock().unwrap();
    if f.moves.len() == f.moves.capacity() {
        return None;
    }
    f.moves.push((s, e));
    Some(Moving(s, e))
}

/// The room for the reclaim's guards, reserved when a userfaultfd range is
/// registered: a pass's move, a touch's wait and a fill's claims
/// ([`FILL_CLAIMS`]) of up to 64 threads at once, and the discards of as
/// many threads, which may then grow the list as they did; whether the
/// room is there.
pub(crate) fn reserve_discards() -> bool {
    const ROOM: usize = 64;
    let mut f = IN_FLIGHT.lock().unwrap();
    let more = ROOM.saturating_sub(f.discards.capacity() - f.discards.len());
    let moves = (ROOM + FILL_CLAIMS).saturating_sub(f.moves.capacity() - f.moves.len());
    // Under the fallible guard: a refusal is answered (`ENOMEM`), not the
    // process's end (`wick_alloc`).
    crate::wick_alloc::fallible(|| {
        (more == 0 || f.discards.try_reserve(more).is_ok()) && (moves == 0 || f.moves.try_reserve(moves).is_ok())
    })
}

/// The most chunks one fill refused at the job's limit claims at once
/// (`windows_uffd`'s fill: the chunks its reclaim passed over for calls in
/// their copy, waited for and moved).
pub(crate) const FILL_CLAIMS: usize = 8;

/// Whether this thread is in a system call counted in flight
/// ([`copying`]): a reclaim it starts must not wait for calls in flight
/// (`wick_uffd::reclaim_at_touch`), its own among them.
pub(crate) fn in_a_call() -> bool {
    IN_CALL.get() != 0
}

std::thread_local! {
    /// The calls in flight this thread counts ([`Copying`]).
    static IN_CALL: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Waits until no system call copying memory of `[addr, addr + len)` is in
/// flight ([`InFlight`]); calls on the range wait while the result lives.
pub(crate) fn discard_waiting(addr: usize, len: usize) -> Discarding {
    let (s, e) = (addr, addr.saturating_add(len));
    let mut f = IN_FLIGHT.lock().unwrap();
    f.discards.push((s, e));
    while any_call_overlaps(&f.calls, s, e) {
        f = f.wait_on(&IN_FLIGHT_CHANGED).unwrap();
    }
    Discarding(s, e)
}

/// Whether any of `[addr, addr + len)` is memory this module mapped, the
/// only memory a discard reaches ([`InFlight`]).
pub(crate) fn mapped(addr: usize, len: usize) -> bool {
    let end = addr.saturating_add(len);
    // The regions do not overlap: the last one starting below `end` ends
    // last of those.
    len != 0 && table().lock().unwrap().range(..end).next_back().is_some_and(|(b, r)| b + r.len > addr)
}

/// Whether a system call could write (`write`) or read all of `[addr,
/// addr + len)` once its pages are faulted in (`wick_uffd::prefault`):
/// committed, not a guard page, with a protection that allows it. A call
/// made through a buffer of its own (`windows_fd`) asks, after the prefault
/// and before the call, so that a buffer Linux's copy would fail with
/// `EFAULT` fails so here, and not in a fault of the copy to or from it.
pub(crate) fn accessible(addr: usize, len: usize, write: bool) -> bool {
    let end = addr.saturating_add(len);
    let mut at = addr;
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: queries this process's memory.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return false;
        }
        let p = mbi.Protect;
        let writes = [PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY];
        let reads = [PAGE_READONLY, PAGE_EXECUTE_READ];
        let base = p & 0xff;
        let ok = mbi.State == MEM_COMMIT
            && p & PAGE_GUARD == 0
            && (writes.contains(&base) || (!write && reads.contains(&base)));
        if !ok {
            return false;
        }
        at = mbi.BaseAddress as usize + mbi.RegionSize;
    }
    true
}

/// `madvise`. Discarding registered userfaultfd memory makes the pages of
/// what was discarded missing again (`wick_uffd::discarding`), as on Linux.
/// A discard waits for the system calls in flight on its range
/// ([`InFlight`]).
///
/// # Safety
/// Same contract as `madvise(2)`.
pub unsafe fn madvise(addr: *mut c_void, len: size_t, advice: c_int) -> c_int {
    let _discard = (advice == MADV_DONTNEED || advice == MADV_FREE)
        .then(|| discard_waiting(addr as usize, len.div_ceil(PAGE) * PAGE));
    // Every discard goes through the userfaultfd's side, registered memory
    // or not: one that finds no range in reach is counted as a change
    // without its lock, which a register waits for (`wick_uffd::discarding`).
    if advice == MADV_DONTNEED || advice == MADV_FREE {
        let end = (addr as usize).saturating_add(len.div_ceil(PAGE) * PAGE);
        return crate::wick_uffd::discarding(addr as u64, (end - addr as usize) as u64, |done| {
            // SAFETY: the caller's contract.
            unsafe { madvise_plain(addr, len, advice, done) }
        });
    }
    // SAFETY: the caller's contract.
    unsafe { madvise_plain(addr, len, advice, &mut Vec::new()) }
}

/// The parts of `[s, e)` of the region at `b` that are mapped (not its holes).
fn mapped_parts(r: &Region, b: usize, s: usize, e: usize) -> Vec<(usize, usize)> {
    let mut parts = Vec::new();
    let mut at = s;
    for &(off, n) in &r.holes {
        let (hs, he) = (b + off, b + off + n);
        if he <= at || hs >= e {
            continue;
        }
        if hs > at {
            parts.push((at, hs));
        }
        at = at.max(he);
    }
    if at < e {
        parts.push((at, e));
    }
    parts
}

/// `madvise` without the userfaultfd side; `done` gets the pieces a
/// `MADV_DONTNEED` or `MADV_FREE` discarded.
///
/// As Linux (mm/madvise.c): `EINVAL` for an unknown advice, an unaligned
/// start or a length that wraps; 0 for no length; the advice goes to each
/// mapped part in turn and, if part of the range is not mapped, `ENOMEM`
/// after; an error stops the walk, the parts before it advised. Large pages
/// are Linux's hugetlb: a discard's start must be a whole large page
/// (`EINVAL`), its end is rounded down to one, and `MADV_FREE` is `EINVAL`.
///
/// # Safety
/// Same contract as `madvise(2)`.
unsafe fn madvise_plain(addr: *mut c_void, len: size_t, advice: c_int, done: &mut Vec<(u64, u64)>) -> c_int {
    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_DONTFORK | MADV_DOFORK
        | MADV_MERGEABLE | MADV_UNMERGEABLE | MADV_HUGEPAGE | MADV_NOHUGEPAGE | MADV_DONTDUMP
        | MADV_DODUMP | MADV_WILLNEED | MADV_DONTNEED | MADV_FREE => {}
        _ => return fail(crate::EINVAL, -1),
    }
    let start = addr as usize;
    if !start.is_multiple_of(PAGE) {
        return fail(crate::EINVAL, -1);
    }
    let Some(end) = len.checked_next_multiple_of(PAGE).and_then(|n| start.checked_add(n)) else {
        return fail(crate::EINVAL, -1);
    };
    if end == start {
        return 0;
    }
    let t = table().lock().unwrap();
    let mut unmapped = !covered(&t, start, end);
    let discard = advice == MADV_DONTNEED || advice == MADV_FREE;
    for b in overlapping(&t, start, end) {
        let r = &t[&b];
        let (s, e) = (start.max(b), end.min(b + r.len));
        let parts = mapped_parts(r, b, s, e);
        if parts.iter().map(|(a, z)| z - a).sum::<usize>() != e - s {
            unmapped = true;
        }
        for (s, e) in parts {
            // Linux's `VM_HUGEPAGE` on the range: what a first access to its
            // lazy memory commits (`GRAINS`). Large pages are hugetlb's,
            // which the advice does not change.
            if (advice == MADV_HUGEPAGE || advice == MADV_NOHUGEPAGE) && !matches!(r.kind, Kind::Large { .. }) {
                set_grain(s, e - s, if advice == MADV_HUGEPAGE { HUGE_PAGE } else { 0 });
            }
            if advice == MADV_WILLNEED {
                let range = WIN32_MEMORY_RANGE_ENTRY { VirtualAddress: s as *mut c_void, NumberOfBytes: e - s };
                // SAFETY: prefetches our mapping; advisory.
                unsafe { PrefetchVirtualMemory(proc(), 1, &range, 0) };
            }
            if !discard {
                continue;
            }
            // SAFETY: the caller's contract, for this part.
            if let Err(errno) = unsafe { discard_part(r, b, s, e, advice, done) } {
                return fail(errno, -1);
            }
        }
    }
    if unmapped {
        return fail(crate::ENOMEM, -1);
    }
    0
}

/// `MADV_DONTNEED` or `MADV_FREE` of `[s, e)`, a mapped part of the region at
/// `b`; what it discarded goes to `done`.
///
/// # Safety
/// Same contract as `madvise(2)`.
unsafe fn discard_part(
    r: &Region,
    b: usize,
    s: usize,
    e: usize,
    advice: c_int,
    done: &mut Vec<(u64, u64)>,
) -> Result<(), c_int> {
    match &r.kind {
        Kind::Large { page, fresh, .. } => {
            // Locked large pages cannot be dropped: they are zeroed in place,
            // whole pages only, as Linux drops whole huge pages (pages never
            // writable are zeros still).
            if advice == MADV_FREE || !(s - b).is_multiple_of(*page) {
                return Err(crate::EINVAL);
            }
            let e = b + (e - b) / page * page;
            if e > s {
                if !fresh {
                    zero_large(s, e - s);
                }
                done.push((s as u64, e as u64));
            }
            Ok(())
        }
        Kind::Private { file } => {
            // SAFETY: the caller's contract.
            unsafe { discard_private(b, s, e, file.as_ref()) }?;
            done.push((s as u64, e as u64));
            Ok(())
        }
        // Shared views keep their pages, which hold the file's (or the
        // userfaultfd's, which discards them itself) contents.
        _ => {
            done.push((s as u64, e as u64));
            Ok(())
        }
    }
}

/// Drops the pages of `[s, e)` of the private mapping at `b`, which read as
/// zeros again, or as the file's contents for a private file mapping.
///
/// # Safety
/// Same contract as `madvise(2)`.
unsafe fn discard_private(b: usize, s: usize, e: usize, file: Option<&(Arc<Owned>, i64)>) -> Result<(), c_int> {
    // Run by run of equal protection, restored after.
    let mut at = s;
    while at < e {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: queries our memory.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }
            == 0
        {
            return Err(crate::ENOMEM);
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
        if mbi.State != MEM_COMMIT {
            // Mapped `PROT_NONE` and decommitted: no pages to drop.
            at += run;
            continue;
        }
        // Cleared first, as for a fixed mapping over lazy memory.
        touched_mark(at, run, false);
        // SAFETY: drops the pages of our private memory.
        unsafe { VirtualFree(at as *mut c_void, run, MEM_DECOMMIT) };
        // Lazy memory gets zero pages again at its next access.
        if !lazy_within(at, run).is_empty() {
            at += run;
            continue;
        }
        if !commit(at, run, PAGE_READWRITE, false) {
            return Err(crate::ENOMEM);
        }
        if let Some((f, off)) = file {
            let from = *off + i64::try_from(at - b).unwrap();
            if !fill_from_file(at, run, f.0, from) {
                return Err(crate::EIO);
            }
        }
        protect(at, run, mbi.Protect);
        at += run;
    }
    Ok(())
}

/// `mincore`: 1 for pages in the working set.
///
/// # Safety
/// `vec` must have room for one byte per page.
pub unsafe fn mincore(addr: *mut c_void, len: size_t, vec: *mut c_uchar) -> c_int {
    let start = addr as usize;
    if !start.is_multiple_of(PAGE) {
        return fail(crate::EINVAL, -1);
    }
    let pages = len.div_ceil(PAGE);
    {
        let t = table().lock().unwrap();
        if !covered(&t, start, start + pages * PAGE) {
            return fail(crate::ENOMEM, -1);
        }
    }
    // SAFETY: the caller's contract: one byte per page.
    let out = unsafe { std::slice::from_raw_parts_mut(vec, pages) };
    out.fill(0);
    if !working_set_bits(start, out) {
        return crate::windows_fd::raw_failed();
    }
    0
}

/// Sets bit 0 of `out[i]` if page `i` from `start` is in the working set
/// (`QueryWorkingSetEx`'s `Valid`), leaving it clear otherwise and the
/// other bits as they are; `false`, with the error in `GetLastError`, if
/// the query fails. Takes no lock ([`mincore`] takes the region table's to
/// check the range; [`uffd_alias`] holds it).
fn working_set_bits(start: usize, out: &mut [u8]) -> bool {
    const BATCH: usize = 512;
    let pages = out.len();
    let mut info: std::vec::Vec<PSAPI_WORKING_SET_EX_INFORMATION> = std::vec::Vec::new();
    let mut i = 0;
    while i < pages {
        let n = (pages - i).min(BATCH);
        info.clear();
        for k in 0..n {
            // SAFETY: an all-zero entry with an address is a valid query.
            let mut e: PSAPI_WORKING_SET_EX_INFORMATION = unsafe { std::mem::zeroed() };
            e.VirtualAddress = (start + (i + k) * PAGE) as *mut c_void;
            info.push(e);
        }
        let bytes =
            u32::try_from(n * std::mem::size_of::<PSAPI_WORKING_SET_EX_INFORMATION>()).unwrap();
        // SAFETY: the buffer holds `n` entries.
        if unsafe { QueryWorkingSetEx(proc(), info.as_mut_ptr().cast(), bytes) } == 0 {
            return false;
        }
        for (k, e) in info.iter().enumerate() {
            // SAFETY: reads the flags of the union.
            let valid = unsafe { e.VirtualAttributes.Flags } & 1;
            out[i + k] = (out[i + k] & !1) | u8::from(valid != 0);
        }
        i += n;
    }
    true
}

/// `msync`.
///
/// # Safety
/// Same contract as `msync(2)`.
pub unsafe fn msync(addr: *mut c_void, len: size_t, flags: c_int) -> c_int {
    let start = addr as usize;
    if !start.is_multiple_of(PAGE) || flags & !(MS_ASYNC | MS_SYNC | MS_INVALIDATE) != 0 {
        return fail(crate::EINVAL, -1);
    }
    let end = start + len.div_ceil(PAGE) * PAGE;
    let t = table().lock().unwrap();
    if !covered(&t, start, end) {
        return fail(crate::ENOMEM, -1);
    }
    for b in overlapping(&t, start, end) {
        let r = &t[&b];
        let (s, e) = (start.max(b), end.min(b + r.len));
        if let Kind::View { file, .. } = &r.kind {
            // SAFETY: flushes our view.
            if unsafe { FlushViewOfFile(s as *const c_void, e - s) } == 0 {
                return crate::windows_fd::raw_failed();
            }
            if let (true, Some(f)) = (flags & MS_SYNC != 0, file) {
                // SAFETY: flushes the file of our view.
                unsafe { FlushFileBuffers(f.0) };
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // A run that ends before the range asked about is not in it, and its
    // length is not worked out (`then_some` did, and a debug build panicked
    // with an overflow: in the list of discarded pages a released
    // userfaultfd range had, under the vectored exception handler, that
    // ended the process; PC step 14f; that list is its record's bits now).
    #[test]
    fn test_a_run_before_the_range_asked_about_is_not_in_it() {
        assert_eq!(ranges_within(&std::vec![(0, 0x1000), (0x3000, 0x1000)], 0x2000, 0x1000), Ranges::new());
        assert_eq!(ranges_within(&std::vec![(0, 0x1000), (0x2000, 0x2000)], 0x3000, 0x2000), std::vec![(0x3000, 0x1000)]);
    }

    /// The tests below place mappings at addresses they freed a moment
    /// before, and check that freed ranges are no longer mapped: another
    /// test mapping memory in parallel could take those addresses, so
    /// they run one at a time.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn map(addr: usize, len: usize, prot: c_int, flags: c_int, fd: c_int, off: i64) -> usize {
        // SAFETY: test mappings, unmapped by the tests.
        let p = unsafe { mmap(addr as *mut c_void, len, prot, flags, fd, off) };
        assert_ne!(p, MAP_FAILED, "{}", std::io::Error::last_os_error());
        p as usize
    }

    const ANON: c_int = MAP_PRIVATE | MAP_ANONYMOUS;

    /// `madvise`'s range and errors are Linux's (mm/madvise.c): `EINVAL` for
    /// an unknown advice, an unaligned start or a length that wraps; 0 for
    /// no length; the mapped parts are advised and `ENOMEM` follows for the
    /// rest, a hole or the end of the mapping.
    #[test]
    fn test_madvise_range_as_linux() {
        let _serial = serial();
        let errno = || std::io::Error::last_os_error().raw_os_error();
        let m = map(0, 4 * PAGE, PROT_READ | PROT_WRITE, ANON, -1, 0);
        // SAFETY: our mapping, and the pages of it each check leaves mapped.
        unsafe {
            for i in 0..4u8 {
                *((m + usize::from(i) * PAGE) as *mut u8) = 1 + i;
            }
            assert_eq!(madvise((m + 1) as *mut c_void, PAGE, MADV_DONTNEED), -1, "unaligned");
            assert_eq!(errno(), Some(crate::EINVAL));
            assert_eq!(madvise(m as *mut c_void, usize::MAX - PAGE, MADV_DONTNEED), -1, "wraps");
            assert_eq!(errno(), Some(crate::EINVAL));
            assert_eq!(madvise(m as *mut c_void, PAGE, 999), -1, "unknown advice");
            assert_eq!(errno(), Some(crate::EINVAL));
            assert_eq!(madvise(m as *mut c_void, 0, MADV_DONTNEED), 0);
            assert_eq!(*(m as *const u8), 1, "nothing discarded");
            // A hole: the pages on either side of it are discarded, then ENOMEM.
            assert_eq!(munmap((m + PAGE) as *mut c_void, PAGE), 0);
            for advice in [MADV_NORMAL, MADV_WILLNEED] {
                assert_eq!(madvise(m as *mut c_void, 3 * PAGE, advice), -1, "advice {advice}");
                assert_eq!(errno(), Some(crate::ENOMEM));
            }
            assert_eq!(*(m as *const u8), 1);
            assert_eq!(madvise(m as *mut c_void, 3 * PAGE, MADV_DONTNEED), -1, "hole");
            assert_eq!(errno(), Some(crate::ENOMEM));
            assert_eq!(*(m as *const u8), 0, "before the hole");
            assert_eq!(*((m + 2 * PAGE) as *const u8), 0, "after the hole");
            assert_eq!(*((m + 3 * PAGE) as *const u8), 4, "past the range");
            // The end of the mapping: the mapped page is discarded, then ENOMEM.
            *((m + 2 * PAGE) as *mut u8) = 5;
            assert_eq!(munmap((m + 3 * PAGE) as *mut c_void, PAGE), 0);
            assert_eq!(madvise((m + 2 * PAGE) as *mut c_void, 2 * PAGE, MADV_DONTNEED), -1, "past the end");
            assert_eq!(errno(), Some(crate::ENOMEM));
            assert_eq!(*((m + 2 * PAGE) as *const u8), 0);
            assert_eq!(munmap(m as *mut c_void, 4 * PAGE), 0);
        }
    }

    fn runs(addr: usize, len: usize) -> Vec<(usize, usize, bool)> {
        let mut v = Vec::new();
        zero_runs(addr, len, |s, n, z| v.push((s, n, z)));
        v
    }

    fn touched_bit(addr: usize) -> Option<bool> {
        let map = TOUCHED.read().unwrap();
        let (b, t) = map.range(..=addr).next_back().filter(|(b, t)| addr < **b + t.len)?;
        Some(t.get((addr - b) / PAGE))
    }

    /// `zero_runs` names the pages of lazy memory a host read can take as
    /// zeros without touching them: the accessible ones not committed. What
    /// was written, what is `PROT_NONE` or unmapped (a read faults, as on
    /// Linux) and memory that is not lazy are read as they are; nothing is
    /// committed by the call; the hint's bits follow commits and discards,
    /// and a wrong bit either way changes no answer.
    #[test]
    fn test_zero_runs_are_the_untouched_pages_of_lazy_memory() {
        let _serial = serial();
        let len = 1 << 20;
        let p = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        let at = |i: usize| p + i * PAGE;
        assert_eq!(runs(p + 100, 16 * PAGE), [(p + 100, 16 * PAGE, true)], "untouched");
        // SAFETY: our mapping.
        unsafe {
            *(at(3) as *mut u8) = 3;
            *(at(10) as *mut u8) = 10;
        }
        assert_eq!((touched_bit(at(3)), touched_bit(at(4))), (Some(true), Some(false)), "the commit set the bit");
        let want = [
            (p + 100, at(3) - p - 100, true),
            (at(3), PAGE, false),
            (at(4), 6 * PAGE, true),
            (at(10), PAGE, false),
            (at(11), p + 100 + 16 * PAGE - at(11), true),
        ];
        assert_eq!(runs(p + 100, 16 * PAGE), want);
        assert_eq!(committed(p, len), 2 * PAGE, "the call committed memory");
        // A bit wrongly clear: asked about, read as it is, set again.
        touched_mark(at(10), PAGE, false);
        assert_eq!(runs(p + 100, 16 * PAGE), want, "a clear bit lost data");
        assert_eq!(touched_bit(at(10)), Some(true));
        // A bit wrongly set: read as it is (a read would commit it, as before).
        touched_mark(at(20), PAGE, true);
        assert_eq!(runs(at(20), PAGE), [(at(20), PAGE, false)]);
        touched_mark(at(20), PAGE, false);
        assert_eq!(runs(at(20), PAGE), [(at(20), PAGE, true)]);
        // Discarded: zeros again.
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise(at(3) as *mut c_void, PAGE, MADV_DONTNEED) }, 0);
        assert_eq!(touched_bit(at(3)), Some(false));
        assert_eq!(runs(at(3), PAGE), [(at(3), PAGE, true)]);
        // PROT_NONE and a hole: read, so that the read faults.
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(at(12) as *mut c_void, 2 * PAGE, PROT_NONE) }, 0);
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(at(15) as *mut c_void, PAGE) }, 0);
        assert_eq!(
            runs(at(11), 6 * PAGE),
            [(at(11), PAGE, true), (at(12), 2 * PAGE, false), (at(14), PAGE, true), (at(15), PAGE, false), (at(16), PAGE, true)]
        );
        assert_eq!(committed(p, len), PAGE);
        // Memory that is not lazy, and memory this module did not map.
        let q = map(0, 4 * PAGE, PROT_READ | PROT_WRITE, ANON, -1, 0);
        assert_eq!(runs(q, 4 * PAGE), [(q, 4 * PAGE, false)]);
        let heap = std::vec![0u8; 3 * PAGE];
        assert_eq!(runs(heap.as_ptr() as usize, heap.len()), [(heap.as_ptr() as usize, heap.len(), false)]);
        // Across lazy memory's end into other memory.
        assert_eq!(runs(at(255), 2 * PAGE).first(), Some(&(at(255), PAGE, true)));
        // SAFETY: our mappings.
        unsafe {
            assert_eq!(munmap(q as *mut c_void, 4 * PAGE), 0);
            assert_eq!(munmap(p as *mut c_void, len), 0);
        }
        assert_eq!(touched_bit(p), None, "the hint outlived its allocation");
        assert_eq!(runs(p, PAGE), [(p, PAGE, false)]);
    }

    fn state(addr: usize) -> u32 {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        assert_ne!(unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
        mbi.State
    }

    /// Committed bytes of `[p, p + len)`, as the kernel reports them.
    fn committed(p: usize, len: usize) -> usize {
        let mut at = p;
        let mut n = 0;
        while at < p + len {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            assert_ne!(unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
            let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(p + len) - at;
            if mbi.State == MEM_COMMIT {
                n += run;
            }
            at += run;
        }
        n
    }

    /// What Firecracker does with a virtio-mem slot, on lazy memory, as
    /// Linux does it (mm/mprotect.c `change_protection` changes the pages
    /// present only; mm/madvise.c `MADV_DONTNEED` zaps them):
    /// - start-up makes the unplugged slot `PROT_NONE`: nothing committed;
    /// - a plug makes it accessible: nothing committed until touched;
    /// - an unplug makes it `PROT_NONE`, the data kept, then discards it:
    ///   its commit is given back, and an access is a fault, not a commit;
    /// - plugged again: zeros, committed at the access.
    #[test]
    fn test_mprotect_keeps_noreserve_memory_lazy() {
        let _serial = serial();
        let len = 8 << 20;
        let p = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        // Start-up: the slot (the upper half) is PROT_NONE.
        let (slot, n) = (p + len / 2, len / 2);
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(slot as *mut c_void, n, PROT_NONE) }, 0);
        assert_eq!(committed(p, len), 0, "mprotect(PROT_NONE) committed memory");
        assert_eq!(wick_mm::commit_on_access(slot, false), Access::NotLazy, "a PROT_NONE access committed");
        assert_eq!(committed(p, len), 0);
        // The lower half is still lazy and writable.
        // SAFETY: our mapping.
        unsafe { *(p as *mut u8) = 1 };
        assert_eq!(committed(p, len), PAGE);
        // Plugged: accessible, nothing committed until touched.
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(slot as *mut c_void, n, PROT_READ | PROT_WRITE) }, 0);
        assert_eq!(committed(slot, n), 0, "mprotect(RW) committed memory");
        for off in (0..2 << 20).step_by(PAGE) {
            // SAFETY: our mapping.
            unsafe { *((slot + off) as *mut u8) = 0xa5 };
        }
        assert_eq!(committed(slot, n), 2 << 20);
        // Unplugged: PROT_NONE keeps the data and its commit ...
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(slot as *mut c_void, n, PROT_NONE) }, 0);
        assert_eq!(committed(slot, n), 2 << 20, "mprotect(PROT_NONE) dropped data");
        assert_eq!(wick_mm::commit_on_access(slot, false), Access::NotLazy, "a PROT_NONE access ran");
        // ... and the discard gives the commit back.
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise(slot as *mut c_void, n, MADV_DONTNEED) }, 0);
        assert_eq!(committed(slot, n), 0, "MADV_DONTNEED kept the commit");
        assert_eq!(wick_mm::commit_on_access(slot, false), Access::NotLazy);
        assert_eq!(committed(slot, n), 0);
        // Plugged again: zeros, committed at the access.
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(slot as *mut c_void, n, PROT_READ | PROT_WRITE) }, 0);
        assert_eq!(committed(slot, n), 0);
        // SAFETY: our mapping.
        assert_eq!(unsafe { *((slot + PAGE) as *const u8) }, 0, "the discarded slot kept its data");
        assert_eq!(committed(slot, n), PAGE);
        // The lower half kept its byte throughout.
        // SAFETY: our mapping.
        assert_eq!(unsafe { *(p as *const u8) }, 1);
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(p as *mut c_void, len) }, 0);
        assert!(lazy_within(p, len).is_empty());
    }

    /// Asked again (`wick_mm::commit_block_on_access_again`, WHP's run loop
    /// at an exit on a page it committed before), the commit answers a lazy
    /// page committed already `Present`, nothing committed, where the first
    /// ask answers `Committed` for it as for a page it commits; a page not
    /// committed (a discarded one) is committed as at a first ask; a
    /// `PROT_NONE` page and a write to read-only memory stay the fault they
    /// are (`NotLazy`), committed or not. In a range advised
    /// `MADV_HUGEPAGE`, a write asked again after a read committed its page
    /// alone commits the aligned 2 MiB, and is present only once all of it
    /// is. LAZYAGAIN lines.
    #[test]
    fn test_a_lazy_page_committed_before_is_present_when_asked_again() {
        let _serial = serial();
        let len = 4 * PAGE;
        let p = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        let mut said = std::vec::Vec::new();
        let mut ask = |what: &str, got: (Access, core::ops::Range<usize>), want: (Access, core::ops::Range<usize>)| {
            said.push(std::format!("{what}: {:?}", got.0));
            assert_eq!(got, want, "{what}");
        };
        ask("first, asked again", wick_mm::commit_block_on_access_again(p, false), (Access::Committed, p..p + PAGE));
        ask("committed, asked again", wick_mm::commit_block_on_access_again(p, true), (Access::Present, 0..0));
        ask("committed, a first ask", wick_mm::commit_block_on_access(p, true), (Access::Committed, p..p + PAGE));
        assert_eq!(committed(p, len), PAGE);
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise(p as *mut c_void, PAGE, MADV_DONTNEED) }, 0);
        assert_eq!(committed(p, len), 0);
        ask("discarded, asked again", wick_mm::commit_block_on_access_again(p, true), (Access::Committed, p..p + PAGE));
        assert_eq!(committed(p, len), PAGE);
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(p as *mut c_void, PAGE, PROT_READ) }, 0);
        ask("committed, read-only, written", wick_mm::commit_block_on_access_again(p, true), (Access::NotLazy, 0..0));
        ask("committed, read-only, read", wick_mm::commit_block_on_access_again(p, false), (Access::Present, 0..0));
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(p as *mut c_void, PAGE, PROT_NONE) }, 0);
        ask("committed, PROT_NONE, read", wick_mm::commit_block_on_access_again(p, false), (Access::NotLazy, 0..0));
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(p as *mut c_void, len) }, 0);
        // Advised MADV_HUGEPAGE: a read commits its page alone (the huge
        // zero page's analogue); a write to it asked again commits the
        // aligned 2 MiB still, as Linux's write after the huge zero page
        // allocates the huge page; asked again after that, present.
        let huge = 2 << 20;
        let hlen = 6 << 20;
        let h = map(0, hlen, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise(h as *mut c_void, hlen, MADV_HUGEPAGE) }, 0);
        let block = (h + huge).next_multiple_of(huge);
        let at = block + 3 * PAGE;
        ask("huge-advised, read", wick_mm::commit_block_on_access(at, false), (Access::Committed, at..at + PAGE));
        ask("huge-advised, read, then written asked again", wick_mm::commit_block_on_access_again(at, true), (Access::Committed, block..block + huge));
        assert_eq!(committed(block, huge), huge);
        ask("huge-advised, the block committed, written asked again", wick_mm::commit_block_on_access_again(at, true), (Access::Present, 0..0));
        std::eprintln!("LAZYAGAIN {}", said.join("; "));
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(h as *mut c_void, hlen) }, 0);
    }

    /// A first access commits a page; a write in a range advised
    /// `MADV_HUGEPAGE` the aligned 2 MiB around it if the lazy range holds
    /// all of it, and a read there a page (Linux's huge zero page) (as
    /// Linux maps a transparent huge page only there, mm/huge_memory.c
    /// `thp_vma_suitable_order`), else a page; `MADV_NOHUGEPAGE`, `munmap`
    /// and a `MAP_FIXED` mapping over the range take the advice away (Linux's
    /// `VM_HUGEPAGE` is the VMA's), `mprotect` keeps it. A record's grain
    /// (`wick_mm::record_grain`, kvm-ioctls' LAZYGRAIN) works the same way.
    #[test]
    fn test_madv_hugepage_is_what_a_first_access_commits() {
        let _serial = serial();
        let huge = 2 << 20;
        // 14 MiB and a page: five aligned 2 MiB blocks from `first` lie
        // wholly inside, and the last page's block reaches past the end
        // (the mapping starts on a 64 KiB boundary).
        let len = (14 << 20) + PAGE;
        let p = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        let first = (p + huge).next_multiple_of(huge);
        // Not advised: a page.
        assert_eq!(wick_mm::commit_on_access(first + 5 * PAGE, true), Access::Committed);
        assert_eq!(committed(p, len), PAGE);
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise(p as *mut c_void, len, MADV_HUGEPAGE) }, 0);
        // A whole aligned block inside: committed whole, and reported so.
        let at = first + huge + 7 * PAGE;
        assert_eq!(wick_mm::commit_block_on_access(at, true), (Access::Committed, first + huge..first + 2 * huge));
        assert_eq!(committed(first + huge, huge), huge);
        // The block holding the mapping's last page is not wholly inside: a page.
        let last = p + len - PAGE;
        assert_eq!(wick_mm::commit_block_on_access(last, true), (Access::Committed, last..last + PAGE));
        // A block partly committed already: the rest of it.
        assert_eq!(wick_mm::commit_on_access(first + PAGE, true), Access::Committed);
        assert_eq!(committed(first, huge), huge);
        // A write to read-only memory: nothing committed, a fault.
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect((first + 3 * huge) as *mut c_void, huge, PROT_READ) }, 0);
        assert_eq!(wick_mm::commit_on_access(first + 3 * huge, true), Access::NotLazy, "a write to read-only memory");
        assert_eq!(committed(first + 3 * huge, huge), 0);
        // A read: a page, as Linux's huge zero page charges nothing.
        assert_eq!(wick_mm::commit_block_on_access(first + 3 * huge, false), (Access::Committed, first + 3 * huge..first + 3 * huge + PAGE));
        assert_eq!(committed(first + 3 * huge, huge), PAGE);
        // mprotect kept the advice: writable again, a write commits the block.
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect((first + 3 * huge) as *mut c_void, huge, PROT_READ | PROT_WRITE) }, 0);
        assert_eq!(wick_mm::commit_on_access(first + 3 * huge + PAGE, true), Access::Committed);
        assert_eq!(committed(first + 3 * huge, huge), huge);
        // MADV_NOHUGEPAGE: a page again.
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise((first + 2 * huge) as *mut c_void, huge, MADV_NOHUGEPAGE) }, 0);
        assert_eq!(wick_mm::commit_on_access(first + 2 * huge, true), Access::Committed);
        assert_eq!(committed(first + 2 * huge, huge), PAGE);
        // A MAP_FIXED mapping over an advised block: a page.
        let over = map(first + 4 * huge, huge, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE | MAP_FIXED, -1, 0);
        assert_eq!(over, first + 4 * huge);
        assert_eq!(wick_mm::commit_on_access(over, true), Access::Committed);
        assert_eq!(committed(over, huge), PAGE);
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(p as *mut c_void, len) }, 0);
        assert!(!GRAINS.lock().unwrap().iter().any(|&(s, n, _)| s < p + len && p < s + n), "munmap kept the advice");
        // A record's grain, set and removed.
        let q = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        let block = (q + huge).next_multiple_of(huge);
        wick_mm::record_grain(q, len, 64 << 10);
        assert_eq!(wick_mm::commit_on_access(block + PAGE, true), Access::Committed);
        assert_eq!(committed(block, huge), 64 << 10);
        wick_mm::record_grain(q, len, 0);
        assert_eq!(wick_mm::commit_on_access(block + huge, true), Access::Committed);
        assert_eq!(committed(block + huge, huge), PAGE);
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(q as *mut c_void, len) }, 0);
    }

    /// Anonymous private `MAP_NORESERVE` memory gets its pages at the first
    /// access, a page at a time, as Linux gives them when touched:
    /// mapped, nothing is committed; a write commits its block only; a
    /// discarded block goes back to reserved and reads zero; the guest's
    /// access (the hypervisor's report) commits as a host access does; an
    /// `mprotect` commits nothing (test_mprotect_keeps_noreserve_memory_lazy).
    #[test]
    fn test_noreserve_memory_is_committed_at_first_access() {
        let _serial = serial();
        let len = 4 << 20;
        let p = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        assert_eq!(state(p), MEM_RESERVE, "committed at the mmap");
        assert_eq!(state(p + len - PAGE), MEM_RESERVE);
        // A host write: the exception handler commits the block.
        // SAFETY: our mapping.
        unsafe { *((p + (1 << 20) + 5) as *mut u8) = 7 };
        assert_eq!(state(p + (1 << 20)), MEM_COMMIT);
        assert_eq!(state(p + (1 << 20) + PAGE), MEM_RESERVE, "more than the page was committed");
        assert_eq!(state(p + (1 << 20) - PAGE), MEM_RESERVE, "more than the page was committed");
        // SAFETY: as above.
        assert_eq!(unsafe { *((p + (1 << 20) + 5) as *const u8) }, 7);
        // The guest's access, as WHP reports it.
        assert_eq!(wick_mm::commit_on_access(p + (2 << 20), true), Access::Committed);
        assert_eq!(state(p + (2 << 20)), MEM_COMMIT);
        // Committed meanwhile (another vCPU first): run again.
        // Discarded: reserved again, zero at the next read.
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise((p + (1 << 20)) as *mut c_void, PAGE, MADV_DONTNEED) }, 0);
        assert_eq!(state(p + (1 << 20)), MEM_RESERVE);
        // SAFETY: as above.
        assert_eq!(unsafe { *((p + (1 << 20) + 5) as *const u8) }, 0);
        // mprotect: nothing more committed; a read commits read-only.
        // SAFETY: as above.
        assert_eq!(unsafe { mprotect(p as *mut c_void, len, PROT_READ) }, 0);
        assert_eq!(state(p), MEM_RESERVE);
        assert_eq!(state(p + len - PAGE), MEM_RESERVE);
        assert_eq!(wick_mm::commit_on_access(p, false), Access::Committed);
        assert_eq!(state(p), MEM_COMMIT);
        assert_eq!(wick_mm::commit_on_access(p + 5, true), Access::NotLazy, "a write to read-only memory");
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(p as *mut c_void, len) }, 0);
        assert!(lazy_within(p, len).is_empty(), "the unmapped range is still lazy");
        // Without MAP_NORESERVE, and with MAP_POPULATE: committed at the mmap.
        let q = map(0, 1 << 20, PROT_READ | PROT_WRITE, ANON, -1, 0);
        assert_eq!(state(q), MEM_COMMIT);
        let r = map(0, 1 << 20, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE | MAP_POPULATE, -1, 0);
        assert_eq!(state(r), MEM_COMMIT);
        // SAFETY: our mappings.
        unsafe {
            assert_eq!(munmap(q as *mut c_void, 1 << 20), 0);
            assert_eq!(munmap(r as *mut c_void, 1 << 20), 0);
        }
    }

    /// In a process whose job may commit 64 MiB, a 256 MiB lazy mapping is
    /// made; 32 MiB of it are written; writing past the limit ends the
    /// process with the OOM exit code, as the cgroup OOM killer ends the VMM.
    #[test]
    fn test_memory_past_the_job_limit_ends_the_process() {
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        if std::env::var_os("WICK_LAZY_CHILD").is_some() {
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let child = std::process::Command::new(exe)
            .args(["--exact", "windows_mm::tests::lazy_child", "--ignored", "--nocapture"])
            .env("WICK_LAZY_CHILD", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // The job is set before the child maps anything (it sleeps 300 ms first).
        // SAFETY: a new unnamed job.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        assert!(!job.is_null());
        // SAFETY: plain data.
        let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
        limit.JobMemoryLimit = 64 << 20;
        // SAFETY: a structure of the size passed; the child's handle.
        unsafe {
            assert_ne!(
                SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const limit).cast(), std::mem::size_of_val(&limit) as u32),
                0
            );
            use std::os::windows::io::AsRawHandle;
            assert_ne!(AssignProcessToJobObject(job, child.as_raw_handle()), 0, "{}", std::io::Error::last_os_error());
        }
        let out = child.wait_with_output().unwrap();
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        // SAFETY: our job handle.
        unsafe { CloseHandle(job) };
        assert!(text.contains("mapped 256 MiB") && text.contains("wrote 32 MiB"), "{text}");
        assert!(!text.contains("wrote 256 MiB"), "the job's limit did not hold: {text}");
        assert!(text.contains("the memory limit"), "{text}");
        assert_eq!(out.status.code(), Some(OOM_EXIT as i32), "{text}");
    }

    /// The process's private commit (`PagefileUsage`), which a Job Object's
    /// memory limit charges.
    fn private_commit() -> usize {
        use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        // SAFETY: plain data.
        let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        c.cb = std::mem::size_of_val(&c) as u32;
        // SAFETY: an output structure of the size given.
        assert_ne!(unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) }, 0);
        c.PagefileUsage
    }

    /// Anonymous shared memory is a section reserved at the mmap, each page
    /// committed at its first access together with a page of private commit
    /// that pays for it ([`Charge`]), as Linux charges a shmem page to the
    /// cgroup when it is touched (mm/shmem.c v6.1:1738, :1862): mapped,
    /// nothing is committed and the private commit does not move; 1024
    /// pages written, those are committed and the private commit is up by
    /// as much; a read of an untouched page commits and charges it too, as
    /// Linux's shmem fault allocates for a read; the guest's access (WHP's
    /// report) commits as a host access does; the data is the section's
    /// through an `mprotect`; an `munmap` gives the charge back. Before,
    /// such memory was committed whole at the mmap and charged to no job.
    ///
    /// The checks run in a process of their own ([`charge_child`]):
    /// `PagefileUsage` is the whole process's, and in the crate's test
    /// process the other tests run beside this one on other threads, so
    /// what they free at the same time is netted out of it. CI run
    /// 43521200989 read 3012 KiB for the 1024 pages there, where the
    /// pages committed (`committed`) were the 1024 written. The charge's
    /// own reservation is checked too: one page of it committed for each
    /// page of the section, which no other thread's memory moves.
    #[test]
    fn test_anonymous_shared_memory_is_charged_at_first_touch() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args(["--exact", "windows_mm::tests::charge_child", "--ignored", "--nocapture"])
            .output()
            .unwrap();
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success() && text.contains("test result: ok. 1 passed"), "{text}");
    }

    /// The charge's reservation for the view at `p`: pages of it committed.
    fn charge_committed(p: usize) -> usize {
        let (base, n) = CHARGES.lock().unwrap().get(&p).map(|(n, c)| (c.base, *n)).expect("no charge for the view");
        committed(base, n)
    }

    #[test]
    #[ignore = "run by test_anonymous_shared_memory_is_charged_at_first_touch, in a process of its own"]
    fn charge_child() {
        let _serial = serial();
        let len = 16 << 20;
        let before = private_commit();
        let p = map(0, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        assert_eq!(state(p), MEM_RESERVE, "committed at the mmap");
        assert_eq!(committed(p, len), 0);
        assert_eq!(charge_committed(p), 0, "the charge committed at the mmap");
        let mapped = private_commit();
        assert!(mapped < before + (1 << 20), "the mmap charged {} KiB", (mapped - before) / 1024);
        for i in 0..1024 {
            // SAFETY: our mapping.
            unsafe { *((p + 2 * i * PAGE) as *mut u8) = (i % 251) as u8 + 1 };
        }
        assert_eq!(committed(p, len), 1024 * PAGE, "a write committed more or less than its page");
        assert_eq!(charge_committed(p), 1024 * PAGE, "the charge for 1024 pages written");
        let written = private_commit();
        assert!(
            written >= mapped + 1024 * PAGE,
            "1024 pages written charged {} KiB (private commit {} KiB at the start, {} KiB mapped, {} KiB written)",
            written.saturating_sub(mapped) / 1024,
            before / 1024,
            mapped / 1024,
            written / 1024
        );
        // A read of an untouched page.
        // SAFETY: as above.
        assert_eq!(unsafe { *((p + PAGE) as *const u8) }, 0);
        assert_eq!(state(p + PAGE), MEM_COMMIT);
        // The guest's access, as WHP reports it.
        assert_eq!(wick_mm::commit_on_access(p + 3 * PAGE, true), Access::Committed);
        assert_eq!(state(p + 3 * PAGE), MEM_COMMIT);
        // mprotect: nothing more committed, the data kept.
        // SAFETY: our mapping.
        assert_eq!(unsafe { mprotect(p as *mut c_void, len, PROT_READ) }, 0);
        assert_eq!(committed(p, len), 1026 * PAGE);
        assert_eq!(charge_committed(p), 1026 * PAGE, "the charge for a read and the guest's access");
        for i in 0..1024 {
            // SAFETY: as above.
            assert_eq!(unsafe { *((p + 2 * i * PAGE) as *const u8) }, (i % 251) as u8 + 1);
        }
        assert_eq!(wick_mm::commit_on_access(p + 5 * PAGE, true), Access::NotLazy, "a write to read-only memory");
        // Part unmapped: its pages fault; the rest stays.
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap((p + len / 2) as *mut c_void, len / 2) }, 0);
        assert!(lazy_within(p + len / 2, len / 2).is_empty(), "the unmapped part is still lazy");
        // SAFETY: as above.
        assert_eq!(unsafe { munmap(p as *mut c_void, len / 2) }, 0);
        let unmapped = private_commit();
        assert!(
            unmapped + 1024 * PAGE <= written + (1 << 20),
            "the charge outlived the mapping: {} KiB before, {} KiB written, {} KiB after",
            before / 1024,
            written / 1024,
            unmapped / 1024
        );
        assert!(!CHARGES.lock().unwrap().contains_key(&p), "the charge's registration outlived the mapping");
    }

    /// In a process whose job may commit 64 MiB, 256 MiB of anonymous shared
    /// memory is mapped; 32 MiB of it are written; writing past the limit
    /// ends the process with the OOM exit code, as the cgroup OOM killer
    /// ends a process whose shmem pages reach `memory.max`. Before, the
    /// whole section was committed at the mmap and no job charged it.
    #[test]
    fn test_shared_memory_past_the_job_limit_ends_the_process() {
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        if std::env::var_os("WICK_SHARED_CHILD").is_some() {
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let child = std::process::Command::new(exe)
            .args(["--exact", "windows_mm::tests::shared_child", "--ignored", "--nocapture"])
            .env("WICK_SHARED_CHILD", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // The job is set before the child maps anything (it sleeps 300 ms first).
        // SAFETY: a new unnamed job.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        assert!(!job.is_null());
        // SAFETY: plain data.
        let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
        limit.JobMemoryLimit = 64 << 20;
        // SAFETY: a structure of the size passed; the child's handle.
        unsafe {
            assert_ne!(
                SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const limit).cast(), std::mem::size_of_val(&limit) as u32),
                0
            );
            use std::os::windows::io::AsRawHandle;
            assert_ne!(AssignProcessToJobObject(job, child.as_raw_handle()), 0, "{}", std::io::Error::last_os_error());
        }
        let out = child.wait_with_output().unwrap();
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        // SAFETY: our job handle.
        unsafe { CloseHandle(job) };
        assert!(text.contains("mapped 256 MiB shared") && text.contains("wrote 32 MiB"), "{text}");
        assert!(!text.contains("wrote 256 MiB"), "the job's limit did not hold: {text}");
        assert!(text.contains("the memory limit"), "{text}");
        assert_eq!(out.status.code(), Some(OOM_EXIT as i32), "{text}");
    }

    /// A process that maps large pages through the jailer's broker (a
    /// jailed Firecracker, made to take that path here): this test is the
    /// jailer, answering each request with a large-page section duplicated
    /// into the child; the child maps guest memory as Firecracker does
    /// (`PROT_NONE`, then `MAP_FIXED` read-write over it) and finds large
    /// pages there. Needs "Lock pages in memory" (for the sections).
    #[test]
    fn test_hugetlb_through_the_broker() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
        use windows_sys::Win32::System::Pipes::CreatePipe;
        if std::env::var_os("WICK_BROKER_CHILD").is_some() {
            return;
        }
        if !lock_memory_privilege() || large_page(MAP_HUGE_2MB).is_none() {
            std::eprintln!("test_hugetlb_through_the_broker: this account lacks SeLockMemoryPrivilege; not run");
            return;
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let pipe = || {
            let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
            // SAFETY: out-parameters.
            assert_ne!(unsafe { CreatePipe(&mut r, &mut w, &sa, 0) }, 0);
            (r, w)
        };
        let ((req_r, req_w), (rep_r, rep_w)) = (pipe(), pipe());
        // Ours stay ours.
        // SAFETY: our handles.
        unsafe {
            SetHandleInformation(req_r, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(rep_w, HANDLE_FLAG_INHERIT, 0);
        }
        let exe = std::env::current_exe().unwrap();
        let child = std::process::Command::new(exe)
            .args(["--exact", "windows_mm::tests::broker_child", "--ignored", "--nocapture"])
            .env("WICK_BROKER_CHILD", "1")
            .env("WICK_LARGE_PAGES", std::format!("{},{}", req_w as usize, rep_r as usize))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // SAFETY: the child's ends, its own now.
        unsafe {
            CloseHandle(req_w);
            CloseHandle(rep_r);
        }
        let child_h = child.as_raw_handle() as usize;
        let (req_r, rep_w) = (req_r as usize, rep_w as usize);
        let jailer = std::thread::spawn(move || {
            let mut served = 0;
            loop {
                let mut len = [0u8; 8];
                let mut n = 0u32;
                // SAFETY: reads into our buffer.
                if unsafe { ReadFile(req_r as HANDLE, len.as_mut_ptr(), 8, &mut n, std::ptr::null_mut()) } == 0 || n != 8 {
                    break;
                }
                let len = u64::from_le_bytes(len);
                // SAFETY: a pagefile-backed large-page section.
                let s = unsafe {
                    CreateFileMappingW(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE | 0x0800_0000 | 0x8000_0000, (len >> 32) as u32, len as u32, std::ptr::null())
                };
                let mut out: HANDLE = std::ptr::null_mut();
                // SAFETY: duplicates our section into the child, closing ours.
                let ok = !s.is_null()
                    && unsafe { DuplicateHandle(GetCurrentProcess(), s, child_h as HANDLE, &mut out, 0, 0, DUPLICATE_SAME_ACCESS | 1) } != 0;
                let mut reply = [0u8; 12];
                if ok {
                    reply[..8].copy_from_slice(&(out as usize as u64).to_le_bytes());
                    served += 1;
                } else {
                    // SAFETY: plain call.
                    reply[8..].copy_from_slice(&unsafe { GetLastError() }.to_le_bytes());
                }
                // SAFETY: writes our buffer.
                unsafe { WriteFile(rep_w as HANDLE, reply.as_ptr(), 12, &mut n, std::ptr::null_mut()) };
            }
            served
        });
        let out = child.wait_with_output().unwrap();
        let served = jailer.join().unwrap();
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "{text}");
        assert!(text.contains("brokered large pages: ok"), "{text}");
        assert_eq!(served, 1, "sections served: one, for the read-write mapping: {text}");
    }

    #[test]
    #[ignore = "run by test_hugetlb_through_the_broker, with the broker's pipes"]
    fn broker_child() {
        FORCE_BROKER.store(true, std::sync::atomic::Ordering::SeqCst);
        let huge = ANON | MAP_NORESERVE | MAP_HUGE_2MB | MAP_HUGETLB;
        let len = 4 << 20;
        // Firecracker's guest memory: a PROT_NONE reservation, then MAP_FIXED over it.
        let base = map(0, len, PROT_NONE, huge, -1, 0);
        assert!(base.is_multiple_of(2 << 20), "not aligned to the large page: {base:#x}");
        let q = map(base, len, PROT_READ | PROT_WRITE, huge | MAP_FIXED, -1, 0);
        assert_eq!(q, base);
        // SAFETY: our mapping, read-write.
        unsafe {
            *(base as *mut u8) = 1;
            *((base + len - 1) as *mut u8) = 2;
            assert_eq!(*((base + len - 1) as *const u8), 2);
        }
        // SAFETY: an all-zero entry with an address is a valid query.
        let mut e: PSAPI_WORKING_SET_EX_INFORMATION = unsafe { std::mem::zeroed() };
        e.VirtualAddress = base as *mut c_void;
        // SAFETY: one entry of the size passed.
        assert_ne!(unsafe { QueryWorkingSetEx(proc(), (&raw mut e).cast(), std::mem::size_of_val(&e) as u32) }, 0);
        // SAFETY: reads the flags of the union.
        let flags = unsafe { e.VirtualAttributes.Flags };
        assert_ne!(flags & (1 << 23), 0, "not a large page (flags {flags:#x})");
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(base as *mut c_void, len) }, 0);
        std::println!("brokered large pages: ok");
    }

    #[test]
    #[ignore = "run by test_shared_memory_past_the_job_limit_ends_the_process in a job of its own"]
    fn shared_child() {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let len = 256 << 20;
        let p = map(0, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        std::println!("mapped 256 MiB shared");
        let write = |mib: usize| {
            for at in (0..mib << 20).step_by(PAGE) {
                // SAFETY: our mapping.
                unsafe { *((p + at) as *mut u8) = 1 };
            }
        };
        write(32);
        std::println!("wrote 32 MiB");
        write(256);
        std::println!("wrote 256 MiB");
    }

    #[test]
    #[ignore = "run by test_memory_past_the_job_limit_ends_the_process in a job of its own"]
    fn lazy_child() {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let len = 256 << 20;
        let p = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        std::println!("mapped 256 MiB");
        let write = |mib: usize| {
            for at in (0..mib << 20).step_by(PAGE) {
                // SAFETY: our mapping.
                unsafe { *((p + at) as *mut u8) = 1 };
            }
        };
        write(32);
        std::println!("wrote 32 MiB");
        write(256);
        std::println!("wrote 256 MiB");
    }

    #[test]
    fn test_firecracker_guest_memory_pattern() {
        let _serial = serial();
        // Reserve with PROT_NONE, trim head and tail, map the middle fixed.
        let len = 4 << 20;
        let p = map(0, len + (2 << 20), PROT_NONE, ANON | MAP_NORESERVE, -1, 0);
        let aligned = (p + (2 << 20) - 1) & !((2 << 20) - 1);
        // SAFETY: parts of our reservation.
        unsafe {
            if aligned > p {
                assert_eq!(munmap(p as *mut c_void, aligned - p), 0);
            }
            let tail = aligned + len;
            if p + len + (2 << 20) > tail {
                assert_eq!(munmap(tail as *mut c_void, p + len + (2 << 20) - tail), 0);
            }
        }
        let m = map(
            aligned,
            len,
            PROT_READ | PROT_WRITE,
            ANON | MAP_FIXED,
            -1,
            0,
        );
        assert_eq!(m, aligned);
        // SAFETY: our mapping.
        unsafe {
            *(m as *mut u8).add(100) = 7;
            // Unplug a slot: PROT_NONE anonymous over part, then plug again.
            let slot = m + (1 << 20);
            *(slot as *mut u8) = 9;
            map(
                slot,
                1 << 20,
                PROT_NONE,
                ANON | MAP_FIXED | MAP_NORESERVE,
                -1,
                0,
            );
            map(
                slot,
                1 << 20,
                PROT_READ | PROT_WRITE,
                ANON | MAP_FIXED | MAP_NORESERVE,
                -1,
                0,
            );
            assert_eq!(*(slot as *const u8), 0, "fresh zero pages");
            assert_eq!(*(m as *const u8).add(100), 7, "the rest is kept");
            // Discard.
            assert_eq!(madvise(m as *mut c_void, PAGE, MADV_DONTNEED), 0);
            assert_eq!(*(m as *const u8).add(100), 0);
            assert_eq!(mprotect(m as *mut c_void, PAGE, PROT_READ), 0);
            let mut v = [0u8; 4];
            assert_eq!(mincore(m as *mut c_void, 4 * PAGE, v.as_mut_ptr()), 0);
            assert_eq!(munmap(m as *mut c_void, len), 0);
            assert_eq!(mprotect(m as *mut c_void, PAGE, PROT_READ), -1, "unmapped");
        }
    }

    #[test]
    fn test_hotplug_slot_pattern() {
        let _serial = serial();
        // vstate/memory.rs: a slot is mapped PROT_NONE over part of the
        // guest memory, then plugged with mprotect and unplugged again.
        let len = 4 << 20;
        let m = map(0, len, PROT_READ | PROT_WRITE, ANON | MAP_NORESERVE, -1, 0);
        let slot = m + (1 << 20);
        // SAFETY: our mapping.
        unsafe {
            *(m as *mut u8) = 3;
            *(slot as *mut u8) = 9;
            map(
                slot,
                1 << 20,
                PROT_NONE,
                ANON | MAP_FIXED | MAP_NORESERVE,
                -1,
                0,
            );
            // Advice and protection across committed and decommitted pages.
            assert_eq!(madvise(m as *mut c_void, 2 << 20, MADV_DONTNEED), 0);
            assert_eq!(mprotect(m as *mut c_void, 2 << 20, PROT_NONE), 0);
            assert_eq!(
                mprotect(m as *mut c_void, 2 << 20, PROT_READ | PROT_WRITE),
                0
            );
            assert_eq!(*(m as *const u8), 0, "MADV_DONTNEED dropped the page");
            assert_eq!(*(slot as *const u8), 0, "plugged slot is zero-filled");
            *((slot + (1 << 20) - 1) as *mut u8) = 5;
            // Unplug: the protection lands on committed pages only.
            assert_eq!(mprotect(slot as *mut c_void, 1 << 20, PROT_NONE), 0);
            assert_eq!(
                mprotect(slot as *mut c_void, 1 << 20, PROT_READ | PROT_WRITE),
                0
            );
            assert_eq!(*((slot + (1 << 20) - 1) as *const u8), 5);
            assert_eq!(munmap(m as *mut c_void, len), 0);
        }
    }

    #[test]
    fn test_placeholder_becomes_memory_on_mprotect() {
        let _serial = serial();
        let p = map(0, 1 << 20, PROT_NONE, ANON, -1, 0);
        // SAFETY: our mapping.
        unsafe {
            assert_eq!(
                mprotect((p + PAGE) as *mut c_void, PAGE, PROT_READ | PROT_WRITE),
                0
            );
            *((p + PAGE) as *mut u8) = 1;
            assert_eq!(munmap(p as *mut c_void, 1 << 20), 0);
        }
    }

    #[test]
    fn test_pmem_backing_file() {
        // virtio-pmem: a file of whole 2 MiB maps as it is; another sits in
        // a private anonymous mapping rounded up to 2 MiB (MAP_FIXED over it).
        let _serial = serial();
        use std::os::windows::io::AsRawHandle;
        for (n, size) in [(0, 2usize << 20), (1, (2 << 20) + 3 * PAGE)] {
            let path = std::env::temp_dir().join(std::format!("wick-pmem-{}-{n}", std::process::id()));
            let f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.set_len(size as u64).unwrap();
            let fd = crate::windows_fd::to_fd_pub(f.as_raw_handle());
            let rw = PROT_READ | PROT_WRITE;
            let p = if size == 2 << 20 {
                map(0, size, rw, MAP_SHARED | MAP_NORESERVE, fd, 0)
            } else {
                let p = map(0, 4 << 20, rw, MAP_PRIVATE | MAP_NORESERVE | ANON, -1, 0);
                assert_eq!(
                    map(p, size, rw, MAP_SHARED | MAP_NORESERVE | MAP_FIXED, fd, 0),
                    p,
                    "file over the rounded-up mapping: {}",
                    std::io::Error::last_os_error()
                );
                p
            };
            // SAFETY: our mapping.
            unsafe {
                *(p as *mut u8) = 0x5a;
                // Past the file: the anonymous memory, committed at its first access.
                let tail = (p + size.next_multiple_of(2 << 20) - PAGE) as *mut u8;
                *tail = 0x77;
                assert_eq!(*tail, 0x77);
                assert_eq!(munmap(p as *mut c_void, size.next_multiple_of(2 << 20)), 0);
            }
            let mut b = [0u8; 1];
            std::io::Read::read_exact(&mut std::fs::File::open(&path).unwrap(), &mut b).unwrap();
            assert_eq!(b[0], 0x5a, "written to the file");
            drop(f);
            let _ = std::fs::remove_file(&path);
        }
    }

    /// An anonymous private mapping whose length is a multiple of 2 MiB is
    /// placed on a 2 MiB boundary when no hint places it, as Linux since 6.7
    /// (v6.12 mm/mmap.c :902 to :907; [`new_placeholder_aligned`]): 2, 4 and
    /// 128 MiB, committed and `MAP_NORESERVE`; each is mapped and usable.
    /// 3 MiB, a `MAP_SHARED` anonymous mapping of 4 MiB and a file mapping
    /// are made with no such requirement (PLACEMENT lines say where). A free
    /// hint 64 KiB past a boundary is taken as it is. With the aligned
    /// reservation refused (`REFUSE_ALIGNED_PLACEMENT`), a 4 MiB mapping is
    /// still made, anywhere.
    #[test]
    fn test_a_whole_2_mib_anonymous_mapping_is_placed_on_a_2_mib_boundary() {
        let _serial = serial();
        use std::io::Write;
        use std::os::windows::io::AsRawHandle;
        let mib = 1 << 20;
        let off = |p: usize| (p % HUGE_PAGE) >> 10;
        let touch_and_unmap = |p: usize, len: usize| {
            // SAFETY: our mapping, unmapped here.
            unsafe {
                std::ptr::write_volatile(p as *mut u8, 1);
                std::ptr::write_volatile((p + len - 1) as *mut u8, 2);
                assert_eq!(munmap(p as *mut c_void, len), 0);
            }
        };
        for (len, flags) in [(2 * mib, ANON), (4 * mib, ANON), (128 * mib, ANON), (2 * mib, ANON | MAP_NORESERVE), (128 * mib, ANON | MAP_NORESERVE)] {
            let p = map(0, len, PROT_READ | PROT_WRITE, flags, -1, 0);
            std::println!("PLACEMENT anonymous private {} MiB (flags {flags:#x}): {} KiB into its 2 MiB", len / mib, off(p));
            assert!(p.is_multiple_of(HUGE_PAGE), "{} MiB, flags {flags:#x}, at {p:#x}", len / mib);
            touch_and_unmap(p, len);
        }
        let p = map(0, 3 * mib, PROT_READ | PROT_WRITE, ANON, -1, 0);
        std::println!("PLACEMENT anonymous private 3 MiB: {} KiB into its 2 MiB", off(p));
        touch_and_unmap(p, 3 * mib);
        let p = map(0, 4 * mib, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        std::println!("PLACEMENT anonymous shared 4 MiB: {} KiB into its 2 MiB", off(p));
        touch_and_unmap(p, 4 * mib);
        let path = std::env::temp_dir().join(std::format!("wick-placement-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&path).unwrap();
        f.write_all(&std::vec![0x11u8; 2 * mib]).unwrap();
        let fd = crate::windows_fd::to_fd_pub(f.as_raw_handle());
        for (what, flags) in [("private", MAP_PRIVATE), ("shared", MAP_SHARED)] {
            let p = map(0, 2 * mib, PROT_READ | PROT_WRITE, flags, fd, 0);
            std::println!("PLACEMENT a file's {what} 2 MiB: {} KiB into its 2 MiB", off(p));
            // SAFETY: our mapping of the file.
            assert_eq!(unsafe { *(p as *const u8) }, 0x11);
            // SAFETY: our mapping.
            assert_eq!(unsafe { munmap(p as *mut c_void, 2 * mib) }, 0);
        }
        drop(f);
        let _ = std::fs::remove_file(&path);
        // A free hint 64 KiB past a boundary: reserved to find it, freed.
        // SAFETY: reserves and frees address space of our own.
        let hint = unsafe {
            let r = VirtualAlloc2(proc(), std::ptr::null(), 8 * mib, MEM_RESERVE, PAGE_NOACCESS, std::ptr::null_mut(), 0) as usize;
            assert_ne!(r, 0);
            VirtualFree(r as *mut c_void, 0, MEM_RELEASE);
            r.next_multiple_of(HUGE_PAGE) + GRANULE
        };
        let p = map(hint, 4 * mib, PROT_READ | PROT_WRITE, ANON, -1, 0);
        std::println!("PLACEMENT a free hint {} KiB into its 2 MiB: at it {}", off(hint), p == hint);
        assert_eq!(p, hint, "the free hint");
        touch_and_unmap(p, 4 * mib);
        REFUSE_ALIGNED_PLACEMENT.store(true, std::sync::atomic::Ordering::SeqCst);
        let p = map(0, 4 * mib, PROT_READ | PROT_WRITE, ANON, -1, 0);
        let reached = !REFUSE_ALIGNED_PLACEMENT.swap(false, std::sync::atomic::Ordering::SeqCst);
        std::println!("PLACEMENT 4 MiB with the aligned reservation refused: made, {} KiB into its 2 MiB", off(p));
        assert!(reached, "the refusal was not reached");
        touch_and_unmap(p, 4 * mib);
    }

    #[test]
    fn test_shared_anonymous_and_file() {
        let _serial = serial();
        use std::io::Write;
        use std::os::windows::io::AsRawHandle;
        let path = std::env::temp_dir().join(std::format!("wick-mm-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.write_all(&std::vec![0x11u8; 2 * GRANULE]).unwrap();
        let fd = crate::windows_fd::to_fd_pub(f.as_raw_handle());
        let a = map(
            0,
            GRANULE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            GRANULE as i64,
        );
        let b = map(0, GRANULE, PROT_READ, MAP_SHARED, fd, GRANULE as i64);
        let c = map(
            0,
            GRANULE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE,
            fd,
            GRANULE as i64,
        );
        // SAFETY: our mappings.
        unsafe {
            *(a as *mut u8) = 0x22;
            assert_eq!(*(b as *const u8), 0x22, "shared");
            assert_eq!(*(c as *const u8), 0x11, "private copy taken at mmap");
            *(c as *mut u8) = 0x33;
            assert_eq!(*(a as *const u8), 0x22);
            // DONTNEED on a private file mapping reads the file again.
            assert_eq!(madvise(c as *mut c_void, PAGE, MADV_DONTNEED), 0);
            assert_eq!(*(c as *const u8), 0x22);
            assert_eq!(msync(a as *mut c_void, PAGE, MS_SYNC), 0);
            // A page offset between 64 KiB boundaries maps the same file.
            let mid = map(0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (GRANULE + PAGE) as i64);
            *((a + PAGE) as *mut u8) = 0x66;
            assert_eq!(*(mid as *const u8), 0x66, "same file page");
            assert_eq!(munmap(mid as *mut c_void, PAGE), 0);
            // ... except over the caller's memory (MAP_FIXED), unaligned
            // offsets and mappings past the end are refused.
            assert_eq!(
                mmap(
                    a as *mut c_void,
                    PAGE,
                    PROT_READ,
                    MAP_SHARED | MAP_FIXED,
                    fd,
                    PAGE as i64
                ),
                MAP_FAILED
            );
            assert_eq!(
                mmap(std::ptr::null_mut(), PAGE, PROT_READ, MAP_SHARED, fd, 100),
                MAP_FAILED
            );
            assert_eq!(
                mmap(
                    std::ptr::null_mut(),
                    4 * GRANULE,
                    PROT_READ,
                    MAP_SHARED,
                    fd,
                    0
                ),
                MAP_FAILED
            );
            for m in [a, b, c] {
                assert_eq!(munmap(m as *mut c_void, GRANULE), 0);
            }
        }
        // A file shorter than a page: as with POSIX, the page past its end
        // reads as zero and is not written back; whole pages past the end
        // are refused.
        f.set_len(5).unwrap();
        let short = map(0, 5, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        // SAFETY: our mapping, one page.
        unsafe {
            assert_eq!(*(short as *const u8), 0x11);
            assert_eq!(*((short + 5) as *const u8), 0, "past the end");
            *(short as *mut u8) = 0x44;
            *((short + 100) as *mut u8) = 0x55;
            assert_eq!(msync(short as *mut c_void, PAGE, MS_SYNC), 0);
            assert_eq!(
                mmap(
                    std::ptr::null_mut(),
                    2 * PAGE,
                    PROT_READ,
                    MAP_SHARED,
                    fd,
                    0
                ),
                MAP_FAILED
            );
            assert_eq!(munmap(short as *mut c_void, 5), 0);
        }
        assert_eq!(f.metadata().unwrap().len(), 5, "the file keeps its size");
        let mut head = [0u8; 5];
        std::os::windows::fs::FileExt::seek_read(&f, &mut head, 0).unwrap();
        assert_eq!(head, [0x44, 0x11, 0x11, 0x11, 0x11]);
        let s = map(
            0,
            GRANULE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        );
        // SAFETY: our mapping.
        unsafe {
            *(s as *mut u8) = 5;
            assert_eq!(munmap((s + PAGE) as *mut c_void, PAGE), 0, "part of a view");
            assert_eq!(*(s as *const u8), 5);
            assert_eq!(munmap(s as *mut c_void, GRANULE), 0);
        }
        drop(f);
        std::fs::remove_file(path).unwrap();
    }

    fn hugetlb(len: usize, prot: c_int, flags: c_int) -> Result<usize, c_int> {
        // SAFETY: a new mapping, or a failure.
        let p = unsafe { mmap(std::ptr::null_mut(), len, prot, flags | MAP_HUGETLB, -1, 0) };
        if p == MAP_FAILED {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap())
        } else {
            Ok(p as usize)
        }
    }

    #[test]
    fn test_hugetlb_refused() {
        let _serial = serial();
        let shared = MAP_SHARED | MAP_ANONYMOUS;
        assert_eq!(hugetlb(2 << 20, PROT_READ, shared | MAP_HUGE_2MB), Err(crate::ENOMEM));
        assert_eq!(hugetlb(1 << 30, PROT_READ, ANON | MAP_HUGE_1GB), Err(crate::ENOMEM));
        assert_eq!(hugetlb(2 << 20, 0x40, ANON), Err(crate::EINVAL));
        // At a fixed address: over memory not on large pages, ENOMEM; at
        // an address not on a large page, EINVAL (as Linux).
        let big = 8 << 20;
        // SAFETY: a new mapping.
        let p = unsafe { mmap(std::ptr::null_mut(), big, PROT_READ | PROT_WRITE, ANON, -1, 0) };
        assert_ne!(p, MAP_FAILED);
        let aligned = (p as usize).next_multiple_of(2 << 20);
        let fixed = |at: usize| {
            // SAFETY: MAP_FIXED over our own mapping, or a failure.
            let q = unsafe {
                mmap(at as *mut c_void, 2 << 20, PROT_READ | PROT_WRITE, ANON | MAP_FIXED | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0)
            };
            (q, std::io::Error::last_os_error().raw_os_error().unwrap())
        };
        if large_page(MAP_HUGE_2MB).is_some() {
            assert_eq!(fixed(aligned), (MAP_FAILED, crate::ENOMEM));
            assert_eq!(fixed(aligned + PAGE), (MAP_FAILED, crate::EINVAL));
        }
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(p, big) }, 0);
    }

    /// This process's token is at or above medium integrity, read through
    /// the pseudo-handle without opening the token, as a jailed process
    /// must (it cannot open its token; the jailer-test `hugepages` stage
    /// reads the message `map_large` prints there): the level the
    /// pseudo-handle gives is the opened token's.
    #[test]
    fn test_integrity_level_is_read() {
        use windows_sys::Win32::Security::{GetTokenInformation, TokenIntegrityLevel};
        let level = integrity_level().unwrap();
        assert!(level >= 0x2000, "{level:#x}");
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: opens our own token (this test is not jailed).
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }, 0);
        let mut buf = [0u64; 64];
        let mut len = 0u32;
        // SAFETY: a buffer of the size passed; `token` is ours.
        let ok = unsafe {
            GetTokenInformation(token, TokenIntegrityLevel, buf.as_mut_ptr().cast(), 512, &mut len)
        };
        // SAFETY: closes the token we opened.
        unsafe { CloseHandle(token) };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        let mut pseudo = [0u64; 64];
        // SAFETY: as above, through the pseudo-handle.
        let ok = unsafe {
            let p = pseudo.as_mut_ptr().cast();
            GetTokenInformation(CURRENT_PROCESS_TOKEN, TokenIntegrityLevel, p, 512, &mut len)
        };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        // The label's SID follows the TOKEN_MANDATORY_LABEL header in the
        // buffer (its pointer differs; the SID bytes do not).
        assert_eq!(&buf[2..], &pseudo[2..]);
        // SAFETY: the buffer holds a TOKEN_MANDATORY_LABEL whose SID is valid.
        let opened = unsafe {
            use windows_sys::Win32::Security::{
                GetSidSubAuthority, GetSidSubAuthorityCount, TOKEN_MANDATORY_LABEL,
            };
            let sid = (*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
            *GetSidSubAuthority(sid, u32::from(*GetSidSubAuthorityCount(sid)) - 1)
        };
        assert_eq!(level, opened);
    }

    /// Whether this process's token holds `SeLockMemoryPrivilege` ("Lock
    /// pages in memory"), enabled or not: what an administrator grants for
    /// large pages, as one reserves huge pages on Linux.
    fn holds_lock_memory_privilege() -> bool {
        use windows_sys::Win32::Foundation::LUID;
        use windows_sys::Win32::Security::{GetTokenInformation, TokenPrivileges};
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: opens our own token.
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }, 0);
        let mut buf = std::vec![0u64; 512];
        let mut len = 0u32;
        // SAFETY: a buffer of the size passed; `token` is ours.
        let ok = unsafe {
            GetTokenInformation(token, TokenPrivileges, buf.as_mut_ptr().cast(), 4096, &mut len)
        };
        // SAFETY: closes the token we opened.
        unsafe { CloseHandle(token) };
        assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
        let mut want = LUID { LowPart: 0, HighPart: 0 };
        let name: Vec<u16> = "SeLockMemoryPrivilege\0".encode_utf16().collect();
        // SAFETY: a NUL-terminated name and an out-parameter.
        assert_ne!(unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut want) }, 0);
        // SAFETY: GetTokenInformation filled a TOKEN_PRIVILEGES.
        let tp = unsafe { &*buf.as_ptr().cast::<TOKEN_PRIVILEGES>() };
        // SAFETY: PrivilegeCount entries follow the count.
        let privs = unsafe { std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize) };
        privs.iter().any(|p| p.Luid.LowPart == want.LowPart && p.Luid.HighPart == want.HighPart)
    }

    /// Large pages are mapped whenever the account holds "Lock pages in
    /// memory" (on fc-win and on a host set up for `boot-test hugepages`);
    /// without it, `ENOMEM`, as Linux fails without huge pages reserved.
    #[test]
    fn test_hugetlb() {
        let _serial = serial();
        let held = holds_lock_memory_privilege();
        let page = match hugetlb(3 << 20, PROT_READ | PROT_WRITE, ANON | MAP_HUGE_2MB) {
            Err(e) => {
                assert!(!held, "large pages refused (errno {e}) to an account that holds SeLockMemoryPrivilege");
                assert_eq!(e, crate::ENOMEM);
                std::eprintln!("test_hugetlb: this account lacks SeLockMemoryPrivilege; only the refusal was checked");
                return;
            }
            Ok(p) => p,
        };
        assert!(held);
        let large = large_page(MAP_HUGE_2MB).unwrap();
        assert!(page.is_multiple_of(large));
        // Windows reports the pages as large pages, valid and locked.
        // SAFETY: an all-zero entry with an address is a valid query.
        let mut e: PSAPI_WORKING_SET_EX_INFORMATION = unsafe { std::mem::zeroed() };
        e.VirtualAddress = (page + large) as *mut c_void;
        let size = u32::try_from(std::mem::size_of_val(&e)).unwrap();
        // SAFETY: one entry of the size passed.
        assert_ne!(unsafe { QueryWorkingSetEx(proc(), (&raw mut e).cast(), size) }, 0);
        // SAFETY: reads the flags of the union.
        let flags = unsafe { e.VirtualAttributes.Flags };
        assert_eq!(flags & 1, 1, "valid");
        assert_ne!(flags & (1 << 23), 0, "a large page (flags {flags:#x})");
        // SAFETY: our 4 MiB (two large pages) mapping.
        unsafe {
            *(page as *mut u8) = 7;
            *((page + (4 << 20) - 1) as *mut u8) = 9;
            assert_eq!(munmap(page as *mut c_void, large), -1, "part of a large-page mapping");
            // Linux's hugetlb MADV_DONTNEED: the start a whole huge page
            // (EINVAL), the end rounded down to one; no MADV_FREE.
            assert_eq!(madvise((page + PAGE) as *mut c_void, large, MADV_DONTNEED), -1, "unaligned start");
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EINVAL));
            assert_eq!(madvise(page as *mut c_void, large, MADV_FREE), -1, "MADV_FREE");
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EINVAL));
            assert_eq!(madvise(page as *mut c_void, PAGE, MADV_DONTNEED), 0, "rounded down to nothing");
            assert_eq!(*(page as *const u8), 7);
            assert_eq!(madvise(page as *mut c_void, large + PAGE, MADV_DONTNEED), 0);
            assert_eq!(*(page as *const u8), 0);
            assert_eq!(*((page + (4 << 20) - 1) as *const u8), 9);
            // The protection it has, and no other (Windows changes no large
            // page's protection); whole large pages only.
            assert_eq!(mprotect(page as *mut c_void, large, PROT_READ | PROT_WRITE), 0);
            assert_eq!(mprotect(page as *mut c_void, large, PROT_READ), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(crate::EACCES));
            assert_eq!(mprotect(page as *mut c_void, PAGE, PROT_READ | PROT_WRITE), -1);
            assert_eq!(*((page + (4 << 20) - 1) as *const u8), 9);
            assert_eq!(munmap(page as *mut c_void, 4 << 20), 0);
        }

        // Firecracker's guest memory (vstate::memory, `allocate`): a
        // PROT_NONE hugetlb reservation, then a MAP_FIXED hugetlb mapping
        // over it.
        let huge = ANON | MAP_NORESERVE | MAP_HUGE_2MB;
        let base = hugetlb(4 << 20, PROT_NONE, huge).unwrap();
        let protection = |at: usize| {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            assert_ne!(unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
            mbi.Protect
        };
        // The reservation is inaccessible, as PROT_NONE is.
        assert_eq!(protection(base), PAGE_NOACCESS);
        let fixed = |at: usize, len: usize, prot: c_int| {
            // SAFETY: MAP_FIXED over our own mapping, or a failure.
            let q = unsafe { mmap(at as *mut c_void, len, prot, huge | MAP_FIXED | MAP_HUGETLB, -1, 0) };
            if q == MAP_FAILED { Err(std::io::Error::last_os_error().raw_os_error().unwrap()) } else { Ok(q as usize) }
        };
        // Part of it with another protection: one allocation, one protection.
        assert_eq!(fixed(base + large, large, PROT_READ | PROT_WRITE), Err(crate::ENOMEM));
        // The whole of it, read-write: allocated again at its address.
        assert_eq!(fixed(base, 4 << 20, PROT_READ | PROT_WRITE), Ok(base));
        assert_eq!(protection(base), PAGE_READWRITE);
        // SAFETY: our 4 MiB mapping, read-write now.
        unsafe {
            *(base as *mut u8) = 3;
            *((base + large) as *mut u8) = 4;
        }
        // Over its second page, with its protection: zeros, the first page kept.
        assert_eq!(fixed(base + large, large, PROT_READ | PROT_WRITE), Ok(base + large));
        // SAFETY: as above.
        unsafe {
            assert_eq!(*(base as *const u8), 3);
            assert_eq!(*((base + large) as *const u8), 0);
        }
        // Over its second page, read-only: another protection for a part.
        assert_eq!(fixed(base + large, large, PROT_READ), Err(crate::ENOMEM));
        // Not a large page boundary; beyond the mapping.
        assert_eq!(fixed(base + PAGE, large, PROT_READ), Err(crate::EINVAL));
        assert_eq!(fixed(base + large, 2 * large, PROT_READ), Err(crate::ENOMEM));
        // SAFETY: our mapping.
        assert_eq!(unsafe { munmap(base as *mut c_void, 4 << 20) }, 0);
    }

    /// MAPCOST, a record: what mapping a 2 MiB view of a new reserved
    /// section ([`reserved_section`], as a reclaim's move maps its temporary
    /// view, [`uffd_move_chunk`]) adds to the process's private commit, by
    /// where the view lands: 64 views mapped anywhere and kept (each line:
    /// the address, its offset in its 2 MiB and in its 1 GiB, the private
    /// commit added); then at chosen addresses in a fresh 4 GiB of address
    /// space: 1 GiB aligned, 2 MiB aligned beside it, straddling two fresh
    /// 2 MiB regions, straddling a 1 GiB boundary, and in a fresh 1 GiB.
    #[test]
    #[ignore = "a record, run by hand"]
    fn test_view_map_costs_on_record() {
        use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
        let pc = || {
            // SAFETY: plain data.
            let mut c: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
            c.cb = std::mem::size_of_val(&c) as u32;
            // SAFETY: a structure of the size given.
            assert_ne!(unsafe { K32GetProcessMemoryInfo(proc(), (&raw mut c).cast(), c.cb) }, 0);
            c.PrivateUsage as isize
        };
        const GIB: usize = 1 << 30;
        let map_at = |at: usize| -> (usize, isize) {
            let s = reserved_section(UFFD_CHUNK).unwrap();
            let before = pc();
            // SAFETY: maps our new section at `at` (0: anywhere).
            let v = unsafe { MapViewOfFile3(s.0, proc(), at as *const c_void, 0, UFFD_CHUNK, 0, PAGE_READWRITE, std::ptr::null_mut(), 0) }.Value as usize;
            let after = pc();
            std::mem::forget(s);
            (v, after - before)
        };
        let mut costs = std::collections::BTreeMap::new();
        for i in 0..64 {
            let (v, d) = map_at(0);
            *costs.entry(d / 1024).or_insert(0) += 1;
            std::println!("MAPCOST anywhere {i}: at {v:#x}, {} KiB into its 2 MiB, {} MiB into its 1 GiB: +{} KiB", (v % UFFD_CHUNK) / 1024, (v % GIB) >> 20, d / 1024);
        }
        std::println!("MAPCOST anywhere, KiB added: count {costs:?}");
        // A fresh 1 GiB-aligned 4 GiB: reserved to find it, then freed.
        // SAFETY: reserves and frees address space of our own.
        let base = unsafe {
            let r = VirtualAlloc2(proc(), std::ptr::null(), 5 * GIB, MEM_RESERVE, PAGE_NOACCESS, std::ptr::null_mut(), 0) as usize;
            assert_ne!(r, 0);
            VirtualFree(r as *mut c_void, 0, MEM_RELEASE);
            r.next_multiple_of(GIB)
        };
        for (what, at) in [
            ("1 GiB aligned, fresh", base),
            ("2 MiB aligned, beside it", base + UFFD_CHUNK),
            ("straddling two fresh 2 MiB regions", base + 8 * UFFD_CHUNK + GRANULE),
            ("straddling a 1 GiB boundary", base + 2 * GIB - GRANULE),
            ("in a fresh 1 GiB", base + 3 * GIB + 16 * UFFD_CHUNK),
        ] {
            let (v, d) = map_at(at);
            std::println!("MAPCOST {what}: at {v:#x} (asked {at:#x}): +{} KiB", d / 1024);
        }
    }

    /// MAPCOST2, a record for the move's temporary view: in a fresh 1 GiB,
    /// a 2 MiB slot made a placeholder at 64 KiB past a 2 MiB boundary
    /// (so it spans two 2 MiB regions), (a) alone, (b) with one private page
    /// committed in each of the two regions beside it (anchors): the private
    /// commit added by the map into the slot, by its unmap keeping the
    /// placeholder, and by a second map, and (b) the anchors' own cost.
    #[test]
    #[ignore = "a record, run by hand"]
    fn test_a_view_slot_and_its_page_tables_on_record() {
        use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
        let pc = || {
            // SAFETY: plain data.
            let mut c: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
            c.cb = std::mem::size_of_val(&c) as u32;
            // SAFETY: a structure of the size given.
            assert_ne!(unsafe { K32GetProcessMemoryInfo(proc(), (&raw mut c).cast(), c.cb) }, 0);
            c.PrivateUsage as isize
        };
        const GIB: usize = 1 << 30;
        let kib = |d: isize| d / 1024;
        for (case, anchors) in [("(a) no anchors", false), ("(b) anchors", true)] {
            // A fresh 1 GiB: found by a reservation, freed, then used.
            // SAFETY: reserves and frees address space of our own.
            let g = unsafe {
                let r = VirtualAlloc2(proc(), std::ptr::null(), 3 * GIB, MEM_RESERVE, PAGE_NOACCESS, std::ptr::null_mut(), 0) as usize;
                assert_ne!(r, 0);
                VirtualFree(r as *mut c_void, 0, MEM_RELEASE);
                r.next_multiple_of(GIB)
            };
            // [g, g + 4 MiB) as placeholders: [g, g+64K) anchor A, [g+64K,
            // g+64K+2M) the slot, [g+64K+2M, g+4M) anchor B.
            let slot = g + GRANULE;
            let t0 = pc();
            // SAFETY: a placeholder of our own at a free address, then split.
            unsafe {
                let p = VirtualAlloc2(proc(), g as *const c_void, 4 << 20, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, std::ptr::null_mut(), 0) as usize;
                assert_eq!(p, g, "{case}: the placeholder");
                assert_ne!(VirtualFree(g as *mut c_void, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), 0);
                assert_ne!(VirtualFree(slot as *mut c_void, UFFD_CHUNK, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), 0);
            }
            if anchors {
                for (a, n) in [(g, GRANULE), (slot + UFFD_CHUNK, (4 << 20) - GRANULE - UFFD_CHUNK)] {
                    // SAFETY: our placeholder, reserved and its first page committed.
                    unsafe {
                        let p = VirtualAlloc2(proc(), a as *const c_void, n, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_NOACCESS, std::ptr::null_mut(), 0) as usize;
                        assert_eq!(p, a);
                        let at = if a == g { g } else { a + n - PAGE };
                        assert_ne!(VirtualAlloc2(proc(), at as *const c_void, PAGE, MEM_COMMIT, PAGE_NOACCESS, std::ptr::null_mut(), 0) as usize, 0);
                    }
                }
            }
            let t1 = pc();
            let mut line = std::format!("MAPCOST2 {case}: the slot at {slot:#x}; anchors and placeholders +{} KiB", kib(t1 - t0));
            for round in 0..3 {
                let s = reserved_section(UFFD_CHUNK).unwrap();
                let before = pc();
                // SAFETY: maps our section into our placeholder.
                let v = unsafe { MapViewOfFile3(s.0, proc(), slot as *const c_void, 0, UFFD_CHUNK, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, std::ptr::null_mut(), 0) }.Value as usize;
                assert_eq!(v, slot, "{case}: map {round}");
                let mapped = pc();
                // SAFETY: commits and touches two pages of it, one in each region.
                unsafe {
                    for at in [slot, slot + UFFD_CHUNK - PAGE] {
                        assert_ne!(VirtualAlloc2(proc(), at as *const c_void, PAGE, MEM_COMMIT, PAGE_READWRITE, std::ptr::null_mut(), 0) as usize, 0);
                        std::ptr::write_volatile(at as *mut u8, 1);
                    }
                }
                let touched = pc();
                // SAFETY: unmaps our view, keeping the placeholder.
                assert_ne!(unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: slot as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) }, 0);
                let unmapped = pc();
                line += &std::format!(
                    "; round {round}: map +{}, two pages committed and touched +{}, unmap keeping the placeholder {:+}",
                    kib(mapped - before),
                    kib(touched - mapped),
                    kib(unmapped - touched)
                );
            }
            std::println!("{line}");
        }
    }
}
