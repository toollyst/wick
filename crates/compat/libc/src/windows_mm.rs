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
//!   the range back into one) and replaces it with the mapping. Offsets into
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
use std::sync::{Arc, Mutex, OnceLock};
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
    MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile3, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PrefetchVirtualMemory, UnmapViewOfFile2, VirtualAlloc2, VirtualFree, VirtualProtect,
    VirtualQuery, WIN32_MEMORY_RANGE_ENTRY,
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
        super::commit_on_access(addr, write)
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
static CHARGES: Mutex<BTreeMap<usize, (usize, Arc<Charge>)>> = Mutex::new(BTreeMap::new());
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
        /// None for a userfaultfd range's chunk, whose section handle is
        /// closed once its views are mapped ([`uffd_alias`]).
        _section: Option<Arc<Owned>>,
        file: Option<Arc<Owned>>,
        charge: Option<Arc<Charge>>,
        /// A released userfaultfd range's alias of the section, handed over
        /// by [`uffd_unalias`] while the view has discarded pages
        /// ([`STALE`]), which are zeroed through it at their first access;
        /// unmapped with the view.
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

fn table() -> &'static Mutex<Table> {
    static T: OnceLock<Mutex<Table>> = OnceLock::new();
    T.get_or_init(Mutex::default)
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
    true
}

/// Releases the region at `base` and its address space.
fn release(t: &mut Table, base: usize) -> bool {
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
/// snapshot's) by a vectored exception handler ([`lazy_on_exception`]), the
/// guest's by the hypervisor's run loop, which WHP leaves with a memory
/// access exit for a page that is not committed (measured: the exit, then
/// the commit, then the access re-run). Sorted, disjoint `(start, len,
/// protection)`. Locked briefly, never while memory is touched, so a fault
/// inside a call that holds the region table cannot deadlock on it.
///
/// An `mprotect` keeps memory lazy ([`protect_lazy`]): the protection of a
/// range is the one its pages get when committed, and a `PAGE_NOACCESS`
/// range (`PROT_NONE`) is committed by no access, which faults, as on Linux.
static LAZY: Mutex<Vec<(usize, usize, PAGE_PROTECTION_FLAGS)>> = Mutex::new(Vec::new());

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
static GRAINS: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());
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
static TOUCHED: std::sync::RwLock<BTreeMap<usize, Arc<Touched>>> = std::sync::RwLock::new(BTreeMap::new());

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
    TOUCHED.write().unwrap_or_else(std::sync::PoisonError::into_inner).insert(base, Arc::new(Touched::new(len)));
}

/// The lazy allocation at `base` is gone, or no longer lazy.
fn touched_remove(base: usize) {
    TOUCHED.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&base);
}

/// Sets (or clears) the bits of the pages `[start, start + len)` overlaps,
/// in whichever lazy allocations it lies.
fn touched_mark(start: usize, len: usize, set: bool) {
    let end = start.saturating_add(len);
    let map = TOUCHED.read().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let map = TOUCHED.read().unwrap_or_else(std::sync::PoisonError::into_inner);
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
    /// They could not be committed (the Windows error): the memory limit is
    /// reached.
    Exhausted(u32),
}

fn commit_on_access(addr: usize, write: bool) -> (Access, core::ops::Range<usize>) {
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
    if let Some(access) = resolve_stale(page, prot) {
        let range = if access == Access::Committed { page..page + PAGE } else { 0..0 };
        return (access, range);
    }
    let grain = if write { lazy_grain(addr) } else { PAGE };
    let block = addr - addr % grain;
    // Never a block over a discarded page, which is zeroed before it opens.
    let whole = block >= s && block + grain <= s + n && stale_within(block, grain).is_empty();
    let (from, to) = if whole { (block, block + grain) } else { (page, page + PAGE) };
    if commit(from, to - from, prot, false) {
        return (Access::Committed, from..to);
    }
    // SAFETY: plain call.
    let err = unsafe { GetLastError() };
    // A huge page that cannot be charged falls back to a page, as Linux's
    // does (mm/huge_memory.c, `THP_FAULT_FALLBACK_CHARGE`).
    if to - from > PAGE && commit(page, PAGE, prot, false) {
        (Access::Committed, page..page + PAGE)
    } else {
        (Access::Exhausted(err), 0..0)
    }
}

/// Commits the lazy pages of `[addr, addr + len)` that are not committed: a
/// system call's buffer, which the kernel copies to or from without an
/// exception this process could resolve (`ReadFile` into a page that is only
/// reserved fails: measured, a guest kernel read into lazy memory). Linux
/// faults the pages in as the call copies.
pub(crate) fn prefault_lazy(addr: usize, len: usize) {
    if len == 0 || LAZY.lock().unwrap().is_empty() {
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
            if mbi.State != MEM_COMMIT && !commit(at, run, prot, false) {
                // SAFETY: plain call.
                out_of_memory(at, unsafe { GetLastError() });
            }
            if mbi.State == MEM_COMMIT {
                for (ss, sl) in stale_within(at, run) {
                    for page in (ss..ss + sl).step_by(PAGE) {
                        if let Some(Access::Exhausted(err)) = resolve_stale(page, prot) {
                            out_of_memory(page, err);
                        }
                    }
                }
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

fn out_of_memory(addr: usize, err: u32) -> ! {
    let rescue = RESCUE.swap(0, std::sync::atomic::Ordering::SeqCst);
    if rescue != 0 {
        // SAFETY: frees the block set aside for this.
        unsafe { VirtualFree(rescue as *mut c_void, 0, MEM_RELEASE) };
    }
    std::eprintln!(
        "wick: guest memory: committing the pages at {addr:#x} failed with error {err}: the memory limit \
         (the jail's memory.max, or the host's commit limit) is reached; the VMM ends, as the cgroup OOM \
         killer ends it on Linux (exit {OOM_EXIT})"
    );
    // SAFETY: ends this process at once, as SIGKILL does.
    unsafe { windows_sys::Win32::System::Threading::TerminateProcess(GetCurrentProcess(), OOM_EXIT) };
    unreachable!("the process ended");
}

std::thread_local! {
    /// [`wick_mm::host_faults_on_this_thread`]: no destructor, so that the
    /// exception handler's access is a plain read of the thread's TLS.
    static HOST_FAULTS: std::cell::Cell<(u64, usize)> = const { std::cell::Cell::new((0, 0)) };
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

/// A host thread's access to lazy memory: its pages are committed and the
/// access runs again.
unsafe extern "system" fn lazy_on_exception(
    info: *mut windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    const ACCESS_VIOLATION: i32 = 0xC000_0005_u32 as i32;
    // SAFETY: the system passes valid exception pointers.
    let rec = unsafe { &*(*info).ExceptionRecord };
    if rec.ExceptionCode == ACCESS_VIOLATION && rec.NumberParameters >= 2 {
        // [0]: 0 read, 1 write, 8 execute; [1]: the address.
        let stack = stack_committed();
        match commit_on_access(rec.ExceptionInformation[1], rec.ExceptionInformation[0] == 1).0 {
            Access::Committed => {
                let (n, deepest) = HOST_FAULTS.get();
                HOST_FAULTS.set((n + 1, deepest.max(stack)));
                return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION;
            }
            Access::Exhausted(err) => out_of_memory(rec.ExceptionInformation[1], err),
            Access::NotLazy => {}
        }
    }
    windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH
}

/// Installs [`lazy_on_exception`] once; whether it is in place.
fn lazy_handler() -> bool {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    *INSTALLED.get_or_init(|| {
        // SAFETY: a new allocation, committed; given back by `out_of_memory`.
        let rescue = unsafe {
            VirtualAlloc2(proc(), std::ptr::null(), RESCUE_LEN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, std::ptr::null_mut(), 0)
        };
        RESCUE.store(rescue as usize, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: first in the chain; the handler stays for the process.
        !unsafe { windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler(1, Some(lazy_on_exception)) }
            .is_null()
    })
}

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
    lazy_add(s, e - s, wprot);
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
            // it ([`STALE`]), which gives it the protection then asked for.
            let mut p = at;
            for (ss, sl) in stale_within(at, run).into_iter().chain([(at + run, 0)]) {
                if ss > p && !protect(p, ss - p, wprot) {
                    return false;
                }
                p = ss + sl;
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
        } else if flags & MAP_NORESERVE != 0 && flags & MAP_POPULATE == 0 && lazy_handler() {
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
        // after, as `windows_uffd` fills registered memory, is race-free,
        // but a Job Object does not charge sections (SECURITY.md, "memory.max
        // does not bound memory in sections"): it waits for wick's own count
        // of the section pages a process commits against `memory.max`.
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
            charged = lazy_handler();
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

fn broker() -> Option<&'static Mutex<Broker>> {
    static BROKER: OnceLock<Option<Mutex<Broker>>> = OnceLock::new();
    BROKER
        .get_or_init(|| {
            let v = std::env::var("WICK_LARGE_PAGES").ok()?;
            let (a, b) = v.split_once(',')?;
            Some(Mutex::new(Broker {
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

/// `mmap`.
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
    wick_mm::check_exec(prot);
    let ty = flags & (MAP_SHARED | MAP_PRIVATE);
    if len == 0 || offset < 0 || (ty != MAP_SHARED && ty != MAP_PRIVATE) || win_prot(prot).is_none()
    {
        return fail(crate::EINVAL, MAP_FAILED);
    }
    // A mapping over memory discards it: it waits for the system calls in
    // flight on the range ([`InFlight`]).
    let _discard = (flags & MAP_FIXED != 0).then(|| discard_waiting(addr as usize, len.div_ceil(PAGE) * PAGE));
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
        let hint = addr as usize;
        let p = (hint != 0 && lead == 0 && hint.is_multiple_of(GRANULE))
            .then(|| new_placeholder(hint, len))
            .flatten()
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

/// `munmap`.
///
/// # Safety
/// Same contract as `munmap(2)`.
pub unsafe fn munmap(addr: *mut c_void, len: size_t) -> c_int {
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
            release(&mut t, b);
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
                if r.lazy {
                    // Its pages not committed fault already; the committed
                    // ones are made to (Windows protects no page that is only
                    // reserved). A discarded page's stays unopened.
                    lazy_remove(s, e - s);
                    stale_remove(s, e - s);
                    protect_committed(s, e, PAGE_NOACCESS);
                } else {
                    protect(s, e - s, PAGE_NOACCESS);
                }
            }
        }
        let r = t.get_mut(&b).unwrap();
        r.add_hole(s - b, e - s);
        if r.all_holes() {
            release(&mut t, b);
        }
    }
    0
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
    let mut t = table().lock().unwrap();
    if !covered(&t, start, end) {
        return fail(crate::ENOMEM, -1);
    }
    if prot != PROT_NONE && !carve(&mut t, start, end) {
        return fail(crate::ENOMEM, -1);
    }
    for b in overlapping(&t, start, end) {
        let r = &t[&b];
        let (s, e) = (start.max(b), end.min(b + r.len));
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
                if !(s - b).is_multiple_of(page) || !(e - b).is_multiple_of(page) {
                    return fail(crate::EINVAL, -1);
                }
                // Windows changes no large page's protection (`Kind::Large`):
                // only the protection it has is granted.
                if old != wprot {
                    return fail(crate::EACCES, -1);
                }
            }
            Kind::Private { .. } | Kind::View { .. } => {
                if !r.mapped_in(s - b, e - s) {
                    return fail(crate::ENOMEM, -1);
                }
                // Lazy memory stays lazy: its pages not committed get the
                // protection when they are.
                if r.lazy {
                    if !protect_lazy(&mut t, b, s, e, wprot) {
                        return fail(crate::EACCES, -1);
                    }
                    continue;
                }
                let r = &t[&b];
                let decommitted = ranges_within(&r.noaccess, s - b, e - s);
                if prot != PROT_NONE {
                    // Mapped `PROT_NONE` parts get their (zero) pages now.
                    for &(o, l) in &decommitted {
                        if !commit(b + o, l, wprot, false) {
                            return fail(crate::ENOMEM, -1);
                        }
                    }
                    let r = t.get_mut(&b).unwrap();
                    ranges_remove(&mut r.noaccess, s - b, e - s);
                    if !protect(s, e - s, wprot) {
                        return fail(crate::EACCES, -1);
                    }
                } else {
                    // Decommitted parts already fault; protect the rest.
                    let mut at = s;
                    for (o, l) in decommitted.into_iter().chain([(e - b, 0)]) {
                        if b + o > at && !protect(at, b + o - at, wprot) {
                            return fail(crate::EACCES, -1);
                        }
                        at = b + o + l;
                    }
                }
            }
        }
    }
    0
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
/// `mcopy_atomic_pte`: `mem_cgroup_charge` at :205, `-ENOMEM` when refused).
/// Before, the whole section was committed here and charged to no job. A
/// resident page is charged before the private page it is copied from is
/// freed, so it counts twice for that moment.
pub(crate) fn uffd_alias(start: usize, len: usize, resident: &[u8]) -> Result<(usize, bool), c_int> {
    let mut t = table().lock().unwrap();
    match t.get(&start) {
        Some(r)
            if r.len == len
                && matches!(r.kind, Kind::Private { file: None })
                && r.holes.is_empty()
                && r.noaccess.is_empty() => {}
        _ => return Err(crate::EINVAL),
    }
    if lazy_handler() {
        return uffd_alias_chunked(&mut t, start, len, resident).map(|alias| (alias, true));
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
    // SAFETY: gives the private allocation back as a placeholder.
    if unsafe { VirtualFree(start as *mut c_void, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
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

/// The grain of a userfaultfd range's reserved section ([`uffd_alias`]):
/// one section per 2 MiB chunk, the block a balloon's free page reporting
/// gives back on x86 (v6.1 mm/page_reporting.c, `pageblock_order`), so that
/// a chunk discarded whole can give its section commit back
/// ([`uffd_swap_chunk`]), which a section's pages cannot (SECTREC-h).
pub(crate) const UFFD_CHUNK: usize = 2 << 20;

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

/// Maps `section` (`len` bytes, from its start) into the placeholder of the
/// same size at `at`; whether it is.
fn view_into(section: &Owned, at: usize, len: usize) -> bool {
    // SAFETY: maps our section over our placeholder.
    let v = unsafe {
        MapViewOfFile3(
            section.0,
            proc(),
            at as *const c_void,
            0,
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
/// is not a multiple), each mapped into a placeholder of the mapping's and
/// one of the alias's, its handle closed then (the views keep the section:
/// "Mapped views of a file mapping object maintain internal references to
/// the object", Learn, CreateFileMappingW), so no handle is held for it
/// (UFFDCHUNK b, CI run 43528910212: 1 GiB as 512 chunks in 5.43 us a
/// chunk, commit and paged pool as one section's, handles +0). Each chunk
/// is a view of the table's, with a charge of its own ([`Charge`]). WHP
/// maps the guest's range over the views in one call (UFFDCHUNK a).
fn uffd_alias_chunked(t: &mut Table, start: usize, len: usize, resident: &[u8]) -> Result<usize, c_int> {
    let chunks: Vec<(usize, usize)> = (0..len).step_by(UFFD_CHUNK).map(|o| (o, UFFD_CHUNK.min(len - o))).collect();
    // SAFETY: reserves address space of our own, as a placeholder.
    let alias = unsafe {
        VirtualAlloc2(proc(), std::ptr::null(), len, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, std::ptr::null_mut(), 0)
    } as usize;
    if alias == 0 {
        return Err(crate::ENOMEM);
    }
    let mut sections = Vec::with_capacity(chunks.len());
    let mut charges = Vec::with_capacity(chunks.len());
    // Undoes the alias's views and placeholders (a placeholder not split
    // off is freed at its own start, a later chunk's) and the charges.
    let undo = |mapped: usize, charged: usize| {
        for (i, &(o, _)) in chunks.iter().enumerate() {
            // SAFETY: frees the alias's view or placeholder made here.
            unsafe {
                if i < mapped {
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
    if split_into(alias, &chunks) + 1 != chunks.len() {
        undo(0, 0);
        return Err(crate::ENOMEM);
    }
    for &(o, n) in &chunks {
        let Some(section) = reserved_section(n) else {
            undo(sections.len(), charges.len());
            return Err(crate::ENOMEM);
        };
        if !view_into(&section, alias + o, n) {
            undo(sections.len(), charges.len());
            return Err(crate::ENOMEM);
        }
        sections.push(section);
        let Some(c) = charge_add(start + o, n) else {
            undo(sections.len(), charges.len());
            return Err(crate::ENOMEM);
        };
        charges.push(c);
    }
    // The resident pages: their charge, then the section's pages through the
    // alias, a chunk at a time (a commit stays within one view), then their
    // content.
    let mut i = 0;
    while i < resident.len() {
        if resident[i] & 1 == 0 {
            i += 1;
            continue;
        }
        let first = i;
        while i < resident.len() && resident[i] & 1 != 0 && (i == first || !(i * PAGE).is_multiple_of(UFFD_CHUNK)) {
            i += 1;
        }
        let (off, n) = (first * PAGE, (i - first) * PAGE);
        if !charge(start + off, n) || !commit_now(alias + off, n, PAGE_READWRITE, false) {
            undo(sections.len(), charges.len());
            return Err(crate::ENOMEM);
        }
        // SAFETY: resident pages of the mapping, into the alias.
        unsafe { std::ptr::copy_nonoverlapping((start + off) as *const u8, (alias + off) as *mut u8, n) };
    }
    // SAFETY: gives the private allocation back as a placeholder.
    if unsafe { VirtualFree(start as *mut c_void, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
        undo(sections.len(), charges.len());
        return Err(crate::EINVAL);
    }
    let r = t.remove(&start).unwrap();
    if r.lazy {
        lazy_remove(start, len);
        touched_remove(start);
    }
    // From here the private memory is gone: a failure leaves the chunks as
    // placeholders of the table's.
    let split = split_into(start, &chunks);
    let mut mapped = 0;
    if split + 1 == chunks.len() {
        while mapped < chunks.len() && view_into(&sections[mapped], start + chunks[mapped].0, chunks[mapped].1) {
            mapped += 1;
        }
    }
    if mapped < chunks.len() {
        for (k, &(o, n)) in chunks.iter().enumerate().take(split + 1) {
            if k < mapped {
                // SAFETY: unmaps a view made here, keeping its placeholder.
                unsafe {
                    UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: (start + o) as *mut c_void }, MEM_PRESERVE_PLACEHOLDER)
                };
            }
            t.insert(start + o, Region::new(if k < split { n } else { len - o }, Kind::Placeholder));
        }
        undo(sections.len(), charges.len());
        return Err(crate::ENOMEM);
    }
    drop(sections);
    for (&(o, n), c) in chunks.iter().zip(charges) {
        t.insert(start + o, Region::new(n, Kind::View { _section: None, file: None, charge: Some(c), alias: None }));
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
/// the chunk is not one of [`uffd_alias`]'s or no section can be made; a
/// failure once a view is unmapped ends the VMM, named, as a commit past
/// the host's limit does ([`out_of_memory`]).
pub(crate) fn uffd_swap_chunk(view: usize, len: usize, alias: usize) -> bool {
    let t = table().lock().unwrap();
    match t.get(&view) {
        Some(r)
            if r.len == len
                && r.holes.is_empty()
                && !r.lazy
                && matches!(r.kind, Kind::View { _section: None, charge: Some(_), file: None, alias: None }) => {}
        _ => return false,
    }
    let Some(section) = reserved_section(len) else {
        return false;
    };
    // SAFETY: unmaps the chunk's alias view, keeping its placeholder; the
    // guest's view keeps the old section until it is unmapped too.
    if unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: alias as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) } == 0 {
        return false;
    }
    let swapped = view_into(&section, alias, len)
        // SAFETY: unmaps the chunk's guest view, keeping its placeholder.
        && unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: view as *mut c_void }, MEM_PRESERVE_PLACEHOLDER) } != 0
        && view_into(&section, view, len);
    if !swapped {
        // SAFETY: plain call.
        out_of_memory(view, unsafe { GetLastError() });
    }
    drop(t);
    uncharge(view, len);
    true
}

/// The parts of `[s, s + len)` in each region of the table, in order (the
/// whole of it if none holds it): a commit or protection change stays
/// within one view.
fn region_pieces(s: usize, len: usize) -> Vec<(usize, usize)> {
    let t = table().lock().unwrap();
    let e = s + len;
    let v: Vec<(usize, usize)> = overlapping(&t, s, e)
        .into_iter()
        .map(|b| (s.max(b), e.min(b + t[&b].len)))
        .filter(|(a, z)| a < z)
        .map(|(a, z)| (a, z - a))
        .collect();
    if v.is_empty() { std::vec![(s, len)] } else { v }
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
pub(crate) fn uffd_commit(s: usize, len: usize) -> bool {
    region_pieces(s, len).into_iter().all(|(a, n)| commit(a, n, PAGE_NOACCESS, false))
}


/// Pages `[s, s + len)` of a userfaultfd range's reserved section that were
/// discarded and become ordinary memory once the range is released, `alias`
/// their address in its alias: lazy, each zeroed at its first access
/// ([`STALE`]), as Linux gives a zapped page as zeros at its next touch; its
/// charge, kept with its commit (`wick_uffd::discarding`), is made sure of
/// then. Nothing is done unless a view of a mapping holds all of the pages.
pub(crate) fn uffd_stale(s: usize, len: usize, alias: usize) {
    let mut t = table().lock().unwrap();
    let e = s + len;
    for b in overlapping(&t, s, e) {
        let r = t.get_mut(&b).unwrap();
        let (a, z) = (s.max(b), e.min(b + r.len));
        if matches!(r.kind, Kind::View { .. }) && a < z {
            r.lazy = true;
            lazy_add(a, z - a, PAGE_READWRITE);
            STALE.lock().unwrap().insert(a, (z - a, alias + (a - s)));
            STALE_SET.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/// Discarded pages of a released userfaultfd range ([`uffd_stale`]): start
/// to `(len, the alias's address of start)`. Each is committed (a section's
/// page cannot be decommitted: SECTREC-h), `PAGE_NOACCESS`, still charged
/// (`wick_uffd::discarding` keeps a charge while its page's commit stays),
/// and holds what the discard left, which
/// `DiscardVirtualMemory` does not make zeros. Its first access, by a host
/// thread or a vCPU (WHP keeps the host's protection, so a vCPU's access
/// exits to [`wick_mm::commit_on_access`]), makes sure of its charge (a no-op
/// for a page still charged), zeroes it through the
/// alias while it is still closed, and opens it ([`resolve_stale`]): no
/// thread or vCPU sees what was there. Taken after the table's lock and
/// before [`CHARGES`].
static STALE: Mutex<BTreeMap<usize, (usize, usize)>> = Mutex::new(BTreeMap::new());
/// Whether [`STALE`] has any: the access path's one look at it otherwise.
static STALE_SET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The runs of `[s, s + len)` that are [`STALE`]. On the vectored exception
/// handler's path ([`commit_on_access`]), where a panic ends the process
/// (Rust aborts a panic that would unwind out of an `extern "system"`
/// function): the run before `s`, which may end before it, is measured only
/// once it is known to reach into `[s, e)` (`then`, not `then_some`, which
/// works out `z - a` first: PC step 14f, a debug build aborted with "attempt
/// to subtract with overflow" at the first access to a wholly discarded
/// chunk).
fn stale_within(s: usize, len: usize) -> Vec<(usize, usize)> {
    if !STALE_SET.load(std::sync::atomic::Ordering::Acquire) {
        return Vec::new();
    }
    let e = s.saturating_add(len);
    let m = STALE.lock().unwrap();
    let first = m.range(..=s).next_back().map_or(s, |(b, _)| *b);
    m.range(first..e)
        .filter_map(|(&b, &(n, _))| {
            let (a, z) = (s.max(b), e.min(b + n));
            (a < z).then(|| (a, z - a))
        })
        .collect()
}

/// Takes `[s, s + len)` out of [`STALE`].
fn stale_cut(m: &mut BTreeMap<usize, (usize, usize)>, s: usize, len: usize) {
    let e = s.saturating_add(len);
    let first = m.range(..=s).next_back().map_or(s, |(b, _)| *b);
    let hit: Vec<(usize, usize, usize)> =
        m.range(first..e).filter(|(&b, &(n, _))| b < e && s < b + n).map(|(&b, &(n, a))| (b, n, a)).collect();
    for (b, n, a) in hit {
        m.remove(&b);
        if b < s {
            m.insert(b, (s - b, a));
        }
        if e < b + n {
            m.insert(e, (b + n - e, a + (e - b)));
        }
    }
    STALE_SET.store(!m.is_empty(), std::sync::atomic::Ordering::Release);
}

/// `[s, s + len)` is unmapped: none of it is [`STALE`] any longer.
fn stale_remove(s: usize, len: usize) {
    if STALE_SET.load(std::sync::atomic::Ordering::Acquire) {
        stale_cut(&mut STALE.lock().unwrap(), s, len);
    }
}

/// The first access to `page` if it is [`STALE`]: charged, zeroed through
/// the alias while still closed, then given `prot`. `None` if it is not.
fn resolve_stale(page: usize, prot: PAGE_PROTECTION_FLAGS) -> Option<Access> {
    if !STALE_SET.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    let mut m = STALE.lock().unwrap();
    let (&b, &(_, alias)) = m.range(..=page).next_back().filter(|(b, (n, _))| page < **b + n)?;
    if !charge(page, PAGE) {
        // SAFETY: plain call.
        return Some(Access::Exhausted(unsafe { GetLastError() }));
    }
    // SAFETY: the alias of the page: the userfaultfd's until it is released,
    // then the view's ([`uffd_unalias`]), unmapped only once its pages are
    // out of `STALE` (taken out under this lock, `unalias`).
    unsafe { std::ptr::write_bytes((alias + (page - b)) as *mut u8, 0, PAGE) };
    if !protect(page, PAGE, prot) {
        // Unmapped meanwhile: the access faults, as on Linux.
        return Some(Access::NotLazy);
    }
    stale_cut(&mut m, page, PAGE);
    drop(m);
    touched_mark(page, PAGE, true);
    Some(Access::Committed)
}

/// The view at `base` (`len` bytes, `kind`) is going: its pages out of
/// [`STALE`], then the alias it was handed, if any, unmapped.
fn unalias(base: usize, len: usize, kind: &Kind) {
    stale_remove(base, len);
    if let Kind::View { alias: Some(alias), .. } = kind {
        // SAFETY: unmaps the alias view made by `uffd_alias`.
        unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: *alias as *mut c_void }, 0) };
    }
}

/// A userfaultfd range `[start, start + len)` is released, its alias at
/// `alias` ([`uffd_alias`]) no longer the userfaultfd's: handed to the view
/// if the view has discarded pages still to zero ([`STALE`]), which keeps it
/// until it goes, else unmapped now.
/// `reserved`: the alias is one view per [`UFFD_CHUNK`], else one view.
pub(crate) fn uffd_unalias(start: usize, len: usize, alias: usize, reserved: bool) {
    let step = if reserved { UFFD_CHUNK } else { len };
    let mut t = table().lock().unwrap();
    for o in (0..len).step_by(step) {
        let n = step.min(len - o);
        if !stale_within(start + o, n).is_empty() {
            if let Some(Kind::View { alias: kept @ None, .. }) =
                t.get_mut(&(start + o)).filter(|r| r.len == n).map(|r| &mut r.kind)
            {
                *kept = Some(alias + o);
                continue;
            }
        }
        // SAFETY: unmaps an alias view made by `uffd_alias`.
        unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: (alias + o) as *mut c_void }, 0) };
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
pub(crate) fn committed_runs(s: usize, len: usize) -> Vec<(usize, usize)> {
    let (mut out, mut at, e) = (Vec::new(), s, s + len);
    while at < e {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            break;
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
        if mbi.State == MEM_COMMIT {
            out.push((at, run));
        }
        at += run;
    }
    out
}

/// Pages `[s, s + len)` of a userfaultfd range's reserved section that were
/// never filled, once the range is unregistered: lazy, committed and
/// charged at their first access, read or write, as the rest of an
/// anonymous shared mapping ([`fill`]), and as Linux's shmem allocates an
/// unregistered page at its fault.
/// Nothing is done unless a view of a mapping holds all of the pages (one
/// unmapped since is left alone).
pub(crate) fn uffd_lazy(s: usize, len: usize) {
    let mut t = table().lock().unwrap();
    let e = s + len;
    for b in overlapping(&t, s, e) {
        let r = t.get_mut(&b).unwrap();
        let (a, z) = (s.max(b), e.min(b + r.len));
        if matches!(r.kind, Kind::View { .. }) && a < z {
            r.lazy = true;
            lazy_add(a, z - a, PAGE_READWRITE);
        }
    }
}


/// The system calls in flight that copy memory of this module's mappings,
/// and the discards waiting for them. The kernel's copy of a system call
/// cannot fault a page in here, so a page discarded after the call's
/// prefault and before its copy reaches it fails the call, where Linux's
/// copy faults the page in again (v6.1 mm/userfaultfd.c `handle_userfault`,
/// mm/memory.c `do_anonymous_page`) and completes. A call that ends (a
/// regular file's, an `O_NONBLOCK` descriptor's: `windows_fd::read`,
/// `write`, `pread`, `pwrite`) is counted on its buffer's range from before
/// its prefault to its end ([`copying`]); a discard of an overlapping range
/// (`MADV_DONTNEED`, `MADV_FREE`, a `MAP_FIXED` mapping over it, as
/// Firecracker's `discard_range` does for a private file mapping) waits for
/// it ([`discard_waiting`]), and a call that starts while a discard of its
/// range waits waits for that discard, so a stream of calls cannot hold a
/// discard off. A call that can wait without end (a blocking socket's or
/// pipe's) goes through a buffer of its own instead (`windows_fd`), so no
/// discard waits on it. A userfaultfd handler in the same process that
/// discards a range a call is waiting on it to fill would wait for that
/// call (Firecracker's handler is another process).
struct InFlight {
    calls: Vec<(usize, usize)>,
    discards: Vec<(usize, usize)>,
}

static IN_FLIGHT: Mutex<InFlight> = Mutex::new(InFlight { calls: Vec::new(), discards: Vec::new() });
static IN_FLIGHT_CHANGED: std::sync::Condvar = std::sync::Condvar::new();

fn any_overlaps(ranges: &[(usize, usize)], s: usize, e: usize) -> bool {
    ranges.iter().any(|&(a, z)| a < e && s < z)
}

fn forget(ranges: &mut Vec<(usize, usize)>, range: (usize, usize)) {
    if let Some(i) = ranges.iter().position(|&r| r == range) {
        ranges.swap_remove(i);
    }
}

/// A system call in flight on `[.0, .1)` ([`copying`]), until dropped.
pub(crate) struct Copying(usize, usize);

impl Drop for Copying {
    fn drop(&mut self) {
        forget(&mut IN_FLIGHT.lock().unwrap().calls, (self.0, self.1));
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

/// Counts a system call copying `[addr, addr + len)` in flight ([`InFlight`]),
/// once no discard of an overlapping range waits.
pub(crate) fn copying(addr: usize, len: usize) -> Copying {
    let (s, e) = (addr, addr.saturating_add(len));
    let mut f = IN_FLIGHT.lock().unwrap();
    while any_overlaps(&f.discards, s, e) {
        f = IN_FLIGHT_CHANGED.wait(f).unwrap();
    }
    f.calls.push((s, e));
    Copying(s, e)
}

/// Waits until no system call copying memory of `[addr, addr + len)` is in
/// flight ([`InFlight`]); calls on the range wait while the result lives.
fn discard_waiting(addr: usize, len: usize) -> Discarding {
    let (s, e) = (addr, addr.saturating_add(len));
    let mut f = IN_FLIGHT.lock().unwrap();
    f.discards.push((s, e));
    while any_overlaps(&f.calls, s, e) {
        f = IN_FLIGHT_CHANGED.wait(f).unwrap();
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
    if (advice == MADV_DONTNEED || advice == MADV_FREE) && crate::wick_uffd::active() {
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
    const BATCH: usize = 512;
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
            return crate::windows_fd::raw_failed();
        }
        for (k, e) in info.iter().enumerate() {
            // SAFETY: reads the flags of the union.
            let valid = unsafe { e.VirtualAttributes.Flags } & 1;
            // SAFETY: the caller's contract.
            unsafe { *vec.add(i + k) = u8::from(valid != 0) };
        }
        i += n;
    }
    0
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
    // with an overflow: in `stale_within`, under the vectored exception
    // handler, that ended the process; PC step 14f).
    #[test]
    fn test_a_run_before_the_range_asked_about_is_not_in_it() {
        assert_eq!(ranges_within(&std::vec![(0, 0x1000), (0x3000, 0x1000)], 0x2000, 0x1000), Ranges::new());
        assert_eq!(ranges_within(&std::vec![(0, 0x1000), (0x2000, 0x2000)], 0x3000, 0x2000), std::vec![(0x3000, 0x1000)]);
        // STALE runs in the first 64 KiB, which no mapping can have (Windows
        // allocates nothing below 0x10000), so the access path of the other
        // tests never finds them.
        {
            let mut m = STALE.lock().unwrap();
            m.insert(0x1000, (0x1000, 0));
            m.insert(0x4000, (0x1000, 0));
            STALE_SET.store(true, std::sync::atomic::Ordering::Release);
        }
        let between = stale_within(0x3000, 0x1000);
        let into = stale_within(0x4800, 0x1000);
        stale_remove(0x1000, 0x4000);
        assert_eq!(between, std::vec![]);
        assert_eq!(into, std::vec![(0x4800, 0x800)]);
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
}
