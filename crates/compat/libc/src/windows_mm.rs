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
//!   zero-filled memory, as Linux faults in zero pages;
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
    PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
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
        super::commit_on_access(addr, write)
    }

    /// Ends the process for memory that could not be committed
    /// ([`Access::Exhausted`]), as the cgroup OOM killer ends the VMM.
    pub fn out_of_memory(addr: usize, err: u32) -> ! {
        super::out_of_memory(addr, err)
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

#[derive(Debug)]
enum Kind {
    Placeholder,
    /// Private memory; for a private file mapping, the file and offset it
    /// was filled from.
    Private {
        file: Option<(Arc<Owned>, i64)>,
    },
    /// A view of `section`, for shared file mappings with the file too.
    View {
        _section: Arc<Owned>,
        file: Option<Arc<Owned>>,
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

/// The parts of [off, off + len) that are in `v`.
fn ranges_within(v: &Ranges, off: usize, len: usize) -> Ranges {
    v.iter()
        .filter_map(|&(o, l)| {
            let (s, e) = (o.max(off), (o + l).min(off + len));
            (s < e).then_some((s, e - s))
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
        r.lazy = false;
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

/// Makes [start, end) one placeholder, from what the table has there, or
/// from free address space. `EINVAL` when it holds part of a private
/// allocation or view, or memory this module did not map.
fn make_placeholder(t: &mut Table, start: usize, end: usize) -> Result<(), c_int> {
    // Refused before anything changes: part of an allocation or view.
    for b in overlapping(t, start, end) {
        let r = &t[&b];
        if !matches!(r.kind, Kind::Placeholder) && (b < start || b + r.len > end) {
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
static LAZY: Mutex<Vec<(usize, usize, PAGE_PROTECTION_FLAGS)>> = Mutex::new(Vec::new());

/// How much is committed at a fault: a 64 KiB aligned block (clipped to its
/// range), so a guest touching its memory in order takes one exit per block
/// rather than per page.
const LAZY_CHUNK: usize = 64 << 10;

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

fn commit_on_access(addr: usize, write: bool) -> Access {
    let found = {
        let l = LAZY.lock().unwrap();
        let i = l.partition_point(|&(s, _, _)| s <= addr);
        i.checked_sub(1).map(|i| l[i]).filter(|&(s, n, _)| addr < s + n)
    };
    let Some((s, n, prot)) = found else {
        return Access::NotLazy;
    };
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
        return Access::NotLazy;
    }
    if mbi.State == MEM_COMMIT {
        // Committed since the access: another thread or vCPU committed its
        // block first (two vCPUs touching one block: measured, the second's
        // exit was emulated as MMIO and the guest took a bogus fault). The
        // access runs again; a write to memory mapped without write access
        // is a protection fault, not ours.
        let writable = matches!(prot, PAGE_READWRITE | PAGE_EXECUTE_READWRITE);
        return if write && !writable { Access::NotLazy } else { Access::Committed };
    }
    let block = addr - addr % LAZY_CHUNK;
    let (from, to) = (block.max(s), (block + LAZY_CHUNK).min(s + n));
    if commit(from, to - from, prot, false) {
        return Access::Committed;
    }
    // SAFETY: plain call.
    let err = unsafe { GetLastError() };
    // Another thread may have committed it meanwhile; only its page matters.
    let page = addr - addr % PAGE;
    if commit(page, PAGE, prot, false) {
        Access::Committed
    } else {
        Access::Exhausted(err)
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
        match commit_on_access(rec.ExceptionInformation[1], rec.ExceptionInformation[0] == 1) {
            Access::Committed => return windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION,
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

/// Commits what is lazy in the region at `base` and makes it ordinary
/// private memory (an `mprotect` over it, whose protections Windows cannot
/// set on pages that are not committed).
fn materialize(t: &mut Table, base: usize) -> bool {
    let r = t.get_mut(&base).unwrap();
    if !r.lazy {
        return true;
    }
    for (s, n, p) in lazy_within(base, r.len) {
        // Committed pages stay as they are; reserved ones get zero pages.
        if !commit(s, n, p, false) {
            return false;
        }
    }
    lazy_remove(base, r.len);
    r.lazy = false;
    true
}

fn commit(base: usize, len: usize, prot: PAGE_PROTECTION_FLAGS, replace: bool) -> bool {
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

/// Reads the file into private memory; past the end it stays zero.
fn fill_from_file(base: usize, len: usize, file: HANDLE, off: i64) -> bool {
    let fd = crate::windows_fd::to_fd_pub(file);
    let mut done = 0usize;
    while done < len {
        // SAFETY: the destination is our committed, writable memory.
        let n = unsafe {
            crate::windows_fd::pread(
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
        // Private file mapping: a private copy of the file.
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
            // SAFETY: creates a pagefile-backed section.
            let s = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_EXECUTE_READWRITE,
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
        Kind::View {
            _section: section,
            file,
        }
    };
    t.get_mut(&base).unwrap().kind = kind;
    if lazy {
        t.get_mut(&base).unwrap().lazy = true;
        lazy_add(base, len, wprot);
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
        // Anonymous private memory over part of one private allocation, as
        // Firecracker does to plug and unplug memory slots: the old pages are
        // dropped in place. Accessible memory is recommitted zero-filled;
        // `PROT_NONE` stays decommitted (no memory, no commit charge) and is
        // committed again by an `mprotect` that allows access.
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
                // SAFETY: decommits part of our allocation.
                unsafe { VirtualFree(s as *mut c_void, e - s, MEM_DECOMMIT) };
                lazy_remove(s, e - s);
            }
            Kind::View { .. } => {
                protect(s, e - s, PAGE_NOACCESS);
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
                // Windows sets no protection on pages not committed: lazy
                // memory is committed first, and is ordinary memory from then on.
                if r.lazy && !materialize(&mut t, b) {
                    return fail(crate::ENOMEM, -1);
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
pub(crate) fn uffd_alias(start: usize, len: usize, resident: &[u8]) -> Result<usize, c_int> {
    let mut t = table().lock().unwrap();
    match t.get(&start) {
        Some(r)
            if r.len == len
                && matches!(r.kind, Kind::Private { file: None })
                && r.holes.is_empty()
                && r.noaccess.is_empty() => {}
        _ => return Err(crate::EINVAL),
    }
    let hi = u32::try_from((len as u64) >> 32).unwrap();
    #[allow(clippy::cast_possible_truncation)]
    let lo = len as u32;
    // SAFETY: creates a pagefile-backed section.
    let s = unsafe {
        CreateFileMappingW(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE, hi, lo, std::ptr::null())
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
    for (i, &b) in resident.iter().enumerate() {
        if b & 1 != 0 {
            // SAFETY: a resident page of the mapping, into the alias.
            unsafe { std::ptr::copy_nonoverlapping((start + i * PAGE) as *const u8, (alias + i * PAGE) as *mut u8, PAGE) };
        }
    }
    let unmap = |a: usize| {
        // SAFETY: unmaps a view made here.
        unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: a as *mut c_void }, 0) };
    };
    // SAFETY: gives the private allocation back as a placeholder.
    if unsafe { VirtualFree(start as *mut c_void, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) } == 0 {
        unmap(alias);
        return Err(crate::EINVAL);
    }
    if view(start, MEM_REPLACE_PLACEHOLDER) != start {
        // The address space stays reserved; the memory is gone.
        t.get_mut(&start).unwrap().kind = Kind::Placeholder;
        unmap(alias);
        return Err(crate::ENOMEM);
    }
    let r = t.get_mut(&start).unwrap();
    r.kind = Kind::View {
        _section: section,
        file: None,
    };
    // A section is committed when it is touched, as the userfaultfd fills it.
    if r.lazy {
        lazy_remove(start, len);
        r.lazy = false;
    }
    Ok(alias)
}

/// Unmaps an alias made by [`uffd_alias`].
pub(crate) fn uffd_unalias(alias: usize) {
    // SAFETY: unmaps the alias view.
    unsafe { UnmapViewOfFile2(proc(), MEMORY_MAPPED_VIEW_ADDRESS { Value: alias as *mut c_void }, 0) };
}

/// `madvise`. Discarding registered userfaultfd memory makes its pages
/// missing again (`wick_uffd::discarding`), as on Linux.
///
/// # Safety
/// Same contract as `madvise(2)`.
pub unsafe fn madvise(addr: *mut c_void, len: size_t, advice: c_int) -> c_int {
    if (advice == MADV_DONTNEED || advice == MADV_FREE) && crate::wick_uffd::active() {
        let end = (addr as usize).saturating_add(len.div_ceil(PAGE) * PAGE);
        return crate::wick_uffd::discarding(addr as u64, (end - addr as usize) as u64, || {
            // SAFETY: the caller's contract.
            unsafe { madvise_plain(addr, len, advice) }
        });
    }
    // SAFETY: the caller's contract.
    unsafe { madvise_plain(addr, len, advice) }
}

/// `madvise` without the userfaultfd side.
///
/// # Safety
/// Same contract as `madvise(2)`.
unsafe fn madvise_plain(addr: *mut c_void, len: size_t, advice: c_int) -> c_int {
    let start = addr as usize;
    if !start.is_multiple_of(PAGE) {
        return fail(crate::EINVAL, -1);
    }
    let end = start + len.div_ceil(PAGE) * PAGE;
    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_DONTFORK | MADV_DOFORK
        | MADV_MERGEABLE | MADV_UNMERGEABLE | MADV_HUGEPAGE | MADV_NOHUGEPAGE | MADV_DONTDUMP
        | MADV_DODUMP | MADV_WILLNEED | MADV_DONTNEED | MADV_FREE => {}
        _ => return fail(crate::EINVAL, -1),
    }
    let t = table().lock().unwrap();
    if !covered(&t, start, end) {
        return fail(crate::ENOMEM, -1);
    }
    if advice == MADV_WILLNEED {
        let range = WIN32_MEMORY_RANGE_ENTRY {
            VirtualAddress: start as *mut c_void,
            NumberOfBytes: end - start,
        };
        // SAFETY: prefetches our mapping; advisory.
        unsafe { PrefetchVirtualMemory(proc(), 1, &range, 0) };
        return 0;
    }
    if advice != MADV_DONTNEED && advice != MADV_FREE {
        return 0;
    }
    for b in overlapping(&t, start, end) {
        let r = &t[&b];
        let (s, e) = (start.max(b), end.min(b + r.len));
        if let Kind::Large { page, fresh, .. } = r.kind {
            // Locked large pages cannot be dropped: they are zeroed in place,
            // whole pages only, as Linux drops whole huge pages (pages never
            // writable are zeros still).
            if !(s - b).is_multiple_of(page) || !(e - b).is_multiple_of(page) {
                return fail(crate::EINVAL, -1);
            }
            if !fresh {
                zero_large(s, e - s);
            }
            continue;
        }
        let Kind::Private { file } = &r.kind else {
            continue;
        };
        if !r.mapped_in(s - b, e - s) {
            return fail(crate::ENOMEM, -1);
        }
        // Run by run of equal protection, restored after.
        let mut at = s;
        while at < e {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: queries our memory.
            if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }
                == 0
            {
                return fail(crate::ENOMEM, -1);
            }
            let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(e) - at;
            if mbi.State != MEM_COMMIT {
                // Mapped `PROT_NONE` and decommitted: no pages to drop.
                at += run;
                continue;
            }
            // SAFETY: drops the pages of our private memory.
            unsafe { VirtualFree(at as *mut c_void, run, MEM_DECOMMIT) };
            // Lazy memory gets zero pages again at its next access.
            if !lazy_within(at, run).is_empty() {
                at += run;
                continue;
            }
            if !commit(at, run, PAGE_READWRITE, false) {
                return fail(crate::ENOMEM, -1);
            }
            if let Some((f, off)) = file {
                let from = *off + i64::try_from(at - b).unwrap();
                if !fill_from_file(at, run, f.0, from) {
                    return fail(crate::EIO, -1);
                }
            }
            protect(at, run, mbi.Protect);
            at += run;
        }
    }
    0
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
            return -1;
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
                return -1;
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

    fn state(addr: usize) -> u32 {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        assert_ne!(unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
        mbi.State
    }

    /// Anonymous private `MAP_NORESERVE` memory gets its pages at the first
    /// access, a 64 KiB block at a time, as Linux gives them when touched:
    /// mapped, nothing is committed; a write commits its block only; a
    /// discarded block goes back to reserved and reads zero; the guest's
    /// access (the hypervisor's report) commits as a host access does; an
    /// `mprotect` makes the whole mapping ordinary memory.
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
        assert_eq!(state(p + (1 << 20) + LAZY_CHUNK - PAGE), MEM_COMMIT);
        assert_eq!(state(p + (1 << 20) + LAZY_CHUNK), MEM_RESERVE, "more than the block was committed");
        assert_eq!(state(p + (1 << 20) - PAGE), MEM_RESERVE, "more than the block was committed");
        // SAFETY: as above.
        assert_eq!(unsafe { *((p + (1 << 20) + 5) as *const u8) }, 7);
        // The guest's access, as WHP reports it.
        assert_eq!(wick_mm::commit_on_access(p + (2 << 20), true), Access::Committed);
        assert_eq!(state(p + (2 << 20)), MEM_COMMIT);
        // Committed meanwhile (another vCPU first): run again.
        // Discarded: reserved again, zero at the next read.
        // SAFETY: our mapping.
        assert_eq!(unsafe { madvise((p + (1 << 20)) as *mut c_void, LAZY_CHUNK, MADV_DONTNEED) }, 0);
        assert_eq!(state(p + (1 << 20)), MEM_RESERVE);
        // SAFETY: as above.
        assert_eq!(unsafe { *((p + (1 << 20) + 5) as *const u8) }, 0);
        // mprotect: the whole mapping committed, and no longer lazy.
        // SAFETY: as above.
        assert_eq!(unsafe { mprotect(p as *mut c_void, len, PROT_READ) }, 0);
        assert_eq!(state(p), MEM_COMMIT);
        assert_eq!(state(p + len - PAGE), MEM_COMMIT);
        assert_eq!(wick_mm::commit_on_access(p, false), Access::NotLazy);
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
            assert_eq!(madvise(page as *mut c_void, PAGE, MADV_DONTNEED), -1, "part of a large page");
            assert_eq!(madvise(page as *mut c_void, large, MADV_DONTNEED), 0);
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
