// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Linux-only `libc` items Firecracker uses, implemented for macOS.
//!
//! Each item either does what it does on Linux, with macOS means, or fails
//! with an error. None of them reports success for something it did not do
//! (docs/ROADMAP.md lists the differences):
//! - `eventfd` and `timerfd` flags and calls are implemented by the macOS
//!   `vmm-sys-util` and in [`crate::timerfd`];
//! - `mmap`: `MAP_POPULATE` prefaults; `MAP_HUGETLB`, and a huge page
//!   memfd, map 2 MiB pages as Linux's hugetlb does for what Firecracker
//!   sees (2 MiB alignment and size, a userfaultfd that faults and fills
//!   2 MiB at a time), on host pages: macOS gives user space no superpage
//!   on Apple silicon ([`mmap_huge`]); `munmap` keeps hugetlb's alignment
//!   rule;
//! - `prctl`: speculative store bypass control uses `PSTATE.SSBS`; options
//!   macOS cannot honour fail with `EINVAL`, like an unknown option on Linux;
//! - block device ioctls map to the `DKIOC*` equivalents;
//! - Linux syscall numbers (`SYS_seccomp`, `SYS_io_uring_*`) are numbers macOS
//!   does not use; [`syscall`] fails with `ENOSYS` for them instead of passing
//!   them to the kernel (which would raise `SIGSYS`);
//! - address families macOS lacks (`AF_PACKET`) are `-1`, so `socket` fails.

use core::ffi::c_void;

use core::sync::atomic::{AtomicU8, Ordering};
use upstream::{self as libc, c_int, c_uchar, c_ulong, c_ushort, off_t, sa_family_t, size_t};

// ---- eventfd (implemented by vmm-sys-util's macOS eventfd) ----

/// `eventfd` flag: close on exec.
pub const EFD_CLOEXEC: c_int = libc::O_CLOEXEC;
/// `eventfd` flag: non-blocking.
pub const EFD_NONBLOCK: c_int = libc::O_NONBLOCK;
/// `eventfd` flag: semaphore semantics.
pub const EFD_SEMAPHORE: c_int = 1;

// ---- mmap / madvise ----

/// Huge page mapping. A bit macOS `mmap` does not use: [`mmap`] refuses it.
pub const MAP_HUGETLB: c_int = 0x0100_0000;
/// Shift of the huge page size in `mmap` flags (Linux value).
pub const MAP_HUGE_SHIFT: c_int = 26;
/// 2 MiB huge pages (Linux value; only meaningful with `MAP_HUGETLB`).
pub const MAP_HUGE_2MB: c_int = 21 << MAP_HUGE_SHIFT;
/// 1 GiB huge pages (Linux value; only meaningful with `MAP_HUGETLB`).
pub const MAP_HUGE_1GB: c_int = 30 << MAP_HUGE_SHIFT;
/// Prefault the mapping. A bit macOS `mmap` does not use: [`mmap`] handles it.
pub const MAP_POPULATE: c_int = 0x0200_0000;
/// Transparent huge page advice (Linux value): [`madvise`] takes it as Linux
/// takes it on a host whose transparent huge pages are `never`.
pub const MADV_HUGEPAGE: c_int = 14;
/// No transparent huge pages for the range (Linux value): as
/// [`MADV_HUGEPAGE`].
pub const MADV_NOHUGEPAGE: c_int = 15;

const HUGE_FLAGS: c_int = MAP_HUGETLB | (0x3f << MAP_HUGE_SHIFT);
/// The huge page size: 2 MiB, Linux's default on x86_64 and on aarch64 with
/// 4 KiB pages, and the one Firecracker's `huge_pages` asks for.
pub(crate) const HUGE_PAGE: u64 = 2 << 20;

/// The check upstream's seccomp filters make of `mmap` and `mprotect`, which
/// trap when the protection includes `PROT_EXEC`, for the host sandbox
/// (`vmm::ext::sandbox`) to turn on once it narrows.
///
/// macOS has no kernel rule for it: Seatbelt filters a system call by number
/// only, and an anonymous mapping made executable runs, also under the
/// hardened runtime (measured on macOS 27 with an ad-hoc signature).
/// Seatbelt's own rules end the process for a file mapped executable
/// (`file-map-executable`) and a `MAP_JIT` mapping
/// (`dynamic-code-generation`).
pub mod wick_mm {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::c_int;

    static EXEC_DENIED: AtomicUsize = AtomicUsize::new(0);

    /// From now on, [`super::mmap`] and [`super::mprotect`] call `hook` when
    /// asked for `PROT_EXEC` (the hook ends the process as a denied call);
    /// if it returns, the call fails with `EPERM`. As the Windows
    /// compatibility libc's.
    pub fn deny_exec(hook: extern "C" fn(c_int)) {
        EXEC_DENIED.store(hook as usize, Ordering::Release);
    }

    /// Whether a call asking for `prot` is denied, after the hook ran.
    pub(super) fn exec_denied(prot: c_int) -> bool {
        if prot & upstream::PROT_EXEC == 0 {
            return false;
        }
        let hook = EXEC_DENIED.load(Ordering::Acquire);
        if hook == 0 {
            return false;
        }
        // SAFETY: only `extern "C" fn(c_int)` values are stored.
        let hook: extern "C" fn(c_int) = unsafe { core::mem::transmute(hook) };
        hook(prot);
        super::set_errno(upstream::EPERM);
        true
    }

    static ADVICE_DENIED: AtomicUsize = AtomicUsize::new(0);
    static ADVICE_ALLOWED: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

    /// From now on, [`super::madvise`] calls `hook` for any advice but
    /// `allowed` (the hook ends the process as a denied call); if it
    /// returns, the call fails with `EPERM`. The check of upstream's `api`
    /// filter, which allows `madvise` with `MADV_DONTNEED` only, for the API
    /// process (`vmm::ext::api_process`). Only calls through this crate are
    /// checked: the system libraries' own (libmalloc's) and a raw system
    /// call are not.
    pub fn allow_only_advice(allowed: c_int, hook: extern "C" fn(c_int)) {
        ADVICE_ALLOWED.store(allowed, Ordering::Release);
        ADVICE_DENIED.store(hook as usize, Ordering::Release);
    }

    /// Whether a call with `advice` is denied, after the hook ran.
    pub(super) fn advice_denied(advice: c_int) -> bool {
        let hook = ADVICE_DENIED.load(Ordering::Acquire);
        if hook == 0 || advice == ADVICE_ALLOWED.load(Ordering::Acquire) {
            return false;
        }
        // SAFETY: only `extern "C" fn(c_int)` values are stored.
        let hook: extern "C" fn(c_int) = unsafe { core::mem::transmute(hook) };
        hook(advice);
        super::set_errno(upstream::EPERM);
        true
    }
}

/// `mprotect`, with the [`wick_mm`] check, and Linux's meaning on memory a
/// userfaultfd has registered: the registration stays and its missing pages
/// keep faulting to the userfaultfd ([`crate::wick_uffd::protecting`]).
///
/// # Safety
/// Same contract as `mprotect(2)`.
pub unsafe fn mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> c_int {
    if wick_mm::exec_denied(prot) {
        return -1;
    }
    let rc = crate::wick_uffd::protecting(addr as u64, len as u64, prot, |at, n| {
        crate::wick_uffd::protection_change(
            // SAFETY: the caller's contract, for a part of its range.
            || unsafe { libc::mprotect(at as *mut c_void, n as usize, prot) },
            |rc| (*rc == 0).then_some((at, n, prot)),
        )
    });
    // Failed or not: a failure part way leaves the pieces before it changed.
    tell_guest(addr as u64, len as u64, false);
    rc
}

/// Tells the hypervisor backend that the protection or the mapping of
/// `[start, start + len)` may have changed ([`crate::wick_guest::protected`]),
/// so that stage 2 follows it, as KVM's stage 2 follows the vmas through
/// the MMU notifier; `replaced` when the call may have put other pages
/// there ([`crate::wick_guest::Hooks::protected`]). After the change
/// returned, with `errno` kept.
fn tell_guest(start: u64, len: u64, replaced: bool) {
    // SAFETY: this thread's errno.
    let saved = unsafe { *libc::__error() };
    crate::wick_guest::protected(start, len, replaced);
    // SAFETY: as above.
    unsafe { *libc::__error() = saved };
}

/// `mmap` with the Linux flags above.
///
/// - `MAP_HUGETLB` with `MAP_ANONYMOUS`, or a huge page memfd
///   ([`shm_object`]) with any flags: [`mmap_huge`]; `MAP_HUGETLB` with
///   another file: `EINVAL`, as Linux (`ksys_mmap_pgoff`); the `MAP_HUGE_*`
///   size bits alone mean nothing, as on Linux;
/// - a memfd of the compatibility `memfd` crate (a POSIX shared memory
///   object, [`shm_object`]) without `MAP_SHARED`: `EINVAL`, before
///   anything is changed. Linux maps it, as any file, copy-on-write; macOS
///   maps such an object only shared (xnu-12377.1.9 bsd/kern/posix_shm.c
///   `pshm_mmap` :763 to :765), and a copy of it, as macOS's private file
///   mappings are (see [`memfd_create`]), would not follow the object until
///   its own write as Linux's mapping does.
///   Firecracker maps its memfds shared only (`memfd_backed`, `IovDeque`);
///   `test_a_private_mapping_of_a_shared_memory_object_is_refused`;
/// - `MAP_POPULATE`: the range is prefaulted after mapping (`MADV_WILLNEED`
///   and a read of every page when it is readable);
/// - `MAP_FIXED`: what the range holds of guest memory is unmapped from the
///   guest while the mapping replaces its pages, and mapped again after
///   ([`crate::wick_guest`]); what it held of userfaultfd registrations goes
///   in the same step ([`crate::wick_uffd::unmapping`]); a range that cuts a
///   huge page mapping off its huge page boundaries is `EINVAL`
///   ([`huge_cut_allowed`]);
/// - `PROT_EXEC` once the host sandbox narrowed: see [`wick_mm`].
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
    if wick_mm::exec_denied(prot) {
        return libc::MAP_FAILED;
    }
    if flags & libc::MAP_ANON != 0 {
        if flags & MAP_HUGETLB != 0 {
            // SAFETY: the caller's contract.
            return mapped(addr, len, prot, flags, unsafe { mmap_huge(addr, len, prot, flags, -1, 0) });
        }
    } else {
        let shm = shm_object(fd);
        if shm.is_some() && flags & libc::MAP_SHARED == 0 {
            // Before anything is changed: a MAP_FIXED one leaves the range,
            // its registrations and the guest's view of it as they were.
            set_errno(libc::EINVAL);
            return libc::MAP_FAILED;
        }
        if shm == Some(true) {
            // SAFETY: the caller's contract.
            return mapped(addr, len, prot, flags, unsafe { mmap_huge(addr, len, prot, flags, fd, offset) });
        }
        if flags & MAP_HUGETLB != 0 {
            set_errno(libc::EINVAL);
            return libc::MAP_FAILED;
        }
    }
    if flags & libc::MAP_FIXED != 0 && !huge_cut_allowed(addr as u64, len as u64) {
        set_errno(libc::EINVAL);
        return libc::MAP_FAILED;
    }
    // SAFETY: forwarded with the Linux-only bits removed.
    let ptr = unsafe { mmap_fixed_aware(addr, len, prot, flags & !(MAP_POPULATE | HUGE_FLAGS), fd, offset) };
    if ptr != libc::MAP_FAILED {
        crate::wick_uffd::note_mapping(ptr as u64, len as u64, false);
    }
    if ptr != libc::MAP_FAILED && flags & MAP_POPULATE != 0 {
        // SAFETY: the range was just mapped.
        unsafe { libc::madvise(ptr, len, libc::MADV_WILLNEED) };
        if prot & libc::PROT_READ != 0 {
            // SAFETY: sysconf has no preconditions.
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as usize;
            let mut off = 0;
            while off < len {
                // SAFETY: inside the readable mapping created above.
                unsafe { core::ptr::read_volatile(ptr.cast::<u8>().add(off)) };
                off += page;
            }
        }
    }
    mapped(addr, len, prot, flags, ptr)
}

/// What [`mmap`] returns, once the hypervisor backend was told
/// ([`tell_guest`]): of the new mapping, and with `MAP_FIXED` of the range
/// asked for also when the call failed (a fixed mapping that fails may have
/// released what was there). A huge page mapping's length is rounded up to
/// whole huge pages here, as [`mmap_huge`] maps it.
fn mapped(addr: *mut c_void, len: size_t, prot: c_int, flags: c_int, ptr: *mut c_void) -> *mut c_void {
    let huge = flags & MAP_HUGETLB != 0
        || (ptr != libc::MAP_FAILED && crate::wick_uffd::touches_huge(ptr as u64, ptr as u64 + 1));
    // A length past the address space (an mmap refused for it) is told as
    // it is: the hook clamps its range.
    let len = if huge { (len as u64).checked_next_multiple_of(HUGE_PAGE).unwrap_or(len as u64) } else { len as u64 };
    if ptr != libc::MAP_FAILED {
        // A fixed mapping's was recorded with its system call
        // ([`mmap_replacing`]).
        // A new mapping is where nothing was, or where something was
        // unmapped since: its pages may not be the ones stage 2 holds. A
        // fixed mapping's were put there by the replace hook.
        let fixed = flags & libc::MAP_FIXED != 0;
        if !fixed {
            crate::wick_uffd::note_protection(ptr as u64, len, prot);
        }
        tell_guest(ptr as u64, len, !fixed);
    } else if flags & libc::MAP_FIXED != 0 {
        // A fixed mapping that failed may have released what was there.
        tell_guest(addr as u64, len, true);
    }
    ptr
}

/// `mmap` of a huge page mapping as Firecracker sees Linux's hugetlb ones:
/// anonymous memory with `MAP_HUGETLB` (`fd` -1), or a huge page memfd
/// ([`shm_object`]; hugetlbfs files map huge with or without the flag).
///
/// macOS gives user space no superpage on Apple silicon: `mach_vm_allocate`
/// and `mmap` with `VM_FLAGS_SUPERPAGE_SIZE_2MB` or `_ANY` fail with
/// `KERN_INVALID_ARGUMENT` / `EINVAL` for 2 MiB to 64 MiB (measured on
/// macOS 27.2, M1 Pro; `test_no_host_superpages`), and Hypervisor.framework
/// takes no page size. So the memory is host pages, and what Linux's hugetlb
/// mapping guarantees the program is kept: the address is a multiple of
/// [`HUGE_PAGE`] (Firecracker relies on it: `allocate_protected` does not
/// over-allocate for hugetlb), the size is rounded up to whole huge pages,
/// a `MAP_FIXED` address or a file offset that is not a multiple fails with
/// `EINVAL`, a file whose size is not whole huge pages fails with `EINVAL`
/// (hugetlbfs refuses that size at `ftruncate`, which macOS's goes through
/// unchecked), a size other than 2 MiB (`MAP_HUGE_1GB`, ...) fails with
/// `ENOMEM` as Linux without a pool of that size does, a length too large
/// to round with `ENOMEM`, and a userfaultfd registered on the mapping
/// faults and fills it 2 MiB at a time ([`crate::wick_uffd`], which is
/// told of the mapping here). The pages are not pinned and the TLB reach is
/// the host's; docs/PORTING.md row 10.
///
/// # Safety
/// Same contract as `mmap(2)`.
unsafe fn mmap_huge(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    let size = (flags >> MAP_HUGE_SHIFT) & 0x3f;
    if size != 0 && size != 21 {
        set_errno(libc::ENOMEM);
        return libc::MAP_FAILED;
    }
    let huge = HUGE_PAGE as usize;
    let Some(len) = len.checked_next_multiple_of(huge).filter(|&l| l > 0) else {
        set_errno(if len == 0 { libc::EINVAL } else { libc::ENOMEM });
        return libc::MAP_FAILED;
    };
    if fd >= 0 {
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        // SAFETY: an out-parameter; the descriptor is the caller's.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return libc::MAP_FAILED;
        }
        if offset % HUGE_PAGE as off_t != 0 || st.st_size % HUGE_PAGE as off_t != 0 {
            set_errno(libc::EINVAL);
            return libc::MAP_FAILED;
        }
    }
    let flags = flags & !(MAP_POPULATE | HUGE_FLAGS);
    let ptr = if flags & libc::MAP_FIXED != 0 {
        if !(addr as usize).is_multiple_of(huge) {
            set_errno(libc::EINVAL);
            return libc::MAP_FAILED;
        }
        // SAFETY: the caller's contract.
        unsafe { mmap_fixed_aware(addr, len, prot, flags, fd, offset) }
    } else {
        // A reservation a huge page larger than needed, the mapping made
        // fixed at its first huge page boundary, the rest released.
        let Some(reserve) = len.checked_add(huge) else {
            set_errno(libc::ENOMEM);
            return libc::MAP_FAILED;
        };
        // SAFETY: a new anonymous reservation.
        let raw = unsafe {
            libc::mmap(addr, reserve, libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0)
        };
        if raw == libc::MAP_FAILED {
            return raw;
        }
        let aligned = (raw as usize).next_multiple_of(huge);
        let head = aligned - raw as usize;
        // SAFETY: over the reservation made above.
        let ptr = unsafe {
            libc::mmap(aligned as *mut c_void, len, prot, flags | libc::MAP_FIXED, fd, offset)
        };
        let err = io_errno();
        // SAFETY: the head and the tail of the reservation, or all of it.
        unsafe {
            if ptr == libc::MAP_FAILED {
                libc::munmap(raw, reserve);
                set_errno(err);
                return libc::MAP_FAILED;
            }
            if head > 0 {
                libc::munmap(raw, head);
            }
            if huge - head > 0 {
                libc::munmap((aligned + len) as *mut c_void, huge - head);
            }
        }
        ptr
    };
    if ptr != libc::MAP_FAILED {
        crate::wick_uffd::note_mapping(ptr as u64, len as u64, true);
    }
    ptr
}

/// [`mmap_replacing`], and with `MAP_FIXED` what it maps over leaves its
/// userfaultfd registration in the same step ([`crate::wick_uffd::unmapping`]),
/// as Linux's `MAP_FIXED` unmaps the vmas first. Not for a discard, whose
/// `MAP_FIXED` keeps the registration (Linux's `MADV_DONTNEED` keeps the
/// vma).
///
/// # Safety
/// Same contract as `mmap(2)`.
unsafe fn mmap_fixed_aware(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    if flags & libc::MAP_FIXED == 0 {
        // SAFETY: the caller's contract.
        return unsafe { libc::mmap(addr, len, prot, flags, fd, offset) };
    }
    crate::wick_uffd::unmapping(
        addr as u64,
        len as u64,
        true,
        // SAFETY: the caller's contract.
        || unsafe { mmap_replacing(true, addr, len, prot, flags, fd, offset) },
        |p| *p != libc::MAP_FAILED,
    )
}

/// Whether `[start, start + len)` may be unmapped or mapped over: a range
/// that touches a huge page mapping must start and end on huge page
/// boundaries, as Linux refuses to split a hugetlb vma elsewhere (mm/vma.c,
/// v6.12, `__split_vma` :377 to :378, `may_split`; munmap and `MAP_FIXED`
/// split the vmas they cut before anything is unmapped, `vms_gather_munmap_vmas`
/// :1209 and :1230), `EINVAL` with nothing changed.
fn huge_cut_allowed(start: u64, len: u64) -> bool {
    let end = start.saturating_add(len);
    !crate::wick_uffd::touches_huge(start, end) || (start.is_multiple_of(HUGE_PAGE) && end.is_multiple_of(HUGE_PAGE))
}

/// The host's `mmap`; with `MAP_FIXED`, the guest's view of `[addr, addr +
/// len)` is replaced with it ([`crate::wick_guest::replacing`]): a new
/// mapping's pages with its protection when `anew`, a discard's fresh pages
/// with the protection the range had otherwise.
///
/// # Safety
/// Same contract as `mmap(2)`.
unsafe fn mmap_replacing(
    anew: bool,
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    if flags & libc::MAP_FIXED == 0 {
        // SAFETY: the caller's contract.
        return unsafe { libc::mmap(addr, len, prot, flags, fd, offset) };
    }
    crate::wick_guest::replacing(addr as u64, len as u64, anew, || {
        // A new mapping's protection is recorded with its system call; a
        // discard keeps the range's.
        crate::wick_uffd::protection_change(
            // SAFETY: the caller's contract.
            || unsafe { libc::mmap(addr, len, prot, flags, fd, offset) },
            |p| (anew && *p != libc::MAP_FAILED).then_some((addr as u64, len as u64, prot)),
        )
    })
}

/// The last error's number.
fn io_errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// Whether `fd` is a POSIX shared memory object, as the compatibility
/// `memfd` crate makes a memfd (`Some`), and then whether it is a huge page
/// memfd: one named `/fcmH.<pid>.<random>`; the object keeps its name after
/// `shm_unlink` and through `dup` (measured; `proc_pidfdinfo` with
/// `PROC_PIDFDPSHMINFO`, which the narrowed sandbox allows as `proc_info`).
/// An object's `fstat` tells nothing (device and inode 0, measured), so the
/// name is the mark. `None` for any other descriptor or none.
fn shm_object(fd: c_int) -> Option<bool> {
    if fd < 0 {
        return None;
    }
    // struct pshm_fdinfo: 1192 bytes, pshminfo.pshm_name at 168 (measured).
    const PROC_PIDFDPSHMINFO: c_int = 5;
    const SIZE: usize = 1192;
    const NAME_AT: usize = 168;
    let mut info = [0u8; SIZE];
    // SAFETY: a buffer of the size passed; our own pid.
    let n = unsafe {
        libc::proc_pidfdinfo(
            std::process::id() as c_int,
            fd,
            PROC_PIDFDPSHMINFO,
            info.as_mut_ptr().cast(),
            SIZE as c_int,
        )
    };
    (n as usize == SIZE).then(|| info[NAME_AT..].starts_with(crate::HUGE_MEMFD_PREFIX.as_bytes()))
}

/// `munmap`, with hugetlb's rule: a range that touches a huge page mapping
/// must start and end on huge page boundaries (`EINVAL`, as Linux refuses
/// to split a hugetlb mapping elsewhere, [`huge_cut_allowed`]). A mapping
/// taken down is no longer huge for [`crate::wick_uffd`], and what it held
/// of userfaultfd registrations goes with it, in the same step
/// ([`crate::wick_uffd::unmapping`]).
///
/// # Safety
/// Same contract as `munmap(2)`.
pub unsafe fn munmap(addr: *mut c_void, len: size_t) -> c_int {
    let start = addr as u64;
    if !huge_cut_allowed(start, len as u64) {
        set_errno(libc::EINVAL);
        return -1;
    }
    // The registration of what it unmaps goes in the same step, as Linux's
    // goes with the vma.
    let unmap = || {
        crate::wick_uffd::protection_change(
            // SAFETY: the caller's contract.
            || unsafe { libc::munmap(addr, len) },
            |rc| (*rc == 0).then_some((start, len as u64, -1)),
        )
    };
    let rc = crate::wick_uffd::unmapping(start, len as u64, false, unmap, |rc| *rc == 0);
    if rc == 0 {
        crate::wick_uffd::note_mapping(start, len as u64, false);
        tell_guest(start, len as u64, true);
    }
    rc
}

/// What one VM map entry holds, as far as `MADV_DONTNEED` cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backing {
    /// `MAP_SHARED`: the pages belong to an object other mappings see.
    Shared,
    /// Private memory with no file under it.
    Anonymous,
    /// A private file mapping (`vm_entry`), or a piece of one with no private
    /// (copied-on-write) pages (`dontneed`).
    File,
    /// A piece of a private file mapping that has private pages.
    FileCopied,
}

unsafe extern "C" {
    fn mach_vm_region(
        task: libc::mach_port_t,
        address: *mut u64,
        size: *mut u64,
        flavor: c_int,
        info: *mut c_int,
        count: *mut u32,
        object_name: *mut libc::mach_port_t,
    ) -> c_int;
    static mach_task_self_: libc::mach_port_t;
}

/// Returns `(start, end, backing, protection)` of the VM map entry at or
/// after `addr`.
fn vm_entry(addr: u64) -> Option<(u64, u64, Backing, c_int)> {
    const VM_REGION_BASIC_INFO_64: c_int = 9;
    const VM_INHERIT_SHARE: u32 = 0;
    let (mut start, mut size, mut object) = (addr, 0u64, 0);
    let mut basic = [0 as c_int; 16];
    let mut count = 9u32;
    // SAFETY: valid output buffers; `basic` is larger than the flavor.
    let ret = unsafe {
        mach_vm_region(
            mach_task_self_,
            &mut start,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            basic.as_mut_ptr(),
            &mut count,
            &mut object,
        )
    };
    if ret != 0 {
        return None;
    }
    // vm_region_basic_info_64: protection, max_protection, inheritance, ...
    // (VM_PROT_* bits are PROT_* bits).
    let protection = basic[0];
    let inheritance = basic[2] as u32;
    let backing = if inheritance == VM_INHERIT_SHARE {
        Backing::Shared
    } else if file_under(start) {
        Backing::File
    } else {
        Backing::Anonymous
    };
    Some((start, start + size, backing, protection))
}

/// `struct proc_regioninfo` of <sys/proc_info.h>.
#[repr(C)]
struct ProcRegionInfo {
    /// `pri_protection` to `pri_flags`.
    _head: [u32; 4],
    _offset: u64,
    /// `pri_behavior` to `pri_depth`.
    _counts: [u32; 14],
    address: u64,
    size: u64,
}

/// `struct proc_regionwithpathinfo` of <sys/proc_info.h>.
#[repr(C)]
struct ProcRegionWithPathInfo {
    region: ProcRegionInfo,
    vnode: libc::vnode_info_path,
}

/// The SDK's `sizeof(struct proc_regionwithpathinfo)`, which `proc_pidinfo`
/// checks.
const _: () = assert!(core::mem::size_of::<ProcRegionWithPathInfo>() == 1272);

/// Whether a file backs the entry at `addr`, somewhere in its shadow chain:
/// `PROC_PIDREGIONPATHINFO` names the vnode of the entry itself (its
/// `pri_address` is the entry's start). Not `proc_regionfilename`, whose
/// flavour (`PROC_PIDREGIONPATHINFO2`) looks for the next entry with a
/// vnode at or after `addr`, so it names a file for anonymous memory below
/// a file mapping (measured, macOS 27.2). The shadow chain's own depth and
/// external pager do not tell either: once every page of a private file
/// mapping is copied, its entry reports a shadow depth of 0 and no
/// external pager, as anonymous memory does (measured).
fn file_under(addr: u64) -> bool {
    const PROC_PIDREGIONPATHINFO: c_int = 8;
    // SAFETY: an all-zero struct of integers is valid.
    let mut info: ProcRegionWithPathInfo = unsafe { core::mem::zeroed() };
    let size = core::mem::size_of::<ProcRegionWithPathInfo>() as c_int;
    // SAFETY: a valid output buffer of `size` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            addr,
            (&mut info as *mut ProcRegionWithPathInfo).cast(),
            size,
        )
    };
    let region = &info.region;
    n == size && region.address <= addr && addr - region.address < region.size && info.vnode.vip_vi.vi_type != 0
}

/// Whether any page of `[start, end)`, part of a private file mapping, has
/// been copied (written, and so private), as `mincore` reports it.
///
/// XNU's `mincore` (xnu-12377.1.9 bsd/kern/kern_mman.c :1641 to :1646) sets
/// `MINCORE_COPIED` (bsd/sys/mman.h :235) for a page the VM query found
/// copied, and `MINCORE_ANONYMOUS` (:236) for one it found outside a file's
/// object. The query (osfmk/vm/vm_map.c `vm_map_page_range_info_internal`)
/// looks the page up in the entry's top object, then down its shadow chain
/// (:20966 to :21007), and stops at the first object that holds the page,
/// resident or compressed (`VM_PAGE_QUERY_PAGE_PAGED_OUT`, :20978 to
/// :20981), or at the chain's end. It reports the page copied when it
/// stopped in the top object and that object has a shadow, and external
/// when the object it stopped in is not an internal one (:21019 to :21025).
/// So:
/// - a written page of a private file mapping, resident, compressed or
///   swapped, is in the top object, an internal one shadowing the file:
///   `MINCORE_COPIED | MINCORE_ANONYMOUS`;
/// - a page never written, resident in the file's cache or not, is found in
///   the file's object or nowhere, and the walk ends there, with no shadow
///   below it: neither flag.
///
/// A page with either flag is taken as copied. Each flag alone tells the
/// cases of `test_madvise_dontneed_of_a_private_file_mapping_with_copied_pages_is_einval`
/// apart (none, one and every page copied; it passes with either read
/// alone, and fails with neither).
fn copied(start: u64, end: u64) -> bool {
    const MINCORE_COPIED: u8 = 0x40;
    const MINCORE_ANONYMOUS: u8 = 0x80;
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let mut state = std::vec![0u8; (end - start).div_ceil(page) as usize];
    // SAFETY: one byte a page of a mapped range.
    let r = unsafe { libc::mincore(start as *mut c_void, (end - start) as size_t, state.as_mut_ptr().cast()) };
    // A query that fails is taken as copied: refused, not discarded wrongly.
    r != 0 || state.iter().any(|s| s & (MINCORE_COPIED | MINCORE_ANONYMOUS) != 0)
}

/// `madvise` with the Linux meaning of `MADV_DONTNEED` and `MADV_FREE`:
/// after a `MADV_DONTNEED` private anonymous memory reads as zeros and its
/// pages are released, and shared memory keeps its contents (the pages are
/// only dropped from this mapping).
///
/// macOS's own `MADV_DONTNEED` is only a hint, so a private anonymous range
/// gets fresh zero pages: an anonymous `MAP_FIXED` mapping with its
/// protection replaces it, with the guest's view of it replaced too
/// ([`crate::wick_guest`]). Not `MADV_ZERO` and `MADV_FREE_REUSABLE`: pages
/// a guest has mapped are not released by them (measured: the footprint of
/// 64 MiB of guest pages stayed at 65.8 MiB), and pages marked reusable that
/// the guest writes again are not charged to the footprint again, which
/// would let a guest past the jailer's memory limit. A private file mapping
/// whose pages have been copied would have to fall back to the file's
/// contents, which macOS offers no call for: a range holding one fails with
/// `EINVAL` before anything changes (Firecracker remaps such memory instead,
/// see `discard_range`).
///
/// The range is taken as Linux takes it (`mm/madvise.c`): a start that is
/// not page aligned, or a length that overflows when rounded up to pages,
/// is `EINVAL`; a length of 0 does nothing; the mapped parts are discarded
/// and unmapped pages in the range then give `ENOMEM`. In a huge page
/// mapping ([`mmap_huge`]) the start must be huge page aligned (`EINVAL`,
/// with the parts before it discarded) and the end is rounded down to a huge
/// page.
///
/// `MADV_FREE` is taken as Linux takes it (v6.12 mm/madvise.c
/// `madvise_vma_behavior` :1046, with `MADV_DONTNEED` to
/// `madvise_dontneed_free` :880): the range is checked as above, and the
/// pieces are taken in order. A huge page mapping is `EINVAL`
/// (`madvise_dontneed_free_valid_vma` :864, before any remove event);
/// memory that is not private anonymous (shared memory, a file mapping) is
/// `EINVAL` after the remove event a userfaultfd that registered it asked
/// for (`userfaultfd_remove` :894, then `madvise_free_single_vma` :797),
/// its pages unchanged; private anonymous memory is discarded as by
/// `MADV_DONTNEED`. Linux frees such pages lazily: until reclaim takes them
/// they may keep their contents, and once taken they read as zeros, or, a
/// userfaultfd's, are missing; freeing them at once is the second of those
/// outcomes. macOS's own `MADV_FREE` (5) is not used: it frees lazily too,
/// but a registered page it frees reads as zeros with no fault, where
/// Linux's would fault to the userfaultfd.
///
/// `MADV_HUGEPAGE` and `MADV_NOHUGEPAGE` (Firecracker's `huge_pages:
/// Transparent`) are advice on Linux too: with transparent huge pages set to
/// `never` the call succeeds and the range stays on small pages. macOS gives
/// user space no superpage (`test_no_host_superpages`), so that is what this
/// host is: the range is checked as Linux checks it (`EINVAL` for a start off
/// a page or a wrapping length, `ENOMEM` for unmapped pages) and the call
/// succeeds; the memory stays on host pages (docs/PORTING.md row 10).
/// macOS has no advice of these numbers, so they must not be passed on.
///
/// Other advice is passed through. Advice [`wick_mm::allow_only_advice`]
/// denies ends the process as a denied call.
///
/// # Safety
/// Same contract as `madvise(2)`.
pub unsafe fn madvise(addr: *mut c_void, len: size_t, advice: c_int) -> c_int {
    if wick_mm::advice_denied(advice) {
        return -1;
    }
    let thp = advice == MADV_HUGEPAGE || advice == MADV_NOHUGEPAGE;
    let free = advice == libc::MADV_FREE;
    if advice != libc::MADV_DONTNEED && !free && !thp {
        // SAFETY: forwarded unchanged.
        return unsafe { libc::madvise(addr, len, advice) };
    }
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let rounded = len.checked_next_multiple_of(page);
    let Some(len) = rounded.filter(|&l| (addr as usize).is_multiple_of(page) && (addr as usize).checked_add(l).is_some())
    else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if len == 0 {
        return 0;
    }
    if thp {
        return thp_advice(addr as u64, addr as u64 + len as u64);
    }
    // Pages registered with a userfaultfd become missing (and a remove event
    // is queued), as on Linux.
    crate::wick_uffd::discarding_or_refusing(addr as u64, len as u64, |done, refused| {
        // SAFETY: the caller's contract.
        unsafe { dontneed(addr, len, free, done, refused) }
    })
}

/// `MADV_HUGEPAGE` or `MADV_NOHUGEPAGE` over the page aligned `[start, end)`:
/// nothing to change on this host (see [`madvise`]); unmapped pages in the
/// range give `ENOMEM`, as Linux's madvise_walk_vmas does.
fn thp_advice(start: u64, end: u64) -> c_int {
    let mut pos = start;
    while pos < end {
        match vm_entry(pos) {
            Some((entry_start, entry_end, _, _)) if entry_start <= pos => pos = entry_end,
            _ => {
                set_errno(libc::ENOMEM);
                return -1;
            }
        }
    }
    0
}

/// The `MADV_DONTNEED`, or with `free` the `MADV_FREE`, of [`madvise`] over a
/// page aligned range; the pieces discarded are added to `done`, and the
/// piece a `MADV_FREE` refuses after its remove event is `refused`.
unsafe fn dontneed(
    addr: *mut c_void,
    len: size_t,
    free: bool,
    done: &mut std::vec::Vec<(u64, u64)>,
    refused: &mut Option<(u64, u64)>,
) -> c_int {
    let (start, end) = (addr as u64, addr as u64 + len as u64);
    // The mapped pieces, and whether there are unmapped pages between them.
    let mut entries = std::vec::Vec::new();
    let mut unmapped = false;
    let mut pos = start;
    while pos < end {
        let Some((entry_start, entry_end, backing, prot)) = vm_entry(pos).filter(|&(s, _, _, _)| s < end)
        else {
            unmapped = true;
            break;
        };
        if entry_start > pos {
            unmapped = true;
            pos = entry_start;
        }
        let piece_end = entry_end.min(end);
        let backing = if backing == Backing::File && copied(pos, piece_end) { Backing::FileCopied } else { backing };
        // A `MADV_FREE` refuses it in its turn, below.
        if backing == Backing::FileCopied && !free {
            set_errno(libc::EINVAL);
            return -1;
        }
        // Adjacent entries alike (a guest range split by earlier discards
        // or protections) are discarded as one piece.
        match entries.last_mut() {
            Some((_, e, b, p)) if *e == pos && *b == backing && *p == prot => *e = piece_end,
            _ => entries.push((pos, piece_end, backing, prot)),
        }
        pos = piece_end;
    }
    for (mut piece_start, piece_end, backing, prot) in entries {
        while piece_start < piece_end {
            let (seg_end, huge) = crate::wick_uffd::huge_segment(piece_start, piece_end);
            // Linux's `MADV_FREE` (see [`madvise`]): no huge pages, before
            // any remove event; then anonymous memory only, after it.
            if free && (huge || backing != Backing::Anonymous) {
                if !huge {
                    *refused = Some((piece_start, seg_end));
                }
                set_errno(libc::EINVAL);
                return -1;
            }
            let (from, to) = if huge {
                if !piece_start.is_multiple_of(HUGE_PAGE) {
                    set_errno(libc::EINVAL);
                    return -1;
                }
                (piece_start, seg_end - seg_end % HUGE_PAGE)
            } else {
                (piece_start, seg_end)
            };
            if from < to {
                // SAFETY: a mapped range of the caller's.
                let ret = unsafe { discard_piece(from as *mut c_void, (to - from) as size_t, backing, prot) };
                if ret != 0 {
                    return ret;
                }
                done.push((from, to));
            }
            piece_start = seg_end;
        }
    }
    if unmapped {
        set_errno(libc::ENOMEM);
        return -1;
    }
    0
}

/// Discards one mapped piece of one backing and protection.
///
/// # Safety
/// `[ptr, ptr + len)` must be mapped memory of the caller's.
unsafe fn discard_piece(ptr: *mut c_void, len: size_t, backing: Backing, prot: c_int) -> c_int {
    match backing {
        // SAFETY: the caller's contract.
        Backing::Shared | Backing::File => unsafe { libc::madvise(ptr, len, libc::MADV_DONTNEED) },
        Backing::Anonymous => {
            // Fresh zero pages, released from the guest meanwhile. Kept
            // `MAP_NORESERVE`, as Firecracker's guest memory is made
            // (`discard_range` keeps it for the same reason).
            // SAFETY: over a mapped range of the caller's, with its
            // protection; the pages replaced are private, so nothing else
            // held them.
            let new = unsafe {
                mmap_replacing(
                    false,
                    ptr,
                    len,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            if new == libc::MAP_FAILED { -1 } else { 0 }
        }
        Backing::FileCopied => unreachable!("refused before any piece is discarded"),
    }
}

// ---- socket options ----

/// `SO_DOMAIN` (Linux value): the socket's address family. macOS has no such
/// option; [`getsockopt`] answers it from the socket's address.
pub const SO_DOMAIN: c_int = 39;

/// `getsockopt` with the Linux-only `SO_DOMAIN` (from `getsockname`'s
/// family); other options are passed through.
///
/// # Safety
/// Same contract as `getsockopt(2)`.
pub unsafe fn getsockopt(
    socket: c_int,
    level: c_int,
    name: c_int,
    value: *mut c_void,
    len: *mut libc::socklen_t,
) -> c_int {
    if level != libc::SOL_SOCKET || name != SO_DOMAIN {
        // SAFETY: forwarded unchanged.
        return unsafe { libc::getsockopt(socket, level, name, value, len) };
    }
    // SAFETY: the caller's contract for `len`.
    if value.is_null() || len.is_null() || unsafe { *len } < core::mem::size_of::<c_int>() as u32 {
        set_errno(libc::EINVAL);
        return -1;
    }
    // SAFETY: a zeroed sockaddr_storage is a valid output buffer.
    let mut addr: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
    let mut addr_len = core::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: valid output buffers; errors (EBADF, ENOTSOCK) are the caller's.
    if unsafe {
        libc::getsockname(
            socket,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut addr_len,
        )
    } != 0
    {
        return -1;
    }
    // SAFETY: checked above that `value` holds a c_int.
    unsafe {
        *value.cast::<c_int>() = c_int::from(addr.ss_family);
        *len = core::mem::size_of::<c_int>() as u32;
    }
    0
}

// ---- block device ioctls (only issued on block special files) ----

/// `DKIOCGETBLOCKSIZE` (`_IOR('d', 24, uint32_t)`): logical block size.
pub const BLKSSZGET: c_ulong = 0x4004_6418;
/// `DKIOCGETPHYSICALBLOCKSIZE` (`_IOR('d', 77, uint32_t)`): physical block size.
pub const BLKPBSZGET: c_ulong = 0x4004_644d;
/// Minimum I/O size. macOS reports no separate value; like Linux without a
/// hint, it is the physical block size (`DKIOCGETPHYSICALBLOCKSIZE`).
pub const BLKIOMIN: c_ulong = BLKPBSZGET;
/// Optimal I/O size. macOS reports no separate value; the physical block size
/// (`DKIOCGETPHYSICALBLOCKSIZE`) is used.
pub const BLKIOOPT: c_ulong = BLKPBSZGET;

/// Request type of `ioctl`.
pub type Ioctl = c_ulong;

// ---- packet sockets (used by Linux TAP test helpers) ----

/// Packet socket family; not available on macOS.
pub const AF_PACKET: c_int = -1;
/// All Ethernet protocols.
pub const ETH_P_ALL: c_int = 0x0003;
/// Ethernet address length.
pub const ETH_ALEN: c_int = 6;

/// Linux `struct sockaddr_ll`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct sockaddr_ll {
    /// Address family (`AF_PACKET`). `sa_family_t` is `u8` on macOS.
    pub sll_family: sa_family_t,
    /// Physical-layer protocol.
    pub sll_protocol: c_ushort,
    /// Interface number.
    pub sll_ifindex: c_int,
    /// ARP hardware type.
    pub sll_hatype: c_ushort,
    /// Packet type.
    pub sll_pkttype: c_uchar,
    /// Length of the address.
    pub sll_halen: c_uchar,
    /// Physical-layer address.
    pub sll_addr: [c_uchar; 8],
}

// ---- seccomp / prctl ----

/// First of the Linux-only syscall numbers; [`syscall`] fails with `ENOSYS` from here on.
const LINUX_ONLY_SYSCALLS: c_int = 0x7fff_ff00;
/// Linux `seccomp` syscall: [`syscall`] fails with `ENOSYS`.
pub const SYS_seccomp: c_int = LINUX_ONLY_SYSCALLS;
/// `seccomp` operation.
pub const SECCOMP_SET_MODE_FILTER: c_int = 1;
/// `prctl` option.
pub const PR_SET_NO_NEW_PRIVS: c_int = 38;
/// `prctl` option.
pub const PR_GET_SECCOMP: c_int = 21;

const PR_GET_SPECULATION_CTRL: c_int = 52;
const PR_SET_SPECULATION_CTRL: c_int = 53;
const PR_SPEC_STORE_BYPASS: c_ulong = 0;
const PR_SPEC_PRCTL: c_int = 1 << 0;
const PR_SPEC_ENABLE: c_ulong = 1 << 1;
const PR_SPEC_DISABLE: c_ulong = 1 << 2;
const PR_SPEC_FORCE_DISABLE: c_ulong = 1 << 3;

unsafe extern "C" {
    /// `prctl` for macOS. Supported options:
    /// - `PR_GET_SECCOMP`: 0 (macOS has no seccomp);
    /// - `PR_SET_SPECULATION_CTRL`/`PR_GET_SPECULATION_CTRL` with
    ///   `PR_SPEC_STORE_BYPASS` on CPUs with `FEAT_SSBS` (see [`ssbd`]).
    ///
    /// Other options fail with `EINVAL`, as unknown options do on Linux.
    #[link_name = "wick_compat_prctl"]
    pub fn prctl(option: c_int, ...) -> c_int;
}

// Apple's arm64 ABI passes variadic arguments on the stack, so the variadic
// entry point loads them into registers and jumps to the Rust implementation.
// Reading four slots is harmless when the caller passed fewer: they lie in the
// caller's frame and are ignored by the options that do not use them.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl _wick_compat_prctl",
    ".p2align 2",
    "_wick_compat_prctl:",
    "ldr x1, [sp]",
    "ldr x2, [sp, #8]",
    "ldr x3, [sp, #16]",
    "ldr x4, [sp, #24]",
    "b _wick_compat_prctl_impl",
);

/// x86_64 passes variadic arguments like fixed ones.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "C" fn wick_compat_prctl(
    option: c_int,
    a2: c_ulong,
    a3: c_ulong,
    a4: c_ulong,
    a5: c_ulong,
) -> c_int {
    wick_compat_prctl_impl(option, a2, a3, a4, a5)
}

#[unsafe(no_mangle)]
extern "C" fn wick_compat_prctl_impl(
    option: c_int,
    a2: c_ulong,
    a3: c_ulong,
    _a4: c_ulong,
    _a5: c_ulong,
) -> c_int {
    let ret = match option {
        PR_GET_SECCOMP => Ok(0),
        PR_SET_SPECULATION_CTRL if a2 == PR_SPEC_STORE_BYPASS => ssbd::set(a3),
        PR_GET_SPECULATION_CTRL if a2 == PR_SPEC_STORE_BYPASS => ssbd::get(),
        PR_SET_SPECULATION_CTRL | PR_GET_SPECULATION_CTRL => Err(libc::ENODEV),
        _ => Err(libc::EINVAL),
    };
    match ret {
        Ok(v) => v,
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

/// Speculative store bypass control with `PSTATE.SSBS` (`FEAT_SSBS`).
///
/// Linux applies the setting to the calling task and the tasks it creates
/// later. Here it applies to the calling thread and to every thread started
/// afterwards (a `pthread` introspection hook clears `SSBS` when a thread
/// starts). Firecracker sets it from the main thread before starting others,
/// so the result is the same.
pub mod ssbd {
    use super::*;

    const MODE_DEFAULT: u8 = 0;
    static MODE: AtomicU8 = AtomicU8::new(MODE_DEFAULT);

    /// Whether the CPU has `FEAT_SSBS`, as macOS reports it
    /// (`hw.optional.arm.FEAT_SSBS`: 1 on an M1 Pro with macOS 27.2, where
    /// `test_ssbd` sets and reads `PSTATE.SSBS`; not on the virtual machines
    /// of hosted CI runners).
    pub(super) fn supported() -> bool {
        let mut v: c_int = 0;
        let mut len = core::mem::size_of::<c_int>();
        // SAFETY: valid output buffer and length.
        let ret = unsafe {
            libc::sysctlbyname(
                c"hw.optional.arm.FEAT_SSBS".as_ptr(),
                (&mut v as *mut c_int).cast(),
                &mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        ret == 0 && v == 1
    }

    #[cfg(target_arch = "aarch64")]
    fn write_ssbs(bypass_allowed: bool) {
        let v: u64 = if bypass_allowed { 1 << 12 } else { 0 };
        // SAFETY: SSBS (s3_3_c4_c2_6) is writable from EL0 when FEAT_SSBS is present.
        unsafe { core::arch::asm!("msr s3_3_c4_c2_6, {}", in(reg) v) };
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn write_ssbs(_bypass_allowed: bool) {}

    /// Reads `PSTATE.SSBS` of the calling thread (true: bypass allowed).
    #[cfg(target_arch = "aarch64")]
    pub fn bypass_allowed() -> bool {
        let v: u64;
        // SAFETY: reading SSBS has no side effects.
        unsafe { core::arch::asm!("mrs {}, s3_3_c4_c2_6", out(reg) v) };
        v & (1 << 12) != 0
    }

    type Hook = Option<unsafe extern "C" fn(u32, libc::pthread_t, *mut c_void, size_t)>;
    const PTHREAD_INTROSPECTION_THREAD_START: u32 = 2;
    static mut PREVIOUS_HOOK: Hook = None;

    unsafe extern "C" {
        fn pthread_introspection_hook_install(hook: Hook) -> Hook;
    }

    unsafe extern "C" fn on_thread_event(
        event: u32,
        thread: libc::pthread_t,
        addr: *mut c_void,
        size: size_t,
    ) {
        if event == PTHREAD_INTROSPECTION_THREAD_START
            && MODE.load(Ordering::Acquire) != MODE_DEFAULT
        {
            // Runs on the new thread before its start routine.
            write_ssbs(false);
        }
        // SAFETY: written once, before the hook is installed.
        if let Some(prev) = unsafe { PREVIOUS_HOOK } {
            // SAFETY: chaining to the hook that was installed before ours.
            unsafe { prev(event, thread, addr, size) };
        }
    }

    fn install_hook() {
        static INSTALLED: AtomicU8 = AtomicU8::new(0);
        if INSTALLED.swap(1, Ordering::AcqRel) == 0 {
            // SAFETY: the hook is an `extern "C"` function with the documented signature;
            // PREVIOUS_HOOK is written before any thread can run our hook.
            unsafe { PREVIOUS_HOOK = pthread_introspection_hook_install(Some(on_thread_event)) };
        }
    }

    pub(super) fn set(ctrl: c_ulong) -> Result<c_int, c_int> {
        if !supported() {
            return Err(libc::ENXIO);
        }
        let mode = MODE.load(Ordering::Acquire);
        match ctrl {
            PR_SPEC_ENABLE => {
                if mode == PR_SPEC_FORCE_DISABLE as u8 {
                    return Err(libc::EPERM);
                }
                MODE.store(MODE_DEFAULT, Ordering::Release);
                write_ssbs(true);
            }
            PR_SPEC_DISABLE | PR_SPEC_FORCE_DISABLE => {
                if mode != PR_SPEC_FORCE_DISABLE as u8 {
                    MODE.store(ctrl as u8, Ordering::Release);
                }
                install_hook();
                write_ssbs(false);
            }
            _ => return Err(libc::ERANGE),
        }
        Ok(0)
    }

    pub(super) fn get() -> Result<c_int, c_int> {
        if !supported() {
            return Ok(0);
        }
        Ok(match MODE.load(Ordering::Acquire) {
            MODE_DEFAULT => PR_SPEC_PRCTL | PR_SPEC_ENABLE as c_int,
            m => PR_SPEC_PRCTL | c_int::from(m),
        })
    }
}

// ---- io_uring (the async block engine is not available on macOS) ----

/// Linux `io_uring_setup` syscall: [`syscall`] fails with `ENOSYS`.
pub const SYS_io_uring_setup: c_int = LINUX_ONLY_SYSCALLS + 1;
/// Linux `io_uring_enter` syscall: [`syscall`] fails with `ENOSYS`.
pub const SYS_io_uring_enter: c_int = LINUX_ONLY_SYSCALLS + 2;
/// Linux `io_uring_register` syscall: [`syscall`] fails with `ENOSYS`.
pub const SYS_io_uring_register: c_int = LINUX_ONLY_SYSCALLS + 3;

unsafe extern "C" {
    /// `syscall(2)`: the Linux-only numbers above fail with `ENOSYS`; other
    /// numbers go to the macOS `syscall`.
    #[link_name = "wick_compat_syscall"]
    pub fn syscall(num: c_int, ...) -> c_int;
}

// The entry point checks the number and tail-calls the macOS `syscall`, so the
// variadic arguments stay where the caller put them.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".globl _wick_compat_syscall",
    ".p2align 2",
    "_wick_compat_syscall:",
    "mov w16, #0xff00",
    "movk w16, #0x7fff, lsl #16",
    "cmp w0, w16",
    "b.ge 1f",
    "b _syscall",
    "1:",
    "b _wick_compat_syscall_enosys",
);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl _wick_compat_syscall",
    "_wick_compat_syscall:",
    "cmp edi, 0x7fffff00",
    "jge 1f",
    "jmp _syscall",
    "1:",
    "jmp _wick_compat_syscall_enosys",
);

#[unsafe(no_mangle)]
extern "C" fn wick_compat_syscall_enosys() -> c_int {
    set_errno(libc::ENOSYS);
    -1
}

// ---- functions with different signatures or missing on macOS ----

/// `mincore` with the Linux signature (`*mut c_uchar`; macOS uses `*mut c_char`)
/// and Linux's answer: one byte per page, its lowest bit set when the page
/// holds data of the mapping.
///
/// macOS compresses (and swaps) a mapping's idle pages whenever memory is
/// short, and cannot be told not to; its mincore then reports such a page
/// paged out, not in core. Firecracker builds a diff snapshot without dirty
/// tracking from mincore (`mincore_bitmap`), on Linux hosts without swap
/// where a written page stays in core: a paged-out page left out of it is
/// guest memory lost on restore (a restored guest's virtio ring read as
/// garbage, measured under memory pressure in `test_vmclock.py`). A page
/// macOS holds paged out has data, and reading it pages it in: it counts
/// as resident here.
///
/// # Safety
/// Same contract as `mincore(2)`.
pub unsafe fn mincore(addr: *mut c_void, len: size_t, vec: *mut c_uchar) -> c_int {
    // SAFETY: forwarded; only the pointer type differs.
    let r = unsafe { libc::mincore(addr, len, vec.cast()) };
    if r == 0 {
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as usize;
        let n = len.div_ceil(page);
        // SAFETY: mincore(2) filled one byte per page of the range in `vec`,
        // which the caller sized for it.
        let bytes = unsafe { std::slice::from_raw_parts_mut(vec, n) };
        for b in bytes {
            *b = linux_residency(*b);
        }
    }
    r
}

/// macOS's `MINCORE_PAGED_OUT` (<sys/mman.h>; not in the libc crate): the
/// compressor or swap holds the page.
const MINCORE_PAGED_OUT: c_uchar = 0x20;

/// Linux's mincore byte for macOS's: resident (1) when the page is in core
/// or paged out (compressed or swapped), absent (0) otherwise.
fn linux_residency(macos: c_uchar) -> c_uchar {
    c_uchar::from(macos & (libc::MINCORE_INCORE as c_uchar | MINCORE_PAGED_OUT) != 0)
}

/// `FALLOC_FL_KEEP_SIZE` (Linux value).
const FALLOC_FL_KEEP_SIZE: c_int = 0x01;
/// `FALLOC_FL_PUNCH_HOLE` (Linux value).
const FALLOC_FL_PUNCH_HOLE: c_int = 0x02;
/// `FALLOC_FL_ZERO_RANGE` (Linux value).
const FALLOC_FL_ZERO_RANGE: c_int = 0x10;

/// macOS `struct fpunchhole` for `F_PUNCHHOLE`.
#[repr(C)]
struct FPunchHole {
    fp_flags: u32,
    reserved: u32,
    fp_offset: off_t,
    fp_length: off_t,
}

/// macOS `fstore_t` for `F_PREALLOCATE`.
#[repr(C)]
struct FStore {
    fst_flags: u32,
    fst_posmode: c_int,
    fst_offset: off_t,
    fst_length: off_t,
    fst_bytesalloc: off_t,
}

const F_PUNCHHOLE: c_int = 99;
const F_PREALLOCATE: c_int = 42;
const F_ALLOCATEALL: u32 = 4;
const F_PEOFPOSMODE: c_int = 3;

fn fstat_size(fd: c_int) -> Result<off_t, ()> {
    // SAFETY: `stat` is plain data written by fstat.
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: a valid output buffer; errno is set on failure.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(());
    }
    Ok(st.st_size)
}

/// Writes zeros over `[start, end)`, which lies within the file.
fn write_zeros(fd: c_int, mut start: off_t, end: off_t) -> Result<(), ()> {
    static ZEROS: [u8; 65536] = [0; 65536];
    while start < end {
        let n = usize::try_from(end - start)
            .unwrap_or(usize::MAX)
            .min(ZEROS.len());
        // SAFETY: reads `n` bytes from a static buffer.
        let ret = unsafe { libc::pwrite(fd, ZEROS.as_ptr().cast(), n, start) };
        if ret < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(());
        }
        start += ret as off_t;
    }
    Ok(())
}

/// `FALLOC_FL_PUNCH_HOLE`: the range reads back as zeros and whole file
/// system blocks in it are freed; the size never changes. `F_PUNCHHOLE` only
/// takes block-aligned ranges, so partial blocks at either edge are zeroed by
/// writing, as Linux does.
fn punch_hole(fd: c_int, offset: off_t, end: off_t) -> Result<(), ()> {
    let end = end.min(fstat_size(fd)?);
    if offset >= end {
        return Ok(());
    }
    // SAFETY: `statfs` is plain data written by fstatfs.
    let mut fs: libc::statfs = unsafe { core::mem::zeroed() };
    // SAFETY: a valid output buffer; errno is set on failure.
    if unsafe { libc::fstatfs(fd, &mut fs) } != 0 {
        return Err(());
    }
    let bs = off_t::from(fs.f_bsize.max(1));
    let first = (offset + bs - 1) / bs * bs;
    let last = end / bs * bs;
    if first >= last {
        return write_zeros(fd, offset, end);
    }
    let arg = FPunchHole {
        fp_flags: 0,
        reserved: 0,
        fp_offset: first,
        fp_length: last - first,
    };
    // SAFETY: a valid descriptor and argument struct.
    if unsafe { libc::fcntl(fd, F_PUNCHHOLE, &arg as *const FPunchHole) } != 0 {
        return Err(());
    }
    write_zeros(fd, offset, first)?;
    write_zeros(fd, last, end)
}

/// Mode `0` / `FALLOC_FL_KEEP_SIZE`: after the call every block of the range
/// is allocated. Holes inside the file are filled with zeros (data is left
/// alone); past the end of the file the space is reserved with
/// `F_PREALLOCATE`, and the size grows to the end of the range unless
/// `keep_size`.
fn allocate(fd: c_int, offset: off_t, end: off_t, keep_size: bool) -> Result<(), ()> {
    let size = fstat_size(fd)?;
    // Fill the holes of [offset, min(end, size)).
    let mut pos = offset;
    let inside = end.min(size);
    while pos < inside {
        // SAFETY: lseek on a valid descriptor; it moves the file offset, which
        // is restored below.
        let saved = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, pos, libc::SEEK_HOLE) };
        // SAFETY: as above.
        let data = if hole >= 0 && hole < inside {
            unsafe { libc::lseek(fd, hole, libc::SEEK_DATA) }
        } else {
            -1
        };
        let data_errno = errno();
        if saved >= 0 {
            // SAFETY: as above.
            unsafe { libc::lseek(fd, saved, libc::SEEK_SET) };
        }
        if hole < 0 {
            return Err(());
        }
        if hole >= inside {
            break;
        }
        // No data after the hole (ENXIO): the hole runs to the end of the file.
        let hole_end = if data >= 0 {
            data.min(inside)
        } else if data_errno == libc::ENXIO {
            inside
        } else {
            set_errno(data_errno);
            return Err(());
        };
        write_zeros(fd, hole, hole_end)?;
        pos = hole_end;
    }
    if end > size {
        let mut store = FStore {
            fst_flags: F_ALLOCATEALL,
            fst_posmode: F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: end - size,
            fst_bytesalloc: 0,
        };
        // SAFETY: a valid descriptor and argument struct.
        if unsafe { libc::fcntl(fd, F_PREALLOCATE, &mut store as *mut FStore) } != 0 {
            return Err(());
        }
        // SAFETY: a valid descriptor.
        if !keep_size && unsafe { libc::ftruncate(fd, end) } != 0 {
            return Err(());
        }
    }
    Ok(())
}

/// `fallocate` for macOS, with the Linux semantics of:
/// - `0` and `FALLOC_FL_KEEP_SIZE`: allocate the range;
/// - `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`: deallocate it (discard);
/// - `FALLOC_FL_ZERO_RANGE` (optionally with `KEEP_SIZE`): make it read as
///   zeros and allocated.
///
/// `FALLOC_FL_COLLAPSE_RANGE` and `FALLOC_FL_INSERT_RANGE` move file data,
/// which no macOS file system call does; they fail with `EOPNOTSUPP`, as on a
/// Linux file system without them.
///
/// # Safety
/// Same contract as `fallocate(2)`.
pub unsafe fn fallocate(fd: c_int, mode: c_int, offset: off_t, len: off_t) -> c_int {
    if offset < 0 || len <= 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    let Some(end) = offset.checked_add(len) else {
        set_errno(libc::EFBIG);
        return -1;
    };
    let keep_size = mode & FALLOC_FL_KEEP_SIZE != 0;
    let result = match mode & !FALLOC_FL_KEEP_SIZE {
        0 => allocate(fd, offset, end, keep_size),
        // Linux requires KEEP_SIZE with PUNCH_HOLE.
        FALLOC_FL_PUNCH_HOLE if keep_size => punch_hole(fd, offset, end),
        FALLOC_FL_PUNCH_HOLE => {
            set_errno(libc::EOPNOTSUPP);
            Err(())
        }
        FALLOC_FL_ZERO_RANGE => {
            punch_hole(fd, offset, end).and_then(|()| allocate(fd, offset, end, keep_size))
        }
        _ => {
            set_errno(libc::EOPNOTSUPP);
            Err(())
        }
    };
    match result {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

/// `off64_t`: macOS's `off_t` is already 64 bits.
pub type off64_t = off_t;

/// `sendfile64` for macOS, with the Linux semantics for any pair of
/// descriptors (macOS's own `sendfile` only sends files to sockets): copies up
/// to `count` bytes from `in_fd` to `out_fd` at its current position.
/// - with `offset`, reads from `*offset`, advances `*offset` and leaves the
///   position of `in_fd` alone;
/// - without, reads from the position of `in_fd` and advances it.
///
/// Returns the number of bytes copied (0 at the end of `in_fd`), at most
/// `0x7fff_f000` per call as on Linux.
///
/// # Safety
/// Same contract as `sendfile(2)`: `offset` is null or valid for reads and
/// writes.
pub unsafe fn sendfile64(out_fd: c_int, in_fd: c_int, offset: *mut off64_t, count: size_t) -> isize {
    const MAX_PER_CALL: usize = 0x7fff_f000;
    const CHUNK: usize = 1 << 20;
    let count = count.min(MAX_PER_CALL);
    if !offset.is_null() && unsafe { *offset } < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut buf = std::vec![0u8; count.min(CHUNK)];
    let mut done = 0usize;
    while done < count {
        let want = (count - done).min(buf.len());
        // SAFETY: `buf` has room for `want` bytes; `offset` per the contract.
        let n = unsafe {
            if offset.is_null() {
                libc::read(in_fd, buf.as_mut_ptr().cast(), want)
            } else {
                libc::pread(in_fd, buf.as_mut_ptr().cast(), want, *offset)
            }
        };
        if n < 0 {
            if done > 0 {
                break;
            }
            return -1;
        }
        if n == 0 {
            break;
        }
        let n = n.unsigned_abs();
        let mut written = 0usize;
        while written < n {
            // SAFETY: writes bytes read into `buf` above.
            let w = unsafe { libc::write(out_fd, buf[written..n].as_ptr().cast(), n - written) };
            if w < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    continue;
                }
                // Bytes read but not written are given back to the input.
                let unread = (n - written) as off_t;
                // SAFETY: `offset` per the contract; otherwise seeks `in_fd` back.
                unsafe {
                    if offset.is_null() {
                        libc::lseek(in_fd, -unread, libc::SEEK_CUR);
                    } else {
                        *offset += written as off_t;
                    }
                }
                done += written;
                if done > 0 {
                    return isize::try_from(done).unwrap_or(isize::MAX);
                }
                set_errno(errno);
                return -1;
            }
            written += w.unsigned_abs();
        }
        if !offset.is_null() {
            // SAFETY: `offset` per the contract.
            unsafe { *offset += n as off_t };
        }
        done += n;
        if n < want {
            break;
        }
    }
    isize::try_from(done).unwrap_or(isize::MAX)
}

/// `memfd_create` for macOS: an unlinked temporary file, so the descriptor
/// supports `read`, `write`, `ftruncate` and `mmap` like a memfd.
///
/// `flags` may hold `MFD_CLOEXEC` and `MFD_ALLOW_SEALING`; macOS has no
/// `F_ADD_SEALS`, so sealing such a descriptor fails when it is attempted.
/// Other flags (`MFD_HUGETLB` and its sizes, `MFD_NOEXEC_SEAL`, ...) ask for
/// what macOS cannot give and fail with `EINVAL`.
///
/// A private mapping of it, as of any file, keeps its own writes from the
/// file, as on Linux, but is a copy of the file made at `mmap`: a page the
/// file changes later reads as it was, whether the mapping had read it or
/// not. Linux maps the file's own page until the mapping writes it (v6.12
/// mm/memory.c `do_fault`: a read takes `do_read_fault` :5431, a write
/// `do_cow_fault` :5433), so there the change shows. macOS maps a file
/// without `MAP_SHARED` with copy (xnu-12377.1.9 bsd/kern/kern_mman.c :880
/// to :882, `vm_map_enter_mem_object_control` :928): the mapping keeps the
/// file's contents as they were at `mmap`
/// (`test_a_private_file_mapping_is_a_copy_made_at_mmap`). Firecracker maps a
/// snapshot's memory file so (`snapshot_file`), and its users must not
/// change that file while the VM runs (docs/snapshotting/snapshot-support.md:
/// it "must be considered immutable", a change "leads to undefined
/// behavior").
///
/// # Safety
/// `name` must be a valid C string (it is not used).
pub unsafe fn memfd_create(_name: *const core::ffi::c_char, flags: core::ffi::c_uint) -> c_int {
    const MFD_CLOEXEC: core::ffi::c_uint = 1;
    const MFD_ALLOW_SEALING: core::ffi::c_uint = 2;
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING) != 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    let dir = std::env::temp_dir();
    let mut template =
        std::vec::Vec::from(dir.join("wick-memfd-XXXXXX").as_os_str().as_encoded_bytes());
    template.push(0);
    // SAFETY: `template` is a writable NUL-terminated buffer ending in XXXXXX.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if fd < 0 {
        return -1;
    }
    // SAFETY: the path was just created by mkstemp; the descriptor keeps the file alive.
    unsafe { libc::unlink(template.as_ptr().cast()) };
    if flags & MFD_CLOEXEC != 0 {
        // SAFETY: valid descriptor.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    fd
}

fn errno() -> c_int {
    // SAFETY: __error() returns the calling thread's errno location.
    unsafe { *libc::__error() }
}

pub(crate) fn set_errno(err: c_int) {
    // SAFETY: __error() returns the calling thread's errno location.
    unsafe { *libc::__error() = err };
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::{format, vec};

    use super::*;

    #[test]
    fn test_sendfile64() {
        let dir = std::env::temp_dir();
        let src_path = dir.join(format!("wick-sendfile-src-{}", std::process::id()));
        let dst_path = dir.join(format!("wick-sendfile-dst-{}", std::process::id()));
        let mut src = std::fs::File::options().create(true).truncate(true).read(true).write(true).open(&src_path).unwrap();
        let mut dst = std::fs::File::options().create(true).truncate(true).read(true).write(true).open(&dst_path).unwrap();
        src.write_all(b"0123456789").unwrap();
        src.seek(SeekFrom::Start(1)).unwrap();
        dst.write_all(b"ab").unwrap();
        let mut off: off64_t = 4;
        // SAFETY: valid descriptors and offset.
        let n = unsafe { sendfile64(dst.as_raw_fd(), src.as_raw_fd(), &mut off, 3) };
        assert_eq!((n, off), (3, 7));
        assert_eq!(src.stream_position().unwrap(), 1, "input position untouched");
        // Without an offset: from the input position, which advances.
        // SAFETY: as above.
        let n = unsafe { sendfile64(dst.as_raw_fd(), src.as_raw_fd(), core::ptr::null_mut(), 2) };
        assert_eq!(n, 2);
        assert_eq!(src.stream_position().unwrap(), 3);
        // At the end.
        let mut off: off64_t = 10;
        // SAFETY: as above.
        assert_eq!(unsafe { sendfile64(dst.as_raw_fd(), src.as_raw_fd(), &mut off, 5) }, 0);
        let mut out = std::string::String::new();
        dst.seek(SeekFrom::Start(0)).unwrap();
        dst.read_to_string(&mut out).unwrap();
        assert_eq!(out, "ab45612");
        std::fs::remove_file(src_path).unwrap();
        std::fs::remove_file(dst_path).unwrap();
    }

    #[test]
    fn test_so_domain() {
        let domain = |family: c_int| {
            // SAFETY: creates a socket owned by this test.
            let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
            assert!(fd >= 0);
            let (mut v, mut len) = (0 as c_int, 4 as libc::socklen_t);
            // SAFETY: valid output buffers.
            let r = unsafe {
                getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    SO_DOMAIN,
                    (&mut v as *mut c_int).cast(),
                    &mut len,
                )
            };
            // SAFETY: closes the socket.
            unsafe { libc::close(fd) };
            assert_eq!((r, len), (0, 4));
            v
        };
        assert_eq!(domain(libc::AF_UNIX), libc::AF_UNIX);
        assert_eq!(domain(libc::AF_INET), libc::AF_INET);
        // Not a socket.
        let (mut v, mut len) = (0 as c_int, 4 as libc::socklen_t);
        // SAFETY: as above.
        let r = unsafe {
            getsockopt(
                0x7fff,
                libc::SOL_SOCKET,
                SO_DOMAIN,
                (&mut v as *mut c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(r, -1);
    }

    #[test]
    fn test_prctl() {
        // SAFETY: plain calls; prctl does not touch memory for these options.
        unsafe {
            assert_eq!(prctl(PR_GET_SECCOMP), 0);
            assert_eq!(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
    }

    /// The variable that tells a test it runs in a process of its own.
    const ALONE: &str = "WICK_LINUX_ITEMS_TEST_ALONE";

    /// Runs test `name` again in a process of its own (this binary, that
    /// test only) and checks that it passed there; true in that process,
    /// which goes on with the test.
    fn alone(name: &str) -> bool {
        if std::env::var_os(ALONE).is_some() {
            return true;
        }
        let child = {
            let _spawning = crate::timerfd::spawning();
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([name, "--exact", "--test-threads=1", "--nocapture"])
                .env(ALONE, "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        };
        let out = child.wait_with_output().unwrap();
        let text = std::format!(
            "{:?}\n{}{}",
            out.status,
            std::string::String::from_utf8_lossy(&out.stdout),
            std::string::String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success() && text.contains("1 passed"), "{name} in a process of its own: {text}");
        false
    }

    #[test]
    fn test_ssbd() {
        if !ssbd::supported() {
            // As Linux on a CPU without the control: ENXIO, and GET reports
            // no control (PR_SPEC_NOT_AFFECTED).
            // SAFETY: as above.
            unsafe {
                assert_eq!(
                    prctl(
                        PR_SET_SPECULATION_CTRL,
                        PR_SPEC_STORE_BYPASS,
                        PR_SPEC_FORCE_DISABLE,
                        0,
                        0
                    ),
                    -1
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ENXIO)
                );
                assert_eq!(
                    prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0),
                    0
                );
            }
            return;
        }
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                prctl(
                    PR_SET_SPECULATION_CTRL,
                    PR_SPEC_STORE_BYPASS,
                    PR_SPEC_FORCE_DISABLE,
                    0,
                    0
                ),
                0,
                "{}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0),
                PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE as c_int
            );
            // Forced: cannot be enabled again.
            assert_eq!(
                prctl(
                    PR_SET_SPECULATION_CTRL,
                    PR_SPEC_STORE_BYPASS,
                    PR_SPEC_ENABLE,
                    0,
                    0
                ),
                -1
            );
        }
        assert!(!ssbd::bypass_allowed());
        // Threads started afterwards have the mitigation too.
        assert!(!std::thread::spawn(ssbd::bypass_allowed).join().unwrap());
        // And a process forked afterwards (Firecracker's API process), as a
        // child task inherits it on Linux: in its first thread and in one
        // it starts. The fork is made in a process of its own, this test
        // only: a thread the fork does not copy can hold a lock the child's
        // new thread needs (std's stack overflow guard's list of threads,
        // locked by every thread start in `set_current_info`), and the child
        // then waits for good. Measured: among the crate's other tests the
        // child waited in `_pthread_mutex_firstfit_lock_wait` under
        // `set_current_info` for 9 minutes, until it was killed.
        if !alone("linux_items::tests::test_ssbd") {
            return;
        }
        // SAFETY: the child reads a register, starts one thread and exits.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                let here = ssbd::bypass_allowed();
                let there = std::thread::spawn(ssbd::bypass_allowed).join().unwrap_or(true);
                libc::_exit(c_int::from(here) | c_int::from(there) << 1);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "{status:#x}");
        }
    }

    #[test]
    fn test_linux_syscalls_fail_with_enosys() {
        for num in [
            SYS_seccomp,
            SYS_io_uring_setup,
            SYS_io_uring_enter,
            SYS_io_uring_register,
        ] {
            // SAFETY: the number is refused before reaching the kernel.
            assert_eq!(unsafe { syscall(num, 0, 0, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOSYS)
            );
        }
        // Real macOS syscalls still work: getpid is 20.
        // SAFETY: getpid has no arguments or side effects.
        assert_eq!(unsafe { syscall(20) }, std::process::id() as c_int);
    }

    /// The host has no superpages for user space (docs/PORTING.md row 10):
    /// what [`mmap_huge`] is built on.
    #[test]
    fn test_no_host_superpages() {
        unsafe extern "C" {
            fn mach_vm_allocate(task: u32, addr: *mut u64, size: u64, flags: c_int) -> c_int;
            fn mach_vm_deallocate(task: u32, addr: u64, size: u64) -> c_int;
        }
        const VM_FLAGS_ANYWHERE: c_int = 1;
        // VM_FLAGS_SUPERPAGE_SHIFT 16: SUPERPAGE_SIZE_ANY 1, SUPERPAGE_SIZE_2MB 2.
        const SUPERPAGE_ANY: c_int = 1 << 16;
        const SUPERPAGE_2MB: c_int = 2 << 16;
        const KERN_INVALID_ARGUMENT: c_int = 4;
        for flag in [SUPERPAGE_ANY, SUPERPAGE_2MB] {
            for size in [HUGE_PAGE, 32 * HUGE_PAGE] {
                let mut addr = 0u64;
                // SAFETY: an allocation of our own, released if it is made.
                let kr = unsafe { mach_vm_allocate(mach_task_self_, &mut addr, size, VM_FLAGS_ANYWHERE | flag) };
                if kr == 0 {
                    // SAFETY: the allocation made above.
                    unsafe { mach_vm_deallocate(mach_task_self_, addr, size) };
                }
                assert_eq!(kr, KERN_INVALID_ARGUMENT, "mach_vm_allocate {size:#x} with superpage flag {flag:#x}");
                // SAFETY: an anonymous mapping, unmapped if it is made.
                let p = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        size as usize,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANON,
                        flag,
                        0,
                    )
                };
                let errno = std::io::Error::last_os_error().raw_os_error();
                if p != libc::MAP_FAILED {
                    // SAFETY: the mapping made above.
                    unsafe { libc::munmap(p, size as usize) };
                }
                assert_eq!(p, libc::MAP_FAILED, "mmap {size:#x} with superpage flag {flag:#x}");
                assert_eq!(errno, Some(libc::EINVAL));
            }
        }
    }

    /// A huge page memfd (the compatibility `memfd` crate's, named for it)
    /// maps huge with or without MAP_HUGETLB, at huge page offsets only and
    /// only when its size is whole huge pages; MAP_HUGETLB with another
    /// file is EINVAL (docs/PORTING.md row 10).
    #[test]
    fn test_hugetlb_files() {
        let _alone = crate::wick_uffd::huge_mapping_test();
        use std::os::fd::AsRawFd;
        let shm = |name: &str, size: off_t| {
            let cname = std::ffi::CString::new(name).unwrap();
            // SAFETY: a NUL-terminated name; the object is unlinked at once.
            let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600 as libc::c_uint) };
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            // SAFETY: as above; sizes the object.
            unsafe {
                libc::shm_unlink(cname.as_ptr());
                assert_eq!(libc::ftruncate(fd, size), 0, "{}", std::io::Error::last_os_error());
            }
            fd
        };
        let pid = std::process::id();
        let huge_fd = shm(&format!("{}{pid}.t1", crate::HUGE_MEMFD_PREFIX), 2 * HUGE_PAGE as off_t);
        let odd_fd = shm(&format!("{}{pid}.t2", crate::HUGE_MEMFD_PREFIX), HUGE_PAGE as off_t + 16384);
        let plain_fd = shm(&format!("/fcm.{pid}.t3"), 2 * HUGE_PAGE as off_t);
        assert_eq!([huge_fd, odd_fd, plain_fd].map(shm_object), [Some(true), Some(true), Some(false)]);
        let path = std::env::temp_dir().join(format!("wick-hugetlb-file-{pid}"));
        let tmp = std::fs::File::create(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        tmp.set_len(2 * HUGE_PAGE).unwrap();
        assert_eq!(shm_object(tmp.as_raw_fd()), None);
        // SAFETY: mappings of the objects above, unmapped below.
        unsafe {
            for flags in [libc::MAP_SHARED, libc::MAP_SHARED | MAP_HUGETLB | MAP_HUGE_2MB] {
                let p = mmap(core::ptr::null_mut(), HUGE_PAGE as usize, libc::PROT_READ | libc::PROT_WRITE, flags, huge_fd, HUGE_PAGE as off_t);
                assert_ne!(p, libc::MAP_FAILED, "{}", std::io::Error::last_os_error());
                assert_eq!(p as u64 % HUGE_PAGE, 0);
                assert_eq!(crate::wick_uffd::huge_page_of(p as u64, p as u64 + HUGE_PAGE), Some(HUGE_PAGE));
                p.cast::<u8>().write_volatile(9);
                assert_eq!(munmap(p, HUGE_PAGE as usize), 0);
            }
            let errs = |p: *mut c_void| {
                assert_eq!(p, libc::MAP_FAILED);
                std::io::Error::last_os_error().raw_os_error()
            };
            let off = mmap(core::ptr::null_mut(), 16384, libc::PROT_READ, libc::MAP_SHARED, huge_fd, 16384);
            assert_eq!(errs(off), Some(libc::EINVAL), "an offset off a huge page");
            let odd = mmap(core::ptr::null_mut(), 16384, libc::PROT_READ, libc::MAP_SHARED, odd_fd, 0);
            assert_eq!(errs(odd), Some(libc::EINVAL), "a size that is not whole huge pages");
            let flagged = mmap(core::ptr::null_mut(), HUGE_PAGE as usize, libc::PROT_READ, libc::MAP_SHARED | MAP_HUGETLB, plain_fd, 0);
            assert_eq!(errs(flagged), Some(libc::EINVAL), "MAP_HUGETLB with another file");
            let flagged = mmap(core::ptr::null_mut(), 16384, libc::PROT_READ, libc::MAP_SHARED | MAP_HUGETLB, tmp.as_raw_fd(), 0);
            assert_eq!(errs(flagged), Some(libc::EINVAL), "MAP_HUGETLB with a plain file");
            let ok = mmap(core::ptr::null_mut(), 16384, libc::PROT_READ, libc::MAP_SHARED, plain_fd, 0);
            assert_ne!(ok, libc::MAP_FAILED);
            assert_eq!(crate::wick_uffd::huge_page_of(ok as u64, ok as u64 + 16384), None);
            assert_eq!(munmap(ok, 16384), 0);
            for fd in [huge_fd, odd_fd, plain_fd] {
                libc::close(fd);
            }
        }
    }

    #[test]
    fn test_mmap_flags() {
        let _alone = crate::wick_uffd::huge_mapping_test();
        // SAFETY: anonymous mappings, unmapped below.
        unsafe {
            // A huge page mapping: 2 MiB aligned, whole huge pages (the 1
            // byte over rounds up to a second one), and usable.
            let huge = mmap(
                core::ptr::null_mut(),
                (1 << 21) + 1,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGETLB | MAP_HUGE_2MB,
                -1,
                0,
            );
            assert_ne!(huge, libc::MAP_FAILED, "{}", std::io::Error::last_os_error());
            assert_eq!(huge as u64 % HUGE_PAGE, 0, "{huge:p}");
            let last = huge.cast::<u8>().add((2 << 21) - 1);
            last.write_volatile(7);
            assert_eq!(last.read_volatile(), 7);
            assert_eq!(crate::wick_uffd::huge_page_of(huge as u64, huge as u64 + (2 << 21)), Some(HUGE_PAGE));
            assert_eq!(crate::wick_uffd::huge_page_of(huge as u64, huge as u64 + (2 << 21) + 1), None);
            // Over the second huge page, fixed, as Firecracker maps guest
            // memory over its reservation: still a huge page there.
            let second = huge.cast::<u8>().add(1 << 21).cast::<c_void>();
            let fixed = mmap(
                second,
                1 << 21,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED | MAP_HUGETLB | MAP_HUGE_2MB,
                -1,
                0,
            );
            assert_eq!(fixed, second);
            assert_eq!(crate::wick_uffd::huge_page_of(huge as u64, huge as u64 + (2 << 21)), Some(HUGE_PAGE));
            // A fixed address that is not a huge page boundary: EINVAL.
            let off = huge.cast::<u8>().add(16384).cast::<c_void>();
            let bad = mmap(
                off,
                1 << 21,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED | MAP_HUGETLB,
                -1,
                0,
            );
            assert_eq!(bad, libc::MAP_FAILED);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
            // A size the host has no pool for: ENOMEM, as Linux.
            let gib = mmap(
                core::ptr::null_mut(),
                1 << 30,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGETLB | MAP_HUGE_1GB,
                -1,
                0,
            );
            assert_eq!(gib, libc::MAP_FAILED);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOMEM));
            // The size bits without MAP_HUGETLB mean nothing: an ordinary mapping.
            let bits = mmap(core::ptr::null_mut(), 16384, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGE_2MB, -1, 0);
            assert_ne!(bits, libc::MAP_FAILED);
            assert_eq!(crate::wick_uffd::huge_page_of(bits as u64, bits as u64 + 16384), None);
            assert_eq!(munmap(bits, 16384), 0);
            // A length that cannot be rounded up: ENOMEM.
            let vast = mmap(core::ptr::null_mut(), usize::MAX - 5, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGETLB, -1, 0);
            assert_eq!(vast, libc::MAP_FAILED);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOMEM));
            // Mapped over without the flag: no longer huge.
            let plain = mmap(
                huge,
                1 << 21,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            );
            assert_eq!(plain, huge);
            assert_eq!(crate::wick_uffd::huge_page_of(huge as u64, huge as u64 + (1 << 21)), None);
            assert_eq!(crate::wick_uffd::huge_page_of(second as u64, second as u64 + (1 << 21)), Some(HUGE_PAGE));
            // munmap of a huge mapping off a huge page boundary: EINVAL; whole: taken down and forgotten.
            assert_eq!(munmap(second.cast::<u8>().add(16384).cast(), 16384), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
            assert_eq!(munmap(second, (1 << 21) - 16384), -1);
            assert_eq!(munmap(huge, 2 << 21), 0);
            assert_eq!(crate::wick_uffd::huge_page_of(second as u64, second as u64 + (1 << 21)), None);
            let p = mmap(
                core::ptr::null_mut(),
                1 << 20,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_POPULATE,
                -1,
                0,
            );
            assert_ne!(p, libc::MAP_FAILED);
            libc::munmap(p, 1 << 20);
        }
    }

    #[test]
    fn test_transparent_huge_page_advice() {
        // The advice is taken and the memory stays on small pages, as on a
        // Linux host whose transparent huge pages are `never` (on Windows it
        // also sets what a first write commits, windows_mm's
        // `test_madv_hugepage_is_what_a_first_access_commits`); the range is
        // checked as Linux checks it.
        const LEN: usize = 1 << 20;
        // SAFETY: a fresh mapping, unmapped below.
        let p = unsafe {
            libc::mmap(core::ptr::null_mut(), LEN, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0)
        };
        assert_ne!(p, libc::MAP_FAILED);
        let errno = || std::io::Error::last_os_error().raw_os_error();
        for advice in [MADV_HUGEPAGE, MADV_NOHUGEPAGE] {
            // SAFETY: our mapping.
            assert_eq!(unsafe { madvise(p, LEN, advice) }, 0, "{advice}: {:?}", errno());
            // SAFETY: a start off a page: refused before anything.
            assert_eq!(unsafe { madvise(p.cast::<u8>().wrapping_add(1).cast(), 1, advice) }, -1);
            assert_eq!(errno(), Some(libc::EINVAL));
            // SAFETY: nothing is mapped there.
            assert_eq!(unsafe { madvise(0xffff_0000_0000_0000_usize as *mut c_void, LEN, advice) }, -1);
            assert_eq!(errno(), Some(libc::ENOMEM));
        }
        // The memory is still ordinary, writable memory.
        // SAFETY: inside the mapping.
        unsafe { p.cast::<u8>().write_volatile(7) };
        // SAFETY: unmapping our own mapping.
        unsafe { libc::munmap(p, LEN) };
    }

    /// `MADV_DONTNEED` of a private file mapping: Linux drops its private
    /// (copied) pages, which then read as the file's contents again
    /// (mm/memory.c `zap_page_range_single`); macOS has no call that does, so
    /// a piece holding a copied page is `EINVAL` with nothing changed, a
    /// piece with none is discarded and still reads as the file. A copied
    /// page is seen whether some pages of the mapping or all of them were
    /// copied: once all were, macOS reports the entry with no file pager and
    /// no shadow, as it does anonymous memory (measured), so the file is
    /// found through the entry's vnode.
    #[test]
    fn test_madvise_dontneed_of_a_private_file_mapping_with_copied_pages_is_einval() {
        const LEN: usize = 1 << 20;
        const RW: c_int = libc::PROT_READ | libc::PROT_WRITE;
        let file = std::fs::File::from(memfd_file());
        file.set_len(LEN as u64).unwrap();
        let errno = || std::io::Error::last_os_error().raw_os_error();
        // SAFETY: a fresh mapping of the file, written, then unmapped.
        unsafe {
            let shared =
                libc::mmap(core::ptr::null_mut(), LEN, RW, libc::MAP_SHARED, file.as_raw_fd(), 0);
            assert_ne!(shared, libc::MAP_FAILED);
            core::ptr::write_bytes(shared.cast::<u8>(), 0x11, LEN);
            libc::munmap(shared, LEN);
        }
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        for copied in [0, 1, LEN / page] {
            // SAFETY: a fresh private mapping of the file.
            let p = unsafe {
                libc::mmap(core::ptr::null_mut(), LEN, RW, libc::MAP_PRIVATE, file.as_raw_fd(), 0)
            };
            assert_ne!(p, libc::MAP_FAILED);
            // SAFETY: inside the mapping.
            unsafe { core::ptr::write_bytes(p.cast::<u8>(), 0x22, copied * page) };
            // SAFETY: the whole mapping.
            let r = unsafe { madvise(p, LEN, libc::MADV_DONTNEED) };
            // SAFETY: inside the mapping.
            let (first, last) = unsafe { (*p.cast::<u8>(), *p.cast::<u8>().add(LEN - 1)) };
            if copied == 0 {
                assert_eq!((r, first, last), (0, 0x11, 0x11), "none copied");
            } else {
                assert_eq!((r, errno()), (-1, Some(libc::EINVAL)), "{copied} pages copied");
                let kept = if copied == 1 { 0x11 } else { 0x22 };
                assert_eq!((first, last), (0x22, kept), "{copied} pages copied: changed");
            }
            // SAFETY: unmapping our own mapping.
            unsafe { libc::munmap(p, LEN) };
        }
    }

    /// `MADV_DONTNEED` of private anonymous memory a copy-on-write copy has
    /// been made of (its entry then has a shadow) reads as zeros, as any
    /// private anonymous memory: no file is under it, though a file mapping
    /// follows it, which `proc_regionfilename` names for it.
    #[test]
    fn test_madvise_dontneed_of_anonymous_memory_with_a_copy_reads_zeros() {
        unsafe extern "C" {
            fn mach_vm_remap(
                target: libc::mach_port_t,
                address: *mut u64,
                size: u64,
                mask: u64,
                flags: c_int,
                source: libc::mach_port_t,
                source_address: u64,
                copy: c_int,
                cur: *mut c_int,
                max: *mut c_int,
                inheritance: u32,
            ) -> c_int;
        }
        const LEN: usize = 1 << 20;
        const VM_FLAGS_ANYWHERE: c_int = 1;
        const RW: c_int = libc::PROT_READ | libc::PROT_WRITE;
        let file = std::fs::File::from(memfd_file());
        file.set_len(LEN as u64).unwrap();
        // Anonymous memory, a reservation, then a private file mapping.
        // SAFETY: a fresh reservation, then mappings inside it.
        let (base, p) = unsafe {
            let anon = libc::MAP_PRIVATE | libc::MAP_ANON;
            let base = libc::mmap(core::ptr::null_mut(), 3 * LEN, libc::PROT_NONE, anon, -1, 0);
            assert_ne!(base, libc::MAP_FAILED);
            let p = libc::mmap(base, LEN, RW, anon | libc::MAP_FIXED, -1, 0);
            let at = base.cast::<u8>().add(2 * LEN).cast();
            let f = libc::mmap(at, LEN, RW, libc::MAP_PRIVATE | libc::MAP_FIXED, file.as_raw_fd(), 0);
            assert_eq!((p, f), (base, at));
            (base, p)
        };
        let mut path = [0u8; 1024];
        // SAFETY: valid buffer; the call writes at most `path.len()` bytes.
        let named = unsafe { libc::proc_regionfilename(libc::getpid(), p as u64, path.as_mut_ptr().cast(), 1024) };
        assert!(named > 0, "no file named for the anonymous memory: the test would not tell");
        // SAFETY: inside the mapping.
        unsafe { core::ptr::write_bytes(p.cast::<u8>(), 0x33, LEN) };
        let (mut copy, mut cur, mut max) = (0u64, 0, 0);
        // SAFETY: a copy-on-write copy of our mapping, anywhere.
        let kr = unsafe {
            let task = mach_task_self_;
            mach_vm_remap(task, &mut copy, LEN as u64, 0, VM_FLAGS_ANYWHERE, task, p as u64, 1, &mut cur, &mut max, 1)
        };
        assert_eq!(kr, 0);
        // SAFETY: inside the mapping; the write gives it a shadow.
        unsafe { *p.cast::<u8>() = 0x44 };
        // SAFETY: the whole mapping.
        assert_eq!(unsafe { madvise(p, LEN, libc::MADV_DONTNEED) }, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: inside the mapping and the copy.
        assert_eq!(unsafe { (*p.cast::<u8>(), *(copy as *const u8)) }, (0, 0x33));
        // SAFETY: unmapping our own mappings.
        unsafe {
            libc::munmap(base, 3 * LEN);
            libc::munmap(copy as *mut c_void, LEN);
        }
    }

    /// `MADV_FREE` as Linux takes it (v6.12 mm/madvise.c): private anonymous
    /// memory is freed, here at once, so it reads as zeros, one of the two
    /// outcomes Linux allows (`madvise_free_single_vma` frees lazily); shared
    /// memory and a file mapping are `EINVAL` (:797, not anonymous) and keep
    /// their contents; the range is checked as for any advice.
    #[test]
    fn test_madv_free_frees_private_anonymous_memory_only() {
        const LEN: usize = 1 << 20;
        let file = std::fs::File::from(memfd_file());
        file.set_len(LEN as u64).unwrap();
        let errno = || std::io::Error::last_os_error().raw_os_error();
        for (flags, fd, freed) in [
            (libc::MAP_PRIVATE | libc::MAP_ANON, -1, true),
            (libc::MAP_SHARED | libc::MAP_ANON, -1, false),
            (libc::MAP_SHARED, file.as_raw_fd(), false),
            (libc::MAP_PRIVATE, file.as_raw_fd(), false),
        ] {
            // SAFETY: a fresh mapping.
            let p = unsafe { libc::mmap(core::ptr::null_mut(), LEN, libc::PROT_READ | libc::PROT_WRITE, flags, fd, 0) };
            assert_ne!(p, libc::MAP_FAILED);
            // SAFETY: inside the mapping.
            unsafe { core::ptr::write_bytes(p.cast::<u8>(), 0x5a, LEN) };
            // SAFETY: the whole mapping.
            let r = unsafe { madvise(p, LEN, libc::MADV_FREE) };
            let expected = if freed { (0, 0) } else { (-1, 0x5a) };
            // SAFETY: inside the mapping.
            let byte = unsafe { *p.cast::<u8>().add(LEN - 1) };
            assert_eq!((r, byte), expected, "flags {flags:#x}");
            if !freed {
                assert_eq!(errno(), Some(libc::EINVAL), "flags {flags:#x}");
            }
            // SAFETY: refused before anything is changed.
            assert_eq!(unsafe { madvise(p.cast::<u8>().add(1).cast(), 1, libc::MADV_FREE) }, -1);
            assert_eq!(errno(), Some(libc::EINVAL));
            // SAFETY: unmapping our own mapping.
            unsafe { libc::munmap(p, LEN) };
        }
    }

    #[test]
    fn test_madvise_dontneed() {
        const LEN: usize = 1 << 20;
        let map = |flags: c_int, fd: c_int| {
            // SAFETY: a fresh mapping.
            let p = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    LEN,
                    libc::PROT_READ | libc::PROT_WRITE,
                    flags,
                    fd,
                    0,
                )
            };
            assert_ne!(p, libc::MAP_FAILED);
            // SAFETY: inside the mapping.
            unsafe { core::ptr::write_bytes(p.cast::<u8>(), 0x5a, LEN) };
            p
        };
        let read = |p: *mut c_void, off: usize| {
            // SAFETY: inside the mapping.
            unsafe { *p.cast::<u8>().add(off) }
        };

        // Private anonymous memory reads as zeros afterwards, and its pages
        // are released (not resident), the rest still there.
        let anon = map(libc::MAP_PRIVATE | libc::MAP_ANON, -1);
        // SAFETY: half of the mapping.
        assert_eq!(unsafe { madvise(anon, LEN / 2, libc::MADV_DONTNEED) }, 0);
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mut resident = std::vec![0u8; LEN / page];
        // SAFETY: one byte per page of the mapping.
        assert_eq!(unsafe { mincore(anon, LEN, resident.as_mut_ptr()) }, 0);
        assert!(resident[..LEN / 2 / page].iter().all(|r| r & 1 == 0), "discarded pages resident: {resident:?}");
        assert!(resident[LEN / 2 / page..].iter().all(|r| r & 1 == 1), "kept pages not resident: {resident:?}");
        assert_eq!(read(anon, 0), 0);
        assert_eq!(read(anon, LEN / 2 - 1), 0);
        assert_eq!(read(anon, LEN / 2), 0x5a);

        // Shared memory keeps its contents.
        let file = std::fs::File::from(memfd_file());
        file.set_len(LEN as u64).unwrap();
        let shared = map(libc::MAP_SHARED, file.as_raw_fd());
        // SAFETY: the whole mapping.
        assert_eq!(unsafe { madvise(shared, LEN, libc::MADV_DONTNEED) }, 0);
        assert_eq!(read(shared, 0), 0x5a);

        // SAFETY: unmapping our own mapping.
        unsafe { libc::munmap(shared, LEN) };

        // The range as Linux takes it (mm/madvise.c check_input_range): a
        // start off a page, or a length that wraps when rounded up to pages
        // (from `anon` to the end of the address space), is EINVAL and
        // nothing changes; a length of 0 does nothing.
        let errno = || std::io::Error::last_os_error().raw_os_error();
        let off_page = anon.cast::<u8>().wrapping_add(1).cast::<c_void>();
        for (addr, len) in [(off_page, 1), (anon, usize::MAX - anon as usize)] {
            // SAFETY: refused before anything is changed.
            assert_eq!(unsafe { madvise(addr, len, libc::MADV_DONTNEED) }, -1);
            assert_eq!(errno(), Some(libc::EINVAL));
        }
        // SAFETY: an empty range.
        assert_eq!(unsafe { madvise(anon, 0, libc::MADV_DONTNEED) }, 0);
        assert_eq!(read(anon, LEN / 2), 0x5a);
        // SAFETY: unmapping our own mapping.
        unsafe { libc::munmap(anon, LEN) };

        // Unmapped pages: ENOMEM. Not a range just unmapped, which another
        // test's thread may map again, but ranges past the end of the
        // address space, where nothing can be mapped: one wholly past it,
        // and one from a mapping just below it, whose mapped part is
        // discarded before ENOMEM is returned (madvise_walk_vmas).
        const TOP: usize = 0x7fff_fe00_0000; // MACH_VM_MAX_ADDRESS (arm64)
        let past_the_end = 0xffff_0000_0000_0000_usize as *mut c_void;
        // SAFETY: nothing is mapped there.
        assert_eq!(unsafe { madvise(past_the_end, LEN, libc::MADV_DONTNEED) }, -1);
        assert_eq!(errno(), Some(libc::ENOMEM));
        // SAFETY: a fresh mapping at the top of the address space if free.
        let top = unsafe {
            libc::mmap(
                (TOP - LEN) as *mut c_void,
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_eq!(top as usize, TOP - LEN, "the top of the address space is taken");
        // SAFETY: inside the mapping.
        unsafe { core::ptr::write_bytes(top.cast::<u8>(), 0x5a, LEN) };
        // SAFETY: our mapping, then unmappable addresses.
        assert_eq!(unsafe { madvise(top, 2 * LEN, libc::MADV_DONTNEED) }, -1);
        assert_eq!(errno(), Some(libc::ENOMEM));
        assert_eq!(read(top, 0), 0);
        assert_eq!(read(top, LEN - 1), 0);
        // SAFETY: unmapping our own mapping.
        unsafe { libc::munmap(top, LEN) };
    }

    /// A replacement of the pages of a range (a `MADV_DONTNEED` of private
    /// anonymous memory, a `MAP_FIXED` mapping) is reported to the
    /// hypervisor backend's hooks before and after, with the range, as a new
    /// mapping or not; other mappings are not. Every mapping, `MAP_FIXED` or
    /// not, `munmap` and `mprotect` is reported to the protection hook after
    /// it returned, and a discard, which changes no vma on Linux, is not.
    /// Recording guest hooks ([`crate::wick_guest::set_hooks`]), set by the
    /// tests that read them, always the same functions. The hooks are the
    /// process's: other tests' calls come here too, some of them earlier at
    /// the addresses a test's mapping now has, so each call is kept with the
    /// thread that made it, and read back by [`hook_calls`].
    mod hooks {
        use std::sync::Mutex;
        use std::thread::ThreadId;
        /// A replace hook's call: the thread, the range, before, anew.
        type Replaced = (ThreadId, u64, u64, bool, bool);
        /// A protection hook's call: the thread, the range, replaced.
        type Protected = (ThreadId, u64, u64, bool);
        pub(super) static REPLACED: Mutex<std::vec::Vec<Replaced>> = Mutex::new(std::vec::Vec::new());
        pub(super) static PROTECTED: Mutex<std::vec::Vec<Protected>> = Mutex::new(std::vec::Vec::new());
        fn stage2(_: u64, _: u64, _: bool) {}
        fn replace(start: u64, len: u64, before: bool, anew: bool) -> bool {
            REPLACED.lock().unwrap().push((std::thread::current().id(), start, len, before, anew));
            true
        }
        fn protected(start: u64, len: u64, replaced: bool) {
            PROTECTED.lock().unwrap().push((std::thread::current().id(), start, len, replaced));
        }
        pub(super) fn record() {
            crate::wick_guest::set_hooks(crate::wick_guest::Hooks { stage2, replace, protected });
            assert!(crate::wick_guest::hooked());
        }
    }

    /// This thread's calls of the recording hooks ([`hooks`]) for ranges that
    /// start in `[start, end)`: the replace hook's (start, len, before,
    /// anew), and the protection hook's (start, len, replaced).
    #[allow(clippy::type_complexity)]
    fn hook_calls(start: u64, end: u64) -> (std::vec::Vec<(u64, u64, bool, bool)>, std::vec::Vec<(u64, u64, bool)>) {
        let me = std::thread::current().id();
        let replaced = hooks::REPLACED
            .lock()
            .unwrap()
            .iter()
            .filter(|&&(t, s, _, _, _)| t == me && s >= start && s < end)
            .map(|&(_, s, l, b, n)| (s, l, b, n))
            .collect();
        let protected = hooks::PROTECTED
            .lock()
            .unwrap()
            .iter()
            .filter(|&&(t, s, _, _)| t == me && s >= start && s < end)
            .map(|&(_, s, l, r)| (s, l, r))
            .collect();
        (replaced, protected)
    }

    #[test]
    fn test_replaced_pages_are_reported_to_the_guest_hooks() {
        hooks::record();
        const LEN: usize = 1 << 20;
        // SAFETY: a fresh mapping; not fixed, so not a replacement.
        let p = unsafe {
            mmap(
                core::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        let (start, half) = (p as u64, (LEN / 2) as u64);
        let calls = || hook_calls(start, start + LEN as u64).0;
        let protected = || hook_calls(start, start + LEN as u64).1;
        assert!(calls().is_empty());
        assert_eq!(protected(), [(start, LEN as u64, true)], "the new mapping");
        // SAFETY: inside the mapping.
        unsafe { core::ptr::write_bytes(p.cast::<u8>(), 0x5a, LEN) };
        // SAFETY: half of the mapping.
        assert_eq!(unsafe { madvise(p, LEN / 2, libc::MADV_DONTNEED) }, 0);
        assert_eq!(calls(), [(start, half, true, false), (start, half, false, false)]);
        assert_eq!(protected().len(), 1, "a discard");
        // SAFETY: over the other half.
        let q = unsafe {
            mmap(
                p.cast::<u8>().add(LEN / 2).cast(),
                LEN / 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(q as u64, start + half);
        assert_eq!(
            calls(),
            [
                (start, half, true, false),
                (start, half, false, false),
                (start + half, half, true, true),
                (start + half, half, false, true)
            ]
        );
        assert_eq!(protected(), [(start, LEN as u64, true), (start + half, half, false)], "MAP_FIXED");
        // SAFETY: the mapping, now all zeros.
        assert_eq!(unsafe { *p.cast::<u8>().add(LEN - 1) }, 0);
        // SAFETY: half of our own mapping.
        assert_eq!(unsafe { mprotect(p, LEN / 2, libc::PROT_READ) }, 0);
        // SAFETY: unmapping our own mapping.
        assert_eq!(unsafe { munmap(p, LEN) }, 0);
        assert_eq!(
            protected(),
            [(start, LEN as u64, true), (start + half, half, false), (start, half, false), (start, LEN as u64, true)],
            "mprotect, then munmap"
        );
    }

    fn memfd_file() -> std::os::fd::OwnedFd {
        // SAFETY: a valid name; the descriptor is owned by the result.
        let fd = unsafe { memfd_create(c"t".as_ptr(), 0) };
        assert!(fd >= 0);
        // SAFETY: a fresh descriptor.
        unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) }
    }

    /// A private mapping of a POSIX shared memory object (a memfd of the
    /// compatibility `memfd` crate, plain or huge page) is `EINVAL` before
    /// anything is changed ([`mmap`]): nothing is mapped, and a `MAP_FIXED`
    /// one leaves the range's contents, its userfaultfd registration and the
    /// guest's view of it (no hook is called) as they were. The object's
    /// shared mapping is made as before.
    #[test]
    fn test_a_private_mapping_of_a_shared_memory_object_is_refused() {
        hooks::record();
        let shm = |name: &str| {
            let cname = std::ffi::CString::new(name).unwrap();
            // SAFETY: a NUL-terminated name; the object is unlinked at once.
            let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600 as libc::c_uint) };
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            // SAFETY: as above; sizes the object.
            unsafe {
                libc::shm_unlink(cname.as_ptr());
                assert_eq!(libc::ftruncate(fd, 2 * HUGE_PAGE as off_t), 0, "{}", std::io::Error::last_os_error());
            }
            fd
        };
        let pid = std::process::id();
        let plain = shm(&format!("/fcm.{pid}.p1"));
        let huge = shm(&format!("{}{pid}.p2", crate::HUGE_MEMFD_PREFIX));
        const LEN: usize = 1 << 20;
        const RW: c_int = libc::PROT_READ | libc::PROT_WRITE;
        let errno = || std::io::Error::last_os_error().raw_os_error();
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        // Private anonymous memory: its first half written, its second
        // registered with a userfaultfd (missing).
        // SAFETY: a fresh mapping.
        let p = unsafe { mmap(core::ptr::null_mut(), LEN, RW, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        let (start, end) = (p as u64, p as u64 + LEN as u64);
        // SAFETY: the first half of the mapping.
        unsafe { core::ptr::write_bytes(p.cast::<u8>(), 0x5a, LEN / 2) };
        let (ctx, user) = crate::wick_uffd::create(0, false, true).unwrap();
        crate::wick_uffd::register(ctx, start + LEN as u64 / 2, LEN as u64 / 2).unwrap();
        let before = hook_calls(start, end);
        for (what, fd) in [("plain", plain), ("huge page", huge)] {
            for flags in [libc::MAP_PRIVATE, libc::MAP_PRIVATE | libc::MAP_FIXED] {
                let at = if flags & libc::MAP_FIXED != 0 { p } else { core::ptr::null_mut() };
                // SAFETY: refused; were it not, a mapping over our own.
                let r = unsafe { mmap(at, LEN, RW, flags, fd, 0) };
                assert_eq!((r, errno()), (libc::MAP_FAILED, Some(libc::EINVAL)), "{what}, flags {flags:#x}");
            }
        }
        assert_eq!(hook_calls(start, end), before, "a guest hook was called");
        // SAFETY: inside the mapping.
        let kept = unsafe { (*p.cast::<u8>(), *p.cast::<u8>().add(LEN / 2 - 1)) };
        assert_eq!(kept, (0x5a, 0x5a), "the written half");
        let missing = [start + LEN as u64 / 2, end - page].map(crate::wick_uffd::is_missing);
        assert_eq!(missing, [true, true], "the registered half");
        // SAFETY: a fresh shared mapping of the object, unmapped below.
        let q = unsafe { mmap(core::ptr::null_mut(), page as usize, RW, libc::MAP_SHARED, plain, 0) };
        assert_ne!(q, libc::MAP_FAILED, "{:?}", errno());
        // SAFETY: our own mappings and descriptors.
        unsafe {
            assert_eq!(munmap(q, page as usize), 0);
            crate::wick_uffd::unregister(ctx, start + LEN as u64 / 2, LEN as u64 / 2).unwrap();
            assert_eq!(munmap(p, LEN), 0);
            for fd in [user, plain, huge] {
                libc::close(fd);
            }
        }
    }

    /// A private mapping of a file keeps its own writes from the file, as on
    /// Linux, and is a copy of the file made at `mmap` ([`memfd_create`]): a
    /// page the file changes later, by `pwrite` or through a shared mapping,
    /// reads as it was, whether the mapping had read it or not, where Linux
    /// reads the change until the mapping writes the page.
    #[test]
    fn test_a_private_file_mapping_is_a_copy_made_at_mmap() {
        use std::os::unix::fs::FileExt;
        const RW: c_int = libc::PROT_READ | libc::PROT_WRITE;
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = 4 * page;
        let file = std::fs::File::from(memfd_file());
        for how in ["pwrite", "a shared mapping"] {
            file.write_all_at(&vec![0x11; len], 0).unwrap();
            // SAFETY: fresh mappings of the file, unmapped below.
            let (shared, private) = unsafe {
                (
                    mmap(core::ptr::null_mut(), len, RW, libc::MAP_SHARED, file.as_raw_fd(), 0).cast::<u8>(),
                    mmap(core::ptr::null_mut(), len, RW, libc::MAP_PRIVATE, file.as_raw_fd(), 0).cast::<u8>(),
                )
            };
            assert!(shared != libc::MAP_FAILED.cast() && private != libc::MAP_FAILED.cast());
            let change = |at: usize, byte: u8| {
                if how == "pwrite" {
                    file.write_all_at(&[byte], at as u64).unwrap();
                } else {
                    // SAFETY: inside the shared mapping.
                    unsafe { shared.add(at).write_volatile(byte) };
                }
            };
            let in_file = |at: usize| {
                let mut b = [0u8];
                file.read_exact_at(&mut b, at as u64).unwrap();
                b[0]
            };
            // SAFETY: inside the private mapping.
            let read = |at: usize| unsafe { private.add(at).read_volatile() };
            // A page not accessed yet: Linux reads 0x22.
            change(0, 0x22);
            assert_eq!(read(0), 0x11, "{how}: a page changed in the file before any access");
            // A page read, then changed: Linux reads 0x33.
            assert_eq!(read(page), 0x11);
            change(page, 0x33);
            assert_eq!(read(page), 0x11, "{how}: a page read, then changed in the file");
            // A page written, then changed: each keeps its own, as on Linux.
            // SAFETY: inside the private mapping.
            unsafe { private.add(2 * page).write_volatile(0x55) };
            change(2 * page, 0x44);
            let written = (read(2 * page), in_file(2 * page), in_file(2 * page + 1));
            assert_eq!(written, (0x55, 0x44, 0x11), "{how}: a page written, then changed in the file");
            // The mapping's write never reaches the file, as on Linux.
            // SAFETY: inside the private mapping.
            unsafe { private.add(3 * page + 1).write_volatile(0x66) };
            assert_eq!(in_file(3 * page + 1), 0x11, "{how}: the mapping's write");
            // SAFETY: our own mappings.
            unsafe {
                assert_eq!(munmap(shared.cast(), len), 0);
                assert_eq!(munmap(private.cast(), len), 0);
            }
        }
    }

    #[test]
    fn test_mincore() {
        let page = 16384;
        let mut buf = vec![1u8; page * 2];
        let mut vec = [0u8; 2];
        let addr = (buf.as_mut_ptr() as usize & !(page - 1)) as *mut c_void;
        // SAFETY: the range is mapped (it is our heap buffer, page aligned down).
        assert_eq!(unsafe { mincore(addr, page, vec.as_mut_ptr()) }, 0);
        // The buffer was written: in core, Linux's 1 and nothing else.
        assert_eq!(vec[0], 1);
    }

    #[test]
    fn test_mincore_paged_out_is_resident() {
        // macOS's bytes for a page in core (referenced, modified, anonymous),
        // one the compressor holds, and one never touched.
        // <sys/mman.h>: MINCORE_ANONYMOUS.
        let anonymous = 0x80;
        let in_core = (libc::MINCORE_INCORE | libc::MINCORE_MODIFIED) as u8 | anonymous;
        let paged_out = MINCORE_PAGED_OUT | anonymous;
        assert_eq!(linux_residency(in_core), 1);
        assert_eq!(linux_residency(paged_out), 1);
        assert_eq!(linux_residency(0), 0);
        assert_eq!(linux_residency(anonymous), 0);
    }

    #[test]
    fn test_memfd_create() {
        use std::os::fd::FromRawFd;
        // SAFETY: valid C string.
        let fd = unsafe { memfd_create(c"t".as_ptr(), 1) };
        assert!(fd >= 0);
        // SAFETY: fresh descriptor we own.
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.write_all(b"abc").unwrap();
        f.rewind().unwrap();
        let mut s = std::string::String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "abc");
        // MFD_HUGETLB cannot be given.
        // SAFETY: valid C string.
        assert_eq!(unsafe { memfd_create(c"t".as_ptr(), 4) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn test_fallocate() {
        let path = std::env::temp_dir().join(format!("wick-compat-libc-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // Allocate extends the file.
        // SAFETY: valid descriptor.
        assert_eq!(unsafe { fallocate(file.as_raw_fd(), 0, 0, 1 << 20) }, 0);
        assert_eq!(file.metadata().unwrap().len(), 1 << 20);
        file.write_all(&vec![0xab; 1 << 20]).unwrap();
        // Punch a hole: the bytes read back as zero and the size stays.
        // SAFETY: valid descriptor.
        let rc = unsafe {
            fallocate(
                file.as_raw_fd(),
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                65536,
                65536,
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(file.metadata().unwrap().len(), 1 << 20);
        let mut back = vec![0u8; 65536];
        file.seek(SeekFrom::Start(65536)).unwrap();
        file.read_exact(&mut back).unwrap();
        assert!(back.iter().all(|b| *b == 0));
        // Unaligned punch: the edges are zeroed, the rest stays.
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&vec![0xab; 1 << 20]).unwrap();
        // SAFETY: valid descriptor.
        let rc = unsafe {
            fallocate(
                file.as_raw_fd(),
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                1000,
                10000,
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
        let mut back = vec![0u8; 12000];
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut back).unwrap();
        assert!(back[..1000].iter().all(|b| *b == 0xab));
        assert!(back[1000..11000].iter().all(|b| *b == 0));
        assert!(back[11000..].iter().all(|b| *b == 0xab));
        // A punch past the end does not grow the file.
        // SAFETY: valid descriptor.
        let rc = unsafe {
            fallocate(
                file.as_raw_fd(),
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                (1 << 20) - 10,
                100,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(file.metadata().unwrap().len(), 1 << 20);
        // Allocating over holes and data keeps the data and fills the holes.
        // SAFETY: valid descriptor.
        assert_eq!(unsafe { fallocate(file.as_raw_fd(), 0, 0, 1 << 20) }, 0);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut back).unwrap();
        assert!(back[..1000].iter().all(|b| *b == 0xab));
        assert!(back[1000..11000].iter().all(|b| *b == 0));
        // KEEP_SIZE reserves space past the end without growing the file.
        // SAFETY: valid descriptor.
        assert_eq!(
            unsafe { fallocate(file.as_raw_fd(), FALLOC_FL_KEEP_SIZE, 0, 2 << 20) },
            0
        );
        assert_eq!(file.metadata().unwrap().len(), 1 << 20);
        // ZERO_RANGE zeroes and grows.
        // SAFETY: valid descriptor.
        assert_eq!(
            unsafe { fallocate(file.as_raw_fd(), FALLOC_FL_ZERO_RANGE, 0, 3 << 20) },
            0
        );
        assert_eq!(file.metadata().unwrap().len(), 3 << 20);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut back).unwrap();
        assert!(back.iter().all(|b| *b == 0));
        // PUNCH_HOLE without KEEP_SIZE and data-moving modes are refused, as Linux does.
        // SAFETY: valid descriptor.
        assert_eq!(
            unsafe { fallocate(file.as_raw_fd(), FALLOC_FL_PUNCH_HOLE, 0, 1) },
            -1
        );
        // SAFETY: valid descriptor.
        assert_eq!(unsafe { fallocate(file.as_raw_fd(), 0x08, 0, 4096) }, -1);
        std::fs::remove_file(path).unwrap();
    }
}
