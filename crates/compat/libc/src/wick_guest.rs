// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the hypervisor backend is told about guest memory (a wick API, not
//! part of `libc`).
//!
//! Hypervisor.framework maps guest memory by the physical pages behind a host
//! range when `hv_vm_map` is called, not by the host address. When this libc
//! replaces the pages of a host range, as Linux does for a `MADV_DONTNEED` of
//! private anonymous memory (fresh zero pages) or for a `MAP_FIXED` mapping
//! over it, the guest would keep reading and writing the old pages while the
//! host and the devices use the new ones (measured with a standalone probe:
//! the host read 0 where the guest had written, and a restored guest read
//! wrong data from its drive after a balloon cycle;
//! `test_madvise_dontneed_replaces_guest_pages`, `boot-test balloon`). And
//! pages mapped in stage 2 are not released by `MADV_FREE_REUSABLE` (the
//! footprint stayed at 65.8 MiB for 64 MiB of pages), so a balloon freed
//! nothing.
//!
//! So the backend registers [`Hooks`]: `replace` is called before and after
//! such a change and unmaps the range from stage 2 for its duration, then
//! maps the new pages (a guest access in between stalls in the backend until
//! the new pages are mapped, as a KVM guest's does while the host zaps the
//! page); `stage2` is [`crate::wick_uffd`]'s: pages of a userfaultfd became
//! present or missing; `protected` is told, after each `mprotect`, `munmap`
//! and `mmap` of this libc returned, that a range's protection or mapping may
//! have changed, so that stage 2 follows the host's protection as KVM's
//! follows the vmas (a guest access the host refuses is `EFAULT`; the backend
//! reads the protection with [`crate::wick_uffd::host_protections`]). Only
//! this libc's calls are seen: one of the system's own library (std's, a
//! framework's) on guest memory is not. Without hooks (no VM in the process)
//! the changes are made as they are.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The hooks of the hypervisor backend.
#[derive(Clone, Copy)]
pub struct Hooks {
    /// `(host_addr, len, present)`: pages registered with a userfaultfd
    /// became present (they must be accessible to the guest, with the slot's
    /// permissions) or missing (they must fault in stage 2).
    pub stage2: fn(u64, u64, bool),
    /// `(host_addr, len, before, anew)`: the pages of the host range are
    /// about to be replaced (`before`), or have been; `anew` when a new
    /// mapping replaces them (`MAP_FIXED`), not a discard. Before: unmap what
    /// the range holds of guest memory from stage 2, and return whether
    /// there was any. After: map it again (a new mapping with its own
    /// protection), and return whether that succeeded; a failure leaves the
    /// guest without its memory, which the caller treats as fatal.
    pub replace: fn(u64, u64, bool, bool) -> bool,
    /// `(host_addr, len, replaced)`: the protection a Linux vma would give
    /// the pages of the host range may have changed, or the range was
    /// unmapped or mapped anew (an `mprotect`, `munmap` or `mmap` of this
    /// libc, after it returned). Stage 2 is to follow it: the backend reads
    /// the range's protection again ([`crate::wick_uffd::host_protections`]).
    /// `replaced`: the pages behind the range may not be the ones stage 2
    /// holds (an `munmap`, a new mapping), whatever the protection reads: a
    /// page unmapped and mapped again by another thread before this call
    /// reads as it did, so a protection cannot tell the new pages from the
    /// old. `mprotect` changes no page, and a `MAP_FIXED` mapping's pages
    /// were put in stage 2 by `replace`.
    pub protected: fn(u64, u64, bool),
}

static STAGE2: AtomicUsize = AtomicUsize::new(0);
static REPLACE: AtomicUsize = AtomicUsize::new(0);
static PROTECTED: AtomicUsize = AtomicUsize::new(0);

/// Sets the hooks of the hypervisor backend. Called once per VM creation
/// (Hypervisor.framework allows one VM per process); the hooks find the live
/// VM themselves.
pub fn set_hooks(hooks: Hooks) {
    STAGE2.store(hooks.stage2 as usize, Ordering::Release);
    REPLACE.store(hooks.replace as usize, Ordering::Release);
    PROTECTED.store(hooks.protected as usize, Ordering::Release);
}

/// Tells the backend that the protection of `[start, start + len)` may have
/// changed, and with `replaced` its pages too (see [`Hooks::protected`]).
/// Not from a signal handler: the hook takes locks.
pub(crate) fn protected(start: u64, len: u64, replaced: bool) {
    let hook = PROTECTED.load(Ordering::Acquire);
    if hook != 0 && len > 0 {
        // SAFETY: set by `set_hooks` from a `fn(u64, u64, bool)`.
        let f: fn(u64, u64, bool) = unsafe { core::mem::transmute(hook) };
        f(start, len, replaced);
    }
}

/// Whether hooks are set.
pub fn hooked() -> bool {
    REPLACE.load(Ordering::Acquire) != 0
}

/// Tells the backend that `[start, start + len)` became present or missing.
pub(crate) fn stage2(start: u64, len: u64, present: bool) {
    let hook = STAGE2.load(Ordering::Acquire);
    if hook != 0 && len > 0 {
        // SAFETY: set by `set_hooks` from a `fn(u64, u64, bool)`.
        let f: fn(u64, u64, bool) = unsafe { core::mem::transmute(hook) };
        f(start, len, present);
    }
}

fn replace(start: u64, len: u64, before: bool, anew: bool) -> bool {
    let hook = REPLACE.load(Ordering::Acquire);
    if hook == 0 || len == 0 {
        return false;
    }
    // SAFETY: set by `set_hooks` from a `fn(u64, u64, bool, bool) -> bool`.
    let f: fn(u64, u64, bool, bool) -> bool = unsafe { core::mem::transmute(hook) };
    f(start, len, before, anew)
}

/// Runs `change`, which replaces the pages of `[start, start + len)`, with
/// the range unmapped from the guest meanwhile and mapped again after.
///
/// The guest's memory cannot be mapped again only when the change left the
/// host range unmapped (a `MAP_FIXED` mapping that failed after releasing
/// the old one): the guest's memory is gone then, and the process aborts
/// with the reason, as upstream's `discard_range` panics in that case.
pub(crate) fn replacing<T>(start: u64, len: u64, anew: bool, change: impl FnOnce() -> T) -> T {
    let mapped = replace(start, len, true, anew);
    let result = change();
    if mapped && !replace(start, len, false, anew) {
        std::eprintln!(
            "wick: guest memory at host {start:#x}+{len:#x} cannot be mapped again after its pages \
             were replaced; the guest would run without it"
        );
        std::process::abort();
    }
    result
}
