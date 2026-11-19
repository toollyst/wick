// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The kernel side of Linux's userfaultfd, on Windows: `libc::wick_uffd`,
//! with the API and the wire format of the macOS module (`wick_uffd.rs`).
//!
//! On Linux, an access to a missing page of memory registered with a
//! userfaultfd queues a page fault event on the descriptor and puts the
//! faulting thread to sleep until a handler fills the page (`UFFDIO_COPY`,
//! `UFFDIO_ZEROPAGE`) and wakes it (`UFFDIO_WAKE`). KVM takes the same path
//! for guest accesses. This module gives the process those semantics:
//!
//! - Host threads: missing pages are `PAGE_NOACCESS`. The process's one
//!   vectored exception handler (`windows_mm::on_exception`, first in the
//!   chain, shared with lazy and released memory) turns an access violation
//!   on one into a page fault event and waits in a waiter slot
//!   ([`resolve_access`]); other exceptions go on down the chain.
//! - Guests: the Windows Hypervisor Platform honours the host protection of
//!   memory mapped into a partition: a guest access to a `PAGE_NOACCESS`
//!   page exits with `WHvRunVpExitReasonMemoryAccess` at the instruction,
//!   which re-runs once the page is accessible (measured on WHP hardware).
//!   The WHP backend resolves those exits with [`fault`].
//! - Registered memory is moved into a pagefile-backed section mapped twice:
//!   at its address, and as an alias that is always writable. Pages are
//!   filled through the alias and only then made accessible, so no thread
//!   sees a page half filled. With the lazy-memory exception handler the
//!   section is reserved: a missing page is not committed, and faults as a
//!   `PAGE_NOACCESS` one does; a fill commits it first, charged to the
//!   job's memory limit, through the view at its address with no access
//!   (`windows_mm::uffd_commit`), as Linux charges the page a `UFFDIO_COPY`
//!   allocates (`ENOMEM` when refused). A page missing when it leaves the
//!   registration (unregistered, or the userfaultfd released) is resolved
//!   at its first access: committed if never filled, zeroed if discarded
//!   (its range's record, `windows_mm::released_pend`).
//! - `madvise(MADV_DONTNEED)` on registered pages makes them missing again
//!   and queues a remove event ([`discarding`]); their memory is discarded.
//! - System calls that copy to or from missing pages fail on Windows
//!   (`ERROR_NOACCESS`) instead of waiting: the compatibility `read`, `pread`
//!   and friends fault the pages in first ([`prefault`]).
//!
//! A userfaultfd is one end of a pair of connected `AF_UNIX` sockets. Events
//! are [`proto::RECORD`]-byte records read from it. Another process holding
//! the descriptor sends a `HELLO` record followed by the `WSAPROTOCOL_INFOW`
//! of a socket it duplicated for this process (`WSADuplicateSocketW`): its
//! private request channel. A thread per userfaultfd serves the channels.

use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::boxed::Box;
use std::io;
use std::sync::Once;
#[cfg(test)]
use std::sync::Mutex;

use crate::windows_stacklock::ProbedMutex;
use std::vec::Vec;

use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, ERROR_FILE_NOT_FOUND, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Networking::WinSock::{
    self as ws, AF_UNIX, INVALID_SOCKET, POLLERR, POLLHUP, POLLRDNORM, SOCKET, SOCKET_ERROR,
    SOCK_STREAM, WSAPOLLFD, WSAPROTOCOL_INFOW, WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED,
};
use windows_sys::Win32::Storage::FileSystem::DeleteFileW;
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, DiscardVirtualMemory, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
    MapViewOfFile, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, SECTION_QUERY,
    SEC_COMMIT, SEC_FILE, SEC_IMAGE, SEC_RESERVE, UnmapViewOfFile, VirtualProtect,
};
use windows_sys::Win32::System::Threading::{
    CreateSemaphoreW, GetCurrentProcess, INFINITE, OpenProcess, PROCESS_DUP_HANDLE, ReleaseSemaphore, Sleep,
    WaitForSingleObject, WaitOnAddress, WakeByAddressAll,
};

use crate::windows_fd::wick_wsa_startup;

/// Wire format shared with the `userfaultfd` crate (as on macOS).
pub mod proto {
    /// Size of an event, a request header and a reply: four `u64` words.
    pub const RECORD: usize = 32;
    /// Event: `[EVENT_PAGEFAULT, addr, flags, 0]`.
    pub const EVENT_PAGEFAULT: u64 = 1;
    /// Event: `[EVENT_REMOVE, start, end, 0]`.
    pub const EVENT_REMOVE: u64 = 2;
    /// Page fault flag: the access was a write.
    pub const FLAG_WRITE: u64 = 1;
    /// Sent on the userfaultfd: `[HELLO, 0, 0, 0]`, then the
    /// `WSAPROTOCOL_INFOW` of the sender's end of its request channel,
    /// duplicated for the userfaultfd's process.
    pub const HELLO: u64 = 0x10;
    /// Request: `[OP_COPY, dst, len, mode]`, then `len` bytes. `mode` is
    /// Linux's `uffdio_copy.mode`: [`MODE_DONTWAKE`] and [`MODE_WP`], any
    /// other bit `EINVAL` (the `len` bytes are read all the same).
    pub const OP_COPY: u64 = 1;
    /// Request: `[OP_ZEROPAGE, start, len, mode]`. `mode` is Linux's
    /// `uffdio_zeropage.mode`: [`MODE_DONTWAKE`], any other bit `EINVAL`.
    pub const OP_ZEROPAGE: u64 = 2;
    /// Request: `[OP_WAKE, start, len, 0]`.
    pub const OP_WAKE: u64 = 3;
    /// Request: `[OP_REGISTER, start, len, 0]`. Reply: the range's ioctls
    /// (Linux's `uffdio_register.ioctls`, [`RANGE_IOCTLS`]) as the result
    /// and the count.
    pub const OP_REGISTER: u64 = 4;
    /// Request: `[OP_UNREGISTER, start, len, 0]`.
    pub const OP_UNREGISTER: u64 = 5;
    /// Copy and zeropage mode: do not wake the waiting threads (Linux's
    /// `UFFDIO_COPY_MODE_DONTWAKE` and `UFFDIO_ZEROPAGE_MODE_DONTWAKE`, both
    /// bit 0, include/uapi/linux/userfaultfd.h).
    pub const MODE_DONTWAKE: u64 = 1;
    /// Copy mode: map the pages write-protected (`UFFDIO_COPY_MODE_WP`, bit
    /// 1), which Linux takes only into a range registered for write-protect
    /// faults; no range is registered so here (a register asks for missing
    /// faults only), so a copy with it is `EINVAL`, once its range is found,
    /// as Linux's into a range not so registered.
    pub const MODE_WP: u64 = 2;
    /// A register's ioctls, Linux's bits (`1 << _UFFDIO_WAKE`, `_COPY`,
    /// `_ZEROPAGE`, include/uapi/linux/userfaultfd.h): the ones a registered
    /// range takes here. Linux's `UFFD_API_RANGE_IOCTLS` also has
    /// `UFFDIO_MOVE` and `UFFDIO_POISON`, which are not here, and
    /// `UFFDIO_WRITEPROTECT` and `UFFDIO_CONTINUE`, which it takes off for a
    /// range registered for missing faults only.
    pub const RANGE_IOCTLS: u64 = 1 << 0x02 | 1 << 0x03 | 1 << 0x04;
    /// A register's ioctls for a range that holds a `MAP_HUGETLB` mapping:
    /// no `UFFDIO_ZEROPAGE`, which Linux's hugetlb refuses
    /// (`UFFD_API_RANGE_IOCTLS_BASIC`). The macOS twin's; never the reply
    /// here, where a huge page mapping is not registered (`EINVAL`,
    /// SECURITY.md, "Not at parity yet").
    pub const RANGE_IOCTLS_HUGETLB: u64 = 1 << 0x02 | 1 << 0x03;
    // Reply: `[result, count, 0, 0]`: `result` is the byte count, or a
    // negative errno; for a partial copy `-EAGAIN` with the count copied.

    // ---- The waiter mirror (see the module's "The waiter mirror" doc below).
    // These constants are the twin of macOS's `libc::wick_uffd::proto`
    // (wick_uffd.rs): duplicated, not shared, so the backends stay
    // independent, and held equal to it by `test_the_mirror_proto_matches_the_macos_twin`.
    // When you change one, change the other. ----

    /// Event: `[EVENT_PAGEFAULT2, addr, flags, tag]`, the mirror era's page
    /// fault, carrying the waiter's `tag` (its word in the waiter mirror,
    /// [`tag`]). A reader that predates the mirror hard-codes
    /// [`EVENT_PAGEFAULT`] (1) and fails on this type loudly (an unrecognized
    /// event), where it would have returned events whose waiters were woken.
    /// Its value matches the macOS twin's `EVENT_PAGEFAULT` (3,
    /// wick_uffd.rs:140), where that side renamed the type in place.
    pub const EVENT_PAGEFAULT2: u64 = 3;
    /// Request: `[OP_MIRROR, 0, 0, 0]`: the push. Reply: `[size, handle, 0,
    /// 0]`, the waiter mirror's section duplicated into the reader's process
    /// read-only (`SECTION_QUERY | SECTION_MAP_READ`, never
    /// `DUPLICATE_SAME_ACCESS`; [`super::dup_mirror_read_only`]) and its value
    /// there, of `size` bytes ([`mirror_bytes`]); a negative errno and no
    /// handle if it fails: `-EPERM` when this process may not open the reader
    /// (a jailed VMM and a handler of the operator: the jail's token opens no
    /// process outside the jail), after which the reader pulls
    /// ([`OP_MIRROR_PULL`]). A serving thread that predates the mirror answers
    /// `-EINVAL` (an unknown request).
    pub const OP_MIRROR: u64 = 6;
    /// Request: `[OP_MIRROR_PULL, 0, 0, 0]`: the pull, for a reader this
    /// process may not open. Reply: `[size, handle, 0, 0]`, `handle` the value,
    /// in **this** (the VMM's) process, of the userfaultfd's read-only handle
    /// of the mirror (made at its creation with [`super::dup_mirror_read_only`],
    /// closed at its release); never the read-write handle the mirror was made
    /// with. The reader takes its own copy out of this process
    /// ([`super::pull_mirror`]: `PROCESS_DUP_HANDLE` on the process the
    /// userfaultfd's socket names as its peer, never a pid from a reply), as
    /// it took the userfaultfd itself out of a jail (vmm-sys-util's
    /// `sock_ctrl_msg`, `FLAG_PULL`). `-EINVAL` when there is no mirror; a
    /// serving thread that predates the pull answers `-EINVAL` (an unknown
    /// request). Windows only: the macOS twin passes a descriptor over the
    /// socket (`SCM_RIGHTS`), which a sandbox does not stop.
    pub const OP_MIRROR_PULL: u64 = 7;
    /// The waiter mirror's words: one per waiter slot.
    pub const MIRROR_WORDS: usize = 256;
    /// A tag's bit 0: its waiter waits.
    pub const TAG_WAITING: u64 = 1;
    /// A tag's slot field: bits 1 to 16. Wider than the table, so a reader
    /// checks it against [`MIRROR_WORDS`].
    const TAG_SLOT_SHIFT: u32 = 1;
    const TAG_SLOT_MASK: u64 = 0xffff;
    /// A tag's claim count: bits 17 to 63, the slot's own count of the
    /// waiters it has held, so that no two waiters of a slot share a tag.
    const TAG_COUNT_SHIFT: u32 = 17;

    /// The tag of the `count`th waiter of slot `slot`, waiting.
    pub const fn tag(count: u64, slot: usize) -> u64 {
        (count << TAG_COUNT_SHIFT) | ((slot as u64 & TAG_SLOT_MASK) << TAG_SLOT_SHIFT) | TAG_WAITING
    }

    /// A tag's slot field, unchecked: up to 65535.
    pub const fn tag_slot(tag: u64) -> usize {
        ((tag >> TAG_SLOT_SHIFT) & TAG_SLOT_MASK) as usize
    }

    /// The mirror section's size: its words in whole pages of `page` bytes
    /// (a view is mapped in whole pages).
    pub const fn mirror_bytes(page: usize) -> usize {
        (MIRROR_WORDS * 8).div_ceil(page) * page
    }
}

/// The feature bit (`UFFD_FEATURE_EVENT_REMOVE`) for remove events.
pub const FEATURE_EVENT_REMOVE: u64 = 1 << 3;

const PAGE: u64 = 4096;
const MAX_RANGES: usize = 64;
const MAX_CTX: usize = 16;
const MAX_WAITERS: usize = 256;
const _: () = assert!(MAX_WAITERS == proto::MIRROR_WORDS);

/// A registered range: one whole private mapping, made a section with an
/// alias at its register, whose pages each belong to one userfaultfd or to
/// none ([`Range::owner`]), as each of Linux's vmas has one context or none.
/// The slot lives, with its alias and record, until every page of it is
/// unmapped or mapped over ([`GONE`]), not only while a page is registered:
/// pages unregistered from it, or released with their userfaultfd, register
/// again through it, with any userfaultfd.
///
/// Its per-page arrays belong to the slot and are never freed: a reader
/// without [`LOCK`] (the exception handler's [`fault`], `is_missing`, the
/// WHP run loop's [`fault`]) may hold them. A range takes the free slot with
/// the least room that fits it, whose arrays it reuses, reset while the slot
/// is free; with none, the first free slot takes new arrays with room for
/// the next power of two of the range's pages ([`array_capacity`]) and keeps
/// the old ones. So what a slot holds grows with the peak of what was
/// registered at once, not with how often: less than twice its largest
/// arrays, less than four times what its largest range needs
/// (`test_register_and_unmap_in_a_loop_keeps_the_array_count_flat`). A range
/// needs a byte for the owner and three bits a page (missing, no read, no
/// write): 352 KiB for 1 GiB of 4 KiB pages (262144, a power of two).
///
/// `gen` is a sequence count that makes a reader without [`LOCK`] read the
/// slot whole ([`lookup`]): a writer, always under [`LOCK`], makes it odd,
/// stores `start` (0 at a free) or the slot's bounds, alias and array
/// pointers, and makes it even again ([`Range::changing`]); the window holds
/// those stores only, no allocation, lock or system call (the arrays are
/// made and reset before it, while the slot is free, which no lookup that
/// answers reads: it reads `start` 0, or its `gen` moved since). Changes of
/// one page's bits in a live slot (a fill, a discard, an unregister, a
/// protection, a register again) do not move it: readers act on them as
/// they are, in the order below. No exception can be raised inside a window
/// (stores to statics only), so unlike macOS's signal handler no fault ever
/// runs on a writer's own thread inside its window.
///
/// The order every change keeps, for readers without [`LOCK`] (the
/// exception handler's [`fault`], `is_missing`, `for_each_missing`): a page
/// with no owner is never missing. A register sets the owner before the
/// missing bit; an unregister, a release and an unmapping clear the missing
/// bit before the owner. A reader reads the missing bit first and the owner
/// after it ([`Range::missing_owner`]), so a missing page it acts on has
/// the owner it reads.
struct Range {
    /// 0: free.
    start: AtomicU64,
    end: AtomicU64,
    /// Second view of `[start, end)`, always readable and writable.
    alias: AtomicU64,
    /// The section is reserved: missing pages that were never filled are
    /// not committed (`windows_mm::uffd_alias`).
    reserved: AtomicBool,
    /// One bit per page: the page is missing.
    missing: AtomicPtr<AtomicU64>,
    /// One byte per page: the userfaultfd it is registered with (an index
    /// of [`CTXS`]), [`NONE`] (the range's memory, registered with none) or
    /// [`GONE`] (unmapped or mapped over).
    owner: AtomicPtr<AtomicU64>,
    /// One bit per page: its protection (`mprotect`) denies reads, and so
    /// every access (`PROT_NONE`).
    noread: AtomicPtr<AtomicU64>,
    /// One bit per page: its protection denies writes (`PROT_READ`, or
    /// `PROT_NONE`).
    nowrite: AtomicPtr<AtomicU64>,
    /// The record its released pages go to, taken at the register
    /// (`windows_mm::released_reserve`; a reserved section's only).
    record: AtomicUsize,
    /// Odd while a writer changes the slot's fields (see above).
    gen: AtomicU64,
}

impl Range {
    const fn new() -> Self {
        Range {
            start: AtomicU64::new(0),
            end: AtomicU64::new(0),
            alias: AtomicU64::new(0),
            reserved: AtomicBool::new(false),
            missing: AtomicPtr::new(ptr::null_mut()),
            owner: AtomicPtr::new(ptr::null_mut()),
            noread: AtomicPtr::new(ptr::null_mut()),
            nowrite: AtomicPtr::new(ptr::null_mut()),
            record: AtomicUsize::new(0),
            gen: AtomicU64::new(0),
        }
    }

    /// The protection `mprotect` gave `page`, as Windows' (read-write until
    /// one is given).
    fn prot(&self, page: u64) -> PAGE_PROTECTION_FLAGS {
        if Self::test(&self.noread, page) {
            PAGE_NOACCESS
        } else if Self::test(&self.nowrite, page) {
            PAGE_READONLY
        } else {
            PAGE_READWRITE
        }
    }

    /// Whether `page`'s protection denies the access (a write if `write`):
    /// then it is no userfault.
    fn denies(&self, page: u64, write: bool) -> bool {
        Self::test(&self.noread, page) || (write && Self::test(&self.nowrite, page))
    }

    /// Calls `f(start, len, prot)` for each run of `[s, s + len)` (pages of
    /// this range, whose first page is at `base`) of one protection.
    fn by_prot(&self, base: u64, s: u64, len: u64, mut f: impl FnMut(u64, u64, PAGE_PROTECTION_FLAGS)) {
        let mut run: Option<(u64, PAGE_PROTECTION_FLAGS)> = None;
        let mut at = s;
        while at < s + len {
            let prot = self.prot((at - base) / PAGE);
            match run {
                Some((_, p)) if p == prot => {}
                Some((r, p)) => {
                    f(r, at - r, p);
                    run = Some((at, prot));
                }
                None => run = Some((at, prot)),
            }
            at += PAGE;
        }
        if let Some((r, p)) = run {
            f(r, s + len - r, p);
        }
    }

    /// `page`'s bit in `map` (none past the array's room).
    fn test(map: &AtomicPtr<AtomicU64>, page: u64) -> bool {
        bit_of(map.load(Ordering::Acquire), page).is_some_and(|w| w.load(Ordering::SeqCst) & (1 << (page % 64)) != 0)
    }

    /// Under [`LOCK`], where the slot's arrays have room for every page of
    /// its range ([`past_capacity`] otherwise).
    fn set(map: &AtomicPtr<AtomicU64>, page: u64, on: bool) {
        let mask = 1 << (page % 64);
        let Some(w) = bit_of(map.load(Ordering::Acquire), page) else {
            past_capacity("bit", page);
        };
        if on {
            w.fetch_or(mask, Ordering::SeqCst);
        } else {
            w.fetch_and(!mask, Ordering::SeqCst);
        }
    }

    /// `page`'s owner byte: [`NONE`] past the array's room.
    fn owner_value(&self, page: u64) -> u8 {
        byte_of(self.owner.load(Ordering::Acquire), page).map_or(NONE, |b| b.load(Ordering::SeqCst))
    }

    /// The userfaultfd `page` is registered with, if any.
    fn owner(&self, page: u64) -> Option<usize> {
        let o = self.owner_value(page);
        (usize::from(o) < MAX_CTX).then_some(usize::from(o))
    }

    /// Whether `page` is registered with any userfaultfd.
    fn owned(&self, page: u64) -> bool {
        self.owner(page).is_some()
    }

    /// Whether `page` is no longer the range's memory ([`GONE`]).
    fn gone(&self, page: u64) -> bool {
        self.owner_value(page) == GONE
    }

    /// `page`'s owner becomes `ctx`'s index, [`NONE`] or [`GONE`]. Under
    /// [`LOCK`], in the order the type's doc gives, as [`Self::set`].
    fn set_owner(&self, page: u64, owner: u8) {
        let Some(b) = byte_of(self.owner.load(Ordering::Acquire), page) else {
            past_capacity("owner", page);
        };
        b.store(owner, Ordering::SeqCst);
    }

    /// Changes the slot's fields with `change`, `gen` odd meanwhile (see the
    /// type's doc). Under [`LOCK`]; `change` only stores.
    fn changing(&self, change: impl FnOnce()) {
        self.gen.fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        tests::window_hook();
        change();
        self.gen.fetch_add(1, Ordering::SeqCst);
    }

    /// The owner of `page` if it is missing: the missing bit read first,
    /// then the owner (the order the type's doc gives), so a page read as
    /// missing here has the owner returned.
    fn missing_owner(&self, page: u64) -> Option<usize> {
        if Self::test(&self.missing, page) { self.owner(page) } else { None }
    }
}

/// [`Range::owner`]: the range's memory, registered with no userfaultfd.
const NONE: u8 = 0xFF;
/// [`Range::owner`]: no longer the range's memory (unmapped, or mapped over).
const GONE: u8 = 0xFE;

/// A change under [`LOCK`] of a page past its slot's array: the arrays are
/// sized for the slot's range at its register, so this is a broken
/// invariant, and a change dropped would lose a registration or a fill
/// silently. Ends the process.
fn past_capacity(array: &str, page: u64) -> ! {
    std::eprintln!("wick: userfaultfd page {page} is past its slot's {array} array");
    std::process::abort();
}

/// The pages a new array has room for: the next power of two of a range's
/// pages, at least 64.
///
/// A per-page array of a slot has its capacity, the pages it has room for,
/// in its first word; then a bit a page ([`bit_of`]) or a byte a page
/// ([`byte_of`]). The one rule that makes a stale pointer harmless: every
/// index is checked against the capacity read from the array itself, never
/// against the slot's range. A reader without [`LOCK`] may read a slot's
/// bounds of one range and its pointers of another (released and reused
/// between its loads); its index then may pass the end of the array it
/// holds. Checked so, it reads nothing there, and the slot's `gen`, which
/// every such change moves, makes it read again ([`lookup`]). Arrays are
/// never freed, so the capacity word itself is always there to read.
fn array_capacity(pages: u64) -> u64 {
    pages.max(64).next_power_of_two()
}

/// A new array of `capacity` pages, `bits` a page (1 or 8), every byte
/// `fill`.
fn alloc_array(capacity: u64, bits: u64, fill: u8) -> *mut AtomicU64 {
    let word = u64::from_ne_bytes([fill; 8]);
    let words = (capacity * bits).div_ceil(64) as usize;
    let mut v: Vec<AtomicU64> = Vec::with_capacity(words + 1);
    v.push(AtomicU64::new(capacity));
    v.extend((0..words).map(|_| AtomicU64::new(word)));
    #[cfg(test)]
    tests::ARRAYS_MADE.fetch_add(1, Ordering::SeqCst);
    Box::into_raw(v.into_boxed_slice()).cast()
}

/// The capacity of `array` ([`array_capacity`]), 0 for none.
fn capacity_of(array: *const AtomicU64) -> u64 {
    if array.is_null() {
        return 0;
    }
    // SAFETY: a slot's array, never freed; its first word is its capacity.
    unsafe { (*array).load(Ordering::Acquire) }
}

/// Whether `page` is within `array`'s capacity ([`array_capacity`]'s rule).
fn within(array: *const AtomicU64, page: u64) -> bool {
    let capacity = capacity_of(array);
    let ok = page < capacity;
    #[cfg(test)]
    tests::index_checked(page, capacity, ok);
    ok
}

/// The word of bit array `array` that holds `page`'s bit, if it has room.
fn bit_of(array: *const AtomicU64, page: u64) -> Option<&'static AtomicU64> {
    // SAFETY: within the array's capacity, past its capacity word.
    within(array, page).then(|| unsafe { &*array.add(1 + (page / 64) as usize) })
}

/// The byte of byte array `array` for `page`, if it has room.
fn byte_of(array: *const AtomicU64, page: u64) -> Option<&'static AtomicU8> {
    // SAFETY: within the array's capacity, past its capacity word.
    within(array, page).then(|| unsafe { &*array.add(1).cast::<AtomicU8>().add(page as usize) })
}

/// Sets `pages` pages of `array` from page 0 to `fill` (each bit, or each
/// byte), and the rest of its room to `rest`. On a free slot's arrays,
/// before a register's window.
fn reset_array(array: *const AtomicU64, bits: u64, pages: u64, fill: u8, rest: u8) {
    let capacity = capacity_of(array);
    if bits == 8 {
        for page in 0..capacity {
            if let Some(b) = byte_of(array, page) {
                b.store(if page < pages { fill } else { rest }, Ordering::SeqCst);
            }
        }
        return;
    }
    for word in 0..capacity.div_ceil(64) {
        let first = word * 64;
        // The bits of this word's pages that lie below `pages`.
        let below = if pages >= first + 64 {
            !0
        } else if pages <= first {
            0
        } else {
            (1u64 << (pages - first)) - 1
        };
        let value = (if fill != 0 { below } else { 0 }) | (if rest != 0 { !below } else { 0 });
        if let Some(w) = bit_of(array, first) {
            w.store(value, Ordering::SeqCst);
        }
    }
}

/// `ctx`, an index of [`CTXS`], as an owner byte.
fn owner_of(ctx: usize) -> u8 {
    debug_assert!(ctx < MAX_CTX);
    #[allow(clippy::cast_possible_truncation)]
    let o = ctx as u8;
    o
}

/// A userfaultfd: the kernel end of its socket pair (-1: free).
struct Ctx {
    fd: AtomicI32,
    features: AtomicU64,
    /// The waiter mirror, mapped read-write here; null before [`create`] makes
    /// it and after [`destroy`] takes it away ([`new_mirror`], the module's
    /// "The waiter mirror section" doc).
    mirror: AtomicPtr<AtomicU64>,
    /// The mirror's section handle, duplicated read-only to each reader
    /// ([`dup_mirror_read_only`]) and closed at [`destroy`]; null for none.
    /// Read-write: never named in a reply.
    section: AtomicPtr<c_void>,
    /// A read-only handle of the mirror in this process
    /// ([`dup_mirror_read_only`]), whose value `OP_MIRROR_PULL` replies with
    /// for a reader to take its own copy of ([`serve_mirror_pull`]); made
    /// with the mirror, closed at [`destroy`]; null for none.
    pull: AtomicPtr<c_void>,
    /// Threads using the mirror or the kernel end ([`enter`]): [`destroy`]
    /// unmaps the mirror and closes the section once none is left.
    users: AtomicUsize,
}

/// A thread waiting for a page.
struct Waiter {
    /// The page address; 0: free.
    page: AtomicU64,
    /// The userfaultfd the fault was posted to: only its wakes and its release
    /// end the wait, whatever happens to the memory meanwhile, as Linux queues
    /// a waiter on its context (fs/userfaultfd.c, v6.1: `handle_userfault`
    /// :377, which queues it on `ctx->fault_pending_wqh`;
    /// `userfaultfd_wake_function` :111 to :146 wakes it by address within that
    /// queue). `usize::MAX`: free.
    ctx: AtomicUsize,
    /// The waiters this slot has held: the count in their tags, so no two
    /// waiters of a slot share a tag (the waiter mirror).
    count: AtomicU64,
    /// A semaphore handle.
    sem: AtomicUsize,
}

static RANGES: [Range; MAX_RANGES] = [const { Range::new() }; MAX_RANGES];
static CTXS: [Ctx; MAX_CTX] = [const {
    Ctx {
        fd: AtomicI32::new(-1),
        features: AtomicU64::new(0),
        mirror: AtomicPtr::new(ptr::null_mut()),
        section: AtomicPtr::new(ptr::null_mut()),
        pull: AtomicPtr::new(ptr::null_mut()),
        users: AtomicUsize::new(0),
    }
}; MAX_CTX];
static WAITERS: [Waiter; MAX_WAITERS] = [const {
    Waiter {
        page: AtomicU64::new(0),
        ctx: AtomicUsize::new(usize::MAX),
        count: AtomicU64::new(0),
        sem: AtomicUsize::new(0),
    }
}; MAX_WAITERS];
/// Number of registered ranges (the I/O wrappers skip all work at 0).
static REGISTERED: AtomicUsize = AtomicUsize::new(0);
/// Serializes changes to the ranges. Taken through [`lock`].
static LOCK: ProbedMutex<()> = ProbedMutex::new("the userfaultfd ranges' LOCK", ());

std::thread_local! {
    /// This thread holds [`LOCK`]: a reclaim it would start (a lazy page a
    /// fill's source buffer touches) cannot take it again.
    static HOLDS_LOCK: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// [`LOCK`], held until the guard drops.
struct Locked(#[allow(dead_code)] crate::windows_stacklock::Probed<std::sync::MutexGuard<'static, ()>>);

impl Drop for Locked {
    fn drop(&mut self) {
        HOLDS_LOCK.set(false);
    }
}

#[track_caller]
fn lock() -> Locked {
    #[cfg(test)]
    LOCK_WAITING.fetch_add(1, Ordering::SeqCst);
    let g = LOCK.lock().unwrap();
    #[cfg(test)]
    LOCK_WAITING.fetch_sub(1, Ordering::SeqCst);
    HOLDS_LOCK.set(true);
    Locked(g)
}

/// Tests: the threads waiting for [`LOCK`] (or taking it) now; with the
/// lock held by the test's thread, a count above 0 is a thread blocked on it.
#[cfg(test)]
static LOCK_WAITING: AtomicUsize = AtomicUsize::new(0);

/// Changes of memory under way without [`LOCK`]: an `munmap`, a
/// `MAP_FIXED` mapping, an `mprotect` or a discard that found no registered
/// range in reach ([`unlocked_change`]).
static UNLOCKED_CHANGES: AtomicUsize = AtomicUsize::new(0);
/// Registers under way ([`register`]).
static REGISTERING: AtomicUsize = AtomicUsize::new(0);

/// A change of memory running without [`LOCK`]; ends when dropped.
struct UnlockedChange;

impl Drop for UnlockedChange {
    fn drop(&mut self) {
        end_unlocked_change();
    }
}

fn end_unlocked_change() {
    if UNLOCKED_CHANGES.fetch_sub(1, Ordering::SeqCst) == 1 && REGISTERING.load(Ordering::SeqCst) > 0 {
        // SAFETY: the address of a static.
        unsafe { WakeByAddressAll((&raw const UNLOCKED_CHANGES).cast()) };
    }
}

/// Whether a change of memory (an `munmap`, a `MAP_FIXED` mapping, an
/// `mprotect`, a discard) may run without [`LOCK`]: when it touches no
/// registered range (`touches` is false) and no register is under way. On
/// Linux the mm's lock orders such a change and a register (both take
/// `mmap_write_lock`; v6.1 fs/userfaultfd.c `userfaultfd_register` :1320,
/// mm/mmap.c `__vm_munmap`, mm/mprotect.c `do_mprotect_pkey`; a
/// `MADV_DONTNEED` takes the read lock, which the register's write lock
/// excludes): either the register finds the memory as the change left it,
/// or the change takes the registration with it. Here the change counts
/// itself in [`UNLOCKED_CHANGES`] and then reads [`REGISTERING`]; a
/// register counts itself in [`REGISTERING`] and then waits for
/// [`UNLOCKED_CHANGES`] to be 0 before it reads the mappings ([`register`]).
/// All four are `SeqCst`, so of a change and a register that overlap in
/// time at least one sees the other (the store-buffering pattern, which
/// sequentially consistent operations, one total order for all of them,
/// rule out):
/// 1. The change's increment comes first. The register's wait reads a
///    count above 0 and waits until the change has dropped it, after its
///    change, and only then reads the mappings.
/// 2. The register's increment comes first. The change reads
///    [`REGISTERING`] above 0 and diverts: it drops its own count before it
///    takes [`LOCK`] (so the register it saw is not left waiting on it), and
///    under the lock decides again, by walking the ranges, whether it
///    touches a registered range ([`untrack_gone`], [`mprotect_locked`],
///    [`discarding`]).
///
/// A register waits only for changes already running without the lock;
/// changes that begin while it waits take [`LOCK`], so it cannot be
/// starved. The register waits with `WaitOnAddress` on
/// [`UNLOCKED_CHANGES`] (the last change out wakes it with
/// `WakeByAddressAll`), holding no lock; no exception handler reaches it or
/// any of the four changes (the exception handler, `windows_mm::on_exception`,
/// resolves a fault: `fault`,
/// `commit_on_access`, `reclaim_at_touch`, `released_access`; the changes
/// are reached only from `windows_mm`'s `munmap`, `mmap`, `mprotect` and
/// `madvise`). Returns the change's count, ended when dropped, or `None`:
/// take [`LOCK`].
fn unlocked_change(touches: impl FnOnce() -> bool) -> Option<UnlockedChange> {
    UNLOCKED_CHANGES.fetch_add(1, Ordering::SeqCst);
    if REGISTERING.load(Ordering::SeqCst) == 0 && !touches() {
        #[cfg(test)]
        tests::change_hook();
        return Some(UnlockedChange);
    }
    end_unlocked_change();
    None
}

/// Whether any registered range overlaps `[start, end)`.
fn touches(start: u64, end: u64) -> bool {
    RANGES.iter().any(|r| {
        let s = r.start.load(Ordering::SeqCst);
        s != 0 && start < r.end.load(Ordering::SeqCst) && s < end
    })
}

/// The memory being moved (`[start, end)`, start 0 when none): a chunk the
/// reclaim moves ([`move_chunk`]) or a register's memory ([`register`]),
/// one at a time ([`MovingWindow`]). An access to it waits for the move
/// ([`fault`]).
static MOVING_START: AtomicU64 = AtomicU64::new(0);
static MOVING_END: AtomicU64 = AtomicU64::new(0);

/// The moving mark ([`MOVING_START`]) over `[start, end)` until dropped:
/// a register's memory while it is moved and its range made ([`register`]),
/// or a chunk the reclaim moves ([`move_chunk`]). The mark is one, so two
/// windows open at once would leave the first's faulting threads waiting on
/// the second's bounds; [`LOCK`] keeps them apart for every window's whole
/// life: a register opens its window after it takes the lock and drops it
/// before the lock's guard (declared after it); the reclaim's thread opens
/// one only in an answer to an ask ([`reclaimer`]), and every asker holds
/// the lock until the answer ([`ask_the_reclaimer`]: a fill's reclaim under
/// the fill's guard, [`reclaim_at_touch`]'s and [`wait_and_move`]'s under
/// their own). Debug builds assert the mark empty at the open and still
/// this window's at the drop.
struct MovingWindow {
    start: u64,
    end: u64,
}

impl MovingWindow {
    fn open(start: u64, end: u64) -> MovingWindow {
        // The reclaimer holds it for its asker (`HOLDS_LOCK` set for good).
        debug_assert!(HOLDS_LOCK.get(), "a moving window opened over [{start:#x}, {end:#x}) without LOCK");
        let was_end = MOVING_END.swap(end, Ordering::SeqCst);
        let was = MOVING_START.swap(start, Ordering::SeqCst);
        debug_assert!(
            was == 0 && was_end == 0,
            "a moving window opened over [{start:#x}, {end:#x}) while [{was:#x}, {was_end:#x}) was open"
        );
        MovingWindow { start, end }
    }
}

impl Drop for MovingWindow {
    fn drop(&mut self) {
        let start = MOVING_START.swap(0, Ordering::SeqCst);
        let end = MOVING_END.swap(0, Ordering::SeqCst);
        debug_assert!(
            start == self.start && end == self.end,
            "the moving window over [{:#x}, {:#x}) closed holding [{start:#x}, {end:#x})",
            self.start,
            self.end
        );
    }
}

/// Whether `addr` is in the chunk being moved.
pub fn is_moving(addr: u64) -> bool {
    let s = MOVING_START.load(Ordering::SeqCst);
    s != 0 && addr >= s && addr < MOVING_END.load(Ordering::SeqCst)
}
static INIT: Once = Once::new();
static READY: AtomicBool = AtomicBool::new(false);

fn errno_err(errno: c_int) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

fn init() -> io::Result<()> {
    INIT.call_once(|| {
        for w in WAITERS.iter() {
            // SAFETY: an unnamed semaphore, initially unsignalled.
            let sem = unsafe { CreateSemaphoreW(ptr::null(), 0, i32::MAX, ptr::null()) };
            if sem.is_null() {
                return;
            }
            w.sem.store(sem as usize, Ordering::Release);
        }
        // The process's one vectored exception handler, which runs this
        // module's step ([`resolve_access`]) first: added by whichever of
        // a lazy mapping, a create and a register comes first.
        if !crate::windows_mm::exception_handler() {
            return;
        }
        READY.store(true, Ordering::Release);
    });
    if READY.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(errno_err(crate::ENOMEM))
    }
}

/// What [`lookup`] found: `addr`'s slot, its page, the page's address, the
/// slot's `gen` when it was read, and what was read of it.
struct Found<T> {
    range: &'static Range,
    page: u64,
    at: u64,
    gen: u64,
    value: T,
}

/// Finds the registered page holding `addr` and reads it with `read(range,
/// page)`, consistently without [`LOCK`]: each slot's `gen` is read before
/// its fields and again after `read` (a fence between), and a change
/// between makes the whole lookup start over, so `read` never pairs one
/// range's bounds with another's arrays (its indexes are checked against
/// each array's own capacity all the same, [`array_capacity`]). A slot that
/// is odd (a writer in its window) is waited for with a yield: the window
/// holds stores only, so the wait is its few stores, unless the writer's
/// thread is preempted in it. A start over needs a window of that slot that
/// began after the first read, and two windows of one slot are separated by
/// system calls outside them (the alias's mapping at a register, the
/// unmapping that frees it), so a lookup, a few loads, starts over again
/// only if each of its tries overlaps a window. Under [`LOCK`] no window is
/// open but the calling thread's own, and that holds no lookup: a slot odd
/// there is a broken invariant, and ends the process rather than wait for
/// itself.
fn lookup<T>(addr: u64, read: impl Fn(&'static Range, u64) -> T) -> Option<Found<T>> {
    'again: loop {
        for r in RANGES.iter() {
            let g1 = r.gen.load(Ordering::SeqCst);
            if g1 & 1 != 0 {
                if HOLDS_LOCK.with(core::cell::Cell::get) {
                    std::eprintln!("wick: a userfaultfd slot looked up inside its own writer's window");
                    std::process::abort();
                }
                std::thread::yield_now();
                continue 'again;
            }
            let start = r.start.load(Ordering::Acquire);
            #[cfg(test)]
            tests::lookup_hook(addr, start);
            let end = r.end.load(Ordering::Acquire);
            let found = (start != 0 && addr >= start && addr < end).then(|| {
                let page = (addr - start) / PAGE;
                (page, start + page * PAGE, read(r, page))
            });
            core::sync::atomic::fence(Ordering::Acquire);
            if r.gen.load(Ordering::SeqCst) != g1 {
                continue 'again;
            }
            if let Some((page, at, value)) = found {
                return Some(Found { range: r, page, at, gen: g1, value });
            }
        }
        return None;
    }
}

/// The range and page index of `addr`, if it is registered memory
/// ([`lookup`]).
fn find(addr: u64) -> Option<(&'static Range, u64)> {
    lookup(addr, |_, _| ()).map(|f| (f.range, f.page))
}

/// Whether `addr` is in a registered page that is missing.
pub fn is_missing(addr: u64) -> bool {
    lookup(addr, |r, page| r.missing_owner(page).is_some()).is_some_and(|f| f.value)
}

fn sock(fd: c_int) -> SOCKET {
    #[allow(clippy::cast_sign_loss)]
    let s = fd as u32 as SOCKET;
    s
}

#[allow(clippy::cast_possible_truncation)]
fn to_fd(s: SOCKET) -> c_int {
    s as u32 as c_int
}

/// The descriptor of a socket made or accepted here: `None` (the socket
/// closed, `EINVAL` set, the reason on stderr) when its value is no
/// descriptor, never truncated. [`to_fd`] is for sockets adopted so.
fn adopt(s: SOCKET) -> Option<c_int> {
    crate::windows_linux::socket_fd(s, crate::windows_linux::socket_fits)
}

fn send_all(fd: c_int, buf: &[u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        let want = i32::try_from(buf.len() - done).unwrap_or(i32::MAX);
        // SAFETY: sends from a valid buffer.
        let n = unsafe { ws::send(sock(fd), buf[done..].as_ptr(), want, 0) };
        if n <= 0 {
            return false;
        }
        done += n.unsigned_abs() as usize;
    }
    true
}

fn recv_all(fd: c_int, buf: &mut [u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        let want = i32::try_from(buf.len() - done).unwrap_or(i32::MAX);
        // SAFETY: receives into a valid buffer.
        let n = unsafe { ws::recv(sock(fd), buf[done..].as_mut_ptr(), want, 0) };
        if n <= 0 {
            return false;
        }
        done += n.unsigned_abs() as usize;
    }
    true
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
    // If the handler side is gone, nobody will serve the fault.
    let _ = send_all(fd, &bytes);
}

/// Resolves an access to `addr`: if it is a missing registered page, queues
/// a page fault event and waits until the page is filled and the waiters are
/// woken. Returns false if `addr` is not a missing registered page.
pub fn fault(addr: u64, write: bool) -> bool {
    // A chunk being moved by a reclaim: closed for the move's time (a few
    // hundred microseconds), then open in its new section; the access runs
    // again.
    if is_moving(addr) {
        let t = std::time::Instant::now();
        #[cfg(test)]
        tests::MOVE_WAITING.fetch_add(1, Ordering::SeqCst);
        while is_moving(addr) {
            std::thread::yield_now();
        }
        MOVE_WAITS.fetch_add(1, Ordering::Relaxed);
        MOVE_WAITED_US.fetch_add(u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX), Ordering::Relaxed);
        return true;
    }
    // The page's owner if it is missing, and whether its protection denies
    // the access, read whole ([`lookup`]). An access its protection denies
    // is the access fault, not a userfault: Linux checks the vma's
    // protection first (v6.1 arch/x86/mm/fault.c, `do_user_addr_fault`:
    // `access_error` at :1410, before `handle_mm_fault` at :1428, where
    // `do_anonymous_page` hands a missing page to userfaultfd).
    let Some(Found { range, page, at: page_addr, gen: g1, value: (Some(ctx), false) }) =
        lookup(addr, |r, page| (r.missing_owner(page), r.denies(page, write)))
    else {
        return false;
    };
    trace::note(trace::FAULT_ENTERED, page_addr, || u64::from(write));
    // Claim a waiter slot.
    let (index, slot) = loop {
        if let Some(found) = WAITERS.iter().enumerate().find(|(_, w)| {
            w.page
                .compare_exchange(0, page_addr, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        }) {
            break found;
        }
        // All slots busy: wait a little.
        // SAFETY: plain call.
        unsafe { Sleep(1) };
    };
    // Its userfaultfd released since the lookup: no fault to report, and the
    // access runs again.
    let Some(mirror) = enter(ctx) else {
        slot.page.store(0, Ordering::SeqCst);
        return true;
    };
    slot.ctx.store(ctx, Ordering::SeqCst);
    let tag = proto::tag(slot.count.fetch_add(1, Ordering::Relaxed).wrapping_add(1), index);
    let word = &mirror[index];
    // Waiting, before the validation reads below. Two validations compose
    // here, each a store before a load against a writer's store before a load
    // (SeqCst all). The page's: filled, unregistered or registered again since
    // the lookup is no fault to report to `ctx`, and a change after this read
    // wakes the waiter ([`fill`], [`unregister`] wake the waiters of each
    // page's owner). The slot's: its `gen` read last, after the page, so that
    // a slot freed and taken by another range since the lookup (its arrays
    // reset while it was free) is told by `gen`, not by bits that are the new
    // range's (`test_fault_reads_the_generation_after_the_page`); the access
    // then runs again on what is there now
    // (`test_fault_validates_after_its_waiter_is_registered`). The wake's: the
    // tag is in the mirror before the bits are read, against a writer's change
    // before its wake loads the mirror ([`wake_where`]), so a waiter whose
    // reads saw the page before a change is woken by that change's wake, its
    // tag cleared, and one that reads after the change posts nothing.
    word.store(tag, Ordering::SeqCst);
    #[cfg(test)]
    tests::validate_hook(addr);
    let report = range.missing_owner(page) == Some(ctx);
    #[cfg(test)]
    tests::between_hook(addr);
    let same = range.gen.load(Ordering::SeqCst) == g1;
    // Woken already (by a wake of its page, or spuriously: a wake that read the
    // slot's page of a waiter before): no record, the access runs again.
    let posted = report && same && word.load(Ordering::SeqCst) == tag;
    if posted {
        let flags = if write { proto::FLAG_WRITE } else { 0 };
        trace::note(trace::FAULT_POSTED, page_addr, || 0);
        post(ctx, [proto::EVENT_PAGEFAULT2, addr, flags, tag]);
        while word.load(Ordering::SeqCst) == tag {
            // SAFETY: a semaphore created at init.
            unsafe { WaitForSingleObject(slot.sem.load(Ordering::Acquire) as HANDLE, INFINITE) };
        }
    }
    word.store(0, Ordering::SeqCst);
    leave(ctx);
    slot.ctx.store(usize::MAX, Ordering::SeqCst);
    slot.page.store(0, Ordering::SeqCst);
    trace::note(trace::FAULT_LEFT, page_addr, || u64::from(posted));
    true
}

/// Wakes the threads waiting for pages in `[start, start + len)`, whichever
/// userfaultfd they wait on.
pub fn wake(start: u64, len: u64) {
    wake_where(|_, page| page >= start && page < start.saturating_add(len));
}

/// Wakes the threads waiting on userfaultfd `ctx` for pages in `[start,
/// start + len)`, as Linux's `wake_userfault` wakes its context's queue
/// (fs/userfaultfd.c, v6.1, `wake_userfault` :1216, through
/// `userfaultfd_wake_function` :121 to :126).
fn wake_ctx(ctx: usize, start: u64, len: u64) {
    wake_where(|c, page| c == ctx && page >= start && page < start.saturating_add(len));
}

/// Wakes the waiters `which(ctx, page)` names.
/// Wakes the waiters `which(ctx, page)` names: clears the waiting bit of the
/// exact tag read from the mirror, so the bit of a later waiter of the slot is
/// never cleared, and a reader drops the woken waiter's record from then on,
/// read or not, as Linux's wake takes the waiter off its queue (v6.1
/// fs/userfaultfd.c `userfaultfd_wake_function` :141). The slot's page and the
/// tag may be two waiters' (the slot changed hands between): then the later
/// one is woken spuriously and runs its access again, as a Linux fault woken
/// spuriously retries.
fn wake_where(which: impl Fn(usize, u64) -> bool) {
    for (index, w) in WAITERS.iter().enumerate() {
        let page = w.page.load(Ordering::SeqCst);
        let ctx = w.ctx.load(Ordering::SeqCst);
        if page == 0 || ctx >= MAX_CTX || !which(ctx, page) {
            continue;
        }
        let Some(mirror) = enter(ctx) else {
            continue;
        };
        let tag = mirror[index].load(Ordering::SeqCst);
        if tag & proto::TAG_WAITING != 0
            && mirror[index]
                .compare_exchange(tag, tag & !proto::TAG_WAITING, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            // SAFETY: a semaphore created at init.
            unsafe { ReleaseSemaphore(w.sem.load(Ordering::Acquire) as HANDLE, 1, ptr::null_mut()) };
        }
        leave(ctx);
    }
}

// ---- The waiter mirror's section. The macOS twin (`libc::wick_uffd`, "The
// waiter mirror") keeps the mirror in a POSIX shared memory object it
// `shm_open`s under a random name and unlinks at once; Windows needs no name
// at all. This side keeps the section handle and a read-write view; each
// reader is given the section read-only ([`dup_mirror_read_only`]) and maps
// it ([`map_mirror_read_only`]), proven read-only by the four tests below.
// [`fault`] stores a waiter's tag in its slot's word before the record is
// posted and clears it when the wait ends; [`wake_where`] clears the waiting
// bit of the exact tag; the reader (`userfaultfd` crate) drops a page fault
// record whose word no longer holds its waiting tag. [`enter`]/[`leave`] hold
// the mirror against [`destroy`]'s drain. ----

/// The waiter mirror section's size in bytes (a whole page).
fn mirror_bytes() -> usize {
    proto::mirror_bytes(PAGE as usize)
}

/// Makes a userfaultfd's waiter mirror: an **unnamed** pagefile-backed
/// section (`CreateFileMappingW` with a null name, so it is in no object
/// namespace and no `OpenFileMappingW` can reach it, as `windows_sectrec`'s
/// sections are), mapped read-write here. Returns the section handle and the
/// read-write view; the caller keeps both. Strictly safer than the macOS
/// twin, which has a name for the instant between its two opens and the
/// unlink: this has no name at any point (SECURITY.md).
pub fn new_mirror() -> io::Result<(HANDLE, *mut AtomicU64)> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let bytes = mirror_bytes();
    // A DACL that grants Everyone (`WD`) only `SECTION_QUERY | SECTION_MAP_READ`
    // (0x5) and no write: so a process that holds a handle to the section —
    // only ever one this side duplicates read-only — cannot `DuplicateHandle`
    // it up to `SECTION_MAP_WRITE` (the access check reads the DACL with the
    // caller's token; without a write ACE it is refused;
    // `test_a_mirror_handle_a_reader_gets_cannot_be_re_duplicated_to_writable`).
    // The creator's own handle, returned by `CreateFileMappingW`, keeps the
    // write `PAGE_READWRITE` asks for, as a creator's handle does. Granting
    // Everyone read is no exposure: the section is unnamed, so no process can
    // open it; a handle is reached only through this side's duplicate.
    //
    // Everyone (`WD`), not the creator's own SID, by necessity: the reader's
    // token is not known when the section is made (a reader is any process the
    // descriptor later reaches), so the DACL cannot name it. A future editor
    // must NOT "tighten" this to the creator's SID — that would refuse a
    // read handle to a reader in another security context (the operator's
    // handler of a jailed VMM, which pulls its copy, `OP_MIRROR_PULL`; a
    // jailed handler of an unjailed VMM, which is pushed one), the opposite
    // of what the mirror needs. The ACE grants query and read, never write,
    // so Everyone-read costs nothing a reader does not already get from this
    // side's read-only handle.
    let sddl: Vec<u16> = "D:(A;;0x5;;;WD)".encode_utf16().chain([0]).collect();
    let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and an out-pointer for the SD.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut psd, ptr::null_mut())
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        // Non-inheritable: the section handle is never inherited by a child
        // (the reader gets its handle through `dup_mirror_read_only`'s
        // `DuplicateHandle`, whose `bInheritHandle` is also 0), so a spawned
        // process cannot acquire the writable creator handle by inheritance.
        bInheritHandle: 0,
    };
    // SAFETY: an unnamed section (null name) with the read-only DACL; checked.
    let section = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            &sa,
            PAGE_READWRITE | SEC_COMMIT,
            (bytes as u64 >> 32) as u32,
            bytes as u32,
            ptr::null(),
        )
    };
    let e = io::Error::last_os_error();
    // SAFETY: the SD allocated by the convert call; the section kept its copy.
    unsafe { LocalFree(psd) };
    if section.is_null() {
        return Err(e);
    }
    // SAFETY: the creator's section handle (write kept); a read-write view.
    let view = unsafe { MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, bytes) }.Value;
    if view.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: the section handle made above.
        unsafe { CloseHandle(section) };
        return Err(e);
    }
    Ok((section, view.cast()))
}

/// The access a reader's handle of the mirror has: `SECTION_MAP_READ`
/// (`FILE_MAP_READ`'s value, 0x4) to map it read-only, and `SECTION_QUERY`
/// (0x1), which [`check_mirror_section`] needs to read what the object is
/// before the reader maps it. No write; the section's DACL grants Everyone
/// exactly these two (0x5, [`new_mirror`]).
const MIRROR_READER_ACCESS: u32 = FILE_MAP_READ | SECTION_QUERY;

/// Duplicates the mirror `section` into `target` (a process handle) with
/// **[`MIRROR_READER_ACCESS`] only** (`SECTION_QUERY | SECTION_MAP_READ`),
/// never `DUPLICATE_SAME_ACCESS`. This is a **distinct** path from the
/// crate's other handle sends, which pass `DUPLICATE_SAME_ACCESS`
/// (windows_fd.rs), so no caller gets the read-write handle by mistake: the
/// reduced access is not a flag on a shared send, it is this function. The
/// duplicate can map the mirror read-only and query it, nothing more
/// (`test_a_mirror_handle_a_reader_gets_cannot_be_re_duplicated_to_writable`).
///
/// # Safety
/// `section` must be a live section handle and `target` a live process
/// handle with `PROCESS_DUP_HANDLE`.
pub unsafe fn dup_mirror_read_only(section: HANDLE, target: HANDLE) -> io::Result<HANDLE> {
    let mut out: HANDLE = ptr::null_mut();
    // SAFETY: the caller's live section and target process handles; the
    // access is `MIRROR_READER_ACCESS`, no `DUPLICATE_SAME_ACCESS`, and
    // `bInheritHandle` (the 6th argument) is 0, so the reader's duplicate is
    // not inheritable either.
    let ok = unsafe { DuplicateHandle(GetCurrentProcess(), section, target, &mut out, MIRROR_READER_ACCESS, 0, 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(out)
}

/// Maps a mirror `section` handle a reader received read-only
/// (`MapViewOfFile` with `FILE_MAP_READ`). The reader indexes the returned
/// words; it cannot write them (the handle lacks `SECTION_MAP_WRITE`). The
/// macOS twin maps its read-only descriptor with `PROT_READ`.
///
/// # Safety
/// `section` must be a live section handle with at least `SECTION_MAP_READ`.
pub unsafe fn map_mirror_read_only(section: HANDLE) -> io::Result<*const AtomicU64> {
    // SAFETY: the caller's live section handle; a read-only view of it.
    let view = unsafe { MapViewOfFile(section, FILE_MAP_READ, 0, 0, mirror_bytes()) }.Value;
    if view.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(view.cast())
}

/// Unmaps a mirror view ([`new_mirror`]'s read-write one or
/// [`map_mirror_read_only`]'s read-only one).
///
/// # Safety
/// `view` must be a mirror view this module mapped and not since unmapped,
/// no longer in use.
pub unsafe fn unmap_mirror(view: *const AtomicU64) {
    // SAFETY: the caller's mirror view.
    unsafe { UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: view as *mut c_void }) };
}

/// Takes the reader's own copy of a mirror out of the VMM, for a reader the
/// VMM cannot open (`OP_MIRROR_PULL`, [`serve_mirror_pull`]): opens process
/// `vmm` with `PROCESS_DUP_HANDLE` and duplicates its handle `value` into
/// this process asking [`MIRROR_READER_ACCESS`] alone, not inheritable,
/// without `DUPLICATE_SAME_ACCESS` (a value naming a writable handle still
/// gives a read-only copy) and without `DUPLICATE_CLOSE_SOURCE` (the VMM's
/// handle stays its own, for other readers, and nothing of the VMM's is
/// closed by a value it gave). `vmm` must come from the userfaultfd socket's
/// peer (`SIO_AF_UNIX_GETPEERPID`, which the system gives), never from a
/// reply. The VMM is not trusted: the copy is checked before it is mapped
/// ([`map_mirror_handle`]). Fails with the error that stopped it: the
/// process not opened (`EACCES`, `ERROR_ACCESS_DENIED`: neither side may
/// open the other, a combination that needs a third process that may), or
/// the value naming no handle there.
pub fn pull_mirror(vmm: u32, value: u64) -> io::Result<HANDLE> {
    // SAFETY: a pid; a process handle with the one right the dup needs.
    let proc = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, vmm) };
    if proc.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut out: HANDLE = ptr::null_mut();
    // SAFETY: the VMM's process handle; a handle value of its table, which
    // the call checks; the copy has the reader's access and nothing more.
    let ok = unsafe {
        DuplicateHandle(proc, value as usize as HANDLE, GetCurrentProcess(), &mut out, MIRROR_READER_ACCESS, 0, 0)
    };
    let e = io::Error::last_os_error();
    // SAFETY: the process handle opened above.
    unsafe { CloseHandle(proc) };
    if ok == 0 {
        return Err(e);
    }
    Ok(out)
}

/// Why a handle a reader got is no mirror ([`check_mirror_section`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAMirror {
    /// Not a section, or one that cannot be queried (`NtQuerySection`'s
    /// status): `ENODEV`, as Linux's `mmap` of a file that cannot be mapped.
    NotASection(i32),
    /// A section of another size (bytes): `EPROTO`.
    Size(u64),
    /// A section backed by a file or an image, or only reserved
    /// (`SECTION_BASIC_INFORMATION.AllocationAttributes`): `EOPNOTSUPP`. A
    /// file's pages are read in at the access and a failed read is an
    /// in-page error in the reader; a reserved page faults; the mirror is
    /// committed pagefile memory.
    Backing(u32),
}

impl NotAMirror {
    /// The errno the read fails with.
    pub fn errno(self) -> c_int {
        match self {
            NotAMirror::NotASection(_) => crate::ENODEV,
            NotAMirror::Size(_) => crate::EPROTO,
            NotAMirror::Backing(_) => crate::EOPNOTSUPP,
        }
    }
}

/// What a section's `AllocationAttributes` and size make of it: a mirror
/// only if committed pagefile memory (`SEC_COMMIT`, no `SEC_FILE`,
/// `SEC_IMAGE` or `SEC_RESERVE`) of exactly [`mirror_bytes`].
pub fn mirror_section_kind(attributes: u32, size: u64) -> Result<(), NotAMirror> {
    if attributes & (SEC_FILE | SEC_IMAGE | SEC_RESERVE) != 0 || attributes & SEC_COMMIT == 0 {
        return Err(NotAMirror::Backing(attributes));
    }
    if size != mirror_bytes() as u64 {
        return Err(NotAMirror::Size(size));
    }
    Ok(())
}

/// `SECTION_BASIC_INFORMATION` (`NtQuerySection`'s class 0).
#[repr(C)]
#[derive(Default)]
struct SectionBasicInformation {
    base: usize,
    attributes: u32,
    size: i64,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySection(section: HANDLE, class: u32, info: *mut c_void, len: usize, returned: *mut usize) -> i32;
}

/// Whether `section`, a handle a reader got (pushed or pulled), is a mirror:
/// a section ([`NotAMirror::NotASection`] otherwise), of committed pagefile
/// memory and of exactly the mirror's size ([`mirror_section_kind`]). Read
/// with `NtQuerySection` (`SectionBasicInformation`, which needs
/// `SECTION_QUERY`) before the reader maps anything: the VMM is the
/// untrusted side and the handler the more privileged one, so the object
/// the handler maps is never one the VMM chose freely (a file's section
/// whose read fails would stop or end the handler; another object's 0x4 is
/// another right).
fn check_mirror_section(section: HANDLE) -> Result<(), NotAMirror> {
    let mut info = SectionBasicInformation::default();
    let mut got = 0usize;
    // SAFETY: a handle of this process and a structure of the size given.
    let status = unsafe {
        NtQuerySection(section, 0, (&raw mut info).cast(), core::mem::size_of::<SectionBasicInformation>(), &mut got)
    };
    if status < 0 {
        return Err(NotAMirror::NotASection(status));
    }
    mirror_section_kind(info.attributes, u64::try_from(info.size).unwrap_or(u64::MAX))
}

/// Maps a reader's copy of a mirror section and closes the handle, which
/// the view keeps alive. The `userfaultfd` crate's reader calls this on the
/// handle value `OP_MIRROR` ([`serve_mirror`]) duplicated into its process,
/// or on the copy it pulled ([`pull_mirror`]); `size` is the size the reply
/// reported, refused with `EPROTO` (and the handle closed) unless it is the
/// table's size (the macOS twin checks the descriptor's `st_size` the same
/// way). Then the object itself is checked before it is mapped
/// ([`check_mirror_section`]: a section, committed pagefile memory, the
/// mirror's size), refused with [`NotAMirror::errno`] and closed otherwise.
/// The handle is consumed either way; [`unmap_mirror`] releases the view
/// the call returns.
///
/// # Safety
/// `value` must be a handle this process holds (as `serve_mirror`
/// duplicates into the reader, or [`pull_mirror`] returns); it is consumed
/// (closed).
pub unsafe fn map_mirror_handle(value: u64, size: u64) -> io::Result<*const AtomicU64> {
    let section = value as usize as HANDLE;
    let checked = if size == mirror_bytes() as u64 {
        check_mirror_section(section).map_err(|e| io::Error::from_raw_os_error(e.errno()))
    } else {
        Err(io::Error::from_raw_os_error(crate::EPROTO))
    };
    // SAFETY: a mirror section of this process with `SECTION_MAP_READ`.
    let view = checked.and_then(|()| unsafe { map_mirror_read_only(section) });
    // SAFETY: the handle; on success the view keeps the section mapped.
    unsafe { CloseHandle(section) };
    view
}

/// The mirror of userfaultfd `ctx`, held against its release until [`leave`];
/// `None` if it has none (released). The count is raised before the mirror is
/// read, and [`destroy`] takes the mirror away before it waits for the count
/// (SeqCst both): either this reads the mirror gone, or [`destroy`] sees the
/// count and waits for it to fall.
fn enter(ctx: usize) -> Option<&'static [AtomicU64; MAX_WAITERS]> {
    let c = CTXS.get(ctx)?;
    c.users.fetch_add(1, Ordering::SeqCst);
    let m = c.mirror.load(Ordering::SeqCst);
    if m.is_null() {
        c.users.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    // SAFETY: a mapping of `MAX_WAITERS` words, kept until `users` is 0.
    Some(unsafe { &*m.cast::<[AtomicU64; MAX_WAITERS]>() })
}

/// Ends an [`enter`] that returned the mirror.
fn leave(ctx: usize) {
    CTXS[ctx].users.fetch_sub(1, Ordering::SeqCst);
}

/// The waiter mirror of userfaultfd `ctx`, for a reader in this process (the
/// `userfaultfd` crate's object that made it): `MIRROR_WORDS` words, mapped
/// read-write here and read by the reader through this pointer, until the
/// userfaultfd's last user descriptor is closed. A reader in another process
/// gets its own read-only mapping instead (`OP_MIRROR`).
pub fn mirror(ctx: usize) -> Option<*const AtomicU64> {
    let m = CTXS.get(ctx)?.mirror.load(Ordering::SeqCst);
    (!m.is_null()).then_some(m.cast_const())
}

/// Called first in the process's exception handler (`windows_mm::on_exception`)
/// at an access violation, before any of its steps looks, for tests: it
/// holds the handler between the fault and its checks
/// (`test_a_host_access_that_faulted_before_its_fill_runs_again`). An
/// `fn()` as a `usize`, 0 for none.
#[cfg(test)]
static EXCEPTION_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Tests: runs [`EXCEPTION_HOOK`]'s function, if any.
#[cfg(test)]
pub(crate) fn exception_hook() {
    let hook = EXCEPTION_HOOK.load(Ordering::SeqCst);
    if hook != 0 {
        // SAFETY: only `fn()` values are stored.
        unsafe { core::mem::transmute::<usize, fn()>(hook)() };
    }
}

/// This module's step of the process's exception handler
/// (`windows_mm::on_exception`, its first step for an access violation):
/// an access to a chunk being moved waits for the move, and one to a
/// missing registered page queues its fault and waits for its fill
/// ([`fault`]); whether so, and the access runs again. Anything else (not
/// registered, not missing, an access the page's protection denies, a page
/// filled or moved since the access faulted) is left to the handler's next
/// steps.
#[inline(never)]
pub(crate) fn resolve_access(addr: u64, write: bool) -> bool {
    READY.load(Ordering::Acquire) && (is_moving(addr) || is_missing(addr)) && fault(addr, write)
}

/// For a look at a page that is to be decided on whole
/// (`windows_mm::settled_access`): runs `f` with [`LOCK`] held, so that no
/// fill, discard, move (the reclaim moves under its asker's [`LOCK`]),
/// register, unregister, release, `mprotect` or unmapping of registered
/// memory runs during it, and tells `f` whether [`fault`] would resolve an
/// access to `addr` now: its chunk being moved, or a missing registered
/// page whose protection allows the access. Takes no lock the caller may
/// hold: called with none of wick's memory locks held, [`LOCK`] first.
pub(crate) fn with_registrations_still<T>(addr: u64, write: bool, f: impl FnOnce(bool) -> T) -> T {
    let _guard = lock();
    let resolvable = is_moving(addr)
        || find(addr).is_some_and(|(r, page)| {
            r.missing_owner(page).is_some() && !r.denies(page, write)
        });
    f(resolvable)
}

/// Runs `f` with [`LOCK`] held, for a look at several pages that is to be
/// decided on whole and acted on before anything changes them
/// (`windows_mm::with_pages_still`). Takes no lock the caller may hold:
/// called with none of wick's memory locks held, [`LOCK`] first.
pub(crate) fn with_lock_held<T>(f: impl FnOnce() -> T) -> T {
    let _guard = lock();
    f()
}

/// Whether `addr` is in a registered range (the handler's last check:
/// memory that is ours).
pub(crate) fn registered(addr: u64) -> bool {
    READY.load(Ordering::Acquire) && lookup(addr, |_, _| ()).is_some()
}

/// Calls `f(start, len)` for each run of missing registered pages in
/// `[start, start + len)`.
pub fn for_each_missing(start: u64, len: u64, mut f: impl FnMut(u64, u64)) {
    let end = start.saturating_add(len);
    let mut run: Option<u64> = None;
    let mut addr = start - start % PAGE;
    while addr < end {
        let (missing, next) = match find(addr) {
            Some((r, page)) => (r.missing_owner(page).is_some(), addr + PAGE),
            // Unregistered memory holds no missing page: on to the next
            // range (a walk by pages over a span as large as a
            // `MADV_DONTNEED` may name would not end).
            None => {
                let next = RANGES
                    .iter()
                    .map(|r| r.start.load(Ordering::Acquire))
                    .filter(|&s| s > addr)
                    .min()
                    .unwrap_or(end)
                    .min(end);
                (false, next.max(addr + PAGE))
            }
        };
        match (missing, run) {
            (true, None) => run = Some(addr),
            (false, Some(s)) => {
                f(s, addr - s);
                run = None;
            }
            _ => {}
        }
        addr = next;
    }
    if let Some(s) = run {
        f(s, end.min(addr) - s);
    }
}

/// Calls `f(start, len)` for each run of `[addr, addr + len)` of `range`
/// that has memory, in order: all of it, or, in a reserved section, its
/// committed runs (an uncommitted page faults already, and has no
/// protection to change or memory to discard). Allocates nothing.
fn with_memory(range: &Range, addr: u64, len: u64, mut f: impl FnMut(u64, u64)) {
    if !range.reserved.load(Ordering::Acquire) {
        f(addr, len);
        return;
    }
    #[allow(clippy::cast_possible_truncation)]
    crate::windows_mm::for_each_committed_run(addr as usize, len as usize, |s, l| f(s as u64, l as u64));
}

/// Missing pages `[s, s + len)` of `range`, whose alias is at `alias` and
/// which starts at `base`, become ordinary memory: in a reserved section
/// they are pending in the range's record, each resolved at its first
/// access (committed if never filled; zeroed through the alias if filled
/// once and discarded, its commit and charge kept by `discarding`, as Linux
/// gives a zapped page as zeros at its next touch), with the protection
/// `mprotect` gave it, which stays with the memory as a vma's does on
/// Linux; elsewhere zeroed and made accessible now. Allocates nothing (the
/// release runs at the job's limit).
fn release_missing(range: &Range, base: u64, alias: u64, s: u64, len: u64) -> io::Result<()> {
    if range.reserved.load(Ordering::Acquire) {
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::released_pend(range.record.load(Ordering::Acquire), alias as usize, s as usize, len as usize, |at| {
            range.prot((at as u64 - base) / PAGE)
        });
        return Ok(());
    }
    // SAFETY: the alias of registered memory.
    unsafe { ptr::write_bytes((alias + (s - base)) as *mut u8, 0, len as usize) };
    let mut result = Ok(());
    range.by_prot(base, s, len, |r, n, prot| {
        if result.is_ok() {
            result = protect_as(r, n, prot);
        }
    });
    result
}

/// Changes the protection of committed registered memory, a view at a time
/// (`VirtualProtect` stays within one allocation; a reserved section is a
/// view per chunk, `windows_mm::UFFD_CHUNK`).
fn protect(addr: u64, len: u64, accessible: bool) -> io::Result<()> {
    protect_as(addr, len, if accessible { PAGE_READWRITE } else { PAGE_NOACCESS })
}

/// The protection of the page at `addr` now (`VirtualQuery`), 0 if it
/// cannot be read.
fn protection_at(addr: u64) -> PAGE_PROTECTION_FLAGS {
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
        return 0;
    }
    mbi.Protect
}

/// [`protect`] with the protection `prot`.
fn protect_as(addr: u64, len: u64, prot: PAGE_PROTECTION_FLAGS) -> io::Result<()> {
    use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
    let (mut at, end) = (addr as usize, (addr + len) as usize);
    while at < end {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let run = (mbi.BaseAddress as usize + mbi.RegionSize).min(end) - at;
        let mut old = 0;
        // SAFETY: changes the protection of registered memory only.
        if unsafe { VirtualProtect(at as *mut c_void, run, prot, &mut old) } == 0 {
            return Err(io::Error::last_os_error());
        }
        at += run;
    }
    Ok(())
}

/// Removes the socket path a dead process of this pid left at `path`,
/// before this process binds it (`bind` refuses a path that exists with
/// WSAEADDRINUSE: `test_af_unix_paths_and_abstract_addresses_on_record`).
/// Removing it cannot take anything live: the name carries this process's
/// pid, which no other live process has, and a sequence number this process
/// has not used yet (`socket_pair`'s only rises), so nothing of ours listens
/// there, and a file there was left by a dead process of this pid that was
/// killed between its bind and its removal of the path (cdb's quit left
/// `wick-uffd-3332-1.sock` on fc-win, and a later process with pid 3332 was
/// refused its userfaultfd). `DeleteFileW` deletes a symbolic link, not its
/// target (Learn, DeleteFileW: "If the path points to a symbolic link, the
/// symbolic link is deleted, not the target"), and removes no directory, so
/// whoever else may write in the temporary directory (the jail's `tmp`: the
/// jailed processes, the jailer, the user; unjailed, the user's processes)
/// cannot make it delete anything but this name. Microsoft's AF_UNIX
/// guidance asks the same: "DeleteFile (or any other file delete API) should
/// be used to delete the socket file prior to calling bind with the same
/// path" (devblogs.microsoft.com, "AF_UNIX comes to Windows"). A name that
/// is there and cannot be removed fails the userfaultfd, with a line naming
/// it; a second name is never tried in its place.
fn remove_left_path(path: &std::path::Path, wide: &[u16]) -> io::Result<()> {
    // SAFETY: a NUL-terminated path.
    if unsafe { DeleteFileW(wide.as_ptr()) } != 0 {
        std::eprintln!(
            "wick: userfaultfd: removed {}, a socket path a dead process of this pid left",
            path.display()
        );
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.cast_signed()) {
        return Ok(());
    }
    std::eprintln!(
        "wick: userfaultfd: the socket path {} could not be removed before its bind: {e}",
        path.display()
    );
    Err(e)
}

/// A connected pair of `AF_UNIX` stream sockets (Windows has no
/// `socketpair`): a listener on a temporary path, connected to. The path is
/// removed as soon as the connection is made, before it is accepted (a
/// queued connection is accepted without its path:
/// `test_af_unix_paths_and_abstract_addresses_on_record`), so it exists only
/// from the bind to the connect, and a process that dies in that window
/// leaves a path the next process of its pid removes (`remove_left_path`).
/// The accepted end must be this process's own connection: any writer of
/// the temporary directory may connect to the listener while its path
/// exists, and the first connection queued is the one accepted; an end
/// whose peer is another process fails the pair, loudly.
///
/// Not an abstract address (a NUL first in `sun_path`, no file): it has no
/// file and so no DACL, the one control Microsoft names for AF_UNIX ("can
/// be secured by controlling the file (or directory) permissions"), and no
/// namespace scopes it as a network namespace scopes Linux's; any process
/// that guessed the name could be the end accepted. (On 20348 such a bind
/// and listen worked and the connect was refused with WSAEINVAL, with the
/// length delimiting the name as on Linux: the same record.)
fn socket_pair() -> io::Result<(c_int, c_int)> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    wick_wsa_startup();
    let new = || {
        // SAFETY: creates a socket.
        let s = unsafe {
            ws::WSASocketW(
                i32::from(AF_UNIX),
                SOCK_STREAM,
                0,
                ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            )
        };
        if s == INVALID_SOCKET {
            Err(io::Error::from_raw_os_error(
                // SAFETY: plain call.
                unsafe { ws::WSAGetLastError() },
            ))
        } else {
            Ok(s)
        }
    };
    let close = |s: SOCKET| {
        // SAFETY: closes a socket made here.
        unsafe { ws::closesocket(s) };
    };
    let path = std::env::temp_dir().join(std::format!(
        "wick-uffd-{}-{}.sock",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let bytes = path.to_string_lossy().into_owned().into_bytes();
    if bytes.len() >= 108 {
        return Err(errno_err(crate::ENAMETOOLONG));
    }
    let mut addr = [0u8; 110];
    addr[0] = 1; // AF_UNIX
    addr[2..2 + bytes.len()].copy_from_slice(&bytes);
    let addr_len = i32::try_from(addr.len()).unwrap();
    let wide: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str().encode_wide().chain([0]).collect()
    };
    remove_left_path(&path, &wide)?;
    // Whether the path is removed already (at the connect).
    let mut removed = false;
    let listener = new()?;
    // SAFETY: a valid AF_UNIX address.
    let bound = unsafe {
        ws::bind(listener, addr.as_ptr().cast(), addr_len) == 0 && ws::listen(listener, 1) == 0
    };
    if !bound {
        // SAFETY: plain call.
        let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
        close(listener);
        return Err(e);
    }
    let result = new().and_then(|a| {
        // SAFETY: a valid AF_UNIX address.
        if unsafe { ws::connect(a, addr.as_ptr().cast(), addr_len) } != 0 {
            // SAFETY: plain call.
            let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
            close(a);
            return Err(e);
        }
        // The connection is queued on the listener; its path is no longer
        // needed.
        // SAFETY: a NUL-terminated path.
        removed = unsafe { DeleteFileW(wide.as_ptr()) } != 0;
        // SAFETY: accepts the connection just made.
        let b = unsafe { ws::accept(listener, ptr::null_mut(), ptr::null_mut()) };
        if b == INVALID_SOCKET {
            // SAFETY: plain call.
            let e = io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() });
            close(a);
            return Err(e);
        }
        // The accepted end's peer: this process, whose connection it is.
        let (mut pid, mut n) = (0u32, 0u32);
        // SAFETY: a u32 out-buffer, on the socket accepted above.
        let asked = unsafe {
            ws::WSAIoctl(b, ws::SIO_AF_UNIX_GETPEERPID, ptr::null(), 0, (&raw mut pid).cast(), 4, &mut n, ptr::null_mut(), None)
        };
        if asked != 0 || pid != std::process::id() {
            let e = if asked != 0 {
                // SAFETY: plain call.
                io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
            } else {
                errno_err(crate::EPERM)
            };
            std::eprintln!(
                "wick: userfaultfd: the connection accepted on {} is not this process's (its peer: {}): {e}",
                path.display(),
                if asked != 0 { std::string::String::from("not known") } else { std::format!("pid {pid}") }
            );
            close(b);
            close(a);
            return Err(e);
        }
        // Both made, or neither: a refused one is closed already.
        match (adopt(b), adopt(a)) {
            (Some(b), Some(a)) => Ok((b, a)),
            (b, a) => {
                for fd in [b, a].into_iter().flatten() {
                    close(sock(fd));
                }
                Err(errno_err(crate::EINVAL))
            }
        }
    });
    close(listener);
    if !removed {
        // A pair not connected (or a path whose removal at the connect was
        // refused): removed now, as before.
        // SAFETY: a NUL-terminated path.
        unsafe { DeleteFileW(wide.as_ptr()) };
    }
    result
}

/// Creates a userfaultfd. Returns its index and the user's descriptor (the
/// other end stays with the serving thread).
pub fn create(features: u64, nonblocking: bool, cloexec: bool) -> io::Result<(usize, c_int)> {
    // Windows handles are not inherited by the processes this one starts
    // unless asked for: every descriptor here is close-on-exec.
    let _ = cloexec;
    // One descriptor for the user, as Linux's userfaultfd returns: refused
    // past the jail's no-file limit (the serving end is this layer's own).
    crate::wick_nofile::check(1)?;
    init()?;
    let (kernel, user) = socket_pair()?;
    let buf: c_int = 1 << 20;
    // SAFETY: plain socket options on the sockets made above.
    unsafe {
        ws::setsockopt(
            sock(kernel),
            ws::SOL_SOCKET,
            ws::SO_SNDBUF,
            (&raw const buf).cast(),
            4,
        );
        if nonblocking {
            let fl = crate::fcntl(user, crate::F_GETFL);
            crate::fcntl(user, crate::F_SETFL, fl | crate::O_NONBLOCK);
        }
    }
    let _guard = lock();
    let Some(index) = CTXS.iter().position(|c| {
        c.fd.compare_exchange(-1, kernel, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        // SAFETY: closes the sockets created above.
        unsafe {
            ws::closesocket(sock(kernel));
            ws::closesocket(sock(user));
        }
        return Err(errno_err(crate::EMFILE));
    };
    CTXS[index].features.store(features, Ordering::Release);
    // The waiter mirror for this userfaultfd: one page, charged to the job
    // negligibly (the module's "The waiter mirror section" doc). Set before
    // the serving thread starts (it answers `OP_MIRROR` from the section) and
    // before the caller registers memory (a fault then reads the mirror).
    // The mirror and its read-only handle for a reader's pull
    // (`OP_MIRROR_PULL`).
    let made = new_mirror().and_then(|(section, view)| {
        // SAFETY: the section just made; this process's pseudo handle.
        match unsafe { dup_mirror_read_only(section, GetCurrentProcess()) } {
            Ok(pull) => Ok((section, view, pull)),
            Err(e) => {
                // SAFETY: the mirror just made, not in use.
                unsafe {
                    unmap_mirror(view);
                    CloseHandle(section);
                }
                Err(e)
            }
        }
    });
    let (section, view, pull) = match made {
        Ok(m) => m,
        Err(e) => {
            CTXS[index].fd.store(-1, Ordering::Release);
            // SAFETY: closes the sockets created above.
            unsafe {
                ws::closesocket(sock(kernel));
                ws::closesocket(sock(user));
            }
            return Err(e);
        }
    };
    CTXS[index].section.store(section, Ordering::Release);
    CTXS[index].pull.store(pull, Ordering::Release);
    CTXS[index].mirror.store(view, Ordering::Release);
    if let Err(e) = std::thread::Builder::new().name("userfaultfd".into()).spawn(move || serve(index, kernel)) {
        CTXS[index].mirror.store(ptr::null_mut(), Ordering::Release);
        CTXS[index].pull.store(ptr::null_mut(), Ordering::Release);
        CTXS[index].section.store(ptr::null_mut(), Ordering::Release);
        CTXS[index].fd.store(-1, Ordering::Release);
        // SAFETY: the mirror just made and the sockets above, none in use yet.
        unsafe {
            unmap_mirror(view);
            CloseHandle(pull);
            CloseHandle(section);
            ws::closesocket(sock(kernel));
            ws::closesocket(sock(user));
        }
        return Err(e);
    }
    Ok((index, user))
}

/// Registers `[start, start + len)` (page aligned; one whole anonymous
/// private mapping, or pages of a range already registered) with
/// userfaultfd `ctx`. Pages that are not resident are missing from now on;
/// each page keeps the protection `mprotect` gave it, as Linux's register
/// leaves the vma's protection as it is.
///
/// Within a range already registered (its slot is kept until its memory is
/// unmapped: [`Range`]), the pages no userfaultfd has, unregistered or
/// released, are registered with `ctx` ([`register_again`]); every page is
/// checked first, and a page another userfaultfd has makes it `EBUSY` with
/// nothing changed, as Linux checks every vma before it changes one (v6.12
/// fs/userfaultfd.c `userfaultfd_register`: `-EBUSY` at :1363 to :1366, in
/// the loop that ends at :1375, before `userfaultfd_register_range`). A
/// range that only overlaps a registered one, or holds a page of it that
/// was unmapped or mapped over, is `EBUSY` too, where Linux registers the
/// new vma (a stated difference: docs/COMPATIBILITY.md's uffd row).
///
/// The section's view is mapped read-write (`windows_mm::uffd_alias`), and
/// each run of pages that holds memory gets the protection `mprotect` gave
/// it back before the range is published. A run that cannot get it (a
/// `VirtualProtect` refusal on the process's own committed view; a guest
/// does not reach it: the VMM registers its memory at a restore, from its
/// own code) ends the process with a line naming the run, the protection it
/// should have and the one it has, and the error
/// (`test_a_register_that_cannot_protect_a_resident_page_ends_the_process`):
/// returned from, the register would leave the run more open than
/// `mprotect` made it, which no later call undoes. Linux's register changes
/// no page's protection and cannot fail so. The order is not turned (the
/// view mapped closed, each run opened to its protection after the copy,
/// so that a refusal leaves a run narrower): every run that holds memory
/// would need a `VirtualProtect`, read-write ones too, which need none now;
/// a refused one would leave pages that hold memory closed and not missing,
/// whose next access nothing resolves, so the process would end there,
/// later and with no line; and the range's resident pages would be closed,
/// unregistered, from the map to the last opening, where now they are open
/// once mapped.
///
/// On a range not on a reserved section, the missing pages are closed once
/// the range is published; a close that fails (`VirtualProtect` refused)
/// returns its error with the range unregistered whole, as [`unregister`]
/// leaves it, and its slot kept, so the memory registers again
/// ([`unregister_whole_at_a_failed_close`]). Linux's register changes no
/// page's protection and has no such failure.
pub fn register(ctx: usize, start: u64, len: u64) -> io::Result<()> {
    register_ioctls(ctx, start, len).map(|_| ())
}

/// [`register`], returning the ioctls the range takes, as Linux's
/// `uffdio_register.ioctls` (fs/userfaultfd.c, v6.12, :1387 to :1388):
/// [`proto::RANGE_IOCTLS`]. Linux's hugetlb set
/// ([`proto::RANGE_IOCTLS_HUGETLB`], `basic_ioctls` :1371 to :1372) is never
/// the answer here: a huge page mapping is not registered (`EINVAL`).
pub fn register_ioctls(ctx: usize, start: u64, len: u64) -> io::Result<u64> {
    register_range(ctx, start, len).map(|()| proto::RANGE_IOCTLS)
}

/// [`register`]'s work.
fn register_range(ctx: usize, start: u64, len: u64) -> io::Result<()> {
    // The range checked as Linux's register checks it (fs/userfaultfd.c,
    // v6.1, `validate_range` at :1309): page aligned, not empty, within the
    // process's addresses.
    validate_range(start, len).map_err(errno_err)?;
    let end = start + len;
    #[cfg(test)]
    assert_eq!(crate::windows_stacklock::held_here(), 0, "a register under one of this layer's locks");
    // Changes of memory already under way without the lock end first, so
    // that the mappings read below are the ones they left
    // ([`unlocked_change`]); changes that start from now on take LOCK.
    REGISTERING.fetch_add(1, Ordering::SeqCst);
    struct Registering;
    impl Drop for Registering {
        fn drop(&mut self) {
            REGISTERING.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _registering = Registering;
    let mut waited = false;
    loop {
        let n = UNLOCKED_CHANGES.load(Ordering::SeqCst);
        if n == 0 {
            break;
        }
        if !waited {
            waited = true;
            #[cfg(test)]
            tests::REGISTER_WAITS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: the address of a static and of a local of its size; it
        // returns once the value differs from `n`, or spuriously (read
        // again above).
        unsafe { WaitOnAddress((&raw const UNLOCKED_CHANGES).cast(), (&raw const n).cast(), core::mem::size_of::<usize>(), INFINITE) };
    }
    // The memory is moved into its sections below (`windows_mm::uffd_alias`),
    // a placeholder for a moment: claimed against system calls' copies
    // first, as the reclaim's move of a chunk is (`windows_mm::claim_move`):
    // a call already in its copy into or out of it (a block device's read
    // into guest memory, a snapshot's write of it) is waited for, without
    // [`LOCK`], as a fill waits for one ([`wait_and_move`]); one that turns
    // to its copy meanwhile waits for the register. The kernel's copy takes
    // no exception this process could resolve, so a call copying while the
    // pages were read-only or gone would fail or lose its bytes. The memory
    // moved is the whole mapping that holds the range
    // (`windows_mm::uffd_mapping_of`), the range itself if none does (the
    // move refuses it then): the mapping is read again under the lock, and
    // claimed again if it changed meanwhile (an `munmap` or a `MAP_FIXED`
    // that took the lock first).
    if !crate::windows_mm::reserve_discards() {
        return Err(errno_err(crate::ENOMEM));
    }
    #[allow(clippy::cast_possible_truncation)]
    let mapping_of = || crate::windows_mm::uffd_mapping_of(start as usize, len as usize).unwrap_or((start as usize, len as usize));
    let mut claimed = mapping_of();
    let (_claim, _guard) = loop {
        let Some(claim) = crate::windows_mm::claim_move(claimed.0, claimed.1) else {
            return Err(errno_err(crate::ENOMEM));
        };
        claim.wait_for_copies();
        let guard = lock();
        let now = mapping_of();
        if now == claimed {
            break (claim, guard);
        }
        claimed = now;
    };
    let (base, end_of_mapping) = (claimed.0 as u64, (claimed.0 + claimed.1) as u64);
    // No mapping in the range: `ENOMEM` if none lies at or above its start,
    // `EINVAL` if the first lies at or past its end, as Linux's
    // (fs/userfaultfd.c, v6.1, `userfaultfd_register` :1323 to :1330).
    match first_mapped_from(start) {
        None => return Err(errno_err(crate::ENOMEM)),
        Some(at) if at >= end => return Err(errno_err(crate::EINVAL)),
        Some(_) => {}
    }
    // Ranges do not overlap, so at most one holds any of it.
    if let Some(r) = RANGES.iter().find(|r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    }) {
        if start < r.start.load(Ordering::Acquire) || end > r.end.load(Ordering::Acquire) {
            return Err(errno_err(crate::EBUSY));
        }
        return register_again(r, ctx, start, end);
    }
    // The range is made over the whole mapping: its pages from `first` to
    // `last` are registered, the others are in no registration, as the rest
    // of a vma Linux's register splits.
    let pages = (end_of_mapping - base) / PAGE;
    let (first, last) = ((start - base) / PAGE, (end - base) / PAGE);
    let part = |page: u64| page >= first && page < last;
    // The free slot with the least room that fits, else the first free one
    // ([`Range`]): a small range leaves a large slot's arrays to a large one.
    let free = || RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) == 0);
    let Some(range) = free()
        .filter(|r| within(r.missing.load(Ordering::Acquire), pages - 1))
        .min_by_key(|r| capacity_of(r.missing.load(Ordering::Acquire)))
        .or_else(|| free().next())
    else {
        return Err(errno_err(crate::ENOMEM));
    };
    // The record its released pages go to, with its bitmaps, taken now: the
    // release runs at the job's limit and cannot fail.
    #[allow(clippy::cast_possible_truncation)]
    let record = crate::windows_mm::released_reserve(base as usize, (end_of_mapping - base) as usize).map_err(errno_err)?;
    let undo = |e: io::Error| {
        crate::windows_mm::released_unreserve(record);
        e
    };
    // The reclaim's working memory for every chunk registered with this one,
    // reserved now, so that a reclaim at the limit allocates nothing.
    let chunks = usize::try_from((end_of_mapping - base).div_ceil(crate::windows_mm::UFFD_CHUNK as u64)).unwrap_or(usize::MAX);
    reserve_reclaim(registered_chunks().saturating_add(chunks)).map_err(undo)?;
    // Each page's protection, in bits 1 (no read) and 2 (no write) of its
    // byte: the alias's view below is mapped read-write. Read under the
    // lock, which an `mprotect` takes while a register runs. Bit 0, set by
    // the move once the memory is closed to writes (`windows_mm::uffd_alias`),
    // says a page holds memory: in the range, the others are missing;
    // outside it, the others are no one's and pending (below).
    let mut resident = std::vec![0u8; pages as usize];
    #[allow(clippy::cast_possible_truncation)]
    crate::windows_mm::uffd_protections(base as usize, (end_of_mapping - base) as usize, &mut resident);
    // Marked moving from the move to the end of the register: an access
    // that faults on the memory meanwhile (a write to a page the move made
    // read-only, any access while it is a placeholder, a missing page's
    // before its range is published) waits in [`fault`] and runs again once
    // the register is done, as an access to a chunk the reclaim moves does
    // ([`move_chunk`]); a vCPU's waits on [`LOCK`] (`with_registrations_still`).
    let _moving = MovingWindow::open(base, end_of_mapping);
    #[allow(clippy::cast_possible_truncation)]
    let (alias, reserved) =
        crate::windows_mm::uffd_alias(base as usize, (end_of_mapping - base) as usize, &mut resident).map_err(|e| undo(errno_err(e)))?;
    if reserved {
        crate::windows_mm::released_alias(record, alias);
    } else {
        // Its missing pages are zeroed and opened at their release.
        crate::windows_mm::released_unreserve(record);
    }
    let alias = alias as u64;
    // The slot is free, so these stores precede its window: a lookup that
    // reads them reads `start` 0 and goes on, or its `gen` moved since it
    // read the range it had ([`lookup`]). The slot's arrays are reset, or
    // made, here too: every page past the range's is no one's and holds no
    // bit, every page of the part the owner `ctx`'s, with its bits set
    // below, and every other page of the mapping no one's.
    range.record.store(record, Ordering::Release);
    range.reserved.store(reserved, Ordering::Release);
    if within(range.missing.load(Ordering::Acquire), pages - 1) {
        reset_array(range.missing.load(Ordering::Acquire), 1, 0, 0, 0);
        reset_array(range.owner.load(Ordering::Acquire), 8, 0, NONE, NONE);
        reset_array(range.noread.load(Ordering::Acquire), 1, 0, 0, 0);
        reset_array(range.nowrite.load(Ordering::Acquire), 1, 0, 0, 0);
    } else {
        // The old arrays, too small, are kept: a stale reader may hold them.
        let capacity = array_capacity(pages);
        range.missing.store(alloc_array(capacity, 1, 0), Ordering::Release);
        range.owner.store(alloc_array(capacity, 8, NONE), Ordering::Release);
        range.noread.store(alloc_array(capacity, 1, 0), Ordering::Release);
        range.nowrite.store(alloc_array(capacity, 1, 0), Ordering::Release);
    }
    // The bounds the bits below and the protection runs read: the slot is
    // still free (`start` 0).
    range.end.store(end_of_mapping, Ordering::Release);
    range.alias.store(alias, Ordering::Release);
    // The owner before the missing bit (the order [`Range`]'s doc gives).
    for page in first..last {
        range.set_owner(page, owner_of(ctx));
    }
    for page in 0..pages {
        let b = resident[page as usize];
        if b & 1 == 0 && part(page) {
            Range::set(&range.missing, page, true);
        }
        Range::set(&range.noread, page, b & 2 != 0);
        Range::set(&range.nowrite, page, b & 4 != 0);
    }
    // A page outside the range that is not resident is no one's and holds
    // no memory in a reserved section: pending in its record, as a page
    // unregistered while missing is ([`release_missing`]), so its first
    // access commits it, zeroed, with its protection, and charges it. In a
    // section of committed memory it holds its zeros already.
    let outside_missing = |page: u64| resident[page as usize] & 1 == 0 && !part(page);
    if reserved {
        let mut run: Option<u64> = None;
        for page in 0..=pages {
            match (page < pages && outside_missing(page), run) {
                (true, None) => run = Some(page),
                (false, Some(r)) => {
                    #[allow(clippy::cast_possible_truncation)]
                    crate::windows_mm::released_pend(record, alias as usize, (base + r * PAGE) as usize, ((page - r) * PAGE) as usize, |at| {
                        range.prot((at as u64 - base) / PAGE)
                    });
                    run = None;
                }
                _ => {}
            }
        }
    }
    // The pages that hold memory get their protection back, in runs of one
    // protection (the missing ones take it when they are filled, [`fill`];
    // those pending in the record at their first access).
    let mut held: Option<u64> = None;
    for page in 0..=pages {
        let holds = page < pages && (resident[page as usize] & 1 != 0 || (!reserved && outside_missing(page)));
        match (holds, held) {
            (true, None) => held = Some(page),
            (false, Some(h)) => {
                range.by_prot(base, base + h * PAGE, (page - h) * PAGE, |a, n, prot| {
                    if prot == PAGE_READWRITE {
                        return;
                    }
                    #[cfg(test)]
                    let given = if tests::PROTECTION_FAILS.load(Ordering::SeqCst) { Err(tests::refused()) } else { protect_as(a, n, prot) };
                    #[cfg(not(test))]
                    let given = protect_as(a, n, prot);
                    if let Err(e) = given {
                        std::eprintln!(
                            "wick: userfaultfd: a register could not give its pages {a:#x}+{n:#x} the protection {prot:#x} mprotect gave them, which have {:#x} ({e}): they would stay more open than mprotect made them, so the process ends",
                            protection_at(a)
                        );
                        std::process::abort();
                    }
                });
                held = None;
            }
            _ => {}
        }
    }
    // Published: its bounds again, with `start` last, in the slot's window.
    range.changing(|| {
        range.end.store(end_of_mapping, Ordering::Release);
        range.alias.store(alias, Ordering::Release);
        range.start.store(base, Ordering::SeqCst);
    });
    REGISTERED.fetch_add(1, Ordering::AcqRel);
    // Missing pages fault from now on (in a reserved section they are not
    // committed, and fault already).
    if !reserved {
        let mut runs = Vec::new();
        for_each_missing(start, len, |s, l| runs.push((s, l)));
        for (i, &(s, l)) in runs.iter().enumerate() {
            if let Err(e) = close_run(i, s, l) {
                unregister_whole_at_a_failed_close(range, ctx, base, &runs);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// [`register`]'s close of its missing run number `i` (from 0),
/// `[s, s + l)`.
fn close_run(i: usize, s: u64, l: u64) -> io::Result<()> {
    #[cfg(test)]
    if tests::CLOSE_FAILS_AT.load(Ordering::SeqCst) == i + 1 {
        return Err(tests::refused());
    }
    #[cfg(not(test))]
    let _ = i;
    protect(s, l, false)
}

/// [`register`]'s range at `start`, published with userfaultfd `ctx`, after
/// a close of one of its missing runs (`runs`, every one of the range's)
/// failed: the range is unregistered whole, as [`unregister`] leaves it, so
/// that the failed register leaves no registration. Its missing pages,
/// closed or not yet, are zeroed and given the protection `mprotect` gave
/// them ([`release_missing`]), then every page is no one's ([`NONE`]), and
/// the waiters of `ctx` on the range, on a page closed meanwhile, are woken
/// (the access runs again on the opened page). The slot is kept, as an
/// unregister keeps it, so the memory registers again ([`register_again`]):
/// freed, its memory would be the section's view, which [`register`] takes
/// for no anonymous private mapping (`EINVAL`). Under [`LOCK`]. A run that
/// cannot be opened ends the process with a line: it would stay closed, or
/// read as zeros while it is missing, in a range said to be in no
/// registration.
fn unregister_whole_at_a_failed_close(range: &Range, ctx: usize, start: u64, runs: &[(u64, u64)]) {
    let alias = range.alias.load(Ordering::Acquire);
    for &(s, l) in runs {
        #[cfg(test)]
        let opened = if tests::REOPEN_FAILS.load(Ordering::SeqCst) { Err(tests::refused()) } else { release_missing(range, start, alias, s, l) };
        #[cfg(not(test))]
        let opened = release_missing(range, start, alias, s, l);
        if let Err(e) = opened {
            std::eprintln!(
                "wick: userfaultfd: a register could not reopen its missing pages {s:#x}+{l:#x} after a close of one failed ({e}): they would stay closed in memory no userfaultfd has, so the process ends"
            );
            std::process::abort();
        }
    }
    let end = range.end.load(Ordering::Acquire);
    // The missing bit before the owner (the order [`Range`]'s doc gives).
    for page in 0..(end - start) / PAGE {
        Range::set(&range.missing, page, false);
    }
    for page in 0..(end - start) / PAGE {
        range.set_owner(page, NONE);
    }
    wake_ctx(ctx, start, end - start);
}

/// Registers again with `ctx` the pages of `[start, end)` that no
/// userfaultfd has, inside range `r`, whose slot was kept ([`register`];
/// under [`LOCK`]). Every page is checked before any changes: one another
/// userfaultfd has, or no longer the range's memory ([`GONE`]), is `EBUSY`.
/// A page `ctx` has already stays as it is, as Linux's register of a vma
/// already registered with the same context and mode (v6.12
/// mm/userfaultfd.c `userfaultfd_register_range` :1848 to :1853). Each other page gets `ctx` as its owner,
/// then, if it is pending in the range's record (it was missing when it
/// left: never filled, or discarded), it is missing again, still closed,
/// with the protection the record kept for it, and leaves the record
/// (`windows_mm::released_take`); a page not pending holds its memory and
/// keeps the protection it has now. So a page unregistered while missing is
/// missing again, as Linux's page that was never faulted in after the
/// unregister, and a page touched since is not. A range not on a reserved
/// section (only in a process whose exception handler could not be added:
/// `windows_mm::exception_handler`, `uffd_alias`) keeps no record: its
/// missing pages were zeroed and opened when they left ([`release_missing`]),
/// so every page counts as holding memory and none is missing again, where
/// Linux's page unregistered while missing would be
/// (`test_a_register_whose_close_fails_leaves_the_range_in_no_registration`).
fn register_again(r: &'static Range, ctx: usize, start: u64, end: u64) -> io::Result<()> {
    let base = r.start.load(Ordering::Acquire);
    let (first, last) = ((start - base) / PAGE, (end - base) / PAGE);
    let mine = owner_of(ctx);
    if (first..last).any(|page| {
        let o = r.owner_value(page);
        o != mine && o != NONE
    }) {
        return Err(errno_err(crate::EBUSY));
    }
    // The protection each page has now, for those not pending.
    let mut prot = std::vec![0u8; (last - first) as usize];
    #[allow(clippy::cast_possible_truncation)]
    crate::windows_mm::uffd_protections(start as usize, (end - start) as usize, &mut prot);
    let take = |page: u64, pending: Option<PAGE_PROTECTION_FLAGS>| {
        if r.owner(page) == Some(ctx) {
            return;
        }
        // The owner before the missing bit (the order [`Range`]'s doc gives).
        r.set_owner(page, mine);
        let (noread, nowrite) = match pending {
            Some(p) => (p == PAGE_NOACCESS, p != PAGE_READWRITE),
            None => {
                let b = prot[(page - first) as usize];
                (b & 2 != 0, b & 4 != 0)
            }
        };
        Range::set(&r.noread, page, noread);
        Range::set(&r.nowrite, page, nowrite);
        if pending.is_some() {
            Range::set(&r.missing, page, true);
        }
    };
    if r.reserved.load(Ordering::Acquire) {
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::released_take(r.record.load(Ordering::Acquire), start as usize, (end - start) as usize, |at, pending| {
            take((at as u64 - base) / PAGE, pending);
        });
    } else {
        // Not on a reserved section: missing pages were zeroed and opened
        // when they left ([`release_missing`]), so every page holds memory.
        for page in first..last {
            take(page, None);
        }
    }
    Ok(())
}

/// The registered range holding all of `[start, start + len)`, which is
/// checked as Linux's `validate_range` checks it (`EINVAL`), every page of
/// it registered with `ctx`: a page in no registration (unregistered, or its
/// memory unmapped or mapped over) is `ENOENT` for the whole call, as
/// Linux's destination must lie in one registered vma (mm/userfaultfd.c,
/// v6.12, `validate_dst_vma` :34, `uffd_mfill_lock` :113). Not Linux's:
/// another userfaultfd's page is `ENOENT` too, where `validate_dst_vma` asks
/// only that the vma has a userfaultfd, any (a fill through one into the
/// other's memory would wake none of the other's waiters). Pages `ctx`
/// registered again after an unregister are one with the rest, as Linux
/// merges the vma of a register with its neighbours
/// (`userfaultfd_register_range`, its `vma_modify_flags_uffd` at :1860);
/// two ranges are not, where Linux's merged vma takes a fill across both
/// (docs/ARCHITECTURE.md, "The ioctls' checks").
fn range_of(ctx: usize, start: u64, len: u64) -> Result<&'static Range, c_int> {
    validate_range(start, len)?;
    let (range, first) = find(start).ok_or(crate::ENOENT)?;
    if start + len > range.end.load(Ordering::Acquire) || (first..first + len / PAGE).any(|page| range.owner(page) != Some(ctx)) {
        return Err(crate::ENOENT);
    }
    Ok(range)
}

/// Unregisters `[start, start + len)`, as Linux 6.12's
/// `userfaultfd_unregister` (fs/userfaultfd.c): the range is checked as
/// `validate_range` checks it, and must hold a mapping (`EINVAL`, :1443 to
/// :1447). Its registered pages, whichever userfaultfd has them (Linux 6.12
/// does not ask: it skips only vmas with no context, :1500, and clears the
/// rest, :1522), are in no registration after: missing ones become ordinary
/// memory, pending in their range's record ([`release_missing`]), and the
/// waiters of each page's owner in the range are woken (`wake_userfault` of
/// each vma's context, :1509 to :1519). Memory not registered is left as it is. The
/// range's slot is kept ([`Range`]), so its pages register again. Linux 6.17
/// refuses with `EINVAL` an unregister through a context of a vma another
/// context has (fs/userfaultfd.c, v6.17, :1475 to :1480); this is 6.12's.
/// A release that fails (`EIO`: a protection that cannot be given) stops
/// there: the pages before it are unregistered, the rest are as they were.
pub fn unregister(_ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    validate_range(start, len)?;
    let end = start + len;
    let _guard = lock();
    match first_mapped_from(start) {
        Some(at) if at < end => {}
        _ => return Err(crate::EINVAL),
    }
    // The userfaultfds whose pages were taken, a bit each.
    let mut owners = 0u32;
    let mut result = Ok(());
    for r in RANGES.iter() {
        let base = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if base == 0 || start >= e || base >= end || result.is_err() {
            continue;
        }
        let (a, b) = (start.max(base), end.min(e));
        let alias = r.alias.load(Ordering::Acquire);
        // The missing runs, walked in place: a run is reported once the walk
        // is past it, so its bits may change in the call. The missing bit is
        // cleared before the owner (the order [`Range`]'s doc gives).
        let mut stop = b;
        for_each_missing(a, b - a, |x, l| {
            if result.is_err() {
                return;
            }
            // Missing pages may hold discarded data: zeros, as Linux gives.
            result = release_missing(r, base, alias, x, l).map_err(|e| e.raw_os_error().unwrap_or(crate::EIO));
            if result.is_ok() {
                for page in (x - base) / PAGE..(x + l - base) / PAGE {
                    Range::set(&r.missing, page, false);
                }
            } else {
                stop = x;
            }
        });
        for page in (a - base) / PAGE..(stop - base) / PAGE {
            if let Some(o) = r.owner(page) {
                owners |= 1 << o;
                r.set_owner(page, NONE);
            }
        }
    }
    for o in 0..MAX_CTX {
        if owners & (1 << o) != 0 {
            wake_ctx(o, start, len);
        }
    }
    result
}

/// Fills missing pages from `dst` on with `fill(alias_at, len, offset)`,
/// `offset` the bytes from `dst` to the first page given (a fill whose
/// commit was refused in part is given its pages in more than one call):
/// stops at the first page that is present. Returns the byte count; `EEXIST` if the
/// first page is present, `EAGAIN` with the count when only some were filled.
///
/// A reserved section's pages are committed, and charged, first; the job's
/// limit refuses the commit. Refused, the pages that fit are filled, a page
/// at a time, as Linux's copy charges each page as it fills it
/// (v6.1 mm/userfaultfd.c `__mcopy_atomic` :616 to :687, `mcopy_atomic_pte`
/// charging one page), and dead pages are reclaimed for the rest
/// ([`reclaim_for_a_fill`]), as Linux's memory cgroup reclaims before
/// anything else. The chunks the reclaim passed over for system calls in
/// their copy are claimed, so no call turns to its copy on them, the fill
/// lets go of [`LOCK`] and waits for those calls, which end on their own,
/// then takes it again and moves them ([`wait_and_move`]). It goes on where
/// it was, never from the start: its own pages stay filled, and it checks
/// again only what may have changed meanwhile, as Linux's copy finds its
/// destination again after letting go of `mmap_lock` (:561 to :580, `retry`):
/// the destination in no registration is `ENOENT` (:577 to :580), a page
/// filled meanwhile stops the fill there (`EEXIST`, :639), and either
/// answers for the pages filled before, if any (`return copied ? copied :
/// err`, :700, which `userfaultfd_copy` gives as `EAGAIN` with the count).
/// A reclaim that gave something back is followed by the commit again, as
/// Linux's memory cgroup charges again after a reclaim that freed pages
/// (mm/memcontrol.c `try_charge_memcg` :2705 to :2706). Refused still with
/// nothing reclaimable left (a pass that gave nothing back and passed over
/// nothing), or after [`MAX_RECLAIM_RETRIES`] waits in a row that gave
/// nothing back, the bound Linux's memory cgroup puts on reclaims without
/// progress before its out-of-memory kill (:2631, :2714; mm/internal.h :172),
/// the VMM ends, named (`windows_mm::fill_out_of_memory`).
fn fill(
    ctx: usize,
    dst: u64,
    len: u64,
    wake_up: bool,
    mut fill: impl FnMut(*mut u8, usize, usize),
) -> Result<u64, (c_int, u64)> {
    let mut guard = Some(lock());
    let range = range_of(ctx, dst, len).map_err(|e| (e, 0))?;
    let first = (dst - range.start.load(Ordering::Acquire)) / PAGE;
    // A page of the destination in no registration (unregistered, or
    // unmapped or mapped over since): ENOENT before anything, nothing
    // filled, as Linux's destination must lie in one vma this userfaultfd
    // has (v6.1 mm/userfaultfd.c, `find_dst_vma` :38 to :40, a range past
    // the vma's end, and :46 to :47, a vma with no userfaultfd; `-ENOENT`
    // set at :577 before it is called).
    if (first..first + len / PAGE).any(|page| range.owner(page) != Some(ctx)) {
        return Err((crate::ENOENT, 0));
    }
    let pages = len / PAGE;
    // The pages this fill filled, from `dst` on.
    let mut done = 0u64;
    let mut range = range;
    let mut empty_reclaims = 0;
    let mut waited = Waited::default();
    let ended: c_int = loop {
        let base = range.start.load(Ordering::Acquire);
        let alias = range.alias.load(Ordering::Acquire);
        let first = (dst - base) / PAGE;
        let mut n = 0;
        while done + n < pages {
            let page = first + done + n;
            if range.owner(page) != Some(ctx) || !Range::test(&range.missing, page) {
                break;
            }
            n += 1;
        }
        if n == 0 {
            break crate::EEXIST;
        }
        let at = dst + done * PAGE;
        let mut bytes = n * PAGE;
        trace::pages(trace::COMMIT_BEGIN, at, bytes, |_| 0);
        #[allow(clippy::cast_possible_truncation)]
        if range.reserved.load(Ordering::Acquire) && !uffd_commit(at, bytes) {
            // The pages that fit, a page at a time.
            let mut fits = 0;
            while fits < bytes && uffd_commit(at + fits, PAGE) {
                fits += PAGE;
            }
            if fits == 0 {
                // SAFETY: plain call.
                let err = unsafe { GetLastError() };
                let mut freed = reclaim_for_a_fill(bytes as usize, &mut waited.passed).freed;
                let passed = waited.passed.iter().any(Option::is_some);
                if passed {
                    // Let go of the lock for the wait, and look again at
                    // what may have changed once it is taken again.
                    guard = None;
                    let Some((g, r, again)) = wait_and_move(ctx, dst, len, &mut waited) else {
                        break crate::ENOENT;
                    };
                    guard = Some(g);
                    range = again;
                    freed += r.freed;
                }
                if freed > 0 {
                    empty_reclaims = 0;
                    continue;
                }
                // Nothing reclaimable left; or waits that gave nothing back
                // (the chunks filled or moved meanwhile), bounded.
                empty_reclaims += 1;
                if !passed || empty_reclaims > MAX_RECLAIM_RETRIES {
                    #[cfg(test)]
                    if tests::REFUSED_FILL_IS_ENOMEM.load(Ordering::SeqCst) {
                        break crate::ENOMEM;
                    }
                    crate::windows_mm::fill_out_of_memory(dst, len, done * PAGE, err, waited.chunks, waited.us);
                }
                continue;
            }
            bytes = fits;
        }
        trace::pages(trace::COMMIT_END, at, bytes, |_| 0);
        #[cfg(any(test, feature = "wick-test-hooks"))]
        fill_hook();
        trace::pages(trace::CONTENT_BEGIN, at, bytes, |_| 0);
        fill((alias + (at - base)) as *mut u8, bytes as usize, (at - dst) as usize);
        // The first qword of each page as the alias reads it now.
        // SAFETY: the alias of the pages just filled.
        trace::pages(trace::CONTENT_END, at, bytes, |pg| unsafe { ptr::read_volatile((alias + (pg - base)) as *const u64) });
        // Each page with the protection `mprotect` gave it (one filled while
        // `PROT_NONE` stays closed, as Linux's copy fills a page of a
        // `PROT_NONE` vma).
        let mut result = Ok(());
        range.by_prot(base, at, bytes, |r, n, prot| {
            if result.is_ok() {
                result = protect_as(r, n, prot);
            }
            // The first qword of each page as the guest's view reads it now,
            // where its protection lets it be read (u64::MAX where not).
            let opened = result.is_ok() && prot != PAGE_NOACCESS;
            // SAFETY: a page of the range just filled, its protection read.
            trace::pages(trace::OPENED, r, n, |pg| if opened { unsafe { ptr::read_volatile(pg as *const u64) } } else { u64::MAX });
        });
        if let Err(e) = result {
            break e.raw_os_error().unwrap_or(crate::EIO);
        }
        let from = first + done;
        for page in from..from + bytes / PAGE {
            Range::set(&range.missing, page, false);
        }
        trace::pages(trace::MISSING_CLEARED, at, bytes, |_| 0);
        done += bytes / PAGE;
        if done == pages {
            break 0;
        }
    };
    let bytes = done * PAGE;
    // The wake may run without `LOCK`: after an ENOENT from `wait_and_move`
    // the guard was let go for the wait and not taken again. That is in
    // order, as `wake_range` (`UFFDIO_WAKE`) wakes without it too: a wake
    // touches only the waiters' slots and semaphores, and a woken waiter's
    // access runs again, faulting again if its page is still missing (Linux's
    // `wake_userfault` takes no `mmap_lock` either, v6.1 fs/userfaultfd.c
    // :1216).
    if wake_up && bytes > 0 {
        wake_ctx(ctx, dst, bytes);
        trace::pages(trace::WOKEN, dst, bytes, |_| 0);
    }
    drop(guard);
    match (ended, bytes) {
        (0, _) => Ok(bytes),
        (e, 0) => Err((e, 0)),
        (_, n) => Err((crate::EAGAIN, n)),
    }
}

/// The `fn()` a fill calls once, after its pages are committed and before
/// their content is written through the alias ([`fill`]), on the filling
/// thread with [`LOCK`] held; 0 for none, taken as it runs. For the WHP
/// test of an access made in that window
/// (`test_hooks::set_fill_hook`, FILLWINDOW).
#[cfg(any(test, feature = "wick-test-hooks"))]
static FILL_HOOK: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "wick-test-hooks"))]
fn fill_hook() {
    let hook = FILL_HOOK.swap(0, Ordering::SeqCst);
    if hook != 0 {
        // SAFETY: only `fn()` values are stored.
        unsafe { core::mem::transmute::<usize, fn()>(hook)() };
    }
}

/// SWAPTRACE (tests, and kvm-ioctls' WHP tests through
/// `test_hooks::set_trace_clock`): a ring of the steps a registered page
/// goes through, each stamped with a test's clock (a `fetch_add` on it, so
/// the steps, the test's own events and the guest's reads of the clock
/// fall in one order), the thread and the CPU it ran on. Without the
/// `wick-test-hooks` feature (and outside tests) every call is empty and
/// its value is never computed. The WHP backend's kinds and the reader
/// are used through `test_hooks` alone.
#[allow(dead_code)]
pub(crate) mod trace {
    #[cfg(any(test, feature = "wick-test-hooks"))]
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// A discard of registered memory begins: the start, the bytes.
    pub(crate) const DISCARD_BEGIN: u64 = 1;
    /// A page made missing by a discard.
    pub(crate) const MISSING_SET: u64 = 2;
    /// A chunk swapped for a new section at a discard: its view, 1 swapped
    /// or 0 not (refused, or at a range's edge).
    pub(crate) const SWAPPED: u64 = 3;
    /// The discard's end.
    pub(crate) const DISCARD_END: u64 = 4;
    /// An access's fault: the page missing at its lookup (1 a write).
    pub(crate) const FAULT_ENTERED: u64 = 5;
    /// Its record posted; it waits.
    pub(crate) const FAULT_POSTED: u64 = 6;
    /// Its wait over (1: a record was posted), the access to run again.
    pub(crate) const FAULT_LEFT: u64 = 7;
    /// A fill's commit of the page begins, and its end.
    pub(crate) const COMMIT_BEGIN: u64 = 8;
    pub(crate) const COMMIT_END: u64 = 9;
    /// The fill's content written through the alias begins, and its end
    /// (the page's first qword as the alias reads it).
    pub(crate) const CONTENT_BEGIN: u64 = 10;
    pub(crate) const CONTENT_END: u64 = 11;
    /// The page opened through the guest's view (its first qword read
    /// there, `u64::MAX` where its protection does not read).
    pub(crate) const OPENED: u64 = 12;
    /// Its missing bit cleared.
    pub(crate) const MISSING_CLEARED: u64 = 13;
    /// Its waiters woken.
    pub(crate) const WOKEN: u64 = 14;
    /// The WHP backend's: a vCPU's memory access exit at the page (1 a
    /// write), and the vCPU let run again after it (how: kvm-ioctls'
    /// `exit_ring` kinds, 5 committed, 6 another pass).
    pub(crate) const VCPU_EXIT: u64 = 20;
    pub(crate) const VCPU_RERUN: u64 = 21;

    /// The entries kept, the last ones by clock.
    #[cfg(any(test, feature = "wick-test-hooks"))]
    pub(crate) const LEN: usize = 1 << 16;
    /// The address of the test's clock (an `AtomicU64`), 0 for no record.
    #[cfg(any(test, feature = "wick-test-hooks"))]
    pub(crate) static CLOCK: AtomicUsize = AtomicUsize::new(0);
    #[cfg(any(test, feature = "wick-test-hooks"))]
    static RING: [[AtomicU64; 4]; LEN] = [const { [const { AtomicU64::new(0) }; 4] }; LEN];

    /// Keeps a step of `kind` at `addr`; `extra` is asked only while a
    /// record is kept.
    #[cfg_attr(not(any(test, feature = "wick-test-hooks")), allow(unused_variables))]
    #[inline]
    pub(crate) fn note(kind: u64, addr: u64, extra: impl FnOnce() -> u64) {
        #[cfg(any(test, feature = "wick-test-hooks"))]
        {
            let clock = CLOCK.load(Ordering::Relaxed);
            if clock == 0 {
                return;
            }
            let value = extra();
            // SAFETY: plain calls.
            let (tid, cpu) = unsafe {
                (
                    windows_sys::Win32::System::Threading::GetCurrentThreadId(),
                    windows_sys::Win32::System::Threading::GetCurrentProcessorNumber(),
                )
            };
            // SAFETY: the test keeps its clock alive while CLOCK holds it.
            let n = unsafe { &*(clock as *const AtomicU64) }.fetch_add(1, Ordering::SeqCst);
            #[allow(clippy::cast_possible_truncation)]
            let e = &RING[n as usize % LEN];
            e[1].store(kind | u64::from(cpu & 0xff_ffff) << 8 | u64::from(tid) << 32, Ordering::Relaxed);
            e[2].store(addr, Ordering::Relaxed);
            e[3].store(value, Ordering::Relaxed);
            e[0].store(n + 1, Ordering::Release);
        }
    }

    /// [`note`] for each page of `[start, start + len)`, `extra` given the
    /// page.
    #[cfg_attr(not(any(test, feature = "wick-test-hooks")), allow(unused_variables))]
    #[inline]
    pub(crate) fn pages(kind: u64, start: u64, len: u64, extra: impl Fn(u64) -> u64) {
        #[cfg(any(test, feature = "wick-test-hooks"))]
        if CLOCK.load(Ordering::Relaxed) != 0 {
            let mut page = start - start % super::PAGE;
            while page < start + len {
                note(kind, page, || extra(page));
                page += super::PAGE;
            }
        }
    }

    /// The step kept at clock `n`, if it is still there: (kind, CPU,
    /// thread, address, extra).
    #[cfg(any(test, feature = "wick-test-hooks"))]
    pub(crate) fn at(n: u64) -> Option<(u64, u32, u32, u64, u64)> {
        #[allow(clippy::cast_possible_truncation)]
        let e = &RING[n as usize % LEN];
        if e[0].load(Ordering::Acquire) != n + 1 {
            return None;
        }
        let w = e[1].load(Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation)]
        Some((w & 0xff, (w >> 8 & 0xff_ffff) as u32, (w >> 32) as u32, e[2].load(Ordering::Relaxed), e[3].load(Ordering::Relaxed)))
    }
}

/// `windows_mm::uffd_commit` of `[at, at + len)`, a fill's commit of a
/// reserved section's pages. In tests, a commit inside the span
/// `tests::REFUSE_COMMITS` names follows its script first: refused, or
/// made, one step a call.
#[allow(clippy::cast_possible_truncation)]
fn uffd_commit(at: u64, len: u64) -> bool {
    #[cfg(test)]
    if !tests::scripted_commit(at, len) {
        return false;
    }
    crate::windows_mm::uffd_commit(at as usize, len as usize)
}

/// Linux's reclaims in a row that give nothing back before its memory
/// cgroup's out-of-memory kill (v6.1 mm/internal.h :172).
const MAX_RECLAIM_RETRIES: u32 = 16;

/// What a fill's reclaims waited for ([`wait_and_move`]): the chunks claimed,
/// waited for and moved, and the microseconds waited, for its line if it
/// ends the VMM; and the chunks its last pass passed over (at most
/// `windows_mm::FILL_CLAIMS`), the most dead first.
#[derive(Default)]
struct Waited {
    chunks: usize,
    us: u64,
    passed: [Option<Candidate>; crate::windows_mm::FILL_CLAIMS],
}

/// A fill's wait for the chunks its reclaim passed over (`waited.passed`),
/// with [`LOCK`] let go (the caller dropped its guard): each claimed, so no
/// system call turns to its copy on it, the calls in their copy waited for
/// (`windows_mm::Moving::wait_for_copies`: they end on their own, and the
/// claim keeps new ones off), then the lock taken again and each moved if it
/// still holds dead pages. The lock's guard and what the moves gave back;
/// `None` if the destination is in no registration of `ctx` any more
/// (`ENOENT`, as Linux's copy that finds no vma after letting go of
/// `mmap_lock`, v6.1 mm/userfaultfd.c :577 to :580). Allocates nothing: the
/// claims' room is reserved at the register (`windows_mm::reserve_discards`).
fn wait_and_move(ctx: usize, dst: u64, len: u64, waited: &mut Waited) -> Option<(Locked, Reclaimed, &'static Range)> {
    let mut claims: [Option<crate::windows_mm::Moving>; crate::windows_mm::FILL_CLAIMS] = Default::default();
    for (c, d) in claims.iter_mut().zip(waited.passed.iter()) {
        if let Some(d) = d {
            *c = crate::windows_mm::claim_move(d.view, d.len);
        }
    }
    let t = std::time::Instant::now();
    #[cfg(test)]
    tests::FILL_WAITS.fetch_add(1, Ordering::SeqCst);
    for c in claims.iter().flatten() {
        c.wait_for_copies();
    }
    #[cfg(test)]
    tests::FILL_WAITED.fetch_add(1, Ordering::SeqCst);
    waited.us += u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX);
    let guard = lock();
    let range = range_of(ctx, dst, len).ok()?;
    let first = (dst - range.start.load(Ordering::Acquire)) / PAGE;
    if (first..first + len / PAGE).any(|page| range.owner(page) != Some(ctx)) {
        return None;
    }
    let mut r = Reclaimed::default();
    for (c, d) in claims.iter().zip(waited.passed.iter_mut()) {
        if let (Some(_), Some(d)) = (c, d.take()) {
            waited.chunks += 1;
            r.add(ask_the_reclaimer(Ask::Move(d)));
        }
    }
    drop(claims);
    Some((guard, r, range))
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
    fill(ctx, dst, len, wake_up, |to, n, offset| {
        // SAFETY: `to` is the alias of missing pages; `src` per the contract,
        // `offset + n` at most `len`.
        unsafe { ptr::copy_nonoverlapping(src.add(offset), to, n) }
    })
}

/// `UFFDIO_ZEROPAGE`: fills missing pages from `start` on with zeros.
pub fn zeropage(ctx: usize, start: u64, len: u64, wake_up: bool) -> Result<u64, (c_int, u64)> {
    fill(ctx, start, len, wake_up, |to, n, _| {
        // SAFETY: `to` is the alias of missing pages.
        unsafe { ptr::write_bytes(to, 0, n) }
    })
}

/// `UFFDIO_WAKE`: the range is checked as Linux's `validate_range` checks
/// it, and the userfaultfd's waiters in it are woken, whatever memory is
/// there now (fs/userfaultfd.c, v6.1, `userfaultfd_wake` :1673 to :1700:
/// no vma is looked up).
pub fn wake_range(ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    validate_range(start, len)?;
    wake_ctx(ctx, start, len);
    Ok(())
}

/// Linux's `validate_range` (fs/userfaultfd.c, v6.1, :1247 to :1265): a
/// page aligned start, a length of whole pages and not 0, the start not
/// below the lowest address a process maps (Linux: `mmap_min_addr`) and the
/// range below the highest (`task_size`), else `EINVAL`. The two bounds are
/// Windows' own (`GetSystemInfo`, `lpMinimumApplicationAddress` and
/// `lpMaximumApplicationAddress`, the last byte a process may map).
fn validate_range(start: u64, len: u64) -> Result<(), c_int> {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
    // SAFETY: an all-zero SYSTEM_INFO is valid; filled by the call.
    let mut si: SYSTEM_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    unsafe { GetSystemInfo(&mut si) };
    let (low, task_size) = (si.lpMinimumApplicationAddress as u64, si.lpMaximumApplicationAddress as u64 + 1);
    if !start.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) || len == 0 || start < low || start >= task_size || len > task_size - start {
        return Err(crate::EINVAL);
    }
    Ok(())
}

/// `mprotect` of `[start, end)` (page aligned): `rest` makes the change past
/// the registered spans it is given, under [`LOCK`] with the registered
/// pages' own done first ([`mprotect_locked`]), or without the lock when no
/// registered range is in reach and no register under way
/// ([`unlocked_change`]), given no spans then.
pub(crate) fn protecting<T>(
    start: u64,
    end: u64,
    read: bool,
    write: bool,
    wprot: PAGE_PROTECTION_FLAGS,
    rest: impl FnOnce(Result<Vec<(u64, u64)>, c_int>) -> T,
) -> T {
    if let Some(_unlocked) = unlocked_change(|| touches(start, end)) {
        return rest(Ok(Vec::new()));
    }
    let _guard = lock();
    rest(mprotect_locked(start, end, read, write, wprot))
}

/// `mprotect` of the registered pages of `[start, end)` (page aligned) to
/// `prot` (Windows' `wprot`, `mprotect`'s `prot` given as `read`/`write`):
/// each page's protection is kept in its range, and given now to the
/// pages that hold their memory (filled, not missing); a missing page,
/// reserved or closed, takes it when it is filled ([`fill`]), and an access
/// it denies is no userfault ([`fault`]), as Linux's `mprotect` changes the
/// vma's protection and leaves its pages as they are. The registered spans
/// done, for `mprotect` to leave alone; `Err(errno)` if a protection could
/// not be given. Under [`LOCK`], which `mprotect` takes before the region
/// table, as `register` and the fills do.
fn mprotect_locked(start: u64, end: u64, read: bool, write: bool, wprot: PAGE_PROTECTION_FLAGS) -> Result<Vec<(u64, u64)>, c_int> {
    let mut done = Vec::new();
    // The registered pages, and those of them that hold memory, by range.
    let mut live: Vec<(&'static Range, u64, u64, u64)> = Vec::new();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let (a, b) = (start.max(s), end.min(e));
        let (mut tracked_run, mut live_run): (Option<u64>, Option<u64>) = (None, None);
        let mut at = a;
        while at <= b {
            let page = (at - s) / PAGE;
            let tracked = at < b && r.owned(page);
            let holds = tracked && !Range::test(&r.missing, page);
            match (tracked, tracked_run) {
                (true, None) => tracked_run = Some(at),
                (false, Some(t)) => {
                    done.push((t, at - t));
                    tracked_run = None;
                }
                _ => {}
            }
            match (holds, live_run) {
                (true, None) => live_run = Some(at),
                (false, Some(l)) => {
                    live.push((r, s, l, at - l));
                    live_run = None;
                }
                _ => {}
            }
            at += PAGE;
        }
    }
    // All or nothing within the registered pages: the pages with memory get
    // the protection first; if one cannot (a protection the view does not
    // allow, such as execute), those changed get theirs back, from the
    // bitmaps not yet changed, and nothing is changed. Linux changes a vma
    // whole or not at all (mm/mprotect.c, `mprotect_fixup`), and a failure
    // leaves the vmas before it changed: so do the spans `mprotect` does
    // after these.
    for (n, &(_, _, l, len)) in live.iter().enumerate() {
        if protect_as(l, len, wprot).is_err() {
            for &(r, s, l, len) in &live[..n] {
                r.by_prot(s, l, len, |a, k, prot| {
                    let _ = protect_as(a, k, prot);
                });
            }
            return Err(crate::EACCES);
        }
    }
    for &(a, len) in &done {
        let Some((r, _)) = find(a) else { continue };
        let s = r.start.load(Ordering::Acquire);
        for page in (a - s) / PAGE..(a + len - s) / PAGE {
            Range::set(&r.noread, page, !read && !write);
            Range::set(&r.nowrite, page, !write);
        }
    }
    Ok(done)
}

/// Wraps a `MADV_DONTNEED` of `[start, start + len)`: `discard` runs on the
/// memory that is not registered and reports the pieces it reached (all of
/// the mapped memory, or what it reached before an error); the registered
/// pages of those pieces are missing again, their memory discarded, a whole
/// 2 MiB chunk of a reserved section given a new section and its commit and
/// charge given back (`windows_mm::uffd_swap_chunk`), and a remove event is
/// queued for each piece (with `EVENT_REMOVE`). Pages the
/// discard did not reach keep their contents, as on Linux when it stops at
/// an error.
pub fn discarding(start: u64, len: u64, discard: impl FnOnce(&mut Vec<(u64, u64)>) -> c_int) -> c_int {
    let end = start.saturating_add(len);
    let mut done = Vec::new();
    if let Some(_unlocked) = unlocked_change(|| touches(start, end)) {
        let ret = discard(&mut done);
        // Released ranges' pages, no registration in reach.
        released_discard(&done, |_| false);
        return ret;
    }
    let _guard = lock();
    trace::note(trace::DISCARD_BEGIN, start, || len);
    let ret = discard(&mut done);
    // Released ranges' pages: those no registration tracks.
    released_discard(&done, |p| find(p).is_some_and(|(r, page)| r.owned(page)));
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let alias = r.alias.load(Ordering::Acquire);
        for &(a, b) in &done {
            // The range's whole pages inside the piece.
            let (first, last) = ((a.max(s) - s).div_ceil(PAGE), (b.min(e).max(s) - s) / PAGE);
            let mut any = false;
            for page in first..last {
                if r.owned(page) {
                    Range::set(&r.missing, page, true);
                    trace::note(trace::MISSING_SET, s + page * PAGE, || 0);
                    any = true;
                }
            }
            if !any {
                continue;
            }
            let (from, to) = (s + first * PAGE, s + last * PAGE);
            // Whole chunks of a reserved section, all registered: a new
            // section in their place, the old one's commit given back
            // (`windows_mm::uffd_swap_chunk`); they then have no memory for
            // the runs below.
            if r.reserved.load(Ordering::Acquire) {
                let chunk = crate::windows_mm::UFFD_CHUNK as u64 / PAGE;
                let pages = (e - s) / PAGE;
                let mut c = first.div_ceil(chunk) * chunk;
                while c < last {
                    let c_end = (c + chunk).min(pages);
                    if c_end > last {
                        break;
                    }
                    if (c..c_end).all(|p| r.owned(p)) {
                        #[allow(clippy::cast_possible_truncation)]
                        let swapped = crate::windows_mm::uffd_swap_chunk((s + c * PAGE) as usize, ((c_end - c) * PAGE) as usize, (alias + c * PAGE) as usize, (s as usize, e as usize));
                        trace::note(trace::SWAPPED, s + c * PAGE, || u64::from(swapped));
                    }
                    c += chunk;
                }
            }
            for_each_missing(from, to - from, |a, l| with_memory(r, a, l, |a, l| {
                let _ = protect(a, l, false);
                // Filling a missing page writes all of it: its content can go.
                // SAFETY: the alias of registered memory.
                unsafe { DiscardVirtualMemory((alias + (a - s)) as *mut c_void, l as usize) };
                // Its charge stays, as its section page does (a section's
                // page cannot be decommitted: SECTREC-h): the charge pays for
                // the host commit, so that the job and the jailer's count
                // (private commit plus section commit less the charge) agree
                // and neither refuses a VMM whose live memory is under
                // memory.max. Where Linux would uncharge it, this counts it
                // until its chunk is discarded whole (`uffd_swap_chunk`, which
                // gives both back) or unmapped.
            }));
            // A remove event for each run of pages of one owner, to that
            // owner, as Linux posts one for each vma with a context
            // (mm/madvise.c, v6.12, `madvise_dontneed_free` :894, which
            // calls `userfaultfd_remove` for each vma); pages of no
            // userfaultfd have none.
            let mut run: Option<(u64, usize)> = None;
            for page in first..=last {
                let o = if page < last { r.owner(page) } else { None };
                match (o, run) {
                    (Some(c), Some((_, rc))) if c == rc => {}
                    _ => {
                        if let Some((p0, rc)) = run.take() {
                            if CTXS[rc].features.load(Ordering::Acquire) & FEATURE_EVENT_REMOVE != 0 {
                                post(rc, [proto::EVENT_REMOVE, s + p0 * PAGE, s + page * PAGE, 0]);
                            }
                        }
                        run = o.map(|c| (page, c));
                    }
                }
            }
        }
    }
    trace::note(trace::DISCARD_END, start, || len);
    ret
}

/// The pieces a discard made (`done`) where they are released ranges'
/// pages, those `registered` does not track: closed and pending again in
/// their records, or a chunk discarded whole given a new section
/// (`windows_mm::released_discard`), so that they read as zeros, as
/// Linux's anonymous memory does after `MADV_DONTNEED` or `MADV_FREE`.
fn released_discard(done: &[(u64, u64)], registered: impl Fn(u64) -> bool) {
    for &(a, b) in done {
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::released_discard(a as usize, (b - a) as usize, |p| registered(p as u64));
    }
}

/// Releases userfaultfd `ctx`: its pages become ordinary memory, other
/// userfaultfds' pages in the same ranges stay theirs, and every waiter of
/// `ctx` is woken, as when Linux releases a userfaultfd (fs/userfaultfd.c,
/// v6.12, `userfaultfd_release` :856, through mm/userfaultfd.c
/// `userfaultfd_release_all` :1899, which skips a vma of another context at
/// :1922). The ranges' slots are kept ([`Range`]): their pages
/// register again.
fn destroy(ctx: usize) {
    let _guard = lock();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        if s == 0 {
            continue;
        }
        let e = r.end.load(Ordering::Acquire);
        let alias = r.alias.load(Ordering::Acquire);
        let pages = (e - s) / PAGE;
        // Walked in place (no list of the runs: this runs at the job's limit,
        // `test_a_userfaultfd_released_at_the_limit_allocates_nothing`), a
        // run of `ctx`'s missing pages at a time; the missing bit cleared
        // before the owner (the order [`Range`]'s doc gives).
        let mut run: Option<u64> = None;
        for page in 0..=pages {
            let mine = page < pages && r.missing_owner(page) == Some(ctx);
            match (mine, run) {
                (true, None) => run = Some(page),
                (false, Some(f)) => {
                    let _ = release_missing(r, s, alias, s + f * PAGE, (page - f) * PAGE);
                    for p in f..page {
                        Range::set(&r.missing, p, false);
                    }
                    run = None;
                }
                _ => {}
            }
        }
        for page in 0..pages {
            if r.owner(page) == Some(ctx) {
                r.set_owner(page, NONE);
            }
        }
    }
    // The record's pages are published before the waiters wake: a thread
    // that faulted on a missing page runs its access again and finds it
    // pending there. Every waiter of the userfaultfd, wherever it waits
    // (memory unmapped or mapped over since included), as Linux's release
    // wakes its whole queue (fs/userfaultfd.c, v6.1, `userfaultfd_release`
    // :852, a range of length 0 at :910 to :911).
    wake_where(|c, _| c == ctx);
    // Take the mirror away and free it once no thread is using it. A fault or
    // wake mid-[`enter`], or an `OP_MIRROR` in flight, holds `users`; the
    // swaps above are seen by a later `enter` (which then reads the mirror
    // gone), and this drains those already in. The waiters woken above write
    // their word and leave within their own `enter`, so the drain covers them
    // too: the view is unmapped and the section closed after the last reader
    // of them (no write-after-close).
    let section = CTXS[ctx].section.swap(ptr::null_mut(), Ordering::AcqRel);
    let pull = CTXS[ctx].pull.swap(ptr::null_mut(), Ordering::AcqRel);
    let view = CTXS[ctx].mirror.swap(ptr::null_mut(), Ordering::AcqRel);
    while CTXS[ctx].users.load(Ordering::SeqCst) != 0 {
        std::thread::yield_now();
    }
    if !view.is_null() {
        // SAFETY: the mirror view, no longer used.
        unsafe { unmap_mirror(view) };
    }
    if !pull.is_null() {
        // SAFETY: the read-only handle, no longer used. A reader that pulled
        // holds a copy of its own.
        unsafe { CloseHandle(pull) };
    }
    if !section.is_null() {
        // SAFETY: the section handle, no longer used.
        unsafe { CloseHandle(section) };
    }
    let fd = CTXS[ctx].fd.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        // SAFETY: the kernel end owned by the serving thread.
        unsafe { ws::closesocket(sock(fd)) };
    }
}

/// Frees the slot of range `r` (under [`LOCK`]), none of whose pages is
/// the range's memory any more ([`GONE`]): its alias is handed to its
/// chunks' views, which zero pending pages through it, or unmapped
/// (`uffd_unalias`), and its record ends (`released_end`). Its waiters are
/// not woken here.
fn free_range(r: &Range) {
    let (s, e) = (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire));
    r.changing(|| r.start.store(0, Ordering::SeqCst));
    REGISTERED.fetch_sub(1, Ordering::AcqRel);
    give_back(r, s, e);
}

/// The alias and record of range `r`, for `[s, e)`, given back
/// ([`free_range`]).
fn give_back(r: &Range, s: u64, e: u64) {
    let alias = r.alias.swap(0, Ordering::AcqRel);
    let reserved = r.reserved.load(Ordering::Acquire);
    if alias != 0 {
        // A reserved range's kept with its chunks' views, through which
        // their pending pages are zeroed.
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::uffd_unalias(s as usize, (e - s) as usize, alias as usize, reserved, reserved.then(|| r.record.load(Ordering::Acquire)));
    }
    if reserved {
        crate::windows_mm::released_end(r.record.load(Ordering::Acquire));
    }
}

/// Whether every page of range `r` is unmapped or mapped over ([`GONE`]).
fn all_gone(r: &Range) -> bool {
    let pages = (r.end.load(Ordering::Acquire) - r.start.load(Ordering::Acquire)) / PAGE;
    (0..pages).all(|page| r.gone(page))
}

/// The pages of `[from, end)` (page aligned) that are no longer the memory
/// a range registered there (`windows_mm::uffd_pages_gone`: unmapped, or
/// mapped over) leave their range ([`GONE`]), which is freed once none of
/// its pages is its memory ([`free_range`]); the rest stays as it was.
/// Under [`LOCK`].
fn untrack_gone(from: u64, end: u64) {
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::SeqCst);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || from >= e || s >= end {
            continue;
        }
        let mut any = false;
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::uffd_pages_gone(from.max(s) as usize, end.min(e) as usize, |at| {
            let page = (at as u64 - s) / PAGE;
            // The missing bit before the owner (the order [`Range`]'s doc
            // gives).
            Range::set(&r.missing, page, false);
            r.set_owner(page, GONE);
            any = true;
        });
        if any && all_gone(r) {
            free_range(r);
        }
    }
}

/// Wraps `change`, a change of the mapping of `[start, start + len)` that
/// ends what it held: `windows_mm`'s `munmap`, or its `mmap` with
/// `MAP_FIXED`. On Linux the registration belongs to the vma and goes with
/// it in the same step, under the mm's lock: munmap gathers the vmas and
/// unmaps them (mm/vma.c, v6.12, `do_vmi_align_munmap` :1332,
/// `vms_gather_munmap_vmas` :1180, which calls fs/userfaultfd.c
/// `userfaultfd_unmap_prep` at :1267), and `MAP_FIXED` unmaps what it maps
/// over first (mm/mmap.c `__mmap_region` :1361, the same gathering at
/// :1386), so the new memory is in no registration. Here, when the range
/// touches a registered range, [`LOCK`] is taken before the change and held
/// until the pages it took (`windows_mm::uffd_pages_gone`, whatever the
/// change's result) are in no registration ([`untrack_gone`]): no fill,
/// fault's resolution, discard, reclaim or release runs in between, which
/// would take the new memory, or a hole, for the old registration's. A
/// range with no page left registered is freed, its alias with it; a range
/// left with some keeps its slot and its alias, the pages that went
/// untracked (docs/COMPATIBILITY.md, the mem_backend Uffd row, states the
/// memory that holds). A thread waiting on one of the pages waits on, as
/// Linux's: its userfaultfd's wake or release ends the wait
/// ([`wake_range`], [`destroy`]), and its access then runs again on what is
/// there now.
///
/// A change that finds no registered range in its way, while no register
/// is under way, runs without LOCK ([`unlocked_change`]).
///
/// Runs with no lock of this layer held by the caller: the change takes
/// the region table, and LOCK comes before it.
pub fn unmapping<T>(start: u64, len: u64, change: impl FnOnce() -> T) -> T {
    debug_assert!(!HOLDS_LOCK.get(), "munmap or MAP_FIXED under the userfaultfd's LOCK");
    #[cfg(test)]
    assert_eq!(crate::windows_stacklock::held_here(), 0, "munmap or MAP_FIXED under one of this layer's locks");
    let from = start - start % PAGE;
    let end = start.saturating_add(len.div_ceil(PAGE).saturating_mul(PAGE));
    if let Some(_unlocked) = unlocked_change(|| touches(from, end)) {
        return change();
    }
    let _guard = lock();
    let result = change();
    #[cfg(test)]
    tests::unmap_hook(from, end);
    untrack_gone(from, end);
    result
}

/// The first address at or above `start` that a mapping of the process
/// holds (`VirtualQuery`: a region not `MEM_FREE`), if any: where Linux's
/// `mas_find` from `start` finds the first vma.
fn first_mapped_from(start: u64) -> Option<u64> {
    use windows_sys::Win32::System::Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQuery};
    let mut at = start;
    loop {
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; a query.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { VirtualQuery(at as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) } == 0 {
            return None;
        }
        if mbi.State != MEM_FREE {
            return Some(at);
        }
        at = mbi.BaseAddress as u64 + mbi.RegionSize as u64;
    }
}

fn words(buf: &[u8; proto::RECORD]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for (i, v) in w.iter_mut().enumerate() {
        *v = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

/// Receives a `HELLO` and its channel on the kernel end. `None`: the end is
/// closed; `Some(None)`: a record that is not a `HELLO`, ignored.
fn recv_hello(fd: c_int) -> Option<Option<c_int>> {
    let mut buf = [0u8; proto::RECORD];
    if !recv_all(fd, &mut buf) {
        return None;
    }
    if words(&buf)[0] != proto::HELLO {
        return Some(None);
    }
    // SAFETY: plain data; filled below.
    let mut info: WSAPROTOCOL_INFOW = unsafe { core::mem::zeroed() };
    // SAFETY: the structure's bytes, filled by the peer's WSADuplicateSocketW.
    let raw = unsafe {
        core::slice::from_raw_parts_mut(
            (&raw mut info).cast::<u8>(),
            core::mem::size_of::<WSAPROTOCOL_INFOW>(),
        )
    };
    if !recv_all(fd, raw) {
        return None;
    }
    // SAFETY: a socket from the peer's protocol information.
    let s = unsafe {
        ws::WSASocketW(
            ws::FROM_PROTOCOL_INFO,
            ws::FROM_PROTOCOL_INFO,
            ws::FROM_PROTOCOL_INFO,
            &info,
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    Some((s != INVALID_SOCKET).then(|| adopt(s)).flatten())
}

/// The process id at the other end of AF_UNIX socket `fd`
/// (`SIO_AF_UNIX_GETPEERPID`), or `None` if the call fails.
fn peer_pid(fd: c_int) -> Option<u32> {
    let mut pid = 0u32;
    let mut n = 0u32;
    // SAFETY: an output buffer of four bytes for the peer's pid.
    let asked = unsafe {
        ws::WSAIoctl(sock(fd), ws::SIO_AF_UNIX_GETPEERPID, ptr::null(), 0, (&raw mut pid).cast(), 4, &mut n, ptr::null_mut(), None)
    };
    (asked == 0).then_some(pid)
}

/// Serves `OP_MIRROR`, the push: duplicates the ctx's mirror section into the
/// reader's process read-only ([`dup_mirror_read_only`]) and replies with the
/// mirror's size and the duplicate's handle value (valid in the reader).
/// `users` is held across the duplicate, so [`destroy`] does not close the
/// section under it. `-EPERM` when the reader cannot be opened for the
/// duplicate (this VMM is jailed and the reader is not: the reader then
/// pulls, [`serve_mirror_pull`]); `-EINVAL` when there is no mirror (its ctx
/// is being torn down), as a serving thread that predates the mirror answers
/// an unknown request `-EINVAL`.
fn serve_mirror(ctx: usize, fd: c_int) -> [u64; 2] {
    let err = |e: c_int| [(-i64::from(e)).cast_unsigned(), 0];
    let Some(c) = CTXS.get(ctx) else {
        return err(crate::EINVAL);
    };
    c.users.fetch_add(1, Ordering::SeqCst);
    let section = c.section.load(Ordering::SeqCst);
    let reply = if section.is_null() {
        err(crate::EINVAL)
    } else if let Some(pid) = peer_pid(fd) {
        // SAFETY: a pid; a process handle with the one right the dup needs.
        let proc = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
        if proc.is_null() {
            err(crate::EPERM)
        } else {
            // SAFETY: a live section and the reader's process handle.
            let r = match unsafe { dup_mirror_read_only(section, proc) } {
                Ok(h) => [mirror_bytes() as u64, h as usize as u64],
                Err(_) => err(crate::EIO),
            };
            // SAFETY: the process handle opened above.
            unsafe { CloseHandle(proc) };
            r
        }
    } else {
        err(crate::EPERM)
    };
    c.users.fetch_sub(1, Ordering::SeqCst);
    reply
}

/// Serves `OP_MIRROR_PULL`: replies with the mirror's size and the value, in
/// this process, of the ctx's read-only handle of it (`Ctx::pull`), for a
/// reader this process cannot open to take its own copy of
/// ([`pull_mirror`]). The read-write handle is never named. `-EINVAL` when
/// there is no mirror.
fn serve_mirror_pull(ctx: usize) -> [u64; 2] {
    let err = |e: c_int| [(-i64::from(e)).cast_unsigned(), 0];
    let Some(c) = CTXS.get(ctx) else {
        return err(crate::EINVAL);
    };
    let pull = c.pull.load(Ordering::SeqCst);
    if pull.is_null() {
        return err(crate::EINVAL);
    }
    [mirror_bytes() as u64, pull as usize as u64]
}

/// Serves `[OP_COPY, dst, len, mode]`, whose `len` bytes of data follow on
/// `fd`; `None` when the channel closed. The request is checked before the
/// data is read, and the data is read and copied a piece at a time, so a
/// length that names no registered memory costs no memory to refuse; a
/// refused request's data is read and dropped all the same, so the next
/// request is answered as itself. The checks are Linux's `userfaultfd_copy`
/// and `mfill_atomic`'s, in their order (fs/userfaultfd.c and
/// mm/userfaultfd.c, v6.12): the range (`EINVAL`, :1602 to :1604; Linux's
/// check of `src` before it, :1598, has nothing to check here, where the
/// data comes with the request), a mode bit other than
/// [`proto::MODE_DONTWAKE`] and [`proto::MODE_WP`] (`EINVAL`, :1606 to
/// :1608), the registered range (`ENOENT`, `uffd_mfill_lock` :733), then
/// [`proto::MODE_WP`] into a range not registered for write-protect faults,
/// which every range is here (`EINVAL`, :762 to :763). As Linux's
/// `UFFDIO_COPY`, it stops at the first page that is not missing: `EEXIST`
/// if that is the first, else `EAGAIN` with the count copied. The macOS
/// twin's `serve_copy`.
fn serve_copy(ctx: usize, fd: c_int, dst: u64, len: u64, mode: u64) -> Option<Result<u64, (c_int, u64)>> {
    /// The data's pieces: a mebibyte.
    const PIECE: u64 = 1 << 20;
    let wake_up = mode & proto::MODE_DONTWAKE == 0;
    let mut result = check_copy(ctx, dst, len, mode).map(|()| 0).map_err(|e| (e, 0));
    let mut buf = Vec::new();
    let mut done = 0;
    while done < len {
        let n = (len - done).min(PIECE);
        buf.resize(n as usize, 0);
        if !recv_all(fd, &mut buf) {
            return None;
        }
        // Once stopped, the rest of the data is read and dropped.
        if let Ok(copied) = result {
            // SAFETY: `buf` holds `n` bytes.
            result = match unsafe { copy(ctx, buf.as_ptr(), dst + done, n, wake_up) } {
                Ok(m) => Ok(copied + m),
                Err((_, m)) if copied + m > 0 => Err((crate::EAGAIN, copied + m)),
                Err(e) => Err(e),
            };
        }
        done += n;
    }
    Some(result)
}

/// [`serve_copy`]'s checks of `[OP_COPY, dst, len, mode]`, in Linux's order.
fn check_copy(ctx: usize, dst: u64, len: u64, mode: u64) -> Result<(), c_int> {
    validate_range(dst, len)?;
    if mode & !(proto::MODE_DONTWAKE | proto::MODE_WP) != 0 {
        return Err(crate::EINVAL);
    }
    let _guard = lock();
    range_of(ctx, dst, len)?;
    if mode & proto::MODE_WP != 0 {
        return Err(crate::EINVAL);
    }
    Ok(())
}

/// Serves one request from a client channel; false when the channel closed.
fn serve_request(ctx: usize, fd: c_int) -> bool {
    let mut head = [0u8; proto::RECORD];
    if !recv_all(fd, &mut head) {
        return false;
    }
    let [op, a, b, c] = words(&head);
    let to_reply = |r: Result<u64, (c_int, u64)>| match r {
        Ok(n) => [n, n],
        Err((e, n)) => [(-i64::from(e)).cast_unsigned(), n],
    };
    let reply = match op {
        proto::OP_COPY => match serve_copy(ctx, fd, a, b, c) {
            Some(r) => to_reply(r),
            None => return false,
        },
        // Linux's `userfaultfd_zeropage`: the range, then a mode bit other
        // than DONTWAKE, both `EINVAL` (fs/userfaultfd.c, v6.12, :1654 to
        // :1660), then the fill's own checks.
        proto::OP_ZEROPAGE => to_reply(match validate_range(a, b) {
            Ok(()) if c & !proto::MODE_DONTWAKE != 0 => Err((crate::EINVAL, 0)),
            _ => zeropage(ctx, a, b, c & proto::MODE_DONTWAKE == 0),
        }),
        proto::OP_WAKE => to_reply(wake_range(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        proto::OP_REGISTER => to_reply(
            register_ioctls(ctx, a, b).map_err(|e| (e.raw_os_error().unwrap_or(crate::EINVAL), 0)),
        ),
        proto::OP_UNREGISTER => to_reply(unregister(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        proto::OP_MIRROR => serve_mirror(ctx, fd),
        proto::OP_MIRROR_PULL => serve_mirror_pull(ctx),
        _ => to_reply(Err((crate::EINVAL, 0))),
    };
    let mut out = [0u8; proto::RECORD];
    out[..8].copy_from_slice(&reply[0].to_le_bytes());
    out[8..16].copy_from_slice(&reply[1].to_le_bytes());
    send_all(fd, &out)
}

/// The serving thread of userfaultfd `ctx`: accepts request channels sent on
/// the kernel end and serves them. Ends when every user descriptor is closed.
fn serve(ctx: usize, kernel: c_int) {
    #[cfg(test)]
    tests::KIND.with(|k| k.set(tests::SERVE));
    let mut clients: Vec<c_int> = Vec::new();
    loop {
        let mut fds: Vec<WSAPOLLFD> = core::iter::once(kernel)
            .chain(clients.iter().copied())
            .map(|fd| WSAPOLLFD {
                fd: sock(fd),
                events: POLLRDNORM,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is a valid array.
        let n = unsafe { ws::WSAPoll(fds.as_mut_ptr(), u32::try_from(fds.len()).unwrap(), -1) };
        if n == SOCKET_ERROR {
            break;
        }
        let ready = POLLRDNORM | POLLHUP | POLLERR;
        if fds[0].revents & ready != 0 {
            match recv_hello(kernel) {
                None => break,
                Some(Some(client)) => clients.push(client),
                Some(None) => {}
            }
        }
        let mut closed = Vec::new();
        for p in &fds[1..] {
            if p.revents & ready != 0 && !serve_request(ctx, to_fd(p.fd)) {
                closed.push(to_fd(p.fd));
            }
        }
        for fd in closed {
            clients.retain(|c| *c != fd);
            // SAFETY: a client channel received above.
            unsafe { ws::closesocket(sock(fd)) };
        }
    }
    for fd in clients {
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(fd)) };
    }
    destroy(ctx);
}

/// Faults in the missing registered pages of `[addr, addr + len)`, as the
/// Linux kernel does when a system call copies to or from them (`write`: the
/// call writes the memory). Returns whether any page was missing.
pub fn prefault(addr: u64, len: u64, write: bool) -> bool {
    // Lazy memory too: a system call fails on pages not committed (the
    // kernel's copy takes no exception this process could resolve).
    #[allow(clippy::cast_possible_truncation)]
    crate::windows_mm::prefault_lazy(addr as usize, len as usize);
    prefault_registered(addr, len, write)
}

/// [`prefault`] of the registered pages alone: a write that takes the lazy
/// memory of its buffer as it is (`windows_fd`'s, which reads untouched lazy
/// pages as zeros without committing them) still has the missing pages of
/// a userfaultfd's range filled first, as Linux's copy faults them.
pub fn prefault_registered(addr: u64, len: u64, write: bool) -> bool {
    if REGISTERED.load(Ordering::Acquire) == 0 || len == 0 {
        return false;
    }
    let end = addr.saturating_add(len);
    let mut page = addr - addr % PAGE;
    let mut any = false;
    while page < end {
        // The first byte of the buffer in this page.
        let at = page.max(addr);
        if is_missing(at) && fault(at, write) {
            any = true;
        }
        page += PAGE;
    }
    any
}

/// Whether any memory is registered: the I/O paths skip [`prefault`] when
/// none is.
pub fn active() -> bool {
    REGISTERED.load(Ordering::Acquire) != 0
}

/// What a reclaim did ([`reclaim_at_touch`], [`reclaim_for_a_fill`]): the
/// chunks it moved, the live pages it copied, the bytes of dead pages it
/// gave back (their section commit and their charge), and the chunks it
/// passed over for a system call in flight on them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reclaimed {
    pub chunks: usize,
    pub copied: usize,
    pub freed: usize,
    pub skipped: usize,
}

impl Reclaimed {
    fn add(&mut self, o: Reclaimed) {
        self.chunks += o.chunks;
        self.copied += o.copied;
        self.freed += o.freed;
    }
}

/// A chunk with dead pages ([`find_candidates`]): its guest view, its
/// length, its alias, and the bytes of its dead pages.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    view: usize,
    len: usize,
    alias: usize,
    dead: usize,
}

/// The reclaim's working memory, reserved when a range is registered
/// ([`reserve_reclaim`]) for every chunk registered then, so that a reclaim
/// allocates nothing: it runs when the job has refused commit, where a heap
/// that must grow would end the process instead (Linux's reclaim takes no
/// memory on that path either; `test_a_reclaim_allocates_nothing`).
/// `CANDIDATES` is a reclaim's list, under [`LOCK`]; `TOUCH_SKIPPED` the
/// chunks a touch's reclaim passed over and waits for, under its own lock,
/// which one touch's wait holds ([`reclaim_at_touch`]); `FILL_SKIPPED` a
/// fill's.
static CANDIDATES: ProbedMutex<Vec<Candidate>> = ProbedMutex::new("CANDIDATES", Vec::new());
static TOUCH_SKIPPED: ProbedMutex<Vec<Candidate>> = ProbedMutex::new("TOUCH_SKIPPED", Vec::new());
/// The chunks a fill's reclaim passed over, at most
/// `windows_mm::FILL_CLAIMS`, under [`LOCK`] ([`reclaim_for_a_fill`]).
static FILL_SKIPPED: ProbedMutex<Vec<Candidate>> = ProbedMutex::new("FILL_SKIPPED", Vec::new());

/// Reserves the reclaim's working memory for `chunks` chunks registered at
/// once ([`CANDIDATES`], [`TOUCH_SKIPPED`]) and room for its discard guards
/// (`windows_mm::reserve_discards`): `ENOMEM` if it cannot be had, as a
/// registration whose memory cannot be charged is refused.
fn reserve_reclaim(chunks: usize) -> io::Result<()> {
    for (list, want) in [(&CANDIDATES, chunks), (&TOUCH_SKIPPED, chunks), (&FILL_SKIPPED, crate::windows_mm::FILL_CLAIMS)] {
        let mut l = list.lock().unwrap();
        if l.capacity() < want {
            let more = want - l.len();
            crate::wick_alloc::fallible(|| l.try_reserve_exact(more)).map_err(|_| errno_err(crate::ENOMEM))?;
        }
    }
    if !crate::windows_mm::reserve_discards() {
        return Err(errno_err(crate::ENOMEM));
    }
    start_the_reclaimer()
}

/// The reclaim's own thread's stack, committed whole when it is made
/// (`CreateThread` without `STACK_SIZE_PARAM_IS_A_RESERVATION` takes the
/// size as the commit: Learn, CreateThread, `dwStackSize`), so that the
/// reclaim never grows a stack at the limit, where a stack that must grow
/// ends the process with `STATUS_STACK_OVERFLOW`
/// (`test_a_stack_that_grows_at_the_limit_on_record`). Learn, CreateThread:
/// "If this flag is not specified, dwStackSize specifies the commit size";
/// the record test reads the stack's committed region with `VirtualQuery`
/// at the thread's start. At least four times the deepest a reclaim took on
/// record, rounded up: 8592 bytes, a fill's and a touch's with no room
/// left, a debug build on Windows Server 2022 20348
/// (`test_the_reclaimers_stack_on_record`, which fails past a quarter).
const RECLAIMER_STACK: usize = 64 << 10;

/// A reclaim asked of [`reclaimer`], by a thread that holds [`LOCK`] for it
/// and waits for the answer: a fill's pass ([`reclaim_for_a_fill`]) or a
/// touch's ([`reclaim_at_touch`]), each with the list of the chunks it
/// passes over, or one chunk's move.
#[derive(Clone, Copy)]
enum Ask {
    None,
    Fill(usize, *mut Vec<Candidate>),
    Touch(usize, *mut Vec<Candidate>),
    Move(Candidate),
    /// For `test_an_ask_of_a_reclaimer_that_has_ended_aborts`: the
    /// reclaimer returns, its thread ends.
    #[cfg(test)]
    End,
}

/// The request and its answer, between a thread that asks and [`reclaimer`].
struct Mailbox {
    ask: Ask,
    answer: Reclaimed,
    /// For `test_a_reclaim_allocates_nothing`: the reclaimer counts its
    /// allocations while it answers, and gives the count back.
    #[cfg(test)]
    count: bool,
    #[cfg(test)]
    allocations: u64,
}

// SAFETY: the list pointer in `Ask::Fill` and `Ask::Touch` is used only by the reclaimer
// while the thread that owns it waits for the answer.
unsafe impl Send for Mailbox {}

static MAILBOX: ProbedMutex<Mailbox> = ProbedMutex::new("MAILBOX", Mailbox {
    ask: Ask::None,
    answer: Reclaimed { chunks: 0, copied: 0, freed: 0, skipped: 0 },
    #[cfg(test)]
    count: false,
    #[cfg(test)]
    allocations: 0,
});
/// The events a request is made and answered with (auto-reset), and
/// whether [`reclaimer`] runs.
static ASKED: AtomicUsize = AtomicUsize::new(0);
static ANSWERED: AtomicUsize = AtomicUsize::new(0);
static RECLAIMER: Once = Once::new();
static RECLAIMER_RUNS: AtomicBool = AtomicBool::new(false);
/// [`reclaimer`]'s thread handle, which is signalled if it ends.
static RECLAIMER_THREAD: AtomicUsize = AtomicUsize::new(0);

/// Starts [`reclaimer`] once, at the first registration: `ENOMEM` if its
/// stack's commit or its events cannot be had, as a registration whose
/// reclaim could not run is refused.
fn start_the_reclaimer() -> io::Result<()> {
    use windows_sys::Win32::System::Threading::{CreateEventW, CreateThread};
    RECLAIMER.call_once(|| {
        // SAFETY: unnamed auto-reset events, not signalled.
        let (asked, answered) = unsafe { (CreateEventW(ptr::null(), 0, 0, ptr::null()), CreateEventW(ptr::null(), 0, 0, ptr::null())) };
        if asked.is_null() || answered.is_null() {
            return;
        }
        ASKED.store(asked as usize, Ordering::Release);
        ANSWERED.store(answered as usize, Ordering::Release);
        // SAFETY: a thread of ours that runs for the process; its stack's
        // size is its commit.
        let t = unsafe { CreateThread(ptr::null(), RECLAIMER_STACK, Some(reclaimer), ptr::null(), 0, ptr::null_mut()) };
        if !t.is_null() {
            // Kept for the process: an asker waits on it too.
            RECLAIMER_THREAD.store(t as usize, Ordering::Release);
            RECLAIMER_RUNS.store(true, Ordering::Release);
        }
    });
    if RECLAIMER_RUNS.load(Ordering::Acquire) { Ok(()) } else { Err(errno_err(crate::ENOMEM)) }
}

/// The reclaim's thread: each request answered on a stack committed whole
/// ([`RECLAIMER_STACK`]), under the [`LOCK`] its asker holds for it.
unsafe extern "system" fn reclaimer(_: *mut c_void) -> u32 {
    use windows_sys::Win32::System::Threading::{INFINITE, SetEvent, WaitForSingleObject};
    #[cfg(test)]
    paint_the_stack();
    #[cfg(test)]
    tests::KIND.with(|k| k.set(tests::RECLAIMER));
    // The asker holds the lock: a reclaim a fault here would start takes
    // nothing ([`reclaim_at_touch`]).
    HOLDS_LOCK.set(true);
    // A stack page refused here is never waited for: the wait would be for
    // this thread ([`on_the_reclaimer`]).
    ON_THE_RECLAIMER.set(true);
    loop {
        // SAFETY: our event.
        unsafe { WaitForSingleObject(ASKED.load(Ordering::Acquire) as HANDLE, INFINITE) };
        let mut m = MAILBOX.lock().unwrap();
        #[cfg(test)]
        tests::COUNTING_ALLOCATIONS.with(|c| c.set(m.count));
        #[cfg(test)]
        tests::ALLOCATIONS.with(|a| a.set(0));
        reclaim_progress(true);
        m.answer = match m.ask {
            Ask::None => Reclaimed::default(),
            // SAFETY: as below.
            Ask::Fill(need, skipped) => fill_pass(need, unsafe { skipped.as_mut() }),
            // SAFETY: the asker's list, which it does not touch until the
            // answer (`Mailbox`).
            Ask::Touch(need, skipped) => touch_pass(need, unsafe { skipped.as_mut() }),
            Ask::Move(d) => move_again(&d),
            #[cfg(test)]
            Ask::End => {
                reclaim_progress(false);
                return 0;
            }
        };
        m.ask = Ask::None;
        reclaim_progress(false);
        #[cfg(test)]
        {
            tests::COUNTING_ALLOCATIONS.with(|c| c.set(false));
            m.allocations = tests::ALLOCATIONS.with(core::cell::Cell::get);
        }
        drop(m);
        // SAFETY: our event.
        unsafe { SetEvent(ANSWERED.load(Ordering::Acquire) as HANDLE) };
    }
}

std::thread_local! {
    /// This thread is [`reclaimer`]'s.
    static ON_THE_RECLAIMER: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Whether the calling thread is the reclaim's own ([`reclaimer`]), which
/// makes every move: its stack is committed whole at its start
/// ([`RECLAIMER_STACK`], `test_the_reclaimers_stack_on_record`), and a
/// stack page refused on it is never waited for
/// (`windows_mm::stack_page_after_the_reclaim`), as the wait would be for
/// itself (`test_the_reclaimers_own_stack_page_is_not_waited_for`).
pub(crate) fn on_the_reclaimer() -> bool {
    ON_THE_RECLAIMER.get()
}

/// The reclaim's progress, for a thread whose stack page the job's limit
/// refused while a reclaim runs (`windows_mm::stack_page_after_the_reclaim`):
/// a count of its steps, shifted left once, and in the low bit whether
/// [`reclaimer`] is answering an ask. The count goes up when an answer
/// begins, at the end of each move ([`move_chunk`], made or not) and when
/// the answer is given, so a value read with the bit set changes at the
/// next move's end or the answer's, whichever comes first: where a moved
/// chunk's dead pages have been given back, or the reclaim is over. Only
/// [`reclaimer`] writes it.
static RECLAIM_STATE: AtomicU64 = AtomicU64::new(0);

/// A step of the reclaim ([`RECLAIM_STATE`]); `busy`, an answer under way.
fn reclaim_progress(busy: bool) {
    let s = RECLAIM_STATE.load(Ordering::Relaxed);
    RECLAIM_STATE.store((((s >> 1) + 1) << 1) | u64::from(busy), Ordering::Release);
}

/// The reclaim's state ([`RECLAIM_STATE`]) if an answer is under way, for
/// [`wait_for_the_reclaim`]; `None` if none is.
pub(crate) fn reclaim_in_flight() -> Option<u64> {
    let s = RECLAIM_STATE.load(Ordering::Acquire);
    (s & 1 == 1).then_some(s)
}

/// Waits until the reclaim's state is no longer `seen` (a move ended or the
/// answer was given), or for `bound` at most: whether it changed, and the
/// microseconds waited. Yields between its reads (`SwitchToThread`), as an
/// access to a moving chunk waits ([`fault`]); allocates nothing, takes no
/// lock, and its stack is two shallow frames (STACKWAIT).
pub(crate) fn wait_for_the_reclaim(seen: u64, bound: std::time::Duration) -> (bool, u64) {
    let t = std::time::Instant::now();
    let ended = loop {
        if RECLAIM_STATE.load(Ordering::Acquire) != seen {
            break true;
        }
        if t.elapsed() >= bound {
            break false;
        }
        std::thread::yield_now();
    };
    (ended, u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX))
}

/// Asks [`reclaimer`] for `ask` and waits for the answer; the caller holds
/// [`LOCK`] (which so serialises the asks). Shallow on the caller's stack:
/// a lock, two event calls. The wait is for the answer or the reclaimer's
/// end, which would leave the asker waiting for good: the process is
/// aborted then, named. The reclaimer does not return (a panic there
/// aborts the process, `panic = "abort"`, and a panic would not unwind
/// out of an `extern "system"` function either), so that end is the test's
/// only (`test_an_ask_of_a_reclaimer_that_has_ended_aborts`).
fn ask_the_reclaimer(ask: Ask) -> Reclaimed {
    use windows_sys::Win32::System::Threading::{INFINITE, SetEvent, WaitForMultipleObjects};
    RECLAIM_ASKS.fetch_add(1, Ordering::Relaxed);
    if !RECLAIMER_RUNS.load(Ordering::Acquire) {
        return Reclaimed::default();
    }
    {
        let mut m = MAILBOX.lock().unwrap();
        m.ask = ask;
        #[cfg(test)]
        {
            m.count = tests::COUNTING_ALLOCATIONS.with(core::cell::Cell::get);
        }
    }
    let both = [ANSWERED.load(Ordering::Acquire) as HANDLE, RECLAIMER_THREAD.load(Ordering::Acquire) as HANDLE];
    // SAFETY: our event and thread handles.
    let woken = unsafe {
        SetEvent(ASKED.load(Ordering::Acquire) as HANDLE);
        WaitForMultipleObjects(2, both.as_ptr(), 0, INFINITE)
    };
    if woken != 0 {
        crate::windows_mm::say_at_the_limit(format_args!(
            "wick: reclaim: the reclaim's thread has ended (wait {woken:#x}), so no reclaim can be answered: aborting"
        ));
        std::process::abort();
    }
    let m = MAILBOX.lock().unwrap();
    #[cfg(test)]
    tests::ALLOCATIONS.with(|a| a.set(a.get() + m.allocations));
    m.answer
}

/// The reclaimer's stack, painted below where it starts, for the record of
/// how deep a reclaim goes (`test_the_reclaimers_stack_on_record`).
#[cfg(test)]
const PAINT: u8 = 0xA5;
#[cfg(test)]
static PAINTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static STACK_BASE: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
#[inline(never)]
fn paint_the_stack() {
    let (base, limit): (usize, usize);
    // SAFETY: reads of the thread's own TEB.
    unsafe { core::arch::asm!("mov {0}, gs:[0x8]", "mov {1}, gs:[0x10]", out(reg) base, out(reg) limit, options(nostack, readonly, preserves_flags)) };
    let here = core::hint::black_box(&base) as *const usize as usize;
    let top = (here - 4096) & !15;
    // SAFETY: the thread's own committed stack below its frames.
    unsafe { core::ptr::write_bytes(limit as *mut u8, PAINT, top - limit) };
    PAINTED.store(limit, Ordering::Release);
    STACK_BASE.store(base, Ordering::Release);
    // What `VirtualQuery` says is committed from the thread's lowest
    // committed page up, before it is used.
    // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
    let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    let n = unsafe { windows_sys::Win32::System::Memory::VirtualQuery(limit as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) };
    let committed = if n != 0 && mbi.State == windows_sys::Win32::System::Memory::MEM_COMMIT { mbi.RegionSize } else { 0 };
    STACK_QUERIED.store(committed, Ordering::Release);
}

/// The reclaimer's stack committed at its start, by `VirtualQuery`.
#[cfg(test)]
static STACK_QUERIED: AtomicUsize = AtomicUsize::new(0);

/// What `VirtualQuery` found committed of the reclaimer's stack at its
/// start (`test_the_reclaimers_stack_on_record`).
#[cfg(test)]
pub(crate) fn reclaimer_stack_queried() -> usize {
    STACK_QUERIED.load(Ordering::Acquire)
}

/// The most of the reclaimer's stack used so far, and its committed size
/// (`test_the_reclaimers_stack_on_record`).
#[cfg(test)]
pub(crate) fn reclaimer_stack() -> (usize, usize) {
    let (limit, base) = (PAINTED.load(Ordering::Acquire), STACK_BASE.load(Ordering::Acquire));
    if limit == 0 {
        return (0, 0);
    }
    let mut at = limit;
    // SAFETY: the reclaimer's committed stack, read while it waits.
    while at < base && unsafe { core::ptr::read_volatile(at as *const u8) } == PAINT {
        at += 1;
    }
    (base - at, base - limit)
}

/// The chunks (`windows_mm::UFFD_CHUNK`) of the registered ranges, as
/// [`reserve_reclaim`] counts them: whole and part chunks of each range.
fn registered_chunks() -> usize {
    let chunk = crate::windows_mm::UFFD_CHUNK as u64;
    RANGES
        .iter()
        .filter(|r| r.start.load(Ordering::Acquire) != 0)
        .map(|r| usize::try_from((r.end.load(Ordering::Acquire) - r.start.load(Ordering::Acquire)).div_ceil(chunk)).unwrap_or(usize::MAX))
        .sum()
}

/// Whether the page at `at` of `range` (whose first page is at `s`) is
/// missing: for a committed page, dead.
fn missing_at(range: &Range, s: u64, at: usize) -> bool {
    Range::test(&range.missing, (at as u64 - s) / PAGE)
}

/// The bytes of the dead pages of `[view, view + len)` in `range` (whose
/// first page is at `s`): committed and missing.
fn dead_bytes(range: &Range, s: u64, view: usize, len: usize) -> usize {
    let mut dead = 0;
    crate::windows_mm::for_each_committed(view, len, |a, n| {
        dead += (a..a + n).step_by(PAGE as usize).filter(|&at| missing_at(range, s, at)).count() * PAGE as usize;
    });
    dead
}

/// Fills `out` (cleared first, never grown: the chunks past its capacity are
/// left out) with the chunks of reserved ranges, every page registered,
/// that hold dead pages: missing (discarded) but committed, a section page
/// and a charge each (a chunk discarded whole has none:
/// `windows_mm::uffd_swap_chunk`), the most dead first; a chunk with none
/// is never one. Under [`LOCK`].
fn find_candidates(out: &mut Vec<Candidate>) {
    out.clear();
    let chunk = crate::windows_mm::UFFD_CHUNK as u64 / PAGE;
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        if s == 0 || !r.reserved.load(Ordering::Acquire) {
            continue;
        }
        let (e, alias) = (r.end.load(Ordering::Acquire), r.alias.load(Ordering::Acquire));
        let pages = (e - s) / PAGE;
        for c in (0..pages).step_by(chunk as usize) {
            let c_end = (c + chunk).min(pages);
            if !(c..c_end).all(|p| r.owned(p)) {
                continue;
            }
            // A move maps the new section's view read-write: a live page
            // `mprotect` closed (`PROT_NONE`, `PROT_READ`) would be open
            // until its protection is given back, so its chunk is not moved.
            if (c..c_end).any(|p| !Range::test(&r.missing, p) && r.prot(p) != PAGE_READWRITE) {
                continue;
            }
            #[allow(clippy::cast_possible_truncation)]
            let (view, len) = ((s + c * PAGE) as usize, ((c_end - c) * PAGE) as usize);
            let dead = dead_bytes(r, s, view, len);
            if dead > 0 && out.len() < out.capacity() {
                #[allow(clippy::cast_possible_truncation)]
                out.push(Candidate { view, len, alias: (alias + c * PAGE) as usize, dead });
            }
        }
    }
    // Unstable: a stable sort takes a buffer.
    out.sort_unstable_by_key(|d| core::cmp::Reverse(d.dead));
}

/// The range a chunk's view is in, and that range's first page.
fn range_of_view(view: usize) -> Option<(&'static Range, u64)> {
    find(view as u64).map(|(r, _)| (r, r.start.load(Ordering::Acquire)))
}

/// The moves made, for the record (RECLAIMREC): each one's live pages
/// copied (high 32 bits) and its time in microseconds (low 32), the first
/// [`MOVES_KEPT`]; fixed, as the reclaim allocates nothing.
const MOVES_KEPT: usize = 4096;
static MOVES: [AtomicU64; MOVES_KEPT] = [const { AtomicU64::new(0) }; MOVES_KEPT];
static MOVES_MADE: AtomicUsize = AtomicUsize::new(0);
/// The accesses that waited for a move ([`fault`]), and how long in all.
static MOVE_WAITS: AtomicU64 = AtomicU64::new(0);
static MOVE_WAITED_US: AtomicU64 = AtomicU64::new(0);
/// The reclaims asked for (a fill or a touch refused at the job's limit),
/// the candidate chunks their passes found, and the view of the chunk moved
/// last ([`reclaim_counts`]).
static RECLAIM_ASKS: AtomicU64 = AtomicU64::new(0);
static CANDIDATES_FOUND: AtomicU64 = AtomicU64::new(0);
static LAST_MOVED: AtomicUsize = AtomicUsize::new(0);

/// What the reclaim at the job's memory limit has done in this process
/// ([`reclaim_counts`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReclaimCounts {
    /// Reclaims asked for: each a fill or a first touch the job's limit
    /// refused.
    pub asks: u64,
    /// The chunks holding dead pages their passes found, summed.
    pub candidates: u64,
    /// The chunks moved into new sections.
    pub moves: u64,
    /// The moves begun and not made (`windows_mm::uffd_move_chunk`'s
    /// refusals: a view not mapped, live pages not committed).
    pub refused: u64,
    /// The address of the chunk moved last (its guest view), 0 for none.
    pub last_moved: usize,
    /// Stack pages the job's limit refused and had on the handler's retry,
    /// after a wait for the reclaim's next step or not
    /// (`windows_mm::stack_page_after_the_reclaim`).
    pub stack_pages_had_again: u64,
}

/// The reclaim's counts so far: read-only, for a record of what it did
/// (MOVEUNDERVCPU). Each is bumped only where a reclaim is asked for, on
/// the reclaim's thread, or by a move; a fill or touch the limit does not
/// refuse reaches none of them.
pub fn reclaim_counts() -> ReclaimCounts {
    ReclaimCounts {
        asks: RECLAIM_ASKS.load(Ordering::Relaxed),
        candidates: CANDIDATES_FOUND.load(Ordering::Relaxed),
        moves: MOVES_MADE.load(Ordering::Relaxed) as u64,
        refused: crate::windows_mm::moves_refused(),
        last_moved: LAST_MOVED.load(Ordering::Relaxed),
        stack_pages_had_again: crate::windows_mm::stack_pages_had_again(),
    }
}

/// Moves one chunk (`windows_mm::uffd_move_chunk`), marked moving for its
/// time: an access to it meanwhile waits in [`fault`] until the mark goes
/// (the waiters of its missing pages wait on for their fill). Its dead
/// pages are its committed pages missing now (`d.dead` is what
/// [`find_candidates`] counted). Under [`LOCK`], with a discard's guard on
/// the chunk.
fn move_chunk(d: &Candidate) -> Reclaimed {
    let Some((range, s)) = range_of_view(d.view) else {
        return Reclaimed::default();
    };
    let moving = MovingWindow::open(d.view as u64, (d.view + d.len) as u64);
    let t = std::time::Instant::now();
    #[allow(clippy::cast_possible_truncation)]
    let span = (s as usize, range.end.load(Ordering::Acquire) as usize);
    let moved = crate::windows_mm::uffd_move_chunk(d.view, d.len, d.alias, span, &|at| missing_at(range, s, at));
    let us = u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX);
    drop(moving);
    reclaim_progress(true);
    let Some((copied, freed)) = moved else {
        return Reclaimed::default();
    };
    let copied = copied / PAGE as usize;
    LAST_MOVED.store(d.view, Ordering::Relaxed);
    let n = MOVES_MADE.fetch_add(1, Ordering::Relaxed);
    if n < MOVES_KEPT {
        MOVES[n].store((copied as u64) << 32 | us.min(u64::from(u32::MAX)), Ordering::Relaxed);
    }
    Reclaimed { chunks: 1, copied, freed, skipped: 0 }
}

/// One pass over `chunks` until `need` bytes are given back: a chunk with a
/// system call in its copy on it is passed over (`windows_mm::try_move`)
/// and, if `skipped` is given, kept there (never grown). Under [`LOCK`].
fn reclaim_pass(need: usize, chunks: &[Candidate], mut skipped: Option<&mut Vec<Candidate>>) -> Reclaimed {
    let mut r = Reclaimed::default();
    for d in chunks {
        if r.freed >= need {
            break;
        }
        let Some(_guard) = crate::windows_mm::try_move(d.view, d.len) else {
            r.skipped += 1;
            if let Some(s) = skipped.as_deref_mut() {
                if s.len() < s.capacity() {
                    s.push(*d);
                }
            }
            continue;
        };
        r.add(move_chunk(d));
    }
    r
}

/// The reclaim of a fill refused at the limit (under [`LOCK`], which the
/// fill holds): one pass, and in `passed` the chunks it passed over for
/// system calls in their copy (at most `windows_mm::FILL_CLAIMS`, the most
/// dead first), which the fill waits for without the lock ([`wait_and_move`]).
/// A call in its prefault, which may be waiting for a fill that the handler
/// sends only once this one is answered, does not hold a chunk: its move
/// keeps what the prefault made present (`windows_mm::InFlight`), so the
/// fill never waits for it. Allocates nothing ([`FILL_SKIPPED`]).
fn reclaim_for_a_fill(need: usize, passed: &mut [Option<Candidate>; crate::windows_mm::FILL_CLAIMS]) -> Reclaimed {
    let mut skipped = FILL_SKIPPED.lock().unwrap();
    skipped.clear();
    let list: *mut Vec<Candidate> = &mut *skipped;
    let r = ask_the_reclaimer(Ask::Fill(need, list));
    for (i, p) in passed.iter_mut().enumerate() {
        *p = skipped.get(i).copied();
    }
    skipped.clear();
    r
}

/// [`reclaim_for_a_fill`]'s pass, on [`reclaimer`].
fn fill_pass(need: usize, skipped: Option<&mut Vec<Candidate>>) -> Reclaimed {
    let mut c = CANDIDATES.lock().unwrap();
    find_candidates(&mut c);
    CANDIDATES_FOUND.fetch_add(c.len() as u64, Ordering::Relaxed);
    let r = reclaim_pass(need.max(crate::windows_mm::UFFD_CHUNK), &c, skipped);
    c.clear();
    r
}

/// [`reclaim_at_touch`]'s first pass, on [`reclaimer`].
fn touch_pass(need: usize, skipped: Option<&mut Vec<Candidate>>) -> Reclaimed {
    let mut c = CANDIDATES.lock().unwrap();
    find_candidates(&mut c);
    CANDIDATES_FOUND.fetch_add(c.len() as u64, Ordering::Relaxed);
    let r = reclaim_pass(need, &c, skipped);
    c.clear();
    r
}

/// A chunk [`reclaim_at_touch`] passed over and waited for, moved if it
/// still holds dead pages (it may have changed meanwhile: moved by a
/// fill's reclaim, filled, unregistered), on [`reclaimer`].
fn move_again(d: &Candidate) -> Reclaimed {
    if range_of_view(d.view).is_some_and(|(range, s)| dead_bytes(range, s, d.view, d.len) > 0) {
        move_chunk(d)
    } else {
        Reclaimed::default()
    }
}

/// Reclaims at least `need` bytes of dead pages (a chunk's worth at least)
/// at a charge refused at the job's memory limit, as Linux's memory cgroup
/// reclaims before it refuses one (v6.1 mm/memcontrol.c, `try_charge_memcg`:
/// `try_to_free_mem_cgroup_pages` before `mem_cgroup_oom`; there a page
/// discarded was freed and uncharged at once). For a lazy, discarded or
/// recharged page's first access (`windows_mm::commit_on_access`,
/// `prefault_lazy`), by a host thread or a vCPU. The chunks holding dead
/// pages are moved into new sections, the most dead first
/// (`windows_mm::uffd_move_chunk`). Those passed over for a system call in
/// its copy on them are claimed, so that no call turns to its copy on them
/// meanwhile, waited for, one at a time and without [`LOCK`], and moved;
/// never by a thread in a call itself (its own call could be among them,
/// `windows_mm::in_a_call`) or one holding [`LOCK`] (which reclaims
/// nothing). The calls end: only calls that do are counted (`windows_fd`),
/// and a call in its prefault, which may wait for a fill, holds no chunk
/// (`windows_mm::InFlight`). Allocates nothing ([`CANDIDATES`]).
pub(crate) fn reclaim_at_touch(need: usize) -> Reclaimed {
    if HOLDS_LOCK.get() || REGISTERED.load(Ordering::Acquire) == 0 {
        return Reclaimed::default();
    }
    let need = need.max(crate::windows_mm::UFFD_CHUNK);
    let wait = !crate::windows_mm::in_a_call();
    // The skipped list is one touch's at a time: a second touch waits here
    // for the first's waits, which end as the calls end.
    let mut skipped = wait.then(|| TOUCH_SKIPPED.lock().unwrap());
    if let Some(s) = skipped.as_deref_mut() {
        s.clear();
    }
    let mut r = {
        let _guard = lock();
        let list = skipped.as_deref_mut().map_or(ptr::null_mut(), |s| s as *mut Vec<Candidate>);
        ask_the_reclaimer(Ask::Touch(need, list))
    };
    let Some(s) = skipped else {
        return r;
    };
    for d in s.iter() {
        if r.freed >= need {
            break;
        }
        let Some(claim) = crate::windows_mm::claim_move(d.view, d.len) else {
            continue;
        };
        claim.wait_for_copies();
        let _guard = lock();
        r.add(ask_the_reclaimer(Ask::Move(*d)));
    }
    r.skipped = 0;
    r
}

/// Hooks for other crates' tests (kvm-ioctls' WHP tests), with the
/// `wick-test-hooks` feature, which only a dev-dependency turns on.
#[cfg(feature = "wick-test-hooks")]
pub mod test_hooks {
    /// Sets the `fn()` a reclaim's move of a chunk calls between its copy
    /// and its swap (`windows_mm::uffd_move_chunk`: the chunk's live pages
    /// closed, `PAGE_NOACCESS`, its accesses waiting for the move), on the
    /// reclaimer's thread with the asker's lock held; `None` takes it away.
    pub fn set_move_hook(hook: Option<fn()>) {
        crate::windows_mm::set_move_hook(hook);
    }

    /// Sets the `fn()` a register's move of its mapping calls once, after
    /// the copy of its resident pages and before the private allocation is
    /// given back (`windows_mm::uffd_alias`: the mapping read-only, its
    /// accesses waiting for the register), with the register's lock held.
    pub fn set_register_hook(hook: fn()) {
        crate::windows_mm::ALIAS_HOOK.store(hook as usize, core::sync::atomic::Ordering::SeqCst);
    }

    /// The reclaim a commit refused at the memory limit runs
    /// ([`super::reclaim_at_touch`]), for at least `need` bytes: the chunks
    /// moved and the bytes given back. Called holding none of wick's locks.
    pub fn reclaim(need: usize) -> (usize, usize) {
        let r = super::reclaim_at_touch(need);
        (r.chunks, r.freed)
    }

    /// Sets the `fn()` the next fill calls once, between the commit of its
    /// pages and the write of their content through the alias
    /// (`super::fill`), on the filling thread with the userfaultfd's lock
    /// held; `None` takes it away.
    pub fn set_fill_hook(hook: Option<fn()>) {
        super::FILL_HOOK.store(hook.map_or(0, |f| f as usize), core::sync::atomic::Ordering::SeqCst);
    }

    /// Whether a thread's access to the page at `page` is in
    /// [`super::fault`] (a waiter slot holds the page): it has not been
    /// given the page, and waits for its fill once its record is posted.
    pub fn in_fault(page: u64) -> bool {
        super::WAITERS.iter().any(|w| w.page.load(core::sync::atomic::Ordering::SeqCst) == page)
    }

    /// Starts (the address of the test's clock, an `AtomicU64` the test
    /// keeps alive until it calls this with `None`) or stops SWAPTRACE's
    /// record (`super::trace`).
    pub fn set_trace_clock(clock: Option<&'static core::sync::atomic::AtomicU64>) {
        super::trace::CLOCK.store(clock.map_or(0, |c| core::ptr::from_ref(c) as usize), core::sync::atomic::Ordering::SeqCst);
    }

    /// Keeps a step of the WHP backend's in SWAPTRACE's record
    /// ([`TRACE_VCPU_EXIT`], [`TRACE_VCPU_RERUN`]).
    pub fn trace(kind: u64, addr: u64, extra: u64) {
        super::trace::note(kind, addr, || extra);
    }

    /// SWAPTRACE's kinds for the WHP backend's steps.
    pub const TRACE_VCPU_EXIT: u64 = super::trace::VCPU_EXIT;
    pub const TRACE_VCPU_RERUN: u64 = super::trace::VCPU_RERUN;

    /// The step SWAPTRACE kept at clock `n`, if it is still there: its
    /// kind's name, the CPU, the thread, the address and the extra word.
    pub fn traced(n: u64) -> Option<(&'static str, u32, u32, u64, u64)> {
        use super::trace as t;
        t::at(n).map(|(kind, cpu, tid, addr, extra)| {
            let name = match kind {
                t::DISCARD_BEGIN => "discard begun",
                t::MISSING_SET => "missing set",
                t::SWAPPED => "chunk swapped (1) or not (0)",
                t::DISCARD_END => "discard ended",
                t::FAULT_ENTERED => "fault entered",
                t::FAULT_POSTED => "fault posted",
                t::FAULT_LEFT => "fault left",
                t::COMMIT_BEGIN => "commit begun",
                t::COMMIT_END => "commit ended",
                t::CONTENT_BEGIN => "content begun",
                t::CONTENT_END => "content ended",
                t::OPENED => "opened",
                t::MISSING_CLEARED => "missing cleared",
                t::WOKEN => "woken",
                t::VCPU_EXIT => "vCPU exit",
                t::VCPU_RERUN => "vCPU run again",
                _ => "?",
            };
            (name, cpu, tid, addr, extra)
        })
    }
}

/// The moves made so far (RECLAIMREC): each one's live pages copied and its
/// microseconds; the accesses that waited for one and their microseconds.
#[cfg(test)]
pub(crate) fn moves_on_record() -> (Vec<(usize, u64)>, u64, u64) {
    let n = MOVES_MADE.load(Ordering::Relaxed).min(MOVES_KEPT);
    let moves = MOVES[..n]
        .iter()
        .map(|m| {
            let v = m.load(Ordering::Relaxed);
            #[allow(clippy::cast_possible_truncation)]
            ((v >> 32) as usize, v & u64::from(u32::MAX))
        })
        .collect();
    (moves, MOVE_WAITS.load(Ordering::Relaxed), MOVE_WAITED_US.load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts that a range the test moves or swaps chunks of starts on a
    /// 2 MiB boundary, where mmap places a mapping of a multiple of 2 MiB
    /// (`windows_mm::new_placeholder_aligned`) and Firecracker its guest
    /// memory: a chunk at a range's edge is neither moved nor swapped
    /// (`windows_mm::at_a_ranges_edge`), so a placement regression fails
    /// here, by name, not as a refused move.
    #[track_caller]
    fn on_a_boundary(mem: u64) {
        assert!(mem.is_multiple_of(CHUNK), "the range at {mem:#x} is {} KiB past a 2 MiB boundary", (mem % CHUNK) >> 10);
    }

    #[track_caller]
    fn map(len: usize) -> u64 {
        // SAFETY: a new anonymous mapping.
        let p = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, crate::MAP_FAILED);
        if len.is_multiple_of(CHUNK as usize) {
            on_a_boundary(p as u64);
        }
        p as u64
    }

    /// The handler side, in this process: reads events from the user end
    /// and fills pages directly.
    fn serve_one(user: c_int, ctx: usize, fill: u8) -> [u64; 4] {
        let mut buf = [0u8; proto::RECORD];
        assert!(recv_all(user, &mut buf));
        let event = words(&buf);
        if event[0] == proto::EVENT_PAGEFAULT2 {
            let page = event[1] - event[1] % PAGE;
            let data = std::vec![fill; PAGE as usize];
            // SAFETY: `data` holds a page.
            unsafe { copy(ctx, data.as_ptr(), page, PAGE, true) }.unwrap();
        }
        event
    }

    // ---- The waiter mirror section's proto and read-only transport. The
    // fault/wake/read wiring and the reader's drop are tested in
    // `windows_uffd`'s fault/wake tests and the `userfaultfd` crate's
    // `windows::tests`. ----

    /// The mirror proto constants are the twin of macOS's
    /// `libc::wick_uffd::proto`, which compiles only on macOS; this asserts
    /// its literal values (named here so a change to either is caught):
    /// wick_uffd.rs `EVENT_PAGEFAULT` 3 (:140), `OP_MIRROR` 6 (:163),
    /// `MIRROR_WORDS` 256 (:167), `TAG_WAITING` 1 (:169), and `tag`/`tag_slot`
    /// the same bit layout. The two protos are duplicated, not shared, so the
    /// backends stay independent; change one, change the other. If this fails
    /// after a macOS proto change, update both proto blocks (this file's and
    /// wick_uffd.rs's) and the two reciprocal doc lines that point across.
    #[test]
    fn test_the_mirror_proto_matches_the_macos_twin() {
        assert_eq!(proto::EVENT_PAGEFAULT2, 3);
        assert_eq!(proto::OP_MIRROR, 6);
        assert_eq!(proto::MIRROR_WORDS, 256);
        assert_eq!(proto::TAG_WAITING, 1);
        assert_eq!(proto::tag(5, 7), (5u64 << 17) | (7u64 << 1) | 1);
        assert_eq!(proto::tag_slot(proto::tag(9, 42)), 42);
        assert_eq!(proto::mirror_bytes(4096), 4096);
        // The mirror fits one page of this host.
        assert_eq!(mirror_bytes(), 4096);
        // The modes and a register's ioctls: wick_uffd.rs `MODE_DONTWAKE` 1,
        // `MODE_WP` 2, `RANGE_IOCTLS` and `RANGE_IOCTLS_HUGETLB` (Linux's
        // `1 << _UFFDIO_WAKE | _COPY | _ZEROPAGE`, and without `_ZEROPAGE`).
        assert_eq!((proto::MODE_DONTWAKE, proto::MODE_WP), (1, 2));
        assert_eq!((proto::RANGE_IOCTLS, proto::RANGE_IOCTLS_HUGETLB), (0x1c, 0xc));
    }

    // ---- The ioctls' checks, as Linux v6.12's, in its order
    // (docs/ARCHITECTURE.md, "The ioctls' checks"; the macOS backend's tests
    // of the same names). The checks of a request's mode, made where it comes
    // off a channel, are the `userfaultfd` crate's
    // `test_fill_modes_and_ranges_are_checked_as_linux`. ----

    /// Every range is checked as Linux's `validate_range` checks it: a start
    /// below `mmap_min_addr` is `EINVAL`, which is 64 KiB on Linux's arm64 and
    /// x86 hosts (security/Kconfig `LSM_MMAP_MIN_ADDR`, v6.12, :145 to :149)
    /// and the lowest address a Windows process maps
    /// (`lpMinimumApplicationAddress`); one at it is memory that is not mapped
    /// (`ENOENT` for a fill, nothing to wake). A register answers the range's
    /// ioctls. Before, a fill below 64 KiB was `ENOENT` (`range_of` checked
    /// the alignment only).
    #[test]
    fn test_fill_modes_and_ranges_are_checked_as_linux() {
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        const MMAP_MIN_ADDR: u64 = 0x1_0000;
        // SAFETY: an all-zero SYSTEM_INFO is valid; filled by the call.
        let mut si: SYSTEM_INFO = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        unsafe { GetSystemInfo(&mut si) };
        assert_eq!(si.lpMinimumApplicationAddress as u64, MMAP_MIN_ADDR, "Windows' lowest address is not Linux's mmap_min_addr");
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map(PAGE as usize);
        assert_eq!(register_ioctls(ctx, mem, PAGE).unwrap(), proto::RANGE_IOCTLS);
        let page = page_of(7);
        for at in [PAGE, MMAP_MIN_ADDR - PAGE] {
            assert_eq!(wake_range(ctx, at, PAGE), Err(crate::EINVAL), "{at:#x}");
            assert_eq!(zeropage(ctx, at, PAGE, true), Err((crate::EINVAL, 0)), "{at:#x}");
            // SAFETY: `page` holds a page.
            assert_eq!(unsafe { copy(ctx, page.as_ptr(), at, PAGE, true) }, Err((crate::EINVAL, 0)), "{at:#x}");
            assert_eq!(unregister(ctx, at, PAGE), Err(crate::EINVAL), "{at:#x}");
            assert_eq!(register(ctx, at, PAGE).unwrap_err().raw_os_error(), Some(crate::EINVAL), "{at:#x}");
        }
        assert_eq!(wake_range(ctx, MMAP_MIN_ADDR, PAGE), Ok(()));
        assert_eq!(zeropage(ctx, MMAP_MIN_ADDR, PAGE, true), Err((crate::ENOENT, 0)));
        // SAFETY: `page` holds a page.
        assert_eq!(unsafe { copy(ctx, page.as_ptr(), MMAP_MIN_ADDR, PAGE, true) }, Err((crate::ENOENT, 0)));
        assert!(is_missing(mem));
        assert_eq!(zeropage(ctx, mem, PAGE, true), Ok(PAGE));
        release(ctx, user);
    }

    /// Not Linux's: two registers of adjacent memory are two ranges, and a
    /// fill across both is `ENOENT`, where Linux merges the second vma with
    /// the first (`userfaultfd_register_range`, `vma_modify_flags_uffd`,
    /// fs/userfaultfd.c, v6.12) and fills across them. Each part fills on
    /// its own. Two mappings here, each made a range of its own on Windows
    /// (SECURITY.md, "Not at parity yet"); on Linux the two are one vma.
    #[test]
    fn test_two_adjacent_registers_are_two_ranges() {
        let (ctx, user) = create(0, false, true).unwrap();
        // Two mappings, one after the other: where one was unmapped, each
        // placed there by its address hint (again if another test's mapping
        // took the addresses meanwhile).
        let at = |a: u64| {
            // SAFETY: a new anonymous mapping, at free addresses of the test's.
            (unsafe { crate::mmap(a as *mut c_void, CHUNK as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0) }) as u64
        };
        let mem = (0..10)
            .find_map(|_| {
                let mem = map(2 * CHUNK as usize);
                assert_eq!(munmap_of(mem, 2 * CHUNK), 0);
                let (a, b) = (at(mem), at(mem + CHUNK));
                if (a, b) == (mem, mem + CHUNK) {
                    return Some(mem);
                }
                for m in [a, b] {
                    assert_eq!(munmap_of(m, CHUNK), 0);
                }
                None
            })
            .expect("the hints were not taken in 10 tries");
        for at in [mem, mem + CHUNK] {
            let r = register(ctx, at, CHUNK);
            assert!(r.is_ok(), "the register at {at:#x}: {r:?}");
        }
        {
            let _guard = lock();
            let (a, b) = (find(mem).unwrap().0, find(mem + CHUNK).unwrap().0);
            assert!(!ptr::eq(a, b), "one range");
        }
        let across = mem + CHUNK - PAGE;
        assert_eq!(zeropage(ctx, across, 2 * PAGE, true), Err((crate::ENOENT, 0)));
        assert!(is_missing(across) && is_missing(across + PAGE));
        assert_eq!(zeropage(ctx, across, PAGE, true), Ok(PAGE));
        assert_eq!(zeropage(ctx, across + PAGE, PAGE, true), Ok(PAGE));
        assert_eq!(unregister(ctx, mem, 2 * CHUNK), Ok(()));
        assert_eq!(munmap_of(mem, 2 * CHUNK), 0);
        release(ctx, user);
    }

    /// Not Linux's, as on macOS: a fill while a remove event is unread is
    /// not `EAGAIN`. `madvise(MADV_DONTNEED)` of registered pages queues
    /// the event and returns ([`discarding`]), where Linux's waits for the
    /// handler to read it (fs/userfaultfd.c, v6.12, `userfaultfd_remove`
    /// :770, `userfaultfd_event_wait_completion` :793) and a fill meanwhile
    /// sees `mmap_changing` (`EAGAIN`, :1588 to :1590). Here the fill fills,
    /// and the event is read after.
    #[test]
    fn test_a_fill_while_a_remove_event_is_unread_fills() {
        let (ctx, user) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let mem = map(2 * PAGE as usize);
        register(ctx, mem, 2 * PAGE).unwrap();
        assert_eq!(zeropage(ctx, mem, 2 * PAGE, true), Ok(2 * PAGE));
        // SAFETY: registered memory of the test's.
        assert_eq!(unsafe { crate::madvise(mem as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert!(is_missing(mem));
        // SAFETY: a page.
        assert_eq!(unsafe { copy(ctx, page_of(3).as_ptr(), mem, PAGE, true) }, Ok(PAGE), "the fill before the remove event is read");
        let mut rec = [0u8; proto::RECORD];
        assert!(recv_all(user, &mut rec));
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem, mem + PAGE]);
        // SAFETY: filled above.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 3);
        assert_eq!(unregister(ctx, mem, 2 * PAGE), Ok(()));
        release(ctx, user);
    }

    /// A reserved section's fill whose commit is refused in part fills the
    /// pages that fit, then the rest once committed: each page from its own
    /// bytes of the source. Before, each later part was filled from the
    /// source's start (the fill's callback was given no offset), so a copy
    /// that met the job's limit wrote the wrong bytes into the pages after
    /// its first part. The commit's refusals are scripted
    /// ([`REFUSE_COMMITS`]): the whole run refused, two pages made one at a
    /// time, the third refused; the rest then committed whole.
    #[test]
    fn test_a_copy_whose_commit_is_refused_in_part_fills_each_page_from_its_own_bytes() {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(4 * PAGE as usize);
        register(ctx, mem, 4 * PAGE).unwrap();
        assert!(find(mem).unwrap().0.reserved.load(Ordering::Acquire), "not a reserved section");
        #[allow(clippy::cast_possible_truncation)]
        let src: std::vec::Vec<u8> = (0..4 * PAGE).map(|i| (i / PAGE) as u8 + 1).collect();
        *REFUSE_COMMITS.lock().unwrap() = Some((mem, mem + 4 * PAGE, [false, true, true, false].into_iter().collect()));
        // SAFETY: `src` holds four pages.
        let r = unsafe { copy(ctx, src.as_ptr(), mem, 4 * PAGE, true) };
        let left = REFUSE_COMMITS.lock().unwrap().take().map(|(_, _, s)| s.len());
        assert_eq!(left, Some(0), "the script was not followed");
        assert_eq!(r, Ok(4 * PAGE));
        for p in 0..4u8 {
            // SAFETY: filled above.
            let b = unsafe { ptr::read_volatile((mem + u64::from(p) * PAGE + 9) as *const u8) };
            assert_eq!(b, p + 1, "page {p} holds page {}'s bytes", b.wrapping_sub(1));
        }
        assert_eq!(unregister(ctx, mem, 4 * PAGE), Ok(()));
        release(ctx, user);
    }

    /// A fill's commits inside `[start, end)` follow the script first, a
    /// step a call: `false` refused, `true` made; past the script, made
    /// ([`uffd_commit`]).
    pub(crate) static REFUSE_COMMITS: std::sync::Mutex<Option<(u64, u64, std::collections::VecDeque<bool>)>> = std::sync::Mutex::new(None);

    /// [`REFUSE_COMMITS`]'s answer for a commit of `[at, at + len)`.
    pub(crate) fn scripted_commit(at: u64, len: u64) -> bool {
        match REFUSE_COMMITS.lock().unwrap().as_mut() {
            Some((start, end, script)) if at >= *start && at + len <= *end => script.pop_front().unwrap_or(true),
            _ => true,
        }
    }

    /// Proof 1: the read-only handle a reader is given maps the mirror
    /// read-only — this side's writes are visible — and a write view of it is
    /// refused with `ERROR_ACCESS_DENIED`.
    #[test]
    fn test_a_mirror_handle_a_reader_gets_maps_read_only() {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        let (section, rw) = new_mirror().unwrap();
        // SAFETY: this process's pseudo handle.
        let me = unsafe { GetCurrentProcess() };
        // SAFETY: live section and process handles.
        let ro = unsafe { dup_mirror_read_only(section, me) }.unwrap();
        // SAFETY: the live read-only section handle.
        let read = unsafe { map_mirror_read_only(ro) }.unwrap();
        // SAFETY: the read-write and read-only views of the one section.
        unsafe {
            (*rw).store(0x1234_5678_9abc_def0, Ordering::SeqCst);
            assert_eq!((*read).load(Ordering::SeqCst), 0x1234_5678_9abc_def0);
        }
        // SAFETY: the read-only handle; a write view must be refused.
        let w = unsafe { MapViewOfFile(ro, FILE_MAP_WRITE, 0, 0, mirror_bytes()) }.Value;
        assert!(w.is_null(), "a write view of a read-only mirror handle was allowed");
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
        // SAFETY: a mirror view this test mapped.
        unsafe { unmap_mirror(read) };
        // SAFETY: a mirror view this test mapped.
        unsafe { unmap_mirror(rw) };
        // SAFETY: handles this test owns.
        unsafe {
            CloseHandle(ro);
            CloseHandle(section);
        }
    }

    /// Proof 2: a read-only mirror view cannot be re-protected writable
    /// (`VirtualProtect` to `PAGE_READWRITE` fails), as macOS's `mprotect`
    /// `PROT_WRITE` on a `PROT_READ` mapping is `EACCES`.
    #[test]
    fn test_a_read_only_mirror_view_cannot_be_made_writable() {
        let (section, rw) = new_mirror().unwrap();
        // SAFETY: pseudo handle.
        // SAFETY: live section and this process's pseudo handle.
        let ro = unsafe { dup_mirror_read_only(section, GetCurrentProcess()) }.unwrap();
        // SAFETY: the live read-only section handle.
        let read = unsafe { map_mirror_read_only(ro) }.unwrap();
        let mut old: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: the read-only view; the call must refuse `PAGE_READWRITE`.
        let ok = unsafe { VirtualProtect(read as *mut c_void, mirror_bytes(), PAGE_READWRITE, &mut old) };
        assert_eq!(ok, 0, "a read-only mirror view was re-protected writable");
        // SAFETY: a mirror view this test mapped.
        unsafe { unmap_mirror(read) };
        // SAFETY: a mirror view this test mapped.
        unsafe { unmap_mirror(rw) };
        // SAFETY: handles this test owns.
        unsafe {
            CloseHandle(ro);
            CloseHandle(section);
        }
    }

    /// Proof 3 (load-bearing): the read-only handle a reader holds cannot be
    /// re-duplicated with write access. This proves the **access mask** is
    /// reduced, not only the view: a reader that could re-dup to write could
    /// corrupt every waiter's mirror word.
    #[test]
    fn test_a_mirror_handle_a_reader_gets_cannot_be_re_duplicated_to_writable() {
        let (section, rw) = new_mirror().unwrap();
        // SAFETY: pseudo handle.
        let me = unsafe { GetCurrentProcess() };
        // SAFETY: live section and process handles.
        let ro = unsafe { dup_mirror_read_only(section, me) }.unwrap();
        let mut wide: HANDLE = ptr::null_mut();
        // SAFETY: the read-only handle; a re-duplication asking for write.
        let ok = unsafe { DuplicateHandle(me, ro, me, &mut wide, FILE_MAP_WRITE, 0, 0) };
        if ok != 0 {
            // SAFETY: a handle this call made.
            unsafe { CloseHandle(wide) };
            // SAFETY: a mirror view this test mapped.
        unsafe { unmap_mirror(rw) };
            // SAFETY: handles this test owns.
            unsafe {
                CloseHandle(ro);
                CloseHandle(section);
            }
            panic!("a read-only mirror handle was re-duplicated to a writable one (access mask not reduced)");
        }
        // SAFETY: a mirror view this test mapped.
        unsafe { unmap_mirror(rw) };
        // SAFETY: handles this test owns.
        unsafe {
            CloseHandle(ro);
            CloseHandle(section);
        }
    }

    /// Proof 4: the mirror section has no name, so no `OpenFileMappingW` can
    /// reach it; a reader reaches it only through a handle this side
    /// duplicates. `NtQueryObject` confirms the object's name is empty
    /// (windows_sectrec makes and relies on unnamed sections the same way).
    #[test]
    fn test_the_mirror_section_has_no_name() {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryObject(handle: HANDLE, class: u32, info: *mut c_void, len: u32, returned: *mut u32) -> i32;
        }
        const OBJECT_NAME_INFORMATION: u32 = 1;
        let (section, rw) = new_mirror().unwrap();
        let mut buf = [0u8; 1024];
        let mut got = 0u32;
        // SAFETY: a valid section handle and an output buffer.
        let status =
            unsafe { NtQueryObject(section, OBJECT_NAME_INFORMATION, buf.as_mut_ptr().cast(), buf.len() as u32, &mut got) };
        assert!(status >= 0, "NtQueryObject: {status:#x}");
        // OBJECT_NAME_INFORMATION starts with a UNICODE_STRING; its Length (in
        // bytes) is 0 for an object with no name.
        let name_len = u16::from_ne_bytes([buf[0], buf[1]]);
        assert_eq!(name_len, 0, "the mirror section has a name {name_len} bytes long");
        // SAFETY: a mirror view this test mapped.
        unsafe { unmap_mirror(rw) };
        // SAFETY: a handle this test owns.
        unsafe { CloseHandle(section) };
    }

    /// MIRRORCHARGE: the mirror is a pagefile-backed shared section, which
    /// Windows does not charge to the job's commit (the windows-sandbox probe
    /// measured 640 MiB of shared section as a 2–6 MiB job peak on fc-win,
    /// 2026-11-10: pagefile-backed shared sections escape the job's memory
    /// limit), so each userfaultfd's one-page (`MIRROR_WORDS` × 8 B = 2 KiB,
    /// rounded to a 4 KiB page) mirror needs no `memory.max` carve-out. Here N
    /// mirrors, each with its first word written (the VMM writes the words
    /// read-write), add far less than a private page each to the process's
    /// private commit (`PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`), which the
    /// job's memory limit counts (`private_commit`); N private pages would be
    /// N × 4 KiB.
    #[test]
    fn test_the_mirror_is_not_charged_as_private_commit() {
        const N: usize = 256;
        let before = private_commit();
        let mut held = std::vec::Vec::with_capacity(N);
        for _ in 0..N {
            let (section, view) = new_mirror().unwrap();
            // SAFETY: the read-write mirror view just mapped; a shared commit.
            unsafe { (*view).store(0xabcd, Ordering::SeqCst) };
            held.push((section, view));
        }
        let delta = private_commit().saturating_sub(before);
        let as_private = N * PAGE as usize;
        crate::windows_mm::say_at_the_limit(format_args!(
            "MIRRORCHARGE {N} mirrors added {delta} B of private commit ({as_private} B if each were a private page)"
        ));
        // Charged as private pages, the delta would be N × 4 KiB (1 MiB);
        // shared, it is a small fraction (the Vec and the handles aside).
        assert!(
            delta < as_private / 4,
            "the mirrors charged {delta} B of private commit for {N} mirrors (a private page each would be {as_private} B)"
        );
        for (section, view) in held {
            // SAFETY: a mirror view and section handle this test owns.
            unsafe {
                unmap_mirror(view);
                CloseHandle(section);
            }
        }
    }

    /// MIRRORRELEASE: a userfaultfd's mirror is given back at its release. Each
    /// `create` wires a mirror; closing the user descriptor ends the serving
    /// thread, which runs `destroy` — it takes the mirror away (so a later
    /// `enter` reads it gone), drains the enter/leave count, then unmaps the
    /// view and closes the section, and gives up the kernel end last (it clears
    /// the fd after the `CloseHandle`, so an fd of -1 means the section was
    /// closed). 48 made and released — three times `MAX_CTX`, so every slot is
    /// reused — each leave the context's mirror and section pointers null
    /// again: the section handle and the view do not leak. The drain closes the
    /// write-after-close race the macOS side had: a waiter's record write or an
    /// `OP_MIRROR` in flight cannot reach a section the release freed meanwhile.
    #[test]
    fn test_a_userfaultfds_mirror_is_given_back_at_its_release() {
        for _ in 0..48 {
            let (ctx, user) = create(0, false, true).unwrap();
            assert!(!CTXS[ctx].mirror.load(Ordering::SeqCst).is_null(), "a mirror at create");
            assert!(!CTXS[ctx].section.load(Ordering::SeqCst).is_null(), "a section at create");
            assert!(!CTXS[ctx].pull.load(Ordering::SeqCst).is_null(), "a read-only handle for a pull at create");
            // Close the user end through the libc (detaching its descriptor
            // state, as a caller's `close` does): the serve thread then releases
            // the userfaultfd and ends.
            // SAFETY: the user descriptor this test owns.
            assert_eq!(unsafe { crate::close(user) }, 0);
            // `destroy` gives up the kernel end last. A bound for a failure only.
            let t = std::time::Instant::now();
            while CTXS[ctx].fd.load(Ordering::SeqCst) >= 0 {
                assert!(t.elapsed() < std::time::Duration::from_secs(60), "the userfaultfd was not released");
                std::thread::yield_now();
            }
            // The fd is -1, so `destroy` ran past its `CloseHandle(section)`:
            // the section is closed and its pointer null, and the view is
            // unmapped and its pointer null.
            assert!(CTXS[ctx].section.load(Ordering::SeqCst).is_null(), "the section is freed at release");
            assert!(CTXS[ctx].mirror.load(Ordering::SeqCst).is_null(), "the mirror is freed at release");
            assert!(CTXS[ctx].pull.load(Ordering::SeqCst).is_null(), "the read-only handle is closed at release");
        }
    }

    /// `ObjectBasicInformation` of a handle (`NtQueryObject` class 0): its
    /// granted access and the object's handle count.
    fn object_basics(h: HANDLE) -> (u32, u32) {
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryObject(handle: HANDLE, class: u32, info: *mut c_void, len: u32, returned: *mut u32) -> i32;
        }
        // Attributes, GrantedAccess, HandleCount, PointerCount, then reserved
        // words: 56 bytes in all.
        let mut info = [0u32; 14];
        let mut got = 0u32;
        // SAFETY: a handle of this process and a buffer of the size given.
        let status = unsafe { NtQueryObject(h, 0, info.as_mut_ptr().cast(), 56, &mut got) };
        assert!(status >= 0, "NtQueryObject: {status:#x}");
        (info[1], info[2])
    }

    /// No reply names the mirror's read-write handle: `OP_MIRROR`'s push
    /// gives the reader a handle of `SECTION_QUERY | SECTION_MAP_READ` alone,
    /// and `OP_MIRROR_PULL` names the VMM's own read-only handle of the
    /// mirror, of the same access, never the section handle the mirror was
    /// made with (which keeps write). Each names the mirror's object
    /// (`CompareObjectHandles`), and neither can be duplicated up to write.
    /// The reader here is this process (the user end's peer).
    #[test]
    fn test_no_mirror_reply_names_the_read_write_handle() {
        use windows_sys::Win32::Foundation::CompareObjectHandles;
        let (ctx, user) = create(0, false, true).unwrap();
        let section = CTXS[ctx].section.load(Ordering::SeqCst);
        let (rw_access, _) = object_basics(section);
        assert_ne!(rw_access & FILE_MAP_WRITE, 0, "the mirror's own handle keeps write");
        let pushed = serve_mirror(ctx, user);
        let pulled = serve_mirror_pull(ctx);
        // SAFETY: plain call.
        let me = unsafe { GetCurrentProcess() };
        for (op, [size, value]) in [("OP_MIRROR", pushed), ("OP_MIRROR_PULL", pulled)] {
            assert_eq!(size, mirror_bytes() as u64, "{op}: {size:#x}");
            let h = value as usize as HANDLE;
            assert_ne!(h, section, "{op} named the read-write handle");
            // SAFETY: two handles of this process.
            assert_ne!(unsafe { CompareObjectHandles(h, section) }, 0, "{op}: not the mirror");
            let (access, _) = object_basics(h);
            assert_eq!(access, MIRROR_READER_ACCESS, "{op}: access {access:#x}");
            let mut wide: HANDLE = ptr::null_mut();
            // SAFETY: a handle of this process; a duplicate asking for write.
            let ok = unsafe { DuplicateHandle(me, h, me, &mut wide, FILE_MAP_WRITE, 0, 0) };
            assert_eq!(ok, 0, "{op}: duplicated up to write");
        }
        // The push's duplicate is the reader's; the pull's handle is the VMM's.
        // SAFETY: the handle the push made for this process.
        unsafe { CloseHandle(pushed[1] as usize as HANDLE) };
        release(ctx, user);
    }

    /// What a mirror's object must be: a section of committed pagefile
    /// memory of exactly the mirror's size. The VMM is the untrusted side, so
    /// the reader checks the object a handle names before it maps it, pushed
    /// or pulled (`map_mirror_handle`), and the handle is closed whatever the
    /// answer: a handle of another type (`ENODEV`), a section of another size
    /// (`EPROTO`) and a section of a file (`EOPNOTSUPP`) are refused; the
    /// mirror maps. MIRRORKIND prints the attributes a real mirror reads with.
    #[test]
    fn test_a_mirror_handle_is_checked_before_it_is_mapped() {
        use std::io::Write as _;
        use std::os::windows::io::AsRawHandle;
        // The rule, on the attributes and sizes.
        let page = mirror_bytes() as u64;
        assert_eq!(mirror_section_kind(SEC_COMMIT, page), Ok(()));
        for attrs in [SEC_COMMIT | SEC_FILE, SEC_COMMIT | SEC_IMAGE, SEC_IMAGE, SEC_FILE, SEC_RESERVE, 0] {
            assert_eq!(mirror_section_kind(attrs, page), Err(NotAMirror::Backing(attrs)), "{attrs:#x}");
        }
        assert_eq!(mirror_section_kind(SEC_COMMIT, 2 * page), Err(NotAMirror::Size(2 * page)));
        // SAFETY: plain call.
        let me = unsafe { GetCurrentProcess() };
        // Hands `map_mirror_handle` a duplicate of `h` and checks it was
        // consumed: the object's handles are as many as before the duplicate.
        let map = |h: HANDLE| -> io::Result<*const AtomicU64> {
            let before = object_basics(h).1;
            let mut dup: HANDLE = ptr::null_mut();
            // SAFETY: a handle of this process; a duplicate of the same access.
            assert_ne!(unsafe { DuplicateHandle(me, h, me, &mut dup, 0, 0, windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS) }, 0);
            assert_eq!(object_basics(h).1, before + 1);
            // SAFETY: a handle of this process, consumed.
            let r = unsafe { map_mirror_handle(dup as usize as u64, page) };
            assert_eq!(object_basics(h).1, before, "the handle given was not closed");
            r
        };
        let errno = |r: io::Result<*const AtomicU64>| r.err().and_then(|e| e.raw_os_error());
        // Not a section: a semaphore.
        // SAFETY: an unnamed semaphore.
        let sem = unsafe { CreateSemaphoreW(ptr::null(), 0, 1, ptr::null()) };
        assert!(!sem.is_null());
        assert_eq!(errno(map(sem)), Some(crate::ENODEV), "a semaphore");
        // A pagefile section of another size.
        // SAFETY: an unnamed pagefile-backed section of two pages.
        let big = unsafe {
            CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | SEC_COMMIT, 0, 2 * page as u32, ptr::null())
        };
        assert!(!big.is_null());
        assert_eq!(errno(map(big)), Some(crate::EPROTO), "a section of two pages");
        // A section of a file, of the mirror's size.
        let path = std::env::temp_dir().join(std::format!("wick-mirror-file-{}.bin", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&std::vec![0u8; page as usize]).unwrap();
        drop(file);
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: a read-only section of the file just written.
        let filed = unsafe {
            CreateFileMappingW(file.as_raw_handle() as HANDLE, ptr::null(), PAGE_READONLY, 0, 0, ptr::null())
        };
        assert!(!filed.is_null(), "{}", io::Error::last_os_error());
        assert_eq!(errno(map(filed)), Some(crate::EOPNOTSUPP), "a section of a file");
        // The mirror, read-only, as a reader gets it.
        let (section, rw) = new_mirror().unwrap();
        // SAFETY: the section just made; this process.
        let ro = unsafe { dup_mirror_read_only(section, me) }.unwrap();
        let mut info = SectionBasicInformation::default();
        let mut got = 0usize;
        // SAFETY: as in `check_mirror_section`.
        let status = unsafe { NtQuerySection(ro, 0, (&raw mut info).cast(), core::mem::size_of_val(&info), &mut got) };
        std::println!("MIRRORKIND status {status:#x} attributes {:#x} size {}", info.attributes, info.size);
        let view = map(ro).unwrap();
        // SAFETY: views and handles this test made.
        unsafe {
            unmap_mirror(view);
            unmap_mirror(rw);
            for h in [ro, section, filed, big, sem] {
                CloseHandle(h);
            }
        }
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

    /// MIRRORHANDLES: attributes the process handle growth seen while
    /// userfaultfds are made and released back to back (a mirror wired at each
    /// `create`, the serving thread detached, `destroy` run when the user end
    /// closes). Two blocks of `N` cycles, each followed by a settle in which the
    /// process handle count is sampled over time, and the per-type handle
    /// histogram (`NtQuerySystemInformation`, `SystemExtendedHandleInformation`,
    /// this process's handles only, named with `NtQueryObject`) taken at the
    /// baseline, at the peak right after the cycles, and at the end of the
    /// settle. Tells (i) threads winding down — the growth is `Thread` handles
    /// that drain to the baseline given enough settle — from (ii) a real
    /// per-release leak — a handle type whose count stays up block over block.
    /// Measured (Windows Server 2022, release, `N` = 48): it is neither. The
    /// growth is the fixed 256-entry waiter-semaphore pool (`WAITERS[].sem`,
    /// made once in `init`'s `call_once` and kept for the process's life):
    /// `Semaphore` handles go 4 to 260 on the first block and stay 260 on the
    /// second (not 516), and the process's total holds near 370 across both
    /// blocks rather than climbing. The per-release delta is zero; `Thread`
    /// stays within 2–3 of the baseline, so the serving threads wind down
    /// promptly. No leak: the earlier "~5.8 handles a cycle" was this one-time
    /// pool filling over the first cycles, not a per-release cost.
    /// A record: nothing asserted but that the cycles ran. Run with
    /// `--release --ignored --nocapture`.
    #[test]
    #[ignore = "a probe: run alone, with --release --ignored --nocapture"]
    fn test_the_release_handle_growth_is_a_bounded_pool_not_a_leak() {
        use core::ffi::c_void;
        use std::collections::BTreeMap;
        use std::time::{Duration, Instant};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
            fn NtQueryObject(handle: HANDLE, class: u32, info: *mut c_void, len: u32, returned: *mut u32) -> i32;
        }
        const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
        const OBJECT_TYPE_INFORMATION: u32 = 2;
        const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
        const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
        const N: usize = 48;

        // The layout of SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; only three fields are
        // read, the rest give the stride.
        #[repr(C)]
        #[derive(Clone, Copy)]
        #[allow(dead_code)]
        struct Entry {
            object: *mut c_void,
            unique_process_id: usize,
            handle_value: usize,
            granted_access: u32,
            creator_back_trace_index: u16,
            object_type_index: u16,
            handle_attributes: u32,
            reserved: u32,
        }

        let hcount = || {
            let mut n = 0u32;
            // SAFETY: a process pseudo-handle and a u32 out-buffer.
            assert_ne!(unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) }, 0);
            n
        };
        // The name of the object a handle names, through `NtQueryObject`'s
        // `ObjectTypeInformation` (safe on any handle; unlike the name class it
        // does not block). The type name is a `UNICODE_STRING` at the front.
        let type_name = |handle: usize| -> std::string::String {
            let mut buf = [0u8; 2048];
            let mut got = 0u32;
            // SAFETY: a handle this process owns and an output buffer.
            let st = unsafe {
                NtQueryObject(handle as HANDLE, OBJECT_TYPE_INFORMATION, buf.as_mut_ptr().cast(), buf.len() as u32, &mut got)
            };
            if st < 0 {
                return std::format!("?{st:#x}");
            }
            let length = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
            let ptr = usize::from_ne_bytes(buf[8..16].try_into().unwrap()) as *const u16;
            if ptr.is_null() || length == 0 {
                return std::string::String::from("<none>");
            }
            // SAFETY: the type name buffer the call filled in, `length` bytes.
            let wide = unsafe { core::slice::from_raw_parts(ptr, length / 2) };
            std::string::String::from_utf16_lossy(wide)
        };
        // This process's handles, counted per object-type index, with one
        // sample handle of each type (to name it).
        let enumerate = || -> BTreeMap<u16, (u32, usize)> {
            let pid = std::process::id() as usize;
            let mut cap = 4usize << 20;
            loop {
                let mut buf = std::vec![0u8; cap];
                let mut ret = 0u32;
                // SAFETY: a byte buffer of `cap` bytes.
                let st = unsafe {
                    NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, buf.as_mut_ptr().cast(), cap as u32, &mut ret)
                };
                if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL) && cap < (512 << 20) {
                    cap *= 2;
                    continue;
                }
                assert!(st >= 0, "NtQuerySystemInformation: {st:#x}");
                // SYSTEM_HANDLE_INFORMATION_EX: NumberOfHandles (usize), Reserved
                // (usize), then the entries.
                let n = usize::from_ne_bytes(buf[0..8].try_into().unwrap());
                // SAFETY: the header says `n` entries follow at offset 16.
                let entries = unsafe { core::slice::from_raw_parts(buf.as_ptr().add(16).cast::<Entry>(), n) };
                let mut hist: BTreeMap<u16, (u32, usize)> = BTreeMap::new();
                for e in entries {
                    if e.unique_process_id == pid {
                        let slot = hist.entry(e.object_type_index).or_insert((0, e.handle_value));
                        slot.0 += 1;
                    }
                }
                return hist;
            }
        };
        let cycle = || {
            let (ctx, user) = create(0, false, true).unwrap();
            // SAFETY: the user descriptor this test owns.
            assert_eq!(unsafe { crate::close(user) }, 0);
            let t = Instant::now();
            while CTXS[ctx].fd.load(Ordering::SeqCst) >= 0 {
                assert!(t.elapsed() < Duration::from_secs(60), "the userfaultfd was not released");
                std::thread::yield_now();
            }
        };
        let settle_samples = |label: &str| -> u32 {
            let mut last = 0u32;
            let mut waited = 0u64;
            for at in [0u64, 5, 15, 30, 60, 120] {
                if at > waited {
                    std::thread::sleep(Duration::from_secs(at - waited));
                    waited = at;
                }
                last = hcount();
                std::println!("MIRRORHANDLES {label}: +{at:>3}s -> {last} handles");
            }
            last
        };
        let diff = |base: &BTreeMap<u16, (u32, usize)>, now: &BTreeMap<u16, (u32, usize)>, label: &str| {
            let mut keys: std::vec::Vec<u16> = base.keys().chain(now.keys()).copied().collect();
            keys.sort_unstable();
            keys.dedup();
            for k in keys {
                let b = base.get(&k).map_or(0, |v| v.0);
                let n = now.get(&k).map_or(0, |v| v.0);
                if b != n {
                    let sample = now.get(&k).or_else(|| base.get(&k)).map_or(0, |v| v.1);
                    std::println!("MIRRORHANDLES {label}: type {k} ({}) {b} -> {n} ({})", type_name(sample), i64::from(n) - i64::from(b));
                }
            }
        };

        // Let any threads of earlier tests in this binary drain first.
        std::thread::sleep(Duration::from_secs(3));
        let base = hcount();
        let base_hist = enumerate();
        std::println!("MIRRORHANDLES baseline: {base} handles, {} types", base_hist.len());

        for block in 1..=2 {
            for _ in 0..N {
                cycle();
            }
            let peak = hcount();
            let peak_hist = enumerate();
            std::println!("MIRRORHANDLES block {block}: {N} cycles, peak {peak} handles (+{} over baseline)", i64::from(peak) - i64::from(base));
            diff(&base_hist, &peak_hist, &std::format!("block {block} peak vs base"));
            let settled = settle_samples(&std::format!("block {block} settle"));
            let settled_hist = enumerate();
            std::println!("MIRRORHANDLES block {block}: settled {settled} handles ({:+} vs baseline, {:+} vs peak)", i64::from(settled) - i64::from(base), i64::from(settled) - i64::from(peak));
            diff(&base_hist, &settled_hist, &std::format!("block {block} settled vs base"));
        }
    }

    /// PROBECOST: the fill path's time per page with the stack probe of its
    /// locks as the stack reclaim's step 3 will have it (`windows_stacklock::probe`,
    /// which writes nothing; in tests only until then) and with the probe
    /// that zeroed its 16 KiB frame, no watch
    /// in either. Per round, 4 MiB of a registered range not yet used: a
    /// fill (`copy`) of each page by this thread; or a host thread's read of
    /// each page, each filled by this thread as its handler (the fault, the
    /// event, the fill, the wake). 5 rounds of each kind in turn; the least
    /// and the median round printed, in microseconds a page. One range is
    /// registered for all rounds, each round in a part of it not used
    /// before. Asserted only that the fills went on. Run with `--release --ignored --nocapture`.
    #[test]
    #[ignore = "a record: run alone, with --release --ignored --nocapture"]
    fn test_the_fills_cost_on_record() {
        use crate::windows_stacklock::{PROBING, Probing};
        const ROUND: u64 = 4 << 20;
        const PAGES: u64 = ROUND / PAGE;
        const ROUNDS: u64 = 5;
        let len = 2 * 2 * ROUNDS * ROUND;
        let (ctx, user) = create(0, false, true).unwrap();
        // SAFETY: a new anonymous mapping, committed at first touch, as a
        // guest's memory is.
        let mem = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        register(ctx, mem, len).unwrap();
        let next = core::cell::Cell::new(mem);
        let slice = || {
            let at = next.get();
            next.set(at + ROUND);
            at
        };
        let page = std::vec![0x5au8; PAGE as usize];
        let fills = |kind: Probing| {
            PROBING.with(|p| p.set(kind));
            let at = slice();
            let t = std::time::Instant::now();
            for p in 0..PAGES {
                // SAFETY: `page` holds a page.
                unsafe { copy(ctx, page.as_ptr(), at + p * PAGE, PAGE, false) }.unwrap();
            }
            t.elapsed().as_secs_f64() * 1e6 / PAGES as f64
        };
        let faults = |kind: Probing| {
            PROBING.with(|p| p.set(kind));
            let at = slice();
            let t = std::time::Instant::now();
            let reader = std::thread::spawn(move || {
                PROBING.with(|p| p.set(kind));
                for p in 0..PAGES {
                    // SAFETY: registered memory; the read waits for the fill.
                    assert_eq!(unsafe { core::ptr::read_volatile((at + p * PAGE) as *const u8) }, 0x6b);
                }
            });
            for _ in 0..PAGES {
                assert_eq!(serve_one(user, ctx, 0x6b)[0], proto::EVENT_PAGEFAULT2);
            }
            reader.join().unwrap();
            t.elapsed().as_secs_f64() * 1e6 / PAGES as f64
        };
        let was = PROBING.with(core::cell::Cell::get);
        for (what, run) in [("fill", &fills as &dyn Fn(Probing) -> f64), ("fault", &faults)] {
            let (mut probe, mut zeroing) = (std::vec::Vec::new(), std::vec::Vec::new());
            for _ in 0..ROUNDS {
                probe.push(run(Probing::Probe));
                zeroing.push(run(Probing::Zeroing));
            }
            for (name, v) in [("probe", &mut probe), ("zeroing", &mut zeroing)] {
                v.sort_by(f64::total_cmp);
                std::println!("PROBECOST {what} {name}: {:.2} us a page least, {:.2} median, of {ROUNDS} rounds of {PAGES} pages", v[0], v[2]);
            }
        }
        PROBING.with(|p| p.set(was));
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// MIRRORCOST (R1): the waiter mirror's cost on the common fault path is
    /// below the measurement's resolution, far below the fault round-trip. It
    /// times the fault+serve+wake round-trip per page — the kernel side stores
    /// the waiter's tag in its mirror word before the record (`fault`) and the
    /// wake clears it (`wake_where`): two relaxed stores and a load+CAS a fault,
    /// no system call. The mutation control adds `GetCurrentProcessId` calls to
    /// each serve. Note that call is user-mode on Windows (it reads the PID from
    /// the TEB, ≈ 1 ns), not a syscall as `getpid` is on Linux, so one of them
    /// is invisible against the ≈ tens-of-µs round-trip (the `mirror+1 getpid`
    /// row matches `mirror`); it takes `GETPID_REPS` of them (≈ tens of µs) to
    /// show as a clear drop, which calibrates the measurement — it resolves a
    /// cost of tens of µs a serve. The mirror's own additions, a handful of
    /// uncontended atomics fewer and cheaper than even one of those reads, do
    /// not show at all, so the mirror's per-fault cost is below that
    /// resolution: negligible. Interleaved as a shared-load control. Run with
    /// `--release --ignored --nocapture`.
    #[test]
    #[ignore = "a record: run with --release --ignored --nocapture"]
    fn test_the_mirror_cost_on_record() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        const ROUND: u64 = 4 << 20;
        const PAGES: u64 = ROUND / PAGE;
        const ROUNDS: u64 = 5;
        /// The control's `GetCurrentProcessId` block per serve, enough of the
        /// user-mode reads (≈ 1 ns each) to show over the round-trip's noise
        /// (one, and even a thousand, is lost in it).
        const GETPID_REPS: u64 = 30000;
        let len = 3 * ROUNDS * ROUND;
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(len as usize);
        register(ctx, mem, len).unwrap();
        let next = core::cell::Cell::new(mem);
        let slice = || {
            let at = next.get();
            next.set(at + ROUND);
            at
        };
        // `getpids` extra syscalls per serve: 0 (the mirror alone), 1 (one
        // syscall, below the round-trip's noise), or `GETPID_REPS` (the floor).
        let faults = |getpids: u64| {
            let at = slice();
            let t = std::time::Instant::now();
            let reader = std::thread::spawn(move || {
                for p in 0..PAGES {
                    // SAFETY: registered memory; the read waits for the fill.
                    assert_eq!(unsafe { core::ptr::read_volatile((at + p * PAGE) as *const u8) }, 0x6b);
                }
            });
            for _ in 0..PAGES {
                for _ in 0..getpids {
                    // SAFETY: plain call; a syscall of the control's block.
                    core::hint::black_box(unsafe { GetCurrentProcessId() });
                }
                assert_eq!(serve_one(user, ctx, 0x6b)[0], proto::EVENT_PAGEFAULT2);
            }
            reader.join().unwrap();
            t.elapsed().as_secs_f64() * 1e6 / PAGES as f64
        };
        let (mut plain, mut one, mut floor) = (std::vec::Vec::new(), std::vec::Vec::new(), std::vec::Vec::new());
        for _ in 0..ROUNDS {
            plain.push(faults(0));
            one.push(faults(1));
            floor.push(faults(GETPID_REPS));
        }
        for (name, v) in [("mirror", &mut plain), ("mirror+1 getpid", &mut one), ("mirror+30000 getpid", &mut floor)] {
            v.sort_by(f64::total_cmp);
            std::println!(
                "MIRRORCOST {name}: {:.2} us a page least, {:.2} median, of {ROUNDS} rounds of {PAGES} pages",
                v[0], v[2]
            );
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Anonymous private memory committed at first touch, as Firecracker
    /// maps guest memory (`MAP_NORESERVE`).
    fn map_noreserve(len: usize) -> u64 {
        // SAFETY: a new anonymous mapping.
        let p = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(p, crate::MAP_FAILED);
        p as u64
    }

    fn mprotect_of(addr: u64, len: u64, prot: c_int) -> Result<(), io::Error> {
        // SAFETY: registered memory of the test's.
        if unsafe { crate::mprotect(addr as *mut c_void, len as usize, prot) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    /// `mprotect` of registered memory whose pages are missing changes their
    /// protection and leaves them missing, as Linux's `mprotect` changes the
    /// vma's protection and leaves its pages unpopulated: made accessible
    /// again, a page's first access is a userfault, filled by the handler;
    /// a page filled while `PROT_NONE` is filled, and keeps its protection
    /// until it is changed; a `PROT_READ` page's read is a userfault too.
    /// `VirtualProtect` changes committed pages only (Learn: "If the state of
    /// any page in the specified region is not committed, the function
    /// fails"), so a missing page's protection is kept in its range
    /// (`mprotect_locked`) until it is filled.
    #[test]
    fn test_mprotect_of_registered_missing_pages_keeps_them_missing() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 4 << 20;
        let mem = map_noreserve(len as usize);
        register(ctx, mem, len).unwrap();
        let slot = mem + (2 << 20);
        mprotect_of(slot, 2 << 20, crate::PROT_NONE).expect("PROT_NONE over missing registered pages");
        assert!(is_missing(slot) && is_missing(slot + PAGE));
        mprotect_of(slot, 2 << 20, crate::PROT_READ | crate::PROT_WRITE).expect("read-write again");
        assert!(is_missing(slot) && is_missing(slot + PAGE));
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { core::ptr::read_volatile((slot + 5) as *const u8) }
        });
        let event = serve_one(user, ctx, 0x33);
        assert_eq!((event[0], event[1]), (proto::EVENT_PAGEFAULT2, slot + 5));
        assert_eq!(reader.join().unwrap(), 0x33);
        // Filled while PROT_NONE: filled, and closed until made accessible.
        mprotect_of(slot + PAGE, PAGE, crate::PROT_NONE).unwrap();
        let page = std::vec![0x44u8; PAGE as usize];
        // SAFETY: `page` holds a page.
        assert_eq!(unsafe { copy(ctx, page.as_ptr(), slot + PAGE, PAGE, true) }, Ok(PAGE));
        assert!(!is_missing(slot + PAGE));
        mprotect_of(slot + PAGE, PAGE, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        // SAFETY: filled and accessible.
        assert_eq!(unsafe { core::ptr::read_volatile((slot + PAGE) as *const u8) }, 0x44);
        // A read-only missing page: its read is a userfault.
        mprotect_of(slot + 2 * PAGE, PAGE, crate::PROT_READ).unwrap();
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { core::ptr::read_volatile((slot + 2 * PAGE) as *const u8) }
        });
        let event = serve_one(user, ctx, 0x55);
        assert_eq!((event[0], event[1] & proto::FLAG_WRITE), (proto::EVENT_PAGEFAULT2, 0));
        assert_eq!(reader.join().unwrap(), 0x55);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Firecracker's memory hotplug after a restore from a userfaultfd: the
    /// whole region registered (`persist.rs`, `guest_memory_from_uffd`), an
    /// unplugged slot made `PROT_NONE` (`vm.rs`, `register_memory_region` →
    /// `slot.protect(true)`), a plugged one read through the handler, the
    /// slot plugged (`protect(false)`) and read through the handler, then
    /// unplugged again (discarded, `MADV_DONTNEED`, and `PROT_NONE`), its
    /// pages missing again. Before the per-page protection, the first
    /// `protect(true)` failed with `EACCES`, and so did the restore.
    #[test]
    fn test_plug_after_a_uffd_restore() {
        let (ctx, user) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let slot_len: u64 = 2 << 20;
        let mem = map_noreserve(2 * slot_len as usize);
        register(ctx, mem, 2 * slot_len).unwrap();
        let unplugged = mem + slot_len;
        mprotect_of(unplugged, slot_len, crate::PROT_NONE).expect("protect(true) of an unplugged slot");
        let read_through_the_handler = |addr: u64, fill: u8| {
            // Missing and inaccessible, so the read faults to the handler
            // (a page a call opened would read zeros, with no event to
            // serve: this test would wait for it instead of failing).
            assert!(is_missing(addr), "{addr:#x} is not missing");
            assert!(!host_readable(addr), "{addr:#x} is missing but accessible: a read would see zeros");
            let reader = std::thread::spawn(move || {
                // SAFETY: registered memory; the read waits for the fill.
                unsafe { core::ptr::read_volatile(addr as *const u8) }
            });
            let event = serve_one(user, ctx, fill);
            assert_eq!((event[0], event[1]), (proto::EVENT_PAGEFAULT2, addr));
            assert_eq!(reader.join().unwrap(), fill);
        };
        read_through_the_handler(mem + 3 * PAGE, 0x61);
        mprotect_of(unplugged, slot_len, crate::PROT_READ | crate::PROT_WRITE).expect("protect(false) at plug");
        read_through_the_handler(unplugged + 7 * PAGE, 0x62);
        // Unplug: discarded, then closed; its pages missing again.
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise(unplugged as *mut c_void, slot_len as usize, crate::MADV_DONTNEED) }, 0);
        let mut removed = [0u8; proto::RECORD];
        assert!(recv_all(user, &mut removed));
        assert_eq!(words(&removed)[0], proto::EVENT_REMOVE);
        mprotect_of(unplugged, slot_len, crate::PROT_NONE).expect("protect(true) at unplug");
        assert!(is_missing(unplugged + 7 * PAGE));
        // Plugged again: a userfault again.
        mprotect_of(unplugged, slot_len, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        read_through_the_handler(unplugged + 7 * PAGE, 0x63);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The protection of a committed page, from `VirtualQuery`.
    fn page_protection(addr: u64) -> u32 {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_ne!(unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
        mbi.Protect
    }

    /// An `mprotect` of registered memory that cannot be done changes none of
    /// its pages: here an executable protection, which the views of a
    /// range's sections do not allow (`EACCES`). The filled pages keep the
    /// protection they had, and a missing page filled afterwards takes the
    /// one given before, not the refused one.
    #[test]
    fn test_a_refused_mprotect_of_registered_memory_changes_nothing() {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(64 << 10);
        register(ctx, mem, 64 << 10).unwrap();
        let page = std::vec![0x5au8; PAGE as usize];
        for p in [0, 2] {
            // SAFETY: `page` holds a page.
            unsafe { copy(ctx, page.as_ptr(), mem + p * PAGE, PAGE, false) }.unwrap();
        }
        mprotect_of(mem, 4 * PAGE, crate::PROT_READ).unwrap();
        assert_eq!(page_protection(mem), PAGE_READONLY);
        let refused = mprotect_of(mem, 4 * PAGE, crate::PROT_READ | crate::PROT_WRITE | crate::PROT_EXEC).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(crate::EACCES), "{refused}");
        assert_eq!((page_protection(mem), page_protection(mem + 2 * PAGE)), (PAGE_READONLY, PAGE_READONLY));
        // SAFETY: `page` holds a page.
        unsafe { copy(ctx, page.as_ptr(), mem + PAGE, PAGE, false) }.unwrap();
        assert_eq!(page_protection(mem + PAGE), PAGE_READONLY);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The reclaim at the memory limit moves no chunk holding a live page
    /// `mprotect` closed: a move maps the chunk's new view read-write, which
    /// would open that page until its protection is given back. Two chunks
    /// with dead pages (every other page discarded): with a live page of the
    /// second made `PROT_READ`, only the first is a candidate; read-write
    /// again, both are.
    #[test]
    fn test_a_chunk_with_a_closed_live_page_is_not_moved() {
        let (ctx, user) = create(0, false, true).unwrap();
        let chunk = crate::windows_mm::UFFD_CHUNK as u64;
        let mem = map_noreserve(2 * chunk as usize);
        register(ctx, mem, 2 * chunk).unwrap();
        let page = std::vec![0x5au8; PAGE as usize];
        for p in (0..2 * chunk).step_by(PAGE as usize) {
            // SAFETY: `page` holds a page.
            unsafe { copy(ctx, page.as_ptr(), mem + p, PAGE, false) }.unwrap();
        }
        for p in (0..2 * chunk).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        let candidates = || {
            let _guard = lock();
            let mut c = Vec::with_capacity(256);
            find_candidates(&mut c);
            c.iter().map(|d| d.view as u64).filter(|v| (mem..mem + 2 * chunk).contains(v)).collect::<Vec<_>>()
        };
        assert_eq!(candidates().len(), 2, "both chunks hold dead pages");
        mprotect_of(mem + chunk + PAGE, PAGE, crate::PROT_READ).unwrap();
        assert_eq!(candidates(), std::vec![mem], "the chunk with a read-only live page is not moved");
        mprotect_of(mem + chunk + PAGE, PAGE, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        assert_eq!(candidates().len(), 2);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// An access its protection denies to a missing page of registered
    /// memory is the access fault (SIGSEGV on Linux; here the process ends
    /// with `STATUS_ACCESS_VIOLATION`), not a userfault: Linux checks the
    /// vma's protection before it faults the page in (v6.1
    /// arch/x86/mm/fault.c, `do_user_addr_fault`: `access_error` and
    /// `bad_area_access_error` at :1410 and :1411, before `handle_mm_fault`
    /// at :1428, where `do_anonymous_page` hands a missing page to
    /// userfaultfd). A read of a `PROT_NONE` page, and a write of a
    /// `PROT_READ` one, each in a child whose handler would say any event.
    #[test]
    fn test_a_registered_page_its_protection_denies_is_no_userfault() {
        for child in ["denied_read_child", "denied_write_child"] {
            let (code, text) = run_child(child, None);
            assert!(text.contains("UFFDDENIED accessing"), "{child}: {text}");
            assert!(!text.contains("UFFDDENIED event"), "{child}: a userfault for an access its protection denies: {text}");
            assert_eq!(code, Some(0xC000_0005_u32.cast_signed()), "{child}: {text}");
        }
    }

    fn denied_access(prot: c_int, write: bool) {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(64 << 10);
        register(ctx, mem, 64 << 10).unwrap();
        mprotect_of(mem, 64 << 10, prot).unwrap();
        std::thread::spawn(move || loop {
            let mut buf = [0u8; proto::RECORD];
            if !recv_all(user, &mut buf) {
                return;
            }
            let event = words(&buf);
            std::println!("UFFDDENIED event {:#x} at {:#x}", event[0], event[1]);
            let page = std::vec![0u8; PAGE as usize];
            // SAFETY: `page` holds a page.
            let _ = unsafe { copy(ctx, page.as_ptr(), event[1] - event[1] % PAGE, PAGE, true) };
        });
        std::println!("UFFDDENIED accessing");
        if write {
            // SAFETY: registered memory, which the access is to fault on.
            unsafe { core::ptr::write_volatile((mem + PAGE) as *mut u8, 1) };
        } else {
            // SAFETY: as above.
            core::hint::black_box(unsafe { core::ptr::read_volatile((mem + PAGE) as *const u8) });
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
        std::println!("UFFDDENIED the access went on");
    }

    #[test]
    #[ignore = "run by test_a_registered_page_its_protection_denies_is_no_userfault"]
    fn denied_read_child() {
        denied_access(crate::PROT_NONE, false);
    }

    #[test]
    #[ignore = "run by test_a_registered_page_its_protection_denies_is_no_userfault"]
    fn denied_write_child() {
        denied_access(crate::PROT_READ, true);
    }

    /// The state and protection of the page at `addr` (`VirtualQuery`):
    /// `None` for a page not committed, else its protection.
    fn committed_protection(addr: u64) -> Option<u32> {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQuery};
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_ne!(unsafe { VirtualQuery(addr as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) }, 0);
        (mbi.State == MEM_COMMIT).then_some(mbi.Protect)
    }

    /// Whether the host can read the page at `addr` without a fault: a
    /// committed page whose protection allows a read.
    fn host_readable(addr: u64) -> bool {
        matches!(committed_protection(addr), Some(p) if p == PAGE_READONLY || p == PAGE_READWRITE)
    }

    /// Registered memory of both kinds the backend has: an ordinary
    /// mapping (its missing pages `PAGE_NOACCESS`) and a `MAP_NORESERVE` one
    /// (a reserved section, its missing pages not committed), each with its
    /// userfaultfd; `f(kind, ctx, user, mem)` for each, 64 KiB registered.
    fn on_both_kinds(mut f: impl FnMut(&str, usize, c_int, u64)) {
        for (kind, mem) in [("ordinary", map(64 << 10)), ("reserved", map_noreserve(64 << 10))] {
            let (ctx, user) = create(0, false, true).unwrap();
            register(ctx, mem, 64 << 10).unwrap();
            f(kind, ctx, user, mem);
        }
    }

    /// The protection asked of a missing page is the one it has once
    /// filled: by a copy, by a zero page, and after a discard made it
    /// missing again and a copy filled it, as Linux's pages take their
    /// vma's protection (the macOS backend's test of the same name); while
    /// missing it stays inaccessible to the host, so an access is still a
    /// userfault.
    #[test]
    fn test_a_filled_page_takes_the_protection_asked_while_it_was_missing() {
        on_both_kinds(|kind, ctx, user, mem| {
            mprotect_of(mem, 2 * PAGE, crate::PROT_READ).unwrap();
            assert!(is_missing(mem) && !host_readable(mem), "{kind}: a missing page became accessible");
            let data = std::vec![0x5au8; PAGE as usize];
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}: copy");
            assert_eq!(zeropage(ctx, mem + PAGE, PAGE, true), Ok(PAGE));
            assert_eq!(committed_protection(mem + PAGE), Some(PAGE_READONLY), "{kind}: zeropage");
            // SAFETY: registered memory of the test's.
            assert_eq!(unsafe { crate::madvise(mem as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            assert!(is_missing(mem) && !host_readable(mem), "{kind}: discarded, the page is accessible");
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}: copy after a discard");
            // SAFETY: filled and readable.
            assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0x5a);
            release(ctx, user);
        });
    }

    /// A virtio-mem slot unplugged and plugged again after a restore through
    /// a userfaultfd, as Firecracker does it: a filled page made `PROT_NONE`
    /// (unplugged) or `PROT_READ`, then discarded (devices/virtio/mem
    /// `update_slot` before `discard_range`), then made read-write; the
    /// handler's next fill there lands, as on Linux, where the discard leaves
    /// the pages missing in their vma (the macOS backend's test of the same
    /// name, where the fill's alias had taken the page's protection and the
    /// process died by SIGBUS). Here the fill writes through the range's
    /// alias, a view of its own whose protection `mprotect` of the guest's
    /// view does not change; a fill made before the plug lands too and the
    /// page takes the protection asked.
    #[test]
    fn test_a_slot_unplugged_and_plugged_again_is_filled_through_its_alias() {
        for closed in [crate::PROT_NONE, crate::PROT_READ] {
            on_both_kinds(|kind, ctx, user, mem| {
                let data = std::vec![0x5au8; PAGE as usize];
                for p in 0..2 {
                    // SAFETY: `data` holds a page.
                    assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + p * PAGE, PAGE, true) }, Ok(PAGE));
                }
                mprotect_of(mem, 2 * PAGE, closed).unwrap();
                // SAFETY: registered memory of the test's.
                assert_eq!(unsafe { crate::madvise(mem as *mut c_void, 2 * PAGE as usize, crate::MADV_DONTNEED) }, 0);
                assert!(is_missing(mem) && is_missing(mem + PAGE), "{kind} {closed}: not missing after the discard");
                // The second page filled while still closed.
                let other = std::vec![0x6bu8; PAGE as usize];
                // SAFETY: `other` holds a page.
                assert_eq!(unsafe { copy(ctx, other.as_ptr(), mem + PAGE, PAGE, true) }, Ok(PAGE), "{kind} {closed}: a fill while closed");
                mprotect_of(mem, 2 * PAGE, crate::PROT_READ | crate::PROT_WRITE).unwrap();
                // SAFETY: `data` holds a page.
                assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, PAGE, true) }, Ok(PAGE), "{kind} {closed}: a fill after the plug");
                // SAFETY: filled just now, read-write.
                assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0x5a, "{kind} {closed}");
                // SAFETY: as above.
                assert_eq!(unsafe { core::ptr::read_volatile((mem + PAGE) as *const u8) }, 0x6b, "{kind} {closed}");
                assert_eq!(committed_protection(mem), Some(PAGE_READWRITE), "{kind} {closed}");
                assert_eq!(committed_protection(mem + PAGE), Some(PAGE_READWRITE), "{kind} {closed}");
                // SAFETY: filled and writable.
                unsafe { core::ptr::write_volatile((mem + PAGE) as *mut u8, 1) };
                release(ctx, user);
            });
        }
        // A whole chunk of a reserved section discarded: it gets a new
        // section, mapped anew in the guest's view and the alias
        // (`windows_mm::uffd_swap_chunk`).
        let chunk = crate::windows_mm::UFFD_CHUNK as u64;
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_noreserve(2 * chunk as usize);
        register(ctx, mem, 2 * chunk).unwrap();
        let slot = mem + chunk;
        let data = std::vec![0x5au8; PAGE as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), slot, PAGE, true) }, Ok(PAGE));
        mprotect_of(slot, chunk, crate::PROT_NONE).unwrap();
        // SAFETY: registered memory of the test's.
        assert_eq!(unsafe { crate::madvise(slot as *mut c_void, chunk as usize, crate::MADV_DONTNEED) }, 0);
        assert!(is_missing(slot), "a discarded chunk's page is not missing");
        mprotect_of(slot, chunk, crate::PROT_READ | crate::PROT_WRITE).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), slot, PAGE, true) }, Ok(PAGE), "a fill after a whole chunk was discarded");
        // SAFETY: filled just now, read-write.
        assert_eq!(unsafe { core::ptr::read_volatile(slot as *const u8) }, 0x5a);
        assert_eq!(committed_protection(slot), Some(PAGE_READWRITE));
        release(ctx, user);
    }

    /// Unregistered, a missing page gets the protection asked of it, as a
    /// Linux page has its vma's once no userfaultfd has it (the macOS
    /// backend's test of the same name): in a reserved section at its first
    /// access, which a read-only page allows, reading zeros.
    #[test]
    fn test_an_unregistered_page_takes_the_protection_asked_while_it_was_missing() {
        on_both_kinds(|kind, ctx, user, mem| {
            mprotect_of(mem, PAGE, crate::PROT_READ).unwrap();
            assert!(!host_readable(mem), "{kind}: a missing page is accessible");
            assert_eq!(unregister(ctx, mem, 64 << 10), Ok(()));
            // SAFETY: unregistered memory the protection lets the host read.
            assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0, "{kind}");
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}");
            release(ctx, user);
        });
    }

    /// Released with its userfaultfd, a missing page gets the protection
    /// asked of it, as a Linux page has its vma's once the userfaultfd is
    /// gone (fs/userfaultfd.c `userfaultfd_release` clears each vma's
    /// userfaultfd flags only; the macOS backend's test of the same name).
    #[test]
    fn test_a_released_page_takes_the_protection_asked_while_it_was_missing() {
        on_both_kinds(|kind, ctx, user, mem| {
            mprotect_of(mem, PAGE, crate::PROT_READ).unwrap();
            assert!(!host_readable(mem), "{kind}: a missing page is accessible");
            release(ctx, user);
            // SAFETY: released memory the protection lets the host read.
            assert_eq!(unsafe { core::ptr::read_volatile(mem as *const u8) }, 0, "{kind}");
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}");
        });
    }

    #[test]
    fn test_host_fault_copy_zeropage() {
        let (ctx, user) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        // A resident page keeps its content.
        // SAFETY: our mapping.
        unsafe { *(mem as *mut u8) = 7 };
        register(ctx, mem, len as u64).unwrap();
        assert!(!is_missing(mem));
        assert!(is_missing(mem + PAGE));

        // A host thread faults on a missing page and waits for the handler.
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        let event = serve_one(user, ctx, 0xab);
        assert_eq!(event[0], proto::EVENT_PAGEFAULT2);
        assert_eq!(event[1], mem + PAGE + 5);
        assert_eq!(event[2] & proto::FLAG_WRITE, 0);
        assert_eq!(reader.join().unwrap(), 0xab);
        // SAFETY: our mapping.
        assert_eq!(unsafe { *(mem as *const u8) }, 7);

        // A present page is refused; zeropage fills the next one.
        // SAFETY: a page of zeros.
        let zeros = std::vec![0u8; PAGE as usize];
        assert_eq!(unsafe { copy(ctx, zeros.as_ptr(), mem + PAGE, PAGE, true) }.unwrap_err().0, crate::EEXIST);
        assert_eq!(zeropage(ctx, mem + 2 * PAGE, PAGE, true).unwrap(), PAGE);
        // SAFETY: filled now.
        assert_eq!(unsafe { *((mem + 2 * PAGE) as *const u8) }, 0);

        // A write fault is flagged as one.
        let writer = std::thread::spawn(move || {
            // SAFETY: registered memory; the write waits for the fill.
            unsafe { core::ptr::write_volatile((mem + 3 * PAGE) as *mut u8, 9) }
        });
        let event = serve_one(user, ctx, 0);
        assert_eq!(event[2] & proto::FLAG_WRITE, proto::FLAG_WRITE);
        writer.join().unwrap();
        // SAFETY: filled now.
        assert_eq!(unsafe { *((mem + 3 * PAGE) as *const u8) }, 9);

        // MADV_DONTNEED makes registered pages missing again, with an event.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        let mut buf = [0u8; proto::RECORD];
        assert!(recv_all(user, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, mem + PAGE, mem + 2 * PAGE]);
        assert!(is_missing(mem + PAGE));
        // A refused discard (an unaligned start) makes nothing missing.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + 2 * PAGE + 1) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, -1);
        assert!(!is_missing(mem + 2 * PAGE));
        // The missing runs of a span as large as the address space, found
        // without a walk by pages over the memory nobody registered.
        // Other tests' registrations can lie right next to this one, and a
        // run of missing pages goes on across them
        // (`test_adjacent_ranges_stay_apart`): only the part of each run in
        // this range is this test's.
        let mut runs = Vec::new();
        for_each_missing(PAGE, u64::MAX / 2, |a, l| runs.push((a, l)));
        let end = mem + len as u64;
        let runs: Vec<_> = runs
            .into_iter()
            .filter_map(|(a, l)| {
                let (s, e) = (a.max(mem), (a + l).min(end));
                (s < e).then(|| (s, e - s))
            })
            .collect();
        assert_eq!(runs, [(mem + PAGE, PAGE), (mem + 4 * PAGE, len as u64 - 4 * PAGE)]);

        // Unregistered: missing pages read as zeros, nothing faults.
        unregister(ctx, mem, len as u64).unwrap();
        // SAFETY: ordinary memory now.
        assert_eq!(unsafe { *((mem + PAGE) as *const u8) }, 0);
        assert_eq!(unsafe { *((mem + 4 * PAGE) as *const u8) }, 0);
        // SAFETY: closes the user end; the serving thread ends.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The bytes of `[mem, mem + len)` committed.
    fn committed(mem: u64, len: u64) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        crate::windows_mm::committed_runs(mem as usize, len as usize).iter().map(|r| r.1 as u64).sum()
    }

    /// Registered memory is a reserved section, charged a page at a time as
    /// the handler fills it, as Linux charges the page a `UFFDIO_COPY`
    /// allocates to the memory cgroup (v6.1 mm/userfaultfd.c,
    /// `mcopy_atomic_pte`, `mem_cgroup_charge` at :205): at the registration
    /// only the resident page is committed and charged; each page filled is
    /// committed and charged; a discarded page keeps its commit (a
    /// section's page cannot be decommitted: SECTREC-h, error 87) and with it
    /// its charge, which pays for that commit, where Linux uncharges it; a
    /// refill charges it once; once unregistered, the discarded page is
    /// zeroed at its first access, and a page never filled is committed and
    /// charged at its first access, a read included, as a shmem page is; the
    /// charge goes with the mapping. Before, the whole section was committed at the
    /// registration and charged to no job.
    #[test]
    fn test_registered_memory_is_charged_as_it_is_filled() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * PAGE;
        let mem = map(len as usize);
        // SAFETY: our mapping.
        unsafe { *(mem as *mut u8) = 7 };
        register(ctx, mem, len).unwrap();
        assert!(range_of(ctx, mem, len).unwrap().reserved.load(Ordering::Acquire), "the section is not reserved");
        let charged = || crate::windows_mm::charged(mem as usize).expect("no charge for the range");
        assert_eq!(committed(mem, len), PAGE, "committed at the registration");
        assert_eq!(charged(), PAGE as usize, "charged at the registration");
        let data = std::vec![0x5au8; 3 * PAGE as usize];
        // SAFETY: `data` holds three pages.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + PAGE, 3 * PAGE, true) }.unwrap(), 3 * PAGE);
        assert_eq!(zeropage(ctx, mem + 8 * PAGE, PAGE, true).unwrap(), PAGE);
        assert_eq!(committed(mem, len), 5 * PAGE);
        assert_eq!(charged(), 5 * PAGE as usize);
        // SAFETY: filled pages.
        unsafe {
            assert_eq!(*(mem as *const u8), 7);
            assert_eq!(*((mem + 3 * PAGE + 9) as *const u8), 0x5a);
            assert_eq!(*((mem + 8 * PAGE) as *const u8), 0);
        }
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert!(is_missing(mem + PAGE));
        // Its charge kept, as its section page stays committed (SECTREC-h):
        // the charge pays for the host commit a page holds, so that no layer
        // counts more than wick's charge (in a chunk discarded whole both go,
        // `test_a_wholly_discarded_chunk_gives_its_section_commit_back`).
        assert_eq!(charged(), 5 * PAGE as usize, "a discarded page's charge");
        assert_eq!(committed(mem, len), 5 * PAGE);
        // Filled again and discarded again: charged once.
        assert_eq!(zeropage(ctx, mem + PAGE, PAGE, true).unwrap(), PAGE);
        assert_eq!(charged(), 5 * PAGE as usize, "a refilled page's charge");
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(charged(), 5 * PAGE as usize, "a page discarded twice");
        unregister(ctx, mem, len).unwrap();
        assert_eq!(charged(), 5 * PAGE as usize, "the discarded page's charge at the unregister");
        // SAFETY: ordinary memory now: the discarded page reads zeros, and
        // a page never filled is committed at its read.
        unsafe {
            assert_eq!(*((mem + PAGE) as *const u8), 0);
            assert_eq!(charged(), 5 * PAGE as usize, "the discarded page's charge after its first read");
            assert!(std::slice::from_raw_parts((mem + PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0));
            assert_eq!(*((mem + 3 * PAGE + 9) as *const u8), 0x5a);
            assert_eq!(*((mem + 20 * PAGE) as *const u8), 0);
            *((mem + 21 * PAGE) as *mut u8) = 1;
        }
        assert_eq!(committed(mem, len), 7 * PAGE);
        assert_eq!(charged(), 7 * PAGE as usize);
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, len as usize) }, 0);
        assert!(crate::windows_mm::charged(mem as usize).is_none(), "the charge outlived the mapping");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A discard of whole 2 MiB chunks of registered memory gives their
    /// section commit back, as Linux frees the pages `MADV_DONTNEED` zaps
    /// (a balloon's free page reporting gives 2 MiB blocks: v6.1
    /// mm/page_reporting.c, `pageblock_order`): the registration maps one
    /// section per chunk (`windows_mm::UFFD_CHUNK`), and a chunk discarded
    /// whole has a new, empty section put in its place in both views
    /// (UFFDCHUNK b: 8.7 us; WHP follows the host's address, UFFDCHUNK a).
    /// Two chunks and a part, filled by one copy across them (the fill split
    /// at each chunk's views): chunk 0 and half of chunk 1 discarded; chunk
    /// 0 then has no page committed nor charged, chunk 1 keeps its section's
    /// pages and their charge, its discarded half's included; each
    /// discarded page is missing again and a refill reads back; the charge
    /// follows each step. The range starts on a 2 MiB boundary, as
    /// Firecracker's guest memory does; its last, partial chunk of 16 pages,
    /// one view alone in its 2 MiB region at the range's edge, is not given a
    /// new section when discarded whole (`windows_mm::at_a_ranges_edge`,
    /// review B3): its pages are missing all the same, and keep their commit
    /// and charge until the range is unmapped.
    #[test]
    fn test_a_wholly_discarded_chunk_gives_its_section_commit_back() {
        const CHUNK: u64 = 2 << 20;
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK + 16 * PAGE;
        // At a 2 MiB boundary in address space found free; another test of
        // the suite may map there between the look and the map, so a
        // mapping placed elsewhere is given back and the look made again.
        let mut tries = 0;
        let mem = loop {
            let at = fresh_gib(1) + (64 << 20);
            // SAFETY: a new anonymous mapping, asked at a free address.
            let p = unsafe { crate::mmap(at as *mut c_void, len as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0) };
            assert_ne!(p, crate::MAP_FAILED);
            if p as usize == at {
                break p as u64;
            }
            // SAFETY: the mapping just made, ours.
            assert_eq!(unsafe { crate::munmap(p, len as usize) }, 0);
            tries += 1;
            assert!(tries < 8, "no free 2 MiB boundary held for the range in 8 tries");
        };
        register(ctx, mem, len).unwrap();
        assert!(range_of(ctx, mem, len).unwrap().reserved.load(Ordering::Acquire), "the section is not reserved");
        #[allow(clippy::cast_possible_truncation)]
        let charged = || -> u64 {
            [mem, mem + CHUNK, mem + 2 * CHUNK]
                .iter()
                .map(|&c| crate::windows_mm::charged(c as usize).expect("no charge for a chunk") as u64)
                .sum()
        };
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        assert_eq!(committed(mem, len), len);
        assert_eq!(charged(), len);
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise(mem as *mut c_void, (CHUNK + CHUNK / 2) as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(committed(mem, CHUNK), 0, "a chunk discarded whole keeps its section commit");
        assert_eq!(committed(mem + CHUNK, CHUNK), CHUNK, "a chunk discarded in part");
        // Chunk 0's charge goes with its section; chunk 1's discarded half
        // keeps its charge, as it keeps its section pages.
        assert_eq!(charged(), len - CHUNK);
        for at in [mem, mem + CHUNK - PAGE, mem + CHUNK, mem + CHUNK + CHUNK / 2 - PAGE] {
            assert!(is_missing(at), "{:#x} is not missing", at - mem);
        }
        assert!(!is_missing(mem + CHUNK + CHUNK / 2));
        // A refill of chunk 0, through its new section.
        let seven = std::vec![7u8; PAGE as usize];
        // SAFETY: a page-sized buffer.
        assert_eq!(unsafe { copy(ctx, seven.as_ptr(), mem + 5 * PAGE, PAGE, true) }.unwrap(), PAGE);
        // SAFETY: a filled page.
        assert_eq!(unsafe { *((mem + 5 * PAGE + 9) as *const u8) }, 7);
        assert_eq!(committed(mem, CHUNK), PAGE);
        assert_eq!(charged(), len - CHUNK + PAGE);
        // SAFETY: a page of chunk 1 not discarded.
        assert_eq!(unsafe { *((mem + CHUNK + CHUNK / 2) as *const u8) }, 0x5a);
        // The last chunk, of 16 pages, discarded whole: at the range's edge.
        // Counted on this thread, where the discard's swap is refused: the
        // process's count also takes the edge refusals of the suite's other
        // tests running meanwhile (their 64 KiB ranges discarded whole),
        // which once made it 2 here (Windows Server 2025 26100).
        let refused = crate::windows_mm::edge_refused_on_this_thread_for_tests();
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise((mem + 2 * CHUNK) as *mut c_void, 16 * PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(crate::windows_mm::edge_refused_on_this_thread_for_tests(), refused + 1, "the last chunk's swap, at the range's edge");
        assert!((0..16).all(|p| is_missing(mem + 2 * CHUNK + p * PAGE)), "the last chunk's pages");
        assert_eq!(committed(mem + 2 * CHUNK, 16 * PAGE), 16 * PAGE, "the last chunk discarded in place");
        assert_eq!(charged(), CHUNK + PAGE + 16 * PAGE);
        unregister(ctx, mem, len).unwrap();
        // SAFETY: our mapping, unregistered: every page reads, the
        // discarded ones as zeros.
        unsafe {
            assert_eq!(*((mem + 6 * PAGE) as *const u8), 0);
            assert_eq!(*((mem + CHUNK) as *const u8), 0);
            assert_eq!(*((mem + 2 * CHUNK + 3 * PAGE) as *const u8), 0);
            assert_eq!(*((mem + 5 * PAGE) as *const u8), 7);
            assert_eq!(*((mem + 2 * CHUNK - PAGE) as *const u8), 0x5a);
        }
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, len as usize) }, 0);
        for c in [mem, mem + CHUNK, mem + 2 * CHUNK] {
            assert!(crate::windows_mm::charged(c as usize).is_none(), "a chunk's charge outlived the mapping");
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// In a process whose job may commit 64 MiB, 256 MiB are registered and
    /// filled 1 MiB at a time: the fill the limit refuses after the reclaim
    /// ends the process with 137 and a line naming the fill, as Linux's
    /// memory cgroup kills the VMM at the copy it cannot charge
    /// (`windows_mm::fill_out_of_memory`; measured on Linux 7.0: the VMM
    /// SIGKILLed, no copy refused while it lived). Between 16 and 64 MiB are
    /// filled first. Before, that fill was `ENOMEM` and the process went on;
    /// before that, the 256 MiB were committed at the registration and no
    /// job charged them.
    #[test]
    fn test_a_fill_past_the_job_limit_ends_the_vmm_with_137() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        let exe = std::env::current_exe().unwrap();
        // The child's name as libtest knows it: this module is the crate's
        // `wick_uffd` (lib.rs's `#[path]`), not its file's name (CI run
        // 43528910212 ran "windows_uffd::tests::fill_limit_child": no test).
        let name = std::format!("{}::fill_limit_child", module_path!().split_once("::").unwrap().1);
        let child = std::process::Command::new(exe)
            .args(["--exact", name.as_str(), "--ignored", "--nocapture"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // The job is set before the child registers anything (it sleeps 300 ms first).
        // SAFETY: a new unnamed job.
        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        assert!(!job.is_null());
        // SAFETY: plain data.
        let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
        limit.JobMemoryLimit = 64 << 20;
        // SAFETY: a structure of the size passed; the child's handle.
        unsafe {
            #[allow(clippy::cast_possible_truncation)]
            let size = std::mem::size_of_val(&limit) as u32;
            assert_ne!(SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const limit).cast(), size), 0);
            use std::os::windows::io::AsRawHandle;
            assert_ne!(AssignProcessToJobObject(job, child.as_raw_handle()), 0, "{}", io::Error::last_os_error());
        }
        let out = child.wait_with_output().unwrap();
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        // SAFETY: our job handle.
        unsafe { CloseHandle(job) };
        assert!(text.contains("running 1 test"), "the child {name} ran no test (status {}): {text}", out.status);
        assert!(text.contains("registered 256 MiB"), "the child did not register (status {}): {text}", out.status);
        let line = text.lines().find(|l| l.starts_with("wick: userfaultfd: the fill of 1048576 bytes at "));
        assert!(line.is_some_and(|l| l.contains("after the reclaim") && l.contains("the VMM ends")), "no line for the fill: {text}");
        std::eprintln!("{}", line.unwrap());
        // The fill's address, against the mapping's: between 16 and 64 MiB in.
        let at = |l: &str, key: &str| -> u64 {
            let h = l.split(key).nth(1).unwrap().trim_start_matches("0x");
            u64::from_str_radix(h.split(|c: char| !c.is_ascii_hexdigit()).next().unwrap(), 16).unwrap()
        };
        let mem = at(text.lines().find(|l| l.starts_with("registered 256 MiB at ")).unwrap(), "at ");
        let dst = at(line.unwrap(), "bytes at ");
        assert!((16 << 20..64 << 20).contains(&(dst - mem)), "the fill ended the process {} MiB in: {text}", (dst - mem) >> 20);
        assert_eq!(out.status.code(), Some(137), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_past_the_job_limit_ends_the_vmm_with_137 in a job of its own"]
    fn fill_limit_child() {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (ctx, user) = create(0, false, true).unwrap();
        let len: u64 = 256 << 20;
        // As Firecracker maps guest memory: committed at first touch, so the
        // mapping itself fits the job.
        // SAFETY: a new anonymous mapping.
        let mem = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        register(ctx, mem, len).unwrap();
        std::println!("registered 256 MiB at {mem:#x}");
        let mib: u64 = 1 << 20;
        let mut done = 0;
        let refused = loop {
            assert!(done < len, "256 MiB filled under a 64 MiB limit");
            match zeropage(ctx, mem + done, mib, false) {
                Ok(n) => done += n,
                Err((e, n)) => break (e, n),
            }
        };
        // Only if the process was not ended at the limit.
        std::println!("refused with {} after {} MiB", if refused.0 == crate::ENOMEM { "ENOMEM" } else { "another error" }, done >> 20);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Runs the child test `child` (this module's, `#[ignore]`d) in a
    /// process of its own, in a job that may commit `limit` bytes if one is
    /// given (set before the child registers anything: it sleeps 300 ms
    /// first): its exit status and output.
    fn run_child(child: &str, limit: Option<usize>) -> (Option<i32>, std::string::String) {
        run_child_with(child, limit, &[])
    }

    /// [`run_child`] with `env` added to the child's environment.
    fn run_child_with(child: &str, limit: Option<usize>, env: &[(&str, &str)]) -> (Option<i32>, std::string::String) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, SetInformationJobObject,
        };
        let name = std::format!("{}::{child}", module_path!().split_once("::").unwrap().1);
        let process = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name.as_str(), "--ignored", "--nocapture"])
            .envs(env.iter().copied())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut job = ptr::null_mut();
        if let Some(limit) = limit {
            // SAFETY: a new unnamed job.
            job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            assert!(!job.is_null());
            // SAFETY: plain data.
            let mut l: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            l.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
            l.JobMemoryLimit = limit;
            // SAFETY: a structure of the size passed; the child's handle.
            unsafe {
                #[allow(clippy::cast_possible_truncation)]
                let size = std::mem::size_of_val(&l) as u32;
                assert_ne!(SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const l).cast(), size), 0);
                use std::os::windows::io::AsRawHandle;
                assert_ne!(AssignProcessToJobObject(job, process.as_raw_handle()), 0, "{}", io::Error::last_os_error());
            }
        }
        let out = process.wait_with_output().unwrap();
        if !job.is_null() {
            // SAFETY: our job handle.
            unsafe { CloseHandle(job) };
        }
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&out.stdout), std::string::String::from_utf8_lossy(&out.stderr));
        assert!(text.contains("running 1 test"), "the child {name} ran no test (status {}): {text}", out.status);
        (out.status.code(), text)
    }

    const CHUNK: u64 = 2 << 20;

    /// The reclaim tests' start, in a child under a job limit: 128 MiB
    /// registered and filled with 0x5a 1 MiB at a time until the job
    /// refuses, then every other page of its first 8 chunks discarded (8
    /// MiB of dead pages, no chunk whole, so each keeps its section commit
    /// and charge, as (A) has them). The range and the bytes filled.
    #[track_caller]
    fn fill_to_the_limit_and_discard_in_part() -> (usize, c_int, u64, u64) {
        let (ctx, user, mem, done) = fill_to_the_limit();
        assert!(done >= 8 * CHUNK + (8 << 20), "only {} MiB filled", done >> 20);
        for p in (0..8 * CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        (ctx, user, mem, done)
    }

    /// 128 MiB registered and filled with 0x5a 1 MiB at a time until the
    /// job refuses: the range and the bytes filled.
    #[track_caller]
    fn fill_to_the_limit() -> (usize, c_int, u64, u64) {
        fill_to_the_limit_from(0)
    }

    /// Set by the reclaim tests ([`fill_to_the_limit_from`]): a fill the
    /// limit still refuses after the reclaim answers `ENOMEM` instead of
    /// ending the process. These tests find the limit by filling to it and
    /// then look at what the reclaim does there; the product's ending is
    /// [`test_a_fill_past_the_job_limit_ends_the_vmm_with_137`]'s, which
    /// leaves this off.
    pub(crate) static REFUSED_FILL_IS_ENOMEM: AtomicBool = AtomicBool::new(false);

    /// The waits a fill refused at the limit began and ended for the calls
    /// in their copy on the chunks its reclaim passed over ([`wait_and_move`]).
    pub(crate) static FILL_WAITS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static FILL_WAITED: AtomicU64 = AtomicU64::new(0);

    /// [`fill_to_the_limit`], the fill begun `from` bytes in: the pages
    /// before are never filled. A fill refused at the limit is `ENOMEM`
    /// in this process from here ([`REFUSED_FILL_IS_ENOMEM`]).
    #[track_caller]
    fn fill_to_the_limit_from(from: u64) -> (usize, c_int, u64, u64) {
        fill_to_the_limit_at(0, from)
    }

    /// [`fill_to_the_limit_from`], the range mapped at `at` if it is not 0
    /// (a free address of a 64 KiB boundary, [`fresh_gib`]).
    #[track_caller]
    fn fill_to_the_limit_at(at: usize, from: u64) -> (usize, c_int, u64, u64) {
        REFUSED_FILL_IS_ENOMEM.store(true, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(300));
        make_the_slack_region();
        let (ctx, user) = create(0, false, true).unwrap();
        let len: u64 = 128 << 20;
        // SAFETY: a new anonymous mapping, committed at first touch.
        let mem = unsafe {
            crate::mmap(
                at as *mut c_void,
                len as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(mem, crate::MAP_FAILED);
        assert!(at == 0 || mem as usize == at, "the range at {mem:p}, asked at {at:#x}");
        let mem = mem as u64;
        if at == 0 {
            on_a_boundary(mem);
        }
        register(ctx, mem, len).unwrap();
        let mib = std::vec![0x5au8; 1 << 20];
        // 1 MiB of room kept for the test's own heap and given back after the
        // fills, as the 1 MiB fill the limit refused whole left room before
        // a refused fill filled the pages that fit.
        // SAFETY: a new commit of ours, freed below.
        let spare = unsafe {
            use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, VirtualAlloc};
            VirtualAlloc(ptr::null(), 1 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        };
        assert!(!spare.is_null());
        let mut done = from;
        loop {
            assert!(done < len, "128 MiB filled under the limit");
            // SAFETY: `mib` holds 1 MiB.
            match unsafe { copy(ctx, mib.as_ptr(), mem + done, 1 << 20, false) } {
                Ok(n) => done += n,
                // The pages that fitted, as Linux's copy answers for the
                // pages it filled before a charge it could not make.
                Err((e, n)) if e == crate::EAGAIN && n > 0 => done += n,
                Err((e, _)) => {
                    assert_eq!(e, crate::ENOMEM);
                    break;
                }
            }
        }
        // SAFETY: our commit above.
        unsafe { windows_sys::Win32::System::Memory::VirtualFree(spare, 0, windows_sys::Win32::System::Memory::MEM_RELEASE) };
        std::println!("filled {} MiB", done >> 20);
        (ctx, user, mem, done)
    }

    /// The process's private commit (`PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`),
    /// which the job's memory limit counts.
    fn private_commit() -> usize {
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_faults: u32,
            sizes: [usize; 10],
        }
        let mut c = Counters { cb: u32::try_from(std::mem::size_of::<Counters>()).unwrap(), ..Counters::default() };
        // SAFETY: this process's pseudo handle and a structure of the size
        // given (PROCESS_MEMORY_COUNTERS_EX).
        let ok = unsafe {
            windows_sys::Win32::System::ProcessStatus::K32GetProcessMemoryInfo(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                (&raw mut c).cast(),
                c.cb,
            )
        };
        assert_ne!(ok, 0);
        c.sizes[8]
    }

    /// Takes every 4 KiB of the job's room left, each page a commit of its
    /// own so that the caller can give it back a page at a time; the pages.
    fn take_every_page() -> std::vec::Vec<usize> {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        let mut held = std::vec::Vec::with_capacity(1 << 16);
        // From here the job has no room: the locks are taken as the product
        // takes them. The watch's frames and its record's lines are deeper
        // than the product's, and a thread whose committed stack ends just
        // below the product's path (the userfaultfd's serve thread in
        // `destroy`, through the release's lazy pages and the region
        // table's search)
        // needed a new page for them, which the limit refused: 10 of 480
        // fills at the limit ended so with the watch (9 with 137, 1 with
        // STATUS_HEAP_CORRUPTION), 0 of 480 with the watch off for the whole
        // test, and 2 of 480 with it off from here (Windows Server 2022
        // 20348, STACK137FRAMES). Those two are the product's own: the same
        // thread in `destroy`, growing its Vec of missing runs, was refused
        // a stack page inside ntdll's heap code (RtlpAllocateHeap under
        // RtlReAllocateHeap). That end is open (COMPATIBILITY.md, the
        // memory.max row); the watch is off here so that it is the
        // product's frames this test runs at the limit.
        crate::windows_stacklock::WATCHING.store(false, Ordering::SeqCst);
        while held.len() < held.capacity() {
            // SAFETY: new private memory of ours.
            let p = unsafe { VirtualAlloc(ptr::null(), PAGE as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
            if p.is_null() {
                break;
            }
            held.push(p as usize);
        }
        held
    }

    /// A region of 2 MiB reserved, its first page committed (so its page
    /// table is there) before the limit is reached, for [`no_room_left`]'s
    /// last pages: a page that `VirtualAlloc` refuses at the limit, as a new
    /// allocation needs a page table too, may still be committed where one
    /// is, as a fill's page in a mapped view is (on Windows Server 2022
    /// 20348, fc-win: a fill made with every `VirtualAlloc` of a page
    /// refused). Its base, and the pages past the first committed.
    static SLACK: AtomicUsize = AtomicUsize::new(0);
    static SLACK_TAKEN: AtomicUsize = AtomicUsize::new(0);

    fn make_the_slack_region() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        // SAFETY: new memory of ours.
        let p = unsafe { VirtualAlloc(ptr::null(), CHUNK as usize, MEM_RESERVE, PAGE_READWRITE) };
        assert!(!p.is_null());
        // SAFETY: the first page of the region just reserved.
        assert!(!unsafe { VirtualAlloc(p, PAGE as usize, MEM_COMMIT, PAGE_READWRITE) }.is_null());
        SLACK.store(p as usize, Ordering::SeqCst);
    }

    /// Commits the slack region's pages ([`SLACK`]) one at a time until the
    /// job refuses; how many.
    fn take_the_slack() -> usize {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, PAGE_READWRITE, VirtualAlloc};
        let base = SLACK.load(Ordering::SeqCst);
        if base == 0 {
            return 0;
        }
        let mut n = SLACK_TAKEN.load(Ordering::SeqCst);
        while (n + 2) * (PAGE as usize) <= CHUNK as usize {
            // SAFETY: a page of our region.
            if unsafe { VirtualAlloc((base + (n + 1) * PAGE as usize) as *const c_void, PAGE as usize, MEM_COMMIT, PAGE_READWRITE) }.is_null() {
                break;
            }
            n += 1;
        }
        SLACK_TAKEN.store(n, Ordering::SeqCst);
        n
    }

    /// Gives back what [`take_the_slack`] took.
    fn give_back_the_slack() {
        use windows_sys::Win32::System::Memory::{MEM_DECOMMIT, VirtualFree};
        let (base, n) = (SLACK.load(Ordering::SeqCst), SLACK_TAKEN.swap(0, Ordering::SeqCst));
        if base != 0 && n != 0 {
            // SAFETY: pages of our region.
            unsafe { VirtualFree((base + PAGE as usize) as *mut c_void, n * PAGE as usize, MEM_DECOMMIT) };
        }
    }

    /// Gives back one page [`take_every_page`] took.
    fn give_back_a_page(held: &mut std::vec::Vec<usize>) {
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
        let p = held.pop().expect("a page held");
        // SAFETY: a page of ours.
        unsafe { VirtualFree(p as *mut c_void, 0, MEM_RELEASE) };
    }

    /// No room left in the job (the lesson of CI run 43640510155: a reclaim
    /// that moved with room left was never tried where it runs): this
    /// thread's stack grown first (a stack that must grow at the limit ends
    /// the process: `test_a_stack_that_grows_at_the_limit_on_record`), then
    /// every page of the job's room taken ([`take_every_page`]), said on
    /// standard error without allocating. The pages, to give back.
    fn no_room_left() -> std::vec::Vec<usize> {
        core::hint::black_box(deep(32));
        let held = take_every_page();
        let slack = take_the_slack();
        crate::windows_mm::say_at_the_limit(format_args!(
            "room left before the reclaim: 0 KiB ({} pages taken, and {slack} where a page table was)",
            held.len()
        ));
        held
    }

    /// Gives back every page [`take_every_page`] took, and the slack
    /// region's ([`take_the_slack`]).
    fn give_back_every_page(held: &mut std::vec::Vec<usize>) {
        give_back_the_slack();
        while !held.is_empty() {
            give_back_a_page(held);
        }
    }

    /// VIEWCHARGE: what mapping a view of a pagefile-backed section takes of
    /// the process's private commit, which the job's memory limit counts
    /// (Learn, JOBOBJECT_EXTENDED_LIMIT_INFORMATION: JobMemoryLimit is "the
    /// limit for the virtual memory that can be committed for the job",
    /// with no list of what counts; that a view's page tables count is
    /// measured, not documented): a, under 1 GiB, a section of 64 KiB, 2 MiB
    /// and 16 MiB, `SEC_RESERVE` and `SEC_COMMIT`, read-write and read-only:
    /// the section, a view anywhere, a second view, a view into a
    /// placeholder, all three unmapped; b, at the job's limit with all its
    /// room taken a page at a time, then given back 4 KiB at a time: whether
    /// a 2 MiB `SEC_RESERVE` view is mapped anywhere and into a
    /// placeholder, the error, and what the map took. On Windows Server
    /// 2022 20348 (fc-win): 4 KiB a 2 MiB view and 32 KiB a 16 MiB one (a
    /// page table a 2 MiB), in every case, given back at the unmap; at the
    /// limit, error 1455 with no room, a view anywhere with 4 KiB, a view
    /// into a placeholder made apart from any other mapping from 8 KiB in
    /// one run and 12 KiB in another (a page directory's page as well). It is why the reclaim's move could not start at a real job
    /// limit (CI run 43640510155). Printed, not asserted, but for the
    /// children ending well.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_what_a_view_mapping_charges_on_record() {
        let (code, text) = run_child("view_charge_child", Some(1 << 30));
        std::eprintln!("{text}");
        assert_eq!(code, Some(0), "{text}");
        let (code, text) = run_child("view_limit_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_what_a_view_mapping_charges_on_record in a job of its own"]
    fn view_charge_child() {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER, MEM_RELEASE, MapViewOfFile3,
            PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, SEC_COMMIT, SEC_RESERVE, UnmapViewOfFile, VirtualAlloc2, VirtualFree,
        };
        // SAFETY: this process's pseudo handle.
        let me = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        let kib = |a: usize, b: usize| (b as i64 - a as i64) / 1024;
        for len in [64usize << 10, 2 << 20, 16 << 20] {
            for (kind, flag) in [("SEC_RESERVE", SEC_RESERVE), ("SEC_COMMIT", SEC_COMMIT)] {
                let p0 = private_commit();
                #[allow(clippy::cast_possible_truncation)]
                // SAFETY: a new pagefile-backed section.
                let sec = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | flag, 0, len as u32, ptr::null()) };
                assert!(!sec.is_null());
                let p1 = private_commit();
                for (access, prot) in [("read-write", PAGE_READWRITE), ("read-only", PAGE_READONLY)] {
                    let a = private_commit();
                    // SAFETY: maps our section anywhere.
                    let v1 = unsafe { MapViewOfFile3(sec, me, ptr::null(), 0, len, 0, prot, ptr::null_mut(), 0) };
                    let b = private_commit();
                    // SAFETY: as above.
                    let v2 = unsafe { MapViewOfFile3(sec, me, ptr::null(), 0, len, 0, prot, ptr::null_mut(), 0) };
                    let c = private_commit();
                    // SAFETY: reserves a placeholder of ours.
                    let ph = unsafe { VirtualAlloc2(me, ptr::null(), len, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, ptr::null_mut(), 0) };
                    let d = private_commit();
                    // SAFETY: maps our section into our placeholder.
                    let v3 = unsafe { MapViewOfFile3(sec, me, ph, 0, len, MEM_REPLACE_PLACEHOLDER, prot, ptr::null_mut(), 0) };
                    let e = private_commit();
                    assert!(!v1.Value.is_null() && !v2.Value.is_null() && v3.Value == ph);
                    // SAFETY: the views mapped here.
                    unsafe {
                        UnmapViewOfFile(v1);
                        UnmapViewOfFile(v2);
                        UnmapViewOfFile(v3);
                    }
                    let f = private_commit();
                    std::println!(
                        "VIEWCHARGE a {} KiB {kind} {access}: the section {:+} KiB, a view anywhere {:+} KiB, a second view {:+} KiB, \
                         a placeholder {:+} KiB, a view into it {:+} KiB; after the three unmapped {:+} KiB",
                        len >> 10,
                        kib(p0, p1),
                        kib(a, b),
                        kib(b, c),
                        kib(c, d),
                        kib(d, e),
                        kib(a, f)
                    );
                    // SAFETY: the placeholder the view left.
                    unsafe { VirtualFree(ph, 0, MEM_RELEASE) };
                }
                // SAFETY: our section's handle.
                unsafe { CloseHandle(sec) };
            }
        }
    }

    #[test]
    #[ignore = "run by test_what_a_view_mapping_charges_on_record in a job of its own"]
    fn view_limit_child() {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE, MEM_RESERVE_PLACEHOLDER,
            MapViewOfFile3, PAGE_NOACCESS, PAGE_READWRITE, SEC_RESERVE, UnmapViewOfFile, UnmapViewOfFile2, VirtualAlloc2, VirtualFree,
        };
        const STEPS: [usize; 12] = [0, 4, 8, 12, 16, 24, 32, 64, 256, 1024, 2048, 4096];
        // SAFETY: this process's pseudo handle.
        let me = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        // Made, and the results' room kept, before the room is taken: at
        // the limit nothing may allocate, nor print (a stack that grows
        // there cannot: test_a_stack_that_grows_at_the_limit_on_record).
        // SAFETY: new pagefile-backed sections and placeholders.
        let made: std::vec::Vec<_> = (0..STEPS.len())
            .map(|_| unsafe {
                (
                    CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, 2 << 20, ptr::null()),
                    CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, 2 << 20, ptr::null()),
                    VirtualAlloc2(me, ptr::null(), 2 << 20, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, ptr::null_mut(), 0),
                )
            })
            .collect();
        assert!(made.iter().all(|m| !m.0.is_null() && !m.1.is_null() && !m.2.is_null()));
        let mut results = [(0usize, false, 0u32, 0i64, false, 0u32); STEPS.len()];
        let mut held = take_every_page();
        let taken = held.len();
        let mut given = 0;
        for (i, &room) in STEPS.iter().enumerate() {
            while given < room {
                give_back_a_page(&mut held);
                given += 4;
            }
            let a = private_commit();
            // SAFETY: maps our section anywhere.
            let v = unsafe { MapViewOfFile3(made[i].0, me, ptr::null(), 0, 2 << 20, 0, PAGE_READWRITE, ptr::null_mut(), 0) };
            // SAFETY: plain call.
            let e1 = if v.Value.is_null() { unsafe { GetLastError() } } else { 0 };
            let b = private_commit();
            // SAFETY: maps our section into our placeholder.
            let w = unsafe { MapViewOfFile3(made[i].1, me, made[i].2, 0, 2 << 20, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, ptr::null_mut(), 0) };
            // SAFETY: plain call.
            let e2 = if w.Value == made[i].2 { 0 } else { unsafe { GetLastError() } };
            results[i] = (room, !v.Value.is_null(), e1, (b as i64 - a as i64) / 1024, w.Value == made[i].2, e2);
            // SAFETY: the views mapped here.
            unsafe {
                if !v.Value.is_null() {
                    UnmapViewOfFile(v);
                }
                if w.Value == made[i].2 {
                    UnmapViewOfFile2(me, w, MEM_PRESERVE_PLACEHOLDER);
                }
            }
        }
        while !held.is_empty() {
            give_back_a_page(&mut held);
        }
        std::println!("VIEWCHARGE b: the job's room taken, {taken} pages, then given back 4 KiB at a time");
        for (room, any, e1, took, ph, e2) in results {
            std::println!(
                "VIEWCHARGE b room {room} KiB: a 2 MiB view anywhere {} (took {took:+} KiB), into a placeholder {}",
                if any { "mapped".into() } else { std::format!("refused, error {e1}") },
                if ph { "mapped".into() } else { std::format!("refused, error {e2}") }
            );
        }
        for (s1, s2, ph) in made {
            // SAFETY: ours.
            unsafe {
                CloseHandle(s1);
                CloseHandle(s2);
                VirtualFree(ph, 0, MEM_RELEASE);
            }
        }
    }

    /// MOVEROOM: the room the reclaim's move needs at the job's limit: the
    /// reclaim tests' start (8 chunks with half their pages dead), then all
    /// the room taken a page at a time and a fill's reclaim
    /// (`reclaim_for_a_fill`) tried with 0 KiB of room, then 4 KiB more each
    /// time, until it moves a chunk: how many chunks each try moved, the
    /// bytes it freed and what the process's private commit did. On Windows
    /// Server 2022 20348 (fc-win), before a move gave back part of its dead
    /// pages' charge for its maps (fc102ff6): none with no room (the move's
    /// map of its new section's view refused, 1455), 2 chunks and 2 MiB with
    /// 4 KiB: one page table, its own view's (the alias's and the guest
    /// view's swaps give back what they take); since, 2 chunks and 2 MiB
    /// with 0 KiB. Printed, not asserted, but for the child ending well.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_the_room_a_move_needs_on_record() {
        let (code, text) = run_child("move_room_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_room_a_move_needs_on_record in a job of its own"]
    fn move_room_child() {
        let (ctx, user, _mem, _) = fill_to_the_limit_and_discard_in_part();
        let mut tries = [(0usize, Reclaimed::default(), 0i64); 16];
        let mut held = take_every_page();
        let taken = held.len();
        let mut n = 0;
        while n < tries.len() {
            let before = private_commit();
            let r = {
                let _guard = lock();
                reclaim_for_a_fill(PAGE as usize, &mut Default::default())
            };
            tries[n] = (n * 4, r, (private_commit() as i64 - before as i64) / 1024);
            n += 1;
            if r.chunks > 0 || held.is_empty() {
                break;
            }
            give_back_a_page(&mut held);
        }
        while !held.is_empty() {
            give_back_a_page(&mut held);
        }
        std::println!("MOVEROOM the job's room taken, {taken} pages, then given back 4 KiB at a time");
        for (room, r, delta) in &tries[..n] {
            std::println!("MOVEROOM room {room} KiB: {} chunks moved, {} KiB freed, private commit {delta:+} KiB", r.chunks, r.freed >> 10);
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let _ = ctx;
    }

    /// The calling thread's stack from its TEB (x86-64): its base, the
    /// lowest committed address, the reserve's low end (DeallocationStack,
    /// 0x1478) and the stack guarantee (GuaranteedStackBytes, 0x1748).
    fn stack_of_this_thread() -> (usize, usize, usize, u32) {
        let (base, limit, reserve, guarantee): (usize, usize, usize, u32);
        // SAFETY: reads of the thread's own TEB.
        unsafe {
            core::arch::asm!(
                "mov {0}, gs:[0x8]",
                "mov {1}, gs:[0x10]",
                "mov {2}, gs:[0x1478]",
                "mov {3:e}, gs:[0x1748]",
                out(reg) base,
                out(reg) limit,
                out(reg) reserve,
                out(reg) guarantee,
                options(nostack, readonly, preserves_flags)
            );
        }
        (base, limit, reserve, guarantee)
    }

    const STACK_PAINT: u8 = 0x5c;

    /// This thread's stack grown 128 KiB below here and painted from its
    /// lowest committed byte to 256 bytes below here: the painted range.
    #[inline(never)]
    fn paint_below_here() -> (usize, usize) {
        core::hint::black_box(deep(32));
        let (_, limit, _, _) = stack_of_this_thread();
        let here = core::hint::black_box(&limit) as *const usize as usize;
        let top = (here - 256) & !15;
        // SAFETY: the thread's own committed stack below its frames.
        unsafe { core::ptr::write_bytes(limit as *mut u8, STACK_PAINT, top - limit) };
        (limit, top)
    }

    /// How far below the top of [`paint_below_here`]'s range the paint was
    /// written over.
    fn used_below((limit, top): (usize, usize)) -> usize {
        let mut at = limit;
        // SAFETY: the thread's own committed stack.
        while at < top && unsafe { core::ptr::read_volatile(at as *const u8) } == STACK_PAINT {
            at += 1;
        }
        top - at
    }

    /// 64 KiB of stack, a page a frame: a thread whose stack must grow.
    #[inline(never)]
    fn deep(n: usize) -> u8 {
        let a = core::hint::black_box([n as u8; 4096]);
        if n == 0 { a[7] } else { a[9].wrapping_add(deep(n - 1)) }
    }

    /// STACKZERO: a thread whose stack must grow at the job's limit, the
    /// room taken a page at a time, against the same thread with room
    /// (the control) and a stack overflowed with room (its reserve used
    /// up): how each child ended, and the threads' stacks from their TEB
    /// before. Learn, "Thread Stack Size": the system commits stack pages
    /// as needed "until either the stack reaches the reserved size minus
    /// one page (which is used as a guard page to prevent stack overflow)
    /// or the system is so low on memory that the operation fails"; both
    /// raise STATUS_STACK_OVERFLOW. On Windows Server 2022 20348 (fc-win):
    /// the thread at the limit ended its process with 0xC00000FD, 32 KiB of
    /// its stack committed, where Linux charges a stack page as any other
    /// and its memory cgroup's out-of-memory kill ends the process (137).
    /// Its children map no lazy memory, so the stack filter that ends such a
    /// process with 137 is not in place (`windows_mm::stack_filter`,
    /// `test_a_stack_that_must_grow_at_the_limit_ends_with_137`): the record
    /// of what Windows does by itself. Printed, not asserted, but for the
    /// control ending well.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_a_stack_that_grows_at_the_limit_on_record() {
        for (child, limit) in [("stack_at_the_limit_child", Some(96 << 20)), ("stack_with_room_child", None), ("stack_overflowed_child", None)] {
            let (code, text) = run_child(child, limit);
            #[allow(clippy::cast_sign_loss)]
            let ended = code.map_or_else(|| "no exit code".into(), |c| std::format!("{:#x}", c as u32));
            std::eprintln!("STACKZERO {child}: ended with {ended}; {}", text.trim().replace('\n', " | "));
            if child == "stack_with_room_child" {
                assert_eq!(code, Some(0), "{text}");
            }
        }
    }

    fn a_thread_that_goes_deep(go_at_once: bool, depth: usize) -> (std::thread::JoinHandle<u8>, std::sync::mpsc::Sender<()>) {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (said, heard) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let (base, limit, reserve, guarantee) = stack_of_this_thread();
            std::println!(
                "the thread's stack: {} KiB committed of a {} KiB reserve, a guarantee of {guarantee} bytes",
                (base - limit) >> 10,
                (base - reserve) >> 10
            );
            said.send(()).unwrap();
            if !go_at_once {
                rx.recv().unwrap();
            }
            deep(depth)
        });
        heard.recv().unwrap();
        (t, tx)
    }

    #[test]
    #[ignore = "run by test_a_stack_that_grows_at_the_limit_on_record in a job of its own"]
    fn stack_at_the_limit_child() {
        let (t, go) = a_thread_that_goes_deep(false, 16);
        let held = take_every_page();
        go.send(()).unwrap();
        let _ = t.join();
        drop(held);
        std::println!("the thread at the limit went 64 KiB deep and the process went on");
    }

    #[test]
    #[ignore = "run by test_a_stack_that_grows_at_the_limit_on_record"]
    fn stack_with_room_child() {
        let (t, _go) = a_thread_that_goes_deep(true, 16);
        assert_eq!(t.join().map(|_| ()).ok(), Some(()));
        std::println!("the thread with room went 64 KiB deep");
    }

    #[test]
    #[ignore = "run by test_a_stack_that_grows_at_the_limit_on_record"]
    fn stack_overflowed_child() {
        let (t, _go) = a_thread_that_goes_deep(true, usize::MAX);
        let _ = t.join();
        std::println!("the unbounded thread came back");
    }

    /// Which kind of thread a stack test runs on: one of Rust's
    /// (`std::thread`, whose stack guarantee Rust sets), one made with
    /// `CreateThread` as a system DLL or the reclaim makes one (no
    /// guarantee set), and a thread of the process's thread pool
    /// (`TrySubmitThreadpoolCallback`), which the system makes.
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        Rust,
        CreateThread,
        Pool,
    }

    /// Runs `body` on a thread of `kind`: it prints its stack (from its
    /// TEB), says it is ready, waits for the go, and goes `depth` frames
    /// deep ([`deep`]); the go, and a receiver told when it came back.
    fn a_thread_of(kind: Kind, depth: usize) -> (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>) {
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let (ready, heard) = std::sync::mpsc::channel::<()>();
        let (back, came_back) = std::sync::mpsc::channel::<()>();
        let body: std::boxed::Box<dyn FnOnce() + Send> = std::boxed::Box::new(move || {
            let (base, limit, reserve, guarantee) = stack_of_this_thread();
            std::println!(
                "the {kind:?} thread's stack: {} KiB committed of a {} KiB reserve, a guarantee of {guarantee} bytes",
                (base - limit) >> 10,
                (base - reserve) >> 10
            );
            ready.send(()).unwrap();
            wait.recv().unwrap();
            core::hint::black_box(deep(depth));
            let _ = back.send(());
        });
        on_a_thread_of(kind, body);
        heard.recv().unwrap();
        (go, came_back)
    }

    /// Runs `body` on a new thread of `kind`.
    fn on_a_thread_of(kind: Kind, body: std::boxed::Box<dyn FnOnce() + Send>) {
        let raw = std::boxed::Box::into_raw(std::boxed::Box::new(body)).cast::<c_void>();
        unsafe extern "system" fn start(raw: *mut c_void) -> u32 {
            // SAFETY: the box made above, given to this thread alone.
            let body = unsafe { std::boxed::Box::from_raw(raw.cast::<std::boxed::Box<dyn FnOnce() + Send>>()) };
            body();
            0
        }
        unsafe extern "system" fn pooled(_: windows_sys::Win32::System::Threading::PTP_CALLBACK_INSTANCE, raw: *mut c_void) {
            // SAFETY: as `start`.
            unsafe { start(raw) };
        }
        match kind {
            Kind::Rust => {
                let raw = raw as usize;
                // Named as Rust names a thread (`SetThreadDescription`).
                std::thread::Builder::new()
                    .name("wick-stack-test".into())
                    .spawn(move || {
                        // SAFETY: the box made above.
                        unsafe { start(raw as *mut c_void) };
                    })
                    .unwrap();
            }
            Kind::CreateThread => {
                // SAFETY: a thread of ours with the default stack.
                let t = unsafe { windows_sys::Win32::System::Threading::CreateThread(ptr::null(), 0, Some(start), raw, 0, ptr::null_mut()) };
                assert!(!t.is_null());
            }
            Kind::Pool => {
                // SAFETY: the process's default pool runs the callback once.
                assert_ne!(unsafe { windows_sys::Win32::System::Threading::TrySubmitThreadpoolCallback(Some(pooled), raw, ptr::null()) }, 0);
            }
        }
    }

    /// A mapping committed at first touch, so that the lazy-memory handler,
    /// and the stack filter with it, are in place (`windows_mm::exception_handler`),
    /// as in a VMM with guest memory.
    fn lazy_memory_is_mapped() {
        // SAFETY: a new anonymous mapping, committed at first touch.
        let p = unsafe {
            crate::mmap(ptr::null_mut(), 1 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_ne!(p, crate::MAP_FAILED);
    }

    /// A thread whose stack must grow when the job's limit has no room left
    /// ends the process as the limit's other ends do, with 137 and the line
    /// that says so (`windows_mm::stack_filter`), where it ended with
    /// `STATUS_STACK_OVERFLOW` (STACKZERO), on each kind of thread
    /// ([`Kind`]); Linux's memory cgroup ends a process whose stack page
    /// cannot be charged with its out-of-memory kill.
    #[test]
    fn test_a_stack_that_must_grow_at_the_limit_ends_with_137() {
        for extra in XSAVE_EXTRAS {
            for child in ["stack_at_the_limit_rust_child", "stack_at_the_limit_createthread_child", "stack_at_the_limit_pool_child"] {
                let (code, text) = run_child_with(child, Some(96 << 20), &[("WICK_TEST_XSAVE_EXTRA", extra)]);
                std::eprintln!("STACK137 {child}, XSAVE area {extra} B larger: {code:?}; {}", text.trim().replace('\n', " | "));
                assert!(text.contains("wick: a thread's stack could not grow"), "{child}, {extra}: {text}");
                assert_eq!(code, Some(137), "{child}, {extra}: {text}");
                assert!(text.contains("STACK137FRAMES 0 "), "{child}, {extra}: no frames: {text}");
                let room = stack_room_problems(&text, extra);
                assert!(room.is_empty(), "{child}, {extra}: {room:#?}\n{text}");
            }
        }
    }

    /// The larger XSAVE areas the overflow tests simulate on top of the
    /// runner's own (`windows_mm::simulated_xsave_extra`): none, AMX's tile
    /// configuration and data (64 + 8192 bytes, as an Intel Xeon with AMX
    /// adds: CI run 44225041771), and twice that, rounded.
    const XSAVE_EXTRAS: [&str; 3] = ["0", "8256", "16384"];

    /// What a child's STACKASK and STACKUSE lines say against the stack the
    /// handler is given (`windows_mm::HANDLER_STACK_BUDGET`,
    /// `windows_mm::DISPATCH_OVERHEAD`): at least the budget left under the
    /// handler, at most the budget used there by the handler and the
    /// filters, the dispatcher's frames at most the exception's context,
    /// the simulated area and the overhead; and the simulated area named
    /// as asked. Each line out of bounds, said.
    fn stack_room_problems(text: &str, extra: &str) -> std::vec::Vec<std::string::String> {
        let budget = crate::windows_mm::HANDLER_STACK_BUDGET;
        let overhead = crate::windows_mm::DISPATCH_OVERHEAD;
        let number = |l: &str, after: &str| -> Option<usize> { l.split_once(after)?.1.split(' ').next()?.parse().ok() };
        let mut wrong = std::vec::Vec::new();
        for l in text.lines() {
            if l.starts_with("STACKASK ") {
                let (Some(frames), Some(left), Some(context), Some(simulated)) = (
                    number(l, "the dispatcher's frames "),
                    number(l, "left under the handler "),
                    number(l, "the exception's context "),
                    number(l, "a larger XSAVE area simulated "),
                ) else {
                    wrong.push(std::format!("unread: {l}"));
                    continue;
                };
                if left < budget {
                    wrong.push(std::format!("{left} B left under the handler, under the budget of {budget} B: {l}"));
                }
                if frames > context + simulated + overhead {
                    wrong.push(std::format!("the dispatcher's frames {frames} B over the context {context} B, {simulated} B simulated and {overhead} B: {l}"));
                }
                if extra.parse::<usize>() != Ok(simulated) {
                    wrong.push(std::format!("simulated {simulated} B where {extra} B was asked: {l}"));
                }
            } else if l.starts_with("STACKUSE ") {
                match number(l, "the filters used ") {
                    Some(used) if used <= budget => {}
                    _ => wrong.push(std::format!("over the budget of {budget} B: {l}")),
                }
            }
        }
        if !text.contains("STACKASK ") {
            wrong.push("no STACKASK line".into());
        }
        wrong
    }

    /// Each thread of a process has the stack guarantee
    /// (`windows_mm::at_thread_start`, `windows_mm::stack_guarantee`) and,
    /// below its committed stack, the room a stack overflow's dispatch and
    /// handler need already committed as guard pages: this test's own
    /// thread, a Rust thread, a `CreateThread` thread and a thread of the
    /// process's pool, each read from its TEB. The room is what the system
    /// runs the overflow on when the stack cannot grow, a commit the memory
    /// limit refused or the reserve's end (`windows_mm::guard_region_for`),
    /// so committed, it does not hang on a commit at the limit. The guard
    /// pages are walked down from StackLimit (`windows_mm::guard_below`;
    /// one `VirtualQuery` at StackLimit less a page says one page whatever
    /// lies below, as CI run 44233741878 read it) and must be at least the
    /// exception's context, the dispatcher's and the handler's (the
    /// guarantee before its rounding) on each kind of thread: right after
    /// the callback's `SetThreadStackGuarantee` (its GUARDSEEN record, read
    /// by the thread's ID, with what was there before the call: the call
    /// makes the region, CI run 44248573219: 12288 or 0 B before, 28672
    /// after, `windows_mm::set_the_stack_guarantee`), at the thread's own
    /// start, and after its stack grew 64 KiB (the system's region, moved
    /// down by the growth). Said on every run (STACKGUARANTEE): per kind,
    /// the record (the guard pages and the guarantee before and after the
    /// call), the walk at the start and after the growth; how many records
    /// were written (the ring keeps the newest `GUARD_SEEN_LEN`); and every
    /// thread of the process: its ID, its guarantee and its guard pages read
    /// through its TEB, its TEB's SameTebFlags (whether the loader skips its
    /// attach, [`TEB_SAME_TEB_FLAGS`]), its record if the ring still holds
    /// it, whether it was made before the loader's callback for the process
    /// ran, the module and offset it starts at. A thread without the
    /// guarantee that the loader attaches and that must have it (made after
    /// the callback, or starting outside ntdll) is read again for up to
    /// 2 s, and fails the test by name unless it was given it by then (it
    /// was listed before its attach ran: said). A thread the loader never
    /// attaches (SkipThreadAttach or LoaderWorker) runs no TLS callback,
    /// wick's included, and fails if it starts outside ntdll. The process's
    /// main thread (made before the callback, given the guarantee by its
    /// `DLL_PROCESS_ATTACH`) fails with fewer guard pages than needed, and
    /// the flags' reading fails if the main thread has no InitialThread bit
    /// or a recorded thread a skip bit.
    #[test]
    fn test_every_thread_has_the_stack_guarantee() {
        let want = crate::windows_mm::stack_guarantee();
        let need = crate::windows_mm::exception_context_bytes()
            + crate::windows_mm::simulated_xsave_extra()
            + crate::windows_mm::DISPATCH_OVERHEAD
            + crate::windows_mm::HANDLER_STACK_BUDGET;
        let region = crate::windows_mm::guard_region_for(want);
        crate::windows_mm::say_at_the_limit(format_args!(
            "STACKGUARANTEE the guarantee {want} B: the exception's context {} B, the dispatcher's {} B, the handler's {} B ({need} B before \
             its rounding); the guard region it sizes {region} B",
            crate::windows_mm::exception_context_bytes(),
            crate::windows_mm::DISPATCH_OVERHEAD,
            crate::windows_mm::HANDLER_STACK_BUDGET
        ));
        let mut wrong = std::vec::Vec::new();
        for kind in [Kind::Rust, Kind::CreateThread, Kind::Pool] {
            let (done, came_back) = std::sync::mpsc::channel::<(u32, Option<crate::windows_mm::GuardSeen>, usize, usize)>();
            on_a_thread_of(
                kind,
                std::boxed::Box::new(move || {
                    let (_, _, _, guarantee) = stack_of_this_thread();
                    // SAFETY: plain call.
                    let seen = crate::windows_mm::guard_seen(unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() });
                    let at_start = guard_pages_below_the_stack();
                    grow_by(64 << 10);
                    let _ = done.send((guarantee, seen, at_start, guard_pages_below_the_stack()));
                }),
            );
            let (guarantee, seen, at_start, grown) = came_back.recv_timeout(std::time::Duration::from_secs(30)).unwrap();
            // On every run, past the test's capture (one `WriteFile`).
            crate::windows_mm::say_at_the_limit(format_args!(
                "STACKGUARANTEE {kind:?} thread: its guarantee {guarantee} B; {}; {at_start} B of guard pages at the thread's own start, \
                 {grown} B after it grew 64 KiB; {need} B needed",
                Seen(seen)
            ));
            match seen {
                None => wrong.push(std::format!("a {kind:?} thread has no GUARDSEEN record: the callback did not run on it")),
                Some(r) => {
                    if r.error != 0 || r.guard_after < need {
                        wrong.push(std::format!("a {kind:?} thread's guard pages right after SetThreadStackGuarantee: {}", Seen(seen)));
                    }
                }
            }
            for (when, bytes) in [("at its start", at_start), ("after it grew 64 KiB", grown)] {
                if bytes < need {
                    wrong.push(std::format!("a {kind:?} thread's guard pages {when} {bytes} B, under the {need} B an overflow needs"));
                }
            }
            if (guarantee as usize) < want {
                wrong.push(std::format!("a {kind:?} thread's guarantee {guarantee} B, under {want} B"));
            }
        }
        let (_, _, _, here) = stack_of_this_thread();
        if (here as usize) < want {
            wrong.push(std::format!("this test's thread's guarantee {here} B, under {want} B"));
        }
        let attached = crate::windows_mm::PROCESS_ATTACHED_AT.load(Ordering::Relaxed);
        crate::windows_mm::say_at_the_limit(format_args!(
            "STACKGUARANTEE {} GUARDSEEN records written in this process, the ring keeps the newest {}",
            crate::windows_mm::guard_seen_written(),
            crate::windows_mm::GUARD_SEEN_LEN
        ));
        let threads = threads_of_this_process();
        let short = |t: &ThreadSeen| t.guarantee.is_some_and(|g| (g as usize) < want);
        let skipped = |t: &ThreadSeen| t.flags.is_some_and(|f| f & (TEB_SKIP_THREAD_ATTACH | TEB_LOADER_WORKER) != 0);
        // A thread listed between its making and its loader's attach (its
        // TLS callbacks run in the thread itself, before its start address)
        // has no guarantee yet. Each one without it that the loader does
        // attach (no skip bit) and that must have it is read again for up
        // to 2 s: given it by then, it was early; gone, or still without,
        // it fails by name.
        let mut pending: std::vec::Vec<u32> = threads
            .iter()
            .filter(|t| short(t) && !skipped(t) && (t.created >= attached || t.start != "ntdll.dll"))
            .map(|t| t.id)
            .collect();
        let mut outcome = std::collections::HashMap::new();
        let since = std::time::Instant::now();
        while !pending.is_empty() && since.elapsed() < std::time::Duration::from_secs(2) {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let now = threads_of_this_process();
            pending.retain(|id| match now.iter().find(|t| t.id == *id) {
                None => {
                    outcome.insert(*id, std::format!("gone {} ms later, without the guarantee when last read", since.elapsed().as_millis()));
                    false
                }
                Some(t) if !short(t) => {
                    outcome.insert(*id, std::format!("given the guarantee ({:?} B) within {} ms: not yet attached when first listed", t.guarantee, since.elapsed().as_millis()));
                    false
                }
                Some(_) => true,
            });
        }
        for id in pending {
            outcome.insert(id, "still without the guarantee 2 s later".into());
        }
        for t in &threads {
            let before = t.created < attached;
            let seen = crate::windows_mm::guard_seen(t.id);
            let late = outcome.get(&t.id);
            crate::windows_mm::say_at_the_limit(format_args!(
                "STACKGUARANTEE thread {}: its guarantee {:?} B, {:?} B of guard pages below its StackLimit, TEB SameTebFlags {}, {}, \
                 made {} the loader's callback for the process, its start {}+{:#x}{}{}",
                t.id,
                t.guarantee,
                t.guard,
                teb_flags(t.flags),
                Seen(seen),
                if before { "before" } else { "after" },
                t.start,
                t.start_at,
                if late.is_some() { "; " } else { "" },
                late.map_or("", std::string::String::as_str),
            ));
            let given_late = late.is_some_and(|o| o.starts_with("given"));
            if short(t) && !given_late {
                if skipped(t) {
                    // Never attached by the loader: no TLS callback, ours
                    // included, runs on it; only ntdll's own work may.
                    if t.start != "ntdll.dll" {
                        wrong.push(std::format!("thread {} is never attached (TEB {}) and starts in {}, not ntdll", t.id, teb_flags(t.flags), t.start));
                    }
                } else if !before || t.start != "ntdll.dll" {
                    wrong.push(std::format!(
                        "thread {} (made {} the process's callback, its start {}+{:#x}) has the guarantee {:?} B and the loader attaches it: {}",
                        t.id,
                        if before { "before" } else { "after" },
                        t.start,
                        t.start_at,
                        t.guarantee,
                        late.map_or("not read again", std::string::String::as_str)
                    ));
                }
            }
            // The main thread: made before the callback, outside ntdll; its
            // guard pages, and SameTebFlags read where the TEB has them.
            if before && t.start != "ntdll.dll" {
                if t.guard.is_some_and(|g| g < need) {
                    wrong.push(std::format!("the main thread {} has {:?} B of guard pages, under the {need} B an overflow needs", t.id, t.guard));
                }
                if t.flags.is_some_and(|f| f & TEB_INITIAL_THREAD == 0) {
                    wrong.push(std::format!("the main thread {}'s TEB SameTebFlags {} has no InitialThread: the offset does not read the TEB's flags", t.id, teb_flags(t.flags)));
                }
            }
            if seen.is_some() && skipped(t) {
                wrong.push(std::format!("thread {} has a GUARDSEEN record and TEB SameTebFlags {}: the offset does not read the TEB's flags", t.id, teb_flags(t.flags)));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// How a GUARDSEEN record reads in a line.
    struct Seen(Option<crate::windows_mm::GuardSeen>);

    impl core::fmt::Display for Seen {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self.0 {
                None => f.write_str("no GUARDSEEN record"),
                Some(r) => write!(
                    f,
                    "GUARDSEEN reason {}: guard pages {} -> {} B, guarantee {} -> {} B across SetThreadStackGuarantee (error {}); \
                     StackLimit {:#x}, {} KiB above the reserve's end",
                    r.reason,
                    r.guard_before,
                    r.guard_after,
                    r.guarantee_before,
                    r.guarantee_after,
                    r.error,
                    r.limit,
                    r.limit.saturating_sub(r.reserve) >> 10
                ),
            }
        }
    }

    /// Raising a thread's stack guarantee charges the process's commit,
    /// which a job's memory limit counts (Learn,
    /// `PROCESS_MEMORY_COUNTERS_EX`: PrivateUsage is "the Commit Charge
    /// value in bytes for this process"; `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`:
    /// the limit "for the virtual memory that can be committed"), by what
    /// its guard region grew, in the call: a child raises its own thread's
    /// guarantee by 64 KiB with nothing else between two reads of its
    /// commit; the guard pages below its StackLimit grow by at least that
    /// much and the commit by the same within a page. GUARDCHARGE, said on
    /// every run.
    #[test]
    fn test_a_stack_guarantee_is_charged_when_it_is_set() {
        let (code, text) = run_child("guarantee_charge_child", None);
        let line = text.lines().find(|l| l.starts_with("GUARDCHARGE ")).unwrap_or_default();
        // On every run, past the test's capture (one `WriteFile`).
        crate::windows_mm::say_at_the_limit(format_args!("{line}"));
        assert_eq!(code, Some(0), "{text}");
        let number = |after: &str| -> Option<isize> { line.split_once(after)?.1.split(|c: char| c != '-' && !c.is_ascii_digit()).next()?.parse().ok() };
        let (Some(set), Some(grew), Some(charged)) = (number("set "), number("the guard pages grew "), number("the commit grew ")) else {
            panic!("no GUARDCHARGE line: {text}");
        };
        assert_eq!(set, 1, "{line}");
        assert!(grew >= 65536, "{line}");
        assert!((charged - grew).abs() <= 4096, "{line}");
    }

    #[test]
    #[ignore = "run by test_a_stack_guarantee_is_charged_when_it_is_set"]
    fn guarantee_charge_child() {
        let (_, limit, reserve, guarantee) = stack_of_this_thread();
        let region = crate::windows_mm::guard_below(limit, limit - reserve);
        let before = crate::windows_mm::moverec_commit();
        let mut size = guarantee + 65536;
        // SAFETY: an in/out pointer to the size.
        let set = unsafe { windows_sys::Win32::System::Threading::SetThreadStackGuarantee(&mut size) } != 0;
        let after = crate::windows_mm::moverec_commit();
        let (_, limit2, _, guarantee2) = stack_of_this_thread();
        let region2 = crate::windows_mm::guard_below(limit2, limit2 - reserve);
        crate::windows_mm::say_at_the_limit(format_args!(
            "GUARDCHARGE set {}: the guarantee {guarantee} -> {guarantee2} B, the guard pages {region} -> {region2} B; the guard pages grew {} \
             B; the commit grew {} B",
            u8::from(set),
            region2.cast_signed() - region.cast_signed(),
            after.cast_signed() - before.cast_signed(),
        ));
    }

    /// A stack guarantee raised with no room left in the job is either
    /// refused by the call, which the callback says by the thread's ID
    /// (`windows_mm::set_the_stack_guarantee`,
    /// `test_a_stack_guarantee_that_cannot_be_set_is_said`), or given with
    /// its guard region committed: never set without its room. A child at
    /// its job's limit (every page taken) raises its own thread's guarantee
    /// by 64 KiB. GUARANTEELIMIT, said on every run.
    #[test]
    fn test_a_stack_guarantee_raised_at_the_limit_is_given_or_refused() {
        let (code, text) = run_child_with("guarantee_at_the_limit_child", Some(96 << 20), &[]);
        let line = text.lines().find(|l| l.starts_with("GUARANTEELIMIT ")).unwrap_or_default();
        // On every run, past the test's capture (one `WriteFile`).
        crate::windows_mm::say_at_the_limit(format_args!("{line}"));
        assert_eq!(code, Some(0), "{text}");
        let number = |after: &str| -> Option<isize> { line.split_once(after)?.1.split(|c: char| c != '-' && !c.is_ascii_digit()).next()?.parse().ok() };
        let (Some(set), Some(error), Some(grew)) = (number("set "), number("error "), number("the guard pages grew ")) else {
            panic!("no GUARANTEELIMIT line: {text}");
        };
        assert!((set == 0 && error != 0) || (set == 1 && grew >= 65536), "{line}");
    }

    #[test]
    #[ignore = "run by test_a_stack_guarantee_raised_at_the_limit_is_given_or_refused in a job of its own"]
    fn guarantee_at_the_limit_child() {
        make_the_slack_region();
        let mut held = no_room_left();
        let (_, limit, reserve, guarantee) = stack_of_this_thread();
        let region = crate::windows_mm::guard_below(limit, limit - reserve);
        let mut size = guarantee + 65536;
        // SAFETY: an in/out pointer to the size.
        let set = unsafe { windows_sys::Win32::System::Threading::SetThreadStackGuarantee(&mut size) } != 0;
        // SAFETY: plain call.
        let error = if set { 0 } else { unsafe { windows_sys::Win32::Foundation::GetLastError() } };
        let (_, limit2, _, guarantee2) = stack_of_this_thread();
        let region2 = crate::windows_mm::guard_below(limit2, limit2 - reserve);
        crate::windows_mm::say_at_the_limit(format_args!(
            "GUARANTEELIMIT set {} error {error}: the guarantee {guarantee} -> {guarantee2} B, the guard pages {region} -> {region2} B; the guard \
             pages grew {} B, with {} pages held",
            u8::from(set),
            region2.cast_signed() - region.cast_signed(),
            held.len()
        ));
        give_back_every_page(&mut held);
    }

    /// Goes `bytes` deeper in the stack than here, writing it.
    #[inline(never)]
    fn grow_by(bytes: usize) {
        let pad = core::hint::black_box([1u8; 4096]);
        if bytes > 4096 {
            grow_by(bytes - 4096);
        }
        core::hint::black_box(&pad);
    }

    /// The bytes of guard pages (committed, `PAGE_GUARD`) right below the
    /// calling thread's committed stack, walked down to its reserve.
    fn guard_pages_below_the_stack() -> usize {
        let (_, limit, reserve, _) = stack_of_this_thread();
        crate::windows_mm::guard_below(limit, limit - reserve)
    }

    /// A thread of this process, as [`threads_of_this_process`] lists it.
    struct ThreadSeen {
        id: u32,
        /// The module its start address lies in (`ThreadQuerySetWin32StartAddress`).
        start: std::string::String,
        /// Its TEB's GuaranteedStackBytes, if it could be read.
        guarantee: Option<u32>,
        /// The guard pages below its TEB's StackLimit, if it could be read.
        guard: Option<usize>,
        /// When it was made (`FILETIME`).
        created: u64,
        /// Its start address's offset in that module.
        start_at: usize,
        /// Its TEB's SameTebFlags ([`TEB_SAME_TEB_FLAGS`]), if it could be read.
        flags: Option<u16>,
    }

    /// The x86-64 TEB's SameTebFlags (a `USHORT` at 0x17EE, ntdll's public
    /// symbols' `_TEB`; not documented by Microsoft, so the test checks its
    /// reading: the process's main thread has [`TEB_INITIAL_THREAD`] and a
    /// thread the callback recorded has neither of the loader's skip bits).
    const TEB_SAME_TEB_FLAGS: usize = 0x17ee;
    /// SameTebFlags' SkipThreadAttach: made with
    /// `THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH`, which the loader attaches to
    /// no DLL and no TLS callback.
    const TEB_SKIP_THREAD_ATTACH: u16 = 0x8;
    /// SameTebFlags' InitialThread: the process's first thread.
    const TEB_INITIAL_THREAD: u16 = 0x400;
    /// SameTebFlags' LoaderWorker: a worker of the loader's own thread pool
    /// (the parallel loader's, which maps and snaps the DLLs a load needs).
    const TEB_LOADER_WORKER: u16 = 0x2000;

    /// SameTebFlags as a line says them: the value and the bits named.
    fn teb_flags(flags: Option<u16>) -> std::string::String {
        let Some(f) = flags else { return "not read".into() };
        let names: std::vec::Vec<&str> = [(TEB_SKIP_THREAD_ATTACH, "SkipThreadAttach"), (TEB_INITIAL_THREAD, "InitialThread"), (TEB_LOADER_WORKER, "LoaderWorker")]
            .iter()
            .filter(|(bit, _)| f & bit != 0)
            .map(|&(_, name)| name)
            .collect();
        std::format!("{f:#06x} ({})", if names.is_empty() { "none".into() } else { names.join(", ") })
    }

    /// Every thread of this process (a ToolHelp snapshot), with its stack
    /// guarantee read from its TEB (`NtQueryInformationThread`,
    /// ThreadBasicInformation) and when it was made (`GetThreadTimes`).
    fn threads_of_this_process() -> std::vec::Vec<ThreadSeen> {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
        use windows_sys::Win32::System::Threading::{GetThreadTimes, OpenThread, THREAD_QUERY_INFORMATION};
        #[repr(C)]
        struct ThreadEntry32 {
            size: u32,
            usage: u32,
            thread: u32,
            owner: u32,
            base_priority: i32,
            delta_priority: i32,
            flags: u32,
        }
        #[repr(C)]
        struct ThreadBasicInformation {
            exit_status: i32,
            teb: usize,
            client_id: [usize; 2],
            affinity: usize,
            priority: i32,
            base_priority: i32,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateToolhelp32Snapshot(flags: u32, process: u32) -> HANDLE;
            fn Thread32First(snapshot: HANDLE, entry: *mut ThreadEntry32) -> i32;
            fn Thread32Next(snapshot: HANDLE, entry: *mut ThreadEntry32) -> i32;
        }
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationThread(thread: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
        }
        const TH32CS_SNAPTHREAD: u32 = 4;
        let me = std::process::id();
        let mut out = std::vec::Vec::new();
        // SAFETY: a snapshot of every thread of the system.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        assert!(!snap.is_null() && snap as isize != -1);
        #[allow(clippy::cast_possible_truncation)]
        let mut e = ThreadEntry32 { size: std::mem::size_of::<ThreadEntry32>() as u32, usage: 0, thread: 0, owner: 0, base_priority: 0, delta_priority: 0, flags: 0 };
        // SAFETY: the snapshot and an entry of the size it says.
        let mut more = unsafe { Thread32First(snap, &mut e) } != 0;
        while more {
            if e.owner == me {
                // SAFETY: a thread of this process, opened to query it.
                let h = unsafe { OpenThread(THREAD_QUERY_INFORMATION, 0, e.thread) };
                if !h.is_null() {
                    // SAFETY: plain data; zero is valid.
                    let mut info: ThreadBasicInformation = unsafe { std::mem::zeroed() };
                    // SAFETY: the thread's handle and a buffer of the size passed.
                    #[allow(clippy::cast_possible_truncation)]
                    let st = unsafe { NtQueryInformationThread(h, 0, (&raw mut info).cast(), std::mem::size_of_val(&info) as u32, ptr::null_mut()) };
                    // Read as another process's memory is: a thread that
                    // ended meanwhile has no TEB, and the read fails.
                    let mut g = 0u32;
                    // SAFETY: this process; a buffer of the size passed.
                    let read = st >= 0
                        && info.teb != 0
                        && unsafe {
                            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                                (info.teb + 0x1748) as *const c_void,
                                (&raw mut g).cast(),
                                4,
                                ptr::null_mut(),
                            )
                        } != 0;
                    let guarantee = read.then_some(g);
                    let mut flags = 0u16;
                    // SAFETY: this process; a buffer of the size passed.
                    let flags = (read
                        && unsafe {
                            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                                (info.teb + TEB_SAME_TEB_FLAGS) as *const c_void,
                                (&raw mut flags).cast(),
                                2,
                                ptr::null_mut(),
                            )
                        } != 0)
                        .then_some(flags);
                    // Its StackLimit and DeallocationStack, read the same
                    // way, and the guard pages below the one, walked to the
                    // other (a record: the thread may be growing its stack).
                    let mut stack = [0usize; 2];
                    let guard = (read
                        && [0x10usize, 0x1478].iter().zip(stack.iter_mut()).all(|(&at, out)| {
                            // SAFETY: this process; a buffer of the size passed.
                            let ok = unsafe {
                                windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                                    windows_sys::Win32::System::Threading::GetCurrentProcess(),
                                    (info.teb + at) as *const c_void,
                                    ptr::from_mut(out).cast(),
                                    std::mem::size_of::<usize>(),
                                    ptr::null_mut(),
                                )
                            };
                            ok != 0
                        })
                        && stack[0] > stack[1])
                        .then(|| crate::windows_mm::guard_below(stack[0], stack[0] - stack[1]));
                    let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
                    let (mut c, mut x, mut k, mut u) = (zero, zero, zero, zero);
                    // SAFETY: the thread's handle and four out-pointers.
                    unsafe { GetThreadTimes(h, &mut c, &mut x, &mut k, &mut u) };
                    let mut start_address = 0usize;
                    // SAFETY: as above; class 9, ThreadQuerySetWin32StartAddress, a pointer.
                    #[allow(clippy::cast_possible_truncation)]
                    unsafe { NtQueryInformationThread(h, 9, (&raw mut start_address).cast(), std::mem::size_of::<usize>() as u32, ptr::null_mut()) };
                    let (start, start_at) = module_of_address(start_address);
                    out.push(ThreadSeen {
                        id: e.thread,
                        start,
                        guarantee,
                        guard,
                        created: (u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime),
                        start_at,
                        flags,
                    });
                    // SAFETY: our handle.
                    unsafe { CloseHandle(h) };
                }
            }
            // SAFETY: as above.
            more = unsafe { Thread32Next(snap, &mut e) } != 0;
        }
        // SAFETY: our snapshot.
        unsafe { CloseHandle(snap) };
        out
    }

    /// The file name of the module `address` lies in, or "?", and the
    /// address's offset in it.
    fn module_of_address(address: usize) -> (std::string::String, usize) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut *mut c_void) -> i32;
            fn GetModuleFileNameW(module: *mut c_void, name: *mut u16, size: u32) -> u32;
        }
        const FROM_ADDRESS: u32 = 4;
        const UNCHANGED_REFCOUNT: u32 = 2;
        let mut module = ptr::null_mut();
        // SAFETY: an address, looked up without a reference taken.
        if address == 0 || unsafe { GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT, address as *const u16, &mut module) } == 0 {
            return ("?".into(), address);
        }
        let mut name = [0u16; 260];
        // SAFETY: the module and a buffer of the size given.
        let n = unsafe { GetModuleFileNameW(module, name.as_mut_ptr(), 260) } as usize;
        let full = std::string::String::from_utf16_lossy(&name[..n.min(260)]);
        (full.rsplit('\\').next().unwrap_or("?").to_ascii_lowercase(), address - module as usize)
    }

    /// A guarantee the system cannot give (here a simulated XSAVE area of
    /// 8 MiB, past any thread's reserve) is said at the thread's start, by
    /// the thread's ID: never a thread left without one silently.
    #[test]
    fn test_a_stack_guarantee_that_cannot_be_set_is_said() {
        let (code, text) = run_child_with("guarantee_not_set_child", None, &[("WICK_TEST_XSAVE_EXTRA", "8388608")]);
        let id = text.lines().find_map(|l| l.strip_prefix("GUARANTEECHILD thread ")).unwrap_or("none");
        assert!(text.contains(&std::format!("wick: thread {id} could not be given a stack guarantee of ")), "{code:?}: {text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_stack_guarantee_that_cannot_be_set_is_said"]
    fn guarantee_not_set_child() {
        unsafe extern "system" fn start(_: *mut c_void) -> u32 {
            // SAFETY: plain call.
            std::println!("GUARANTEECHILD thread {}", unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() });
            0
        }
        // SAFETY: a thread of ours with the default stack, waited for.
        unsafe {
            let t = windows_sys::Win32::System::Threading::CreateThread(ptr::null(), 0, Some(start), ptr::null(), 0, ptr::null_mut());
            assert!(!t.is_null());
            windows_sys::Win32::System::Threading::WaitForSingleObject(t, 30_000);
            windows_sys::Win32::Foundation::CloseHandle(t);
        }
    }

    /// The line of a stack that could not grow names its thread, by its ID
    /// and its description (which Rust sets to a thread's name), so that a
    /// run says which thread it was (MOVEUNDERVCPU, CI runs 43784960688 and
    /// 43790310601, did not); the ID is the one Rust's own overflow line
    /// gives.
    #[test]
    fn test_the_line_of_a_stack_that_could_not_grow_names_its_thread() {
        let (code, text) = run_child("stack_at_the_limit_rust_child", Some(96 << 20));
        assert_eq!(code, Some(137), "{text}");
        let line = text.lines().find(|l| l.starts_with("wick: a thread's stack could not grow")).unwrap_or_default();
        let rust = text
            .lines()
            .find_map(|l| l.split_once("thread 'wick-stack-test' (")?.1.split_once(") has overflowed").map(|(id, _)| id))
            .expect("Rust's overflow line with the thread's ID");
        assert!(line.contains(&std::format!("thread {rust} \"wick-stack-test\"")), "{text}");
    }

    /// The frames printed after the line of a stack that could not grow
    /// (STACK137FRAMES) name the module of each frame outside this
    /// executable with its offset in it: the exception dispatcher's frames
    /// are ntdll's, and CI run 43823078930's `vcpu-runner` died ten frames
    /// deep in a DLL `WHvRunVirtualProcessor` called, which the line gave
    /// as bare addresses (randomised per boot), so it could not be named
    /// after the run.
    #[test]
    fn test_the_frames_of_a_stack_that_could_not_grow_name_their_modules() {
        let (code, text) = run_child("stack_at_the_limit_rust_child", Some(96 << 20));
        assert_eq!(code, Some(137), "{text}");
        let frames: std::vec::Vec<&str> = text.lines().filter(|l| l.starts_with("STACK137FRAMES ")).collect();
        assert!(frames.iter().any(|l| l.to_ascii_lowercase().contains(" ntdll.dll+0x")), "{text}");
        for l in &frames {
            let what = l.split(' ').nth(2).unwrap_or_default();
            assert!(what.starts_with("image+0x") || what.contains(".dll+0x") || what.contains(".DLL+0x"), "a frame not named: {l}\n{text}");
        }
    }

    /// A frame in an image whose headers point outside it is given as a
    /// bare address, and the lines after it are written: the module's name
    /// is looked up in the headers of any `SEC_IMAGE` view
    /// (`windows_mm::module_of`), not only a module the loader checked, on
    /// the path that writes a process's last lines (STACK137FRAMES, then
    /// its 137), so an offset the headers give that leads outside the image
    /// must not be followed. A hand-made PE32+ image (one section holding an
    /// export directory and its name) mapped `SEC_IMAGE`, a child per case:
    /// as made, the frame is named (`damaged.dll+0x1010`); its export
    /// directory's RVA past the image, or its name's RVA past the image,
    /// the frame is the bare address. Each child then says it went on.
    #[test]
    fn test_a_frame_in_a_damaged_image_is_given_bare() {
        for (case, want) in [("control", Some("damaged.dll+0x1010")), ("exports", None), ("name", None)] {
            let (code, text, _) = run_child_watched("damaged_image_child", &[("WICK_TEST_IMAGE", case)], false);
            let line = text.lines().find(|l| l.starts_with("STACK137FRAMES 0 ")).unwrap_or_default();
            assert!(text.contains(&std::format!("DAMAGED {case}: after the frame")), "{case}: {code:?}: {text}");
            assert_eq!(code, Some(0), "{case}: {text}");
            match want {
                Some(w) => assert!(line.starts_with(&std::format!("STACK137FRAMES 0 {w} (0x")), "{case}: {line}\n{text}"),
                None => assert!(line.len() > 19 && line["STACK137FRAMES 0 0x".len()..].chars().all(|c| c.is_ascii_hexdigit()), "{case}: {line}\n{text}"),
            }
        }
    }

    /// A PE32+ image of 0x2000 bytes, made by hand: its headers, and a
    /// section at 0x1000 holding an export directory whose name,
    /// "damaged.dll", is at 0x1100; `case` "exports" points the export
    /// directory past the image, "name" the name.
    fn damaged_image(case: &str) -> std::vec::Vec<u8> {
        let mut b = std::vec![0u8; 0x400];
        let put16 = |b: &mut [u8], at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        let put32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        b[0..2].copy_from_slice(b"MZ");
        put32(&mut b, 0x3c, 0x40);
        b[0x40..0x44].copy_from_slice(b"PE\0\0");
        // The file header.
        put16(&mut b, 0x44, 0x8664);
        put16(&mut b, 0x46, 1);
        put16(&mut b, 0x54, 0xf0);
        put16(&mut b, 0x56, 0x2022);
        // The optional header (PE32+).
        let o = 0x58;
        put16(&mut b, o, 0x20b);
        put32(&mut b, o + 4, 0x200);
        put32(&mut b, o + 20, 0x1000);
        b[o + 24..o + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        put32(&mut b, o + 32, 0x1000);
        put32(&mut b, o + 36, 0x200);
        put16(&mut b, o + 40, 6);
        put16(&mut b, o + 48, 6);
        put32(&mut b, o + 56, 0x2000);
        put32(&mut b, o + 60, 0x200);
        put16(&mut b, o + 68, 3);
        put16(&mut b, o + 70, 0x160);
        b[o + 72..o + 80].copy_from_slice(&0x10_0000u64.to_le_bytes());
        b[o + 80..o + 88].copy_from_slice(&0x1000u64.to_le_bytes());
        b[o + 88..o + 96].copy_from_slice(&0x10_0000u64.to_le_bytes());
        b[o + 96..o + 104].copy_from_slice(&0x1000u64.to_le_bytes());
        put32(&mut b, o + 108, 16);
        put32(&mut b, o + 112, if case == "exports" { 0x10_0000 } else { 0x1000 });
        put32(&mut b, o + 116, 40);
        // The section header.
        let s = o + 0xf0;
        b[s..s + 8].copy_from_slice(b".edata\0\0");
        put32(&mut b, s + 8, 0x1000);
        put32(&mut b, s + 12, 0x1000);
        put32(&mut b, s + 16, 0x200);
        put32(&mut b, s + 20, 0x200);
        put32(&mut b, s + 36, 0x4000_0040);
        // The export directory at RVA 0x1000 (file 0x200), its name at 0x1100.
        put32(&mut b, 0x200 + 12, if case == "name" { 0x20_0000 } else { 0x1100 });
        b[0x300..0x30c].copy_from_slice(b"damaged.dll\0");
        b
    }

    #[test]
    #[ignore = "run by test_a_frame_in_a_damaged_image_is_given_bare"]
    fn damaged_image_child() {
        use std::os::windows::io::AsRawHandle;
        let case = std::env::var("WICK_TEST_IMAGE").unwrap();
        let path = std::env::temp_dir().join(std::format!("wick-damaged-{}-{case}.dll", std::process::id()));
        std::fs::write(&path, damaged_image(&case)).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: an image section of our file, read-only.
        let section = unsafe {
            windows_sys::Win32::System::Memory::CreateFileMappingW(
                file.as_raw_handle(),
                ptr::null(),
                windows_sys::Win32::System::Memory::PAGE_READONLY | windows_sys::Win32::System::Memory::SEC_IMAGE,
                0,
                0,
                ptr::null(),
            )
        };
        assert!(!section.is_null(), "SEC_IMAGE refused the hand-made image: {}", io::Error::last_os_error());
        // SAFETY: maps the section, anywhere.
        let view = unsafe { windows_sys::Win32::System::Memory::MapViewOfFile(section, windows_sys::Win32::System::Memory::FILE_MAP_READ, 0, 0, 0) };
        assert!(!view.Value.is_null(), "the image's view: {}", io::Error::last_os_error());
        let at = view.Value as usize;
        std::println!("DAMAGED {case}: mapped at {at:#x}");
        crate::windows_mm::say_frame_for_test(0, at + 0x1010);
        std::println!("DAMAGED {case}: after the frame");
        // SAFETY: our view and section.
        unsafe {
            windows_sys::Win32::System::Memory::UnmapViewOfFile(view);
            windows_sys::Win32::Foundation::CloseHandle(section);
        }
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

    fn stack_at_the_limit(kind: Kind) {
        lazy_memory_is_mapped();
        make_the_slack_region();
        let (go, came_back) = a_thread_of(kind, 32);
        let held = no_room_left();
        go.send(()).unwrap();
        let _ = came_back.recv_timeout(std::time::Duration::from_secs(10));
        drop(held);
        std::println!("the {kind:?} thread at the limit went 128 KiB deep and the process went on");
    }

    #[test]
    #[ignore = "run by test_a_stack_that_must_grow_at_the_limit_ends_with_137 in a job of its own"]
    fn stack_at_the_limit_rust_child() {
        stack_at_the_limit(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_a_stack_that_must_grow_at_the_limit_ends_with_137 in a job of its own"]
    fn stack_at_the_limit_createthread_child() {
        stack_at_the_limit(Kind::CreateThread);
    }

    #[test]
    #[ignore = "run by test_a_stack_that_must_grow_at_the_limit_ends_with_137 in a job of its own"]
    fn stack_at_the_limit_pool_child() {
        stack_at_the_limit(Kind::Pool);
    }

    /// What a child of [`stack_during_a_move`] does once a move is held in
    /// its middle with no room left in the job.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum DuringMove {
        /// A thread holding no lock goes 128 KiB deep, is refused a stack
        /// page, waits; the move is let go once it waits.
        Ends,
        /// The same thread goes deep holding `RELEASED`.
        Held,
        /// The thread waits; the move is never let go.
        Never,
        /// As `Ends`, its retry refused (`REFUSE_STACK_RETRY`).
        Again,
        /// The reclaim's own thread goes 128 KiB deep in the move's middle.
        Reclaimer,
        /// As `Ends`, but the handler of the refused page, before it reads
        /// the reclaim's state, lets the move go and waits until the
        /// reclaim's answer is given ([`let_the_reclaim_end`]).
        Late,
    }

    static MOVE_HELD: AtomicBool = AtomicBool::new(false);
    static MOVE_GO: AtomicBool = AtomicBool::new(false);
    static DEEP_STARTED: AtomicBool = AtomicBool::new(false);
    static TOUCHER_GROWN: AtomicBool = AtomicBool::new(false);
    static DEEP_GO: AtomicBool = AtomicBool::new(false);
    static TOUCH_GO: AtomicBool = AtomicBool::new(false);

    /// `windows_mm::MOVE_HOOK`'s: holds the move (on the reclaim's
    /// thread) until [`MOVE_GO`], which may never come.
    fn hold_the_move() {
        MOVE_HELD.store(true, Ordering::SeqCst);
        while !MOVE_GO.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
    }

    /// `windows_mm::MOVE_HOOK`'s: the reclaim's own thread goes 128 KiB
    /// deep in the move's middle, past the 64 KiB committed at its start.
    fn deep_on_the_reclaimer() {
        MOVE_HELD.store(true, Ordering::SeqCst);
        core::hint::black_box(deep(32));
    }

    /// [`windows_mm::STACK_HANDLER_HOOK`]'s: in the handler of the refused
    /// page, before it reads the reclaim's state, the held move is let go
    /// and the reclaim's answer waited for: the refusal came in the move's
    /// middle, the handler finds the reclaim over.
    fn let_the_reclaim_end() {
        MOVE_GO.store(true, Ordering::SeqCst);
        while reclaim_in_flight().is_some() {
            std::thread::yield_now();
        }
    }

    /// Waits for `n` waits of a refused stack page to have begun.
    fn wait_for_stack_waits(n: u64) {
        let t = std::time::Instant::now();
        while crate::windows_mm::STACK_WAITS_BEGUN.load(Ordering::SeqCst) < n {
            assert!(t.elapsed() < std::time::Duration::from_secs(20), "no refused stack page waited");
            std::thread::yield_now();
        }
    }

    /// A chunk with 1 MiB of dead pages, moved by a touch's reclaim at the
    /// job's limit and held in the move's middle ([`hold_the_move`]); a
    /// Rust thread (its stack guarantee 20 KiB) then goes 128 KiB deep, or
    /// the reclaim's own thread does, as `mode` says.
    fn stack_during_a_move(mode: DuringMove) {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        crate::windows_mm::set_move_hook(Some(if mode == DuringMove::Reclaimer { deep_on_the_reclaimer } else { hold_the_move }));
        crate::windows_mm::REFUSE_STACK_RETRY.store(mode == DuringMove::Again, Ordering::SeqCst);
        if mode == DuringMove::Late {
            crate::windows_mm::STACK_HANDLER_HOOK.store(let_the_reclaim_end as fn() as usize, Ordering::SeqCst);
        }
        // Both threads made, started and the toucher's stack grown before
        // the limit: waited for, as a thread still starting or growing at
        // the limit is itself refused a stack page with no reclaim under
        // way and ends the process with 137 (CI run 43947438431: the
        // toucher, still in its `deep(16)`, on a 4-processor runner).
        let deep_one = std::thread::Builder::new()
            .name("wick-stack-wait".into())
            .spawn(move || {
                DEEP_STARTED.store(true, Ordering::SeqCst);
                while !DEEP_GO.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                if mode == DuringMove::Held { crate::windows_mm::with_released_held(|| deep(32)) } else { deep(32) }
            })
            .unwrap();
        let toucher = std::thread::spawn(|| {
            core::hint::black_box(deep(16));
            TOUCHER_GROWN.store(true, Ordering::SeqCst);
            while !TOUCH_GO.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            reclaim_at_touch(PAGE as usize)
        });
        wait_for(&DEEP_STARTED, "the deep thread's start");
        wait_for(&TOUCHER_GROWN, "the toucher's stack grown");
        let mut held = no_room_left();
        TOUCH_GO.store(true, Ordering::SeqCst);
        wait_for(&MOVE_HELD, "the move");
        if mode != DuringMove::Reclaimer {
            DEEP_GO.store(true, Ordering::SeqCst);
        }
        if matches!(mode, DuringMove::Ends | DuringMove::Again) {
            wait_for_stack_waits(1);
            MOVE_GO.store(true, Ordering::SeqCst);
        } else {
            // The process ends with 137 meanwhile.
            wait_for(&MOVE_GO, "the end with 137");
        }
        let r = toucher.join().expect("the toucher failed");
        let v = deep_one.join().expect("the deep thread failed");
        give_back_every_page(&mut held);
        crate::windows_mm::set_move_hook(None);
        std::println!(
            "DURINGMOVE {mode:?}: {} chunk moved; the deep thread came back ({v}); {} stack page(s) had on the retry",
            r.chunks,
            crate::windows_mm::stack_pages_had_again()
        );
        assert_eq!(r.chunks, 1);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The lines of a [`stack_during_a_move`] child, for the record.
    fn during_move_lines(text: &str) -> std::string::String {
        text.lines()
            .filter(|l| l.starts_with("STACKWAIT") || l.starts_with("DURINGMOVE") || l.starts_with("wick: a thread's stack"))
            .collect::<std::vec::Vec<_>>()
            .join(" | ")
    }

    /// A stack page the job's limit refuses while a move is in its middle
    /// is had once the move ends, and the thread goes on: the thread,
    /// holding none of wick's memory locks, waits for the reclaim's next
    /// step and asks once more (`windows_mm::stack_page_after_the_reclaim`),
    /// as Linux's memory cgroup reclaims and charges the page (where before
    /// the process ended with 137). STACKWAIT: the stack the wait and the
    /// retry used under the handler's frame, of what was left there.
    /// The main thread takes the job's room ([`no_room_left`]) only once
    /// the deep thread has started and the toucher's stack is grown
    /// (`DEEP_STARTED`, `TOUCHER_GROWN`): a thread still starting or growing
    /// at the limit is refused its own stack page with no reclaim under way
    /// and ends the child with 137 (CI run 43947438431).
    #[test]
    fn test_a_stack_page_refused_during_a_move_is_had_once_it_ends() {
        let (code, text) = run_child("stack_during_a_move_ends_child", Some(96 << 20));
        std::eprintln!("STACKWAIT ends: {code:?}; {}", during_move_lines(&text));
        assert!(text.contains("DURINGMOVE Ends: 1 chunk moved; the deep thread came back"), "{text}");
        assert!(text.lines().any(|l| l.starts_with("STACKWAIT") && l.contains("the reclaim's step seen; the page had")), "{text}");
        assert!(!text.contains("wick: a thread's stack could not grow"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_stack_page_refused_during_a_move_is_had_once_it_ends in a job of its own"]
    fn stack_during_a_move_ends_child() {
        stack_during_a_move(DuringMove::Ends);
    }

    /// A stack page refused in a move's middle whose handler reads the
    /// reclaim's state only after the reclaim's answer was given (the
    /// dispatch between the refusal and that read, held open by
    /// [`let_the_reclaim_end`]) is had: the handler asks for the page once
    /// more, with no wait, whenever the commit was refused, so the room the
    /// move gave back is found; before, it found no reclaim under way and
    /// the process ended with 137.
    /// The main thread takes the job's room ([`no_room_left`]) only once
    /// the deep thread has started and the toucher's stack is grown
    /// (`DEEP_STARTED`, `TOUCHER_GROWN`): a thread still starting or growing
    /// at the limit is refused its own stack page with no reclaim under way
    /// and ends the child with 137 (CI run 43947438431).
    #[test]
    fn test_a_stack_page_refused_as_the_reclaim_ends_is_had() {
        let (code, text) = run_child("stack_during_a_move_late_child", Some(96 << 20));
        std::eprintln!("STACKWAIT late: {code:?}; {}", during_move_lines(&text));
        assert!(text.contains("DURINGMOVE Late: 1 chunk moved; the deep thread came back"), "{text}");
        assert!(text.lines().any(|l| l.starts_with("STACKWAIT the retry alone (no wait)") && l.ends_with("the page had")), "{text}");
        assert!(!text.contains("wick: a thread's stack could not grow"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_stack_page_refused_as_the_reclaim_ends_is_had in a job of its own"]
    fn stack_during_a_move_late_child() {
        stack_during_a_move(DuringMove::Late);
    }

    /// A thread that holds one of wick's memory locks (`RELEASED`, as
    /// `released_resolve` holds it over its charge and commit) when its
    /// stack page is refused during a move does not wait: the move may need
    /// that lock, so the wait could be for itself. It ends as before, with
    /// 137, at once, its line saying why it did not wait.
    /// The main thread takes the job's room ([`no_room_left`]) only once
    /// the deep thread has started and the toucher's stack is grown
    /// (`DEEP_STARTED`, `TOUCHER_GROWN`): a thread still starting or growing
    /// at the limit is refused its own stack page with no reclaim under way
    /// and ends the child with 137 (CI run 43947438431).
    #[test]
    fn test_a_stack_page_refused_with_a_lock_held_is_not_waited_for() {
        let (code, text) = run_child("stack_during_a_move_held_child", Some(96 << 20));
        std::eprintln!("STACKWAIT held: {code:?}; {}", during_move_lines(&text));
        let line = text.lines().find(|l| l.starts_with("wick: a thread's stack could not grow")).unwrap_or_default();
        assert!(line.contains("\"wick-stack-wait\"") && line.contains("a reclaim was under way and was not waited for: the thread held 1 of wick's memory locks"), "{text}");
        assert!(!text.contains("STACKWAIT the wait"), "{text}");
        assert_eq!(code, Some(137), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_stack_page_refused_with_a_lock_held_is_not_waited_for in a job of its own"]
    fn stack_during_a_move_held_child() {
        stack_during_a_move(DuringMove::Held);
    }

    /// A wait for a move that does not end is bounded
    /// (`windows_mm::STACK_WAIT_BOUND`, 1 s): the page is asked for once
    /// more, refused, and the process ends with 137, its line saying it
    /// waited to the bound.
    /// The main thread takes the job's room ([`no_room_left`]) only once
    /// the deep thread has started and the toucher's stack is grown
    /// (`DEEP_STARTED`, `TOUCHER_GROWN`): a thread still starting or growing
    /// at the limit is refused its own stack page with no reclaim under way
    /// and ends the child with 137 (CI run 43947438431).
    #[test]
    fn test_a_stack_page_waits_for_a_move_that_does_not_end_to_its_bound() {
        let (code, text) = run_child("stack_during_a_move_never_child", Some(96 << 20));
        std::eprintln!("STACKWAIT never: {code:?}; {}", during_move_lines(&text));
        let line = text.lines().find(|l| l.starts_with("wick: a thread's stack could not grow")).unwrap_or_default();
        assert!(line.contains("a reclaim was under way and was waited for, ") && line.contains("(its bound reached), and the page was still refused"), "{text}");
        let us: u64 = line.split("waited for, ").nth(1).and_then(|r| r.split(' ').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
        assert!((1_000_000..3_000_000).contains(&us), "waited {us} us: {text}");
        assert_eq!(code, Some(137), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_stack_page_waits_for_a_move_that_does_not_end_to_its_bound in a job of its own"]
    fn stack_during_a_move_never_child() {
        stack_during_a_move(DuringMove::Never);
    }

    /// One wait and one retry: a page refused again after the move ended
    /// (the retry refused by `REFUSE_STACK_RETRY`, a test hook) ends the
    /// process with 137, its line saying it waited for the reclaim's step
    /// and the page was still refused, which tells it from the end without
    /// a wait.
    /// The main thread takes the job's room ([`no_room_left`]) only once
    /// the deep thread has started and the toucher's stack is grown
    /// (`DEEP_STARTED`, `TOUCHER_GROWN`): a thread still starting or growing
    /// at the limit is refused its own stack page with no reclaim under way
    /// and ends the child with 137 (CI run 43947438431).
    #[test]
    fn test_a_stack_page_refused_again_after_the_wait_ends_with_137() {
        let (code, text) = run_child("stack_during_a_move_again_child", Some(96 << 20));
        std::eprintln!("STACKWAIT again: {code:?}; {}", during_move_lines(&text));
        let line = text.lines().find(|l| l.starts_with("wick: a thread's stack could not grow")).unwrap_or_default();
        assert!(line.contains("a reclaim was under way and was waited for, ") && line.contains("(to its next step), and the page was still refused"), "{text}");
        assert_eq!(code, Some(137), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_stack_page_refused_again_after_the_wait_ends_with_137 in a job of its own"]
    fn stack_during_a_move_again_child() {
        stack_during_a_move(DuringMove::Again);
    }

    /// The reclaim's own thread never waits for a reclaim (it would wait
    /// for itself): its stack is committed whole at its start
    /// (`RECLAIMER_STACK`, `test_the_reclaimers_stack_on_record`); made to
    /// go past it in a move's middle at the limit, it ends the process with
    /// 137 at once, its line naming it.
    /// The main thread takes the job's room ([`no_room_left`]) only once
    /// the deep thread has started and the toucher's stack is grown
    /// (`DEEP_STARTED`, `TOUCHER_GROWN`): a thread still starting or growing
    /// at the limit is refused its own stack page with no reclaim under way
    /// and ends the child with 137 (CI run 43947438431).
    #[test]
    fn test_the_reclaimers_own_stack_page_is_not_waited_for() {
        for extra in XSAVE_EXTRAS {
            let (code, text) = run_child_with("stack_during_a_move_reclaimer_child", Some(96 << 20), &[("WICK_TEST_XSAVE_EXTRA", extra)]);
            std::eprintln!("STACKWAIT reclaimer, XSAVE area {extra} B larger: {code:?}; {}", during_move_lines(&text));
            let line = text.lines().find(|l| l.starts_with("wick: a thread's stack could not grow")).unwrap_or_default();
            assert!(line.contains("a reclaim was under way and was not waited for: the thread is the reclaim's own"), "{extra}: {text}");
            assert!(!text.contains("STACKWAIT the wait"), "{extra}: {text}");
            assert_eq!(code, Some(137), "{extra}: {text}");
            let room = stack_room_problems(&text, extra);
            assert!(room.is_empty(), "{extra}: {room:#?}\n{text}");
        }
    }

    #[test]
    #[ignore = "run by test_the_reclaimers_own_stack_page_is_not_waited_for in a job of its own"]
    fn stack_during_a_move_reclaimer_child() {
        stack_during_a_move(DuringMove::Reclaimer);
    }

    /// A stack overflow at the reserve's end is still one, with the stack
    /// filter in place: the filter says so (its line, with how much of the
    /// reserve was left, the thread and its guarantee) and ends the process
    /// with `STATUS_STACK_OVERFLOW` (0xC00000FD) itself, on each kind of
    /// thread ([`Kind`]), with room left, and no thread pool's callback runs
    /// after it (no FILTERREC "the next callback ran" line); each child at
    /// error mode 0 (the system's default) and 3 (`SEM_FAILCRITICALERRORS |
    /// SEM_NOGPFAULTERRORBOX`, what CI's runner gives its children), alone,
    /// where the filter ends it with `RaiseFailFastException` and the
    /// exception's record (Windows Error Reporting reports it if enabled),
    /// and in a job as the jailer makes Firecracker's
    /// (`JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, which Learn says
    /// forces `SEM_NOGPFAULTERRORBOX` on each process of the job: Windows
    /// Error Reporting is not called, and the unhandled-exception filter's
    /// caller handles the exception), where it ends it with
    /// `TerminateProcess`. Each line says which. Before, a pool thread's
    /// overflow passed on (`EXCEPTION_CONTINUE_SEARCH`) under
    /// `SEM_NOGPFAULTERRORBOX` (the job's, or error mode 3 alone) was taken
    /// by the pool's own handler, which went on running callbacks on that
    /// thread, the process with it (exit 0: in the job on Windows Server
    /// 2022 20348 and 2025 26100 alike; alone at error mode 3 in CI run
    /// 43881982686 and FILTERREC). A control: an access violation on a pool
    /// thread at error mode 0 and 3 alone, which the pool's handler never
    /// took (0xC0000005 before and after); under the mutation that ends the
    /// process by `RaiseFailFastException` without the exception's record
    /// (STATUS_FAIL_FAST_EXCEPTION, 0xC0000602, in place of its code) it
    /// fails, with the overflow's cases.
    /// Each child waits for its thread by the thread's own
    /// structure, with no timeout ([`stack_overflow`]): a child whose
    /// process went on says how, and ends 0.
    ///
    /// Its record, STACKENDHOST: the host's build and revision, this
    /// process's error mode, its just-in-time debugger (AeDebug) and Windows
    /// Error Reporting's keys; and for each child when it ended after the
    /// filter's line, with what status, and, if it still runs 12 s after
    /// its start, the processes it started or that report its fault, and
    /// its threads' stacks (cdb, where the host has it).
    #[test]
    fn test_a_stack_overflow_at_the_reserves_end_is_still_one() {
        stack_end_host_record();
        let mut not_ended = std::vec::Vec::new();
        for extra in XSAVE_EXTRAS {
            for child in ["stack_overflow_rust_child", "stack_overflow_createthread_child", "stack_overflow_pool_child"] {
                for jailed in [false, true] {
                    for mode in ["0", "3"] {
                        let env = [("WICK_TEST_ERROR_MODE", mode), ("WICK_TEST_XSAVE_EXTRA", extra)];
                        let (code, text, ended) = run_child_watched(child, &env, jailed);
                        let how = if jailed { "in a job as the jailer's" } else { "alone" };
                        std::eprintln!(
                            "STACKEND {child} {how}, error mode {mode}, XSAVE area {extra} B larger: {code:?} after {ended:?}; {}",
                            text.trim().replace('\n', " | ")
                        );
                        let said = text.contains("wick: a thread's stack overflowed at its reserve's end")
                            && text.contains(if jailed { ENDS_JAILED_OVERFLOW } else { ENDS_OVERFLOW });
                        let room = stack_room_problems(&text, extra);
                        if !said || code != Some(0xC000_00FD_u32.cast_signed()) || text.contains(NEXT_RAN) || !room.is_empty() {
                            not_ended.push(std::format!("{child} {how}, error mode {mode}, {extra} B ({code:?}): {room:?}: {text}"));
                        }
                    }
                }
            }
        }
        // The control: a pool thread's access violation, alone.
        for mode in ["0", "3"] {
            let env = [("WICK_TEST_FAULT", "av"), ("WICK_TEST_LAZY", "1"), ("WICK_TEST_ERROR_MODE", mode)];
            let (code, text, ended) = run_child_watched("unhandled_pool_child", &env, false);
            std::eprintln!("STACKEND control unhandled_pool_child av alone, error mode {mode}: {code:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
            if !text.contains(ENDS) || code != Some(0xC000_0005_u32.cast_signed()) || text.contains(NEXT_RAN) {
                not_ended.push(std::format!("the control, a pool thread's access violation, error mode {mode} ({code:?}): {text}"));
            }
        }
        assert!(not_ended.is_empty(), "not ended by the filter with its line and the exception's code: {not_ended:#?}");
    }

    /// The line [`on_a_thread_and_wait`]'s next callback writes: a pool went
    /// on after the exception.
    const NEXT_RAN: &str = "FILTERREC the next callback ran";
    /// How the filters' lines end: out of a job of the jailer's limits, and
    /// in one; for the last filter, and for a stack overflow at the
    /// reserve's end (the stack filter's).
    const ENDS: &str = "the process ends with its code, reported by Windows Error Reporting if it is enabled";
    const ENDS_JAILED: &str = "in a job that dies on unhandled exceptions, the process ends with its code";
    const ENDS_OVERFLOW: &str = "the process ends with STATUS_STACK_OVERFLOW (0xC00000FD), reported by Windows Error Reporting if it is enabled";
    const ENDS_JAILED_OVERFLOW: &str = "in a job that dies on unhandled exceptions, the process ends with STATUS_STACK_OVERFLOW (0xC00000FD)";

    /// An unbounded recursion on a new thread of `kind`, waited for by the
    /// thread's own structure ([`on_a_thread_and_wait`]): the overflow either
    /// ends the process or this returns and says how the process went on. A
    /// child run in a job waits until it is in that job first
    /// ([`in_the_job_if_asked`]).
    fn stack_overflow(kind: Kind) {
        fn said_then_deep(kind: Kind) {
            let (base, limit, reserve, guarantee) = stack_of_this_thread();
            std::println!(
                "the {kind:?} thread's stack: {} KiB committed of a {} KiB reserve, a guarantee of {guarantee} bytes",
                (base - limit) >> 10,
                (base - reserve) >> 10
            );
            core::hint::black_box(deep(usize::MAX));
        }
        in_the_job_if_asked();
        lazy_memory_is_mapped();
        let how = on_a_thread_and_wait(kind, said_then_deep);
        std::println!("the {kind:?} thread's unbounded recursion: {how}, and the process went on");
    }

    /// A child run in a job (WICK_TEST_JOB, its name) waits until it is in
    /// that job, and says its error mode.
    fn in_the_job_if_asked() {
        if let Ok(name) = std::env::var("WICK_TEST_JOB") {
            use windows_sys::Win32::System::JobObjects::{IsProcessInJob, OpenJobObjectW};
            use windows_sys::Win32::System::Threading::GetCurrentProcess;
            /// winnt.h's (windows-sys has it under System_SystemServices).
            const JOB_OBJECT_QUERY: u32 = 4;
            let wide: std::vec::Vec<u16> = name.encode_utf16().chain([0]).collect();
            // SAFETY: a NUL-terminated name.
            let job = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, wide.as_ptr()) };
            assert!(!job.is_null(), "the job {name}: {}", io::Error::last_os_error());
            // The parent assigns this process once it has started it.
            loop {
                let mut is = 0;
                // SAFETY: this process, a job handle with JOB_OBJECT_QUERY.
                assert_ne!(unsafe { IsProcessInJob(GetCurrentProcess(), job, &mut is) }, 0);
                if is != 0 {
                    break;
                }
                std::thread::yield_now();
            }
            // SAFETY: our handle.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            use windows_sys::Win32::System::JobObjects::{
                JOBOBJECT_BASIC_LIMIT_INFORMATION, JobObjectBasicLimitInformation, QueryInformationJobObject,
            };
            // SAFETY: plain data.
            let mut l: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { core::mem::zeroed() };
            // SAFETY: this process's job (Learn, QueryInformationJobObject:
            // with no handle, "the immediate job of the calling process").
            #[allow(clippy::cast_possible_truncation)]
            let ok = unsafe { QueryInformationJobObject(ptr::null_mut(), JobObjectBasicLimitInformation, (&raw mut l).cast(), core::mem::size_of_val(&l) as u32, ptr::null_mut()) };
            std::println!("the child's immediate job: query {ok}, limit flags {:#x}", l.LimitFlags);
        }
        // FILTERREC: the error mode asked of the child, in place of the one
        // it inherited, and the filters' frames said.
        if let Some(mode) = std::env::var("WICK_TEST_ERROR_MODE").ok().and_then(|m| m.parse::<u32>().ok()) {
            // SAFETY: plain call.
            unsafe { windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(mode) };
        }
        if std::env::var_os("WICK_TEST_FILTER_FRAMES").is_some() {
            crate::windows_mm::SAY_FILTER_FRAMES.store(true, Ordering::SeqCst);
        }
        if std::env::var_os("WICK_TEST_FAIL_FAST").is_some() {
            crate::windows_mm::FAIL_FAST.store(true, Ordering::SeqCst);
        }
        if let Some(k) = std::env::var("WICK_TEST_FAIL_FAST_EAT_KIB").ok().and_then(|k| k.parse::<usize>().ok()) {
            crate::windows_mm::FAIL_FAST_EAT_KIB.store(k, Ordering::SeqCst);
        }
        // SAFETY: plain call.
        std::println!("the child's error mode: {:#x}", unsafe { windows_sys::Win32::System::Diagnostics::Debug::GetErrorMode() });
    }

    /// FILTERREC: the thread a pool's first callback ran on (0 before).
    static POOLED_ON: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    /// FILTERREC, a record: how an unhandled exception on a thread pool's
    /// thread ends, by the child's error mode (0, the system's default;
    /// 2, `SEM_NOGPFAULTERRORBOX`, which Learn's SetErrorMode says makes
    /// "the system not invoke Windows Error Reporting", and with which
    /// UnhandledExceptionFilter "returns control to the exception handler,
    /// which is free to take any appropriate action"; 3, as CI's runner
    /// gives its children), for a stack overflow at the reserve's end and
    /// an access violation, each child alone (no job): its end, the frames
    /// the filters were called from (FILTERFRAMES), and, where the process
    /// went on, the thread the pool's next callback ran on and that
    /// thread's stack (its guard page). With STACKENDHOST's host part.
    #[test]
    #[ignore = "a record, run by hand and by CI's WHP step"]
    fn test_how_a_pool_threads_unhandled_exception_ends_on_record() {
        stack_end_host_record();
        for (child, env) in [
            ("stack_overflow_pool_child", &[][..]),
            ("unhandled_pool_child", &[("WICK_TEST_FAULT", "av"), ("WICK_TEST_LAZY", "1")][..]),
        ] {
            for mode in ["0", "2", "3"] {
                let mut e = env.to_vec();
                e.push(("WICK_TEST_ERROR_MODE", mode));
                e.push(("WICK_TEST_FILTER_FRAMES", "1"));
                let (code, text, ended) = run_child_watched(child, &e, false);
                std::eprintln!("FILTERREC {child} error mode {mode}: {code:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
            }
            // The end the filters would give by RaiseFailFastException: by
            // error mode alone, and in a job of the jailer's limits.
            for (mode, jailed) in [("0", false), ("3", false), ("0", true)] {
                let mut e = env.to_vec();
                e.push(("WICK_TEST_ERROR_MODE", mode));
                e.push(("WICK_TEST_FAIL_FAST", "1"));
                let (code, text, ended) = run_child_watched(child, &e, jailed);
                std::eprintln!(
                    "FILTERREC {child} fail-fast, error mode {mode}{}: {code:?} after {ended:?}; {}",
                    if jailed { ", in a job as the jailer's" } else { "" },
                    text.trim().replace('\n', " | ")
                );
            }
        }
    }

    /// FAILFASTSTACK, a record: how much stack `RaiseFailFastException`
    /// takes when the stack filter calls it at a stack overflow at the
    /// reserve's end (the filters' end out of a job, `windows_mm::end_with`),
    /// on each kind of thread, alone at error mode 3: the filter first takes
    /// 0, 1, 2, ... KiB more of the stack ([`crate::windows_mm::FAIL_FAST_EAT_KIB`])
    /// and says the bytes then left above the reserve's low end; the child
    /// ends with [`crate::windows_mm::FAIL_FAST_PROBE`] while the call had
    /// the stack it needs. Per kind, the least left that still ended so and
    /// the most that did not.
    #[test]
    #[ignore = "a record, run by hand"]
    fn test_how_much_stack_fail_fast_takes_at_the_reserves_end_on_record() {
        let probe = crate::windows_mm::FAIL_FAST_PROBE.cast_signed();
        for child in ["stack_overflow_rust_child", "stack_overflow_createthread_child", "stack_overflow_pool_child"] {
            let (mut ended, mut not) = (usize::MAX, 0usize);
            for k in 0..=40 {
                let kib = std::format!("{k}");
                let env = [("WICK_TEST_ERROR_MODE", "3"), ("WICK_TEST_FAIL_FAST_EAT_KIB", kib.as_str())];
                let (code, text, _) = run_child_watched(child, &env, false);
                let left = text
                    .split("KiB taken, ")
                    .nth(1)
                    .and_then(|t| t.split(' ').next())
                    .and_then(|n| n.parse::<usize>().ok());
                std::eprintln!("FAILFASTSTACK {child} took {k} KiB more: {code:?}, {left:?} bytes left before the call");
                match (code == Some(probe), left) {
                    (true, Some(l)) => ended = ended.min(l),
                    (false, Some(l)) => not = not.max(l),
                    _ => {}
                }
                if code != Some(probe) && left.is_none() {
                    break;
                }
            }
            std::eprintln!("FAILFASTSTACK {child}: ended with the record's code with {ended} bytes left at least; not with {not} at most");
        }
    }

    /// Runs `body` on a new thread of `kind` and waits for it by the
    /// thread's own structure, with no timeout; says how it went on if the
    /// process did. A Rust or `CreateThread` thread is waited for to its
    /// end (its handle); a pool thread is the only thread of a pool of its
    /// own (at most and at least one, Learn: SetThreadpoolThreadMaximum,
    /// SetThreadpoolThreadMinimum), and a second callback is queued once the
    /// first has started `body`, so it runs only once that thread is back in
    /// its pool (or a new one replaced it): as Windows Server 2025
    /// 26100.33674's pool took a stack overflow and went on waiting for work
    /// (CI run 43823078930's windows job: the child's process alive after
    /// 60 s, its overflowed thread back in `ntdll!TppWorkerThread`).
    fn on_a_thread_and_wait(kind: Kind, body: fn(Kind)) -> std::string::String {
        use windows_sys::Win32::System::Threading::{
            CloseThreadpool, CreateThread, CreateThreadpool, INFINITE, PTP_CALLBACK_INSTANCE, SetThreadpoolThreadMaximum,
            SetThreadpoolThreadMinimum, TP_CALLBACK_ENVIRON_V3, TP_CALLBACK_PRIORITY_NORMAL, TrySubmitThreadpoolCallback,
            WaitForSingleObject,
        };
        type Started = (std::sync::mpsc::Sender<()>, fn(Kind));
        unsafe extern "system" fn started(raw: *mut c_void) -> u32 {
            // SAFETY: the function pointer passed below.
            let body: fn(Kind) = unsafe { core::mem::transmute::<*mut c_void, fn(Kind)>(raw) };
            body(Kind::CreateThread);
            0
        }
        unsafe extern "system" fn pooled(_: PTP_CALLBACK_INSTANCE, raw: *mut c_void) {
            // SAFETY: the pair boxed below, given to this callback alone.
            let (said, body) = *unsafe { std::boxed::Box::from_raw(raw.cast::<Started>()) };
            // SAFETY: plain call.
            POOLED_ON.store(unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() }, Ordering::SeqCst);
            said.send(()).unwrap();
            drop(said);
            body(Kind::Pool);
        }
        unsafe extern "system" fn next(_: PTP_CALLBACK_INSTANCE, tx: *mut c_void) {
            // SAFETY: the sender boxed below, given to this callback alone.
            let tx = unsafe { std::boxed::Box::from_raw(tx.cast::<std::sync::mpsc::Sender<()>>()) };
            {
                use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, PAGE_GUARD, VirtualQuery};
                // SAFETY: plain call.
                let me = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
                let (_, limit, reserve, guarantee) = stack_of_this_thread();
                // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our stack.
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
                // SAFETY: as above, the page below the committed part.
                let q = unsafe { VirtualQuery((limit - PAGE as usize) as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) };
                std::println!(
                    "FILTERREC the next callback ran on thread {me} (the first ran on {}); its stack: {} KiB of the reserve left below \
                     the committed part, the page below it state {:#x} protection {:#x} (a guard page: {}), its guarantee {guarantee}",
                    POOLED_ON.load(Ordering::SeqCst),
                    (limit - reserve) >> 10,
                    if q == 0 { 0 } else { mbi.State },
                    if q == 0 { 0 } else { mbi.Protect },
                    q != 0 && mbi.Protect & PAGE_GUARD != 0
                );
            }
            let _ = tx.send(());
        }
        match kind {
            Kind::Rust => {
                let ended = std::thread::Builder::new().name("wick-stack-test".into()).spawn(move || body(Kind::Rust)).unwrap().join();
                std::format!("the thread ended ({})", if ended.is_ok() { "returned" } else { "panicked" })
            }
            Kind::CreateThread => {
                // SAFETY: a thread of ours with the default stack.
                let t = unsafe { CreateThread(ptr::null(), 0, Some(started), body as *mut c_void, 0, ptr::null_mut()) };
                assert!(!t.is_null());
                // SAFETY: our thread's handle.
                unsafe { WaitForSingleObject(t, INFINITE) };
                "the thread ended".into()
            }
            Kind::Pool => {
                // SAFETY: a pool of our own.
                let pool = unsafe { CreateThreadpool(ptr::null()) };
                assert_ne!(pool, 0);
                // SAFETY: our pool, of one thread.
                unsafe {
                    SetThreadpoolThreadMaximum(pool, 1);
                    assert_ne!(SetThreadpoolThreadMinimum(pool, 1), 0);
                }
                // As TpInitializeCallbackEnviron and TpSetCallbackThreadpool
                // (winnt.h) make it.
                let env = TP_CALLBACK_ENVIRON_V3 {
                    Version: 3,
                    Pool: pool,
                    CallbackPriority: TP_CALLBACK_PRIORITY_NORMAL,
                    #[allow(clippy::cast_possible_truncation)]
                    Size: core::mem::size_of::<TP_CALLBACK_ENVIRON_V3>() as u32,
                    ..Default::default()
                };
                let (said, has_started) = std::sync::mpsc::channel::<()>();
                let raw = std::boxed::Box::into_raw(std::boxed::Box::new((said, body))).cast::<c_void>();
                // SAFETY: a callback of this module, on our pool.
                assert_ne!(unsafe { TrySubmitThreadpoolCallback(Some(pooled), raw, &env) }, 0);
                // The next callback is queued once the pool's one thread has
                // started `body`, so it runs only once that thread is back.
                has_started.recv().unwrap();
                let (tx, rx) = std::sync::mpsc::channel::<()>();
                let tx = std::boxed::Box::into_raw(std::boxed::Box::new(tx)).cast::<c_void>();
                // SAFETY: as above.
                assert_ne!(unsafe { TrySubmitThreadpoolCallback(Some(next), tx, &env) }, 0);
                rx.recv().unwrap();
                // SAFETY: our pool, its callbacks done.
                unsafe { CloseThreadpool(pool) };
                "its pool ran the next callback".into()
            }
        }
    }

    /// The exceptions [`test_an_unhandled_exception_ends_the_process_with_its_code`]
    /// raises, and their codes: an access violation (a write to address 8),
    /// an illegal instruction (`ud2`) and software exceptions no signal
    /// stands for, one raised non-continuable and one continuable.
    const UNHANDLED: [(&str, u32); 4] = [("av", 0xC000_0005), ("ud2", 0xC000_001D), ("raise", 0xE057_1C4B), ("raise-continuable", 0xE057_1C4D)];

    /// An exception that nothing handles gets a line that names it, its
    /// address and its thread (the last unhandled-exception filter,
    /// `windows_mm::last_filter`), and the filter ends the process with its
    /// code, with no pool callback after it (no [`NEXT_RAN`] line), on
    /// every kind of thread ([`Kind`]), at error mode 0 and 3, alone and in
    /// a job of the jailer's limits, with lazy memory mapped (the stack
    /// filter above it, as in a VMM) and, for the access violation, without
    /// (as in the API process or the jailer): in the job by
    /// `TerminateProcess`, where the end is left to the filters' caller,
    /// which for a pool thread's stack overflow was its pool, going on
    /// ([`test_a_stack_overflow_at_the_reserves_end_is_still_one`]); alone by
    /// `RaiseFailFastException` with the exception's record, which Windows
    /// Error Reporting reports if it is enabled, as Linux's default action
    /// for a fault signal no handler is registered for ends a process with
    /// a core. No time is asserted.
    #[test]
    fn test_an_unhandled_exception_ends_the_process_with_its_code() {
        let mut not_ended = std::vec::Vec::new();
        for (fault, code) in UNHANDLED {
            for lazy in ["1", "0"] {
                if lazy == "0" && fault != "av" {
                    continue;
                }
                for child in ["unhandled_rust_child", "unhandled_createthread_child", "unhandled_pool_child"] {
                    for jailed in [false, true] {
                        for mode in ["0", "3"] {
                            let env = [("WICK_TEST_FAULT", fault), ("WICK_TEST_LAZY", lazy), ("WICK_TEST_ERROR_MODE", mode)];
                            let (got, text, ended) = run_child_watched(child, &env, jailed);
                            let how = if jailed { "in a job as the jailer's" } else { "alone" };
                            std::eprintln!(
                                "UNHANDLED {child} {fault} lazy {lazy} {how}, error mode {mode}: {got:?} after {ended:?}; {}",
                                text.trim().replace('\n', " | ")
                            );
                            let said = text.contains(&std::format!("wick: an unhandled exception {code:#x}"))
                                && text.contains(if jailed { ENDS_JAILED } else { ENDS });
                            if !said || got != Some(code.cast_signed()) || text.contains(NEXT_RAN) {
                                not_ended.push(std::format!("{child} {fault} lazy {lazy} {how}, error mode {mode} ({got:?}): {text}"));
                            }
                        }
                    }
                }
            }
        }
        assert!(not_ended.is_empty(), "not ended by the last filter with its line and the exception's code: {not_ended:#?}");
    }

    /// The last filter keeps the filter it replaced: in this executable,
    /// which the Visual C++ runtime starts, the runtime's own
    /// (`__scrt_unhandled_exception_filter`, installed by its
    /// `pre_cpp_initialization` in `.CRT$XCAA`, before the `.CRT$XCU`
    /// initializer that installs the last filter). LASTFILTER: where it is,
    /// as this executable plus an offset (named with cdb and the pdb).
    #[test]
    fn test_the_last_filter_keeps_the_filter_it_replaced() {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
        let replaced = crate::windows_mm::replaced_at_start();
        let base_of = |a: usize| {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
            // SAFETY: as above.
            assert_ne!(unsafe { VirtualQuery(a as *const c_void, &mut mbi, core::mem::size_of_val(&mbi)) }, 0);
            mbi.AllocationBase as usize
        };
        assert_ne!(replaced, 0, "the last filter replaced no filter");
        let exe = base_of(test_the_last_filter_keeps_the_filter_it_replaced as *const () as usize);
        std::eprintln!(
            "LASTFILTER the filter the last one replaced: {replaced:#x}, {}+{:#x} (this executable at {exe:#x})",
            if base_of(replaced) == exe { "this executable" } else { "another module" },
            replaced - base_of(replaced)
        );
        assert_eq!(base_of(replaced), exe, "the filter replaced is not this executable's");
    }

    /// An MSVC C++ exception nothing catches (`unhandled_fault`'s "cxx")
    /// reaches the last filter, which writes its line and calls the filter
    /// it replaced, the C runtime's, which ends the process with
    /// `terminate()`: with no terminate handler set, `abort()`
    /// (ucrt 10.0.26100.0 misc/terminate.cpp:38-58), which with no SIGABRT
    /// handler ends it by `__fastfail(FAST_FAIL_FATAL_APP_EXIT)`
    /// (startup/abort.cpp:71-77), exit 0xC0000409; on each kind of thread,
    /// alone and in a job of the jailer's limits (the last filter's own end
    /// in such a job is not reached). CXXEND: each child's end.
    #[test]
    fn test_a_cxx_exception_nothing_catches_ends_through_the_runtimes_filter() {
        let mut wrong = std::vec::Vec::new();
        for child in ["unhandled_rust_child", "unhandled_createthread_child", "unhandled_pool_child"] {
            for jailed in [false, true] {
                let (got, text, ended) = run_child_watched(child, &[("WICK_TEST_FAULT", "cxx"), ("WICK_TEST_LAZY", "1")], jailed);
                let how = if jailed { "in a job as the jailer's" } else { "alone" };
                std::eprintln!("CXXEND {child} {how}: {got:?} after {ended:?}; {}", text.trim().replace('\n', " | "));
                let said = text.contains("wick: an unhandled exception 0xe06d7363")
                    && text.contains("a C++ exception, which the filter this one replaced (the C runtime's) ends with terminate()");
                if !said || got != Some(0xC000_0409_u32.cast_signed()) {
                    wrong.push(std::format!("{child} {how} ({got:?}): {text}"));
                }
            }
        }
        assert!(wrong.is_empty(), "not ended by the runtime's filter after the last filter's line: {wrong:#?}");
    }

    /// A process in a job without `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`
    /// nested in one with it (an operator's job around an unjailed VMM)
    /// ends as one in no such job: the outer job's limit does not reach it.
    /// Its immediate job's query (what the filters ask) shows no flag;
    /// a pool thread's stack overflow and an access violation, on a pool
    /// thread and a `CreateThread` thread, end the process with their code
    /// by the filters' `RaiseFailFastException`, the line out of such a job
    /// said, as with the inner job alone, and no pool callback runs after
    /// it (no [`NEXT_RAN`] line), at error mode 0 and 3 (the outer job's
    /// flag forces no error mode on the inner job's process). NESTJOB: each
    /// child's end, nested and with the inner job alone.
    #[test]
    fn test_a_job_nested_in_one_that_dies_on_unhandled_exceptions_ends_by_its_own_limits() {
        use windows_sys::Win32::System::JobObjects::{JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
        let jobs = [JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE];
        let mut wrong = std::vec::Vec::new();
        for (child, env) in [
            ("stack_overflow_pool_child", &[][..]),
            ("unhandled_pool_child", &[("WICK_TEST_FAULT", "av"), ("WICK_TEST_LAZY", "1")][..]),
            ("unhandled_createthread_child", &[("WICK_TEST_FAULT", "av"), ("WICK_TEST_LAZY", "1")][..]),
        ] {
            let code: u32 = if child.starts_with("stack") { 0xC000_00FD } else { 0xC000_0005 };
            let ends = if child.starts_with("stack") { ENDS_OVERFLOW } else { ENDS };
            for extra in XSAVE_EXTRAS {
                for nested in [false, true] {
                    for mode in ["0", "3"] {
                        let mut e = env.to_vec();
                        e.push(("WICK_TEST_ERROR_MODE", mode));
                        e.push(("WICK_TEST_XSAVE_EXTRA", extra));
                        let (got, text, ended) = run_child_in_jobs(child, &e, if nested { &jobs[..] } else { &jobs[1..] });
                        let how = if nested { "inner job (no flag) in an outer one with the flag" } else { "one job, no flag" };
                        std::eprintln!(
                            "NESTJOB {child} {how}, error mode {mode}, XSAVE area {extra} B larger: {got:?} after {ended:?}; {}",
                            text.trim().replace('\n', " | ")
                        );
                        let flags = std::format!("the child's immediate job: query 1, limit flags {JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE:#x}");
                        let room = if child.starts_with("stack") { stack_room_problems(&text, extra) } else { std::vec::Vec::new() };
                        if !text.contains(&flags) || !text.contains(ends) || got != Some(code.cast_signed()) || text.contains(NEXT_RAN) || !room.is_empty() {
                            wrong.push(std::format!("{child} {how}, error mode {mode}, {extra} B ({got:?}): {room:?}: {text}"));
                        }
                    }
                }
            }
        }
        assert!(wrong.is_empty(), "not ended as in a job without the flag: {wrong:#?}");
    }

    fn unhandled_fault(kind: Kind) {
        let fault = std::env::var("WICK_TEST_FAULT").unwrap();
        std::println!("the {kind:?} thread raises {fault}");
        match fault.as_str() {
            // SAFETY: a write that faults, on purpose.
            "av" => unsafe { core::ptr::write_volatile(core::hint::black_box(8usize) as *mut u8, 1) },
            // SAFETY: an instruction that faults, on purpose.
            "ud2" => unsafe { core::arch::asm!("ud2", options(nomem, nostack)) },
            // SAFETY: a software exception with no arguments.
            "raise" => unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseException(UNHANDLED[2].1, 1 /* EXCEPTION_NONCONTINUABLE */, 0, ptr::null()) },
            // SAFETY: as above.
            "raise-continuable" => unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseException(UNHANDLED[3].1, 0, 0, ptr::null()) },
            // An MSVC C++ exception as the runtime's filter recognises it
            // (ehdata.h:568, `PER_IS_MSVC_PURE_OR_NATIVE_EH`: the code, four
            // parameters, EH_MAGIC_NUMBER1), with no object and no
            // `ThrowInfo` (what `throw;` raises with no current exception).
            "cxx" => {
                let parameters = [0x1993_0520usize, 0, 0, 0];
                // SAFETY: four parameters, as passed.
                unsafe { windows_sys::Win32::System::Diagnostics::Debug::RaiseException(0xE06D_7363, 1, 4, parameters.as_ptr()) }
            }
            other => panic!("no fault {other}"),
        }
    }

    fn unhandled(kind: Kind) {
        in_the_job_if_asked();
        if std::env::var("WICK_TEST_LAZY").as_deref() == Ok("1") {
            lazy_memory_is_mapped();
        }
        let how = on_a_thread_and_wait(kind, unhandled_fault);
        std::println!("the {kind:?} thread's exception: {how}, and the process went on");
    }

    #[test]
    #[ignore = "run by test_an_unhandled_exception_ends_the_process_with_its_code"]
    fn unhandled_rust_child() {
        unhandled(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_an_unhandled_exception_ends_the_process_with_its_code"]
    fn unhandled_createthread_child() {
        unhandled(Kind::CreateThread);
    }

    #[test]
    #[ignore = "run by test_an_unhandled_exception_ends_the_process_with_its_code"]
    fn unhandled_pool_child() {
        unhandled(Kind::Pool);
    }

    /// STACKENDHOST's host part: this process's error mode, which its
    /// children inherit (Learn, SetErrorMode), and `reg query` of what
    /// decides how a process with an unhandled exception ends.
    fn stack_end_host_record() {
        // SAFETY: plain call.
        std::eprintln!("STACKENDHOST error mode: {:#x}", unsafe { windows_sys::Win32::System::Diagnostics::Debug::GetErrorMode() });
        const NT: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        const WER: &str = "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting";
        let keys: [(std::string::String, &[&str]); 7] = [
            (NT.into(), &["/v", "CurrentBuild"]),
            (NT.into(), &["/v", "UBR"]),
            (std::format!("{NT}\\AeDebug"), &["/s"]),
            ("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug".into(), &["/s"]),
            (std::format!("HKLM\\{WER}"), &["/s"]),
            (std::format!("HKCU\\{WER}"), &["/s"]),
            ("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting".into(), &["/s"]),
        ];
        for (path, rest) in &keys {
            let mut args = std::vec!["query", path.as_str()];
            args.extend_from_slice(rest);
            let out = std::process::Command::new("reg").args(&args).output();
            let text = match out {
                Ok(o) => std::format!("{}{}", std::string::String::from_utf8_lossy(&o.stdout), std::string::String::from_utf8_lossy(&o.stderr)),
                Err(e) => std::format!("reg: {e}"),
            };
            for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                std::eprintln!("STACKENDHOST {path}: {line}");
            }
        }
    }

    /// [`run_child`] with no memory limit, which also says when the child
    /// ended, and, if it still runs 12 s after its start, what holds it
    /// (STACKENDHOST). `jailed`: in a job of the limits the jailer gives
    /// Firecracker's (overlay/jailer/platform/windows/mod.rs,
    /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
    /// JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`), named to the child in
    /// WICK_TEST_JOB.
    fn run_child_watched(child: &str, env: &[(&str, &str)], jailed: bool) -> (Option<i32>, std::string::String, std::time::Duration) {
        use windows_sys::Win32::System::JobObjects::{JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE};
        let jobs: &[u32] = if jailed { &[JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION] } else { &[] };
        run_child_in_jobs(child, env, jobs)
    }

    /// [`run_child_watched`] in nested jobs, each with the limit flags
    /// given, outermost first: the child is assigned to each in that order
    /// (Learn, "Nested Jobs": a process already in a job assigned to
    /// another makes the second a child job of the first), and is named
    /// the innermost (WICK_TEST_JOB).
    fn run_child_in_jobs(child: &str, env: &[(&str, &str)], jobs: &[u32]) -> (Option<i32>, std::string::String, std::time::Duration) {
        use std::io::Read;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        static JOBS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let name = std::format!("{}::{child}", module_path!().split_once("::").unwrap().1);
        let mut made = std::vec::Vec::new();
        let mut job_name = std::string::String::new();
        for &flags in jobs {
            job_name = std::format!(
                "Local\\wick-test-{}-{}",
                std::process::id(),
                JOBS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let wide: std::vec::Vec<u16> = job_name.encode_utf16().chain([0]).collect();
            // SAFETY: a new job of this name.
            let job = unsafe { CreateJobObjectW(ptr::null(), wide.as_ptr()) };
            assert!(!job.is_null(), "{}", io::Error::last_os_error());
            // SAFETY: plain data.
            let mut l: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            l.BasicLimitInformation.LimitFlags = flags;
            // SAFETY: a structure of the size passed.
            unsafe {
                #[allow(clippy::cast_possible_truncation)]
                let size = std::mem::size_of_val(&l) as u32;
                assert_ne!(SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const l).cast(), size), 0);
            }
            made.push(job);
        }
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", name.as_str(), "--ignored", "--nocapture"]).envs(env.iter().copied());
        if !jobs.is_empty() {
            command.env("WICK_TEST_JOB", &job_name);
        }
        let start = std::time::Instant::now();
        let mut process = command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        for &job in &made {
            use std::os::windows::io::AsRawHandle;
            // SAFETY: our job; the child's handle.
            assert_ne!(unsafe { AssignProcessToJobObject(job, process.as_raw_handle()) }, 0, "{}", io::Error::last_os_error());
        }
        let mut out = process.stdout.take().unwrap();
        let mut err = process.stderr.take().unwrap();
        let readers = [
            std::thread::spawn(move || { let mut v = Vec::new(); let _ = out.read_to_end(&mut v); v }),
            std::thread::spawn(move || { let mut v = Vec::new(); let _ = err.read_to_end(&mut v); v }),
        ];
        let mut looked = false;
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            if !looked && start.elapsed() >= std::time::Duration::from_secs(12) {
                looked = true;
                stack_end_who_holds(child, process.id());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let ended = start.elapsed();
        for job in made.into_iter().rev() {
            // SAFETY: our job handle.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
        }
        let [o, e] = readers.map(|r| r.join().unwrap());
        let text = std::format!("{}{}", std::string::String::from_utf8_lossy(&o), std::string::String::from_utf8_lossy(&e));
        assert!(text.contains("running 1 test"), "the child {name} ran no test (status {status}): {text}");
        (status.code(), text, ended)
    }

    /// STACKENDHOST's look at a child that has not ended: the processes it
    /// started and those that report faults or debug (by name), then its
    /// threads' stacks.
    fn stack_end_who_holds(child: &str, pid: u32) {
        let script = std::format!(
            "Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {pid} -or $_.ProcessId -eq {pid} -or $_.Name -match 'WerFault|WerSvc|vsjitdebugger|dwwin|drwtsn|windbg|cdb|ntsd|procdump' }} | ForEach-Object {{ \"$($_.ProcessId) parent $($_.ParentProcessId) $($_.Name): $($_.CommandLine)\" }}"
        );
        if let Ok(o) = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &script]).output() {
            for line in std::string::String::from_utf8_lossy(&o.stdout).lines().filter(|l| !l.trim().is_empty()) {
                std::eprintln!("STACKENDHOST {child} at 12 s: {line}");
            }
        }
        let cdb = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe";
        if !std::path::Path::new(cdb).exists() {
            std::eprintln!("STACKENDHOST {child} at 12 s: no cdb at {cdb}");
            return;
        }
        let pid = std::format!("{pid}");
        if let Ok(o) = std::process::Command::new(cdb).args(["-p", pid.as_str(), "-pv", "-c", "~*kn 40; qd"]).output() {
            for line in std::string::String::from_utf8_lossy(&o.stdout).lines() {
                let l = line.trim();
                if l.starts_with(|c: char| c.is_ascii_hexdigit()) || l.contains(" Id: ") {
                    std::eprintln!("STACKENDHOST {child} stack: {l}");
                }
            }
        }
    }

    #[test]
    #[ignore = "run by test_a_stack_overflow_at_the_reserves_end_is_still_one"]
    fn stack_overflow_rust_child() {
        stack_overflow(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_a_stack_overflow_at_the_reserves_end_is_still_one"]
    fn stack_overflow_createthread_child() {
        stack_overflow(Kind::CreateThread);
    }

    #[test]
    #[ignore = "run by test_a_stack_overflow_at_the_reserves_end_is_still_one"]
    fn stack_overflow_pool_child() {
        stack_overflow(Kind::Pool);
    }

    /// A host thread's first access to lazy memory near its stack reserve's
    /// end is either served or a stack overflow at the reserve's end, said
    /// as one: never a silent end. The access is served on the thread's own
    /// stack (`windows_mm::on_exception`, below the exception
    /// dispatcher's frames), and its commit takes the region table and
    /// commits the page, so near the reserve's end the handler's own frames
    /// meet the end inside it: the stack overflow then raised there must be
    /// dispatched as any other,
    /// Rust's "has overflowed its stack" line, the stack filter's
    /// line (the reserve's end) and 0xC00000FD. A
    /// child per case: a thread recurses until a number of KiB are left
    /// above its reserve's low end (DeallocationStack), then reads a lazy
    /// page; a Rust thread and a `CreateThread` thread (both with the
    /// guarantee, `windows_mm::at_thread_start`; a pool thread's stack is
    /// the same, and its overflow's end is
    /// `test_a_stack_overflow_at_the_reserves_end_is_still_one`'s). Asserted
    /// per case:
    /// the read served and the child ended 0, or the overflow said, as
    /// above; and for each kind, that some case met the reserve's end in
    /// the handler's commit (STACKASK says where the overflow was raised),
    /// so that the window is tested, not only its edges.
    ///
    /// Where the window lies: a read at `left` KiB is served when the
    /// handler's commit, under the dispatcher's frames (the context and the
    /// simulated area) and the handler's own, stays above the guard region
    /// the guarantee sizes, so the window rises with the guarantee and the
    /// context, the simulated area counted in both. Measured, CI run
    /// 44233741878 (a context of 3247 B): at 0 B simulated (a guarantee of
    /// 24 KiB) the commit met the reserve's end at 38 to 42 KiB left and
    /// the read was served from 43; at 8256 B (32 KiB) at 55 to 59, served
    /// from 60; at 16384 B (40 KiB) not at all in 31 to 64, every case an
    /// overflow before the commit. Why there: the stack overflows at the
    /// reserve's end when it reaches the guarantee and two pages above the
    /// reserve's low end (STACKASK in the window, all three sizes: the
    /// faulting rsp 28.4 to 28.7 KiB, 36.4 to 36.9, 44.5 to 45.0 above
    /// StackLimit, which is the low end and a page: the guarantee and
    /// 8 KiB), and the read's handler commits that far below the read: the
    /// exception's context and the simulated area, the dispatcher's own
    /// frames past them (STACKASK: 2.4 KiB at 0 simulated, 3.2 with an area
    /// simulated), then the handler's frames to and through its commit
    /// (about 4 KiB to its deepest, 5 KiB wide: the window's width). So
    /// the window is 8 + 2.4 to 3.2 + 0 to 5 KiB, 11 to 16, above the
    /// guarantee, the context and the simulated area together, as measured
    /// (14.8 and 15.8 at its top), and at 16384 B it lies at 70 to 75 KiB,
    /// past the 64 the cases reached. The cases run 8 KiB past each edge,
    /// from 3 to 24 KiB above that sum (and from 4 to 64 KiB with nothing
    /// simulated, the whole stack's end); where the window was is said on
    /// every run (LAZYWINDOW).
    #[test]
    fn test_a_lazy_touch_at_the_reserves_end_is_a_loud_overflow() {
        let context = crate::windows_mm::exception_context_bytes();
        for extra in XSAVE_EXTRAS {
            // The window lies 11 to 16 KiB above the guarantee, the context
            // and the simulated area together (above: the floor's two
            // pages, the dispatcher's frames past the context, the
            // handler's own to and through its commit); the cases run
            // 8 KiB past each of its edges.
            let simulated = extra.parse::<usize>().unwrap();
            let guarantee = (context + simulated + crate::windows_mm::DISPATCH_OVERHEAD + crate::windows_mm::HANDLER_STACK_BUDGET)
                .next_multiple_of(4096);
            let sum = (guarantee + context + simulated) >> 10;
            let (lowest, highest) = if simulated == 0 { (4, (sum + 24).max(64)) } else { (sum + 3, sum + 24) };
            std::eprintln!("LAZYEND {extra} B simulated: the guarantee {guarantee} B, the cases {lowest} to {highest} KiB left");
            let mut in_the_handler = [false; 2];
            // Per kind: the lowest and highest case met in the commit, and
            // the lowest served.
            let mut met = [(usize::MAX, 0usize); 2];
            let mut served_from = [usize::MAX; 2];
            for (k, kind) in ["rust", "createthread"].into_iter().enumerate() {
                for left in (lowest..=highest).rev() {
                    let left_kib = std::format!("{left}");
                    let child = std::format!("lazy_at_the_reserves_end_{kind}_child");
                    let env = [("WICK_TEST_LEFT_KIB", left_kib.as_str()), ("WICK_TEST_XSAVE_EXTRA", extra)];
                    let (code, text, _) = run_child_watched(&child, &env, false);
                    std::eprintln!("LAZYEND {kind} at {left} KiB left, XSAVE area {extra} B larger: {code:?}; {}", text.trim().replace('\n', " | "));
                    let served = code == Some(0) && text.contains("LAZYEND the read gave 0");
                    let loud = code == Some(0xC000_00FD_u32.cast_signed())
                        && text.contains("has overflowed its stack")
                        && text.contains("wick: a thread's stack overflowed at its reserve's end");
                    assert!(served || loud, "{kind} at {left} KiB left, {extra} B: neither served nor an overflow said as one ({code:?}): {text}");
                    if loud {
                        let room = stack_room_problems(&text, extra);
                        assert!(room.is_empty(), "{kind} at {left} KiB left, {extra} B: {room:#?}\n{text}");
                    }
                    let in_it = loud && text.contains("raised in the lazy handler's commit");
                    in_the_handler[k] |= in_it;
                    if in_it {
                        met[k] = (met[k].0.min(left), met[k].1.max(left));
                    }
                    if served {
                        served_from[k] = served_from[k].min(left);
                    }
                }
            }
            // On every run, past the test's capture (one `WriteFile` to
            // standard error): where the window was, against the sum.
            for (k, kind) in ["rust", "createthread"].into_iter().enumerate() {
                crate::windows_mm::say_at_the_limit(format_args!(
                    "LAZYWINDOW {kind}, {extra} B simulated, the guarantee {guarantee} B, the context {context} B: the commit met \
                     the reserve's end at {} KiB left, served from {} KiB; the sum {sum} KiB, the cases {lowest} to {highest}",
                    if met[k].1 == 0 { "no case".into() } else { std::format!("{} to {}", met[k].0, met[k].1) },
                    if served_from[k] == usize::MAX { "none".into() } else { std::format!("{}", served_from[k]) },
                ));
            }
            assert!(
                in_the_handler.iter().all(|&b| b),
                "{extra} B: no case met the reserve's end in the lazy handler's commit (rust, createthread): {in_the_handler:?}"
            );
        }
    }

    /// Recurses until `left` bytes are left above `reserve`, then reads the
    /// lazy page at `mem`, saying so before and after, without allocating.
    #[inline(never)]
    fn down_to_then_read(left: usize, reserve: usize, mem: u64) -> u8 {
        let pad = core::hint::black_box([0u8; 256]);
        let here = core::ptr::addr_of!(pad) as usize;
        let v = if here - reserve > left {
            down_to_then_read(left, reserve, mem)
        } else {
            crate::windows_mm::say_at_the_limit(format_args!("LAZYEND reading at {} B above the reserve's end", here - reserve));
            // SAFETY: a lazy page of ours, never touched.
            let v = unsafe { core::ptr::read_volatile(mem as *const u8) };
            crate::windows_mm::say_at_the_limit(format_args!("LAZYEND the read gave {v}"));
            v
        };
        v.wrapping_add(core::hint::black_box(&pad)[0])
    }

    fn lazy_at_the_reserves_end(kind: Kind) {
        let left = std::env::var("WICK_TEST_LEFT_KIB").unwrap().parse::<usize>().unwrap() << 10;
        // SAFETY: a new anonymous mapping, committed at first touch (lazy).
        let mem = unsafe {
            crate::mmap(ptr::null_mut(), 1 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        let (done, came_back) = std::sync::mpsc::channel::<u8>();
        on_a_thread_of(
            kind,
            std::boxed::Box::new(move || {
                let (_, _, reserve, _) = stack_of_this_thread();
                let _ = done.send(down_to_then_read(left, reserve, mem));
            }),
        );
        let v = came_back.recv_timeout(std::time::Duration::from_secs(60)).expect("the thread neither came back nor ended the process");
        assert_eq!(v, 0);
    }

    #[test]
    #[ignore = "run by test_a_lazy_touch_at_the_reserves_end_is_a_loud_overflow"]
    fn lazy_at_the_reserves_end_rust_child() {
        lazy_at_the_reserves_end(Kind::Rust);
    }

    #[test]
    #[ignore = "run by test_a_lazy_touch_at_the_reserves_end_is_a_loud_overflow"]
    fn lazy_at_the_reserves_end_createthread_child() {
        lazy_at_the_reserves_end(Kind::CreateThread);
    }

    /// An unhandled exception the stack filter does not take goes to the
    /// filter it replaced: one set before the lazy-memory handler came is
    /// called for an exception no handler takes, and ends the process its
    /// own way (exit 7, its line).
    #[test]
    fn test_the_filter_the_stack_filter_replaced_is_called() {
        let (code, text) = run_child("filter_replaced_child", None);
        assert!(text.contains("the earlier filter: exception 0xe0001234"), "{text}");
        assert_eq!(code, Some(7), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_filter_the_stack_filter_replaced_is_called"]
    fn filter_replaced_child() {
        use windows_sys::Win32::System::Diagnostics::Debug::{EXCEPTION_POINTERS, RaiseException, SetUnhandledExceptionFilter};
        unsafe extern "system" fn earlier(info: *const EXCEPTION_POINTERS) -> i32 {
            // SAFETY: the system's exception pointers.
            let code = unsafe { (*(*info).ExceptionRecord).ExceptionCode };
            crate::windows_mm::say_at_the_limit(format_args!("the earlier filter: exception {:#x}", code.cast_unsigned()));
            // SAFETY: ends this process.
            unsafe { windows_sys::Win32::System::Threading::TerminateProcess(windows_sys::Win32::System::Threading::GetCurrentProcess(), 7) };
            0
        }
        // SAFETY: the filter stays for the process.
        unsafe { SetUnhandledExceptionFilter(Some(earlier)) };
        lazy_memory_is_mapped();
        // SAFETY: an exception no handler takes.
        unsafe { RaiseException(0xE000_1234, 0, 0, ptr::null()) };
        std::println!("the exception was taken");
    }

    /// The pages of the first 8 chunks: the discarded ones missing, the
    /// others still 0x5a.
    fn the_live_pages_read_back(mem: u64) {
        for p in (0..8 * CHUNK).step_by(PAGE as usize) {
            if (p / PAGE).is_multiple_of(2) {
                assert!(is_missing(mem + p), "{p:#x} is not missing");
            } else {
                // SAFETY: a filled page.
                assert_eq!(unsafe { *((mem + p + 9) as *const u8) }, 0x5a, "{p:#x}");
            }
        }
    }

    /// What a guest that gives back scattered pages (a balloon's 4 KiB
    /// pages, no chunk whole) gets back, and when, in a child under a job
    /// limit: the discard of every other page of a chunk gives none of the
    /// process's private commit back (the dead pages keep their section
    /// commit and its charge: the job and the jailer's count read that much
    /// more than Linux's memory.current, which uncharged them at the
    /// discard); with no room left in the job ([`no_room_left`]) each dead
    /// page is filled again, as its commit and charge are still there,
    /// with no reclaim asked and no chunk moved (`reclaim_counts`). The
    /// commit goes back to the job only when the chunk moves
    /// (`test_a_chunk_with_one_dead_page_at_the_limit`) or is discarded
    /// whole (`test_a_wholly_discarded_chunk_gives_its_section_commit_back`).
    /// SCATTERED line.
    #[test]
    fn test_a_scattered_discard_keeps_its_charge_and_its_refill_takes_none() {
        let (code, text) = run_child("scattered_discard_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert!(text.contains("SCATTERED "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_scattered_discard_keeps_its_charge_and_its_refill_takes_none in a job of its own"]
    fn scattered_discard_child() {
        let (ctx, user, mem, _) = fill_to_the_limit();
        let before = private_commit();
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        let after = private_commit();
        let dead = CHUNK / (2 * PAGE);
        let mut held = no_room_left();
        let counts = reclaim_counts();
        let mut made = 0;
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            if fill_a_page(ctx, mem + p) == "made" {
                made += 1;
            }
        }
        let filled = reclaim_counts();
        give_back_every_page(&mut held);
        std::println!(
            "SCATTERED the discard of {dead} pages gave back {} KiB of the process's private commit (Linux: {} KiB); with no \
             room left, {made} of {dead} dead pages filled again, {} reclaims asked, {} chunks moved",
            (before as i64 - after as i64) / 1024,
            dead * PAGE / 1024,
            filled.asks - counts.asks,
            filled.moves - counts.moves
        );
        // Within 64 KiB: the heap's own blocks for the lines may move it.
        assert!(before.abs_diff(after) < 64 << 10, "the discard moved the private commit by {} KiB", (before as i64 - after as i64) / 1024);
        assert_eq!((made, filled.asks - counts.asks, filled.moves - counts.moves), (dead, 0, 0));
        for p in (0..CHUNK).step_by(PAGE as usize) {
            // SAFETY: a filled page.
            assert_eq!(unsafe { *((mem + p + 9) as *const u8) }, 0x5a, "{p:#x}");
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A fill refused at the job's limit while partly discarded chunks hold
    /// dead pages (their section commit and charge, as (A) keeps them)
    /// reclaims them first and succeeds, as Linux's memory cgroup reclaims
    /// before it refuses a charge (v6.1 mm/memcontrol.c `try_charge_memcg`:
    /// `try_to_free_mem_cgroup_pages` before `mem_cgroup_oom`; there the
    /// discarded pages were freed at the discard already). The live pages
    /// read back, the discarded ones are missing, and a fill past what the
    /// dead pages gave back is still refused (`ENOMEM` in these tests,
    /// [`REFUSED_FILL_IS_ENOMEM`]; the product ends the VMM there). Before,
    /// the fill was refused
    /// with 8 MiB of dead pages charged. With no room left in the job
    /// ([`no_room_left`]): in CI run 43640510155 no move was made there, its
    /// map refused (`test_the_room_a_move_needs_on_record`).
    #[test]
    fn test_a_fill_at_the_limit_reclaims_partly_discarded_chunks() {
        let (code, text) = run_child("reclaim_fill_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        assert!(text.contains("filled 4096 KiB more"), "the fill was not reclaimed for: {text}");
        assert!(text.contains("refused with ENOMEM after"), "the limit did not hold past the dead pages: {text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_at_the_limit_reclaims_partly_discarded_chunks in a job of its own"]
    fn reclaim_fill_child() {
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let page = std::vec![0x5au8; PAGE as usize];
        let held = no_room_left();
        let fill_pages = |from: u64, most: u64| -> (u64, Option<c_int>) {
            let mut n = 0;
            while n < most {
                // SAFETY: `page` holds a page.
                match unsafe { copy(ctx, page.as_ptr(), mem + from + n, PAGE, false) } {
                    Ok(k) => n += k,
                    Err((e, _)) => return (n, Some(e)),
                }
            }
            (n, None)
        };
        let (more, _) = fill_pages(done, 4 << 20);
        std::println!("filled {} KiB more", more >> 10);
        assert_eq!(more, 4 << 20, "a fill at the limit was refused with 8 MiB of dead pages charged");
        the_live_pages_read_back(mem);
        // Past what the dead pages gave back (8 MiB less the 4 just
        // filled, and a little of the job's room left before them).
        let (rest, refused) = fill_pages(done + more, 16 << 20);
        std::println!("refused with {} after {} KiB more", if refused == Some(crate::ENOMEM) { "ENOMEM" } else { "no error" }, rest >> 10);
        assert_eq!(refused, Some(crate::ENOMEM));
        assert!(rest < (4 << 20) + (2 << 20), "{} KiB filled past the dead pages", rest >> 10);
        drop(held);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let _ = ctx;
    }

    /// A first touch of lazy memory refused at the job's limit reclaims the
    /// dead pages of partly discarded chunks first, and the access goes on,
    /// where it ended the process with 137 before: Linux reclaims before
    /// its out-of-memory kill (as above). With no room left in the job
    /// ([`no_room_left`]).
    #[test]
    fn test_a_lazy_touch_at_the_limit_reclaims_before_it_ends_the_vmm() {
        let (code, text) = run_child("reclaim_touch_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        assert!(text.contains("touched 4096 KiB"), "the touch was not reclaimed for (status {code:?}): {text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_lazy_touch_at_the_limit_reclaims_before_it_ends_the_vmm in a job of its own"]
    fn reclaim_touch_child() {
        let (_ctx, user, mem, _) = fill_to_the_limit_and_discard_in_part();
        // SAFETY: a new anonymous mapping, committed at first touch.
        let lazy = unsafe {
            crate::mmap(
                ptr::null_mut(),
                16 << 20,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, crate::MAP_FAILED);
        let held = no_room_left();
        for p in (0..4usize << 20).step_by(PAGE as usize) {
            // SAFETY: our mapping; the first touch commits the page.
            unsafe { core::ptr::write_volatile((lazy as *mut u8).add(p), 1) };
        }
        std::println!("touched 4096 KiB");
        drop(held);
        the_live_pages_read_back(mem);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// LIMITREC: one line of a reclaim test's steps, without allocating (it
    /// is said at the limit): the step, the private commit and the reclaim's
    /// counts so far.
    fn limit_step(step: &str) {
        let c = reclaim_counts();
        crate::windows_mm::say_at_the_limit(format_args!(
            "LIMITREC {step}: private commit {} KiB; reclaims asked {}, candidates {}, moves made {}, not made {}",
            private_commit() / 1024,
            c.asks,
            c.candidates,
            c.moves,
            c.refused
        ));
    }

    /// MOVEREC: the last move's steps (`windows_mm::MOVEREC`) in one line,
    /// private commit in KiB, said without allocating after `what`.
    fn moverec_line(what: &str, fill: &str) {
        let m: [usize; 12] = core::array::from_fn(|i| crate::windows_mm::MOVEREC[i].load(Ordering::SeqCst));
        let tmp = m[2];
        crate::windows_mm::say_at_the_limit(format_args!(
            "MOVEREC {what} {fill}: the move ended at step {} (1 map refused, 2 commit, 3 close, 4 alias unmap, 5 made); private commit KiB: \
             start {}, before its first map {}, temporary view mapped {}, live pages committed {}, copied {}, views swapped {}, \
             temporary view unmapped {}; the temporary view at {tmp:#x}, {} KiB into its 2 MiB, spanning {} 2 MiB regions, {} pages \
             committed in the region below its start outside it, {} in the one above its end",
            m[9],
            m[0] / 1024,
            m[1] / 1024,
            m[3] / 1024,
            m[5] / 1024,
            m[6] / 1024,
            m[7] / 1024,
            m[8] / 1024,
            (tmp % (2 << 20)) / 1024,
            m[11],
            m[4],
            m[10]
        ));
    }

    /// One page filled at `at`: "made", "ENOMEM" or "another errno".
    fn fill_a_page(ctx: usize, at: u64) -> &'static str {
        let page = [0x5au8; PAGE as usize];
        // SAFETY: `page` holds a page.
        match unsafe { copy(ctx, page.as_ptr(), at, PAGE, false) } {
            Ok(_) => "made",
            Err((e, _)) if e == crate::ENOMEM => "ENOMEM",
            Err(_) => "another errno",
        }
    }

    /// A chunk's commit and charge, for [`move_not_made_child`]: its pages
    /// committed and its charge's.
    fn chunk_state(chunk: u64) -> (u64, u64) {
        (committed(chunk, CHUNK), crate::windows_mm::charged(chunk as usize).unwrap_or(0) as u64)
    }

    /// A move not made leaves its chunk exactly as it was, its charge whole
    /// (`windows_mm::uffd_move_chunk`): with no room left in the job
    /// ([`no_room_left`]), each step a move can be refused at
    /// (`windows_mm::REFUSE_MOVE_STEP`: its new section not made, its view's
    /// map into the move slot, its alias's first view's unmap) is refused
    /// once at a fill's reclaim. With the one chunk holding dead pages the
    /// fill is refused (`ENOMEM`), the chunk's commit and charge as before,
    /// one move not made, none made, a line on standard error for each; the
    /// next fill, nothing refused, moves it and is made, its dead pages'
    /// commit and charge given back. With two such chunks and the map
    /// refused, the next candidate's move is made and the fill with it: one
    /// chunk as it was, the other moved. Nothing is ever owed: a move takes
    /// nothing before its first map (review B3; before, it gave back 12 KiB
    /// of its dead pages' charge for its maps and owed it if another commit
    /// took that room and the move was not made). The pages read back.
    #[test]
    fn test_a_move_not_made_leaves_its_chunk_as_it_was() {
        let (code, text) = run_child("move_not_made_child", Some(96 << 20));
        for l in text.lines().filter(|l| l.starts_with("NOTMADE") || l.starts_with("wick: reclaim") || l.starts_with("filled")) {
            std::eprintln!("{l}");
        }
        for what in ["make its new section", "map its new section", "unmap its alias"] {
            let said = std::format!("could not {what} (error ");
            assert!(
                text.lines().any(|l| l.contains(&said) && l.contains("): the chunk is left as it was, its charge whole")),
                "no line for {what}: {text}"
            );
        }
        for step in 1..=3 {
            assert!(
                text.contains(&std::format!("NOTMADE one candidate, step {step} refused: the fill ENOMEM, 0 moves made, 1 not made, the chunk as it was")),
                "step {step}: {text}"
            );
        }
        assert!(text.contains("NOTMADE one candidate, nothing refused: the fill made, 1 moves made, 0 not made, the chunk moved"), "{text}");
        assert!(text.contains("NOTMADE two candidates, the map refused: the fill made, 1 moves made, 1 not made, 1 as it was, 1 moved"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_move_not_made_leaves_its_chunk_as_it_was in a job of its own"]
    fn move_not_made_child() {
        let (ctx, user, mem, done) = fill_to_the_limit();
        let moves = || moves_on_record().0.len();
        let dead = |chunk: u64| {
            for p in (PAGE..CHUNK).step_by(2 * PAGE as usize) {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((chunk + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
        };
        let read_back = |chunk: u64| {
            for p in (0..CHUNK).step_by(PAGE as usize) {
                if (p / PAGE) % 2 == 1 {
                    assert!(is_missing(chunk + p), "{chunk:#x}: {p:#x} is not missing");
                } else {
                    // SAFETY: a filled page.
                    assert_eq!(unsafe { *((chunk + p + 9) as *const u8) }, 0x5a, "{chunk:#x}: {p:#x}");
                }
            }
        };
        let mut next = mem + done;
        // One candidate: the first chunk, every other page dead.
        dead(mem);
        let before = chunk_state(mem);
        assert_eq!(before.0, CHUNK, "the chunk's dead pages keep their commit");
        for step in 1..=3usize {
            let mut held = no_room_left();
            let (m1, r1) = (moves(), crate::windows_mm::moves_refused());
            crate::windows_mm::REFUSE_MOVE_STEP.store(step, Ordering::SeqCst);
            let fill = fill_a_page(ctx, next);
            let reached = crate::windows_mm::REFUSE_MOVE_STEP.swap(0, Ordering::SeqCst) == 0;
            let (m2, r2) = (moves(), crate::windows_mm::moves_refused());
            give_back_every_page(&mut held);
            let after = chunk_state(mem);
            assert!(reached, "step {step}: the refusal was not reached");
            crate::windows_mm::say_at_the_limit(format_args!(
                "NOTMADE one candidate, step {step} refused: the fill {fill}, {} moves made, {} not made, the chunk {}; its commit \
                 and charge {:#x} {:#x} -> {:#x} {:#x}",
                m2 - m1,
                r2 - r1,
                if after == before { "as it was" } else { "changed" },
                before.0,
                before.1,
                after.0,
                after.1
            ));
            read_back(mem);
        }
        let mut held = no_room_left();
        let (m1, r1) = (moves(), crate::windows_mm::moves_refused());
        let fill = fill_a_page(ctx, next);
        let (m2, r2) = (moves(), crate::windows_mm::moves_refused());
        give_back_every_page(&mut held);
        let after = chunk_state(mem);
        crate::windows_mm::say_at_the_limit(format_args!(
            "NOTMADE one candidate, nothing refused: the fill {fill}, {} moves made, {} not made, the chunk {}; its commit and \
             charge {:#x} {:#x} -> {:#x} {:#x}",
            m2 - m1,
            r2 - r1,
            if after == (CHUNK / 2, before.1 - CHUNK / 2) { "moved" } else { "not moved as expected" },
            before.0,
            before.1,
            after.0,
            after.1
        ));
        read_back(mem);
        next += PAGE;
        // Two candidates, the next two chunks; the first move's map refused.
        let (a, b) = (mem + CHUNK, mem + 2 * CHUNK);
        dead(a);
        dead(b);
        let before = [chunk_state(a), chunk_state(b)];
        let mut held = no_room_left();
        let (m1, r1) = (moves(), crate::windows_mm::moves_refused());
        crate::windows_mm::REFUSE_MOVE_STEP.store(2, Ordering::SeqCst);
        let fill = fill_a_page(ctx, next);
        let reached = crate::windows_mm::REFUSE_MOVE_STEP.swap(0, Ordering::SeqCst) == 0;
        let (m2, r2) = (moves(), crate::windows_mm::moves_refused());
        give_back_every_page(&mut held);
        let after = [chunk_state(a), chunk_state(b)];
        assert!(reached, "two candidates: the refusal was not reached");
        let same = (0..2).filter(|&i| after[i] == before[i]).count();
        let moved = (0..2).filter(|&i| after[i] == (CHUNK / 2, before[i].1 - CHUNK / 2)).count();
        crate::windows_mm::say_at_the_limit(format_args!(
            "NOTMADE two candidates, the map refused: the fill {fill}, {} moves made, {} not made, {same} as it was, {moved} moved",
            m2 - m1,
            r2 - r1
        ));
        read_back(a);
        read_back(b);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A free 1 GiB-aligned stretch of `gib` GiB of address space: reserved
    /// to find it, then freed.
    fn fresh_gib(gib: usize) -> usize {
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, VirtualAlloc, VirtualFree};
        // SAFETY: reserves and frees address space of our own.
        unsafe {
            let r = VirtualAlloc(ptr::null(), (gib + 1) << 30, MEM_RESERVE, PAGE_NOACCESS) as usize;
            assert_ne!(r, 0);
            VirtualFree(r as *mut c_void, 0, MEM_RELEASE);
            r.next_multiple_of(1 << 30)
        }
    }

    /// VIEWCOST: the last view swap's steps (`windows_mm::VIEWREC`) in KiB
    /// of private commit, each `None` if not reached, in the order they are
    /// made: the alias's first view's unmap, its map, the second view's
    /// unmap, its map, then the same for the guest's view.
    fn viewcost_steps() -> [Option<i64>; 8] {
        let v: [usize; 10] = core::array::from_fn(|i| crate::windows_mm::VIEWREC[i].load(Ordering::SeqCst));
        let d = |a: usize, b: usize| (a != 0 && b != 0).then(|| (b as i64 - a as i64) / 1024);
        [d(v[0], v[1]), d(v[1], v[2]), d(v[2], v[3]), d(v[3], v[4]), d(v[4], v[5]), d(v[5], v[6]), d(v[6], v[7]), d(v[7], v[8])]
    }

    /// VIEWCOST: the last view swap's steps ([`viewcost_steps`]), said
    /// without allocating.
    fn viewcost_line(case: &str, view: usize, alias: usize, extra: core::fmt::Arguments<'_>) {
        let k = |x: Option<i64>| x.unwrap_or(i64::MIN);
        let v = viewcost_steps();
        crate::windows_mm::say_at_the_limit(format_args!(
            "VIEWCOST {case}, {}: the guest view at {view:#x}, {} KiB into its 2 MiB, {} MiB into its 1 GiB; its alias at {alias:#x}, \
             {} KiB into its 2 MiB, {} MiB into its 1 GiB; KiB, a view at a time: the alias's first view unmap {:+}, map {:+}, \
             its second unmap {:+}, map {:+}; the guest view's first unmap {:+}, map {:+}, its second unmap {:+}, map {:+}{extra}",
            if crate::windows_mm::VIEWREC[9].load(Ordering::SeqCst) == 1 { "move" } else { "swap" },
            (view % CHUNK as usize) >> 10,
            (view % (1 << 30)) >> 20,
            (alias % CHUNK as usize) >> 10,
            (alias % (1 << 30)) >> 20,
            k(v[0]),
            k(v[1]),
            k(v[2]),
            k(v[3]),
            k(v[4]),
            k(v[5]),
            k(v[6]),
            k(v[7]),
        ));
    }

    /// VIEWCOST's assertion for a chunk swapped: each view's unmap and map,
    /// made while the chunk's other view (old or new) maps its 2 MiB region,
    /// take and give no page table, in the alias and the guest's view (a
    /// chunk with a view alone in a 2 MiB region of its range is not
    /// swapped: `windows_mm::at_a_ranges_edge`).
    fn assert_halves_cost_nothing(what: &str) {
        let v = viewcost_steps();
        for (k, side) in ["the alias's", "the guest view's"].into_iter().enumerate() {
            for i in 0..2 {
                assert_eq!(v[4 * k + 2 * i], Some(0), "{what}: {side} view {i}'s unmap: {v:?}");
                assert_eq!(v[4 * k + 2 * i + 1], Some(0), "{what}: {side} view {i}'s map: {v:?}");
            }
        }
    }

    /// VIEWCOST, a record: what each step of a chunk's view swap
    /// (`windows_mm::unmap_alias` and `swap_views`: each of the alias's two
    /// views unmapped keeping its placeholder and the new section's mapped
    /// there, one at a time, then the same for the guest's view) adds to the process's
    /// private commit, for a move (one dead page, `reclaim_at_touch`) and
    /// then a swap (the chunk discarded whole), of the first, middle and last
    /// chunk of a 3-chunk range and of a 1-chunk range, the range and its
    /// alias each on a 2 MiB boundary in a fresh 1 GiB, 64 KiB past one, and
    /// where the product puts them (anywhere: the alias on a 2 MiB
    /// boundary). A view's page tables are charged at its map and given back
    /// at its unmap (MAPCOST); between the guest view's unmap and its map,
    /// what the unmap gave is room another commit can take
    /// (`test_a_move_whose_guest_view_room_is_taken_is_made`). Asserted: the
    /// moves and swaps are made, each view's unmap and map takes no page
    /// table ([`assert_halves_cost_nothing`]), and the move's view of its
    /// new section, in the move slot, takes none at its map and gives none
    /// back at its unmap; but a chunk with a view alone in a 2 MiB region of
    /// its range (`windows_mm::at_a_ranges_edge`: the last chunk's second
    /// view of a range 64 KiB past a boundary, whose unmap gave back the
    /// region's table, -4 KiB, and whose map took it, +4, before review B3)
    /// is neither moved nor swapped, each refusal counted and said, the
    /// chunk's pages as they were and then missing.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture (CI's WHP step)"]
    fn test_what_a_chunks_view_swap_costs_on_record() {
        let page = [0x5au8; PAGE as usize];
        for (case, off) in [("on a 2 MiB boundary", Some(0usize)), ("64 KiB past a 2 MiB boundary", Some(64 << 10)), ("anywhere", None)] {
            for n in [3u64, 1] {
                let (at, alias_at) = match off {
                    Some(o) => {
                        let g = fresh_gib(4);
                        (g + (64 << 20) + o, g + (2 << 30) + (64 << 20) + o)
                    }
                    None => (0, 0),
                };
                crate::windows_mm::ALIAS_AT.store(alias_at, Ordering::SeqCst);
                let (ctx, user) = create(0, false, true).unwrap();
                let len = n * CHUNK;
                // SAFETY: a new anonymous mapping, committed at first touch.
                let mem = unsafe {
                    crate::mmap(
                        at as *mut c_void,
                        len as usize,
                        crate::PROT_READ | crate::PROT_WRITE,
                        crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                        -1,
                        0,
                    )
                };
                assert_ne!(mem, crate::MAP_FAILED);
                assert!(at == 0 || mem as usize == at, "{case}: the range at {mem:p}, asked at {at:#x}");
                let mem = mem as u64;
                register(ctx, mem, len).unwrap();
                let alias = range_of_view(mem as usize).unwrap().0.alias.load(Ordering::Acquire) as usize;
                assert!(alias_at == 0 || alias == alias_at, "{case}: the alias at {alias:#x}, asked at {alias_at:#x}");
                assert!(alias_at != 0 || alias.is_multiple_of(CHUNK as usize), "{case}: the alias at {alias:#x}, not on a 2 MiB boundary");
                // The first and last 16 pages of each chunk filled.
                for c in 0..n {
                    for p in (0..16).chain(CHUNK / PAGE - 16..CHUNK / PAGE) {
                        // SAFETY: `page` holds a page.
                        unsafe { copy(ctx, page.as_ptr(), mem + c * CHUNK + p * PAGE, PAGE, false) }.unwrap();
                    }
                }
                for c in 0..n {
                    let pos = match (c, n) {
                        (_, 1) => "the only",
                        (0, _) => "the first",
                        (c, n) if c + 1 == n => "the last",
                        _ => "a middle",
                    };
                    let chunk = mem + c * CHUNK;
                    let what = std::format!("{case}, a {n}-chunk range, {pos} chunk");
                    // SAFETY: registered memory of ours.
                    assert_eq!(unsafe { crate::madvise((chunk + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
                    let a = alias + (c * CHUNK) as usize;
                    if crate::windows_mm::at_a_ranges_edge(chunk as usize, CHUNK as usize, a, mem as usize, (mem + len) as usize) {
                        let e0 = crate::windows_mm::edge_refused_for_tests();
                        let r = reclaim_at_touch(PAGE as usize);
                        let e1 = crate::windows_mm::edge_refused_for_tests();
                        assert_eq!((r.chunks, e1 - e0), (0, 1), "{what}: the move at the range's edge");
                        for p in (0..16).chain(CHUNK / PAGE - 16..CHUNK / PAGE) {
                            if p == 1 {
                                assert!(is_missing(chunk + PAGE), "{what}: the dead page");
                            } else {
                                // SAFETY: a filled page.
                                assert_eq!(unsafe { *((chunk + p * PAGE) as *const u8) }, 0x5a, "{what}: page {p}");
                            }
                        }
                        // SAFETY: registered memory of ours, the chunk whole.
                        assert_eq!(unsafe { crate::madvise(chunk as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) }, 0);
                        let e2 = crate::windows_mm::edge_refused_for_tests();
                        assert_eq!(crate::windows_mm::VIEWREC[9].load(Ordering::SeqCst), 0, "{what}: the swap at the range's edge");
                        assert_eq!(e2 - e1, 1, "{what}: the swap at the range's edge");
                        assert!((0..CHUNK).step_by(PAGE as usize).all(|p| is_missing(chunk + p)), "{what}: the discarded chunk's pages");
                        crate::windows_mm::say_at_the_limit(format_args!(
                            "VIEWCOST {what}: at the range's edge, neither moved nor swapped; its commit {:#x} kept",
                            committed(chunk, CHUNK)
                        ));
                        continue;
                    }
                    let r = reclaim_at_touch(PAGE as usize);
                    assert_eq!(r.chunks, 1, "{what}: the move");
                    let m: [usize; 12] = core::array::from_fn(|i| crate::windows_mm::MOVEREC[i].load(Ordering::SeqCst));
                    viewcost_line(
                        &what,
                        chunk as usize,
                        alias + (c * CHUNK) as usize,
                        format_args!(
                            "; its temporary view {} KiB into its 2 MiB: map {:+}, unmap {:+}",
                            (m[2] % CHUNK as usize) >> 10,
                            (m[3] as i64 - m[1] as i64) / 1024,
                            (m[8] as i64 - m[7] as i64) / 1024
                        ),
                    );
                    assert_halves_cost_nothing(&std::format!("{what}, the move"));
                    assert_eq!((m[3] as i64 - m[1] as i64, m[8] as i64 - m[7] as i64), (0, 0), "{what}: the move's view in the slot, its map and unmap");
                    // SAFETY: registered memory of ours, the chunk whole.
                    assert_eq!(unsafe { crate::madvise(chunk as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) }, 0);
                    assert_eq!(crate::windows_mm::VIEWREC[9].load(Ordering::SeqCst), 2, "{what}: the swap");
                    assert_ne!(crate::windows_mm::VIEWREC[8].load(Ordering::SeqCst), 0, "{what}: the swap");
                    viewcost_line(&what, chunk as usize, alias + (c * CHUNK) as usize, format_args!(""));
                    assert_halves_cost_nothing(&std::format!("{what}, the swap"));
                    crate::windows_mm::VIEWREC[9].store(0, Ordering::SeqCst);
                }
                // SAFETY: closes the user end, then unmaps our mapping.
                unsafe {
                    ws::closesocket(sock(user));
                    assert_eq!(crate::munmap(mem as *mut c_void, len as usize), 0);
                }
            }
        }
    }

    /// A chunk with a view alone in a 2 MiB region of its range
    /// (`windows_mm::at_a_ranges_edge`), whose swap would give back that
    /// region's page table at the view's unmap and need it again at its map,
    /// is neither moved nor swapped until review B4: refused before any
    /// step, counted, and said on standard error. A 2-chunk range 64 KiB
    /// past a 2 MiB boundary (its last chunk's second view alone in the
    /// region past it), the first and last 16 pages of each chunk filled:
    /// a dead page in the last chunk, the reclaim moves nothing, its pages as
    /// they were and its commit and charge kept; a dead page in the first
    /// chunk too, the reclaim moves that one only; the last chunk discarded
    /// whole is not swapped, its pages missing and their commit and charge
    /// kept (a partial discard's, until the chunk is unmapped), the first
    /// discarded whole is, its commit gone; the last chunk filled again and
    /// the range unregistered, its released chunk discarded whole is not
    /// swapped either (`windows_mm::released_swap`) and reads zeros. The
    /// edge's arithmetic beside it: a range on a 2 MiB boundary of whole
    /// chunks has no such chunk, a short last chunk of one view (64 KiB)
    /// does, and a range starting 1 MiB or more past a boundary its first.
    #[test]
    fn test_a_chunk_at_a_ranges_edge_is_neither_moved_nor_swapped() {
        let (code, text) = run_child("edge_child", None);
        for l in text.lines().filter(|l| l.starts_with("EDGE") || l.starts_with("wick: reclaim")) {
            std::eprintln!("{l}");
        }
        assert!(text.contains("has a view alone in a 2 MiB region at its range's edge, whose swap would need a page table between its unmap and its map: not moved"), "{text}");
        assert!(text.contains("at its range's edge, whose swap would need a page table between its unmap and its map: not swapped for a new section at its discard; its pages are discarded in place"), "{text}");
        assert!(text.contains("not swapped for a new section at its discard; its pages are closed and discarded in place"), "{text}");
        assert!(text.contains("EDGE done"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_chunk_at_a_ranges_edge_is_neither_moved_nor_swapped in a process of its own"]
    fn edge_child() {
        use crate::windows_mm::{at_a_ranges_edge, charged, edge_refused_for_tests};
        let c = CHUNK as usize;
        let m = 1 << 30;
        // The arithmetic: (view, len, alias, start, end).
        assert!(!at_a_ranges_edge(m, c, 3 * m, m, m + 2 * c), "whole chunks on a boundary, the first");
        assert!(!at_a_ranges_edge(m + c, c, 3 * m + c, m, m + 2 * c), "whole chunks on a boundary, the last");
        assert!(at_a_ranges_edge(m + c, 64 << 10, 3 * m + c, m, m + c + (64 << 10)), "a short last chunk of one view");
        assert!(!at_a_ranges_edge(m + c, c / 2, 3 * m + c, m, m + c + c / 2), "a short last chunk of two views in its region");
        assert!(at_a_ranges_edge(m + (1 << 20), c, 3 * m, m + (1 << 20), m + (1 << 20) + 2 * c), "a range 1 MiB past a boundary, its first");
        assert!(at_a_ranges_edge(m + (64 << 10), c, 3 * m, m + (64 << 10), m + (64 << 10) + c), "a range 64 KiB past, its only chunk");
        assert!(at_a_ranges_edge(m, c, 3 * m + (64 << 10), m, m + c), "an alias 64 KiB past");
        let page = [0x5au8; PAGE as usize];
        let at = fresh_gib(1) + (64 << 20) + (64 << 10);
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        // SAFETY: a new anonymous mapping, committed at first touch.
        let mem = unsafe {
            crate::mmap(at as *mut c_void, len as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_eq!(mem as usize, at);
        let mem = mem as u64;
        register(ctx, mem, len).unwrap();
        let alias = range_of_view(mem as usize).unwrap().0.alias.load(Ordering::Acquire) as usize;
        let (first, last) = (mem, mem + CHUNK);
        assert!(!at_a_ranges_edge(first as usize, c, alias, mem as usize, (mem + len) as usize), "the first chunk");
        assert!(at_a_ranges_edge(last as usize, c, alias + c, mem as usize, (mem + len) as usize), "the last chunk");
        let pages = || (0..16).chain(CHUNK / PAGE - 16..CHUNK / PAGE);
        for chunk in [first, last] {
            for p in pages() {
                // SAFETY: `page` holds a page.
                unsafe { copy(ctx, page.as_ptr(), chunk + p * PAGE, PAGE, false) }.unwrap();
            }
        }
        let filled = |chunk: u64, dead: &[u64]| {
            for p in pages() {
                if dead.contains(&p) {
                    assert!(is_missing(chunk + p * PAGE), "{chunk:#x}: page {p} not missing");
                } else {
                    // SAFETY: a filled page.
                    assert_eq!(unsafe { *((chunk + p * PAGE) as *const u8) }, 0x5a, "{chunk:#x}: page {p}");
                }
            }
        };
        let state = |chunk: u64| (committed(chunk, CHUNK), charged(chunk as usize).unwrap_or(0));
        // A dead page in the last chunk.
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise((last + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        let before = state(last);
        let e0 = edge_refused_for_tests();
        let r = reclaim_at_touch(PAGE as usize);
        let e1 = edge_refused_for_tests();
        std::println!("EDGE the last chunk with a dead page: {} moved, {} refused at the edge, its commit and charge {before:x?} -> {:x?}", r.chunks, e1 - e0, state(last));
        assert_eq!((r.chunks, e1 - e0), (0, 1));
        assert_eq!(state(last), before, "the last chunk's commit and charge");
        filled(last, &[1]);
        // A dead page in the first chunk too: that one moves.
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise((first + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        let r = reclaim_at_touch(PAGE as usize);
        let e2 = edge_refused_for_tests();
        std::println!("EDGE then the first with one: {} moved, {} refused at the edge", r.chunks, e2 - e1);
        assert_eq!(r.chunks, 1, "the first chunk's move");
        assert_eq!(state(last), before, "the last chunk's commit and charge");
        filled(first, &[1]);
        filled(last, &[1]);
        // Each discarded whole.
        // SAFETY: registered memory of ours, the last chunk whole.
        assert_eq!(unsafe { crate::madvise(last as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) }, 0);
        let e3 = edge_refused_for_tests();
        let kept = state(last);
        std::println!("EDGE the last chunk discarded whole: {} refused at the edge, its commit and charge {kept:x?}", e3 - e2);
        assert_eq!(e3 - e2, 1);
        assert_eq!(kept, before, "the last chunk's commit and charge, discarded in place");
        assert!((0..CHUNK).step_by(PAGE as usize).all(|p| is_missing(last + p)), "the last chunk's pages");
        // SAFETY: registered memory of ours, the first chunk whole.
        assert_eq!(unsafe { crate::madvise(first as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(edge_refused_for_tests(), e3, "the first chunk's swap");
        assert_eq!(committed(first, CHUNK), 0, "the first chunk's commit after its swap");
        // The last chunk filled again, then released and discarded whole.
        for p in pages() {
            // SAFETY: `page` holds a page.
            unsafe { copy(ctx, page.as_ptr(), last + p * PAGE, PAGE, false) }.unwrap();
        }
        unregister(ctx, mem, len).unwrap();
        // SAFETY: our mapping, released, its last chunk whole.
        assert_eq!(unsafe { crate::madvise(last as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) }, 0);
        let e4 = edge_refused_for_tests();
        // SAFETY: our mapping, released.
        let (b0, b1) = unsafe { (ptr::read_volatile(last as *const u8), ptr::read_volatile((last + CHUNK - PAGE) as *const u8)) };
        std::println!("EDGE the released last chunk discarded whole: {} refused at the edge, its first and last page read {b0:#x} {b1:#x}", e4 - e3);
        assert_eq!((e4 - e3, b0, b1), (1, 0, 0));
        // SAFETY: closes the user end, then unmaps our mapping.
        unsafe {
            ws::closesocket(sock(user));
            assert_eq!(crate::munmap(mem as *mut c_void, len as usize), 0);
        }
        std::println!("EDGE done");
    }

    /// A chunk's two views (`windows_mm::chunk_views`, split at 1 MiB) are
    /// one mapping to every call across the split, each of which Windows
    /// refuses across two views ("All pages in the specified region must be
    /// within the same reserved region", Learn, VirtualProtect): a register
    /// with resident pages on both sides of it (its commits through the
    /// alias); a fill of two pages across it (`uffd_commit`); a
    /// `MADV_DONTNEED` of two pages across it while registered (missing
    /// again), a `UFFDIO_ZEROPAGE` across it, and a refill; once
    /// unregistered, an mprotect read-only and back and a partial munmap
    /// across it (`mprotect_rest`, `munmap`); a `MAP_FIXED` mapping over
    /// the second chunk (its views unmapped and their placeholders made one
    /// region again); and the munmap of the rest. Each call succeeds and
    /// the pages read back.
    #[test]
    fn test_a_chunks_two_views_are_one_mapping_to_every_call() {
        let half = crate::windows_mm::chunk_half(CHUNK as usize) as u64;
        assert_eq!(half, CHUNK / 2);
        let len = 2 * CHUNK;
        // SAFETY: a new anonymous mapping.
        let mem = unsafe {
            crate::mmap(ptr::null_mut(), len as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        let byte = |at: u64| {
            // SAFETY: mapped memory of ours.
            unsafe { ptr::read_volatile(at as *const u8) }
        };
        for p in [half - PAGE, half] {
            // SAFETY: mapped memory of ours.
            unsafe { ptr::write_volatile((mem + p) as *mut u8, 0x11) };
        }
        let (ctx, user) = create(0, false, true).unwrap();
        register(ctx, mem, len).unwrap();
        assert!(range_of_view(mem as usize).is_some_and(|(r, _)| r.reserved.load(Ordering::Acquire)), "not a chunked range");
        for p in [half - PAGE, half] {
            assert_eq!(byte(mem + p), 0x11, "resident page {p:#x} after the register");
        }
        let src = [0x22u8; 2 * PAGE as usize];
        let across = mem + CHUNK + half - PAGE;
        // SAFETY: `src` holds the two pages.
        assert_eq!(unsafe { copy(ctx, src.as_ptr(), across, 2 * PAGE, false) }, Ok(2 * PAGE), "the fill across the split");
        assert_eq!((byte(across), byte(across + PAGE)), (0x22, 0x22));
        // A discard of the two pages across the split while registered:
        // missing again, a zero page across it, discarded again, refilled.
        let two = (mem + half - PAGE) as *mut c_void;
        let discard = || {
            // SAFETY: two pages of ours across the split.
            assert_eq!(unsafe { crate::madvise(two, 2 * PAGE as usize, crate::MADV_DONTNEED) }, 0, "MADV_DONTNEED across the split");
            assert!(is_missing(mem + half - PAGE) && is_missing(mem + half), "the discarded pages are missing");
        };
        discard();
        assert_eq!(zeropage(ctx, mem + half - PAGE, 2 * PAGE, false), Ok(2 * PAGE), "the zero page across the split");
        assert_eq!((byte(mem + half - PAGE), byte(mem + half)), (0, 0));
        discard();
        let refill = [0x44u8; 2 * PAGE as usize];
        // SAFETY: `refill` holds the two pages.
        assert_eq!(unsafe { copy(ctx, refill.as_ptr(), mem + half - PAGE, 2 * PAGE, false) }, Ok(2 * PAGE), "the refill across the split");
        assert_eq!((byte(mem + half - PAGE), byte(mem + half)), (0x44, 0x44));
        unregister(ctx, mem, len).unwrap();
        let start = (mem + half - 2 * PAGE) as *mut c_void;
        // SAFETY: mapped memory of ours, four pages across the split.
        unsafe {
            assert_eq!(crate::mprotect(start, 4 * PAGE as usize, crate::PROT_READ), 0, "mprotect read-only across the split");
            assert_eq!(crate::mprotect(start, 4 * PAGE as usize, crate::PROT_READ | crate::PROT_WRITE), 0, "and back");
        }
        assert_eq!((byte(mem + half - PAGE), byte(mem + half)), (0x44, 0x44));
        // SAFETY: mapped memory of ours, written across the split.
        unsafe { ptr::write_volatile((mem + half) as *mut u8, 0x33) };
        // SAFETY: two pages of ours across the split.
        assert_eq!(unsafe { crate::munmap((mem + half - PAGE) as *mut c_void, 2 * PAGE as usize) }, 0, "munmap across the split");
        // SAFETY: a new anonymous mapping over the second chunk.
        let fixed = unsafe {
            crate::mmap(
                (mem + CHUNK) as *mut c_void,
                CHUNK as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(fixed as u64, mem + CHUNK, "MAP_FIXED over the second chunk");
        assert_eq!(byte(across), 0, "the new mapping's page");
        // SAFETY: our mappings, whole.
        unsafe {
            assert_eq!(crate::munmap(mem as *mut c_void, len as usize), 0);
            ws::closesocket(sock(user));
        }
    }

    /// The pages of `[at, at + len)` mincore gives as resident.
    fn resident(at: u64, len: u64) -> std::vec::Vec<u8> {
        let mut v = std::vec![0u8; (len / PAGE) as usize];
        // SAFETY: `v` has a byte a page.
        assert_eq!(unsafe { crate::mincore(at as *mut c_void, len as usize, v.as_mut_ptr()) }, 0);
        v
    }

    /// A new anonymous private mapping of `len` bytes, every page written
    /// with `fill`, registered with a new userfaultfd and unregistered from
    /// `[from, to)` (offsets): a released range there.
    #[track_caller]
    fn released_of(len: u64, fill: u8, from: u64, to: u64) -> (u64, c_int, usize) {
        // SAFETY: a new anonymous mapping, written whole.
        let mem = unsafe {
            let m = crate::mmap(ptr::null_mut(), len as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0);
            assert_ne!(m, crate::MAP_FAILED);
            ptr::write_bytes(m.cast::<u8>(), fill, len as usize);
            m as u64
        };
        if len.is_multiple_of(CHUNK) {
            on_a_boundary(mem);
        }
        let (ctx, user) = create(0, false, true).unwrap();
        register(ctx, mem, len).unwrap();
        assert!(range_of_view(mem as usize).is_some_and(|(r, _)| r.reserved.load(Ordering::Acquire)), "not a chunked range");
        if to > from {
            unregister(ctx, mem + from, to - from).unwrap();
        }
        (mem, user, ctx)
    }

    /// A `MADV_DONTNEED` or `MADV_FREE` of a released chunk's pages
    /// (registered, then unregistered) reads zeros after, as Linux's
    /// anonymous memory does once its userfaultfd is gone (mm/madvise.c
    /// zaps the pages; `MADV_FREE` may keep them until reclaim, and zeros
    /// are one of its outcomes). Before this, a defect from before a
    /// chunk's two views: the pages kept their data (PROBEDISCARD
    /// "reserved true madvise 0 byte after 0x11", the one-view tree).
    /// Each case:
    /// - two pages across the split, `MADV_DONTNEED`: zeros, a page made
    ///   read-only before it read-only after (its first access resolves
    ///   it), a write after it kept; the chunk's commit and charge kept,
    ///   as a registered partial discard keeps them, and its mincore the
    ///   same as a registered discard's of the same pages;
    /// - the same with `MADV_FREE`;
    /// - a whole chunk: zeros, and its commit and its charge given back
    ///   (measured before and after: 2 MiB and 0), as a registered chunk
    ///   discarded whole gives them back;
    /// - one call over a released chunk and a registered one: the released
    ///   chunk's pages read zeros, the registered chunk's are missing;
    /// - a reader of a page while it is discarded sees each word as it was
    ///   or zero, nothing else;
    /// - the control: an anonymous `MAP_SHARED` mapping's pages keep their
    ///   data, as Linux's shmem does.
    #[test]
    fn test_a_discard_of_a_released_chunk_reads_zeros() {
        let half = crate::windows_mm::chunk_half(CHUNK as usize) as u64;
        let byte = |at: u64| {
            // SAFETY: mapped memory of ours.
            unsafe { ptr::read_volatile(at as *const u8) }
        };
        let madvise = |at: u64, len: u64, advice: c_int| {
            // SAFETY: our mapping.
            unsafe { crate::madvise(at as *mut c_void, len as usize, advice) }
        };
        let charged = |view: u64| crate::windows_mm::charged(view as usize).unwrap_or(0) as u64;
        // A registered range of one chunk, two pages across its split
        // discarded: what a registered partial discard leaves.
        let (reg, reg_user, _) = released_of(CHUNK, 0x11, 0, 0);
        // Read first, so that the pages are resident (in the working set).
        assert_eq!((byte(reg + half - PAGE), byte(reg + half)), (0x11, 0x11));
        let reg_charge = charged(reg);
        assert_eq!(madvise(reg + half - PAGE, 2 * PAGE, crate::MADV_DONTNEED), 0);
        assert!(is_missing(reg + half - PAGE) && is_missing(reg + half));
        let (reg_resident, reg_after) = (resident(reg + half - PAGE, 2 * PAGE), charged(reg));
        std::eprintln!("RELDISCARD registered partial: charge {reg_charge:#x} -> {reg_after:#x}, mincore {reg_resident:?}");
        // Released, three chunks.
        let (mem, user, _) = released_of(3 * CHUNK, 0x11, 0, 3 * CHUNK);
        // Partial, MADV_DONTNEED, a page read-only.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::mprotect((mem + half) as *mut c_void, PAGE as usize, crate::PROT_READ) }, 0);
        let (commit, charge) = (committed(mem, CHUNK), charged(mem));
        assert_eq!((byte(mem + half - PAGE), byte(mem + half)), (0x11, 0x11));
        assert_eq!(resident(mem + half - PAGE, 2 * PAGE), [1, 1], "the pages resident before the discard");
        assert_eq!(madvise(mem + half - PAGE, 2 * PAGE, crate::MADV_DONTNEED), 0);
        let rel_resident = resident(mem + half - PAGE, 2 * PAGE);
        let (commit_after, charge_after) = (committed(mem, CHUNK), charged(mem));
        std::eprintln!(
            "RELDISCARD released partial: commit {commit:#x} -> {commit_after:#x}, charge {charge:#x} -> {charge_after:#x}, mincore {rel_resident:?}"
        );
        assert_eq!((byte(mem + half - PAGE), byte(mem + half), byte(mem + half + PAGE)), (0, 0, 0x11), "MADV_DONTNEED across the split");
        assert_eq!(states(mem + half, PAGE)[0].1, PAGE_READONLY, "the page read-only before the discard, after its first access");
        // SAFETY: mapped memory of ours, writable.
        unsafe { ptr::write_volatile((mem + half - PAGE) as *mut u8, 0x22) };
        assert_eq!(byte(mem + half - PAGE), 0x22, "a write after the discard");
        assert_eq!((commit_after, charge_after), (commit, charge), "a partial discard keeps its commit and charge, as a registered one");
        assert_eq!(rel_resident, reg_resident, "mincore of the discarded pages against a registered discard's");
        assert_eq!(charge, reg_charge);
        // Partial, MADV_FREE.
        assert_eq!(madvise(mem + CHUNK + half - PAGE, 2 * PAGE, crate::MADV_FREE), 0);
        assert_eq!((byte(mem + CHUNK + half - PAGE), byte(mem + CHUNK + half)), (0, 0), "MADV_FREE across the split");
        // Whole, the third chunk.
        let whole = mem + 2 * CHUNK;
        let (commit, charge) = (committed(whole, CHUNK), charged(whole));
        assert_eq!(madvise(whole, CHUNK, crate::MADV_DONTNEED), 0);
        let (commit_after, charge_after) = (committed(whole, CHUNK), charged(whole));
        std::eprintln!("RELDISCARD released whole chunk: commit {commit:#x} -> {commit_after:#x}, charge {charge:#x} -> {charge_after:#x}");
        assert_eq!((commit, charge), (CHUNK, CHUNK), "the chunk before");
        assert_eq!((commit_after, charge_after), (0, 0), "a whole chunk's commit and charge, given back");
        assert_eq!((byte(whole + PAGE), byte(whole + half)), (0, 0), "the whole chunk");
        assert_eq!(committed(whole, CHUNK), 2 * PAGE, "the reads committed their pages");
        // A reader while a page is discarded: each word as it was, or zero.
        let page = mem + CHUNK + PAGE;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut seen = (0u64, 0u64, 0u64);
                while !stop.load(Ordering::Relaxed) {
                    for w in 0..PAGE / 8 {
                        // SAFETY: mapped memory of ours.
                        match unsafe { ptr::read_volatile((page + w * 8) as *const u64) } {
                            0x1111_1111_1111_1111 => seen.0 += 1,
                            0 => seen.1 += 1,
                            _ => seen.2 += 1,
                        }
                    }
                }
                seen
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(madvise(page, PAGE, crate::MADV_DONTNEED), 0);
        std::thread::sleep(std::time::Duration::from_millis(20));
        stop.store(true, Ordering::Relaxed);
        let seen = reader.join().unwrap();
        std::eprintln!("RELDISCARD a reader during the discard: words as they were {}, zero {}, other {}", seen.0, seen.1, seen.2);
        assert_eq!(seen.2, 0, "a word neither as it was nor zero");
        assert!(seen.1 > 0, "the reader saw no zero after the discard");
        // SAFETY: our mappings, whole; closes the user ends.
        unsafe {
            assert_eq!(crate::munmap(mem as *mut c_void, 3 * CHUNK as usize), 0);
            assert_eq!(crate::munmap(reg as *mut c_void, CHUNK as usize), 0);
            ws::closesocket(sock(user));
            ws::closesocket(sock(reg_user));
        }
        // One call over a released chunk and a registered one.
        let (mixed, mixed_user, _) = released_of(2 * CHUNK, 0x11, 0, CHUNK);
        assert_eq!(madvise(mixed + PAGE, 2 * CHUNK - 2 * PAGE, crate::MADV_DONTNEED), 0);
        assert_eq!(byte(mixed + half), 0, "the released chunk's page");
        assert!(is_missing(mixed + CHUNK + half), "the registered chunk's page is missing");
        // SAFETY: our mapping; closes the user end.
        unsafe {
            assert_eq!(crate::munmap(mixed as *mut c_void, 2 * CHUNK as usize), 0);
            ws::closesocket(sock(mixed_user));
        }
        // The control: shared memory keeps its pages.
        // SAFETY: a new anonymous shared mapping, written.
        let shared = unsafe {
            let m = crate::mmap(ptr::null_mut(), CHUNK as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_SHARED | crate::MAP_ANONYMOUS, -1, 0);
            assert_ne!(m, crate::MAP_FAILED);
            ptr::write_bytes(m.cast::<u8>(), 0x33, CHUNK as usize);
            m as u64
        };
        assert_eq!(madvise(shared, CHUNK, crate::MADV_DONTNEED), 0);
        assert_eq!((byte(shared), byte(shared + half)), (0x33, 0x33), "MAP_SHARED keeps its data");
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(shared as *mut c_void, CHUNK as usize) }, 0);
    }

    /// The page [`touch_released_page`] reads, once (0: none).
    static TOUCH_AT: AtomicU64 = AtomicU64::new(0);

    /// A first access to the page at [`TOUCH_AT`] from another thread, as a
    /// vCPU's, resolving it (committed and charged), waited for.
    fn touch_released_page() {
        let at = TOUCH_AT.swap(0, Ordering::SeqCst);
        if at != 0 {
            // SAFETY: a page of a released range of the test's.
            std::thread::spawn(move || unsafe { ptr::read_volatile(at as *const u8) }).join().unwrap();
        }
    }

    /// A page of a released chunk discarded whole that a first access on
    /// another thread resolves as the discard ends keeps its charge: the
    /// chunk's charge is given back under the records' lock, which the
    /// resolve takes, so the resolve comes after it and charges its page
    /// again (`windows_mm::released_swap`). Given back after the locks were
    /// dropped, it decommitted the page's charge with the rest: a committed
    /// section page with none ("committed 0x1000, charged 0x0" on 20348
    /// with the charge given back so). The access is made by
    /// `windows_mm::AFTER_RELEASED_DISCARD_LOCKS`.
    #[test]
    fn test_a_page_resolved_as_its_released_chunk_is_discarded_keeps_its_charge() {
        let (mem, user, _) = released_of(CHUNK, 0x11, 0, CHUNK);
        let charged = |view: u64| crate::windows_mm::charged(view as usize).unwrap_or(0) as u64;
        assert_eq!(charged(mem), CHUNK);
        TOUCH_AT.store(mem + PAGE, Ordering::SeqCst);
        *crate::windows_mm::AFTER_RELEASED_DISCARD_LOCKS.lock().unwrap() = Some(touch_released_page);
        // SAFETY: our mapping, released.
        let d = unsafe { crate::madvise(mem as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) };
        *crate::windows_mm::AFTER_RELEASED_DISCARD_LOCKS.lock().unwrap() = None;
        assert_eq!(d, 0);
        assert_eq!(TOUCH_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        let (commit, charge) = (committed(mem, CHUNK), charged(mem));
        std::eprintln!("RELDISCARD a page resolved as its chunk's discard ended: committed {commit:#x}, charged {charge:#x}");
        // SAFETY: our mapping; closes the user end.
        unsafe {
            assert_eq!(crate::munmap(mem as *mut c_void, CHUNK as usize), 0);
            ws::closesocket(sock(user));
        }
        assert_eq!((commit, charge), (PAGE, PAGE), "the resolved page's commit and its charge");
    }

    /// RELALIAS, a record: what a released 1 GiB range keeps of its alias.
    /// A `MAP_NORESERVE` range registered, a page filled in each chunk
    /// through the alias (UFFDIO_COPY, so that the alias's page tables
    /// exist), then unregistered whole: the process's private commit
    /// (PrivateUsage, which counts the page tables) before and after the
    /// unregister, three rounds; then the same with no page filled, three
    /// rounds. Since the released discard a released
    /// chunk keeps its alias's views (`windows_mm::uffd_unalias`); before,
    /// a range with no stale page dropped them at the release.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_what_a_released_range_keeps_of_its_alias_on_record() {
        let len = 512 * CHUNK;
        for round in 0..6 {
            let fills = round < 3;
            // SAFETY: a new anonymous mapping, committed at first touch.
            let mem = unsafe {
                crate::mmap(
                    ptr::null_mut(),
                    len as usize,
                    crate::PROT_READ | crate::PROT_WRITE,
                    crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_ne!(mem, crate::MAP_FAILED);
            let mem = mem as u64;
            let (ctx, user) = create(0, false, true).unwrap();
            register(ctx, mem, len).unwrap();
            let src = [0x5au8; PAGE as usize];
            for c in (0..512).filter(|_| fills) {
                // SAFETY: `src` holds a page.
                assert_eq!(unsafe { copy(ctx, src.as_ptr(), mem + c * CHUNK + PAGE, PAGE, false) }, Ok(PAGE));
            }
            let before = private_commit();
            unregister(ctx, mem, len).unwrap();
            let after = private_commit();
            std::eprintln!(
                "RELALIAS round {round}, {}: private commit {} KiB before the unregister, {} after ({:+} KiB)",
                if fills { "a page filled in each chunk" } else { "nothing filled" },
                before >> 10,
                after >> 10,
                (after as i64 - before as i64) / 1024
            );
            // SAFETY: our mapping; closes the user end.
            unsafe {
                assert_eq!(crate::munmap(mem as *mut c_void, len as usize), 0);
                ws::closesocket(sock(user));
            }
        }
    }

    /// A released chunk never filled, on a 2 MiB boundary and advised
    /// `MADV_HUGEPAGE`: a first write commits the whole aligned 2 MiB, its
    /// two views, and reports it, as `windows_mm`'s
    /// test_madv_hugepage_is_what_a_first_access_commits asserts for lazy
    /// memory; a record's 64 KiB grain commits its 64 KiB block on either
    /// side of the split. Review B1: with two views a chunk's huge commit
    /// was refused (one commit across two allocations) and fell back to a
    /// page, silently.
    #[test]
    fn test_a_released_chunks_huge_page_is_committed_whole() {
        use crate::windows_mm::wick_mm::{Access, commit_block_on_access, record_grain};
        let half = crate::windows_mm::chunk_half(CHUNK as usize) as u64;
        let grain = 64 << 10;
        let rw = crate::PROT_READ | crate::PROT_WRITE;
        let flags = crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE;
        // Two chunks on a 2 MiB boundary: three chunks' room found, freed,
        // and asked for at its boundary (a hint; another thread may take
        // the room meanwhile, so a few tries).
        let mem = (0..8)
            .find_map(|_| {
                // SAFETY: a new anonymous mapping, unmapped at once.
                let room = unsafe { crate::mmap(ptr::null_mut(), 3 * CHUNK as usize, rw, flags, -1, 0) };
                assert_ne!(room, crate::MAP_FAILED);
                // SAFETY: the mapping just made.
                assert_eq!(unsafe { crate::munmap(room, 3 * CHUNK as usize) }, 0);
                let at = (room as u64).next_multiple_of(CHUNK);
                // SAFETY: a new anonymous mapping, at `at` if it is free.
                let p = unsafe { crate::mmap(at as *mut c_void, 2 * CHUNK as usize, rw, flags, -1, 0) } as u64;
                assert_ne!(p, crate::MAP_FAILED as u64);
                if p != at {
                    // SAFETY: our mapping, elsewhere than asked.
                    assert_eq!(unsafe { crate::munmap(p as *mut c_void, 2 * CHUNK as usize) }, 0);
                }
                (p == at).then_some(p)
            })
            .expect("no 2 MiB boundary found free in 8 tries");
        assert!(mem.is_multiple_of(CHUNK));
        let (ctx, user) = create(0, false, true).unwrap();
        register(ctx, mem, 2 * CHUNK).unwrap();
        assert!(range_of_view(mem as usize).is_some_and(|(r, _)| r.reserved.load(Ordering::Acquire)), "not a chunked range");
        unregister(ctx, mem, 2 * CHUNK).unwrap();
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise(mem as *mut c_void, CHUNK as usize, crate::MADV_HUGEPAGE) }, 0);
        #[allow(clippy::cast_possible_truncation)]
        let (m, c, h, g) = (mem as usize, CHUNK as usize, half as usize, grain as usize);
        let at = commit_block_on_access(m + 5 * PAGE as usize, true);
        std::eprintln!("HUGERESOLVE a write into the advised chunk: {at:?}, {:#x} bytes of it committed", committed(mem, CHUNK));
        assert_eq!(at, (Access::Committed, m..m + c), "the whole aligned 2 MiB, both views");
        assert_eq!(committed(mem, CHUNK), CHUNK);
        // The range returned is what was resolved: no page of it pending in
        // the record, every other page of the chunk still pending.
        let pending_outside = |chunk: usize, resolved: &[&core::ops::Range<usize>]| {
            (chunk..chunk + c).step_by(PAGE as usize).find(|&p| {
                crate::windows_mm::released_is_pending(p) == resolved.iter().any(|r| r.contains(&p))
            })
        };
        assert_eq!(pending_outside(m, &[&at.1]), None, "a page resolved outside the range returned, or pending in it");
        // The second chunk at a record's 64 KiB grain: the block below the
        // split, then the one above it.
        record_grain(m + c, c, g);
        let below = commit_block_on_access(m + c + h - PAGE as usize, true);
        let above = commit_block_on_access(m + c + h, true);
        std::eprintln!("HUGERESOLVE 64 KiB below the split: {below:?}; above: {above:?}; {:#x} bytes committed", committed(mem + CHUNK, CHUNK));
        record_grain(m + c, c, 0);
        assert_eq!(below, (Access::Committed, m + c + h - g..m + c + h), "the block below the split");
        assert_eq!(above, (Access::Committed, m + c + h..m + c + h + g), "the block above the split");
        assert_eq!(pending_outside(m + c, &[&below.1, &above.1]), None, "a page resolved outside the blocks returned, or pending in them");
        assert_eq!(committed(mem + CHUNK, CHUNK), 2 * grain);
        // SAFETY: our mappings, whole; closes the user end.
        unsafe {
            assert_eq!(crate::munmap(mem as *mut c_void, 2 * CHUNK as usize), 0);
            ws::closesocket(sock(user));
        }
    }

    /// A chunk's views go together: Windows refusing the unmap of the
    /// first (a test refusal, `windows_mm::REFUSE_CHUNK_UNMAP`) changes
    /// nothing, for a munmap of the chunk (`EINVAL`) and a `MAP_FIXED`
    /// mapping over it (`EINVAL`): both views keep their pages, and a page
    /// of the released range never filled is still pending in its record
    /// (zeros at its first access, which takes a write); its placeholders
    /// not made one again (`windows_mm::REFUSE_COALESCE`), the chunk is two
    /// placeholders, which a `MAP_FIXED` mapping over it takes as one
    /// (`make_placeholder` counts them again). Review B1.
    #[test]
    fn test_a_chunk_whose_first_unmap_is_refused_is_left_whole() {
        let half = crate::windows_mm::chunk_half(CHUNK as usize) as u64;
        let len = 2 * CHUNK;
        let rw = crate::PROT_READ | crate::PROT_WRITE;
        // SAFETY: a new anonymous mapping.
        let mem = unsafe { crate::mmap(ptr::null_mut(), len as usize, rw, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0) };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        let byte = |at: u64| {
            // SAFETY: mapped memory of ours.
            unsafe { ptr::read_volatile(at as *const u8) }
        };
        for p in [half - PAGE, half] {
            // SAFETY: mapped memory of ours.
            unsafe { ptr::write_volatile((mem + p) as *mut u8, 0x11) };
        }
        let (ctx, user) = create(0, false, true).unwrap();
        register(ctx, mem, len).unwrap();
        assert!(range_of_view(mem as usize).is_some_and(|(r, _)| r.reserved.load(Ordering::Acquire)), "not a chunked range");
        unregister(ctx, mem, len).unwrap();
        let einval = Some(crate::EINVAL);
        for case in ["munmap", "MAP_FIXED"] {
            *crate::windows_mm::REFUSE_CHUNK_UNMAP.lock().unwrap() = Some((mem as usize, 0));
            // SAFETY: our mapping's first chunk, its first view's unmap refused.
            let failed = unsafe {
                if case == "munmap" {
                    crate::munmap(mem as *mut c_void, CHUNK as usize) == -1
                } else {
                    let flags = crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED;
                    crate::mmap(mem as *mut c_void, CHUNK as usize, rw, flags, -1, 0) == crate::MAP_FAILED
                }
            };
            let errno = io::Error::last_os_error().raw_os_error();
            assert!(crate::windows_mm::REFUSE_CHUNK_UNMAP.lock().unwrap().is_none(), "{case}: the refusal was not reached");
            assert!(failed && errno == einval, "{case} over a chunk whose first unmap is refused: failed {failed}, errno {errno:?}");
            assert_eq!((byte(mem + half - PAGE), byte(mem + half)), (0x11, 0x11), "{case}: the chunk's pages");
        }
        // A page never filled, pending in the record still.
        let never = mem + 5 * PAGE;
        assert_eq!(byte(never), 0, "a page never filled");
        // SAFETY: mapped memory of ours, released.
        unsafe { ptr::write_volatile(never as *mut u8, 0x55) };
        assert_eq!(byte(never), 0x55);
        // The second chunk's placeholders not made one again.
        *crate::windows_mm::REFUSE_COALESCE.lock().unwrap() = Some((mem + CHUNK) as usize);
        let flags = crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED;
        // SAFETY: a fixed anonymous mapping over our second chunk.
        let fixed = unsafe { crate::mmap((mem + CHUNK) as *mut c_void, CHUNK as usize, rw, flags, -1, 0) } as u64;
        assert!(crate::windows_mm::REFUSE_COALESCE.lock().unwrap().is_none(), "the coalesce refusal was not reached");
        assert_eq!(fixed, mem + CHUNK, "MAP_FIXED over a chunk left two placeholders: errno {:?}", io::Error::last_os_error().raw_os_error());
        assert_eq!(byte(fixed + half), 0);
        // SAFETY: the new mapping.
        unsafe { ptr::write_volatile((fixed + half) as *mut u8, 0x66) };
        assert_eq!(byte(fixed + half), 0x66);
        // SAFETY: our mappings, whole; closes the user end.
        unsafe {
            assert_eq!(crate::munmap(mem as *mut c_void, len as usize), 0);
            ws::closesocket(sock(user));
        }
    }

    /// A chunk's second view whose unmap Windows refuses once its first is
    /// gone (a test refusal) ends the VMM with a line naming it and an
    /// abort (0xC0000409): the chunk is half mapped. Review B1. In a
    /// process of its own.
    #[test]
    fn test_a_chunk_whose_second_unmap_is_refused_aborts_named() {
        let (code, text) = run_child("second_unmap_refused_child", None);
        assert!(text.contains("could not be unmapped once its first was"), "{text}");
        assert!(!text.contains("UNMAPPED"), "{text}");
        assert_eq!(code, Some(0xC000_0409_u32.cast_signed()), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_chunk_whose_second_unmap_is_refused_aborts_named in a process of its own"]
    fn second_unmap_refused_child() {
        let len = 2 * CHUNK;
        // SAFETY: a new anonymous mapping.
        let mem = unsafe {
            crate::mmap(ptr::null_mut(), len as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        let (ctx, _user) = create(0, false, true).unwrap();
        register(ctx, mem, len).unwrap();
        unregister(ctx, mem, len).unwrap();
        *crate::windows_mm::REFUSE_CHUNK_UNMAP.lock().unwrap() = Some((mem as usize, 1));
        // SAFETY: our mapping's first chunk, its second view's unmap refused.
        let r = unsafe { crate::munmap(mem as *mut c_void, CHUNK as usize) };
        std::println!("UNMAPPED: {r}");
    }

    /// UFFDHALF, a record: the register of a 1 GiB range (512 chunks, each
    /// two views since review B1, one before: UFFDCHUNK b measured 5.43 us a
    /// chunk for the sections and views alone) and the whole-chunk discard
    /// of 100 of its chunks (`uffd_swap_chunk`; UFFDCHUNK b: 8.7 us a swap
    /// of one view each), in microseconds a chunk, three rounds; then the
    /// munmap of the range.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture (CI's WHP step)"]
    fn test_a_chunks_views_cost_on_record() {
        let len = 512 * CHUNK;
        for round in 0..3 {
            // SAFETY: a new anonymous mapping, committed at first touch.
            let mem = unsafe {
                crate::mmap(
                    ptr::null_mut(),
                    len as usize,
                    crate::PROT_READ | crate::PROT_WRITE,
                    crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_ne!(mem, crate::MAP_FAILED);
            let mem = mem as u64;
            let (ctx, user) = create(0, false, true).unwrap();
            let t = std::time::Instant::now();
            register(ctx, mem, len).unwrap();
            let registered = t.elapsed();
            let t = std::time::Instant::now();
            for c in 0..100 {
                // SAFETY: registered memory of ours, a chunk whole.
                assert_eq!(unsafe { crate::madvise((mem + c * CHUNK) as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) }, 0);
            }
            let swapped = t.elapsed();
            let t = std::time::Instant::now();
            // SAFETY: closes the user end, then unmaps our mapping.
            unsafe {
                ws::closesocket(sock(user));
                assert_eq!(crate::munmap(mem as *mut c_void, len as usize), 0);
            }
            let unmapped = t.elapsed();
            std::eprintln!(
                "UFFDHALF round {round}: register of 512 chunks {:.2} us a chunk; whole-chunk discard of 100 {:.2} us a chunk; munmap {:.2} us a chunk",
                registered.as_secs_f64() * 1e6 / 512.0,
                swapped.as_secs_f64() * 1e6 / 100.0,
                unmapped.as_secs_f64() * 1e6 / 512.0
            );
        }
    }

    /// The pages [`take_the_room_the_unmap_gave`] took.
    static VIEW_ROOM_TAKEN: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());
    static VIEW_ROOM_TAKEN_ONCE: AtomicBool = AtomicBool::new(false);

    /// Another commit taking the room a view's unmap gave in a chunk's swap
    /// (`windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP` or
    /// `BETWEEN_ALIAS_UNMAP_AND_MAP`, `view` the view's index), the first
    /// time only: all the job has, its pages and the slack
    /// ([`take_the_slack`]). The unmap's step is the alias's first view's if
    /// the guest view's has not been reached (VIEWREC).
    fn take_the_room_the_unmap_gave(view: usize) {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc};
        if VIEW_ROOM_TAKEN_ONCE.swap(true, Ordering::SeqCst) {
            return;
        }
        let gave = {
            let v = &crate::windows_mm::VIEWREC;
            let guest = v[4].load(Ordering::SeqCst) != 0;
            let step = if guest { 5 } else { 1 } + 2 * view;
            (v[step - 1].load(Ordering::SeqCst) as i64 - v[step].load(Ordering::SeqCst) as i64) / 1024
        };
        let mut held = VIEW_ROOM_TAKEN.lock().unwrap();
        while held.len() < held.capacity() {
            // SAFETY: new private memory of ours.
            let p = unsafe { VirtualAlloc(ptr::null(), PAGE as usize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
            if p.is_null() {
                break;
            }
            held.push(p as usize);
        }
        let before = SLACK_TAKEN.load(Ordering::SeqCst);
        let after = take_the_slack();
        crate::windows_mm::say_at_the_limit(format_args!(
            "VIEWROOM the view's unmap gave {gave} KiB; the hook took {} KiB in pages and {} KiB where a page table was; \
             private commit {} KiB",
            held.len() * PAGE as usize / 1024,
            (after - before) * PAGE as usize / 1024,
            private_commit() / 1024
        ));
    }

    /// A move whose guest view's room, what a view's unmap gave back (a page
    /// table for each 2 MiB region only it maps: VIEWCOST), another commit
    /// takes before the view is mapped again
    /// (`windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP`), with no room left in
    /// the job ([`no_room_left`]): the move is made, the fill that needed
    /// it too, and the VMM goes on. The range on a 2 MiB boundary, as
    /// Firecracker's guest memory is; its first chunk with 8 dead pages.
    /// With both views of a chunk swapped together, the unmaps gave back the
    /// region's page table, the hook took it, and the map was refused: the
    /// VMM ended with 137 (fails on 9dcf90d0).
    #[test]
    fn test_a_move_whose_guest_view_room_is_taken_is_made() {
        view_room_taken("guest_view_room_taken_child", "VIEWROOM the fill made, 1 moves made, 0 not made");
    }

    /// The same with the alias's view (`windows_mm::BETWEEN_ALIAS_UNMAP_AND_MAP`).
    #[test]
    fn test_a_move_whose_alias_room_is_taken_is_made() {
        view_room_taken("alias_room_taken_child", "VIEWROOM the fill made, 1 moves made, 0 not made");
    }

    /// The same with the swap of a registered chunk discarded whole
    /// (`windows_mm::uffd_swap_chunk`, the guest view's room taken): the
    /// discard is made, the chunk's pages missing and its commit given back.
    #[test]
    fn test_a_discard_whose_guest_view_room_is_taken_is_made() {
        view_room_taken("discard_room_taken_child", "VIEWROOM the discard made, its pages missing");
    }

    /// Runs `child` in a job of its own and asserts its hook ran and `made`.
    fn view_room_taken(child: &str, made: &str) {
        let (code, text) = run_child(child, Some(96 << 20));
        for l in text
            .lines()
            .filter(|l| l.starts_with("VIEWROOM") || l.starts_with("VIEWCOST") || l.starts_with("room left") || l.starts_with("wick:") || l.starts_with("filled"))
        {
            std::eprintln!("{l}");
        }
        assert!(text.contains("VIEWROOM the view's unmap gave"), "the hook did not run: {text}");
        assert!(text.contains(made), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_move_whose_guest_view_room_is_taken_is_made in a job of its own"]
    fn guest_view_room_taken_child() {
        move_room_taken(&crate::windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP);
    }

    #[test]
    #[ignore = "run by test_a_move_whose_alias_room_is_taken_is_made in a job of its own"]
    fn alias_room_taken_child() {
        move_room_taken(&crate::windows_mm::BETWEEN_ALIAS_UNMAP_AND_MAP);
    }

    /// The children's move: the range at the limit, its first chunk with 8
    /// dead pages, the room taken by `hook`'s turn.
    fn move_room_taken(hook: &Mutex<Option<fn(usize)>>) {
        let at = fresh_gib(1) + (64 << 20);
        let (ctx, user, mem, done) = fill_to_the_limit_at(at, 0);
        for p in 0..8 {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + (2 * p + 1) * PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        VIEW_ROOM_TAKEN.lock().unwrap().reserve_exact(4096);
        let mut held = no_room_left();
        *hook.lock().unwrap() = Some(take_the_room_the_unmap_gave);
        let (m1, refused1) = (moves_on_record().0.len(), crate::windows_mm::moves_refused());
        let fill = fill_a_page(ctx, mem + done);
        let (m2, refused2) = (moves_on_record().0.len(), crate::windows_mm::moves_refused());
        *hook.lock().unwrap() = None;
        let alias = range_of_view(mem as usize).map_or(0, |(r, _)| r.alias.load(Ordering::Acquire) as usize);
        viewcost_line("the hook's move", mem as usize, alias, format_args!(""));
        crate::windows_mm::say_at_the_limit(format_args!(
            "VIEWROOM the fill {fill}, {} moves made, {} not made",
            m2 - m1,
            refused2 - refused1
        ));
        give_back_the_room(&mut held);
        for p in (0..CHUNK).step_by(PAGE as usize) {
            if p % (2 * PAGE) == PAGE && p < 16 * PAGE {
                assert!(is_missing(mem + p), "{p:#x} is not missing");
            } else {
                // SAFETY: a filled page.
                assert_eq!(unsafe { *((mem + p + 9) as *const u8) }, 0x5a, "{p:#x}");
            }
        }
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Gives back what the hook and [`no_room_left`] took.
    fn give_back_the_room(held: &mut std::vec::Vec<usize>) {
        {
            let mut t = VIEW_ROOM_TAKEN.lock().unwrap();
            while !t.is_empty() {
                give_back_a_page(&mut t);
            }
        }
        give_back_every_page(held);
    }

    #[test]
    #[ignore = "run by test_a_discard_whose_guest_view_room_is_taken_is_made in a job of its own"]
    fn discard_room_taken_child() {
        let at = fresh_gib(1) + (64 << 20);
        let (_ctx, user, mem, _) = fill_to_the_limit_at(at, 0);
        VIEW_ROOM_TAKEN.lock().unwrap().reserve_exact(4096);
        let mut held = no_room_left();
        let commit = committed(mem, CHUNK);
        *crate::windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP.lock().unwrap() = Some(take_the_room_the_unmap_gave);
        // SAFETY: registered memory of ours, its first chunk whole.
        let d = unsafe { crate::madvise(mem as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) };
        *crate::windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP.lock().unwrap() = None;
        assert_eq!(d, 0);
        assert_eq!(crate::windows_mm::VIEWREC[9].load(Ordering::SeqCst), 2, "the swap");
        let alias = range_of_view(mem as usize).map_or(0, |(r, _)| r.alias.load(Ordering::Acquire) as usize);
        viewcost_line("the hook's swap", mem as usize, alias, format_args!(""));
        let (missing, after) = ((0..CHUNK).step_by(PAGE as usize).all(|p| is_missing(mem + p)), committed(mem, CHUNK));
        give_back_the_room(&mut held);
        crate::windows_mm::say_at_the_limit(format_args!(
            "VIEWROOM the discard made, its pages {}; the chunk's commit {commit:#x} -> {after:#x}",
            if missing { "missing" } else { "not all missing" }
        ));
        assert_eq!(after, 0, "the chunk's commit");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The move slot (`windows_mm::MOVE_SLOT`), in a process of its own
    /// (MOVESLOT lines): none, nor the move budget, in a process that maps
    /// and unmaps memory and registers nothing; made with the budget at the
    /// first registration, 64 KiB past a 2 MiB boundary, at what cost to the
    /// private commit (a record); then a move of a chunk with a dead page
    /// maps its new section's view in the slot, the map and its unmap taking
    /// and giving back no commit, where a view mapped anywhere took 4 KiB
    /// (MOVEREC; fails on 9dcf90d0); and a short last chunk's move (a range
    /// of a chunk and a half) uses the slot split to its length, a whole
    /// chunk's after it the slot whole again.
    #[test]
    fn test_a_moves_temporary_view_takes_no_commit() {
        let (code, text) = run_child("move_slot_child", None);
        for l in text.lines().filter(|l| l.starts_with("MOVESLOT")) {
            std::eprintln!("{l}");
        }
        assert!(text.contains("MOVESLOT done"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_moves_temporary_view_takes_no_commit in a process of its own"]
    fn move_slot_child() {
        // SAFETY: a mapping of ours, written and unmapped.
        unsafe {
            let m = crate::mmap(ptr::null_mut(), 4 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0);
            assert_ne!(m, crate::MAP_FAILED);
            ptr::write_bytes(m.cast::<u8>(), 1, 4 << 20);
            assert_eq!(crate::munmap(m, 4 << 20), 0);
        }
        assert_eq!(crate::windows_mm::move_slot_and_budget_for_tests(), (0, 0), "a process that registers nothing");
        let before = private_commit();
        assert!(crate::windows_mm::uffd_budget_now_for_tests());
        let after = private_commit();
        let (slot, budget) = crate::windows_mm::move_slot_and_budget_for_tests();
        assert_ne!(budget, 0);
        std::println!(
            "MOVESLOT the budget and the slot (at {slot:#x}): {:+} KiB of private commit (the budget 2048)",
            (after as i64 - before as i64) / 1024
        );
        let page = [0x5au8; PAGE as usize];
        for (what, len) in [("a whole chunk", CHUNK), ("a chunk and a half, the short last chunk", CHUNK + CHUNK / 2), ("a whole chunk again", CHUNK)] {
            let (ctx, user) = create(0, false, true).unwrap();
            // SAFETY: a new anonymous mapping, committed at first touch.
            let mem = unsafe {
                crate::mmap(ptr::null_mut(), len as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
            };
            assert_ne!(mem, crate::MAP_FAILED);
            let mem = mem as u64;
            register(ctx, mem, len).unwrap();
            let last = (len - 1) / CHUNK * CHUNK;
            for p in (last..len).step_by(PAGE as usize) {
                // SAFETY: `page` holds a page.
                unsafe { copy(ctx, page.as_ptr(), mem + p, PAGE, false) }.unwrap();
            }
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + last + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            let r = reclaim_at_touch(PAGE as usize);
            let m: [usize; 12] = core::array::from_fn(|i| crate::windows_mm::MOVEREC[i].load(Ordering::SeqCst));
            let (map, unmap) = ((m[3] as i64 - m[1] as i64) / 1024, (m[8] as i64 - m[7] as i64) / 1024);
            std::println!("MOVESLOT {what}: {} moved, its view at {:#x} (the slot {slot:#x}): map {map:+} KiB, unmap {unmap:+} KiB", r.chunks, m[2]);
            assert_eq!(r.chunks, 1, "{what}: the move");
            assert_eq!((map, unmap), (0, 0), "{what}: the view's map and unmap");
            assert_eq!(m[2], slot, "{what}: the move's view");
            for p in (last..len).step_by(PAGE as usize).filter(|&p| p != last + PAGE) {
                // SAFETY: a filled page.
                assert_eq!(unsafe { *((mem + p) as *const u8) }, 0x5a, "{what}: {p:#x}");
            }
            assert!(is_missing(mem + last + PAGE));
            // SAFETY: closes the user end, then unmaps our mapping.
            unsafe {
                ws::closesocket(sock(user));
                assert_eq!(crate::munmap(mem as *mut c_void, len as usize), 0);
            }
        }
        assert_eq!(slot % CHUNK as usize, 64 << 10, "the slot at {slot:#x}");
        std::println!("MOVESLOT done");
    }

    /// The readers [`read_both_halves`] started, each giving the byte it
    /// read and when it was read.
    static HALF_READERS: Mutex<std::vec::Vec<std::thread::JoinHandle<(u8, std::time::Instant)>>> = Mutex::new(std::vec::Vec::new());
    /// The two pages they read (one in each of a chunk's views) and when the
    /// hook ended.
    static HALF_PAGES: Mutex<(u64, u64, Option<std::time::Instant>)> = Mutex::new((0, 0, None));

    /// `windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP`'s turn for the guest view's
    /// first view (its placeholder out, the second view the old section's,
    /// its live pages closed): a reader of a page of each starts, then the
    /// hook waits 50 ms.
    fn read_both_halves(view: usize) {
        if view != 0 {
            return;
        }
        let (a, b, _) = *HALF_PAGES.lock().unwrap();
        let mut readers = HALF_READERS.lock().unwrap();
        for at in [a, b] {
            readers.push(std::thread::spawn(move || {
                // SAFETY: a page of a registered range of the test's.
                let v = unsafe { ptr::read_volatile(at as *const u8) };
                (v, std::time::Instant::now())
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        HALF_PAGES.lock().unwrap().2 = Some(std::time::Instant::now());
    }

    /// The chunk being moved is marked moving whole (`move_chunk`'s
    /// `MOVING_START` to its end) while its views are swapped one at a time:
    /// an access to a live page of either view, made when the guest view's
    /// first view is out and its second still the old section's, waits for
    /// the move and then reads the page's data.
    #[test]
    fn test_an_access_to_either_view_of_a_moving_chunk_waits_for_the_move() {
        let (code, text) = run_child("moving_halves_child", None);
        for l in text.lines().filter(|l| l.starts_with("MOVINGHALVES")) {
            std::eprintln!("{l}");
        }
        assert!(text.contains("MOVINGHALVES done"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_an_access_to_either_view_of_a_moving_chunk_waits_for_the_move in a process of its own"]
    fn moving_halves_child() {
        let half = crate::windows_mm::chunk_half(CHUNK as usize) as u64;
        let (ctx, user) = create(0, false, true).unwrap();
        // SAFETY: a new anonymous mapping, committed at first touch.
        let mem = unsafe {
            crate::mmap(ptr::null_mut(), CHUNK as usize, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_ne!(mem, crate::MAP_FAILED);
        let mem = mem as u64;
        on_a_boundary(mem);
        register(ctx, mem, CHUNK).unwrap();
        let page = [0x5au8; PAGE as usize];
        for p in [0, PAGE, half, half + PAGE] {
            // SAFETY: `page` holds a page.
            unsafe { copy(ctx, page.as_ptr(), mem + p, PAGE, false) }.unwrap();
        }
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        *HALF_PAGES.lock().unwrap() = (mem, mem + half + PAGE, None);
        *crate::windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP.lock().unwrap() = Some(read_both_halves);
        let r = reclaim_at_touch(PAGE as usize);
        *crate::windows_mm::BETWEEN_GUEST_UNMAP_AND_MAP.lock().unwrap() = None;
        let moved = std::time::Instant::now();
        assert_eq!(r.chunks, 1, "the move");
        let hook_end = HALF_PAGES.lock().unwrap().2.expect("the hook ran");
        let readers = std::mem::take(&mut *HALF_READERS.lock().unwrap());
        for (k, h) in readers.into_iter().enumerate() {
            let (v, at) = h.join().unwrap();
            std::println!(
                "MOVINGHALVES the reader of view {k}: read {v:#x}, {} us after the hook ended, the move ended {} us after it",
                at.saturating_duration_since(hook_end).as_micros(),
                moved.saturating_duration_since(hook_end).as_micros()
            );
            assert_eq!(v, 0x5a, "view {k}'s page");
            assert!(at >= hook_end, "view {k}'s reader did not wait for the move");
        }
        // SAFETY: closes the user end, then unmaps our mapping.
        unsafe {
            ws::closesocket(sock(user));
            assert_eq!(crate::munmap(mem as *mut c_void, CHUNK as usize), 0);
        }
        std::println!("MOVINGHALVES done");
    }

    /// A chunk with one dead page, the least a move gives back, with no room
    /// left in the job ([`no_room_left`]): a fill's reclaim moves it (its
    /// maps take no room: the move slot and the views swapped one at a time)
    /// or fails cleanly (the chunk and its charge as they were); which one,
    /// what the fill then got, what the move did to the process's private
    /// commit, and where its view was mapped (its offset in 2 MiB), printed;
    /// then chunks with 2, 3 and 4 dead pages the same way. Before the
    /// discards, at the same limit with no dead page anywhere, the reclaim
    /// moves nothing and tries no move: a chunk with no dead pages is never
    /// a candidate. Each fill's reclaim makes one move, on a range on a 2 MiB
    /// boundary, and the fill is made, but for one dead page when the fill's
    /// charge page is the first committed in its 2 MiB region: that commit
    /// takes a page table too, 8 KiB, where the move gave back 4 (as Linux
    /// charges a fault's page table to the memory cgroup with its page,
    /// v6.1 include/asm-generic/pgalloc.h :8 and :85, `GFP_PGTABLE_USER`
    /// with `__GFP_ACCOUNT`), so the fill is refused (`ENOMEM`), as before
    /// review B3; asserted so, where before only the line's presence was,
    /// which let a move not made pass. The live pages read back.
    #[test]
    fn test_a_chunk_with_one_dead_page_at_the_limit() {
        let (code, text) = run_child("one_dead_page_child", Some(96 << 20));
        std::eprintln!("{text}");
        assert!(text.contains("no dead page: the fill ENOMEM, 0 moves made, 0 tried"), "{text}");
        assert!(text.contains("ONEDEAD 1 dead page(s): "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_chunk_with_one_dead_page_at_the_limit in a job of its own"]
    fn one_dead_page_child() {
        let (ctx, user, mem, done) = fill_to_the_limit();
        let moves = || moves_on_record().0.len();
        let mut held = no_room_left();
        let (m0, refused0) = (moves(), crate::windows_mm::moves_refused());
        let none = fill_a_page(ctx, mem + done);
        let (m1, refused1) = (moves(), crate::windows_mm::moves_refused());
        crate::windows_mm::say_at_the_limit(format_args!(
            "no dead page: the fill {none}, {} moves made, {} tried",
            m1 - m0,
            (m1 - m0) as u64 + refused1 - refused0
        ));
        give_back_every_page(&mut held);
        // Chunk k - 1 with k dead pages (its odd pages from 1), each tried
        // with no room left.
        let mut wrong = std::vec::Vec::new();
        for k in 1..=4u64 {
            let chunk = mem + (k - 1) * CHUNK;
            for i in 0..k {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((chunk + (2 * i + 1) * PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
            // Whether the fill's charge page is the first committed in its
            // 2 MiB region of the charge's reservation: its commit then takes
            // a page table too, 8 KiB in all.
            #[allow(clippy::cast_possible_truncation)]
            let cp = crate::windows_mm::charge_page_of((mem + done + k * PAGE) as usize).expect("no charge page") as u64;
            let region = cp - cp % CHUNK;
            let fresh = (region..region + CHUNK).step_by(PAGE as usize).all(|p| p == cp || committed_protection(p).is_none());
            let mut held = no_room_left();
            let (m1, refused1) = (moves(), crate::windows_mm::moves_refused());
            let before = private_commit();
            let one = fill_a_page(ctx, mem + done + k * PAGE);
            let after = private_commit();
            let (m2, refused2) = (moves(), crate::windows_mm::moves_refused());
            let view = crate::windows_mm::LAST_MOVE_VIEW.load(Ordering::Relaxed);
            give_back_every_page(&mut held);
            std::println!(
                "ONEDEAD {k} dead page(s): the fill {one}, {} moves made, {} not made; the process's private \
                 commit {:+} KiB over the fill; the move's view at {view:#x}, {:#x} into its 2 MiB; the fill's charge \
                 page the first in its 2 MiB region {fresh}",
                m2 - m1,
                refused2 - refused1,
                (after as i64 - before as i64) / 1024,
                view % CHUNK as usize
            );
            // The one chunk with dead pages now: this one (those before it
            // moved in their rounds), moved; the fill made, but where one
            // dead page's 4 KiB is less than the fill takes with its charge
            // page's page table.
            if m2 - m1 != 1 || !(one == "made" || (one == "ENOMEM" && k == 1 && fresh)) {
                wrong.push(k);
            }
            for p in (0..CHUNK).step_by(PAGE as usize) {
                if p % (2 * PAGE) == PAGE && p < (2 * k + 1) * PAGE {
                    assert!(is_missing(chunk + p), "{k}: {p:#x} is not missing");
                } else {
                    // SAFETY: a filled page.
                    assert_eq!(unsafe { *((chunk + p + 9) as *const u8) }, 0x5a, "{k}: {p:#x}");
                }
            }
        }
        assert!(wrong.is_empty(), "the fill not made, or not one move made, for {wrong:?}");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let _ = ctx;
    }

    /// What a move gives back is its dead pages' charge, not its missing
    /// pages': a chunk whose first half was never filled (missing, no commit
    /// and no charge) and whose last page is dead, with no room left in the
    /// job ([`no_room_left`]), is moved by a fill's reclaim, the fill made
    /// with what it gave back; the pages read back as they were, and a
    /// never-filled one, touched after the move, faults to a handler thread
    /// and reads its fill (under a timeout: macOS's twin of the move read
    /// such pages under the lock their fill needs, and deadlocked).
    #[test]
    fn test_a_chunk_whose_dead_pages_lie_above_unfilled_ones_moves() {
        let (code, text) = run_child("dead_above_unfilled_child", Some(96 << 20));
        for l in text
            .lines()
            .filter(|l| l.starts_with("LIMITREC") || l.starts_with("MOVEREC") || l.starts_with("room left") || l.starts_with("wick: reclaim") || l.starts_with("filled"))
        {
            std::eprintln!("{l}");
        }
        assert!(text.contains("dead above unfilled: the fill made, 1 moves made, 0 not made"), "{text}");
        assert!(text.contains("a never-filled page read after the move faulted to the handler and read its fill"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_chunk_whose_dead_pages_lie_above_unfilled_ones_moves in a job of its own"]
    fn dead_above_unfilled_child() {
        let (ctx, user, mem, done) = fill_to_the_limit_from(CHUNK / 2);
        let last = mem + CHUNK - PAGE;
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise(last as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        let mut held = no_room_left();
        limit_step("dead above unfilled, no room left");
        {
            // Whether the fill's page has a page table already: a committed
            // page in its 2 MiB-aligned region (one page table maps 2 MiB).
            let target = mem + done;
            let region = target - target % (2 << 20);
            let mut committed = 0;
            let mut at = region;
            while at < target {
                if committed_protection(at).is_some() {
                    committed += 1;
                }
                at += PAGE;
            }
            crate::windows_mm::say_at_the_limit(format_args!(
                "LIMITREC the fill's page is {} KiB into its 2 MiB-aligned region, {committed} pages committed below it there; the range at {mem:#x}, the page at {target:#x}",
                (target - region) / 1024
            ));
            // Its charge page ([`windows_mm::charge_page_of`]): committed
            // with the fill, a page of private commit, and a page table if
            // its 2 MiB region has none.
            #[allow(clippy::cast_possible_truncation)]
            let cp = crate::windows_mm::charge_page_of(target as usize).unwrap_or(0) as u64;
            let cregion = cp - cp % (2 << 20);
            let mut in_region = 0;
            let mut at = cregion;
            while cp != 0 && at < cregion + (2 << 20) {
                if at != cp && committed_protection(at).is_some() {
                    in_region += 1;
                }
                at += PAGE;
            }
            crate::windows_mm::say_at_the_limit(format_args!(
                "LIMITREC the fill's charge page at {cp:#x}, {} KiB into its 2 MiB-aligned region, {in_region} other pages committed in that region",
                (cp - cregion) / 1024
            ));
        }
        let (m1, refused1) = (moves_on_record().0.len(), crate::windows_mm::moves_refused());
        let fill = fill_a_page(ctx, mem + done);
        limit_step("dead above unfilled, after the fill");
        moverec_line("dead above unfilled, the fill", fill);
        let (m2, refused2) = (moves_on_record().0.len(), crate::windows_mm::moves_refused());
        give_back_every_page(&mut held);
        std::println!("dead above unfilled: the fill {fill}, {} moves made, {} not made", m2 - m1, refused2 - refused1);
        for p in (0..CHUNK).step_by(PAGE as usize) {
            if p < CHUNK / 2 || mem + p == last {
                assert!(is_missing(mem + p), "{p:#x} is not missing");
            } else {
                // SAFETY: a filled page.
                assert_eq!(unsafe { *((mem + p + 9) as *const u8) }, 0x5a, "{p:#x}");
            }
        }
        // A never-filled page of the moved chunk still faults to the handler,
        // which fills it: the move neither read it (under the lock the fill
        // needs, which would hang) nor opened it (which would read a zero
        // here, with no event). Under a timeout, as the macOS twin of this
        // defect was a deadlock.
        let unfilled = mem + PAGE;
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            let _ = tx.send(unsafe { core::ptr::read_volatile((unfilled + 9) as *const u8) });
        });
        let handler = std::thread::spawn(move || serve_one(user, ctx, 0x6d));
        let read = rx.recv_timeout(std::time::Duration::from_secs(10));
        assert_eq!(read, Ok(0x6d), "a never-filled page read after the move: not filled through the handler within 10 s");
        let event = handler.join().unwrap();
        assert_eq!((event[0], event[1]), (proto::EVENT_PAGEFAULT2, unfilled + 9));
        reader.join().unwrap();
        std::println!("dead above unfilled: a never-filled page read after the move faulted to the handler and read its fill");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// An ask of a reclaimer whose thread has ended (`Ask::End`, the test's
    /// only way to end it) does not wait for good: the asker's wait is for
    /// the answer or the thread's end (`ask_the_reclaimer`), and the process
    /// is aborted with a named line.
    #[test]
    fn test_an_ask_of_a_reclaimer_that_has_ended_aborts() {
        let (code, text) = run_child("ended_reclaimer_child", None);
        assert!(text.contains("wick: reclaim: the reclaim's thread has ended"), "{text}");
        assert_eq!(code, Some(0xC000_0409_u32.cast_signed()), "not aborted: {text}");
    }

    #[test]
    #[ignore = "run by test_an_ask_of_a_reclaimer_that_has_ended_aborts in a process of its own"]
    fn ended_reclaimer_child() {
        let (ctx, _user) = create(0, false, true).unwrap();
        let mem = map(CHUNK as usize);
        register(ctx, mem, CHUNK).unwrap();
        let _lock = lock();
        let r = ask_the_reclaimer(Ask::End);
        std::println!("answered: {r:?}");
    }

    /// How deep the reclaim's thread goes (`reclaimer`, its stack painted
    /// below where it starts and committed whole, `RECLAIMER_STACK`): the
    /// most of it a fill's reclaim and a touch's used, with no room left in
    /// the job, against its committed size; and the most of a host thread's
    /// stack committed when the lazy-memory handler took its touch there
    /// (`wick_mm::host_faults_on_this_thread`), the faulting thread's own
    /// frames up to the hand-off, and how deep that path went below the
    /// touching frame (the thread's stack painted first). Printed
    /// (RECLAIMSTACK); asserted that the reclaimer's stack was committed
    /// whole at its start (`VirtualQuery`) and it used no more than a
    /// quarter of it.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture"]
    fn test_the_reclaimers_stack_on_record() {
        let (code, text) = run_child("reclaimer_stack_child", Some(96 << 20));
        for line in text.lines().filter(|l| l.starts_with("RECLAIMSTACK")) {
            std::eprintln!("{line}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_reclaimers_stack_on_record in a job of its own"]
    fn reclaimer_stack_child() {
        // The locks as the product takes them: a watch's paint below a lock
        // would count as the reclaimer's use.
        crate::windows_stacklock::WATCHING.store(false, Ordering::SeqCst);
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let page = std::vec![0x5au8; PAGE as usize];
        // SAFETY: a new anonymous mapping, committed at first touch.
        let lazy = unsafe {
            crate::mmap(ptr::null_mut(), 4 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        };
        assert_ne!(lazy, crate::MAP_FAILED);
        let mut held = no_room_left();
        let mut n = 0;
        while n < 2 << 20 {
            // SAFETY: `page` holds a page.
            match unsafe { copy(ctx, page.as_ptr(), mem + done + n, PAGE, false) } {
                Ok(k) => n += k,
                Err(_) => break,
            }
        }
        let after_fill = reclaimer_stack();
        // This thread's committed stack below here painted: how deep the
        // touch's path goes on the touching thread (the lazy-memory
        // handler, the commit, the hand-off to the reclaimer).
        let painted = paint_below_here();
        for p in (0..4usize << 20).step_by(PAGE as usize) {
            // SAFETY: our mapping; the first touch commits the page.
            unsafe { core::ptr::write_volatile((lazy as *mut u8).add(p), 1) };
        }
        let path = used_below(painted);
        let after_touch = reclaimer_stack();
        let (faults, deepest) = crate::windows_mm::wick_mm::host_faults_on_this_thread();
        give_back_every_page(&mut held);
        let (moves, _, _) = moves_on_record();
        std::println!(
            "RECLAIMSTACK {} chunks moved; the reclaimer's stack: {} bytes used by the fills' reclaims, {} by the touches' too, \
             of {} committed ({} by VirtualQuery at its start); this thread's {faults} lazy touches, their path {path} bytes \
             deep below the touching frame (of {} painted), its stack {deepest} bytes committed at the deepest",
            moves.len(),
            after_fill.0,
            after_touch.0,
            after_touch.1,
            reclaimer_stack_queried(),
            painted.1 - painted.0
        );
        assert!(reclaimer_stack_queried() >= RECLAIMER_STACK, "the reclaimer's stack was not committed whole");
        // 2 MiB filled and 4 MiB touched past the limit, each chunk giving
        // back 1 MiB: 6 moves at least (before review B3 neither was
        // asserted, and a fill refused ended the loop unsaid).
        assert!(n == 2 << 20 && moves.len() >= 6, "{} KiB filled, {} chunks moved", n >> 10, moves.len());
        assert!(after_touch.0 > 0 && after_touch.0 <= after_touch.1 / 4, "the reclaimer used {after_touch:?}");
        assert!(path < painted.1 - painted.0, "the touch's path went past the painted stack");
        let _ = ctx;
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A chunk moved by the reclaim while a host thread reads and writes
    /// its live pages, 100 rounds: the thread's writes are all kept, it
    /// never sees another value, and nothing faults for good. Each round
    /// discards the chunk's even pages, moves the chunk (its live pages
    /// copied into a new section, which both views then map: the dead
    /// pages' commit and charge given back), and fills the even pages
    /// again for the next. In a process of its own: a reclaim takes any
    /// registered chunk of the process with discarded pages, so it would
    /// move the chunks of the crate's other tests, running on other threads.
    /// The moves are made under no job limit; at one, with no room left,
    /// `test_a_fill_at_the_limit_reclaims_partly_discarded_chunks` and the
    /// others at the limit move chunks.
    #[test]
    fn test_a_moved_chunk_reads_and_writes_through() {
        let (code, text) = run_child("moved_chunk_child", None);
        assert!(text.contains("moved 100 times"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_moved_chunk_reads_and_writes_through in a process of its own"]
    fn moved_chunk_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let writer = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut round = 0u64;
                while !stop.load(Ordering::Acquire) {
                    round += 1;
                    for p in (PAGE..CHUNK).step_by(2 * PAGE as usize) {
                        let at = (mem + p + 64) as *mut u64;
                        // SAFETY: a live page of the registered range.
                        unsafe {
                            core::ptr::write_volatile(at, round ^ p);
                            assert_eq!(core::ptr::read_volatile(at), round ^ p, "a write to {p:#x} was lost");
                        }
                    }
                }
                round
            })
        };
        let mut moved = 0;
        for _ in 0..100 {
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
            let r = reclaim_at_touch(PAGE as usize);
            moved += r.chunks;
            assert_eq!(committed(mem, CHUNK), CHUNK / 2, "the moved chunk holds its live pages only");
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                assert_eq!(zeropage(ctx, mem + p, PAGE, true).unwrap(), PAGE);
            }
        }
        stop.store(true, Ordering::Release);
        let rounds = writer.join().expect("the writer failed");
        assert_eq!(moved, 100, "a reclaim did not move the chunk");
        assert!(rounds > 100, "the writer ran {rounds} rounds");
        std::println!("moved 100 times; the writer ran {rounds} rounds");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The test binary's allocator: the product's (`wick_alloc`, so that a
    /// child at a job limit ends as the VMM would), counting the allocations
    /// a thread makes while [`COUNTING_ALLOCATIONS`] is set on it
    /// (`test_a_reclaim_allocates_nothing`), and, while [`COUNTING_KINDS`]
    /// is set, those of every thread marked with a kind ([`KIND`]: the
    /// userfaultfd's serve thread, the reclaimer, a test's own thread), with
    /// where the first few were made ([`KindCount`]).
    struct Counting;

    std::thread_local! {
        pub(super) static COUNTING_ALLOCATIONS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        pub(super) static ALLOCATIONS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
        /// This thread's kind for [`COUNTING_KINDS`]: 0 none, else an index
        /// of [`KINDS`] ([`SERVE`], [`RECLAIMER`], [`CALLER`]).
        pub(super) static KIND: core::cell::Cell<u8> = const { core::cell::Cell::new(0) };
    }

    /// The userfaultfd's serve thread (marked in `serve`).
    pub(super) const SERVE: u8 = 1;
    /// The reclaim's thread (marked in `reclaimer`).
    pub(super) const RECLAIMER: u8 = 2;
    /// A test's own thread, as the VMM's thread that fills or touches.
    pub(super) const CALLER: u8 = 3;
    const KIND_NAMES: [&str; 4] = ["", "the serve thread", "the reclaimer", "the caller"];
    /// The return addresses kept of each kind's first allocations.
    const SITES: usize = 8;
    const FRAMES: usize = 20;

    /// What a kind's thread allocated while [`COUNTING_KINDS`] was set.
    struct KindCount {
        allocations: AtomicU64,
        bytes: AtomicU64,
        /// Return addresses of its first [`SITES`] allocations, made in the
        /// allocator without allocating (`RtlCaptureStackBackTrace`).
        sites: [[AtomicUsize; FRAMES]; SITES],
    }

    static COUNTING_KINDS: AtomicBool = AtomicBool::new(false);
    static KINDS: [KindCount; 4] = [const {
        KindCount { allocations: AtomicU64::new(0), bytes: AtomicU64::new(0), sites: [const { [const { AtomicUsize::new(0) }; FRAMES] }; SITES] }
    }; 4];

    /// Counts an allocation of `size` bytes for this thread's kind.
    fn count_for_the_kind(size: usize) {
        if !COUNTING_KINDS.load(Ordering::Relaxed) {
            return;
        }
        let kind = usize::from(KIND.with(core::cell::Cell::get));
        if kind == 0 {
            return;
        }
        let k = &KINDS[kind];
        let n = k.allocations.fetch_add(1, Ordering::SeqCst);
        k.bytes.fetch_add(size as u64, Ordering::SeqCst);
        if let Some(site) = k.sites.get(usize::try_from(n).unwrap_or(SITES)) {
            let mut frames = [ptr::null_mut::<c_void>(); FRAMES];
            // SAFETY: room for FRAMES addresses.
            #[allow(clippy::cast_possible_truncation)]
            let got = unsafe { windows_sys::Win32::System::Diagnostics::Debug::RtlCaptureStackBackTrace(1, FRAMES as u32, frames.as_mut_ptr(), ptr::null_mut()) };
            for (slot, f) in site.iter().zip(&frames[..usize::from(got)]) {
                slot.store(*f as usize, Ordering::Relaxed);
            }
        }
    }

    /// Starts counting the allocations of every marked thread, from zero.
    fn count_the_kinds() {
        for k in &KINDS {
            k.allocations.store(0, Ordering::SeqCst);
            k.bytes.store(0, Ordering::SeqCst);
            for site in &k.sites {
                for f in site {
                    f.store(0, Ordering::Relaxed);
                }
            }
        }
        COUNTING_KINDS.store(true, Ordering::SeqCst);
    }

    /// Stops counting: each kind's allocations and bytes.
    fn counted_kinds() -> [(u64, u64); 4] {
        COUNTING_KINDS.store(false, Ordering::SeqCst);
        core::array::from_fn(|i| (KINDS[i].allocations.load(Ordering::SeqCst), KINDS[i].bytes.load(Ordering::SeqCst)))
    }

    /// ALLOCS: what `what` allocated on each kind's thread, and the return
    /// addresses of the first allocations, as offsets in this executable
    /// for a debugger to name (`cdb -z <exe>`, `ln`). Without allocating.
    fn say_the_allocations(what: &str, counts: &[(u64, u64); 4]) {
        unsafe extern "C" {
            static __ImageBase: u8;
        }
        let base = core::ptr::addr_of!(__ImageBase) as usize;
        for (kind, &(n, bytes)) in counts.iter().enumerate().skip(1) {
            crate::windows_mm::say_at_the_limit(format_args!("ALLOCS {what}: {} {n} allocations, {bytes} bytes", KIND_NAMES[kind]));
            for (i, site) in KINDS[kind].sites.iter().enumerate().take(usize::try_from(n).unwrap_or(SITES)) {
                for (j, f) in site.iter().enumerate() {
                    let a = f.load(Ordering::Relaxed);
                    if a == 0 {
                        break;
                    }
                    if a >= base && a - base < 64 << 20 {
                        crate::windows_mm::say_at_the_limit(format_args!("ALLOCSITE {} {i} {j} image+{:#x}", KIND_NAMES[kind], a - base));
                    } else {
                        crate::windows_mm::say_at_the_limit(format_args!("ALLOCSITE {} {i} {j} {a:#x}", KIND_NAMES[kind]));
                    }
                }
            }
        }
    }

    // SAFETY: the calls of wick's heap allocator (`wick_alloc`, the
    // product's), as they are; the counts are thread-local cells and
    // atomics, which allocate nothing.
    unsafe impl std::alloc::GlobalAlloc for Counting {
        unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
            if COUNTING_ALLOCATIONS.with(core::cell::Cell::get) {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
            count_for_the_kind(layout.size());
            // SAFETY: the caller's contract.
            unsafe { crate::wick_alloc::Allocator.alloc_zeroed(layout) }
        }
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            if COUNTING_ALLOCATIONS.with(core::cell::Cell::get) {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
            count_for_the_kind(layout.size());
            // SAFETY: the caller's contract.
            unsafe { crate::wick_alloc::Allocator.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
            // SAFETY: the caller's contract.
            unsafe { crate::wick_alloc::Allocator.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
            if COUNTING_ALLOCATIONS.with(core::cell::Cell::get) {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
            count_for_the_kind(new_size);
            // SAFETY: the caller's contract.
            unsafe { crate::wick_alloc::Allocator.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Counting = Counting;

    /// The allocations `f` makes on this thread, and its result.
    fn allocations_of<T>(f: impl FnOnce() -> T) -> (u64, T) {
        ALLOCATIONS.with(|a| a.set(0));
        COUNTING_ALLOCATIONS.with(|c| c.set(true));
        let r = f();
        COUNTING_ALLOCATIONS.with(|c| c.set(false));
        (ALLOCATIONS.with(core::cell::Cell::get), r)
    }

    /// HEAPEND: a heap allocation the job's limit refuses, with nothing to
    /// reclaim (no range registered), ends the process with 137 and a line
    /// naming the size and what the reclaim gave back (`wick_alloc`), for
    /// each of the allocator's calls: an allocation (`Vec::with_capacity`),
    /// a zeroed one (`vec![0; n]`) and a reallocation (`reserve_exact`).
    /// Without the wrapper Rust's allocation error ends it with 0xC0000409.
    /// In a process of its own, under a job limit, with the product's
    /// allocator as the test binary's ([`Counting`]).
    #[test]
    fn test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line() {
        let mut failed = std::vec::Vec::new();
        for (child, kind) in [("heap_end_alloc_child", "an allocation"), ("heap_end_zeroed_child", "a zeroed allocation"), ("heap_end_realloc_child", "a reallocation")] {
            let (code, text) = run_child(child, Some(96 << 20));
            for l in text.lines().filter(|l| l.starts_with("wick:") || l.starts_with("HEAP") || l.contains("memory allocation")) {
                std::eprintln!("{child}: {l}");
            }
            let line = std::format!("wick: heap: {kind} of 1048576 bytes");
            let read = text.contains("HEAPEND the host's commit limit read at the job's limit: Some(");
            if code != Some(137) || !text.contains(&line) || !text.contains("the reclaim gave back 0 bytes") || !read {
                failed.push(std::format!("{child}: exit {code:x?}, the line {}, the commit limit read {read}", text.contains(&line)));
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    /// [`test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line`]'s
    /// three children: no room left, then the allocation. Each first reads
    /// the host's commit limit as the refusal does (`wick_alloc`), with the
    /// job's limit reached: the read does not fail there.
    fn heap_end(kind: &str) {
        watchdog(60);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let mut small: std::vec::Vec<u8> = std::vec::Vec::with_capacity(16);
        small.push(1);
        let held = no_room_left();
        let total = crate::wick_alloc::host_commit_limit();
        crate::windows_mm::say_at_the_limit(format_args!("HEAPEND the host's commit limit read at the job's limit: {total:?}"));
        let v: std::vec::Vec<u8> = match kind {
            "zeroed" => std::vec![0u8; 1 << 20],
            "realloc" => {
                small.reserve_exact((1 << 20) - small.len());
                small
            }
            _ => std::vec::Vec::with_capacity(1 << 20),
        };
        crate::windows_mm::say_at_the_limit(format_args!("HEAPEND {kind}: the allocation was made ({} bytes)", v.capacity()));
        core::hint::black_box((v, held));
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line in a job of its own"]
    fn heap_end_alloc_child() {
        heap_end("alloc");
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line in a job of its own"]
    fn heap_end_zeroed_child() {
        heap_end("zeroed");
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line in a job of its own"]
    fn heap_end_realloc_child() {
        heap_end("realloc");
    }

    /// HEAPABOVE: a heap allocation of more than the host can commit at all
    /// (its commit limit, `wick_alloc::host_commit_limit`, and 1 GiB) is
    /// refused as the system's allocator refuses it, as Linux's malloc is
    /// above RAM and swap (v6.1 mm/util.c :1002 to :1006): a `try_reserve`
    /// outside wick's guard answers its error and the process lives, in a
    /// job and in none; an infallible allocation ends with Rust's
    /// allocation error (0xC0000409, "memory allocation of N bytes
    /// failed"); neither says a line of wick's. On 6ef1c85e both ended with
    /// 137 and a line that blamed the memory limit. The same in a job whose
    /// limit is above the host's commit limit (2 GiB above), where the host,
    /// not the job, cannot hold the size.
    ///
    /// Best-effort live: the commit limit (`ullTotalPageFile`) is not static —
    /// a system-managed pagefile auto-grows it (measured on the CI WHP runner,
    /// where host+1 GiB committed; on fc-win/fc-win25's fixed pagefile it does
    /// not) — so when a run finds the size committed (the limit grew to hold
    /// it), the child says "band-1 not exercised live" and the row passes
    /// without the refusal. The band-1 LOGIC is proven deterministically by
    /// `windows_alloc::tests::test_band_decision`; what every row still proves
    /// is that no size above the host yields a 137 line ("wick: heap"), and
    /// that the job did not lower the commit limit the child reads.
    #[test]
    fn test_a_heap_allocation_above_the_hosts_commit_limit_is_refused_as_the_systems() {
        let mut failed = std::vec::Vec::new();
        let abort = Some(0xC000_0409u32.cast_signed());
        let total = crate::wick_alloc::host_commit_limit().expect("the host's commit limit");
        let above = total + (2 << 30);
        for (child, limit, want_code, want) in [
            ("heap_above_reserve_child", Some(96 << 20), Some(0), "HEAPABOVE try_reserve: Err"),
            ("heap_above_reserve_child", None, Some(0), "HEAPABOVE try_reserve: Err"),
            ("heap_above_alloc_child", Some(96 << 20), abort, "memory allocation of "),
            ("heap_above_reserve_child", Some(above), Some(0), "HEAPABOVE try_reserve: Err"),
            ("heap_above_alloc_child", Some(above), abort, "memory allocation of "),
        ] {
            let (code, text) = run_child(child, limit);
            for l in text.lines().filter(|l| l.starts_with("wick:") || l.starts_with("HEAP") || l.contains("memory allocation")) {
                std::eprintln!("{child} (job {limit:?}): {l}");
            }
            // The child's own reading of the host's commit limit, in the job.
            let child_total = text
                .lines()
                .find_map(|l| l.strip_prefix("HEAPABOVE the host's commit limit read in the job: "))
                .and_then(|n| n.trim().parse::<usize>().ok());
            // The job did not lower it: a job's memory limit (96 MiB below the
            // host here, or host+2 GiB above) does not change the commit limit
            // the child reads, which would otherwise drop toward the job's. A
            // system-managed pagefile may raise it between the parent's read
            // and the child's, so this allows growth (>=) and catches only a
            // lowering (to within 9/10 of the parent's reading).
            let not_lowered = child_total.is_some_and(|c| c * 10 >= total * 9);
            // Band 1 reached live (the system refused: the reserve's Err or the
            // alloc's 0xC0000409), or skipped because the commit limit grew to
            // hold the size this run (best-effort; the band-1 logic is proven
            // deterministically by `windows_alloc::tests::test_band_decision`).
            // Never a 137 line ("wick: heap"): that is the regression this test
            // guards (6ef1c85e blamed the memory limit for a size above the
            // host).
            let skipped = text.contains("band-1 not exercised live");
            let outcome = if skipped { code == Some(0) } else { code == want_code && text.contains(want) };
            if !outcome || text.contains("wick: heap") || !not_lowered {
                failed.push(std::format!(
                    "{child} (job {limit:?}): exit {code:x?}, skipped {skipped}, said {}, child_total {child_total:?} vs {total} not_lowered {not_lowered}",
                    text.contains(want)
                ));
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    /// [`test_a_heap_allocation_above_the_hosts_commit_limit_is_refused_as_the_systems`]'s
    /// size: the host's commit limit, as read in the job, and 1 GiB. The
    /// read is said, for the parent to check it against its own, out of a
    /// job.
    fn above_the_host() -> usize {
        let total = crate::wick_alloc::host_commit_limit().expect("the host's commit limit");
        crate::windows_mm::say_at_the_limit(format_args!("HEAPABOVE the host's commit limit read in the job: {total}"));
        total + (1 << 30)
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_above_the_hosts_commit_limit_is_refused_as_the_systems"]
    fn heap_above_reserve_child() {
        watchdog(60);
        // In the job before asking (the parent assigns it after the spawn).
        std::thread::sleep(std::time::Duration::from_millis(300));
        let size = above_the_host();
        let mut v: std::vec::Vec<u8> = std::vec::Vec::new();
        let r = v.try_reserve_exact(size);
        if r.is_err() {
            crate::windows_mm::say_at_the_limit(format_args!("HEAPABOVE try_reserve: Err ({size} bytes)"));
            return;
        }
        // The reservation was committed: band 1 is reached only when the
        // system refuses, and the commit limit (`ullTotalPageFile`) is not
        // static — a system-managed pagefile auto-grows it, so it can rise past
        // the size between the read and the reserve (measured on the CI WHP
        // runner, where it does; the band-1 LOGIC is proven deterministically
        // by `windows_alloc::tests::test_band_decision`). Re-read it: grown to
        // hold the size, this run did not exercise band 1, skipped with a
        // notice. If it did not grow, a reservation above the commit limit
        // succeeding is a real fault.
        let now = crate::wick_alloc::host_commit_limit();
        assert!(
            now.is_some_and(|t| t >= size),
            "a try_reserve of {size} above the commit limit succeeded and the limit did not grow (now {now:?})"
        );
        crate::windows_mm::say_at_the_limit(format_args!(
            "HEAPABOVE try_reserve: Ok, the host commit limit grew to {} >= {size}; band-1 not exercised live \
             (system-managed pagefile)",
            now.unwrap()
        ));
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_above_the_hosts_commit_limit_is_refused_as_the_systems"]
    fn heap_above_alloc_child() {
        watchdog(60);
        // In the job before asking (the parent assigns it after the spawn).
        std::thread::sleep(std::time::Duration::from_millis(300));
        let size = above_the_host();
        // An infallible allocation: band 1 ends it with Rust's allocation
        // error (0xC0000409) before this returns. If it returns, the host
        // committed the size — the commit limit grew past it (the reserve
        // child's note; band 1 not exercised this run), reported as a skip so
        // the parent passes rather than expecting the abort.
        let v: std::vec::Vec<u8> = std::vec::Vec::with_capacity(size);
        crate::windows_mm::say_at_the_limit(format_args!(
            "HEAPABOVE the allocation of {size} bytes was made ({} bytes); band-1 not exercised live \
             (system-managed pagefile)",
            v.capacity()
        ));
        core::hint::black_box(v);
    }

    /// HEAPPAST: a heap allocation of more than the job's limit holds in
    /// all (200 MiB in a job of 96 MiB), but not more than the host can
    /// commit, ends with 137 and a line saying so and what Linux does
    /// there, with no reclaim: Linux's malloc gives it (mm/util.c :1002 to
    /// :1006 ask RAM and swap, not the memory cgroup) and the cgroup kills
    /// the VMM at the touch of the page past the limit (mm/memory.c :4117);
    /// Windows commits it at the allocation. The same for a `try_reserve`
    /// outside wick's guard (std's `read_to_end` with a large size hint).
    /// On 6ef1c85e both ended with 137 and the line of a limit reached
    /// ("the reclaim gave back 0 bytes").
    #[test]
    fn test_a_heap_allocation_more_than_the_job_limit_holds_ends_with_137_and_says_so() {
        let mut failed = std::vec::Vec::new();
        for child in ["heap_past_alloc_child", "heap_past_reserve_child"] {
            let (code, text) = run_child(child, Some(96 << 20));
            for l in text.lines().filter(|l| l.starts_with("wick:") || l.starts_with("HEAP") || l.contains("memory allocation")) {
                std::eprintln!("{child}: {l}");
            }
            let line = "of 209715200 bytes (from 0) is more than the memory limit of 100663296 bytes (the jail's memory.max) holds in all, so no reclaim ran";
            if code != Some(137) || !text.contains(line) || !text.contains("at the touch of the page past the limit") {
                failed.push(std::format!("{child}: exit {code:x?}, the line {}", text.contains(line)));
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_more_than_the_job_limit_holds_ends_with_137_and_says_so"]
    fn heap_past_alloc_child() {
        watchdog(60);
        // In the job before asking (the parent assigns it after the spawn).
        std::thread::sleep(std::time::Duration::from_millis(300));
        let v: std::vec::Vec<u8> = std::vec::Vec::with_capacity(200 << 20);
        crate::windows_mm::say_at_the_limit(format_args!("HEAPPAST the allocation was made ({} bytes)", v.capacity()));
        core::hint::black_box(v);
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_more_than_the_job_limit_holds_ends_with_137_and_says_so"]
    fn heap_past_reserve_child() {
        watchdog(60);
        // In the job before asking (the parent assigns it after the spawn).
        std::thread::sleep(std::time::Duration::from_millis(300));
        let mut v: std::vec::Vec<u8> = std::vec::Vec::new();
        let r = v.try_reserve_exact(200 << 20);
        crate::windows_mm::say_at_the_limit(format_args!("HEAPPAST try_reserve: {}", if r.is_err() { "Err" } else { "Ok" }));
        core::hint::black_box(v);
    }

    /// HEAPRECLAIM: a heap allocation the job's limit refuses where the
    /// reclaim has dead pages to give back (the reclaim tests' start: 8
    /// chunks half dead) is made once the reclaim ran, and the process goes
    /// on, as Linux's memory cgroup charges again after a reclaim that freed
    /// pages (v6.1 mm/memcontrol.c :2705 to :2706). Without the wrapper it
    /// ends with 0xC0000409.
    #[test]
    fn test_a_heap_allocation_refused_at_the_limit_is_made_after_the_reclaim() {
        let (code, text) = run_child("heap_reclaim_child", Some(96 << 20));
        for l in text.lines().filter(|l| l.starts_with("wick:") || l.starts_with("HEAP") || l.contains("memory allocation")) {
            std::eprintln!("{l}");
        }
        assert!(text.contains("HEAPRECLAIM the allocation was made"), "{code:x?} {text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_refused_at_the_limit_is_made_after_the_reclaim in a job of its own"]
    fn heap_reclaim_child() {
        watchdog(60);
        let (_ctx, user, _mem, _) = fill_to_the_limit_and_discard_in_part();
        let mut held = no_room_left();
        let moved = MOVES_MADE.load(Ordering::Relaxed);
        let v: std::vec::Vec<u8> = std::vec![0x77u8; 1 << 20];
        let moved = MOVES_MADE.load(Ordering::Relaxed) - moved;
        crate::windows_mm::say_at_the_limit(format_args!(
            "HEAPRECLAIM the allocation was made ({} bytes, {moved} chunks moved for it)",
            v.len()
        ));
        assert!(moved > 0, "no chunk moved: the allocation was not refused");
        drop(v);
        give_back_every_page(&mut held);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// HEAPGUARD: wick's own fallible sites still answer `ENOMEM` under the
    /// wrapper (`wick_alloc::fallible`): a register at the job's limit
    /// whose record's bitmaps (1.5 MiB for 16 GiB) cannot be had is
    /// `ENOMEM`, and the process lives. The same without the wrapper; with
    /// it and no guard, the process ended with 137 (the commit says where).
    #[test]
    fn test_a_guarded_fallible_site_answers_enomem_at_the_limit() {
        let (code, text) = run_child("heap_guard_child", Some(96 << 20));
        for l in text.lines().filter(|l| l.starts_with("wick:") || l.starts_with("HEAP")) {
            std::eprintln!("{l}");
        }
        assert!(text.contains("HEAPGUARD the register at the limit: ENOMEM"), "{code:x?} {text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_guarded_fallible_site_answers_enomem_at_the_limit in a job of its own"]
    fn heap_guard_child() {
        watchdog(60);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (a, ua) = create(0, false, true).unwrap();
        let len = 16u64 << 30;
        let mem = map_noreserve(len as usize);
        let mut held = no_room_left();
        let r = register(a, mem, len);
        let errno = r.as_ref().err().and_then(io::Error::raw_os_error);
        crate::windows_mm::say_at_the_limit(format_args!(
            "HEAPGUARD the register at the limit: {}",
            if errno == Some(crate::ENOMEM) { "ENOMEM" } else if r.is_ok() { "made" } else { "another error" }
        ));
        give_back_every_page(&mut held);
        assert_eq!(errno, Some(crate::ENOMEM), "{r:?}");
        release(a, ua);
        assert_eq!(munmap_of(mem, len), 0);
    }

    /// HEAPNORECLAIM: a heap allocation refused at the job's limit on a
    /// thread that holds a lock of wick's memory layer (the released-page
    /// records'), as if in the exception handler, or as if on the
    /// reclaim's own thread, ends with 137 and a line naming why no reclaim
    /// ran, with no wait: the reclaim takes those locks and that thread. With
    /// registered dead pages, so that a reclaim would have work to do. A
    /// watchdog ends a child that hangs (exit 3).
    #[test]
    fn test_a_heap_allocation_refused_where_no_reclaim_may_run_ends_with_137() {
        let mut failed = std::vec::Vec::new();
        for (child, why) in [
            ("heap_under_a_lock_child", "with a lock of wick's memory layer held"),
            ("heap_in_the_handler_child", "in the exception handler"),
            ("heap_on_the_reclaimer_child", "on the reclaim's own thread"),
        ] {
            let (code, text) = run_child(child, Some(96 << 20));
            for l in text.lines().filter(|l| l.starts_with("wick:") || l.starts_with("HEAP") || l.starts_with("WATCHDOG") || l.contains("memory allocation")) {
                std::eprintln!("{child}: {l}");
            }
            if code != Some(137) || !text.contains(why) || !text.contains("so no reclaim ran") {
                failed.push(std::format!("{child}: exit {code:x?}, the reason said {}", text.contains(why)));
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    /// The three children of
    /// [`test_a_heap_allocation_refused_where_no_reclaim_may_run_ends_with_137`].
    fn heap_where_no_reclaim(how: &str) {
        watchdog(60);
        let (_ctx, _user, _mem, _) = fill_to_the_limit_and_discard_in_part();
        let held = no_room_left();
        let make = || std::vec![0x77u8; 1 << 20];
        let v = match how {
            "lock" => crate::windows_mm::with_released_held(make),
            "handler" => crate::windows_mm::as_if_in_the_handler(make),
            _ => {
                ON_THE_RECLAIMER.set(true);
                make()
            }
        };
        crate::windows_mm::say_at_the_limit(format_args!("HEAPNORECLAIM {how}: the allocation was made ({} bytes)", v.len()));
        core::hint::black_box((v, held));
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_refused_where_no_reclaim_may_run_ends_with_137 in a job of its own"]
    fn heap_under_a_lock_child() {
        heap_where_no_reclaim("lock");
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_refused_where_no_reclaim_may_run_ends_with_137 in a job of its own"]
    fn heap_in_the_handler_child() {
        heap_where_no_reclaim("handler");
    }

    #[test]
    #[ignore = "run by test_a_heap_allocation_refused_where_no_reclaim_may_run_ends_with_137 in a job of its own"]
    fn heap_on_the_reclaimer_child() {
        heap_where_no_reclaim("reclaimer");
    }

    /// A reclaim allocates nothing: it runs when the job has refused commit,
    /// where a heap that must grow would end the process instead (Linux's
    /// reclaim takes no memory on that path either). A fill's reclaim, and
    /// a touch's that passes over a chunk with a call in its copy on it and
    /// then waits for that call (held 200 ms by another thread), each move
    /// their chunks with no allocation on the reclaiming thread. In a
    /// process of its own (a reclaim takes any chunk of the process).
    /// Its moves are made under no job limit (the reclaimer's asks are the
    /// same at one).
    #[test]
    fn test_a_reclaim_allocates_nothing() {
        let (code, text) = run_child("reclaim_allocations_child", None);
        assert!(text.contains("allocations: touch 0, fill 0"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_reclaim_allocates_nothing in a process of its own"]
    fn reclaim_allocations_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 3 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        let discard_even = |chunk: u64| {
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((mem + chunk * CHUNK + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
        };
        discard_even(0);
        discard_even(1);
        // A call in its copy on the first chunk, for 200 ms.
        let held = std::sync::Arc::new(AtomicBool::new(false));
        let caller = {
            let held = held.clone();
            std::thread::spawn(move || {
                #[allow(clippy::cast_possible_truncation)]
                let call = crate::windows_mm::copying(mem as usize, PAGE as usize);
                call.copy_now();
                held.store(true, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(200));
                drop(call);
            })
        };
        while !held.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        let (touch, r) = allocations_of(|| reclaim_at_touch(PAGE as usize));
        caller.join().unwrap();
        assert_eq!(r.chunks, 2, "the touch's reclaim moved {r:?}");
        discard_even(2);
        let (fill, r) = allocations_of(|| {
            let _lock = lock();
            reclaim_for_a_fill(PAGE as usize, &mut Default::default())
        });
        assert_eq!(r.chunks, 1, "the fill's reclaim moved {r:?}");
        std::println!("allocations: touch {touch}, fill {fill}");
        assert_eq!((touch, fill), (0, 0));
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The userfaultfd released at the job's limit allocates nothing: its
    /// serve thread, from the close of the user end through `destroy`
    /// (the missing pages made ordinary memory: lazy where never filled,
    /// zeroed at their next access where discarded, the alias given up),
    /// runs where a heap that must grow is refused, and where ntdll's heap
    /// code took a stack page the job refused (STACK137FRAMES: `destroy`
    /// growing a list of the missing runs, `RtlReAllocateHeap`); Linux's
    /// release of a userfaultfd needs no memory: it clears each vma's flags
    /// in place, a merge with the vma before (which may allocate) only tried
    /// (v6.1 fs/userfaultfd.c `userfaultfd_release`, 885-899). In a job of
    /// its own, with no room left ([`no_room_left`]).
    #[test]
    fn test_a_userfaultfd_released_at_the_limit_allocates_nothing() {
        let (code, text) = run_child("release_allocations_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        assert!(text.contains("ALLOCS the release at the limit: the serve thread 0 allocations"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_userfaultfd_released_at_the_limit_allocates_nothing and test_what_the_limit_paths_allocate_on_record in a job of their own"]
    fn release_allocations_child() {
        let (ctx, user, _mem, _done) = fill_to_the_limit_and_discard_in_part();
        let held = no_room_left();
        count_the_kinds();
        // SAFETY: closes the user end: the serve thread releases the
        // userfaultfd and ends.
        unsafe { ws::closesocket(sock(user)) };
        // `destroy` gives up the kernel end last. A bound for a failure only.
        let t = std::time::Instant::now();
        while CTXS[ctx].fd.load(Ordering::SeqCst) >= 0 {
            assert!(t.elapsed() < std::time::Duration::from_secs(60), "the userfaultfd was not released");
            std::thread::yield_now();
        }
        let counts = counted_kinds();
        say_the_allocations("the release at the limit", &counts);
        drop(held);
    }

    /// ALLOCS, on record: what the paths that run after the job's limit
    /// refused allocate, on each thread they run on: a fill refused and
    /// reclaimed for, then refused with `ENOMEM` (the caller's `copy` and
    /// the reclaimer); a first touch of lazy memory refused and reclaimed
    /// for (the touching thread, in the exception handler, and the
    /// reclaimer); the userfaultfd's release (its serve thread). With the
    /// first allocations' return addresses (ALLOCSITE), for a debugger to
    /// name. Each in a job of its own with no room left; a child that ends
    /// at the limit (a heap or a stack refused) is on record with its end.
    #[test]
    #[ignore = "a record: ALLOCS"]
    fn test_what_the_limit_paths_allocate_on_record() {
        for child in ["fill_allocations_child", "touch_allocations_child", "release_allocations_child"] {
            let (code, text) = run_child(child, Some(96 << 20));
            // Every line of the child's, its end included: a path that
            // allocates at the limit may end the process there.
            for line in text.lines() {
                std::println!("{child}: {line}");
            }
            std::println!("{child}: exit {code:?}");
            assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        }
    }

    /// A fill at the job's limit allocates nothing: fills of a page each,
    /// from no room left, refused, reclaimed for and made, until one is
    /// refused (`ENOMEM` in these tests, [`REFUSED_FILL_IS_ENOMEM`]),
    /// allocate nothing on the filling thread, the
    /// serve thread or the reclaimer, where a heap that must grow is refused
    /// there; Linux's fill takes only the page it fills and the page tables
    /// it needs (v6.1 mm/userfaultfd.c: `mcopy_atomic_pte`'s
    /// `alloc_page_vma`, 156, charged by `mem_cgroup_charge`, 205;
    /// `mm_alloc_pmd`'s `pmd_alloc`, 317, and `__pte_alloc`, 643, in
    /// `__mcopy_atomic`). In a job of its own, with no room left
    /// ([`no_room_left`]).
    #[test]
    fn test_a_fill_at_the_limit_allocates_nothing() {
        let (code, text) = run_child("fill_allocations_child", Some(96 << 20));
        assert!(text.contains("room left before the reclaim: 0 KiB"), "{text}");
        for kind in ["the serve thread", "the reclaimer", "the caller"] {
            assert!(text.contains(&std::format!("ALLOCS fills at the limit: {kind} 0 allocations")), "{text}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_at_the_limit_allocates_nothing and test_what_the_limit_paths_allocate_on_record in a job of their own"]
    fn fill_allocations_child() {
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let page = std::vec![0x5au8; PAGE as usize];
        let held = no_room_left();
        KIND.with(|k| k.set(CALLER));
        count_the_kinds();
        let (mut n, mut refused) = (0, None);
        while n < 16 << 20 {
            // SAFETY: `page` holds a page.
            match unsafe { copy(ctx, page.as_ptr(), mem + done + n, PAGE, false) } {
                Ok(k) => n += k,
                Err((e, _)) => {
                    refused = Some(e);
                    break;
                }
            }
        }
        let counts = counted_kinds();
        KIND.with(|k| k.set(0));
        say_the_allocations("fills at the limit", &counts);
        crate::windows_mm::say_at_the_limit(format_args!("filled {} KiB, then {:?}", n >> 10, refused));
        assert_eq!(refused, Some(crate::ENOMEM));
        drop(held);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    #[test]
    #[ignore = "run by test_what_the_limit_paths_allocate_on_record in a job of its own"]
    fn touch_allocations_child() {
        let (_ctx, user, _mem, _) = fill_to_the_limit_and_discard_in_part();
        // SAFETY: a new anonymous mapping, committed at first touch.
        let lazy = unsafe {
            crate::mmap(
                ptr::null_mut(),
                16 << 20,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, crate::MAP_FAILED);
        let held = no_room_left();
        KIND.with(|k| k.set(CALLER));
        count_the_kinds();
        for p in (0..4usize << 20).step_by(PAGE as usize) {
            // SAFETY: our mapping; the first touch commits the page.
            unsafe { core::ptr::write_volatile((lazy as *mut u8).add(p), 1) };
        }
        let counts = counted_kinds();
        KIND.with(|k| k.set(0));
        say_the_allocations("touches at the limit", &counts);
        drop(held);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Closes the user end of `ctx` and waits until its serve thread has
    /// released it (`destroy` gives up the kernel end last). A bound for a
    /// failure only.
    fn release(ctx: usize, user: c_int) {
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
        let t = std::time::Instant::now();
        while CTXS[ctx].fd.load(Ordering::SeqCst) >= 0 {
            assert!(t.elapsed() < std::time::Duration::from_secs(60), "the userfaultfd was not released");
            std::thread::yield_now();
        }
    }

    /// A range of four pages registered, its page 0 filled, page 1 filled
    /// and discarded, pages 2 and 3 never filled: released, so that page 1
    /// is a discarded page to zero at its first access and pages 2 and 3
    /// are lazy. Its address.
    fn released_with_pending_pages(fill: u8) -> u64 {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map(4 * PAGE as usize);
        register(ctx, mem, 4 * PAGE).unwrap();
        let data = std::vec![fill; 2 * PAGE as usize];
        // SAFETY: `data` holds two pages.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, 2 * PAGE, true) }.unwrap(), 2 * PAGE);
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise((mem + PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        release(ctx, user);
        mem
    }

    /// A page discarded while registered reads zeros once its userfaultfd is
    /// released, all of it, at every read, and takes a write; a page never
    /// filled reads zeros and takes a write; a filled page keeps its data;
    /// as Linux's released range, whose zapped and never-faulted pages are
    /// anonymous memory's zero-filled pages (a control for the released
    /// ranges' records, docs/ARCHITECTURE.md, "Released userfaultfd ranges").
    #[test]
    fn test_a_stale_page_read_after_release_reads_zeros() {
        let mem = released_with_pending_pages(0x5a);
        // SAFETY: our mapping, released: ordinary memory.
        unsafe {
            for _ in 0..2 {
                assert!(std::slice::from_raw_parts((mem + PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "the discarded page");
                assert!(std::slice::from_raw_parts((mem + 2 * PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "a page never filled");
            }
            assert_eq!(*((mem + 9) as *const u8), 0x5a, "the filled page");
            *((mem + PAGE + 9) as *mut u8) = 7;
            *((mem + 3 * PAGE + 9) as *mut u8) = 8;
            assert_eq!((*((mem + PAGE + 9) as *const u8), *((mem + 3 * PAGE + 9) as *const u8)), (7, 8));
        }
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
    }

    /// A fixed mapping over a released range while a first access resolves
    /// its discarded page waits for the resolve: the view stays until the
    /// page is zeroed and given its protection (the resolve holds the
    /// records' lock from its check that the page is committed, and a view
    /// leaves the records before it goes), so the resolve's protection
    /// change cannot be refused for a view gone under it, which left the
    /// page charged, zeroed and still pending; the new mapping reads zeros,
    /// as Linux's fault and `mmap` serialise on the mm's lock. The resolve
    /// is parked after zeroing the page, for the mapping to come while it
    /// is (`windows_mm::resolve_pause_arm`). In a process of its own (the
    /// park is the process's).
    #[test]
    fn test_a_fixed_mapping_over_a_page_being_resolved_waits_for_it() {
        let (code, text) = run_child("resolve_under_a_fixed_mapping_child", None);
        assert!(text.contains("RESOLVE the view while parked: committed"), "{text}");
        assert!(text.contains("RESOLVE access: Committed"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fixed_mapping_over_a_page_being_resolved_waits_for_it in a process of its own"]
    fn resolve_under_a_fixed_mapping_child() {
        let mem = released_with_pending_pages(0x5a);
        let page = (mem + PAGE) as usize;
        crate::windows_mm::resolve_pause_arm();
        let resolver = std::thread::spawn(move || crate::windows_mm::wick_mm::commit_on_access(page, false));
        let t = std::time::Instant::now();
        while !crate::windows_mm::resolve_parked() {
            assert!(t.elapsed() < std::time::Duration::from_secs(10), "the resolve did not park");
            std::thread::yield_now();
        }
        let mapper = std::thread::spawn(move || {
            // SAFETY: a fixed anonymous mapping over our released range.
            let p = unsafe {
                crate::mmap(
                    mem as *mut c_void,
                    4 * PAGE as usize,
                    crate::PROT_READ | crate::PROT_WRITE,
                    crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED,
                    -1,
                    0,
                )
            };
            p as u64
        });
        // The mapping's time to unmap the view, were it not to wait.
        std::thread::sleep(std::time::Duration::from_millis(300));
        // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
        let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe { windows_sys::Win32::System::Memory::VirtualQuery(page as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) };
        let view = if mbi.State == windows_sys::Win32::System::Memory::MEM_COMMIT { "committed" } else { "gone" };
        std::println!("RESOLVE the view while parked: {view} (state {:#x})", mbi.State);
        crate::windows_mm::resolve_go();
        let access = resolver.join().unwrap();
        std::println!("RESOLVE access: {access:?}");
        assert_eq!(mapper.join().unwrap(), mem, "the fixed mapping");
        // SAFETY: the new mapping, ours.
        assert!(unsafe { std::slice::from_raw_parts(page as *const u8, PAGE as usize) }.iter().all(|&b| b == 0));
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
    }

    /// A poisoned lock on the path of a first access (here the released
    /// ranges' records', poisoned by a thread that panicked holding it) ends
    /// the process with a line naming it and an abort (0xC0000409), never a
    /// panic inside the exception's dispatch: the access is resolved in the
    /// vectored handler, which cannot unwind. A bug's end, named. In a
    /// process of its own.
    #[test]
    fn test_a_poisoned_lock_on_the_access_path_aborts_named() {
        let (code, text) = run_child("poisoned_access_child", None);
        assert!(text.contains("wick: the lock RELEASED was poisoned"), "{text}");
        assert!(!text.contains("reached the page"), "{text}");
        assert_eq!(code, Some(0xC000_0409_u32.cast_signed()), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_poisoned_lock_on_the_access_path_aborts_named in a process of its own"]
    fn poisoned_access_child() {
        let mem = released_with_pending_pages(0x5a);
        crate::windows_mm::poison_released();
        // SAFETY: our mapping, released: its discarded page is resolved at
        // this first read.
        let b = unsafe { core::ptr::read_volatile((mem + PAGE) as *const u8) };
        std::println!("reached the page: {b}");
    }

    /// Two threads touching one page of a released range at once, each
    /// writing at its own offset, both keep their writes: the page is
    /// resolved once (a discarded page zeroed once, a page never filled
    /// committed once), as Linux faults a page in once under its page table
    /// lock. For the discarded page and for a page never filled, 200 rounds
    /// each (a control for the released ranges' records).
    #[test]
    fn test_a_page_touched_by_two_threads_after_release_keeps_both_writes() {
        for round in 0..200u32 {
            let mem = released_with_pending_pages(0x5a);
            for page in [1u64, 2] {
                let at = mem + page * PAGE;
                let go = std::sync::Arc::new(std::sync::Barrier::new(2));
                let threads: std::vec::Vec<_> = [(0u64, 0x11u8), (8, 0x22)]
                    .into_iter()
                    .map(|(off, v)| {
                        let go = go.clone();
                        std::thread::spawn(move || {
                            go.wait();
                            // SAFETY: our mapping, released.
                            unsafe { core::ptr::write_volatile((at + off) as *mut u8, v) };
                        })
                    })
                    .collect();
                for t in threads {
                    t.join().expect("a toucher failed");
                }
                // SAFETY: as above.
                let got = unsafe { (*(at as *const u8), *((at + 8) as *const u8)) };
                assert_eq!(got, (0x11, 0x22), "round {round}, page {page}: a write was lost");
            }
            // SAFETY: our mapping.
            assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
        }
    }

    /// An unregister of part of a range leaves that part's discarded and
    /// never-filled pages as released ones (zeros at their first access,
    /// then ordinary memory) and the rest registered: its missing pages
    /// still missing and filled through the userfaultfd (a control for the
    /// released ranges' records).
    #[test]
    fn test_a_partial_unregister_keeps_its_pages_pending() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 12 * PAGE;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; 8 * PAGE as usize];
        // SAFETY: `data` holds eight pages.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, 8 * PAGE, true) }.unwrap(), 8 * PAGE);
        for page in [2u64, 5] {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + page * PAGE) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        // Pages 4 to 9: 4 filled, 5 discarded, 6 and 7 filled, 8 and 9 never filled.
        unregister(ctx, mem + 4 * PAGE, 6 * PAGE).unwrap();
        // SAFETY: the unregistered part: ordinary memory.
        unsafe {
            assert_eq!(*((mem + 4 * PAGE) as *const u8), 0x5a);
            assert!(std::slice::from_raw_parts((mem + 5 * PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "the discarded page");
            assert!(std::slice::from_raw_parts((mem + 8 * PAGE) as *const u8, PAGE as usize).iter().all(|&b| b == 0), "a page never filled");
            *((mem + 9 * PAGE) as *mut u8) = 3;
            assert_eq!(*((mem + 9 * PAGE) as *const u8), 3);
        }
        // The rest is still registered: page 2 and pages 10 and 11 missing.
        assert!(is_missing(mem + 2 * PAGE) && is_missing(mem + 10 * PAGE) && is_missing(mem + 11 * PAGE));
        assert!(!is_missing(mem + 5 * PAGE) && !is_missing(mem + 8 * PAGE));
        let seven = std::vec![7u8; PAGE as usize];
        // SAFETY: a page-sized buffer.
        assert_eq!(unsafe { copy(ctx, seven.as_ptr(), mem + 10 * PAGE, PAGE, true) }.unwrap(), PAGE);
        // SAFETY: a filled page.
        assert_eq!(unsafe { *((mem + 10 * PAGE + 9) as *const u8) }, 7);
        release(ctx, user);
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(mem as *mut c_void, len as usize) }, 0);
    }

    /// Ranges registered and released while other threads touch the pending
    /// pages of those released before: records freed and taken again under
    /// touching threads (docs/ARCHITECTURE.md, "Released userfaultfd ranges":
    /// the readers).
    /// One thread makes 200 ranges of 4 pages (`released_with_pending_pages`,
    /// filled with the round's byte) and unmaps the one of two rounds
    /// before; four threads touch the pending pages of the ranges still
    /// mapped, each its own pages, and check that a page reads zeros before
    /// their write and their write after it; the filled pages keep their
    /// round's byte. In a process of its own (the slots and records are
    /// the process's).
    #[test]
    fn test_released_records_reused_under_touching_threads() {
        let (code, text) = run_child("released_reuse_child", None);
        assert!(text.contains("REUSE 200 rounds"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_released_records_reused_under_touching_threads in a process of its own"]
    fn released_reuse_child() {
        // The ranges still mapped: (address, round), and whether the maker is done.
        let mapped = std::sync::Arc::new(std::sync::RwLock::new(std::vec::Vec::<(u64, u8)>::new()));
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let touchers: std::vec::Vec<_> = (0..4u64)
            .map(|me| {
                let (mapped, done) = (mapped.clone(), done.clone());
                std::thread::spawn(move || {
                    let mut touched = std::collections::BTreeSet::new();
                    while !done.load(Ordering::SeqCst) {
                        let ranges = mapped.read().unwrap();
                        for &(mem, round) in ranges.iter() {
                            // Pages 1 to 3 are pending; each toucher writes
                            // its own byte of them, at offset 64 * me.
                            for page in 1..4u64 {
                                let at = mem + page * PAGE + 64 * me;
                                // SAFETY: a mapped page of a released range.
                                unsafe {
                                    // By range too: a new range may be mapped where an old one was.
                                    if touched.insert((at, round)) {
                                        assert_eq!(core::ptr::read_volatile(at as *const u8), 0, "a pending page was not zeros");
                                        core::ptr::write_volatile(at as *mut u8, round);
                                    }
                                    assert_eq!(core::ptr::read_volatile(at as *const u8), round, "a write was lost");
                                }
                            }
                        }
                        drop(ranges);
                        std::thread::yield_now();
                    }
                })
            })
            .collect();
        for round in 0..200u32 {
            #[allow(clippy::cast_possible_truncation)]
            let fill = (round % 250 + 1) as u8;
            let mem = released_with_pending_pages(fill);
            let mut ranges = mapped.write().unwrap();
            ranges.push((mem, fill));
            if ranges.len() > 2 {
                let (old, old_fill) = ranges.remove(0);
                // SAFETY: a filled page of ours.
                assert_eq!(unsafe { *(old as *const u8) }, old_fill, "a filled page changed");
                // SAFETY: our mapping, which no toucher reads now.
                assert_eq!(unsafe { crate::munmap(old as *mut c_void, 4 * PAGE as usize) }, 0);
            }
        }
        done.store(true, Ordering::SeqCst);
        for t in touchers {
            t.join().expect("a toucher failed");
        }
        std::println!("REUSE 200 rounds");
    }

    /// The released ranges' records are as many as the slots, one taken at
    /// each register and held until the registration is released and its
    /// memory unmapped (docs/ARCHITECTURE.md, "Released userfaultfd ranges"):
    /// with 64 ranges released
    /// and still mapped, a 65th register is refused with `ENOMEM` and
    /// changes nothing, as Linux refuses a register whose vma
    /// split would pass `vm.max_map_count` (mm/mmap.c `split_vma`); their
    /// pages read as before. In a process of its own.
    #[test]
    fn test_released_records_past_the_table_refuse_a_register() {
        let (code, text) = run_child("released_table_child", None);
        assert!(text.contains("TABLE the 65th register: ENOMEM"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    /// A record is freed when the last of its released range is unmapped:
    /// with the table full, an unmap of half of one released range (its
    /// discarded page) keeps the record, and the register is still refused;
    /// an unmap of the rest frees it, and the register is made. In a process
    /// of its own.
    #[test]
    fn test_release_then_munmap_frees_the_record() {
        let (code, text) = run_child("released_table_child", None);
        assert!(text.contains("TABLE after half unmapped: ENOMEM"), "{text}");
        assert!(text.contains("TABLE after the rest unmapped: registered"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_released_records_past_the_table_refuse_a_register and test_release_then_munmap_frees_the_record in a process of its own"]
    fn released_table_child() {
        let held: std::vec::Vec<u64> = (0..MAX_RANGES).map(|_| released_with_pending_pages(0x5a)).collect();
        let try_one = |what: &str| {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map(4 * PAGE as usize);
            let r = register(ctx, mem, 4 * PAGE);
            let said = match &r {
                Ok(()) => "registered".into(),
                Err(e) if e.raw_os_error() == Some(crate::ENOMEM) => "ENOMEM".into(),
                Err(e) => std::format!("{e}"),
            };
            std::println!("TABLE {what}: {said}");
            release(ctx, user);
            // SAFETY: our mapping.
            assert_eq!(unsafe { crate::munmap(mem as *mut c_void, 4 * PAGE as usize) }, 0);
        };
        try_one("the 65th register");
        // Nothing changed: each range's pages read as they did.
        for &mem in &held[1..] {
            // SAFETY: our mappings, released.
            unsafe {
                assert_eq!(*((mem + 9) as *const u8), 0x5a);
                assert_eq!(*((mem + PAGE + 9) as *const u8), 0);
            }
        }
        // SAFETY: our mapping: pages 0 and 1 (the discarded one) of the first.
        assert_eq!(unsafe { crate::munmap(held[0] as *mut c_void, 2 * PAGE as usize) }, 0);
        try_one("after half unmapped");
        // SAFETY: the rest of it.
        assert_eq!(unsafe { crate::munmap((held[0] + 2 * PAGE) as *mut c_void, 2 * PAGE as usize) }, 0);
        try_one("after the rest unmapped");
    }

    /// The jailer's count of this process (overlay/jailer/platform/windows
    /// commit.rs): private commit plus section commit less the committed,
    /// private, `PAGE_NOACCESS` memory that pays for sections (the cover),
    /// no more than the section commit.
    fn jailers_count() -> u64 {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, VirtualQuery};
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_faults: u32,
            sizes: [usize; 10],
            shared_commit: u64,
        }
        use windows_sys::Win32::System::ProcessStatus::K32GetProcessMemoryInfo;
        let mut c = Counters { cb: u32::try_from(std::mem::size_of::<Counters>()).unwrap(), ..Counters::default() };
        // SAFETY: this process's pseudo handle and a structure of the size
        // given (PROCESS_MEMORY_COUNTERS_EX2, which begins as the type the
        // binding names).
        assert_ne!(unsafe { K32GetProcessMemoryInfo(windows_sys::Win32::System::Threading::GetCurrentProcess(), (&raw mut c).cast(), c.cb) }, 0);
        let (private, shared) = (c.sizes[8] as u64, c.shared_commit);
        let (mut at, mut cover) = (0usize, 0u64);
        loop {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { VirtualQuery(at as *const c_void, &mut m, std::mem::size_of_val(&m)) } == 0 {
                break;
            }
            if m.State == MEM_COMMIT && m.Type == MEM_PRIVATE && m.Protect == PAGE_NOACCESS {
                cover += m.RegionSize as u64;
            }
            match (m.BaseAddress as usize).checked_add(m.RegionSize) {
                Some(next) if next > at => at = next,
                _ => break,
            }
        }
        private + shared - cover.min(shared)
    }

    /// The jailer's count taken in the middle of a move
    /// (`windows_mm::MOVE_HOOK`, between the copy and the swap).
    static DURING: AtomicU64 = AtomicU64::new(u64::MAX);

    fn count_during_the_move() {
        DURING.store(jailers_count(), Ordering::SeqCst);
    }

    /// While a chunk is moved both sections hold its live pages; the move
    /// budget, committed private `PAGE_NOACCESS` memory made at the first
    /// registration (`windows_mm::uffd_budget`), is cover for them, so the
    /// jailer's count, taken in the middle of the move, is no higher than
    /// before it, and a VMM at its limit is not ended for a reclaim. Without
    /// the budget block (decommitted for the test) the same move raises the
    /// count by its live pages: the budget is what holds it.
    /// With no room left in the job at each move ([`no_room_left`]): the
    /// count during the move is below what it was before by no more than 64
    /// KiB, against the 1 MiB of dead pages the chunk holds (it never counts
    /// a chunk's dead pages as gone before they are; a move gives none of
    /// their charge back before it is made, since review B3, where it gave
    /// back 12 KiB before its maps). The count needs `PROCESS_MEMORY_COUNTERS_EX2`'s
    /// `SharedCommitUsage` (Windows 10 or 11 22H2 with the September 2023
    /// update and later): on a host without it the jailer refuses
    /// memory.max (`test_a_memory_limit_on_this_host`), and the child says
    /// so and fails, naming the build and where the test runs.
    #[test]
    fn test_the_jailers_count_does_not_rise_during_a_move() {
        let (code, text) = run_child("move_count_child", Some(256 << 20));
        assert!(text.contains("with the budget: "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_jailers_count_does_not_rise_during_a_move in a process of its own"]
    fn move_count_child() {
        {
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE, SEC_COMMIT};
            let before = jailers_count();
            // SAFETY: a new pagefile-backed section of 1 MiB, closed below.
            let s = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, ptr::null(), PAGE_READWRITE | SEC_COMMIT, 0, 1 << 20, ptr::null()) };
            assert!(!s.is_null());
            let with = jailers_count();
            // SAFETY: ours.
            unsafe { CloseHandle(s) };
            if with < before + (1 << 20) {
                use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
                use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
                // SAFETY: an all-zero OSVERSIONINFOW with its size is valid.
                let mut vi: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
                vi.dwOSVersionInfoSize = u32::try_from(std::mem::size_of::<OSVERSIONINFOW>()).unwrap();
                // SAFETY: plain call.
                unsafe { RtlGetVersion(&mut vi) };
                panic!(
                    "not a regression: this host, Windows {}.{}.{}, cannot run this test: its SharedCommitUsage does not \
                     move with a section (a 1 MiB section moved the count from {before} to {with}). \
                     PROCESS_MEMORY_COUNTERS_EX2's SharedCommitUsage is in Windows 10 and 11 22H2 with the September 2023 \
                     update and later (Learn); measured in CI's Windows Server 2025 (26100) and the PC's Windows 11, absent \
                     in Windows Server 2022 (20348, fc-win). Here the jailer refuses memory.max, named \
                     (test_a_memory_limit_on_this_host), so its count during a move cannot be read; this test runs in CI \
                     and on the PC",
                    vi.dwMajorVersion,
                    vi.dwMinorVersion,
                    vi.dwBuildNumber
                );
            }
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        crate::windows_mm::set_move_hook(Some(count_during_the_move));
        let moved = |budget: bool| -> (u64, u64) {
            assert!(crate::windows_mm::uffd_budget_for_tests(budget), "no move budget was made");
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                // SAFETY: registered memory of ours.
                assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            }
            DURING.store(u64::MAX, Ordering::SeqCst);
            let mut held = no_room_left();
            let before = jailers_count();
            let r = reclaim_at_touch(PAGE as usize);
            let during = DURING.load(Ordering::SeqCst);
            give_back_every_page(&mut held);
            assert_eq!(r.chunks, 1, "no chunk was moved");
            assert_ne!(during, u64::MAX, "the move's hook did not run");
            for p in (0..CHUNK).step_by(2 * PAGE as usize) {
                assert_eq!(zeropage(ctx, mem + p, PAGE, true).unwrap(), PAGE);
            }
            (before, during)
        };
        let (before, during) = moved(true);
        std::println!("with the budget: {before} before the move, {during} during it");
        assert!(during <= before + (64 << 10), "the count rose by {} KiB during a move", (during - before) >> 10);
        assert!(during + (64 << 10) >= before, "the count fell by {} KiB during a move, before the dead pages went", (before - during) >> 10);
        let (before, during) = moved(false);
        std::println!("without it: {before} before the move, {during} during it");
        assert!(during >= before + (512 << 10), "without the budget the count rose by {} KiB only", during.saturating_sub(before) >> 10);
        assert!(crate::windows_mm::uffd_budget_for_tests(true));
        crate::windows_mm::set_move_hook(None);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// RECLAIMREC: the reclaim's cost at the job's limit (it runs only
    /// there). In a child under a job limit of 96 MiB: the range filled to
    /// the limit and every other page of its first 8 chunks discarded
    /// ([`fill_to_the_limit_and_discard_in_part`]), then 8 MiB filled a
    /// page at a time while a host thread reads the 8 chunks' live pages:
    /// the chunks moved, the live pages each copied and its microseconds
    /// (least, median, greatest), the reader's accesses that waited for a
    /// move and their time, and the job's commit (the process's private
    /// commit) and section commit before and after. Printed; asserted only
    /// that the fill went on.
    #[test]
    #[ignore = "a record: run alone on Windows with --ignored --nocapture (CI's WHP step)"]
    fn test_the_reclaims_cost_on_record() {
        let (code, text) = run_child("reclaim_record_child", Some(96 << 20));
        for line in text.lines().filter(|l| l.starts_with("RECLAIMREC")) {
            std::println!("{line}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_the_reclaims_cost_on_record in a job of its own"]
    fn reclaim_record_child() {
        use windows_sys::Win32::System::ProcessStatus::K32GetProcessMemoryInfo;
        // The locks as the product takes them: the watch's paint is no
        // part of the reclaim's time.
        crate::windows_stacklock::WATCHING.store(false, Ordering::SeqCst);
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_faults: u32,
            sizes: [usize; 10],
            shared_commit: u64,
        }
        let counts = || {
            let mut c = Counters { cb: u32::try_from(std::mem::size_of::<Counters>()).unwrap(), ..Counters::default() };
            // SAFETY: this process's pseudo handle and a structure of the
            // size given (PROCESS_MEMORY_COUNTERS_EX2).
            unsafe { K32GetProcessMemoryInfo(windows_sys::Win32::System::Threading::GetCurrentProcess(), (&raw mut c).cast(), c.cb) };
            (c.sizes[8] >> 10, c.shared_commit >> 10)
        };
        let (ctx, user, mem, done) = fill_to_the_limit_and_discard_in_part();
        let before = counts();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        // The reader started and its stack grown before the room is taken,
        // waited for: a thread still starting at the limit is refused its
        // own stack page (CI run 43947438431, the stack-wait tests).
        let grown = std::sync::Arc::new(AtomicBool::new(false));
        let reader = {
            let stop = stop.clone();
            let grown = grown.clone();
            std::thread::spawn(move || {
                core::hint::black_box(deep(16));
                grown.store(true, Ordering::SeqCst);
                let mut reads = 0u64;
                while !stop.load(Ordering::Acquire) {
                    for p in (PAGE..8 * CHUNK).step_by(2 * PAGE as usize) {
                        // SAFETY: a live page of the registered range.
                        assert_eq!(unsafe { core::ptr::read_volatile((mem + p) as *const u8) }, 0x5a);
                        reads += 1;
                    }
                }
                reads
            })
        };
        let page = std::vec![0x5au8; PAGE as usize];
        wait_for(&grown, "the reader's stack grown");
        let held = no_room_left();
        let mut more = 0;
        while more < 8 << 20 {
            // SAFETY: `page` holds a page.
            match unsafe { copy(ctx, page.as_ptr(), mem + done + more, PAGE, false) } {
                Ok(n) => more += n,
                Err(_) => break,
            }
        }
        stop.store(true, Ordering::Release);
        let reads = reader.join().unwrap();
        drop(held);
        let after = counts();
        let (moves, waits, waited) = moves_on_record();
        let mut us: Vec<u64> = moves.iter().map(|m| m.1).collect();
        us.sort_unstable();
        let copied: usize = moves.iter().map(|m| m.0).sum();
        std::println!(
            "RECLAIMREC {} chunks moved, {copied} live pages copied, {} us a chunk least, {} median, {} greatest",
            moves.len(),
            us.first().copied().unwrap_or(0),
            us.get(us.len() / 2).copied().unwrap_or(0),
            us.last().copied().unwrap_or(0)
        );
        std::println!("RECLAIMREC filled {} KiB past the limit; the reader's {reads} reads, {waits} of which waited for a move, {waited} us in all", more >> 10);
        std::println!(
            "RECLAIMREC private commit {} KiB before, {} KiB after; section commit {} KiB before, {} KiB after",
            before.0, after.0, before.1, after.1
        );
        // 8 chunks with 1 MiB of dead pages each: the fill of up to 8 MiB
        // past the limit moves every one (8172 KiB filled on record, the
        // rest the fills' own page tables); before review B3 only the 4 MiB
        // was asserted, which half the moves refused would have passed.
        assert!(more >= 4 << 20 && moves.len() == 8, "{} KiB filled past the limit, {} chunks moved", more >> 10, moves.len());
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    #[test]
    fn test_prefault_before_system_calls() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        let handler = std::thread::spawn(move || serve_one(user, ctx, 0x11));
        // A read into missing pages: the pages are faulted in first.
        let path = std::env::temp_dir().join(std::format!("wick-uffd-read-{}", std::process::id()));
        std::fs::write(&path, [0x22u8; 16]).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let fd = crate::windows_fd::to_fd_pub(std::os::windows::io::AsRawHandle::as_raw_handle(&f));
        // SAFETY: a valid descriptor and registered memory.
        let n = unsafe { crate::read(fd, (mem + 8) as *mut c_void, 16) };
        assert_eq!(n, 16);
        assert_eq!(handler.join().unwrap()[0], proto::EVENT_PAGEFAULT2);
        // SAFETY: filled and read into.
        unsafe {
            assert_eq!(*(mem as *const u8), 0x11);
            assert_eq!(*((mem + 8) as *const u8), 0x22);
        }
        drop(f);
        let _ = std::fs::remove_file(&path);
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A discard (`MADV_DONTNEED`) of a read's buffer, made by another
    /// thread after the read faulted the buffer in and before its system
    /// call, waits for the read, as Linux's read completes into a page its
    /// copy faults in again (mm/userfaultfd.c `handle_userfault`): a
    /// regular file's read, whose call cannot block for ever, is counted in
    /// flight on its range, and the discard waits for it. The window is
    /// [`crate::windows_fd::BEFORE_CALL`]: it starts the discard and gives it
    /// 50 ms. Asserted: the discard is still waiting at the window's end, the
    /// read returns its 16 bytes, and the discard then leaves the pages
    /// missing again.
    #[test]
    fn test_a_discard_waits_for_a_read_in_flight_on_its_range() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        let handler = std::thread::spawn(move || serve_one(user, ctx, 0x11));
        let path = std::env::temp_dir().join(std::format!("wick-uffd-inflight-{}", std::process::id()));
        std::fs::write(&path, [0x22u8; 16]).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let fd = crate::windows_fd::to_fd_pub(std::os::windows::io::AsRawHandle::as_raw_handle(&f));
        let (go, went) = mpsc::channel::<()>();
        let done = Arc::new(AtomicBool::new(false));
        let ended = done.clone();
        let discarder = std::thread::spawn(move || {
            went.recv().unwrap();
            // SAFETY: the test's registered mapping.
            let r = unsafe { crate::madvise(mem as *mut c_void, len, crate::MADV_DONTNEED) };
            ended.store(true, Ordering::Release);
            r
        });
        let held = Arc::new(AtomicBool::new(false));
        let seen = held.clone();
        crate::windows_fd::BEFORE_CALL.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                go.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(50));
                seen.store(!done.load(Ordering::Acquire), Ordering::Release);
            }));
        });
        // SAFETY: a valid descriptor and registered memory.
        let n = unsafe { crate::read(fd, (mem + 8) as *mut c_void, 16) };
        let error = std::io::Error::last_os_error();
        crate::windows_fd::BEFORE_CALL.with(|h| *h.borrow_mut() = None);
        let discarded = discarder.join().unwrap();
        let held = held.load(Ordering::Acquire);
        std::println!(
            "INFLIGHT a file's read with a discard of its buffer started in its window: {n} ({error}); \
             the discard waiting at the window's end: {held}; the discard: {discarded}"
        );
        assert_eq!(handler.join().unwrap()[0], proto::EVENT_PAGEFAULT2);
        assert!(held, "the discard did not wait for the read in flight");
        assert_eq!(n, 16, "the read failed: {error}");
        assert_eq!(discarded, 0);
        assert!(is_missing(mem + 8), "the discard did not happen");
        drop(f);
        let _ = std::fs::remove_file(&path);
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A read that can block for ever (a blocking pipe's) is not counted in
    /// flight, so that a discard never waits on it, and reads through a
    /// buffer of its own, copied into the caller's afterwards as a guest
    /// access is made, so that a discard of the caller's buffer meanwhile
    /// cannot fail it, as Linux's copy faults the page in again. The
    /// window ([`crate::windows_fd::BEFORE_CALL`]) starts the discard and
    /// waits until it is done, at most 2 s; the pipe's writer writes 100 ms
    /// later. Asserted: the discard ended in the window, and the read returns
    /// the writer's 16 bytes, which the buffer then holds (its page faulted
    /// in before the call, discarded, faulted in again at the copy, filled,
    /// and written over: two faults served).
    #[test]
    fn test_a_blocking_read_does_not_hold_a_discard() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        let handler = std::thread::spawn(move || [serve_one(user, ctx, 0x11), serve_one(user, ctx, 0x11)]);
        let mut fds = [0 as c_int; 2];
        // SAFETY: two descriptors' room.
        assert_eq!(unsafe { crate::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        let (go, went) = mpsc::channel::<()>();
        let (done, discarded) = mpsc::channel::<c_int>();
        std::thread::spawn(move || {
            went.recv().unwrap();
            // SAFETY: the test's registered mapping.
            let r = unsafe { crate::madvise(mem as *mut c_void, len, crate::MADV_DONTNEED) };
            let _ = done.send(r);
        });
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let data = [0x33u8; 16];
            // SAFETY: the pipe's write end and a buffer of 16 bytes.
            unsafe { crate::write(wr, data.as_ptr().cast(), 16) }
        });
        let in_window = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen = in_window.clone();
        crate::windows_fd::BEFORE_CALL.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                go.send(()).unwrap();
                *seen.lock().unwrap() = Some(discarded.recv_timeout(Duration::from_secs(2)).ok());
            }));
        });
        // SAFETY: the pipe's read end and registered memory.
        let n = unsafe { crate::read(rd, (mem + 8) as *mut c_void, 16) };
        let error = std::io::Error::last_os_error();
        crate::windows_fd::BEFORE_CALL.with(|h| *h.borrow_mut() = None);
        let window = *in_window.lock().unwrap();
        std::println!("INFLIGHT a blocking pipe's read with a discard of its buffer in its window: {n} ({error}); the discard in the window: {window:?}");
        assert_eq!(writer.join().unwrap(), 16);
        assert_eq!(window, Some(Some(0)), "the discard was held by a read that can block");
        assert_eq!(n, 16, "the read failed: {error}");
        let events = handler.join().unwrap();
        assert_eq!([events[0][0], events[1][0]], [proto::EVENT_PAGEFAULT2; 2]);
        // SAFETY: read into, after the fill.
        unsafe {
            assert_eq!(*((mem + 8) as *const u8), 0x33);
            assert_eq!(*(mem as *const u8), 0x11, "the page was not filled again");
        }
        // SAFETY: the pipe's ends; closes the user end.
        unsafe {
            crate::close(rd);
            crate::close(wr);
            ws::closesocket(sock(user));
        }
    }

    /// Two registrations side by side, of two userfaultfds (as two tests'
    /// mappings, or two of Firecracker's, can be): a run of missing pages
    /// goes on across the boundary, but nothing is reported past the span
    /// asked for, and a discard of one range never touches the other or
    /// tells the other's userfaultfd.
    #[test]
    fn test_adjacent_ranges_stay_apart() {
        let len = 64 * 1024usize;
        let ulen = len as u64;
        // SAFETY: a reservation, then two mappings over it, as Firecracker maps guest memory.
        let base = unsafe {
            crate::mmap(ptr::null_mut(), 2 * len, crate::PROT_NONE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(base, crate::MAP_FAILED);
        let (a, b) = (base as u64, base as u64 + ulen);
        for m in [a, b] {
            // SAFETY: over our reservation.
            let p = unsafe {
                crate::mmap(
                    m as *mut c_void,
                    len,
                    crate::PROT_READ | crate::PROT_WRITE,
                    crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED,
                    -1,
                    0,
                )
            };
            assert_eq!(p as u64, m);
        }
        let (ca, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let (cb, ub) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        register(ca, a, ulen).unwrap();
        register(cb, b, ulen).unwrap();

        // All pages of both are missing: one run across the boundary, as the
        // CI failure of test_host_fault_copy_zeropage saw it (28 pages from
        // its range's 12 and a neighbour's 16) ...
        let mut runs = Vec::new();
        for_each_missing(PAGE, u64::MAX / 2, |s, l| runs.push((s, l)));
        assert!(runs.iter().any(|&(s, l)| s <= a && s + l >= b + ulen), "{runs:x?}");
        // ... but never past the span asked for.
        let mut runs = Vec::new();
        for_each_missing(a, ulen, |s, l| runs.push((s, l)));
        assert_eq!(runs, [(a, ulen)]);
        let mut runs = Vec::new();
        for_each_missing(b + PAGE, PAGE, |s, l| runs.push((s, l)));
        assert_eq!(runs, [(b + PAGE, PAGE)]);

        // B's first page filled, with content.
        let five = std::vec![5u8; PAGE as usize];
        // SAFETY: a page-sized buffer into B's missing first page.
        assert_eq!(unsafe { copy(cb, five.as_ptr(), b, PAGE, true) }.unwrap(), PAGE);
        // A discard of A alone: A's event only; B's page is still there.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise(a as *mut c_void, len, crate::MADV_DONTNEED) }, 0);
        let mut buf = [0u8; proto::RECORD];
        assert!(recv_all(ua, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, a, b]);
        assert!(!is_missing(b));
        // SAFETY: B's present page.
        assert_eq!(unsafe { *(b as *const u8) }, 5);
        // B's first event is its own discard, not A's.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::madvise(b as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert!(recv_all(ub, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, b, b + PAGE]);
        // A discard of both: each userfaultfd hears of its own range only.
        // SAFETY: our mappings.
        assert_eq!(unsafe { crate::madvise(a as *mut c_void, 2 * len, crate::MADV_DONTNEED) }, 0);
        assert!(recv_all(ua, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, a, b]);
        assert!(recv_all(ub, &mut buf));
        assert_eq!(words(&buf)[..3], [proto::EVENT_REMOVE, b, b + ulen]);

        unregister(ca, a, ulen).unwrap();
        unregister(cb, b, ulen).unwrap();
        // SAFETY: closes the user ends; our mappings.
        unsafe {
            ws::closesocket(sock(ua));
            ws::closesocket(sock(ub));
            crate::munmap(base, 2 * len);
        }
    }

    #[test]
    fn test_register_errors() {
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map(64 * 1024);
        assert_eq!(register(ctx, mem + 1, PAGE).unwrap_err().raw_os_error(), Some(crate::EINVAL));
        // Part of a mapping registers, as Linux's
        // (`test_part_of_a_mapping_is_registered`), and the whole of it after
        // that with the same userfaultfd; the same range registered again
        // with the same userfaultfd is a success that changes nothing, as
        // Linux's (v6.12 mm/userfaultfd.c `userfaultfd_register_range` :1848
        // to :1853).
        register(ctx, mem, PAGE).unwrap();
        register(ctx, mem, 64 * 1024).unwrap();
        register(ctx, mem, 64 * 1024).unwrap();
        // A wake checks the range only (fs/userfaultfd.c, v6.1,
        // `userfaultfd_wake` :1673 to :1700, `validate_range` :1247 to
        // :1265): memory in no registration is woken as any.
        assert_eq!(wake_range(ctx, mem + 64 * 1024, PAGE), Ok(()));
        assert_eq!(wake_range(ctx, mem + 1, PAGE), Err(crate::EINVAL));
        assert_eq!(wake_range(ctx, mem, 0), Err(crate::EINVAL));
        assert_eq!(wake_range(ctx, 0, PAGE), Err(crate::EINVAL));
        // A register checks the range as Linux's (`validate_range` at
        // :1309), then finds the first mapping at or above its start
        // (`userfaultfd_register` :1323 to :1330): none, `ENOMEM`; one at
        // or past its end, `EINVAL`.
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        // SAFETY: an all-zero SYSTEM_INFO is valid; filled by the call.
        let mut si: SYSTEM_INFO = unsafe { core::mem::zeroed() };
        // SAFETY: as above.
        unsafe { GetSystemInfo(&mut si) };
        let task_size = si.lpMaximumApplicationAddress as u64 + 1;
        assert_eq!(register(ctx, task_size, PAGE).unwrap_err().raw_os_error(), Some(crate::EINVAL), "past the process's addresses");
        assert_eq!(register(ctx, task_size - PAGE, 2 * PAGE).unwrap_err().raw_os_error(), Some(crate::EINVAL), "across its end");
        // The last 64 KiB of the process's addresses, if nothing is mapped
        // there (nothing above).
        let top = task_size - (64 << 10);
        if states(top, 64 << 10).iter().all(|&(state, _)| state == windows_sys::Win32::System::Memory::MEM_FREE) {
            assert_eq!(register(ctx, top, 64 << 10).unwrap_err().raw_os_error(), Some(crate::ENOMEM), "nothing mapped at or above");
        } else {
            std::println!("the last 64 KiB of the process's addresses are mapped: the ENOMEM case not run");
        }
        // Free addresses with a mapping above them (the process's modules
        // lie above its mappings): the first mapping past the range's end.
        let free = map(64 << 10);
        assert_eq!(munmap_of(free, 64 << 10), 0);
        assert!(states(free, PAGE).iter().all(|&(state, _)| state == windows_sys::Win32::System::Memory::MEM_FREE), "{:x?}", states(free, PAGE));
        assert_eq!(register(ctx, free, PAGE).unwrap_err().raw_os_error(), Some(crate::EINVAL), "free addresses below a mapping");
        // SAFETY: as above.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// Set by the hooks of the two tests below and their threads.
    static HELD: AtomicBool = AtomicBool::new(false);
    static RELEASED: AtomicBool = AtomicBool::new(false);
    static READ_NOW: AtomicBool = AtomicBool::new(false);

    /// Waits, for up to 20 s, until `flag` is set.
    fn wait_for(flag: &AtomicBool, what: &str) {
        let t = std::time::Instant::now();
        while !flag.load(Ordering::SeqCst) {
            assert!(t.elapsed() < std::time::Duration::from_secs(20), "{what} did not happen");
            std::thread::yield_now();
        }
    }

    /// [`EXCEPTION_HOOK`]'s: says the handler is held and holds it until
    /// the test releases it.
    fn hold_the_handler() {
        HELD.store(true, Ordering::SeqCst);
        wait_for(&RELEASED, "the release of the handler");
    }

    /// A host thread's access that faulted on a missing page whose fill
    /// ends before the exception handler looks at the page (the thread
    /// preempted between the fault and the handler, or the handler slow):
    /// the access runs again and reads the fill, as Linux's fault, which
    /// finds the page present, returns and the access runs again. Before
    /// the fix the handler, finding the page not missing, passed the
    /// exception on and the process ended with an access violation. In a
    /// process of its own (the hook holds every access violation's
    /// handler).
    #[test]
    fn test_a_host_access_that_faulted_before_its_fill_runs_again() {
        let (code, text) = run_child("late_handler_fill_child", None);
        assert!(text.contains("read back 0xab"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_host_access_that_faulted_before_its_fill_runs_again in a process of its own"]
    fn late_handler_fill_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        assert!(is_missing(mem + PAGE));
        EXCEPTION_HOOK.store(hold_the_handler as fn() as usize, Ordering::SeqCst);
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read faults, and its handler
            // is held until the page is filled.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        wait_for(&HELD, "the reader's fault");
        let data = std::vec![0xabu8; PAGE as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + PAGE, PAGE, true) }.unwrap(), PAGE);
        assert!(!is_missing(mem + PAGE));
        RELEASED.store(true, Ordering::SeqCst);
        let got = reader.join().expect("the reader failed");
        EXCEPTION_HOOK.store(0, Ordering::SeqCst);
        std::println!("read back {got:#x}");
        assert_eq!(got, 0xab);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The look a vCPU's memory access exit takes last
    /// (`windows_mm::settled_access`, the run loop's step after the commit
    /// and `fault`), with the page changed between the looks, as another
    /// thread changes it while the vCPU thread is between them: a fill after
    /// the commit's look leaves `fault` nothing and the page Allowed (the
    /// access runs again); a discard after `fault`'s look makes it
    /// Resolvable (asked of the commit and the userfaultfd again, never
    /// `EFAULT`); a page the host refuses is Refused: a filled page made
    /// `PROT_READ` to a write (KVM: `EFAULT`) and Allowed to a read, a
    /// missing page `PROT_NONE` asked, lazy memory made `PROT_READ` to a
    /// write (and Resolvable to a read, not committed yet), unmapped memory;
    /// a released range's pending page is Resolvable. In a process of its
    /// own.
    #[test]
    fn test_a_page_changed_between_a_vcpus_looks_is_settled_as_it_is_now() {
        let (code, text) = run_child("settled_looks_child", None);
        std::eprintln!("{}", text.lines().filter(|l| l.starts_with("SETTLED") || l.contains("panicked")).collect::<std::vec::Vec<_>>().join("\n"));
        assert!(text.contains("SETTLED done"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_page_changed_between_a_vcpus_looks_is_settled_as_it_is_now in a process of its own"]
    fn settled_looks_child() {
        use crate::windows_mm::{settled_access as settled, Access, Settled};
        // The settled look, and `with_pages_still`'s `allowed` for the same
        // page (kvm-ioctls whp/settle.rs's look): yes for Allowed alone.
        let look = |what: &str, at: u64, write: bool, want: Settled| {
            #[allow(clippy::cast_possible_truncation)]
            let at = at as usize;
            let got = settled(at, write);
            let still = crate::windows_mm::with_pages_still(|allowed| allowed(at, write));
            std::println!("SETTLED {what}: {got:?}, allowed while still {still}");
            assert_eq!(got, want, "{what}");
            assert_eq!(still, want == Settled::Allowed, "{what}: with_pages_still's allowed");
        };
        let commit = |at: u64, write: bool| crate::windows_mm::wick_mm::commit_on_access(at as usize, write);
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        let data = std::vec![0x5au8; PAGE as usize];
        let page = mem + PAGE;
        // A fill between the commit's look and fault()'s.
        assert_eq!(commit(page, true), Access::NotLazy);
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), page, PAGE, true) }.unwrap(), PAGE);
        assert!(!fault(page, true), "a filled page is not fault()'s");
        look("filled after the commit's look", page, true, Settled::Allowed);
        // A discard between fault()'s look and the settled one.
        assert!(!fault(page, true));
        // SAFETY: registered memory of ours.
        assert_eq!(unsafe { crate::madvise(page as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert!(is_missing(page));
        look("discarded after fault()'s look", page, true, Settled::Resolvable);
        // Filled again and made PROT_READ: a write refused, a read allowed.
        // SAFETY: as above.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), page, PAGE, true) }.unwrap(), PAGE);
        // SAFETY: as above.
        assert_eq!(unsafe { crate::mprotect(page as *mut c_void, PAGE as usize, crate::PROT_READ) }, 0);
        assert!(!fault(page, true));
        look("a filled page PROT_READ, written", page, true, Settled::Refused);
        look("the same page, read", page, false, Settled::Allowed);
        // A missing page PROT_NONE asked: no userfault, refused.
        let none = mem + 3 * PAGE;
        // SAFETY: as above.
        assert_eq!(unsafe { crate::mprotect(none as *mut c_void, PAGE as usize, crate::PROT_NONE) }, 0);
        assert!(is_missing(none) && !fault(none, false));
        look("a missing page PROT_NONE, read", none, false, Settled::Refused);
        // A released range's pending page: resolvable.
        let pending = mem + 5 * PAGE;
        unregister(ctx, mem + 4 * PAGE, 4 * PAGE).unwrap();
        assert!(!fault(pending, true));
        look("a released range's pending page, written", pending, true, Settled::Resolvable);
        // Lazy memory made PROT_READ: a write refused, a read resolvable.
        // SAFETY: a new anonymous mapping, committed at first touch.
        let lazy = unsafe {
            crate::mmap(ptr::null_mut(), 1 << 20, crate::PROT_READ | crate::PROT_WRITE, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_NORESERVE, -1, 0)
        } as u64;
        // SAFETY: as above.
        assert_eq!(unsafe { crate::mprotect(lazy as *mut c_void, 1 << 20, crate::PROT_READ) }, 0);
        assert_eq!(commit(lazy, true), Access::NotLazy);
        look("lazy memory PROT_READ, written", lazy, true, Settled::Refused);
        look("lazy memory PROT_READ, read before its commit", lazy, false, Settled::Resolvable);
        // Unmapped memory.
        // SAFETY: our mapping.
        assert_eq!(unsafe { crate::munmap(lazy as *mut c_void, 1 << 20) }, 0);
        look("unmapped memory, read", lazy, false, Settled::Refused);
        std::println!("SETTLED done");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// [`EXCEPTION_HOOK`]'s: holds the first access violation's handler
    /// until the test releases it; the others' handlers run on.
    fn hold_the_first_handler() {
        static FIRST: AtomicBool = AtomicBool::new(false);
        if FIRST.swap(true, Ordering::SeqCst) {
            return;
        }
        HELD.store(true, Ordering::SeqCst);
        wait_for(&RELEASED, "the release of the handler");
    }

    /// A host thread's access that faulted on a missing registered page
    /// whose range is unregistered, and the page resolved by another
    /// thread's write, before the access's handler looks at it (the thread
    /// preempted between the fault and the handler's checks, held by
    /// [`EXCEPTION_HOOK`]): the access runs again and reads what the other
    /// thread wrote, as on Linux, where the unregistered page is ordinary
    /// memory the other thread's fault allocated (v6.1 mm/memory.c,
    /// `do_anonymous_page`) and the held fault, finding the page present,
    /// returns and the access runs again. In each order of first use of the
    /// process's exception handler (a child each): a lazy (`MAP_NORESERVE`)
    /// mapping first, as in a VMM whose guest memory is mapped before its
    /// userfaultfd is made, and the userfaultfd's create first. While the
    /// two modules had a vectored handler each, the one added last ran
    /// first, and with the userfaultfd's created first the lazy-memory
    /// handler looked (the page registered and missing, not its to
    /// resolve) before the userfaultfd's was held, and the userfaultfd's,
    /// finding the page no longer registered, passed the exception on: the
    /// process ended with the access violation (0xC0000005).
    #[test]
    fn test_a_host_access_that_faulted_before_an_unregister_runs_again() {
        for child in ["late_handler_unregister_lazy_mapping_first_child", "late_handler_unregister_create_first_child"] {
            let (code, text) = run_child(child, None);
            std::eprintln!("LATEUNREG {child}: {code:?}; {}", text.lines().filter(|l| l.starts_with("LATEUNREG") || l.contains("panicked") || l.starts_with("wick:")).collect::<std::vec::Vec<_>>().join(" | "));
            assert!(text.contains("LATEUNREG read back 0x77"), "{child}: {text}");
            assert_eq!(code, Some(0), "{child}: {text}");
        }
    }

    #[test]
    #[ignore = "run by test_a_host_access_that_faulted_before_an_unregister_runs_again in a process of its own"]
    fn late_handler_unregister_lazy_mapping_first_child() {
        lazy_memory_is_mapped();
        late_handler_unregister();
    }

    #[test]
    #[ignore = "run by test_a_host_access_that_faulted_before_an_unregister_runs_again in a process of its own"]
    fn late_handler_unregister_create_first_child() {
        late_handler_unregister();
    }

    /// [`test_a_host_access_that_faulted_before_an_unregister_runs_again`]'s
    /// body: a page never filled, the reader's access held in its handler,
    /// the range unregistered (the page pending in its released record),
    /// another thread's write of 0x77 resolving it, then the reader let go.
    fn late_handler_unregister() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        assert!(is_missing(mem + PAGE));
        EXCEPTION_HOOK.store(hold_the_first_handler as fn() as usize, Ordering::SeqCst);
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read faults, and its handler
            // is held until the page is resolved by the writer.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        wait_for(&HELD, "the reader's fault");
        unregister(ctx, mem, len as u64).unwrap();
        assert!(!is_missing(mem + PAGE));
        std::thread::spawn(move || {
            // SAFETY: the unregistered range: the write resolves the page.
            unsafe { core::ptr::write_volatile((mem + PAGE + 5) as *mut u8, 0x77) };
        })
        .join()
        .expect("the writer failed");
        RELEASED.store(true, Ordering::SeqCst);
        let got = reader.join().expect("the reader failed");
        EXCEPTION_HOOK.store(0, Ordering::SeqCst);
        std::println!("LATEUNREG read back {got:#x}");
        assert_eq!(got, 0x77);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The mirror of the test above, the change between the handler's
    /// userfaultfd step and its released and lazy resolve: the range
    /// unregistered before the access, so that the userfaultfd's step finds
    /// the page not registered and leaves it, the page pending in its
    /// released record; the handler held there
    /// (`windows_mm::HOOK_AFTER_THE_USERFAULTFD`) while another thread's
    /// write resolves the page; let go, the access runs again and reads
    /// what the other thread wrote, the resolve finding the page held by
    /// its record, no longer pending and accessible. (A page released
    /// pending and registered again before the handler's last check cannot
    /// be: a released range is not registered again yet,
    /// test_memory_unregistered_whole_registers_again.) In a process of
    /// its own.
    #[test]
    fn test_a_host_access_that_faulted_on_a_released_page_resolved_meanwhile_runs_again() {
        let (code, text) = run_child("late_handler_released_child", None);
        std::eprintln!("LATERELEASED {code:?}; {}", text.lines().filter(|l| l.starts_with("LATERELEASED") || l.contains("panicked") || l.starts_with("wick:")).collect::<std::vec::Vec<_>>().join(" | "));
        assert!(text.contains("LATERELEASED read back 0x77"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    /// A released range's pending page, resolved by its first access
    /// (`Committed`), is `Present` to the commit after, nothing committed,
    /// read or written: the page another access resolved before, which
    /// WHP's run loop then counts toward its bound (`exit::RamRetries`)
    /// where `Committed` started the count again. RELPRESENT line.
    #[test]
    fn test_a_released_page_resolved_before_is_present_to_the_commit() {
        use crate::windows_mm::{wick_mm::commit_on_access, Access};
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        unregister(ctx, mem, len as u64).unwrap();
        let page = (mem + PAGE) as usize;
        let first = commit_on_access(page, false);
        let read = commit_on_access(page, false);
        let written = commit_on_access(page, true);
        std::eprintln!("RELPRESENT first {first:?}, then read {read:?}, written {written:?}");
        assert_eq!((first, read, written), (Access::Committed, Access::Present, Access::Present));
        release(ctx, user);
        assert_eq!(munmap_of(mem, len as u64), 0);
    }

    #[test]
    #[ignore = "run by test_a_host_access_that_faulted_on_a_released_page_resolved_meanwhile_runs_again in a process of its own"]
    fn late_handler_released_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 64 * 1024;
        let mem = map(len);
        register(ctx, mem, len as u64).unwrap();
        unregister(ctx, mem, len as u64).unwrap();
        assert!(!is_missing(mem + PAGE));
        crate::windows_mm::HOOK_AFTER_THE_USERFAULTFD.store(hold_the_first_handler as fn() as usize, Ordering::SeqCst);
        let reader = std::thread::spawn(move || {
            // SAFETY: the unregistered range, its page pending: the read
            // faults, and its handler is held after the userfaultfd's step.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        wait_for(&HELD, "the reader's fault");
        std::thread::spawn(move || {
            // SAFETY: as above: the write resolves the page.
            unsafe { core::ptr::write_volatile((mem + PAGE + 5) as *mut u8, 0x77) };
        })
        .join()
        .expect("the writer failed");
        RELEASED.store(true, Ordering::SeqCst);
        let got = reader.join().expect("the reader failed");
        std::println!("LATERELEASED read back {got:#x}");
        assert_eq!(got, 0x77);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// `windows_mm::MOVE_HOOK`'s: lets the reader read the moving chunk
    /// and waits until its fault's handler is held.
    fn read_during_the_move() {
        READ_NOW.store(true, Ordering::SeqCst);
        wait_for(&HELD, "the reader's fault during the move");
    }

    /// The same for a live page of a chunk being moved: the access faults
    /// while the chunk is closed for the move and its handler looks once
    /// the move is over (not moving, not missing): the access runs again
    /// and reads the page's content. Before the fix the process ended
    /// with an access violation. In a process of its own.
    #[test]
    fn test_a_host_access_that_faulted_during_a_move_runs_again() {
        let (code, text) = run_child("late_handler_move_child", None);
        assert!(text.contains("read back 0x5a"), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_host_access_that_faulted_during_a_move_runs_again in a process of its own"]
    fn late_handler_move_child() {
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * CHUNK;
        let mem = map(len as usize);
        register(ctx, mem, len).unwrap();
        let data = std::vec![0x5au8; len as usize];
        // SAFETY: `data` holds `len` bytes.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, len, true) }.unwrap(), len);
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        crate::windows_mm::set_move_hook(Some(read_during_the_move));
        EXCEPTION_HOOK.store(hold_the_handler as fn() as usize, Ordering::SeqCst);
        let reader = std::thread::spawn(move || {
            wait_for(&READ_NOW, "the move");
            // SAFETY: a live page of the registered range, closed for the
            // move; the read faults, and its handler is held until the move
            // is over.
            unsafe { core::ptr::read_volatile((mem + PAGE + 5) as *const u8) }
        });
        let r = reclaim_at_touch(PAGE as usize);
        assert_eq!(r.chunks, 1, "no chunk was moved");
        assert!(!is_moving(mem + PAGE) && !is_missing(mem + PAGE));
        RELEASED.store(true, Ordering::SeqCst);
        let got = reader.join().expect("the reader failed");
        EXCEPTION_HOOK.store(0, Ordering::SeqCst);
        crate::windows_mm::set_move_hook(None);
        std::println!("read back {got:#x}");
        assert_eq!(got, 0x5a);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A plain AF_UNIX stream socket, for the tests below.
    fn unix_socket() -> SOCKET {
        wick_wsa_startup();
        // SAFETY: creates a socket.
        let s = unsafe {
            ws::WSASocketW(i32::from(AF_UNIX), SOCK_STREAM, 0, ptr::null(), 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT)
        };
        assert_ne!(s, INVALID_SOCKET, "WSASocketW: {}", io::Error::last_os_error());
        s
    }

    /// A `sockaddr_un` for `name` (a path, or an abstract name when it
    /// starts with NUL) and the length to pass: the family, then the name's
    /// bytes, with no terminator for an abstract name (Linux's rule for
    /// abstract names: the length delimits it).
    fn unix_addr(name: &[u8]) -> ([u8; 110], i32) {
        let mut a = [0u8; 110];
        a[0] = 1; // AF_UNIX
        a[2..2 + name.len()].copy_from_slice(name);
        let len = if name.first() == Some(&0) { 2 + name.len() } else { a.len() };
        (a, i32::try_from(len).unwrap())
    }

    fn wsa_error() -> i32 {
        // SAFETY: plain call.
        unsafe { ws::WSAGetLastError() }
    }

    /// The path of this process's userfaultfd socket number `seq`, as
    /// `socket_pair` names it.
    fn uffd_socket_path(seq: u64) -> std::path::PathBuf {
        std::env::temp_dir().join(std::format!("wick-uffd-{}-{seq}.sock", std::process::id()))
    }

    /// A process killed between `socket_pair`'s bind and its removal of
    /// the path leaves the path (cdb's quit left `wick-uffd-3332-1.sock` on
    /// fc-win, 2026-11-16, and a later test process with pid 3332 was
    /// refused its second userfaultfd: `bind` WSAEADDRINUSE, 10048). The
    /// next process of that pid must make its userfaultfds all the same, as
    /// Linux's `socketpair`, which has no path, always does; and no path of
    /// a userfaultfd it made may stay once `create` returned. In a process
    /// of its own (its sequence numbers start at 0).
    #[test]
    fn test_a_userfaultfd_is_made_over_paths_a_dead_process_of_this_pid_left() {
        let (code, out) = run_child("sockpath_leftover_child", None);
        std::eprintln!("{out}");
        assert_eq!(code, Some(0), "the child failed");
        assert!(out.contains("SOCKPATH made 4 userfaultfds over 4 left paths"), "the child did not get to its end");
    }

    #[test]
    #[ignore = "run by test_a_userfaultfd_is_made_over_paths_a_dead_process_of_this_pid_left"]
    fn sockpath_leftover_child() {
        // This child's paths, removed at its end however it ends.
        struct Paths;
        impl Drop for Paths {
            fn drop(&mut self) {
                for seq in 0..4 {
                    let _ = std::fs::remove_file(uffd_socket_path(seq));
                }
            }
        }
        let _paths = Paths;
        // Left as a killed process leaves them: a socket bound to the path
        // and closed, its file (an NTFS reparse point) still there.
        for seq in 0..4 {
            let path = uffd_socket_path(seq);
            let (a, len) = unix_addr(path.to_str().unwrap().as_bytes());
            let s = unix_socket();
            // SAFETY: a valid AF_UNIX address.
            assert_eq!(unsafe { ws::bind(s, a.as_ptr().cast(), len) }, 0, "bind {}: {}", path.display(), wsa_error());
            // SAFETY: our socket.
            unsafe { ws::closesocket(s) };
            assert!(path.exists(), "{} went with its socket", path.display());
        }
        for seq in 0..4 {
            let made = create(0, false, true);
            let (ctx, user) = made.unwrap_or_else(|e| panic!("userfaultfd {seq} over a path a dead process left: {e}"));
            assert!(!uffd_socket_path(seq).exists(), "{} stayed after create returned", uffd_socket_path(seq).display());
            release(ctx, user);
        }
        std::eprintln!("SOCKPATH made 4 userfaultfds over 4 left paths; none of their paths stayed");
    }

    /// SOCKPATH: what AF_UNIX on this host does with the cases
    /// `socket_pair` meets (note-uffd-sockpath.md): (a) an abstract address
    /// (a NUL first in `sun_path`): bind, listen, connect, accept; (b) the
    /// listener's path deleted (DeleteFileW) after a connect and before its
    /// accept: is the queued connection still accepted; (c) the pid
    /// `SIO_AF_UNIX_GETPEERPID` gives for each end of a pair this process
    /// made; (d) a bind over a path a closed socket left: its error, and the
    /// bind after DeleteFileW. On record: it prints what it saw and fails
    /// only on a call the cases need that it could not make.
    #[test]
    fn test_af_unix_paths_and_abstract_addresses_on_record() {
        let wide = |p: &std::path::Path| -> Vec<u16> {
            use std::os::windows::ffi::OsStrExt;
            p.as_os_str().encode_wide().chain([0]).collect()
        };
        let peer = |s: SOCKET| -> std::string::String {
            let (mut pid, mut n) = (0u32, 0u32);
            // SAFETY: a u32 out-buffer.
            let rc = unsafe {
                ws::WSAIoctl(s, ws::SIO_AF_UNIX_GETPEERPID, ptr::null(), 0, (&raw mut pid).cast(), 4, &mut n, ptr::null_mut(), None)
            };
            if rc == 0 { std::format!("pid {pid}") } else { std::format!("error {}", wsa_error()) }
        };
        let me = std::process::id();
        let close = |s: SOCKET| {
            // SAFETY: our socket.
            unsafe { ws::closesocket(s) };
        };
        // (a) An abstract address.
        let name = std::format!("\0wick-sockpath-rec-{me}");
        let (a, len) = unix_addr(name.as_bytes());
        let l = unix_socket();
        // SAFETY: valid addresses and our sockets, here and below.
        let bound = unsafe { ws::bind(l, a.as_ptr().cast(), len) };
        let bound_err = if bound == 0 { 0 } else { wsa_error() };
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let listened = if bound == 0 { unsafe { ws::listen(l, 1) } } else { -1 };
        let mut line = std::format!("SOCKPATH abstract: bind {bound} (error {bound_err}), listen {listened}");
        if listened == 0 {
            let c = unix_socket();
            // SAFETY: our sockets, valid addresses and NUL-terminated paths.
            let connected = unsafe { ws::connect(c, a.as_ptr().cast(), len) };
            let connect_err = if connected == 0 { 0 } else { wsa_error() };
            line.push_str(&std::format!(", connect {connected} (error {connect_err})"));
            if connected == 0 {
                // SAFETY: our sockets, valid addresses and NUL-terminated paths.
                let s = unsafe { ws::accept(l, ptr::null_mut(), ptr::null_mut()) };
                line.push_str(&std::format!(", accept {}", if s == INVALID_SOCKET { std::format!("error {}", wsa_error()) } else { std::format!("ok, its peer {}", peer(s)) }));
                if s != INVALID_SOCKET {
                    close(s);
                }
            }
            close(c);
        }
        close(l);
        std::eprintln!("{line}");
        // (b), (c): a path deleted between connect and accept.
        let path = std::env::temp_dir().join(std::format!("wick-sockpath-rec-{me}.sock"));
        let (a, len) = unix_addr(path.to_str().unwrap().as_bytes());
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::bind(l, a.as_ptr().cast(), len) }, 0, "bind {}: {}", path.display(), wsa_error());
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::listen(l, 1) }, 0);
        let c = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::connect(c, a.as_ptr().cast(), len) }, 0, "connect: {}", wsa_error());
        // SAFETY: a NUL-terminated path.
        let deleted = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        let delete_err = if deleted != 0 { 0 } else { io::Error::last_os_error().raw_os_error().unwrap_or(0) };
        let gone = !path.exists();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let s = unsafe { ws::accept(l, ptr::null_mut(), ptr::null_mut()) };
        let accepted = if s == INVALID_SOCKET { std::format!("error {}", wsa_error()) } else { "ok".into() };
        let mut moved = std::string::String::from("not tried");
        if s != INVALID_SOCKET {
            // SAFETY: our sockets, valid addresses and NUL-terminated paths.
            let sent = unsafe { ws::send(c, b"x".as_ptr(), 1, 0) };
            let mut b = [0u8; 1];
            // SAFETY: our sockets, valid addresses and NUL-terminated paths.
            let got = unsafe { ws::recv(s, b.as_mut_ptr(), 1, 0) };
            moved = std::format!("send {sent}, recv {got} ({:?})", b[0] as char);
        }
        std::eprintln!(
            "SOCKPATH path deleted after connect, before accept: DeleteFileW {deleted} (error {delete_err}), the path gone {gone}; accept {accepted}; a byte through it: {moved}"
        );
        if s != INVALID_SOCKET {
            std::eprintln!("SOCKPATH peers (this process is pid {me}): of the accepted end {}, of the connected end {}", peer(s), peer(c));
            close(s);
        }
        close(c);
        close(l);
        // (d) A bind over a path a closed socket left, then after DeleteFileW.
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        assert_eq!(unsafe { ws::bind(l, a.as_ptr().cast(), len) }, 0, "bind {}: {}", path.display(), wsa_error());
        close(l);
        let left = path.exists();
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let again = unsafe { ws::bind(l, a.as_ptr().cast(), len) };
        let again_err = if again == 0 { 0 } else { wsa_error() };
        close(l);
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let deleted = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        let l = unix_socket();
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let after = unsafe { ws::bind(l, a.as_ptr().cast(), len) };
        let after_err = if after == 0 { 0 } else { wsa_error() };
        close(l);
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let deleted_last = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        std::eprintln!(
            "SOCKPATH a path a closed socket left: there {left}; bind over it {again} (error {again_err}); DeleteFileW {deleted}; bind after it {after} (error {after_err}); removed at the end {deleted_last}"
        );
        // (e) DeleteFileW of a name that is missing: its error.
        // SAFETY: our sockets, valid addresses and NUL-terminated paths.
        let missing = unsafe { DeleteFileW(wide(&path).as_ptr()) };
        std::eprintln!("SOCKPATH DeleteFileW of a missing name: {missing} (error {})", io::Error::last_os_error().raw_os_error().unwrap_or(0));
        assert!(!path.exists());
    }

    // ---- munmap and MAP_FIXED of registered memory (the macOS backend's
    // tests of the same names; Linux's registration belongs to the vma and
    // goes with it: mm/vma.c, v6.12, `do_vmi_align_munmap` :1332, through
    // `vms_gather_munmap_vmas` :1180 and fs/userfaultfd.c
    // `userfaultfd_unmap_prep` :1267; `MAP_FIXED` unmaps what it maps over
    // first, mm/mmap.c `__mmap_region` :1361 and :1386). Each runs in a child
    // of its own (nothing else may map in the holes), whose checks are all
    // made and each failure said ("UNMAPCHECK fail: ..."), the copies that
    // may end the process last, under a watchdog.

    /// The checks of one child: each failure said as it is found, all of
    /// them asserted at the end.
    struct Checks(std::vec::Vec<std::string::String>);

    impl Checks {
        fn new() -> Self {
            Checks(std::vec::Vec::new())
        }

        fn check(&mut self, ok: bool, what: impl core::fmt::Display) {
            if !ok {
                std::println!("UNMAPCHECK fail: {what}");
                self.0.push(std::format!("{what}"));
            }
        }

        fn done(self) {
            std::println!("UNMAPCHECK done, {} failed", self.0.len());
            assert!(self.0.is_empty(), "{} checks failed: {:?}", self.0.len(), self.0);
        }
    }

    /// Ends the child with exit code 3 and a line after `secs`: a wait that
    /// would hang it.
    fn watchdog(secs: u64) {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(secs));
            std::println!("WATCHDOG {secs} s passed: the child is ended");
            std::process::exit(3);
        });
    }

    /// Waits up to 10 s for `cond`; whether it held.
    fn holds_within(cond: impl Fn() -> bool) -> bool {
        let t = std::time::Instant::now();
        while !cond() {
            if t.elapsed() > std::time::Duration::from_secs(10) {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        true
    }

    const UNMAP_LEN: u64 = 64 << 10;

    /// The two kinds of registered memory ([`on_both_kinds`]): a fresh
    /// mapping of [`UNMAP_LEN`] bytes of `kind`.
    fn map_of(kind: &str) -> u64 {
        if kind == "reserved" { map_noreserve(UNMAP_LEN as usize) } else { map(UNMAP_LEN as usize) }
    }

    const MEM_KINDS: [&str; 2] = ["ordinary", "reserved"];

    /// A fresh mapping of `pages` pages of `kind` ([`map_of`]).
    fn map_pages(kind: &str, pages: u64) -> u64 {
        let len = (pages * PAGE) as usize;
        if kind == "reserved" { map_noreserve(len) } else { map(len) }
    }

    fn munmap_of(at: u64, len: u64) -> c_int {
        // SAFETY: memory of the test's own, through this libc.
        unsafe { crate::munmap(at as *mut c_void, len as usize) }
    }

    /// An anonymous private mapping of `len` bytes at `at` with `MAP_FIXED`,
    /// through this libc: its address, or `MAP_FAILED` as a u64.
    fn map_fixed(at: u64, len: u64, prot: c_int) -> u64 {
        // SAFETY: the test's own addresses.
        (unsafe { crate::mmap(at as *mut c_void, len as usize, prot, crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_FIXED, -1, 0) }) as u64
    }

    /// The state and protection of each page of `[at, at + len)`
    /// (`VirtualQuery`).
    fn states(at: u64, len: u64) -> std::vec::Vec<(u32, u32)> {
        use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
        (at..at + len)
            .step_by(PAGE as usize)
            .map(|a| {
                // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                unsafe { VirtualQuery(a as *const c_void, &mut mbi, std::mem::size_of_val(&mbi)) };
                (mbi.State, mbi.Protect)
            })
            .collect()
    }

    fn page_of(b: u8) -> std::vec::Vec<u8> {
        std::vec![b; PAGE as usize]
    }

    /// A mapping made where registered memory was unmapped, before its
    /// userfaultfd is released, keeps its state and protection through the
    /// release: on Linux the registration went with the unmapped vma, and
    /// the release walks only the vmas its userfaultfd has (mm/userfaultfd.c,
    /// v6.12, `userfaultfd_release_all` :1918 to :1924), changing nothing
    /// else. Firecracker unmaps its guest memory so at teardown
    /// (vstate/memory.rs:308, before the VM's `uffd`, vstate/vm.rs:84 and
    /// :95), and another thread may map in the hole meanwhile: here this
    /// libc's `mmap` of a `PROT_NONE` reservation, and the system's own
    /// (`VirtualAlloc`, committed `PAGE_NOACCESS`, as a thread's stack guard
    /// is made). For both kinds of registered memory, pages missing and
    /// filled.
    #[test]
    fn test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is() {
        let (code, text, _) = run_child_in_jobs("release_after_unmap_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is in a process of its own"]
    fn release_after_unmap_child() {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, VirtualAlloc, VirtualFree};
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            for how in ["this libc's mmap PROT_NONE", "VirtualAlloc PAGE_NOACCESS"] {
                let (ctx, user) = create(0, false, true).unwrap();
                let mem = map_of(kind);
                register(ctx, mem, UNMAP_LEN).unwrap();
                // SAFETY: a page.
                assert_eq!(unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
                assert_eq!(munmap_of(mem, UNMAP_LEN), 0, "{kind}");
                let made = if how.starts_with("VirtualAlloc") {
                    // SAFETY: the hole, reserved and committed by the system's call.
                    unsafe { VirtualAlloc(mem as *const c_void, UNMAP_LEN as usize, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS) as u64 }
                } else {
                    map_fixed(mem, UNMAP_LEN, crate::PROT_NONE)
                };
                if made != mem {
                    std::println!("UNMAP {kind}, {how}: the hole was not mapped ({made:#x}, {})", io::Error::last_os_error());
                    c.check(false, std::format!("{kind}, {how}: the hole could not be mapped"));
                    release(ctx, user);
                    continue;
                }
                let before = states(mem, 4 * PAGE);
                release(ctx, user);
                let after = states(mem, 4 * PAGE);
                std::println!("UNMAP {kind}, {how}: (state, protection) of its first 4 pages before the release {before:x?}, after {after:x?}");
                c.check(before == after, std::format!("{kind}, {how}: the release changed the new mapping: {before:x?} -> {after:x?}"));
                if how.starts_with("VirtualAlloc") {
                    // SAFETY: the reservation made above.
                    unsafe { VirtualFree(mem as *mut c_void, 0, MEM_RELEASE) };
                } else {
                    assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
                }
            }
        }
        c.done();
    }

    /// Registered memory unmapped while its userfaultfd is open leaves no
    /// registration behind (the registration went with the vma; a fill
    /// where no registered vma is is `ENOENT`, mm/userfaultfd.c, v6.12,
    /// `uffd_mfill_lock` :113, `validate_dst_vma` :34). Part of a range: the
    /// unmapped page is in no registration and stays unmapped, the
    /// userfaultfd's release included (an access to it is the process's
    /// fault, as an access where Linux has no vma); the rest is as it was.
    /// All of it: nothing is left of the range. For both kinds.
    #[test]
    fn test_memory_unmapped_while_registered_leaves_no_registration_behind() {
        let (code, text, _) = run_child_in_jobs("unmapped_leaves_nothing_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_memory_unmapped_while_registered_leaves_no_registration_behind in a process of its own"]
    fn unmapped_leaves_nothing_child() {
        use crate::windows_mm::wick_mm::{Access, commit_on_access};
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            // Part: its second page.
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            assert_eq!(munmap_of(mem + PAGE, PAGE), 0, "{kind}");
            c.check(!is_missing(mem + PAGE), std::format!("{kind}, part: the unmapped page is still registered (missing)"));
            let z = zeropage(ctx, mem + PAGE, PAGE, true);
            c.check(z == Err((crate::ENOENT, 0)), std::format!("{kind}, part: a fill of the unmapped page: {z:?}"));
            c.check(is_missing(mem), std::format!("{kind}, part: the page left mapped is no longer missing"));
            // SAFETY: a page.
            let f = unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem, PAGE, true) };
            c.check(f == Ok(PAGE), std::format!("{kind}, part: a fill of the page left mapped: {f:?}"));
            if f == Ok(PAGE) {
                // SAFETY: filled just now.
                c.check(unsafe { ptr::read_volatile(mem as *const u8) } == 0x5a, std::format!("{kind}, part: the filled page"));
            }
            release(ctx, user);
            #[allow(clippy::cast_possible_truncation)]
            let a = commit_on_access((mem + PAGE) as usize, false);
            std::println!("UNMAP {kind}, part: after the release, a first access to the unmapped page: {a:?}; its state {:x?}", states(mem + PAGE, PAGE));
            c.check(
                matches!(a, Access::NotLazy) && !host_readable(mem + PAGE),
                std::format!("{kind}, part: after the release the unmapped page is opened: {a:?}, {:x?}", states(mem + PAGE, PAGE)),
            );
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
            // All of it, a page filled, the userfaultfd still open.
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            // SAFETY: a page.
            assert_eq!(unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0, "{kind}");
            c.check(find(mem).is_none() && find(mem + PAGE).is_none(), std::format!("{kind}, all: the unmapped range is still held"));
            let z = zeropage(ctx, mem + PAGE, PAGE, true);
            std::println!("UNMAP {kind}, all: a zero page into the unmapped range: {z:?}");
            c.check(z == Err((crate::ENOENT, 0)), std::format!("{kind}, all: a fill of the unmapped range: {z:?}"));
            release(ctx, user);
        }
        c.done();
    }

    /// How registered memory is replaced: unmapped and mapped again in the
    /// hole, or mapped over with `MAP_FIXED` (the macOS backend's
    /// `Replace`).
    const REPLACE_CASE: &str = "WICK_UFFD_REPLACE";

    /// [`UNMAP_LEN`] bytes registered with a fresh userfaultfd `a` (of the
    /// kind `WICK_UFFD_KIND` names), the first page filled with 0x5a, then
    /// replaced by new read-write memory at the same address as
    /// [`REPLACE_CASE`] says, through this libc. Returns (a, its user end,
    /// another userfaultfd b, its user end, the memory).
    fn replaced() -> (usize, c_int, usize, c_int, u64) {
        let how = std::env::var("WICK_UFFD_REPLACE").unwrap();
        let kind = std::env::var("WICK_UFFD_KIND").unwrap();
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let mem = map_of(&kind);
        register(a, mem, UNMAP_LEN).unwrap();
        // SAFETY: a page.
        assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
        if how == "UnmapThenMap" {
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        let p = map_fixed(mem, UNMAP_LEN, crate::PROT_READ | crate::PROT_WRITE);
        std::println!("UNMAP replaced ({how}, {kind}): the new mapping at {p:#x} (the old at {mem:#x}): {}", if p == mem { "made".into() } else { std::format!("{}", io::Error::last_os_error()) });
        assert_eq!(p, mem, "{how}, {kind}: the new mapping");
        (a, ua, b, ub, mem)
    }

    /// Runs `child` once for each replacement and kind, in a process of its
    /// own each; asserts that every one ended with 0, naming those that did
    /// not with their lines.
    fn replace_cases(child: &str) {
        let mut failed = std::vec::Vec::new();
        for how in ["UnmapThenMap", "MapFixedOver"] {
            for kind in MEM_KINDS {
                let (code, text, _) = run_child_in_jobs(child, &[(REPLACE_CASE, how), ("WICK_UFFD_KIND", kind)], &[]);
                for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
                    std::eprintln!("{how}, {kind}: {l}");
                }
                if code != Some(0) {
                    failed.push(std::format!("{how}, {kind}: exit {code:x?}"));
                }
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    /// The new memory is in no registration: not missing, an access there is
    /// no userfault, and a fill there is `ENOENT`, as Linux's for a
    /// destination in no registered vma (mm/userfaultfd.c, v6.12:
    /// `mfill_atomic` :700, `uffd_mfill_lock` :733, `ENOENT` at :113 when
    /// `validate_dst_vma` finds no userfaultfd on it, :34). The copy, which
    /// ended the process with an access violation on fc-win
    /// (as a probe on fc-win first found), last.
    #[test]
    fn test_memory_replaced_while_registered_is_in_no_registration() {
        replace_cases("replaced_no_registration_child");
    }

    #[test]
    #[ignore = "run by test_memory_replaced_while_registered_is_in_no_registration in processes of its own"]
    fn replaced_no_registration_child() {
        watchdog(60);
        let mut c = Checks::new();
        let (a, _ua, _b, _ub, mem) = replaced();
        if let Some((r, _)) = find(mem) {
            let alias = r.alias.load(Ordering::Acquire);
            std::println!(
                "UNMAP the old range's alias at [{alias:#x}, {:#x}), the page a fill of {:#x} writes through at {:#x}",
                alias + (r.end.load(Ordering::Acquire) - r.start.load(Ordering::Acquire)),
                mem + PAGE,
                alias + PAGE
            );
        }
        c.check(!is_missing(mem) && !is_missing(mem + PAGE), "the new memory is missing");
        // An access fault there, as the handler sees it, on a thread of its
        // own: a userfault waits for a fill that never comes.
        let faulted = std::thread::spawn(move || fault(mem + 3 * PAGE, false));
        let waited = !holds_within(|| faulted.is_finished());
        std::println!("UNMAP an access fault on the new memory: {}", if waited { "waits as a userfault (10 s)" } else { "no userfault" });
        c.check(!waited, "an access fault on the new memory waits as a userfault");
        std::println!("UNMAP a zero page into the new memory follows");
        let z = zeropage(a, mem + PAGE, PAGE, true);
        std::println!("UNMAP a zero page into the new memory: {z:?}; the page now {:x?}", states(mem + PAGE, PAGE));
        c.check(z == Err((crate::ENOENT, 0)), std::format!("a zero page into the new memory: {z:?}"));
        std::println!("UNMAP the copy into the new memory follows");
        // SAFETY: a page.
        let f = unsafe { copy(a, page_of(0x77).as_ptr(), mem + 2 * PAGE, PAGE, true) };
        std::println!("UNMAP the copy into the new memory: {f:?}; the page now {:x?}", states(mem + 2 * PAGE, PAGE));
        c.check(f == Err((crate::ENOENT, 0)), std::format!("a copy into the new memory: {f:?}"));
        c.done();
    }

    /// The new memory registers anew, with the same userfaultfd or another
    /// (Linux's new vma has no userfaultfd: mm/mmap.c, v6.12,
    /// `__mmap_region` :1386 and `vm_area_alloc` :1435; `userfaultfd_register`
    /// refuses only a vma another userfaultfd has, fs/userfaultfd.c :1363 to
    /// :1366), and a fill lands in the new memory.
    #[test]
    fn test_memory_replaced_while_registered_registers_anew() {
        replace_cases("replaced_registers_anew_child");
    }

    #[test]
    #[ignore = "run by test_memory_replaced_while_registered_registers_anew in processes of its own"]
    fn replaced_registers_anew_child() {
        watchdog(60);
        let mut c = Checks::new();
        let (a, _ua, b, _ub, mem) = replaced();
        let again = register(a, mem, UNMAP_LEN);
        c.check(again.is_ok(), std::format!("its userfaultfd's register of the new memory: {again:?}"));
        if again.is_ok() {
            c.check(is_missing(mem) && is_missing(mem + PAGE), "the new pages are not missing");
            // SAFETY: a page.
            let f = unsafe { copy(a, page_of(0x77).as_ptr(), mem + PAGE, PAGE, true) };
            c.check(f == Ok(PAGE), std::format!("a fill of the new memory: {f:?}"));
            if f == Ok(PAGE) {
                // SAFETY: filled just now.
                let got = unsafe { ptr::read_volatile((mem + PAGE) as *const u8) };
                c.check(got == 0x77, std::format!("the fill did not reach the new memory: {got:#x}"));
            }
            c.check(unregister(a, mem, UNMAP_LEN).is_ok(), "the unregister");
        }
        let other = register(b, mem, UNMAP_LEN);
        c.check(other.is_ok(), std::format!("another userfaultfd's register of the new memory: {other:?}"));
        c.done();
    }

    /// Whether `user` has an event to read within `ms` milliseconds.
    fn event_within(user: c_int, ms: i32) -> bool {
        let mut p = ws::WSAPOLLFD { fd: sock(user), events: ws::POLLRDNORM, revents: 0 };
        // SAFETY: one pollfd.
        unsafe { ws::WSAPoll(&mut p, 1, ms) == 1 }
    }

    /// Pages unregistered from the middle of a range are in no registration,
    /// and another userfaultfd registers them, as Linux's unregister splits
    /// the vma and clears the middle one's context (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_unregister` :1413, `userfaultfd_clear_vma` at :1522;
    /// `userfaultfd_register` refuses only a vma another context has, :1364
    /// to :1366): each part then faults to its own userfaultfd and is filled
    /// only through it (a fill through the other is `ENOENT`; not Linux's,
    /// whose `validate_dst_vma`, mm/userfaultfd.c :23 to :37, asks only that
    /// the vma has a userfaultfd: [`range_of`]). The macOS backend's test of
    /// the same name. For both kinds.
    #[test]
    fn test_a_partial_unregister_frees_that_part_for_another_userfaultfd() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let (b, ub) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 3);
            register(a, mem, 3 * PAGE).unwrap();
            assert_eq!(unregister(a, mem + PAGE, PAGE), Ok(()), "{kind}");
            let taken = register(b, mem + PAGE, PAGE);
            assert!(taken.is_ok(), "{kind}: the unregistered middle is refused to another userfaultfd: {taken:?}");
            assert!(is_missing(mem) && is_missing(mem + PAGE) && is_missing(mem + 2 * PAGE), "{kind}");
            // A fault in the middle goes to b, not to a.
            let reader = std::thread::spawn(move || {
                // SAFETY: registered memory; the read waits for b's fill.
                unsafe { ptr::read_volatile((mem + PAGE) as *const u8) }
            });
            assert!(event_within(ub, 10_000), "{kind}: no fault event on the middle's userfaultfd");
            let mut rec = [0u8; proto::RECORD];
            assert!(recv_all(ub, &mut rec));
            assert_eq!(words(&rec)[..2], [proto::EVENT_PAGEFAULT2, mem + PAGE], "{kind}");
            assert!(!event_within(ua, 0), "{kind}: the other userfaultfd got the middle's fault");
            // SAFETY: each source holds a page.
            unsafe {
                assert_eq!(copy(a, page_of(2).as_ptr(), mem + PAGE, PAGE, true), Err((crate::ENOENT, 0)), "{kind}: a filled b's page");
                assert_eq!(copy(b, page_of(2).as_ptr(), mem + PAGE, PAGE, true), Ok(PAGE), "{kind}");
                assert_eq!(copy(b, page_of(1).as_ptr(), mem, PAGE, true), Err((crate::ENOENT, 0)), "{kind}: b filled a's page");
                assert_eq!(copy(a, page_of(1).as_ptr(), mem, PAGE, true), Ok(PAGE), "{kind}");
                assert_eq!(copy(a, page_of(3).as_ptr(), mem + 2 * PAGE, PAGE, true), Ok(PAGE), "{kind}");
            }
            assert_eq!(reader.join().unwrap(), 2, "{kind}");
            // SAFETY: filled above.
            unsafe {
                assert_eq!(ptr::read_volatile(mem as *const u8), 1, "{kind}");
                assert_eq!(ptr::read_volatile((mem + 2 * PAGE) as *const u8), 3, "{kind}");
            }
            release(a, ua);
            release(b, ub);
        }
    }

    /// The same userfaultfd registers its own range again: what it has stays
    /// as it is (a filled page keeps its contents), as Linux's register
    /// refuses only another context's vma (fs/userfaultfd.c, v6.12, :1364 to
    /// :1366) and skips one this context already has (mm/userfaultfd.c
    /// `userfaultfd_register_range` :1851 to :1853). The macOS backend's test
    /// of the same name. For both kinds.
    #[test]
    fn test_the_same_userfaultfd_registers_its_range_again() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 2);
            register(a, mem, 2 * PAGE).unwrap();
            // SAFETY: a page.
            assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE), "{kind}");
            let again = register(a, mem, 2 * PAGE);
            assert!(again.is_ok(), "{kind}: {again:?}");
            assert!(!is_missing(mem) && is_missing(mem + PAGE), "{kind}");
            // SAFETY: filled above.
            assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a, "{kind}");
            assert_eq!(unregister(a, mem, 2 * PAGE), Ok(()), "{kind}");
            release(a, ua);
        }
    }

    /// Part of a mapping is registered, the rest left as it is, as Linux's
    /// register splits the vma at the range's edges (mm/userfaultfd.c, v6.12,
    /// `userfaultfd_register_range` :1825, `vma_modify_flags_uffd` at :1860).
    /// The macOS backend's test of the same name. For both kinds. Here the
    /// register moves the whole mapping into its sections and registers the
    /// part's pages only. Before, the register of the part was `EINVAL`: the
    /// check "the register of part of a mapping" fails there.
    #[test]
    fn test_part_of_a_mapping_is_registered() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 4);
            // SAFETY: the first page of the mapping, before the register; the
            // fourth is left untouched, so that registered it would be missing.
            unsafe { ptr::write_volatile(mem as *mut u8, 7) };
            let r = register(a, mem + PAGE, 2 * PAGE);
            assert!(r.is_ok(), "{kind}: the register of part of a mapping: {r:?}");
            assert!(is_missing(mem + PAGE) && is_missing(mem + 2 * PAGE), "{kind}");
            assert!(!is_missing(mem) && !is_missing(mem + 3 * PAGE), "{kind}: pages outside the range were registered");
            // SAFETY: the pages outside the range, ordinary memory still.
            unsafe {
                assert_eq!(ptr::read_volatile(mem as *const u8), 7, "{kind}");
                assert_eq!(ptr::read_volatile((mem + 3 * PAGE) as *const u8), 0, "{kind}");
                ptr::write_volatile((mem + 3 * PAGE) as *mut u8, 8);
            }
            assert_eq!(zeropage(a, mem + PAGE, 2 * PAGE, true), Ok(2 * PAGE), "{kind}");
            assert_eq!(unregister(a, mem + PAGE, 2 * PAGE), Ok(()), "{kind}");
            release(a, ua);
        }
    }

    /// Memory mapped with `MAP_FIXED` over part of a mapping (which keeps it
    /// one mapping here, its pages committed again in place) registers, and
    /// is the new memory: its pages missing and filled, the rest of the
    /// mapping as it was, as Linux's `MAP_FIXED` makes a vma of its own that
    /// the register takes (mm/mmap.c, v6.12, `mmap_region`). For both kinds.
    /// Before, the register was `EINVAL`: the check "the register of the
    /// memory mapped over part of a mapping" fails there.
    #[test]
    fn test_memory_mapped_over_part_of_a_mapping_is_registered() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 8);
            for p in 0..8 {
                // SAFETY: the test's own read-write memory.
                unsafe { ptr::write_volatile((mem + p * PAGE) as *mut u8, 1) };
            }
            assert_eq!(map_fixed(mem + 2 * PAGE, 2 * PAGE, crate::PROT_READ | crate::PROT_WRITE), mem + 2 * PAGE, "{kind}");
            let r = register(a, mem + 2 * PAGE, 2 * PAGE);
            assert!(r.is_ok(), "{kind}: the register of the memory mapped over part of a mapping: {r:?}");
            assert!(is_missing(mem + 2 * PAGE) && is_missing(mem + 3 * PAGE), "{kind}: the new memory is not missing");
            for p in [0, 1, 4, 5, 6, 7] {
                assert!(!is_missing(mem + p * PAGE), "{kind}: page {p}, outside the range, is missing");
                // SAFETY: a page outside the range, ordinary memory still.
                assert_eq!(unsafe { ptr::read_volatile((mem + p * PAGE) as *const u8) }, 1, "{kind}: page {p}");
            }
            // SAFETY: a page.
            assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem + 2 * PAGE, PAGE, true) }, Ok(PAGE), "{kind}");
            assert_eq!(zeropage(a, mem + 3 * PAGE, PAGE, true), Ok(PAGE), "{kind}");
            // SAFETY: filled above.
            unsafe {
                assert_eq!(ptr::read_volatile((mem + 2 * PAGE) as *const u8), 0x5a, "{kind}");
                assert_eq!(ptr::read_volatile((mem + 3 * PAGE) as *const u8), 0, "{kind}");
                ptr::write_volatile((mem + 7 * PAGE) as *mut u8, 2);
                assert_eq!(ptr::read_volatile((mem + 7 * PAGE) as *const u8), 2, "{kind}");
            }
            release(a, ua);
            assert_eq!(munmap_of(mem, 8 * PAGE), 0, "{kind}");
        }
    }

    /// A register of part of a mapping charges what a register of the whole
    /// mapping charges, at the mapping's start: its resident pages, inside
    /// the range and out, each copied once into the sections (the move's
    /// cost); a page outside the range that was not resident is committed
    /// and charged at its first access, a fill inside it at the fill, as a
    /// page of a range never filled is after an unregister
    /// (`test_registered_memory_is_charged_as_it_is_filled`); the charge goes
    /// with the mapping. For both kinds. Before, the register was `EINVAL`:
    /// the check "the register of part of the mapping" fails there.
    #[test]
    fn test_a_part_registered_is_charged_as_the_whole_mapping_would_be() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let len = 64 * PAGE;
            let mem = map_pages(kind, 64);
            // SAFETY: the test's own read-write memory: pages 0 and 40,
            // outside the range below, resident.
            unsafe {
                ptr::write_volatile(mem as *mut u8, 7);
                ptr::write_volatile((mem + 40 * PAGE) as *mut u8, 9);
            }
            let r = register(a, mem + 8 * PAGE, 8 * PAGE);
            assert!(r.is_ok(), "{kind}: the register of part of the mapping: {r:?}");
            let charged = || crate::windows_mm::charged(mem as usize);
            if find(mem).is_some_and(|(r, _)| r.reserved.load(Ordering::Acquire)) {
                assert_eq!(charged(), Some(2 * PAGE as usize), "{kind}: charged at the registration");
            }
            assert_eq!(committed(mem, len), 2 * PAGE, "{kind}: committed at the registration");
            // SAFETY: a page.
            assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem + 8 * PAGE, PAGE, true) }, Ok(PAGE), "{kind}");
            assert_eq!(committed(mem, len), 3 * PAGE, "{kind}: committed after a fill");
            // SAFETY: page 20, outside the range and never touched: ordinary
            // memory, zeros at its first read.
            assert_eq!(unsafe { ptr::read_volatile((mem + 20 * PAGE) as *const u8) }, 0, "{kind}");
            assert_eq!(committed(mem, len), 4 * PAGE, "{kind}: committed after a first access outside the range");
            if find(mem).is_some_and(|(r, _)| r.reserved.load(Ordering::Acquire)) {
                assert_eq!(charged(), Some(4 * PAGE as usize), "{kind}: charged after a fill and a first access");
            }
            // SAFETY: the resident pages outside the range, kept.
            unsafe {
                assert_eq!(ptr::read_volatile(mem as *const u8), 7, "{kind}");
                assert_eq!(ptr::read_volatile((mem + 40 * PAGE) as *const u8), 9, "{kind}");
            }
            release(a, ua);
            assert_eq!(munmap_of(mem, len), 0, "{kind}");
            assert!(charged().is_none(), "{kind}: the charge outlived the mapping");
        }
    }

    /// Parts of one mapping register as Linux's vmas of one mapping do: two
    /// userfaultfds each on a part of its own; a register over both parts
    /// is `EBUSY`, as Linux checks every vma first (fs/userfaultfd.c,
    /// `userfaultfd_register` :1363 to :1366: a vma of another context); a fill through one into the
    /// other's part is `ENOENT`; a second part of the same userfaultfd; an
    /// unregister of part of a part leaves its page ordinary memory, which
    /// registers again holding what was written to it; a released
    /// userfaultfd's pages are ordinary memory after; the mapping's
    /// `munmap` frees the range. For both kinds. Before, the first register
    /// was `EINVAL`: the check "the register of a first part" fails there.
    #[test]
    fn test_parts_of_a_mapping_register_with_two_userfaultfds() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let (b, ub) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 8);
            // SAFETY: the test's own read-write memory.
            unsafe { ptr::write_volatile(mem as *mut u8, 7) };
            let r = register(a, mem + PAGE, 2 * PAGE);
            assert!(r.is_ok(), "{kind}: the register of a first part: {r:?}");
            let r = register(b, mem + 4 * PAGE, 2 * PAGE);
            assert!(r.is_ok(), "{kind}: another userfaultfd's register of another part: {r:?}");
            assert!(is_missing(mem + 4 * PAGE) && is_missing(mem + 5 * PAGE), "{kind}: the other part is not missing");
            assert!(range_of(b, mem + 4 * PAGE, 2 * PAGE).is_ok(), "{kind}: the other part is not the other userfaultfd's");
            // SAFETY: a page.
            assert_eq!(unsafe { copy(a, page_of(1).as_ptr(), mem + 4 * PAGE, PAGE, true) }.map_err(|e| e.0), Err(crate::ENOENT), "{kind}");
            assert_eq!(register(a, mem + 2 * PAGE, 3 * PAGE).unwrap_err().raw_os_error(), Some(crate::EBUSY), "{kind}: over both parts");
            let r = register(a, mem + 6 * PAGE, PAGE);
            assert!(r.is_ok(), "{kind}: a second part: {r:?}");
            assert!(is_missing(mem + 6 * PAGE), "{kind}: the second part is not missing");
            assert_eq!(unregister(a, mem + 2 * PAGE, PAGE), Ok(()), "{kind}");
            assert!(!is_missing(mem + 2 * PAGE) && is_missing(mem + PAGE), "{kind}: after the unregister of part of a part");
            // SAFETY: ordinary memory now, zeros at its first access.
            unsafe {
                assert_eq!(ptr::read_volatile((mem + 2 * PAGE) as *const u8), 0, "{kind}");
                ptr::write_volatile((mem + 2 * PAGE) as *mut u8, 3);
            }
            assert!(register(a, mem + 2 * PAGE, PAGE).is_ok(), "{kind}: the page registered again");
            assert!(!is_missing(mem + 2 * PAGE), "{kind}: a page written since its unregister is missing");
            // SAFETY: holds what was written.
            assert_eq!(unsafe { ptr::read_volatile((mem + 2 * PAGE) as *const u8) }, 3, "{kind}");
            release(b, ub);
            assert!(!is_missing(mem + 4 * PAGE), "{kind}: a released userfaultfd's page is missing");
            // SAFETY: ordinary memory now.
            assert_eq!(unsafe { ptr::read_volatile((mem + 4 * PAGE) as *const u8) }, 0, "{kind}");
            assert_eq!(zeropage(a, mem + PAGE, PAGE, true), Ok(PAGE), "{kind}");
            // SAFETY: a page.
            assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem + 6 * PAGE, PAGE, true) }, Ok(PAGE), "{kind}");
            // SAFETY: filled, and pages outside every part.
            unsafe {
                assert_eq!(ptr::read_volatile((mem + 6 * PAGE) as *const u8), 0x5a, "{kind}");
                assert_eq!(ptr::read_volatile(mem as *const u8), 7, "{kind}");
                assert_eq!(ptr::read_volatile((mem + 7 * PAGE) as *const u8), 0, "{kind}");
            }
            release(a, ua);
            assert_eq!(munmap_of(mem, 8 * PAGE), 0, "{kind}");
            assert!(find(mem).is_none(), "{kind}: the range outlived its mapping");
        }
    }

    /// A register of part of a mapping keeps what the rest of the mapping
    /// holds out of the working set (a page trimmed to the pagefile, which
    /// `QueryWorkingSetEx` does not count: here the move is told so for
    /// pages 0 and 5, `windows_mm::OUT_OF_THE_WORKING_SET`, as a trim on the
    /// runner is not certain): such a page outside the range is read once
    /// and copied if it holds anything but zeros; one of zeros, or never
    /// touched, reads zeros at its first access. Linux leaves the rest of
    /// the split vma as it was, swapped pages included. The pages read are
    /// the move's cost (MOVEREAD line). For both kinds. Before, the register
    /// of the part was `EINVAL`: the check "the register of part of the
    /// mapping" fails there.
    #[test]
    fn test_a_part_registered_keeps_the_rest_of_the_mapping_out_of_the_working_set() {
        let (code, text, _) = run_child_in_jobs("rest_out_of_the_working_set_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("MOVEREAD") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_part_registered_keeps_the_rest_of_the_mapping_out_of_the_working_set in a process of its own"]
    fn rest_out_of_the_working_set_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 8);
            // SAFETY: the test's own read-write memory: pages 0 and 5 hold
            // data, page 6 zeros written, page 7 is never touched; the
            // range is pages 2 and 3.
            unsafe {
                ptr::write_volatile(mem as *mut u8, 7);
                ptr::write_volatile((mem + 5 * PAGE + 100) as *mut u8, 9);
                ptr::write_volatile((mem + 6 * PAGE) as *mut u8, 0);
            }
            crate::windows_mm::OUT_OF_THE_WORKING_SET.lock().unwrap().extend([mem as usize, (mem + 5 * PAGE) as usize]);
            let read_before = crate::windows_mm::PAGES_READ_AT_A_MOVE.load(Ordering::SeqCst);
            let r = register(a, mem + 2 * PAGE, 2 * PAGE);
            let read = crate::windows_mm::PAGES_READ_AT_A_MOVE.load(Ordering::SeqCst) - read_before;
            std::println!("MOVEREAD {kind}: {read} pages outside the range read at the move, of 6");
            c.check(r.is_ok(), std::format!("{kind}: the register of part of the mapping: {r:?}"));
            c.check(read >= 2, std::format!("{kind}: {read} pages read, not the two out of the working set"));
            c.check(is_missing(mem + 2 * PAGE) && is_missing(mem + 3 * PAGE), std::format!("{kind}: the range is not missing"));
            // SAFETY: pages outside the range, ordinary memory still.
            unsafe {
                let p0 = ptr::read_volatile(mem as *const u8);
                let p5 = ptr::read_volatile((mem + 5 * PAGE + 100) as *const u8);
                c.check(p0 == 7 && p5 == 9, std::format!("{kind}: pages out of the working set lost their data: {p0}, {p5}"));
                let p6 = ptr::read_volatile((mem + 6 * PAGE) as *const u8);
                let p7 = ptr::read_volatile((mem + 7 * PAGE) as *const u8);
                c.check(p6 == 0 && p7 == 0, std::format!("{kind}: pages of zeros read {p6}, {p7}"));
            }
            release(a, ua);
            munmap_of(mem, 8 * PAGE);
        }
        c.done();
    }

    /// An `munmap` of the registered part of a mapping takes that part only:
    /// the rest keeps what it held and takes writes, as Linux's `munmap` of
    /// the registered vma leaves its neighbours; the range goes with the
    /// last of the mapping. For both kinds. Before, the register was
    /// `EINVAL`: the check "the register of part of the mapping" fails
    /// there.
    #[test]
    fn test_an_munmap_of_a_registered_part_leaves_the_rest_of_the_mapping() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 4);
            // SAFETY: the test's own read-write memory.
            unsafe {
                ptr::write_volatile(mem as *mut u8, 7);
                ptr::write_volatile((mem + 3 * PAGE) as *mut u8, 8);
            }
            let r = register(a, mem + PAGE, 2 * PAGE);
            assert!(r.is_ok(), "{kind}: the register of part of the mapping: {r:?}");
            assert_eq!(munmap_of(mem + PAGE, 2 * PAGE), 0, "{kind}");
            assert!(!is_missing(mem + PAGE), "{kind}: an unmapped page is missing");
            // SAFETY: the pages outside the part, still mapped.
            unsafe {
                assert_eq!(ptr::read_volatile(mem as *const u8), 7, "{kind}");
                assert_eq!(ptr::read_volatile((mem + 3 * PAGE) as *const u8), 8, "{kind}");
                ptr::write_volatile((mem + 3 * PAGE) as *mut u8, 9);
                assert_eq!(ptr::read_volatile((mem + 3 * PAGE) as *const u8), 9, "{kind}");
            }
            release(a, ua);
            assert_eq!(munmap_of(mem, PAGE), 0, "{kind}");
            assert_eq!(munmap_of(mem + 3 * PAGE, PAGE), 0, "{kind}");
            assert!(find(mem).is_none(), "{kind}: the range outlived its mapping");
        }
    }

    /// A page written and then trimmed from the working set (to the
    /// modified list or the pagefile) before a register keeps its data and
    /// is not missing, as on Linux, where only a page with no pte is missing
    /// and a swapped page's pte holds its swap entry (v6.1 mm/memory.c
    /// `handle_pte_fault` :4950 to :4952 against :4957 to :4958): the move
    /// reads each committed, readable page out of the working set once and
    /// copies those that are not all zeros. Pages 1 and 2 written, page 3
    /// written with zeros, page 0 never touched; pages 1 to 3 trimmed with
    /// `VirtualUnlock` (Learn, VirtualUnlock: a range that is not locked is
    /// taken out of the working set), then, if any is still in it,
    /// `EmptyWorkingSet`, then, for any still in it, the move told so
    /// (`windows_mm::OUT_OF_THE_WORKING_SET`): TRIM lines say which did it,
    /// MOVEREAD lines the pages read (the cost). Pages 1 and 2 hold their
    /// data; pages 0 and 3 are missing, as a page never touched is on
    /// Linux (page 3, written with zeros, is not missing there: the one
    /// difference left, which reads the same once filled with zeros). For
    /// both kinds. Before, a page out of the working set was missing: the
    /// check "a written page out of the working set was taken as missing"
    /// fails there.
    #[test]
    fn test_a_written_page_out_of_the_working_set_is_not_missing_after_a_register() {
        let (code, text, _) = run_child_in_jobs("trimmed_page_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("TRIM") || l.starts_with("MOVEREAD") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_written_page_out_of_the_working_set_is_not_missing_after_a_register in a process of its own"]
    fn trimmed_page_child() {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        use windows_sys::Win32::System::ProcessStatus::K32EmptyWorkingSet;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        watchdog(60);
        let in_the_working_set = |at: u64| {
            let mut v = [0u8; 1];
            // SAFETY: one byte for one page of the test's mapping.
            assert_eq!(unsafe { crate::mincore(at as *mut c_void, PAGE as usize, v.as_mut_ptr()) }, 0);
            v[0] & 1 != 0
        };
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 4);
            // SAFETY: the test's own read-write memory.
            unsafe {
                ptr::write_volatile((mem + PAGE + 8) as *mut u8, 7);
                ptr::write_volatile((mem + 2 * PAGE + 16) as *mut u8, 9);
                ptr::write_volatile((mem + 3 * PAGE) as *mut u8, 0);
            }
            let written = [mem + PAGE, mem + 2 * PAGE, mem + 3 * PAGE];
            // SAFETY: pages of the test's mapping, not locked.
            unsafe { VirtualUnlock((mem + PAGE) as *mut c_void, 3 * PAGE as usize) };
            let by_unlock = written.iter().filter(|&&p| !in_the_working_set(p)).count();
            if written.iter().any(|&p| in_the_working_set(p)) {
                // SAFETY: the current process's pseudo handle.
                unsafe { K32EmptyWorkingSet(GetCurrentProcess()) };
            }
            let by_empty = written.iter().filter(|&&p| !in_the_working_set(p)).count() - by_unlock;
            let told: std::vec::Vec<u64> = written.iter().copied().filter(|&p| in_the_working_set(p)).collect();
            std::println!("TRIM {kind}: of 3 written pages, {by_unlock} out of the working set by VirtualUnlock, {by_empty} more by EmptyWorkingSet, {} told to the move", told.len());
            crate::windows_mm::OUT_OF_THE_WORKING_SET.lock().unwrap().extend(told.iter().map(|&p| p as usize));
            let read_before = crate::windows_mm::PAGES_READ_AT_A_MOVE.load(Ordering::SeqCst);
            let r = register(a, mem, 4 * PAGE);
            let read = crate::windows_mm::PAGES_READ_AT_A_MOVE.load(Ordering::SeqCst) - read_before;
            std::println!("MOVEREAD {kind}: {read} of 4 pages read at the register's move");
            c.check(r.is_ok(), std::format!("{kind}: the register: {r:?}"));
            c.check(
                !is_missing(mem + PAGE) && !is_missing(mem + 2 * PAGE),
                std::format!("{kind}: a written page out of the working set was taken as missing"),
            );
            if !is_missing(mem + PAGE) && !is_missing(mem + 2 * PAGE) {
                // SAFETY: registered pages holding memory.
                let (p1, p2) = unsafe { (ptr::read_volatile((mem + PAGE + 8) as *const u8), ptr::read_volatile((mem + 2 * PAGE + 16) as *const u8)) };
                c.check(p1 == 7 && p2 == 9, std::format!("{kind}: the trimmed pages read {p1}, {p2}"));
            }
            c.check(is_missing(mem), std::format!("{kind}: the page never touched is not missing"));
            c.check(is_missing(mem + 3 * PAGE), std::format!("{kind}: the page written with zeros is not missing"));
            release(a, ua);
            munmap_of(mem, 4 * PAGE);
        }
        c.done();
    }

    /// A register leaves each page the protection `mprotect` gave it, as
    /// Linux's register changes the vma's flags and never its protection
    /// (fs/userfaultfd.c, v6.1, `userfaultfd_register` :1434 and :1466 to
    /// :1467 set the userfaultfd bits of `vm_flags` and the context only;
    /// `vm_page_prot` is untouched): a resident page made
    /// read-only stays read-only (a missing page's protection asked is
    /// `test_a_filled_page_takes_the_protection_asked_while_it_was_missing`'s;
    /// a resident page made `PROT_NONE`,
    /// `test_a_resident_page_made_prot_none_keeps_its_contents_through_a_register`).
    /// Before, the register made the resident pages read-write. For both
    /// kinds.
    #[test]
    fn test_a_register_keeps_the_protection_mprotect_gave() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            for p in 0..2 {
                // SAFETY: the test's own read-write memory.
                unsafe { ptr::write_volatile((mem + p * PAGE) as *mut u8, 7) };
            }
            mprotect_of(mem, PAGE, crate::PROT_READ).unwrap();
            register(a, mem, UNMAP_LEN).unwrap();
            assert!(!is_missing(mem), "{kind}: the resident read-only page is missing");
            assert_eq!(committed_protection(mem), Some(PAGE_READONLY), "{kind}: the read-only page after the register");
            // SAFETY: read-only, readable.
            assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 7, "{kind}");
            release(a, ua);
        }
    }

    /// A resident page made `PROT_NONE` before a register keeps its
    /// contents and is not missing, as on Linux, where it stays in its vma
    /// and `mincore` counts it (mm/mincore.c, v6.1, `mincore_pte_range`
    /// :129 to :130: a present pte is in core, and x86's `pte_present`
    /// counts a `PROT_NONE` one, arch/x86/include/asm/pgtable.h :735 to
    /// :738), and
    /// the register changes no page (fs/userfaultfd.c `userfaultfd_register`
    /// :1466 to :1467). Here the register takes residency from `mincore`,
    /// whose working-set query does not count a `PAGE_NOACCESS` page
    /// (`QueryWorkingSetEx`'s `Valid`), so the page is taken as missing. For
    /// both kinds.
    #[test]
    #[ignore = "fails until a resident PAGE_NOACCESS page registers as resident on Windows (SECURITY.md, Not at parity yet)"]
    fn test_a_resident_page_made_prot_none_keeps_its_contents_through_a_register() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            // SAFETY: the test's own read-write memory.
            unsafe { ptr::write_volatile(mem as *mut u8, 7) };
            mprotect_of(mem, PAGE, crate::PROT_NONE).unwrap();
            register(a, mem, UNMAP_LEN).unwrap();
            assert!(!is_missing(mem), "{kind}: the resident PROT_NONE page is missing after the register");
            assert!(!host_readable(mem), "{kind}: the PROT_NONE page is readable after the register: {:x?}", states(mem, PAGE));
            mprotect_of(mem, PAGE, crate::PROT_READ).unwrap();
            // SAFETY: resident and readable now.
            assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 7, "{kind}");
            release(a, ua);
        }
    }

    /// A range's slot is kept, with no page registered, until its memory is
    /// unmapped ([`Range`]): unregistered whole, its pages are in no
    /// registration (not missing, a fill `ENOENT`) and the slot is still
    /// there, so that they register again; unmapped, the slot is freed. On
    /// Linux the vma is kept with no context after the unregister
    /// (fs/userfaultfd.c, v6.12, `userfaultfd_clear_vma` at :1522), and goes
    /// at the unmap. Before, the slot went at the unregister, and the
    /// memory, a section's views from then on, could not register again.
    /// For both kinds.
    #[test]
    fn test_a_ranges_slot_is_kept_until_its_memory_is_unmapped() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(a, mem, UNMAP_LEN).unwrap();
            assert_eq!(unregister(a, mem, PAGE), Ok(()), "{kind}");
            assert_eq!(unregister(a, mem + PAGE, UNMAP_LEN - PAGE), Ok(()), "{kind}");
            assert!(find(mem).is_some() && find(mem + UNMAP_LEN - PAGE).is_some(), "{kind}: the slot went with its last registered page");
            assert!(!is_missing(mem) && !is_missing(mem + PAGE), "{kind}: an unregistered page is missing");
            // SAFETY: a page.
            assert_eq!(unsafe { copy(a, page_of(1).as_ptr(), mem + PAGE, PAGE, true) }, Err((crate::ENOENT, 0)), "{kind}");
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0, "{kind}");
            assert!(find(mem).is_none() && find(mem + PAGE).is_none(), "{kind}: the slot is still held after the unmap");
            release(a, ua);
        }
    }

    /// Memory unregistered whole registers again, with the same userfaultfd
    /// and then another, and a fill lands in it: on Linux the unregister
    /// clears the vma's userfaultfd (fs/userfaultfd.c, v6.1,
    /// `userfaultfd_unregister` :1654 to :1655), so the vma is one no
    /// userfaultfd has, which `userfaultfd_register` takes (:1363 to :1366
    /// refuse only a vma another userfaultfd has). For both kinds.
    #[test]
    fn test_memory_unregistered_whole_registers_again() {
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let (b, ub) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(a, mem, UNMAP_LEN).unwrap();
            // SAFETY: a page.
            assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            assert_eq!(unregister(a, mem, UNMAP_LEN), Ok(()));
            let again = register(a, mem, UNMAP_LEN);
            std::println!("UNMAP {kind}: unregistered whole, its userfaultfd's register again: {again:?}");
            c.check(again.is_ok(), std::format!("{kind}: its userfaultfd's register again: {again:?}"));
            if again.is_ok() {
                // SAFETY: a page.
                let f = unsafe { copy(a, page_of(0x77).as_ptr(), mem + PAGE, PAGE, true) };
                c.check(f == Ok(PAGE), std::format!("{kind}: a fill after the register again: {f:?}"));
                // SAFETY: the page filled before the unregister, kept.
                c.check(unsafe { ptr::read_volatile(mem as *const u8) } == 0x5a, std::format!("{kind}: the page filled before"));
                c.check(unregister(a, mem, UNMAP_LEN).is_ok(), std::format!("{kind}: the second unregister"));
            }
            let other = register(b, mem, UNMAP_LEN);
            std::println!("UNMAP {kind}: unregistered whole, another userfaultfd's register: {other:?}");
            c.check(other.is_ok(), std::format!("{kind}: another userfaultfd's register: {other:?}"));
            release(a, ua);
            release(b, ub);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// Registered memory replaced by a shared anonymous mapping, a view of
    /// a section as the range's own memory is, is in no registration: the
    /// range is freed, the new pages are not missing, and a fill there is
    /// `ENOENT`, as Linux's for a destination in no registered vma
    /// (mm/userfaultfd.c, v6.12, `validate_dst_vma` :34, `ENOENT` at :113).
    /// A view counts as the range's only when it is marked so
    /// (`windows_mm::Kind::View`'s `uffd`), whatever its section handle.
    /// Unmapped then mapped again, and mapped over with `MAP_FIXED`; for
    /// both kinds.
    #[test]
    fn test_a_shared_mapping_over_registered_memory_is_in_no_registration() {
        let mut failed = std::vec::Vec::new();
        for how in ["UnmapThenMap", "MapFixedOver"] {
            for kind in MEM_KINDS {
                let (code, text, _) = run_child_in_jobs("shared_over_child", &[(REPLACE_CASE, how), ("WICK_UFFD_KIND", kind)], &[]);
                for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
                    std::eprintln!("{how}, {kind}: {l}");
                }
                if code != Some(0) {
                    failed.push(std::format!("{how}, {kind}: exit {code:x?}"));
                }
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    #[test]
    #[ignore = "run by test_a_shared_mapping_over_registered_memory_is_in_no_registration in processes of its own"]
    fn shared_over_child() {
        watchdog(60);
        let mut c = Checks::new();
        let how = std::env::var(REPLACE_CASE).unwrap();
        let kind = std::env::var("WICK_UFFD_KIND").unwrap();
        let (ctx, _user) = create(0, false, true).unwrap();
        let mem = map_of(&kind);
        register(ctx, mem, UNMAP_LEN).unwrap();
        // SAFETY: a page.
        assert_eq!(unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
        if how == "UnmapThenMap" {
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        // SAFETY: the test's own addresses.
        let p = unsafe {
            crate::mmap(
                mem as *mut c_void,
                UNMAP_LEN as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_SHARED | crate::MAP_ANONYMOUS | crate::MAP_FIXED,
                -1,
                0,
            )
        } as u64;
        std::println!("UNMAP shared over ({how}, {kind}): the new mapping at {p:#x} (the old at {mem:#x})");
        assert_eq!(p, mem, "{how}, {kind}: the new shared mapping: {}", io::Error::last_os_error());
        c.check(find(mem).is_none() && find(mem + PAGE).is_none(), "the range is still held over the shared mapping");
        c.check(!is_missing(mem) && !is_missing(mem + PAGE), "the shared mapping's pages are missing");
        let z = zeropage(ctx, mem + PAGE, PAGE, true);
        std::println!("UNMAP shared over: a zero page into the shared mapping: {z:?}");
        c.check(z == Err((crate::ENOENT, 0)), std::format!("a zero page into the shared mapping: {z:?}"));
        // SAFETY: a page.
        let f = unsafe { copy(ctx, page_of(0x77).as_ptr(), mem + 2 * PAGE, PAGE, true) };
        c.check(f == Err((crate::ENOENT, 0)), std::format!("a copy into the shared mapping: {f:?}"));
        // SAFETY: the new memory, read-write.
        unsafe { ptr::write_volatile((mem + 3 * PAGE) as *mut u8, 9) };
        // SAFETY: as above.
        let got = unsafe { ptr::read_volatile((mem + 3 * PAGE) as *const u8) };
        c.check(got == 9, std::format!("the shared mapping reads {got}"));
        c.done();
    }

    /// A discard of the new memory is an ordinary one: its pages read zeros
    /// and stay accessible, as Linux's `MADV_DONTNEED` of memory no
    /// userfaultfd has (mm/madvise.c, v6.12, `madvise_dontneed_free` :880,
    /// fs/userfaultfd.c :777 to :779, `madvise_dontneed_single_vma` :846).
    #[test]
    fn test_a_discard_of_memory_replaced_while_registered_is_ordinary() {
        replace_cases("replaced_discard_child");
    }

    #[test]
    #[ignore = "run by test_a_discard_of_memory_replaced_while_registered_is_ordinary in processes of its own"]
    fn replaced_discard_child() {
        watchdog(60);
        let mut c = Checks::new();
        let (_a, _ua, _b, _ub, mem) = replaced();
        // SAFETY: the new memory, read-write.
        unsafe { ptr::write_volatile(mem as *mut u8, 7) };
        // SAFETY: the new memory.
        c.check(unsafe { crate::madvise(mem as *mut c_void, 2 * PAGE as usize, crate::MADV_DONTNEED) } == 0, "the discard");
        c.check(!is_missing(mem) && !is_missing(mem + PAGE), "the discard made the new memory missing");
        c.check(host_readable(mem), std::format!("the discarded new memory is closed: {:x?}", states(mem, PAGE)));
        if host_readable(mem) {
            // SAFETY: readable.
            c.check(unsafe { ptr::read_volatile(mem as *const u8) } == 0, "the discarded page is not zeros");
        }
        c.done();
    }

    /// A thread waiting on a page whose memory is mapped over waits on (no
    /// event or wake comes of the unmapping without
    /// `UFFD_FEATURE_EVENT_UNMAP`) until its userfaultfd's `UFFDIO_WAKE`,
    /// which checks the range only (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_wake` :1545 to :1575), or its release, which wakes every
    /// waiter (`userfaultfd_release` :873); it then runs its access again,
    /// here on new memory, which it reads.
    #[test]
    fn test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd() {
        let (code, text, _) = run_child_in_jobs("waiter_mapped_over_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd in a process of its own"]
    fn waiter_mapped_over_child() {
        watchdog(60);
        let mut c = Checks::new();
        // Held for the child's time, so that the waiters' userfaultfd is not
        // the first (a waiter that recorded none would read as the first's).
        let _first = create(0, false, true).unwrap();
        for kind in MEM_KINDS {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            let waiter = |at: u64| {
                std::thread::spawn(move || {
                    assert!(fault(at, false), "not missing");
                    // SAFETY: the memory mapped over it, readable.
                    unsafe { ptr::read_volatile(at as *const u8) }
                })
            };
            let (first, second) = (waiter(mem), waiter(mem + PAGE));
            let waiting = |at: u64| WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == at);
            assert!(holds_within(|| waiting(mem) && waiting(mem + PAGE)), "{kind}: the waiters");
            assert_eq!(map_fixed(mem, UNMAP_LEN, crate::PROT_READ | crate::PROT_WRITE), mem, "{kind}");
            // SAFETY: the new memory, read-write.
            unsafe { ptr::write_bytes(mem as *mut u8, 7, 2 * PAGE as usize) };
            c.check(find(mem).is_none(), std::format!("{kind}: the memory mapped over is still registered"));
            c.check(!first.is_finished() && !second.is_finished(), std::format!("{kind}: a waiter went on with no wake"));
            let w = wake_range(ctx, mem, PAGE);
            c.check(w == Ok(()), std::format!("{kind}: UFFDIO_WAKE of the first page: {w:?}"));
            let woke = holds_within(|| first.is_finished());
            c.check(woke, std::format!("{kind}: the wake did not wake the first waiter"));
            c.check(!second.is_finished(), std::format!("{kind}: the wake of one page woke the other"));
            release(ctx, user);
            let woke2 = holds_within(|| second.is_finished());
            c.check(woke2, std::format!("{kind}: the release did not wake the second waiter"));
            if woke {
                c.check(first.join().unwrap() == 7, std::format!("{kind}: the first read"));
            }
            if woke2 {
                c.check(second.join().unwrap() == 7, std::format!("{kind}: the second read"));
            }
            if !(woke && woke2) {
                std::println!("UNMAP {kind}: a waiter was left waiting; the child ends here");
                c.done();
                return;
            }
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// A thread waiting on a page whose memory is unmapped, once its
    /// userfaultfd wakes it, runs its access again and takes the process's
    /// own fault, as on Linux, where the address has no vma: here an access
    /// violation no handler takes, which ends the child (0xC0000005).
    #[test]
    fn test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken() {
        for kind in MEM_KINDS {
            // In a job of the jailer's limits, as Firecracker runs: an
            // exception no handler takes ends the child with its code at
            // once, not after Windows Error Reporting.
            let (code, text, _) = run_child_watched("waiter_unmapped_child", &[("WICK_UFFD_KIND", kind)], true);
            for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
                std::eprintln!("{kind}: {l}");
            }
            assert_eq!(code, Some(0xC000_0005_u32.cast_signed()), "{kind}: {text}");
        }
    }

    #[test]
    #[ignore = "run by test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken in a process of its own"]
    fn waiter_unmapped_child() {
        in_the_job_if_asked();
        watchdog(20);
        let kind = std::env::var("WICK_UFFD_KIND").unwrap();
        // As in `waiter_mapped_over_child`: the waiter's userfaultfd is not
        // the first.
        let _first = create(0, false, true).unwrap();
        let (ctx, _user) = create(0, false, true).unwrap();
        let mem = map_of(&kind);
        register(ctx, mem, UNMAP_LEN).unwrap();
        let _reader = std::thread::spawn(move || {
            // SAFETY: registered memory: the read waits, then runs again.
            unsafe { ptr::read_volatile(mem as *const u8) }
        });
        assert!(holds_within(|| WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == mem)), "the waiter");
        assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        let w = wake_range(ctx, mem, PAGE);
        std::println!("UNMAP UFFDIO_WAKE of the unmapped page: {w:?}");
        std::thread::sleep(std::time::Duration::from_secs(5));
        let again = WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == mem);
        std::println!("UNMAP 5 s after the wake the reader is {}", if again { "waiting again on the unmapped page" } else { "not waiting" });
        std::process::exit(4);
    }

    /// Memory mapped over one page of a registered range and registered
    /// again by the same userfaultfd is filled in the new memory.
    #[test]
    #[ignore = "fails until a slot holds only registered pages on Windows (SECURITY.md, Not at parity yet: MAP_FIXED over part of a registered mapping is EINVAL)"]
    fn test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory() {
        let (code, text, _) = run_child_in_jobs("page_mapped_over_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory in a process of its own"]
    fn page_mapped_over_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            // SAFETY: a page.
            assert_eq!(unsafe { copy(ctx, page_of(0x11).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
            let p = map_fixed(mem + PAGE, PAGE, crate::PROT_READ | crate::PROT_WRITE);
            let err = io::Error::last_os_error();
            std::println!("UNMAP {kind}: MAP_FIXED over one registered page: {p:#x} ({})", if p == mem + PAGE { "made".into() } else { std::format!("{err}") });
            c.check(p == mem + PAGE, std::format!("{kind}: MAP_FIXED over one registered page: {err}"));
            if p == mem + PAGE {
                c.check(!is_missing(mem + PAGE) && !is_missing(mem), std::format!("{kind}: missing after the MAP_FIXED"));
                let z = zeropage(ctx, mem + PAGE, PAGE, true);
                c.check(z == Err((crate::ENOENT, 0)), std::format!("{kind}: a fill of the new page: {z:?}"));
                let r = register(ctx, mem + PAGE, PAGE);
                c.check(r.is_ok(), std::format!("{kind}: the register of the new page: {r:?}"));
                if r.is_ok() {
                    c.check(is_missing(mem + PAGE), std::format!("{kind}: the new page is not missing"));
                    // SAFETY: a page.
                    let f = unsafe { copy(ctx, page_of(0x77).as_ptr(), mem + PAGE, PAGE, true) };
                    c.check(f == Ok(PAGE), std::format!("{kind}: the fill of the new page: {f:?}"));
                    // SAFETY: filled pages.
                    unsafe {
                        c.check(ptr::read_volatile((mem + PAGE) as *const u8) == 0x77, std::format!("{kind}: the fill did not reach the new memory"));
                        c.check(ptr::read_volatile(mem as *const u8) == 0x11, std::format!("{kind}: the first page changed"));
                    }
                }
            }
            release(ctx, user);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// A munmap or a `MAP_FIXED` mapping that cuts a huge page of a
    /// registered huge page range is `EINVAL` with nothing changed (Linux
    /// refuses to split a hugetlb vma off a huge page boundary, mm/vma.c,
    /// v6.12, `__split_vma` :377 to :378, called by `vms_gather_munmap_vmas`
    /// at :1209 and :1230); on the boundaries, the huge pages leave the
    /// registration.
    #[test]
    #[ignore = "no registered huge page on Windows (docs/COMPATIBILITY.md, the mem_backend Uffd row: a huge page mapping is not registered)"]
    fn test_a_cut_of_a_registered_huge_page_is_einval() {
        let (code, text, _) = run_child_in_jobs("huge_cut_child", &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("UNMAP") || l.starts_with("WATCHDOG")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_cut_of_a_registered_huge_page_is_einval in a process of its own"]
    fn huge_cut_child() {
        const HUGE: u64 = 2 << 20;
        watchdog(60);
        let mut c = Checks::new();
        let (ctx, user) = create(0, false, true).unwrap();
        let len = 2 * HUGE;
        // SAFETY: a huge page mapping of this libc.
        let mem = unsafe {
            crate::mmap(
                ptr::null_mut(),
                len as usize,
                crate::PROT_READ | crate::PROT_WRITE,
                crate::MAP_PRIVATE | crate::MAP_ANONYMOUS | crate::MAP_HUGETLB | crate::MAP_HUGE_2MB,
                -1,
                0,
            )
        } as u64;
        let err = io::Error::last_os_error();
        std::println!("UNMAP the huge page mapping: {}", if mem == crate::MAP_FAILED as u64 { std::format!("{err}") } else { std::format!("{mem:#x}") });
        assert_ne!(mem, crate::MAP_FAILED as u64, "the huge page mapping: {err}");
        let r = register(ctx, mem, len);
        std::println!("UNMAP the register of the huge page mapping: {r:?}");
        c.check(r.is_ok(), std::format!("the register of a huge page mapping: {r:?}"));
        if r.is_ok() {
            c.check(munmap_of(mem + PAGE, PAGE) == -1 && io::Error::last_os_error().raw_os_error() == Some(crate::EINVAL), "munmap of a page inside");
            c.check(map_fixed(mem + HUGE - PAGE, 2 * PAGE, crate::PROT_READ | crate::PROT_WRITE) == crate::MAP_FAILED as u64, "MAP_FIXED across a huge page boundary");
            for off in [0, PAGE, HUGE - PAGE, HUGE, len - PAGE] {
                c.check(is_missing(mem + off), std::format!("{off:#x}: changed by a refused call"));
            }
            c.check(munmap_of(mem + HUGE, HUGE) == 0, "munmap of the second huge page");
            c.check(is_missing(mem) && !is_missing(mem + HUGE), "the second huge page is still registered");
            let z = zeropage(ctx, mem + HUGE, HUGE, true);
            c.check(z == Err((crate::ENOENT, 0)), std::format!("a fill of the unmapped huge page: {z:?}"));
        }
        release(ctx, user);
        c.done();
    }

    /// A fill whose destination holds a page in no registration is
    /// `ENOENT` for the whole call, nothing filled (mm/userfaultfd.c, v6.12,
    /// `validate_dst_vma` :23 to :37, `uffd_mfill_lock` :113: the
    /// destination must lie in one vma this userfaultfd has; an unregister
    /// of a page in the middle splits the vma).
    #[test]
    fn test_a_fill_of_an_unregistered_page_is_enoent() {
        for kind in MEM_KINDS {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            register(ctx, mem, UNMAP_LEN).unwrap();
            assert_eq!(unregister(ctx, mem + PAGE, PAGE), Ok(()));
            let data = std::vec![0x5au8; 3 * PAGE as usize];
            // SAFETY: `data` holds three pages.
            let f = unsafe { copy(ctx, data.as_ptr(), mem, 3 * PAGE, true) };
            let still = is_missing(mem);
            release(ctx, user);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
            assert_eq!(f, Err((crate::ENOENT, 0)), "{kind}: the fill across the unregistered page");
            assert!(still, "{kind}: the page before it was filled");
        }
    }

    // ---- The changes of memory and the register, and the unmapping and its
    // unregistration, as one step each (the macOS backend's tests of the
    // same names).

    /// The registers that found a change of memory running without the lock
    /// ([`unlocked_change`]) and waited for it.
    pub(super) static REGISTER_WAITS: AtomicUsize = AtomicUsize::new(0);

    /// [`register`]'s close of its missing runs on a range not on a reserved
    /// section: the run of this number (from 1) fails, as if `VirtualProtect`
    /// had refused it; 0 for none.
    pub(super) static CLOSE_FAILS_AT: AtomicUsize = AtomicUsize::new(0);

    /// [`register`]'s giving of a resident run its protection, before the
    /// range is published, fails, as if `VirtualProtect` had refused it.
    pub(super) static PROTECTION_FAILS: AtomicBool = AtomicBool::new(false);

    /// A register that cannot give a page that holds memory the protection
    /// `mprotect` gave it (the section's view is mapped read-write, and the
    /// register gives each resident run its protection back before it
    /// publishes the range) ends the process with a line: else the page
    /// would stay readable and writable where `mprotect` made it read-only,
    /// in memory the register said it did not take. Both kinds of section:
    /// a reserved one (the exception handler's) and one that is not.
    #[test]
    fn test_a_register_that_cannot_protect_a_resident_page_ends_the_process() {
        let mut failed = std::vec::Vec::new();
        for kind in ["reserved", "unreserved"] {
            let (code, text, _) = run_child_in_jobs("protection_fails_child", &[("WICK_UFFD_ALIAS", kind)], &[]);
            for l in text.lines().filter(|l| l.starts_with("PROTFAIL") || l.starts_with("wick:") || l.starts_with("WATCHDOG")) {
                std::eprintln!("{kind}: {l}");
            }
            let line = text.contains("wick: userfaultfd: a register could not give");
            if !line || code == Some(0) || code == Some(3) {
                failed.push(std::format!("{kind}: exit {code:x?}, the line {line}"));
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    #[test]
    #[ignore = "run by test_a_register_that_cannot_protect_a_resident_page_ends_the_process in processes of its own"]
    fn protection_fails_child() {
        const PAGES: u64 = 8;
        watchdog(60);
        if std::env::var("WICK_UFFD_ALIAS").as_deref() == Ok("unreserved") {
            crate::windows_mm::UFFD_UNRESERVED.store(true, Ordering::SeqCst);
        }
        let (a, _ua) = create(0, false, true).unwrap();
        let mem = map((PAGES * PAGE) as usize);
        // Pages 0 to 3 hold memory, 2 and 3 read-only; 4 to 7 are missing.
        for page in 0..4 {
            // SAFETY: a page of the test's own mapping.
            unsafe { ptr::write_volatile((mem + page * PAGE) as *mut u8, 0x40 + page as u8) };
        }
        mprotect_of(mem + 2 * PAGE, 2 * PAGE, crate::PROT_READ).unwrap();
        PROTECTION_FAILS.store(true, Ordering::SeqCst);
        let r = register(a, mem, PAGES * PAGE);
        PROTECTION_FAILS.store(false, Ordering::SeqCst);
        std::println!("PROTFAIL the register returned: {r:?}");
        let states = states(mem, PAGES * PAGE);
        for page in 0..PAGES {
            let at = mem + page * PAGE;
            let owner = find(at).and_then(|(r, p)| r.owner(p));
            std::println!("PROTFAIL page {page}: missing {}, owner {owner:?}, state {:#x}, protection {:#x}", is_missing(at), states[page as usize].0, states[page as usize].1);
        }
        let again = register(a, mem, PAGES * PAGE);
        std::println!("PROTFAIL the same memory registered again: {again:?}");
        // Last: a read of a missing page, which may end the process.
        // SAFETY: a page of the test's own mapping.
        let b = unsafe { ptr::read_volatile((mem + 5 * PAGE) as *const u8) };
        std::println!("PROTFAIL a missing page read: {b:#x}");
    }

    /// [`register`], after a close failed: its reopening fails too.
    pub(super) static REOPEN_FAILS: AtomicBool = AtomicBool::new(false);

    /// The error [`CLOSE_FAILS_AT`] and [`REOPEN_FAILS`] give.
    pub(super) fn refused() -> io::Error {
        io::Error::from_raw_os_error(windows_sys::Win32::Foundation::ERROR_COMMITMENT_LIMIT.cast_signed())
    }

    /// A register on a range not on a reserved section (the section of a
    /// process whose exception handler could not be added:
    /// `windows_mm::UFFD_UNRESERVED`) whose close of its second missing run
    /// fails, after the range is published, returns that error with the
    /// range in no registration: no page missing or any userfaultfd's, each
    /// readable with what it held (a missing one zeros), a fill `ENOENT`, and
    /// the same memory registers again, as memory unregistered whole does
    /// (`test_memory_unregistered_whole_registers_again`). Linux's register
    /// changes no page's protection, so it has no such failure. In a process
    /// of its own, as it changes how the process's ranges are made.
    #[test]
    fn test_a_register_whose_close_fails_leaves_the_range_in_no_registration() {
        let (code, text) = run_child("close_fails_child", None);
        for l in text.lines().filter(|l| l.starts_with("CLOSEFAIL") || l.starts_with("UNMAPCHECK") || l.starts_with("wick:")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_register_whose_close_fails_leaves_the_range_in_no_registration in a process of its own"]
    fn close_fails_child() {
        const PAGES: u64 = 8;
        watchdog(60);
        crate::windows_mm::UFFD_UNRESERVED.store(true, Ordering::SeqCst);
        let (a, ua) = create(0, false, true).unwrap();
        let mem = map((PAGES * PAGE) as usize);
        // Pages 0, 2 and 4 hold memory: the missing runs are 1, 3 and 5 to 7.
        let held = |page: u64| page < 6 && page.is_multiple_of(2);
        for page in (0..PAGES).filter(|&p| held(p)) {
            // SAFETY: a page of the test's own mapping.
            unsafe { ptr::write_volatile((mem + page * PAGE) as *mut u8, 0x40 + page as u8) };
        }
        CLOSE_FAILS_AT.store(2, Ordering::SeqCst);
        let r = register(a, mem, PAGES * PAGE);
        CLOSE_FAILS_AT.store(0, Ordering::SeqCst);
        std::println!("CLOSEFAIL the register whose second close fails: {r:?}");
        let mut c = Checks::new();
        let code = r.as_ref().err().and_then(io::Error::raw_os_error);
        c.check(code == refused().raw_os_error(), std::format!("the register: {r:?}"));
        let states = states(mem, PAGES * PAGE);
        for page in 0..PAGES {
            let at = mem + page * PAGE;
            let owner = find(at).and_then(|(r, p)| r.owner(p));
            std::println!("CLOSEFAIL page {page}: missing {}, owner {owner:?}, protection {:#x}", is_missing(at), states[page as usize].1);
            c.check(!is_missing(at), std::format!("page {page} is missing"));
            c.check(owner.is_none(), std::format!("page {page} is userfaultfd {owner:?}'s"));
            c.check(states[page as usize].1 == PAGE_READWRITE, std::format!("page {page}'s protection {:#x}", states[page as usize].1));
            if states[page as usize].1 == PAGE_READWRITE {
                // SAFETY: a page of the test's own mapping, readable.
                let b = unsafe { ptr::read_volatile(at as *const u8) };
                let want = if held(page) { 0x40 + page as u8 } else { 0 };
                c.check(b == want, std::format!("page {page} reads {b:#x}, not {want:#x}"));
            }
        }
        // SAFETY: a page.
        let f = unsafe { copy(a, page_of(0x77).as_ptr(), mem + PAGE, PAGE, true) };
        c.check(f == Err((crate::ENOENT, 0)), std::format!("a fill after the register: {f:?}"));
        let again = register(a, mem, PAGES * PAGE);
        std::println!("CLOSEFAIL the same memory registered again: {again:?}");
        c.check(again.is_ok(), std::format!("the register again: {again:?}"));
        if again.is_ok() {
            // Not on a reserved section, every page registered again holds
            // memory ([`register_again`]): none is missing.
            let missing: std::vec::Vec<u64> = (0..PAGES).filter(|&p| is_missing(mem + p * PAGE)).collect();
            std::println!("CLOSEFAIL registered again, the pages missing: {missing:?}");
            c.check(missing.is_empty(), std::format!("pages missing after the register again: {missing:?}"));
            c.check(unregister(a, mem, PAGES * PAGE).is_ok(), "the unregister after the register again");
        }
        release(a, ua);
        assert_eq!(munmap_of(mem, PAGES * PAGE), 0);
        c.done();
    }

    /// A register whose close fails and whose reopening fails too ends the
    /// process with a line: its pages would be closed, or read as zeros
    /// though missing, in a range it reports as not registered.
    #[test]
    fn test_a_register_whose_reopening_fails_ends_the_process() {
        let (code, text) = run_child("reopen_fails_child", None);
        for l in text.lines().filter(|l| l.starts_with("CLOSEFAIL") || l.starts_with("wick:")) {
            std::eprintln!("{l}");
        }
        assert!(code.is_some_and(|c| c != 0 && c != 3), "{code:x?} {text}");
        assert!(text.contains("wick: userfaultfd: a register could not reopen"), "{code:x?} {text}");
    }

    #[test]
    #[ignore = "run by test_a_register_whose_reopening_fails_ends_the_process in a process of its own"]
    fn reopen_fails_child() {
        watchdog(60);
        crate::windows_mm::UFFD_UNRESERVED.store(true, Ordering::SeqCst);
        let (a, _ua) = create(0, false, true).unwrap();
        let mem = map((4 * PAGE) as usize);
        // SAFETY: a page of the test's own mapping.
        unsafe { ptr::write_volatile((mem + PAGE) as *mut u8, 1) };
        CLOSE_FAILS_AT.store(2, Ordering::SeqCst);
        REOPEN_FAILS.store(true, Ordering::SeqCst);
        let r = register(a, mem, 4 * PAGE);
        std::println!("CLOSEFAIL the register returned: {r:?}");
    }

    /// What [`unlocked_change`] calls between its check and the change: a
    /// test's own.
    static CHANGE_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

    pub(super) fn change_hook() {
        let hook = *CHANGE_HOOK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(hook) = hook {
            hook();
        }
    }

    /// What [`unmapping`] calls between the change of the mapping and the
    /// unregistration, under [`LOCK`], with the range: a test's own.
    type UnmapHook = fn(u64, u64);
    static UNMAP_HOOK: Mutex<Option<UnmapHook>> = Mutex::new(None);

    pub(super) fn unmap_hook(start: u64, end: u64) {
        let hook = *UNMAP_HOOK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(hook) = hook {
            hook(start, end);
        }
    }

    /// The register [`register_in_the_change`] starts, and its thread.
    static RACE_REGISTER: Mutex<Option<(usize, u64, u64)>> = Mutex::new(None);
    static RACE_THREAD: Mutex<Option<std::thread::JoinHandle<io::Result<()>>>> = Mutex::new(None);

    /// The hook of the register race tests, between a change's check and
    /// the change (the first such change once armed): a register of the
    /// test's range on a thread of its own; it goes on once the register
    /// waits for the change ([`REGISTER_WAITS`]) or is done, so that, with
    /// no timing, either the register waits and reads the memory the change
    /// left, or it ran first, inside the change's window.
    fn register_in_the_change() {
        let Some((ctx, start, len)) = RACE_REGISTER.lock().unwrap().take() else {
            return;
        };
        let waits = REGISTER_WAITS.load(Ordering::SeqCst);
        let thread = std::thread::spawn(move || register(ctx, start, len));
        let waited = holds_within(|| thread.is_finished() || REGISTER_WAITS.load(Ordering::SeqCst) > waits);
        std::println!(
            "RACE the register {}",
            if REGISTER_WAITS.load(Ordering::SeqCst) > waits {
                "waits for the change"
            } else if waited {
                "was done inside the change's window"
            } else {
                "neither waited nor ended in 10 s"
            }
        );
        *RACE_THREAD.lock().unwrap() = Some(thread);
    }

    /// Runs `change` with a register of `[start, start + len)` by `ctx`
    /// started between its check and the change; the register's result.
    fn register_racing(ctx: usize, start: u64, len: u64, change: impl FnOnce()) -> io::Result<()> {
        *RACE_REGISTER.lock().unwrap() = Some((ctx, start, len));
        *CHANGE_HOOK.lock().unwrap() = Some(register_in_the_change);
        change();
        *CHANGE_HOOK.lock().unwrap() = None;
        let thread = RACE_THREAD.lock().unwrap().take().expect("the change did not run without the lock");
        thread.join().unwrap()
    }

    /// Runs `child` in a process of its own (nothing else maps in its
    /// holes) and asserts it ended with 0, its RACE and UNMAP lines shown.
    fn in_a_child(child: &str) {
        let (code, text, _) = run_child_in_jobs(child, &[], &[]);
        for l in text.lines().filter(|l| l.starts_with("RACE") || l.starts_with("UNMAP") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
            std::eprintln!("{l}");
        }
        assert_eq!(code, Some(0), "{text}");
    }

    /// The page a write during a register's move goes to
    /// ([`write_during_the_move`]), and the writer's thread with whether it
    /// was still waiting when the hook went on.
    static MOVE_WRITE_AT: AtomicU64 = AtomicU64::new(0);
    static MOVE_WRITER: Mutex<Option<(std::thread::JoinHandle<()>, bool)>> = Mutex::new(None);
    /// The accesses that began waiting in [`fault`] for a moving mark.
    pub(super) static MOVE_WAITING: AtomicU64 = AtomicU64::new(0);

    /// [`crate::windows_mm::ALIAS_HOOK`]: a thread writes 2 to the page at
    /// [`MOVE_WRITE_AT`] once the register's copy of its pages is made and
    /// before the private allocation is given back; the hook goes on once
    /// the write waits for the move, or is done.
    fn write_during_the_move() {
        let at = MOVE_WRITE_AT.load(Ordering::SeqCst);
        let before = MOVE_WAITING.load(Ordering::SeqCst);
        // SAFETY: a page of the test's own mapping.
        let writer = std::thread::spawn(move || unsafe { ptr::write_volatile(at as *mut u8, 2) });
        until(|| MOVE_WAITING.load(Ordering::SeqCst) > before || writer.is_finished());
        let waiting = !writer.is_finished();
        *MOVE_WRITER.lock().unwrap() = Some((writer, waiting));
    }

    /// A write to registered memory made while the register moves it into
    /// its sections (after its pages are copied, before the private
    /// allocation is given back) lands in the registered memory: the move
    /// makes the mapping read-only first and marks it moving, so the write
    /// faults, waits for the register, and runs again on the views. Linux's
    /// register moves nothing, so the write simply lands. For both kinds of
    /// mapping, through the chunked sections (the exception handler's) and
    /// through one section (`WICK_UFFD_ALIAS=unreserved`). Before, the
    /// write landed in the private page after its copy, and the page read
    /// back the value from before it (1, not 2): the check "the write made
    /// during the move was lost" fails there.
    #[test]
    fn test_a_write_during_a_registers_move_lands_in_the_registered_memory() {
        for alias in ["reserved", "unreserved"] {
            let (code, text, _) = run_child_in_jobs("write_during_the_move_child", &[("WICK_UFFD_ALIAS", alias)], &[]);
            for l in text.lines().filter(|l| l.starts_with("UNMAPCHECK") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
                std::eprintln!("{alias}: {l}");
            }
            assert_eq!(code, Some(0), "{alias}: {text}");
        }
    }

    #[test]
    #[ignore = "run by test_a_write_during_a_registers_move_lands_in_the_registered_memory in processes of its own"]
    fn write_during_the_move_child() {
        watchdog(60);
        if std::env::var("WICK_UFFD_ALIAS").as_deref() == Ok("unreserved") {
            crate::windows_mm::UFFD_UNRESERVED.store(true, Ordering::SeqCst);
        }
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 4);
            // SAFETY: a page of the test's own mapping: resident, so copied.
            unsafe { ptr::write_volatile(mem as *mut u8, 1) };
            MOVE_WRITE_AT.store(mem, Ordering::SeqCst);
            crate::windows_mm::ALIAS_HOOK.store(write_during_the_move as fn() as usize, Ordering::SeqCst);
            let r = register(a, mem, 4 * PAGE);
            let Some((writer, waiting)) = MOVE_WRITER.lock().unwrap().take() else {
                c.check(false, std::format!("{kind}: the hook did not run ({r:?})"));
                release(a, ua);
                continue;
            };
            writer.join().unwrap();
            c.check(r.is_ok(), std::format!("{kind}: the register: {r:?}"));
            c.check(waiting, std::format!("{kind}: the write went through while the register moved the memory"));
            // SAFETY: page 0, resident, registered and not missing.
            let value = unsafe { ptr::read_volatile(mem as *const u8) };
            c.check(value == 2, std::format!("{kind}: the write made during the move was lost: the page reads {value}"));
            c.check(!is_missing(mem), std::format!("{kind}: the written page is missing"));
            release(a, ua);
            munmap_of(mem, 4 * PAGE);
        }
        c.done();
    }

    /// A write made as a register starts its move (a hook right before the
    /// mapping is closed for it, `windows_mm::NARROW_HOOK`) to a page never
    /// touched is kept: the register reads the pages' residency only once
    /// the mapping is closed, so a write before that makes the page resident
    /// and copied (an ordinary mapping's committed page: the write ends at
    /// once), and a first touch after it waits for the register and then
    /// faults as missing (a lazy page: the test fills it with zeros, which
    /// wakes the writer, whose write then lands). Linux's register takes the
    /// page as it is when the register holds the mm's lock: present, or
    /// missing and faulted. For both kinds. Before, residency was read
    /// before the hook's point, so the written page was taken as missing and
    /// not copied: it read 0 after the fill, and the check "the write made
    /// as the move started was lost" fails there.
    #[test]
    fn test_a_write_made_as_a_register_starts_its_move_is_kept() {
        in_a_child("write_as_the_move_starts_child");
    }

    #[test]
    #[ignore = "run by test_a_write_made_as_a_register_starts_its_move_is_kept in a process of its own"]
    fn write_as_the_move_starts_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 4);
            // Page 3 is never touched before the hook's write.
            MOVE_WRITE_AT.store(mem + 3 * PAGE, Ordering::SeqCst);
            crate::windows_mm::NARROW_HOOK.store(write_during_the_move as fn() as usize, Ordering::SeqCst);
            let r = register(a, mem, 4 * PAGE);
            c.check(r.is_ok(), std::format!("{kind}: the register: {r:?}"));
            let Some((writer, waiting)) = MOVE_WRITER.lock().unwrap().take() else {
                c.check(false, std::format!("{kind}: the hook did not run ({r:?})"));
                release(a, ua);
                continue;
            };
            std::println!("RACE {kind}: the write waited for the register: {waiting}; the page is missing after it: {}", is_missing(mem + 3 * PAGE));
            if is_missing(mem + 3 * PAGE) {
                c.check(zeropage(a, mem + 3 * PAGE, PAGE, true) == Ok(PAGE), std::format!("{kind}: the fill of the missing page"));
            }
            writer.join().unwrap();
            // SAFETY: page 3, filled or holding memory.
            let value = unsafe { ptr::read_volatile((mem + 3 * PAGE) as *const u8) };
            c.check(value == 2, std::format!("{kind}: the write made as the move started was lost: the page reads {value}"));
            release(a, ua);
            munmap_of(mem, 4 * PAGE);
        }
        c.done();
    }

    /// A register waits for a system call that is in its copy into or out
    /// of the memory (counted in flight: `windows_mm::copying`, as a block
    /// device's read into guest memory is, `windows_fd::read`), and only
    /// then moves it: the kernel's copy takes no exception this process
    /// could resolve, so a copy into the memory while it was read-only or a
    /// placeholder would fail, or land in the private pages after their
    /// copy and be lost. Linux's register moves nothing and does not wait.
    /// Before, the register did not wait: the check "the register moved the
    /// memory while a system call copied into it" fails there.
    #[test]
    fn test_a_register_waits_for_a_call_copying_into_its_memory() {
        in_a_child("register_waits_for_a_copy_child");
    }

    #[test]
    #[ignore = "run by test_a_register_waits_for_a_call_copying_into_its_memory in a process of its own"]
    fn register_waits_for_a_copy_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 4);
            // A call into page 1, in its copy.
            let call = crate::windows_mm::copying((mem + PAGE) as usize, PAGE as usize);
            call.copy_now();
            let waited = crate::windows_mm::CLAIMS_THAT_WAITED.load(Ordering::SeqCst);
            let reg = std::thread::spawn(move || register(a, mem, 4 * PAGE));
            until(|| crate::windows_mm::CLAIMS_THAT_WAITED.load(Ordering::SeqCst) > waited || reg.is_finished());
            c.check(!reg.is_finished(), std::format!("{kind}: the register moved the memory while a system call copied into it"));
            drop(call);
            let r = reg.join().unwrap();
            c.check(r.is_ok(), std::format!("{kind}: the register after the call: {r:?}"));
            release(a, ua);
            munmap_of(mem, 4 * PAGE);
        }
        c.done();
    }

    /// A register whose move fails before the private allocation is given
    /// back (its release refused, `windows_mm::MOVE_RELEASE_REFUSED`) gives
    /// the runs it made read-only for the move their protection back: the
    /// register fails (`EINVAL`), nothing is registered, and the memory
    /// holds what it held and takes writes. For both kinds of mapping,
    /// through the chunked sections and through one section. A guard of the
    /// restore that [`test_a_refused_reopen_after_a_failed_move_ends_the_process`]
    /// makes fatal: the parent commit, which gave the protection back too,
    /// passes it.
    #[test]
    fn test_a_failed_registers_move_gives_the_memory_back_writable() {
        for alias in ["reserved", "unreserved"] {
            let (code, text, _) = run_child_in_jobs("failed_move_child", &[("WICK_UFFD_ALIAS", alias)], &[]);
            for l in text.lines().filter(|l| l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
                std::eprintln!("{alias}: {l}");
            }
            assert_eq!(code, Some(0), "{alias}: {text}");
        }
    }

    #[test]
    #[ignore = "run by test_a_failed_registers_move_gives_the_memory_back_writable in processes of its own"]
    fn failed_move_child() {
        watchdog(60);
        if std::env::var("WICK_UFFD_ALIAS").as_deref() == Ok("unreserved") {
            crate::windows_mm::UFFD_UNRESERVED.store(true, Ordering::SeqCst);
        }
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 4);
            // SAFETY: a page of the test's own mapping: resident, so narrowed.
            unsafe { ptr::write_volatile(mem as *mut u8, 1) };
            crate::windows_mm::MOVE_RELEASE_REFUSED.store(true, Ordering::SeqCst);
            let r = register(a, mem, 4 * PAGE);
            c.check(
                r.as_ref().map_err(io::Error::raw_os_error) == Err(Some(crate::EINVAL)),
                std::format!("{kind}: the register whose move failed: {r:?}"),
            );
            c.check(find(mem).is_none(), std::format!("{kind}: registered after a failed move"));
            // SAFETY: page 0 of the test's mapping, which the failed move
            // left as it was.
            let value = unsafe { ptr::read_volatile(mem as *const u8) };
            c.check(value == 1, std::format!("{kind}: the page reads {value} after the failed move"));
            // SAFETY: as above; a write the narrowed run would refuse.
            unsafe { ptr::write_volatile(mem as *mut u8, 3) };
            // SAFETY: as above.
            let value = unsafe { ptr::read_volatile(mem as *const u8) };
            c.check(value == 3, std::format!("{kind}: the write after the failed move reads back {value}"));
            release(a, ua);
            munmap_of(mem, 4 * PAGE);
        }
        c.done();
    }

    /// A register whose move fails before the private allocation is given
    /// back, and whose restore of the runs the move made read-only is then
    /// refused (`windows_mm::REOPEN_REFUSED`), ends the process there with a
    /// line naming the run: the run would stay read-only while the process
    /// holds it writable, so a later write would fault outside any move and
    /// end the process far from the cause, or a system call's copy into it
    /// would fail. Before, the refusal was ignored and the register failed
    /// with `EINVAL`: the child returned, and the check "not aborted" fails
    /// there (with the two refusals at the same points).
    #[test]
    fn test_a_refused_reopen_after_a_failed_move_ends_the_process() {
        let (code, text) = run_child("refused_reopen_child", None);
        assert!(text.contains("wick: userfaultfd: a register's move could not give its pages"), "{text}");
        assert_eq!(code, Some(0xC000_0409_u32.cast_signed()), "not aborted: {text}");
    }

    #[test]
    #[ignore = "run by test_a_refused_reopen_after_a_failed_move_ends_the_process in a process of its own"]
    fn refused_reopen_child() {
        watchdog(60);
        let (a, _ua) = create(0, false, true).unwrap();
        let mem = map_pages("ordinary", 4);
        // SAFETY: a page of the test's own mapping: resident, so narrowed.
        unsafe { ptr::write_volatile(mem as *mut u8, 1) };
        crate::windows_mm::MOVE_RELEASE_REFUSED.store(true, Ordering::SeqCst);
        crate::windows_mm::REOPEN_REFUSED.store(true, Ordering::SeqCst);
        let r = register(a, mem, 4 * PAGE);
        std::println!("the register returned: {r:?}");
    }

    /// A register that starts while an `munmap` of the memory runs without
    /// the lock (it found no registered range) finds the memory gone:
    /// `EINVAL` (a mapping lies above, Windows' own), nothing registered, as
    /// on Linux, where the mm's lock orders the two and a register over no
    /// vma is `EINVAL` when a vma lies past the range (fs/userfaultfd.c,
    /// v6.1, `userfaultfd_register` :1323 to :1330). Without the order, the
    /// register took the memory before the `munmap`, which then left it
    /// registered over memory that is gone.
    #[test]
    fn test_a_register_racing_a_munmap_leaves_nothing_registered() {
        in_a_child("register_racing_munmap_child");
    }

    #[test]
    #[ignore = "run by test_a_register_racing_a_munmap_leaves_nothing_registered in a process of its own"]
    fn register_racing_munmap_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            let r = register_racing(a, mem, UNMAP_LEN, || assert_eq!(munmap_of(mem, UNMAP_LEN), 0));
            std::println!("RACE {kind}: the register: {r:?}");
            c.check(find(mem).is_none(), std::format!("{kind}: registered over memory that is gone ({r:?})"));
            c.check(r.as_ref().map_err(io::Error::raw_os_error) == Err(Some(crate::EINVAL)), std::format!("{kind}: the register: {r:?}"));
            release(a, ua);
        }
        c.done();
    }

    /// A register that starts while a `MAP_FIXED` mapping over the memory
    /// runs without the lock registers the new memory: its pages missing,
    /// a fill lands in it. Without the order the register took the old
    /// memory (a written page present, the alias over the old pages), and
    /// the mapping then replaced it under the registration.
    #[test]
    fn test_a_register_racing_a_map_fixed_registers_the_new_memory() {
        in_a_child("register_racing_map_fixed_child");
    }

    #[test]
    #[ignore = "run by test_a_register_racing_a_map_fixed_registers_the_new_memory in a process of its own"]
    fn register_racing_map_fixed_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            // SAFETY: the test's mapping, before any register.
            unsafe { ptr::write_volatile(mem as *mut u8, 1) };
            let r = register_racing(a, mem, UNMAP_LEN, || {
                assert_eq!(map_fixed(mem, UNMAP_LEN, crate::PROT_READ | crate::PROT_WRITE), mem);
            });
            std::println!("RACE {kind}: the register: {r:?}");
            c.check(r.is_ok(), std::format!("{kind}: the register: {r:?}"));
            c.check(is_missing(mem) && is_missing(mem + PAGE), std::format!("{kind}: the new memory is not what was registered"));
            if r.is_ok() && is_missing(mem) {
                // SAFETY: a page.
                let f = unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) };
                c.check(f == Ok(PAGE), std::format!("{kind}: the fill: {f:?}"));
                if f == Ok(PAGE) {
                    // SAFETY: filled just now.
                    c.check(unsafe { ptr::read_volatile(mem as *const u8) } == 0x5a, std::format!("{kind}: the fill went elsewhere"));
                }
                c.check(unregister(a, mem, UNMAP_LEN) == Ok(()), std::format!("{kind}: the unregister"));
            }
            release(a, ua);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// A register that starts while an `mprotect` of the memory runs without
    /// the lock keeps its pages missing and inaccessible, with the
    /// protection asked recorded: an unregister gives the page that
    /// protection. Without the order the `mprotect` came after the register
    /// and its protection was lost.
    #[test]
    fn test_a_register_racing_an_mprotect_keeps_its_pages_missing() {
        in_a_child("register_racing_mprotect_child");
    }

    #[test]
    #[ignore = "run by test_a_register_racing_an_mprotect_keeps_its_pages_missing in a process of its own"]
    fn register_racing_mprotect_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            let r = register_racing(a, mem, UNMAP_LEN, || {
                // SAFETY: the test's mapping.
                assert_eq!(unsafe { crate::mprotect(mem as *mut c_void, PAGE as usize, crate::PROT_READ) }, 0);
            });
            std::println!("RACE {kind}: the register: {r:?}; the page {:x?}", states(mem, PAGE));
            c.check(r.is_ok(), std::format!("{kind}: the register: {r:?}"));
            c.check(is_missing(mem), std::format!("{kind}: the page is not missing"));
            c.check(!host_readable(mem), std::format!("{kind}: a missing page left accessible: {:x?}", states(mem, PAGE)));
            if r.is_ok() {
                c.check(unregister(a, mem, UNMAP_LEN) == Ok(()), std::format!("{kind}: the unregister"));
                // The page takes its protection at its first access (a
                // reserved range's released page) or at once.
                // SAFETY: readable once unregistered, PROT_READ.
                let _ = unsafe { ptr::read_volatile(mem as *const u8) };
                let p = committed_protection(mem);
                std::println!("RACE {kind}: the page's protection once unregistered and read: {p:x?}");
                c.check(p == Some(PAGE_READONLY), std::format!("{kind}: the protection asked: {p:x?}"));
            }
            release(a, ua);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// A register that starts while a `MADV_DONTNEED` of the memory runs
    /// without the lock registers the pages the discard left: missing, and a
    /// fill lands in them. Without the order the register took the written
    /// page, present, and the discard then replaced it under the
    /// registration.
    #[test]
    fn test_a_register_racing_a_discard_fills_the_new_pages() {
        in_a_child("register_racing_discard_child");
    }

    #[test]
    #[ignore = "run by test_a_register_racing_a_discard_fills_the_new_pages in a process of its own"]
    fn register_racing_discard_child() {
        watchdog(60);
        let mut c = Checks::new();
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let mem = map_of(kind);
            // SAFETY: the test's mapping, before any register.
            unsafe { ptr::write_volatile(mem as *mut u8, 1) };
            let r = register_racing(a, mem, UNMAP_LEN, || {
                // SAFETY: the test's mapping.
                assert_eq!(unsafe { crate::madvise(mem as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
            });
            std::println!("RACE {kind}: the register: {r:?}");
            c.check(r.is_ok(), std::format!("{kind}: the register: {r:?}"));
            c.check(is_missing(mem), std::format!("{kind}: the discarded page is not missing"));
            if r.is_ok() && is_missing(mem) {
                // SAFETY: a page.
                let f = unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) };
                c.check(f == Ok(PAGE), std::format!("{kind}: the fill: {f:?}"));
                if f == Ok(PAGE) {
                    // SAFETY: filled just now.
                    c.check(unsafe { ptr::read_volatile(mem as *const u8) } == 0x5a, std::format!("{kind}: the fill went elsewhere"));
                }
            }
            if r.is_ok() {
                c.check(unregister(a, mem, UNMAP_LEN) == Ok(()), std::format!("{kind}: the unregister"));
            }
            release(a, ua);
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        }
        c.done();
    }

    /// The race test's state, for its hook ([`race_in_the_change`]).
    static RACE_MEM: AtomicU64 = AtomicU64::new(0);
    static RACE_CTX: AtomicUsize = AtomicUsize::new(0);
    static RACE_USER: AtomicI32 = AtomicI32::new(-1);
    static RACE_HOLE: AtomicBool = AtomicBool::new(false);
    type Filled = Result<u64, (c_int, u64)>;
    static RACE_FILL: Mutex<Option<std::thread::JoinHandle<Filled>>> = Mutex::new(None);
    /// The new memory's first 4 pages as the change left them.
    static RACE_AFTER: Mutex<std::vec::Vec<(u32, u32)>> = Mutex::new(std::vec::Vec::new());

    /// The hook of [`test_an_unmapping_and_its_unregistration_are_one_step`]:
    /// between the change of the mapping and the unregistration, a mapping
    /// made in the hole (for a munmap; the system's own call, as another
    /// thread's stack guard is made), a handler's fill of a page the old
    /// registration has missing, and the userfaultfd's close. Each runs on a
    /// thread of its own, and the hook goes on once the thread is done or
    /// waits for [`LOCK`] ([`LOCK_WAITING`]): with no timing, either the
    /// step holds the lock and they run after it, or they run inside it.
    fn race_in_the_change(start: u64, _end: u64) {
        use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, VirtualAlloc};
        let mem = RACE_MEM.load(Ordering::SeqCst);
        if start != mem {
            return;
        }
        if RACE_HOLE.load(Ordering::SeqCst) {
            // SAFETY: the hole the munmap left, the test's own range.
            let p = unsafe { VirtualAlloc(mem as *const c_void, UNMAP_LEN as usize, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS) } as u64;
            assert_eq!(p, mem, "the mapping in the hole: {}", io::Error::last_os_error());
        }
        *RACE_AFTER.lock().unwrap() = states(mem, 4 * PAGE);
        let ctx = RACE_CTX.load(Ordering::SeqCst);
        let waiting = LOCK_WAITING.load(Ordering::SeqCst);
        let filler = std::thread::spawn(move || {
            // SAFETY: a page.
            unsafe { copy(ctx, page_of(0x5a).as_ptr(), mem + PAGE, PAGE, true) }
        });
        assert!(holds_within(|| filler.is_finished() || LOCK_WAITING.load(Ordering::SeqCst) > waiting), "the fill neither waited nor ended");
        std::println!("RACE the fill {}", if filler.is_finished() { "ran inside the step" } else { "waits for LOCK" });
        *RACE_FILL.lock().unwrap() = Some(filler);
        let waiting = LOCK_WAITING.load(Ordering::SeqCst);
        // SAFETY: closes the user end: the release follows.
        unsafe { ws::closesocket(sock(RACE_USER.load(Ordering::SeqCst))) };
        assert!(
            holds_within(|| CTXS[ctx].fd.load(Ordering::SeqCst) < 0 || LOCK_WAITING.load(Ordering::SeqCst) > waiting),
            "the release neither waited nor ended"
        );
        std::println!("RACE the release {}", if CTXS[ctx].fd.load(Ordering::SeqCst) < 0 { "ran inside the step" } else { "waits for LOCK" });
    }

    /// An unmapping of registered memory, or a `MAP_FIXED` mapping over it,
    /// and its unregistration are one step to everything else that changes
    /// the ranges, as Linux's registration goes with the vma under the mm's
    /// lock ([`unmapping`]): a handler's fill of a page the old registration
    /// had missing and the userfaultfd's release, both arriving between the
    /// change of the mapping and the unregistration ([`race_in_the_change`]),
    /// find no registration (the fill `ENOENT`) and leave the new memory, or
    /// a `PAGE_NOACCESS` mapping made in the hole, as it is. For both kinds,
    /// each in a process of its own (holes).
    #[test]
    fn test_an_unmapping_and_its_unregistration_are_one_step() {
        for hole in ["hole", "fixed"] {
            for kind in MEM_KINDS {
                let (code, text, _) = run_child_in_jobs("one_step_child", &[("WICK_UFFD_KIND", kind), ("WICK_UFFD_HOLE", hole)], &[]);
                for l in text.lines().filter(|l| l.starts_with("RACE") || l.starts_with("UNMAP") || l.starts_with("WATCHDOG") || l.starts_with("wick:")) {
                    std::eprintln!("{kind}, {hole}: {l}");
                }
                assert_eq!(code, Some(0), "{kind}, {hole}: {text}");
            }
        }
    }

    #[test]
    #[ignore = "run by test_an_unmapping_and_its_unregistration_are_one_step in processes of its own"]
    fn one_step_child() {
        watchdog(60);
        let kind = std::env::var("WICK_UFFD_KIND").unwrap();
        let hole = std::env::var("WICK_UFFD_HOLE").unwrap() == "hole";
        let mut c = Checks::new();
        *UNMAP_HOOK.lock().unwrap() = Some(race_in_the_change);
        let (ctx, user) = create(0, false, true).unwrap();
        let mem = map_of(&kind);
        register(ctx, mem, UNMAP_LEN).unwrap();
        // SAFETY: a page.
        assert_eq!(unsafe { copy(ctx, page_of(0x11).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
        RACE_CTX.store(ctx, Ordering::SeqCst);
        RACE_USER.store(user, Ordering::SeqCst);
        RACE_HOLE.store(hole, Ordering::SeqCst);
        RACE_MEM.store(mem, Ordering::SeqCst);
        if hole {
            assert_eq!(munmap_of(mem, UNMAP_LEN), 0);
        } else {
            assert_eq!(map_fixed(mem, UNMAP_LEN, crate::PROT_NONE), mem);
        }
        let after = RACE_AFTER.lock().unwrap().clone();
        let fill = RACE_FILL.lock().unwrap().take().unwrap().join().unwrap();
        std::println!("RACE {kind}: the fill: {fill:?}");
        c.check(fill == Err((crate::ENOENT, 0)), std::format!("{kind}: the fill between the change and the unregistration: {fill:?}"));
        c.check(holds_within(|| CTXS[ctx].fd.load(Ordering::SeqCst) < 0), "the release did not end");
        c.check(find(mem).is_none(), std::format!("{kind}: the range is still registered"));
        let now = states(mem, 4 * PAGE);
        std::println!("RACE {kind}: (state, protection) of the new memory's first 4 pages after the change {after:x?}, after the fill and the release {now:x?}");
        c.check(!after.is_empty() && now == after, std::format!("{kind}: the fill or the release changed the new memory: {after:x?} -> {now:x?}"));
        c.check(!host_readable(mem + PAGE), std::format!("{kind}: the new memory was opened: {now:x?}"));
        c.done();
    }

    // 1b: a chunk the fill's reclaim passes over (agent design approved by
    // review). A counted system call is in its prefault or its copy
    // (`windows_mm::InFlight`); only a call in its copy holds a chunk off a
    // move, and a fill refused at the limit waits for such calls without
    // `LOCK`, then moves the chunk and goes on where it was.

    /// The 1b children's threads: each waits for its turn, made by the test
    /// thread (no channel: nothing is allocated at the job's limit).
    static TURN: AtomicUsize = AtomicUsize::new(0);
    /// What a reader thread returned, and whether it is in its call's
    /// window ([`crate::windows_fd::BEFORE_CALL`]), and let go of it.
    static READ_RETURNED: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(i64::MIN);
    static IN_WINDOW: AtomicBool = AtomicBool::new(false);
    static LET_GO: AtomicBool = AtomicBool::new(false);
    /// The reads a looping reader made ([`fill_against_a_reading_loop_child`]).
    static READS: AtomicU64 = AtomicU64::new(0);
    static STOP: AtomicBool = AtomicBool::new(false);
    /// The 1b children's threads started and their stacks grown: the job's
    /// room is taken only once all are ([`at_the_limit`]), as a thread still
    /// starting or growing at the limit is refused its stack page.
    static GROWN: AtomicUsize = AtomicUsize::new(0);

    /// A 1b child's thread: its stack grown 128 KiB, then `prepare`, then
    /// counted in [`GROWN`], then `f`.
    fn grown_thread<T: Send + 'static>(prepare: impl FnOnce() + Send + 'static, f: impl FnOnce() -> T + Send + 'static) -> std::thread::JoinHandle<T> {
        std::thread::spawn(move || {
            core::hint::black_box(deep(32));
            prepare();
            GROWN.fetch_add(1, Ordering::SeqCst);
            f()
        })
    }

    /// Waits until `f` holds, for 20 s at most: whether it did.
    fn until(f: impl Fn() -> bool) -> bool {
        let t = std::time::Instant::now();
        while !f() {
            if t.elapsed() > std::time::Duration::from_secs(20) {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    /// The 1b children's start, in a job of 96 MiB ([`fill_to_the_limit`]):
    /// every other page of the first chunk discarded (1 MiB of dead pages,
    /// the only ones); the eighth chunk discarded whole (its section and its
    /// commit given back) and its first page filled, so that a fill of its
    /// next pages needs a page's charge each and no page table; and a file
    /// of 64 KiB of 0x22 to read. The range, the user end, the eighth
    /// chunk's second page (fresh: missing, never committed) and the file's
    /// descriptor. A fill the limit refuses from here ends the process, as
    /// the product's does ([`REFUSED_FILL_IS_ENOMEM`] is turned off by
    /// [`at_the_limit`]).
    fn one_dead_chunk(tag: &str) -> (usize, c_int, u64, u64, std::fs::File, c_int) {
        let (ctx, user, mem, done) = fill_to_the_limit();
        assert!(done >= 9 * CHUNK, "only {} MiB filled", done >> 20);
        for p in (0..CHUNK).step_by(2 * PAGE as usize) {
            // SAFETY: registered memory of ours.
            assert_eq!(unsafe { crate::madvise((mem + p) as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        }
        // SAFETY: as above.
        assert_eq!(unsafe { crate::madvise((mem + 7 * CHUNK) as *mut c_void, CHUNK as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(fill_a_page(ctx, mem + 7 * CHUNK), "made");
        let path = std::env::temp_dir().join(std::format!("wick-1b-{tag}-{}", std::process::id()));
        std::fs::write(&path, [0x22u8; 64 << 10]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let fd = crate::windows_fd::to_fd_pub(std::os::windows::io::AsRawHandle::as_raw_handle(&file));
        (ctx, user, mem, mem + 7 * CHUNK + PAGE, file, fd)
    }

    /// No room left ([`no_room_left`]), once the child's `threads` threads
    /// and a watchdog have started and grown their stacks ([`GROWN`]),
    /// refused fills ending the process from here, and the watchdog ending
    /// it with 3 after 60 s, said, for a wait that would never end.
    fn at_the_limit(threads: usize) -> std::vec::Vec<usize> {
        grown_thread(
            || {},
            || {
                std::thread::sleep(std::time::Duration::from_secs(60));
                crate::windows_mm::say_at_the_limit(format_args!("WATCHDOG the child did not end in 60 s"));
                std::process::exit(3);
            },
        );
        assert!(until(|| GROWN.load(Ordering::SeqCst) == threads + 1), "the threads did not start");
        let held = no_room_left();
        REFUSED_FILL_IS_ENOMEM.store(false, Ordering::SeqCst);
        held
    }

    /// A reader of 16 bytes of `fd` at `buf`, through `pread` (counted in
    /// flight: a regular file's), started at turn `turn`, its stack grown
    /// first; with `park`, its call waits in its window, turned to its copy,
    /// until [`LET_GO`] (20 s at most). Its result in [`READ_RETURNED`].
    fn reader(fd: c_int, buf: u64, turn: usize, park: bool) -> std::thread::JoinHandle<()> {
        grown_thread(
            move || {
                if park {
                    crate::windows_fd::BEFORE_CALL.with(|h| {
                        *h.borrow_mut() = Some(Box::new(|| {
                            IN_WINDOW.store(true, Ordering::SeqCst);
                            until(|| LET_GO.load(Ordering::SeqCst));
                        }));
                    });
                }
            },
            move || {
                until(|| TURN.load(Ordering::SeqCst) >= turn);
                // SAFETY: a valid descriptor and registered memory of the test's.
                let n = unsafe { crate::pread(fd, buf as *mut c_void, 16, 0) };
                READ_RETURNED.store(i64::try_from(n).unwrap_or(-2), Ordering::SeqCst);
            },
        )
    }

    /// A thread that lets the parked read go ([`LET_GO`]) `ms` after a
    /// fill's wait has begun ([`FILL_WAITS`]).
    fn releaser(ms: u64) -> std::thread::JoinHandle<()> {
        grown_thread(
            || {},
            move || {
                until(|| FILL_WAITS.load(Ordering::SeqCst) > 0);
                std::thread::sleep(std::time::Duration::from_millis(ms));
                LET_GO.store(true, Ordering::SeqCst);
            },
        )
    }

    /// Whether 16 bytes at `at` are the file's.
    fn read_the_file(at: u64) -> bool {
        // SAFETY: memory of the test's, filled.
        (0..16).all(|i| unsafe { *((at + i) as *const u8) } == 0x22)
    }

    /// The cycle a fill that waited for every call in flight would make, and
    /// that passing them over made instead: a counted read waits in its
    /// prefault for the handler's fill of its missing page, in a chunk whose
    /// dead pages are the only room; the handler first fills another page,
    /// which the limit refuses. The read's call, in its prefault, does not
    /// hold the chunk: the fill's reclaim moves it, the fill is made, then
    /// the read's page, and the read returns the file's bytes. Before, the
    /// reclaim passed the chunk over, and the fill ended the VMM with 137
    /// (its failing first, 20348 and 26100). FILLPREFAULT line, with the
    /// fill's path below its frame on the filling thread (no wait).
    #[test]
    fn test_a_fill_moves_a_chunk_a_call_waits_in_its_prefault_on() {
        let (code, text) = run_child("fill_moves_under_a_prefault_child", Some(96 << 20));
        std::eprintln!("{}", text.lines().filter(|l| l.starts_with("FILLPREFAULT") || l.starts_with("wick:")).collect::<std::vec::Vec<_>>().join("\n"));
        assert!(text.contains("FILLPREFAULT "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_moves_a_chunk_a_call_waits_in_its_prefault_on in a job of its own"]
    fn fill_moves_under_a_prefault_child() {
        let (ctx, user, mem, fresh, file, fd) = one_dead_chunk("prefault");
        assert!(is_missing(mem), "the read's page is not missing");
        let r = reader(fd, mem + 8, 1, false);
        let counts = reclaim_counts();
        let page = [0x77u8; PAGE as usize];
        let mut buf = [0u8; proto::RECORD];
        let mut held = at_the_limit(1);
        TURN.store(1, Ordering::SeqCst);
        assert!(recv_all(user, &mut buf));
        let event = words(&buf);
        let painted = paint_below_here();
        // SAFETY: `page` holds a page.
        let other = unsafe { copy(ctx, page.as_ptr(), fresh, PAGE, true) };
        let path = used_below(painted);
        let moved = reclaim_counts().moves - counts.moves;
        // SAFETY: as above.
        let own = unsafe { copy(ctx, page.as_ptr(), mem, PAGE, true) };
        let came = until(|| READ_RETURNED.load(Ordering::SeqCst) != i64::MIN);
        give_back_every_page(&mut held);
        r.join().unwrap();
        let n = READ_RETURNED.load(Ordering::SeqCst);
        std::println!(
            "FILLPREFAULT the read's event {:#x} at {:#x}; the other page's fill at the limit: {other:?}, {moved} chunks moved, \
             the fill's path {path} bytes below its frame; the read's page's fill: {own:?}; the read: {n}{}",
            event[0],
            event[1],
            if came { "" } else { " (not returned in 20 s)" }
        );
        assert_eq!([event[0], event[1] - event[1] % PAGE], [proto::EVENT_PAGEFAULT2, mem]);
        assert_eq!((other, own, moved), (Ok(PAGE), Ok(PAGE), 1));
        assert_eq!(n, 16);
        assert!(read_the_file(mem + 8));
        drop(file);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A fill refused at the limit whose reclaim passes over the one chunk
    /// with dead pages, a counted read being in its copy on it, waits for
    /// that read without `LOCK` (the claim keeps other calls off), then
    /// moves the chunk and is made: the read held 300 ms in its window
    /// ([`crate::windows_fd::BEFORE_CALL`]) and let go by the test. Before,
    /// the fill ended the VMM with 137 (its failing first). FILLWAIT line:
    /// how long the fill took, and its path below its frame with the wait,
    /// against [`test_a_fill_moves_a_chunk_a_call_waits_in_its_prefault_on`]'s
    /// without.
    #[test]
    fn test_a_fill_waits_for_a_call_in_its_copy_then_reclaims() {
        let (code, text) = run_child("fill_waits_for_a_copy_child", Some(96 << 20));
        std::eprintln!("{}", text.lines().filter(|l| l.starts_with("FILLWAIT") || l.starts_with("wick:")).collect::<std::vec::Vec<_>>().join("\n"));
        assert!(text.contains("FILLWAIT "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_waits_for_a_call_in_its_copy_then_reclaims in a job of its own"]
    fn fill_waits_for_a_copy_child() {
        let (ctx, user, mem, fresh, file, fd) = one_dead_chunk("copy");
        let r = reader(fd, mem + PAGE + 8, 1, true);
        let releaser = releaser(300);
        let counts = reclaim_counts();
        let page = [0x77u8; PAGE as usize];
        let mut held = at_the_limit(2);
        TURN.store(1, Ordering::SeqCst);
        assert!(until(|| IN_WINDOW.load(Ordering::SeqCst)), "the read did not reach its window");
        let painted = paint_below_here();
        let t = std::time::Instant::now();
        // SAFETY: `page` holds a page.
        let filled = unsafe { copy(ctx, page.as_ptr(), fresh, PAGE, true) };
        let took = t.elapsed();
        let path = used_below(painted);
        let moved = reclaim_counts().moves - counts.moves;
        let came = until(|| READ_RETURNED.load(Ordering::SeqCst) != i64::MIN);
        give_back_every_page(&mut held);
        r.join().unwrap();
        releaser.join().unwrap();
        let n = READ_RETURNED.load(Ordering::SeqCst);
        std::println!(
            "FILLWAIT the fill at the limit with the one chunk of dead pages in a read's copy: {filled:?} in {} ms, {} waits \
             begun and {} ended, {moved} chunks moved, the fill's path {path} bytes below its frame; the read: {n}{}",
            took.as_millis(),
            FILL_WAITS.load(Ordering::SeqCst),
            FILL_WAITED.load(Ordering::SeqCst),
            if came { "" } else { " (not returned in 20 s)" }
        );
        assert_eq!((filled, moved), (Ok(PAGE), 1));
        assert_eq!((FILL_WAITS.load(Ordering::SeqCst), FILL_WAITED.load(Ordering::SeqCst)), (1, 1));
        assert!(took >= std::time::Duration::from_millis(250), "the fill did not wait for the read");
        assert_eq!(n, 16);
        assert!(read_the_file(mem + PAGE + 8), "the read's bytes are not in the moved chunk");
        drop(file);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The turn to the copy and a move's start are decided under one lock
    /// (`windows_mm::Copying::copy_now`, `try_move`): a counted read parked
    /// in its prefault, before its turn ([`crate::windows_fd::BEFORE_TURN`]),
    /// a fill's reclaim moving its chunk meanwhile (the read in its prefault
    /// does not hold it), and the read let go during the move (held by
    /// `windows_mm::MOVE_HOOK` until the read has waited, 20 s at
    /// most): the read's turn waits for the move, then it reads the file's
    /// bytes into the moved chunk. Its other order, a call in its copy and
    /// then the move, is [`test_a_fill_waits_for_a_call_in_its_copy_then_reclaims`].
    /// A call that starts during a move waits at its start, on the region
    /// table the move holds. Not
    /// failing first: before, the read waited at its start instead (the
    /// move's guard was a discard's). TURNWAIT line, with what Windows does
    /// with a regular file's read into reserved memory, as a chunk's view is
    /// a placeholder for a move's swap: the copy the lock keeps from it.
    #[test]
    fn test_a_call_turning_to_its_copy_waits_for_a_move() {
        let (code, text) = run_child("turn_waits_for_a_move_child", Some(96 << 20));
        std::eprintln!("{}", text.lines().filter(|l| l.starts_with("TURNWAIT") || l.starts_with("wick:")).collect::<std::vec::Vec<_>>().join("\n"));
        assert!(text.contains("TURNWAIT "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    /// `windows_mm::MOVE_HOOK`'s for
    /// [`test_a_call_turning_to_its_copy_waits_for_a_move`]: lets the parked
    /// read go, then holds the move until the read's turn has waited.
    fn hold_the_move_for_a_turn() {
        LET_GO.store(true, Ordering::SeqCst);
        until(|| crate::windows_mm::TURNS_THAT_WAITED.load(Ordering::SeqCst) > 0);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    #[test]
    #[ignore = "run by test_a_call_turning_to_its_copy_waits_for_a_move in a job of its own"]
    fn turn_waits_for_a_move_child() {
        use windows_sys::Win32::Storage::FileSystem::ReadFile;
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree};
        let (ctx, user, mem, fresh, file, fd) = one_dead_chunk("turn");
        // What a regular file's read into reserved memory gives.
        // SAFETY: a new reservation of ours, released below.
        let reserved = unsafe { VirtualAlloc(ptr::null(), 1 << 16, MEM_RESERVE, PAGE_READWRITE) };
        assert!(!reserved.is_null());
        let mut got = 0u32;
        // SAFETY: the file's handle; a reserved buffer, which the call may not write.
        let ok = unsafe {
            ReadFile(std::os::windows::io::AsRawHandle::as_raw_handle(&file), reserved.cast(), 16, &mut got, ptr::null_mut())
        };
        let error = io::Error::last_os_error();
        // SAFETY: our reservation.
        unsafe { VirtualFree(reserved, 0, MEM_RELEASE) };
        let into_reserved = std::format!("ReadFile {} with {got} bytes ({error})", if ok != 0 { "succeeded" } else { "failed" });
        let buf = mem + PAGE + 8;
        let r = grown_thread(
            || {
                crate::windows_fd::BEFORE_TURN.with(|h| {
                    *h.borrow_mut() = Some(Box::new(|| {
                        IN_WINDOW.store(true, Ordering::SeqCst);
                        until(|| LET_GO.load(Ordering::SeqCst));
                    }));
                });
            },
            move || {
                until(|| TURN.load(Ordering::SeqCst) >= 1);
                // SAFETY: a valid descriptor and registered memory of the test's.
                let n = unsafe { crate::pread(fd, buf as *mut c_void, 16, 0) };
                READ_RETURNED.store(i64::try_from(n).unwrap_or(-2), Ordering::SeqCst);
            },
        );
        let page = [0x77u8; PAGE as usize];
        let filler = grown_thread(
            || {},
            move || {
                until(|| TURN.load(Ordering::SeqCst) >= 2);
                // SAFETY: `page` holds a page.
                unsafe { copy(ctx, page.as_ptr(), fresh, PAGE, true) }
            },
        );
        crate::windows_mm::set_move_hook(Some(hold_the_move_for_a_turn));
        let mut held = at_the_limit(2);
        TURN.store(1, Ordering::SeqCst);
        assert!(until(|| IN_WINDOW.load(Ordering::SeqCst)), "the read did not reach its turn");
        TURN.store(2, Ordering::SeqCst);
        let came = until(|| READ_RETURNED.load(Ordering::SeqCst) != i64::MIN);
        give_back_every_page(&mut held);
        crate::windows_mm::set_move_hook(None);
        let filled = filler.join().unwrap();
        r.join().unwrap();
        let n = READ_RETURNED.load(Ordering::SeqCst);
        let turns = crate::windows_mm::TURNS_THAT_WAITED.load(Ordering::SeqCst);
        std::println!(
            "TURNWAIT the read's turn to its copy during the move: {turns} turns waited; the read: {n}{}; the fill that \
             moved: {filled:?}; a regular file's read into reserved memory: {into_reserved}",
            if came { "" } else { " (not returned in 20 s)" }
        );
        assert_eq!((turns, n, filled), (1, 16, Ok(PAGE)));
        assert!(read_the_file(mem + PAGE + 8));
        drop(file);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// A fill whose reclaim passes over a chunk for a call in its copy,
    /// waits for it and moves it, and is refused still with nothing
    /// reclaimable left ends the VMM with 137 and a line that says so: the
    /// fill's bytes and address, what it filled, the one chunk passed over,
    /// waited for and reclaimed again. 2 MiB less a page asked, 1 MiB
    /// reclaimable. Before, the line had no wait (its failing first).
    #[test]
    fn test_a_fill_with_nothing_reclaimable_ends_named() {
        let (code, text) = run_child("fill_ends_named_child", Some(96 << 20));
        let line = text.lines().find(|l| l.starts_with("wick: userfaultfd: the fill of "));
        std::eprintln!("{}", line.unwrap_or("no line"));
        assert!(
            line.is_some_and(|l| l.contains("1 chunks passed over for system calls copying them waited for") && l.contains("nothing reclaimable left")),
            "{text}"
        );
        assert_eq!(code, Some(137), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_with_nothing_reclaimable_ends_named in a job of its own"]
    fn fill_ends_named_child() {
        let (ctx, _user, mem, fresh, _file, fd) = one_dead_chunk("named");
        let _r = reader(fd, mem + PAGE + 8, 1, true);
        let _releaser = releaser(100);
        let _held = at_the_limit(2);
        TURN.store(1, Ordering::SeqCst);
        assert!(until(|| IN_WINDOW.load(Ordering::SeqCst)), "the read did not reach its window");
        let r = zeropage(ctx, fresh, CHUNK - PAGE, true);
        crate::windows_mm::say_at_the_limit(format_args!("the fill was answered: {r:?}"));
    }

    /// A fill of three pages refused at its second, while the one chunk of
    /// dead pages is in a read's copy: it fills the first, waits, and in the
    /// wait another thread fills the third (the room for it given back by
    /// the test). Then the second is filled and the fill stops at the
    /// third, answering for its two pages: `EAGAIN` with 8192, as Linux's
    /// copy answers (v6.1 mm/userfaultfd.c `__mcopy_atomic`: the third page
    /// `-EEXIST` at :639, `return copied ? copied : err` at :700, which
    /// `userfaultfd_copy` gives as the count and `-EAGAIN`, fs/userfaultfd.c).
    /// Its own first page is not taken for present (no `EEXIST`), nothing
    /// is filled twice and no page is lost. Before, the fill ended the VMM
    /// with 137 at its second page (its failing first).
    #[test]
    fn test_a_fill_resumes_after_its_wait() {
        let (code, text) = run_child("fill_resumes_child", Some(96 << 20));
        std::eprintln!("{}", text.lines().filter(|l| l.starts_with("FILLRESUME") || l.starts_with("wick:")).collect::<std::vec::Vec<_>>().join("\n"));
        assert!(text.contains("FILLRESUME "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_resumes_after_its_wait in a job of its own"]
    fn fill_resumes_child() {
        let (ctx, user, mem, fresh, file, fd) = one_dead_chunk("resume");
        let r = reader(fd, mem + PAGE + 8, 1, true);
        let filler = grown_thread(
            || {},
            move || {
                let three = [0xA1u8; 3 * PAGE as usize];
                until(|| TURN.load(Ordering::SeqCst) >= 2);
                // SAFETY: `three` holds three pages.
                unsafe { copy(ctx, three.as_ptr(), fresh, 3 * PAGE, true) }
            },
        );
        let other = [0xB3u8; PAGE as usize];
        let mut held = at_the_limit(2);
        // Room for one page.
        give_back_a_page(&mut held);
        TURN.store(1, Ordering::SeqCst);
        assert!(until(|| IN_WINDOW.load(Ordering::SeqCst)), "the read did not reach its window");
        TURN.store(2, Ordering::SeqCst);
        let waiting = until(|| FILL_WAITS.load(Ordering::SeqCst) > 0);
        // Room for the third page, and its fill by this thread, while the
        // three-page fill waits.
        give_back_a_page(&mut held);
        // SAFETY: `other` holds a page.
        let third = unsafe { copy(ctx, other.as_ptr(), fresh + 2 * PAGE, PAGE, true) };
        LET_GO.store(true, Ordering::SeqCst);
        let filled = filler.join().unwrap();
        give_back_every_page(&mut held);
        r.join().unwrap();
        // SAFETY: the three pages, filled.
        let bytes: [u8; 3] = core::array::from_fn(|i| unsafe { *((fresh + i as u64 * PAGE + 5) as *const u8) });
        std::println!(
            "FILLRESUME the three-page fill: {filled:?}; it waited: {waiting}; the third page's fill during the wait: {third:?}; \
             the pages: {bytes:x?}; the read: {}",
            READ_RETURNED.load(Ordering::SeqCst)
        );
        assert!(waiting, "the fill did not wait");
        assert_eq!(third, Ok(PAGE));
        assert_eq!(filled, Err((crate::EAGAIN, 2 * PAGE)));
        assert_eq!(bytes, [0xA1, 0xA1, 0xB3]);
        assert_eq!(READ_RETURNED.load(Ordering::SeqCst), 16);
        drop(file);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// No livelock against a thread that keeps reading into the one chunk
    /// of dead pages: each read held 20 ms in its copy, one after another.
    /// A fill refused at the limit claims the chunk, so the next read's turn
    /// to its copy waits behind it, waits for the read in its copy (20 ms
    /// at most, that read's kernel copy and its hold), moves the chunk and is
    /// made; the reads go on after. Before, the fill ended the VMM with 137
    /// (its failing first). FILLLOOP line.
    #[test]
    fn test_a_fill_against_a_reading_loop_is_made() {
        let (code, text) = run_child("fill_against_a_reading_loop_child", Some(96 << 20));
        std::eprintln!("{}", text.lines().filter(|l| l.starts_with("FILLLOOP") || l.starts_with("wick:")).collect::<std::vec::Vec<_>>().join("\n"));
        assert!(text.contains("FILLLOOP "), "{text}");
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_fill_against_a_reading_loop_is_made in a job of its own"]
    fn fill_against_a_reading_loop_child() {
        let (ctx, user, mem, fresh, file, fd) = one_dead_chunk("loop");
        let buf = mem + PAGE + 8;
        let looper = grown_thread(
            || {
                crate::windows_fd::BEFORE_CALL.with(|h| {
                    *h.borrow_mut() = Some(Box::new(|| {
                        IN_WINDOW.store(true, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }));
                });
            },
            move || {
                until(|| TURN.load(Ordering::SeqCst) >= 1);
                let mut bad = 0;
                while !STOP.load(Ordering::SeqCst) {
                    // SAFETY: a valid descriptor and registered memory of the test's.
                    if unsafe { crate::pread(fd, buf as *mut c_void, 16, 0) } != 16 {
                        bad += 1;
                    }
                    READS.fetch_add(1, Ordering::SeqCst);
                }
                bad
            },
        );
        let counts = reclaim_counts();
        let page = [0x77u8; PAGE as usize];
        let mut held = at_the_limit(1);
        TURN.store(1, Ordering::SeqCst);
        assert!(until(|| READS.load(Ordering::SeqCst) >= 3), "the reads did not start");
        let before = READS.load(Ordering::SeqCst);
        let t = std::time::Instant::now();
        // SAFETY: `page` holds a page.
        let filled = unsafe { copy(ctx, page.as_ptr(), fresh, PAGE, true) };
        let took = t.elapsed();
        let at_fill = READS.load(Ordering::SeqCst);
        let went_on = until(|| READS.load(Ordering::SeqCst) >= at_fill + 5);
        STOP.store(true, Ordering::SeqCst);
        let bad = looper.join().unwrap();
        give_back_every_page(&mut held);
        let moved = reclaim_counts().moves - counts.moves;
        std::println!(
            "FILLLOOP the fill at the limit against reads of 20 ms in their copy: {filled:?} in {} ms, {} waits, {moved} chunks \
             moved; reads {before} before it, {} after it, {bad} not of 16 bytes",
            took.as_millis(),
            FILL_WAITS.load(Ordering::SeqCst),
            READS.load(Ordering::SeqCst) - at_fill
        );
        assert_eq!((filled, moved, bad), (Ok(PAGE), 1, 0));
        assert!(FILL_WAITS.load(Ordering::SeqCst) >= 1, "the fill did not wait for a read");
        assert!(took < std::time::Duration::from_secs(1), "the fill waited {} ms", took.as_millis());
        assert!(went_on, "the reads did not go on after the fill");
        assert!(read_the_file(buf));
        drop(file);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(user)) };
    }

    /// The next event on `user` within 10 s: its first three words.
    fn next_event(user: c_int) -> Option<[u64; 3]> {
        if !event_within(user, 10_000) {
            return None;
        }
        let mut rec = [0u8; proto::RECORD];
        recv_all(user, &mut rec).then(|| {
            let w = words(&rec);
            [w[0], w[1], w[2]]
        })
    }

    /// Register and unregister as Linux's, with an owner a page (the macOS
    /// backend's test of the same name): registered again, and further,
    /// what the userfaultfd has stays as it is (mm/userfaultfd.c, v6.12,
    /// `userfaultfd_register_range` :1848 to :1853); another userfaultfd's
    /// register over its pages is `EBUSY` (fs/userfaultfd.c :1363 to
    /// :1366); an unregister through either takes the pages (6.12, :1500,
    /// :1522); a page no userfaultfd has registers with any. For both kinds.
    /// A range not on a reserved section (no lazy-memory handler) has its
    /// missing pages zeroed and opened when they leave a registration, so
    /// they hold memory and are not missing when registered again; on a
    /// reserved section, the product's, they are.
    #[test]
    fn test_register_and_unregister_as_linux() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let (b, ub) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 3);
            register(a, mem, 3 * PAGE).unwrap();
            let reserved = find(mem).unwrap().0.reserved.load(Ordering::Acquire);
            assert_eq!(zeropage(a, mem, PAGE, true), Ok(PAGE), "{kind}");
            register(a, mem, 3 * PAGE).unwrap();
            assert!(!is_missing(mem) && is_missing(mem + PAGE) && is_missing(mem + 2 * PAGE), "{kind}");
            for (start, len) in [(mem + 2 * PAGE, PAGE), (mem, 3 * PAGE)] {
                assert_eq!(register(b, start, len).unwrap_err().raw_os_error(), Some(crate::EBUSY), "{kind}");
            }
            assert!(is_missing(mem + PAGE) && is_missing(mem + 2 * PAGE), "{kind}: a refused register changed a page");
            assert_eq!(unregister(b, mem + PAGE, PAGE), Ok(()), "{kind}");
            assert!(!is_missing(mem + PAGE), "{kind}");
            register(b, mem + PAGE, PAGE).unwrap();
            assert_eq!(is_missing(mem + PAGE), reserved, "{kind}: b's page registered again");
            assert!(is_missing(mem + 2 * PAGE), "{kind}");
            assert_eq!(zeropage(a, mem + PAGE, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            assert_eq!(unregister(b, mem + PAGE, PAGE), Ok(()), "{kind}");
            register(a, mem, 3 * PAGE).unwrap();
            assert!(!is_missing(mem) && is_missing(mem + 2 * PAGE), "{kind}");
            assert_eq!(unregister(a, mem, 3 * PAGE), Ok(()), "{kind}");
            register(b, mem, 3 * PAGE).unwrap();
            assert!(!is_missing(mem) && is_missing(mem + 2 * PAGE) == reserved, "{kind}");
            if reserved {
                assert_eq!(zeropage(b, mem + PAGE, 2 * PAGE, true), Ok(2 * PAGE), "{kind}");
            }
            assert_eq!(zeropage(a, mem + PAGE, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            assert_eq!(unregister(b, mem, 3 * PAGE), Ok(()), "{kind}");
            release(a, ua);
            release(b, ub);
            assert_eq!(munmap_of(mem, 3 * PAGE), 0);
        }
    }

    /// A register whose range ends in a page another userfaultfd has is
    /// `EBUSY` and changes nothing before it: Linux checks every vma of the
    /// range before it registers one (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_register`: `EBUSY` at :1363 to :1366, in the loop that
    /// ends at :1375, before `userfaultfd_register_range` at :1378). The
    /// macOS backend's test of the same name. For both kinds.
    #[test]
    fn test_a_register_ending_in_another_userfaultfds_page_changes_nothing() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let (b, ub) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 3);
            register(a, mem, 3 * PAGE).unwrap();
            assert_eq!(unregister(a, mem, 2 * PAGE), Ok(()), "{kind}");
            assert_eq!(register(b, mem, 3 * PAGE).unwrap_err().raw_os_error(), Some(crate::EBUSY), "{kind}");
            assert!(!is_missing(mem) && !is_missing(mem + PAGE) && is_missing(mem + 2 * PAGE), "{kind}");
            assert_eq!(zeropage(b, mem, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            assert_eq!(zeropage(b, mem + 2 * PAGE, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            // SAFETY: unregistered memory, accessible as before the register.
            unsafe {
                ptr::write_volatile(mem as *mut u8, 4);
                assert_eq!(ptr::read_volatile(mem as *const u8), 4, "{kind}");
            }
            assert_eq!(zeropage(a, mem + 2 * PAGE, PAGE, true), Ok(PAGE), "{kind}");
            release(a, ua);
            release(b, ub);
            assert_eq!(munmap_of(mem, 3 * PAGE), 0);
        }
    }

    /// Two userfaultfds' pages in one slot, each part as Linux's own vma:
    /// each fills only its pages, a discard posts each part's remove event
    /// to its userfaultfd (Linux's walk calls `userfaultfd_remove` per vma,
    /// mm/madvise.c, v6.12, :894), and the release of one takes only its
    /// pages (fs/userfaultfd.c `userfaultfd_release` :856, through
    /// mm/userfaultfd.c `userfaultfd_release_all` :1899, which skips another
    /// context's vma at :1922), the slot living on for the other's. The macOS
    /// backend's test of the same name. For both kinds.
    #[test]
    fn test_two_userfaultfds_in_one_slot_fill_discard_and_release_their_own() {
        for kind in MEM_KINDS {
            let slots = || RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) != 0).count();
            let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
            let (b, ub) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
            let mem = map_pages(kind, 4);
            register(a, mem, 4 * PAGE).unwrap();
            let used = slots();
            assert_eq!(unregister(a, mem + 2 * PAGE, 2 * PAGE), Ok(()), "{kind}");
            register(b, mem + 2 * PAGE, 2 * PAGE).unwrap();
            assert_eq!(slots(), used, "{kind}: the second userfaultfd's pages took a slot");
            assert_eq!(zeropage(a, mem + 2 * PAGE, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            assert_eq!(zeropage(b, mem, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            assert_eq!(zeropage(a, mem, PAGE, true), Ok(PAGE), "{kind}");
            assert_eq!(zeropage(b, mem + 2 * PAGE, PAGE, true), Ok(PAGE), "{kind}");
            // SAFETY: the test's mapping.
            assert_eq!(unsafe { crate::madvise(mem as *mut c_void, 4 * PAGE as usize, crate::MADV_DONTNEED) }, 0, "{kind}");
            assert_eq!(next_event(ua), Some([proto::EVENT_REMOVE, mem, mem + 2 * PAGE]), "{kind}: the first part's remove event");
            assert_eq!(next_event(ub), Some([proto::EVENT_REMOVE, mem + 2 * PAGE, mem + 4 * PAGE]), "{kind}: the second part's");
            assert!(!event_within(ua, 0) && !event_within(ub, 0), "{kind}: a second event");
            assert!((0..4).all(|p| is_missing(mem + p * PAGE)), "{kind}");
            release(a, ua);
            assert!(!is_missing(mem) && !is_missing(mem + PAGE) && is_missing(mem + 2 * PAGE) && is_missing(mem + 3 * PAGE), "{kind}");
            assert_eq!(slots(), used, "{kind}: the slot went with the first userfaultfd");
            // SAFETY: released, so ordinary memory: a zero page.
            assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0, "{kind}");
            assert_eq!(zeropage(b, mem, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            assert_eq!(zeropage(b, mem + 2 * PAGE, 2 * PAGE, true), Ok(2 * PAGE), "{kind}");
            release(b, ub);
            assert_eq!(slots(), used, "{kind}: the slot went before its memory");
            assert_eq!(munmap_of(mem, 4 * PAGE), 0);
            assert_eq!(slots(), used - 1, "{kind}: the slot outlived its memory");
        }
    }

    /// A fill must lie in pages of the caller only: across the boundary
    /// between two userfaultfds' pages it is `ENOENT` with nothing filled,
    /// as Linux's destination must be one vma of the caller's
    /// (mm/userfaultfd.c, v6.12, `validate_dst_vma` :23 to :37). Across
    /// pages the same userfaultfd unregistered and registered again it is
    /// one call, as over Linux's vma merged again at the register
    /// (`userfaultfd_register_range`, `vma_modify_flags_uffd` at :1860). The
    /// macOS backend's test of the same name, on a reserved range (an
    /// ordinary one's pages hold memory once they leave a registration).
    #[test]
    fn test_a_fill_lies_in_one_userfaultfds_pages() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let mem = map_pages("reserved", 4);
        register(a, mem, 4 * PAGE).unwrap();
        assert_eq!(unregister(a, mem + PAGE, PAGE), Ok(()));
        register(a, mem + PAGE, PAGE).unwrap();
        assert_eq!(zeropage(a, mem, 2 * PAGE, true), Ok(2 * PAGE));
        assert_eq!(unregister(a, mem + 3 * PAGE, PAGE), Ok(()));
        register(b, mem + 3 * PAGE, PAGE).unwrap();
        assert_eq!(zeropage(a, mem + 2 * PAGE, 2 * PAGE, true), Err((crate::ENOENT, 0)));
        assert_eq!(zeropage(b, mem + 2 * PAGE, 2 * PAGE, true), Err((crate::ENOENT, 0)));
        assert!(is_missing(mem + 2 * PAGE) && is_missing(mem + 3 * PAGE), "a refused fill filled");
        assert_eq!(zeropage(a, mem + 2 * PAGE, PAGE, true), Ok(PAGE));
        assert_eq!(zeropage(b, mem + 3 * PAGE, PAGE, true), Ok(PAGE));
        release(a, ua);
        release(b, ub);
        assert_eq!(munmap_of(mem, 4 * PAGE), 0);
    }

    /// An unregister made through another userfaultfd takes the pages, as
    /// Linux 6.12's (fs/userfaultfd.c `userfaultfd_unregister` :1413) skips
    /// only vmas with no context (:1500) and clears the rest (:1522), waking
    /// each one's context's waiters (:1509 to :1519): a thread waiting on a
    /// page of it runs again, the page is ordinary memory (zeros), and a
    /// later fill through its userfaultfd is `ENOENT`. Linux 6.17 refuses
    /// such an unregister with `EINVAL` (:1475 to :1480); wick follows 6.12.
    /// The macOS backend's test of the same name. For both kinds.
    #[test]
    fn test_an_unregister_through_another_userfaultfd_wakes_and_takes_the_pages() {
        for kind in MEM_KINDS {
            let (a, ua) = create(0, false, true).unwrap();
            let (b, ub) = create(0, false, true).unwrap();
            let mem = map_pages(kind, 1);
            register(b, mem, PAGE).unwrap();
            let reader = std::thread::spawn(move || {
                // SAFETY: registered memory; the read waits for b's fill or a wake.
                unsafe { ptr::read_volatile(mem as *const u8) }
            });
            assert_eq!(next_event(ub).map(|w| [w[0], w[1]]), Some([proto::EVENT_PAGEFAULT2, mem]), "{kind}");
            assert_eq!(unregister(a, mem, PAGE), Ok(()), "{kind}");
            assert_eq!(reader.join().unwrap(), 0, "{kind}: the waiter's access did not go through");
            assert!(!is_missing(mem), "{kind}");
            assert_eq!(zeropage(b, mem, PAGE, true), Err((crate::ENOENT, 0)), "{kind}");
            assert!(!event_within(ua, 0) && !event_within(ub, 0), "{kind}: an event after the unregister");
            release(a, ua);
            release(b, ub);
            assert_eq!(munmap_of(mem, PAGE), 0);
        }
    }

    /// A page unregistered while missing, then registered again, is missing
    /// again and faults to its new userfaultfd, and no thread ever sees what
    /// it held: one filled and discarded before the unregister (committed,
    /// closed and charged, pending in its range's record), one never filled
    /// (not committed). A page touched after the unregister (zeros) holds
    /// memory and is not missing. As Linux's page that was never faulted in
    /// between, and its zero page after a touch. On a reserved range, the
    /// product's.
    #[test]
    fn test_a_page_pending_when_registered_again_is_missing_and_shows_nothing_old() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let mem = map_pages("reserved", 3);
        register(a, mem, 3 * PAGE).unwrap();
        // SAFETY: a page.
        assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
        // SAFETY: the test's mapping.
        assert_eq!(unsafe { crate::madvise(mem as *mut c_void, PAGE as usize, crate::MADV_DONTNEED) }, 0);
        assert!(is_missing(mem));
        assert_eq!(unregister(a, mem, 3 * PAGE), Ok(()));
        // SAFETY: ordinary memory now: its first access reads zeros.
        assert_eq!(unsafe { ptr::read_volatile((mem + 2 * PAGE) as *const u8) }, 0);
        register(b, mem, 3 * PAGE).unwrap();
        assert!(is_missing(mem) && is_missing(mem + PAGE), "a pending page is not missing again");
        assert!(!is_missing(mem + 2 * PAGE), "a page touched after the unregister is missing");
        for p in [0, 1] {
            let at = mem + p * PAGE;
            let reader = std::thread::spawn(move || {
                // SAFETY: registered memory; the read waits for b's fill.
                unsafe { ptr::read_volatile(at as *const u8) }
            });
            assert_eq!(next_event(ub).map(|w| [w[0], w[1]]), Some([proto::EVENT_PAGEFAULT2, at]), "page {p}");
            assert!(!event_within(ua, 0), "page {p}: the first userfaultfd got the fault");
            // SAFETY: a page.
            assert_eq!(unsafe { copy(b, page_of(0x77).as_ptr(), at, PAGE, true) }, Ok(PAGE), "page {p}");
            assert_eq!(reader.join().unwrap(), 0x77, "page {p}");
        }
        release(a, ua);
        release(b, ub);
        assert_eq!(munmap_of(mem, 3 * PAGE), 0);
    }

    /// A whole chunk of a reserved range discarded (a new section in its
    /// place, `windows_mm::uffd_swap_chunk`), unregistered and registered
    /// again with another userfaultfd: its pages are missing in the new
    /// section, and a fill lands in it through the same alias.
    #[test]
    fn test_a_swapped_chunk_registered_again_is_missing_and_filled() {
        let chunk = crate::windows_mm::UFFD_CHUNK as u64;
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let mem = map_noreserve(2 * chunk as usize);
        register(a, mem, 2 * chunk).unwrap();
        let slot = mem + chunk;
        // SAFETY: a page.
        assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), slot, PAGE, true) }, Ok(PAGE));
        // SAFETY: registered memory of the test's.
        assert_eq!(unsafe { crate::madvise(slot as *mut c_void, chunk as usize, crate::MADV_DONTNEED) }, 0);
        assert_eq!(unregister(a, mem, 2 * chunk), Ok(()));
        register(b, slot, chunk).unwrap();
        assert!(is_missing(slot) && is_missing(slot + chunk - PAGE), "the swapped chunk's pages are not missing");
        // SAFETY: a page.
        assert_eq!(unsafe { copy(b, page_of(0x77).as_ptr(), slot, PAGE, true) }, Ok(PAGE));
        // SAFETY: filled just now.
        assert_eq!(unsafe { ptr::read_volatile(slot as *const u8) }, 0x77);
        release(a, ua);
        release(b, ub);
        assert_eq!(munmap_of(mem, 2 * chunk), 0);
    }

    /// The pages of a released userfaultfd register again with another, as
    /// Linux's release clears its vmas' context (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_release` :856): a page missing at the release is missing
    /// again, one filled keeps its contents. On a reserved range.
    #[test]
    fn test_pages_of_a_released_userfaultfd_register_again() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let mem = map_pages("reserved", 2);
        register(a, mem, 2 * PAGE).unwrap();
        // SAFETY: a page.
        assert_eq!(unsafe { copy(a, page_of(0x5a).as_ptr(), mem, PAGE, true) }, Ok(PAGE));
        release(a, ua);
        register(b, mem, 2 * PAGE).unwrap();
        assert!(!is_missing(mem) && is_missing(mem + PAGE));
        // SAFETY: filled before the release, kept.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a);
        assert_eq!(zeropage(b, mem + PAGE, PAGE, true), Ok(PAGE));
        release(b, ub);
        assert_eq!(munmap_of(mem, 2 * PAGE), 0);
    }

    /// More scattered partial unregisters of one registration than there are
    /// slots ([`MAX_RANGES`]) all succeed and take no slot, and the pages
    /// left registered fault and fill as before. Firecracker's on-demand
    /// handler unregisters the range of every remove event and asserts that
    /// it succeeds (lib/firecracker/src/firecracker/examples/uffd/
    /// on_demand_handler.rs :93 to :94, uffd_utils.rs :133 to :144), runs
    /// scattered as a balloon's inflation leaves them
    /// (tests/integration_tests/functional/test_uffd.py :100 to :109); on
    /// Linux each is a vma split, up to `vm.max_map_count`. macOS's test
    /// of the same name, with its register of an unregistered page by
    /// another userfaultfd. In a process of its own, as it counts the
    /// process's slots.
    #[test]
    fn test_more_scattered_unregisters_than_slots_all_succeed() {
        let (code, text) = run_child("scattered_unregisters_child", None);
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_more_scattered_unregisters_than_slots_all_succeed in a process of its own"]
    fn scattered_unregisters_child() {
        let slots = || RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) != 0).count();
        let (a, ua) = create(0, false, true).unwrap();
        let pages = 2 * MAX_RANGES as u64 + 3;
        let mem = map((pages * PAGE) as usize);
        register(a, mem, pages * PAGE).unwrap();
        let used = slots();
        // Every odd page: MAX_RANGES + 1 unregisters, each its own run.
        for page in (1..pages).step_by(2) {
            assert_eq!(unregister(a, mem + page * PAGE, PAGE), Ok(()), "unregister of page {page}");
        }
        assert_eq!(slots(), used, "the unregisters took slots");
        for page in 0..pages {
            assert_eq!(is_missing(mem + page * PAGE), page % 2 == 0, "page {page}");
        }
        // An unregistered page is no one's to fill.
        assert_eq!(zeropage(a, mem + PAGE, PAGE, true), Err((crate::ENOENT, 0)));
        // A page left registered faults to its userfaultfd and is filled.
        let last = mem + (pages - 1) * PAGE;
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { ptr::read_volatile(last as *const u8) }
        });
        let mut rec = [0u8; proto::RECORD];
        assert!(recv_all(ua, &mut rec), "no fault event");
        assert_eq!(words(&rec)[..2], [proto::EVENT_PAGEFAULT2, last]);
        let data = std::vec![9u8; PAGE as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), last, PAGE, true) }, Ok(PAGE));
        assert_eq!(reader.join().unwrap(), 9);
        assert_eq!(zeropage(a, mem, PAGE, true), Ok(PAGE));
        // Another userfaultfd registers an unregistered page, in the same
        // slot, and its fill lands there; a's fill of it is ENOENT.
        let (b, ub) = create(0, false, true).unwrap();
        assert_eq!(register(b, mem + PAGE, PAGE).map_err(|e| e.raw_os_error()), Ok(()), "b's register of an unregistered page");
        assert_eq!(slots(), used, "b's register took a slot");
        assert_eq!(zeropage(a, mem + PAGE, PAGE, true), Err((crate::ENOENT, 0)));
        assert_eq!(zeropage(b, mem + PAGE, PAGE, true), Ok(PAGE));
        assert_eq!(unregister(a, mem, pages * PAGE), Ok(()));
        // The slot is kept until the memory is unmapped ([`Range`]).
        assert_eq!(slots(), used, "the slot went before its memory");
        assert_eq!(munmap_of(mem, pages * PAGE), 0);
        assert_eq!(slots(), used - 1, "the range outlived its memory");
        // SAFETY: closes the user ends.
        unsafe {
            ws::closesocket(sock(ua));
            ws::closesocket(sock(ub));
        }
    }

    /// The per-page arrays allocated ([`alloc_array`]): four for each slot
    /// that a range does not fit in.
    pub(super) static ARRAYS_MADE: AtomicUsize = AtomicUsize::new(0);
    /// The indexes [`within`] refused, past an array's capacity.
    static REFUSED: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn index_checked(page: u64, capacity: u64, ok: bool) {
        if page >= capacity {
            // A check that let it through would read past the array: stop
            // here, before the read.
            assert!(!ok, "index {page} past the array's capacity {capacity} let through");
            REFUSED.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// One-shot hooks: a `fn()` and, for the address-armed ones, the
    /// address it waits for.
    static LOOKUP_HOOK: AtomicUsize = AtomicUsize::new(0);
    static LOOKUP_AT: AtomicU64 = AtomicU64::new(0);
    static VALIDATE_HOOK: AtomicUsize = AtomicUsize::new(0);
    static VALIDATE_AT: AtomicU64 = AtomicU64::new(0);
    static BETWEEN_HOOK: AtomicUsize = AtomicUsize::new(0);
    static BETWEEN_AT: AtomicU64 = AtomicU64::new(0);
    static WINDOW_HOOK: AtomicUsize = AtomicUsize::new(0);

    fn run_once(hook: &AtomicUsize) {
        let f = hook.swap(0, Ordering::SeqCst);
        if f != 0 {
            // SAFETY: set by a test from a `fn()`.
            let f: fn() = unsafe { core::mem::transmute(f) };
            f();
        }
    }

    fn run_at(at: &AtomicU64, addr: u64, hook: &AtomicUsize) {
        let armed = at.load(Ordering::SeqCst);
        if armed != 0 && addr == armed && at.compare_exchange(armed, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            run_once(hook);
        }
    }

    /// [`lookup`], between its read of a slot's `start` and the rest: once,
    /// for the address armed, at the slot that starts there.
    pub(super) fn lookup_hook(addr: u64, start: u64) {
        if start == addr {
            run_at(&LOOKUP_AT, addr, &LOOKUP_HOOK);
        }
    }

    /// [`fault`], once its waiter is in [`WAITERS`], before it reads the page
    /// and validates the slot.
    pub(super) fn validate_hook(addr: u64) {
        run_at(&VALIDATE_AT, addr, &VALIDATE_HOOK);
    }

    /// [`fault`], between its validation's read of the page (missing, owner)
    /// and of the slot's `gen`.
    pub(super) fn between_hook(addr: u64) {
        run_at(&BETWEEN_AT, addr, &BETWEEN_HOOK);
    }

    /// [`Range::changing`], with `gen` odd.
    pub(super) fn window_hook() {
        run_once(&WINDOW_HOOK);
    }

    /// The live slots.
    fn live_slots() -> usize {
        RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) != 0).count()
    }

    /// Registers `pages` fresh pages with `ctx`, fills one, unregisters them
    /// and unmaps them (the slot freed at the unmap, [`Range`]); the arrays
    /// made after.
    fn round(ctx: usize, pages: u64) -> usize {
        let mem = map((pages * PAGE) as usize);
        register(ctx, mem, pages * PAGE).unwrap();
        assert_eq!(zeropage(ctx, mem, PAGE, true), Ok(PAGE));
        assert_eq!(unregister(ctx, mem, pages * PAGE), Ok(()));
        assert_eq!(munmap_of(mem, pages * PAGE), 0);
        assert_eq!(live_slots(), 0, "the slot outlived its memory");
        ARRAYS_MADE.load(Ordering::SeqCst)
    }

    /// A range registered and unmapped again and again keeps the count of
    /// arrays flat: a slot keeps its arrays, and the next range that fits
    /// takes them again ([`Range`]). A larger range makes the count rise once
    /// (four arrays of the next capacity), and flat again after, for it and
    /// for the smaller one. Rounds are counted, not timed. The macOS
    /// backend's test (`..._register_and_release_...`), with the unmap that
    /// frees a slot here. In a process of its own, as it counts the
    /// process's allocations.
    #[test]
    fn test_register_and_unmap_in_a_loop_keeps_the_array_count_flat() {
        let (code, text) = run_child("array_count_child", None);
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_register_and_unmap_in_a_loop_keeps_the_array_count_flat in a process of its own"]
    fn array_count_child() {
        const ROUNDS: usize = 16;
        let (a, ua) = create(0, false, true).unwrap();
        let small: Vec<usize> = (0..ROUNDS).map(|_| round(a, 4)).collect();
        assert!(small.iter().all(|&n| n == 4), "arrays made after each round of 4 pages: {small:?}");
        let large: Vec<usize> = (0..ROUNDS).map(|_| round(a, 100)).collect();
        assert!(large.iter().all(|&n| n == 8), "arrays made after each round of 100 pages: {large:?}");
        let again: Vec<usize> = (0..ROUNDS).map(|_| round(a, 4)).collect();
        assert!(again.iter().all(|&n| n == 8), "arrays made after each round of 4 pages again: {again:?}");
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(ua)) };
    }

    /// An index past an array's capacity reads nothing ([`array_capacity`]'s
    /// rule): the bit and byte of the last page it has room for are there,
    /// the next are not.
    #[test]
    fn test_an_index_past_an_arrays_capacity_reads_nothing() {
        let bits = alloc_array(64, 1, 0xff);
        let bytes = alloc_array(64, 8, 7);
        let refused = REFUSED.load(Ordering::SeqCst);
        assert!(bit_of(bits, 63).is_some_and(|w| w.load(Ordering::SeqCst) == !0));
        assert_eq!(byte_of(bytes, 63).map(|b| b.load(Ordering::SeqCst)), Some(7));
        assert!(bit_of(bits, 64).is_none() && byte_of(bytes, 64).is_none());
        assert!(byte_of(ptr::null(), 0).is_none());
        assert!(REFUSED.load(Ordering::SeqCst) >= refused + 2);
    }

    /// The hooks' pages, the first registration's and the second's, and the
    /// second's userfaultfd.
    static FIRST: AtomicU64 = AtomicU64::new(0);
    static SECOND: AtomicU64 = AtomicU64::new(0);
    static SECOND_CTX: AtomicUsize = AtomicUsize::new(0);

    /// Maps new memory over the first registration's page, which frees its
    /// slot ([`untrack_gone`]), and registers the second's page, which takes
    /// the slot (the free slot with room, in a process of a test's own).
    fn replace_and_reuse() {
        let first = FIRST.load(Ordering::SeqCst);
        assert_eq!(map_fixed(first, PAGE, crate::PROT_READ | crate::PROT_WRITE), first);
        register(SECOND_CTX.load(Ordering::SeqCst), SECOND.load(Ordering::SeqCst), PAGE).unwrap();
    }

    /// Two fresh pages, the lower first, and the hooks' statics set: the
    /// first registered with `a`, the second to be registered with `b`.
    fn two_pages(a: usize, b: usize) -> (u64, u64) {
        let (x, y) = (map(PAGE as usize), map(PAGE as usize));
        let (first, second) = (x.min(y), x.max(y));
        FIRST.store(first, Ordering::SeqCst);
        SECOND.store(second, Ordering::SeqCst);
        SECOND_CTX.store(b, Ordering::SeqCst);
        register(a, first, PAGE).unwrap();
        assert!(is_missing(first));
        (first, second)
    }

    /// A reader between its reads of a slot's fields, whose slot is freed
    /// (its memory mapped over) and taken by another userfaultfd's range at
    /// a higher address, starts over and answers for the new state: its
    /// address is in no registration. Without the slot's `gen` it would read
    /// the old start with the new end and arrays, and find the address
    /// missing. The macOS backend's test of the same name. In a process of
    /// its own, so that the slot the second range takes is the first's.
    #[test]
    fn test_a_reader_between_its_generation_reads_starts_over() {
        let (code, text) = run_child("reader_between_child", None);
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_reader_between_its_generation_reads_starts_over in a process of its own"]
    fn reader_between_child() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let (first, second) = two_pages(a, b);
        LOOKUP_HOOK.store(replace_and_reuse as fn() as usize, Ordering::SeqCst);
        LOOKUP_AT.store(first, Ordering::SeqCst);
        let missing = is_missing(first);
        assert_eq!(LOOKUP_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert!(!missing, "a reader of the freed slot found its address missing in the new range's arrays");
        assert!(is_missing(second) && !is_missing(first));
        assert_eq!(munmap_of(first, PAGE), 0);
        assert_eq!(munmap_of(second, PAGE), 0);
        // SAFETY: closes the user ends.
        unsafe {
            ws::closesocket(sock(ua));
            ws::closesocket(sock(ub));
        }
    }

    /// A host read of the first page, faulting, on a thread of its own: the
    /// byte it read once it ends, `None` if it has not within 20 s.
    fn read_the_first() -> Option<u8> {
        let first = FIRST.load(Ordering::SeqCst);
        let done = std::sync::Arc::new(AtomicU64::new(u64::MAX));
        let d = done.clone();
        std::thread::spawn(move || {
            // SAFETY: registered memory; a hook replaces it in the fault.
            let v = unsafe { ptr::read_volatile(first as *const u8) };
            d.store(u64::from(v), Ordering::SeqCst);
        });
        until(|| done.load(Ordering::SeqCst) != u64::MAX).then(|| u8::try_from(done.load(Ordering::SeqCst)).unwrap())
    }

    /// A fault whose slot is freed and taken by its own userfaultfd's next
    /// range once its waiter is registered posts nothing and runs its access
    /// again, which reads the new memory, in no registration. Without the
    /// validation of `gen` it would read the new range's page, missing and
    /// its userfaultfd's own, post the old address and wait for a fill that
    /// never comes. The same userfaultfd, where the macOS backend's test of
    /// the same name has another: here the waiter's userfaultfd is the one
    /// its lookup read, and the owner check alone tells another one's page.
    /// In a process of its own, as the test above.
    #[test]
    fn test_fault_validates_after_its_waiter_is_registered() {
        let (code, text) = run_child("validates_child", None);
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_fault_validates_after_its_waiter_is_registered in a process of its own"]
    fn validates_child() {
        let (a, ua) = create(0, false, true).unwrap();
        let (first, second) = two_pages(a, a);
        VALIDATE_HOOK.store(replace_and_reuse as fn() as usize, Ordering::SeqCst);
        VALIDATE_AT.store(first, Ordering::SeqCst);
        let v = read_the_first();
        assert_eq!(VALIDATE_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert!(!event_within(ua, 0), "an event was posted for an address the userfaultfd no longer has");
        assert_eq!(v, Some(0), "the faulting read did not end");
        assert!(is_missing(second) && !is_missing(first));
        assert_eq!(munmap_of(first, PAGE), 0);
        assert_eq!(munmap_of(second, PAGE), 0);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(ua)) };
    }

    /// A fault whose range is freed, and whose slot the same userfaultfd's
    /// next range takes (its arrays reset before that range's window, while
    /// the slot is free), between the validation's reads of the page and of
    /// the slot's `gen`, posts nothing: the page read missing and the
    /// userfaultfd's own are the new range's, and only `gen` read after them
    /// tells. The access runs again and reads the new memory, in no
    /// registration. The macOS backend's test of the same name. In a process
    /// of its own, as the tests above.
    #[test]
    fn test_fault_reads_the_generation_after_the_page() {
        let (code, text) = run_child("generation_after_child", None);
        assert_eq!(code, Some(0), "{text}");
    }

    #[test]
    #[ignore = "run by test_fault_reads_the_generation_after_the_page in a process of its own"]
    fn generation_after_child() {
        let (a, ua) = create(0, false, true).unwrap();
        let (first, second) = two_pages(a, a);
        BETWEEN_HOOK.store(replace_and_reuse as fn() as usize, Ordering::SeqCst);
        BETWEEN_AT.store(first, Ordering::SeqCst);
        let v = read_the_first();
        assert_eq!(BETWEEN_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert!(!event_within(ua, 0), "an event was posted for an address the userfaultfd no longer has");
        assert_eq!(v, Some(0), "the faulting read did not end");
        assert!(is_missing(second) && !is_missing(first));
        assert_eq!(munmap_of(first, PAGE), 0);
        assert_eq!(munmap_of(second, PAGE), 0);
        // SAFETY: closes the user end.
        unsafe { ws::closesocket(sock(ua)) };
    }

    /// A lookup on the thread that is changing a slot, inside its window
    /// (`gen` odd, [`LOCK`] held), ends the process with its line rather
    /// than wait for itself ([`lookup`]): the window holds stores only, so
    /// this is a broken invariant, made here by the window's test hook.
    #[test]
    fn test_a_lookup_inside_its_own_writers_window_ends_the_process() {
        let (code, text) = run_child("own_window_child", None);
        assert_ne!(code, Some(0), "{text}");
        assert!(text.contains("wick: a userfaultfd slot looked up inside its own writer's window"), "{code:?} {text}");
        assert!(!text.contains("the lookup returned"), "{text}");
    }

    #[test]
    #[ignore = "run by test_a_lookup_inside_its_own_writers_window_ends_the_process in a process of its own"]
    fn own_window_child() {
        let (a, _ua) = create(0, false, true).unwrap();
        let mem = map(PAGE as usize);
        FIRST.store(mem, Ordering::SeqCst);
        fn look() {
            let _ = is_missing(FIRST.load(Ordering::SeqCst));
            std::println!("the lookup returned");
        }
        WINDOW_HOOK.store(look as fn() as usize, Ordering::SeqCst);
        let _ = register(a, mem, PAGE);
        std::println!("the lookup returned");
    }
}
