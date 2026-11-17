// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The kernel side of Linux's userfaultfd, on macOS.
//!
//! On Linux, an access to a missing page of memory registered with a
//! userfaultfd queues a page fault event on the descriptor and puts the
//! faulting thread to sleep until a handler fills the page (`UFFDIO_COPY`,
//! `UFFDIO_ZEROPAGE`) and wakes it (`UFFDIO_WAKE`). KVM takes the same path for
//! guest accesses: it resolves stage-2 faults with `get_user_pages`, which
//! faults the host page. This module gives the process those semantics:
//!
//! - Host threads: missing pages are `PROT_NONE`. The `SIGBUS`/`SIGSEGV`
//!   handler queues a page fault event and waits in a waiter slot; signals on
//!   other addresses go to the previous handler.
//! - Guests: Hypervisor.framework does not honour host protections, so the HVF
//!   backend keeps missing pages inaccessible in stage 2
//!   ([`crate::wick_guest::Hooks::stage2`]) and resolves stage-2 faults with
//!   [`fault`].
//! - Pages are filled through a second mapping of them made for the fill
//!   (`mach_vm_remap`, [`fill_view`]) and taken away after it, and only then
//!   made accessible, so no thread sees a page half filled and the pages are
//!   mapped, and charged to the footprint, once.
//! - `madvise(MADV_DONTNEED)` on registered pages makes them missing again and
//!   queues a remove event ([`discarding`]).
//! - `mprotect` of registered memory ([`protecting`]) changes the present
//!   pages and records the protection for every page; missing pages stay
//!   `PROT_NONE` and take it once filled or no longer registered, as Linux's
//!   mprotect changes the vma and leaves its registration as it is. An access
//!   the asked protection refuses is the process's own fault, with no event
//!   ([`asked_allows`]), as Linux checks the vma before the userfaultfd.
//! - `munmap`, and `mmap` with `MAP_FIXED`, of registered memory take its
//!   pages out of the registration in the same step ([`unmapping`]), as
//!   Linux's registration goes with the vma: the new memory, or a mapping
//!   made later in the hole, is in no registration.
//!
//! A registered range is one set of per-page arrays: the
//! missing bit, the protection asked, and the owner, the userfaultfd the
//! page is registered with or none ([`Range::owner`]). Linux's registration
//! belongs to the vma and an unregister of part of one splits it; here the
//! range stays whole and its pages change owner, so an unregister needs no
//! new range and cannot fail for want of one. Firecracker's on-demand uffd
//! handler unregisters the range of every remove event and asserts it
//! succeeds (lib/firecracker/src/firecracker/examples/uffd/on_demand_handler.rs,
//! `unregister_range`), many scattered runs under a balloon
//! (tests/integration_tests/functional/test_uffd.py), where a range per
//! part would run out of the [`MAX_RANGES`] slots. The cost is a byte a
//! page (64 KiB a GiB of 16 KiB pages). A range is freed
//! once no page of it has an owner; its slot keeps the arrays for the next
//! range that fits ([`Range`]).
//!
//! Every change of the arrays is made under [`LOCK`]; the signal handler
//! ([`on_signal`], [`fault`]) and the backend's stage-2 side ([`is_missing`],
//! [`for_each_missing`]) read them without it. Each change keeps one rule:
//! **a page with no owner is never missing** (the owner is set before the
//! missing bit, and the missing bit cleared before the owner), so a reader
//! that sees no owner never waits for a fill. The changes, in order:
//!
//! - register, new memory: a free slot's arrays are reset, or new ones
//!   made (owner the userfaultfd, missing for pages not resident), then the
//!   range is published in the slot's window ([`Range`]'s `gen`), then the
//!   missing pages are made `PROT_NONE` and missing in stage 2. Until then an access goes through to the memory as it is, as it did
//!   a moment before the register.
//! - register, pages of a range no userfaultfd has: asked, then owner, then
//!   missing, then `PROT_NONE` (as above).
//! - unregister, and a userfaultfd's release ([`destroy`]) of its own
//!   pages: the missing pages are given their asked protection (accessible
//!   to the host and to stage 2) first, then each page's missing bit is
//!   cleared, then its owner; then the waiters are woken. A thread whose
//!   access faulted before the protection changed either finds the page
//!   missing and waits in [`fault`] for the wake, or finds it no longer
//!   missing and runs again ([`resolved`], bounded by [`may_retry`]).
//! - unmapping (`munmap`, `MAP_FIXED`): under [`LOCK`] with the system
//!   call; the missing bit, then the owner. A thread waiting on such a page
//!   waits on until its userfaultfd wakes or releases it, as Linux's.
//! - fill (`UFFDIO_COPY`, `UFFDIO_ZEROPAGE`): every page must be the
//!   caller's ([`range_of`]); the data is written through a view made for
//!   the fill and taken away after it ([`fill_view`]), the
//!   pages given their asked protection, then the missing bits cleared, then
//!   the waiters woken. A reader between sees a missing page that is
//!   accessible: [`fault`] waits for the wake, or the access, retried, goes
//!   through.
//! - discard (`MADV_DONTNEED`, `MADV_FREE`): the pages are replaced, set
//!   missing (owned pages only), and made `PROT_NONE`; a remove event goes
//!   to each page's owner ([`vmas`]).
//!
//! An unregister takes any userfaultfd's pages in its range, whichever one
//! it is made through, and wakes their waiters, as Linux 6.12's
//! `userfaultfd_unregister` (fs/userfaultfd.c :1413) checks only that each
//! vma can be registered (:1460 to :1483) and clears every vma that has a
//! userfaultfd (:1500 to :1501), waking its own (:1519). Linux 6.17 refuses
//! one made through another userfaultfd with `EINVAL` ("prevent
//! unregistering through a different userfaultfd", :1474 to :1480); wick
//! follows 6.12, its reference.
//!
//! The order of the locks: [`LOCK`] first, then the hypervisor backend's
//! replace window ([`crate::wick_guest::replacing`]), which a discard
//! ([`discarding`]) and a `MAP_FIXED` mapping ([`unmapping`]) open inside it;
//! no path opens the window and then takes [`LOCK`], as the window holds
//! the system call alone. The backend's stage-2 hook takes its own lock
//! under [`LOCK`] and waits for nothing there.
//!
//! A userfaultfd is one end of a socket pair. Events are [`RECORD`](proto::RECORD)-byte
//! records read from it ([`proto`]). Another process holding the descriptor
//! sends its requests over a private channel it sets up through it; a thread
//! per userfaultfd serves them.
//!
//! The waiter mirror. A fault's record is written into the socket at the
//! fault, and a socket cannot take a record back; Linux's wake takes each
//! waiting fault it wakes off the queue, read or not (v6.12 fs/userfaultfd.c
//! `userfaultfd_wake_function` :141), so a fault not read before its wake is
//! never read. So each userfaultfd has a mirror ([`Ctx`]): one word per
//! waiter slot in shared memory, which this side writes and each reader maps
//! read-only (`OP_MIRROR`). A waiter stores its tag there, waiting, before it
//! validates its page ([`fault`]), and its record carries the tag; a wake
//! clears the waiting bit of the exact tag it saw ([`wake_where`]), and the
//! waiter waits until it is clear. A reader returns a page fault record only
//! while the mirror's word is still its tag, waiting: a record whose waiter
//! was woken before the reader checked it is dropped, however late it was
//! written. The mirror is the only state that says woken.

use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::boxed::Box;
use std::io;
use std::sync::{Mutex, Once};
use std::vec::Vec;

use upstream as libc;

/// Wire format shared with the `userfaultfd` crate.
pub mod proto {
    /// Size of an event, a request header and a reply: four `u64` words.
    pub const RECORD: usize = 32;
    /// Event: `[EVENT_PAGEFAULT, addr, flags, tag]`: `tag` is the waiter's
    /// (its word in the waiter mirror, [`tag`]). 1 before the mirror: a
    /// reader that predates it fails on this type loudly (an unrecognized
    /// event), where it would have returned events whose waiters were woken.
    pub const EVENT_PAGEFAULT: u64 = 3;
    /// Event: `[EVENT_REMOVE, start, end, 0]`.
    pub const EVENT_REMOVE: u64 = 2;
    /// Page fault flag: the access was a write.
    pub const FLAG_WRITE: u64 = 1;
    /// Sent on the userfaultfd with a descriptor: `[HELLO, 0, 0, 0]`. The
    /// descriptor is the sender's end of its request channel.
    pub const HELLO: u64 = 0x10;
    /// Request: `[OP_COPY, dst, len, mode]`, then `len` bytes.
    pub const OP_COPY: u64 = 1;
    /// Request: `[OP_ZEROPAGE, start, len, mode]`.
    pub const OP_ZEROPAGE: u64 = 2;
    /// Request: `[OP_WAKE, start, len, 0]`.
    pub const OP_WAKE: u64 = 3;
    /// Request: `[OP_REGISTER, start, len, 0]`.
    pub const OP_REGISTER: u64 = 4;
    /// Request: `[OP_UNREGISTER, start, len, 0]`.
    pub const OP_UNREGISTER: u64 = 5;
    /// Request: `[OP_MIRROR, 0, 0, 0]`. Reply: `[size, 0, 0, 0]` with the
    /// waiter mirror's read-only descriptor (`SCM_RIGHTS`), a POSIX shared
    /// memory object of `size` bytes ([`mirror_bytes`]); a negative errno
    /// and no descriptor if it fails. A serving thread that predates the
    /// mirror answers `-EINVAL` (an unknown request).
    pub const OP_MIRROR: u64 = 6;
    /// Copy and zeropage mode: do not wake the waiting threads.
    pub const MODE_DONTWAKE: u64 = 1;
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

    /// The mirror object's size: its words in whole pages of `page` bytes
    /// (macOS's shared memory is sized in pages, xnu bsd/kern/posix_shm.c
    /// `pshm_truncate`'s `vm_map_round_page`).
    pub const fn mirror_bytes(page: usize) -> usize {
        (MIRROR_WORDS * 8).div_ceil(page) * page
    }
    // Reply: `[result, count, 0, 0]`: `result` is the byte count, or a
    // negative errno; for a partial copy `-EAGAIN` with the count copied.
}

/// The feature bit (`UFFD_FEATURE_EVENT_REMOVE`) for remove events.
pub const FEATURE_EVENT_REMOVE: u64 = 1 << 3;

const MAX_RANGES: usize = 64;
/// `VM_FLAGS_ANYWHERE`.
const VM_FLAGS_ANYWHERE: c_int = 1;
const MAX_CTX: usize = 16;
const MAX_WAITERS: usize = 256;
const _: () = assert!(MAX_WAITERS == proto::MIRROR_WORDS);
/// The protection bits a page's asked protection keeps.
const PROT_RWX: c_int = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;

/// A slot of [`RANGES`]: a registered range, or free (`start` 0).
///
/// Its per-page arrays belong to the slot and are never freed: a reader
/// without [`LOCK`] (the signal handler, [`fault`], the stage-2 side) may
/// hold them. A range takes the free slot with the least room that fits it,
/// whose arrays it reuses, reset while the slot is free; with none, the
/// first free slot takes new arrays with room for the next power of two of
/// the range's pages ([`array_capacity`]) and keeps the old ones. So what
/// a slot holds grows with the peak of what was registered at once, not
/// with how often: its largest arrays have room for at most twice what its
/// largest range needs, and the ones it outgrew sum to less than those
/// again, so a slot holds less than twice its largest arrays, less than
/// four times what its largest range needs (less than twice for a range of
/// a power of two pages; the least room is 64 pages, 136 bytes); in at
/// most [`MAX_RANGES`] slots
/// (`test_register_and_release_in_a_loop_keeps_the_array_count_flat`). A
/// range needs a byte for the owner, a byte for the asked protection and a
/// bit for missing a page: 136 KiB for 1 GiB of 16 KiB pages (65536, a power
/// of two), under 272 KiB in its slot with any arrays it outgrew.
/// Firecracker's restore registers each region of guest memory once
/// (lib/firecracker/src/vmm/src/persist.rs :581 to :582), one slot each,
/// fresh: on aarch64 one region, two when the memory reaches past the
/// 64-bit MMIO gap (arch/aarch64/mod.rs `arch_memory_regions` :60 to :85);
/// so a 1 GiB guest's userfaultfd holds 136 KiB of arrays.
///
/// `gen` is a sequence count that makes a reader without [`LOCK`] read the
/// slot whole ([`lookup`]). A writer, always under [`LOCK`], records its
/// thread in `writer`, makes `gen` odd, changes `start`, `end`, `page`,
/// and the array pointers, and makes `gen` even again: the window
/// holds those stores only, no allocation, lock or system call (the arrays
/// are made and reset before it). Changes of one page's bits in a live
/// slot (a fill, a discard, an unregister of pages, a protection) do not
/// move it: readers act on them as they are, in the order the module doc
/// gives.
struct Range {
    /// 0: free.
    start: AtomicU64,
    end: AtomicU64,
    /// The page size of the range: the host's, or the huge page's for a
    /// `MAP_HUGETLB` mapping ([`note_mapping`]), where a fault is reported
    /// for and a fill covers a whole huge page, as Linux's hugetlb does.
    page: AtomicU64,
    /// One bit per page: the page is missing.
    missing: AtomicPtr<AtomicU64>,
    /// One byte per page: the userfaultfd the page is registered with, or
    /// [`NONE`] once an unregister or an unmapping took it out. Linux's
    /// registration belongs to the vma, and an unregister of part of one
    /// splits it; here the range stays one set of arrays, and
    /// each page has its owner, so that any userfaultfd may register the
    /// part unregistered with no new range (see the module doc).
    owner: AtomicPtr<AtomicU64>,
    /// One byte per page: the protection asked of the page (`PROT_*` bits),
    /// which a missing page gets once it is filled or no longer registered
    /// ([`protecting`]).
    asked: AtomicPtr<AtomicU64>,
    /// Odd while a writer changes the slot's fields (see above).
    gen: AtomicU64,
    /// The thread (`pthread_self`) whose change made `gen` odd.
    writer: AtomicU64,
}

impl Range {
    const fn new() -> Self {
        Range {
            start: AtomicU64::new(0),
            end: AtomicU64::new(0),
            page: AtomicU64::new(0),
            missing: AtomicPtr::new(ptr::null_mut()),
            owner: AtomicPtr::new(ptr::null_mut()),
            asked: AtomicPtr::new(ptr::null_mut()),
            gen: AtomicU64::new(0),
            writer: AtomicU64::new(0),
        }
    }

    /// The range's page size.
    fn page_size(&self) -> u64 {
        self.page.load(Ordering::Acquire)
    }

    fn test(map: &AtomicPtr<AtomicU64>, page: u64) -> bool {
        bit_of(map.load(Ordering::Acquire), page).is_some_and(|w| w.load(Ordering::SeqCst) & (1 << (page % 64)) != 0)
    }

    /// Under [`LOCK`], where the slot's arrays have room for every page of
    /// its range ([`past_capacity`] otherwise).
    fn set(map: &AtomicPtr<AtomicU64>, page: u64, on: bool) {
        let mask = 1 << (page % 64);
        let Some(w) = bit_of(map.load(Ordering::Acquire), page) else {
            past_capacity("missing", page);
        };
        if on {
            w.fetch_or(mask, Ordering::SeqCst);
        } else {
            w.fetch_and(!mask, Ordering::SeqCst);
        }
    }

    /// The protection asked of `page` (none past the array's room).
    fn asked(&self, page: u64) -> c_int {
        byte_of(self.asked.load(Ordering::Acquire), page).map_or(0, |b| c_int::from(b.load(Ordering::Acquire)))
    }

    /// Under [`LOCK`], as [`Self::set`].
    fn set_asked(&self, page: u64, prot: c_int) {
        let Some(b) = byte_of(self.asked.load(Ordering::Acquire), page) else {
            past_capacity("asked", page);
        };
        b.store((prot & PROT_RWX) as u8, Ordering::Release);
    }

    /// The userfaultfd `page` is registered with, if any (none past the
    /// array's room).
    fn owner(&self, page: u64) -> Option<usize> {
        let owner = byte_of(self.owner.load(Ordering::Acquire), page)?.load(Ordering::SeqCst);
        (owner != NONE).then_some(usize::from(owner))
    }

    /// Whether `page` is registered.
    fn owned(&self, page: u64) -> bool {
        self.owner(page).is_some()
    }

    /// Registers `page` with userfaultfd `ctx`, or takes it out (`None`).
    /// Under [`LOCK`], as [`Self::set`].
    fn set_owner(&self, page: u64, ctx: Option<usize>) {
        let Some(b) = byte_of(self.owner.load(Ordering::Acquire), page) else {
            past_capacity("owner", page);
        };
        b.store(ctx.map_or(NONE, |c| c as u8), Ordering::SeqCst);
    }

    /// Changes the slot's fields with `change`, `gen` odd meanwhile (see the
    /// type's doc). Under [`LOCK`]; `change` only stores.
    fn changing(&self, change: impl FnOnce()) {
        self.writer.store(this_thread(), Ordering::SeqCst);
        self.gen.fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        tests::window_hook();
        change();
        self.gen.fetch_add(1, Ordering::SeqCst);
        self.writer.store(0, Ordering::SeqCst);
    }
}

/// A change under [`LOCK`] of a page past its slot's array: the arrays are
/// sized for the slot's range at its register, so this is a broken
/// invariant, and a change dropped would lose a registration or a fill
/// silently. Ends the process, as a fill's view that cannot be taken away
/// does ([`drop_fill_view`]).
fn past_capacity(array: &str, page: u64) -> ! {
    std::eprintln!("wick: userfaultfd page {page} is past its slot's {array} array");
    std::process::abort();
}

/// The calling thread, as [`Range::writer`] records it. Async-signal-safe.
fn this_thread() -> u64 {
    // SAFETY: reads the calling thread's own identifier.
    let me = unsafe { libc::pthread_self() };
    me as u64
}

/// A per-page array of a slot: its first word is its capacity, the pages it
/// has room for; then a bit a page ([`bit_of`]) or a byte a page
/// ([`byte_of`]).
///
/// The one rule that makes a stale pointer harmless: every index is checked
/// against the capacity read from the array itself, never against the
/// slot's range. A reader without [`LOCK`] may read a slot's bounds of one
/// range and its pointers of another (released and reused between its
/// loads); its index then may pass the end of the array it holds. Checked
/// so, it reads nothing there, and the slot's `gen`, which every such
/// change moves, makes it read again ([`lookup`]). Arrays are never freed,
/// so the capacity word itself is always there to read.
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

/// Whether `page` is within `array`'s capacity ([`array_capacity`]'s rule).
fn within(array: *const AtomicU64, page: u64) -> bool {
    if array.is_null() {
        return false;
    }
    // SAFETY: a slot's array, never freed; its first word is its capacity.
    let capacity = unsafe { (*array).load(Ordering::Acquire) };
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

/// [`Range::owner`]'s byte for a page in no registration.
const NONE: u8 = u8::MAX;
const _: () = assert!(MAX_CTX < NONE as usize);

/// A userfaultfd: the kernel end of its socket pair (-1: free).
struct Ctx {
    fd: AtomicI32,
    features: AtomicU64,
    /// The waiter mirror, mapped read-write here; null when there is no
    /// userfaultfd (before [`create`] has made it, after [`destroy`]).
    mirror: AtomicPtr<AtomicU64>,
    /// The mirror's read-only descriptor, sent to each reader (-1: none).
    mirror_fd: AtomicI32,
    /// Threads using the mirror or the kernel end ([`enter`]): [`destroy`]
    /// unmaps and closes them once none is left.
    users: AtomicUsize,
}

/// A thread waiting for a page.
struct Waiter {
    /// The page address; 0: free.
    page: AtomicU64,
    /// The userfaultfd the fault was posted to: only its wakes and its
    /// release end the wait, as Linux's waiter is on its context's queue.
    ctx: AtomicUsize,
    /// The waiters this slot has held: the count in their tags.
    count: AtomicU64,
    /// A Mach semaphore.
    sem: AtomicU64,
}

static RANGES: [Range; MAX_RANGES] = [const { Range::new() }; MAX_RANGES];
static CTXS: [Ctx; MAX_CTX] = [const {
    Ctx {
        fd: AtomicI32::new(-1),
        features: AtomicU64::new(0),
        mirror: AtomicPtr::new(ptr::null_mut()),
        mirror_fd: AtomicI32::new(-1),
        users: AtomicUsize::new(0),
    }
}; MAX_CTX];
static WAITERS: [Waiter; MAX_WAITERS] = [const {
    Waiter {
        page: AtomicU64::new(0),
        ctx: AtomicUsize::new(usize::MAX),
        count: AtomicU64::new(0),
        sem: AtomicU64::new(0),
    }
}; MAX_WAITERS];
static PAGE: AtomicU64 = AtomicU64::new(0);
/// The `MAP_HUGETLB` mappings made through the compatibility `mmap`
/// (`[start, end)`): a userfaultfd registered on one works in huge pages.
/// A mapping made over one without the flag takes its place; an unmapped
/// one is forgotten when something is mapped over it.
static HUGE_MAPPINGS: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());
/// Held by every test that makes huge page mappings: what [`huge_page_of`]
/// answers for an address next to a test's mapping is then that test's own,
/// not a huge mapping another test made there in the meantime.
#[cfg(test)]
pub(crate) fn huge_mapping_test() -> std::sync::MutexGuard<'static, ()> {
    static TESTS: Mutex<()> = Mutex::new(());
    TESTS.lock().unwrap_or_else(|e| e.into_inner())
}
/// Number of registered ranges (the I/O wrappers skip all work at 0).
static REGISTERED: AtomicUsize = AtomicUsize::new(0);
/// Serializes changes to the ranges. Taken through [`lock`]. A change that
/// also opens the hypervisor backend's replace window (a discard, a
/// `MAP_FIXED` mapping or an unmapping of registered memory) takes it first
/// and the window inside it; no path opens the window first and takes it
/// inside (the window's change is the system call alone).
static LOCK: Mutex<()> = Mutex::new(());

/// Takes [`LOCK`], and counts it in [`CHANGES`]. Under `cfg(test)`, a
/// caller that finds it held first counts itself in `tests::LOCK_WAITS`, so
/// that a test can tell, with no timing, that a thread waits for it.
fn lock() -> std::sync::MutexGuard<'static, ()> {
    #[cfg(test)]
    match LOCK.try_lock() {
        Ok(guard) => {
            CHANGES.fetch_add(1, Ordering::SeqCst);
            return guard;
        }
        Err(std::sync::TryLockError::Poisoned(e)) => {
            CHANGES.fetch_add(1, Ordering::SeqCst);
            return e.into_inner();
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            tests::LOCK_WAITS.fetch_add(1, Ordering::SeqCst);
        }
    }
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CHANGES.fetch_add(1, Ordering::SeqCst);
    guard
}
/// How many times [`LOCK`] was taken: every change of a registered range
/// (a fill, a discard, an unregister, a release, a protection change, an
/// unmapping) is made under it, so a fault that finds this count unchanged
/// since its last retry finds the ranges as they were then ([`may_retry`]).
static CHANGES: AtomicU64 = AtomicU64::new(0);
/// Changes of memory under way without [`LOCK`]: an `munmap`, `MAP_FIXED`
/// mapping, `mprotect` or discard that found no registered range in reach
/// ([`unlocked_change`]).
static UNLOCKED_CHANGES: AtomicUsize = AtomicUsize::new(0);
/// Registers under way ([`register`]).
static REGISTERING: AtomicUsize = AtomicUsize::new(0);
/// Where a register waits for [`UNLOCKED_CHANGES`] to reach 0.
static DRAINED: (Mutex<()>, std::sync::Condvar) = (Mutex::new(()), std::sync::Condvar::new());

/// A change of memory running without [`LOCK`]; ends when dropped.
struct UnlockedChange;

impl Drop for UnlockedChange {
    fn drop(&mut self) {
        end_unlocked_change();
    }
}

fn end_unlocked_change() {
    if UNLOCKED_CHANGES.fetch_sub(1, Ordering::SeqCst) == 1 && REGISTERING.load(Ordering::SeqCst) > 0 {
        let _drained = DRAINED.0.lock().unwrap_or_else(|e| e.into_inner());
        DRAINED.1.notify_all();
    }
}

/// Whether a change of `[start, end)` (an `munmap`, a `MAP_FIXED` mapping,
/// an `mprotect`, a discard) may run without [`LOCK`]: when it touches no
/// registered range (`touches` is false) and no register is under way. On
/// Linux the mm's lock orders such a change and a register: either the
/// register finds the memory as the change left it, or the change takes the
/// registration with it. Here the change counts itself in
/// [`UNLOCKED_CHANGES`] and then reads [`REGISTERING`]; a register counts
/// itself in [`REGISTERING`] and then waits for [`UNLOCKED_CHANGES`] to be 0
/// before it reads the mappings ([`register`]). Both are `SeqCst`, so of a
/// change and a register that overlap in time at least one sees the other
/// (Dekker's order): either the change takes [`LOCK`] and so runs before or
/// after the whole register, or the register waits until the change is
/// done. A register waits only for changes already running without the
/// lock; changes that begin while it waits take [`LOCK`], so it cannot be
/// starved.
///
/// The two orders: (1) the change's increment comes first in the single
/// order of `SeqCst` operations. Then the register's wait reads a count
/// above 0 and waits until the change has dropped it, after its system
/// call, and only then reads the mappings. (2) The register's increment
/// comes first. Then the change reads [`REGISTERING`] above 0 and diverts:
/// it drops its own count before it takes [`LOCK`] (so the register it saw
/// is not left waiting on it), and under the lock it decides again whether
/// it touches a registered range; unmapping, protecting and
/// discarding_or_refusing each do, by walking the ranges under the lock
/// (`slots`, or `RANGES` in discarding) rather than by reusing the
/// lock-free read. The wait is on a `Mutex` and `Condvar`, which a signal
/// handler must not take: none of the three is reached from one. The
/// handler (`on_signal`) calls only `asked_allows`, `fault` and the
/// previous handler, and `fault` waits on a Mach semaphore; the raw
/// `protect` is wick_uffd's own `mprotect`, not the compatibility one.
/// Returns the change's count, ended when dropped, or `None`: take
/// [`LOCK`].
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

static INIT: Once = Once::new();
static OLD_SIGBUS: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());
static OLD_SIGSEGV: AtomicPtr<libc::sigaction> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" {
    static mach_task_self_: libc::mach_port_t;
    fn semaphore_create(
        task: libc::mach_port_t,
        semaphore: *mut u32,
        policy: c_int,
        value: c_int,
    ) -> c_int;
    fn semaphore_signal(semaphore: u32) -> c_int;
    fn semaphore_wait(semaphore: u32) -> c_int;
    fn mach_vm_region(
        target_task: libc::mach_port_t,
        address: *mut u64,
        size: *mut u64,
        flavor: c_int,
        info: *mut c_int,
        count: *mut u32,
        object_name: *mut libc::mach_port_t,
    ) -> c_int;
    fn mach_vm_deallocate(target_task: libc::mach_port_t, address: u64, size: u64) -> c_int;
    fn mach_vm_remap(
        target_task: libc::mach_port_t,
        target_address: *mut u64,
        size: u64,
        mask: u64,
        flags: c_int,
        src_task: libc::mach_port_t,
        src_address: u64,
        copy: c_int,
        cur_protection: *mut c_int,
        max_protection: *mut c_int,
        inheritance: u32,
    ) -> c_int;
}

/// The host's page size.
fn page_size() -> u64 {
    PAGE.load(Ordering::Relaxed)
}

/// Ranges whose protection, as asked of this libc's `mmap` or `mprotect`,
/// XNU widened: a write or execute protection is given read too (xnu
/// bsd/kern/kern_mman.c, `mmap` :349 to :351, `mprotect` :1251 to :1253;
/// "the hardware currently does not support writing without
/// read-before-write"), where a Linux vma keeps what was asked (no
/// `VM_READ`). The hypervisor backend holds the guest to the vma's rule
/// ([`mapped_protections`]). Sorted, disjoint.
///
/// Its lock is a leaf: held only around a system call and its record
/// ([`protection_change`]) or a read ([`mapped_protections`]), never while
/// another lock is taken. The compatibility `mprotect`, `munmap` and
/// `MAP_FIXED` `mmap` make their system call and its record under it, so
/// for overlapping ranges the records come in the kernel's order; a new
/// mapping's range is no one else's until `mmap` returned, so it is recorded
/// after ([`note_protection`]). Only ranges asked with a write or execute
/// protection and no read are kept, which Firecracker never asks (its
/// guest memory is `PROT_READ | PROT_WRITE`, `PROT_READ` or `PROT_NONE`), so
/// in a Firecracker run the list stays empty; an entry goes when its range is
/// protected again or unmapped through this libc.
///
/// The one stale case: a range unmapped and mapped again by the system's own
/// calls, not this libc's, keeps its record, and a later mapping there whose
/// protection is exactly what XNU made of the recorded ask (the ask with
/// read) reads as that ask, write or execute without read. That is a read
/// refused that the host allows, never a permission the host does not give;
/// a mapping there with any other protection reads as it is
/// ([`mapped_protections`]).
static WIDENED: Mutex<Vec<(u64, u64, i8)>> = Mutex::new(Vec::new());

/// Records the protection `prot` asked of `[start, start + len)` by a
/// `mmap` that succeeded and made a new mapping there: kept when XNU widened
/// it (a write or execute protection without read), forgotten otherwise.
pub fn note_protection(start: u64, len: u64, prot: c_int) {
    note_locked(&mut WIDENED.lock().unwrap_or_else(std::sync::PoisonError::into_inner), start, len, prot);
}

/// Makes a change of protection or mapping with `call` and records what
/// `noted` says it did (`start`, `len`, the protection asked, -1 for a range
/// unmapped), in one step under [`WIDENED`]'s lock. A call that failed
/// records nothing: XNU's `mprotect` checks the whole range before it
/// changes any of it (osfmk/vm/vm_map.c, xnu-12377.1.9, `vm_map_protect`:
/// the first pass :5945, the changes from :6063).
pub fn protection_change<T>(call: impl FnOnce() -> T, noted: impl FnOnce(&T) -> Option<(u64, u64, c_int)>) -> T {
    let mut all = WIDENED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let done = call();
    if let Some((start, len, prot)) = noted(&done) {
        #[cfg(test)]
        between_call_and_record(start);
        note_locked(&mut all, start, len, prot);
    }
    done
}

/// Tests: run once by the next [`protection_change`] of a range starting at
/// the address given, between its system call and its record, so that a
/// test can start another change of the same range there.
#[cfg(test)]
#[allow(clippy::type_complexity)]
static BETWEEN_CALL_AND_RECORD: Mutex<Option<(u64, Box<dyn FnOnce() + Send>)>> = Mutex::new(None);

#[cfg(test)]
fn between_call_and_record(start: u64) {
    let mut hook = BETWEEN_CALL_AND_RECORD.lock().unwrap();
    if hook.as_ref().is_some_and(|&(at, _)| at == start) {
        let (_, f) = hook.take().unwrap();
        drop(hook);
        f();
    }
}

fn note_locked(all: &mut Vec<(u64, u64, i8)>, start: u64, len: u64, prot: c_int) {
    let rw_x = libc::PROT_WRITE | libc::PROT_EXEC;
    let kept_ask = prot >= 0 && prot & libc::PROT_READ == 0 && prot & rw_x != 0;
    if all.is_empty() && !kept_ask {
        // Nothing to cut and nothing to keep: every change of a Firecracker
        // run, which asks no protection XNU widens.
        return;
    }
    let end = start.saturating_add(len);
    let mut kept = Vec::with_capacity(all.len() + 2);
    for &(s, e, p) in all.iter() {
        if e <= start || s >= end {
            kept.push((s, e, p));
            continue;
        }
        if s < start {
            kept.push((s, start, p));
        }
        if e > end {
            kept.push((end, e, p));
        }
    }
    if kept_ask {
        kept.push((start, end, prot as i8));
    }
    kept.sort_unstable_by_key(|&(s, _, _)| s);
    *all = kept;
}

/// Tests: whether [`WIDENED`] has an entry over `[start, end)`.
#[cfg(test)]
fn widened_over(start: u64, end: u64) -> bool {
    WIDENED.lock().unwrap().iter().any(|&(s, e, _)| s < end && start < e)
}

/// Records a mapping `[start, start + len)` the compatibility `mmap` made,
/// with or without `MAP_HUGETLB`.
pub fn note_mapping(start: u64, len: u64, huge: bool) {
    let end = start.saturating_add(len);
    let mut all = HUGE_MAPPINGS.lock().unwrap();
    let mut kept = Vec::with_capacity(all.len() + 2);
    for &(s, e) in all.iter() {
        if e <= start || s >= end {
            kept.push((s, e));
            continue;
        }
        if s < start {
            kept.push((s, start));
        }
        if e > end {
            kept.push((end, e));
        }
    }
    if huge {
        kept.push((start, end));
    }
    *all = kept;
}

/// The first part of `[start, end)` that is all huge page mappings or all
/// ordinary memory: its end, and whether it is huge.
pub fn huge_segment(start: u64, end: u64) -> (u64, bool) {
    let all = HUGE_MAPPINGS.lock().unwrap();
    if let Some(&(_, e)) = all.iter().find(|&&(s, e)| s <= start && start < e) {
        return (e.min(end), true);
    }
    let next = all.iter().map(|&(s, _)| s).filter(|&s| s > start).min().unwrap_or(end);
    (next.min(end), false)
}

/// Whether any of `[start, end)` is a huge page mapping.
pub fn touches_huge(start: u64, end: u64) -> bool {
    let all = HUGE_MAPPINGS.lock().unwrap();
    all.iter().any(|&(s, e)| s < end && start < e)
}

/// The page size of `[start, end)` if all of it is huge page mappings:
/// [`crate::linux_items::HUGE_PAGE`]; `None` for ordinary memory, or for a
/// range only part of which is huge (one range has one page size).
pub fn huge_page_of(start: u64, end: u64) -> Option<u64> {
    let all = HUGE_MAPPINGS.lock().unwrap();
    let mut at = start;
    while at < end {
        // Adjacent huge mappings (one made fixed over part of another) are
        // kept as separate entries.
        at = all.iter().find(|&&(s, e)| s <= at && at < e)?.1;
    }
    Some(crate::linux_items::HUGE_PAGE)
}

fn errno_err(errno: c_int) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

fn init() -> io::Result<()> {
    let mut result = Ok(());
    INIT.call_once(|| {
        // SAFETY: sysconf has no preconditions.
        PAGE.store(
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64,
            Ordering::Relaxed,
        );
        for w in WAITERS.iter() {
            let mut sem = 0u32;
            // SAFETY: creates a semaphore owned by this task.
            if unsafe { semaphore_create(mach_task_self_, &mut sem, 0, 0) } != 0 {
                result = Err(errno_err(libc::ENOMEM));
                return;
            }
            w.sem.store(u64::from(sem), Ordering::Release);
        }
        for (sig, old) in [(libc::SIGBUS, &OLD_SIGBUS), (libc::SIGSEGV, &OLD_SIGSEGV)] {
            // SAFETY: installs a handler; the previous one is kept for chaining.
            unsafe {
                let mut act: libc::sigaction = core::mem::zeroed();
                act.sa_sigaction = on_signal as *const () as usize;
                act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
                libc::sigemptyset(&mut act.sa_mask);
                let prev = Box::into_raw(Box::new(core::mem::zeroed::<libc::sigaction>()));
                if libc::sigaction(sig, &act, prev) != 0 {
                    result = Err(io::Error::last_os_error());
                    return;
                }
                old.store(prev, Ordering::Release);
            }
        }
    });
    if PAGE.load(Ordering::Relaxed) == 0 {
        return Err(errno_err(libc::ENOMEM));
    }
    result
}

/// What [`lookup`] found.
enum Found<T> {
    /// `addr` is in this slot's range, its page and the page's start, the
    /// slot's `gen` when it was read, and what was read of it.
    In(&'static Range, u64, u64, u64, T),
    /// In no range.
    Out,
    /// A slot is being changed by the calling thread itself ([`Range::changing`]):
    /// a fault inside the window, a bug or a signal that interrupted it. It
    /// cannot wait for itself (it holds [`LOCK`], which a fill needs); the
    /// caller takes the address for no registration of ours, and a fault for
    /// the process's own, handed to the previous handler.
    Mine,
}

/// Finds the registered page holding `addr` and reads it with `read(range,
/// page)`, consistently without [`LOCK`]: each slot's `gen` is read before
/// its fields and again after `read` (a fence between), and a change
/// between makes the whole lookup start over. A slot that is odd (a writer
/// in its window) is waited for, by the nanosleep [`fault`] waits with for a
/// waiter slot; the window holds stores only, so the wait is its few
/// stores, unless the writer's thread is preempted in it. A slot odd by the
/// calling thread is [`Found::Mine`]. A start over needs a write of that
/// slot that began after the first read, and two writes of one slot are
/// separated by at least one system call outside the window (a register
/// reads the memory's map entries and residency before its window,
/// `mapped_entries` and `missing_pages`; a release follows the change that
/// freed the range: an unmapping's own call, an unregister's read of the
/// map entries, the read of a userfaultfd's end that found it closed), so a
/// lookup, a few
/// loads, starts over again only if each of its tries overlaps a window.
/// Async-signal-safe.
fn lookup<T>(addr: u64, read: impl Fn(&'static Range, u64) -> T) -> Found<T> {
    // Any slot in the calling thread's own window, whichever slot `addr` is
    // in: its writer holds [`LOCK`], so a wait of this thread for a fill
    // would never end.
    let me = this_thread();
    if RANGES.iter().any(|r| r.gen.load(Ordering::SeqCst) & 1 != 0 && r.writer.load(Ordering::SeqCst) == me) {
        return Found::Mine;
    }
    'again: loop {
        for r in RANGES.iter() {
            let g1 = r.gen.load(Ordering::SeqCst);
            if g1 & 1 != 0 {
                let ts = libc::timespec { tv_sec: 0, tv_nsec: 100_000 };
                // SAFETY: async-signal-safe sleep.
                unsafe { libc::nanosleep(&ts, ptr::null_mut()) };
                continue 'again;
            }
            let start = r.start.load(Ordering::Acquire);
            #[cfg(test)]
            tests::lookup_hook(addr, start);
            let (end, ps) = (r.end.load(Ordering::Acquire), r.page_size());
            let inside = start != 0 && ps != 0 && addr >= start && addr < end;
            let found = inside.then(|| {
                let page = (addr - start) / ps;
                (page, start + page * ps, read(r, page))
            });
            core::sync::atomic::fence(Ordering::Acquire);
            if r.gen.load(Ordering::SeqCst) != g1 {
                continue 'again;
            }
            if let Some((page, at, value)) = found {
                return Found::In(r, page, at, g1, value);
            }
        }
        return Found::Out;
    }
}

/// The range and page index of `addr`, if it is registered memory. Under
/// [`LOCK`], where no slot changes.
fn find(addr: u64) -> Option<(&'static Range, u64)> {
    match lookup(addr, |_, _| ()) {
        Found::In(r, page, ..) => Some((r, page)),
        _ => None,
    }
}

/// Whether `addr` is in a registered page that is missing.
pub fn is_missing(addr: u64) -> bool {
    matches!(lookup(addr, |r, page| r.owned(page) && Range::test(&r.missing, page)), Found::In(.., true))
}

/// The kinds of host access a fault can be, as Linux's arm64 fault handler
/// tells them apart.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    Exec,
}

/// Whether the protection asked of the registered page holding `addr`
/// ([`protecting`]) allows a host access of kind `access`. Linux checks the
/// vma's flags before it handles a fault (arch/arm64/mm/fault.c, v6.12,
/// `do_page_fault` :590 to :595: `if (!(vma->vm_flags & vm_flags))` is
/// `bad_area` with `SEGV_ACCERR`), so an access they refuse never reaches
/// the userfaultfd. The flags it needs (:553 to :568): an instruction fetch
/// `VM_EXEC`; a write `VM_WRITE`; a read any of `VM_READ`, `VM_WRITE`
/// ("Write implies read") and `VM_EXEC`, which Linux takes for a read when
/// the processor has no EPAN (`FEAT_PAN3`, Armv8.7). It is taken as on a
/// processor without it: macOS's `hw.optional.arm` lists no PAN feature, so
/// a newer Apple processor that has it is not told apart; an execute-only
/// page is not one Firecracker asks for. Async-signal-safe.
fn asked_allows(addr: u64, access: Access) -> bool {
    matches!(lookup(addr, |r, page| allows(r.asked(page), access)), Found::In(.., true))
}

/// Whether asked protection `prot` allows `access` ([`asked_allows`]).
fn allows(prot: c_int, access: Access) -> bool {
    let need = match access {
        Access::Exec => libc::PROT_EXEC,
        Access::Write => libc::PROT_WRITE,
        Access::Read => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    };
    prot & need != 0
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
    let mut done = 0;
    while done < bytes.len() {
        // SAFETY: async-signal-safe write of a local buffer.
        let n = unsafe { libc::write(fd, bytes[done..].as_ptr().cast(), bytes.len() - done) };
        if n <= 0 {
            // SAFETY: reads this thread's errno.
            if n < 0 && unsafe { *libc::__error() } == libc::EINTR {
                continue;
            }
            // The handler side is gone: nobody will serve the fault.
            return;
        }
        done += n as usize;
    }
}

/// The mirror of userfaultfd `ctx`, held against its release until [`leave`];
/// `None` if it has none (released). Async-signal-safe.
///
/// The count is raised before the mirror is read, and [`destroy`] takes the
/// mirror away before it reads the count (SeqCst both): either this reads
/// the mirror gone, or [`destroy`] sees the count and waits for it to fall.
fn enter(ctx: usize) -> Option<&'static [AtomicU64; MAX_WAITERS]> {
    let c = CTXS.get(ctx)?;
    c.users.fetch_add(1, Ordering::SeqCst);
    let m = c.mirror.load(Ordering::SeqCst);
    if m.is_null() {
        c.users.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    // SAFETY: a mapping of MAX_WAITERS words, kept until `users` is 0.
    Some(unsafe { &*m.cast::<[AtomicU64; MAX_WAITERS]>() })
}

/// The waiter mirror of userfaultfd `ctx`, for a reader in this process (the
/// `userfaultfd` crate's object that made it): `MIRROR_WORDS` words, mapped
/// until the userfaultfd's last user descriptor is closed.
pub fn mirror(ctx: usize) -> Option<*const AtomicU64> {
    let m = CTXS.get(ctx)?.mirror.load(Ordering::SeqCst);
    (!m.is_null()).then_some(m.cast_const())
}

/// Ends an [`enter`] that returned the mirror.
fn leave(ctx: usize) {
    CTXS[ctx].users.fetch_sub(1, Ordering::SeqCst);
}

/// Resolves an access to `addr`: if it is a missing registered page, queues
/// a page fault event and waits until the page is filled and the waiters are
/// woken. Returns false if `addr` is not a missing registered page.
/// Async-signal-safe.
pub fn fault(addr: u64, write: bool) -> bool {
    #[cfg(test)]
    tests::fault_hook(addr);
    let Found::In(range, page, page_addr, g1, Some(ctx)) = lookup(addr, |r, page| {
        if Range::test(&r.missing, page) {
            r.owner(page)
        } else {
            None
        }
    }) else {
        return false;
    };
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
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 100_000,
        };
        // SAFETY: async-signal-safe sleep.
        unsafe { libc::nanosleep(&ts, ptr::null_mut()) };
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
    // here, each a store before a load against a writer's store before a
    // load (SeqCst all). The slot's: the waiter is in [`WAITERS`] before
    // `gen` is read, after the page's bits (`test_fault_reads_the_generation_after_the_page`),
    // against a writer's `gen` store before it changes the slot. The
    // wake's: the tag is in the mirror before the bits are read, against a
    // writer's change before its wake loads the mirror ([`wake_where`]). So
    // a waiter whose reads saw the page before a change is woken by that
    // change's wake, its tag cleared; one that reads after it sees the
    // change, posts nothing and runs its access again
    // (`test_fault_validates_after_its_waiter_is_registered`). A page made
    // missing again after the change takes a change under [`LOCK`] in a
    // `gen` window, which `g1`, read before the tag, then no longer matches.
    word.store(tag, Ordering::SeqCst);
    #[cfg(test)]
    tests::validate_hook(addr);
    // Filled, or taken out, since the lookup: no fault to report.
    let report = Range::test(&range.missing, page) && range.owner(page) == Some(ctx);
    #[cfg(test)]
    tests::between_hook(addr);
    let same = range.gen.load(Ordering::SeqCst) == g1;
    // Woken already (by a wake of its page, or spuriously: a wake that read
    // the slot's page of the waiter before): no record, the access runs again.
    if report && same && word.load(Ordering::SeqCst) == tag {
        let flags = if write { proto::FLAG_WRITE } else { 0 };
        #[cfg(test)]
        tests::post_hook(addr);
        post(ctx, [proto::EVENT_PAGEFAULT, addr, flags, tag]);
        while word.load(Ordering::SeqCst) == tag {
            // SAFETY: a semaphore created at init; Mach traps are async-signal-safe.
            unsafe { semaphore_wait(slot.sem.load(Ordering::Acquire) as u32) };
        }
    }
    word.store(0, Ordering::SeqCst);
    leave(ctx);
    slot.ctx.store(usize::MAX, Ordering::SeqCst);
    slot.page.store(0, Ordering::SeqCst);
    true
}

/// Wakes the threads waiting for pages in `[start, start + len)`, whichever
/// userfaultfd they wait on.
pub fn wake(start: u64, len: u64) {
    wake_where(|_, page| page >= start && page < start.saturating_add(len));
}

/// Wakes the threads waiting on userfaultfd `ctx` for pages in `[start,
/// start + len)`, as Linux's `wake_userfault` wakes its context's queue
/// (fs/userfaultfd.c, v6.12, `userfaultfd_wake_function` :120 to :122).
fn wake_ctx(ctx: usize, start: u64, len: u64) {
    wake_where(|c, page| c == ctx && page >= start && page < start.saturating_add(len));
}

/// Wakes the waiters `which(ctx, page)` names: clears the waiting bit of
/// the exact tag read from the mirror, so the bit of a later waiter of the
/// slot is never cleared, and a reader drops the woken waiter's record from
/// then on, read or not, as Linux's wake takes the waiter off its queue
/// (v6.12 fs/userfaultfd.c `userfaultfd_wake_function` :141). The slot's
/// page and the tag may be two waiters' (the slot changed hands between):
/// then the later one is woken spuriously and runs its access again, as a
/// Linux fault woken spuriously retries.
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
            unsafe { semaphore_signal(w.sem.load(Ordering::Acquire) as u32) };
        }
        leave(ctx);
    }
}

/// Whether an access to `addr` that faulted would now go through: the
/// host's protection of its page allows the access, and, when the page is
/// in a registered range, it is not missing and its asked protection allows
/// it too ([`asked_allows`]; a missing page keeps `PROT_NONE`, so the host's
/// protection refuses every access to it). The host's protection of a
/// present registered page is the asked one: a fill sets it
/// ([`protect_as_asked`] in [`fill`]), and [`protecting`] changes it and
/// records the same protection as asked, under [`LOCK`]; XNU's widening of
/// a write protection without read (bsd/kern/kern_mman.c, `mprotect` :1251
/// to :1253) gives a host protection that allows a read, which the asked
/// one allows as well ("write implies read", [`asked_allows`]). A page
/// whose mapping a call outside this library replaced may hold another
/// protection; the host's is the one read here.
///
/// Not as Linux: an address in no registered range whose page refused the
/// access when it faulted, and whose protection came to allow it before
/// this handler read it (an `mprotect` by another thread, this library's or
/// the system's), is retried, where Linux decides at the fault and delivers
/// the signal; the handler cannot tell it from a page an unregister freed
/// meanwhile. Before this rule it went to the previous handler.
///
/// Async-signal-safe: one `mach_vm_region`, a Mach message whose reply port
/// is the thread's own (xnu-12377.1.9 libsyscall/mach/mig_reply_port.c
/// `mig_get_reply_port` :64 to :77: no allocation, no lock; a thread's
/// first one is made by `mach_port_construct`). Firecracker's run-phase
/// sandbox profile allows each (overlay/vmm/ext/sandbox.rs: `mach_vm_region`
/// in `MIG_ROUTINES`, `mach_msg2_trap` and
/// `_kernelrpc_mach_port_construct_trap` in `MACH_TRAPS`); a refused call
/// would leave the fault to the previous handler, as before this rule.
fn resolved(addr: u64, access: Access) -> bool {
    match lookup(addr, |r, page| (r.owned(page) && Range::test(&r.missing, page)) || !allows(r.asked(page), access)) {
        Found::In(.., true) | Found::Mine => return false,
        Found::In(.., false) | Found::Out => {}
    }
    const VM_REGION_BASIC_INFO_64: c_int = 9;
    let (mut at, mut size, mut object) = (addr, 0u64, 0);
    let mut info = [0 as c_int; 16];
    let mut count = 9u32;
    // SAFETY: valid output buffers, `info` larger than the flavor's 9 words.
    let kr = unsafe {
        mach_vm_region(mach_task_self_, &mut at, &mut size, VM_REGION_BASIC_INFO_64, info.as_mut_ptr(), &mut count, &mut object)
    };
    let need = match access {
        Access::Exec => libc::PROT_EXEC,
        Access::Write => libc::PROT_WRITE,
        Access::Read => libc::PROT_READ,
    };
    // vm_region_basic_info_64 starts with the current protection.
    kr == 0 && at <= addr && addr - at < size && info[0] & need == need
}

/// A thread's retries of one address ([`may_retry`]).
struct Retry {
    thread: AtomicU64,
    addr: AtomicU64,
    /// [`CHANGES`] at the last retry.
    changes: AtomicU64,
    count: AtomicU64,
}

/// Retries by thread, at [`retry_index`]; a thread that shares an entry
/// with another resets its count, and the other's.
static RETRIES: [Retry; 64] = [const {
    Retry {
        thread: AtomicU64::new(0),
        addr: AtomicU64::new(0),
        changes: AtomicU64::new(0),
        count: AtomicU64::new(0),
    }
}; 64];

/// The retries of one address by one thread with no change of the ranges
/// in between ([`CHANGES`]) that [`on_signal`] makes before it hands the
/// fault to the previous handler. A retry of a resolved fault goes through,
/// or faults on a page that changed since (missing again: a change under
/// [`LOCK`]); a second retry with nothing changed would be the same fault
/// again.
const RETRY_BOUND: u64 = 2;

/// The entry of [`RETRIES`] for thread `me` (its `pthread_self`): the high
/// bits of a multiplicative mix. A `pthread_t` lies at the top of its
/// thread's stack mapping, so two threads' values differ by multiples of
/// the page, and their low bits are equal: `(me >> 4) % 64` put 16 live
/// threads in one entry (measured, macOS 27.2: every one in entry 0), the
/// mix in 16 (`test_live_threads_spread_over_the_retry_entries`).
fn retry_index(me: u64) -> usize {
    (me.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58) as usize % RETRIES.len()
}

/// Whether the calling thread may retry its access to `addr` once more:
/// false after [`RETRY_BOUND`] retries of it with no change of the ranges
/// in between. So a wrong reading of [`resolved`] ends as the fault it is,
/// handed to the previous handler, while nothing changes; while other
/// threads change the ranges ([`CHANGES`] moves at every fill, discard or
/// unregister), it is retried again after each change, for as long as they
/// go on, and ends when they stop. A fault [`resolved`] reads wrongly (a
/// SIGBUS on a mapping whose protection allows the access: a file mapping
/// past its end, a pager's error) is thus retried twice after each fill
/// during an on-demand restore, where before this rule, and on Linux, it
/// ended at once. Async-signal-safe.
fn may_retry(addr: u64) -> bool {
    // SAFETY: reads the calling thread's own identifier.
    let me = unsafe { libc::pthread_self() } as u64;
    let r = &RETRIES[retry_index(me)];
    let changes = CHANGES.load(Ordering::SeqCst);
    let count = if r.thread.load(Ordering::Relaxed) == me
        && r.addr.load(Ordering::Relaxed) == addr
        && r.changes.load(Ordering::Relaxed) == changes
    {
        r.count.load(Ordering::Relaxed) + 1
    } else {
        r.thread.store(me, Ordering::Relaxed);
        r.addr.store(addr, Ordering::Relaxed);
        r.changes.store(changes, Ordering::Relaxed);
        1
    };
    r.count.store(count, Ordering::Relaxed);
    count <= RETRY_BOUND
}

extern "C" fn on_signal(sig: c_int, info: *mut libc::siginfo_t, uctx: *mut libc::c_void) {
    // SAFETY: the kernel passes a valid siginfo.
    let addr = unsafe { (*info).si_addr } as u64;
    #[cfg(test)]
    tests::signal_hook(addr);
    // ESR from the thread state: uc_mcontext (offset 48) -> __es.__esr (offset 8).
    // SAFETY: the Darwin arm64 ucontext and mcontext layout.
    let esr = unsafe {
        let mcontext = *(uctx.cast::<u8>().add(48).cast::<*const u8>());
        *(mcontext.add(8).cast::<u32>())
    };
    let ec = esr >> 26;
    let write = (ec == 0x24 || ec == 0x25) && esr & (1 << 6) != 0;
    // An instruction abort (EC 0x20 from EL0, 0x21 from EL1).
    let access = match (ec, write) {
        (0x20 | 0x21, _) => Access::Exec,
        (_, true) => Access::Write,
        (_, false) => Access::Read,
    };
    // An access the asked protection refuses is the process's own fault, as
    // on Linux: on to the previous handler.
    if is_missing(addr) && asked_allows(addr, access) && fault(addr, write) {
        // Retry the access.
        return;
    }
    // A page that was missing when the access faulted and was filled or
    // unregistered before this handler read it (or before `fault` did):
    // retried, as Linux's fault finds the page present, or the vma no
    // longer registered, and maps it.
    if resolved(addr, access) && may_retry(addr) {
        return;
    }
    let old = if sig == libc::SIGBUS {
        &OLD_SIGBUS
    } else {
        &OLD_SIGSEGV
    };
    let old = old.load(Ordering::Acquire);
    // SAFETY: the action saved at init.
    let act = unsafe { &*old };
    if act.sa_flags & libc::SA_SIGINFO != 0 && act.sa_sigaction > 1 {
        // SAFETY: chaining to the previous handler with the same arguments.
        let f: extern "C" fn(c_int, *mut libc::siginfo_t, *mut libc::c_void) =
            unsafe { core::mem::transmute(act.sa_sigaction) };
        f(sig, info, uctx);
    } else if act.sa_sigaction == libc::SIG_IGN {
        // Returning would fault again forever: take the default action.
        // SAFETY: resets the disposition; the access faults again and dies.
        unsafe { libc::signal(sig, libc::SIG_DFL) };
    } else if act.sa_sigaction == libc::SIG_DFL {
        // SAFETY: as above.
        unsafe { libc::signal(sig, libc::SIG_DFL) };
    } else {
        // SAFETY: a plain handler.
        let f: extern "C" fn(c_int) = unsafe { core::mem::transmute(act.sa_sigaction) };
        f(sig);
    }
}

/// Tells the HVF backend ([`crate::wick_guest::Hooks::stage2`]) that
/// registered pages became present (they must be accessible to the guest)
/// or missing (they must fault).
fn stage2(start: u64, len: u64, present: bool) {
    crate::wick_guest::stage2(start, len, present);
}

/// Calls `f(start, len)` for each run of missing registered pages in
/// `[start, start + len)`, in the pages of each range (a huge page is
/// whole; host pages outside the ranges).
pub fn for_each_missing(start: u64, len: u64, mut f: impl FnMut(u64, u64)) {
    let ps = page_size();
    if ps == 0 {
        return;
    }
    let end = start.saturating_add(len);
    let mut run: Option<u64> = None;
    let mut addr = start - start % ps;
    while addr < end {
        // The page holding `addr`, the one after it, and whether it is missing.
        // Each piece is read whole by `lookup`, which starts that piece over,
        // not the walk, when its slot changed meanwhile.
        let (page_start, next, missing) = match lookup(addr, |r, page| {
            (r.page_size(), r.owned(page) && Range::test(&r.missing, page))
        }) {
            Found::In(_, _, page_start, _, (rps, missing)) => (page_start, page_start + rps, missing),
            // Unregistered memory holds no missing page: on to the next
            // range (a walk by host pages over a span as large as a
            // `MADV_DONTNEED` may name would not end). The next start is
            // read without the slots' `gen`: a range registered meanwhile
            // may be passed over, as one registered just after the walk.
            Found::Out | Found::Mine => {
                let next = RANGES
                    .iter()
                    .map(|r| r.start.load(Ordering::Acquire))
                    .filter(|&s| s > addr)
                    .min()
                    .unwrap_or(end)
                    .min(end);
                (addr, next.max(addr + ps), false)
            }
        };
        match (missing, run) {
            (true, None) => run = Some(page_start),
            (false, Some(s)) => {
                f(s, page_start - s);
                run = None;
            }
            _ => {}
        }
        addr = next;
    }
    if let Some(s) = run {
        f(s, addr - s);
    }
}

fn protect(addr: u64, len: u64, prot: c_int) -> io::Result<()> {
    // SAFETY: changes the protection of registered memory only.
    if unsafe { libc::mprotect(addr as *mut _, len as usize, prot) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Gives the pages of range `r` in `[a, b)` (whole pages of it) the
/// protection asked of each ([`protecting`]), in runs of one protection.
fn protect_as_asked(r: &Range, a: u64, b: u64) -> io::Result<()> {
    let base = r.start.load(Ordering::Acquire);
    let ps = r.page_size();
    let mut at = a;
    while at < b {
        let prot = r.asked((at - base) / ps);
        let mut to = at + ps;
        while to < b && r.asked((to - base) / ps) == prot {
            to += ps;
        }
        protect(at, to - at, prot)?;
        at = to;
    }
    Ok(())
}

/// Wraps an `mprotect(start, len, prot)`, which `apply` makes, of memory
/// that may be registered. Linux's mprotect changes a vma's protection and
/// leaves its userfaultfd registration as it is (mm/mprotect.c, v6.12,
/// `mprotect_fixup` :603: `vma_modify_flags` :664 and `vm_flags_reset` :677,
/// nothing of `vm_userfaultfd_ctx`), and an access the protection allows to
/// a missing page faults to the userfaultfd; here a missing page is
/// `PROT_NONE` so that it faults, which a plain mprotect
/// would undo, letting the process read zeros and write to a page a later
/// fill overwrites. So registered missing pages keep `PROT_NONE`, `apply`
/// changes the rest, piece by piece in order (an error ends the call, as
/// Linux's walk of the vmas ends at one, with what came before changed),
/// and every registered page has `prot` recorded as asked: a missing page
/// gets it once filled ([`copy`], [`zeropage`]) or no longer registered
/// ([`unregister`], the userfaultfd closed), and keeps it across a discard
/// that makes it missing again. A range that touches no registered range,
/// or a start off a host page (which `apply` refuses, `EINVAL`), goes to
/// `apply` as it is. The pages of a huge page range are whole: a range that
/// cuts one is `EINVAL`, as Linux's hugetlb refuses to split a vma off a
/// huge page boundary (mm/hugetlb.c `hugetlb_vm_op_split`).
pub fn protecting(start: u64, len: u64, prot: c_int, apply: impl Fn(u64, u64) -> c_int) -> c_int {
    let host = page_size();
    let end = start.checked_add(len).and_then(|e| e.checked_next_multiple_of(host.max(1)));
    let Some(end) = end.filter(|_| host != 0 && len != 0 && start.is_multiple_of(host)) else {
        return apply(start, len);
    };
    if let Some(_unlocked) = unlocked_change(|| slots(start, end).next().is_some()) {
        return apply(start, len);
    }
    let _guard = lock();
    for r in slots(start, end) {
        let (s, e, ps) = (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire), r.page_size());
        if !(start.max(s) - s).is_multiple_of(ps) || !(end.min(e) - s).is_multiple_of(ps) {
            crate::linux_items::set_errno(libc::EINVAL);
            return -1;
        }
    }
    let mut missing = Vec::new();
    for_each_missing(start, end - start, |a, l| missing.push((a.max(start), (a + l).min(end))));
    // The pieces between the missing runs go to `apply`; the asked
    // protection is recorded as the walk passes each page.
    let record = |a: u64, b: u64| {
        for r in slots(a, b) {
            let (s, ps) = (r.start.load(Ordering::Acquire), r.page_size());
            let (from, to) = (a.max(s), b.min(r.end.load(Ordering::Acquire)));
            for page in (from - s) / ps..(to - s) / ps {
                if r.owned(page) {
                    r.set_asked(page, prot);
                }
            }
        }
    };
    let mut at = start;
    for (a, b) in missing.into_iter().chain(core::iter::once((end, end))) {
        if a > at {
            let rc = apply(at, a - at);
            if rc != 0 {
                return rc;
            }
            record(at, a);
        }
        record(a, b);
        // A missing run keeps its protection until it is filled, and
        // takes the one asked then (`protect_as_asked`): recorded as asked,
        // under `LOCK` as every change of a registered range is.
        if b > a {
            note_protection(a, b - a, prot);
        }
        at = b;
    }
    0
}

/// Mirrors made and not yet given back ([`new_mirror`], [`drop_mirror`]).
#[cfg(test)]
static MIRRORS: AtomicUsize = AtomicUsize::new(0);

/// How many fresh names [`new_mirror`] tries when the name it drew is
/// taken: one taken is already a draw of 64 random bits matching another's.
const MIRROR_NAME_TRIES: u32 = 8;

/// A test's look at a mirror's name ([`MIRROR_NAMED`]).
#[cfg(test)]
type MirrorHook = Box<dyn FnMut(&core::ffi::CStr)>;

#[cfg(test)]
std::thread_local! {
    /// Run between a mirror's opens and its unlink, with its name, on the
    /// thread that makes it (tests only: a product build keeps no name).
    static MIRROR_NAMED: core::cell::RefCell<Option<MirrorHook>> = const { core::cell::RefCell::new(None) };
}

/// A waiter mirror: a POSIX shared memory object of [`proto::mirror_bytes`],
/// named `/fcm.<pid>.u` and 64 random bits from `getentropy` (16 hex
/// digits; under the sandbox's rule for this process's objects, vmm's
/// sandbox.rs `shm_rule`), made with mode 0400, opened a second time
/// read-only and unlinked at once, so that only these two descriptors reach
/// it. The name cannot be taken first or guessed, and while it is there a
/// process of the same uid could open it for reading only, which gives it
/// waiter tags (slot numbers and counts), no guest data (SECURITY.md, Fixed
/// defects, "macOS: a memfd and a waiter mirror had a name anyone could
/// guess while they were made"). No predictable name stands in when
/// `getentropy` fails: the error is returned. Returns its read-write mapping
/// and the read-only descriptor (close-on-exec); the read-write descriptor is
/// closed.
fn new_mirror() -> io::Result<(*mut AtomicU64, c_int)> {
    let bytes = proto::mirror_bytes(page_size() as usize);
    let mut tries = 0;
    let (rw, ro) = loop {
        let mut bits = [0u8; 8];
        // SAFETY: a buffer of 8 bytes, under getentropy's 256.
        if unsafe { libc::getentropy(bits.as_mut_ptr().cast(), bits.len()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let name = std::format!("/fcm.{}.u{:016x}\0", std::process::id(), u64::from_ne_bytes(bits));
        let cname = name.as_ptr().cast::<core::ffi::c_char>();
        // SAFETY: a NUL-terminated name; the results are checked. Its
        // maker's descriptor is read-write whatever the mode: the mode is
        // asked of an open of an existing object only (xnu-12377.121.6
        // bsd/kern/posix_shm.c :534).
        let rw = unsafe { libc::shm_open(cname, libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o400 as libc::c_uint) };
        if rw < 0 {
            let e = io::Error::last_os_error();
            tries += 1;
            if e.raw_os_error() == Some(libc::EEXIST) && tries < MIRROR_NAME_TRIES {
                continue;
            }
            return Err(e);
        }
        // SAFETY: as above.
        let ro = unsafe { libc::shm_open(cname, libc::O_RDONLY, 0 as libc::c_uint) };
        let e = io::Error::last_os_error();
        #[cfg(test)]
        MIRROR_NAMED.with_borrow_mut(|hook| {
            if let Some(hook) = hook {
                // SAFETY: the name above, NUL-terminated.
                hook(unsafe { core::ffi::CStr::from_ptr(cname) });
            }
        });
        // SAFETY: as above; the descriptors keep the object.
        let unlinked = unsafe { libc::shm_unlink(cname) } == 0;
        let e = if unlinked { e } else { io::Error::last_os_error() };
        if ro < 0 || !unlinked {
            // SAFETY: the descriptors opened above.
            unsafe {
                libc::close(rw);
                if ro >= 0 {
                    libc::close(ro);
                }
            }
            return Err(e);
        }
        break (rw, ro);
    };
    // SAFETY: the object's descriptor; a fresh shared mapping of it.
    let (sized, map) = unsafe {
        let sized = libc::ftruncate(rw, (proto::MIRROR_WORDS * 8) as libc::off_t) == 0;
        let map = libc::mmap(
            ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            rw,
            0,
        );
        (sized, map)
    };
    let e = io::Error::last_os_error();
    // SAFETY: the read-write descriptor; the mapping keeps the object.
    unsafe { libc::close(rw) };
    if !sized || map == libc::MAP_FAILED {
        if map != libc::MAP_FAILED {
            // SAFETY: the mapping made above.
            unsafe { libc::munmap(map, bytes) };
        }
        // SAFETY: the read-only descriptor opened above.
        unsafe { libc::close(ro) };
        return Err(e);
    }
    // SAFETY: the read-only descriptor opened above.
    unsafe { libc::fcntl(ro, libc::F_SETFD, libc::FD_CLOEXEC) };
    #[cfg(test)]
    MIRRORS.fetch_add(1, Ordering::SeqCst);
    Ok((map.cast(), ro))
}

/// Gives back a mirror [`new_mirror`] made.
fn drop_mirror(map: *mut AtomicU64, ro: c_int) {
    // SAFETY: the mapping and descriptor `new_mirror` made, no longer used.
    unsafe {
        libc::munmap(map.cast(), proto::mirror_bytes(page_size() as usize));
        libc::close(ro);
    }
    #[cfg(test)]
    MIRRORS.fetch_sub(1, Ordering::SeqCst);
}

/// Creates a userfaultfd. Returns its index and the user's descriptor (the
/// other end stays with the serving thread).
pub fn create(features: u64, nonblocking: bool, cloexec: bool) -> io::Result<(usize, c_int)> {
    init()?;
    let (mirror, mirror_fd) = new_mirror()?;
    let mut fds = [0 as c_int; 2];
    // SAFETY: creates two descriptors.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
        let e = io::Error::last_os_error();
        drop_mirror(mirror, mirror_fd);
        return Err(e);
    }
    let [kernel, user] = fds;
    let one: c_int = 1;
    let buf: c_int = 1 << 20;
    // SAFETY: plain socket and descriptor options.
    unsafe {
        for fd in fds {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&one as *const c_int).cast(),
                4,
            );
        }
        libc::setsockopt(
            kernel,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&buf as *const c_int).cast(),
            4,
        );
        libc::fcntl(kernel, libc::F_SETFD, libc::FD_CLOEXEC);
        if cloexec {
            libc::fcntl(user, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        if nonblocking {
            let fl = libc::fcntl(user, libc::F_GETFL);
            libc::fcntl(user, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
    let _guard = lock();
    let Some(index) = CTXS.iter().position(|c| {
        c.fd.compare_exchange(-1, kernel, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) else {
        // SAFETY: closes the descriptors created above.
        unsafe {
            libc::close(kernel);
            libc::close(user);
        }
        drop_mirror(mirror, mirror_fd);
        return Err(errno_err(libc::EMFILE));
    };
    CTXS[index].mirror_fd.store(mirror_fd, Ordering::SeqCst);
    CTXS[index].mirror.store(mirror, Ordering::SeqCst);
    CTXS[index].features.store(features, Ordering::Release);
    std::thread::Builder::new()
        .name("userfaultfd".into())
        .spawn(move || serve(index, kernel))
        .inspect_err(|_| {
            let c = &CTXS[index];
            let (m, fd) = (c.mirror.swap(ptr::null_mut(), Ordering::SeqCst), c.mirror_fd.swap(-1, Ordering::SeqCst));
            drop_mirror(m, fd);
            c.fd.store(-1, Ordering::Release);
        })?;
    Ok((index, user))
}

/// One past the highest address a process maps: `MACH_VM_MAX_ADDRESS`
/// (mach/arm/vm_param.h, 128 TiB less 32 MiB), what Linux's
/// `validate_range` checks against its `TASK_SIZE`.
const TASK_SIZE: u64 = 0x0000_7FFF_FE00_0000;

/// Linux's `validate_range` (fs/userfaultfd.c): a start aligned to host
/// pages and not 0 (Linux: below `mmap_min_addr`), a length of whole host
/// pages and not 0, the range below [`TASK_SIZE`], else `EINVAL`. Returns
/// the range's end.
fn validate_range(start: u64, len: u64) -> Result<u64, c_int> {
    let host = page_size();
    if host == 0
        || start == 0
        || !start.is_multiple_of(host)
        || len == 0
        || !len.is_multiple_of(host)
        || start >= TASK_SIZE
        || len > TASK_SIZE - start
    {
        return Err(libc::EINVAL);
    }
    Ok(start + len)
}

/// The VM map entries in `[start, end)`, cut to it, in order: Linux's vmas
/// of the range, holes left out. Each with its current protection
/// (`PROT_*` bits).
fn mapped_entries(start: u64, end: u64) -> Vec<(u64, u64, c_int)> {
    const VM_REGION_BASIC_INFO_64: c_int = 9;
    let mut entries = Vec::new();
    let mut at = start;
    while at < end {
        let (mut addr, mut size, mut object) = (at, 0u64, 0);
        let mut info = [0 as c_int; 16];
        let mut count = 9u32;
        // SAFETY: valid output buffers, `info` larger than the flavor's 9
        // words. The entry at or after `addr`; KERN_INVALID_ADDRESS when
        // there is none.
        let kr = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut addr,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        if kr != 0 || addr >= end || size == 0 {
            break;
        }
        // vm_region_basic_info_64 starts with the current protection
        // (VM_PROT_* bits are PROT_* bits).
        entries.push((addr.max(at), (addr + size).min(end), info[0] & PROT_RWX));
        at = addr + size;
    }
    entries
}

/// The protection a Linux vma would give each host page of `[start, end)`
/// (both page aligned), for the hypervisor backend's stage 2
/// ([`crate::wick_guest::Hooks::protected`]): `PROT_*` bits, or -1 for a
/// page in no mapping. A page a userfaultfd registered has the protection
/// asked of it ([`protecting`]; its host protection is `PROT_NONE` while it
/// is missing), any other page its mapping's own.
///
/// `f` is given the reader of them, and is called while no register or
/// unregister can be half-way: under [`LOCK`] when the range touches a
/// registration or a register is under way, otherwise counted as a change
/// running without it ([`unlocked_change`]), which a register that starts
/// meanwhile waits for before it reads the mappings. So a register (asked
/// published, then the host made `PROT_NONE`) is seen whole or not at all.
/// `f` takes the backend's memory lock and reads under it, then stores what
/// it read before it lets the lock go: the order is [`LOCK`] (or the
/// count), then that lock, then the read. Two callers for the same pages,
/// each after its own `mprotect` returned, are ordered by the memory lock,
/// and the one that stores last read last, after both calls, so stage 2
/// ends with the protection the host has; a read before the memory lock
/// could be stored after a later caller's (mm/mprotect.c, v6.12, does both
/// the change and the invalidation under the mmap write lock). Not from a
/// signal handler.
pub fn host_protections<T>(start: u64, end: u64, f: impl FnOnce(&dyn Fn() -> Vec<i8>) -> T) -> T {
    let unlocked = unlocked_change(|| slots(start, end).next().is_some());
    let guard = unlocked.is_none().then(lock);
    let locked = guard.is_some();
    let read = || {
        let host = host_page();
        let mut prot = mapped_protections(start, end);
        if locked {
            for r in slots(start, end) {
                let (s, e) = (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire));
                let mut at = s.max(start);
                while at < e.min(end) {
                    let page = (at - s) / r.page_size();
                    if r.owned(page) {
                        prot[((at - start) / host) as usize] = r.asked(page) as i8;
                    }
                    at += host;
                }
            }
        }
        prot
    };
    f(&read)
}

/// The host's page size, also before the first userfaultfd set
/// [`page_size`]: the hypervisor backend reads protections in a process
/// that may never make one.
fn host_page() -> u64 {
    // SAFETY: plain call.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

/// The protection of each host page of `[start, end)` (both page aligned)
/// as its mapping has it now (`PROT_*` bits, -1 for a page in no mapping),
/// registrations not looked at: for a new mapping, which none has
/// registered yet (the hypervisor backend's `replace` hook after a
/// `MAP_FIXED`). Takes no lock.
pub fn mapped_protections(start: u64, end: u64) -> Vec<i8> {
    let host = host_page();
    let mut prot = std::vec![-1i8; ((end - start) / host) as usize];
    // The mappings and the records read in one step: a compatibility
    // change makes its system call and its record under this lock.
    let widened = WIDENED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for (a, b, p) in mapped_entries(start, end) {
        let (a, b) = ((a - start) / host, (b - start).div_ceil(host));
        prot[a as usize..b as usize].fill(p as i8);
    }
    // What was asked where XNU widened it, as a vma keeps it; only where the
    // page has what XNU made of that ask, so a change made since by other
    // means (the system's own `mprotect`) reads as it is.
    for &(s, e, p) in widened.iter().filter(|&&(s, e, _)| s < end && start < e) {
        let (a, b) = ((s.max(start) - start) / host, (e.min(end) - start).div_ceil(host));
        for page in &mut prot[a as usize..b as usize] {
            if *page >= 0 && c_int::from(*page) == c_int::from(p) | libc::PROT_READ {
                *page = p;
            }
        }
    }
    prot
}

/// The protection of the entry of `entries` ([`mapped_entries`]) that
/// holds `addr`, which one does.
fn protection_in(entries: &[(u64, u64, c_int)], addr: u64) -> c_int {
    entries.iter().find(|&&(s, e, _)| s <= addr && addr < e).map_or(0, |&(_, _, prot)| prot)
}

/// The occupied range slots that overlap `[start, end)`.
fn slots(start: u64, end: u64) -> impl Iterator<Item = &'static Range> {
    RANGES.iter().filter(move |r| {
        let s = r.start.load(Ordering::Acquire);
        s != 0 && start < r.end.load(Ordering::Acquire) && s < end
    })
}

/// Which of the `len / ps` pages from `start` on are missing: a page is
/// when any host page of it is not resident. Residency is Linux's, where a
/// page the compressor or swap holds has data and is not missing
/// (crate::mincore).
fn missing_pages(start: u64, len: u64, ps: u64) -> io::Result<Vec<bool>> {
    let host = page_size();
    let mut resident = std::vec![0u8; (len / host) as usize];
    // SAFETY: `resident` has one byte per host page of the range.
    if unsafe { crate::mincore(start as *mut _, len as usize, resident.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(resident
        .chunks((ps / host) as usize)
        .map(|page| page.iter().any(|r| r & 1 == 0))
        .collect())
}

/// Whether all of `[start, end)` is in registered ranges, whose missing
/// pages are inaccessible only to make accesses fault: to the process they
/// are readable and writable memory.
fn all_registered(start: u64, end: u64) -> bool {
    let mut spans: Vec<(u64, u64)> = slots(start, end)
        .map(|r| (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire)))
        .collect();
    spans.sort_unstable();
    let mut at = start;
    for (s, e) in spans {
        if s > at {
            return false;
        }
        at = at.max(e);
    }
    at >= end
}

/// Whether any page of the range in slot `r` is still registered.
fn any_owned(r: &Range) -> bool {
    let pages = (r.end.load(Ordering::Acquire) - r.start.load(Ordering::Acquire)) / r.page_size();
    (0..pages).any(|page| r.owned(page))
}

/// Frees slot `r`: its range is no longer registered memory. Its arrays
/// stay with the slot ([`Range`]), for the next range that fits in them.
fn release(r: &Range) {
    r.changing(|| r.start.store(0, Ordering::Release));
    REGISTERED.fetch_sub(1, Ordering::AcqRel);
}

/// Registers `[start, start + len)` with userfaultfd `ctx`, as Linux's
/// `userfaultfd_register` (fs/userfaultfd.c, v6.12): the range is checked
/// as `validate_range` checks it, then every VM map entry in it, in order
/// (holes are left out; none at all is `EINVAL`), and the first entry that
/// fails decides, with nothing registered:
///
/// - not readable and writable: `EPERM` (Linux refuses only memory that can
///   never be written, and takes anonymous memory with other protections,
///   which fills here would change); registered memory is, whatever its
///   missing pages' protection ([`all_registered`]);
/// - a `MAP_HUGETLB` mapping ([`note_mapping`]) that holds the start or the
///   end of the range not at a huge page boundary: `EINVAL`;
/// - registered with another userfaultfd: `EBUSY`. Pages this one has are
///   left as they are, as Linux leaves a vma already registered with it.
///
/// Pages that are not resident are missing from now on. A `MAP_HUGETLB`
/// mapping is registered in huge pages: a huge page is missing when any
/// host page of it is, and faults and fills work on whole huge pages.
pub fn register(ctx: usize, start: u64, len: u64) -> io::Result<()> {
    let end = validate_range(start, len).map_err(errno_err)?;
    let huge = crate::linux_items::HUGE_PAGE;
    // Changes of memory already under way without the lock end first, so
    // that the mappings read below are the ones they left
    // ([`unlocked_change`]).
    REGISTERING.fetch_add(1, Ordering::SeqCst);
    struct Registering;
    impl Drop for Registering {
        fn drop(&mut self) {
            REGISTERING.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _registering = Registering;
    {
        let mut drained = DRAINED.0.lock().unwrap_or_else(|e| e.into_inner());
        while UNLOCKED_CHANGES.load(Ordering::SeqCst) > 0 {
            #[cfg(test)]
            tests::REGISTER_WAITS.fetch_add(1, Ordering::SeqCst);
            drained = DRAINED.1.wait(drained).unwrap_or_else(|e| e.into_inner());
        }
    }
    let _guard = lock();
    let entries = mapped_entries(start, end);
    let Some(&(first, first_end, _)) = entries.first() else {
        return Err(errno_err(libc::EINVAL));
    };
    if huge_segment(first, first_end).1 && !start.is_multiple_of(huge) {
        return Err(errno_err(libc::EINVAL));
    }
    // The parts to register: the entries, cut where huge page mappings
    // begin and end, adjacent ones of one page size joined.
    let mut parts: Vec<(u64, u64, u64)> = Vec::new();
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    for &(s, e, prot) in &entries {
        if prot & rw != rw && !all_registered(s, e) {
            return Err(errno_err(libc::EPERM));
        }
        let mut at = s;
        while at < e {
            let (next, is_huge) = huge_segment(at, e);
            if is_huge && next == end && !end.is_multiple_of(huge) {
                return Err(errno_err(libc::EINVAL));
            }
            let ps = if is_huge { huge } else { page_size() };
            match parts.last_mut() {
                Some(last) if last.1 == at && last.2 == ps => last.1 = next,
                _ => parts.push((at, next, ps)),
            }
            at = next;
        }
        // Another userfaultfd's page anywhere in the range: EBUSY, with
        // nothing changed, as Linux checks every vma of the range before it
        // changes one (fs/userfaultfd.c, v6.12, `userfaultfd_register`: the
        // check at :1363 to :1366, in the loop over the vmas that ends at
        // :1375, before the change at :1378).
        for r in slots(s, e) {
            let (base, ps) = (r.start.load(Ordering::Acquire), r.page_size());
            let (a, b) = (s.max(base), e.min(r.end.load(Ordering::Acquire)));
            if ((a - base) / ps..(b - base).div_ceil(ps)).any(|page| r.owner(page).is_some_and(|c| c != ctx)) {
                return Err(errno_err(libc::EBUSY));
            }
        }
    }
    // Memory in no range is new ranges; pages of a range that no
    // userfaultfd has (unregistered, or their memory unmapped or mapped over
    // since) are registered again, with this one.
    let mut new = Vec::new();
    for &(s, e, ps) in &parts {
        let mut at = s;
        let mut mine: Vec<(u64, u64)> = slots(s, e)
            .map(|r| (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire)))
            .collect();
        mine.sort_unstable();
        for (a, b) in mine {
            if a > at {
                new.push((at, a, ps));
            }
            at = at.max(b);
        }
        if at < e {
            new.push((at, e, ps));
        }
    }
    // Pages of ranges that no userfaultfd has, with whether they are
    // missing now and their protection, which is what was asked of them:
    // unregistered, they are ordinary memory.
    let mut again = Vec::new();
    for &(s, e, _) in &parts {
        for r in slots(s, e) {
            let base = r.start.load(Ordering::Acquire);
            let ps = r.page_size();
            let (a, b) = (s.max(base), e.min(r.end.load(Ordering::Acquire)));
            for page in (a - base) / ps..(b - base) / ps {
                if !r.owned(page) {
                    let at = base + page * ps;
                    again.push((r, page, missing_pages(at, ps, ps)?[0], protection_in(&entries, at)));
                }
            }
        }
    }
    if RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) == 0).count() < new.len() {
        return Err(errno_err(libc::ENOMEM));
    }
    let mut made: Vec<(u64, u64, u64, Vec<bool>)> = Vec::new();
    for &(s, e, ps) in &new {
        made.push((s, e, ps, missing_pages(s, e - s, ps)?));
    }
    for (s, e, ps, missing) in made {
        let pages = (e - s) / ps;
        // The free slot with the least room that fits, else the first free
        // one: a small range leaves a large slot's arrays to a large range.
        let free = || RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) == 0);
        let capacity_of = |r: &Range| {
            let array = r.missing.load(Ordering::Acquire);
            // SAFETY: a slot's array, never freed; its first word is its capacity.
            if array.is_null() { 0 } else { unsafe { (*array).load(Ordering::Acquire) } }
        };
        let range = free()
            .filter(|r| within(r.missing.load(Ordering::Acquire), pages - 1))
            .min_by_key(|r| capacity_of(r))
            .or_else(|| free().next())
            .unwrap();
        // The arrays are made, or the slot's reset, before the window: a
        // free slot's arrays are read by no lookup that answers (it reads
        // `start` 0 and goes on, or its `gen` moved since).
        let reused = within(range.missing.load(Ordering::Acquire), pages - 1);
        let (missing_bits, owner, asked) = if reused {
            (range.missing.load(Ordering::Acquire), range.owner.load(Ordering::Acquire), range.asked.load(Ordering::Acquire))
        } else {
            let capacity = array_capacity(pages);
            (alloc_array(capacity, 1, 0), alloc_array(capacity, 8, NONE), alloc_array(capacity, 8, 0))
        };
        // SAFETY: arrays made above or the slot's own, never freed.
        let capacity = unsafe { (*missing_bits).load(Ordering::Acquire) };
        for page in 0..capacity {
            let (m, o, a) = if page < pages {
                let prot = (protection_in(&entries, s + page * ps) & PROT_RWX) as u8;
                (missing[page as usize], ctx as u8, prot)
            } else {
                (false, NONE, 0)
            };
            if let Some(w) = bit_of(missing_bits, page) {
                let mask = 1 << (page % 64);
                if m {
                    w.fetch_or(mask, Ordering::SeqCst);
                } else {
                    w.fetch_and(!mask, Ordering::SeqCst);
                }
            }
            if let Some(b) = byte_of(owner, page) {
                b.store(o, Ordering::SeqCst);
            }
            if let Some(b) = byte_of(asked, page) {
                b.store(a, Ordering::SeqCst);
            }
        }
        range.changing(|| {
            range.end.store(e, Ordering::Release);
            range.page.store(ps, Ordering::Release);
            range.missing.store(missing_bits, Ordering::Release);
            range.owner.store(owner, Ordering::Release);
            range.asked.store(asked, Ordering::Release);
            range.start.store(s, Ordering::Release);
        });
        REGISTERED.fetch_add(1, Ordering::AcqRel);
    }
    let mut runs = Vec::new();
    for (r, page, missing, prot) in again {
        // The owner before the missing bit: a page is never missing with no
        // owner (the module doc).
        r.set_asked(page, prot);
        r.set_owner(page, Some(ctx));
        Range::set(&r.missing, page, missing);
        if missing {
            let ps = r.page_size();
            runs.push((r.start.load(Ordering::Acquire) + page * ps, ps));
        }
    }
    for &(s, e, _) in &new {
        for_each_missing(s, e - s, |a, l| runs.push((a, l)));
    }
    // Missing pages fault from now on.
    for (a, l) in runs {
        protect(a, l, libc::PROT_NONE)?;
        stage2(a, l, false);
    }
    Ok(())
}

/// The registered range holding all of `[start, start + len)`, which must be
/// aligned to its pages (huge ones for a huge page range, as Linux's
/// hugetlb `UFFDIO_COPY` requires) and checked as Linux's `validate_range`
/// checks it (`EINVAL`). Every page of it must be registered with `ctx`:
/// a page in no registration (unregistered, or its memory unmapped or
/// replaced) or another userfaultfd's is `ENOENT` for the whole call, as
/// Linux's destination must lie in one vma this userfaultfd has
/// (mm/userfaultfd.c, v6.12, `validate_dst_vma` :34, `uffd_mfill_lock`
/// :113). Pages of one range registered with `ctx` again after an
/// unregister are one with the rest, as Linux merges the vma of a register
/// with its neighbours (`userfaultfd_register_range`, its
/// `vma_modify_flags_uffd` at :1860); two ranges are not.
fn range_of(ctx: usize, start: u64, len: u64) -> Result<&'static Range, c_int> {
    let end = validate_range(start, len)?;
    let (range, first) = find(start).ok_or(libc::ENOENT)?;
    if end > range.end.load(Ordering::Acquire) {
        return Err(libc::ENOENT);
    }
    let ps = range.page_size();
    if !start.is_multiple_of(ps) || !len.is_multiple_of(ps) {
        return Err(libc::EINVAL);
    }
    if (first..first + len / ps).any(|page| range.owner(page) != Some(ctx)) {
        return Err(libc::ENOENT);
    }
    Ok(range)
}

/// Unregisters `[start, start + len)`, as Linux's `userfaultfd_unregister`
/// (fs/userfaultfd.c, v6.12): the range is checked as `validate_range`
/// checks it; it must hold a VM map entry (holes are left out), and a
/// `MAP_HUGETLB` mapping at
/// its start, or a registered one cut by it, only at huge page boundaries
/// (`EINVAL`). Its registered pages, whichever userfaultfd has them (Linux
/// does not ask), become ordinary memory: missing ones zero pages, their
/// waiters woken. Memory not registered is left as it is. A range no page
/// of which is registered any more is freed.
pub fn unregister(_ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    let end = validate_range(start, len)?;
    let huge = crate::linux_items::HUGE_PAGE;
    let _guard = lock();
    let entries = mapped_entries(start, end);
    let Some(&(first, first_end, _)) = entries.first() else {
        return Err(libc::EINVAL);
    };
    if huge_segment(first, first_end).1 && !start.is_multiple_of(huge) {
        return Err(libc::EINVAL);
    }
    // Linux cuts a registered hugetlb vma only at huge page boundaries.
    for r in slots(start, end) {
        let (s, e, ps) = (
            r.start.load(Ordering::Acquire),
            r.end.load(Ordering::Acquire),
            r.page_size(),
        );
        if !(start.max(s) - s).is_multiple_of(ps) || !(end.min(e) - s).is_multiple_of(ps) {
            return Err(libc::EINVAL);
        }
    }
    for &(s, e, _) in &entries {
        for r in slots(s, e) {
            let base = r.start.load(Ordering::Acquire);
            let ps = r.page_size();
            let (a, b) = (s.max(base), e.min(r.end.load(Ordering::Acquire)));
            // Given what was asked of them first, then not missing: a thread
            // that faulted on a page before finds it missing and waits for
            // the wake below.
            let mut runs = Vec::new();
            for_each_missing(a, b - a, |x, l| runs.push((x, l)));
            for (x, l) in runs {
                protect_as_asked(r, x, x + l).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
                stage2(x, l, true);
            }
            // The missing bit before the owner (the module doc).
            for page in (a - base) / ps..(b - base) / ps {
                Range::set(&r.missing, page, false);
                r.set_owner(page, None);
            }
            if !any_owned(r) {
                release(r);
            }
        }
    }
    wake(start, len);
    Ok(())
}

/// Fills missing pages from `dst` on with `fill(view, len)`, through a view
/// of the pages of their own ([`fill_view`]): stops at the first page that
/// is present. The pages are reachable once they are filled and the view is
/// gone: then they take the protection asked of them, and the guest's stage
/// 2 maps them. With the view gone the pages are mapped nowhere, so they are
/// charged to the process's footprint (phys_footprint, which counts a page
/// for each mapping that touched it) by the first mapping that touches
/// them: the guest's stage 2 or the VMM's own. Linux charges a page to the
/// memory cgroup at the fill (v6.12 mm/userfaultfd.c `mfill_atomic_pte_copy`
/// :302) and a zeropage not at all (the shared zero page, :348 to :360); a
/// page filled here and never touched is held and charged to no one until
/// it is (SECURITY.md, Not at parity yet, "macOS: a page is charged to the
/// memory limit once for each mapping that touched it"). Reading each page
/// through the range here would charge it at the fill, and again when the
/// guest touches it. Returns the byte count; `EEXIST` if the first page is
/// present, `EAGAIN` with the count when only some were filled.
fn fill(
    ctx: usize,
    dst: u64,
    len: u64,
    wake_up: bool,
    mut fill: impl FnMut(*mut u8, usize, usize),
) -> Result<u64, (c_int, u64)> {
    let _guard = lock();
    let range = range_of(ctx, dst, len).map_err(|e| (e, 0))?;
    let base = range.start.load(Ordering::Acquire);
    let ps = range.page_size();
    let first = (dst - base) / ps;
    let mut n = 0;
    while n < len / ps {
        let page = first + n;
        if !Range::test(&range.missing, page) {
            break;
        }
        n += 1;
    }
    if n == 0 {
        return Err((libc::EEXIST, 0));
    }
    let bytes = n * ps;
    let view = fill_view(dst, bytes).map_err(|e| (e, 0))?;
    fill(view as *mut u8, bytes as usize, 0);
    drop_fill_view(view, bytes);
    protect_as_asked(range, dst, dst + bytes).map_err(|e| (e.raw_os_error().unwrap_or(libc::EIO), 0))?;
    stage2(dst, bytes, true);
    for page in first..first + n {
        Range::set(&range.missing, page, false);
    }
    if wake_up {
        wake_ctx(ctx, dst, bytes);
    }
    if bytes < len {
        Err((libc::EAGAIN, bytes))
    } else {
        Ok(bytes)
    }
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
    fill(ctx, dst, len, wake_up, |to, n, _| {
        // SAFETY: `to` is a view of missing pages; `src` per the contract.
        unsafe { ptr::copy_nonoverlapping(src, to, n) }
    })
}

/// `UFFDIO_ZEROPAGE`: fills missing pages from `start` on with zeros.
pub fn zeropage(ctx: usize, start: u64, len: u64, wake_up: bool) -> Result<u64, (c_int, u64)> {
    fill(ctx, start, len, wake_up, |to, n, _| {
        // SAFETY: `to` is a view of missing pages.
        unsafe { ptr::write_bytes(to, 0, n) }
    })
}

/// `UFFDIO_WAKE`.
pub fn wake_range(ctx: usize, start: u64, len: u64) -> Result<(), c_int> {
    // Linux checks the range only, not that it is registered (fs/userfaultfd.c,
    // v6.12, `userfaultfd_wake` :1545 to :1575): a thread can wait on a page
    // whose memory was unmapped since, and its handler can still wake it.
    validate_range(start, len)?;
    wake_ctx(ctx, start, len);
    Ok(())
}

/// A mapping of the pages `[dst, dst + len)` (missing pages of a range,
/// `PROT_NONE` there) of their own, read-write, at another address, for one
/// fill to write through while the pages stay out of every other thread's
/// reach; [`drop_fill_view`] takes it away once the fill is done, so that the
/// pages are mapped, and charged to the process's footprint, once (SECURITY.md,
/// Not at parity yet, "macOS: a page is charged to the memory limit once for
/// each mapping that touched it"). It maps the pages the range has now, so a
/// discard or a mapping made over the range since needs nothing done for it.
/// The remap gives the view the pages' protection (`PROT_NONE`) and their
/// maximum, which for memory a userfaultfd takes allows reading and writing
/// (a register refuses other memory, `EPERM`). Errors: `ENOMEM` when the
/// kernel refuses the view, `EPERM` when its maximum does not allow writing.
fn fill_view(dst: u64, len: u64) -> Result<u64, c_int> {
    let mut view = 0u64;
    let (mut cur, mut max) = (0, 0);
    // SAFETY: maps the same pages a second time, shared, anywhere.
    let kr = unsafe {
        mach_vm_remap(
            mach_task_self_,
            &mut view,
            len,
            0,
            VM_FLAGS_ANYWHERE,
            mach_task_self_,
            dst,
            0,
            &mut cur,
            &mut max,
            1, // VM_INHERIT_NONE
        )
    };
    if kr != 0 {
        return Err(libc::ENOMEM);
    }
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    if max & rw != rw || protect(view, len, rw).is_err() {
        drop_fill_view(view, len);
        return Err(libc::EPERM);
    }
    Ok(view)
}

/// Takes away a view [`fill_view`] made. A view that stays would keep the
/// pages charged twice and writable at an address no one tracks, so a
/// refusal ends the process, naming the call.
fn drop_fill_view(view: u64, len: u64) {
    // SAFETY: the view made by fill_view, used by no one any more.
    let kr = unsafe { mach_vm_deallocate(mach_task_self_, view, len) };
    if kr != 0 {
        std::eprintln!("wick: userfaultfd fill: mach_vm_deallocate of its view {view:#x}+{len:#x} failed: {kr}");
        std::process::abort();
    }
}

/// Wraps a `MADV_DONTNEED` of `[start, start + len)`: registered pages are
/// made accessible for `discard` to zero and release them, and the pages of
/// the pieces `discard` reports it discarded are missing again, with a
/// remove event queued for each vma they cover ([`vmas`]; with
/// `EVENT_REMOVE`), as Linux's walk calls `userfaultfd_remove` for each vma
/// (mm/madvise.c, v6.12, `madvise_dontneed_free` :894). Pieces in a huge page
/// range are whole huge pages (Linux's hugetlb `MADV_DONTNEED` wants a huge
/// page aligned start and rounds the end down); pages the discard did not
/// reach keep their contents, as on Linux when it stops at an error.
pub fn discarding(start: u64, len: u64, discard: impl FnOnce(&mut Vec<(u64, u64)>) -> c_int) -> c_int {
    discarding_or_refusing(start, len, |done, _| discard(done))
}

/// [`discarding`] for a discard that may also refuse a piece after its
/// remove event, as Linux's `MADV_FREE` refuses memory that is not private
/// anonymous only after `userfaultfd_remove` (v6.12 mm/madvise.c
/// `madvise_dontneed_free` :894, `madvise_free_single_vma` :797): the
/// discard sets the piece in `refused` and stops there, and the piece's
/// pages keep their contents. The piece is a run of macOS map entries
/// alike (one backing and protection, joined by `linux_items::dontneed`),
/// which is not a vma: where it holds pages of different registrations, or
/// registered and unregistered ones, Linux has several vmas there, as vmas
/// of different userfaultfd contexts or flags do not merge (mm/vma.c
/// `is_mergeable_vma` :24 and :28), and its walk stops at the first one's
/// error (mm/madvise.c `madvise_walk_vmas` :1275 to :1276). So only the
/// first vma's event is posted ([`refused_event`]). The events go out in
/// address order, as Linux's walk of the vmas posts them.
pub fn discarding_or_refusing(
    start: u64,
    len: u64,
    discard: impl FnOnce(&mut Vec<(u64, u64)>, &mut Option<(u64, u64)>) -> c_int,
) -> c_int {
    let ps = page_size();
    let end = start.saturating_add(len);
    let mut done = Vec::new();
    let mut refused = None;
    let touches = || {
        ps != 0
            && RANGES.iter().any(|r| {
                let s = r.start.load(Ordering::Acquire);
                s != 0 && start < r.end.load(Ordering::Acquire) && s < end
            })
    };
    if let Some(_unlocked) = unlocked_change(touches) {
        return discard(&mut done, &mut refused);
    }
    let _guard = lock();
    let mut runs = Vec::new();
    for_each_missing(start, len, |s, l| runs.push((s, l)));
    for &(s, l) in &runs {
        // Missing pages hold zeros: let the discard reach them.
        let _ = protect(s, l, libc::PROT_READ | libc::PROT_WRITE);
    }
    let ret = discard(&mut done, &mut refused);
    let mut events = Vec::new();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        if s == 0 || start >= e || s >= end {
            continue;
        }
        let ps = r.page_size();
        for &(a, b) in &done {
            let (a, b) = (a.max(s), b.min(e));
            if a >= b {
                continue;
            }
            // The range's whole pages inside the piece.
            let (first, last) = ((a - s).div_ceil(ps), (b - s) / ps);
            for page in first..last {
                if r.owned(page) {
                    Range::set(&r.missing, page, true);
                }
            }
        }
        // Every missing page of the range in reach is inaccessible again:
        // the ones just discarded and the ones made accessible above.
        let from = start.max(s) - (start.max(s) - s) % ps;
        let to = (s + (end.min(e) - s).next_multiple_of(ps)).min(e);
        let mut runs = Vec::new();
        for_each_missing(from, to - from, |a, l| runs.push((a, l)));
        for (a, l) in runs {
            let _ = protect(a, l, libc::PROT_NONE);
            stage2(a, l, false);
        }
    }
    // One remove event a vma the discard reached, over the pieces it did,
    // adjacent ones joined: a piece is a run of macOS map entries alike,
    // which need not end where a vma does.
    let mut spans: Vec<(u64, u64)> = Vec::new();
    done.sort_unstable();
    for (a, b) in done {
        match spans.last_mut() {
            Some(last) if last.1 >= a => last.1 = last.1.max(b),
            _ => spans.push((a, b)),
        }
    }
    for (a, b) in spans {
        events.extend(vmas(a, b).into_iter().filter_map(|(ctx, x, y)| remove_event(ctx, x, y)));
    }
    if let Some((a, b)) = refused {
        events.extend(refused_event(a, b));
    }
    events.sort_by_key(|&(_, [_, at, _, _])| at);
    for (ctx, event) in events {
        post(ctx, event);
    }
    ret
}

/// The remove event of a refused piece `[a, b)` (see
/// [`discarding_or_refusing`]): Linux's first vma there, the run of pages
/// from `a` that one userfaultfd has registered, over adjacent ranges of the
/// same userfaultfd, which Linux would have merged into one vma, up to the
/// first page that is unregistered or another's; none when `a` itself is
/// in no registration (`userfaultfd_remove` posts nothing for a vma with no
/// context, fs/userfaultfd.c, v6.12, :777 to :779) or the userfaultfd did not
/// ask for remove events. Called with [`LOCK`] held. A refused piece is never
/// in a huge page range (`MADV_FREE` refuses those before any event).
fn refused_event(a: u64, b: u64) -> Option<(usize, [u64; 4])> {
    let (ctx, x, y) = vmas(a, b).into_iter().next().filter(|&(_, x, _)| x == a)?;
    remove_event(ctx, x, y)
}

/// The remove event of `[a, b)` for userfaultfd `ctx`, if it asked for remove
/// events.
fn remove_event(ctx: usize, a: u64, b: u64) -> Option<(usize, [u64; 4])> {
    (CTXS[ctx].features.load(Ordering::Acquire) & FEATURE_EVENT_REMOVE != 0)
        .then_some((ctx, [proto::EVENT_REMOVE, a, b, 0]))
}

/// The registered vmas Linux would have in `[a, b)`, in address order, as
/// `(ctx, start, end)` over the whole pages there: runs of registered pages
/// of one userfaultfd, one page size and one protection asked. A page in no
/// registration (an unregister of part of a range splits the vma,
/// fs/userfaultfd.c, v6.12, `userfaultfd_unregister` :1413), another
/// userfaultfd's page or another protection asked (vmas of different
/// contexts or flags do not merge, mm/vma.c `is_mergeable_vma` :24 and :28;
/// an `mprotect` of part of a vma splits it, mm/mprotect.c `mprotect_fixup`
/// :603) ends a run; adjacent ranges of one userfaultfd continue it, as
/// Linux merges the vma of a register with its neighbour (mm/userfaultfd.c
/// `userfaultfd_register_range`, its `vma_modify_flags_uffd` at :1860). A hugetlb vma and an ordinary one do
/// not merge, so neither do runs of two page sizes. Called with [`LOCK`]
/// held.
fn vmas(a: u64, b: u64) -> Vec<(usize, u64, u64)> {
    let mut ranges: Vec<&Range> = RANGES
        .iter()
        .filter(|r| {
            let s = r.start.load(Ordering::Acquire);
            s != 0 && s < b && a < r.end.load(Ordering::Acquire)
        })
        .collect();
    ranges.sort_unstable_by_key(|r| r.start.load(Ordering::Acquire));
    // (ctx, start, end, page size, protection asked)
    let mut runs: Vec<(usize, u64, u64, u64, c_int)> = Vec::new();
    for r in ranges {
        let s = r.start.load(Ordering::Acquire);
        let e = r.end.load(Ordering::Acquire);
        let ps = r.page_size();
        let (first, last) = ((a.max(s) - s).div_ceil(ps), (b.min(e) - s) / ps);
        for page in first..last {
            let Some(ctx) = r.owner(page) else {
                continue;
            };
            let at = s + page * ps;
            let asked = r.asked(page);
            match runs.last_mut() {
                Some(run) if run.0 == ctx && run.2 == at && run.3 == ps && run.4 == asked => run.2 = at + ps,
                _ => runs.push((ctx, at, at + ps, ps, asked)),
            }
        }
    }
    runs.into_iter().map(|(ctx, x, y, _, _)| (ctx, x, y)).collect()
}

/// Wraps a change of the mapping of `[start, start + len)` that ends what
/// it held, `change`: a `munmap`, or an `mmap` with `MAP_FIXED`
/// (`mapped_anew`), which `made` says was done. On Linux the registration
/// belongs to the vma and goes with it in the same step, under the mm's
/// lock: munmap gathers the vmas and unmaps them (mm/vma.c, v6.12,
/// `do_vmi_align_munmap` :1332, `vms_gather_munmap_vmas` :1180, which calls
/// fs/userfaultfd.c `userfaultfd_unmap_prep` at :1267), and `MAP_FIXED`
/// unmaps what it maps over first (mm/mmap.c `__mmap_region` :1361, the same
/// gathering at :1386), so the new memory is in no registration. Here, when
/// the range touches a registered range, [`LOCK`] is taken before the change
/// and held until the whole pages it reached are in no registration: no
/// fill, release or other change of the ranges runs in between, which would
/// take the new memory (or another mapping made in a hole) for the old
/// registration's. A range with no page left registered is freed. With
/// `mapped_anew`, pages that were missing are mapped into the guest's stage
/// 2 (the backend's window, inside the change, mapped them as missing). A
/// thread waiting on one of the pages waits on, as Linux's: its
/// userfaultfd's wake or release ends the wait ([`wake_range`],
/// [`destroy`]). A change that fails, or touches no registered range,
/// changes nothing here. A range that cuts a huge page of a huge page range
/// is refused by the callers before (`EINVAL`).
pub fn unmapping<T>(start: u64, len: u64, mapped_anew: bool, change: impl FnOnce() -> T, made: impl Fn(&T) -> bool) -> T {
    let host = page_size();
    let end = start.saturating_add(len);
    let touches = || {
        host != 0
            && RANGES.iter().any(|r| {
                let s = r.start.load(Ordering::Acquire);
                s != 0 && start < r.end.load(Ordering::Acquire) && s < end
            })
    };
    if let Some(_unlocked) = unlocked_change(touches) {
        return change();
    }
    let _guard = lock();
    let result = change();
    if !made(&result) {
        return result;
    }
    #[cfg(test)]
    tests::unmap_hook(start, end);
    let (from, to) = (start - start % host, end.next_multiple_of(host));
    for r in slots(from, to) {
        let (s, e, ps) = (r.start.load(Ordering::Acquire), r.end.load(Ordering::Acquire), r.page_size());
        let (first, last) = ((from.max(s) - s).div_ceil(ps), (to.min(e) - s) / ps);
        if first >= last {
            continue;
        }
        let mut was_missing = Vec::new();
        // The missing bit before the owner (the module doc).
        for page in first..last {
            if r.owned(page) && Range::test(&r.missing, page) {
                was_missing.push(page);
            }
            Range::set(&r.missing, page, false);
            r.set_owner(page, None);
        }
        if mapped_anew {
            for page in was_missing {
                stage2(s + page * ps, ps, true);
            }
        }
        if !any_owned(r) {
            release(r);
        }
    }
    result
}

/// Releases userfaultfd `ctx`: its ranges become ordinary memory and every
/// waiter is woken, as when Linux releases a userfaultfd.
fn destroy(ctx: usize) {
    let _guard = lock();
    for r in RANGES.iter() {
        let s = r.start.load(Ordering::Acquire);
        if s == 0 {
            continue;
        }
        let (e, ps) = (r.end.load(Ordering::Acquire), r.page_size());
        let pages = (e - s) / ps;
        if !(0..pages).any(|page| r.owner(page) == Some(ctx)) {
            continue;
        }
        // Its missing pages, run by run, become ordinary memory; then its
        // pages leave the registration, the missing bit before the owner
        // (the module doc). Another userfaultfd's pages stay its own.
        let mut page = 0;
        while page < pages {
            if r.owner(page) != Some(ctx) || !Range::test(&r.missing, page) {
                page += 1;
                continue;
            }
            let from = page;
            while page < pages && r.owner(page) == Some(ctx) && Range::test(&r.missing, page) {
                page += 1;
            }
            let (a, b) = (s + from * ps, s + page * ps);
            let _ = protect_as_asked(r, a, b);
            stage2(a, b - a, true);
        }
        for page in 0..pages {
            if r.owner(page) == Some(ctx) {
                Range::set(&r.missing, page, false);
                r.set_owner(page, None);
            }
        }
        if !any_owned(r) {
            release(r);
        }
    }
    // Every thread waiting on it, the pages of memory unmapped since
    // included, as Linux's release wakes its whole queue (fs/userfaultfd.c,
    // v6.12, `userfaultfd_release` :873, a range of length 0).
    wake_where(|c, _| c == ctx);
    // Then the mirror goes, and once no thread uses it or the kernel end
    // ([`enter`]: a waiter woken above, on its way out, or one that read
    // the owner before it was cleared and finds the page no longer its),
    // both are given back. Before, a waiter's write could reach a kernel
    // end closed meanwhile, or a descriptor that took its number.
    let c = &CTXS[ctx];
    let mirror = c.mirror.swap(ptr::null_mut(), Ordering::SeqCst);
    while c.users.load(Ordering::SeqCst) != 0 {
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 100_000 };
        // SAFETY: a plain sleep.
        unsafe { libc::nanosleep(&ts, ptr::null_mut()) };
    }
    if !mirror.is_null() {
        drop_mirror(mirror, c.mirror_fd.swap(-1, Ordering::SeqCst));
    }
    let fd = c.fd.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        // SAFETY: the kernel end owned by the serving thread.
        unsafe { libc::close(fd) };
    }
}

fn read_full(fd: c_int, buf: &mut [u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: reads into a local buffer.
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    true
}

fn write_full(fd: c_int, buf: &[u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: writes a local buffer.
        let n = unsafe { libc::write(fd, buf[done..].as_ptr().cast(), buf.len() - done) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return false;
        }
        done += n as usize;
    }
    true
}

fn words(buf: &[u8; proto::RECORD]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for (i, v) in w.iter_mut().enumerate() {
        *v = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
    }
    w
}

/// Receives a record on the kernel end: `None` when every user descriptor
/// is closed, else the descriptor of a `HELLO`. A record that is not a
/// `HELLO`, or comes without a descriptor, is ignored; descriptors not kept
/// are closed. A signal or a record sent in pieces does not end the
/// userfaultfd.
fn recv_hello(fd: c_int) -> Option<Option<c_int>> {
    let mut buf = [0u8; proto::RECORD];
    let mut fds: Vec<c_int> = Vec::new();
    let mut done = 0;
    while done < buf.len() {
        let mut cmsg = [0u64; 64];
        let mut iov = libc::iovec {
            iov_base: buf[done..].as_mut_ptr().cast(),
            iov_len: buf.len() - done,
        };
        // SAFETY: a zeroed msghdr is valid; the buffers outlive the call, and
        // the control messages read are those the kernel wrote.
        let n = unsafe {
            let mut msg: libc::msghdr = core::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg.as_mut_ptr().cast();
            msg.msg_controllen = core::mem::size_of_val(&cmsg) as _;
            let n = libc::recvmsg(fd, &mut msg, libc::MSG_WAITALL);
            let mut c = if n > 0 {
                libc::CMSG_FIRSTHDR(&msg)
            } else {
                ptr::null_mut()
            };
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(c);
                    let len = ((*c).cmsg_len as usize).saturating_sub(data as usize - c as usize);
                    for i in 0..len / core::mem::size_of::<c_int>() {
                        fds.push(ptr::read_unaligned(data.cast::<c_int>().add(i)));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            n
        };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            for fd in fds {
                // SAFETY: descriptors received here and not kept.
                unsafe { libc::close(fd) };
            }
            return None;
        }
        done += n as usize;
    }
    let mut fds = fds.into_iter();
    let peer = if words(&buf)[0] == proto::HELLO {
        fds.next()
    } else {
        None
    };
    for fd in fds {
        // SAFETY: descriptors received here and not kept.
        unsafe { libc::close(fd) };
    }
    Some(peer)
}

/// Serves `[OP_COPY, dst, len, _]`, whose `len` bytes of data follow on
/// `fd`; `None` when the channel closed. The request is checked before the
/// data is read, and the data is read and copied a piece at a time, so a
/// length that names no registered memory costs no memory to refuse. As
/// Linux's `UFFDIO_COPY`, it stops at the first page that is not missing:
/// `EEXIST` if that is the first, else `EAGAIN` with the count copied.
fn serve_copy(
    ctx: usize,
    fd: c_int,
    dst: u64,
    len: u64,
    wake_up: bool,
) -> Option<Result<u64, (c_int, u64)>> {
    // Pieces of a mebibyte, or of the range's page when it is larger (a
    // huge page is filled whole).
    let range = range_of(ctx, dst, len);
    let piece = range.map_or(1 << 20, |r| r.page_size().max(1 << 20));
    let mut result = range.map(|_| 0).map_err(|e| (e, 0));
    let mut buf = Vec::new();
    let mut done = 0;
    while done < len {
        let n = (len - done).min(piece);
        buf.resize(n as usize, 0);
        if !read_full(fd, &mut buf) {
            return None;
        }
        // Once stopped, the rest of the data is read and dropped.
        if let Ok(copied) = result {
            // SAFETY: `buf` holds `n` bytes.
            result = match unsafe { copy(ctx, buf.as_ptr(), dst + done, n, wake_up) } {
                Ok(m) => Ok(copied + m),
                Err((_, m)) if copied + m > 0 => Err((libc::EAGAIN, copied + m)),
                Err(e) => Err(e),
            };
        }
        done += n;
    }
    Some(result)
}

/// Serves one request from a client channel; false when the channel closed.
fn serve_request(ctx: usize, fd: c_int) -> bool {
    let mut head = [0u8; proto::RECORD];
    if !read_full(fd, &mut head) {
        return false;
    }
    let [op, a, b, c] = words(&head);
    let wake_up = c & proto::MODE_DONTWAKE == 0;
    let to_reply = |r: Result<u64, (c_int, u64)>| match r {
        Ok(n) => [n, n],
        Err((e, n)) => [(-(e as i64)) as u64, n],
    };
    let reply = match op {
        proto::OP_COPY => match serve_copy(ctx, fd, a, b, wake_up) {
            Some(r) => to_reply(r),
            None => return false,
        },
        proto::OP_ZEROPAGE => to_reply(zeropage(ctx, a, b, wake_up)),
        proto::OP_WAKE => to_reply(wake_range(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        proto::OP_REGISTER => to_reply(
            register(ctx, a, b)
                .map(|()| 0)
                .map_err(|e| (e.raw_os_error().unwrap_or(libc::EINVAL), 0)),
        ),
        proto::OP_UNREGISTER => to_reply(unregister(ctx, a, b).map(|()| 0).map_err(|e| (e, 0))),
        proto::OP_MIRROR => return send_mirror(ctx, fd),
        _ => to_reply(Err((libc::EINVAL, 0))),
    };
    let mut out = [0u8; proto::RECORD];
    out[..8].copy_from_slice(&reply[0].to_le_bytes());
    out[8..16].copy_from_slice(&reply[1].to_le_bytes());
    write_full(fd, &out)
}

/// Serves `OP_MIRROR`: the reply with the mirror's read-only descriptor.
/// The serving thread holds the mirror while it serves (its `destroy` comes
/// after its loop), so the descriptor is open here.
fn send_mirror(ctx: usize, fd: c_int) -> bool {
    let ro = CTXS[ctx].mirror_fd.load(Ordering::SeqCst);
    let mut out = [0u8; proto::RECORD];
    if ro < 0 {
        out[..8].copy_from_slice(&(-i64::from(libc::EBADF)).to_le_bytes());
        return write_full(fd, &out);
    }
    out[..8].copy_from_slice(&(proto::mirror_bytes(page_size() as usize) as u64).to_le_bytes());
    // SAFETY: arithmetic on a size.
    let space = unsafe { libc::CMSG_SPACE(core::mem::size_of::<c_int>() as u32) } as usize;
    let mut control = std::vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: out.as_mut_ptr().cast(),
        iov_len: out.len(),
    };
    // SAFETY: a msghdr with one buffer and one descriptor, all local.
    let sent = unsafe {
        let mut msg: libc::msghdr = core::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<c_int>() as u32) as _;
        *(libc::CMSG_DATA(c).cast::<c_int>()) = ro;
        libc::sendmsg(fd, &msg, 0)
    };
    match usize::try_from(sent) {
        Ok(n) if n == out.len() => true,
        // The rest of the reply, the descriptor gone with its first byte.
        Ok(n) if n > 0 => write_full(fd, &out[n..]),
        _ => false,
    }
}

/// The serving thread of userfaultfd `ctx`: accepts request channels sent on
/// the kernel end and serves them. Ends when every user descriptor is closed.
fn serve(ctx: usize, kernel: c_int) {
    let mut clients: Vec<c_int> = Vec::new();
    loop {
        let mut fds: Vec<libc::pollfd> = core::iter::once(kernel)
            .chain(clients.iter().copied())
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: `fds` is a valid array.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match recv_hello(kernel) {
                None => break,
                Some(Some(client)) => clients.push(client),
                Some(None) => {}
            }
        }
        let mut closed = Vec::new();
        for p in &fds[1..] {
            if p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                && !serve_request(ctx, p.fd)
            {
                closed.push(p.fd);
            }
        }
        for fd in closed {
            clients.retain(|c| *c != fd);
            // SAFETY: a client channel received above.
            unsafe { libc::close(fd) };
        }
    }
    for fd in clients {
        // SAFETY: as above.
        unsafe { libc::close(fd) };
    }
    destroy(ctx);
}

/// Faults in the missing registered pages of `[addr, addr + len)`, as the
/// Linux kernel does when a system call copies to or from them (`write`: the
/// call writes the memory). Returns whether any page was missing.
pub fn prefault(addr: u64, len: u64, write: bool) -> bool {
    if REGISTERED.load(Ordering::Acquire) == 0 || len == 0 {
        return false;
    }
    let ps = page_size();
    let end = addr.saturating_add(len);
    let mut page = addr - addr % ps;
    let mut any = false;
    while page < end {
        // The first byte of the buffer in this page.
        let at = page.max(addr);
        // A page whose asked protection refuses the access is left to the
        // call, which fails with EFAULT, as Linux's copy fails on it with no
        // fault reaching the userfaultfd.
        let access = if write { Access::Write } else { Access::Read };
        if is_missing(at) && asked_allows(at, access) && fault(at, write) {
            any = true;
        }
        page += ps;
    }
    any
}

/// System calls that copy to or from user memory, with the Linux userfaultfd
/// semantics: Linux waits for missing pages a call touches; these fault them
/// in first, and again if the call fails with `EFAULT` because one was
/// released in between.
pub mod syscalls {
    use core::ffi::{c_int, c_void};

    use upstream::{self as libc, iovec, msghdr, off_t, size_t, sockaddr, socklen_t, ssize_t};

    use super::{prefault, REGISTERED};

    fn errno() -> c_int {
        // SAFETY: reads this thread's errno.
        unsafe { *libc::__error() }
    }

    /// Calls `call` with the buffers `fault` faults in.
    fn with_pages(fault: impl Fn() -> bool, mut call: impl FnMut() -> ssize_t) -> ssize_t {
        if REGISTERED.load(core::sync::atomic::Ordering::Acquire) == 0 {
            return call();
        }
        fault();
        loop {
            let ret = call();
            if ret >= 0 || errno() != libc::EFAULT || !fault() {
                return ret;
            }
        }
    }

    /// SIGPIPE as Linux raises it, after a write to `fd` that returned
    /// `ret`; returns `ret`, with errno as the call left it.
    ///
    /// Linux raises SIGPIPE on the calling thread when a write to a stream
    /// socket (a Unix one or TCP) fails with `EPIPE` having sent nothing, unless the call
    /// passed `MSG_NOSIGNAL` (net/unix/af_unix.c `unix_stream_sendmsg`,
    /// `pipe_err`: `send_sig(SIGPIPE, current, 0)`, which `send_sig_info`
    /// sends to the thread, `PIDTYPE_PID`); `write(2)` and `writev(2)` pass
    /// no flags. xnu raises it for the process (bsd/kern/sys_socket.c
    /// `soo_write`, bsd/kern/uipc_syscalls.c `sendit`), and not at all on a
    /// socket with `SO_NOSIGPIPE`, which Rust's std sets on every socket it
    /// makes on Apple systems (its own writes stand for Linux's, which pass
    /// `MSG_NOSIGNAL`; they do not come here). So only where xnu kept quiet
    /// for that flag alone, this raises it, once: a socket without the flag
    /// has had its signal from xnu, and a pipe (`ENOTSOCK`) too. As on
    /// Linux, a blocked SIGPIPE stays pending for the thread and an ignored
    /// one is dropped (`pthread_kill`).
    fn linux_sigpipe(fd: c_int, flags: c_int, ret: ssize_t) -> ssize_t {
        if ret >= 0 || errno() != libc::EPIPE || flags & libc::MSG_NOSIGNAL != 0 {
            return ret;
        }
        let mut on: c_int = 0;
        let mut len = core::mem::size_of::<c_int>() as socklen_t;
        // SAFETY: an int and its length, as SO_NOSIGPIPE takes.
        let got = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&raw mut on).cast(),
                &mut len,
            )
        };
        // Only a stream socket's write raises it on Linux (a datagram or
        // seqpacket socket's, unix_dgram_sendmsg, does not).
        let mut kind: c_int = 0;
        let mut kind_len = core::mem::size_of::<c_int>() as socklen_t;
        // SAFETY: as above, for SO_TYPE.
        let stream = got == 0
            && on != 0
            && unsafe {
                libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, (&raw mut kind).cast(), &mut kind_len)
            } == 0
            && kind == libc::SOCK_STREAM;
        if stream {
            // SAFETY: a signal to the calling thread.
            unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGPIPE) };
        }
        // SAFETY: this thread's errno, as the call left it.
        unsafe { *libc::__error() = libc::EPIPE };
        ret
    }

    fn iov_pages(iov: *const iovec, count: c_int, write: bool) -> bool {
        let mut any = false;
        for i in 0..count.max(0) as usize {
            // SAFETY: the caller's iovec array has `count` entries.
            let v = unsafe { &*iov.add(i) };
            any |= prefault(v.iov_base as u64, v.iov_len as u64, write);
        }
        any
    }

    /// `read(2)`.
    ///
    /// # Safety
    /// As `read(2)`.
    pub unsafe fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, count as u64, true),
            || unsafe { libc::read(fd, buf, count) },
        )
    }

    /// `write(2)`.
    ///
    /// # Safety
    /// As `write(2)`.
    pub unsafe fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || prefault(buf as u64, count as u64, false),
            || unsafe { libc::write(fd, buf, count) },
        );
        linux_sigpipe(fd, 0, ret)
    }

    /// `pread(2)`.
    ///
    /// # Safety
    /// As `pread(2)`.
    pub unsafe fn pread(fd: c_int, buf: *mut c_void, count: size_t, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, count as u64, true),
            || unsafe { libc::pread(fd, buf, count, offset) },
        )
    }

    /// `pwrite(2)`.
    ///
    /// # Safety
    /// As `pwrite(2)`.
    pub unsafe fn pwrite(fd: c_int, buf: *const c_void, count: size_t, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, count as u64, false),
            || unsafe { libc::pwrite(fd, buf, count, offset) },
        )
    }

    /// `readv(2)`.
    ///
    /// # Safety
    /// As `readv(2)`.
    pub unsafe fn readv(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, iovcnt, true),
            || unsafe { libc::readv(fd, iov, iovcnt) },
        )
    }

    /// `writev(2)`.
    ///
    /// # Safety
    /// As `writev(2)`.
    pub unsafe fn writev(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || iov_pages(iov, iovcnt, false),
            || unsafe { libc::writev(fd, iov, iovcnt) },
        );
        linux_sigpipe(fd, 0, ret)
    }

    /// `preadv(2)`.
    ///
    /// # Safety
    /// As `preadv(2)`.
    pub unsafe fn preadv(fd: c_int, iov: *const iovec, iovcnt: c_int, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, iovcnt, true),
            || unsafe { libc::preadv(fd, iov, iovcnt, offset) },
        )
    }

    /// `pwritev(2)`.
    ///
    /// # Safety
    /// As `pwritev(2)`.
    pub unsafe fn pwritev(fd: c_int, iov: *const iovec, iovcnt: c_int, offset: off_t) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, iovcnt, false),
            || unsafe { libc::pwritev(fd, iov, iovcnt, offset) },
        )
    }

    /// `recv(2)`.
    ///
    /// # Safety
    /// As `recv(2)`.
    pub unsafe fn recv(socket: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, len as u64, true),
            || unsafe { libc::recv(socket, buf, len, flags) },
        )
    }

    /// `send(2)`.
    ///
    /// # Safety
    /// As `send(2)`.
    pub unsafe fn send(socket: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || prefault(buf as u64, len as u64, false),
            || unsafe { libc::send(socket, buf, len, flags) },
        );
        linux_sigpipe(socket, flags, ret)
    }

    /// `recvfrom(2)`.
    ///
    /// # Safety
    /// As `recvfrom(2)`.
    pub unsafe fn recvfrom(
        socket: c_int,
        buf: *mut c_void,
        len: size_t,
        flags: c_int,
        addr: *mut sockaddr,
        addrlen: *mut socklen_t,
    ) -> ssize_t {
        // SAFETY: the caller's contract.
        with_pages(
            || prefault(buf as u64, len as u64, true),
            || unsafe { libc::recvfrom(socket, buf, len, flags, addr, addrlen) },
        )
    }

    /// `sendto(2)`.
    ///
    /// # Safety
    /// As `sendto(2)`.
    pub unsafe fn sendto(
        socket: c_int,
        buf: *const c_void,
        len: size_t,
        flags: c_int,
        addr: *const sockaddr,
        addrlen: socklen_t,
    ) -> ssize_t {
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || prefault(buf as u64, len as u64, false),
            || unsafe { libc::sendto(socket, buf, len, flags, addr, addrlen) },
        );
        linux_sigpipe(socket, flags, ret)
    }

    /// `recvmsg(2)`.
    ///
    /// # Safety
    /// As `recvmsg(2)`.
    pub unsafe fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
        // SAFETY: the caller's msghdr.
        let (iov, n) = unsafe { ((*msg).msg_iov, (*msg).msg_iovlen) };
        // SAFETY: the caller's contract.
        with_pages(
            || iov_pages(iov, n, true),
            || unsafe { libc::recvmsg(fd, msg, flags) },
        )
    }

    /// `sendmsg(2)`.
    ///
    /// # Safety
    /// As `sendmsg(2)`.
    pub unsafe fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
        // SAFETY: the caller's msghdr.
        let (iov, n) = unsafe { ((*msg).msg_iov, (*msg).msg_iovlen) };
        // SAFETY: the caller's contract.
        let ret = with_pages(
            || iov_pages(iov, n, false),
            || unsafe { libc::sendmsg(fd, msg, flags) },
        );
        linux_sigpipe(fd, flags, ret)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use core::sync::atomic::AtomicBool;

    use super::*;

    /// The host's page size, for every test and test helper. The module's
    /// `page_size()` is 0 until `init`, and a test run in a process of its
    /// own that read it first called every range empty: the replaced-memory
    /// tests' first records (4c92edaa) were their own `len` of 0, not the
    /// product's. So this sets the libc up first and refuses a size of 0, and
    /// `test_the_tests_take_the_page_size_from_their_helper` keeps a bare
    /// call out of this module.
    fn test_page_size() -> u64 {
        init().unwrap();
        let size = super::page_size();
        assert_ne!(size, 0, "the page size is 0 after init");
        size
    }

    /// How many times a caller found [`LOCK`] held ([`lock`]).
    pub(super) static LOCK_WAITS: AtomicUsize = AtomicUsize::new(0);

    /// How many times a register waited for changes running without the
    /// lock ([`register`]).
    pub(super) static REGISTER_WAITS: AtomicUsize = AtomicUsize::new(0);

    /// What a change running without the lock calls between its lock-free
    /// check and the change ([`unlocked_change`]): a race test's register.
    static CHANGE_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

    pub(super) fn change_hook() {
        let hook = *CHANGE_HOOK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hook) = hook {
            hook();
        }
    }

    /// What [`unmapping`] calls between the change of the mapping and the
    /// unregistration, with the range: a test's own, for its own range.
    type Hook = fn(u64, u64);
    static UNMAP_HOOK: Mutex<Option<Hook>> = Mutex::new(None);

    pub(super) fn unmap_hook(start: u64, end: u64) {
        let hook = *UNMAP_HOOK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hook) = hook {
            hook(start, end);
        }
    }

    /// What [`on_signal`] calls first ([`HOOK_IN_FAULT`] false), or
    /// [`fault`] first (true), for an access to the page at
    /// [`SIGNAL_HOOK_AT`] (once: the address is cleared): a test's change
    /// of that page between the fault and the handler's, or `fault`'s,
    /// reading of it.
    static SIGNAL_HOOK_AT: AtomicU64 = AtomicU64::new(0);
    static SIGNAL_HOOK: AtomicUsize = AtomicUsize::new(0);
    static HOOK_IN_FAULT: AtomicBool = AtomicBool::new(false);

    pub(super) fn signal_hook(addr: u64) {
        if !HOOK_IN_FAULT.load(Ordering::SeqCst) {
            run_hook(addr);
        }
    }

    pub(super) fn fault_hook(addr: u64) {
        if HOOK_IN_FAULT.load(Ordering::SeqCst) {
            run_hook(addr);
        }
    }

    fn run_hook(addr: u64) {
        let at = SIGNAL_HOOK_AT.load(Ordering::SeqCst);
        if at != 0
            && addr >= at
            && addr < at + test_page_size()
            && SIGNAL_HOOK_AT.compare_exchange(at, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok()
        {
            // SAFETY: set by the test from a `fn()`.
            let hook: fn() = unsafe { core::mem::transmute(SIGNAL_HOOK.load(Ordering::SeqCst)) };
            hook();
        }
    }

    /// Waits until `done`, failing after 10 s (a guard, not a measure: each
    /// condition is one the waited-for thread sets).
    fn until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "{what}: not in 10 s");
            std::thread::yield_now();
        }
    }

    /// The bare calls of the module's page size in `text`, a module's source:
    /// the line of each call in its tests that is neither a method's
    /// (`r.page_size()`), nor the helper's own (`super::`, `test_`), nor in a
    /// comment.
    fn bare_page_size_calls(text: &str) -> Vec<usize> {
        let needle = ["page", "_size()"].concat();
        let Some(tests) = text.find("\nmod tests {") else {
            return Vec::new();
        };
        text[tests..]
            .match_indices(needle.as_str())
            .filter(|&(at, _)| {
                let before = &text[..tests + at];
                let line = &before[before.rfind('\n').map_or(0, |n| n + 1)..];
                !(before.ends_with('.')
                    || before.ends_with("super::")
                    || before.ends_with("test_")
                    || line.trim_start().starts_with("//"))
            })
            .map(|(at, _)| text[..tests + at].lines().count())
            .collect()
    }

    /// Every test and test helper takes the page size from
    /// [`test_page_size`], never from the module's `page_size()`, which is 0
    /// before `init`.
    #[test]
    fn test_the_tests_take_the_page_size_from_their_helper() {
        let call = ["page", "_size()"].concat();
        let case = std::format!(
            "fn f() {{}}\nmod tests {{\n    let ps = {call};\n    r.{call};\n    super::{call};\n    // `{call}`\n}}\n"
        );
        assert_eq!(bare_page_size_calls(&case), [3]);
        let bad = bare_page_size_calls(include_str!("wick_uffd.rs"));
        assert!(bad.is_empty(), "wick_uffd.rs's tests call the page size bare, at lines {bad:?}: use test_page_size()");
    }

    fn map(pages: u64) -> u64 {
        init().unwrap();
        // SAFETY: a fresh anonymous mapping.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                (pages * test_page_size()) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        p as u64
    }

    fn socketpair() -> [c_int; 2] {
        let mut fds = [0; 2];
        // SAFETY: creates two descriptors.
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(r, 0);
        fds
    }

    /// Sends the first `len` bytes of a record with descriptors attached.
    fn send_record(fd: c_int, words: [u64; 4], len: usize, fds: &[c_int]) {
        let mut bytes = [0u8; proto::RECORD];
        for (i, w) in words.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let mut control = [0u64; 8];
        // SAFETY: a msghdr with one buffer and the descriptors.
        let n = unsafe {
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: len,
            };
            let mut msg: libc::msghdr = core::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            if !fds.is_empty() {
                let size = core::mem::size_of_val(fds) as u32;
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = libc::CMSG_SPACE(size) as _;
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(size) as _;
                ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast(), fds.len());
            }
            libc::sendmsg(fd, &msg, 0)
        };
        assert_eq!(n, len as isize);
    }

    /// Waits up to five seconds for `fd` to be readable.
    fn readable(fd: c_int) -> bool {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd.
        unsafe { libc::poll(&mut p, 1, 5000) == 1 }
    }

    fn record(head: [u64; 4]) -> Vec<u8> {
        head.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// Sends a request and its data; returns the reply.
    fn request(chan: c_int, head: [u64; 4], data: &[u8]) -> (i64, u64) {
        let mut msg = record(head);
        msg.extend_from_slice(data);
        assert!(write_full(chan, &msg));
        assert!(readable(chan), "no reply to {head:x?}");
        let mut reply = [0u8; proto::RECORD];
        assert!(read_full(chan, &mut reply));
        let w = words(&reply);
        (w[0] as i64, w[1])
    }

    /// Whether the serving thread answers requests on `chan`.
    fn served(chan: c_int) -> bool {
        request(chan, [proto::OP_WAKE, 0, 0, 0], &[]).0 == err(libc::EINVAL)
    }

    /// A request channel to the serving thread of the userfaultfd `user`.
    fn channel(user: c_int) -> c_int {
        let [mine, theirs] = socketpair();
        send_record(user, [proto::HELLO, 0, 0, 0], proto::RECORD, &[theirs]);
        // The serving thread holds the descriptor once it answered.
        assert!(served(mine));
        // SAFETY: our copy of the end sent.
        unsafe { libc::close(theirs) };
        mine
    }

    fn err(e: c_int) -> i64 {
        -(e as i64)
    }

    /// The variable that tells a test it runs in a process of its own.
    const CHILD: &str = "WICK_UFFD_TEST_ALONE";

    /// Runs test `name` again in a process of its own (this binary, that
    /// test only, ignored or not), with `env` added: `Err` with its status
    /// and output if it did not pass there.
    fn run_alone(name: &str, env: &[(&str, &str)]) -> Result<(), std::string::String> {
        let child = {
            let _spawning = crate::timerfd::spawning();
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([name, "--exact", "--include-ignored", "--test-threads=1", "--nocapture"])
                .env(CHILD, "1")
                .envs(env.iter().copied())
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
        if out.status.success() && text.contains("1 passed") {
            Ok(())
        } else {
            Err(text)
        }
    }

    /// Runs test `name` again in a process of its own and checks that it
    /// passed there; true in that process, which goes on with the test.
    fn in_own_process(name: &str) -> bool {
        if std::env::var_os(CHILD).is_some() {
            return true;
        }
        if let Err(text) = run_alone(name, &[]) {
            panic!("{text}");
        }
        false
    }

    fn close(fds: &[c_int]) {
        for &fd in fds {
            // SAFETY: descriptors of the test.
            unsafe { libc::close(fd) };
        }
    }

    /// The previous handler of this process's SIGBUS and SIGSEGV, in the
    /// resolved-fault tests (installed before [`init`] saves it): records
    /// the address and makes its page readable and writable, so the access
    /// goes through when it returns.
    static CHAINED: AtomicU64 = AtomicU64::new(0);

    extern "C" fn previous_handler(_: c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
        // SAFETY: the kernel passes a valid siginfo.
        let addr = unsafe { (*info).si_addr } as u64;
        CHAINED.store(addr, Ordering::SeqCst);
        let ps = test_page_size();
        // SAFETY: the test's page; raw, not the compatibility mprotect.
        unsafe { libc::mprotect((addr - addr % ps) as *mut _, ps as usize, libc::PROT_READ | libc::PROT_WRITE) };
    }

    fn install_previous_handler() {
        for sig in [libc::SIGBUS, libc::SIGSEGV] {
            // SAFETY: installs the test's handler.
            unsafe {
                let mut act: libc::sigaction = core::mem::zeroed();
                act.sa_sigaction = previous_handler as *const () as usize;
                act.sa_flags = libc::SA_SIGINFO;
                libc::sigemptyset(&mut act.sa_mask);
                assert_eq!(libc::sigaction(sig, &act, ptr::null_mut()), 0);
            }
        }
    }

    /// The userfaultfd the signal hooks below act with.
    static HOOK_CTX: AtomicUsize = AtomicUsize::new(0);
    /// The page the signal hooks below act on.
    static HOOK_PAGE: AtomicU64 = AtomicU64::new(0);

    fn fill_hook() {
        let page = std::vec![0x77u8; test_page_size() as usize];
        let at = HOOK_PAGE.load(Ordering::SeqCst);
        // SAFETY: `page` holds a page.
        let r = unsafe { copy(HOOK_CTX.load(Ordering::SeqCst), page.as_ptr(), at, test_page_size(), true) };
        assert_eq!(r, Ok(test_page_size()));
    }

    fn unregister_hook() {
        let at = HOOK_PAGE.load(Ordering::SeqCst);
        assert_eq!(unregister(HOOK_CTX.load(Ordering::SeqCst), at, test_page_size()), Ok(()));
    }

    /// A change of the page's protection by a call outside this library
    /// (the system's own `mprotect`), to read and write.
    fn raw_writable_hook() {
        let at = HOOK_PAGE.load(Ordering::SeqCst);
        // SAFETY: the test's page.
        unsafe { libc::mprotect(at as *mut _, test_page_size() as usize, libc::PROT_READ | libc::PROT_WRITE) };
    }

    /// A resolved-fault case: what, the hook, the pages registered, the
    /// page accessed, the byte the read then gives.
    type ResolvedCase = (&'static str, fn(), u64, u64, u8);

    /// An access to a missing page whose fill, or whose unregister, completed
    /// between the fault and the handler's reading of the page (a hook at
    /// [`on_signal`]'s start makes the change there), or between the
    /// handler's reading and [`fault`]'s own (a hook at `fault`'s start,
    /// after `on_signal` read the page missing), is retried, as Linux's fault
    /// finds the page present, or no longer registered, and maps it: the
    /// read gives the filled page, or zeros, and the previous handler is
    /// not called. Before, the handler found the page not missing and
    /// handed the fault on (for Firecracker, its SIGSEGV handler, which
    /// ends the VMM). The unregister is of one page of two (the range
    /// lives on) and of a whole range (it is freed). An access the asked
    /// protection refuses (a store to a page registered after a
    /// compatibility `mprotect` to `PROT_READ`, filled) still goes to the
    /// previous handler, also when a call outside this library made the
    /// page writable between the fault and the handler's reading of it
    /// (the asked protection decides for a registered page).
    #[test]
    fn test_a_fault_resolved_before_its_handler_reads_the_page_is_retried() {
        if !in_own_process("wick_uffd::tests::test_a_fault_resolved_before_its_handler_reads_the_page_is_retried") {
            return;
        }
        install_previous_handler();
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        HOOK_CTX.store(ctx, Ordering::SeqCst);
        let cases: [ResolvedCase; 3] = [
            ("filled", fill_hook, 2, 0, 0x77),
            ("one page unregistered", unregister_hook, 2, 1, 0),
            ("the range unregistered", unregister_hook, 1, 0, 0),
        ];
        // Every case is run, and the failures told together.
        let mut failures = Vec::new();
        for in_fault in [false, true] {
            HOOK_IN_FAULT.store(in_fault, Ordering::SeqCst);
            let place = if in_fault { "in fault()" } else { "at the handler's start" };
            for (what, hook, pages, at, want) in cases {
                let mem = map(pages);
                register(ctx, mem, pages * ps).unwrap();
                let page = mem + at * ps;
                HOOK_PAGE.store(page, Ordering::SeqCst);
                SIGNAL_HOOK.store(hook as usize, Ordering::SeqCst);
                SIGNAL_HOOK_AT.store(page, Ordering::SeqCst);
                CHAINED.store(0, Ordering::SeqCst);
                // SAFETY: registered memory; the hook resolves the fault.
                let got = unsafe { ptr::read_volatile(page as *const u8) };
                if SIGNAL_HOOK_AT.load(Ordering::SeqCst) != 0 {
                    failures.push(std::format!("{what} {place}: the hook did not run"));
                }
                if CHAINED.load(Ordering::SeqCst) != 0 {
                    failures.push(std::format!("{what} {place}: the fault went to the previous handler"));
                }
                if got != want {
                    failures.push(std::format!("{what} {place}: read {got:#x}, not {want:#x}"));
                }
                let _ = unregister(ctx, mem, pages * ps);
            }
        }
        HOOK_IN_FAULT.store(false, Ordering::SeqCst);
        assert!(failures.is_empty(), "{failures:#?}");
        // Refused by the asked protection: on to the previous handler.
        let mem = map(1);
        register(ctx, mem, ps).unwrap();
        // SAFETY: the test's registered page.
        assert_eq!(unsafe { crate::linux_items::mprotect(mem as *mut _, ps as usize, libc::PROT_READ) }, 0);
        let page = std::vec![0x55u8; ps as usize];
        // SAFETY: `page` holds a page.
        assert_eq!(unsafe { copy(ctx, page.as_ptr(), mem, ps, true) }, Ok(ps));
        for raw in [false, true] {
            // SAFETY: the test's page, back to the protection asked.
            unsafe { libc::mprotect(mem as *mut _, ps as usize, libc::PROT_READ) };
            if raw {
                HOOK_PAGE.store(mem, Ordering::SeqCst);
                SIGNAL_HOOK.store(raw_writable_hook as fn() as usize, Ordering::SeqCst);
                SIGNAL_HOOK_AT.store(mem, Ordering::SeqCst);
            }
            CHAINED.store(0, Ordering::SeqCst);
            // SAFETY: the store faults; the previous handler makes the page writable.
            unsafe { ptr::write_volatile(mem as *mut u8, 1) };
            let what = if raw { "made writable outside this library meanwhile" } else { "as it is" };
            assert_eq!(CHAINED.load(Ordering::SeqCst), mem, "a store the asked protection refuses, {what}, was not handed on");
        }
        let _ = unregister(ctx, mem, ps);
        close(&[user]);
    }

    /// The retries of one address by one thread with no change of the
    /// ranges in between are bounded ([`RETRY_BOUND`]): then the fault goes
    /// to the previous handler. A change under [`LOCK`], or another address,
    /// starts the count again.
    #[test]
    fn test_retries_of_a_fault_with_nothing_changed_are_bounded() {
        // A private address no other test's fault uses; LOCK not taken in
        // between, unless by another test (which only starts the count
        // again, so the bound is checked with the lock held).
        let addr = 0x10;
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tries: std::vec::Vec<bool> = (0..RETRY_BOUND + 1).map(|_| may_retry(addr)).collect();
        let mut want = std::vec![true; RETRY_BOUND as usize];
        want.push(false);
        assert_eq!(tries, want);
        CHANGES.fetch_add(1, Ordering::SeqCst);
        assert!(may_retry(addr), "the same address after a change");
        assert!(may_retry(addr + 1), "another address");
    }

    /// Live threads land in different entries of [`RETRIES`]
    /// ([`retry_index`]): 16 threads alive at once take at least 8 entries.
    /// With the index of `pthread_self`'s low bits they took one.
    #[test]
    fn test_live_threads_spread_over_the_retry_entries() {
        const N: usize = 16;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let threads: Vec<_> = (0..N)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    // SAFETY: the calling thread's own identifier.
                    let index = retry_index(unsafe { libc::pthread_self() } as u64);
                    // All alive at once: no identifier reused.
                    barrier.wait();
                    index
                })
            })
            .collect();
        let mut entries: Vec<usize> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        entries.sort_unstable();
        entries.dedup();
        assert!(entries.len() >= N / 2, "{N} live threads in {} retry entries: {entries:?}", entries.len());
    }

    /// Two threads in different entries of [`RETRIES`] keep their own
    /// counts: one's retry between the other's does not start the other's
    /// count again.
    #[test]
    fn test_threads_in_different_retry_entries_keep_their_counts() {
        use std::sync::mpsc::channel;
        // CHANGES does not move while the lock is held.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (to_a, a_gets) = channel::<()>();
        let (from_a, a_said) = channel::<(usize, Vec<bool>)>();
        let a = std::thread::spawn(move || {
            // SAFETY: the calling thread's own identifier.
            let index = retry_index(unsafe { libc::pthread_self() } as u64);
            let first = std::vec![may_retry(0x20), may_retry(0x20)];
            from_a.send((index, first)).unwrap();
            a_gets.recv().unwrap();
            from_a.send((index, std::vec![may_retry(0x20)])).unwrap();
        });
        let (index_a, first) = a_said.recv().unwrap();
        assert_eq!(first, [true, true]);
        // Another live thread in another entry retries meanwhile.
        let mut tried = 0;
        loop {
            let b = std::thread::spawn(move || {
                // SAFETY: the calling thread's own identifier.
                let index = retry_index(unsafe { libc::pthread_self() } as u64);
                // Only from another entry: one in the first thread's entry
                // would start its count again by design.
                (index != index_a).then(|| may_retry(0x30))
            });
            // A thread that ended may leave its identifier to the next.
            if let Some(retried) = b.join().unwrap() {
                assert!(retried);
                break;
            }
            tried += 1;
            assert!(tried < 64, "no thread in an entry other than {index_a}");
        }
        to_a.send(()).unwrap();
        let (_, last) = a_said.recv().unwrap();
        assert_eq!(last, [false], "the first thread's count was started again by the other's retry");
        a.join().unwrap();
    }

    #[test]
    fn test_ranges_that_wrap() {
        // A range whose end wraps around is EINVAL, as Linux's validate_range.
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        let wrap = 0u64.wrapping_sub(ps);
        assert_eq!(zeropage(ctx, mem, wrap, true), Err((libc::EINVAL, 0)));
        assert_eq!(wake_range(ctx, mem, wrap), Err(libc::EINVAL));
        assert_eq!(unregister(ctx, mem + ps, wrap), Err(libc::EINVAL));
        // SAFETY: refused before `src` is read.
        let r = unsafe { copy(ctx, ptr::null(), mem + ps, wrap, true) };
        assert_eq!(r, Err((libc::EINVAL, 0)));
        let chan = channel(user);
        let head = [proto::OP_ZEROPAGE, mem, wrap, 0];
        assert_eq!(request(chan, head, &[]), (err(libc::EINVAL), 0));
        // Still registered and missing.
        assert!(is_missing(mem) && is_missing(mem + ps));
        assert_eq!(zeropage(ctx, mem, 2 * ps, true), Ok(2 * ps));
        close(&[chan, user]);
    }

    #[test]
    fn test_register_checks_the_range_as_linux() {
        // Linux's validate_range: past the address space is EINVAL, before
        // anything sized by the length.
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(4);
        for len in [1 << 62, TASK_SIZE - mem + ps, (u64::MAX - mem) & !(ps - 1)] {
            let e = register(ctx, mem, len).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EINVAL), "{len:#x}");
            assert_eq!(unregister(ctx, mem, len), Err(libc::EINVAL), "{len:#x}");
        }
        let e = register(ctx, TASK_SIZE, ps).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        register(ctx, mem, 2 * ps).unwrap();
        assert!(is_missing(mem));
        // Through a handler's channel too.
        let chan = channel(user);
        let other = map(1);
        let (r, _) = request(chan, [proto::OP_REGISTER, other, 1 << 62, 0], &[]);
        assert_eq!(r, err(libc::EINVAL));
        let (r, _) = request(chan, [proto::OP_REGISTER, other, ps, 0], &[]);
        assert_eq!(r, 0);
        assert!(is_missing(other));
        close(&[chan, user]);
    }

    /// As Linux's `userfaultfd_register` and `userfaultfd_unregister`, the
    /// mapped parts of a range are registered and unregistered and its holes
    /// left out; a range of holes only is `EINVAL`. Nothing but this test
    /// may map memory while the holes are open, or a mapping can take them.
    /// Among other tests' threads, one did (their mappings, the views
    /// fills make), so it runs in a process of its own: this binary
    /// again, this test only. There the serving thread did (Rust's start of
    /// a thread maps its signal stack and guard page), so the holes are made
    /// only once that thread has answered a request.
    #[test]
    fn test_register_takes_the_mapped_parts_of_a_range() {
        if !in_own_process("wick_uffd::tests::test_register_takes_the_mapped_parts_of_a_range") {
            return;
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        // Parts of two pages, holes of one.
        let mem = map(8);
        let chan = channel(user);
        for page in [2, 5] {
            // SAFETY: a page of the mapping above.
            let r = unsafe { libc::munmap((mem + page * ps) as *mut _, ps as usize) };
            assert_eq!(r, 0);
        }
        let e = register(ctx, mem + 2 * ps, ps).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(unregister(ctx, mem + 5 * ps, ps), Err(libc::EINVAL));
        let (r, _) = request(chan, [proto::OP_UNREGISTER, mem + 2 * ps, ps, 0], &[]);
        assert_eq!(r, err(libc::EINVAL));
        register(ctx, mem, 8 * ps).unwrap();
        let mapped = [0, 1, 3, 4, 6, 7];
        for page in mapped {
            assert!(is_missing(mem + page * ps), "{page}");
        }
        // Memory mapped in a hole afterwards is not registered, as a new vma.
        assert!(mapped_entries(mem + 2 * ps, mem + 3 * ps).is_empty());
        // SAFETY: maps over the hole made above, still a hole.
        let p = unsafe {
            libc::mmap(
                (mem + 2 * ps) as *mut _,
                ps as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(p as u64, mem + 2 * ps);
        assert!(!is_missing(mem + 2 * ps));
        // SAFETY: the page just mapped.
        unsafe { ptr::write_volatile((mem + 2 * ps) as *mut u8, 7) };
        assert_eq!(zeropage(ctx, mem + 3 * ps, 2 * ps, true), Ok(2 * ps));
        // Over the hole left, the page mapped in the other, and memory
        // never registered.
        assert_eq!(unregister(ctx, mem, 8 * ps), Ok(()));
        for page in mapped {
            assert!(!is_missing(mem + page * ps), "{page}");
        }
        // SAFETY: mapped and no longer registered.
        unsafe {
            assert_eq!(ptr::read_volatile((mem + 2 * ps) as *const u8), 7);
            assert_eq!(ptr::read_volatile((mem + 7 * ps) as *const u8), 0);
        }
        close(&[chan, user]);
    }

    #[test]
    fn test_register_and_unregister_as_linux() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        register(a, mem, 2 * ps).unwrap();
        assert_eq!(zeropage(a, mem, ps, true), Ok(ps));
        // Again, and further: what the userfaultfd has stays as it is, as
        // Linux skips a vma registered with it; the rest is registered.
        register(a, mem, 3 * ps).unwrap();
        assert!(!is_missing(mem) && is_missing(mem + ps) && is_missing(mem + 2 * ps));
        // Another userfaultfd's: EBUSY, and nothing of the range registered.
        let next = map(1);
        for (start, len) in [(mem + 2 * ps, ps), (mem, 3 * ps)] {
            let e = register(b, start, len).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EBUSY));
        }
        // Linux's unregister clears a vma whichever userfaultfd has it.
        assert_eq!(unregister(b, mem + ps, ps), Ok(()));
        assert!(!is_missing(mem + ps));
        // The page unregistered is no userfaultfd's: another registers it,
        // as Linux's register takes a vma with no context, and the pages on
        // either side stay the first's.
        register(b, mem + ps, ps).unwrap();
        assert!(is_missing(mem + ps) && is_missing(mem + 2 * ps));
        assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)));
        assert_eq!(unregister(b, mem + ps, ps), Ok(()));
        // Registered again: not resident, so missing.
        register(a, mem, 3 * ps).unwrap();
        assert!(!is_missing(mem) && is_missing(mem + ps));
        // Unregistered whole, the memory is free for another userfaultfd.
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        register(b, mem, 3 * ps).unwrap();
        assert!(!is_missing(mem) && is_missing(mem + ps) && is_missing(mem + 2 * ps));
        assert_eq!(zeropage(b, mem + ps, 2 * ps, true), Ok(2 * ps));
        assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)));
        register(a, next, ps).unwrap();
        close(&[ua, ub]);
    }

    /// Pages unregistered from the middle of a range are in no registration,
    /// and another userfaultfd registers them, as Linux's unregister splits
    /// the vma and clears the middle one's context (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_unregister` :1413, `userfaultfd_clear_vma` at :1522;
    /// `userfaultfd_register` :1239 refuses only a vma another context has,
    /// :1364 to :1366): each part then faults to
    /// its own userfaultfd and is filled only through it (a fill through the
    /// other is `ENOENT`, mm/userfaultfd.c `validate_dst_vma` :23 to :37).
    #[test]
    fn test_a_partial_unregister_frees_that_part_for_another_userfaultfd() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        register(a, mem, 3 * ps).unwrap();
        assert_eq!(unregister(a, mem + ps, ps), Ok(()));
        let taken = register(b, mem + ps, ps);
        assert!(taken.is_ok(), "the unregistered middle is refused to another userfaultfd: {taken:?}");
        assert!(is_missing(mem) && is_missing(mem + ps) && is_missing(mem + 2 * ps));
        // A fault in the middle goes to b, not to a.
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for b's fill.
            unsafe { ptr::read_volatile((mem + ps) as *const u8) }
        });
        assert!(readable(ub), "no fault event on the middle's userfaultfd");
        let mut rec = [0u8; proto::RECORD];
        assert!(read_full(ub, &mut rec));
        assert_eq!(words(&rec)[..2], [proto::EVENT_PAGEFAULT, mem + ps]);
        let mut p = libc::pollfd { fd: ua, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd.
        assert_eq!(unsafe { libc::poll(&mut p, 1, 0) }, 0, "the other userfaultfd got the middle's fault");
        let page = |v: u8| std::vec![v; ps as usize];
        let (one, two, three) = (page(1), page(2), page(3));
        // SAFETY: each source holds a page.
        unsafe {
            assert_eq!(copy(a, two.as_ptr(), mem + ps, ps, true), Err((libc::ENOENT, 0)), "a filled b's page");
            assert_eq!(copy(b, two.as_ptr(), mem + ps, ps, true), Ok(ps));
            assert_eq!(copy(b, one.as_ptr(), mem, ps, true), Err((libc::ENOENT, 0)), "b filled a's page");
            assert_eq!(copy(a, one.as_ptr(), mem, ps, true), Ok(ps));
            assert_eq!(copy(a, three.as_ptr(), mem + 2 * ps, ps, true), Ok(ps));
        }
        assert_eq!(reader.join().unwrap(), 2);
        // SAFETY: filled above.
        unsafe {
            assert_eq!(ptr::read_volatile(mem as *const u8), 1);
            assert_eq!(ptr::read_volatile((mem + 2 * ps) as *const u8), 3);
        }
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        close(&[ua, ub]);
    }

    /// The same userfaultfd registers its own range again: what it has stays
    /// as it is (a filled page keeps its contents), as Linux's register
    /// refuses only another context's vma (fs/userfaultfd.c, v6.12, :1364 to
    /// :1366) and skips one this context already has (mm/userfaultfd.c
    /// `userfaultfd_register_range` :1851 to :1853). A control for the split,
    /// which must keep it.
    #[test]
    fn test_the_same_userfaultfd_registers_its_range_again() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        register(a, mem, 2 * ps).unwrap();
        let data = std::vec![0x5au8; ps as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        let again = register(a, mem, 2 * ps);
        assert!(again.is_ok(), "{again:?}");
        assert!(!is_missing(mem) && is_missing(mem + ps));
        // SAFETY: filled above.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a);
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        close(&[ua]);
    }

    /// The per-page arrays allocated ([`alloc_array`]): three for each slot
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

    /// One-shot hooks: a `fn()` and, for [`lookup_hook`] and
    /// [`validate_hook`], the address it waits for.
    static LOOKUP_HOOK: AtomicUsize = AtomicUsize::new(0);
    static LOOKUP_AT: AtomicU64 = AtomicU64::new(0);
    static VALIDATE_HOOK: AtomicUsize = AtomicUsize::new(0);
    static VALIDATE_AT: AtomicU64 = AtomicU64::new(0);
    static WINDOW_HOOK: AtomicUsize = AtomicUsize::new(0);

    fn run_once(hook: &AtomicUsize) {
        let f = hook.swap(0, Ordering::SeqCst);
        if f != 0 {
            // SAFETY: set by a test from a `fn()`.
            let f: fn() = unsafe { core::mem::transmute(f) };
            f();
        }
    }

    /// [`lookup`], between its read of a slot's `start` and the rest: once,
    /// for the address armed, at the slot that starts there.
    pub(super) fn lookup_hook(addr: u64, start: u64) {
        let at = LOOKUP_AT.load(Ordering::SeqCst);
        if at != 0 && addr == at && start == at && LOOKUP_AT.compare_exchange(at, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            run_once(&LOOKUP_HOOK);
        }
    }

    /// [`fault`], once its waiter is in [`WAITERS`] and its tag in the
    /// mirror, before it reads the page and validates the slot.
    pub(super) fn validate_hook(addr: u64) {
        let at = VALIDATE_AT.load(Ordering::SeqCst);
        if at != 0 && addr == at && VALIDATE_AT.compare_exchange(at, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            run_once(&VALIDATE_HOOK);
        }
    }

    static BETWEEN_HOOK: AtomicUsize = AtomicUsize::new(0);
    static BETWEEN_AT: AtomicU64 = AtomicU64::new(0);
    static POST_HOOK: AtomicUsize = AtomicUsize::new(0);
    static POST_AT: AtomicU64 = AtomicU64::new(0);

    /// [`fault`], once it has validated and seen its tag still waiting, just
    /// before it writes its record.
    pub(super) fn post_hook(addr: u64) {
        let at = POST_AT.load(Ordering::SeqCst);
        if at != 0 && addr == at && POST_AT.compare_exchange(at, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            run_once(&POST_HOOK);
        }
    }

    /// [`fault`], between its validation's reads of the page (missing,
    /// owner) and of the slot's `gen`.
    pub(super) fn between_hook(addr: u64) {
        let at = BETWEEN_AT.load(Ordering::SeqCst);
        if at != 0 && addr == at && BETWEEN_AT.compare_exchange(at, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            run_once(&BETWEEN_HOOK);
        }
    }

    /// [`Range::changing`], with `gen` odd.
    pub(super) fn window_hook() {
        run_once(&WINDOW_HOOK);
    }

    /// Registers `pages` fresh pages with `ctx`, fills one, unregisters
    /// them (the slot released) and unmaps them; the arrays made after.
    fn round(ctx: usize, pages: u64) -> usize {
        let ps = test_page_size();
        let mem = map(pages);
        register(ctx, mem, pages * ps).unwrap();
        assert_eq!(zeropage(ctx, mem, ps, true), Ok(ps));
        assert_eq!(unregister(ctx, mem, pages * ps), Ok(()));
        assert_eq!(slots(mem, mem + pages * ps).count(), 0);
        // SAFETY: the round's mapping.
        unsafe { libc::munmap(mem as *mut _, (pages * ps) as usize) };
        ARRAYS_MADE.load(Ordering::SeqCst)
    }

    /// A range registered and released again and again keeps the count of
    /// arrays flat: a slot keeps its arrays, and the next range that fits
    /// takes them again. A larger range makes the count rise once (three
    /// arrays of the next capacity), and flat again after, for it and for
    /// the smaller one. Rounds are counted, not timed. In a process of its
    /// own, as it counts the process's allocations.
    #[test]
    fn test_register_and_release_in_a_loop_keeps_the_array_count_flat() {
        if !in_own_process("wick_uffd::tests::test_register_and_release_in_a_loop_keeps_the_array_count_flat") {
            return;
        }
        const ROUNDS: usize = 16;
        let (a, ua) = create(0, false, true).unwrap();
        let small: Vec<usize> = (0..ROUNDS).map(|_| round(a, 4)).collect();
        assert_eq!(small[0], 3, "the first range made other than its three arrays: {small:?}");
        assert!(small.iter().all(|&n| n == 3), "arrays made after each round of 4 pages: {small:?}");
        let large: Vec<usize> = (0..ROUNDS).map(|_| round(a, 100)).collect();
        assert!(large.iter().all(|&n| n == 6), "arrays made after each round of 100 pages: {large:?}");
        let again: Vec<usize> = (0..ROUNDS).map(|_| round(a, 4)).collect();
        assert!(again.iter().all(|&n| n == 6), "arrays made after each round of 4 pages again: {again:?}");
        close(&[ua]);
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

    /// The hooks' pages: the first registration's, and the second's.
    static FIRST: AtomicU64 = AtomicU64::new(0);
    static SECOND: AtomicU64 = AtomicU64::new(0);
    static SECOND_CTX: AtomicUsize = AtomicUsize::new(0);

    /// Releases the first registration's slot (its one page unregistered)
    /// and registers the second's page, which takes the slot (the free slot
    /// with room).
    fn release_and_reuse() {
        let ps = test_page_size();
        let (first, second) = (FIRST.load(Ordering::SeqCst), SECOND.load(Ordering::SeqCst));
        assert_eq!(unregister(HOOK_CTX.load(Ordering::SeqCst), first, ps), Ok(()));
        register(SECOND_CTX.load(Ordering::SeqCst), second, ps).unwrap();
    }

    /// A reader between its reads of a slot's fields, whose slot is released
    /// and taken by another userfaultfd's range at a higher address, starts
    /// over and answers for the new state: its address is in no
    /// registration. Without the slot's `gen` it would read the old start
    /// with the new end and arrays, and find the address missing. In a
    /// process of its own, so that the slot the second range takes is the
    /// first's.
    #[test]
    fn test_a_reader_between_its_generation_reads_starts_over() {
        if !in_own_process("wick_uffd::tests::test_a_reader_between_its_generation_reads_starts_over") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let (first, second) = (map(1), map(1));
        let (first, second) = (first.min(second), first.max(second));
        HOOK_CTX.store(a, Ordering::SeqCst);
        SECOND_CTX.store(b, Ordering::SeqCst);
        FIRST.store(first, Ordering::SeqCst);
        SECOND.store(second, Ordering::SeqCst);
        register(a, first, ps).unwrap();
        assert!(is_missing(first));
        LOOKUP_HOOK.store(release_and_reuse as fn() as usize, Ordering::SeqCst);
        LOOKUP_AT.store(first, Ordering::SeqCst);
        let missing = is_missing(first);
        assert_eq!(LOOKUP_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert!(!missing, "a reader of the released slot found its address missing in the new range's arrays");
        assert!(is_missing(second) && !is_missing(first));
        assert_eq!(unregister(b, second, ps), Ok(()));
        close(&[ua, ub]);
    }

    /// The next record on `fd` (a non-blocking user end), waited for 10 s.
    fn next_record(fd: c_int) -> [u64; 4] {
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd.
        assert_eq!(unsafe { libc::poll(&mut p, 1, 10_000) }, 1, "no record in 10 s");
        let mut rec = [0u8; proto::RECORD];
        // SAFETY: reads one record into a local buffer.
        let n = unsafe { libc::read(fd, rec.as_mut_ptr().cast(), proto::RECORD) };
        assert_eq!(n, proto::RECORD as isize);
        words(&rec)
    }

    /// Whether a reader of userfaultfd `ctx` would return a page fault
    /// record of tag `tag`: its slot's word in the mirror is the tag, waiting
    /// (the `userfaultfd` crate's check).
    fn mirror_waits(ctx: usize, tag: u64) -> bool {
        let slot = proto::tag_slot(tag);
        assert!(slot < MAX_WAITERS, "tag {tag:#x}");
        // SAFETY: the mirror's MAX_WAITERS words, while `ctx` is open.
        let word = unsafe { &*mirror(ctx).unwrap().add(slot) }.load(Ordering::SeqCst);
        tag & proto::TAG_WAITING != 0 && word == tag
    }

    fn wake_the_first() {
        let ps = test_page_size();
        assert_eq!(wake_range(HOOK_CTX.load(Ordering::SeqCst), FIRST.load(Ordering::SeqCst), ps), Ok(()));
    }

    /// A wake that lands after a waiter validated and saw its tag waiting,
    /// and before its record is written: the record is written all the
    /// same, after the wake, and the mirror says its waiter was woken, so a
    /// reader drops it, as Linux's read never returns a fault its wake took
    /// off the queue (v6.12 fs/userfaultfd.c `userfaultfd_wake_function`
    /// :141). The waiter runs its access again on the page, still missing,
    /// and faults again: that record is read.
    #[test]
    fn test_a_record_written_after_its_wake_is_not_read() {
        if !in_own_process("wick_uffd::tests::test_a_record_written_after_its_wake_is_not_read") {
            return;
        }
        // SAFETY: plain alarm; its default action ends the child.
        unsafe { libc::alarm(20) };
        let (ctx, user) = create(0, true, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        register(ctx, mem, ps).unwrap();
        HOOK_CTX.store(ctx, Ordering::SeqCst);
        FIRST.store(mem, Ordering::SeqCst);
        POST_HOOK.store(wake_the_first as fn() as usize, Ordering::SeqCst);
        POST_AT.store(mem, Ordering::SeqCst);
        // SAFETY: registered memory; the read waits for its page.
        let reader = std::thread::spawn(move || unsafe { ptr::read_volatile(mem as *const u8) });
        let late = next_record(user);
        assert_eq!(POST_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert_eq!(late[..2], [proto::EVENT_PAGEFAULT, mem]);
        assert!(!mirror_waits(ctx, late[3]), "a record written after its wake reads as its waiter's");
        let again = next_record(user);
        assert_eq!(again[..2], [proto::EVENT_PAGEFAULT, mem]);
        assert!(mirror_waits(ctx, again[3]), "the new fault's record reads as woken");
        assert_ne!(late[3], again[3], "two waiters with one tag");
        assert_eq!(zeropage(ctx, mem, ps, true), Ok(ps));
        assert_eq!(reader.join().unwrap(), 0);
        assert!(!mirror_waits(ctx, again[3]), "filled and woken, its record still reads as waiting");
        assert_eq!(unregister(ctx, mem, ps), Ok(()));
        close(&[user]);
    }

    fn fill_the_first() {
        let ps = test_page_size();
        assert_eq!(zeropage(HOOK_CTX.load(Ordering::SeqCst), FIRST.load(Ordering::SeqCst), ps, true), Ok(ps));
    }

    /// A fill with its wake between a waiter's read of its page (missing)
    /// and the rest of its validation: the wake clears the tag the waiter
    /// stored before that read, so the waiter writes no record and runs its
    /// access again, which reads the filled page. Were the tag stored after
    /// the read, the wake would find none to clear, and the waiter would
    /// post and wait for a wake already gone, without end (the child ends
    /// by its alarm then).
    #[test]
    fn test_a_wake_between_a_waiters_read_and_its_post_is_not_missed() {
        if !in_own_process("wick_uffd::tests::test_a_wake_between_a_waiters_read_and_its_post_is_not_missed") {
            return;
        }
        // SAFETY: plain alarm; its default action ends the child.
        unsafe { libc::alarm(20) };
        let (ctx, user) = create(0, true, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        register(ctx, mem, ps).unwrap();
        HOOK_CTX.store(ctx, Ordering::SeqCst);
        FIRST.store(mem, Ordering::SeqCst);
        BETWEEN_HOOK.store(fill_the_first as fn() as usize, Ordering::SeqCst);
        BETWEEN_AT.store(mem, Ordering::SeqCst);
        // SAFETY: registered memory; the hook fills it in the fault.
        let v = unsafe { ptr::read_volatile(mem as *const u8) };
        assert_eq!(BETWEEN_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert_eq!(v, 0);
        assert!(nothing_to_read(user), "a record was written");
        assert_eq!(unregister(ctx, mem, ps), Ok(()));
        close(&[user]);
    }

    /// A userfaultfd's mirror is made with it and given back at its release:
    /// three times `MAX_CTX` userfaultfds made and released one after another
    /// leave the process's descriptors and its count of mirrors as they were,
    /// and each mirror's mapping is gone (`msync`: `ENOMEM`) once its
    /// release is done. In a process of its own, so that no other test's
    /// descriptors or mappings come and go meanwhile.
    #[test]
    fn test_a_userfaultfds_mirror_is_given_back_at_its_release() {
        if !in_own_process("wick_uffd::tests::test_a_userfaultfds_mirror_is_given_back_at_its_release") {
            return;
        }
        init().unwrap();
        // SAFETY: F_GETFD of each number, open or not.
        let open = || (0..4096).filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0).count();
        let (fds, mirrors) = (open(), MIRRORS.load(Ordering::SeqCst));
        for round in 0..3 * MAX_CTX {
            let (ctx, user) = create(0, false, true).unwrap();
            let m = mirror(ctx).unwrap();
            assert_eq!(MIRRORS.load(Ordering::SeqCst), mirrors + 1, "round {round}");
            assert_eq!(open(), fds + 3, "round {round}: the kernel end, the user end and the mirror's descriptor");
            close(&[user]);
            until("the release", || CTXS[ctx].fd.load(Ordering::SeqCst) < 0);
            // SAFETY: an asynchronous sync of one page, mapped or not:
            // ENOMEM where nothing is mapped (mincore answers 0 there).
            let r = unsafe { libc::msync(m as *mut _, test_page_size() as usize, libc::MS_ASYNC) };
            let e = io::Error::last_os_error().raw_os_error();
            assert_eq!((r, e), (-1, Some(libc::ENOMEM)), "round {round}: the mirror is still mapped");
        }
        assert_eq!(open(), fds, "descriptors left");
        assert_eq!(MIRRORS.load(Ordering::SeqCst), mirrors, "mirrors left");
    }

    /// Makes a userfaultfd, with [`MIRROR_NAMED`] reading its mirror's name
    /// and trying, while the name is there, a second `shm_open` of it for
    /// reading and writing and for reading, as another process of this uid
    /// could; gives the userfaultfd back. Returns the name and the two opens.
    fn mirror_name_and_opens() -> (std::ffi::CString, [Result<(), Option<c_int>>; 2]) {
        let seen = std::rc::Rc::new(core::cell::RefCell::new(std::vec::Vec::new()));
        let into = seen.clone();
        MIRROR_NAMED.set(Some(std::boxed::Box::new(move |name: &core::ffi::CStr| {
            let opens = [libc::O_RDWR, libc::O_RDONLY].map(|flags| {
                // SAFETY: a NUL-terminated name; a descriptor opened is closed.
                let fd = unsafe { libc::shm_open(name.as_ptr(), flags, 0 as libc::c_uint) };
                if fd >= 0 {
                    // SAFETY: as above.
                    unsafe { libc::close(fd) };
                    Ok(())
                } else {
                    Err(io::Error::last_os_error().raw_os_error())
                }
            });
            into.borrow_mut().push((std::ffi::CString::from(name), opens));
        })));
        let made = create(0, false, true);
        MIRROR_NAMED.set(None);
        let (_, user) = made.unwrap();
        close(&[user]);
        let mut seen = seen.take();
        assert_eq!(seen.len(), 1, "one mirror made");
        seen.remove(0)
    }

    /// Whether `name` is this process's mirror name with 16 hex digits.
    fn random_mirror_name(name: &core::ffi::CStr) -> bool {
        let name = name.to_str().unwrap();
        name.strip_prefix(&std::format!("/fcm.{}.u", std::process::id()))
            .is_some_and(|rest| rest.len() == 16 && rest.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    /// While a userfaultfd's mirror has its name, between its making and its
    /// unlink, a second `shm_open` of that name by the same uid opens it for
    /// reading only (mode 0400): reading and writing is `EACCES`, so another
    /// process cannot change the waiter tags the VMM's wakes compare, and
    /// what reading gives is those tags, slot numbers and counts, no guest
    /// data. With mode 0600 the second open read and wrote it.
    #[test]
    fn test_a_mirror_opens_for_reading_only_while_it_has_its_name() {
        init().unwrap();
        // SAFETY: no arguments.
        assert_ne!(unsafe { libc::geteuid() }, 0, "root opens any object; run as a user");
        let (name, opens) = mirror_name_and_opens();
        assert_eq!(opens, [Err(Some(libc::EACCES)), Ok(())], "{name:?} opened again");
        // SAFETY: as above; nothing is made (no O_CREAT).
        assert_eq!(unsafe { libc::shm_open(name.as_ptr(), libc::O_RDONLY, 0 as libc::c_uint) }, -1, "{name:?} after the unlink");
    }

    /// A mirror's name cannot be guessed: with the names a counter gave
    /// (`/fcm.<pid>.u0` on) taken first, as a process of any uid could take
    /// them (the names are one namespace, xnu-12377.121.6
    /// bsd/kern/posix_shm.c `pshm_cache_search` :223; here the same uid),
    /// two userfaultfds are made, each mirror's name is 16 random hex
    /// digits after `u`, and the two differ. With the counter a taken name
    /// was skipped, and the userfaultfd made anyway, so what this test shows
    /// is not a creation the taking stopped but that no name is guessable
    /// (a mirror's name a counter gave fails it). The names taken are given
    /// back before any check.
    #[test]
    fn test_a_mirrors_name_cannot_be_guessed() {
        init().unwrap();
        let pid = std::process::id();
        std::println!("SWEEP-PID {pid}");
        let mut taken = std::vec::Vec::new();
        for n in 0..256 {
            let name = std::ffi::CString::new(std::format!("/fcm.{pid}.u{n}")).unwrap();
            // SAFETY: a NUL-terminated name; a descriptor opened is closed,
            // the name keeping the object.
            let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600 as libc::c_uint) };
            if fd >= 0 {
                // SAFETY: as above.
                unsafe { libc::close(fd) };
                taken.push(name);
            }
        }
        let names = std::panic::catch_unwind(|| [mirror_name_and_opens().0, mirror_name_and_opens().0]);
        for name in &taken {
            // SAFETY: a name made above.
            unsafe { libc::shm_unlink(name.as_ptr()) };
        }
        let names = names.unwrap_or_else(|e| std::panic::resume_unwind(e));
        for name in &names {
            assert!(random_mirror_name(name), "{name:?}");
        }
        assert_ne!(names[0], names[1]);
    }

    /// The process's phys_footprint, the ledger the jailer's memory limit
    /// (a jetsam limit) is checked against.
    fn phys_footprint() -> u64 {
        // SAFETY: plain data filled by the call.
        let mut info: libc::rusage_info_v4 = unsafe { core::mem::zeroed() };
        // SAFETY: a V4 buffer for the V4 flavour.
        let r = unsafe {
            libc::proc_pid_rusage(libc::getpid(), libc::RUSAGE_INFO_V4, ptr::from_mut(&mut info).cast())
        };
        assert_eq!(r, 0);
        info.ri_phys_footprint
    }

    /// 64 MiB of registered memory filled, half with `UFFDIO_COPY` and half
    /// with `UFFDIO_ZEROPAGE`, and then read through the memory, as the VMM
    /// reads guest memory a handler filled, is charged 64 MiB, as on Linux,
    /// whose memory cgroup charges a page once, when it is allocated (v6.12
    /// mm/userfaultfd.c `mfill_atomic_pte_copy` :302; mm/memcontrol.c
    /// `commit_charge` :2370 refuses a second charge), whatever then maps
    /// it. Here the charge comes at the read, not at the fill ([`fill`]). Prints the
    /// footprint after each step (FOOTPRINT lines). The fill writes through
    /// a view that is gone once it is done ([`fill_view`]), and charges the
    /// page in the memory itself; before, the page stayed mapped by the
    /// range's alias and was charged for it and again for the memory, 128
    /// MiB (SECURITY.md, Not at parity yet, "macOS: a page is charged to
    /// the memory limit once for each mapping that touched it"). In a
    /// process of its own, so that no other test's memory moves the
    /// footprint meanwhile.
    #[test]
    fn test_a_filled_page_is_charged_once() {
        if !in_own_process("wick_uffd::tests::test_a_filled_page_is_charged_once") {
            return;
        }
        const MIB: u64 = 64;
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let pages = (MIB << 20) / ps;
        let mem = map(pages);
        register(ctx, mem, pages * ps).unwrap();
        let src = std::vec![0x5au8; ps as usize];
        let before = phys_footprint();
        let step = |name: &str, last: u64| {
            let now = phys_footprint();
            std::println!(
                "FOOTPRINT MiB: {name}: {:+} (total {:+})",
                (now as i64 - last as i64) >> 20,
                (now as i64 - before as i64) >> 20
            );
            now
        };
        let half = pages / 2;
        for i in 0..half {
            // SAFETY: a readable page of source.
            assert_eq!(unsafe { copy(ctx, src.as_ptr(), mem + i * ps, ps, false) }, Ok(ps));
        }
        assert_eq!(zeropage(ctx, mem + half * ps, (pages - half) * ps, false), Ok((pages - half) * ps));
        let filled = step("filled through views", before);
        let mut sum = 0u64;
        for i in 0..pages {
            // SAFETY: filled pages of the mapping.
            sum += u64::from(unsafe { ptr::read_volatile((mem + i * ps) as *const u8) });
        }
        assert_eq!(sum, 0x5a * half);
        let read = step("read through the memory", filled);
        close(&[user]);
        until("the release", || CTXS[ctx].fd.load(Ordering::SeqCst) < 0);
        step("released", read);
        // SAFETY: the test's own mapping.
        unsafe { libc::munmap(mem as *mut _, (pages * ps) as usize) };
        let charged = read.saturating_sub(before) >> 20;
        assert!(charged <= MIB + 4, "{MIB} MiB filled and read is charged {charged} MiB");
    }

    /// A fault whose slot is released and taken by another userfaultfd's
    /// range once its waiter is registered posts nothing and runs its access
    /// again, which goes through to the memory, now in no registration.
    /// Without the validation it would post the old address to the new
    /// range's userfaultfd and wait for a fill that never comes. In a
    /// process of its own, as the test above.
    #[test]
    fn test_fault_validates_after_its_waiter_is_registered() {
        if !in_own_process("wick_uffd::tests::test_fault_validates_after_its_waiter_is_registered") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let (first, second) = (map(1), map(1));
        HOOK_CTX.store(a, Ordering::SeqCst);
        SECOND_CTX.store(b, Ordering::SeqCst);
        FIRST.store(first, Ordering::SeqCst);
        SECOND.store(second, Ordering::SeqCst);
        register(a, first, ps).unwrap();
        VALIDATE_HOOK.store(release_and_reuse as fn() as usize, Ordering::SeqCst);
        VALIDATE_AT.store(first, Ordering::SeqCst);
        let done = std::sync::Arc::new(AtomicU64::new(u64::MAX));
        let d = done.clone();
        std::thread::spawn(move || {
            // SAFETY: registered memory; the hook releases it in the fault.
            let v = unsafe { ptr::read_volatile(first as *const u8) };
            d.store(u64::from(v), Ordering::SeqCst);
        });
        until("the faulting read", || done.load(Ordering::SeqCst) != u64::MAX);
        assert_eq!(VALIDATE_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert_eq!(done.load(Ordering::SeqCst), 0);
        assert!(nothing_to_read(ua) && nothing_to_read(ub), "an event was posted");
        assert!(is_missing(second) && !is_missing(first));
        assert_eq!(unregister(b, second, ps), Ok(()));
        close(&[ua, ub]);
    }

    /// A fault whose range is released, and whose slot the same userfaultfd's
    /// next range takes (its arrays reset before that range's window, while
    /// the slot is free), between the validation's reads of the page and of
    /// the slot's `gen`, posts nothing: the page read missing and the
    /// userfaultfd's own are the new range's, and only `gen` read after them
    /// tells. The access runs again and reads the memory, now in no
    /// registration. In a process of its own, as the tests above.
    #[test]
    fn test_fault_reads_the_generation_after_the_page() {
        if !in_own_process("wick_uffd::tests::test_fault_reads_the_generation_after_the_page") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let (first, second) = (map(1), map(1));
        HOOK_CTX.store(a, Ordering::SeqCst);
        SECOND_CTX.store(a, Ordering::SeqCst);
        FIRST.store(first, Ordering::SeqCst);
        SECOND.store(second, Ordering::SeqCst);
        register(a, first, ps).unwrap();
        BETWEEN_HOOK.store(release_and_reuse as fn() as usize, Ordering::SeqCst);
        BETWEEN_AT.store(first, Ordering::SeqCst);
        let done = std::sync::Arc::new(AtomicU64::new(u64::MAX));
        let d = done.clone();
        std::thread::spawn(move || {
            // SAFETY: registered memory; the hook releases it in the fault.
            let v = unsafe { ptr::read_volatile(first as *const u8) };
            d.store(u64::from(v), Ordering::SeqCst);
        });
        until("the faulting read", || done.load(Ordering::SeqCst) != u64::MAX);
        assert_eq!(BETWEEN_AT.load(Ordering::SeqCst), 0, "the hook did not run");
        assert_eq!(done.load(Ordering::SeqCst), 0);
        let mut rec = [0u8; proto::RECORD];
        let posted = (!nothing_to_read(ua) && read_full(ua, &mut rec)).then(|| words(&rec));
        assert_eq!(posted, None, "an event for an address the userfaultfd no longer has");
        assert!(is_missing(second) && !is_missing(first));
        assert_eq!(unregister(a, second, ps), Ok(()));
        close(&[ua]);
    }

    /// A fault on the thread that is changing a slot, inside the window
    /// (`gen` odd, [`LOCK`] held), goes to the previous handler: the lookup
    /// answers that the slot is the thread's own, and nothing waits on
    /// itself. Here it is a read of another range's missing page, which
    /// would otherwise wait for a fill that needs [`LOCK`]. In a process of
    /// its own, with the recording previous handler.
    #[test]
    fn test_a_fault_inside_a_writers_window_goes_to_the_previous_handler() {
        if !in_own_process("wick_uffd::tests::test_a_fault_inside_a_writers_window_goes_to_the_previous_handler") {
            return;
        }
        install_previous_handler();
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let (first, second) = (map(1), map(1));
        FIRST.store(first, Ordering::SeqCst);
        register(a, first, ps).unwrap();
        CHAINED.store(0, Ordering::SeqCst);
        fn touch() {
            // SAFETY: the test's registered page; the previous handler makes
            // it readable.
            let _ = unsafe { ptr::read_volatile(FIRST.load(Ordering::SeqCst) as *const u8) };
        }
        WINDOW_HOOK.store(touch as fn() as usize, Ordering::SeqCst);
        register(a, second, ps).unwrap();
        assert_eq!(WINDOW_HOOK.load(Ordering::SeqCst), 0, "the hook did not run");
        assert_eq!(CHAINED.load(Ordering::SeqCst), first, "the fault did not go to the previous handler");
        assert!(nothing_to_read(ua), "an event was posted");
        assert_eq!(unregister(a, first, ps), Ok(()));
        assert_eq!(unregister(a, second, ps), Ok(()));
        close(&[ua]);
    }

    /// The slots in use: each a registered range.
    fn slots_in_use() -> usize {
        RANGES.iter().filter(|r| r.start.load(Ordering::Acquire) != 0).count()
    }

    /// More scattered partial unregisters of one registration than there are
    /// slots ([`MAX_RANGES`]) all succeed and take no slot, and the pages
    /// left registered fault and fill as before. Firecracker's on-demand
    /// handler unregisters the range of every remove event and asserts that
    /// it succeeds (lib/firecracker/src/firecracker/examples/uffd/
    /// on_demand_handler.rs :93 to :94, uffd_utils.rs :133 to :144), runs
    /// scattered as a balloon's inflation leaves them
    /// (tests/integration_tests/functional/test_uffd.py :100 to :109); on
    /// Linux each is a vma split, up to `vm.max_map_count`. In a process of
    /// its own, as it counts the process's slots.
    #[test]
    fn test_more_scattered_unregisters_than_slots_all_succeed() {
        if !in_own_process("wick_uffd::tests::test_more_scattered_unregisters_than_slots_all_succeed") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let pages = 2 * MAX_RANGES as u64 + 3;
        let mem = map(pages);
        register(a, mem, pages * ps).unwrap();
        let used = slots_in_use();
        // Every odd page: MAX_RANGES + 1 unregisters, each its own run.
        for page in (1..pages).step_by(2) {
            assert_eq!(unregister(a, mem + page * ps, ps), Ok(()), "unregister of page {page}");
        }
        assert_eq!(slots_in_use(), used, "the unregisters took slots");
        for page in 0..pages {
            assert_eq!(is_missing(mem + page * ps), page % 2 == 0, "page {page}");
        }
        // An unregistered page is no one's to fill; another userfaultfd
        // registers one, in the same slot.
        assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)));
        register(b, mem + 3 * ps, ps).unwrap();
        assert_eq!(slots_in_use(), used, "a register of an unregistered page took a slot");
        assert_eq!(zeropage(b, mem + 3 * ps, ps, true), Ok(ps));
        // A page left registered faults to its userfaultfd and is filled.
        let last = mem + (pages - 1) * ps;
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for the fill.
            unsafe { ptr::read_volatile(last as *const u8) }
        });
        let mut rec = [0u8; proto::RECORD];
        assert!(readable(ua) && read_full(ua, &mut rec), "no fault event");
        assert_eq!(words(&rec)[..2], [proto::EVENT_PAGEFAULT, last]);
        let data = std::vec![9u8; ps as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), last, ps, true) }, Ok(ps));
        assert_eq!(reader.join().unwrap(), 9);
        assert_eq!(zeropage(a, mem, ps, true), Ok(ps));
        assert_eq!(unregister(a, mem, pages * ps), Ok(()));
        assert_eq!(slots_in_use(), used - 1, "the range outlived its last page");
        close(&[ua, ub]);
    }

    /// A register whose range ends in a page another userfaultfd has is
    /// `EBUSY`, and changes nothing before it: Linux checks every vma of the
    /// range before it registers one (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_register`: `EBUSY` at :1363 to :1366, in the loop that
    /// ends at :1375, before `userfaultfd_register_range` at :1378).
    #[test]
    fn test_a_register_ending_in_another_userfaultfds_page_changes_nothing() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        register(a, mem, 3 * ps).unwrap();
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        let e = register(b, mem, 3 * ps).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EBUSY));
        // The first two pages are still no one's: ordinary memory, not
        // missing, not b's to fill; the last is still a's.
        assert!(!is_missing(mem) && !is_missing(mem + ps) && is_missing(mem + 2 * ps));
        assert_eq!(zeropage(b, mem, ps, true), Err((libc::ENOENT, 0)));
        assert_eq!(zeropage(b, mem + 2 * ps, ps, true), Err((libc::ENOENT, 0)));
        // SAFETY: unregistered memory, accessible as before the register.
        unsafe {
            ptr::write_volatile(mem as *mut u8, 4);
            assert_eq!(ptr::read_volatile(mem as *const u8), 4);
        }
        assert_eq!(zeropage(a, mem + 2 * ps, ps, true), Ok(ps));
        assert_eq!(unregister(a, mem + 2 * ps, ps), Ok(()));
        close(&[ua, ub]);
    }

    /// Two userfaultfds' pages in one slot, each part as Linux's own vma:
    /// each fills only its pages, a discard posts each part's remove event
    /// to its userfaultfd (Linux's walk calls `userfaultfd_remove` per vma,
    /// mm/madvise.c, v6.12, :894), and the release of one takes only its
    /// pages (`userfaultfd_release` :856 clears its own vmas), the slot living
    /// on for the other's, which still fills them.
    #[test]
    fn test_two_userfaultfds_in_one_slot_fill_discard_and_release_their_own() {
        let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let (b, ub) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(4);
        register(a, mem, 4 * ps).unwrap();
        assert_eq!(unregister(a, mem + 2 * ps, 2 * ps), Ok(()));
        register(b, mem + 2 * ps, 2 * ps).unwrap();
        assert_eq!(slots(mem, mem + 4 * ps).count(), 1, "the second userfaultfd's pages took a slot");
        assert_eq!(zeropage(a, mem + 2 * ps, ps, true), Err((libc::ENOENT, 0)));
        assert_eq!(zeropage(b, mem, ps, true), Err((libc::ENOENT, 0)));
        assert_eq!(zeropage(a, mem, ps, true), Ok(ps));
        assert_eq!(zeropage(b, mem + 2 * ps, ps, true), Ok(ps));
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, (4 * ps) as usize, libc::MADV_DONTNEED) };
        assert_eq!(r, 0);
        let mut rec = [0u8; proto::RECORD];
        assert!(readable(ua) && read_full(ua, &mut rec), "no remove event for the first part");
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem, mem + 2 * ps]);
        assert!(readable(ub) && read_full(ub, &mut rec), "no remove event for the second part");
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem + 2 * ps, mem + 4 * ps]);
        assert!(nothing_to_read(ua) && nothing_to_read(ub), "a second event");
        assert!((0..4).all(|page| is_missing(mem + page * ps)));
        close(&[ua]);
        // The release is the serving thread's, once it sees the close.
        let until = Instant::now() + Duration::from_secs(10);
        while is_missing(mem) {
            assert!(Instant::now() < until, "the first userfaultfd was not released in 10 s");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!is_missing(mem + ps) && is_missing(mem + 2 * ps) && is_missing(mem + 3 * ps));
        assert_eq!(slots(mem, mem + 4 * ps).count(), 1, "the slot went with the first userfaultfd");
        // SAFETY: released, so ordinary memory: a zero page.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0);
        assert_eq!(zeropage(b, mem, ps, true), Err((libc::ENOENT, 0)));
        assert_eq!(zeropage(b, mem + 2 * ps, 2 * ps, true), Ok(2 * ps));
        assert_eq!(unregister(b, mem + 2 * ps, 2 * ps), Ok(()));
        assert_eq!(slots(mem, mem + 4 * ps).count(), 0, "the slot outlived its last page");
        close(&[ub]);
    }

    /// A fill must lie in pages of the caller only: across the boundary
    /// between two userfaultfds' pages it is `ENOENT`, as Linux's
    /// destination must be one vma of the caller's (mm/userfaultfd.c, v6.12,
    /// `validate_dst_vma` :23 to :37). Across pages the same userfaultfd
    /// unregistered and registered again it is one call, as over Linux's
    /// vma merged again at the register (`userfaultfd_register_range`,
    /// `vma_modify_flags_uffd` at :1860).
    #[test]
    fn test_a_fill_lies_in_one_userfaultfds_pages() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(4);
        register(a, mem, 4 * ps).unwrap();
        assert_eq!(unregister(a, mem + ps, ps), Ok(()));
        register(a, mem + ps, ps).unwrap();
        assert_eq!(zeropage(a, mem, 2 * ps, true), Ok(2 * ps));
        assert_eq!(unregister(a, mem + 3 * ps, ps), Ok(()));
        register(b, mem + 3 * ps, ps).unwrap();
        assert_eq!(zeropage(a, mem + 2 * ps, 2 * ps, true), Err((libc::ENOENT, 0)));
        assert_eq!(zeropage(b, mem + 2 * ps, 2 * ps, true), Err((libc::ENOENT, 0)));
        assert!(is_missing(mem + 2 * ps) && is_missing(mem + 3 * ps), "a refused fill filled");
        assert_eq!(zeropage(a, mem + 2 * ps, ps, true), Ok(ps));
        assert_eq!(zeropage(b, mem + 3 * ps, ps, true), Ok(ps));
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        assert_eq!(unregister(b, mem + 3 * ps, ps), Ok(()));
        close(&[ua, ub]);
    }

    /// An unregister made through another userfaultfd takes the pages, as
    /// Linux 6.12's (fs/userfaultfd.c `userfaultfd_unregister` :1413) checks
    /// only that each vma can be registered (:1460 to :1483) and clears every
    /// vma that has a context (:1500 to :1501), waking that context's waiters
    /// (:1519): a thread waiting on a page of it runs again, the page is
    /// ordinary memory, and a later fill through its userfaultfd is `ENOENT`.
    /// Linux 6.17 refuses such an unregister with `EINVAL` (:1474 to :1480);
    /// wick follows 6.12.
    #[test]
    fn test_an_unregister_through_another_userfaultfd_wakes_and_takes_the_pages() {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        register(b, mem, ps).unwrap();
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the read waits for b's fill or wake.
            unsafe { ptr::read_volatile(mem as *const u8) }
        });
        let mut rec = [0u8; proto::RECORD];
        assert!(readable(ub) && read_full(ub, &mut rec), "no fault event");
        assert_eq!(words(&rec)[..2], [proto::EVENT_PAGEFAULT, mem]);
        assert_eq!(unregister(a, mem, ps), Ok(()));
        assert_eq!(reader.join().unwrap(), 0, "the waiter's access did not go through");
        assert!(!is_missing(mem));
        assert_eq!(zeropage(b, mem, ps, true), Err((libc::ENOENT, 0)));
        assert!(nothing_to_read(ua) && nothing_to_read(ub), "an event after the unregister");
        assert_eq!(slots(mem, mem + ps).count(), 0, "the range outlived its last page");
        close(&[ua, ub]);
    }

    /// Part of a mapping is registered, the rest left as it is, as Linux's
    /// register splits the vma at the range's edges (mm/userfaultfd.c, v6.12,
    /// `userfaultfd_register_range` :1825, `vma_modify_flags_uffd` at :1860).
    /// A control for the split, which must keep it.
    #[test]
    fn test_part_of_a_mapping_is_registered() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(4);
        // SAFETY: the first page of the mapping, before the register; the
        // last is left untouched, so that registered it would be missing.
        unsafe { ptr::write_volatile(mem as *mut u8, 7) };
        register(a, mem + ps, 2 * ps).unwrap();
        assert!(is_missing(mem + ps) && is_missing(mem + 2 * ps));
        assert!(!is_missing(mem) && !is_missing(mem + 3 * ps), "pages outside the range were registered");
        // SAFETY: the pages outside the range, ordinary memory still.
        unsafe {
            assert_eq!(ptr::read_volatile(mem as *const u8), 7);
            assert_eq!(ptr::read_volatile((mem + 3 * ps) as *const u8), 0);
            ptr::write_volatile((mem + 3 * ps) as *mut u8, 8);
        }
        assert_eq!(zeropage(a, mem + ps, 2 * ps, true), Ok(2 * ps));
        assert_eq!(unregister(a, mem + ps, 2 * ps), Ok(()));
        close(&[ua]);
    }

    /// The register a race test runs inside a change of memory: its
    /// userfaultfd and range, taken by the first change that runs without
    /// the lock.
    static RACE_REGISTER: Mutex<Option<(usize, u64, u64)>> = Mutex::new(None);
    /// The register's thread, with its result.
    static RACE_THREAD: Mutex<Option<std::thread::JoinHandle<io::Result<()>>>> = Mutex::new(None);

    /// The change hook of the race tests: starts the register on a thread of
    /// its own and returns once it waits for this change ([`register`]), or
    /// once it is done (without the counts it does not wait).
    fn register_in_the_change() {
        let Some((ctx, start, len)) = RACE_REGISTER.lock().unwrap().take() else {
            return;
        };
        let waits = REGISTER_WAITS.load(Ordering::SeqCst);
        let thread = std::thread::spawn(move || register(ctx, start, len));
        until("the register waits or ends", || REGISTER_WAITS.load(Ordering::SeqCst) > waits || thread.is_finished());
        *RACE_THREAD.lock().unwrap() = Some(thread);
    }

    /// Runs `change`, a change of memory no userfaultfd has registered, with
    /// a register of `[start, start + len)` by `ctx` started between its
    /// lock-free check and the change itself; the register's result.
    fn register_racing(ctx: usize, start: u64, len: u64, change: impl FnOnce()) -> io::Result<()> {
        *RACE_REGISTER.lock().unwrap() = Some((ctx, start, len));
        *CHANGE_HOOK.lock().unwrap() = Some(register_in_the_change);
        change();
        *CHANGE_HOOK.lock().unwrap() = None;
        let thread = RACE_THREAD.lock().unwrap().take().expect("the change did not run without the lock");
        thread.join().unwrap()
    }

    /// A protection XNU widens is read as it was asked
    /// ([`mapped_protections`]), as a Linux vma keeps it: `PROT_WRITE` alone
    /// through the compatibility `mprotect` reads as asked where macOS's
    /// entry has read added (xnu bsd/kern/kern_mman.c :1251 to :1253); read
    /// and write again reads read and write; an `munmap` leaves nothing; a
    /// new `mmap` with `PROT_WRITE` alone reads as asked (:349 to :351). The
    /// control: macOS's own entry has read in each widened case. (`PROT_EXEC`
    /// alone is widened the same way; this libc refuses executable memory
    /// where the sandbox would, so it is not asked here.)
    #[test]
    fn test_a_protection_xnu_widens_reads_as_asked() {
        let ps = host_page();
        let (w, rw) = (libc::PROT_WRITE as i8, (libc::PROT_READ | libc::PROT_WRITE) as i8);
        let mem = map(2);
        let at = |m: u64| mapped_protections(m, m + 2 * ps);
        let entry = |m: u64| mapped_entries(m, m + ps)[0].2;
        // SAFETY: the test's mapping.
        assert_eq!(unsafe { crate::linux_items::mprotect(mem as *mut _, ps as usize, libc::PROT_WRITE) }, 0);
        assert_eq!(at(mem), [w, rw], "PROT_WRITE alone");
        assert_ne!(entry(mem) & libc::PROT_READ, 0, "the control: macOS's entry has read");
        // SAFETY: as above.
        assert_eq!(unsafe { crate::linux_items::mprotect(mem as *mut _, 2 * ps as usize, libc::PROT_READ | libc::PROT_WRITE) }, 0);
        assert_eq!(at(mem), [rw, rw], "read and write again");
        // SAFETY: as above.
        assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut _, 2 * ps as usize) }, 0);
        assert_eq!(at(mem), [-1, -1], "unmapped");
        // SAFETY: a new mapping, unmapped below.
        let m = unsafe {
            crate::linux_items::mmap(core::ptr::null_mut(), ps as usize, libc::PROT_WRITE, libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
        };
        assert_ne!(m, libc::MAP_FAILED);
        assert_eq!(mapped_protections(m as u64, m as u64 + ps), [w], "a new mapping with PROT_WRITE alone");
        assert_ne!(entry(m as u64) & libc::PROT_READ, 0, "the control: macOS's entry has read");
        // SAFETY: the mapping just made.
        assert_eq!(unsafe { crate::linux_items::munmap(m, ps as usize) }, 0);
        assert!(!widened_over(m as u64, m as u64 + ps), "an munmap drops the record");
    }

    /// The record of a widened protection follows the later changes of its
    /// range as a vma would: a discard (`MADV_DONTNEED`, new zero pages)
    /// keeps it; a `MAP_FIXED` mapping over it with read and write drops it;
    /// a change by the system's own `mprotect` (not this libc's) reads as
    /// the system made it, not as the record says; an `munmap` drops it.
    #[test]
    fn test_a_widened_protection_follows_later_changes_of_its_range() {
        let ps = host_page();
        let (w, r, rw) = (libc::PROT_WRITE as i8, libc::PROT_READ as i8, (libc::PROT_READ | libc::PROT_WRITE) as i8);
        let mem = map(1);
        let at = || mapped_protections(mem, mem + ps)[0];
        let p = mem as *mut core::ffi::c_void;
        // SAFETY: the test's mapping, here and below.
        assert_eq!(unsafe { crate::linux_items::mprotect(p, ps as usize, libc::PROT_WRITE) }, 0);
        assert_eq!(at(), w, "PROT_WRITE alone");
        // SAFETY: as above.
        assert_eq!(unsafe { crate::linux_items::madvise(p, ps as usize, libc::MADV_DONTNEED) }, 0);
        assert_eq!(at(), w, "after a discard");
        // SAFETY: as above.
        let fixed = unsafe {
            crate::linux_items::mmap(
                p,
                ps as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(fixed, p);
        assert_eq!(at(), rw, "a MAP_FIXED mapping with read and write over it");
        // SAFETY: as above.
        assert_eq!(unsafe { crate::linux_items::mprotect(p, ps as usize, libc::PROT_WRITE) }, 0);
        assert_eq!(at(), w, "PROT_WRITE alone again");
        // SAFETY: as above; the system's own call.
        assert_eq!(unsafe { libc::mprotect(p, ps as usize, libc::PROT_READ) }, 0);
        assert_eq!(at(), r, "after the system's own mprotect to PROT_READ");
        // SAFETY: as above.
        assert_eq!(unsafe { crate::linux_items::munmap(p, ps as usize) }, 0);
        assert!(!widened_over(mem, mem + ps), "an munmap drops the record");
    }

    /// Two compatibility `mprotect`s of the same page are recorded in the
    /// order of their system calls: one asks `PROT_WRITE` alone, and between
    /// its system call and its record another thread asks read and write;
    /// that one's system call waits until the first is recorded, so the page
    /// reads read and write, the protection asked last. Recorded apart from
    /// the system call, the first's record would come last and the page would
    /// read `PROT_WRITE` alone, a read refused that the host allows.
    #[test]
    fn test_protection_records_come_in_the_order_of_their_calls() {
        let ps = host_page();
        let mem = map(1);
        let (tx, rx) = std::sync::mpsc::channel();
        *BETWEEN_CALL_AND_RECORD.lock().unwrap() = Some((
            mem,
            Box::new(move || {
                let second = std::thread::spawn(move || {
                    // SAFETY: the test's mapping.
                    let rc = unsafe {
                        crate::linux_items::mprotect(mem as *mut core::ffi::c_void, ps as usize, libc::PROT_READ | libc::PROT_WRITE)
                    };
                    tx.send(rc).unwrap();
                });
                // The second's system call waits; give it the time to be done
                // if it did not.
                std::thread::sleep(std::time::Duration::from_millis(100));
                drop(second);
            }),
        ));
        // SAFETY: the test's mapping.
        assert_eq!(unsafe { crate::linux_items::mprotect(mem as *mut core::ffi::c_void, ps as usize, libc::PROT_WRITE) }, 0);
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(10)), Ok(0), "the second mprotect");
        assert_eq!(
            mapped_protections(mem, mem + ps),
            [(libc::PROT_READ | libc::PROT_WRITE) as i8],
            "the protection asked last"
        );
        // SAFETY: the test's mapping.
        assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut core::ffi::c_void, ps as usize) }, 0);
    }

    /// The hypervisor backend's read of the host protection
    /// ([`host_protections`]) racing a register of the same memory: a
    /// register started between the read's lock-free check and its read
    /// waits for the read, which sees the memory as before the register (its
    /// own protection, read and write), never half-way (asked published and
    /// the missing pages made `PROT_NONE`, which would store "nothing" for
    /// pages the guest may use). Then a read after the register gets the
    /// asked protection of its missing pages. Without the count the register
    /// does not wait, and the hook's wait for it fails. In a process of its
    /// own, as the other race tests: another test's register in flight
    /// (`REGISTERING`) sends the read down the locked path, where the hook
    /// is not called ("the change did not run without the lock").
    #[test]
    fn test_a_protection_read_racing_a_register_is_the_asked_one() {
        if !in_own_process("wick_uffd::tests::test_a_protection_read_racing_a_register_is_the_asked_one") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        let rw = (libc::PROT_READ | libc::PROT_WRITE) as i8;
        let mut during = std::vec::Vec::new();
        let waits = REGISTER_WAITS.load(Ordering::SeqCst);
        let registered = register_racing(a, mem, 2 * ps, || {
            during = host_protections(mem, mem + 2 * ps, |read| read());
        });
        assert!(registered.is_ok(), "{registered:?}");
        assert!(REGISTER_WAITS.load(Ordering::SeqCst) > waits, "the register did not wait for the read");
        assert_eq!(during, [rw, rw], "the read racing the register");
        assert!(is_missing(mem) && is_missing(mem + ps));
        let after = host_protections(mem, mem + 2 * ps, |read| read());
        assert_eq!(after, [rw, rw], "the read after the register: the asked protection of missing pages");
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        close(&[ua]);
    }

    /// A register that starts while an `munmap` of the memory runs without
    /// the lock (it found no registered range) finds the memory gone:
    /// `EINVAL`, nothing registered, as on Linux, where the mm's lock orders
    /// the two and a register over no vma is `EINVAL` (fs/userfaultfd.c,
    /// v6.12, `userfaultfd_register` :1294 to :1299). Without the order, the
    /// register published its range before the `munmap`, which then left it
    /// registered over memory that is gone. In a process of its own, so that
    /// nothing else maps in the hole.
    #[test]
    fn test_a_register_racing_a_munmap_leaves_nothing_registered() {
        if !in_own_process("wick_uffd::tests::test_a_register_racing_a_munmap_leaves_nothing_registered") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        let r = register_racing(a, mem, 2 * ps, || {
            // SAFETY: the test's mapping.
            assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut _, (2 * ps) as usize) }, 0);
        });
        assert!(slots(mem, mem + 2 * ps).next().is_none(), "registered over memory that is gone ({r:?})");
        assert_eq!(r.map_err(|e| e.raw_os_error()), Err(Some(libc::EINVAL)));
        close(&[ua]);
    }

    /// A register that starts while a `MAP_FIXED` mapping over the memory
    /// runs without the lock registers the new memory: its pages missing,
    /// a fill lands in it. Without the order the register took the old
    /// memory (a written page present), and
    /// the mapping then replaced it under the registration.
    #[test]
    fn test_a_register_racing_a_map_fixed_registers_the_new_memory() {
        if !in_own_process("wick_uffd::tests::test_a_register_racing_a_map_fixed_registers_the_new_memory") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        // SAFETY: the test's mapping, before any register.
        unsafe { ptr::write_volatile(mem as *mut u8, 1) };
        let r = register_racing(a, mem, 2 * ps, || {
            let flags = libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED;
            // SAFETY: over the test's mapping.
            let p = unsafe { crate::linux_items::mmap(mem as *mut _, (2 * ps) as usize, RW, flags, -1, 0) };
            assert_eq!(p as u64, mem);
        });
        assert!(r.is_ok(), "{r:?}");
        assert!(is_missing(mem) && is_missing(mem + ps), "the new memory is not what was registered");
        let data = std::vec![0x5au8; ps as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        // SAFETY: filled just now.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a, "the fill went elsewhere");
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        close(&[ua]);
    }

    /// A register that starts while an `mprotect` of the memory runs without
    /// the lock keeps its pages missing and inaccessible, with the
    /// protection asked recorded. Without the order the `mprotect` came
    /// after the register and opened its missing page. The `mprotect` asks
    /// read and write again, as [`register`] refuses memory that is not
    /// readable and writable (`EPERM`, where Linux would take it).
    #[test]
    fn test_a_register_racing_an_mprotect_keeps_its_pages_missing() {
        if !in_own_process("wick_uffd::tests::test_a_register_racing_an_mprotect_keeps_its_pages_missing") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        let r = register_racing(a, mem, ps, || {
            // SAFETY: the test's mapping.
            assert_eq!(unsafe { crate::linux_items::mprotect(mem as *mut _, ps as usize, RW) }, 0);
        });
        assert!(r.is_ok(), "{r:?}");
        assert!(is_missing(mem));
        assert_eq!(prot_of(mem) & RW, 0, "a missing page left accessible");
        assert_eq!(unregister(a, mem, ps), Ok(()));
        assert_eq!(prot_of(mem) & RW, RW, "the protection asked");
        close(&[ua]);
    }

    /// A register that starts while a `MADV_DONTNEED` of the memory runs
    /// without the lock registers the pages the discard left: missing, and a
    /// fill lands in them. Without the order the register took the written
    /// page, present, and the discard then replaced it under the
    /// registration.
    #[test]
    fn test_a_register_racing_a_discard_fills_the_new_pages() {
        if !in_own_process("wick_uffd::tests::test_a_register_racing_a_discard_fills_the_new_pages") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        // SAFETY: the test's mapping, before any register.
        unsafe { ptr::write_volatile(mem as *mut u8, 1) };
        let r = register_racing(a, mem, ps, || {
            // SAFETY: the test's mapping.
            let r = unsafe { crate::linux_items::madvise(mem as *mut _, ps as usize, libc::MADV_DONTNEED) };
            assert_eq!(r, 0);
        });
        assert!(r.is_ok(), "{r:?}");
        assert!(is_missing(mem), "the discarded page is not missing");
        let data = std::vec![0x5au8; ps as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        // SAFETY: filled just now.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a, "the fill went elsewhere");
        assert_eq!(unregister(a, mem, ps), Ok(()));
        close(&[ua]);
    }

    /// How registered memory is replaced: unmapped and mapped again in the
    /// hole, or mapped over with `MAP_FIXED`.
    #[derive(Clone, Copy, Debug)]
    enum Replace {
        UnmapThenMap,
        MapFixedOver,
    }

    /// Two pages registered with a fresh userfaultfd `a`, the first filled
    /// (`0x5a`), then replaced by new memory at the same addresses, as
    /// [`Replace`] says, through the compatibility calls. Linux's registration
    /// belongs to the vma (`vm_userfaultfd_ctx`) and goes with it: munmap
    /// removes the vma (mm/vma.c, v6.12, `do_vmi_align_munmap` :1332, through
    /// `vms_gather_munmap_vmas` :1180, which calls fs/userfaultfd.c
    /// `userfaultfd_unmap_prep` at :1267), and `MAP_FIXED` unmaps what it
    /// maps over first (mm/mmap.c, v6.12, `__mmap_region` :1361, the same
    /// `vms_gather_munmap_vmas` at :1386), so the new memory is not
    /// registered. Run in a process of its own, as the holes test:
    /// nothing else may map in the hole. Returns (a, its user end, b, its
    /// user end, a's channel, the memory).
    fn replaced(how: Replace) -> (usize, c_int, usize, c_int, c_int, u64) {
        let (a, ua) = create(0, false, true).unwrap();
        let (b, ub) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        let chan = channel(ua);
        let data = std::vec![0x5au8; ps as usize];
        register(a, mem, 2 * ps).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        // SAFETY: the test's own mapping, replaced at the same addresses;
        // nothing else maps in this process meanwhile.
        unsafe {
            if let Replace::UnmapThenMap = how {
                assert_eq!(crate::linux_items::munmap(mem as *mut _, (2 * ps) as usize), 0);
            }
            let p = crate::linux_items::mmap(
                mem as *mut _,
                (2 * ps) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            );
            assert_eq!(p as u64, mem, "{how:?}");
        }
        (a, ua, b, ub, chan, mem)
    }

    const REPLACES: [Replace; 2] = [Replace::UnmapThenMap, Replace::MapFixedOver];

    /// The cases of [`REPLACES`] test `name` runs here. In the test's own
    /// process: none; each case runs in a process of its own (nothing else
    /// may map in the hole), all of them, and the test fails naming every
    /// case that failed, with its output. In a case's process: that case.
    fn replace_cases(name: &str) -> Vec<Replace> {
        const CASE: &str = "WICK_UFFD_REPLACE";
        if let Some(case) = std::env::var_os(CASE) {
            return REPLACES.into_iter().filter(|how| case.to_str() == Some(std::format!("{how:?}").as_str())).collect();
        }
        let failed: Vec<std::string::String> = REPLACES
            .iter()
            .filter_map(|how| {
                let case = std::format!("{how:?}");
                run_alone(name, &[(CASE, &case)]).err().map(|text| std::format!("{case}: {text}"))
            })
            .collect();
        assert!(failed.is_empty(), "{} of {} cases failed:\n{}", failed.len(), REPLACES.len(), failed.join("\n"));
        Vec::new()
    }

    /// The new memory is in no registration: not missing, and a fill there
    /// is `ENOENT`, as Linux's for a destination in no registered vma
    /// (mm/userfaultfd.c, v6.12: `mfill_atomic` :700 takes the vma with
    /// `uffd_mfill_lock` :733, which is `ENOENT` at :113 when
    /// `validate_dst_vma` finds no userfaultfd on it, :34).
    #[test]
    fn test_memory_replaced_while_registered_is_in_no_registration() {
        for how in replace_cases("wick_uffd::tests::test_memory_replaced_while_registered_is_in_no_registration") {
            let (a, ua, _b, ub, chan, mem) = replaced(how);
            let ps = test_page_size();
            assert!(!is_missing(mem) && !is_missing(mem + ps), "{how:?}: the new memory is registered");
            assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)), "{how:?}");
            close(&[chan, ua, ub]);
        }
    }

    /// The new memory registers anew, with the same userfaultfd or another:
    /// Linux's new vma has no userfaultfd (mm/mmap.c, v6.12, `__mmap_region`
    /// takes the old vmas out at :1386 and makes a new one with
    /// `vm_area_alloc` at :1435), and `userfaultfd_register` refuses only a
    /// vma another userfaultfd has (fs/userfaultfd.c, v6.12, :1363 to :1366).
    #[test]
    fn test_memory_replaced_while_registered_registers_anew() {
        for how in replace_cases("wick_uffd::tests::test_memory_replaced_while_registered_registers_anew") {
            // Its userfaultfd again: both pages are missing, and a fill lands
            // in the new memory, not in the pages the old one had.
            let (a, ua, _b, ub, chan, mem) = replaced(how);
            let ps = test_page_size();
            let data = std::vec![0x5au8; ps as usize];
            register(a, mem, 2 * ps).unwrap();
            assert!(is_missing(mem) && is_missing(mem + ps), "{how:?}: the new pages are not missing");
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { copy(a, data.as_ptr(), mem + ps, ps, true) }, Ok(ps), "{how:?}");
            // SAFETY: filled just now, in the new memory.
            let got = unsafe { ptr::read_volatile((mem + ps) as *const u8) };
            assert_eq!(got, 0x5a, "{how:?}: the fill did not reach the new memory");
            assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
            close(&[chan, ua, ub]);
            // Another userfaultfd: Linux registers the new memory.
            let (_a, ua, b, ub, chan, mem) = replaced(how);
            register(b, mem, 2 * ps).unwrap_or_else(|e| panic!("{how:?}: another userfaultfd's register: {e}"));
            assert!(is_missing(mem) && is_missing(mem + ps), "{how:?}");
            assert_eq!(unregister(b, mem, 2 * ps), Ok(()));
            close(&[chan, ua, ub]);
        }
    }

    /// A discard of the new memory is an ordinary one: its pages hold zeros
    /// and stay accessible, as Linux's `MADV_DONTNEED` of memory no
    /// userfaultfd has (mm/madvise.c, v6.12: `madvise_dontneed_free` :880
    /// goes on past `userfaultfd_remove` :894, which returns true for a vma
    /// with no userfaultfd, fs/userfaultfd.c :777 to :779, and
    /// `madvise_dontneed_single_vma` zaps the pages, :846). It must not take
    /// the replaced range's slot for it.
    #[test]
    fn test_a_discard_of_memory_replaced_while_registered_is_ordinary() {
        for how in replace_cases("wick_uffd::tests::test_a_discard_of_memory_replaced_while_registered_is_ordinary") {
            let (_a, ua, _b, ub, chan, mem) = replaced(how);
            let ps = test_page_size();
            // SAFETY: the new memory, read and writable.
            unsafe { ptr::write_volatile(mem as *mut u8, 7) };
            // SAFETY: the new memory.
            let r = unsafe { crate::linux_items::madvise(mem as *mut _, (2 * ps) as usize, libc::MADV_DONTNEED) };
            assert_eq!(r, 0);
            assert!(!is_missing(mem) && !is_missing(mem + ps), "{how:?}: the discard made the new memory missing");
            // SAFETY: not missing, so accessible.
            assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0, "{how:?}");
            close(&[chan, ua, ub]);
        }
    }

    /// Registered memory unmapped while its userfaultfd is open, as
    /// Firecracker's teardown unmaps its guest memory (the guest regions'
    /// drop, lib/firecracker/src/vmm/src/vstate/memory.rs:308, before the
    /// VM's `uffd` is dropped, vstate/vm.rs:84 and :95), leaves no
    /// registration behind: on Linux the registration belongs to the vma
    /// and goes with it (mm/vma.c, v6.12, `do_vmi_align_munmap` :1332), and a
    /// fill where no registered vma is is `ENOENT` (mm/userfaultfd.c
    /// `uffd_mfill_lock` :113, `validate_dst_vma` :34). Part of a range: the
    /// unmapped page is in no registration, the rest is as it was. All of
    /// it: nothing is left of the range, and the userfaultfd's close after
    /// it finds nothing to release. In a process of its own: no other test
    /// may map or register in the holes meanwhile.
    #[test]
    fn test_memory_unmapped_while_registered_leaves_no_registration_behind() {
        if !in_own_process("wick_uffd::tests::test_memory_unmapped_while_registered_leaves_no_registration_behind") {
            return;
        }
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let data = std::vec![0x5au8; ps as usize];
        let unmap = |at: u64, len: u64| {
            // SAFETY: pages of the test's own mapping, unmapped by this
            // libc's munmap, as Firecracker's drop unmaps them.
            assert_eq!(unsafe { crate::linux_items::munmap(at as *mut _, len as usize) }, 0);
        };
        // Part: the second of two pages.
        let mem = map(2);
        register(a, mem, 2 * ps).unwrap();
        unmap(mem + ps, ps);
        assert!(!is_missing(mem + ps), "the unmapped page is still registered");
        assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)), "a fill of the unmapped page");
        assert!(is_missing(mem), "the page left mapped is no longer missing");
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        // SAFETY: filled just now.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a);
        unmap(mem, ps);
        assert!(slots(mem, mem + 2 * ps).next().is_none(), "a range with no page left is still held");
        // All: two pages, one filled, then the userfaultfd closed.
        let mem = map(2);
        register(a, mem, 2 * ps).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        unmap(mem, 2 * ps);
        assert!(slots(mem, mem + 2 * ps).next().is_none(), "the unmapped range is still held");
        assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)));
        close(&[ua]);
    }

    /// The race test's state, for its hook ([`race_in_the_change`]).
    static RACE_MEM: AtomicU64 = AtomicU64::new(0);
    static RACE_CTX: AtomicUsize = AtomicUsize::new(0);
    static RACE_USER: AtomicI32 = AtomicI32::new(-1);
    static RACE_HOLE: AtomicBool = AtomicBool::new(false);
    type Filled = Result<u64, (c_int, u64)>;
    static RACE_FILL: Mutex<Option<std::thread::JoinHandle<Filled>>> = Mutex::new(None);

    /// The hook of [`test_an_unmapping_and_its_unregistration_are_one_step`]:
    /// between the change of the mapping and the unregistration, a mapping
    /// made in the hole (for a munmap), a handler's fill of a page the old
    /// registration has missing, and the userfaultfd's close. Each runs on a
    /// thread of its own, and the hook goes on once the thread is done or
    /// waits for [`LOCK`]: with no timing, either the step holds the lock
    /// and they run after it, or they run inside it.
    fn race_in_the_change(start: u64, _end: u64) {
        let mem = RACE_MEM.load(Ordering::SeqCst);
        if start != mem {
            return;
        }
        let ps = test_page_size();
        if RACE_HOLE.load(Ordering::SeqCst) {
            // SAFETY: the hole the munmap left, the test's own range; the
            // system's call, as another thread's stack guard is made.
            let p = unsafe {
                libc::mmap(
                    mem as *mut _,
                    (2 * ps) as usize,
                    libc::PROT_NONE,
                    libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_eq!(p as u64, mem);
        }
        let ctx = RACE_CTX.load(Ordering::SeqCst);
        let waits = LOCK_WAITS.load(Ordering::SeqCst);
        let filler = std::thread::spawn(move || {
            let data = std::vec![0x5au8; test_page_size() as usize];
            // SAFETY: `data` holds a page.
            unsafe { copy(ctx, data.as_ptr(), mem + test_page_size(), test_page_size(), true) }
        });
        until("the fill", || filler.is_finished() || LOCK_WAITS.load(Ordering::SeqCst) > waits);
        *RACE_FILL.lock().unwrap() = Some(filler);
        let waits = LOCK_WAITS.load(Ordering::SeqCst);
        close(&[RACE_USER.load(Ordering::SeqCst)]);
        until("the release", || {
            slots(mem, mem + 2 * ps).next().is_none() || LOCK_WAITS.load(Ordering::SeqCst) > waits
        });
    }

    /// An unmapping of registered memory, or a `MAP_FIXED` mapping over it,
    /// and its unregistration are one step to everything else that changes
    /// the ranges, as Linux's registration goes with the vma under the mm's
    /// lock ([`unmapping`]): a handler's fill of a page the old registration
    /// had missing and the userfaultfd's release, both arriving between the
    /// change of the mapping and the unregistration ([`race_in_the_change`]),
    /// find no registration and leave the new memory, or a `PROT_NONE`
    /// mapping made in the hole, as it is. Before, a fill there made the
    /// new memory's page accessible and a release made the missing pages
    /// read-write. In a process of its own (holes).
    #[test]
    fn test_an_unmapping_and_its_unregistration_are_one_step() {
        if !in_own_process("wick_uffd::tests::test_an_unmapping_and_its_unregistration_are_one_step") {
            return;
        }
        *UNMAP_HOOK.lock().unwrap() = Some(race_in_the_change);
        let ps = test_page_size();
        for hole in [true, false] {
            let (ctx, user) = create(0, false, true).unwrap();
            let mem = map(2);
            register(ctx, mem, 2 * ps).unwrap();
            let data = std::vec![0x11u8; ps as usize];
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, ps, true) }, Ok(ps));
            RACE_CTX.store(ctx, Ordering::SeqCst);
            RACE_USER.store(user, Ordering::SeqCst);
            RACE_HOLE.store(hole, Ordering::SeqCst);
            RACE_MEM.store(mem, Ordering::SeqCst);
            // SAFETY: the test's own mapping, through this libc's calls.
            unsafe {
                if hole {
                    assert_eq!(crate::linux_items::munmap(mem as *mut _, (2 * ps) as usize), 0);
                } else {
                    let p = crate::linux_items::mmap(
                        mem as *mut _,
                        (2 * ps) as usize,
                        libc::PROT_NONE,
                        libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                        -1,
                        0,
                    );
                    assert_eq!(p as u64, mem);
                }
            }
            RACE_MEM.store(0, Ordering::SeqCst);
            let filled = RACE_FILL.lock().unwrap().take().unwrap().join().unwrap();
            until("the release", || slots(mem, mem + 2 * ps).next().is_none());
            let prot = (prot_of(mem), prot_of(mem + ps));
            // SAFETY: the test's own range.
            unsafe { libc::munmap(mem as *mut _, (2 * ps) as usize) };
            let case = if hole { "munmap, then a mapping in the hole" } else { "MAP_FIXED" };
            assert_eq!(filled, Err((libc::ENOENT, 0)), "{case}: the fill found the old registration");
            assert_eq!(prot, (libc::PROT_NONE, libc::PROT_NONE), "{case}: the new memory's protection changed");
        }
        *UNMAP_HOOK.lock().unwrap() = None;
    }

    /// A thread waiting on a page whose memory is mapped over waits on, as
    /// Linux's (no event or wake comes of the unmapping without
    /// `UFFD_FEATURE_EVENT_UNMAP`), until its userfaultfd's `UFFDIO_WAKE`,
    /// which checks the range only (fs/userfaultfd.c, v6.12,
    /// `userfaultfd_wake` :1545 to :1575), or its release, which wakes every
    /// waiter (`userfaultfd_release` :873). The woken thread runs its access
    /// again: here new memory is mapped there, which it reads. (On a hole it
    /// takes the process's own fault:
    /// `test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken`.)
    /// The waiters are waiting once their records are read, as a handler
    /// knows them: a waiter holds its slot before it validates and posts,
    /// and one whose memory is mapped over meanwhile posts nothing and runs
    /// its access again, as an access after the mapping would on Linux
    /// (where the mapping waits for `mmap_lock`, which the fault holds until
    /// it is queued). The first waiter's validation is held 50 ms, so that
    /// a test going on at the slot would map over it there.
    #[test]
    fn test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd() {
        fn hold() {
            std::thread::sleep(Duration::from_millis(50));
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        VALIDATE_HOOK.store(hold as fn() as usize, Ordering::SeqCst);
        VALIDATE_AT.store(mem, Ordering::SeqCst);
        let waiter = |at: u64| {
            std::thread::spawn(move || {
                // The access's fault, as the signal handler takes it.
                assert!(fault(at, false), "not missing");
                // SAFETY: the memory mapped over it below, readable.
                unsafe { ptr::read_volatile(at as *const u8) }
            })
        };
        let (first, second) = (waiter(mem), waiter(mem + ps));
        let mut posted = [next_record(user)[1], next_record(user)[1]];
        posted.sort_unstable();
        assert_eq!(posted, [mem, mem + ps], "the waiters' records");
        // SAFETY: the test's own mapping, mapped over through this libc.
        let p = unsafe {
            crate::linux_items::mmap(
                mem as *mut _,
                (2 * ps) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_eq!(p as u64, mem);
        // SAFETY: the new memory, read and writable.
        unsafe { ptr::write_bytes(mem as *mut u8, 7, (2 * ps) as usize) };
        assert!(slots(mem, mem + 2 * ps).next().is_none(), "the memory mapped over is still registered");
        assert!(!first.is_finished() && !second.is_finished(), "a waiter went on with no wake");
        assert_eq!(wake_range(ctx, mem, ps), Ok(()));
        assert_eq!(first.join().unwrap(), 7);
        assert!(!second.is_finished(), "the wake of one page woke the other");
        close(&[user]);
        assert_eq!(second.join().unwrap(), 7);
        // SAFETY: the test's own mapping.
        unsafe { libc::munmap(mem as *mut _, (2 * ps) as usize) };
    }

    /// A thread waiting on a page whose memory is unmapped, once its
    /// userfaultfd wakes it, runs its access again and takes the process's
    /// own fault, as on Linux, where the address has no vma: here the
    /// previous `SIGSEGV`/`SIGBUS` handler, which ends the child. In a child,
    /// under an alarm (a waiter left waiting would hang it: `SIGALRM`).
    #[test]
    fn test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken() {
        const CHILD_CASE: &str = "WICK_UFFD_UNMAPPED_WAITER";
        let name = "wick_uffd::tests::test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken";
        if std::env::var_os(CHILD_CASE).is_none() {
            let out = {
                let _spawning = crate::timerfd::spawning();
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([name, "--exact", "--include-ignored", "--test-threads=1", "--nocapture"])
                    .env(CHILD_CASE, "1")
                    .output()
                    .unwrap()
            };
            use std::os::unix::process::ExitStatusExt;
            let sig = out.status.signal();
            assert!(
                sig == Some(libc::SIGSEGV) || sig == Some(libc::SIGBUS),
                "{:?}\n{}{}",
                out.status,
                std::string::String::from_utf8_lossy(&out.stdout),
                std::string::String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        // SAFETY: plain alarm; its default action ends the child.
        unsafe { libc::alarm(10) };
        let (ctx, _user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        register(ctx, mem, ps).unwrap();
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory: the read waits, then runs again.
            unsafe { ptr::read_volatile(mem as *const u8) }
        });
        until("the waiter", || WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == mem));
        // SAFETY: the test's own mapping, through this libc.
        assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut _, ps as usize) }, 0);
        assert_eq!(wake_range(ctx, mem, ps), Ok(()));
        let _ = reader.join();
        std::eprintln!("the woken read of an unmapped page went on");
    }

    /// Memory mapped over one page of a registered range and registered
    /// again by the same userfaultfd is filled in the new memory: a fill
    /// writes through a view of the pages there now ([`fill_view`]).
    #[test]
    fn test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        let data = std::vec![0x11u8; ps as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem, ps, true) }, Ok(ps));
        // SAFETY: the test's own page, mapped over through this libc.
        let p = unsafe {
            crate::linux_items::mmap(
                (mem + ps) as *mut _,
                ps as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_eq!(p as u64, mem + ps);
        assert!(!is_missing(mem + ps) && !is_missing(mem));
        assert_eq!(zeropage(ctx, mem + ps, ps, true), Err((libc::ENOENT, 0)));
        register(ctx, mem + ps, ps).unwrap();
        assert!(is_missing(mem + ps), "the new page is not missing");
        let data = std::vec![0x77u8; ps as usize];
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + ps, ps, true) }, Ok(ps));
        // SAFETY: filled just now; the first page as it was.
        unsafe {
            assert_eq!(ptr::read_volatile((mem + ps) as *const u8), 0x77, "the fill did not reach the new memory");
            assert_eq!(ptr::read_volatile(mem as *const u8), 0x11);
        }
        assert_eq!(unregister(ctx, mem, 2 * ps), Ok(()));
        close(&[user]);
        // SAFETY: the test's own mapping.
        unsafe { libc::munmap(mem as *mut _, (2 * ps) as usize) };
    }

    /// A munmap or a `MAP_FIXED` mapping that cuts a huge page of a
    /// registered huge page range is `EINVAL` with nothing changed, as Linux
    /// refuses to split a hugetlb vma off a huge page boundary before
    /// anything is unmapped (mm/vma.c, v6.12, `__split_vma` :377 to :378,
    /// called by `vms_gather_munmap_vmas` at :1209 and :1230); on the
    /// boundaries, the huge pages leave the registration.
    #[test]
    fn test_a_cut_of_a_registered_huge_page_is_einval() {
        use crate::linux_items::{HUGE_PAGE, MAP_HUGETLB, MAP_HUGE_2MB};
        let _alone = huge_mapping_test();
        let (ctx, user) = create(0, false, true).unwrap();
        let host = test_page_size();
        let len = 2 * HUGE_PAGE;
        // SAFETY: a huge page mapping of the compatibility mmap, unmapped at the end.
        let mem = unsafe {
            crate::linux_items::mmap(
                ptr::null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGETLB | MAP_HUGE_2MB,
                -1,
                0,
            )
        } as u64;
        assert_ne!(mem, libc::MAP_FAILED as u64);
        register(ctx, mem, len).unwrap();
        // SAFETY: inside the test's huge mapping; refused before any change.
        unsafe {
            assert_eq!(crate::linux_items::munmap((mem + host) as *mut _, host as usize), -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL), "munmap");
            let p = crate::linux_items::mmap(
                (mem + HUGE_PAGE - host) as *mut _,
                (2 * host) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            assert_eq!(p, libc::MAP_FAILED, "MAP_FIXED across a huge page boundary");
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL), "MAP_FIXED");
        }
        for off in [0, host, HUGE_PAGE - host, HUGE_PAGE, len - host] {
            assert!(is_missing(mem + off), "{off:#x}: changed by a refused call");
        }
        // SAFETY: the second huge page, on its boundaries.
        assert_eq!(unsafe { crate::linux_items::munmap((mem + HUGE_PAGE) as *mut _, HUGE_PAGE as usize) }, 0);
        assert!(is_missing(mem) && !is_missing(mem + HUGE_PAGE));
        assert_eq!(zeropage(ctx, mem + HUGE_PAGE, HUGE_PAGE, true), Err((libc::ENOENT, 0)));
        // SAFETY: the first, the rest of the test's mapping.
        assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut _, HUGE_PAGE as usize) }, 0);
        assert!(slots(mem, mem + len).next().is_none());
        close(&[user]);
    }

    /// A mapping made where registered memory was unmapped, before its
    /// userfaultfd is released, keeps its protection through the release.
    /// Firecracker unmaps its guest memory that way at teardown: the guest
    /// regions' drop (lib/firecracker/src/vmm/src/vstate/memory.rs:308) runs
    /// when `VmCommon` drops `guest_memory` (vstate/vm.rs:84), before its
    /// `uffd` (:95), and another thread may map the hole meanwhile (a new
    /// thread's stack guard, a `PROT_NONE` reservation). On Linux the
    /// registration goes with the unmapped vma (mm/vma.c
    /// `do_vmi_align_munmap` :1332), and the release walks only the vmas
    /// this userfaultfd has (mm/userfaultfd.c, v6.12,
    /// `userfaultfd_release_all` :1918 to :1924: a vma of another context, or
    /// none, is skipped), changing no protection, so the new mapping is left
    /// as it was. In a process of its own, as the holes test: another test's
    /// thread could map into the hole before the `MAP_FIXED`, which would
    /// then replace that memory; and the hole is made only once the serving
    /// thread has answered a request, its start's mappings made.
    #[test]
    fn test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is() {
        if !in_own_process("wick_uffd::tests::test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is") {
            return;
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        assert!(is_missing(mem) && is_missing(mem + ps));
        let chan = channel(user);
        // SAFETY: the test's own mapping, unmapped by this libc's munmap as
        // Firecracker's drop unmaps it, then a reservation in its place, made
        // by the system's call as a thread's stack guard is.
        unsafe {
            assert_eq!(crate::linux_items::munmap(mem as *mut _, (2 * ps) as usize), 0);
            let p = libc::mmap(
                mem as *mut _,
                (2 * ps) as usize,
                libc::PROT_NONE,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            );
            assert_eq!(p as u64, mem);
        }
        close(&[chan, user]);
        // The release is the serving thread's, once it sees the close.
        let until = Instant::now() + Duration::from_secs(10);
        while slots(mem, mem + 2 * ps).next().is_some() {
            assert!(Instant::now() < until, "the userfaultfd was not released in 10 s");
            std::thread::sleep(Duration::from_millis(5));
        }
        let prot = (prot_of(mem), prot_of(mem + ps));
        // SAFETY: the reservation made above.
        unsafe { libc::munmap(mem as *mut _, (2 * ps) as usize) };
        assert_eq!(prot, (libc::PROT_NONE, libc::PROT_NONE), "the release changed the new mapping's protection");
    }

    /// The current protection of the page at `addr` (`PROT_*` bits).
    fn prot_of(addr: u64) -> c_int {
        const VM_REGION_BASIC_INFO_64: c_int = 9;
        let (mut at, mut size, mut object) = (addr, 0u64, 0);
        let mut info = [0 as c_int; 16];
        let mut count = 9u32;
        // SAFETY: valid output buffers, as `mapped_entries`.
        let kr = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut at,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        assert!(kr == 0 && at <= addr && addr < at + size, "no entry at {addr:#x}");
        info[0] & (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC)
    }

    const RW: c_int = libc::PROT_READ | libc::PROT_WRITE;

    fn mprotect(addr: u64, len: u64, prot: c_int) {
        // SAFETY: the test's own mapping.
        assert_eq!(unsafe { crate::linux_items::mprotect(addr as *mut _, len as usize, prot) }, 0);
    }

    /// As Linux, where mprotect leaves a userfaultfd registration as it is
    /// (mm/mprotect.c changes the vma's protection, not `vm_userfaultfd_ctx`)
    /// and an access its protection allows to a missing page faults to the
    /// userfaultfd:
    /// a virtio-mem slot unplugged (`PROT_NONE`) and plugged (`PROT_READ |
    /// PROT_WRITE`) after a restore from a userfaultfd (vstate/memory.rs
    /// `protect`; persist.rs `guest_memory_from_uffd` registers every region,
    /// the hotplug one too) keeps its missing pages missing: inaccessible to
    /// the host, so the VMM's own access faults to the handler, where before
    /// it read zeros and a later copy overwrote what it wrote.
    #[test]
    fn test_mprotect_of_registered_missing_pages_keeps_them_missing() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        let data = std::vec![0x5au8; ps as usize];
        register(a, mem, 2 * ps).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        mprotect(mem, 2 * ps, libc::PROT_NONE);
        mprotect(mem, 2 * ps, RW);
        assert!(is_missing(mem + ps));
        assert_eq!(prot_of(mem + ps) & RW, 0, "mprotect made a missing page accessible");
        // The filled page has what was asked.
        assert_eq!(prot_of(mem) & RW, RW);
        // SAFETY: filled and readable.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a);
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        close(&[ua]);
    }

    /// Reads the next event from the userfaultfd's user end `user` and fills
    /// the page it names with `fill`; returns the event.
    fn serve_one(user: c_int, ctx: usize, fill: u8) -> [u64; 4] {
        let mut event = [0u8; proto::RECORD];
        assert!(read_full(user, &mut event), "the userfaultfd closed");
        let w = words(&event);
        let ps = test_page_size();
        let page = std::vec![fill; ps as usize];
        // SAFETY: `page` holds a page.
        assert_eq!(unsafe { copy(ctx, page.as_ptr(), w[1] - w[1] % ps, ps, true) }, Ok(ps));
        w
    }

    /// Firecracker's memory hotplug after a restore from a userfaultfd, in
    /// the compatibility calls it makes: the whole region registered
    /// (persist.rs `guest_memory_from_uffd`), an unplugged slot made
    /// `PROT_NONE` (vm.rs `register_memory_region`, `slot.protect(true)`), a
    /// plugged page read through the handler, the slot plugged
    /// (`protect(false)`) and read through the handler, then unplugged again
    /// (discarded, `MADV_DONTNEED`, with its remove event, and `PROT_NONE`),
    /// its pages missing again, and plugged again. The name and the steps
    /// are the Windows backend's test of the same path. Before each read the
    /// page must be missing and inaccessible, so a page a call opened fails
    /// here rather than reading zeros with no event to serve.
    #[test]
    fn test_plug_after_a_uffd_restore() {
        let (ctx, user) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let slot_len = 4 * ps;
        let mem = map(8);
        register(ctx, mem, 2 * slot_len).unwrap();
        let unplugged = mem + slot_len;
        mprotect(unplugged, slot_len, libc::PROT_NONE);
        let read_through_the_handler = |addr: u64, fill: u8| {
            assert!(is_missing(addr), "{addr:#x} is not missing");
            assert_eq!(prot_of(addr) & RW, 0, "{addr:#x} is missing but accessible: a read would see zeros");
            let reader = std::thread::spawn(move || {
                // SAFETY: registered memory; the read waits for the fill.
                unsafe { ptr::read_volatile(addr as *const u8) }
            });
            let event = serve_one(user, ctx, fill);
            assert_eq!((event[0], event[1]), (proto::EVENT_PAGEFAULT, addr));
            assert_eq!(reader.join().unwrap(), fill);
        };
        read_through_the_handler(mem + 3 * ps, 0x61);
        mprotect(unplugged, slot_len, RW);
        read_through_the_handler(unplugged + 3 * ps, 0x62);
        // Unplug: discarded, then closed; its pages missing again.
        // SAFETY: registered memory of the test's.
        let r = unsafe { crate::linux_items::madvise(unplugged as *mut _, slot_len as usize, libc::MADV_DONTNEED) };
        assert_eq!(r, 0);
        let mut removed = [0u8; proto::RECORD];
        assert!(read_full(user, &mut removed));
        assert_eq!(words(&removed)[..3], [proto::EVENT_REMOVE, unplugged, unplugged + slot_len]);
        mprotect(unplugged, slot_len, libc::PROT_NONE);
        assert!(is_missing(unplugged + 3 * ps));
        // Plugged again: a fault to the handler again.
        mprotect(unplugged, slot_len, RW);
        read_through_the_handler(unplugged + 3 * ps, 0x63);
        assert_eq!(unregister(ctx, mem, 2 * slot_len), Ok(()));
        close(&[user]);
    }

    /// A filled page made inaccessible and accessible again is not missing:
    /// its data stays, as on Linux.
    #[test]
    fn test_mprotect_of_a_filled_page_does_not_make_it_missing() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        let data = std::vec![0x5au8; ps as usize];
        register(a, mem, ps).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        mprotect(mem, ps, libc::PROT_NONE);
        assert!(!is_missing(mem));
        mprotect(mem, ps, RW);
        assert!(!is_missing(mem));
        // SAFETY: filled and readable.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a);
        assert_eq!(unregister(a, mem, ps), Ok(()));
        close(&[ua]);
    }

    /// The protection asked of a missing page is the one it has once filled:
    /// by a copy, by a zero page, and after a discard made it missing again
    /// and a copy filled it, as Linux's pages take their vma's protection.
    #[test]
    fn test_a_filled_page_takes_the_protection_asked_while_it_was_missing() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        let data = std::vec![0x5au8; ps as usize];
        register(a, mem, 2 * ps).unwrap();
        mprotect(mem, 2 * ps, libc::PROT_READ);
        assert_eq!(prot_of(mem) & RW, 0, "a missing page became accessible");
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        assert_eq!(prot_of(mem) & RW, libc::PROT_READ, "copy");
        assert_eq!(zeropage(a, mem + ps, ps, true), Ok(ps));
        assert_eq!(prot_of(mem + ps) & RW, libc::PROT_READ, "zeropage");
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, ps as usize, libc::MADV_DONTNEED) };
        assert_eq!(r, 0);
        assert!(is_missing(mem));
        assert_eq!(prot_of(mem) & RW, 0);
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        assert_eq!(prot_of(mem) & RW, libc::PROT_READ, "copy after a discard");
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        close(&[ua]);
    }

    /// A virtio-mem slot unplugged and plugged again after a restore through
    /// a userfaultfd, as Firecracker does it: the slot made `PROT_NONE`, then
    /// discarded (devices/virtio/mem/device.rs: `update_slot` before
    /// `discard_range`), then made read-write; the handler's next fill there
    /// lands, as on Linux, where the discard leaves the pages missing in their
    /// vma.
    #[test]
    fn test_a_slot_unplugged_and_plugged_again_is_filled() {
        let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        let data = std::vec![0x5au8; ps as usize];
        register(a, mem, 2 * ps).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        mprotect(mem, 2 * ps, libc::PROT_NONE);
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, (2 * ps) as usize, libc::MADV_DONTNEED) };
        assert_eq!(r, 0);
        assert!(is_missing(mem) && is_missing(mem + ps));
        mprotect(mem, 2 * ps, RW);
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        // SAFETY: filled just now.
        assert_eq!(unsafe { ptr::read_volatile(mem as *const u8) }, 0x5a);
        assert_eq!(prot_of(mem) & RW, RW);
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        close(&[ua]);
    }

    /// Unregistered, a missing page gets the protection asked of it, as a
    /// Linux page has its vma's once no userfaultfd has it.
    #[test]
    fn test_an_unregistered_page_takes_the_protection_asked_while_it_was_missing() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        register(a, mem, ps).unwrap();
        mprotect(mem, ps, libc::PROT_READ);
        assert_eq!(unregister(a, mem, ps), Ok(()));
        assert_eq!(prot_of(mem) & RW, libc::PROT_READ);
        close(&[ua]);
    }

    /// Released with its userfaultfd, a missing page gets the protection
    /// asked of it, as a Linux page has its vma's once the userfaultfd is
    /// gone: its release (fs/userfaultfd.c, v6.12, `userfaultfd_release`
    /// :856) clears each vma with mm/userfaultfd.c `userfaultfd_clear_vma`
    /// :1797, whose new flags drop only `__VM_UFFD_FLAGS` (:1810).
    #[test]
    fn test_a_released_page_takes_the_protection_asked_while_it_was_missing() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        register(a, mem, ps).unwrap();
        mprotect(mem, ps, libc::PROT_READ);
        assert_eq!(prot_of(mem) & RW, 0, "a missing page is not accessible");
        close(&[ua]);
        // The release is the serving thread's, once it sees the close.
        let until = Instant::now() + Duration::from_secs(10);
        while slots(mem, mem + ps).next().is_some() {
            assert!(Instant::now() < until, "the userfaultfd was not released in 10 s");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(prot_of(mem) & RW, libc::PROT_READ);
    }

    /// A host access to a missing page that the protection asked of it
    /// refuses is the process's own fault, with no event, as on Linux, whose
    /// fault handler refuses it before the userfaultfd is asked
    /// ([`asked_allows`]); one it allows faults to the
    /// userfaultfd (the control). Each case in a child, which a refused
    /// access ends by its signal.
    #[test]
    fn test_a_registered_page_its_protection_denies_is_no_userfault() {
        const CASE: &str = "WICK_UFFD_ASKED_CASE";
        // (case, protection asked, the access writes, refused)
        const CASES: [(&str, c_int, bool, bool); 3] = [
            ("none", libc::PROT_NONE, false, true),
            ("read-only", libc::PROT_READ, true, true),
            ("allowed", libc::PROT_READ, false, false),
        ];
        let Some(case) = std::env::var_os(CASE) else {
            for (name, _, _, refused) in CASES {
                let out = {
                    let _spawning = crate::timerfd::spawning();
                    std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "wick_uffd::tests::test_a_registered_page_its_protection_denies_is_no_userfault",
                            "--exact",
                            "--test-threads=1",
                            "--nocapture",
                        ])
                        .env(CASE, name)
                        .output()
                        .unwrap()
                };
                let text = std::format!(
                    "{name}: {:?}\n{}{}",
                    out.status,
                    std::string::String::from_utf8_lossy(&out.stdout),
                    std::string::String::from_utf8_lossy(&out.stderr)
                );
                use std::os::unix::process::ExitStatusExt;
                if refused {
                    let sig = out.status.signal();
                    assert!(sig == Some(libc::SIGSEGV) || sig == Some(libc::SIGBUS), "{text}");
                    assert!(!text.contains("EVENT"), "{text}");
                } else {
                    assert!(out.status.success() && text.contains("EVENT"), "{text}");
                }
            }
            return;
        };
        let (_, prot, write, _) = CASES.iter().find(|c| case == c.0).copied().unwrap();
        // An access that waits for an event that never comes would hang:
        // the alarm's default action ends the child, which the parent sees.
        // SAFETY: plain alarm.
        unsafe { libc::alarm(10) };
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        register(a, mem, ps).unwrap();
        mprotect(mem, ps, prot);
        let handler = std::thread::spawn(move || {
            let mut event = [0u8; proto::RECORD];
            if read_full(ua, &mut event) {
                std::eprintln!("EVENT {:x?}", words(&event));
                assert_eq!(zeropage(a, mem, ps, true), Ok(ps));
            }
        });
        // SAFETY: a page of the test's mapping; a refused access ends the
        // process here.
        unsafe {
            if write {
                ptr::write_volatile(mem as *mut u8, 1);
            } else {
                ptr::read_volatile(mem as *const u8);
            }
        }
        handler.join().unwrap();
    }

    /// `MADV_FREE` of registered pages makes them missing, as Linux's does once
    /// it frees them (mm/madvise.c `madvise_free_single_vma`: a freed page's
    /// entry is cleared, and the next access faults to the userfaultfd);
    /// freeing at once is one of the outcomes Linux allows. Passed to macOS
    /// as it is, its `MADV_FREE` (5) frees lazily and the page reads zeros
    /// later with no fault.
    #[test]
    fn test_madv_free_of_registered_pages_makes_them_missing() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(1);
        let data = std::vec![0x5au8; ps as usize];
        register(a, mem, ps).unwrap();
        // SAFETY: `data` holds a page.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, ps, true) }, Ok(ps));
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, ps as usize, libc::MADV_FREE) };
        assert_eq!(r, 0);
        assert!(is_missing(mem), "MADV_FREE left a registered page present");
        assert_eq!(unregister(a, mem, ps), Ok(()));
        close(&[ua]);
    }

    /// `MADV_FREE` takes the pieces of its range in order, as Linux walks
    /// the vmas (v6.12 mm/madvise.c `madvise_walk_vmas`): private anonymous
    /// memory is freed (here at once: missing, with its remove event); shared
    /// memory is `EINVAL` after its remove event (`madvise_dontneed_free`
    /// :894 posts it through `userfaultfd_remove`, then
    /// `madvise_free_single_vma` :797 refuses a vma that is not anonymous),
    /// its pages as they were; the events in address order.
    #[test]
    fn test_madv_free_of_registered_shared_memory_is_einval_after_its_remove_event() {
        let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        // SAFETY: shared memory over the test's second and third pages.
        let shared = unsafe {
            libc::mmap(
                (mem + ps) as *mut _,
                (2 * ps) as usize,
                RW,
                libc::MAP_SHARED | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        assert_eq!(shared as u64, mem + ps);
        register(a, mem, 3 * ps).unwrap();
        let data = std::vec![0x5au8; 2 * ps as usize];
        // SAFETY: `data` holds two pages.
        assert_eq!(unsafe { copy(a, data.as_ptr(), mem, 2 * ps, true) }, Ok(2 * ps));
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, (3 * ps) as usize, libc::MADV_FREE) };
        assert_eq!((r, io::Error::last_os_error().raw_os_error()), (-1, Some(libc::EINVAL)));
        let mut rec = [0u8; proto::RECORD];
        assert!(readable(ua) && read_full(ua, &mut rec), "no event");
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem, mem + ps], "the private page's event");
        assert!(readable(ua) && read_full(ua, &mut rec), "no event for the refused shared pages");
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem + ps, mem + 3 * ps], "the shared pages' event");
        assert!(is_missing(mem), "the private page was not freed");
        assert!(!is_missing(mem + ps), "the refused shared page was discarded");
        // SAFETY: present, as before the call.
        assert_eq!(unsafe { ptr::read_volatile((mem + ps) as *const u8) }, 0x5a);
        assert!(is_missing(mem + 2 * ps));
        assert_eq!(prot_of(mem + 2 * ps) & RW, 0, "a missing page left accessible");
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        close(&[ua]);
        // SAFETY: the test's mapping.
        unsafe { libc::munmap(mem as *mut _, (3 * ps) as usize) };
    }

    /// Shared memory for the `MADV_FREE` tests below: `pages` pages of one
    /// `MAP_SHARED` anonymous mapping.
    fn map_shared(pages: u64) -> u64 {
        init().unwrap();
        // SAFETY: a fresh shared anonymous mapping.
        let p = unsafe {
            libc::mmap(ptr::null_mut(), (pages * test_page_size()) as usize, RW, libc::MAP_SHARED | libc::MAP_ANON, -1, 0)
        };
        assert_ne!(p, libc::MAP_FAILED);
        p as u64
    }

    /// Whether `fd` stays with nothing to read for 200 ms.
    fn nothing_to_read(fd: c_int) -> bool {
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd.
        unsafe { libc::poll(&mut p, 1, 200) == 0 }
    }

    /// `MADV_FREE` of shared memory whose two halves two userfaultfds have
    /// registered: `EINVAL`, and a remove event for the first half only, to
    /// its userfaultfd. Linux's walk of the vmas stops at the first error
    /// (mm/madvise.c, v6.12, `madvise_walk_vmas` :1275 to :1276), and the
    /// halves are two vmas, as vmas of different userfaultfd contexts do not
    /// merge (mm/vma.c `is_mergeable_vma` :28): the first gets its event
    /// (`userfaultfd_remove`, :894) and is refused (:797); the second is not
    /// reached.
    #[test]
    fn test_madv_free_refused_over_two_userfaultfds_posts_one_event() {
        let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let (b, ub) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let mem = map_shared(4);
        register(a, mem, 2 * ps).unwrap();
        register(b, mem + 2 * ps, 2 * ps).unwrap();
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, (4 * ps) as usize, libc::MADV_FREE) };
        assert_eq!((r, io::Error::last_os_error().raw_os_error()), (-1, Some(libc::EINVAL)));
        let mut rec = [0u8; proto::RECORD];
        assert!(readable(ua) && read_full(ua, &mut rec), "no event for the first half");
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem, mem + 2 * ps]);
        assert!(nothing_to_read(ua), "a second event for the first userfaultfd");
        assert!(nothing_to_read(ub), "an event for the second half, which Linux's walk does not reach");
        assert_eq!(unregister(a, mem, 2 * ps), Ok(()));
        assert_eq!(unregister(b, mem + 2 * ps, 2 * ps), Ok(()));
        close(&[ua, ub]);
        // SAFETY: the test's mapping.
        unsafe { libc::munmap(mem as *mut _, (4 * ps) as usize) };
    }

    /// `MADV_FREE` of shared memory whose first page no userfaultfd has
    /// registered and the rest one has: `EINVAL` with no remove event, as
    /// Linux's first vma has no context (`userfaultfd_remove` posts nothing,
    /// fs/userfaultfd.c, v6.12, :777 to :779) and is refused (mm/madvise.c
    /// :797), where the walk stops (:1275 to :1276).
    #[test]
    fn test_madv_free_refused_from_an_unregistered_page_posts_no_event() {
        let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let mem = map_shared(3);
        register(a, mem + ps, 2 * ps).unwrap();
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, (3 * ps) as usize, libc::MADV_FREE) };
        assert_eq!((r, io::Error::last_os_error().raw_os_error()), (-1, Some(libc::EINVAL)));
        assert!(nothing_to_read(ua), "an event for a vma Linux's walk does not reach");
        assert!(is_missing(mem + ps) && is_missing(mem + 2 * ps));
        assert_eq!(unregister(a, mem + ps, 2 * ps), Ok(()));
        close(&[ua]);
        // SAFETY: the test's mapping.
        unsafe { libc::munmap(mem as *mut _, (3 * ps) as usize) };
    }

    /// `MADV_FREE` of a huge page mapping is `EINVAL` with no remove event,
    /// as Linux refuses it for a hugetlb vma before `userfaultfd_remove`
    /// (v6.12 mm/madvise.c `madvise_dontneed_free_valid_vma` :864, checked
    /// at :888); its pages are as they were. The same without a userfaultfd.
    #[test]
    fn test_madv_free_of_a_huge_page_mapping_is_einval_with_no_remove_event() {
        use crate::linux_items::{HUGE_PAGE, MAP_HUGETLB, MAP_HUGE_2MB};
        let _alone = huge_mapping_test();
        let (a, ua) = create(FEATURE_EVENT_REMOVE, true, true).unwrap();
        let len = 2 * HUGE_PAGE;
        // SAFETY: a huge page mapping of the compatibility mmap, unmapped at the end.
        let mem = unsafe {
            crate::linux_items::mmap(
                ptr::null_mut(),
                len as usize,
                RW,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGETLB | MAP_HUGE_2MB,
                -1,
                0,
            )
        } as u64;
        assert_ne!(mem, libc::MAP_FAILED as u64);
        let free = |at: u64, len: u64| {
            // SAFETY: the test's mapping.
            let r = unsafe { crate::linux_items::madvise(at as *mut _, len as usize, libc::MADV_FREE) };
            (r, io::Error::last_os_error().raw_os_error())
        };
        // SAFETY: the test's mapping, not registered yet.
        unsafe { ptr::write_volatile((mem + HUGE_PAGE) as *mut u8, 7) };
        assert_eq!(free(mem + HUGE_PAGE, HUGE_PAGE), (-1, Some(libc::EINVAL)), "unregistered");
        // SAFETY: as above.
        assert_eq!(unsafe { ptr::read_volatile((mem + HUGE_PAGE) as *const u8) }, 7);
        register(a, mem, len).unwrap();
        let page = std::vec![3u8; HUGE_PAGE as usize];
        // SAFETY: `page` holds a huge page.
        assert_eq!(unsafe { copy(a, page.as_ptr(), mem, HUGE_PAGE, true) }, Ok(HUGE_PAGE));
        assert_eq!(free(mem, len), (-1, Some(libc::EINVAL)), "registered");
        let mut p = libc::pollfd { fd: ua, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd; events are posted before the call returns.
        assert_eq!(unsafe { libc::poll(&mut p, 1, 0) }, 0, "a remove event was posted");
        assert!(!is_missing(mem) && is_missing(mem + HUGE_PAGE));
        // SAFETY: filled above.
        assert_eq!(unsafe { ptr::read_volatile((mem + 5) as *const u8) }, 3);
        assert_eq!(unregister(a, mem, len), Ok(()));
        close(&[ua]);
        // SAFETY: the mapping made above, through the compatibility munmap
        // (see test_huge_page_ranges_fault_and_fill_whole_pages).
        assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut _, len as usize) }, 0);
    }

    /// The remove events of one discard go out in address order, as Linux's
    /// walk of the vmas posts them, whatever order the ranges were
    /// registered in.
    #[test]
    fn test_the_remove_events_of_one_discard_go_out_in_address_order() {
        let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        register(a, mem + 2 * ps, ps).unwrap();
        register(a, mem, ps).unwrap();
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::madvise(mem as *mut _, (3 * ps) as usize, libc::MADV_DONTNEED) };
        assert_eq!(r, 0);
        let mut rec = [0u8; proto::RECORD];
        assert!(readable(ua) && read_full(ua, &mut rec), "no event");
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem, mem + ps]);
        assert!(readable(ua) && read_full(ua, &mut rec), "no second event");
        assert_eq!(words(&rec)[..3], [proto::EVENT_REMOVE, mem + 2 * ps, mem + 3 * ps]);
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        close(&[ua]);
    }

    /// A discard posts one remove event a vma, as Linux's walk calls
    /// `userfaultfd_remove` once for each vma it reaches (mm/madvise.c, v6.12,
    /// `madvise_walk_vmas` :1233, its call of each vma at :1274, `madvise_dontneed_free` :894), and
    /// none for a vma with no userfaultfd (fs/userfaultfd.c :777 to :779). The
    /// vmas here are those Linux would have: a page unregistered from the
    /// middle splits the vma (`userfaultfd_unregister` :1413), and so does a
    /// protection asked of part of it (mm/mprotect.c `mprotect_fixup` :603);
    /// two registers of adjacent memory by one userfaultfd leave one vma, as
    /// the second merges with the first (mm/vma.c `is_mergeable_vma` :24 and
    /// :28 hold).
    #[test]
    fn test_a_discard_posts_one_remove_event_a_vma() {
        let (a, ua) = create(FEATURE_EVENT_REMOVE, false, true).unwrap();
        let ps = test_page_size();
        let events = |mem: u64, len: u64| {
            // SAFETY: the test's mapping.
            let r = unsafe { crate::linux_items::madvise(mem as *mut _, len as usize, libc::MADV_DONTNEED) };
            assert_eq!(r, 0);
            let mut got = Vec::new();
            let mut rec = [0u8; proto::RECORD];
            while !nothing_to_read(ua) {
                assert!(read_full(ua, &mut rec));
                let w = words(&rec);
                assert_eq!(w[0], proto::EVENT_REMOVE);
                got.push((w[1] - mem, w[2] - mem));
            }
            got
        };
        // A page unregistered from the middle: two vmas registered, one not.
        let mem = map(4);
        register(a, mem, 4 * ps).unwrap();
        assert_eq!(unregister(a, mem + ps, ps), Ok(()));
        assert_eq!(events(mem, 4 * ps), [(0, ps), (2 * ps, 4 * ps)], "a page unregistered from the middle");
        assert_eq!(unregister(a, mem, 4 * ps), Ok(()));
        // Two registers of adjacent memory: one vma.
        let mem = map(4);
        register(a, mem, 2 * ps).unwrap();
        register(a, mem + 2 * ps, 2 * ps).unwrap();
        assert_eq!(events(mem, 4 * ps), [(0, 4 * ps)], "two registers of adjacent memory");
        assert_eq!(unregister(a, mem, 4 * ps), Ok(()));
        // A protection asked of the third page: three vmas.
        let mem = map(4);
        register(a, mem, 4 * ps).unwrap();
        // SAFETY: the test's mapping.
        let r = unsafe { crate::linux_items::mprotect((mem + 2 * ps) as *mut _, ps as usize, libc::PROT_READ) };
        assert_eq!(r, 0);
        let want = [(0, 2 * ps), (2 * ps, 3 * ps), (3 * ps, 4 * ps)];
        assert_eq!(events(mem, 4 * ps), want, "a protection asked of the third page");
        assert_eq!(unregister(a, mem, 4 * ps), Ok(()));
        close(&[ua]);
    }

    /// An unregister of part of a range leaves the rest registered.
    #[test]
    fn test_a_partial_unregister_keeps_the_rest_registered() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        register(a, mem, 3 * ps).unwrap();
        assert_eq!(unregister(a, mem + ps, ps), Ok(()));
        assert!(is_missing(mem) && !is_missing(mem + ps) && is_missing(mem + 2 * ps));
        assert_eq!(zeropage(a, mem + 2 * ps, ps, true), Ok(ps));
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        close(&[ua]);
    }

    /// A fill whose destination holds a page in no registration is `ENOENT`
    /// for the whole call, a page unregistered from the middle of a range
    /// included, as Linux's destination must lie in one vma this userfaultfd
    /// has (mm/userfaultfd.c, v6.12, `validate_dst_vma` :23 to :37,
    /// `uffd_mfill_lock` :113): the unregister split the vma. Before, such a
    /// page was `EEXIST`, and a fill across it filled the pages before it.
    #[test]
    fn test_a_fill_of_an_unregistered_page_is_enoent() {
        let (a, ua) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        register(a, mem, 3 * ps).unwrap();
        assert_eq!(unregister(a, mem + ps, ps), Ok(()));
        assert_eq!(zeropage(a, mem + ps, ps, true), Err((libc::ENOENT, 0)), "the unregistered page");
        assert_eq!(zeropage(a, mem, 3 * ps, true), Err((libc::ENOENT, 0)), "a fill across it");
        assert!(is_missing(mem) && is_missing(mem + 2 * ps), "a refused fill filled a page");
        assert_eq!(zeropage(a, mem, ps, true), Ok(ps));
        assert_eq!(unregister(a, mem, 3 * ps), Ok(()));
        close(&[ua]);
    }

    /// Not Linux's: a private file mapping is registered, where Linux's
    /// `vma_can_userfault` refuses it (`EINVAL`), as a memfd here is a file
    /// and Linux takes a memfd's mappings (shmem).
    #[test]
    fn test_register_takes_a_private_file_mapping() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let path = std::env::temp_dir().join(std::format!("wick-uffd-file-{}", std::process::id()));
        let file = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file.set_len(2 * ps).unwrap();
        // SAFETY: a private mapping of the file above.
        let mem = unsafe {
            libc::mmap(
                ptr::null_mut(),
                (2 * ps) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                std::os::fd::AsRawFd::as_raw_fd(&file),
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED);
        register(ctx, mem as u64, 2 * ps).unwrap();
        assert_eq!(zeropage(ctx, mem as u64, 2 * ps, true), Ok(2 * ps));
        assert_eq!(unregister(ctx, mem as u64, 2 * ps), Ok(()));
        close(&[user]);
    }

    #[test]
    fn test_register_needs_read_write_memory() {
        // Fills write through a view of the memory, whose maximum
        // protection the view has (`fill_view`).
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(3);
        for (page, prot) in [(1, libc::PROT_NONE), (2, libc::PROT_READ)] {
            // SAFETY: a page of the mapping above.
            let r = unsafe { libc::mprotect((mem + page * ps) as *mut _, ps as usize, prot) };
            assert_eq!(r, 0);
            let e = register(ctx, mem, (page + 1) * ps).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{prot}");
            let e = register(ctx, mem + page * ps, ps).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{prot}");
        }
        register(ctx, mem, ps).unwrap();
        assert_eq!(zeropage(ctx, mem, ps, true), Ok(ps));
        close(&[user]);
    }

    /// Whether `addr` is in a VM map entry.
    fn is_mapped(addr: u64) -> bool {
        const VM_REGION_BASIC_INFO_64: c_int = 9;
        let (mut at, mut size, mut object) = (addr, 0u64, 0);
        let mut info = [0 as c_int; 16];
        let mut count = 9u32;
        // SAFETY: valid output buffers, as `mapped_entries`.
        let kr = unsafe {
            mach_vm_region(
                mach_task_self_,
                &mut at,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                info.as_mut_ptr(),
                &mut count,
                &mut object,
            )
        };
        kr == 0 && at <= addr && addr < at + size
    }

    /// The process's VM map entries (task_info TASK_VM_INFO's region_count,
    /// mach/task_info.h: the 32-bit word 2).
    fn region_count() -> u64 {
        const TASK_VM_INFO: c_int = 22;
        unsafe extern "C" {
            fn task_info(task: libc::mach_port_t, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
        }
        let mut info = [0 as c_int; 128];
        let mut count = 128u32;
        // SAFETY: a buffer of `count` words for this flavour, of this task.
        assert_eq!(unsafe { task_info(mach_task_self_, TASK_VM_INFO, info.as_mut_ptr(), &mut count) }, 0);
        info[2] as u64
    }

    /// 64 MiB of registered memory filled a page at a time, in a random
    /// order, leaves the map as it found it: the range one entry or a few
    /// (its pages all read and write again, which XNU merges), and the
    /// process's entries where they were, give or take a few made by other
    /// tests' threads, since each fill's view is gone. A fill that left its
    /// view (the alias's way) adds an entry a fill, 4096 here; a range whose
    /// entries stayed split adds one a page. Measured on an M1 Pro, macOS
    /// 27.2, before this test: 32588 entries in a 1 GiB range halfway through
    /// such fills, 8 after. In a process of its own, so that no other test
    /// maps memory meanwhile.
    #[test]
    fn test_fills_in_a_random_order_leave_the_map_as_they_found_it() {
        if !in_own_process("wick_uffd::tests::test_fills_in_a_random_order_leave_the_map_as_they_found_it") {
            return;
        }
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let pages = (64 << 20) / ps;
        let mem = map(pages);
        register(ctx, mem, pages * ps).unwrap();
        let before = region_count();
        let data = std::vec![0x5au8; ps as usize];
        // Every page once, in the order of a full-period LCG (a = 5, c = 1
        // modulo a power of two).
        let mut i = 0u64;
        for _ in 0..pages {
            i = (5 * i + 1) % pages;
            // SAFETY: `data` holds a page.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), mem + i * ps, ps, false) }, Ok(ps));
        }
        let entries = mapped_entries(mem, mem + pages * ps).len();
        let after = region_count();
        std::println!("ENTRIES: the range {entries}, the process {before} -> {after}");
        assert!((0..pages).all(|p| !is_missing(mem + p * ps)), "a page left missing");
        assert!(entries <= 8, "the range is {entries} entries after its fills");
        assert!(after <= before + 16, "the process went from {before} to {after} entries");
        close(&[user]);
    }

    /// A fill writes through a view of the pages of its own, read-write and
    /// outside the range, while the pages stay missing and `PROT_NONE` in
    /// the range, so a thread that reads them meanwhile waits and never
    /// sees a page half written, as on Linux, where `UFFDIO_COPY` maps the
    /// page only once it is copied (v6.12 mm/userfaultfd.c
    /// `mfill_atomic_pte_copy` :302, `mfill_atomic_install_pte`); the view
    /// is gone once the fill is done, so the pages are mapped, and charged,
    /// once ([`test_a_filled_page_is_charged_once`]). Through `copy`'s and
    /// `zeropage`'s own `fill`, with a writer that checks halfway, of a
    /// page of data and of zeros.
    #[test]
    fn test_a_fill_writes_through_a_view_that_goes_with_it() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        for (page, byte) in [(0u64, 0x5au8), (1, 0)] {
            let dst = mem + page * ps;
            let reader = std::thread::spawn(move || {
                // SAFETY: registered memory: the read waits for the fill.
                unsafe { ptr::read_volatile((dst + ps - 1) as *const u8) }
            });
            until("the reader's wait", || WAITERS.iter().any(|w| w.page.load(Ordering::SeqCst) == dst));
            let mut view = 0u64;
            let r = fill(ctx, dst, ps, true, |to, n, _| {
                view = to as u64;
                assert!(view + n as u64 <= mem || view >= mem + 2 * ps, "the view {view:#x} is in the range");
                assert_eq!(prot_of(view), libc::PROT_READ | libc::PROT_WRITE);
                // SAFETY: the view, `n` bytes.
                unsafe { ptr::write_bytes(to, byte, n / 2) };
                assert!(is_missing(dst), "the page is not missing halfway through its fill");
                assert_eq!(prot_of(dst), libc::PROT_NONE, "the page is reachable halfway through its fill");
                std::thread::sleep(Duration::from_millis(20));
                assert!(!reader.is_finished(), "a read went on halfway through the fill");
                // SAFETY: as above.
                unsafe { ptr::write_bytes(to.add(n / 2), byte, n - n / 2) };
            });
            assert_eq!(r, Ok(ps));
            assert_ne!(view, 0, "the fill wrote nothing");
            assert!(!is_mapped(view), "the view {view:#x} outlived its fill");
            assert_eq!(reader.join().unwrap(), byte);
            assert!(!is_missing(dst));
        }
        close(&[user]);
    }

    #[test]
    fn test_copy_from_a_handler() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        // More than two pieces of copied data.
        let pages = (2 << 20) / ps + 3;
        let mem = map(pages);
        register(ctx, mem, pages * ps).unwrap();
        let chan = channel(user);
        // Data for memory that is not registered is read and refused: the
        // next request is understood.
        let elsewhere = map(3);
        let data = std::vec![7u8; (3 * ps) as usize];
        let head = [proto::OP_COPY, elsewhere, 3 * ps, 0];
        assert_eq!(request(chan, head, &data), (err(libc::ENOENT), 0));
        // A page in the last piece is present: the copy stops there.
        let present = pages - 2;
        assert_eq!(zeropage(ctx, mem + present * ps, ps, true), Ok(ps));
        let data: Vec<u8> = (0..pages * ps).map(|i| (i / ps) as u8).collect();
        let head = [proto::OP_COPY, mem, pages * ps, 0];
        let partial = (err(libc::EAGAIN), present * ps);
        assert_eq!(request(chan, head, &data), partial);
        for p in 0..pages {
            let expect = match p {
                p if p < present => p as u8,
                p if p == present => 0,
                _ => {
                    assert!(is_missing(mem + p * ps), "page {p}");
                    continue;
                }
            };
            // SAFETY: a filled page.
            let got = unsafe { ptr::read_volatile((mem + p * ps + 5) as *const u8) };
            assert_eq!(got, expect, "page {p}");
        }
        // Present from the first page on: EEXIST.
        let page = &data[..ps as usize];
        let exists = (err(libc::EEXIST), 0);
        assert_eq!(request(chan, [proto::OP_COPY, mem, ps, 0], page), exists);
        let last = mem + (pages - 1) * ps;
        let whole = (ps as i64, ps);
        assert_eq!(request(chan, [proto::OP_COPY, last, ps, 0], page), whole);
        // A length no data follows: the channel closes, the userfaultfd stays.
        assert!(write_full(chan, &record([proto::OP_COPY, mem, 1 << 62, 0])));
        close(&[chan]);
        let chan = channel(user);
        assert_eq!(request(chan, [proto::OP_WAKE, mem, ps, 0], &[]), (0, 0));
        close(&[chan, user]);
    }

    /// A discard of registered memory replaces its pages
    /// (`linux_items::discard_piece`): a copy after the discard lands in the
    /// pages the memory now has, not in the old ones (which would also have
    /// kept the old pages resident).
    #[test]
    fn test_discarded_pages_are_filled_in_the_new_pages() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(4);
        register(ctx, mem, 4 * ps).unwrap();
        let page = mem + ps;
        let read = || {
            // SAFETY: a filled page.
            unsafe { ptr::read_volatile((page + 5) as *const u8) }
        };
        for (fill, expect) in [(0x11u8, 0x11u8), (0x22, 0x22)] {
            let data = std::vec![fill; ps as usize];
            // SAFETY: `data` holds a page; `page` is a missing page of the range.
            assert_eq!(unsafe { copy(ctx, data.as_ptr(), page, ps, true) }, Ok(ps));
            assert!(!is_missing(page));
            assert_eq!(read(), expect, "copy of {fill:#x}");
            // Missing again, with fresh pages; the copy above lands in them.
            // SAFETY: one page of the mapping, through the compatibility madvise.
            assert_eq!(unsafe { crate::linux_items::madvise(page as *mut _, ps as usize, libc::MADV_DONTNEED) }, 0);
            assert!(is_missing(page));
        }
        close(&[user]);
    }

    /// A huge page mapping is registered in huge pages (docs/PORTING.md
    /// row 10): a fault anywhere in one reports its address and waits for
    /// the whole page; a copy must be aligned to huge pages and fills a
    /// whole one; the other huge pages stay missing; a discard must start
    /// on a huge page and its end is rounded down to one, as Linux's.
    #[test]
    fn test_huge_page_ranges_fault_and_fill_whole_pages() {
        use crate::linux_items::{HUGE_PAGE, MAP_HUGETLB, MAP_HUGE_2MB};
        let _alone = huge_mapping_test();
        let (ctx, user) = create(0, false, true).unwrap();
        let host = test_page_size();
        let len = 3 * HUGE_PAGE;
        // SAFETY: a huge page mapping of the compatibility mmap, unmapped at the end.
        let mem = unsafe {
            crate::linux_items::mmap(
                ptr::null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_HUGETLB | MAP_HUGE_2MB,
                -1,
                0,
            )
        } as u64;
        assert_ne!(mem, libc::MAP_FAILED as u64);
        // Aligned to host pages, not to huge ones: refused.
        let refused = register(ctx, mem + host, len - host).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EINVAL));
        register(ctx, mem, len).unwrap();
        for off in [0, host, HUGE_PAGE - host, HUGE_PAGE, 2 * HUGE_PAGE + 5 * host] {
            assert!(is_missing(mem + off), "{off:#x}");
        }
        let mut runs = Vec::new();
        for_each_missing(mem + host, len - 2 * host, |s, l| runs.push((s, l)));
        assert_eq!(runs, std::vec![(mem, len)], "whole huge pages");
        let chan = channel(user);
        // A copy aligned to host pages only: EINVAL, as Linux's hugetlb.
        let page = std::vec![3u8; HUGE_PAGE as usize];
        let short = (err(libc::EINVAL), 0);
        assert_eq!(request(chan, [proto::OP_COPY, mem + host, HUGE_PAGE, 0], &page), short);
        assert_eq!(request(chan, [proto::OP_COPY, mem, host, 0], &page[..host as usize]), short);
        // A read in the middle of the second huge page: the event names the
        // address, and the reader waits until the whole page is filled.
        let at = mem + HUGE_PAGE + 3 * host + 9;
        let reader = std::thread::spawn(move || {
            // SAFETY: registered memory; the fault is served below.
            unsafe { ptr::read_volatile(at as *const u8) }
        });
        assert!(readable(user), "no page fault event");
        let mut rec = [0u8; proto::RECORD];
        assert!(read_full(user, &mut rec));
        assert_eq!(words(&rec)[..3], [proto::EVENT_PAGEFAULT, at, 0]);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!reader.is_finished(), "the reader went on before the fill");
        let whole = (HUGE_PAGE as i64, HUGE_PAGE);
        assert_eq!(request(chan, [proto::OP_COPY, mem + HUGE_PAGE, HUGE_PAGE, 0], &page), whole);
        assert_eq!(reader.join().unwrap(), 3);
        for off in [HUGE_PAGE, HUGE_PAGE + host, 2 * HUGE_PAGE - 1] {
            assert!(!is_missing(mem + off), "{off:#x}");
            // SAFETY: a filled page.
            assert_eq!(unsafe { ptr::read_volatile((mem + off) as *const u8) }, 3);
        }
        for off in [0, HUGE_PAGE - 1, 2 * HUGE_PAGE, 3 * HUGE_PAGE - 1] {
            assert!(is_missing(mem + off), "{off:#x}");
        }
        // Filled: EEXIST for the whole page.
        let exists = (err(libc::EEXIST), 0);
        assert_eq!(request(chan, [proto::OP_COPY, mem + HUGE_PAGE, HUGE_PAGE, 0], &page), exists);
        // Discards as Linux's hugetlb takes them (mm/madvise.c
        // madvise_dontneed_free_valid_vma): a start off the huge page is
        // EINVAL, an end inside it is rounded down (here to nothing), and
        // the page keeps its contents; a whole huge page is missing again.
        let dontneed = |at: u64, len: u64| {
            // SAFETY: registered memory.
            unsafe { crate::linux_items::madvise(at as *mut _, len as usize, libc::MADV_DONTNEED) }
        };
        assert_eq!(dontneed(mem + HUGE_PAGE + host, host), -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINVAL));
        assert_eq!(dontneed(mem + HUGE_PAGE, HUGE_PAGE - host), 0);
        for off in [HUGE_PAGE, HUGE_PAGE + host, 2 * HUGE_PAGE - 1] {
            assert!(!is_missing(mem + off), "{off:#x}");
            // SAFETY: a filled page.
            assert_eq!(unsafe { ptr::read_volatile((mem + off) as *const u8) }, 3);
        }
        assert_eq!(dontneed(mem + HUGE_PAGE, HUGE_PAGE + host), 0, "{}", io::Error::last_os_error());
        for off in [HUGE_PAGE, HUGE_PAGE + host, 2 * HUGE_PAGE - 1] {
            assert!(is_missing(mem + off), "{off:#x}");
        }
        assert_eq!(request(chan, [proto::OP_ZEROPAGE, mem + HUGE_PAGE, HUGE_PAGE, 0], &[]), whole);
        // SAFETY: a page zeroed again.
        assert_eq!(unsafe { ptr::read_volatile((mem + HUGE_PAGE + host) as *const u8) }, 0);
        unregister(ctx, mem, len).unwrap();
        close(&[chan, user]);
        // SAFETY: the mapping made above, through the compatibility munmap,
        // which forgets the huge mapping (the system's would leave it in
        // HUGE_MAPPINGS, where another test's mapping at that address then
        // reads as huge).
        assert_eq!(unsafe { crate::linux_items::munmap(mem as *mut _, len as usize) }, 0);
    }

    /// A system call that copies to or from missing registered pages waits
    /// for the handler to fill them and then completes, as Linux's
    /// `copy_to_user` and `copy_from_user` do for a userfaultfd made with
    /// `user_mode_only(false)` (upstream's `persist.rs`): their fault goes
    /// through mm/memory.c `do_anonymous_page` to `handle_userfault`.
    /// macOS's own `read` into such a page fails with `EFAULT` instead.
    #[test]
    fn test_system_calls_wait_for_missing_pages() {
        let (ctx, user) = create(0, false, true).unwrap();
        let ps = test_page_size();
        let mem = map(2);
        register(ctx, mem, 2 * ps).unwrap();
        let chan = channel(user);
        let [r, w] = {
            let mut fds = [0; 2];
            // SAFETY: creates two descriptors.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            fds
        };
        let data = [0x22u8; 16];
        // SAFETY: 16 bytes into the pipe; then the plain call into a missing page.
        unsafe {
            assert_eq!(libc::write(w, data.as_ptr().cast(), 16), 16);
            assert_eq!(libc::read(r, (mem + 8) as *mut core::ffi::c_void, 16), -1);
        }
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EFAULT));
        // A read into the first page (the call writes the memory, a write
        // fault as on Linux), then a write from the second (a read fault):
        // each call waits for its page.
        let page = std::vec![0x11u8; ps as usize];
        let (into, from) = (mem + 8, mem + ps + 8);
        type Call = Box<dyn FnOnce() -> isize + Send>;
        let calls: [(u64, u64, Call); 2] = [
            (into, proto::FLAG_WRITE, Box::new(move || {
                // SAFETY: registered memory; the fault is served below.
                unsafe { syscalls::read(r, into as *mut core::ffi::c_void, 16) }
            })),
            (from, 0, Box::new(move || {
                // SAFETY: as above.
                unsafe { syscalls::write(w, from as *const core::ffi::c_void, 16) }
            })),
        ];
        for (at, flags, call) in calls {
            let call = std::thread::spawn(call);
            assert!(readable(user), "no page fault event for {at:#x}");
            let mut rec = [0u8; proto::RECORD];
            assert!(read_full(user, &mut rec));
            assert_eq!(words(&rec)[..3], [proto::EVENT_PAGEFAULT, at, flags]);
            std::thread::sleep(Duration::from_millis(50));
            assert!(!call.is_finished(), "the call went on before the fill");
            let base = at - at % ps;
            assert_eq!(request(chan, [proto::OP_COPY, base, ps, 0], &page), (ps as i64, ps));
            assert_eq!(call.join().unwrap(), 16);
        }
        // SAFETY: filled pages; the pipe holds what the write took.
        unsafe {
            assert_eq!(ptr::read_volatile(mem as *const u8), 0x11);
            assert_eq!(ptr::read_volatile(into as *const u8), 0x22);
            let mut back = [0u8; 16];
            assert_eq!(libc::read(r, back.as_mut_ptr().cast(), 16), 16);
            assert_eq!(back, [0x11u8; 16]);
        }
        unregister(ctx, mem, 2 * ps).unwrap();
        close(&[r, w, chan, user]);
    }

    /// Whether the peer of `fd` closed it, within five seconds.
    fn peer_closed(fd: c_int) -> bool {
        if !readable(fd) {
            return false;
        }
        let mut b = 0u8;
        // SAFETY: reads one byte.
        unsafe { libc::read(fd, (&mut b as *mut u8).cast(), 1) == 0 }
    }

    #[test]
    fn test_records_close_descriptors_not_kept() {
        let (_, user) = create(0, false, true).unwrap();
        // A record that is not a HELLO: its descriptor is closed.
        let [a, b] = socketpair();
        send_record(user, [0x99, 0, 0, 0], proto::RECORD, &[b]);
        // A HELLO with two: the first is the channel, the second is closed.
        let [c, d] = socketpair();
        let [e, f] = socketpair();
        send_record(user, [proto::HELLO, 0, 0, 0], proto::RECORD, &[d, f]);
        assert!(served(c));
        close(&[b, d, f]);
        assert!(peer_closed(a), "descriptor of a record not a HELLO kept");
        assert!(peer_closed(e), "second descriptor of a HELLO kept");
        assert!(served(c));
        close(&[a, c, e, user]);
    }

    unsafe extern "C" {
        fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> c_int;
    }

    /// Sends `sig` to every userfaultfd serving thread.
    fn signal_serving_threads(sig: c_int) {
        let mut list: libc::thread_act_array_t = ptr::null_mut();
        let mut count = 0;
        // SAFETY: lists this task's threads; the list and its ports are
        // released below.
        unsafe {
            let task = mach_task_self_;
            assert_eq!(libc::task_threads(task, &mut list, &mut count), 0);
            for i in 0..count as usize {
                let port = *list.add(i);
                let t = libc::pthread_from_mach_thread_np(port);
                let mut name = [0 as libc::c_char; 64];
                if t != 0 && libc::pthread_getname_np(t, name.as_mut_ptr(), name.len()) == 0 {
                    let name = core::ffi::CStr::from_ptr(name.as_ptr());
                    if name.to_bytes() == b"userfaultfd" {
                        libc::pthread_kill(t, sig);
                    }
                }
                mach_port_deallocate(task, port);
            }
            let size = count as usize * core::mem::size_of::<libc::thread_act_t>();
            libc::vm_deallocate(task, list as libc::vm_address_t, size as libc::vm_size_t);
        }
    }

    extern "C" fn ignore(_: c_int) {}

    #[test]
    fn test_signals_and_split_records() {
        // A handler that interrupts the serving threads' system calls.
        // SAFETY: installs a handler that does nothing, without SA_RESTART.
        unsafe {
            let mut act: libc::sigaction = core::mem::zeroed();
            act.sa_sigaction = ignore as *const () as usize;
            libc::sigemptyset(&mut act.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR2, &act, ptr::null_mut()), 0);
        }
        let (_, user) = create(0, false, true).unwrap();
        let [mine, theirs] = socketpair();
        // Half a HELLO, and signals while the serving thread waits for the rest.
        send_record(user, [proto::HELLO, 0, 0, 0], 16, &[theirs]);
        let until = Instant::now() + Duration::from_millis(200);
        while Instant::now() < until {
            signal_serving_threads(libc::SIGUSR2);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(write_full(user, &[0; 16]));
        // The HELLO arrived whole: the channel is served.
        assert!(served(mine));
        close(&[theirs, mine, user]);
    }
}
