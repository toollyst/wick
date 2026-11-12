// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Guest RAM as the backend itself reads and writes it, for what KVM writes
//! into the guest on its behalf (the kvm-clock structures, the clock pairing
//! hypercall's result): KVM's `kvm_read_guest`/`kvm_write_guest`
//! (virt/kvm/kvm_main.c). The guest names the address, so every byte is
//! checked: the access goes page by page, each page through the slot that
//! maps it (`gfn_to_hva_many`); a page no slot maps fails the access, and a
//! write to a read-only slot (`KVM_MEM_READONLY`) fails as KVM's
//! `KVM_HVA_ERR_RO_BAD` does; pages written before the failing one stay
//! written, as in KVM. A page written into a slot with dirty logging is
//! marked dirty (`mark_page_dirty_in_slot`): WHP's dirty bitmap only sees the
//! guest's own writes, so the slot keeps these and the dirty log adds them.
//!
//! No WHP call here: the module is plain memory arithmetic on the slot table,
//! tested on any Windows host.

use std::collections::HashMap;

/// The guest page size the slots and the dirty log use.
pub(crate) const PAGE: u64 = 4096;

/// One mapped guest-memory slot.
#[derive(Debug)]
pub(crate) struct Slot {
    pub(crate) guest_phys: u64,
    pub(crate) size: u64,
    /// The host address mapped at `guest_phys`.
    pub(crate) host: u64,
    /// `KVM_MEM_READONLY`.
    pub(crate) readonly: bool,
    pub(crate) log_dirty: bool,
    /// With `log_dirty`: pages the backend wrote since the last dirty log,
    /// one bit per page.
    pub(crate) host_dirty: Vec<u64>,
}

impl Slot {
    pub(crate) fn new(guest_phys: u64, size: u64, host: u64, readonly: bool, log_dirty: bool) -> Self {
        let pages = size.div_ceil(PAGE);
        let host_dirty = if log_dirty { vec![0; usize::try_from(pages.div_ceil(64)).unwrap()] } else { Vec::new() };
        Slot { guest_phys, size, host, readonly, log_dirty, host_dirty }
    }

    /// Whether `gpa` lies in this slot.
    fn holds(&self, gpa: u64) -> bool {
        gpa >= self.guest_phys && gpa - self.guest_phys < self.size
    }

    /// Takes the pages the backend wrote into `bitmap` (the dirty log of
    /// this slot, one bit per page) and clears them.
    pub(crate) fn take_host_dirty(&mut self, bitmap: &mut [u64]) {
        for (word, dirty) in bitmap.iter_mut().zip(self.host_dirty.iter_mut()) {
            *word |= *dirty;
            *dirty = 0;
        }
    }
}

/// Splits a guest access of `len` bytes at `gpa` into its pages and calls
/// `each(slot, gpa of the piece, its offset in the access, its length)` for
/// each, in order; false at the first page that no slot maps or, for a
/// write, that is in a read-only slot.
fn segments(
    slots: &mut HashMap<u32, Slot>,
    gpa: u64,
    len: usize,
    write: bool,
    mut each: impl FnMut(&mut Slot, u64, usize, usize),
) -> bool {
    let mut done = 0usize;
    while done < len {
        let Some(at) = gpa.checked_add(done as u64) else { return false };
        #[allow(clippy::cast_possible_truncation)]
        let seg = ((PAGE - at % PAGE) as usize).min(len - done);
        let Some(slot) = slots.values_mut().find(|s| s.holds(at)) else { return false };
        // A slot is whole pages (KVM refuses another size; WHvMapGpaRange
        // too); a slot whose end is not on a page boundary is still not
        // read or written past.
        if at - slot.guest_phys + seg as u64 > slot.size || (write && slot.readonly) {
            return false;
        }
        each(slot, at, done, seg);
        done += seg;
    }
    true
}

/// KVM's `kvm_write_guest`: writes `data` at `gpa`; false (KVM's `-EFAULT`)
/// at the first page that no slot maps or that is read-only.
pub(crate) fn write(slots: &mut HashMap<u32, Slot>, gpa: u64, data: &[u8]) -> bool {
    segments(slots, gpa, data.len(), true, |slot, at, from, seg| {
        let off = at - slot.guest_phys;
        // SAFETY: `off + seg` is within the slot (checked by `segments`), whose
        // host memory the slot's owner keeps mapped while it is registered;
        // the slot table is locked by the caller for the copy.
        unsafe { std::ptr::copy_nonoverlapping(data[from..].as_ptr(), (slot.host + off) as *mut u8, seg) };
        if slot.log_dirty {
            let page = usize::try_from(off / PAGE).unwrap();
            slot.host_dirty[page / 64] |= 1 << (page % 64);
        }
    })
}

// Read by the tests only until kvm-clock's wall clock reads its version
// through it.
#[allow(dead_code)]
/// KVM's `kvm_read_guest`: reads `buf.len()` bytes at `gpa`; false (KVM's
/// `-EFAULT`) at the first page that no slot maps.
pub(crate) fn read(slots: &mut HashMap<u32, Slot>, gpa: u64, buf: &mut [u8]) -> bool {
    segments(slots, gpa, buf.len(), false, |slot, at, from, seg| {
        let off = at - slot.guest_phys;
        // SAFETY: as in `write`.
        unsafe { std::ptr::copy_nonoverlapping((slot.host + off) as *const u8, buf[from..].as_mut_ptr(), seg) };
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two slots of `pages` pages each over `mem`: slot 0 at 0x10000 and
    /// slot 1 at 0x10000 + its size + `gap` pages.
    fn table(mem: &mut [u8], pages: u64, gap: u64, readonly1: bool, log_dirty: bool) -> HashMap<u32, Slot> {
        let size = pages * PAGE;
        let host = mem.as_mut_ptr() as u64;
        let mut t = HashMap::new();
        t.insert(0, Slot::new(0x10000, size, host, false, log_dirty));
        t.insert(1, Slot::new(0x10000 + size + gap * PAGE, size, host + size, readonly1, log_dirty));
        t
    }

    // The clock pairing hypercall's 64 bytes at an address the guest picks
    // within 63 bytes of a slot's end, with no slot after it: refused
    // (KVM: -KVM_EFAULT), and nothing past the slot is written. Before this
    // module the backend checked only the first byte and wrote past the
    // slot's host mapping.
    #[test]
    fn test_a_write_past_a_slots_end_is_refused_and_writes_nothing_after_it() {
        let mut mem = vec![0u8; 3 * PAGE as usize];
        let mut t = HashMap::new();
        t.insert(0, Slot::new(0x10000, 2 * PAGE, mem.as_mut_ptr() as u64, false, false));
        let end = 0x10000 + 2 * PAGE;
        assert!(!write(&mut t, end - 8, &[0xab; 64]));
        // The bytes past the slot (the third page of `mem`) are untouched.
        assert!(mem[2 * PAGE as usize..].iter().all(|&b| b == 0));
        // KVM writes the pages before the failing one: here the 8 bytes in
        // the slot's last page.
        assert!(mem[2 * PAGE as usize - 8..2 * PAGE as usize].iter().all(|&b| b == 0xab));
        // Wholly outside any slot, and past the end of the address space.
        assert!(!write(&mut t, end, &[1; 4]));
        assert!(!write(&mut t, u64::MAX - 3, &[1; 8]));
        assert!(!write(&mut t, 0, &[1; 1]));
    }

    // A write into a read-only slot is refused (KVM_HVA_ERR_RO_BAD), a read
    // of it is not; a write that runs from a writable slot into a
    // read-only one adjacent writes the first and stops at the second.
    #[test]
    fn test_a_read_only_slot_is_not_written() {
        let mut mem = vec![0u8; 2 * PAGE as usize];
        let mut t = table(&mut mem, 1, 0, true, false);
        let ro = 0x10000 + PAGE;
        mem[PAGE as usize] = 7;
        assert!(!write(&mut t, ro, &[1; 16]));
        assert_eq!(mem[PAGE as usize], 7);
        let mut b = [0u8; 1];
        assert!(read(&mut t, ro, &mut b));
        assert_eq!(b[0], 7);
        assert!(!write(&mut t, ro - 4, &[2; 8]));
        assert_eq!(&mem[PAGE as usize - 4..PAGE as usize], &[2; 4]);
        assert_eq!(mem[PAGE as usize], 7);
    }

    // Across two adjacent writable slots a write goes on page by page, as
    // KVM's does; across a hole it stops at the hole.
    #[test]
    fn test_a_write_crosses_adjacent_slots_but_not_a_hole() {
        let mut mem = vec![0u8; 2 * PAGE as usize];
        let mut t = table(&mut mem, 1, 0, false, false);
        let edge = 0x10000 + PAGE;
        let data: Vec<u8> = (0..64).collect();
        assert!(write(&mut t, edge - 32, &data));
        assert_eq!(&mem[PAGE as usize - 32..PAGE as usize + 32], &data[..]);
        let mut back = [0u8; 64];
        assert!(read(&mut t, edge - 32, &mut back));
        assert_eq!(&back[..], &data[..]);

        let mut mem = vec![0u8; 2 * PAGE as usize];
        let mut t = table(&mut mem, 1, 1, false, false);
        assert!(!write(&mut t, edge - 32, &data));
        assert!(!read(&mut t, edge - 32, &mut back));
    }

    // Pages the backend writes into a slot with dirty logging are in its
    // next dirty log, once (KVM's mark_page_dirty_in_slot); a slot without
    // dirty logging keeps nothing.
    #[test]
    fn test_backend_writes_are_in_the_dirty_log() {
        let mut mem = vec![0u8; 2 * PAGE as usize];
        let mut t = table(&mut mem, 1, 0, false, true);
        assert!(write(&mut t, 0x10000 + PAGE - 4, &[1; 8]));
        let mut log0 = [0u64; 1];
        let mut log1 = [0u64; 1];
        t.get_mut(&0).unwrap().take_host_dirty(&mut log0);
        t.get_mut(&1).unwrap().take_host_dirty(&mut log1);
        assert_eq!((log0[0], log1[0]), (1, 1));
        let mut again = [0u64; 1];
        t.get_mut(&0).unwrap().take_host_dirty(&mut again);
        assert_eq!(again[0], 0);
        // A read marks nothing.
        let mut b = [0u8; 4];
        assert!(read(&mut t, 0x10000, &mut b));
        t.get_mut(&0).unwrap().take_host_dirty(&mut again);
        assert_eq!(again[0], 0);

        let mut mem = vec![0u8; 2 * PAGE as usize];
        let mut t = table(&mut mem, 1, 0, false, false);
        assert!(write(&mut t, 0x10000, &[1; 8]));
        assert!(t[&0].host_dirty.is_empty());
    }
}
