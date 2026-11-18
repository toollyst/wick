// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `WHvTranslateGva` with the guest's page tables settled in the host.
//!
//! WHP walks the guest's page tables through the host memory behind guest
//! RAM, and it does not fault that memory in: where a table page is not
//! there for it the call fails with `ERROR_NOACCESS` (998, HRESULT
//! 0x800703E6), not a result code (TRANSLATEREC, CI run 44225041771): a
//! page missing in userfaultfd guest RAM (after a snapshot's restore), and
//! a chunk the reclaim is moving (its live pages closed, then a
//! placeholder, then its new section's view) or a register is moving (the
//! mapping read-only for the copy, then a placeholder); read-only fails a
//! walk that sets the accessed and dirty bits only. KVM's walk faults the
//! page in, through the same path as the guest's own access
//! (`kvm_read_guest_page` -> `__copy_from_user`, Linux v6.1
//! arch/x86/kvm/mmu/paging_tmpl.h `FNAME(walk_addr_generic)`), so on Linux
//! the translation waits for the userfaultfd's fill or the page's
//! migration and never fails for it. Each of the three translations the
//! backend makes goes through [`translate`]: the instruction emulator's
//! (`emulate::translate_cb`, MMIO), string port I/O's (`VcpuFd::gpa_of`)
//! and `KVM_TRANSLATE`'s (`VcpuFd::translate_gva`).
//!
//! [`translate`] calls `WHvTranslateGva`; on `ERROR_NOACCESS` alone it
//! walks the guest's tables itself, as the hardware would for the vCPU's
//! paging mode ([`walk`]), and does it under
//! `libc::wick_mm::with_pages_still` (the userfaultfd's lock, then the
//! region table's, the released ranges' and lazy memory's: no fill,
//! discard, move, register, release, `mprotect`, unmapping or mapping runs
//! meanwhile). The first table page that is not there for the access
//! (missing, in a move, lazy and not committed, a released range's pending
//! page) ends that look: with the locks dropped it is brought in as the
//! guest's own access would be ([`bring_in`]: committed, filled by the
//! userfaultfd's handler, or the move waited for), and the walk is made
//! again from the top. Once every table page the walk reads is there,
//! `WHvTranslateGva` is called again under the same locks, so nothing moves
//! between the look and the call: its answer is the walk's own (success,
//! or the guest's page fault). At most [`ATTEMPTS`] looks; past them, or if
//! a table page cannot be brought in (the host refuses it), the first
//! answer stands, with a line.
//!
//! The walk reads guest-controlled values: every entry's address is
//! checked against the slot table before it is read (a page no slot holds
//! ends the walk: `WHvTranslateGva`'s own answer then stands), at most five
//! entries a look are read, and only from pages the locks keep allowed.
//!
//! Lock order. The vCPU thread calls [`translate`] holding none of the
//! backend's locks (`held::none_held`, a debug assertion: the emulator's
//! callbacks run in `VcpuFd::emulate_mmio` before the irqchip or the
//! device writes are taken, and `mem_cb` takes the slot table for each
//! access alone; string I/O's `gpa_of` runs in `VcpuFd::string_io` with
//! none taken; `KVM_TRANSLATE` with none) and none of wick's. It takes the
//! slot table alone, to copy the slots, and drops it; then wick's locks in
//! their order (userfaultfd, region table, released ranges, lazy memory)
//! for a look and the call, which take no other lock and call back into
//! nothing; and waits ([`bring_in`]) holding none.

use super::held;
use super::whv::{self, WHV_PARTITION_HANDLE, WHV_TRANSLATE_GVA_FLAGS, WHV_TRANSLATE_GVA_RESULT, WHV_TRANSLATE_GVA_RESULT_CODE};

/// `HRESULT_FROM_WIN32(ERROR_NOACCESS)`: WHP's answer when a table page is
/// not there for it.
pub(crate) const NOACCESS: i32 = 0x8007_03E6_u32 as i32;

/// The looks [`translate`] takes at most: a 5-level walk brings in at most
/// five pages, and a move or a discard that comes back between two looks
/// one more each.
pub(crate) const ATTEMPTS: usize = 16;

/// What `WHvTranslateGva` answered: its `HRESULT`, and, when that is
/// `S_OK`, the result code and the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) hres: i32,
    pub(crate) code: WHV_TRANSLATE_GVA_RESULT_CODE,
    pub(crate) gpa: u64,
}

/// One `WHvTranslateGva` call, as WHP answers it.
pub(crate) fn raw(part: WHV_PARTITION_HANDLE, vp: u32, gva: u64, flags: WHV_TRANSLATE_GVA_FLAGS) -> Answer {
    // SAFETY: plain data; zero is a valid value.
    let mut result: WHV_TRANSLATE_GVA_RESULT = unsafe { std::mem::zeroed() };
    let mut gpa = 0u64;
    #[cfg(any(test, feature = "whp-trace"))]
    let before = super::ffi::trace::stack();
    // SAFETY: out-pointers valid for the call.
    let hres = unsafe { whv::WHvTranslateGva(part, vp, gva, flags, &mut result, &mut gpa) };
    #[cfg(any(test, feature = "whp-trace"))]
    super::ffi::trace::note("WHvTranslateGva", vp, &[], None, before, hres);
    #[cfg(test)]
    if hres == NOACCESS {
        NOACCESS_SEEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    Answer { hres, code: result.ResultCode, gpa }
}

/// Tests: the `ERROR_NOACCESS` answers [`raw`] has had, so that a test can
/// tell that its translation met one.
#[cfg(test)]
pub(crate) static NOACCESS_SEEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `WHvTranslateGva` for the vCPU `vp`, with the guest's page tables
/// settled in the host first when WHP could not reach one (the module's
/// comment): its answer.
pub(crate) fn translate(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    ram: &super::pvclock::Ram,
    gva: u64,
    flags: WHV_TRANSLATE_GVA_FLAGS,
) -> Answer {
    let first = raw(part, vp, gva, flags);
    if first.hres != NOACCESS {
        return first;
    }
    #[cfg(test)]
    if SETTLE_OFF.load(std::sync::atomic::Ordering::SeqCst) {
        return first;
    }
    settled(part, vp, ram, gva, flags).unwrap_or(first)
}

/// Tests: set, [`translate`] answers as before it settled anything (WHP's
/// first answer), so that a test shows what its case did then.
#[cfg(test)]
pub(crate) static SETTLE_OFF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The second way of [`translate`]: `None` when the first answer stands.
fn settled(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    ram: &super::pvclock::Ram,
    gva: u64,
    flags: WHV_TRANSLATE_GVA_FLAGS,
) -> Option<Answer> {
    // A wait holding one of these would hold up every vCPU that takes it.
    if !held::none_held("a translation's walk of the guest's page tables") {
        said(&format!("whp: the translation of {gva:#x} met a page-table page WHP could not reach, on a thread holding the backend's locks ({:#x}): not waited for, WHvTranslateGva's ERROR_NOACCESS stands", held::held()));
        return None;
    }
    let names = [whv::WHvX64RegisterCr0, whv::WHvX64RegisterCr3, whv::WHvX64RegisterCr4, whv::WHvX64RegisterEfer];
    // SAFETY: plain data; zero is a valid value.
    let mut values: [whv::WHV_REGISTER_VALUE; 4] = unsafe { std::mem::zeroed() };
    super::ffi::get_registers(part, vp, &names, &mut values).ok()?;
    let [cr0, cr3, cr4, efer] = values.map(|v| super::ffi::as_u64(&v));
    let paging = Paging::of(cr0, cr4, efer);
    // No tables: the failure is not a table page's.
    if paging == Paging::Off {
        return None;
    }
    // The slots as they are now: a host address is only read once the
    // locks below say its page is there, so a slot removed meanwhile is
    // not read through.
    let slots: Vec<(u64, u64, u64, bool)> =
        ram.lock().unwrap().values().map(|s| (s.guest_phys, s.size, s.host, s.readonly)).collect();
    let host_of = |gpa: u64, size: u64| {
        slots
            .iter()
            .find(|&&(start, len, _, _)| gpa >= start && gpa - start < len && gpa - start + size <= len)
            .map(|&(start, _, host, readonly)| (host + (gpa - start), readonly))
    };
    let setbits = flags & whv::WHvTranslateGvaFlagSetPageTableBits != 0;
    let mut last = (0, 0);
    for _ in 0..ATTEMPTS {
        let mut need = None;
        let answer = libc::wick_mm::with_pages_still(|allowed| {
            let walked = walk(paging, cr3, gva, &mut |gpa, size| {
                // Outside guest RAM: the walk ends there, and WHP's answer
                // for it stands.
                let (host, readonly) = host_of(gpa, size)?;
                // The accessed and dirty bits are written into the entries
                // (not into a read-only slot's: WHP's answer stands there).
                let write = setbits && !readonly;
                #[allow(clippy::cast_possible_truncation)]
                let page = host as usize;
                if !allowed(page, write) {
                    need = Some((host, write));
                    return None;
                }
                // SAFETY: a page the locks keep committed and readable
                // until they are dropped; the entry is aligned to its size
                // (a table is page-aligned, a PAE PDPT 32-byte aligned).
                Some(unsafe {
                    if size == 4 {
                        u64::from(std::ptr::read_volatile(host as *const u32))
                    } else {
                        std::ptr::read_volatile(host as *const u64)
                    }
                })
            });
            if need.is_some() {
                return None;
            }
            // Where it ended does not change the call: an entry not
            // present, a large page or the last level, or a page outside
            // guest RAM, are WHP's to answer.
            let _ = walked;
            Some(raw(part, vp, gva, flags))
        });
        match (answer, need) {
            (Some(a), _) => return Some(a),
            (None, Some((host, write))) => {
                last = (host, last.1 + 1);
                bring_in(host, write);
            }
            (None, None) => return None,
        }
    }
    said(&format!(
        "whp: the translation of {gva:#x}: the guest's page tables were not all there after {ATTEMPTS} looks, the last at the \
         table page of host address {:#x} ({} brought in; a page the host refuses, or one moved or discarded again at each \
         look): WHvTranslateGva's ERROR_NOACCESS stands",
        last.0,
        last.1
    ));
    None
}

/// Brings in the table page at `host` as the guest's own access would
/// (the run loop's steps for a memory access exit): lazy memory or a
/// released range's pending page committed (at the job's limit, the VMM
/// ends as there: `out_of_memory`), a missing userfaultfd page filled by
/// its handler, a chunk in a move waited for. Called holding no lock.
fn bring_in(host: u64, write: bool) {
    #[allow(clippy::cast_possible_truncation)]
    let page = host as usize;
    if let libc::wick_mm::Access::Exhausted(err) = libc::wick_mm::commit_on_access(page, write) {
        libc::wick_mm::out_of_memory(page, err);
    }
    if libc::wick_uffd::active() {
        libc::wick_uffd::fault(host, write);
    }
}

/// A line of the backend's, the first 16 and then every 1024th: a guest
/// can make these as often as it does MMIO.
fn said(line: &str) {
    static LINES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = LINES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n < 16 || n.is_multiple_of(1024) {
        super::ffi::report(log::Level::Warn, &format!("{line} ({} such lines)", n + 1));
    }
}

/// The vCPU's paging mode, as the hardware walks the tables in it
/// (Intel SDM vol. 3A, 4.1.1, table 4-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Paging {
    /// CR0.PG clear (real mode, or protected mode without paging): no
    /// tables.
    Off,
    /// 32-bit paging: two levels of 4-byte entries; `pse` (CR4.PSE) makes a
    /// directory entry with PS a 4 MiB page.
    Bits32 { pse: bool },
    /// PAE paging: the 4-entry PDPT at CR3, then two levels of 8-byte
    /// entries.
    Pae,
    /// 4-level paging (EFER.LMA; long mode and compatibility mode alike).
    Level4,
    /// 5-level paging (EFER.LMA and CR4.LA57).
    Level5,
}

impl Paging {
    /// The mode CR0, CR4 and EFER put the vCPU in.
    pub(crate) fn of(cr0: u64, cr4: u64, efer: u64) -> Paging {
        const CR0_PG: u64 = 1 << 31;
        const CR4_PSE: u64 = 1 << 4;
        const CR4_PAE: u64 = 1 << 5;
        const CR4_LA57: u64 = 1 << 12;
        const EFER_LMA: u64 = 1 << 10;
        if cr0 & CR0_PG == 0 {
            Paging::Off
        } else if efer & EFER_LMA != 0 {
            if cr4 & CR4_LA57 != 0 { Paging::Level5 } else { Paging::Level4 }
        } else if cr4 & CR4_PAE != 0 {
            Paging::Pae
        } else {
            Paging::Bits32 { pse: cr4 & CR4_PSE != 0 }
        }
    }
}

/// Where a [`walk`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Walk {
    /// At an entry that ends it: not present (bit 0 clear), a large page
    /// (PS at a level that has them), or the last level's; `reads` entries
    /// read.
    Ended { reads: usize },
    /// `read` gave no entry (outside guest RAM, or not there yet) at the
    /// `reads`th.
    Stopped { reads: usize },
}

/// One level of a walk: the address bits that index it, its entries' size,
/// whether an entry with PS (bit 7) maps a page there, and the bits of an
/// entry that address the next table.
struct Level {
    shift: u32,
    index_mask: u64,
    size: u64,
    large: bool,
    next: u64,
}

/// Bits 51:12 of an 8-byte entry: the next table's address (the bits
/// above the processor's MAXPHYADDR are reserved and fault the guest's own
/// walk; WHP answers that, the walk here only reads the table).
const ADDR_8: u64 = 0x000F_FFFF_FFFF_F000;
/// Bits 31:12 of a 4-byte entry.
const ADDR_4: u64 = 0xFFFF_F000;

const fn level8(shift: u32, large: bool) -> Level {
    Level { shift, index_mask: 511, size: 8, large, next: ADDR_8 }
}

/// Reads the entries the hardware reads to translate `gva` in `paging`
/// with `cr3`, top level first, each through `read(gpa, size)` (4 or 8
/// bytes; `None` ends the walk there), and follows them while they are
/// present and not a page. Never more than five reads; every address is
/// one `read` is asked about, whatever the entries hold.
pub(crate) fn walk(paging: Paging, cr3: u64, gva: u64, read: &mut dyn FnMut(u64, u64) -> Option<u64>) -> Walk {
    const PML5: Level = level8(48, false);
    const PML4: Level = level8(39, false);
    const PDPT: Level = level8(30, true);
    const PD: Level = level8(21, true);
    const PT: Level = level8(12, false);
    // PAE's PDPT: four entries, no PS; its directory and table as in 4-level.
    const PAE_PDPT: Level = Level { shift: 30, index_mask: 3, size: 8, large: false, next: ADDR_8 };
    static LEVEL5: [Level; 5] = [PML5, PML4, PDPT, PD, PT];
    static LEVEL4: [Level; 4] = [PML4, PDPT, PD, PT];
    static PAE: [Level; 3] = [PAE_PDPT, PD, PT];
    static BITS32: [Level; 2] = [
        Level { shift: 22, index_mask: 1023, size: 4, large: false, next: ADDR_4 },
        Level { shift: 12, index_mask: 1023, size: 4, large: false, next: ADDR_4 },
    ];
    static BITS32_PSE: [Level; 2] = [
        Level { shift: 22, index_mask: 1023, size: 4, large: true, next: ADDR_4 },
        Level { shift: 12, index_mask: 1023, size: 4, large: false, next: ADDR_4 },
    ];
    let (mut table, gva, levels): (u64, u64, &[Level]) = match paging {
        Paging::Off => return Walk::Ended { reads: 0 },
        // CR3's PCID (bits 11:0, with CR4.PCIDE) and the bits above 51 are
        // not the table's address.
        Paging::Level5 => (cr3 & ADDR_8, gva, &LEVEL5),
        Paging::Level4 => (cr3 & ADDR_8, gva, &LEVEL4),
        // A 32-bit CR3: PAE's PDPT is 32-byte aligned (bits 31:5).
        Paging::Pae => (cr3 & 0xFFFF_FFE0, gva & 0xFFFF_FFFF, &PAE),
        Paging::Bits32 { pse: false } => (cr3 & ADDR_4, gva & 0xFFFF_FFFF, &BITS32),
        Paging::Bits32 { pse: true } => (cr3 & ADDR_4, gva & 0xFFFF_FFFF, &BITS32_PSE),
    };
    for (i, l) in levels.iter().enumerate() {
        let at = table + ((gva >> l.shift) & l.index_mask) * l.size;
        let Some(entry) = read(at, l.size) else {
            return Walk::Stopped { reads: i + 1 };
        };
        if entry & 1 == 0 || i + 1 == levels.len() || (l.large && entry & 0x80 != 0) {
            return Walk::Ended { reads: i + 1 };
        }
        table = entry & l.next;
    }
    unreachable!("the last level ends the walk")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Guest memory as entries by address; a read of an address not in it
    /// gives `None`, as a page outside guest RAM does. Every read recorded.
    struct Memory {
        entries: HashMap<u64, u64>,
        reads: Vec<(u64, u64)>,
    }

    impl Memory {
        fn new(entries: &[(u64, u64)]) -> Self {
            Memory { entries: entries.iter().copied().collect(), reads: Vec::new() }
        }

        fn walk(&mut self, paging: Paging, cr3: u64, gva: u64) -> Walk {
            walk(paging, cr3, gva, &mut |at, size| {
                self.reads.push((at, size));
                self.entries.get(&at).copied()
            })
        }
    }

    #[test]
    fn test_the_mode_is_read_as_the_hardware_reads_it() {
        assert_eq!(Paging::of(0x11, 0x20, 0x500), Paging::Off, "PG clear, whatever else");
        assert_eq!(Paging::of(0x8000_0011, 0x20, 0x500), Paging::Level4);
        assert_eq!(Paging::of(0x8000_0011, 0x1020, 0x500), Paging::Level5);
        assert_eq!(Paging::of(0x8000_0011, 0x20, 0x100), Paging::Pae, "LME without LMA is not long mode");
        assert_eq!(Paging::of(0x8000_0011, 0x10, 0), Paging::Bits32 { pse: true });
        assert_eq!(Paging::of(0x8000_0011, 0, 0), Paging::Bits32 { pse: false });
    }

    // 4-level: PML4[511] -> PDPT, PDPT[510] -> PD, PD[0] a 2 MiB page:
    // three reads, the walk ending at PS; CR3's PCID and bit 63 masked.
    #[test]
    fn test_a_4_level_walk_stops_at_a_large_page_and_masks_the_pcid() {
        let gva = 0xffff_ffff_8000_1234;
        let mut m = Memory::new(&[(0x20_1000 + 511 * 8, 0x20_2000 | 7), (0x20_2000 + 510 * 8, 0x20_3000 | 7), (0x20_3000, 0x83)]);
        assert_eq!(m.walk(Paging::Level4, 0x8000_0000_0020_1abc, gva), Walk::Ended { reads: 3 });
        assert_eq!(m.reads, [(0x20_1ff8, 8), (0x20_2ff0, 8), (0x20_3000, 8)]);
        // The same with a 4 KiB page at the end: four reads.
        let mut m = Memory::new(&[
            (0x1000, 0x2000 | 3),
            (0x2000, 0x3000 | 3),
            (0x3000 + 8, 0x4000 | 3),
            (0x4000 + 5 * 8, 0x9000 | 3),
        ]);
        assert_eq!(m.walk(Paging::Level4, 0x1000, 0x20_5000), Walk::Ended { reads: 4 });
        // A 1 GiB page at the PDPT: two reads.
        let mut m = Memory::new(&[(0x1000, 0x2000 | 3), (0x2000 + 8, 0x4000_0000 | 0x83)]);
        assert_eq!(m.walk(Paging::Level4, 0x1000, 0x4000_0000), Walk::Ended { reads: 2 });
    }

    #[test]
    fn test_a_5_level_walk_reads_the_pml5_first() {
        let gva = 0x01ff_0000_0000_0000_u64 | (3 << 39);
        let mut m = Memory::new(&[(0x1000 + 0x1ff * 8, 0x2000 | 3), (0x2000 + 3 * 8, 0x3000 | 3), (0x3000, 0), (0x5000, 0)]);
        assert_eq!(m.walk(Paging::Level5, 0x1000, gva), Walk::Ended { reads: 3 }, "the PDPT entry not present ends it");
        assert_eq!(m.reads, [(0x1ff8, 8), (0x2018, 8), (0x3000, 8)]);
    }

    // PAE: the PDPT's entry by bits 31:30 at CR3 (bits 31:5), then 8-byte
    // directory and table entries; bits above 31 of the address unused.
    #[test]
    fn test_a_pae_walk_reads_the_pdpt_at_cr3() {
        let mut m = Memory::new(&[(0x1020 + 3 * 8, 0x2000 | 1), (0x2000 + 0x10 * 8, 0x3000 | 3), (0x3000 + 0x22 * 8, 0x7000 | 3)]);
        let gva = 0xdead_0000_c202_2000_u64;
        assert_eq!(m.walk(Paging::Pae, 0x1020, gva), Walk::Ended { reads: 3 });
        assert_eq!(m.reads, [(0x1038, 8), (0x2080, 8), (0x3110, 8)]);
        // A 2 MiB page in the directory.
        let mut m = Memory::new(&[(0x1000, 0x2000 | 1), (0x2000, 0x83)]);
        assert_eq!(m.walk(Paging::Pae, 0x1000, 0x1000), Walk::Ended { reads: 2 });
    }

    // 32-bit: 4-byte entries; PS is a 4 MiB page only with CR4.PSE.
    #[test]
    fn test_a_32_bit_walk_honours_pse_only_when_it_is_on() {
        let entries = [(0x1000 + 4 * 4, 0x0040_0083), (0x0040_0000 + 0x3 * 4, 3)];
        let gva = 0x0100_3000;
        let mut m = Memory::new(&entries);
        assert_eq!(m.walk(Paging::Bits32 { pse: true }, 0x1000, gva), Walk::Ended { reads: 1 });
        let mut m = Memory::new(&entries);
        assert_eq!(m.walk(Paging::Bits32 { pse: false }, 0x1000, gva), Walk::Ended { reads: 2 }, "PS is ignored without PSE");
        assert_eq!(m.reads, [(0x1010, 4), (0x0040_000c, 4)]);
    }

    // A hostile guest's tables: every entry pointing back at the table
    // itself is read five times at most (5-level), never more; an address
    // outside guest RAM stops the walk without a read past it.
    #[test]
    fn test_a_walk_reads_at_most_five_entries_and_stops_outside_ram() {
        let mut m = Memory::new(&[]);
        let mut n = 0;
        let w = walk(Paging::Level5, 0x1000, u64::MAX, &mut |_, _| {
            n += 1;
            Some(0x1000 | 3)
        });
        assert_eq!((w, n), (Walk::Ended { reads: 5 }, 5));
        let mut m2 = Memory::new(&[(0x1000, 0xffff_ffff_f000 | 3)]);
        assert_eq!(m2.walk(Paging::Level4, 0x1000, 0), Walk::Stopped { reads: 2 });
        assert_eq!(m2.reads[1], (0xffff_ffff_f000, 8));
        assert_eq!(m.walk(Paging::Off, 0x1000, 0), Walk::Ended { reads: 0 });
        assert!(m.reads.is_empty());
    }
}
