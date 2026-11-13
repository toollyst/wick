// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The machine-check MSRs, and HWCR, whose McStatusWrEn decides what a
//! guest may write to a bank's STATUS, kept for each vCPU as KVM keeps them
//! (Linux v6.1 arch/x86/kvm/x86.c: `set_msr_mce`, `get_msr_mce`,
//! `can_set_mci_status`, and their cases and `MSR_K7_HWCR`'s in
//! `kvm_set_msr_common` and `kvm_get_msr_common`). No WHP register holds
//! them. `KVM_GET_MSRS` and `KVM_SET_MSRS` read and write them here, so a
//! snapshot carries what the guest and the VMM left in them, and a guest's
//! own `RDMSR` and `WRMSR` of one that reaches the backend (an MSR exit)
//! is answered from here too.
//!
//! KVM's state without `KVM_X86_SETUP_MCE`, which Firecracker never calls
//! (vmm arch/x86_64/msr.rs, the note on IA32_MCG_CTL): `mcg_cap` is
//! `KVM_MAX_MCE_BANKS`, 32 banks with neither MCG_CTL_P nor MCG_CMCI_P
//! (`kvm_arch_vcpu_create`), and every value 0 (`kcalloc`).
//!
//! Written without the crate's types, so that its tests run on any host:
//! `rustc --edition 2024 --test crates/compat/kvm-ioctls/src/whp/mce.rs`.

/// `MSR_IA32_P5_MC_ADDR` and `MSR_IA32_P5_MC_TYPE`.
pub const P5_MC_ADDR: u32 = 0x0;
pub const P5_MC_TYPE: u32 = 0x1;
/// `MSR_IA32_MCG_CAP`, `_STATUS`, `_CTL`.
pub const MCG_CAP: u32 = 0x179;
pub const MCG_STATUS: u32 = 0x17a;
pub const MCG_CTL: u32 = 0x17b;
/// `MSR_IA32_MC0_CTL2`, the first of one a bank (CMCI).
pub const MC0_CTL2: u32 = 0x280;
/// `MSR_IA32_MC0_CTL`, the first of four a bank: CTL, STATUS, ADDR, MISC.
pub const MC0_CTL: u32 = 0x400;
/// `KVM_MAX_MCE_BANKS`.
pub const BANKS: usize = 32;
/// `MSR_K7_HWCR`, in KVM's emulated MSRs on every host (`emulated_msrs_all`).
pub const HWCR: u32 = 0xc001_0015;
/// HWCR's McStatusWrEn.
const MC_STATUS_WR_EN: u64 = 1 << 18;

/// `MCG_CTL_P`, `MCG_CMCI_P` (arch/x86/include/asm/mce.h).
const MCG_CTL_P: u64 = 1 << 8;
const MCG_CMCI_P: u64 = 1 << 10;
/// `MCI_CTL2_CMCI_EN`, `MCI_CTL2_CMCI_THRESHOLD_MASK`.
const MCI_CTL2_WRITABLE: u64 = (1 << 30) | 0x7fff;

/// Whether WHP answers a guest's RDMSR and WRMSR of `index` itself, with
/// no MSR exit and no register the backend can read or write: IA32_MCG_CAP
/// and IA32_MCG_STATUS (a Windows 11 PC, build 26300, Ryzen 9 7900:
/// `test_what_a_cpu_template_changes_on_record`, "intercepts 0", MCG_CAP
/// read as 0, a write of MCG_STATUS taken). WHP has no register name for
/// either (WinHvPlatformDefs.h, WHV_REGISTER_NAME), and a partition whose
/// MSR action list holds either is refused at its set-up (`vm::configure`).
/// So their values are WHP's, which neither `KVM_GET_MSRS` nor a snapshot
/// can have: the calls end at them (`regs::has_msr`), and they are not in
/// the MSR index list.
pub fn whp_answers(index: u32) -> bool {
    matches!(index, MCG_CAP | MCG_STATUS)
}

/// Whether `index` is one of the machine-check MSRs KVM has a case for:
/// the P5 pair, MCG_CAP/STATUS/CTL, the 32 banks' CTL2 and their four
/// registers each; or HWCR.
pub fn is_mce(index: u32) -> bool {
    matches!(index, P5_MC_ADDR | P5_MC_TYPE | MCG_CAP..=MCG_CTL | HWCR)
        || (MC0_CTL2..MC0_CTL2 + BANKS as u32).contains(&index)
        || (MC0_CTL..MC0_CTL + 4 * BANKS as u32).contains(&index)
}

/// One vCPU's machine-check MSRs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mce {
    pub mcg_cap: u64,
    pub mcg_status: u64,
    pub mcg_ctl: u64,
    /// Four a bank: CTL, STATUS, ADDR, MISC (`mce_banks`).
    pub banks: [u64; 4 * BANKS],
    /// `mci_ctl2_banks`.
    pub ctl2: [u64; BANKS],
    /// `msr_hwcr`.
    pub hwcr: u64,
}

impl Default for Mce {
    fn default() -> Self {
        Mce { mcg_cap: BANKS as u64, mcg_status: 0, mcg_ctl: 0, banks: [0; 4 * BANKS], ctl2: [0; BANKS], hwcr: 0 }
    }
}

impl Mce {
    fn bank_count(&self) -> u32 {
        (self.mcg_cap & 0xff) as u32
    }

    /// `index` read by the VMM (`host`, `KVM_GET_MSRS`) or the guest
    /// (`RDMSR`); `None` where KVM refuses it (the guest takes a #GP, the
    /// VMM's call ends there): MCG_CTL without MCG_CTL_P and a CTL2 without
    /// MCG_CMCI_P to the guest, a bank KVM does not have, an index that is
    /// none of these.
    pub fn get(&self, index: u32, host: bool) -> Option<u64> {
        let cap = self.mcg_cap;
        match index {
            P5_MC_ADDR | P5_MC_TYPE => Some(0),
            HWCR => Some(self.hwcr),
            MCG_CAP => Some(cap),
            MCG_CTL => (cap & MCG_CTL_P != 0 || host).then_some(self.mcg_ctl),
            MCG_STATUS => Some(self.mcg_status),
            i if (MC0_CTL2..MC0_CTL2 + BANKS as u32).contains(&i) => {
                let bank = i - MC0_CTL2;
                (bank < self.bank_count() && (cap & MCG_CMCI_P != 0 || host)).then(|| self.ctl2[bank as usize])
            }
            i if (MC0_CTL..MC0_CTL + 4 * BANKS as u32).contains(&i) => {
                let offset = i - MC0_CTL;
                (offset < 4 * self.bank_count()).then(|| self.banks[offset as usize])
            }
            _ => None,
        }
    }

    /// `data` written to `index` by the VMM (`host`) or the guest, as KVM's
    /// `set_msr_mce` takes it; false where KVM refuses it, nothing then
    /// changed. `amd_guest`: the guest's CPUID names AMD or Hygon, which
    /// with HWCR's McStatusWrEn is KVM's `can_set_mci_status`. MCG_CAP and
    /// the P5 pair are not written by any `WRMSR` or `KVM_SET_MSRS`
    /// (`kvm_set_msr_common` has no case for them). HWCR as KVM's
    /// `MSR_K7_HWCR` case: three bits ignored, McStatusWrEn alone kept, any
    /// other value refused, and 0 taken without a change (KVM's `break`).
    pub fn set(&mut self, index: u32, data: u64, host: bool, amd_guest: bool) -> bool {
        let cap = self.mcg_cap;
        let mci_status_writable = amd_guest && self.hwcr & MC_STATUS_WR_EN != 0;
        match index {
            HWCR => {
                let data = data & !(0x40 | 0x100 | 0x8);
                if data == MC_STATUS_WR_EN {
                    self.hwcr = data;
                } else if data != 0 {
                    return false;
                }
            }
            MCG_STATUS => self.mcg_status = data,
            MCG_CTL => {
                if cap & MCG_CTL_P == 0 && (data != 0 || !host) {
                    return false;
                }
                if data != 0 && data != u64::MAX {
                    return false;
                }
                self.mcg_ctl = data;
            }
            i if (MC0_CTL2..MC0_CTL2 + BANKS as u32).contains(&i) => {
                let bank = i - MC0_CTL2;
                if bank >= self.bank_count() {
                    return false;
                }
                if cap & MCG_CMCI_P == 0 && (data != 0 || !host) {
                    return false;
                }
                if data & !MCI_CTL2_WRITABLE != 0 {
                    return false;
                }
                self.ctl2[bank as usize] = data;
            }
            i if (MC0_CTL..MC0_CTL + 4 * BANKS as u32).contains(&i) => {
                let offset = i - MC0_CTL;
                if offset >= 4 * self.bank_count() {
                    return false;
                }
                // CTL: 0 or all ones, bit 10 and bit 0 allowed clear.
                if offset.is_multiple_of(4) && data != 0 && (data | (1 << 10) | 1) != u64::MAX {
                    return false;
                }
                // STATUS: a guest writes only 0 unless it may write more.
                if offset % 4 == 1 && !host && data != 0 && !mci_status_writable {
                    return false;
                }
                self.banks[offset as usize] = data;
            }
            _ => return false,
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The MSRs KVM has a case for, and the edges of their ranges.
    #[test]
    fn test_is_mce() {
        assert!(whp_answers(0x179) && whp_answers(0x17a) && !whp_answers(0x17b) && !whp_answers(0x400));
        for yes in [0, 1, 0x179, 0x17a, 0x17b, 0x280, 0x29f, 0x400, 0x47f, HWCR] {
            assert!(is_mce(yes), "{yes:#x}");
        }
        for no in [2, 0x178, 0x17c, 0x27f, 0x2a0, 0x3ff, 0x480, 0x4d0] {
            assert!(!is_mce(no), "{no:#x}");
        }
    }

    // KVM's state without KVM_X86_SETUP_MCE: 32 banks, no MCG_CTL_P nor
    // MCG_CMCI_P, every value 0; what the guest and the VMM may read.
    #[test]
    fn test_reads_as_kvm() {
        let m = Mce::default();
        assert_eq!(m.get(MCG_CAP, false), Some(32));
        assert_eq!(m.get(P5_MC_ADDR, false), Some(0));
        assert_eq!(m.get(P5_MC_TYPE, true), Some(0));
        assert_eq!(m.get(MCG_STATUS, false), Some(0));
        // MCG_CTL and the CTL2s: the VMM's, not the guest's.
        assert_eq!(m.get(MCG_CTL, false), None);
        assert_eq!(m.get(MCG_CTL, true), Some(0));
        assert_eq!(m.get(0x280, false), None);
        assert_eq!(m.get(0x29f, true), Some(0));
        assert_eq!(m.get(0x47f, false), Some(0));
        assert_eq!(m.get(0x480, true), None);
    }

    // What KVM takes and refuses of a write, and that a refusal changes
    // nothing.
    #[test]
    fn test_writes_as_kvm() {
        let mut m = Mce::default();
        assert!(m.set(MCG_STATUS, 0x5, false, false));
        assert_eq!(m.get(MCG_STATUS, true), Some(0x5));
        // MCG_CTL without MCG_CTL_P: the VMM's 0 only.
        assert!(!m.set(MCG_CTL, 0, false, false));
        assert!(!m.set(MCG_CTL, u64::MAX, true, false));
        assert!(m.set(MCG_CTL, 0, true, false));
        // MCG_CAP and the P5 pair are not written.
        assert!(!m.set(MCG_CAP, 32, true, false));
        assert!(!m.set(P5_MC_ADDR, 0, true, false));
        // CTL2 without MCG_CMCI_P: the VMM's 0 only.
        assert!(!m.set(0x280, 0, false, false));
        assert!(m.set(0x280, 0, true, false));
        assert!(!m.set(0x280, 1 << 30, true, false));
        // A bank's CTL: 0 or all ones, bits 10 and 0 may be clear; by
        // anyone.
        assert!(m.set(0x400, u64::MAX, false, false));
        assert!(m.set(0x410, !((1 << 10) | 1), false, false));
        assert!(!m.set(0x404, 0x1234, true, false));
        assert_eq!(m.get(0x404, true), Some(0));
        // STATUS: the guest's non-zero only on an AMD guest whose HWCR has
        // McStatusWrEn; the VMM's any.
        assert!(!m.set(0x401, 0xbe00_0000_0000_0000, false, false));
        assert!(!m.set(0x401, 0xbe00_0000_0000_0000, false, true), "an AMD guest without McStatusWrEn");
        assert!(m.set(0x401, 0, false, false));
        assert!(m.set(HWCR, 1 << 18, false, true));
        assert!(!m.set(0x401, 0xbe00_0000_0000_0000, false, false), "McStatusWrEn on a guest that is not AMD's");
        assert!(m.set(0x401, 0xbe00_0000_0000_0000, false, true));
        assert!(m.set(0x405, 0xbe00_0000_0000_0000, true, false));
        // ADDR and MISC: any.
        assert!(m.set(0x402, 0xdead_beef, false, false));
        assert!(m.set(0x47f, 7, false, false));
        assert_eq!(
            (m.get(0x400, false), m.get(0x401, false), m.get(0x402, false), m.get(0x405, false), m.get(0x47f, false)),
            (Some(u64::MAX), Some(0xbe00_0000_0000_0000), Some(0xdead_beef), Some(0xbe00_0000_0000_0000), Some(7))
        );
        // Past the banks: refused.
        assert!(!m.set(0x480, 0, true, false));
    }

    // HWCR as KVM's MSR_K7_HWCR case: the flush filter, IGNNE and TLB cache
    // bits ignored, McStatusWrEn kept, anything else refused, and 0 taken
    // without clearing it.
    #[test]
    fn test_hwcr_as_kvm() {
        let mut m = Mce::default();
        assert_eq!(m.get(HWCR, false), Some(0));
        assert!(m.set(HWCR, 0x40 | 0x100 | 0x8, false, true), "ignored bits alone");
        assert_eq!(m.get(HWCR, true), Some(0));
        assert!(m.set(HWCR, (1 << 18) | 0x8, false, false));
        assert_eq!(m.get(HWCR, false), Some(1 << 18));
        assert!(!m.set(HWCR, (1 << 18) | 1, true, false), "another bit");
        assert!(m.set(HWCR, 0, false, false));
        assert_eq!(m.get(HWCR, false), Some(1 << 18), "0 leaves it as it was");
    }

    // Banks beyond MCG_CAP's count are refused both ways, as KVM's
    // `last_msr` checks them.
    #[test]
    fn test_bank_count_bounds() {
        let m = Mce { mcg_cap: 2, ..Mce::default() };
        let mut w = m.clone();
        assert_eq!(m.get(0x407, false), Some(0));
        assert_eq!(m.get(0x408, false), None);
        assert_eq!(m.get(0x281, true), Some(0));
        assert_eq!(m.get(0x282, true), None);
        assert!(!w.set(0x408, 0, true, false));
        assert!(!w.set(0x282, 0, true, false));
        assert_eq!(w, m);
    }
}
