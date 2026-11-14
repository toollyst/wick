// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The guest's CPUID x2APIC bit against the partition's local APIC mode.
//!
//! A Linux guest trusts CPUID leaf 1 ECX bit 21: `x2apic_supported()` is
//! `boot_cpu_has(X86_FEATURE_X2APIC)` (Linux v6.1
//! arch/x86/include/asm/apic.h:259), `check_x2apic` and `enable_IR_x2apic`
//! go on from it (arch/x86/kernel/apic/apic.c:1920-1932, 1949-1961), and
//! `x2apic_enable` sets `x2apic_mode` before `__x2apic_enable` writes
//! APIC_BASE.EXTD (apic.c:1871-1878, 1791-1799). The write is unchecked: if
//! it faults, the guest says "unchecked MSR access error: WRMSR to 0x1b"
//! and drives the x2APIC's MSRs from then on, which reach no APIC on a
//! partition whose local APIC is an xAPIC: no timer interrupt, no IPI (CI
//! run 43452122814, an Intel Xeon Platinum 8573C runner, whose CPUID the
//! partition passed on with x2APIC: every guest stage stuck).
//!
//! KVM offers x2APIC whatever the host has ("KVM emulates x2apic in software
//! irrespective of host support", v6.1 arch/x86/kvm/cpuid.c:599-600) and
//! takes a guest's EXTD only when the guest's CPUID has the bit
//! (`kvm_set_apic_base`, arch/x86/kvm/x86.c:475-492: X2APIC_ENABLE is a
//! reserved bit otherwise).
//!
//! Option E makes a partition's local APIC an x2APIC, as KVM's, on an AMD
//! host ([`partition_for`]); the product's partitions stay xAPICs on every
//! host (`vm::X2APIC_PARTITIONS`), and only tests make x2APIC ones. There,
//! WHP's x2APIC answers the guest's x2APIC register accesses itself but for
//! the LVT timer's TSC-deadline mode, which WHP refuses with #GP and the
//! backend takes from the #GP exit (`gp`; option E of the x2APIC plan,
//! measured on AMD hosts only: CI's EPYC runners and a PC's Ryzen 9 7900,
//! X2E0REC and GPEXITREC), and refuses for now: the one way WHP keeps that
//! mode, the APIC register page's get and set, loses an interrupt
//! requested between them (X2RMWREC, PC step 15a at 305a806). The supported CPUID offers x2APIC there, whatever the host
//! has, and `KVM_SET_CPUID2` takes a table with or without it. On any
//! other host (Intel, Hygon) the partition stays an xAPIC until a run
//! there measures option E: the supported CPUID never offers x2APIC and a
//! `KVM_SET_CPUID2` table that has it is refused, so that the guest's
//! CPUID and the partition's APIC agree and a guest's EXTD is refused as
//! KVM refuses it to a guest whose CPUID lacks the bit.
//!
//! Written without the crate's types, so that its tests run on any host
//! (the fuzz crate's lib tests, `whp_apicmode`).

/// The local APIC a partition emulates (`WHV_X64_LOCAL_APIC_EMULATION_MODE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalApic {
    /// `WHvX64LocalApicEmulationModeXApic`: no x2APIC mode.
    XApic,
    /// `WHvX64LocalApicEmulationModeX2Apic`: xAPIC mode at reset, x2APIC
    /// mode once APIC_BASE.EXTD is set, as on the processor and in KVM.
    X2Apic,
}

/// CPUID leaf 1 ECX: x2APIC.
pub const LEAF1_ECX_X2APIC: u32 = 1 << 21;

/// The local APIC of a partition on a host whose CPUID leaf 0 vendor string
/// is `vendor` (EBX, EDX, ECX): an x2APIC on AMD ("AuthenticAMD"), where
/// the x2APIC partition is measured, an xAPIC anywhere else.
pub fn partition_for(vendor: &[u8; 12]) -> LocalApic {
    if vendor == b"AuthenticAMD" { LocalApic::X2Apic } else { LocalApic::XApic }
}

/// Leaf 1's ECX as a partition with `apic` offers it: on an xAPIC, without
/// x2APIC, whatever the host has; on an x2APIC, with it, as KVM offers it.
pub fn offered_leaf1_ecx(apic: LocalApic, ecx: u32) -> u32 {
    match apic {
        LocalApic::XApic => ecx & !LEAF1_ECX_X2APIC,
        LocalApic::X2Apic => ecx | LEAF1_ECX_X2APIC,
    }
}

/// Whether `KVM_SET_CPUID2` refuses a table whose leaf 1 has `ecx` (`None`:
/// no leaf 1) on a partition with `apic`: on an xAPIC, a table that offers
/// x2APIC; on an x2APIC, none.
pub fn refuses_leaf1_ecx(apic: LocalApic, ecx: Option<u32>) -> bool {
    match apic {
        LocalApic::XApic => ecx.is_some_and(|e| e & LEAF1_ECX_X2APIC != 0),
        LocalApic::X2Apic => false,
    }
}

/// The x2APIC registers' MSRs, KVM's `APIC_BASE_MSR ... APIC_BASE_MSR +
/// 0xff` (Linux v6.1 arch/x86/kvm/x86.c 3611, 4058).
pub const X2APIC_MSRS: core::ops::RangeInclusive<u32> = 0x800..=0x8ff;

/// IA32_APIC_BASE's EXTD: x2APIC mode.
const APIC_BASE_EXTD: u64 = 1 << 10;

/// What the run loop does with a guest's `RDMSR` or `WRMSR` of an x2APIC
/// register's MSR that WHP handed it as an MSR exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X2ApicMsrExit {
    /// #GP(0), the instruction not done: the local APIC is not in x2APIC
    /// mode (APIC_BASE.EXTD clear), where KVM's `kvm_x2apic_msr_read` and
    /// `kvm_x2apic_msr_write` return 1 (`!apic_x2apic_mode(apic)`, v6.1
    /// arch/x86/kvm/lapic.c 2961-2962, 2972-2973) and `kvm_emulate_rdmsr`
    /// and `kvm_emulate_wrmsr` inject #GP(0) for it (`kvm_complete_insn_gp`,
    /// x86.c 748-756, from x86.c 2016-2040 and 2041-2064); `ignore_msrs`
    /// (off by default, x86.c 143) never masks it, as it masks only
    /// `KVM_MSR_RET_INVALID`, an MSR KVM has no case for
    /// (`kvm_get_msr_ignored_check`, `kvm_set_msr_ignored_check`, x86.c
    /// 1866-1876, 1911-1923). On an xAPIC partition
    /// (every product partition) that is every such access: WHP exits for
    /// them (GPEXITREC, APIC_BASE.EXTD clear: reason 0x1000) and the
    /// backend had answered them as an unknown MSR, the write ignored and
    /// the read 0 (TSCDLTEST, PC step 15b at 305a806: the guest's WRMSR
    /// 0x832 in xAPIC mode went on to its next instruction).
    Gp,
    /// In x2APIC mode, where WHP's x2APIC answers every such access itself,
    /// with no exit (GPEXITREC, APIC_BASE.EXTD set: 0 MSR exits): an exit is
    /// one the backend has no answer for, and the vCPU fails, named, rather
    /// than give the guest an APIC register's value it does not have.
    Unanswered,
}

/// The run loop's answer to an MSR exit for `index` with APIC_BASE
/// `apic_base` ([`X2ApicMsrExit`]), or `None` for an MSR that is not an
/// x2APIC register's.
pub fn x2apic_msr_exit(index: u32, apic_base: u64) -> Option<X2ApicMsrExit> {
    if !X2APIC_MSRS.contains(&index) {
        return None;
    }
    Some(if apic_base & APIC_BASE_EXTD == 0 { X2ApicMsrExit::Gp } else { X2ApicMsrExit::Unanswered })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_an_x2apic_msr_outside_x2apic_mode_is_a_gp_as_kvm() {
        // xAPIC mode (enabled, BSP), x2APIC mode, disabled.
        let (xapic, x2apic, off) = (0xfee0_0900u64, 0xfee0_0d00u64, 0xfee0_0100u64);
        for index in [0x800u32, 0x802, 0x80b, 0x80f, 0x830, 0x832, 0x838, 0x839, 0x83f, 0x8ff] {
            assert_eq!(x2apic_msr_exit(index, xapic), Some(X2ApicMsrExit::Gp), "{index:#x}");
            assert_eq!(x2apic_msr_exit(index, off), Some(X2ApicMsrExit::Gp), "{index:#x}, APIC disabled");
            assert_eq!(x2apic_msr_exit(index, x2apic), Some(X2ApicMsrExit::Unanswered), "{index:#x}");
        }
        // Not an x2APIC register's: APIC_BASE itself, the TSC deadline, the
        // MSRs either side of the range, kvmclock.
        for index in [0x1bu32, 0x6e0, 0x7ff, 0x900, 0x4b56_4d01, 0xc000_0080] {
            assert_eq!(x2apic_msr_exit(index, xapic), None, "{index:#x}");
            assert_eq!(x2apic_msr_exit(index, x2apic), None, "{index:#x}");
        }
    }

    #[test]
    fn test_an_xapic_partition_never_offers_x2apic() {
        // The Intel runner's leaf 1 ECX has x2APIC; an AMD host's may not.
        for host in [0xfffa_3203u32, 0xfeda_3203, 0, u32::MAX, LEAF1_ECX_X2APIC] {
            let offered = offered_leaf1_ecx(LocalApic::XApic, host);
            assert_eq!(offered & LEAF1_ECX_X2APIC, 0, "host {host:#x}");
            assert_eq!(offered | LEAF1_ECX_X2APIC, host | LEAF1_ECX_X2APIC, "only bit 21 changes: host {host:#x}");
        }
    }

    #[test]
    fn test_a_table_with_x2apic_is_refused_on_an_xapic_partition() {
        assert!(refuses_leaf1_ecx(LocalApic::XApic, Some(LEAF1_ECX_X2APIC)));
        assert!(refuses_leaf1_ecx(LocalApic::XApic, Some(0xfffa_3203)));
        assert!(!refuses_leaf1_ecx(LocalApic::XApic, Some(0xfffa_3203 & !LEAF1_ECX_X2APIC)));
        assert!(!refuses_leaf1_ecx(LocalApic::XApic, Some(0)));
        assert!(!refuses_leaf1_ecx(LocalApic::XApic, None), "no leaf 1: nothing offered");
        // What the supported CPUID offers is always taken back.
        for host in [0xfffa_3203u32, 0, u32::MAX] {
            assert!(!refuses_leaf1_ecx(LocalApic::XApic, Some(offered_leaf1_ecx(LocalApic::XApic, host))));
        }
    }

    #[test]
    fn test_an_x2apic_partition_offers_x2apic_as_kvm() {
        for host in [0xfffa_3203u32, 0xfeda_3203 & !LEAF1_ECX_X2APIC, 0, u32::MAX] {
            let offered = offered_leaf1_ecx(LocalApic::X2Apic, host);
            assert_ne!(offered & LEAF1_ECX_X2APIC, 0, "host {host:#x}");
            assert_eq!(offered & !LEAF1_ECX_X2APIC, host & !LEAF1_ECX_X2APIC, "only bit 21 changes: host {host:#x}");
        }
        for ecx in [Some(LEAF1_ECX_X2APIC), Some(0), None] {
            assert!(!refuses_leaf1_ecx(LocalApic::X2Apic, ecx), "{ecx:?}");
        }
    }

    #[test]
    fn test_the_partition_is_an_x2apic_on_amd_only() {
        assert_eq!(partition_for(b"AuthenticAMD"), LocalApic::X2Apic);
        assert_eq!(partition_for(b"GenuineIntel"), LocalApic::XApic);
        assert_eq!(partition_for(b"HygonGenuine"), LocalApic::XApic);
        assert_eq!(partition_for(&[0; 12]), LocalApic::XApic);
    }
}
