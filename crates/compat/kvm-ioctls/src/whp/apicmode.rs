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
//! A partition's local APIC is an x2APIC, as KVM's, on an AMD host
//! ([`partition_for`]): WHP's x2APIC answers the guest's x2APIC register
//! accesses itself but for the LVT timer's TSC-deadline mode, which the
//! backend finishes from a #GP exit (`gp`; option E of the x2APIC plan,
//! measured on AMD hosts only: CI's EPYC runners and a PC's Ryzen 9 7900,
//! X2E0REC and GPEXITREC). The supported CPUID offers x2APIC there, whatever the host
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

#[cfg(test)]
mod tests {
    use super::*;

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
