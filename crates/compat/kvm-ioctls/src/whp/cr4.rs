// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The CR4 values `KVM_SET_SREGS` takes, as KVM decides them (Linux v6.1).
//!
//! `__kvm_is_valid_cr4` (arch/x86/kvm/x86.c:1103-1112, through
//! `kvm_is_valid_sregs`, x86.c:11460-11481) refuses a CR4 with a bit of
//! `cr4_reserved_bits`, made from the host's capabilities, KVM's supported
//! CPUID (x86.c:12293), or of `cr4_guest_rsvd_bits`, made from the vCPU's
//! own CPUID at `KVM_SET_CPUID2` (arch/x86/kvm/cpuid.c:355-356); both are
//! `__cr4_reserved_bits` (arch/x86/kvm/x86.h:455-478): every bit KVM does
//! not know (`CR4_RESERVED_BITS`, arch/x86/include/asm/kvm_host.h:117-123)
//! and each feature's bit whose CPUID flag is missing. Here the host's
//! capabilities are the supported CPUID (the root partition's CPUID less
//! what the backend leaves out, `regs::supported_cpuid`), so a CR4 bit the
//! partition does not take, PCIDE on a host whose root partition has no
//! PCID (the PC's Ryzen 9 7900 under Hyper-V: SREGSREC), is refused here by
//! name, as KVM refuses it on a host without the feature, and not by WHP
//! with an invalid parameter.
//!
//! Written without the crate's types, so that its tests run on any host
//! (the fuzz crate's lib tests, `whp_cr4`).

pub const VME: u64 = 1 << 0;
pub const PVI: u64 = 1 << 1;
pub const TSD: u64 = 1 << 2;
pub const DE: u64 = 1 << 3;
pub const PSE: u64 = 1 << 4;
pub const PAE: u64 = 1 << 5;
pub const MCE: u64 = 1 << 6;
pub const PGE: u64 = 1 << 7;
pub const PCE: u64 = 1 << 8;
pub const OSFXSR: u64 = 1 << 9;
pub const OSXMMEXCPT: u64 = 1 << 10;
pub const UMIP: u64 = 1 << 11;
pub const LA57: u64 = 1 << 12;
pub const VMXE: u64 = 1 << 13;
pub const FSGSBASE: u64 = 1 << 16;
pub const PCIDE: u64 = 1 << 17;
pub const OSXSAVE: u64 = 1 << 18;
pub const SMEP: u64 = 1 << 20;
pub const SMAP: u64 = 1 << 21;
pub const PKE: u64 = 1 << 22;

/// The bits KVM knows (the complement of `CR4_RESERVED_BITS`).
pub const KNOWN: u64 = VME
    | PVI
    | TSD
    | DE
    | PSE
    | PAE
    | MCE
    | PGE
    | PCE
    | OSFXSR
    | PCIDE
    | OSXSAVE
    | SMEP
    | FSGSBASE
    | OSXMMEXCPT
    | LA57
    | VMXE
    | SMAP
    | PKE
    | UMIP;

/// A CPUID flag: leaf, sub-leaf, register (1 EBX, 2 ECX, 3 EDX), bit.
pub type Flag = (u32, u32, u8, u32);
/// A CR4 bit a CPUID flag gates: the bit, its name, the flag, its name.
pub type Gate = (u64, &'static str, Flag, &'static str);

/// Each CR4 bit a CPUID flag gates (`__cr4_reserved_bits`).
pub const GATED: [Gate; 9] = [
    (OSXSAVE, "OSXSAVE", (1, 0, 2, 26), "XSAVE"),
    (SMEP, "SMEP", (7, 0, 1, 7), "SMEP"),
    (SMAP, "SMAP", (7, 0, 1, 20), "SMAP"),
    (FSGSBASE, "FSGSBASE", (7, 0, 1, 0), "FSGSBASE"),
    (PKE, "PKE", (7, 0, 2, 3), "PKU"),
    (LA57, "LA57", (7, 0, 2, 16), "LA57"),
    (UMIP, "UMIP", (7, 0, 2, 2), "UMIP"),
    (VMXE, "VMXE", (1, 0, 2, 5), "VMX"),
    (PCIDE, "PCIDE", (1, 0, 2, 17), "PCID"),
];

/// `__cr4_reserved_bits` of a CPUID: `has(leaf, sub-leaf, register, bit)`
/// says whether the flag is set (a leaf the CPUID lacks has none).
pub fn reserved_bits(has: impl Fn(u32, u32, u8, u32) -> bool) -> u64 {
    let mut reserved = !KNOWN;
    for (bit, _, (leaf, index, register, flag), _) in GATED {
        if !has(leaf, index, register, flag) {
            reserved |= bit;
        }
    }
    reserved
}

/// Which CPUID a refused CR4 bit is missing from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lacking {
    /// The host's (the supported CPUID): KVM's `cr4_reserved_bits`.
    Host,
    /// The vCPU's (`KVM_SET_CPUID2`): KVM's `cr4_guest_rsvd_bits`.
    Guest,
}

/// The bits of `cr4` KVM refuses, with whose CPUID lacks them (the host's
/// first, as KVM looks at it first), or `None` if it takes the value.
pub fn refused(cr4: u64, host_reserved: u64, guest_reserved: u64) -> Option<(u64, Lacking)> {
    if cr4 & host_reserved != 0 {
        Some((cr4 & host_reserved, Lacking::Host))
    } else if cr4 & guest_reserved != 0 {
        Some((cr4 & guest_reserved, Lacking::Guest))
    } else {
        None
    }
}

/// `bits` by name: `PCIDE (bit 17, CPUID PCID)`, a bit KVM does not know
/// by its number.
pub fn names(bits: u64) -> String {
    let mut out = Vec::new();
    for n in 0..64 {
        let bit = 1u64 << n;
        if bits & bit == 0 {
            continue;
        }
        match GATED.iter().find(|g| g.0 == bit) {
            Some((_, name, _, flag)) => out.push(format!("{name} (bit {n}, CPUID {flag})")),
            None => out.push(format!("bit {n} (reserved)")),
        }
    }
    out.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CPUID with the flags in `set`, by (leaf, sub-leaf, register, bit).
    fn cpuid(set: &[(u32, u32, u8, u32)]) -> impl Fn(u32, u32, u8, u32) -> bool + '_ {
        move |l, i, r, b| set.contains(&(l, i, r, b))
    }

    #[test]
    fn test_reserved_bits_are_kvms() {
        // No flag: every gated bit and every unknown bit reserved, the
        // architectural ones free.
        let none = reserved_bits(cpuid(&[]));
        for (bit, ..) in GATED {
            assert_ne!(none & bit, 0);
        }
        for bit in [VME, PVI, TSD, DE, PSE, PAE, MCE, PGE, PCE, OSFXSR, OSXMMEXCPT] {
            assert_eq!(none & bit, 0);
        }
        assert_ne!(none & (1 << 14), 0, "SMXE is not one KVM knows");
        assert_ne!(none & (1 << 23), 0, "CET is not one KVM v6.1 knows");
        // Each flag frees its bit only.
        for (bit, _, flag, _) in GATED {
            let one = [flag];
            assert_eq!(reserved_bits(cpuid(&one)), none & !bit);
        }
    }

    #[test]
    fn test_a_host_without_pcid_refuses_pcide_by_name() {
        // The PC: no PCID in the root's CPUID, so neither in the guest's.
        let host = reserved_bits(cpuid(&[(1, 0, 2, 26), (7, 0, 1, 7), (7, 0, 1, 20), (7, 0, 1, 0), (7, 0, 2, 2)]));
        let guest = host;
        // A Linux guest's snapshot made on KVM: CR4 0x370eb0.
        assert_eq!(refused(0x37_0eb0, host, guest), Some((PCIDE, Lacking::Host)));
        assert_eq!(names(PCIDE), "PCIDE (bit 17, CPUID PCID)");
        // Without PCIDE it is taken, UMIP included, which the host has.
        assert_eq!(refused(0x37_0eb0 & !PCIDE, host, guest), None);
        // A host with PCID and a guest CPUID without it: the guest's half.
        let host = reserved_bits(cpuid(&[(1, 0, 2, 17)]));
        let guest = reserved_bits(cpuid(&[]));
        assert_eq!(refused(PCIDE | PAE, host, guest), Some((PCIDE, Lacking::Guest)));
        assert_eq!(refused(PAE, host, guest), None);
    }

    #[test]
    fn test_unknown_bits_are_named_by_number() {
        assert_eq!(names(1 << 14 | VMXE), "VMXE (bit 13, CPUID VMX), bit 14 (reserved)");
        assert_eq!(names(0), "");
    }
}
