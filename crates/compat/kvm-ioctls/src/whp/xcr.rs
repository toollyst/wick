// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! XCR0 against the guest's CPUID, as KVM checks it (Linux v6.1
//! arch/x86/kvm/x86.c, `__kvm_set_xcr`; arch/x86/kvm/cpuid.c,
//! `cpuid_get_supported_xcr0`).
//!
//! KVM lets a guest's XSETBV, and the VMM's `KVM_SET_XCRS`, enable only the
//! state components of the guest's CPUID leaf 0xD (sub-leaf 0, EDX:EAX)
//! that KVM supports, x87 always: a CPU template that clears a component
//! there (all five static ones clear MPX, AVX-512 and PKRU) keeps the
//! guest from enabling it. WHP has no exit for XSETBV (Microsoft Learn,
//! WHvRunVirtualProcessor: `WHV_RUN_VP_EXIT_REASON`), and a partition's
//! XSAVE components are fixed before the partition is set up (Partition
//! Property Data Types: "These properties can only be configured during
//! the initial creation of the partition, prior to calling
//! WHvSetupPartition"), which is at `KVM_CREATE_VM`, before any CPUID is
//! known. So a guest's XSETBV is checked against the partition's
//! components only (CI run 43397419784: with AVX cleared in the table, a
//! guest's XSETBV of AVX was taken). `KVM_SET_CPUID2` therefore refuses a
//! table that leaves out a component the partition lets a guest enable
//! ([`unenforced`]), and `KVM_SET_XCRS` checks as KVM does
//! ([`refused`]).
//!
//! Written without the crate's types, so that its tests run on any host:
//! `rustc --edition 2024 --test crates/compat/kvm-ioctls/src/whp/xcr.rs`.

/// `XFEATURE_MASK_*` (arch/x86/include/asm/fpu/types.h).
pub const FP: u64 = 1 << 0;
pub const SSE: u64 = 1 << 1;
pub const YMM: u64 = 1 << 2;
pub const BNDREGS: u64 = 1 << 3;
pub const BNDCSR: u64 = 1 << 4;
/// Opmask, ZMM_Hi256, Hi16_ZMM.
pub const AVX512: u64 = 0b111 << 5;
pub const PKRU: u64 = 1 << 9;
/// XTILE_CFG, XTILE_DATA.
pub const XTILE: u64 = 0b11 << 17;

/// `KVM_SUPPORTED_XCR0` (x86.c).
pub const KVM_SUPPORTED: u64 = FP | SSE | YMM | BNDREGS | BNDCSR | AVX512 | PKRU | XTILE;

/// KVM's `guest_supported_xcr0` for a CPUID table whose leaf 0xD sub-leaf
/// 0 is `leaf_d0` (EAX, EDX), `None` if the table has none, on a host
/// whose `kvm_caps.supported_xcr0` is `supported`.
pub fn guest_supported(leaf_d0: Option<(u32, u32)>, supported: u64) -> u64 {
    leaf_d0.map_or(0, |(eax, edx)| (u64::from(edx) << 32 | u64::from(eax)) & supported)
}

/// Whether KVM refuses XCR0 = `xcr0` for a vCPU whose
/// `guest_supported_xcr0` is `guest_supported` (`__kvm_set_xcr`: a guest's
/// XSETBV then takes #GP, the VMM's `KVM_SET_XCRS` fails with `EINVAL`).
pub fn refused(xcr0: u64, guest_supported: u64) -> bool {
    xcr0 & FP == 0
        || (xcr0 & YMM != 0 && xcr0 & SSE == 0)
        || xcr0 & !(guest_supported | FP) != 0
        || (xcr0 & BNDREGS == 0) != (xcr0 & BNDCSR == 0)
        || (xcr0 & AVX512 != 0 && (xcr0 & YMM == 0 || xcr0 & AVX512 != AVX512))
        || (xcr0 & XTILE != 0 && xcr0 & XTILE != XTILE)
}

/// The state components of `mask` by name, as the SDM names them (Intel
/// SDM vol. 1, 13.1, "XSAVE-Supported Features and State-Component
/// Bitmaps"); a bit without one by its number.
pub fn names(mask: u64) -> String {
    const NAMES: [(u32, &str); 9] = [
        (0, "x87"),
        (1, "SSE"),
        (2, "AVX"),
        (3, "MPX BNDREGS"),
        (4, "MPX BNDCSR"),
        (5, "AVX-512 opmask"),
        (6, "AVX-512 ZMM_Hi256"),
        (7, "AVX-512 Hi16_ZMM"),
        (9, "PKRU"),
    ];
    let mut out = Vec::new();
    for bit in 0..64 {
        if mask & (1 << bit) == 0 {
            continue;
        }
        match (bit, NAMES.iter().find(|(b, _)| *b == bit)) {
            (_, Some((_, name))) => out.push((*name).to_string()),
            (17, None) => out.push("AMX TILECFG".to_string()),
            (18, None) => out.push("AMX TILEDATA".to_string()),
            _ => out.push(format!("bit {bit}")),
        }
    }
    out.join(", ")
}

/// The state components a guest may enable on WHP, whose partition lets it
/// enable `partition`, that KVM would refuse it for a CPUID table giving
/// `guest_supported`: 0 if WHP enforces the table as KVM does.
pub fn unenforced(partition: u64, guest_supported: u64) -> u64 {
    partition & !(guest_supported | FP)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The table's leaf 0xD, limited to what KVM supports; none without one.
    #[test]
    fn test_guest_supported() {
        let host = FP | SSE | YMM | PKRU | (1 << 62);
        assert_eq!(guest_supported(Some((0x207, 0)), host & KVM_SUPPORTED), FP | SSE | YMM | PKRU);
        // A template's leaf 0xD with PKRU and AVX-512 cleared.
        assert_eq!(guest_supported(Some((0x7, 0)), host & KVM_SUPPORTED), FP | SSE | YMM);
        // EDX is the high half (LWP, bit 62, which KVM does not support).
        assert_eq!(guest_supported(Some((0x3, 1 << 30)), host), FP | SSE | (1 << 62));
        assert_eq!(guest_supported(None, host), 0);
    }

    // __kvm_set_xcr's checks, in its order.
    #[test]
    fn test_refused_as_kvm() {
        let all = KVM_SUPPORTED;
        assert!(!refused(FP, 0), "x87 is always taken");
        assert!(refused(0, all), "x87 must be set");
        assert!(refused(SSE, all));
        assert!(refused(FP | YMM, all), "AVX without SSE");
        assert!(!refused(FP | SSE | YMM, all));
        assert!(refused(FP | SSE | YMM, FP | SSE), "AVX not in the guest's CPUID");
        assert!(refused(FP | SSE, 0), "SSE not in the guest's CPUID");
        assert!(refused(FP | BNDREGS, all), "BNDREGS without BNDCSR");
        assert!(!refused(FP | BNDREGS | BNDCSR, all));
        assert!(refused(FP | SSE | AVX512, all), "AVX-512 without AVX");
        assert!(refused(FP | SSE | YMM | (1 << 5), all), "a part of AVX-512");
        assert!(!refused(FP | SSE | YMM | AVX512, all));
        assert!(refused(FP | (1 << 18), all), "a part of the tile state");
        assert!(!refused(FP | XTILE, all));
        assert!(!refused(FP | SSE | YMM | PKRU, all));
        assert!(refused(FP | SSE | YMM | PKRU, FP | SSE | YMM));
    }

    // What a partition lets a guest enable beyond the table: none when the
    // table has all of it, x87 never counted.
    #[test]
    fn test_unenforced() {
        let partition = FP | SSE | YMM | PKRU;
        assert_eq!(unenforced(partition, FP | SSE | YMM | PKRU), 0);
        assert_eq!(unenforced(partition, FP | SSE | YMM), PKRU);
        // A static template on a host without MPX, AVX-512 or PKRU.
        assert_eq!(unenforced(FP | SSE | YMM, guest_supported(Some((0x7, 0)), KVM_SUPPORTED)), 0);
        // No leaf 0xD: all but x87.
        assert_eq!(unenforced(partition, 0), SSE | YMM | PKRU);
        assert_eq!(unenforced(FP, 0), 0);
    }

    #[test]
    fn test_names() {
        assert_eq!(names(PKRU | AVX512 | BNDREGS | BNDCSR), "MPX BNDREGS, MPX BNDCSR, AVX-512 opmask, AVX-512 ZMM_Hi256, AVX-512 Hi16_ZMM, PKRU");
        assert_eq!(names(XTILE | (1 << 19)), "AMX TILECFG, AMX TILEDATA, bit 19");
        assert_eq!(names(0), "");
    }
}
