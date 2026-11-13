// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! KVM's firmware pseudo-registers other than the PSCI version, as Linux 6.1
//! keeps them (arch/arm64/kvm/hypercalls.c): the three
//! `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_<n>` levels and the three bitmaps of
//! the services a guest may call (`KVM_REG_ARM_STD_BMAP`,
//! `KVM_REG_ARM_STD_HYP_BMAP`, `KVM_REG_ARM_VENDOR_HYP_BMAP`). KVM lists
//! them in `KVM_GET_REG_LIST` (`kvm_arm_fw_reg_ids`), so Firecracker saves
//! them in a snapshot and writes them back on restore, and a CPU template
//! may write them before the guest starts.
//!
//! The rules here are KVM's, with no vCPU needed to check them:
//! - a bitmap takes only the bits KVM knows (`EINVAL`), and once a vCPU of
//!   the VM has run, only the value it has (`EBUSY`)
//!   (`kvm_arm_set_fw_reg_bmap`);
//! - a call whose bit is clear is answered NOT_SUPPORTED, with X1 to X3 0
//!   (`kvm_hvc_call_allowed`, `kvm_hvc_call_handler`);
//! - a workaround level reads as what the host gives the guest and takes
//!   only a level no higher (`get_kernel_wa_level`, `kvm_arm_set_fw_reg`).

use super::exit::Psci;
use super::regs::Bmap;

/// `KVM_REG_FEATURE_LEVEL_MASK`.
const LEVEL_MASK: u64 = 0xf;
/// `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_ENABLED`.
const WORKAROUND_2_ENABLED: u64 = 1 << 4;
/// `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_AVAIL`.
const WORKAROUND_2_AVAIL: u64 = 2;
/// `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_2_NOT_REQUIRED`.
const WORKAROUND_2_NOT_REQUIRED: u64 = 3;

/// `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_<n>_NOT_AVAIL`, the level of each of
/// the three here. KVM derives the level from the same host state as its
/// SMCCC_ARCH_FEATURES answer (`get_kernel_wa_level` beside
/// `kvm_hvc_call_handler`): NOT_SUPPORTED there, which is what this backend
/// answers for all three (`VcpuFd::psci`), goes with NOT_AVAIL here.
pub(crate) const WORKAROUND_LEVEL: u64 = 0;

/// Whether `KVM_SET_ONE_REG` of `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_<n>`
/// takes `value` where the host's level is `level` (`kvm_arm_set_fw_reg`).
/// Nothing is stored: KVM only checks that the guest was not promised more
/// than this host gives.
pub(crate) fn workaround_accepts(n: u8, value: u64, level: u64) -> bool {
    if n != 2 {
        return value & !LEVEL_MASK == 0 && value <= level;
    }
    if value & !(LEVEL_MASK | WORKAROUND_2_ENABLED) != 0 {
        return false;
    }
    // The enabled bit only with the level AVAIL.
    if value & WORKAROUND_2_ENABLED != 0 && value & LEVEL_MASK != WORKAROUND_2_AVAIL {
        return false;
    }
    // KVM narrows the four levels to two: NOT_AVAIL and UNKNOWN to
    // NOT_AVAIL (0), AVAIL and NOT_REQUIRED to NOT_REQUIRED (3).
    let wanted = match value & LEVEL_MASK {
        0 | 1 => 0,
        2 | 3 => WORKAROUND_2_NOT_REQUIRED,
        _ => return false,
    };
    wanted <= level
}

/// `KVM_SET_ONE_REG` of a bitmap (`kvm_arm_set_fw_reg_bmap`): `Err(EINVAL)`
/// for a bit KVM does not know, `Err(EBUSY)` for a change once the VM has
/// run, else the value to keep.
pub(crate) fn bmap_write(bmap: Bmap, current: u64, value: u64, ran_once: bool) -> Result<u64, i32> {
    if value & !bmap.features() != 0 {
        return Err(libc::EINVAL);
    }
    if ran_once && value != current {
        return Err(libc::EBUSY);
    }
    Ok(value)
}

/// Whether the guest may make `call` with the VM's bitmaps `features`
/// (indexed by [`Bmap`]), as `kvm_hvc_call_allowed` decides: the TRNG's
/// calls by the standard bitmap's bit 0, PV time's by the standard
/// hypervisor bitmap's bit 0, KVM's UID and features calls by the vendor
/// bitmap's bit 0 and KVM_PTP by its bit 1. Every other call this backend
/// answers is allowed whatever the bitmaps say (`kvm_hvc_call_default_allowed`:
/// SMCCC_VERSION, SMCCC_ARCH_FEATURES and the PSCI range).
pub(crate) fn allowed(call: Psci, features: &[u64; 3]) -> bool {
    let bit = |bmap: Bmap, bit: u32| features[bmap as usize] >> bit & 1 == 1;
    match call {
        Psci::TrngVersion | Psci::TrngFeatures | Psci::TrngGetUuid | Psci::TrngRnd32 | Psci::TrngRnd64 => {
            bit(Bmap::Std, 0)
        }
        Psci::PvTimeFeatures | Psci::PvTimeSt => bit(Bmap::StdHyp, 0),
        Psci::KvmFeatures | Psci::VendorHypUid => bit(Bmap::VendorHyp, 0),
        Psci::KvmPtp => bit(Bmap::VendorHyp, 1),
        _ => true,
    }
}

/// Whether SMCCC_ARCH_FEATURES reports PV_TIME_FEATURES: by the standard
/// hypervisor bitmap's PV time bit (`kvm_hvc_call_handler`).
pub(crate) fn pv_time_reported(features: &[u64; 3]) -> bool {
    features[Bmap::StdHyp as usize] & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::super::regs::SMCCC_FEATURES;
    use super::*;

    // kvm_arm_set_fw_reg with every host level NOT_AVAIL: WORKAROUND_1 and
    // _3 take 0 only (a level above the host's, or a bit outside the level
    // mask, is EINVAL); WORKAROUND_2 takes NOT_AVAIL (0) and UNKNOWN (1),
    // which KVM narrows to NOT_AVAIL, and not AVAIL or NOT_REQUIRED, the
    // enabled bit (only valid with AVAIL), or any other bit.
    #[test]
    fn test_workaround_levels_are_taken_as_kvm_takes_them() {
        let level = WORKAROUND_LEVEL;
        assert_eq!(level, 0);
        for n in [1, 3] {
            assert!(workaround_accepts(n, 0, level));
            for value in [1, 2, 0xf, 0x10, 1 << 32] {
                assert!(!workaround_accepts(n, value, level), "{n} {value:#x}");
            }
        }
        assert!(workaround_accepts(2, 0, level) && workaround_accepts(2, 1, level));
        for value in [2, 3, 4, 0xf, 0x10, 0x11, 0x12, 0x13, 0x20, 1 << 32] {
            assert!(!workaround_accepts(2, value, level), "{value:#x}");
        }
        // The rule itself, for a host that gives more (none does here): a
        // level up to the host's; for WORKAROUND_2 with NOT_REQUIRED, every
        // level, and the enabled bit with AVAIL alone.
        assert!(workaround_accepts(1, 1, 2) && workaround_accepts(1, 2, 2) && !workaround_accepts(1, 3, 2));
        for value in [0, 1, 2, 3, 0x12] {
            assert!(workaround_accepts(2, value, 3), "{value:#x}");
        }
        for value in [4, 0x10, 0x11, 0x13] {
            assert!(!workaround_accepts(2, value, 3), "{value:#x}");
        }
    }

    // kvm_arm_set_fw_reg_bmap: an unknown bit is EINVAL before anything
    // else; after the first run only the value in place is taken (EBUSY).
    #[test]
    fn test_a_bitmap_takes_known_bits_and_no_change_after_the_first_run() {
        for (bmap, unknown) in [(Bmap::Std, 0b10), (Bmap::StdHyp, 0b10), (Bmap::VendorHyp, 0b100)] {
            let all = bmap.features();
            assert_eq!(bmap_write(bmap, all, 0, false), Ok(0));
            assert_eq!(bmap_write(bmap, 0, all, false), Ok(all));
            assert_eq!(bmap_write(bmap, all, unknown, false), Err(libc::EINVAL));
            assert_eq!(bmap_write(bmap, all, all | 1 << 63, true), Err(libc::EINVAL));
            assert_eq!(bmap_write(bmap, all, 0, true), Err(libc::EBUSY));
            assert_eq!(bmap_write(bmap, all, all, true), Ok(all));
            assert_eq!(bmap_write(bmap, 0, 0, true), Ok(0));
        }
        assert_eq!(bmap_write(Bmap::VendorHyp, 3, 1, false), Ok(1));
    }

    // kvm_hvc_call_allowed: each bit gates its calls and no other.
    #[test]
    fn test_each_bit_gates_its_calls() {
        let trng = [Psci::TrngVersion, Psci::TrngFeatures, Psci::TrngGetUuid, Psci::TrngRnd32, Psci::TrngRnd64];
        let pv = [Psci::PvTimeFeatures, Psci::PvTimeSt];
        let func = [Psci::KvmFeatures, Psci::VendorHypUid];
        let ptp = [Psci::KvmPtp];
        let always = [
            Psci::Version,
            Psci::Features,
            Psci::CpuOn,
            Psci::SystemReset2,
            Psci::SmcccVersion,
            Psci::SmcccArchFeatures,
            Psci::NotSupported,
        ];
        type Calls<'a> = &'a [&'a [Psci]];
        let cases: [(&[u64; 3], Calls, Calls); 6] = [
            (&SMCCC_FEATURES, &[&trng, &pv, &func, &ptp], &[]),
            (&[0, 1, 3], &[&pv, &func, &ptp], &[&trng]),
            (&[1, 0, 3], &[&trng, &func, &ptp], &[&pv]),
            (&[1, 1, 2], &[&trng, &pv, &ptp], &[&func]),
            (&[1, 1, 1], &[&trng, &pv, &func], &[&ptp]),
            (&[0, 0, 0], &[], &[&trng, &pv, &func, &ptp]),
        ];
        for (features, on, off) in cases {
            for call in on.iter().copied().flatten().chain(&always) {
                assert!(allowed(*call, features), "{call:?} {features:?}");
            }
            for call in off.iter().copied().flatten() {
                assert!(!allowed(*call, features), "{call:?} {features:?}");
            }
            assert_eq!(pv_time_reported(features), features[1] == 1);
        }
    }
}
