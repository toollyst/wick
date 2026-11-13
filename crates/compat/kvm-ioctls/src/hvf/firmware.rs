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
//!
//! What the host gives is what Linux decides for the host's CPU
//! (arch/arm64/kernel/proton-pack.c), from its ID registers and MIDR
//! ([`HostCpu`]): the state of Spectre v2, v4 and BHB, which KVM's
//! SMCCC_ARCH_FEATURES answers a guest by and the three levels follow. The
//! rules are those of Linux 6.1 as its stable series has them (6.1.192):
//! the release of 6.1 itself took a CPU none of its lists names as
//! unaffected by Spectre-BHB, where every later 6.1 takes it as affected
//! (`is_spectre_bhb_affected`: "the core isn't known to be safe so we're
//! going to assume it's vulnerable"). Three things Linux also weighs have
//! one value on a Mac: there is no firmware below the kernel to ask for a
//! workaround (no EL3, no SMCCC conduit: Linux reads NOT_SUPPORTED), the
//! mitigations are not turned off on a command line, and
//! Hypervisor.framework shows one set of ID registers for all cores.

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

/// A Spectre variant's state on a host, as Linux keeps it
/// (arch/arm64/include/asm/spectre.h `enum mitigation_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Spectre {
    Unaffected,
    Mitigated,
    Vulnerable,
}

/// The host CPU's registers Linux decides the three states from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HostCpu {
    pub midr: u64,
    /// ID_AA64PFR0_EL1 (CSV2, bits 59:56).
    pub pfr0: u64,
    /// ID_AA64PFR1_EL1 (SSBS, bits 7:4).
    pub pfr1: u64,
    /// ID_AA64MMFR1_EL1 (ECBHB, bits 63:60).
    pub mmfr1: u64,
    /// ID_AA64ISAR2_EL1 (CLRBHB, bits 31:28).
    pub isar2: u64,
}

/// `MIDR_CPU_MODEL_MASK`: implementer, architecture and part number.
const MODEL_MASK: u64 = 0xff0f_fff0;

// The cores of Linux's lists (arch/arm64/include/asm/cputype.h
// `MIDR_CPU_MODEL(imp, partnum)`), every variant and revision
// (`MIDR_ALL_VERSIONS`).
const CORTEX_A35: u64 = 0x410f_d040;
const CORTEX_A53: u64 = 0x410f_d030;
const CORTEX_A55: u64 = 0x410f_d050;
const CORTEX_A57: u64 = 0x410f_d070;
const CORTEX_A72: u64 = 0x410f_d080;
const CORTEX_A76: u64 = 0x410f_d0b0;
const CORTEX_A76AE: u64 = 0x410f_d0e0;
const CORTEX_A77: u64 = 0x410f_d0d0;
const CORTEX_A78: u64 = 0x410f_d410;
const CORTEX_A78AE: u64 = 0x410f_d420;
const CORTEX_A78C: u64 = 0x410f_d4b0;
const CORTEX_A510: u64 = 0x410f_d460;
const CORTEX_A520: u64 = 0x410f_d800;
const CORTEX_A710: u64 = 0x410f_d470;
const CORTEX_A715: u64 = 0x410f_d4d0;
const CORTEX_A720: u64 = 0x410f_d810;
const CORTEX_X1: u64 = 0x410f_d440;
const CORTEX_X1C: u64 = 0x410f_d4c0;
const CORTEX_X2: u64 = 0x410f_d480;
const CORTEX_X3: u64 = 0x410f_d4e0;
const NEOVERSE_N1: u64 = 0x410f_d0c0;
const NEOVERSE_N2: u64 = 0x410f_d490;
const NEOVERSE_V1: u64 = 0x410f_d400;
const NEOVERSE_V2: u64 = 0x410f_d4f0;
const BRAHMA_B53: u64 = 0x420f_1000;
const HISI_TSV110: u64 = 0x480f_d010;
const HISI_HIP09: u64 = 0x480f_d020;
const QCOM_KRYO_2XX_SILVER: u64 = 0x510f_8010;
const QCOM_KRYO_3XX_SILVER: u64 = 0x510f_8030;
const QCOM_KRYO_4XX_GOLD: u64 = 0x510f_8040;
const QCOM_KRYO_4XX_SILVER: u64 = 0x510f_8050;
const AMPERE1: u64 = 0xc00f_ac30;

/// `spectre_v2_safe_list` (spectre_v2_get_cpu_hw_mitigation_state).
const V2_SAFE: &[u64] = &[
    CORTEX_A35,
    CORTEX_A53,
    CORTEX_A55,
    BRAHMA_B53,
    HISI_TSV110,
    QCOM_KRYO_2XX_SILVER,
    QCOM_KRYO_3XX_SILVER,
    QCOM_KRYO_4XX_SILVER,
];
/// `spectre_v4_safe_list` (spectre_v4_get_cpu_hw_mitigation_state).
const V4_SAFE: &[u64] =
    &[CORTEX_A35, CORTEX_A53, CORTEX_A55, BRAHMA_B53, QCOM_KRYO_3XX_SILVER, QCOM_KRYO_4XX_SILVER];
/// `spectre_bhb_safe_list` (is_spectre_bhb_safe).
const BHB_SAFE: &[u64] = &[
    CORTEX_A35,
    CORTEX_A53,
    CORTEX_A55,
    CORTEX_A510,
    CORTEX_A520,
    BRAHMA_B53,
    QCOM_KRYO_2XX_SILVER,
    QCOM_KRYO_3XX_SILVER,
    QCOM_KRYO_4XX_SILVER,
];
/// The cores `spectre_bhb_loop_affected` has a loop count for (its k132,
/// k38, k32, k24, k11 and k8 lists): mitigated by the loop.
const BHB_LOOP: &[u64] = &[
    CORTEX_X3,
    NEOVERSE_V2,
    CORTEX_A715,
    CORTEX_A720,
    CORTEX_A78,
    CORTEX_A78AE,
    CORTEX_A78C,
    CORTEX_X1,
    CORTEX_X1C,
    CORTEX_A710,
    CORTEX_X2,
    NEOVERSE_N2,
    NEOVERSE_V1,
    HISI_TSV110,
    CORTEX_A76,
    CORTEX_A76AE,
    CORTEX_A77,
    NEOVERSE_N1,
    QCOM_KRYO_4XX_GOLD,
    HISI_HIP09,
    AMPERE1,
    CORTEX_A72,
    CORTEX_A57,
];

impl HostCpu {
    /// From `id`, which gives a system register by its encoding
    /// (`op0:op1:CRn:CRm:op2`), 0 for one the host does not have.
    pub(crate) fn read(id: impl Fn(u16) -> u64) -> Self {
        HostCpu { midr: id(0xc000), pfr0: id(0xc020), pfr1: id(0xc021), mmfr1: id(0xc039), isar2: id(0xc032) }
    }

    fn is(&self, list: &[u64]) -> bool {
        list.contains(&(self.midr & MODEL_MASK))
    }

    fn csv2(&self) -> u64 {
        self.pfr0 >> 56 & 0xf
    }

    /// The `ARM64_SSBS` capability (cpufeature.c: ID_AA64PFR1_EL1.SSBS at
    /// least 1).
    fn ssbs(&self) -> bool {
        self.pfr1 >> 4 & 0xf != 0
    }

    /// Spectre v2 (proton-pack.c `spectre_v2_enable_mitigation`): a CPU
    /// with CSV2, or of the safe list, is unaffected
    /// (`spectre_v2_get_cpu_hw_mitigation_state`). Any other asks its
    /// firmware for ARCH_WORKAROUND_1; with none, as here, it is vulnerable.
    pub(crate) fn spectre_v2(&self) -> Spectre {
        if self.csv2() != 0 || self.is(V2_SAFE) { Spectre::Unaffected } else { Spectre::Vulnerable }
    }

    /// Spectre v4 (`spectre_v4_enable_mitigation`): a CPU of the safe list
    /// is unaffected, one with SSBS mitigated
    /// (`spectre_v4_enable_hw_mitigation`); any other asks its firmware for
    /// ARCH_WORKAROUND_2 and, with none, is vulnerable.
    pub(crate) fn spectre_v4(&self) -> Spectre {
        if self.is(V4_SAFE) {
            Spectre::Unaffected
        } else if self.ssbs() {
            Spectre::Mitigated
        } else {
            Spectre::Vulnerable
        }
    }

    /// Spectre-BHB (`is_spectre_bhb_affected`, `spectre_bhb_enable_mitigation`):
    /// unaffected with CSV2 at 3 or on the safe list; every other CPU is
    /// taken as affected, and is mitigated by ECBHB, by the ClearBHB
    /// instruction or, for the cores Linux has a count for, by its loop,
    /// but never while Spectre v2 is vulnerable ("No point mitigating
    /// Spectre-BHB alone"). The firmware's ARCH_WORKAROUND_3 is the last
    /// resort, and there is none here.
    pub(crate) fn spectre_bhb(&self) -> Spectre {
        if self.csv2() == 3 || self.is(BHB_SAFE) {
            return Spectre::Unaffected;
        }
        let ecbhb = self.mmfr1 >> 60 != 0;
        let clrbhb = self.isar2 >> 28 & 0xf != 0;
        if self.spectre_v2() != Spectre::Vulnerable && (ecbhb || clrbhb || self.is(BHB_LOOP)) {
            Spectre::Mitigated
        } else {
            Spectre::Vulnerable
        }
    }

    /// SMCCC_ARCH_FEATURES' X0 for `ARM_SMCCC_ARCH_WORKAROUND_<n>`
    /// (hypercalls.c `kvm_hvc_call_handler`), `None` where KVM leaves
    /// NOT_SUPPORTED. WORKAROUND_1 and _3: 0 if mitigated, 1
    /// (`SMCCC_ARCH_WORKAROUND_RET_UNAFFECTED`) if unaffected. WORKAROUND_2:
    /// 2 (`SMCCC_RET_NOT_REQUIRED`) if unaffected; a mitigated host has
    /// SSBS here, for which KVM reports no firmware support ("the SSBS
    /// support will be indicated to the guest and the default is safe").
    pub(crate) fn workaround_feature(&self, n: u8) -> Option<u64> {
        let by_state = |state| match state {
            Spectre::Unaffected => Some(1),
            Spectre::Mitigated => Some(0),
            Spectre::Vulnerable => None,
        };
        match n {
            1 => by_state(self.spectre_v2()),
            2 => match self.spectre_v4() {
                Spectre::Unaffected => Some(2),
                Spectre::Mitigated if !self.ssbs() => Some(2),
                _ => None,
            },
            3 => by_state(self.spectre_bhb()),
            _ => None,
        }
    }

    /// `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_<n>`'s level on this host
    /// (hypercalls.c `get_kernel_wa_level`). WORKAROUND_1 and _3: NOT_AVAIL
    /// (0), AVAIL (1) or NOT_REQUIRED (2); WORKAROUND_2: NOT_AVAIL (0) or
    /// NOT_REQUIRED (3).
    pub(crate) fn workaround_level(&self, n: u8) -> u64 {
        match (n, self.workaround_feature(n)) {
            (_, None) => 0,
            (2, Some(_)) => WORKAROUND_2_NOT_REQUIRED,
            (_, Some(0)) => 1,
            (_, Some(_)) => 2,
        }
    }
}

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
        let level = 0;
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

    fn cpu(midr: u64, csv2: u64, ssbs: u64, ecbhb: u64, clrbhb: u64) -> HostCpu {
        HostCpu { midr, pfr0: csv2 << 56, pfr1: ssbs << 4, mmfr1: ecbhb << 60, isar2: clrbhb << 28 }
    }

    // Linux's rules (6.1.192 arch/arm64/kernel/proton-pack.c) on a host
    // whose firmware offers no workaround, and KVM's answers from them
    // (hypercalls.c kvm_hvc_call_handler, get_kernel_wa_level), for cores
    // of each kind. `None` is NOT_SUPPORTED.
    #[test]
    fn test_the_workarounds_follow_the_cpus_spectre_state_as_linux_decides_it() {
        use Spectre::{Mitigated, Unaffected, Vulnerable};
        // An Apple core (implementer 0x61): on none of Linux's lists.
        let apple = 0x611f_0250;
        let cases: [(&str, HostCpu, [Spectre; 3], [Option<u64>; 3], [u64; 3]); 10] = [
            // No CSV2, no SSBS, a loop count for BHB, but v2 vulnerable.
            ("Cortex-A72", cpu(0x410f_d080, 0, 0, 0, 0), [Vulnerable; 3], [None; 3], [0; 3]),
            // On all three safe lists, every revision.
            ("Cortex-A53 r0p4", cpu(0x410f_d034, 0, 0, 0, 0), [Unaffected; 3], [Some(1), Some(2), Some(1)], [2, 3, 2]),
            // On the v2 safe list alone: v4 vulnerable, BHB by its loop.
            ("TSV110", cpu(0x480f_d010, 0, 0, 0, 0), [Unaffected, Vulnerable, Mitigated], [Some(1), None, Some(0)], [2, 0, 1]),
            // CSV2 and SSBS, BHB by the loop: WORKAROUND_3 is offered.
            (
                "Neoverse-N1",
                cpu(0x414f_d0c1, 1, 2, 0, 0),
                [Unaffected, Mitigated, Mitigated],
                [Some(1), None, Some(0)],
                [2, 0, 1],
            ),
            ("CSV2 at 3", cpu(apple, 3, 1, 0, 0), [Unaffected, Mitigated, Unaffected], [Some(1), None, Some(1)], [2, 0, 2]),
            // A core no list names, CSV2 below 3: affected by BHB, and
            // mitigated only by ECBHB or ClearBHB.
            ("CSV2, SSBS", cpu(apple, 1, 1, 0, 0), [Unaffected, Mitigated, Vulnerable], [Some(1), None, None], [2, 0, 0]),
            ("CSV2 at 2, no SSBS", cpu(apple, 2, 0, 0, 0), [Unaffected, Vulnerable, Vulnerable], [Some(1), None, None], [2, 0, 0]),
            ("ECBHB", cpu(apple, 2, 2, 1, 0), [Unaffected, Mitigated, Mitigated], [Some(1), None, Some(0)], [2, 0, 1]),
            ("ClearBHB", cpu(apple, 1, 2, 0, 1), [Unaffected, Mitigated, Mitigated], [Some(1), None, Some(0)], [2, 0, 1]),
            // ClearBHB without CSV2: v2 vulnerable, so BHB is left so.
            ("ClearBHB, no CSV2", cpu(apple, 0, 2, 0, 1), [Vulnerable, Mitigated, Vulnerable], [None; 3], [0; 3]),
        ];
        for (name, cpu, states, features, levels) in cases {
            assert_eq!([cpu.spectre_v2(), cpu.spectre_v4(), cpu.spectre_bhb()], states, "{name}");
            assert_eq!([1, 2, 3].map(|n| cpu.workaround_feature(n)), features, "{name}");
            assert_eq!([1, 2, 3].map(|n| cpu.workaround_level(n)), levels, "{name}");
        }
        // The lists are by model: another part number of the same
        // implementer is not on them.
        assert_eq!(cpu(0x410f_d090, 0, 0, 0, 0).spectre_v2(), Vulnerable);
        // The registers are read by their encodings.
        let read = HostCpu::read(u64::from);
        assert_eq!(read, HostCpu { midr: 0xc000, pfr0: 0xc020, pfr1: 0xc021, mmfr1: 0xc039, isar2: 0xc032 });
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
