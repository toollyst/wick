// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Translation between KVM `ONE_REG` ids (arm64) and Hypervisor.framework registers.

use kvm_bindings::{
    KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM_CORE, KVM_REG_ARM64, KVM_REG_ARM64_SYSREG,
    KVM_REG_SIZE_MASK, KVM_REG_SIZE_SHIFT, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64, KVM_REG_SIZE_U128,
};

use super::ffi::*;

/// Size in bytes of the register `reg_id` (same as `kvm_ioctls::reg_size`).
pub fn reg_size(reg_id: u64) -> usize {
    2_usize.pow(((reg_id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT) as u32)
}

/// A KVM register id, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    /// General purpose register (`HV_REG_X0..=HV_REG_X30`), `PC`, or `CPSR` (PSTATE).
    Gp(hv_reg_t),
    /// System register.
    Sys(hv_sys_reg_t),
    /// SIMD/FP register `V<n>`.
    Simd(u32),
    /// `FPSR` or `FPCR` (32-bit in KVM, 64-bit in Hypervisor.framework).
    Fp(hv_reg_t),
    /// KVM `TIMER_CNT`: the guest virtual counter (`CNTVCT_EL0`).
    VirtualCount,
    /// KVM `PTIMER_CNT`: the physical counter. Read only here (KVM allows
    /// writing it only with `KVM_CAP_COUNTER_OFFSET`, which is not offered).
    PhysicalCount,
    /// AArch32 banked SPSRs (abt, und, irq, fiq). AArch32 is not offered, so
    /// they read as 0 and only 0 can be written.
    Aarch32Spsr,
    /// `KVM_REG_ARM_PSCI_VERSION`: the PSCI version the guest is given, 1.0
    /// or 0.2 (a snapshot taken before 1.0 was offered). As KVM's, one for
    /// the VM.
    PsciVersion,
    /// `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_<n>` (n 1 to 3): how far the
    /// firmware mitigates Spectre v2, v4 and BHB for the guest. Not kept:
    /// read from what the host says, written only to be checked against it
    /// (hypercalls.c `get_kernel_wa_level`, `kvm_arm_set_fw_reg`).
    Workaround(u8),
    /// One of KVM's bitmaps of the services the guest may call
    /// (`KVM_REG_ARM_FW_FEAT_BMAP_REG`). One for the VM, as KVM's.
    Bmap(Bmap),
    /// `OSLSR_EL1`: the OS lock, which the VMM emulates (Hypervisor.framework
    /// has no such register); listed and restored as KVM's.
    OsLock,
}

/// A bitmap register of `KVM_REG_ARM_FW_FEAT_BMAP`: its number there, and
/// the index of its value in `VmInner::smccc_features`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bmap {
    /// `KVM_REG_ARM_STD_BMAP`: the standard secure services. Bit 0
    /// (`KVM_REG_ARM_STD_BIT_TRNG_V1_0`): the TRNG's five calls.
    Std = 0,
    /// `KVM_REG_ARM_STD_HYP_BMAP`: the standard hypervisor services. Bit 0
    /// (`KVM_REG_ARM_STD_HYP_BIT_PV_TIME`): PV time's two calls.
    StdHyp = 1,
    /// `KVM_REG_ARM_VENDOR_HYP_BMAP`: KVM's own services. Bit 0
    /// (`KVM_REG_ARM_VENDOR_HYP_BIT_FUNC_FEAT`): the UID and the features
    /// call; bit 1 (`KVM_REG_ARM_VENDOR_HYP_BIT_PTP`): KVM_PTP.
    VendorHyp = 2,
}

impl Bmap {
    /// The bits KVM knows, all set in a new VM (hypercalls.c
    /// `KVM_ARM_SMCCC_*_FEATURES`, `kvm_arm_init_hypercalls`; the bit
    /// counts are Linux 6.1's include/uapi `asm/kvm.h`).
    pub const fn features(self) -> u64 {
        match self {
            Bmap::Std | Bmap::StdHyp => 0b1,
            Bmap::VendorHyp => 0b11,
        }
    }

    /// The KVM register id.
    pub const fn id(self) -> u64 {
        KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_FW_FEAT_BMAP | self as u64
    }
}

/// A new VM's bitmaps, indexed by [`Bmap`].
pub const SMCCC_FEATURES: [u64; 3] = [Bmap::Std.features(), Bmap::StdHyp.features(), Bmap::VendorHyp.features()];

impl Reg {
    /// Whether it is one of KVM's firmware pseudo-registers, which belong
    /// to the VM and to no Hypervisor.framework vCPU.
    pub fn is_firmware(self) -> bool {
        matches!(self, Reg::PsciVersion | Reg::Workaround(_) | Reg::Bmap(_))
    }
}

const CORE: u64 = KVM_REG_ARM64 | KVM_REG_ARM_CORE as u64;
const SYSREG: u64 = KVM_REG_ARM64 | KVM_REG_ARM64_SYSREG as u64;
/// `KVM_REG_ARM_FW` coprocessor (PSCI version and similar pseudo registers).
const KVM_REG_ARM_FW: u64 = 0x0014 << 16;
/// `KVM_REG_ARM_FW_FEAT_BMAP` coprocessor (the bitmaps of services).
const KVM_REG_ARM_FW_FEAT_BMAP: u64 = 0x0016 << 16;

/// KVM's encoding of `KVM_REG_ARM_TIMER_CNT`: `ARM64_SYS_REG(3, 3, 14, 3, 2)`.
pub(crate) const KVM_TIMER_CNT: u16 = 0xdf1a;
/// KVM's encoding of `KVM_REG_ARM_TIMER_CVAL`: `ARM64_SYS_REG(3, 3, 14, 0, 2)`.
const KVM_TIMER_CVAL: u16 = 0xdf02;
/// KVM's encoding of `KVM_REG_ARM_TIMER_CTL`: `ARM64_SYS_REG(3, 3, 14, 3, 1)`.
const KVM_TIMER_CTL: u16 = 0xdf19;
/// `KVM_REG_ARM_PTIMER_CNT`: `ARM64_SYS_REG(3, 3, 14, 0, 1)`.
const KVM_PTIMER_CNT: u16 = 0xdf01;

// Offsets in `struct kvm_regs`, in units of u32 (as used in core register ids).
const OFF_SP: u64 = 62;
const OFF_PC: u64 = 64;
const OFF_PSTATE: u64 = 66;
const OFF_SP_EL1: u64 = 68;
const OFF_ELR_EL1: u64 = 70;
const OFF_SPSR: u64 = 72; // 5 x u64
const OFF_VREGS: u64 = 84; // 32 x u128
const OFF_FPSR: u64 = 212;
const OFF_FPCR: u64 = 213;

/// Decodes a KVM register id. Returns `None` for ids this backend does not know.
pub fn decode(id: u64) -> Option<Reg> {
    if id & KVM_REG_ARM64 != KVM_REG_ARM64 {
        return None;
    }
    let coproc = id & KVM_REG_ARM_COPROC_MASK as u64;
    let low = id & 0xffff;
    match coproc {
        c if c == KVM_REG_ARM_CORE as u64 => match low {
            o if o < OFF_SP && o % 2 == 0 => Some(Reg::Gp(HV_REG_X0 + (o / 2) as u32)),
            OFF_SP => Some(Reg::Sys(HV_SYS_REG_SP_EL0)),
            OFF_PC => Some(Reg::Gp(HV_REG_PC)),
            OFF_PSTATE => Some(Reg::Gp(HV_REG_CPSR)),
            OFF_SP_EL1 => Some(Reg::Sys(HV_SYS_REG_SP_EL1)),
            OFF_ELR_EL1 => Some(Reg::Sys(HV_SYS_REG_ELR_EL1)),
            OFF_SPSR => Some(Reg::Sys(HV_SYS_REG_SPSR_EL1)),
            o if o > OFF_SPSR && o < OFF_VREGS && o % 2 == 0 => Some(Reg::Aarch32Spsr),
            o if (OFF_VREGS..OFF_FPSR).contains(&o) && (o - OFF_VREGS).is_multiple_of(4) => {
                Some(Reg::Simd(((o - OFF_VREGS) / 4) as u32))
            }
            OFF_FPSR => Some(Reg::Fp(HV_REG_FPSR)),
            OFF_FPCR => Some(Reg::Fp(HV_REG_FPCR)),
            _ => None,
        },
        c if c == KVM_REG_ARM64_SYSREG as u64 => match low as u16 {
            KVM_TIMER_CNT => Some(Reg::VirtualCount),
            KVM_TIMER_CVAL => Some(Reg::Sys(HV_SYS_REG_CNTV_CVAL_EL0)),
            KVM_TIMER_CTL => Some(Reg::Sys(HV_SYS_REG_CNTV_CTL_EL0)),
            KVM_PTIMER_CNT => Some(Reg::PhysicalCount),
            OSLSR_EL1 => Some(Reg::OsLock),
            r => Some(Reg::Sys(r)),
        },
        // KVM takes these by their whole id (hypercalls.c
        // kvm_arm_get_fw_reg: `switch (reg->id)`): 64 bits wide only.
        KVM_REG_ARM_FW | KVM_REG_ARM_FW_FEAT_BMAP if id & KVM_REG_SIZE_MASK != KVM_REG_SIZE_U64 => None,
        KVM_REG_ARM_FW => match low {
            0 => Some(Reg::PsciVersion),
            1..=3 => Some(Reg::Workaround(low as u8)),
            _ => None,
        },
        KVM_REG_ARM_FW_FEAT_BMAP => match low {
            0 => Some(Reg::Bmap(Bmap::Std)),
            1 => Some(Reg::Bmap(Bmap::StdHyp)),
            2 => Some(Reg::Bmap(Bmap::VendorHyp)),
            _ => None,
        },
        _ => None,
    }
}

fn core_id(size: u64, off: u64) -> u64 {
    CORE | size | off
}

/// `OSLSR_EL1` (op0 2, op1 0, CRn 1, CRm 1, op2 4).
const OSLSR_EL1: u16 = 0x808c;

pub(crate) fn sys_id(enc: u16) -> u64 {
    SYSREG | KVM_REG_SIZE_U64 | u64::from(enc)
}

/// System registers that carry guest state (saved in snapshots).
const STATE_SYSREGS: &[u16] = &[
    0xc000, // MIDR_EL1
    0xc005, // MPIDR_EL1
    0x8012, // MDSCR_EL1
    0xc080, // SCTLR_EL1
    0xc082, // CPACR_EL1
    0xc100, // TTBR0_EL1
    0xc101, // TTBR1_EL1
    0xc102, // TCR_EL1
    0xc108,
    0xc109,
    0xc10a,
    0xc10b, // APIA/APIB keys
    0xc110,
    0xc111,
    0xc112,
    0xc113, // APDA/APDB keys
    0xc118,
    0xc119, // APGA key
    0xc288, // AFSR0_EL1
    0xc289, // AFSR1_EL1
    0xc290, // ESR_EL1
    0xc300, // FAR_EL1
    0xc3a0, // PAR_EL1
    0xc510, // MAIR_EL1
    0xc518, // AMAIR_EL1
    0xc600, // VBAR_EL1
    0xc681, // CONTEXTIDR_EL1
    0xc684, // TPIDR_EL1
    0xc708, // CNTKCTL_EL1
    0xd000, // CSSELR_EL1
    0xde82, // TPIDR_EL0
    0xde83, // TPIDRRO_EL0
    KVM_TIMER_CTL,
    KVM_TIMER_CVAL,
    KVM_TIMER_CNT,
];

/// The firmware pseudo-registers, in the order KVM lists them
/// (hypercalls.c `kvm_arm_fw_reg_ids`).
pub const FW_REGS: [u64; 7] = [
    PSCI_VERSION_ID,
    workaround_id(1),
    workaround_id(2),
    workaround_id(3),
    Bmap::Std.id(),
    Bmap::StdHyp.id(),
    Bmap::VendorHyp.id(),
];

/// KVM register id of `KVM_REG_ARM_SMCCC_ARCH_WORKAROUND_<n>`.
pub const fn workaround_id(n: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_FW | n
}

/// The register ids reported by `KVM_GET_REG_LIST`.
pub fn reg_list() -> Vec<u64> {
    let mut ids = Vec::with_capacity(128);
    for i in 0..31 {
        ids.push(core_id(KVM_REG_SIZE_U64, i * 2));
    }
    for off in [
        OFF_SP,
        OFF_PC,
        OFF_PSTATE,
        OFF_SP_EL1,
        OFF_ELR_EL1,
        OFF_SPSR,
    ] {
        ids.push(core_id(KVM_REG_SIZE_U64, off));
    }
    for i in 0..32 {
        ids.push(core_id(KVM_REG_SIZE_U128, OFF_VREGS + i * 4));
    }
    ids.push(core_id(KVM_REG_SIZE_U32, OFF_FPSR));
    ids.push(core_id(KVM_REG_SIZE_U32, OFF_FPCR));
    // KVM's firmware registers come after the core ones (guest.c
    // kvm_arm_copy_reg_indices): Firecracker saves every listed register,
    // so a snapshot keeps the PSCI version and the services' bitmaps.
    ids.extend(FW_REGS);
    ids.extend(STATE_SYSREGS.iter().map(|r| sys_id(*r)));
    // DBGBVRn, DBGBCRn, DBGWVRn, DBGWCRn (op0 2, op1 0, CRn 0, CRm n, op2 4
    // to 7), all 16 of each whatever the host has, as KVM lists them
    // (arch/arm64/kvm/sys_regs.c DBG_BCR_BVR_WCR_WVR_EL1(0..15), kept per
    // vCPU in vcpu_debug_state by get_bvr/set_bvr); Hypervisor.framework
    // keeps all 16 too (measured on a host with 6 breakpoints and 4
    // watchpoints: every one reads back what was written).
    for n in 0..16u16 {
        for op2 in 4..=7u16 {
            ids.push(sys_id(0x8000 | n << 3 | op2));
        }
    }
    // KVM lists OSLSR_EL1 (its descriptor has set_user), so a snapshot keeps
    // the OS lock.
    ids.push(sys_id(OSLSR_EL1));
    ids
}

/// PSCI 0.2 as encoded in `KVM_REG_ARM_PSCI_VERSION` (`major << 16 | minor`).
pub const PSCI_VERSION_0_2: u64 = 2;
/// PSCI 1.0, the version this backend offered before 1.1: a snapshot taken
/// then restores it.
pub const PSCI_VERSION_1_0: u64 = 0x1_0000;
/// PSCI 1.1, the version a new VM's guest is given, as KVM's
/// (include/kvm/arm_psci.h `KVM_ARM_PSCI_LATEST`).
pub const PSCI_VERSION_1_1: u64 = 0x1_0001;

/// KVM register id of `KVM_REG_ARM_PSCI_VERSION`.
pub const PSCI_VERSION_ID: u64 = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_FW;

/// KVM register id of `SCTLR_EL1`.
pub const SCTLR_ID: u64 = SYSREG | KVM_REG_SIZE_U64 | 0xc080;
/// `PSTATE` after `KVM_ARM_VCPU_INIT`: EL1h with D, A, I and F masked.
pub const PSTATE_RESET: u64 = 0x3c5;
/// `SCTLR_EL1` after `KVM_ARM_VCPU_INIT` (Linux `arch/arm64/kvm/sys_regs.c`).
pub const SCTLR_RESET: u64 = 0x00c5_0078;

/// KVM register id of `PSTATE`.
#[allow(dead_code)]
pub const PSTATE_ID: u64 = CORE | KVM_REG_SIZE_U64 | OFF_PSTATE;
/// KVM register id of `PC`.
#[allow(dead_code)]
pub const PC_ID: u64 = CORE | KVM_REG_SIZE_U64 | OFF_PC;
/// KVM register id of `MPIDR_EL1`.
#[cfg(test)]
pub const MPIDR_ID: u64 = SYSREG | KVM_REG_SIZE_U64 | HV_SYS_REG_MPIDR_EL1 as u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_core() {
        assert_eq!(decode(core_id(KVM_REG_SIZE_U64, 0)), Some(Reg::Gp(0)));
        assert_eq!(decode(core_id(KVM_REG_SIZE_U64, 60)), Some(Reg::Gp(30)));
        assert_eq!(decode(PC_ID), Some(Reg::Gp(HV_REG_PC)));
        assert_eq!(decode(PSTATE_ID), Some(Reg::Gp(HV_REG_CPSR)));
        assert_eq!(
            decode(core_id(KVM_REG_SIZE_U128, OFF_VREGS + 4)),
            Some(Reg::Simd(1))
        );
        assert_eq!(
            decode(core_id(KVM_REG_SIZE_U32, OFF_FPCR)),
            Some(Reg::Fp(HV_REG_FPCR))
        );
        assert_eq!(decode(core_id(KVM_REG_SIZE_U64, 1)), None);
    }

    #[test]
    fn test_decode_sys() {
        assert_eq!(decode(MPIDR_ID), Some(Reg::Sys(HV_SYS_REG_MPIDR_EL1)));
        assert_eq!(decode(sys_id(KVM_TIMER_CNT)), Some(Reg::VirtualCount));
        assert_eq!(
            decode(sys_id(KVM_TIMER_CVAL)),
            Some(Reg::Sys(HV_SYS_REG_CNTV_CVAL_EL0))
        );
    }

    #[test]
    fn test_reg_list_decodes() {
        for id in reg_list() {
            assert!(decode(id).is_some(), "{id:#x}");
        }
        assert_eq!(reg_size(PC_ID), 8);
    }

    // The ids are KVM's (Linux 6.1 include/uapi asm/kvm.h
    // KVM_REG_ARM_FW_REG(0..3), KVM_REG_ARM_FW_FEAT_BMAP_REG(0..2)), listed
    // in KVM's order after the core registers, and taken 64 bits wide only.
    #[test]
    fn test_firmware_registers_are_kvms() {
        assert_eq!(
            FW_REGS,
            [
                0x6030_0000_0014_0000,
                0x6030_0000_0014_0001,
                0x6030_0000_0014_0002,
                0x6030_0000_0014_0003,
                0x6030_0000_0016_0000,
                0x6030_0000_0016_0001,
                0x6030_0000_0016_0002,
            ]
        );
        let list = reg_list();
        let first = list.iter().position(|id| *id == FW_REGS[0]).unwrap();
        assert_eq!(list[first..first + 7], FW_REGS);
        assert_eq!(list[first - 1], core_id(KVM_REG_SIZE_U32, OFF_FPCR));
        assert_eq!(decode(FW_REGS[0]), Some(Reg::PsciVersion));
        assert_eq!(decode(FW_REGS[2]), Some(Reg::Workaround(2)));
        assert_eq!(decode(FW_REGS[5]), Some(Reg::Bmap(Bmap::StdHyp)));
        for id in FW_REGS {
            assert_eq!(decode(id & !KVM_REG_SIZE_MASK | KVM_REG_SIZE_U32), None, "{id:#x}");
        }
        assert_eq!(decode(workaround_id(4)), None);
        assert_eq!(decode(Bmap::VendorHyp.id() + 1), None);
        assert_eq!(SMCCC_FEATURES, [1, 1, 3]);
    }
}
