// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The CPU's ID registers as the guest sees them: `KVM_GET_ONE_REG` and
//! `KVM_SET_ONE_REG` of `MIDR_EL1` and the AArch64 feature registers
//! (`ID_AA64*_EL1`), the registers CPU templates change.
//!
//! As on KVM since Linux 6.7, they are the VM's, not a vCPU's: a write
//! through any vCPU sets them for all, and is accepted only before the VM
//! has run (after it, a different value is refused with `EBUSY`). A write
//! may lower the fields KVM lets user space change, never raise one above
//! the host's, and must leave every other field as the host has it
//! (`EINVAL`). Hypervisor.framework keeps a vCPU's ID registers
//! writable, and the guest's `mrs` reads what was written
//! (`test_id_register_writes_reach_the_guest`); each vCPU is given the
//! VM's values when it is created.
//!
//! The ID registers of the ID space (`op0 = 3, op1 = 0, CRn = 0,
//! CRm = 1..7`) that this Hypervisor.framework does not have read as 0
//! and take only 0, as KVM's unallocated ID registers.

/// The ID registers listed by `KVM_GET_REG_LIST`, if this
/// Hypervisor.framework has them (some are from macOS 15.2 or 27).
pub const ID_REGS: &[u16] = &[
    0xc020, // ID_AA64PFR0_EL1
    0xc021, // ID_AA64PFR1_EL1
    0xc022, // ID_AA64PFR2_EL1
    0xc024, // ID_AA64ZFR0_EL1
    0xc025, // ID_AA64SMFR0_EL1
    0xc028, // ID_AA64DFR0_EL1
    0xc029, // ID_AA64DFR1_EL1
    0xc030, // ID_AA64ISAR0_EL1
    0xc031, // ID_AA64ISAR1_EL1
    0xc032, // ID_AA64ISAR2_EL1
    0xc038, // ID_AA64MMFR0_EL1
    0xc039, // ID_AA64MMFR1_EL1
    0xc03a, // ID_AA64MMFR2_EL1
    0xc03b, // ID_AA64MMFR3_EL1
    0xc03c, // ID_AA64MMFR4_EL1
];

/// `ID_AA64ISAR1_EL1`'s pointer authentication fields (APA, API, GPA,
/// GPI) and `ID_AA64ISAR2_EL1`'s (GPA3, APA3): KVM shows them only to a vCPU
/// given `KVM_ARM_VCPU_PTRAUTH_ADDRESS` and `_GENERIC`
/// (`__kvm_read_sanitised_id_reg`).
pub fn ptrauth_fields(enc: u16) -> u64 {
    match enc {
        0xc031 => 0xff00_0ff0,
        0xc032 => 0xff00,
        _ => 0,
    }
}

/// Whether `enc` is a pointer authentication key register (APIA, APIB,
/// APDA, APDB, APGA; KEYLO and KEYHI). KVM hides them from a vCPU without
/// `KVM_ARM_VCPU_PTRAUTH_ADDRESS` and `_GENERIC`: not listed, and
/// `ENOENT` on get and set (arch/arm64/kvm/sys_regs.c `ptrauth_visibility`).
pub fn is_ptrauth_key(enc: u16) -> bool {
    matches!(enc, 0xc108..=0xc10b | 0xc110..=0xc113 | 0xc118 | 0xc119)
}

/// `MIDR_EL1`: invariant, as on KVM (Linux 6.1, the host kernel upstream's
/// templates are tested on): a different value is refused.
pub const MIDR: u16 = 0xc000;

/// Whether `enc` (a system register's `op0:op1:CRn:CRm:op2`) is an ID
/// register handled here.
pub fn is_id_reg(enc: u16) -> bool {
    enc == MIDR || in_id_space(enc)
}

/// The ID space: `op0 = 3, op1 = 0, CRn = 0, CRm = 1..7`.
fn in_id_space(enc: u16) -> bool {
    let crm = (enc >> 3) & 0xf;
    enc >> 7 == 0b1_1000_0000 && (1..=7).contains(&crm)
}

/// The 4-bit fields user space may lower, by shift, for each register: the
/// fields of Linux's writable masks (`arch/arm64/kvm/sys_regs.c`, from 6.7),
/// less the signed fields (written only unchanged here). Every field not
/// listed must keep the host's value.
fn lowerable(enc: u16) -> &'static [u32] {
    match enc {
        // ID_AA64PFR0_EL1: all but AMU, MPAM, SVE, RAS, GIC, AdvSIMD, FP.
        // EL0-EL3, SEL2, DIT, CSV2, CSV3.
        0xc020 => &[0, 4, 8, 12, 36, 48, 56, 60],
        // ID_AA64PFR1_EL1: BT, SSBS, CSV2_frac.
        0xc021 => &[0, 4, 32],
        // ID_AA64ISAR0_EL1: every field.
        0xc030 => &[4, 8, 12, 16, 20, 28, 32, 36, 40, 44, 48, 52, 56, 60],
        // ID_AA64ISAR1_EL1: all but APA, API, GPA, GPI (pointer
        // authentication is the vCPU features' choice).
        0xc031 => &[0, 12, 16, 20, 32, 36, 40, 44, 48, 52, 56, 60],
        // ID_AA64ISAR2_EL1: all but APA3, GPA3 and PAC_frac (pointer
        // authentication, as above).
        0xc032 => &[0, 4, 16, 20, 28, 32, 36, 40, 44, 48, 52, 56, 60],
        // ID_AA64MMFR0_EL1: PARange, BigEnd, SNSMem, BigEndEL0, TGran16,
        // ExS, FGT, ECV (not ASIDBits, the stage-2 granules, or the signed
        // TGran4 and TGran64).
        0xc038 => &[0, 8, 12, 16, 20, 44, 56, 60],
        // ID_AA64MMFR1_EL1: all but VMIDBits, VH, XNX, TWED, HCX.
        0xc039 => &[0, 12, 16, 20, 24, 36, 44, 48, 52, 56, 60],
        // ID_AA64MMFR2_EL1: all but CCIDX, NV, IDS, FWB, EVT.
        0xc03a => &[0, 4, 8, 12, 16, 28, 32, 44, 48, 52, 60],
        _ => &[],
    }
}

/// Checks a write of `new` over the host's `host`: each field KVM lets user
/// space change may be lowered, the others must be unchanged. Returns the
/// shift of the first field refused.
pub fn check_write(enc: u16, host: u64, new: u64) -> Result<(), u32> {
    let lower = lowerable(enc);
    for shift in (0..64).step_by(4) {
        let h = (host >> shift) & 0xf;
        let n = (new >> shift) & 0xf;
        if n == h || (lower.contains(&shift) && n < h) {
            continue;
        }
        return Err(shift);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptrauth_fields() {
        // Measured on an M1 Pro: API 2, GPI 1 (IMPLEMENTATION DEFINED).
        let isar1 = 0x0000_0111_1021_1202_u64;
        assert_eq!(isar1 & !ptrauth_fields(0xc031), 0x0000_0111_0021_1002);
        assert_eq!(ptrauth_fields(0xc030), 0);
    }

    #[test]
    fn test_id_space() {
        for enc in ID_REGS {
            assert!(is_id_reg(*enc), "{enc:#x}");
        }
        assert!(is_id_reg(MIDR));
        // ID_PFR0_EL1 (AArch32, CRm 1) and an unallocated one (CRm 7).
        assert!(is_id_reg(0xc008));
        assert!(is_id_reg(0xc03f));
        // MPIDR_EL1, REVIDR_EL1 (CRm 0) and SCTLR_EL1 are not.
        assert!(!is_id_reg(0xc005));
        assert!(!is_id_reg(0xc006));
        assert!(!is_id_reg(0xc080));
    }

    #[test]
    fn test_writes_lower_writable_fields_only() {
        // Measured on an M1 Pro (macOS 27.2).
        let isar0 = 0x0221_1001_1021_2120;
        // V1N1: sha3, sm3, sm4, fhm, ts, rndr to 0, sha2 to 1.
        let v1n1 = (isar0 & !0xF0FF_0FFF_0000_F000) | 0x1000;
        assert_eq!(check_write(0xc030, isar0, v1n1), Ok(()));
        // Raising one is refused: AES from 2 to 3.
        assert_eq!(check_write(0xc030, isar0, isar0 + 0x10), Err(4));
        // Unchanged is accepted for every register.
        assert_eq!(check_write(0xc025, 7, 7), Ok(()));
        // ID_AA64ISAR1_EL1: pointer authentication is not written.
        let isar1 = 0x0000_0111_1021_1202;
        // (API is 2 here: an IMPLEMENTATION DEFINED algorithm, APA 0.)
        assert_eq!(check_write(0xc031, isar1, isar1 & !0xff0), Err(8));
        // But the others are: I8MM, DGH, BF16 off (V1N1).
        assert_eq!(check_write(0xc031, isar1, isar1 & !0x00FF_F000_0000_0000), Ok(()));
        // ID_AA64PFR0_EL1: DIT lowered; SVE, FP not writable.
        let pfr0 = 0x1101_0000_1011_0011;
        assert_eq!(check_write(0xc020, pfr0, pfr0 & !0x000F_0000_0000_0000), Ok(()));
        assert_eq!(check_write(0xc020, pfr0, pfr0 | 0x1_0000_0000), Err(32));
        assert_eq!(check_write(0xc020, pfr0, pfr0 | 0xf_0000), Err(16));
        // MIDR_EL1: invariant.
        assert_eq!(check_write(MIDR, 0x610f_0000, 0x410f_d0c0), Err(4));
        // A register with no writable field.
        assert_eq!(check_write(0xc028, 0x10_0006, 0x10_0005), Err(0));
    }
}
