// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! What a vCPU exit asks for, from its exception syndrome (ESR_EL2): the
//! part of the run loop (`VcpuFd::run` in vcpu.rs) that reads what the
//! guest controls. No Hypervisor.framework call, so it is fuzzed on hosts
//! without one (fuzz/fuzz_targets/hvf_exit.rs).
//!
//! Field positions are the Arm ARM's (ESR_EL2): EC is bits 31:26,
//! ISS bits 24:0; a data abort's instruction syndrome is ISV (24), SAS
//! (23:22), SSE (21), SRT (20:16), SF (15), S1PTW (7) and WnR (6); a trapped
//! system register access's ISS is Op0 (21:20), Op2 (19:17), Op1 (16:14),
//! CRn (13:10), Rt (9:5), CRm (4:1) and Direction (0, 1 = read).

/// WFI or WFE.
pub const EC_WFX: u64 = 0x01;
/// HVC from AArch64.
pub const EC_HVC64: u64 = 0x16;
/// SMC from AArch64.
pub const EC_SMC64: u64 = 0x17;
/// A trapped MSR, MRS or system instruction.
pub const EC_SYSREG: u64 = 0x18;
/// An instruction abort from a lower exception level.
pub const EC_INST_ABORT_LOWER: u64 = 0x20;
/// A data abort from a lower exception level.
pub const EC_DATA_ABORT_LOWER: u64 = 0x24;

/// What an exception exit is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// A stage 2 abort: `write` for a data abort that wrote.
    Abort {
        /// An instruction fetch rather than a data access.
        instruction: bool,
        /// A data access that wrote (WnR).
        write: bool,
    },
    /// HVC (PSCI and other calls; the PC is already past it).
    Hvc,
    /// SMC (the PC is at it).
    Smc,
    /// WFI.
    Wfi,
    /// WFE.
    Wfe,
    /// A system register access.
    Sysreg(SysregAccess),
    /// Any other exception class.
    Unsupported,
}

/// The exit an exception syndrome describes.
pub fn decode(esr: u64) -> Exit {
    let ec = (esr >> 26) & 0x3f;
    let iss = esr & 0x1ff_ffff;
    match ec {
        EC_DATA_ABORT_LOWER | EC_INST_ABORT_LOWER => Exit::Abort {
            instruction: ec == EC_INST_ABORT_LOWER,
            write: ec == EC_DATA_ABORT_LOWER && iss & (1 << 6) != 0,
        },
        EC_HVC64 => Exit::Hvc,
        EC_SMC64 => Exit::Smc,
        EC_WFX if iss & 1 == 0 => Exit::Wfi,
        EC_WFX => Exit::Wfe,
        EC_SYSREG => Exit::Sysreg(SysregAccess::decode(iss)),
        _ => Exit::Unsupported,
    }
}

/// An MMIO access a data abort's instruction syndrome describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mmio {
    /// A store.
    pub write: bool,
    /// Bytes: 1, 2, 4 or 8.
    pub len: usize,
    /// The register: 0 to 30, or 31 (XZR).
    pub srt: u32,
    /// A load that sign-extends.
    pub sign_extend: bool,
    /// A load into a 64-bit register.
    pub sixty_four: bool,
}

impl Mmio {
    /// The access of a data abort's syndrome; `None` without a valid
    /// instruction syndrome (ISV clear) or for a stage 1 page table walk,
    /// which no register describes.
    pub fn decode(esr: u64) -> Option<Mmio> {
        let iss = esr & 0x1ff_ffff;
        if iss & (1 << 24) == 0 || iss & (1 << 7) != 0 {
            return None;
        }
        Some(Mmio {
            write: iss & (1 << 6) != 0,
            len: 1usize << ((iss >> 22) & 0b11),
            srt: ((iss >> 16) & 0x1f) as u32,
            sign_extend: iss & (1 << 21) != 0,
            sixty_four: iss & (1 << 15) != 0,
        })
    }

    /// The bytes a store writes, from the value of its register (`reg`,
    /// ignored for XZR).
    pub fn store_bytes(&self, reg: u64) -> [u8; 8] {
        let v = if self.srt == 31 { 0 } else { reg };
        let mut out = [0u8; 8];
        out[..self.len].copy_from_slice(&v.to_le_bytes()[..self.len]);
        out
    }

    /// The register value a load puts in its register, from the bytes the
    /// device returned (`data`, at least `len` of them).
    pub fn load_value(&self, data: &[u8]) -> u64 {
        let mut buf = [0u8; 8];
        buf[..self.len].copy_from_slice(&data[..self.len]);
        let mut v = u64::from_le_bytes(buf);
        if self.sign_extend && self.len < 8 {
            let shift = 64 - 8 * self.len as u32;
            v = (((v << shift) as i64) >> shift) as u64;
        }
        if !self.sixty_four {
            v &= 0xffff_ffff;
        }
        v
    }
}

/// A trapped system register access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysregAccess {
    /// MRS (a read) rather than MSR.
    pub read: bool,
    /// The general-purpose register: 0 to 30, or 31 (XZR).
    pub rt: u32,
    /// (Op0, Op1, CRn, CRm, Op2).
    pub encoding: (u64, u64, u64, u64, u64),
}

impl SysregAccess {
    /// The access an ISS describes.
    pub fn decode(iss: u64) -> SysregAccess {
        SysregAccess {
            read: iss & 1 != 0,
            rt: ((iss >> 5) & 0x1f) as u32,
            encoding: (
                (iss >> 20) & 3,   // op0
                (iss >> 14) & 7,   // op1
                (iss >> 10) & 0xf, // CRn
                (iss >> 1) & 0xf,  // CRm
                (iss >> 17) & 7,   // op2
            ),
        }
    }
}

/// The debug registers a trapped access reaches (KVM emulates the same
/// ones): the OS lock, the OS double lock and the core power-down request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugRegs {
    /// OSLSR_EL1.OSLK, set at reset.
    pub os_lock: bool,
    /// OSDLR_EL1.DLK.
    pub os_double_lock: bool,
    /// DBGPRCR_EL1.CORENPDRQ.
    pub power_request: bool,
}

impl Default for DebugRegs {
    fn default() -> Self {
        DebugRegs { os_lock: true, os_double_lock: false, power_request: false }
    }
}

/// What a trapped system register access does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysregResult {
    /// A read: this value goes to Rt (unless Rt is XZR); the PC moves past.
    Read(u64),
    /// A write took effect; the PC moves past.
    Written,
    /// Not a register the VMM emulates: an undefined instruction exception
    /// in the guest, at the instruction.
    Undefined,
}

impl DebugRegs {
    /// Emulates `access`; `value` is Rt's value for a write (0 for XZR).
    pub fn access(&mut self, access: SysregAccess, value: u64) -> SysregResult {
        let bit = value & 1 != 0;
        match (access.encoding, access.read) {
            // OSLAR_EL1 (write only): sets the OS lock.
            ((2, 0, 1, 0, 4), false) => {
                self.os_lock = bit;
                SysregResult::Written
            }
            // OSLSR_EL1 (read only): OS lock implemented (OSLM = 0b10) and its state.
            ((2, 0, 1, 1, 4), true) => SysregResult::Read(0b1000 | u64::from(self.os_lock) << 1),
            // OSDLR_EL1: double lock.
            ((2, 0, 1, 3, 4), true) => SysregResult::Read(u64::from(self.os_double_lock)),
            ((2, 0, 1, 3, 4), false) => {
                self.os_double_lock = bit;
                SysregResult::Written
            }
            // DBGPRCR_EL1: core power-down request.
            ((2, 0, 1, 4, 4), true) => SysregResult::Read(u64::from(self.power_request)),
            ((2, 0, 1, 4, 4), false) => {
                self.power_request = bit;
                SysregResult::Written
            }
            _ => SysregResult::Undefined,
        }
    }
}

/// The offset from VBAR_EL1 of the vector a synchronous exception taken to
/// EL1 enters, from the PSTATE (`cpsr`) of the guest it interrupts.
pub fn sync_vector_offset(cpsr: u64) -> u64 {
    let from_el1 = (cpsr >> 2) & 3 == 1;
    match (from_el1, cpsr & 1 != 0) {
        (true, true) => 0x200,  // current EL with SP_ELx
        (true, false) => 0x000, // current EL with SP_EL0
        (false, _) => 0x400,    // lower EL, AArch64
    }
}

/// A PSCI 0.2 call, from the function id in W0 (SMC32 and SMC64 ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Psci {
    /// PSCI_VERSION.
    Version,
    /// CPU_SUSPEND.
    CpuSuspend,
    /// CPU_OFF.
    CpuOff,
    /// CPU_ON: X1 the target's MPIDR, X2 its entry point, X3 its context.
    CpuOn,
    /// AFFINITY_INFO: X1 the target's MPIDR.
    AffinityInfo,
    /// MIGRATE_INFO_TYPE.
    MigrateInfoType,
    /// SYSTEM_OFF.
    SystemOff,
    /// SYSTEM_RESET.
    SystemReset,
    /// Any other id: NOT_SUPPORTED.
    NotSupported,
}

impl Psci {
    /// The call `x0` names; only its low 32 bits are the function id.
    pub fn decode(x0: u64) -> Psci {
        match x0 as u32 {
            0x8400_0000 => Psci::Version,
            0x8400_0001 | 0xc400_0001 => Psci::CpuSuspend,
            0x8400_0002 => Psci::CpuOff,
            0x8400_0003 | 0xc400_0003 => Psci::CpuOn,
            0x8400_0004 | 0xc400_0004 => Psci::AffinityInfo,
            0x8400_0006 => Psci::MigrateInfoType,
            0x8400_0008 => Psci::SystemOff,
            0x8400_0009 => Psci::SystemReset,
            _ => Psci::NotSupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_known_syndromes() {
        // LDR w1, [x0] faulting at stage 2: ISV, SAS=2 (4 bytes), SRT=1.
        let esr = (EC_DATA_ABORT_LOWER << 26) | (1 << 24) | (2 << 22) | (1 << 16);
        assert_eq!(decode(esr), Exit::Abort { instruction: false, write: false });
        let m = Mmio::decode(esr).unwrap();
        assert_eq!((m.write, m.len, m.srt, m.sign_extend, m.sixty_four), (false, 4, 1, false, false));
        assert_eq!(m.load_value(&[0xff, 0xff, 0xff, 0xff]), 0xffff_ffff);
        // LDRSB x2: sign-extended into 64 bits.
        let m = Mmio::decode((EC_DATA_ABORT_LOWER << 26) | (1 << 24) | (1 << 21) | (2 << 16) | (1 << 15)).unwrap();
        assert_eq!(m.load_value(&[0x80]), 0xffff_ffff_ffff_ff80);
        // STR xzr: stores zeros.
        let m = Mmio::decode((EC_DATA_ABORT_LOWER << 26) | (1 << 24) | (3 << 22) | (31 << 16) | (1 << 6)).unwrap();
        assert_eq!(m.store_bytes(u64::MAX), [0; 8]);
        // No valid syndrome, or a page table walk: nothing to emulate.
        assert_eq!(Mmio::decode(EC_DATA_ABORT_LOWER << 26), None);
        assert_eq!(Mmio::decode((EC_DATA_ABORT_LOWER << 26) | (1 << 24) | (1 << 7)), None);
        assert_eq!(decode((EC_WFX << 26) | 1), Exit::Wfe);
        assert_eq!(decode(EC_WFX << 26), Exit::Wfi);
        // MRS x3, OSLSR_EL1 (2, 0, 1, 1, 4).
        let iss = (2 << 20) | (4 << 17) | (1 << 10) | (3 << 5) | (1 << 1) | 1;
        assert_eq!(
            decode((EC_SYSREG << 26) | iss),
            Exit::Sysreg(SysregAccess { read: true, rt: 3, encoding: (2, 0, 1, 1, 4) })
        );
        assert_eq!(decode(0), Exit::Unsupported);
    }

    #[test]
    fn test_debug_registers() {
        let mut d = DebugRegs::default();
        let acc = |read, encoding| SysregAccess { read, rt: 0, encoding };
        // The OS lock is set at reset, and OSLAR clears it.
        assert_eq!(d.access(acc(true, (2, 0, 1, 1, 4)), 0), SysregResult::Read(0b1010));
        assert_eq!(d.access(acc(false, (2, 0, 1, 0, 4)), 0), SysregResult::Written);
        assert_eq!(d.access(acc(true, (2, 0, 1, 1, 4)), 0), SysregResult::Read(0b1000));
        // OSLAR is write only, OSLSR read only.
        assert_eq!(d.access(acc(true, (2, 0, 1, 0, 4)), 0), SysregResult::Undefined);
        assert_eq!(d.access(acc(false, (2, 0, 1, 1, 4)), 1), SysregResult::Undefined);
        assert_eq!(d.access(acc(false, (2, 0, 1, 4, 4)), 3), SysregResult::Written);
        assert_eq!(d.access(acc(true, (2, 0, 1, 4, 4)), 0), SysregResult::Read(1));
        assert_eq!(d.access(acc(true, (3, 0, 1, 0, 0)), 0), SysregResult::Undefined);
        assert_eq!(sync_vector_offset(0x3c5), 0x200);
        assert_eq!(sync_vector_offset(0x3c4), 0x000);
        assert_eq!(sync_vector_offset(0x3c0), 0x400);
        assert_eq!(Psci::decode(0xffff_ffff_8400_0008), Psci::SystemOff);
        assert_eq!(Psci::decode(0xc400_0003), Psci::CpuOn);
        assert_eq!(Psci::decode(0x8400_0005), Psci::NotSupported);
    }
}
