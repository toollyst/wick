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
/// A breakpoint from a lower exception level.
pub const EC_BREAKPOINT_LOWER: u64 = 0x30;
/// A software step from a lower exception level.
pub const EC_SOFTWARE_STEP_LOWER: u64 = 0x32;
/// A watchpoint from a lower exception level.
pub const EC_WATCHPOINT_LOWER: u64 = 0x34;
/// BKPT (AArch32).
pub const EC_BKPT32: u64 = 0x38;
/// BRK (AArch64).
pub const EC_BRK64: u64 = 0x3c;

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
    /// A debug exception (a breakpoint, a software step, a watchpoint, BKPT
    /// or BRK from the guest), which reaches the host only while user space
    /// debugs the guest (`super::debug`).
    Debug,
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
        // KVM's `kvm_handle_guest_debug` classes (handle_exit.c
        // `arm_exit_handlers`): the lower-EL ones and the two instructions.
        EC_BREAKPOINT_LOWER | EC_SOFTWARE_STEP_LOWER | EC_WATCHPOINT_LOWER | EC_BKPT32 | EC_BRK64 => Exit::Debug,
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

/// The debug registers a trapped access reaches, as KVM emulates them
/// (arch/arm64/kvm/sys_regs.c): the OS lock (OSLAR_EL1, OSLSR_EL1), and
/// OSDLR_EL1 and DBGPRCR_EL1, which read as 0 and ignore writes
/// (`trap_raz_wi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DebugRegs {
    /// OSLSR_EL1.OSLK: clear at reset, as KVM resets OSLSR_EL1 to
    /// `OSLSR_EL1_OSLM_IMPLEMENTED`.
    pub os_lock: bool,
}

/// OSLSR_EL1 with the OS lock clear: OSLM = 0b10, the OS lock implemented
/// (`OSLSR_EL1_OSLM_IMPLEMENTED`, its reset value on KVM).
pub const OSLSR_RESET: u64 = 0b1000;
/// OSLSR_EL1.OSLK.
pub const OSLSR_OSLK: u64 = 0b10;

impl DebugRegs {
    /// OSLSR_EL1 as the guest reads it.
    pub fn oslsr(self) -> u64 {
        OSLSR_RESET | if self.os_lock { OSLSR_OSLK } else { 0 }
    }

    /// Takes an OSLSR_EL1 value written by user space: as KVM's
    /// `set_oslsr_el1`, only OSLK may differ from the reset value.
    pub fn set_oslsr(&mut self, v: u64) -> bool {
        if (v ^ OSLSR_RESET) & !OSLSR_OSLK != 0 {
            return false;
        }
        self.os_lock = v & OSLSR_OSLK != 0;
        true
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
            ((2, 0, 1, 1, 4), true) => SysregResult::Read(self.oslsr()),
            // OSDLR_EL1 and DBGPRCR_EL1: read as 0, writes ignored.
            ((2, 0, 1, 3 | 4, 4), true) => SysregResult::Read(0),
            ((2, 0, 1, 3 | 4, 4), false) => SysregResult::Written,
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

/// `ARM_SMCCC_HV_PV_TIME_FEATURES` (Arm DEN0057A; Linux's
/// include/linux/arm-smccc.h): fast call, SMC64, standard hypervisor
/// services, function 0x20.
pub const PV_TIME_FEATURES: u32 = 0xc500_0020;
/// `ARM_SMCCC_HV_PV_TIME_ST`: function 0x21.
pub const PV_TIME_ST: u32 = 0xc500_0021;

/// A call through the SMCCC conduit (HVC or SMC), from the function id in
/// W0 (SMC32 and SMC64 ids): the PSCI 1.1 calls, SMCCC 1.1's own, the TRNG
/// service's (`super::trng`) and KVM's vendor hypervisor services, what KVM
/// answers for a guest on Linux (arch/arm64/kvm/psci.c, hypercalls.c,
/// trng.c), and PV time's (`super::pvtime`).
/// Without SMCCC 1.1 a Linux guest
/// finds no hypervisor services: no `ptp_kvm` clock.
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
    /// PSCI_FEATURES (PSCI 1.0): X1 a function id.
    Features,
    /// SYSTEM_RESET2 (PSCI 1.1): X1 the reset type, X2 a cookie.
    SystemReset2,
    /// TRNG_VERSION (Arm DEN0098).
    TrngVersion,
    /// TRNG_FEATURES: X1 a function id.
    TrngFeatures,
    /// TRNG_GET_UUID.
    TrngGetUuid,
    /// TRNG_RND32: X1 the number of bits, at most 96.
    TrngRnd32,
    /// TRNG_RND64: X1 the number of bits, at most 192.
    TrngRnd64,
    /// SMCCC_VERSION.
    SmcccVersion,
    /// SMCCC_ARCH_FEATURES: X1 a function id.
    SmcccArchFeatures,
    /// The vendor hypervisor service's UID (KVM's).
    VendorHypUid,
    /// KVM's vendor hypervisor features: a bitmap.
    KvmFeatures,
    /// KVM_PTP: X1 the counter, virtual (0) or physical (1).
    KvmPtp,
    /// PV_TIME_FEATURES (Arm DEN0057A, SMC64 only): X1 a PV time call.
    PvTimeFeatures,
    /// PV_TIME_ST: the IPA of the vCPU's stolen-time structure.
    PvTimeSt,
    /// Any other id: NOT_SUPPORTED.
    NotSupported,
}

/// SMCCC 1.1.
pub const SMCCC_VERSION_1_1: u64 = 0x1_0001;
/// ARM_SMCCC_VENDOR_HYP_UID_KVM_REG_0..3: KVM's vendor hypervisor UID.
pub const KVM_UID: [u64; 4] = [0xb66f_b428, 0xe911_c52e, 0x564b_caa9, 0x743a_004d];
/// KVM's features bitmap: ARM_SMCCC_KVM_FUNC_FEATURES (0) and
/// ARM_SMCCC_KVM_FUNC_PTP (1).
pub const KVM_FEATURES: u64 = 0b11;

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
            0x8400_000a => Psci::Features,
            0x8400_0012 | 0xc400_0012 => Psci::SystemReset2,
            super::trng::VERSION => Psci::TrngVersion,
            super::trng::FEATURES => Psci::TrngFeatures,
            super::trng::GET_UUID => Psci::TrngGetUuid,
            super::trng::RND32 => Psci::TrngRnd32,
            super::trng::RND64 => Psci::TrngRnd64,
            0x8000_0000 => Psci::SmcccVersion,
            0x8000_0001 => Psci::SmcccArchFeatures,
            0x8600_ff01 => Psci::VendorHypUid,
            0x8600_0000 => Psci::KvmFeatures,
            0x8600_0001 => Psci::KvmPtp,
            PV_TIME_FEATURES => Psci::PvTimeFeatures,
            PV_TIME_ST => Psci::PvTimeSt,
            _ => Psci::NotSupported,
        }
    }

    /// PSCI_FEATURES for function id `id` from a guest given PSCI 1.`minor`:
    /// whether it is implemented (0, and for CPU_SUSPEND: the original
    /// power_state format, no OS-initiated mode), as KVM answers
    /// (kvm_psci_1_x_call): SYSTEM_RESET2 from 1.1 on; SYSTEM_SUSPEND only
    /// when the VMM enabled it for the VM (KVM_CAP_ARM_SYSTEM_SUSPEND),
    /// which Firecracker does not.
    pub fn implemented(id: u64, minor: u32) -> bool {
        if Psci::decode(id) == Psci::SystemReset2 {
            return minor >= 1 && id >> 32 == 0;
        }
        matches!(
            Psci::decode(id),
            Psci::Version
                | Psci::CpuSuspend
                | Psci::CpuOff
                | Psci::CpuOn
                | Psci::AffinityInfo
                | Psci::MigrateInfoType
                | Psci::SystemOff
                | Psci::SystemReset
                | Psci::Features
                | Psci::SmcccVersion
        ) && id >> 32 == 0
    }
}

/// KVM_PTP's four result words (kvm_ptp_get_time): the wall clock in
/// nanoseconds and the counter, each as its upper and lower 32 bits.
pub fn ptp_words(realtime_ns: u64, counter: u64) -> [u64; 4] {
    [realtime_ns >> 32, realtime_ns & 0xffff_ffff, counter >> 32, counter & 0xffff_ffff]
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
    fn test_decode_debug_classes() {
        // Breakpoint, software step, watchpoint (lower EL), BKPT, BRK.
        for ec in [0x30u64, 0x32, 0x34, 0x38, 0x3c] {
            assert_eq!(decode(ec << 26 | 0x22), Exit::Debug, "{ec:#x}");
        }
        // The current-EL classes cannot come from a guest (its EL1 is the
        // host's lower level); vector catch (0x3a) is AArch32 only.
        for ec in [0x31u64, 0x33, 0x35, 0x3a, 0x3d] {
            assert_eq!(decode(ec << 26), Exit::Unsupported, "{ec:#x}");
        }
    }

    #[test]
    fn test_debug_registers() {
        let mut d = DebugRegs::default();
        let acc = |read, encoding| SysregAccess { read, rt: 0, encoding };
        // As KVM resets it, the OS lock is clear (OSLSR_EL1 is
        // OSLSR_EL1_OSLM_IMPLEMENTED: arch/arm64/kvm/sys_regs.c, its
        // descriptor's reset_val); OSLAR sets and clears it.
        assert_eq!(d.access(acc(true, (2, 0, 1, 1, 4)), 0), SysregResult::Read(0b1000));
        assert_eq!(d.access(acc(false, (2, 0, 1, 0, 4)), 1), SysregResult::Written);
        assert_eq!(d.access(acc(true, (2, 0, 1, 1, 4)), 0), SysregResult::Read(0b1010));
        assert_eq!(d.access(acc(false, (2, 0, 1, 0, 4)), 0), SysregResult::Written);
        assert_eq!(d.access(acc(true, (2, 0, 1, 1, 4)), 0), SysregResult::Read(0b1000));
        // OSLAR is write only, OSLSR read only (read_from_write_only,
        // write_to_read_only: an undefined instruction).
        assert_eq!(d.access(acc(true, (2, 0, 1, 0, 4)), 0), SysregResult::Undefined);
        assert_eq!(d.access(acc(false, (2, 0, 1, 1, 4)), 1), SysregResult::Undefined);
        // OSDLR_EL1 and DBGPRCR_EL1 read as 0 and ignore writes, as KVM's
        // (trap_raz_wi).
        for enc in [(2, 0, 1, 3, 4), (2, 0, 1, 4, 4)] {
            assert_eq!(d.access(acc(false, enc), 3), SysregResult::Written);
            assert_eq!(d.access(acc(true, enc), 0), SysregResult::Read(0));
        }
        assert_eq!(d.access(acc(true, (3, 0, 1, 0, 0)), 0), SysregResult::Undefined);
        assert_eq!(sync_vector_offset(0x3c5), 0x200);
        assert_eq!(sync_vector_offset(0x3c4), 0x000);
        assert_eq!(sync_vector_offset(0x3c0), 0x400);
        assert_eq!(Psci::decode(0xffff_ffff_8400_0008), Psci::SystemOff);
        assert_eq!(Psci::decode(0xc400_0003), Psci::CpuOn);
        assert_eq!(Psci::decode(0x8400_0005), Psci::NotSupported);
        assert_eq!(Psci::decode(0x8400_000a), Psci::Features);
        assert_eq!(Psci::decode(0x8400_0012), Psci::SystemReset2);
        assert_eq!(Psci::decode(0xc400_0012), Psci::SystemReset2);
        for (id, call) in [
            (0x8400_0050, Psci::TrngVersion),
            (0x8400_0051, Psci::TrngFeatures),
            (0x8400_0052, Psci::TrngGetUuid),
            (0x8400_0053, Psci::TrngRnd32),
            (0xc400_0053, Psci::TrngRnd64),
            // The other calls have no SMC64 form (include/linux/arm-smccc.h).
            (0xc400_0050, Psci::NotSupported),
            (0x8400_0054, Psci::NotSupported),
        ] {
            assert_eq!(Psci::decode(id), call, "{id:#x}");
        }
        assert_eq!(Psci::decode(0x8000_0000), Psci::SmcccVersion);
        assert_eq!(Psci::decode(0x8600_ff01), Psci::VendorHypUid);
        assert_eq!(Psci::decode(0x8600_0001), Psci::KvmPtp);
        assert_eq!(Psci::decode(0xc500_0020), Psci::PvTimeFeatures);
        assert_eq!(Psci::decode(0xc500_0021), Psci::PvTimeSt);
        // PV time has no SMC32 calls.
        assert_eq!(Psci::decode(0x8500_0021), Psci::NotSupported);
    }

    #[test]
    fn test_psci_features_and_ptp() {
        // PSCI_FEATURES: the PSCI 1.0 calls and SMCCC_VERSION, and from
        // PSCI 1.1 SYSTEM_RESET2 (both forms); nothing else.
        for minor in [0, 1] {
            for id in [0x8400_0000, 0xc400_0003, 0x8400_0009, 0x8400_000a, 0x8000_0000] {
                assert!(Psci::implemented(id, minor), "{id:#x}");
            }
            // MIGRATE, SYSTEM_SUSPEND (not enabled for the VM), MEM_PROTECT,
            // the workarounds, the TRNG's and KVM's services (they are not
            // PSCI), garbage in the upper half.
            for id in [
                0x8400_0005,
                0x8400_000e,
                0xc400_000e,
                0x8400_0013,
                0x8000_8000,
                0x8400_0050,
                0x8600_0001,
                0xc500_0020,
                1 << 32 | 0x8400_0000,
                1 << 32 | 0x8400_0012,
            ] {
                assert!(!Psci::implemented(id, minor), "{id:#x}");
            }
        }
        for id in [0x8400_0012, 0xc400_0012] {
            assert!(!Psci::implemented(id, 0), "{id:#x}");
            assert!(Psci::implemented(id, 1), "{id:#x}");
        }
        assert_eq!(ptp_words(0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321), [
            0x1234_5678,
            0x9abc_def0,
            0x0fed_cba9,
            0x8765_4321
        ]);
    }
}
