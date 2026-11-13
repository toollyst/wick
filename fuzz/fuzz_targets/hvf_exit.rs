// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The Hypervisor.framework run loop's decoding of what a vCPU exit asks for
//! (`crates/compat/kvm-ioctls/src/hvf/exit.rs`), on a sequence of exits: any
//! exception syndrome, the register a store reads, the bytes a device returns
//! to a load, the PSTATE an undefined instruction is raised from, and the
//! function id of a PSCI call.
//!
//! Each step is checked against a reference written from the Arm ARM
//! (ESR_EL2; the AArch64 load and store semantics; the exception vector
//! table) and the function ids of PSCI up to 1.1 (DEN0022), SMCCC, KVM's
//! vendor services, PV time and the TRNG service (DEN0098): the exit class,
//! the MMIO access (only 1, 2, 4 or 8 bytes, never past the 8-byte buffer;
//! the bytes a store sends; the register value a load leaves, sign- or
//! zero-extended into a W or X register), the debug registers' state after
//! each trapped access, which accesses raise an undefined instruction, and
//! the vector it enters. Nothing may panic: the syndrome comes from the
//! hardware, but describes whatever instruction the guest ran.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fuzz::hvf_exit::{self, DebugRegs, Exit, Mmio, Psci, SysregAccess, SysregResult};

#[derive(Arbitrary, Debug)]
struct Step {
    /// ESR_EL2; the class is often one the run loop handles.
    esr: u32,
    class: Option<Class>,
    /// The register a store or MSR reads.
    reg: u64,
    /// The bytes the device returns to a load.
    data: [u8; 8],
    /// PSTATE of the instruction an undefined instruction exception is raised at.
    cpsr: u64,
    /// X0 of a PSCI call.
    x0: u64,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Class {
    Wfx,
    Hvc,
    Smc,
    Sysreg,
    InstAbort,
    DataAbort,
}

/// The debug registers as KVM emulates them (arch/arm64/kvm/sys_regs.c):
/// OSLAR_EL1 write only and OSLSR_EL1 read only, the OS lock clear at reset
/// (OSLSR_EL1's reset_val, OSLSR_EL1_OSLM_IMPLEMENTED); OSDLR_EL1 and
/// DBGPRCR_EL1 read as 0 and ignore writes (trap_raz_wi).
#[derive(Default)]
struct Reference {
    os_lock: bool,
}

impl Reference {
    /// `None` for an access that is UNDEFINED, else the value read (0 for a write).
    fn access(&mut self, read: bool, op0: u64, op1: u64, crn: u64, crm: u64, op2: u64, value: u64) -> Option<u64> {
        if (op0, op1, crn, op2) != (2, 0, 1, 4) {
            return None;
        }
        let bit = value & 1 == 1;
        match (crm, read) {
            (0, false) => self.os_lock = bit, // OSLAR_EL1, WO
            (1, true) => return Some(if self.os_lock { 0b1010 } else { 0b1000 }), // OSLSR_EL1, RO
            (3 | 4, true) => return Some(0),  // OSDLR_EL1, DBGPRCR_EL1: RAZ
            (3 | 4, false) => {}              // WI
            _ => return None,
        }
        Some(0)
    }
}

fn step(s: &Step, debug: &mut DebugRegs, reference: &mut Reference) {
    let mut esr = u64::from(s.esr);
    if let Some(c) = s.class {
        let ec = match c {
            Class::Wfx => 0x01,
            Class::Hvc => 0x16,
            Class::Smc => 0x17,
            Class::Sysreg => 0x18,
            Class::InstAbort => 0x20,
            Class::DataAbort => 0x24,
        };
        esr = (esr & !(0x3f << 26)) | (ec << 26);
    }
    let ec = esr >> 26;
    let bit = |n: u32| esr >> n & 1 == 1;
    let field = |lo: u32, width: u32| esr >> lo & ((1 << width) - 1);

    let exit = hvf_exit::decode(esr);
    let expected = match ec {
        0x01 if bit(0) => Exit::Wfe,
        0x01 => Exit::Wfi,
        0x16 => Exit::Hvc,
        0x17 => Exit::Smc,
        0x18 => Exit::Sysreg(SysregAccess {
            read: bit(0),
            rt: field(5, 5) as u32,
            encoding: (field(20, 2), field(14, 3), field(10, 4), field(1, 4), field(17, 3)),
        }),
        0x20 => Exit::Abort { instruction: true, write: false },
        0x24 => Exit::Abort { instruction: false, write: bit(6) },
        // KVM's kvm_handle_guest_debug classes: breakpoint, software step and
        // watchpoint from a lower EL, BKPT, BRK.
        0x30 | 0x32 | 0x34 | 0x38 | 0x3c => Exit::Debug,
        _ => Exit::Unsupported,
    };
    assert_eq!(exit, expected, "esr {esr:#x}");

    match exit {
        Exit::Abort { instruction: false, write } => {
            let mmio = Mmio::decode(esr);
            // Without ISV, or on a stage 1 walk, no register describes the access.
            if !bit(24) || bit(7) {
                assert_eq!(mmio, None);
                return;
            }
            let m = mmio.expect("a valid instruction syndrome");
            assert_eq!(m.write, write);
            let len = match field(22, 2) {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 8,
            };
            assert_eq!(m.len, len);
            assert_eq!(m.srt, field(16, 5) as u32);
            if m.write {
                // STR{B,H,} Wt / Xt: the low `len` bytes of Rt, XZR as zero.
                let v = if m.srt == 31 { 0 } else { s.reg };
                let mut want = [0u8; 8];
                for (i, b) in want.iter_mut().enumerate().take(len) {
                    *b = (v >> (8 * i)) as u8;
                }
                assert_eq!(m.store_bytes(s.reg), want);
            } else {
                // LDR{,S}{B,H,W}: zero- or sign-extended, then the upper half
                // of a W register is zero.
                let raw = match len {
                    1 => s.data[0] as u64,
                    2 => u16::from_le_bytes([s.data[0], s.data[1]]) as u64,
                    4 => u32::from_le_bytes(s.data[..4].try_into().unwrap()) as u64,
                    _ => u64::from_le_bytes(s.data),
                };
                let extended = match (bit(21), len) {
                    (true, 1) => raw as u8 as i8 as i64 as u64,
                    (true, 2) => raw as u16 as i16 as i64 as u64,
                    (true, 4) => raw as u32 as i32 as i64 as u64,
                    _ => raw,
                };
                let want = if bit(15) { extended } else { extended as u32 as u64 };
                assert_eq!(m.load_value(&s.data), want, "esr {esr:#x}");
            }
        }
        Exit::Hvc | Exit::Smc => {
            let id = s.x0 as u32;
            let want = match id {
                0x8400_0000 => Psci::Version,
                0x8400_0001 | 0xc400_0001 => Psci::CpuSuspend,
                0x8400_0002 => Psci::CpuOff,
                0x8400_0003 | 0xc400_0003 => Psci::CpuOn,
                0x8400_0004 | 0xc400_0004 => Psci::AffinityInfo,
                0x8400_0006 => Psci::MigrateInfoType,
                0x8400_0008 => Psci::SystemOff,
                0x8400_0009 => Psci::SystemReset,
                // PSCI 1.0, SMCCC 1.1 and KVM's vendor services (27d7cc5).
                0x8400_000a => Psci::Features,
                // PSCI 1.1 SYSTEM_RESET2 (include/uapi/linux/psci.h
                // PSCI_1_1_FN_SYSTEM_RESET2 and its SMC64 form).
                0x8400_0012 | 0xc400_0012 => Psci::SystemReset2,
                0x8000_0000 => Psci::SmcccVersion,
                0x8000_0001 => Psci::SmcccArchFeatures,
                // ARM_SMCCC_ARCH_WORKAROUND_1, _2, _3 (include/linux/arm-smccc.h:
                // the architecture's fast SMC32 calls 0x8000, 0x7fff, 0x3fff).
                0x8000_8000 | 0x8000_7fff | 0x8000_3fff => Psci::ArchWorkaround,
                0x8600_ff01 => Psci::VendorHypUid,
                0x8600_0000 => Psci::KvmFeatures,
                0x8600_0001 => Psci::KvmPtp,
                // PV time (Arm DEN0057A): SMC64 only.
                0xc500_0020 => Psci::PvTimeFeatures,
                0xc500_0021 => Psci::PvTimeSt,
                // The SMCCC TRNG service (Arm DEN0098; include/linux/arm-smccc.h
                // ARM_SMCCC_TRNG_*): RND64 is its one SMC64 call.
                0x8400_0050 => Psci::TrngVersion,
                0x8400_0051 => Psci::TrngFeatures,
                0x8400_0052 => Psci::TrngGetUuid,
                0x8400_0053 => Psci::TrngRnd32,
                0xc400_0053 => Psci::TrngRnd64,
                _ => Psci::NotSupported,
            };
            assert_eq!(Psci::decode(s.x0), want, "x0 {:#x}", s.x0);
        }
        Exit::Sysreg(access) => {
            let value = if access.read || access.rt == 31 { 0 } else { s.reg };
            let (op0, op1, crn, crm, op2) = access.encoding;
            let got = debug.access(access, value);
            match reference.access(access.read, op0, op1, crn, crm, op2, value) {
                None => {
                    assert_eq!(got, SysregResult::Undefined, "{access:?}");
                    // Taken to EL1's synchronous vector for where the guest was.
                    let el = s.cpsr >> 2 & 3;
                    let sp_elx = s.cpsr & 1 == 1;
                    let want = if el == 1 { if sp_elx { 0x200 } else { 0 } } else { 0x400 };
                    assert_eq!(hvf_exit::sync_vector_offset(s.cpsr), want);
                }
                Some(v) if access.read => assert_eq!(got, SysregResult::Read(v), "{access:?}"),
                Some(_) => assert_eq!(got, SysregResult::Written, "{access:?}"),
            }
            assert_eq!(debug.os_lock, reference.os_lock);
        }
        _ => {}
    }
}

fuzz_target!(|steps: Vec<Step>| {
    let mut debug = DebugRegs::default();
    let mut reference = Reference::default();
    for s in &steps {
        step(s, &mut debug, &mut reference);
    }
});
