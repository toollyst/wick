// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Guest debugging for Firecracker's gdb stub (`KVM_SET_GUEST_DEBUG`,
//! `KVM_TRANSLATE`, `KVM_EXIT_DEBUG`) on WHP: the decisions, without a WHP
//! call, so they are tested on any Windows host. `vcpu.rs` makes the calls.
//!
//! KVM intercepts #DB and #BP for a vCPU being debugged and reports them as
//! `KVM_EXIT_DEBUG`. WHP reports an exception as an exit only when the
//! partition was made with exception exits (`ExtendedVmExits` bit 2,
//! `ExceptionExit`, set before `WHvSetupPartition`) and the exception's bit
//! is in the partition's `ExceptionExitBitmap`. The partition is made with
//! exception exits only with this crate's `gdb` feature (Firecracker's
//! `gdb`), so a build without it is exactly as before ([`extended_vm_exits`]).
//!
//! What differs from KVM:
//! - the bitmap is the partition's, where KVM's guest debug is per vCPU
//!   (Firecracker's gdb stub sets every vCPU alike);
//! - hardware breakpoints are the vCPU's own DR0-DR3 and DR7: KVM keeps the
//!   guest's debug registers apart, WHP has no exit on `MOV DR`, so the guest
//!   sees them and can overwrite them; they are written again at every entry
//!   while gdb has hardware breakpoints, and the guest's own values put back
//!   when gdb has none;
//! - single steps set the vCPU's `RFLAGS.TF`, which `get_regs` hides while
//!   gdb owns it, as KVM does.

// What only the run loop of a gdb build uses; the tests use all of it in
// both builds.
#![cfg_attr(not(feature = "gdb"), allow(dead_code))]

use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_INJECT_BP, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW_BP,
    KVM_GUESTDBG_USE_SW_BP, kvm_debug_exit_arch, kvm_translation,
};
use vmm_sys_util::errno::Error;

use super::Result;

/// The debug exception.
pub(crate) const DB_VECTOR: u8 = 1;
/// The breakpoint exception (`INT3`).
pub(crate) const BP_VECTOR: u8 = 3;
/// `RFLAGS.TF`: a #DB after the next instruction.
pub(crate) const RFLAGS_TF: u64 = 1 << 8;
/// `RFLAGS.RF`: no instruction breakpoint on the next instruction.
pub(crate) const RFLAGS_RF: u64 = 1 << 16;

/// `ExtendedVmExits`'s `X64CpuidExit`, `X64MsrExit`.
const EXITS_CPUID_MSR: u64 = (1 << 0) | (1 << 1);
/// `ExtendedVmExits`'s `ExceptionExit`.
pub(crate) const EXITS_EXCEPTION: u64 = 1 << 2;
/// `ExtendedVmExits`'s `HypercallExit`.
const EXITS_HYPERCALL: u64 = 1 << 5;

/// The partition's `ExtendedVmExits`: CPUID and MSR exits, hypercall exits
/// where WHP has them (`supported`, its `ExtendedVmExits` capability), and
/// exception exits only with the `gdb` feature.
pub(crate) fn extended_vm_exits(supported: u64) -> u64 {
    let exits = EXITS_CPUID_MSR | (supported & EXITS_HYPERCALL);
    if cfg!(feature = "gdb") { exits | EXITS_EXCEPTION } else { exits }
}

/// What a `KVM_SET_GUEST_DEBUG` asks of the vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The partition's `ExceptionExitBitmap`.
    pub(crate) bitmap: u64,
    /// DR0-DR3 and DR7 as given (`debugreg`), or the guest's own back.
    pub(crate) hw: bool,
    /// `RFLAGS.TF` until the next debug exit.
    pub(crate) step: bool,
    /// A #BP into the guest at the next entry (the guest's own `INT3`).
    pub(crate) inject_bp: bool,
}

/// The plan for `control`. `KVM_GUESTDBG_INJECT_DB` and
/// `KVM_GUESTDBG_BLOCKIRQ`, which Firecracker never sets, are refused
/// (`EINVAL`, as KVM refuses what it does not support); so is enabling
/// debugging in a build without the `gdb` feature (`ENOSYS`): its partition
/// has no exception exits, and the debug exits would never come.
pub(crate) fn plan(control: u32) -> Result<Plan> {
    const KNOWN: u32 = KVM_GUESTDBG_ENABLE
        | KVM_GUESTDBG_SINGLESTEP
        | KVM_GUESTDBG_USE_SW_BP
        | KVM_GUESTDBG_USE_HW_BP
        | KVM_GUESTDBG_INJECT_BP;
    if control & !KNOWN != 0 {
        return Err(Error::new(libc::EINVAL));
    }
    if control & KVM_GUESTDBG_ENABLE == 0 {
        return Ok(Plan { bitmap: 0, hw: false, step: false, inject_bp: false });
    }
    if !cfg!(feature = "gdb") {
        return Err(Error::new(libc::ENOSYS));
    }
    let step = control & KVM_GUESTDBG_SINGLESTEP != 0;
    let hw = control & KVM_GUESTDBG_USE_HW_BP != 0;
    let mut bitmap = 0;
    if hw || step {
        bitmap |= 1 << DB_VECTOR;
    }
    if control & KVM_GUESTDBG_USE_SW_BP != 0 {
        bitmap |= 1 << BP_VECTOR;
    }
    Ok(Plan { bitmap, hw, step, inject_bp: control & KVM_GUESTDBG_INJECT_BP != 0 })
}

/// A vCPU's guest-debug state between `set_guest_debug` and its run loop.
#[derive(Debug, Default, Clone)]
pub(crate) struct State {
    /// gdb set `RFLAGS.TF` (the guest's own was clear).
    pub(crate) tf_owned: bool,
    /// gdb's DR0-DR3 and DR7, written at every entry while set.
    pub(crate) hw: Option<([u64; 4], u64)>,
    /// The guest's DR0-DR3, DR6, DR7 from before gdb's.
    pub(crate) saved: Option<[u64; 6]>,
    /// `RFLAGS.RF` at the next entry: the vCPU stopped on one of gdb's
    /// instruction breakpoints, which would hit again at once.
    pub(crate) resume_rf: bool,
    /// A #BP for the guest at the next entry.
    pub(crate) inject_bp: bool,
    /// The length of the instruction of the last debug exit (`INT3`: 1).
    pub(crate) last_len: u64,
}

/// `RFLAGS` as the guest has it: without the `TF` gdb set.
pub(crate) fn guest_rflags(rflags: u64, state: &State) -> u64 {
    if state.tf_owned { rflags & !RFLAGS_TF } else { rflags }
}

/// `RFLAGS` to write for the guest's `rflags`: with the `TF` gdb owns.
pub(crate) fn vcpu_rflags(rflags: u64, state: &State) -> u64 {
    if state.tf_owned { rflags | RFLAGS_TF } else { rflags }
}

/// `RFLAGS` after a plan: `TF` set for a step (owned only if the guest's was
/// clear), cleared again if gdb owned it and steps no more.
pub(crate) fn step_rflags(rflags: u64, step: bool, state: &mut State) -> u64 {
    if step && rflags & RFLAGS_TF == 0 {
        state.tf_owned = true;
        rflags | RFLAGS_TF
    } else if !step && state.tf_owned {
        state.tf_owned = false;
        rflags & !RFLAGS_TF
    } else {
        rflags
    }
}

/// Whether `rip` is one of gdb's enabled instruction breakpoints (DR7's
/// global enable bit `G<n>`, with R/W 00, execution, in its bits 16-17).
pub(crate) fn at_hw_breakpoint(rip: u64, state: &State) -> bool {
    let Some((addrs, dr7)) = state.hw else { return false };
    (0..4).any(|i| dr7 & (2 << (i * 2)) != 0 && (dr7 >> (16 + i * 4)) & 0x3 == 0 && addrs[i] == rip)
}

/// The `KVM_EXIT_DEBUG` for an exception exit of `vector` at `rip`, `None`
/// for a vector the partition never asks for. `param` is WHP's
/// `ExceptionParameter`, for #DB the pending debug exceptions (DR6's bits).
pub(crate) fn debug_exit(vector: u8, rip: u64, param: u64, dr7: u64) -> Option<kvm_debug_exit_arch> {
    let dr6 = match vector {
        DB_VECTOR => param,
        BP_VECTOR => 0,
        _ => return None,
    };
    Some(kvm_debug_exit_arch { exception: u32::from(vector), pad: 0, pc: rip, dr6, dr7 })
}

/// WHP's `WHV_X64_PENDING_INTERRUPTION_REGISTER` for a #BP (a hardware
/// exception, type 3, vector 3): delivered with `RIP` past the `INT3`, as
/// the guest's own breakpoint would have been.
pub(crate) fn pending_bp() -> u64 {
    1 | (3 << 1) | (u64::from(BP_VECTOR) << 16)
}

/// KVM's `INVALID_GPA` (`~0ull`, include/linux/kvm_types.h): the
/// physical address of a translation that failed.
pub(crate) const INVALID_GPA: u64 = u64::MAX;

/// `CR0.PG`.
pub(crate) const CR0_PG: u64 = 1 << 31;

/// `KVM_TRANSLATE`'s answer, as KVM's `kvm_arch_vcpu_ioctl_translate`
/// (arch/x86/kvm/x86.c, Linux 6.12), which never fails: `walk` is `None`
/// when the vCPU's paging is off, where KVM's `nonpaging_gva_to_gpa`
/// (arch/x86/kvm/mmu/mmu.c) gives the address itself, valid (at the PVH
/// entry, before the guest turns paging on); otherwise it is
/// `WHvTranslateGva`'s result code and address for a walk without access
/// checks, as KVM's (`kvm_mmu_gva_to_gpa_system`, access 0). Valid only for
/// `WHvTranslateGvaResultSuccess` (0); every other result (page not present,
/// privilege violation, invalid page table flags, a GPA that is not mapped
/// or not readable, an overlay, an intercept) is no translation, with
/// `INVALID_GPA`, as KVM's walk that fails. `writeable` is 1 and `usermode`
/// 0 whatever the walk found, as KVM sets them.
pub(crate) fn translation(gva: u64, walk: Option<(i32, u64)>) -> kvm_translation {
    let gpa = match walk {
        None => Some(gva),
        Some((0, gpa)) => Some(gpa),
        Some(_) => None,
    };
    kvm_translation {
        linear_address: gva,
        physical_address: gpa.unwrap_or(INVALID_GPA),
        valid: u8::from(gpa.is_some()),
        writeable: 1,
        usermode: 0,
        pad: [0; 5],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u32 = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;

    #[test]
    fn test_extended_vm_exits_only_with_gdb() {
        // Today's value without the feature: CPUID, MSR and, where WHP has
        // them, hypercall exits; never exception exits.
        for supported in [0, EXITS_HYPERCALL, u64::MAX] {
            let exits = extended_vm_exits(supported);
            assert_eq!(exits & !EXITS_EXCEPTION, 0b11 | (supported & EXITS_HYPERCALL));
            assert_eq!(exits & EXITS_EXCEPTION != 0, cfg!(feature = "gdb"));
        }
    }

    #[test]
    fn test_plan() {
        // Disabling is always possible and asks for no exception exit.
        assert_eq!(plan(0).unwrap(), Plan { bitmap: 0, hw: false, step: false, inject_bp: false });
        assert_eq!(plan(KVM_GUESTDBG_USE_HW_BP).unwrap().bitmap, 0);
        // What KVM refuses as unsupported, refused.
        for bad in [kvm_bindings::KVM_GUESTDBG_INJECT_DB, kvm_bindings::KVM_GUESTDBG_BLOCKIRQ, 1 << 30] {
            assert_eq!(plan(ALL | bad).unwrap_err().errno(), libc::EINVAL);
        }
        if !cfg!(feature = "gdb") {
            // Without the feature the partition has no exception exits.
            assert_eq!(plan(ALL).unwrap_err().errno(), libc::ENOSYS);
            return;
        }
        // Upstream's vcpu_set_debug: #DB for hardware breakpoints, #BP for INT3.
        assert_eq!(plan(ALL).unwrap(), Plan { bitmap: (1 << 1) | (1 << 3), hw: true, step: false, inject_bp: false });
        assert!(plan(ALL | KVM_GUESTDBG_SINGLESTEP).unwrap().step);
        assert!(plan(ALL | KVM_GUESTDBG_INJECT_BP).unwrap().inject_bp);
        assert_eq!(plan(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP).unwrap().bitmap, 1 << 1);
        assert_eq!(plan(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP).unwrap().bitmap, 1 << 3);
    }

    #[test]
    fn test_single_step_flag_is_gdbs_own() {
        let mut s = State::default();
        // gdb steps: TF set, and hidden from the guest's view.
        let r = step_rflags(0x202, true, &mut s);
        assert_eq!(r, 0x302);
        assert!(s.tf_owned);
        assert_eq!(guest_rflags(r, &s), 0x202);
        // A register write keeps the step going.
        assert_eq!(vcpu_rflags(0x246, &s), 0x346);
        // Stepping ends: TF goes, and the guest's view is the vCPU's again.
        assert_eq!(step_rflags(0x302, false, &mut s), 0x202);
        assert!(!s.tf_owned);
        assert_eq!(guest_rflags(0x302, &s), 0x302);
        // A guest that set TF itself keeps it, and sees it.
        let mut s = State::default();
        assert_eq!(step_rflags(0x302, true, &mut s), 0x302);
        assert!(!s.tf_owned);
        assert_eq!(step_rflags(0x302, false, &mut s), 0x302);
    }

    #[test]
    fn test_resume_flag_at_a_hardware_breakpoint() {
        // Upstream's DR7: GE and bit 10, then G<n> for each address.
        let dr7 = (0b11 << 9) | 2 | (2 << 2);
        let s = State { hw: Some(([0x1000, 0x2000, 0, 0], dr7)), ..State::default() };
        assert!(at_hw_breakpoint(0x1000, &s));
        assert!(at_hw_breakpoint(0x2000, &s));
        assert!(!at_hw_breakpoint(0x3000, &s));
        // DR2 is not enabled, nor is a data breakpoint an instruction one.
        let s2 = State { hw: Some(([0, 0, 0x3000, 0], (0b11 << 9) | (1 << 4))), ..State::default() };
        assert!(!at_hw_breakpoint(0x3000, &s2));
        let s3 = State { hw: Some(([0x1000, 0, 0, 0], (0b11 << 9) | 2 | (0b01 << 16))), ..State::default() };
        assert!(!at_hw_breakpoint(0x1000, &s3));
        assert!(!at_hw_breakpoint(0x1000, &State::default()));
    }

    #[test]
    fn test_debug_exit() {
        let db = debug_exit(DB_VECTOR, 0xffff_ffff_8100_0000, 1 << 14, 0x602).unwrap();
        assert_eq!((db.exception, db.pc, db.dr6, db.dr7), (1, 0xffff_ffff_8100_0000, 1 << 14, 0x602));
        let bp = debug_exit(BP_VECTOR, 0x1234, 0xdead, 0x600).unwrap();
        assert_eq!((bp.exception, bp.pc, bp.dr6), (3, 0x1234, 0));
        // Only #DB and #BP are ever asked for.
        for v in [0u8, 2, 6, 13, 14, 255] {
            assert!(debug_exit(v, 0, 0, 0).is_none());
        }
    }

    #[test]
    fn test_pending_bp_is_a_hardware_exception_3() {
        let p = pending_bp();
        assert_eq!(p & 1, 1);
        assert_eq!((p >> 1) & 0x7, 3);
        assert_eq!((p >> 4) & 1, 0, "#BP has no error code");
        assert_eq!((p >> 16) & 0xffff, 3);
    }

    #[test]
    fn test_translation_result_codes() {
        let t = translation(0xffff_ffff_8100_0123, Some((0, 0x100_0123)));
        assert_eq!(
            (t.linear_address, t.physical_address, t.valid, t.writeable, t.usermode),
            (0xffff_ffff_8100_0123, 0x100_0123, 1, 1, 0)
        );
        // PageNotPresent .. Intercept: no translation, KVM's INVALID_GPA;
        // the call itself succeeds and writeable is still 1, as KVM's.
        for code in 1..=8 {
            let t = translation(0x10, Some((code, 0x99)));
            assert_eq!((t.valid, t.physical_address, t.writeable), (0, INVALID_GPA, 1), "result code {code}");
        }
    }

    // Paging off (the PVH entry): KVM's nonpaging walk gives the address
    // itself, valid, also one no guest memory backs (gdb reads a kernel
    // symbol there; the read of guest memory then fails, not the translation).
    #[test]
    fn test_translation_without_paging_is_the_address() {
        for gva in [0x100_0000u64, 0xffff_ffff_82ed_2098] {
            let t = translation(gva, None);
            assert_eq!((t.physical_address, t.valid, t.writeable, t.usermode), (gva, 1, 1, 0));
        }
    }
}
