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
//! #DB and #BP exits only with this crate's `gdb` feature (Firecracker's
//! `gdb`), so a build without it has none of gdb's ([`extended_vm_exits`]);
//! an x2APIC partition has exception exits in every build, for #GP alone
//! (`gp`, `vm::configure`), which gdb's bitmap is written over.
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
    /// A #BP for the guest at the next entry: its own `INT3`, run again in
    /// a [`Window`].
    pub(crate) inject_bp: bool,
    /// The #BP window open on this vCPU.
    pub(crate) window: Option<Window>,
}

// Handing a #BP back to the guest (`KVM_GUESTDBG_INJECT_BP`). WHP refuses a
// #BP as a pending event: `WHvRegisterPendingInterruption` with a #BP,
// hardware or software exception, length 0 or 1, fails with
// STATUS_HV_INVALID_PARAMETER (0xc0350005), and `WHvRegisterPendingEvent`
// gives an InternalError exit (measured on an AMD host,
// `test_bp_handed_back_to_the_guest` at bf52d6f). So the guest runs its
// INT3 again with #BP out of the partition's exception exits, which only
// natively delivers it. The bitmap is the partition's, so for that window
// the other vCPUs are held out of the guest (`vcpu.rs`, `enter`), and the
// window ends deterministically: DR0 is an instruction breakpoint on the
// handler the gate names (with #DB intercepted), a fault taken before the
// handler's first instruction (SDM vol. 3, 17.2.4; delivery clears RF,
// 6.12.1.2): the #BP delivered and its RIP pushed, nothing else run. A
// delivery that faults (absent gate, task gate, beyond the IDT's limit, DPL
// below CPL, a bad stack) faults the same way natively; the window
// intercepts those faults ([`DELIVERY_FAULTS`]) and starts a round for the
// fault's vector: out of the bitmap, DR0 on its handler, the INT3 run again.
// Each round takes a vector out, so there are at most six; a triple fault
// is a shutdown, as on hardware.

/// The faults an exception's delivery can itself raise: #DF, #TS, #NP,
/// #SS, #GP, #PF.
pub(crate) const DELIVERY_FAULTS: u64 = (1 << 8) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14);

/// DR7 in a window: DR0 an instruction breakpoint (`L0`; R/W0 and LEN0 00),
/// bit 10 (reads as 1).
pub(crate) const WINDOW_DR7: u64 = (1 << 10) | 1;
/// DR7 with no breakpoint.
pub(crate) const DR7_NONE: u64 = 1 << 10;

/// How long the other vCPUs may be held: a window ends at the handler or at
/// a delivery fault. This bound is the last resort for one whose end never
/// comes (no handler could be read and no fault came, as with a stale TLB
/// entry for the IDT); it is cancelled and closed, and says so.
///
/// Why 20 ms. A delivery touches the IDT, the GDT (the handler's code
/// segment), the TSS (a stack switch), the stack (one or two pages) and,
/// for the DR to fire, the handler's address: each can be guest RAM not yet
/// committed (a memory-access exit and a commit, tens of microseconds) or a
/// userfaultfd page (served by the handler process, a round trip through
/// another process, milliseconds under load). Without such faults a window
/// takes microseconds; 2 ms would close one that waits on two or three uffd
/// pages of a busy handler. A window closed early is safe, only slower: the
/// INT3 not yet delivered exits to gdb's stub again, which hands it back
/// again (from the code; not measured). 200 ms would hold every other vCPU,
/// with its timers and interrupts, for a fifth of a second. 20 ms leaves
/// room for several uffd round trips and stays under a guest-visible stall
/// (Linux's soft-lockup and RCU-stall detectors are seconds).
pub(crate) const WINDOW_BOUND: std::time::Duration = std::time::Duration::from_millis(20);

/// How many windows were closed at [`WINDOW_BOUND`]: the tests' check that
/// none needed it.
pub(crate) static WINDOWS_EXPIRED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The partition's exception exits during a window: #DB for its end, and
/// the delivery faults `faults` still intercepted. Never #BP.
pub(crate) fn window_bitmap(faults: u64) -> u64 {
    (1 << DB_VECTOR) | (faults & DELIVERY_FAULTS)
}

/// An open window.
#[derive(Debug, Clone)]
pub(crate) struct Window {
    /// DR0-DR3, DR6, DR7 from before the window, put back at its end.
    pub(crate) saved: [u64; 6],
    /// `WHvRegisterInterruptState`'s NMI mask from before (the window masks
    /// NMIs: one that comes is taken just after it).
    pub(crate) nmi_masked: bool,
    /// The vector being delivered: #BP, or the fault its delivery raised.
    pub(crate) vector: u8,
    /// Its handler, armed in DR0; `None` if its gate gives none.
    pub(crate) handler: Option<u64>,
    /// The delivery faults still intercepted.
    pub(crate) faults: u64,
    /// When it opened, for [`WINDOW_BOUND`].
    pub(crate) opened: std::time::Instant,
}

/// `CR0.PE`, `EFER.LMA`.
const CR0_PE: u64 = 1;
const EFER_LMA: u64 = 1 << 10;

/// The format of the vCPU's interrupt table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TableMode {
    /// The real-mode IVT: 4-byte entries, offset and segment.
    Real,
    /// 8-byte gates.
    Protected,
    /// 16-byte gates.
    Long,
}

pub(crate) fn table_mode(cr0: u64, efer: u64) -> TableMode {
    if cr0 & CR0_PE == 0 {
        TableMode::Real
    } else if efer & EFER_LMA != 0 {
        TableMode::Long
    } else {
        TableMode::Protected
    }
}

/// The linear address and size of `vector`'s entry, `None` beyond the
/// table's limit.
pub(crate) fn gate_at(mode: TableMode, base: u64, limit: u16, vector: u8) -> Option<(u64, usize)> {
    let size: u64 = match mode {
        TableMode::Real => 4,
        TableMode::Protected => 8,
        TableMode::Long => 16,
    };
    let at = u64::from(vector) * size;
    (at + size - 1 <= u64::from(limit)).then_some((base.wrapping_add(at), size as usize))
}

/// Where an entry sends the CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Linear(u64),
    /// Protected mode: the offset in the code segment `selector` names.
    Segment { selector: u16, offset: u64 },
}

/// The target of an entry of `mode` (`gate` of its size); `None` for one
/// that sends nowhere: not present, a task gate or another type. Delivery
/// through such a gate faults, which the window intercepts.
pub(crate) fn gate_target(mode: TableMode, gate: &[u8]) -> Option<Target> {
    let word = |i: usize| u64::from(u16::from_le_bytes([gate[i], gate[i + 1]]));
    match mode {
        TableMode::Real => Some(Target::Linear((word(2) << 4) + word(0))),
        TableMode::Protected | TableMode::Long => {
            let kind = gate[5];
            // Present, a system descriptor (S clear), an interrupt or trap
            // gate (32-bit 0xE/0xF; 16-bit 6/7 outside long mode).
            if kind & 0x80 == 0 || kind & 0x10 != 0 {
                return None;
            }
            match (mode, kind & 0xF) {
                (TableMode::Long, 0xE | 0xF) => {
                    let high = u64::from(u32::from_le_bytes(gate[8..12].try_into().unwrap()));
                    Some(Target::Linear(word(0) | (word(6) << 16) | (high << 32)))
                }
                (TableMode::Protected, 0xE | 0xF) => {
                    Some(Target::Segment { selector: word(2) as u16, offset: word(0) | (word(6) << 16) })
                }
                (TableMode::Protected, 0x6 | 0x7) => Some(Target::Segment { selector: word(2) as u16, offset: word(0) }),
                _ => None,
            }
        }
    }
}

/// The base of a segment descriptor.
pub(crate) fn descriptor_base(d: &[u8; 8]) -> u64 {
    u64::from(d[2]) | (u64::from(d[3]) << 8) | (u64::from(d[4]) << 16) | (u64::from(d[7]) << 24)
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

/// WHP's `WHV_X64_PENDING_INTERRUPTION_REGISTER` for a #GP(0): a hardware
/// exception (type 3), vector 13, with its error code (bit 4), 0.
pub(crate) fn pending_gp() -> u64 {
    1 | (3 << 1) | (1 << 4) | (13 << 16)
}

/// WHP's `WHV_X64_PENDING_INTERRUPTION_REGISTER` for a #SS(0): a hardware
/// exception (type 3), vector 12, with an error code (bit 4) of 0.
pub(crate) fn pending_ss() -> u64 {
    1 | (3 << 1) | (1 << 4) | (12 << 16)
}

/// WHP's `WHV_X64_PENDING_INTERRUPTION_REGISTER` for a #PF with `code`: a
/// hardware exception (type 3), vector 14, with its error code (bit 4) in
/// the upper half. The faulting address goes in CR2 with it.
pub(crate) fn pending_pf(code: u32) -> u64 {
    1 | (3 << 1) | (1 << 4) | (14 << 16) | (u64::from(code) << 32)
}

/// KVM's `INVALID_GPA` (`~0ull`, include/linux/kvm_types.h): the
/// physical address of a translation that failed.
pub(crate) const INVALID_GPA: u64 = u64::MAX;

/// `CR0.PG`.
pub(crate) const CR0_PG: u64 = 1 << 31;

/// The `WHvTranslateGva` flags of KVM's `KVM_TRANSLATE` walk
/// (`kvm_mmu_gva_to_gpa_system`: access 0, "without checking CPL",
/// arch/x86/kvm/x86.c), a supervisor read: `ValidateRead` with
/// `PrivilegeExempt`. WHP refuses a walk with no validate flag (E_INVALIDARG
/// for "none" and "exempt" alone, at the PVH entry and in long mode,
/// measured on a WHP machine, `test_translate_as_kvm_at_the_entry_and_in_long_mode`).
pub(crate) const TRANSLATE_FLAGS: super::whv::WHV_TRANSLATE_GVA_FLAGS =
    super::whv::WHvTranslateGvaFlagValidateRead | super::whv::WHvTranslateGvaFlagPrivilegeExempt;

/// `KVM_TRANSLATE`'s answer, as KVM's `kvm_arch_vcpu_ioctl_translate`
/// (arch/x86/kvm/x86.c, Linux 6.12), which never fails: `walk` is `None`
/// when the vCPU's paging is off, where KVM's `nonpaging_gva_to_gpa`
/// (arch/x86/kvm/mmu/mmu.c) gives the address itself, valid (at the PVH
/// entry, before the guest turns paging on: the whole 64-bit address, where
/// WHP's own walk truncates it to 32 bits in protected mode, measured);
/// otherwise it is `WHvTranslateGva`'s answer for KVM's walk
/// (`kvm_mmu_gva_to_gpa_system`, access 0: a supervisor read, whatever the
/// CPL; [`TRANSLATE_FLAGS`]), `None` when WHP refused the call. Valid only
/// for `WHvTranslateGvaResultSuccess` (0); every other result (page not
/// present, privilege violation, invalid page table flags, a GPA that is not
/// mapped or not readable, an overlay, an intercept) and a refused call are
/// no translation, with `INVALID_GPA`, as KVM's walk that fails: the ioctl
/// never fails. `writeable` is 1 and `usermode` 0 whatever the walk found,
/// as KVM sets them.
pub(crate) fn translation(gva: u64, walk: Option<Option<(i32, u64)>>) -> kvm_translation {
    let gpa = match walk {
        None => Some(gva),
        Some(Some((0, gpa))) => Some(gpa),
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
    fn test_pending_gp_is_a_hardware_exception_13_with_error_code_0() {
        let p = pending_gp();
        assert_eq!(p & 1, 1);
        assert_eq!((p >> 1) & 0x7, 3);
        assert_eq!((p >> 4) & 1, 1, "#GP has an error code");
        assert_eq!((p >> 16) & 0xffff, 13);
        assert_eq!(p >> 32, 0, "error code 0");
    }

    #[test]
    fn test_window_never_intercepts_bp() {
        assert_eq!(window_bitmap(DELIVERY_FAULTS), (1 << 1) | (1 << 8) | (0b1_1111 << 10));
        assert_eq!(window_bitmap(u64::MAX) & (1 << BP_VECTOR), 0);
        // A round takes its fault out; #DB stays for the end.
        assert_eq!(window_bitmap(DELIVERY_FAULTS & !(1 << 11)) & (1 << 11), 0);
        assert_eq!(window_bitmap(0), 1 << 1);
        assert_eq!(WINDOW_DR7 & 0b11, 1, "L0 only");
        assert_eq!((WINDOW_DR7 >> 16) & 0xF, 0, "an instruction breakpoint, length 1");
    }

    #[test]
    fn test_table_modes_and_entries() {
        assert_eq!(table_mode(0x10, 0), TableMode::Real);
        assert_eq!(table_mode(0x11, 0), TableMode::Protected);
        assert_eq!(table_mode(0x8000_0011, 0x500), TableMode::Long);
        // Within the limit: the entry's last byte at most the limit.
        assert_eq!(gate_at(TableMode::Long, 0x5000, 4095, 3), Some((0x5030, 16)));
        assert_eq!(gate_at(TableMode::Long, 0x5000, 0x3F, 3), Some((0x5030, 16)));
        assert_eq!(gate_at(TableMode::Long, 0x5000, 0x3E, 3), None);
        assert_eq!(gate_at(TableMode::Protected, 0x100, 0x1F, 3), Some((0x118, 8)));
        assert_eq!(gate_at(TableMode::Real, 0, 0x3FF, 3), Some((12, 4)));
    }

    #[test]
    fn test_gate_targets() {
        // Long mode: an interrupt gate (0x8E) and a trap gate (0x8F) to
        // 0xffff_ffff_8100_1234; Linux's int3 gate has DPL 3 (0xEE).
        let long = |kind: u8| {
            let mut g = [0u8; 16];
            g[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
            g[2..4].copy_from_slice(&0x10u16.to_le_bytes());
            g[5] = kind;
            g[6..8].copy_from_slice(&0x8100u16.to_le_bytes());
            g[8..12].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
            g
        };
        for kind in [0x8E, 0x8F, 0xEE] {
            assert_eq!(gate_target(TableMode::Long, &long(kind)), Some(Target::Linear(0xffff_ffff_8100_1234)));
        }
        // Not present, a task gate (in long mode: #GP), a 16-bit gate, a
        // code descriptor: nowhere.
        for kind in [0x0E, 0x85, 0x86, 0x9A] {
            assert_eq!(gate_target(TableMode::Long, &long(kind)), None, "{kind:#x}");
        }
        // Protected mode: 32-bit and 16-bit gates go through the selector;
        // a task gate goes nowhere.
        let mut g = [0u8; 8];
        g[0..2].copy_from_slice(&0x5678u16.to_le_bytes());
        g[2..4].copy_from_slice(&0x08u16.to_le_bytes());
        g[6..8].copy_from_slice(&0x0010u16.to_le_bytes());
        g[5] = 0x8E;
        assert_eq!(gate_target(TableMode::Protected, &g), Some(Target::Segment { selector: 8, offset: 0x10_5678 }));
        g[5] = 0x86;
        assert_eq!(gate_target(TableMode::Protected, &g), Some(Target::Segment { selector: 8, offset: 0x5678 }));
        g[5] = 0x85;
        assert_eq!(gate_target(TableMode::Protected, &g), None);
        // Real mode: segment * 16 + offset.
        assert_eq!(gate_target(TableMode::Real, &[0x34, 0x12, 0x00, 0xF0]), Some(Target::Linear(0xF1234)));
        // A flat code segment's base, and one at 0x1234_5600.
        assert_eq!(descriptor_base(&0x00CF_9A00_0000_FFFFu64.to_le_bytes()), 0);
        assert_eq!(descriptor_base(&0x12CF_9A34_5600_FFFFu64.to_le_bytes()), 0x1234_5600);
    }

    #[test]
    fn test_translation_result_codes() {
        let t = translation(0xffff_ffff_8100_0123, Some(Some((0, 0x100_0123))));
        assert_eq!(
            (t.linear_address, t.physical_address, t.valid, t.writeable, t.usermode),
            (0xffff_ffff_8100_0123, 0x100_0123, 1, 1, 0)
        );
        // PageNotPresent .. Intercept: no translation, KVM's INVALID_GPA;
        // the call itself succeeds and writeable is still 1, as KVM's.
        for code in 1..=8 {
            let t = translation(0x10, Some(Some((code, 0x99))));
            assert_eq!((t.valid, t.physical_address, t.writeable), (0, INVALID_GPA, 1), "result code {code}");
        }
        // A walk WHP refused: no translation, the call still succeeds.
        let t = translation(0x10, Some(None));
        assert_eq!((t.valid, t.physical_address, t.writeable), (0, INVALID_GPA, 1));
        // ValidateRead | PrivilegeExempt (winhvplatformdefs.h).
        assert_eq!(TRANSLATE_FLAGS, 0x1 | 0x8);
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
