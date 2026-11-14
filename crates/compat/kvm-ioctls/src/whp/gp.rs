// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The general-protection exits of an x2APIC partition (option E of the
//! x2APIC plan): what the run loop does with a guest #GP that WHP hands it
//! (`ExceptionExit`, vector 13 in the exception exit bitmap), decided
//! without a WHP call, so that its tests run on any host (the fuzz crate's
//! lib tests, `whp_gp`).
//!
//! WHP's x2APIC answers every x2APIC register access in the hypervisor but
//! one: a guest's `WRMSR` of the LVT timer entry (0x832) that selects
//! TSC-deadline mode raises #GP in the guest (X2APICREC, GPEXITREC), where
//! KVM takes it (`kvm_x2apic_msr_write`, Linux v6.1 arch/x86/kvm/lapic.c
//! 2956-2965). So that one write is finished here, as KVM finishes it, and
//! every other #GP goes back to the guest as the processor raised it, the
//! way KVM's `#GP` intercept gives back what it does not emulate
//! (`kvm_queue_exception_e(vcpu, GP_VECTOR, error_code)`, v6.1
//! arch/x86/kvm/vmx/vmx.c 5091-5103):
//!
//! - [`wrmsr_length`]: the instruction is a `WRMSR` (`0F 30`), after legacy
//!   prefixes and, in 64-bit code, a REX prefix, within the 15 bytes an
//!   instruction may have;
//! - [`lvtt_write`]: what KVM stores for the write: the low 32 bits
//!   (`kvm_lapic_msr_write`, lapic.c 2943-2954), masked with the APIC
//!   software-disabled, and kept to the entry's fields
//!   (`LVT_MASK | timer_mode_mask`, lapic.c 2186-2192), the timer mode
//!   field two bits wide only when the guest's CPUID has TSC_DEADLINE
//!   (`timer_mode_mask`, v6.1 arch/x86/kvm/cpuid.c 329-334);
//! - [`decide`]: the write is emulated only at CPL 0 (above it the
//!   processor raises #GP before any MSR intercept), in x2APIC mode
//!   (APIC_BASE.EXTD: KVM's write is #GP outside it, lapic.c 2961-2962),
//!   for ECX 0x832; anything else is given back;
//! - [`give_back`]: the #GP, merged with the event WHP was delivering when
//!   it was raised (WHP shows it in `WHvRegisterPendingInterruption`:
//!   X2E0REC a, CI run 43521200989) as KVM's `kvm_multiple_exception`
//!   merges exceptions (v6.1 arch/x86/kvm/x86.c 694-718): during a #DF, a
//!   triple fault (shutdown); during a contributory exception (#DE, #TS,
//!   #NP, #SS, #GP) or a #PF, a #DF with error code 0; during any other
//!   exception, the #GP in its place. During an external interrupt, an NMI
//!   or a software interrupt (`INT n`) the #GP is given alone, as the
//!   processor gives it (the error code's EXT and IDT bits name the
//!   event); KVM keeps such an interrupt and injects it again after the
//!   #GP (`interrupt.injected`, kept by `kvm_check_and_inject_events`),
//!   which a guest with a working IDT never sees, as its delivery cannot
//!   fault.

/// The #GP's vector.
pub const GP_VECTOR: u8 = 13;
/// The #DF's vector.
pub const DF_VECTOR: u8 = 8;
/// The x2APIC LVT timer entry's MSR.
pub const MSR_X2APIC_LVTT: u32 = 0x832;
/// `APIC_LVT_MASKED`.
pub const LVT_MASKED: u32 = 1 << 16;
/// `APIC_SEND_PENDING`.
const LVT_SEND_PENDING: u32 = 1 << 12;
/// `APIC_VECTOR_MASK`.
const LVT_VECTOR: u32 = 0xff;
/// The timer mode field (bits 18:17).
pub const TIMER_MODE: u32 = 0b11 << 17;
/// TSC-deadline mode (`APIC_LVT_TIMER_TSCDEADLINE`).
pub const TIMER_TSC_DEADLINE: u32 = 0b10 << 17;
/// Periodic mode (`APIC_LVT_TIMER_PERIODIC`).
const TIMER_PERIODIC: u32 = 0b01 << 17;
/// The longest instruction x86 decodes.
const MAX_INSTRUCTION: usize = 15;

/// `WHV_X64_PENDING_INTERRUPTION_REGISTER`'s fields (regs.rs has the same
/// encoding for `kvm_vcpu_events`).
const PI_PENDING: u64 = 1;
const PI_TYPE_SHIFT: u32 = 1;
const PI_DELIVER_ERROR_CODE: u64 = 1 << 4;
const PI_VECTOR_SHIFT: u32 = 16;
const PI_ERROR_CODE_SHIFT: u32 = 32;
const PI_TYPE_EXCEPTION: u64 = 3;
/// Software exceptions (`INT1`; `INT3`, `INTO`): exceptions to KVM's merge.
const PI_TYPE_PRIVILEGED_SOFTWARE_EXCEPTION: u64 = 5;
const PI_TYPE_SOFTWARE_EXCEPTION: u64 = 6;

/// The length of the `WRMSR` at the start of `bytes`, or `None` if they do
/// not start with one: legacy prefixes (operand and address size, segment
/// overrides, `REP`/`REPNE`; not `LOCK`, which makes `WRMSR` a #UD), then
/// in 64-bit code (`long_mode`) at most one REX prefix right before the
/// opcode, then `0F 30`, within 15 bytes.
pub fn wrmsr_length(bytes: &[u8], long_mode: bool) -> Option<u8> {
    let mut at = 0;
    while at < bytes.len().min(MAX_INSTRUCTION) {
        match bytes[at] {
            0x66 | 0x67 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0xF2 | 0xF3 => at += 1,
            0x40..=0x4F if long_mode => {
                // A REX prefix counts only right before the opcode.
                let rest = &bytes[at + 1..];
                return (rest.starts_with(&[0x0F, 0x30]) && at + 3 <= MAX_INSTRUCTION).then(|| (at + 3) as u8);
            }
            0x0F => {
                return (bytes.get(at + 1) == Some(&0x30) && at + 2 <= MAX_INSTRUCTION).then(|| (at + 2) as u8);
            }
            _ => return None,
        }
    }
    None
}

/// What KVM stores in the LVT timer entry for a guest's write of `eax`
/// (the MSR's low 32 bits; its high ones are not looked at): masked if the
/// APIC is software-disabled (`sw_enabled` false), and kept to the
/// entry's fields, the timer mode two bits wide only if the guest's CPUID
/// has TSC_DEADLINE (`tsc_deadline`), one bit (one-shot or periodic) if not.
pub fn lvtt_write(eax: u32, sw_enabled: bool, tsc_deadline: bool) -> u32 {
    let mut value = eax;
    if !sw_enabled {
        value |= LVT_MASKED;
    }
    let mode = if tsc_deadline { TIMER_MODE } else { TIMER_PERIODIC };
    value & (LVT_MASKED | LVT_SEND_PENDING | LVT_VECTOR | mode)
}

/// Whether an LVT timer entry `value` is in TSC-deadline mode, as KVM's
/// `apic_lvtt_tscdeadline`.
pub fn tsc_deadline_mode(value: u32) -> bool {
    value & TIMER_MODE == TIMER_TSC_DEADLINE
}

/// What a #GP exit comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The guest's x2APIC write of the LVT timer entry: `length` bytes of
    /// instruction, the MSR's low 32 bits `eax`.
    LvttWrite { length: u8, eax: u32 },
    /// Anything else: the #GP goes back to the guest ([`give_back`]).
    GiveBack,
}

/// The decision for a #GP raised at CPL `cpl` by the instruction whose
/// first bytes are `bytes`, in 64-bit code if `long_mode`, with APIC_BASE's
/// EXTD `x2apic` and ECX `ecx`, EAX `eax`. An event being delivered when
/// the #GP was raised (`delivering`) is no instruction's: given back.
pub fn decide(cpl: u8, delivering: bool, bytes: &[u8], long_mode: bool, x2apic: bool, ecx: u32, eax: u32) -> Decision {
    if delivering || cpl != 0 || !x2apic || ecx != MSR_X2APIC_LVTT {
        return Decision::GiveBack;
    }
    match wrmsr_length(bytes, long_mode) {
        Some(length) => Decision::LvttWrite { length, eax },
        None => Decision::GiveBack,
    }
}

/// Whether the guest's instruction is worth reading ECX and APIC_BASE for:
/// a `WRMSR` at CPL 0 raised outside an event's delivery. The run loop asks
/// this before it reads the two registers, so that a guest's other #GPs
/// cost it no register read.
pub fn may_emulate(cpl: u8, delivering: bool, bytes: &[u8], long_mode: bool) -> bool {
    cpl == 0 && !delivering && wrmsr_length(bytes, long_mode).is_some()
}

/// What the guest gets for a #GP with `error_code` raised while WHP was
/// delivering `pending` (`WHvRegisterPendingInterruption`; 0 or not
/// pending: nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiveBack {
    /// The pending-interruption register to set.
    Event(u64),
    /// A triple fault: `KVM_EXIT_SHUTDOWN`.
    Shutdown,
}

/// A hardware exception's pending-interruption value.
pub fn exception(vector: u8, error_code: Option<u32>) -> u64 {
    PI_PENDING
        | (PI_TYPE_EXCEPTION << PI_TYPE_SHIFT)
        | error_code.map_or(0, |e| PI_DELIVER_ERROR_CODE | (u64::from(e) << PI_ERROR_CODE_SHIFT))
        | (u64::from(vector) << PI_VECTOR_SHIFT)
}

/// KVM's `exception_class`: contributory, page fault or benign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Contributory,
    PageFault,
    Benign,
}

fn class(vector: u8) -> Class {
    match vector {
        14 => Class::PageFault,
        0 | 10 | 11 | 12 | 13 => Class::Contributory,
        _ => Class::Benign,
    }
}

/// The #GP with `error_code`, merged with `pending` as KVM merges a #GP
/// with the exception it was delivering (module documentation).
pub fn give_back(pending: u64, error_code: u32) -> GiveBack {
    let gp = GiveBack::Event(exception(GP_VECTOR, Some(error_code)));
    if pending & PI_PENDING == 0 {
        return gp;
    }
    let kind = (pending >> PI_TYPE_SHIFT) & 0x7;
    if !matches!(kind, PI_TYPE_EXCEPTION | PI_TYPE_PRIVILEGED_SOFTWARE_EXCEPTION | PI_TYPE_SOFTWARE_EXCEPTION) {
        // An external interrupt, an NMI or a software interrupt.
        return gp;
    }
    #[allow(clippy::cast_possible_truncation)]
    let prev = (pending >> PI_VECTOR_SHIFT) as u8;
    if prev == DF_VECTOR {
        return GiveBack::Shutdown;
    }
    match (class(prev), class(GP_VECTOR)) {
        (Class::Contributory, Class::Contributory) | (Class::PageFault, Class::Contributory | Class::PageFault) => {
            GiveBack::Event(exception(DF_VECTOR, Some(0)))
        }
        _ => gp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_wrmsr_is_found_after_its_prefixes() {
        assert_eq!(wrmsr_length(&[0x0F, 0x30, 0xE6, 0x80], true), Some(2));
        assert_eq!(wrmsr_length(&[0x0F, 0x30], false), Some(2));
        assert_eq!(wrmsr_length(&[0x48, 0x0F, 0x30], true), Some(3), "REX.W");
        assert_eq!(wrmsr_length(&[0x66, 0x2E, 0x41, 0x0F, 0x30], true), Some(5));
        assert_eq!(wrmsr_length(&[0x48, 0x0F, 0x30], false), None, "0x48 is DEC EAX outside 64-bit code");
        assert_eq!(wrmsr_length(&[0x48, 0x66, 0x0F, 0x30], true), None, "a REX before another prefix is not one");
        assert_eq!(wrmsr_length(&[0xF0, 0x0F, 0x30], true), None, "LOCK WRMSR is #UD");
        assert_eq!(wrmsr_length(&[0x0F, 0x32], true), None, "RDMSR");
        assert_eq!(wrmsr_length(&[0x0F], true), None);
        assert_eq!(wrmsr_length(&[], true), None);
        assert_eq!(wrmsr_length(&[0x8E, 0xD8], true), None, "MOV DS");
        let mut fits = [0x66u8; 15];
        fits[13] = 0x0F;
        fits[14] = 0x30;
        assert_eq!(wrmsr_length(&fits, true), Some(15), "13 prefixes and the opcode: 15 bytes");
        let mut long = [0x66u8; 16];
        long[14] = 0x0F;
        long[15] = 0x30;
        assert_eq!(wrmsr_length(&long, true), None, "14 prefixes and the opcode: one byte too many");
    }

    #[test]
    fn test_the_lvt_timer_write_is_kvms() {
        // Linux's TSC-deadline write.
        assert_eq!(lvtt_write(0x400ec, true, true), 0x400ec);
        // Without TSC_DEADLINE in the CPUID the mode is one bit.
        assert_eq!(lvtt_write(0x400ec, true, false), 0xec);
        assert_eq!(lvtt_write(0x200ec, true, false), 0x200ec);
        // Software-disabled: masked.
        assert_eq!(lvtt_write(0x400ec, false, true), 0x500ec);
        // Reserved bits dropped, not a #GP; mode 11 kept as KVM keeps it.
        assert_eq!(lvtt_write(0xfff9_f0ec, true, true), 0x1_10ec);
        assert_eq!(lvtt_write(0x600ec, true, true), 0x600ec);
        assert!(tsc_deadline_mode(0x400ec));
        assert!(tsc_deadline_mode(0x500ec));
        assert!(!tsc_deadline_mode(0x600ec));
        assert!(!tsc_deadline_mode(0x200ec));
        assert!(!tsc_deadline_mode(0xec));
    }

    #[test]
    fn test_only_the_x2apic_lvt_timer_write_at_cpl_0_is_emulated() {
        let wrmsr = [0x0F, 0x30, 0xE6, 0x80];
        assert_eq!(decide(0, false, &wrmsr, true, true, 0x832, 0x400ec), Decision::LvttWrite { length: 2, eax: 0x400ec });
        assert_eq!(decide(3, false, &wrmsr, true, true, 0x832, 0x400ec), Decision::GiveBack, "CPL 3");
        assert_eq!(decide(0, false, &wrmsr, true, false, 0x832, 0x400ec), Decision::GiveBack, "xAPIC mode");
        assert_eq!(decide(0, false, &wrmsr, true, true, 0x830, 0), Decision::GiveBack, "another MSR");
        assert_eq!(decide(0, true, &wrmsr, true, true, 0x832, 0x400ec), Decision::GiveBack, "during a delivery");
        assert_eq!(decide(0, false, &[0x0F, 0x32], true, true, 0x832, 0), Decision::GiveBack, "RDMSR");
        assert!(may_emulate(0, false, &wrmsr, true));
        assert!(!may_emulate(1, false, &wrmsr, true));
        assert!(!may_emulate(0, false, &[0xFA], true), "CLI");
    }

    #[test]
    fn test_a_gp_merges_with_the_event_being_delivered_as_kvms() {
        let gp = |e: u32| GiveBack::Event(exception(GP_VECTOR, Some(e)));
        // X2E0REC a's values.
        assert_eq!(exception(GP_VECTOR, Some(0)), 0xd0017);
        assert_eq!(exception(DF_VECTOR, Some(0)), 0x80017);
        assert_eq!(exception(GP_VECTOR, Some(0x1234)), 0x1234_000d_0017);
        // Nothing being delivered.
        assert_eq!(give_back(0, 0), gp(0));
        assert_eq!(give_back(0xd0016, 0x20), gp(0x20), "not pending");
        // An external interrupt (vector 0x41, X2E0REC a): the #GP alone.
        assert_eq!(give_back(0x41_0001, 0x20b), gp(0x20b));
        // An NMI, a software interrupt.
        assert_eq!(give_back(0x2_0005, 0x12), gp(0x12));
        assert_eq!(give_back(0x80_0009, 0x402), gp(0x402));
        // A #GP being delivered: a #DF (X2E0REC a: its handler ran).
        assert_eq!(give_back(0xd0017, 0x6a), GiveBack::Event(0x80017));
        // A #DF being delivered: shutdown.
        assert_eq!(give_back(0x80017, 0x42), GiveBack::Shutdown);
        // #PF, #NP: a #DF.
        assert_eq!(give_back(exception(14, Some(2)), 0), GiveBack::Event(0x80017));
        assert_eq!(give_back(exception(11, Some(8)), 0), GiveBack::Event(0x80017));
        // A benign exception (#UD, #BP as a software exception): the #GP.
        assert_eq!(give_back(exception(6, None), 0x18), gp(0x18));
        assert_eq!(give_back(PI_PENDING | (PI_TYPE_SOFTWARE_EXCEPTION << PI_TYPE_SHIFT) | (3 << PI_VECTOR_SHIFT), 0x1a), gp(0x1a));
    }
}
