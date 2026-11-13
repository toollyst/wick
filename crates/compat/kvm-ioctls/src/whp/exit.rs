// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! What the WHP run loop (`vcpu.rs`, `run`) decides from what a vCPU exit
//! reports, without a WHP call: the guest controls every field read here, so
//! this module is compiled into the `whp_exit` fuzz target on any host
//! (`fuzz/fuzz_targets/whp_exit.rs`) and checked there against the x86
//! architecture's rules, as `hvf/exit.rs` is against the Arm ARM. The run
//! loop reads the fields from WHP's exit context and calls these.

/// The length of the instruction that exited, from the exit context's
/// `InstructionLength` (the low 4 bits of its bit field): x86 instructions
/// are at most 15 bytes.
pub fn instruction_length(bitfield: u8) -> u64 {
    u64::from(bitfield & 0x0f)
}

/// A port access (`WHV_X64_IO_PORT_ACCESS_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortAccess {
    /// `OUT` (else `IN`).
    pub write: bool,
    /// The access size in bytes: 1, 2 or 4.
    pub size: usize,
    /// `INS`/`OUTS`.
    pub string: bool,
    /// With a `REP` prefix.
    pub rep: bool,
}

/// Decodes a port access's information word: bit 0 `IsWrite`, bits 1-3
/// `AccessSize`, bit 4 `StringOp`, bit 5 `RepPrefix`. `None` for a size x86
/// port I/O does not have (only 1, 2 and 4 bytes): the run loop fails the
/// run, as KVM never reports another.
pub fn port_access(info: u32) -> Option<PortAccess> {
    let size = ((info >> 1) & 0x7) as usize;
    matches!(size, 1 | 2 | 4).then_some(PortAccess {
        write: info & 1 != 0,
        size,
        string: (info >> 4) & 1 != 0,
        rep: (info >> 5) & 1 != 0,
    })
}

/// Whether a memory access (`WHV_MEMORY_ACCESS_INFO`, its `AccessType` in
/// bits 0-1: 0 read, 1 write, 2 execute) was a write.
pub fn memory_write(info: u32) -> bool {
    info & 0x3 == 1
}

/// An MSR access: whether it is a `WRMSR` (bit 0 of its information word)
/// and the value it writes, `EDX:EAX` (the upper halves of `RAX` and `RDX`
/// are not part of it).
pub fn msr_access(info: u32, rax: u64, rdx: u64) -> (bool, u64) {
    (info & 1 != 0, (rdx << 32) | (rax & 0xffff_ffff))
}

/// `RAX` after an `IN` of `size` bytes that read `value`: a byte or a word
/// leaves the rest of `RAX` as it was; a doubleword zero-extends into `RAX`,
/// as every 32-bit register write does in 64-bit mode (KVM: `complete_pio`).
pub fn in_result(rax: u64, value: u64, size: usize) -> u64 {
    match size {
        1 => (rax & !0xff) | (value & 0xff),
        2 => (rax & !0xffff) | (value & 0xffff),
        4 => value & 0xffff_ffff,
        _ => value,
    }
}

/// The CPUID bits KVM computes from the vCPU's state at each `CPUID`
/// (`kvm_update_cpuid_runtime`), applied to the table's `ECX`: leaf 1's
/// OSXSAVE (bit 27) is CR4.OSXSAVE (bit 18), leaf 7 subleaf 0's OSPKE
/// (bit 4) is CR4.PKE (bit 22). Other leaves are returned as they are.
pub fn cpuid_ecx(function: u32, index: u32, ecx: u32, cr4: u64) -> u32 {
    let follow = |ecx: u32, bit: u32, cr4_bit: u32| (ecx & !(1 << bit)) | (u32::from(cr4 & (1 << cr4_bit) != 0) << bit);
    match (function, index) {
        (0x1, _) => follow(ecx, 27, 18),
        (0x7, 0) => follow(ecx, 4, 22),
        _ => ecx,
    }
}

/// The vCPU's current privilege level, from the exit context's
/// `ExecutionState` (`WHV_X64_VP_EXECUTION_STATE`: `Cpl` is bits 0-1).
pub fn cpl(execution_state: u16) -> u8 {
    (execution_state & 3) as u8
}

/// Whether the vCPU runs 64-bit code, as KVM's `is_64_bit_hypercall`
/// (`is_64_bit_mode`) decides: long mode (`ExecutionState.EferLma`, bit 4) and
/// a 64-bit code segment (the exit context's `Cs` attributes, `Long`, bit 13).
pub fn long_mode_code(execution_state: u16, cs_attributes: u16) -> bool {
    execution_state >> 4 & 1 == 1 && cs_attributes >> 13 & 1 == 1
}

/// What a KVM hypercall (`kvm_emulate_hypercall`: `nr` in RAX, its first
/// two arguments in RBX and RCX) is answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hypercall {
    /// `KVM_HC_VAPIC_POLL_IRQ`: 0, nothing to do.
    PollIrq,
    /// `KVM_HC_CLOCK_PAIRING` with `KVM_CLOCK_PAIRING_WALLCLOCK`: the
    /// structure at the guest physical address in the first argument.
    ClockPairing { gpa: u64 },
    /// An error, as `RAX` (`-KVM_EOPNOTSUPP` for another clock type,
    /// `-KVM_ENOSYS` for a hypercall KVM does not know).
    Error(u64),
}

/// Decodes a KVM hypercall made at privilege level `cpl`, in 64-bit code or
/// not (`op_64_bit`), as KVM's `__kvm_emulate_hypercall` (arch/x86/kvm/x86.c)
/// does: outside 64-bit code the number and the arguments are their low 32
/// bits, and a hypercall from any privilege level but 0 is `-KVM_EPERM`
/// whatever its number (so guest user space cannot have the host write
/// guest memory for it).
pub fn hypercall(nr: u64, a0: u64, a1: u64, op_64_bit: bool, cpl: u8) -> Hypercall {
    const KVM_ENOSYS: i64 = 1000;
    const KVM_EPERM: i64 = 1;
    const KVM_EOPNOTSUPP: i64 = 95;
    const KVM_HC_VAPIC_POLL_IRQ: u64 = 1;
    const KVM_HC_CLOCK_PAIRING: u64 = 9;
    const KVM_CLOCK_PAIRING_WALLCLOCK: u64 = 0;
    let (nr, a0, a1) = if op_64_bit { (nr, a0, a1) } else { (nr & 0xffff_ffff, a0 & 0xffff_ffff, a1 & 0xffff_ffff) };
    if cpl != 0 {
        return Hypercall::Error((-KVM_EPERM).cast_unsigned());
    }
    match nr {
        KVM_HC_VAPIC_POLL_IRQ => Hypercall::PollIrq,
        KVM_HC_CLOCK_PAIRING if a1 == KVM_CLOCK_PAIRING_WALLCLOCK => Hypercall::ClockPairing { gpa: a0 },
        KVM_HC_CLOCK_PAIRING => Hypercall::Error((-KVM_EOPNOTSUPP).cast_unsigned()),
        _ => Hypercall::Error((-KVM_ENOSYS).cast_unsigned()),
    }
}

/// The `RAX` a hypercall's result leaves: outside 64-bit code its low 32
/// bits, as KVM's `kvm_emulate_hypercall` writes it.
pub fn hypercall_rax(result: u64, op_64_bit: bool) -> u64 {
    if op_64_bit { result } else { result & 0xffff_ffff }
}

/// A segment register a prefix names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

/// How a string port instruction (`INS`, `OUTS`) addresses memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringAddressing {
    /// The width of `RSI`, `RDI` and `RCX` as the instruction uses them: 2,
    /// 4 or 8 bytes.
    pub address_bytes: u8,
    /// The segment a prefix puts in `DS`'s place for `OUTS`'s source (the
    /// last such prefix counts); `INS` writes through `ES` whatever the
    /// prefix.
    pub segment: Option<Segment>,
}

/// Reads a string port instruction's prefixes from its bytes (the exit's
/// `InstructionBytes`), in 64-bit code (`long`) or code whose segment's
/// default size is 32 bits (`default_32`) or 16: the address size is the
/// mode's (64, 32, 16) unless the prefix 0x67 gives the other one (32, 16,
/// 32), as KVM's decoder sets `ad_bytes` (Linux v6.1 arch/x86/kvm/emulate.c,
/// `x86_decode_insn`: `def_ad_bytes ^ 6` outside 64-bit mode, 4 in it).
/// Bytes that are not legacy prefixes end the prefixes (a REX prefix, the
/// opcode).
pub fn string_addressing(bytes: &[u8], long: bool, default_32: bool) -> StringAddressing {
    let mut other_size = false;
    let mut segment = None;
    for &b in bytes {
        match b {
            0x26 => segment = Some(Segment::Es),
            0x2e => segment = Some(Segment::Cs),
            0x36 => segment = Some(Segment::Ss),
            0x3e => segment = Some(Segment::Ds),
            0x64 => segment = Some(Segment::Fs),
            0x65 => segment = Some(Segment::Gs),
            0x67 => other_size = true,
            0x66 | 0xf0 | 0xf2 | 0xf3 => {}
            _ => break,
        }
    }
    let address_bytes = match (long, default_32, other_size) {
        (true, _, false) => 8,
        (true, _, true) | (false, true, false) | (false, false, true) => 4,
        (false, true, true) | (false, false, false) => 2,
    };
    StringAddressing { address_bytes, segment }
}

/// The part of `reg` an instruction with addresses of `address_bytes` uses
/// (KVM's `address_mask`).
pub fn string_offset(reg: u64, address_bytes: u8) -> u64 {
    match address_bytes {
        8 => reg,
        4 => reg & 0xffff_ffff,
        _ => reg & 0xffff,
    }
}

/// How many elements a string instruction has left: `RCX` at the address
/// size with a `REP` prefix (which may be 0: the instruction then does
/// nothing), 1 without.
pub fn string_count(rep: bool, rcx: u64, address_bytes: u8) -> u64 {
    if rep { string_offset(rcx, address_bytes) } else { 1 }
}

/// `reg` moved by `by`, down or up, as an instruction with addresses of
/// `address_bytes` leaves it (KVM's `assign_register` through
/// `register_address_increment`): the whole register at 8 bytes; its low
/// half with the upper half cleared at 4, as a 32-bit register write is; its
/// low 16 bits with the rest kept at 2.
pub fn string_advance(reg: u64, address_bytes: u8, by: u64, down: bool) -> u64 {
    let moved = if down { reg.wrapping_sub(by) } else { reg.wrapping_add(by) };
    match address_bytes {
        8 => moved,
        4 => moved & 0xffff_ffff,
        _ => (reg & !0xffff) | (moved & 0xffff),
    }
}

/// How many elements of `size` bytes KVM reads from the port at once for an
/// `INS` with `count` left (emulate.c, `pio_in_emulated`): the least of what
/// is left, what its 1024-byte buffer holds, and the bytes to the end of
/// `RDI`'s page (from its start, with the direction flag set: `down`),
/// which KVM takes as a number of elements whatever their size; at least
/// one.
pub fn ins_read_ahead(size: usize, rdi: u64, count: u64, down: bool) -> usize {
    let offset = rdi % 4096;
    let in_page = if down { offset } else { 4096 - offset };
    #[allow(clippy::cast_possible_truncation)]
    let n = in_page.min(1024 / size as u64).min(count) as usize;
    n.max(1)
}

/// The linear address of `offset` in a segment of base `base`: 64 bits in
/// 64-bit code, 32 otherwise (KVM's `linearize`).
pub fn linear_address(base: u64, offset: u64, long: bool) -> u64 {
    let la = base.wrapping_add(offset);
    if long { la } else { la & 0xffff_ffff }
}

/// A page fault's error code: `P` for a fault on a page that is present,
/// `W` for a write, `U` from privilege level 3, `RSVD` for reserved bits
/// set in a page table entry (which is a fault on a present page).
pub fn page_fault_code(present: bool, write: bool, user: bool, reserved: bool) -> u32 {
    u32::from(present || reserved) | u32::from(write) << 1 | u32::from(user) << 2 | u32::from(reserved) << 3
}

#[cfg(test)]
mod tests {
    use super::*;

    // The address size of INS and OUTS by mode and prefix, and the segment
    // an OUTS reads through.
    #[test]
    fn test_string_addressing() {
        let of = |bytes: &[u8], long, d32| string_addressing(bytes, long, d32);
        assert_eq!(of(&[0xf3, 0x6e], true, false), StringAddressing { address_bytes: 8, segment: None });
        assert_eq!(of(&[0x67, 0xf3, 0x6e], true, false).address_bytes, 4);
        assert_eq!(of(&[0xf3, 0x6c], false, true).address_bytes, 4);
        assert_eq!(of(&[0x67, 0x6c], false, true).address_bytes, 2);
        assert_eq!(of(&[0x6c], false, false).address_bytes, 2);
        assert_eq!(of(&[0x67, 0x6c], false, false).address_bytes, 4);
        // The last segment prefix counts; an operand-size prefix is none.
        assert_eq!(of(&[0x2e, 0x65, 0x66, 0x6f], true, false).segment, Some(Segment::Gs));
        // A REX prefix ends the prefixes: a 0x67 after it is not one.
        assert_eq!(of(&[0x48, 0x67, 0x6f], true, false).address_bytes, 8);
        assert_eq!(of(&[], true, false), StringAddressing { address_bytes: 8, segment: None });
    }

    #[test]
    fn test_string_registers() {
        let r = 0x1122_3344_ffff_ffff;
        assert_eq!(string_offset(r, 8), r);
        assert_eq!(string_offset(r, 4), 0xffff_ffff);
        assert_eq!(string_offset(r, 2), 0xffff);
        assert_eq!(string_count(false, 0, 8), 1);
        assert_eq!(string_count(true, 0x1_0000_0000, 4), 0);
        assert_eq!(string_count(true, 0x1_0000_0003, 8), 0x1_0000_0003);
        // Up at 8 bytes wraps; at 4 the upper half is cleared; at 2 the
        // rest is kept.
        assert_eq!(string_advance(u64::MAX, 8, 1, false), 0);
        assert_eq!(string_advance(r, 4, 1, false), 0);
        assert_eq!(string_advance(r, 2, 1, false), 0x1122_3344_ffff_0000);
        assert_eq!(string_advance(0x1_0000_0000, 4, 4, true), 0xffff_fffc);
        assert_eq!(string_advance(0x10, 8, 4, true), 0xc);
        assert_eq!(linear_address(u64::MAX, 2, true), 1);
        assert_eq!(linear_address(0xffff_fff0, 0x20, false), 0x10);
    }

    // KVM's read-ahead for INS, with its own arithmetic: bytes to the page's
    // end taken as a number of elements, the buffer of 1024 bytes, at least
    // one element.
    #[test]
    fn test_ins_read_ahead() {
        assert_eq!(ins_read_ahead(1, 0x8400, 3, false), 3);
        assert_eq!(ins_read_ahead(1, 0x8400, 5000, false), 1024);
        assert_eq!(ins_read_ahead(4, 0x8400, 5000, false), 256);
        assert_eq!(ins_read_ahead(2, 0x8ffe, 100, false), 2);
        assert_eq!(ins_read_ahead(1, 0x8421, 2, true), 2);
        assert_eq!(ins_read_ahead(1, 0x8001, 9, true), 1);
        // At a page's start going down, nothing is "in the page": one.
        assert_eq!(ins_read_ahead(4, 0x8000, 9, true), 1);
        assert_eq!(ins_read_ahead(1, 0x8400, 1, false), 1);
    }

    #[test]
    fn test_page_fault_code() {
        assert_eq!(page_fault_code(false, false, false, false), 0);
        assert_eq!(page_fault_code(false, true, true, false), 0b110);
        assert_eq!(page_fault_code(true, true, false, false), 0b011);
        assert_eq!(page_fault_code(false, false, true, true), 0b1101);
    }

    #[test]
    fn test_port_access() {
        // OUT DX, AL: write, 1 byte.
        assert_eq!(port_access(0b0_0011), Some(PortAccess { write: true, size: 1, string: false, rep: false }));
        // REP INSD: 4 bytes, string, rep.
        assert_eq!(port_access(0b11_1000), Some(PortAccess { write: false, size: 4, string: true, rep: true }));
        for size in [0, 3, 5, 6, 7] {
            assert_eq!(port_access(size << 1), None, "size {size}");
        }
    }

    #[test]
    fn test_in_result() {
        let rax = 0x1122_3344_5566_7788;
        assert_eq!(in_result(rax, 0xab, 1), 0x1122_3344_5566_77ab);
        assert_eq!(in_result(rax, 0xabcd, 2), 0x1122_3344_5566_abcd);
        assert_eq!(in_result(rax, 0xdead_beef, 4), 0xdead_beef);
    }

    #[test]
    fn test_msr_and_cpuid() {
        assert_eq!(msr_access(1, 0xffff_ffff_0000_0001, 2), (true, 0x2_0000_0001));
        assert_eq!(cpuid_ecx(1, 0, 0, 1 << 18), 1 << 27);
        assert_eq!(cpuid_ecx(1, 0, 1 << 27, 0), 0);
        assert_eq!(cpuid_ecx(7, 1, 1 << 4, 0), 1 << 4, "only subleaf 0 follows CR4.PKE");
        assert_eq!(hypercall(9, 0x1000, 0, true, 0), Hypercall::ClockPairing { gpa: 0x1000 });
        assert_eq!(hypercall(9, 0x1000, 1, true, 0), Hypercall::Error((-95i64).cast_unsigned()));
        assert_eq!(hypercall(42, 0, 0, true, 0), Hypercall::Error((-1000i64).cast_unsigned()));
    }

    // KVM's __kvm_emulate_hypercall: a hypercall from guest user space (or
    // CPL 1, 2) is -KVM_EPERM before its number is looked at, so the clock
    // pairing hypercall never writes for it; outside 64-bit code the number
    // and the arguments are their low halves and so is the result in RAX.
    #[test]
    fn test_hypercall_privilege_and_operand_size() {
        let eperm = Hypercall::Error((-1i64).cast_unsigned());
        for cpl in 1..=3 {
            assert_eq!(hypercall(9, 0x1000, 0, true, cpl), eperm, "cpl {cpl}");
            assert_eq!(hypercall(1, 0, 0, true, cpl), eperm, "cpl {cpl}");
        }
        assert_eq!(hypercall(0x1_0000_0009, 0xdead_0000_1000, 0x7_0000_0000, false, 0), Hypercall::ClockPairing { gpa: 0x1000 });
        assert_eq!(hypercall(0x1_0000_0009, 0x1000, 0, true, 0), Hypercall::Error((-1000i64).cast_unsigned()));
        assert_eq!(hypercall_rax((-1000i64).cast_unsigned(), false), 0xffff_fc18);
        assert_eq!(hypercall_rax((-1000i64).cast_unsigned(), true), (-1000i64).cast_unsigned());
        // WHV_X64_VP_EXECUTION_STATE and the CS attributes' Long bit.
        assert_eq!(cpl(0b11 | 1 << 4), 3);
        assert!(long_mode_code(1 << 4, 1 << 13));
        assert!(!long_mode_code(1 << 4, 0), "compatibility mode");
        assert!(!long_mode_code(0, 1 << 13), "no long mode");
    }
}
