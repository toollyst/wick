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

/// The mode KVM's emulator decodes and checks an instruction in, as
/// `init_emulate_ctxt` sets it (Linux v6.1 arch/x86/kvm/x86.c): real mode
/// without CR0.PE, virtual-8086 with RFLAGS.VM, 64-bit with EFER.LMA and a
/// 64-bit code segment, else protected mode of CS's default size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeMode {
    Real,
    Vm86,
    Prot16,
    Prot32,
    Prot64,
}

/// The [`CodeMode`] of a vCPU from its exit context: `ExecutionState`
/// (`Cr0Pe` is bit 2, `EferLma` bit 4), RFLAGS (VM is bit 17) and the code
/// segment's attributes (`Long` bit 13, `Default` bit 14).
pub fn code_mode(execution_state: u16, rflags: u64, cs_attributes: u16) -> CodeMode {
    if execution_state >> 2 & 1 == 0 {
        CodeMode::Real
    } else if rflags >> 17 & 1 == 1 {
        CodeMode::Vm86
    } else if long_mode_code(execution_state, cs_attributes) {
        CodeMode::Prot64
    } else if cs_attributes >> 14 & 1 == 1 {
        CodeMode::Prot32
    } else {
        CodeMode::Prot16
    }
}

/// A segment register as WHP holds it (`WHV_X64_SEGMENT_REGISTER`): its
/// base, its limit in bytes (the granularity already applied, as
/// `kvm_segment.limit`), and its attributes (the type in bits 0-3, `Present`
/// bit 7, `Default` bit 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentView {
    pub base: u64,
    pub limit: u32,
    pub attributes: u16,
}

/// The exception a segment check gives: #SS(0) for an access through SS,
/// #GP(0) for any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentFault {
    Gp,
    Ss,
}

/// The linear address of a data access of `size` bytes at `offset` (at the
/// instruction's address size) through `segment`, or the fault it takes, as
/// KVM's emulator checks it (Linux v6.1 arch/x86/kvm/emulate.c,
/// `__linearize`, for an access that is not a fetch; string instructions
/// have no alignment rule there). In 64-bit code: the base of FS and GS only
/// (`seg_base`), and the address canonical for `va_bits` (48, or 57 with
/// CR4.LA57) with `size` bytes below the end of the address space. In any
/// other mode: 32 bits of address, the segment present (WHP's segments have
/// no unusable bit; KVM reads AMD's the same way, `!present`), no write to a
/// code segment outside real mode nor to a data segment without write
/// access, no read of an execute-only code segment, and the access within
/// the limit, an expand-down segment's limit being its lowest address.
pub fn linearize(
    segment: Segment,
    view: SegmentView,
    offset: u64,
    size: u64,
    write: bool,
    mode: CodeMode,
    va_bits: u32,
) -> Result<u64, SegmentFault> {
    let bad = if segment == Segment::Ss { SegmentFault::Ss } else { SegmentFault::Gp };
    if mode == CodeMode::Prot64 {
        let base = if matches!(segment, Segment::Fs | Segment::Gs) { view.base } else { 0 };
        let la = base.wrapping_add(offset);
        let shift = 64 - va_bits;
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let canonical = (((la << shift) as i64) >> shift) as u64 == la;
        // `min_t(u64, ~0u, (1ull << va_bits) - la)`, in u64 arithmetic.
        let max_size = (1u64 << va_bits).wrapping_sub(la).min(u64::from(u32::MAX));
        return if canonical && size <= max_size { Ok(la) } else { Err(bad) };
    }
    let la = view.base.wrapping_add(offset) & 0xffff_ffff;
    let kind = view.attributes & 0xf;
    let (code, writable_or_readable, expand_down) = (kind & 8 != 0, kind & 2 != 0, kind & 8 == 0 && kind & 4 != 0);
    if view.attributes >> 7 & 1 == 0 {
        return Err(bad);
    }
    if write && ((mode != CodeMode::Real && code) || !writable_or_readable) {
        return Err(bad);
    }
    if code && !writable_or_readable {
        return Err(bad);
    }
    let mut limit = u64::from(view.limit);
    if expand_down {
        if offset <= limit {
            return Err(bad);
        }
        limit = if view.attributes >> 14 & 1 == 1 { 0xffff_ffff } else { 0xffff };
    }
    if offset > limit {
        return Err(bad);
    }
    if limit != 0xffff_ffff && size > limit + 1 - offset {
        return Err(bad);
    }
    Ok(la)
}

/// Whether a guest's CPUID leaf 0 names Intel ("GenuineIntel" in EBX, EDX,
/// ECX), as KVM's `is_guest_vendor_intel` decides.
pub fn guest_vendor_intel(ebx: u32, ecx: u32, edx: u32) -> bool {
    ebx == 0x756e_6547 && ecx == 0x6c65_746e && edx == 0x4965_6e69
}

/// Whether CPUID leaf 0's vendor (`ebx`, `ecx`, `edx`) is AMD's or Hygon's,
/// as KVM's `guest_cpuid_is_amd_or_hygon` reads the guest's
/// (arch/x86/include/asm/kvm_para.h `is_guest_vendor_amd`, `_hygon`).
pub fn guest_vendor_amd_or_hygon(ebx: u32, ecx: u32, edx: u32) -> bool {
    // "AuthenticAMD", "HygonGenuine".
    (ebx == 0x6874_7541 && ecx == 0x444d_4163 && edx == 0x6974_6e65)
        || (ebx == 0x6f67_7948 && ecx == 0x656e_6975 && edx == 0x6e65_476e)
}

/// A page fault's error code: `P` for a fault on a page that is present,
/// `W` for a write, `U` from privilege level 3, `RSVD` for reserved bits
/// set in a page table entry (which is a fault on a present page).
pub fn page_fault_code(present: bool, write: bool, user: bool, reserved: bool) -> u32 {
    u32::from(present || reserved) | u32::from(write) << 1 | u32::from(user) << 2 | u32::from(reserved) << 3
}

/// A device read of an MMIO instruction with the data the device gave
/// (`VcpuExit::MmioRead`, filled by Firecracker), kept until the
/// instruction finishes ([`answer_read`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRead {
    pub addr: u64,
    pub len: usize,
    pub data: [u8; 8],
}

/// What the emulator's device read of `len` bytes at `addr` is answered
/// with when the instruction is emulated again from its exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAnswer {
    /// The data of the read given for it: the next of `reads`, for the same
    /// access.
    Data([u8; 8]),
    /// None given yet: the emulation stops here and the device is asked.
    Ask,
    /// The next read given was for another access: the instruction is not
    /// the one the data was for.
    Mismatch,
}

/// The answer to an emulator's device read of an instruction whose reads
/// before `next` were answered from `reads`, in order: the same
/// instruction from the same state asks for the same accesses again, so
/// the `next`th read given is for this one (KVM's emulator replays its
/// reads from its read cache the same way, `read_emulated`).
pub fn answer_read(reads: &[DeviceRead], next: &mut usize, addr: u64, len: usize) -> ReadAnswer {
    match reads.get(*next) {
        None => ReadAnswer::Ask,
        Some(r) if r.addr == addr && r.len == len => {
            *next += 1;
            ReadAnswer::Data(r.data)
        }
        Some(_) => ReadAnswer::Mismatch,
    }
}

/// How an emulation of an MMIO instruction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emulated {
    /// Finished, nothing for a device but what the irqchip took.
    Completed,
    /// The emulator could not do it.
    Failed,
    /// A device read did not match the data given ([`ReadAnswer::Mismatch`]).
    Mismatch,
    /// A device read with no data yet.
    Read { addr: u64, len: usize },
    /// Finished with a write to a device.
    Write,
}

/// What the run loop does after an emulation that ended as `e`, with
/// `answered` device reads of the instruction answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioStep {
    /// The instruction is done: the run goes on (enters the guest).
    Done,
    /// The instruction is done; its device write is the exit.
    Write,
    /// The device is asked for this read (`VcpuExit::MmioRead`), and the
    /// instruction finishes at the next run.
    Ask { addr: u64, len: usize },
    /// The vCPU stops (`VcpuExit::InternalError`): entering the guest
    /// would run the instruction again and ask its devices again.
    Stop,
}

/// [`MmioStep`] for an emulation that ended as `e`. An instruction the
/// emulator cannot do before any device read is entered again, as before
/// (its exit comes back); after one, it is stopped, as is one whose read
/// does not match the data given.
pub fn mmio_step(e: Emulated, answered: usize) -> MmioStep {
    match e {
        Emulated::Completed => MmioStep::Done,
        Emulated::Failed if answered == 0 => MmioStep::Done,
        Emulated::Failed | Emulated::Mismatch => MmioStep::Stop,
        Emulated::Read { addr, len } => MmioStep::Ask { addr, len },
        Emulated::Write => MmioStep::Write,
    }
}

/// The interrupt shadow (`WHvRegisterInterruptState` bit 0) a vCPU is to
/// have after the VMM finished an instruction that exited, as KVM leaves it
/// (Linux v6.1): an instruction KVM skips ends any shadow
/// (`skip_emulated_instruction`, arch/x86/kvm/vmx/vmx.c:1636,
/// `__svm_skip_emulated_instruction`, svm/svm.c:403), and one its emulator
/// finishes leaves the instruction's own shadow, MOV SS's or POP SS's,
/// none for any other (`toggle_interruptibility`, x86.c:8263-8280, at the
/// writeback, x86.c:8955). `had`: the exit's `ExecutionState`
/// `InterruptShadow`; `loads_ss`: the instruction is a MOV SS or POP SS
/// ([`loads_ss`]). `None` when the state already is that (no WHP call);
/// else the shadow to write. Not as KVM: two MOV SS in a row, whose second
/// KVM leaves with no shadow; WHP keeps no kind of shadow to tell them by.
pub fn shadow_after(had: bool, loads_ss: bool) -> Option<bool> {
    if had == loads_ss { None } else { Some(loads_ss) }
}

/// Whether the instruction in `bytes` (the exit's instruction bytes) is a
/// MOV SS (`8E /2`) or, outside 64-bit code, POP SS (`17`), after its
/// legacy prefixes and, in 64-bit code, a REX prefix: the instructions that
/// open a shadow of their own (Intel SDM vol. 2, MOV and POP).
pub fn loads_ss(bytes: &[u8], long_mode_code: bool) -> bool {
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3) {
        i += 1;
    }
    if long_mode_code && i < bytes.len() && bytes[i] & 0xF0 == 0x40 {
        i += 1;
    }
    match bytes.get(i) {
        Some(0x8E) => bytes.get(i + 1).is_some_and(|modrm| modrm >> 3 & 7 == 2),
        Some(0x17) => !long_mode_code,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_shadow_after_a_finished_instruction_is_kvms() {
        // STI's shadow, then a MOV, CPUID, OUT...: ended.
        assert_eq!(shadow_after(true, false), Some(false));
        // No shadow, an instruction without one: nothing to write.
        assert_eq!(shadow_after(false, false), None);
        // MOV SS from a device: its own shadow.
        assert_eq!(shadow_after(false, true), Some(true));
        assert_eq!(shadow_after(true, true), None);
    }

    #[test]
    fn test_mov_ss_and_pop_ss_are_told_from_the_bytes() {
        assert!(loads_ss(&[0x8E, 0x14, 0x25, 0, 0, 0x60, 0], true), "mov ss, [0x600000]");
        assert!(loads_ss(&[0x66, 0x8E, 0x10], true), "with an operand-size prefix");
        assert!(loads_ss(&[0x48, 0x8E, 0x10], true), "with REX.W in 64-bit code");
        assert!(!loads_ss(&[0x48, 0x8E, 0x10], false), "0x48 is DEC EAX outside 64-bit code");
        assert!(!loads_ss(&[0x8E, 0x18], true), "mov ds, [rax]");
        assert!(!loads_ss(&[0x8B, 0x04, 0x25, 0, 0, 0x60, 0], true), "mov eax, [0x600000]");
        assert!(loads_ss(&[0x17], false), "pop ss");
        assert!(!loads_ss(&[0x17], true), "no POP SS in 64-bit code");
        assert!(!loads_ss(&[], true));
        assert!(!loads_ss(&[0x66, 0x67], true));
        assert!(!loads_ss(&[0x8E], true), "no ModRM byte");
    }

    // The device reads of an MMIO instruction, kept between its exits and
    // answered in order when it is emulated again from its exit, as the run
    // loop does (`vcpu.rs`, `emulate_mmio`), with a model of the emulator:
    // an instruction that asks for `asks`, in order, stopping at the first
    // read it has no data for.
    #[test]
    fn test_an_mmio_instructions_device_reads() {
        fn emulate(asks: &[(u64, usize)], reads: &[DeviceRead]) -> (Emulated, Vec<[u8; 8]>) {
            let mut next = 0;
            let mut got = Vec::new();
            for &(addr, len) in asks {
                match answer_read(reads, &mut next, addr, len) {
                    ReadAnswer::Data(d) => got.push(d),
                    ReadAnswer::Ask => return (Emulated::Read { addr, len }, got),
                    ReadAnswer::Mismatch => return (Emulated::Mismatch, got),
                }
            }
            (Emulated::Completed, got)
        }
        // The run loop: an exit for each read with no data, the device's
        // data kept, the instruction emulated again from its exit.
        fn run(asks: &[(u64, usize)]) -> (Vec<(u64, usize)>, Vec<[u8; 8]>) {
            let mut reads: Vec<DeviceRead> = Vec::new();
            let mut exits = Vec::new();
            loop {
                let (e, got) = emulate(asks, &reads);
                match mmio_step(e, reads.len()) {
                    MmioStep::Ask { addr, len } => {
                        exits.push((addr, len));
                        let n = u8::try_from(exits.len()).unwrap();
                        reads.push(DeviceRead { addr, len, data: [n; 8] });
                    }
                    MmioStep::Done => return (exits, got),
                    s => panic!("{asks:?}: {s:?}"),
                }
                assert!(exits.len() <= asks.len(), "{asks:?} asked again: {exits:?}");
            }
        }
        // One read: one exit, then done with its data.
        assert_eq!(run(&[(0x60_0000, 4)]), (vec![(0x60_0000, 4)], vec![[1; 8]]));
        // Two device reads in one instruction (an access split at a page,
        // two operands): an exit for each, in order, each answered with its
        // own data. The data of one read went to the first device read
        // before, and the second was asked again on every run.
        assert_eq!(
            run(&[(0x60_0FFC, 4), (0x60_1000, 4)]),
            (vec![(0x60_0FFC, 4), (0x60_1000, 4)], vec![[1; 8], [2; 8]])
        );
        // No device read: done at once.
        assert_eq!(run(&[]), (vec![], vec![]));
        // A read other than the one the data was for stops the vCPU.
        let given = [DeviceRead { addr: 0x60_0000, len: 4, data: [7; 8] }];
        assert_eq!(emulate(&[(0x60_0004, 4)], &given).0, Emulated::Mismatch);
        assert_eq!(emulate(&[(0x60_0000, 2)], &given).0, Emulated::Mismatch);
        assert_eq!(mmio_step(Emulated::Mismatch, 1), MmioStep::Stop);
        // The data given is used once: a second read of the same access
        // is a read of its own.
        let mut next = 0;
        assert_eq!(answer_read(&given, &mut next, 0x60_0000, 4), ReadAnswer::Data([7; 8]));
        assert_eq!(answer_read(&given, &mut next, 0x60_0000, 4), ReadAnswer::Ask);
        // An emulation that fails after a device read stops; before one, it
        // is entered again; a write is the exit.
        assert_eq!(mmio_step(Emulated::Failed, 1), MmioStep::Stop);
        assert_eq!(mmio_step(Emulated::Failed, 0), MmioStep::Done);
        assert_eq!(mmio_step(Emulated::Write, 1), MmioStep::Write);
    }

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

    // KVM's emulator modes and its segment checks (emulate.c, `__linearize`).
    #[test]
    fn test_linearize() {
        let flat = SegmentView { base: 0, limit: 0xffff_ffff, attributes: 0xc093 };
        let lin = |seg, view, offset, size, write, mode| linearize(seg, view, offset, size, write, mode, 48);
        // The mode: no PE, VM, LMA with CS.L, CS.D.
        assert_eq!(code_mode(0, 0, 0x2000), CodeMode::Real);
        assert_eq!(code_mode(0x4, 1 << 17, 0), CodeMode::Vm86);
        assert_eq!(code_mode(0x14, 2, 0x209b), CodeMode::Prot64);
        assert_eq!(code_mode(0x4, 2, 0x409b), CodeMode::Prot32);
        assert_eq!(code_mode(0x4, 2, 0x9b), CodeMode::Prot16);
        // 64-bit: only FS and GS have a base; canonical or #GP, #SS by SS.
        let based = SegmentView { base: 0x1000, ..flat };
        assert_eq!(lin(Segment::Ds, based, 0x10, 1, false, CodeMode::Prot64), Ok(0x10));
        assert_eq!(lin(Segment::Gs, based, 0x10, 1, false, CodeMode::Prot64), Ok(0x1010));
        assert_eq!(lin(Segment::Ds, flat, 0x0000_8000_0000_0000, 1, false, CodeMode::Prot64), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Ss, flat, 0x0000_8000_0000_0000, 1, true, CodeMode::Prot64), Err(SegmentFault::Ss));
        assert_eq!(lin(Segment::Es, flat, 0xffff_8000_0000_0000, 4, true, CodeMode::Prot64), Ok(0xffff_8000_0000_0000));
        assert!(lin(Segment::Es, flat, 0x0000_8000_0000_0000, 1, true, CodeMode::Prot64).is_err());
        assert_eq!(linearize(Segment::Es, flat, 0x0000_8000_0000_0000, 1, true, CodeMode::Prot64, 57), Ok(0x0000_8000_0000_0000));
        // Elsewhere: 32 bits, the limit, the last byte within it.
        let small = SegmentView { base: 0xffff_fff0, limit: 0xff, attributes: 0x93 };
        assert_eq!(lin(Segment::Ds, small, 0x20, 1, false, CodeMode::Prot32), Ok(0x10));
        assert!(lin(Segment::Ds, small, 0xff, 1, false, CodeMode::Prot32).is_ok());
        assert_eq!(lin(Segment::Ds, small, 0xff, 2, false, CodeMode::Prot32), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Ds, small, 0x100, 1, false, CodeMode::Real), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Ss, small, 0x100, 1, false, CodeMode::Prot16), Err(SegmentFault::Ss));
        // Not present; read-only data written; code written outside real
        // mode; execute-only code read.
        assert_eq!(lin(Segment::Es, SegmentView { attributes: 0x13, ..flat }, 0, 1, false, CodeMode::Prot32), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Es, SegmentView { attributes: 0xc091, ..flat }, 0, 1, true, CodeMode::Prot32), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Es, SegmentView { attributes: 0xc091, ..flat }, 0, 1, false, CodeMode::Prot32), Ok(0));
        let code = SegmentView { attributes: 0xc09b, ..flat };
        assert_eq!(lin(Segment::Cs, code, 0, 1, true, CodeMode::Prot32), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Cs, code, 0, 1, true, CodeMode::Real), Ok(0));
        assert_eq!(lin(Segment::Cs, code, 0, 1, false, CodeMode::Prot32), Ok(0));
        assert_eq!(lin(Segment::Cs, SegmentView { attributes: 0xc099, ..flat }, 0, 1, false, CodeMode::Prot32), Err(SegmentFault::Gp));
        // Expand-down: above the limit, up to 64 KiB or 4 GiB by D.
        let down = SegmentView { base: 0, limit: 0xfff, attributes: 0x97 };
        assert_eq!(lin(Segment::Ds, down, 0xfff, 1, true, CodeMode::Prot16), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Ds, down, 0x1000, 1, true, CodeMode::Prot16), Ok(0x1000));
        assert_eq!(lin(Segment::Ds, down, 0xffff, 2, true, CodeMode::Prot16), Err(SegmentFault::Gp));
        assert_eq!(lin(Segment::Ds, SegmentView { attributes: 0x4097, ..down }, 0xffff, 2, true, CodeMode::Prot32), Ok(0xffff));
        // "GenuineIntel"; "AuthenticAMD" is not.
        assert!(guest_vendor_intel(0x756e_6547, 0x6c65_746e, 0x4965_6e69));
        assert!(!guest_vendor_intel(0x6874_7541, 0x444d_4163, 0x6974_6e65));
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
