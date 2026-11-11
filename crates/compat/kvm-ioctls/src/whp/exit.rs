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
pub(crate) fn instruction_length(bitfield: u8) -> u64 {
    u64::from(bitfield & 0x0f)
}

/// A port access (`WHV_X64_IO_PORT_ACCESS_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PortAccess {
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
pub(crate) fn port_access(info: u32) -> Option<PortAccess> {
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
pub(crate) fn memory_write(info: u32) -> bool {
    info & 0x3 == 1
}

/// An MSR access: whether it is a `WRMSR` (bit 0 of its information word)
/// and the value it writes, `EDX:EAX` (the upper halves of `RAX` and `RDX`
/// are not part of it).
pub(crate) fn msr_access(info: u32, rax: u64, rdx: u64) -> (bool, u64) {
    (info & 1 != 0, (rdx << 32) | (rax & 0xffff_ffff))
}

/// `RAX` after an `IN` of `size` bytes that read `value`: a byte or a word
/// leaves the rest of `RAX` as it was; a doubleword zero-extends into `RAX`,
/// as every 32-bit register write does in 64-bit mode (KVM: `complete_pio`).
pub(crate) fn in_result(rax: u64, value: u64, size: usize) -> u64 {
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
pub(crate) fn cpuid_ecx(function: u32, index: u32, ecx: u32, cr4: u64) -> u32 {
    let follow = |ecx: u32, bit: u32, cr4_bit: u32| (ecx & !(1 << bit)) | (u32::from(cr4 & (1 << cr4_bit) != 0) << bit);
    match (function, index) {
        (0x1, _) => follow(ecx, 27, 18),
        (0x7, 0) => follow(ecx, 4, 22),
        _ => ecx,
    }
}

/// What a KVM hypercall (`kvm_emulate_hypercall`: `nr` in RAX, its first
/// two arguments in RBX and RCX) is answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hypercall {
    /// `KVM_HC_VAPIC_POLL_IRQ`: 0, nothing to do.
    PollIrq,
    /// `KVM_HC_CLOCK_PAIRING` with `KVM_CLOCK_PAIRING_WALLCLOCK`: the
    /// structure at the guest physical address in the first argument.
    ClockPairing { gpa: u64 },
    /// An error, as `RAX` (`-KVM_EOPNOTSUPP` for another clock type,
    /// `-KVM_ENOSYS` for a hypercall KVM does not know).
    Error(u64),
}

/// Decodes a KVM hypercall.
pub(crate) fn hypercall(nr: u64, a0: u64, a1: u64) -> Hypercall {
    const KVM_ENOSYS: i64 = 1000;
    const KVM_EOPNOTSUPP: i64 = 95;
    const KVM_HC_VAPIC_POLL_IRQ: u64 = 1;
    const KVM_HC_CLOCK_PAIRING: u64 = 9;
    const KVM_CLOCK_PAIRING_WALLCLOCK: u64 = 0;
    match nr {
        KVM_HC_VAPIC_POLL_IRQ => Hypercall::PollIrq,
        KVM_HC_CLOCK_PAIRING if a1 == KVM_CLOCK_PAIRING_WALLCLOCK => Hypercall::ClockPairing { gpa: a0 },
        KVM_HC_CLOCK_PAIRING => Hypercall::Error((-KVM_EOPNOTSUPP).cast_unsigned()),
        _ => Hypercall::Error((-KVM_ENOSYS).cast_unsigned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(hypercall(9, 0x1000, 0), Hypercall::ClockPairing { gpa: 0x1000 });
        assert_eq!(hypercall(9, 0x1000, 1), Hypercall::Error((-95i64).cast_unsigned()));
        assert_eq!(hypercall(42, 0, 0), Hypercall::Error((-1000i64).cast_unsigned()));
    }
}
