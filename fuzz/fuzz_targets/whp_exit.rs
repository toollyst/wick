// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the WHP run loop decides from a vCPU exit's fields, which the guest
//! controls (`crates/compat/kvm-ioctls/src/whp/exit.rs`): the instruction
//! length, a port access's direction, size and kind, a memory access's
//! direction, an MSR access and the value it writes, the `RAX` an `IN`
//! leaves, the CPUID bits that follow CR4, the hypercall answered (at
//! the privilege level and operand size the exit context gives), a
//! string instruction's addressing and segment checks, and the interrupt
//! shadow an instruction the VMM finished leaves (MOV SS / POP SS from its
//! bytes).
//! Checked against a reference written here from the x86 architecture (the
//! Intel SDM: port I/O sizes, 32-bit register writes zero-extending,
//! `WRMSR` taking `EDX:EAX`, CPUID's OSXSAVE and OSPKE) and KVM's hypercall
//! ABI: nothing panics, and every answer is the reference's.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fuzz::whp_exit::{
    CodeMode, Hypercall, PortAccess, Segment, SegmentFault, SegmentView, code_mode, cpl, cpuid_ecx, hypercall, hypercall_rax,
    in_result, ins_read_ahead, instruction_length, linearize, loads_ss, long_mode_code, memory_write, msr_access, port_access,
    shadow_after, string_addressing, string_advance, string_count, string_offset,
};

#[derive(Arbitrary, Debug)]
enum Exit {
    Port { info: u32, rax: u64, value: u64 },
    Memory { info: u32 },
    Msr { info: u32, rax: u64, rdx: u64 },
    Cpuid { function: u8, index: u8, ecx: u32, cr4: u64 },
    Hypercall { nr: u64, a0: u64, a1: u64, state: u16, cs: u16 },
    String { bytes: Vec<u8>, long: bool, default_32: bool, reg: u64, rcx: u64, size: u8, rep: bool, down: bool },
    Linear { state: u16, rflags: u64, cs: u16, seg: u8, base: u64, limit: u32, attributes: u16, offset: u64, size: u16, write: bool, la57: bool },
    Shadow { bytes: Vec<u8>, long: bool, had: bool },
}

#[derive(Arbitrary, Debug)]
struct Input {
    bitfield: u8,
    exits: Vec<Exit>,
}

fn check(e: &Exit) {
    match *e {
        Exit::Port { info, rax, value } => {
            let size = (info >> 1) & 7;
            match port_access(info) {
                None => assert!(!matches!(size, 1 | 2 | 4), "a {size}-byte access refused"),
                Some(PortAccess { write, size: s, string, rep }) => {
                    assert!(matches!(s, 1 | 2 | 4), "a {s}-byte port access");
                    assert_eq!(s as u32, size);
                    assert_eq!(write, info & 1 == 1);
                    assert_eq!(string, info & 0x10 != 0);
                    assert_eq!(rep, info & 0x20 != 0);
                    // IN: the low `s` bytes of RAX are the value read; a
                    // doubleword write clears bits 32-63; a byte or word
                    // write keeps every other bit.
                    let got = in_result(rax, value, s);
                    let mask = (1u64 << (8 * s)) - 1;
                    assert_eq!(got & mask, value & mask);
                    if s == 4 {
                        assert_eq!(got >> 32, 0);
                    } else {
                        assert_eq!(got & !mask, rax & !mask);
                    }
                }
            }
        }
        Exit::Memory { info } => assert_eq!(memory_write(info), info % 4 == 1),
        Exit::Msr { info, rax, rdx } => {
            let (write, value) = msr_access(info, rax, rdx);
            assert_eq!(write, info & 1 == 1);
            assert_eq!(value as u32, rax as u32, "EAX is the low half");
            assert_eq!((value >> 32) as u32, rdx as u32, "EDX is the high half");
        }
        Exit::Cpuid { function, index, ecx, cr4 } => {
            let (function, index) = (u32::from(function % 9), u32::from(index % 3));
            let got = cpuid_ecx(function, index, ecx, cr4);
            let (bit, cr4_bit) = match (function, index) {
                (1, _) => (27, 18),
                (7, 0) => (4, 22),
                _ => {
                    assert_eq!(got, ecx);
                    return;
                }
            };
            assert_eq!(got & !(1 << bit), ecx & !(1 << bit), "only the OS bit changes");
            assert_eq!(got >> bit & 1, (cr4 >> cr4_bit & 1) as u32);
        }
        Exit::Hypercall { nr, a0, a1, state, cs } => {
            // Mostly the hypercalls KVM knows, in their high bits anything.
            let nr = (nr & !0xff) | (nr & 0xff) % 12;
            let a1 = (a1 & !0xff) | (a1 & 0xff) % 3;
            let (level, wide) = (cpl(state), long_mode_code(state, cs));
            assert_eq!(u16::from(level), state & 3);
            assert_eq!(wide, state & 0x10 != 0 && cs & 0x2000 != 0);
            // KVM's __kvm_emulate_hypercall: low halves outside 64-bit
            // code, -KVM_EPERM from any level but 0.
            let low = |v: u64| if wide { v } else { v & 0xffff_ffff };
            let want = match (level, low(nr), low(a1)) {
                (1..=3, _, _) => Hypercall::Error((-1i64) as u64),
                (_, 1, _) => Hypercall::PollIrq,
                (_, 9, 0) => Hypercall::ClockPairing { gpa: low(a0) },
                (_, 9, _) => Hypercall::Error((-95i64) as u64),
                _ => Hypercall::Error((-1000i64) as u64),
            };
            assert_eq!(hypercall(nr, a0, a1, wide, level), want);
            if let Hypercall::Error(rax) = want {
                assert_eq!(hypercall_rax(rax, wide), low(rax));
            }
        }
        Exit::String { ref bytes, long, default_32, reg, rcx, size, rep, down } => {
            // INS and OUTS (`VcpuFd::string_io`): the guest chooses the
            // instruction's bytes and every register.
            let size = [1usize, 2, 4][usize::from(size % 3)];
            let wide = string_addressing(bytes, long, default_32).address_bytes;
            assert!(matches!(wide, 2 | 4 | 8), "an address size of {wide} bytes");
            assert!(wide == 8 || !long || bytes.contains(&0x67), "64-bit code without the prefix has 64-bit addresses");
            let mask = match wide {
                8 => u64::MAX,
                4 => 0xffff_ffff,
                _ => 0xffff,
            };
            assert_eq!(string_offset(reg, wide), reg & mask);
            let count = string_count(rep, rcx, wide);
            assert_eq!(count, if rep { rcx & mask } else { 1 });
            // The register moves by the element within the address size; at
            // 32 bits its upper half is cleared, at 16 the rest is kept.
            let moved = string_advance(reg, wide, size as u64, down);
            let want = if down { reg.wrapping_sub(size as u64) } else { reg.wrapping_add(size as u64) };
            assert_eq!(moved & mask, want & mask);
            match wide {
                8 => {}
                4 => assert_eq!(moved >> 32, 0),
                _ => assert_eq!(moved >> 16, reg >> 16),
            }
            // What is asked of the port at once fits KVM's 1024 bytes, is
            // at least one element and no more than is left.
            let n = ins_read_ahead(size, reg, count, down);
            assert!(n >= 1 && n * size <= 1024, "{n} elements of {size}");
            assert!(n as u64 <= count.max(1));
        }
        // Checked by `check_shadow`.
        Exit::Shadow { .. } => {}
        Exit::Linear { state, rflags, cs, seg, base, limit, attributes, offset, size, write, la57 } => {
            // KVM's emulator modes (x86.c, `init_emulate_ctxt`) and its
            // segment checks (emulate.c, `__linearize`), against the Intel
            // SDM's rules: canonical addresses in 64-bit code; elsewhere
            // 32-bit addresses, a present segment, every byte within the
            // limit.
            let mode = code_mode(state, rflags, cs);
            let want = if state & 4 == 0 {
                CodeMode::Real
            } else if rflags & (1 << 17) != 0 {
                CodeMode::Vm86
            } else if state & 0x10 != 0 && cs & 0x2000 != 0 {
                CodeMode::Prot64
            } else if cs & 0x4000 != 0 {
                CodeMode::Prot32
            } else {
                CodeMode::Prot16
            };
            assert_eq!(mode, want);
            let segment = [Segment::Es, Segment::Cs, Segment::Ss, Segment::Ds, Segment::Fs, Segment::Gs][usize::from(seg % 6)];
            let va = if la57 { 57 } else { 48 };
            let size = u64::from(size % 1024) + 1;
            let view = SegmentView { base, limit, attributes };
            let got = linearize(segment, view, offset, size, write, mode, va);
            if let Err(fault) = got {
                assert_eq!(fault == SegmentFault::Ss, segment == Segment::Ss, "#SS through SS only");
            }
            if mode == CodeMode::Prot64 {
                let la = if matches!(segment, Segment::Fs | Segment::Gs) { base } else { 0 }.wrapping_add(offset);
                let top = la >> (va - 1);
                let canonical = top == 0 || top == u64::MAX >> (va - 1);
                if !canonical {
                    assert!(got.is_err(), "{la:#x} is not canonical at {va} bits");
                }
                if let Ok(at) = got {
                    assert_eq!(at, la);
                }
                return;
            }
            let Ok(at) = got else { return };
            assert_eq!(at, base.wrapping_add(offset) & 0xffff_ffff);
            assert!(attributes & 0x80 != 0, "a segment that is not present");
            let kind = attributes & 0xf;
            if write {
                assert!(kind & 0xa == 2 || (kind & 8 != 0 && mode == CodeMode::Real && kind & 2 != 0), "a write through type {kind:#x}");
            }
            let expand_down = kind & 0xc == 4;
            if expand_down {
                assert!(offset > u64::from(limit));
                let top = if attributes & 0x4000 != 0 { 0xffff_ffff } else { 0xffff };
                assert!(offset <= top);
                if top != 0xffff_ffff {
                    assert!(offset + size - 1 <= top);
                }
            } else if limit == u32::MAX {
                assert!(offset <= u64::from(limit));
            } else {
                assert!(offset + size - 1 <= u64::from(limit), "{size} bytes at {offset:#x} past the limit {limit:#x}");
            }
        }
    }
}

/// The reference for an instruction's own shadow: after the legacy
/// prefixes (and a REX prefix in 64-bit code), `8E /2` or, outside 64-bit
/// code, `17` (Intel SDM vol. 2, MOV and POP).
fn opens_shadow(bytes: &[u8], long: bool) -> bool {
    const LEGACY: [u8; 11] = [0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3];
    let rest: Vec<u8> = bytes.iter().copied().skip_while(|b| LEGACY.contains(b)).collect();
    let rest = if long && rest.first().is_some_and(|b| (0x40..=0x4F).contains(b)) { &rest[1..] } else { &rest[..] };
    match rest {
        [0x8E, modrm, ..] => (modrm >> 3) & 7 == 2,
        [0x17, ..] => !long,
        _ => false,
    }
}

fn check_shadow(e: &Exit) {
    if let Exit::Shadow { bytes, long, had } = e {
        let own = loads_ss(bytes, *long);
        assert_eq!(own, opens_shadow(bytes, *long), "{bytes:02x?}");
        // KVM: the shadow after is the instruction's own; nothing to write
        // when it already is.
        match shadow_after(*had, own) {
            None => assert_eq!(*had, own),
            Some(after) => assert_eq!(after, own),
        }
    }
}

fuzz_target!(|input: Input| {
    assert!(instruction_length(input.bitfield) <= 15);
    assert_eq!(instruction_length(input.bitfield), u64::from(input.bitfield & 15));
    for e in &input.exits {
        check(e);
        check_shadow(e);
    }
});
