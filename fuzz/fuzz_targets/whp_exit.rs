// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the WHP run loop decides from a vCPU exit's fields, which the guest
//! controls (`crates/compat/kvm-ioctls/src/whp/exit.rs`): the instruction
//! length, a port access's direction, size and kind, a memory access's
//! direction, an MSR access and the value it writes, the `RAX` an `IN`
//! leaves, the CPUID bits that follow CR4, and the hypercall answered (at
//! the privilege level and operand size the exit context gives).
//! Checked against a reference written here from the x86 architecture (the
//! Intel SDM: port I/O sizes, 32-bit register writes zero-extending,
//! `WRMSR` taking `EDX:EAX`, CPUID's OSXSAVE and OSPKE) and KVM's hypercall
//! ABI: nothing panics, and every answer is the reference's.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fuzz::whp_exit::{
    Hypercall, PortAccess, cpl, cpuid_ecx, hypercall, hypercall_rax, in_result, ins_read_ahead, instruction_length, linear_address,
    long_mode_code, memory_write, msr_access, port_access, string_addressing, string_advance, string_count, string_offset,
};

#[derive(Arbitrary, Debug)]
enum Exit {
    Port { info: u32, rax: u64, value: u64 },
    Memory { info: u32 },
    Msr { info: u32, rax: u64, rdx: u64 },
    Cpuid { function: u8, index: u8, ecx: u32, cr4: u64 },
    Hypercall { nr: u64, a0: u64, a1: u64, state: u16, cs: u16 },
    String { bytes: Vec<u8>, long: bool, default_32: bool, reg: u64, rcx: u64, base: u64, size: u8, rep: bool, down: bool },
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
        Exit::String { ref bytes, long, default_32, reg, rcx, base, size, rep, down } => {
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
            let la = linear_address(base, string_offset(reg, wide), long);
            assert!(long || la <= 0xffff_ffff);
        }
    }
}

fuzz_target!(|input: Input| {
    assert!(instruction_length(input.bitfield) <= 15);
    assert_eq!(instruction_length(input.bitfield), u64::from(input.bitfield & 15));
    for e in &input.exits {
        check(e);
    }
});
