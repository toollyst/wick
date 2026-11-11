// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the WHP run loop decides from a vCPU exit's fields, which the guest
//! controls (`crates/compat/kvm-ioctls/src/whp/exit.rs`): the instruction
//! length, a port access's direction, size and kind, a memory access's
//! direction, an MSR access and the value it writes, the `RAX` an `IN`
//! leaves, the CPUID bits that follow CR4, and the hypercall answered.
//! Checked against a reference written here from the x86 architecture (the
//! Intel SDM: port I/O sizes, 32-bit register writes zero-extending,
//! `WRMSR` taking `EDX:EAX`, CPUID's OSXSAVE and OSPKE) and KVM's hypercall
//! ABI: nothing panics, and every answer is the reference's.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fuzz::whp_exit::{Hypercall, PortAccess, cpuid_ecx, hypercall, in_result, instruction_length, memory_write, msr_access, port_access};

#[derive(Arbitrary, Debug)]
enum Exit {
    Port { info: u32, rax: u64, value: u64 },
    Memory { info: u32 },
    Msr { info: u32, rax: u64, rdx: u64 },
    Cpuid { function: u8, index: u8, ecx: u32, cr4: u64 },
    Hypercall { nr: u8, a0: u64, a1: u8 },
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
        Exit::Hypercall { nr, a0, a1 } => {
            let (nr, a1) = (u64::from(nr % 12), u64::from(a1 % 3));
            let want = match (nr, a1) {
                (1, _) => Hypercall::PollIrq,
                (9, 0) => Hypercall::ClockPairing { gpa: a0 },
                (9, _) => Hypercall::Error((-95i64) as u64),
                _ => Hypercall::Error((-1000i64) as u64),
            };
            assert_eq!(hypercall(nr, a0, a1), want);
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
