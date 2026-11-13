// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SMCCC TRNG service and PSCI 1.1's SYSTEM_RESET2 as a guest calls
//! them: a guest program makes the calls and stores each answer's
//! registers to MMIO.

use kvm_bindings::KVM_SYSTEM_EVENT_RESET;

use super::pvtime::tests::{PC, PSTATE, RAM, X9, mmio_values, new_vcpu, vm_with_code};
use super::regs::{PSCI_VERSION_0_2, PSCI_VERSION_1_0, PSCI_VERSION_1_1, PSCI_VERSION_ID};
use super::trng;
use crate::{VcpuExit, VcpuFd};

const HVC: u32 = 0xd400_0002;
/// -1, -2 as the 64-bit X0 the guest reads.
const NOT_SUPPORTED: u64 = -1i64 as u64;
const INVALID_PARAMS: u64 = -2i64 as u64;

/// `xN = value` (movz, then a movk for each other non-zero 16 bits).
fn mov(reg: u32, value: u64) -> Vec<u32> {
    let mut code = vec![0xd280_0000 | ((value & 0xffff) as u32) << 5 | reg];
    for hw in 1..4u32 {
        let part = (value >> (16 * hw)) & 0xffff;
        if part != 0 {
            code.push(0xf280_0000 | hw << 21 | (part as u32) << 5 | reg);
        }
    }
    code
}

/// `x0 = id; x1 = arg; hvc #0`, then `str xN, [x9]` for each of `stored`.
fn call(id: u32, arg: u64, stored: std::ops::Range<u32>) -> Vec<u32> {
    let mut code = mov(0, u64::from(id));
    code.extend(mov(1, arg));
    // X2 and X3 hold what the call before left: cleared, so that a call
    // that does not write them shows.
    code.extend(mov(2, 0));
    code.extend(mov(3, 0));
    code.push(HVC);
    code.extend(stored.map(|reg| 0xf900_0120 | reg));
    code
}

fn program(calls: &[Vec<u32>]) -> Vec<u32> {
    let mut code: Vec<u32> = calls.concat();
    code.push(0x1400_0000); // b .
    code
}

// The TRNG service as KVM's (arch/arm64/kvm/trng.c kvm_trng_call): version
// 1.0; TRNG_FEATURES knows the five calls; KVM's UUID; RND64 gives up to
// 192 bits from X3 upwards and refuses more; RND32 up to 96 in 32-bit
// words; the bits differ from call to call.
#[test]
fn test_trng_calls_as_on_kvm() {
    let code = program(&[
        call(trng::VERSION, 0, 0..1),
        call(trng::FEATURES, u64::from(trng::RND64), 0..1),
        call(trng::FEATURES, 0x8400_0054, 0..1),
        call(trng::GET_UUID, 0, 0..4),
        call(trng::RND64, 192, 0..4),
        call(trng::RND64, 192, 0..4),
        call(trng::RND64, 193, 0..4),
        call(trng::RND64, 8, 0..4),
        call(trng::RND32, 96, 0..4),
        call(trng::RND32, 97, 0..4),
        // An id next to the service's: no call.
        call(0x8400_0054, 0, 0..1),
    ]);
    let (vm, _) = vm_with_code(&code, 0);
    let v = mmio_values(new_vcpu(&vm, 0), 3 + 4 * 7 + 1);
    assert_eq!(v[..3], [0x1_0000, 0, NOT_SUPPORTED]);
    assert_eq!(v[3..7], trng::UUID);
    let (first, second) = (&v[7..11], &v[11..15]);
    assert_eq!((first[0], second[0]), (0, 0));
    assert_ne!(first[1..], second[1..], "two draws of 192 bits are the same");
    assert!(first[1..].iter().all(|&w| w != 0) && second[1..].iter().all(|&w| w != 0), "{first:x?} {second:x?}");
    assert_eq!(v[15..19], [INVALID_PARAMS, 0, 0, 0]);
    assert_eq!(v[19..22], [0, 0, 0]);
    assert!(v[22] < 256, "{:#x}", v[22]);
    assert_eq!(v[23], 0);
    assert!(v[24..27].iter().all(|&w| w >> 32 == 0), "{:x?}", &v[24..27]);
    assert_ne!(v[24..27], [0, 0, 0]);
    assert_eq!(v[27..31], [INVALID_PARAMS, 0, 0, 0]);
    assert_eq!(v[31], NOT_SUPPORTED);
}

/// Runs `vcpu` from the program's start; its MMIO stores, and the system
/// event that ended the run.
fn until_system_event(mut vcpu: VcpuFd) -> (Vec<u64>, u32, Vec<u64>) {
    std::thread::spawn(move || {
        vcpu.set_one_reg(PC, &RAM.to_le_bytes()).unwrap();
        vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
        vcpu.set_one_reg(X9, &0x1000u64.to_le_bytes()).unwrap();
        let mut values = Vec::new();
        loop {
            match vcpu.run().unwrap() {
                VcpuExit::MmioWrite(0x1000, data) => values.push(u64::from_le_bytes(data.try_into().unwrap())),
                VcpuExit::SystemEvent(event, data) => return (values, event, data.to_vec()),
                other => panic!("unexpected exit {other:?}"),
            }
        }
    })
    .join()
    .unwrap()
}

// PSCI 1.1 as KVM's (arch/arm64/kvm/psci.c kvm_psci_1_x_call): the version;
// PSCI_FEATURES knows SYSTEM_RESET2, both forms, and not SYSTEM_SUSPEND or
// MEM_PROTECT; SYSTEM_RESET2 with a type that is neither architectural
// (0) nor a vendor's (bit 31) is INVALID_PARAMS, with the upper half of X1
// not looked at; with type 0 it is a reset for the VMM, flagged RESET2.
// A VM restored with PSCI 1.0 or 0.2 has no SYSTEM_RESET2.
#[test]
fn test_psci_1_1_system_reset2_as_on_kvm() {
    const VERSION: u32 = 0x8400_0000;
    const FEATURES: u32 = 0x8400_000a;
    const RESET2: u32 = 0x8400_0012;
    const RESET2_64: u32 = 0xc400_0012;
    let code = program(&[
        call(VERSION, 0, 0..1),
        call(FEATURES, u64::from(RESET2), 0..1),
        call(FEATURES, u64::from(RESET2_64), 0..1),
        call(FEATURES, 0x8400_000e, 0..1),
        call(FEATURES, 0x8400_0013, 0..1),
        call(RESET2, 1, 0..1),
        call(RESET2_64, 0x7fff_ffff, 0..1),
        call(RESET2_64, 1 << 32 | 1, 0..1),
        call(RESET2, 0, 0..1),
    ]);
    let (vm, _) = vm_with_code(&code, 0);
    let (values, event, data) = until_system_event(new_vcpu(&vm, 0));
    assert_eq!(values, [PSCI_VERSION_1_1, 0, 0, NOT_SUPPORTED, NOT_SUPPORTED, INVALID_PARAMS, INVALID_PARAMS, INVALID_PARAMS]);
    // KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2.
    assert_eq!((event, data), (KVM_SYSTEM_EVENT_RESET, vec![1]));
    // One VM a process (Hypervisor.framework): each ends before the next.
    drop(vm);

    // A vendor reset type is a reset as well.
    let (vm, _) = vm_with_code(&program(&[call(RESET2_64, 0x8000_0000, 0..1)]), 0);
    let (values, event, data) = until_system_event(new_vcpu(&vm, 0));
    assert_eq!((values, event, data), (vec![], KVM_SYSTEM_EVENT_RESET, vec![1]));
    drop(vm);

    // PSCI 1.0 and 0.2: no SYSTEM_RESET2; SYSTEM_RESET (flags 0) ends the run.
    for (version, features) in [(PSCI_VERSION_1_0, NOT_SUPPORTED), (PSCI_VERSION_0_2, NOT_SUPPORTED)] {
        let code = program(&[
            call(VERSION, 0, 0..1),
            call(FEATURES, u64::from(RESET2), 0..1),
            call(RESET2, 0, 0..1),
            call(0x8400_0009, 0, 0..1),
        ]);
        let (vm, _) = vm_with_code(&code, 0);
        let vcpu = new_vcpu(&vm, 0);
        vcpu.set_one_reg(PSCI_VERSION_ID, &version.to_le_bytes()).unwrap();
        let (values, event, data) = until_system_event(vcpu);
        assert_eq!(values, [version, features, NOT_SUPPORTED], "{version:#x}");
        assert_eq!((event, data), (KVM_SYSTEM_EVENT_RESET, vec![0]), "{version:#x}");
        drop(vm);
    }
}
