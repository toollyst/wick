// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SMCCC TRNG service and PSCI 1.1's SYSTEM_RESET2 as a guest calls
//! them: a guest program makes the calls and stores each answer's
//! registers to MMIO. And KVM's firmware pseudo-registers: listed, read
//! and written as KVM's, a service turned off by its bit, and the whole
//! register list saved and written to a new VM as a snapshot does.

use kvm_bindings::{KVM_REG_SIZE_MASK, KVM_REG_SIZE_U32, KVM_SYSTEM_EVENT_RESET, RegList};

use super::exit::{KVM_UID, PV_TIME_FEATURES, PV_TIME_ST};
use super::pvtime::tests::{PC, PSTATE, RAM, X9, mmio_values, new_vcpu, vm_with_code};
use super::regs::{
    Bmap, FW_REGS, PSCI_VERSION_0_2, PSCI_VERSION_1_0, PSCI_VERSION_1_1, PSCI_VERSION_ID, reg_size, workaround_id,
};
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

fn read(vcpu: &VcpuFd, id: u64) -> u64 {
    let mut buf = [0u8; 8];
    vcpu.get_one_reg(id, &mut buf).unwrap();
    u64::from_le_bytes(buf)
}

fn write(vcpu: &VcpuFd, id: u64, value: u64) -> Result<usize, i32> {
    vcpu.set_one_reg(id, &value.to_le_bytes()).map_err(|e| e.errno())
}

/// Every register `KVM_GET_REG_LIST` names with its value: what
/// Firecracker saves of a vCPU (`get_all_registers`).
fn saved(vcpu: &VcpuFd) -> Vec<(u64, Vec<u8>)> {
    let mut list = RegList::new(500).unwrap();
    vcpu.get_reg_list(&mut list).unwrap();
    list.as_slice()
        .iter()
        .map(|&id| {
            let mut value = vec![0u8; reg_size(id)];
            vcpu.get_one_reg(id, &mut value).unwrap();
            (id, value)
        })
        .collect()
}

// KVM's firmware pseudo-registers (Linux 6.1 hypercalls.c): the seven are
// in the register list in kvm_arm_fw_reg_ids' order; a new VM's values are
// PSCI 1.1, each workaround level NOT_AVAIL (what SMCCC_ARCH_FEATURES
// answers for them here), and every service's bit (kvm_arm_init_hypercalls);
// they are the VM's (written by one vCPU, read by another); a bitmap takes
// any subset of its bits and no other bit (EINVAL), a workaround level only
// one the host gives (EINVAL); an id of another size or number is ENOENT.
#[test]
fn test_firmware_registers_are_listed_and_kept_as_kvms() {
    let (vm, _) = vm_with_code(&program(&[]), 0);
    let vcpus = [new_vcpu(&vm, 0), new_vcpu(&vm, 1)];
    let mut list = RegList::new(500).unwrap();
    vcpus[0].get_reg_list(&mut list).unwrap();
    let ids = list.as_slice();
    let first = ids.iter().position(|id| *id == PSCI_VERSION_ID).expect("the PSCI version is not listed");
    assert_eq!(ids[first..first + 7], FW_REGS);
    for vcpu in &vcpus {
        assert_eq!(FW_REGS.map(|id| read(vcpu, id)), [PSCI_VERSION_1_1, 0, 0, 0, 1, 1, 3]);
    }

    let (std, std_hyp, vendor) = (Bmap::Std.id(), Bmap::StdHyp.id(), Bmap::VendorHyp.id());
    for (id, bad) in [(std, 2), (std, 3), (std_hyp, 2), (vendor, 4), (vendor, 1 << 63)] {
        assert_eq!(write(&vcpus[0], id, bad), Err(libc::EINVAL), "{id:#x} {bad:#x}");
    }
    for (id, value) in [(std, 0), (std_hyp, 0), (vendor, 2), (vendor, 1), (vendor, 0)] {
        assert_eq!(write(&vcpus[0], id, value), Ok(8));
        assert_eq!((read(&vcpus[0], id), read(&vcpus[1], id)), (value, value), "{id:#x}");
    }
    // No vCPU has run: a bit may be set again.
    assert_eq!(write(&vcpus[1], std, 1), Ok(8));
    assert_eq!(read(&vcpus[0], std), 1);

    for n in [1, 3] {
        assert_eq!(write(&vcpus[0], workaround_id(n), 0), Ok(8));
        assert_eq!(write(&vcpus[0], workaround_id(n), 1), Err(libc::EINVAL));
    }
    for (value, result) in [(0, Ok(8)), (1, Ok(8)), (2, Err(libc::EINVAL)), (3, Err(libc::EINVAL)), (0x10, Err(libc::EINVAL))] {
        assert_eq!(write(&vcpus[0], workaround_id(2), value), result, "{value:#x}");
    }
    // Nothing is kept of a workaround write.
    assert_eq!(read(&vcpus[0], workaround_id(2)), 0);

    let mut buf = [0u8; 8];
    for id in [workaround_id(4), vendor + 1, std & !KVM_REG_SIZE_MASK | KVM_REG_SIZE_U32] {
        assert_eq!(vcpus[0].get_one_reg(id, &mut buf).unwrap_err().errno(), libc::ENOENT, "{id:#x}");
        assert_eq!(vcpus[0].set_one_reg(id, &buf).unwrap_err().errno(), libc::ENOENT, "{id:#x}");
    }
}

const SMCCC_ARCH_FEATURES: u32 = 0x8000_0001;
const KVM_FEATURES: u32 = 0x8600_0000;
const KVM_PTP: u32 = 0x8600_0001;
const KVM_CALL_UID: u32 = 0x8600_ff01;

// A service whose bit is cleared before the guest runs is not there for
// the guest, as on KVM (hypercalls.c kvm_hvc_call_allowed): its calls
// answer NOT_SUPPORTED with X1 to X3 0, SMCCC_ARCH_FEATURES no longer
// reports PV time, and KVM's features call gives the vendor bitmap as
// written. Once a vCPU has run, a bitmap takes only the value it has
// (EBUSY), and an unknown bit is still EINVAL.
#[test]
fn test_a_service_turned_off_by_its_bit_is_not_supported_as_on_kvm() {
    let (std, std_hyp, vendor) = (Bmap::Std.id(), Bmap::StdHyp.id(), Bmap::VendorHyp.id());
    let off = [NOT_SUPPORTED, 0, 0, 0];
    // X1 holds a non-zero argument at each call, X2 and X3 0: an answer of
    // [NOT_SUPPORTED, 0, 0, 0] shows X1 written.
    let code = program(&[
        call(trng::VERSION, 5, 0..4),
        call(trng::FEATURES, u64::from(trng::RND64), 0..4),
        call(trng::GET_UUID, 5, 0..4),
        call(trng::RND32, 32, 0..4),
        call(trng::RND64, 64, 0..4),
        call(SMCCC_ARCH_FEATURES, u64::from(PV_TIME_FEATURES), 0..1),
        call(PV_TIME_FEATURES, u64::from(PV_TIME_FEATURES), 0..4),
        call(PV_TIME_ST, 5, 0..4),
        call(KVM_FEATURES, 5, 0..4),
        call(KVM_CALL_UID, 5, 0..4),
        call(KVM_PTP, 0, 0..1),
        call(KVM_PTP, 1, 0..4),
        // What no bitmap gates.
        call(0x8400_0000, 0, 0..1),
        call(0x8000_0000, 0, 0..1),
    ]);

    // The TRNG, PV time and KVM_PTP off; KVM's UID and features calls on.
    let (vm, _) = vm_with_code(&code, 0);
    let vcpu = new_vcpu(&vm, 0);
    let other = new_vcpu(&vm, 1);
    for (id, value) in [(std, 0), (std_hyp, 0), (vendor, 1)] {
        assert_eq!(write(&vcpu, id, value), Ok(8));
    }
    let v = mmio_values(vcpu, 4 * 5 + 1 + 4 * 4 + 1 + 4 + 2);
    for (i, answer) in v[..20].chunks(4).enumerate() {
        assert_eq!(answer, off, "TRNG call {i}");
    }
    assert_eq!(v[20], NOT_SUPPORTED, "SMCCC_ARCH_FEATURES of PV_TIME_FEATURES");
    assert_eq!(v[21..25], off, "PV_TIME_FEATURES");
    assert_eq!(v[25..29], off, "PV_TIME_ST");
    assert_eq!(v[29..33], [1, 0, 0, 0], "KVM's features");
    assert_eq!(v[33..37], KVM_UID);
    assert_eq!(v[37], NOT_SUPPORTED, "KVM_PTP");
    assert_eq!(v[38..42], off, "KVM_PTP");
    assert_eq!(v[42..], [PSCI_VERSION_1_1, 0x1_0001]);
    // The VM has run.
    for (id, value, result) in [
        (std, 1, Err(libc::EBUSY)),
        (std, 0, Ok(8)),
        (std, 2, Err(libc::EINVAL)),
        (std_hyp, 1, Err(libc::EBUSY)),
        (vendor, 3, Err(libc::EBUSY)),
        (vendor, 0, Err(libc::EBUSY)),
        (vendor, 1, Ok(8)),
        // The PSCI version has no such rule.
        (PSCI_VERSION_ID, PSCI_VERSION_1_0, Ok(8)),
    ] {
        assert_eq!(write(&other, id, value), result, "{id:#x} {value:#x}");
    }
    assert_eq!([std, std_hyp, vendor].map(|id| read(&other, id)), [0, 0, 1]);
    drop(other);
    drop(vm);

    // KVM's UID and features calls off, the others on (a new VM's values
    // but for that bit): the TRNG and KVM_PTP answer, PV time is reported.
    let (vm, _) = vm_with_code(&code, 0);
    let vcpu = new_vcpu(&vm, 0);
    assert_eq!(write(&vcpu, vendor, 2), Ok(8));
    let v = mmio_values(vcpu, 4 * 5 + 1 + 4 * 4 + 1 + 4 + 2);
    assert_eq!(v[0..4], [0x1_0000, 0, 0, 0], "TRNG_VERSION");
    assert_eq!(v[8..12], trng::UUID);
    assert_eq!(v[20], 0, "SMCCC_ARCH_FEATURES of PV_TIME_FEATURES");
    assert_eq!(v[29..33], off, "KVM's features");
    assert_eq!(v[33..37], off, "KVM's UID");
    assert_ne!(v[37], NOT_SUPPORTED, "KVM_PTP");
    drop(vm);
}

// What a snapshot does with the registers (Firecracker's aarch64
// `save_state` reads every register of KVM_GET_REG_LIST, `restore_state`
// writes each to the new VM's vCPU, in the list's order, before it runs):
// a VM with PSCI 1.0, the TRNG off and KVM_PTP off comes back with them,
// and its guest finds what the saved one would.
#[test]
fn test_a_snapshots_registers_restore_the_firmware_registers() {
    let (std, vendor) = (Bmap::Std.id(), Bmap::VendorHyp.id());
    let state = {
        let (vm, _) = vm_with_code(&program(&[]), 0);
        let vcpu = new_vcpu(&vm, 0);
        for (id, value) in [(PSCI_VERSION_ID, PSCI_VERSION_1_0), (std, 0), (vendor, 1)] {
            assert_eq!(write(&vcpu, id, value), Ok(8));
        }
        let state = saved(&vcpu);
        // One VM a process (Hypervisor.framework): it ends before the next.
        drop(vcpu);
        drop(vm);
        state
    };
    let kept: Vec<u64> =
        state.iter().filter(|(id, _)| FW_REGS.contains(id)).map(|(_, v)| u64::from_le_bytes(v[..8].try_into().unwrap())).collect();
    assert_eq!(kept, [PSCI_VERSION_1_0, 0, 0, 0, 0, 1, 1]);

    let code = program(&[
        call(0x8400_0000, 0, 0..1),
        call(trng::VERSION, 5, 0..4),
        call(KVM_FEATURES, 0, 0..1),
        call(KVM_PTP, 0, 0..1),
    ]);
    let (vm, _) = vm_with_code(&code, 0);
    let vcpu = new_vcpu(&vm, 0);
    assert_eq!(FW_REGS.map(|id| read(&vcpu, id)), [PSCI_VERSION_1_1, 0, 0, 0, 1, 1, 3]);
    for (id, value) in &state {
        vcpu.set_one_reg(*id, value).unwrap_or_else(|e| panic!("{id:#x}: {e}"));
    }
    assert_eq!(FW_REGS.map(|id| read(&vcpu, id)), [PSCI_VERSION_1_0, 0, 0, 0, 0, 1, 1]);
    assert_eq!(mmio_values(vcpu, 7), [PSCI_VERSION_1_0, NOT_SUPPORTED, 0, 0, 0, 1, NOT_SUPPORTED]);
}
