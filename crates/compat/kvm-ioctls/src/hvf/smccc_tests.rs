// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The SMCCC TRNG service and PSCI 1.1's SYSTEM_RESET2 as a guest calls
//! them: a guest program makes the calls and stores each answer's
//! registers to MMIO. And KVM's firmware pseudo-registers: listed, read
//! and written as KVM's, a service turned off by its bit, and the whole
//! register list saved and written to a new VM as a snapshot does.

use kvm_bindings::{
    KVM_ARM_VCPU_POWER_OFF, KVM_MP_STATE_STOPPED, KVM_REG_SIZE_MASK, KVM_REG_SIZE_U32, KVM_SYSTEM_EVENT_RESET,
    KVM_SYSTEM_EVENT_SHUTDOWN, RegList, kvm_vcpu_init,
};

use super::exit::{KVM_UID, PV_TIME_FEATURES, PV_TIME_ST};
use super::pvtime::tests::{PC, PSTATE, RAM, X9, mmio_values, new_vcpu, vm_with_code};
use super::regs::{
    Bmap, FW_REGS, PSCI_VERSION_0_2, PSCI_VERSION_1_0, PSCI_VERSION_1_1, PSCI_VERSION_ID, reg_size, sys_id, workaround_id,
};
use super::trng;
use crate::{VcpuExit, VcpuFd};

const HVC: u32 = 0xd400_0002;
/// -1, -2 as the 64-bit X0 the guest reads.
const NOT_SUPPORTED: u64 = -1i64 as u64;
const INVALID_PARAMS: u64 = -2i64 as u64;
const ALREADY_ON: u64 = -4i64 as u64;
const INTERNAL_FAILURE: u64 = -6i64 as u64;

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
    // X2 and X3 hold what the call before left: cleared, so that a call
    // that does not write them shows.
    call3(id, [arg, 0, 0], stored)
}

/// [`call`] with X1 to X3 given.
fn call3(id: u32, args: [u64; 3], stored: std::ops::Range<u32>) -> Vec<u32> {
    let mut code = mov(0, u64::from(id));
    for (reg, arg) in (1..).zip(args) {
        code.extend(mov(reg, arg));
    }
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

/// The core register `xN`'s id (KVM_REG_ARM_CORE, two 32-bit words a register).
fn x(n: u64) -> u64 {
    0x6030_0000_0010_0000 + 2 * n
}

/// A vCPU that starts powered off (KVM_ARM_VCPU_POWER_OFF).
fn new_vcpu_off(vm: &crate::VmFd, id: u64) -> VcpuFd {
    let vcpu = vm.create_vcpu(id).unwrap();
    let mut kvi = kvm_vcpu_init::default();
    vm.get_preferred_target(&mut kvi).unwrap();
    kvi.features[0] |= 1 << KVM_ARM_VCPU_POWER_OFF;
    vcpu.vcpu_init(&kvi).unwrap();
    vcpu
}

// Every PSCI call returns as KVM's (Linux 6.1 arch/arm64/kvm/psci.c
// kvm_psci_0_2_call, kvm_psci_1_x_call: `smccc_set_retval(vcpu, val, 0, 0,
// 0)`): X1 to X3 are 0 after the call, whatever the guest had in them.
// PSCI_FEATURES looks at the low half of X1 (`u32 arg`). AFFINITY_INFO
// (kvm_psci_vcpu_affinity_info) is INVALID_PARAMS for a target with a bit
// outside the MPIDR's affinity fields, for a level over 3 and when no vCPU
// matches, and looks only at the fields from the level upwards; CPU_ON
// (kvm_psci_vcpu_on) refuses the same targets, and one that is on with
// ALREADY_ON; their SMC32 forms take the low half of each argument
// (kvm_psci_narrow_to_32bit). SYSTEM_OFF leaves [INTERNAL_FAILURE, 0, 0, 0]
// in the registers of the vCPU that called it.
#[test]
fn test_psci_calls_return_as_kvms() {
    const VERSION: u32 = 0x8400_0000;
    const FEATURES: u32 = 0x8400_000a;
    const AFFINITY_INFO: u32 = 0x8400_0004;
    const AFFINITY_INFO_64: u32 = 0xc400_0004;
    const CPU_ON: u32 = 0x8400_0003;
    const CPU_ON_64: u32 = 0xc400_0003;
    let hi = 1u64 << 40;
    let code = program(&[
        call3(VERSION, [5, 6, 7], 0..4),
        call3(FEATURES, [u64::from(VERSION), 6, 7], 0..4),
        call3(FEATURES, [1 << 32 | u64::from(CPU_ON_64), 6, 7], 0..4),
        call3(FEATURES, [0x8400_0005, 6, 7], 0..4),
        // MIGRATE_INFO_TYPE, and an id PSCI does not have.
        call3(0x8400_0006, [5, 6, 7], 0..4),
        call3(0x8400_0005, [5, 6, 7], 0..4),
        // vCPU 1 is off, vCPU 0 (the caller) on, there is no vCPU 2.
        call3(AFFINITY_INFO_64, [1, 0, 7], 0..4),
        call3(AFFINITY_INFO_64, [0, 0, 7], 0..4),
        call3(AFFINITY_INFO_64, [2, 0, 7], 0..4),
        // From level 1 upwards vCPU 0 and 1 are the same: one is on.
        call3(AFFINITY_INFO_64, [1, 1, 7], 0..4),
        call3(AFFINITY_INFO_64, [0x100, 1, 7], 0..4),
        call3(AFFINITY_INFO_64, [0x100, 2, 7], 0..4),
        call3(AFFINITY_INFO_64, [1, 4, 7], 0..4),
        // Bit 24 is in no affinity field; bit 40 neither, and the SMC32
        // call does not see it, nor the upper half of the level.
        call3(AFFINITY_INFO_64, [1 << 24 | 1, 0, 7], 0..4),
        call3(AFFINITY_INFO_64, [hi | 1, 0, 7], 0..4),
        call3(AFFINITY_INFO, [hi | 1, hi, 7], 0..4),
        call3(AFFINITY_INFO_64, [1, hi, 7], 0..4),
        call3(CPU_ON_64, [0, 6, 7], 0..4),
        call3(CPU_ON_64, [2, 6, 7], 0..4),
        call3(CPU_ON_64, [1 << 24 | 1, 6, 7], 0..4),
        call3(CPU_ON_64, [hi, 6, 7], 0..4),
        call3(CPU_ON, [hi, 6, 7], 0..4),
        // SYSTEM_OFF.
        call3(0x8400_0008, [5, 6, 7], 0..4),
    ]);
    let (vm, _) = vm_with_code(&code, 0);
    let mut vcpu = new_vcpu(&vm, 0);
    let _off = new_vcpu_off(&vm, 1);
    let (values, event, data, regs) = std::thread::spawn(move || {
        vcpu.set_one_reg(PC, &RAM.to_le_bytes()).unwrap();
        vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
        vcpu.set_one_reg(X9, &0x1000u64.to_le_bytes()).unwrap();
        let mut values = Vec::new();
        let (event, data) = loop {
            match vcpu.run().unwrap() {
                VcpuExit::MmioWrite(0x1000, data) => values.push(u64::from_le_bytes(data.try_into().unwrap())),
                VcpuExit::SystemEvent(event, data) => break (event, data.to_vec()),
                other => panic!("unexpected exit {other:?}"),
            }
        };
        (values, event, data, [0, 1, 2, 3].map(|n| read(&vcpu, x(n))))
    })
    .join()
    .unwrap();
    let want: [(&str, u64); 22] = [
        ("PSCI_VERSION", PSCI_VERSION_1_1),
        ("PSCI_FEATURES of PSCI_VERSION", 0),
        ("PSCI_FEATURES of CPU_ON with the upper half of X1 set", 0),
        ("PSCI_FEATURES of MIGRATE", NOT_SUPPORTED),
        ("MIGRATE_INFO_TYPE", 2),
        ("MIGRATE", NOT_SUPPORTED),
        ("AFFINITY_INFO of vCPU 1", 1),
        ("AFFINITY_INFO of vCPU 0", 0),
        ("AFFINITY_INFO of vCPU 2", INVALID_PARAMS),
        ("AFFINITY_INFO of 1 at level 1", 0),
        ("AFFINITY_INFO of 0x100 at level 1", INVALID_PARAMS),
        ("AFFINITY_INFO of 0x100 at level 2", 0),
        ("AFFINITY_INFO at level 4", INVALID_PARAMS),
        ("AFFINITY_INFO with bit 24", INVALID_PARAMS),
        ("AFFINITY_INFO with bit 40", INVALID_PARAMS),
        ("SMC32 AFFINITY_INFO with bit 40", 1),
        ("AFFINITY_INFO at level 1 << 40", INVALID_PARAMS),
        ("CPU_ON of the caller", ALREADY_ON),
        ("CPU_ON of vCPU 2", INVALID_PARAMS),
        ("CPU_ON with bit 24", INVALID_PARAMS),
        ("CPU_ON with bit 40", INVALID_PARAMS),
        ("SMC32 CPU_ON with bit 40: the caller", ALREADY_ON),
    ];
    assert_eq!(values.len(), 4 * want.len());
    for ((name, x0), answer) in want.iter().zip(values.chunks(4)) {
        assert_eq!(answer, [*x0, 0, 0, 0], "{name}");
    }
    assert_eq!((event, data), (KVM_SYSTEM_EVENT_SHUTDOWN, vec![0]));
    assert_eq!(regs, [INTERNAL_FAILURE, 0, 0, 0], "after SYSTEM_OFF");
}

/// Runs `code` on one vCPU until its system event; the event and X0 to X3
/// after it.
fn registers_at_system_event(code: &[u32], version: u64) -> (u32, Vec<u64>, [u64; 4]) {
    let (vm, _) = vm_with_code(code, 0);
    let mut vcpu = new_vcpu(&vm, 0);
    vcpu.set_one_reg(PSCI_VERSION_ID, &version.to_le_bytes()).unwrap();
    std::thread::spawn(move || {
        vcpu.set_one_reg(PC, &RAM.to_le_bytes()).unwrap();
        vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
        match vcpu.run().unwrap() {
            VcpuExit::SystemEvent(event, data) => (event, data.to_vec(), [0, 1, 2, 3].map(|n| read(&vcpu, x(n)))),
            other => panic!("unexpected exit {other:?}"),
        }
    })
    .join()
    .unwrap()
}

// What SYSTEM_RESET and SYSTEM_RESET2 leave in the caller's registers, as
// KVM (psci.c): SYSTEM_RESET [INTERNAL_FAILURE, 0, 0, 0], under every PSCI
// version; a SYSTEM_RESET2 that resets writes X0 alone (`vcpu_set_reg(vcpu,
// 0, PSCI_RET_INTERNAL_FAILURE); return 0`), X1 to X3 staying the guest's,
// which the SMC32 call has cut to their low halves before
// (kvm_psci_narrow_to_32bit).
#[test]
fn test_a_reset_leaves_the_registers_kvm_leaves() {
    let hi = 1u64 << 32;
    for version in [PSCI_VERSION_1_1, PSCI_VERSION_1_0, PSCI_VERSION_0_2] {
        let code = program(&[call3(0x8400_0009, [5, hi | 6, 7], 0..0)]);
        assert_eq!(
            registers_at_system_event(&code, version),
            (KVM_SYSTEM_EVENT_RESET, vec![0], [INTERNAL_FAILURE, 0, 0, 0]),
            "{version:#x}"
        );
    }
    let args = [hi | 0x8000_0001, hi | 6, hi | 7];
    for (id, left) in [(0xc400_0012, args), (0x8400_0012, [0x8000_0001, 6, 7])] {
        let code = program(&[call3(id, args, 0..0)]);
        assert_eq!(
            registers_at_system_event(&code, PSCI_VERSION_1_1),
            (KVM_SYSTEM_EVENT_RESET, vec![1], [INTERNAL_FAILURE, left[0], left[1], left[2]]),
            "{id:#x}"
        );
    }
}

// CPU_OFF returns SUCCESS through the same path (kvm_psci_0_2_call: `val =
// PSCI_RET_SUCCESS`, then smccc_set_retval): the stopped vCPU's X0 to X3
// are 0, which is what a snapshot of it holds. vCPU 1 calls CPU_OFF; vCPU
// 0 asks AFFINITY_INFO until vCPU 1 is off and then stores to MMIO, at
// which vCPU 1 is kicked out of its run and read.
#[test]
fn test_cpu_off_leaves_the_registers_kvm_leaves() {
    let mut code = call3(0xc400_0004, [1, 0, 0], 0..0);
    let back = code.len() as u32 + 1;
    code.push(0xf100_041f); // cmp x0, #1
    code.push(0x5400_0001 | (back.wrapping_neg() & 0x7_ffff) << 5); // b.ne to the start
    code.push(0xf900_0120); // str x0, [x9]
    code.push(0x1400_0000); // b .
    let entry = RAM + 4 * code.len() as u64;
    code.extend(program(&[call3(0x8400_0002, [5, 6, 7], 0..0)]));
    let (vm, _) = vm_with_code(&code, 0);
    let mut first = new_vcpu(&vm, 0);
    let mut second = new_vcpu(&vm, 1);
    let kick = second.kick_for_test();
    let stopped = std::thread::spawn(move || {
        second.set_one_reg(PC, &entry.to_le_bytes()).unwrap();
        second.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
        assert_eq!(second.run().unwrap_err().errno(), libc::EINTR);
        (second.get_mp_state().unwrap().mp_state, [0, 1, 2, 3].map(|n| read(&second, x(n))))
    });
    std::thread::spawn(move || {
        first.set_one_reg(PC, &RAM.to_le_bytes()).unwrap();
        first.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
        first.set_one_reg(X9, &0x1000u64.to_le_bytes()).unwrap();
        match first.run().unwrap() {
            VcpuExit::MmioWrite(0x1000, data) => assert_eq!(data, 1u64.to_le_bytes()),
            other => panic!("unexpected exit {other:?}"),
        }
    })
    .join()
    .unwrap();
    kick();
    assert_eq!(stopped.join().unwrap(), (KVM_MP_STATE_STOPPED, [0, 0, 0, 0]));
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
// PSCI 1.1, each workaround level the host's (what goes with
// SMCCC_ARCH_FEATURES' answer: test_the_arch_workarounds_answer_as_kvm_on_this_cpu),
// and every service's bit (kvm_arm_init_hypercalls);
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
    let [w1, w2, w3] = [1, 2, 3].map(|n| read(&vcpus[0], workaround_id(n)));
    for vcpu in &vcpus {
        assert_eq!(FW_REGS.map(|id| read(vcpu, id)), [PSCI_VERSION_1_1, w1, w2, w3, 1, 1, 3]);
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

    // A workaround level takes NOT_AVAIL on any host, and nothing is kept
    // of the write: the register reads the host's level still. A bit
    // outside the level (and, for WORKAROUND_2, its enabled bit) is EINVAL.
    for (n, level) in [(1, w1), (2, w2), (3, w3)] {
        assert_eq!(write(&vcpus[0], workaround_id(n), 0), Ok(8));
        assert_eq!(read(&vcpus[1], workaround_id(n)), level);
        for bad in [0x20, 1 << 32, 0x10] {
            assert_eq!(write(&vcpus[0], workaround_id(n), bad), Err(libc::EINVAL), "{n} {bad:#x}");
        }
    }

    let mut buf = [0u8; 8];
    for id in [workaround_id(4), vendor + 1, std & !KVM_REG_SIZE_MASK | KVM_REG_SIZE_U32] {
        assert_eq!(vcpus[0].get_one_reg(id, &mut buf).unwrap_err().errno(), libc::ENOENT, "{id:#x}");
        assert_eq!(vcpus[0].set_one_reg(id, &buf).unwrap_err().errno(), libc::ENOENT, "{id:#x}");
    }
}

fn sysctl(name: &std::ffi::CStr) -> Option<i32> {
    let mut value = 0i32;
    let mut len = std::mem::size_of::<i32>();
    // SAFETY: a 4-byte value and its length; the name is NUL-terminated.
    let ret = unsafe {
        libc::sysctlbyname(name.as_ptr(), std::ptr::from_mut(&mut value).cast(), &mut len, std::ptr::null_mut(), 0)
    };
    (ret == 0).then_some(value)
}

// SMCCC_ARCH_FEATURES of ARM_SMCCC_ARCH_WORKAROUND_1, _2 and _3 answers by
// the host CPU's Spectre state as Linux decides it, and each firmware
// register's level goes with its answer, as KVM's two functions give them
// (hypercalls.c kvm_hvc_call_handler beside get_kernel_wa_level). The host
// CPU's side is checked against macOS's own record of the CPU
// (`hw.optional.arm.FEAT_CSV2`, `FEAT_SSBS`): a CPU with CSV2 is unaffected
// by Spectre v2 (answer 1, level NOT_REQUIRED); no Mac's core is on
// Linux's Spectre v4 safe list and none has firmware to ask, so
// WORKAROUND_2 is NOT_SUPPORTED with or without SSBS (level NOT_AVAIL).
// A register takes its level and none above. The calls themselves return
// as KVM's entry code returns them (hyp-entry.S el1_sync): X0 and X1 0, X2
// and X3 untouched.
#[test]
fn test_the_arch_workarounds_answer_as_kvm_on_this_cpu() {
    const WORKAROUNDS: [u32; 3] = [0x8000_8000, 0x8000_7fff, 0x8000_3fff];
    let mut calls: Vec<Vec<u32>> =
        WORKAROUNDS.iter().map(|id| call3(SMCCC_ARCH_FEATURES, [1 << 32 | u64::from(*id), 6, 7], 0..4)).collect();
    calls.extend(WORKAROUNDS.iter().map(|id| call3(*id, [5, 6, 7], 0..4)));
    // Its neighbour is no call, and no feature.
    calls.push(call3(0x8000_8001, [5, 6, 7], 0..4));
    calls.push(call3(SMCCC_ARCH_FEATURES, [0x8000_8001, 6, 7], 0..4));
    let (vm, _) = vm_with_code(&program(&calls), 0);
    let vcpu = new_vcpu(&vm, 0);
    let levels = [1, 2, 3].map(|n| read(&vcpu, workaround_id(n)));
    // MIDR_EL1, ID_AA64PFR0_EL1 (CSV2 59:56), ID_AA64PFR1_EL1 (SSBS 7:4),
    // ID_AA64MMFR1_EL1 (ECBHB 63:60), ID_AA64ISAR2_EL1 (CLRBHB 31:28): what
    // the answers below are decided from, for the record of a run.
    let ids = [0xc000, 0xc020, 0xc021, 0xc039, 0xc032].map(|r| {
        let mut buf = [0u8; 8];
        vcpu.get_one_reg(sys_id(r), &mut buf).map(|_| u64::from_le_bytes(buf)).ok()
    });
    println!("MIDR, ID_AA64PFR0, ID_AA64PFR1, ID_AA64MMFR1, ID_AA64ISAR2: {ids:x?}");
    for (n, level) in (1u64..).zip(levels) {
        assert_eq!(write(&vcpu, workaround_id(n), level), Ok(8), "WORKAROUND_{n} at its level {level}");
        // WORKAROUND_2's levels are narrowed to NOT_AVAIL (0, 1) and
        // NOT_REQUIRED (2, 3): the first above NOT_AVAIL is 2.
        let above = if n == 2 && level == 0 { 2 } else { level + 1 };
        assert_eq!(write(&vcpu, workaround_id(n), above), Err(libc::EINVAL), "WORKAROUND_{n} above {level}");
        assert_eq!(write(&vcpu, workaround_id(n), 0), Ok(8), "WORKAROUND_{n} at NOT_AVAIL");
    }
    let v = mmio_values(vcpu, 4 * 8);
    let answers = [v[0], v[4], v[8]];
    println!("SMCCC_ARCH_FEATURES of WORKAROUND_1, _2, _3: {answers:x?}; levels {levels:?}");
    for (n, (answer, level)) in (1usize..).zip(answers.iter().zip(levels)) {
        assert_eq!(v[4 * (n - 1) + 1..4 * n], [0, 0, 0], "WORKAROUND_{n}'s X1 to X3");
        // get_kernel_wa_level beside kvm_hvc_call_handler.
        let goes_with = match (n, *answer) {
            (_, NOT_SUPPORTED) => 0,
            (1 | 3, 0) => 1,
            (1 | 3, 1) => 2,
            (2, 2) => 3,
            _ => panic!("WORKAROUND_{n}: answer {answer:#x}"),
        };
        assert_eq!(level, goes_with, "WORKAROUND_{n}: answer {answer:#x}");
    }
    let csv2 = sysctl(c"hw.optional.arm.FEAT_CSV2").expect("hw.optional.arm.FEAT_CSV2");
    println!("hw.optional.arm.FEAT_CSV2 {csv2}, FEAT_SSBS {:?}", sysctl(c"hw.optional.arm.FEAT_SSBS"));
    assert_eq!(answers[0], if csv2 == 1 { 1 } else { NOT_SUPPORTED }, "WORKAROUND_1 with FEAT_CSV2 {csv2}");
    assert_eq!(answers[1], NOT_SUPPORTED, "WORKAROUND_2");
    // BHB is never mitigated or unaffected where v2 is vulnerable.
    assert!(answers[0] != NOT_SUPPORTED || answers[2] == NOT_SUPPORTED, "{answers:x?}");
    for answer in v[12..24].chunks(4) {
        assert_eq!(answer, [0, 0, 6, 7], "a workaround call");
    }
    assert_eq!(v[24..28], [NOT_SUPPORTED, 0, 0, 0]);
    assert_eq!(v[28..32], [NOT_SUPPORTED, 0, 0, 0]);
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
    assert_eq!((kept[0], &kept[4..]), (PSCI_VERSION_1_0, &[0, 1, 1][..]));

    let code = program(&[
        call(0x8400_0000, 0, 0..1),
        call(trng::VERSION, 5, 0..4),
        call(KVM_FEATURES, 0, 0..1),
        call(KVM_PTP, 0, 0..1),
    ]);
    let (vm, _) = vm_with_code(&code, 0);
    let vcpu = new_vcpu(&vm, 0);
    // The workaround levels are the host's in both VMs: the saved ones are
    // taken, being no higher.
    let [w1, w2, w3] = [1, 2, 3].map(|n| read(&vcpu, workaround_id(n)));
    assert_eq!(kept[1..4], [w1, w2, w3]);
    assert_eq!(FW_REGS.map(|id| read(&vcpu, id)), [PSCI_VERSION_1_1, w1, w2, w3, 1, 1, 3]);
    for (id, value) in &state {
        vcpu.set_one_reg(*id, value).unwrap_or_else(|e| panic!("{id:#x}: {e}"));
    }
    assert_eq!(FW_REGS.map(|id| read(&vcpu, id)), [PSCI_VERSION_1_0, w1, w2, w3, 0, 1, 1]);
    assert_eq!(mmio_values(vcpu, 7), [PSCI_VERSION_1_0, NOT_SUPPORTED, 0, 0, 0, 1, NOT_SUPPORTED]);
}
