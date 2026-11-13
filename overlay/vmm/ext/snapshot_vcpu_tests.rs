// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Snapshot restore of a vCPU through upstream's own path
//! (`KvmVcpu::save_state`, `restore_state`) on Hypervisor.framework.
#![cfg(test)]

use kvm_bindings::{KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC};

use crate::arch::aarch64::vcpu::{KvmVcpu, KvmVcpuError, VcpuArchError, VcpuState};
use crate::cpu_config::aarch64::custom_cpu_template::VcpuFeatures;
use crate::cpu_config::templates::RegisterValueFilter;
use crate::vstate::vm::tests::setup_vm_with_memory;

/// `APIAKEYLO_EL1`, the first pointer authentication key in the list.
const APIAKEYLO_EL1: u64 = 0x6030_0000_0013_c108;
const PTRAUTH: u32 = (1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS) | (1 << KVM_ARM_VCPU_PTRAUTH_GENERIC);

/// The state of a vCPU given pointer authentication (as a template's
/// `vcpu_features` gives it).
fn ptrauth_state() -> VcpuState {
    let mut vm = setup_vm_with_memory(0x1000);
    let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
    vm.setup_irqchip(1).unwrap();
    let features = [VcpuFeatures {
        index: 0,
        bitmap: RegisterValueFilter {
            filter: PTRAUTH,
            value: PTRAUTH,
        },
    }];
    vcpu.init(&features).unwrap();
    vcpu.save_state().unwrap()
}

fn restore(state: &VcpuState) -> Result<(), KvmVcpuError> {
    let mut vm = setup_vm_with_memory(0x1000);
    let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
    vm.setup_irqchip(1).unwrap();
    vcpu.restore_state(state)
}

#[test]
fn test_a_state_with_ptrauth_keys_needs_ptrauth() {
    // As on KVM, the key registers are a vCPU's only with pointer
    // authentication (arch/arm64/kvm/sys_regs.c `ptrauth_visibility`): a
    // state that has them and a kvi without the features (a snapshot taken
    // before wick hid pointer authentication without them) is refused at the
    // first key, with upstream's error naming it; with the features it
    // restores.
    let state = ptrauth_state();
    assert!(state.regs.iter().any(|r| r.id == APIAKEYLO_EL1));
    restore(&state).unwrap();

    let mut without = ptrauth_state();
    without.kvi.features[0] &= !PTRAUTH;
    match restore(&without) {
        Err(KvmVcpuError::RestoreState(VcpuArchError::SetOneReg(id, _, e))) => {
            assert_eq!((id, e.errno()), (APIAKEYLO_EL1, libc::ENOENT));
        }
        other => panic!("restored without pointer authentication: {other:?}"),
    }
}

/// KVM's firmware pseudo-registers (Linux 6.1 arch/arm64/kvm/hypercalls.c
/// `kvm_arm_fw_reg_ids`): the PSCI version, the three
/// SMCCC_ARCH_WORKAROUND levels, and the standard, standard hypervisor and
/// vendor hypervisor bitmaps of services.
const FIRMWARE_REGS: [u64; 7] = [
    0x6030_0000_0014_0000,
    0x6030_0000_0014_0001,
    0x6030_0000_0014_0002,
    0x6030_0000_0014_0003,
    0x6030_0000_0016_0000,
    0x6030_0000_0016_0001,
    0x6030_0000_0016_0002,
];
const PSCI_1_0: u64 = 0x1_0000;
const PSCI_1_1: u64 = 0x1_0001;

fn firmware_regs(vcpu: &KvmVcpu) -> [u64; 7] {
    FIRMWARE_REGS.map(|id| {
        let mut value = [0u8; 8];
        vcpu.fd.get_one_reg(id, &mut value).unwrap();
        u64::from_le_bytes(value)
    })
}

/// The firmware registers of a new VM's vCPU restored from `state`.
fn restored_firmware_regs(state: &VcpuState) -> [u64; 7] {
    let mut vm = setup_vm_with_memory(0x1000);
    let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
    vm.setup_irqchip(1).unwrap();
    vcpu.restore_state(state).unwrap();
    firmware_regs(&vcpu)
}

#[test]
fn test_a_snapshot_keeps_the_firmware_registers() {
    // Upstream saves every register KVM_GET_REG_LIST names and writes each
    // back at the restore. KVM's list has its seven firmware registers, so
    // a microVM given PSCI 1.0, no TRNG and no KVM_PTP keeps them over a
    // snapshot; here too.
    let state = {
        let mut vm = setup_vm_with_memory(0x1000);
        let mut vcpu = KvmVcpu::new(0, &vm).unwrap();
        vm.setup_irqchip(1).unwrap();
        vcpu.init(&[]).unwrap();
        assert_eq!(firmware_regs(&vcpu), [PSCI_1_1, 0, 0, 0, 1, 1, 3]);
        for (id, value) in [(FIRMWARE_REGS[0], PSCI_1_0), (FIRMWARE_REGS[4], 0), (FIRMWARE_REGS[6], 1)] {
            vcpu.fd.set_one_reg(id, &value.to_le_bytes()).unwrap();
        }
        // One VM a process (Hypervisor.framework): it ends with this block.
        vcpu.save_state().unwrap()
    };
    let saved: Vec<u64> = state.regs.iter().filter(|r| FIRMWARE_REGS.contains(&r.id)).map(|r| r.value()).collect();
    assert_eq!(saved, [PSCI_1_0, 0, 0, 0, 0, 1, 1]);
    assert_eq!(restored_firmware_regs(&state), [PSCI_1_0, 0, 0, 0, 0, 1, 1]);

    // A state without them, which is what every build before the list named
    // them saved (the PSCI version included): it restores, and the VM has a
    // new VM's values, PSCI 1.1 whatever version its guest was given, as a
    // KVM that is not told a version gives its latest.
    let mut older = VcpuState {
        mp_state: state.mp_state,
        regs: Default::default(),
        mpidr: state.mpidr,
        kvi: state.kvi,
        pvtime_ipa: state.pvtime_ipa,
    };
    for reg in state.regs.iter().filter(|r| !FIRMWARE_REGS.contains(&r.id)) {
        older.regs.push(reg);
    }
    assert_eq!(older.regs.len() + 7, state.regs.len());
    assert_eq!(restored_firmware_regs(&older), [PSCI_1_1, 0, 0, 0, 1, 1, 3]);
}
