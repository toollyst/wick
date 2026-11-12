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
