// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Shared code of wick's fuzz targets: the modules under test, compiled from
//! their own sources, and the reference implementations they are checked
//! against.

/// `vmm::platform::vnet`, compiled from its source (it uses only `std` and
/// `libc`), so it is fuzzed without building the vmm crate.
#[path = "../../overlay/vmm/platform/vnet.rs"]
pub mod vnet;

pub mod frame;

pub mod whp;

/// KVM's x86_64 structures (the snapshot state of the interrupt controller),
/// on any host: the Windows build's bindings, which keep the Linux x86_64
/// layout. `whp::irqchip` names them `kvm_bindings::...`.
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    unexpected_cfgs,
    clippy::all
)]
#[path = "../../crates/compat/kvm-bindings/src/windows/x86_64/bindings.rs"]
mod x86_bindings;
pub use x86_bindings::*;
extern crate self as kvm_bindings;

/// The exit decoding of the Hypervisor.framework backend
/// (`crates/compat/kvm-ioctls/src/hvf/exit.rs`), compiled from its source (it
/// uses nothing but `core`), so it is fuzzed on any host but Windows, where
/// `trng`, which it names, does not build (tools/fuzz.sh, `host_targets`).
#[cfg(not(windows))]
#[path = "../../crates/compat/kvm-ioctls/src/hvf/exit.rs"]
pub mod hvf_exit;

/// The SMCCC TRNG service's numbers and answers
/// (`crates/compat/kvm-ioctls/src/hvf/trng.rs`), which the exit decoding
/// names as `super::trng`; compiled from its source.
/// It calls `getentropy`, which wick's POSIX layer for Windows does not have.
#[cfg(not(windows))]
#[allow(dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/hvf/trng.rs"]
mod trng;

/// What the WHP run loop decides from a vCPU exit's fields
/// (`crates/compat/kvm-ioctls/src/whp/exit.rs`), compiled from its source (it
/// uses nothing but `core`), so it is fuzzed on any host.
#[allow(unreachable_pub, dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/exit.rs"]
pub mod whp_exit;

/// The guest's CPUID x2APIC bit against the WHP partition's local APIC mode
/// (`crates/compat/kvm-ioctls/src/whp/apicmode.rs`), compiled from its
/// source (it uses nothing but `core`) so its tests run on every host.
#[allow(unreachable_pub, dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/apicmode.rs"]
pub mod whp_apicmode;

/// What the WHP backend does with a guest #GP on its x2APIC partition
/// (`crates/compat/kvm-ioctls/src/whp/gp.rs`), compiled from its source (it
/// uses nothing but `core`) so its tests run on every host.
#[allow(unreachable_pub, dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/gp.rs"]
pub mod whp_gp;

/// KVM's answer to a guest's and the VMM's MSR accesses that no WHP
/// register holds, as the WHP backend gives it
/// (`crates/compat/kvm-ioctls/src/whp/kvmmsr.rs`), compiled from its source
/// (it uses nothing but `core`) so its tests run on every host.
#[allow(unreachable_pub, dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/kvmmsr.rs"]
pub mod whp_kvmmsr;

/// The CR4 values the WHP backend's `KVM_SET_SREGS` takes, as KVM decides
/// them (`crates/compat/kvm-ioctls/src/whp/cr4.rs`), compiled from its
/// source (it uses nothing but `core`) so its tests run on every host.
#[allow(unreachable_pub, dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/cr4.rs"]
pub mod whp_cr4;

/// KVM's TSC matching as the WHP backend decides it
/// (`crates/compat/kvm-ioctls/src/whp/tscsync.rs`), compiled from its source
/// (it uses nothing but `core`) so its tests run on every host.
#[allow(unreachable_pub, dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/tscsync.rs"]
pub mod whp_tscsync;
