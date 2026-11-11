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
/// uses nothing but `core`), so it is fuzzed on any host.
#[path = "../../crates/compat/kvm-ioctls/src/hvf/exit.rs"]
pub mod hvf_exit;

/// What the WHP run loop decides from a vCPU exit's fields
/// (`crates/compat/kvm-ioctls/src/whp/exit.rs`), compiled from its source (it
/// uses nothing but `core`), so it is fuzzed on any host.
#[allow(unreachable_pub, dead_code)]
#[path = "../../crates/compat/kvm-ioctls/src/whp/exit.rs"]
pub mod whp_exit;
