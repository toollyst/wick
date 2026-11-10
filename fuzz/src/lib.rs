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
