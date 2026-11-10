// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `kvm-ioctls` 0.25 for wick.
//!
//! - Linux: the crates.io crate, re-exported as is.
//! - macOS (Apple Silicon): the subset of the API Firecracker uses, implemented
//!   with Hypervisor.framework. See `docs/ARCHITECTURE.md`.

#[cfg(target_os = "linux")]
pub use upstream::*;

#[cfg(target_os = "macos")]
mod hvf;
#[cfg(target_os = "macos")]
pub use hvf::*;

#[cfg(windows)]
mod whp;
#[cfg(windows)]
pub use whp::*;
