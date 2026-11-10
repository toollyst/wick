// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `vm-memory` 0.18.0 for wick.
//!
//! - Linux, macOS: the upstream crate, re-exported as is.
//! - Windows: the upstream source with its Unix mmap backend (`mmap`,
//!   `MAP_FIXED`, raw descriptors), which runs on wick's POSIX layer, so
//!   Firecracker maps guest memory through one interface on every OS.

#[cfg(not(windows))]
pub use upstream::*;

#[cfg(windows)]
// Upstream code: lints capped as cargo caps them for upstream crates.
#[allow(warnings, clippy::all)]
#[path = "windows/mod.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;
