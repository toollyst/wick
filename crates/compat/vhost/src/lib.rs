// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `vhost` 0.17.0 for wick.
//!
//! - Linux, macOS: the upstream crate, re-exported as is.
//! - Windows: the upstream source over `wick_os` (`AF_UNIX` sockets) and
//!   wick's descriptor passing, so vhost-user works the same. The kernel
//!   vhost backends (`vhost-kern`, `vhost-net`, `vhost-vdpa`) need Linux.

#[cfg(all(windows, feature = "vhost-kern"))]
compile_error!("the kernel vhost backends (vhost-kern) need Linux");

#[cfg(not(windows))]
pub use upstream::*;

// The macro imports of the upstream root (dropped from the generated source).
#[cfg(windows)]
#[cfg_attr(feature = "vhost-user", macro_use)]
extern crate bitflags;
#[cfg(windows)]
#[cfg_attr(feature = "vhost-kern", macro_use)]
extern crate vmm_sys_util;

// Upstream code: lints capped as cargo caps them for upstream crates.
#[cfg(windows)]
#[allow(warnings, clippy::all)]
#[path = "windows/mod.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;
