// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `micro_http` for wick.
//!
//! - Linux, macOS: the upstream crate, re-exported as is.
//! - Windows: the upstream source over `wick_os` (`AF_UNIX` sockets) and
//!   wick's epoll.

#[cfg(not(windows))]
pub use upstream::*;

#[cfg(windows)]
// Upstream code: lints capped as cargo caps them for upstream crates.
#[allow(warnings, clippy::all)]
#[path = "windows/mod.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;
