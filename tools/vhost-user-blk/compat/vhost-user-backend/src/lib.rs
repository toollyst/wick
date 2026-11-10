// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `vhost-user-backend` 0.23.0 for wick's vhost-user-blk test backend.
//!
//! - Linux, macOS: the upstream crate, re-exported as is.
//! - Windows: the upstream source over `wick_os` (`AF_UNIX` sockets) and the
//!   epoll, eventfd and descriptor passing of wick's compatibility crates.

#[cfg(not(windows))]
pub use upstream::*;

// The macro import of the upstream root (dropped from the generated source).
#[cfg(windows)]
#[macro_use]
extern crate log;

// Upstream code: lints capped as cargo caps them for upstream crates.
#[cfg(windows)]
#[allow(warnings, clippy::all)]
#[path = "windows/mod.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;
