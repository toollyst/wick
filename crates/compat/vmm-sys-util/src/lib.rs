// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `vmm-sys-util` 0.15.0 for wick.
//!
//! - Linux: the original crate, re-exported as is.
//! - macOS: the original crate plus the Linux-only modules Firecracker and its
//!   dependencies use, implemented with macOS primitives, and `terminal`,
//!   the original but for `set_non_block` on a revoked terminal. Each module
//!   keeps the original API; behaviour differences are documented on the item.
//! - Windows: the original crate's portable modules plus the Unix-only ones
//!   Firecracker uses, on Win32 handles (`wick-os` descriptors).
//!
//! See `docs/ARCHITECTURE.md`.

#![deny(missing_docs, missing_debug_implementations)]

pub use upstream::*;

#[cfg(any(target_os = "macos", windows))]
mod epoll_types;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;
// Upstream's `terminal` is also in `upstream::*`; this name wins over both globs.
#[cfg(target_os = "macos")]
pub use macos::terminal;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
