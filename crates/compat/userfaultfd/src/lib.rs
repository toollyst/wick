// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `userfaultfd` 0.9.0 for wick.
//!
//! - Linux: the original crate, re-exported as is.
//! - macOS: the same API and semantics, on the userfaultfd kernel side in
//!   wick's `libc` (`libc::wick_uffd`). See [`macos`] and `docs/ARCHITECTURE.md`.
//! - Other hosts: the API Firecracker uses; creating a userfaultfd fails
//!   until the host has a backend (`docs/ROADMAP.md`).

#[cfg(target_os = "linux")]
pub use upstream::*;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::*;
