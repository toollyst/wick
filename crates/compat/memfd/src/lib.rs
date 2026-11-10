// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `memfd` 0.6.5 for wick.
//!
//! - Linux: the original crate, re-exported as is.
//! - macOS: the same API on an unlinked POSIX shared memory object.
//! - Windows: the same API on a nameless temporary file, whose size seals
//!   are held by a section (see `windows`).
//!
//! Seals the OS cannot enforce (`SealWrite`, `SealFutureWrite`) and huge
//! pages are refused.

#[cfg(target_os = "linux")]
pub use upstream::*;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod os;
#[cfg(windows)]
#[path = "windows.rs"]
mod os;

#[cfg(not(target_os = "linux"))]
mod portable;
#[cfg(not(target_os = "linux"))]
pub use portable::*;
