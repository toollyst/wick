// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `std::os::unix` and `std::os::fd` on every host.
//!
//! Upstream code imports `wick_os::unix::...` and `wick_os::fd::...` instead of
//! `std::os::...`:
//! - Unix: these are std's modules, re-exported.
//! - Windows: the same traits and types, where a file descriptor is the value
//!   of a kernel handle (`HANDLE` or `SOCKET`). Windows keeps handle values in
//!   32 bits, so `RawFd` is `i32` as on Unix and needs no table.

#[cfg(unix)]
pub use std::os::{fd, unix};

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{fd, stdio, unix};
