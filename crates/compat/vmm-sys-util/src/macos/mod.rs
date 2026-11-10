// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! macOS implementations of the Linux-only `vmm-sys-util` modules.

#[macro_use]
pub mod ioctl;
pub mod epoll;
pub mod eventfd;
pub mod seek_hole;
pub mod signal;
