// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! Windows implementations of the Unix-only `vmm-sys-util` modules.

#[macro_use]
pub mod ioctl;
mod errors;
pub mod epoll;
pub mod event;
pub mod eventfd;
pub mod seek_hole;
pub mod signal;
pub mod sock_ctrl_msg;
pub mod tempdir;
pub mod terminal;

#[cfg(test)]
mod nofilerec;
