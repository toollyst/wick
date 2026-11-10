// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Windows backends of the platform interfaces.
//!
//! The asynchronous I/O queue and the hole keeper are those of macOS, over
//! the compatibility libc (`pread`/`pwrite`/`FlushFileBuffers`; `SEEK_DATA`
//! and hole punching on NTFS sparse files); the network interface is a Unix
//! stream endpoint.

#[path = "../macos/async_io.rs"]
pub mod async_io;
#[path = "../macos/fs.rs"]
pub mod fs;
pub mod net;
