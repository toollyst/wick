// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Platform interfaces of wick.
//!
//! Each submodule is one interface to a facility Firecracker takes from the
//! host OS. Its Linux backend is the kernel API upstream uses; the other
//! backends implement the same behaviour with that OS's own facilities. The
//! rest of the VMM uses only the interfaces.
//!
//! | Interface | Linux | macOS | Windows |
//! |---|---|---|---|
//! | [`async_io`] | io_uring | worker threads, `pread`/`pwrite`/`F_FULLFSYNC` | the macOS worker threads, `FlushFileBuffers` |
//! | [`fs`] | (holes kept by the file system) | holes restored with `F_PUNCHHOLE` | sparse files, holes restored and checked |
//! | [`net`] | TUN/TAP | vmnet.framework, or a Unix datagram endpoint; [`vnet`] header handling | a Unix stream endpoint (QEMU framing); [`vnet`] header handling |

pub mod async_io;
pub mod fs;
pub mod net;
pub mod vnet;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as backend;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as backend;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as backend;
