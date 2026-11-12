// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! `vm-memory` 0.18.0 for wick.
//!
//! - Linux, macOS: the upstream crate, re-exported as is.
//! - Windows: the upstream source with its Unix mmap backend (`mmap`,
//!   `MAP_FIXED`, raw descriptors), which runs on wick's POSIX layer, so
//!   Firecracker maps guest memory through one interface on every OS.

#[cfg(not(windows))]
pub use upstream::*;

#[cfg(windows)]
// Upstream code: lints capped as cargo caps them for upstream crates.
#[allow(warnings, clippy::all)]
#[path = "windows/mod.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// `WriteVolatile` for wick's `std::io::Stdout` (`wick_os::stdio::Stdout`,
/// which wick-std puts in its place on Windows), as upstream has it for std's
/// (io.rs: a `write(2)` on its descriptor, past std's buffer). Firecracker's
/// Nitro Enclaves console writes guest output to it.
#[cfg(all(windows, feature = "rawfd"))]
mod wick_stdout {
    use wick_os::fd::AsFd;
    use wick_os::stdio::Stdout;

    use crate::bitmap::BitmapSlice;
    use crate::{VolatileMemoryError, VolatileSlice, WriteVolatile};

    impl WriteVolatile for Stdout {
        fn write_volatile<B: BitmapSlice>(
            &mut self,
            buf: &VolatileSlice<B>,
        ) -> Result<usize, VolatileMemoryError> {
            self.as_fd().write_volatile(buf)
        }
    }

    impl WriteVolatile for &Stdout {
        fn write_volatile<B: BitmapSlice>(
            &mut self,
            buf: &VolatileSlice<B>,
        ) -> Result<usize, VolatileMemoryError> {
            self.as_fd().write_volatile(buf)
        }
    }
}
