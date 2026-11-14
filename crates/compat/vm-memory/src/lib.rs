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

/// wick's own tests of the Windows build. Here, not in `windows/`, which
/// tools/gen-windows-sources.sh writes from upstream's source.
#[cfg(all(test, windows))]
mod wick_tests {
    /// A socket made non-blocking through wick_os (`set_nonblocking`, as
    /// vsock's muxer makes its connections: vsock/unix/muxer.rs) is
    /// `O_NONBLOCK` to the libc whose `read` and `write` move its bytes
    /// (`read_volatile_raw_fd`, windows/io.rs), as Linux's std makes it with
    /// `ioctl(FIONBIO)`, which sets `O_NONBLOCK` in the open file's flags
    /// (v6.1 fs/ioctl.c:341-361 `ioctl_fionbio`), and `F_GETFL` shows it.
    #[cfg(feature = "rawfd")]
    #[test]
    fn test_a_socket_made_non_blocking_by_wick_os_is_o_nonblocking_to_the_libc() {
        use wick_os::fd::AsRawFd;
        let (a, _b) = wick_os::unix::net::UnixStream::pair().unwrap();
        for on in [true, false, true] {
            a.set_nonblocking(on).unwrap();
            // SAFETY: plain call on our socket.
            let flags = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(flags & libc::O_NONBLOCK, if on { libc::O_NONBLOCK } else { 0 }, "F_GETFL after set_nonblocking({on})");
        }
    }
}
