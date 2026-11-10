// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The Windows implementation: descriptors are handle values.

pub mod fd;
mod fs;
mod net;

pub use net::{peer_pid, startup};

/// `std::os::unix`.
pub mod unix {
    /// `std::os::unix::io`.
    pub mod io {
        pub use super::super::fd::*;
    }
    /// `std::os::unix::net`.
    pub mod net {
        pub use super::super::net::{Incoming, SocketAddr, UnixListener, UnixStream};
    }
    /// `std::os::unix::fs`.
    pub mod fs {
        pub use super::super::fs::{FileExt, MetadataExt};
    }
    /// `std::os::unix::ffi`.
    pub mod ffi {
        pub use super::super::fs::{OsStrExt, OsStringExt};
    }
}

#[cfg(test)]
mod tests;
