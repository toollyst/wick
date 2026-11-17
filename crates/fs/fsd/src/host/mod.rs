// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The host directory backends (docs/design-fs.md §4.3): [`unix::HostDir`]
//! on Linux and macOS. Windows has none yet: its backend is the Windows
//! port's (§6.3), and until it lands the server refuses to start there
//! ([`UNAVAILABLE`]).

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod unix;

/// What the server says on a host without a backend, before it touches
/// anything.
pub const UNAVAILABLE: &str = "virtio-fs is not yet available on this host: wick-fsd has no directory backend for it";

/// Whether this host has a backend.
pub const AVAILABLE: bool = cfg!(any(target_os = "linux", target_os = "macos"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_only_where_one_exists() {
        assert_eq!(AVAILABLE, cfg!(any(target_os = "linux", target_os = "macos")));
        assert!(UNAVAILABLE.contains("not yet available"));
    }
}
