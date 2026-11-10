// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Not-supported stand-in for `userfaultfd` on hosts without it.

use std::io;
use std::os::raw::c_void;
#[cfg(windows)]
use wick_os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

use bitflags::bitflags;

/// Errors from this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// userfaultfd is not available on this host.
    #[error("Error accessing /dev/userfaultfd: {0}")]
    OpenDevUserfaultfd(io::Error),
}

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;

fn unsupported() -> Error {
    Error::OpenDevUserfaultfd(io::Error::new(
        io::ErrorKind::Unsupported,
        "userfaultfd is only available on Linux",
    ))
}

bitflags! {
    /// Optional userfaultfd features.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FeatureFlags: u64 {
        /// Page fault notifications for private anonymous memory.
        const PAGEFAULT_FLAG_WP = 1 << 0;
        /// Fork notifications.
        const EVENT_FORK = 1 << 1;
        /// mremap notifications.
        const EVENT_REMAP = 1 << 2;
        /// madvise(MADV_REMOVE/DONTNEED) notifications.
        const EVENT_REMOVE = 1 << 3;
        /// munmap notifications.
        const EVENT_UNMAP = 1 << 6;
    }
}

bitflags! {
    /// Ioctls supported on a registered range.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IoctlFlags: u64 {
        /// UFFDIO_REGISTER.
        const REGISTER = 1 << 0;
        /// UFFDIO_UNREGISTER.
        const UNREGISTER = 1 << 1;
        /// UFFDIO_API.
        const API = 1 << 63;
    }
}

/// A userfaultfd. Never created on this host.
#[derive(Debug)]
pub struct Uffd {
    _private: std::convert::Infallible,
}

impl Uffd {
    /// Registers a memory range.
    pub fn register(&self, _start: *mut c_void, _len: usize) -> Result<IoctlFlags> {
        Err(unsupported())
    }

    /// Unregisters a memory range.
    pub fn unregister(&self, _start: *mut c_void, _len: usize) -> Result<()> {
        Err(unsupported())
    }
}

// No `Uffd` is ever created on this host, so there is no descriptor to give.
#[cfg(any(unix, windows))]
impl AsRawFd for Uffd {
    fn as_raw_fd(&self) -> RawFd {
        match self._private {}
    }
}

/// Builder for [`Uffd`].
#[derive(Debug, Default)]
pub struct UffdBuilder {
    _private: (),
}

impl UffdBuilder {
    /// Creates a builder.
    pub fn new() -> UffdBuilder {
        UffdBuilder::default()
    }

    /// Sets `O_CLOEXEC`.
    pub fn close_on_exec(&mut self, _close_on_exec: bool) -> &mut Self {
        self
    }

    /// Sets `O_NONBLOCK`.
    pub fn non_blocking(&mut self, _non_blocking: bool) -> &mut Self {
        self
    }

    /// Only handle user-mode faults.
    pub fn user_mode_only(&mut self, _user_mode_only: bool) -> &mut Self {
        self
    }

    /// Requires optional features.
    pub fn require_features(&mut self, _feature: FeatureFlags) -> &mut Self {
        self
    }

    /// Requires ioctls.
    pub fn require_ioctls(&mut self, _ioctls: IoctlFlags) -> &mut Self {
        self
    }

    /// Always fails: userfaultfd is Linux-only.
    pub fn create(&self) -> Result<Uffd> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_is_unsupported() {
        let err = UffdBuilder::new()
            .close_on_exec(true)
            .non_blocking(true)
            .require_features(FeatureFlags::EVENT_REMOVE)
            .create()
            .unwrap_err();
        assert!(err.to_string().contains("only available on Linux"));
    }
}
