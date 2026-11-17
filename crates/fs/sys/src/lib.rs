// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The system calls of wick-fsd's host directory backends (docs/design-fs.md
//! §4.3, §6.1, §6.2), each behind one safe function. All of the server's
//! unsafe code is here; `wick-fsd` itself forbids it.
//!
//! Every name these functions take is one component the caller has checked
//! (`wick_fsd::fuse::name::Name`), and every call is relative to a directory
//! descriptor: none takes a path. Opens never follow a link at any
//! component and never leave the directory they start from: Linux's
//! `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, macOS's `openat` with
//! `O_NOFOLLOW_ANY | O_RESOLVE_BENEATH`. Errors are the host's errno, which
//! the caller translates to Linux's.
//!
//! Linux and macOS only; on any other host the crate is empty.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::*;
