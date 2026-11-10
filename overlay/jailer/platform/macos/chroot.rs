// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! macOS backend of upstream's `chroot` module.
//!
//! macOS has no mount namespaces or `pivot_root`, so the jail is `chroot(2)`.
//! The root directory before it is kept, closed on exec, so the exec can
//! leave the chroot again (`platform::exec_command`): no program can start
//! inside a chroot on macOS, and Firecracker enters the same jail itself
//! before anything else.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::{JailerError, to_cstring};
use crate::platform::{self, HostError};

pub fn chroot(path: &Path) -> Result<(), JailerError> {
    let old_root: OwnedFd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")
        .map_err(HostError::Chroot)?
        .into();
    let c_path = to_cstring(path)?;
    // SAFETY: NUL-terminated path.
    if unsafe { libc::chroot(c_path.as_ptr()) } != 0 {
        return Err(HostError::Chroot(io::Error::last_os_error()).into());
    }
    platform::set_old_root(old_root)?;
    // SAFETY: NUL-terminated path.
    if unsafe { libc::chdir(c"/".as_ptr()) } != 0 {
        return Err(JailerError::ChdirNewRoot(io::Error::last_os_error()));
    }
    Ok(())
}
