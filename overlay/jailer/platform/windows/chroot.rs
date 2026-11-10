// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Windows backend of upstream's `chroot` module.
//!
//! Windows has no chroot. The jail's root becomes a drive of its own
//! (`DefineDosDevice`) and the current directory its root, so the absolute
//! paths upstream's jailer and Firecracker use from here on resolve inside the
//! jail; the directory is opened to the jailed token and labelled low
//! integrity (`platform::enter_jail`). Confinement itself is the jailed
//! process's restricted token (`platform::exec_command`).

use std::path::Path;

use crate::JailerError;

pub fn chroot(path: &Path) -> Result<(), JailerError> {
    crate::platform::enter_jail(path)
}
