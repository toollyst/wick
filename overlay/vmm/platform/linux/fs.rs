// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`HoleKeeper`] on Linux: regions that are not written keep their holes, so
//! there is nothing to restore.

use std::fs::File;
use std::io;

use crate::platform::fs::HoleKeeper;

/// Linux files keep their holes.
pub fn keep_holes(_file: &File) -> io::Result<()> {
    Ok(())
}

/// Nothing to track on Linux.
#[derive(Debug)]
pub struct Holes;

impl HoleKeeper for Holes {
    fn new(_file: &File) -> io::Result<Self> {
        Ok(Holes)
    }

    fn written(&mut self, _start: u64, _len: u64) {}

    fn restore(self, _file: &File) -> io::Result<()> {
        Ok(())
    }
}
