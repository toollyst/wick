// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md §4.3: the descriptor a leaf keeps of a file the guest
//! opened lives until the node is forgotten, and then is closed: an
//! unlinked file's space goes back to the host. The process's descriptors
//! are counted, so this file holds one test alone (the harness runs the
//! tests of one file as threads of one process).

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use common::drive::G;
use common::*;
use wick_fs_sys as sys;
use wick_fsd::host::unix::{HostDir, Options};
use wick_fsd::memdir::MemDir;

/// The process's open descriptors (`/dev/fd` lists them on Linux and macOS;
/// the listing's own is in every count).
fn descriptors() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

#[test]
fn test_forget_frees_an_unlinked_file() {
    // The model: the object goes with its last open.
    let mut g = G::new(MemDir::new());
    let before = g.s.dir().objects();
    let (n, fh) = g.create(ROOT, b"f");
    g.unlink(ROOT, b"f").unwrap();
    assert_eq!(g.s.dir().objects(), before + 1, "open, so kept");
    g.release(n, fh);
    g.forget(n, 1);
    assert_eq!(g.s.dir().objects(), before);

    // The host directory: the held descriptor closes when the node goes.
    let base = scratch("forget");
    let dir = HostDir::new(sys::open_root(&base).unwrap(), Options { case_insensitive_ok: true }).unwrap();
    let mut g = G::new(dir);
    let before = descriptors();
    let (n, fh) = g.create(ROOT, b"f");
    assert_eq!(g.write(n, fh, 0, &[7; 4096]), Ok(4096));
    g.unlink(ROOT, b"f").unwrap();
    g.release(n, fh);
    assert_eq!(descriptors(), before + 1, "the leaf keeps the file open while its node lives");
    assert_eq!(g.getattr(n, None).unwrap().nlink, 0);
    g.forget(n, 1);
    assert_eq!(descriptors(), before, "forgotten, the file is closed");
    // A file only looked up holds no descriptor.
    std::fs::write(base.join("g"), b"g").unwrap();
    let m = g.lookup(ROOT, b"g").unwrap();
    assert_eq!(descriptors(), before);
    g.forget(m, 1);
    remove(&base);
}
