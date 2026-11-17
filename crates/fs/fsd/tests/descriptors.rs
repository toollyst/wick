// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md §4.3: the host directory holds at most one descriptor
//! per node (a directory's own, a leaf's widest open) and one per handle,
//! the bound stage 0 checks against the host's limit
//! (`limits::descriptors`). Counted after each step of a guest that tries
//! to hold more: directories looked up again and again, a leaf linked into
//! directories the guest then forgets (a leaf's names never keep a
//! directory open), every leaf open twice with different access, every
//! directory listed. The process's descriptors are counted, so this file
//! holds one test alone (the harness runs the tests of one file as threads
//! of one process).

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use common::drive::G;
use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::Opcode;
use wick_fsd::host::unix::{HostDir, Options, NAMES_MAX};

const DIRS: usize = 12;
const FILES: usize = 24;

/// The process's open descriptors (`/dev/fd` lists them on Linux and macOS;
/// the listing's own is in every count).
fn descriptors() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

/// The descriptors held beyond `before` (the root's included there) are at
/// most the session's nodes but the root, plus its handles.
fn within(g: &G<HostDir>, before: usize, step: &str) {
    let held = descriptors().saturating_sub(before);
    let bound = g.s.nodes() - 1 + g.s.handles_open();
    assert!(held <= bound, "{step}: {held} descriptors held, more than nodes + handles = {bound}");
}

#[test]
fn test_one_descriptor_per_node_and_handle() {
    let base = scratch("descriptors");
    for i in 0..DIRS {
        std::fs::create_dir(base.join(format!("d{i}"))).unwrap();
    }
    for j in 0..FILES {
        std::fs::write(base.join(format!("f{j}")), b"x").unwrap();
    }
    let dir = HostDir::new(sys::open_root(&base).unwrap(), Options { case_insensitive_ok: true }).unwrap();
    let mut g = G::new(dir);
    let before = descriptors();

    // A directory looked up again is the descriptor already held.
    let d0 = g.lookup(ROOT, b"d0").unwrap();
    let one = descriptors();
    for _ in 0..8 {
        assert_eq!(g.lookup(ROOT, b"d0").unwrap(), d0);
    }
    assert_eq!(descriptors(), one, "one descriptor per directory");
    g.forget(d0, 9);
    assert_eq!(descriptors(), before, "forgotten, the directory is closed");

    // Each leaf linked into NAMES_MAX directories, each forgotten after
    // the link: the leaf keeps the names, never the directories.
    let mut leaves = Vec::new();
    for j in 0..FILES {
        let f = g.lookup(ROOT, format!("f{j}").as_bytes()).unwrap();
        for i in 0..NAMES_MAX {
            let d = g.lookup(ROOT, format!("d{i}").as_bytes()).unwrap();
            assert_eq!(g.link(f, d, format!("l{j}").as_bytes()).unwrap(), f);
            g.forget(d, 1);
            within(&g, before, "links into forgotten directories");
        }
        leaves.push(f);
    }
    assert_eq!(g.s.nodes(), 1 + FILES);
    assert_eq!(descriptors(), before, "leaves only looked up and linked hold nothing");
    for &f in &leaves {
        assert_eq!(g.getattr(f, None).unwrap().nlink, 1 + u32::try_from(NAMES_MAX).unwrap());
    }

    // Each leaf opened read-write and released (its widest open kept), then
    // opened read-only and left open: two descriptors, one node and one
    // handle.
    let mut handles = Vec::new();
    for &f in &leaves {
        let fh = g.open(f, 2).unwrap();
        g.release(f, fh);
        handles.push((f, g.open(f, 0).unwrap()));
        within(&g, before, "leaves open");
    }
    assert_eq!(descriptors() - before, 2 * FILES);

    // Every directory a node and listed.
    let mut listed = Vec::new();
    for i in 0..DIRS {
        let d = g.lookup(ROOT, format!("d{i}").as_bytes()).unwrap();
        let r = g.ok(Opcode::Opendir, d, &[&le32(0), &le32(0)]);
        listed.push((d, u64_at(&r, 0)));
        within(&g, before, "directories listed");
    }

    // All of it given back: nothing stays open.
    for (d, fh) in listed {
        let args = [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat();
        g.ok(Opcode::Releasedir, d, &[&args]);
        g.forget(d, 1);
    }
    for (f, fh) in handles {
        g.release(f, fh);
        g.forget(f, 1 + u64::try_from(NAMES_MAX).unwrap());
    }
    assert_eq!(g.s.nodes(), 1);
    assert_eq!(descriptors(), before, "everything forgotten, everything closed");
    remove(&base);
}
