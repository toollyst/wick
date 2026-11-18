// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md §4.3, held descriptors: nodes cost memory, and the
//! descriptors they hold are a cache of at most `max_held`, the least
//! recently used let go first. A guest walks many times more directories
//! (side by side, and one chain deep) and files than the cache holds, uses
//! each again after it was let go (opened again by its name beneath its
//! parent), and the process's descriptors are counted after every step:
//! never more than the cache and the handles open. The descriptors are the
//! process's, so this file holds one test alone (the harness runs the tests
//! of one file as threads of one process).

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use common::drive::G;
use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::{Errno, Opcode};
use wick_fsd::host::unix::{HostDir, Options};
use wick_fsd::session::Session;

/// The cache, the root's included.
const HELD: usize = 8;
const DIRS: usize = 48;
const DEPTH: usize = 24;

/// The process's open descriptors (`/dev/fd` lists them on Linux and macOS;
/// the listing's own is in every count).
fn descriptors() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

/// Beyond `before` (the root's held there): the cache but the root, and the
/// handles open.
fn within(g: &G<Session<HostDir>>, before: usize, step: &str) {
    let held = descriptors().saturating_sub(before);
    let bound = HELD - 1 + g.s.handles_open();
    assert!(held <= bound, "{step}: {held} descriptors held, more than the cache and the handles = {bound}");
}

fn releasedir(g: &mut G<Session<HostDir>>, d: u64, fh: u64) {
    let args = [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat();
    g.ok(Opcode::Releasedir, d, &[&args]);
}

#[test]
fn test_a_walk_beyond_the_cache_holds_at_most_the_cache() {
    let base = scratch("held");
    for i in 0..DIRS {
        std::fs::create_dir(base.join(format!("d{i}"))).unwrap();
    }
    let options = Options {
        case_insensitive_ok: true,
        max_held: HELD,
    };
    let mut g = G::new(HostDir::new(sys::open_root(&base).unwrap(), options).unwrap());
    let before = descriptors();

    // Side by side: every directory a node, each looked up once.
    let mut dirs = Vec::new();
    for i in 0..DIRS {
        dirs.push(g.lookup(ROOT, format!("d{i}").as_bytes()).unwrap());
        within(&g, before, "directories looked up");
    }
    // One chain, each made beneath the last.
    let mut chain = vec![ROOT];
    for i in 0..DEPTH {
        let parent = *chain.last().unwrap();
        chain.push(g.mkdir(parent, format!("c{i}").as_bytes()));
        within(&g, before, "a chain made");
    }
    let deepest = *chain.last().unwrap();

    // A file in each, written and released: every directory, let go long
    // since, opened again by its name.
    let mut files = Vec::new();
    for (i, &d) in dirs.iter().enumerate() {
        let (f, fh) = g.create(d, b"f");
        assert_eq!(g.write(f, fh, 0, format!("file {i}").as_bytes()), Ok(u32::try_from(format!("file {i}").len()).unwrap()));
        g.release(f, fh);
        files.push(f);
        within(&g, before, "files made");
    }
    assert!(g.s.nodes() > 10 * HELD, "{} nodes", g.s.nodes());

    // The deepest of the chain, its whole chain let go: found again from the
    // root down, one name at a time.
    for &d in dirs.iter().take(HELD) {
        g.getattr(d, None).unwrap();
    }
    g.getattr(deepest, None).unwrap();
    assert_eq!(g.lookup(deepest, b"missing"), Err(Errno::ENOENT));
    let (f, fh) = g.create(deepest, b"deep");
    g.release(f, fh);
    g.forget(f, 1);
    let mut path = base.clone();
    for i in 0..DEPTH {
        path.push(format!("c{i}"));
    }
    assert!(path.join("deep").is_file(), "made where the chain is");
    within(&g, before, "the chain's deepest used");

    // Every directory listed and every file read again, in another order.
    for (i, (&d, &f)) in dirs.iter().zip(&files).enumerate().rev() {
        let r = g.ok(Opcode::Opendir, d, &[&le32(0), &le32(0)]);
        releasedir(&mut g, d, u64_at(&r, 0));
        let fh = g.open(f, 0).unwrap();
        assert_eq!(g.read(f, fh, 0, 64).unwrap(), format!("file {i}").as_bytes());
        within(&g, before, "used again");
        g.release(f, fh);
    }

    // Handles beyond the cache are handles: each one open, the cache still
    // its size.
    let mut open = Vec::new();
    for &f in &files {
        open.push((f, g.open(f, 0).unwrap()));
        within(&g, before, "files left open");
    }
    for (f, fh) in open {
        g.release(f, fh);
    }

    // Everything forgotten: nothing stays open.
    for &f in &files {
        g.forget(f, 1);
    }
    for &d in dirs.iter().chain(&chain[1..]) {
        g.forget(d, 1);
    }
    assert_eq!(g.s.nodes(), 1);
    assert_eq!(descriptors(), before, "everything forgotten, everything closed");
    remove(&base);
}
