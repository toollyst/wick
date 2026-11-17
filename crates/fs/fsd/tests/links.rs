// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md §4.3, the leaf model: the guest's own links, renames
//! and unlinks never lose a live object. Each sequence runs over `MemDir`
//! (the model, where a node is the object) and over the host directory,
//! where a node is reached by the names it is known by: a link's other name
//! after an unlink, a node first reached by one name and used by another,
//! one of two links renamed or exchanged, more links than a leaf keeps
//! names for (the held directories are searched), an open file renamed and
//! its directory renamed while it is open.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use common::drive::{FATTR_MODE, FATTR_SIZE, G, RENAME_EXCHANGE};
use common::*;
use wick_fs_sys as sys;
use wick_fsd::dir::ConfinedDir;
use wick_fsd::fuse::Errno;
use wick_fsd::host::unix::{HostDir, Options};
use wick_fsd::memdir::MemDir;

/// A session over a fresh host directory, removed when dropped.
struct Host {
    g: G<HostDir>,
    base: std::path::PathBuf,
}

impl Drop for Host {
    fn drop(&mut self) {
        remove(&self.base);
    }
}

fn host(tag: &str) -> Host {
    let base = scratch(tag);
    let dir = HostDir::new(sys::open_root(&base).unwrap(), Options { case_insensitive_ok: true }).unwrap();
    Host { g: G::new(dir), base }
}

/// Runs a sequence over `MemDir` and over the host directory.
macro_rules! both {
    ($name:ident) => {
        mod $name {
            #[test]
            fn memdir() {
                super::$name(&mut super::G::new(super::MemDir::new()));
            }

            #[test]
            fn host() {
                let mut h = super::host(concat!("links-", stringify!($name)));
                super::$name(&mut h.g);
            }
        }
    };
}

fn nlink<D: ConfinedDir>(g: &mut G<D>, n: u64) -> u32 {
    g.getattr(n, None).unwrap_or_else(|e| panic!("getattr of node {n}: {e:?}")).nlink
}

/// LINK a→b, UNLINK a: the node lives on as b, by its id and by the name.
fn link_then_unlink<D: ConfinedDir>(g: &mut G<D>) {
    let (n, fh) = g.create(ROOT, b"a");
    assert_eq!(g.write(n, fh, 0, b"data"), Ok(4));
    g.release(n, fh);
    assert_eq!(g.link(n, ROOT, b"b"), Ok(n), "one object, one node");
    assert_eq!(nlink(g, n), 2);
    g.unlink(ROOT, b"a").unwrap();
    let a = g.getattr(n, None).unwrap();
    assert_eq!((a.nlink, a.size), (1, 4));
    g.rewrite(n, b"DATA");
    let a = g.setattr(n, FATTR_MODE, 0, 0o640, None).unwrap();
    assert_eq!(a.mode & 0o777, 0o640);
    assert_eq!(g.setattr(n, FATTR_SIZE, 2, 0, None).unwrap().size, 2);
    assert_eq!(g.lookup(ROOT, b"b"), Ok(n));
    assert_eq!(g.lookup(ROOT, b"a"), Err(Errno::ENOENT));
    // Into another directory, the original name removed.
    let d = g.mkdir(ROOT, b"d");
    assert_eq!(g.link(n, d, b"c"), Ok(n));
    g.unlink(ROOT, b"b").unwrap();
    g.rewrite(n, b"in d");
    assert_eq!(nlink(g, n), 1);
    assert_eq!(g.lookup(d, b"c"), Ok(n));
    // The new name removed, the original kept.
    let (m, fh) = g.create(ROOT, b"e");
    g.release(m, fh);
    assert_eq!(g.link(m, ROOT, b"f"), Ok(m));
    g.unlink(ROOT, b"f").unwrap();
    g.rewrite(m, b"e");
    assert_eq!(nlink(g, m), 1);
}
both!(link_then_unlink);

/// A node first reached by b, then by a, then each of the names removed in
/// turn.
fn first_reached_by_another_name<D: ConfinedDir>(g: &mut G<D>) {
    let (n, fh) = g.create(ROOT, b"a");
    g.release(n, fh);
    assert_eq!(g.link(n, ROOT, b"b"), Ok(n));
    // CREATE and LINK each counted a lookup: the node is gone after this.
    g.forget(n, 2);
    assert_eq!(g.s.node_counts(n), None);
    let m = g.lookup(ROOT, b"b").unwrap();
    assert_eq!(g.lookup(ROOT, b"a"), Ok(m));
    g.unlink(ROOT, b"b").unwrap();
    g.rewrite(m, b"through a");
    assert_eq!(nlink(g, m), 1);
    g.rename((ROOT, b"a"), (ROOT, b"c"), 0).unwrap();
    g.rewrite(m, b"through c");
    assert_eq!(g.lookup(ROOT, b"c"), Ok(m));
    // The name looked up last is the one removed.
    assert_eq!(g.link(m, ROOT, b"e"), Ok(m));
    assert_eq!(g.lookup(ROOT, b"c"), Ok(m));
    g.unlink(ROOT, b"c").unwrap();
    g.rewrite(m, b"through e");
    assert_eq!(g.lookup(ROOT, b"e"), Ok(m));
}
both!(first_reached_by_another_name);

/// One of two links renamed (into another directory), the other removed;
/// then a link exchanged with another file, where the backend exchanges.
fn rename_one_of_two_links<D: ConfinedDir>(g: &mut G<D>) {
    let d = g.mkdir(ROOT, b"d");
    let (n, fh) = g.create(ROOT, b"a");
    g.release(n, fh);
    assert_eq!(g.link(n, ROOT, b"b"), Ok(n));
    g.rename((ROOT, b"a"), (d, b"c"), 0).unwrap();
    g.rewrite(n, b"2");
    assert_eq!(nlink(g, n), 2);
    g.unlink(ROOT, b"b").unwrap();
    g.rewrite(n, b"3");
    assert_eq!(nlink(g, n), 1);
    assert_eq!(g.lookup(d, b"c"), Ok(n));
    // A rename onto the node's other name: nothing changes.
    assert_eq!(g.link(n, ROOT, b"b"), Ok(n));
    g.rename((ROOT, b"b"), (d, b"c"), 0).unwrap();
    g.rewrite(n, b"4");
    g.unlink(ROOT, b"b").unwrap();
    g.rewrite(n, b"5");
    // Exchanged: n's second name now names x, and x's name names n.
    let (x, fh) = g.create(ROOT, b"x");
    g.release(x, fh);
    assert_eq!(g.link(n, ROOT, b"b2"), Ok(n));
    match g.rename((ROOT, b"b2"), (ROOT, b"x"), RENAME_EXCHANGE) {
        Ok(()) => {
            g.unlink(d, b"c").unwrap();
            g.rewrite(n, b"n as x");
            g.rewrite(x, b"x as b2");
            assert_eq!(g.lookup(ROOT, b"x"), Ok(n));
            assert_eq!(g.lookup(ROOT, b"b2"), Ok(x));
        }
        Err(e) => assert_eq!(e, Errno::EINVAL, "an exchange is done or EINVAL"),
    }
    // Renamed over: the replaced object's node is ENOENT, the mover lives.
    let (y, fh) = g.create(ROOT, b"y");
    g.release(y, fh);
    let (z, fh) = g.create(ROOT, b"z");
    g.release(z, fh);
    g.rename((ROOT, b"z"), (ROOT, b"y"), 0).unwrap();
    g.rewrite(z, b"z as y");
    // y's node: no name; ENOENT, or (a backend that kept its open, as
    // virtiofsd keeps an O_PATH descriptor) nlink 0.
    match g.getattr(y, None) {
        Err(e) => assert_eq!(e, Errno::ENOENT),
        Ok(a) => assert_eq!(a.nlink, 0),
    }
    assert_eq!(g.lookup(ROOT, b"y"), Ok(z));
}
both!(rename_one_of_two_links);

/// More links than a leaf keeps names for, the newest removed first: the
/// one left is found in the held directories, with and without an open
/// descriptor of the file.
fn names_beyond_what_a_node_keeps<D: ConfinedDir>(g: &mut G<D>) {
    let d = g.mkdir(ROOT, b"d");
    let (n, fh) = g.create(ROOT, b"a");
    g.release(n, fh);
    let links: u32 = 20;
    for i in 0..links {
        let dir = if i % 2 == 0 { ROOT } else { d };
        assert_eq!(g.link(n, dir, format!("l{i}").as_bytes()), Ok(n));
    }
    for i in (0..links).rev() {
        let dir = if i % 2 == 0 { ROOT } else { d };
        g.unlink(dir, format!("l{i}").as_bytes()).unwrap();
    }
    assert_eq!(nlink(g, n), 1);
    g.rewrite(n, b"found");
    assert_eq!(g.lookup(ROOT, b"a"), Ok(n));
    // Never opened since it was looked up: no descriptor to fall back on.
    g.forget(n, 1 + u64::from(links) + 1);
    assert_eq!(g.s.node_counts(n), None);
    assert_eq!(g.lookup(d, b"l1"), Err(Errno::ENOENT));
    let m = g.lookup(ROOT, b"a").unwrap();
    for i in 0..links {
        assert_eq!(g.link(m, d, format!("k{i}").as_bytes()), Ok(m));
    }
    for i in (0..links).rev() {
        g.unlink(d, format!("k{i}").as_bytes()).unwrap();
    }
    assert_eq!(nlink(g, m), 1);
    g.rewrite(m, b"found again");
}
both!(names_beyond_what_a_node_keeps);

/// An open file renamed by the guest, then its directory renamed and the
/// file moved out of it: the handle keeps working and the node follows.
fn open_file_renamed<D: ConfinedDir>(g: &mut G<D>) {
    let d = g.mkdir(ROOT, b"d");
    let (n, fh) = g.create(d, b"f");
    assert_eq!(g.write(n, fh, 0, b"one"), Ok(3));
    g.rename((d, b"f"), (d, b"g"), 0).unwrap();
    assert_eq!(g.write(n, fh, 3, b"two"), Ok(3));
    assert_eq!(g.getattr(n, Some(fh)).unwrap().size, 6);
    assert_eq!(g.getattr(n, None).unwrap().size, 6);
    g.setattr(n, FATTR_MODE, 0, 0o600, None).unwrap();
    g.rewrite(n, b"ONE");
    // The directory renamed, the file open beneath it.
    g.rename((ROOT, b"d"), (ROOT, b"e"), 0).unwrap();
    assert_eq!(g.write(n, fh, 6, b"!"), Ok(1));
    assert_eq!(g.getattr(n, None).unwrap().size, 7);
    g.rewrite(n, b"o");
    assert_eq!(g.read(n, fh, 0, 16).unwrap(), b"oNEtwo!");
    // Moved out of it.
    g.rename((d, b"g"), (ROOT, b"h"), 0).unwrap();
    g.rewrite(n, b"moved");
    assert_eq!(g.lookup(ROOT, b"h"), Ok(n));
    assert_eq!(g.read(n, fh, 0, 16).unwrap(), b"movedo!");
    g.release(n, fh);
}
both!(open_file_renamed);

/// An open file unlinked: I/O through the handles, GETATTR and SETATTR with
/// and without a handle (nlink 0), a new OPEN of the node, no LINK back.
fn unlinked_but_open<D: ConfinedDir>(g: &mut G<D>) {
    let (n, fh) = g.create(ROOT, b"f");
    assert_eq!(g.write(n, fh, 0, b"hello"), Ok(5));
    let ro = g.open(n, 0).unwrap();
    g.unlink(ROOT, b"f").unwrap();
    assert_eq!(g.lookup(ROOT, b"f"), Err(Errno::ENOENT));
    assert_eq!(g.read(n, fh, 0, 16).unwrap(), b"hello");
    assert_eq!(g.write(n, fh, 5, b" world"), Ok(6));
    g.fsync(n, fh).unwrap();
    g.fallocate(n, fh, 0, 8192).unwrap();
    let a = g.getattr(n, Some(fh)).unwrap();
    assert_eq!((a.nlink, a.size), (0, 8192));
    // Without the handle flag, as virtiofsd answers through its O_PATH
    // descriptor: the same.
    let a = g.getattr(n, None).unwrap();
    assert_eq!((a.nlink, a.size), (0, 8192));
    assert_eq!(g.setattr(n, FATTR_SIZE, 3, 0, Some(fh)).unwrap().size, 3);
    assert_eq!(g.setattr(n, FATTR_MODE, 0, 0o604, None).unwrap().mode & 0o777, 0o604);
    assert_eq!(g.read(n, ro, 0, 16).unwrap(), b"hel");
    let again = g.open(n, 0).unwrap();
    assert_eq!(g.read(n, again, 0, 16).unwrap(), b"hel");
    g.release(n, again);
    // Linux's link(2) of an unlinked file: ENOENT.
    assert_eq!(g.link(n, ROOT, b"back"), Err(Errno::ENOENT));
    g.release(n, fh);
    g.release(n, ro);
    g.forget(n, 1);
    assert_eq!(g.s.node_counts(n), None);
}
both!(unlinked_but_open);
