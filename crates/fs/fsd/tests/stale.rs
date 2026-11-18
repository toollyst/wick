// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md §4.3, held descriptors: a directory the cache let go is
//! opened again by its one name beneath its parent and checked to be the
//! same identity. Where the guest moved it, it is found there; where the
//! host moved, removed or replaced it (a link put in its place included,
//! never followed), it is ESTALE, the error Linux's FUSE gives for a node it
//! cannot find again, until a lookup finds it again. A cache of two (the
//! root and one more) lets every other directory go.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use common::drive::{G, RENAME_EXCHANGE};
use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::Errno;
use wick_fsd::host::unix::{HostDir, Options};
use wick_fsd::session::Session;

fn small(base: &Path) -> G<Session<HostDir>> {
    let options = Options {
        case_insensitive_ok: true,
        max_held: 2,
    };
    G::new(HostDir::new(sys::open_root(base).unwrap(), options).unwrap())
}

/// `a` and `b` beneath a fresh share, both looked up: `a` let go.
fn two(tag: &str) -> (PathBuf, G<Session<HostDir>>, u64, u64) {
    let base = scratch(tag);
    std::fs::create_dir(base.join("a")).unwrap();
    std::fs::create_dir(base.join("b")).unwrap();
    let mut g = small(&base);
    let a = g.lookup(ROOT, b"a").unwrap();
    let b = g.lookup(ROOT, b"b").unwrap();
    (base, g, a, b)
}

/// Makes the file `n` in directory node `d`, its node forgotten.
fn made_in(g: &mut G<Session<HostDir>>, d: u64, n: &[u8]) {
    let (f, fh) = g.create(d, n);
    g.release(f, fh);
    g.forget(f, 1);
}

#[test]
fn test_a_directory_the_guest_moved_is_found_where_it_went() {
    let (base, mut g, a, b) = two("stale-guest-move");
    // Moved while let go: its node follows the rename.
    g.rename((ROOT, b"a"), (b, b"a2"), 0).unwrap();
    g.getattr(b, None).unwrap();
    g.getattr(a, None).unwrap();
    made_in(&mut g, a, b"x");
    assert!(base.join("b/a2/x").is_file());
    // Let go again and exchanged with its parent's sibling.
    std::fs::create_dir(base.join("c")).unwrap();
    let c = g.lookup(ROOT, b"c").unwrap();
    match g.rename((b, b"a2"), (ROOT, b"c"), RENAME_EXCHANGE) {
        Ok(()) => {
            g.getattr(b, None).unwrap();
            made_in(&mut g, a, b"y");
            made_in(&mut g, c, b"z");
            assert!(base.join("c/x").is_file() && base.join("c/y").is_file(), "a is at c now");
            assert!(base.join("b/a2/z").is_file(), "c is at b/a2 now");
        }
        // A volume without an exchange (docs/design-fs.md §4.3).
        Err(e) => assert_eq!(e, Errno::EINVAL),
    }
    remove(&base);
}

#[test]
fn test_a_directory_the_host_moved_is_estale_until_looked_up() {
    let (base, mut g, a, b) = two("stale-host-move");
    std::fs::rename(base.join("a"), base.join("a2")).unwrap();
    assert_eq!(g.getattr(a, None).map(drop), Err(Errno::ESTALE));
    assert_eq!(g.lookup(a, b"x"), Err(Errno::ESTALE));
    // A lookup finds it again: the same node, at its new place.
    assert_eq!(g.lookup(ROOT, b"a2").unwrap(), a);
    g.getattr(b, None).unwrap();
    made_in(&mut g, a, b"x");
    assert!(base.join("a2/x").is_file());
    remove(&base);
}

#[test]
fn test_a_held_directory_the_host_moved_is_served() {
    // Not let go (a cache with room: here even the new file's descriptor
    // would push it out of `small`'s): its descriptor follows it, as before.
    let base = scratch("stale-held");
    std::fs::create_dir(base.join("a")).unwrap();
    let options = Options {
        case_insensitive_ok: true,
        ..Options::default()
    };
    let mut g = G::new(HostDir::new(sys::open_root(&base).unwrap(), options).unwrap());
    let a = g.lookup(ROOT, b"a").unwrap();
    std::fs::rename(base.join("a"), base.join("a2")).unwrap();
    made_in(&mut g, a, b"x");
    assert!(base.join("a2/x").is_file());
    remove(&base);
}

#[test]
fn test_a_directory_the_host_removed_or_replaced_is_estale() {
    let (base, mut g, a, b) = two("stale-host-remove");
    std::fs::create_dir(base.join("b/q")).unwrap();
    let q = g.lookup(b, b"q").unwrap();
    // Removed, then another directory of the same name: not the same one,
    // unless the host gave it the same inode number (ext4 reuses a freed
    // one; APFS does not): an identity is (st_dev, st_ino), as a leaf's.
    let old = std::fs::metadata(base.join("a")).unwrap().ino();
    std::fs::remove_dir(base.join("a")).unwrap();
    assert_eq!(g.getattr(a, None).map(drop), Err(Errno::ESTALE));
    std::fs::create_dir(base.join("a")).unwrap();
    let reused = std::fs::metadata(base.join("a")).unwrap().ino() == old;
    g.getattr(q, None).unwrap();
    let want = if reused { Ok(()) } else { Err(Errno::ESTALE) };
    assert_eq!(g.getattr(a, None).map(drop), want, "inode number reused: {reused}");
    // A child whose parent the host moved: its parent is not found again.
    std::fs::rename(base.join("b"), base.join("b2")).unwrap();
    g.lookup(ROOT, b"a").unwrap();
    assert_eq!(g.getattr(q, None).map(drop), Err(Errno::ESTALE));
    assert_eq!(g.lookup(ROOT, b"b2").unwrap(), b);
    g.getattr(q, None).unwrap();
    remove(&base);
}

#[test]
fn test_a_link_put_in_a_directory_s_place_is_never_followed() {
    let (base, mut g, a, _b) = two("stale-host-link");
    let outside = scratch("stale-host-link-outside");
    std::fs::write(outside.join("canary"), b"canary").unwrap();
    std::fs::remove_dir(base.join("a")).unwrap();
    std::os::unix::fs::symlink(&outside, base.join("a")).unwrap();
    // Not the directory: ESTALE on both hosts, the link never followed.
    assert_eq!(g.getattr(a, None).map(drop), Err(Errno::ESTALE));
    assert_eq!(g.lookup(a, b"canary"), Err(Errno::ESTALE));
    let (e, _) = g.call(wick_fsd::fuse::Opcode::Mkdir, a, &[&le32(0o755), &le32(0), &name(b"made")]);
    assert_eq!(errno(e), Errno::ESTALE);
    assert_eq!(std::fs::read(outside.join("canary")).unwrap(), b"canary");
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1, "nothing made outside");
    remove(&base);
    remove(&outside);
}

#[test]
fn test_an_unlinked_file_open_while_the_cache_lets_go_is_served() {
    // The guest's own unlink never makes a live object ENOENT: its handle
    // keeps the descriptor the leaf shares, through any number of
    // directories passing through the cache.
    let (base, mut g, _a, _b) = two("stale-unlinked");
    let (f, fh) = g.create(ROOT, b"f");
    assert_eq!(g.write(f, fh, 0, b"kept"), Ok(4));
    g.unlink(ROOT, b"f").unwrap();
    for i in 0..8 {
        let d = g.mkdir(ROOT, format!("m{i}").as_bytes());
        g.getattr(d, None).unwrap();
        g.forget(d, 1);
    }
    assert_eq!(g.getattr(f, None).unwrap().nlink, 0);
    let again = g.open(f, 0).unwrap();
    assert_eq!(g.read(f, again, 0, 4).unwrap(), b"kept");
    g.release(f, again);
    g.release(f, fh);
    // Closed, the descriptor is the cache's again: still served until the
    // cache lets it go, as any node's.
    assert_eq!(g.getattr(f, None).unwrap().nlink, 0);
    g.forget(f, 1);
    remove(&base);
}

/// A chain deeper than the cache, every ancestor let go, walked again from
/// the root, in a process of its own (the descriptors and their limit are
/// the process's, and this file's other tests run as threads of one), which
/// starts with its standard streams alone whatever its launcher left open
/// (a CI runner leaves descriptors far above them in its steps): the
/// soft `RLIMIT_NOFILE` is set to the descriptors open, the cache full, and
/// one more, so a walk that kept a second descriptor beyond the cache would
/// meet EMFILE; then one more for CREATE's handle. The bound is
/// docs/design-fs.md §4.3's, inside `SPARE_FDS` and so inside
/// `limits::descriptors`.
#[test]
fn test_a_chain_deeper_than_the_cache_is_walked_within_one_spare_descriptor() {
    const ALONE: &str = "WICK_FS_TEST_STALE_ALONE";
    const NAME: &str = "test_a_chain_deeper_than_the_cache_is_walked_within_one_spare_descriptor";
    if std::env::var_os(ALONE).is_none() {
        let mut alone = std::process::Command::new(std::env::current_exe().unwrap());
        alone.args([NAME, "--exact", "--test-threads=1", "--nocapture"]).env(ALONE, "1");
        let out = sys::launch::output(&alone, sys::launch::Descriptors { only_stdio: true, ..Default::default() }).unwrap();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success() && text.contains("1 passed"), "the walk in a process of its own: {:?}:\n{text}", out.status);
        return;
    }
    const DEPTH: usize = 8;
    let base = scratch("stale-deep");
    let mut path = base.clone();
    for i in 0..DEPTH {
        path.push(format!("c{i}"));
        std::fs::create_dir(&path).unwrap();
    }
    std::fs::create_dir(base.join("other")).unwrap();
    let mut g = small(&base);
    let mut d = ROOT;
    for i in 0..DEPTH {
        d = g.lookup(d, format!("c{i}").as_bytes()).unwrap();
    }
    // The cache (the root and one more) holds `other` now: the chain, all of
    // it, let go.
    g.lookup(ROOT, b"other").unwrap();

    // The lowest free descriptor is the next one opened; none is open above
    // it (the listing's own is it), so the limit counts descriptors.
    let next = std::fs::File::open("/dev/null").map(|f| std::os::fd::AsRawFd::as_raw_fd(&f)).unwrap();
    let open: Vec<i32> = std::fs::read_dir("/dev/fd").unwrap().map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap()).collect();
    let above: Vec<String> = open.iter().filter(|&&fd| fd > next).map(|&fd| sys::descriptor_described(fd)).collect();
    assert!(above.is_empty(), "descriptors open above the lowest free one {next} (of {open:?}): {above:?}");
    let next = u64::try_from(next).unwrap();
    let (soft, _) = sys::nofile().unwrap();
    let limits = wick_fsd::limits::Limits {
        max_held: 2,
        ..wick_fsd::limits::Limits::default()
    };
    assert!(2 <= wick_fsd::limits::SPARE_FDS && 2 <= wick_fsd::limits::descriptors(&limits));

    // The walk: one descriptor beyond the cache at most.
    sys::set_nofile(next + 1).unwrap();
    let walked = g.getattr(d, None).map(drop);
    let missing = g.lookup(d, b"missing");
    // CREATE: its handle's descriptor too.
    sys::set_nofile(next + 2).unwrap();
    let created = g.call(wick_fsd::fuse::Opcode::Create, d, &[&[&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat(), &name(b"deep")]);
    sys::set_nofile(soft).unwrap();
    assert_eq!(walked, Ok(()), "the chain walked again within the cache and one");
    assert_eq!(missing, Err(Errno::ENOENT));
    assert_eq!(created.0, 0, "CREATE within the cache, one and its handle");
    assert!(path.join("deep").is_file(), "made where the chain is");
    // After: the cache and the handle, nothing of the walk left.
    let after = std::fs::read_dir("/dev/fd").unwrap().count();
    assert!(after <= open.len() + 1, "{after} descriptors after, {} before the walk", open.len());
    remove(&base);
}
