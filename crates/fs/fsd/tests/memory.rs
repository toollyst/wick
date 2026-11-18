// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md §4.2, Limits: a node costs the server memory, at most
//! `NODE_BYTES_MAX`, whatever the guest does. The bound holds by
//! construction (a leaf keeps at most `NAMES_MAX` names, a name is at most
//! `NAME_MAX` bytes, a directory one name in its parent), which
//! `HostDir::footprint` counts after a guest links and looks up more names
//! than a leaf keeps; and the process's resident memory, read from the
//! host, grows by at most `NODE_BYTES_MAX` per node when every node is the
//! worst case (`NAMES_MAX` names of `NAME_MAX` bytes). With
//! `--nocapture` it prints the bytes per node, worst and typical (one
//! short name), for design-fs. Resident memory is the process's, so this
//! file holds one test alone (the harness runs the tests of one file as
//! threads of one process).

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::path::Path;

use common::drive::G;
use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::name::NAME_MAX;
use wick_fsd::host::unix::{HostDir, NAMES_MAX, NODE_BYTES_MAX, Options};
use wick_fsd::session::Session;

/// Nodes measured: enough that the tables' growth and the page size are
/// lost in the total.
const NODES: usize = 4096;
/// Nodes measured for the typical case (smaller each, so more of them).
const TYPICAL: usize = 16384;

/// The process's resident bytes, as the host counts them.
fn resident() -> usize {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
        let pages: usize = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
        let page = std::process::Command::new("getconf").arg("PAGESIZE").output().unwrap();
        let page: usize = String::from_utf8(page.stdout).unwrap().trim().parse().unwrap();
        pages * page
    }
    #[cfg(target_os = "macos")]
    {
        let ps = std::process::Command::new("/bin/ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        let kib: usize = String::from_utf8(ps.stdout).unwrap().trim().parse().unwrap();
        kib * 1024
    }
}

/// A name of `NAME_MAX` bytes for `i`.
fn long(i: usize) -> Vec<u8> {
    let mut n = format!("{i:08}").into_bytes();
    n.resize(NAME_MAX, b'n');
    n
}

fn session(base: &Path) -> G<Session<HostDir>> {
    let options = Options {
        case_insensitive_ok: true,
        ..Options::default()
    };
    G::new(HostDir::new(sys::open_root(base).unwrap(), options).unwrap())
}

#[test]
fn test_a_node_costs_at_most_node_bytes_max() {
    let base = scratch("memory");
    // NAMES_MAX + 2 directories, each with a link of every file under the
    // same long name; the files themselves in `f`.
    let dirs: Vec<String> = (0..NAMES_MAX + 2).map(|k| format!("l{k}")).collect();
    std::fs::create_dir(base.join("f")).unwrap();
    std::fs::create_dir(base.join("short")).unwrap();
    for d in &dirs {
        std::fs::create_dir(base.join(d)).unwrap();
    }
    for i in 0..NODES {
        let n = String::from_utf8(long(i)).unwrap();
        std::fs::write(base.join("f").join(&n), b"").unwrap();
        for d in &dirs {
            std::fs::hard_link(base.join("f").join(&n), base.join(d).join(&n)).unwrap();
        }
    }
    for i in 0..TYPICAL {
        std::fs::write(base.join("short").join(format!("s{i}")), b"").unwrap();
    }

    // Typical first, one short name each; its session kept, so the worst
    // case's memory is never what this one gave back.
    let mut typical_g = session(&base);
    let short = typical_g.lookup(ROOT, b"short").unwrap();
    let before = resident();
    for i in 0..TYPICAL {
        typical_g.lookup(short, format!("s{i}").as_bytes()).unwrap();
    }
    let typical = resident().saturating_sub(before) / TYPICAL;
    eprintln!("memory: typical {typical} bytes per node ({TYPICAL} leaves, one short name)");
    assert!(typical <= NODE_BYTES_MAX, "{typical} bytes per node");

    // Worst case: every leaf looked up by more long names than it keeps.
    let mut g = session(&base);
    let parents: Vec<u64> = dirs.iter().map(|d| g.lookup(ROOT, d.as_bytes()).unwrap()).collect();
    let before = resident();
    for i in 0..NODES {
        let n = long(i);
        let leaf = g.lookup(parents[0], &n).unwrap();
        for &p in &parents[1..] {
            assert_eq!(g.lookup(p, &n).unwrap(), leaf);
        }
    }
    let worst = resident().saturating_sub(before) / NODES;
    let f = g.s.dir().footprint();
    assert_eq!(f.leaves, NODES);
    assert_eq!(f.names, NODES * NAMES_MAX, "each leaf keeps NAMES_MAX names, never more");
    assert!(f.name_bytes <= (f.names + f.dirs) * NAME_MAX, "{f:?}");
    eprintln!("memory: worst case {worst} bytes per node ({NODES} leaves, {NAMES_MAX} names of {NAME_MAX} bytes)");
    assert!(worst <= NODE_BYTES_MAX, "{worst} bytes per node, more than NODE_BYTES_MAX = {NODE_BYTES_MAX}");
    drop((g, typical_g));
    remove(&base);
}
