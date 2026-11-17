// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md rows 3 and 15, §7 Case: a name the host stores in
//! another form (case, Unicode normalization) is not the guest's name. A
//! lookup by the other form is ENOENT, a create or rename onto it EEXIST.
//! macOS: disk images (no root needed); APFS folds normalization even on a
//! case-sensitive volume. Linux: a casefold ext4 directory, made by the
//! Docker run as root and named by `WICK_FS_TEST_CASEFOLD_DIR`.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::path::Path;

use common::*;
use wick_fsd::fuse::{Errno, Opcode};
use wick_fsd::host::unix::Options;
use wick_fsd::session::{Config, Session};
use wick_fsd::host::unix::HostDir;

fn lookup(s: &mut Session<HostDir>, n: &[u8]) -> Result<u64, Errno> {
    let (e, b) = call(s, Opcode::Lookup, ROOT, &[&name(n)]);
    if e < 0 {
        return Err(errno(e));
    }
    match u64_at(&b, 0) {
        0 => Err(Errno::ENOENT),
        id => Ok(id),
    }
}

fn create(s: &mut Session<HostDir>, n: &[u8]) -> Result<(), Errno> {
    let args = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
    let (e, _) = call(s, Opcode::Create, ROOT, &[&args, &name(n)]);
    if e < 0 { Err(errno(e)) } else { Ok(()) }
}

fn rename(s: &mut Session<HostDir>, from: (u64, &[u8]), to: (u64, &[u8]), flags: u32) -> Result<(), Errno> {
    let args = [&le64(to.0)[..], &le32(flags), &le32(0)].concat();
    let (e, _) = call(s, Opcode::Rename2, from.0, &[&args, &name(from.1), &name(to.1)]);
    if e < 0 { Err(errno(e)) } else { Ok(()) }
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// On a volume that folds case: one stored name, the other forms refused;
/// an object renamed to its own other case is stored under the new one
/// (docs/design-fs.md §4.3, Rename), with or without `RENAME_NOREPLACE`,
/// and keeps its node and its other links; a name that folds onto another
/// link of the same object is EEXIST, as onto another object.
fn case_collisions(dir: &Path) {
    std::fs::write(dir.join("Foo"), b"f").unwrap();
    std::fs::write(dir.join("x"), b"").unwrap();
    let mut s = session_over(dir, Options { case_insensitive_ok: true }, Config::default()).unwrap();
    let node = lookup(&mut s, b"Foo").unwrap();
    assert_eq!(lookup(&mut s, b"foo"), Err(Errno::ENOENT));
    assert_eq!(lookup(&mut s, b"FOO"), Err(Errno::ENOENT));
    assert_eq!(create(&mut s, b"foo"), Err(Errno::EEXIST));
    let (e, _) = call(&mut s, Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name(b"FOO")]);
    assert_eq!(errno(e), Errno::EEXIST);
    let (e, _) = call(&mut s, Opcode::Rename, ROOT, &[&le64(ROOT), &name(b"x"), &name(b"foo")]);
    assert_eq!(errno(e), Errno::EEXIST, "a rename onto another object's case variant");
    let (e, _) = call(&mut s, Opcode::Unlink, ROOT, &[&name(b"foo")]);
    assert_eq!(errno(e), Errno::ENOENT);
    // An object renamed to its own other case: the host stores the new one,
    // and the object keeps its node.
    let (e, _) = call(&mut s, Opcode::Rename, ROOT, &[&le64(ROOT), &name(b"Foo"), &name(b"foo")]);
    assert_eq!(e, 0);
    assert_eq!(names(dir), ["foo", "x"]);
    assert_eq!(lookup(&mut s, b"foo"), Ok(node));
    assert_eq!(lookup(&mut s, b"Foo"), Err(Errno::ENOENT));
    // RENAME_NOREPLACE: the new case is no name the guest has.
    rename(&mut s, (ROOT, b"foo"), (ROOT, b"FOO"), 1).unwrap();
    assert_eq!(names(dir), ["FOO", "x"]);
    // RENAME_EXCHANGE: the other case is not there to exchange with.
    assert_eq!(rename(&mut s, (ROOT, b"FOO"), (ROOT, b"Foo"), 2), Err(Errno::ENOENT));
    assert_eq!(names(dir), ["FOO", "x"]);
    // Another link of the object, in another directory: untouched by a
    // rename to another case, and a name there that folds onto it is EEXIST.
    std::fs::create_dir(dir.join("d2")).unwrap();
    std::fs::hard_link(dir.join("FOO"), dir.join("d2/other")).unwrap();
    let d2 = lookup(&mut s, b"d2").unwrap();
    rename(&mut s, (ROOT, b"FOO"), (ROOT, b"fOO"), 0).unwrap();
    assert_eq!(names(dir), ["d2", "fOO", "x"]);
    assert_eq!(names(&dir.join("d2")), ["other"]);
    assert_eq!(std::fs::read(dir.join("d2/other")).unwrap(), b"f");
    assert_eq!(rename(&mut s, (d2, b"other"), (ROOT, b"foo"), 0), Err(Errno::EEXIST), "onto another link's case");
    // Another link in the same directory: a name that folds onto it is
    // EEXIST, and both names stay.
    std::fs::hard_link(dir.join("fOO"), dir.join("Zed")).unwrap();
    assert_eq!(rename(&mut s, (ROOT, b"Zed"), (ROOT, b"foo"), 0), Err(Errno::EEXIST), "onto another link's case");
    assert_eq!(names(dir), ["Zed", "d2", "fOO", "x"]);
    // A link stored exactly: two names of one object, nothing done (POSIX).
    rename(&mut s, (ROOT, b"Zed"), (ROOT, b"fOO"), 0).unwrap();
    assert_eq!(names(dir), ["Zed", "d2", "fOO", "x"]);
    // A directory to its own other case.
    rename(&mut s, (ROOT, b"d2"), (ROOT, b"D2"), 0).unwrap();
    assert_eq!(names(dir), ["D2", "Zed", "fOO", "x"]);
    assert_eq!(names(&dir.join("D2")), ["other"]);
    // Another object's name, as before, and the unrelated object untouched.
    assert_eq!(rename(&mut s, (ROOT, b"x"), (ROOT, b"zed"), 0), Err(Errno::EEXIST));
    assert_eq!(names(dir), ["D2", "Zed", "fOO", "x"]);
    assert_eq!(s.counters().layer_refusals, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn test_case_collision_is_eexist() {
    let img = Image::new("alias-ci", "APFS");
    let dir = img.mount.join("d");
    std::fs::create_dir(&dir).unwrap();
    case_collisions(&dir);
}

#[cfg(target_os = "macos")]
#[test]
fn test_case_insensitive_root_refused() {
    let img = Image::new("alias-ci-root", "APFS");
    let dir = img.mount.join("d");
    std::fs::create_dir(&dir).unwrap();
    let root = wick_fs_sys::open_root(&dir).unwrap();
    let e = HostDir::new(root, Options::default()).unwrap_err();
    assert!(e.0.contains("case-insensitive"), "{}", e.0);
}

#[cfg(target_os = "macos")]
#[test]
fn test_alias_names_refused() {
    let img = Image::new("alias-cs", "Case-sensitive APFS");
    let dir = img.mount.join("d");
    std::fs::create_dir(&dir).unwrap();
    // NFD é, as macOS tools often write it.
    std::fs::write(dir.join("e\u{301}"), b"").unwrap();
    let mut s = session_over(&dir, Options::default(), Config::default()).unwrap();
    lookup(&mut s, "e\u{301}".as_bytes()).unwrap();
    assert_eq!(lookup(&mut s, "\u{e9}".as_bytes()), Err(Errno::ENOENT), "NFC is not the stored NFD name");
    assert_eq!(create(&mut s, "\u{e9}".as_bytes()), Err(Errno::EEXIST));
    // Case-sensitive: two names, two files.
    create(&mut s, b"A").unwrap();
    create(&mut s, b"a").unwrap();
    assert_eq!(names(&dir), ["A", "a", "e\u{301}"]);
    // The firmlink and /.vol forms are paths, never names: layer 1 refuses
    // `/` in a name, and every open is relative to a held directory.
    assert_eq!(lookup(&mut s, b"/.vol"), Err(Errno::EINVAL));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a casefold directory: WICK_FS_TEST_CASEFOLD_DIR"]
fn test_case_collision_is_eexist() {
    let dir = std::env::var_os("WICK_FS_TEST_CASEFOLD_DIR").expect("WICK_FS_TEST_CASEFOLD_DIR");
    let dir = Path::new(&dir);
    let root = wick_fs_sys::open_root(dir).unwrap();
    let e = HostDir::new(root, Options::default()).unwrap_err();
    assert!(e.0.contains("case-insensitive"), "{}", e.0);
    case_collisions(dir);
}
