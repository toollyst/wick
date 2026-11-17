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

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// On a volume that folds case: one stored name, the other forms refused.
fn case_collisions(dir: &Path) {
    std::fs::write(dir.join("Foo"), b"").unwrap();
    std::fs::write(dir.join("x"), b"").unwrap();
    let mut s = session_over(dir, Options { case_insensitive_ok: true }, Config::default()).unwrap();
    lookup(&mut s, b"Foo").unwrap();
    assert_eq!(lookup(&mut s, b"foo"), Err(Errno::ENOENT));
    assert_eq!(lookup(&mut s, b"FOO"), Err(Errno::ENOENT));
    assert_eq!(create(&mut s, b"foo"), Err(Errno::EEXIST));
    let (e, _) = call(&mut s, Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name(b"FOO")]);
    assert_eq!(errno(e), Errno::EEXIST);
    let (e, _) = call(&mut s, Opcode::Rename, ROOT, &[&le64(ROOT), &name(b"x"), &name(b"foo")]);
    assert_eq!(errno(e), Errno::EEXIST, "a rename onto another object's case variant");
    let (e, _) = call(&mut s, Opcode::Unlink, ROOT, &[&name(b"foo")]);
    assert_eq!(errno(e), Errno::ENOENT);
    // An object renamed to its own other case: the host stores the new one.
    let (e, _) = call(&mut s, Opcode::Rename, ROOT, &[&le64(ROOT), &name(b"Foo"), &name(b"foo")]);
    assert_eq!(e, 0);
    assert_eq!(names(dir), ["foo", "x"]);
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
