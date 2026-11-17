// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The host directory's stated behaviours (docs/design-fs.md §4.3): mount
//! points beneath the share, host names and attributes that are not the
//! guest's, host hard links, the errno table, rename's flags, the guest's
//! open flags, and stage 0's refusals.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::{Errno, Opcode};
use wick_fsd::host::unix::{GUEST_XATTR_PREFIX, Options, RECORD_XATTR};
use wick_fsd::limits::{Limits, descriptors};
use wick_fsd::session::Config;
use wick_fsd::stage0::{self, Share};

fn rn2(newdir: u64, flags: u32) -> Vec<u8> {
    [&le64(newdir)[..], &le32(flags), &le32(0)].concat()
}

fn xattr_get(path: &Path, n: &[u8]) -> Option<Vec<u8>> {
    let f = std::fs::File::open(path).unwrap();
    sys::xattr::get(std::os::fd::AsFd::as_fd(&f), n).unwrap()
}

/// A mount point beneath the share is not entered: EXDEV, on both hosts
/// (the root directory and its `/proc` or `/dev`, a mount any host has).
#[test]
fn test_mount_point_beneath_the_share_is_exdev() {
    let mount = if cfg!(target_os = "macos") { &b"dev"[..] } else { b"proc" };
    let mut s = session_over(Path::new("/"), Options { case_insensitive_ok: true }, Config::default()).unwrap();
    let (e, _) = call(&mut s, Opcode::Lookup, ROOT, &[&name(mount)]);
    assert_eq!(errno(e), Errno::EXDEV);
    // Listed, as the host lists it; never entered.
    let (e, _) = call(&mut s, Opcode::Lookup, ROOT, &[&name(b"etc")]);
    assert!(e == 0 || errno(e) == Errno::ENOENT, "{e}");
    assert_eq!(s.counters().layer_refusals, 0);
}

#[test]
fn test_host_names_that_are_not_guest_names_are_skipped() {
    let mut h = H::with("names", Default::default(), |share| {
        std::fs::write(share.join("plain"), b"").unwrap();
        // An escape image (layer 1 refuses it on every host).
        std::fs::write(share.join("a\u{F03A}b"), b"").unwrap();
        // Linux: not UTF-8 (APFS refuses such a name).
        #[cfg(target_os = "linux")]
        std::fs::write(share.join(std::ffi::OsStr::from_bytes(b"bad\xff")), b"").unwrap();
    });
    let names = h.list(ROOT);
    assert_eq!(names, vec![b"plain".to_vec()]);
    // Counted each time a listing passes them.
    let skipped = if cfg!(target_os = "linux") { 2 } else { 1 };
    assert!(h.s.counters().names_skipped >= skipped, "{}", h.s.counters().names_skipped);
    // And no guest name reaches them.
    assert_eq!(h.lookup(ROOT, "a\u{F03A}b".as_bytes()), Err(Errno::EINVAL));
}

#[test]
fn test_host_xattrs_outside_the_prefix_are_not_shown() {
    let host_attr: &[u8] = if cfg!(target_os = "macos") { b"com.example.host" } else { b"user.host" };
    let mut h = H::with("xattr", Default::default(), |share| {
        std::fs::write(share.join("f"), b"").unwrap();
        let f = std::fs::File::open(share.join("f")).unwrap();
        sys::xattr::set(std::os::fd::AsFd::as_fd(&f), host_attr, b"host's", false, false).unwrap();
    });
    let f = u64_at(&h.lookup(ROOT, b"f").unwrap(), 0);
    let list = h.ok(Opcode::Listxattr, f, &[&le32(4096), &le32(0)]);
    assert!(list.is_empty(), "the host's attribute is not shown: {:?}", String::from_utf8_lossy(&list));
    let get = |n: &[u8]| [&le32(64)[..], &le32(0), n, b"\0"].concat();
    assert_eq!(h.err(Opcode::Getxattr, f, &[&get(host_attr)]), Errno::ENODATA);
    // The guest's own goes under the prefix, the host's stays as it was.
    let set = [&le32(5)[..], &le32(0), host_attr, b"\0", b"guest"].concat();
    h.ok(Opcode::Setxattr, f, &[&set]);
    let path = h.share.join("f");
    assert_eq!(xattr_get(&path, host_attr), Some(b"host's".to_vec()));
    assert_eq!(xattr_get(&path, &[GUEST_XATTR_PREFIX, host_attr].concat()), Some(b"guest".to_vec()));
    assert_eq!(h.ok(Opcode::Listxattr, f, &[&le32(4096), &le32(0)]), [host_attr, b"\0"].concat());
    // The record: where design-fs §4.5 says, 40 bytes.
    h.chmod(f, 0o640).unwrap();
    assert_eq!(xattr_get(&path, RECORD_XATTR).map(|r| r.len()), Some(40));
    // The guest cannot name the record.
    let rec = [&le32(64)[..], &le32(0), RECORD_XATTR, b"\0"].concat();
    assert_eq!(h.err(Opcode::Getxattr, f, &[&rec]), Errno::ENODATA);
}

/// A host hard link to a file outside the share is that file: the server
/// cannot tell where its other names are, so a guest write reaches them
/// (design-fs §4.3; SECURITY's residual risk, as for any program given the
/// directory). The guest sees the link count.
#[test]
fn test_host_hard_link_to_a_file_outside_is_the_same_file() {
    let mut h = H::new("hardlink");
    let out = h.base.join("linked-outside");
    std::fs::write(&out, b"outside").unwrap();
    std::fs::hard_link(&out, h.share.join("hl")).unwrap();
    let e = h.lookup(ROOT, b"hl").unwrap();
    assert_eq!(u32_at(&e[ATTR_IN_ENTRY..], A_NLINK), 2);
    let node = u64_at(&e, 0);
    let fh = h.open(node, 2).unwrap();
    h.write(node, fh, 0, b"GUEST").unwrap();
    h.release(node, fh);
    assert_eq!(std::fs::read(&out).unwrap(), b"GUESTde");
    // The guest's unlink removes the share's name only.
    h.ok(Opcode::Unlink, ROOT, &[&name(b"hl")]);
    assert!(out.exists());
    h.canaries_untouched();
}

/// Errors reach the guest in Linux's numbers on both hosts (macOS's
/// ENOTEMPTY is 66, its ELOOP 62, its ENOATTR 93: the guest gets 39, 40, 61).
#[test]
fn test_errors_are_linux_numbers() {
    let mut h = H::with("errno", Default::default(), |share| {
        std::fs::create_dir_all(share.join("full/x")).unwrap();
        std::fs::write(share.join("file"), b"").unwrap();
        let d = sys::open_root(share).unwrap();
        sys::symlinkat(b"file", std::os::fd::AsFd::as_fd(&d), b"link").unwrap();
    });
    let full = u64_at(&h.lookup(ROOT, b"full").unwrap(), 0);
    let file = u64_at(&h.lookup(ROOT, b"file").unwrap(), 0);
    let link = u64_at(&h.lookup(ROOT, b"link").unwrap(), 0);
    let _ = full;
    assert_eq!(h.err(Opcode::Rmdir, ROOT, &[&name(b"full")]).get(), 39, "ENOTEMPTY");
    assert_eq!(h.err(Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name(b"full")]).get(), 17, "EEXIST");
    assert_eq!(h.lookup(file, b"x").unwrap_err().get(), 20, "ENOTDIR");
    assert_eq!(h.lookup(ROOT, b"none").unwrap_err().get(), 2, "ENOENT");
    assert_eq!(h.open(link, 0).unwrap_err().get(), 40, "ELOOP");
    let get = [&le32(64)[..], &le32(0), b"user.none\0"].concat();
    assert_eq!(h.err(Opcode::Getxattr, file, &[&get]).get(), 61, "ENODATA");
    let e = h.err(Opcode::Rename2, ROOT, &[&rn2(ROOT, 0), &name(b"file"), &name(b"full")]);
    assert_eq!(e.get(), 21, "EISDIR: a file onto a directory");
    let d2 = h.mkdir(ROOT, b"d2");
    let _ = d2;
    let e = h.err(Opcode::Rename2, ROOT, &[&rn2(ROOT, 0), &name(b"d2"), &name(b"full")]);
    assert_eq!(e.get(), 39, "ENOTEMPTY: onto a full directory");
    // fsync and fdatasync reach the host (macOS: F_FULLFSYNC).
    let fh = h.open(file, 2).unwrap();
    for datasync in [0u32, 1] {
        let args = [&le64(fh)[..], &le32(datasync), &le32(0)].concat();
        h.ok(Opcode::Fsync, file, &[&args]);
    }
    h.release(file, fh);
    assert_eq!(h.s.counters().layer_refusals, 0);
}

#[test]
fn test_rename_flags_reach_the_host() {
    let mut h = H::with("rename", Default::default(), |share| {
        std::fs::write(share.join("a"), b"a").unwrap();
        std::fs::create_dir(share.join("d")).unwrap();
        std::fs::write(share.join("d/inner"), b"i").unwrap();
    });
    let a = u64_at(&h.lookup(ROOT, b"a").unwrap(), 0);
    let d = u64_at(&h.lookup(ROOT, b"d").unwrap(), 0);
    assert_eq!(h.err(Opcode::Rename2, ROOT, &[&rn2(ROOT, 1), &name(b"a"), &name(b"d")]), Errno::EEXIST);
    // A file and a directory exchanged on the host.
    h.ok(Opcode::Rename2, ROOT, &[&rn2(ROOT, 2), &name(b"a"), &name(b"d")]);
    assert!(h.share.join("a").is_dir());
    assert_eq!(std::fs::read(h.share.join("d")).unwrap(), b"a");
    assert_eq!(u64_at(&h.lookup(ROOT, b"a").unwrap(), 0), d, "the held directory followed");
    assert_eq!(u64_at(&h.lookup(ROOT, b"d").unwrap(), 0), a);
    h.lookup(d, b"inner").unwrap();
    assert_eq!(h.err(Opcode::Rename2, ROOT, &[&rn2(ROOT, 2), &name(b"a"), &name(b"none")]), Errno::ENOENT);
    h.canaries_untouched();
}

/// The guest's open flags never reach the host: an O_APPEND open writes
/// where the guest says, an O_TRUNC open truncates nothing (the guest's
/// kernel sends SETATTR for that), and O_DIRECT or O_SYNC are the guest's.
#[test]
fn test_open_flags_never_reach_the_host() {
    const O_TRUNC: u32 = 0o1000;
    const O_APPEND: u32 = 0o2000;
    const O_SYNC: u32 = 0o4010000;
    const O_DIRECT: u32 = 0o40000;
    const O_NOATIME: u32 = 0o1000000;
    let mut h = H::with("oflags", Default::default(), |share| {
        std::fs::write(share.join("f"), b"0123456789").unwrap();
    });
    let f = u64_at(&h.lookup(ROOT, b"f").unwrap(), 0);
    let fh = h.open(f, 2 | O_APPEND | O_TRUNC | O_SYNC | O_DIRECT | O_NOATIME).unwrap();
    assert_eq!(std::fs::read(h.share.join("f")).unwrap(), b"0123456789", "no O_TRUNC on the host");
    h.write(f, fh, 0, b"AB").unwrap();
    assert_eq!(std::fs::read(h.share.join("f")).unwrap(), b"AB23456789", "no O_APPEND on the host");
    h.release(f, fh);
}

/// A share with limits small enough for any host's descriptor limit, so
/// that what a case checks never depends on the runner's (that the default
/// limits fit every stock host is `limits::tests`).
fn share(dir: &Path, read_only: bool) -> Share {
    Share {
        dir: dir.to_path_buf(),
        read_only,
        case_insensitive_ok: true,
        limits: Limits {
            max_nodes: 256,
            max_handles: 64,
            ..Limits::default()
        },
    }
}

#[test]
fn test_stage0_refusals() {
    let base = scratch("stage0");
    let home = base.join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::create_dir_all(home.join("src")).unwrap();
    for (dir, what) in [
        (Path::new("/"), "refused share root"),
        (&home, "home directory"),
        (&home.join(".ssh"), "settings and credentials"),
        (&base.join("missing"), "No such file"),
    ] {
        let e = stage0::open(&share(dir, false), Some(&home)).unwrap_err();
        assert!(e.0.contains(what), "{}: {}", dir.display(), e.0);
    }
    let file = base.join("file");
    std::fs::write(&file, b"").unwrap();
    assert!(stage0::open(&share(&file, false), Some(&home)).is_err(), "a file");
    // A link to a directory: the canonical path is served, never the link.
    std::os::unix::fs::symlink(home.join("src"), base.join("link")).unwrap();
    stage0::open(&share(&base.join("link"), false), Some(&home)).unwrap();
    stage0::open(&share(&home.join("src"), false), Some(&home)).unwrap();
    // One descriptor more than this host's limit allows (macOS: the lower
    // of the hard RLIMIT_NOFILE and kern.maxfilesperproc), whatever it is.
    let (_, hard) = sys::nofile().unwrap();
    let small = share(&home.join("src"), false).limits;
    let spare = descriptors(&small) - 256;
    if let Some(nodes) = hard.checked_sub(spare).and_then(|n| n.checked_add(1)).and_then(|n| usize::try_from(n).ok()) {
        let big = Share {
            limits: Limits {
                max_nodes: nodes,
                ..small
            },
            ..share(&home.join("src"), false)
        };
        assert_eq!(descriptors(&big.limits), hard + 1);
        let e = stage0::open(&big, Some(&home)).unwrap_err();
        assert!(e.0.contains("RLIMIT_NOFILE") && e.0.contains(&format!("({hard})")), "{}", e.0);
        // And exactly the limit is served.
        let fits = Share {
            limits: Limits {
                max_nodes: nodes - 1,
                ..small
            },
            ..big
        };
        stage0::open(&fits, Some(&home)).unwrap();
    }
    remove(&base);
}

/// What an exchange of `A` ("a") and `B` ("b") in `dir` did, given its
/// reply `e`: done (each name has the other's bytes) or EINVAL with both
/// unchanged; anything else fails, and so does a reply the files belie.
fn exchange_outcome(dir: &Path, e: i32) -> &'static str {
    let read = |n: &str| std::fs::read(dir.join(n)).map_err(|e| e.kind());
    let now = (read("A"), read("B"));
    let (a, b) = (Ok(b"a".to_vec()), Ok(b"b".to_vec()));
    if e == 0 {
        assert_eq!(now, (b, a), "the exchange returned 0: A and B must have swapped");
        "exchanged"
    } else {
        assert_eq!(errno(e), Errno::EINVAL, "an exchange is done or EINVAL");
        assert_eq!(now, (a, b), "an exchange refused with EINVAL changed the files");
        "EINVAL, both unchanged"
    }
}

/// The case refusal and the volume root, on macOS disk images (no root
/// needed); the file system without native extended attributes (msdos:
/// macOS would keep them in `._` files) is served read-only only, and an
/// exchange there is EINVAL with nothing changed, as Linux's on a file
/// system without it: the volume reports no `VOL_CAP_INT_RENAME_SWAP`, so
/// the backend never asks it (`sys::rename_swap`; macOS 26.7.2's msdos
/// returned 0 to `RENAME_SWAP`, CI run 44188936001, and what it did there
/// is printed below).
#[cfg(target_os = "macos")]
#[test]
fn test_stage0_and_renames_on_other_volumes() {
    let ci = Image::new("ci", "APFS");
    let dir = ci.mount.join("d");
    std::fs::create_dir(&dir).unwrap();
    let e = stage0::open(
        &Share {
            case_insensitive_ok: false,
            ..share(&dir, false)
        },
        None,
    )
    .unwrap_err();
    assert!(e.0.contains("case-insensitive"), "{}", e.0);
    stage0::open(&share(&dir, false), None).unwrap();
    let e = stage0::open(&share(&ci.mount, false), None).unwrap_err();
    assert!(e.0.contains("root of a volume"), "{}", e.0);
    let cs = Image::new("cs", "Case-sensitive APFS");
    let dir = cs.mount.join("d");
    std::fs::create_dir(&dir).unwrap();
    stage0::open(
        &Share {
            case_insensitive_ok: false,
            ..share(&dir, false)
        },
        None,
    )
    .unwrap();
    let fat = Image::new("fat", "MS-DOS");
    let dir = fat.mount.join("d");
    std::fs::create_dir(&dir).unwrap();
    let e = stage0::open(&share(&dir, false), None).unwrap_err();
    assert!(e.0.contains("without extended attributes"), "{}", e.0);
    stage0::open(&share(&dir, true), None).unwrap();
    // The backend itself, read-write, to see its renames.
    std::fs::write(dir.join("A"), b"a").unwrap();
    std::fs::write(dir.join("B"), b"b").unwrap();
    let held = std::fs::File::open(&dir).unwrap();
    let swap = sys::rename_swap(std::os::fd::AsFd::as_fd(&held)).unwrap();
    // The host's own answer, for the record (the backend does not depend
    // on it): renameatx_np(RENAME_SWAP) of two other files.
    std::fs::write(dir.join("C"), b"c").unwrap();
    std::fs::write(dir.join("D"), b"d").unwrap();
    let host = sys::rename(std::os::fd::AsFd::as_fd(&held), b"C", std::os::fd::AsFd::as_fd(&held), b"D", false, true);
    let after = |n: &str| std::fs::read(dir.join(n)).map(|v| String::from_utf8_lossy(&v).into_owned()).ok();
    eprintln!(
        "msdos on this macOS: VOL_CAP_INT_RENAME_SWAP {swap}; renameatx_np(RENAME_SWAP) {host:?}, then C {:?} D {:?}",
        after("C"),
        after("D")
    );
    let mut s = session_over(&dir, Options { case_insensitive_ok: true }, Config::default()).unwrap();
    let (e, _) = call(&mut s, Opcode::Rename2, ROOT, &[&rn2(ROOT, 2), &name(b"A"), &name(b"B")]);
    let outcome = exchange_outcome(&dir, e);
    eprintln!("exchange on msdos: {outcome}");
    if !swap {
        assert_eq!(outcome, "EINVAL, both unchanged", "a volume without the capability is never asked");
    }
}

/// Linux: a file system without user extended attributes is served
/// read-only only. Needs a mounted vfat or exfat directory the test user may
/// write, named by `WICK_FS_TEST_NOXATTR_DIR` (CI's fs job mounts one with
/// sudo; the Docker run mounts one as root).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a vfat/exfat mount: WICK_FS_TEST_NOXATTR_DIR"]
fn test_stage0_and_renames_on_other_volumes() {
    let dir = std::env::var_os("WICK_FS_TEST_NOXATTR_DIR").expect("WICK_FS_TEST_NOXATTR_DIR");
    let dir = Path::new(&dir).join(format!("wick-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let e = stage0::open(&share(&dir, false), None).unwrap_err();
    assert!(e.0.contains("without extended attributes"), "{}", e.0);
    stage0::open(&share(&dir, true), None).unwrap();
    let e = stage0::open(
        &Share {
            case_insensitive_ok: false,
            ..share(&dir, true)
        },
        None,
    )
    .unwrap_err();
    assert!(e.0.contains("case-insensitive"), "{}", e.0);
    std::fs::write(dir.join("A"), b"a").unwrap();
    std::fs::write(dir.join("B"), b"b").unwrap();
    let mut s = session_over(&dir, Options { case_insensitive_ok: true }, Config::default()).unwrap();
    // Case: a lookup by another case is not the file (a negative entry with
    // the default cache mode: node id 0).
    let (e, out) = call(&mut s, Opcode::Lookup, ROOT, &[&name(b"a")]);
    assert_eq!((e, u64_at(&out, 0)), (0, 0), "\"a\" is not \"A\"");
    let (e, _) = call(&mut s, Opcode::Lookup, ROOT, &[&name(b"A")]);
    assert_eq!(e, 0);
    let (e, _) = call(&mut s, Opcode::Rename2, ROOT, &[&rn2(ROOT, 2), &name(b"A"), &name(b"B")]);
    eprintln!("exchange on {}: {}", dir.display(), exchange_outcome(&dir, e));
    remove(&dir);
}
