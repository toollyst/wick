// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md §6: every request kind the session serves, made over
//! the host directory in this process and over a confined wick-fsd, and
//! answered alike. A system call the serving path needs and the
//! confinement does not give (Linux's filter, macOS's Seatbelt profile)
//! ends the server or fails the request, and shows here as a request
//! without an answer or a different one: the confinement is tested against
//! the whole serving path, not only the requests other tests make.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use common::drive::{FATTR_FH, FATTR_MODE, FATTR_SIZE, G, RENAME_EXCHANGE};
use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::{Errno, Opcode};
use wick_fsd::host::unix::{HostDir, Options};

const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;
const FALLOC_FL_KEEP_SIZE: u32 = 1;
const FALLOC_FL_PUNCH_HOLE: u32 = 2;
const S_IFIFO: u32 = 0o010_000;

/// What each request was answered: its name and the error (0 or a negative
/// errno).
type Transcript = Vec<(&'static str, i32)>;

/// Makes one request and notes its answer; the body is returned.
fn step<L: Link>(t: &mut Transcript, g: &mut G<L>, what: &'static str, op: Opcode, node: u64, args: &[&[u8]]) -> Vec<u8> {
    let r = g
        .raw(op, node, args)
        .unwrap_or_else(|| panic!("{what} ({op:?}): no answer, the server is gone (after {t:?})"));
    t.push((what, i32::from_le_bytes(r[4..8].try_into().unwrap())));
    r[16..].to_vec()
}

fn setattr_in(valid: u32, fh: u64, size: u64, times: (u64, u64), mode: u32, ids: (u32, u32)) -> Vec<u8> {
    let mut a = vec![0u8; 88];
    a[0..4].copy_from_slice(&le32(valid));
    a[8..16].copy_from_slice(&le64(fh));
    a[16..24].copy_from_slice(&le64(size));
    a[32..40].copy_from_slice(&le64(times.0));
    a[40..48].copy_from_slice(&le64(times.1));
    a[68..72].copy_from_slice(&le32(mode));
    a[76..80].copy_from_slice(&le32(ids.0));
    a[80..84].copy_from_slice(&le32(ids.1));
    a
}

fn io_in(fh: u64, offset: u64, size: u32) -> Vec<u8> {
    [&le64(fh)[..], &le64(offset), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat()
}

fn release_in(fh: u64) -> Vec<u8> {
    [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat()
}

/// Every request kind once (the ones the session answers ENOSYS too, so
/// that a change there is seen), in an order where each has something to
/// work on.
#[allow(clippy::too_many_lines)]
fn every_request<L: Link>(g: &mut G<L>) -> Transcript {
    let t = &mut Transcript::new();
    step(t, g, "statfs", Opcode::Statfs, ROOT, &[]);
    // A symlink the host made in the share (host_made): READLINK reads it
    // (readlinkat); the guest's own symlinks are kept as files.
    let hl = u64_at(&step(t, g, "lookup host symlink", Opcode::Lookup, ROOT, &[&name(b"hl")]), 0);
    assert_eq!(step(t, g, "readlink host symlink", Opcode::Readlink, hl, &[]), b"made by the host");
    // The host's special bits are not shown (permission bits alone).
    for (what, shown, n) in [("lookup host setuid file", "mode: host setuid file", &b"hs"[..]), ("lookup host sticky dir", "mode: host sticky dir", b"hd")] {
        let r = step(t, g, what, Opcode::Lookup, ROOT, &[&name(n)]);
        let mode = i32::from_le_bytes(r[ATTR_IN_ENTRY + 60..ATTR_IN_ENTRY + 64].try_into().unwrap()) & 0o7777;
        assert_eq!(mode, 0o755, "{what}: shown {mode:o}");
        t.push((shown, mode));
        g.forget(u64_at(&r, 0), 1);
    }
    step(t, g, "access", Opcode::Access, ROOT, &[&le32(4), &le32(0)]);
    let d = u64_at(&step(t, g, "mkdir", Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name(b"d")]), 0);
    let create = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
    let r = step(t, g, "create", Opcode::Create, d, &[&create, &name(b"f")]);
    let (f, fh) = (u64_at(&r, 0), u64_at(&r, ATTR_IN_ENTRY + 88));
    let data = b"every request";
    let size = u32::try_from(data.len()).unwrap();
    let w = [&le64(fh)[..], &le64(0), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
    step(t, g, "write", Opcode::Write, f, &[&w, data]);
    assert_eq!(step(t, g, "read", Opcode::Read, f, &[&io_in(fh, 0, 64)]), data);
    step(t, g, "flush", Opcode::Flush, f, &[&le64(fh), &le64(0), &le64(0)]);
    step(t, g, "fsync", Opcode::Fsync, f, &[&le64(fh), &le32(0), &le32(0)]);
    step(t, g, "fsync datasync", Opcode::Fsync, f, &[&le64(fh), &le32(1), &le32(0)]);
    let falloc = |off: u64, len: u64, mode: u32| [&le64(fh)[..], &le64(off), &le64(len), &le32(mode), &le32(0)].concat();
    step(t, g, "fallocate", Opcode::Fallocate, f, &[&falloc(0, 8192, 0)]);
    step(t, g, "fallocate keep size", Opcode::Fallocate, f, &[&falloc(8192, 8192, FALLOC_FL_KEEP_SIZE)]);
    let punch = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
    step(t, g, "fallocate punch hole", Opcode::Fallocate, f, &[&falloc(4096, 4096, punch)]);
    step(t, g, "getattr", Opcode::Getattr, f, &[&le32(0), &le32(0), &le64(0)]);
    step(t, g, "getattr through fh", Opcode::Getattr, f, &[&le32(1), &le32(0), &le64(fh)]);
    let (no_times, no_ids) = ((0, 0), (0, 0));
    step(t, g, "setattr size", Opcode::Setattr, f, &[&setattr_in(FATTR_SIZE | FATTR_FH, fh, 5, no_times, 0, no_ids)]);
    step(t, g, "setattr mode", Opcode::Setattr, f, &[&setattr_in(FATTR_MODE, 0, 0, no_times, 0o600, no_ids)]);
    let times = FATTR_ATIME | FATTR_MTIME;
    step(t, g, "setattr times", Opcode::Setattr, f, &[&setattr_in(times, 0, 0, (1_000_000, 2_000_000), 0, no_ids)]);
    let now = times | FATTR_ATIME_NOW | FATTR_MTIME_NOW;
    step(t, g, "setattr times now", Opcode::Setattr, f, &[&setattr_in(now, 0, 0, no_times, 0, no_ids)]);
    let ids = FATTR_UID | FATTR_GID;
    step(t, g, "setattr ids", Opcode::Setattr, f, &[&setattr_in(ids, 0, 0, no_times, 0, (UID, GID))]);
    step(t, g, "setxattr", Opcode::Setxattr, f, &[&le32(1), &le32(0), b"user.a\0", b"v"]);
    assert_eq!(step(t, g, "getxattr", Opcode::Getxattr, f, &[&le32(64), &le32(0), b"user.a\0"]), b"v");
    step(t, g, "getxattr size", Opcode::Getxattr, f, &[&le32(0), &le32(0), b"user.a\0"]);
    assert_eq!(step(t, g, "listxattr", Opcode::Listxattr, f, &[&le32(64), &le32(0)]), b"user.a\0");
    step(t, g, "removexattr", Opcode::Removexattr, f, &[b"user.a\0"]);
    let lk = [&le64(fh)[..], &le64(0), &le64(0), &le64(u64::MAX), &le32(1), &le32(0), &le32(0), &le32(0)].concat();
    step(t, g, "getlk", Opcode::Getlk, f, &[&lk]);
    step(t, g, "setlk", Opcode::Setlk, f, &[&lk]);
    step(t, g, "lseek", Opcode::Lseek, f, &[&le64(fh), &le64(0), &le32(3), &le32(0)]);
    let copy = [&le64(fh)[..], &le64(0), &le64(f), &le64(fh), &le64(64), &le64(5), &le64(0)].concat();
    step(t, g, "copy_file_range", Opcode::CopyFileRange, f, &[&copy]);
    step(t, g, "statx", Opcode::Statx, f, &[&le32(0), &le32(0), &le64(0), &le32(0), &le32(0x7ff)]);
    step(t, g, "bmap", Opcode::Bmap, f, &[&le64(0), &le32(4096), &le32(0)]);
    step(t, g, "syncfs", Opcode::Syncfs, ROOT, &[&le64(0)]);
    step(t, g, "release", Opcode::Release, f, &[&release_in(fh)]);
    let r = step(t, g, "open read-only", Opcode::Open, f, &[&le32(0), &le32(0)]);
    step(t, g, "release read-only", Opcode::Release, f, &[&release_in(u64_at(&r, 0))]);
    step(t, g, "symlink", Opcode::Symlink, d, &[&name(b"s"), &name(b"f")]);
    let s = u64_at(&step(t, g, "lookup symlink", Opcode::Lookup, d, &[&name(b"s")]), 0);
    assert_eq!(step(t, g, "readlink", Opcode::Readlink, s, &[]), b"f");
    let fifo = [&le32(S_IFIFO | 0o644)[..], &le32(0), &le32(0), &le32(0)].concat();
    step(t, g, "mknod fifo", Opcode::Mknod, d, &[&fifo, &name(b"p")]);
    step(t, g, "link", Opcode::Link, d, &[&le64(f), &name(b"g")]);
    step(t, g, "rename", Opcode::Rename, d, &[&le64(ROOT), &name(b"g"), &name(b"h")]);
    let exchange = [&le64(d)[..], &le32(RENAME_EXCHANGE), &le32(0)].concat();
    step(t, g, "rename2 exchange", Opcode::Rename2, ROOT, &[&exchange, &name(b"h"), &name(b"p")]);
    let r = step(t, g, "opendir", Opcode::Opendir, d, &[&[0; 8]]);
    let dfh = u64_at(&r, 0);
    let listed = step(t, g, "readdir", Opcode::Readdir, d, &[&io_in(dfh, 0, 4096)]);
    assert!(!listed.is_empty(), "readdir of a directory with entries gave none");
    let listed = step(t, g, "readdirplus", Opcode::Readdirplus, d, &[&io_in(dfh, 0, 4096)]);
    assert!(!listed.is_empty(), "readdirplus of a directory with entries gave none");
    step(t, g, "fsyncdir", Opcode::Fsyncdir, d, &[&le64(dfh), &le32(0), &le32(0)]);
    step(t, g, "releasedir", Opcode::Releasedir, d, &[&release_in(dfh)]);
    // The exchange left the fifo as h at the root and the link as p in d.
    for (what, parent, n) in [("unlink", d, &b"f"[..]), ("unlink symlink", d, b"s"), ("unlink link", d, b"p"), ("unlink fifo", ROOT, b"h")] {
        step(t, g, what, Opcode::Unlink, parent, &[&name(n)]);
    }
    step(t, g, "rmdir", Opcode::Rmdir, ROOT, &[&name(b"d")]);
    step(t, g, "interrupt", Opcode::Interrupt, 0, &[&le64(1)]);
    for n in [f, s, d, hl] {
        g.forget(n, 1);
    }
    std::mem::take(t)
}

/// A guest's special mode bits (set-user-id, set-group-id, sticky) on a
/// directory and a file, by MKDIR, CREATE and SETATTR: answered back in full
/// from the metadata record, the host's object never given them (the
/// backend makes files 0o600 and directories 0o700 and `set_perm` passes the
/// permission bits alone, so no host `fchmod` asks Seatbelt's
/// `file-write-setugid`, which drops the bit without an error). The modes
/// answered go in the transcript (`mode: ...`), compared confined with in
/// process; `host` is the share's directory as the host sees it.
fn special_modes<L: Link>(t: &mut Transcript, g: &mut G<L>, host: &std::path::Path) {
    const ATTR_OUT_MODE: usize = 16 + 60;
    let mode_at = |r: &[u8], at: usize| i32::from_le_bytes(r[at..at + 4].try_into().unwrap()) & 0o7777;
    let r = step(t, g, "mkdir 07777", Opcode::Mkdir, ROOT, &[&le32(0o7777), &le32(0), &name(b"sd")]);
    let sd = u64_at(&r, 0);
    t.push(("mode: mkdir 07777", mode_at(&r, ATTR_IN_ENTRY + 60)));
    assert_eq!(mode_at(&r, ATTR_IN_ENTRY + 60), 0o7777, "mkdir 07777: the guest's mode answered");
    let create = [&le32(2)[..], &le32(0o6755), &le32(0), &le32(0)].concat();
    let r = step(t, g, "create 06755", Opcode::Create, sd, &[&create, &name(b"sf")]);
    let (sf, fh) = (u64_at(&r, 0), u64_at(&r, ATTR_IN_ENTRY + 88));
    t.push(("mode: create 06755", mode_at(&r, ATTR_IN_ENTRY + 60)));
    assert_eq!(mode_at(&r, ATTR_IN_ENTRY + 60), 0o6755, "create 06755: the guest's mode answered");
    step(t, g, "release 06755", Opcode::Release, sf, &[&release_in(fh)]);
    let none = ((0, 0), (0, 0));
    let setattrs = [
        ("setattr 06777", "mode: setattr 06777", sf, 0o6777),
        ("setattr 04700", "mode: setattr 04700", sf, 0o4700),
        ("setattr 01755", "mode: setattr 01755", sd, 0o1755),
    ];
    for (what, answered, node, mode) in setattrs {
        let r = step(t, g, what, Opcode::Setattr, node, &[&setattr_in(FATTR_MODE, 0, 0, none.0, mode, none.1)]);
        t.push((answered, mode_at(&r, ATTR_OUT_MODE)));
        assert_eq!(mode_at(&r, ATTR_OUT_MODE), i32::try_from(mode).unwrap(), "{what}: the guest's mode answered");
    }
    let r = step(t, g, "getattr 04700", Opcode::Getattr, sf, &[&le32(0), &le32(0), &le64(0)]);
    assert_eq!(mode_at(&r, ATTR_OUT_MODE), 0o4700, "getattr after setattr 04700");
    t.push(("mode: getattr 04700", mode_at(&r, ATTR_OUT_MODE)));
    for n in ["sd", "sd/sf"] {
        let m = std::os::unix::fs::PermissionsExt::mode(&std::fs::symlink_metadata(host.join(n)).unwrap().permissions());
        assert_eq!(m & 0o7000, 0, "{n}: the host's object has special bits ({m:o})");
    }
    step(t, g, "unlink 04700", Opcode::Unlink, sd, &[&name(b"sf")]);
    step(t, g, "rmdir 01755", Opcode::Rmdir, ROOT, &[&name(b"sd")]);
    for n in [sf, sd] {
        g.forget(n, 1);
    }
}

/// The answers the session gives: every request served, the ones it does not
/// implement ENOSYS; a `mode: ` entry is a mode answered, checked where it
/// is made.
fn expected(t: &Transcript) {
    const ENOSYS: [&str; 8] = ["getlk", "setlk", "lseek", "copy_file_range", "statx", "bmap", "syncfs", "interrupt"];
    for (what, e) in t {
        if what.starts_with("mode: ") {
            continue;
        }
        let as_expected = if ENOSYS.contains(what) { *e < 0 && errno(*e) == Errno::ENOSYS } else { *e == 0 };
        assert!(as_expected, "{what}: answered {e} (all: {t:?})");
    }
}

/// STATFS's answer: the blocks, free blocks, available blocks, files and
/// free files; then the block size, the longest name and the fragment size
/// (`fuse_kstatfs`).
fn statfs<L: Link>(g: &mut G<L>) -> ([u64; 5], [u32; 3]) {
    let r = g.raw(Opcode::Statfs, ROOT, &[]).expect("statfs: no answer, the server is gone");
    assert_eq!(i32::from_le_bytes(r[4..8].try_into().unwrap()), 0, "statfs refused");
    let b = &r[16..];
    let wide = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    let narrow = |i: usize| u32::from_le_bytes(b[40 + i * 4..44 + i * 4].try_into().unwrap());
    ([wide(0), wide(1), wide(2), wide(3), wide(4)], [narrow(0), narrow(1), narrow(2)])
}

/// STATFS confined answers as STATFS in this process: the sizes equal, and
/// each count between two in-process answers taken just before and just
/// after (the volume is in use; a count the confinement changed, as
/// Seatbelt rounds the free blocks without `vfs.disk-space`, falls outside
/// unless the volume moved by as much between them, and then the next try
/// decides).
///
/// `near` is a session that served the same requests as `confined`, over a
/// directory of the same volume: the free and available blocks a session
/// answers are the host's or what its byte budget leaves, whichever is less
/// (`Session::statfs`), and the budget is the session's own. A fresh session
/// over the share answered the whole budget, 64 GiB (16777216 blocks of 4
/// KiB), where the confined one had spent 8 KiB of it on the requests'
/// writes, so on a host with more than 64 GiB free (CI run 44296604010's
/// Linux runners) the two differed by 2 blocks every time.
fn statfs_alike<A: Link, B: Link>(near: &mut G<A>, confined: &mut G<B>) {
    let mut last = None;
    for _ in 0..50 {
        let (before, c, after) = (statfs(near), statfs(confined), statfs(near));
        assert_eq!(c.1, before.1, "statfs: block size, name length, fragment size");
        if (0..5).all(|i| before.0[i].min(after.0[i]) <= c.0[i] && c.0[i] <= before.0[i].max(after.0[i])) {
            return;
        }
        last = Some((before.0, c.0, after.0));
    }
    panic!("statfs confined is not between two answers in this process, 50 tries; the last (before, confined, after): {last:?}");
}

/// What the host put in a share before it is served: a symlink, and a file
/// and a directory with special mode bits (set-user-id and set-group-id,
/// sticky), which the host's own tools set and the guest is shown without
/// (a host object without a record shows its permission bits alone).
fn host_made(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::os::unix::fs::symlink("made by the host", dir.join("hl")).unwrap();
    std::fs::write(dir.join("hs"), b"set-user-id by the host").unwrap();
    std::fs::set_permissions(dir.join("hs"), std::fs::Permissions::from_mode(0o6755)).unwrap();
    std::fs::create_dir(dir.join("hd")).unwrap();
    std::fs::set_permissions(dir.join("hd"), std::fs::Permissions::from_mode(0o1755)).unwrap();
    for (n, m) in [("hs", 0o6755), ("hd", 0o1755)] {
        let got = std::fs::symlink_metadata(dir.join(n)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(got, m, "{n}: the host kept {got:o}");
    }
}

#[test]
fn test_every_request_confined_answered_as_unconfined() {
    let base = scratch("requests");
    let host = base.join("host");
    std::fs::create_dir(&host).unwrap();
    host_made(&host);
    let dir = HostDir::new(sys::open_root(&host).unwrap(), Options { case_insensitive_ok: true, ..Options::default() }).unwrap();
    let mut near = G::new(dir);
    let mut unconfined = every_request(&mut near);
    special_modes(&mut unconfined, &mut near, &host);
    expected(&unconfined);

    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    host_made(&share);
    if let Some(r) = remote::confined_over(&share, &remote::socket_in(&base)) {
        let mut g = G::over(r);
        let mut confined = every_request(&mut g);
        special_modes(&mut confined, &mut g, &share);
        statfs_alike(&mut near, &mut g);
        remote::finish_clean(&mut g.s);
        assert_eq!(confined, unconfined, "the confined server answered otherwise");
    }
    remove(&base);
}

/// Requests the guest gets an error for, each once: the error paths' calls
/// (a failed lookup, open, unlink or rename, an errno answered) made where
/// each is made, in an order where each has something to fail on.
fn error_requests<L: Link>(g: &mut G<L>) -> Transcript {
    let t = &mut Transcript::new();
    step(t, g, "lookup missing", Opcode::Lookup, ROOT, &[&name(b"missing")]);
    step(t, g, "lookup a name too long", Opcode::Lookup, ROOT, &[&name(&[b'n'; 300])]);
    let e = u64_at(&step(t, g, "mkdir e", Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name(b"e")]), 0);
    let create = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
    let r = step(t, g, "create e/f", Opcode::Create, e, &[&create, &name(b"f")]);
    let (f, fh) = (u64_at(&r, 0), u64_at(&r, ATTR_IN_ENTRY + 88));
    step(t, g, "mkdir existing", Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name(b"e")]);
    let exclusive = [&le32(2 | 0o100 | 0o200)[..], &le32(0o644), &le32(0), &le32(0)].concat();
    step(t, g, "create existing exclusive", Opcode::Create, e, &[&exclusive, &name(b"f")]);
    step(t, g, "rmdir not empty", Opcode::Rmdir, ROOT, &[&name(b"e")]);
    step(t, g, "rmdir a file", Opcode::Rmdir, e, &[&name(b"f")]);
    step(t, g, "unlink missing", Opcode::Unlink, e, &[&name(b"missing")]);
    step(t, g, "unlink a directory", Opcode::Unlink, ROOT, &[&name(b"e")]);
    step(t, g, "opendir a file", Opcode::Opendir, f, &[&[0; 8]]);
    step(t, g, "readlink a file", Opcode::Readlink, f, &[]);
    step(t, g, "getxattr missing", Opcode::Getxattr, f, &[&le32(64), &le32(0), b"user.none\0"]);
    step(t, g, "removexattr missing", Opcode::Removexattr, f, &[b"user.none\0"]);
    step(t, g, "rename missing", Opcode::Rename, e, &[&le64(e), &name(b"missing"), &name(b"x")]);
    step(t, g, "link a directory", Opcode::Link, ROOT, &[&le64(e), &name(b"e2")]);
    step(t, g, "read a handle never opened", Opcode::Read, f, &[&io_in(fh + 1000, 0, 64)]);
    step(t, g, "release", Opcode::Release, f, &[&release_in(fh)]);
    step(t, g, "unlink f", Opcode::Unlink, e, &[&name(b"f")]);
    step(t, g, "rmdir e", Opcode::Rmdir, ROOT, &[&name(b"e")]);
    for n in [f, e] {
        g.forget(n, 1);
    }
    std::mem::take(t)
}

/// The error paths confined answer as in this process: the same errors,
/// the server up after each.
#[test]
fn test_error_paths_confined_answered_as_unconfined() {
    let base = scratch("errors");
    let host = base.join("host");
    std::fs::create_dir(&host).unwrap();
    let dir = HostDir::new(sys::open_root(&host).unwrap(), Options { case_insensitive_ok: true, ..Options::default() }).unwrap();
    let unconfined = error_requests(&mut G::new(dir));
    let failed = unconfined.iter().filter(|(_, e)| *e < 0).count();
    assert!(failed >= 14, "fewer errors than the requests made for them: {unconfined:?}");
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    if let Some(r) = remote::confined_over(&share, &remote::socket_in(&base)) {
        let mut g = G::over(r);
        let confined = error_requests(&mut g);
        remote::finish_clean(&mut g.s);
        assert_eq!(confined, unconfined, "the confined server answered otherwise");
    }
    remove(&base);
}

/// The names of a READDIR answer (`fuse_dirent`s: ino, off, namelen, type,
/// the name padded to 8) and the last entry's offset.
fn dirents(body: &[u8]) -> (Vec<Vec<u8>>, u64) {
    let (mut names, mut at, mut last) = (Vec::new(), 0, 0);
    while at + 24 <= body.len() {
        last = u64_at(body, at + 8);
        let len = usize::try_from(u32::from_le_bytes(body[at + 16..at + 20].try_into().unwrap())).unwrap();
        names.push(body[at + 24..at + 24 + len].to_vec());
        at += (24 + len).div_ceil(8) * 8;
    }
    (names, last)
}

/// A confined server lists a directory of 3000 entries with long names
/// whole, READDIR by READDIR of 64 KiB (more directory reads, and larger
/// buffers, than the every-request set's one small directory).
#[test]
fn test_a_confined_server_lists_a_big_directory() {
    const ENTRIES: usize = 3000;
    let base = scratch("big-dir");
    let share = base.join("share");
    std::fs::create_dir_all(share.join("big")).unwrap();
    let mut want: Vec<Vec<u8>> = (0..ENTRIES).map(|i| format!("{i:05}-{}", "n".repeat(120)).into_bytes()).collect();
    for n in &want {
        std::fs::write(share.join("big").join(std::str::from_utf8(n).unwrap()), b"").unwrap();
    }
    if let Some(r) = remote::confined_over(&share, &remote::socket_in(&base)) {
        let mut g = G::over(r);
        let big = g.lookup(ROOT, b"big").unwrap();
        let r = g.raw(Opcode::Opendir, big, &[&[0; 8]]).expect("opendir: no answer, the server is gone");
        assert_eq!(i32::from_le_bytes(r[4..8].try_into().unwrap()), 0, "opendir refused");
        let dfh = u64_at(&r[16..], 0);
        let (mut got, mut off, mut reads) = (Vec::new(), 0, 0);
        loop {
            let r = g
                .raw(Opcode::Readdir, big, &[&io_in(dfh, off, 64 << 10)])
                .unwrap_or_else(|| panic!("readdir {reads}: no answer, the server is gone"));
            assert_eq!(i32::from_le_bytes(r[4..8].try_into().unwrap()), 0, "readdir {reads} refused");
            let (names, last) = dirents(&r[16..]);
            if names.is_empty() {
                break;
            }
            got.extend(names);
            off = last;
            reads += 1;
        }
        g.raw(Opcode::Releasedir, big, &[&release_in(dfh)]).expect("releasedir: no answer, the server is gone");
        g.forget(big, 1);
        remote::finish_clean(&mut g.s);
        got.retain(|n| n != b"." && n != b"..");
        got.sort();
        want.sort();
        assert!(reads > 1, "listed in {reads} READDIR");
        assert_eq!(got, want, "the listing");
    }
    remove(&base);
}

/// A confined server answering SETATTR of the times to now 20000 times
/// stays up and answers each: the server's one wall-clock read under the
/// profile (`Session`'s `now()`), which libc makes as the `gettimeofday`
/// system call (116) about once in a million reads, when the commpage's time
/// is being updated (docs/design-fs.md §6.2; confine_probe makes the call by
/// number, which decides it; this is the request path that reaches it).
#[test]
fn test_a_confined_server_sets_times_to_now_again_and_again() {
    let base = scratch("times-now");
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    if let Some(r) = remote::confined_over(&share, &remote::socket_in(&base)) {
        let mut g = G::over(r);
        // The server's own file (as root the test's would be root's, and
        // the server, 65534, could not set its times).
        let t = &mut Transcript::new();
        let create = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
        let r = step(t, &mut g, "create", Opcode::Create, ROOT, &[&create, &name(b"f")]);
        let (f, fh) = (u64_at(&r, 0), u64_at(&r, ATTR_IN_ENTRY + 88));
        step(t, &mut g, "release", Opcode::Release, f, &[&release_in(fh)]);
        assert_eq!(t, &[("create", 0), ("release", 0)]);
        let now = FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW;
        for i in 0..20_000 {
            let r = g
                .raw(Opcode::Setattr, f, &[&setattr_in(now, 0, 0, (0, 0), 0, (0, 0))])
                .unwrap_or_else(|| panic!("SETATTR {i}: no answer, the server is gone"));
            assert_eq!(i32::from_le_bytes(r[4..8].try_into().unwrap()), 0, "SETATTR {i} refused");
        }
        g.forget(f, 1);
        remote::finish_clean(&mut g.s);
    }
    remove(&base);
}

/// A confined server answering READs of 1 MiB, again and again, stays up
/// and answers each with the file's bytes (docs/design-fs.md §6.2). Each
/// READ's reply is a zeroed block of the size read (session.rs, `read`),
/// and each reply frame one more block of that size (serve.rs), both freed
/// once written: on macOS 27.2 libmalloc (xzone) hands such a block out
/// again from one it freed, clearing it with `madvise`, a call the profile
/// killed until it listed it. 64 reads, at offsets that move through a
/// file of 2 MiB.
#[test]
fn test_a_confined_server_answers_large_reads_again_and_again() {
    let base = scratch("large-reads");
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    let data: Vec<u8> = (0..2usize << 20).map(|i| u8::try_from(i % 251).unwrap()).collect();
    std::fs::write(share.join("big"), &data).unwrap();
    if let Some(r) = remote::confined_over(&share, &remote::socket_in(&base)) {
        let mut g = G::over(r);
        let node = g.lookup(1, b"big").unwrap();
        let fh = g.open(node, 0).unwrap();
        for i in 0..64u64 {
            let offset = (i * 4096) % (1 << 20);
            let got = g.read(node, fh, offset, 1 << 20).unwrap_or_else(|e| panic!("READ {i}: {e:?}"));
            let at = usize::try_from(offset).unwrap();
            assert!(got == data[at..at + (1 << 20)], "READ {i} at {offset}: not the file's bytes");
        }
        g.release(node, fh);
        remote::finish_clean(&mut g.s);
    }
    remove(&base);
}
