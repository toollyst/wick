// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md rows 7 and 12: host FIFOs, sockets, devices and
//! symlinks are shown and never opened; what the guest makes of those kinds
//! is a regular host file with a record; no setuid, setgid or sticky bit
//! reaches the host.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::{Errno, Opcode};

const S_IFMT: u32 = 0o170_000;

/// Every request a guest could make of a node by its id, none of which may
/// open a host object that is not a regular file or directory.
fn poke(h: &mut H, node: u64) {
    let _ = h.getattr(node);
    let _ = h.open(node, 0);
    let _ = h.open(node, 2);
    let _ = h.chmod(node, 0o600);
    let _ = h.call(Opcode::Readlink, node, &[]);
    let _ = h.call(Opcode::Listxattr, node, &[&le32(4096), &le32(0)]);
    let _ = h.call(Opcode::Getxattr, node, &[&[&le32(64)[..], &le32(0), b"user.a\0"].concat()]);
    let _ = h.call(Opcode::Setxattr, node, &[&[&le32(1)[..], &le32(0), b"user.a\0v"].concat()]);
    let _ = h.call(Opcode::Opendir, node, &[&[0; 8]]);
    let mut a = vec![0u8; 88];
    // Size and times.
    a[0..4].copy_from_slice(&le32((1 << 3) | (1 << 4) | (1 << 5)));
    let _ = h.call(Opcode::Setattr, node, &[&a]);
}

#[test]
fn test_special_files_never_opened() {
    let mut h = H::with("special", Default::default(), |share| {
        let d = sys::open_root(share).unwrap();
        sys::mkfifoat(std::os::fd::AsFd::as_fd(&d), b"fifo", 0o666).unwrap();
        std::os::unix::net::UnixListener::bind(share.join("sock")).unwrap();
        sys::symlinkat(b"../outside/secret", std::os::fd::AsFd::as_fd(&d), b"up").unwrap();
        sys::symlinkat(b"/etc/passwd", std::os::fd::AsFd::as_fd(&d), b"abs").unwrap();
    });
    // A writer waits in open(2) until a reader opens the FIFO: if the server
    // ever opened it for reading, the writer would be let through.
    let fifo = h.share.join("fifo");
    let opened = Arc::new(AtomicBool::new(false));
    let writer = {
        let fifo = fifo.clone();
        let opened = opened.clone();
        std::thread::spawn(move || {
            let f = std::fs::OpenOptions::new().write(true).open(&fifo);
            opened.store(true, Ordering::SeqCst);
            drop(f);
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    for (n, ty) in [(&b"fifo"[..], 0o010_000), (b"sock", 0o140_000), (b"up", 0o120_000), (b"abs", 0o120_000)] {
        let e = h.lookup(ROOT, n).unwrap();
        let node = u64_at(&e, 0);
        let mode = u32_at(&e[ATTR_IN_ENTRY..], A_MODE);
        if ty == 0o120_000 {
            assert_eq!(mode & S_IFMT, ty, "a host symlink is shown as one");
            assert_eq!(h.open(node, 0), Err(Errno::ELOOP));
        } else {
            // A FIFO or socket the host made: a regular file with no
            // permission, never opened.
            assert_eq!(mode, 0o100_000, "{}", String::from_utf8_lossy(n));
            assert_eq!(h.open(node, 0), Err(Errno::EACCES));
        }
        poke(&mut h, node);
    }
    let up = u64_at(&h.lookup(ROOT, b"up").unwrap(), 0);
    assert_eq!(h.ok(Opcode::Readlink, up, &[]), b"../outside/secret");
    // A name beneath a symlink: not a directory.
    assert_eq!(h.lookup(up, b"x"), Err(Errno::ENOTDIR));
    assert_eq!(h.create(up, b"x"), Err(Errno::ENOTDIR));
    std::thread::sleep(Duration::from_millis(100));
    assert!(!opened.load(Ordering::SeqCst), "the server opened the FIFO");
    // Let the writer go.
    let r = std::fs::File::open(&fifo).unwrap();
    writer.join().unwrap();
    drop(r);
    // The host's objects are as they were.
    assert!(std::fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
    assert_eq!(std::fs::read_link(h.share.join("up")).unwrap().as_os_str(), "../outside/secret");
    assert_eq!(h.s.counters().layer_refusals, 0);
    h.canaries_untouched();
}

/// Linux as root: a device node the host made is shown and never opened
/// (it would have to be made by root; the CI fs job runs this as a user,
/// the devctr run as root).
#[cfg(target_os = "linux")]
#[test]
fn test_host_device_node_never_opened() {
    if sys::uid() != 0 {
        eprintln!("test_host_device_node_never_opened: needs root to make a device node; ran nothing");
        return;
    }
    let mut h = H::with("device", Default::default(), |share| {
        let st = std::process::Command::new("mknod").arg(share.join("null")).args(["c", "1", "3"]).status();
        assert!(st.unwrap().success());
    });
    let e = h.lookup(ROOT, b"null").unwrap();
    assert_eq!(u32_at(&e[ATTR_IN_ENTRY..], A_MODE), 0o100_000);
    let node = u64_at(&e, 0);
    assert_eq!(h.open(node, 0), Err(Errno::EACCES));
    poke(&mut h, node);
    h.canaries_untouched();
}

#[test]
fn test_guest_symlink_is_a_regular_file_on_host() {
    let mut h = H::new("guest-symlink");
    let e = h.ok(Opcode::Symlink, ROOT, &[&name(b"l"), &name(b"../outside/secret")]);
    assert_eq!(u32_at(&e[ATTR_IN_ENTRY..], A_MODE) & S_IFMT, 0o120_000, "the guest sees a symlink");
    let host = std::fs::symlink_metadata(h.share.join("l")).unwrap();
    assert!(host.file_type().is_file(), "the host sees a regular file");
    assert_eq!(std::fs::read(h.share.join("l")).unwrap(), b"../outside/secret");
    assert_eq!(host.mode() & 0o111, 0, "not executable on the host");
    let l = u64_at(&e, 0);
    assert_eq!(h.open(l, 0), Err(Errno::ELOOP));
    // A FIFO, socket and device the guest makes: regular host files too.
    for (n, mode) in [(&b"p"[..], 0o010_644u32), (b"s", 0o140_644), (b"c", 0o020_644), (b"b", 0o060_644)] {
        let args = [&le32(mode)[..], &le32(0x0103), &le32(0), &le32(0)].concat();
        let e = h.ok(Opcode::Mknod, ROOT, &[&args, &name(n)]);
        assert_eq!(u32_at(&e[ATTR_IN_ENTRY..], A_MODE), mode);
        let host = std::fs::symlink_metadata(h.share.join(String::from_utf8_lossy(n).as_ref())).unwrap();
        assert!(host.file_type().is_file());
        assert_eq!(h.open(u64_at(&e, 0), 2), Err(Errno::EACCES));
    }
    h.canaries_untouched();
}

#[test]
fn test_setuid_never_reaches_host() {
    let mut h = H::new("setuid");
    let (f, fh) = h.create(ROOT, b"f").unwrap();
    h.release(f, fh);
    let d = h.mkdir(ROOT, b"d");
    for (node, path, mode) in [(f, "f", 0o7755u32), (d, "d", 0o7777)] {
        h.chmod(node, mode).unwrap();
        let shown = u32_at(&h.getattr(node).unwrap(), A_MODE) & 0o7777;
        assert_eq!(shown, mode, "the guest sees what it set");
        let host = std::fs::metadata(h.share.join(path)).unwrap().mode();
        assert_eq!(host & 0o7000, 0, "{path}: no setuid, setgid or sticky bit on the host");
    }
    // A mode without owner access stays usable by the server.
    h.chmod(f, 0o000).unwrap();
    assert_eq!(std::fs::metadata(h.share.join("f")).unwrap().mode() & 0o600, 0o600);
    let fh = h.open(f, 2).unwrap();
    h.write(f, fh, 0, b"still").unwrap();
    h.release(f, fh);
    // MKNOD with setuid: the record has it, the host never.
    let args = [&le32(0o104_755)[..], &le32(0), &le32(0), &le32(0)].concat();
    let e = h.ok(Opcode::Mknod, ROOT, &[&args, &name(b"suid")]);
    assert_eq!(u32_at(&e[ATTR_IN_ENTRY..], A_MODE), 0o104_755);
    assert_eq!(std::fs::metadata(h.share.join("suid")).unwrap().mode() & 0o7000, 0);
}
