// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick-fsd's first step (docs/design-fs.md §4.2), before anything is
//! opened: `--ready-fd` must be a pipe's write end or a socket, and is
//! closed once the ready byte is written. What else it was started with is
//! closed (server.rs reads the confined process's descriptors on Linux).

#![cfg(unix)]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

use std::io::Read;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};
use std::time::Duration;

use wick_fs_sys as sys;

fn wick_fsd(dir: &std::path::Path, ready: Option<OwnedFd>) -> Command {
    wick_fsd_at(dir, "40", ready)
}

/// wick-fsd over `dir/share` with `--ready-fd at`, `ready` (if any) left
/// open there.
fn wick_fsd_at(dir: &std::path::Path, at: &str, ready: Option<OwnedFd>) -> Command {
    std::fs::create_dir_all(dir.join("share")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wick-fsd"));
    cmd.arg("--share-dir")
        .arg(dir.join("share"))
        .arg("--socket")
        .arg(dir.join("fs.sock"))
        .args(["--id", "t", "--ready-fd", at])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(fd) = ready {
        sys::command_with_inherited(&mut cmd, vec![(fd, at.parse().unwrap())]);
    }
    cmd
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wick-fsd-start-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 0 to 2 are the standard streams: `--ready-fd` there would be closed
/// after the ready byte and its number taken by the next open (the
/// connection), where the log would then go. Refused by the parse, by name,
/// as is a number below 0.
#[test]
fn test_ready_fd_is_never_a_standard_stream() {
    let dir = scratch("std");
    for n in ["0", "1", "2", "-1"] {
        let out = wick_fsd_at(&dir, n, None).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{n}: {err}");
        assert!(err.contains(&format!("--ready-fd {n}: 0 to 2 are the standard streams")), "{n}: {err}");
        assert!(out.stdout.is_empty() && !dir.join("fs.sock").exists(), "{n}: started");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Started with its standard output and error closed (`>&-`), the server
/// finds `/dev/null` at 1 and 2 (Rust's start opens it for any of 0 to 2
/// that is closed, before main): its `ready` and its log go nowhere, never
/// into the connection or the share's root, which take numbers of their
/// own. Linux reads its descriptors while it waits for its connection
/// (not yet confined, so a process of the same user may).
#[cfg(target_os = "linux")]
#[test]
fn test_closed_standard_streams_are_dev_null_to_the_server() {
    let dir = scratch("closed");
    let (mut read_end, write_end) = std::io::pipe().unwrap();
    let mut cmd = wick_fsd(&dir, Some(write_end.into()));
    sys::command_with_closed(&mut cmd, &[1, 2]);
    let mut child = cmd.spawn().unwrap();
    drop(cmd);
    // The byte, then the pipe's end: --ready-fd is closed.
    let mut got = Vec::new();
    read_end.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"R");
    let mut fds: Vec<(i32, String)> = std::fs::read_dir(format!("/proc/{}/fd", child.id()))
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (e.file_name().to_str().unwrap().parse().unwrap(), std::fs::read_link(e.path()).unwrap().display().to_string())
        })
        .collect();
    fds.sort();
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    for fd in 0..3 {
        assert_eq!(fds[fd].1, "/dev/null", "{fds:?}");
    }
    // The share's root and the listener, at numbers of their own.
    assert!(fds.iter().skip(3).all(|(fd, _)| *fd > 2) && fds.len() == 5, "{fds:?}");
    assert!(fds.iter().any(|(_, what)| what.starts_with("socket:")), "{fds:?}");
}

#[test]
fn test_ready_fd_must_be_a_pipe_s_write_end_or_a_socket() {
    let dir = scratch("kinds");
    let file: OwnedFd = std::fs::File::create(dir.join("not-a-pipe")).unwrap().into();
    let (read_end, write_end) = std::io::pipe().unwrap();
    drop(write_end);
    for (what, fd, named) in [
        ("a regular file", Some(file), "40: file "),
        ("a pipe's read end", Some(OwnedFd::from(read_end)), "40: pipe "),
        ("nothing", None, "--ready-fd 40: 9 "),
    ] {
        let out = wick_fsd(&dir, fd).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{what}: {err}");
        assert!(err.contains(named), "{what}: {err}");
        if what != "nothing" {
            assert!(err.contains("--ready-fd 40 is not a pipe's write end or a socket"), "{what}: {err}");
        }
        assert!(out.stdout.is_empty() && !dir.join("fs.sock").exists(), "{what}: started");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A pipe's write end is taken: on Linux and macOS the ready byte, then the
/// end closed (the reader sees the pipe's end while the server still waits
/// for its connection); elsewhere the refusal of a host without
/// confinement, after the check, with nothing written.
#[test]
fn test_ready_fd_gets_one_byte_and_is_closed() {
    let dir = scratch("byte");
    let (mut read_end, write_end) = std::io::pipe().unwrap();
    let mut cmd = wick_fsd(&dir, Some(write_end.into()));
    let mut child = cmd.spawn().unwrap();
    // The test's own copy of the write end goes with the command.
    drop(cmd);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut got = Vec::new();
        let r = read_end.read_to_end(&mut got);
        let _ = tx.send((r.map(drop), got));
    });
    let (r, got) = rx.recv_timeout(Duration::from_secs(30)).expect("the pipe's end, within 30 s");
    r.unwrap();
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert_eq!(got, b"R");
        assert!(child.try_wait().unwrap().is_none(), "the server ended instead of waiting for its connection");
        child.kill().unwrap();
        child.wait().unwrap();
    } else {
        assert!(got.is_empty(), "{got:?}");
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("does not serve unconfined") && !err.contains("--ready-fd"), "{err}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What keeps a discovery build (`--cfg wick_fsd_discovery`, whose macOS
/// profile allows and reports what it does not list) from being taken for
/// the product: `--version` says which build it is, and a discovery build
/// says so first on stderr, before anything else it does. This test is
/// built with the same flags as the binary, so it checks each build's own
/// words.
#[test]
fn test_a_build_says_whether_it_is_a_discovery_build() {
    let out = Command::new(env!("CARGO_BIN_EXE_wick-fsd")).arg("--version").output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let line = String::from_utf8_lossy(&out.stdout);
    let discovery = "(discovery build: its profile allows and reports what it does not list; never a product)";
    assert_eq!(line.trim_end(), wick_fsd::version_line(), "{out:?}");
    assert!(line.starts_with("wick-fsd "), "{line}");
    let err = String::from_utf8_lossy(&out.stderr);
    if wick_fsd::DISCOVERY_BUILD {
        assert!(line.contains(discovery), "{line}");
        assert_eq!(err.lines().next(), Some(format!("wick-fsd: {}", wick_fsd::version_line()).as_str()), "{err}");
    } else {
        assert!(!line.contains("discovery"), "{line}");
        assert!(err.is_empty(), "{err}");
    }
}
