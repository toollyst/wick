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
    std::fs::create_dir_all(dir.join("share")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wick-fsd"));
    cmd.arg("--share-dir")
        .arg(dir.join("share"))
        .arg("--socket")
        .arg(dir.join("fs.sock"))
        .args(["--id", "t", "--ready-fd", "40"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(fd) = ready {
        sys::command_with_inherited(&mut cmd, vec![(fd, 40)]);
    }
    cmd
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wick-fsd-start-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

/// A pipe's write end is taken: on Linux the ready byte, then the end
/// closed (the reader sees the pipe's end while the server still waits for
/// its connection); elsewhere the refusal of a host without confinement,
/// after the check, with nothing written.
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
    if cfg!(target_os = "linux") {
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
