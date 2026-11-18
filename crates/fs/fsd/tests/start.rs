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
use std::process::Command;
use std::time::Duration;

use wick_fs_sys as sys;
use wick_fs_sys::launch::{self, Descriptors, Io};

fn wick_fsd(dir: &std::path::Path, ready: Option<OwnedFd>) -> (Command, Descriptors) {
    wick_fsd_at(dir, "40", ready)
}

/// wick-fsd over `dir/share` with `--ready-fd at`, and `ready` (if any)
/// to be left open there by [`launch`] (no fork in this test process:
/// sys/src/unix/launch.rs says why).
fn wick_fsd_at(dir: &std::path::Path, at: &str, ready: Option<OwnedFd>) -> (Command, Descriptors) {
    std::fs::create_dir_all(dir.join("share")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wick-fsd"));
    cmd.arg("--share-dir")
        .arg(dir.join("share"))
        .arg("--socket")
        .arg(dir.join("fs.sock"))
        .args(["--id", "t", "--ready-fd", at]);
    let inherited = ready.map(|fd| (fd, at.parse().unwrap())).into_iter().collect();
    (cmd, Descriptors { inherited, ..Default::default() })
}

/// As root under /tmp, whose directories every uid can search (root's own
/// temporary directory on macOS is 0700, which the uid the root test drops
/// to cannot search: common/mod.rs's scratch says so). A name left there
/// is removed as a name (`remove_dir_all` follows no link), then made with
/// `create_dir`, which fails on a name already there.
fn scratch(tag: &str) -> std::path::PathBuf {
    let base = if sys::euid() == 0 { std::path::PathBuf::from("/tmp") } else { std::env::temp_dir() };
    let dir = base.join(format!("wick-fsd-start-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
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
        let (cmd, fds) = wick_fsd_at(&dir, n, None);
        let out = launch::output(&cmd, fds).unwrap();
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
    let (cmd, mut fds) = wick_fsd(&dir, Some(write_end.into()));
    fds.closed = vec![1, 2];
    let mut child = launch::launch(&cmd, [Io::Null, Io::Piped, Io::Piped], fds).unwrap();
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
        let (cmd, fds) = wick_fsd(&dir, fd);
        let out = launch::output(&cmd, fds).unwrap();
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
    let (cmd, fds) = wick_fsd(&dir, Some(write_end.into()));
    // The test's own copy of the write end goes with the launch.
    let mut child = launch::launch(&cmd, [Io::Null, Io::Piped, Io::Piped], fds).unwrap();
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

/// wick-fsd over `dir/share` with its socket `sock`, the ready byte on a
/// pipe whose read end is returned (its write end at 40, given by
/// [`launch`]), and `extra` arguments.
fn wick_fsd_socket(
    dir: &std::path::Path,
    sock: &std::path::Path,
    extra: &[&str],
) -> (Command, Descriptors, std::io::PipeReader) {
    std::fs::create_dir_all(dir.join("share")).unwrap();
    let (read_end, write_end) = std::io::pipe().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wick-fsd"));
    cmd.arg("--share-dir")
        .arg(dir.join("share"))
        .arg("--socket")
        .arg(sock)
        .args(["--id", "t", "--ready-fd", "40"])
        .args(extra);
    (cmd, Descriptors { inherited: vec![(write_end.into(), 40)], ..Default::default() }, read_end)
}

/// The ready byte or the server's end, within 30 s; the server is killed
/// and reaped either way, and its stderr returned. A server that refuses
/// holds `--ready-fd` until its refusal is written (main.rs), so the end of
/// the pipe comes after it: the kill never cuts it off.
fn ready_then_kill(
    (cmd, fds, mut read_end): (Command, Descriptors, std::io::PipeReader),
    then: impl FnOnce(u32),
) -> (Vec<u8>, String) {
    let mut child = launch::launch(&cmd, [Io::Null, Io::Null, Io::Piped], fds).unwrap();
    drop(cmd);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut got = Vec::new();
        let _ = read_end.read_to_end(&mut got);
        let _ = tx.send(got);
    });
    let got = rx.recv_timeout(Duration::from_secs(30)).expect("the pipe's end, within 30 s");
    if got == b"R" {
        then(child.id());
    }
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    (got, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// As root: whether a process of `uid`:`gid` can connect to `sock`. On
/// Linux a forked child (sys::connect_as); on macOS this test binary started
/// again by posix_spawn ([`launch`]) on `connect_as_child` alone, since a
/// fork in a test process can abort in libSystem's fork child handler
/// (sys/src/unix/launch.rs says why).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connect_as(sock: &std::path::Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        sys::connect_as(sock, uid, gid)
    }
    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "connect_as_child", "--ignored", "--test-threads=1", "--nocapture"])
            .env("WICK_FSD_CONNECT_AS", format!("{uid}:{gid}:{}", sock.display()));
        let out = launch::output(&cmd, Descriptors::default()).unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        // libtest's "test connect_as_child ... " may lead the line.
        match text.lines().find_map(|l| l.split_once("connect_as: ").map(|(_, r)| r)) {
            Some("ok") => Ok(()),
            Some(e) => Err(e.to_string()),
            None => panic!("connect_as_child said nothing: {out:?}"),
        }
    }
}

/// [`connect_as`]'s child on macOS: drops to the uid and gid it is given and
/// connects, then says how that went on stdout. Ignored, and nothing without
/// its variable.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "connect_as's child, run by connect_as alone"]
fn connect_as_child() {
    let Ok(spec) = std::env::var("WICK_FSD_CONNECT_AS") else { return };
    let mut it = spec.splitn(3, ':');
    let (uid, gid, path) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
    let r = sys::connect_as_here(std::path::Path::new(path), uid.parse().unwrap(), gid.parse().unwrap());
    println!("connect_as: {}", r.map_or_else(|e| e, |()| "ok".to_string()));
}

/// The socket is made 0600 and this euid's before it is listened on
/// (sys::listen_private), in a directory that must be owned by root, this
/// euid or `--peer-uid` and writable by no group or other (docs/design-fs.md
/// §4.2): a directory another uid can write is refused by its mode and
/// owner, and nothing is bound in it. As root (CI's root runs; the first run
/// on macOS is CI's): a directory owned by another uid is refused unless it
/// is `--peer-uid`'s, and the jail's uid (`--peer-uid 65534`) cannot connect
/// to the socket until it is given the socket, as the jailer does after the
/// ready byte (overlay/jailer/fs_share.rs), when it can.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn test_the_socket_is_private_and_its_directory_too() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let dir = scratch("private");
    let sockets = dir.join("sockets");
    std::fs::create_dir(&sockets).unwrap();
    let sock = sockets.join("fs.sock");
    let euid = sys::euid();

    for mode in [0o777, 0o775, 0o757, 0o1777, 0o722] {
        std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(mode)).unwrap();
        let (got, err) = ready_then_kill(wick_fsd_socket(&dir, &sock, &[]), |_| {});
        assert!(got.is_empty(), "{mode:o}: ready said: {err}");
        assert!(
            err.contains(&format!("--socket's directory {} is mode {mode:04o} owned by uid {euid}", sockets.display())),
            "{mode:o}: {err}"
        );
        assert!(sock.symlink_metadata().is_err(), "{mode:o}: bound");
    }

    std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (got, err) = ready_then_kill(wick_fsd_socket(&dir, &sock, &[]), |_| {
        let m = sock.symlink_metadata().unwrap();
        assert!(m.file_type().is_socket(), "{m:?}");
        assert_eq!((m.mode() & 0o7777, m.uid()), (0o600, euid));
    });
    assert_eq!(got, b"R", "{err}");
    let _ = std::fs::remove_file(&sock);

    if euid == 0 {
        // A directory of another uid: refused, unless that uid is the peer.
        std::os::unix::fs::chown(&sockets, Some(65534), None).unwrap();
        std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (got, err) = ready_then_kill(wick_fsd_socket(&dir, &sock, &[]), |_| {});
        assert!(got.is_empty() && err.contains("is mode 0700 owned by uid 65534"), "{err}");

        // The peer's directory: taken. Before the socket is given to the
        // peer's uid it cannot connect (mode 0600, root's), and no other
        // uid can; after, it can.
        let (got, err) = ready_then_kill(wick_fsd_socket(&dir, &sock, &["--peer-uid", "65534"]), |_| {
            for uid in [65534, 65533] {
                let e = connect_as(&sock, uid, 65534).unwrap_err();
                assert!(e.contains("Permission denied"), "uid {uid}: {e}");
            }
            std::os::unix::fs::chown(&sock, Some(65534), Some(65534)).unwrap();
            assert_eq!(connect_as(&sock, 65533, 65534).map_err(|e| e.contains("Permission denied")), Err(true));
            connect_as(&sock, 65534, 65534).unwrap();
        });
        assert_eq!(got, b"R", "{err}");
        let _ = std::fs::remove_file(&sock);
        std::os::unix::fs::chown(&sockets, Some(0), None).unwrap();
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The soft and the hard RLIMIT_NOFILE are both the descriptors the share's
/// limits may hold open, whatever hard limit the server was started with
/// (here the test's, above it): the hard one is not raised again once the
/// ids are dropped. Linux reads it from /proc; both hosts read the server's
/// own read-back, which it states.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn test_the_descriptor_limit_is_exactly_the_need() {
    let dir = scratch("nofile");
    let sockets = dir.join("sockets");
    std::fs::create_dir(&sockets).unwrap();
    // 1024 held + 100 handles + 64 spare.
    let need = 1188;
    let (_, hard) = sys::nofile().unwrap();
    assert!(hard > need, "the test's own hard limit {hard} must be above {need}");
    let (got, err) = ready_then_kill(wick_fsd_socket(&dir, &sockets.join("fs.sock"), &["--max-handles", "100"]), |_pid| {
        #[cfg(target_os = "linux")]
        {
            let limits = std::fs::read_to_string(format!("/proc/{_pid}/limits")).unwrap();
            let line = limits.lines().find(|l| l.starts_with("Max open files")).unwrap();
            let v: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(v[3..5], [need.to_string(), need.to_string()], "{line}");
        }
    });
    assert_eq!(got, b"R", "{err}");
    assert!(err.contains(&format!("wick-fsd: t: RLIMIT_NOFILE {need} (soft and hard)")), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}
