// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick-fsd's one connection (docs/design-fs.md §4.2, stage 0), on every
//! host it is confined on: the first peer of `--peer-uid` is served and the
//! listener is gone after that one accept, and a peer of another uid is
//! refused (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS). Run as a
//! user and as root (the CI fs jobs' sudo steps), where the server drops to
//! 65534.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::os::unix::net::UnixStream;

use common::remote::{Remote, Server, base_args, confined_over, give_share, socket_in};
use common::*;

/// Open item: on macOS 27.2 this failed once in 120 runs (20 runs after
/// alias.rs at load 17): the confined server had not ended 30 s after the
/// test closed the connection, and the wait killed it. Not seen in the 100
/// runs since; no crash report and no Seatbelt line for it. The cause is not
/// established: `Server::wait` now records the server's state before such a
/// kill (common/remote.rs), so the next one says where it was.
#[test]
fn test_second_connection_refused() {
    let base = scratch("conn-second");
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    let socket = socket_in(&base);
    let Some(mut r) = confined_over(&share, &socket) else {
        remove(&base);
        return;
    };
    assert!(!socket.exists(), "the listener is unlinked after the one accept");
    UnixStream::connect(&socket).unwrap_err();
    let (status, err) = r.finish();
    assert!(status.success(), "{status:?}: {err}");
    remove(&base);
}

#[test]
fn test_wrong_peer_refused() {
    let base = scratch("conn-peer");
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    give_share(&share);
    let socket = socket_in(&base);
    let mut args = base_args(&share, &socket);
    let other = (wick_fs_sys::euid() + 1).to_string();
    args.extend(["--peer-uid".to_string(), other]);
    let server = Server::start(&args, |_| {});
    let Err((mut server, _)) = Remote::connect(server) else {
        panic!("a peer of another uid was served");
    };
    let (status, err) = server.wait();
    assert!(!status.success(), "{status:?}");
    assert!(err.contains("not --peer-uid"), "{err}");
    assert!(!socket.exists());
    remove(&base);
}
