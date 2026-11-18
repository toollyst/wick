// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick-fsd has no unconfined mode: on a host whose confinement is not built
//! yet (Windows, until its port) it refuses to start,
//! with a valid command line, and serves nothing (docs/design-fs.md §4.2).

#![cfg(not(any(target_os = "linux", target_os = "macos")))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

#[test]
fn test_refuses_without_confinement() {
    let dir = std::env::temp_dir().join(format!("wick-fsd-unconfined-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("share")).unwrap();
    let socket = dir.join("fs.sock");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wick-fsd"))
        .arg("--share-dir")
        .arg(dir.join("share"))
        .arg("--socket")
        .arg(&socket)
        .args(["--id", "t"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("does not serve unconfined"), "{err}");
    assert!(out.stdout.is_empty(), "said ready");
    assert!(!socket.exists(), "made a socket");
    std::fs::remove_dir_all(&dir).unwrap();
}
