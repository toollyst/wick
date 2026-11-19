// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A server started under a file size limit (`RLIMIT_FSIZE`: an operator's
//! `ulimit -f`, or a launcher's) answers a guest's WRITE past it with EFBIG
//! and serves on (docs/design-fs.md §4.2). The kernel refuses such a write
//! with EFBIG and sends the writer SIGXFSZ, whose default action ends the
//! process (Linux mm/filemap.c `generic_write_check_limits`; xnu the same
//! signal and errno), so a server that kept that default would let a guest
//! end its own share's server with one WRITE; wick-fsd ignores SIGXFSZ before
//! anything else.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::path::Path;

use common::drive::G;
use common::remote::{self, Remote, Server, base_args, give_share, socket_in, userns_restricted};
use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::Errno;

/// The limit, 1 MiB, set on this test process (its one test) and so on the
/// server it starts, as `ulimit -f` sets it for a shell's children.
const LIMIT: u64 = 1 << 20;

/// The server, started under the limit, confined and connected; `None`
/// where this host refuses the user namespace a server that is not root
/// needs.
fn server_under_the_limit(share: &Path, socket: &Path) -> Option<G<Remote>> {
    give_share(share);
    sys::set_file_size_limit(LIMIT).unwrap();
    match Remote::connect(Server::start(&base_args(share, socket), |_| {})) {
        Ok(r) => Some(G::over(r)),
        Err((mut server, why)) => {
            let (status, err) = server.wait();
            if let Some(restricted) = userns_restricted() {
                eprintln!("ran nothing confined: {restricted}: {status:?} {err}");
                return None;
            }
            panic!("no confined server ({why}; {status:?}): {err}");
        }
    }
}

#[test]
fn test_a_write_past_the_file_size_limit_is_efbig_and_the_server_serves_on() {
    let base = scratch("fsize");
    let share = base.join("share");
    std::fs::create_dir(&share).unwrap();
    let Some(mut g) = server_under_the_limit(&share, &socket_in(&base)) else {
        remove(&base);
        return;
    };
    let (node, fh) = g.create(ROOT, b"big");
    // Below the limit: written.
    assert_eq!(g.write(node, fh, 0, &[1; 4096]), Ok(4096));
    // At the limit and past it: EFBIG, the server alive.
    assert_eq!(g.write(node, fh, LIMIT, &[2; 4096]), Err(Errno::EFBIG), "a write at the limit");
    assert_eq!(g.write(node, fh, LIMIT + (1 << 20), &[3; 16]), Err(Errno::EFBIG), "a write past the limit");
    // Across it: Linux writes up to the limit (a short write), macOS
    // refuses the whole write; either way nothing past the limit.
    let across = g.write(node, fh, LIMIT - 1024, &[4; 4096]);
    assert!(matches!(across, Ok(1024) | Err(Errno::EFBIG)), "a write across the limit: {across:?}");
    // Still serving: the file is what was written below the limit.
    let attr = g.getattr(node, Some(fh)).unwrap();
    assert!(attr.size <= LIMIT, "{} bytes, past the limit", attr.size);
    assert_eq!(g.write(node, fh, 8192, &[5; 4096]), Ok(4096), "a write below the limit after the refusals");
    g.release(node, fh);
    remote::finish_clean(&mut g.s);
    remove(&base);
}
