// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! docs/design-fs.md row 2 and §11 item 3: a host thread swaps a directory
//! in the share with a symlink to a directory outside it, atomically and
//! without pause, while the guest works through the name. Nothing may happen
//! outside the share; a layer-2 refusal is the expected answer to a swap
//! that lands between the server's look and its open. It runs twice: with
//! the default cache of held descriptors, and with a cache of two, where
//! every directory is opened again by its name between requests (ESTALE
//! when the swap moved it, docs/design-fs.md §4.3).
//!
//! `WICK_FS_RACE_ITERATIONS` sets the guest's rounds (default 10⁵, each
//! about ten requests: 10⁶ requests against the swap). A
//! watchdog ends the process if a round stops making progress for 30 s, so a
//! hang fails the test instead of the job's timeout.

#![cfg(any(target_os = "linux", target_os = "macos"))]
// An integration test file is itself the test crate.
#![allow(clippy::tests_outside_test_module)]

mod common;

use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::*;
use wick_fs_sys as sys;
use wick_fsd::fuse::{Errno, Opcode};
use wick_fsd::limits::Limits;
use wick_fsd::session::Config;

fn watchdog(progress: Arc<AtomicU64>, done: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last = (0, Instant::now());
        while !done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
            let p = progress.load(Ordering::SeqCst);
            if p != last.0 {
                last = (p, Instant::now());
            } else if last.1.elapsed() > Duration::from_secs(30) {
                eprintln!("test_swap_race: no progress for 30 s at round {p}");
                std::process::abort();
            }
        }
    })
}

#[test]
fn test_swap_race() {
    let rounds: u64 = std::env::var("WICK_FS_RACE_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    race("race", Limits::default(), rounds);
    // A cache of two (the root and one more): every directory is let go
    // between requests and opened again by its name while the swap runs.
    race(
        "race-held",
        Limits {
            max_held: 2,
            ..Limits::default()
        },
        rounds / 2,
    );
}

fn race(tag: &str, limits: Limits, rounds: u64) {
    let config = Config {
        limits,
        ..Config::default()
    };
    let mut h = H::with(tag, config, |_| {});
    let outside = h.outside.clone();
    std::fs::create_dir(h.share.join("d")).unwrap();
    std::fs::write(h.share.join("d/inner"), b"in").unwrap();
    {
        let share = sys::open_root(&h.share).unwrap();
        sys::symlinkat(outside.as_os_str().as_encoded_bytes(), share.as_fd(), b"l").unwrap();
    }
    let canaries = snapshot(&outside);
    let stop = Arc::new(AtomicBool::new(false));
    let swaps = Arc::new(AtomicU64::new(0));
    let swapper = {
        let share = h.share.clone();
        let stop = stop.clone();
        let swaps = swaps.clone();
        std::thread::spawn(move || {
            let dir = sys::open_root(&share).unwrap();
            while !stop.load(Ordering::Relaxed) {
                sys::rename(dir.as_fd(), b"d", dir.as_fd(), b"l", false, true).unwrap();
                swaps.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    let progress = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let dog = watchdog(progress.clone(), done.clone());
    let start = Instant::now();
    let (mut dirs, mut links, mut made) = (0u64, 0u64, 0u64);
    for i in 0..rounds {
        progress.store(i, Ordering::SeqCst);
        let n = if i % 2 == 0 { &b"d"[..] } else { b"l" };
        let Ok(e) = h.lookup(ROOT, n) else {
            continue;
        };
        let node = u64_at(&e, 0);
        let mode = u32_at(&e[ATTR_IN_ENTRY..], A_MODE) & 0o170_000;
        if mode == 0o040_000 {
            dirs += 1;
            // Work inside whatever directory the node is.
            match h.create(node, b"new") {
                Ok((f, fh)) => {
                    let _ = h.write(f, fh, 0, b"x");
                    h.release(f, fh);
                    let _ = h.call(Opcode::Unlink, node, &[&name(b"new")]);
                    made += 1;
                    h.raw(Opcode::Forget as u32, f, &[&le64(1)], 0);
                }
                Err(e) => assert!(matches!(e, Errno::EEXIST | Errno::ENOENT | Errno::EACCES | Errno::ESTALE), "{e:?}"),
            }
            if let Ok(e) = h.lookup(node, b"inner") {
                let inner = u64_at(&e, 0);
                if let Ok(fh) = h.open(inner, 0) {
                    let _ = h.read(inner, fh, 0, 16);
                    h.release(inner, fh);
                }
                h.raw(Opcode::Forget as u32, inner, &[&le64(1)], 0);
            }
            // The new directory's node forgotten, as a guest kernel does.
            if let (0, e) = h.call(Opcode::Mkdir, node, &[&le32(0o755), &le32(0), &name(b"sub")]) {
                h.raw(Opcode::Forget as u32, u64_at(&e, 0), &[&le64(1)], 0);
            }
            let _ = h.call(Opcode::Rmdir, node, &[&name(b"sub")]);
        } else {
            links += 1;
            // Through a symlink node nothing reaches the target: not a
            // directory, or (swapped since) no longer that node.
            let e = h.create(node, b"new").unwrap_err();
            assert!(matches!(e, Errno::ENOTDIR | Errno::ENOENT), "{e:?}");
            let _ = h.open(node, 0);
        }
        // Through the name, again, while the swapper runs.
        if let Ok((f, fh)) = h.create(ROOT, b"top") {
            h.release(f, fh);
            let _ = h.call(Opcode::Rename2, ROOT, &[&le64(node), &le32(0), &le32(0), &name(b"top"), &name(b"moved")]);
            let _ = h.call(Opcode::Unlink, node, &[&name(b"moved")]);
            let _ = h.call(Opcode::Unlink, ROOT, &[&name(b"top")]);
            h.raw(Opcode::Forget as u32, f, &[&le64(1)], 0);
        }
        h.raw(Opcode::Forget as u32, node, &[&le64(1)], 0);
        if i % 4096 == 0 {
            assert_eq!(snapshot(&outside), canaries, "round {i}: the directory outside the share changed");
        }
    }
    stop.store(true, Ordering::SeqCst);
    swapper.join().unwrap();
    done.store(true, Ordering::SeqCst);
    dog.join().unwrap();
    assert_eq!(snapshot(&outside), canaries, "the directory outside the share changed");
    h.canaries_untouched();
    eprintln!(
        "test_swap_race ({tag}, {} held): {rounds} rounds in {:.1?}, {} swaps; directory {dirs}, symlink {links}, files made {made}, \
         layer-2 refusals {}",
        limits.max_held,
        start.elapsed(),
        swaps.load(Ordering::SeqCst),
        h.s.counters().layer_refusals
    );
    assert!(dirs > 0 && links > 0, "the swap was seen both ways");
    assert_eq!(h.s.nodes(), 1, "every node the rounds took was forgotten");
}
