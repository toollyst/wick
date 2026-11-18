// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! macOS implementations of the Linux-only `vmm-sys-util` modules.

#[macro_use]
pub mod ioctl;
pub mod epoll;
pub mod eventfd;
pub mod seek_hole;
pub mod signal;
pub mod terminal;

/// Runs the ignored test `name` (its path in the crate) in a process of its
/// own, which runs nothing else, and checks that it passed: a test that
/// forks does so there, where no other test's thread can hold a lock (the
/// allocator's, a Mutex) that the child of the fork would wait on for good.
#[cfg(test)]
pub(crate) fn run_alone(name: &str) {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--ignored", "--nocapture", "--test-threads=1"])
        .output()
        .unwrap();
    let text = format!(
        "{:?}\n{}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success() && text.contains("1 passed"), "{text}");
}
