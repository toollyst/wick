// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! SIGPIPE on a write after the peer's close, as Linux raises it, counted
//! by upstream's handler (`signals.sigpipe`). Each case runs in a process of
//! its own with Firecracker's handlers; on Linux they check the kernel, on
//! macOS the compatibility libc's write wrappers (`wick_uffd::syscalls`).
//!
//! Linux (net/unix/af_unix.c `unix_stream_sendmsg`, `pipe_err`): a write to
//! a stream socket that fails with `EPIPE` having sent nothing raises
//! SIGPIPE on the calling thread (`send_sig(SIGPIPE, current, 0)`,
//! `PIDTYPE_PID`), unless the call passed `MSG_NOSIGNAL`; `write(2)` passes
//! no flags. A pipe with no reader raises it too (fs/pipe.c `pipe_write`).
//! Rust's std writes a `UnixStream` with `send(.., MSG_NOSIGNAL)`
//! (library/std/src/os/unix/net/stream.rs, `Write for &UnixStream`), so no
//! signal.
#![cfg(test)]

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

use crate::logger::{IncMetric, METRICS};

/// Runs `case` in a process of its own (`sigpipe_child`) and asserts it
/// passed.
fn run(case: &str) {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ext::sigpipe_tests::sigpipe_child", "--ignored", "--nocapture", "--test-threads=1"])
        .env("WICK_TEST_CASE", case)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SIGPIPE-CASE-OK"),
        "{case}: {:?}\n--- stdout\n{stdout}\n--- stderr\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A connection made by std (on macOS std sets `SO_NOSIGPIPE` on what it
/// makes, and accepted connections inherit it) whose peer has closed.
fn std_socket_with_closed_peer() -> (UnixStream, vmm_sys_util::tempdir::TempDir) {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let client = UnixStream::connect(&path).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    drop(client);
    (accepted, dir)
}

/// A raw call's result, with errno read at once.
fn raw(ret: isize) -> std::io::Result<usize> {
    usize::try_from(ret).map_err(|_| std::io::Error::last_os_error())
}

/// SIGPIPEs counted after `write`, which must fail with `EPIPE` (the errno
/// the caller sees); the count is read after the signal had time to come
/// (xnu sends its own to the process, which may take it on another thread).
fn sigpipes_of(write: impl FnOnce() -> std::io::Result<usize>) -> u64 {
    let before = METRICS.signals.sigpipe.count();
    let err = write().unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EPIPE), "{err}");
    std::thread::sleep(std::time::Duration::from_millis(200));
    METRICS.signals.sigpipe.count() - before
}

// write(2) to a std-made stream socket after the peer's close: EPIPE and one
// SIGPIPE, as Linux's unix_stream_sendmsg raises for a write without
// MSG_NOSIGNAL.
#[test]
fn test_a_raw_write_to_a_closed_peer_raises_one_sigpipe() {
    run("raw-std");
}

// The same on a socket pair, which std makes without SO_NOSIGPIPE (xnu raises
// the signal itself there): still one, not two.
#[test]
fn test_a_raw_write_to_a_closed_socket_pair_raises_one_sigpipe() {
    run("raw-pair");
}

// std's write (send with MSG_NOSIGNAL on Linux) and sendmsg with MSG_NOSIGNAL
// (vmm-sys-util's, for vhost-user and a page fault handler): EPIPE and no
// SIGPIPE, on Linux and here.
#[test]
fn test_writes_with_no_signal_raise_no_sigpipe() {
    run("nosignal");
}

// A pipe with no reader: one SIGPIPE (Linux's pipe_write; xnu raises it
// itself, and the wrappers, which find no socket, add none).
#[test]
fn test_a_write_to_a_pipe_without_reader_raises_one_sigpipe() {
    run("pipe");
}

// A thread that blocks SIGPIPE: the signal stays pending for that thread, as
// Linux's send_sig to the calling thread leaves it, and comes when it
// unblocks it.
#[test]
fn test_a_blocked_sigpipe_stays_pending_for_the_thread() {
    run("blocked");
}

#[test]
#[ignore = "run by the test_*sigpipe* tests of ext::sigpipe_tests in a separate process"]
fn sigpipe_child() {
    crate::signal_handler::register_signal_handlers().unwrap();
    let byte = [7u8];
    match std::env::var("WICK_TEST_CASE").unwrap().as_str() {
        "raw-std" => {
            let (socket, _dir) = std_socket_with_closed_peer();
            // SAFETY: one byte from a valid buffer.
            let n = sigpipes_of(|| raw(unsafe { libc::write(socket.as_raw_fd(), byte.as_ptr().cast(), 1) }));
            assert_eq!(n, 1);
        }
        "raw-pair" => {
            let (socket, peer) = UnixStream::pair().unwrap();
            drop(peer);
            // SAFETY: as above.
            let n = sigpipes_of(|| raw(unsafe { libc::write(socket.as_raw_fd(), byte.as_ptr().cast(), 1) }));
            assert_eq!(n, 1);
        }
        "nosignal" => {
            let (socket, _dir) = std_socket_with_closed_peer();
            let n = sigpipes_of(|| (&socket).write(&byte));
            assert_eq!(n, 0);
            let mut iov = libc::iovec { iov_base: byte.as_ptr() as *mut _, iov_len: 1 };
            // SAFETY: a zeroed msghdr with one iovec.
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            // SAFETY: a valid msghdr.
            let n = sigpipes_of(|| raw(unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) }));
            assert_eq!(n, 0);
        }
        "pipe" => {
            let mut fds = [0; 2];
            // SAFETY: a two-element output buffer.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            // SAFETY: the read end, made just above.
            unsafe { libc::close(fds[0]) };
            // SAFETY: one byte from a valid buffer.
            let n = sigpipes_of(|| raw(unsafe { libc::write(fds[1], byte.as_ptr().cast(), 1) }));
            assert_eq!(n, 1);
        }
        "blocked" => {
            let (socket, _dir) = std_socket_with_closed_peer();
            // SAFETY: a set of one signal, for this thread.
            let set = unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGPIPE);
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                set
            };
            // SAFETY: as above.
            let n = sigpipes_of(|| raw(unsafe { libc::write(socket.as_raw_fd(), byte.as_ptr().cast(), 1) }));
            assert_eq!(n, 0, "a blocked SIGPIPE was handled");
            // SAFETY: an output set.
            let pending = unsafe {
                let mut p: libc::sigset_t = std::mem::zeroed();
                libc::sigpending(&mut p);
                libc::sigismember(&p, libc::SIGPIPE)
            };
            assert_eq!(pending, 1, "no SIGPIPE pending");
            let before = METRICS.signals.sigpipe.count();
            // SAFETY: the set blocked above.
            unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
            assert_eq!(METRICS.signals.sigpipe.count(), before + 1);
        }
        other => panic!("{other}"),
    }
    println!("SIGPIPE-CASE-OK");
}
