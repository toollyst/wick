// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The serial writing to a full non-blocking standard output, as Firecracker
//! leaves it when the serial writes there (`set_stdout_nonblocking`), with
//! the same results on every host.
//!
//! Linux: a write to a full non-blocking pipe fails with `EAGAIN` (fs/pipe.c
//! `anon_pipe_write`, `if (!ret) ret = -EAGAIN`), and std's `Stdout`, a
//! `LineWriter` on `write(2)`, reports `ErrorKind::WouldBlock` and keeps what
//! it could not write in its buffer. vm-superio's serial writes each byte
//! with `write_all` and `flush` and counts a failure as a lost byte
//! (`tx_lost_byte`: `missed_write_count`), and the serial device counts the
//! error (`error_count`); the error's kind is not looked at. On Windows
//! `std::io::stdout()` is `wick_os::stdio::Stdout` (wick-std), which gives the
//! same results; std's own reported `ErrorKind::WriteZero`, with the same
//! counts.
#![cfg(test)]

use std::io::{ErrorKind, Write};

use crate::devices::legacy::serial::{METRICS, SerialDevice, SerialOut, SerialOutInner};
use crate::logger::IncMetric;
use crate::vstate::bus::BusDevice;

const CHILD_ENV: &str = "WICK_TEST_SERIAL_STDOUT_CHILD";

// The child changes its own standard output, so it runs in a process of its
// own; its report comes back on the original one.
#[test]
fn test_the_serial_on_a_full_non_blocking_stdout() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ext::serial_stdout_tests::serial_stdout_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("SERIAL-STDOUT-CHILD-OK"),
        "{:?}\n--- stdout\n{stdout}\n--- stderr\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Writes to standard output until a write of 1 byte fails, halving the
/// size at each failure (a Linux pipe that refuses 4096 bytes may still take
/// fewer, in its last page). Returns the bytes written and the error.
fn fill_stdout() -> (usize, std::io::Error) {
    let chunk = [b'.'; 4096];
    let mut size = chunk.len();
    let mut total = 0usize;
    loop {
        // SAFETY: `size` bytes of a valid buffer.
        let n = unsafe { libc::write(libc::STDOUT_FILENO, chunk.as_ptr().cast(), size) };
        let err = std::io::Error::last_os_error();
        if n > 0 {
            total += usize::try_from(n).unwrap();
            assert!(total < 64 << 20, "the pipe never filled");
            continue;
        }
        assert_eq!(n, -1, "a write that takes nothing fails");
        if size == 1 {
            return (total, err);
        }
        size /= 2;
    }
}

/// Reads `n` bytes from `fd`, a blocking pipe.
fn read_exact(fd: libc::c_int, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        // SAFETY: the rest of a valid buffer.
        let r = unsafe { libc::read(fd, buf[got..].as_mut_ptr().cast(), n - got) };
        assert!(r > 0, "{}", std::io::Error::last_os_error());
        got += usize::try_from(r).unwrap();
    }
    buf
}

#[test]
#[ignore = "run by test_the_serial_on_a_full_non_blocking_stdout in a separate process"]
fn serial_stdout_child() {
    assert!(std::env::var_os(CHILD_ENV).is_some(), "run by its parent test");
    let mut fds = [0; 2];
    // SAFETY: room for two descriptors; the standard descriptors are ours.
    let saved = unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        let saved = libc::dup(libc::STDOUT_FILENO);
        assert!(saved >= 0);
        assert_eq!(libc::dup2(fds[1], libc::STDOUT_FILENO), libc::STDOUT_FILENO);
        saved
    };
    // What the device manager does before it gives the serial std's stdout.
    crate::utils::set_stdout_nonblocking();
    let (total, err) = fill_stdout();
    assert_eq!(err.raw_os_error(), Some(libc::EAGAIN), "{err}");

    let mut serial = SerialDevice::new(
        None,
        SerialOut::new(SerialOutInner::Stdout(std::io::stdout()), None),
        None,
    )
    .unwrap();
    let (missed, errors, written) = (
        METRICS.missed_write_count.count(),
        METRICS.error_count.count(),
        METRICS.write_count.count(),
    );
    // The guest writes a byte to the transmitter (offset 0).
    BusDevice::write(&mut serial, 0, 0, b"x");
    assert_eq!(METRICS.missed_write_count.count() - missed, 1, "a lost byte");
    assert_eq!(METRICS.error_count.count() - errors, 1, "a failed write");
    assert_eq!(METRICS.write_count.count(), written);

    // A line written as the logger writes one (logging.rs,
    // `std::io::stdout().write_all`; it counts any error as a missed log),
    // and the error the serial got: WouldBlock, EAGAIN. (No logger is
    // installed in this process: only `Logger::init` sets one.)
    let err = std::io::stdout().write_all(b"line\n").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WouldBlock, "{err:?}");
    assert_eq!(err.raw_os_error(), Some(libc::EAGAIN), "{err:?}");

    // Room again: what the failed flushes left in the buffer goes out with
    // the next flush, as from std's buffer on Linux: the serial's byte, and
    // the line, which `LineWriter::write_all` adds to a non-empty buffer
    // before it flushes (library/std/src/io/buffered/linewritershim.rs).
    assert!(read_exact(fds[0], total).iter().all(|&b| b == b'.'));
    std::io::stdout().flush().unwrap();
    assert_eq!(read_exact(fds[0], 6), b"xline\n");

    // SAFETY: the standard descriptors and our pipe.
    unsafe {
        assert_eq!(libc::dup2(saved, libc::STDOUT_FILENO), libc::STDOUT_FILENO);
        libc::close(saved);
        libc::close(fds[1]);
        libc::close(fds[0]);
    }
    println!("SERIAL-STDOUT-CHILD-OK");
}
