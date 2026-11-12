// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A full pipe made non-blocking through another descriptor, as the
//! Windows port's compatibility layer must reproduce it: upstream's
//! `set_stdout_nonblocking` sets `O_NONBLOCK` on fd 1, and every descriptor
//! of that open file description has it (fs/fcntl.c `setfl` sets
//! `filp->f_flags`), including the ones a parent process and its other
//! children hold. A write to it once full fails with `EAGAIN` (fs/pipe.c,
//! `anon_pipe_write`: with `O_NONBLOCK` and the pipe full, `if (!ret) ret =
//! -EAGAIN; break;`), so std's `write_all` fails with
//! `ErrorKind::WouldBlock`, not `WriteZero`.
#![cfg(test)]

use std::io::{ErrorKind, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// A pipe of 64 KiB (Linux's default, 16 pages, PIPE_DEF_BUFFERS; set here
// to be sure) with nobody reading, O_NONBLOCK set through a duplicate of
// its write end, and 70 KiB written to the original descriptor: the write
// stops at the full pipe with WouldBlock.
#[test]
fn test_a_full_pipe_made_non_blocking_through_a_duplicate_is_would_block() {
    let mut fds = [0; 2];
    // SAFETY: room for two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: just made, owned from here.
    let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a pipe descriptor of ours.
        let size = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, 64 * 1024) };
        assert_eq!(size, 64 * 1024, "{}", std::io::Error::last_os_error());
    }
    // SAFETY: duplicates a descriptor of ours.
    let dup = unsafe { libc::dup(writer.as_raw_fd()) };
    assert!(dup >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: just made, owned from here.
    let dup = unsafe { OwnedFd::from_raw_fd(dup) };
    // SAFETY: plain calls on a descriptor of ours.
    unsafe {
        let flags = libc::fcntl(dup.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(libc::fcntl(dup.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
        assert_ne!(
            libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) & libc::O_NONBLOCK,
            0,
            "O_NONBLOCK set through the duplicate is the original descriptor's too"
        );
    }
    let mut file = std::fs::File::from(writer);
    let err = file.write_all(&vec![7u8; 70 * 1024]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WouldBlock, "{err:?}");
    assert_eq!(err.raw_os_error(), Some(libc::EAGAIN));
    // The reader stays open to here: without one the write is EPIPE.
    drop(reader);
}
