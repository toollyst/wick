// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The macOS backend: an unlinked POSIX shared memory object.
//!
//! macOS sizes a POSIX shared memory object once and never resizes it, so the
//! size seals hold as soon as the object has a size (also `SealShrink` alone
//! forbids growing).

use std::ffi::CString;
use std::fs::File;
use std::io;
pub(crate) use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

/// A new, unlinked object.
pub(crate) fn create(cloexec: bool) -> io::Result<File> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // macOS limits shm names to 31 bytes; the name only has to be unique briefly.
    let shm_name = format!(
        "/fcm.{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let cname = CString::new(shm_name).map_err(io::Error::other)?;
    // SAFETY: valid C string; the result is checked.
    let fd = unsafe {
        libc::shm_open(
            cname.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: valid C string. Unlinking keeps the object alive through `fd` only.
    unsafe { libc::shm_unlink(cname.as_ptr()) };
    if !cloexec {
        // SAFETY: descriptor we own.
        unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    }
    // SAFETY: fresh descriptor we own.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// The OS already refuses to resize a sized object.
pub(crate) fn seal_size(_file: &File, _grow: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) fn check_size_sealed(file: &File, size: u64) {
    file.set_len(size * 2).unwrap_err();
    file.set_len(size / 2).unwrap_err();
}
