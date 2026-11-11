// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The macOS backend: an unlinked POSIX shared memory object.
//!
//! macOS sizes a POSIX shared memory object once and never resizes it, so the
//! size seals hold as soon as the object has a size (also `SealShrink` alone
//! forbids growing).
//!
//! A huge page memfd (`MFD_HUGETLB`, 2 MiB) is an object named
//! `libc::HUGE_MEMFD_PREFIX` (`/fcmH.<pid>.<n>`): the compatibility `libc`'s
//! `mmap` reads the name back (`proc_pidfdinfo`) and maps it in 2 MiB pages
//! as hugetlbfs does, with or without `MAP_HUGETLB`, refusing an offset off
//! a huge page and a size that is not whole huge pages (which hugetlbfs
//! refuses at `ftruncate`; here it is caught at the mapping). Other huge
//! page sizes have no pool here (`ENODEV`, as Linux without one).

use std::ffi::CString;
use std::fs::File;
use std::io;
pub(crate) use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

/// A new, unlinked object; a huge page one if `huge` (2 MiB).
pub(crate) fn create(cloexec: bool, huge: Option<crate::HugetlbSize>) -> io::Result<File> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let prefix = match huge {
        None => "/fcm.",
        Some(crate::HugetlbSize::Huge2MB) => libc::HUGE_MEMFD_PREFIX,
        Some(size) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("no {size:?} huge pages on this host (ENODEV on Linux without such a pool)"),
            ));
        }
    };
    // macOS limits shm names to 31 bytes; the name only has to be unique
    // briefly (a huge page object's name is its mark, kept after unlink).
    let shm_name = format!(
        "{prefix}{}.{}",
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
