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
//!
//! An object maps shared only. Linux maps a memfd private copy-on-write, as
//! any file. macOS refuses a shared memory object's mapping without
//! `MAP_SHARED` (xnu-12377.1.9 bsd/kern/posix_shm.c `pshm_mmap` :763 to
//! :765), and a copy of it would not follow the object until its own write
//! as Linux's mapping does. So the compatibility `libc`'s `mmap` refuses a
//! private mapping of one with `EINVAL` before it changes anything
//! (`test_a_private_mapping_of_a_shared_memory_object_is_refused`).
//! Firecracker maps its memfds shared only (`memfd_backed` in
//! vstate/memory.rs, `IovDeque`).

use std::ffi::CString;
use std::fs::File;
use std::io;
pub(crate) use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

/// The mode an object has while it has its name: its owner may open it for
/// reading and writing, others not at all (SECURITY.md, "macOS: a memfd and
/// a waiter mirror have a name while they are made").
const MODE: libc::c_uint = 0o600;

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
            MODE,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Between `create`'s `shm_open` and its `shm_unlink` the object has a
    /// name, and another `shm_open` of that name by the same uid opens it
    /// for reading and writing; once it is unlinked the name opens nothing
    /// (SECURITY.md, "macOS: a memfd and a waiter mirror have a name while
    /// they are made"). An object made with mode 0 is opened again by no one
    /// but root (xnu-12377.121.6 bsd/kern/posix_shm.c `pshm_access` :781 to
    /// :791, which `shm_open` asks of an existing object only, :534), while
    /// its maker keeps the descriptor it made, readable, writable and
    /// mappable: the change that entry proposes.
    #[test]
    fn test_a_shared_memory_objects_name_opens_for_its_uid_until_it_is_unlinked() {
        // SAFETY: no arguments.
        assert_ne!(unsafe { libc::geteuid() }, 0, "root opens any object; run as a user");
        let open = |name: &CString, flags: libc::c_int, mode: libc::c_uint| {
            // SAFETY: a NUL-terminated name; the result is checked by the caller.
            let fd = unsafe { libc::shm_open(name.as_ptr(), flags, mode) };
            if fd < 0 {
                Err(io::Error::last_os_error().raw_os_error())
            } else {
                // SAFETY: a descriptor just opened, ours to close.
                unsafe { libc::close(fd) };
                Ok(())
            }
        };
        for (tag, mode, again) in [("w1", MODE, Ok(())), ("w2", 0, Err(Some(libc::EACCES)))] {
            let name = CString::new(format!("/fcm.{}.{tag}", std::process::id())).unwrap();
            // SAFETY: as above; made as `create` makes an object.
            let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, mode) };
            assert!(fd >= 0, "{}", io::Error::last_os_error());
            // SAFETY: a descriptor just opened, owned by the File from here.
            let file = unsafe { File::from_raw_fd(fd) };
            file.set_len(16384).unwrap();
            // SAFETY: a shared mapping of the object just sized; unmapped below.
            let p = unsafe {
                libc::mmap(std::ptr::null_mut(), 16384, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0)
            };
            assert_ne!(p, libc::MAP_FAILED, "{}", io::Error::last_os_error());
            // SAFETY: the mapping just made, 16384 bytes.
            unsafe {
                p.cast::<u8>().write(1);
                libc::munmap(p, 16384);
            }
            let both = open(&name, libc::O_RDWR, 0);
            let read = open(&name, libc::O_RDONLY, 0);
            // SAFETY: as above; unlinked before any check, so that a failed
            // one leaves no object behind (an object outlives its process).
            let unlinked = unsafe { libc::shm_unlink(name.as_ptr()) };
            assert_eq!(unlinked, 0, "{}", io::Error::last_os_error());
            assert_eq!(both, again, "mode {mode:o}, read and write");
            assert_eq!(read, again, "mode {mode:o}, read");
            assert_eq!(open(&name, libc::O_RDONLY, 0), Err(Some(libc::ENOENT)), "mode {mode:o}, unlinked");
        }
    }
}
