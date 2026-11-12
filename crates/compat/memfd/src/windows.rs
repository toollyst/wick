// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Windows backend: a temporary file that has no name and goes away
//! with its last handle, like a memfd.
//!
//! The file is created with `FILE_FLAG_DELETE_ON_CLOSE` and unlinked at
//! once (POSIX delete semantics), with no sharing, so no other open can
//! reach it. It is marked temporary, so Windows keeps its pages in memory
//! rather than writing them back, as long as memory allows.
//!
//! A size seal attaches a section of the file at its size to the
//! descriptor (`libc::wick_mm::Section`):
//! - mappings of the descriptor are views of that section, so they never
//!   change size;
//! - while the section exists Windows refuses to truncate the file below
//!   it, for every handle, in every process;
//! - the compatibility libc refuses `ftruncate`, and a `write`/`pwrite`
//!   past the end under `SealGrow`, with `EPERM`;
//! - `sock_ctrl_msg` sends the section with the descriptor, so a receiver
//!   maps the same fixed-size section and has the same checks.
//!
//! On Windows `SealGrow` alone therefore also prevents shrinking, and
//! `std::fs::File::set_len` in this process does not pass through the
//! compatibility libc: it can still grow a file sealed with `SealGrow`.
//! Mappings, in this process and in receivers, keep the sealed size.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(crate) use wick_os::fd::{AsRawFd, IntoRawFd, RawFd};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_EXISTS, GENERIC_READ, GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_TEMPORARY, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_DELETE_ON_CLOSE,
    FileDispositionInfoEx, SetFileInformationByHandle,
};
use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};

/// A new temporary file with no name. `EMFILE` past the jail's no-file
/// limit (`libc::wick_nofile`), as `memfd_create` on Linux.
pub(crate) fn create(cloexec: bool) -> io::Result<File> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    libc::wick_nofile::check(1)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: i32::from(!cloexec),
    };
    let h = loop {
        let path = std::env::temp_dir().join(format!(
            "wick-memfd-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: valid path and attributes; the result is checked.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            break h;
        }
        // SAFETY: plain call.
        if unsafe { GetLastError() } != ERROR_FILE_EXISTS {
            return Err(io::Error::last_os_error());
        }
    };
    // SAFETY: a fresh handle we own.
    let file = unsafe { File::from_raw_handle(h) };
    // Unlink the name now. File systems without POSIX delete (FAT) keep it
    // until the last handle goes, which deletes it.
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: valid information of the right class and size.
    unsafe {
        SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            (&raw const info).cast(),
            u32::try_from(std::mem::size_of_val(&info)).unwrap(),
        )
    };
    Ok(file)
}

/// Fixes the size of `file`: attaches a section at its current size (a new
/// one when it changed since an earlier seal), sealed against growth if
/// `grow`.
pub(crate) fn seal_size(file: &File, grow: bool) -> io::Result<()> {
    let fd = file.as_raw_fd();
    let size = file.metadata()?.len();
    if let Some(s) = libc::wick_fd::attached::<libc::wick_mm::Section>(fd) {
        if s.size == size {
            s.grow_sealed.fetch_or(grow, Ordering::AcqRel);
            return Ok(());
        }
    }
    // SAFETY: a section of the whole file, at its size; checked below.
    #[allow(clippy::cast_possible_truncation)]
    let section = unsafe {
        CreateFileMappingW(
            file.as_raw_handle(),
            std::ptr::null(),
            PAGE_READWRITE,
            (size >> 32) as u32,
            size as u32,
            std::ptr::null(),
        )
    };
    if section.is_null() {
        return Err(io::Error::last_os_error());
    }
    let section = libc::wick_mm::Section {
        handle: section as usize,
        size,
        grow_sealed: AtomicBool::new(grow),
    };
    libc::wick_fd::attach(fd, Arc::new(section))
}

#[cfg(test)]
pub(crate) fn check_size_sealed(file: &File, size: u64) {
    use std::io::{Seek, SeekFrom, Write};
    let fd = file.as_raw_fd();
    let size = i64::try_from(size).unwrap();
    // SAFETY: calls on our descriptor.
    unsafe {
        assert_eq!(libc::ftruncate(fd, size * 2), -1);
        assert_eq!(libc::ftruncate(fd, size / 2), -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        assert_eq!(libc::pwrite(fd, b"x".as_ptr().cast(), 1, size), -1);
        assert_eq!(
            libc::pwrite(fd, b"xy".as_ptr().cast(), 2, size - 1),
            1,
            "short"
        );
    }
    // Windows itself refuses truncating below the section, even through std.
    file.set_len(u64::try_from(size / 2).unwrap()).unwrap_err();
    let mut f = file;
    f.seek(SeekFrom::Start(0)).unwrap();
    f.write_all(b"in bounds").unwrap();
}
