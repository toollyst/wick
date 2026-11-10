// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The memfd API on an OS backend (`crate::os`), which creates the file and
//! enforces the size seals.
//!
//! `SealShrink` and `SealGrow` need the file to be sized, and are refused
//! before. `SealSeal` is enforced here. `SealWrite` and `SealFutureWrite`
//! cannot be enforced and are refused with `ENOTSUP`.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::sync::Mutex;

use crate::os;
use crate::os::{AsRawFd, IntoRawFd, RawFd};

/// Errors from this crate.
#[derive(Debug)]
pub enum Error {
    /// Cannot create the object.
    Create(io::Error),
    /// Cannot add seals.
    AddSeals(io::Error),
    /// Cannot read seals.
    GetSeals(io::Error),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Create(e) | Error::AddSeals(e) | Error::GetSeals(e) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::Create(_) => "cannot create a memfd",
            Error::AddSeals(_) => "cannot add seals to the memfd",
            Error::GetSeals(_) => "cannot read seals for a memfd",
        })
    }
}

/// Huge page sizes. None of them is available off Linux.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum HugetlbSize {
    Huge64KB,
    Huge512KB,
    Huge1MB,
    Huge2MB,
    Huge8MB,
    Huge16MB,
    Huge256MB,
    Huge1GB,
    Huge2GB,
    Huge16GB,
}

/// File seals (see the module docs).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(missing_docs)]
pub enum FileSeal {
    SealShrink,
    SealGrow,
    SealWrite,
    SealSeal,
    SealFutureWrite,
}

/// A set of seals.
pub type SealsHashSet = HashSet<FileSeal>;

/// Options for creating a [`Memfd`].
#[derive(Clone, Debug)]
pub struct MemfdOptions {
    allow_sealing: bool,
    cloexec: bool,
    hugetlb: Option<HugetlbSize>,
}

impl MemfdOptions {
    /// Default options: close-on-exec, no sealing, no huge pages.
    pub const fn new() -> Self {
        MemfdOptions {
            allow_sealing: false,
            cloexec: true,
            hugetlb: None,
        }
    }

    /// Allow seals.
    pub const fn allow_sealing(mut self, value: bool) -> Self {
        self.allow_sealing = value;
        self
    }

    /// Close on exec.
    pub const fn close_on_exec(mut self, value: bool) -> Self {
        self.cloexec = value;
        self
    }

    /// Huge pages (creation fails off Linux if set).
    pub const fn hugetlb(mut self, size: Option<HugetlbSize>) -> Self {
        self.hugetlb = size;
        self
    }

    /// Creates the object. `name` is only used for debugging.
    pub fn create<T: AsRef<str>>(&self, name: T) -> Result<Memfd, Error> {
        if self.hugetlb.is_some() {
            return Err(Error::Create(io::Error::new(
                io::ErrorKind::Unsupported,
                "huge pages are not available for memfd on this OS",
            )));
        }
        let _ = name;
        let file = os::create(self.cloexec).map_err(Error::Create)?;
        Ok(Memfd {
            file,
            seals: Mutex::new(HashSet::new()),
            allow_sealing: self.allow_sealing,
        })
    }
}

impl Default for MemfdOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// An anonymous shared memory file.
#[derive(Debug)]
pub struct Memfd {
    file: fs::File,
    seals: Mutex<SealsHashSet>,
    allow_sealing: bool,
}

impl Memfd {
    /// Returns the underlying file.
    pub fn as_file(&self) -> &fs::File {
        &self.file
    }

    /// Converts into the underlying file.
    pub fn into_file(self) -> fs::File {
        self.file
    }

    /// Returns the seals in effect.
    pub fn seals(&self) -> Result<SealsHashSet, Error> {
        Ok(self.seals.lock().unwrap().clone())
    }

    /// Adds a seal. See [`Self::add_seals`].
    pub fn add_seal(&self, seal: FileSeal) -> Result<(), Error> {
        self.add_seals(&[seal])
    }

    /// Adds seals, like `fcntl(F_ADD_SEALS)` on Linux:
    /// - fails with `EPERM` if sealing was not allowed at creation or `SealSeal` is set;
    /// - `SealShrink`/`SealGrow` need the object to be sized already;
    ///   otherwise they fail with `EINVAL` (see `crate::os` for how they are
    ///   enforced);
    /// - `SealWrite`/`SealFutureWrite` fail with `ENOTSUP`.
    ///
    /// Nothing is added unless every seal can be.
    pub fn add_seals<'a>(
        &self,
        seals: impl IntoIterator<Item = &'a FileSeal>,
    ) -> Result<(), Error> {
        let seals: Vec<FileSeal> = seals.into_iter().copied().collect();
        let mut current = self.seals.lock().unwrap();
        let fail = |errno| Err(Error::AddSeals(io::Error::from_raw_os_error(errno)));
        if !self.allow_sealing || current.contains(&FileSeal::SealSeal) {
            return fail(libc::EPERM);
        }
        for seal in &seals {
            match seal {
                FileSeal::SealShrink | FileSeal::SealGrow => {
                    let size = self.file.metadata().map_err(Error::AddSeals)?.len();
                    if size == 0 {
                        return fail(libc::EINVAL);
                    }
                }
                FileSeal::SealSeal => {}
                FileSeal::SealWrite | FileSeal::SealFutureWrite => return fail(libc::ENOTSUP),
            }
        }
        let size_seal = |s| seals.contains(&s) && !current.contains(&s);
        let (shrink, grow) = (
            size_seal(FileSeal::SealShrink),
            size_seal(FileSeal::SealGrow),
        );
        if shrink || grow {
            os::seal_size(&self.file, current.contains(&FileSeal::SealGrow) || grow)
                .map_err(Error::AddSeals)?;
        }
        current.extend(seals);
        Ok(())
    }
}

impl AsRawFd for Memfd {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl IntoRawFd for Memfd {
    fn into_raw_fd(self) -> RawFd {
        self.file.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_resize_map() {
        let mfd = MemfdOptions::default()
            .allow_sealing(true)
            .create("guest_mem")
            .unwrap();
        mfd.as_file().set_len(1 << 20).unwrap();
        mfd.add_seals(&[FileSeal::SealShrink, FileSeal::SealGrow])
            .unwrap();
        mfd.add_seal(FileSeal::SealSeal).unwrap();
        assert_eq!(mfd.seals().unwrap().len(), 3);
        // Two shared mappings of the object see the same bytes.
        let fd = mfd.as_raw_fd();
        // SAFETY: mapping 1 MiB of a 1 MiB shared object; unmapped below.
        unsafe {
            let a = libc::mmap(
                std::ptr::null_mut(),
                1 << 20,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            let b = libc::mmap(
                std::ptr::null_mut(),
                1 << 20,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(a, libc::MAP_FAILED);
            assert_ne!(b, libc::MAP_FAILED);
            *(a as *mut u8).add(4096) = 0x5a;
            assert_eq!(*(b as *const u8).add(4096), 0x5a);
            libc::munmap(a, 1 << 20);
            libc::munmap(b, 1 << 20);
        }
    }

    #[test]
    fn test_seals_are_enforced() {
        let mfd = MemfdOptions::default()
            .allow_sealing(true)
            .create("s")
            .unwrap();
        // Size seals need a size first.
        mfd.add_seal(FileSeal::SealGrow).unwrap_err();
        mfd.as_file().set_len(1 << 16).unwrap();
        mfd.add_seals(&[FileSeal::SealShrink, FileSeal::SealGrow])
            .unwrap();
        // Resizing is refused.
        os::check_size_sealed(mfd.as_file(), 1 << 16);
        // Write seals cannot be enforced.
        mfd.add_seal(FileSeal::SealWrite).unwrap_err();
        // After SealSeal nothing can be added.
        mfd.add_seal(FileSeal::SealSeal).unwrap();
        mfd.add_seal(FileSeal::SealShrink).unwrap_err();
        // Without allow_sealing every seal is refused.
        let plain = MemfdOptions::default().create("p").unwrap();
        plain.as_file().set_len(4096).unwrap();
        plain.add_seal(FileSeal::SealShrink).unwrap_err();
    }

    #[test]
    fn test_hugetlb_is_refused() {
        MemfdOptions::default()
            .hugetlb(Some(HugetlbSize::Huge2MB))
            .create("x")
            .unwrap_err();
    }
}
