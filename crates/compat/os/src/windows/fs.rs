// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `std::os::unix::{fs, ffi}` on Windows: the parts with the same meaning.
//!
//! Left out on purpose, because `std::fs::Metadata` and `FileType` on Windows
//! do not carry the information, and answering anyway would be a guess:
//! `FileTypeExt` (block and character devices, FIFOs, sockets), the
//! `MetadataExt` accessors other than `size` (`dev`, `ino`, `mode`, `blocks`,
//! ...), `OpenOptionsExt` and `PermissionsExt`. Code that needs them goes
//! through `vmm::platform`, which asks the handle itself.

use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Seek, SeekFrom};
use std::os::windows::fs::FileExt as _;

/// `std::os::unix::fs::FileExt`: reads and writes at an offset.
///
/// Unix's `pread`/`pwrite` leave the file position alone. Windows' positioned
/// I/O on a synchronous handle moves it, so the position is put back after
/// each call. A Windows file object has one position for all its handles, so
/// a thread that uses the position of the same file while another does
/// positioned I/O must synchronise with it, as on Unix with `lseek`+`read`.
pub trait FileExt {
    /// `pread`.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;
    /// `pwrite`.
    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize>;

    /// Reads exactly `buf.len()` bytes at `offset`.
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(buf, offset) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if buf.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
        }
    }

    /// Writes all of `buf` at `offset`.
    fn write_all_at(&self, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match self.write_at(buf, offset) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

fn keeping_position<T>(
    mut file: &File,
    f: impl FnOnce(&File) -> io::Result<T>,
) -> io::Result<T> {
    let pos = file.stream_position()?;
    let r = f(file);
    file.seek(SeekFrom::Start(pos))?;
    r
}

impl FileExt for File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        keeping_position(self, |f| match f.seek_read(buf, offset) {
            // Reading at or past the end is end of file, as with `pread`.
            Err(e) if e.raw_os_error() == Some(38) => Ok(0), // ERROR_HANDLE_EOF
            r => r,
        })
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        keeping_position(self, |f| f.seek_write(buf, offset))
    }
}

/// `std::os::unix::fs::MetadataExt`, the accessors Windows metadata has.
pub trait MetadataExt {
    /// `st_size`.
    fn size(&self) -> u64;
}

impl MetadataExt for Metadata {
    fn size(&self) -> u64 {
        self.len()
    }
}

/// `std::os::unix::ffi::OsStrExt`.
///
/// Windows strings are UTF-16; as bytes they are UTF-8 (WTF-8 for unpaired
/// surrogates). Bytes that are not UTF-8 cannot name anything on Windows, so
/// [`OsStrExt::from_bytes`] panics on them.
pub trait OsStrExt {
    /// The string from bytes.
    fn from_bytes(slice: &[u8]) -> &Self;
    /// The bytes of the string.
    fn as_bytes(&self) -> &[u8];
}

impl OsStrExt for OsStr {
    fn from_bytes(slice: &[u8]) -> &OsStr {
        match std::str::from_utf8(slice) {
            Ok(s) => OsStr::new(s),
            Err(e) => panic!("OsStr::from_bytes: not UTF-8 on Windows: {e}"),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_encoded_bytes()
    }
}

/// `std::os::unix::ffi::OsStringExt`.
pub trait OsStringExt {
    /// The string from bytes.
    fn from_vec(vec: Vec<u8>) -> Self;
    /// The bytes of the string.
    fn into_vec(self) -> Vec<u8>;
}

impl OsStringExt for OsString {
    fn from_vec(vec: Vec<u8>) -> OsString {
        match String::from_utf8(vec) {
            Ok(s) => s.into(),
            Err(e) => panic!("OsString::from_vec: not UTF-8 on Windows: {e}"),
        }
    }

    fn into_vec(self) -> Vec<u8> {
        self.into_encoded_bytes()
    }
}
