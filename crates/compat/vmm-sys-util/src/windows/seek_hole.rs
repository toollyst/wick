// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `vmm_sys_util::seek_hole` on Windows: `lseek` with `SEEK_HOLE`/`SEEK_DATA`
//! of the compatibility `libc`, which reads the allocated ranges of a sparse
//! NTFS file with the Linux semantics, including `ENXIO` past the last data
//! or the end of the file. The macOS module is the same over APFS.

use std::fs::File;
use std::io::{Error, Result};

use wick_os::fd::AsRawFd;

/// A file with holes.
pub trait SeekHole {
    /// Seek to the first hole in a file.
    ///
    /// Seek at a position greater than or equal to `offset`. If no holes exist
    /// after `offset`, the seek position will be set to the end of the file.
    /// If `offset` is at or after the end of the file, the seek position is
    /// unchanged, and None is returned.
    ///
    /// Returns the current seek position after the seek or an error.
    fn seek_hole(&mut self, offset: u64) -> Result<Option<u64>>;

    /// Seek to the first data in a file.
    ///
    /// Seek at a position greater than or equal to `offset`.
    /// If no data exists after `offset`, the seek position is unchanged,
    /// and None is returned.
    ///
    /// Returns the current offset after the seek or an error.
    fn seek_data(&mut self, offset: u64) -> Result<Option<u64>>;
}

fn lseek(file: &mut File, offset: u64, whence: libc::c_int) -> Result<Option<u64>> {
    let offset = i64::try_from(offset).map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: a valid descriptor; lseek has no memory arguments.
    let res = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
    if res < 0 {
        let err = Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENXIO) {
            return Ok(None);
        }
        return Err(err);
    }
    // Non-negative here.
    #[allow(clippy::cast_sign_loss)]
    Ok(Some(res as u64))
}

impl SeekHole for File {
    fn seek_hole(&mut self, offset: u64) -> Result<Option<u64>> {
        lseek(self, offset, libc::SEEK_HOLE)
    }

    fn seek_data(&mut self, offset: u64) -> Result<Option<u64>> {
        lseek(self, offset, libc::SEEK_DATA)
    }
}

/// What [`holes_kept`] says of a file that is not sparse.
pub const NOT_SPARSE: &str = "the diff file is not a sparse file: on Windows only a sparse file \
                              has holes, so all of it, zeros included, would be copied over the \
                              base. Firecracker writes a diff snapshot as a sparse file; copies \
                              (Copy-Item, copy, robocopy) lose that, and a dense copy cannot be \
                              repaired. Rebase where Firecracker wrote the diff (a move within \
                              the volume keeps it sparse) and move the merged memory file instead";

/// Fails unless `file`'s holes are where its writer left them, for a tool
/// that copies a file's data and skips its holes (`rebase-snap`,
/// `snapshot-editor edit-memory rebase`).
///
/// On Linux a file extended by `set_len`, or written past a gap, has holes
/// there. On Windows only a file marked sparse does: any other file has
/// allocated zeros where Linux has holes, `SEEK_DATA` rightly finds them
/// data, and the tool would copy them over the base. So a file with data
/// that is not sparse is refused (`NOT_SPARSE`, `InvalidInput`). An empty
/// file has nothing to copy and passes.
///
/// This tells a file whose holes were never kept from one that has them; it
/// cannot tell a hole lost from a page of zeros. A dense file marked sparse
/// afterwards passes and is copied whole, zeros included, as on Linux a diff
/// file that lost its holes (a dense copy) is: `SEEK_DATA` finds no hole in
/// either.
pub fn holes_kept(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_SPARSE_FILE, GetFileInformationByHandle,
    };

    // SAFETY: an all-zero struct is a valid output buffer.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the file's handle and a valid output buffer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(Error::last_os_error());
    }
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    if size > 0 && info.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE == 0 {
        return Err(Error::new(std::io::ErrorKind::InvalidInput, NOT_SPARSE));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use super::*;
    use crate::tempfile::TempFile;

    const MIB: u64 = 1 << 20;

    #[allow(clippy::cast_possible_wrap)]
    fn punch(file: &File, offset: u64, len: u64) {
        // SAFETY: a valid descriptor.
        let rc = unsafe {
            libc::fallocate(
                file.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                offset as libc::off_t,
                len as libc::off_t,
            )
        };
        assert_eq!(rc, 0, "{}", Error::last_os_error());
    }

    #[test]
    fn test_seek_hole_and_data() {
        let tmp = TempFile::new().unwrap();
        let mut file = tmp.into_file();
        // Empty: no data, no hole.
        assert_eq!(file.seek_data(0).unwrap(), None);
        assert_eq!(file.seek_hole(0).unwrap(), None);

        // Layout: hole [0, 16M), data [16M, 17M), hole [17M, 18M), data [18M, 19M).
        file.write_all(&vec![0x5a; 19 * MIB as usize]).unwrap();
        file.sync_all().unwrap();
        punch(&file, 0, 16 * MIB);
        punch(&file, 17 * MIB, MIB);

        assert_eq!(file.seek_data(0).unwrap(), Some(16 * MIB));
        assert_eq!(file.stream_position().unwrap(), 16 * MIB);
        assert_eq!(file.seek_hole(16 * MIB).unwrap(), Some(17 * MIB));
        assert_eq!(file.seek_data(17 * MIB).unwrap(), Some(18 * MIB));
        // No hole up to the end: the end of the file.
        assert_eq!(file.seek_hole(18 * MIB).unwrap(), Some(19 * MIB));
        // At or past the end: None, and the position is unchanged.
        assert_eq!(file.seek_data(19 * MIB).unwrap(), None);
        assert_eq!(file.seek_hole(19 * MIB).unwrap(), None);
        assert_eq!(file.stream_position().unwrap(), 19 * MIB);
    }

    #[test]
    fn test_holes_kept_only_in_a_sparse_file() {
        // Extended by set_len, as upstream's tools and tests make holes:
        // on NTFS a file not marked sparse has no hole there.
        let mut dense = TempFile::new().unwrap().into_file();
        assert!(holes_kept(&dense).is_ok(), "an empty file has nothing to copy");
        dense.set_len(MIB).unwrap();
        dense.write_all(&[0x5a; 4096]).unwrap();
        assert_eq!(dense.seek_hole(0).unwrap(), Some(MIB), "no hole in a file not sparse");
        let err = holes_kept(&dense).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), NOT_SPARSE);

        // The same, sparse (as `fallocate`'s punching or Firecracker's
        // snapshot path make it): the extension is a hole.
        let mut sparse = TempFile::new().unwrap().into_file();
        sparse.set_len(MIB).unwrap();
        punch(&sparse, 0, MIB);
        sparse.write_all(&[0x5a; 4096]).unwrap();
        holes_kept(&sparse).unwrap();
        assert_eq!(sparse.seek_hole(0).unwrap(), Some(64 * 1024), "a hole from the next 64 KiB unit");
    }
}
