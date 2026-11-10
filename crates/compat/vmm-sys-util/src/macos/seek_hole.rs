// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `vmm_sys_util::seek_hole` on macOS: `lseek` with `SEEK_HOLE`/`SEEK_DATA`,
//! which macOS (APFS) has with the Linux semantics, including `ENXIO` past the
//! last data or the end of the file.

use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::io::AsRawFd;

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

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::io::AsRawFd;

    use super::*;
    use crate::tempfile::TempFile;

    const MIB: u64 = 1 << 20;

    fn punch(file: &File, offset: u64, len: u64) {
        let arg = libc::fpunchhole_t {
            fp_flags: 0,
            reserved: 0,
            fp_offset: offset as libc::off_t,
            fp_length: len as libc::off_t,
        };
        // SAFETY: `arg` outlives the call.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &arg) },
            0
        );
    }

    #[test]
    fn test_seek_hole_and_data() {
        let tmp = TempFile::new().unwrap();
        let mut file = tmp.into_file();
        // Empty: no data, no hole.
        assert_eq!(file.seek_data(0).unwrap(), None);
        assert_eq!(file.seek_hole(0).unwrap(), None);

        // APFS keeps a hole only before the first data and where one is
        // punched (it allocates zeros for gaps and extensions after data).
        // Layout: hole [0, 16M), data [16M, 17M), punched [17M, 18M), data [18M, 19M).
        file.seek(SeekFrom::Start(16 * MIB)).unwrap();
        file.write_all(&vec![0x5a; 3 * MIB as usize]).unwrap();
        file.sync_all().unwrap();
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
}
