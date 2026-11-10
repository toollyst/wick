// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`HoleKeeper`] on macOS (and Windows).
//!
//! APFS allocates (and zero-fills) the gap between two writes to a sparse
//! file, so after a dump the file has data where Linux would have holes. It
//! does so when the file is flushed, not at the write: until then
//! `SEEK_DATA` still reports the gap as a hole. The holes are mapped with
//! `SEEK_HOLE`/`SEEK_DATA` before writing; afterwards the file is flushed, and
//! every part of them that was not written and now holds data is punched out.
//!
//! Windows uses the same backend over NTFS sparse files (`SEEK_DATA` and
//! punching come from the compatibility libc). NTFS allocates sparse files
//! in 64 KiB units, so a write into part of a unit allocates the rest with
//! zeros, and punching can only free whole units. After punching, every
//! region that was not written is checked to be a hole again; if one is not,
//! [`HoleKeeper::restore`] fails rather than leave zeros where Linux leaves a
//! hole (a diff snapshot would carry them as data).

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;

use crate::platform::fs::HoleKeeper;

/// `FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE`.
const PUNCH_HOLE: libc::c_int = 0x03;

/// APFS blocks are 4 KiB; NTFS frees sparse files in 64 KiB units.
#[cfg(not(windows))]
pub const HOLE_UNIT: usize = 4096;
/// APFS blocks are 4 KiB; NTFS frees sparse files in 64 KiB units.
#[cfg(windows)]
pub const HOLE_UNIT: usize = 64 * 1024;

/// Makes `file` keep holes: APFS files always do; a Windows file is made
/// sparse.
pub fn keep_holes(file: &File) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        use windows_sys::Win32::System::Ioctl::{FILE_SET_SPARSE_BUFFER, FSCTL_SET_SPARSE};
        let sparse = FILE_SET_SPARSE_BUFFER { SetSparse: true };
        let mut n = 0u32;
        // SAFETY: valid input of the right size; no output.
        let ok = unsafe {
            DeviceIoControl(
                std::os::windows::io::AsRawHandle::as_raw_handle(file),
                FSCTL_SET_SPARSE,
                std::ptr::from_ref(&sparse).cast(),
                u32::try_from(std::mem::size_of_val(&sparse)).unwrap(),
                std::ptr::null_mut(),
                0,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(windows))]
    let _ = file;
    Ok(())
}

/// The holes a file had, and what has been written since.
#[derive(Debug)]
pub struct Holes {
    holes: Vec<(u64, u64)>,
    written: Vec<(u64, u64)>,
}

fn lseek(fd: libc::c_int, offset: u64, whence: libc::c_int) -> io::Result<Option<u64>> {
    let offset =
        libc::off_t::try_from(offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: lseek on a descriptor the caller owns.
    let ret = unsafe { libc::lseek(fd, offset, whence) };
    if ret >= 0 {
        return Ok(Some(ret.cast_unsigned()));
    }
    let err = io::Error::last_os_error();
    // ENXIO: no hole/data at or after `offset`.
    if err.raw_os_error() == Some(libc::ENXIO) {
        Ok(None)
    } else {
        Err(err)
    }
}

/// `[start, end)` ranges of `holes` not covered by the sorted, merged `written`.
fn unwritten(holes: &[(u64, u64)], written: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(start, end) in holes {
        let mut cur = start;
        for &(ws, we) in written {
            if we <= cur || ws >= end {
                continue;
            }
            if ws > cur {
                out.push((cur, ws));
            }
            cur = cur.max(we);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            out.push((cur, end));
        }
    }
    out
}

fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

impl HoleKeeper for Holes {
    fn new(file: &File) -> io::Result<Self> {
        let fd = file.as_raw_fd();
        let size = file.metadata()?.len();
        let saved = lseek(fd, 0, libc::SEEK_CUR)?.unwrap_or(0);
        let mut holes = Vec::new();
        let mut pos = 0;
        let scan = (|| {
            while pos < size {
                let Some(hole) = lseek(fd, pos, libc::SEEK_HOLE)? else {
                    break;
                };
                if hole >= size {
                    break;
                }
                let end = lseek(fd, hole, libc::SEEK_DATA)?.unwrap_or(size).min(size);
                holes.push((hole, end));
                pos = end;
            }
            Ok::<(), io::Error>(())
        })();
        lseek(fd, saved, libc::SEEK_SET)?;
        scan?;
        // Past the end of the file everything is a hole.
        holes.push((size, u64::MAX));
        Ok(Holes {
            holes,
            written: Vec::new(),
        })
    }

    fn written(&mut self, start: u64, len: u64) {
        if len > 0 {
            self.written.push((start, start.saturating_add(len)));
        }
    }

    fn restore(self, file: &File) -> io::Result<()> {
        let fd = file.as_raw_fd();
        // APFS fills the gaps when the data is flushed; flush first so that
        // the fill is there to be punched (and cannot appear afterwards).
        file.sync_data()?;
        let size = file.metadata()?.len();
        let saved = lseek(fd, 0, libc::SEEK_CUR)?.unwrap_or(0);
        let unwritten = unwritten(&self.holes, &merge(self.written));
        let result = (|| {
            for &(start, end) in &unwritten {
                let end = end.min(size);
                if start >= end {
                    continue;
                }
                // Punch only where APFS put data.
                let Some(data) = lseek(fd, start, libc::SEEK_DATA)? else {
                    continue;
                };
                if data >= end {
                    continue;
                }
                let (Ok(off), Ok(len)) = (
                    libc::off_t::try_from(data),
                    libc::off_t::try_from(end - data),
                ) else {
                    return Err(io::Error::from_raw_os_error(libc::EFBIG));
                };
                // SAFETY: fallocate on a descriptor the caller owns.
                if unsafe { libc::fallocate(fd, PUNCH_HOLE, off, len) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // A file system that frees only whole allocation units may keep
            // zeros where nothing was written.
            for &(start, end) in &unwritten {
                let end = end.min(size);
                if start >= end {
                    continue;
                }
                if let Some(data) = lseek(fd, start, libc::SEEK_DATA)?.filter(|d| *d < end) {
                    return Err(io::Error::other(format!(
                        "the file system keeps zero-filled data at {data:#x}, where nothing was \
                         written: it allocates sparse files in units larger than the writes \
                         (NTFS: 64 KiB), so the unwritten region cannot be a hole"
                    )));
                }
            }
            Ok(())
        })();
        lseek(fd, saved, libc::SEEK_SET)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unwritten() {
        let holes = [(0, 100), (200, 300)];
        let written = merge(vec![(50, 60), (10, 20), (15, 30), (90, 210), (290, 400)]);
        assert_eq!(written, vec![(10, 30), (50, 60), (90, 210), (290, 400)]);
        assert_eq!(
            unwritten(&holes, &written),
            vec![(0, 10), (30, 50), (60, 90), (210, 290)]
        );
        assert_eq!(unwritten(&holes, &[]), holes.to_vec());
    }
}
