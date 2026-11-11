// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Writing files without filling their holes.
//!
//! Snapshots write guest memory with seeks over pages that need not be
//! written (clean pages of a diff snapshot, unplugged memory). Upstream relies
//! on Linux behaviour: a region nobody writes keeps what it had, and a hole
//! stays a hole, so a diff snapshot file has data exactly where pages were
//! dirty (`rebase-snap` copies only those).
//!
//! [`SparseWriter`] gives that behaviour on every host: when it is finished,
//! every region that was a hole before (or lay past the end of the file) and
//! was not written through it is a hole again. On Linux nothing needs to be
//! done; on macOS, APFS fills the gaps between writes with allocated zeros,
//! and the backend punches them out again; on Windows a file keeps holes only
//! if it is sparse ([`keep_holes`]), and NTFS allocates sparse files in
//! 64 KiB units, so writing part of a unit allocates all of it: the backend
//! punches what it can and fails if a region the writer skipped is still
//! data, rather than leave zeros where Linux leaves a hole.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};

use vm_memory::bitmap::BitmapSlice;
use vm_memory::{VolatileMemoryError, VolatileSlice, WriteVolatile};

/// `std::os::unix::fs::FileTypeExt`. On Windows, the queries a
/// `std::fs::FileType` answers there: it describes files, directories and
/// symbolic links only (std cannot read the metadata of a device), so it is
/// never a block or character device, a FIFO or a socket. Raw disks are not
/// drive backends on Windows; drives are files.
#[cfg(not(windows))]
pub use std::os::unix::fs::FileTypeExt;

/// See the Unix re-export.
#[cfg(windows)]
pub trait FileTypeExt {
    /// Never: Windows file types are files, directories and links.
    fn is_block_device(&self) -> bool;
    /// Never, as above.
    fn is_char_device(&self) -> bool;
    /// Never, as above.
    fn is_fifo(&self) -> bool;
    /// Never, as above.
    fn is_socket(&self) -> bool;
}

#[cfg(windows)]
impl FileTypeExt for std::fs::FileType {
    fn is_block_device(&self) -> bool {
        false
    }
    fn is_char_device(&self) -> bool {
        false
    }
    fn is_fifo(&self) -> bool {
        false
    }
    fn is_socket(&self) -> bool {
        false
    }
}

/// The `st_dev`, `st_rdev` and `st_ino` of a file on Windows, whose
/// `std::fs::Metadata` has none: from the handle (`libc::fstat`: the volume
/// serial number and the file index; no device number).
#[cfg(windows)]
#[derive(Debug)]
pub struct StatIds(libc::stat);

#[cfg(windows)]
impl StatIds {
    /// The identifiers of `file`.
    pub fn of(file: &File) -> io::Result<Self> {
        use std::os::unix::io::AsRawFd;
        // SAFETY: an all-zero `stat` is a valid output buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and output buffer.
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(StatIds(st))
    }

    /// The volume.
    pub fn st_dev(&self) -> u64 {
        self.0.st_dev
    }

    /// The device a special file is (none on Windows).
    pub fn st_rdev(&self) -> u64 {
        self.0.st_rdev
    }

    /// The file on its volume.
    pub fn st_ino(&self) -> u64 {
        self.0.st_ino
    }

    /// The id a block device backed by this file reports to the guest
    /// (`VIRTIO_BLK_T_GET_ID`), in place of kvmtool's decimal
    /// `st_dev st_rdev st_ino`, which the driver reads only the first
    /// `VIRTIO_BLK_ID_BYTES` (20) of. On Linux that form fits; a Windows one
    /// (a 32-bit volume serial number, `0` and a 64-bit file index whose top
    /// 16 bits are the NTFS sequence number) is up to 31 digits, so files of
    /// one volume would share an id. Here the volume and the file index, 96
    /// bits, are written as 20 base-32 digits, which keeps every bit: distinct
    /// per file, and the same each time the file is opened, as on Linux.
    pub fn device_id(&self) -> String {
        device_id(self.0.st_dev, self.0.st_ino)
    }
}

/// See [`StatIds::device_id`]: `volume` (a 32-bit serial number) and `index`
/// as one 96-bit number in 20 lowercase base-32 digits (`0-9a-v`), most
/// significant first.
#[cfg(windows)]
fn device_id(volume: u64, index: u64) -> String {
    const DIGITS: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    // `fstat` reports `dwVolumeSerialNumber`: 32 bits.
    let volume = u32::try_from(volume).expect("a volume serial number is 32 bits");
    let id = (u128::from(volume) << 64) | u128::from(index);
    (0..20)
        .rev()
        .map(|digit| char::from(DIGITS[((id >> (5 * digit)) & 31) as usize]))
        .collect()
}

/// The bytes the file system has allocated to `file`: `st_blocks` times 512,
/// from `fstat` (on Windows the compatibility libc's, which reports the
/// allocation size of the handle, so a sparse file's holes are not counted).
#[cfg(test)]
pub(crate) fn allocated(file: &File) -> u64 {
    use std::os::unix::io::AsRawFd;
    // SAFETY: an all-zero `stat` is a valid output buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and output buffer.
    let ret = unsafe { libc::fstat(file.as_raw_fd(), &mut st) };
    assert_eq!(ret, 0, "fstat: {}", io::Error::last_os_error());
    u64::try_from(st.st_blocks).unwrap() * 512
}

/// Makes `file` keep holes where it is extended or not written, as Linux files
/// do. Called before a file is extended to a size its writer will not fill
/// (a snapshot memory file). On Linux and macOS files always do; on Windows
/// the file is made sparse.
pub fn keep_holes(file: &File) -> io::Result<()> {
    super::backend::fs::keep_holes(file)
}

/// The smallest region a hole of a file can be: a write into part of one
/// allocates all of it. The page on Linux and macOS; 64 KiB on Windows,
/// where NTFS allocates sparse files in compression units. A diff snapshot
/// writes whole units (`dump_dirty`), so that the pages it leaves out stay
/// holes.
pub const HOLE_UNIT: usize = super::backend::fs::HOLE_UNIT;

/// Keeps track of a file's holes while it is written.
pub trait HoleKeeper: Sized {
    /// Records the holes `file` has now.
    fn new(file: &File) -> io::Result<Self>;
    /// Records that `[start, start + len)` was written.
    fn written(&mut self, start: u64, len: u64);
    /// Turns every recorded hole that was not written back into a hole.
    fn restore(self, file: &File) -> io::Result<()>;
}

/// A writer over a file that leaves the regions it does not write as they
/// were: data stays data and holes stay holes.
#[derive(Debug)]
pub struct SparseWriter<'f> {
    file: &'f mut File,
    pos: u64,
    holes: super::backend::fs::Holes,
}

impl<'f> SparseWriter<'f> {
    /// Starts writing `file` at its current position.
    pub fn new(file: &'f mut File) -> io::Result<Self> {
        let pos = file.stream_position()?;
        let holes = HoleKeeper::new(file)?;
        Ok(SparseWriter { file, pos, holes })
    }

    /// Finishes writing: regions that were holes and were not written are
    /// holes again.
    pub fn finish(self) -> io::Result<()> {
        self.holes.restore(self.file)
    }
}

impl Seek for SparseWriter<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = self.file.seek(pos)?;
        Ok(self.pos)
    }
}

impl WriteVolatile for SparseWriter<'_> {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        let n = self.file.write_volatile(buf)?;
        self.holes.written(self.pos, n as u64);
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use std::io::Read;

    use vm_memory::VolatileSlice;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    const MIB: u64 = 1 << 20;

    // Ids that kvmtool's decimal form, cut to 20 bytes, would make equal: a
    // volume serial of 10 digits, `0`, and NTFS indices of consecutive files
    // (sequence number 1) that differ past the 20th digit.
    #[cfg(windows)]
    #[test]
    fn test_device_id_keeps_every_bit() {
        let volume = 0xcafe_babe_u64;
        let (first, second) = ((1u64 << 48) | 0x1234, (1u64 << 48) | 0x1235);
        let cut = |index: u64| format!("{volume}0{index}")[..20].to_string();
        assert_eq!(cut(first), cut(second), "the collision this replaces");

        let ids = [device_id(volume, first), device_id(volume, second)];
        assert_ne!(ids[0], ids[1]);
        for id in &ids {
            assert_eq!(id.len(), 20);
            let digits = id
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase());
            assert!(digits, "{id}");
        }
        // The volume and the index do not run into each other.
        assert_ne!(device_id(1, 0), device_id(0, 1 << 63));
        assert_eq!(device_id(0, 0), "00000000000000000000");
        assert_eq!(
            device_id(u64::from(u32::MAX), u64::MAX),
            "1vvvvvvvvvvvvvvvvvvv"
        );
    }

    // Two files of one volume have distinct ids, and a file keeps its id when
    // it is opened again (`build_disk_image_id` on a drive update or restore).
    #[cfg(windows)]
    #[test]
    fn test_device_id_is_per_file_and_stable() {
        let a = TempFile::new().unwrap();
        let b = TempFile::new().unwrap();
        let id = |f: &File| StatIds::of(f).unwrap().device_id();
        let volume = |f: &File| StatIds::of(f).unwrap().st_dev();
        assert_eq!(volume(a.as_file()), volume(b.as_file()));
        assert_ne!(id(a.as_file()), id(b.as_file()));
        let reopened = File::open(a.as_path()).unwrap();
        assert_eq!(id(&reopened), id(a.as_file()));
    }

    fn write_at(w: &mut SparseWriter, data: &mut [u8], at: u64) {
        w.seek(SeekFrom::Start(at)).unwrap();
        // SAFETY: `data` outlives the slice.
        let slice = unsafe { VolatileSlice::new(data.as_mut_ptr(), data.len()) };
        w.write_all_volatile(&slice).unwrap();
    }

    #[test]
    fn test_gaps_stay_holes() {
        let mut file = TempFile::new().unwrap().into_file();
        // As `Vm::snapshot_memory_to_file` does: on Windows, a file keeps holes only if
        // it is sparse.
        keep_holes(&file).unwrap();
        file.set_len(64 * MIB).unwrap();
        let mut page = vec![0xabu8; 64 << 10];
        let mut w = SparseWriter::new(&mut file).unwrap();
        for i in 0..8 {
            write_at(&mut w, &mut page, i * 4 * MIB);
        }
        // Skip the rest, as dump_dirty does.
        w.seek(SeekFrom::Current(1 << 20)).unwrap();
        w.finish().unwrap();
        // The file system may allocate gaps when it flushes (APFS does).
        file.sync_all().unwrap();

        // Only the written data is allocated (allow file system metadata blocks).
        let written = 8 * page.len() as u64;
        assert!(allocated(&file) >= written);
        assert!(allocated(&file) < written + MIB, "{}", allocated(&file));
        assert_eq!(file.metadata().unwrap().len(), 64 * MIB);
        let mut back = vec![0u8; page.len()];
        file.seek(SeekFrom::Start(4 * MIB)).unwrap();
        file.read_exact(&mut back).unwrap();
        assert_eq!(back, page);
    }

    #[test]
    fn test_existing_data_is_kept() {
        // A diff snapshot is merged into an existing full snapshot.
        let mut file = TempFile::new().unwrap().into_file();
        keep_holes(&file).unwrap();
        file.set_len(16 * MIB).unwrap();
        let mut base = vec![0x11u8; (16 * MIB) as usize];
        let mut w = SparseWriter::new(&mut file).unwrap();
        write_at(&mut w, &mut base, 0);
        w.finish().unwrap();

        let mut diff = vec![0x22u8; 16 << 10];
        let mut w = SparseWriter::new(&mut file).unwrap();
        write_at(&mut w, &mut diff, 8 * MIB);
        w.finish().unwrap();

        let mut back = vec![0u8; (16 * MIB) as usize];
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut back).unwrap();
        let at = (8 * MIB) as usize;
        assert!(back[..at].iter().all(|b| *b == 0x11));
        assert!(back[at..at + diff.len()].iter().all(|b| *b == 0x22));
        assert!(back[at + diff.len()..].iter().all(|b| *b == 0x11));
        assert!(allocated(&file) >= 16 * MIB);
    }
}
