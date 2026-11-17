// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! FUSE replies: a `fuse_out_header` and the opcode's reply structs, laid
//! out as fuse.h 7.47 has them, little-endian.
//!
//! A reply goes into the request's writable buffers, which the VMM bounds
//! by the frame's `writable_cap`; the server checks a reply's length
//! against it before sending (the VMM refuses a longer one,
//! `wick_fs_frame::InFlight::finish`).

use super::{Errno, OUT_HEADER_LEN};

/// Appends little-endian fields.
#[derive(Debug, Default)]
struct Out(Vec<u8>);

impl Out {
    fn u16(&mut self, v: u16) -> &mut Out {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn u32(&mut self, v: u32) -> &mut Out {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn i32(&mut self, v: i32) -> &mut Out {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn u64(&mut self, v: u64) -> &mut Out {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn zeros(&mut self, n: usize) -> &mut Out {
        self.0.resize(self.0.len() + n, 0);
        self
    }
}

/// `fuse_out_header` for a reply of `len` bytes in all (header included):
/// `error` is 0 or a negated [`Errno`].
fn out_header(len: u32, error: i32, unique: u64) -> [u8; OUT_HEADER_LEN] {
    let mut out = Out::default();
    out.u32(len).i32(error).u64(unique);
    let mut header = [0; OUT_HEADER_LEN];
    header.copy_from_slice(&out.0);
    header
}

/// The whole reply for a failed request: the header alone, with `-errno`.
pub fn error(unique: u64, errno: Errno) -> [u8; OUT_HEADER_LEN] {
    const LEN: u32 = 16;
    const _: () = assert!(LEN as usize == OUT_HEADER_LEN);
    out_header(LEN, -errno.get(), unique)
}

/// Why a reply was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong {
    /// The reply's length, header included.
    pub len: usize,
    /// What the request's buffers take.
    pub cap: usize,
}

/// A successful reply: the header, then `parts` in order, if the whole fits
/// `cap` bytes (the request's `writable_cap`).
pub fn reply(unique: u64, parts: &[&[u8]], cap: usize) -> Result<Vec<u8>, TooLong> {
    let len = parts
        .iter()
        .try_fold(OUT_HEADER_LEN, |n, p| n.checked_add(p.len()))
        .unwrap_or(usize::MAX);
    if len > cap {
        return Err(TooLong { len, cap });
    }
    // len ≤ cap, and a cap is a frame's u32 writable_cap.
    let header = out_header(u32::try_from(len).map_err(|_| TooLong { len, cap })?, 0, unique);
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&header);
    for part in parts {
        out.extend_from_slice(part);
    }
    Ok(out)
}

/// `fuse_attr`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

/// Bytes in `fuse_attr`.
pub const ATTR_LEN: usize = 88;

impl Attr {
    fn put(&self, out: &mut Out) {
        out.u64(self.ino)
            .u64(self.size)
            .u64(self.blocks)
            .u64(self.atime)
            .u64(self.mtime)
            .u64(self.ctime)
            .u32(self.atimensec)
            .u32(self.mtimensec)
            .u32(self.ctimensec)
            .u32(self.mode)
            .u32(self.nlink)
            .u32(self.uid)
            .u32(self.gid)
            .u32(self.rdev)
            .u32(self.blksize)
            .u32(self.flags);
    }
}

/// Cache timeouts: seconds and nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Valid {
    /// Seconds.
    pub secs: u64,
    /// Nanoseconds, below 10⁹.
    pub nsecs: u32,
}

/// `fuse_entry_out`: the reply to `LOOKUP`, `MKNOD`, `MKDIR`, `SYMLINK`,
/// `LINK` and (with an [`open_out`] after it) `CREATE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryOut {
    /// The server's node id; 0 is a negative entry, cached for `entry`.
    pub nodeid: u64,
    /// The node id's generation.
    pub generation: u64,
    /// How long the guest may keep the name.
    pub entry: Valid,
    /// How long the guest may keep the attributes.
    pub attr_valid: Valid,
    /// The attributes.
    pub attr: Attr,
}

/// Bytes in `fuse_entry_out`.
pub const ENTRY_OUT_LEN: usize = 128;

impl EntryOut {
    fn put(&self, out: &mut Out) {
        out.u64(self.nodeid)
            .u64(self.generation)
            .u64(self.entry.secs)
            .u64(self.attr_valid.secs)
            .u32(self.entry.nsecs)
            .u32(self.attr_valid.nsecs);
        self.attr.put(out);
    }

    /// The struct's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Out::default();
        self.put(&mut out);
        out.0
    }
}

/// `fuse_attr_out`, the reply to `GETATTR` and `SETATTR`.
pub fn attr_out(valid: Valid, attr: &Attr) -> Vec<u8> {
    let mut out = Out::default();
    out.u64(valid.secs).u32(valid.nsecs).zeros(4);
    attr.put(&mut out);
    out.0
}

/// Bytes in `fuse_attr_out`.
pub const ATTR_OUT_LEN: usize = 104;

/// `fuse_open_out`, the reply to `OPEN` and `OPENDIR` (and `CREATE`'s
/// second part). 24 bytes for a guest of protocol 7.47 or later
/// (`backing_id_64`), 16 for an earlier one: the size the guest's kernel
/// was built with, which it checks.
pub fn open_out(fh: u64, open_flags: u32, minor: u32) -> Vec<u8> {
    let mut out = Out::default();
    out.u64(fh).u32(open_flags).i32(0);
    if minor >= 47 {
        out.u64(0);
    }
    out.0
}

/// `fuse_write_out`, the reply to `WRITE` and `COPY_FILE_RANGE`.
pub fn write_out(size: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&size.to_le_bytes());
    b
}

/// `fuse_getxattr_out`, the reply to a `GETXATTR` or `LISTXATTR` of size
/// 0: the size the value or list needs.
pub fn getxattr_out(size: u32) -> [u8; 8] {
    write_out(size)
}

/// A single `u64`: `fuse_lseek_out` (`LSEEK`) and
/// `fuse_copy_file_range_out` (`COPY_FILE_RANGE_64`).
pub fn u64_out(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// `fuse_kstatfs`, in `fuse_statfs_out`, the reply to `STATFS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

/// Bytes in `fuse_statfs_out`.
pub const STATFS_OUT_LEN: usize = 80;

impl Kstatfs {
    /// `fuse_statfs_out`'s bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Out::default();
        out.u64(self.blocks)
            .u64(self.bfree)
            .u64(self.bavail)
            .u64(self.files)
            .u64(self.ffree)
            .u32(self.bsize)
            .u32(self.namelen)
            .u32(self.frsize)
            .zeros(4 + 6 * 4);
        out.0
    }
}

/// `fuse_init_out`, the reply to `INIT`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub max_stack_depth: u32,
    pub request_timeout: u16,
}

/// Bytes in `fuse_init_out`.
pub const INIT_OUT_LEN: usize = 64;

impl InitOut {
    /// The struct's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Out::default();
        out.u32(self.major)
            .u32(self.minor)
            .u32(self.max_readahead)
            .u32(self.flags)
            .u16(self.max_background)
            .u16(self.congestion_threshold)
            .u32(self.max_write)
            .u32(self.time_gran)
            .u16(self.max_pages)
            .u16(self.map_alignment)
            .u32(self.flags2)
            .u32(self.max_stack_depth)
            .u16(self.request_timeout)
            .zeros(11 * 2);
        out.0
    }
}

/// `fuse_dirent` with its name, padded to 8 bytes (`FUSE_DIRENT_SIZE`):
/// one entry of a `READDIR` reply.
pub fn dirent(ino: u64, off: u64, kind: u32, name: &[u8]) -> Vec<u8> {
    let mut out = Out::default();
    put_dirent(&mut out, ino, off, kind, name);
    out.0
}

fn put_dirent(out: &mut Out, ino: u64, off: u64, kind: u32, name: &[u8]) {
    // A name is at most NAME_MAX (255) bytes, or a host name the backend
    // checked against it.
    let namelen = u32::try_from(name.len()).unwrap_or(u32::MAX);
    out.u64(ino).u64(off).u32(namelen).u32(kind);
    out.0.extend_from_slice(name);
    let pad = (8 - name.len() % 8) % 8;
    out.zeros(pad);
}

/// `fuse_direntplus` with its name, padded to 8 bytes: one entry of a
/// `READDIRPLUS` reply.
pub fn direntplus(entry: &EntryOut, off: u64, kind: u32, name: &[u8]) -> Vec<u8> {
    let mut out = Out::default();
    entry.put(&mut out);
    put_dirent(&mut out, entry.attr.ino, off, kind, name);
    out.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_reply_is_the_header_with_the_negated_errno() {
        let bytes = error(0x0102_0304_0506_0708, Errno::ENOSYS);
        assert_eq!(&bytes[0..4], &16u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &(-38i32).to_le_bytes());
        assert_eq!(&bytes[8..16], &0x0102_0304_0506_0708u64.to_le_bytes());
    }

    #[test]
    fn test_reply_length_and_its_cap() {
        let a = [1u8; 10];
        let b = [2u8; 6];
        let out = reply(9, &[&a, &b], 32).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(&out[0..4], &32u32.to_le_bytes());
        assert_eq!(&out[4..8], &0i32.to_le_bytes());
        assert_eq!(&out[8..16], &9u64.to_le_bytes());
        assert_eq!(&out[16..26], &a);
        assert_eq!(reply(9, &[&a, &b], 31), Err(TooLong { len: 32, cap: 31 }));
        assert_eq!(reply(9, &[], 16).unwrap().len(), 16);
        assert_eq!(reply(9, &[], 15), Err(TooLong { len: 16, cap: 15 }));
    }

    #[test]
    fn test_reply_structs_have_fuse_h_sizes() {
        // fuse.h 7.47: sizeof of each struct, and the field offsets the
        // guest reads.
        let attr = Attr {
            ino: 1,
            flags: 0xAABB_CCDD,
            ..Attr::default()
        };
        let mut out = Out::default();
        attr.put(&mut out);
        assert_eq!(out.0.len(), ATTR_LEN);
        assert_eq!(&out.0[84..88], &0xAABB_CCDDu32.to_le_bytes());

        let entry = EntryOut {
            nodeid: 5,
            entry: Valid { secs: 1, nsecs: 2 },
            attr,
            ..EntryOut::default()
        };
        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), ENTRY_OUT_LEN);
        assert_eq!(&bytes[16..24], &1u64.to_le_bytes());
        assert_eq!(&bytes[32..36], &2u32.to_le_bytes());
        assert_eq!(&bytes[40..48], &1u64.to_le_bytes()); // attr.ino

        assert_eq!(attr_out(Valid::default(), &attr).len(), ATTR_OUT_LEN);
        assert_eq!(open_out(1, 2, 47).len(), 24);
        assert_eq!(open_out(1, 2, 46).len(), 16);
        assert_eq!(Kstatfs::default().to_bytes().len(), STATFS_OUT_LEN);
        let init = InitOut {
            request_timeout: 0x1234,
            ..InitOut::default()
        };
        let bytes = init.to_bytes();
        assert_eq!(bytes.len(), INIT_OUT_LEN);
        assert_eq!(&bytes[40..42], &0x1234u16.to_le_bytes());
    }

    #[test]
    fn test_dirents_are_padded_to_8_bytes() {
        // FUSE_NAME_OFFSET is 24; FUSE_DIRENT_SIZE rounds up to 8.
        for (name, len) in [(&b"a"[..], 32), (b"abcdefgh", 32), (b"abcdefghi", 40)] {
            let d = dirent(7, 1, 4, name);
            assert_eq!(d.len(), len, "{name:?}");
            assert_eq!(&d[16..20], &u32::try_from(name.len()).unwrap().to_le_bytes());
            assert_eq!(&d[24..24 + name.len()], name);
            assert!(d[24 + name.len()..].iter().all(|&b| b == 0));
        }
        let plus = direntplus(&EntryOut::default(), 3, 8, b"x");
        assert_eq!(plus.len(), ENTRY_OUT_LEN + 32);
    }
}
