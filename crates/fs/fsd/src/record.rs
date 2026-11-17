// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The metadata record, `wick.stat`: what the guest set that a host object
//! cannot hold as the guest means it (docs/design-fs.md §4.2, Metadata
//! emulation; the layout and its rules are §4.5). 40 bytes, little-endian,
//! the same bytes on every host, so a share moved between hosts keeps it; stored
//! as Linux's xattr `user.wick.stat`, macOS's `wick.stat`, Windows's EA
//! `WICK.STAT`, never nameable by the guest.
//!
//! | offset | size | field |
//! | --- | --- | --- |
//! | 0 | 4 | magic `wkst` |
//! | 4 | 2 | version, 1 |
//! | 6 | 2 | flags: bit 0 mode, 1 uid, 2 gid, 3 rdev present |
//! | 8 | 4 | mode: Linux `st_mode`, type bits and 0o7777 |
//! | 12 | 4 | uid |
//! | 16 | 4 | gid |
//! | 20 | 4 | rdev major |
//! | 24 | 4 | rdev minor |
//! | 28 | 12 | reserved, 0 |
//!
//! A record that breaks any rule is refused (the operation fails with EIO and
//! is counted), never reinterpreted or repaired. Times, size and link count
//! are always the host's.

use std::fmt;

use crate::dir::{HostKind, HostStat, RECORD_LEN};

/// Linux's file type mask and types (`include/uapi/linux/stat.h`).
pub const S_IFMT: u32 = 0o170_000;
/// A socket.
pub const S_IFSOCK: u32 = 0o140_000;
/// A symlink.
pub const S_IFLNK: u32 = 0o120_000;
/// A regular file.
pub const S_IFREG: u32 = 0o100_000;
/// A block device.
pub const S_IFBLK: u32 = 0o060_000;
/// A directory.
pub const S_IFDIR: u32 = 0o040_000;
/// A character device.
pub const S_IFCHR: u32 = 0o020_000;
/// A FIFO.
pub const S_IFIFO: u32 = 0o010_000;
/// setgid.
pub const S_ISGID: u32 = 0o2000;

const MAGIC: [u8; 4] = *b"wkst";
const VERSION: u16 = 1;
const HAS_MODE: u16 = 1 << 0;
const HAS_UID: u16 = 1 << 1;
const HAS_GID: u16 = 1 << 2;
const HAS_RDEV: u16 = 1 << 3;
const KNOWN_FLAGS: u16 = HAS_MODE | HAS_UID | HAS_GID | HAS_RDEV;

/// The record's fields; `None` is "not set: the host's or the share's".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// Type and mode bits.
    pub mode: Option<u32>,
    /// Owner.
    pub uid: Option<u32>,
    /// Group.
    pub gid: Option<u32>,
    /// Device number (major, minor).
    pub rdev: Option<(u32, u32)>,
}

/// Why a stored record was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Not 40 bytes.
    Length(usize),
    /// Another magic.
    Magic,
    /// Another version.
    Version(u16),
    /// Unknown flag bits.
    Flags(u16),
    /// Reserved bytes not 0.
    Reserved,
    /// A mode with bits beyond type and 0o7777, or no known type.
    Mode(u32),
    /// A type the host object cannot carry (a directory's record saying
    /// regular file, a file's saying directory, any on a host symlink).
    Kind,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::Length(n) => write!(f, "a record of {n} bytes"),
            RecordError::Magic => f.write_str("a record with another magic"),
            RecordError::Version(v) => write!(f, "a record of version {v}"),
            RecordError::Flags(v) => write!(f, "a record with flags {v:#x}"),
            RecordError::Reserved => f.write_str("a record with reserved bytes set"),
            RecordError::Mode(m) => write!(f, "a record with mode {m:#o}"),
            RecordError::Kind => f.write_str("a record whose type the host object cannot have"),
        }
    }
}

impl std::error::Error for RecordError {}

fn valid_mode(mode: u32) -> bool {
    mode & !(S_IFMT | 0o7777) == 0
        && matches!(
            mode & S_IFMT,
            S_IFSOCK | S_IFLNK | S_IFREG | S_IFBLK | S_IFDIR | S_IFCHR | S_IFIFO
        )
}

impl Record {
    /// The 40 bytes.
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        let mut flags = 0u16;
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        if let Some(mode) = self.mode {
            flags |= HAS_MODE;
            out[8..12].copy_from_slice(&mode.to_le_bytes());
        }
        if let Some(uid) = self.uid {
            flags |= HAS_UID;
            out[12..16].copy_from_slice(&uid.to_le_bytes());
        }
        if let Some(gid) = self.gid {
            flags |= HAS_GID;
            out[16..20].copy_from_slice(&gid.to_le_bytes());
        }
        if let Some((major, minor)) = self.rdev {
            flags |= HAS_RDEV;
            out[20..24].copy_from_slice(&major.to_le_bytes());
            out[24..28].copy_from_slice(&minor.to_le_bytes());
        }
        out[6..8].copy_from_slice(&flags.to_le_bytes());
        out
    }

    /// The record in `bytes`, if it keeps every rule.
    pub fn decode(bytes: &[u8]) -> Result<Record, RecordError> {
        let b: &[u8; RECORD_LEN] = bytes
            .try_into()
            .map_err(|_| RecordError::Length(bytes.len()))?;
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        if b[0..4] != MAGIC {
            return Err(RecordError::Magic);
        }
        let version = u16_at(4);
        if version != VERSION {
            return Err(RecordError::Version(version));
        }
        let flags = u16_at(6);
        if flags & !KNOWN_FLAGS != 0 {
            return Err(RecordError::Flags(flags));
        }
        if b[28..].iter().any(|&x| x != 0) {
            return Err(RecordError::Reserved);
        }
        // A field not present must be 0, so no two byte strings decode to
        // the same record.
        let field = |bit: u16, value: u32| -> Result<Option<u32>, RecordError> {
            match (flags & bit != 0, value) {
                (true, v) => Ok(Some(v)),
                (false, 0) => Ok(None),
                (false, _) => Err(RecordError::Reserved),
            }
        };
        let mode = field(HAS_MODE, u32_at(8))?;
        if let Some(m) = mode
            && !valid_mode(m)
        {
            return Err(RecordError::Mode(m));
        }
        let uid = field(HAS_UID, u32_at(12))?;
        let gid = field(HAS_GID, u32_at(16))?;
        let major = field(HAS_RDEV, u32_at(20))?;
        let minor = field(HAS_RDEV, u32_at(24))?;
        let rdev = major.zip(minor);
        Ok(Record {
            mode,
            uid,
            gid,
            rdev,
        })
    }

    /// Whether a host object of `kind` may carry this record: a directory
    /// only a directory's type; a regular file any type but a directory's
    /// (the others are emulated on it); a host symlink or other object
    /// none.
    pub fn check_kind(&self, kind: HostKind) -> Result<(), RecordError> {
        let Some(ty) = self.mode.map(|m| m & S_IFMT) else {
            return match kind {
                HostKind::File | HostKind::Dir => Ok(()),
                HostKind::HostSymlink | HostKind::Other => Err(RecordError::Kind),
            };
        };
        let ok = match kind {
            HostKind::Dir => ty == S_IFDIR,
            HostKind::File => ty != S_IFDIR,
            HostKind::HostSymlink | HostKind::Other => false,
        };
        if ok { Ok(()) } else { Err(RecordError::Kind) }
    }
}

/// What the guest sees of a node's type and ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shown {
    /// Type and mode bits.
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Linux's encoded device number (`new_encode_dev`).
    pub rdev: u32,
}

/// The type a host object has without a record.
pub fn host_type(kind: HostKind) -> u32 {
    match kind {
        HostKind::File | HostKind::Other => S_IFREG,
        HostKind::Dir => S_IFDIR,
        HostKind::HostSymlink => S_IFLNK,
    }
}

/// Type, mode, owner and device of a node: the record's where it has them,
/// else the host's type and permission bits and the share's owner. A host
/// symlink shows 0o777; another host object (FIFO, device) shows as a
/// regular file with no permission, as it is never opened.
pub fn shown(stat: &HostStat, record: Option<&Record>, owner: (u32, u32)) -> Shown {
    let record = record.copied().unwrap_or_default();
    let host_mode = match stat.kind {
        HostKind::HostSymlink => S_IFLNK | 0o777,
        HostKind::Other => S_IFREG,
        HostKind::File | HostKind::Dir => host_type(stat.kind) | u32::from(stat.perm & 0o777),
    };
    Shown {
        mode: record.mode.unwrap_or(host_mode),
        uid: record.uid.unwrap_or(owner.0),
        gid: record.gid.unwrap_or(owner.1),
        rdev: record.rdev.map_or(0, |(major, minor)| encode_dev(major, minor)),
    }
}

/// Linux's `new_encode_dev` into 32 bits (`include/linux/kdev_t.h`): the
/// form `fuse_attr.rdev` and `fuse_mknod_in.rdev` carry.
pub fn encode_dev(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
}

/// Linux's `new_decode_dev`: (major, minor) of a 32-bit device number.
pub fn decode_dev(dev: u32) -> (u32, u32) {
    ((dev & 0xfff00) >> 8, (dev & 0xff) | ((dev >> 12) & 0xfff00))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir::{HostId, Timespec};

    fn stat(kind: HostKind, perm: u16) -> HostStat {
        HostStat {
            id: HostId { volume: 1, file: 2 },
            kind,
            size: 0,
            blocks: 0,
            nlink: 1,
            perm,
            atime: Timespec::default(),
            mtime: Timespec::default(),
            ctime: Timespec::default(),
        }
    }

    #[test]
    fn test_record_bytes_round_trip() {
        let r = Record {
            mode: Some(S_IFCHR | 0o4620),
            uid: Some(0),
            gid: Some(5),
            rdev: Some((4, 64)),
        };
        let b = r.encode();
        assert_eq!(&b[0..4], b"wkst");
        assert_eq!(&b[4..8], &[1, 0, 0x0f, 0]);
        assert_eq!(&b[8..12], &(S_IFCHR | 0o4620).to_le_bytes());
        assert_eq!(&b[12..16], &0u32.to_le_bytes());
        assert_eq!(&b[16..20], &5u32.to_le_bytes());
        assert_eq!(&b[20..28], &[4, 0, 0, 0, 64, 0, 0, 0]);
        assert_eq!(&b[28..], &[0; 12]);
        assert_eq!(Record::decode(&b), Ok(r));
        // Only what is set is present.
        let partial = Record {
            uid: Some(1000),
            ..Record::default()
        };
        let b = partial.encode();
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), HAS_UID);
        assert_eq!(Record::decode(&b), Ok(partial));
        assert_eq!(Record::decode(&Record::default().encode()), Ok(Record::default()));
    }

    #[test]
    fn test_a_record_that_breaks_a_rule_is_refused() {
        let good = Record {
            mode: Some(S_IFREG | 0o644),
            ..Record::default()
        }
        .encode();
        assert_eq!(Record::decode(&good[..39]), Err(RecordError::Length(39)));
        assert_eq!(Record::decode(&[good.as_slice(), &[0]].concat()), Err(RecordError::Length(41)));
        let mut b = good;
        b[0] = b'W';
        assert_eq!(Record::decode(&b), Err(RecordError::Magic));
        let mut b = good;
        b[4] = 2;
        assert_eq!(Record::decode(&b), Err(RecordError::Version(2)));
        let mut b = good;
        b[6] |= 0x10;
        assert_eq!(Record::decode(&b), Err(RecordError::Flags(0x11)));
        let mut b = good;
        b[39] = 1;
        assert_eq!(Record::decode(&b), Err(RecordError::Reserved));
        // A field marked absent that holds a value.
        let mut b = good;
        b[12] = 7;
        assert_eq!(Record::decode(&b), Err(RecordError::Reserved));
        // A mode beyond type and 0o7777, and a type Linux has not got.
        for mode in [S_IFREG | 0o10000, 0o644, 0o150_000 | 0o644] {
            let b = Record {
                mode: Some(mode),
                ..Record::default()
            }
            .encode();
            assert_eq!(Record::decode(&b), Err(RecordError::Mode(mode)), "{mode:#o}");
        }
    }

    #[test]
    fn test_record_type_must_fit_the_host_object() {
        let with = |mode| Record {
            mode: Some(mode),
            ..Record::default()
        };
        assert_eq!(with(S_IFDIR | 0o755).check_kind(HostKind::Dir), Ok(()));
        assert_eq!(with(S_IFREG | 0o644).check_kind(HostKind::Dir), Err(RecordError::Kind));
        for ty in [S_IFREG, S_IFLNK, S_IFIFO, S_IFSOCK, S_IFCHR, S_IFBLK] {
            assert_eq!(with(ty | 0o600).check_kind(HostKind::File), Ok(()));
        }
        assert_eq!(with(S_IFDIR | 0o755).check_kind(HostKind::File), Err(RecordError::Kind));
        for kind in [HostKind::HostSymlink, HostKind::Other] {
            assert_eq!(Record::default().check_kind(kind), Err(RecordError::Kind));
        }
        assert_eq!(Record::default().check_kind(HostKind::File), Ok(()));
    }

    #[test]
    fn test_shown_attributes_without_and_with_a_record() {
        let owner = (1000, 100);
        assert_eq!(
            shown(&stat(HostKind::File, 0o640), None, owner),
            Shown {
                mode: S_IFREG | 0o640,
                uid: 1000,
                gid: 100,
                rdev: 0
            }
        );
        assert_eq!(shown(&stat(HostKind::Dir, 0o755), None, owner).mode, S_IFDIR | 0o755);
        assert_eq!(shown(&stat(HostKind::HostSymlink, 0), None, owner).mode, S_IFLNK | 0o777);
        assert_eq!(shown(&stat(HostKind::Other, 0o666), None, owner).mode, S_IFREG);
        // The record wins, setuid and all; the host's bits never show
        // through it.
        let r = Record {
            mode: Some(S_IFBLK | 0o4660),
            uid: Some(0),
            gid: Some(6),
            rdev: Some((8, 1)),
        };
        assert_eq!(
            shown(&stat(HostKind::File, 0o600), Some(&r), owner),
            Shown {
                mode: S_IFBLK | 0o4660,
                uid: 0,
                gid: 6,
                rdev: 0x801
            }
        );
    }

    #[test]
    fn test_device_numbers_are_linuxs_encoding() {
        assert_eq!(encode_dev(8, 1), 0x801);
        assert_eq!(decode_dev(0x801), (8, 1));
        // Minors above 255 and majors above 255.
        for (major, minor) in [(0, 0), (259, 0), (4095, 0xfffff), (1, 256), (136, 70000)] {
            assert_eq!(decode_dev(encode_dev(major, minor)), (major, minor), "{major}:{minor}");
        }
    }
}
