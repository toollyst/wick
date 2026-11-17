// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `ConfinedDir`: the one interface between the common server
//! ([`crate::session`]) and a host's directory layer; its contract is
//! docs/design-fs.md §4.3.
//!
//! The common server does FUSE, the node and handle tables, the limits, the
//! metadata record and the cache policy. A `ConfinedDir` does only "act on
//! one checked component beneath a held directory, never following a link",
//! on one host: Linux (`openat2` beneath), macOS (`O_RESOLVE_BENEATH` and
//! `O_NOFOLLOW_ANY`), Windows (`NtCreateFile` relative to a handle with
//! `OBJ_DONT_REPARSE`), and [`crate::memdir::MemDir`], an in-memory directory
//! for tests and fuzzing.
//!
//! Every name a `ConfinedDir` is given has passed [`Name::new`] (layer 1);
//! every name it returns is checked again by the server, which skips (and
//! counts) one that is not a [`Name`].

use std::fmt;

use crate::fuse::Errno;
use crate::fuse::name::Name;

/// A host object's identity, never its name: Linux and macOS
/// `(st_dev, st_ino)`, Windows `(VolumeSerialNumber, FileId)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostId {
    /// The volume.
    pub volume: u64,
    /// The object on the volume.
    pub file: u128,
}

/// What a host object is. Only `File` and `Dir` are ever opened; the
/// others are shown and never followed or opened (design-fs rows 2 and 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symlink, junction or mount point the host made.
    HostSymlink,
    /// Anything else the host has: a FIFO, socket or device node.
    Other,
}

/// A time, seconds and nanoseconds since the epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    /// Seconds.
    pub secs: i64,
    /// Nanoseconds, below 10⁹.
    pub nsecs: u32,
}

/// A host object's attributes. Type, mode beyond the permission bits, uid,
/// gid and rdev are the record's ([`crate::record`]), never the host's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostStat {
    /// Identity.
    pub id: HostId,
    /// Kind.
    pub kind: HostKind,
    /// Bytes.
    pub size: u64,
    /// 512-byte blocks allocated.
    pub blocks: u64,
    /// Hard links.
    pub nlink: u32,
    /// Permission bits as the host shows them, 0o777 at most.
    pub perm: u16,
    /// Last access.
    pub atime: Timespec,
    /// Last change of the content.
    pub mtime: Timespec,
    /// Last change of the attributes.
    pub ctime: Timespec,
}

/// How a regular file is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenMode {
    /// For reading.
    pub read: bool,
    /// For writing.
    pub write: bool,
}

/// `renameat2`'s flags the server passes on (docs/design-fs.md §4.3). The
/// server has refused every other combination: never both; never
/// `RENAME_WHITEOUT`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenameFlags {
    /// `RENAME_NOREPLACE`: EEXIST if the target exists. Every backend does
    /// it.
    pub noreplace: bool,
    /// `RENAME_EXCHANGE`: swap the two names atomically, ENOENT if either
    /// is missing. A backend whose host has no atomic exchange refuses it
    /// with EINVAL (Windows: NTFS has none); the others do it.
    pub exchange: bool,
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The host's name, as bytes (unescaped by the backend): one that is
    /// not a guest name (not UTF-8, an escape image, ...) is skipped and
    /// counted by the server.
    pub name: Vec<u8>,
    /// Its identity.
    pub id: HostId,
    /// Its kind.
    pub kind: HostKind,
    /// Where a listing after this entry continues: 1 to `i64::MAX`.
    pub cookie: u64,
}

/// The largest cookie a backend may give (the server adds its own two
/// entries, `.` and `..`, before them).
pub const MAX_COOKIE: u64 = (1 << 63) - 1;

/// A file system's sizes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatFs {
    /// Blocks of `frsize` bytes.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks an unprivileged user may use.
    pub bavail: u64,
    /// Inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Preferred I/O size.
    pub bsize: u32,
    /// Fragment size, the unit of the block counts.
    pub frsize: u32,
}

/// How [`ConfinedDir::set_xattr`] treats an existing attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrMode {
    /// Create or replace.
    Any,
    /// `XATTR_CREATE`: EEXIST if it exists.
    Create,
    /// `XATTR_REPLACE`: ENODATA if it does not.
    Replace,
}

/// A backend's error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DirError {
    /// The guest's errno (Linux's numbers on every host).
    Errno(Errno),
    /// A refusal by layer 2 (the beneath-flags) or 3 (the OS sandbox). The
    /// guest gets EACCES and the server counts it: layer 1 should have
    /// stopped the request, so commit 5's corpus test fails on any.
    Refused {
        /// 2 or 3.
        layer: u8,
        /// The host's code.
        host_code: i64,
    },
}

impl fmt::Debug for DirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirError::Errno(e) => write!(f, "{e:?}"),
            DirError::Refused { layer, host_code } => {
                write!(f, "refused by layer {layer} (host code {host_code})")
            }
        }
    }
}

impl From<Errno> for DirError {
    fn from(e: Errno) -> DirError {
        DirError::Errno(e)
    }
}

/// The record's size ([`crate::record::Record`]).
pub const RECORD_LEN: usize = 40;

/// A host's directory layer.
pub trait ConfinedDir {
    /// What the node table holds per node: Linux and macOS a directory's
    /// descriptor, or for anything else a leaf (the names it is known by and
    /// the descriptor of the guest's widest open; docs/design-fs.md §4.3);
    /// Windows a handle opened by id.
    type Node: Clone;
    /// An object open for I/O (a regular file) or listing (a directory).
    type Open;

    /// The share's root.
    fn root(&self) -> Self::Node;

    /// One component beneath `parent`, never following a link. ENOENT when
    /// the stored name is not exactly `name` (an alias by case or
    /// normalization).
    fn lookup(&self, parent: &Self::Node, name: Name<'_>) -> Result<(Self::Node, HostStat), DirError>;

    /// The node's attributes.
    fn stat(&self, node: &Self::Node) -> Result<HostStat, DirError>;

    /// Opens a regular file after checking it is still `expect`.
    fn open(&self, node: &Self::Node, expect: HostId, mode: OpenMode) -> Result<Self::Open, DirError>;

    /// Opens a directory for listing after checking it is still `expect`.
    fn open_dir(&self, node: &Self::Node, expect: HostId) -> Result<Self::Open, DirError>;

    /// Closes what `open` or `open_dir` gave.
    fn close(&self, open: Self::Open);

    /// Creates a regular file (read-write open); with `exclusive`, EEXIST if
    /// the name exists, else opens what is there if it is a regular file.
    fn create(
        &self,
        parent: &Self::Node,
        name: Name<'_>,
        exclusive: bool,
    ) -> Result<(Self::Node, Self::Open, HostStat), DirError>;

    /// Creates a directory.
    fn mkdir(&self, parent: &Self::Node, name: Name<'_>) -> Result<(Self::Node, HostStat), DirError>;

    /// Removes a non-directory, only if it is still `expect`.
    fn unlink(&self, parent: &Self::Node, name: Name<'_>, expect: HostId) -> Result<(), DirError>;

    /// Removes an empty directory, only if it is still `expect`.
    fn rmdir(&self, parent: &Self::Node, name: Name<'_>, expect: HostId) -> Result<(), DirError>;

    /// Renames one component to another, never by path, with Linux's
    /// errors (`fs/namei.c`): a directory into itself or beneath it is
    /// EINVAL, onto an ancestor of its old parent ENOTEMPTY (EINVAL under
    /// exchange), and two names of one object succeed with nothing changed.
    fn rename(
        &self,
        from: (&Self::Node, Name<'_>),
        to: (&Self::Node, Name<'_>),
        flags: RenameFlags,
    ) -> Result<(), DirError>;

    /// A new name for a non-directory that is still `expect`.
    fn link(&self, node: &Self::Node, expect: HostId, to: (&Self::Node, Name<'_>)) -> Result<HostStat, DirError>;

    /// Reads at `offset` into `buf`.
    fn read_at(&self, open: &Self::Open, offset: u64, buf: &mut [u8]) -> Result<usize, DirError>;

    /// Writes `data` at `offset`.
    fn write_at(&self, open: &Self::Open, offset: u64, data: &[u8]) -> Result<usize, DirError>;

    /// Flushes to stable storage.
    fn sync(&self, open: &Self::Open, data_only: bool) -> Result<(), DirError>;

    /// Sets a regular file's length.
    fn set_len(&self, node: &Self::Node, len: u64) -> Result<(), DirError>;

    /// Allocates `len` bytes at `offset` (growing the file unless
    /// `keep_size`), or with `punch` makes them a hole.
    fn allocate(&self, open: &Self::Open, offset: u64, len: u64, keep_size: bool, punch: bool) -> Result<(), DirError>;

    /// Sets the times given.
    fn set_times(&self, node: &Self::Node, atime: Option<Timespec>, mtime: Option<Timespec>) -> Result<(), DirError>;

    /// Sets the guest's permission bits (0o777); a backend keeps the
    /// server's own access to the object and never sets setuid, setgid or
    /// sticky on the host.
    fn set_perm(&self, node: &Self::Node, perm: u16) -> Result<(), DirError>;

    /// Entries after `after` (0: from the start), at most `max`, in `out`.
    fn read_dir(&self, dir: &Self::Open, after: u64, max: usize, out: &mut Vec<DirEntry>) -> Result<(), DirError>;

    /// A host symlink's target, at most `max` bytes (ENAMETOOLONG beyond).
    fn read_link(&self, node: &Self::Node, max: usize) -> Result<Vec<u8>, DirError>;

    /// The file system's sizes.
    fn statfs(&self, node: &Self::Node) -> Result<StatFs, DirError>;

    /// The node's record, if it has one: exactly [`RECORD_LEN`] bytes, or
    /// whatever is stored (the server refuses another length).
    fn get_record(&self, node: &Self::Node) -> Result<Option<Vec<u8>>, DirError>;

    /// Stores the node's record.
    fn set_record(&self, node: &Self::Node, record: &[u8; RECORD_LEN]) -> Result<(), DirError>;

    /// A guest attribute's value.
    fn get_xattr(&self, node: &Self::Node, name: &[u8]) -> Result<Option<Vec<u8>>, DirError>;

    /// Sets a guest attribute.
    fn set_xattr(&self, node: &Self::Node, name: &[u8], value: &[u8], mode: XattrMode) -> Result<(), DirError>;

    /// The guest attributes' (name, value length) pairs.
    fn list_xattr(&self, node: &Self::Node) -> Result<Vec<(Vec<u8>, usize)>, DirError>;

    /// Removes a guest attribute (ENODATA if absent).
    fn remove_xattr(&self, node: &Self::Node, name: &[u8]) -> Result<(), DirError>;
}
