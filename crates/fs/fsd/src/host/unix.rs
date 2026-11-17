// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The host directory on Linux and macOS (docs/design-fs.md §4.3, §6.1,
//! §6.2): [`ConfinedDir`] over a held directory descriptor, one checked
//! component at a time, through `wick_fs_sys`.
//!
//! - **Nodes.** A directory is held open (`O_RDONLY | O_DIRECTORY`), one
//!   descriptor per identity, by its node only. Any
//!   other object is one [`Leaf`] per identity: the names it is known by
//!   beneath held directories (most recent first, kept as the guest looks up,
//!   creates, links, renames and unlinks), and, once the guest has opened
//!   it, the descriptor of its widest open. Each use finds the object by a
//!   name and checks the identity there (a host's swap is never another
//!   object); when no known name is it, an object without any name
//!   (`nlink` 0: unlinked while the guest held it) is served through the
//!   descriptor, and one with a name is looked for in the held directories.
//!   The same on both hosts: no `O_PATH` (macOS has none) and no reopening
//!   through `/proc`.
//! - **Opens** never follow a link at any component and never leave their
//!   directory (`openat2` beneath on Linux, `O_NOFOLLOW_ANY |
//!   O_RESOLVE_BENEATH` on macOS). A host symlink, FIFO, socket or device is
//!   shown and never opened: its kind is read with `fstatat(...,
//!   AT_SYMLINK_NOFOLLOW)` first, and an open finds a regular file or fails.
//! - **Refusals** of layer 2 (a link or an escape a host swap put in the
//!   name since the `fstatat`) are [`DirError::Refused`]: EACCES to the
//!   guest, counted.
//! - **Mount points** beneath the share are not entered: a name whose object
//!   is on another device is EXDEV, on both hosts.
//! - **Exact names.** A name whose stored form differs (a volume that folds
//!   case or Unicode normalization: APFS always folds normalization; Linux's
//!   casefold directories, vfat, exfat) is ENOENT to a lookup and EEXIST to a
//!   create.
//! - **Metadata.** The record is the xattr `user.wick.stat` (Linux) or
//!   `wick.stat` (macOS); a guest attribute `n` is `user.wick.x.n` /
//!   `wick.x.n`. Other host attributes are neither shown nor touched.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use wick_fs_sys as sys;

use crate::dir::{
    ConfinedDir, DirEntry, DirError, HostId, HostKind, HostStat, MAX_COOKIE, OpenMode, RECORD_LEN, RenameFlags,
    StatFs, Timespec, XattrMode,
};
use crate::fuse::Errno;
use crate::fuse::name::Name;

/// The record's attribute name.
#[cfg(target_os = "linux")]
pub const RECORD_XATTR: &[u8] = b"user.wick.stat";
/// The record's attribute name.
#[cfg(target_os = "macos")]
pub const RECORD_XATTR: &[u8] = b"wick.stat";

/// The prefix of a guest attribute's host name.
#[cfg(target_os = "linux")]
pub const GUEST_XATTR_PREFIX: &[u8] = b"user.wick.x.";
/// The prefix of a guest attribute's host name.
#[cfg(target_os = "macos")]
pub const GUEST_XATTR_PREFIX: &[u8] = b"wick.x.";

/// A host errno as the guest's.
pub fn errno(e: sys::HostErrno) -> Errno {
    Errno::from_linux(sys::linux_errno(e)).unwrap_or(Errno::EIO)
}

fn err(e: sys::HostErrno) -> DirError {
    DirError::Errno(errno(e))
}

/// An open's error: a link or an escape refused by the beneath flags is a
/// layer-2 refusal, anything else the guest's errno.
fn open_err(e: sys::HostErrno) -> DirError {
    if e.0 == sys::errno::ELOOP || e.0 == sys::errno::BENEATH_REFUSAL {
        DirError::Refused {
            layer: 2,
            host_code: i64::from(e.0),
        }
    } else {
        err(e)
    }
}

fn enoent() -> DirError {
    DirError::Errno(Errno::ENOENT)
}

fn kind_of(mode: u32) -> HostKind {
    match mode & sys::mode::S_IFMT {
        sys::mode::S_IFREG => HostKind::File,
        sys::mode::S_IFDIR => HostKind::Dir,
        sys::mode::S_IFLNK => HostKind::HostSymlink,
        _ => HostKind::Other,
    }
}

fn id_of(st: &sys::Stat) -> HostId {
    HostId {
        volume: st.dev,
        file: u128::from(st.ino),
    }
}

fn time(t: (i64, u32)) -> Timespec {
    Timespec { secs: t.0, nsecs: t.1 }
}

fn host_stat(st: &sys::Stat) -> HostStat {
    HostStat {
        id: id_of(st),
        kind: kind_of(st.mode),
        size: st.size,
        blocks: st.blocks,
        nlink: u32::try_from(st.nlink).unwrap_or(u32::MAX),
        perm: u16::try_from(st.mode & 0o777).unwrap_or(0),
        atime: time(st.atime),
        mtime: time(st.mtime),
        ctime: time(st.ctime),
    }
}

/// A held directory.
#[derive(Debug)]
pub struct DirFd {
    fd: OwnedFd,
    id: HostId,
    /// Names beneath it are folded by the host: lookups check the stored
    /// name.
    folds: bool,
}

/// How many names a [`Leaf`] keeps. A name used since moves to the front;
/// one pushed out is found again by the search of the held directories
/// ([`SEARCH_MAX`]), so the guest's own links never lose an object.
pub const NAMES_MAX: usize = 8;

/// How many directory entries one search for a leaf's name reads at most
/// before the answer is ENOENT.
pub const SEARCH_MAX: usize = 1 << 16;

/// A non-directory: its identity, where it is known, and the descriptor of
/// the guest's widest open of it.
#[derive(Debug)]
pub struct Leaf {
    id: HostId,
    state: Mutex<LeafState>,
}

#[derive(Debug, Default)]
struct LeafState {
    /// (directory, its identity, name), the most recently used first, at
    /// most [`NAMES_MAX`]. The directory is held by its own node, never by a
    /// leaf's name: a name whose directory the guest forgot is dropped, so a
    /// node holds one descriptor at most ([`crate::limits::descriptors`]).
    names: Vec<(Weak<DirFd>, HostId, Box<[u8]>)>,
    /// The widest descriptor the guest has had of it, kept until the node
    /// is forgotten (as virtiofsd's `O_PATH` descriptor keeps the inode).
    held: Option<(Arc<File>, OpenMode)>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Leaf {
    /// Puts `(dir, name)` first.
    fn add_name(&self, dir: &Arc<DirFd>, name: &[u8]) {
        let mut st = lock(&self.state);
        st.names.retain(|(d, id, n)| d.strong_count() > 0 && !(*id == dir.id && **n == *name));
        st.names.insert(0, (Arc::downgrade(dir), dir.id, name.into()));
        st.names.truncate(NAMES_MAX);
    }

    fn remove_name(&self, dir: HostId, name: &[u8]) {
        lock(&self.state).names.retain(|(_, id, n)| !(*id == dir && **n == *name));
    }

    /// The names whose directory is still held, the others dropped.
    fn names(&self) -> Vec<(Arc<DirFd>, Box<[u8]>)> {
        let mut st = lock(&self.state);
        let mut live = Vec::with_capacity(st.names.len());
        st.names.retain(|(d, _, n)| match d.upgrade() {
            Some(d) => {
                live.push((d, n.clone()));
                true
            }
            None => false,
        });
        live
    }

    fn held(&self) -> Option<(Arc<File>, OpenMode)> {
        lock(&self.state).held.clone()
    }

    /// Keeps `f` if it is wider than the held descriptor.
    fn hold(&self, f: &Arc<File>, mode: OpenMode) {
        let score = |m: OpenMode| u8::from(m.read) + 2 * u8::from(m.write);
        let mut st = lock(&self.state);
        if st.held.as_ref().is_none_or(|(_, m)| score(mode) > score(*m)) {
            st.held = Some((f.clone(), mode));
        }
    }
}

/// Where a leaf is now.
enum At {
    /// Beneath a held directory, by this name, as `fstatat` found it.
    Name(Arc<DirFd>, Box<[u8]>, sys::Stat),
    /// Nowhere: unlinked while the guest held it; its descriptor.
    Unlinked(Arc<File>, OpenMode),
}

/// Weak references by identity, pruned as they grow.
#[derive(Debug)]
struct Registry<T> {
    map: HashMap<HostId, Weak<T>>,
    prune_at: usize,
}

impl<T> Registry<T> {
    fn new() -> Registry<T> {
        Registry {
            map: HashMap::new(),
            prune_at: 1024,
        }
    }

    fn get(&self, id: HostId) -> Option<Arc<T>> {
        self.map.get(&id).and_then(Weak::upgrade)
    }

    fn insert(&mut self, id: HostId, v: &Arc<T>) {
        if self.map.len() >= self.prune_at {
            self.map.retain(|_, w| w.strong_count() > 0);
            self.prune_at = (self.map.len() * 2).max(1024);
        }
        self.map.insert(id, Arc::downgrade(v));
    }

    fn live(&self) -> Vec<Arc<T>> {
        self.map.values().filter_map(Weak::upgrade).collect()
    }
}

/// What the node table holds for each node.
#[derive(Clone, Debug)]
pub enum HostNode {
    /// A directory, held open.
    Dir(Arc<DirFd>),
    /// Anything else.
    Leaf(Arc<Leaf>),
}

/// An open object.
#[derive(Debug)]
pub enum HostOpen {
    /// A regular file, opened with the guest's access mode only (shared with
    /// its leaf, which keeps the widest).
    File(Arc<File>),
    /// A directory being listed.
    Dir(RefCell<sys::DirReader>, HostId),
}

/// The share's settings that reach the backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// Run on a volume that folds case (the operator's explicit choice,
    /// docs/design-fs.md §7): exact-name lookups, EEXIST on a collision.
    pub case_insensitive_ok: bool,
}

/// Why a share is not served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A shared host directory.
#[derive(Debug)]
pub struct HostDir {
    root: Arc<DirFd>,
    dev: u64,
    /// Each non-directory the server knows, one leaf per identity.
    leaves: Mutex<Registry<Leaf>>,
    /// Each directory the server holds, for the search of a leaf's name.
    dirs: Mutex<Registry<DirFd>>,
    /// The volume takes an exchange ([`sys::rename_swap`]); else EINVAL,
    /// without asking it.
    swap: bool,
}

/// Whether names beneath `fd` are folded. macOS: always checked, as APFS
/// and HFS+ fold Unicode normalization on every volume. Linux: a casefold
/// directory, vfat or exfat.
fn folds(fd: BorrowedFd<'_>) -> Result<bool, sys::HostErrno> {
    #[cfg(target_os = "macos")]
    {
        let _ = fd;
        Ok(true)
    }
    #[cfg(target_os = "linux")]
    {
        sys::case_sensitive(fd).map(|s| !s)
    }
}

impl HostDir {
    /// Serves the directory `root` (opened for reading by stage 0).
    ///
    /// Refused: a host without beneath-resolution (Linux before 5.6 or
    /// without `openat2`, macOS without `O_RESOLVE_BENEATH`; design-fs
    /// decision 5), and a root whose names fold case unless
    /// `case_insensitive_ok`.
    pub fn new(root: OwnedFd, options: Options) -> Result<HostDir, Refusal> {
        let st = sys::fstat(root.as_fd()).map_err(|e| Refusal(format!("cannot read the share's root: {e:?}")))?;
        if kind_of(st.mode) != HostKind::Dir {
            return Err(Refusal("the share's root is not a directory".into()));
        }
        sys::probe_beneath(root.as_fd()).map_err(|e| {
            #[cfg(target_os = "linux")]
            let what = "openat2(RESOLVE_BENEATH), Linux 5.6 or later and allowed by any seccomp filter";
            #[cfg(target_os = "macos")]
            let what = "O_RESOLVE_BENEATH (macOS 15.4 or later)";
            Refusal(format!("this host has no {what}: an open of `..` beneath the share was not refused ({e:?})"))
        })?;
        let sensitive = sys::case_sensitive(root.as_fd())
            .map_err(|e| Refusal(format!("cannot tell whether the share's volume folds case: {e:?}")))?;
        if !sensitive && !options.case_insensitive_ok {
            return Err(Refusal(
                "the share's names are case-insensitive: two guest names that differ only by case would be one \
                 host file. Use a case-sensitive volume, or allow it explicitly (exact-name lookups, EEXIST on a \
                 collision)"
                    .into(),
            ));
        }
        let folds = folds(root.as_fd()).map_err(|e| Refusal(format!("cannot read the share's flags: {e:?}")))?;
        let root = Arc::new(DirFd {
            fd: root,
            id: id_of(&st),
            folds,
        });
        let swap = sys::rename_swap(root.fd.as_fd())
            .map_err(|e| Refusal(format!("cannot read the share's volume capabilities: {e:?}")))?;
        let mut dirs = Registry::new();
        dirs.insert(root.id, &root);
        Ok(HostDir {
            root,
            dev: st.dev,
            leaves: Mutex::new(Registry::new()),
            dirs: Mutex::new(dirs),
            swap,
        })
    }

    fn dir<'a>(&self, node: &'a HostNode) -> Result<&'a Arc<DirFd>, DirError> {
        match node {
            HostNode::Dir(d) => Ok(d),
            HostNode::Leaf(_) => Err(DirError::Errno(Errno::ENOTDIR)),
        }
    }

    /// ENOENT unless `name` is stored as exactly these bytes beneath `dir`.
    fn exact(&self, dir: &DirFd, name: &[u8]) -> Result<(), DirError> {
        if !dir.folds {
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        {
            let stored = sys::stored_name(dir.fd.as_fd(), name).map_err(err)?;
            if stored == name { Ok(()) } else { Err(enoent()) }
        }
        #[cfg(target_os = "linux")]
        {
            // No call names the stored form: list the directory.
            let fd = sys::reopen_dir(dir.fd.as_fd()).map_err(open_err)?;
            let mut r = sys::DirReader::new(fd).map_err(err)?;
            let mut after = 0;
            loop {
                let mut batch = Vec::new();
                r.read(after, 256, &mut batch).map_err(err)?;
                let Some(last) = batch.last() else {
                    return Err(enoent());
                };
                after = last.cookie;
                if batch.iter().any(|e| e.name == name) {
                    return Ok(());
                }
            }
        }
    }

    /// The object `name` beneath `dir`, not following a link: on the share's
    /// device and stored under exactly that name.
    fn find(&self, dir: &DirFd, name: &[u8]) -> Result<sys::Stat, DirError> {
        let st = sys::fstatat(dir.fd.as_fd(), name).map_err(err)?;
        self.exact(dir, name)?;
        if st.dev != self.dev {
            // A mount point beneath the share.
            return Err(DirError::Errno(Errno::EXDEV));
        }
        Ok(st)
    }

    /// The directory `name` beneath `parent`, which must be `want`: the
    /// descriptor already held for that identity (one per directory, so a
    /// node holds one at most), else opened.
    fn hold_dir(&self, parent: &DirFd, name: &[u8], want: &sys::Stat) -> Result<Arc<DirFd>, DirError> {
        if let Some(d) = lock(&self.dirs).get(id_of(want)) {
            return Ok(d);
        }
        let fd = sys::open_dir(parent.fd.as_fd(), name).map_err(open_err)?;
        let st = sys::fstat(fd.as_fd()).map_err(err)?;
        if (st.dev, st.ino) != (want.dev, want.ino) {
            return Err(enoent());
        }
        let folds = folds(fd.as_fd()).map_err(err)?;
        let d = Arc::new(DirFd {
            fd,
            id: id_of(&st),
            folds,
        });
        lock(&self.dirs).insert(d.id, &d);
        Ok(d)
    }

    /// The leaf of `id`, made if the server knows none.
    fn leaf(&self, id: HostId) -> Arc<Leaf> {
        let mut leaves = lock(&self.leaves);
        if let Some(l) = leaves.get(id) {
            return l;
        }
        let l = Arc::new(Leaf {
            id,
            state: Mutex::default(),
        });
        leaves.insert(id, &l);
        l
    }

    /// The leaf of `id`, if the server knows one.
    fn known(&self, id: HostId) -> Option<Arc<Leaf>> {
        lock(&self.leaves).get(id)
    }

    /// Where `leaf` is now: by a known name that is still it; else, if it
    /// has no name at all, its descriptor; else by a name found in the held
    /// directories. ENOENT if none.
    fn locate(&self, leaf: &Leaf) -> Result<At, DirError> {
        let mut failure = None;
        for (d, n) in leaf.names() {
            match sys::fstatat(d.fd.as_fd(), &n) {
                Ok(st) if id_of(&st) == leaf.id => {
                    leaf.add_name(&d, &n);
                    return Ok(At::Name(d, n, st));
                }
                // Gone, or another object's name now.
                Ok(_) => leaf.remove_name(d.id, &n),
                Err(e) if e.0 == sys::errno::ENOENT || e.0 == sys::errno::ENOTDIR => leaf.remove_name(d.id, &n),
                Err(e) => failure = failure.or_else(|| Some(err(e))),
            }
        }
        if let Some((f, mode)) = leaf.held() {
            let st = sys::fstat(f.as_fd()).map_err(err)?;
            if st.nlink == 0 {
                return Ok(At::Unlinked(f, mode));
            }
        }
        if let Some((d, n, st)) = self.search(leaf.id) {
            leaf.add_name(&d, &n);
            return Ok(At::Name(d, n, st));
        }
        Err(failure.unwrap_or_else(enoent))
    }

    /// A name of `id` in a directory the server holds, reading at most
    /// [`SEARCH_MAX`] entries: an object the guest reaches is beneath one
    /// (its parent's node holds it), so a name the leaf no longer keeps is
    /// found here.
    fn search(&self, id: HostId) -> Option<(Arc<DirFd>, Box<[u8]>, sys::Stat)> {
        if id.volume != self.dev {
            return None;
        }
        let dirs = lock(&self.dirs).live();
        let mut read = 0;
        for d in dirs {
            let Ok(fd) = sys::reopen_dir(d.fd.as_fd()) else {
                continue;
            };
            let Ok(mut r) = sys::DirReader::new(fd) else {
                continue;
            };
            let mut after = 0;
            loop {
                let mut batch = Vec::new();
                if r.read(after, 256, &mut batch).is_err() {
                    break;
                }
                let Some(last) = batch.last() else {
                    break;
                };
                after = last.cookie;
                for e in batch {
                    read += 1;
                    if read > SEARCH_MAX {
                        return None;
                    }
                    // d_ino is not st_ino on every file system (overlayfs):
                    // each guest name is checked by fstatat.
                    if Name::new(&e.name).is_err() {
                        continue;
                    }
                    if let Ok(st) = sys::fstatat(d.fd.as_fd(), &e.name)
                        && id_of(&st) == id
                    {
                        return Some((d.clone(), e.name.into(), st));
                    }
                }
            }
        }
        None
    }

    /// The regular file `name` beneath `dir` opened, checked to be `id`.
    fn open_at(dir: &DirFd, name: &[u8], st: &sys::Stat, id: HostId, read: bool, write: bool) -> Result<File, DirError> {
        // Its kind first (as `locate` found it): a FIFO, socket or device is
        // never opened.
        match kind_of(st.mode) {
            HostKind::File => {}
            HostKind::Dir => return Err(DirError::Errno(Errno::EISDIR)),
            HostKind::HostSymlink => return Err(DirError::Errno(Errno::ELOOP)),
            HostKind::Other => return Err(DirError::Errno(Errno::EACCES)),
        }
        let fd = sys::open_file(dir.fd.as_fd(), name, read, write).map_err(open_err)?;
        let st = sys::fstat(fd.as_fd()).map_err(err)?;
        if id_of(&st) != id || kind_of(st.mode) != HostKind::File {
            return Err(enoent());
        }
        Ok(File::from(fd))
    }

    /// A leaf opened for `mode`, checked: by its name, or, unlinked, its
    /// descriptor if that has the access.
    fn open_leaf(&self, leaf: &Leaf, mode: OpenMode) -> Result<Arc<File>, DirError> {
        match self.locate(leaf)? {
            At::Name(d, n, st) => Ok(Arc::new(Self::open_at(&d, &n, &st, leaf.id, mode.read, mode.write)?)),
            At::Unlinked(f, held) if (!mode.read || held.read) && (!mode.write || held.write) => Ok(f),
            At::Unlinked(..) => Err(enoent()),
        }
    }

    /// A descriptor of a file or directory node, checked, for its metadata
    /// (attributes, mode, times): a directory's own, a leaf's held one, or
    /// the leaf opened for reading.
    fn meta_fd(&self, node: &HostNode) -> Result<Meta, DirError> {
        match node {
            HostNode::Dir(d) => {
                let fd = sys::reopen_dir(d.fd.as_fd()).map_err(open_err)?;
                let st = sys::fstat(fd.as_fd()).map_err(err)?;
                if id_of(&st) != d.id {
                    return Err(enoent());
                }
                Ok(Meta::Own(fd))
            }
            HostNode::Leaf(l) => match self.locate(l)? {
                At::Name(d, n, st) => match l.held() {
                    // Found by a name, so in the share: its held descriptor
                    // is the same object.
                    Some((f, _)) if kind_of(st.mode) == HostKind::File => Ok(Meta::Held(f)),
                    _ => Ok(Meta::Own(Self::open_at(&d, &n, &st, l.id, true, false)?.into())),
                },
                At::Unlinked(f, _) => Ok(Meta::Held(f)),
            },
        }
    }

    /// Whether a node is a regular file or directory now (the only kinds
    /// with a record and attributes), checked without opening it.
    fn carries_metadata(&self, node: &HostNode) -> Result<bool, DirError> {
        match node {
            HostNode::Dir(_) => Ok(true),
            HostNode::Leaf(l) => match self.locate(l)? {
                At::Name(_, _, st) => Ok(kind_of(st.mode) == HostKind::File),
                At::Unlinked(..) => Ok(true),
            },
        }
    }

    fn node_id(node: &HostNode) -> HostId {
        match node {
            HostNode::Dir(d) => d.id,
            HostNode::Leaf(l) => l.id,
        }
    }

    fn guest_xattr(name: &[u8]) -> Vec<u8> {
        [GUEST_XATTR_PREFIX, name].concat()
    }
}

/// A descriptor for metadata: opened for it, or a leaf's held one.
enum Meta {
    Own(OwnedFd),
    Held(Arc<File>),
}

impl AsFd for Meta {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Meta::Own(fd) => fd.as_fd(),
            Meta::Held(f) => f.as_fd(),
        }
    }
}

impl ConfinedDir for HostDir {
    type Node = HostNode;
    type Open = HostOpen;

    fn root(&self) -> HostNode {
        HostNode::Dir(self.root.clone())
    }

    fn lookup(&self, parent: &HostNode, name: Name<'_>) -> Result<(HostNode, HostStat), DirError> {
        let p = self.dir(parent)?;
        let st = self.find(p, name.as_bytes())?;
        let node = if kind_of(st.mode) == HostKind::Dir {
            HostNode::Dir(self.hold_dir(p, name.as_bytes(), &st)?)
        } else {
            let leaf = self.leaf(id_of(&st));
            leaf.add_name(p, name.as_bytes());
            HostNode::Leaf(leaf)
        };
        Ok((node, host_stat(&st)))
    }

    fn stat(&self, node: &HostNode) -> Result<HostStat, DirError> {
        match node {
            HostNode::Dir(d) => {
                let st = sys::fstat(d.fd.as_fd()).map_err(err)?;
                Ok(host_stat(&st))
            }
            HostNode::Leaf(l) => match self.locate(l)? {
                At::Name(_, _, st) => Ok(host_stat(&st)),
                At::Unlinked(f, _) => Ok(host_stat(&sys::fstat(f.as_fd()).map_err(err)?)),
            },
        }
    }

    fn open(&self, node: &HostNode, expect: HostId, mode: OpenMode) -> Result<HostOpen, DirError> {
        match node {
            HostNode::Dir(_) => Err(DirError::Errno(Errno::EISDIR)),
            HostNode::Leaf(l) => {
                if l.id != expect {
                    return Err(enoent());
                }
                let f = self.open_leaf(l, mode)?;
                l.hold(&f, mode);
                Ok(HostOpen::File(f))
            }
        }
    }

    fn open_dir(&self, node: &HostNode, expect: HostId) -> Result<HostOpen, DirError> {
        let d = self.dir(node)?;
        if d.id != expect {
            return Err(enoent());
        }
        let fd = sys::reopen_dir(d.fd.as_fd()).map_err(open_err)?;
        let st = sys::fstat(fd.as_fd()).map_err(err)?;
        if id_of(&st) != d.id {
            return Err(enoent());
        }
        let reader = sys::DirReader::new(fd).map_err(err)?;
        Ok(HostOpen::Dir(RefCell::new(reader), d.id))
    }

    fn close(&self, open: HostOpen) {
        drop(open);
    }

    fn create(&self, parent: &HostNode, name: Name<'_>, exclusive: bool) -> Result<(HostNode, HostOpen, HostStat), DirError> {
        let p = self.dir(parent)?;
        let n = name.as_bytes();
        // What is there: another kind is never opened; on a folding volume,
        // another name for it is a collision.
        match sys::fstatat(p.fd.as_fd(), n) {
            Ok(st) => {
                if exclusive {
                    return Err(DirError::Errno(Errno::EEXIST));
                }
                if self.exact(p, n).is_err() {
                    return Err(DirError::Errno(Errno::EEXIST));
                }
                match kind_of(st.mode) {
                    HostKind::File => {}
                    HostKind::Dir => return Err(DirError::Errno(Errno::EISDIR)),
                    HostKind::HostSymlink | HostKind::Other => return Err(DirError::Errno(Errno::EEXIST)),
                }
            }
            Err(e) if e.0 == sys::errno::ENOENT => {}
            Err(e) => return Err(err(e)),
        }
        let fd = sys::create_file(p.fd.as_fd(), n, exclusive, 0o600).map_err(open_err)?;
        let st = sys::fstat(fd.as_fd()).map_err(err)?;
        if kind_of(st.mode) != HostKind::File || st.dev != self.dev {
            return Err(DirError::Errno(Errno::EEXIST));
        }
        let f = Arc::new(File::from(fd));
        let leaf = self.leaf(id_of(&st));
        leaf.add_name(p, n);
        leaf.hold(&f, OpenMode { read: true, write: true });
        Ok((HostNode::Leaf(leaf), HostOpen::File(f), host_stat(&st)))
    }

    fn mkdir(&self, parent: &HostNode, name: Name<'_>) -> Result<(HostNode, HostStat), DirError> {
        let p = self.dir(parent)?;
        sys::mkdirat(p.fd.as_fd(), name.as_bytes(), 0o700).map_err(err)?;
        self.lookup(parent, name)
    }

    fn unlink(&self, parent: &HostNode, name: Name<'_>, expect: HostId) -> Result<(), DirError> {
        let p = self.dir(parent)?;
        let st = self.find(p, name.as_bytes())?;
        if id_of(&st) != expect {
            return Err(enoent());
        }
        if kind_of(st.mode) == HostKind::Dir {
            return Err(DirError::Errno(Errno::EISDIR));
        }
        sys::unlinkat(p.fd.as_fd(), name.as_bytes(), false).map_err(err)?;
        if let Some(l) = self.known(expect) {
            l.remove_name(p.id, name.as_bytes());
        }
        Ok(())
    }

    fn rmdir(&self, parent: &HostNode, name: Name<'_>, expect: HostId) -> Result<(), DirError> {
        let p = self.dir(parent)?;
        let st = self.find(p, name.as_bytes())?;
        if id_of(&st) != expect {
            return Err(enoent());
        }
        if kind_of(st.mode) != HostKind::Dir {
            return Err(DirError::Errno(Errno::ENOTDIR));
        }
        sys::unlinkat(p.fd.as_fd(), name.as_bytes(), true).map_err(err)
    }

    fn rename(&self, from: (&HostNode, Name<'_>), to: (&HostNode, Name<'_>), flags: RenameFlags) -> Result<(), DirError> {
        let fd = self.dir(from.0)?;
        let td = self.dir(to.0)?;
        let src = self.find(fd, from.1.as_bytes())?;
        // The target, if there is one, by its exact name: on a folding
        // volume another name for an object is a collision, not it.
        let target = match sys::fstatat(td.fd.as_fd(), to.1.as_bytes()) {
            Ok(st) => {
                let same = (src.dev, src.ino) == (st.dev, st.ino);
                if !same && self.exact(td, to.1.as_bytes()).is_err() {
                    return Err(DirError::Errno(Errno::EEXIST));
                }
                if st.dev != self.dev {
                    return Err(DirError::Errno(Errno::EXDEV));
                }
                Some(st)
            }
            Err(e) if e.0 == sys::errno::ENOENT => None,
            Err(e) => return Err(err(e)),
        };
        // A volume that does not report an exchange is never asked for one
        // (macOS: one may answer 0 without it, `sys::rename_swap`); a
        // missing target is ENOENT first, as Linux finds both names before
        // the file system sees the flag.
        if flags.exchange && !self.swap {
            return Err(if target.is_none() { enoent() } else { DirError::Errno(Errno::EINVAL) });
        }
        let r = sys::rename(
            fd.fd.as_fd(),
            from.1.as_bytes(),
            td.fd.as_fd(),
            to.1.as_bytes(),
            flags.noreplace,
            flags.exchange,
        );
        // A file system without the flag: Linux's answer, EINVAL.
        r.map_err(|e| match e.0 {
            x if x == sys::errno::ENOTSUP || x == sys::errno::EOPNOTSUPP => DirError::Errno(Errno::EINVAL),
            _ => err(e),
        })?;
        // The leaves follow their names (two names of one object: nothing
        // moved).
        let (src, target) = (id_of(&src), target.as_ref().map(id_of));
        if target == Some(src) {
            return Ok(());
        }
        let (fname, tname) = (from.1.as_bytes(), to.1.as_bytes());
        if let Some(t) = target.and_then(|t| self.known(t)) {
            t.remove_name(td.id, tname);
            if flags.exchange {
                t.add_name(fd, fname);
            }
        }
        if let Some(s) = self.known(src) {
            s.remove_name(fd.id, fname);
            s.add_name(td, tname);
        }
        Ok(())
    }

    fn link(&self, node: &HostNode, expect: HostId, to: (&HostNode, Name<'_>)) -> Result<HostStat, DirError> {
        let HostNode::Leaf(l) = node else {
            return Err(DirError::Errno(Errno::EPERM));
        };
        let td = self.dir(to.0)?;
        if expect != l.id {
            return Err(enoent());
        }
        // An unlinked object gets no name back: ENOENT, as Linux's link(2).
        let At::Name(d, n, st) = self.locate(l)? else {
            return Err(enoent());
        };
        if kind_of(st.mode) != HostKind::File {
            return Err(DirError::Errno(Errno::EPERM));
        }
        sys::linkat(d.fd.as_fd(), &n, td.fd.as_fd(), to.1.as_bytes()).map_err(err)?;
        // The name may have been given to another object between the check
        // and the link (a host's swap): take the new name back.
        let new = sys::fstatat(td.fd.as_fd(), to.1.as_bytes()).map_err(err)?;
        if id_of(&new) != expect {
            let _ = sys::unlinkat(td.fd.as_fd(), to.1.as_bytes(), false);
            return Err(enoent());
        }
        l.add_name(td, to.1.as_bytes());
        Ok(host_stat(&new))
    }

    fn read_at(&self, open: &HostOpen, offset: u64, buf: &mut [u8]) -> Result<usize, DirError> {
        let HostOpen::File(f) = open else {
            return Err(DirError::Errno(Errno::EISDIR));
        };
        let mut done = 0;
        // A short read only at the end of the file, as Linux's read of a
        // regular file.
        while done < buf.len() {
            let at = offset.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            match f.read_at(&mut buf[done..], at) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(io_err(&e)),
            }
        }
        Ok(done)
    }

    fn write_at(&self, open: &HostOpen, offset: u64, data: &[u8]) -> Result<usize, DirError> {
        let HostOpen::File(f) = open else {
            return Err(DirError::Errno(Errno::EISDIR));
        };
        let mut done = 0;
        while done < data.len() {
            let at = offset.saturating_add(u64::try_from(done).unwrap_or(u64::MAX));
            match f.write_at(&data[done..], at) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if done > 0 => {
                    let _ = e;
                    break;
                }
                Err(e) => return Err(io_err(&e)),
            }
        }
        Ok(done)
    }

    fn sync(&self, open: &HostOpen, data_only: bool) -> Result<(), DirError> {
        let fd = match open {
            HostOpen::File(f) => f.as_fd(),
            HostOpen::Dir(r, _) => {
                let r = r.borrow();
                return sys::fsync(r.fd(), data_only).map_err(err);
            }
        };
        sys::fsync(fd, data_only).map_err(err)
    }

    fn set_len(&self, node: &HostNode, len: u64) -> Result<(), DirError> {
        let HostNode::Leaf(l) = node else {
            return Err(DirError::Errno(Errno::EISDIR));
        };
        // Through the held descriptor if it may write (the guest's ftruncate
        // of an unlinked file has a writable open), else opened by name.
        let f = match (self.locate(l)?, l.held()) {
            (At::Name(..) | At::Unlinked(..), Some((f, m))) if m.write => f,
            (At::Name(d, n, st), _) => Arc::new(Self::open_at(&d, &n, &st, l.id, false, true)?),
            (At::Unlinked(..), _) => return Err(enoent()),
        };
        f.set_len(len).map_err(|e| io_err(&e))
    }

    fn allocate(&self, open: &HostOpen, offset: u64, len: u64, keep_size: bool, punch: bool) -> Result<(), DirError> {
        let HostOpen::File(f) = open else {
            return Err(DirError::Errno(Errno::EISDIR));
        };
        sys::fallocate(f.as_fd(), offset, len, keep_size, punch).map_err(err)
    }

    fn set_times(&self, node: &HostNode, atime: Option<Timespec>, mtime: Option<Timespec>) -> Result<(), DirError> {
        let fd = self.meta_fd(node)?;
        let t = |t: Option<Timespec>| t.map(|t| (t.secs, t.nsecs));
        sys::futimens(fd.as_fd(), t(atime), t(mtime)).map_err(err)
    }

    fn set_perm(&self, node: &HostNode, perm: u16) -> Result<(), DirError> {
        let fd = self.meta_fd(node)?;
        // The server keeps its own access (owner read and write, and search
        // for a directory); never setuid, setgid or sticky.
        let own = if matches!(node, HostNode::Dir(_)) { 0o700 } else { 0o600 };
        sys::fchmod(fd.as_fd(), u32::from(perm & 0o777) | own).map_err(err)
    }

    fn read_dir(&self, dir: &HostOpen, after: u64, max: usize, out: &mut Vec<DirEntry>) -> Result<(), DirError> {
        let HostOpen::Dir(r, id) = dir else {
            return Err(DirError::Errno(Errno::ENOTDIR));
        };
        let mut r = r.borrow_mut();
        let mut raw = Vec::new();
        r.read(after, max, &mut raw).map_err(err)?;
        for e in raw {
            if e.cookie > MAX_COOKIE {
                break;
            }
            let kind = match e.dtype {
                sys::dtype::DT_REG => HostKind::File,
                sys::dtype::DT_DIR => HostKind::Dir,
                sys::dtype::DT_LNK => HostKind::HostSymlink,
                sys::dtype::DT_UNKNOWN => match sys::fstatat(r.fd(), &e.name) {
                    Ok(st) => kind_of(st.mode),
                    // Gone since it was listed: the server's lookup says so.
                    Err(_) => HostKind::Other,
                },
                _ => HostKind::Other,
            };
            out.push(DirEntry {
                name: e.name,
                id: HostId {
                    volume: id.volume,
                    file: u128::from(e.ino),
                },
                kind,
                cookie: e.cookie,
            });
        }
        Ok(())
    }

    fn read_link(&self, node: &HostNode, max: usize) -> Result<Vec<u8>, DirError> {
        let HostNode::Leaf(l) = node else {
            return Err(DirError::Errno(Errno::EINVAL));
        };
        let At::Name(d, n, before) = self.locate(l)? else {
            return Err(DirError::Errno(Errno::EINVAL));
        };
        if kind_of(before.mode) != HostKind::HostSymlink {
            return Err(DirError::Errno(Errno::EINVAL));
        }
        let target = sys::readlinkat(d.fd.as_fd(), &n, max).map_err(err)?;
        // Still the same link afterwards, or the target read is another's.
        let after = sys::fstatat(d.fd.as_fd(), &n).map_err(err)?;
        if id_of(&after) != l.id {
            return Err(enoent());
        }
        Ok(target)
    }

    fn statfs(&self, node: &HostNode) -> Result<StatFs, DirError> {
        let fd = match node {
            HostNode::Dir(d) => d.fd.as_fd(),
            // Every leaf is on the share's volume.
            HostNode::Leaf(_) => self.root.fd.as_fd(),
        };
        let s = sys::fstatvfs(fd).map_err(err)?;
        Ok(StatFs {
            blocks: s.blocks,
            bfree: s.bfree,
            bavail: s.bavail,
            files: s.files,
            ffree: s.ffree,
            bsize: u32::try_from(s.bsize).unwrap_or(u32::MAX),
            frsize: u32::try_from(s.frsize).unwrap_or(u32::MAX),
        })
    }

    fn get_record(&self, node: &HostNode) -> Result<Option<Vec<u8>>, DirError> {
        // A host symlink, FIFO, socket or device carries no record and is
        // never opened to look.
        if !self.carries_metadata(node)? {
            return Ok(None);
        }
        let fd = self.meta_fd(node)?;
        match sys::xattr::get(fd.as_fd(), RECORD_XATTR) {
            Ok(v) => Ok(v),
            // A file system without extended attributes holds no record
            // (stage 0 serves one read-only only).
            Err(e) if e.0 == sys::errno::ENOTSUP || e.0 == sys::errno::EOPNOTSUPP => Ok(None),
            Err(e) => Err(err(e)),
        }
    }

    fn set_record(&self, node: &HostNode, record: &[u8; RECORD_LEN]) -> Result<(), DirError> {
        let fd = self.meta_fd(node)?;
        sys::xattr::set(fd.as_fd(), RECORD_XATTR, record, false, false).map_err(err)
    }

    fn get_xattr(&self, node: &HostNode, name: &[u8]) -> Result<Option<Vec<u8>>, DirError> {
        let fd = self.meta_fd(node)?;
        sys::xattr::get(fd.as_fd(), &Self::guest_xattr(name)).map_err(err)
    }

    fn set_xattr(&self, node: &HostNode, name: &[u8], value: &[u8], mode: XattrMode) -> Result<(), DirError> {
        let fd = self.meta_fd(node)?;
        let (create, replace) = match mode {
            XattrMode::Any => (false, false),
            XattrMode::Create => (true, false),
            XattrMode::Replace => (false, true),
        };
        sys::xattr::set(fd.as_fd(), &Self::guest_xattr(name), value, create, replace).map_err(err)
    }

    fn list_xattr(&self, node: &HostNode) -> Result<Vec<(Vec<u8>, usize)>, DirError> {
        if !self.carries_metadata(node)? {
            return Ok(Vec::new());
        }
        let fd = self.meta_fd(node)?;
        let names = match sys::xattr::list(fd.as_fd()) {
            Ok(n) => n,
            Err(e) if e.0 == sys::errno::ENOTSUP || e.0 == sys::errno::EOPNOTSUPP => Vec::new(),
            Err(e) => return Err(err(e)),
        };
        let mut out = Vec::new();
        for n in names {
            // Only the guest's own; the host's others are not shown.
            let Some(guest) = n.strip_prefix(GUEST_XATTR_PREFIX) else {
                continue;
            };
            if let Some(v) = sys::xattr::get(fd.as_fd(), &n).map_err(err)? {
                out.push((guest.to_vec(), v.len()));
            }
        }
        Ok(out)
    }

    fn remove_xattr(&self, node: &HostNode, name: &[u8]) -> Result<(), DirError> {
        let fd = self.meta_fd(node)?;
        sys::xattr::remove(fd.as_fd(), &Self::guest_xattr(name)).map_err(err)
    }
}

fn io_err(e: &std::io::Error) -> DirError {
    err(sys::HostErrno(e.raw_os_error().unwrap_or(5)))
}

impl HostDir {
    /// The share root's identity.
    pub fn root_id(&self) -> HostId {
        self.root.id
    }

    /// The identity of a node.
    pub fn id(node: &HostNode) -> HostId {
        Self::node_id(node)
    }
}
