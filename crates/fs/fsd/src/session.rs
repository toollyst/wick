// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The server core: one guest's FUSE session over a [`ConfinedDir`]
//! (docs/design-fs.md §4). [`Session::handle`] takes a request frame's
//! payload and its `writable_cap` and gives the reply frame's payload, if
//! the request gets one. It runs each request to the end before the next
//! and never waits on the guest, so no request can hold the server.
//!
//! The rules it keeps, each tested below:
//! - **One reply per request that has buffers, none without.** A request
//!   with `writable_cap` 0 gets no reply frame; one with buffers gets exactly
//!   one, at most `writable_cap` bytes, empty when no FUSE reply fits or
//!   exists (a FORGET sent with buffers), so the VMM's tracker never waits.
//! - **A request runs only if its reply fits.** A fixed-size reply that does
//!   not fit the guest's buffers is ERANGE before anything is done, so no
//!   lookup is counted and nothing is created for a reply the guest never
//!   gets. Data replies (READ, READDIR, READDIRPLUS) are cut to the buffers,
//!   to the size the guest asked for and to `max_write`, and only that much
//!   is allocated: no size a guest names is allocated as it says.
//! - **Ids are keys.** A node id or `fh` is looked up in the server's tables
//!   and fails closed (EBADF): never an index or a pointer
//!   ([`crate::inodes`], [`crate::handles`]).
//! - **INIT first, once.** Before INIT every request is EIO; a second INIT is
//!   EIO; after DESTROY every request is EIO.
//! - **Nothing blocks on the guest's say-so.** INIT offers no POSIX or BSD
//!   locks, so the guest keeps locks to itself and GETLK, SETLK and SETLKW
//!   are ENOSYS at once, never a wait; INTERRUPT is ENOSYS (Linux's virtio-fs
//!   never sends it, and no request is ever pending to interrupt). No DAX
//!   (the decoder refuses its opcodes), `max_write` 1 MiB.
//! - **Limits before work**: nodes (ENFILE), handles (EMFILE), the byte budget
//!   (ENOSPC), the attribute budget (ENOSPC), each counted ([`Counters`]).
//! - **Metadata is the record's** ([`crate::record`]); a malformed stored
//!   record is EIO and counted, never repaired.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cache::CacheMode;
use crate::dir::{
    ConfinedDir, DirEntry, DirError, HostId, HostKind, HostStat, OpenMode, RenameFlags, Timespec,
    XattrMode,
};
use crate::fuse::decode::{InitIn, Op, ReadIn, SetattrIn, Wire, decode};
use crate::fuse::encode::{
    self, ATTR_OUT_LEN, Attr, ENTRY_OUT_LEN, EntryOut, INIT_OUT_LEN, InitOut, Kstatfs, STATFS_OUT_LEN,
};
use crate::fuse::name::{NAME_MAX, Name};
use crate::fuse::{Errno, InHeader, KERNEL_MINOR_VERSION, KERNEL_VERSION, MAX_WRITE, OUT_HEADER_LEN, Opcode, PATH_MAX};
use crate::handles::{Handles, Kind};
use crate::inodes::{Forgot, Inodes, ROOT};
use crate::limits::{Counters, GUEST_XATTR_NAME_MAX, Limits, MAX_READ, XATTR_ENTRY_COST};
use crate::record::{
    self, Record, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, S_ISGID,
};

/// The oldest protocol minor version the server takes: 7.31, the first
/// with virtio-fs (Linux 5.4).
pub const MIN_MINOR: u32 = 31;

/// INIT flags the server may answer with (each only if the guest offered
/// it). Never `FUSE_POSIX_LOCKS` (1 << 1), `FUSE_FLOCK_LOCKS` (1 << 10),
/// `FUSE_MAP_ALIGNMENT` or DAX, `FUSE_WRITEBACK_CACHE`, `FUSE_EXPORT_SUPPORT`,
/// `FUSE_DONT_MASK`, `FUSE_POSIX_ACL`, `FUSE_HANDLE_KILLPRIV(_V2)`,
/// `FUSE_SETXATTR_EXT` or `FUSE_SECURITY_CTX` (so the decoder's [`Wire`] is
/// the default one).
const INIT_FLAGS: u32 = (1 << 0) // FUSE_ASYNC_READ
    | (1 << 5) // FUSE_BIG_WRITES
    | (1 << 13) // FUSE_DO_READDIRPLUS
    | (1 << 14) // FUSE_READDIRPLUS_AUTO
    | (1 << 22); // FUSE_MAX_PAGES

/// `max_pages` with `FUSE_MAX_PAGES`: `max_write` in 4 KiB pages.
const MAX_PAGES: u16 = 256;
const _: () = assert!(MAX_PAGES as u32 * 4096 == MAX_WRITE);

const O_ACCMODE: u32 = 3;
const O_EXCL: u32 = 0o200;
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;
const FATTR_ATIME: u32 = 1 << 4;
const FATTR_MTIME: u32 = 1 << 5;
const FATTR_FH: u32 = 1 << 6;
const FATTR_ATIME_NOW: u32 = 1 << 7;
const FATTR_MTIME_NOW: u32 = 1 << 8;
const FUSE_GETATTR_FH: u32 = 1 << 0;
const RENAME_NOREPLACE: u32 = 1 << 0;
const RENAME_EXCHANGE: u32 = 1 << 1;
const FALLOC_FL_KEEP_SIZE: u32 = 1 << 0;
const FALLOC_FL_PUNCH_HOLE: u32 = 1 << 1;
const XATTR_CREATE: u32 = 1;
const XATTR_REPLACE: u32 = 2;
const DT_UNKNOWN: u32 = 0;
const DT_DIR: u32 = 4;
const DT_LNK: u32 = 10;

/// Entries asked of the backend per READDIR round.
pub(crate) const READDIR_BATCH: usize = 64;

/// One share's settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Cache mode.
    pub cache: CacheMode,
    /// Every change refused with EROFS.
    pub read_only: bool,
    /// The uid and gid shown for objects without a record.
    pub owner: (u32, u32),
    /// Limits.
    pub limits: Limits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Before INIT.
    Waiting,
    /// After INIT, with the protocol minor version agreed.
    Ready { minor: u32 },
    /// After DESTROY.
    Destroyed,
}

type Done = Result<Vec<u8>, Errno>;

/// One guest's session.
#[derive(Debug)]
pub struct Session<D: ConfinedDir> {
    dir: D,
    config: Config,
    state: State,
    inodes: Inodes<D::Node>,
    handles: Handles<D::Open>,
    bytes_added: u64,
    counters: Counters,
}

/// A host identity as an inode number: a mix of its bits, never 0 (a
/// directory entry with inode 0 is skipped). Not unique in theory; the
/// guest uses node ids, not this, to tell objects apart.
pub fn ino_of(id: HostId) -> u64 {
    let lo = u64::try_from(id.file & u128::from(u64::MAX)).unwrap_or(0);
    let hi = u64::try_from(id.file >> 64).unwrap_or(0);
    let mut x = lo ^ hi.rotate_left(29) ^ id.volume.rotate_left(47);
    // splitmix64's finalizer.
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x.max(1)
}

/// The permission bits a host object gets for a guest mode: the guest's
/// for a regular file or directory; none for an emulated symlink, FIFO,
/// socket or device, a regular host file host tools should neither run nor
/// read as what it stands for (design-fs row 12). The backend adds the
/// server's own access.
fn host_perm(mode: u32) -> u16 {
    match mode & S_IFMT {
        S_IFREG | S_IFDIR => u16::try_from(mode & 0o777).unwrap_or(0),
        _ => 0,
    }
}

fn bits_u64(v: i64) -> u64 {
    u64::from_le_bytes(v.to_le_bytes())
}

fn bits_i64(v: u64) -> i64 {
    i64::from_le_bytes(v.to_le_bytes())
}

fn now() -> Timespec {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    Timespec {
        secs: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        nsecs: d.subsec_nanos(),
    }
}

fn usize_of(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl<D: ConfinedDir> Session<D> {
    /// A session over `dir`, waiting for INIT.
    pub fn new(dir: D, config: Config) -> Result<Session<D>, DirError> {
        let root = dir.root();
        let stat = dir.stat(&root)?;
        if stat.kind != HostKind::Dir {
            return Err(DirError::Errno(Errno::ENOTDIR));
        }
        let config = Config {
            cache: config.cache.clamped(),
            ..config
        };
        Ok(Session {
            inodes: Inodes::new(root, stat.id, config.limits.max_nodes),
            handles: Handles::new(config.limits.max_handles),
            dir,
            config,
            state: State::Waiting,
            bytes_added: 0,
            counters: Counters::default(),
        })
    }

    /// The counters.
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// The backend.
    pub fn dir(&self) -> &D {
        &self.dir
    }

    /// Nodes held, the root included.
    pub fn nodes(&self) -> usize {
        self.inodes.len()
    }

    /// Handles open.
    pub fn handles_open(&self) -> usize {
        self.handles.len()
    }

    /// Bytes the guest's writes have added, against the byte budget.
    pub fn bytes_added(&self) -> u64 {
        self.bytes_added
    }

    /// Whether DESTROY ended the session.
    pub fn destroyed(&self) -> bool {
        self.state == State::Destroyed
    }

    /// The guest's lookups and open handles of a node, if held.
    pub fn node_counts(&self, nodeid: u64) -> Option<(u64, u32)> {
        self.inodes.counts(nodeid)
    }

    /// The host identity a held node stands for (tests and fuzzing).
    pub fn node_host_id(&self, nodeid: u64) -> Option<HostId> {
        self.inodes.get(nodeid).ok().map(|e| e.id)
    }

    /// Whether the tables keep their rules: every handle on a held node,
    /// every count within its limit. The fuzz target checks it after each
    /// request.
    pub fn check(&self) -> Result<(), String> {
        let limits = &self.config.limits;
        if self.inodes.len() > limits.max_nodes.max(1) {
            return Err(format!("{} nodes, limit {}", self.inodes.len(), limits.max_nodes));
        }
        if self.handles.len() > limits.max_handles {
            return Err(format!("{} handles, limit {}", self.handles.len(), limits.max_handles));
        }
        if self.bytes_added > limits.max_bytes {
            return Err(format!("{} bytes added, limit {}", self.bytes_added, limits.max_bytes));
        }
        for nodeid in self.handles.nodes() {
            match self.inodes.counts(nodeid) {
                Some((_, h)) if h > 0 => {}
                other => return Err(format!("a handle on node {nodeid}, which has {other:?}")),
            }
        }
        Ok(())
    }

    /// Serves one request: `payload` is a request frame's payload and
    /// `writable_cap` its chain's writable bytes. The reply frame's payload,
    /// if the request gets a frame (exactly when `writable_cap` is not 0),
    /// at most `writable_cap` bytes.
    pub fn handle(&mut self, payload: &[u8], writable_cap: usize) -> Option<Vec<u8>> {
        let (unique, done) = match decode(payload, &Wire::default()) {
            Ok(request) => {
                // The request in flight when Seatbelt reports a call, by the
                // time (a discovery build only).
                crate::discovery_spacing();
                crate::discovery_say(format_args!(
                    "request {:?} node {}",
                    Opcode::from_wire(request.header.opcode),
                    request.header.nodeid
                ));
                let done = self.dispatch(&request.header, request.op, writable_cap);
                (request.header.unique, done)
            }
            Err(refused) => {
                self.counters.requests_refused += 1;
                let has_reply = refused
                    .header
                    .and_then(|h| Opcode::from_wire(h.opcode))
                    .is_none_or(Opcode::has_reply);
                let unique = refused.header.map_or(0, |h| h.unique);
                (unique, has_reply.then_some(Err(refused.error.errno())))
            }
        };
        if writable_cap == 0 {
            return None;
        }
        let reply = match done {
            None => Vec::new(),
            Some(Ok(body)) => match encode::reply(unique, &[&body], writable_cap) {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.counters.replies_too_long += 1;
                    self.error_reply(unique, Errno::ERANGE, writable_cap)
                }
            },
            Some(Err(e)) => self.error_reply(unique, e, writable_cap),
        };
        Some(reply)
    }

    fn error_reply(&mut self, unique: u64, e: Errno, cap: usize) -> Vec<u8> {
        if cap >= OUT_HEADER_LEN {
            encode::error(unique, e).to_vec()
        } else {
            self.counters.replies_too_long += 1;
            Vec::new()
        }
    }

    /// ERANGE unless a reply of `len` bytes after the header fits.
    fn fits(&mut self, cap: usize, len: usize) -> Result<(), Errno> {
        if cap >= OUT_HEADER_LEN.saturating_add(len) {
            Ok(())
        } else {
            self.counters.replies_too_long += 1;
            Err(Errno::ERANGE)
        }
    }

    fn dispatch(&mut self, h: &InHeader, op: Op<'_>, cap: usize) -> Option<Done> {
        // Requests without a reply run whatever the buffers are.
        match op {
            Op::Forget { nlookup } => {
                if matches!(self.state, State::Ready { .. }) {
                    self.forget(h.nodeid, nlookup);
                }
                return None;
            }
            Op::BatchForget(forgets) => {
                if matches!(self.state, State::Ready { .. }) {
                    for (nodeid, n) in forgets.iter() {
                        self.forget(nodeid, n);
                    }
                }
                return None;
            }
            _ => {}
        }
        // Not even a header fits: nothing can carry the reply, so nothing
        // is done (DESTROY, RELEASE and UNLINK included).
        if let Err(e) = self.fits(cap, 0) {
            return Some(Err(e));
        }
        let minor = match (self.state, &op) {
            (State::Waiting, Op::Init(init)) => return Some(self.init(init, cap)),
            (State::Ready { .. }, Op::Init(_)) => return Some(Err(Errno::EIO)),
            (State::Ready { minor }, _) => minor,
            (State::Waiting | State::Destroyed, _) => return Some(Err(Errno::EIO)),
        };
        Some(self.ready(h, op, cap, minor))
    }

    fn forget(&mut self, nodeid: u64, n: u64) {
        if self.inodes.forget(nodeid, n) == Forgot::Unmatched {
            self.counters.forgets_unmatched += 1;
        }
    }

    fn init(&mut self, init: &InitIn, cap: usize) -> Done {
        self.fits(cap, INIT_OUT_LEN)?;
        if init.major != KERNEL_VERSION || init.minor < MIN_MINOR {
            return Err(Errno::EPROTO);
        }
        let minor = init.minor.min(KERNEL_MINOR_VERSION);
        self.state = State::Ready { minor };
        Ok(InitOut {
            major: KERNEL_VERSION,
            minor,
            max_readahead: init.max_readahead,
            flags: (INIT_FLAGS | self.config.cache.init_flags()) & init.flags,
            max_write: MAX_WRITE,
            time_gran: 1,
            max_pages: MAX_PAGES,
            ..InitOut::default()
        }
        .to_bytes())
    }

    fn open_out_len(minor: u32) -> usize {
        encode::open_out(0, 0, minor).len()
    }

    fn ready(&mut self, h: &InHeader, op: Op<'_>, cap: usize, minor: u32) -> Done {
        let ro = self.config.read_only;
        let changes = matches!(
            op,
            Op::Setattr(_)
                | Op::Symlink { .. }
                | Op::Mknod { .. }
                | Op::Mkdir { .. }
                | Op::Unlink { .. }
                | Op::Rmdir { .. }
                | Op::Rename { .. }
                | Op::Link { .. }
                | Op::Create { .. }
                | Op::Fallocate { .. }
                | Op::Setxattr { .. }
                | Op::Removexattr { .. }
        );
        if ro && changes {
            return Err(Errno::EROFS);
        }
        match op {
            Op::Init(_) | Op::Forget { .. } | Op::BatchForget(_) => Err(Errno::EIO),
            Op::Destroy => {
                for handle in self.handles.drain() {
                    self.dir.close(handle.open);
                }
                self.inodes.clear();
                self.state = State::Destroyed;
                Ok(Vec::new())
            }
            Op::Lookup { name } => self.lookup(h.nodeid, name, cap),
            Op::Getattr { getattr_flags, fh } => {
                self.fits(cap, ATTR_OUT_LEN)?;
                if getattr_flags & FUSE_GETATTR_FH != 0 {
                    self.handles.get(fh, h.nodeid)?;
                }
                let (node, _, _) = self.node(h.nodeid)?;
                let stat = self.stat(&node)?;
                let attr = self.attr(&node, &stat)?;
                Ok(encode::attr_out(self.config.cache.valid(), &attr))
            }
            Op::Setattr(s) => self.setattr(h, &s, cap),
            Op::Readlink => self.readlink(h.nodeid),
            Op::Symlink { name, target } => self.symlink(h, name, target, cap),
            Op::Mknod {
                mode, rdev, name, ..
            } => self.mknod(h, mode, rdev, name, cap),
            Op::Mkdir { mode, name, .. } => self.mkdir(h, mode, name, cap),
            Op::Unlink { name } => self.remove(h.nodeid, name, false),
            Op::Rmdir { name } => self.remove(h.nodeid, name, true),
            Op::Rename {
                newdir,
                flags,
                old,
                new,
            } => self.rename(h.nodeid, newdir, flags, old, new),
            Op::Link { oldnodeid, name } => self.link(h.nodeid, oldnodeid, name, cap),
            Op::Open { flags, .. } => self.open(h.nodeid, flags, cap, minor),
            Op::Read(r) => self.read(h.nodeid, &r, cap),
            Op::Write { arg, data } => self.write(h.nodeid, arg.fh, arg.offset, data, cap),
            Op::Statfs => self.statfs(h.nodeid, cap),
            Op::Release(r) => self.release(h.nodeid, r.fh, false),
            Op::Releasedir(r) => self.release(h.nodeid, r.fh, true),
            Op::Fsync { fh, fsync_flags } => {
                let handle = self.handles.get(fh, h.nodeid)?;
                if !matches!(handle.kind, Kind::File { .. }) {
                    return Err(Errno::EBADF);
                }
                let r = self.dir.sync(&handle.open, fsync_flags & 1 != 0);
                r.map_err(|e| self.dir_err(e))?;
                Ok(Vec::new())
            }
            Op::Fsyncdir { fh, .. } => {
                let handle = self.handles.get(fh, h.nodeid)?;
                if handle.kind != Kind::Dir {
                    return Err(Errno::EBADF);
                }
                Ok(Vec::new())
            }
            Op::Flush { fh, .. } => {
                self.handles.get(fh, h.nodeid)?;
                Ok(Vec::new())
            }
            Op::Opendir { .. } => self.opendir(h.nodeid, cap, minor),
            Op::Readdir(r) => self.readdir(h.nodeid, &r, cap, false),
            Op::Readdirplus(r) => self.readdir(h.nodeid, &r, cap, true),
            Op::Access { .. } => {
                // The guest checks permissions itself (virtio-fs mounts with
                // default_permissions); the node must exist.
                self.node(h.nodeid)?;
                Ok(Vec::new())
            }
            Op::Create {
                flags, mode, name, ..
            } => self.create(h, flags, mode, name, cap, minor),
            Op::Fallocate {
                fh,
                offset,
                length,
                mode,
            } => self.fallocate(h.nodeid, fh, offset, length, mode),
            Op::Setxattr {
                flags, name, value, ..
            } => self.setxattr(h.nodeid, flags, name.as_bytes(), value),
            Op::Getxattr { size, name } => self.getxattr(h.nodeid, size, name.as_bytes(), cap),
            Op::Listxattr { size } => self.listxattr(h.nodeid, size, cap),
            Op::Removexattr { name } => {
                let name = name.as_bytes();
                Self::guest_xattr_name(name)?;
                let (node, _, kind) = self.node(h.nodeid)?;
                Self::xattr_kind(kind)?;
                let r = self.dir.remove_xattr(&node, name);
                r.map_err(|e| self.dir_err(e))?;
                Ok(Vec::new())
            }
            // No locks are negotiated, no request is ever pending, and these
            // have a fallback in the guest: answered at once.
            Op::Getlk(_)
            | Op::Setlk(_)
            | Op::Setlkw(_)
            | Op::Interrupt { .. }
            | Op::Bmap { .. }
            | Op::Lseek { .. }
            | Op::CopyFileRange { .. }
            | Op::Syncfs
            | Op::Statx { .. } => Err(Errno::ENOSYS),
        }
    }

    // ---- helpers ----

    fn dir_err(&mut self, e: DirError) -> Errno {
        match e {
            DirError::Errno(e) => e,
            DirError::Refused { .. } => {
                self.counters.layer_refusals += 1;
                Errno::EACCES
            }
        }
    }

    fn node(&self, nodeid: u64) -> Result<(D::Node, HostId, HostKind), Errno> {
        let e = self.inodes.get(nodeid)?;
        Ok((e.node.clone(), e.id, e.kind))
    }

    fn stat(&mut self, node: &D::Node) -> Result<HostStat, Errno> {
        let r = self.dir.stat(node);
        r.map_err(|e| self.dir_err(e))
    }

    fn record(&mut self, node: &D::Node, kind: HostKind) -> Result<Option<Record>, Errno> {
        let r = self.dir.get_record(node);
        let Some(bytes) = r.map_err(|e| self.dir_err(e))? else {
            return Ok(None);
        };
        match Record::decode(&bytes).and_then(|r| r.check_kind(kind).map(|()| r)) {
            Ok(r) => Ok(Some(r)),
            Err(_) => {
                self.counters.records_refused += 1;
                Err(Errno::EIO)
            }
        }
    }

    fn shown(&mut self, node: &D::Node, stat: &HostStat) -> Result<record::Shown, Errno> {
        let r = self.record(node, stat.kind)?;
        Ok(record::shown(stat, r.as_ref(), self.config.owner))
    }

    fn attr(&mut self, node: &D::Node, stat: &HostStat) -> Result<Attr, Errno> {
        let s = self.shown(node, stat)?;
        Ok(Attr {
            ino: ino_of(stat.id),
            size: stat.size,
            blocks: stat.blocks,
            atime: bits_u64(stat.atime.secs),
            mtime: bits_u64(stat.mtime.secs),
            ctime: bits_u64(stat.ctime.secs),
            atimensec: stat.atime.nsecs,
            mtimensec: stat.mtime.nsecs,
            ctimensec: stat.ctime.nsecs,
            mode: s.mode,
            nlink: stat.nlink,
            uid: s.uid,
            gid: s.gid,
            rdev: s.rdev,
            blksize: 4096,
            flags: 0,
        })
    }

    fn entry(&self, nodeid: u64, attr: Attr) -> EntryOut {
        let valid = self.config.cache.valid();
        EntryOut {
            nodeid,
            generation: 0,
            entry: valid,
            attr_valid: valid,
            attr,
        }
    }

    /// Counts a lookup of a node the backend gave and its entry.
    fn hand_out(&mut self, node: D::Node, stat: &HostStat, parent: u64) -> Done {
        let attr = self.attr(&node, stat)?;
        let nodeid = match self.inodes.lookup(node, stat.id, stat.kind, parent) {
            Ok(id) => id,
            Err(e) => {
                self.counters.nodes_refused += 1;
                return Err(e);
            }
        };
        Ok(self.entry(nodeid, attr).to_bytes())
    }

    fn need_node_room(&mut self) -> Result<(), Errno> {
        if self.inodes.has_room() {
            Ok(())
        } else {
            self.counters.nodes_refused += 1;
            Err(Errno::ENFILE)
        }
    }

    fn need_handle_room(&mut self) -> Result<(), Errno> {
        if self.handles.has_room() {
            Ok(())
        } else {
            self.counters.handles_refused += 1;
            Err(Errno::EMFILE)
        }
    }

    fn charge(&mut self, n: u64) -> Result<(), Errno> {
        match self.bytes_added.checked_add(n) {
            Some(total) if total <= self.config.limits.max_bytes => {
                self.bytes_added = total;
                Ok(())
            }
            _ => {
                self.counters.bytes_refused += 1;
                Err(Errno::ENOSPC)
            }
        }
    }

    fn refund(&mut self, n: u64) {
        self.bytes_added = self.bytes_added.saturating_sub(n);
    }

    /// The record of an object the guest creates in `parent`: its type and
    /// mode, the caller as owner, the parent's group if the parent is
    /// setgid (and a directory then setgid too), as Linux's
    /// `inode_init_owner`.
    fn new_record(&mut self, parent: &D::Node, h: &InHeader, mode: u32, rdev: Option<(u32, u32)>) -> Result<Record, Errno> {
        let pstat = self.stat(parent)?;
        let p = self.shown(parent, &pstat)?;
        let mut mode = mode;
        let mut gid = h.gid;
        if p.mode & S_ISGID != 0 {
            gid = p.gid;
            if mode & S_IFMT == S_IFDIR {
                mode |= S_ISGID;
            }
        }
        Ok(Record {
            mode: Some(mode),
            uid: Some(h.uid),
            gid: Some(gid),
            rdev,
        })
    }

    fn finish_new(&mut self, node: &D::Node, record: &Record) -> Result<HostStat, Errno> {
        let r = self.dir.set_record(node, &record.encode());
        r.map_err(|e| self.dir_err(e))?;
        let r = self.dir.set_perm(node, host_perm(record.mode.unwrap_or(0)));
        r.map_err(|e| self.dir_err(e))?;
        self.stat(node)
    }

    // ---- operations ----

    fn lookup(&mut self, parent: u64, name: Name<'_>, cap: usize) -> Done {
        self.fits(cap, ENTRY_OUT_LEN)?;
        let (pnode, _, _) = self.node(parent)?;
        match self.dir.lookup(&pnode, name) {
            Ok((node, stat)) => self.hand_out(node, &stat, parent),
            Err(DirError::Errno(Errno::ENOENT)) if self.config.cache.negative_entries() => Ok(EntryOut {
                nodeid: 0,
                entry: self.config.cache.valid(),
                ..EntryOut::default()
            }
            .to_bytes()),
            Err(e) => Err(self.dir_err(e)),
        }
    }

    fn setattr(&mut self, h: &InHeader, s: &SetattrIn, cap: usize) -> Done {
        self.fits(cap, ATTR_OUT_LEN)?;
        if s.valid & FATTR_FH != 0 {
            self.handles.get(s.fh, h.nodeid)?;
        }
        let (node, _, kind) = self.node(h.nodeid)?;
        let stat = self.stat(&node)?;
        let record = self.record(&node, stat.kind)?;
        let shown = record::shown(&stat, record.as_ref(), self.config.owner);
        if s.valid & (FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE) != 0
            && matches!(kind, HostKind::HostSymlink | HostKind::Other)
        {
            return Err(Errno::EPERM);
        }
        if s.valid & FATTR_SIZE != 0 {
            match (stat.kind, shown.mode & S_IFMT) {
                (HostKind::Dir, _) => return Err(Errno::EISDIR),
                (HostKind::File, S_IFREG) => {}
                _ => return Err(Errno::EINVAL),
            }
            if s.size > bits_u64(i64::MAX) {
                return Err(Errno::EFBIG);
            }
            let grow = s.size.saturating_sub(stat.size);
            self.charge(grow)?;
            if let Err(e) = self.dir.set_len(&node, s.size) {
                self.refund(grow);
                return Err(self.dir_err(e));
            }
            self.refund(stat.size.saturating_sub(s.size));
        }
        if s.valid & (FATTR_MODE | FATTR_UID | FATTR_GID) != 0 {
            let mut r = record.unwrap_or_default();
            if s.valid & FATTR_MODE != 0 {
                r.mode = Some((shown.mode & S_IFMT) | (s.mode & 0o7777));
                let perm = host_perm((shown.mode & S_IFMT) | (s.mode & 0o777));
                let res = self.dir.set_perm(&node, perm);
                res.map_err(|e| self.dir_err(e))?;
            }
            if s.valid & FATTR_UID != 0 {
                r.uid = Some(s.uid);
            }
            if s.valid & FATTR_GID != 0 {
                r.gid = Some(s.gid);
            }
            let res = self.dir.set_record(&node, &r.encode());
            res.map_err(|e| self.dir_err(e))?;
        }
        let time = |set: bool, set_now: bool, secs: u64, nsecs: u32| {
            if set_now {
                Some(now())
            } else if set {
                Some(Timespec {
                    secs: bits_i64(secs),
                    nsecs: nsecs.min(999_999_999),
                })
            } else {
                None
            }
        };
        let atime = time(s.valid & FATTR_ATIME != 0, s.valid & FATTR_ATIME_NOW != 0, s.atime, s.atimensec);
        let mtime = time(s.valid & FATTR_MTIME != 0, s.valid & FATTR_MTIME_NOW != 0, s.mtime, s.mtimensec);
        if atime.is_some() || mtime.is_some() {
            let res = self.dir.set_times(&node, atime, mtime);
            res.map_err(|e| self.dir_err(e))?;
        }
        let stat = self.stat(&node)?;
        let attr = self.attr(&node, &stat)?;
        Ok(encode::attr_out(self.config.cache.valid(), &attr))
    }

    fn readlink(&mut self, nodeid: u64) -> Done {
        let (node, id, kind) = self.node(nodeid)?;
        match kind {
            HostKind::HostSymlink => {
                let r = self.dir.read_link(&node, PATH_MAX - 1);
                r.map_err(|e| self.dir_err(e))
            }
            HostKind::File => {
                let stat = self.stat(&node)?;
                let shown = self.shown(&node, &stat)?;
                if shown.mode & S_IFMT != S_IFLNK {
                    return Err(Errno::EINVAL);
                }
                let open = self
                    .dir
                    .open(&node, id, OpenMode { read: true, write: false });
                let open = open.map_err(|e| self.dir_err(e))?;
                let mut buf = vec![0u8; PATH_MAX];
                let r = self.dir.read_at(&open, 0, &mut buf);
                self.dir.close(open);
                let n = r.map_err(|e| self.dir_err(e))?;
                if n == 0 || n >= PATH_MAX {
                    return Err(Errno::EIO);
                }
                buf.truncate(n);
                Ok(buf)
            }
            HostKind::Dir | HostKind::Other => Err(Errno::EINVAL),
        }
    }

    /// Creates a regular file to hold an emulated object: the new node and
    /// its open object.
    fn new_file(&mut self, parent: &D::Node, name: Name<'_>) -> Result<(D::Node, D::Open), Errno> {
        let r = self.dir.create(parent, name, true);
        let (node, open, _) = r.map_err(|e| self.dir_err(e))?;
        Ok((node, open))
    }

    fn symlink(&mut self, h: &InHeader, name: Name<'_>, target: &[u8], cap: usize) -> Done {
        self.fits(cap, ENTRY_OUT_LEN)?;
        self.need_node_room()?;
        let (parent, _, _) = self.node(h.nodeid)?;
        let len = len_u64(target.len());
        self.charge(len)?;
        let record = match self.new_record(&parent, h, S_IFLNK | 0o777, None) {
            Ok(r) => r,
            Err(e) => {
                self.refund(len);
                return Err(e);
            }
        };
        let (node, open) = match self.new_file(&parent, name) {
            Ok(x) => x,
            Err(e) => {
                self.refund(len);
                return Err(e);
            }
        };
        let w = self.dir.write_at(&open, 0, target);
        self.dir.close(open);
        let done = match w {
            Ok(n) if n == target.len() => self.finish_new(&node, &record),
            Ok(_) => Err(Errno::EIO),
            Err(e) => Err(self.dir_err(e)),
        };
        match done {
            Ok(stat) => self.hand_out(node, &stat, h.nodeid),
            Err(e) => {
                self.undo_create(&parent, name, &node);
                self.refund(len);
                Err(e)
            }
        }
    }

    /// Removes an object this request made and could not finish.
    fn undo_create(&mut self, parent: &D::Node, name: Name<'_>, node: &D::Node) {
        if let Ok(stat) = self.dir.stat(node) {
            let _ = if stat.kind == HostKind::Dir {
                self.dir.rmdir(parent, name, stat.id)
            } else {
                self.dir.unlink(parent, name, stat.id)
            };
        }
    }

    fn mknod(&mut self, h: &InHeader, mode: u32, rdev: u32, name: Name<'_>, cap: usize) -> Done {
        self.fits(cap, ENTRY_OUT_LEN)?;
        let ty = match mode & S_IFMT {
            0 => S_IFREG,
            S_IFDIR => return Err(Errno::EPERM),
            t @ (S_IFREG | S_IFIFO | S_IFSOCK | S_IFCHR | S_IFBLK) => t,
            _ => return Err(Errno::EINVAL),
        };
        let dev = matches!(ty, S_IFCHR | S_IFBLK).then(|| record::decode_dev(rdev));
        self.need_node_room()?;
        let (parent, _, _) = self.node(h.nodeid)?;
        let record = self.new_record(&parent, h, ty | (mode & 0o7777), dev)?;
        let (node, open) = self.new_file(&parent, name)?;
        self.dir.close(open);
        match self.finish_new(&node, &record) {
            Ok(stat) => self.hand_out(node, &stat, h.nodeid),
            Err(e) => {
                self.undo_create(&parent, name, &node);
                Err(e)
            }
        }
    }

    fn mkdir(&mut self, h: &InHeader, mode: u32, name: Name<'_>, cap: usize) -> Done {
        self.fits(cap, ENTRY_OUT_LEN)?;
        self.need_node_room()?;
        let (parent, _, _) = self.node(h.nodeid)?;
        let record = self.new_record(&parent, h, S_IFDIR | (mode & 0o7777), None)?;
        let r = self.dir.mkdir(&parent, name);
        let (node, _) = r.map_err(|e| self.dir_err(e))?;
        match self.finish_new(&node, &record) {
            Ok(stat) => self.hand_out(node, &stat, h.nodeid),
            Err(e) => {
                self.undo_create(&parent, name, &node);
                Err(e)
            }
        }
    }

    fn remove(&mut self, parent: u64, name: Name<'_>, dir: bool) -> Done {
        let (pnode, _, _) = self.node(parent)?;
        let r = self.dir.lookup(&pnode, name);
        let (_, stat) = r.map_err(|e| self.dir_err(e))?;
        let r = match (dir, stat.kind) {
            (true, HostKind::Dir) => self.dir.rmdir(&pnode, name, stat.id),
            (true, _) => return Err(Errno::ENOTDIR),
            (false, HostKind::Dir) => return Err(Errno::EISDIR),
            (false, _) => self.dir.unlink(&pnode, name, stat.id),
        };
        r.map_err(|e| self.dir_err(e))?;
        if stat.kind == HostKind::File && stat.nlink <= 1 {
            self.refund(stat.size);
        }
        Ok(Vec::new())
    }

    fn rename(&mut self, olddir: u64, newdir: u64, flags: u32, old: Name<'_>, new: Name<'_>) -> Done {
        // NOREPLACE and EXCHANGE go to the backend, which may refuse
        // EXCHANGE (EINVAL) where its host has no atomic exchange. Both at
        // once, RENAME_WHITEOUT (a device node the server never makes on a
        // host) and unknown bits are EINVAL on every host
        // (docs/design-fs.md §4.3).
        let known = RENAME_NOREPLACE | RENAME_EXCHANGE;
        if flags & !known != 0 || flags == known {
            return Err(Errno::EINVAL);
        }
        let exchange = flags & RENAME_EXCHANGE != 0;
        let (from, _, _) = self.node(olddir)?;
        let (to, _, _) = self.node(newdir)?;
        let r = self.dir.lookup(&from, old);
        let (_, src) = r.map_err(|e| self.dir_err(e))?;
        let target = self.dir.lookup(&to, new).ok();
        let r = self.dir.rename(
            (&from, old),
            (&to, new),
            RenameFlags {
                noreplace: flags & RENAME_NOREPLACE != 0,
                exchange,
            },
        );
        r.map_err(|e| self.dir_err(e))?;
        // A replaced file's bytes leave the budget; an exchange replaces
        // nothing.
        if !exchange
            && let Some((_, t)) = target
            && t.id != src.id
            && t.kind == HostKind::File
            && t.nlink <= 1
        {
            self.refund(t.size);
        }
        // A held node follows its object: the source to the new name, and
        // after an exchange the target to the old one.
        self.follow(src.id, &to, new, newdir);
        if exchange && let Some((_, t)) = target {
            self.follow(t.id, &from, old, olddir);
        }
        Ok(Vec::new())
    }

    /// Points the held node of `id`, if any, at what `name` beneath `dir`
    /// (node `dirid`) now is, if that is still `id`.
    fn follow(&mut self, id: HostId, dir: &D::Node, name: Name<'_>, dirid: u64) {
        if let Some(nodeid) = self.inodes.find(id)
            && let Ok((node, stat)) = self.dir.lookup(dir, name)
            && stat.id == id
        {
            self.inodes.moved(nodeid, node, dirid);
        }
    }

    fn link(&mut self, newparent: u64, oldnodeid: u64, name: Name<'_>, cap: usize) -> Done {
        self.fits(cap, ENTRY_OUT_LEN)?;
        let (node, id, kind) = self.node(oldnodeid)?;
        if kind != HostKind::File {
            return Err(Errno::EPERM);
        }
        let (parent, _, _) = self.node(newparent)?;
        let r = self.dir.link(&node, id, (&parent, name));
        let stat = r.map_err(|e| self.dir_err(e))?;
        self.hand_out(node, &stat, newparent)
    }

    /// Checks that a node may be opened as a regular file.
    fn openable(&mut self, node: &D::Node, kind: HostKind) -> Result<(), Errno> {
        match kind {
            HostKind::Dir => return Err(Errno::EISDIR),
            HostKind::HostSymlink => return Err(Errno::ELOOP),
            HostKind::Other => return Err(Errno::EACCES),
            HostKind::File => {}
        }
        let stat = self.stat(node)?;
        match self.shown(node, &stat)?.mode & S_IFMT {
            S_IFREG => Ok(()),
            S_IFLNK => Err(Errno::ELOOP),
            // Emulated FIFOs, sockets and devices: the guest's kernel opens
            // them itself, the host file never.
            _ => Err(Errno::EACCES),
        }
    }

    fn access(flags: u32) -> Result<OpenMode, Errno> {
        match flags & O_ACCMODE {
            0 => Ok(OpenMode { read: true, write: false }),
            1 => Ok(OpenMode { read: false, write: true }),
            2 => Ok(OpenMode { read: true, write: true }),
            _ => Err(Errno::EINVAL),
        }
    }

    fn open(&mut self, nodeid: u64, flags: u32, cap: usize, minor: u32) -> Done {
        self.fits(cap, Self::open_out_len(minor))?;
        let mode = Self::access(flags)?;
        if mode.write && self.config.read_only {
            return Err(Errno::EROFS);
        }
        let (node, id, kind) = self.node(nodeid)?;
        self.openable(&node, kind)?;
        self.need_handle_room()?;
        let r = self.dir.open(&node, id, mode);
        let open = r.map_err(|e| self.dir_err(e))?;
        let kind = Kind::File {
            read: mode.read,
            write: mode.write,
        };
        self.store_handle(nodeid, kind, open, minor)
    }

    fn store_handle(&mut self, nodeid: u64, kind: Kind, open: D::Open, minor: u32) -> Done {
        match self.handles.insert(nodeid, kind, open) {
            Ok(fh) => {
                self.inodes.opened(nodeid);
                Ok(encode::open_out(fh, self.config.cache.open_flags(kind == Kind::Dir), minor))
            }
            Err((e, open)) => {
                self.dir.close(open);
                self.counters.handles_refused += 1;
                Err(e)
            }
        }
    }

    fn file_handle(&self, nodeid: u64, fh: u64, write: bool) -> Result<&D::Open, Errno> {
        let handle = self.handles.get(fh, nodeid)?;
        match handle.kind {
            Kind::File { read, write: w } if (write && w) || (!write && read) => Ok(&handle.open),
            _ => Err(Errno::EBADF),
        }
    }

    fn read(&mut self, nodeid: u64, r: &ReadIn, cap: usize) -> Done {
        self.fits(cap, 0)?;
        // The guest's size, its buffers and max_write, whichever is least, is
        // all that is allocated.
        let want = usize_of(r.size).min(MAX_READ).min(cap - OUT_HEADER_LEN);
        let open = self.file_handle(nodeid, r.fh, false)?;
        let mut buf = vec![0u8; want];
        let res = self.dir.read_at(open, r.offset, &mut buf);
        let n = res.map_err(|e| self.dir_err(e))?;
        buf.truncate(n.min(want));
        Ok(buf)
    }

    fn write(&mut self, nodeid: u64, fh: u64, offset: u64, data: &[u8], cap: usize) -> Done {
        self.fits(cap, 8)?;
        self.file_handle(nodeid, fh, true)?;
        let len = len_u64(data.len());
        let end = offset
            .checked_add(len)
            .filter(|&e| e <= bits_u64(i64::MAX))
            .ok_or(Errno::EFBIG)?;
        let (node, _, _) = self.node(nodeid)?;
        let size = self.stat(&node)?.size;
        let grow = end.saturating_sub(size);
        self.charge(grow)?;
        let open = self.file_handle(nodeid, fh, true)?;
        let res = self.dir.write_at(open, offset, data);
        let n = match res {
            Ok(n) => n.min(data.len()),
            Err(e) => {
                self.refund(grow);
                return Err(self.dir_err(e));
            }
        };
        let grew = offset.saturating_add(len_u64(n)).saturating_sub(size);
        self.refund(grow.saturating_sub(grew));
        // n ≤ data.len() ≤ MAX_WRITE.
        Ok(encode::write_out(u32::try_from(n).unwrap_or(MAX_WRITE)).to_vec())
    }

    fn statfs(&mut self, nodeid: u64, cap: usize) -> Done {
        self.fits(cap, STATFS_OUT_LEN)?;
        let (node, _, _) = self.node(nodeid)?;
        let r = self.dir.statfs(&node);
        let st = r.map_err(|e| self.dir_err(e))?;
        // What the byte budget leaves is all the guest may still add.
        let frsize = u64::from(st.frsize.max(1));
        let left = self.config.limits.max_bytes.saturating_sub(self.bytes_added) / frsize;
        Ok(Kstatfs {
            blocks: st.blocks,
            bfree: st.bfree.min(left),
            bavail: st.bavail.min(left),
            files: st.files,
            ffree: st.ffree,
            bsize: st.bsize,
            namelen: u32::try_from(NAME_MAX).unwrap_or(255),
            frsize: st.frsize,
        }
        .to_bytes())
    }

    fn release(&mut self, nodeid: u64, fh: u64, dir: bool) -> Done {
        let handle = self.handles.remove(fh, nodeid, dir)?;
        self.dir.close(handle.open);
        self.inodes.closed(nodeid);
        Ok(Vec::new())
    }

    fn opendir(&mut self, nodeid: u64, cap: usize, minor: u32) -> Done {
        self.fits(cap, Self::open_out_len(minor))?;
        let (node, id, kind) = self.node(nodeid)?;
        if kind != HostKind::Dir {
            return Err(Errno::ENOTDIR);
        }
        self.need_handle_room()?;
        let r = self.dir.open_dir(&node, id);
        let open = r.map_err(|e| self.dir_err(e))?;
        self.store_handle(nodeid, Kind::Dir, open, minor)
    }

    fn readdir(&mut self, nodeid: u64, r: &ReadIn, cap: usize, plus: bool) -> Done {
        self.fits(cap, 0)?;
        let limit = usize_of(r.size).min(MAX_READ).min(cap - OUT_HEADER_LEN);
        let handle = self.handles.get(r.fh, nodeid)?;
        if handle.kind != Kind::Dir {
            return Err(Errno::EBADF);
        }
        let (dnode, did, _) = self.node(nodeid)?;
        let parent = self.inodes.get(nodeid).map(|e| e.parent).unwrap_or(ROOT);
        let pid = self.inodes.get(parent).map(|e| e.id).unwrap_or(did);
        let mut out = Vec::with_capacity(limit);
        let fixed = if plus { ENTRY_OUT_LEN } else { 0 };
        let size_of = |name: &[u8]| fixed + 24 + name.len().div_ceil(8) * 8;
        // `.` and `..` are the server's, at offsets 1 and 2; the backend's
        // cookies follow, shifted by 2.
        for (off, name, id) in [(1u64, &b"."[..], did), (2, b"..", pid)] {
            if r.offset >= off {
                continue;
            }
            if out.len() + size_of(name) > limit {
                return Ok(out);
            }
            let ino = ino_of(id);
            if plus {
                // Node id 0: the guest links nothing and counts no lookup.
                let entry = EntryOut {
                    attr: Attr {
                        ino,
                        mode: S_IFDIR,
                        ..Attr::default()
                    },
                    ..EntryOut::default()
                };
                out.extend_from_slice(&encode::direntplus(&entry, off, DT_DIR, name));
            } else {
                out.extend_from_slice(&encode::dirent(ino, off, DT_DIR, name));
            }
        }
        let mut after = r.offset.saturating_sub(2);
        loop {
            let mut batch: Vec<DirEntry> = Vec::new();
            let handle = self.handles.get(r.fh, nodeid)?;
            let res = self.dir.read_dir(&handle.open, after, READDIR_BATCH, &mut batch);
            res.map_err(|e| self.dir_err(e))?;
            if batch.is_empty() {
                return Ok(out);
            }
            for e in batch {
                if e.cookie > crate::dir::MAX_COOKIE || e.cookie <= after {
                    // A backend that does not move forward: stop rather than
                    // loop.
                    return Ok(out);
                }
                let Ok(name) = Name::new(&e.name) else {
                    self.counters.names_skipped += 1;
                    after = e.cookie;
                    continue;
                };
                if out.len() + size_of(name.as_bytes()) > limit {
                    return Ok(out);
                }
                let off = e.cookie + 2;
                let ty = match e.kind {
                    HostKind::Dir => DT_DIR,
                    HostKind::HostSymlink => DT_LNK,
                    HostKind::File | HostKind::Other => DT_UNKNOWN,
                };
                if plus {
                    let entry = self.plus_entry(&dnode, nodeid, name);
                    let Some(entry) = entry else {
                        // Gone since it was listed.
                        after = e.cookie;
                        continue;
                    };
                    // DT_* is the type bits shifted down.
                    let ty = if entry.nodeid == 0 {
                        ty
                    } else {
                        (entry.attr.mode & S_IFMT) >> 12
                    };
                    out.extend_from_slice(&encode::direntplus(&entry, off, ty, name.as_bytes()));
                } else {
                    out.extend_from_slice(&encode::dirent(ino_of(e.id), off, ty, name.as_bytes()));
                }
                after = e.cookie;
            }
        }
    }

    /// A READDIRPLUS entry: the looked-up node (one lookup counted), or
    /// node id 0 (nothing counted) when its attributes cannot be given;
    /// `None` when the name is gone.
    fn plus_entry(&mut self, dnode: &D::Node, dir: u64, name: Name<'_>) -> Option<EntryOut> {
        let (node, stat) = match self.dir.lookup(dnode, name) {
            Ok(found) => found,
            Err(e) => {
                self.dir_err(e);
                return None;
            }
        };
        let Ok(attr) = self.attr(&node, &stat) else {
            return Some(EntryOut {
                attr: Attr {
                    ino: ino_of(stat.id),
                    ..Attr::default()
                },
                ..EntryOut::default()
            });
        };
        match self.inodes.lookup(node, stat.id, stat.kind, dir) {
            Ok(nodeid) => Some(self.entry(nodeid, attr)),
            Err(_) => {
                self.counters.nodes_refused += 1;
                Some(EntryOut {
                    attr: Attr {
                        ino: attr.ino,
                        ..Attr::default()
                    },
                    ..EntryOut::default()
                })
            }
        }
    }

    fn create(&mut self, h: &InHeader, flags: u32, mode: u32, name: Name<'_>, cap: usize, minor: u32) -> Done {
        let open_len = Self::open_out_len(minor);
        self.fits(cap, ENTRY_OUT_LEN + open_len)?;
        let access = Self::access(flags)?;
        self.need_node_room()?;
        self.need_handle_room()?;
        let (parent, _, _) = self.node(h.nodeid)?;
        let existed = self.dir.lookup(&parent, name).is_ok();
        let exclusive = flags & O_EXCL != 0;
        let record = self.new_record(&parent, h, S_IFREG | (mode & 0o7777), None)?;
        let r = self.dir.create(&parent, name, exclusive);
        let (node, open, stat) = r.map_err(|e| self.dir_err(e))?;
        let stat = if existed {
            if let Err(e) = self.openable(&node, stat.kind) {
                self.dir.close(open);
                return Err(e);
            }
            stat
        } else {
            match self.finish_new(&node, &record) {
                Ok(s) => s,
                Err(e) => {
                    self.dir.close(open);
                    self.undo_create(&parent, name, &node);
                    return Err(e);
                }
            }
        };
        let attr = match self.attr(&node, &stat) {
            Ok(a) => a,
            Err(e) => {
                self.dir.close(open);
                return Err(e);
            }
        };
        let nodeid = match self.inodes.lookup(node, stat.id, stat.kind, h.nodeid) {
            Ok(id) => id,
            Err(e) => {
                self.dir.close(open);
                self.counters.nodes_refused += 1;
                return Err(e);
            }
        };
        let kind = Kind::File {
            read: access.read,
            write: access.write,
        };
        match self.handles.insert(nodeid, kind, open) {
            Ok(fh) => {
                self.inodes.opened(nodeid);
                let mut out = self.entry(nodeid, attr).to_bytes();
                out.extend_from_slice(&encode::open_out(fh, self.config.cache.open_flags(false), minor));
                Ok(out)
            }
            Err((e, open)) => {
                self.dir.close(open);
                // The lookup this reply would have handed out.
                self.inodes.forget(nodeid, 1);
                self.counters.handles_refused += 1;
                Err(e)
            }
        }
    }

    fn fallocate(&mut self, nodeid: u64, fh: u64, offset: u64, length: u64, mode: u32) -> Done {
        let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
        let punch = mode & FALLOC_FL_PUNCH_HOLE != 0;
        if mode & !(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) != 0 || (punch && !keep) {
            return Err(Errno::EOPNOTSUPP);
        }
        self.file_handle(nodeid, fh, true)?;
        let end = offset
            .checked_add(length)
            .filter(|&e| e <= bits_u64(i64::MAX))
            .ok_or(Errno::EFBIG)?;
        let (node, _, _) = self.node(nodeid)?;
        let size = self.stat(&node)?.size;
        let grow = if punch { 0 } else { end.saturating_sub(size) };
        self.charge(grow)?;
        let open = self.file_handle(nodeid, fh, true)?;
        let r = self.dir.allocate(open, offset, length, keep, punch);
        if let Err(e) = r {
            self.refund(grow);
            return Err(self.dir_err(e));
        }
        Ok(Vec::new())
    }

    /// `system.*` (POSIX ACLs and the like) is not the guest's to store; a
    /// name longer than every host can hold is ERANGE.
    fn guest_xattr_name(name: &[u8]) -> Result<(), Errno> {
        if name.starts_with(b"system.") {
            Err(Errno::EOPNOTSUPP)
        } else if name.len() > GUEST_XATTR_NAME_MAX {
            Err(Errno::ERANGE)
        } else {
            Ok(())
        }
    }

    fn xattr_kind(kind: HostKind) -> Result<(), Errno> {
        match kind {
            HostKind::File | HostKind::Dir => Ok(()),
            HostKind::HostSymlink | HostKind::Other => Err(Errno::EPERM),
        }
    }

    fn setxattr(&mut self, nodeid: u64, flags: u32, name: &[u8], value: &[u8]) -> Done {
        Self::guest_xattr_name(name)?;
        let mode = match flags {
            0 => XattrMode::Any,
            XATTR_CREATE => XattrMode::Create,
            XATTR_REPLACE => XattrMode::Replace,
            _ => return Err(Errno::EINVAL),
        };
        let (node, _, kind) = self.node(nodeid)?;
        Self::xattr_kind(kind)?;
        let r = self.dir.list_xattr(&node);
        let list = r.map_err(|e| self.dir_err(e))?;
        let others: usize = list
            .iter()
            .filter(|(n, _)| n.as_slice() != name)
            .map(|(n, len)| XATTR_ENTRY_COST + n.len() + len)
            .sum();
        if others + XATTR_ENTRY_COST + name.len() + value.len() > self.config.limits.xattr_budget {
            self.counters.xattr_refused += 1;
            return Err(Errno::ENOSPC);
        }
        let r = self.dir.set_xattr(&node, name, value, mode);
        r.map_err(|e| self.dir_err(e))?;
        Ok(Vec::new())
    }

    fn getxattr(&mut self, nodeid: u64, size: u32, name: &[u8], cap: usize) -> Done {
        Self::guest_xattr_name(name)?;
        let (node, _, kind) = self.node(nodeid)?;
        Self::xattr_kind(kind)?;
        let r = self.dir.get_xattr(&node, name);
        let value = r.map_err(|e| self.dir_err(e))?.ok_or(Errno::ENODATA)?;
        self.sized(value, size, cap)
    }

    fn listxattr(&mut self, nodeid: u64, size: u32, cap: usize) -> Done {
        let (node, _, kind) = self.node(nodeid)?;
        if Self::xattr_kind(kind).is_err() {
            return self.sized(Vec::new(), size, cap);
        }
        let r = self.dir.list_xattr(&node);
        let list = r.map_err(|e| self.dir_err(e))?;
        // One allocation of the answer's length, never grown (the names'
        // count is the host's; see sys::xattr::list).
        let mut names = Vec::with_capacity(list.iter().map(|(n, _)| n.len() + 1).sum());
        for (n, _) in list {
            names.extend_from_slice(&n);
            names.push(0);
        }
        self.sized(names, size, cap)
    }

    /// A GETXATTR or LISTXATTR answer: with size 0 the length the data
    /// needs, else the data if it fits the guest's size (ERANGE if not).
    /// The guest's size is only compared, never allocated.
    fn sized(&mut self, data: Vec<u8>, size: u32, cap: usize) -> Done {
        let len = u32::try_from(data.len()).map_err(|_| Errno::E2BIG)?;
        if size == 0 {
            self.fits(cap, 8)?;
            return Ok(encode::getxattr_out(len).to_vec());
        }
        if len > size {
            return Err(Errno::ERANGE);
        }
        self.fits(cap, data.len())?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests;
