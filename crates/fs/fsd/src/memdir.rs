// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `MemDir`: a [`ConfinedDir`] held in memory, for the session's tests and
//! the `fs_session` fuzz target. It keeps the contract the host backends
//! keep (one component beneath a node, identities checked, a host symlink
//! or other object never opened), so the common server is tested without a
//! host file system. It is not a shipped backend.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::dir::{
    ConfinedDir, DirEntry, DirError, HostId, HostKind, HostStat, MAX_COOKIE, OpenMode, RECORD_LEN,
    RenameFlags, StatFs, Timespec, XattrMode,
};
use crate::fuse::Errno;
use crate::fuse::name::Name;

/// The volume every `MemDir` object is on.
pub const VOLUME: u64 = 0x6d65_6d64;

#[derive(Debug)]
enum Body {
    File(Vec<u8>),
    /// name → (object, cookie); cookies grow with each insertion.
    Dir(BTreeMap<String, (u64, u64)>),
    HostSymlink(Vec<u8>),
    Other,
}

#[derive(Debug)]
struct Obj {
    body: Body,
    nlink: u32,
    perm: u16,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    record: Option<Vec<u8>>,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    opens: u32,
}

#[derive(Debug)]
struct State {
    objs: HashMap<u64, Obj>,
    next: u64,
    next_cookie: u64,
}

/// An in-memory directory tree.
#[derive(Debug)]
pub struct MemDir {
    state: Mutex<State>,
    /// Whether rename does `RENAME_EXCHANGE` (else EINVAL, as on Windows).
    exchange: bool,
}

/// A `MemDir` open object.
#[derive(Debug)]
pub struct MemOpen {
    obj: u64,
    mode: OpenMode,
}

fn enoent() -> DirError {
    DirError::Errno(Errno::ENOENT)
}

fn id_of(obj: u64) -> HostId {
    HostId {
        volume: VOLUME,
        file: u128::from(obj),
    }
}

impl Obj {
    fn new(body: Body, perm: u16) -> Obj {
        Obj {
            body,
            nlink: 1,
            perm,
            atime: Timespec::default(),
            mtime: Timespec::default(),
            ctime: Timespec::default(),
            record: None,
            xattrs: BTreeMap::new(),
            opens: 0,
        }
    }

    fn kind(&self) -> HostKind {
        match self.body {
            Body::File(_) => HostKind::File,
            Body::Dir(_) => HostKind::Dir,
            Body::HostSymlink(_) => HostKind::HostSymlink,
            Body::Other => HostKind::Other,
        }
    }

    fn size(&self) -> u64 {
        let n = match &self.body {
            Body::File(d) | Body::HostSymlink(d) => d.len(),
            Body::Dir(e) => e.len(),
            Body::Other => 0,
        };
        u64::try_from(n).unwrap_or(u64::MAX)
    }
}

impl State {
    fn obj(&self, obj: u64) -> Result<&Obj, DirError> {
        self.objs.get(&obj).ok_or_else(enoent)
    }

    fn obj_mut(&mut self, obj: u64) -> Result<&mut Obj, DirError> {
        self.objs.get_mut(&obj).ok_or_else(enoent)
    }

    fn stat(&self, obj: u64) -> Result<HostStat, DirError> {
        let o = self.obj(obj)?;
        Ok(HostStat {
            id: id_of(obj),
            kind: o.kind(),
            size: o.size(),
            blocks: o.size().div_ceil(512),
            nlink: o.nlink,
            perm: o.perm,
            atime: o.atime,
            mtime: o.mtime,
            ctime: o.ctime,
        })
    }

    fn entries(&self, dir: u64) -> Result<&BTreeMap<String, (u64, u64)>, DirError> {
        match &self.obj(dir)?.body {
            Body::Dir(e) => Ok(e),
            _ => Err(Errno::ENOTDIR.into()),
        }
    }

    fn entries_mut(&mut self, dir: u64) -> Result<&mut BTreeMap<String, (u64, u64)>, DirError> {
        match &mut self.obj_mut(dir)?.body {
            Body::Dir(e) => Ok(e),
            _ => Err(Errno::ENOTDIR.into()),
        }
    }

    fn child(&self, dir: u64, name: &str) -> Result<u64, DirError> {
        self.entries(dir)?.get(name).map(|&(o, _)| o).ok_or_else(enoent)
    }

    fn insert(&mut self, dir: u64, name: &str, obj: u64) -> Result<(), DirError> {
        self.next_cookie += 1;
        let cookie = self.next_cookie;
        let entries = self.entries_mut(dir)?;
        if entries.contains_key(name) {
            return Err(Errno::EEXIST.into());
        }
        entries.insert(name.to_string(), (obj, cookie));
        Ok(())
    }

    fn new_obj(&mut self, obj: Obj) -> u64 {
        self.next += 1;
        self.objs.insert(self.next, obj);
        self.next
    }

    /// Whether `node` is `anc` or beneath it.
    fn below(&self, node: u64, anc: u64) -> bool {
        let mut cur = node;
        for _ in 0..=4096 {
            if cur == anc {
                return true;
            }
            if cur == 1 {
                return false;
            }
            let parent = self
                .objs
                .iter()
                .find(|(_, o)| matches!(&o.body, Body::Dir(e) if e.values().any(|&(c, _)| c == cur)))
                .map(|(&k, _)| k);
            match parent {
                Some(p) => cur = p,
                None => return false,
            }
        }
        false
    }

    /// Drops an object no name and no open holds.
    fn gc(&mut self, obj: u64) {
        if self.objs.get(&obj).is_some_and(|o| o.nlink == 0 && o.opens == 0) {
            self.objs.remove(&obj);
        }
    }

    fn open_file(&self, obj: u64) -> Result<&Vec<u8>, DirError> {
        match &self.obj(obj)?.body {
            Body::File(d) => Ok(d),
            _ => Err(Errno::EBADF.into()),
        }
    }

    fn open_file_mut(&mut self, obj: u64) -> Result<&mut Vec<u8>, DirError> {
        match &mut self.obj_mut(obj)?.body {
            Body::File(d) => Ok(d),
            _ => Err(Errno::EBADF.into()),
        }
    }
}

fn usize_of(v: u64) -> Result<usize, DirError> {
    usize::try_from(v).map_err(|_| DirError::Errno(Errno::EFBIG))
}

/// Files in a `MemDir` grow to at most this many bytes (EFBIG beyond), so a
/// write at a far offset does not allocate the gap.
pub const MAX_FILE: u64 = 64 << 20;

impl Default for MemDir {
    fn default() -> MemDir {
        MemDir::new()
    }
}

impl MemDir {
    /// An empty tree: the root directory alone (object 1, mode 0o755).
    pub fn new() -> MemDir {
        let mut objs = HashMap::new();
        objs.insert(1, Obj::new(Body::Dir(BTreeMap::new()), 0o755));
        MemDir {
            state: Mutex::new(State {
                objs,
                next: 1,
                next_cookie: 0,
            }),
            exchange: true,
        }
    }

    /// An empty tree whose rename refuses `RENAME_EXCHANGE` with EINVAL, as
    /// the Windows backend does (NTFS has no atomic exchange;
    /// docs/design-fs.md §4.3).
    pub fn without_exchange() -> MemDir {
        MemDir {
            exchange: false,
            ..MemDir::new()
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while the lock was held already failed the test or fuzz
        // run; the state is still the last one written.
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Puts an object the host made into `dir` (tests): a host symlink to
    /// `target`, or (with `None`) another object such as a FIFO. Returns its
    /// object number.
    pub fn add_host_object(&self, dir: u64, name: &str, target: Option<&[u8]>) -> Result<u64, DirError> {
        let mut s = self.lock();
        let body = match target {
            Some(t) => Body::HostSymlink(t.to_vec()),
            None => Body::Other,
        };
        let obj = s.new_obj(Obj::new(body, 0o777));
        s.insert(dir, name, obj)?;
        Ok(obj)
    }

    /// Puts a name the guest cannot have (not a `Name`) into `dir`, as a
    /// host could (tests): a regular file.
    pub fn add_raw_name(&self, dir: u64, name: &str) -> Result<u64, DirError> {
        let mut s = self.lock();
        let obj = s.new_obj(Obj::new(Body::File(Vec::new()), 0o644));
        s.insert(dir, name, obj)?;
        Ok(obj)
    }

    /// Stores raw bytes as an object's record (tests of malformed records).
    pub fn put_raw_record(&self, obj: u64, bytes: &[u8]) -> Result<(), DirError> {
        self.lock().obj_mut(obj)?.record = Some(bytes.to_vec());
        Ok(())
    }

    /// How many objects the tree holds, open but unlinked ones included.
    pub fn objects(&self) -> usize {
        self.lock().objs.len()
    }

    /// The hard links of the object `id`, if it still exists (open but
    /// unlinked: 0).
    pub fn nlink(&self, id: HostId) -> Option<u32> {
        if id.volume != VOLUME {
            return None;
        }
        let obj = u64::try_from(id.file).ok()?;
        self.lock().objs.get(&obj).map(|o| o.nlink)
    }

    /// How many opens are not closed.
    pub fn open_count(&self) -> u64 {
        self.lock().objs.values().map(|o| u64::from(o.opens)).sum()
    }
}

impl ConfinedDir for MemDir {
    type Node = u64;
    type Open = MemOpen;

    fn root(&self) -> u64 {
        1
    }

    fn lookup(&self, parent: &u64, name: Name<'_>) -> Result<(u64, HostStat), DirError> {
        let s = self.lock();
        let obj = s.child(*parent, name.as_str())?;
        Ok((obj, s.stat(obj)?))
    }

    fn stat(&self, node: &u64) -> Result<HostStat, DirError> {
        self.lock().stat(*node)
    }

    fn open(&self, node: &u64, expect: HostId, mode: OpenMode) -> Result<MemOpen, DirError> {
        let mut s = self.lock();
        if id_of(*node) != expect {
            return Err(enoent());
        }
        let o = s.obj_mut(*node)?;
        match o.body {
            Body::File(_) => {}
            Body::Dir(_) => return Err(Errno::EISDIR.into()),
            Body::HostSymlink(_) => return Err(Errno::ELOOP.into()),
            Body::Other => return Err(Errno::EACCES.into()),
        }
        o.opens += 1;
        Ok(MemOpen { obj: *node, mode })
    }

    fn open_dir(&self, node: &u64, expect: HostId) -> Result<MemOpen, DirError> {
        let mut s = self.lock();
        if id_of(*node) != expect {
            return Err(enoent());
        }
        let o = s.obj_mut(*node)?;
        if !matches!(o.body, Body::Dir(_)) {
            return Err(Errno::ENOTDIR.into());
        }
        o.opens += 1;
        Ok(MemOpen {
            obj: *node,
            mode: OpenMode {
                read: true,
                write: false,
            },
        })
    }

    fn close(&self, open: MemOpen) {
        let mut s = self.lock();
        if let Some(o) = s.objs.get_mut(&open.obj) {
            o.opens = o.opens.saturating_sub(1);
        }
        s.gc(open.obj);
    }

    fn create(&self, parent: &u64, name: Name<'_>, exclusive: bool) -> Result<(u64, MemOpen, HostStat), DirError> {
        let mut s = self.lock();
        let rw = OpenMode {
            read: true,
            write: true,
        };
        if let Ok(obj) = s.child(*parent, name.as_str()) {
            if exclusive {
                return Err(Errno::EEXIST.into());
            }
            let o = s.obj_mut(obj)?;
            if !matches!(o.body, Body::File(_)) {
                return Err(Errno::EISDIR.into());
            }
            o.opens += 1;
            return Ok((obj, MemOpen { obj, mode: rw }, s.stat(obj)?));
        }
        s.entries(*parent)?;
        let mut o = Obj::new(Body::File(Vec::new()), 0o644);
        o.opens = 1;
        let obj = s.new_obj(o);
        s.insert(*parent, name.as_str(), obj)?;
        Ok((obj, MemOpen { obj, mode: rw }, s.stat(obj)?))
    }

    fn mkdir(&self, parent: &u64, name: Name<'_>) -> Result<(u64, HostStat), DirError> {
        let mut s = self.lock();
        if s.entries(*parent)?.contains_key(name.as_str()) {
            return Err(Errno::EEXIST.into());
        }
        let obj = s.new_obj(Obj::new(Body::Dir(BTreeMap::new()), 0o755));
        s.insert(*parent, name.as_str(), obj)?;
        Ok((obj, s.stat(obj)?))
    }

    fn unlink(&self, parent: &u64, name: Name<'_>, expect: HostId) -> Result<(), DirError> {
        let mut s = self.lock();
        let obj = s.child(*parent, name.as_str())?;
        if id_of(obj) != expect {
            return Err(enoent());
        }
        if matches!(s.obj(obj)?.body, Body::Dir(_)) {
            return Err(Errno::EISDIR.into());
        }
        s.entries_mut(*parent)?.remove(name.as_str());
        let o = s.obj_mut(obj)?;
        o.nlink = o.nlink.saturating_sub(1);
        s.gc(obj);
        Ok(())
    }

    fn rmdir(&self, parent: &u64, name: Name<'_>, expect: HostId) -> Result<(), DirError> {
        let mut s = self.lock();
        let obj = s.child(*parent, name.as_str())?;
        if id_of(obj) != expect {
            return Err(enoent());
        }
        if !s.entries(obj)?.is_empty() {
            return Err(Errno::ENOTEMPTY.into());
        }
        s.entries_mut(*parent)?.remove(name.as_str());
        let o = s.obj_mut(obj)?;
        o.nlink = 0;
        s.gc(obj);
        Ok(())
    }

    fn rename(&self, from: (&u64, Name<'_>), to: (&u64, Name<'_>), flags: RenameFlags) -> Result<(), DirError> {
        if flags.exchange && !self.exchange {
            return Err(Errno::EINVAL.into());
        }
        let mut s = self.lock();
        let obj = s.child(*from.0, from.1.as_str())?;
        s.entries(*to.0)?;
        let target = s.child(*to.0, to.1.as_str()).ok();
        // Linux's checks, in its order (`fs/namei.c`): the source an
        // ancestor of the new parent is EINVAL; the target an ancestor of
        // the old parent is EINVAL under exchange, else ENOTEMPTY; the same
        // object under both names is done, with nothing changed.
        if flags.exchange {
            let target = target.ok_or_else(enoent)?;
            if s.below(*to.0, obj) || s.below(*from.0, target) {
                return Err(Errno::EINVAL.into());
            }
            if target == obj {
                return Ok(());
            }
            // Each name keeps its place in its directory's listing.
            if let Some(e) = s.entries_mut(*from.0)?.get_mut(from.1.as_str()) {
                e.0 = target;
            }
            if let Some(e) = s.entries_mut(*to.0)?.get_mut(to.1.as_str()) {
                e.0 = obj;
            }
            return Ok(());
        }
        if s.below(*to.0, obj) {
            return Err(Errno::EINVAL.into());
        }
        if let Some(target) = target {
            if flags.noreplace {
                return Err(Errno::EEXIST.into());
            }
            if s.below(*from.0, target) {
                return Err(Errno::ENOTEMPTY.into());
            }
            if target == obj {
                return Ok(());
            }
            let src_dir = matches!(s.obj(obj)?.body, Body::Dir(_));
            let target_dir = matches!(s.obj(target)?.body, Body::Dir(_));
            match (src_dir, target_dir) {
                (true, false) => return Err(Errno::ENOTDIR.into()),
                (false, true) => return Err(Errno::EISDIR.into()),
                (true, true) if !s.entries(target)?.is_empty() => return Err(Errno::ENOTEMPTY.into()),
                _ => {}
            }
            s.entries_mut(*to.0)?.remove(to.1.as_str());
            let t = s.obj_mut(target)?;
            t.nlink = if target_dir { 0 } else { t.nlink.saturating_sub(1) };
            s.gc(target);
        }
        s.entries_mut(*from.0)?.remove(from.1.as_str());
        s.insert(*to.0, to.1.as_str(), obj)
    }

    fn link(&self, node: &u64, expect: HostId, to: (&u64, Name<'_>)) -> Result<HostStat, DirError> {
        let mut s = self.lock();
        if id_of(*node) != expect {
            return Err(enoent());
        }
        let o = s.obj(*node)?;
        if !matches!(o.body, Body::File(_)) {
            return Err(Errno::EPERM.into());
        }
        // An unlinked object gets no name back (Linux's vfs_link: ENOENT).
        if o.nlink == 0 {
            return Err(enoent());
        }
        s.insert(*to.0, to.1.as_str(), *node)?;
        let o = s.obj_mut(*node)?;
        o.nlink = o.nlink.saturating_add(1);
        s.stat(*node)
    }

    fn read_at(&self, open: &MemOpen, offset: u64, buf: &mut [u8]) -> Result<usize, DirError> {
        if !open.mode.read {
            return Err(Errno::EBADF.into());
        }
        let s = self.lock();
        let data = s.open_file(open.obj)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, open: &MemOpen, offset: u64, data: &[u8]) -> Result<usize, DirError> {
        if !open.mode.write {
            return Err(Errno::EBADF.into());
        }
        let end = offset
            .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
            .filter(|&e| e <= MAX_FILE)
            .ok_or(DirError::Errno(Errno::EFBIG))?;
        let (start, end) = (usize_of(offset)?, usize_of(end)?);
        let mut s = self.lock();
        let file = s.open_file_mut(open.obj)?;
        if file.len() < end {
            file.resize(end, 0);
        }
        file[start..end].copy_from_slice(data);
        Ok(data.len())
    }

    fn sync(&self, open: &MemOpen, _data_only: bool) -> Result<(), DirError> {
        self.lock().obj(open.obj).map(|_| ())
    }

    fn set_len(&self, node: &u64, len: u64) -> Result<(), DirError> {
        if len > MAX_FILE {
            return Err(Errno::EFBIG.into());
        }
        let len = usize_of(len)?;
        let mut s = self.lock();
        match &mut s.obj_mut(*node)?.body {
            Body::File(d) => {
                d.resize(len, 0);
                Ok(())
            }
            Body::Dir(_) => Err(Errno::EISDIR.into()),
            _ => Err(Errno::EINVAL.into()),
        }
    }

    fn allocate(&self, open: &MemOpen, offset: u64, len: u64, keep_size: bool, punch: bool) -> Result<(), DirError> {
        if !open.mode.write {
            return Err(Errno::EBADF.into());
        }
        let end = offset
            .checked_add(len)
            .filter(|&e| e <= MAX_FILE)
            .ok_or(DirError::Errno(Errno::EFBIG))?;
        let (start, end) = (usize_of(offset)?, usize_of(end)?);
        let mut s = self.lock();
        let file = s.open_file_mut(open.obj)?;
        if punch {
            let stop = end.min(file.len());
            if start < stop {
                file[start..stop].fill(0);
            }
        } else if !keep_size && file.len() < end {
            file.resize(end, 0);
        }
        Ok(())
    }

    fn set_times(&self, node: &u64, atime: Option<Timespec>, mtime: Option<Timespec>) -> Result<(), DirError> {
        let mut s = self.lock();
        let o = s.obj_mut(*node)?;
        if let Some(t) = atime {
            o.atime = t;
        }
        if let Some(t) = mtime {
            o.mtime = t;
        }
        Ok(())
    }

    fn set_perm(&self, node: &u64, perm: u16) -> Result<(), DirError> {
        self.lock().obj_mut(*node)?.perm = perm & 0o777;
        Ok(())
    }

    fn read_dir(&self, dir: &MemOpen, after: u64, max: usize, out: &mut Vec<DirEntry>) -> Result<(), DirError> {
        let s = self.lock();
        let mut all: Vec<(&String, u64, u64)> = s
            .entries(dir.obj)?
            .iter()
            .filter(|(_, (_, cookie))| *cookie > after)
            .map(|(name, &(obj, cookie))| (name, obj, cookie))
            .collect();
        all.sort_by_key(|&(_, _, cookie)| cookie);
        for (name, obj, cookie) in all.into_iter().take(max) {
            out.push(DirEntry {
                name: name.as_bytes().to_vec(),
                id: id_of(obj),
                kind: s.obj(obj)?.kind(),
                cookie: cookie.min(MAX_COOKIE),
            });
        }
        Ok(())
    }

    fn read_link(&self, node: &u64, max: usize) -> Result<Vec<u8>, DirError> {
        match &self.lock().obj(*node)?.body {
            Body::HostSymlink(t) if t.len() <= max => Ok(t.clone()),
            Body::HostSymlink(_) => Err(Errno::ENAMETOOLONG.into()),
            _ => Err(Errno::EINVAL.into()),
        }
    }

    fn statfs(&self, _node: &u64) -> Result<StatFs, DirError> {
        let s = self.lock();
        let files = u64::try_from(s.objs.len()).unwrap_or(u64::MAX);
        Ok(StatFs {
            blocks: 1 << 20,
            bfree: 1 << 19,
            bavail: 1 << 19,
            files: files + (1 << 16),
            ffree: 1 << 16,
            bsize: 4096,
            frsize: 4096,
        })
    }

    fn get_record(&self, node: &u64) -> Result<Option<Vec<u8>>, DirError> {
        Ok(self.lock().obj(*node)?.record.clone())
    }

    fn set_record(&self, node: &u64, record: &[u8; RECORD_LEN]) -> Result<(), DirError> {
        self.lock().obj_mut(*node)?.record = Some(record.to_vec());
        Ok(())
    }

    fn get_xattr(&self, node: &u64, name: &[u8]) -> Result<Option<Vec<u8>>, DirError> {
        Ok(self.lock().obj(*node)?.xattrs.get(name).cloned())
    }

    fn set_xattr(&self, node: &u64, name: &[u8], value: &[u8], mode: XattrMode) -> Result<(), DirError> {
        let mut s = self.lock();
        let o = s.obj_mut(*node)?;
        let exists = o.xattrs.contains_key(name);
        match (mode, exists) {
            (XattrMode::Create, true) => Err(Errno::EEXIST.into()),
            (XattrMode::Replace, false) => Err(Errno::ENODATA.into()),
            _ => {
                o.xattrs.insert(name.to_vec(), value.to_vec());
                Ok(())
            }
        }
    }

    fn list_xattr(&self, node: &u64) -> Result<Vec<(Vec<u8>, usize)>, DirError> {
        Ok(self
            .lock()
            .obj(*node)?
            .xattrs
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect())
    }

    fn remove_xattr(&self, node: &u64, name: &[u8]) -> Result<(), DirError> {
        let mut s = self.lock();
        match s.obj_mut(*node)?.xattrs.remove(name) {
            Some(_) => Ok(()),
            None => Err(Errno::ENODATA.into()),
        }
    }
}
