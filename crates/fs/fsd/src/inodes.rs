// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The node table: the server's node ids, chosen here and never a host
//! inode number, each mapped to the backend's node and the host identity.
//!
//! A guest's node id is only ever a key into this table: an id the server
//! did not hand out, or one the guest has forgotten, is EBADF (as
//! virtiofsd's `inodes.get(..).ok_or_else(ebadf)`). Ids are never reused in a
//! session, so a stale id can never reach another object, and the
//! generation is always 0.
//!
//! The guest's lookup count follows Linux's rules (fs/fuse/inode.c): each
//! reply that hands a node id out (LOOKUP, MKNOD, MKDIR, SYMLINK, LINK,
//! CREATE, a READDIRPLUS entry) adds one; FORGET and BATCH_FORGET take
//! `nlookup` away. A forget of more than the count takes it to 0 and is
//! counted, never wraps. A node goes when its count is 0 **and** no handle
//! is open on it, so a forget never frees a node an open file uses. The
//! root (id 1) is never forgotten.

use std::collections::HashMap;

use crate::dir::{HostId, HostKind};
use crate::fuse::Errno;

/// The root's node id, `FUSE_ROOT_ID`.
pub const ROOT: u64 = 1;

/// One node.
#[derive(Debug)]
pub struct Entry<N> {
    /// The backend's node.
    pub node: N,
    /// The host identity.
    pub id: HostId,
    /// The host kind when last seen.
    pub kind: HostKind,
    /// A directory's parent, for its `..` entry; the root's is itself.
    pub parent: u64,
    /// The guest's lookups.
    lookups: u64,
    /// Handles open on it.
    handles: u32,
}

/// What a forget did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forgot {
    /// The count went down; the node stays (lookups or handles left).
    Kept,
    /// The node went.
    Removed,
    /// No such node, or more forgotten than looked up (the count is 0 now).
    Unmatched,
}

/// The node table.
#[derive(Debug)]
pub struct Inodes<N> {
    map: HashMap<u64, Entry<N>>,
    by_id: HashMap<HostId, u64>,
    next: u64,
    max: usize,
}

impl<N: Clone> Inodes<N> {
    /// A table holding the root, for at most `max` nodes (the root
    /// included, so at least 1).
    pub fn new(root: N, id: HostId, max: usize) -> Inodes<N> {
        let mut map = HashMap::new();
        map.insert(
            ROOT,
            Entry {
                node: root,
                id,
                kind: HostKind::Dir,
                parent: ROOT,
                lookups: 1,
                handles: 0,
            },
        );
        let mut by_id = HashMap::new();
        by_id.insert(id, ROOT);
        Inodes {
            map,
            by_id,
            next: ROOT + 1,
            max: max.max(1),
        }
    }

    /// The node, or EBADF.
    pub fn get(&self, nodeid: u64) -> Result<&Entry<N>, Errno> {
        self.map.get(&nodeid).ok_or(Errno::EBADF)
    }

    /// How many nodes are held, the root included.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether only the root is held.
    pub fn is_empty(&self) -> bool {
        self.map.len() <= 1
    }

    /// The node id held for this host object, if any.
    pub fn find(&self, id: HostId) -> Option<u64> {
        self.by_id.get(&id).copied()
    }

    /// Whether a new node may be added.
    pub fn has_room(&self) -> bool {
        self.map.len() < self.max
    }

    /// One more guest lookup of the host object `id`, seen under `parent`:
    /// its node id, the one it already has or a new one (ENFILE at the
    /// limit). A held node's backend node is replaced with this newer one.
    pub fn lookup(&mut self, node: N, id: HostId, kind: HostKind, parent: u64) -> Result<u64, Errno> {
        if let Some(&nodeid) = self.by_id.get(&id)
            && let Some(e) = self.map.get_mut(&nodeid)
        {
            e.lookups = e.lookups.saturating_add(1);
            if nodeid != ROOT {
                e.node = node;
                e.kind = kind;
                if kind == HostKind::Dir {
                    e.parent = parent;
                }
            }
            return Ok(nodeid);
        }
        if !self.has_room() || self.next == u64::MAX {
            return Err(Errno::ENFILE);
        }
        let nodeid = self.next;
        self.next += 1;
        self.map.insert(
            nodeid,
            Entry {
                node,
                id,
                kind,
                parent,
                lookups: 1,
                handles: 0,
            },
        );
        self.by_id.insert(id, nodeid);
        Ok(nodeid)
    }

    /// Replaces a held node's backend node after a rename moved it.
    pub fn moved(&mut self, nodeid: u64, node: N, parent: u64) {
        if nodeid == ROOT {
            return;
        }
        if let Some(e) = self.map.get_mut(&nodeid) {
            e.node = node;
            if e.kind == HostKind::Dir {
                e.parent = parent;
            }
        }
    }

    /// Takes `n` lookups away.
    pub fn forget(&mut self, nodeid: u64, n: u64) -> Forgot {
        if nodeid == ROOT {
            return Forgot::Kept;
        }
        let Some(e) = self.map.get_mut(&nodeid) else {
            return Forgot::Unmatched;
        };
        let over = n > e.lookups;
        e.lookups = e.lookups.saturating_sub(n);
        let result = if over { Forgot::Unmatched } else { Forgot::Kept };
        if self.release_if_unused(nodeid) {
            if over { Forgot::Unmatched } else { Forgot::Removed }
        } else {
            result
        }
    }

    /// A handle opened on the node.
    pub fn opened(&mut self, nodeid: u64) {
        if let Some(e) = self.map.get_mut(&nodeid) {
            e.handles = e.handles.saturating_add(1);
        }
    }

    /// A handle on the node closed; the node goes if nothing else holds it.
    pub fn closed(&mut self, nodeid: u64) {
        if let Some(e) = self.map.get_mut(&nodeid) {
            e.handles = e.handles.saturating_sub(1);
        }
        self.release_if_unused(nodeid);
    }

    /// The guest's lookup count and open handles of a node.
    pub fn counts(&self, nodeid: u64) -> Option<(u64, u32)> {
        self.map.get(&nodeid).map(|e| (e.lookups, e.handles))
    }

    fn release_if_unused(&mut self, nodeid: u64) -> bool {
        if nodeid == ROOT {
            return false;
        }
        let unused = self
            .map
            .get(&nodeid)
            .is_some_and(|e| e.lookups == 0 && e.handles == 0);
        if unused
            && let Some(e) = self.map.remove(&nodeid)
            && self.by_id.get(&e.id) == Some(&nodeid)
        {
            self.by_id.remove(&e.id);
        }
        unused
    }

    /// Drops every node but the root (DESTROY).
    pub fn clear(&mut self) {
        self.map.retain(|&k, _| k == ROOT);
        self.by_id.retain(|_, &mut v| v == ROOT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(file: u128) -> HostId {
        HostId { volume: 9, file }
    }

    #[test]
    fn test_node_ids_are_the_servers_and_never_reused() {
        let mut t = Inodes::new((), id(2), 8);
        // Host file ids 1000 and 1001 get node ids 2 and 3.
        let a = t.lookup((), id(1000), HostKind::File, ROOT).unwrap();
        let b = t.lookup((), id(1001), HostKind::File, ROOT).unwrap();
        assert_eq!((a, b), (2, 3));
        // The same host object, the same id; its count goes up.
        assert_eq!(t.lookup((), id(1000), HostKind::File, ROOT), Ok(a));
        assert_eq!(t.counts(a), Some((2, 0)));
        assert_eq!(t.forget(a, 2), Forgot::Removed);
        assert_eq!(t.get(a).map(|_| ()), Err(Errno::EBADF));
        // Looked up again, it gets a new id: a stale id never reaches it.
        assert_eq!(t.lookup((), id(1000), HostKind::File, ROOT), Ok(4));
        // An id never handed out.
        for bad in [0, 5, 99, u64::MAX] {
            assert_eq!(t.get(bad).map(|_| ()), Err(Errno::EBADF), "{bad}");
        }
    }

    #[test]
    fn test_forget_never_underflows_or_frees_an_open_node() {
        let mut t = Inodes::new((), id(2), 8);
        let a = t.lookup((), id(10), HostKind::File, ROOT).unwrap();
        t.opened(a);
        // Forgetting every lookup and more: the count is 0, not wrapped, and
        // the node stays while its handle is open.
        assert_eq!(t.forget(a, u64::MAX), Forgot::Unmatched);
        assert_eq!(t.counts(a), Some((0, 1)));
        assert_eq!(t.forget(a, 1), Forgot::Unmatched);
        t.closed(a);
        assert_eq!(t.counts(a), None);
        // The root is never forgotten; unknown ids are unmatched.
        assert_eq!(t.forget(ROOT, u64::MAX), Forgot::Kept);
        assert!(t.get(ROOT).is_ok_and(|e| e.parent == ROOT));
        assert_eq!(t.forget(77, 1), Forgot::Unmatched);
        // A closed handle on a node still looked up keeps it.
        let b = t.lookup((), id(11), HostKind::File, ROOT).unwrap();
        t.opened(b);
        t.closed(b);
        assert_eq!(t.counts(b), Some((1, 0)));
    }

    #[test]
    fn test_node_limit_is_enfile() {
        let mut t = Inodes::new((), id(2), 3);
        t.lookup((), id(10), HostKind::File, ROOT).unwrap();
        t.lookup((), id(11), HostKind::File, ROOT).unwrap();
        assert!(!t.has_room());
        assert_eq!(t.lookup((), id(12), HostKind::File, ROOT), Err(Errno::ENFILE));
        // A node already held can still be looked up.
        assert_eq!(t.lookup((), id(10), HostKind::File, ROOT), Ok(2));
        assert_eq!(t.len(), 3);
    }
}
