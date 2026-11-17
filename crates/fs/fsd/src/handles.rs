// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The handle table: the `fh` the server hands out at OPEN, OPENDIR and
//! CREATE, chosen here (a counter, never reused in a session) and only ever
//! a key into this table. An unknown `fh`, one already released, one of the
//! other kind (a file's for a directory request) or one opened on another
//! node than the request names is EBADF.

use std::collections::HashMap;

use crate::fuse::Errno;

/// What a handle is open for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File {
        /// Readable.
        read: bool,
        /// Writable.
        write: bool,
    },
    /// A directory, for listing.
    Dir,
}

/// One open handle.
#[derive(Debug)]
pub struct Handle<O> {
    /// The node it is open on.
    pub nodeid: u64,
    /// What for.
    pub kind: Kind,
    /// The backend's open object.
    pub open: O,
}

/// The handle table.
#[derive(Debug)]
pub struct Handles<O> {
    map: HashMap<u64, Handle<O>>,
    next: u64,
    max: usize,
}

impl<O> Handles<O> {
    /// An empty table for at most `max` handles.
    pub fn new(max: usize) -> Handles<O> {
        Handles {
            map: HashMap::new(),
            next: 1,
            max,
        }
    }

    /// Whether one more may be opened.
    pub fn has_room(&self) -> bool {
        self.map.len() < self.max && self.next != u64::MAX
    }

    /// How many are open.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether none is open.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Stores an open object; its `fh`, or EMFILE at the limit (the caller
    /// checks [`Handles::has_room`] before opening, so this is a second
    /// line).
    pub fn insert(&mut self, nodeid: u64, kind: Kind, open: O) -> Result<u64, (Errno, O)> {
        if !self.has_room() {
            return Err((Errno::EMFILE, open));
        }
        let fh = self.next;
        self.next += 1;
        self.map.insert(fh, Handle { nodeid, kind, open });
        Ok(fh)
    }

    /// The handle `fh` on `nodeid`, or EBADF.
    pub fn get(&self, fh: u64, nodeid: u64) -> Result<&Handle<O>, Errno> {
        self.map
            .get(&fh)
            .filter(|h| h.nodeid == nodeid)
            .ok_or(Errno::EBADF)
    }

    /// Takes the handle `fh` on `nodeid` out, if it is of the kind `dir`
    /// says, or EBADF.
    pub fn remove(&mut self, fh: u64, nodeid: u64, dir: bool) -> Result<Handle<O>, Errno> {
        let ok = self
            .map
            .get(&fh)
            .is_some_and(|h| h.nodeid == nodeid && (h.kind == Kind::Dir) == dir);
        if !ok {
            return Err(Errno::EBADF);
        }
        self.map.remove(&fh).ok_or(Errno::EBADF)
    }

    /// Takes every handle out (DESTROY).
    pub fn drain(&mut self) -> Vec<Handle<O>> {
        self.map.drain().map(|(_, h)| h).collect()
    }

    /// Every handle's node id.
    pub fn nodes(&self) -> impl Iterator<Item = u64> + '_ {
        self.map.values().map(|h| h.nodeid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: Kind = Kind::File {
        read: true,
        write: true,
    };

    #[test]
    fn test_handles_are_keys_that_fail_closed() {
        let mut t = Handles::new(2);
        let a = t.insert(5, RW, 'a').unwrap();
        let b = t.insert(6, Kind::Dir, 'b').unwrap();
        assert_eq!((a, b), (1, 2));
        assert_eq!(t.insert(7, RW, 'c').map_err(|e| e.0), Err(Errno::EMFILE));
        assert_eq!(t.get(a, 5).map(|h| h.open), Ok('a'));
        // Another node's request, an unknown fh.
        assert_eq!(t.get(a, 6).map(|h| h.open), Err(Errno::EBADF));
        assert_eq!(t.get(99, 5).map(|h| h.open), Err(Errno::EBADF));
        // Released as the other kind: refused, and still there.
        assert_eq!(t.remove(a, 5, true).map(|h| h.open), Err(Errno::EBADF));
        assert_eq!(t.remove(b, 6, false).map(|h| h.open), Err(Errno::EBADF));
        assert_eq!(t.remove(a, 5, false).map(|h| h.open), Ok('a'));
        // Released twice; never reused.
        assert_eq!(t.remove(a, 5, false).map(|h| h.open), Err(Errno::EBADF));
        assert_eq!(t.insert(5, RW, 'd'), Ok(3));
        assert_eq!(t.get(a, 5).map(|h| h.open), Err(Errno::EBADF));
    }
}
