// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A guest's requests to a session over any `ConfinedDir`, so one sequence
//! runs over `MemDir` (the model) and the host directory alike.

use wick_fsd::dir::ConfinedDir;
use wick_fsd::fuse::encode::request;
use wick_fsd::fuse::{Errno, Opcode};
use wick_fsd::session::{Config, Session};

use super::{CAP, GID, UID, errno, le32, le64, name, u32_at, u64_at};

pub const FATTR_MODE: u32 = 1;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_FH: u32 = 1 << 6;
pub const FUSE_GETATTR_FH: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
/// fuse_attr inside an attr_out: size, mode and nlink.
const ATTR: usize = 16;

/// A file's attributes as the guest sees them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub size: u64,
    pub mode: u32,
    pub nlink: u32,
}

pub struct G<D: ConfinedDir> {
    pub s: Session<D>,
    unique: u64,
}

impl<D: ConfinedDir> G<D> {
    pub fn new(dir: D) -> G<D> {
        let s = Session::new(
            dir,
            Config {
                owner: (UID, GID),
                ..Config::default()
            },
        )
        .unwrap();
        let mut g = G { s, unique: 0 };
        let args = [&le32(7)[..], &le32(47), &le32(1 << 20), &le32(u32::MAX), &[0; 48]].concat();
        g.ok(Opcode::Init, 0, &[&args]);
        g
    }

    pub fn raw(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> Option<Vec<u8>> {
        self.unique += 2;
        let bytes = request(op as u32, self.unique, nodeid, (UID, GID), args);
        let reply = self.s.handle(&bytes, CAP);
        self.s.check().unwrap();
        reply
    }

    /// The error (0 or a negative errno) and the body.
    pub fn call(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> (i32, Vec<u8>) {
        let r = self.raw(op, nodeid, args).unwrap();
        (i32::from_le_bytes(r[4..8].try_into().unwrap()), r[16..].to_vec())
    }

    pub fn ok(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> Vec<u8> {
        let (e, body) = self.call(op, nodeid, args);
        assert_eq!(e, 0, "{op:?} on {nodeid}: {:?}", errno(e));
        body
    }

    fn result(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> Result<Vec<u8>, Errno> {
        let (e, body) = self.call(op, nodeid, args);
        if e < 0 { Err(errno(e)) } else { Ok(body) }
    }

    /// The node id a name has now, ENOENT for none (a negative entry).
    pub fn lookup(&mut self, parent: u64, n: &[u8]) -> Result<u64, Errno> {
        let body = self.result(Opcode::Lookup, parent, &[&name(n)])?;
        match u64_at(&body, 0) {
            0 => Err(Errno::ENOENT),
            id => Ok(id),
        }
    }

    pub fn mkdir(&mut self, parent: u64, n: &[u8]) -> u64 {
        u64_at(&self.ok(Opcode::Mkdir, parent, &[&le32(0o755), &le32(0), &name(n)]), 0)
    }

    /// CREATE, read-write: (node id, fh).
    pub fn create(&mut self, parent: u64, n: &[u8]) -> (u64, u64) {
        let args = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
        let r = self.ok(Opcode::Create, parent, &[&args, &name(n)]);
        (u64_at(&r, 0), u64_at(&r, 40 + 88))
    }

    pub fn open(&mut self, nodeid: u64, flags: u32) -> Result<u64, Errno> {
        let r = self.result(Opcode::Open, nodeid, &[&le32(flags), &le32(0)])?;
        Ok(u64_at(&r, 0))
    }

    pub fn write(&mut self, nodeid: u64, fh: u64, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        let size = u32::try_from(data.len()).unwrap();
        let args = [&le64(fh)[..], &le64(offset), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
        let r = self.result(Opcode::Write, nodeid, &[&args, data])?;
        Ok(u32_at(&r, 0))
    }

    pub fn read(&mut self, nodeid: u64, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        let args = [&le64(fh)[..], &le64(offset), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
        self.result(Opcode::Read, nodeid, &[&args])
    }

    pub fn fsync(&mut self, nodeid: u64, fh: u64) -> Result<(), Errno> {
        let args = [&le64(fh)[..], &le32(0), &le32(0)].concat();
        self.result(Opcode::Fsync, nodeid, &[&args]).map(drop)
    }

    pub fn fallocate(&mut self, nodeid: u64, fh: u64, offset: u64, len: u64) -> Result<(), Errno> {
        let args = [&le64(fh)[..], &le64(offset), &le64(len), &le32(0), &le32(0)].concat();
        self.result(Opcode::Fallocate, nodeid, &[&args]).map(drop)
    }

    pub fn release(&mut self, nodeid: u64, fh: u64) {
        let args = [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat();
        self.ok(Opcode::Release, nodeid, &[&args]);
    }

    /// FORGET: no reply (a request without room for one, as the device
    /// sends it).
    pub fn forget(&mut self, nodeid: u64, n: u64) {
        self.unique += 2;
        let bytes = request(Opcode::Forget as u32, self.unique, nodeid, (UID, GID), &[&le64(n)]);
        assert_eq!(self.s.handle(&bytes, 0), None);
        self.s.check().unwrap();
    }

    /// GETATTR, through `fh` if given (FUSE_GETATTR_FH, as Linux sends it
    /// for an open file).
    pub fn getattr(&mut self, nodeid: u64, fh: Option<u64>) -> Result<Attr, Errno> {
        let flags = if fh.is_some() { FUSE_GETATTR_FH } else { 0 };
        let args = [&le32(flags)[..], &le32(0), &le64(fh.unwrap_or(0))].concat();
        let r = self.result(Opcode::Getattr, nodeid, &[&args])?;
        Ok(attr(&r[ATTR..]))
    }

    /// SETATTR of `valid` (size, mode), through `fh` if given (FATTR_FH).
    pub fn setattr(&mut self, nodeid: u64, valid: u32, size: u64, mode: u32, fh: Option<u64>) -> Result<Attr, Errno> {
        let mut a = vec![0u8; 88];
        let valid = valid | if fh.is_some() { FATTR_FH } else { 0 };
        a[0..4].copy_from_slice(&le32(valid));
        a[8..16].copy_from_slice(&le64(fh.unwrap_or(0)));
        a[16..24].copy_from_slice(&le64(size));
        a[68..72].copy_from_slice(&le32(mode));
        let r = self.result(Opcode::Setattr, nodeid, &[&a])?;
        Ok(attr(&r[ATTR..]))
    }

    /// LINK `nodeid` as `n` in `parent`: the new entry's node id.
    pub fn link(&mut self, nodeid: u64, parent: u64, n: &[u8]) -> Result<u64, Errno> {
        let r = self.result(Opcode::Link, parent, &[&le64(nodeid), &name(n)])?;
        Ok(u64_at(&r, 0))
    }

    pub fn unlink(&mut self, parent: u64, n: &[u8]) -> Result<(), Errno> {
        self.result(Opcode::Unlink, parent, &[&name(n)]).map(drop)
    }

    pub fn rename(&mut self, from: (u64, &[u8]), to: (u64, &[u8]), flags: u32) -> Result<(), Errno> {
        let args = [&le64(to.0)[..], &le32(flags), &le32(0)].concat();
        self.result(Opcode::Rename2, from.0, &[&args, &name(from.1), &name(to.1)]).map(drop)
    }

    /// Writes `data` at 0 through a fresh read-write open of the node and
    /// reads it back through it.
    pub fn rewrite(&mut self, nodeid: u64, data: &[u8]) {
        let fh = self.open(nodeid, 2).unwrap_or_else(|e| panic!("open of node {nodeid}: {e:?}"));
        assert_eq!(self.write(nodeid, fh, 0, data), Ok(u32::try_from(data.len()).unwrap()));
        let back = self.read(nodeid, fh, 0, u32::try_from(data.len()).unwrap()).unwrap();
        assert_eq!(back, data);
        self.release(nodeid, fh);
    }
}

fn attr(a: &[u8]) -> Attr {
    Attr {
        ino: u64_at(a, 0),
        size: u64_at(a, 8),
        mode: u32_at(a, 60),
        nlink: u32_at(a, 64),
    }
}
