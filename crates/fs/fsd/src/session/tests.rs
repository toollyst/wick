// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::cache::{FOPEN_CACHE_DIR, FOPEN_DIRECT_IO, FOPEN_KEEP_CACHE, FUSE_AUTO_INVAL_DATA};
use crate::fuse::encode::request;
use crate::limits::Limits;
use crate::memdir::MemDir;

/// A generous reply buffer.
const CAP: usize = 1 << 16;

const UID: u32 = 1000;
const GID: u32 = 100;

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn name(s: &str) -> Vec<u8> {
    [s.as_bytes(), b"\0"].concat()
}

/// fuse_attr's field offsets inside an entry_out (40 bytes in) and an
/// attr_out (16 bytes in).
const ATTR_IN_ENTRY: usize = 40;
const ATTR_IN_ATTR_OUT: usize = 16;
const A_INO: usize = 0;
const A_SIZE: usize = 8;
const A_MODE: usize = 60;
const A_UID: usize = 68;
const A_GID: usize = 72;
const A_RDEV: usize = 76;

struct T {
    s: Session<MemDir>,
    unique: u64,
}

fn errno_of(e: i32) -> Errno {
    Errno::from_linux(-e).unwrap_or_else(|| panic!("errno {}", -e))
}

/// A reply split: (error, body).
fn split(reply: &[u8], unique: u64) -> (i32, Vec<u8>) {
    assert!(reply.len() >= 16, "a reply of {} bytes", reply.len());
    assert_eq!(u32_at(reply, 0) as usize, reply.len());
    assert_eq!(u64_at(reply, 8), unique);
    (i32::from_le_bytes(reply[4..8].try_into().unwrap()), reply[16..].to_vec())
}

impl T {
    fn new() -> T {
        T::with(Config {
            owner: (UID, GID),
            ..Config::default()
        })
    }

    fn with(config: Config) -> T {
        let mut t = T::bare(config);
        t.init(47);
        t
    }

    fn bare(config: Config) -> T {
        T {
            s: Session::new(MemDir::new(), config).unwrap(),
            unique: 0,
        }
    }

    /// An initialised session over `dir`.
    fn over(dir: MemDir, config: Config) -> T {
        let mut t = T {
            s: Session::new(dir, config).unwrap(),
            unique: 0,
        };
        t.init(47);
        t
    }

    fn init(&mut self, minor: u32) -> Vec<u8> {
        let args = [&le32(7)[..], &le32(minor), &le32(1 << 20), &le32(u32::MAX), &[0; 48]].concat();
        self.ok(Opcode::Init, 0, &[&args])
    }

    /// The raw reply to a request with `cap` bytes of buffers.
    fn raw(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]], cap: usize) -> Option<Vec<u8>> {
        self.unique += 2;
        let bytes = request(op as u32, self.unique, nodeid, (UID, GID), args);
        let reply = self.s.handle(&bytes, cap);
        if let Some(r) = &reply {
            assert!(r.len() <= cap);
        }
        assert_eq!(reply.is_some(), cap > 0);
        self.s.check().unwrap();
        reply
    }

    fn call(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> (i32, Vec<u8>) {
        let reply = self.raw(op, nodeid, args, CAP).unwrap();
        split(&reply, self.unique)
    }

    fn ok(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> Vec<u8> {
        let (e, body) = self.call(op, nodeid, args);
        assert_eq!(e, 0, "{op:?} on {nodeid} failed");
        body
    }

    fn err(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> Errno {
        let (e, body) = self.call(op, nodeid, args);
        assert!(e < 0, "{op:?} on {nodeid} succeeded");
        assert!(body.is_empty());
        errno_of(e)
    }

    fn lookup(&mut self, parent: u64, n: &str) -> Vec<u8> {
        self.ok(Opcode::Lookup, parent, &[&name(n)])
    }

    fn mkdir(&mut self, parent: u64, n: &str, mode: u32) -> u64 {
        let e = self.ok(Opcode::Mkdir, parent, &[&le32(mode), &le32(0), &name(n)]);
        u64_at(&e, 0)
    }

    /// CREATE: (node id, fh).
    fn create(&mut self, parent: u64, n: &str, mode: u32) -> (u64, u64) {
        let args = [&le32(2)[..], &le32(mode), &le32(0), &le32(0)].concat();
        let r = self.ok(Opcode::Create, parent, &[&args, &name(n)]);
        (u64_at(&r, 0), u64_at(&r, ENTRY_OUT_LEN))
    }

    fn open(&mut self, nodeid: u64, flags: u32) -> Result<(u64, u32), Errno> {
        let (e, r) = self.call(Opcode::Open, nodeid, &[&le32(flags), &le32(0)]);
        if e < 0 {
            return Err(errno_of(e));
        }
        Ok((u64_at(&r, 0), u32_at(&r, 8)))
    }

    fn read_in(fh: u64, offset: u64, size: u32) -> Vec<u8> {
        [&le64(fh)[..], &le64(offset), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat()
    }

    fn write(&mut self, nodeid: u64, fh: u64, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        let size = u32::try_from(data.len()).unwrap();
        let args = [&le64(fh)[..], &le64(offset), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
        let (e, r) = self.call(Opcode::Write, nodeid, &[&args, data]);
        if e < 0 {
            return Err(errno_of(e));
        }
        Ok(u32_at(&r, 0))
    }

    fn release(&mut self, nodeid: u64, fh: u64) {
        let args = [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat();
        self.ok(Opcode::Release, nodeid, &[&args]);
    }

    fn getattr(&mut self, nodeid: u64) -> Vec<u8> {
        let a = self.ok(Opcode::Getattr, nodeid, &[&[0; 16]]);
        a[ATTR_IN_ATTR_OUT..].to_vec()
    }

    fn forget(&mut self, nodeid: u64, n: u64) {
        assert_eq!(self.raw(Opcode::Forget, nodeid, &[&le64(n)], 0), None);
    }

    fn setattr(&mut self, nodeid: u64, valid: u32, size: u64, mode: u32, uid: u32, gid: u32) -> (i32, Vec<u8>) {
        let mut a = vec![0u8; 88];
        a[0..4].copy_from_slice(&le32(valid));
        a[16..24].copy_from_slice(&le64(size));
        a[68..72].copy_from_slice(&le32(mode));
        a[76..80].copy_from_slice(&le32(uid));
        a[80..84].copy_from_slice(&le32(gid));
        self.call(Opcode::Setattr, nodeid, &[&a])
    }
}

#[test]
fn test_requests_before_init_a_second_init_and_after_destroy_are_eio() {
    let mut t = T::bare(Config::default());
    assert_eq!(t.err(Opcode::Getattr, ROOT, &[&[0; 16]]), Errno::EIO);
    assert_eq!(t.err(Opcode::Lookup, ROOT, &[&name("a")]), Errno::EIO);
    // A FORGET before INIT changes nothing and gets no reply.
    t.forget(ROOT, 1);
    t.init(47);
    t.getattr(ROOT);
    let again = [&le32(7)[..], &le32(47), &le32(0), &le32(0)].concat();
    assert_eq!(t.err(Opcode::Init, 0, &[&again]), Errno::EIO);
    let (dir, fh) = t.create(ROOT, "f", 0o644);
    t.ok(Opcode::Destroy, 0, &[]);
    assert!(t.s.destroyed());
    assert_eq!(t.s.dir().open_count(), 0, "DESTROY closes every handle");
    assert_eq!(t.s.handles_open(), 0);
    assert_eq!(t.err(Opcode::Getattr, ROOT, &[&[0; 16]]), Errno::EIO);
    assert_eq!(t.err(Opcode::Init, 0, &[&again]), Errno::EIO);
    assert_eq!(t.err(Opcode::Read, dir, &[&T::read_in(fh, 0, 10)]), Errno::EIO);
}

#[test]
fn test_init_offers_no_locks_no_dax_and_max_write_1_mib() {
    let mut t = T::bare(Config::default());
    let out = t.init(47);
    assert_eq!(out.len(), INIT_OUT_LEN);
    assert_eq!((u32_at(&out, 0), u32_at(&out, 4)), (7, 47));
    let flags = u32_at(&out, 12);
    // The guest offered every flag; none of these is taken.
    for (bit, what) in [
        (1 << 1, "POSIX_LOCKS"),
        (1 << 10, "FLOCK_LOCKS"),
        (1 << 26, "MAP_ALIGNMENT"),
        (1 << 16, "WRITEBACK_CACHE"),
        (1 << 4, "EXPORT_SUPPORT"),
        (1 << 20, "POSIX_ACL"),
        (1 << 29, "SETXATTR_EXT"),
        (1 << 30, "INIT_EXT"),
        (1 << 19, "HANDLE_KILLPRIV"),
        (1 << 28, "HANDLE_KILLPRIV_V2"),
    ] {
        assert_eq!(flags & bit, 0, "{what}");
    }
    assert_ne!(flags & (1 << 22), 0, "MAX_PAGES");
    assert_eq!(flags & FUSE_AUTO_INVAL_DATA, FUSE_AUTO_INVAL_DATA, "auto's flag");
    assert_eq!(u32_at(&out, 20), 1 << 20, "max_write");
    assert_eq!(u16::from_le_bytes([out[28], out[29]]), 256, "max_pages");
    assert_eq!(u32_at(&out, 32), 0, "flags2: no DAX");

    // An older guest: its minor; the flags only those it offered.
    let mut t = T::bare(Config::default());
    let args = [&le32(7)[..], &le32(31), &le32(0), &le32(1)].concat();
    let out = t.ok(Opcode::Init, 0, &[&args]);
    assert_eq!((u32_at(&out, 4), u32_at(&out, 12)), (31, 1));
    // Another major, or a minor before virtio-fs: EPROTO, still waiting.
    for (major, minor) in [(6, 47), (8, 0), (7, 30)] {
        let mut t = T::bare(Config::default());
        let args = [&le32(major)[..], &le32(minor), &le32(0), &le32(0)].concat();
        assert_eq!(t.err(Opcode::Init, 0, &[&args]), Errno::EPROTO);
        assert_eq!(t.err(Opcode::Getattr, ROOT, &[&[0; 16]]), Errno::EIO);
    }
}

#[test]
fn test_node_ids_are_the_servers_and_unknown_ids_are_ebadf() {
    let mut t = T::new();
    // Host objects the guest has not looked up: MemDir objects 2 to 4.
    for n in ["h1", "h2", "h3"] {
        t.s.dir().add_raw_name(1, n).unwrap();
    }
    t.mkdir(ROOT, "d", 0o755);
    let e = t.lookup(ROOT, "d");
    let nodeid = u64_at(&e, 0);
    // The server's id, the first it handed out, not the host's object
    // number (5) nor the inode number shown.
    assert_eq!(nodeid, 2);
    let ino = u64_at(&e, ATTR_IN_ENTRY + A_INO);
    assert_eq!(ino, ino_of(HostId { volume: crate::memdir::VOLUME, file: 5 }));
    assert_ne!(ino, nodeid);
    for bad in [0, 3, 5, 1000, u64::MAX] {
        assert_eq!(t.err(Opcode::Getattr, bad, &[&[0; 16]]), Errno::EBADF, "{bad}");
        assert_eq!(t.err(Opcode::Lookup, bad, &[&name("x")]), Errno::EBADF);
    }
    // An fh never handed out, another node's, a directory's for a file
    // request and the other way round.
    let (f, fh) = t.create(ROOT, "f", 0o644);
    let dfh = u64_at(&t.ok(Opcode::Opendir, ROOT, &[&[0; 8]]), 0);
    assert_eq!(t.err(Opcode::Read, f, &[&T::read_in(fh + 100, 0, 4)]), Errno::EBADF);
    assert_eq!(t.err(Opcode::Read, nodeid, &[&T::read_in(fh, 0, 4)]), Errno::EBADF);
    assert_eq!(t.err(Opcode::Read, ROOT, &[&T::read_in(dfh, 0, 4)]), Errno::EBADF);
    assert_eq!(t.err(Opcode::Readdir, f, &[&T::read_in(fh, 0, 4096)]), Errno::EBADF);
    let rel = [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat();
    assert_eq!(t.err(Opcode::Releasedir, f, &[&rel]), Errno::EBADF);
    t.release(f, fh);
    assert_eq!(t.err(Opcode::Release, f, &[&rel]), Errno::EBADF, "released twice");
}

#[test]
fn test_forget_cannot_underflow_or_free_a_node_with_an_open_handle() {
    let mut t = T::new();
    let (f, fh) = t.create(ROOT, "f", 0o644);
    t.write(f, fh, 0, b"data").unwrap();
    assert_eq!(t.s.node_counts(f), Some((1, 1)));
    // More than the guest looked up, twice, and as a batch.
    t.forget(f, u64::MAX);
    t.forget(f, 5);
    let batch = [le32(2).as_slice(), &le32(0), &le64(f), &le64(7), &le64(999), &le64(1)].concat();
    assert_eq!(t.raw(Opcode::BatchForget, 0, &[&batch], 0), None);
    assert_eq!(t.s.node_counts(f), Some((0, 1)), "kept for its handle");
    assert_eq!(t.s.counters().forgets_unmatched, 4);
    // The handle still reads its file.
    let r = t.ok(Opcode::Read, f, &[&T::read_in(fh, 0, 100)]);
    assert_eq!(r, b"data");
    t.release(f, fh);
    assert_eq!(t.s.node_counts(f), None);
    assert_eq!(t.err(Opcode::Getattr, f, &[&[0; 16]]), Errno::EBADF);
    // The root is never forgotten.
    t.forget(ROOT, u64::MAX);
    t.getattr(ROOT);
}

#[test]
fn test_sizes_the_guest_names_are_capped_before_allocation() {
    let mut t = T::new();
    let (f, fh) = t.create(ROOT, "f", 0o644);
    t.write(f, fh, 0, &[7u8; 10_000]).unwrap();
    // A READ of 4 GiB into 4 KiB of buffers: at most the buffers.
    let reply = t.raw(Opcode::Read, f, &[&T::read_in(fh, 0, u32::MAX)], 16 + 4096).unwrap();
    let (e, data) = split(&reply, t.unique);
    assert_eq!((e, data.len()), (0, 4096));
    // The guest's size when it is the least.
    let reply = t.raw(Opcode::Read, f, &[&T::read_in(fh, 0, 10)], CAP).unwrap();
    assert_eq!(reply.len(), 16 + 10);
    // READDIR of 4 GiB into 100 bytes: entries up to 84 bytes.
    let dfh = u64_at(&t.ok(Opcode::Opendir, ROOT, &[&[0; 8]]), 0);
    let reply = t.raw(Opcode::Readdir, ROOT, &[&T::read_in(dfh, 0, u32::MAX)], 100).unwrap();
    let (e, data) = split(&reply, t.unique);
    assert_eq!(e, 0);
    assert!(data.len() <= 84 && !data.is_empty());
    // GETXATTR and LISTXATTR: the size is compared, never allocated.
    let set = [&le32(3)[..], &le32(0), b"user.a\0", b"abc"].concat();
    t.ok(Opcode::Setxattr, f, &[&set]);
    let get = |size: u32| [&le32(size)[..], &le32(0), b"user.a\0"].concat();
    assert_eq!(t.ok(Opcode::Getxattr, f, &[&get(u32::MAX)]), b"abc");
    assert_eq!(t.ok(Opcode::Getxattr, f, &[&get(0)]), [3, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(t.err(Opcode::Getxattr, f, &[&get(2)]), Errno::ERANGE);
    let list = |size: u32| [&le32(size)[..], &le32(0)].concat();
    assert_eq!(t.ok(Opcode::Listxattr, f, &[&list(u32::MAX)]), b"user.a\0");
    assert_eq!(u32_at(&t.ok(Opcode::Listxattr, f, &[&list(0)]), 0), 7);
    assert_eq!(t.err(Opcode::Listxattr, f, &[&list(6)]), Errno::ERANGE);
}

#[test]
fn test_a_request_whose_reply_does_not_fit_does_nothing() {
    let mut t = T::new();
    t.mkdir(ROOT, "d", 0o755);
    let before = t.s.nodes();
    // LOOKUP into 100 bytes (entry_out needs 144): ERANGE, no lookup counted.
    let reply = t.raw(Opcode::Lookup, ROOT, &[&name("d")], 100).unwrap();
    assert_eq!(split(&reply, t.unique).0, -Errno::ERANGE.get());
    let d = u64_at(&t.lookup(ROOT, "d"), 0);
    assert_eq!(t.s.node_counts(d), Some((2, 0)), "the mkdir's and this lookup's");
    // MKDIR into 100 bytes, or with no buffers: not made.
    let args = [&le32(0o755)[..], &le32(0)].concat();
    let reply = t.raw(Opcode::Mkdir, ROOT, &[&args, &name("x")], 100).unwrap();
    assert_eq!(split(&reply, t.unique).0, -Errno::ERANGE.get());
    assert_eq!(t.raw(Opcode::Mkdir, ROOT, &[&args, &name("y")], 0), None);
    assert!(t.absent(ROOT, "x") && t.absent(ROOT, "y"));
    assert_eq!(t.s.nodes(), before, "nothing new held");
    // Buffers smaller than a header: an empty reply, nothing done, also
    // for a request whose reply is the header alone.
    assert_eq!(t.raw(Opcode::Mkdir, ROOT, &[&args, &name("z")], 8), Some(Vec::new()));
    assert_eq!(t.raw(Opcode::Rmdir, ROOT, &[&name("d")], 15), Some(Vec::new()));
    assert_eq!(t.raw(Opcode::Destroy, 0, &[], 3), Some(Vec::new()));
    assert!(!t.s.destroyed());
    assert!(!t.absent(ROOT, "d"));
    assert!(t.s.counters().replies_too_long >= 4);
}

impl T {
    /// Whether `n` is absent under `parent`: ENOENT, or a negative entry.
    fn absent(&mut self, parent: u64, n: &str) -> bool {
        let (e, body) = self.call(Opcode::Lookup, parent, &[&name(n)]);
        e == -Errno::ENOENT.get() || (e == 0 && u64_at(&body, 0) == 0)
    }
}

#[test]
fn test_every_request_with_buffers_gets_exactly_one_reply() {
    let mut t = T::new();
    // A FORGET sent with buffers: an empty reply, so the VMM stops waiting.
    assert_eq!(t.raw(Opcode::Forget, ROOT, &[&le64(1)], 64), Some(Vec::new()));
    // Bytes that are no request: an error reply, with unique 0 when there is
    // no header.
    let reply = t.s.handle(b"short", 64).unwrap();
    assert_eq!(u32_at(&reply, 0), 16);
    assert_eq!(u64_at(&reply, 8), 0);
    assert_eq!(t.s.handle(b"short", 0), None);
    // An unknown opcode: ENOSYS with its unique.
    let bytes = request(9999, 77, ROOT, (0, 0), &[]);
    let reply = t.s.handle(&bytes, 64).unwrap();
    assert_eq!(split(&reply, 77).0, -Errno::ENOSYS.get());
    assert_eq!(t.s.counters().requests_refused, 2 + 1);
}

#[test]
fn test_locks_and_interrupt_are_answered_at_once() {
    let mut t = T::new();
    let (f, fh) = t.create(ROOT, "f", 0o644);
    let lk = [&le64(fh)[..], &le64(1), &le64(0), &le64(u64::MAX), &le32(1), &le32(1), &le32(0), &le32(0)].concat();
    for op in [Opcode::Getlk, Opcode::Setlk, Opcode::Setlkw] {
        assert_eq!(t.err(op, f, &[&lk]), Errno::ENOSYS, "{op:?}");
    }
    assert_eq!(t.err(Opcode::Interrupt, 0, &[&le64(1)]), Errno::ENOSYS);
    assert_eq!(t.err(Opcode::Bmap, f, &[&[0; 16]]), Errno::ENOSYS);
    // Interrupting a request that was answered changes nothing.
    t.write(f, fh, 0, b"x").unwrap();
}

#[test]
fn test_node_and_handle_limits_are_enfile_and_emfile_and_counted() {
    let mut t = T::with(Config {
        limits: Limits {
            max_nodes: 3,
            max_handles: 2,
            ..Limits::default()
        },
        ..Config::default()
    });
    let a = t.mkdir(ROOT, "a", 0o755);
    t.mkdir(ROOT, "b", 0o755);
    assert_eq!(t.err(Opcode::Mkdir, ROOT, &[&le32(0o755), &le32(0), &name("c")]), Errno::ENFILE);
    assert!(t.absent(ROOT, "c"), "refused before the backend made it");
    assert_eq!(t.s.counters().nodes_refused, 1);
    // Held nodes can still be looked up.
    assert_eq!(u64_at(&t.lookup(ROOT, "a"), 0), a);
    // Handles.
    t.ok(Opcode::Opendir, ROOT, &[&[0; 8]]);
    t.ok(Opcode::Opendir, a, &[&[0; 8]]);
    assert_eq!(t.err(Opcode::Opendir, ROOT, &[&[0; 8]]), Errno::EMFILE);
    assert_eq!(t.s.counters().handles_refused, 1);
    assert_eq!(t.s.dir().open_count(), 2, "refused before the backend opened");
}

#[test]
fn test_byte_budget_is_enospc_counted_and_shown_in_statfs() {
    let mut t = T::with(Config {
        limits: Limits {
            max_bytes: 10_000,
            ..Limits::default()
        },
        ..Config::default()
    });
    let (f, fh) = t.create(ROOT, "f", 0o644);
    assert_eq!(t.write(f, fh, 0, &[1; 6000]), Ok(6000));
    // Rewriting what is there costs nothing; growing past the budget is
    // refused and writes nothing.
    assert_eq!(t.write(f, fh, 0, &[2; 6000]), Ok(6000));
    assert_eq!(t.write(f, fh, 6000, &[3; 5000]), Err(Errno::ENOSPC));
    assert_eq!(u64_at(&t.getattr(f), A_SIZE), 6000);
    assert_eq!(t.s.bytes_added(), 6000);
    assert_eq!(t.s.counters().bytes_refused, 1);
    // A truncation up is charged, down refunded.
    assert_eq!(t.setattr(f, FATTR_SIZE, 20_000, 0, 0, 0).0, -Errno::ENOSPC.get());
    assert_eq!(t.setattr(f, FATTR_SIZE, 1000, 0, 0, 0).0, 0);
    assert_eq!(t.s.bytes_added(), 1000);
    // statfs shows what is left: 9000 bytes, 2 blocks of 4 KiB.
    let st = t.ok(Opcode::Statfs, ROOT, &[]);
    assert_eq!((u64_at(&st, 8), u64_at(&st, 16)), (2, 2));
    // Unlinking the last name gives the bytes back.
    t.release(f, fh);
    t.ok(Opcode::Unlink, ROOT, &[&name("f")]);
    assert_eq!(t.s.bytes_added(), 0);
    // A symlink's target is charged.
    t.ok(Opcode::Symlink, ROOT, &[&name("l"), &name("target")]);
    assert_eq!(t.s.bytes_added(), 6);
}

#[test]
fn test_cache_modes_reach_entries_opens_and_negative_lookups() {
    for (cache, valid, file_flags, dir_flags, negative) in [
        (CacheMode::Never, 0, FOPEN_DIRECT_IO, 0, false),
        (CacheMode::default(), 1, 0, 0, true),
        (CacheMode::Always { timeout_ms: 5000 }, 5, FOPEN_KEEP_CACHE, FOPEN_CACHE_DIR, true),
    ] {
        let mut t = T::with(Config {
            cache,
            ..Config::default()
        });
        let (f, fh) = t.create(ROOT, "f", 0o644);
        t.release(f, fh);
        let e = t.lookup(ROOT, "f");
        assert_eq!((u64_at(&e, 16), u64_at(&e, 24)), (valid, valid), "{cache:?}");
        assert_eq!(t.open(f, 0).unwrap().1, file_flags, "{cache:?}");
        let d = t.ok(Opcode::Opendir, ROOT, &[&[0; 8]]);
        assert_eq!(u32_at(&d, 8), dir_flags, "{cache:?}");
        let (e, body) = t.call(Opcode::Lookup, ROOT, &[&name("missing")]);
        if negative {
            assert_eq!((e, u64_at(&body, 0), u64_at(&body, 16)), (0, 0, valid));
        } else {
            assert_eq!(e, -Errno::ENOENT.get());
        }
    }
}

#[test]
fn test_metadata_lives_in_the_record() {
    let mut t = T::new();
    // A character device: emulated, a regular file on the host.
    let args = [&le32(0o020_660)[..], &le32(record::encode_dev(4, 64)), &le32(0), &le32(0)].concat();
    let e = t.ok(Opcode::Mknod, ROOT, &[&args, &name("tty")]);
    let a = &e[ATTR_IN_ENTRY..];
    assert_eq!(u32_at(a, A_MODE), 0o020_660);
    assert_eq!(u32_at(a, A_RDEV), record::encode_dev(4, 64));
    assert_eq!((u32_at(a, A_UID), u32_at(a, A_GID)), (UID, GID), "the caller owns it");
    let dev = u64_at(&e, 0);
    assert_eq!(t.open(dev, 2), Err(Errno::EACCES), "never opened on the host");
    // chmod with setuid and chown: in the record; the host keeps 0o777 at
    // most.
    let (f, fh) = t.create(ROOT, "f", 0o644);
    t.release(f, fh);
    let (e, out) = t.setattr(f, FATTR_MODE | FATTR_UID | FATTR_GID, 0, 0o104_755, 0, 0);
    assert_eq!(e, 0);
    let a = &out[ATTR_IN_ATTR_OUT..];
    assert_eq!((u32_at(a, A_MODE), u32_at(a, A_UID), u32_at(a, A_GID)), (0o104_755, 0, 0));
    let (_, host) = t.s.dir().lookup(&1, Name::new(b"f").unwrap()).unwrap();
    assert_eq!(host.perm, 0o755);
    // A mode change keeps the type.
    let (_, out) = t.setattr(dev, FATTR_MODE, 0, 0o100_600, 0, 0);
    assert_eq!(u32_at(&out[ATTR_IN_ATTR_OUT..], A_MODE), 0o020_600);
    // A symlink: a regular file with the target as content.
    let e = t.ok(Opcode::Symlink, ROOT, &[&name("l"), &name("/etc/passwd")]);
    let l = u64_at(&e, 0);
    assert_eq!(u32_at(&e[ATTR_IN_ENTRY..], A_MODE), 0o120_777);
    assert_eq!(t.ok(Opcode::Readlink, l, &[]), b"/etc/passwd");
    assert_eq!(t.open(l, 0), Err(Errno::ELOOP));
    // A setgid directory hands its group and setgid on.
    let d = t.mkdir(ROOT, "d", 0o2775);
    t.setattr(d, FATTR_GID, 0, 0, 0, 55);
    let e = t.ok(Opcode::Mkdir, d, &[&le32(0o755), &le32(0), &name("sub")]);
    let a = &e[ATTR_IN_ENTRY..];
    assert_eq!((u32_at(a, A_MODE), u32_at(a, A_GID)), (0o042_755, 55));
}

#[test]
fn test_a_malformed_record_is_eio_and_counted() {
    let mut t = T::new();
    let (f, fh) = t.create(ROOT, "f", 0o644);
    t.release(f, fh);
    // MemDir object 2 is the file.
    t.s.dir().put_raw_record(2, b"not a record").unwrap();
    assert_eq!(t.err(Opcode::Getattr, f, &[&[0; 16]]), Errno::EIO);
    // A directory's type on a regular file.
    let r = Record {
        mode: Some(S_IFDIR | 0o755),
        ..Record::default()
    };
    t.s.dir().put_raw_record(2, &r.encode()).unwrap();
    assert_eq!(t.err(Opcode::Getattr, f, &[&[0; 16]]), Errno::EIO);
    assert_eq!(t.s.counters().records_refused, 2);
}

#[test]
fn test_a_read_only_share_refuses_every_change() {
    let mut t = T::with(Config {
        read_only: true,
        ..Config::default()
    });
    let args = [&le32(0o755)[..], &le32(0)].concat();
    assert_eq!(t.err(Opcode::Mkdir, ROOT, &[&args, &name("d")]), Errno::EROFS);
    let create = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
    assert_eq!(t.err(Opcode::Create, ROOT, &[&create, &name("f")]), Errno::EROFS);
    assert_eq!(t.err(Opcode::Symlink, ROOT, &[&name("l"), &name("t")]), Errno::EROFS);
    assert_eq!(t.err(Opcode::Unlink, ROOT, &[&name("x")]), Errno::EROFS);
    assert_eq!(t.setattr(ROOT, FATTR_MODE, 0, 0o700, 0, 0).0, -Errno::EROFS.get());
    let set = [&le32(1)[..], &le32(0), b"user.a\0", b"x"].concat();
    assert_eq!(t.err(Opcode::Setxattr, ROOT, &[&set]), Errno::EROFS);
    // Reading is fine.
    t.getattr(ROOT);
    t.ok(Opcode::Opendir, ROOT, &[&[0; 8]]);
}

#[test]
fn test_readdir_lists_dot_dotdot_and_names_and_skips_what_is_no_name() {
    let mut t = T::new();
    t.mkdir(ROOT, "a", 0o755);
    let (f, fh) = t.create(ROOT, "b", 0o644);
    t.release(f, fh);
    t.s.dir().add_raw_name(1, "x/y").unwrap();
    t.s.dir().add_raw_name(1, "..").unwrap();
    t.s.dir().add_host_object(1, "link", Some(b"/etc")).unwrap();
    let dfh = u64_at(&t.ok(Opcode::Opendir, ROOT, &[&[0; 8]]), 0);
    let names = |data: &[u8], plus: bool| {
        let mut out = Vec::new();
        let mut at = 0;
        let skip = if plus { ENTRY_OUT_LEN } else { 0 };
        while at < data.len() {
            let d = &data[at + skip..];
            let len = u32_at(d, 16) as usize;
            out.push((String::from_utf8(d[24..24 + len].to_vec()).unwrap(), u64_at(d, 8), u32_at(d, 20)));
            at += skip + 24 + len.div_ceil(8) * 8;
        }
        out
    };
    let all = t.ok(Opcode::Readdir, ROOT, &[&T::read_in(dfh, 0, 4096)]);
    let got = names(&all, false);
    let listed: Vec<&str> = got.iter().map(|(n, _, _)| n.as_str()).collect();
    assert_eq!(listed, [".", "..", "a", "b", "link"]);
    assert_eq!(got[2].2, 4, "a is DT_DIR");
    assert_eq!(got[4].2, 10, "link is DT_LNK");
    assert_eq!(t.s.counters().names_skipped, 2);
    // Continuing from each entry's offset gives the rest.
    let after_a = got[2].1;
    let rest = names(&t.ok(Opcode::Readdir, ROOT, &[&T::read_in(dfh, after_a, 4096)]), false);
    let rest: Vec<&str> = rest.iter().map(|(n, _, _)| n.as_str()).collect();
    assert_eq!(rest, ["b", "link"]);
    // READDIRPLUS: a lookup counted for each named entry, none for . and ..
    let plus = t.ok(Opcode::Readdirplus, ROOT, &[&T::read_in(dfh, 0, 4096)]);
    let got = names(&plus, true);
    assert_eq!(got.len(), 5);
    assert_eq!(u64_at(&plus, 0), 0, "`.` hands out no node");
    let a = u64_at(&t.lookup(ROOT, "a"), 0);
    assert_eq!(t.s.node_counts(a), Some((3, 0)), "mkdir, readdirplus, lookup");
    // A host symlink is shown, never opened; it reads its target.
    let link = u64_at(&t.lookup(ROOT, "link"), 0);
    assert_eq!(t.open(link, 0), Err(Errno::ELOOP));
    assert_eq!(t.ok(Opcode::Readlink, link, &[]), b"/etc");
    t.s.dir().add_host_object(1, "fifo", None).unwrap();
    let fifo = u64_at(&t.lookup(ROOT, "fifo"), 0);
    assert_eq!(t.open(fifo, 0), Err(Errno::EACCES));
}

/// RENAME2's arguments: the new parent, the flags and padding.
fn rn(newdir: u64, flags: u32) -> Vec<u8> {
    [&le64(newdir)[..], &le32(flags), &le32(0)].concat()
}

#[test]
fn test_rename_moves_held_nodes_and_refuses_whiteout() {
    let mut t = T::new();
    let a = t.mkdir(ROOT, "a", 0o755);
    let b = t.mkdir(ROOT, "b", 0o755);
    let (f, fh) = t.create(a, "f", 0o644);
    t.write(f, fh, 0, b"x").unwrap();
    t.ok(Opcode::Rename2, a, &[&rn(b, 0), &name("f"), &name("g")]);
    assert!(t.absent(a, "f"));
    assert_eq!(u64_at(&t.lookup(b, "g"), 0), f, "the same node, moved");
    t.getattr(f);
    // WHITEOUT on every host; NOREPLACE with EXCHANGE, or with WHITEOUT;
    // an unknown bit.
    for flags in [4, 3, 6, 5, 8, 1 << 31] {
        assert_eq!(t.err(Opcode::Rename2, b, &[&rn(a, flags), &name("g"), &name("h")]), Errno::EINVAL);
    }
    assert!(t.absent(a, "h"));
    let (g2, fh2) = t.create(b, "h", 0o644);
    t.release(g2, fh2);
    assert_eq!(t.err(Opcode::Rename2, b, &[&rn(b, 1), &name("g"), &name("h")]), Errno::EEXIST);
    // Onto its own name: done with plain RENAME, EEXIST with NOREPLACE.
    assert_eq!(t.err(Opcode::Rename2, b, &[&rn(b, 1), &name("g"), &name("g")]), Errno::EEXIST);
    t.ok(Opcode::Rename2, b, &[&rn(b, 0), &name("g"), &name("g")]);
    // LINK hands the same node out once more.
    let e = t.ok(Opcode::Link, a, &[&le64(f), &name("again")]);
    assert_eq!(u64_at(&e, 0), f);
    assert_eq!(u32_at(&e[ATTR_IN_ENTRY..], 64), 2, "nlink");
    assert_eq!(t.err(Opcode::Link, a, &[&le64(b), &name("dirlink")]), Errno::EPERM);
    // One object's two names: the rename succeeds and changes nothing.
    t.ok(Opcode::Rename2, a, &[&rn(b, 0), &name("again"), &name("g")]);
    assert_eq!(u64_at(&t.lookup(a, "again"), 0), f);
    assert_eq!(u32_at(&t.getattr(f), 64), 2, "nlink");
    // A directory beneath itself is EINVAL; onto an ancestor of its old
    // parent, ENOTEMPTY.
    let c = t.mkdir(a, "c", 0o755);
    assert_eq!(t.err(Opcode::Rename2, ROOT, &[&rn(c, 0), &name("a"), &name("x")]), Errno::EINVAL);
    let d = t.mkdir(c, "d", 0o755);
    assert_eq!(t.err(Opcode::Rename2, c, &[&rn(ROOT, 0), &name("d"), &name("a")]), Errno::ENOTEMPTY);
    t.getattr(d);
}

#[test]
fn test_rename_exchange_swaps_names_and_held_nodes() {
    let mut t = T::with(Config {
        limits: Limits {
            max_bytes: 10,
            ..Limits::default()
        },
        ..Config::default()
    });
    let a = t.mkdir(ROOT, "a", 0o755);
    let b = t.mkdir(ROOT, "b", 0o755);
    let (f, fh) = t.create(a, "f", 0o644);
    t.write(f, fh, 0, b"fffff").unwrap();
    t.release(f, fh);
    let (g, gh) = t.create(b, "g", 0o644);
    t.write(g, gh, 0, b"ggggg").unwrap();
    t.release(g, gh);
    let sub = t.mkdir(b, "sub", 0o755);
    let (x, xh) = t.create(sub, "x", 0o644);
    t.release(x, xh);
    // Two files: each name now holds the other, and nothing left the
    // budget (no file was replaced).
    t.ok(Opcode::Rename2, a, &[&rn(b, 2), &name("f"), &name("g")]);
    assert_eq!(u64_at(&t.lookup(a, "f"), 0), g);
    assert_eq!(u64_at(&t.lookup(b, "g"), 0), f);
    let (h, hh) = t.create(ROOT, "h", 0o644);
    assert_eq!(t.write(h, hh, 0, b"h"), Err(Errno::ENOSPC));
    t.release(h, hh);
    // A file and a directory may be exchanged; the held directory's
    // parent follows it (the session's own check runs after each request).
    t.ok(Opcode::Rename2, a, &[&rn(b, 2), &name("f"), &name("sub")]);
    assert_eq!(u64_at(&t.lookup(a, "f"), 0), sub);
    assert_eq!(u64_at(&t.lookup(b, "sub"), 0), g);
    assert_eq!(u64_at(&t.lookup(sub, "x"), 0), x);
    assert_eq!(u32_at(&t.getattr(sub), A_MODE) & 0o170_000, 0o040_000);
    // Either name missing is ENOENT; a directory exchanged with an
    // ancestor of its parent, or into itself, is EINVAL.
    assert_eq!(t.err(Opcode::Rename2, a, &[&rn(b, 2), &name("f"), &name("none")]), Errno::ENOENT);
    assert_eq!(t.err(Opcode::Rename2, a, &[&rn(b, 2), &name("none"), &name("g")]), Errno::ENOENT);
    assert_eq!(t.err(Opcode::Rename2, sub, &[&rn(ROOT, 2), &name("x"), &name("a")]), Errno::EINVAL);
    assert_eq!(t.err(Opcode::Rename2, a, &[&rn(sub, 2), &name("f"), &name("x")]), Errno::EINVAL);
    // An object exchanged with itself: done, nothing changed.
    t.ok(Opcode::Rename2, b, &[&rn(b, 2), &name("g"), &name("g")]);
    assert_eq!(u64_at(&t.lookup(b, "g"), 0), f);
}

#[test]
fn test_rename_exchange_is_einval_where_the_backend_refuses_it() {
    // MemDir::without_exchange stands for the Windows backend: NTFS has no
    // atomic exchange (docs/design-fs.md §4.3).
    let mut t = T::over(MemDir::without_exchange(), Config::default());
    let (f, fh) = t.create(ROOT, "f", 0o644);
    t.release(f, fh);
    let (g, gh) = t.create(ROOT, "g", 0o644);
    t.release(g, gh);
    assert_eq!(t.err(Opcode::Rename2, ROOT, &[&rn(ROOT, 2), &name("f"), &name("g")]), Errno::EINVAL);
    assert_eq!(u64_at(&t.lookup(ROOT, "f"), 0), f, "nothing moved");
    assert_eq!(u64_at(&t.lookup(ROOT, "g"), 0), g);
    // NOREPLACE and plain renames still go through.
    assert_eq!(t.err(Opcode::Rename2, ROOT, &[&rn(ROOT, 1), &name("f"), &name("g")]), Errno::EEXIST);
    t.ok(Opcode::Rename2, ROOT, &[&rn(ROOT, 1), &name("f"), &name("h")]);
    assert_eq!(u64_at(&t.lookup(ROOT, "h"), 0), f);
}

#[test]
fn test_guest_xattrs_have_a_budget_and_no_system_namespace() {
    let mut t = T::with(Config {
        limits: Limits {
            xattr_budget: 100,
            ..Limits::default()
        },
        ..Config::default()
    });
    let (f, fh) = t.create(ROOT, "f", 0o644);
    t.release(f, fh);
    let set = |flags: u32, n: &[u8], v: &[u8]| {
        [&le32(u32::try_from(v.len()).unwrap())[..], &le32(flags), n, b"\0", v].concat()
    };
    t.ok(Opcode::Setxattr, f, &[&set(0, b"user.a", &[1; 40])]);
    t.ok(Opcode::Setxattr, f, &[&set(0, b"security.selinux", b"ctx")]);
    // 4 + 6 + 40, 4 + 16 + 3: 73 of 100; 30 more bytes are over.
    assert_eq!(t.err(Opcode::Setxattr, f, &[&set(0, b"user.b", &[0; 30])]), Errno::ENOSPC);
    assert_eq!(t.s.counters().xattr_refused, 1);
    // Replacing a value counts the new one only.
    t.ok(Opcode::Setxattr, f, &[&set(0, b"user.a", &[2; 50])]);
    assert_eq!(t.err(Opcode::Setxattr, f, &[&set(1, b"user.a", b"x")]), Errno::EEXIST);
    assert_eq!(t.err(Opcode::Setxattr, f, &[&set(2, b"user.z", b"x")]), Errno::ENODATA);
    assert_eq!(t.err(Opcode::Setxattr, f, &[&set(3, b"user.z", b"x")]), Errno::EINVAL);
    for n in [&b"system.posix_acl_access"[..], b"system.x"] {
        assert_eq!(t.err(Opcode::Setxattr, f, &[&set(0, n, b"x")]), Errno::EOPNOTSUPP);
    }
    t.ok(Opcode::Removexattr, f, &[b"user.a\0"]);
    assert_eq!(t.err(Opcode::Removexattr, f, &[b"user.a\0"]), Errno::ENODATA);
    let get = [&le32(100)[..], &le32(0), b"user.a\0"].concat();
    assert_eq!(t.err(Opcode::Getxattr, f, &[&get]), Errno::ENODATA);
}
