// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `wick_fsd::session`, the server core, over the in-memory directory
//! (`MemDir`), driven by a sequence of requests: built FUSE requests on the
//! node ids and handles the session handed out (and on ids it never did),
//! with any arguments and any reply buffer size, and byte strings the
//! decoder refuses. Small limits, so the node, handle, byte and attribute
//! limits are reached.
//!
//! After every request:
//! - a reply frame exists exactly when the request had buffers, and fits
//!   them; a reply of a header or more carries its own length and the
//!   request's unique, and an error reply is the header alone;
//! - the session's tables keep their rules (`Session::check`: every handle
//!   on a held node, every limit kept);
//! - each node's guest lookup count and open handles are what a model kept
//!   here from the replies says (a lookup counted only for a reply the
//!   guest got, a forget never below 0, a node kept while a handle is open
//!   and gone when neither holds it);
//! - the backend has exactly as many opens as the session has handles;
//! - every node the guest holds is reachable while its object lives: a
//!   GETATTR without a handle answers with the object's link count when it
//!   has a name (links, renames and unlinks of its other names never lose
//!   it) and, unlinked, while a handle of it is open.

#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fsd::cache::CacheMode;
use wick_fsd::fuse::Opcode;
use wick_fsd::fuse::decode::{Wire, decode};
use wick_fsd::fuse::encode::request;
use wick_fsd::limits::Limits;
use wick_fsd::memdir::MemDir;
use wick_fsd::session::{Config, Session};

const ROOT: u64 = 1;
const NAMES: &[&str] = &["a", "b", "c", "d", "e", "..", ".", "x/y", "\u{F03A}"];

#[derive(Arbitrary, Debug)]
enum Cap {
    Full,
    None,
    Small(u8),
    Any(u16),
}

#[derive(Arbitrary, Debug)]
struct Req {
    op: u8,
    node: u8,
    fh: u8,
    name: u8,
    name2: u8,
    a: u32,
    b: u32,
    off: u16,
    data: Vec<u8>,
    cap: Cap,
}

#[derive(Arbitrary, Debug)]
enum Step {
    Req(Req),
    Raw { bytes: Vec<u8>, cap: u16 },
}

#[derive(Arbitrary, Debug)]
struct Input {
    cache: u8,
    read_only: bool,
    steps: Vec<Step>,
}

const OPS: &[Opcode] = &[
    Opcode::Lookup,
    Opcode::Forget,
    Opcode::Getattr,
    Opcode::Setattr,
    Opcode::Readlink,
    Opcode::Symlink,
    Opcode::Mknod,
    Opcode::Mkdir,
    Opcode::Unlink,
    Opcode::Rmdir,
    Opcode::Rename2,
    Opcode::Link,
    Opcode::Open,
    Opcode::Read,
    Opcode::Write,
    Opcode::Statfs,
    Opcode::Release,
    Opcode::Fsync,
    Opcode::Flush,
    Opcode::Opendir,
    Opcode::Readdir,
    Opcode::Readdirplus,
    Opcode::Releasedir,
    Opcode::Access,
    Opcode::Create,
    Opcode::Fallocate,
    Opcode::Setxattr,
    Opcode::Getxattr,
    Opcode::Listxattr,
    Opcode::Removexattr,
    Opcode::BatchForget,
    Opcode::Setlkw,
    Opcode::Interrupt,
    Opcode::Init,
    Opcode::Destroy,
];

/// The model: per node, (lookups, handles); per fh, its node.
#[derive(Default)]
struct Model {
    nodes: BTreeMap<u64, (u64, u32)>,
    fhs: BTreeMap<u64, u64>,
}

impl Model {
    fn looked_up(&mut self, nodeid: u64) {
        if nodeid != 0 && nodeid != ROOT {
            self.nodes.entry(nodeid).or_default().0 += 1;
        }
    }

    fn forget(&mut self, nodeid: u64, n: u64) {
        if let Some(c) = self.nodes.get_mut(&nodeid) {
            c.0 = c.0.saturating_sub(n);
        }
        self.tidy(nodeid);
    }

    fn opened(&mut self, nodeid: u64, fh: u64) {
        self.fhs.insert(fh, nodeid);
        if nodeid != ROOT {
            self.nodes.entry(nodeid).or_default().1 += 1;
        }
    }

    fn released(&mut self, fh: u64) {
        if let Some(nodeid) = self.fhs.remove(&fh) {
            if let Some(c) = self.nodes.get_mut(&nodeid) {
                c.1 -= 1;
            }
            self.tidy(nodeid);
        }
    }

    fn tidy(&mut self, nodeid: u64) {
        if self.nodes.get(&nodeid) == Some(&(0, 0)) {
            self.nodes.remove(&nodeid);
        }
    }
}

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn cstr(s: &str) -> Vec<u8> {
    [s.as_bytes(), b"\0"].concat()
}

/// The arguments of a well-formed request for `op`.
fn args(op: Opcode, r: &Req, fh: u64, other: u64) -> Vec<u8> {
    let n1 = cstr(NAMES[usize::from(r.name) % NAMES.len()]);
    let n2 = cstr(NAMES[usize::from(r.name2) % NAMES.len()]);
    let off = u64::from(r.off) * 64;
    let data = &r.data[..r.data.len().min(8192)];
    let size = u32::try_from(data.len()).unwrap();
    let read_in = [&le64(fh)[..], &le64(off), &le32(r.a), &le32(0), &le64(0), &le32(0), &le32(0)].concat();
    match op {
        Opcode::Lookup | Opcode::Unlink | Opcode::Rmdir => n1,
        Opcode::Forget => le64(u64::from(r.a % 4)).to_vec(),
        Opcode::Getattr => [&le32(r.b & 1)[..], &le32(0), &le64(fh)].concat(),
        Opcode::Setattr => {
            let mut a = vec![0u8; 88];
            a[0..4].copy_from_slice(&le32(r.b & 0x1ff));
            a[8..16].copy_from_slice(&le64(fh));
            a[16..24].copy_from_slice(&le64(u64::from(r.a % 300_000)));
            a[68..72].copy_from_slice(&le32(r.a));
            a[76..80].copy_from_slice(&le32(r.b >> 16));
            a[80..84].copy_from_slice(&le32(r.b >> 8));
            a
        }
        Opcode::Readlink | Opcode::Statfs | Opcode::Destroy => Vec::new(),
        Opcode::Symlink => [n1, cstr("t/a/r/g/e/t")].concat(),
        Opcode::Mknod => [&le32(r.a)[..], &le32(r.b), &le32(0), &le32(0), &n1].concat(),
        Opcode::Mkdir => [&le32(r.a)[..], &le32(0), &n1].concat(),
        Opcode::Rename2 => [&le64(other)[..], &le32(r.b % 8), &le32(0), &n1, &n2].concat(),
        Opcode::Link => [&le64(other)[..], &n1].concat(),
        Opcode::Open | Opcode::Opendir => [&le32(r.a % 4)[..], &le32(0)].concat(),
        Opcode::Read | Opcode::Readdir | Opcode::Readdirplus => read_in,
        Opcode::Write => [&le64(fh)[..], &le64(off), &le32(size), &le32(0), &le64(0), &le32(0), &le32(0), data].concat(),
        Opcode::Release | Opcode::Releasedir => [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat(),
        Opcode::Fsync => [&le64(fh)[..], &le32(r.a & 1), &le32(0)].concat(),
        Opcode::Flush => [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat(),
        Opcode::Access => [&le32(r.a)[..], &le32(0)].concat(),
        Opcode::Create => [&le32(r.a % 4 | (r.b & 0o200))[..], &le32(r.b), &le32(0), &le32(0), &n1].concat(),
        Opcode::Fallocate => [&le64(fh)[..], &le64(off), &le64(u64::from(r.a % 100_000)), &le32(r.b % 4), &le32(0)].concat(),
        Opcode::Setxattr => {
            let value = &data[..data.len().min(300)];
            let len = u32::try_from(value.len()).unwrap();
            [&le32(len)[..], &le32(r.b % 4), b"user.", &n1, value].concat()
        }
        Opcode::Getxattr => [&le32(r.a % 512)[..], &le32(0), b"user.", &n1].concat(),
        Opcode::Listxattr => [&le32(r.a % 512)[..], &le32(0)].concat(),
        Opcode::Removexattr => [b"user.".as_slice(), &n1].concat(),
        Opcode::BatchForget => [&le32(2)[..], &le32(0), &le64(other), &le64(u64::from(r.a % 3)), &le64(fh), &le64(1)].concat(),
        Opcode::Setlkw => vec![0; 48],
        Opcode::Interrupt => le64(1).to_vec(),
        Opcode::Init => [&le32(7)[..], &le32(31 + r.a % 20), &le32(0), &le32(r.b), &[0u8; 48]].concat(),
        _ => Vec::new(),
    }
}

fn pick<T: Copy>(list: &[T], i: u8, fallback: T) -> T {
    if list.is_empty() {
        fallback
    } else {
        list[usize::from(i) % list.len()]
    }
}

fuzz_target!(|input: Input| {
    let cache = match input.cache % 3 {
        0 => CacheMode::Never,
        1 => CacheMode::default(),
        _ => CacheMode::Always { timeout_ms: 1000 },
    };
    let config = Config {
        cache,
        read_only: input.read_only,
        owner: (1000, 1000),
        limits: Limits {
            max_nodes: 12,
            max_held: 4,
            max_handles: 4,
            max_bytes: 256 << 10,
            xattr_budget: 256,
        },
    };
    let mut s = Session::new(MemDir::new(), config).unwrap();
    let mut model = Model::default();
    let mut unique = 0u64;
    let init = request(Opcode::Init as u32, 1, 0, (0, 0), &[&args(Opcode::Init, &Req::default_init(), 0, 0)]);
    assert!(s.handle(&init, 1024).is_some());

    for step in input.steps.iter().take(64) {
        unique += 2;
        let (bytes, cap, built) = match step {
            Step::Raw { bytes, cap } => {
                // Only bytes the decoder refuses: a valid request is the
                // built steps' to make, so the model knows what it did.
                if decode(bytes, &Wire::default()).is_ok() {
                    continue;
                }
                (bytes.clone(), usize::from(*cap), None)
            }
            Step::Req(r) => {
                let op = OPS[usize::from(r.op) % OPS.len()];
                let mut known: Vec<u64> = model.nodes.keys().copied().collect();
                known.push(ROOT);
                let node = if r.node >= 250 { u64::from(r.node) } else { pick(&known, r.node, ROOT) };
                let other = pick(&known, r.name2.wrapping_add(r.node), ROOT);
                let fhs: Vec<u64> = model.fhs.keys().copied().collect();
                let fh = if r.fh >= 250 { u64::from(r.fh) } else { pick(&fhs, r.fh, 1) };
                let cap = match r.cap {
                    Cap::Full => 1 << 20,
                    Cap::None => 0,
                    Cap::Small(n) => usize::from(n),
                    Cap::Any(n) => usize::from(n),
                };
                let a = args(op, r, fh, other);
                (request(op as u32, unique, node, (r.a, r.b), &[&a]), cap, Some((op, node, fh, other, r.a)))
            }
        };
        let reply = s.handle(&bytes, cap);
        assert_eq!(reply.is_some(), cap > 0);
        let reply = reply.unwrap_or_default();
        assert!(reply.len() <= cap);
        let mut ok_body: Option<&[u8]> = None;
        if reply.len() >= 16 {
            let len = u32::from_le_bytes(reply[0..4].try_into().unwrap()) as usize;
            let error = i32::from_le_bytes(reply[4..8].try_into().unwrap());
            assert_eq!(len, reply.len());
            assert!(error <= 0);
            if error < 0 {
                assert_eq!(len, 16);
            }
            if built.is_some() {
                assert_eq!(u64::from_le_bytes(reply[8..16].try_into().unwrap()), unique);
                if error == 0 {
                    ok_body = Some(&reply[16..]);
                }
            }
        }
        if let Some((op, node, fh, other, a)) = built {
            match (op, ok_body) {
                (Opcode::Forget, _) if !s.destroyed() => model.forget(node, u64::from(a % 4)),
                (Opcode::BatchForget, _) if !s.destroyed() => {
                    model.forget(other, u64::from(a % 3));
                    model.forget(fh, 1);
                }
                (Opcode::Lookup | Opcode::Mknod | Opcode::Mkdir | Opcode::Symlink | Opcode::Link, Some(b)) => {
                    model.looked_up(u64_at(b, 0));
                }
                (Opcode::Create, Some(b)) => {
                    let nodeid = u64_at(b, 0);
                    model.looked_up(nodeid);
                    model.opened(nodeid, u64_at(b, 128));
                }
                (Opcode::Open | Opcode::Opendir, Some(b)) => model.opened(node, u64_at(b, 0)),
                (Opcode::Release | Opcode::Releasedir, Some(_)) => model.released(fh),
                (Opcode::Readdirplus, Some(b)) => {
                    let mut at = 0;
                    while at + 152 <= b.len() {
                        model.looked_up(u64_at(b, at));
                        let namelen = u32::from_le_bytes(b[at + 144..at + 148].try_into().unwrap()) as usize;
                        at += 152 + namelen.div_ceil(8) * 8;
                    }
                }
                (Opcode::Destroy, Some(_)) => model = Model::default(),
                _ => {}
            }
        }
        if let Err(e) = s.check() {
            panic!("{e}");
        }
        for (&nodeid, &counts) in &model.nodes {
            assert_eq!(s.node_counts(nodeid), Some(counts), "node {nodeid}");
        }
        assert_eq!(s.dir().open_count(), u64::try_from(s.handles_open()).unwrap());
        assert_eq!(model.fhs.len(), s.handles_open());
        assert_eq!(s.nodes(), model.nodes.len() + 1, "nodes held beyond the model's");
        if !s.destroyed() {
            for (&nodeid, &(_, handles)) in &model.nodes {
                let Some(id) = s.node_host_id(nodeid) else { continue };
                let nlink = s.dir().nlink(id);
                unique += 2;
                let probe = request(Opcode::Getattr as u32, unique, nodeid, (0, 0), &[&[0u8; 16]]);
                let r = s.handle(&probe, 1 << 12).unwrap();
                let error = i32::from_le_bytes(r[4..8].try_into().unwrap());
                if nlink.is_some_and(|n| n > 0) || handles > 0 {
                    assert_eq!(error, 0, "node {nodeid} (nlink {nlink:?}, {handles} handles) lost");
                    let shown = u32::from_le_bytes(r[16 + 16 + 64..16 + 16 + 68].try_into().unwrap());
                    assert_eq!(Some(shown), nlink, "node {nodeid}'s link count");
                }
            }
        }
    }
});

impl Req {
    fn default_init() -> Req {
        Req {
            op: 0,
            node: 0,
            fh: 0,
            name: 0,
            name2: 0,
            a: 16,
            b: u32::MAX,
            off: 0,
            data: Vec::new(),
            cap: Cap::Full,
        }
    }
}
