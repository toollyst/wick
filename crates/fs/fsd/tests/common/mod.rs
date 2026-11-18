// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The host-backend tests' harness: a session over a real host directory
//! (`share`), with canaries in a sibling directory (`outside`) that no
//! request may reach, spoken to in FUSE requests as a guest would.

#![allow(dead_code)]

pub mod drive;
#[cfg(target_os = "linux")]
pub mod remote;

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use wick_fs_sys as sys;
use wick_fsd::dir::ConfinedDir;
use wick_fsd::fuse::encode::request;
use wick_fsd::fuse::{Errno, Opcode};
use wick_fsd::host::unix::{HostDir, Options};
use wick_fsd::session::{Config, Session};

pub const ROOT: u64 = 1;
pub const CAP: usize = 1 << 21;
pub const UID: u32 = 1000;
pub const GID: u32 = 1000;
/// fuse_attr's offsets inside an entry_out and an attr_out.
pub const ATTR_IN_ENTRY: usize = 40;
pub const ATTR_IN_ATTR_OUT: usize = 16;
pub const A_SIZE: usize = 8;
pub const A_MODE: usize = 60;
pub const A_NLINK: usize = 64;

pub fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

pub fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

pub fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

pub fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A name as FUSE carries it: its bytes and a NUL.
pub fn name(n: &[u8]) -> Vec<u8> {
    [n, b"\0"].concat()
}

/// A fresh directory for one test: `<tmp>/wick-fsd-<tag>-<pid>`.
pub fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("wick-fsd-{tag}-{}", std::process::id()));
    remove(&p);
    std::fs::create_dir_all(&p).unwrap();
    std::fs::canonicalize(&p).unwrap()
}

/// Removes a test's tree, giving back the permissions a test took away.
pub fn remove(p: &Path) {
    if !p.exists() {
        return;
    }
    let _ = std::process::Command::new("chmod").args(["-R", "u+rwx"]).arg(p).status();
    let _ = std::fs::remove_dir_all(p);
}

/// A snapshot of a directory tree: each path's kind, size, mtime and
/// content (files), to compare before and after.
pub fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, u64, i64, i64, Vec<u8>)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let m = std::fs::symlink_metadata(&p).unwrap();
        let data = if m.file_type().is_file() {
            std::fs::read(&p).unwrap()
        } else if m.file_type().is_symlink() {
            std::fs::read_link(&p).unwrap().into_os_string().into_encoded_bytes()
        } else {
            Vec::new()
        };
        out.insert(p.clone(), (m.mode(), m.size(), m.mtime(), m.mtime_nsec(), data));
        if m.file_type().is_dir() {
            for e in std::fs::read_dir(&p).unwrap() {
                stack.push(e.unwrap().path());
            }
        }
    }
    out
}

/// How the harness reaches a server: a session in this process, or a
/// confined wick-fsd over its socket (`remote::Remote`).
pub trait Link {
    /// A FUSE request with `cap` bytes for the reply: the reply, if any.
    fn send(&mut self, req: &[u8], cap: usize) -> Option<Vec<u8>>;
    /// The server's layer-2/3 refusals so far, where the harness can see
    /// them (a remote server reports them when it ends).
    fn layer_refusals(&self) -> Option<u64> {
        None
    }
    /// Whether the server holds `nodeid`, where the harness can see it.
    fn node_held(&self, _nodeid: u64) -> Option<bool> {
        None
    }
}

impl<D: ConfinedDir> Link for Session<D> {
    fn send(&mut self, req: &[u8], cap: usize) -> Option<Vec<u8>> {
        let reply = self.handle(req, cap);
        self.check().unwrap();
        reply
    }

    fn layer_refusals(&self) -> Option<u64> {
        Some(self.counters().layer_refusals)
    }

    fn node_held(&self, nodeid: u64) -> Option<bool> {
        Some(self.node_counts(nodeid).is_some())
    }
}

/// A session over `<scratch>/share`, canaries in `<scratch>/outside`.
pub struct H<L: Link = Session<HostDir>> {
    pub s: L,
    pub base: PathBuf,
    pub share: PathBuf,
    pub outside: PathBuf,
    unique: u64,
    canaries: Canaries,
}

/// A snapshot of the canaries.
pub type Canaries = BTreeMap<PathBuf, (u32, u64, i64, i64, Vec<u8>)>;

/// `<scratch>/share` and `<scratch>/outside` with its canaries.
pub fn share_and_outside(tag: &str, prepare: impl FnOnce(&Path)) -> (PathBuf, PathBuf, PathBuf) {
    let base = scratch(tag);
    let share = base.join("share");
    let outside = base.join("outside");
    std::fs::create_dir(&share).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret"), b"canary").unwrap();
    std::fs::create_dir(outside.join("dir")).unwrap();
    std::fs::write(outside.join("dir").join("inner"), b"canary 2").unwrap();
    prepare(&share);
    (base, share, outside)
}

/// FUSE_INIT's arguments: 7.47, 1 MiB readahead, every flag offered.
pub fn init_args() -> Vec<u8> {
    [&le32(7)[..], &le32(47), &le32(1 << 20), &le32(u32::MAX), &[0; 48]].concat()
}

impl H {
    pub fn new(tag: &str) -> H {
        H::with(tag, Config::default(), |_| {})
    }

    /// A session with `config`; `prepare` fills the share first.
    pub fn with(tag: &str, config: Config, prepare: impl FnOnce(&Path)) -> H {
        let (base, share, outside) = share_and_outside(tag, prepare);
        let canaries = snapshot(&outside);
        let root = sys::open_root(&share).unwrap();
        // The test volumes of macOS fold case; the backend then checks every
        // name it finds (which is what these tests exercise there).
        let options = Options {
            case_insensitive_ok: true,
            max_held: config.limits.max_held,
        };
        let dir = HostDir::new(root, options).unwrap();
        let config = Config {
            owner: (UID, GID),
            ..config
        };
        H::over(Session::new(dir, config).unwrap(), base, share, outside, canaries)
    }
}

impl<L: Link> H<L> {
    /// A harness over `link`, INIT done.
    pub fn over(link: L, base: PathBuf, share: PathBuf, outside: PathBuf, canaries: Canaries) -> H<L> {
        let mut h = H {
            s: link,
            base,
            share,
            outside,
            unique: 0,
            canaries,
        };
        h.ok(Opcode::Init, 0, &[&init_args()]);
        h
    }

    /// The raw reply, if any.
    pub fn raw(&mut self, op: u32, nodeid: u64, args: &[&[u8]], cap: usize) -> Option<Vec<u8>> {
        self.unique += 2;
        let bytes = request(op, self.unique, nodeid, (UID, GID), args);
        self.s.send(&bytes, cap)
    }

    /// (error, body) of a request.
    pub fn call(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> (i32, Vec<u8>) {
        let reply = self.raw(op as u32, nodeid, args, CAP).unwrap();
        assert_eq!(u64_at(&reply, 8), self.unique);
        (i32::from_le_bytes(reply[4..8].try_into().unwrap()), reply[16..].to_vec())
    }

    pub fn ok(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> Vec<u8> {
        let (e, body) = self.call(op, nodeid, args);
        assert_eq!(e, 0, "{op:?} on {nodeid}: {:?}", errno(e));
        body
    }

    pub fn err(&mut self, op: Opcode, nodeid: u64, args: &[&[u8]]) -> Errno {
        let (e, _) = self.call(op, nodeid, args);
        assert!(e < 0, "{op:?} on {nodeid} succeeded");
        errno(e)
    }

    /// LOOKUP: the entry, or the error (a negative entry is ENOENT).
    pub fn lookup(&mut self, parent: u64, n: &[u8]) -> Result<Vec<u8>, Errno> {
        let (e, body) = self.call(Opcode::Lookup, parent, &[&name(n)]);
        if e < 0 {
            Err(errno(e))
        } else if u64_at(&body, 0) == 0 {
            Err(Errno::ENOENT)
        } else {
            Ok(body)
        }
    }

    pub fn mkdir(&mut self, parent: u64, n: &[u8]) -> u64 {
        u64_at(&self.ok(Opcode::Mkdir, parent, &[&le32(0o755), &le32(0), &name(n)]), 0)
    }

    /// CREATE (read-write): (node id, fh).
    pub fn create(&mut self, parent: u64, n: &[u8]) -> Result<(u64, u64), Errno> {
        let args = [&le32(2)[..], &le32(0o644), &le32(0), &le32(0)].concat();
        let (e, r) = self.call(Opcode::Create, parent, &[&args, &name(n)]);
        if e < 0 {
            return Err(errno(e));
        }
        Ok((u64_at(&r, 0), u64_at(&r, 40 + 88)))
    }

    pub fn open(&mut self, nodeid: u64, flags: u32) -> Result<u64, Errno> {
        let (e, r) = self.call(Opcode::Open, nodeid, &[&le32(flags), &le32(0)]);
        if e < 0 { Err(errno(e)) } else { Ok(u64_at(&r, 0)) }
    }

    pub fn write(&mut self, nodeid: u64, fh: u64, offset: u64, data: &[u8]) -> Result<u32, Errno> {
        let size = u32::try_from(data.len()).unwrap();
        let args = [&le64(fh)[..], &le64(offset), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
        let (e, r) = self.call(Opcode::Write, nodeid, &[&args, data]);
        if e < 0 { Err(errno(e)) } else { Ok(u32_at(&r, 0)) }
    }

    pub fn read(&mut self, nodeid: u64, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        let args = [&le64(fh)[..], &le64(offset), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
        let (e, r) = self.call(Opcode::Read, nodeid, &[&args]);
        if e < 0 { Err(errno(e)) } else { Ok(r) }
    }

    pub fn release(&mut self, nodeid: u64, fh: u64) {
        let args = [&le64(fh)[..], &le32(0), &le32(0), &le64(0)].concat();
        self.ok(Opcode::Release, nodeid, &[&args]);
    }

    pub fn getattr(&mut self, nodeid: u64) -> Result<Vec<u8>, Errno> {
        let (e, r) = self.call(Opcode::Getattr, nodeid, &[&[0; 16]]);
        if e < 0 { Err(errno(e)) } else { Ok(r[ATTR_IN_ATTR_OUT..].to_vec()) }
    }

    /// SETATTR of the mode.
    pub fn chmod(&mut self, nodeid: u64, mode: u32) -> Result<(), Errno> {
        let mut a = vec![0u8; 88];
        a[0..4].copy_from_slice(&le32(1));
        a[68..72].copy_from_slice(&le32(mode));
        let (e, _) = self.call(Opcode::Setattr, nodeid, &[&a]);
        if e < 0 { Err(errno(e)) } else { Ok(()) }
    }

    /// The guest names of a directory, READDIR from the start.
    pub fn list(&mut self, nodeid: u64) -> Vec<Vec<u8>> {
        let dfh = u64_at(&self.ok(Opcode::Opendir, nodeid, &[&[0; 8]]), 0);
        let mut names = Vec::new();
        let mut off = 0;
        loop {
            let args = [&le64(dfh)[..], &le64(off), &le32(65536), &le32(0), &le64(0), &le32(0), &[0; 4]].concat();
            let r = self.ok(Opcode::Readdir, nodeid, &[&args]);
            if r.is_empty() {
                break;
            }
            let mut at = 0;
            while at < r.len() {
                let namelen = usize::try_from(u32_at(&r, at + 16)).unwrap();
                off = u64_at(&r, at + 8);
                names.push(r[at + 24..at + 24 + namelen].to_vec());
                at += (24 + namelen).div_ceil(8) * 8;
            }
        }
        let args = [&le64(dfh)[..], &le32(0), &le32(0), &le64(0)].concat();
        self.ok(Opcode::Releasedir, nodeid, &[&args]);
        names.retain(|n| n != b"." && n != b"..");
        names
    }

    /// The canaries outside the share are as they were, and nothing was
    /// added there.
    pub fn canaries_untouched(&self) {
        assert_eq!(snapshot(&self.outside), self.canaries, "the directory outside the share changed");
    }
}

impl<L: Link> Drop for H<L> {
    fn drop(&mut self) {
        remove(&self.base);
    }
}

pub fn errno(e: i32) -> Errno {
    Errno::from_linux(-e).unwrap_or_else(|| panic!("errno {e} not Linux's"))
}

/// A disk image made and mounted for one test (macOS, no root:
/// `hdiutil create` / `attach -nobrowse`), detached when dropped.
#[cfg(target_os = "macos")]
pub struct Image {
    pub mount: PathBuf,
    dir: PathBuf,
}

#[cfg(target_os = "macos")]
impl Image {
    /// `fs` is hdiutil's file system name: `APFS`, `Case-sensitive APFS`,
    /// `MS-DOS`, `ExFAT`, `HFS+`.
    pub fn new(tag: &str, fs: &str) -> Image {
        let dir = scratch(&format!("img-{tag}"));
        let img = dir.join("i.dmg");
        let mount = dir.join("mnt");
        let ok = std::process::Command::new("hdiutil")
            .args(["create", "-quiet", "-size", "32m", "-fs", fs, "-volname", "wicktest"])
            .arg(&img)
            .status()
            .unwrap()
            .success();
        assert!(ok, "hdiutil create -fs {fs}");
        let ok = std::process::Command::new("hdiutil")
            .args(["attach", "-quiet", "-nobrowse", "-mountpoint"])
            .arg(&mount)
            .arg(&img)
            .status()
            .unwrap()
            .success();
        assert!(ok, "hdiutil attach");
        Image { mount, dir }
    }
}

#[cfg(target_os = "macos")]
impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::process::Command::new("hdiutil")
            .args(["detach", "-quiet", "-force"])
            .arg(&self.mount)
            .status();
        remove(&self.dir);
    }
}

/// A session straight over `dir` (no stage 0), with `options`.
pub fn session_over(dir: &Path, options: wick_fsd::host::unix::Options, config: Config) -> Result<Session<HostDir>, String> {
    let root = sys::open_root(dir).map_err(|e| format!("{e:?}"))?;
    let d = HostDir::new(root, options).map_err(|r| r.0)?;
    let mut s = Session::new(d, Config { owner: (UID, GID), ..config }).map_err(|e| format!("{e:?}"))?;
    let init = request(Opcode::Init as u32, 1, 0, (UID, GID), &[&init_args()]);
    s.handle(&init, CAP).unwrap();
    Ok(s)
}

/// One request to a bare session: (error, body).
pub fn call(s: &mut Session<HostDir>, op: Opcode, nodeid: u64, args: &[&[u8]]) -> (i32, Vec<u8>) {
    let bytes = request(op as u32, 7, nodeid, (UID, GID), args);
    let reply = s.handle(&bytes, CAP).unwrap();
    s.check().unwrap();
    (i32::from_le_bytes(reply[4..8].try_into().unwrap()), reply[16..].to_vec())
}
