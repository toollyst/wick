// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The bounded FUSE decoder (docs/design-fs.md row 6 and §6, FUSE decoder).
//!
//! [`decode`] takes a request frame's payload, the readable bytes of one
//! descriptor chain, which the server holds in its own buffer (the guest
//! cannot change them while they are read), and returns the request with
//! every argument checked against those bytes, or why it was refused. It
//! borrows from the payload and allocates nothing, whatever the lengths say.
//!
//! The payload is a `fuse_in_header`, the opcode's arguments, and the
//! extensions (`total_extlen` × 8 bytes, the last argument when present,
//! fs/fuse/dev.c `fuse_args_to_req`). The rules:
//! - `fuse_in_header.len` is the payload's length;
//! - a fixed argument has exactly its size in fuse.h for the protocol the
//!   guest speaks (minor ≥ 12, so none of the `FUSE_COMPAT_*` sizes), and
//!   nothing is left over after the last argument;
//! - a name ends at its NUL, which lies inside the arguments, and is a
//!   [`Name`] (one component, [`super::name`]); a symlink's target and an
//!   extended attribute's name have their own bounds;
//! - `WRITE` carries exactly `size` bytes of data, at most [`MAX_WRITE`];
//! - `BATCH_FORGET` carries exactly `count` × 16 bytes;
//! - the extensions lie inside the payload, come only with the opcodes the
//!   kernel adds them to (`CREATE`, `MKNOD`, `MKDIR`, `SYMLINK`; fs/fuse/dir.c
//!   `get_create_ext`) and only when INIT negotiated them, and are a chain of
//!   `fuse_ext_header`s, each of at least 8 bytes, a multiple of 8, inside
//!   the rest;
//! - the opcodes the server never implements are [`DecodeError::Unsupported`]
//!   (`ENOSYS`) before their arguments are read, and an opcode FUSE has not
//!   got is [`DecodeError::UnknownOpcode`] (`ENOSYS`).

use std::fmt;

use super::name::{Name, NameError};
use super::{
    Errno, IN_HEADER_LEN, InHeader, MAX_WRITE, Opcode, PATH_MAX, XATTR_NAME_MAX, XATTR_SIZE_MAX,
};

/// What INIT negotiated that changes how requests are laid out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wire {
    /// `FUSE_SETXATTR_EXT`: `fuse_setxattr_in` is 16 bytes, not 8.
    pub setxattr_ext: bool,
    /// `FUSE_SECURITY_CTX` or `FUSE_CREATE_SUPP_GROUP`: creating requests
    /// may carry extensions. Without either, an extension is refused.
    pub extensions: bool,
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload is shorter than `fuse_in_header`.
    ShortHeader(usize),
    /// `fuse_in_header.len` is not the payload's length.
    Length {
        /// The header's `len`.
        header: u32,
        /// The payload's length.
        payload: usize,
    },
    /// An opcode FUSE has not got.
    UnknownOpcode(u32),
    /// An opcode the server never implements.
    Unsupported(Opcode),
    /// The arguments do not have the opcode's layout.
    Args(Opcode, &'static str),
    /// A name that is not one component.
    Name(Opcode, NameError),
    /// A symlink target or extended attribute name that is too long.
    TooLong(Opcode, &'static str),
    /// An extended attribute value above [`XATTR_SIZE_MAX`].
    XattrValue(usize),
    /// A `WRITE` above [`MAX_WRITE`].
    WriteSize(u32),
    /// Extensions that break a rule.
    Extensions(&'static str),
}

impl DecodeError {
    /// The error the guest gets: `ENOSYS` for opcodes the server does not
    /// implement, a name's own ([`NameError::errno`]), `ENAMETOOLONG` and
    /// `E2BIG` for the bounds Linux gives those, `EINVAL` for every
    /// malformed request.
    pub fn errno(self) -> Errno {
        match self {
            DecodeError::UnknownOpcode(_) | DecodeError::Unsupported(_) => Errno::ENOSYS,
            DecodeError::Name(_, e) => e.errno(),
            DecodeError::TooLong(..) => Errno::ENAMETOOLONG,
            DecodeError::XattrValue(_) => Errno::E2BIG,
            DecodeError::ShortHeader(_)
            | DecodeError::Length { .. }
            | DecodeError::Args(..)
            | DecodeError::WriteSize(_)
            | DecodeError::Extensions(_) => Errno::EINVAL,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::ShortHeader(len) => {
                write!(f, "a request of {len} bytes, shorter than its header")
            }
            DecodeError::Length { header, payload } => {
                write!(f, "a request header of length {header} in {payload} bytes")
            }
            DecodeError::UnknownOpcode(op) => write!(f, "unknown opcode {op}"),
            DecodeError::Unsupported(op) => write!(f, "{op:?} is not implemented"),
            DecodeError::Args(op, why) => write!(f, "{op:?}: {why}"),
            DecodeError::Name(op, e) => write!(f, "{op:?}: {e}"),
            DecodeError::TooLong(op, what) => write!(f, "{op:?}: {what} too long"),
            DecodeError::XattrValue(len) => {
                write!(f, "an extended attribute value of {len} bytes")
            }
            DecodeError::WriteSize(size) => {
                write!(f, "a write of {size} bytes, above {MAX_WRITE}")
            }
            DecodeError::Extensions(why) => write!(f, "extensions: {why}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A request refused, with its header when the payload had one: the reply
/// carries the header's `unique`, and a request without a reply
/// ([`Opcode::has_reply`]) gets none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused {
    /// The header, if the payload had one.
    pub header: Option<InHeader>,
    /// Why.
    pub error: DecodeError,
}

/// A decoded request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// Its header.
    pub header: InHeader,
    /// Its arguments.
    pub op: Op<'a>,
    /// Its extensions, empty unless INIT negotiated them.
    pub extensions: Extensions<'a>,
}

/// `fuse_setattr_in`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetattrIn {
    pub valid: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// `fuse_read_in`, for `READ`, `READDIR` and `READDIRPLUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
}

/// `fuse_write_in`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
}

/// `fuse_release_in`, for `RELEASE` and `RELEASEDIR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

/// `fuse_lk_in`, for `GETLK`, `SETLK` and `SETLKW`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LkIn {
    pub fh: u64,
    pub owner: u64,
    pub start: u64,
    pub end: u64,
    pub kind: u32,
    pub pid: u32,
    pub lk_flags: u32,
}

/// `fuse_init_in`. A guest of protocol 7.36 or later sends all 64 bytes;
/// an older one the first 16 (`flags2` is then 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub flags2: u32,
}

/// `fuse_copy_file_range_in`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyFileRangeIn {
    pub fh_in: u64,
    pub off_in: u64,
    pub nodeid_out: u64,
    pub fh_out: u64,
    pub off_out: u64,
    pub len: u64,
    pub flags: u64,
}

/// An extended attribute name: 1 to [`XATTR_NAME_MAX`] bytes without a
/// NUL. Its namespace (`user.`, `security.`, …) is the server's to judge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XattrName<'a>(&'a [u8]);

impl<'a> XattrName<'a> {
    /// The name's bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Debug for XattrName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XattrName({:?})", String::from_utf8_lossy(self.0))
    }
}

/// The `fuse_forget_one` records of a `BATCH_FORGET`: (node id, lookups).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Forgets<'a>(&'a [u8]);

impl<'a> Forgets<'a> {
    /// How many.
    pub fn len(&self) -> usize {
        self.0.len() / 16
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Each (node id, lookups).
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64)> + 'a {
        self.0.chunks_exact(16).map(|one| {
            let mut f = Fields::new(one);
            (f.u64(), f.u64())
        })
    }
}

impl fmt::Debug for Forgets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// A request's extensions: `fuse_ext_header` records, checked as a chain.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Extensions<'a>(&'a [u8]);

impl<'a> Extensions<'a> {
    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Each extension's type and body (the bytes after its header).
    pub fn iter(&self) -> impl Iterator<Item = (u32, &'a [u8])> + 'a {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            let (size, kind) = ext_header(rest)?;
            let (one, after) = rest.split_at_checked(size)?;
            rest = after;
            Some((kind, one.get(8..)?))
        })
    }
}

impl fmt::Debug for Extensions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.iter().map(|(kind, body)| (kind, body.len())))
            .finish()
    }
}

/// An extension header's size (as a usize) and type, if 8 bytes are there.
fn ext_header(bytes: &[u8]) -> Option<(usize, u32)> {
    let (head, _) = bytes.split_first_chunk::<8>()?;
    let mut f = Fields::new(head);
    let size = usize::try_from(f.u32()).ok()?;
    Some((size, f.u32()))
}

/// A request's arguments, by opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op<'a> {
    Lookup {
        name: Name<'a>,
    },
    Forget {
        nlookup: u64,
    },
    Getattr {
        getattr_flags: u32,
        fh: u64,
    },
    Setattr(SetattrIn),
    Readlink,
    Symlink {
        name: Name<'a>,
        /// The target's bytes without the NUL: any bytes, kept as the
        /// emulated link's content and never resolved by the server.
        target: &'a [u8],
    },
    Mknod {
        mode: u32,
        rdev: u32,
        umask: u32,
        name: Name<'a>,
    },
    Mkdir {
        mode: u32,
        umask: u32,
        name: Name<'a>,
    },
    Unlink {
        name: Name<'a>,
    },
    Rmdir {
        name: Name<'a>,
    },
    Rename {
        newdir: u64,
        flags: u32,
        old: Name<'a>,
        new: Name<'a>,
    },
    Link {
        oldnodeid: u64,
        name: Name<'a>,
    },
    Open {
        flags: u32,
        open_flags: u32,
    },
    Read(ReadIn),
    Write {
        arg: WriteIn,
        data: &'a [u8],
    },
    Statfs,
    Release(ReleaseIn),
    Fsync {
        fh: u64,
        fsync_flags: u32,
    },
    Setxattr {
        flags: u32,
        setxattr_flags: u32,
        name: XattrName<'a>,
        value: &'a [u8],
    },
    Getxattr {
        size: u32,
        name: XattrName<'a>,
    },
    Listxattr {
        size: u32,
    },
    Removexattr {
        name: XattrName<'a>,
    },
    Flush {
        fh: u64,
        lock_owner: u64,
    },
    Init(InitIn),
    Opendir {
        flags: u32,
        open_flags: u32,
    },
    Readdir(ReadIn),
    Readdirplus(ReadIn),
    Releasedir(ReleaseIn),
    Fsyncdir {
        fh: u64,
        fsync_flags: u32,
    },
    Getlk(LkIn),
    Setlk(LkIn),
    Setlkw(LkIn),
    Access {
        mask: u32,
    },
    Create {
        flags: u32,
        mode: u32,
        umask: u32,
        open_flags: u32,
        name: Name<'a>,
    },
    Interrupt {
        unique: u64,
    },
    Bmap {
        block: u64,
        blocksize: u32,
    },
    Destroy,
    BatchForget(Forgets<'a>),
    Fallocate {
        fh: u64,
        offset: u64,
        length: u64,
        mode: u32,
    },
    Lseek {
        fh: u64,
        offset: u64,
        whence: u32,
    },
    /// `COPY_FILE_RANGE` and, with `wide` set, `COPY_FILE_RANGE_64` (the
    /// same arguments, a 64-bit count in the reply).
    CopyFileRange {
        arg: CopyFileRangeIn,
        wide: bool,
    },
    Syncfs,
    Statx {
        getattr_flags: u32,
        fh: u64,
        sx_flags: u32,
        sx_mask: u32,
    },
}

/// Reads little-endian fields in order from bytes whose length was checked
/// against the struct's size: a read past the end gives 0 and marks the
/// reader, and [`Fields::end`] then fails, so a wrong size here is an error,
/// never a panic.
struct Fields<'a> {
    rest: &'a [u8],
    short: bool,
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8]) -> Fields<'a> {
        Fields {
            rest: bytes,
            short: false,
        }
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        match self.rest.split_first_chunk::<N>() {
            Some((head, tail)) => {
                self.rest = tail;
                *head
            }
            None => {
                self.short = true;
                self.rest = &[];
                [0; N]
            }
        }
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }

    fn skip<const N: usize>(&mut self) {
        let _: [u8; N] = self.take();
    }

    /// Whether every byte was read, and no more.
    fn end(&self) -> bool {
        !self.short && self.rest.is_empty()
    }
}

/// The arguments still to read.
struct Args<'a> {
    op: Opcode,
    rest: &'a [u8],
}

impl<'a> Args<'a> {
    /// The next `len` bytes, a fixed struct.
    fn fixed(&mut self, len: usize) -> Result<Fields<'a>, DecodeError> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or(DecodeError::Args(self.op, "shorter than its arguments"))?;
        self.rest = tail;
        Ok(Fields::new(head))
    }

    /// The bytes up to the next NUL, which must be inside the arguments;
    /// the NUL is consumed.
    fn cstr(&mut self) -> Result<&'a [u8], DecodeError> {
        let end = self
            .rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(DecodeError::Args(self.op, "a string without its NUL"))?;
        let (s, tail) = self.rest.split_at(end);
        self.rest = tail.get(1..).unwrap_or_default();
        Ok(s)
    }

    /// A guest name and its NUL.
    fn name(&mut self) -> Result<Name<'a>, DecodeError> {
        let op = self.op;
        let bytes = self.cstr()?;
        Name::new(bytes).map_err(|e| DecodeError::Name(op, e))
    }

    /// An extended attribute name and its NUL.
    fn xattr_name(&mut self) -> Result<XattrName<'a>, DecodeError> {
        let bytes = self.cstr()?;
        if bytes.is_empty() {
            return Err(DecodeError::Args(self.op, "an empty attribute name"));
        }
        if bytes.len() > XATTR_NAME_MAX {
            return Err(DecodeError::TooLong(self.op, "attribute name"));
        }
        Ok(XattrName(bytes))
    }

    /// The bytes left.
    fn remaining(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.rest)
    }

    /// Fails unless every argument byte was read.
    fn done(&self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Args(self.op, "bytes after its arguments"))
        }
    }
}

/// Reads one fixed struct of `len` bytes with `read`, which must read
/// exactly `len` bytes of fields.
fn fixed<'a, T>(
    args: &mut Args<'a>,
    len: usize,
    read: impl FnOnce(&mut Fields<'a>) -> T,
) -> Result<T, DecodeError> {
    let mut f = args.fixed(len)?;
    let value = read(&mut f);
    if f.end() {
        Ok(value)
    } else {
        // A size table here that disagrees with its reader: a bug of this
        // file, refused like a bad request rather than trusted.
        Err(DecodeError::Args(args.op, "internal: a struct read with the wrong size"))
    }
}

fn header(bytes: &[u8]) -> Option<InHeader> {
    let (head, _) = bytes.split_first_chunk::<IN_HEADER_LEN>()?;
    let mut f = Fields::new(head);
    let header = InHeader {
        len: f.u32(),
        opcode: f.u32(),
        unique: f.u64(),
        nodeid: f.u64(),
        uid: f.u32(),
        gid: f.u32(),
        pid: f.u32(),
        total_extlen: f.u16(),
    };
    f.skip::<2>();
    f.end().then_some(header)
}

/// Decodes one request's bytes (a request frame's whole payload).
pub fn decode<'a>(payload: &'a [u8], wire: &Wire) -> Result<Request<'a>, Refused> {
    let Some(h) = header(payload) else {
        return Err(Refused {
            header: None,
            error: DecodeError::ShortHeader(payload.len()),
        });
    };
    let refuse = |error| Refused {
        header: Some(h),
        error,
    };
    if usize::try_from(h.len).ok() != Some(payload.len()) {
        return Err(refuse(DecodeError::Length {
            header: h.len,
            payload: payload.len(),
        }));
    }
    let op = Opcode::from_wire(h.opcode)
        .ok_or_else(|| refuse(DecodeError::UnknownOpcode(h.opcode)))?;
    if op.is_unsupported() {
        return Err(refuse(DecodeError::Unsupported(op)));
    }
    let body = payload.get(IN_HEADER_LEN..).unwrap_or_default();
    let ext_len = usize::from(h.total_extlen) * 8;
    let Some(split) = body.len().checked_sub(ext_len) else {
        return Err(refuse(DecodeError::Extensions("longer than the request")));
    };
    let (args, ext) = body.split_at(split);
    let extensions = extensions(op, ext, wire).map_err(refuse)?;
    let mut args = Args { op, rest: args };
    let op = decode_args(&mut args, wire).map_err(refuse)?;
    args.done().map_err(refuse)?;
    Ok(Request {
        header: h,
        op,
        extensions,
    })
}

fn extensions<'a>(op: Opcode, ext: &'a [u8], wire: &Wire) -> Result<Extensions<'a>, DecodeError> {
    if ext.is_empty() {
        return Ok(Extensions::default());
    }
    if !wire.extensions {
        return Err(DecodeError::Extensions("not negotiated"));
    }
    if !matches!(
        op,
        Opcode::Create | Opcode::Mknod | Opcode::Mkdir | Opcode::Symlink
    ) {
        return Err(DecodeError::Extensions("on a request that takes none"));
    }
    let mut rest = ext;
    while !rest.is_empty() {
        let (size, _) =
            ext_header(rest).ok_or(DecodeError::Extensions("a header cut short"))?;
        if size < 8 || !size.is_multiple_of(8) {
            return Err(DecodeError::Extensions("a size below 8 or not a multiple of 8"));
        }
        rest = rest
            .get(size..)
            .ok_or(DecodeError::Extensions("a size past the end"))?;
    }
    Ok(Extensions(ext))
}

fn read_in(f: &mut Fields<'_>) -> ReadIn {
    let arg = ReadIn {
        fh: f.u64(),
        offset: f.u64(),
        size: f.u32(),
        read_flags: f.u32(),
        lock_owner: f.u64(),
        flags: f.u32(),
    };
    f.skip::<4>();
    arg
}

fn release_in(f: &mut Fields<'_>) -> ReleaseIn {
    ReleaseIn {
        fh: f.u64(),
        flags: f.u32(),
        release_flags: f.u32(),
        lock_owner: f.u64(),
    }
}

fn lk_in(f: &mut Fields<'_>) -> LkIn {
    let arg = LkIn {
        fh: f.u64(),
        owner: f.u64(),
        start: f.u64(),
        end: f.u64(),
        kind: f.u32(),
        pid: f.u32(),
        lk_flags: f.u32(),
    };
    f.skip::<4>();
    arg
}

fn fsync_in(f: &mut Fields<'_>) -> (u64, u32) {
    let arg = (f.u64(), f.u32());
    f.skip::<4>();
    arg
}

fn open_in(f: &mut Fields<'_>) -> (u32, u32) {
    (f.u32(), f.u32())
}

fn decode_args<'a>(a: &mut Args<'a>, wire: &Wire) -> Result<Op<'a>, DecodeError> {
    Ok(match a.op {
        Opcode::Lookup => Op::Lookup { name: a.name()? },
        Opcode::Forget => Op::Forget {
            nlookup: fixed(a, 8, |f| f.u64())?,
        },
        Opcode::Getattr => {
            let (getattr_flags, fh) = fixed(a, 16, |f| {
                let flags = f.u32();
                f.skip::<4>();
                (flags, f.u64())
            })?;
            Op::Getattr { getattr_flags, fh }
        }
        Opcode::Setattr => Op::Setattr(fixed(a, 88, |f| {
            let valid = f.u32();
            f.skip::<4>(); // padding
            let (fh, size, lock_owner) = (f.u64(), f.u64(), f.u64());
            let (atime, mtime, ctime) = (f.u64(), f.u64(), f.u64());
            let (atimensec, mtimensec, ctimensec) = (f.u32(), f.u32(), f.u32());
            let mode = f.u32();
            f.skip::<4>(); // unused4
            let (uid, gid) = (f.u32(), f.u32());
            f.skip::<4>(); // unused5
            SetattrIn {
                valid,
                fh,
                size,
                lock_owner,
                atime,
                mtime,
                ctime,
                atimensec,
                mtimensec,
                ctimensec,
                mode,
                uid,
                gid,
            }
        })?),
        Opcode::Readlink => Op::Readlink,
        Opcode::Symlink => {
            // The name, then the target (fs/fuse/dir.c `fuse_symlink`).
            let name = a.name()?;
            let target = a.cstr()?;
            if target.is_empty() {
                return Err(DecodeError::Args(Opcode::Symlink, "an empty target"));
            }
            if target.len() >= PATH_MAX {
                return Err(DecodeError::TooLong(Opcode::Symlink, "target"));
            }
            Op::Symlink { name, target }
        }
        Opcode::Mknod => {
            let (mode, rdev, umask) = fixed(a, 16, |f| {
                let arg = (f.u32(), f.u32(), f.u32());
                f.skip::<4>();
                arg
            })?;
            Op::Mknod {
                mode,
                rdev,
                umask,
                name: a.name()?,
            }
        }
        Opcode::Mkdir => {
            let (mode, umask) = fixed(a, 8, |f| (f.u32(), f.u32()))?;
            Op::Mkdir {
                mode,
                umask,
                name: a.name()?,
            }
        }
        Opcode::Unlink => Op::Unlink { name: a.name()? },
        Opcode::Rmdir => Op::Rmdir { name: a.name()? },
        Opcode::Rename => {
            let newdir = fixed(a, 8, |f| f.u64())?;
            Op::Rename {
                newdir,
                flags: 0,
                old: a.name()?,
                new: a.name()?,
            }
        }
        Opcode::Rename2 => {
            let (newdir, flags) = fixed(a, 16, |f| {
                let arg = (f.u64(), f.u32());
                f.skip::<4>();
                arg
            })?;
            Op::Rename {
                newdir,
                flags,
                old: a.name()?,
                new: a.name()?,
            }
        }
        Opcode::Link => {
            let oldnodeid = fixed(a, 8, |f| f.u64())?;
            Op::Link {
                oldnodeid,
                name: a.name()?,
            }
        }
        Opcode::Open => {
            let (flags, open_flags) = fixed(a, 8, open_in)?;
            Op::Open { flags, open_flags }
        }
        Opcode::Opendir => {
            let (flags, open_flags) = fixed(a, 8, open_in)?;
            Op::Opendir { flags, open_flags }
        }
        Opcode::Read => Op::Read(fixed(a, 40, read_in)?),
        Opcode::Readdir => Op::Readdir(fixed(a, 40, read_in)?),
        Opcode::Readdirplus => Op::Readdirplus(fixed(a, 40, read_in)?),
        Opcode::Write => {
            let arg = fixed(a, 40, |f| {
                let arg = WriteIn {
                    fh: f.u64(),
                    offset: f.u64(),
                    size: f.u32(),
                    write_flags: f.u32(),
                    lock_owner: f.u64(),
                    flags: f.u32(),
                };
                f.skip::<4>();
                arg
            })?;
            if arg.size > MAX_WRITE {
                return Err(DecodeError::WriteSize(arg.size));
            }
            let data = a.remaining();
            if usize::try_from(arg.size).ok() != Some(data.len()) {
                return Err(DecodeError::Args(
                    Opcode::Write,
                    "data of another length than its size",
                ));
            }
            Op::Write { arg, data }
        }
        Opcode::Statfs => Op::Statfs,
        Opcode::Release => Op::Release(fixed(a, 24, release_in)?),
        Opcode::Releasedir => Op::Releasedir(fixed(a, 24, release_in)?),
        Opcode::Fsync => {
            let (fh, fsync_flags) = fixed(a, 16, fsync_in)?;
            Op::Fsync { fh, fsync_flags }
        }
        Opcode::Fsyncdir => {
            let (fh, fsync_flags) = fixed(a, 16, fsync_in)?;
            Op::Fsyncdir { fh, fsync_flags }
        }
        Opcode::Setxattr => {
            // `fuse_setxattr_in` is 16 bytes with FUSE_SETXATTR_EXT, else
            // its first 8 (fs/fuse/xattr.c `fuse_setxattr`).
            let (size, flags, setxattr_flags) = if wire.setxattr_ext {
                fixed(a, 16, |f| {
                    let arg = (f.u32(), f.u32(), f.u32());
                    f.skip::<4>();
                    arg
                })?
            } else {
                let (size, flags) = fixed(a, 8, |f| (f.u32(), f.u32()))?;
                (size, flags, 0)
            };
            let name = a.xattr_name()?;
            let value = a.remaining();
            if usize::try_from(size).ok() != Some(value.len()) {
                return Err(DecodeError::Args(
                    Opcode::Setxattr,
                    "a value of another length than its size",
                ));
            }
            if value.len() > XATTR_SIZE_MAX {
                return Err(DecodeError::XattrValue(value.len()));
            }
            Op::Setxattr {
                flags,
                setxattr_flags,
                name,
                value,
            }
        }
        Opcode::Getxattr => {
            let size = fixed(a, 8, |f| {
                let size = f.u32();
                f.skip::<4>();
                size
            })?;
            Op::Getxattr {
                size,
                name: a.xattr_name()?,
            }
        }
        Opcode::Listxattr => Op::Listxattr {
            size: fixed(a, 8, |f| {
                let size = f.u32();
                f.skip::<4>();
                size
            })?,
        },
        Opcode::Removexattr => Op::Removexattr {
            name: a.xattr_name()?,
        },
        Opcode::Flush => {
            let (fh, lock_owner) = fixed(a, 24, |f| {
                let fh = f.u64();
                f.skip::<8>();
                (fh, f.u64())
            })?;
            Op::Flush { fh, lock_owner }
        }
        Opcode::Init => {
            // 64 bytes from protocol 7.36 on, the first 16 before; a later
            // guest may send more, which fuse.h grows by adding fields at
            // the end that a server that does not know them ignores.
            let len = if a.rest.len() >= 64 { a.rest.len() } else { 16 };
            let init = fixed(a, len, |f| {
                let arg = InitIn {
                    major: f.u32(),
                    minor: f.u32(),
                    max_readahead: f.u32(),
                    flags: f.u32(),
                    flags2: if len >= 64 { f.u32() } else { 0 },
                };
                if len >= 64 {
                    // `unused[11]` and whatever a later guest added.
                    f.rest = &[];
                }
                arg
            })?;
            Op::Init(init)
        }
        Opcode::Getlk => Op::Getlk(fixed(a, 48, lk_in)?),
        Opcode::Setlk => Op::Setlk(fixed(a, 48, lk_in)?),
        Opcode::Setlkw => Op::Setlkw(fixed(a, 48, lk_in)?),
        Opcode::Access => Op::Access {
            mask: fixed(a, 8, |f| {
                let mask = f.u32();
                f.skip::<4>();
                mask
            })?,
        },
        Opcode::Create => {
            let (flags, mode, umask, open_flags) =
                fixed(a, 16, |f| (f.u32(), f.u32(), f.u32(), f.u32()))?;
            Op::Create {
                flags,
                mode,
                umask,
                open_flags,
                name: a.name()?,
            }
        }
        Opcode::Interrupt => Op::Interrupt {
            unique: fixed(a, 8, |f| f.u64())?,
        },
        Opcode::Bmap => {
            let (block, blocksize) = fixed(a, 16, |f| {
                let arg = (f.u64(), f.u32());
                f.skip::<4>();
                arg
            })?;
            Op::Bmap { block, blocksize }
        }
        Opcode::Destroy => Op::Destroy,
        Opcode::BatchForget => {
            let count = fixed(a, 8, |f| {
                let count = f.u32();
                f.skip::<4>();
                count
            })?;
            let records = a.remaining();
            let expected = usize::try_from(count).ok().and_then(|c| c.checked_mul(16));
            if expected != Some(records.len()) {
                return Err(DecodeError::Args(
                    Opcode::BatchForget,
                    "records of another length than count × 16",
                ));
            }
            Op::BatchForget(Forgets(records))
        }
        Opcode::Fallocate => {
            let (fh, offset, length, mode) = fixed(a, 32, |f| {
                let arg = (f.u64(), f.u64(), f.u64(), f.u32());
                f.skip::<4>();
                arg
            })?;
            Op::Fallocate {
                fh,
                offset,
                length,
                mode,
            }
        }
        Opcode::Lseek => {
            let (fh, offset, whence) = fixed(a, 24, |f| {
                let arg = (f.u64(), f.u64(), f.u32());
                f.skip::<4>();
                arg
            })?;
            Op::Lseek { fh, offset, whence }
        }
        Opcode::CopyFileRange | Opcode::CopyFileRange64 => Op::CopyFileRange {
            arg: fixed(a, 56, |f| CopyFileRangeIn {
                fh_in: f.u64(),
                off_in: f.u64(),
                nodeid_out: f.u64(),
                fh_out: f.u64(),
                off_out: f.u64(),
                len: f.u64(),
                flags: f.u64(),
            })?,
            wide: a.op == Opcode::CopyFileRange64,
        },
        Opcode::Syncfs => {
            fixed(a, 8, |f| f.skip::<8>())?;
            Op::Syncfs
        }
        Opcode::Statx => {
            let (getattr_flags, fh, sx_flags, sx_mask) = fixed(a, 24, |f| {
                let getattr_flags = f.u32();
                f.skip::<4>();
                (getattr_flags, f.u64(), f.u32(), f.u32())
            })?;
            Op::Statx {
                getattr_flags,
                fh,
                sx_flags,
                sx_mask,
            }
        }
        Opcode::Ioctl
        | Opcode::Poll
        | Opcode::NotifyReply
        | Opcode::SetupMapping
        | Opcode::RemoveMapping
        | Opcode::Tmpfile
        | Opcode::CuseInit => return Err(DecodeError::Unsupported(a.op)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request: the header (with the right `len` unless `len` is given),
    /// then `args`.
    fn request(opcode: u32, total_extlen: u16, args: &[&[u8]]) -> Vec<u8> {
        let body: Vec<u8> = args.concat();
        let len = u32::try_from(IN_HEADER_LEN + body.len()).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&opcode.to_le_bytes());
        out.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // unique
        out.extend_from_slice(&9u64.to_le_bytes()); // nodeid
        out.extend_from_slice(&1000u32.to_le_bytes()); // uid
        out.extend_from_slice(&1001u32.to_le_bytes()); // gid
        out.extend_from_slice(&42u32.to_le_bytes()); // pid
        out.extend_from_slice(&total_extlen.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&body);
        out
    }

    fn op(o: Opcode) -> u32 {
        o as u32
    }

    fn ok(bytes: &[u8]) -> Op<'_> {
        ok_with(bytes, &Wire::default())
    }

    fn ok_with<'a>(bytes: &'a [u8], wire: &Wire) -> Op<'a> {
        match decode(bytes, wire) {
            Ok(request) => request.op,
            Err(e) => panic!("refused: {e:?}"),
        }
    }

    fn err(bytes: &[u8]) -> DecodeError {
        err_with(bytes, &Wire::default())
    }

    fn err_with(bytes: &[u8], wire: &Wire) -> DecodeError {
        match decode(bytes, wire) {
            Ok(request) => panic!("accepted: {request:?}"),
            Err(refused) => {
                if bytes.len() >= IN_HEADER_LEN {
                    let header = refused.header.unwrap();
                    assert_eq!(header.unique, 0x1122_3344_5566_7788);
                }
                refused.error
            }
        }
    }

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn le64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    #[test]
    fn test_header_fields_and_its_len() {
        let bytes = request(op(Opcode::Statfs), 0, &[]);
        let r = decode(&bytes, &Wire::default()).unwrap();
        assert_eq!(
            r.header,
            InHeader {
                len: 40,
                opcode: 17,
                unique: 0x1122_3344_5566_7788,
                nodeid: 9,
                uid: 1000,
                gid: 1001,
                pid: 42,
                total_extlen: 0,
            }
        );
        assert_eq!(r.op, Op::Statfs);
        assert!(r.extensions.is_empty());

        // Shorter than the header: no header to answer with.
        for len in [0, 1, 39] {
            let refused = decode(&bytes[..len], &Wire::default()).unwrap_err();
            assert_eq!(refused.header, None);
            assert_eq!(refused.error, DecodeError::ShortHeader(len));
        }
        // `len` must be the payload's length, both ways.
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            err(&longer),
            DecodeError::Length {
                header: 40,
                payload: 41
            }
        );
        let mut lying = request(op(Opcode::Lookup), 0, &[b"name\0"]);
        lying[0..4].copy_from_slice(&le32(40));
        assert_eq!(
            err(&lying),
            DecodeError::Length {
                header: 40,
                payload: 45
            }
        );
        lying[0..4].copy_from_slice(&le32(u32::MAX));
        assert!(matches!(err(&lying), DecodeError::Length { .. }));
    }

    #[test]
    fn test_every_fixed_argument_has_its_exact_size() {
        // fuse.h 7.47's sizeof for each opcode whose arguments are one
        // struct; one byte short or over is refused.
        let table: &[(Opcode, usize)] = &[
            (Opcode::Forget, 8),
            (Opcode::Getattr, 16),
            (Opcode::Setattr, 88),
            (Opcode::Readlink, 0),
            (Opcode::Open, 8),
            (Opcode::Read, 40),
            (Opcode::Statfs, 0),
            (Opcode::Release, 24),
            (Opcode::Fsync, 16),
            (Opcode::Listxattr, 8),
            (Opcode::Flush, 24),
            (Opcode::Opendir, 8),
            (Opcode::Readdir, 40),
            (Opcode::Releasedir, 24),
            (Opcode::Fsyncdir, 16),
            (Opcode::Getlk, 48),
            (Opcode::Setlk, 48),
            (Opcode::Setlkw, 48),
            (Opcode::Access, 8),
            (Opcode::Interrupt, 8),
            (Opcode::Bmap, 16),
            (Opcode::Destroy, 0),
            (Opcode::Fallocate, 32),
            (Opcode::Readdirplus, 40),
            (Opcode::Lseek, 24),
            (Opcode::CopyFileRange, 56),
            (Opcode::Syncfs, 8),
            (Opcode::Statx, 24),
            (Opcode::CopyFileRange64, 56),
        ];
        for &(o, size) in table {
            let exact = vec![0u8; size];
            ok(&request(op(o), 0, &[&exact]));
            let over = vec![0u8; size + 1];
            assert_eq!(
                err(&request(op(o), 0, &[&over])),
                DecodeError::Args(o, "bytes after its arguments"),
                "{o:?}"
            );
            if size > 0 {
                let short = vec![0u8; size - 1];
                assert_eq!(
                    err(&request(op(o), 0, &[&short])),
                    DecodeError::Args(o, "shorter than its arguments"),
                    "{o:?}"
                );
            }
        }
    }

    #[test]
    fn test_fields_are_read_from_their_offsets() {
        // Each field a distinct value, so a field read from the wrong place
        // shows.
        let words: Vec<u8> = (1u32..=22).flat_map(u32::to_le_bytes).collect();
        let w = |i: usize| u32::from_le_bytes(words[i * 4..i * 4 + 4].try_into().unwrap());
        let d = |i: usize| u64::from_le_bytes(words[i * 4..i * 4 + 8].try_into().unwrap());

        let Op::Setattr(s) = ok(&request(op(Opcode::Setattr), 0, &[&words[..88]])) else {
            panic!()
        };
        assert_eq!(
            s,
            SetattrIn {
                valid: w(0),
                fh: d(2),
                size: d(4),
                lock_owner: d(6),
                atime: d(8),
                mtime: d(10),
                ctime: d(12),
                atimensec: w(14),
                mtimensec: w(15),
                ctimensec: w(16),
                mode: w(17),
                uid: w(19),
                gid: w(20),
            }
        );
        let Op::Read(r) = ok(&request(op(Opcode::Read), 0, &[&words[..40]])) else {
            panic!()
        };
        assert_eq!(
            r,
            ReadIn {
                fh: d(0),
                offset: d(2),
                size: w(4),
                read_flags: w(5),
                lock_owner: d(6),
                flags: w(8),
            }
        );
        let Op::Getlk(l) = ok(&request(op(Opcode::Getlk), 0, &[&words[..48]])) else {
            panic!()
        };
        assert_eq!(
            l,
            LkIn {
                fh: d(0),
                owner: d(2),
                start: d(4),
                end: d(6),
                kind: w(8),
                pid: w(9),
                lk_flags: w(10),
            }
        );
        assert_eq!(
            ok(&request(op(Opcode::Statx), 0, &[&words[..24]])),
            Op::Statx {
                getattr_flags: w(0),
                fh: d(2),
                sx_flags: w(4),
                sx_mask: w(5),
            }
        );
        assert_eq!(
            ok(&request(op(Opcode::Flush), 0, &[&words[..24]])),
            Op::Flush {
                fh: d(0),
                lock_owner: d(4),
            }
        );
        assert_eq!(
            ok(&request(op(Opcode::Fallocate), 0, &[&words[..32]])),
            Op::Fallocate {
                fh: d(0),
                offset: d(2),
                length: d(4),
                mode: w(6),
            }
        );
        assert_eq!(
            ok(&request(op(Opcode::CopyFileRange64), 0, &[&words[..56]])),
            Op::CopyFileRange {
                arg: CopyFileRangeIn {
                    fh_in: d(0),
                    off_in: d(2),
                    nodeid_out: d(4),
                    fh_out: d(6),
                    off_out: d(8),
                    len: d(10),
                    flags: d(12),
                },
                wide: true,
            }
        );
        assert_eq!(
            ok(&request(op(Opcode::Release), 0, &[&words[..24]])),
            Op::Release(ReleaseIn {
                fh: d(0),
                flags: w(2),
                release_flags: w(3),
                lock_owner: d(4),
            })
        );
    }

    /// The names layer 1 refuses, with the error each gets.
    fn bad_names() -> Vec<(Vec<u8>, NameError)> {
        let mut names = vec![
            (b"".to_vec(), NameError::Empty),
            (b".".to_vec(), NameError::Dots),
            (b"..".to_vec(), NameError::Dots),
            (b"/".to_vec(), NameError::Slash),
            (b"/etc/passwd".to_vec(), NameError::Slash),
            (b"../../etc".to_vec(), NameError::Slash),
            (b"a/..".to_vec(), NameError::Slash),
            (vec![b'a'; 256], NameError::TooLong),
            (b"\xff\xfe".to_vec(), NameError::NotUtf8),
            ("\u{F03A}".as_bytes().to_vec(), NameError::EscapeImage),
            ("a\u{F02F}b".as_bytes().to_vec(), NameError::EscapeImage),
        ];
        names.push(("\u{F05C}".as_bytes().to_vec(), NameError::EscapeImage));
        names
    }

    /// Every opcode that takes a name, as a request around `name` (with its
    /// NUL), the name in each of its places.
    fn name_requests(name: &[u8]) -> Vec<(Opcode, Vec<u8>)> {
        let n = [name, b"\0"].concat();
        let ok_name = b"ok\0";
        let z8 = [0u8; 8];
        let z16 = [0u8; 16];
        vec![
            (Opcode::Lookup, request(op(Opcode::Lookup), 0, &[&n])),
            (Opcode::Unlink, request(op(Opcode::Unlink), 0, &[&n])),
            (Opcode::Rmdir, request(op(Opcode::Rmdir), 0, &[&n])),
            (Opcode::Mknod, request(op(Opcode::Mknod), 0, &[&z16, &n])),
            (Opcode::Mkdir, request(op(Opcode::Mkdir), 0, &[&z8, &n])),
            (Opcode::Create, request(op(Opcode::Create), 0, &[&z16, &n])),
            (Opcode::Link, request(op(Opcode::Link), 0, &[&z8, &n])),
            (Opcode::Symlink, request(op(Opcode::Symlink), 0, &[&n, b"target\0"])),
            (Opcode::Rename, request(op(Opcode::Rename), 0, &[&z8, &n, ok_name])),
            (Opcode::Rename, request(op(Opcode::Rename), 0, &[&z8, ok_name, &n])),
            (Opcode::Rename2, request(op(Opcode::Rename2), 0, &[&z16, &n, ok_name])),
            (Opcode::Rename2, request(op(Opcode::Rename2), 0, &[&z16, ok_name, &n])),
        ]
    }

    #[test]
    fn test_every_name_taking_opcode_refuses_what_is_not_a_name() {
        // Layer 1 of docs/design-fs.md row 1, before any host call.
        for (o, bytes) in name_requests(b"fine") {
            ok(&bytes);
            assert!(o.has_reply());
        }
        for (name, why) in bad_names() {
            for (o, bytes) in name_requests(&name) {
                // Rename's tag is the opcode it was sent as.
                assert_eq!(err(&bytes), DecodeError::Name(o, why), "{o:?} {name:?}");
                assert_eq!(err(&bytes).errno(), why.errno());
            }
        }
        assert_eq!(
            DecodeError::Name(Opcode::Lookup, NameError::TooLong).errno(),
            Errno::ENAMETOOLONG
        );
        // A NUL inside the name ends it: the bytes after it are left over.
        assert_eq!(
            err(&request(op(Opcode::Lookup), 0, &[b"a\0b\0"])),
            DecodeError::Args(Opcode::Lookup, "bytes after its arguments")
        );
        // A name whose NUL is past the end (not there).
        for (o, bytes) in name_requests(b"x") {
            let mut cut = bytes.clone();
            // Drop the last NUL and fix len: the last string has no NUL.
            cut.pop();
            let len = u32::try_from(cut.len()).unwrap();
            cut[0..4].copy_from_slice(&le32(len));
            assert_eq!(
                err(&cut),
                DecodeError::Args(o, "a string without its NUL"),
                "{o:?}"
            );
        }
    }

    #[test]
    fn test_names_are_the_guests_bytes() {
        let bytes = request(
            op(Opcode::Rename2),
            0,
            &[&le64(77), &le32(1), &[0; 4], "é\0".as_bytes(), b"b c\0"],
        );
        let Op::Rename {
            newdir,
            flags,
            old,
            new,
        } = ok(&bytes)
        else {
            panic!()
        };
        assert_eq!((newdir, flags, old.as_str(), new.as_str()), (77, 1, "é", "b c"));
        let bytes = request(
            op(Opcode::Mknod),
            0,
            &[&le32(0o10644), &le32(0x0801), &le32(0o22), &[0; 4], b"dev\0"],
        );
        let Op::Mknod {
            mode, rdev, name, ..
        } = ok(&bytes)
        else {
            panic!()
        };
        assert_eq!((mode, rdev, name.as_str()), (0o10644, 0x0801, "dev"));
    }

    #[test]
    fn test_symlink_target_bounds() {
        let sym = |target: &[u8]| request(op(Opcode::Symlink), 0, &[b"link\0", target]);
        // A target is any bytes: an absolute path or `..` is the guest's
        // business, stored as the emulated link's content.
        let bytes = sym(b"/etc/passwd\0");
        let Op::Symlink { name, target } = ok(&bytes) else {
            panic!()
        };
        assert_eq!((name.as_str(), target), ("link", &b"/etc/passwd"[..]));
        ok(&sym(b"../../x\0"));
        ok(&sym(&[vec![b'a'; PATH_MAX - 1], vec![0]].concat()));
        assert_eq!(
            err(&sym(&[vec![b'a'; PATH_MAX], vec![0]].concat())),
            DecodeError::TooLong(Opcode::Symlink, "target")
        );
        assert_eq!(
            err(&sym(b"\0")),
            DecodeError::Args(Opcode::Symlink, "an empty target")
        );
        assert_eq!(
            err(&sym(b"x")),
            DecodeError::Args(Opcode::Symlink, "a string without its NUL")
        );
        assert_eq!(
            err(&sym(b"x\0y")),
            DecodeError::Args(Opcode::Symlink, "bytes after its arguments")
        );
    }

    fn write_in(size: u32) -> Vec<u8> {
        [&le64(3)[..], &le64(4096), &le32(size), &le32(0), &le64(0), &le32(0), &[0; 4]].concat()
    }

    #[test]
    fn test_write_carries_exactly_its_size_up_to_max_write() {
        let data = vec![7u8; 100];
        let bytes = request(op(Opcode::Write), 0, &[&write_in(100), &data]);
        let Op::Write { arg, data: got } = ok(&bytes)
        else {
            panic!()
        };
        assert_eq!((arg.fh, arg.offset, arg.size, got), (3, 4096, 100, &data[..]));
        for size in [99, 101, 0, u32::MAX] {
            let e = err(&request(op(Opcode::Write), 0, &[&write_in(size), &data]));
            assert!(matches!(e, DecodeError::Args(Opcode::Write, _) | DecodeError::WriteSize(_)), "{size}");
        }
        let max = vec![0u8; MAX_WRITE as usize];
        ok(&request(op(Opcode::Write), 0, &[&write_in(MAX_WRITE), &max]));
        let over = vec![0u8; MAX_WRITE as usize + 1];
        assert_eq!(
            err(&request(op(Opcode::Write), 0, &[&write_in(MAX_WRITE + 1), &over])),
            DecodeError::WriteSize(MAX_WRITE + 1)
        );
        assert_eq!(DecodeError::WriteSize(MAX_WRITE + 1).errno(), Errno::EINVAL);
        // A zero-length write is a request like any other.
        ok(&request(op(Opcode::Write), 0, &[&write_in(0)]));
    }

    #[test]
    fn test_batch_forget_count_times_16() {
        let forget = |count: u32, records: &[u8]| {
            request(op(Opcode::BatchForget), 0, &[&le32(count), &[0; 4], records])
        };
        let records = [le64(5), le64(1), le64(6), le64(2)].concat();
        let bytes = forget(2, &records);
        let Op::BatchForget(f) = ok(&bytes) else {
            panic!()
        };
        assert_eq!(f.len(), 2);
        assert_eq!(f.iter().collect::<Vec<_>>(), vec![(5, 1), (6, 2)]);
        let bytes = forget(0, &[]);
        let Op::BatchForget(f) = ok(&bytes) else {
            panic!()
        };
        assert!(f.is_empty());
        for (count, len) in [(2, 31), (2, 33), (1, 32), (3, 32), (u32::MAX, 32), (0x1000_0000, 0)] {
            assert_eq!(
                err(&forget(count, &vec![0; len])),
                DecodeError::Args(Opcode::BatchForget, "records of another length than count × 16"),
                "{count} {len}"
            );
        }
        assert!(!Opcode::BatchForget.has_reply());
        assert!(!Opcode::Forget.has_reply());
    }

    #[test]
    fn test_setxattr_layout_follows_init() {
        let ext = Wire {
            setxattr_ext: true,
            ..Wire::default()
        };
        let short = request(
            op(Opcode::Setxattr),
            0,
            &[&le32(3), &le32(1), b"user.a\0", b"abc"],
        );
        let Op::Setxattr {
            flags,
            setxattr_flags,
            name,
            value,
        } = ok(&short)
        else {
            panic!()
        };
        assert_eq!((flags, setxattr_flags, name.as_bytes(), value), (1, 0, &b"user.a"[..], &b"abc"[..]));
        let long = request(
            op(Opcode::Setxattr),
            0,
            &[&le32(3), &le32(1), &le32(1), &[0; 4], b"user.a\0", b"abc"],
        );
        let Op::Setxattr { setxattr_flags, .. } = ok_with(&long, &ext) else {
            panic!()
        };
        assert_eq!(setxattr_flags, 1);
        // Each read with the other layout is refused: the value is not its
        // size, or the name runs past its NUL.
        assert_eq!(
            err(&long),
            DecodeError::Args(Opcode::Setxattr, "a value of another length than its size")
        );
        assert_eq!(
            err_with(&short, &ext),
            DecodeError::Args(Opcode::Setxattr, "a string without its NUL")
        );

        let set = |size: u32, name: &[u8], value: &[u8]| {
            request(op(Opcode::Setxattr), 0, &[&le32(size), &le32(0), name, value])
        };
        assert_eq!(
            err(&set(4, b"user.a\0", b"abc")),
            DecodeError::Args(Opcode::Setxattr, "a value of another length than its size")
        );
        let max = vec![0u8; XATTR_SIZE_MAX];
        ok(&set(65536, b"user.a\0", &max));
        let over = vec![0u8; XATTR_SIZE_MAX + 1];
        assert_eq!(err(&set(65537, b"user.a\0", &over)), DecodeError::XattrValue(65537));
        assert_eq!(DecodeError::XattrValue(65537).errno(), Errno::E2BIG);
        assert_eq!(
            err(&set(0, b"\0", b"")),
            DecodeError::Args(Opcode::Setxattr, "an empty attribute name")
        );
        let long_name = [vec![b'u'; XATTR_NAME_MAX + 1], vec![0]].concat();
        assert_eq!(
            err(&set(0, &long_name, b"")),
            DecodeError::TooLong(Opcode::Setxattr, "attribute name")
        );
        let max_name = [vec![b'u'; XATTR_NAME_MAX], vec![0]].concat();
        ok(&set(0, &max_name, b""));

        let get = request(op(Opcode::Getxattr), 0, &[&le32(64), &[0; 4], b"user.b\0"]);
        let Op::Getxattr { size, name } = ok(&get) else {
            panic!()
        };
        assert_eq!((size, name.as_bytes()), (64, &b"user.b"[..]));
        assert_eq!(
            err(&request(op(Opcode::Getxattr), 0, &[&le32(64), &[0; 4], b"user.b"])),
            DecodeError::Args(Opcode::Getxattr, "a string without its NUL")
        );
        let bytes = request(op(Opcode::Removexattr), 0, &[b"user.c\0"]);
        let Op::Removexattr { name } = ok(&bytes)
        else {
            panic!()
        };
        assert_eq!(name.as_bytes(), b"user.c");
    }

    #[test]
    fn test_init_takes_the_old_and_the_new_layout() {
        let head = [le32(7), le32(47), le32(65536), le32(0x8000_0001)].concat();
        let Op::Init(old) = ok(&request(op(Opcode::Init), 0, &[&head])) else {
            panic!()
        };
        assert_eq!(
            old,
            InitIn {
                major: 7,
                minor: 47,
                max_readahead: 65536,
                flags: 0x8000_0001,
                flags2: 0
            }
        );
        let full = [&head[..], &le32(0x55), &[0; 44]].concat();
        let Op::Init(new) = ok(&request(op(Opcode::Init), 0, &[&full])) else {
            panic!()
        };
        assert_eq!(new.flags2, 0x55);
        // A later guest's longer struct: the fields this server knows.
        let later = [&full[..], &[9; 16]].concat();
        let Op::Init(later) = ok(&request(op(Opcode::Init), 0, &[&later])) else {
            panic!()
        };
        assert_eq!(later, new);
        for len in [0, 15, 17, 63] {
            let bytes = vec![0u8; len];
            let e = err(&request(op(Opcode::Init), 0, &[&bytes]));
            assert!(matches!(e, DecodeError::Args(Opcode::Init, _)), "{len}: {e:?}");
        }
    }

    #[test]
    fn test_unimplemented_and_unknown_opcodes_are_enosys() {
        // Refused before their arguments are read: any bytes.
        for o in [
            Opcode::Ioctl,
            Opcode::Poll,
            Opcode::NotifyReply,
            Opcode::SetupMapping,
            Opcode::RemoveMapping,
            Opcode::Tmpfile,
            Opcode::CuseInit,
        ] {
            for args in [&b""[..], b"\xff\xff\xff", &[0; 200]] {
                let e = err(&request(op(o), 0, &[args]));
                assert_eq!(e, DecodeError::Unsupported(o));
                assert_eq!(e.errno(), Errno::ENOSYS);
            }
        }
        // Gaps in the numbering, past the end, and the byte-swapped INITs
        // fuse.h reserves.
        for value in [0, 7, 19, 54, 4095, 4097, 1_048_576, 436_207_616, u32::MAX] {
            assert_eq!(Opcode::from_wire(value), None);
            let e = err(&request(value, 0, &[]));
            assert_eq!(e, DecodeError::UnknownOpcode(value));
            assert_eq!(e.errno(), Errno::ENOSYS);
        }
        // Every opcode number round-trips.
        for value in 0..=4096 {
            if let Some(o) = Opcode::from_wire(value) {
                assert_eq!(o as u32, value);
            }
        }
    }

    #[test]
    fn test_extensions_are_bounded_and_negotiated() {
        let on = Wire {
            extensions: true,
            ..Wire::default()
        };
        // FUSE_EXT_GROUPS with one group: a 16-byte extension
        // (fs/fuse/dir.c `get_create_supp_group`).
        let groups = [le32(16), le32(32), le32(1), le32(1234)].concat();
        let mkdir = request(op(Opcode::Mkdir), 2, &[&[0; 8], b"d\0", &groups]);
        let r = decode(&mkdir, &on).unwrap();
        let Op::Mkdir { name, .. } = r.op else {
            panic!()
        };
        assert_eq!(name.as_str(), "d");
        let got: Vec<(u32, &[u8])> = r.extensions.iter().collect();
        assert_eq!(got, vec![(32, &groups[8..])]);

        // Not negotiated: refused.
        assert_eq!(
            err(&mkdir),
            DecodeError::Extensions("not negotiated")
        );
        // On an opcode the kernel never extends.
        let lookup = request(op(Opcode::Lookup), 2, &[b"d\0", &groups]);
        assert_eq!(
            err_with(&lookup, &on),
            DecodeError::Extensions("on a request that takes none")
        );
        // Longer than the request.
        let past = request(op(Opcode::Mkdir), 200, &[&[0; 8], b"d\0", &groups]);
        assert_eq!(
            err_with(&past, &on),
            DecodeError::Extensions("longer than the request")
        );
        // A chain that is not one.
        for (size, why) in [
            (0, "a size below 8 or not a multiple of 8"),
            (4, "a size below 8 or not a multiple of 8"),
            (12, "a size below 8 or not a multiple of 8"),
            (24, "a size past the end"),
            (u32::MAX, "a size below 8 or not a multiple of 8"),
        ] {
            let bad = [le32(size), le32(32), le32(1), le32(1234)].concat();
            let bytes = request(op(Opcode::Mkdir), 2, &[&[0; 8], b"d\0", &bad]);
            assert_eq!(err_with(&bytes, &on), DecodeError::Extensions(why), "{size}");
        }
        // Two extensions back to back.
        let two = [&groups[..], &le32(8), &le32(0)].concat();
        let bytes = request(op(Opcode::Create), 3, &[&[0; 16], b"f\0", &two]);
        let r = decode(&bytes, &on).unwrap();
        assert_eq!(r.extensions.iter().count(), 2);
        // The extensions are cut from the end: a name that runs into them
        // has no NUL of its own.
        let bytes = request(op(Opcode::Mkdir), 2, &[&[0; 8], b"d", &groups]);
        assert_eq!(
            err_with(&bytes, &on),
            DecodeError::Args(Opcode::Mkdir, "a string without its NUL")
        );
    }

    #[test]
    fn test_every_known_opcode_decodes_without_panicking_on_any_short_input() {
        // Each opcode with 0..=128 bytes of arguments of each fill: an
        // error or a request, never a panic (the fuzz target fs_decode goes
        // further).
        for value in 0..=60 {
            for len in 0..=128 {
                for fill in [0u8, 0xff, b'a'] {
                    let args = vec![fill; len];
                    let _ = decode(&request(value, 0, &[&args]), &Wire::default());
                }
            }
        }
    }
}
