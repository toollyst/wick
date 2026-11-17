// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! FUSE as a guest's virtio-fs driver speaks it: the requests a frame's
//! payload holds ([`decode`]), the replies the server writes back
//! ([`encode`]) and the names in requests ([`name`]).
//!
//! The layout is Linux's `include/uapi/linux/fuse.h`, protocol 7.47
//! (Linux 666539eecdf4). The guest is little-endian on every architecture
//! wick runs (x86_64, aarch64), so every field is read and written
//! little-endian. Errors go back as the guest's errno values, Linux's,
//! whatever the host's are ([`Errno`]).

pub mod decode;
pub mod encode;
pub mod name;

use std::fmt;

/// The FUSE major version this server speaks.
pub const KERNEL_VERSION: u32 = 7;

/// The newest FUSE minor version whose layout this module has.
pub const KERNEL_MINOR_VERSION: u32 = 47;

/// Bytes in `fuse_in_header`.
pub const IN_HEADER_LEN: usize = 40;

/// Bytes in `fuse_out_header`.
pub const OUT_HEADER_LEN: usize = 16;

/// The most data one `WRITE` carries, and the `max_write` the server offers
/// in INIT: 1 MiB, virtiofsd's `MAX_BUFFER_SIZE`. A frame holds it with its
/// headers (`wick_fs_frame::MAX_PAYLOAD_LEN`).
pub const MAX_WRITE: u32 = 1 << 20;

/// The longest extended attribute name, Linux's `XATTR_NAME_MAX`.
pub const XATTR_NAME_MAX: usize = 255;

/// The largest extended attribute value, Linux's `XATTR_SIZE_MAX`.
pub const XATTR_SIZE_MAX: usize = 1 << 16;

/// The longest symlink target with its NUL, Linux's `PATH_MAX`.
pub const PATH_MAX: usize = 4096;

const _: () = assert!(
    IN_HEADER_LEN + 40 + MAX_WRITE as usize <= wick_fs_frame::MAX_PAYLOAD_LEN
);
const _: () = assert!(OUT_HEADER_LEN + MAX_WRITE as usize <= wick_fs_frame::MAX_PAYLOAD_LEN);

/// An error as the guest's kernel numbers it: Linux's values, the same on
/// x86_64 and aarch64 (`include/uapi/asm-generic/errno-base.h`, `errno.h`).
/// A host error is translated to one of these, never sent as the host's
/// number (macOS's ENOSYS is 78, Linux's 38).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Errno(i32);

macro_rules! errnos {
    ($($name:ident = $value:literal,)*) => {
        impl Errno {
            $(
                #[doc = concat!("Linux's `", stringify!($name), "`.")]
                pub const $name: Errno = Errno($value);
            )*

            /// The errno with Linux's number `value`, if this module names it.
            pub fn from_linux(value: i32) -> Option<Errno> {
                match value {
                    $($value => Some(Errno::$name),)*
                    _ => None,
                }
            }

            fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some(stringify!($name)),)*
                    _ => None,
                }
            }
        }
    };
}

errnos! {
    EPERM = 1,
    ENOENT = 2,
    EINTR = 4,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    EBADF = 9,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ETXTBSY = 26,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    EMLINK = 31,
    ERANGE = 34,
    ENAMETOOLONG = 36,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
    ENODATA = 61,
    EPROTO = 71,
    EOVERFLOW = 75,
    EILSEQ = 84,
    EOPNOTSUPP = 95,
    ESTALE = 116,
}

impl Errno {
    /// The positive value.
    pub fn get(self) -> i32 {
        self.0
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "Errno({})", self.0),
        }
    }
}

macro_rules! opcodes {
    ($($name:ident = $value:literal,)*) => {
        /// A FUSE request's opcode (`enum fuse_opcode`).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Opcode {
            $($name = $value,)*
        }

        impl Opcode {
            /// The opcode with this number, if FUSE has one.
            pub fn from_wire(value: u32) -> Option<Opcode> {
                match value {
                    $($value => Some(Opcode::$name),)*
                    _ => None,
                }
            }
        }
    };
}

opcodes! {
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Symlink = 6,
    Mknod = 8,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Link = 13,
    Open = 14,
    Read = 15,
    Write = 16,
    Statfs = 17,
    Release = 18,
    Fsync = 20,
    Setxattr = 21,
    Getxattr = 22,
    Listxattr = 23,
    Removexattr = 24,
    Flush = 25,
    Init = 26,
    Opendir = 27,
    Readdir = 28,
    Releasedir = 29,
    Fsyncdir = 30,
    Getlk = 31,
    Setlk = 32,
    Setlkw = 33,
    Access = 34,
    Create = 35,
    Interrupt = 36,
    Bmap = 37,
    Destroy = 38,
    Ioctl = 39,
    Poll = 40,
    NotifyReply = 41,
    BatchForget = 42,
    Fallocate = 43,
    Readdirplus = 44,
    Rename2 = 45,
    Lseek = 46,
    CopyFileRange = 47,
    SetupMapping = 48,
    RemoveMapping = 49,
    Syncfs = 50,
    Tmpfile = 51,
    Statx = 52,
    CopyFileRange64 = 53,
    CuseInit = 4096,
}

impl Opcode {
    /// Whether the guest waits for a reply: all but `FORGET` and
    /// `BATCH_FORGET` (fuse.h: "no reply").
    pub fn has_reply(self) -> bool {
        !matches!(self, Opcode::Forget | Opcode::BatchForget)
    }

    /// Opcodes this server never implements, answered `ENOSYS` without
    /// reading their arguments (docs/design-fs.md §6, FUSE decoder): DAX's
    /// mappings (no DAX window), ioctls, poll and its notify replies,
    /// `O_TMPFILE` and CUSE.
    pub fn is_unsupported(self) -> bool {
        matches!(
            self,
            Opcode::Ioctl
                | Opcode::Poll
                | Opcode::NotifyReply
                | Opcode::SetupMapping
                | Opcode::RemoveMapping
                | Opcode::Tmpfile
                | Opcode::CuseInit
        )
    }
}

/// `fuse_in_header`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InHeader {
    /// The request's bytes, this header included.
    pub len: u32,
    /// The opcode as sent; [`Opcode::from_wire`] names it.
    pub opcode: u32,
    /// The guest's id of the request, which the reply carries back.
    pub unique: u64,
    /// The node the request is about (the server's id, from an earlier
    /// reply; 0 in INIT).
    pub nodeid: u64,
    /// The caller's uid in the guest.
    pub uid: u32,
    /// The caller's gid in the guest.
    pub gid: u32,
    /// The caller's pid in the guest.
    pub pid: u32,
    /// The extensions at the end of the request, in units of 8 bytes.
    pub total_extlen: u16,
}
