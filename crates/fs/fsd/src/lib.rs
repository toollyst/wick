// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick-fsd, the file server behind wick's virtio-fs device
//! (docs/design-fs.md): one process per shared host directory, which parses
//! the guest's FUSE requests, never sees guest memory and confines itself
//! before it serves.
//!
//! So far, the same code on every host:
//! - [`fuse`]: the bounded decoder of requests, the encoder of replies and
//!   the rules for guest names;
//! - [`session`]: the server core, over [`dir::ConfinedDir`], with its node
//!   and handle tables ([`inodes`], [`handles`]), [`limits`], the metadata
//!   [`record`] and the [`cache`] modes;
//! - [`memdir`]: an in-memory `ConfinedDir` for tests and fuzzing.
//!
//! The host directory, on Linux and macOS (the Windows one comes with its
//! port): [`host`]'s `HostDir`, over the system calls of the `wick-fs-sys`
//! crate, and `stage0`, the share's checks before anything is served.
//!
//! The server: [`serve`], the loop over one connection's frames, and
//! [`confine`], stage 1's confinement (Linux; macOS's comes with its own
//! commit). The `wick-fsd` binary (`src/main.rs`) puts them together; on a
//! host without confinement it refuses to start.

pub mod cache;
pub mod confine;
pub mod dir;
pub mod fuse;
pub mod handles;
pub mod host;
pub mod inodes;
pub mod limits;
pub mod memdir;
pub mod record;
pub mod serve;
pub mod session;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod stage0;
