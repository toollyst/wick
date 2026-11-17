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
//! The host backends, confinement and the serving loop come in later
//! commits; nothing here touches a host file system.

pub mod cache;
pub mod dir;
pub mod fuse;
pub mod handles;
pub mod inodes;
pub mod limits;
pub mod memdir;
pub mod record;
pub mod session;
