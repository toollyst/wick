// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick-fsd, the file server behind wick's virtio-fs device
//! (docs/design-fs.md): one process per shared host directory, which parses
//! the guest's FUSE requests, never sees guest memory and confines itself
//! before it serves.
//!
//! So far: [`fuse`], the bounded decoder of requests, the encoder of
//! replies and the rules for guest names, the same code on every host.

pub mod fuse;
