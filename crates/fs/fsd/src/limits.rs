// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The server's own limits, the same numbers on every host
//! (docs/design-fs.md row 9 and §4, Limits), and the counters of what they
//! and the other checks refused.
//!
//! Each limit is checked before the work it bounds: a node is refused
//! before the backend creates or looks anything up for it (ENFILE), a
//! handle before the backend opens (EMFILE), bytes before they are written
//! (ENOSPC). The queue of requests is the serving loop's (a later commit).

/// Nodes the guest may hold at once, the root included.
pub const DEFAULT_MAX_NODES: usize = 1 << 16;

/// Handles the guest may hold open at once.
pub const DEFAULT_MAX_HANDLES: usize = 4096;

/// Bytes the guest's writes may add to the share in one run of the server
/// (docs/design-fs.md decision 7). Provisional, until the jailer's
/// `--fs-share` sets it per share.
pub const DEFAULT_MAX_BYTES: u64 = 64 << 30;

/// The largest READ or READDIR reply's data: `max_write`, the most one
/// frame holds after its headers.
pub const MAX_READ: usize = crate::fuse::MAX_WRITE as usize;

/// Guest extended attributes a node may hold, counted as the stored
/// encoding would be (per attribute 4 bytes of lengths, the name and the
/// value). Provisional (docs/design-fs.md §4.2, Limits): set to what a
/// default host file system holds beside the record once that is measured;
/// ext4 keeps all of a file's attributes in one block, 4 KiB by default.
pub const DEFAULT_XATTR_BUDGET: usize = 3 << 10;

/// The limits of one share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Nodes held at once (ENFILE beyond).
    pub max_nodes: usize,
    /// Handles open at once (EMFILE beyond).
    pub max_handles: usize,
    /// Bytes the guest may add (ENOSPC beyond).
    pub max_bytes: u64,
    /// Encoded extended attribute bytes per node (ENOSPC beyond).
    pub xattr_budget: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_nodes: DEFAULT_MAX_NODES,
            max_handles: DEFAULT_MAX_HANDLES,
            max_bytes: DEFAULT_MAX_BYTES,
            xattr_budget: DEFAULT_XATTR_BUDGET,
        }
    }
}

/// What the server refused or found, for the metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Requests the decoder refused.
    pub requests_refused: u64,
    /// New nodes refused at the node limit.
    pub nodes_refused: u64,
    /// Opens refused at the handle limit.
    pub handles_refused: u64,
    /// Writes, truncations and allocations refused at the byte limit.
    pub bytes_refused: u64,
    /// Attribute writes refused at the attribute budget.
    pub xattr_refused: u64,
    /// Stored records refused as malformed or of the wrong type.
    pub records_refused: u64,
    /// Host names not shown because they are not guest names.
    pub names_skipped: u64,
    /// Refusals from layer 2 or 3 (each one a layer 1 gap).
    pub layer_refusals: u64,
    /// FORGETs of a node the server does not hold, or of more lookups
    /// than it has.
    pub forgets_unmatched: u64,
    /// Requests whose reply did not fit the guest's buffers.
    pub replies_too_long: u64,
}
