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

/// Nodes the guest may hold at once, the root included. With
/// [`DEFAULT_MAX_HANDLES`] and [`SPARE_FDS`], 9280 descriptors at most
/// ([`descriptors`]): under [`LOWEST_STOCK_NOFILE`] with 960 to spare, so a
/// default share starts on every stock host (docs/design-fs.md §4.2,
/// Limits).
pub const DEFAULT_MAX_NODES: usize = 8192;

/// Handles the guest may hold open at once.
pub const DEFAULT_MAX_HANDLES: usize = 1024;

/// Descriptors the server may have open besides one per node and one per
/// handle: the standard streams, the connection, and those a request opens
/// and closes before its reply (a directory reopened to list or search it,
/// a descriptor for metadata, a directory opened by a lookup before its
/// node is added).
pub const SPARE_FDS: u64 = 64;

/// The lowest per-process descriptor limit of the stock hosts the server
/// runs on: macOS on a Mac with 8 GB of memory or less, whose
/// `kern.maxfilesperproc` is `OPEN_MAX` (xnu `bsd_scale_setup` scales it
/// only above 8 GB; GitHub's macos-latest runner has 7 GB). Linux's stock
/// hard limits are higher: 65536 on GitHub's ubuntu runners, 524288 for a
/// systemd service or a login shell (`DefaultLimitNOFILE=1024:524288`).
pub const LOWEST_STOCK_NOFILE: u64 = 10240;

/// The most descriptors a share with `limits` can hold open at once: one
/// per node (a directory's own; a leaf's widest open, once opened), one per
/// handle, and [`SPARE_FDS`]. Stage 0 refuses a share whose host limit is
/// below it, so the server never meets EMFILE itself.
pub fn descriptors(limits: &Limits) -> u64 {
    u64::try_from(limits.max_nodes)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(limits.max_handles).unwrap_or(u64::MAX))
        .saturating_add(SPARE_FDS)
}

/// Bytes the guest's writes may add to the share in one run of the server
/// (docs/design-fs.md decision 7). Provisional, until the jailer's
/// `--fs-share` sets it per share.
pub const DEFAULT_MAX_BYTES: u64 = 64 << 30;

/// The largest READ or READDIR reply's data: `max_write`, the most one
/// frame holds after its headers.
pub const MAX_READ: usize = crate::fuse::MAX_WRITE as usize;

/// What one guest extended attribute costs against the budget besides its
/// name and value: at least what the tightest default host file system
/// spends on an entry. ext4 spends 16 bytes of entry, the `wick.x.` part of
/// the name and padding of both to 4 bytes, at most 29 bytes beyond the name
/// and value (docs/design-fs.md §4.2, Limits; measured by
/// tools/linux/xattr-budget.sh).
pub const XATTR_ENTRY_COST: usize = 32;

/// Guest extended attribute bytes a node may hold, each attribute charged
/// [`XATTR_ENTRY_COST`] + its name + its value. 3 KiB: what default ext4
/// holds beside the record, the least of the default Linux file systems
/// (one 4028-byte value or 146 empty attributes, charged 4066 and 5002;
/// docs/design-fs.md §4.2, Limits), less room for the host's own attributes
/// (an SELinux label, ACLs).
pub const DEFAULT_XATTR_BUDGET: usize = 3 << 10;

/// The longest guest extended attribute name, in bytes, on every host
/// (ERANGE beyond, as Linux's for a name over 255): macOS stores names of at
/// most 127 bytes (`XATTR_MAXNAMELEN`), less the 7 of the `wick.x.` prefix
/// (docs/design-fs.md §4.2, Limits).
pub const GUEST_XATTR_NAME_MAX: usize = 120;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A default share starts on every stock host: its most descriptors fit
    /// the lowest stock limit (a Mac's `kern.maxfilesperproc` of 10240) and
    /// so GitHub's ubuntu runners' hard limit of 65536 (CI run 44188936001
    /// refused the old defaults' 69696 there).
    #[test]
    fn test_default_limits_fit_stock_hosts() {
        let need = descriptors(&Limits::default());
        assert_eq!(need, 9280);
        assert!(need <= LOWEST_STOCK_NOFILE, "{need} > {LOWEST_STOCK_NOFILE}");
        assert!(need <= 65536, "{need} > 65536");
    }

    #[test]
    fn test_descriptors_saturate() {
        let l = Limits {
            max_nodes: usize::MAX,
            ..Limits::default()
        };
        assert_eq!(descriptors(&l), u64::MAX);
    }
}
