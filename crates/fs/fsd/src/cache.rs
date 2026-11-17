// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! How long the guest may keep what the server tells it, per share
//! (docs/design-fs.md §4.4; the names are virtiofsd's `cache=`). The guest has
//! no mount option for it: it caches what each reply allows.
//!
//! - `never`: timeouts 0, `FOPEN_DIRECT_IO` on every open, no negative
//!   entries. Every lookup, getattr, read and readdir reaches the host. A
//!   shared `mmap` of a file then fails in the guest unless it negotiates
//!   `FUSE_DIRECT_IO_ALLOW_MMAP` (7.39), which this server does not yet.
//! - `auto` (the default, [`DEFAULT_TIMEOUT_MS`]): entries, attributes and
//!   negative entries kept for the timeout; no `FOPEN_KEEP_CACHE`, so a file's
//!   pages are dropped at each open (close-to-open, as NFS);
//!   `FUSE_AUTO_INVAL_DATA`, so a getattr that sees a new mtime or size drops
//!   them too.
//! - `always`: the timeout (a day by default), `FOPEN_KEEP_CACHE` and
//!   `FOPEN_CACHE_DIR`: for shares nothing else changes.

use crate::fuse::encode::Valid;

/// The `auto` timeout: 1 s (docs/design-fs.md §4.4; provisional until
/// host-edit latency is measured against it, §10 question 10).
pub const DEFAULT_TIMEOUT_MS: u32 = 1000;

/// The longest timeout a share may set: a day.
pub const MAX_TIMEOUT_MS: u32 = 24 * 60 * 60 * 1000;

/// `FOPEN_DIRECT_IO`.
pub const FOPEN_DIRECT_IO: u32 = 1 << 0;
/// `FOPEN_KEEP_CACHE`.
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;
/// `FOPEN_CACHE_DIR`.
pub const FOPEN_CACHE_DIR: u32 = 1 << 3;
/// `FUSE_AUTO_INVAL_DATA`.
pub const FUSE_AUTO_INVAL_DATA: u32 = 1 << 12;

/// A share's cache mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheMode {
    /// Nothing kept.
    Never,
    /// Kept for `timeout_ms`; file pages dropped at open.
    Auto {
        /// Milliseconds, at most [`MAX_TIMEOUT_MS`].
        timeout_ms: u32,
    },
    /// Kept for `timeout_ms` with file pages and directory listings.
    Always {
        /// Milliseconds, at most [`MAX_TIMEOUT_MS`].
        timeout_ms: u32,
    },
}

impl Default for CacheMode {
    fn default() -> CacheMode {
        CacheMode::Auto {
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

impl CacheMode {
    /// The mode, with its timeout clamped to [`MAX_TIMEOUT_MS`].
    pub fn clamped(self) -> CacheMode {
        match self {
            CacheMode::Never => CacheMode::Never,
            CacheMode::Auto { timeout_ms } => CacheMode::Auto {
                timeout_ms: timeout_ms.min(MAX_TIMEOUT_MS),
            },
            CacheMode::Always { timeout_ms } => CacheMode::Always {
                timeout_ms: timeout_ms.min(MAX_TIMEOUT_MS),
            },
        }
    }

    fn timeout_ms(self) -> u32 {
        match self.clamped() {
            CacheMode::Never => 0,
            CacheMode::Auto { timeout_ms } | CacheMode::Always { timeout_ms } => timeout_ms,
        }
    }

    /// How long names and attributes may be kept (`entry_valid`,
    /// `attr_valid`).
    pub fn valid(self) -> Valid {
        let ms = self.timeout_ms();
        Valid {
            secs: u64::from(ms / 1000),
            nsecs: (ms % 1000) * 1_000_000,
        }
    }

    /// Whether a name that is not there is answered as a negative entry the
    /// guest keeps for [`CacheMode::valid`] (else ENOENT, kept for nothing).
    pub fn negative_entries(self) -> bool {
        self.timeout_ms() > 0
    }

    /// `fuse_open_out.open_flags` for a regular file (`dir` false) or a
    /// directory.
    pub fn open_flags(self, dir: bool) -> u32 {
        match (self, dir) {
            (CacheMode::Never, false) => FOPEN_DIRECT_IO,
            (CacheMode::Always { .. }, false) => FOPEN_KEEP_CACHE,
            (CacheMode::Always { .. }, true) => FOPEN_CACHE_DIR,
            (CacheMode::Never, true) | (CacheMode::Auto { .. }, _) => 0,
        }
    }

    /// INIT flags the mode asks for.
    pub fn init_flags(self) -> u32 {
        match self {
            CacheMode::Auto { .. } => FUSE_AUTO_INVAL_DATA,
            CacheMode::Never | CacheMode::Always { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_modes_give_their_timeouts_and_flags() {
        let never = CacheMode::Never;
        assert_eq!(never.valid(), Valid { secs: 0, nsecs: 0 });
        assert!(!never.negative_entries());
        assert_eq!(never.open_flags(false), FOPEN_DIRECT_IO);
        assert_eq!(never.open_flags(true), 0);
        assert_eq!(never.init_flags(), 0);

        let auto = CacheMode::default();
        assert_eq!(auto, CacheMode::Auto { timeout_ms: 1000 });
        assert_eq!(auto.valid(), Valid { secs: 1, nsecs: 0 });
        assert!(auto.negative_entries());
        assert_eq!(auto.open_flags(false), 0);
        assert_eq!(auto.open_flags(true), 0);
        assert_eq!(auto.init_flags(), FUSE_AUTO_INVAL_DATA);
        let ms = CacheMode::Auto { timeout_ms: 1500 };
        assert_eq!(ms.valid(), Valid { secs: 1, nsecs: 500_000_000 });
        let zero = CacheMode::Auto { timeout_ms: 0 };
        assert!(!zero.negative_entries());

        let always = CacheMode::Always {
            timeout_ms: u32::MAX,
        };
        assert_eq!(always.valid(), Valid { secs: 86_400, nsecs: 0 });
        assert_eq!(always.open_flags(false), FOPEN_KEEP_CACHE);
        assert_eq!(always.open_flags(true), FOPEN_CACHE_DIR);
        assert_eq!(always.init_flags(), 0);
    }
}
