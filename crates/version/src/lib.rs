// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick's release version: the upstream Firecracker release in `patches/base`
//! (`1.18.0`) when `patches/version` is 0, or `<upstream>+wick.<N>` (for example
//! `1.18.0+wick.1`) for wick's fix release N on it, read at build time
//! (`build.rs`). Build metadata keeps a fix release from sorting below the
//! upstream release (a semver pre-release, `1.18.0-wick.1`, would).
//!
//! It is a release label only. Format and compatibility versions (snapshot
//! format, API specification, CPU template fingerprints) stay upstream's.
//!
//! [`version!`] expands to a string literal, so it works wherever
//! `env!("CARGO_PKG_VERSION")` does, `concat!` included.

include!(concat!(env!("OUT_DIR"), "/version.rs"));

/// The full version, `<upstream>` or `<upstream>+wick.<N>`.
pub const VERSION: &str = version!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_semver() {
        let v = semver::Version::parse(VERSION).unwrap();
        assert!(v.pre.is_empty());
        assert_eq!(format!("{}.{}.{}", v.major, v.minor, v.patch), UPSTREAM);
        if NUMBER == 0 {
            assert!(v.build.is_empty());
        } else {
            assert_eq!(v.build.as_str(), format!("wick.{NUMBER}"));
        }
        // Never below the upstream release.
        assert!(v >= semver::Version::parse(UPSTREAM).unwrap());
    }

    #[test]
    fn test_version_macro_is_a_literal() {
        assert_eq!(concat!("v", version!()), format!("v{VERSION}"));
    }
}
