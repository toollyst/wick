// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! wick's release version, `<upstream>-wick.<N>` (for example `1.18.0-wick.1`):
//! the upstream Firecracker release in `patches/base` and wick's own number in
//! `patches/version`, read at build time (`build.rs`).
//!
//! It is a release label only. Format and compatibility versions (snapshot
//! format, API specification, CPU template fingerprints) stay upstream's.
//!
//! [`version!`] expands to a string literal, so it works wherever
//! `env!("CARGO_PKG_VERSION")` does, `concat!` included.

include!(concat!(env!("OUT_DIR"), "/version.rs"));

/// The full version, `<upstream>-wick.<N>`.
pub const VERSION: &str = version!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_semver() {
        let v = semver::Version::parse(VERSION).unwrap();
        assert_eq!(v.pre.as_str(), format!("wick.{NUMBER}"));
        assert!(v.build.is_empty());
        assert_eq!(format!("{}.{}.{}", v.major, v.minor, v.patch), UPSTREAM);
    }

    #[test]
    fn test_version_macro_is_a_literal() {
        assert_eq!(concat!("v", version!()), format!("v{VERSION}"));
    }
}
