// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `kvm-bindings` 0.14 for wick.
//!
//! - Linux, macOS: the upstream crate (the kvm-ioctls tag), re-exported as is.
//! - Windows: the same x86_64 bindings with `c_ulong`/`c_long` as `u64`/`i64`,
//!   so the structures keep their Linux x86_64 layout on an LLP64 host.

// The generated bindings have identifiers that look alike (as upstream).
#![cfg_attr(windows, allow(confusable_idents))]

#[cfg(not(windows))]
pub use upstream::*;

#[cfg(windows)]
#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    clippy::all
)]
mod windows {
    #[cfg(feature = "serde")]
    #[macro_use]
    #[path = "serialize.rs"]
    mod serialize;

    #[path = "x86_64/mod.rs"]
    mod x86_64;
    pub use self::x86_64::*;
}
#[cfg(windows)]
pub use windows::*;
