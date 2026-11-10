// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The standard library, with `std::os::unix` and `std::os::fd` on Windows.
//!
//! A crate root that declares
//!
//! ```ignore
//! #[cfg(windows)]
//! extern crate wick_std as std;
//! ```
//!
//! resolves every `std::` path in the crate through this crate: everything
//! is the real standard library (re-exported), except that `std::os` also
//! has `unix` and `fd` from `wick_os`, wick's implementation of them on
//! Windows. Macros (`println!`, `vec!`, ...) still come from the real `std`.
//!
//! On Windows `std::os::raw::c_long` and `c_ulong` are also 64 bits wide: the
//! upstream crates use them in bindings of Linux kernel ABIs (`ifreq`,
//! io_uring, ...), whose layout is LP64; LLP64 Windows would make them 32
//! bits and change those layouts. The compatibility kvm-bindings fix them the
//! same way. Nothing in those crates calls a Windows C API with them.
//!
//! On other systems the real modules are re-exported unchanged.

pub use std::*;

/// `std::os`, plus `unix` and `fd` on Windows.
pub mod os {
    pub use std::os::*;

    #[cfg(windows)]
    pub use wick_os::{fd, unix};

    /// `std::os::raw`, with 64-bit `c_long` and `c_ulong` on Windows.
    #[cfg(windows)]
    pub mod raw {
        pub use std::os::raw::*;

        /// `long` of the Linux LP64 ABI.
        #[allow(non_camel_case_types)]
        pub type c_long = i64;
        /// `unsigned long` of the Linux LP64 ABI.
        #[allow(non_camel_case_types)]
        pub type c_ulong = u64;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_reexports_std() {
        let v: super::vec::Vec<u8> = super::vec![1];
        assert_eq!(super::mem::size_of_val(&v[0]), 1);
        #[cfg(windows)]
        let _: Option<super::os::unix::net::UnixStream> = None;
        #[cfg(windows)]
        assert_eq!(super::mem::size_of::<super::os::raw::c_ulong>(), 8);
        assert_eq!(super::mem::size_of::<super::os::raw::c_int>(), 4);
    }
}
