// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The jailer's `--resource-limit no-file=` for the descriptors this crate
//! makes, and wick-std's `std::fs` shadow.
//!
//! The limit and its semantics are the compat libc's `wick_nofile`
//! (crates/compat/libc/src/windows_nofile.rs, where they are documented): a
//! number of handles of the process, from `WICK_NO_FILE`, which the Windows
//! jailer sets; a call that would make descriptors past it fails with
//! `EMFILE` (`WSAEMFILE`, the compat libc's `EMFILE`) before it makes
//! anything. This crate reads the variable the same way, once.

use std::ffi::OsStr;
use std::io;
use std::sync::OnceLock;

use windows_sys::Win32::Networking::WinSock::WSAEMFILE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

/// The environment variable the Windows jailer gives the limit in.
pub const ENV: &str = "WICK_NO_FILE";

/// `EMFILE`: the compat libc's value, Winsock's `WSAEMFILE`.
pub const EMFILE: i32 = WSAEMFILE;

static LIMIT: OnceLock<Option<u64>> = OnceLock::new();

/// The limit [`ENV`] gives: `None` without it, 0 (every descriptor refused)
/// for a value that is no number, as the compat libc reads it.
pub fn parse(value: Option<&OsStr>) -> Option<u64> {
    let value = value?;
    if let Some(n) = value.to_str().and_then(|v| v.parse::<u64>().ok()) {
        return Some(n);
    }
    eprintln!("{ENV}={}: not a number of handles; every descriptor is refused (EMFILE)", value.to_string_lossy());
    Some(0)
}

/// This process's limit, read from [`ENV`] once.
pub fn limit() -> Option<u64> {
    *LIMIT.get_or_init(|| parse(std::env::var_os(ENV).as_deref()))
}

/// The handles this process holds, as Windows counts them.
pub fn handles() -> Option<u64> {
    let mut n = 0u32;
    // SAFETY: the current process's pseudo handle and an out-parameter.
    (unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) } != 0).then_some(u64::from(n))
}

/// `Ok` when `n` more descriptors fit under the limit, else `EMFILE`. One
/// `GetProcessHandleCount` when a limit is set, nothing otherwise.
pub fn check(n: u64) -> io::Result<()> {
    let Some(limit) = limit() else {
        return Ok(());
    };
    if handles().is_some_and(|count| count.saturating_add(n) <= limit) {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(EMFILE))
    }
}
