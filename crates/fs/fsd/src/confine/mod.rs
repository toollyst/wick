// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Stage 1's confinement, per host (docs/design-fs.md §6): Linux's and
//! macOS's. Windows has none yet, and wick-fsd refuses to serve there (it
//! has no unconfined mode).

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(unix)]
use std::os::fd::RawFd;

#[cfg(unix)]
use wick_fs_sys as sys;

#[cfg(unix)]
use crate::host::unix::Refusal;

/// The descriptors `open` are exactly the standard streams and `expected`:
/// one refusal naming each other one (what it is, `descriptor_described`)
/// and each expected one not open, `when`.
#[cfg(unix)]
pub fn held_exactly(when: &str, open: &[RawFd], expected: &[RawFd]) -> Result<(), Refusal> {
    held_exactly_named(when, open, expected, sys::descriptor_described)
}

/// [`held_exactly`], each other descriptor named by `name`: on macOS under
/// the profile its kind alone (`descriptor_kind`), as the profile kills the
/// `fcntl` that asks for a descriptor's path.
#[cfg(unix)]
pub fn held_exactly_named(
    when: &str,
    open: &[RawFd],
    expected: &[RawFd],
    name: fn(RawFd) -> String,
) -> Result<(), Refusal> {
    let expected: Vec<RawFd> = [0, 1, 2].iter().chain(expected).copied().collect();
    let other: Vec<String> = open.iter().filter(|fd| !expected.contains(fd)).map(|&fd| name(fd)).collect();
    let missing: Vec<RawFd> = expected.iter().filter(|fd| !open.contains(fd)).copied().collect();
    let mut not = Vec::new();
    if !other.is_empty() {
        not.push(format!("descriptors open that wick-fsd did not open or keep: {}", other.join(", ")));
    }
    if !missing.is_empty() {
        not.push(format!("descriptors it holds that are not open: {missing:?}"));
    }
    if not.is_empty() {
        return Ok(());
    }
    Err(Refusal(format!("confinement: {when}, {}; wick-fsd does not serve unconfined", not.join("; "))))
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn test_descriptors_held_exactly() {
        held_exactly("t", &[0, 1, 2, 5, 9], &[9, 5]).unwrap();
        let r = held_exactly("before pivot_root", &[0, 1, 2, 5, 9, 131], &[5, 9]).unwrap_err().0;
        assert!(r.contains("before pivot_root, descriptors open that wick-fsd did not open or keep: 131: "), "{r}");
        assert!(r.contains("does not serve unconfined") && !r.contains("not open: ["), "{r}");
        let r = held_exactly("t", &[0, 1, 2, 7], &[5]).unwrap_err().0;
        assert!(r.contains("7: ") && r.contains("descriptors it holds that are not open: [5]"), "{r}");
        let r = held_exactly("t", &[0, 2, 5], &[5]).unwrap_err().0;
        assert!(r.contains("not open: [1]"), "{r}");
    }
}
