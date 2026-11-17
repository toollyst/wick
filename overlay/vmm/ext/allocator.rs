// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The heap's allocator of every Windows binary that links the VMM
//! (Firecracker's included): wick's (`libc::wick_alloc`), the system's
//! heap with what Linux's memory cgroup does at a charge it cannot make: an
//! allocation the memory limit refuses asks the reclaim once, then ends the
//! VMM with 137 and a line, where Rust's allocation error would end it with
//! 0xC0000409 and no reclaim. On success it costs the check of the system
//! call's result only.
//!
//! Firecracker says at its start which allocator it runs with ([`say`]),
//! from the allocator itself (`libc::wick_alloc::installed`), and
//! `boot-test.ps1`'s boot stage checks the line, so that the tests of the
//! allocator (`libc`'s `test_a_heap_allocation_*`) are of the one the
//! binary uses.

#[global_allocator]
static ALLOCATOR: libc::wick_alloc::Allocator = libc::wick_alloc::Allocator;

/// Says which allocator the process's heap runs with: wick's, as an info
/// line, else an error line (a build that lost [`ALLOCATOR`]).
pub fn say() {
    if libc::wick_alloc::installed() {
        crate::logger::info_unrestricted!(
            "wick: the heap's allocator is wick's: an allocation the memory limit refuses reclaims once, then ends the VMM with 137"
        );
    } else {
        crate::logger::error_unrestricted!(
            "wick: the heap's allocator is not wick's: an allocation the memory limit refuses ends the VMM with 0xC0000409"
        );
    }
}

#[cfg(test)]
mod tests {
    /// The VMM's heap allocator is wick's, in the VMM's own test binary as in
    /// every binary that links the VMM.
    #[test]
    fn test_the_heaps_allocator_is_wicks() {
        assert!(libc::wick_alloc::installed());
    }
}
