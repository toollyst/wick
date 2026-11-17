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
//! Firecracker says which allocator it runs with, from the allocator itself
//! (`libc::wick_alloc::installed`): a build that lost [`ALLOCATOR`] says so
//! at its start, as an error line ([`say_at_start`]); a correct one says it
//! at debug level when it builds a VM ([`say_at_build`]), after the logger
//! has its level, and `boot-test.ps1`'s boot stage, which runs Firecracker
//! at `--level Debug`, checks that line, so that the tests of the allocator
//! (`libc`'s `test_a_heap_allocation_*`) are of the one the binary uses.

#[global_allocator]
static ALLOCATOR: libc::wick_alloc::Allocator = libc::wick_alloc::Allocator;

/// At the start, before the logger has the level asked for: an error line
/// if the heap's allocator is not wick's, nothing if it is.
pub fn say_at_start() {
    if !libc::wick_alloc::installed() {
        crate::logger::error_unrestricted!(
            "wick: the heap's allocator is not wick's: an allocation the memory limit refuses ends the VMM with 0xC0000409"
        );
    }
}

/// At a VM's build, once a process: a debug line if the heap's allocator is
/// wick's (a fact that never changes in a correct build).
pub fn say_at_build() {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| {
        if libc::wick_alloc::installed() {
            crate::logger::debug!(
                "wick: the heap's allocator is wick's: an allocation the memory limit refuses reclaims once, then ends the VMM with 137"
            );
        }
    });
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
