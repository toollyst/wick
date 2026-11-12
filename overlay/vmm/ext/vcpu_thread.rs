// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a host does to a vCPU thread when it is made.
//!
//! macOS: the thread gets latency tier 0, so that the host wakes it from a
//! guest's timed wait (`WFI` until the virtual timer is due, inside
//! `hv_vcpu_run`) at most 1 ms late (2 ms while the user is idle) and not 5 ms
//! (10 ms): `kvm_ioctls::latency` has the kernel's rule and the measurements.
//! It is a Mach call the sandbox allows until it narrows only
//! (`sandbox::SETUP_MIG_ROUTINES`), so it is made by the thread that starts
//! the vCPU threads, which upstream does while the microVM is built
//! (`Vcpu::start_threaded`, on boot and on restore), and its failure is that
//! start's failure. Linux: nothing to do, KVM's wait is a timer with no slack
//! (arch/arm64/kvm/arch_timer.c). Windows: nothing is done here.

use std::io;
use std::thread::JoinHandle;

/// Called by [`Vcpu::start_threaded`](crate::vstate::vcpu::Vcpu::start_threaded)
/// with the vCPU thread it has just made.
///
/// # Errors
///
/// The host's refusal: the vCPU does not start.
#[cfg(target_os = "macos")]
pub fn spawned(thread: &JoinHandle<()>) -> io::Result<()> {
    use std::os::unix::thread::JoinHandleExt;
    kvm_ioctls::latency::vcpu_thread(thread.as_pthread_t())
}

/// Called by [`Vcpu::start_threaded`](crate::vstate::vcpu::Vcpu::start_threaded)
/// with the vCPU thread it has just made.
///
/// # Errors
///
/// None on this host.
#[cfg(not(target_os = "macos"))]
pub fn spawned(_thread: &JoinHandle<()>) -> io::Result<()> {
    Ok(())
}
