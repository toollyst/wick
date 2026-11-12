// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! How late macOS may wake a vCPU thread from a timed wait.
//!
//! With the in-kernel GIC a guest's `WFI` waits inside `hv_vcpu_run` until
//! its virtual timer is due. macOS fires that wait's timer late to coalesce
//! it with others, by a leeway that depends on the waiting thread's latency
//! tier (apple-oss-distributions/xnu, osfmk/kern/timer_call.c
//! `timer_call_slop`): `MIN(wait >> shift, max)`, and up to as much again
//! while the user is idle (`timer_user_idle_level`, 0 to 128, in 128ths).
//! The tiers' `shift` and `max` are `latency_qos_scale` and
//! `latency_qos_ns_max` of osfmk/arm/arm_timer.c: tier 0 an eighth of the
//! wait and 1 ms at most; tier 1, which a thread of a foreground process has
//! when nothing sets one, a quarter and 5 ms. KVM's wait is an hrtimer with
//! no slack (arch/arm64/kvm/arch_timer.c), about 50 us late.
//!
//! So each vCPU thread is given tier 0 ([`vcpu_thread`]): a guest timer is
//! then late by an eighth of its wait, at most 1 ms (2 ms while the user is
//! idle), where it was a quarter and 5 ms (10 ms). Measured on an M1 Pro,
//! macOS 27.2, 20 ms waits, against a `NOTE_CRITICAL` timer in the same
//! rounds, the user idle: a median 4.7 to 9.5 ms later than it without the
//! tier, 1.3 to 1.7 ms with it (`test_a_wfi_ends_when_its_timer_is_due`,
//! three runs). Only a time-constraint thread is not
//! coalesced at all, and a spinning guest then starves the host until the
//! kernel demotes the thread (after 1 s, measured): not used.
//!
//! The tier in effect is the more coalesced of the thread's, the task's and
//! the QoS class's (osfmk/kern/thread_policy.c, "Calculate timer QOS":
//! `MAX`). A Firecracker started as a background process (`taskpolicy -b`,
//! a QoS clamp, a launchd job of `ProcessType` Background) keeps its task's
//! tier whatever its threads ask for: its guest's timers stay late by the
//! task's leeway (a guest's 20 ms sleeps a median 170 ms longer, measured
//! with tools/macos/guest-timer.py under each).

use std::io;

const THREAD_LATENCY_QOS_POLICY: libc::thread_policy_flavor_t = 7;
/// `LATENCY_QOS_TIER_0` (mach/thread_policy.h): `(0xff << 16) | 1`.
const LATENCY_QOS_TIER_0: libc::integer_t = (0xff << 16) | 1;

fn port(thread: libc::pthread_t) -> libc::mach_port_t {
    // SAFETY: a pthread of this process; the port is not a new right.
    unsafe { libc::pthread_mach_thread_np(thread) }
}

/// Gives `thread`, which is to run a vCPU, latency tier 0. A Mach call
/// (`thread_policy_set`), which Firecracker's sandbox allows until it
/// narrows only: called by the thread that starts the vCPU threads, before.
///
/// # Errors
///
/// The kernel's refusal, with its `kern_return_t`.
pub fn vcpu_thread(thread: libc::pthread_t) -> io::Result<()> {
    let mut tier = LATENCY_QOS_TIER_0;
    // SAFETY: a thread of this task and a thread_latency_qos_policy of one
    // integer.
    #[allow(deprecated)]
    let kr = unsafe { libc::thread_policy_set(port(thread), THREAD_LATENCY_QOS_POLICY, &mut tier, 1) };
    if kr == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "thread_policy_set(THREAD_LATENCY_QOS_POLICY, tier 0) for a vCPU thread: kern_return_t {kr}"
        )))
    }
}

/// The latency tier `thread` asks for, as `LATENCY_QOS_TIER_*`; `None` if it
/// asks for none (the default).
///
/// # Errors
///
/// The kernel's refusal, with its `kern_return_t`.
pub fn requested(thread: libc::pthread_t) -> io::Result<Option<libc::integer_t>> {
    let mut tier: libc::integer_t = 0;
    let mut count: libc::mach_msg_type_number_t = 1;
    let mut default: libc::boolean_t = 0;
    // SAFETY: a thread of this task, one integer to fill, its count and the
    // flag that says the default was returned.
    #[allow(deprecated)]
    let kr = unsafe {
        libc::thread_policy_get(port(thread), THREAD_LATENCY_QOS_POLICY, &mut tier, &mut count, &mut default)
    };
    if kr != 0 {
        return Err(io::Error::other(format!("thread_policy_get(THREAD_LATENCY_QOS_POLICY): kern_return_t {kr}")));
    }
    Ok(if default != 0 || tier == 0 { None } else { Some(tier) })
}

#[cfg(test)]
mod tests {
    use std::os::unix::thread::JoinHandleExt;

    use super::*;

    // A thread given tier 0 asks for it, and one that is not asks for none.
    #[test]
    fn test_vcpu_thread_gets_tier_0() {
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || wait.recv().unwrap());
        let other = std::thread::spawn(|| requested(unsafe { libc::pthread_self() }).unwrap());
        assert_eq!(requested(thread.as_pthread_t()).unwrap(), None);
        vcpu_thread(thread.as_pthread_t()).unwrap();
        assert_eq!(requested(thread.as_pthread_t()).unwrap(), Some(LATENCY_QOS_TIER_0));
        assert_eq!(other.join().unwrap(), None);
        go.send(()).unwrap();
        thread.join().unwrap();
    }
}
