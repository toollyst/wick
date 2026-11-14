// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The local APIC timer's TSC-deadline mode, which KVM's local APIC always
//! has and WHP's does not.
//!
//! A Linux guest whose CPUID has `TSC_DEADLINE` programs its local timer by
//! writing a guest TSC value to `IA32_TSC_DEADLINE` and never calibrates the
//! APIC timer (`calibrate_APIC_clock` returns at once). Without it, Linux
//! measures the APIC timer at boot against the TSC over 100 ms of polling,
//! and a vCPU that is descheduled in that window (a CPU limit on the VMM
//! throttles it) finishes the polling in a burst: the timer comes out far too
//! slow and is disabled ("APIC frequency too slow"), or mis-scaled for the
//! guest's life. KVM emulates the mode in software (an hrtimer per vCPU, the
//! interrupt from the LVT timer entry), so a Firecracker guest on Linux never
//! calibrates; this module does the same on WHP:
//!
//! - the partition is set up without WHP's own TSC-deadline support
//!   (`TscDeadlineTmrSupport`), so every access to `IA32_TSC_DEADLINE`
//!   leaves the hypervisor as an MSR exit and its value is this backend's,
//!   saved and restored with the other MSRs, as KVM's is (WHP has no
//!   register through which the hypervisor's own deadline could be);
//! - a write arms a host timer ([`Timers`]: one thread per VM on a
//!   high-resolution waitable timer) for the moment the guest TSC reaches
//!   the deadline; a deadline already past fires at once;
//! - when it fires, the vCPU is made to leave the guest
//!   (`WHvCancelRunVirtualProcessor`) and, on its own thread, the deadline
//!   is cleared and the LVT timer entry's vector requested for it, unless
//!   the APIC is software-disabled or the timer no longer in TSC-deadline
//!   mode ([`deadline_interrupt`]).
//!
//! WHP's xAPIC refuses the guest's write of the LVT timer entry that
//! selects TSC-deadline mode (measured on Windows 11 26H2, build
//! 26300.9711, whose WHP has no `TscDeadlineTmrSupport` at all: the entry
//! read `0x100ec`, Linux's earlier `lapic_timer_shutdown` write, masked
//! with the vector, at every `IA32_TSC_DEADLINE` write of a boot, and the
//! guest never got a local timer interrupt). So the entry's mode and mask
//! fields are not the guest's: the mode shows one-shot with no initial
//! count (WHP's own timer not running), and the mask is the last write WHP
//! accepted, which Linux's is always masked (it unmasks only together with
//! the mode bit). A guest in TSC-deadline mode is therefore taken at its
//! `IA32_TSC_DEADLINE` writes, which the processor honours only with the
//! timer unmasked in that mode and Linux makes only then: a non-zero write
//! arms the timer whenever the entry is in TSC-deadline mode or in one-shot
//! mode with no count ([`deadline_mode`]), and the interrupt is raised at
//! the entry's vector regardless of its mask bit ([`deadline_interrupt`];
//! `boot-test.ps1 smp`, where a guest's first sleep hung before). A guest
//! that masks the entry and leaves a deadline armed gets an interrupt the
//! processor would not raise; Linux disarms (`lapic_timer_shutdown`
//! masks, and nothing is armed in the shutdown state).
//!
//! That inference is xAPIC mode's. A vCPU in x2APIC mode (on an x2APIC
//! partition) has the guest's own entry: WHP takes every x2APIC write of it
//! but the one that selects TSC-deadline mode, which the run loop finishes
//! as KVM does (`gp`), so the mode field and the mask are the guest's and
//! are read as KVM reads them ([`page_in_deadline_mode`],
//! [`deadline_interrupt`]). In xAPIC mode WHP drops that write, the entry
//! keeping its value before it (X2E0REC f, CI run 43528910212, on an
//! x2APIC partition as on an xAPIC one); a deadline written while the entry
//! so kept has no valid vector and the APIC is software-enabled would arm a
//! timer whose interrupt never comes, and is refused, named, instead
//! ([`lost_xapic_deadline`]); with the APIC software-disabled (a CPU going
//! offline) no interrupt is due, on KVM either, and the write is taken.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CREATE_WAITABLE_TIMER_MANUAL_RESET, CancelWaitableTimer,
    CreateEventW, CreateWaitableTimerExW, INFINITE, SetEvent, SetWaitableTimer, TIMER_ALL_ACCESS,
    WaitForMultipleObjects,
};

use super::ffi::OwnedHandle;

/// `IA32_TSC_DEADLINE`.
pub(crate) const MSR_TSC_DEADLINE: u32 = 0x6e0;

/// Offsets in the xAPIC register page.
const APIC_ID: usize = 0x20;
const APIC_SVR: usize = 0xf0;
const APIC_LVTT: usize = 0x320;
const APIC_TMICT: usize = 0x380;
/// `APIC_SPIV_APIC_ENABLED`.
const SVR_ENABLED: u32 = 1 << 8;
/// `X2APIC_ENABLE` in `IA32_APIC_BASE` (EXTD).
pub(crate) const APIC_BASE_EXTD: u64 = 1 << 10;
/// `APIC_LVT_MASKED`.
const LVT_MASKED: u32 = 1 << 16;

fn reg(page: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(page[offset..offset + 4].try_into().unwrap())
}

/// Whether the LVT timer entry `lvtt`, with `tmict` the initial count
/// register, is in TSC-deadline mode as far as WHP's xAPIC shows it: its
/// mode field (bits 18:17) is TSC-deadline (`10`), or one-shot (`00`) with
/// no initial count, which is how a TSC-deadline entry reads if WHP dropped
/// the mode bit it does not implement. Periodic mode, or one-shot mode with
/// WHP's own timer counting, is not: a deadline written then is ignored, as
/// the processor ignores it.
pub(crate) fn deadline_mode(lvtt: u32, tmict: u32) -> bool {
    match (lvtt >> 17) & 0b11 {
        0b10 => true,
        0b00 => tmict == 0,
        _ => false,
    }
}

/// Whether the APIC register page of a vCPU whose `IA32_APIC_BASE` is
/// `apic_base` shows the timer in TSC-deadline mode. In x2APIC mode (EXTD
/// set) the entry is the guest's own, mode field and mask: WHP takes every
/// other x2APIC write of it, and the one it refuses, TSC-deadline mode, is
/// written by the backend as KVM stores it (`gp`, the run loop's #GP
/// exit), so the mode field says, as KVM's `apic_lvtt_tscdeadline`. In
/// xAPIC mode WHP drops that write (X2E0REC f, CI run 43528910212: the
/// entry kept the value before it), and [`deadline_mode`]'s inference
/// stands.
pub(crate) fn page_in_deadline_mode(page: &[u8], apic_base: u64) -> bool {
    let lvtt = reg(page, APIC_LVTT);
    if apic_base & APIC_BASE_EXTD != 0 {
        lvtt >> 17 & 0b11 == 0b10
    } else {
        deadline_mode(lvtt, reg(page, APIC_TMICT))
    }
}

/// The interrupt an expired deadline raises, from the APIC register page
/// of a vCPU whose `IA32_APIC_BASE` is `apic_base`: `(APIC ID, vector)`, or
/// `None` when none is raised: the APIC software-disabled, the timer not in
/// TSC-deadline mode, the entry masked in x2APIC mode (KVM's
/// `kvm_apic_local_deliver` raises none for a masked entry), or the entry's
/// vector not a valid one (below 16: in xAPIC mode, the guest's write of
/// the vector was lost too; [`lost_xapic_deadline`]). In xAPIC mode the
/// entry's mask bit is not the guest's (module documentation) and is not
/// consulted.
///
/// The ID register is in the page as the APIC's mode has it: in xAPIC mode
/// the ID in bits 31:24, in x2APIC mode (EXTD set) the 32-bit x2APIC ID,
/// which WHP's page holds as it is (vCPU 1 read `0x1000000`, then `0x1`
/// once the host set EXTD: X2E0REC c, CI run 43521200989), as KVM's own
/// register does (Linux v6.1 arch/x86/kvm/lapic.c, `kvm_apic_set_x2apic_id`
/// and `kvm_apic_id`). KVM raises the timer's interrupt in the vCPU's own
/// APIC (`kvm_apic_local_deliver`); here it is an MSI to that APIC's ID.
pub(crate) fn deadline_interrupt(page: &[u8], apic_base: u64) -> Option<(u32, u8)> {
    let lvtt = reg(page, APIC_LVTT);
    #[allow(clippy::cast_possible_truncation)]
    let vector = lvtt as u8;
    let x2apic = apic_base & APIC_BASE_EXTD != 0;
    if reg(page, APIC_SVR) & SVR_ENABLED == 0
        || !page_in_deadline_mode(page, apic_base)
        || vector < 16
        || (x2apic && lvtt & LVT_MASKED != 0)
    {
        return None;
    }
    let id = reg(page, APIC_ID);
    Some((if x2apic { id } else { id >> 24 }, vector))
}

/// Whether a guest's non-zero `IA32_TSC_DEADLINE` write on a vCPU in xAPIC
/// mode would arm a timer whose interrupt never comes: the APIC software-
/// enabled and the entry read as TSC-deadline mode ([`deadline_mode`]'s
/// inference) with no valid vector, as it does when WHP dropped the guest's
/// write that selected the mode and with it the vector (the entry before it
/// the reset value, masked with vector 0). Such a write is refused, loudly,
/// where it would otherwise leave the guest without its timer.
///
/// A software-disabled APIC takes no timer interrupt on KVM either (its LVT
/// entries masked, `kvm_apic_local_deliver` raises none), and a guest writes
/// a deadline there: a CPU going offline masks its LVT timer entry with
/// vector 0 and disables its APIC (Linux v6.1 arch/x86/kernel/smpboot.c
/// 1690, `native_cpu_disable`'s `apic_soft_disable`; apic/apic.c 1181 and
/// 1216-1218) and then, idle until it is dead, may program its next event
/// (`lapic_next_deadline`, apic.c 483-494). That write is taken and raises
/// nothing ([`deadline_interrupt`]), as KVM's ignores it (`0x10000` is
/// one-shot mode there). Refused, it ended a VMM whose guest took a CPU
/// offline (`boot-test.ps1 smp`, PC step 14g at acdec89).
pub(crate) fn lost_xapic_deadline(page: &[u8], apic_base: u64) -> bool {
    apic_base & APIC_BASE_EXTD == 0
        && reg(page, APIC_SVR) & SVR_ENABLED != 0
        && page_in_deadline_mode(page, apic_base)
        && (reg(page, APIC_LVTT) & 0xff) < 16
}

/// How long until a guest TSC at `tsc` reaches `deadline`, at `hz`. Rounded
/// up, so the interrupt never comes before the guest TSC reached it.
pub(crate) fn time_to(deadline: u64, tsc: u64, hz: u64) -> Duration {
    let ticks = u128::from(deadline.saturating_sub(tsc));
    let hz = u128::from(hz.max(1));
    let ns = (ticks * 1_000_000_000).div_ceil(hz);
    Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
}

/// What a timer does when it fires (on the timer thread).
pub(crate) type Fire = Arc<dyn Fn() + Send + Sync>;

struct Entry {
    due: Instant,
    fire: Fire,
}

#[derive(Default)]
struct State {
    armed: HashMap<u32, Entry>,
    stop: bool,
}

struct Shared {
    state: Mutex<State>,
    /// Auto-reset: the set of armed timers changed, or the thread is to stop.
    changed: OwnedHandle,
}

// SAFETY: the event handle is a kernel object usable from any thread.
unsafe impl Send for Shared {}
// SAFETY: as above; the state is behind its lock.
unsafe impl Sync for Shared {}

/// One-shot host timers, one per key (a vCPU index), served by one thread.
pub(crate) struct Timers {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    thread_id: ThreadId,
}

impl std::fmt::Debug for Timers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timers").finish_non_exhaustive()
    }
}

impl Timers {
    /// Starts the timer thread. Fails if Windows has no high-resolution
    /// waitable timer (before Windows 10 1803): a normal one fires only at
    /// the system timer's resolution (15.6 ms by default), too late for a
    /// guest's local timer.
    pub(crate) fn new() -> io::Result<Timers> {
        // SAFETY: an unnamed auto-reset event.
        let changed = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if changed.is_null() {
            return Err(io::Error::last_os_error());
        }
        let changed = OwnedHandle(changed);
        // SAFETY: an unnamed manual-reset high-resolution timer.
        let timer = unsafe {
            CreateWaitableTimerExW(
                std::ptr::null(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION | CREATE_WAITABLE_TIMER_MANUAL_RESET,
                TIMER_ALL_ACCESS,
            )
        };
        if timer.is_null() {
            return Err(io::Error::last_os_error());
        }
        let timer = OwnedHandle(timer);
        let shared = Arc::new(Shared { state: Mutex::new(State::default()), changed });
        let thread_shared = shared.clone();
        let thread = std::thread::Builder::new()
            .name("whp-tsc-deadline".into())
            .spawn(move || run(&thread_shared, &timer))?;
        let thread_id = thread.thread().id();
        Ok(Timers { shared, thread: Some(thread), thread_id })
    }

    /// Arms the timer of `key` to run `fire` at `due`, replacing one armed.
    pub(crate) fn arm(&self, key: u32, due: Instant, fire: Fire) {
        self.shared.state.lock().unwrap().armed.insert(key, Entry { due, fire });
        // SAFETY: our event.
        unsafe { SetEvent(self.shared.changed.0) };
    }

    /// Disarms the timer of `key`. A `fire` the thread already took runs.
    pub(crate) fn disarm(&self, key: u32) {
        self.shared.state.lock().unwrap().armed.remove(&key);
    }
}

impl Drop for Timers {
    fn drop(&mut self) {
        self.shared.state.lock().unwrap().stop = true;
        // SAFETY: our event.
        unsafe { SetEvent(self.shared.changed.0) };
        if let Some(t) = self.thread.take() {
            // The last reference can be dropped by a `fire` on the thread itself.
            if std::thread::current().id() != self.thread_id {
                let _ = t.join();
            }
        }
    }
}

/// The timer thread: runs each timer that is due, then waits for the next
/// one or for a change.
fn run(shared: &Shared, timer: &OwnedHandle) {
    loop {
        let mut due = Vec::new();
        let next = {
            let mut state = shared.state.lock().unwrap();
            if state.stop {
                return;
            }
            let now = Instant::now();
            state.armed.retain(|_, e| {
                if e.due <= now {
                    due.push(e.fire.clone());
                    false
                } else {
                    true
                }
            });
            state.armed.values().map(|e| e.due).min()
        };
        if !due.is_empty() {
            for fire in due {
                fire();
            }
            continue;
        }
        let handles: [HANDLE; 2] = [shared.changed.0, timer.0];
        let count = match next {
            Some(at) => {
                // Relative, in 100 ns units (negative), rounded up.
                let wait = at.saturating_duration_since(Instant::now());
                let units = i64::try_from(wait.as_nanos().div_ceil(100)).unwrap_or(i64::MAX).max(1);
                let due_time = -units;
                // SAFETY: our timer; no completion routine.
                if unsafe { SetWaitableTimer(timer.0, &due_time, 0, None, std::ptr::null(), 0) } == 0 {
                    // Cannot happen with a valid handle; never wait without it.
                    std::thread::yield_now();
                    continue;
                }
                2
            }
            None => {
                // SAFETY: our timer.
                unsafe { CancelWaitableTimer(timer.0) };
                1
            }
        };
        // SAFETY: `count` handles we own.
        let woke = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, INFINITE) };
        if woke != WAIT_OBJECT_0 && woke != WAIT_OBJECT_0 + 1 {
            std::thread::yield_now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// An xAPIC-mode page: the ID in bits 31:24.
    fn page(svr: u32, lvtt: u32, tmict: u32, id: u32) -> Vec<u8> {
        let mut p = vec![0u8; 4096];
        p[APIC_SVR..APIC_SVR + 4].copy_from_slice(&svr.to_le_bytes());
        p[APIC_LVTT..APIC_LVTT + 4].copy_from_slice(&lvtt.to_le_bytes());
        p[APIC_TMICT..APIC_TMICT + 4].copy_from_slice(&tmict.to_le_bytes());
        p[APIC_ID..APIC_ID + 4].copy_from_slice(&(id << 24).to_le_bytes());
        p
    }

    /// An x2APIC-mode page: the 32-bit ID as it is.
    fn x2apic_page(svr: u32, lvtt: u32, tmict: u32, id: u32) -> Vec<u8> {
        let mut p = page(svr, lvtt, tmict, 0);
        p[APIC_ID..APIC_ID + 4].copy_from_slice(&id.to_le_bytes());
        p
    }

    /// `IA32_APIC_BASE` enabled, in xAPIC and in x2APIC mode.
    const XAPIC: u64 = 0xfee0_0800;
    const X2APIC: u64 = 0xfee0_0c00;

    #[test]
    fn test_deadline_mode() {
        // TSC-deadline mode, as written (Linux: APIC_LVT_TIMER_TSCDEADLINE).
        assert!(deadline_mode(0x4_00ec, 0));
        // The same entry if WHP's xAPIC dropped bit 18: one-shot, no count.
        assert!(deadline_mode(0xec, 0));
        // One-shot with WHP's own timer counting, and periodic: not.
        assert!(!deadline_mode(0xec, 1000));
        assert!(!deadline_mode(0x2_00ec, 0));
        // The reserved mode.
        assert!(!deadline_mode(0x6_00ec, 0));
    }

    #[test]
    fn test_deadline_interrupt() {
        // Linux's LOCAL_TIMER_VECTOR on APIC 1.
        assert_eq!(deadline_interrupt(&page(0x1ff, 0x4_00ec, 0, 1), XAPIC), Some((1, 0xec)));
        assert_eq!(deadline_interrupt(&page(0x1ff, 0xec, 0, 3), XAPIC), Some((3, 0xec)));
        // In x2APIC mode the page holds the 32-bit ID as it is (vCPU 1:
        // 0x1, X2E0REC c): the interrupt is vCPU 1's, not APIC 0's.
        assert_eq!(deadline_interrupt(&x2apic_page(0x1ff, 0x4_00ec, 0, 1), X2APIC), Some((1, 0xec)));
        assert_eq!(deadline_interrupt(&x2apic_page(0x1ff, 0x4_00ec, 0, 31), X2APIC), Some((31, 0xec)));
        assert_eq!(deadline_interrupt(&x2apic_page(0x1ff, 0x4_00ec, 0, 0), X2APIC), Some((0, 0xec)));
        // In x2APIC mode the entry is the guest's own: one-shot with no
        // count is one-shot, and a masked entry raises nothing (KVM's
        // kvm_apic_local_deliver).
        assert_eq!(deadline_interrupt(&x2apic_page(0x1ff, 0xec, 0, 1), X2APIC), None);
        assert_eq!(deadline_interrupt(&x2apic_page(0x1ff, 0x5_00ec, 0, 1), X2APIC), None);
        // The entry as WHP shows it after refusing the guest's write that
        // selected TSC-deadline mode: Linux's lapic_timer_shutdown write,
        // masked, with the vector (0x100ec measured on Windows 11 26H2). The
        // mask is not the guest's: the interrupt is raised.
        assert_eq!(deadline_interrupt(&page(0x1ff, LVT_MASKED | 0xec, 0, 1), XAPIC), Some((1, 0xec)));
        assert_eq!(deadline_interrupt(&page(0x1ff, 0x5_00ec, 0, 0), XAPIC), Some((0, 0xec)));
        // Software-disabled APIC, other modes, no vector written.
        assert_eq!(deadline_interrupt(&page(0x0ff, 0x4_00ec, 0, 0), XAPIC), None);
        assert_eq!(deadline_interrupt(&page(0x1ff, 0x2_00ec, 0, 0), XAPIC), None);
        assert_eq!(deadline_interrupt(&page(0x1ff, 0xec, 5, 0), XAPIC), None);
        assert_eq!(deadline_interrupt(&page(0x1ff, LVT_MASKED, 0, 0), XAPIC), None);
        assert_eq!(deadline_interrupt(&x2apic_page(0x0ff, 0x4_00ec, 0, 1), X2APIC), None);
    }

    #[test]
    fn test_the_mode_by_the_apics_mode() {
        // x2APIC mode: the mode field as KVM reads it.
        assert!(page_in_deadline_mode(&x2apic_page(0x1ff, 0x4_00ec, 0, 1), X2APIC));
        assert!(page_in_deadline_mode(&x2apic_page(0x1ff, 0x5_00ec, 0, 1), X2APIC));
        assert!(!page_in_deadline_mode(&x2apic_page(0x1ff, 0xec, 0, 1), X2APIC));
        assert!(!page_in_deadline_mode(&x2apic_page(0x1ff, 0x2_00ec, 0, 1), X2APIC));
        // xAPIC mode: the inference.
        assert!(page_in_deadline_mode(&page(0x1ff, 0xec, 0, 1), XAPIC));
        assert!(page_in_deadline_mode(&page(0x1ff, 0x1_00ec, 0, 1), XAPIC));
        assert!(!page_in_deadline_mode(&page(0x1ff, 0xec, 9, 1), XAPIC));
    }

    #[test]
    fn test_a_lost_xapic_deadline_is_named() {
        // The reset entry (masked, vector 0) kept after WHP dropped the
        // guest's TSC-deadline write: the timer would never fire.
        assert!(lost_xapic_deadline(&page(0x1ff, LVT_MASKED, 0, 0), XAPIC));
        assert!(lost_xapic_deadline(&page(0x1ff, 0, 0, 0), XAPIC));
        // Linux's shutdown write kept (0x100ec): the vector is there.
        assert!(!lost_xapic_deadline(&page(0x1ff, 0x1_00ec, 0, 0), XAPIC));
        // Not in TSC-deadline mode (periodic, counting): the write is
        // ignored as the processor ignores it, nothing lost.
        assert!(!lost_xapic_deadline(&page(0x1ff, 0x2_0000, 0, 0), XAPIC));
        assert!(!lost_xapic_deadline(&page(0x1ff, LVT_MASKED, 7, 0), XAPIC));
        // x2APIC mode is never the inference's.
        assert!(!lost_xapic_deadline(&x2apic_page(0x1ff, LVT_MASKED, 0, 0), X2APIC));
        // A CPU going offline: its APIC software-disabled and the entry
        // masked with vector 0 (Linux's apic_soft_disable); a deadline then
        // raises nothing, on KVM as here, and is taken.
        assert!(!lost_xapic_deadline(&page(0x0ff, LVT_MASKED, 0, 0), XAPIC));
        assert!(!lost_xapic_deadline(&page(0x00f, LVT_MASKED, 0, 1), XAPIC));
    }

    #[test]
    fn test_time_to() {
        let hz = 2_500_000_000;
        assert_eq!(time_to(hz, 0, hz), Duration::from_secs(1));
        assert_eq!(time_to(100, 200, hz), Duration::ZERO);
        // Rounded up: one tick is 0.4 ns.
        assert_eq!(time_to(1, 0, hz), Duration::from_nanos(1));
        assert_eq!(time_to(u64::MAX, 0, 1), Duration::from_nanos(u64::MAX));
        // A whole guest TSC range at 3 GHz does not overflow.
        assert!(time_to(u64::MAX, 0, 3_000_000_000) > Duration::from_secs(6_000_000_000));
    }

    #[test]
    fn test_timers_fire_once_in_order() {
        let timers = Timers::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        for (key, ms) in [(0u32, 30u64), (1, 10), (2, 20)] {
            let tx = Mutex::new(tx.clone());
            let due = start + Duration::from_millis(ms);
            timers.arm(key, due, Arc::new(move || tx.lock().unwrap().send((key, Instant::now(), due)).unwrap()));
        }
        let mut order = Vec::new();
        for _ in 0..3 {
            let (key, at, due) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(at >= due, "timer {key} fired early");
            order.push(key);
        }
        assert_eq!(order, [1, 2, 0]);
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "a timer fired twice");
    }

    #[test]
    fn test_timers_rearm_and_disarm() {
        let timers = Timers::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let send = |v: u32| {
            let tx = Mutex::new(tx.clone());
            Arc::new(move || tx.lock().unwrap().send(v).unwrap()) as Fire
        };
        let now = Instant::now();
        // Re-armed earlier: only the second fires.
        timers.arm(0, now + Duration::from_secs(60), send(1));
        timers.arm(0, now + Duration::from_millis(5), send(2));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
        // Disarmed: nothing fires.
        timers.arm(1, Instant::now() + Duration::from_millis(20), send(3));
        timers.disarm(1);
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        // Already due: fires at once.
        timers.arm(2, Instant::now(), send(4));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 4);
    }

    /// A high-resolution waitable timer fires well within a millisecond of
    /// its due time on an idle host, where a normal one waits for the next
    /// system timer tick (15.6 ms by default). The bound is loose, for a
    /// loaded machine; the median is reported.
    #[test]
    fn test_timers_are_high_resolution() {
        let timers = Timers::new().unwrap();
        let (tx, rx) = mpsc::channel();
        let mut late = Vec::new();
        for _ in 0..50 {
            let tx = Mutex::new(tx.clone());
            let due = Instant::now() + Duration::from_micros(700);
            timers.arm(0, due, Arc::new(move || tx.lock().unwrap().send(Instant::now().saturating_duration_since(due)).unwrap()));
            late.push(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        }
        late.sort();
        let median = late[late.len() / 2];
        // The control, at the same time: a normal waitable timer.
        // SAFETY: an unnamed manual-reset timer, closed below.
        let normal = OwnedHandle(unsafe {
            CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), CREATE_WAITABLE_TIMER_MANUAL_RESET, TIMER_ALL_ACCESS)
        });
        let mut control = Vec::new();
        for _ in 0..50 {
            let due = Instant::now() + Duration::from_micros(700);
            // SAFETY: our timer; 700 µs, relative.
            unsafe {
                SetWaitableTimer(normal.0, &-7000, 0, None, std::ptr::null(), 0);
                windows_sys::Win32::System::Threading::WaitForSingleObject(normal.0, INFINITE);
            }
            control.push(Instant::now().saturating_duration_since(due));
        }
        control.sort();
        eprintln!(
            "TSC-deadline timers: median {median:?} late, worst {:?}; a normal waitable timer: median {:?} late",
            late[late.len() - 1],
            control[control.len() / 2]
        );
        assert!(median < Duration::from_millis(4), "median {median:?} late");
    }
}
