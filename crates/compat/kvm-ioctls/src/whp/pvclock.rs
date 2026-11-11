// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! kvm-clock, the paravirtual clock KVM gives a guest, on WHP.
//!
//! A Linux guest of Firecracker on KVM finds `KVMKVMKVM` at CPUID 0x40000000
//! and the clock source features at 0x40000001, writes the guest physical
//! address of a `pvclock_vcpu_time_info` to `MSR_KVM_SYSTEM_TIME_NEW` and of a
//! `pvclock_wall_clock` to `MSR_KVM_WALL_CLOCK_NEW`, and from then on reads
//! time as `system_time + scale(rdtsc - tsc_timestamp)`. It takes its TSC
//! frequency from there too, instead of calibrating the TSC against the PIT
//! (which is slow and unreliable when every PIT read is a VM exit).
//!
//! The guest TSC of a WHP partition runs at the host's TSC frequency
//! (`WHvCapabilityCodeProcessorClockFrequency`) and is the same on every
//! vCPU, so one reference pair `(tsc, ns)` serves every vCPU and the clock is
//! stable (`PVCLOCK_TSC_STABLE_BIT`), as KVM's master clock is. `ns` is the
//! VM clock of `get_clock`/`set_clock`. A `set_clock` (snapshot restore)
//! drops the reference and starts a new clock generation: upstream restores
//! the vCPUs' MSRs, and so publishes their time info, before it sets the
//! clock, so each vCPU publishes its time info again before it next enters
//! the guest, under a reference taken then, as KVM does on a clock update
//! request (`KVM_REQ_CLOCK_UPDATE`). Without it, a restored guest's kvm-clock
//! restarts from the new VM's clock before `set_clock`, near 0, and goes
//! backwards.
//!
//! Upstream saves the vCPUs, their TSCs among them, before it reads the
//! clock, and restores them before it sets it; on KVM the moments between
//! are microseconds, on WHP milliseconds, enough for a restored Linux guest's
//! clocksource watchdog to find kvm-clock and the TSC apart (measured: 5 ms
//! over 480 ms) and mark the TSC unstable. So `get_clock` also returns the
//! guest TSC at the moment of the clock it returns (`host_tsc`, the field
//! KVM fills with the host's), the clock being the guest's kvm-clock at that
//! TSC, and `set_clock` makes that pair the reference: the restored guest's
//! kvm-clock goes on from its TSC exactly as it did before the snapshot.

use std::sync::Mutex;

use super::{ffi, whv};

/// `MSR_KVM_WALL_CLOCK_NEW`.
pub(crate) const MSR_WALL_CLOCK: u32 = 0x4b56_4d00;
/// `MSR_KVM_SYSTEM_TIME_NEW`.
pub(crate) const MSR_SYSTEM_TIME: u32 = 0x4b56_4d01;
/// `KVM_FEATURE_CLOCKSOURCE2`.
pub(crate) const FEATURE_CLOCKSOURCE2: u32 = 1 << 3;
/// `KVM_FEATURE_CLOCKSOURCE_STABLE_BIT`.
pub(crate) const FEATURE_CLOCKSOURCE_STABLE: u32 = 1 << 24;
/// `PVCLOCK_TSC_STABLE_BIT`.
const PVCLOCK_TSC_STABLE: u8 = 1;

/// The guest TSC frequency in Hz (the host's).
pub(crate) fn tsc_hz() -> u64 {
    static HZ: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *HZ.get_or_init(|| {
        let mut hz = 0u64;
        let mut written = 0u32;
        // SAFETY: an output buffer of the size passed.
        let hr = unsafe {
            whv::WHvGetCapability(
                whv::WHvCapabilityCodeProcessorClockFrequency,
                (&raw mut hz).cast(),
                8,
                &mut written,
            )
        };
        if hr >= 0 { hz } else { 0 }
    })
}

/// KVM's `kvm_get_time_scale`: `(shift, mul)` with which
/// `((delta << shift) * mul) >> 32` (a negative shift shifts right) turns
/// `delta` ticks at `base_hz` into ticks at `scaled_hz`.
pub(crate) fn time_scale(scaled_hz: u64, base_hz: u64) -> (i8, u32) {
    let mut shift: i8 = 0;
    let mut tps64 = base_hz;
    let mut scaled64 = scaled_hz;
    while tps64 > scaled64 * 2 || tps64 & 0xffff_ffff_0000_0000 != 0 {
        tps64 >>= 1;
        shift -= 1;
    }
    #[allow(clippy::cast_possible_truncation)]
    let mut tps32 = tps64 as u32;
    while u64::from(tps32) <= scaled64 || scaled64 & 0xffff_ffff_0000_0000 != 0 {
        if scaled64 & 0xffff_ffff_0000_0000 != 0 || tps32 & 0x8000_0000 != 0 {
            scaled64 >>= 1;
        } else {
            tps32 <<= 1;
        }
        shift += 1;
    }
    #[allow(clippy::cast_possible_truncation)]
    let mul = ((scaled64 << 32) / u64::from(tps32)) as u32;
    (shift, mul)
}

/// Applies a `(shift, mul)` from [`time_scale`] to `delta`: what the guest
/// computes.
fn scale(delta: u64, shift: i8, mul: u32) -> u64 {
    let d = if shift >= 0 { delta << shift } else { delta >> -shift };
    ((u128::from(d) * u128::from(mul)) >> 32) as u64
}

/// The VM's kvm-clock reference and wall clock MSR.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// `(guest tsc, VM clock ns)` taken at the same moment.
    reference: Option<(u64, u64)>,
    /// The last `MSR_KVM_WALL_CLOCK_NEW` value.
    pub(crate) wall_msr: u64,
    /// Counts the times the VM clock was set: a vCPU whose time info was
    /// published under an older one publishes it again.
    pub(crate) generation: u64,
}

impl State {
    /// Forgets the reference and starts a new generation (the VM clock was
    /// set).
    pub(crate) fn reset(&mut self) {
        self.reference = None;
        self.generation += 1;
    }

    /// Makes `(tsc, ns)` the reference: the guest's kvm-clock reads `ns`
    /// when its TSC reads `tsc` (a restored clock, with the guest TSC it was
    /// saved with).
    pub(crate) fn pin(&mut self, tsc: u64, ns: u64) {
        self.reference = Some((tsc, ns));
    }

    /// The guest's kvm-clock when its TSC reads `tsc`, as the guest computes
    /// it from the time info published under the reference, if there is one.
    pub(crate) fn clock_at(&self, tsc: u64) -> Option<u64> {
        let (ref_tsc, ref_ns) = self.reference?;
        let hz = tsc_hz();
        if hz == 0 {
            return None;
        }
        let (shift, mul) = time_scale(1_000_000_000, hz);
        Some(if tsc >= ref_tsc {
            ref_ns.saturating_add(scale(tsc - ref_tsc, shift, mul))
        } else {
            ref_ns.saturating_sub(scale(ref_tsc - tsc, shift, mul))
        })
    }
}

/// `struct pvclock_vcpu_time_info`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct VcpuTimeInfo {
    version: u32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    pad: [u8; 2],
}

/// `struct pvclock_wall_clock`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct WallClock {
    version: u32,
    sec: u32,
    nsec: u32,
}

/// Writes `value` at host address `at` the way KVM updates a pvclock
/// structure: the version odd while the fields change, then even.
///
/// # Safety
/// `at` must be valid for writes of a `T` whose first field is the version.
unsafe fn publish<T: Copy>(at: *mut T, value: T) {
    let version = at.cast::<u32>();
    // SAFETY: the caller's contract.
    unsafe {
        let v = core::ptr::read_volatile(version);
        core::ptr::write_volatile(version, v.wrapping_add(1) | 1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let mut copy = value;
        // Keep the odd version while the rest is written.
        *(&raw mut copy).cast::<u32>() = v.wrapping_add(1) | 1;
        core::ptr::write_volatile(at, copy);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(version, (v.wrapping_add(1) | 1).wrapping_add(1));
    }
}

/// Handles a guest write of `MSR_KVM_SYSTEM_TIME_NEW` on vCPU `vp`: fills the
/// `pvclock_vcpu_time_info` at the guest physical address in `value` (bit 0
/// enables it). `host` translates a guest physical address; `now_ns` is the
/// VM clock.
pub(crate) fn system_time(
    state: &Mutex<State>,
    part: whv::WHV_PARTITION_HANDLE,
    vp: u32,
    value: u64,
    host: impl Fn(u64) -> Option<u64>,
    now_ns: impl Fn() -> u64,
) {
    if value & 1 == 0 {
        return;
    }
    let gpa = value & !0x1f;
    let Some(at) = host(gpa) else { return };
    let hz = tsc_hz();
    if hz == 0 {
        return;
    }
    let (tsc, ns) = {
        let mut s = state.lock().unwrap();
        *s.reference.get_or_insert_with(|| {
            let tsc = ffi::get_register(part, vp, whv::WHvX64RegisterTsc)
                .map(|v| ffi::as_u64(&v))
                .unwrap_or(0);
            (tsc, now_ns())
        })
    };
    let (shift, mul) = time_scale(1_000_000_000, hz);
    let info = VcpuTimeInfo {
        tsc_timestamp: tsc,
        system_time: ns,
        tsc_to_system_mul: mul,
        tsc_shift: shift,
        flags: PVCLOCK_TSC_STABLE,
        ..VcpuTimeInfo::default()
    };
    // SAFETY: guest RAM the guest gave for its time info (32 bytes, 32-byte
    // aligned, so within one page).
    unsafe { publish(at as *mut VcpuTimeInfo, info) };
}

/// `PVCLOCK_GUEST_STOPPED`: the vCPU was stopped by the host.
pub(crate) const PVCLOCK_GUEST_STOPPED: u8 = 1 << 1;

/// `KVM_KVMCLOCK_CTRL` for the vCPU whose `MSR_KVM_SYSTEM_TIME_NEW` is
/// `value`: sets `PVCLOCK_GUEST_STOPPED` in its time info, which the guest's
/// lockup watchdogs read (and clear) after a pause, so that the time the VM
/// was paused is not taken for a soft lockup. False when the vCPU has no
/// kvm-clock, which KVM answers with `EINVAL`.
pub(crate) fn set_guest_stopped(value: u64, host: impl Fn(u64) -> Option<u64>) -> bool {
    if value & 1 == 0 {
        return false;
    }
    let Some(at) = host(value & !0x1f) else { return false };
    let at = at as *mut VcpuTimeInfo;
    // SAFETY: guest RAM the guest gave for its time info (see system_time).
    unsafe {
        let mut info = core::ptr::read_volatile(at);
        info.flags |= PVCLOCK_GUEST_STOPPED;
        publish(at, info);
    }
    true
}

/// Handles a guest write of `MSR_KVM_WALL_CLOCK_NEW`: fills the
/// `pvclock_wall_clock` at the guest physical address `value` with the wall
/// time at which the VM clock was 0.
pub(crate) fn wall_clock(state: &Mutex<State>, value: u64, host: impl Fn(u64) -> Option<u64>, now_ns: u64) {
    state.lock().unwrap().wall_msr = value;
    let Some(at) = host(value) else { return };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let boot = now.saturating_sub(std::time::Duration::from_nanos(now_ns));
    #[allow(clippy::cast_possible_truncation)]
    let wc = WallClock {
        version: 0,
        sec: boot.as_secs() as u32,
        nsec: boot.subsec_nanos(),
    };
    // SAFETY: guest RAM the guest gave for its wall clock (12 bytes).
    unsafe { publish(at as *mut WallClock, wc) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_scale() {
        for hz in [1_000_000_000u64, 2_400_000_000, 3_692_995_608, 100_000_000, 4_000_000_000] {
            let (shift, mul) = time_scale(1_000_000_000, hz);
            // One second of ticks is one second, to within a few ns.
            let ns = scale(hz, shift, mul);
            assert!(ns.abs_diff(1_000_000_000) < 10, "{hz} Hz: {ns} ns (shift {shift}, mul {mul:#x})");
            // An hour does not overflow and stays exact to the ppm.
            let h = scale(hz * 3600, shift, mul);
            assert!(h.abs_diff(3_600_000_000_000) < 3_600_000, "{hz} Hz: {h} ns");
        }
    }

    // A snapshot restore publishes the vCPUs' time info (their MSRs) before
    // it sets the clock: setting it must start a new generation, so each
    // vCPU publishes again under a reference taken after it.
    #[test]
    fn test_set_clock_starts_a_new_generation() {
        let mut state = State { reference: Some((1_000, 2_000)), ..State::default() };
        let before = state.generation;
        state.reset();
        assert_eq!(state.reference, None);
        assert_eq!(state.generation, before + 1);
    }

    // The pair a snapshot saved is the restored reference, and the clock is
    // read from the guest TSC through it, both ways from the reference.
    #[test]
    fn test_pinned_reference_reads_the_clock_from_the_tsc() {
        let mut state = State::default();
        assert_eq!(state.clock_at(1), None);
        let hz = tsc_hz();
        if hz == 0 {
            return; // no WHP: no TSC frequency to scale by
        }
        state.pin(10 * hz, 5_000_000_000);
        let at = |s: &State, tsc| s.clock_at(tsc).unwrap();
        assert_eq!(at(&state, 10 * hz), 5_000_000_000);
        assert!(at(&state, 11 * hz).abs_diff(6_000_000_000) < 10);
        assert!(at(&state, 9 * hz).abs_diff(4_000_000_000) < 10);
        state.reset();
        assert_eq!(state.clock_at(10 * hz), None);
    }

    #[test]
    fn test_guest_stopped_is_published() {
        let mut info = VcpuTimeInfo { version: 4, flags: PVCLOCK_TSC_STABLE, system_time: 7, ..Default::default() };
        let at = &raw mut info as u64;
        // The MSR's enable bit, the struct at "guest address" 0x1000.
        assert!(!set_guest_stopped(0x1000, |_| Some(at)), "kvm-clock off");
        assert!(set_guest_stopped(0x1001, |gpa| (gpa == 0x1000).then_some(at)));
        assert_eq!(info.flags, PVCLOCK_TSC_STABLE | PVCLOCK_GUEST_STOPPED);
        assert_eq!(info.system_time, 7, "the rest as it was");
        assert_eq!(info.version, 6, "an update: even, advanced");
    }

    #[test]
    fn test_publish_versions() {
        let mut info = VcpuTimeInfo::default();
        // SAFETY: a local structure.
        unsafe { publish(&raw mut info, VcpuTimeInfo { system_time: 5, ..VcpuTimeInfo::default() }) };
        assert_eq!(info.version, 2);
        assert_eq!(info.system_time, 5);
        // SAFETY: as above.
        unsafe { publish(&raw mut info, VcpuTimeInfo { system_time: 6, ..VcpuTimeInfo::default() }) };
        assert_eq!(info.version, 4);
    }
}
