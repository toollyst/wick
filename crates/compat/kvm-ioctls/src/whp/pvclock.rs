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
//!
//! The guest names where both structures go, so they are written as KVM
//! writes them (arch/x86/kvm/x86.c): the wall clock through
//! `kvm_read_guest`/`kvm_write_guest` ([`guest_mem`]: page by page, a page
//! no slot maps or a read-only one stops it, written pages dirty), the time
//! info in place through a `gfn_to_pfn_cache`, which takes it only within
//! one page of a writable slot ([`guest_mem::with_page`]). Neither address
//! is aligned by KVM, so neither is assumed aligned here.

use std::collections::HashMap;
use std::sync::Mutex;

use super::guest_mem::{self, Slot};
use super::{ffi, whv};

/// The VM's guest RAM slots, which the structures are written into.
pub(crate) type Ram = Mutex<HashMap<u32, Slot>>;

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

/// `struct pvclock_vcpu_time_info` (32 bytes, little-endian, packed as the
/// guest lays it out).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct VcpuTimeInfo {
    version: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
}

/// The size of `struct pvclock_vcpu_time_info`.
const TIME_INFO_LEN: usize = 32;

impl VcpuTimeInfo {
    fn to_bytes(self) -> [u8; TIME_INFO_LEN] {
        let mut b = [0u8; TIME_INFO_LEN];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[8..16].copy_from_slice(&self.tsc_timestamp.to_le_bytes());
        b[16..24].copy_from_slice(&self.system_time.to_le_bytes());
        b[24..28].copy_from_slice(&self.tsc_to_system_mul.to_le_bytes());
        b[28] = self.tsc_shift.to_le_bytes()[0];
        b[29] = self.flags;
        b
    }

    fn from_bytes(b: &[u8; TIME_INFO_LEN]) -> Self {
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        VcpuTimeInfo {
            version: u32_at(0),
            tsc_timestamp: u64_at(8),
            system_time: u64_at(16),
            tsc_to_system_mul: u32_at(24),
            tsc_shift: i8::from_le_bytes([b[28]]),
            flags: b[29],
        }
    }
}

/// The time info at `gpa` updated in place as KVM's
/// `kvm_setup_guest_pvclock` does: its version made odd (`(version + 1) |
/// 1`), the fields `update` gives from what the guest holds, then the
/// version made even; KVM keeps a `PVCLOCK_GUEST_STOPPED` the guest has not
/// cleared yet, and so does this. Nothing is written, and false returned,
/// where KVM's cache takes no time info ([`guest_mem::with_page`]: across a
/// page, a read-only slot, no slot). Bytes, volatile: the guest's address
/// need not be aligned, and the guest reads it while it changes.
fn update_time_info(ram: &Ram, gpa: u64, update: impl FnOnce(VcpuTimeInfo) -> VcpuTimeInfo) -> bool {
    use core::sync::atomic::{Ordering, fence};
    guest_mem::with_page(&mut ram.lock().unwrap(), gpa, TIME_INFO_LEN, |at| {
        // SAFETY: `with_page` gives the host address of 32 bytes of guest
        // RAM within one page of a slot that stays mapped while the slot
        // table is locked (it is, for this call); arrays of bytes have no
        // alignment.
        unsafe {
            let old = VcpuTimeInfo::from_bytes(&core::ptr::read_volatile(at.cast::<[u8; TIME_INFO_LEN]>()));
            let odd = old.version.wrapping_add(1) | 1;
            core::ptr::write_volatile(at.cast::<[u8; 4]>(), odd.to_le_bytes());
            fence(Ordering::SeqCst);
            let mut new = update(old);
            new.flags |= old.flags & PVCLOCK_GUEST_STOPPED;
            new.version = odd;
            core::ptr::write_volatile(at.cast::<[u8; TIME_INFO_LEN]>(), new.to_bytes());
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(at.cast::<[u8; 4]>(), odd.wrapping_add(1).to_le_bytes());
        }
    })
}

/// The time info address in a `MSR_KVM_SYSTEM_TIME_NEW` value: KVM's
/// `system_time & ~1ULL` (kvm_write_system_time), the enable bit off and
/// nothing aligned.
fn time_info_gpa(value: u64) -> u64 {
    value & !1
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
    ram: &Ram,
    now_ns: impl Fn() -> u64,
) {
    if value & 1 == 0 {
        return;
    }
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
    // Where KVM's cache takes no time info, the guest gets none, as on KVM.
    update_time_info(ram, time_info_gpa(value), |_| info);
}

/// `PVCLOCK_GUEST_STOPPED`: the vCPU was stopped by the host.
pub(crate) const PVCLOCK_GUEST_STOPPED: u8 = 1 << 1;

/// `KVM_KVMCLOCK_CTRL` for the vCPU whose `MSR_KVM_SYSTEM_TIME_NEW` is
/// `value`: sets `PVCLOCK_GUEST_STOPPED` in its time info, which the guest's
/// lockup watchdogs read (and clear) after a pause, so that the time the VM
/// was paused is not taken for a soft lockup. False when the vCPU has no
/// kvm-clock (the MSR's enable bit off), which KVM answers with `EINVAL`;
/// with it on, KVM takes the request (`pvclock_set_guest_stopped_request`)
/// whether or not its cache could take the time info, which then gets
/// nothing, and so does this.
pub(crate) fn set_guest_stopped(value: u64, ram: &Ram) -> bool {
    if value & 1 == 0 {
        return false;
    }
    update_time_info(ram, time_info_gpa(value), |mut info| {
        info.flags |= PVCLOCK_GUEST_STOPPED;
        info
    });
    true
}

/// Handles a write of `MSR_KVM_WALL_CLOCK_NEW` (by the guest or a restore):
/// fills the `pvclock_wall_clock` at the guest physical address `value` with
/// the wall time at which the VM clock was 0.
pub(crate) fn wall_clock(state: &Mutex<State>, value: u64, ram: &Ram, now_ns: u64) {
    state.lock().unwrap().wall_msr = value;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let boot = now.saturating_sub(std::time::Duration::from_nanos(now_ns));
    write_wall_clock(ram, value, boot);
}

/// KVM's `kvm_write_wall_clock`, step by step: nothing for address 0; the
/// version read (if that fails, nothing is written); an odd one is the
/// guest's junk and made even; the version advanced and written (if that
/// fails, nothing more), then version, seconds and nanoseconds, then the
/// version advanced again. Each through `kvm_read_guest`/`kvm_write_guest`
/// ([`guest_mem`]), the slot table locked throughout.
fn write_wall_clock(ram: &Ram, gpa: u64, epoch: std::time::Duration) {
    if gpa == 0 {
        return;
    }
    let mut slots = ram.lock().unwrap();
    let mut v = [0u8; 4];
    if !guest_mem::read(&mut slots, gpa, &mut v) {
        return;
    }
    let mut version = u32::from_le_bytes(v);
    if version & 1 != 0 {
        version = version.wrapping_add(1);
    }
    version = version.wrapping_add(1);
    if !guest_mem::write(&mut slots, gpa, &version.to_le_bytes()) {
        return;
    }
    let mut wc = [0u8; 12];
    wc[0..4].copy_from_slice(&version.to_le_bytes());
    // KVM's `(u32)wall_nsec`: the seconds wrap in 2106.
    #[allow(clippy::cast_possible_truncation)]
    wc[4..8].copy_from_slice(&(epoch.as_secs() as u32).to_le_bytes());
    wc[8..12].copy_from_slice(&epoch.subsec_nanos().to_le_bytes());
    guest_mem::write(&mut slots, gpa, &wc);
    version = version.wrapping_add(1);
    guest_mem::write(&mut slots, gpa, &version.to_le_bytes());
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

    const PAGE: u64 = guest_mem::PAGE;

    /// Guest RAM of two one-page slots over `mem`: 0x10000 (writable) and
    /// 0x11000 (read-only if `readonly1`), with dirty logging.
    fn ram(mem: &mut [u8], readonly1: bool) -> Ram {
        let host = mem.as_mut_ptr() as u64;
        let mut t = HashMap::new();
        t.insert(0, Slot::new(0x10000, PAGE, host, false, true));
        t.insert(1, Slot::new(0x10000 + PAGE, PAGE, host + PAGE, readonly1, true));
        Mutex::new(t)
    }

    fn info_at(mem: &[u8], off: usize) -> VcpuTimeInfo {
        VcpuTimeInfo::from_bytes(mem[off..off + TIME_INFO_LEN].try_into().unwrap())
    }

    #[test]
    fn test_time_info_layout() {
        let info = VcpuTimeInfo {
            version: 3,
            tsc_timestamp: 0x1122_3344_5566_7788,
            system_time: 9,
            tsc_to_system_mul: 0xdead_beef,
            tsc_shift: -2,
            flags: 5,
        };
        let b = info.to_bytes();
        // struct pvclock_vcpu_time_info: version, pad0, tsc_timestamp,
        // system_time, tsc_to_system_mul, tsc_shift, flags, pad[2].
        assert_eq!(&b[0..4], &[3, 0, 0, 0]);
        assert_eq!(&b[8..16], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!((b[28], b[29]), (0xfe, 5));
        assert_eq!(VcpuTimeInfo::from_bytes(&b), info);
    }

    // The time info at the address the guest gives, aligned or not (KVM:
    // `& ~1`), updated with the version odd then even, a GUEST_STOPPED the
    // guest has not cleared kept, the page dirty.
    #[test]
    fn test_time_info_is_updated_in_place_at_any_address() {
        let mut mem = vec![0u8; 2 * PAGE as usize];
        let r = ram(&mut mem, false);
        let value = 0x10000 + 0x46 + 1; // not 32-byte aligned; the enable bit
        assert_eq!(time_info_gpa(value), 0x10046);
        let fresh = VcpuTimeInfo { system_time: 5, flags: PVCLOCK_TSC_STABLE, ..Default::default() };
        assert!(update_time_info(&r, time_info_gpa(value), |_| fresh));
        let got = info_at(&mem, 0x46);
        assert_eq!((got.version, got.system_time, got.flags), (2, 5, PVCLOCK_TSC_STABLE));
        assert!(mem[..0x46].iter().all(|&b| b == 0) && mem[0x46 + 32..].iter().all(|&b| b == 0));
        // KVM_KVMCLOCK_CTRL: the flag set, the rest as it was.
        assert!(set_guest_stopped(value, &r));
        let got = info_at(&mem, 0x46);
        assert_eq!((got.version, got.system_time, got.flags), (4, 5, PVCLOCK_TSC_STABLE | PVCLOCK_GUEST_STOPPED));
        // The next update keeps the flag the guest has not cleared.
        assert!(update_time_info(&r, 0x10046, |_| fresh));
        assert_eq!(info_at(&mem, 0x46).flags, PVCLOCK_TSC_STABLE | PVCLOCK_GUEST_STOPPED);
        assert_eq!(info_at(&mem, 0x46).version, 6);
        let mut log = [0u64; 1];
        r.lock().unwrap().get_mut(&0).unwrap().take_host_dirty(&mut log);
        assert_eq!(log[0], 1);
        // With the enable bit off, KVM_KVMCLOCK_CTRL is EINVAL.
        assert!(!set_guest_stopped(value & !1, &r));
    }

    // Where KVM's cache takes no time info, nothing is written: across a
    // page (here into the next, writable, slot), in a read-only slot, where
    // no slot is. KVM_KVMCLOCK_CTRL still succeeds with the enable bit on.
    #[test]
    fn test_time_info_is_not_written_where_kvm_takes_none() {
        let mut mem = vec![0u8; 2 * PAGE as usize];
        let r = ram(&mut mem, false);
        let info = VcpuTimeInfo { system_time: 5, ..Default::default() };
        assert!(!update_time_info(&r, 0x10000 + PAGE - 16, |_| info));
        let mut mem2 = vec![0u8; 2 * PAGE as usize];
        let r2 = ram(&mut mem2, true);
        assert!(!update_time_info(&r2, 0x10000 + PAGE + 64, |_| info));
        assert!(!update_time_info(&r2, 0x10000 + 2 * PAGE, |_| info));
        assert!(set_guest_stopped(0x10000 + 2 * PAGE + 1, &r2));
        assert!(mem.iter().all(|&b| b == 0) && mem2.iter().all(|&b| b == 0));
    }

    // kvm_write_wall_clock's steps: an even version advanced to odd, the
    // fields, then even; an odd (junk) one made even first; at an address
    // across two slots, written page by page.
    #[test]
    fn test_wall_clock_as_kvm_writes_it() {
        let mut mem = vec![0u8; 2 * PAGE as usize];
        let r = ram(&mut mem, false);
        let epoch = std::time::Duration::new(1_700_000_000, 123);
        let wc = |mem: &[u8], off: usize| {
            let u = |i: usize| u32::from_le_bytes(mem[off + i..off + i + 4].try_into().unwrap());
            (u(0), u(4), u(8))
        };
        mem[0x102..0x106].copy_from_slice(&4u32.to_le_bytes());
        write_wall_clock(&r, 0x10102, epoch);
        assert_eq!(wc(&mem, 0x102), (6, 1_700_000_000, 123));
        mem[0x102..0x106].copy_from_slice(&7u32.to_le_bytes());
        write_wall_clock(&r, 0x10102, epoch);
        assert_eq!(wc(&mem, 0x102), (10, 1_700_000_000, 123));
        // Across the two slots' boundary.
        let off = PAGE as usize - 6;
        write_wall_clock(&r, 0x10000 + off as u64, epoch);
        assert_eq!(wc(&mem, off), (2, 1_700_000_000, 123));
        let mut log = [0u64; 1];
        r.lock().unwrap().get_mut(&1).unwrap().take_host_dirty(&mut log);
        assert_eq!(log[0], 1);
    }

    // Where kvm_write_wall_clock stops: no address; a version it cannot
    // read (no slot); a version it cannot write (a read-only slot): nothing
    // written. Into a read-only slot from a writable one before it: the
    // version's first bytes (in the writable page) only, as KVM's
    // kvm_write_guest writes the pages before the one it refuses.
    #[test]
    fn test_wall_clock_where_kvm_writes_nothing() {
        let mut mem = vec![0u8; 2 * PAGE as usize];
        let r = ram(&mut mem, true);
        let epoch = std::time::Duration::new(1_700_000_000, 123);
        write_wall_clock(&r, 0, epoch);
        write_wall_clock(&r, 0x10000 + 2 * PAGE, epoch);
        write_wall_clock(&r, 0x10000 + PAGE + 8, epoch);
        assert!(mem.iter().all(|&b| b == 0));
        write_wall_clock(&r, 0x10000 + PAGE - 2, epoch);
        assert_eq!(&mem[PAGE as usize - 2..PAGE as usize + 10], &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
