// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! KVM's TSC matching, the decision alone: which offset a host's write of a
//! vCPU's `IA32_TSC` gives it (Linux v6.1 arch/x86/kvm/x86.c,
//! `kvm_synchronize_tsc`, lines 2665-2718, and `__kvm_synchronize_tsc`,
//! 2618-2663). KVM takes a host write close in time and value to the last
//! one as an attempt to synchronize the vCPUs, and gives the vCPU the offset
//! of the current generation rather than the value written: a restore that
//! writes each vCPU's saved TSC, saved at a slightly different moment each,
//! ends with one offset for the VM, and so does a boot that writes 0 to each
//! vCPU (KVM itself writes 0 at a vCPU's creation, `kvm_arch_vcpu_postcreate`,
//! x86.c:11951). WHP has no offset to give a virtual processor, only its TSC
//! register; the backend (`vcpu.rs`, `synchronize_tsc`) gives a matched vCPU
//! the generation's offset by copying the TSC of the vCPU that began the
//! generation with partition time held still.
//!
//! It uses nothing but `core`, so it is compiled into the fuzz crate
//! (`fuzz/src/lib.rs`) and its tests run on every host.

/// What KVM keeps for the matching, per VM (`kvm->arch`): the last host
/// write and when it was made, at which TSC rate, and the vCPU whose offset
/// is the current generation's (`cur_tsc_offset`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TscSync {
    /// `last_tsc_nsec`: the monotonic time of the last write, in ns.
    last_ns: u64,
    /// `last_tsc_write`: the value of the last write.
    last_write: u64,
    /// `last_tsc_khz`: the vCPU's TSC rate at the last write (0 before any).
    last_khz: u32,
    /// The vCPU whose write began the current generation, which holds its
    /// offset (`cur_tsc_offset`); `None` before any write.
    reference: Option<u32>,
}

/// The offset a host write gives the vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TscWrite {
    /// Matched, on a host whose TSC is stable: the vCPU takes the current
    /// generation's offset, that of vCPU `reference` (x86.c:2703-2705,
    /// `offset = kvm->arch.cur_tsc_offset`), whatever value was written.
    Matched { reference: u32 },
    /// Matched, on a host whose TSC is not stable: the value written plus
    /// the cycles elapsed since the last write, as its own offset; the
    /// generation goes on (x86.c:2706-2710).
    MatchedUnstable { value: u64 },
    /// Not matched: the value written, which begins a new generation whose
    /// offset is this vCPU's (x86.c:2637-2652); the other vCPUs keep theirs.
    New { value: u64 },
}

/// `nsec_to_cycles`: `ns` nanoseconds in cycles of a `khz` TSC (KVM scales
/// by the vCPU's `virtual_tsc_mult`/`shift`, which are this product's
/// fixed-point form).
pub fn ns_to_cycles(ns: u64, khz: u32) -> u64 {
    (u128::from(ns) * u128::from(khz) / 1_000_000) as u64
}

impl TscSync {
    /// A VM's state before any write.
    pub const fn new() -> TscSync {
        TscSync {
            last_ns: 0,
            last_write: 0,
            last_khz: 0,
            reference: None,
        }
    }

    /// A host's write of `data` to vCPU `vp`'s `IA32_TSC` at monotonic time
    /// `ns`, the vCPU's TSC running at `khz` (0: unknown), on a host whose
    /// TSC is `stable` or not (`kvm_check_tsc_unstable`): the offset the
    /// vCPU gets, and the state after it, as `kvm_synchronize_tsc`:
    /// - with the rate known, a write of 0 is synchronizing (a vCPU's
    ///   creation or reset, x86.c:2677-2683), and so is a write within one
    ///   second of TSC cycles either side of the last write advanced by the
    ///   time since it, `last_tsc_write + nsec_to_cycles(elapsed)`
    ///   (x86.c:2684-2694), compared in u64 arithmetic that wraps as KVM's;
    /// - a synchronizing write at the last write's rate is matched
    ///   (x86.c:2702-2712); any other begins a new generation;
    /// - the write is then the last one, its time, value and rate
    ///   (x86.c:2627-2630), the value plus the elapsed cycles for a matched
    ///   one on an unstable host (x86.c:2708).
    pub fn write(&mut self, vp: u32, data: u64, ns: u64, khz: u32, stable: bool) -> TscWrite {
        let elapsed = ns.wrapping_sub(self.last_ns);
        let synchronizing = khz != 0 && {
            if data == 0 {
                true
            } else {
                let expected = self.last_write.wrapping_add(ns_to_cycles(elapsed, khz));
                let hz = u64::from(khz) * 1000;
                data < expected.wrapping_add(hz) && data.wrapping_add(hz) > expected
            }
        };
        let (out, written) = match self.reference {
            Some(reference) if synchronizing && khz == self.last_khz => {
                if stable {
                    (TscWrite::Matched { reference }, data)
                } else {
                    let value = data.wrapping_add(ns_to_cycles(elapsed, khz));
                    (TscWrite::MatchedUnstable { value }, value)
                }
            }
            // Before any write `last_khz` is 0 and a synchronizing write
            // has a rate, so the first write is never matched.
            _ => {
                self.reference = Some(vp);
                (TscWrite::New { value: data }, data)
            }
        };
        self.last_ns = ns;
        self.last_write = written;
        self.last_khz = khz;
        out
    }

    /// The vCPU whose offset is the current generation's.
    pub fn reference(&self) -> Option<u32> {
        self.reference
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KHZ: u32 = 3_692_995;
    const HZ: u64 = KHZ as u64 * 1000;
    const MS: u64 = 1_000_000;

    #[test]
    fn test_a_boot_that_writes_0_to_each_vcpu_has_one_offset() {
        let mut s = TscSync::new();
        // KVM's own write of 0 at each vCPU's creation, then Firecracker's
        // boot MSRs (IA32_TSC 0) on each, a few ms later.
        assert_eq!(s.write(0, 0, 10 * MS, KHZ, true), TscWrite::New { value: 0 });
        assert_eq!(s.write(1, 0, 11 * MS, KHZ, true), TscWrite::Matched { reference: 0 });
        assert_eq!(s.write(0, 0, 40 * MS, KHZ, true), TscWrite::Matched { reference: 0 });
        assert_eq!(s.write(1, 0, 900 * MS, KHZ, true), TscWrite::Matched { reference: 0 });
        assert_eq!(s.reference(), Some(0));
    }

    #[test]
    fn test_a_restore_matches_the_save_gap_away() {
        // A new process's VM: the vCPUs' creation (0), then each vCPU's saved
        // TSC, the second saved 52 us after the first and written 300 us
        // after it.
        let saved = 7_000 * HZ;
        let gap = 52 * HZ / 1_000_000;
        let mut s = TscSync::new();
        s.write(0, 0, MS, KHZ, true);
        s.write(1, 0, MS + 200_000, KHZ, true);
        assert_eq!(s.write(0, saved, 5 * MS, KHZ, true), TscWrite::New { value: saved });
        assert_eq!(s.reference(), Some(0));
        assert_eq!(s.write(1, saved + gap, 5 * MS + 300_000, KHZ, true), TscWrite::Matched { reference: 0 });
        // Saved again, an hour of guest time later, and restored again.
        let later = saved + 3_600 * HZ;
        let mut t = TscSync::new();
        t.write(0, 0, MS, KHZ, true);
        t.write(1, 0, MS, KHZ, true);
        assert_eq!(t.write(0, later, 9 * MS, KHZ, true), TscWrite::New { value: later });
        assert_eq!(t.write(1, later + gap, 9 * MS + 250_000, KHZ, true), TscWrite::Matched { reference: 0 });
        // In the other order too: the vCPU written first is the reference.
        let mut u = TscSync::new();
        assert_eq!(u.write(1, later + gap, MS, KHZ, true), TscWrite::New { value: later + gap });
        assert_eq!(u.write(0, later, MS + 100_000, KHZ, true), TscWrite::Matched { reference: 1 });
    }

    #[test]
    fn test_the_one_second_window_and_its_ends() {
        // After a write of `w` at 0 ns, the window at time `t` is
        // (w + cycles(t) - HZ, w + cycles(t) + HZ), both ends out.
        let w = 1_000 * HZ;
        let at = |data: u64, t: u64| {
            let mut s = TscSync::new();
            s.write(0, w, 0, KHZ, true);
            s.write(1, data, t, KHZ, true)
        };
        let matched = TscWrite::Matched { reference: 0 };
        assert_eq!(at(w + HZ - 1, 0), matched);
        assert_eq!(at(w + HZ, 0), TscWrite::New { value: w + HZ });
        assert_eq!(at(w - HZ + 1, 0), matched);
        assert_eq!(at(w - HZ, 0), TscWrite::New { value: w - HZ });
        // Two seconds later the window has moved by two seconds of cycles.
        let two = ns_to_cycles(2_000 * MS, KHZ);
        assert_eq!(at(w + two, 2_000 * MS), matched);
        assert_eq!(at(w, 2_000 * MS), TscWrite::New { value: w });
        assert_eq!(at(w + two + HZ - 1, 2_000 * MS), matched);
        assert_eq!(at(w + two + HZ, 2_000 * MS), TscWrite::New { value: w + two + HZ });
    }

    #[test]
    fn test_a_write_of_0_matches_at_any_time_and_value() {
        let mut s = TscSync::new();
        s.write(0, 123_456 * HZ, 0, KHZ, true);
        assert_eq!(s.write(1, 0, 3_600_000 * MS, KHZ, true), TscWrite::Matched { reference: 0 });
    }

    #[test]
    fn test_another_rate_or_none_begins_a_new_generation() {
        let mut s = TscSync::new();
        s.write(0, 0, 0, KHZ, true);
        // The same value at another rate: not matched, a new generation.
        assert_eq!(s.write(1, 0, 1_000, KHZ - 1, true), TscWrite::New { value: 0 });
        assert_eq!(s.reference(), Some(1));
        // An unknown rate never synchronizes, even a write of 0.
        assert_eq!(s.write(0, 0, 2_000, 0, true), TscWrite::New { value: 0 });
        assert_eq!(s.reference(), Some(0));
        // ... and leaves `last_khz` 0, so the next write at a rate is new too.
        assert_eq!(s.write(1, 0, 3_000, KHZ, true), TscWrite::New { value: 0 });
    }

    #[test]
    fn test_a_later_unmatched_write_begins_a_generation_of_its_own() {
        let mut s = TscSync::new();
        s.write(0, 0, 0, KHZ, true);
        assert_eq!(s.write(1, 0, MS, KHZ, true), TscWrite::Matched { reference: 0 });
        // vCPU 1 written far from vCPU 0: its own generation; vCPU 0 keeps
        // its offset (nothing is written to it).
        let far = 50_000 * HZ;
        assert_eq!(s.write(1, far, 2 * MS, KHZ, true), TscWrite::New { value: far });
        assert_eq!(s.reference(), Some(1));
        // A write close to that one matches vCPU 1's generation, even on
        // vCPU 0.
        assert_eq!(s.write(0, far + 10, 3 * MS, KHZ, true), TscWrite::Matched { reference: 1 });
        // vCPU 1's own write matched to its own generation.
        assert_eq!(s.write(1, far + 20, 4 * MS, KHZ, true), TscWrite::Matched { reference: 1 });
    }

    #[test]
    fn test_an_unstable_host_adds_the_elapsed_cycles_and_keeps_the_generation() {
        let mut s = TscSync::new();
        let w = 10 * HZ;
        s.write(0, w, 0, KHZ, false);
        let elapsed = 3 * MS;
        let value = w + 5 + ns_to_cycles(elapsed, KHZ);
        assert_eq!(s.write(1, w + 5, elapsed, KHZ, false), TscWrite::MatchedUnstable { value });
        assert_eq!(s.reference(), Some(0));
        // The last write is the value with the cycles added (x86.c:2708).
        let expected = value + ns_to_cycles(MS, KHZ);
        assert_eq!(s.write(0, expected + HZ - 1, elapsed + MS, KHZ, false), TscWrite::MatchedUnstable {
            value: expected + HZ - 1 + ns_to_cycles(MS, KHZ)
        });
    }

    #[test]
    fn test_the_comparison_wraps_as_kvms_u64() {
        // A write near 2^64: `data + hz` wraps in KVM's comparison, so a
        // value just below the top is not matched against a small one.
        let mut s = TscSync::new();
        s.write(0, 5, 0, KHZ, true);
        assert_eq!(s.write(1, u64::MAX - 1, 0, KHZ, true), TscWrite::New { value: u64::MAX - 1 });
        // A last write near 2^64: the window's top, `expected + hz`, wraps
        // to a small number, so nothing matches it, as in KVM.
        let mut t = TscSync::new();
        t.write(0, u64::MAX - 10, 0, KHZ, true);
        assert_eq!(t.write(1, u64::MAX - 10, 0, KHZ, true), TscWrite::New { value: u64::MAX - 10 });
    }

    #[test]
    fn test_ns_to_cycles() {
        assert_eq!(ns_to_cycles(1_000_000_000, KHZ), HZ);
        assert_eq!(ns_to_cycles(1_000, 1_000_000), 1_000);
        assert_eq!(ns_to_cycles(u64::MAX, u32::MAX), (u128::from(u64::MAX) * u128::from(u32::MAX) / 1_000_000) as u64);
    }
}
