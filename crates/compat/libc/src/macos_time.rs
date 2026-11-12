// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `clock_gettime` with Linux's `CLOCK_MONOTONIC` on macOS.
//!
//! Linux's `CLOCK_MONOTONIC` (kernel/time/timekeeping.c, `ktime_get_ts64`)
//! has nanosecond resolution, never reads lower than it has read (setting the
//! wall clock moves only `wall_to_monotonic`, `do_settimeofday64`; NTP
//! changes its rate, never its value), and does not count the time the host
//! is suspended (`__timekeeping_inject_sleeptime` adds that to
//! `CLOCK_BOOTTIME`'s offset alone). Firecracker subtracts two readings of it
//! without a check (`LatencyMetricsRecorder`, the start-up times) and keeps
//! deadlines in it (MMDS tokens).
//!
//! macOS's clock of that name is none of the three. Libc computes it as
//! `gettimeofday` minus the boot time, in microseconds (Libc
//! gen/clock_gettime.c, `_mach_boottime_usec`), so it is the wall clock seen
//! from the boot:
//!
//! - it reads lower than before, by about a nanosecond once a second, while
//!   an NTP adjustment is in force: user space extends the kernel's last
//!   time-of-day record with the scale for ticks, the kernel makes the next
//!   record with the scale for whole seconds, and the two differ (xnu
//!   osfmk/kern/clock.c `scale_delta`, `get_scale_factors_from_adj`;
//!   libsyscall `__commpage_gettimeofday_internal`). Measured on macOS 27.2:
//!   766 records below the one before in the 18 minutes after an NTP
//!   synchronisation, by 0.97 ns each, none in the 27 minutes before it. In
//!   microseconds that is a reading 1 µs lower whenever a microsecond begins
//!   in that nanosecond; such a reading itself was not caught (none in 16
//!   billion readings over the next 30 minutes, where the arithmetic gives
//!   about two);
//! - it reads off by the whole step while the wall clock is being set: the
//!   kernel publishes the new time of day first and the new boot time after
//!   the hardware clock is written (`clock_set_calendar_microtime`), and
//!   Libc's check that the boot time did not change passes in between (from
//!   the source; setting the clock needs root);
//! - it counts the time the Mac sleeps.
//!
//! The macOS clock with Linux's three properties is `CLOCK_UPTIME_RAW`:
//! `mach_absolute_time` in nanoseconds (Libc `clock_gettime_nsec_np`), the
//! hardware counter, which only counts up and stops while the Mac sleeps
//! (`mach_continuous_time`, `CLOCK_MONOTONIC_RAW`, is the one that adds
//! `mach_absolutetime_asleep`: osfmk/kern/clock.c). So `CLOCK_MONOTONIC`
//! reads that clock here. It is also the clock of `std::time::Instant` on
//! macOS and of the hypervisor backend's counters, so a `CLOCK_MONOTONIC`
//! reading and those have one origin.
//!
//! One difference from Linux is left: this clock is not steered by NTP, as
//! Linux's `CLOCK_MONOTONIC_RAW` is not. It runs at the counter's own rate,
//! where Linux's `CLOCK_MONOTONIC` is brought to UTC's rate, by at most
//! 500 ppm (`MAXFREQ`, include/linux/timex.h). An interval measured here
//! differs from the same interval on Linux by the counter's rate error, at
//! most that bound on a host NTP could discipline at all.
//!
//! The other clocks are macOS's own, unchanged; `CLOCK_BOOTTIME` has no
//! macOS constant in this crate and no user in Firecracker.

use upstream as libc;
use upstream::{c_int, clockid_t, timespec};

/// `clock_gettime(2)`, with Linux's `CLOCK_MONOTONIC` (see the module's
/// text): that clock is `CLOCK_UPTIME_RAW`'s reading. Any other clock is
/// macOS's.
///
/// # Safety
/// `tp` must be valid for writes.
pub unsafe fn clock_gettime(clk_id: clockid_t, tp: *mut timespec) -> c_int {
    let clock = if clk_id == libc::CLOCK_MONOTONIC { libc::CLOCK_UPTIME_RAW } else { clk_id };
    // SAFETY: the caller's contract.
    unsafe { libc::clock_gettime(clock, tp) }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// `mach_timebase_info_data_t`: ticks times `numer` over `denom` are nanoseconds.
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }

    extern "C" {
        fn mach_absolute_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> c_int;
    }

    fn read(clock: clockid_t) -> timespec {
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: a timespec to fill.
        assert_eq!(unsafe { clock_gettime(clock, &mut ts) }, 0);
        ts
    }

    fn ns(ts: timespec) -> u128 {
        u128::try_from(ts.tv_sec).unwrap() * 1_000_000_000 + u128::try_from(ts.tv_nsec).unwrap()
    }

    /// `mach_absolute_time` in nanoseconds, as Libc's `clock_gettime_nsec_np`
    /// converts it.
    fn mach_ns() -> u128 {
        let mut info = Timebase { numer: 0, denom: 0 };
        // SAFETY: a structure to fill; no arguments otherwise.
        let ticks = unsafe {
            assert_eq!(mach_timebase_info(&mut info), 0);
            mach_absolute_time()
        };
        u128::from(ticks) * u128::from(info.numer) / u128::from(info.denom)
    }

    // Linux: CLOCK_MONOTONIC is in nanoseconds (ktime_get_ts64). macOS's own
    // CLOCK_MONOTONIC is a number of microseconds: every reading's
    // nanoseconds end in 000, so this fails on it at the first assertion.
    #[test]
    fn test_clock_monotonic_is_in_nanoseconds() {
        let finer = (0..1000).filter(|_| read(libc::CLOCK_MONOTONIC).tv_nsec % 1000 != 0).count();
        assert!(finer > 0, "1000 readings, each a whole number of microseconds");
    }

    // The clock is the hardware counter's (mach_absolute_time, which Rust's
    // Instant and the hypervisor backend read): a reading lies between the
    // counter read before it and after it. macOS's own CLOCK_MONOTONIC is
    // the wall clock since the boot, which is off from the counter by the
    // time slept and by what NTP has added or taken.
    #[test]
    fn test_clock_monotonic_is_the_hardware_counter() {
        for _ in 0..1000 {
            let before = mach_ns();
            let got = ns(read(libc::CLOCK_MONOTONIC));
            let after = mach_ns();
            assert!(before <= got && got <= after, "{before} <= {got} <= {after}");
        }
    }

    // Linux: CLOCK_MONOTONIC never reads lower than it has read. 10 million
    // readings on 4 threads, each compared with the last one any thread
    // took before it began.
    #[test]
    fn test_clock_monotonic_never_reads_lower() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static LAST: AtomicU64 = AtomicU64::new(0);
        let threads: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut lower = 0u64;
                    let mut mine = 0u64;
                    for _ in 0..2_500_000 {
                        let seen = LAST.load(Ordering::SeqCst);
                        let now = u64::try_from(ns(read(libc::CLOCK_MONOTONIC))).unwrap();
                        if now < seen || now < mine {
                            lower += 1;
                        }
                        mine = now;
                        LAST.fetch_max(now, Ordering::SeqCst);
                    }
                    lower
                })
            })
            .collect();
        let lower: u64 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(lower, 0, "readings lower than one taken before");
    }

    // The other clocks are macOS's own.
    #[test]
    fn test_other_clocks_are_passed_on() {
        let wall = read(libc::CLOCK_REALTIME);
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        // SAFETY: a timeval to fill.
        assert_eq!(unsafe { libc::gettimeofday(&mut tv, core::ptr::null_mut()) }, 0);
        assert!((tv.tv_sec - wall.tv_sec).abs() <= 1, "{} and {}", tv.tv_sec, wall.tv_sec);
        let cpu = read(libc::CLOCK_THREAD_CPUTIME_ID);
        assert!(cpu.tv_sec < 3600, "thread CPU time {}", cpu.tv_sec);
        let mut ts = timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: a timespec to fill.
        assert_eq!(unsafe { clock_gettime(99, &mut ts) }, -1);
    }
}
