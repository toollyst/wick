// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Clocks, `localtime_r` and `timerfd` on Windows.
//!
//! Clocks:
//! - `CLOCK_REALTIME`: `GetSystemTimePreciseAsFileTime`;
//! - `CLOCK_MONOTONIC` (and `_RAW`, `_COARSE`): the performance counter,
//!   the clock of `std::time::Instant`;
//! - `CLOCK_BOOTTIME`: interrupt time, which counts while suspended;
//! - `CLOCK_PROCESS_CPUTIME_ID` / `CLOCK_THREAD_CPUTIME_ID`: the CPU time of
//!   the process / calling thread, kernel and user, to the nanosecond as
//!   Linux counts it (the scheduler's run time): the cycles Windows counts
//!   for them (`QueryProcessCycleTime`, `QueryThreadCycleTime`, read from the
//!   TSC at each switch) at the TSC's rate, which an invariant TSC keeps
//!   constant; the rate is measured against the performance counter since
//!   the process started ([`cpu_ns`]). `GetProcessTimes`'s kernel and user
//!   times, which Windows charges a clock tick at a time (15.6 ms), read 0
//!   for a process that ran a few milliseconds; they are used only on a host
//!   whose TSC is not invariant, where cycles are no measure of time
//!   (Learn, `QueryThreadCycleTime`: "Do not attempt to convert the CPU
//!   clock cycles ... to elapsed time" for CPUs that vary the timer's rate).
//!   Both counters count at the TSC's rate while their thread runs and
//!   never faster: on a PC (Ryzen 9 7900 under Hyper-V, 3393774) 0.994 to
//!   0.999 x the TSC over 2 to 200 ms of spinning, idle or with 22 other
//!   threads spinning, and less when the thread got less of the CPU
//!   (0.72 x with 46 threads on 24 logical processors)
//!   (`test_cpu_cycle_counters_on_record`, CPUCYCLEREC lines).
//!
//! A timerfd is a manual-reset, high-resolution waitable timer: signalled
//! while expirations are waiting to be read, which is what `epoll` waits on.
//! The process keeps each timer's schedule; `read` (through this crate's
//! `read`) returns the expirations since the last read as one `u64` and
//! re-arms the kernel timer for the next one, so the count is exact even when
//! reads come late. `TFD_TIMER_ABSTIME` and all clocks above are supported.

use std::sync::{Arc, Mutex, OnceLock};

use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, SetLastError,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows_sys::Win32::System::Threading::{
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, CREATE_WAITABLE_TIMER_MANUAL_RESET,
    CancelWaitableTimer, CreateWaitableTimerExW, GetCurrentProcess, GetCurrentThread,
    GetProcessTimes, GetThreadTimes, INFINITE, SetWaitableTimer, TIMER_ALL_ACCESS,
    WaitForSingleObject,
};
use windows_sys::Win32::System::WindowsProgramming::{
    QueryInterruptTimePrecise, QueryProcessCycleTime, QueryThreadCycleTime,
};

use crate::{c_char, c_int, time_t};

/// `clockid_t`.
pub type clockid_t = c_int;
/// Wall-clock time.
pub const CLOCK_REALTIME: clockid_t = 0;
/// Monotonic time, not counting suspend.
pub const CLOCK_MONOTONIC: clockid_t = 1;
/// CPU time of the process.
pub const CLOCK_PROCESS_CPUTIME_ID: clockid_t = 2;
/// CPU time of the calling thread.
pub const CLOCK_THREAD_CPUTIME_ID: clockid_t = 3;
/// As `CLOCK_MONOTONIC`.
pub const CLOCK_MONOTONIC_RAW: clockid_t = 4;
/// As `CLOCK_REALTIME`.
pub const CLOCK_REALTIME_COARSE: clockid_t = 5;
/// As `CLOCK_MONOTONIC`.
pub const CLOCK_MONOTONIC_COARSE: clockid_t = 6;
/// Monotonic time, counting suspend.
pub const CLOCK_BOOTTIME: clockid_t = 7;

/// `struct timespec` with the Linux layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct timespec {
    /// Seconds.
    pub tv_sec: time_t,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

/// `struct itimerspec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct itimerspec {
    /// Interval for periodic timers; zero for one-shot.
    pub it_interval: timespec,
    /// Time until the next expiration; zero to disarm.
    pub it_value: timespec,
}

/// `struct tm` with the Linux layout.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tm {
    /// Seconds (0-60).
    pub tm_sec: c_int,
    /// Minutes (0-59).
    pub tm_min: c_int,
    /// Hours (0-23).
    pub tm_hour: c_int,
    /// Day of the month (1-31).
    pub tm_mday: c_int,
    /// Month (0-11).
    pub tm_mon: c_int,
    /// Years since 1900.
    pub tm_year: c_int,
    /// Day of the week (0-6, Sunday = 0).
    pub tm_wday: c_int,
    /// Day of the year (0-365).
    pub tm_yday: c_int,
    /// Daylight saving time in effect.
    pub tm_isdst: c_int,
    /// Seconds east of UTC.
    pub tm_gmtoff: i64,
    /// Time zone abbreviation (null: not provided).
    pub tm_zone: *const c_char,
}

fn set_errno(e: c_int) {
    #[allow(clippy::cast_sign_loss)]
    // SAFETY: sets the thread's last error.
    unsafe {
        SetLastError(e as u32)
    };
}

const NANOS: i64 = 1_000_000_000;
/// 100 ns intervals from 1601-01-01 to 1970-01-01.
const EPOCH_DIFF: i64 = 116_444_736_000_000_000;

fn filetime_100ns(ft: FILETIME) -> i64 {
    #[allow(clippy::cast_possible_wrap)]
    let v = ((u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)) as i64;
    v
}

/// The TSC and the performance counter read together: the TSC at the
/// middle of the counter's read, of the tightest of three reads (the least
/// TSC between the two RDTSCs), so that a thread switch inside one read
/// does not put the pair a time slice apart.
fn tsc_and_counter() -> (u64, i64) {
    let mut best = (u64::MAX, 0u64, 0i64);
    for _ in 0..3 {
        // SAFETY: RDTSC has no preconditions.
        let a = unsafe { core::arch::x86_64::_rdtsc() };
        let mut q = 0;
        // SAFETY: writes `q`.
        unsafe { QueryPerformanceCounter(&mut q) };
        // SAFETY: as above.
        let b = unsafe { core::arch::x86_64::_rdtsc() };
        let width = b.wrapping_sub(a);
        if width < best.0 {
            best = (width, a + width / 2, q);
        }
    }
    (best.1, best.2)
}

/// [`tsc_and_counter`] at the process's start, before `main`
/// ([`ANCHOR_AT_START`]), from which the TSC's rate is measured.
static START: OnceLock<(u64, i64)> = OnceLock::new();
/// Set by [`anchor_at_start`]: [`START`] was read by the C runtime's
/// initializers, not at a first use.
static ANCHORED_AT_START: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn anchor_at_start() {
    START.get_or_init(tsc_and_counter);
    ANCHORED_AT_START.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Run by the C runtime before `main` (its `.CRT$XCU` initializers), so that
/// the TSC's rate is measured over the process's life, not from a first
/// use. Referenced by [`cpu_ns`], so the object that holds it is linked
/// wherever the CPU clocks are.
#[used]
#[link_section = ".CRT$XCU"]
static ANCHOR_AT_START: extern "C" fn() = anchor_at_start;

/// Whether the host's TSC is invariant (CPUID.80000007H:EDX bit 8): it then
/// runs at one rate in every power state, and cycles are a measure of time.
fn tsc_invariant() -> bool {
    use core::arch::x86_64::__cpuid;
    static INVARIANT: OnceLock<bool> = OnceLock::new();
    *INVARIANT.get_or_init(|| __cpuid(0x8000_0000).eax >= 0x8000_0007 && __cpuid(0x8000_0007).edx & (1 << 8) != 0)
}

/// `cycles` of CPU time in nanoseconds at the TSC's rate, measured against
/// the performance counter from the process's start ([`START`]) to now.
///
/// The error, whatever the span: over a span of `S` counter ticks (100 ns
/// each where the counter runs at 10 MHz) the rate is the TSC's over the
/// counter's, and the counter's count is off by at most one tick, so the
/// rate is off by at most `1/S` of itself. A thread runs at most the whole
/// span, `S` ticks, so its time is off by at most `S x 1/S`: one tick,
/// 100 ns; the process's, with `N` threads that ran, by at most `N` ticks.
/// Each TSC/counter pair adds the TSC between its two RDTSCs, halved
/// ([`tsc_and_counter`] keeps the tightest of three). So no span need be
/// waited out: only a span of at least one tick, which a read right after
/// the start waits for (at most 100 ns). Before, a read in the first
/// millisecond after the start waited the rest of it, spinning: Firecracker
/// and the jailer read their start CPU time then, and that wait, up to
/// 1 ms of CPU, was in `process_startup_time_cpu_us` (on a PC, 3393774:
/// `test_cpu_clocks_count_what_runs_finely`'s first window read the thread
/// clock 0.76 ms over its 2 ms of spinning, the process clock 0.02 ms).
/// `None` where the TSC is not invariant.
pub(crate) fn cpu_ns(cycles: u64) -> Option<i64> {
    if !tsc_invariant() {
        return None;
    }
    std::hint::black_box(&ANCHOR_AT_START);
    cpu_ns_since(cycles, *START.get_or_init(tsc_and_counter))
}

/// [`cpu_ns`] with the rate measured from `start`.
fn cpu_ns_since(cycles: u64, (t0, q0): (u64, i64)) -> Option<i64> {
    let freq = *COUNTER_HZ.get_or_init(|| {
        let mut f = 0;
        // SAFETY: writes `f`; cannot fail on Windows XP and later.
        unsafe { QueryPerformanceFrequency(&mut f) };
        f
    });
    let (mut t1, mut q1) = tsc_and_counter();
    while q1 <= q0 {
        std::hint::spin_loop();
        (t1, q1) = tsc_and_counter();
    }
    let hz = u128::from(t1.wrapping_sub(t0)) * u128::try_from(freq).ok()? / u128::try_from(q1 - q0).ok()?;
    if hz == 0 {
        return None;
    }
    i64::try_from(u128::from(cycles) * 1_000_000_000 / hz).ok()
}

/// The performance counter's frequency.
static COUNTER_HZ: OnceLock<i64> = OnceLock::new();

/// Nanoseconds on `clock`, or `None` for an unknown clock.
pub(crate) fn now_ns(clock: clockid_t) -> Option<i64> {
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    Some(match clock {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => {
            // SAFETY: writes the FILETIME.
            unsafe { GetSystemTimePreciseAsFileTime(&mut ft) };
            (filetime_100ns(ft) - EPOCH_DIFF) * 100
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE => {
            static FREQ: OnceLock<i64> = OnceLock::new();
            let freq = *FREQ.get_or_init(|| {
                let mut f = 0;
                // SAFETY: writes `f`; cannot fail on Windows XP and later.
                unsafe { QueryPerformanceFrequency(&mut f) };
                f
            });
            let mut c = 0;
            // SAFETY: writes `c`.
            unsafe { QueryPerformanceCounter(&mut c) };
            let c = i128::from(c);
            #[allow(clippy::cast_possible_truncation)]
            let ns = (c * i128::from(NANOS) / i128::from(freq)) as i64;
            ns
        }
        CLOCK_BOOTTIME => {
            let mut t = 0u64;
            // SAFETY: writes `t`.
            unsafe { QueryInterruptTimePrecise(&mut t) };
            #[allow(clippy::cast_possible_wrap)]
            let ns = t as i64 * 100;
            ns
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID if tsc_invariant() => {
            let mut cycles = 0u64;
            // SAFETY: pseudo-handles of this process/thread; writes `cycles`.
            let ok = unsafe {
                if clock == CLOCK_PROCESS_CPUTIME_ID {
                    QueryProcessCycleTime(GetCurrentProcess(), &mut cycles)
                } else {
                    QueryThreadCycleTime(GetCurrentThread(), &mut cycles)
                }
            };
            if ok == 0 {
                return None;
            }
            // The rate is measured again at each reading, a little better
            // each time; a reading never goes below the last one of its
            // clock, as Linux's never do.
            let ns = cpu_ns(cycles)?;
            if clock == CLOCK_PROCESS_CPUTIME_ID {
                static LAST: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
                LAST.fetch_max(ns, std::sync::atomic::Ordering::Relaxed).max(ns)
            } else {
                std::thread_local! {
                    static LAST: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
                }
                LAST.with(|last| {
                    let ns = ns.max(last.get());
                    last.set(ns);
                    ns
                })
            }
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            let (mut c, mut e, mut k, mut u) = (ft, ft, ft, ft);
            // SAFETY: pseudo-handles of this process/thread; writes the times.
            let ok = unsafe {
                if clock == CLOCK_PROCESS_CPUTIME_ID {
                    GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u)
                } else {
                    GetThreadTimes(GetCurrentThread(), &mut c, &mut e, &mut k, &mut u)
                }
            };
            if ok == 0 {
                return None;
            }
            (filetime_100ns(k) + filetime_100ns(u)) * 100
        }
        _ => return None,
    })
}

fn to_timespec(ns: i64) -> timespec {
    timespec {
        tv_sec: ns.div_euclid(NANOS),
        tv_nsec: ns.rem_euclid(NANOS),
    }
}

fn from_timespec(ts: &timespec) -> Option<i64> {
    if !(0..NANOS).contains(&ts.tv_nsec) || ts.tv_sec < 0 {
        return None;
    }
    ts.tv_sec.checked_mul(NANOS)?.checked_add(ts.tv_nsec)
}

/// `clock_gettime`.
///
/// # Safety
/// `tp` must be valid for writes.
pub unsafe fn clock_gettime(clk_id: clockid_t, tp: *mut timespec) -> c_int {
    match now_ns(clk_id) {
        Some(ns) => {
            // SAFETY: the caller's contract.
            unsafe { *tp = to_timespec(ns) };
            0
        }
        None => {
            set_errno(crate::EINVAL);
            -1
        }
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `localtime_r`, with `tm_gmtoff` filled in. Uses the CRT's time zone.
///
/// # Safety
/// `time` must be valid for reads and `result` for writes.
pub unsafe fn localtime_r(time: *const time_t, result: *mut tm) -> *mut tm {
    // SAFETY: an all-zero CRT `tm` is valid.
    let mut crt: upstream::tm = unsafe { std::mem::zeroed() };
    // SAFETY: the caller's contract for `time`; `crt` is ours.
    if unsafe { upstream::localtime_s(&mut crt, time) } != 0 {
        set_errno(crate::EINVAL);
        return std::ptr::null_mut();
    }
    let local = days_from_civil(
        i64::from(crt.tm_year) + 1900,
        i64::from(crt.tm_mon) + 1,
        i64::from(crt.tm_mday),
    ) * 86_400
        + i64::from(crt.tm_hour) * 3600
        + i64::from(crt.tm_min) * 60
        + i64::from(crt.tm_sec);
    // SAFETY: the caller's contract.
    unsafe {
        *result = tm {
            tm_sec: crt.tm_sec,
            tm_min: crt.tm_min,
            tm_hour: crt.tm_hour,
            tm_mday: crt.tm_mday,
            tm_mon: crt.tm_mon,
            tm_year: crt.tm_year,
            tm_wday: crt.tm_wday,
            tm_yday: crt.tm_yday,
            tm_isdst: crt.tm_isdst,
            tm_gmtoff: local - *time,
            tm_zone: std::ptr::null(),
        };
    }
    result
}

/// Non-blocking timer descriptor (Linux value).
pub const TFD_NONBLOCK: c_int = 0o4000;
/// Not inherited by child processes (Linux value).
pub const TFD_CLOEXEC: c_int = 0o2_000_000;
/// `it_value` is an absolute time on the timer's clock.
pub const TFD_TIMER_ABSTIME: c_int = 1;

#[derive(Debug)]
pub(crate) struct Timer {
    clock: clockid_t,
    nonblocking: bool,
    /// The next expiration not read yet, on `clock`, if armed.
    next: Option<i64>,
    /// 0 for one-shot.
    interval: i64,
}

fn handle(fd: c_int) -> HANDLE {
    crate::windows_fd::handle(fd)
}

/// The timer `fd` names, if it is one of ours.
pub(crate) fn lookup(fd: c_int) -> Option<Arc<Mutex<Timer>>> {
    crate::windows_fd::wick_fd::attached::<Mutex<Timer>>(fd)
}

/// Sets the kernel timer to fire at `at` on `clock`, which makes it
/// non-signalled until then; `None` makes it non-signalled and stopped.
fn program(h: HANDLE, t: &Timer, at: Option<i64>) -> bool {
    // A due time in the past fires at once; a negative value is relative.
    let due: i64 = match at {
        Some(at) => {
            let now = now_ns(t.clock).unwrap_or(at);
            -((at - now).max(0) / 100).max(1)
        }
        None => i64::MIN + 1,
    };
    // SAFETY: plain calls on our timer handle.
    unsafe {
        if SetWaitableTimer(h, &due, 0, None, std::ptr::null(), 0) == 0 {
            return false;
        }
        if at.is_none() {
            CancelWaitableTimer(h);
        }
    }
    true
}

/// `timerfd_create`.
///
/// # Safety
/// No requirements; `unsafe` like the libc function.
pub unsafe fn timerfd_create(clockid: clockid_t, flags: c_int) -> c_int {
    if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 || now_ns(clockid).is_none() {
        set_errno(crate::EINVAL);
        return -1;
    }
    // A new descriptor: refused past the jail's no-file limit.
    if !crate::wick_nofile::room(1) {
        return -1;
    }
    let make = |hires: u32| {
        // SAFETY: creates an unnamed timer.
        unsafe {
            CreateWaitableTimerExW(
                std::ptr::null(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_MANUAL_RESET | hires,
                TIMER_ALL_ACCESS,
            )
        }
    };
    let mut h = make(CREATE_WAITABLE_TIMER_HIGH_RESOLUTION);
    if h.is_null() {
        // Before Windows 10 1803.
        h = make(0);
    }
    if h.is_null() {
        return -1;
    }
    if flags & TFD_CLOEXEC == 0 {
        // SAFETY: marks our handle inheritable, like a descriptor without
        // close-on-exec.
        unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
    }
    #[allow(clippy::cast_possible_truncation)]
    let fd = h as isize as c_int;
    let timer = Timer {
        clock: clockid,
        nonblocking: flags & TFD_NONBLOCK != 0,
        next: None,
        interval: 0,
    };
    if crate::windows_fd::wick_fd::attach(fd, Arc::new(Mutex::new(timer))).is_err() {
        // SAFETY: closes the timer created above.
        unsafe { CloseHandle(h) };
        return -1;
    }
    fd
}

fn current(t: &Timer) -> itimerspec {
    let value = match t.next {
        Some(next) => {
            let now = now_ns(t.clock).unwrap_or(next);
            // A timer due now reads as just about to fire, not as disarmed.
            to_timespec((next - now).max(1))
        }
        None => timespec::default(),
    };
    itimerspec {
        it_interval: to_timespec(t.interval),
        it_value: value,
    }
}

/// `timerfd_settime`.
///
/// # Safety
/// `new_value` must be valid for reads; `old_value` null or valid for writes.
pub unsafe fn timerfd_settime(
    fd: c_int,
    flags: c_int,
    new_value: *const itimerspec,
    old_value: *mut itimerspec,
) -> c_int {
    let Some(timer) = lookup(fd) else {
        set_errno(crate::EBADF);
        return -1;
    };
    // SAFETY: the caller's contract.
    let new = unsafe { *new_value };
    let (Some(value), Some(interval)) = (from_timespec(&new.it_value), from_timespec(&new.it_interval))
    else {
        set_errno(crate::EINVAL);
        return -1;
    };
    if flags & !TFD_TIMER_ABSTIME != 0 {
        set_errno(crate::EINVAL);
        return -1;
    }
    let mut t = timer.lock().unwrap();
    if !old_value.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *old_value = current(&t) };
    }
    t.interval = interval;
    t.next = if value == 0 {
        None
    } else if flags & TFD_TIMER_ABSTIME != 0 {
        Some(value)
    } else {
        Some(now_ns(t.clock).unwrap_or(0) + value)
    };
    if !program(handle(fd), &t, t.next) {
        return -1;
    }
    0
}

/// `timerfd_gettime`.
///
/// # Safety
/// `curr_value` must be valid for writes.
pub unsafe fn timerfd_gettime(fd: c_int, curr_value: *mut itimerspec) -> c_int {
    let Some(timer) = lookup(fd) else {
        set_errno(crate::EBADF);
        return -1;
    };
    let t = timer.lock().unwrap();
    // SAFETY: the caller's contract.
    unsafe { *curr_value = current(&t) };
    0
}

/// `read` on a timer: the expirations since the last read, as a `u64`.
pub(crate) fn read(fd: c_int, timer: &Mutex<Timer>, buf: &mut [u8]) -> isize {
    if buf.len() < 8 {
        set_errno(crate::EINVAL);
        return -1;
    }
    loop {
        let wait_on;
        {
            let mut t = timer.lock().unwrap();
            if let Some(next) = t.next {
                let now = now_ns(t.clock).unwrap_or(next);
                if now >= next {
                    let count = if t.interval == 0 {
                        t.next = None;
                        1
                    } else {
                        let n = (now - next) / t.interval + 1;
                        t.next = Some(next + n * t.interval);
                        n
                    };
                    if !program(handle(fd), &t, t.next) {
                        return -1;
                    }
                    #[allow(clippy::cast_sign_loss)]
                    buf[..8].copy_from_slice(&(count as u64).to_ne_bytes());
                    return 8;
                }
                // Signalled a little before our clock reached `next`: make
                // it non-signalled until then.
                if !program(handle(fd), &t, t.next) {
                    return -1;
                }
            }
            if t.nonblocking {
                set_errno(crate::EAGAIN);
                return -1;
            }
            wait_on = handle(fd);
        }
        // SAFETY: waits on our handle of the timer.
        if unsafe { WaitForSingleObject(wait_on, INFINITE) } != WAIT_OBJECT_0 {
            return -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn read_fd(fd: c_int) -> isize {
        let t = lookup(fd).unwrap();
        let mut buf = [0u8; 8];
        let n = read(fd, &t, &mut buf);
        if n == 8 {
            #[allow(clippy::cast_possible_wrap)]
            let v = u64::from_ne_bytes(buf) as isize;
            v
        } else {
            n
        }
    }

    #[test]
    fn test_clocks() {
        let mut a = timespec::default();
        let mut b = timespec::default();
        for clock in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID] {
            // SAFETY: valid out-parameters.
            unsafe {
                assert_eq!(clock_gettime(clock, &mut a), 0);
                assert_eq!(clock_gettime(clock, &mut b), 0);
            }
            assert!((b.tv_sec, b.tv_nsec) >= (a.tv_sec, a.tv_nsec), "clock {clock}");
        }
        // SAFETY: as above.
        unsafe { clock_gettime(CLOCK_REALTIME, &mut a) };
        let sys = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        assert!((sys.as_secs() as i64 - a.tv_sec).abs() <= 1);
        // SAFETY: as above.
        assert_eq!(unsafe { clock_gettime(99, &mut a) }, -1);
    }

    fn clock_ns(clock: clockid_t) -> i64 {
        let mut t = timespec::default();
        // SAFETY: a valid out-parameter.
        assert_eq!(unsafe { clock_gettime(clock, &mut t) }, 0);
        t.tv_sec * NANOS + t.tv_nsec
    }

    /// The calling thread's kernel plus user time as Windows charges it, a
    /// clock tick at a time.
    fn thread_times_ns() -> i64 {
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        // SAFETY: the calling thread's pseudo-handle; writes the times.
        assert_ne!(unsafe { GetThreadTimes(GetCurrentThread(), &mut c, &mut e, &mut k, &mut u) }, 0);
        (filetime_100ns(k) + filetime_100ns(u)) * 100
    }

    fn spin(d: Duration) {
        let start = std::time::Instant::now();
        while start.elapsed() < d {
            std::hint::spin_loop();
        }
    }

    /// The CPU clocks count what runs as Linux's do, to well under a
    /// millisecond (CPUCLOCK lines): 2 ms of spinning moves the thread's
    /// clock by up to 2 ms (what the thread ran of them), where
    /// `GetThreadTimes` moves by a clock tick or not at all; 300 ms of spinning agrees with `GetThreadTimes` within
    /// two ticks and 5%; 100 ms asleep moves it by under a millisecond; the
    /// process's clock moves at least as much as the thread's. The TSC's
    /// start was read before `main`, and a read right after a start takes
    /// under 50 us (no wait for the rate's span). On a host whose TSC is not invariant
    /// the clocks are `GetProcessTimes`'s and the test says so.
    #[test]
    fn test_cpu_clocks_count_what_runs_finely() {
        use std::eprintln;
        if !tsc_invariant() {
            eprintln!("CPUCLOCK the host's TSC is not invariant: the CPU clocks are GetProcessTimes' and GetThreadTimes' ticks");
            return;
        }
        assert!(ANCHORED_AT_START.load(std::sync::atomic::Ordering::Relaxed), "the TSC's start was not read before main");
        // A read right after the start waits for no more than a counter
        // tick (before: the rest of a millisecond, spinning). The least of
        // three fresh starts, so that a thread switch is not counted.
        let first = (0..3)
            .map(|_| {
                let start = tsc_and_counter();
                let at = std::time::Instant::now();
                assert!(cpu_ns_since(1_000_000, start).is_some());
                at.elapsed()
            })
            .min()
            .unwrap();
        eprintln!("CPUCLOCK a read right after the rate's start: {} ns", first.as_nanos());
        assert!(first < Duration::from_micros(50), "a read right after the rate's start took {first:?}");
        // Each clock read once before the windows: a window starts at a
        // reading, never before a first one's own work.
        let _ = (clock_ns(CLOCK_THREAD_CPUTIME_ID), clock_ns(CLOCK_PROCESS_CPUTIME_ID));
        let measure = |work: &dyn Fn()| {
            let (t, p, k, w) = (clock_ns(CLOCK_THREAD_CPUTIME_ID), clock_ns(CLOCK_PROCESS_CPUTIME_ID), thread_times_ns(), std::time::Instant::now());
            work();
            let wall = i64::try_from(w.elapsed().as_nanos()).unwrap();
            (clock_ns(CLOCK_THREAD_CPUTIME_ID) - t, clock_ns(CLOCK_PROCESS_CPUTIME_ID) - p, thread_times_ns() - k, wall)
        };
        let short = measure(&|| spin(Duration::from_millis(2)));
        let long = measure(&|| spin(Duration::from_millis(300)));
        let asleep = measure(&|| std::thread::sleep(Duration::from_millis(100)));
        for (what, (t, p, k, w)) in [("2 ms spinning", short), ("300 ms spinning", long), ("100 ms asleep", asleep)] {
            eprintln!("CPUCLOCK {what}: thread clock +{t} ns, process clock +{p} ns, GetThreadTimes +{k} ns, wall {w} ns");
            assert!(p >= t, "{what}: the process's clock moved less than the thread's");
        }
        let (t, _, _, w) = short;
        // Not all 2 ms where other tests' threads take the CPU, but some of
        // it, and never a clock tick of it.
        assert!(t >= 100_000 && t <= w + 200_000, "2 ms spinning: the thread clock moved {t} ns in {w} ns");
        let (t, _, k, _) = long;
        assert!((t - k).abs() <= 31_250_000 + t / 20, "300 ms spinning: {t} ns against GetThreadTimes' {k} ns");
        let (t, _, _, _) = asleep;
        assert!(t < 1_000_000, "100 ms asleep: the thread clock moved {t} ns");
    }

    /// The counters a CPU clock can be made of, read together.
    #[derive(Clone, Copy)]
    struct Counters {
        /// The performance counter, in ns.
        wall: i64,
        tsc: u64,
        /// `QueryThreadCycleTime` through the pseudo-handle and through a
        /// handle of the thread's own (`OpenThread`).
        thread: u64,
        thread_by_handle: u64,
        process: u64,
        /// `GetThreadTimes` and `GetProcessTimes`, kernel plus user, in ns.
        thread_times: i64,
        process_times: i64,
    }

    fn counters(handle: HANDLE) -> Counters {
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        let (mut pc, mut pe, mut pk, mut pu) = (z, z, z, z);
        let (mut thread, mut thread_by_handle, mut process) = (0, 0, 0);
        let mut q = 0;
        // SAFETY: pseudo-handles and the thread's own handle; each call writes its out-parameters.
        let tsc = unsafe {
            QueryPerformanceCounter(&mut q);
            let tsc = core::arch::x86_64::_rdtsc();
            QueryThreadCycleTime(GetCurrentThread(), &mut thread);
            QueryThreadCycleTime(handle, &mut thread_by_handle);
            QueryProcessCycleTime(GetCurrentProcess(), &mut process);
            GetThreadTimes(GetCurrentThread(), &mut c, &mut e, &mut k, &mut u);
            GetProcessTimes(GetCurrentProcess(), &mut pc, &mut pe, &mut pk, &mut pu);
            tsc
        };
        let mut f = 0;
        // SAFETY: writes `f`.
        unsafe { QueryPerformanceFrequency(&mut f) };
        Counters {
            wall: i64::try_from(i128::from(q) * i128::from(NANOS) / i128::from(f)).unwrap(),
            tsc,
            thread,
            thread_by_handle,
            process,
            thread_times: (filetime_100ns(k) + filetime_100ns(u)) * 100,
            process_times: (filetime_100ns(pk) + filetime_100ns(pu)) * 100,
        }
    }

    /// A CPUCYCLEREC line's text for the span from `a` to `b`: each cycle
    /// counter's change against the TSC's, and each time against the wall's.
    fn cycles_line(a: Counters, b: Counters) -> std::string::String {
        use std::format;
        let tsc = b.tsc.wrapping_sub(a.tsc).max(1);
        let wall = (b.wall - a.wall).max(1);
        #[allow(clippy::cast_precision_loss)]
        let r = |n: u64| n as f64 / tsc as f64;
        #[allow(clippy::cast_precision_loss)]
        let w = |n: i64| n as f64 / wall as f64;
        #[allow(clippy::cast_precision_loss)]
        let ghz = tsc as f64 / wall as f64;
        format!(
            "wall {wall} ns, TSC +{tsc} ({:.4} GHz); thread cycles (pseudo-handle) +{} ({:.4} x TSC), (own handle) +{} \
             ({:.4} x TSC); process cycles +{} ({:.4} x TSC); GetThreadTimes +{} ns ({:.3} x wall), GetProcessTimes +{} ns \
             ({:.3} x wall)",
            ghz,
            b.thread - a.thread,
            r(b.thread - a.thread),
            b.thread_by_handle - a.thread_by_handle,
            r(b.thread_by_handle - a.thread_by_handle),
            b.process - a.process,
            r(b.process - a.process),
            b.thread_times - a.thread_times,
            w(b.thread_times - a.thread_times),
            b.process_times - a.process_times,
            w(b.process_times - a.process_times),
        )
    }

    /// A record (CPUCYCLEREC lines) of what Windows' cycle counters count,
    /// for the CPU clocks, after a PC (Ryzen 9 7900, 4999ff6) read the
    /// thread's CPU clock at 1.32 x the wall over 2 ms of spinning while the
    /// process's read 1.01 x (the cause was [`cpu_ns`]'s start-up wait, not
    /// the counters: on that PC at 3393774 these lines showed both at the
    /// TSC's rate); Learn says not to convert those cycles to time ("some
    /// CPUs will vary the frequency of the timer when changing the
    /// frequency at which the CPU runs").
    /// Printed: the host (CPU, hypervisor, its vendor and feature leaves);
    /// then for spins of 2, 20 and 200 ms on an otherwise idle process, the
    /// thread's cycles through its pseudo-handle and through a handle of its
    /// own, the process's cycles (each against the TSC), and
    /// `GetThreadTimes` and `GetProcessTimes` (against the wall); the same
    /// 200 ms read again after a `Sleep(1)` (the running stretch accounted
    /// at a switch); a spinning thread read by another thread; the 200 ms
    /// spin with every other logical processor spinning (no boost headroom)
    /// and the process's cycles against the sum of its threads'; and 100 ms
    /// asleep.
    #[test]
    #[ignore = "a record: run with --ignored --nocapture"]
    fn test_cpu_cycle_counters_on_record() {
        use core::arch::x86_64::__cpuid;
        use std::string::{String, ToString};
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::vec::Vec;
        use std::{eprintln, format};
        use windows_sys::Win32::System::Threading::{GetCurrentThreadId, OpenThread, Sleep, THREAD_QUERY_LIMITED_INFORMATION};
        let own = || {
            // SAFETY: the calling thread's id; closed by the caller.
            let h = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, GetCurrentThreadId()) };
            assert!(!h.is_null());
            h
        };
        let mut brand = Vec::new();
        for leaf in 0x8000_0002u32..=0x8000_0004 {
            let r = __cpuid(leaf);
            for v in [r.eax, r.ebx, r.ecx, r.edx] {
                brand.extend_from_slice(&v.to_le_bytes());
            }
        }
        let brand = String::from_utf8_lossy(&brand).trim_matches(char::from(0)).trim().to_string();
        let hv = __cpuid(1).ecx >> 31 & 1 == 1;
        let vendor = if hv {
            let r = __cpuid(0x4000_0000);
            let mut v = Vec::new();
            for x in [r.ebx, r.ecx, r.edx] {
                v.extend_from_slice(&x.to_le_bytes());
            }
            let f = __cpuid(0x4000_0003);
            format!(
                "{} (max leaf {:#x}); leaf 0x40000003 EAX {:#x} EBX {:#x} EDX {:#x}",
                String::from_utf8_lossy(&v),
                r.eax,
                f.eax,
                f.ebx,
                f.edx
            )
        } else {
            "none".to_string()
        };
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        eprintln!(
            "CPUCYCLEREC host: {brand}; {cpus} logical processors; invariant TSC {}; hypervisor {vendor}",
            tsc_invariant()
        );
        let handle = own();
        for ms in [2, 20, 200] {
            let a = counters(handle);
            spin(Duration::from_millis(ms));
            let b = counters(handle);
            eprintln!("CPUCYCLEREC {ms} ms spinning: {}", cycles_line(a, b));
            if ms == 200 {
                // SAFETY: plain call.
                unsafe { Sleep(1) };
                eprintln!("CPUCYCLEREC the same 200 ms read again after Sleep(1): {}", cycles_line(a, counters(handle)));
            }
        }
        // A spinning thread read by another: its cycles through a handle.
        let started = std::sync::Arc::new(AtomicBool::new(false));
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let raw = std::sync::Arc::new(AtomicU64::new(0));
        let spinner = {
            let (started, stop, raw) = (started.clone(), stop.clone(), raw.clone());
            std::thread::spawn(move || {
                raw.store(own() as u64, Ordering::SeqCst);
                started.store(true, Ordering::SeqCst);
                while !stop.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            })
        };
        while !started.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        let other = raw.load(Ordering::SeqCst) as HANDLE;
        let read_other = || {
            let mut c = 0;
            // SAFETY: the spinner's handle, open until it is closed below.
            unsafe { QueryThreadCycleTime(other, &mut c) };
            // SAFETY: plain call.
            (c, unsafe { core::arch::x86_64::_rdtsc() })
        };
        std::thread::sleep(Duration::from_millis(20));
        let (c0, t0) = read_other();
        std::thread::sleep(Duration::from_millis(200));
        let (c1, t1) = read_other();
        stop.store(true, Ordering::SeqCst);
        spinner.join().unwrap();
        #[allow(clippy::cast_precision_loss)]
        let ratio = (c1 - c0) as f64 / t1.wrapping_sub(t0) as f64;
        eprintln!("CPUCYCLEREC a spinning thread read by another over 200 ms: cycles +{} against TSC +{} ({ratio:.4} x TSC)", c1 - c0, t1 - t0);
        // SAFETY: the spinner's own handle, no longer used.
        unsafe { CloseHandle(other) };
        // Every other logical processor spinning.
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let others: Vec<_> = (1..cpus)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut a = 0;
                    // SAFETY: the pseudo-handle; writes `a`.
                    unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut a) };
                    while !stop.load(Ordering::Relaxed) {
                        std::hint::spin_loop();
                    }
                    let mut b = 0;
                    // SAFETY: as above.
                    unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut b) };
                    b - a
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(50));
        let a = counters(handle);
        spin(Duration::from_millis(200));
        let b = counters(handle);
        stop.store(true, Ordering::SeqCst);
        let spun: u64 = others.into_iter().map(|t| t.join().unwrap()).sum();
        eprintln!("CPUCYCLEREC 200 ms spinning with {} other threads spinning: {}", cpus - 1, cycles_line(a, b));
        eprintln!(
            "CPUCYCLEREC with them: the other threads' own cycles summed +{spun} over their whole run (the process's over \
             the 200 ms above: +{})",
            b.process - a.process
        );
        let a = counters(handle);
        std::thread::sleep(Duration::from_millis(100));
        eprintln!("CPUCYCLEREC 100 ms asleep: {}", cycles_line(a, counters(handle)));
        // SAFETY: the handle opened above.
        unsafe { CloseHandle(handle) };
    }

    #[test]
    fn test_localtime_r() {
        let t: time_t = 1_700_000_000;
        // SAFETY: an all-zero tm is valid.
        let mut out: tm = unsafe { std::mem::zeroed() };
        // SAFETY: valid pointers.
        assert!(!unsafe { localtime_r(&t, &mut out) }.is_null());
        // Whatever the zone, local time minus the offset is the UTC instant.
        let local = days_from_civil(
            i64::from(out.tm_year) + 1900,
            i64::from(out.tm_mon) + 1,
            i64::from(out.tm_mday),
        ) * 86_400
            + i64::from(out.tm_hour) * 3600
            + i64::from(out.tm_min) * 60
            + i64::from(out.tm_sec);
        assert_eq!(local - out.tm_gmtoff, t);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    #[test]
    fn test_one_shot_and_periodic() {
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
        assert!(fd != -1);
        assert_eq!(read_fd(fd), -1, "not armed");
        let mut spec = itimerspec {
            it_value: to_timespec(20_000_000),
            it_interval: timespec::default(),
        };
        // SAFETY: valid pointers.
        assert_eq!(unsafe { timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) }, 0);
        let mut cur = itimerspec::default();
        // SAFETY: as above.
        unsafe { timerfd_gettime(fd, &mut cur) };
        assert!(cur.it_value.tv_nsec > 0);
        // SAFETY: waits on the descriptor: the handle is signalled at expiry.
        assert_eq!(unsafe { WaitForSingleObject(handle(fd), 1000) }, WAIT_OBJECT_0);
        assert_eq!(read_fd(fd), 1);
        // SAFETY: as above.
        assert_ne!(unsafe { WaitForSingleObject(handle(fd), 50) }, WAIT_OBJECT_0, "reset by read");
        assert_eq!(read_fd(fd), -1);

        // Periodic, read late: several expirations at once.
        spec.it_value = to_timespec(10_000_000);
        spec.it_interval = to_timespec(10_000_000);
        // SAFETY: valid pointers.
        unsafe { timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) };
        std::thread::sleep(Duration::from_millis(105));
        let n = read_fd(fd);
        assert!((8..=12).contains(&n), "{n} expirations");
        // Disarm.
        spec.it_value = timespec::default();
        // SAFETY: valid pointers.
        unsafe { timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { timerfd_gettime(fd, &mut cur) };
        assert_eq!(cur.it_value, timespec::default());
        // SAFETY: closes the timer.
        unsafe { crate::windows_fd::close(fd) };
    }

    #[test]
    fn test_abstime_and_blocking() {
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(CLOCK_MONOTONIC, 0) };
        let at = now_ns(CLOCK_MONOTONIC).unwrap() + 30_000_000;
        let spec = itimerspec {
            it_value: to_timespec(at),
            it_interval: timespec::default(),
        };
        // SAFETY: valid pointers.
        assert_eq!(unsafe { timerfd_settime(fd, TFD_TIMER_ABSTIME, &spec, std::ptr::null_mut()) }, 0);
        // Blocking read waits for the expiration.
        assert_eq!(read_fd(fd), 1);
        assert!(now_ns(CLOCK_MONOTONIC).unwrap() >= at);
        // SAFETY: closes the timer.
        unsafe { crate::windows_fd::close(fd) };
    }

    #[test]
    fn test_a_timer_closed_disarmed_is_released() {
        // macOS kept a timer closed while disarmed (d291b9d). Here no worker
        // thread holds a timer: its state lives in the descriptor table,
        // and a close through this crate removes it at once.
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
        assert!(fd != -1);
        let state = Arc::downgrade(&lookup(fd).unwrap());
        // SAFETY: closes the timer, never armed.
        assert_eq!(unsafe { crate::windows_fd::close(fd) }, 0);
        assert!(state.upgrade().is_none(), "the timer outlived its close");
    }

    #[test]
    fn test_a_timer_closed_behind_the_table_is_released() {
        // Firecracker's `TimerFd` holds the descriptor in a `std::fs::File`,
        // whose drop calls `CloseHandle` itself, not this crate's `close`.
        // The table's own handle of the timer then keeps it until the
        // table next sweeps closed descriptors, which it does each time it
        // has doubled (at 64 entries at the latest): a bounded delay, not
        // a leak. Disarmed, as in the macOS leak.
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
        assert!(fd != -1);
        let state = Arc::downgrade(&lookup(fd).unwrap());
        // SAFETY: what `File`'s drop does with the descriptor's handle.
        assert_ne!(unsafe { CloseHandle(handle(fd)) }, 0);
        // Other descriptors made meanwhile, held open so that the table
        // grows to its sweep: the closed timer must be gone by then. The
        // table is the process's, which other tests fill and sweep at the
        // same time, so the sweep's size is read as it is now, not assumed:
        // once this test alone holds more entries than that, a sweep has run.
        let mut held = std::vec::Vec::new();
        let mut released = false;
        while held.len() <= crate::windows_fd::wick_fd::next_sweep() {
            // SAFETY: plain call.
            let other = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
            assert!(other != -1);
            held.push(other);
            if state.upgrade().is_none() {
                released = true;
                break;
            }
        }
        let made = held.len();
        for other in held {
            // SAFETY: closes the timers made above.
            unsafe { crate::windows_fd::close(other) };
        }
        assert!(released, "a timer closed by CloseHandle was kept past {made} timers made");
    }
}
