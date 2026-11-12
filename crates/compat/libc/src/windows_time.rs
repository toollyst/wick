// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Clocks, `localtime_r` and `timerfd` on Windows.
//!
//! Clocks:
//! - `CLOCK_REALTIME`: `GetSystemTimePreciseAsFileTime`;
//! - `CLOCK_MONOTONIC` (and `_RAW`, `_COARSE`): the performance counter,
//!   the clock of `std::time::Instant`;
//! - `CLOCK_BOOTTIME`: interrupt time, which counts while suspended;
//! - `CLOCK_PROCESS_CPUTIME_ID` / `CLOCK_THREAD_CPUTIME_ID`: kernel plus user
//!   time of the process / calling thread.
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
use windows_sys::Win32::System::WindowsProgramming::QueryInterruptTimePrecise;

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
