// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `timerfd_*` for macOS.
//!
//! A timer is an unnamed FIFO (made, opened, its name removed), as an eventfd
//! is here (vmm-sys-util's): Firecracker makes timers after its sandbox is
//! narrowed (a hotplugged device's rate limiter), where upstream's filter
//! allows `timerfd_create` and the narrowed sandbox allows a FIFO but no
//! socket pair. The caller gets a descriptor open for reading (and writing,
//! so that opening waits for no peer), which becomes readable when the timer
//! expires and yields one native-endian `u64` per expiration, like a Linux
//! timerfd. One background thread fires all timers through a write-only
//! descriptor of its own, and learns that the caller closed the timer when
//! the FIFO has no reader left (`EPIPE`).
//!
//! Differences from Linux:
//! - each expiration is a separate 8-byte record instead of one accumulated
//!   counter, so a reader of 8 bytes sees `1` and the descriptor stays readable
//!   until all records are consumed;
//! - only relative timers are supported (`TFD_TIMER_ABSTIME` fails with
//!   `EINVAL`), and every clock is treated as `CLOCK_MONOTONIC`.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

use std::boxed::Box;
use std::string::ToString;
use std::vec::Vec;

use upstream::{self as libc, c_int, clockid_t, timespec};

/// Set `O_NONBLOCK` on the timer descriptor.
pub const TFD_NONBLOCK: c_int = libc::O_NONBLOCK;
/// Set `FD_CLOEXEC` on the timer descriptor.
pub const TFD_CLOEXEC: c_int = libc::O_CLOEXEC;
/// Absolute expiration time (not supported on macOS).
pub const TFD_TIMER_ABSTIME: c_int = 1;

/// Linux `struct itimerspec`.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct itimerspec {
    /// Interval for periodic timers; zero for one-shot.
    pub it_interval: timespec,
    /// Time until the first expiration; zero disarms the timer.
    pub it_value: timespec,
}

#[derive(Debug)]
struct Timer {
    write_end: OwnedFd,
    deadline: Option<Instant>,
    interval: Duration,
}

#[derive(Debug, Default)]
struct Timers {
    by_fd: Mutex<HashMap<c_int, Timer>>,
    changed: Condvar,
}

static TIMERS: LazyLock<&'static Timers> = LazyLock::new(|| {
    let timers: &'static Timers = Box::leak(Box::default());
    std::thread::Builder::new()
        .name("wick-timerfd".to_string())
        .spawn(move || run(timers))
        .expect("cannot start the timerfd thread");
    timers
});

use crate::linux_items::set_errno;

fn to_duration(ts: &timespec) -> Option<Duration> {
    let secs = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u32::try_from(ts.tv_nsec)
        .ok()
        .filter(|n| *n < 1_000_000_000)?;
    Some(Duration::new(secs, nanos))
}

fn to_timespec(d: Duration) -> timespec {
    timespec {
        tv_sec: libc::time_t::try_from(d.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_nsec: libc::c_long::from(d.subsec_nanos()),
    }
}

fn current(timer: &Timer, now: Instant) -> itimerspec {
    itimerspec {
        it_interval: to_timespec(timer.interval),
        it_value: to_timespec(timer.deadline.map_or(Duration::ZERO, |d| {
            d.saturating_duration_since(now)
                .max(Duration::from_nanos(1))
        })),
    }
}

fn fcntl_or(fd: c_int, get: c_int, set: c_int, flag: c_int) -> bool {
    // SAFETY: fcntl on a descriptor we own.
    let flags = unsafe { libc::fcntl(fd, get) };
    // SAFETY: as above.
    flags >= 0 && unsafe { libc::fcntl(fd, set, flags | flag) } >= 0
}

/// `F_SETNOSIGPIPE` (<sys/fcntl.h>; not in the libc crate): a write to a
/// FIFO without a reader fails with `EPIPE` and raises no `SIGPIPE`.
const F_SETNOSIGPIPE: c_int = 73;

/// An unnamed FIFO: (the caller's descriptor, open for reading and writing;
/// the timer thread's, open for writing, non-blocking, without `SIGPIPE`).
fn unnamed_fifo() -> Option<(OwnedFd, OwnedFd)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let path = std::env::temp_dir().join(std::format!(
            ".timerfd-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let Ok(cpath) = CString::new(path.as_os_str().as_bytes()) else {
            set_errno(libc::EINVAL);
            return None;
        };
        // SAFETY: mkfifo with a NUL-terminated path.
        if unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) } != 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return None;
        }
        // Open for reading and writing, the reader's end waits for no peer;
        // the writer's then finds a reader.
        // SAFETY: open with a NUL-terminated path.
        let read_fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        // SAFETY: as above.
        let write_fd = (read_fd >= 0)
            .then(|| unsafe { libc::open(cpath.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) });
        let err = std::io::Error::last_os_error();
        // SAFETY: as above; the descriptors keep the FIFO.
        unsafe { libc::unlink(cpath.as_ptr()) };
        // SAFETY: fresh descriptors we own, when open() returned them.
        let read_end = (read_fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(read_fd) });
        let write_end = write_fd
            .filter(|fd| *fd >= 0)
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
        let (Some(read_end), Some(write_end)) = (read_end, write_end) else {
            set_errno(err.raw_os_error().unwrap_or(libc::EIO));
            return None;
        };
        // SAFETY: fcntl on a descriptor we own.
        if unsafe { libc::fcntl(write_end.as_raw_fd(), F_SETNOSIGPIPE, 1) } != 0 {
            return None;
        }
        return Some((read_end, write_end));
    }
    set_errno(libc::EEXIST);
    None
}

/// Creates a timer and returns its descriptor, or `-1` with `errno` set.
///
/// # Safety
/// Same contract as Linux `timerfd_create`.
pub unsafe fn timerfd_create(_clockid: clockid_t, flags: c_int) -> c_int {
    let Some((read_end, write_end)) = unnamed_fifo() else {
        return -1;
    };
    let ok = (flags & TFD_NONBLOCK == 0
        || fcntl_or(
            read_end.as_raw_fd(),
            libc::F_GETFL,
            libc::F_SETFL,
            libc::O_NONBLOCK,
        ))
        && (flags & TFD_CLOEXEC != 0 || {
            // The FIFO was opened close-on-exec; the caller did not ask for it.
            // SAFETY: fcntl on a descriptor we own.
            unsafe { libc::fcntl(read_end.as_raw_fd(), libc::F_SETFD, 0) >= 0 }
        });
    if !ok {
        return -1;
    }

    let fd = std::os::fd::IntoRawFd::into_raw_fd(read_end);
    let timers = *TIMERS;
    timers.by_fd.lock().unwrap().insert(
        fd,
        Timer {
            write_end,
            deadline: None,
            interval: Duration::ZERO,
        },
    );
    fd
}

/// Arms or disarms the timer. Returns `0`, or `-1` with `errno` set.
///
/// # Safety
/// `new_value` must be valid; `old_value` must be null or valid for writes.
pub unsafe fn timerfd_settime(
    fd: c_int,
    flags: c_int,
    new_value: *const itimerspec,
    old_value: *mut itimerspec,
) -> c_int {
    if flags & TFD_TIMER_ABSTIME != 0 || new_value.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    // SAFETY: the caller guarantees `new_value` is valid.
    let new_value = unsafe { &*new_value };
    let (Some(value), Some(interval)) = (
        to_duration(&new_value.it_value),
        to_duration(&new_value.it_interval),
    ) else {
        set_errno(libc::EINVAL);
        return -1;
    };

    let timers = *TIMERS;
    let mut by_fd = timers.by_fd.lock().unwrap();
    let Some(timer) = by_fd.get_mut(&fd) else {
        set_errno(libc::EBADF);
        return -1;
    };
    let now = Instant::now();
    if !old_value.is_null() {
        // SAFETY: the caller guarantees `old_value` is valid for writes.
        unsafe { *old_value = current(timer, now) };
    }
    timer.deadline = (!value.is_zero()).then(|| now + value);
    timer.interval = interval;
    timers.changed.notify_all();
    0
}

/// Reads the time left and the interval. Returns `0`, or `-1` with `errno` set.
///
/// # Safety
/// `curr_value` must be valid for writes.
pub unsafe fn timerfd_gettime(fd: c_int, curr_value: *mut itimerspec) -> c_int {
    let timers = *TIMERS;
    let by_fd = timers.by_fd.lock().unwrap();
    let Some(timer) = by_fd.get(&fd) else {
        set_errno(libc::EBADF);
        return -1;
    };
    // SAFETY: the caller guarantees `curr_value` is valid for writes.
    unsafe { *curr_value = current(timer, Instant::now()) };
    0
}

fn run(timers: &'static Timers) {
    let mut by_fd = timers.by_fd.lock().unwrap();
    loop {
        let now = Instant::now();
        let mut closed = Vec::new();
        for (fd, timer) in by_fd.iter_mut() {
            let Some(deadline) = timer.deadline else {
                continue;
            };
            if deadline > now {
                continue;
            }
            let mut expirations = 0u64;
            let mut next = Some(deadline);
            while let Some(d) = next.filter(|d| *d <= now) {
                expirations += 1;
                next = (!timer.interval.is_zero()).then(|| d + timer.interval);
            }
            timer.deadline = next;
            for _ in 0..expirations {
                let record = 1u64.to_ne_bytes();
                // SAFETY: writing 8 bytes from a valid buffer to a descriptor we own.
                let n = unsafe {
                    libc::write(
                        timer.write_end.as_raw_fd(),
                        record.as_ptr().cast(),
                        record.len(),
                    )
                };
                if n < 0 {
                    let err = std::io::Error::last_os_error().raw_os_error();
                    if err == Some(libc::EPIPE) {
                        // The caller closed the timer.
                        closed.push(*fd);
                    }
                    // EAGAIN: unread records already signal the expiration.
                    break;
                }
            }
        }
        for fd in closed {
            by_fd.remove(&fd);
        }

        let wait = by_fd
            .values()
            .filter_map(|t| t.deadline)
            .min()
            .map(|d| d.saturating_duration_since(Instant::now()));
        by_fd = match wait {
            Some(wait) => timers.changed.wait_timeout(by_fd, wait).unwrap().0,
            None => timers.changed.wait(by_fd).unwrap(),
        };
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::prelude::rust_2021::{Err, None, Ok, Some};

    use super::*;

    fn spec(value_ms: u64, interval_ms: u64) -> itimerspec {
        itimerspec {
            it_value: to_timespec(Duration::from_millis(value_ms)),
            it_interval: to_timespec(Duration::from_millis(interval_ms)),
        }
    }

    fn read_u64(file: &mut std::fs::File) -> Option<u64> {
        let mut buf = [0u8; 8];
        match file.read(&mut buf) {
            Ok(8) => Some(u64::from_ne_bytes(buf)),
            Ok(_) => None,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(e) => panic!("{e}"),
        }
    }

    fn gettime(fd: c_int) -> itimerspec {
        let mut cur = spec(0, 0);
        // SAFETY: valid descriptor and output pointer.
        assert_eq!(unsafe { timerfd_gettime(fd, &mut cur) }, 0);
        cur
    }

    #[test]
    fn test_one_shot() {
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: we own `fd`.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        assert_eq!(read_u64(&mut file), None);
        assert_eq!(gettime(fd).it_value.tv_nsec, 0);

        // SAFETY: valid descriptor and spec.
        assert_eq!(
            unsafe { timerfd_settime(fd, 0, &spec(20, 0), std::ptr::null_mut()) },
            0
        );
        assert!(gettime(fd).it_value.tv_nsec > 0);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(read_u64(&mut file), Some(1));
        assert_eq!(read_u64(&mut file), None);
        // Disarmed after firing.
        let cur = gettime(fd);
        assert_eq!((cur.it_value.tv_sec, cur.it_value.tv_nsec), (0, 0));
    }

    #[test]
    fn test_periodic_and_disarm() {
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK) };
        // SAFETY: we own `fd`.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        // SAFETY: valid descriptor and spec.
        assert_eq!(
            unsafe { timerfd_settime(fd, 0, &spec(10, 10), std::ptr::null_mut()) },
            0
        );
        std::thread::sleep(Duration::from_millis(100));
        let mut fired = 0;
        while read_u64(&mut file).is_some() {
            fired += 1;
        }
        assert!(fired >= 2, "fired {fired} times");

        let mut old = spec(0, 0);
        // SAFETY: valid descriptor and specs.
        assert_eq!(unsafe { timerfd_settime(fd, 0, &spec(0, 0), &mut old) }, 0);
        assert_eq!(old.it_interval.tv_nsec, 10_000_000);
        std::thread::sleep(Duration::from_millis(50));
        while read_u64(&mut file).is_some() {}
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(read_u64(&mut file), None);
    }

    #[test]
    fn test_errors() {
        // SAFETY: invalid descriptor, valid spec.
        assert_eq!(
            unsafe { timerfd_settime(-5, 0, &spec(1, 0), std::ptr::null_mut()) },
            -1
        );
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
        // SAFETY: valid descriptor and spec.
        assert_eq!(
            unsafe { timerfd_settime(fd, TFD_TIMER_ABSTIME, &spec(1, 0), std::ptr::null_mut()) },
            -1
        );
        // SAFETY: closing our descriptor.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_a_timer_is_a_fifo_and_its_close_is_seen() {
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK) };
        assert!(fd >= 0);
        // An unnamed FIFO, as an eventfd here: the narrowed sandbox allows
        // making one, and no socket pair.
        // SAFETY: fstat into a zeroed struct.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFIFO);
        // SAFETY: fcntl on our descriptor; not asked for, not set.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
        // SAFETY: valid descriptor and spec.
        assert_eq!(
            unsafe { timerfd_settime(fd, 0, &spec(1, 0), std::ptr::null_mut()) },
            0
        );
        // SAFETY: closing our descriptor before the timer fires: its
        // expiration finds no reader (EPIPE, no SIGPIPE) and drops it.
        unsafe { libc::close(fd) };
        let gone = (0..200).any(|_| {
            std::thread::sleep(Duration::from_millis(5));
            !TIMERS.by_fd.lock().unwrap().contains_key(&fd)
        });
        assert!(gone);
    }
}
