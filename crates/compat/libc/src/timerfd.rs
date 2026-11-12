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
//! the FIFO has no reader left (`EPIPE`). It waits for the next expiration
//! on a kqueue timer marked `NOTE_CRITICAL`, which macOS fires when due:
//! any other wait of its (a condition variable's, `nanosleep`, a `kevent`
//! timeout) it may delay to coalesce timers, by up to 100 ms in a
//! background process (`kern.timer_coalesce_bg_ns_max`), where Linux fires
//! a timerfd's hrtimer with no slack.
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
use std::sync::{LazyLock, Mutex};
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

impl Timer {
    /// Whether the caller closed the timer: no reader is left on the FIFO.
    /// A write of no bytes fails with `EPIPE` then, and writes nothing
    /// while there is one (measured). Linux frees a timer at its close;
    /// here that cannot be seen, so a closed timer is found by this, at its
    /// next expiration or the next time a timer is made or a timer thread
    /// wakes, and its FIFO released then.
    fn closed(&self) -> bool {
        // SAFETY: a write of no bytes to a descriptor we own.
        let n = unsafe { libc::write(self.write_end.as_raw_fd(), [0u8; 1].as_ptr().cast(), 0) };
        n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPIPE)
    }
}

#[derive(Debug)]
struct Timers {
    by_fd: Mutex<HashMap<c_int, Timer>>,
    /// The kqueue the timer thread waits on: a user event, [`CHANGED`], and
    /// a timer, [`DUE`], for the next expiration.
    kq: c_int,
}

/// The kqueue user event that tells the timer thread a timer changed.
const CHANGED: usize = 0;
/// The kqueue timer of the next expiration.
const DUE: usize = 1;

fn kevent_change(kq: c_int, ident: usize, filter: i16, flags: u16, fflags: u32, data: isize) -> c_int {
    let change = libc::kevent {
        ident,
        filter,
        flags,
        fflags,
        data,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: one change, no events out.
    unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) }
}

static TIMERS: LazyLock<&'static Timers> = LazyLock::new(|| {
    // SAFETY: plain call; the kqueue lives as long as the process.
    let kq = unsafe { libc::kqueue() };
    assert!(
        kq >= 0 && kevent_change(kq, CHANGED, libc::EVFILT_USER, libc::EV_ADD | libc::EV_CLEAR, 0, 0) == 0,
        "cannot make the timerfd thread's kqueue: {}",
        std::io::Error::last_os_error()
    );
    let timers: &'static Timers = Box::leak(Box::new(Timers {
        by_fd: Mutex::default(),
        kq,
    }));
    std::thread::Builder::new()
        .name("wick-timerfd".to_string())
        .spawn(move || run(timers))
        .expect("cannot start the timerfd thread");
    timers
});

use crate::linux_items::set_errno;

/// Starts the thread that fires the timers, if it is not running yet.
/// A timer can be made after the host sandbox stops the process from making
/// threads (a hot-plugged device's rate limiter, when no timer was made at
/// boot): the sandbox's narrow() calls this first, as it starts the Async
/// block engine's workers.
pub fn timerfd_start_thread() {
    LazyLock::force(&TIMERS);
}

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

/// What a timer's FIFO is named in the temporary directory
/// (`.timerfd-<pid>-<n>`): the host sandbox lets a narrowed process remove
/// a FIFO so named of its own (`vmm::ext::sandbox`), as it lets it remove
/// an eventfd's.
pub const TIMERFD_FIFO_PREFIX: &str = ".timerfd-";

/// Held by the crate's tests that start a process, while they start it,
/// and by those that need no other process to hold their descriptors: XNU's
/// `posix_spawn` copies every descriptor into the child, close-on-exec ones
/// too (bsd/kern/kern_exec.c, `fork1` with `PROC_CREATE_SPAWN`), and closes
/// those only when the new image is activated (`fdt_exec`), so meanwhile
/// the child holds the read end of a timer its parent closed, and the timer
/// is not seen closed (measured: 2 of 200 runs of the timer tests).
#[cfg(test)]
pub(crate) fn spawning() -> std::sync::MutexGuard<'static, ()> {
    static SPAWNING: Mutex<()> = Mutex::new(());
    SPAWNING.lock().unwrap_or_else(|e| e.into_inner())
}

/// An unnamed FIFO: (the caller's descriptor, open for reading and writing;
/// the timer thread's, open for writing, non-blocking, without `SIGPIPE`).
fn unnamed_fifo() -> Option<(OwnedFd, OwnedFd)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let path = std::env::temp_dir().join(std::format!(
            "{TIMERFD_FIFO_PREFIX}{}-{}",
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
    let mut by_fd = timers.by_fd.lock().unwrap();
    // Timers closed since: one closed while disarmed is never written, so
    // nothing else finds it gone.
    by_fd.retain(|_, timer| !timer.closed());
    by_fd.insert(
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
    kevent_change(timers.kq, CHANGED, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, 0);
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
    loop {
        let mut by_fd = timers.by_fd.lock().unwrap();
        by_fd.retain(|_, timer| !timer.closed());
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
        drop(by_fd);
        // Until the next expiration, or a change made since the lock was
        // released (the user event stays triggered until it is taken).
        if let Some(wait) = wait {
            let ns = isize::try_from(wait.as_nanos()).unwrap_or(isize::MAX);
            let flags = libc::NOTE_CRITICAL | libc::NOTE_NSECONDS;
            kevent_change(timers.kq, DUE, libc::EVFILT_TIMER, libc::EV_ADD | libc::EV_ONESHOT, flags, ns);
        }
        let mut got = std::mem::MaybeUninit::<libc::kevent>::uninit();
        // SAFETY: room for one event, no timeout; an interrupted wait only
        // goes round again.
        unsafe { libc::kevent(timers.kq, std::ptr::null(), 0, got.as_mut_ptr(), 1, std::ptr::null()) };
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

    /// Waits until `fd` is readable, for at most `limit`. A timer fires
    /// from a thread here (`run`), as Linux's from an hrtimer: never early,
    /// late by however long the host takes to schedule it, which on a
    /// loaded host has no bound. The tests wait for the firing rather than
    /// sleep a fixed time, and check it was not early.
    fn wait_readable(fd: c_int, limit: Duration) -> bool {
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ms = c_int::try_from(limit.as_millis()).unwrap();
        // SAFETY: one valid pollfd.
        unsafe { libc::poll(&mut p, 1, ms) == 1 }
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

        let armed = Instant::now();
        // SAFETY: valid descriptor and spec.
        assert_eq!(
            unsafe { timerfd_settime(fd, 0, &spec(20, 0), std::ptr::null_mut()) },
            0
        );
        assert!(gettime(fd).it_value.tv_nsec > 0);
        assert!(wait_readable(fd, Duration::from_secs(30)), "a 20 ms timer did not fire in 30 s");
        let at = armed.elapsed();
        assert!(at >= Duration::from_millis(20), "fired early, after {at:?}");
        assert_eq!(read_u64(&mut file), Some(1));
        assert_eq!(read_u64(&mut file), None);
        // Disarmed after firing.
        let cur = gettime(fd);
        assert_eq!((cur.it_value.tv_sec, cur.it_value.tv_nsec), (0, 0));
    }

    /// A timer fires when it is due, as Linux's (an hrtimer, which takes no
    /// slack), however much macOS may delay the process's timers to
    /// coalesce them: by up to 100 ms for a background process
    /// (`kern.timer_coalesce_bg_ns_max`; a 50 ms wait measured 160 to 230 ms
    /// late under `taskpolicy -b`), where upstream's timer tests give 25 and
    /// 50 ms of margin. In a process of its own made background, each
    /// expiration is measured against a control armed with it: a kqueue
    /// timer marked `NOTE_CRITICAL`, which macOS does not coalesce, so the
    /// host's scheduling delays, unbounded on a loaded host, fall on both.
    /// Their median difference must stay under 20 ms, a fifth of the most
    /// the host may coalesce.
    #[test]
    fn test_timers_are_not_coalesced() {
        const NAME: &str = "timerfd::tests::test_timers_are_not_coalesced";
        const CHILD: &str = "WICK_TIMERFD_TEST_ALONE";
        if std::env::var_os(CHILD).is_none() {
            let child = {
                let _spawning = spawning();
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([NAME, "--exact", "--test-threads=1", "--nocapture"])
                    .env(CHILD, "1")
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            };
            let out = child.wait_with_output().unwrap();
            let text = std::format!(
                "{:?}\n{}{}",
                out.status,
                std::string::String::from_utf8_lossy(&out.stdout),
                std::string::String::from_utf8_lossy(&out.stderr)
            );
            assert!(out.status.success() && text.contains("1 passed"), "{text}");
            return;
        }
        // SAFETY: plain call, on this process.
        let r = unsafe { libc::setpriority(libc::PRIO_DARWIN_PROCESS, 0, libc::PRIO_DARWIN_BG) };
        assert_eq!(r, 0);
        // SAFETY: plain calls; we own the descriptors.
        let (kq, fd) = unsafe {
            (libc::kqueue(), timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC))
        };
        assert!(kq >= 0 && fd >= 0);
        // SAFETY: we own `fd`.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let event = |ident: usize, filter: i16, flags: u16, fflags: u32, data: isize| libc::kevent {
            ident,
            filter,
            flags,
            fflags,
            data,
            udata: std::ptr::null_mut(),
        };
        let read = event(fd as usize, libc::EVFILT_READ, libc::EV_ADD, 0, 0);
        // SAFETY: one change, no events.
        let r = unsafe { libc::kevent(kq, &read, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        assert_eq!(r, 0);
        let mut later = Vec::new();
        for _ in 0..15 {
            // Before the timer is armed: a background thread can wait a
            // millisecond for the CPU between the two.
            let armed = Instant::now();
            // SAFETY: valid descriptor and spec.
            assert_eq!(unsafe { timerfd_settime(fd, 0, &spec(50, 0), std::ptr::null_mut()) }, 0);
            let control = event(
                1,
                libc::EVFILT_TIMER,
                libc::EV_ADD | libc::EV_ONESHOT,
                libc::NOTE_CRITICAL | libc::NOTE_USECONDS,
                50_000,
            );
            // SAFETY: one change, no events.
            let r = unsafe { libc::kevent(kq, &control, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            assert_eq!(r, 0);
            let (mut timer, mut controlled) = (None, None);
            while timer.is_none() || controlled.is_none() {
                let mut got = event(0, 0, 0, 0, 0);
                // SAFETY: one event out, no timeout.
                let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut got, 1, std::ptr::null()) };
                assert_eq!(n, 1);
                let at = armed.elapsed();
                if got.filter == libc::EVFILT_READ {

                    timer.get_or_insert(at);
                    while read_u64(&mut file).is_some() {}
                } else {
                    controlled.get_or_insert(at);
                }
            }
            let (timer, controlled) = (timer.unwrap(), controlled.unwrap());
            assert!(timer >= Duration::from_millis(50), "fired early, after {timer:?}");
            later.push(timer.as_micros() as i128 - controlled.as_micros() as i128);
        }
        later.sort_unstable();
        let median = later[later.len() / 2];
        assert!(median < 20_000, "the timer fired a median {median} us after the control: {later:?}");
        // SAFETY: our descriptor.
        unsafe { libc::close(kq) };
    }

    #[test]
    fn test_periodic_and_disarm() {
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK) };
        // SAFETY: we own `fd`.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let armed = Instant::now();
        // SAFETY: valid descriptor and spec.
        assert_eq!(
            unsafe { timerfd_settime(fd, 0, &spec(10, 10), std::ptr::null_mut()) },
            0
        );
        // Two expirations (a late thread writes the ones it missed at once),
        // the second not before 20 ms.
        let mut fired = 0;
        while fired < 2 {
            assert!(wait_readable(fd, Duration::from_secs(30)), "fired {fired} times in 30 s");
            while read_u64(&mut file).is_some() {
                fired += 1;
            }
        }
        let at = armed.elapsed();
        assert!(at >= Duration::from_millis(20), "{fired} expirations after {at:?}");

        let mut old = spec(0, 0);
        // SAFETY: valid descriptor and specs.
        assert_eq!(unsafe { timerfd_settime(fd, 0, &spec(0, 0), &mut old) }, 0);
        assert_eq!(old.it_interval.tv_nsec, 10_000_000);
        // Disarmed under the timers' lock, which the thread holds while it
        // writes: nothing is written after, whatever was before.
        while read_u64(&mut file).is_some() {}
        assert!(!wait_readable(fd, Duration::from_millis(50)));
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
    fn test_a_timer_closed_disarmed_is_released() {
        let _alone = spawning();
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, TFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: fstat into a zeroed struct.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
        let fifo = (st.st_dev, st.st_ino);
        let held = || {
            TIMERS.by_fd.lock().unwrap().values().any(|t| {
                // SAFETY: fstat into a zeroed struct, of a descriptor the
                // registry owns.
                let mut s: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                let ok = unsafe { libc::fstat(t.write_end.as_raw_fd(), &mut s) } == 0;
                ok && (s.st_dev, s.st_ino) == fifo
            })
        };
        // Never armed, then closed: on Linux the timer is gone; here the
        // next timer made releases it.
        // SAFETY: closing our descriptor.
        unsafe { libc::close(fd) };
        // SAFETY: plain call.
        let next = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, TFD_CLOEXEC) };
        assert!(next >= 0);
        assert!(!held());
        // A timer still open is kept.
        assert!(TIMERS.by_fd.lock().unwrap().contains_key(&next));
        // SAFETY: closing our descriptor.
        unsafe { libc::close(next) };
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
        // SAFETY: closing our descriptor.
        unsafe { libc::close(fd) };

        // The close of a timer: with TFD_CLOEXEC, and while no other test
        // starts a process ([`spawning`]), so that no child holds the FIFO's
        // read end (its expiration would then find a reader).
        let _alone = spawning();
        // SAFETY: plain call.
        let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
        // The timer is known by its FIFO, not by the descriptor's number,
        // which another test's thread may be given once it is closed.
        let fifo = (st.st_dev, st.st_ino);
        let held = || {
            TIMERS.by_fd.lock().unwrap().values().any(|t| {
                // SAFETY: fstat into a zeroed struct, of a descriptor the
                // registry owns.
                let mut s: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: as above.
                let ok = unsafe { libc::fstat(t.write_end.as_raw_fd(), &mut s) } == 0;
                ok && (s.st_dev, s.st_ino) == fifo
            })
        };
        assert!(held());
        // SAFETY: valid descriptor and spec.
        assert_eq!(
            unsafe { timerfd_settime(fd, 0, &spec(20, 0), std::ptr::null_mut()) },
            0
        );
        // SAFETY: closing our descriptor before the timer fires: its
        // expiration finds no reader (EPIPE, no SIGPIPE) and drops it.
        unsafe { libc::close(fd) };
        // Well past the expiration, for a loaded host.
        let gone = (0..1000).any(|_| {
            std::thread::sleep(Duration::from_millis(5));
            !held()
        });
        assert!(gone);
    }
}
