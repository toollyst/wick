// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A wait that ends when it is due, not when macOS coalesces it.
//!
//! A thread's timed wait (a condition variable's, a sleep) is a kernel timer
//! that macOS may fire late to coalesce it with others (XNU
//! osfmk/kern/timer_call.c `timer_compute_leeway`): up to 1 ms for a
//! foreground thread (`kern.timer_coalesce_ts_ns_max`) and 100 ms in a
//! background process (`kern.timer_coalesce_bg_ns_max`). KVM waits for a
//! vCPU's virtual timer with an hrtimer in `HRTIMER_MODE_ABS_HARD`, with no
//! slack (arch/arm64/kvm/arch_timer.c). A [`Waiter`] waits on a kqueue timer
//! marked `NOTE_CRITICAL`, which XNU does not coalesce (bsd/kern/kern_event.c
//! `filt_timerarm`: `THREAD_CALL_DELAY_USER_CRITICAL`), and is woken by a
//! kqueue user event.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

/// The user event that wakes the waiter.
const WOKEN: usize = 0;
/// The timer of a timed wait.
const DUE: usize = 1;

/// How a [`Waiter::wait`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    /// [`Waiter::wake`] was called (before the wait or during it).
    Woken,
    /// The timeout passed.
    Due,
    /// A signal interrupted the wait.
    Interrupted,
}

/// A kqueue with a user event, [`WOKEN`], and, during a timed wait, a
/// critical timer, [`DUE`].
#[derive(Debug)]
pub(crate) struct Waiter {
    kq: OwnedFd,
}

fn event(ident: usize, filter: i16, flags: u16, fflags: u32, data: isize) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags,
        data,
        udata: std::ptr::null_mut(),
    }
}

impl Waiter {
    pub(crate) fn new() -> std::io::Result<Waiter> {
        // SAFETY: plain call.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a new descriptor of ours.
        let waiter = Waiter {
            kq: unsafe { OwnedFd::from_raw_fd(kq) },
        };
        // EV_CLEAR: a wake stays pending until a wait returns it, then is
        // cleared (`filt_usertouch` sets it, `filt_userprocess` clears it).
        waiter.change(&event(WOKEN, libc::EVFILT_USER, libc::EV_ADD | libc::EV_CLEAR, 0, 0))?;
        Ok(waiter)
    }

    fn change(&self, change: &libc::kevent) -> std::io::Result<()> {
        // SAFETY: one change, no events out.
        let r = unsafe { libc::kevent(self.kq.as_raw_fd(), change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Ends the current wait, or the next one if none is under way. May be
    /// called from any thread and from a signal handler (one system call).
    pub(crate) fn wake(&self) {
        // Fails only for a bad descriptor or change, neither possible here.
        let _ = self.change(&event(WOKEN, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, 0));
    }

    /// Waits until woken, or until `timeout` passed (`None`: no timeout).
    /// A wake made since the last wait returned ends it at once.
    pub(crate) fn wait(&self, timeout: Option<Duration>) -> Ended {
        let due = timeout.map(|t| {
            let ns = isize::try_from(t.as_nanos()).unwrap_or(isize::MAX).max(1);
            event(
                DUE,
                libc::EVFILT_TIMER,
                libc::EV_ADD | libc::EV_ONESHOT,
                libc::NOTE_CRITICAL | libc::NOTE_NSECONDS,
                ns,
            )
        });
        let (changes, n_changes) = match &due {
            Some(due) => (std::ptr::from_ref(due), 1),
            None => (std::ptr::null(), 0),
        };
        let mut got = event(0, 0, 0, 0, 0);
        // SAFETY: at most one change in, one event out, no timeout.
        let n = unsafe { libc::kevent(self.kq.as_raw_fd(), changes, n_changes, &mut got, 1, std::ptr::null()) };
        let ended = if n < 0 {
            Ended::Interrupted
        } else if got.ident == WOKEN && got.filter == libc::EVFILT_USER {
            Ended::Woken
        } else {
            return Ended::Due;
        };
        if due.is_some() {
            // The timer did not fire, or fired and was not returned: remove
            // it, so that it cannot end a later wait (ENOENT if it is gone).
            let _ = self.change(&event(DUE, libc::EVFILT_TIMER, libc::EV_DELETE, 0, 0));
        }
        ended
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    // A wake made before the wait (as one made between a waiter's decision
    // to wait and its `kevent` call) is not lost: the wait returns it at
    // once, whatever its timeout, and the wake is then used up.
    #[test]
    fn test_a_wake_before_the_wait_ends_it() {
        let waiter = Waiter::new().unwrap();
        waiter.wake();
        assert_eq!(waiter.wait(Some(Duration::from_secs(10))), Ended::Woken);
        waiter.wake();
        waiter.wake();
        assert_eq!(waiter.wait(None), Ended::Woken);
        let start = Instant::now();
        assert_eq!(waiter.wait(Some(Duration::from_millis(20))), Ended::Due);
        assert!(start.elapsed() >= Duration::from_millis(20), "{:?}", start.elapsed());
    }

    // A wake from another thread ends a wait under way, and a timed wait
    // woken before its timeout leaves no timer behind: an untimed wait after
    // it ends by the next wake, not by the earlier wait's timer.
    #[test]
    fn test_a_wake_ends_a_wait_and_leaves_no_timer() {
        let waiter = std::sync::Arc::new(Waiter::new().unwrap());
        waiter.wake();
        assert_eq!(waiter.wait(Some(Duration::from_millis(30))), Ended::Woken);
        let other = waiter.clone();
        let waker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            other.wake();
        });
        let start = Instant::now();
        assert_eq!(waiter.wait(None), Ended::Woken);
        assert!(start.elapsed() >= Duration::from_millis(200), "{:?}", start.elapsed());
        waker.join().unwrap();
    }
}
