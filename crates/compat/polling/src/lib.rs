// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `polling` 3.11.0 for wick.
//!
//! - Linux, macOS: the upstream crate, re-exported as is (nothing of wick's
//!   uses it there).
//! - Windows: the upstream source with one change to its waitable sources
//!   (`PollerIocpExt::add_waitable`, which wick's epoll uses for eventfds,
//!   pipes, the console and nested instances): a removal returns once the
//!   thread pool no longer waits on the handle nor runs a callback for it, so
//!   that the handle may be closed, as Linux's `EPOLL_CTL_DEL` leaves nothing
//!   behind (tools/gen-windows-sources-polling.py says what upstream did).

#[cfg(not(windows))]
pub use upstream::*;

#[cfg(windows)]
// Upstream code: lints capped as cargo caps them for upstream crates.
#[allow(warnings, clippy::all)]
#[path = "windows/mod.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// The waits' callbacks, for the tests: each counted where it starts and
/// ends, and held at its start while [`HOLD`](test_hooks::HOLD) is set.
#[cfg(all(test, windows))]
mod test_hooks {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    pub(crate) static HOLD: AtomicBool = AtomicBool::new(false);
    pub(crate) static ENTERED: AtomicU64 = AtomicU64::new(0);
    pub(crate) static LEFT: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn callback_entered() {
        ENTERED.fetch_add(1, Ordering::SeqCst);
        while HOLD.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    pub(crate) fn callback_left() {
        LEFT.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent};

    use super::os::iocp::PollerIocpExt;
    use super::test_hooks::{ENTERED, HOLD, LEFT};
    use super::{Event, Events, PollMode, Poller};

    /// The hooks are the process's: one test at a time uses them.
    static ONE: Mutex<()> = Mutex::new(());

    /// A manual-reset event, signalled if `set`.
    fn event(set: bool) -> OwnedHandle {
        // SAFETY: a new unnamed event; checked, then owned.
        unsafe {
            let h = CreateEventW(std::ptr::null(), 1, i32::from(set), std::ptr::null());
            assert!(!h.is_null(), "CreateEventW: {}", std::io::Error::last_os_error());
            OwnedHandle::from_raw_handle(h)
        }
    }

    fn set(h: &OwnedHandle) {
        // SAFETY: an open event.
        assert_ne!(unsafe { SetEvent(h.as_raw_handle()) }, 0);
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let begun = Instant::now();
        while !done() {
            assert!(begun.elapsed() < Duration::from_secs(10), "{what} within 10 s");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A source's wait is registered at the next `wait` (polling queues
    /// the update while no thread waits): one that reports nothing, so that
    /// the thread pool waits on what was added.
    fn register(poller: &Poller) {
        assert_eq!(keys(poller, 0), Vec::<usize>::new(), "an event before any was signalled");
    }

    /// The keys a wait of `ms` reports.
    fn keys(poller: &Poller, ms: u64) -> Vec<usize> {
        let mut events = Events::new();
        poller.wait(&mut events, Some(Duration::from_millis(ms))).unwrap();
        events.iter().map(|e| e.key).collect()
    }

    // A removal while the source's callback runs (held at its start by the
    // test seam) returns only once that callback has ended, so that the
    // handle may be closed after it: upstream's returned at once
    // (UnregisterWait does not wait for a callback that runs), and the
    // callback, going on, made the removed source idle, posted it, and the
    // next wait waited on it again, on a handle its owner then closed
    // (STATUS_THREADPOOL_HANDLE_EXCEPTION, 0xc000070a: CI run 43676869163).
    // The callback, let go, leaves the removed source as it is: no event,
    // no wait.
    #[test]
    fn test_a_removal_returns_once_a_running_callback_has_ended() {
        let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let poller = Arc::new(Poller::new().unwrap());
        let h = event(false);
        // SAFETY: the event stays open until it is removed.
        unsafe { poller.add_waitable(&h, Event::readable(1), PollMode::Level) }.unwrap();
        register(&poller);
        let (entered, left) = (ENTERED.load(Ordering::SeqCst), LEFT.load(Ordering::SeqCst));
        HOLD.store(true, Ordering::SeqCst);
        // Callbacks let go however this test ends, so no later one hangs.
        struct LetGo;
        impl Drop for LetGo {
            fn drop(&mut self) {
                HOLD.store(false, Ordering::SeqCst);
            }
        }
        let _let_go = LetGo;
        set(&h);
        wait_until("the callback's start", || ENTERED.load(Ordering::SeqCst) > entered);
        let removed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let remover = {
            let (poller, removed) = (Arc::clone(&poller), Arc::clone(&removed));
            let raw = h.as_raw_handle() as usize;
            std::thread::spawn(move || {
                // SAFETY: the event is open until this thread is joined.
                let b = unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(raw as _) };
                poller.remove_waitable(b).unwrap();
                removed.store(true, Ordering::SeqCst);
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        let early = removed.load(Ordering::SeqCst);
        HOLD.store(false, Ordering::SeqCst);
        remover.join().unwrap();
        assert!(!early, "the removal returned while the source's callback ran");
        assert_eq!(LEFT.load(Ordering::SeqCst), left + 1, "the callback ended before the removal returned");
        drop(h);
        assert_eq!(keys(&poller, 100), Vec::<usize>::new(), "an event of a removed source");
    }

    // A source removed after its callback posted its packet, before a wait
    // fed it: the wait yields nothing for it and waits on it no more (its
    // handle closed after the removal).
    #[test]
    fn test_a_source_removed_with_its_packet_posted_yields_nothing() {
        let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let poller = Poller::new().unwrap();
        for round in 0..50 {
            let h = event(false);
            // SAFETY: the event stays open until it is removed.
            unsafe { poller.add_waitable(&h, Event::readable(round), PollMode::Level) }.unwrap();
            register(&poller);
            let left = LEFT.load(Ordering::SeqCst);
            set(&h);
            wait_until("the callback's end", || LEFT.load(Ordering::SeqCst) > left);
            poller.remove_waitable(&h).unwrap();
            drop(h);
            assert_eq!(keys(&poller, 20), Vec::<usize>::new(), "round {round}: an event of a removed source");
        }
    }

    // Interest changed while the source's callback runs, over and over, and
    // the source removed and its handle closed at once: no wait is left
    // behind on a closed handle (the process would end with 0xc000070a), and
    // a removed source reports nothing.
    #[test]
    fn test_a_modify_racing_the_callback_leaves_no_wait_behind() {
        let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let poller = Arc::new(Poller::new().unwrap());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waiter = {
            let (poller, stop) = (Arc::clone(&poller), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut events = Events::new();
                let mut seen = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    events.clear();
                    poller.wait(&mut events, Some(Duration::from_millis(5))).unwrap();
                    seen.extend(events.iter().map(|e| e.key));
                }
                seen
            })
        };
        let rounds = 5000;
        for round in 0..rounds {
            let h = event(false);
            // SAFETY: the event stays open until it is removed.
            unsafe { poller.add_waitable(&h, Event::readable(round), PollMode::Level) }.unwrap();
            set(&h);
            for i in 0..round % 4 {
                let interest = if i % 2 == 0 { Event::none(round) } else { Event::readable(round) };
                poller.modify_waitable(&h, interest, PollMode::Level).unwrap();
            }
            // SAFETY: an open event.
            unsafe { ResetEvent(h.as_raw_handle()) };
            poller.remove_waitable(&h).unwrap();
            drop(h);
        }
        stop.store(true, Ordering::SeqCst);
        poller.notify().unwrap();
        let seen = waiter.join().unwrap();
        // Each round's events came before its removal; none of a later wait
        // of the same key can be told apart here, so the bound is the rounds'.
        assert!(seen.iter().all(|&k| k < rounds), "an unknown key in {seen:?}");
        assert_eq!(keys(&poller, 50), Vec::<usize>::new(), "an event after every source was removed");
    }

    // A poller dropped with a source registered cancels its wait as a
    // removal does (upstream left it registered, on a handle its owner may
    // then close): the source signalled after the drop runs no callback of
    // the thread pool's, which would have taken it (ENTERED), and its handle
    // is closed after that.
    #[test]
    fn test_a_dropped_poller_leaves_no_wait_on_its_sources() {
        let _one = ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut ran = 0;
        for round in 0..20 {
            let poller = Poller::new().unwrap();
            let h = event(false);
            // SAFETY: the event stays open past the poller.
            unsafe { poller.add_waitable(&h, Event::readable(round), PollMode::Level) }.unwrap();
            register(&poller);
            drop(poller);
            let entered = ENTERED.load(Ordering::SeqCst);
            set(&h);
            std::thread::sleep(Duration::from_millis(20));
            ran += ENTERED.load(Ordering::SeqCst) - entered;
            drop(h);
        }
        assert_eq!(ran, 0, "callbacks of a dropped poller's waits");
    }
}
