// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The backend's locks a thread may hold while it waits for guest RAM
//! (the slot table, the irqchip, a vCPU's queued device writes), kept per
//! thread, so that a wait that must hold none of them can say so
//! ([`none_held`]): the walk of the guest's page tables before a
//! translation (`settle`) waits for a userfaultfd fill or a reclaim's move,
//! and a thread holding one of these while it waits would hold up every
//! vCPU that takes it (a fill's handler may itself be waiting for a vCPU's
//! device). A `Mutex` that records its holder's thread: its guard sets the
//! lock's bit while it lives.

use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};

/// The slot table (`VmInner::memory`, `pvclock::Ram`).
pub(crate) const RAM: u8 = 1;
/// The irqchip (`VmInner::irqchip`).
pub(crate) const IRQCHIP: u8 = 2;
/// A vCPU's device writes queued for Firecracker (`Shared::device_writes`).
pub(crate) const DEVICE_WRITES: u8 = 4;

thread_local! {
    static HELD: Cell<u8> = const { Cell::new(0) };
}

/// The bits of the locks this thread holds now.
pub(crate) fn held() -> u8 {
    HELD.with(Cell::get)
}

/// Whether this thread holds none of the locks: `what` names the wait, for
/// the debug assertion's line.
pub(crate) fn none_held(what: &str) -> bool {
    let h = held();
    debug_assert!(
        h == 0,
        "{what} waits holding the backend's {}{}{}",
        if h & RAM != 0 { "slot table " } else { "" },
        if h & IRQCHIP != 0 { "irqchip " } else { "" },
        if h & DEVICE_WRITES != 0 { "device writes " } else { "" },
    );
    h == 0
}

/// A `Mutex` whose guard records that this thread holds it.
#[derive(Debug)]
pub(crate) struct Tracked<T> {
    which: u8,
    inner: Mutex<T>,
}

impl<T> Tracked<T> {
    pub(crate) const fn new(which: u8, value: T) -> Self {
        Self { which, inner: Mutex::new(value) }
    }

    /// [`Mutex::lock`], the lock's bit set for this thread while the guard
    /// lives.
    pub(crate) fn lock(&self) -> LockResult<Guard<'_, T>> {
        match self.inner.lock() {
            Ok(g) => Ok(Guard::new(g, self.which)),
            Err(p) => Err(PoisonError::new(Guard::new(p.into_inner(), self.which))),
        }
    }
}

/// [`Tracked::lock`]'s guard.
pub(crate) struct Guard<'a, T> {
    guard: MutexGuard<'a, T>,
    which: u8,
}

impl<'a, T> Guard<'a, T> {
    fn new(guard: MutexGuard<'a, T>, which: u8) -> Self {
        HELD.with(|h| h.set(h.get() | which));
        Self { guard, which }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        HELD.with(|h| h.set(h.get() & !self.which));
    }
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A guard sets its lock's bit for its own thread alone, and clears it
    // when dropped; two locks' bits are kept apart.
    #[test]
    fn test_a_guard_records_its_lock_for_its_thread() {
        let ram = Tracked::new(RAM, 1u32);
        let chip = Tracked::new(IRQCHIP, 2u32);
        assert_eq!(held(), 0);
        let g = ram.lock().unwrap();
        assert_eq!(held(), RAM);
        assert_eq!(std::thread::scope(|s| s.spawn(held).join().unwrap()), 0);
        {
            let c = chip.lock().unwrap();
            assert_eq!(held(), RAM | IRQCHIP);
            assert_eq!(*c + *g, 3);
        }
        assert_eq!(held(), RAM);
        drop(g);
        assert_eq!(held(), 0);
        assert!(none_held("the test"));
    }
}
