# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
"""The one change tools/gen-windows-sources.sh makes to polling 3.11.0 on
Windows, to src/iocp/mod.rs (its waitable sources, `Poller::add_waitable`).

Upstream's removal of a waitable (`remove_waitable`, `begin_delete`) sets
the source cancelled and drops its wait, whose `UnregisterWait` does not wait
for a callback that runs (Learn, UnregisterWait: it "fails with the
ERROR_IO_PENDING error code"). That callback, blocked on the source's lock,
then set the source idle over cancelled and posted it; the next wait fed it
and registered a new wait for the removed source, which nothing unregisters;
the caller, having removed the source, closes the handle, and the pool waits
on a closed handle ("If this handle is closed while the wait is still
pending, the function's behavior is undefined", Learn,
RegisterWaitForSingleObject): STATUS_THREADPOOL_HANDLE_EXCEPTION
(0xc000070a), CI run 43676869163. With this change:

- a removal (and a poller's drop) cancels the wait once the source's lock is
  given back and returns once no callback of it runs or will run
  (`UnregisterWaitEx` with `INVALID_HANDLE_VALUE`, which "waits for all
  callback functions to complete before returning"), so its return means the
  pool no longer uses the handle;
- a callback that finds its source cancelled leaves it as it is (not idle,
  not posted, not waited on again);
- a packet of a source removed after it was posted yields no event;
- a wait unregistered before its callback ran gives the callback, and the
  packet it holds, back (upstream leaked them).

    python3 -I tools/gen-windows-sources-polling.py <generated iocp/mod.rs>
"""

import sys

# (what upstream has, what it becomes): each must be found once.
CHANGES = [
    # The callback: a test seam where it starts; a source cancelled meanwhile
    # is left as it is.
    (
        """                    move || {
                        let mut handle = match packet.as_ref().data().project_ref() {
                            PacketInnerProj::Waitable { handle } => lock!(handle.lock()),
                            _ => unreachable!(),
                        };
""",
        """                    move || {
                        #[cfg(test)]
                        crate::test_hooks::callback_entered();
                        let mut handle = match packet.as_ref().data().project_ref() {
                            PacketInnerProj::Waitable { handle } => lock!(handle.lock()),
                            _ => unreachable!(),
                        };

                        // wick: removed meanwhile (`begin_delete`, which waits
                        // for this callback): not made idle, posted or waited
                        // on again.
                        if matches!(handle.status, WaitableStatus::Cancelled) {
                            return;
                        }
""",
    ),
    # A packet posted before its source's removal yields nothing.
    (
        """            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());
                let event = handle.interest;
""",
        """            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());
                // wick: posted before its source was removed: no event, and
                // no new wait.
                if matches!(handle.status, WaitableStatus::Cancelled) {
                    return Ok(FeedEventResult::NoEvent);
                }
                let event = handle.interest;
""",
    ),
    # The removal waits for the wait's end, with the source's lock given back
    # (the callback takes it).
    (
        """            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());

                // Set the status to be cancelled. This drops the wait handle and prevents
                // any further updates.
                handle.status = WaitableStatus::Cancelled;

                return Ok(());
            }
""",
        """            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());

                // Set the status to be cancelled. This prevents any further updates.
                // wick: the wait is cancelled once the lock is given back (a
                // callback that runs takes it, and finds the source cancelled),
                // and this returns once no callback of it runs or will run: the
                // pool no longer uses the handle, which its owner may close.
                let status = std::mem::replace(&mut handle.status, WaitableStatus::Cancelled);
                drop(handle);
                if let WaitableStatus::Waiting(wait) = status {
                    wait.unregister_and_wait();
                }

                return Ok(());
            }
""",
    ),
    # A poller dropped with waitables cancels their waits as a removal does.
    (
        """
impl Poller {
    /// Creates a new poller.
""",
        """
// wick: a poller dropped with waitables registered cancels their waits as
// their removal does, so that their handles may be closed after it.
impl Drop for Poller {
    fn drop(&mut self) {
        let waitables = std::mem::take(lock!(self.waitables.get_mut()));
        for (_, source) in waitables {
            let _ = source.begin_delete();
        }
    }
}

impl Poller {
    /// Creates a new poller.
""",
    ),
]

# The wait itself, replaced whole: from its doc comment to the end of its impl.
WAIT_START = """/// A handle for an ongoing wait operation.
#[derive(Debug)]
struct WaitHandle(RawHandle);
"""
WAIT_END = """        let wait_handle = unsafe { wait_handle.assume_init() };
        Ok(Self(wait_handle))
    }
}
"""
WAIT = """/// A handle for an ongoing wait operation.
///
/// wick: its callback's context is shared by the thread pool's wait and this
/// handle ([`WaitContext`]), so that a removal can wait for the callback
/// ([`WaitHandle::unregister_and_wait`]) and give back a callback that never
/// ran, with the packet it holds.
struct WaitHandle {
    wait: RawHandle,
    context: *const c_void,
    /// Drops this handle's reference to `context`; with `true`, once no
    /// callback of the wait runs or will run, also the pool's if the callback
    /// never ran.
    release: unsafe fn(*const c_void, bool),
}

impl fmt::Debug for WaitHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WaitHandle").field(&self.wait).finish()
    }
}

/// What a wait's callback runs, taken once: by the callback, or, for a wait
/// unregistered before it fired, dropped by [`WaitHandle::unregister_and_wait`].
struct WaitContext<F> {
    callback: Mutex<Option<F>>,
}

impl Drop for WaitHandle {
    fn drop(&mut self) {
        unsafe {
            UnregisterWait(self.wait as _);
            (self.release)(self.context, false);
        }
    }
}

impl WaitHandle {
    /// Wait for a waitable handle to become signaled.
    fn new<F>(
        handle: RawHandle,
        callback: F,
        timeout: Option<Duration>,
        long_wait: bool,
    ) -> io::Result<Self>
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        // Make sure a panic in the callback doesn't propagate to the OS.
        struct AbortOnDrop;

        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                std::process::abort();
            }
        }

        unsafe extern "system" fn wait_callback<F: FnOnce() + Send + Sync + 'static>(
            context: *mut c_void,
            _timer_fired: bool,
        ) {
            let _guard = AbortOnDrop;
            // The pool's reference, given back when this ends.
            let context = Arc::from_raw(context as *const WaitContext<F>);
            let callback = lock!(context.callback.lock()).take();
            if let Some(callback) = callback {
                callback();
            }
            drop(context);
            #[cfg(test)]
            crate::test_hooks::callback_left();

            // We executed without panicking, so don't abort.
            forget(_guard);
        }

        unsafe fn release<F>(context: *const c_void, ended: bool) {
            let context = Arc::from_raw(context as *const WaitContext<F>);
            // No callback of the wait runs or will run: one that never ran
            // leaves the pool's reference to drop here.
            let never_ran = ended && lock!(context.callback.lock()).is_some();
            if never_ran {
                Arc::decrement_strong_count(Arc::as_ptr(&context));
            }
        }

        let mut wait_handle = MaybeUninit::<RawHandle>::uninit();

        let mut flags = WT_EXECUTEONLYONCE;
        if long_wait {
            flags |= WT_EXECUTELONGFUNCTION;
        }

        let context = Arc::new(WaitContext {
            callback: Mutex::new(Some(callback)),
        });
        let for_pool = Arc::into_raw(Arc::clone(&context));
        let res = unsafe {
            RegisterWaitForSingleObject(
                wait_handle.as_mut_ptr().cast::<_>(),
                handle as _,
                Some(wait_callback::<F>),
                for_pool as _,
                timeout.map_or(INFINITE, dur2timeout),
                flags,
            )
        };

        if res == 0 {
            let err = io::Error::last_os_error();
            // Not registered: the pool's reference is not the pool's.
            drop(unsafe { Arc::from_raw(for_pool) });
            return Err(err);
        }

        let wait_handle = unsafe { wait_handle.assume_init() };
        Ok(Self {
            wait: wait_handle,
            context: Arc::into_raw(context).cast(),
            release: release::<F>,
        })
    }

    /// wick: cancels the wait and returns once no callback of it runs or will
    /// run (`UnregisterWaitEx` with `INVALID_HANDLE_VALUE`: "the function waits
    /// for all callback functions to complete before returning", Learn), so
    /// that the pool no longer uses the handle waited on and its owner may
    /// close it. Never from the wait's own callback, nor with a lock its
    /// callback takes held.
    fn unregister_and_wait(self) {
        let this = std::mem::ManuallyDrop::new(self);
        unsafe {
            let ended = windows_sys::Win32::System::Threading::UnregisterWaitEx(
                this.wait as _,
                windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
            ) != 0;
            (this.release)(this.context, ended);
        }
    }
}
"""


def main() -> None:
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for old, new in CHANGES:
        if text.count(old) != 1:
            sys.exit(f"{path}: expected one of:\n{old}")
        text = text.replace(old, new)
    start, end = text.find(WAIT_START), text.find(WAIT_END)
    if start < 0 or end < start or text.count(WAIT_START) != 1:
        sys.exit(f"{path}: WaitHandle not found as polling 3.11.0 has it")
    text = text[:start] + WAIT + text[end + len(WAIT_END):]
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


if __name__ == "__main__":
    main()
