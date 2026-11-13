// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `eventfd` for Windows.
//!
//! Same API and semantics as `vmm_sys_util::eventfd` on Linux:
//! - one descriptor, readable while the counter is non-zero, that can be
//!   registered with [`crate::epoll::Epoll`], duplicated, and handed to
//!   another process;
//! - `write(v)` adds `v`; `u64::MAX` is invalid, and a write that would take
//!   the counter past `u64::MAX - 1` blocks, or fails with `WouldBlock` when
//!   non-blocking;
//! - `read` returns the counter and resets it, or takes one unit in semaphore
//!   mode; it blocks, or fails with `WouldBlock`, while the counter is zero.
//!
//! The descriptor is a manual-reset event, which is signalled exactly while
//! the counter is non-zero, so waiting on it (`WaitForSingleObject`, IOCP
//! wait packets) is waiting for readability, and the wait consumes nothing.
//! The counter, the flags and a lock live in a one-page shared section; a
//! second manual-reset event is signalled while the counter has room. Every
//! change happens under the lock together with the matching `SetEvent` or
//! `ResetEvent`, so the events never disagree with the counter.
//!
//! A descriptor is the event handle alone; the section is attached to it
//! with `libc::wick_fd`, so `libc::dup` and `libc::close` keep the pair
//! together as Linux keeps one open file behind duplicated descriptors. Descriptors sent to another process go with their
//! section and space event ([`companions`], [`adopt`]); `sock_ctrl_msg` does
//! that, as `SCM_RIGHTS` carries an eventfd on Linux.
//!
//! A consumer ([`EventFd::add_consumer`]) is what KVM's irqfd is to an
//! eventfd, as on macOS: KVM hooks the eventfd's wait queue, so a write
//! raises the interrupt in the writing thread and takes the count (Linux
//! v6.1 fs/eventfd.c `eventfd_write` wakes the queue under its lock, :304-310;
//! virt/kvm/eventfd.c `irqfd_wakeup` reads the count and injects, :186-210,
//! for a write of 0 too). A write through a descriptor of this process is
//! handed to the consumers instead of being counted, unless none takes it.
//! The consumers live with the section's mapping in this process, so a
//! write of another process (a vhost-user backend's, through a descriptor
//! [`adopt`]ed there) is counted, for whoever reads the counter.

use std::io;
use std::result;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock, TryLockError};

use wick_os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd, from_handle, handle};
use windows_sys::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READWRITE, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, INFINITE, ResetEvent, SetEvent, WaitForSingleObject,
};

use super::errors::{einval, ewouldblock};

/// Non-blocking mode (Linux value).
pub const EFD_NONBLOCK: i32 = 0o4000;
/// Not inherited by child processes (Linux value).
pub const EFD_CLOEXEC: i32 = 0o2_000_000;
/// Semaphore mode (Linux value).
pub const EFD_SEMAPHORE: i32 = 1;

/// The largest value the counter holds.
const MAX: u64 = u64::MAX - 1;
const MAGIC: u64 = u64::from_le_bytes(*b"FCEVTFD1");
const SECTION_SIZE: u32 = 4096;
const FLAG_SEMAPHORE: u32 = 1;
const FLAG_NONBLOCK: u32 = 2;

/// Takes a write in place of the counter ([`EventFd::add_consumer`]):
/// returns whether it did.
pub type Consumer = Box<dyn Fn() -> bool + Send + Sync>;

/// Names a consumer added with [`EventFd::add_consumer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumerId(u64);

/// The consumers of an eventfd in this process.
#[derive(Default)]
struct Consumers(RwLock<Vec<(ConsumerId, Consumer)>>);

impl std::fmt::Debug for Consumers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Consumers").finish_non_exhaustive()
    }
}

/// The shared page.
#[repr(C)]
struct Header {
    magic: u64,
    lock: AtomicU32,
    flags: AtomicU32,
    counter: AtomicU64,
}

/// An owned kernel handle.
#[derive(Debug)]
struct Handle(HANDLE);

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: closes a handle this object owns.
        unsafe { CloseHandle(self.0) };
    }
}

fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn new_handle(h: HANDLE) -> io::Result<Handle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(Handle(h))
    }
}

fn duplicate(h: HANDLE, target_process: HANDLE) -> io::Result<HANDLE> {
    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process; the result is checked.
    check(unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            h,
            target_process,
            &mut out,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    })?;
    Ok(out)
}

fn set_inherit(h: HANDLE, inherit: bool) -> io::Result<()> {
    let flags = if inherit { HANDLE_FLAG_INHERIT } else { 0 };
    // SAFETY: changes a flag of a handle we own.
    check(unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, flags) })
}

/// The state behind every descriptor of one eventfd in this process.
#[derive(Debug)]
struct Shared {
    section: Handle,
    view: *mut Header,
    /// Signalled while the counter is below [`MAX`].
    space: Handle,
    /// Held for reading while a write calls them, and never with the
    /// page's lock: a consumer may take locks of its own (a VM's), and a
    /// thread that holds those may read the counter (the irqfd watcher
    /// reads an irqfd under the VM's `irqfds` lock).
    consumers: Consumers,
}

// SAFETY: the view is shared memory accessed with atomics under the lock.
unsafe impl Send for Shared {}
// SAFETY: as above.
unsafe impl Sync for Shared {}

impl Drop for Shared {
    fn drop(&mut self) {
        // SAFETY: unmaps the view this object mapped.
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.view.cast(),
            })
        };
    }
}

/// Holds the lock of the shared page.
struct Guard<'a>(&'a Header);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.lock.store(0, Ordering::Release);
    }
}

impl Shared {
    fn map(section: Handle, space: Handle) -> io::Result<Shared> {
        // SAFETY: maps the whole section; the result is checked.
        let view = unsafe {
            MapViewOfFile(section.0, FILE_MAP_ALL_ACCESS, 0, 0, SECTION_SIZE as usize)
        };
        if view.Value.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Shared {
            section,
            view: view.Value.cast(),
            space,
            consumers: Consumers::default(),
        })
    }

    fn header(&self) -> &Header {
        // SAFETY: the view is mapped for the life of `self`.
        unsafe { &*self.view }
    }

    /// Takes the lock. Critical sections are a few instructions and one
    /// `SetEvent`/`ResetEvent`, so spinning, then yielding, is enough.
    fn lock(&self) -> Guard<'_> {
        let h = self.header();
        let mut spins = 0u32;
        while h
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
        Guard(h)
    }

    fn flags(&self) -> u32 {
        self.header().flags.load(Ordering::Relaxed)
    }
}

/// The eventfd `fd` names, if it is one.
fn lookup(fd: RawFd) -> Option<Arc<Shared>> {
    libc::wick_fd::attached::<Shared>(fd)
}

fn attach(fd: RawFd, shared: &Arc<Shared>) -> io::Result<()> {
    libc::wick_fd::attach(fd, shared.clone())
}

/// Whether `fd` is an eventfd of this process.
pub fn is_eventfd(fd: RawFd) -> bool {
    lookup(fd).is_some()
}

/// The handles that go with eventfd `fd` to another process: the section and
/// the space event. `sock_ctrl_msg` duplicates them next to `fd`.
pub fn companions(fd: RawFd) -> Option<[RawFd; 2]> {
    lookup(fd).map(|s| [from_handle(s.section.0), from_handle(s.space.0)])
}

/// Makes `fd`, received from another process, an eventfd of this one, with
/// the `section` and `space` handles that came with it.
///
/// # Safety
///
/// The three handles must be open, owned by the caller (`section` and
/// `space` are taken over; `fd` stays the caller's descriptor), and be the
/// [`companions`] of the same eventfd in the sending process.
pub unsafe fn adopt(fd: RawFd, section: RawFd, space: RawFd) -> io::Result<()> {
    let section = Handle(handle(section));
    let space = Handle(handle(space));
    let shared = Shared::map(section, space)?;
    if shared.header().magic != MAGIC {
        return Err(einval());
    }
    attach(fd, &Arc::new(shared))
}

/// An `eventfd` counter that can be waited on with `epoll`.
#[derive(Debug)]
pub struct EventFd {
    /// The readable event: the descriptor.
    event: HANDLE,
    shared: Arc<Shared>,
}

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for EventFd {}
// SAFETY: as above.
unsafe impl Sync for EventFd {}

fn wait(h: HANDLE) -> io::Result<()> {
    // SAFETY: waits on a handle we hold.
    if unsafe { WaitForSingleObject(h, INFINITE) } == WAIT_OBJECT_0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

impl EventFd {
    /// Creates a new counter set to zero. `flag` is a combination of
    /// [`EFD_NONBLOCK`], [`EFD_CLOEXEC`] and [`EFD_SEMAPHORE`]. `EMFILE`
    /// past the jail's no-file limit (`libc::wick_nofile`), for its one
    /// descriptor; its section and second event are not reserved.
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        if flag & !(EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE) != 0 {
            return Err(einval());
        }
        libc::wick_nofile::check(1)?;
        let inherit = flag & EFD_CLOEXEC == 0;
        // SAFETY: creates unnamed objects; results are checked.
        let (section, event, space) = unsafe {
            (
                new_handle(CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    SECTION_SIZE,
                    std::ptr::null(),
                ))?,
                new_handle(CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()))?,
                new_handle(CreateEventW(std::ptr::null(), 1, 1, std::ptr::null()))?,
            )
        };
        for h in [&section, &event, &space] {
            set_inherit(h.0, inherit)?;
        }
        let shared = Shared::map(section, space)?;
        let header = shared.header();
        let mut flags = 0;
        if flag & EFD_SEMAPHORE != 0 {
            flags |= FLAG_SEMAPHORE;
        }
        if flag & EFD_NONBLOCK != 0 {
            flags |= FLAG_NONBLOCK;
        }
        header.flags.store(flags, Ordering::Relaxed);
        header.counter.store(0, Ordering::Relaxed);
        // SAFETY: the view is ours and not shared yet.
        unsafe { (*shared.view).magic = MAGIC };
        let shared = Arc::new(shared);
        let event = std::mem::ManuallyDrop::new(event).0;
        let evt = EventFd { event, shared };
        attach(from_handle(event), &evt.shared)?;
        Ok(evt)
    }

    fn nonblocking(&self) -> bool {
        self.shared.flags() & FLAG_NONBLOCK != 0
    }

    /// Adds `v` to the counter, or hands the write to the consumers.
    pub fn write(&self, v: u64) -> result::Result<(), io::Error> {
        if v == u64::MAX {
            return Err(einval());
        }
        // Not under the page's lock (see `Shared::consumers`).
        if self.consumed() {
            return Ok(());
        }
        loop {
            {
                let guard = self.shared.lock();
                let value = guard.0.counter.load(Ordering::Relaxed);
                if MAX - value >= v {
                    if v > 0 {
                        let new = value + v;
                        guard.0.counter.store(new, Ordering::Relaxed);
                        // SAFETY: plain calls on handles we hold.
                        unsafe {
                            check(SetEvent(self.event))?;
                            if new == MAX {
                                check(ResetEvent(self.shared.space.0))?;
                            }
                        }
                    }
                    return Ok(());
                }
            }
            if self.nonblocking() {
                return Err(ewouldblock());
            }
            wait(self.shared.space.0)?;
        }
    }

    /// Reads the counter and resets it to zero, or takes one unit in semaphore
    /// mode. Blocks (or fails with `WouldBlock`) while the counter is zero.
    pub fn read(&self) -> result::Result<u64, io::Error> {
        loop {
            {
                let guard = self.shared.lock();
                let value = guard.0.counter.load(Ordering::Relaxed);
                if value > 0 {
                    let taken = if self.shared.flags() & FLAG_SEMAPHORE != 0 {
                        1
                    } else {
                        value
                    };
                    let left = value - taken;
                    guard.0.counter.store(left, Ordering::Relaxed);
                    // SAFETY: plain calls on handles we hold.
                    unsafe {
                        if left == 0 {
                            check(ResetEvent(self.event))?;
                        }
                        check(SetEvent(self.shared.space.0))?;
                    }
                    return Ok(taken);
                }
            }
            if self.nonblocking() {
                return Err(ewouldblock());
            }
            wait(self.event)?;
        }
    }

    /// Hands a write to the consumers; whether one took it. Each is called,
    /// as each of KVM's irqfds on one eventfd injects (`irqfd_wakeup` does
    /// not look at the count it read).
    fn consumed(&self) -> bool {
        let consumers = self.shared.consumers.0.read().unwrap_or_else(PoisonError::into_inner);
        consumers.iter().fold(false, |taken, (_, consume)| consume() | taken)
    }

    /// Adds a consumer: from now on a write through a descriptor of this
    /// process calls it, in the writing thread, and is not counted if it
    /// returns true (see the module's documentation). Waits for consumers
    /// running. A consumer must not write this eventfd, or add or remove a
    /// consumer of it.
    pub fn add_consumer(&self, consumer: Consumer) -> ConsumerId {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = ConsumerId(NEXT.fetch_add(1, Ordering::Relaxed));
        self.shared
            .consumers
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push((id, consumer));
        id
    }

    /// Removes a consumer; once it returns, the consumer is not running and
    /// is not called again, as KVM's irqfd deassignment waits for the
    /// injections under way (virt/kvm/eventfd.c `kvm_irqfd_deassign`). So it
    /// must not be called while holding a lock the consumer takes. Whether
    /// it was there.
    pub fn remove_consumer(&self, id: ConsumerId) -> bool {
        let mut consumers = self.shared.consumers.0.write().unwrap_or_else(PoisonError::into_inner);
        let before = consumers.len();
        consumers.retain(|(c, _)| *c != id);
        consumers.len() != before
    }

    /// As [`Self::remove_consumer`] if no consumer runs; otherwise leaves it
    /// and returns false. For a consumer's owner going away inside a
    /// consumer's call, which would wait for itself.
    pub fn try_remove_consumer(&self, id: ConsumerId) -> bool {
        let mut consumers = match self.shared.consumers.0.try_write() {
            Ok(consumers) => consumers,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return false,
        };
        let before = consumers.len();
        consumers.retain(|(c, _)| *c != id);
        consumers.len() != before
    }

    /// Whether `other` is a descriptor of the same eventfd: of one kernel
    /// event (`CompareObjectHandles`), as KVM compares the `eventfd_ctx`
    /// two descriptors open (virt/kvm/eventfd.c `kvm_irqfd_assign`).
    pub fn is_same(&self, other: &EventFd) -> bool {
        // SAFETY: two handles we hold.
        unsafe { CompareObjectHandles(self.event, other.event) != 0 }
    }

    /// Returns a new handle to the same counter. `EMFILE` past the jail's
    /// no-file limit, as a `dup` on Linux.
    pub fn try_clone(&self) -> result::Result<EventFd, io::Error> {
        libc::wick_nofile::check(1)?;
        // SAFETY: duplicates our own handle.
        let event = duplicate(self.event, unsafe { GetCurrentProcess() })?;
        let evt = EventFd {
            event,
            shared: self.shared.clone(),
        };
        attach(from_handle(event), &evt.shared)?;
        Ok(evt)
    }
}

impl Drop for EventFd {
    fn drop(&mut self) {
        libc::wick_fd::detach(from_handle(self.event));
        // SAFETY: closes the descriptor this object owns.
        unsafe { CloseHandle(self.event) };
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        from_handle(self.event)
    }
}

impl FromRawFd for EventFd {
    /// Takes an eventfd descriptor of this process: one from
    /// [`IntoRawFd::into_raw_fd`], or one received from another process and
    /// [`adopt`]ed.
    ///
    /// # Safety
    ///
    /// `fd` must be an open descriptor that the new object owns.
    ///
    /// # Panics
    ///
    /// If `fd` is not an eventfd of this process: a bare event handle has no
    /// counter, and making one up would give it a second, unrelated value.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        let shared = lookup(fd).unwrap_or_else(|| {
            panic!("EventFd::from_raw_fd({fd}): not an eventfd of this process")
        });
        EventFd {
            event: handle(fd),
            shared,
        }
    }
}

impl IntoRawFd for EventFd {
    /// Gives up the descriptor; it stays an eventfd until closed.
    fn into_raw_fd(self) -> RawFd {
        let fd = from_handle(self.event);
        std::mem::forget(self);
        fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        EventFd::new(EFD_NONBLOCK).unwrap();
        EventFd::new(0).unwrap();
        EventFd::new(EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE).unwrap();
        EventFd::new(0x4000_0000).unwrap_err();
    }

    #[test]
    fn test_read_write() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        evt.write(55).unwrap();
        evt.write(5).unwrap();
        assert_eq!(evt.read().unwrap(), 60);
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(evt.write(u64::MAX).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_signalled_while_non_zero() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        // SAFETY: waits with a zero timeout.
        let signalled = || unsafe { WaitForSingleObject(evt.event, 0) } == WAIT_OBJECT_0;
        assert!(!signalled());
        evt.write(1).unwrap();
        assert!(signalled());
        assert!(signalled(), "waiting consumes nothing");
        evt.read().unwrap();
        assert!(!signalled());
    }

    #[test]
    fn test_semaphore() {
        let evt = EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE).unwrap();
        evt.write(3).unwrap();
        assert_eq!(evt.read().unwrap(), 1);
        assert_eq!(evt.read().unwrap(), 1);
        assert_eq!(evt.read().unwrap(), 1);
        assert!(evt.read().is_err());
    }

    #[test]
    fn test_overflow() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(MAX).unwrap();
        assert_eq!(evt.write(1).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(evt.read().unwrap(), MAX);
        evt.write(1).unwrap();
    }

    #[test]
    fn test_blocking() {
        let evt = EventFd::new(0).unwrap();
        let other = evt.try_clone().unwrap();
        let t = std::thread::spawn(move || other.read().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(50));
        evt.write(7).unwrap();
        assert_eq!(t.join().unwrap(), 7);
    }

    #[test]
    fn test_clone_and_raw() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let clone = evt.try_clone().unwrap();
        assert_ne!(evt.as_raw_fd(), clone.as_raw_fd());
        clone.write(2).unwrap();
        let fd = clone.into_raw_fd();
        assert!(is_eventfd(fd));
        // SAFETY: the descriptor came from `into_raw_fd`.
        let back = unsafe { EventFd::from_raw_fd(fd) };
        back.write(3).unwrap();
        assert_eq!(evt.read().unwrap(), 5);
        drop(back);
        assert!(!is_eventfd(fd));
    }

    #[test]
    fn test_adopt() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let [section, space] = companions(evt.as_raw_fd()).unwrap();
        // What `sock_ctrl_msg` does for the receiving process, done here in
        // the same process: duplicate the three handles, then adopt.
        // SAFETY: duplicates our own handles.
        let me = unsafe { GetCurrentProcess() };
        let fd = from_handle(duplicate(evt.event, me).unwrap());
        let section = from_handle(duplicate(handle(section), me).unwrap());
        let space = from_handle(duplicate(handle(space), me).unwrap());
        // SAFETY: the handles are fresh duplicates of one eventfd.
        unsafe { adopt(fd, section, space).unwrap() };
        // SAFETY: adopted above.
        let received = unsafe { EventFd::from_raw_fd(fd) };
        received.write(9).unwrap();
        assert_eq!(evt.read().unwrap(), 9);
    }

    /// An eventfd as another process holds it: the three handles duplicated
    /// and adopted, with a mapping of the section of its own.
    fn as_another_process_has_it(evt: &EventFd) -> EventFd {
        let [section, space] = companions(evt.as_raw_fd()).unwrap();
        // SAFETY: duplicates our own handles.
        let me = unsafe { GetCurrentProcess() };
        let fd = from_handle(duplicate(evt.event, me).unwrap());
        let section = from_handle(duplicate(handle(section), me).unwrap());
        let space = from_handle(duplicate(handle(space), me).unwrap());
        // SAFETY: the handles are fresh duplicates of one eventfd.
        unsafe { adopt(fd, section, space).unwrap() };
        // SAFETY: adopted above.
        unsafe { EventFd::from_raw_fd(fd) }
    }

    fn counting(calls: &Arc<AtomicU64>, takes: bool) -> Consumer {
        let calls = calls.clone();
        Box::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            takes
        })
    }

    fn signalled(evt: &EventFd) -> bool {
        // SAFETY: waits with a zero timeout on a handle the eventfd holds.
        unsafe { WaitForSingleObject(evt.event, 0) == WAIT_OBJECT_0 }
    }

    #[test]
    fn test_a_consumer_takes_the_writes_of_this_process() {
        // As KVM's irqfd takes an eventfd's writes: in the writing thread,
        // and the count is gone; a write of 0 too, which Linux's
        // eventfd_write passes to the wait queue as any other.
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        evt.add_consumer(counting(&calls, true));
        evt.write(3).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        evt.try_clone().unwrap().write(1).unwrap();
        evt.write(0).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        // Nothing waits in the descriptor either.
        assert!(!signalled(&evt));
        // An invalid write reaches no consumer.
        assert_eq!(evt.write(u64::MAX).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_a_write_no_consumer_takes_is_counted() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        evt.add_consumer(counting(&calls, false));
        evt.write(5).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(signalled(&evt));
        assert_eq!(evt.read().unwrap(), 5);
        // Each consumer is called; one that takes the write is enough.
        let other = Arc::new(AtomicU64::new(0));
        evt.add_consumer(counting(&other, true));
        evt.write(2).unwrap();
        assert_eq!((calls.load(Ordering::SeqCst), other.load(Ordering::SeqCst)), (2, 1));
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_a_write_of_another_process_is_not_consumed() {
        // Its descriptor maps the section on its own: its writes are
        // counted, for whoever reads the counter (an irqfd watcher).
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        evt.add_consumer(counting(&calls, true));
        let other = as_another_process_has_it(&evt);
        other.write(4).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(evt.read().unwrap(), 4);
    }

    #[test]
    fn test_a_removed_consumer_is_not_called() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let id = evt.add_consumer(counting(&calls, true));
        assert!(evt.remove_consumer(id));
        assert!(!evt.remove_consumer(id));
        assert!(!evt.try_remove_consumer(id));
        evt.write(6).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(evt.read().unwrap(), 6);
    }

    #[test]
    fn test_descriptors_of_one_eventfd_are_the_same() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let other = EventFd::new(EFD_NONBLOCK).unwrap();
        assert!(evt.is_same(&evt.try_clone().unwrap()));
        assert!(evt.is_same(&as_another_process_has_it(&evt)));
        assert!(!evt.is_same(&other));
    }

    /// A consumer that says it started, then waits for `gate`.
    fn gated(
        gate: &Arc<std::sync::Mutex<()>>,
    ) -> (Consumer, std::sync::mpsc::Receiver<()>, Arc<AtomicU64>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let (gate, done) = (gate.clone(), Arc::new(AtomicU64::new(0)));
        let finished = done.clone();
        let consumer: Consumer = Box::new(move || {
            let _ = tx.send(());
            drop(gate.lock().unwrap());
            finished.fetch_add(1, Ordering::SeqCst);
            true
        });
        (consumer, rx, done)
    }

    const BOUND: std::time::Duration = std::time::Duration::from_secs(10);

    #[test]
    fn test_a_consumer_runs_without_the_pages_lock() {
        // A consumer takes locks of its own (a VM's), and the thread that
        // holds them may read the counter meanwhile (the irqfd watcher reads
        // an irqfd under the VM's `irqfds` lock): were the consumer called
        // with the page's lock held, the two would wait for each other
        // forever.
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let gate = Arc::new(std::sync::Mutex::new(()));
        let (consumer, started, _) = gated(&gate);
        evt.add_consumer(consumer);
        let held = gate.lock().unwrap();
        let writer = evt.try_clone().unwrap();
        let write = std::thread::spawn(move || writer.write(1).unwrap());
        started.recv_timeout(BOUND).expect("the consumer did not start");
        let reader = evt.try_clone().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(reader.read().map_err(|e| e.kind())).unwrap());
        let read = rx.recv_timeout(BOUND).unwrap_or_else(|_| {
            panic!("a read waited for a running consumer: the consumer holds the page's lock")
        });
        assert_eq!(read, Err(io::ErrorKind::WouldBlock));
        drop(held);
        write.join().unwrap();
    }

    #[test]
    fn test_removing_a_consumer_waits_for_its_run() {
        // As KVM's deassignment: once removed, the consumer is not running.
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let gate = Arc::new(std::sync::Mutex::new(()));
        let (consumer, started, finished) = gated(&gate);
        let id = evt.add_consumer(consumer);
        let held = gate.lock().unwrap();
        let writer = evt.try_clone().unwrap();
        let write = std::thread::spawn(move || writer.write(1).unwrap());
        started.recv_timeout(BOUND).expect("the consumer did not start");
        // From inside a run (an owner dropped by its own consumer) it does
        // not wait for itself.
        assert!(!evt.try_remove_consumer(id));
        let remover = evt.try_clone().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let removed = remover.remove_consumer(id);
            tx.send((removed, finished.load(Ordering::SeqCst))).unwrap();
        });
        // It waits while the consumer runs (any time it returns before the
        // gate opens is an error; the wait cannot make a correct removal
        // fail).
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200)).is_err(),
            "the removal returned while its consumer ran"
        );
        drop(held);
        let (removed, runs) = rx.recv_timeout(BOUND).expect("the removal did not end");
        assert!(removed);
        assert_eq!(runs, 1, "the consumer's run had ended when the removal returned");
        write.join().unwrap();
    }
}

#[cfg(test)]
mod dup_tests {
    use super::*;

    #[test]
    fn test_libc_dup_is_an_eventfd() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        // SAFETY: duplicates our descriptor.
        let d = unsafe { libc::dup(evt.as_raw_fd()) };
        assert!(is_eventfd(d));
        // SAFETY: `d` is an eventfd of this process.
        let other = unsafe { EventFd::from_raw_fd(d) };
        other.write(3).unwrap();
        assert_eq!(evt.read().unwrap(), 3);
        assert!(companions(d).is_some());
    }
}
