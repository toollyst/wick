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

use std::io;
use std::result;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use wick_os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd, from_handle, handle};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE,
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

    /// Adds `v` to the counter.
    pub fn write(&self, v: u64) -> result::Result<(), io::Error> {
        if v == u64::MAX {
            return Err(einval());
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
