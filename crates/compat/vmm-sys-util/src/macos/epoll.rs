// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `epoll` for macOS, built on `kqueue`.
//!
//! Same API as `vmm_sys_util::epoll` on Linux. Each registered descriptor gets
//! an `EVFILT_READ` filter for [`EventSet::IN`] and an `EVFILT_WRITE` filter for
//! [`EventSet::OUT`]; `wait` merges the filters that fired for one descriptor
//! into one [`EpollEvent`] carrying the registered `data`.
//!
//! Mapping:
//! - level-triggered by default, like epoll; [`EventSet::EDGE_TRIGGERED`] maps
//!   to `EV_CLEAR` and [`EventSet::ONE_SHOT`] to `EV_DISPATCH`;
//! - `EV_EOF` is reported as [`EventSet::HANG_UP`] and
//!   [`EventSet::READ_HANG_UP`], `EV_ERROR` as [`EventSet::ERROR`];
//! - [`EventSet::PRIORITY`], [`EventSet::WAKE_UP`] and
//!   [`EventSet::EXCLUSIVE`] are accepted and ignored.

use std::collections::HashMap;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::sync::Mutex;

pub use crate::epoll_types::{ControlOperation, EpollEvent, EventSet, epoll_event};

/// An epoll instance backed by a kqueue.
#[derive(Debug)]
pub struct Epoll {
    kq: RawFd,
    /// Registered descriptors and their user data.
    interests: Mutex<HashMap<RawFd, u64>>,
}

fn kevent_for(fd: RawFd, filter: i16, flags: u16) -> libc::kevent {
    libc::kevent {
        ident: fd as usize,
        filter,
        flags,
        fflags: 0,
        data: 0,
        udata: ptr::null_mut(),
    }
}

impl Epoll {
    /// Creates a new instance.
    pub fn new() -> io::Result<Self> {
        // SAFETY: kqueue() takes no arguments; the result is checked.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `kq` is a descriptor we own.
        if unsafe { libc::fcntl(kq, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: closing the descriptor we just opened.
            unsafe { libc::close(kq) };
            return Err(err);
        }
        Ok(Epoll {
            kq,
            interests: Mutex::new(HashMap::new()),
        })
    }

    fn apply(&self, changes: &[libc::kevent]) -> io::Result<()> {
        if changes.is_empty() {
            return Ok(());
        }
        // Ask for one receipt per change so per-filter errors are reported.
        let mut receipts: Vec<libc::kevent> = changes
            .iter()
            .map(|c| libc::kevent {
                flags: c.flags | libc::EV_RECEIPT,
                ..*c
            })
            .collect();
        let mut out = receipts.clone();
        // SAFETY: both buffers hold `receipts.len()` kevents.
        let ret = unsafe {
            libc::kevent(
                self.kq,
                receipts.as_mut_ptr(),
                i32::try_from(receipts.len()).unwrap_or(i32::MAX),
                out.as_mut_ptr(),
                i32::try_from(out.len()).unwrap_or(i32::MAX),
                ptr::null(),
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        for ev in out.iter().take(usize::try_from(ret).unwrap_or(0)) {
            // Deleting a filter that was never added is not an error for epoll semantics.
            if ev.flags & libc::EV_ERROR != 0 && ev.data != 0 && ev.data != libc::ENOENT as isize {
                #[allow(clippy::cast_possible_truncation)]
                return Err(io::Error::from_raw_os_error(ev.data as i32));
            }
        }
        Ok(())
    }

    fn filter_changes(fd: RawFd, events: EventSet) -> Vec<libc::kevent> {
        let mut flags = libc::EV_ADD | libc::EV_ENABLE;
        if events.contains(EventSet::EDGE_TRIGGERED) {
            flags |= libc::EV_CLEAR;
        }
        if events.contains(EventSet::ONE_SHOT) {
            flags |= libc::EV_DISPATCH;
        }
        let read = if events.contains(EventSet::IN) {
            flags
        } else {
            libc::EV_DELETE
        };
        let write = if events.contains(EventSet::OUT) {
            flags
        } else {
            libc::EV_DELETE
        };
        vec![
            kevent_for(fd, libc::EVFILT_READ, read),
            kevent_for(fd, libc::EVFILT_WRITE, write),
        ]
    }

    /// Adds, changes or removes `fd` in the interest list.
    pub fn ctl(&self, operation: ControlOperation, fd: RawFd, event: EpollEvent) -> io::Result<()> {
        let mut interests = self.interests.lock().unwrap();
        match operation {
            ControlOperation::Add => {
                if interests.contains_key(&fd) {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
                self.apply(&Self::filter_changes(fd, event.event_set()))?;
                interests.insert(fd, event.data());
            }
            ControlOperation::Modify => {
                if !interests.contains_key(&fd) {
                    return Err(io::Error::from_raw_os_error(libc::ENOENT));
                }
                self.apply(&Self::filter_changes(fd, event.event_set()))?;
                interests.insert(fd, event.data());
            }
            ControlOperation::Delete => {
                if interests.remove(&fd).is_none() {
                    return Err(io::Error::from_raw_os_error(libc::ENOENT));
                }
                self.apply(&Self::filter_changes(fd, EventSet::empty()))?;
            }
        }
        Ok(())
    }

    /// Waits up to `timeout` milliseconds (`-1`: forever) and fills `events`.
    /// Returns the number of events written.
    pub fn wait(&self, timeout: i32, events: &mut [EpollEvent]) -> io::Result<usize> {
        if events.is_empty() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // A descriptor can fire two filters, so ask for twice as many kevents.
        let mut fired = vec![kevent_for(0, 0, 0); events.len() * 2];
        let ts;
        let ts_ptr = if timeout < 0 {
            ptr::null()
        } else {
            ts = libc::timespec {
                tv_sec: libc::time_t::from(timeout / 1000),
                tv_nsec: libc::c_long::from((timeout % 1000) * 1_000_000),
            };
            &ts as *const libc::timespec
        };
        // SAFETY: `fired` has room for the requested number of kevents.
        let ret = unsafe {
            libc::kevent(
                self.kq,
                ptr::null(),
                0,
                fired.as_mut_ptr(),
                i32::try_from(fired.len()).unwrap_or(i32::MAX),
                ts_ptr,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let interests = self.interests.lock().unwrap();
        let mut count = 0usize;
        let mut slot_of: HashMap<RawFd, usize> = HashMap::new();
        for ev in fired.iter().take(usize::try_from(ret).unwrap_or(0)) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let fd = ev.ident as RawFd;
            let Some(&data) = interests.get(&fd) else {
                continue;
            };
            let mut bits = EventSet::empty();
            if ev.filter == libc::EVFILT_READ {
                bits |= EventSet::IN;
            } else if ev.filter == libc::EVFILT_WRITE {
                bits |= EventSet::OUT;
            }
            if ev.flags & libc::EV_EOF != 0 {
                bits |= EventSet::HANG_UP | EventSet::READ_HANG_UP;
            }
            if ev.flags & libc::EV_ERROR != 0 {
                bits |= EventSet::ERROR;
            }
            let slot = match slot_of.get(&fd) {
                Some(slot) => *slot,
                None => {
                    if count == events.len() {
                        // Level-triggered events fire again on the next wait.
                        continue;
                    }
                    slot_of.insert(fd, count);
                    events[count] = EpollEvent::new(EventSet::empty(), data);
                    count += 1;
                    count - 1
                }
            };
            let merged = events[slot].event_set() | bits;
            events[slot] = EpollEvent::new(merged, data);
        }
        Ok(count)
    }
}

impl AsRawFd for Epoll {
    fn as_raw_fd(&self) -> RawFd {
        self.kq
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        // SAFETY: we own the kqueue descriptor.
        unsafe { libc::close(self.kq) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventfd::{EventFd, EFD_NONBLOCK};

    #[test]
    fn test_event_ops() {
        let mut event = EpollEvent::default();
        assert_eq!(event.events(), 0);
        assert_eq!(event.data(), 0);
        event = EpollEvent::new(EventSet::IN | EventSet::OUT, 2);
        assert_eq!(event.event_set(), EventSet::IN | EventSet::OUT);
        assert_eq!(event.data(), 2);
        assert_eq!(event.fd(), 2);
    }

    #[test]
    fn test_level_triggered() {
        let epoll = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                evt.as_raw_fd(),
                EpollEvent::new(EventSet::IN, 77),
            )
            .unwrap();
        let mut ready = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(0, &mut ready).unwrap(), 0);

        evt.write(1).unwrap();
        assert_eq!(epoll.wait(100, &mut ready).unwrap(), 1);
        assert_eq!(ready[0].data(), 77);
        assert!(ready[0].event_set().contains(EventSet::IN));
        // Still readable until consumed.
        assert_eq!(epoll.wait(0, &mut ready).unwrap(), 1);
        evt.read().unwrap();
        assert_eq!(epoll.wait(0, &mut ready).unwrap(), 0);
    }

    #[test]
    fn test_ctl_errors_and_delete() {
        let epoll = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd = evt.as_raw_fd();
        epoll
            .ctl(ControlOperation::Modify, fd, EpollEvent::default())
            .unwrap_err();
        epoll
            .ctl(ControlOperation::Delete, fd, EpollEvent::default())
            .unwrap_err();
        epoll
            .ctl(ControlOperation::Add, fd, EpollEvent::new(EventSet::IN, 1))
            .unwrap();
        epoll
            .ctl(ControlOperation::Add, fd, EpollEvent::new(EventSet::IN, 1))
            .unwrap_err();
        epoll
            .ctl(
                ControlOperation::Modify,
                fd,
                EpollEvent::new(EventSet::IN, 5),
            )
            .unwrap();
        evt.write(1).unwrap();
        let mut ready = [EpollEvent::default(); 2];
        assert_eq!(epoll.wait(100, &mut ready).unwrap(), 1);
        assert_eq!(ready[0].data(), 5);
        epoll
            .ctl(ControlOperation::Delete, fd, EpollEvent::default())
            .unwrap();
        assert_eq!(epoll.wait(0, &mut ready).unwrap(), 0);
    }

    #[test]
    fn test_hang_up_and_out() {
        let epoll = Epoll::new().unwrap();
        let mut fds = [0; 2];
        // SAFETY: room for two descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        epoll
            .ctl(
                ControlOperation::Add,
                fds[0],
                EpollEvent::new(EventSet::IN, 10),
            )
            .unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                fds[1],
                EpollEvent::new(EventSet::OUT, 11),
            )
            .unwrap();
        let mut ready = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(100, &mut ready).unwrap(), 1);
        assert_eq!(ready[0].data(), 11);
        assert!(ready[0].event_set().contains(EventSet::OUT));

        epoll
            .ctl(ControlOperation::Delete, fds[1], EpollEvent::default())
            .unwrap();
        // SAFETY: closing our write end.
        unsafe { libc::close(fds[1]) };
        assert_eq!(epoll.wait(100, &mut ready).unwrap(), 1);
        assert_eq!(ready[0].data(), 10);
        assert!(ready[0].event_set().contains(EventSet::HANG_UP));
        // SAFETY: closing our read end.
        unsafe { libc::close(fds[0]) };
    }

    #[test]
    fn test_more_ready_than_room() {
        let epoll = Epoll::new().unwrap();
        let evts: Vec<EventFd> = (0..3)
            .map(|_| EventFd::new(EFD_NONBLOCK).unwrap())
            .collect();
        for (i, evt) in evts.iter().enumerate() {
            epoll
                .ctl(
                    ControlOperation::Add,
                    evt.as_raw_fd(),
                    EpollEvent::new(EventSet::IN, i as u64),
                )
                .unwrap();
            evt.write(1).unwrap();
        }
        let mut ready = [EpollEvent::default(); 2];
        assert_eq!(epoll.wait(100, &mut ready).unwrap(), 2);
        let mut big = [EpollEvent::default(); 8];
        assert_eq!(epoll.wait(100, &mut big).unwrap(), 3);
    }
}
