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
//! - the end of a stream is reported as Linux's poll functions report it,
//!   by the descriptor's kind (see [`Kind`]): a socket whose receiving side
//!   is shut (`EV_EOF` on `EVFILT_READ`) is readable with
//!   [`EventSet::READ_HANG_UP`], and [`EventSet::HANG_UP`] only once both
//!   sides are shut; a pipe's read end is readable only with data and hangs
//!   up once no writer is left, its write end gets [`EventSet::ERROR`] once
//!   no reader is left; a socket error (`EV_EOF`'s `fflags`) is
//!   [`EventSet::ERROR`];
//! - as epoll, [`EventSet::READ_HANG_UP`] only when asked for,
//!   [`EventSet::HANG_UP`] and [`EventSet::ERROR`] always;
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
    /// Registered descriptors, their user data, events and kind.
    interests: Mutex<HashMap<RawFd, (u64, EventSet, Kind)>>,
}

/// What a descriptor is, for how the end of its stream is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// net/unix/af_unix.c `unix_poll`, net/ipv4/tcp.c `tcp_poll`.
    Socket,
    /// fs/pipe.c `pipe_poll`.
    Pipe,
    Other,
}

impl Kind {
    fn of(fd: RawFd) -> Kind {
        // SAFETY: an all-zero stat is a valid output buffer.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is a valid output buffer; a bad `fd` fails.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Kind::Other;
        }
        match st.st_mode & libc::S_IFMT {
            libc::S_IFSOCK => Kind::Socket,
            libc::S_IFIFO => Kind::Pipe,
            _ => Kind::Other,
        }
    }
}

/// Which sides of socket `fd` are shut (receiving, sending), as kqueue's
/// `EV_EOF` on its read and write filters tells it, asked of a kqueue of its
/// own so that a side the caller has no filter for is known too.
fn shut_sides(fd: RawFd) -> (bool, bool) {
    // SAFETY: kqueue() takes no arguments; the result is checked.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return (false, false);
    }
    let changes = [
        kevent_for(fd, libc::EVFILT_READ, libc::EV_ADD),
        kevent_for(fd, libc::EVFILT_WRITE, libc::EV_ADD),
    ];
    let mut out = [kevent_for(0, 0, 0); 2];
    let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: both buffers hold two kevents; `kq` is ours.
    let n = unsafe { libc::kevent(kq, changes.as_ptr(), 2, out.as_mut_ptr(), 2, &zero) };
    // SAFETY: closing the kqueue made above.
    unsafe { libc::close(kq) };
    let eof = |filter| {
        out.iter()
            .take(usize::try_from(n).unwrap_or(0))
            .any(|e| e.filter == filter && e.flags & libc::EV_EOF != 0 && e.flags & libc::EV_ERROR == 0)
    };
    (eof(libc::EVFILT_READ), eof(libc::EVFILT_WRITE))
}

/// The events a fired filter stands for on a descriptor of `kind`, as
/// Linux's poll function for it reports them.
fn events_for(fd: RawFd, kind: Kind, ev: &libc::kevent) -> EventSet {
    let read = ev.filter == libc::EVFILT_READ;
    let eof = ev.flags & libc::EV_EOF != 0;
    let mut bits = if read { EventSet::IN } else { EventSet::OUT };
    if !eof {
        return bits;
    }
    match kind {
        Kind::Socket => {
            // A socket error comes with the end of the stream (so_error).
            if ev.fflags != 0 {
                bits |= EventSet::ERROR;
            }
            let (rcv, snd) = shut_sides(fd);
            if rcv {
                bits |= EventSet::IN | EventSet::READ_HANG_UP;
            }
            if rcv && snd {
                bits |= EventSet::HANG_UP;
            }
        }
        Kind::Pipe if read => {
            // Readable only while there is data; no writer left: hang-up.
            if ev.data == 0 {
                bits.remove(EventSet::IN);
            }
            bits |= EventSet::HANG_UP;
        }
        // No reader left on a pipe's write end: an error.
        Kind::Pipe => bits |= EventSet::ERROR,
        Kind::Other => bits |= EventSet::HANG_UP,
    }
    bits
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
                interests.insert(fd, (event.data(), event.event_set(), Kind::of(fd)));
            }
            ControlOperation::Modify => {
                if !interests.contains_key(&fd) {
                    return Err(io::Error::from_raw_os_error(libc::ENOENT));
                }
                self.apply(&Self::filter_changes(fd, event.event_set()))?;
                interests.insert(fd, (event.data(), event.event_set(), Kind::of(fd)));
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

    /// In a forked child: a kqueue is not inherited across `fork` (an epoll
    /// instance is, on Linux), so this makes the instance a new kqueue under
    /// the same descriptor, with the same interests. A one-shot interest that
    /// fired is armed again.
    pub fn reopen_after_fork(&self) -> io::Result<()> {
        let interests = self.interests.lock().unwrap();
        // SAFETY: kqueue() takes no arguments; the result is checked.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors are ours: `self.kq` is the inherited,
        // dead one; dup2 replaces it and keeps its number.
        let ret = unsafe { libc::dup2(kq, self.kq) };
        let err = io::Error::last_os_error();
        if kq != self.kq {
            // SAFETY: the new descriptor, now duplicated.
            unsafe { libc::close(kq) };
        }
        if ret < 0 {
            return Err(err);
        }
        // SAFETY: `self.kq` is ours.
        if unsafe { libc::fcntl(self.kq, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        for (&fd, &(_, events, _)) in interests.iter() {
            self.apply(&Self::filter_changes(fd, events))?;
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
            let Some(&(data, interest, kind)) = interests.get(&fd) else {
                continue;
            };
            let mut bits = if ev.filter == libc::EVFILT_READ || ev.filter == libc::EVFILT_WRITE {
                events_for(fd, kind, ev)
            } else {
                EventSet::empty()
            };
            if ev.flags & libc::EV_ERROR != 0 {
                bits |= EventSet::ERROR;
            }
            // As epoll: what was asked for, and always hang-up and error.
            bits &= interest | EventSet::HANG_UP | EventSet::ERROR;
            if bits.is_empty() {
                continue;
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

    /// The events one `wait` reports for `fd` registered with `interest`.
    fn events_of(fd: RawFd, interest: EventSet) -> EventSet {
        let epoll = Epoll::new().unwrap();
        epoll
            .ctl(ControlOperation::Add, fd, EpollEvent::new(interest, 9))
            .unwrap();
        let mut ready = [EpollEvent::default(); 2];
        assert_eq!(epoll.wait(100, &mut ready).unwrap(), 1, "{interest:?}");
        ready[0].event_set()
    }

    fn socketpair() -> [RawFd; 2] {
        let mut s = [0; 2];
        // SAFETY: room for two descriptors.
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, s.as_mut_ptr()) }, 0);
        s
    }

    fn close(fd: RawFd) {
        // SAFETY: a descriptor the test owns.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_stream_socket_peer_closed_or_half_closed_as_linux() {
        // Linux, net/unix/af_unix.c unix_poll: RCV_SHUTDOWN gives EPOLLIN and
        // EPOLLRDHUP; EPOLLHUP only when both directions are shut
        // (sk_shutdown == SHUTDOWN_MASK, which the peer's close sets:
        // unix_release_sock); a socket whose peer closed stays writable
        // (unix_writable). epoll reports EPOLLRDHUP only when asked for it,
        // EPOLLHUP and EPOLLERR always (fs/eventpoll.c: do_epoll_ctl adds
        // them, ep_item_poll masks with the interest).
        let all = EventSet::IN | EventSet::OUT | EventSet::READ_HANG_UP;
        let s = socketpair();
        close(s[1]);
        assert_eq!(events_of(s[0], all), all | EventSet::HANG_UP);
        assert_eq!(events_of(s[0], EventSet::IN), EventSet::IN | EventSet::HANG_UP);
        assert_eq!(events_of(s[0], EventSet::OUT), EventSet::OUT | EventSet::HANG_UP);
        close(s[0]);
        // The peer shuts down its sending side only: readable to EOF, no HUP.
        let s = socketpair();
        // SAFETY: our descriptor.
        assert_eq!(unsafe { libc::shutdown(s[1], libc::SHUT_WR) }, 0);
        assert_eq!(
            events_of(s[0], EventSet::IN | EventSet::READ_HANG_UP),
            EventSet::IN | EventSet::READ_HANG_UP
        );
        assert_eq!(events_of(s[0], EventSet::IN), EventSet::IN);
        close(s[0]);
        close(s[1]);
    }

    #[test]
    fn test_pipe_ends_as_linux() {
        // Linux, fs/pipe.c pipe_poll: the read end is readable only with data,
        // and EPOLLHUP once no writer is left; the write end gets EPOLLERR once
        // no reader is left. No EPOLLRDHUP on a pipe.
        let mut p = [0; 2];
        // SAFETY: room for two descriptors.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        close(p[1]);
        let rd = EventSet::IN | EventSet::READ_HANG_UP;
        assert_eq!(events_of(p[0], rd), EventSet::HANG_UP);
        close(p[0]);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        // SAFETY: one byte from a local.
        assert_eq!(unsafe { libc::write(p[1], [7u8].as_ptr().cast(), 1) }, 1);
        close(p[1]);
        assert_eq!(events_of(p[0], rd), EventSet::IN | EventSet::HANG_UP);
        close(p[0]);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        close(p[0]);
        assert_eq!(events_of(p[1], EventSet::OUT), EventSet::OUT | EventSet::ERROR);
        close(p[1]);
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

    #[test]
    fn test_reopen_after_fork() {
        // As an epoll instance on Linux, the instance works in a forked child
        // (here once reopened): same descriptor, same interests and data.
        let epoll = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        epoll
            .ctl(ControlOperation::Add, evt.as_raw_fd(), EpollEvent::new(EventSet::IN, 7))
            .unwrap();
        evt.write(1).unwrap();
        // SAFETY: the child only makes plain calls and leaves with _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut ready = [EpollEvent::default(); 2];
            // Without reopening, the inherited descriptor is no kqueue.
            let before = epoll.wait(0, &mut ready).is_err();
            let reopened = epoll.reopen_after_fork().is_ok();
            let n = epoll.wait(100, &mut ready).unwrap_or(0);
            let ok = before && reopened && n == 1 && ready[0].data() == 7;
            // SAFETY: ends the child.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waits for the child just made.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "{status:#x}");
        // The parent's instance is untouched.
        let mut ready = [EpollEvent::default(); 2];
        assert_eq!(epoll.wait(100, &mut ready).unwrap(), 1);
    }
}
