// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `epoll` for Windows, on an I/O completion port (the `polling` crate).
//!
//! Same API as `vmm_sys_util::epoll` on Linux, level-triggered. What a
//! descriptor is decides how its readiness is watched:
//! - sockets: AFD poll requests, the mechanism behind `select` and `WSAPoll`,
//!   which leaves the socket's blocking mode alone. A peer that closed is
//!   reported as [`EventSet::HANG_UP`] and [`EventSet::READ_HANG_UP`] with
//!   [`EventSet::IN`], as on Linux; a reset adds [`EventSet::ERROR`];
//! - eventfds ([`crate::eventfd`]): a wait packet on the readable event for
//!   [`EventSet::IN`] and one on the space event for [`EventSet::OUT`];
//! - console input: a wait packet on the console handle. The console is
//!   signalled for any input record, so records that produce no bytes (key
//!   releases, mouse, focus, resize) are dropped before the console is
//!   reported readable;
//! - any other waitable handle (processes, threads, events, timers): a wait
//!   packet, readable while signalled.
//!
//! - a [`Redirect`]ed socket: the socket it currently names, else itself (a
//!   listening socket that hands its traffic to the connection it accepted).
//!
//! Like Linux, regular files cannot be registered (`EPERM`). Pipes have no
//! readiness to wait for on Windows, and fail with `ERROR_NOT_SUPPORTED`.
//! [`EventSet::ONE_SHOT`] is supported.
//!
//! [`EventSet::EDGE_TRIGGERED`] is supported for sockets. IOCP readiness is
//! level-triggered, so an edge is derived from the reader, as the
//! edge-triggered contract has it read until `EAGAIN`: the descriptor is
//! reported once, and armed again when its reader finds it empty (the
//! compatibility libc's `read` and `recv` report `EAGAIN` through
//! `libc::wick_fd::drained`). It then fires as soon as there is data again,
//! including data that came while it was reported. A reader that stops
//! before `EAGAIN` is not woken by more data, which edge-triggered readers
//! do not rely on. Other descriptors fail with `EINVAL`.
//!
//! Level-triggered readiness is that of the moment [`Epoll::wait`] looks, as
//! with epoll: eventfds (manual-reset events) and sockets (`WSAPoll`) are
//! checked directly then, without consuming anything, so every ready
//! descriptor is reported (up to the room given), not only those whose
//! completion packet has arrived. The completion port wakes the wait.
//!
//! Re-arming happens when [`Epoll::wait`] starts: drains and redirects made
//! on the thread that waits (an event loop handling the event) take effect
//! at its next wait.
//! [`EventSet::PRIORITY`], [`EventSet::WAKE_UP`] and [`EventSet::EXCLUSIVE`]
//! are accepted and ignored.

use std::collections::HashMap;
use std::io;
use std::num::NonZeroUsize;
use std::os::windows::io::{AsRawHandle, BorrowedSocket, RawHandle};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wick_os::fd::{from_handle, handle, socket, AsRawFd, RawFd};
use polling::os::iocp::PollerIocpExt;
use polling::{Event, Events, PollMode, Poller};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_NOT_SUPPORTED, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Networking::WinSock::{
    getsockopt, WSAPoll, POLLERR, POLLHUP, POLLRDNORM, POLLWRNORM, SOL_SOCKET, SO_TYPE,
    WSAPOLLFD,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::Storage::FileSystem::{
    GetFileType, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, PeekConsoleInputW, ReadConsoleInputW, INPUT_RECORD, KEY_EVENT,
};

use super::errors::einval;
pub use crate::epoll_types::{epoll_event, ControlOperation, EpollEvent, EventSet};

fn os_error(code: u32) -> io::Error {
    #[allow(clippy::cast_possible_wrap)]
    io::Error::from_raw_os_error(code as i32)
}

/// How a descriptor's readiness is watched.
#[derive(Debug, Clone, Copy)]
enum Kind {
    Socket,
    /// A socket whose readiness is that of the socket its [`Redirect`] names.
    Redirect,
    /// The space event of the eventfd.
    EventFd {
        space: RawFd,
    },
    Console,
    Waitable,
}

#[derive(Debug, Clone, Copy)]
struct Interest {
    data: u64,
    events: EventSet,
    kind: Kind,
    /// A one-shot registration that fired and waits for `Modify`, or an
    /// edge-triggered one that fired and waits for its reader to drain it.
    disarmed: bool,
    /// The socket registered with the poller (sockets and redirects).
    armed: RawFd,
    /// The drain count when an edge-triggered registration fired.
    seen_drain: u64,
    /// The redirect generation the registration follows.
    generation: u64,
}

impl Interest {
    fn edge(&self) -> bool {
        self.events.contains(EventSet::EDGE_TRIGGERED) && !self.events.contains(EventSet::ONE_SHOT)
    }
}

/// What a registration needs besides its [`Interest`].
#[derive(Debug, Default)]
struct Links {
    drain: Option<Arc<AtomicU64>>,
    redirect: Option<Arc<Redirect>>,
}

/// Makes epoll watch, for a socket, the socket it names: a listening socket
/// registered once (a network endpoint's descriptor) whose traffic flows on
/// the connection it accepted. Attached to the registered socket with
/// [`Redirect::attach`]; [`Redirect::set`] changes the target, which takes
/// effect at the next [`Epoll::wait`].
#[derive(Debug, Default)]
pub struct Redirect {
    target: Mutex<Option<RawFd>>,
    generation: AtomicU64,
}

impl Redirect {
    /// Attaches a redirect, to nothing yet, to the socket `fd`.
    pub fn attach(fd: RawFd) -> io::Result<Arc<Redirect>> {
        if !is_socket(fd) {
            return Err(einval());
        }
        let r = Arc::new(Redirect::default());
        libc::wick_fd::attach(fd, r.clone())?;
        Ok(r)
    }

    /// Watches `target` (`None`: the socket itself) from the next wait on.
    pub fn set(&self, target: Option<RawFd>) {
        *self.target.lock().unwrap() = target;
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    fn current(&self) -> (Option<RawFd>, u64) {
        let t = self.target.lock().unwrap();
        (*t, self.generation.load(Ordering::Acquire))
    }
}

/// Packet keys: the descriptor, and which of its sources fired.
const SUB_MAIN: usize = 0;
const SUB_SPACE: usize = 1;

#[allow(clippy::cast_sign_loss)]
fn key(fd: RawFd, sub: usize) -> usize {
    (fd as u32 as usize) << 1 | sub
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn unkey(key: usize) -> (RawFd, usize) {
    ((key >> 1) as u32 as RawFd, key & 1)
}

fn is_socket(fd: RawFd) -> bool {
    wick_os::windows::startup();
    let mut ty: i32 = 0;
    let mut len = 4;
    // SAFETY: the option value is an `i32`; a non-socket fails.
    unsafe {
        getsockopt(
            socket(fd),
            SOL_SOCKET,
            SO_TYPE,
            (&raw mut ty).cast(),
            &mut len,
        ) == 0
    }
}

fn kind_of(fd: RawFd) -> io::Result<Kind> {
    if libc::wick_fd::attached::<Redirect>(fd).is_some() {
        return Ok(Kind::Redirect);
    }
    if let Some([_, space]) = crate::eventfd::companions(fd) {
        return Ok(Kind::EventFd { space });
    }
    if is_socket(fd) {
        return Ok(Kind::Socket);
    }
    let h = handle(fd);
    // SAFETY: queries a handle value; an invalid one gives FILE_TYPE_UNKNOWN.
    match unsafe { GetFileType(h) } {
        FILE_TYPE_CHAR => {
            let mut mode = 0;
            // SAFETY: as above.
            if unsafe { GetConsoleMode(h, &mut mode) } != 0 {
                Ok(Kind::Console)
            } else {
                // Character devices other than consoles (`NUL`, serial ports)
                // are waitable only for overlapped I/O completion.
                Err(os_error(ERROR_NOT_SUPPORTED))
            }
        }
        FILE_TYPE_DISK => Err(io::Error::from_raw_os_error(libc::EPERM)),
        FILE_TYPE_PIPE => Err(os_error(ERROR_NOT_SUPPORTED)),
        _ => Ok(Kind::Waitable),
    }
}

/// Whether console input has a record that reads as bytes; drops the
/// records in front of it that do not.
fn console_ready(h: HANDLE) -> bool {
    loop {
        // SAFETY: an all-zero INPUT_RECORD is valid.
        let mut rec: INPUT_RECORD = unsafe { std::mem::zeroed() };
        let mut n = 0u32;
        // SAFETY: room for one record.
        if unsafe { PeekConsoleInputW(h, &mut rec, 1, &mut n) } == 0 {
            // Let the reader see the error.
            return true;
        }
        if n == 0 {
            return false;
        }
        if u32::from(rec.EventType) == KEY_EVENT {
            // SAFETY: the record is a key event.
            let key = unsafe { rec.Event.KeyEvent };
            // SAFETY: a union of u16 and i8; both read as the code unit.
            if key.bKeyDown != 0 && unsafe { key.uChar.UnicodeChar } != 0 {
                return true;
            }
        }
        // SAFETY: removes the record peeked above.
        if unsafe { ReadConsoleInputW(h, &mut rec, 1, &mut n) } == 0 {
            return true;
        }
    }
}

/// `POLLHUP` on a socket now.
fn socket_hung_up(fd: RawFd) -> bool {
    let mut pfd = WSAPOLLFD {
        fd: socket(fd),
        events: 0,
        revents: 0,
    };
    // SAFETY: one valid entry, no wait.
    let n = unsafe { WSAPoll(&mut pfd, 1, 0) };
    n > 0 && pfd.revents & POLLHUP != 0
}

/// Whether a manual-reset event is signalled now (nothing is consumed).
fn signalled(fd: RawFd) -> bool {
    // SAFETY: a zero-timeout wait on an open handle.
    unsafe { WaitForSingleObject(handle(fd), 0) == WAIT_OBJECT_0 }
}

/// A source found ready: a completion packet, or a direct check.
#[derive(Debug, Clone, Copy)]
struct Fired {
    key: usize,
    readable: bool,
    writable: bool,
    interrupt: bool,
    err: bool,
    /// From the completion port: may be stale by the time it is read.
    packet: bool,
}

impl From<&Event> for Fired {
    fn from(ev: &Event) -> Self {
        Fired {
            key: ev.key,
            readable: ev.readable,
            writable: ev.writable,
            interrupt: ev.is_interrupt(),
            err: ev.is_err() == Some(true),
            packet: true,
        }
    }
}

/// An epoll instance backed by an I/O completion port.
#[derive(Debug)]
pub struct Epoll {
    poller: Poller,
    interests: Mutex<HashMap<RawFd, Interest>>,
    /// Locked after `interests`.
    links: Mutex<HashMap<RawFd, Links>>,
}

impl Epoll {
    /// Creates a new instance.
    pub fn new() -> io::Result<Self> {
        Ok(Epoll {
            poller: Poller::new()?,
            interests: Mutex::default(),
            links: Mutex::default(),
        })
    }

    fn mode(events: EventSet) -> PollMode {
        if events.intersects(EventSet::ONE_SHOT | EventSet::EDGE_TRIGGERED) {
            PollMode::Oneshot
        } else {
            PollMode::Level
        }
    }

    /// Registers the sources of `fd`.
    fn arm(&self, fd: RawFd, interest: &Interest) -> io::Result<()> {
        let ev = interest.events;
        let (read, write) = if interest.disarmed {
            (false, false)
        } else {
            (ev.contains(EventSet::IN), ev.contains(EventSet::OUT))
        };
        let mode = Self::mode(ev);
        let main = Event::new(key(fd, SUB_MAIN), read, write);
        // SAFETY: the sources stay registered until `disarm`, which the
        // caller does before closing them, as with epoll.
        unsafe {
            match interest.kind {
                Kind::Socket | Kind::Redirect => {
                    self.poller
                        .add_with_mode(socket(interest.armed) as u64, main, mode)
                }
                Kind::EventFd { space } => {
                    let readable = Event::new(key(fd, SUB_MAIN), read, false);
                    self.poller
                        .add_waitable(handle(fd) as RawHandle, readable, mode)?;
                    let room = Event::new(key(fd, SUB_SPACE), write, false);
                    self.poller
                        .add_waitable(handle(space) as RawHandle, room, mode)
                        .inspect_err(|_| {
                            let _ = self.poller.remove_waitable(waitable(fd));
                        })
                }
                Kind::Console | Kind::Waitable => {
                    let readable = Event::new(key(fd, SUB_MAIN), read, false);
                    self.poller
                        .add_waitable(handle(fd) as RawHandle, readable, mode)
                }
            }
        }
    }

    /// Removes the sources of `fd`.
    fn disarm(&self, fd: RawFd, interest: &Interest) -> io::Result<()> {
        match interest.kind {
            Kind::Socket | Kind::Redirect => {
                // SAFETY: the socket is open while registered.
                let s = unsafe { BorrowedSocket::borrow_raw(socket(interest.armed) as u64) };
                self.poller.delete(s)
            }
            Kind::EventFd { space } => {
                let r = self.poller.remove_waitable(waitable(fd));
                self.poller.remove_waitable(waitable(space)).and(r)
            }
            Kind::Console | Kind::Waitable => self.poller.remove_waitable(waitable(fd)),
        }
    }

    /// Adds, changes or removes `fd` in the interest list.
    pub fn ctl(&self, operation: ControlOperation, fd: RawFd, event: EpollEvent) -> io::Result<()> {
        let mut interests = self.interests.lock().unwrap();
        let events = event.event_set();
        match operation {
            ControlOperation::Add | ControlOperation::Modify => {
                let old = interests.get(&fd).copied();
                match (&operation, old) {
                    (ControlOperation::Add, Some(_)) => {
                        return Err(os_error(ERROR_ALREADY_EXISTS));
                    }
                    (ControlOperation::Modify, None) => {
                        return Err(os_error(ERROR_FILE_NOT_FOUND));
                    }
                    _ => {}
                }
                let kind = match old {
                    Some(old) => old.kind,
                    None => kind_of(fd)?,
                };
                let mut links = self.links.lock().unwrap();
                let mut link = Links::default();
                let mut interest = Interest {
                    data: event.data(),
                    events,
                    kind,
                    disarmed: false,
                    armed: fd,
                    seen_drain: 0,
                    generation: 0,
                };
                if interest.edge() {
                    if !matches!(kind, Kind::Socket | Kind::Redirect) {
                        return Err(einval());
                    }
                    let drain = libc::wick_fd::drain_counter(fd);
                    interest.seen_drain = drain.load(Ordering::Acquire);
                    link.drain = Some(drain);
                }
                if matches!(kind, Kind::Redirect) {
                    let Some(r) = libc::wick_fd::attached::<Redirect>(fd) else {
                        return Err(einval());
                    };
                    let (target, generation) = r.current();
                    interest.armed = target.unwrap_or(fd);
                    interest.generation = generation;
                    link.redirect = Some(r);
                }
                if let Some(old) = old {
                    self.disarm(fd, &old)?;
                }
                if let Err(err) = self.arm(fd, &interest) {
                    interests.remove(&fd);
                    links.remove(&fd);
                    return Err(err);
                }
                interests.insert(fd, interest);
                links.insert(fd, link);
            }
            ControlOperation::Delete => {
                let Some(old) = interests.remove(&fd) else {
                    return Err(os_error(ERROR_FILE_NOT_FOUND));
                };
                if let Some(link) = self.links.lock().unwrap().remove(&fd) {
                    if link.drain.is_some() {
                        libc::wick_fd::forget_drains(fd);
                    }
                }
                self.disarm(fd, &old)?;
            }
        }
        Ok(())
    }

    /// Arms again the edge-triggered registrations whose reader drained them
    /// and moves redirected ones to their current target.
    fn rearm(&self) -> io::Result<()> {
        let mut interests = self.interests.lock().unwrap();
        let links = self.links.lock().unwrap();
        for (fd, interest) in interests.iter_mut() {
            let Some(link) = links.get(fd) else {
                continue;
            };
            let mut want = *interest;
            if let Some(r) = &link.redirect {
                let (target, generation) = r.current();
                if generation != interest.generation {
                    want.generation = generation;
                    want.armed = target.unwrap_or(*fd);
                    // A new socket: whatever it has is new.
                    want.disarmed = interest.disarmed && !interest.edge();
                }
            }
            if let Some(drain) = &link.drain {
                let count = drain.load(Ordering::Acquire);
                if interest.disarmed && count != interest.seen_drain {
                    want.disarmed = false;
                }
            }
            if want.armed != interest.armed || want.disarmed != interest.disarmed {
                if want.armed == interest.armed {
                    self.disarm(*fd, interest)?;
                } else {
                    // The previous target may be closed already (a peer that
                    // left); its registration goes either way.
                    let _ = self.disarm(*fd, interest);
                }
                self.arm(*fd, &want)?;
            }
            *interest = want;
        }
        Ok(())
    }

    /// Waits up to `timeout` milliseconds (`-1`: forever) and fills `events`.
    /// Returns the number of events written.
    pub fn wait(&self, timeout: i32, events: &mut [EpollEvent]) -> io::Result<usize> {
        let Some(cap) = NonZeroUsize::new(events.len()) else {
            return Err(einval());
        };
        let timeout = u64::try_from(timeout).ok().map(Duration::from_millis);
        let deadline = timeout.map(|t| std::time::Instant::now() + t);
        let mut fired = Events::with_capacity(cap.saturating_mul(NonZeroUsize::new(2).unwrap()));
        loop {
            self.rearm()?;
            // What is ready already, without waiting for its packet.
            let ready = self.sweep();
            if !ready.is_empty() {
                let count = self.collect(&ready, events)?;
                if count > 0 {
                    return Ok(count);
                }
            }
            fired.clear();
            let left = deadline.map(|d| d.saturating_duration_since(std::time::Instant::now()));
            self.poller.wait(&mut fired, left)?;
            let mut all: Vec<Fired> = fired.iter().map(|ev| Fired::from(&ev)).collect();
            if !all.is_empty() {
                all.extend(self.sweep());
            }
            let count = self.collect(&all, events)?;
            // Readiness that turned out to be none (console records with no
            // bytes, a packet gone stale) does not end the wait, as epoll
            // would not have woken.
            if count > 0 || fired.is_empty() || left == Some(Duration::ZERO) {
                return Ok(count);
            }
        }
    }

    /// The level-triggered eventfds and sockets that are ready now.
    fn sweep(&self) -> Vec<Fired> {
        let interests = self.interests.lock().unwrap();
        let mut out = Vec::new();
        for (fd, interest) in interests.iter() {
            if interest.disarmed || interest.edge() {
                continue;
            }
            let want_in = interest.events.contains(EventSet::IN);
            let want_out = interest.events.contains(EventSet::OUT);
            let fired = |sub, readable, writable, err| Fired {
                key: key(*fd, sub),
                readable,
                writable,
                interrupt: false,
                err,
                packet: false,
            };
            match interest.kind {
                Kind::EventFd { space } => {
                    if want_in && signalled(*fd) {
                        out.push(fired(SUB_MAIN, true, false, false));
                    }
                    if want_out && signalled(space) {
                        out.push(fired(SUB_SPACE, true, false, false));
                    }
                }
                Kind::Socket | Kind::Redirect => {
                    let mut events = 0;
                    if want_in {
                        events |= POLLRDNORM;
                    }
                    if want_out {
                        events |= POLLWRNORM;
                    }
                    let mut pfd = WSAPOLLFD {
                        fd: socket(interest.armed),
                        events,
                        revents: 0,
                    };
                    // SAFETY: one valid entry, no wait.
                    if unsafe { WSAPoll(&mut pfd, 1, 0) } > 0 {
                        let r = pfd.revents;
                        let readable = r & (POLLRDNORM | POLLHUP) != 0;
                        let writable = r & POLLWRNORM != 0;
                        let err = r & POLLERR != 0;
                        if readable || writable || err {
                            out.push(fired(SUB_MAIN, readable, writable, err));
                        }
                    }
                }
                // Console readiness is checked when collected; other handles
                // may be auto-reset, which a check would consume.
                Kind::Console | Kind::Waitable => {}
            }
        }
        out
    }

    fn collect(&self, fired: &[Fired], events: &mut [EpollEvent]) -> io::Result<usize> {
        let mut interests = self.interests.lock().unwrap();
        let mut count = 0usize;
        let mut slot_of: HashMap<RawFd, usize> = HashMap::new();
        for ev in fired {
            let (fd, sub) = unkey(ev.key);
            let Some(interest) = interests.get(&fd).copied() else {
                continue;
            };
            if interest.disarmed {
                continue;
            }
            // An eventfd's packet only wakes the wait: its state now is in
            // the sweep that follows (the packet may predate a read).
            if ev.packet && matches!(interest.kind, Kind::EventFd { .. }) && !interest.edge() {
                continue;
            }
            let mut bits = EventSet::empty();
            match (interest.kind, sub) {
                (Kind::Socket | Kind::Redirect, _) => {
                    if ev.readable {
                        bits |= EventSet::IN;
                        if socket_hung_up(interest.armed) {
                            bits |= EventSet::HANG_UP | EventSet::READ_HANG_UP;
                        }
                    }
                    if ev.writable {
                        bits |= EventSet::OUT;
                    }
                    if ev.interrupt {
                        bits |= EventSet::HANG_UP | EventSet::ERROR;
                    }
                    if ev.err {
                        bits |= EventSet::ERROR;
                    }
                }
                (Kind::EventFd { .. }, SUB_SPACE) => bits |= EventSet::OUT,
                (Kind::Console, _) => {
                    if console_ready(handle(fd)) {
                        bits |= EventSet::IN;
                    }
                }
                _ => bits |= EventSet::IN,
            }
            // Only what was asked for, plus the conditions epoll always reports.
            bits &= interest.events | EventSet::ERROR | EventSet::HANG_UP;
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
                    events[count] = EpollEvent::new(EventSet::empty(), interest.data);
                    count += 1;
                    count - 1
                }
            };
            let merged = events[slot].event_set() | bits;
            events[slot] = EpollEvent::new(merged, interest.data);
            if interest.events.contains(EventSet::ONE_SHOT) || interest.edge() {
                // The other source of an eventfd stops too, as epoll's
                // one-shot covers the whole descriptor. An edge waits for
                // its reader to drain the descriptor (see `rearm`).
                let mut off = interest;
                off.disarmed = true;
                if interest.edge() {
                    if let Some(drain) = self
                        .links
                        .lock()
                        .unwrap()
                        .get(&fd)
                        .and_then(|l| l.drain.clone())
                    {
                        off.seen_drain = drain.load(Ordering::Acquire);
                    }
                }
                self.disarm(fd, &interest)?;
                self.arm(fd, &off)?;
                interests.insert(fd, off);
            }
        }
        Ok(count)
    }
}

fn waitable(fd: RawFd) -> std::os::windows::io::BorrowedHandle<'static> {
    // SAFETY: the handle is open while registered.
    unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(handle(fd) as RawHandle) }
}

impl AsRawFd for Epoll {
    fn as_raw_fd(&self) -> RawFd {
        from_handle(self.poller.as_raw_handle())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;

    use wick_os::unix::net::UnixStream;

    use super::*;
    use crate::eventfd::{EventFd, EFD_NONBLOCK};

    fn wait_now(epoll: &Epoll) -> Vec<(u64, EventSet)> {
        let mut events = [EpollEvent::default(); 8];
        let n = epoll.wait(0, &mut events).unwrap();
        events[..n]
            .iter()
            .map(|e| (e.data(), e.event_set()))
            .collect()
    }

    #[test]
    fn test_eventfd_level_triggered() {
        let epoll = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                evt.as_raw_fd(),
                EpollEvent::new(EventSet::IN, 7),
            )
            .unwrap();
        assert!(wait_now(&epoll).is_empty());
        evt.write(1).unwrap();
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 7);
        assert_eq!(events[0].event_set(), EventSet::IN);
        // Still readable: reported again.
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        evt.read().unwrap();
        assert!(wait_now(&epoll).is_empty());
    }

    fn read_all(fd: RawFd) -> usize {
        let mut total = 0;
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: a valid buffer.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return total;
            }
            total += n.unsigned_abs();
        }
    }

    #[test]
    fn test_socket_edge_triggered() {
        let epoll = Epoll::new().unwrap();
        let (a, mut b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let ev = EpollEvent::new(EventSet::IN | EventSet::EDGE_TRIGGERED, 3);
        epoll.ctl(ControlOperation::Add, a.as_raw_fd(), ev).unwrap();
        assert!(wait_now(&epoll).is_empty());
        b.write_all(b"one").unwrap();
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 3);
        // Not reported again until the reader is done.
        assert!(wait_now(&epoll).is_empty());
        b.write_all(b"two").unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(wait_now(&epoll).is_empty());
        assert_eq!(read_all(a.as_raw_fd()), 6);
        assert!(wait_now(&epoll).is_empty(), "drained, nothing new");
        b.write_all(b"three").unwrap();
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1, "a new edge");
        epoll
            .ctl(ControlOperation::Delete, a.as_raw_fd(), ev)
            .unwrap();
    }

    #[test]
    fn test_redirect_follows_the_connection() {
        let dir = crate::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().join("ep");
        let listener = wick_os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let l = listener.as_raw_fd();
        let redirect = Redirect::attach(l).unwrap();
        let epoll = Epoll::new().unwrap();
        let ev = EpollEvent::new(EventSet::IN | EventSet::EDGE_TRIGGERED, 9);
        epoll.ctl(ControlOperation::Add, l, ev).unwrap();
        let mut peer = UnixStream::connect(&path).unwrap();
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1, "a connection");
        let (conn, _) = listener.accept().unwrap();
        conn.set_nonblocking(true).unwrap();
        redirect.set(Some(conn.as_raw_fd()));
        libc::wick_fd::drained(l);
        assert!(wait_now(&epoll).is_empty());
        peer.write_all(b"frame").unwrap();
        assert_eq!(
            epoll.wait(1000, &mut events).unwrap(),
            1,
            "data on the connection"
        );
        assert_eq!(events[0].data(), 9);
        assert_eq!(read_all(conn.as_raw_fd()), 5);
        libc::wick_fd::drained(l);
        drop(peer);
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1, "the peer left");
        assert!(events[0].event_set().contains(EventSet::HANG_UP));
        redirect.set(None);
        drop(conn);
        libc::wick_fd::drained(l);
        assert!(wait_now(&epoll).is_empty(), "back on the listener");
        let _again = UnixStream::connect(&path).unwrap();
        assert_eq!(
            epoll.wait(1000, &mut events).unwrap(),
            1,
            "a new connection"
        );
    }

    #[test]
    fn test_eventfd_out() {
        let epoll = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                evt.as_raw_fd(),
                EpollEvent::new(EventSet::IN | EventSet::OUT, 1),
            )
            .unwrap();
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].event_set(), EventSet::OUT);
        evt.write(1).unwrap();
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].event_set(), EventSet::IN | EventSet::OUT);
    }

    #[test]
    fn test_ctl_errors_and_delete() {
        let epoll = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd = evt.as_raw_fd();
        let ev = EpollEvent::new(EventSet::IN, 0);
        assert_eq!(
            epoll
                .ctl(ControlOperation::Modify, fd, ev)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        epoll.ctl(ControlOperation::Add, fd, ev).unwrap();
        assert_eq!(
            epoll.ctl(ControlOperation::Add, fd, ev).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        epoll
            .ctl(
                ControlOperation::Add,
                12345,
                EpollEvent::new(EventSet::IN | EventSet::EDGE_TRIGGERED, 0),
            )
            .unwrap_err();
        evt.write(1).unwrap();
        epoll.ctl(ControlOperation::Delete, fd, ev).unwrap();
        assert!(wait_now(&epoll).is_empty());
        assert_eq!(
            epoll
                .ctl(ControlOperation::Delete, fd, ev)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn test_regular_file_rejected() {
        let epoll = Epoll::new().unwrap();
        let file = crate::tempfile::TempFile::new().unwrap();
        let err = epoll
            .ctl(
                ControlOperation::Add,
                file.as_file().as_raw_fd(),
                EpollEvent::new(EventSet::IN, 0),
            )
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_one_shot() {
        let epoll = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd = evt.as_raw_fd();
        epoll
            .ctl(
                ControlOperation::Add,
                fd,
                EpollEvent::new(EventSet::IN | EventSet::ONE_SHOT, 3),
            )
            .unwrap();
        evt.write(1).unwrap();
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert!(wait_now(&epoll).is_empty());
        epoll
            .ctl(
                ControlOperation::Modify,
                fd,
                EpollEvent::new(EventSet::IN | EventSet::ONE_SHOT, 3),
            )
            .unwrap();
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
    }

    #[test]
    fn test_socket_in_out_hang_up() {
        let epoll = Epoll::new().unwrap();
        let (mut a, b) = UnixStream::pair().unwrap();
        let fd = b.as_raw_fd();
        epoll
            .ctl(
                ControlOperation::Add,
                fd,
                EpollEvent::new(EventSet::IN | EventSet::OUT | EventSet::READ_HANG_UP, 9),
            )
            .unwrap();
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].event_set(), EventSet::OUT);
        a.write_all(b"x").unwrap();
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].event_set(), EventSet::IN | EventSet::OUT);
        let mut buf = [0u8; 1];
        (&b).read_exact(&mut buf).unwrap();
        a.shutdown(Shutdown::Both).unwrap();
        drop(a);
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        let set = events[0].event_set();
        assert!(
            set.contains(EventSet::IN | EventSet::HANG_UP | EventSet::READ_HANG_UP),
            "{set:?}"
        );
        // As with epoll, READ_HANG_UP only when asked for.
        epoll
            .ctl(
                ControlOperation::Modify,
                fd,
                EpollEvent::new(EventSet::IN, 9),
            )
            .unwrap();
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(
            events[0].event_set(),
            EventSet::IN | EventSet::HANG_UP,
            "{:?}",
            events[0].event_set()
        );
    }

    #[test]
    fn test_more_ready_than_room() {
        let epoll = Epoll::new().unwrap();
        let evts: Vec<_> = (0..4)
            .map(|_| EventFd::new(EFD_NONBLOCK).unwrap())
            .collect();
        for (i, e) in evts.iter().enumerate() {
            e.write(1).unwrap();
            epoll
                .ctl(
                    ControlOperation::Add,
                    e.as_raw_fd(),
                    EpollEvent::new(EventSet::IN, i as u64),
                )
                .unwrap();
        }
        let mut events = [EpollEvent::default(); 2];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 2);
        let mut all = [EpollEvent::default(); 8];
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(epoll.wait(1000, &mut all).unwrap(), 4);
    }
}
