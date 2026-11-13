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
//! - the read end of a pipe (a standard input redirected from another
//!   process): a zero-byte read waits for data, but a pending read holds
//!   up every other call on a synchronous handle
//!   (`test_a_pending_pipe_read_holds_up_the_handle`), so a
//!   watcher thread checks the pipe with `PeekNamedPipe` (which consumes
//!   nothing and does not wait) and signals an event the wait is woken by.
//!   It checks every millisecond after it saw data, backing off to every
//!   16 ms while the pipe stays empty. The pipe is readable when it has data
//!   and, as on Linux, reports [`EventSet::IN`] with [`EventSet::HANG_UP`]
//!   once every writer closed and it is empty. Only [`EventSet::IN`] can be
//!   asked for: the write end's `WriteQuotaAvailable` follows the room left,
//!   but reads 0 while the reader waits in a read, when a write completes at
//!   once (`test_pipe_write_room_reads_0_while_a_read_waits`), so
//!   [`EventSet::OUT`] fails with `ERROR_NOT_SUPPORTED`.
//!
//! - another [`Epoll`] (a nested epoll): readable while it has something to
//!   report; a forwarder thread waits on its completion port (see `Nest`).
//!
//! Like Linux, regular files cannot be registered (`EPERM`).
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
use std::os::windows::io::{AsRawHandle, BorrowedSocket, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileType, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE,
};
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetNumberOfConsoleInputEvents, PeekConsoleInputW, ReadConsoleInputW,
    ENABLE_LINE_INPUT, INPUT_RECORD, KEY_EVENT,
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
    /// The read end of a pipe; `event` is its [`PipeWatch`]'s event.
    Pipe {
        event: RawFd,
    },
    /// Another [`Epoll`]; `wake` is its [`Nest`]'s event.
    Epoll {
        wake: RawFd,
    },
}

/// What lets an [`Epoll`] be registered in another one (a nested epoll, as
/// the vsock muxer registers its own in the event loop's).
///
/// A completion port is not a waitable object: a wait packet on one ends the
/// process with `STATUS_THREADPOOL_HANDLE_EXCEPTION`. So once an instance is
/// nested, a forwarder thread waits on its port in its place, keeps the
/// packets for the instance's next [`Epoll::wait`], and sets `wake`, the
/// manual-reset event the outer instance watches. The instance is readable
/// while `wake` is set; its [`Epoll::wait`] resets it, then waits on it in
/// place of the port. The forwarder waits for that before it waits on the
/// port again: a level-triggered source still ready posts again, without
/// spinning while nobody takes the packets.
#[derive(Debug)]
struct Nest {
    poller: Arc<Poller>,
    wake: OwnedHandle,
    /// Set (auto-reset) when the packets were taken.
    taken: OwnedHandle,
    pending: Mutex<Vec<Fired>>,
    active: AtomicBool,
    stop: AtomicBool,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn new_event(manual: bool) -> io::Result<OwnedHandle> {
    // SAFETY: creates an unnamed event, not signalled.
    let ev = unsafe { CreateEventW(std::ptr::null(), i32::from(manual), 0, std::ptr::null()) };
    if ev.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the event was just created and is owned here.
    Ok(unsafe { OwnedHandle::from_raw_handle(ev as RawHandle) })
}

/// The instances that may be nested, by descriptor (their port's handle).
fn nests() -> &'static Mutex<HashMap<RawFd, std::sync::Weak<Nest>>> {
    static NESTS: std::sync::OnceLock<Mutex<HashMap<RawFd, std::sync::Weak<Nest>>>> =
        std::sync::OnceLock::new();
    NESTS.get_or_init(Mutex::default)
}

impl Nest {
    fn new(poller: Arc<Poller>) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Nest {
            poller,
            wake: new_event(true)?,
            taken: new_event(false)?,
            pending: Mutex::default(),
            active: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            thread: Mutex::default(),
        }))
    }

    fn wake_fd(&self) -> RawFd {
        from_handle(self.wake.as_raw_handle())
    }

    /// Starts the forwarder, once.
    fn start(self: &Arc<Self>) -> io::Result<()> {
        let mut thread = self.thread.lock().unwrap();
        if thread.is_some() {
            return Ok(());
        }
        let nest = self.clone();
        *thread = Some(
            std::thread::Builder::new()
                .name("wick-epoll-nest".into())
                .spawn(move || nest.forward())?,
        );
        self.active.store(true, Ordering::Release);
        Ok(())
    }

    fn forward(&self) {
        let mut events = Events::new();
        while !self.stop.load(Ordering::Acquire) {
            events.clear();
            if self.poller.wait(&mut events, None).is_err() {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            if events.is_empty() {
                // A notification (`Drop`), or the instance's own wait has
                // the port for a moment.
                continue;
            }
            {
                let mut pending = self.pending.lock().unwrap();
                pending.extend(events.iter().map(|ev| Fired::from(&ev)));
                // SAFETY: the event outlives the thread.
                unsafe { SetEvent(self.wake.as_raw_handle()) };
            }
            // SAFETY: as above; woken by `take` or `Drop`.
            unsafe { WaitForSingleObject(self.taken.as_raw_handle(), u32::MAX) };
        }
    }

    /// The packets kept so far; the instance is not readable for them again.
    fn take(&self) -> Vec<Fired> {
        let fired = {
            let mut pending = self.pending.lock().unwrap();
            // SAFETY: the events are open while `self` is.
            unsafe { ResetEvent(self.wake.as_raw_handle()) };
            std::mem::take(&mut *pending)
        };
        // SAFETY: as above.
        unsafe { SetEvent(self.taken.as_raw_handle()) };
        fired
    }
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
    pipe: Option<PipeWatch>,
}

/// What a pipe's read end holds now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipeState {
    Empty,
    Data,
    /// Every writer closed and nothing is left (end of file); also a pipe
    /// that cannot be queried, so that its reader sees the error.
    Closed,
}

fn pipe_state(fd: RawFd) -> PipeState {
    let mut avail = 0u32;
    // SAFETY: queries the pipe without reading; no buffer is passed.
    let ok = unsafe {
        PeekNamedPipe(
            handle(fd),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut avail,
            std::ptr::null_mut(),
        )
    };
    match (ok != 0, avail) {
        (true, 0) => PipeState::Empty,
        (true, _) => PipeState::Data,
        (false, _) => PipeState::Closed,
    }
}

/// The thread that watches a registered pipe (see the module docs) and the
/// manual-reset event it sets while the pipe is readable. Dropping it stops
/// the thread.
#[derive(Debug)]
struct PipeWatch {
    event: OwnedHandle,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// A handle value that may move to the watcher thread.
#[derive(Clone, Copy)]
struct SendHandle(HANDLE);
// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for SendHandle {}

impl PipeWatch {
    const FAST: Duration = Duration::from_millis(1);
    const SLOW: Duration = Duration::from_millis(16);

    fn start(fd: RawFd) -> io::Result<Self> {
        // SAFETY: creates an unnamed manual-reset event, not signalled.
        let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if ev.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the event was just created and is owned here.
        let event = unsafe { OwnedHandle::from_raw_handle(ev as RawHandle) };
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            let ev = SendHandle(ev);
            std::thread::Builder::new()
                .name("wick-epoll-pipe".into())
                .spawn(move || {
                    let ev = ev;
                    let mut interval = Self::FAST;
                    while !stop.load(Ordering::Acquire) {
                        if pipe_state(fd) == PipeState::Empty {
                            interval = (interval * 2).min(Self::SLOW);
                        } else {
                            // The reader resets it when it finds the pipe
                            // empty (see `Epoll::collect`).
                            // SAFETY: the event outlives the thread.
                            unsafe { SetEvent(ev.0) };
                            interval = Self::FAST;
                        }
                        std::thread::park_timeout(interval);
                    }
                })?
        };
        Ok(PipeWatch {
            event,
            stop,
            thread: Some(thread),
        })
    }

    fn event_fd(&self) -> RawFd {
        from_handle(self.event.as_raw_handle())
    }
}

impl Drop for PipeWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            t.thread().unpark();
            let _ = t.join();
        }
    }
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
    let nest = nests().lock().unwrap().get(&fd).and_then(std::sync::Weak::upgrade);
    if let Some(nest) = nest {
        nest.start()?;
        return Ok(Kind::Epoll {
            wake: nest.wake_fd(),
        });
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
        // The watcher and its event are set up by `Epoll::ctl`.
        FILE_TYPE_PIPE => Ok(Kind::Pipe { event: -1 }),
        _ => Ok(Kind::Waitable),
    }
}

/// In line input mode: whether the Enter that ends a line is among the
/// records waiting. Nothing is removed.
///
/// Linux's terminal in canonical mode has input only once a line is
/// complete (drivers/tty/n_tty.c `input_available_p`: `canon_head !=
/// read_tail`); until then a non-blocking read fails with `EAGAIN`
/// (`n_tty_read`: `tty_io_nonblock`) and poll does not report it readable
/// (`n_tty_poll`). A console read in line input mode returns "only when a
/// carriage return is read" (ENABLE_LINE_INPUT,
/// learn.microsoft.com/windows/console/setconsolemode) and has no
/// non-blocking form, so a read begun with part of a line typed would hold
/// its thread until Enter. A console that cannot be asked counts as ready,
/// so that the reader sees the error. The reader's rule is the same
/// (`wick_os::stdio`).
fn line_ready(h: HANDLE) -> bool {
    let mut count = 0u32;
    // SAFETY: an out-pointer to a u32.
    if unsafe { GetNumberOfConsoleInputEvents(h, &mut count) } == 0 {
        return true;
    }
    if count == 0 {
        return false;
    }
    // SAFETY: an all-zero INPUT_RECORD is valid.
    let mut recs: Vec<INPUT_RECORD> = vec![unsafe { std::mem::zeroed() }; count as usize];
    let mut n = 0u32;
    // SAFETY: room for `count` records.
    if unsafe { PeekConsoleInputW(h, recs.as_mut_ptr(), count, &mut n) } == 0 {
        return true;
    }
    recs.iter().take(n as usize).any(|rec| {
        if u32::from(rec.EventType) != KEY_EVENT {
            return false;
        }
        // SAFETY: the record is a key event.
        let key = unsafe { rec.Event.KeyEvent };
        // SAFETY: a union of u16 and i8; both read as the code unit.
        key.bKeyDown != 0 && unsafe { key.uChar.UnicodeChar } == 0x0d
    })
}

/// Whether a read of console input would return at once. In line input
/// mode: a whole line waits ([`line_ready`]), as Linux's poll reports a
/// canonical terminal; the records of an unfinished line keep the
/// console's handle signalled, so a wait comes back here to look until
/// Enter or raw mode (Firecracker is in line input mode only from the
/// serial's registration to the vCPUs' start, and from its stop to its
/// exit). Otherwise: a record that reads as bytes waits; the records in
/// front of it that do not are dropped.
fn console_ready(h: HANDLE) -> bool {
    let mut mode = 0u32;
    // SAFETY: an out-pointer to a u32; fails on anything but a console.
    if unsafe { GetConsoleMode(h, &mut mode) } != 0 && mode & ENABLE_LINE_INPUT != 0 {
        return line_ready(h);
    }
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

/// The calling thread's buffers for [`Epoll::wait`], kept between waits.
#[derive(Default)]
struct Scratch {
    /// The completion port's packets.
    packets: Option<Events>,
    /// What was found ready: packets and direct checks.
    fired: Vec<Fired>,
    /// A descriptor's slot in the caller's array.
    slot_of: HashMap<RawFd, usize>,
}

thread_local! {
    static SCRATCH: std::cell::RefCell<Scratch> = std::cell::RefCell::new(Scratch::default());
}

/// An epoll instance backed by an I/O completion port.
#[derive(Debug)]
pub struct Epoll {
    poller: Arc<Poller>,
    interests: Mutex<HashMap<RawFd, Interest>>,
    /// Locked after `interests`.
    links: Mutex<HashMap<RawFd, Links>>,
    nest: Arc<Nest>,
}

impl Epoll {
    /// Creates a new instance. `EMFILE` past the jail's no-file limit
    /// (`libc::wick_nofile`), as `epoll_create1` on Linux, for its one
    /// descriptor; the port's helpers are not reserved.
    pub fn new() -> io::Result<Self> {
        libc::wick_nofile::check(1)?;
        let poller = Arc::new(Poller::new()?);
        let nest = Nest::new(poller.clone())?;
        let epoll = Epoll {
            poller,
            interests: Mutex::default(),
            links: Mutex::default(),
            nest,
        };
        nests()
            .lock()
            .unwrap()
            .insert(epoll.as_raw_fd(), Arc::downgrade(&epoll.nest));
        Ok(epoll)
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
                Kind::Pipe { event: ev } | Kind::Epoll { wake: ev } => {
                    let readable = Event::new(key(fd, SUB_MAIN), read, false);
                    self.poller
                        .add_waitable(handle(ev) as RawHandle, readable, mode)
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
            Kind::Pipe { event: ev } | Kind::Epoll { wake: ev } => {
                self.poller.remove_waitable(waitable(ev))
            }
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
                if fd == self.as_raw_fd() {
                    // An instance in itself, as on Linux.
                    return Err(einval());
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
                if let Kind::Pipe { .. } = kind {
                    if events.contains(EventSet::OUT) {
                        return Err(os_error(ERROR_NOT_SUPPORTED));
                    }
                    // A modified registration keeps its watcher.
                    let watch = match links.get_mut(&fd).and_then(|l| l.pipe.take()) {
                        Some(w) => w,
                        None => PipeWatch::start(fd)?,
                    };
                    interest.kind = Kind::Pipe {
                        event: watch.event_fd(),
                    };
                    link.pipe = Some(watch);
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
    ///
    /// Allocates nothing once its thread has waited with as much room
    /// before, as Linux's `epoll_wait` writes into the caller's array: the
    /// port's packets, what is found ready and the map of a descriptor to
    /// its slot are the thread's, kept between waits ([`SCRATCH`]). Each
    /// wait allocated them before (the packets' room twice the caller's,
    /// for the event manager's 256 events), on every pass of the VMM's
    /// event loop, as the macOS instance did (d0dbe31;
    /// `test_a_wait_allocates_nothing`). A nested instance's packets
    /// (`Nest::take`) and a console in line input mode (`line_ready`) still
    /// allocate when they are there.
    pub fn wait(&self, timeout: i32, events: &mut [EpollEvent]) -> io::Result<usize> {
        let Some(cap) = NonZeroUsize::new(events.len()) else {
            return Err(einval());
        };
        SCRATCH.with(|scratch| match scratch.try_borrow_mut() {
            Ok(mut scratch) => self.wait_with(timeout, events, cap, &mut scratch),
            // Not reached: nothing a wait calls waits again. Fresh ones then.
            Err(_) => self.wait_with(timeout, events, cap, &mut Scratch::default()),
        })
    }

    fn wait_with(&self, timeout: i32, events: &mut [EpollEvent], cap: NonZeroUsize, scratch: &mut Scratch) -> io::Result<usize> {
        let timeout = u64::try_from(timeout).ok().map(Duration::from_millis);
        let deadline = timeout.map(|t| std::time::Instant::now() + t);
        let room = cap.saturating_mul(NonZeroUsize::new(2).unwrap());
        let Scratch { packets, fired, slot_of } = scratch;
        let packets = match packets {
            Some(p) if p.capacity() >= room => p,
            _ => packets.insert(Events::with_capacity(room)),
        };
        loop {
            self.rearm()?;
            // What is ready already, without waiting for its packet.
            let nested = self.nest.active.load(Ordering::Acquire);
            fired.clear();
            if nested {
                fired.extend(self.nest.take());
            }
            self.sweep(fired);
            if !fired.is_empty() {
                let count = self.collect(fired, events, slot_of)?;
                if count > 0 {
                    return Ok(count);
                }
            }
            if nested {
                // The forwarder has the port (see `Nest`).
                let left = deadline.map(|d| d.saturating_duration_since(std::time::Instant::now()));
                let ms = left.map_or(u32::MAX, |l| {
                    u32::try_from(l.as_millis()).unwrap_or(u32::MAX - 1)
                });
                // SAFETY: the event is open while `self` is.
                let woken =
                    unsafe { WaitForSingleObject(self.nest.wake.as_raw_handle(), ms) } == WAIT_OBJECT_0;
                if !woken {
                    return Ok(0);
                }
                continue;
            }
            packets.clear();
            let left = deadline.map(|d| d.saturating_duration_since(std::time::Instant::now()));
            self.poller.wait(packets, left)?;
            fired.clear();
            fired.extend(packets.iter().map(|ev| Fired::from(&ev)));
            if !fired.is_empty() {
                self.sweep(fired);
            }
            let count = self.collect(fired, events, slot_of)?;
            // Readiness that turned out to be none (console records with no
            // bytes, a packet gone stale) does not end the wait, as epoll
            // would not have woken.
            if count > 0 || packets.is_empty() || left == Some(Duration::ZERO) {
                return Ok(count);
            }
        }
    }

    /// Adds the level-triggered eventfds and sockets that are ready now to
    /// `out`.
    fn sweep(&self, out: &mut Vec<Fired>) {
        let interests = self.interests.lock().unwrap();
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
                // Checked directly, as it consumes nothing.
                Kind::Pipe { .. } => {
                    if want_in && pipe_state(*fd) != PipeState::Empty {
                        out.push(fired(SUB_MAIN, true, false, false));
                    }
                }
                // A manual-reset event: checked directly.
                Kind::Epoll { wake } => {
                    if want_in && signalled(wake) {
                        out.push(fired(SUB_MAIN, true, false, false));
                    }
                }
            }
        }
    }

    fn collect(&self, fired: &[Fired], events: &mut [EpollEvent], slot_of: &mut HashMap<RawFd, usize>) -> io::Result<usize> {
        let mut interests = self.interests.lock().unwrap();
        let mut count = 0usize;
        slot_of.clear();
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
            // The same for a nested instance, whose wait resets its event.
            if ev.packet
                && matches!(interest.kind, Kind::EventFd { .. } | Kind::Epoll { .. })
                && !interest.edge()
            {
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
                (Kind::Pipe { event }, _) => match pipe_state(fd) {
                    PipeState::Data => bits |= EventSet::IN,
                    PipeState::Closed => bits |= EventSet::IN | EventSet::HANG_UP,
                    PipeState::Empty => {
                        // A packet from before the reader emptied the pipe:
                        // the watcher sets the event again on new data.
                        // SAFETY: the event is open while registered.
                        unsafe { ResetEvent(handle(event)) };
                    }
                },
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

impl Drop for Epoll {
    fn drop(&mut self) {
        nests().lock().unwrap().remove(&self.as_raw_fd());
        let thread = self.nest.thread.lock().unwrap().take();
        if let Some(thread) = thread {
            self.nest.stop.store(true, Ordering::Release);
            let _ = self.poller.notify();
            // SAFETY: the event is open while `self` is.
            unsafe { SetEvent(self.nest.taken.as_raw_handle()) };
            let _ = thread.join();
        }
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

    /// Counts the calling thread's allocations, for
    /// [`test_a_wait_allocates_nothing`].
    struct Counting;
    thread_local! {
        static ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
    // SAFETY: the system allocator's, with a count beside it.
    unsafe impl std::alloc::GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
            // SAFETY: the caller's layout.
            unsafe { std::alloc::System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
            // SAFETY: a block of this allocator, with its layout.
            unsafe { std::alloc::System.dealloc(ptr, layout) }
        }
    }
    #[global_allocator]
    static COUNTING: Counting = Counting;

    // A wait allocates nothing once its thread has waited before, as
    // Linux's epoll_wait writes into the caller's array, and as the macOS
    // instance's does since d0dbe31 (its wait allocated 70 MB in one vsock
    // test). Each wait here allocated the port's packets (room for twice
    // the caller's events), the list of what was ready and the map of a
    // descriptor to its slot, on every pass of the VMM's event loop. Both
    // ways a wait ends: with eventfds found ready by the direct check, and
    // with nothing ready, through the completion port.
    #[test]
    fn test_a_wait_allocates_nothing() {
        let epoll = Epoll::new().unwrap();
        let evts: Vec<EventFd> = (0..3).map(|_| EventFd::new(EFD_NONBLOCK).unwrap()).collect();
        for (i, evt) in evts.iter().enumerate() {
            epoll
                .ctl(ControlOperation::Add, evt.as_raw_fd(), EpollEvent::new(EventSet::IN, i as u64))
                .unwrap();
            evt.write(1).unwrap();
        }
        let mut ready = [EpollEvent::default(); 256];
        assert_eq!(epoll.wait(0, &mut ready).unwrap(), 3);
        let before = ALLOCATIONS.with(std::cell::Cell::get);
        for _ in 0..100 {
            assert_eq!(epoll.wait(0, &mut ready).unwrap(), 3);
        }
        let ready_ones = ALLOCATIONS.with(std::cell::Cell::get) - before;
        for evt in &evts {
            evt.read().unwrap();
        }
        assert_eq!(epoll.wait(0, &mut ready).unwrap(), 0);
        let before = ALLOCATIONS.with(std::cell::Cell::get);
        for _ in 0..100 {
            assert_eq!(epoll.wait(0, &mut ready).unwrap(), 0);
        }
        let none = ALLOCATIONS.with(std::cell::Cell::get) - before;
        assert_eq!((ready_ones, none), (0, 0), "allocations in 100 waits with 3 eventfds ready, and in 100 with none");
    }

    // A rate limiter's timer (vmm's rng test_bandwidth_rate_limiter: the
    // refill timer's event did not arrive in the 100 ms it waits): a
    // non-blocking one-shot timerfd, registered before it is armed and
    // expired while nobody waited, is reported by the next wait, and its
    // read gives one expiration.
    #[test]
    fn test_a_timer_that_expired_unwatched_is_reported() {
        // SAFETY: plain calls on our descriptor and buffers.
        unsafe {
            let fd = libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC);
            assert!(fd >= 0, "{}", io::Error::last_os_error());
            let epoll = Epoll::new().unwrap();
            epoll
                .ctl(ControlOperation::Add, fd, EpollEvent::new(EventSet::IN, 9))
                .unwrap();
            assert!(wait_now(&epoll).is_empty(), "disarmed");
            let spec = libc::itimerspec {
                it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
                it_value: libc::timespec { tv_sec: 0, tv_nsec: 100_000_000 },
            };
            assert_eq!(libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()), 0);
            std::thread::sleep(std::time::Duration::from_millis(350));
            let mut events = [EpollEvent::default(); 4];
            assert_eq!(epoll.wait(100, &mut events).unwrap(), 1, "the expired timer");
            assert_eq!(events[0].data(), 9);
            let mut buf = [0u8; 8];
            assert_eq!(libc::read(fd, buf.as_mut_ptr().cast(), 8), 8, "{}", io::Error::last_os_error());
            assert_eq!(u64::from_ne_bytes(buf), 1);
            assert!(wait_now(&epoll).is_empty(), "read");
            assert_eq!(libc::close(fd), 0);
        }
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

    /// An anonymous pipe: (read end, write end).
    fn pipe() -> (RawFd, RawFd) {
        let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out-pointers to handles.
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(&mut r, &mut w, std::ptr::null(), 0)
            },
            0
        );
        (from_handle(r as RawHandle), from_handle(w as RawHandle))
    }

    fn pipe_write(fd: RawFd, bytes: &[u8]) {
        let mut n = 0;
        // SAFETY: a valid buffer.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::WriteFile(
                handle(fd),
                bytes.as_ptr(),
                u32::try_from(bytes.len()).unwrap(),
                &mut n,
                std::ptr::null_mut(),
            )
        };
        assert!(ok != 0 && n as usize == bytes.len());
    }

    fn pipe_read(fd: RawFd, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut n = 0;
        // SAFETY: a valid buffer.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::ReadFile(
                handle(fd),
                buf.as_mut_ptr(),
                u32::try_from(len).unwrap(),
                &mut n,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        buf.truncate(n as usize);
        buf
    }

    fn close_handle(fd: RawFd) {
        // SAFETY: closes a handle the test owns.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle(fd)) };
    }

    #[test]
    fn test_pipe_in_and_hang_up() {
        let epoll = Epoll::new().unwrap();
        let (r, w) = pipe();
        epoll
            .ctl(ControlOperation::Add, r, EpollEvent::new(EventSet::IN, 5))
            .unwrap();
        assert!(wait_now(&epoll).is_empty());
        pipe_write(w, b"ab");
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!((events[0].data(), events[0].event_set()), (5, EventSet::IN));
        // Level-triggered: still readable until read.
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(pipe_read(r, 8), b"ab");
        assert_eq!(epoll.wait(100, &mut events).unwrap(), 0);
        // The writer leaves: end of file, as Linux reports it.
        close_handle(w);
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].event_set(), EventSet::IN | EventSet::HANG_UP);
        epoll
            .ctl(ControlOperation::Delete, r, EpollEvent::default())
            .unwrap();
        close_handle(r);
    }

    #[test]
    fn test_pipe_wakes_a_blocked_wait() {
        let epoll = Epoll::new().unwrap();
        let (r, w) = pipe();
        epoll
            .ctl(
                ControlOperation::Add,
                r,
                EpollEvent::new(EventSet::IN | EventSet::ONE_SHOT, 1),
            )
            .unwrap();
        let start = std::time::Instant::now();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            pipe_write(w, b"x");
            w
        });
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(5000, &mut events).unwrap(), 1);
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(150) && took < Duration::from_secs(1), "{took:?}");
        // One-shot: not again until modified.
        assert!(wait_now(&epoll).is_empty());
        epoll
            .ctl(
                ControlOperation::Modify,
                r,
                EpollEvent::new(EventSet::IN, 1),
            )
            .unwrap();
        assert_eq!(epoll.wait(1000, &mut events).unwrap(), 1);
        close_handle(writer.join().unwrap());
        drop(epoll);
        close_handle(r);
    }

    #[test]
    fn test_pipe_out_not_supported() {
        let epoll = Epoll::new().unwrap();
        let (r, w) = pipe();
        let err = epoll
            .ctl(
                ControlOperation::Add,
                r,
                EpollEvent::new(EventSet::IN | EventSet::OUT, 0),
            )
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(ERROR_NOT_SUPPORTED as i32));
        close_handle(r);
        close_handle(w);
    }

    /// `FILE_PIPE_LOCAL_INFORMATION` of a pipe end (ntifs.h; class 24 of
    /// `NtQueryInformationFile`): `(ReadDataAvailable, WriteQuotaAvailable)`.
    fn pipe_local(fd: RawFd) -> (u32, u32) {
        #[link(name = "ntdll", kind = "raw-dylib")]
        extern "system" {
            fn NtQueryInformationFile(h: HANDLE, io: *mut [usize; 2], info: *mut [u32; 10], len: u32, class: u32) -> i32;
        }
        let (mut io, mut info) = ([0usize; 2], [0u32; 10]);
        // SAFETY: a pipe handle and out-buffers of the sizes given.
        let status = unsafe { NtQueryInformationFile(handle(fd), &mut io, &mut info, 40, 24) };
        assert_eq!(status, 0);
        (info[5], info[7])
    }

    // Why `EventSet::OUT` is refused on a pipe: the write end's room reads 0
    // while the reader waits in a read, although a write then completes at
    // once, so it cannot tell a full pipe from one a reader drains.
    #[test]
    fn test_pipe_write_room_reads_0_while_a_read_waits() {
        let (r, w) = pipe();
        let room = pipe_local(w).1;
        assert!(room > 0);
        pipe_write(w, b"abc");
        assert_eq!(pipe_local(w).1, room - 3);
        let mut buf = [0u8; 3];
        let mut n = 0;
        // SAFETY: a valid buffer.
        assert_ne!(unsafe { windows_sys::Win32::Storage::FileSystem::ReadFile(handle(r), buf.as_mut_ptr(), 3, &mut n, std::ptr::null_mut()) }, 0);
        assert_eq!(pipe_local(w).1, room);
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0u8; room as usize];
            let mut n = 0;
            // SAFETY: a valid buffer.
            unsafe { windows_sys::Win32::Storage::FileSystem::ReadFile(handle(r), buf.as_mut_ptr(), room, &mut n, std::ptr::null_mut()) };
            n
        });
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(pipe_local(w).1, 0);
        pipe_write(w, b"x");
        assert_eq!(reader.join().unwrap(), 1);
        close_handle(r);
        close_handle(w);
    }

    // Why the read end is watched with `PeekNamedPipe` rather than a pending
    // zero-byte read: that read waits for data, but while it waits every
    // other call on the (synchronous) handle waits behind it.
    #[test]
    fn test_a_pending_pipe_read_holds_up_the_handle() {
        let (r, w) = pipe();
        let reader = std::thread::spawn(move || {
            let mut n = 0;
            let start = std::time::Instant::now();
            // SAFETY: zero bytes into a valid pointer.
            let ok = unsafe { windows_sys::Win32::Storage::FileSystem::ReadFile(handle(r), [0u8; 1].as_mut_ptr(), 0, &mut n, std::ptr::null_mut()) };
            (ok, start.elapsed())
        });
        std::thread::sleep(Duration::from_millis(100));
        let (tx, rx) = std::sync::mpsc::channel();
        let query = std::thread::spawn(move || {
            pipe_local(r);
            tx.send(()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "the query did not wait");
        pipe_write(w, b"x");
        let (ok, took) = reader.join().unwrap();
        assert_ne!(ok, 0);
        assert!(took >= Duration::from_millis(300), "{took:?}");
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        query.join().unwrap();
        close_handle(r);
        close_handle(w);
    }

    /// Tells the child of `test_serial_input_reads_an_emptied_pipe_as_eagain`
    /// that it is the child.
    const SERIAL_CHILD_ENV: &str = "WICK_TEST_SERIAL_INPUT_CHILD";

    /// Firecracker's serial input on a standard input that is a pipe, run by
    /// `test_serial_input_reads_an_emptied_pipe_as_eagain`.
    ///
    /// A wait reports the pipe readable only while it has data (`collect`
    /// asks `pipe_state` then), and an emptied pipe is not reported again.
    /// But the serial reads its input on two events, the input's and the
    /// buffer-ready eventfd's, and one wait can report both (upstream's
    /// vmm/tests/devices.rs, test_issue_serial_hangup_anon_pipe_while_registered_stdin:
    /// "Either one of the events might be handled first. The handling of the
    /// second event will find the stdin without any pending bytes and will
    /// result in EWOULDBLOCK"). So the input event's read can find the pipe
    /// empty, its writer open. Linux's pipe_read gives EAGAIN there
    /// (fs/pipe.c), and the serial waits for input again
    /// (handle_ewouldblock). The serial reads with `std::io::stdin()`, which
    /// in vmm is wick-std's, `wick_os::stdio::stdin()`, read here. std's own
    /// reads an empty non-blocking pipe as `Ok(0)` (ReadFile's ERROR_NO_DATA
    /// is ErrorKind::BrokenPipe in std's decode_error_kind, which
    /// Handle::read returns as the end): the serial's end of input, after
    /// which it never reads its input again.
    #[test]
    #[ignore = "the child of test_serial_input_reads_an_emptied_pipe_as_eagain"]
    fn serial_input_child() {
        if std::env::var_os(SERIAL_CHILD_ENV).is_none() {
            return;
        }
        // Non-blocking, as Firecracker makes its standard input before the
        // vCPUs start (start_vcpus, Terminal::set_non_block).
        // SAFETY: plain calls on the standard input.
        unsafe {
            let flags = libc::fcntl(0, libc::F_GETFL);
            assert!(flags >= 0, "F_GETFL: {}", io::Error::last_os_error());
            assert_eq!(
                libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK),
                0,
                "F_SETFL: {}",
                io::Error::last_os_error()
            );
        }
        let epoll = Epoll::new().unwrap();
        epoll
            .ctl(ControlOperation::Add, 0, EpollEvent::new(EventSet::IN, 9))
            .unwrap();
        // The parent wrote one byte and keeps its end open.
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(epoll.wait(10_000, &mut events).unwrap(), 1);
        assert_eq!((events[0].data(), events[0].event_set()), (9, EventSet::IN));
        let mut input = wick_os::stdio::stdin();
        let mut buf = [0u8; 64];
        // The buffer-ready event's read, handled first, takes the byte.
        assert_eq!(input.read(&mut buf).unwrap(), 1);
        // Empty, its writer open: not reported any more.
        assert!(wait_now(&epoll).is_empty());
        // The read of the input event reported above.
        let got = input.read(&mut buf).map_err(|e| e.raw_os_error());
        assert_eq!(
            got,
            Err(Some(libc::EWOULDBLOCK)),
            "an empty pipe whose writer is open must read as EWOULDBLOCK; Ok(0) is the end of the input, and the serial detaches it"
        );
        epoll
            .ctl(ControlOperation::Delete, 0, EpollEvent::default())
            .unwrap();
    }

    #[test]
    fn test_serial_input_reads_an_emptied_pipe_as_eagain() {
        if std::env::var_os(SERIAL_CHILD_ENV).is_some() {
            return;
        }
        // An anonymous pipe as the jailer gives Firecracker its console
        // (CreatePipe, through std::io::pipe; jailer platform/windows/console.rs).
        let (reader, mut writer) = std::io::pipe().unwrap();
        let exe = std::env::current_exe().unwrap();
        let child = std::process::Command::new(exe)
            .args([
                "--exact",
                "windows::epoll::tests::serial_input_child",
                "--ignored",
                "--nocapture",
            ])
            .env(SERIAL_CHILD_ENV, "1")
            .stdin(reader)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        writer.write_all(b"x").unwrap();
        // The writer stays open until the child is done: its reads must see
        // an empty pipe, not the end of one.
        let out = child.wait_with_output().unwrap();
        drop(writer);
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
    }

    #[test]
    fn test_nested_epoll() {
        let outer = Epoll::new().unwrap();
        let inner = Epoll::new().unwrap();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        inner
            .ctl(ControlOperation::Add, evt.as_raw_fd(), EpollEvent::new(EventSet::IN, 5))
            .unwrap();
        outer
            .ctl(ControlOperation::Add, inner.as_raw_fd(), EpollEvent::new(EventSet::IN, 1))
            .unwrap();
        assert!(wait_now(&outer).is_empty(), "nothing ready inside");
        let writer = {
            let evt = evt.try_clone().unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                evt.write(1).unwrap();
            })
        };
        let mut events = [EpollEvent::default(); 4];
        assert_eq!(outer.wait(2000, &mut events).unwrap(), 1, "woken by the inner source");
        assert_eq!(events[0].data(), 1);
        assert_eq!(events[0].event_set(), EventSet::IN);
        writer.join().unwrap();
        // Level-triggered: still ready while the inner source is.
        assert_eq!(wait_now(&outer), vec![(1, EventSet::IN)]);
        assert_eq!(wait_now(&inner), vec![(5, EventSet::IN)]);
        evt.read().unwrap();
        assert!(wait_now(&inner).is_empty());
        assert!(wait_now(&outer).is_empty(), "the inner source was read");
        // A source added after the nesting wakes the outer one too.
        let late = EventFd::new(EFD_NONBLOCK).unwrap();
        inner
            .ctl(ControlOperation::Add, late.as_raw_fd(), EpollEvent::new(EventSet::IN, 6))
            .unwrap();
        late.write(1).unwrap();
        assert_eq!(outer.wait(2000, &mut events).unwrap(), 1);
        outer
            .ctl(ControlOperation::Delete, inner.as_raw_fd(), EpollEvent::default())
            .unwrap();
        assert!(wait_now(&outer).is_empty());
        assert_eq!(wait_now(&inner), vec![(6, EventSet::IN)]);
        // The instances go before the eventfds they watch (a handle closed
        // while registered is undefined behaviour for the thread pool wait).
        drop(outer);
        drop(inner);
    }
}
