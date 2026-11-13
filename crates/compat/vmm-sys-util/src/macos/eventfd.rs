// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `eventfd` for macOS.
//!
//! Same API and semantics as `vmm_sys_util::eventfd` on Linux:
//! - one descriptor, readable while the counter is non-zero, that can be
//!   registered with [`crate::epoll::Epoll`], duplicated, and handed to another
//!   process (`FromRawFd`/`IntoRawFd`, `SCM_RIGHTS`), where 8-byte reads and
//!   writes work as on an eventfd;
//! - `write(v)` adds `v`; `u64::MAX` is invalid, and a write that would take
//!   the counter past `u64::MAX - 1` blocks, or fails with `WouldBlock` when
//!   non-blocking;
//! - `read` returns the counter and resets it, or takes one unit in semaphore
//!   mode; it blocks, or fails with `WouldBlock`, while the counter is zero.
//!
//! The descriptor is a FIFO opened for reading and writing, then unlinked.
//! Each write puts one 8-byte record in it (writes up to `PIPE_BUF` are
//! atomic) and a read sums the records. The counter of the handles of one
//! process is also kept in memory, which is where the overflow check is made;
//! records written by other processes are added when read.
//!
//! A consumer ([`EventFd::add_consumer`]) is what KVM's irqfd is to an
//! eventfd: KVM hooks the eventfd's wait queue, so a write raises the
//! interrupt in the writing thread and takes the count (Linux v6.1
//! fs/eventfd.c `eventfd_write` wakes the queue under its lock,
//! virt/kvm/eventfd.c `irqfd_wakeup` reads the count and injects; it does so
//! for a write of 0 too). A write through a handle of this process is handed
//! to the consumers instead of being counted, unless none takes it. A handle
//! made from a descriptor ([`FromRawFd`], e.g. one another process holds)
//! has a counter of its own: its writes stay records, which whoever reads
//! the descriptor takes.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, TryLockError};

pub use libc::{EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};

const RECORD: usize = std::mem::size_of::<u64>();
/// The largest value the counter holds.
const MAX: u64 = u64::MAX - 1;

/// Takes a write in place of the counter ([`EventFd::add_consumer`]):
/// returns whether it did.
pub type Consumer = Box<dyn Fn() -> bool + Send + Sync>;

/// Names a consumer added with [`EventFd::add_consumer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumerId(u64);

/// The in-memory counter shared by the handles of one process.
#[derive(Default)]
struct Counter {
    value: Mutex<u64>,
    changed: Condvar,
    /// Held for reading while a write calls them, and never with `value`:
    /// a consumer may take locks of its own (a VM's), and a thread that
    /// holds those may read the counter (an irqfd thread).
    consumers: RwLock<Vec<(ConsumerId, Consumer)>>,
}

impl std::fmt::Debug for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Counter")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

/// An `eventfd` counter that can be waited on with `epoll`.
#[derive(Debug)]
pub struct EventFd {
    fifo: File,
    counter: Arc<Counter>,
    semaphore: bool,
    /// Whether calls fail with `WouldBlock` instead of waiting. The
    /// descriptor itself is always non-blocking; blocking calls wait in
    /// `poll`.
    nonblocking: bool,
}

fn fcntl_set(fd: RawFd, get: i32, set: i32, flag: i32, on: bool) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own; the return value is checked.
    let flags = unsafe { libc::fcntl(fd, get) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = if on { flags | flag } else { flags & !flag };
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, set, flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits until `fd` is readable; with `timeout` 0, only checks.
fn poll_readable(fd: RawFd, timeout: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: one valid pollfd.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout) };
        if ret >= 0 {
            return Ok(ret > 0 && pfd.revents & libc::POLLIN != 0);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// How the name of an eventfd's FIFO starts, in the temporary directory
/// (`std::env::temp_dir()`): then the process ID, `-` and a counter. The
/// name is removed as soon as the FIFO is open; Firecracker's sandbox lets a
/// running microVM remove only such names and its network endpoints.
pub const FIFO_PREFIX: &str = ".eventfd-";

/// A FIFO opened for reading and writing, with no name left behind.
fn anonymous_fifo() -> io::Result<File> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let path = std::env::temp_dir().join(format!(
            "{FIFO_PREFIX}{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: mkfifo with a NUL-terminated path.
        if unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) } != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(err);
        }
        // Opening a FIFO for reading and writing does not wait for a peer.
        // SAFETY: open with a NUL-terminated path.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let err = io::Error::last_os_error();
        // SAFETY: as above.
        unsafe { libc::unlink(cpath.as_ptr()) };
        if fd < 0 {
            return Err(err);
        }
        // SAFETY: a fresh descriptor we own.
        return Ok(unsafe { File::from_raw_fd(fd) });
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists))
}

impl EventFd {
    /// Creates a new counter set to zero. `flag` is a combination of
    /// [`EFD_NONBLOCK`], [`EFD_CLOEXEC`] and [`EFD_SEMAPHORE`].
    pub fn new(flag: i32) -> result::Result<EventFd, io::Error> {
        if flag & !(EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE) != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let fifo = anonymous_fifo()?;
        let fd = fifo.as_raw_fd();
        fcntl_set(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK, true)?;
        fcntl_set(
            fd,
            libc::F_GETFD,
            libc::F_SETFD,
            libc::FD_CLOEXEC,
            flag & EFD_CLOEXEC != 0,
        )?;
        Ok(EventFd {
            fifo,
            counter: Arc::default(),
            semaphore: flag & EFD_SEMAPHORE != 0,
            nonblocking: flag & EFD_NONBLOCK != 0,
        })
    }

    /// Adds `v` to the counter.
    pub fn write(&self, v: u64) -> result::Result<(), io::Error> {
        if v == u64::MAX {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // Not under `value`'s lock (see `Counter::consumers`).
        if self.consumed() {
            return Ok(());
        }
        let mut value = self.counter.value.lock().unwrap();
        while MAX - *value < v {
            if self.nonblocking {
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            }
            value = self.counter.changed.wait(value).unwrap();
        }
        if v == 0 {
            return Ok(());
        }
        self.put_record(v)?;
        *value += v;
        Ok(())
    }

    /// Hands a write to the consumers; whether one took it.
    fn consumed(&self) -> bool {
        let consumers = self.counter.consumers.read().unwrap();
        consumers.iter().fold(false, |taken, (_, consume)| consume() | taken)
    }

    /// Adds a consumer: from now on a write through a handle of this
    /// process calls it, in the writing thread, and is not counted if it
    /// returns true (see the module's documentation). It must not write
    /// this counter, or remove a consumer of it.
    pub fn add_consumer(&self, consumer: Consumer) -> ConsumerId {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = ConsumerId(NEXT.fetch_add(1, Ordering::Relaxed));
        self.counter.consumers.write().unwrap().push((id, consumer));
        id
    }

    /// Removes a consumer; once it returns, the consumer is not running and
    /// is not called again, as KVM's irqfd deassignment waits for the
    /// injections under way (virt/kvm/eventfd.c `kvm_irqfd_deassign`). So it
    /// must not be called while holding a lock the consumer takes. Whether
    /// it was there.
    pub fn remove_consumer(&self, id: ConsumerId) -> bool {
        let mut consumers = self.counter.consumers.write().unwrap();
        let before = consumers.len();
        consumers.retain(|(c, _)| *c != id);
        consumers.len() != before
    }

    /// As [`Self::remove_consumer`] if no consumer runs; otherwise leaves it
    /// and returns false. For a consumer's owner going away inside a
    /// consumer's call, which would wait for itself.
    pub fn try_remove_consumer(&self, id: ConsumerId) -> bool {
        match self.counter.consumers.try_write() {
            Ok(mut consumers) => {
                let before = consumers.len();
                consumers.retain(|(c, _)| *c != id);
                consumers.len() != before
            }
            Err(TryLockError::WouldBlock) => false,
            Err(TryLockError::Poisoned(e)) => panic!("{e}"),
        }
    }

    /// Writes one record. A full FIFO (thousands of records nobody read) is
    /// folded into one record first.
    fn put_record(&self, v: u64) -> io::Result<()> {
        match (&self.fifo).write(&v.to_ne_bytes()) {
            Ok(RECORD) => Ok(()),
            Ok(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                let sum = self.take_records()?.saturating_add(v).min(MAX);
                (&self.fifo).write_all(&sum.to_ne_bytes())
            }
            Err(err) => Err(err),
        }
    }

    /// Reads and sums every record waiting.
    fn take_records(&self) -> io::Result<u64> {
        let mut total = 0u64;
        let mut buf = [0u8; RECORD * 64];
        loop {
            match (&self.fifo).read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // Records are written whole, so reads return whole records.
                    for rec in buf[..n].chunks_exact(RECORD) {
                        total = total.saturating_add(u64::from_ne_bytes(rec.try_into().unwrap()));
                    }
                    if n < buf.len() {
                        break;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(total.min(MAX))
    }

    /// Reads the counter and resets it to zero, or takes one unit in semaphore
    /// mode. Blocks (or fails with `WouldBlock`) while the counter is zero.
    pub fn read(&self) -> result::Result<u64, io::Error> {
        loop {
            {
                let mut value = self.counter.value.lock().unwrap();
                let total = self.take_records()?;
                if total > 0 {
                    let taken = if self.semaphore {
                        if total > 1 {
                            (&self.fifo).write_all(&(total - 1).to_ne_bytes())?;
                        }
                        1
                    } else {
                        total
                    };
                    // Units written by other processes were never counted here.
                    *value = if self.semaphore {
                        value.saturating_sub(1)
                    } else {
                        0
                    };
                    self.counter.changed.notify_all();
                    return Ok(taken);
                }
                if self.nonblocking {
                    return Err(io::Error::from_raw_os_error(libc::EAGAIN));
                }
            }
            poll_readable(self.fifo.as_raw_fd(), -1)?;
        }
    }

    /// Returns a new handle to the same counter.
    pub fn try_clone(&self) -> result::Result<EventFd, io::Error> {
        Ok(EventFd {
            fifo: self.fifo.try_clone()?,
            counter: self.counter.clone(),
            semaphore: self.semaphore,
            nonblocking: self.nonblocking,
        })
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fifo.as_raw_fd()
    }
}

impl FromRawFd for EventFd {
    /// Takes an eventfd descriptor of this kind, e.g. one received from
    /// another process. Its blocking mode is that of the descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be an open descriptor that the new object owns.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY: the caller hands over ownership of `fd`.
        let fifo = unsafe { File::from_raw_fd(fd) };
        // SAFETY: fcntl on the descriptor we now own.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let nonblocking = flags >= 0 && flags & libc::O_NONBLOCK != 0;
        let _ = fcntl_set(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK, true);
        EventFd {
            fifo,
            counter: Arc::default(),
            semaphore: false,
            nonblocking,
        }
    }
}

impl IntoRawFd for EventFd {
    fn into_raw_fd(self) -> RawFd {
        self.fifo.into_raw_fd()
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
        evt.write(55).unwrap();
        assert_eq!(evt.read().unwrap(), 55);
    }

    #[test]
    fn test_writes_add_up() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        evt.write(1).unwrap();
        evt.write(2).unwrap();
        evt.write(3).unwrap();
        assert_eq!(evt.read().unwrap(), 6);
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_read_nothing() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let err = evt.read().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EAGAIN));
    }

    #[test]
    fn test_semaphore() {
        let evt = EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE).unwrap();
        evt.write(1).unwrap();
        evt.write(2).unwrap();
        assert_eq!(evt.read().unwrap(), 1);
        assert_eq!(evt.read().unwrap(), 1);
        assert_eq!(evt.read().unwrap(), 1);
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    fn counting(calls: &Arc<AtomicU64>, takes: bool) -> Consumer {
        let calls = calls.clone();
        Box::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            takes
        })
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
        assert!(!poll_readable(evt.as_raw_fd(), 0).unwrap());
    }

    #[test]
    fn test_a_write_no_consumer_takes_is_counted() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        evt.add_consumer(counting(&calls, false));
        evt.write(5).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(evt.read().unwrap(), 5);
        // Each consumer is called; one that takes the write is enough.
        let other = Arc::new(AtomicU64::new(0));
        evt.add_consumer(counting(&other, true));
        evt.write(2).unwrap();
        assert_eq!((calls.load(Ordering::SeqCst), other.load(Ordering::SeqCst)), (2, 1));
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_a_handle_from_the_descriptor_is_not_consumed() {
        // What another process holds: its writes stay records, for whoever
        // reads the descriptor (an irqfd thread).
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        evt.add_consumer(counting(&calls, true));
        // SAFETY: a new descriptor of the same FIFO, owned by the handle.
        let other = unsafe { EventFd::from_raw_fd(libc::dup(evt.as_raw_fd())) };
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
        evt.write(6).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(evt.read().unwrap(), 6);
    }

    /// A consumer that says it started, then waits for `gate`.
    fn gated(gate: &Arc<Mutex<()>>) -> (Consumer, std::sync::mpsc::Receiver<()>, Arc<AtomicU64>) {
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
    fn test_a_consumer_runs_without_the_counters_lock() {
        // A consumer takes locks of its own (a VM's), and the thread that
        // holds them may read the counter meanwhile (the irqfd thread reads
        // an irqfd under the VM's lock): were the consumer called with the
        // counter's lock held, the two would wait for each other forever.
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let gate = Arc::new(Mutex::new(()));
        let (consumer, started, _) = gated(&gate);
        evt.add_consumer(consumer);
        let held = gate.lock().unwrap();
        let writer = evt.try_clone().unwrap();
        let write = std::thread::spawn(move || writer.write(1).unwrap());
        started.recv_timeout(BOUND).expect("the consumer did not start");
        // The consumer waits for `gate`, which this thread holds: a read
        // here must not wait for the consumer.
        let reader = evt.try_clone().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(reader.read().map_err(|e| e.kind())).unwrap());
        let read = rx.recv_timeout(BOUND).unwrap_or_else(|_| {
            panic!("a read waited for a running consumer: the consumer holds the counter's lock")
        });
        assert_eq!(read, Err(io::ErrorKind::WouldBlock));
        drop(held);
        write.join().unwrap();
    }

    #[test]
    fn test_removing_a_consumer_waits_for_its_run() {
        // As KVM's deassignment: once removed, the consumer is not running.
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let gate = Arc::new(Mutex::new(()));
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

    #[test]
    fn test_clone() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read().unwrap(), 923);
    }

    #[test]
    fn test_overflow() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        assert_eq!(
            evt.write(u64::MAX).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        evt.write(u64::MAX - 1).unwrap();
        assert_eq!(evt.write(1).unwrap_err().raw_os_error(), Some(libc::EAGAIN));
        evt.write(0).unwrap();
        assert_eq!(evt.read().unwrap(), u64::MAX - 1);
        evt.write(1).unwrap();
    }

    #[test]
    fn test_blocking_write_waits_for_read() {
        let evt = EventFd::new(0).unwrap();
        evt.write(u64::MAX - 1).unwrap();
        let reader = evt.try_clone().unwrap();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            reader.read().unwrap()
        });
        evt.write(5).unwrap();
        assert_eq!(handle.join().unwrap(), u64::MAX - 1);
        assert_eq!(evt.read().unwrap(), 5);
    }

    #[test]
    fn test_blocking_read_waits_for_write() {
        let evt = EventFd::new(0).unwrap();
        let writer = evt.try_clone().unwrap();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            writer.write(7).unwrap();
        });
        assert_eq!(evt.read().unwrap(), 7);
        handle.join().unwrap();
    }

    #[test]
    fn test_one_descriptor() {
        // What a process that received the descriptor does: 8-byte writes
        // and reads on it.
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd = evt.as_raw_fd();
        let v = 3u64.to_ne_bytes();
        // SAFETY: an 8-byte write from a local.
        assert_eq!(unsafe { libc::write(fd, v.as_ptr().cast(), 8) }, 8);
        evt.write(4).unwrap();
        assert_eq!(evt.read().unwrap(), 7);
        evt.write(9).unwrap();
        let mut buf = [0u8; 8];
        // SAFETY: an 8-byte read into a local.
        assert_eq!(unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 8) }, 8);
        assert_eq!(u64::from_ne_bytes(buf), 9);
    }

    #[test]
    fn test_raw_fd_round_trip() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let writer = evt.try_clone().unwrap();
        let fd = evt.into_raw_fd();
        // SAFETY: `fd` was just released by `into_raw_fd`.
        let evt = unsafe { EventFd::from_raw_fd(fd) };
        writer.write(11).unwrap();
        assert_eq!(evt.read().unwrap(), 11);
        assert_eq!(evt.read().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_full_fifo_folds_records() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        for _ in 0..20_000 {
            evt.write(1).unwrap();
        }
        assert_eq!(evt.read().unwrap(), 20_000);
    }
}
