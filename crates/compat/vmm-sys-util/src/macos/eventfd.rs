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

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

pub use libc::{EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};

const RECORD: usize = std::mem::size_of::<u64>();
/// The largest value the counter holds.
const MAX: u64 = u64::MAX - 1;

/// The in-memory counter shared by the handles of one process.
#[derive(Debug, Default)]
struct Counter {
    value: Mutex<u64>,
    changed: Condvar,
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

/// A FIFO opened for reading and writing, with no name left behind.
fn anonymous_fifo() -> io::Result<File> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let path = std::env::temp_dir().join(format!(
            ".eventfd-{}-{}",
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
