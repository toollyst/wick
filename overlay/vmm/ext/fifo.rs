// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The file Firecracker writes its log, its metrics and a serial device's
//! output to (`OutFile`, from `utils::open_file_nonblock`), so that a FIFO
//! given for them holds what a Linux FIFO holds.
//!
//! Linux (upstream): Firecracker opens the path `O_RDWR | O_NONBLOCK`, so it
//! is a reader itself: a write never fails for want of a reader, and the
//! bytes wait in the FIFO for the next reader until it holds pipe(7)'s
//! 65536 unread; then a write fails with `EAGAIN`, which upstream counts
//! (`missed_log_count`, `missed_metrics_count`) or answers with 400
//! (`FlushMetrics`). A byte is in the kernel's FIFO when `write` returns, so
//! it survives any end of Firecracker while another process holds the FIFO
//! open.
//!
//! macOS: a FIFO is a pair of local stream sockets with 8192 bytes of buffer
//! (xnu fifo_vnops.c, uipc_usrreq.c `PIPSIZ`, the host-wide
//! `net.local.stream.sendspace`), which no call on the FIFO's descriptor
//! raises. So `OutFile` writes into the FIFO directly while it has room, and
//! only what does not fit goes into an overflow of Firecracker's own, 65536
//! less the FIFO's buffer, after which writes fail as Linux's do; once
//! anything is in the overflow every write goes behind it, so the order is
//! kept; a thread made at the first FIFO's open (before the host sandbox
//! narrows) moves the overflow into the FIFO as the reader makes room; it
//! stops for the API process's fork, gone from the kernel's count of threads
//! when [`before_fork`] returns, and runs again after it ([`after_fork`]). A
//! write of up to 4096 bytes (Linux's `PIPE_BUF`) is taken whole or not at
//! all. Only the overflow can be lost, and only at `SIGKILL`: what Linux
//! would still hold for a reader more than the FIFO's own buffer behind.
//! An orderly end (`exit`, the panic hook, upstream's signal handlers)
//! drains it first ([`drain`]). So does an end by `SIGTERM`, `SIGINT` or
//! `SIGQUIT`, which upstream leaves at their default action and on Linux
//! end Firecracker with its bytes in the FIFO: once a FIFO is open, a
//! handler drains and then ends Firecracker by the same signal at its
//! default action, so its parent reads the wait status Linux gives.
//!
//! Windows: the path names a pipe its reader made, and Firecracker is the
//! pipe's client. Such a pipe ends with its reader, and a write to it then
//! fails (os error 232 or 233), which a Linux FIFO held read-write never
//! does. So `OutFile` writes into the reader's pipe directly while it
//! lives and has room, and keeps what it does not take, and everything
//! once the reader has gone, in an overflow of 65536 bytes less what the
//! live pipe holds; past that writes fail as Linux's do; a thread moves the
//! overflow into the pipe as its reader makes room, and into the pipe a
//! new reader makes under the same name, if its owner is the first's. The
//! rules, the pipe and the thread are `wick_os::fifo` (`std::os::fifo`
//! here), where their tests are; this file has only the type. Left to
//! Windows: bytes a reader left unread in its pipe end with that pipe, and
//! the overflow is lost at an abrupt end, as on macOS. Windows has no fork
//! ([`before_fork`] and [`after_fork`] do nothing there).

/// How long the orderly drain waits for a reader that holds the FIFO open
/// and takes nothing, and for a lock another thread holds (Linux's end does
/// not wait: its bytes stay in the FIFO; this bounds the delay the drain
/// adds on macOS).
pub const DRAIN_STALL: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(not(any(target_os = "macos", windows)))]
/// The file itself: Linux's FIFO is what upstream expects.
pub type OutFile = std::fs::File;

/// Moves what Firecracker still holds for a FIFO's reader into the FIFO
/// before an orderly end. Nothing to do where the file is the FIFO itself.
#[cfg(not(any(target_os = "macos", windows)))]
pub fn drain() {}

/// Called before a `fork`: no thread of this module's to stop where the
/// file is the FIFO itself.
#[cfg(not(target_os = "macos"))]
pub fn before_fork() -> std::io::Result<()> {
    Ok(())
}

/// Called after a `fork`, on both sides: nothing to do where the file is
/// the FIFO itself.
#[cfg(not(target_os = "macos"))]
pub fn after_fork(_in_child: bool) -> std::io::Result<()> {
    Ok(())
}

/// `file` as an [`OutFile`] written directly, whatever it is (tests that
/// write to a file they opened themselves).
#[cfg(not(any(target_os = "macos", windows)))]
pub fn plain(file: std::fs::File) -> OutFile {
    file
}

#[cfg(windows)]
pub use windows::{OutFile, drain, plain};

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::io::{self, Write};
    use std::os::fifo::{OutPipe, PIPE_BUF};
    use std::path::Path;

    use vm_memory::bitmap::BitmapSlice;
    use vm_memory::{VolatileMemoryError, VolatileSlice, WriteVolatile};

    /// Where Firecracker's log, metrics and serial output go.
    #[derive(Debug)]
    pub struct OutFile(Kind);

    #[derive(Debug)]
    enum Kind {
        /// A regular file or device: written directly, as upstream does.
        File(File),
        /// A named pipe, with its overflow.
        Pipe(OutPipe),
    }

    impl OutFile {
        /// `file` as upstream opened `path` (for reading and writing,
        /// created if missing): a pipe gets its overflow, anything else is
        /// written directly.
        pub fn opened(file: File, path: &Path) -> io::Result<OutFile> {
            Ok(OutFile(match OutPipe::from_file(file, path)? {
                Ok(pipe) => {
                    // A pipe made again under the name that is not taken
                    // for the reader's (another owner's) is in the log, once.
                    std::os::fifo::set_report(report);
                    Kind::Pipe(pipe)
                }
                Err(file) => Kind::File(file),
            }))
        }

        fn write_any(&self, buf: &[u8]) -> io::Result<usize> {
            match &self.0 {
                Kind::File(f) => (&*f).write(buf),
                Kind::Pipe(p) => p.write(buf),
            }
        }
    }

    /// `wick_os::fifo`'s line about a pipe it did not take, through
    /// Firecracker's logger (not rate-limited: it comes once).
    fn report(line: &str) {
        crate::logger::warn_unrestricted!("{line}");
    }

    /// `file` as an [`OutFile`] written directly, whatever it is (tests
    /// that write to a file they opened themselves).
    pub fn plain(file: File) -> OutFile {
        OutFile(Kind::File(file))
    }

    /// Moves what Firecracker still holds for each pipe's reader into its
    /// pipe before an orderly end (the panic hook; a return from `main`
    /// runs it through the C runtime's `atexit`, `wick_os::fifo`).
    pub fn drain() {
        std::os::fifo::drain();
    }

    impl Write for &OutFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_any(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            match &self.0 {
                Kind::File(f) => (&*f).flush(),
                Kind::Pipe(_) => Ok(()),
            }
        }
    }

    impl Write for OutFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_any(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            (&*self).flush()
        }
    }

    impl WriteVolatile for OutFile {
        fn write_volatile<B: BitmapSlice>(&mut self, buf: &VolatileSlice<B>) -> Result<usize, VolatileMemoryError> {
            match &mut self.0 {
                Kind::File(f) => f.write_volatile(buf),
                Kind::Pipe(p) => {
                    // At most PIPE_BUF at a time, through a buffer of ours.
                    let mut bytes = [0u8; PIPE_BUF];
                    let n = buf.len().min(PIPE_BUF);
                    let n = buf.subslice(0, n)?.copy_to(&mut bytes[..n]);
                    p.write(&bytes[..n]).map_err(VolatileMemoryError::IOError)
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::{OutFile, after_fork, before_fork, drain, plain};
#[cfg(all(test, target_os = "macos"))]
pub(crate) use macos::queued;

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::VecDeque;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::cell::UnsafeCell;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};

    use super::DRAIN_STALL;
    use vm_memory::bitmap::BitmapSlice;
    use vm_memory::{VolatileMemoryError, VolatileSlice, WriteVolatile};

    /// pipe(7): what a Linux FIFO holds unread, here the FIFO's own buffer
    /// and the overflow together.
    pub const CAPACITY: usize = 65536;
    /// Linux's `PIPE_BUF`: a write of at most this many bytes is taken whole
    /// or refused (pipe(7)).
    pub const PIPE_BUF: usize = 4096;
    /// `F_SETNOSIGPIPE` (xnu sys/fcntl.h): `EPIPE` without `SIGPIPE`.
    const F_SETNOSIGPIPE: libc::c_int = 73;

    /// Where Firecracker's log, metrics and serial output go.
    pub struct OutFile(Kind);

    enum Kind {
        /// A regular file or device: written directly, as upstream does.
        File(File),
        /// A FIFO, with its overflow.
        Fifo(Arc<Fifo>),
    }

    struct Fifo {
        /// The FIFO, write only: what `OutFile` writes.
        w: File,
        /// Upstream's `O_RDWR` descriptor: Firecracker a reader of the FIFO,
        /// as on Linux. The drain closes it (-1 then), so that `EPIPE` then
        /// says that no other process holds the FIFO for reading. An atomic,
        /// not a lock: the drain runs in signal handlers.
        keep: AtomicI32,
        /// Bytes accepted while the FIFO was full, oldest first.
        ring: OwnerLock<VecDeque<u8>>,
        /// The overflow's size: [`CAPACITY`] less the FIFO's buffer.
        cap: usize,
        /// `ring`'s length, for the relay's poll list.
        queued: AtomicUsize,
        /// The FIFO has no reader left (`EPIPE`): the relay stops.
        broken: AtomicBool,
    }

    /// A lock that knows the thread holding it, made of one atomic: the
    /// thread's id, 0 when free. A signal handler that writes (upstream's
    /// log and metrics at a fatal signal) or drains on a thread interrupted
    /// inside it must not wait for itself (Linux's logger, a read lock, does
    /// not wait); and the drain, which runs in signal handlers, must neither
    /// allocate nor wait unboundedly. Taking it is a compare-and-swap; a
    /// thread that finds it held spins briefly, then sleeps 50 µs at a time
    /// (`nanosleep`): holders hold it across non-blocking writes only, but
    /// for the drain, which holds it while it waits for the reader (at most
    /// [`DRAIN_STALL`] without progress).
    struct OwnerLock<T> {
        owner: AtomicU64,
        value: UnsafeCell<T>,
    }

    // SAFETY: the value is reached only through `Held`, which one thread has
    // at a time (the owner's compare-and-swap).
    unsafe impl<T: Send> Sync for OwnerLock<T> {}

    struct Held<'a, T> {
        lock: &'a OwnerLock<T>,
    }

    impl<T> Drop for Held<'_, T> {
        fn drop(&mut self) {
            self.lock.owner.store(0, Ordering::Release);
            // An ending signal that came while this thread held a lock.
            end::deferred();
        }
    }

    impl<T> Held<'_, T> {
        /// The release alone, for the check [`Drop`] itself makes
        /// (`relay::held_by_this_thread`).
        fn release_quietly(self) {
            self.lock.owner.store(0, Ordering::Release);
            std::mem::forget(self);
        }
    }

    impl<T> std::ops::Deref for Held<'_, T> {
        type Target = T;
        fn deref(&self) -> &T {
            // SAFETY: this thread holds the lock.
            unsafe { &*self.lock.value.get() }
        }
    }

    impl<T> std::ops::DerefMut for Held<'_, T> {
        fn deref_mut(&mut self) -> &mut T {
            // SAFETY: this thread holds the lock.
            unsafe { &mut *self.lock.value.get() }
        }
    }

    fn me() -> u64 {
        // SAFETY: plain call; async-signal-safe. Never 0 (a pointer).
        unsafe { libc::pthread_self() as u64 }
    }

    impl<T> OwnerLock<T> {
        fn new(value: T) -> Self {
            OwnerLock { owner: AtomicU64::new(0), value: UnsafeCell::new(value) }
        }

        /// The lock, or `None` when the calling thread holds it already (a
        /// signal handler on a thread interrupted inside it).
        fn lock(&self) -> Option<Held<'_, T>> {
            self.acquire(None)
        }

        /// Whether the calling thread holds it.
        fn mine(&self) -> bool {
            self.owner.load(Ordering::Acquire) == me()
        }

        /// As [`Self::lock`], but `None` too if another thread still holds
        /// it at `until`.
        fn lock_until(&self, until: Instant) -> Option<Held<'_, T>> {
            self.acquire(Some(until))
        }

        fn acquire(&self, until: Option<Instant>) -> Option<Held<'_, T>> {
            let me = me();
            if self.owner.load(Ordering::Acquire) == me {
                return None;
            }
            let mut tries = 0u32;
            loop {
                if self.owner.compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return Some(Held { lock: self });
                }
                if until.is_some_and(|u| Instant::now() >= u) {
                    return None;
                }
                tries = tries.saturating_add(1);
                if tries < 100 {
                    std::hint::spin_loop();
                } else {
                    let nap = libc::timespec { tv_sec: 0, tv_nsec: 50_000 };
                    // SAFETY: plain call; async-signal-safe.
                    unsafe { libc::nanosleep(&nap, std::ptr::null_mut()) };
                }
            }
        }
    }

    /// `write(2)` on `fd`.
    fn raw_write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: a valid buffer of that length.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n.cast_unsigned()) }
    }

    /// Waits until `fd` takes a write (at least the FIFO's low-water mark
    /// free, 512 bytes, measured), at most `timeout`.
    fn wait_writable(fd: RawFd, timeout: Duration) -> bool {
        let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        let ms = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one pollfd.
        unsafe { libc::poll(&mut p, 1, ms) > 0 }
    }

    impl Fifo {
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let fd = self.w.as_raw_fd();
            let Some(mut ring) = self.ring.lock() else {
                // A signal handler that interrupted this thread's own
                // write: straight into the FIFO, ahead of the overflow,
                // never waiting.
                return raw_write(fd, buf);
            };
            let free = self.cap - ring.len();
            let taken = if ring.is_empty() {
                // Into the FIFO while it has room: in the kernel when
                // `write` returns, as on Linux.
                let n = match raw_write(fd, buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                    // No reader left (only after the drain closed `keep`).
                    Err(e) => return Err(e),
                };
                // The rest behind it. With the overflow empty it has room
                // for any write of up to PIPE_BUF.
                let rest = &buf[n..];
                let more = rest.len().min(free);
                ring.extend(&rest[..more]);
                n + more
            } else {
                // Behind what is already waiting.
                if buf.len() <= PIPE_BUF && free < buf.len() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let more = buf.len().min(free);
                ring.extend(&buf[..more]);
                more
            };
            let queued = ring.len();
            self.queued.store(queued, Ordering::Release);
            drop(ring);
            if queued > 0 {
                relay::wake();
            }
            if taken == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(taken)
        }

        /// Moves the front of the overflow into the FIFO, as much as it
        /// takes now (the relay).
        fn relay_once(&self) {
            let Some(mut ring) = self.ring.lock() else { return };
            while !ring.is_empty() {
                let (front, _) = ring.as_slices();
                match raw_write(self.w.as_raw_fd(), front) {
                    Ok(n) => {
                        ring.drain(..n);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        self.broken.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            self.queued.store(ring.len(), Ordering::Release);
        }

        /// The orderly end's drain: `keep` closed, then the overflow written
        /// while a reader takes it; stops when none holds the FIFO (`EPIPE`,
        /// as Linux frees a FIFO's bytes when its last holder goes) or the
        /// reader has taken nothing for [`DRAIN_STALL`]. Skipped when the
        /// overflow's lock is this thread's (a signal handler inside a write:
        /// the overflow may be half updated) or another thread's still at
        /// `until`. Async-signal-safe: atomics, `write`, `poll`, `close`,
        /// `nanosleep`, `clock_gettime`; nothing allocated (the overflow's
        /// bytes are moved in place).
        fn drain(&self, until: Instant) {
            let Some(mut ring) = self.ring.lock_until(until) else { return };
            if ring.is_empty() {
                return;
            }
            let keep = self.keep.swap(-1, Ordering::AcqRel);
            if keep >= 0 {
                // SAFETY: our descriptor, taken out of `keep` just now.
                unsafe { libc::close(keep) };
            }
            let fd = self.w.as_raw_fd();
            let mut deadline = Instant::now() + DRAIN_STALL;
            while !ring.is_empty() {
                let (front, _) = ring.as_slices();
                match raw_write(fd, front) {
                    Ok(n) => {
                        ring.drain(..n);
                        deadline = Instant::now() + DRAIN_STALL;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        let left = deadline.saturating_duration_since(Instant::now());
                        if left.is_zero() || !wait_writable(fd, left) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            self.queued.store(ring.len(), Ordering::Release);
        }
    }

    /// The FIFO's own buffer: `net.local.stream.sendspace` (xnu
    /// uipc_usrreq.c, the stream socket's reserve a FIFO gets).
    fn fifo_buffer() -> io::Result<usize> {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: a NUL-terminated name and an int-sized output.
        let r = unsafe {
            libc::sysctlbyname(
                c"net.local.stream.sendspace".as_ptr(),
                (&raw mut v).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(usize::try_from(v).unwrap_or(0))
    }

    impl OutFile {
        /// `file` as upstream opened `path` (`O_RDWR | O_NONBLOCK`, created
        /// if missing): a FIFO gets its overflow, anything else is written
        /// directly.
        pub fn opened(file: File, path: &Path) -> io::Result<OutFile> {
            let meta = file.metadata()?;
            if !meta.file_type().is_fifo() {
                return Ok(OutFile(Kind::File(file)));
            }
            // Another open of the same FIFO, write only (it has a reader:
            // `file`), checked to be the same file.
            let w = OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(path)?;
            let wm = w.metadata()?;
            if (wm.dev(), wm.ino()) != (meta.dev(), meta.ino()) {
                return Err(io::Error::other(format!("{}: replaced while it was opened", path.display())));
            }
            // SAFETY: fcntl on a descriptor we own.
            if unsafe { libc::fcntl(w.as_raw_fd(), F_SETNOSIGPIPE, 1) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // At least PIPE_BUF, so that a small write is taken whole while
            // the overflow is empty, should a host's FIFO buffer be raised
            // near 65536.
            let cap = CAPACITY.saturating_sub(fifo_buffer()?).max(PIPE_BUF);
            let fifo = Arc::new(Fifo {
                w,
                keep: AtomicI32::new(file.into_raw_fd()),
                ring: OwnerLock::new(VecDeque::with_capacity(cap)),
                cap,
                queued: AtomicUsize::new(0),
                broken: AtomicBool::new(false),
            });
            relay::register(&fifo)?;
            Ok(OutFile(Kind::Fifo(fifo)))
        }

        fn write_any(&self, buf: &[u8]) -> io::Result<usize> {
            match &self.0 {
                Kind::File(f) => (&*f).write(buf),
                Kind::Fifo(f) => f.write(buf),
            }
        }

        /// Runs `f` while this thread holds the overflow's lock, as a write
        /// does (the signal re-entry test).
        #[cfg(test)]
        pub(super) fn holding<R>(&self, f: impl FnOnce() -> R) -> R {
            match &self.0 {
                Kind::File(_) => f(),
                Kind::Fifo(fifo) => {
                    let _held = fifo.ring.lock().expect("not held by this thread");
                    f()
                }
            }
        }

        /// Stops the relay, and returns the bytes in the overflow then (the
        /// drain test: what only the drain can move).
        #[cfg(test)]
        pub(crate) fn pause_relay(&self) -> usize {
            relay::PAUSED.store(true, Ordering::Release);
            match &self.0 {
                Kind::File(_) => 0,
                // The lock waits out a relay pass in progress.
                Kind::Fifo(fifo) => fifo.ring.lock().expect("not held by this thread").len(),
            }
        }

        /// Waits until the reader has taken bytes from the full FIFO (it
        /// takes a write again), at most 10 s: the drain tests' children
        /// end only once their reader reads, so that no test depends on how
        /// soon its reader starts.
        #[cfg(test)]
        pub(crate) fn wait_reader(&self) {
            if let Kind::Fifo(fifo) = &self.0 {
                assert!(wait_writable(fifo.w.as_raw_fd(), Duration::from_secs(10)), "the reader read nothing");
            }
        }

        /// Waits until the relay has moved into the FIFO all it can now:
        /// the overflow empty, or the FIFO without room for it.
        #[cfg(test)]
        pub(super) fn settled(&self) {
            if let Kind::Fifo(fifo) = &self.0 {
                let deadline = Instant::now() + Duration::from_secs(10);
                while fifo.queued.load(Ordering::Acquire) > 0 {
                    if !wait_writable(fifo.w.as_raw_fd(), Duration::ZERO) {
                        // Full, and it stays so until the reader reads; the
                        // lock waits out a relay pass in progress.
                        drop(fifo.ring.lock());
                        return;
                    }
                    assert!(Instant::now() < deadline, "the relay did not settle");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    impl Drop for OutFile {
        /// A FIFO's `OutFile` takes it off the relay's list (`relay::unregister`):
        /// then its last reference is this one, or the relay's for a pass
        /// in progress, and its memory is freed on this thread or the
        /// relay's, never in a signal handler.
        fn drop(&mut self) {
            if let Kind::Fifo(fifo) = &self.0 {
                relay::unregister(fifo);
            }
        }
    }

    impl Drop for Fifo {
        /// A FIFO's `OutFile` dropped (a serial device's, with its VM) is
        /// drained first: on Linux its bytes are in the FIFO already.
        fn drop(&mut self) {
            #[cfg(test)]
            DROPPED_ON.store(me(), Ordering::Release);
            self.drain(Instant::now() + DRAIN_STALL);
            let keep = *self.keep.get_mut();
            if keep >= 0 {
                // SAFETY: our descriptor, not closed yet (the drain sets -1).
                unsafe { libc::close(keep) };
            }
        }
    }

    /// The thread that ran the last `Fifo`'s drop (`pthread_self`), for
    /// `test_a_fifo_is_freed_by_its_owner_not_a_handler`.
    #[cfg(test)]
    pub(crate) static DROPPED_ON: AtomicU64 = AtomicU64::new(0);

    /// [`relay::each`] for the test of who frees a FIFO: `f` runs while the
    /// list is held, as a signal handler's drain runs.
    #[cfg(test)]
    pub(crate) fn while_listed(f: impl Fn()) {
        relay::each(Instant::now() + DRAIN_STALL, |_| f());
    }

    /// `pthread_self` of the calling thread, as [`DROPPED_ON`] records it.
    #[cfg(test)]
    pub(crate) fn this_thread() -> u64 {
        me()
    }

    /// `file` as an [`OutFile`] written directly, whatever it is (tests
    /// that write to a file they opened themselves).
    pub fn plain(file: File) -> OutFile {
        OutFile(Kind::File(file))
    }

    impl Write for &OutFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_any(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            match &self.0 {
                Kind::File(f) => (&*f).flush(),
                Kind::Fifo(_) => Ok(()),
            }
        }
    }

    impl Write for OutFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_any(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            (&*self).flush()
        }
    }

    impl WriteVolatile for OutFile {
        fn write_volatile<B: BitmapSlice>(&mut self, buf: &VolatileSlice<B>) -> Result<usize, VolatileMemoryError> {
            match &mut self.0 {
                Kind::File(f) => f.write_volatile(buf),
                Kind::Fifo(f) => {
                    // At most PIPE_BUF at a time, through a buffer of ours.
                    let mut bytes = [0u8; PIPE_BUF];
                    let n = buf.len().min(PIPE_BUF);
                    let n = buf.subslice(0, n)?.copy_to(&mut bytes[..n]);
                    f.write(&bytes[..n]).map_err(VolatileMemoryError::IOError)
                }
            }
        }
    }

    impl std::fmt::Debug for OutFile {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match &self.0 {
                Kind::File(file) => f.debug_tuple("OutFile").field(file).finish(),
                Kind::Fifo(fifo) => f
                    .debug_struct("OutFile")
                    .field("fifo", &fifo.w)
                    .field("queued", &fifo.queued.load(Ordering::Relaxed))
                    .field("cap", &fifo.cap)
                    .finish(),
            }
        }
    }

    /// Moves what Firecracker still holds for each FIFO's reader into the
    /// FIFO before an orderly end (`exit` through an `atexit` handler, the
    /// panic hook, upstream's fatal signal handlers before their `_exit`).
    ///
    /// Async-signal-safe, so that a signal handler may call it before its
    /// `_exit` (upstream's and the sandbox's): nothing allocated, and no
    /// wait for a lock but bounded: a lock this thread holds (the handler
    /// interrupted a write) skips that FIFO at once; one another thread
    /// holds is waited for until [`DRAIN_STALL`] from the call, then
    /// skipped. Then [`DRAIN_STALL`] at most for each FIFO whose reader
    /// stops taking bytes.
    pub fn drain() {
        let until = Instant::now() + DRAIN_STALL;
        relay::each(until, |fifo| fifo.drain(until));
    }

    /// Stops the relay thread before a `fork` (`ext::api_process::split`,
    /// which forks only from one thread): it holds the overflows' locks
    /// while it runs, and a fork copies only the calling thread. Waits for
    /// a relay pass in progress to end, and then until the kernel counts
    /// the relay's thread no more (`relay::stop`); a thread the kernel
    /// still lists 10 s after its join is an error, and the split fails
    /// by it. [`after_fork`] starts the relay again.
    pub fn before_fork() -> io::Result<()> {
        // The three signals this module handles wait until [`after_fork`]:
        // one that came to the child (a terminal's, sent to the whole
        // process group) before it has its default action again would run
        // the handler there, which writes the child's copies of
        // Firecracker's bytes.
        end::hold();
        relay::stop()
    }

    /// After a `fork` that [`before_fork`] preceded, or after the `fork`
    /// was not made. In Firecracker (`in_child` false) the relay runs
    /// again, and moves what the overflows hold, written once, by
    /// Firecracker. In the child (the API process), whose copies of the
    /// overflows are Firecracker's bytes, the copies are emptied, so that
    /// its drains (its exit, its panic hook) do not write them a second
    /// time, and it gets no relay: it writes no FIFO (the API process
    /// turns its log off right after this call, `api_process::fork`).
    ///
    /// That is also why the child's drains never wait: its profile has
    /// neither `poll` nor `nanosleep` (`sandbox::API_SYSCALLS`), and an
    /// overflow emptied here and never written again gives them nothing
    /// to wait for (`test_the_api_process_drain_waits_for_nothing`).
    pub fn after_fork(in_child: bool) -> io::Result<()> {
        if in_child {
            relay::forget_in_child();
            end::default_in_child();
            end::release();
            Ok(())
        } else {
            let restarted = relay::restart();
            end::release();
            restarted
        }
    }

    /// [`before_fork`]'s wait for a joined relay, on thread `tid` (the test
    /// of its error: a thread that has not ended).
    #[cfg(test)]
    pub(crate) fn reaped(tid: u64, wait: Duration) -> io::Result<()> {
        relay::reaped(tid, wait)
    }

    /// The bytes all overflows hold now (the split test: Firecracker's relay
    /// runs again after it).
    #[cfg(test)]
    pub(crate) fn queued() -> usize {
        let total = AtomicUsize::new(0);
        relay::each(Instant::now() + DRAIN_STALL, |fifo| {
            total.fetch_add(fifo.queued.load(Ordering::Acquire), Ordering::Relaxed);
        });
        total.into_inner()
    }

    /// The end by `SIGTERM`, `SIGINT` or `SIGQUIT`. Upstream handles none of
    /// them, so each ends Firecracker at once (signal(7): their default
    /// action), and on Linux what it wrote is in the FIFO for a reader that
    /// holds it. Here the overflow is Firecracker's own memory: a handler
    /// moves it into the FIFO as the orderly ends do ([`super::drain`]) and
    /// then ends Firecracker by the same signal at its default action, so
    /// its parent's `wait` reads what Linux's does (ended by that signal;
    /// `SIGQUIT` with its core, where cores are on).
    ///
    /// Installed at the first FIFO's open and only over the default action:
    /// a signal that is ignored stays ignored (nohup(1); a shell's
    /// background job; the jail's stand-in for a PID namespace,
    /// `ext::jail::DROPPED_IN_PID_NS`), as on Linux, and without a FIFO
    /// nothing is installed.
    mod end {
        use super::*;

        pub(super) const SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT];
        /// The signal that came while its thread held an overflow's lock
        /// (inside a write) or the list's: that thread's drain would skip
        /// the FIFO it was writing to, so the end waits for the lock's
        /// release ([`deferred`]), a few instructions on. 0: none.
        static DEFERRED: AtomicI32 = AtomicI32::new(0);
        /// The signal Firecracker is ending by; 0 before. A second one
        /// that reaches another thread meanwhile leaves the first to end
        /// it, as on Linux the first ends it.
        static ENDING: AtomicI32 = AtomicI32::new(0);
        /// The signals [`install`] put its handler on, a bit each.
        static INSTALLED: AtomicU64 = AtomicU64::new(0);
        /// The calling thread's signal mask before [`hold`] (macOS's
        /// `sigset_t` is 32 bits); `NOT_HELD` otherwise.
        static HELD: AtomicU64 = AtomicU64::new(NOT_HELD);
        const NOT_HELD: u64 = u64::MAX;

        /// Blocks the three signals on the calling thread, the only one
        /// (a fork is next), until [`release`].
        pub(super) fn hold() {
            // SAFETY: a set of three valid signals, and the old mask written.
            unsafe {
                let mut set: libc::sigset_t = 0;
                for sig in SIGNALS {
                    libc::sigaddset(&mut set, sig);
                }
                let mut old: libc::sigset_t = 0;
                if libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) == 0 {
                    // A second hold without a release keeps the first's mask.
                    let _ = HELD.compare_exchange(NOT_HELD, u64::from(old), Ordering::AcqRel, Ordering::Acquire);
                }
            }
        }

        /// The mask [`hold`] found, again: a signal that waited is taken
        /// now, by the handler in Firecracker and by its default action in
        /// the child.
        pub(super) fn release() {
            let old = HELD.swap(NOT_HELD, Ordering::AcqRel);
            if let Ok(old) = libc::sigset_t::try_from(old) {
                // SAFETY: a mask this thread had.
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
            }
        }

        pub(super) fn install() -> io::Result<()> {
            for sig in SIGNALS {
                // SAFETY: zeroed sigactions, read and then written for a
                // signal number of the list; the handler is async-signal-safe.
                unsafe {
                    let mut old: libc::sigaction = std::mem::zeroed();
                    if libc::sigaction(sig, std::ptr::null(), &mut old) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if old.sa_sigaction != libc::SIG_DFL {
                        continue;
                    }
                    let mut act: libc::sigaction = std::mem::zeroed();
                    act.sa_sigaction = on_signal as *const () as usize;
                    // A handler that returns (the end deferred, or left to
                    // an earlier signal's) disturbs no system call.
                    act.sa_flags = libc::SA_RESTART;
                    // The three block one another, and nothing else: not
                    // SIGSYS, which the first thread keeps taking
                    // (`ext::sandbox`).
                    for other in SIGNALS {
                        libc::sigaddset(&mut act.sa_mask, other);
                    }
                    if libc::sigaction(sig, &act, std::ptr::null_mut()) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    INSTALLED.fetch_or(1 << sig, Ordering::AcqRel);
                }
            }
            Ok(())
        }

        /// In a fork's child (the API process): the default action again
        /// for the signals [`install`] took. The child has none of
        /// Firecracker's bytes to move ([`relay::forget_in_child`]), and
        /// its sandbox is not Firecracker's: a signal ends it at once, as
        /// before.
        pub(super) fn default_in_child() {
            let installed = INSTALLED.swap(0, Ordering::AcqRel);
            for sig in SIGNALS {
                if installed & (1 << sig) != 0 {
                    // SAFETY: a zeroed sigaction with the default action.
                    unsafe {
                        let mut act: libc::sigaction = std::mem::zeroed();
                        act.sa_sigaction = libc::SIG_DFL;
                        libc::sigaction(sig, &act, std::ptr::null_mut());
                    }
                }
            }
        }

        extern "C" fn on_signal(sig: libc::c_int) {
            // SAFETY: this thread's errno, kept for the code interrupted.
            let saved = unsafe { *libc::__error() };
            if relay::held_by_this_thread(Instant::now() + DRAIN_STALL) {
                DEFERRED.store(sig, Ordering::Release);
            } else {
                finish(sig);
            }
            // SAFETY: as above.
            unsafe { *libc::__error() = saved };
        }

        /// Called at every release of a lock: ends Firecracker by the
        /// signal that waited for it.
        pub(super) fn deferred() {
            // While this thread holds another lock still, the end waits
            // for that one's release.
            if DEFERRED.load(Ordering::Acquire) != 0 && !relay::held_by_this_thread(Instant::now() + DRAIN_STALL) {
                let sig = DEFERRED.swap(0, Ordering::AcqRel);
                if sig != 0 {
                    finish(sig);
                }
            }
        }

        /// Drains, then ends the process by `sig` at its default action.
        /// Async-signal-safe: the drain, `sigaction`, `pthread_sigmask`,
        /// `pthread_kill`.
        fn finish(sig: libc::c_int) {
            if ENDING.compare_exchange(0, sig, Ordering::AcqRel, Ordering::Acquire).is_err() {
                return;
            }
            super::drain();
            // SAFETY: the default action for `sig`, unblocked on this
            // thread (it is blocked inside its handler, and on the relay's
            // thread always), then `sig` to this thread: the kernel ends
            // the process by it before `raise` returns.
            unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                act.sa_sigaction = libc::SIG_DFL;
                libc::sigaction(sig, &act, std::ptr::null_mut());
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, sig);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
                libc::raise(sig);
            }
        }
    }

    /// The thread that moves overflows into their FIFOs.
    mod relay {
        use super::*;
        use std::sync::Mutex;
        use std::thread::JoinHandle;

        struct Relay {
            /// The open FIFOs. An owner lock: a signal handler's drain on a
            /// thread interrupted while registering one skips the list.
            ///
            /// The list holds a strong reference to each, which only
            /// [`unregister`] (an `OutFile`'s drop) takes out, under this
            /// lock. So a signal handler, which reaches a FIFO only through
            /// [`each`] or [`held_by_this_thread`] while it holds the lock
            /// and only borrows it there, never owns the last reference: a
            /// FIFO's memory is freed (its `Drop`, the drain and `free`) by
            /// the thread that drops its `OutFile` or by the relay thread,
            /// never in a signal handler, where `free` is not
            /// async-signal-safe (`test_a_fifo_is_freed_by_its_owner_not_a_handler`).
            fifos: OwnerLock<Vec<Arc<Fifo>>>,
            /// The wake pipe, written by a write that queued bytes; -1 in
            /// a fork's child, which has no relay.
            wake_r: AtomicI32,
            wake_w: AtomicI32,
            /// The relay thread, while it runs.
            thread: Mutex<Option<JoinHandle<()>>>,
            /// The kernel's id of the relay thread (`thread_id`, unique
            /// while the host is up), which the thread writes as it
            /// starts; 0 before that.
            tid: AtomicU64,
        }

        /// How long [`stop`] waits for the kernel to take the relay's
        /// thread, joined, off the process's list of threads.
        const REAP: Duration = Duration::from_secs(10);
        /// proc_info(2)'s flavor that lists a process's thread ids, one
        /// `uint64_t` each (xnu bsd/sys/proc_info_private.h, 28 in
        /// xnu-11215.1.10, macOS 15.0, through xnu-12377.121.6, macOS 26;
        /// the header is xnu's private one, which the SDK does not carry:
        /// its `sys/proc_info.h` has only `PROC_PIDLISTTHREADS`, 6, whose
        /// entries are not thread ids). A kernel without the flavor fails
        /// the call, and the split with it.
        const PROC_PIDLISTTHREADIDS: libc::c_int = 28;

        static RELAY: OnceLock<Relay> = OnceLock::new();
        /// The relay ends at its next pass ([`stop`]).
        static STOP: AtomicBool = AtomicBool::new(false);

        /// The relay moves nothing (tests of what the drain alone moves).
        #[cfg(test)]
        pub(super) static PAUSED: AtomicBool = AtomicBool::new(false);

        extern "C" fn at_exit() {
            super::drain();
        }

        fn start() -> io::Result<&'static Relay> {
            if let Some(r) = RELAY.get() {
                return Ok(r);
            }
            let mut fds = [0; 2];
            // SAFETY: two descriptors written.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: just made, owned here.
            let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            for fd in [&r, &w] {
                // SAFETY: fcntl on descriptors we own.
                unsafe {
                    if libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) < 0
                        || libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
            let mut fresh = false;
            let relay = RELAY.get_or_init(|| {
                fresh = true;
                Relay {
                    fifos: OwnerLock::new(Vec::new()),
                    wake_r: AtomicI32::new(r.into_raw_fd()),
                    wake_w: AtomicI32::new(w.into_raw_fd()),
                    thread: Mutex::new(None),
                    tid: AtomicU64::new(0),
                }
            });
            if fresh {
                spawn(relay)?;
                // SAFETY: a plain extern "C" fn.
                if unsafe { libc::atexit(at_exit) } != 0 {
                    return Err(io::Error::other("atexit refused the FIFO drain"));
                }
                super::end::install()?;
            }
            Ok(relay)
        }

        fn spawn(relay: &'static Relay) -> io::Result<()> {
            let mut thread = relay.thread.lock().unwrap();
            if thread.is_none() {
                STOP.store(false, Ordering::Release);
                relay.tid.store(0, Ordering::Release);
                *thread = Some(std::thread::Builder::new().name("fc_fifo".into()).spawn(move || run(relay))?);
            }
            Ok(())
        }

        pub(super) fn register(fifo: &Arc<Fifo>) -> io::Result<()> {
            let relay = start()?;
            let mut list = relay.fifos.lock().expect("not registering from a signal handler");
            list.push(Arc::clone(fifo));
            Ok(())
        }

        /// Takes `fifo` off the list, under its lock, so that the caller's
        /// reference is the last but the relay's for a pass in progress
        /// (an `OutFile`'s drop; never in a signal handler). A handler that
        /// holds the lock meanwhile, on another thread, is waited for: its
        /// use of the FIFO ends before the FIFO can be freed.
        pub(super) fn unregister(fifo: &Arc<Fifo>) {
            let Some(relay) = RELAY.get() else { return };
            // `None`: this thread holds the list already (a drop inside
            // `each`'s callback, which only borrows: not done): the FIFO
            // stays registered rather than be freed under its borrower.
            if let Some(mut list) = relay.fifos.lock() {
                list.retain(|f| !Arc::ptr_eq(f, fifo));
            }
        }

        /// Ends the relay thread, if it runs, and waits for it: for its
        /// join, and then until the kernel lists its thread no more.
        ///
        /// The join alone is not the thread's end to the kernel. An exiting
        /// thread wakes its joiner before it asks the kernel to end it
        /// (libpthread src/pthread.c `_pthread_terminate`:
        /// `_pthread_joiner_wake`, then `__bsdthread_terminate`), and the
        /// kernel takes an ended thread off its task's list, and out of
        /// `thread_count`, later still, on its reaper thread (xnu
        /// osfmk/kern/thread.c `thread_terminate_queue_invoke`). Until
        /// then proc_info(2)'s `pti_threadnum` (`thread_count`,
        /// osfmk/kern/bsd_kern.c `fill_taskprocinfo`) counts it, and
        /// `ext::api_process::fork`, which reads that, refuses the fork
        /// ("Firecracker has 2 threads").
        pub(super) fn stop() -> io::Result<()> {
            let Some(relay) = RELAY.get() else { return Ok(()) };
            let thread = relay.thread.lock().unwrap().take();
            let Some(thread) = thread else { return Ok(()) };
            STOP.store(true, Ordering::Release);
            wake();
            // A relay that panicked has ended too (and the panic aborts
            // Firecracker: panic = "abort").
            let _ = thread.join();
            // Written by the thread before anything else, so before its end.
            match relay.tid.load(Ordering::Acquire) {
                0 => Err(io::Error::other("the FIFO relay's thread ended without its kernel thread id")),
                tid => reaped(tid, REAP),
            }
        }

        /// Waits until the kernel lists thread `tid`, which has been
        /// joined, among this process's threads no more.
        ///
        /// It reads the list `thread_count` counts (`task->threads`; the
        /// reaper takes a thread off the one and out of the other under one
        /// hold of the task's lock, and both readings take that lock), by
        /// the thread's id, which names no later thread. It ends: a joined
        /// thread runs none of Firecracker's code and waits for nothing of
        /// Firecracker's any more, only the rest of `_pthread_terminate`
        /// into `__bsdthread_terminate`, and the kernel reaps it whatever
        /// this thread does; this thread yields the processor between two
        /// readings. A thread still listed after `wait` ([`REAP`]) is an
        /// error, not waited for longer.
        pub(super) fn reaped(tid: u64, wait: Duration) -> io::Result<()> {
            let deadline = Instant::now() + wait;
            while thread_ids()?.contains(&tid) {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "the FIFO relay's thread (id {tid}) was joined, and the kernel still lists it among this \
                         process's threads {} ms later",
                        wait.as_millis()
                    )));
                }
                std::thread::yield_now();
            }
            Ok(())
        }

        /// The kernel's ids of this process's threads (proc_info(2)
        /// `PROC_PIDLISTTHREADIDS`: xnu bsd/kern/proc_info.c
        /// `proc_pidlistthreads`, osfmk/kern/bsd_kern.c
        /// `fill_taskthreadlist`, which walks `task->threads` under the
        /// task's lock). The same system call, on this process, as
        /// `ext::api_process`'s count, which both sandbox profiles allow
        /// (`process-info*` with `(target self)`).
        fn thread_ids() -> io::Result<Vec<u64>> {
            let mut ids = vec![0u64; 64];
            loop {
                let size = libc::c_int::try_from(std::mem::size_of_val(ids.as_slice())).map_err(io::Error::other)?;
                // SAFETY: a valid output buffer of the size passed.
                let got = unsafe {
                    libc::proc_pidinfo(libc::getpid(), PROC_PIDLISTTHREADIDS, 0, ids.as_mut_ptr().cast(), size)
                };
                if got <= 0 {
                    // A process has a thread: 0 bytes is the call's failure.
                    return Err(io::Error::last_os_error());
                }
                if got < size {
                    ids.truncate(usize::try_from(got).map_err(io::Error::other)? / std::mem::size_of::<u64>());
                    return Ok(ids);
                }
                // A full buffer may be a list cut short.
                ids.resize(ids.len() * 2, 0);
            }
        }

        /// Starts the relay thread again after [`stop`].
        pub(super) fn restart() -> io::Result<()> {
            match RELAY.get() {
                Some(relay) if relay.wake_r.load(Ordering::Acquire) >= 0 => spawn(relay),
                _ => Ok(()),
            }
        }

        /// In a fork's child: the overflows' copies emptied, and the
        /// parent's wake pipe closed here (no relay reads it in this
        /// process; the parent's relay must not be woken by it).
        pub(super) fn forget_in_child() {
            let Some(relay) = RELAY.get() else { return };
            each(Instant::now() + DRAIN_STALL, |fifo| {
                if let Some(mut ring) = fifo.ring.lock() {
                    ring.clear();
                    fifo.queued.store(0, Ordering::Release);
                }
            });
            for fd in [&relay.wake_r, &relay.wake_w] {
                let fd = fd.swap(-1, Ordering::AcqRel);
                if fd >= 0 {
                    // SAFETY: this process's copy of the wake pipe's end.
                    unsafe { libc::close(fd) };
                }
            }
            // The copy of the parent's handle names a thread that is not
            // in this process.
            std::mem::forget(relay.thread.lock().unwrap().take());
        }

        /// Runs `f` on each open FIFO, without allocating (a signal
        /// handler's drain). Each FIFO is borrowed from the list while its
        /// lock is held, never cloned: the list's reference outlives the
        /// call ([`Relay::fifos`]).
        pub(super) fn each(until: Instant, f: impl Fn(&Fifo)) {
            if let Some(list) = RELAY.get().and_then(|r| r.fifos.lock_until(until)) {
                for fifo in list.iter() {
                    f(fifo);
                }
            }
        }

        /// Whether the calling thread holds the list's lock or an
        /// overflow's: a signal handler's question, on a thread it may have
        /// interrupted inside a write or a registration. Allocates nothing.
        pub(super) fn held_by_this_thread(until: Instant) -> bool {
            let Some(relay) = RELAY.get() else { return false };
            if relay.fifos.mine() {
                return true;
            }
            // Another thread's at `until` still: not this thread's.
            let Some(list) = relay.fifos.lock_until(until) else { return false };
            let held = list.iter().any(|fifo| fifo.ring.mine());
            // Released without the look for a deferred end, which asks this.
            list.release_quietly();
            held
        }

        pub(super) fn wake() {
            if let Some(r) = RELAY.get() {
                // A full pipe is a wake already pending; -1 (a fork's
                // child) fails, and none is needed.
                let _ = raw_write(r.wake_w.load(Ordering::Acquire), &[1]);
            }
        }

        /// The relay's signal mask: the signals a fault raises on the
        /// faulting thread reach upstream's handlers here as on any thread
        /// (SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP; SIGABRT for a panic's
        /// abort). Every other signal is blocked, so that one sent to the
        /// process (upstream's SIGXCPU, SIGHUP, the sandbox's SIGSYS: xnu
        /// bsd/kern/kern_sig.c `get_signalthread` takes the first thread
        /// that does not block it) runs its handler on a thread of
        /// Firecracker's own, not on this one while it holds an overflow's
        /// lock, where the handler's drain would skip that FIFO. The vCPU
        /// kick is sent to vCPU threads only (`pthread_kill`, vcpu.rs).
        fn set_mask() {
            // SAFETY: a set built here, applied to this thread.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigfillset(&mut set);
                for sig in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE, libc::SIGTRAP, libc::SIGABRT] {
                    libc::sigdelset(&mut set, sig);
                }
                libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
            }
        }

        fn run(relay: &'static Relay) {
            let mut tid = 0u64;
            // SAFETY: 0 names the calling thread; `tid` is written.
            if unsafe { libc::pthread_threadid_np(0, &mut tid) } != 0 {
                tid = 0;
            }
            relay.tid.store(tid, Ordering::Release);
            set_mask();
            let mut buf = [0u8; 64];
            loop {
                if STOP.load(Ordering::Acquire) {
                    return;
                }
                #[cfg(test)]
                if PAUSED.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                let wake_r = relay.wake_r.load(Ordering::Acquire);
                let fifos: Vec<Arc<Fifo>> = relay
                    .fifos
                    .lock()
                    .expect("this thread takes no signal that writes")
                    .iter()
                    .filter(|f| f.queued.load(Ordering::Acquire) > 0 && !f.broken.load(Ordering::Acquire))
                    .cloned()
                    .collect();
                let mut fds = vec![libc::pollfd { fd: wake_r, events: libc::POLLIN, revents: 0 }];
                fds.extend(fifos.iter().map(|f| libc::pollfd { fd: f.w.as_raw_fd(), events: libc::POLLOUT, revents: 0 }));
                // SAFETY: `fds` is valid for its length.
                if unsafe { libc::poll(fds.as_mut_ptr(), libc::nfds_t::try_from(fds.len()).unwrap_or(libc::nfds_t::MAX), -1) } < 0 {
                    continue;
                }
                if fds[0].revents != 0 {
                    // SAFETY: reading into our buffer.
                    while unsafe { libc::read(wake_r, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
                }
                for (f, p) in fifos.iter().zip(&fds[1..]) {
                    if p.revents != 0 {
                        f.relay_once();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(unix)]
pub(crate) mod tests {
    use std::io::{ErrorKind, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use crate::utils::open_file_nonblock;

    /// Line `i`: 100 bytes, its number first, so order, loss and
    /// duplication show.
    pub(crate) fn line(i: usize) -> Vec<u8> {
        format!("{i:099}\n").into_bytes()
    }

    pub(crate) fn lines(range: std::ops::Range<usize>) -> Vec<u8> {
        range.flat_map(line).collect()
    }

    /// A new FIFO in a directory of its own.
    pub(crate) fn fifo(name: &str) -> (vmm_sys_util::tempdir::TempDir, PathBuf) {
        let dir = vmm_sys_util::tempdir::TempDir::new_with_prefix("/tmp/wick-fifo-").unwrap();
        let path = dir.as_path().join(name);
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "{}", std::io::Error::last_os_error());
        (dir, path)
    }

    /// A reader of `path` that does not block (it opens at once: Firecracker
    /// holds the FIFO, or no writer is needed for a non-blocking reader).
    pub(crate) fn reader(path: &Path) -> OwnedFd {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: just opened, owned here.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    /// Reads `n` bytes from `fd`, or fails after 10 s.
    pub(crate) fn read_exactly(fd: &OwnedFd, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        let mut got = 0;
        let deadline = Instant::now() + Duration::from_secs(10);
        while got < n {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "{got} of {n} bytes in 10 s");
            let mut p = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: one pollfd.
            unsafe { libc::poll(&mut p, 1, libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX)) };
            // SAFETY: reading into our buffer.
            let r = unsafe { libc::read(fd.as_raw_fd(), out[got..].as_mut_ptr().cast(), n - got) };
            if r > 0 {
                got += r.cast_unsigned();
            }
        }
        out
    }

    /// Everything `fd` has now, without waiting.
    fn read_available(fd: &OwnedFd) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            // SAFETY: reading into our buffer.
            let r = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                return out;
            }
            out.extend_from_slice(&buf[..r.cast_unsigned()]);
        }
    }

    /// Writes `buf` until the first error; the bytes taken and the error.
    fn fill(out: &mut super::OutFile, buf: &[u8]) -> (usize, std::io::Error) {
        let mut taken = 0;
        loop {
            match out.write(buf) {
                Ok(n) => {
                    assert_eq!(n, buf.len(), "a {}-byte write is taken whole or refused (PIPE_BUF)", buf.len());
                    taken += n;
                }
                Err(e) => return (taken, e),
            }
            assert!(taken <= 2 * 65536, "{taken} bytes taken with no reader and no error");
        }
    }

    /// The relay moved what it can (macOS); nothing to wait for on Linux.
    fn settled(out: &super::OutFile) {
        #[cfg(target_os = "macos")]
        out.settled();
        #[cfg(not(target_os = "macos"))]
        let _ = out;
    }

    /// The FIFO's own buffer on macOS (`net.local.stream.sendspace`).
    #[cfg(target_os = "macos")]
    fn fifo_buffer() -> usize {
        let out = Command::new("/usr/sbin/sysctl").args(["-n", "net.local.stream.sendspace"]).output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().parse().unwrap()
    }

    // A FIFO nobody reads takes pipe(7)'s 65536 at most, then the would-block
    // error (EAGAIN), as on Linux.
    #[test]
    fn test_a_fifo_nobody_reads_takes_linuxs_capacity() {
        let (_dir, path) = fifo("lines");
        let mut out = open_file_nonblock(&path).unwrap();
        let (taken, err) = fill(&mut out, &line(0));
        assert_eq!(err.kind(), ErrorKind::WouldBlock, "{err}");
        // Linux's count depends on the write pattern: fs/pipe.c pipe_write
        // adds a write to the last page only when it fits there, so 100-byte
        // writes fill each 4096-byte page with 40 (4000 bytes), and the 16
        // pages (65536) take 64000. macOS: the FIFO's own buffer takes 81
        // (its socket takes a write that fits, 8192 // 100) and the overflow
        // 573 (57344 // 100): 65400. Either is pipe(7)'s 65536 or less.
        assert!((64000..=65536).contains(&taken), "{taken} bytes before the would-block error");
        #[cfg(target_os = "linux")]
        assert_eq!(taken, 64000);
        // 4096-byte writes take exactly 65536 on both: on Linux each takes a
        // page of its own (no room in the last), 16 pages; on macOS the FIFO
        // takes two (8192, measured) and the overflow, 65536 less that, 14.
        let (_dir, path) = fifo("pages");
        let mut out = open_file_nonblock(&path).unwrap();
        let (taken, err) = fill(&mut out, &[b'p'; 4096]);
        assert_eq!((taken, err.kind()), (65536, ErrorKind::WouldBlock));
    }

    // A reader that opens later gets every line in order, once each; then
    // writes go on.
    #[test]
    fn test_a_late_reader_gets_every_line_in_order() {
        let (_dir, path) = fifo("late");
        let mut out = open_file_nonblock(&path).unwrap();
        // 30000 bytes: more than the macOS FIFO's own 8192, less than
        // Linux's 64000 for this pattern.
        for i in 0..300 {
            out.write_all(&line(i)).unwrap();
        }
        let r = reader(&path);
        assert!(read_exactly(&r, 30000) == lines(0..300), "the lines came back otherwise");
        out.write_all(&line(9999)).unwrap();
        assert_eq!(read_exactly(&r, 100), line(9999));
    }

    // A write of at most 4096 bytes (PIPE_BUF) is taken whole or refused; a
    // longer one takes what fits.
    #[test]
    fn test_a_small_write_is_all_or_nothing() {
        let (_dir, path) = fifo("atomic");
        let mut out = open_file_nonblock(&path).unwrap();
        let r = reader(&path);
        fill(&mut out, &line(0));
        // Full: 3000 bytes do not fit (Linux: no free page, and 3000 do not
        // fit the last page's 96 free bytes; macOS: the overflow is full).
        assert_eq!(out.write(&[b'a'; 3000]).unwrap_err().kind(), ErrorKind::WouldBlock);
        // The reader takes 5000: Linux frees one page (the first 4000 bytes'),
        // macOS 5000 bytes of its FIFO, which the relay fills from the
        // overflow, freeing about that much there.
        read_exactly(&r, 5000);
        settled(&out);
        // 9000 bytes: more than fits, taken in part (Linux: the free page,
        // 4096; macOS: the overflow's free bytes, 5000 less what the FIFO
        // kept under its 512-byte low-water mark).
        let n = out.write(&[b'b'; 9000]).unwrap();
        assert!(0 < n && n < 9000, "{n} of a 9000-byte write");
        #[cfg(target_os = "linux")]
        assert_eq!(n, 4096);
        // Full again: a 3000-byte write is refused whole, nothing written.
        assert_eq!(out.write(&[b'a'; 3000]).unwrap_err().kind(), ErrorKind::WouldBlock);
        let rest = read_available(&r);
        assert!(!rest.contains(&b'a'), "a refused write left bytes");
    }

    // A path that is no FIFO is written directly, as upstream does.
    #[test]
    fn test_a_regular_file_is_written_directly() {
        let dir = vmm_sys_util::tempdir::TempDir::new_with_prefix("/tmp/wick-fifo-").unwrap();
        let path = dir.as_path().join("log.txt");
        let mut out = open_file_nonblock(&path).unwrap();
        out.write_all(&line(1)).unwrap();
        drop(out);
        assert_eq!(std::fs::read(&path).unwrap(), line(1));
    }

    /// Runs the ignored child test `name` with `path`; returns its output.
    fn child(name: &str, path: &Path) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("ext::fifo::tests::{name}"), "--ignored", "--nocapture", "--test-threads", "1"])
            .env("WICK_FIFO_TEST_PATH", path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn child_path() -> PathBuf {
        PathBuf::from(std::env::var_os("WICK_FIFO_TEST_PATH").expect("run by its parent test"))
    }

    /// The child's end, at most 30 s away; a child still running then is
    /// killed (a deadlock fails the test, never hangs it).
    fn wait_child(c: &mut std::process::Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = c.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                c.kill().unwrap();
                c.wait().unwrap();
                panic!("the child did not end in 30 s");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // A relay thread the kernel still lists when the wait is over is an
    // error that says so (here a thread that has not ended: this one), and
    // a thread id the kernel does not list is no wait.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_a_relay_thread_the_kernel_still_lists_is_an_error() {
        let mut tid = 0u64;
        // SAFETY: 0 names the calling thread; `tid` is written.
        assert_eq!(unsafe { libc::pthread_threadid_np(0, &mut tid) }, 0);
        let start = Instant::now();
        let err = super::macos::reaped(tid, Duration::from_millis(50)).unwrap_err();
        assert!(start.elapsed() >= Duration::from_millis(50), "{:?}", start.elapsed());
        assert_eq!(
            err.to_string(),
            format!(
                "the FIFO relay's thread (id {tid}) was joined, and the kernel still lists it among this process's \
                 threads 50 ms later"
            )
        );
        // Thread ids start above 0 and u64::MAX is none.
        super::macos::reaped(u64::MAX, Duration::ZERO).unwrap();
    }

    /// How often [`relay_stop_child`] stops the relay.
    #[cfg(target_os = "macos")]
    const RELAY_STOPS: usize = 1000;

    // When `before_fork` returns, the kernel counts the relay's thread no
    // more: `ext::api_process::split` forks only from a process of one
    // thread, by the kernel's count, and `pthread_join` returns before the
    // joined thread's kernel thread has gone (libpthread pthread.c
    // `_pthread_terminate`: `_pthread_joiner_wake` before
    // `__bsdthread_terminate`).
    #[cfg(target_os = "macos")]
    #[test]
    fn test_the_relay_stopped_for_a_fork_is_gone_from_the_kernels_count() {
        use std::io::Read;
        let (_dir, path) = fifo("log");
        let mut c = child("relay_stop_child", &path);
        let status = wait_child(&mut c);
        let mut out = String::new();
        c.stdout.take().unwrap().read_to_string(&mut out).unwrap();
        assert!(
            status.success() && out.contains(&format!("RELAY-STOP more-than-one-thread 0 of {RELAY_STOPS}\n")),
            "{status:?}\n{out}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_the_relay_stopped_for_a_fork_is_gone_from_the_kernels_count"]
    fn relay_stop_child() {
        use crate::ext::api_process::threads;
        // In a fork, whose only thread is this one, as Firecracker's main
        // thread at the split.
        // SAFETY: the fork runs the test and ends; this process waits for
        // it and ends as it ended.
        match unsafe { libc::fork() } {
            0 => {}
            // SAFETY: the fork's pid; ends this process as it ended.
            pid => unsafe {
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
                if libc::WIFEXITED(status) {
                    libc::_exit(libc::WEXITSTATUS(status));
                }
                libc::_exit(128 + libc::WTERMSIG(status));
            },
        }
        assert_eq!(threads().unwrap(), 1, "the fork has one thread");
        // The first FIFO's open starts the relay.
        let _out = open_file_nonblock(&child_path()).unwrap();
        let mut more = 0;
        for round in 0..RELAY_STOPS {
            assert_eq!(threads().unwrap(), 2, "round {round}: the relay runs");
            super::before_fork().unwrap();
            // What `ext::api_process::fork` reads, and refuses the fork by.
            if threads().unwrap() != 1 {
                more += 1;
            }
            super::after_fork(false).unwrap();
        }
        println!("RELAY-STOP more-than-one-thread {more} of {RELAY_STOPS}");
        std::io::stdout().flush().unwrap();
        // SAFETY: ends the fork.
        unsafe { libc::_exit(0) }
    }

    // A line written while the FIFO has room is in it when the write
    // returns: a child that writes one and is killed at once leaves it for
    // the reader, as on Linux.
    #[test]
    fn test_a_line_is_in_the_readers_pipe_when_the_write_returns() {
        let (_dir, path) = fifo("killed");
        let r = reader(&path);
        let status = wait_child(&mut child("child_writes_a_line_then_dies", &path));
        assert!(!status.success(), "{status}");
        assert_eq!(read_exactly(&r, 100), line(7));
    }

    #[test]
    #[ignore = "run by test_a_line_is_in_the_readers_pipe_when_the_write_returns"]
    fn child_writes_a_line_then_dies() {
        let mut out = open_file_nonblock(&child_path()).unwrap();
        out.write_all(&line(7)).unwrap();
        // SAFETY: ends this process at once.
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    }

    // Lines written while a reader drains the FIFO, through full and empty
    // spells, arrive in order, once each.
    #[test]
    fn test_order_is_kept_across_a_full_pipe() {
        let (_dir, path) = fifo("order");
        let r = reader(&path);
        let mut out = open_file_nonblock(&path).unwrap();
        const N: usize = 3000;
        let reading = std::thread::spawn(move || {
            let mut got = Vec::new();
            while got.len() < N * 100 {
                let chunk = read_exactly(&r, 1000);
                got.extend_from_slice(&chunk);
                std::thread::sleep(Duration::from_micros(200));
            }
            got
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        for i in 0..N {
            loop {
                match out.write(&line(i)) {
                    Ok(n) => {
                        assert_eq!(n, 100);
                        break;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "stuck at line {i}");
                        std::thread::sleep(Duration::from_micros(100));
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        }
        assert!(reading.join().unwrap() == lines(0..N), "the lines came back otherwise");
    }

    // What waits beyond the FIFO reaches its reader with no further write.
    #[test]
    fn test_the_overflow_reaches_the_reader_without_another_write() {
        let (_dir, path) = fifo("overflow");
        let r = reader(&path);
        let mut out = open_file_nonblock(&path).unwrap();
        for i in 0..300 {
            out.write_all(&line(i)).unwrap();
        }
        assert!(read_exactly(&r, 30000) == lines(0..300), "the lines came back otherwise");
    }

    // An orderly end (exit) gives a reader that reads everything written,
    // the overflow included (the drain; Linux: the FIFO holds it all).
    #[test]
    fn test_an_orderly_exit_drains_the_overflow_to_a_reader() {
        let (_dir, path) = fifo("exit");
        let r = reader(&path);
        let mut c = child("child_writes_then_exits", &path);
        let mut out = out_lines(&mut c);
        until(&mut out, "WICK-WRITTEN");
        assert!(read_exactly(&r, 30000) == lines(0..300), "the lines came back otherwise");
        assert!(wait_child(out.child).success());
    }

    #[test]
    #[ignore = "run by test_an_orderly_exit_drains_the_overflow_to_a_reader"]
    fn child_writes_then_exits() {
        let mut out = open_file_nonblock(&child_path()).unwrap();
        for i in 0..300 {
            out.write_all(&line(i)).unwrap();
        }
        // macOS: the relay stopped, so that only the drain can move the
        // overflow (the reader has read nothing: the FIFO's 8100 bytes are
        // in it, the rest in the overflow).
        #[cfg(target_os = "macos")]
        assert_eq!(out.pause_relay(), 30000 - fifo_buffer() / 100 * 100);
        println!("WICK-WRITTEN");
        std::io::stdout().flush().unwrap();
        #[cfg(target_os = "macos")]
        out.wait_reader();
        // exit(3): its atexit handlers run (the drain).
        // SAFETY: ends this process.
        unsafe { libc::exit(0) };
    }

    // An abrupt end (SIGKILL) loses only what Firecracker held beyond the
    // FIFO's own buffer; Linux loses nothing while the reader holds it.
    #[test]
    fn test_an_abrupt_end_loses_only_the_overflow() {
        let (_dir, path) = fifo("abrupt");
        let r = reader(&path);
        let mut c = child("child_writes_then_dies", &path);
        let mut out = out_lines(&mut c);
        until(&mut out, "WICK-WRITTEN");
        assert!(!wait_child(out.child).success());
        let got = read_available(&r);
        // Linux: all 300 lines are in the FIFO. macOS: the lines the FIFO's
        // own buffer took (a write that fits it, so its size // 100), the
        // first ones, in order; the rest were in the overflow.
        #[cfg(target_os = "linux")]
        let kept = 300;
        #[cfg(target_os = "macos")]
        let kept = fifo_buffer() / 100;
        assert!(got == lines(0..kept), "{} bytes kept, {kept} lines expected", got.len());
    }

    #[test]
    #[ignore = "run by test_an_abrupt_end_loses_only_the_overflow"]
    fn child_writes_then_dies() {
        let mut out = open_file_nonblock(&child_path()).unwrap();
        for i in 0..300 {
            out.write_all(&line(i)).unwrap();
        }
        println!("WICK-WRITTEN");
        std::io::stdout().flush().unwrap();
        // SAFETY: ends this process at once.
        unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    }

    /// The default action for the three signals, whatever this process
    /// inherited (a shell's background job ignores SIGINT and SIGQUIT).
    fn default_ending_signals() {
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT] {
            // SAFETY: the default action for a signal of the list.
            unsafe { libc::signal(sig, libc::SIG_DFL) };
        }
    }

    // SIGTERM, SIGINT and SIGQUIT, which upstream leaves at their default
    // action, end Firecracker by the signal, and a reader that holds the
    // FIFO reads everything written: on Linux it is all in the FIFO; on
    // macOS a handler moves the overflow into it first, then ends the
    // process by the same signal (the wait status is the signal's).
    #[test]
    fn test_a_terminating_signal_leaves_the_reader_every_line() {
        use std::os::unix::process::ExitStatusExt;
        for (name, sig) in [("term", libc::SIGTERM), ("int", libc::SIGINT), ("quit", libc::SIGQUIT)] {
            let (_dir, path) = fifo(name);
            let r = reader(&path);
            let mut c = child("child_writes_then_waits_for_a_signal", &path);
            let mut out = out_lines(&mut c);
            until(&mut out, "WICK-WRITTEN");
            // SAFETY: the child's pid.
            assert_eq!(unsafe { libc::kill(out.child.id().cast_signed(), sig) }, 0);
            assert!(read_exactly(&r, 30000) == lines(0..300), "{name}: the lines came back otherwise");
            assert_eq!(wait_child(out.child).signal(), Some(sig), "{name}");
        }
    }

    #[test]
    #[ignore = "run by test_a_terminating_signal_leaves_the_reader_every_line"]
    fn child_writes_then_waits_for_a_signal() {
        default_ending_signals();
        let mut out = open_file_nonblock(&child_path()).unwrap();
        for i in 0..300 {
            out.write_all(&line(i)).unwrap();
        }
        #[cfg(target_os = "macos")]
        assert_eq!(out.pause_relay(), 30000 - fifo_buffer() / 100 * 100);
        println!("WICK-WRITTEN");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    // The signal comes to a thread that is inside a write to the FIFO (it
    // holds the overflow's lock, and a drain there would skip that FIFO):
    // the end waits for the write, then drains and ends by the signal.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_a_terminating_signal_inside_a_write_ends_after_the_write() {
        use std::os::unix::process::ExitStatusExt;
        let (_dir, path) = fifo("inside");
        let r = reader(&path);
        let mut c = child("child_is_signalled_inside_a_write", &path);
        let mut out = out_lines(&mut c);
        until(&mut out, "WICK-WRITTEN");
        assert!(read_exactly(&r, 30000) == lines(0..300), "the lines came back otherwise");
        until(&mut out, "WICK-STILL-INSIDE");
        assert_eq!(wait_child(out.child).signal(), Some(libc::SIGTERM));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_a_terminating_signal_inside_a_write_ends_after_the_write"]
    fn child_is_signalled_inside_a_write() {
        default_ending_signals();
        let out = child_fills();
        out.wait_reader();
        out.holding(|| {
            // SAFETY: SIGTERM to this thread, taken before raise returns.
            unsafe { libc::raise(libc::SIGTERM) };
            // The handler returned: the write goes on.
            println!("WICK-STILL-INSIDE");
            std::io::stdout().flush().unwrap();
        });
        // The lock's release ended the process.
        println!("WICK-SURVIVED");
        std::io::stdout().flush().unwrap();
    }

    // A signal that is ignored when the FIFO is opened stays ignored (nohup,
    // a background job, the jail's stand-in for a PID namespace), and the
    // API process, forked with the FIFO open, has the default action again:
    // it holds none of Firecracker's bytes, and its sandbox is its own. The
    // three are blocked from before the fork until then, so that none runs
    // the handler in the fork.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_ending_signals_keep_what_they_were_and_a_fork_gets_the_default() {
        let (_dir, path) = fifo("kept");
        let _r = reader(&path);
        let mut c = child("child_reports_its_ending_signals", &path);
        let mut out = out_lines(&mut c);
        assert_eq!(until(&mut out, "WICK-SIGNALS"), "term=ignored int=handled quit=handled fork=ignored,default,default blocked=3->0 here=0");
        assert!(wait_child(out.child).success());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_ending_signals_keep_what_they_were_and_a_fork_gets_the_default"]
    fn child_reports_its_ending_signals() {
        fn action(sig: libc::c_int) -> &'static str {
            // SAFETY: a zeroed sigaction, read for a valid signal.
            let act = unsafe {
                let mut act: libc::sigaction = std::mem::zeroed();
                libc::sigaction(sig, std::ptr::null(), &mut act);
                act.sa_sigaction
            };
            match act {
                libc::SIG_DFL => "default",
                libc::SIG_IGN => "ignored",
                _ => "handled",
            }
        }
        /// How many of the three the calling thread blocks.
        fn blocked() -> usize {
            // SAFETY: the calling thread's mask, read.
            unsafe {
                let mut set: libc::sigset_t = 0;
                libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set);
                [libc::SIGTERM, libc::SIGINT, libc::SIGQUIT].iter().filter(|s| libc::sigismember(&set, **s) == 1).count()
            }
        }
        default_ending_signals();
        // SAFETY: SIGTERM ignored, as nohup leaves SIGHUP.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
        let _out = open_file_nonblock(&child_path()).unwrap();
        let here = format!(
            "term={} int={} quit={}",
            action(libc::SIGTERM),
            action(libc::SIGINT),
            action(libc::SIGQUIT)
        );
        super::before_fork().unwrap();
        let mut fds = [0; 2];
        // SAFETY: a pipe for the fork's answer; the fork resets, reports
        // and ends.
        let forked = unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                let before = blocked();
                super::after_fork(true).unwrap();
                // SIGTERM was not this module's: it stays ignored.
                let all = format!(
                    "{},{},{} blocked={before}->{}",
                    action(libc::SIGTERM),
                    action(libc::SIGINT),
                    action(libc::SIGQUIT),
                    blocked()
                );
                libc::write(fds[1], all.as_ptr().cast(), all.len());
                libc::_exit(0);
            }
            libc::close(fds[1]);
            let mut buf = [0u8; 128];
            let n = libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len());
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            String::from_utf8_lossy(&buf[..usize::try_from(n).unwrap_or(0)]).into_owned()
        };
        super::after_fork(false).unwrap();
        let forked = format!("{forked} here={}", blocked());
        println!("WICK-SIGNALS {here} fork={forked}");
        std::io::stdout().flush().unwrap();
    }

    static HANDLER_OUT: std::sync::OnceLock<super::OutFile> = std::sync::OnceLock::new();

    extern "C" fn handler_writes(_: libc::c_int) {
        let mut out = HANDLER_OUT.get().unwrap();
        out.write_all(&line(42)).unwrap();
    }

    // A signal handler that writes (upstream's at a fatal signal) on a
    // thread interrupted inside a write goes through, never waiting for
    // itself. In a child: a handler that waited for itself would hang it.
    #[test]
    fn test_a_write_from_a_signal_handler_inside_a_write_goes_through() {
        let (_dir, path) = fifo("signal");
        let r = reader(&path);
        assert!(wait_child(&mut child("child_writes_from_a_signal_handler", &path)).success());
        assert_eq!(read_exactly(&r, 100), line(42));
    }

    #[test]
    #[ignore = "run by test_a_write_from_a_signal_handler_inside_a_write_goes_through"]
    fn child_writes_from_a_signal_handler() {
        let out = HANDLER_OUT.get_or_init(|| open_file_nonblock(&child_path()).unwrap());
        // SAFETY: a handler for SIGUSR2, which only this process raises.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler_writes as *const () as usize;
            libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
        }
        let raise = || {
            // SAFETY: delivered to this thread before raise returns.
            unsafe { libc::raise(libc::SIGUSR2) };
        };
        // As inside a write: this thread holds the overflow's lock.
        #[cfg(target_os = "macos")]
        out.holding(raise);
        #[cfg(not(target_os = "macos"))]
        {
            let _ = out;
            raise();
        }
    }

    /// A child's output lines, read by a thread of their own, and the child,
    /// killed if a marker does not come in time.
    struct ChildLines<'a> {
        child: &'a mut std::process::Child,
        lines: std::sync::mpsc::Receiver<String>,
    }

    fn out_lines(child: &mut std::process::Child) -> ChildLines<'_> {
        use std::io::BufRead;
        let out = child.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in std::io::BufReader::new(out).lines() {
                if tx.send(l.unwrap_or_default()).is_err() {
                    return;
                }
            }
        });
        ChildLines { child, lines }
    }

    /// What follows `marker` on the child's next line that has it (libtest
    /// may have printed "test <name> ... " before it on the same line),
    /// within 30 s; else the child is killed (a drain that waits for ever
    /// fails the test, never hangs it).
    fn until(c: &mut ChildLines, marker: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match c.lines.recv_timeout(left) {
                Ok(l) => {
                    if let Some(rest) = l.split(marker).nth(1) {
                        return rest.trim().to_owned();
                    }
                }
                Err(e) => {
                    let _ = c.child.kill();
                    let _ = c.child.wait();
                    panic!("the child did not print {marker} ({e:?})");
                }
            }
        }
    }

    /// The child's printed `WICK-DRAIN-US <n>`: how long its drain took.
    fn drain_took(c: &mut ChildLines) -> Duration {
        Duration::from_micros(until(c, "WICK-DRAIN-US ").parse().unwrap())
    }

    /// 300 lines into the FIFO the parent named: on macOS 81 in the FIFO,
    /// the rest in the overflow, with the relay stopped (only the drain
    /// moves them).
    fn child_fills() -> &'static super::OutFile {
        let out = HANDLER_OUT.get_or_init(|| open_file_nonblock(&child_path()).unwrap());
        let mut w = out;
        for i in 0..300 {
            w.write_all(&line(i)).unwrap();
        }
        #[cfg(target_os = "macos")]
        assert_eq!(out.pause_relay(), 30000 - fifo_buffer() / 100 * 100);
        println!("WICK-WRITTEN");
        std::io::stdout().flush().unwrap();
        out
    }

    fn on_sigusr2(handler: extern "C" fn(libc::c_int)) {
        // SAFETY: a handler for SIGUSR2, which only this process raises.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler as *const () as usize;
            libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
        }
    }

    fn raise_sigusr2() {
        // SAFETY: delivered to this thread before raise returns.
        unsafe { libc::raise(libc::SIGUSR2) };
    }

    /// Drains, prints how long that took, and ends as a fatal signal's
    /// handler ends Firecracker (forward_sigsys, exit_with_code): `_exit`.
    extern "C" fn handler_drains_then_exits(_: libc::c_int) {
        let start = Instant::now();
        super::drain();
        let took = start.elapsed().as_micros();
        // Formatting allocates: a test's report, after the drain.
        println!("WICK-DRAIN-US {took}");
        std::io::stdout().flush().unwrap();
        // SAFETY: ends the process, as the handlers do.
        unsafe { libc::_exit(148) };
    }

    // A signal handler that drains before its _exit (the sandbox's
    // forward_sigsys, upstream's exit_with_code) gives a reader that reads
    // everything written, the overflow included.
    #[test]
    fn test_a_drain_in_a_signal_handler_reaches_the_reader() {
        let (_dir, path) = fifo("handler");
        let r = reader(&path);
        let mut c = child("child_drains_in_a_signal_handler", &path);
        let mut out = out_lines(&mut c);
        until(&mut out, "WICK-WRITTEN");
        assert!(read_exactly(&r, 30000) == lines(0..300), "the lines came back otherwise");
        drain_took(&mut out);
        assert_eq!(wait_child(out.child).code(), Some(148));
    }

    #[test]
    #[ignore = "run by test_a_drain_in_a_signal_handler_reaches_the_reader"]
    fn child_drains_in_a_signal_handler() {
        let out = child_fills();
        #[cfg(target_os = "macos")]
        out.wait_reader();
        #[cfg(not(target_os = "macos"))]
        let _ = out;
        on_sigusr2(handler_drains_then_exits);
        raise_sigusr2();
    }

    // A drain in a signal handler that interrupted this thread's own write
    // returns at once: the overflow may be half updated, and the lock is
    // this thread's.
    #[test]
    fn test_a_drain_on_the_thread_inside_a_write_does_not_wait() {
        let (_dir, path) = fifo("inside");
        let _r = reader(&path);
        let mut c = child("child_drains_inside_a_write", &path);
        let mut out = out_lines(&mut c);
        let took = drain_took(&mut out);
        // Without waiting: well under DRAIN_STALL, which a wait for the
        // lock (or for the reader, which reads nothing here) would take.
        assert!(took < super::DRAIN_STALL / 2, "{took:?}");
        assert_eq!(wait_child(out.child).code(), Some(148));
    }

    #[test]
    #[ignore = "run by test_a_drain_on_the_thread_inside_a_write_does_not_wait"]
    fn child_drains_inside_a_write() {
        let out = child_fills();
        on_sigusr2(handler_drains_then_exits);
        #[cfg(target_os = "macos")]
        out.holding(raise_sigusr2);
        #[cfg(not(target_os = "macos"))]
        {
            let _ = out;
            raise_sigusr2();
        }
    }

    // A drain in a signal handler while another thread holds the overflow's
    // lock (and never lets go) waits for it DRAIN_STALL at most, then ends.
    #[test]
    fn test_a_drain_waits_for_another_threads_lock_a_bounded_time() {
        let (_dir, path) = fifo("other");
        let _r = reader(&path);
        let mut c = child("child_drains_while_another_thread_holds_the_lock", &path);
        let mut out = out_lines(&mut c);
        let took = drain_took(&mut out);
        // Linux: nothing to drain, no lock. macOS: the lock waited for until
        // DRAIN_STALL from the call, then the FIFO skipped; less than twice
        // that (the 50 µs naps, the clock reads).
        #[cfg(target_os = "macos")]
        assert!(took >= super::DRAIN_STALL && took < 2 * super::DRAIN_STALL, "{took:?}");
        #[cfg(not(target_os = "macos"))]
        assert!(took < super::DRAIN_STALL / 2, "{took:?}");
        assert_eq!(wait_child(out.child).code(), Some(148));
    }

    #[test]
    #[ignore = "run by test_a_drain_waits_for_another_threads_lock_a_bounded_time"]
    fn child_drains_while_another_thread_holds_the_lock() {
        let out = child_fills();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            #[cfg(target_os = "macos")]
            out.holding(|| {
                held_tx.send(()).unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            });
            #[cfg(not(target_os = "macos"))]
            {
                let _ = out;
                held_tx.send(()).unwrap();
            }
        });
        held_rx.recv().unwrap();
        on_sigusr2(handler_drains_then_exits);
        raise_sigusr2();
    }

    // A FIFO is freed by the thread that drops its OutFile, never by a
    // signal handler that reached it through the relay's list at that same
    // moment (its `free` is not async-signal-safe): the list holds a strong
    // reference, taken out only under the list's lock, and a handler only
    // borrows. Here the "handler" holds the list (as `drain` does) while
    // another thread drops the OutFile, and lets that drop finish if it can
    // (up to 200 ms): with the list's reference, the drop waits for the
    // list and the FIFO is freed by the dropping thread after it; with a
    // weak list and a handler's own reference, the handler's would be the
    // last and the FIFO freed by the handler.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_a_fifo_is_freed_by_its_owner_not_a_handler() {
        let (_dir, path) = fifo("freed");
        let _r = reader(&path);
        let mut c = child("child_drops_while_a_handler_holds_the_list", &path);
        let mut out = out_lines(&mut c);
        assert_eq!(until(&mut out, "WICK-FREED-BY"), "the dropping thread");
        assert!(wait_child(out.child).success());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_a_fifo_is_freed_by_its_owner_not_a_handler"]
    fn child_drops_while_a_handler_holds_the_list() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        // The only FIFO of this process.
        let out = open_file_nonblock(&child_path()).unwrap();
        let (go, went) = mpsc::channel::<()>();
        let (done, dropped) = mpsc::channel::<u64>();
        let dropper = std::thread::spawn(move || {
            went.recv().unwrap();
            drop(out);
            done.send(super::macos::this_thread()).unwrap();
        });
        let once = AtomicBool::new(false);
        super::macos::while_listed(|| {
            if !once.swap(true, Ordering::AcqRel) {
                go.send(()).unwrap();
                // The drop's end, if it can end while the list is held.
                let _ = dropped.recv_timeout(Duration::from_millis(200));
            }
        });
        assert!(once.load(Ordering::Acquire), "the FIFO was not listed");
        let handler = super::macos::this_thread();
        dropper.join().unwrap();
        let by = super::macos::DROPPED_ON.load(Ordering::Acquire);
        let who = if by == handler { "the handler" } else if by == 0 { "nobody" } else { "the dropping thread" };
        println!("WICK-FREED-BY {who}");
        std::io::stdout().flush().unwrap();
    }

    // The API process's end drains its FIFOs (`api_process::exit`, its
    // panic hook) under its own profile, which has neither `poll` nor
    // `nanosleep` (`sandbox::API_SYSCALLS`): the drain's wait for a slow
    // reader would be a denied call there, and end Firecracker 148. It is
    // never one: the fork's copies of Firecracker's overflows are emptied
    // (`after_fork(true)`) and the API process writes no FIFO after that
    // (its log is off from then on), so its drain finds nothing to wait
    // for. Here Firecracker's side leaves its log FIFO full with an
    // overflow behind it and its reader reading nothing, forks as the
    // split does, and the fork takes the API profile and drains: it ends 0,
    // not by SIGSYS, and wrote nothing of Firecracker's.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_the_api_process_drain_waits_for_nothing() {
        let (_dir, path) = fifo("api-drain");
        let r = reader(&path);
        let mut c = child("child_forks_an_api_process_that_drains", &path);
        let mut out = out_lines(&mut c);
        assert_eq!(until(&mut out, "WICK-API-DRAIN"), "exit 0", "the API process's drain");
        assert!(wait_child(out.child).success());
        // Only what the FIFO took before the fork (the reader read nothing
        // until now): the fork wrote none of the overflow.
        let mut buf = vec![0u8; 65536];
        // SAFETY: reading into our buffer.
        let n = unsafe { libc::read(r.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(usize::try_from(n).unwrap(), fifo_buffer() / 100 * 100);
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "run by test_the_api_process_drain_waits_for_nothing"]
    fn child_forks_an_api_process_that_drains() {
        let mut out = open_file_nonblock(&child_path()).unwrap();
        for i in 0..300 {
            out.write_all(&line(i)).unwrap();
        }
        // The overflow stays: what the drain would have to wait for.
        assert_eq!(out.pause_relay(), 30000 - fifo_buffer() / 100 * 100);
        super::before_fork().unwrap();
        // SAFETY: one thread forks (the relay is stopped); the fork takes
        // the API profile, drains as the API process's exit does, and ends.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            super::after_fork(true).unwrap();
            crate::ext::sandbox::select(crate::ext::sandbox::Policy::Default);
            crate::ext::sandbox::apply_api().unwrap();
            super::drain();
            // SAFETY: ends the fork.
            unsafe { libc::_exit(0) }
        }
        super::after_fork(false).unwrap();
        let mut status = 0;
        // SAFETY: the fork's pid.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let how = if libc::WIFEXITED(status) {
            format!("exit {}", libc::WEXITSTATUS(status))
        } else {
            format!("signal {}", libc::WTERMSIG(status))
        };
        println!("WICK-API-DRAIN {how}");
        std::io::stdout().flush().unwrap();
        // This process's own end drains nothing either: the test reads what
        // the FIFO held before the fork, nothing more.
        std::mem::forget(out);
        // SAFETY: ends this process without its drain.
        unsafe { libc::_exit(0) }
    }

    // A FIFO's OutFile dropped (a serial device's, with its VM) gives the
    // reader everything written, the overflow included, as on Linux.
    #[test]
    fn test_a_dropped_out_file_drains_to_the_reader() {
        let (_dir, path) = fifo("dropped");
        let r = reader(&path);
        let mut out = open_file_nonblock(&path).unwrap();
        for i in 0..300 {
            out.write_all(&line(i)).unwrap();
        }
        let reading = std::thread::spawn(move || read_exactly(&r, 30000));
        drop(out);
        assert!(reading.join().unwrap() == lines(0..300), "the lines came back otherwise");
    }
}
