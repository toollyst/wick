// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`AsyncIo`] on macOS (and Windows): a pool of worker threads.
//!
//! macOS has no io_uring, and its POSIX AIO cannot signal a descriptor that
//! `epoll` (kqueue) waits on together with the device's other events. The
//! queue therefore does what the kernel ring does, in user space (Windows
//! uses the same queue; see `platform::windows`):
//! - `push` places the operation on the submission queue (a `Vec`), and the
//!   user data in a slab, exactly like [`crate::io_uring::IoUring`];
//! - `submit` moves the queued operations to a shared job list served by
//!   worker threads;
//! - a worker runs one `pread`, `pwrite` or `F_FULLFSYNC`, appends the result
//!   to the completion list and writes the completion [`EventFd`].
//!
//! `F_FULLFSYNC` is used for fsync because on macOS plain `fsync` does not
//! flush the drive's cache, which Linux's `fsync` does. On Windows `fsync`
//! is `FlushFileBuffers`, which flushes the drive's cache too.
//!
//! Dropping the queue discards operations that have not started and waits
//! for running ones, so no worker touches guest memory afterwards.

use std::collections::{HashSet, VecDeque};
use std::fmt::{self, Debug};
use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;

use vmm_sys_util::eventfd::EventFd;

use crate::io_uring::SQueueError;
use crate::platform::async_io::{
    AsyncIo, Cqe, IoUringError, MAX_ENTRIES, MAX_FILES, OpCode, Operation, Restriction,
};

/// Worker threads per queue. The block device keeps at most
/// `IO_URING_NUM_ENTRIES` operations in flight; four threads keep a fast SSD
/// busy without one thread per operation.
const WORKERS: u32 = 4;

/// An operation on its way to a worker.
#[derive(Debug)]
struct Job {
    opcode: OpCode,
    file: usize,
    addr: usize,
    len: u32,
    offset: u64,
    key: usize,
    denied: bool,
}

#[derive(Debug, Default)]
struct State {
    jobs: VecDeque<Job>,
    completions: VecDeque<(i32, usize)>,
    /// Submitted operations whose completion is not on `completions` yet.
    running: u32,
    shutdown: bool,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    /// Signalled when jobs arrive or on shutdown.
    work: Condvar,
    /// Signalled when an operation completes.
    done: Condvar,
    files: Vec<File>,
    eventfd: Option<EventFd>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A worker never panics while holding the lock, so it is never poisoned.
        self.state.lock().unwrap()
    }

    /// Announces a completion on the event, if there is one.
    fn notify_completion(&self) {
        if let Some(evt) = &self.eventfd {
            // A full pipe means the counter is already non-zero, which is all
            // a waiter needs.
            if let Err(err) = evt.write(1)
                && err.kind() != io::ErrorKind::WouldBlock
            {
                crate::logger::error!("async io: completion event: {err}");
            }
        }
    }
}

/// The macOS queue.
pub struct Queue<T> {
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
    submission: Vec<Job>,
    sq_entries: u32,
    cq_entries: u32,
    num_ops: u32,
    slab: slab::Slab<T>,
    /// Opcodes allowed by the restrictions, if any were given.
    allowed: Option<HashSet<u8>>,
}

impl<T> Debug for Queue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Queue")
            .field("files", &self.shared.files.len())
            .field("sq_entries", &self.sq_entries)
            .field("num_ops", &self.num_ops)
            .finish()
    }
}

fn errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Runs one operation and returns what io_uring would put in the CQE:
/// the byte count, or a negative errno.
fn execute(files: &[File], job: &Job) -> i32 {
    if job.denied {
        return -libc::EACCES;
    }
    let fd = files[job.file].as_raw_fd();
    // An offset of -1 means the file position, as for io_uring.
    let offset = match i64::try_from(job.offset) {
        Ok(offset) => Some(offset),
        Err(_) if job.offset == u64::MAX => None,
        Err(_) => return -libc::EINVAL,
    };
    let buf = job.addr as *mut libc::c_void;
    let len = job.len as usize;
    loop {
        // SAFETY: `buf` and `len` describe memory the submitter keeps valid
        // until the operation completes (the io_uring contract), and `fd` is
        // a file this queue owns.
        let ret: isize = unsafe {
            match (job.opcode, offset) {
                (OpCode::Read, Some(off)) => libc::pread(fd, buf, len, off),
                (OpCode::Read, None) => libc::read(fd, buf, len),
                (OpCode::Write, Some(off)) => libc::pwrite(fd, buf, len, off),
                (OpCode::Write, None) => libc::write(fd, buf, len),
                #[cfg(target_os = "macos")]
                (OpCode::Fsync, _) => {
                    let mut ret = libc::fcntl(fd, libc::F_FULLFSYNC);
                    // Some file systems (and non-files) do not implement
                    // F_FULLFSYNC; fsync is then the strongest flush.
                    if ret < 0 && matches!(errno(), libc::ENOTSUP | libc::ENOTTY | libc::EINVAL) {
                        ret = libc::fsync(fd);
                    }
                    ret as isize
                }
                #[cfg(windows)]
                (OpCode::Fsync, _) => libc::fsync(fd) as isize,
            }
        };
        if ret >= 0 {
            return i32::try_from(ret).unwrap_or(i32::MAX);
        }
        let err = errno();
        if err != libc::EINTR {
            return -err;
        }
    }
}

fn worker(shared: Arc<Shared>) {
    loop {
        let job = {
            let mut state = shared.lock();
            loop {
                if state.shutdown {
                    return;
                }
                if let Some(job) = state.jobs.pop_front() {
                    break job;
                }
                state = shared.work.wait(state).unwrap();
            }
        };
        let res = execute(&shared.files, &job);
        {
            let mut state = shared.lock();
            state.completions.push_back((res, job.key));
            state.running -= 1;
        }
        shared.done.notify_all();
        shared.notify_completion();
    }
}

impl<T: Debug> AsyncIo<T> for Queue<T> {
    fn new(
        num_entries: u32,
        files: Vec<&File>,
        restrictions: Vec<Restriction>,
        eventfd: Option<&EventFd>,
    ) -> Result<Self, IoUringError> {
        if num_entries == 0 || num_entries > MAX_ENTRIES {
            return Err(IoUringError::Setup(io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        if files.len() > MAX_FILES {
            return Err(IoUringError::RegisterFileLimitExceeded);
        }
        let sq_entries = num_entries.next_power_of_two();
        let cq_entries = 2 * sq_entries;

        let files = files
            .into_iter()
            .map(File::try_clone)
            .collect::<Result<Vec<_>, _>>()
            .map_err(IoUringError::RegisterFile)?;
        let eventfd = eventfd
            .map(EventFd::try_clone)
            .transpose()
            .map_err(IoUringError::RegisterEventfd)?;
        let allowed = (!restrictions.is_empty()).then(|| {
            restrictions
                .iter()
                .filter_map(|r| match r {
                    Restriction::AllowOpCode(op) => Some(*op as u8),
                    // Operations always name a registered file here.
                    Restriction::RequireFixedFds => None,
                })
                .collect()
        });

        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            work: Condvar::new(),
            done: Condvar::new(),
            files,
            eventfd,
        });
        let mut queue = Queue {
            shared,
            workers: Vec::new(),
            submission: Vec::with_capacity(sq_entries as usize),
            sq_entries,
            cq_entries,
            num_ops: 0,
            slab: slab::Slab::with_capacity((sq_entries + cq_entries) as usize),
            allowed,
        };
        for _ in 0..WORKERS.min(sq_entries) {
            let shared = queue.shared.clone();
            let handle = std::thread::Builder::new()
                .name("wick_async_io".into())
                .spawn(move || worker(shared))
                .map_err(IoUringError::Setup)?;
            queue.workers.push(handle);
        }
        Ok(queue)
    }

    fn push(&mut self, op: Operation<T>) -> Result<(), (IoUringError, T)> {
        let file = op.fd();
        let files = self.shared.files.len();
        if files == 0 {
            return Err((IoUringError::NoRegisteredFds, op.user_data));
        }
        if file as usize >= files {
            return Err((IoUringError::InvalidFixedFd(file), op.user_data));
        }
        if self.num_ops >= self.cq_entries {
            return Err((IoUringError::FullCQueue, op.user_data));
        }
        if self.submission.len() >= self.sq_entries as usize {
            return Err((IoUringError::SQueue(SQueueError::FullQueue), op.user_data));
        }
        let denied = self
            .allowed
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&(op.opcode as u8)));
        self.submission.push(Job {
            opcode: op.opcode,
            file: file as usize,
            addr: op.addr.unwrap_or(0),
            len: op.len.unwrap_or(0),
            offset: op.offset.unwrap_or(0),
            key: self.slab.insert(op.user_data),
            denied,
        });
        self.num_ops += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<Option<Cqe<T>>, IoUringError> {
        let Some((res, key)) = self.shared.lock().completions.pop_front() else {
            return Ok(None);
        };
        self.num_ops = self.num_ops.saturating_sub(1);
        Ok(Some(Cqe::new(res, self.slab.remove(key))))
    }

    fn submit(&mut self) -> Result<u32, IoUringError> {
        // Like the kernel, a batch ends at the first operation a restriction
        // denies: it completes with -EACCES and the ones after it stay queued.
        let end = self
            .submission
            .iter()
            .position(|job| job.denied)
            .map_or(self.submission.len(), |i| i + 1);
        if end == 0 {
            return Ok(0);
        }
        let mut denied = None;
        {
            let mut state = self.shared.lock();
            for job in self.submission.drain(..end) {
                if job.denied {
                    denied = Some(job.key);
                } else {
                    state.running += 1;
                    state.jobs.push_back(job);
                }
            }
            if let Some(key) = denied {
                state.completions.push_back((-libc::EACCES, key));
            }
        }
        self.shared.work.notify_all();
        if denied.is_some() {
            self.shared.notify_completion();
        }
        Ok(u32::try_from(end).unwrap())
    }

    fn submit_and_wait_all(&mut self) -> Result<u32, IoUringError> {
        let to_submit = self.submission.len();
        let count = self.submit()?;
        // A batch cut short returns without waiting, as io_uring_enter does.
        if count as usize != to_submit {
            return Ok(count);
        }
        let mut state = self.shared.lock();
        while state.running > 0 {
            state = self.shared.done.wait(state).unwrap();
        }
        Ok(count)
    }

    fn pending_sqes(&self) -> Result<u32, IoUringError> {
        Ok(u32::try_from(self.submission.len()).unwrap())
    }

    fn num_ops(&self) -> u32 {
        self.num_ops
    }
}

impl<T> Drop for Queue<T> {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            state.shutdown = true;
            state.jobs.clear();
        }
        self.shared.work.notify_all();
        for handle in self.workers.drain(..) {
            // A worker only returns; a panic in it has already been reported.
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_drop_waits_for_running_operations() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(1 << 20).unwrap();
        let mut buf = vec![0u8; 1 << 20];
        let mut q: Queue<u32> = AsyncIo::new(4, vec![&file], vec![], None).unwrap();
        for i in 0..4 {
            q.push(Operation::read(0, buf.as_mut_ptr() as usize, 1 << 20, 0, i))
                .unwrap();
        }
        q.submit().unwrap();
        drop(q);
        // Every worker has exited, so the buffer is no longer in use.
        buf[0] = 1;
    }

    #[test]
    fn test_invalid_sizes() {
        let r: Result<Queue<u32>, _> = AsyncIo::new(0, vec![], vec![], None);
        assert!(matches!(r, Err(IoUringError::Setup(_))));
        let r: Result<Queue<u32>, _> = AsyncIo::new(MAX_ENTRIES + 1, vec![], vec![], None);
        assert!(matches!(r, Err(IoUringError::Setup(_))));
    }
}
