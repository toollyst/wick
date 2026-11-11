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
//! - `submit` moves the queued operations to the job list of the process's
//!   worker threads, which every queue shares;
//! - a worker runs one `pread`, `pwrite` or `F_FULLFSYNC`, appends the result
//!   to its queue's completion list and writes the completion [`EventFd`].
//!
//! The workers are the process's, not a queue's: a queue made after the
//! sandbox has narrowed (the block device's new ring when a drive's file is
//! replaced, a drive added to a running microVM) needs no new thread, as an
//! io_uring needs none on Linux, where the narrowed filter allows
//! `io_uring_setup` but no `clone`. Until [`seal_workers`] the pool grows to
//! `WORKERS` threads for each live queue; from then on it keeps the threads
//! it has (at least one), and later queues share them.
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

use vmm_sys_util::eventfd::EventFd;

use crate::io_uring::SQueueError;
use crate::platform::async_io::{
    AsyncIo, Cqe, IoUringError, MAX_ENTRIES, MAX_FILES, OpCode, Operation, Restriction,
};

/// Worker threads per live queue, until [`seal_workers`]. The block device
/// keeps at most `IO_URING_NUM_ENTRIES` operations in flight; four threads
/// keep a fast SSD busy without one thread per operation.
const WORKERS: u32 = 4;

/// The process's worker threads and the jobs they serve, from every queue.
#[derive(Debug, Default)]
struct Pool {
    jobs: VecDeque<(Arc<Shared>, Job)>,
    threads: u32,
    /// Queues that exist.
    live: u32,
    /// No thread is made any more ([`seal_workers`]).
    sealed: bool,
}

static POOL: Mutex<Pool> = Mutex::new(Pool {
    jobs: VecDeque::new(),
    threads: 0,
    live: 0,
    sealed: false,
});
/// Signalled when jobs arrive.
static WORK: Condvar = Condvar::new();

fn pool() -> MutexGuard<'static, Pool> {
    // A worker never panics while holding the lock, so it is never poisoned.
    POOL.lock().unwrap()
}

/// Makes worker threads until the pool has `want`, unless it is sealed.
fn grow(pool: &mut Pool, want: u32) -> io::Result<()> {
    while !pool.sealed && pool.threads < want {
        std::thread::Builder::new()
            .name("wick_async_io".into())
            .spawn(worker)?;
        pool.threads += 1;
    }
    Ok(())
}

/// Starts the worker threads that queues made from now on share, at least
/// one, and makes no more: called before the sandbox stops the process from
/// creating threads (`ext::sandbox::narrow`).
pub fn seal_workers() -> io::Result<()> {
    let mut pool = pool();
    grow(&mut pool, 1)?;
    pool.sealed = true;
    Ok(())
}

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
    completions: VecDeque<(i32, usize)>,
    /// Submitted operations whose completion is not on `completions` yet.
    running: u32,
}

/// A queue's side the workers see.
#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
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

fn worker() {
    loop {
        let (shared, job) = {
            let mut pool = pool();
            loop {
                if let Some(next) = pool.jobs.pop_front() {
                    break next;
                }
                pool = WORK.wait(pool).unwrap();
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

        {
            let mut pool = pool();
            let want = WORKERS.saturating_mul(pool.live + 1);
            grow(&mut pool, want).map_err(IoUringError::Setup)?;
            pool.live += 1;
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            done: Condvar::new(),
            files,
            eventfd,
        });
        Ok(Queue {
            shared,
            submission: Vec::with_capacity(sq_entries as usize),
            sq_entries,
            cq_entries,
            num_ops: 0,
            slab: slab::Slab::with_capacity((sq_entries + cq_entries) as usize),
            allowed,
        })
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
        let mut jobs = Vec::with_capacity(end);
        for job in self.submission.drain(..end) {
            if job.denied {
                denied = Some(job.key);
            } else {
                jobs.push(job);
            }
        }
        {
            let mut state = self.shared.lock();
            state.running += u32::try_from(jobs.len()).unwrap();
            if let Some(key) = denied {
                state.completions.push_back((-libc::EACCES, key));
            }
        }
        if !jobs.is_empty() {
            let mut pool = pool();
            pool.jobs
                .extend(jobs.into_iter().map(|job| (self.shared.clone(), job)));
            drop(pool);
            WORK.notify_all();
        }
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
        // Operations that have not started are discarded; running ones are
        // waited for, so no worker touches their buffers afterwards.
        let discarded = {
            let mut pool = pool();
            let before = pool.jobs.len();
            pool.jobs.retain(|(shared, _)| !Arc::ptr_eq(shared, &self.shared));
            let discarded = before - pool.jobs.len();
            pool.live -= 1;
            discarded
        };
        let mut state = self.shared.lock();
        state.running -= u32::try_from(discarded).unwrap();
        while state.running > 0 {
            state = self.shared.done.wait(state).unwrap();
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
    fn test_queue_after_seal_makes_no_thread() {
        // The narrowed sandbox kills a process that creates a thread: a queue
        // made after seal_workers (a drive's new file, a hotplugged drive)
        // works on the threads already there.
        seal_workers().unwrap();
        let threads = pool().threads;
        assert!(threads >= 1);
        let file = TempFile::new().unwrap().into_file();
        file.set_len(4096).unwrap();
        let mut buf = vec![0u8; 4096];
        let mut q: Queue<u32> = AsyncIo::new(4, vec![&file], vec![], None).unwrap();
        let q2: Queue<u32> = AsyncIo::new(4, vec![&file], vec![], None).unwrap();
        q.push(Operation::read(0, buf.as_mut_ptr() as usize, 4096, 0, 7))
            .unwrap();
        assert_eq!(q.submit_and_wait_all().unwrap(), 1);
        let cqe = q.pop().unwrap().unwrap();
        assert_eq!(cqe.result().unwrap(), 4096);
        assert_eq!(cqe.user_data(), 7);
        drop(q2);
        assert_eq!(pool().threads, threads);
    }

    #[test]
    fn test_invalid_sizes() {
        let r: Result<Queue<u32>, _> = AsyncIo::new(0, vec![], vec![], None);
        assert!(matches!(r, Err(IoUringError::Setup(_))));
        let r: Result<Queue<u32>, _> = AsyncIo::new(MAX_ENTRIES + 1, vec![], vec![], None);
        assert!(matches!(r, Err(IoUringError::Setup(_))));
    }
}
