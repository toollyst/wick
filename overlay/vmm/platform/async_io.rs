// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous file I/O, used by the block device's `Async` engine.
//!
//! The interface is io_uring's submission/completion model, so the Linux
//! backend is the kernel ring itself:
//! - operations are pushed onto a submission queue and name their file by the
//!   index it had in the list given to [`AsyncIo::new`];
//! - [`AsyncIo::submit`] hands the queued operations to the host, which runs
//!   them concurrently;
//! - completions are popped in any order with [`AsyncIo::pop`], and each one
//!   is announced on the completion [`EventFd`];
//! - at most twice the submission queue size operations are outstanding
//!   (queued, running or completed but not popped), so completions are never
//!   dropped;
//! - [`Restriction`]s are enforced: once any is given, an operation whose
//!   opcode is not allowed completes with `-EACCES`, and the submission
//!   stops there: the operations queued after it wait for the next submit.
//!
//! Backends: Linux uses io_uring ([`crate::io_uring::IoUring`]); macOS uses a
//! pool of worker threads doing `pread`/`pwrite`/`F_FULLFSYNC`.

use std::fmt::Debug;
use std::fs::File;

use vmm_sys_util::eventfd::EventFd;

pub use crate::io_uring::IoUringError;
pub use crate::io_uring::operation::{Cqe, OpCode, Operation};
pub use crate::io_uring::restriction::Restriction;

/// Largest submission queue an instance can have (`IORING_MAX_ENTRIES`).
pub const MAX_ENTRIES: u32 = 32768;
/// Largest number of files an instance can use (`IORING_MAX_FIXED_FILES`).
pub const MAX_FILES: usize = 1 << 15;

/// An asynchronous I/O queue whose operations carry user data of type `T`.
pub trait AsyncIo<T>: Sized + Debug {
    /// Creates a queue.
    ///
    /// * `num_entries` - submission queue size, rounded up to a power of two.
    /// * `files` - files the operations work on, named by index.
    /// * `restrictions` - limits that take effect now and can never be lifted.
    /// * `eventfd` - written to after each completion.
    fn new(
        num_entries: u32,
        files: Vec<&File>,
        restrictions: Vec<Restriction>,
        eventfd: Option<&EventFd>,
    ) -> Result<Self, IoUringError>;

    /// Queues an operation. On failure the user data is given back.
    fn push(&mut self, op: Operation<T>) -> Result<(), (IoUringError, T)>;

    /// Pops a completed operation, or returns `None` if none has completed.
    fn pop(&mut self) -> Result<Option<Cqe<T>>, IoUringError>;

    /// Starts all queued operations without waiting. Returns how many started.
    fn submit(&mut self) -> Result<u32, IoUringError>;

    /// Starts all queued operations and waits until every outstanding
    /// operation has completed. Returns how many started.
    fn submit_and_wait_all(&mut self) -> Result<u32, IoUringError>;

    /// Number of operations queued but not started.
    fn pending_sqes(&self) -> Result<u32, IoUringError>;

    /// Number of outstanding operations: queued, running, or completed but not
    /// popped.
    fn num_ops(&self) -> u32;
}

/// This host's [`AsyncIo`] backend.
pub type Queue<T> = super::backend::async_io::Queue<T>;

/// Readies the host for queues made once the process may no longer create
/// threads (`ext::sandbox::narrow`): on Linux nothing, an io_uring needs no
/// thread; on macOS the worker threads every later queue shares are started
/// here, and no more are made.
pub fn seal_workers() -> std::io::Result<()> {
    super::backend::async_io::seal_workers()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    // Interface tests: they run against the backend of the host they are
    // built for.
    use std::io::{Read, Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    const LEN: usize = 4096;

    fn file_with(contents: &[u8]) -> File {
        let mut file = TempFile::new().unwrap().into_file();
        file.write_all(contents).unwrap();
        file
    }

    fn queue(file: &File, restrictions: Vec<Restriction>, evt: &EventFd) -> Queue<u32> {
        AsyncIo::new(8, vec![file], restrictions, Some(evt)).unwrap()
    }

    fn pop_all(q: &mut Queue<u32>) -> Vec<(u32, Result<u32, Option<i32>>)> {
        let mut out = Vec::new();
        while let Some(cqe) = q.pop().unwrap() {
            // `Cqe::result` keeps the CQE's negative errno as the OS error code.
            let res = cqe.result().map_err(|e| e.raw_os_error());
            out.push((cqe.user_data(), res));
        }
        out.sort_by_key(|(id, _)| *id);
        out
    }

    #[test]
    fn test_read_write_fsync() {
        let file = file_with(&[0u8; LEN]);
        let evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut q = queue(&file, vec![], &evt);

        let src: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
        let mut dst = vec![0u8; LEN];
        q.push(Operation::write(0, src.as_ptr() as usize, LEN as u32, 0, 1))
            .unwrap();
        assert_eq!(q.pending_sqes().unwrap(), 1);
        assert_eq!(q.submit_and_wait_all().unwrap(), 1);
        assert_eq!(q.pending_sqes().unwrap(), 0);
        assert!(evt.read().unwrap() >= 1);

        q.push(Operation::read(0, dst.as_mut_ptr() as usize, 100, 10, 2))
            .unwrap();
        q.push(Operation::fsync(0, 3)).unwrap();
        assert_eq!(q.num_ops(), 3);
        q.submit_and_wait_all().unwrap();

        let done = pop_all(&mut q);
        assert_eq!(done, vec![(1, Ok(LEN as u32)), (2, Ok(100)), (3, Ok(0))]);
        assert_eq!(q.num_ops(), 0);
        assert_eq!(&dst[..100], &src[10..110]);
    }

    #[test]
    fn test_submit_without_waiting() {
        let file = file_with(&[7u8; LEN]);
        let evt = EventFd::new(0).unwrap();
        let mut q = queue(&file, vec![], &evt);
        let mut dst = vec![0u8; LEN];
        q.push(Operation::read(
            0,
            dst.as_mut_ptr() as usize,
            LEN as u32,
            0,
            9,
        ))
        .unwrap();
        assert_eq!(q.submit().unwrap(), 1);
        // A blocking read of the completion event returns once the read is done.
        evt.read().unwrap();
        let cqe = q.pop().unwrap().unwrap();
        assert_eq!(cqe.result().unwrap(), LEN as u32);
        assert!(dst.iter().all(|b| *b == 7));
    }

    #[test]
    fn test_short_read_at_end_of_file() {
        let file = file_with(&[1u8; 100]);
        let evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut q = queue(&file, vec![], &evt);
        let mut dst = vec![0u8; LEN];
        q.push(Operation::read(
            0,
            dst.as_mut_ptr() as usize,
            LEN as u32,
            50,
            1,
        ))
        .unwrap();
        q.submit_and_wait_all().unwrap();
        assert_eq!(pop_all(&mut q), vec![(1, Ok(50))]);
    }

    #[test]
    fn test_restrictions() {
        let file = file_with(&[0u8; LEN]);
        let evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut q = queue(
            &file,
            vec![
                Restriction::RequireFixedFds,
                Restriction::AllowOpCode(OpCode::Read),
            ],
            &evt,
        );
        let mut buf = vec![0u8; 16];
        q.push(Operation::read(0, buf.as_mut_ptr() as usize, 16, 0, 1))
            .unwrap();
        q.push(Operation::write(0, buf.as_ptr() as usize, 16, 0, 2))
            .unwrap();
        q.push(Operation::fsync(0, 3)).unwrap();
        // The batch ends at the denied write; the fsync stays queued.
        assert_eq!(q.submit_and_wait_all().unwrap(), 2);
        assert_eq!(q.pending_sqes().unwrap(), 1);
        assert_eq!(q.submit_and_wait_all().unwrap(), 1);
        let denied = Err(Some(-libc::EACCES));
        assert_eq!(pop_all(&mut q), vec![(1, Ok(16)), (2, denied), (3, denied)]);
    }

    #[test]
    fn test_queue_limits() {
        let file = file_with(&[0u8; LEN]);
        let evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut buf = vec![0u8; LEN];
        let addr = buf.as_mut_ptr() as usize;

        // Files are named by index.
        let mut q = queue(&file, vec![], &evt);
        let (err, data) = q.push(Operation::read(1, addr, 1, 0, 5)).unwrap_err();
        assert!(matches!(err, IoUringError::InvalidFixedFd(1)));
        assert_eq!(data, 5);
        let mut no_files: Queue<u32> = AsyncIo::new(8, vec![], vec![], None).unwrap();
        let (err, _) = no_files
            .push(Operation::read(0, addr, 1, 0, 5))
            .unwrap_err();
        assert!(matches!(err, IoUringError::NoRegisteredFds));

        // The submission queue holds 8 operations.
        for i in 0..8 {
            q.push(Operation::read(0, addr, 1, 0, i)).unwrap();
        }
        let (err, data) = q.push(Operation::read(0, addr, 1, 0, 8)).unwrap_err();
        assert!(err.is_throttling_err());
        assert_eq!(data, 8);
        q.submit_and_wait_all().unwrap();

        // At most 16 operations are outstanding.
        for i in 8..16 {
            q.push(Operation::read(0, addr, 1, 0, i)).unwrap();
        }
        q.submit_and_wait_all().unwrap();
        assert_eq!(q.num_ops(), 16);
        let (err, _) = q.push(Operation::read(0, addr, 1, 0, 16)).unwrap_err();
        assert!(matches!(err, IoUringError::FullCQueue));
        assert!(err.is_throttling_err());
        assert_eq!(pop_all(&mut q).len(), 16);
        q.push(Operation::read(0, addr, 1, 0, 16)).unwrap();
    }

    #[test]
    fn test_many_concurrent_writes() {
        // Every block is written by its own operation; the result must equal
        // the same writes done synchronously.
        const BLOCKS: usize = 64;
        const BLOCK: usize = 512;
        let mut file = file_with(&[0u8; BLOCKS * BLOCK]);
        let evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut q: Queue<u32> = AsyncIo::new(16, vec![&file], vec![], Some(&evt)).unwrap();
        let src: Vec<u8> = (0..BLOCKS * BLOCK).map(|i| (i / BLOCK) as u8).collect();

        let mut next = 0;
        let mut done = 0;
        while done < BLOCKS {
            while next < BLOCKS {
                let addr = src[next * BLOCK..].as_ptr() as usize;
                let off = (next * BLOCK) as u64;
                match q.push(Operation::write(0, addr, BLOCK as u32, off, next as u32)) {
                    Ok(()) => next += 1,
                    Err((err, _)) if err.is_throttling_err() => break,
                    Err((err, _)) => panic!("{err}"),
                }
            }
            q.submit().unwrap();
            while let Some(cqe) = q.pop().unwrap() {
                assert_eq!(cqe.result().unwrap(), BLOCK as u32);
                done += 1;
            }
        }
        q.submit_and_wait_all().unwrap();

        let mut contents = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, src);
    }
}
