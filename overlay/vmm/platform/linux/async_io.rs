// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`AsyncIo`] on Linux: the kernel io_uring.

use std::fmt::Debug;
use std::fs::File;
use std::os::unix::io::AsRawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::io_uring::IoUring;
use crate::platform::async_io::{AsyncIo, Cqe, IoUringError, Operation, Restriction};

/// The Linux queue is the io_uring instance itself.
pub type Queue<T> = IoUring<T>;

/// An io_uring needs no thread of the process: nothing to start.
pub fn seal_workers() -> std::io::Result<()> {
    Ok(())
}

impl<T: Debug> AsyncIo<T> for IoUring<T> {
    fn new(
        num_entries: u32,
        files: Vec<&File>,
        restrictions: Vec<Restriction>,
        eventfd: Option<&EventFd>,
    ) -> Result<Self, IoUringError> {
        IoUring::new(
            num_entries,
            files,
            restrictions,
            eventfd.map(AsRawFd::as_raw_fd),
        )
    }

    fn push(&mut self, op: Operation<T>) -> Result<(), (IoUringError, T)> {
        IoUring::push(self, op)
    }

    fn pop(&mut self) -> Result<Option<Cqe<T>>, IoUringError> {
        IoUring::pop(self)
    }

    fn submit(&mut self) -> Result<u32, IoUringError> {
        IoUring::submit(self)
    }

    fn submit_and_wait_all(&mut self) -> Result<u32, IoUringError> {
        IoUring::submit_and_wait_all(self)
    }

    fn pending_sqes(&self) -> Result<u32, IoUringError> {
        IoUring::pending_sqes(self)
    }

    fn num_ops(&self) -> u32 {
        IoUring::num_ops(self)
    }
}
