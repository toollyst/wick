// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What a Linux FIFO opened `O_RDWR | O_NONBLOCK` does for its writer, on a
//! Windows named pipe whose reader made it: Firecracker's log, metrics and
//! serial output file (upstream `utils::open_file_nonblock`,
//! src/vmm/src/utils/mod.rs: "we need all READ, WRITE and O_NONBLOCK in
//! order to not block the process if nobody is consuming the message", and
//! "writing to a pipe will start failing when reaching 64K of unconsumed
//! content").
//!
//! Linux: the writer is a reader of the FIFO too, so a write never fails
//! for want of a reader; the bytes wait in the FIFO, up to pipe(7)'s 65536,
//! for whoever reads next; past that a write fails with `EAGAIN`; a write of
//! up to `PIPE_BUF` (4096) bytes is taken whole or not at all, a longer one
//! as far as it fits (fs/pipe.c `pipe_write`).
//!
//! Windows: the reader makes the pipe and Firecracker is its client. The
//! pipe holds what the reader gave it (its quota), and it ends with the
//! reader's handle: a write then fails with `ERROR_NO_DATA` (232) or
//! `ERROR_PIPE_NOT_CONNECTED` (233), which no Linux FIFO held read-write
//! gives, and a later reader of the name has a new pipe Firecracker is not
//! connected to. So ([`Queue`]):
//!
//! - while the reader's pipe lives and nothing waits behind it, a write
//!   goes into it directly: the bytes are the reader's when the write
//!   returns, as they are the FIFO's on Linux;
//! - what the pipe does not take, and everything once the reader has gone,
//!   waits in an overflow of Firecracker's own: 65536 bytes less what the
//!   live pipe holds, so that both together are a Linux FIFO's capacity;
//!   past that a write fails with the would-block error (`EAGAIN`);
//! - once anything waits, every write goes behind it, so order is kept;
//! - a relay ([`windows`]) moves the overflow into the pipe as its reader
//!   makes room, and into the pipe a new reader makes under the same name.
//!
//! This file's part has no Windows call in it and is tested on every host
//! (a pipe is the [`Pipe`] trait); [`windows`] is the pipe and the relay.

use std::collections::VecDeque;
use std::io;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{OutPipe, drain};

/// pipe(7): what a Linux FIFO holds unread; here the reader's pipe and the
/// overflow together.
pub const CAPACITY: usize = 65536;
/// Linux's `PIPE_BUF`: a write of at most this many bytes is taken whole or
/// not at all (pipe(7); include/uapi/linux/limits.h).
pub const PIPE_BUF: usize = 4096;

/// Why a pipe took no write.
#[derive(Debug)]
pub enum Fault {
    /// The reader closed its end: the pipe is over.
    Gone,
    /// Any other failure of the write.
    Other(io::Error),
}

/// The reader's pipe, as a non-blocking Windows byte pipe is (measured, CI
/// run 43341846250, `test_non_blocking_pipe_writes_on_record`): it holds
/// exactly its quota; a write is taken whole when it fits the free room and
/// not at all (0 bytes, no error) when it does not, whatever its size; only
/// a read waiting at that moment takes its bytes first, and the rest is
/// whole or nothing again.
pub trait Pipe {
    /// One non-blocking write: the bytes taken, 0 when there was no room.
    fn write(&mut self, buf: &[u8]) -> Result<usize, Fault>;
    /// The most bytes the pipe holds unread.
    fn quota(&self) -> usize;
}

/// The writer's side of one path: the reader's pipe while one lives, and
/// the overflow.
#[derive(Debug)]
pub struct Queue<P> {
    pipe: Option<P>,
    /// Bytes accepted and not in a reader's pipe yet, oldest first.
    ring: VecDeque<u8>,
}

impl<P: Pipe> Queue<P> {
    /// The queue of a path whose reader's pipe is `pipe`.
    pub fn new(pipe: P) -> Self {
        Queue { pipe: Some(pipe), ring: VecDeque::new() }
    }

    /// The bytes in the overflow.
    pub fn queued(&self) -> usize {
        self.ring.len()
    }

    /// Whether a reader's pipe is held (it may have ended since the last
    /// write to it).
    pub fn connected(&self) -> bool {
        self.pipe.is_some()
    }

    /// A new reader's pipe, after the last one ended.
    pub fn connect(&mut self, pipe: P) {
        self.pipe = Some(pipe);
    }

    /// The overflow's size now: a Linux FIFO's capacity less what the live
    /// pipe holds; all of it once the reader has gone, whose pipe holds
    /// nothing any more.
    fn room(&self) -> usize {
        let held = self.pipe.as_ref().map_or(0, Pipe::quota);
        CAPACITY.saturating_sub(held).saturating_sub(self.ring.len())
    }

    /// The largest piece a pipe of `quota` bytes can take whole: `PIPE_BUF`,
    /// or the pipe's quota if that is less (a write larger than the quota
    /// is never taken).
    fn atom(quota: usize) -> usize {
        PIPE_BUF.min(quota).max(1)
    }

    /// Writes `buf` into the reader's pipe: whole if it fits; else, when
    /// longer than a piece, piece by piece until one is refused, as Linux
    /// takes a long write page by page. The bytes taken.
    fn direct(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(pipe) = self.pipe.as_mut() else { return Ok(0) };
        let atom = Self::atom(pipe.quota());
        let mut total = match pipe.write(buf) {
            Ok(n) => n,
            Err(Fault::Gone) => {
                self.pipe = None;
                return Ok(0);
            }
            Err(Fault::Other(e)) => return Err(e),
        };
        if buf.len() <= atom {
            return Ok(total);
        }
        while total < buf.len() {
            let rest = &buf[total..];
            let piece = &rest[..rest.len().min(atom)];
            match pipe.write(piece) {
                Ok(n) => {
                    total += n;
                    if n < piece.len() {
                        break;
                    }
                }
                Err(Fault::Gone) => {
                    self.pipe = None;
                    break;
                }
                // Part of the write is in the pipe: the count, as Linux
                // returns it; the error is the next write's.
                Err(Fault::Other(e)) if total == 0 => return Err(e),
                Err(Fault::Other(_)) => break,
            }
        }
        Ok(total)
    }

    /// A write with a Linux FIFO's results: the bytes accepted (in the
    /// reader's pipe, or in the overflow behind what waits there), or the
    /// would-block error when neither has room. A write of at most
    /// [`PIPE_BUF`] bytes is accepted whole or refused; a longer one is
    /// accepted as far as there is room.
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Behind what already waits, never past it.
        let taken = if self.ring.is_empty() { self.direct(buf)? } else { 0 };
        let rest = &buf[taken..];
        let room = self.room();
        let more = if rest.len() <= room {
            rest.len()
        } else if buf.len() <= PIPE_BUF && taken == 0 {
            0
        } else {
            room
        };
        self.ring.extend(&rest[..more]);
        match taken + more {
            0 => Err(io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        }
    }

    /// Moves the front of the overflow into the reader's pipe, as much as
    /// it takes now, in pieces it can take whole. The bytes moved. A pipe
    /// that fails is over: the bytes stay for the next reader's.
    pub fn relay(&mut self) -> usize {
        let Some(pipe) = self.pipe.as_mut() else { return 0 };
        let atom = Self::atom(pipe.quota());
        let mut moved = 0;
        while !self.ring.is_empty() {
            let (front, _) = self.ring.as_slices();
            let piece = &front[..front.len().min(atom)];
            match pipe.write(piece) {
                Ok(0) => break,
                Ok(n) => {
                    self.ring.drain(..n);
                    moved += n;
                }
                Err(_) => {
                    self.pipe = None;
                    break;
                }
            }
        }
        moved
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::ErrorKind;
    use std::rc::Rc;

    use super::*;

    /// A reader's end: what it holds unread, and whether it is closed.
    #[derive(Default)]
    struct Reader {
        held: Vec<u8>,
        /// The size of a read that waits now, if one does, and what it got.
        waiting: usize,
        got: Vec<u8>,
        closed: bool,
        /// A failure the next write gets.
        fail: Option<i32>,
    }

    /// A pipe with Windows' measured rules (see [`Pipe`]).
    struct Fake {
        quota: usize,
        reader: Rc<RefCell<Reader>>,
    }

    fn pipe(quota: usize) -> (Fake, Rc<RefCell<Reader>>) {
        let reader = Rc::new(RefCell::new(Reader::default()));
        (Fake { quota, reader: reader.clone() }, reader)
    }

    impl Pipe for Fake {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Fault> {
            let mut r = self.reader.borrow_mut();
            if r.closed {
                return Err(Fault::Gone);
            }
            if let Some(code) = r.fail.take() {
                return Err(Fault::Other(io::Error::from_raw_os_error(code)));
            }
            // A waiting read takes its bytes first; the rest is whole or
            // nothing against the free room.
            let first = buf.len().min(r.waiting);
            r.waiting -= first;
            r.got.extend_from_slice(&buf[..first]);
            let rest = &buf[first..];
            if rest.len() > self.quota.saturating_sub(r.held.len()) {
                return Ok(first);
            }
            r.held.extend_from_slice(rest);
            Ok(buf.len())
        }

        fn quota(&self) -> usize {
            self.quota
        }
    }

    /// The reader reads `n` bytes it holds.
    fn read(reader: &Rc<RefCell<Reader>>, n: usize) -> Vec<u8> {
        let mut r = reader.borrow_mut();
        let n = n.min(r.held.len());
        r.held.drain(..n).collect()
    }

    /// Line `i`: 100 bytes, its number first.
    fn line(i: usize) -> Vec<u8> {
        format!("{i:099}\n").into_bytes()
    }

    /// Writes `buf` until the first error: the bytes taken and the error.
    fn fill(q: &mut Queue<Fake>, buf: &[u8]) -> (usize, io::Error) {
        let mut taken = 0;
        loop {
            match q.write(buf) {
                Ok(n) => {
                    assert_eq!(n, buf.len(), "a {}-byte write is taken whole or refused", buf.len());
                    taken += n;
                }
                Err(e) => return (taken, e),
            }
            assert!(taken <= 2 * CAPACITY, "{taken} bytes taken and no error");
        }
    }

    // A pipe nobody reads takes pipe(7)'s 65536 at most, whatever the
    // reader's pipe holds of it, then the would-block error: Linux takes
    // 64000 in 100-byte writes (fs/pipe.c `pipe_write`: 40 to a page, 16
    // pages) and 65536 in 4096-byte writes.
    #[test]
    fn test_a_pipe_nobody_reads_takes_linuxs_capacity() {
        for quota in [0, 1, 512, 4096, 8192, 65536] {
            let (p, _r) = pipe(quota);
            let mut q = Queue::new(p);
            let (taken, err) = fill(&mut q, &line(0));
            assert_eq!(err.kind(), ErrorKind::WouldBlock, "quota {quota}");
            assert!((64000..=CAPACITY).contains(&taken), "quota {quota}: {taken}");
            // Exactly 65536 in page-sized writes, as Linux: the pipe's part
            // (a pipe of less than a page takes the first write's front)
            // and the overflow's are 65536 together.
            let (p, _r) = pipe(quota);
            let mut q = Queue::new(p);
            let (taken, err) = fill(&mut q, &[b'p'; PIPE_BUF]);
            assert_eq!((taken, err.kind()), (CAPACITY, ErrorKind::WouldBlock), "quota {quota}");
        }
        // A pipe its reader made larger holds what it holds, as a FIFO
        // whose reader raised it with F_SETPIPE_SZ (fs/pipe.c
        // `pipe_set_size`, up to /proc/sys/fs/pipe-max-size); the overflow
        // adds nothing to it.
        let (p, _r) = pipe(2 * CAPACITY);
        let mut q = Queue::new(p);
        for _ in 0..32 {
            assert_eq!(q.write(&[b'p'; PIPE_BUF]).unwrap(), PIPE_BUF);
        }
        assert_eq!(q.write(&[b'p'; PIPE_BUF]).unwrap_err().kind(), ErrorKind::WouldBlock);
        assert_eq!(q.queued(), 0);
    }

    // A write after the reader left succeeds, as on a FIFO held
    // read-write; writes go on to 64 KiB, then the would-block error; a
    // reader that comes later gets every line in order, once each; then
    // writes go into its pipe directly.
    #[test]
    fn test_a_pipe_whose_reader_left_takes_writes_as_a_fifo_does() {
        let (p, r) = pipe(65536);
        let mut q = Queue::new(p);
        q.write(&line(0)).unwrap();
        assert_eq!((read(&r, 100), q.queued()), (line(0), 0));
        r.borrow_mut().closed = true;
        assert_eq!(q.write(&line(1)).unwrap(), 100);
        assert!(!q.connected());
        let mut i = 2;
        let err = loop {
            match q.write(&line(i)) {
                Ok(n) => assert_eq!(n, 100),
                Err(e) => break e,
            }
            i += 1;
        };
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
        // Lines 1 to 655: 65500 bytes; the 656th does not fit 65536.
        assert_eq!((i, q.queued()), (656, 65500));
        assert_eq!(q.relay(), 0, "no reader, nothing moves");
        // A new reader, with a small pipe: the relay fills it as it reads.
        let (p, r) = pipe(4096);
        q.connect(p);
        let mut got = Vec::new();
        while q.queued() > 0 {
            assert!(q.relay() > 0);
            got.extend(read(&r, usize::MAX));
        }
        got.extend(read(&r, usize::MAX));
        assert!(got == (1..656).flat_map(line).collect::<Vec<u8>>(), "the lines came back otherwise");
        q.write(&line(9999)).unwrap();
        assert_eq!((q.queued(), read(&r, 100)), (0, line(9999)));
    }

    // A write of at most 4096 bytes (PIPE_BUF) is taken whole or refused,
    // and a refused one leaves no byte; a longer one takes what fits.
    #[test]
    fn test_a_small_write_is_all_or_nothing() {
        for quota in [512, 4096, 65536] {
            let (p, r) = pipe(quota);
            let mut q = Queue::new(p);
            fill(&mut q, &line(0));
            assert_eq!(q.write(&[b'a'; 3000]).unwrap_err().kind(), ErrorKind::WouldBlock, "quota {quota}");
            // The reader takes 5000 bytes, the relay moving on behind it.
            let mut took = 0;
            while took < 5000 {
                took += read(&r, 5000 - took).len();
                q.relay();
            }
            let n = q.write(&[b'b'; 9000]).unwrap();
            assert!(0 < n && n < 9000, "quota {quota}: {n} of a 9000-byte write");
            assert_eq!(q.write(&[b'a'; 3000]).unwrap_err().kind(), ErrorKind::WouldBlock);
            let mut rest = Vec::new();
            loop {
                let part = read(&r, usize::MAX);
                if part.is_empty() && q.relay() == 0 {
                    break;
                }
                rest.extend(part);
            }
            assert!(!rest.contains(&b'a'), "quota {quota}: a refused write left bytes");
            assert_eq!(rest.iter().filter(|b| **b == b'b').count(), n);
        }
        // Every size up to PIPE_BUF, at every fill of the last 5000 bytes.
        for quota in [4096, 65536] {
            for len in [1, 99, 100, 101, 4095, 4096] {
                let (p, _r) = pipe(quota);
                let mut q = Queue::new(p);
                fill(&mut q, &[b'x'; 4096]);
                let _ = fill(&mut q, &[b'x'; 1]);
                // Full to the byte (page-sized pipes).
                assert_eq!(q.write(&vec![b'a'; len]).unwrap_err().kind(), ErrorKind::WouldBlock, "{quota} {len}");
            }
        }
    }

    // Order is kept through full and empty spells: once anything waits,
    // a write goes behind it even when the pipe has room again.
    #[test]
    fn test_order_is_kept_across_a_full_pipe() {
        let (p, r) = pipe(4096);
        let mut q = Queue::new(p);
        let mut got = Vec::new();
        let mut i = 0;
        let mut refused = 0;
        while i < 3000 {
            match q.write(&line(i)) {
                Ok(n) => {
                    assert_eq!(n, 100);
                    i += 1;
                }
                Err(e) => {
                    assert_eq!(e.kind(), ErrorKind::WouldBlock);
                    refused += 1;
                    // The reader reads a little, the relay follows.
                    got.extend(read(&r, 700));
                    q.relay();
                }
            }
            if i % 7 == 0 {
                // Room in the pipe while bytes wait: the next write must
                // still go behind them.
                got.extend(read(&r, 250));
            }
        }
        loop {
            let part = read(&r, usize::MAX);
            if part.is_empty() && q.relay() == 0 {
                break;
            }
            got.extend(part);
        }
        assert!(refused > 0, "the pipe never filled");
        assert!(got == (0..3000).flat_map(line).collect::<Vec<u8>>(), "the lines came back otherwise");
    }

    // While the reader's pipe has room and nothing waits, the bytes are in
    // it when the write returns: nothing of them is in the overflow.
    #[test]
    fn test_a_line_is_in_the_readers_pipe_when_the_write_returns() {
        let (p, r) = pipe(65536);
        let mut q = Queue::new(p);
        q.write(&line(7)).unwrap();
        assert_eq!((q.queued(), r.borrow().held.clone()), (0, line(7)));
    }

    // A long write goes into the pipe page by page as far as it fits, the
    // rest into the overflow, and past both it is taken in part.
    #[test]
    fn test_a_long_write_is_taken_as_far_as_it_fits() {
        let (p, r) = pipe(8192);
        let mut q = Queue::new(p);
        q.write(&[b'x'; 100]).unwrap();
        // 20000 do not fit the pipe's 8092 free: one page does, then the
        // next page is refused (3996 free); the rest waits.
        assert_eq!(q.write(&[b'y'; 20000]).unwrap(), 20000);
        assert_eq!((r.borrow().held.len(), q.queued()), (4196, 15904));
        // The overflow is 65536 less the pipe's 8192: 57344.
        assert_eq!(q.write(&vec![b'z'; 60000]).unwrap(), 57344 - 15904);
        assert_eq!(q.write(&[b'z'; 5000]).unwrap_err().kind(), ErrorKind::WouldBlock);
        // A read waiting takes its bytes first (Windows fills waiting reads
        // before it asks whether the rest fits).
        let (p, r) = pipe(4096);
        let mut q = Queue::new(p);
        r.borrow_mut().waiting = 10;
        assert_eq!(q.write(&[b'w'; 9000]).unwrap(), 9000);
        assert_eq!((r.borrow().got.len(), r.borrow().held.len(), q.queued()), (10, 4096, 9000 - 10 - 4096));
    }

    // A failure of the pipe that is not its reader's leaving is the
    // writer's error when nothing was taken, and no byte is kept for it.
    #[test]
    fn test_another_failure_of_the_pipe_is_the_writers() {
        let (p, r) = pipe(4096);
        let mut q = Queue::new(p);
        r.borrow_mut().fail = Some(5);
        assert_eq!(q.write(&line(0)).unwrap_err().raw_os_error(), Some(5));
        assert_eq!((q.queued(), r.borrow().held.len()), (0, 0));
        q.write(&line(1)).unwrap();
        assert_eq!(read(&r, 100), line(1));
    }
}
