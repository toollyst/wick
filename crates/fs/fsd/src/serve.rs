// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Stage 1's loop (docs/design-fs.md §4.2): the hellos, then each request
//! frame from the VMM to the session and its reply back, until the VMM
//! closes the connection. A frame that breaks a rule of `wick_fs_frame` ends
//! the connection. One request at a time, in order, on one thread.

use std::io::{Read, Write};

use wick_fs_frame::{self as frame, HEADER_LEN, Header, Kind, Sender};

use crate::dir::ConfinedDir;
use crate::session::Session;

/// Why serving ended.
#[derive(Debug)]
pub enum End {
    /// The VMM closed the connection between frames: the normal end.
    Closed,
    /// The connection failed.
    Io(std::io::Error),
    /// A frame broke a rule.
    Frame(frame::FrameError),
    /// The connection closed inside a frame.
    Truncated,
    /// The process the server lives for (its parent, `--parent-pid`)
    /// ended while the connection waited (docs/design-fs.md §8, Jailer, the
    /// parent watch): a read or write of the connection said so with
    /// [`ParentEnded`].
    ParentEnded(i32),
}

/// What a connection that also watches the server's parent (main.rs on
/// macOS) gives as its I/O error when the parent ended while it waited.
#[derive(Debug)]
pub struct ParentEnded(pub i32);

impl std::fmt::Display for ParentEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "its parent, pid {}, ended", self.0)
    }
}

impl std::error::Error for ParentEnded {}

/// A connection's I/O error as the end: [`End::ParentEnded`] if the
/// connection said the parent ended, else [`End::Io`].
fn io_end(e: std::io::Error) -> End {
    match e.get_ref().and_then(|x| x.downcast_ref::<ParentEnded>()) {
        Some(ParentEnded(pid)) => End::ParentEnded(*pid),
        None => End::Io(e),
    }
}

impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            End::Closed => f.write_str("the VMM closed the connection"),
            End::Io(e) => write!(f, "the connection failed: {e}"),
            End::Frame(e) => write!(f, "a frame broke a rule: {e:?}"),
            End::Truncated => f.write_str("the connection closed inside a frame"),
            End::ParentEnded(pid) => write!(f, "its parent, pid {pid}, ended while it served"),
        }
    }
}

/// Reads exactly `buf`; `Ok(false)` if the connection closed before its
/// first byte.
fn read_all(conn: &mut impl Read, buf: &mut [u8]) -> Result<bool, End> {
    let mut done = 0;
    while done < buf.len() {
        match conn.read(&mut buf[done..]) {
            Ok(0) if done == 0 => return Ok(false),
            Ok(0) => return Err(End::Truncated),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_end(e)),
        }
    }
    Ok(true)
}

/// One frame from the VMM: its header and payload; `None` at a clean close.
fn next(conn: &mut impl Read, buf: &mut Vec<u8>) -> Result<Option<Header>, End> {
    let mut head = [0u8; HEADER_LEN];
    if !read_all(conn, &mut head)? {
        return Ok(None);
    }
    // Checked before the payload is read: a refused length is never
    // buffered.
    let header = Header::parse(&head, Sender::Vmm).map_err(End::Frame)?;
    buf.clear();
    buf.resize(header.payload_len(), 0);
    if !read_all(conn, buf)? && !buf.is_empty() {
        return Err(End::Truncated);
    }
    Ok(Some(header))
}

/// The hellos: this side's, then the VMM's, which must name `id`.
pub fn hello(conn: &mut (impl Read + Write), id: &str) -> Result<(), End> {
    conn.write_all(&frame::hello_frame(id).map_err(End::Frame)?).map_err(io_end)?;
    let mut buf = Vec::new();
    let Some(header) = next(conn, &mut buf)? else {
        return Err(End::Truncated);
    };
    let f = frame::Frame { header, payload: &buf };
    frame::check_hello(&f, id).map_err(End::Frame)
}

/// Serves requests until the VMM closes the connection.
pub fn serve<D: ConfinedDir>(conn: &mut (impl Read + Write), session: &mut Session<D>) -> End {
    let mut buf = Vec::new();
    loop {
        let header = match next(conn, &mut buf) {
            Ok(Some(h)) => h,
            Ok(None) => return End::Closed,
            Err(e) => return e,
        };
        if header.kind() != Kind::Request {
            return End::Frame(frame::FrameError::Hello("a hello after the first frame"));
        }
        let cap = usize::try_from(header.writable_cap()).unwrap_or(0);
        let Some(reply) = session.handle(&buf, cap) else {
            continue;
        };
        let head = match Header::reply(header.cookie(), reply.len()) {
            Ok(h) => h,
            Err(e) => return End::Frame(e),
        };
        let mut out = Vec::with_capacity(HEADER_LEN + reply.len());
        out.extend_from_slice(&head.encode());
        out.extend_from_slice(&reply);
        if let Err(e) = conn.write_all(&out) {
            return io_end(e);
        }
    }
}
