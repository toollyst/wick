// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The frames between wick's virtio-fs device and its file server, wick-fsd.
//!
//! docs/design-fs.md §4.1: the device in the VMM copies the readable bytes of
//! each descriptor chain, unparsed, into one frame on a connected Unix stream,
//! and writes the server's reply into the chain's writable buffers. Neither
//! side trusts the other: the VMM's input is a server that may have been taken
//! over, and the server's is a hostile guest. So each side checks every
//! header here before it reads the payload, and a frame that breaks a rule
//! ends the connection: the caller closes the stream (the VMM then marks the
//! device as needing a reset). Nothing here parses FUSE.
//!
//! The wire format, little-endian: a 24-byte header, then the payload.
//!
//! | offset | size | field |
//! | --- | --- | --- |
//! | 0 | 4 | `len`: the whole frame, header included, `HEADER_LEN..=MAX_FRAME_LEN` |
//! | 4 | 2 | `kind`: 1 hello (either side), 2 request (VMM → server), 3 reply (server → VMM) |
//! | 6 | 2 | `queue`: a request's virtqueue (0 is the hiprio queue); 0 in the others |
//! | 8 | 8 | `cookie`: the VMM's id for a request and its reply, never 0; 0 in a hello |
//! | 16 | 4 | `writable_cap`: the bytes a request's chain takes back, at most `MAX_PAYLOAD_LEN`, 0 for a request that gets no reply; 0 in the others |
//! | 20 | 4 | reserved, 0 |
//!
//! After connecting, each side sends a hello and reads the other's before
//! anything else ([`hello_frame`], [`check_hello`]): the same protocol version
//! and the same share id, so the VMM never talks to a socket that is not the
//! server of the share its configuration names.
//!
//! The VMM tracks its requests with [`InFlight`]: it hands out the cookies,
//! accepts a reply only for a request that is waiting for one and only if the
//! reply fits that request's chain, and bounds what it has to hold: when
//! [`InFlight::start`] says [`Full`], the device stops taking chains off the
//! queue until replies come back.

use std::collections::BTreeMap;
use std::fmt;

/// The protocol version both sides send in their hello.
pub const PROTOCOL_VERSION: u32 = 1;

/// Bytes in a frame header.
pub const HEADER_LEN: usize = 24;

/// The largest frame, header included: a FUSE `WRITE` of `max_write` (1 MiB,
/// as virtiofsd's `MAX_BUFFER_SIZE`) with its headers, and room to spare.
pub const MAX_FRAME_LEN: usize = (1 << 20) + (4 << 10);

/// The largest payload, which is also the largest `writable_cap`: a reply
/// must fit in one frame.
pub const MAX_PAYLOAD_LEN: usize = MAX_FRAME_LEN - HEADER_LEN;

/// The most reply bytes the VMM waits for at once: the sum of the
/// `writable_cap` of its requests in flight. Without it, a queue of 256
/// chains of 1 MiB each would make the VMM hold 256 MiB.
pub const MAX_IN_FLIGHT_REPLY_BYTES: u64 = 16 << 20;

/// The longest share id.
pub const MAX_ID_LEN: usize = 64;

// A FUSE WRITE of max_write (1 MiB) fits a request: fuse_in_header (40)
// and fuse_write_in (40) before the data; a READ reply of 1 MiB fits after
// its fuse_out_header (16). An empty InFlight takes any request: one
// payload is below the in-flight budget.
const _: () = assert!(40 + 40 + (1 << 20) <= MAX_PAYLOAD_LEN);
const _: () = assert!(16 + (1 << 20) <= MAX_PAYLOAD_LEN);
const _: () = assert!(MAX_FRAME_LEN <= u32::MAX as usize);
const _: () = assert!((MAX_PAYLOAD_LEN as u64) < MAX_IN_FLIGHT_REPLY_BYTES);

/// A hello's payload before the id: version, flags, id length.
const HELLO_FIXED_LEN: usize = 4 + 4 + 1;

const KIND_HELLO: u16 = 1;
const KIND_REQUEST: u16 = 2;
const KIND_REPLY: u16 = 3;

/// What a frame is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The first frame each side sends.
    Hello,
    /// A descriptor chain's readable bytes, VMM → server.
    Request,
    /// The bytes for a request's chain, server → VMM.
    Reply,
}

impl Kind {
    fn from_wire(value: u16) -> Option<Kind> {
        match value {
            KIND_HELLO => Some(Kind::Hello),
            KIND_REQUEST => Some(Kind::Request),
            KIND_REPLY => Some(Kind::Reply),
            _ => None,
        }
    }

    fn to_wire(self) -> u16 {
        match self {
            Kind::Hello => KIND_HELLO,
            Kind::Request => KIND_REQUEST,
            Kind::Reply => KIND_REPLY,
        }
    }
}

/// Which side sent the bytes being parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    /// The virtio-fs device in Firecracker.
    Vmm,
    /// wick-fsd.
    Server,
}

impl Sender {
    fn may_send(self, kind: Kind) -> bool {
        matches!(
            (self, kind),
            (_, Kind::Hello) | (Sender::Vmm, Kind::Request) | (Sender::Server, Kind::Reply)
        )
    }
}

/// Why a frame was refused. Every one ends the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// `len` is below the header's size or above [`MAX_FRAME_LEN`].
    Length(u64),
    /// `kind` is none of hello, request, reply.
    UnknownKind(u16),
    /// A kind the sender never sends (a request from the server, a reply
    /// from the VMM).
    WrongSender(Kind, Sender),
    /// A field that must be 0 is not, or the cookie is 0 where it must not be.
    Field(Kind, &'static str, u64),
    /// A request's `writable_cap` is above [`MAX_PAYLOAD_LEN`].
    WritableCap(u64),
    /// A hello that is not well formed.
    Hello(&'static str),
    /// The peer speaks another protocol version.
    Version {
        /// Ours, [`PROTOCOL_VERSION`].
        ours: u32,
        /// The peer's.
        theirs: u32,
    },
    /// A share id with a character outside `[A-Za-z0-9_-]`, empty or longer
    /// than [`MAX_ID_LEN`].
    BadId,
    /// The peer serves, or asks for, another share.
    OtherShare,
    /// A reply whose cookie is not a request waiting for one: never sent, a
    /// request that gets no reply, or answered already.
    UnknownCookie(u64),
    /// A reply longer than its request's chain can take.
    ReplyTooLong {
        /// The reply's payload.
        len: u64,
        /// The request's `writable_cap`.
        cap: u32,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Length(len) => write!(
                f,
                "frame length {len} is outside {HEADER_LEN}..={MAX_FRAME_LEN}"
            ),
            FrameError::UnknownKind(kind) => write!(f, "unknown frame kind {kind}"),
            FrameError::WrongSender(kind, sender) => {
                write!(
                    f,
                    "a {kind:?} frame from the {sender:?}, which never sends one"
                )
            }
            FrameError::Field(kind, field, value) => {
                write!(f, "{kind:?} frame with {field} {value}")
            }
            FrameError::WritableCap(cap) => {
                write!(f, "request writable_cap {cap} is above {MAX_PAYLOAD_LEN}")
            }
            FrameError::Hello(why) => write!(f, "malformed hello: {why}"),
            FrameError::Version { ours, theirs } => {
                write!(f, "peer speaks protocol version {theirs}, this side {ours}")
            }
            FrameError::BadId => write!(
                f,
                "share id must be 1 to {MAX_ID_LEN} characters of [A-Za-z0-9_-]"
            ),
            FrameError::OtherShare => write!(f, "the peer is for another share"),
            FrameError::UnknownCookie(cookie) => {
                write!(f, "reply to cookie {cookie}, which no request waits on")
            }
            FrameError::ReplyTooLong { len, cap } => {
                write!(f, "reply of {len} bytes for a chain that takes {cap}")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// A frame header that has passed every check of its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    len: u32,
    kind: Kind,
    queue: u16,
    cookie: u64,
    writable_cap: u32,
}

fn frame_len(payload_len: usize) -> Result<u32, FrameError> {
    let len = payload_len.saturating_add(HEADER_LEN);
    if len > MAX_FRAME_LEN {
        return Err(FrameError::Length(u64::try_from(len).unwrap_or(u64::MAX)));
    }
    u32::try_from(len).map_err(|_| FrameError::Length(u64::MAX))
}

impl Header {
    /// A hello's header, for a payload of `payload_len` bytes.
    fn hello(payload_len: usize) -> Result<Header, FrameError> {
        Ok(Header {
            len: frame_len(payload_len)?,
            kind: Kind::Hello,
            queue: 0,
            cookie: 0,
            writable_cap: 0,
        })
    }

    /// A request's header: `cookie` from [`InFlight::start`], the chain's
    /// `queue`, the `writable_cap` given to [`InFlight::start`], and the
    /// chain's readable bytes as the payload.
    pub fn request(
        cookie: u64,
        queue: u16,
        writable_cap: u32,
        payload_len: usize,
    ) -> Result<Header, FrameError> {
        let header = Header {
            len: frame_len(payload_len)?,
            kind: Kind::Request,
            queue,
            cookie,
            writable_cap,
        };
        header.check()?;
        Ok(header)
    }

    /// A reply's header, for the request `cookie`.
    pub fn reply(cookie: u64, payload_len: usize) -> Result<Header, FrameError> {
        let header = Header {
            len: frame_len(payload_len)?,
            kind: Kind::Reply,
            queue: 0,
            cookie,
            writable_cap: 0,
        };
        header.check()?;
        Ok(header)
    }

    /// The rules of each kind's fields.
    fn check(&self) -> Result<(), FrameError> {
        let field = |name, value| Err(FrameError::Field(self.kind, name, value));
        match self.kind {
            Kind::Hello => {
                if self.queue != 0 {
                    return field("queue", u64::from(self.queue));
                }
                if self.cookie != 0 {
                    return field("cookie", self.cookie);
                }
                if self.writable_cap != 0 {
                    return field("writable_cap", u64::from(self.writable_cap));
                }
            }
            Kind::Request => {
                if self.cookie == 0 {
                    return field("cookie", 0);
                }
                if self.writable_cap as usize > MAX_PAYLOAD_LEN {
                    return Err(FrameError::WritableCap(u64::from(self.writable_cap)));
                }
            }
            Kind::Reply => {
                if self.queue != 0 {
                    return field("queue", u64::from(self.queue));
                }
                if self.cookie == 0 {
                    return field("cookie", 0);
                }
                if self.writable_cap != 0 {
                    return field("writable_cap", u64::from(self.writable_cap));
                }
            }
        }
        Ok(())
    }

    /// Checks the header `sender` sent: its length, its kind, that `sender`
    /// sends that kind, and the rules of that kind's fields. It needs only
    /// the header, so a frame too long is refused before its payload is
    /// buffered.
    pub fn parse(bytes: &[u8; HEADER_LEN], sender: Sender) -> Result<Header, FrameError> {
        let [
            l0,
            l1,
            l2,
            l3,
            k0,
            k1,
            q0,
            q1,
            c0,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            c7,
            w0,
            w1,
            w2,
            w3,
            r0,
            r1,
            r2,
            r3,
        ] = *bytes;
        let len = u32::from_le_bytes([l0, l1, l2, l3]);
        if (len as usize) < HEADER_LEN || len as usize > MAX_FRAME_LEN {
            return Err(FrameError::Length(u64::from(len)));
        }
        let raw_kind = u16::from_le_bytes([k0, k1]);
        let kind = Kind::from_wire(raw_kind).ok_or(FrameError::UnknownKind(raw_kind))?;
        if !sender.may_send(kind) {
            return Err(FrameError::WrongSender(kind, sender));
        }
        let reserved = u32::from_le_bytes([r0, r1, r2, r3]);
        if reserved != 0 {
            return Err(FrameError::Field(kind, "reserved", u64::from(reserved)));
        }
        let header = Header {
            len,
            kind,
            queue: u16::from_le_bytes([q0, q1]),
            cookie: u64::from_le_bytes([c0, c1, c2, c3, c4, c5, c6, c7]),
            writable_cap: u32::from_le_bytes([w0, w1, w2, w3]),
        };
        header.check()?;
        Ok(header)
    }

    /// The header's bytes on the wire.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.len.to_le_bytes());
        out[4..6].copy_from_slice(&self.kind.to_wire().to_le_bytes());
        out[6..8].copy_from_slice(&self.queue.to_le_bytes());
        out[8..16].copy_from_slice(&self.cookie.to_le_bytes());
        out[16..20].copy_from_slice(&self.writable_cap.to_le_bytes());
        out
    }

    /// The whole frame's length, header included.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Never true: a frame is at least its header. Here for clippy's
    /// `len_without_is_empty`.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The payload's length.
    pub fn payload_len(&self) -> usize {
        self.len() - HEADER_LEN
    }

    /// What the frame is.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// A request's virtqueue; 0 for the others.
    pub fn queue(&self) -> u16 {
        self.queue
    }

    /// A request's or reply's cookie; 0 for a hello.
    pub fn cookie(&self) -> u64 {
        self.cookie
    }

    /// The bytes a request's chain takes back; 0 for the others.
    pub fn writable_cap(&self) -> u32 {
        self.writable_cap
    }
}

/// A whole frame, borrowed from the receive buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Its checked header.
    pub header: Header,
    /// Its `header.payload_len()` bytes.
    pub payload: &'a [u8],
}

/// The first frame at the start of `buf`, which `sender` sent: `Ok(None)`
/// while `buf` holds less than the whole frame, the frame once it does. The
/// caller drops `frame.header.len()` bytes from the front of `buf` after
/// using it. The header is checked as soon as its 24 bytes are in, so a
/// frame that will be refused never makes the caller buffer its payload.
pub fn parse(buf: &[u8], sender: Sender) -> Result<Option<Frame<'_>>, FrameError> {
    let Some(head) = buf.first_chunk::<HEADER_LEN>() else {
        return Ok(None);
    };
    let header = Header::parse(head, sender)?;
    Ok(buf
        .get(HEADER_LEN..header.len())
        .map(|payload| Frame { header, payload }))
}

/// Checks a share id: 1 to [`MAX_ID_LEN`] characters of `[A-Za-z0-9_-]`. The
/// id becomes part of file names (the jail's `fs-<id>.sock`), so nothing
/// else is allowed.
pub fn check_id(id: &str) -> Result<(), FrameError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok { Ok(()) } else { Err(FrameError::BadId) }
}

/// The hello for the share `id`, as a whole frame.
pub fn hello_frame(id: &str) -> Result<Vec<u8>, FrameError> {
    check_id(id)?;
    let payload_len = HELLO_FIXED_LEN + id.len();
    let header = Header::hello(payload_len)?;
    let mut frame = Vec::with_capacity(header.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    // Flags: none yet. A later version that adds one also raises the version.
    frame.extend_from_slice(&0u32.to_le_bytes());
    // check_id bounds the length to MAX_ID_LEN, which fits a byte.
    frame.push(u8::try_from(id.len()).map_err(|_| FrameError::BadId)?);
    frame.extend_from_slice(id.as_bytes());
    Ok(frame)
}

/// A peer's hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello<'a> {
    /// The protocol version the peer speaks.
    pub version: u32,
    /// The share the peer serves (server) or asks for (VMM).
    pub id: &'a str,
}

/// Reads a hello frame.
pub fn parse_hello<'a>(frame: &Frame<'a>) -> Result<Hello<'a>, FrameError> {
    if frame.header.kind() != Kind::Hello {
        return Err(FrameError::Hello("the first frame is not a hello"));
    }
    let Some((fixed, id)) = frame.payload.split_first_chunk::<HELLO_FIXED_LEN>() else {
        return Err(FrameError::Hello("shorter than its fixed part"));
    };
    let [v0, v1, v2, v3, f0, f1, f2, f3, id_len] = *fixed;
    let version = u32::from_le_bytes([v0, v1, v2, v3]);
    // Another version may lay the rest out differently: compared first, so a
    // newer peer gets a version error, not a malformed one.
    if version != PROTOCOL_VERSION {
        return Ok(Hello { version, id: "" });
    }
    if u32::from_le_bytes([f0, f1, f2, f3]) != 0 {
        return Err(FrameError::Hello("flags are not 0"));
    }
    if id.len() != usize::from(id_len) {
        return Err(FrameError::Hello("id length does not match the frame"));
    }
    let id = std::str::from_utf8(id).map_err(|_| FrameError::BadId)?;
    check_id(id)?;
    Ok(Hello { version, id })
}

/// Checks the peer's hello against this side's protocol version and share
/// `id`.
pub fn check_hello(frame: &Frame<'_>, id: &str) -> Result<(), FrameError> {
    let hello = parse_hello(frame)?;
    if hello.version != PROTOCOL_VERSION {
        return Err(FrameError::Version {
            ours: PROTOCOL_VERSION,
            theirs: hello.version,
        });
    }
    if hello.id != id {
        return Err(FrameError::OtherShare);
    }
    Ok(())
}

/// The largest `writable_cap` a request can have for a chain whose writable
/// buffers hold `writable` bytes. A reply never needs more: it fits in one
/// frame.
pub fn clamp_writable(writable: u64) -> u32 {
    // MAX_PAYLOAD_LEN fits a u32 (a test checks it).
    u32::try_from(writable.min(MAX_PAYLOAD_LEN as u64)).unwrap_or(u32::MAX)
}

/// The VMM cannot take another request now: too many are waiting, or their
/// replies could need more than [`MAX_IN_FLIGHT_REPLY_BYTES`]. The device
/// leaves the chain on its queue and tries again after a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// The VMM's requests that wait for a reply.
#[derive(Debug)]
pub struct InFlight {
    /// Cookie → the request's `writable_cap`.
    waiting: BTreeMap<u64, u32>,
    /// The sum of `waiting`'s caps.
    reserved: u64,
    max_requests: usize,
    next_cookie: u64,
}

impl InFlight {
    /// A tracker that lets at most `max_requests` (at least 1) requests wait
    /// at once: the device's queue sizes added up.
    pub fn new(max_requests: usize) -> InFlight {
        InFlight {
            waiting: BTreeMap::new(),
            reserved: 0,
            max_requests: max_requests.max(1),
            next_cookie: 1,
        }
    }

    fn cookie(&mut self) -> u64 {
        loop {
            let cookie = self.next_cookie;
            self.next_cookie = self.next_cookie.wrapping_add(1).max(1);
            if cookie != 0 && !self.waiting.contains_key(&cookie) {
                return cookie;
            }
        }
    }

    /// The cookie for a new request whose chain takes `writable_cap` bytes
    /// back ([`clamp_writable`]). A request with `writable_cap` 0 gets a
    /// cookie but waits for nothing: a reply to it is refused. [`Full`] when
    /// the request would exceed a limit; an empty tracker always takes a
    /// request, so a single request never waits for good.
    pub fn start(&mut self, writable_cap: u32) -> Result<u64, Full> {
        if writable_cap as usize > MAX_PAYLOAD_LEN {
            // A caller that skipped clamp_writable: never a frame.
            return Err(Full);
        }
        if writable_cap == 0 {
            return Ok(self.cookie());
        }
        let reserved = self.reserved + u64::from(writable_cap);
        if self.waiting.len() >= self.max_requests || reserved > MAX_IN_FLIGHT_REPLY_BYTES {
            return Err(Full);
        }
        let cookie = self.cookie();
        self.waiting.insert(cookie, writable_cap);
        self.reserved = reserved;
        Ok(cookie)
    }

    /// Takes a reply's header: the request it answers stops waiting, and its
    /// `writable_cap` is returned. Refused (and the connection is then
    /// closed) for a header that is not a reply, a cookie no request waits on
    /// (never sent, a request without reply, answered already) and a payload
    /// longer than the request's chain takes.
    pub fn finish(&mut self, header: &Header) -> Result<u32, FrameError> {
        if header.kind() != Kind::Reply {
            return Err(FrameError::WrongSender(header.kind(), Sender::Server));
        }
        let cap = self
            .waiting
            .remove(&header.cookie())
            .ok_or_else(|| FrameError::UnknownCookie(header.cookie()))?;
        self.reserved -= u64::from(cap);
        if header.payload_len() > cap as usize {
            return Err(FrameError::ReplyTooLong {
                len: u64::try_from(header.payload_len()).unwrap_or(u64::MAX),
                cap,
            });
        }
        Ok(cap)
    }

    /// Requests waiting for a reply.
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    /// No request waits for a reply.
    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// The sum of the waiting requests' `writable_cap`.
    pub fn reserved(&self) -> u64 {
        self.reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(
        len: u32,
        kind: u16,
        queue: u16,
        cookie: u64,
        cap: u32,
        reserved: u32,
    ) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&len.to_le_bytes());
        out[4..6].copy_from_slice(&kind.to_le_bytes());
        out[6..8].copy_from_slice(&queue.to_le_bytes());
        out[8..16].copy_from_slice(&cookie.to_le_bytes());
        out[16..20].copy_from_slice(&cap.to_le_bytes());
        out[20..24].copy_from_slice(&reserved.to_le_bytes());
        out
    }

    fn frame(header: &Header, payload: &[u8]) -> Vec<u8> {
        let mut out = header.encode().to_vec();
        out.extend_from_slice(payload);
        out
    }

    fn u32_of(value: usize) -> u32 {
        u32::try_from(value).unwrap()
    }

    fn max_frame() -> u32 {
        u32_of(MAX_FRAME_LEN)
    }

    fn max_payload() -> u32 {
        u32_of(MAX_PAYLOAD_LEN)
    }

    #[test]
    fn test_limits_fit_their_users() {
        // The compile-time checks next to the constants hold; MAX_FRAME_LEN
        // fits a frame's u32 length.
        assert_eq!(usize::try_from(max_frame()).unwrap(), MAX_FRAME_LEN);
        assert_eq!(clamp_writable(u64::MAX) as usize, MAX_PAYLOAD_LEN);
        assert_eq!(clamp_writable(4096), 4096);
    }

    #[test]
    fn test_request_and_reply_round_trip() {
        let request = Header::request(7, 1, 4096, 80).unwrap();
        let bytes = request.encode();
        assert_eq!(Header::parse(&bytes, Sender::Vmm), Ok(request));
        assert_eq!(request.len(), HEADER_LEN + 80);
        assert_eq!(request.payload_len(), 80);
        assert_eq!(
            (
                request.kind(),
                request.queue(),
                request.cookie(),
                request.writable_cap()
            ),
            (Kind::Request, 1, 7, 4096)
        );

        let reply = Header::reply(7, 16).unwrap();
        assert_eq!(Header::parse(&reply.encode(), Sender::Server), Ok(reply));
        assert_eq!((reply.queue(), reply.writable_cap()), (0, 0));

        // The exact bytes of the documented layout.
        assert_eq!(bytes, raw(104, 2, 1, 7, 4096, 0));
    }

    #[test]
    fn test_parse_waits_for_the_whole_frame() {
        let header = Header::request(1, 1, 16, 5).unwrap();
        let bytes = frame(&header, b"hello");
        for cut in 0..bytes.len() {
            assert_eq!(parse(&bytes[..cut], Sender::Vmm), Ok(None), "cut at {cut}");
        }
        let mut more = bytes.clone();
        more.extend_from_slice(b"next frame");
        let got = parse(&more, Sender::Vmm).unwrap().unwrap();
        assert_eq!(got.header, header);
        assert_eq!(got.payload, b"hello");
    }

    #[test]
    fn test_length_is_refused_from_the_header_alone() {
        // Too short to hold its own header, and over the maximum: refused
        // with only the 24 header bytes in, before any payload is buffered.
        for len in [0, 1, u32_of(HEADER_LEN) - 1, max_frame() + 1, u32::MAX] {
            let bytes = raw(len, 2, 0, 1, 0, 0);
            assert_eq!(
                parse(&bytes, Sender::Vmm),
                Err(FrameError::Length(u64::from(len)))
            );
        }
        Header::parse(&raw(max_frame(), 2, 0, 1, 0, 0), Sender::Vmm).unwrap();
        Header::parse(&raw(u32_of(HEADER_LEN), 2, 0, 1, 0, 0), Sender::Vmm).unwrap();
        assert_eq!(
            Header::request(1, 0, 0, MAX_PAYLOAD_LEN + 1),
            Err(FrameError::Length(MAX_FRAME_LEN as u64 + 1))
        );
        assert_eq!(
            Header::reply(1, usize::MAX),
            Err(FrameError::Length(u64::MAX))
        );
    }

    #[test]
    fn test_kind_and_sender() {
        for kind in [0, 4, u16::MAX] {
            assert_eq!(
                Header::parse(&raw(24, kind, 0, 1, 0, 0), Sender::Vmm),
                Err(FrameError::UnknownKind(kind))
            );
        }
        // A request from the server, a reply from the VMM.
        assert_eq!(
            Header::parse(&raw(24, 2, 0, 1, 0, 0), Sender::Server),
            Err(FrameError::WrongSender(Kind::Request, Sender::Server))
        );
        assert_eq!(
            Header::parse(&raw(24, 3, 0, 1, 0, 0), Sender::Vmm),
            Err(FrameError::WrongSender(Kind::Reply, Sender::Vmm))
        );
        Header::parse(&raw(33, 1, 0, 0, 0, 0), Sender::Vmm).unwrap();
        Header::parse(&raw(33, 1, 0, 0, 0, 0), Sender::Server).unwrap();
    }

    #[test]
    fn test_field_rules() {
        let field = |kind, name, value| Err(FrameError::Field(kind, name, value));
        // Reserved bytes, in every kind.
        for (kind, sender, cookie) in [
            (1, Sender::Vmm, 0),
            (2, Sender::Vmm, 1),
            (3, Sender::Server, 1),
        ] {
            assert!(matches!(
                Header::parse(&raw(33, kind, 0, cookie, 0, 1), sender),
                Err(FrameError::Field(_, "reserved", 1))
            ));
        }
        // Requests: cookie never 0; writable_cap at most MAX_PAYLOAD_LEN; any queue.
        assert_eq!(
            Header::parse(&raw(24, 2, 0, 0, 0, 0), Sender::Vmm),
            field(Kind::Request, "cookie", 0)
        );
        let over = max_payload() + 1;
        assert_eq!(
            Header::parse(&raw(24, 2, 0, 1, over, 0), Sender::Vmm),
            Err(FrameError::WritableCap(u64::from(over)))
        );
        assert_eq!(
            Header::request(1, 0, over, 0),
            Err(FrameError::WritableCap(u64::from(over)))
        );
        Header::parse(&raw(24, 2, u16::MAX, 1, max_payload(), 0), Sender::Vmm).unwrap();
        // Replies: cookie never 0, no queue, no writable_cap.
        assert_eq!(
            Header::parse(&raw(24, 3, 0, 0, 0, 0), Sender::Server),
            field(Kind::Reply, "cookie", 0)
        );
        assert_eq!(
            Header::parse(&raw(24, 3, 1, 1, 0, 0), Sender::Server),
            field(Kind::Reply, "queue", 1)
        );
        assert_eq!(
            Header::parse(&raw(24, 3, 0, 1, 9, 0), Sender::Server),
            field(Kind::Reply, "writable_cap", 9)
        );
        assert_eq!(Header::reply(0, 0), field(Kind::Reply, "cookie", 0));
        // Hellos: no queue, cookie or writable_cap.
        assert_eq!(
            Header::parse(&raw(33, 1, 1, 0, 0, 0), Sender::Vmm),
            field(Kind::Hello, "queue", 1)
        );
        assert_eq!(
            Header::parse(&raw(33, 1, 0, 5, 0, 0), Sender::Vmm),
            field(Kind::Hello, "cookie", 5)
        );
        assert_eq!(
            Header::parse(&raw(33, 1, 0, 0, 5, 0), Sender::Vmm),
            field(Kind::Hello, "writable_cap", 5)
        );
    }

    fn hello_of(bytes: &[u8]) -> Result<(), FrameError> {
        let got = parse(bytes, Sender::Server)?.ok_or(FrameError::Hello("incomplete"))?;
        check_hello(&got, "docs")
    }

    #[test]
    fn test_hello() {
        let bytes = hello_frame("docs").unwrap();
        assert_eq!(bytes.len(), HEADER_LEN + HELLO_FIXED_LEN + 4);
        let got = parse(&bytes, Sender::Vmm).unwrap().unwrap();
        assert_eq!(
            parse_hello(&got),
            Ok(Hello {
                version: PROTOCOL_VERSION,
                id: "docs"
            })
        );
        assert_eq!(hello_of(&bytes), Ok(()));
        // Another share.
        assert_eq!(
            hello_of(&hello_frame("doc").unwrap()),
            Err(FrameError::OtherShare)
        );
        assert_eq!(
            hello_of(&hello_frame("docs2").unwrap()),
            Err(FrameError::OtherShare)
        );

        // Another version, whatever follows it.
        let mut other = bytes.clone();
        other[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            hello_of(&other),
            Err(FrameError::Version { ours: 1, theirs: 2 })
        );

        // Flags set.
        let mut flags = bytes.clone();
        flags[HEADER_LEN + 4] = 1;
        assert_eq!(hello_of(&flags), Err(FrameError::Hello("flags are not 0")));

        // The id length byte disagrees with the frame, both ways.
        for id_len in [3u8, 5, 0, u8::MAX] {
            let mut bad = bytes.clone();
            bad[HEADER_LEN + 8] = id_len;
            assert_eq!(
                hello_of(&bad),
                Err(FrameError::Hello("id length does not match the frame"))
            );
        }

        // Shorter than its fixed part.
        let short = frame(
            &Header::hello(HELLO_FIXED_LEN - 1).unwrap(),
            &[1, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            hello_of(&short),
            Err(FrameError::Hello("shorter than its fixed part"))
        );

        // An id that is not one: not UTF-8, a path, a dot.
        for id in [&b"\xff\xfe"[..], b"a/b", b"..", b"a b", b""] {
            let mut payload = PROTOCOL_VERSION.to_le_bytes().to_vec();
            payload.extend_from_slice(&[0, 0, 0, 0, u8::try_from(id.len()).unwrap()]);
            payload.extend_from_slice(id);
            let bad = frame(&Header::hello(payload.len()).unwrap(), &payload);
            assert_eq!(hello_of(&bad), Err(FrameError::BadId), "id {id:?}");
        }

        // A request where the hello must be.
        let request = frame(&Header::request(1, 1, 0, 0).unwrap(), &[]);
        let got = parse(&request, Sender::Vmm).unwrap().unwrap();
        assert_eq!(
            check_hello(&got, "docs"),
            Err(FrameError::Hello("the first frame is not a hello"))
        );
    }

    #[test]
    fn test_share_ids() {
        for id in ["a", "docs", "A-b_9", &"x".repeat(MAX_ID_LEN)] {
            assert_eq!(check_id(id), Ok(()), "{id}");
        }
        for id in [
            "",
            ".",
            "..",
            "a/b",
            "a.b",
            "a b",
            "é",
            "a\0",
            &"x".repeat(MAX_ID_LEN + 1),
        ] {
            assert_eq!(check_id(id), Err(FrameError::BadId), "{id:?}");
            assert_eq!(hello_frame(id), Err(FrameError::BadId), "{id:?}");
        }
    }

    #[test]
    fn test_inflight_cookies() {
        let mut inflight = InFlight::new(8);
        let a = inflight.start(100).unwrap();
        let b = inflight.start(0).unwrap();
        let c = inflight.start(200).unwrap();
        assert!(a != 0 && b != 0 && c != 0);
        assert!(a != b && b != c && a != c);
        // The request without reply does not wait.
        assert_eq!((inflight.len(), inflight.reserved()), (2, 300));

        // A reply to it, to a cookie never given and to 0's neighbours.
        let reply = |cookie, len| Header::reply(cookie, len).unwrap();
        assert_eq!(
            inflight.finish(&reply(b, 0)),
            Err(FrameError::UnknownCookie(b))
        );
        assert_eq!(
            inflight.finish(&reply(999, 0)),
            Err(FrameError::UnknownCookie(999))
        );

        assert_eq!(inflight.finish(&reply(a, 100)), Ok(100));
        // Answered already.
        assert_eq!(
            inflight.finish(&reply(a, 0)),
            Err(FrameError::UnknownCookie(a))
        );
        assert_eq!((inflight.len(), inflight.reserved()), (1, 200));

        // Longer than the chain takes: refused, and the request is gone.
        assert_eq!(
            inflight.finish(&reply(c, 201)),
            Err(FrameError::ReplyTooLong { len: 201, cap: 200 })
        );
        assert!(inflight.is_empty());
        assert_eq!(inflight.reserved(), 0);

        // Only a reply is a reply.
        let d = inflight.start(10).unwrap();
        let request = Header::request(d, 0, 10, 0).unwrap();
        assert_eq!(
            inflight.finish(&request),
            Err(FrameError::WrongSender(Kind::Request, Sender::Server))
        );
    }

    #[test]
    fn test_inflight_limits() {
        // The byte budget: 16 requests of 1 MiB fill it, the 17th waits.
        let mib = 1 << 20;
        let mut inflight = InFlight::new(256);
        let mut cookies = Vec::new();
        for _ in 0..MAX_IN_FLIGHT_REPLY_BYTES / u64::from(mib) {
            cookies.push(inflight.start(mib).unwrap());
        }
        assert_eq!(inflight.reserved(), MAX_IN_FLIGHT_REPLY_BYTES);
        assert_eq!(inflight.start(1), Err(Full));
        // A request without reply needs no room.
        inflight.start(0).unwrap();
        // A reply frees its room.
        inflight
            .finish(&Header::reply(cookies[0], 0).unwrap())
            .unwrap();
        inflight.start(mib).unwrap();
        assert_eq!(inflight.start(1), Err(Full));

        // The request count.
        let mut inflight = InFlight::new(2);
        let first = inflight.start(1).unwrap();
        inflight.start(1).unwrap();
        assert_eq!(inflight.start(1), Err(Full));
        inflight.finish(&Header::reply(first, 1).unwrap()).unwrap();
        inflight.start(1).unwrap();

        // An empty tracker always takes the largest request; a tracker of 0
        // requests is one of 1.
        let mut inflight = InFlight::new(0);
        inflight.start(max_payload()).unwrap();
        assert_eq!(inflight.start(1), Err(Full));
        // A cap no frame can carry is never taken.
        assert_eq!(InFlight::new(4).start(max_payload() + 1), Err(Full));
    }

    #[test]
    fn test_inflight_cookie_wraps_past_zero_and_waiting() {
        let mut inflight = InFlight::new(4);
        inflight.next_cookie = u64::MAX;
        let last = inflight.start(1).unwrap();
        assert_eq!(last, u64::MAX);
        // 0 is skipped.
        assert_eq!(inflight.start(1).unwrap(), 1);
        // A cookie still waiting is skipped.
        inflight.next_cookie = u64::MAX;
        assert_eq!(inflight.start(1).unwrap(), 2);
    }
}
