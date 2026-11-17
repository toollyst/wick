// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `wick_fs_frame`, the frames between the virtio-fs device and wick-fsd
//! (docs/design-fs.md §4.1), on any byte stream either side could be sent:
//! a server taken over writes anything to the VMM, and a hostile guest's
//! bytes reach the server inside requests.
//!
//! Parsing a stream frame by frame must never accept a frame outside the
//! format's bounds or a kind the sender never sends, nor a hello whose share
//! id is not `[a-z0-9_-]`, must hand out exactly
//! the payload the header announces, must re-encode an accepted header to
//! the same bytes, and must ask for more bytes only while the frame is
//! incomplete.
//!
//! The VMM's request tracker, driven by any sequence of requests and
//! replies, must agree with a model written here: the same refusals
//! (`Full` only past the request count or the reply budget, a reply only to
//! a request waiting for one and only within its chain), and never more
//! reply bytes reserved than the budget.

#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fs_frame::{
    FrameError, Full, HEADER_LEN, Header, InFlight, Kind, MAX_FRAME_LEN, MAX_ID_LEN,
    MAX_IN_FLIGHT_REPLY_BYTES, MAX_PAYLOAD_LEN, Sender, check_hello, parse, parse_hello,
};

#[derive(Arbitrary, Debug)]
enum Op {
    /// A request whose chain takes this many bytes back.
    Start(u32),
    /// A reply of `len` bytes to the `pick`th cookie handed out, or to
    /// `other` when `pick` is past them.
    Finish { pick: u8, other: u64, len: u32 },
}

#[derive(Arbitrary, Debug)]
struct Input {
    from_server: bool,
    stream: Vec<u8>,
    max_requests: u8,
    ops: Vec<Op>,
}

fn check_stream(stream: &[u8], sender: Sender) {
    let mut rest = stream;
    loop {
        match parse(rest, sender) {
            Ok(Some(frame)) => {
                let header = frame.header;
                assert!((HEADER_LEN..=MAX_FRAME_LEN).contains(&header.len()));
                assert_eq!(frame.payload.len(), header.payload_len());
                assert_eq!(&header.encode()[..], &rest[..HEADER_LEN]);
                assert_eq!(frame.payload, &rest[HEADER_LEN..header.len()]);
                match header.kind() {
                    Kind::Hello => {
                        assert_eq!((header.queue(), header.cookie(), header.writable_cap()), (0, 0, 0));
                        // An accepted hello's id is 1 to MAX_ID_LEN of `[a-z0-9_-]` (no
                        // capital: ids must not fold together on a host that
                        // ignores case), or empty for another version.
                        if let Ok(hello) = parse_hello(&frame) {
                            assert!(
                                hello.id.len() <= MAX_ID_LEN
                                    && hello.id.bytes().all(|b| {
                                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                                    }),
                                "accepted id {:?}",
                                hello.id
                            );
                        }
                        let _ = check_hello(&frame, "docs");
                    }
                    Kind::Request => {
                        assert_eq!(sender, Sender::Vmm);
                        assert_ne!(header.cookie(), 0);
                        assert!(header.writable_cap() as usize <= MAX_PAYLOAD_LEN);
                    }
                    Kind::Reply => {
                        assert_eq!(sender, Sender::Server);
                        assert_ne!(header.cookie(), 0);
                        assert_eq!((header.queue(), header.writable_cap()), (0, 0));
                    }
                }
                rest = &rest[header.len()..];
            }
            Ok(None) => {
                // More bytes are needed only while the frame is incomplete.
                if let Some(head) = rest.first_chunk::<HEADER_LEN>() {
                    let header = Header::parse(head, sender).expect("parse accepted this header");
                    assert!(rest.len() < header.len());
                }
                return;
            }
            Err(_) => return,
        }
    }
}

fn check_inflight(max_requests: u8, ops: &[Op]) {
    let mut inflight = InFlight::new(usize::from(max_requests));
    let max = usize::from(max_requests).max(1);
    // The model: cookie → cap of each request waiting for a reply.
    let mut waiting: BTreeMap<u64, u32> = BTreeMap::new();
    let mut handed_out: Vec<u64> = Vec::new();
    for op in ops {
        match *op {
            Op::Start(cap) => {
                let reserved: u64 = waiting.values().map(|&c| u64::from(c)).sum();
                let refused = cap as usize > MAX_PAYLOAD_LEN
                    || (cap != 0 && (waiting.len() >= max || reserved + u64::from(cap) > MAX_IN_FLIGHT_REPLY_BYTES));
                match inflight.start(cap) {
                    Ok(cookie) => {
                        assert!(!refused, "took a request past a limit");
                        assert_ne!(cookie, 0);
                        assert!(!waiting.contains_key(&cookie));
                        if cap != 0 {
                            waiting.insert(cookie, cap);
                        }
                        handed_out.push(cookie);
                    }
                    Err(Full) => assert!(refused, "refused a request within the limits"),
                }
            }
            Op::Finish { pick, other, len } => {
                let cookie = handed_out.get(usize::from(pick)).copied().unwrap_or(other);
                let Ok(header) = Header::reply(cookie, len as usize) else {
                    // Cookie 0 or a payload no frame carries: never a reply.
                    assert!(cookie == 0 || len as usize > MAX_PAYLOAD_LEN);
                    continue;
                };
                let got = inflight.finish(&header);
                match waiting.remove(&cookie) {
                    None => assert_eq!(got, Err(FrameError::UnknownCookie(cookie))),
                    Some(cap) if len > cap => {
                        assert_eq!(got, Err(FrameError::ReplyTooLong { len: u64::from(len), cap }))
                    }
                    Some(cap) => assert_eq!(got, Ok(cap)),
                }
            }
        }
        let reserved: u64 = waiting.values().map(|&c| u64::from(c)).sum();
        assert_eq!(inflight.reserved(), reserved);
        assert_eq!(inflight.len(), waiting.len());
        assert!(inflight.reserved() <= MAX_IN_FLIGHT_REPLY_BYTES);
        assert!(inflight.len() <= max);
    }
}

fuzz_target!(|input: Input| {
    let sender = if input.from_server { Sender::Server } else { Sender::Vmm };
    check_stream(&input.stream, sender);
    check_inflight(input.max_requests, &input.ops);
});
