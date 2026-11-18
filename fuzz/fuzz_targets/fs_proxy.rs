// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The virtio-fs device's decisions (`crates/ext/src/fs/copy.rs`,
//! docs/design-fs.md §4.1) under any sequence of guest chains and server
//! frames: a hostile guest builds the chains, a server taken over sends
//! anything, as reply frames with any header inside.
//!
//! Checked against a model kept here:
//! - a chain is sent as a request frame exactly when it is within a frame's
//!   bounds and its writable part is none or holds a `fuse_out_header`; the
//!   frame carries the chain's readable bytes unchanged, its queue and its
//!   writable part clamped to a frame; it waits for a reply exactly when it
//!   has a writable part;
//! - any other chain is answered by the device: `-EIO` with the request's
//!   `unique` where 16 bytes fit, nothing where they do not;
//! - a reply goes to its chain exactly when its cookie waits, it fits the
//!   chain, and its `fuse_out_header` has the frame's length and the
//!   request's `unique`; then its bytes are the reply's, unchanged;
//! - any other reply loses the server: every waiting chain is answered once
//!   with `-EIO` and its own `unique`, and from then on every chain is
//!   answered by the device, nothing sent;
//! - no chain is answered twice, none is forgotten (the waiting count is
//!   the model's), and no answer is longer than its chain's writable part.

#![no_main]

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fs_frame::{Frame, Header, Kind, MAX_PAYLOAD_LEN, Sender, clamp_writable, parse};
use wick_fuzz::fs_copy::{Answer, Chain, OUT_HEADER_LEN, Proxy, Refusal, Taken, eio, unique_of};

#[derive(Arbitrary, Debug)]
enum Op {
    /// A chain: `readable` bytes (`extra` more said than given past a
    /// frame's bound when `long`), and `writable` bytes to write back.
    Chain { hiprio: bool, readable: Vec<u8>, long: bool, extra: u16, writable: u32, huge: bool },
    /// A reply to the `pick`th waiting request (or to `other` past them),
    /// built as `shape` says.
    Reply { pick: u8, other: u64, shape: Shape, extra: Vec<u8> },
    /// The connection ends.
    Lose,
}

#[derive(Arbitrary, Debug)]
enum Shape {
    /// A correct header: `len`, error, the request's `unique`.
    Good { error: i32 },
    /// The same with an error near the range a reply's may take
    /// (-511..=0): `-(errno % 1024)`.
    Errno { errno: u16 },
    /// A header whose `len` is off by `delta`.
    BadLen { delta: i8 },
    /// Another `unique`.
    BadUnique { unique: u64 },
    /// Shorter than a header.
    Short { len: u8 },
}

#[derive(Debug)]
struct Waiting {
    unique: [u8; 8],
    writable: u64,
    queue: u16,
    head: u16,
}

fuzz_target!(|ops: Vec<Op>| {
    let mut proxy = Proxy::new(8);
    let mut waiting: BTreeMap<u64, Waiting> = BTreeMap::new();
    let mut lost = false;
    let mut head = 0u16;
    for op in ops.into_iter().take(256) {
        match op {
            Op::Chain { hiprio, readable, long, extra, writable, huge } => {
                head = head.wrapping_add(1);
                let readable_len = readable.len() as u64 + if long { MAX_PAYLOAD_LEN as u64 + u64::from(extra) } else { 0 };
                let writable = if huge { u64::from(writable) << 16 } else { u64::from(writable) };
                let chain = Chain { queue: u16::from(!hiprio), head, readable: &readable, readable_len, writable };
                let unique = unique_of(&readable);
                let refusal_bytes = if writable >= OUT_HEADER_LEN as u64 { eio(unique) } else { Vec::new() };
                let fits = readable_len <= MAX_PAYLOAD_LEN as u64 && readable.len() as u64 == readable_len;
                let short = writable > 0 && writable < OUT_HEADER_LEN as u64;
                match proxy.take(&chain) {
                    (Taken::Send { frame, cookie, waits }, None) => {
                        assert!(!lost && fits && !short);
                        let f = parse(&frame, Sender::Vmm).unwrap().unwrap();
                        assert_eq!(f.header.len(), frame.len());
                        assert_eq!(f.header.kind(), Kind::Request);
                        assert_eq!(f.header.cookie(), cookie);
                        assert_eq!(f.header.queue(), chain.queue);
                        assert_eq!(f.header.writable_cap(), clamp_writable(writable));
                        assert_eq!(f.payload, &readable[..]);
                        assert_eq!(waits, writable > 0);
                        if waits {
                            let old = waiting.insert(cookie, Waiting { unique, writable, queue: chain.queue, head });
                            assert!(old.is_none(), "cookie {cookie} handed out twice");
                        }
                    }
                    (Taken::Answer(bytes), Some(why)) => {
                        match why {
                            Refusal::Lost => assert!(lost),
                            Refusal::TooLong => assert!(!lost && !fits),
                            Refusal::ShortWritable => assert!(!lost && fits && short),
                        }
                        if why == Refusal::ShortWritable {
                            assert!(bytes.is_empty());
                        } else {
                            assert_eq!(bytes, refusal_bytes);
                        }
                    }
                    (Taken::Full, None) => assert!(!lost && fits && !short && writable > 0),
                    other => panic!("{other:?}"),
                }
            }
            Op::Reply { pick, other, shape, extra } => {
                let target = waiting.keys().nth(usize::from(pick)).copied();
                let cookie = target.unwrap_or(other);
                let expected_unique = waiting.get(&cookie).map(|w| w.unique).unwrap_or([0; 8]);
                let mut payload = Vec::new();
                let (len_ok, unique_ok, error_ok) = match shape {
                    Shape::Good { .. } | Shape::Errno { .. } => {
                        let error = match shape {
                            Shape::Errno { errno } => -(i32::from(errno) % 1024),
                            Shape::Good { error } => error,
                            _ => unreachable!(),
                        };
                        payload.extend_from_slice(&0u32.to_le_bytes());
                        payload.extend_from_slice(&error.to_le_bytes());
                        payload.extend_from_slice(&expected_unique);
                        payload.extend_from_slice(&extra);
                        let len = u32::try_from(payload.len()).unwrap();
                        payload[..4].copy_from_slice(&len.to_le_bytes());
                        // 5364d081125a's verify_response: -511..=0, and an
                        // error reply is the header alone.
                        (true, true, (-511..=0).contains(&error) && (error == 0 || extra.is_empty()))
                    }
                    Shape::BadLen { delta } => {
                        let delta = if delta == 0 { 1 } else { delta };
                        payload.extend_from_slice(&[0; 4]);
                        payload.extend_from_slice(&0i32.to_le_bytes());
                        payload.extend_from_slice(&expected_unique);
                        payload.extend_from_slice(&extra);
                        let len = i64::try_from(payload.len()).unwrap() + i64::from(delta);
                        payload[..4].copy_from_slice(&(len as u32).to_le_bytes());
                        (false, true, true)
                    }
                    Shape::BadUnique { unique } => {
                        let unique = if unique.to_le_bytes() == expected_unique { unique ^ 1 } else { unique };
                        payload.extend_from_slice(&16u32.to_le_bytes());
                        payload.extend_from_slice(&0i32.to_le_bytes());
                        payload.extend_from_slice(&unique.to_le_bytes());
                        (true, false, true)
                    }
                    Shape::Short { len } => {
                        payload.resize(usize::from(len % 16), 0);
                        (false, true, true)
                    }
                };
                let Ok(header) = Header::reply(cookie, payload.len()) else { continue };
                let frame = Frame { header, payload: &payload };
                let good = !lost
                    && waiting.get(&cookie).is_some_and(|w| payload.len() as u64 <= u64::from(clamp_writable(w.writable)))
                    && payload.len() >= OUT_HEADER_LEN
                    && len_ok
                    && unique_ok
                    && error_ok;
                let answers = proxy.reply(&frame);
                if good {
                    let w = waiting.remove(&cookie).unwrap();
                    assert_eq!(answers, vec![Answer { cookie, queue: w.queue, head: w.head, bytes: payload.clone() }]);
                    assert!(proxy.lost().is_none());
                } else {
                    lost = true;
                    check_loss(&mut waiting, answers);
                    assert!(proxy.lost().is_some());
                }
            }
            Op::Lose => {
                let answers = proxy.lose("the connection ended".to_string());
                if lost {
                    assert!(answers.is_empty() && waiting.is_empty());
                }
                lost = true;
                check_loss(&mut waiting, answers);
            }
        }
        assert_eq!(proxy.waiting(), waiting.len());
    }
});

/// Every waiting chain answered once, with `-EIO` and its own `unique`.
fn check_loss(waiting: &mut BTreeMap<u64, Waiting>, answers: Vec<Answer>) {
    assert_eq!(answers.len(), waiting.len());
    for a in answers {
        let w = waiting.remove(&a.cookie).expect("an answer to a chain that did not wait, or twice");
        assert_eq!((a.queue, a.head), (w.queue, w.head));
        assert_eq!(a.bytes, eio(w.unique));
        assert!(a.bytes.len() as u64 <= w.writable);
    }
}
