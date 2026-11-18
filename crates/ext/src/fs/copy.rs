// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! What the virtio-fs device does with a descriptor chain and with a reply
//! frame, without guest memory or a socket, so that the `fs_proxy` fuzz
//! target runs exactly this code (docs/design-fs.md §4.1).
//!
//! A chain becomes a request frame (its readable bytes, unparsed), or an
//! answer the device gives the chain itself. A reply frame becomes the bytes
//! for the chain it answers, once checked. The device reads of FUSE only
//! what it needs to give old guest kernels the checks v7.1's driver makes
//! itself (`virtio_fs_verify_response`, Linux 68b69fa0edb2; v6.1 to v7.0
//! trust the reply): bytes 8..16 of each request (`fuse_in_header.unique`)
//! and bytes 0..16 of each reply (`fuse_out_header`: `len` and `unique`).
//! No opcode, no `error`, no argument is read.
//!
//! Once the server is lost (its connection ended or it sent a frame that
//! breaks a rule) every chain waiting for a reply, and every chain taken
//! after, is answered with a `fuse_out_header` of `-EIO`, so the guest's
//! request fails rather than hangs or reads a "success" the server never
//! sent. Nothing reconnects.

use std::collections::BTreeMap;

use wick_fs_frame::{Frame, Header, InFlight, Kind, MAX_PAYLOAD_LEN, clamp_writable};

/// Bytes in a `fuse_out_header` (`len`, `error`, `unique`): the least a
/// reply is, and the answer the device gives a failed request.
pub const OUT_HEADER_LEN: usize = 16;

/// Linux's `EIO`.
const EIO: i32 = 5;

/// A chain as the device read it off a queue.
#[derive(Clone, Copy, Debug)]
pub struct Chain<'a> {
    /// Its queue (0 is the hiprio queue).
    pub queue: u16,
    /// Its head descriptor's index.
    pub head: u16,
    /// Its readable bytes, in order: all of them when [`Chain::readable_len`]
    /// is at most [`MAX_PAYLOAD_LEN`], a prefix otherwise.
    pub readable: &'a [u8],
    /// How many readable bytes the chain has.
    pub readable_len: u64,
    /// How many writable bytes the chain has.
    pub writable: u64,
}

/// What becomes of a chain.
#[derive(Debug, PartialEq, Eq)]
pub enum Taken {
    /// Send `frame` to the server. With `waits`, the chain waits for the
    /// reply; without (a request that gets no reply, as FORGET), it is used
    /// now with length 0.
    Send {
        /// The whole request frame.
        frame: Vec<u8>,
        /// Its cookie, which the reply names.
        cookie: u64,
        /// Whether a reply comes for it.
        waits: bool,
    },
    /// The device answers the chain now: these bytes go into its writable
    /// buffers, and its used length is their count (0 or
    /// [`OUT_HEADER_LEN`]).
    Answer(Vec<u8>),
    /// Over the in-flight limit: the chain goes back on its queue until a
    /// reply comes.
    Full,
}

/// Bytes for a chain that waited: write them into its writable buffers,
/// and its used length is their count.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    /// The request's cookie.
    pub cookie: u64,
    /// The chain's queue.
    pub queue: u16,
    /// The chain's head descriptor's index.
    pub head: u16,
    /// What goes into the chain.
    pub bytes: Vec<u8>,
}

/// Why a chain was answered by the device rather than sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// More readable bytes than a frame carries.
    TooLong,
    /// Writable bytes, but fewer than a `fuse_out_header`.
    ShortWritable,
    /// The server is lost.
    Lost,
}

#[derive(Debug)]
struct Pending {
    queue: u16,
    head: u16,
    unique: [u8; 8],
}

/// The device's side of its requests: cookies, the chains waiting for
/// replies, and whether the server is lost.
#[derive(Debug)]
pub struct Proxy {
    in_flight: InFlight,
    pending: BTreeMap<u64, Pending>,
    lost: Option<String>,
}

/// The `fuse_out_header` the device answers a failed request with:
/// `len` 16, `error` `-EIO` and the request's `unique`.
pub fn eio(unique: [u8; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(OUT_HEADER_LEN);
    // OUT_HEADER_LEN is 16.
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&(-EIO).to_le_bytes());
    out.extend_from_slice(&unique);
    out
}

/// Bytes 8..16 of a request (`fuse_in_header.unique`), or 0 when it is
/// shorter.
pub fn unique_of(request: &[u8]) -> [u8; 8] {
    request
        .get(8..16)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .unwrap_or([0; 8])
}

impl Proxy {
    /// A proxy that lets at most `max_requests` requests wait at once.
    pub fn new(max_requests: usize) -> Proxy {
        Proxy {
            in_flight: InFlight::new(max_requests),
            pending: BTreeMap::new(),
            lost: None,
        }
    }

    /// Why the server is lost, once it is.
    pub fn lost(&self) -> Option<&str> {
        self.lost.as_deref()
    }

    /// Chains waiting for a reply.
    pub fn waiting(&self) -> usize {
        self.pending.len()
    }

    /// The answer the device gives a chain it does not send: a
    /// `fuse_out_header` of `-EIO` where the chain can hold one, nothing
    /// (used length 0) where it cannot.
    pub fn refused(chain: &Chain<'_>) -> Vec<u8> {
        if chain.writable >= OUT_HEADER_LEN as u64 {
            eio(unique_of(chain.readable))
        } else {
            Vec::new()
        }
    }

    /// What becomes of `chain`, and why it was refused if it was.
    pub fn take(&mut self, chain: &Chain<'_>) -> (Taken, Option<Refusal>) {
        if self.lost.is_some() {
            return (Taken::Answer(Self::refused(chain)), Some(Refusal::Lost));
        }
        if chain.readable_len > MAX_PAYLOAD_LEN as u64 || chain.readable.len() as u64 != chain.readable_len {
            return (Taken::Answer(Self::refused(chain)), Some(Refusal::TooLong));
        }
        if chain.writable > 0 && chain.writable < OUT_HEADER_LEN as u64 {
            return (Taken::Answer(Vec::new()), Some(Refusal::ShortWritable));
        }
        let cap = clamp_writable(chain.writable);
        let Ok(cookie) = self.in_flight.start(cap) else {
            return (Taken::Full, None);
        };
        let header = match Header::request(cookie, chain.queue, cap, chain.readable.len()) {
            Ok(header) => header,
            // The length was checked above and the cap clamped: not reached.
            Err(_) => return (Taken::Answer(Self::refused(chain)), Some(Refusal::TooLong)),
        };
        let mut frame = Vec::with_capacity(header.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(chain.readable);
        let waits = cap != 0;
        if waits {
            self.pending.insert(
                cookie,
                Pending {
                    queue: chain.queue,
                    head: chain.head,
                    unique: unique_of(chain.readable),
                },
            );
        }
        (Taken::Send { frame, cookie, waits }, None)
    }

    /// The answers a reply frame gives: the chain it answers, when every
    /// check holds; otherwise the server is lost, and every waiting chain
    /// is answered with `-EIO`.
    pub fn reply(&mut self, frame: &Frame<'_>) -> Vec<Answer> {
        match self.check(frame) {
            Ok(answer) => vec![answer],
            Err(why) => self.lose(why),
        }
    }

    fn check(&mut self, frame: &Frame<'_>) -> Result<Answer, String> {
        if let Some(why) = &self.lost {
            return Err(why.clone());
        }
        if frame.header.kind() != Kind::Reply {
            return Err(format!("a {:?} frame where a reply was due", frame.header.kind()));
        }
        let cookie = frame.header.cookie();
        // Back on the pending list, so that the loss answers it too.
        let restore = |this: &mut Proxy, pending: Pending, why: String| {
            this.pending.insert(cookie, pending);
            Err(why)
        };
        let finished = self.in_flight.finish(&frame.header);
        let pending = self.pending.remove(&cookie);
        if let Err(e) = finished {
            let why = format!("a bad reply frame: {e}");
            return match pending {
                Some(pending) => restore(self, pending, why),
                None => Err(why),
            };
        }
        let Some(pending) = pending else {
            return Err(format!("a reply to cookie {cookie}, which no chain waits for"));
        };
        let payload = frame.payload;
        let Some(head) = payload.first_chunk::<OUT_HEADER_LEN>() else {
            return restore(self, pending, format!("a reply of {} bytes, shorter than a fuse_out_header", payload.len()));
        };
        let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        if u64::from(len) != payload.len() as u64 {
            return restore(self, pending, format!("a reply whose header says {len} bytes in a frame of {}", payload.len()));
        }
        if head[8..16] != pending.unique {
            return restore(self, pending, "a reply whose unique is not its request's".to_string());
        }
        Ok(Answer {
            cookie,
            queue: pending.queue,
            head: pending.head,
            bytes: payload.to_vec(),
        })
    }

    /// The server is lost for `why`: every chain waiting for a reply is
    /// answered with `-EIO`, and every chain taken from now on too.
    pub fn lose(&mut self, why: String) -> Vec<Answer> {
        if self.lost.is_none() {
            self.lost = Some(why);
        }
        std::mem::take(&mut self.pending)
            .into_iter()
            .map(|(cookie, p)| Answer {
                cookie,
                queue: p.queue,
                head: p.head,
                bytes: eio(p.unique),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use wick_fs_frame::{HEADER_LEN, Sender, parse};

    use super::*;

    fn request(unique: u64, len: usize) -> Vec<u8> {
        let mut r = vec![0u8; len];
        if len >= 16 {
            r[8..16].copy_from_slice(&unique.to_le_bytes());
        }
        r
    }

    fn chain(readable: &[u8], writable: u64) -> Chain<'_> {
        Chain {
            queue: 1,
            head: 7,
            readable,
            readable_len: readable.len() as u64,
            writable,
        }
    }

    fn reply(cookie: u64, payload: &[u8]) -> Vec<u8> {
        let mut f = Header::reply(cookie, payload.len()).unwrap().encode().to_vec();
        f.extend_from_slice(payload);
        f
    }

    fn out(len: u32, error: i32, unique: u64, extra: usize) -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&len.to_le_bytes());
        o.extend_from_slice(&error.to_le_bytes());
        o.extend_from_slice(&unique.to_le_bytes());
        o.resize(16 + extra, 0xab);
        o
    }

    /// The cookie of a request frame.
    fn cookie_of(frame: &[u8]) -> u64 {
        parse(frame, Sender::Vmm).unwrap().unwrap().header.cookie()
    }

    fn sent(p: &mut Proxy, c: &Chain<'_>) -> u64 {
        match p.take(c) {
            (Taken::Send { frame, waits: true, .. }, None) => {
                assert_eq!(&frame[HEADER_LEN..], c.readable);
                cookie_of(&frame)
            }
            other => panic!("{other:?}"),
        }
    }

    fn answers(p: &mut Proxy, frame: &[u8]) -> Vec<Answer> {
        p.reply(&parse(frame, Sender::Server).unwrap().unwrap())
    }

    #[test]
    fn test_a_good_reply_goes_to_its_chain() {
        let mut p = Proxy::new(4);
        let r = request(42, 40);
        let cookie = sent(&mut p, &chain(&r, 100));
        let body = out(20, 0, 42, 4);
        let a = answers(&mut p, &reply(cookie, &body));
        assert_eq!(a, vec![Answer { cookie, queue: 1, head: 7, bytes: body }]);
        assert_eq!(p.waiting(), 0);
        assert!(p.lost().is_none());
    }

    #[test]
    fn test_each_reply_header_mismatch_loses_the_server() {
        // Shorter than a fuse_out_header; `len` not the frame's; `unique`
        // not the request's; longer than the chain.
        let cases: [(&str, Vec<u8>); 4] = [
            ("shorter than a fuse_out_header", vec![0u8; 15]),
            ("header says", out(17, 0, 42, 0)),
            ("unique is not", out(16, 0, 43, 0)),
            ("bad reply frame", out(116, 0, 42, 100)),
        ];
        for (what, body) in cases {
            let mut p = Proxy::new(4);
            let r = request(42, 40);
            let cookie = sent(&mut p, &chain(&r, 100));
            let other = request(9, 40);
            let _ = sent(&mut p, &chain(&other, 100));
            let a = answers(&mut p, &reply(cookie, &body));
            // Both waiting chains answered with -EIO, each with its unique.
            assert_eq!(a.len(), 2, "{what}");
            let mut uniques: Vec<[u8; 8]> = a.iter().map(|x| <[u8; 8]>::try_from(&x.bytes[8..16]).unwrap()).collect();
            uniques.sort();
            assert_eq!(uniques, vec![9u64.to_le_bytes(), 42u64.to_le_bytes()], "{what}");
            for x in &a {
                assert_eq!(&x.bytes[..8], &[16, 0, 0, 0, 0xfb, 0xff, 0xff, 0xff], "{what}");
            }
            assert!(p.lost().unwrap().contains(what), "{what}: {:?}", p.lost());
        }
    }

    #[test]
    fn test_unknown_duplicate_and_no_reply_cookies_lose_the_server() {
        let mut p = Proxy::new(4);
        let r = request(1, 40);
        let _ = sent(&mut p, &chain(&r, 100));
        // A reply to a request without one (FORGET: no writable bytes).
        let forget = request(2, 40);
        let (taken, _) = p.take(&chain(&forget, 0));
        let Taken::Send { frame, waits: false, .. } = taken else { panic!("{taken:?}") };
        let a = answers(&mut p, &reply(cookie_of(&frame), &out(16, 0, 2, 0)));
        assert_eq!(a.len(), 1, "the waiting chain answered");
        assert!(p.lost().is_some());

        let mut p = Proxy::new(4);
        let cookie = sent(&mut p, &chain(&r, 100));
        assert_eq!(answers(&mut p, &reply(cookie, &out(16, 0, 1, 0))).len(), 1);
        // The same cookie again; then one never handed out.
        let a = answers(&mut p, &reply(cookie, &out(16, 0, 1, 0)));
        assert!(a.is_empty() && p.lost().is_some());
        let mut p = Proxy::new(4);
        let _ = sent(&mut p, &chain(&r, 100));
        assert_eq!(answers(&mut p, &reply(999, &out(16, 0, 1, 0))).len(), 1);
        assert!(p.lost().unwrap().contains("bad reply frame"));
    }

    #[test]
    fn test_after_the_loss_every_chain_gets_eio_and_nothing_is_sent() {
        let mut p = Proxy::new(4);
        let r = request(5, 40);
        let cookie = sent(&mut p, &chain(&r, 100));
        let a = p.lose("the server closed the connection".into());
        assert_eq!(a, vec![Answer { cookie, queue: 1, head: 7, bytes: eio(5u64.to_le_bytes()) }]);
        assert_eq!(p.take(&chain(&r, 100)), (Taken::Answer(eio(5u64.to_le_bytes())), Some(Refusal::Lost)));
        // Less than a fuse_out_header, or no writable part: used length 0.
        assert_eq!(p.take(&chain(&r, 15)), (Taken::Answer(vec![]), Some(Refusal::Lost)));
        assert_eq!(p.take(&chain(&r, 0)), (Taken::Answer(vec![]), Some(Refusal::Lost)));
        // A request shorter than its unique: unique 0.
        assert_eq!(p.take(&chain(&r[..10], 16)), (Taken::Answer(eio([0; 8])), Some(Refusal::Lost)));
        assert_eq!(p.lost(), Some("the server closed the connection"));
    }

    #[test]
    fn test_hostile_chains() {
        let mut p = Proxy::new(4);
        let r = request(3, 40);
        // Writable but shorter than a fuse_out_header: used 0, nothing sent.
        assert_eq!(p.take(&chain(&r, 15)), (Taken::Answer(vec![]), Some(Refusal::ShortWritable)));
        // More readable bytes than a frame carries: -EIO, nothing sent.
        let long = Chain { readable_len: MAX_PAYLOAD_LEN as u64 + 1, ..chain(&r, 100) };
        assert_eq!(p.take(&long), (Taken::Answer(eio(3u64.to_le_bytes())), Some(Refusal::TooLong)));
        // A prefix that is not the whole of what the chain says it has.
        let short = Chain { readable_len: 41, ..chain(&r, 100) };
        assert_eq!(p.take(&short).1, Some(Refusal::TooLong));
        // No writable part (FORGET): sent, used now.
        assert!(matches!(p.take(&chain(&r, 0)), (Taken::Send { waits: false, .. }, None)));
        // A huge writable part is clamped to a frame.
        let (taken, _) = p.take(&chain(&r, u64::MAX));
        let Taken::Send { frame, waits: true, .. } = taken else { panic!("{taken:?}") };
        let h = parse(&frame, Sender::Vmm).unwrap().unwrap().header;
        assert_eq!(h.writable_cap() as usize, MAX_PAYLOAD_LEN);
        assert!(p.lost().is_none());
    }

    #[test]
    fn test_the_in_flight_limit_holds_chains_back() {
        let mut p = Proxy::new(2);
        let r = request(1, 40);
        let a = sent(&mut p, &chain(&r, 100));
        let _ = sent(&mut p, &chain(&r, 100));
        assert_eq!(p.take(&chain(&r, 100)), (Taken::Full, None));
        // A request without reply still goes: it waits for nothing.
        assert!(matches!(p.take(&chain(&r, 0)).0, Taken::Send { waits: false, .. }));
        assert_eq!(answers(&mut p, &reply(a, &out(16, 0, 1, 0))).len(), 1);
        assert!(matches!(p.take(&chain(&r, 100)).0, Taken::Send { waits: true, .. }));
    }
}
