// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The device against a fake wick-fsd on a socket pair, its queues in guest
//! memory as upstream's tests lay them out (`VirtQueue`), driven by an
//! event manager as Firecracker's loop drives it.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use event_manager::{EventManager, MutEventSubscriber, SubscriberOps};
use vmm::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use vmm::devices::virtio::test_utils::{VirtQueue, default_interrupt};
use vmm::test_utils::single_region_mem;
use vmm::vmm_config::{RateLimiterConfig, TokenBucketConfig};
use wick_fs_frame::{
    HEADER_LEN, Header, Kind, MAX_IN_FLIGHT_REPLY_BYTES, MAX_PAYLOAD_LEN, PROTOCOL_VERSION, Sender, hello_frame,
};

use super::*;
use crate::fs::metrics;

/// Guest memory: the queues in the first 64 KiB, chains' buffers above.
const MEM: usize = 8 << 20;
const DATA: u64 = 0x10000;

type Manager = EventManager<Arc<Mutex<dyn MutEventSubscriber>>>;

/// A reply to the request, as the server would send it, from its cookie.
type BadReply = fn(u64) -> Vec<u8>;

/// [`MAX_PAYLOAD_LEN`] as a descriptor's length (it fits: about 1 MiB).
#[allow(clippy::cast_possible_truncation)]
const FRAME_PAYLOAD: u32 = MAX_PAYLOAD_LEN as u32;

fn share(queue_size: u16) -> ShareConfig {
    ShareConfig {
        id: "docs".to_string(),
        tag: "docs".to_string(),
        socket: "/nonexistent".into(),
        queue_size: Some(queue_size),
        rate_limiter: None,
    }
}

/// A FUSE request of `len` bytes whose `unique` is `unique`.
fn request(unique: u64, len: usize) -> Vec<u8> {
    let mut r = vec![0x5a; len];
    r[8..16].copy_from_slice(&unique.to_le_bytes());
    r
}

/// A reply body: `fuse_out_header` {len, error, unique}, then `extra` bytes.
fn out(len: u32, error: i32, unique: u64, extra: usize) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&len.to_le_bytes());
    o.extend_from_slice(&error.to_le_bytes());
    o.extend_from_slice(&unique.to_le_bytes());
    o.resize(16 + extra, 0xab);
    o
}

fn eio(unique: u64) -> Vec<u8> {
    out(16, -5, unique, 0)
}

/// The device with its two queues in guest memory, an event manager and
/// the server's end of the connection.
struct Rig {
    mem: &'static GuestMemoryMmap,
    vqs: Vec<VirtQueue<'static>>,
    dev: Arc<Mutex<FsDevice>>,
    em: Manager,
    server: UnixStream,
    next_desc: [u16; 2],
    next_addr: u64,
    seen: [u16; 2],
}

impl Rig {
    fn new(share: ShareConfig) -> Rig {
        let (vmm_end, server) = UnixStream::pair().unwrap();
        vmm_end.set_nonblocking(true).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        Rig::over(share, vmm_end, server)
    }

    fn over(share: ShareConfig, conn: UnixStream, server: UnixStream) -> Rig {
        let mem: &'static GuestMemoryMmap = Box::leak(Box::new(single_region_mem(MEM)));
        let size = share.queue_size();
        let vq0 = VirtQueue::new(GuestAddress(0), mem, size);
        let vq1 = VirtQueue::new(GuestAddress(0x8000), mem, size);
        assert!(vq0.end().0 <= 0x8000 && vq1.end().0 <= DATA);
        let mut dev = FsDevice::new(&share, conn).unwrap();
        dev.stall.after = Duration::from_millis(200);
        dev.queues = vec![vq0.create_queue(), vq1.create_queue()];
        let dev = Arc::new(Mutex::new(dev));
        let mut em = Manager::new().unwrap();
        em.add_subscriber(dev.clone());
        dev.lock().unwrap().activate(mem.clone(), default_interrupt()).unwrap();
        let mut rig = Rig { mem, vqs: vec![vq0, vq1], dev, em, server, next_desc: [0; 2], next_addr: DATA, seen: [0; 2] };
        rig.run();
        assert!(rig.dev.lock().unwrap().registered);
        rig
    }

    /// Lets the device handle what is ready.
    fn run(&mut self) {
        for _ in 0..8 {
            if self.em.run_with_timeout(20).unwrap() == 0 {
                break;
            }
        }
    }

    fn alloc(&mut self, len: u64) -> GuestAddress {
        if self.next_addr + len > MEM as u64 {
            self.next_addr = DATA;
        }
        let a = GuestAddress(self.next_addr);
        self.next_addr += len.div_ceil(16) * 16;
        a
    }

    /// Puts a chain of `descs` (address, length, flags) on queue `q`.
    fn raw_chain(&mut self, q: usize, descs: &[(GuestAddress, u32, u16)]) -> u16 {
        let size = self.vqs[q].size();
        let first = self.next_desc[q];
        for (i, &(addr, len, flags)) in descs.iter().enumerate() {
            let idx = (first + u16::try_from(i).unwrap()) % size;
            let next = (idx + 1) % size;
            let flags = if i + 1 < descs.len() { flags | VIRTQ_DESC_F_NEXT } else { flags };
            self.vqs[q].dtable[usize::from(idx)].set(addr.0, len, flags, next);
        }
        self.next_desc[q] = (first + u16::try_from(descs.len()).unwrap()) % size;
        let ring = self.vqs[q].avail.idx.get();
        self.vqs[q].avail.ring[usize::from(ring % size)].set(first);
        self.vqs[q].avail.idx.set(ring.wrapping_add(1));
        self.dev.lock().unwrap().queue_events[q].write(1).unwrap();
        first
    }

    /// A chain of `readable` buffers then writable ones of `writable`
    /// bytes each: its head and the writable buffers' addresses.
    fn chain(&mut self, q: usize, readable: &[&[u8]], writable: &[u32]) -> (u16, Vec<GuestAddress>) {
        let mut descs = Vec::new();
        for r in readable {
            let a = self.alloc(r.len() as u64);
            self.mem.write_slice(r, a).unwrap();
            descs.push((a, u32::try_from(r.len()).unwrap(), 0));
        }
        let mut bufs = Vec::new();
        for &w in writable {
            let a = self.alloc(u64::from(w));
            bufs.push(a);
            descs.push((a, w, VIRTQ_DESC_F_WRITE));
        }
        (self.raw_chain(q, &descs), bufs)
    }

    /// The chains used on queue `q` since the last call: (head, length).
    fn used(&mut self, q: usize) -> Vec<(u16, u32)> {
        let size = self.vqs[q].size();
        let idx = self.vqs[q].used.idx.get();
        let mut out = Vec::new();
        while self.seen[q] != idx {
            let e = self.vqs[q].used.ring[usize::from(self.seen[q] % size)].get();
            out.push((u16::try_from(e.id).unwrap(), e.len));
            self.seen[q] = self.seen[q].wrapping_add(1);
        }
        out
    }

    fn read(&self, addr: GuestAddress, len: usize) -> Vec<u8> {
        let mut b = vec![0; len];
        self.mem.read_slice(&mut b, addr).unwrap();
        b
    }

    /// The next request frame the device sent.
    fn request(&mut self) -> (Header, Vec<u8>) {
        read_frame(&mut self.server, Sender::Vmm)
    }

    fn reply(&mut self, cookie: u64, payload: &[u8]) {
        let mut f = Header::reply(cookie, payload.len()).unwrap().encode().to_vec();
        f.extend_from_slice(payload);
        self.server.write_all(&f).unwrap();
    }

    fn nothing_sent(&mut self) -> bool {
        self.server.set_nonblocking(true).unwrap();
        let mut b = [0u8; 1];
        let r = self.server.read(&mut b);
        self.server.set_nonblocking(false).unwrap();
        matches!(r, Err(e) if e.kind() == ErrorKind::WouldBlock)
    }

    fn metrics(&self) -> Arc<FsMetrics> {
        self.dev.lock().unwrap().metrics()
    }
}

fn read_frame(conn: &mut UnixStream, sender: Sender) -> (Header, Vec<u8>) {
    let mut head = [0u8; HEADER_LEN];
    conn.read_exact(&mut head).unwrap();
    let h = Header::parse(&head, sender).unwrap();
    let mut payload = vec![0; h.payload_len()];
    conn.read_exact(&mut payload).unwrap();
    (h, payload)
}

#[test]
fn test_config_space_is_the_tag_and_one_request_queue() {
    let rig = Rig::new(share(16));
    let dev = rig.dev.lock().unwrap();
    let mut c = [0xffu8; 40];
    dev.read_config(0, &mut c);
    assert_eq!(&c[..4], b"docs");
    assert!(c[4..36].iter().all(|&b| b == 0));
    assert_eq!(u32::from_le_bytes(c[36..40].try_into().unwrap()), 1);
    assert_eq!(dev.device_type(), VirtioDeviceType::Fs);
    assert_eq!(dev.avail_features(), 1 << VIRTIO_F_VERSION_1);
}

#[test]
fn test_a_request_and_its_reply() {
    let mut rig = Rig::new(share(16));
    let r = request(42, 40);
    let (head, bufs) = rig.chain(1, &[&r[..10], &r[10..]], &[8, 100]);
    rig.run();
    let (h, payload) = rig.request();
    assert_eq!((h.kind(), h.queue(), h.writable_cap()), (Kind::Request, 1, 108));
    assert_eq!(payload, r);
    let body = out(20, 0, 42, 4);
    rig.reply(h.cookie(), &body);
    rig.run();
    assert_eq!(rig.used(1), vec![(head, 20)]);
    assert_eq!(rig.read(bufs[0], 8), body[..8]);
    assert_eq!(rig.read(bufs[1], 12), body[8..]);
    let m = rig.metrics();
    assert_eq!((m.requests.count(), m.replies.count(), m.reply_bytes.count()), (1, 1, 20));
    // A request without a reply (FORGET, on the high-priority queue): sent,
    // and used at once with length 0.
    let (head, _) = rig.chain(0, &[&request(0, 48)], &[]);
    rig.run();
    let (h, _) = rig.request();
    assert_eq!((h.queue(), h.writable_cap()), (0, 0));
    assert_eq!(rig.used(0), vec![(head, 0)]);
}

#[test]
fn test_server_death_fails_inflight_with_eio() {
    let mut rig = Rig::new(share(16));
    let (head, bufs) = rig.chain(1, &[&request(7, 40)], &[100]);
    rig.run();
    let _ = rig.request();
    // The server dies mid-request: its end closes.
    rig.server.shutdown(std::net::Shutdown::Both).unwrap();
    rig.run();
    assert_eq!(rig.used(1), vec![(head, 16)]);
    assert_eq!(rig.read(bufs[0], 16), eio(7));
    let m = rig.metrics();
    assert_eq!((m.server_lost.fetch(), m.eio_answers.count()), (1, 1));
    // Every chain after: -EIO at once where it holds a header, used 0 where
    // it cannot (shorter than a header, no writable part); never a hang.
    let (h1, b1) = rig.chain(1, &[&request(8, 40)], &[100]);
    let (h2, _) = rig.chain(1, &[&request(9, 40)], &[15]);
    let (h3, _) = rig.chain(0, &[&request(0, 40)], &[]);
    rig.run();
    assert_eq!(rig.used(1), vec![(h1, 16), (h2, 0)]);
    assert_eq!(rig.used(0), vec![(h3, 0)]);
    assert_eq!(rig.read(b1[0], 16), eio(8));
    assert!(rig.dev.lock().unwrap().conn.is_none(), "the connection is closed");
}

#[test]
fn test_no_reconnect_after_loss() {
    let dir = std::env::temp_dir().join(format!("wick-ext-fs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn({
        let listener = listener.try_clone().unwrap();
        move || {
            let (mut c, _) = listener.accept().unwrap();
            c.write_all(&hello_frame("docs").unwrap()).unwrap();
            let _ = read_frame(&mut c, Sender::Vmm);
            c
        }
    });
    let conn = connect_to(&path, "docs", Duration::from_secs(5)).unwrap();
    let server = server.join().unwrap();
    let mut rig = Rig::over(ShareConfig { socket: path.clone(), ..share(16) }, conn, server);
    rig.server.shutdown(std::net::Shutdown::Both).unwrap();
    rig.run();
    assert!(rig.dev.lock().unwrap().proxy.lost().is_some());
    for _ in 0..3 {
        let _ = rig.chain(1, &[&request(1, 40)], &[100]);
        rig.run();
    }
    assert_eq!(rig.used(1).len(), 3);
    // The socket is still there, and nothing connected to it again.
    listener.set_nonblocking(true).unwrap();
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A server that reads nothing: the device stops taking chains at a frame's
/// worth of unsent bytes, the event loop goes on serving others, and the
/// stall shows as the metric.
#[test]
fn test_server_hang_never_blocks_the_loop() {
    let mut rig = Rig::new(share(16));
    let other = Arc::new(Mutex::new(Counter::default()));
    rig.em.add_subscriber(other.clone());
    // 8 chains of 1 MiB readable each, all over one guest buffer.
    let big = rig.alloc(1 << 20);
    rig.mem.write_slice(&request(3, 1 << 20), big).unwrap();
    let reply_buf = rig.alloc(4096);
    for _ in 0..8 {
        rig.raw_chain(1, &[(big, 1 << 20, 0), (reply_buf, 4096, VIRTQ_DESC_F_WRITE)]);
    }
    let start = Instant::now();
    for i in 0..20 {
        other.lock().unwrap().event.write(1).unwrap();
        let t = Instant::now();
        rig.em.run_with_timeout(20).unwrap();
        assert!(t.elapsed() < Duration::from_secs(1), "a pass of the loop took {:?}", t.elapsed());
        if i == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    assert!(other.lock().unwrap().served >= 20, "the other subscriber was served");
    let dev = rig.dev.lock().unwrap();
    assert!(dev.unsent() < 2 * MAX_FRAME_LEN, "{} bytes buffered", dev.unsent());
    assert!(!dev.queues[1].is_empty(), "chains left on the queue");
    drop(dev);
    // Past the stall time, still nothing read: stalled.
    while start.elapsed() < Duration::from_millis(400) {
        rig.em.run_with_timeout(50).unwrap();
    }
    assert_eq!(rig.metrics().stalled.fetch(), 1);
    // The server reads again (its own thread, as wick-fsd is its own
    // process): every chain goes, and the stall ends.
    let mut server = rig.server.try_clone().unwrap();
    let reader = std::thread::spawn(move || {
        for _ in 0..8 {
            let _ = read_frame(&mut server, Sender::Vmm);
        }
    });
    let t = Instant::now();
    while !reader.is_finished() && t.elapsed() < Duration::from_secs(10) {
        rig.em.run_with_timeout(20).unwrap();
    }
    reader.join().unwrap();
    rig.run();
    assert_eq!(rig.metrics().stalled.fetch(), 0);
    assert_eq!(rig.metrics().requests.count(), 8);
}

#[derive(Debug)]
struct Counter {
    event: EventFd,
    served: u32,
}

impl Default for Counter {
    fn default() -> Counter {
        Counter { event: EventFd::new(libc::EFD_NONBLOCK).unwrap(), served: 0 }
    }
}

impl MutEventSubscriber for Counter {
    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::new(&self.event, EventSet::IN)).unwrap();
    }

    fn process(&mut self, _: Events, _: &mut EventOps) {
        let _ = self.event.read();
        self.served += 1;
    }
}

/// A flood of chains whose replies could each take a frame: the requests
/// waiting stop at the reply budget, the rest stay on the queue, and a
/// reply lets the next one go.
#[test]
fn test_inflight_cap_backpressure() {
    let mut rig = Rig::new(share(64));
    let writable = rig.alloc(MAX_PAYLOAD_LEN as u64);
    let cap = MAX_PAYLOAD_LEN as u64;
    let fit = MAX_IN_FLIGHT_REPLY_BYTES / cap;
    let n = fit + 2;
    for i in 0..n {
        let r = rig.alloc(40);
        rig.mem.write_slice(&request(i + 1, 40), r).unwrap();
        rig.raw_chain(1, &[(r, 40, 0), (writable, FRAME_PAYLOAD, VIRTQ_DESC_F_WRITE)]);
    }
    let mut cookies = Vec::new();
    rig.server.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    loop {
        rig.run();
        let mut head = [0u8; HEADER_LEN];
        if rig.server.read_exact(&mut head).is_err() {
            break;
        }
        let h = Header::parse(&head, Sender::Vmm).unwrap();
        let mut p = vec![0; h.payload_len()];
        rig.server.read_exact(&mut p).unwrap();
        cookies.push((h.cookie(), u64::from_le_bytes(p[8..16].try_into().unwrap())));
    }
    rig.server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(cookies.len() as u64, fit, "requests waiting at the budget");
    assert_eq!(rig.metrics().waiting.fetch(), fit);
    assert!(rig.metrics().inflight_full.count() > 0);
    assert_eq!(u64::from(rig.dev.lock().unwrap().queues[1].len()), n - fit);
    // One reply: one more request goes.
    let (cookie, unique) = cookies[0];
    rig.reply(cookie, &out(16, 0, unique, 0));
    rig.run();
    let (h, _) = rig.request();
    assert_eq!(h.kind(), Kind::Request);
    assert_eq!(u64::from(rig.dev.lock().unwrap().queues[1].len()), n - fit - 1);
}

#[test]
fn test_hostile_chains() {
    let mut rig = Rig::new(share(16));
    let r = rig.alloc(40);
    rig.mem.write_slice(&request(11, 40), r).unwrap();
    let w = rig.alloc(100);
    // A readable buffer after a writable one.
    let a = rig.raw_chain(1, &[(w, 100, VIRTQ_DESC_F_WRITE), (r, 40, 0)]);
    // An indirect descriptor, which the device does not offer.
    let b = rig.raw_chain(1, &[(r, 40, VIRTQ_DESC_F_INDIRECT), (w, 100, VIRTQ_DESC_F_WRITE)]);
    // Writable, but less than a fuse_out_header.
    let c = rig.raw_chain(1, &[(r, 40, 0), (w, 8, VIRTQ_DESC_F_WRITE)]);
    // A readable buffer outside guest memory.
    let d = rig.raw_chain(1, &[(GuestAddress(MEM as u64 + 0x1000), 40, 0), (w, 100, VIRTQ_DESC_F_WRITE)]);
    rig.run();
    assert_eq!(rig.used(1), vec![(a, 0), (b, 0), (c, 0), (d, 0)]);
    // More readable bytes than a frame carries: -EIO with its unique.
    let long = rig.alloc(MAX_PAYLOAD_LEN as u64 + 1);
    rig.mem.write_slice(&request(12, 40), long).unwrap();
    let e = rig.raw_chain(1, &[(long, FRAME_PAYLOAD + 1, 0), (w, 100, VIRTQ_DESC_F_WRITE)]);
    rig.run();
    assert_eq!(rig.used(1), vec![(e, 16)]);
    assert_eq!(rig.read(w, 16), eio(12));
    assert!(rig.nothing_sent(), "no hostile chain reached the server");
    assert_eq!(rig.metrics().refused_chains.count(), 5);
    assert!(rig.dev.lock().unwrap().proxy.lost().is_none());
}

#[test]
fn test_hostile_replies() {
    // Each loses the server: the waiting chain gets -EIO, and nothing is
    // written past its writable buffer.
    let cases: [(&str, BadReply); 5] = [
        ("longer than the chain", |c| frame(c, &out(116, 0, 21, 100))),
        ("a cookie no request has", |c| frame(c + 1000, &out(16, 0, 21, 0))),
        ("a header that is not one", |_| vec![0xee; HEADER_LEN + 16]),
        ("another request's unique", |c| frame(c, &out(16, 0, 22, 0))),
        ("a len not the reply's", |c| frame(c, &out(20, 0, 21, 0))),
    ];
    for (what, bad) in cases {
        let mut rig = Rig::new(share(16));
        let (head, bufs) = rig.chain(1, &[&request(21, 40)], &[100]);
        let canary = GuestAddress(bufs[0].0 + 100);
        rig.mem.write_slice(&[0xc5; 64], canary).unwrap();
        rig.run();
        let (h, _) = rig.request();
        rig.server.write_all(&bad(h.cookie())).unwrap();
        rig.run();
        assert_eq!(rig.used(1), vec![(head, 16)], "{what}");
        assert_eq!(rig.read(bufs[0], 16), eio(21), "{what}");
        assert_eq!(rig.read(canary, 64), vec![0xc5; 64], "{what}");
        assert!(rig.dev.lock().unwrap().proxy.lost().is_some(), "{what}");
        assert_eq!(rig.metrics().server_lost.fetch(), 1, "{what}");
    }
}

fn frame(cookie: u64, payload: &[u8]) -> Vec<u8> {
    let mut f = Header::reply(cookie, payload.len()).unwrap().encode().to_vec();
    f.extend_from_slice(payload);
    f
}

#[test]
fn test_rate_limiter_holds_chains() {
    let limited = ShareConfig {
        rate_limiter: Some(RateLimiterConfig {
            bandwidth: None,
            ops: Some(TokenBucketConfig { size: 1, one_time_burst: None, refill_time: 200 }),
        }),
        ..share(16)
    };
    let mut rig = Rig::new(limited);
    let _ = rig.chain(1, &[&request(1, 40)], &[100]);
    let _ = rig.chain(1, &[&request(2, 40)], &[100]);
    rig.run();
    let (h, p) = rig.request();
    assert_eq!(&p[8..16], &1u64.to_le_bytes());
    assert!(rig.nothing_sent(), "the second waits for a token");
    assert!(rig.metrics().rate_limited.count() > 0);
    assert_eq!(rig.dev.lock().unwrap().queues[1].len(), 1);
    // The bucket refills: the rate limiter's event takes the second.
    let t = Instant::now();
    while !rig.dev.lock().unwrap().queues[1].is_empty() && t.elapsed() < Duration::from_secs(2) {
        rig.em.run_with_timeout(50).unwrap();
    }
    let (_, p) = rig.request();
    assert_eq!(&p[8..16], &2u64.to_le_bytes());
    let _ = h;
}

/// The guest resets the device: the session the server holds is not the
/// next driver's, so the server is lost and the connection closed; after
/// a new activation every request fails with -EIO.
#[test]
fn test_reset_loses_the_server() {
    let mut rig = Rig::new(share(16));
    let _ = rig.chain(1, &[&request(5, 40)], &[100]);
    rig.run();
    let _ = rig.request();
    assert!(rig.dev.lock().unwrap().reset());
    rig.dev.lock().unwrap().queue_events[1].write(1).unwrap();
    rig.run();
    // The server sees the connection end.
    let mut b = [0u8; 1];
    assert_eq!(rig.server.read(&mut b).unwrap(), 0);
    let size = rig.vqs[1].size();
    let vq1 = VirtQueue::new(GuestAddress(0x8000), rig.mem, size);
    let vq0 = VirtQueue::new(GuestAddress(0), rig.mem, size);
    {
        let mut dev = rig.dev.lock().unwrap();
        dev.queues = vec![vq0.create_queue(), vq1.create_queue()];
        dev.activate(rig.mem.clone(), default_interrupt()).unwrap();
    }
    rig.vqs = vec![vq0, vq1];
    rig.next_desc = [0; 2];
    rig.seen = [0; 2];
    rig.run();
    let (head, bufs) = rig.chain(1, &[&request(6, 40)], &[100]);
    rig.run();
    assert_eq!(rig.used(1), vec![(head, 16)]);
    assert_eq!(rig.read(bufs[0], 16), eio(6));
}

/// The metrics line's hook reads the counters while the device's lock is
/// held (a fatal signal can come while the device's thread holds it).
#[test]
fn test_write_metrics_takes_no_device_lock() {
    let rig = Rig::new(share(16));
    let m = rig.metrics();
    let held = rig.dev.lock().unwrap();
    m.requests.inc();
    let mut out = serde_json::Map::new();
    metrics::write_from(&[("docs".to_string(), m.clone())], &mut out);
    assert_eq!(out["fs_docs"]["requests"], 1);
    drop(held);
}

/// A server for one hello, answering with `hello`.
fn hello_peer(hello: Vec<u8>, then_close: bool) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    let dir = std::env::temp_dir().join(format!("wick-ext-hello-{}-{}", std::process::id(), hello.len()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let t = std::thread::spawn(move || {
        let (mut c, _) = listener.accept().unwrap();
        // The VMM's hello first, so that the answer is never a broken pipe.
        let _ = read_frame(&mut c, Sender::Vmm);
        c.write_all(&hello).unwrap();
        if !then_close {
            std::thread::sleep(Duration::from_millis(600));
        }
    });
    (path, t)
}

#[test]
fn test_hello_refusals() {
    let mut newer = hello_frame("docs").unwrap();
    newer[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&(PROTOCOL_VERSION + 1).to_le_bytes());
    let cases: [(&str, Vec<u8>, bool, &str); 5] = [
        ("another share", hello_frame("other").unwrap(), true, "share"),
        ("another version", newer, true, "version"),
        ("not a wick-fsd", b"SSH-2.0-OpenSSH_9.9\r\n\0\0\0\0\0\0\0\0".to_vec(), true, "not a hello"),
        ("a peer that closes", Vec::new(), true, "reading the hello"),
        ("a peer that says nothing", Vec::new(), false, "reading the hello"),
    ];
    for (what, hello, close, says) in cases {
        let (path, t) = hello_peer(hello, close);
        let e = connect_to(&path, "docs", Duration::from_millis(300)).unwrap_err();
        assert!(e.contains("no wick-fsd for this share") && e.contains(says), "{what}: {e}");
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
    let e = connect_to(std::path::Path::new("/nonexistent/s.sock"), "docs", Duration::from_millis(300)).unwrap_err();
    assert!(e.contains("cannot connect"), "{e}");
}
