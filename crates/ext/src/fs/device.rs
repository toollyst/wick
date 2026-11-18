// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The virtio-fs device (docs/design-fs.md §4.1): it copies each chain's
//! readable bytes to wick-fsd as a request frame and each reply frame back
//! into the chain's writable buffers. What it decides is [`super::copy`]'s;
//! this file moves bytes between the queues, guest memory and the socket.
//!
//! The VMM's event loop is never blocked on the server: the socket is
//! non-blocking and watched by the event manager, requests wait in a buffer
//! of at most two frames' bytes (past one frame no chain is taken), replies
//! are read a bounded amount per event, and the requests waiting for a
//! reply are capped in count and in the bytes their replies may take
//! (`wick_fs_frame::InFlight`). A chain the device cannot take now stays on
//! its queue. A server that stops answering while requests wait shows as
//! the `stalled` metric and one log line; the guest's requests then wait,
//! as on a slow file system.
//!
//! A lost server (its connection ended or broke a rule) fails every waiting
//! request and every later one with `-EIO`; nothing reconnects.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use event_manager::{EventOps, EventSet, Events, MutEventSubscriber};
use utils::time::TimerFd;
use vmm::devices::virtio::ActivateError;
use vmm::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use vmm::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use vmm::devices::virtio::queue::{DescriptorChain, Queue};
use vmm::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use vmm::impl_device_type;
use vmm::logger::{IncMetric, StoreMetric, error, info, warn};
use vmm::rate_limiter::{RateLimiter, TokenType};
use vmm::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;
use wick_fs_frame::{
    Frame, HEADER_LEN, Header, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, Sender, check_hello, clamp_writable,
    hello_frame, parse,
};

use super::config::{MAX_TAG_LEN, ShareConfig};
use super::copy::{Answer, Chain, Proxy, Refusal, Taken};
use super::metrics::FsMetrics;

/// The high-priority queue (FORGET and the like).
const HIPRIO: u16 = 0;
/// The one request queue.
const REQUEST: u16 = 1;
const NUM_QUEUES: usize = 2;

/// `virtio_fs_config`: `tag[36]` and `le32 num_request_queues`. The
/// notification queue's `notify_buf_size` follows only with
/// `VIRTIO_FS_F_NOTIFICATION`, which the device does not offer.
const CONFIG_LEN: usize = MAX_TAG_LEN + 4;

/// `VIRTQ_DESC_F_INDIRECT`: the device does not offer indirect descriptors.
const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

/// How long the hello may take, each way.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// No reply for this long while requests wait: the server is stalled.
const STALL_AFTER: Duration = Duration::from_secs(10);

/// Bytes read from the socket at a time, and at most per event.
const READ_CHUNK: usize = 256 << 10;
const READ_BUDGET: usize = 4 << 20;

// The event manager's ids for this device's descriptors.
const EV_ACTIVATE: u32 = 0;
const EV_HIPRIO: u32 = 1;
const EV_REQUEST: u32 = 2;
const EV_RATE: u32 = 3;
const EV_SOCKET: u32 = 4;
const EV_STALL: u32 = 5;

/// Connects to the share's server and checks its hello: run while the
/// microVM is built (`attach_boot_devices`), before the VMM's sandbox
/// narrows (design-fs §4.1).
pub fn connect(share: &ShareConfig) -> Result<UnixStream, String> {
    connect_to(&share.socket, &share.id, HELLO_TIMEOUT)
}

fn connect_to(path: &Path, id: &str, timeout: Duration) -> Result<UnixStream, String> {
    let fail = |what: String| format!("share {id}: {what} ({})", path.display());
    let mut conn =
        UnixStream::connect(path).map_err(|e| fail(format!("cannot connect to wick-fsd's socket: {e}")))?;
    hello(&mut conn, id, timeout).map_err(|e| fail(format!("no wick-fsd for this share: {e}")))?;
    conn.set_nonblocking(true)
        .map_err(|e| fail(format!("cannot make the connection non-blocking: {e}")))?;
    Ok(conn)
}

/// Sends this side's hello and checks the server's: the same protocol
/// version and the same share id.
fn hello(conn: &mut UnixStream, id: &str, timeout: Duration) -> Result<(), String> {
    conn.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    conn.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    let ours = hello_frame(id).map_err(|e| e.to_string())?;
    conn.write_all(&ours).map_err(|e| format!("sending the hello: {e}"))?;
    let mut head = [0u8; HEADER_LEN];
    conn.read_exact(&mut head).map_err(|e| format!("reading the hello: {e}"))?;
    let header = Header::parse(&head, Sender::Server).map_err(|e| format!("not a hello: {e}"))?;
    let mut payload = vec![0u8; header.payload_len()];
    conn.read_exact(&mut payload).map_err(|e| format!("reading the hello: {e}"))?;
    check_hello(&Frame { header, payload: &payload }, id).map_err(|e| e.to_string())
}

/// A chain's descriptors as the device walked them.
#[derive(Debug, Default)]
struct Walked {
    /// Its readable bytes, at most [`MAX_PAYLOAD_LEN`] of them.
    readable: Vec<u8>,
    readable_len: u64,
    /// Its writable buffers, in order.
    writable: Vec<(GuestAddress, u32)>,
    writable_len: u64,
}

/// Reads a chain: readable buffers first, then writable ones, none
/// indirect, each inside guest memory.
fn walk(mem: &GuestMemoryMmap, head: DescriptorChain) -> Result<Walked, &'static str> {
    let mut w = Walked::default();
    for desc in head {
        if desc.flags & VIRTQ_DESC_F_INDIRECT != 0 {
            return Err("an indirect descriptor, which the device does not offer");
        }
        if desc.is_write_only() {
            w.writable.push((desc.addr, desc.len));
            w.writable_len += u64::from(desc.len);
            continue;
        }
        if !w.writable.is_empty() {
            return Err("a readable buffer after a writable one");
        }
        w.readable_len += u64::from(desc.len);
        let room = MAX_PAYLOAD_LEN - w.readable.len();
        let take = room.min(desc.len as usize);
        let start = w.readable.len();
        w.readable.resize(start + take, 0);
        mem.read_slice(&mut w.readable[start..], desc.addr)
            .map_err(|_| "a readable buffer outside guest memory")?;
    }
    Ok(w)
}

/// Writes `bytes` into a chain's writable buffers: how many were written.
fn write_chain(mem: &GuestMemoryMmap, buffers: &[(GuestAddress, u32)], bytes: &[u8]) -> usize {
    let mut done = 0;
    for &(addr, len) in buffers {
        if done == bytes.len() {
            break;
        }
        let n = (bytes.len() - done).min(len as usize);
        if mem.write_slice(&bytes[done..done + n], addr).is_err() {
            break;
        }
        done += n;
    }
    done
}

/// The timer that tells a stalled server.
#[derive(Debug)]
struct Stall {
    timer: TimerFd,
    after: Duration,
    armed: bool,
    /// A reply came or a request was sent since the timer was armed.
    progress: bool,
    stalled: bool,
}

/// One share's virtio-fs device.
#[derive(Debug)]
pub struct FsDevice {
    id: String,
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,
    device_state: DeviceState,
    queues: Vec<Queue>,
    queue_events: Vec<EventFd>,
    config: [u8; CONFIG_LEN],
    rate_limiter: RateLimiter,
    metrics: Arc<FsMetrics>,

    /// The connection to wick-fsd; `None` once the server is lost and the
    /// connection closed.
    conn: Option<UnixStream>,
    /// What the event manager watches the connection for.
    conn_events: Option<EventSet>,
    /// The runtime events are registered.
    registered: bool,
    proxy: Proxy,
    /// The writable buffers of each chain waiting for a reply, by cookie.
    waiting: HashMap<u64, Vec<(GuestAddress, u32)>>,
    /// Request bytes not yet sent, from `out_pos` on.
    out: Vec<u8>,
    out_pos: usize,
    /// Reply bytes read but not yet a whole frame.
    input: Vec<u8>,
    /// Queues with chains used since their last interrupt.
    used: [bool; NUM_QUEUES],
    /// The loss is logged and counted.
    loss_said: bool,
    stall: Stall,
}

impl FsDevice {
    /// The device for `share`, talking to wick-fsd over `conn` (connected,
    /// hello checked, non-blocking).
    pub fn new(share: &ShareConfig, conn: UnixStream) -> Result<FsDevice, String> {
        let eventfd = || EventFd::new(libc::EFD_NONBLOCK).map_err(|e| format!("an eventfd: {e}"));
        let mut config = [0u8; CONFIG_LEN];
        config[..share.tag.len()].copy_from_slice(share.tag.as_bytes());
        config[MAX_TAG_LEN..].copy_from_slice(&1u32.to_le_bytes());
        let rate_limiter = share.rate_limiter.map(RateLimiter::from).unwrap_or_default();
        let size = share.queue_size();
        Ok(FsDevice {
            id: share.id.clone(),
            avail_features: 1 << VIRTIO_F_VERSION_1,
            acked_features: 0,
            activate_event: eventfd()?,
            device_state: DeviceState::Inactive,
            queues: vec![Queue::new(size); NUM_QUEUES],
            queue_events: (0..NUM_QUEUES).map(|_| eventfd()).collect::<Result<_, _>>()?,
            config,
            rate_limiter,
            metrics: Arc::new(FsMetrics::default()),
            conn: Some(conn),
            conn_events: None,
            registered: false,
            // Every chain of both queues may wait at once; the reply bytes
            // are capped by InFlight.
            proxy: Proxy::new(NUM_QUEUES * usize::from(size)),
            waiting: HashMap::new(),
            out: Vec::new(),
            out_pos: 0,
            input: Vec::new(),
            used: [false; NUM_QUEUES],
            loss_said: false,
            stall: Stall {
                timer: TimerFd::new(),
                after: STALL_AFTER,
                armed: false,
                progress: false,
                stalled: false,
            },
        })
    }

    /// The device's counters, which the metrics line reads without its lock.
    pub fn metrics(&self) -> Arc<FsMetrics> {
        self.metrics.clone()
    }

    fn mem(&self) -> Option<GuestMemoryMmap> {
        self.device_state.active_state().map(|s| s.mem.clone())
    }

    fn unsent(&self) -> usize {
        self.out.len() - self.out_pos
    }

    /// Takes chains off both queues (the high-priority one first) until
    /// they are empty or the device cannot take more now.
    fn take_chains(&mut self, mem: &GuestMemoryMmap) {
        for q in [HIPRIO, REQUEST] {
            loop {
                if self.proxy.lost().is_none() && self.unsent() >= MAX_FRAME_LEN {
                    // The server is not reading: no chain is taken until
                    // the socket takes what is buffered.
                    return;
                }
                if self.rate_limiter.is_blocked() {
                    return;
                }
                let queue = &mut self.queues[usize::from(q)];
                let head = match queue.pop() {
                    Ok(Some(head)) => head,
                    Ok(None) => break,
                    Err(e) => {
                        error!("fs {}: queue {q}: {e}", self.id);
                        self.metrics.event_fails.inc();
                        break;
                    }
                };
                let index = head.index;
                let walked = match walk(mem, head) {
                    Ok(w) => w,
                    Err(why) => {
                        warn!("fs {}: a chain refused: {why}", self.id);
                        self.metrics.refused_chains.inc();
                        self.add_used(q, index, 0);
                        continue;
                    }
                };
                if !self.take_one(mem, q, index, walked) {
                    self.queues[usize::from(q)].undo_pop();
                    return;
                }
            }
        }
    }

    /// Takes one walked chain: false when it must go back on its queue.
    fn take_one(&mut self, mem: &GuestMemoryMmap, q: u16, index: u16, walked: Walked) -> bool {
        let chain = Chain {
            queue: q,
            head: index,
            readable: &walked.readable,
            readable_len: walked.readable_len,
            writable: walked.writable_len,
        };
        let bytes = walked.readable.len() as u64 + u64::from(clamp_writable(walked.writable_len));
        if !self.rate_limiter.consume(1, TokenType::Ops) {
            self.metrics.rate_limited.inc();
            return false;
        }
        if !self.rate_limiter.consume(bytes, TokenType::Bytes) {
            self.rate_limiter.manual_replenish(1, TokenType::Ops);
            self.metrics.rate_limited.inc();
            return false;
        }
        match self.proxy.take(&chain) {
            (Taken::Send { frame, cookie, waits }, _) => {
                self.metrics.requests.inc();
                FsMetrics::add(&self.metrics.request_bytes, frame.len());
                self.out.extend_from_slice(&frame);
                if waits {
                    self.waiting.insert(cookie, walked.writable);
                } else {
                    self.add_used(q, index, 0);
                }
            }
            (Taken::Answer(bytes), refusal) => {
                self.metrics.refused_chains.inc();
                if refusal == Some(Refusal::Lost) && !bytes.is_empty() {
                    self.metrics.eio_answers.inc();
                }
                let n = write_chain(mem, &walked.writable, &bytes);
                if n != bytes.len() {
                    self.metrics.event_fails.inc();
                }
                self.add_used(q, index, n);
            }
            (Taken::Full, _) => {
                self.rate_limiter.manual_replenish(1, TokenType::Ops);
                self.rate_limiter.manual_replenish(bytes, TokenType::Bytes);
                self.metrics.inflight_full.inc();
                return false;
            }
        }
        true
    }

    fn add_used(&mut self, q: u16, index: u16, len: usize) {
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        match self.queues[usize::from(q)].add_used(index, len) {
            Ok(()) => self.used[usize::from(q)] = true,
            Err(e) => {
                error!("fs {}: queue {q}: {e}", self.id);
                self.metrics.event_fails.inc();
            }
        }
    }

    /// Writes the answers into their chains.
    fn deliver(&mut self, mem: &GuestMemoryMmap, answers: Vec<Answer>) {
        let eio = self.proxy.lost().is_some();
        for answer in answers {
            let Some(buffers) = self.waiting.remove(&answer.cookie) else {
                // Not reached: every waiting cookie has its buffers.
                self.metrics.event_fails.inc();
                continue;
            };
            let n = write_chain(mem, &buffers, &answer.bytes);
            if n != answer.bytes.len() {
                self.metrics.event_fails.inc();
            }
            if eio {
                self.metrics.eio_answers.inc();
            } else {
                self.metrics.replies.inc();
                FsMetrics::add(&self.metrics.reply_bytes, n);
            }
            self.add_used(answer.queue, answer.head, n);
        }
    }

    /// The server is lost for `why`: every waiting chain gets `-EIO`.
    fn lose(&mut self, mem: &GuestMemoryMmap, why: String) {
        let answers = self.proxy.lose(why);
        self.deliver(mem, answers);
    }

    /// Sends what is buffered, as far as the socket takes it.
    fn flush(&mut self, mem: &GuestMemoryMmap) {
        if self.proxy.lost().is_some() {
            self.out.clear();
            self.out_pos = 0;
            return;
        }
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        let mut broke = None;
        while self.out_pos < self.out.len() {
            match conn.write(&self.out[self.out_pos..]) {
                Ok(0) => {
                    broke = Some("the connection took no bytes".to_string());
                    break;
                }
                Ok(n) => {
                    self.out_pos += n;
                    self.stall.progress = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    broke = Some(format!("sending to the server failed: {e}"));
                    break;
                }
            }
        }
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        } else if self.out_pos >= MAX_FRAME_LEN {
            self.out.drain(..self.out_pos);
            self.out_pos = 0;
        }
        if let Some(why) = broke {
            self.lose(mem, why);
        }
    }

    /// Reads replies, at most [`READ_BUDGET`] bytes, and answers their
    /// chains.
    fn read_replies(&mut self, mem: &GuestMemoryMmap) {
        let mut budget = READ_BUDGET;
        while self.proxy.lost().is_none() {
            self.take_frames(mem);
            if self.proxy.lost().is_some() || budget == 0 {
                break;
            }
            let Some(conn) = self.conn.as_mut() else {
                break;
            };
            let start = self.input.len();
            self.input.resize(start + READ_CHUNK, 0);
            let read = conn.read(&mut self.input[start..]);
            self.input.truncate(start + *read.as_ref().unwrap_or(&0));
            match read {
                Ok(0) => self.lose(mem, "the server closed the connection".to_string()),
                Ok(n) => {
                    budget = budget.saturating_sub(n);
                    self.stall.progress = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => self.lose(mem, format!("reading from the server failed: {e}")),
            }
        }
    }

    /// Answers the chains of the whole frames read so far.
    fn take_frames(&mut self, mem: &GuestMemoryMmap) {
        let mut used = 0;
        let mut answers = Vec::new();
        while self.proxy.lost().is_none() {
            match parse(&self.input[used..], Sender::Server) {
                Ok(Some(frame)) => {
                    used += frame.header.len();
                    answers.extend(self.proxy.reply(&frame));
                }
                Ok(None) => break,
                Err(e) => answers.extend(self.proxy.lose(format!("a bad frame from the server: {e}"))),
            }
        }
        self.input.drain(..used);
        // A frame never grows the buffer past one frame and a read.
        self.input.shrink_to(MAX_FRAME_LEN + READ_CHUNK);
        self.deliver(mem, answers);
    }

    /// Everything the device can do now: take chains, send, read replies;
    /// then the interrupts, what the connection is watched for, the stall
    /// timer and the counters.
    fn run(&mut self, ops: &mut EventOps, socket_ready: Option<EventSet>) {
        let Some(mem) = self.mem() else {
            return;
        };
        if let Some(ready) = socket_ready {
            if ready.contains(EventSet::OUT) {
                self.flush(&mem);
            }
            if ready.intersects(EventSet::IN | EventSet::HANG_UP | EventSet::ERROR | EventSet::READ_HANG_UP) {
                self.read_replies(&mem);
            }
        }
        loop {
            self.take_chains(&mem);
            let before = self.unsent();
            self.flush(&mem);
            // Taking stopped at a full buffer, and sending made room.
            if !(before >= MAX_FRAME_LEN && self.unsent() < MAX_FRAME_LEN) {
                break;
            }
        }
        self.signal();
        self.say_loss();
        self.watch(ops);
        self.update_stall();
        self.metrics.waiting.store(self.proxy.waiting() as u64);
    }

    fn signal(&mut self) {
        let Some(state) = self.device_state.active_state() else {
            return;
        };
        for q in [HIPRIO, REQUEST] {
            if std::mem::take(&mut self.used[usize::from(q)]) {
                self.queues[usize::from(q)].advance_used_ring_idx();
                if let Err(e) = state.interrupt.trigger(VirtioInterruptType::Queue(q)) {
                    error!("fs {}: signalling queue {q}: {e:?}", self.id);
                    self.metrics.event_fails.inc();
                }
            }
        }
    }

    /// Logs and counts the loss, once.
    fn say_loss(&mut self) {
        if let Some(why) = self.proxy.lost()
            && !self.loss_said
        {
            self.loss_said = true;
            self.metrics.lose();
            error!(
                "fs {}: the server is lost ({why}); every request of the share now fails with EIO, and nothing reconnects",
                self.id
            );
        }
    }

    /// Watches the connection for what is due: replies, and room to send
    /// while bytes wait; once the server is lost, nothing, and the
    /// connection is closed.
    fn watch(&mut self, ops: &mut EventOps) {
        if !self.registered {
            return;
        }
        let want = match (&self.conn, self.proxy.lost()) {
            (Some(_), None) if self.unsent() > 0 => Some(EventSet::IN | EventSet::OUT),
            (Some(_), None) => Some(EventSet::IN),
            _ => None,
        };
        if want == self.conn_events {
            if want.is_none() {
                self.conn = None;
            }
            return;
        }
        let Some(conn) = self.conn.as_ref() else {
            return;
        };
        let done = match (self.conn_events, want) {
            (Some(_), Some(w)) => ops.modify(Events::with_data(conn, EV_SOCKET, w)),
            (None, Some(w)) => ops.add(Events::with_data(conn, EV_SOCKET, w)),
            (Some(cur), None) => ops.remove(Events::with_data(conn, EV_SOCKET, cur)),
            (None, None) => Ok(()),
        };
        match done {
            Ok(()) => {
                self.conn_events = want;
                if want.is_none() {
                    self.conn = None;
                }
            }
            Err(e) => {
                error!("fs {}: watching the connection: {e:?}", self.id);
                self.metrics.event_fails.inc();
                if want.is_some()
                    && let Some(mem) = self.mem()
                {
                    // Unwatched, a reply would never be read: lose it now
                    // rather than let the guest's requests hang.
                    self.lose(&mem, format!("the connection cannot be watched: {e:?}"));
                    self.signal();
                    self.say_loss();
                }
            }
        }
    }

    /// Arms the stall timer while requests are outstanding, and tells when
    /// replies come again after a stall.
    fn update_stall(&mut self) {
        let outstanding = self.proxy.lost().is_none() && (self.proxy.waiting() > 0 || self.unsent() > 0);
        if self.stall.stalled && (self.stall.progress || !outstanding) {
            self.stall.stalled = false;
            self.metrics.stalled.store(0);
            info!("fs {}: the server answers again", self.id);
        }
        if outstanding && !self.stall.armed {
            self.stall.timer.arm(self.stall.after, None);
            self.stall.armed = true;
            self.stall.progress = false;
        } else if !outstanding && self.stall.armed {
            self.stall.timer.arm(Duration::ZERO, None);
            self.stall.armed = false;
        }
    }

    fn stall_tick(&mut self) {
        self.stall.timer.read();
        self.stall.armed = false;
        let outstanding = self.proxy.lost().is_none() && (self.proxy.waiting() > 0 || self.unsent() > 0);
        if outstanding && !self.stall.progress && !self.stall.stalled {
            self.stall.stalled = true;
            self.metrics.stalled.store(1);
            warn!(
                "fs {}: no reply from the server for {} s: {} requests wait, {} request bytes unsent",
                self.id,
                self.stall.after.as_secs_f64(),
                self.proxy.waiting(),
                self.unsent()
            );
        }
        self.stall.progress = false;
    }

    fn register_runtime_events(&mut self, ops: &mut EventOps) {
        if self.registered {
            return;
        }
        let fds = [
            Events::with_data(&self.queue_events[usize::from(HIPRIO)], EV_HIPRIO, EventSet::IN),
            Events::with_data(&self.queue_events[usize::from(REQUEST)], EV_REQUEST, EventSet::IN),
            Events::with_data(&self.rate_limiter, EV_RATE, EventSet::IN),
            Events::with_data(&self.stall.timer, EV_STALL, EventSet::IN),
        ];
        for events in fds {
            if let Err(e) = ops.add(events) {
                error!("fs {}: registering an event: {e:?}", self.id);
                self.metrics.event_fails.inc();
            }
        }
        self.registered = true;
    }
}

impl VirtioDevice for FsDevice {
    impl_device_type!(VirtioDeviceType::Fs);

    fn id(&self) -> &str {
        &self.id
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .as_ref()
    }

    fn config_as_bytes(&self) -> &[u8] {
        &self.config
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // virtio_fs_config is read-only for the driver.
        warn!("fs {}: a write of {} bytes at {offset} to the read-only config", self.id, data.len());
    }

    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: Arc<dyn VirtioInterrupt>) -> Result<(), ActivateError> {
        for q in self.queues.iter_mut() {
            q.initialize(&mem).map_err(ActivateError::QueueMemoryError)?;
        }
        self.activate_event.write(1).map_err(|_| ActivateError::EventFd)?;
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    /// The guest resets the device. The server's FUSE session belongs to
    /// the connection, and the chains waiting for replies are no longer the
    /// guest's to be written: so the server is lost (nothing is written;
    /// the connection closes at the next event), and after a new
    /// activation every request fails with `-EIO`. A device never activated
    /// keeps its connection.
    fn _reset(&mut self) -> bool {
        if self.is_activated() || !self.waiting.is_empty() {
            let _ = self.proxy.lose("the guest reset the device".to_string());
            self.waiting.clear();
            self.out.clear();
            self.out_pos = 0;
            self.input.clear();
            self.used = [false; NUM_QUEUES];
        }
        true
    }
}

impl MutEventSubscriber for FsDevice {
    fn init(&mut self, ops: &mut EventOps) {
        if self.is_activated() {
            self.register_runtime_events(ops);
            self.watch(ops);
        } else if let Err(e) = ops.add(Events::with_data(&self.activate_event, EV_ACTIVATE, EventSet::IN)) {
            error!("fs {}: registering the activate event: {e:?}", self.id);
            self.metrics.event_fails.inc();
        }
    }

    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let source = events.data();
        let ready = events.event_set();
        if !self.is_activated() {
            // Spurious before activation (or after a reset): consumed.
            match source {
                EV_ACTIVATE => {
                    let _ = self.activate_event.read();
                }
                EV_HIPRIO | EV_REQUEST => self.drain_queue_events(),
                EV_RATE => {
                    let _ = self.rate_limiter.event_handler();
                }
                EV_STALL => {
                    self.stall.timer.read();
                }
                _ => {}
            }
            // A reset device's connection is closed at its next event.
            self.watch(ops);
            return;
        }
        let mut socket_ready = None;
        match source {
            EV_ACTIVATE => {
                let _ = self.activate_event.read();
                if let Err(e) = ops.remove(Events::with_data(&self.activate_event, EV_ACTIVATE, EventSet::IN)) {
                    error!("fs {}: unregistering the activate event: {e:?}", self.id);
                }
                self.register_runtime_events(ops);
            }
            EV_HIPRIO | EV_REQUEST => {
                let q = if source == EV_HIPRIO { HIPRIO } else { REQUEST };
                if let Err(e) = self.queue_events[usize::from(q)].read() {
                    error!("fs {}: reading queue {q}'s event: {e}", self.id);
                    self.metrics.event_fails.inc();
                }
            }
            EV_RATE => {
                if let Err(e) = self.rate_limiter.event_handler() {
                    error!("fs {}: the rate limiter's event: {e:?}", self.id);
                    self.metrics.event_fails.inc();
                }
            }
            EV_SOCKET => socket_ready = Some(ready),
            EV_STALL => self.stall_tick(),
            _ => warn!("fs {}: an unknown event {source}", self.id),
        }
        self.run(ops, socket_ready);
    }
}

#[cfg(test)]
mod tests;
