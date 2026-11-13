// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`TapDevice`] on Windows: a Unix stream endpoint (see
//! [`crate::platform::net`] for the names) that a host-side switch connects
//! to. Frames go both ways as plain Ethernet frames, each preceded by its
//! length as a 32-bit big-endian number: the framing of QEMU's
//! `-netdev stream`, which passt and gvisor-tap-vsock (`-listen-qemu`) use
//! too. Those tools listen and wait for QEMU to connect, as this endpoint
//! listens, so neither connects to it without an adapter (a process that
//! connects to both); what has run against it is the test scripts' own
//! switch (`boot-test.ps1 net`, `jailer-test.ps1 netguest`). The
//! virtio-net header is handled by [`vnet`].
//!
//! - One switch is connected at a time. One that connects while another is
//!   there waits in the listener's queue, and takes its place when it
//!   leaves; what it sent meanwhile reaches the guest then. So no frame a
//!   switch sent is lost to the order in which switches came and went, as
//!   on a TAP, where every host-side writer's frames reach the guest.
//! - Frames the guest sends while no switch is connected are dropped, and
//!   the write succeeds: what Linux does with a frame written to a TAP that
//!   is up when nothing on the host takes it (drivers/net/tun.c,
//!   `tun_get_user`: the frame goes to the host's stack and the write
//!   returns its length). An endpoint is never down, so the `EIO` a write to
//!   a TAP that is down gets (the same function, `!(dev->flags & IFF_UP)`)
//!   has no counterpart here.
//! - The endpoint drops no frame of a switch for want of room: while
//!   Firecracker does not read, the frames wait in the connection, and a
//!   full connection holds the switch's writes back. A TAP drops instead:
//!   `tun_net_xmit` drops the host's frame when the TAP's queue
//!   (`TUN_READQ_SIZE`, 500 frames) is full (`ptr_ring_produce` fails) or
//!   no process holds the TAP (`!tfile`). With no Firecracker there is no
//!   endpoint, and a switch cannot connect.
//! - The descriptor is the interface: once it is closed, reads and writes
//!   fail with `EBADF` and the connected switch is disconnected, whoever
//!   closed it (`Endpoint::check_open`).
//! - The guest's frames are never sent in part. A frame the connection
//!   cannot take at all is dropped and its write fails with `ENOBUFS`,
//!   which upstream logs and counts in `tap_write_fails` (net/device.rs,
//!   `write_to_mmds_or_tap`), as on macOS, where a `sendto` the datagram
//!   endpoint's peer refuses fails the write (`send_to_peers`). Linux's
//!   write to a TAP is never refused for room: the TAP's socket has
//!   `sk_sndbuf` `INT_MAX` (v6.1 drivers/net/tun.c:3455), and `tun_get_user`
//!   hands the frame to the host's stack and returns its length (:1544 to
//!   :1548, :2010 to :2020); a frame lost after that is counted by the
//!   host, in the receiving socket's `RcvbufErrors` (net/ipv4/udp.c:2094)
//!   or the TAP's `rx_dropped` (net/core/dev.c:4694 to :4697). Nothing past
//!   the endpoint counts a frame, so the endpoint does not drop one
//!   silently (`test_a_frame_the_connection_cannot_take_fails_with_enobufs`).
//!   A frame segmented here (an offloaded superframe) fails the same way if
//!   the connection had no room for one of its segments, once every
//!   segment was tried (`test_a_superframe_with_a_segment_dropped_fails_with_enobufs`).
//!   A frame the connection took part of is completed, waiting up to
//!   [`SEND_STALL`] for the switch, after which the switch is disconnected
//!   (a byte stream cannot skip the rest of a frame). The write does not
//!   wait for room otherwise: Firecracker's event loop serves every device
//!   from one thread, and a TAP never makes it wait for a reader.
//! - The descriptor that is polled is the listening socket for the life of
//!   the interface; the epoll follows it to the connection it accepted
//!   ([`vmm_sys_util::epoll::Redirect`]), and reads report when they leave
//!   nothing behind, as edge-triggered polling needs.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::raw::{c_int, c_uint};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vmm_sys_util::epoll::Redirect;

use crate::devices::virtio::iovec::IoVecBuffer;
use crate::platform::net::{TapDevice, TapError};
use crate::platform::vnet::{self, VnetHdr};

/// `IFNAMSIZ`: interface names are shorter.
const IFACE_NAME_MAX_LEN: usize = 16;
/// Most interfaces a `%d` name is tried with.
const MAX_UNITS: u32 = 1 << 15;
/// The largest frame a switch may send: a 64 KiB packet and its Ethernet
/// header.
const MAX_FRAME: usize = 65536 + 14 + 4 + 4;
/// How long the rest of a frame the connection took part of may wait.
pub const SEND_STALL: Duration = Duration::from_secs(1);
/// How much is read from the connection at a time.
const READ_CHUNK: usize = 64 << 10;

/// The directory of endpoints named without a path separator: the jail's
/// own directory of its network, if the jailer gave one (`--netns`,
/// `ext::jail::netns`: `<network>\<id>`), else `%TEMP%\firecracker-net`.
pub fn endpoint_dir() -> io::Result<PathBuf> {
    if let Some(dir) = crate::ext::jail::netns() {
        return Ok(dir.to_path_buf());
    }
    let dir = std::env::temp_dir().join("firecracker-net");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Endpoints by interface index, for [`simulator`].
static INDEXES: Mutex<Vec<(i32, PathBuf)>> = Mutex::new(Vec::new());
static NEXT_INDEX: AtomicI32 = AtomicI32::new(1);

/// The listening endpoint and the switch connected to it.
struct Endpoint {
    listener: UnixListener,
    path: PathBuf,
    redirect: Arc<Redirect>,
    conn: Option<UnixStream>,
    /// Bytes received from the switch and not handed to the guest yet.
    rx: Vec<u8>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("path", &self.path)
            .field("connected", &self.conn.is_some())
            .finish()
    }
}

impl Endpoint {
    /// Listens at `path`. `EBUSY` if an endpoint listens there already; a
    /// socket file nothing listens on (left by a process that died) is
    /// replaced.
    fn open(path: &Path) -> io::Result<Self> {
        let listener = match UnixListener::bind(path) {
            Ok(l) => l,
            Err(err) if path.exists() => {
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::from_raw_os_error(libc::EBUSY));
                }
                std::fs::remove_file(path).map_err(|_| err)?;
                UnixListener::bind(path)?
            }
            Err(err) => return Err(err),
        };
        listener.set_nonblocking(true)?;
        let redirect = Redirect::attach(listener.as_raw_fd())?;
        Ok(Endpoint {
            listener,
            path: path.to_owned(),
            redirect,
            conn: None,
            rx: Vec::new(),
        })
    }

    /// Takes the first waiting switch if none is connected. Later ones stay
    /// in the listener's queue until this one leaves: one taken in the same
    /// call would be closed with whatever it had sent unread, though the
    /// one before it may have left already, its end not read yet (a switch
    /// that sends and closes, then the next that connects and sends, before
    /// a read: two frames, and the second was lost).
    ///
    /// No switch waiting is no error. A listener that fails otherwise fails
    /// the I/O that asked. (A closed listener does not get here:
    /// [`Endpoint::check_open`] has refused the I/O.)
    fn accept(&mut self) -> io::Result<()> {
        while self.conn.is_none() {
            let conn = match self.listener.accept() {
                Ok((conn, _)) => conn,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                // A switch that went away before it was taken: the next.
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            };
            // A connection that cannot be made non-blocking is dropped; the
            // next waiting one is tried.
            if conn.set_nonblocking(true).is_ok() {
                self.redirect.set(Some(conn.as_raw_fd()));
                self.conn = Some(conn);
            }
        }
        Ok(())
    }

    /// `EBADF` unless the tap's descriptor still names the listening socket.
    ///
    /// The descriptor Firecracker holds for the interface
    /// ([`Tap::as_raw_fd`]) is the listener's, while frames flow on the
    /// connection it accepted. On Linux `readv` and `writev` look the
    /// descriptor up first and fail with `EBADF` when it is closed
    /// (fs/read_write.c, `do_readv` and `do_writev`: `fdget_pos`), so a
    /// closed tap descriptor passes no frame, whatever is at the other
    /// side. Here the connection would carry on without this check, as it
    /// did: upstream's test_tx_tap_failure and
    /// test_read_tap_fail_event_handler close the descriptor to count
    /// tap_write_fails and tap_read_fails, and passed only because they
    /// connect no switch (the listener's `accept` failed).
    ///
    /// The switch is disconnected, as the TAP's queue goes with its
    /// descriptor, and what it had sent is discarded.
    ///
    /// "Still names" is the descriptor table's answer
    /// (`libc::wick_fd::attached`): the [`Redirect`] attached at
    /// [`Endpoint::open`] is found only while the value names the object it
    /// was attached to (`CompareObjectHandles` with the table's own handle
    /// of it), so a value closed by any call, or one that names another
    /// object since, is not the listener. Under a jail's strict handle
    /// checks the table asks as a probe (`libc::wick_fd::probe`), which
    /// the sandbox lets fail.
    ///
    /// Cost, once per [`Tap::write_iovec`] and [`Tap::read_iovec`] (not
    /// per segment of an offloaded frame): the table's lock, a hash lookup
    /// and one system call (`CompareObjectHandles`). Its time is on record
    /// from test_descriptor_check_cost_on_record (the TAPCHECK line): 889 ns
    /// a check, against 5,967 ns for a whole `write_iovec` of a 1514-byte
    /// frame, in an unoptimised build on CI's runner (AMD EPYC 7763, run
    /// 43318983352). The effect on a guest's throughput (`boot-test.ps1
    /// net`, kit against kit) is not measured yet.
    fn check_open(&mut self) -> io::Result<()> {
        let fd = self.listener.as_raw_fd();
        let attached = libc::wick_fd::attached::<Redirect>(fd);
        if attached.is_some_and(|r| Arc::ptr_eq(&r, &self.redirect)) {
            return Ok(());
        }
        self.disconnect();
        Err(io::Error::from_raw_os_error(libc::EBADF))
    }

    fn disconnect(&mut self) {
        self.redirect.set(None);
        self.conn = None;
        self.rx.clear();
    }

    /// The length of the first complete frame in `rx`.
    fn complete_frame(&self) -> Option<usize> {
        let len = u32::from_be_bytes(self.rx.get(..4)?.try_into().unwrap()) as usize;
        (self.rx.len() >= 4 + len).then_some(len)
    }

    /// Receives one frame into `iovs`, truncated to fit. `None` if no frame
    /// is waiting.
    fn recv(&mut self, iovs: &mut [libc::iovec]) -> io::Result<Option<usize>> {
        loop {
            if let Some(len) = self.complete_frame() {
                let mut copied = 0;
                for iov in iovs.iter() {
                    let n = iov.iov_len.min(len - copied);
                    // SAFETY: the iovec names memory the caller lets us
                    // write; the source is within `rx`.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            self.rx[4 + copied..].as_ptr(),
                            iov.iov_base.cast::<u8>(),
                            n,
                        );
                    }
                    copied += n;
                    if copied == len {
                        break;
                    }
                }
                self.rx.drain(..4 + len);
                return Ok(Some(copied));
            }
            if self.conn.is_none() {
                self.accept()?;
            }
            let Some(conn) = self.conn.as_mut() else {
                libc::wick_fd::drained(self.listener.as_raw_fd());
                return Ok(None);
            };
            let at = self.rx.len();
            self.rx.resize(at + READ_CHUNK, 0);
            let read = conn.read(&mut self.rx[at..]);
            self.rx.truncate(at + *read.as_ref().unwrap_or(&0));
            match read {
                // The switch left: the next one may connect.
                Ok(0) => self.disconnect(),
                Ok(_) => {
                    if self.rx.len() >= 4 && self.complete_frame().is_none() {
                        let len = u32::from_be_bytes(self.rx[..4].try_into().unwrap()) as usize;
                        if len > MAX_FRAME {
                            // Not this framing: the switch is dropped.
                            self.disconnect();
                        }
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    libc::wick_fd::drained(self.listener.as_raw_fd());
                    return Ok(None);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                // A broken connection is a switch that left.
                Err(_) => self.disconnect(),
            }
        }
    }

    /// Sends one frame to the switch, or drops it (see the module docs):
    /// `ENOBUFS` if the connection had no room for any of it; no error
    /// with no switch connected.
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if self.conn.is_none() {
            self.accept()?;
        }
        let Some(conn) = self.conn.as_mut() else {
            return Ok(());
        };
        let len = u32::try_from(frame.len())
            .map_err(|_| io::Error::from_raw_os_error(libc::EMSGSIZE))?;
        let mut msg = Vec::with_capacity(4 + frame.len());
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(frame);
        let sent = match conn.write(&msg) {
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
            }
            Err(_) => {
                self.disconnect();
                return Ok(());
            }
        };
        if sent < msg.len() {
            let finished = (|| {
                conn.set_nonblocking(false)?;
                conn.set_write_timeout(Some(SEND_STALL))?;
                conn.write_all(&msg[sent..])?;
                conn.set_write_timeout(None)?;
                conn.set_nonblocking(true)
            })();
            if finished.is_err() {
                self.disconnect();
            }
        }
        Ok(())
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A network interface for a virtio-net device.
#[derive(Debug)]
pub struct Tap {
    name: String,
    endpoint: Endpoint,
    index: i32,
    hdr_len: AtomicUsize,
    offload: AtomicU32,
    /// The frame being written, and the segments made of it.
    tx: Vec<u8>,
    scratch: Vec<u8>,
}

/// An endpoint path; `%d` in its last component is a unit number.
fn parse_name(if_name: &str) -> Result<(Option<PathBuf>, String), TapError> {
    let invalid = || TapError::InvalidIfname;
    let percent = if_name.matches('%').count();
    if percent > 1 || (percent == 1 && !if_name.contains("%d")) {
        return Err(invalid());
    }
    if if_name.contains(['/', '\\']) {
        return Ok((None, if_name.to_owned()));
    }
    // The rules of Linux's `dev_valid_name`, plus what Windows file names
    // cannot hold.
    let name = if if_name.is_empty() { "tap%d" } else { if_name };
    if name.len() >= IFACE_NAME_MAX_LEN
        || name == "."
        || name == ".."
        || name.contains(|c: char| c.is_whitespace() || ":*?\"<>|".contains(c))
    {
        return Err(invalid());
    }
    let dir = endpoint_dir().map_err(TapError::OpenTun)?;
    Ok((Some(dir), name.to_owned()))
}

fn open_endpoint(dir: Option<&Path>, name: &str) -> Result<(String, Endpoint), TapError> {
    let open = |name: &str| {
        let path = match dir {
            Some(dir) => dir.join(name),
            None => PathBuf::from(name),
        };
        // `sockaddr_un` holds 108 bytes with the NUL.
        if path.as_os_str().len() >= 108 {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        Endpoint::open(&path)
    };
    let failed = |err: io::Error, name: &str| match err.raw_os_error() {
        Some(libc::ENAMETOOLONG) => TapError::InvalidIfname,
        _ => TapError::IfreqExecuteError(err, name.to_owned()),
    };
    if !name.contains("%d") {
        return open(name)
            .map(|ep| (name.to_owned(), ep))
            .map_err(|e| failed(e, name));
    }
    for unit in 0..MAX_UNITS {
        let candidate = name.replacen("%d", &unit.to_string(), 1);
        if dir.is_some() && candidate.len() >= IFACE_NAME_MAX_LEN {
            break;
        }
        match open(&candidate) {
            Ok(ep) => return Ok((candidate, ep)),
            Err(err) if err.raw_os_error() == Some(libc::EBUSY) => continue,
            Err(err) => return Err(failed(err, &candidate)),
        }
    }
    Err(TapError::IfreqExecuteError(
        io::Error::from_raw_os_error(libc::ENFILE),
        name.to_owned(),
    ))
}

impl Tap {
    /// See [`TapDevice::open_named`].
    pub fn open_named(if_name: &str) -> Result<Tap, TapError> {
        let (dir, name) = parse_name(if_name)?;
        let (name, endpoint) = open_endpoint(dir.as_deref(), &name)?;
        let index = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
        INDEXES
            .lock()
            .unwrap()
            .push((index, endpoint.path.clone()));
        Ok(Tap {
            name,
            endpoint,
            index,
            hdr_len: AtomicUsize::new(vnet::MIN_HDR_LEN),
            offload: AtomicU32::new(0),
            tx: Vec::new(),
            scratch: Vec::new(),
        })
    }

    /// See [`TapDevice::if_name_as_str`].
    pub fn if_name_as_str(&self) -> &str {
        &self.name
    }

    /// See [`TapDevice::set_offload`]. The host never hands the guest
    /// offloaded frames, which every setting allows.
    pub fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        vnet::check_offload(flags).map_err(TapError::SetOffloadFlags)?;
        self.offload.store(flags, Ordering::Relaxed);
        Ok(())
    }

    /// See [`TapDevice::set_vnet_hdr_size`].
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        let len = vnet::check_hdr_len(size).map_err(TapError::SetSizeOfVnetHdr)?;
        self.hdr_len.store(len, Ordering::Relaxed);
        Ok(())
    }

    /// See [`TapDevice::write_iovec`].
    pub fn write_iovec(&mut self, buffer: &IoVecBuffer) -> io::Result<usize> {
        self.endpoint.check_open()?;
        let total = buffer.len() as usize;
        let hdr_len = self.hdr_len.load(Ordering::Relaxed);
        copy_frame(buffer, &mut self.tx);
        debug_assert_eq!(self.tx.len(), total);
        // As the TUN driver: a header and at least an Ethernet header.
        if self.tx.len() < hdr_len + 14 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let (hdr, frame) = self.tx.split_at_mut(hdr_len);
        let hdr = VnetHdr::parse(hdr).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let endpoint = &mut self.endpoint;
        // A segment the connection had no room for is dropped and the
        // others are still tried, as the host's stack would take each
        // segment of a frame a TAP was given; the write then fails.
        let mut dropped = false;
        vnet::segment(&hdr, frame, &mut self.scratch, &mut |seg| match endpoint.send(seg) {
            Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => {
                dropped = true;
                Ok(())
            }
            other => other,
        })?;
        if dropped {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }
        Ok(total)
    }

    /// See [`TapDevice::read_iovec`]. The header is zeroed: a complete
    /// frame, no offloads.
    pub fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        self.endpoint.check_open()?;
        let hdr_len = self.hdr_len.load(Ordering::Relaxed);
        let mut skip = hdr_len;
        let mut first = 0;
        while first < buffer.len() && skip >= buffer[first].iov_len && skip > 0 {
            let len = buffer[first].iov_len;
            // SAFETY: the iovec names memory the caller lets us write.
            unsafe { std::ptr::write_bytes(buffer[first].iov_base.cast::<u8>(), 0, len) };
            skip -= len;
            first += 1;
        }
        if skip > 0 && first == buffer.len() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let saved = buffer.get(first).copied();
        if let Some(iov) = buffer.get_mut(first) {
            // SAFETY: as above; `skip` is within this iovec.
            unsafe { std::ptr::write_bytes(iov.iov_base.cast::<u8>(), 0, skip) };
            // SAFETY: `skip` is below `iov_len`.
            iov.iov_base = unsafe { iov.iov_base.cast::<u8>().add(skip) }.cast();
            iov.iov_len -= skip;
        }
        let result = self.endpoint.recv(&mut buffer[first..]);
        if let Some(saved) = saved {
            buffer[first] = saved;
        }
        match result? {
            Some(n) => Ok(hdr_len + n),
            None => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
        }
    }
}

/// Copies the frame the guest's descriptors name into `tx` (cleared first),
/// taking the guest's pages that were never committed as the zeros they
/// read as, without touching them: a copy that touched them would commit
/// and charge them (the exception handler of lazy guest RAM), where Linux's
/// TAP write copies them with `copy_from_user`, whose read fault maps the
/// zero page and charges nothing (mm/memory.c v6.1 4088-4091,
/// `do_anonymous_page`). The host-read plan's U1; the rest is copied as
/// `IoVecBuffer::read_volatile_at` copies it.
fn copy_frame(buffer: &IoVecBuffer, tx: &mut Vec<u8>) {
    tx.clear();
    tx.reserve(buffer.len() as usize);
    // SAFETY: the buffer's iovecs, which it keeps valid while it lives.
    let iovecs = unsafe { std::slice::from_raw_parts(buffer.as_iovec_ptr(), buffer.iovec_count()) };
    for v in iovecs {
        libc::wick_mm::zero_runs(v.iov_base as usize, v.iov_len, |start, len, zeros| {
            let at = tx.len();
            if zeros {
                tx.resize(at + len, 0);
                return;
            }
            tx.reserve(len);
            // SAFETY: `[start, start + len)` is guest memory a descriptor
            // names (valid for reads while the buffer lives), and `tx` has
            // room for `len` bytes past `at`.
            unsafe {
                std::ptr::copy_nonoverlapping(start as *const u8, tx.as_mut_ptr().add(at), len);
                tx.set_len(at + len);
            }
        });
    }
}

impl TapDevice for Tap {
    fn open_named(if_name: &str) -> Result<Self, TapError> {
        Tap::open_named(if_name)
    }

    fn if_name_as_str(&self) -> &str {
        Tap::if_name_as_str(self)
    }

    fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        Tap::set_offload(self, flags)
    }

    fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        Tap::set_vnet_hdr_size(self, size)
    }

    fn write_iovec(&mut self, buffer: &IoVecBuffer) -> io::Result<usize> {
        Tap::write_iovec(self, buffer)
    }

    fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        Tap::read_iovec(self, buffer)
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.endpoint.listener.as_raw_fd()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        INDEXES.lock().unwrap().retain(|(i, _)| *i != self.index);
    }
}

#[doc(hidden)]
pub mod simulator {
    //! The host side of a [`Tap`]: what the Linux tests do with a packet
    //! socket bound to the TAP.

    use std::cell::RefCell;

    use super::*;

    /// The index of an open interface.
    pub fn if_index(tap: &Tap) -> i32 {
        tap.index
    }

    /// Brings the interface up. Endpoints are always up.
    pub fn enable(_tap: &Tap) {}

    /// A switch connected to an endpoint.
    #[derive(Debug)]
    pub struct TapTrafficSimulator {
        conn: UnixStream,
        rx: RefCell<Vec<u8>>,
    }

    impl TapTrafficSimulator {
        /// Connects to the interface with index `tap_index`.
        pub fn new(tap_index: i32) -> Self {
            let path = INDEXES
                .lock()
                .unwrap()
                .iter()
                .find(|(i, _)| *i == tap_index)
                .map(|(_, p)| p.clone())
                .expect("no endpoint interface with this index");
            let conn = UnixStream::connect(path).unwrap();
            conn.set_nonblocking(true).unwrap();
            TapTrafficSimulator {
                conn,
                rx: RefCell::new(Vec::new()),
            }
        }

        /// Sends a frame to the interface.
        pub fn push_tx_packet(&self, buf: &[u8]) {
            if buf.is_empty() {
                return;
            }
            let mut msg = u32::try_from(buf.len()).unwrap().to_be_bytes().to_vec();
            msg.extend_from_slice(buf);
            self.conn.set_nonblocking(false).unwrap();
            (&self.conn)
                .write_all(&msg)
                .expect("Can't inject tx_packet");
            self.conn.set_nonblocking(true).unwrap();
        }

        /// Receives a frame from the interface, if one is waiting.
        pub fn pop_rx_packet(&self, buf: &mut [u8]) -> bool {
            let mut rx = self.rx.borrow_mut();
            let mut chunk = [0u8; 4096];
            loop {
                match (&self.conn).read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => rx.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            let Some(len) = rx
                .get(..4)
                .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
            else {
                return false;
            };
            if rx.len() < 4 + len {
                return false;
            }
            let n = len.min(buf.len());
            buf[..n].copy_from_slice(&rx[4..4 + n]);
            rx.drain(..4 + len);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::simulator::*;
    use super::*;

    fn frame(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// U1: the guest's frame is copied with its untouched lazy pages as
    /// zeros, and those pages stay uncommitted (not in the working set:
    /// `mincore`), as Linux's copy maps the zero page for them.
    #[test]
    fn test_a_frame_from_untouched_guest_memory_commits_nothing() {
        const PAGE: usize = 4096;
        let len = 16 * PAGE;
        // SAFETY: lazy anonymous memory for the test, unmapped below.
        let m = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(m, libc::MAP_FAILED);
        let m = m.cast::<u8>();
        let mut want = vec![0u8; len];
        for i in [1usize, 2, 9] {
            want[i * PAGE + 3] = u8::try_from(i).unwrap();
            // SAFETY: our mapping.
            unsafe { *m.add(i * PAGE + 3) = want[i * PAGE + 3] };
        }
        let resident = || {
            let mut v = vec![0u8; 16];
            // SAFETY: our mapping and a byte a page.
            assert_eq!(unsafe { libc::mincore(m.cast(), len, v.as_mut_ptr()) }, 0);
            v.iter().filter(|b| **b & 1 != 0).count()
        };
        assert_eq!(resident(), 3);
        // SAFETY: our mapping, read as guest memory is.
        let guest = unsafe { std::slice::from_raw_parts(m.add(100), len - 200) };
        let mut tx = vec![7u8; 5];
        copy_frame(&IoVecBuffer::from(guest), &mut tx);
        assert_eq!(tx, &want[100..len - 100]);
        assert_eq!(resident(), 3, "the copy committed untouched memory");
        // SAFETY: our mapping.
        assert_eq!(unsafe { libc::munmap(m.cast(), len) }, 0);
    }

    #[test]
    fn test_parse_name() {
        assert!(matches!(parse_name("tap%d"), Ok((Some(_), _))));
        assert!(matches!(parse_name(r"C:\x\ep.sock"), Ok((None, _))));
        assert!(matches!(parse_name("a:b"), Err(TapError::InvalidIfname)));
        assert!(matches!(parse_name("%s"), Err(TapError::InvalidIfname)));
    }

    /// `tap.read_iovec`, retried for up to 0.5 s while it finds nothing.
    fn read_frame(tap: &mut Tap, rx: &mut [u8]) -> io::Result<usize> {
        let mut iov = [libc::iovec {
            iov_base: rx.as_mut_ptr().cast(),
            iov_len: rx.len(),
        }];
        let mut n = Err(io::Error::from_raw_os_error(libc::EAGAIN));
        for _ in 0..100 {
            n = tap.read_iovec(&mut iov);
            if n.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        n
    }

    #[test]
    fn test_one_switch_at_a_time() {
        let mut tap = Tap::open_named("fcsw%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let a = TapTrafficSimulator::new(if_index(&tap));
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&frame(100));
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        // b connects while a is there, and sends: it waits.
        let b = TapTrafficSimulator::new(if_index(&tap));
        b.push_tx_packet(&frame(70));
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        let mut buf = vec![0u8; 200];
        assert!(a.pop_rx_packet(&mut buf));
        assert_eq!(&buf[..100], &out[12..]);
        assert!(a.pop_rx_packet(&mut buf));
        assert!(!b.pop_rx_packet(&mut buf), "the guest's frames go to the connected switch only");
        let mut rx = vec![0u8; 200];
        let mut iov = [libc::iovec {
            iov_base: rx.as_mut_ptr().cast(),
            iov_len: rx.len(),
        }];
        let err = tap.read_iovec(&mut iov).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EAGAIN), "b's frame waits while a is there");

        // a leaves; b takes its place, and what it sent comes in.
        drop(a);
        assert_eq!(read_frame(&mut tap, &mut rx).unwrap(), 12 + 70);
        assert_eq!(&rx[12..82], &frame(70)[..]);
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        assert!(b.pop_rx_packet(&mut buf));
        assert_eq!(&buf[..100], &out[12..]);
    }

    #[test]
    fn test_closed_descriptor_fails_io_with_a_switch_connected() {
        // Upstream's test_tx_tap_failure and test_read_tap_fail_event_handler
        // close the tap's descriptor under the device and count the I/O
        // that fails; no switch is connected there. With one connected the
        // answer is the same on Linux: the write and the read are refused
        // at the descriptor (EBADF) whoever is at the tap's other side.
        let mut tap = Tap::open_named("fcclosed%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let mut switch = UnixStream::connect(&tap.endpoint.path).unwrap();
        switch.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&frame(100));

        // The switch is the connected one: a frame each way.
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        let mut got = [0u8; 4 + 100];
        switch.read_exact(&mut got).unwrap();
        assert_eq!(&got[..4], &100u32.to_be_bytes()[..]);
        assert_eq!(&got[4..], &frame(100)[..]);
        let mut msg = 70u32.to_be_bytes().to_vec();
        msg.extend_from_slice(&frame(70));
        switch.write_all(&msg).unwrap();
        let mut rx = vec![0u8; 200];
        assert_eq!(read_frame(&mut tap, &mut rx).unwrap(), 12 + 70);

        // SAFETY: closes the tap's descriptor under it, as upstream's tests
        // do. Nothing uses the value again: see the end of the test.
        assert_eq!(unsafe { libc::close(tap.as_raw_fd()) }, 0);

        let err = tap
            .write_iovec(&IoVecBuffer::from(out.as_slice()))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF), "tx on the closed descriptor");
        let mut iov = [libc::iovec {
            iov_base: rx.as_mut_ptr().cast(),
            iov_len: rx.len(),
        }];
        let err = tap.read_iovec(&mut iov).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF), "rx on the closed descriptor");

        // The switch's connection went with the descriptor, and the frame
        // written after the close did not reach it: end of stream, at once
        // or within the read's timeout (an error here is the test's
        // failure).
        let mut byte = [0u8; 1];
        assert_eq!(switch.read(&mut byte).unwrap(), 0, "the switch reads end of stream");

        // The listener's descriptor is closed already. Dropping the tap
        // would close its value a second time, which by then may name a
        // handle made since.
        let path = tap.endpoint.path.clone();
        std::mem::forget(tap);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_a_frame_with_no_switch_is_dropped_and_the_write_succeeds() {
        // As a write to a TAP that is up when nothing on the host takes
        // the frame (drivers/net/tun.c, tun_get_user): the whole length is
        // returned, and the frame is gone, not kept for a later switch.
        let mut tap = Tap::open_named("fcnosw%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let mut lost = vec![0u8; 12];
        lost.extend_from_slice(&frame(100));
        let n = tap.write_iovec(&IoVecBuffer::from(lost.as_slice())).unwrap();
        assert_eq!(n, lost.len());

        let mut switch = UnixStream::connect(&tap.endpoint.path).unwrap();
        switch.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&frame(60));
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        // The first thing the switch reads is the second frame.
        let mut got = [0u8; 4 + 60];
        switch.read_exact(&mut got).unwrap();
        assert_eq!(&got[..4], &60u32.to_be_bytes()[..]);
        assert_eq!(&got[4..], &frame(60)[..]);
    }

    /// A switch connected to an endpoint that reads nothing until
    /// [`Holder::finish`], so that the connection fills. One exception: a
    /// write that has been inside [`Tap::write_iovec`] for 200 ms is
    /// completing a frame the connection took part of ([`SEND_STALL`]),
    /// and the switch then reads 64 KiB, room for the rest, so that the
    /// completion is not stalled into a disconnect (`stalls` counts them).
    struct Holder {
        go: std::sync::mpsc::Sender<()>,
        reader: std::thread::JoinHandle<(Vec<u8>, String, usize)>,
        base: std::time::Instant,
        writing_since: Arc<std::sync::atomic::AtomicU64>,
    }

    impl Holder {
        fn connect(tap: &Tap) -> Self {
            use std::sync::mpsc::RecvTimeoutError;
            let mut switch = UnixStream::connect(&tap.endpoint.path).unwrap();
            let (go, wait) = std::sync::mpsc::channel::<()>();
            let base = std::time::Instant::now();
            let writing_since = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let since = Arc::clone(&writing_since);
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let mut chunk = vec![0u8; 64 << 10];
                let mut stalls = 0;
                loop {
                    match wait.recv_timeout(Duration::from_millis(20)) {
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {
                            let at = since.load(Ordering::SeqCst);
                            let now = u64::try_from(base.elapsed().as_nanos()).unwrap() + 1;
                            if at != 0 && at != u64::MAX && now.saturating_sub(at) > 200_000_000 {
                                stalls += 1;
                                let n = switch.read(&mut chunk).unwrap();
                                bytes.extend_from_slice(&chunk[..n]);
                                // Not again for the same write.
                                let _ = since.compare_exchange(at, u64::MAX, Ordering::SeqCst, Ordering::SeqCst);
                            }
                        }
                    }
                }
                switch.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                loop {
                    match switch.read(&mut chunk) {
                        Ok(0) => return (bytes, "end of stream".to_string(), stalls),
                        Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                        Err(err) => return (bytes, format!("{err}"), stalls),
                    }
                }
            });
            Holder { go, reader, base, writing_since }
        }

        fn write(&self, tap: &mut Tap, buffer: &IoVecBuffer) -> io::Result<usize> {
            let now = u64::try_from(self.base.elapsed().as_nanos()).unwrap() + 1;
            self.writing_since.store(now, Ordering::SeqCst);
            let result = tap.write_iovec(buffer);
            self.writing_since.store(0, Ordering::SeqCst);
            result
        }

        /// Shuts the tap's side down for writing, lets the switch read to
        /// the end, and returns the frames it got and its stalls.
        fn finish(self, tap: &mut Tap) -> (Vec<Vec<u8>>, usize) {
            if let Some(conn) = tap.endpoint.conn.as_ref() {
                conn.shutdown(std::net::Shutdown::Write).unwrap();
            }
            self.go.send(()).unwrap();
            let (bytes, end, stalls) = self.reader.join().unwrap();
            assert_eq!(end, "end of stream");
            let mut frames = Vec::new();
            let mut at = 0;
            while at < bytes.len() {
                assert!(at + 4 <= bytes.len(), "a length sent in part");
                let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
                assert!(at + 4 + len <= bytes.len(), "a frame sent in part: {} bytes after the last whole one", bytes.len() - at);
                frames.push(bytes[at + 4..at + 4 + len].to_vec());
                at += 4 + len;
            }
            (frames, stalls)
        }
    }

    #[test]
    fn test_a_frame_the_connection_cannot_take_fails_with_enobufs() {
        // A switch that reads nothing: the frames go into the connection
        // until it is full, and the first it cannot take fails with
        // ENOBUFS, so upstream counts it in tap_write_fails, where it was
        // dropped with the write's whole length returned and nothing
        // counted it (the module docs). The switch then gets exactly the
        // frames whose writes succeeded, whole.
        const LIMIT: usize = 200_000;
        let mut tap = Tap::open_named("fcfull%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let holder = Holder::connect(&tap);
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&frame(1514));
        let buffer = IoVecBuffer::from(out.as_slice());
        let mut taken = 0;
        let mut refused = None;
        for _ in 0..LIMIT {
            match holder.write(&mut tap, &buffer) {
                Ok(n) => {
                    assert_eq!(n, out.len());
                    taken += 1;
                }
                Err(err) => {
                    refused = Some(err);
                    break;
                }
            }
        }
        let connected = tap.endpoint.conn.is_some();
        let (frames, stalls) = holder.finish(&mut tap);
        let err = refused.unwrap_or_else(|| {
            panic!("{LIMIT} frames written to a switch that reads nothing and none refused ({} reached it)", frames.len())
        });
        assert_eq!(err.raw_os_error(), Some(libc::ENOBUFS), "{err}");
        assert!(connected, "the switch was disconnected");
        assert_eq!(frames.len(), taken, "frames the switch got against writes that succeeded ({stalls} stalls)");
        assert!(frames.iter().all(|f| f[..] == frame(1514)[..]));
    }

    /// An IPv4 TCP superframe of `payload` bytes as a guest's TSO writes
    /// it, its virtio-net header (12 bytes) first: segments of `mss`.
    fn tso_superframe(payload: usize, mss: u16) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        VnetHdr {
            flags: vnet::F_NEEDS_CSUM,
            gso_type: vnet::GSO_TCPV4,
            hdr_len: 54,
            gso_size: mss,
            csum_start: 34,
            csum_offset: 16,
        }
        .write(&mut f);
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00]);
        let total = u16::try_from(40 + payload).unwrap();
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1]);
        f.extend_from_slice(&[0x30, 0x39, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        f.extend((0..payload).map(|i| (i * 7 % 251) as u8));
        f
    }

    #[test]
    fn test_a_superframe_with_a_segment_dropped_fails_with_enobufs() {
        // Superframes segmented here, to a switch that reads nothing:
        // the first whose segments the connection does not all take fails
        // with ENOBUFS once every segment was tried, and the switch gets
        // the segments of the frames that succeeded, and those of the
        // refused one that fitted, never all of them.
        const LIMIT: usize = 20_000;
        const PAYLOAD: usize = 64_000;
        const MSS: u16 = 1448;
        let segments = PAYLOAD.div_ceil(usize::from(MSS));
        let mut tap = Tap::open_named("fcfullso%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let holder = Holder::connect(&tap);
        let out = tso_superframe(PAYLOAD, MSS);
        let buffer = IoVecBuffer::from(out.as_slice());
        let mut taken = 0;
        let mut refused = None;
        for _ in 0..LIMIT {
            match holder.write(&mut tap, &buffer) {
                Ok(n) => {
                    assert_eq!(n, out.len());
                    taken += 1;
                }
                Err(err) => {
                    refused = Some(err);
                    break;
                }
            }
        }
        let connected = tap.endpoint.conn.is_some();
        let (frames, stalls) = holder.finish(&mut tap);
        let err = refused.unwrap_or_else(|| {
            panic!("{LIMIT} superframes written to a switch that reads nothing and none refused ({} segments reached it)", frames.len())
        });
        assert_eq!(err.raw_os_error(), Some(libc::ENOBUFS), "{err}");
        assert!(connected, "the switch was disconnected");
        assert!(frames.iter().all(|f| f.len() <= 14 + 40 + usize::from(MSS)));
        let of_refused = frames.len().checked_sub(taken * segments).unwrap_or_else(|| {
            panic!("{} segments for {taken} superframes of {segments} that succeeded ({stalls} stalls)", frames.len())
        });
        assert!(of_refused < segments, "all {segments} segments of the refused superframe reached the switch");
        println!("SOFULL superframes={taken} segments_each={segments} of_the_refused_one={of_refused} stalls={stalls}");
    }

    /// What [`Endpoint::check_open`] costs, on record: the time of a check
    /// alone, and of a whole `write_iovec` of a 1514-byte frame (which
    /// holds one check) to a switch that reads. Times are the test
    /// profile's (unoptimised) on whatever machine runs it; nothing is
    /// asserted of them. The guest-visible effect is `boot-test.ps1 net`'s
    /// throughput on the PC, kit against kit.
    #[test]
    #[ignore = "a record: prints the TAPCHECK line, asserts no time"]
    fn test_descriptor_check_cost_on_record() {
        const N: u32 = 20_000;
        let mut tap = Tap::open_named("fccost%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let mut switch = UnixStream::connect(&tap.endpoint.path).unwrap();
        switch.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // The switch reads to the end of the stream, so the connection is
        // not full for long. `write_iovec` here is as fast as the loop
        // goes, with no guest in between, so the reading thread can fall
        // behind: a frame the full connection cannot take at all is
        // dropped and its write fails with ENOBUFS, as in the product
        // ([`Endpoint::send`] and the module docs), so it is in `refused`
        // and not in `delivered` (before the write failed, run
        // 43323860314: 19929 of 20000 delivered; run 43318983352: all
        // 20000). The tap's side is shut down for writing before the
        // tap goes, so everything the connection took is read first
        // (`end` is how the stream ended, `rest` the bytes after the last
        // whole frame): `frames - delivered` are then the dropped ones,
        // and their writes, which sent nothing, are in the average.
        let reader = std::thread::spawn(move || {
            let mut chunk = vec![0u8; 64 << 10];
            let mut bytes = 0usize;
            loop {
                match switch.read(&mut chunk) {
                    Ok(0) => return (bytes, "end of stream".to_string()),
                    Err(err) => return (bytes, format!("{err}")),
                    Ok(n) => bytes += n,
                }
            }
        });
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&frame(1514));
        let buffer = IoVecBuffer::from(out.as_slice());

        let start = std::time::Instant::now();
        let mut refused = 0u32;
        for _ in 0..N {
            match tap.write_iovec(&buffer) {
                Ok(_) => {}
                Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => refused += 1,
                Err(err) => panic!("{err}"),
            }
        }
        let write = start.elapsed();
        let start = std::time::Instant::now();
        for _ in 0..N {
            tap.endpoint.check_open().unwrap();
        }
        let check = start.elapsed();
        let connected = tap.endpoint.conn.is_some();
        if let Some(conn) = tap.endpoint.conn.as_ref() {
            conn.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let (bytes, end) = reader.join().unwrap();
        drop(tap);
        println!(
            "TAPCHECK frames={N} delivered={} refused={refused} rest={} end=\"{end}\" connected={connected} \
             write_iovec_ns={} check_ns={} (per call, test profile)",
            bytes / (4 + 1514),
            bytes % (4 + 1514),
            write.as_nanos() / u128::from(N),
            check.as_nanos() / u128::from(N),
        );
    }

    #[test]
    fn test_switches_that_come_and_go_lose_no_frame() {
        // What upstream's rx tests do (inject_tap_tx_frame): each frame
        // through a switch of its own that sends it and leaves, all before
        // the interface reads. A TAP gives the guest every one.
        let mut tap = Tap::open_named("fcseq%d").unwrap();
        for len in [200, 300, 60] {
            TapTrafficSimulator::new(if_index(&tap)).push_tx_packet(&frame(len));
        }
        let mut rx = vec![0u8; 1000];
        for len in [200, 300, 60] {
            assert_eq!(read_frame(&mut tap, &mut rx).unwrap(), vnet::MIN_HDR_LEN + len);
            assert_eq!(&rx[vnet::MIN_HDR_LEN..vnet::MIN_HDR_LEN + len], &frame(len)[..]);
        }
        let err = read_frame(&mut tap, &mut rx).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EAGAIN));
    }

    #[test]
    fn test_frames_split_across_reads() {
        let mut tap = Tap::open_named("fcsplit%d").unwrap();
        let sim = TapTrafficSimulator::new(if_index(&tap));
        // Many frames at once: every one comes out whole.
        for len in [60, 1514, 61, 9000] {
            sim.push_tx_packet(&frame(len));
        }
        let mut rx = vec![0u8; 10000];
        for len in [60, 1514, 61, 9000] {
            let mut iov = [libc::iovec {
                iov_base: rx.as_mut_ptr().cast(),
                iov_len: rx.len(),
            }];
            let mut n = Err(io::Error::from_raw_os_error(libc::EAGAIN));
            for _ in 0..100 {
                n = tap.read_iovec(&mut iov);
                if n.is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(n.unwrap(), vnet::MIN_HDR_LEN + len);
            assert_eq!(&rx[vnet::MIN_HDR_LEN..vnet::MIN_HDR_LEN + len], &frame(len)[..]);
        }
    }

    #[test]
    fn test_stale_endpoint_replaced() {
        let path = endpoint_dir().unwrap().join("fcstale");
        let _ = std::fs::remove_file(&path);
        // A process that died leaves its socket file behind.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let tap = Tap::open_named("fcstale").unwrap();
        drop(tap);
        assert!(!path.exists());
    }
}
