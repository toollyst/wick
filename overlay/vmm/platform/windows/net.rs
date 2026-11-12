// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`TapDevice`] on Windows: a Unix stream endpoint (see
//! [`crate::platform::net`] for the names) that a host-side switch connects
//! to. Frames go both ways as plain Ethernet frames, each preceded by its
//! length as a 32-bit big-endian number: the framing of QEMU's
//! `-netdev stream`, which gvisor-tap-vsock and passt also speak. The
//! virtio-net header is handled by [`vnet`].
//!
//! - One switch is connected at a time. One that connects while another is
//!   there waits in the listener's queue, and takes its place when it
//!   leaves; what it sent meanwhile reaches the guest then. So no frame a
//!   switch sent is lost to the order in which switches came and went, as
//!   on a TAP, where every host-side writer's frames reach the guest.
//! - Frames the guest sends while no switch is connected are dropped, as on
//!   a link without a peer.
//! - The guest's frames are never sent in part: a frame the connection
//!   cannot take at all is dropped, as when a TAP queue is full, and a frame
//!   it took part of is completed, waiting up to [`SEND_STALL`] for the
//!   switch, after which the switch is disconnected (a byte stream cannot
//!   skip the rest of a frame).
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
/// header (gvisor-tap-vsock and passt send at most the MTU).
const MAX_FRAME: usize = 65536 + 14 + 4 + 4;
/// How long the rest of a frame the connection took part of may wait.
pub const SEND_STALL: Duration = Duration::from_secs(1);
/// How much is read from the connection at a time.
const READ_CHUNK: usize = 64 << 10;

/// The directory of endpoints named without a path separator: the jail's
/// network, if the jailer gave one (`--netns`, `ext::jail::netns`), else
/// `%TEMP%\firecracker-net`.
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
    /// No switch waiting is no error. A listener that fails otherwise (its
    /// descriptor closed, the tap's own descriptor as Firecracker sees it)
    /// fails the I/O that asked, as I/O on a closed tap descriptor fails on
    /// Linux (EBADF): upstream's test_tx_tap_failure and
    /// test_read_tap_fail_event_handler close it to count tap_write_fails
    /// and tap_read_fails, which a dropped frame left at 0.
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

    /// Sends one frame to the switch, or drops it (see the module docs).
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
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
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
        let total = buffer.len() as usize;
        let hdr_len = self.hdr_len.load(Ordering::Relaxed);
        self.tx.clear();
        buffer
            .read_volatile_at(&mut self.tx, 0, total)
            .map_err(io::Error::other)?;
        // As the TUN driver: a header and at least an Ethernet header.
        if self.tx.len() < hdr_len + 14 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let (hdr, frame) = self.tx.split_at_mut(hdr_len);
        let hdr = VnetHdr::parse(hdr).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let endpoint = &mut self.endpoint;
        vnet::segment(&hdr, frame, &mut self.scratch, &mut |seg| endpoint.send(seg))?;
        Ok(total)
    }

    /// See [`TapDevice::read_iovec`]. The header is zeroed: a complete
    /// frame, no offloads.
    pub fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
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
