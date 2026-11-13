// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`TapDevice`] on macOS: a vmnet.framework interface or a Unix datagram
//! endpoint (see [`crate::platform::net`] for the names), carrying plain
//! Ethernet frames; the virtio-net header is handled by [`vnet`]. A vmnet
//! interface in virtio-header mode (macOS 15.4 and later,
//! [`vmnet::Interface::vnet`]) carries a header too: the guest's TCP
//! superframes are handed over with theirs ([`vnet::tx_offload`]), and what
//! vmnet delivers is given to the guest as a TAP gives it
//! ([`vnet::rx_offload`], [`vnet::rx_segment`]).
//!
//! In a jail given a network (`--netns`, [`crate::ext::jail::netns`]),
//! endpoints named without `/` are made in the network's directory, which
//! the chroot hides: the jail reaches it through the descriptor it opened
//! before the chroot ([`crate::ext::jail::netns_dir`]), by making it the
//! working directory of the calling thread alone for each call that names
//! a path ([`in_dir`]). vmnet, the host's own network, is not the jail's.
//!
//! A jail's directory is its own, inside the network directory the operator
//! named (`<network>/<id>`, made by the jailer), and the operator's switch
//! binds its sockets directly in the network directory, where no jail can
//! make one. So a jailed endpoint sends the guest's frames only to senders
//! whose address is such a socket, owned by the network directory's owner
//! or root ([`Switch`]), and drops what any other sender sends it. That is
//! not an identity check: a datagram's sender address is the path its
//! sender bound, as it wrote it (measured), and Unix datagram sockets have
//! no peer credentials (xnu bsd/kern/uipc_usrreq.c, `LOCAL_PEERCRED`: a
//! stream's only). What keeps another jail from sending here at all is the
//! kernel's file check on this directory (another uid) and the sender's
//! own sandbox profile (the same uid).

use std::collections::VecDeque;
use std::ffi::{CStr, OsStr};
use std::fmt;
use std::io;
use std::mem;
use std::os::raw::{c_int, c_uint};
use std::os::unix::ffi::OsStrExt;
use std::os::fd::BorrowedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};

use super::vmnet::{self, Mode};
use crate::devices::virtio::iovec::IoVecBuffer;
use crate::platform::net::{TapDevice, TapError};
use crate::platform::vnet::{self, VnetHdr};

/// `IFNAMSIZ`: interface names are shorter.
const IFACE_NAME_MAX_LEN: usize = 16;
/// `_CS_DARWIN_USER_TEMP_DIR`.
const CS_DARWIN_USER_TEMP_DIR: c_int = 65537;
/// Buffer sizes of endpoints; the send buffer bounds the datagram size.
const SNDBUF: c_int = 1 << 20;
const RCVBUF: c_int = 4 << 20;
/// Most interfaces a `%d` name is tried with.
const MAX_UNITS: u32 = 1 << 15;
/// The largest frame read from vmnet in virtio-header mode: the most the
/// net device takes (upstream's `MAX_BUFFER_SIZE`, 65562 bytes); vmnet's
/// coalesced frames were at most 65238 bytes (macOS 27.2).
const RX_ROOM: usize = 65562;

unsafe extern "C" {
    /// Sets the calling thread's working directory to `fd`, or back to the
    /// process's with -1 (libsystem_pthread; fts uses it).
    fn pthread_fchdir_np(fd: c_int) -> c_int;
}

/// Runs `f`, which names paths, with relative paths resolved in `dir` (the
/// jail's network) on this thread only; without `dir`, as the process
/// resolves them.
fn in_dir<T>(dir: Option<BorrowedFd<'_>>, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let Some(dir) = dir else {
        return f();
    };
    // SAFETY: a directory descriptor; changes this thread's working directory.
    if unsafe { pthread_fchdir_np(dir.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = f();
    // SAFETY: -1 returns this thread to the process's working directory.
    let back = unsafe { pthread_fchdir_np(-1) };
    // Failing to would leave every relative path of this thread resolved in
    // the network: not survivable.
    assert_eq!(back, 0, "cannot leave the network directory: {}", io::Error::last_os_error());
    result
}

/// Where endpoints named without `/` are made: the jail's network, as its
/// path outside the jail and the descriptor that reaches it.
fn network() -> Option<(&'static Path, BorrowedFd<'static>)> {
    Some((crate::ext::jail::netns()?, crate::ext::jail::netns_dir()?))
}

/// The directory of endpoints named without `/`: the jail's network (by its
/// path outside the jail), or `firecracker-net` in the user's temporary
/// directory.
pub fn endpoint_dir() -> io::Result<PathBuf> {
    if let Some((path, _)) = network() {
        return Ok(path.to_owned());
    }
    let dir = user_endpoint_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// `firecracker-net` in the user's temporary directory (not made here):
/// where endpoints named without `/` are made outside a jail.
pub fn user_endpoint_dir() -> io::Result<PathBuf> {
    let mut buf = vec![0u8; usize::try_from(libc::PATH_MAX).unwrap()];
    // SAFETY: confstr into a buffer of the given size.
    let len = unsafe { libc::confstr(CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), buf.len()) };
    if len == 0 || len > buf.len() {
        return Err(io::Error::last_os_error());
    }
    let dir =
        CStr::from_bytes_until_nul(&buf).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    Ok(Path::new(OsStr::from_bytes(dir.to_bytes())).join("firecracker-net"))
}

fn sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: sockaddr_un is plain data.
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    addr.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).unwrap();
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = src.cast_signed();
    }
    let len = mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    // A sockaddr_un is far smaller than 256 bytes.
    addr.sun_len = u8::try_from(len).unwrap();
    Ok((addr, libc::socklen_t::from(addr.sun_len)))
}

fn cvt(ret: isize) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret.cast_unsigned())
    }
}

/// A non-blocking Unix datagram socket with large buffers.
pub(crate) fn dgram_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket call; the result is checked.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just created and is owned here.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    for (opt, size) in [(libc::SO_SNDBUF, SNDBUF), (libc::SO_RCVBUF, RCVBUF)] {
        // SAFETY: setsockopt with an int option.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                std::ptr::from_ref(&size).cast(),
                libc::socklen_t::try_from(mem::size_of::<c_int>()).unwrap(),
            );
        }
    }
    // SAFETY: fcntl on a descriptor owned here.
    unsafe {
        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok(sock)
}

/// Binds `sock` at `path`. A socket file nobody listens on any more is
/// replaced; one in use fails with `EBUSY`, as a TAP opened twice does.
/// Once the sandbox is narrowed (a device hot-plugged into a running
/// microVM), a stale socket file is not replaced: removing it is setup's
/// (`vmm::ext::sandbox`'s unlink rule), so the bind fails with
/// `EADDRINUSE`, which the API reports, and the microVM runs on.
pub(crate) fn bind(sock: &OwnedFd, path: &Path) -> io::Result<()> {
    let (addr, len) = sockaddr(path)?;
    let try_bind = || {
        // SAFETY: bind with a valid address.
        let ret = unsafe { libc::bind(sock.as_raw_fd(), std::ptr::from_ref(&addr).cast(), len) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    match try_bind() {
        Err(err) if err.raw_os_error() == Some(libc::EADDRINUSE) => {
            if crate::ext::sandbox::narrowed() {
                return Err(err);
            }
            let probe = dgram_socket()?;
            // SAFETY: connect with a valid address.
            let ret =
                unsafe { libc::connect(probe.as_raw_fd(), std::ptr::from_ref(&addr).cast(), len) };
            if ret == 0 {
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::ECONNREFUSED) {
                return Err(err);
            }
            std::fs::remove_file(path)?;
            try_bind()
        }
        other => other,
    }
}

/// A socket address, as received.
#[derive(Clone, Copy)]
struct Peer(libc::sockaddr_un, libc::socklen_t);

impl Peer {
    fn path(&self) -> &[u8] {
        let off = mem::offset_of!(libc::sockaddr_un, sun_path);
        let len = usize::try_from(self.1).unwrap_or(0).saturating_sub(off);
        let path = &self.0.sun_path[..len.min(self.0.sun_path.len())];
        // SAFETY: c_char and u8 have the same layout.
        let path: &[u8] = unsafe { &*(std::ptr::from_ref(path) as *const [u8]) };
        path.split(|b| *b == 0).next().unwrap_or(&[])
    }
}

/// Who a jailed endpoint's peers may be: the sockets directly in the
/// network directory, the parent of the jail's own, that its owner or root
/// owns.
#[derive(Debug)]
struct Switch {
    /// The network directory's path outside the jail.
    network: PathBuf,
    /// Its owner.
    owner: libc::uid_t,
}

impl Switch {
    /// For an endpoint in the jail's directory `dir`, at `path` outside
    /// the jail.
    fn of(path: &Path, dir: BorrowedFd<'_>) -> io::Result<Self> {
        let network = path
            .parent()
            .ok_or_else(|| io::Error::other("the jail's network directory has no parent"))?;
        Ok(Switch { network: network.to_owned(), owner: Self::stat(dir, c"..")?.st_uid })
    }

    fn stat(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<libc::stat> {
        // SAFETY: plain data, filled by fstatat.
        let mut st: libc::stat = unsafe { mem::zeroed() };
        // SAFETY: a directory descriptor and a NUL-terminated name; no link
        // followed at its last name.
        if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }

    /// The address a sender named `sender` is sent to from the jail's
    /// directory (`../<name>`), if it names one name directly in the
    /// network directory, by its path outside the jail.
    fn address(&self, sender: &Peer) -> Option<Peer> {
        let name = Path::new(OsStr::from_bytes(sender.path())).strip_prefix(&self.network).ok()?;
        let mut names = name.components();
        let (Some(std::path::Component::Normal(name)), None) = (names.next(), names.next()) else {
            return None;
        };
        let (addr, len) = sockaddr(&Path::new("..").join(name)).ok()?;
        Some(Peer(addr, len))
    }

    /// Whether `address` (of [`Switch::address`]) is a socket of the
    /// network directory's owner or root.
    fn owns(&self, dir: BorrowedFd<'_>, address: &Peer) -> bool {
        let Ok(name) = std::ffi::CString::new(address.path()) else {
            return false;
        };
        Self::stat(dir, &name).is_ok_and(|st| {
            st.st_mode & libc::S_IFMT == libc::S_IFSOCK && (st.st_uid == 0 || st.st_uid == self.owner)
        })
    }
}

/// A Unix datagram endpoint.
struct Endpoint {
    sock: OwnedFd,
    /// Its path: relative to `dir` when it is in the jail's network.
    path: PathBuf,
    /// The jail's network, where relative paths resolve ([`in_dir`]).
    dir: Option<BorrowedFd<'static>>,
    /// The network's path outside the jail: a peer that names itself by it
    /// is reached relative to `dir`.
    dir_path: Option<PathBuf>,
    /// In a jail: who may be a peer. Elsewhere any sender is one.
    switch: Option<Switch>,
    /// Where frames from the guest go: every host-side socket that sent a
    /// datagram here (in a jail: of the switch's).
    peers: Vec<Peer>,
    /// Datagrams dropped because their sender may not be a peer.
    refused: u64,
    /// The senders whose refusal was logged (each once), by the address
    /// they gave; at most [`REFUSED_LOGGED`], so that a sender that keeps
    /// changing its name fills neither the log nor memory.
    refused_senders: Vec<Vec<u8>>,
}

/// How many refused senders are logged by name; one more line says that
/// further ones are not.
const REFUSED_LOGGED: usize = 8;

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("path", &self.path)
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Binds an endpoint at `path`, relative to the network `dir` (with its
    /// path outside the jail) if given. `jail`: `dir` is a jail's own
    /// directory in its network, whose peers are the switch's ([`Switch`]).
    fn open(path: &Path, dir: Option<(&Path, BorrowedFd<'static>)>, jail: bool) -> io::Result<Self> {
        let sock = dgram_socket()?;
        let fd = dir.map(|(_, fd)| fd);
        let switch = match dir {
            Some((dir_path, fd)) if jail => Some(Switch::of(dir_path, fd)?),
            _ => None,
        };
        in_dir(fd, || bind(&sock, path))?;
        Ok(Endpoint {
            sock,
            path: path.to_owned(),
            dir: fd,
            dir_path: dir.map(|(p, _)| p.to_owned()),
            switch,
            peers: Vec::new(),
            refused: 0,
            refused_senders: Vec::new(),
        })
    }

    /// Notes the sender of a datagram as a peer. `false`: it may not be
    /// one (in a jail, anything but a socket of the switch's), and its
    /// datagram is not a frame.
    fn note_peer(&mut self, addr: libc::sockaddr_un, len: libc::socklen_t) -> bool {
        let mut peer = Peer(addr, len);
        if let (Some(switch), Some(dir)) = (&self.switch, self.dir) {
            let admitted = switch.address(&peer).filter(|address| {
                // A peer already taken is not looked at again: a name in
                // the network directory is replaced only by who may write
                // there, its owner.
                self.peers.iter().any(|p| p.path() == address.path()) || switch.owns(dir, address)
            });
            let Some(address) = admitted else {
                // Said once for each sender, so that an operator whose
                // switch is bound by another name than its real path in
                // the network directory sees why nothing flows.
                self.refused += 1;
                let sender = peer.path();
                if self.refused_senders.len() <= REFUSED_LOGGED
                    && !self.refused_senders.iter().any(|s| s == sender)
                {
                    if self.refused_senders.len() < REFUSED_LOGGED {
                        crate::logger::warn!(
                            "net: {:?} dropped a datagram from {:?}: its peers are the sockets directly in {:?}, \
                             bound by that path, that the directory's owner or root owns ({} dropped so far; \
                             said once for this sender)",
                            self.path,
                            OsStr::from_bytes(sender),
                            switch.network,
                            self.refused
                        );
                    } else {
                        crate::logger::warn!(
                            "net: {:?} dropped a datagram from one more sender that is no peer; further senders \
                             are not logged ({} dropped so far)",
                            self.path,
                            self.refused
                        );
                    }
                    self.refused_senders.push(sender.to_vec());
                }
                return false;
            };
            if !self.peers.iter().any(|p| p.path() == address.path()) {
                self.peers.push(address);
            }
            return true;
        }
        // A peer in the network naming itself by its path outside the jail
        // is reached by its name in the network's directory.
        if let Some(dir) = &self.dir_path
            && let Ok(rel) = Path::new(OsStr::from_bytes(peer.path())).strip_prefix(dir)
            && let Ok((addr, len)) = sockaddr(rel)
        {
            peer = Peer(addr, len);
        }
        if !peer.path().is_empty() && !self.peers.iter().any(|p| p.path() == peer.path()) {
            self.peers.push(peer);
        }
        true
    }

    /// `recvmsg` into `iovs`, noting the sender: the datagram's length, and
    /// whether its sender may be a peer ([`Endpoint::note_peer`]).
    fn recvmsg(&mut self, iovs: &mut [libc::iovec], flags: c_int) -> io::Result<(usize, bool)> {
        // SAFETY: plain data.
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        // SAFETY: plain data.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = std::ptr::from_mut(&mut addr).cast();
        msg.msg_namelen = libc::socklen_t::try_from(mem::size_of::<libc::sockaddr_un>()).unwrap();
        msg.msg_iov = iovs.as_mut_ptr();
        msg.msg_iovlen =
            c_int::try_from(iovs.len()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        loop {
            // SAFETY: the message names buffers the caller owns.
            match cvt(unsafe { libc::recvmsg(self.sock.as_raw_fd(), &mut msg, flags) }) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
                Ok(n) => return Ok((n, self.note_peer(addr, msg.msg_namelen))),
            }
        }
    }

    /// Reads one frame; `None` if none is waiting. Empty datagrams only
    /// attach their sender; a datagram whose sender may not be a peer is
    /// dropped.
    fn recv(&mut self, iovs: &mut [libc::iovec]) -> io::Result<Option<usize>> {
        loop {
            match self.recvmsg(iovs, 0) {
                Ok((0, _) | (_, false)) => continue,
                Ok((n, true)) => return Ok(Some(n)),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }
        }
    }

    /// Learns the senders of the datagrams waiting, without taking frames
    /// meant for the guest: attach datagrams in front are consumed, and so
    /// are datagrams whose sender may not be a peer.
    fn learn_peers(&mut self) -> io::Result<()> {
        // macOS refuses a receive without buffers (EMSGSIZE): peek one byte.
        let mut byte = 0u8;
        let mut iov = [libc::iovec {
            iov_base: std::ptr::from_mut(&mut byte).cast(),
            iov_len: 1,
        }];
        loop {
            match self.recvmsg(&mut iov, libc::MSG_PEEK) {
                // An empty datagram attaches; one that is no peer's goes.
                Ok((0, _) | (_, false)) => {
                    self.recvmsg(&mut iov, 0)?;
                }
                // A frame, left for the guest.
                Ok((_, true)) => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    }

    /// Sends a frame to every peer. Peers that went away are forgotten.
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if self.peers.is_empty() {
            self.learn_peers()?;
        }
        let fd = self.sock.as_raw_fd();
        let mut result = Ok(());
        let peers = &mut self.peers;
        in_dir(self.dir, || {
            Self::send_to_peers(fd, peers, frame, &mut result);
            Ok(())
        })?;
        result
    }

    fn send_to_peers(fd: RawFd, peers: &mut Vec<Peer>, frame: &[u8], result: &mut io::Result<()>) {
        peers.retain(|peer| {
            // SAFETY: sendto with a valid buffer and address.
            let ret = unsafe {
                libc::sendto(
                    fd,
                    frame.as_ptr().cast(),
                    frame.len(),
                    0,
                    std::ptr::from_ref(&peer.0).cast(),
                    peer.1,
                )
            };
            if ret >= 0 {
                return true;
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ECONNREFUSED | libc::ENOENT) => false,
                _ => {
                    if result.is_ok() {
                        *result = Err(err);
                    }
                    true
                }
            }
        });
    }
}

// No `Drop`: the socket file stays when the device goes, as the API socket
// does, and the next bind at the path replaces it while the microVM is
// built (`bind`, `test_stale_endpoint_replaced`). A running microVM may not
// remove a socket: upstream's filters have no `unlink`, and the host sandbox
// lets the run phase remove only this process's eventfd and timer FIFOs
// (`vmm::ext::sandbox`); a device hot-plugged at a stale path is refused.

#[derive(Debug)]
enum Backend {
    Endpoint(Endpoint),
    Vmnet(vmnet::Interface),
}

impl Backend {
    fn recv(&mut self, iovs: &mut [libc::iovec]) -> io::Result<Option<usize>> {
        match self {
            Backend::Endpoint(ep) => ep.recv(iovs),
            Backend::Vmnet(iface) => {
                if let Some(n) = iface.read(iovs)? {
                    return Ok(Some(n));
                }
                // Consume the notifications, then look once more: a packet
                // that arrives later notifies again.
                iface.drain_notifications();
                iface.read(iovs)
            }
        }
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        match self {
            Backend::Endpoint(ep) => ep.send(frame),
            Backend::Vmnet(iface) => iface.write(None, frame),
        }
    }
}

/// Open interfaces by index, for the host side used in tests.
static INDEXES: Mutex<Vec<(i32, PathBuf)>> = Mutex::new(Vec::new());
static NEXT_INDEX: AtomicI32 = AtomicI32::new(1);

/// A network interface for a virtio-net device.
#[derive(Debug)]
pub struct Tap {
    name: String,
    backend: Backend,
    index: i32,
    hdr_len: AtomicUsize,
    offload: AtomicU32,
    /// The frame being written, and the segments made of it.
    tx: Vec<u8>,
    scratch: Vec<u8>,
    /// vmnet in virtio-header mode: the packet being read, the frames made
    /// of a superframe the guest's offloads do not take, waiting to be
    /// read, and the frames dropped as a TAP is never given them.
    rx: Vec<u8>,
    pending: VecDeque<(VnetHdr, Vec<u8>)>,
    dropped: u64,
}

/// What an interface name refers to.
enum Target {
    Vmnet(Mode),
    /// An endpoint path; `%d` in its last component is a unit number.
    Endpoint {
        dir: Option<PathBuf>,
        /// The jail's network, which `dir` is (reached by this descriptor).
        network: Option<BorrowedFd<'static>>,
        name: String,
    },
}

fn parse_name(if_name: &str) -> Result<Target, TapError> {
    let invalid = || TapError::InvalidIfname;
    if if_name.starts_with("vmnet-") && network().is_some() {
        // vmnet is the host's network, as a host interface is outside a
        // network namespace on Linux.
        return Err(TapError::IfreqExecuteError(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "vmnet is the host's network, not the jail's (--netns)",
            ),
            if_name.to_owned(),
        ));
    }
    match if_name {
        "vmnet-shared" => return Ok(Target::Vmnet(Mode::Shared)),
        "vmnet-host" => return Ok(Target::Vmnet(Mode::Host)),
        _ => {}
    }
    if let Some(dev) = if_name.strip_prefix("vmnet-br-") {
        if dev.is_empty() || if_name.len() >= IFACE_NAME_MAX_LEN {
            return Err(invalid());
        }
        return Ok(Target::Vmnet(Mode::Bridged(dev.to_owned())));
    }
    let percent = if_name.matches('%').count();
    if percent > 1 || (percent == 1 && !if_name.contains("%d")) {
        return Err(invalid());
    }
    if if_name.contains('/') {
        return Ok(Target::Endpoint {
            dir: None,
            network: None,
            name: if_name.to_owned(),
        });
    }
    // The rules of `dev_valid_name`.
    let name = if if_name.is_empty() { "tap%d" } else { if_name };
    if name.len() >= IFACE_NAME_MAX_LEN
        || name == "."
        || name == ".."
        || name.contains(|c: char| c == ':' || c.is_whitespace())
    {
        return Err(invalid());
    }
    let dir = endpoint_dir().map_err(TapError::OpenTun)?;
    Ok(Target::Endpoint {
        dir: Some(dir),
        network: network().map(|(_, fd)| fd),
        name: name.to_owned(),
    })
}

/// Opens the endpoint `name` in `dir` (`None`: `name` is the path), which
/// is the network reached by `network` if given.
fn open_endpoint(
    dir: Option<&Path>,
    network: Option<BorrowedFd<'static>>,
    name: &str,
) -> Result<(String, Endpoint), TapError> {
    // In a jail the network is the jail's own directory in it.
    let jail = crate::ext::jail::root().is_some();
    let open = |name: &str| match (dir, network) {
        (Some(dir), Some(fd)) => Endpoint::open(Path::new(name), Some((dir, fd)), jail),
        (Some(dir), None) => Endpoint::open(&dir.join(name), None, false),
        (None, _) => Endpoint::open(Path::new(name), None, false),
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
        let (name, backend) = match parse_name(if_name)? {
            Target::Vmnet(_) if crate::ext::sandbox::narrowed() => {
                // A vmnet start makes setup's calls (a pipe, the lookup of
                // NetworkSharing, the root daemon behind vmnet, over XPC),
                // which the narrowed sandbox raises SIGSYS for: refused before
                // any of them, so the API reports it and the microVM runs on
                // (sandbox::tests::test_vmnet_hotplug_after_narrow_is_refused).
                return Err(TapError::Backend(
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "a vmnet interface is started while the microVM is built; the sandbox \
                         refuses one hot-plugged into a running microVM (a Unix endpoint can be \
                         hot-plugged)",
                    ),
                    if_name.to_owned(),
                ));
            }
            Target::Vmnet(mode) => {
                let iface = vmnet::Interface::start(&mode)
                    .map_err(|err| TapError::Backend(err, if_name.to_owned()))?;
                (if_name.to_owned(), Backend::Vmnet(iface))
            }
            Target::Endpoint { dir, network, name } => {
                let (name, ep) = open_endpoint(dir.as_deref(), network, &name)?;
                (name, Backend::Endpoint(ep))
            }
        };
        let index = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
        if let Backend::Endpoint(ep) = &backend {
            let path = match &ep.dir_path {
                Some(dir) => dir.join(&ep.path),
                None => ep.path.clone(),
            };
            INDEXES.lock().unwrap().push((index, path));
        }
        Ok(Tap {
            name,
            backend,
            index,
            hdr_len: AtomicUsize::new(vnet::MIN_HDR_LEN),
            offload: AtomicU32::new(0),
            tx: Vec::new(),
            scratch: Vec::new(),
            rx: Vec::new(),
            pending: VecDeque::new(),
            dropped: 0,
        })
    }

    /// See [`TapDevice::if_name_as_str`].
    pub fn if_name_as_str(&self) -> &str {
        &self.name
    }

    /// See [`TapDevice::set_offload`]. The host hands the guest offloaded
    /// frames only from vmnet in virtio-header mode, and then only those the
    /// flags allow ([`vnet::rx_offload`]); otherwise complete frames, which
    /// every setting allows.
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
        if let Backend::Vmnet(iface) = &self.backend
            && iface.vnet
            && vnet::tx_offload(&hdr, frame)? == vnet::Tx::Offload
        {
            let mut out = [0u8; vmnet::VNET_HDR_LEN];
            hdr.write(&mut out);
            iface.write(Some(&out), frame)?;
            return Ok(total);
        }
        let backend = &mut self.backend;
        vnet::segment(&hdr, frame, &mut self.scratch, &mut |seg| backend.send(seg))?;
        Ok(total)
    }

    /// See [`TapDevice::read_iovec`]. The header is zeroed (a complete
    /// frame, no offloads), but from vmnet in virtio-header mode
    /// ([`Tap::read_vnet`]).
    pub fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        if matches!(&self.backend, Backend::Vmnet(iface) if iface.vnet) {
            return self.read_vnet(buffer);
        }
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
        let result = self.backend.recv(&mut buffer[first..]);
        if let Some(saved) = saved {
            buffer[first] = saved;
        }
        match result? {
            Some(n) => Ok(hdr_len + n),
            None => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
        }
    }

    /// A frame from vmnet in virtio-header mode, given as a TAP gives it
    /// ([`vnet::rx_offload`]): one frame with its header, or the next of the
    /// frames a superframe was split into ([`vnet::rx_segment`]); a frame a
    /// TAP is never given is dropped, counted and logged, and the next one
    /// read.
    fn read_vnet(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        let hdr_len = self.hdr_len.load(Ordering::Relaxed);
        let offloads = self.offload.load(Ordering::Relaxed);
        loop {
            if let Some((hdr, frame)) = self.pending.pop_front() {
                return copy_out(buffer, hdr_len, &hdr, &frame);
            }
            let size = vmnet::VNET_HDR_LEN + RX_ROOM;
            self.rx.resize(size, 0);
            let mut iov = [libc::iovec {
                iov_base: self.rx.as_mut_ptr().cast(),
                iov_len: size,
            }];
            let Some(n) = self.backend.recv(&mut iov)? else {
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            };
            let Backend::Vmnet(iface) = &mut self.backend else {
                unreachable!("read_vnet of an endpoint");
            };
            let mtu = usize::try_from(iface.mtu).unwrap_or(usize::MAX);
            let host = iface.host_addresses();
            let (theirs, frame) = self.rx[..n].split_at_mut(vmnet::VNET_HDR_LEN.min(n));
            let data_valid = theirs.first().is_some_and(|flags| flags & vnet::F_DATA_VALID != 0);
            match vnet::rx_offload(frame, data_valid, mtu, offloads, &|a| host.contains(&a)) {
                vnet::Rx::Frame(hdr) => return copy_out(buffer, hdr_len, &hdr, frame),
                vnet::Rx::Segment => {
                    let pending = &mut self.pending;
                    vnet::rx_segment(frame, mtu, offloads, &mut self.scratch, &mut |hdr, seg| {
                        pending.push_back((*hdr, seg.to_vec()));
                        Ok(())
                    })?;
                }
                vnet::Rx::Drop => {
                    self.dropped += 1;
                    let count = self.dropped.to_string();
                    if count.starts_with('1') && count[1..].chars().all(|c| c == '0') {
                        crate::logger::warn!(
                            "{}: dropped a {}-byte frame vmnet delivered that a TAP is never given (over \
                             the MTU {mtu}, not a TCP superframe with a checksum vmnet or this side \
                             checked); {} so far",
                            self.name,
                            frame.len(),
                            self.dropped
                        );
                    }
                }
            }
        }
    }
}

/// Writes a header of `hdr_len` bytes (`hdr`, then zeros) and `frame` into
/// `buffer`, as the TUN driver's read does (`tun_put_user`, drivers/net/
/// tun.c, v6.1): EINVAL if the header does not fit (:2108); a frame longer
/// than the rest is cut, and the length is still the whole one (:2152,
/// :2160).
fn copy_out(
    buffer: &mut [libc::iovec],
    hdr_len: usize,
    hdr: &VnetHdr,
    frame: &[u8],
) -> io::Result<usize> {
    if buffer.iter().map(|iov| iov.iov_len).sum::<usize>() < hdr_len {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let total = hdr_len + frame.len();
    let mut head = vec![0u8; hdr_len];
    hdr.write(&mut head);
    let mut parts = [head.as_slice(), frame];
    for iov in buffer.iter() {
        let mut at = 0;
        while at < iov.iov_len {
            let Some(part) = parts.iter_mut().find(|p| !p.is_empty()) else {
                return Ok(total);
            };
            let n = part.len().min(iov.iov_len - at);
            // SAFETY: the iovec names memory the caller lets us write; `at + n`
            // is within it.
            unsafe { std::ptr::copy_nonoverlapping(part.as_ptr(), iov.iov_base.cast::<u8>().add(at), n) };
            *part = &part[n..];
            at += n;
        }
    }
    Ok(total)
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
        match &self.backend {
            Backend::Endpoint(ep) => ep.sock.as_raw_fd(),
            Backend::Vmnet(iface) => iface.as_raw_fd(),
        }
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        INDEXES.lock().unwrap().retain(|(i, _)| *i != self.index);
    }
}

#[doc(hidden)]
pub mod simulator {
    //! The host side of an endpoint [`Tap`]: what the Linux tests do with a
    //! packet socket bound to the TAP.

    use super::*;

    /// The index of an open interface.
    pub fn if_index(tap: &Tap) -> i32 {
        tap.index
    }

    /// Brings the interface up. Endpoints are always up.
    pub fn enable(_tap: &Tap) {}

    /// A host-side socket attached to an endpoint.
    #[derive(Debug)]
    pub struct TapTrafficSimulator {
        sock: OwnedFd,
        path: PathBuf,
        tap: (libc::sockaddr_un, libc::socklen_t),
    }

    impl TapTrafficSimulator {
        /// Attaches to the interface with index `tap_index`.
        pub fn new(tap_index: i32) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let tap_path = INDEXES
                .lock()
                .unwrap()
                .iter()
                .find(|(i, _)| *i == tap_index)
                .map(|(_, p)| p.clone())
                .expect("no endpoint interface with this index");
            let path = endpoint_dir().unwrap().join(format!(
                "sim-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let sock = dgram_socket().unwrap();
            bind(&sock, &path).unwrap();
            let sim = TapTrafficSimulator {
                sock,
                path,
                tap: sockaddr(&tap_path).unwrap(),
            };
            sim.push_tx_packet(&[]);
            sim
        }

        /// Sends a frame to the interface.
        pub fn push_tx_packet(&self, buf: &[u8]) {
            // SAFETY: sendto with a valid buffer and address.
            let ret = unsafe {
                libc::sendto(
                    self.sock.as_raw_fd(),
                    buf.as_ptr().cast(),
                    buf.len(),
                    0,
                    std::ptr::from_ref(&self.tap.0).cast(),
                    self.tap.1,
                )
            };
            assert!(
                ret >= 0,
                "Can't inject tx_packet: {}",
                io::Error::last_os_error()
            );
        }

        /// Receives a frame from the interface, if one is waiting.
        pub fn pop_rx_packet(&self, buf: &mut [u8]) -> bool {
            // macOS returns at once from a receive into nothing; take the
            // frame through a byte, as Linux truncates it to nothing.
            let mut byte = [0u8];
            let buf = if buf.is_empty() { &mut byte[..] } else { buf };
            // SAFETY: recv into a buffer owned by the caller.
            let ret =
                unsafe { libc::recv(self.sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            ret != -1
        }
    }

    impl Drop for TapTrafficSimulator {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use super::simulator::*;
    use super::*;

    fn frame(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 253) as u8).collect()
    }

    #[test]
    fn test_names() {
        assert!(matches!(
            parse_name("vmnet-shared"),
            Ok(Target::Vmnet(Mode::Shared))
        ));
        assert!(matches!(
            parse_name("vmnet-host"),
            Ok(Target::Vmnet(Mode::Host))
        ));
        assert!(
            matches!(parse_name("vmnet-br-en0"), Ok(Target::Vmnet(Mode::Bridged(ref d))) if d == "en0")
        );
        for bad in [
            "vmnet-br-",
            "a:b",
            "a b",
            ".",
            "..",
            "x%d%d",
            "x%s",
            "0123456789abcdef",
        ] {
            assert!(
                matches!(parse_name(bad), Err(TapError::InvalidIfname)),
                "{bad}"
            );
        }
        assert!(matches!(
            parse_name("/tmp/x.sock"),
            Ok(Target::Endpoint { dir: None, .. })
        ));
    }

    #[test]
    fn test_path_endpoint() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().join("ep%d");
        let tap = Tap::open_named(path.to_str().unwrap()).unwrap();
        let name = dir.as_path().join("ep0");
        assert_eq!(tap.if_name_as_str(), name.to_str().unwrap());
        assert!(name.exists());
        // The name stays when the endpoint goes (the run phase may not
        // remove a socket); the next bind replaces it.
        drop(tap);
        assert!(name.exists());
        drop(Tap::open_named(path.to_str().unwrap()).unwrap());

        let long = format!("/{}", "x".repeat(200));
        assert!(matches!(
            Tap::open_named(&long),
            Err(TapError::InvalidIfname)
        ));
    }

    #[test]
    fn test_stale_endpoint_replaced() {
        let path = endpoint_dir().unwrap().join("fcstale");
        let _ = std::fs::remove_file(&path);
        // A process that died leaves its socket file behind.
        let sock = dgram_socket().unwrap();
        bind(&sock, &path).unwrap();
        drop(sock);
        assert!(path.exists());
        let tap = Tap::open_named("fcstale").unwrap();
        // A live one is busy, as a TAP opened twice.
        let busy = Tap::open_named("fcstale").unwrap_err();
        assert!(matches!(&busy, TapError::IfreqExecuteError(e, _) if e.raw_os_error() == Some(libc::EBUSY)), "{busy:?}");
        // Left behind by an ended VM, replaced by the next.
        drop(tap);
        assert!(path.exists());
        drop(Tap::open_named("fcstale").unwrap());
        std::fs::remove_file(&path).unwrap();
    }

    // An endpoint in a jail's network: made, reached and removed in the
    // network's directory through its descriptor, whatever the process's
    // working directory (in the jail, the chroot hides the directory).
    #[test]
    fn test_endpoint_in_network_directory() {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixDatagram;

        let net = endpoint_dir().unwrap().join(format!("net-{}", std::process::id()));
        std::fs::create_dir_all(&net).unwrap();
        let dir: &'static OwnedFd = Box::leak(Box::new(OwnedFd::from(std::fs::File::open(&net).unwrap())));
        let mut ep = Endpoint::open(Path::new("tap0"), Some((&net, dir.as_fd())), false).unwrap();
        assert!(net.join("tap0").exists());
        // Relative to the network, not to the process's working directory.
        assert!(!Path::new("tap0").exists());
        // A peer naming itself by its path outside the jail, and one by its
        // name in the network.
        let outer = UnixDatagram::bind(net.join("outer")).unwrap();
        outer.send_to(b"", net.join("tap0")).unwrap();
        let inner_path = net.join("inner");
        let inner = UnixDatagram::bind(&inner_path).unwrap();
        inner.send_to(b"", net.join("tap0")).unwrap();
        ep.learn_peers().unwrap();
        let names: Vec<_> = ep.peers.iter().map(|p| p.path().to_vec()).collect();
        assert_eq!(names, [b"outer".to_vec(), b"inner".to_vec()]);
        ep.send(&frame(60)).unwrap();
        let mut buf = [0u8; 100];
        assert_eq!(outer.recv(&mut buf).unwrap(), 60);
        assert_eq!(inner.recv(&mut buf).unwrap(), 60);
        // This thread resolves relative paths as the process does again.
        std::fs::metadata("tap0").unwrap_err();
        // A second endpoint of the name is busy, as a TAP opened twice.
        let busy = Endpoint::open(Path::new("tap0"), Some((&net, dir.as_fd())), false).unwrap_err();
        assert_eq!(busy.raw_os_error(), Some(libc::EBUSY));
        drop(ep);
        assert!(net.join("tap0").exists());
        std::fs::remove_dir_all(&net).unwrap();
    }

    // A jail's endpoint, in the jail's own directory of a network: its
    // peers are the sockets directly in the network directory that the
    // directory's owner owns (the operator's switch). Any other sender is
    // not sent the guest's frames, and what it sends is not a frame: a
    // socket in the jail's own directory, one in another jail's, one that
    // names itself as the switch does but by a relative name or through
    // `..`, and one with no name. Linux: a second opener of a TAP never
    // becomes a party to it (drivers/net/tun.c tun_attach: EBUSY).
    #[test]
    fn test_a_jails_endpoint_takes_only_the_switch_as_a_peer() {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixDatagram;

        let net = endpoint_dir().unwrap().join(format!("jn{}", std::process::id()));
        let (a, b) = (net.join("a"), net.join("b"));
        for dir in [&a, &b] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let open = |dir: &Path| -> &'static OwnedFd { Box::leak(Box::new(OwnedFd::from(std::fs::File::open(dir).unwrap()))) };
        let (dir, other) = (open(&a), open(&b));
        let mut ep = Endpoint::open(Path::new("tap0"), Some((&a, dir.as_fd())), true).unwrap();
        let tap0 = a.join("tap0");
        let switch = UnixDatagram::bind(net.join("switch")).unwrap();
        let inside = UnixDatagram::bind(a.join("inside")).unwrap();
        let theirs = UnixDatagram::bind(b.join("tap0")).unwrap();
        // Named "switch", as the real one's last name, by a relative name
        // bound in another directory; and one reached through `..`.
        let relative = dgram_socket().unwrap();
        in_dir(Some(other.as_fd()), || bind(&relative, Path::new("switch"))).unwrap();
        let relative = UnixDatagram::from(relative);
        let dotted = UnixDatagram::bind(b.join("../b/switch2")).unwrap();
        let unnamed = UnixDatagram::unbound().unwrap();
        let strangers = [&inside, &theirs, &relative, &dotted, &unnamed];
        for sock in strangers.iter().copied().chain([&switch]) {
            sock.set_nonblocking(true).unwrap();
        }
        // Each stranger attaches and sends a frame; then the switch does.
        for (n, stranger) in strangers.iter().enumerate() {
            stranger.send_to(b"", &tap0).unwrap();
            stranger.send_to(&[u8::try_from(n).unwrap() + 1; 60], &tap0).unwrap();
        }
        switch.send_to(&[0xee; 64], &tap0).unwrap();
        // The guest gets the switch's frame, and that one only.
        let mut buf = [0u8; 100];
        let mut iov = [libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() }];
        assert_eq!(ep.recv(&mut iov).unwrap(), Some(64));
        assert_eq!(buf[..64], [0xee; 64]);
        assert_eq!(ep.recv(&mut iov).unwrap(), None);
        assert_eq!(ep.refused, 10, "two datagrams from each of five strangers");
        // Each stranger is said once, by the address it gave (none, for the
        // socket without a name).
        let said: Vec<_> = ep.refused_senders.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect();
        let want = [a.join("inside"), b.join("tap0"), PathBuf::from("switch"), b.join("../b/switch2"), PathBuf::new()];
        assert_eq!(said, want.map(|p| p.to_str().unwrap().to_owned()));
        // The guest's frames go to the switch, and to it only.
        let names: Vec<_> = ep.peers.iter().map(|p| p.path().to_vec()).collect();
        assert_eq!(names, [b"../switch".to_vec()]);
        ep.send(&frame(60)).unwrap();
        assert_eq!(switch.recv(&mut buf).unwrap(), 60);
        for stranger in strangers {
            assert_eq!(stranger.recv(&mut buf).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        // A stranger's frame in front of the queue is not left there for
        // the guest when peers are learned.
        ep.peers.clear();
        inside.send_to(&[1; 60], &tap0).unwrap();
        switch.send_to(b"", &tap0).unwrap();
        ep.send(&frame(60)).unwrap();
        assert_eq!(switch.recv(&mut buf).unwrap(), 60);
        assert_eq!(ep.recv(&mut iov).unwrap(), None);
        std::fs::remove_dir_all(&net).unwrap();
    }

    #[test]
    fn test_peers() {
        let mut tap = Tap::open_named("fcpeer%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let a = TapTrafficSimulator::new(if_index(&tap));
        let b = TapTrafficSimulator::new(if_index(&tap));

        // Every attached peer gets the guest's frames.
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&frame(100));
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        let mut buf = vec![0u8; 200];
        assert!(a.pop_rx_packet(&mut buf));
        assert_eq!(&buf[..100], &out[12..]);
        assert!(b.pop_rx_packet(&mut buf));
        assert!(!a.pop_rx_packet(&mut buf));

        // A peer that went away is forgotten.
        drop(b);
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        assert!(a.pop_rx_packet(&mut buf));
        assert_eq!(
            match &tap.backend {
                Backend::Endpoint(ep) => ep.peers.len(),
                Backend::Vmnet(_) => unreachable!(),
            },
            1
        );

        // Frames shorter than an Ethernet header are refused.
        let short = vec![0u8; 12 + 13];
        let err = tap
            .write_iovec(&IoVecBuffer::from(short.as_slice()))
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn test_header_split_across_buffers() {
        let mut tap = Tap::open_named("fcsplit%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let sim = TapTrafficSimulator::new(if_index(&tap));
        let sent = frame(300);
        sim.push_tx_packet(&sent);
        let mut a = vec![0xffu8; 4];
        let mut b = vec![0xffu8; 4];
        let mut c = vec![0xffu8; 400];
        let mut iovs = [&mut a, &mut b, &mut c].map(|v| libc::iovec {
            iov_base: v.as_mut_ptr().cast(),
            iov_len: v.len(),
        });
        assert_eq!(tap.read_iovec(&mut iovs).unwrap(), 312);
        assert_eq!(iovs[2].iov_len, 400);
        assert_eq!(a, [0; 4]);
        assert_eq!(b, [0; 4]);
        assert_eq!(&c[..4], &[0; 4]);
        assert_eq!(&c[4..304], sent.as_slice());

        // Buffers smaller than the header.
        sim.push_tx_packet(&sent);
        let mut small = [libc::iovec {
            iov_base: a.as_mut_ptr().cast(),
            iov_len: 4,
        }];
        let err = tap.read_iovec(&mut small).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn test_offloaded_write_is_segmented() {
        // A TSO frame from the guest leaves as MSS-sized segments.
        let mut tap = Tap::open_named("fctso%d").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        let sim = TapTrafficSimulator::new(if_index(&tap));
        let payload = frame(3000);
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00]);
        let total = u16::try_from(20 + 20 + payload.len()).unwrap();
        pkt.extend_from_slice(&[0x45, 0]);
        pkt.extend_from_slice(&total.to_be_bytes());
        pkt.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        pkt.extend_from_slice(&[0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff]);
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(&payload);
        VnetHdr {
            gso_type: vnet::GSO_TCPV4,
            gso_size: 1000,
            ..Default::default()
        }
        .write(&mut pkt);
        tap.write_iovec(&IoVecBuffer::from(pkt.as_slice())).unwrap();
        let mut got = Vec::new();
        let mut buf = vec![0u8; 2000];
        for _ in 0..3 {
            assert!(sim.pop_rx_packet(&mut buf));
            got.extend_from_slice(&buf[54..1054]);
        }
        assert!(!sim.pop_rx_packet(&mut buf));
        assert_eq!(got, payload);
    }

    #[test]
    fn test_copy_out_writes_the_header_and_frame_across_buffers() {
        let hdr = VnetHdr {
            flags: vnet::F_NEEDS_CSUM,
            gso_type: vnet::GSO_TCPV4,
            hdr_len: 66,
            gso_size: 1448,
            csum_start: 34,
            csum_offset: 16,
        };
        let frame: Vec<u8> = (0..100u8).collect();
        let mut want = vec![0u8; 12];
        hdr.write(&mut want);
        want.extend_from_slice(&frame);
        // Buffers that split the header and the frame anywhere.
        for split in [1, 5, 12, 13, 50] {
            let mut a = vec![0xaa; split];
            let mut b = vec![0xaa; 200];
            let mut iovs = [
                libc::iovec {
                    iov_base: a.as_mut_ptr().cast(),
                    iov_len: a.len(),
                },
                libc::iovec {
                    iov_base: b.as_mut_ptr().cast(),
                    iov_len: b.len(),
                },
            ];
            assert_eq!(copy_out(&mut iovs, 12, &hdr, &frame).unwrap(), 112);
            let mut got = a.clone();
            got.extend_from_slice(&b[..112 - split]);
            assert_eq!(got, want, "split {split}");
            assert!(b[112 - split..].iter().all(|&x| x == 0xaa));
        }
        // Cut where the buffers end, the whole length returned, as
        // tun_put_user does; a buffer shorter than the header is refused.
        let mut a = vec![0u8; 40];
        let mut iovs = [libc::iovec {
            iov_base: a.as_mut_ptr().cast(),
            iov_len: a.len(),
        }];
        assert_eq!(copy_out(&mut iovs, 12, &hdr, &frame).unwrap(), 112);
        assert_eq!(a, want[..40]);
        iovs[0].iov_len = 11;
        let err = copy_out(&mut iovs, 12, &hdr, &frame).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }
}
