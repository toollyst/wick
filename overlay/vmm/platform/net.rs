// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The host side of a virtio-net device: a TAP-like interface that carries
//! the guest's Ethernet frames.
//!
//! The interface is that of a Linux TAP opened with `IFF_TAP | IFF_NO_PI |
//! IFF_VNET_HDR`, which is the Linux backend:
//! - [`TapDevice::open_named`] opens the interface `if_name`; a `%d` in the
//!   name is replaced by the first free number, and an empty name means
//!   `tap%d`; names are shorter than 16 bytes; an interface is open at most
//!   once;
//! - every frame read or written starts with a virtio-net header of the size
//!   set by [`TapDevice::set_vnet_hdr_size`] (at least 10, the initial size);
//!   the host acts on the header of written frames (checksum completion,
//!   segmentation) as the Linux TUN driver does;
//! - [`TapDevice::set_offload`] accepts the `TUN_F_*` combinations the TUN
//!   driver accepts;
//! - reads and writes never block: a read with no frame waiting fails with
//!   `EAGAIN`, and the descriptor ([`AsRawFd`]) polls readable when a frame
//!   may be waiting.
//!
//! Backends:
//! - Linux: TUN/TAP ([`crate::devices::virtio::net::tap`]).
//! - macOS: an interface name is either a vmnet.framework interface
//!   (`vmnet-shared`: NAT to the host's networks; `vmnet-host`: the host and
//!   other VMs; `vmnet-br-<if>`: bridged to host interface `<if>`), or a Unix
//!   datagram endpoint that a host-side switch exchanges plain Ethernet
//!   frames with (a name without `/` lives in the per-user directory
//!   `$(getconf DARWIN_USER_TEMP_DIR)/firecracker-net/`, a name with `/` is
//!   the path itself). The host side attaches by sending a datagram to the
//!   endpoint (an empty one only attaches) and receives every frame the guest
//!   sends. The virtio-net header is handled by [`super::vnet`].
//! - Windows: a Unix stream endpoint that a host-side switch connects to,
//!   carrying plain Ethernet frames each preceded by its 32-bit big-endian
//!   length (QEMU's `-netdev stream` framing, which gvisor-tap-vsock and
//!   passt speak); one switch at a time. A name without `/` or `\` lives in
//!   `%TEMP%\firecracker-net\`, a name with one is the path itself. The
//!   virtio-net header is handled by [`super::vnet`].

use std::fmt::Debug;
use std::io;
use std::os::raw::{c_int, c_uint};
use std::os::unix::io::AsRawFd;

use crate::devices::virtio::iovec::IoVecBuffer;
pub use crate::devices::virtio::net::TapError;

/// A host network interface carrying a virtio-net device's frames.
pub trait TapDevice: AsRawFd + Debug + Send + Sized {
    /// Opens the interface `if_name`.
    fn open_named(if_name: &str) -> Result<Self, TapError>;

    /// The interface's name, with any `%d` replaced.
    fn if_name_as_str(&self) -> &str;

    /// Sets the offloads (`TUN_F_*`) the host may use in frames it hands to
    /// the guest.
    fn set_offload(&self, flags: c_uint) -> Result<(), TapError>;

    /// Sets the size of the virtio-net header in front of every frame.
    fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError>;

    /// Writes one frame, header first. Returns the bytes taken from `buffer`.
    fn write_iovec(&mut self, buffer: &IoVecBuffer) -> io::Result<usize>;

    /// Reads one frame, header first, into `buffer`. Returns its length.
    fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize>;
}

/// This host's [`TapDevice`].
pub type Tap = super::backend::net::Tap;

/// The host side of a [`Tap`], for tests: what the Linux tests do with a
/// packet socket bound to the TAP.
#[cfg(not(target_os = "linux"))]
#[doc(hidden)]
pub use super::backend::net::simulator;

#[cfg(test)]
mod tests {
    // Interface tests: they run against the backend of the host they are
    // built for. On Linux they need CAP_NET_ADMIN, like the TAP tests.
    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use crate::devices::virtio::net::test_utils::{TapTrafficSimulator, enable, if_index};

    type IoVecBufferMut = crate::devices::virtio::iovec::IoVecBufferMut<256>;

    /// The size a TAP's virtio-net header starts with.
    const VNET_HDR_SIZE: usize = 10;
    const PAYLOAD_SIZE: usize = 512;
    const TUN_F_CSUM: c_uint = 0x01;
    const TUN_F_TSO4: c_uint = 0x02;
    const TUN_F_TSO6: c_uint = 0x04;
    const TUN_F_UFO: c_uint = 0x10;

    #[test]
    fn test_names() {
        let tap = Tap::open_named("").unwrap();
        let name = tap.if_name_as_str();
        assert!(
            name.starts_with("tap")
                && name.len() > 3
                && name[3..].chars().all(|c| c.is_ascii_digit()),
            "expected a name like 'tapN', got '{name}'"
        );

        let tap = Tap::open_named("fcnet%d").unwrap();
        let name = tap.if_name_as_str();
        assert!(name.starts_with("fcnet") && !name.contains('%'), "{name}");

        assert!(matches!(
            Tap::open_named("a123456789abcdef"),
            Err(TapError::InvalidIfname)
        ));
        let tap = Tap::open_named("a123456789abcde").unwrap();
        assert_eq!(tap.if_name_as_str(), "a123456789abcde");
    }

    #[test]
    fn test_exclusive_open() {
        let _tap = Tap::open_named("fcexclusive").unwrap();
        Tap::open_named("fcexclusive").unwrap_err();
    }

    #[test]
    fn test_set_options() {
        let tap = Tap::open_named("").unwrap();
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        assert!(matches!(
            tap.set_vnet_hdr_size(9),
            Err(TapError::SetSizeOfVnetHdr(_))
        ));
        tap.set_offload(0).unwrap();
        tap.set_offload(TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO)
            .unwrap();
        // Segmentation offloads need checksum offload.
        assert!(matches!(
            tap.set_offload(TUN_F_TSO4),
            Err(TapError::SetOffloadFlags(_))
        ));
    }

    #[test]
    fn test_read_nothing_waiting() {
        let mut tap = Tap::open_named("").unwrap();
        enable(&tap);
        let mut buf = vec![0u8; 2048];
        let mut iov = [libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        }];
        let err = tap.read_iovec(&mut iov).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EAGAIN));
    }

    /// A Linux TAP that is up carries frames of the host's own (IPv6
    /// neighbour discovery, MLD): the tests look past them.
    const TRIES: usize = 32;

    /// Pops frames until one starting with `expected`.
    fn pop_frame(sim: &TapTrafficSimulator, expected: &[u8]) -> bool {
        let mut buf = vec![0u8; 65536];
        for _ in 0..TRIES {
            buf.fill(0);
            if !sim.pop_rx_packet(&mut buf) {
                return false;
            }
            if buf.starts_with(expected) {
                return true;
            }
        }
        false
    }

    /// Reads frames until one of `len` bytes, header included.
    fn read_frame(tap: &mut Tap, iovs: &mut [libc::iovec], len: usize) -> bool {
        for _ in 0..TRIES {
            match tap.read_iovec(iovs) {
                Ok(n) if n == len => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
        false
    }

    #[test]
    fn test_write_iovec() {
        let mut tap = Tap::open_named("").unwrap();
        enable(&tap);
        let sim = TapTrafficSimulator::new(if_index(&tap));

        let mut fragment1 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);
        // An empty virtio-net header: no offloads.
        fragment1[..VNET_HDR_SIZE].fill(0);
        let fragment2 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);
        let fragment3 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);
        let scattered = IoVecBuffer::from(vec![
            fragment1.as_slice(),
            fragment2.as_slice(),
            fragment3.as_slice(),
        ]);
        assert_eq!(tap.write_iovec(&scattered).unwrap(), 3 * PAYLOAD_SIZE);

        let mut sent = fragment1[VNET_HDR_SIZE..].to_vec();
        sent.extend_from_slice(&fragment2);
        sent.extend_from_slice(&fragment3);
        assert!(pop_frame(&sim, &sent));
    }

    #[test]
    fn test_read_iovec() {
        let mut tap = Tap::open_named("").unwrap();
        enable(&tap);
        let sim = TapTrafficSimulator::new(if_index(&tap));

        let mut buff1 = vec![0xaa; PAYLOAD_SIZE + VNET_HDR_SIZE];
        let mut buff2 = vec![0; 2 * PAYLOAD_SIZE];
        let mut rx = IoVecBufferMut::from(vec![buff1.as_mut_slice(), buff2.as_mut_slice()]);

        let packet = vmm_sys_util::rand::rand_alphanumerics(2 * PAYLOAD_SIZE);
        sim.push_tx_packet(packet.as_bytes());
        assert!(read_frame(
            &mut tap,
            rx.as_iovec_mut_slice(),
            2 * PAYLOAD_SIZE + VNET_HDR_SIZE
        ));
        assert_eq!(&buff1[..VNET_HDR_SIZE], &[0; VNET_HDR_SIZE]);
        assert_eq!(&buff1[VNET_HDR_SIZE..], &packet.as_bytes()[..PAYLOAD_SIZE]);
        assert_eq!(&buff2[..PAYLOAD_SIZE], &packet.as_bytes()[PAYLOAD_SIZE..]);
        assert_eq!(&buff2[PAYLOAD_SIZE..], &vec![0; PAYLOAD_SIZE]);
    }

    #[test]
    fn test_header_size_applies() {
        // A 12-byte header (what the virtio-net device uses) on both paths.
        let mut tap = Tap::open_named("").unwrap();
        tap.set_vnet_hdr_size(12).unwrap();
        enable(&tap);
        let sim = TapTrafficSimulator::new(if_index(&tap));

        let mut out = vec![0u8; 12 + PAYLOAD_SIZE];
        out[12..].copy_from_slice(&vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE));
        tap.write_iovec(&IoVecBuffer::from(out.as_slice())).unwrap();
        assert!(pop_frame(&sim, &out[12..]));

        let packet = vmm_sys_util::rand::rand_alphanumerics(PAYLOAD_SIZE);
        sim.push_tx_packet(packet.as_bytes());
        let mut buf = vec![0xffu8; 12 + PAYLOAD_SIZE];
        let mut rx = IoVecBufferMut::from(buf.as_mut_slice());
        assert!(read_frame(
            &mut tap,
            rx.as_iovec_mut_slice(),
            12 + PAYLOAD_SIZE
        ));
        // The header fields; what the TUN driver puts in the bytes past them
        // depends on the kernel version (skipped before 6.x, zeroed after).
        assert_eq!(&buf[..10], &[0; 10]);
        assert_eq!(&buf[12..], packet.as_bytes());
    }
}
