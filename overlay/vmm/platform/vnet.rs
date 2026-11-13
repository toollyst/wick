// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The virtio-net header handling of the Linux TUN driver, for [`net`]
//! backends whose host has no such driver.
//!
//! A TAP opened with `IFF_VNET_HDR` exchanges every frame with a virtio-net
//! header in front, and the kernel acts on it:
//! - frames written with `VIRTIO_NET_HDR_F_NEEDS_CSUM` get their checksum
//!   completed (`csum_start`/`csum_offset`);
//! - frames written with a GSO type are segmented (TCPv4/TCPv6, as
//!   `tcp_gso_segment`) or IP-fragmented (UDP, as the UFO path), each segment
//!   with complete headers and checksums;
//! - frames read get a header of the configured size; a backend that only
//!   delivers complete frames leaves it zeroed;
//! - `TUNSETVNETHDRSZ` and `TUNSETOFFLOAD` reject the values the kernel
//!   rejects.
//!
//! Backends that carry plain Ethernet frames use this module to give the
//! guest the same behaviour.
//!
//! [`net`]: super::net

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

/// `sizeof(struct virtio_net_hdr)`: the smallest header `TUNSETVNETHDRSZ`
/// accepts, and the size a TAP starts with.
pub const MIN_HDR_LEN: usize = 10;

/// `VIRTIO_NET_HDR_F_NEEDS_CSUM`.
pub const F_NEEDS_CSUM: u8 = 1;
/// `VIRTIO_NET_HDR_GSO_NONE`.
pub const GSO_NONE: u8 = 0;
/// `VIRTIO_NET_HDR_GSO_TCPV4`.
pub const GSO_TCPV4: u8 = 1;
/// `VIRTIO_NET_HDR_GSO_UDP` (UFO).
pub const GSO_UDP: u8 = 3;
/// `VIRTIO_NET_HDR_GSO_TCPV6`.
pub const GSO_TCPV6: u8 = 4;
/// `VIRTIO_NET_HDR_GSO_ECN`.
pub const GSO_ECN: u8 = 0x80;

/// `TUN_F_*` offload flags.
pub const TUN_F_CSUM: u32 = 0x01;
/// `TUN_F_TSO4`.
pub const TUN_F_TSO4: u32 = 0x02;
/// `TUN_F_TSO6`.
pub const TUN_F_TSO6: u32 = 0x04;
/// `TUN_F_TSO_ECN`.
pub const TUN_F_TSO_ECN: u32 = 0x08;
/// `TUN_F_UFO`.
pub const TUN_F_UFO: u32 = 0x10;
/// `TUN_F_USO4`.
pub const TUN_F_USO4: u32 = 0x20;
/// `TUN_F_USO6`.
pub const TUN_F_USO6: u32 = 0x40;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPV6_HOPOPTS: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AH: u8 = 51;
const IPV6_DSTOPTS: u8 = 60;
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_CWR: u8 = 0x80;
const IP_MF: u16 = 0x2000;
/// Stored instead of a computed checksum of zero (`CSUM_MANGLED_0`).
const CSUM_MANGLED_0: u16 = 0xffff;

/// The fields of a virtio-net header (`struct virtio_net_hdr`, little endian).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VnetHdr {
    /// `VIRTIO_NET_HDR_F_*`.
    pub flags: u8,
    /// `VIRTIO_NET_HDR_GSO_*`.
    pub gso_type: u8,
    /// Length of the headers (a hint; recomputed from the frame).
    pub hdr_len: u16,
    /// Payload bytes per segment.
    pub gso_size: u16,
    /// Where checksumming starts.
    pub csum_start: u16,
    /// Where the checksum goes, from `csum_start`.
    pub csum_offset: u16,
}

impl VnetHdr {
    /// Parses the first [`MIN_HDR_LEN`] bytes of `bytes`.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let b = bytes.get(..MIN_HDR_LEN)?;
        let le = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        Some(VnetHdr {
            flags: b[0],
            gso_type: b[1],
            hdr_len: le(2),
            gso_size: le(4),
            csum_start: le(6),
            csum_offset: le(8),
        })
    }

    /// Writes the header into the first [`MIN_HDR_LEN`] bytes of `out`.
    pub fn write(&self, out: &mut [u8]) {
        out[0] = self.flags;
        out[1] = self.gso_type;
        out[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        out[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        out[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
    }
}

/// The check of `TUNSETVNETHDRSZ`.
pub fn check_hdr_len(len: i32) -> io::Result<usize> {
    match usize::try_from(len) {
        Ok(len) if len >= MIN_HDR_LEN => Ok(len),
        _ => Err(einval()),
    }
}

/// The check of `TUNSETOFFLOAD` (`set_offload` in `drivers/net/tun.c`):
/// segmentation offloads need checksum offload, and unknown bits are
/// rejected.
pub fn check_offload(flags: u32) -> io::Result<()> {
    let mut rest = flags;
    if rest & TUN_F_CSUM != 0 {
        rest &= !TUN_F_CSUM;
        if rest & (TUN_F_TSO4 | TUN_F_TSO6) != 0 {
            rest &= !(TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN);
        }
        rest &= !TUN_F_UFO;
        if rest & TUN_F_USO4 != 0 && rest & TUN_F_USO6 != 0 {
            rest &= !(TUN_F_USO4 | TUN_F_USO6);
        }
    }
    if rest == 0 { Ok(()) } else { Err(einval()) }
}

fn einval() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn put16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_be_bytes());
}

fn put32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_be_bytes());
}

/// One's complement sum of `data` as big-endian words, added to `acc`.
fn sum(data: &[u8], mut acc: u64) -> u64 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u64::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        acc += u64::from(*last) << 8;
    }
    acc
}

/// Folds `acc` to 16 bits and complements it (`csum_fold`).
fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    // The loop leaves at most 16 bits.
    #[allow(clippy::cast_possible_truncation)]
    let folded = acc as u16;
    !folded
}

/// Where the network header starts, and its EtherType.
fn l3_start(frame: &[u8]) -> Option<(usize, u16)> {
    let mut off = 12;
    let mut ethertype = be16(frame.get(..14)?, 12);
    while ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD {
        frame.get(off..off + 6)?;
        ethertype = be16(frame, off + 4);
        off += 4;
    }
    Some((off + 2, ethertype))
}

/// The network header of a frame.
#[derive(Debug)]
struct L3 {
    /// Offset of the IP header.
    off: usize,
    v6: bool,
    /// Length of the IP header, extension headers included.
    len: usize,
    /// The transport protocol.
    proto: u8,
    /// IPv6: length of the part that is not fragmented (the base header, the
    /// hop-by-hop and routing headers, and destination options not after a
    /// routing header, as `ip6_find_1stfragopt`), and the offset of the
    /// next-header byte that names the first fragmentable header.
    unfrag: usize,
    nexthdr_at: usize,
}

fn parse_l3(frame: &[u8]) -> Option<L3> {
    let (off, ethertype) = l3_start(frame)?;
    match ethertype {
        ETH_P_IP => {
            let ip = frame.get(off..off + 20)?;
            let len = usize::from(ip[0] & 0xf) * 4;
            if ip[0] >> 4 != 4 || len < 20 || frame.len() < off + len {
                return None;
            }
            Some(L3 {
                off,
                v6: false,
                len,
                proto: ip[9],
                unfrag: len,
                nexthdr_at: off + 9,
            })
        }
        ETH_P_IPV6 => {
            let ip = frame.get(off..off + 40)?;
            if ip[0] >> 4 != 6 {
                return None;
            }
            let mut proto = ip[6];
            let mut len = 40;
            let mut nexthdr_at = off + 6;
            let mut unfrag = None;
            let mut routing = false;
            loop {
                let ext_len = match proto {
                    IPV6_HOPOPTS | IPV6_ROUTING | IPV6_DSTOPTS => {
                        (usize::from(*frame.get(off + len + 1)?) + 1) * 8
                    }
                    IPV6_AH => (usize::from(*frame.get(off + len + 1)?) + 2) * 4,
                    IPV6_FRAGMENT => 8,
                    _ => break,
                };
                if unfrag.is_none() {
                    match proto {
                        IPV6_HOPOPTS => {}
                        IPV6_ROUTING => routing = true,
                        IPV6_DSTOPTS if !routing => {}
                        _ => unfrag = Some((len, nexthdr_at)),
                    }
                }
                let at = off + len;
                frame.get(at..at + ext_len)?;
                proto = frame[at];
                nexthdr_at = at;
                len += ext_len;
            }
            let (unfrag, nexthdr_at) = unfrag.unwrap_or((len, nexthdr_at));
            Some(L3 {
                off,
                v6: true,
                len,
                proto,
                unfrag,
                nexthdr_at,
            })
        }
        _ => None,
    }
}

/// Sum of the transport pseudo header for an L4 segment of `l4_len` bytes.
fn pseudo_sum(frame: &[u8], l3: &L3, l4_len: usize) -> u64 {
    if l3.v6 {
        let acc = sum(&frame[l3.off + 8..l3.off + 40], 0);
        acc + (l4_len as u64 >> 16) + (l4_len as u64 & 0xffff) + u64::from(l3.proto)
    } else {
        let acc = sum(&frame[l3.off + 12..l3.off + 20], 0);
        acc + l4_len as u64 + u64::from(l3.proto)
    }
}

/// Recomputes the IPv4 header checksum.
fn ipv4_checksum(frame: &mut [u8], l3: &L3) {
    put16(frame, l3.off + 10, 0);
    let csum = fold(sum(&frame[l3.off..l3.off + l3.len], 0));
    put16(frame, l3.off + 10, csum);
}

/// Sets the length field of the IP header for a packet of `frame.len()`.
fn set_ip_len(frame: &mut [u8], l3: &L3) -> io::Result<()> {
    let ip_len = frame.len() - l3.off;
    let (at, len) = if l3.v6 {
        (l3.off + 4, ip_len - 40)
    } else {
        (l3.off + 2, ip_len)
    };
    put16(frame, at, u16::try_from(len).map_err(|_| einval())?);
    Ok(())
}

/// Completes a partial checksum: the one's complement sum from `start` to the
/// end of the frame, stored at `start + offset` (`skb_checksum_help`).
pub fn complete_checksum(frame: &mut [u8], start: usize, offset: usize) -> io::Result<()> {
    let at = start.checked_add(offset).ok_or_else(einval)?;
    if at + 2 > frame.len() {
        return Err(einval());
    }
    let csum = fold(sum(&frame[start..], 0));
    put16(frame, at, if csum == 0 { CSUM_MANGLED_0 } else { csum });
    Ok(())
}

/// Turns one frame written with header `hdr` into the frames that leave the
/// host, passing each to `emit`. `frame` excludes the header; `scratch` holds
/// the segments being built.
pub fn segment(
    hdr: &VnetHdr,
    frame: &mut [u8],
    scratch: &mut Vec<u8>,
    emit: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let gso = hdr.gso_type & !GSO_ECN;
    if hdr.flags & F_NEEDS_CSUM != 0 {
        let start = usize::from(hdr.csum_start);
        let offset = usize::from(hdr.csum_offset);
        if start + offset + 2 > frame.len() {
            return Err(einval());
        }
        // Segmentation computes the TCP checksum of every segment itself.
        if !matches!(gso, GSO_TCPV4 | GSO_TCPV6) {
            complete_checksum(frame, start, offset)?;
        }
    }
    match gso {
        GSO_NONE => emit(frame),
        GSO_TCPV4 | GSO_TCPV6 if hdr.gso_size > 0 => tcp_segment(
            frame,
            usize::from(hdr.gso_size),
            gso == GSO_TCPV6,
            false,
            scratch,
            emit,
        ),
        GSO_UDP if hdr.gso_size > 0 => {
            udp_fragment(frame, usize::from(hdr.gso_size), scratch, emit)
        }
        _ => Err(einval()),
    }
}

/// What a backend that takes the virtio-net header itself (vmnet's virtio
/// header mode) is given for one frame the guest wrote ([`tx_offload`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tx {
    /// The frame and the guest's header as they are: a TCP superframe whose
    /// checksum and segmentation the backend completes, as the host stack
    /// does with what a TAP passes it.
    Offload,
    /// [`segment`]'s frames, each complete, with a zeroed header.
    Segment,
}

/// The checks the Linux TUN driver makes of a frame written with header
/// `hdr` (`frame` excludes the header), and whether the frame can go to a
/// backend that takes the header itself as [`Tx::Offload`].
///
/// An error is a frame a TAP refuses with `EINVAL`:
/// - `tun_get_user` (drivers/net/tun.c, v6.1, :1765 to :1785): `hdr_len`,
///   raised to `csum_start + csum_offset + 2` with `NEEDS_CSUM`, beyond the
///   frame, or set and shorter than an Ethernet header; a frame shorter than
///   an Ethernet header;
/// - `virtio_net_hdr_to_skb` (include/linux/virtio_net.h, v6.1, :55 to
///   :139): a GSO type other than TCPv4, TCPv6 and UDP (with or without the
///   ECN bit); a GSO type with `gso_size` 0; with `NEEDS_CSUM`, the
///   checksum field or the transport header (from `csum_start`) beyond the
///   frame (`skb_partial_csum_set`, net/core/skbuff.c :5043); without it, a
///   GSO frame shorter than the transport header's minimum (:135 to :139).
///   A TAP's frame does not reach the protocol checks of :103 to :134: its
///   skb's `network_header` is still 0 there (net/core/skbuff.c :326,
///   `__build_skb_around` :273 sets only the MAC and transport offsets; tun
///   resets it at tun.c :1920, after the call at :1868).
///
/// A superframe is not refused for its size: past what the device takes,
/// Firecracker drops it before the backend (`MAX_BUFFER_SIZE`, upstream's
/// net device), and the kernel segments what is over a device's
/// `gso_max_size` in software rather than refusing it.
///
/// [`Tx::Offload`] is a TCPv4 or TCPv6 superframe with `NEEDS_CSUM`, the
/// checksum field at TCP's offset 16 of the TCP header that `csum_start`
/// names and that follows the frame's IP header, no ECN bit, and more
/// payload than `gso_size` (a frame with less is not GSO for Linux,
/// virtio_net.h :151). Everything else is segmented here, as before.
pub fn tx_offload(hdr: &VnetHdr, frame: &[u8]) -> io::Result<Tx> {
    const ETH_HLEN: usize = 14;
    const TCP_HLEN: usize = 20;
    const UDP_HLEN: usize = 8;
    let needs_csum = hdr.flags & F_NEEDS_CSUM != 0;
    let start = usize::from(hdr.csum_start);
    let offset = usize::from(hdr.csum_offset);
    // tun_get_user.
    let mut hdr_len = usize::from(hdr.hdr_len);
    if needs_csum && start + offset + 2 > hdr_len {
        hdr_len = start + offset + 2;
    }
    if hdr_len > frame.len() || frame.len() < ETH_HLEN || (hdr_len != 0 && hdr_len < ETH_HLEN) {
        return Err(einval());
    }
    // virtio_net_hdr_to_skb.
    let gso = hdr.gso_type & !GSO_ECN;
    let (thlen, proto) = match hdr.gso_type {
        GSO_NONE => (0, None),
        _ => match gso {
            GSO_TCPV4 | GSO_TCPV6 => (TCP_HLEN, Some(IPPROTO_TCP)),
            GSO_UDP => (UDP_HLEN, Some(IPPROTO_UDP)),
            _ => return Err(einval()),
        },
    };
    if proto.is_some() && hdr.gso_size == 0 {
        return Err(einval());
    }
    let l3 = parse_l3(frame);
    let p_off = if needs_csum {
        if start + thlen.max(offset + 2) > frame.len() {
            return Err(einval());
        }
        start + thlen
    } else if proto.is_some() {
        if thlen > frame.len() {
            return Err(einval());
        }
        thlen
    } else {
        0
    };
    // UFO's gso_size may leave out the transport header.
    let nh_off = if gso == GSO_UDP { p_off - thlen } else { p_off };
    let is_gso = proto.is_some() && frame.len() - nh_off > usize::from(hdr.gso_size);
    let offload = is_gso
        && needs_csum
        && hdr.gso_type & GSO_ECN == 0
        && offset == 16
        && match (gso, &l3) {
            (GSO_TCPV4 | GSO_TCPV6, Some(l3)) => {
                l3.v6 == (gso == GSO_TCPV6) && l3.proto == IPPROTO_TCP && start == l3.off + l3.len
            }
            _ => false,
        };
    Ok(if offload { Tx::Offload } else { Tx::Segment })
}

/// What the guest is given for one frame from a backend that hands over its
/// own virtio-net header and coalesces TCP (vmnet's virtio-header mode with
/// TSO), as a TAP would give it ([`rx_offload`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rx {
    /// The frame, as [`rx_offload`] left it, with this header.
    Frame(VnetHdr),
    /// [`rx_segment`]'s frames: a TCP superframe that the guest's offloads
    /// do not take whole.
    Segment,
    /// No frame: what a TAP is never given (see [`rx_offload`]).
    Drop,
}

/// The transport header of a frame: where it starts, where the checksum
/// field is from there, its length, and where the IP packet ends.
struct L4 {
    l3: L3,
    off: usize,
    csum_offset: usize,
    len: usize,
    end: usize,
}

/// The TCP or UDP header of an IP packet that is not a fragment, if the
/// frame holds all of it.
fn parse_l4(frame: &[u8]) -> Option<L4> {
    let l3 = parse_l3(frame)?;
    let ip = &frame[l3.off..];
    let (end, fragment) = if l3.v6 {
        let fragment = has_ipv6_fragment_header(frame, &l3);
        (l3.off + 40 + usize::from(be16(ip, 4)), fragment)
    } else {
        (l3.off + usize::from(be16(ip, 2)), be16(ip, 6) & 0x3fff != 0)
    };
    let off = l3.off + l3.len;
    if fragment || end > frame.len() || end < off {
        return None;
    }
    let (csum_offset, len) = match l3.proto {
        IPPROTO_TCP => {
            let doff = usize::from(*frame.get(off + 12)? >> 4) * 4;
            (16, doff)
        }
        IPPROTO_UDP => (6, 8),
        _ => return None,
    };
    if len < 8 || off + len > end {
        return None;
    }
    Some(L4 {
        l3,
        off,
        csum_offset,
        len,
        end,
    })
}

/// Whether an IPv6 packet's header chain holds a fragment header.
fn has_ipv6_fragment_header(frame: &[u8], l3: &L3) -> bool {
    let mut proto = frame[l3.off + 6];
    let mut at = l3.off + 40;
    while at < l3.off + l3.len {
        if proto == IPV6_FRAGMENT {
            return true;
        }
        let len = match proto {
            IPV6_AH => (usize::from(frame[at + 1]) + 2) * 4,
            IPV6_FRAGMENT => 8,
            _ => (usize::from(frame[at + 1]) + 1) * 8,
        };
        proto = frame[at];
        at += len;
    }
    false
}

/// The sum of the pseudo header, folded and not complemented: what the
/// checksum field holds while the checksum is left to the receiver
/// (`~tcp_v4_check(len, saddr, daddr, 0)`).
fn seed(frame: &[u8], l4: &L4) -> u16 {
    !fold(pseudo_sum(frame, &l4.l3, l4.end - l4.off))
}

/// Whether the transport checksum of the packet is correct.
fn l4_checksum_ok(frame: &[u8], l4: &L4) -> bool {
    let acc = sum(
        &frame[l4.off..l4.end],
        pseudo_sum(frame, &l4.l3, l4.end - l4.off),
    );
    fold(acc) == 0
}

/// A UDP over IPv4 datagram sent without a checksum.
fn udp4_without_checksum(frame: &[u8], l4: &L4) -> bool {
    !l4.l3.v6 && l4.l3.proto == IPPROTO_UDP && be16(frame, l4.off + 6) == 0
}

/// The source address of the packet.
fn source(frame: &[u8], l3: &L3) -> IpAddr {
    if l3.v6 {
        let b: [u8; 16] = frame[l3.off + 8..l3.off + 24]
            .try_into()
            .unwrap_or_default();
        IpAddr::from(b)
    } else {
        let b: [u8; 4] = frame[l3.off + 12..l3.off + 16]
            .try_into()
            .unwrap_or_default();
        IpAddr::from(b)
    }
}

/// The payload bytes per segment of a TCP superframe on a link of `mtu`:
/// what fits one IP packet of `mtu` bytes after its IP and TCP headers.
fn superframe_mss(l4: &L4, mtu: usize) -> Option<usize> {
    mtu.checked_sub(l4.l3.len + l4.len).filter(|&mss| mss > 0)
}

/// The header and frame a TAP gives the guest for `frame`, which a backend
/// that coalesces TCP (vmnet's virtio-header mode with TSO) delivered, with
/// `data_valid` if the backend's header said it checked the frame's
/// checksums (`VIRTIO_NET_HDR_F_DATA_VALID`). `mtu` is the link's MTU,
/// `offloads` the `TUN_F_*` flags the device set ([`check_offload`]), and
/// `from_host` says whether an address is one of the host's own on the
/// link. The frame's checksum field may be rewritten.
///
/// The backend's header is not passed on: vmnet's says `DATA_VALID |
/// RSC_INFO` with `csum_start` 168 on every coalesced frame (measured on
/// macOS 27.2), which is not the segment count `RSC_INFO` names, and a
/// guest without `VIRTIO_NET_F_GUEST_RSC4/6` may not be given it. A TAP's
/// header is `virtio_net_hdr_from_skb`'s (include/linux/virtio_net.h,
/// v6.1, :165 to :204) with `has_data_valid` false (drivers/net/tun.c,
/// :2112): `NEEDS_CSUM` for a `CHECKSUM_PARTIAL` skb, a GSO type for a GSO
/// one, and otherwise nothing. So:
///
/// - A TCP frame over the MTU is a superframe the backend coalesced. On
///   Linux it is a GRO skb: `tcp4_gro_complete` and `tcp6_gro_complete`
///   (net/ipv4/tcp_offload.c :338, net/ipv6/tcpv6_offload.c :35) leave the
///   pseudo header's sum in the checksum field, and `tcp_gro_complete`
///   (:299 to :311) makes it `CHECKSUM_PARTIAL` at the TCP header, with
///   `SKB_GSO_TCP_ECN` if CWR is set, whatever the frame's source. The
///   TAP takes it whole when its features have the GSO type
///   (`netif_needs_gso`, include/linux/netdevice.h :4947; tun.c's
///   `set_offload` :2867 gives `NETIF_F_TSO`/`TSO6` for `TUN_F_TSO4`/`6`
///   with `TUN_F_CSUM`, and `NETIF_F_TSO_ECN` for `TUN_F_TSO_ECN`); here,
///   [`Rx::Frame`] with `NEEDS_CSUM` and `GSO_TCPV4`/`TCPV6`. Otherwise
///   the kernel segments it ([`Rx::Segment`]). `gso_size` is GRO's first
///   segment's payload, which the backend does not report: it is the MTU's
///   (the MTU less the IP and TCP headers), the most a sender on this link
///   puts in a segment. `SKB_GSO_TCP_FIXEDID`, which would make a TAP
///   segment an IPv4 superframe with DF set whose segments had one IP ID
///   (net/core/dev.c :10025 to :10031 offers `NETIF_F_TSO_MANGLEID` only
///   to `hw_features`, after tun.c :997 set the features), cannot be told
///   from the superframe; it is taken as not set, as for the host's own
///   TSO frames. Without `data_valid` its checksum is checked first, as
///   `tcp4_gro_receive` checks each segment's (:320 to :328).
/// - A TCP or UDP frame up to the MTU from the host's own address is
///   `CHECKSUM_PARTIAL` when the TAP has `NETIF_F_HW_CSUM`
///   (`TUN_F_CSUM`): `__tcp_v4_send_check` (net/ipv4/tcp_ipv4.c :644) and
///   `udp4_hwcsum` (net/ipv4/udp.c :829, from :955) leave the pseudo
///   header's sum. Here, `NEEDS_CSUM` and that sum, when the frame's
///   checksum is correct (a frame that claims the host's address but is
///   not the host's keeps its checksum for the guest to check). A forwarded
///   frame keeps its checksum and gets no flags; one the backend marked
///   `DATA_VALID` has its checksum completed, since the backend need not
///   have left a complete one.
/// - Other frames up to the MTU (not TCP or UDP, fragments, a UDP datagram
///   over IPv4 without a checksum) are given as they are, with no flags.
/// - A frame over the MTU that is not a TCP superframe whose IP length is
///   the frame's, whose checksum the backend checked or that is correct, is
///   [`Rx::Drop`]: a TAP is never given one, and its checksum field is not
///   one the guest could check.
pub fn rx_offload(
    frame: &mut [u8],
    data_valid: bool,
    mtu: usize,
    offloads: u32,
    from_host: &dyn Fn(IpAddr) -> bool,
) -> Rx {
    let csum = offloads & TUN_F_CSUM != 0;
    let l4 = parse_l4(frame);
    let ip_len = match (&l4, l3_start(frame)) {
        (Some(l4), _) => l4.end - l4.l3.off,
        (None, Some((off, _))) => frame.len().saturating_sub(off),
        (None, None) => 0,
    };
    if ip_len > mtu {
        let Some(l4) = l4.filter(|l4| l4.l3.proto == IPPROTO_TCP && l4.end == frame.len()) else {
            return Rx::Drop;
        };
        let Some(mss) = superframe_mss(&l4, mtu) else {
            return Rx::Drop;
        };
        if !data_valid && !l4_checksum_ok(frame, &l4) {
            return Rx::Drop;
        }
        let (gso, tso) = if l4.l3.v6 {
            (GSO_TCPV6, TUN_F_TSO6)
        } else {
            (GSO_TCPV4, TUN_F_TSO4)
        };
        let cwr = frame[l4.off + 13] & TCP_CWR != 0;
        if !csum || offloads & tso == 0 || (cwr && offloads & TUN_F_TSO_ECN == 0) {
            return Rx::Segment;
        }
        put16(frame, l4.off + l4.csum_offset, seed(frame, &l4));
        // The frame is at most 64 KiB here: its IP length fits 16 bits.
        #[allow(clippy::cast_possible_truncation)]
        return Rx::Frame(VnetHdr {
            flags: F_NEEDS_CSUM,
            gso_type: gso | if cwr { GSO_ECN } else { 0 },
            hdr_len: (l4.off + l4.len) as u16,
            gso_size: mss as u16,
            csum_start: l4.off as u16,
            csum_offset: l4.csum_offset as u16,
        });
    }
    let Some(l4) = l4.filter(|l4| !udp4_without_checksum(frame, l4)) else {
        return Rx::Frame(VnetHdr::default());
    };
    if csum && from_host(source(frame, &l4.l3)) && (data_valid || l4_checksum_ok(frame, &l4)) {
        put16(frame, l4.off + l4.csum_offset, seed(frame, &l4));
        // Up to the MTU, and the MTU is an IP length: these fit 16 bits.
        #[allow(clippy::cast_possible_truncation)]
        return Rx::Frame(VnetHdr {
            flags: F_NEEDS_CSUM,
            csum_start: l4.off as u16,
            csum_offset: l4.csum_offset as u16,
            ..VnetHdr::default()
        });
    }
    if data_valid {
        put16(frame, l4.off + l4.csum_offset, seed(frame, &l4));
        // In the frame: parse_l4 checked it.
        let _ = complete_checksum(&mut frame[..l4.end], l4.off, l4.csum_offset);
    }
    Rx::Frame(VnetHdr::default())
}

/// The frames a TAP is given for a superframe that [`rx_offload`] answered
/// [`Rx::Segment`] for, each passed to `emit` with its header: the kernel's
/// software segmentation (`validate_xmit_skb`, net/core/dev.c :3668) into
/// segments of the MTU's payload ([`rx_offload`]), each `CHECKSUM_PARTIAL`
/// with `NEEDS_CSUM` when the TAP has `TUN_F_CSUM` (tcp_offload.c :129 to
/// :132), and otherwise with its checksum complete and no flags.
pub fn rx_segment(
    frame: &[u8],
    mtu: usize,
    offloads: u32,
    scratch: &mut Vec<u8>,
    emit: &mut dyn FnMut(&VnetHdr, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let l4 = parse_l4(frame).ok_or_else(einval)?;
    if l4.l3.proto != IPPROTO_TCP {
        return Err(einval());
    }
    let mss = superframe_mss(&l4, mtu).ok_or_else(einval)?;
    let partial = offloads & TUN_F_CSUM != 0;
    let hdr = if partial {
        // A TCP header's offset is within the first 64 KiB.
        #[allow(clippy::cast_possible_truncation)]
        VnetHdr {
            flags: F_NEEDS_CSUM,
            csum_start: l4.off as u16,
            csum_offset: 16,
            ..VnetHdr::default()
        }
    } else {
        VnetHdr::default()
    };
    tcp_segment(frame, mss, l4.l3.v6, partial, scratch, &mut |seg| {
        emit(&hdr, seg)
    })
}

/// TCP segmentation (`tcp_gso_segment`): every segment carries at most `mss`
/// bytes of payload, the sequence number of its first byte, FIN and PSH only
/// on the last segment and CWR only on the first, an incremented IPv4 ID, and
/// complete checksums; with `partial`, each TCP checksum is left as the
/// pseudo header's sum instead, as a segment of a `CHECKSUM_PARTIAL` skb is
/// (net/ipv4/tcp_offload.c, v6.1, :129 to :132).
fn tcp_segment(
    frame: &[u8],
    mss: usize,
    v6: bool,
    partial: bool,
    scratch: &mut Vec<u8>,
    emit: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let l3 = parse_l3(frame).ok_or_else(einval)?;
    if l3.v6 != v6 || l3.proto != IPPROTO_TCP {
        return Err(einval());
    }
    let l4 = l3.off + l3.len;
    let tcp = frame.get(l4..l4 + 20).ok_or_else(einval)?;
    let doff = usize::from(tcp[12] >> 4) * 4;
    let hdrs = l4 + doff;
    if doff < 20 || hdrs > frame.len() {
        return Err(einval());
    }
    let seq = be32(frame, l4 + 4);
    let flags = frame[l4 + 13];
    let id = (!v6).then(|| be16(frame, l3.off + 4));
    let payload = &frame[hdrs..];
    let count = payload.len().div_ceil(mss).max(1);
    for i in 0..count {
        let start = i * mss;
        let end = payload.len().min(start + mss);
        scratch.clear();
        scratch.extend_from_slice(&frame[..hdrs]);
        scratch.extend_from_slice(&payload[start..end]);
        let seg = scratch.as_mut_slice();
        set_ip_len(seg, &l3)?;
        if let Some(id) = id {
            // `i` is below 2^16 for any frame that fits an IP packet.
            #[allow(clippy::cast_possible_truncation)]
            put16(seg, l3.off + 4, id.wrapping_add(i as u16));
            ipv4_checksum(seg, &l3);
        }
        #[allow(clippy::cast_possible_truncation)]
        put32(seg, l4 + 4, seq.wrapping_add(start as u32));
        let mut f = flags;
        if i + 1 < count {
            f &= !(TCP_FIN | TCP_PSH);
        }
        if i > 0 {
            f &= !TCP_CWR;
        }
        seg[l4 + 13] = f;
        put16(seg, l4 + 16, 0);
        let pseudo = pseudo_sum(seg, &l3, seg.len() - l4);
        let csum = if partial {
            !fold(pseudo)
        } else {
            fold(sum(&seg[l4..], pseudo))
        };
        put16(seg, l4 + 16, csum);
        emit(seg)?;
    }
    Ok(())
}

/// Identification for IPv6 fragment headers.
static FRAG_ID: AtomicU32 = AtomicU32::new(1);

/// UDP fragmentation offload: the datagram, its checksum already complete, is
/// sent as IP fragments of at most `mss` bytes of fragmentable payload
/// (rounded down to a multiple of 8, as fragment offsets require).
fn udp_fragment(
    frame: &[u8],
    mss: usize,
    scratch: &mut Vec<u8>,
    emit: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let l3 = parse_l3(frame).ok_or_else(einval)?;
    if l3.proto != IPPROTO_UDP {
        return Err(einval());
    }
    let head = l3.off + l3.unfrag;
    let payload = &frame[head..];
    if payload.len() <= mss {
        return emit(frame);
    }
    let step = mss & !7;
    if step == 0 {
        return Err(einval());
    }
    let id = FRAG_ID.fetch_add(1, Ordering::Relaxed);
    let mut start = 0;
    while start < payload.len() {
        let end = payload.len().min(start + step);
        let more = end < payload.len();
        let off = u16::try_from(start / 8).map_err(|_| einval())? << 3;
        scratch.clear();
        scratch.extend_from_slice(&frame[..head]);
        if l3.v6 {
            // Fragment header: next header, reserved, offset | M, identification.
            let next = frame[l3.nexthdr_at];
            scratch[l3.nexthdr_at] = IPV6_FRAGMENT;
            scratch.extend_from_slice(&[next, 0]);
            scratch.extend_from_slice(&(off | u16::from(more)).to_be_bytes());
            scratch.extend_from_slice(&id.to_be_bytes());
        }
        scratch.extend_from_slice(&payload[start..end]);
        let seg = scratch.as_mut_slice();
        set_ip_len(seg, &l3)?;
        if !l3.v6 {
            put16(seg, l3.off + 6, (off >> 3) | if more { IP_MF } else { 0 });
            ipv4_checksum(seg, &l3);
        }
        emit(seg)?;
        start = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use super::*;

    const MAC: [u8; 12] = [2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];

    fn ipv4(proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut f = MAC.to_vec();
        f.extend_from_slice(&ETH_P_IP.to_be_bytes());
        let total = (20 + l4.len()) as u16;
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, proto, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend_from_slice(l4);
        let l3 = parse_l3(&f).unwrap();
        ipv4_checksum(&mut f, &l3);
        f
    }

    fn ipv6(proto: u8, ext: &[u8], l4: &[u8]) -> Vec<u8> {
        let mut f = MAC.to_vec();
        f.extend_from_slice(&ETH_P_IPV6.to_be_bytes());
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&((ext.len() + l4.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[if ext.is_empty() { proto } else { IPV6_HOPOPTS }, 64]);
        f.extend_from_slice(&[0xfd; 16]);
        f.extend_from_slice(&[0xfe; 16]);
        f.extend_from_slice(ext);
        f.extend_from_slice(l4);
        f
    }

    fn tcp(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![
            0x30, 0x39, 0x00, 0x50, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x50, flags,
        ];
        t.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        t.extend_from_slice(payload);
        t
    }

    fn udp(payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0x30, 0x39, 0x00, 0x35];
        u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// Puts the pseudo-header sum in the checksum field, as a guest does
    /// before asking for checksum offload.
    fn partial(frame: &mut [u8], csum_at: usize) -> VnetHdr {
        let l3 = parse_l3(frame).unwrap();
        let l4 = l3.off + l3.len;
        let acc = pseudo_sum(frame, &l3, frame.len() - l4);
        put16(frame, l4 + csum_at, !fold(acc));
        VnetHdr {
            flags: F_NEEDS_CSUM,
            csum_start: l4 as u16,
            csum_offset: csum_at as u16,
            ..Default::default()
        }
    }

    fn l4_valid(frame: &[u8]) -> bool {
        let l3 = parse_l3(frame).unwrap();
        let l4 = l3.off + l3.len;
        fold(sum(&frame[l4..], pseudo_sum(frame, &l3, frame.len() - l4))) == 0
    }

    fn run(hdr: &VnetHdr, frame: &mut [u8]) -> io::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        segment(hdr, frame, &mut Vec::new(), &mut |seg| {
            out.push(seg.to_vec());
            Ok(())
        })?;
        Ok(out)
    }

    /// A TCP superframe as a guest's TSO writes it.
    fn tso_frame(v6: bool, len: usize) -> (VnetHdr, Vec<u8>) {
        let t = tcp(0x18, &payload(len));
        let mut f = if v6 {
            ipv6(IPPROTO_TCP, &[], &t)
        } else {
            ipv4(IPPROTO_TCP, &t)
        };
        let mut hdr = partial(&mut f, 16);
        hdr.gso_type = if v6 { GSO_TCPV6 } else { GSO_TCPV4 };
        hdr.gso_size = 1448;
        hdr.hdr_len = hdr.csum_start + 20;
        (hdr, f)
    }

    const MTU: usize = 1500;
    const ALL: u32 = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_UFO;

    /// A TCP segment with complete checksums, as a backend delivers it; TCP
    /// header with the timestamp option (32 bytes), as vmnet's were.
    fn rx_tcp(v6: bool, flags: u8, len: usize) -> Vec<u8> {
        let mut t = tcp(flags, &[]);
        t[12] = 0x80;
        t.extend_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
        t.extend_from_slice(&payload(len));
        let mut f = if v6 {
            ipv6(IPPROTO_TCP, &[], &t)
        } else {
            ipv4(IPPROTO_TCP, &t)
        };
        fill(&mut f, 16);
        f
    }

    /// Completes the transport checksum at `csum_at` of the frame.
    fn fill(f: &mut [u8], csum_at: usize) {
        let hdr = partial(f, csum_at);
        complete_checksum(f, hdr.csum_start.into(), csum_at).unwrap();
    }

    /// The host's own address in these frames: the source of `ipv4` and
    /// `ipv6`.
    fn host(a: IpAddr) -> bool {
        a == IpAddr::from([10, 0, 0, 1]) || a == IpAddr::from([0xfd; 16])
    }

    fn forwarded(_: IpAddr) -> bool {
        false
    }

    /// The checksum a guest completing `NEEDS_CSUM` writes.
    fn completed(frame: &[u8], hdr: &VnetHdr) -> Vec<u8> {
        let mut f = frame.to_vec();
        complete_checksum(&mut f, hdr.csum_start.into(), hdr.csum_offset.into()).unwrap();
        f
    }

    #[test]
    fn test_rx_superframe_is_one_gso_frame_whatever_its_source() {
        for v6 in [false, true] {
            for from_host in [host as fn(IpAddr) -> bool, forwarded] {
                let orig = rx_tcp(v6, 0x10, 40000);
                let mut f = orig.clone();
                let Rx::Frame(hdr) = rx_offload(&mut f, true, MTU, ALL, &from_host) else {
                    panic!("v6 {v6}: not one frame");
                };
                let l4 = if v6 { 54 } else { 34 };
                let want = VnetHdr {
                    flags: F_NEEDS_CSUM,
                    gso_type: if v6 { GSO_TCPV6 } else { GSO_TCPV4 },
                    hdr_len: (l4 + 32) as u16,
                    // The MTU less the IP and TCP headers: 1448 for IPv4,
                    // the gso_size vmnet's guest TSO frames had.
                    gso_size: if v6 { 1428 } else { 1448 },
                    csum_start: l4 as u16,
                    csum_offset: 16,
                };
                assert_eq!(hdr, want, "v6 {v6}");
                // The pseudo header's sum, as tcp4/6_gro_complete leave it:
                // the guest's completion gives back the original frame.
                let l3 = parse_l3(&f).unwrap();
                assert_eq!(be16(&f, l4 + 16), !fold(pseudo_sum(&f, &l3, f.len() - l4)));
                assert_eq!(completed(&f, &hdr), orig, "v6 {v6}");
                // What the guest is given is what Linux's virtio_net_hdr_to_skb
                // takes, and what a TAP's own writer could hand over.
                assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Offload, "v6 {v6}");
            }
        }
    }

    #[test]
    fn test_rx_superframe_the_offloads_do_not_take_is_segmented() {
        for v6 in [false, true] {
            let cwr = 0x10 | TCP_CWR;
            for (flags, offloads) in [
                (0x10, TUN_F_CSUM | if v6 { TUN_F_TSO4 } else { TUN_F_TSO6 }),
                (0x10, 0),
                (cwr, ALL),
            ] {
                let mut f = rx_tcp(v6, flags, 40000);
                assert_eq!(rx_offload(&mut f, true, MTU, offloads, &host), Rx::Segment);
                let mut segs = Vec::new();
                rx_segment(&f, MTU, offloads, &mut Vec::new(), &mut |h, s| {
                    segs.push((*h, s.to_vec()));
                    Ok(())
                })
                .unwrap();
                let mss = if v6 { 1428 } else { 1448 };
                assert_eq!(segs.len(), 40000_usize.div_ceil(mss));
                let hdrs = f.len() - 40000;
                let mut data = Vec::new();
                for (h, s) in &segs {
                    assert!(s.len() - hdrs <= mss);
                    assert!(s.len() - 14 <= MTU);
                    let s = if offloads & TUN_F_CSUM != 0 {
                        assert_eq!(h.flags, F_NEEDS_CSUM);
                        assert_eq!(usize::from(h.csum_start), hdrs - 32);
                        completed(s, h)
                    } else {
                        assert_eq!(*h, VnetHdr::default());
                        s.clone()
                    };
                    assert!(l4_valid(&s));
                    data.extend_from_slice(&s[hdrs..]);
                }
                assert_eq!(data, payload(40000));
            }
            // With TUN_F_TSO_ECN, a CWR superframe is one frame with the ECN bit.
            let mut f = rx_tcp(v6, 0x10 | TCP_CWR, 40000);
            let Rx::Frame(hdr) = rx_offload(&mut f, true, MTU, ALL | TUN_F_TSO_ECN, &host) else {
                panic!("v6 {v6}: not one frame");
            };
            assert_eq!(hdr.gso_type & GSO_ECN, GSO_ECN);
        }
    }

    #[test]
    fn test_rx_superframe_checksum_is_checked_unless_the_backend_did() {
        let mut f = rx_tcp(false, 0x10, 40000);
        assert!(matches!(
            rx_offload(&mut f, false, MTU, ALL, &host),
            Rx::Frame(_)
        ));
        let mut f = rx_tcp(false, 0x10, 40000);
        f[100] ^= 1;
        assert_eq!(rx_offload(&mut f.clone(), false, MTU, ALL, &host), Rx::Drop);
        assert!(matches!(
            rx_offload(&mut f, true, MTU, ALL, &host),
            Rx::Frame(_)
        ));
    }

    #[test]
    fn test_rx_over_the_mtu_is_dropped_unless_a_tcp_superframe() {
        // UDP: not coalesced by GRO into what a TAP is given.
        let mut f = ipv4(IPPROTO_UDP, &udp(&payload(4000)));
        fill(&mut f, 6);
        assert_eq!(rx_offload(&mut f, true, MTU, ALL, &host), Rx::Drop);
        // Not IP.
        let mut f = MAC.to_vec();
        f.extend_from_slice(&[0x88, 0xb5]);
        f.extend_from_slice(&payload(3000));
        assert_eq!(rx_offload(&mut f, true, MTU, ALL, &host), Rx::Drop);
        // A TCP frame whose IP length is not the frame's.
        let mut f = rx_tcp(false, 0x10, 40000);
        f.extend_from_slice(&[0; 4]);
        assert_eq!(rx_offload(&mut f, true, MTU, ALL, &host), Rx::Drop);
        // An MTU with no room for payload after the headers.
        let mut f = rx_tcp(false, 0x10, 40000);
        assert_eq!(rx_offload(&mut f, true, 52, ALL, &host), Rx::Drop);
    }

    #[test]
    fn test_rx_from_the_host_is_partial_as_the_hosts_own_stack_sends_it() {
        for v6 in [false, true] {
            for (proto, at) in [(IPPROTO_TCP, 16), (IPPROTO_UDP, 6)] {
                let l4 = if proto == IPPROTO_TCP {
                    tcp(0x18, &payload(1000))
                } else {
                    udp(&payload(1000))
                };
                let mut orig = if v6 {
                    ipv6(proto, &[], &l4)
                } else {
                    ipv4(proto, &l4)
                };
                fill(&mut orig, at);
                for data_valid in [false, true] {
                    let mut f = orig.clone();
                    let Rx::Frame(hdr) = rx_offload(&mut f, data_valid, MTU, ALL, &host) else {
                        panic!("not a frame");
                    };
                    let start = if v6 { 54 } else { 34 };
                    assert_eq!(
                        hdr,
                        VnetHdr {
                            flags: F_NEEDS_CSUM,
                            csum_start: start,
                            csum_offset: at as u16,
                            ..Default::default()
                        },
                        "v6 {v6} proto {proto}"
                    );
                    assert_eq!(completed(&f, &hdr), orig);
                    assert_ne!(f, orig);
                }
                // Without TUN_F_CSUM, the host completes it: as it came.
                let mut f = orig.clone();
                assert_eq!(
                    rx_offload(&mut f, false, MTU, 0, &host),
                    Rx::Frame(VnetHdr::default())
                );
                assert_eq!(f, orig);
                // From another address: forwarded, as it came.
                let mut f = orig.clone();
                assert_eq!(
                    rx_offload(&mut f, false, MTU, ALL, &forwarded),
                    Rx::Frame(VnetHdr::default())
                );
                assert_eq!(f, orig);
                // The host's address with a wrong checksum: not the host's
                // stack; the guest checks it.
                let mut bad = orig.clone();
                let n = bad.len();
                bad[n - 1] ^= 1;
                let mut f = bad.clone();
                assert_eq!(
                    rx_offload(&mut f, false, MTU, ALL, &host),
                    Rx::Frame(VnetHdr::default())
                );
                assert_eq!(f, bad);
            }
        }
    }

    #[test]
    fn test_rx_forwarded_frame_the_backend_checked_gets_its_checksum_completed() {
        for v6 in [false, true] {
            let mut orig = if v6 {
                ipv6(IPPROTO_TCP, &[], &tcp(0x18, &payload(999)))
            } else {
                ipv4(IPPROTO_TCP, &tcp(0x18, &payload(999)))
            };
            fill(&mut orig, 16);
            let at = if v6 { 54 + 16 } else { 34 + 16 };
            // What the backend left in the field: not the checksum.
            let mut f = orig.clone();
            put16(&mut f, at, 0x1234);
            assert_eq!(
                rx_offload(&mut f, true, MTU, ALL, &forwarded),
                Rx::Frame(VnetHdr::default())
            );
            assert_eq!(f, orig, "v6 {v6}");
        }
    }

    #[test]
    fn test_rx_other_frames_are_given_as_they_came() {
        let mut frames = Vec::new();
        // ICMP from the host.
        frames.push(ipv4(1, &payload(64)));
        // A UDP datagram over IPv4 without a checksum.
        frames.push(ipv4(IPPROTO_UDP, &udp(&payload(100))));
        // An IPv4 fragment (MF) and a later one (offset).
        let mut frag = ipv4(IPPROTO_UDP, &udp(&payload(100)));
        fill(&mut frag, 6);
        frag[20] = 0x20;
        let l3 = parse_l3(&frag).unwrap();
        ipv4_checksum(&mut frag, &l3);
        frames.push(frag.clone());
        frag[20] = 0;
        frag[21] = 0x10;
        ipv4_checksum(&mut frag, &l3);
        frames.push(frag);
        // An IPv6 fragment.
        let mut f = ipv6(IPPROTO_UDP, &[], &[]);
        f.truncate(14 + 40);
        f[14 + 6] = IPV6_FRAGMENT;
        f.extend_from_slice(&[IPPROTO_UDP, 0, 0, 1, 0, 0, 0, 7]);
        f.extend_from_slice(&udp(&payload(100)));
        let n = (f.len() - 54) as u16;
        f[18..20].copy_from_slice(&n.to_be_bytes());
        frames.push(f);
        // ARP-sized, padded to 60 bytes.
        let mut arp = MAC.to_vec();
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.resize(60, 0);
        frames.push(arp);
        for (i, orig) in frames.into_iter().enumerate() {
            for data_valid in [false, true] {
                let mut f = orig.clone();
                assert_eq!(
                    rx_offload(&mut f, data_valid, MTU, ALL, &host),
                    Rx::Frame(VnetHdr::default()),
                    "frame {i}"
                );
                assert_eq!(f, orig, "frame {i}");
            }
        }
    }

    #[test]
    fn test_tx_offload_takes_tcp_superframes() {
        for v6 in [false, true] {
            let (hdr, f) = tso_frame(v6, 20000);
            assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Offload, "v6 {v6}");
            // A frame with no more payload than gso_size is not GSO for
            // Linux (virtio_net.h :151): segmented here, as one frame.
            let (hdr, f) = tso_frame(v6, 1448);
            assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Segment, "v6 {v6}");
        }
    }

    #[test]
    fn test_tx_offload_segments_what_it_does_not_hand_over() {
        // ECN, a GSO frame without NEEDS_CSUM, UFO, checksum offload alone,
        // a plain frame, a TCPv4 type on an IPv6 frame with NEEDS_CSUM (Linux
        // takes it: the type is checked against the frame only without it),
        // and a csum_start that is not the TCP header.
        let (mut hdr, f) = tso_frame(false, 20000);
        hdr.gso_type |= GSO_ECN;
        assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Segment);
        let (mut hdr, f) = tso_frame(false, 20000);
        hdr.flags = 0;
        assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Segment);
        let mut f = ipv4(IPPROTO_UDP, &udp(&payload(4000)));
        let mut hdr = partial(&mut f, 6);
        hdr.gso_type = GSO_UDP;
        hdr.gso_size = 1472;
        assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Segment);
        let mut f = ipv4(IPPROTO_TCP, &tcp(0x18, &payload(100)));
        let hdr = partial(&mut f, 16);
        assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Segment);
        assert_eq!(tx_offload(&VnetHdr::default(), &f).unwrap(), Tx::Segment);
        let (mut hdr, f) = tso_frame(true, 20000);
        hdr.gso_type = GSO_TCPV4;
        assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Segment);
        let (mut hdr, f) = tso_frame(false, 20000);
        hdr.csum_start += 4;
        hdr.csum_offset = 12;
        assert_eq!(tx_offload(&hdr, &f).unwrap(), Tx::Segment);
    }

    #[test]
    fn test_tx_offload_refuses_what_a_tap_refuses() {
        let (good, f) = tso_frame(false, 20000);
        let refused = |hdr: VnetHdr, f: &[u8], why: &str| {
            let err = tx_offload(&hdr, f).expect_err(why);
            assert_eq!(err.raw_os_error(), Some(libc::EINVAL), "{why}");
        };
        // virtio_net_hdr_to_skb: GSO types it does not know.
        for t in [2, 5, 6, 0x7f, 0x80 | 2] {
            refused(
                VnetHdr {
                    gso_type: t,
                    ..good
                },
                &f,
                &format!("gso_type {t:#x}"),
            );
        }
        // A GSO type with gso_size 0.
        refused(
            VnetHdr {
                gso_size: 0,
                ..good
            },
            &f,
            "gso_size 0",
        );
        // NEEDS_CSUM: the checksum field past the frame, and the transport
        // header past it.
        let end = f.len() as u16;
        refused(
            VnetHdr {
                csum_start: end - 1,
                csum_offset: 0,
                hdr_len: 0,
                ..good
            },
            &f,
            "csum field past the frame",
        );
        refused(
            VnetHdr {
                csum_start: 0,
                csum_offset: end,
                hdr_len: 0,
                ..good
            },
            &f,
            "csum_offset past the frame",
        );
        refused(
            VnetHdr {
                csum_start: end - 10,
                csum_offset: 0,
                hdr_len: 0,
                ..good
            },
            &f,
            "TCP header past the frame",
        );
        // tun_get_user: hdr_len past the frame, or shorter than Ethernet's.
        refused(
            VnetHdr {
                hdr_len: end + 1,
                ..good
            },
            &f,
            "hdr_len past the frame",
        );
        refused(
            VnetHdr {
                flags: 0,
                hdr_len: 13,
                ..good
            },
            &f,
            "hdr_len 13",
        );
        refused(
            VnetHdr::default(),
            &f[..13],
            "a frame shorter than Ethernet's header",
        );
        // Without NEEDS_CSUM, a GSO frame shorter than the transport header.
        let mut arp = MAC.to_vec();
        arp.extend_from_slice(&[0x08, 0x06]);
        let gso = VnetHdr {
            gso_type: GSO_TCPV4,
            gso_size: 1448,
            ..Default::default()
        };
        arp.resize(19, 0);
        refused(gso, &arp, "TCPv4 GSO, 19 bytes");
        // What Linux takes, so do we: without NEEDS_CSUM a TAP does not
        // check the frame against the type (the skb has no network header
        // yet), whatever the frame.
        tx_offload(&good, &f).unwrap();
        tx_offload(
            &VnetHdr {
                flags: 0,
                hdr_len: 0,
                ..good
            },
            &f,
        )
        .unwrap();
        let (v6, f6) = tso_frame(true, 20000);
        tx_offload(
            &VnetHdr {
                flags: 0,
                gso_type: GSO_TCPV4,
                ..v6
            },
            &f6,
        )
        .unwrap();
        arp.resize(60, 0);
        tx_offload(&gso, &arp).unwrap();
    }

    #[test]
    fn test_header_round_trip() {
        let hdr = VnetHdr {
            flags: 1,
            gso_type: GSO_TCPV4,
            hdr_len: 54,
            gso_size: 1448,
            csum_start: 34,
            csum_offset: 16,
        };
        let mut bytes = [0u8; 12];
        hdr.write(&mut bytes);
        assert_eq!(VnetHdr::parse(&bytes), Some(hdr));
        assert_eq!(VnetHdr::parse(&bytes[..9]), None);
    }

    #[test]
    fn test_ioctl_checks() {
        assert_eq!(check_hdr_len(10).unwrap(), 10);
        assert_eq!(check_hdr_len(12).unwrap(), 12);
        check_hdr_len(9).unwrap_err();
        check_hdr_len(-1).unwrap_err();

        check_offload(0).unwrap();
        check_offload(TUN_F_CSUM).unwrap();
        check_offload(TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN | TUN_F_UFO).unwrap();
        check_offload(TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6).unwrap();
        check_offload(TUN_F_TSO4).unwrap_err();
        check_offload(TUN_F_CSUM | TUN_F_TSO_ECN).unwrap_err();
        check_offload(TUN_F_CSUM | TUN_F_USO4).unwrap_err();
        check_offload(0x80).unwrap_err();
    }

    #[test]
    fn test_plain_frame_unchanged() {
        let mut frame = ipv4(IPPROTO_UDP, &udp(&payload(100)));
        let orig = frame.clone();
        assert_eq!(run(&VnetHdr::default(), &mut frame).unwrap(), vec![orig]);
    }

    #[test]
    fn test_checksum_completion() {
        let mut frame = ipv4(IPPROTO_UDP, &udp(&payload(101)));
        let hdr = partial(&mut frame, 6);
        assert!(!l4_valid(&frame));
        let out = run(&hdr, &mut frame).unwrap();
        assert_eq!(out.len(), 1);
        assert!(l4_valid(&out[0]));

        let mut frame = ipv6(IPPROTO_TCP, &[], &tcp(0x18, &payload(77)));
        let hdr = partial(&mut frame, 16);
        let out = run(&hdr, &mut frame).unwrap();
        assert!(l4_valid(&out[0]));
    }

    #[test]
    fn test_bad_headers() {
        let mut frame = ipv4(IPPROTO_UDP, &udp(&payload(10)));
        let len = frame.len() as u16;
        let bad = |hdr: VnetHdr, frame: &mut [u8]| {
            run(&hdr, frame).unwrap_err().raw_os_error() == Some(libc::EINVAL)
        };
        // Checksum field past the end of the frame.
        let hdr = VnetHdr {
            flags: F_NEEDS_CSUM,
            csum_start: len - 1,
            csum_offset: 0,
            ..Default::default()
        };
        assert!(bad(hdr, &mut frame));
        // GSO without a segment size, unknown GSO types, TSO of UDP.
        for (gso_type, gso_size) in [(GSO_TCPV4, 0), (GSO_UDP, 0), (2, 100), (5, 100)] {
            let hdr = VnetHdr {
                gso_type,
                gso_size,
                ..Default::default()
            };
            assert!(bad(hdr, &mut frame));
        }
        let hdr = VnetHdr {
            gso_type: GSO_TCPV4,
            gso_size: 100,
            ..Default::default()
        };
        assert!(bad(hdr, &mut frame));
        let mut v6 = ipv6(IPPROTO_TCP, &[], &tcp(0, &payload(10)));
        assert!(bad(hdr, &mut v6));
    }

    fn check_tcp_segments(segs: &[Vec<u8>], data: &[u8], mss: usize, v6: bool) {
        assert_eq!(segs.len(), data.len().div_ceil(mss));
        let mut joined = Vec::new();
        for (i, seg) in segs.iter().enumerate() {
            let l3 = parse_l3(seg).unwrap();
            let l4 = l3.off + l3.len;
            if v6 {
                assert_eq!(usize::from(be16(seg, l3.off + 4)), seg.len() - l3.off - 40);
            } else {
                assert_eq!(usize::from(be16(seg, l3.off + 2)), seg.len() - l3.off);
                assert_eq!(be16(seg, l3.off + 4), 0x1234 + i as u16);
                assert_eq!(fold(sum(&seg[l3.off..l4], 0)), 0);
            }
            assert!(l4_valid(seg));
            assert_eq!(be32(seg, l4 + 4), 0x1000_0000 + (i * mss) as u32);
            let flags = seg[l4 + 13];
            let last = i + 1 == segs.len();
            assert_eq!(flags & (TCP_FIN | TCP_PSH) != 0, last);
            assert_eq!(flags & TCP_CWR != 0, i == 0);
            assert_eq!(flags & 0x10, 0x10);
            joined.extend_from_slice(&seg[l4 + 20..]);
            assert!(seg.len() - l4 - 20 <= mss);
        }
        assert_eq!(joined, data);
    }

    #[test]
    fn test_tso() {
        let data = payload(3500);
        let flags = TCP_FIN | TCP_PSH | TCP_CWR | 0x10;
        for v6 in [false, true] {
            let mut frame = if v6 {
                ipv6(IPPROTO_TCP, &[], &tcp(flags, &data))
            } else {
                ipv4(IPPROTO_TCP, &tcp(flags, &data))
            };
            let mut hdr = partial(&mut frame, 16);
            hdr.gso_type = if v6 { GSO_TCPV6 } else { GSO_TCPV4 } | GSO_ECN;
            hdr.gso_size = 1000;
            let segs = run(&hdr, &mut frame).unwrap();
            check_tcp_segments(&segs, &data, 1000, v6);
        }
        // A payload that fits one segment is sent as one complete segment.
        let mut frame = ipv4(IPPROTO_TCP, &tcp(0x10, &payload(10)));
        let mut hdr = partial(&mut frame, 16);
        hdr.gso_type = GSO_TCPV4;
        hdr.gso_size = 1000;
        let segs = run(&hdr, &mut frame).unwrap();
        assert_eq!(segs.len(), 1);
        assert!(l4_valid(&segs[0]));
    }

    #[test]
    fn test_ufo_ipv4() {
        let data = payload(4000);
        let mut frame = ipv4(IPPROTO_UDP, &udp(&data));
        let mut hdr = partial(&mut frame, 6);
        hdr.gso_type = GSO_UDP;
        hdr.gso_size = 1475;
        let frags = run(&hdr, &mut frame).unwrap();
        // 4008 bytes of UDP in fragments of 1472 bytes.
        assert_eq!(frags.len(), 3);
        let mut joined = Vec::new();
        for (i, f) in frags.iter().enumerate() {
            let l3 = parse_l3(f).unwrap();
            let frag = be16(f, l3.off + 6);
            assert_eq!(usize::from(frag & 0x1fff) * 8, joined.len());
            assert_eq!(frag & IP_MF != 0, i < 2);
            assert_eq!(usize::from(be16(f, l3.off + 2)), f.len() - l3.off);
            assert_eq!(be16(f, l3.off + 4), 0x1234);
            assert_eq!(fold(sum(&f[l3.off..l3.off + 20], 0)), 0);
            joined.extend_from_slice(&f[l3.off + 20..]);
        }
        // The reassembled datagram has a valid checksum.
        let whole = ipv4(IPPROTO_UDP, &joined);
        assert!(l4_valid(&whole));
        assert_eq!(&joined[8..], data.as_slice());
    }

    #[test]
    fn test_ufo_ipv6() {
        let data = payload(3000);
        // A hop-by-hop header stays in front of the fragment header.
        let hop = [IPPROTO_UDP, 0, 1, 4, 0, 0, 0, 0];
        let mut frame = ipv6(IPPROTO_UDP, &hop, &udp(&data));
        let mut hdr = partial(&mut frame, 6);
        hdr.gso_type = GSO_UDP;
        hdr.gso_size = 1400;
        let frags = run(&hdr, &mut frame).unwrap();
        assert_eq!(frags.len(), 3);
        let mut joined = Vec::new();
        let mut ids = Vec::new();
        for (i, f) in frags.iter().enumerate() {
            let base = 14;
            assert_eq!(f[base + 6], IPV6_HOPOPTS);
            assert_eq!(f[base + 40], IPV6_FRAGMENT);
            let fh = base + 48;
            assert_eq!(f[fh], IPPROTO_UDP);
            let off = be16(f, fh + 2);
            assert_eq!(usize::from(off >> 3) * 8, joined.len());
            assert_eq!(off & 1 != 0, i < 2);
            ids.push(be32(f, fh + 4));
            assert_eq!(usize::from(be16(f, base + 4)), f.len() - base - 40);
            joined.extend_from_slice(&f[fh + 8..]);
        }
        assert!(ids.iter().all(|id| *id == ids[0]));
        let whole = ipv6(IPPROTO_UDP, &hop, &joined);
        assert!(l4_valid(&whole));
        assert_eq!(&joined[8..], data.as_slice());
    }

    #[test]
    fn test_ufo_ipv6_fragment_header_place() {
        // Where ip6_find_1stfragopt puts the fragment header: after
        // destination options, unless they follow a routing header.
        let data = payload(2000);
        for (chain, unfrag) in [
            (vec![IPV6_HOPOPTS, IPV6_DSTOPTS], 2),
            (vec![IPV6_DSTOPTS], 1),
            (vec![IPV6_DSTOPTS, IPV6_ROUTING, IPV6_DSTOPTS], 2),
        ] {
            let mut ext = Vec::new();
            for i in 0..chain.len() {
                let next = chain.get(i + 1).copied().unwrap_or(IPPROTO_UDP);
                ext.extend_from_slice(&[next, 0, 1, 4, 0, 0, 0, 0]);
            }
            let mut frame = ipv6(IPPROTO_UDP, &ext, &udp(&data));
            frame[14 + 6] = chain[0];
            let mut hdr = partial(&mut frame, 6);
            hdr.gso_type = GSO_UDP;
            hdr.gso_size = 1400;
            let frags = run(&hdr, &mut frame).unwrap();
            assert_eq!(frags.len(), 2, "{chain:?}");
            let fh = 14 + 40 + 8 * unfrag;
            let first = chain.get(unfrag).copied().unwrap_or(IPPROTO_UDP);
            for f in &frags {
                assert_eq!(f[fh - 8], IPV6_FRAGMENT, "{chain:?}");
                assert_eq!(f[fh], first, "{chain:?}");
            }
        }
    }

    #[test]
    fn test_vlan_tagged() {
        let mut frame = ipv4(IPPROTO_TCP, &tcp(0x10, &payload(2500)));
        frame.splice(12..12, [0x81, 0x00, 0x00, 0x05]);
        let mut hdr = partial(&mut frame, 16);
        hdr.gso_type = GSO_TCPV4;
        hdr.gso_size = 1000;
        let segs = run(&hdr, &mut frame).unwrap();
        assert_eq!(segs.len(), 3);
        assert!(segs.iter().all(|s| l4_valid(s) && s[12] == 0x81));
    }
}
