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
    let mut words = data.chunks_exact(2);
    for w in &mut words {
        acc += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = words.remainder() {
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
            scratch,
            emit,
        ),
        GSO_UDP if hdr.gso_size > 0 => {
            udp_fragment(frame, usize::from(hdr.gso_size), scratch, emit)
        }
        _ => Err(einval()),
    }
}

/// TCP segmentation (`tcp_gso_segment`): every segment carries at most `mss`
/// bytes of payload, the sequence number of its first byte, FIN and PSH only
/// on the last segment and CWR only on the first, an incremented IPv4 ID, and
/// complete checksums.
fn tcp_segment(
    frame: &[u8],
    mss: usize,
    v6: bool,
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
        let csum = fold(sum(&seg[l4..], pseudo_sum(seg, &l3, seg.len() - l4)));
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
