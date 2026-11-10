// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! A reference for [`crate::vnet`]: Ethernet/IP/TCP/UDP parsing and
//! checksums written from the RFCs and the Linux code `vnet` follows
//! (`skb_checksum_help`, `tcp_gso_segment`, `udp6_ufo_fragment`,
//! `ip6_find_1stfragopt`), independently of `vnet`, and [`check`], which
//! says whether the frames `vnet::segment` sent for a frame are the frames
//! Linux would send.

use std::io;

use crate::vnet::{F_NEEDS_CSUM, GSO_ECN, GSO_NONE, GSO_TCPV4, GSO_TCPV6, GSO_UDP, VnetHdr};

/// The largest frame the virtio-net device hands its tap
/// (`MAX_BUFFER_SIZE`), less the 12-byte virtio-net header it uses.
pub const MAX_FRAME: usize = 65562 - 12;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88a8;
pub const IPPROTO_HOPOPTS: u8 = 0;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_CWR: u8 = 0x80;
pub const IP_MF: u16 = 0x2000;

pub fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

pub fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// The Internet checksum (RFC 1071) of `data` with `extra` added to the sum:
/// zero when `data` holds a correct checksum of itself.
pub fn checksum(data: &[u8], extra: u64) -> u16 {
    let mut acc = extra;
    for (i, b) in data.iter().enumerate() {
        acc += if i % 2 == 0 {
            u64::from(*b) << 8
        } else {
            u64::from(*b)
        };
    }
    while acc > 0xffff {
        acc = (acc >> 16) + (acc & 0xffff);
    }
    !(acc as u16)
}

/// Fragmentation fields of an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frag {
    /// Byte offset of the fragment.
    pub offset: usize,
    pub more: bool,
    pub id: u32,
}

/// The layers of a frame.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Offset of the IP header.
    pub l3: usize,
    pub v6: bool,
    /// Offset of the transport header (past every extension header).
    pub l4: usize,
    /// The transport protocol.
    pub proto: u8,
    /// Where IP fragmentation splits the packet: past the IPv4 header, or for
    /// IPv6 where `ip6_find_1stfragopt` puts the fragment header.
    pub frag_at: usize,
    /// IPv6: the next-header byte that names the header at `frag_at`.
    pub frag_nexthdr_at: usize,
    /// The fragment this packet is, if it is one.
    pub frag: Option<Frag>,
}

/// Parses Ethernet (with 802.1Q/802.1ad tags), IPv4 or IPv6 (with its
/// extension headers), up to the transport header.
pub fn parse(frame: &[u8]) -> Option<Packet> {
    let mut at = 12;
    loop {
        frame.get(at..at + 2)?;
        match be16(frame, at) {
            ETH_P_8021Q | ETH_P_8021AD => at += 4,
            _ => break,
        }
    }
    let ethertype = be16(frame, at);
    let l3 = at + 2;
    match ethertype {
        ETH_P_IP => {
            let ip = frame.get(l3..l3 + 20)?;
            let ihl = usize::from(ip[0] & 0xf) * 4;
            if ip[0] >> 4 != 4 || ihl < 20 || frame.len() < l3 + ihl {
                return None;
            }
            let field = be16(ip, 6);
            let offset = usize::from(field & 0x1fff) * 8;
            let more = field & IP_MF != 0;
            Some(Packet {
                l3,
                v6: false,
                l4: l3 + ihl,
                proto: ip[9],
                frag_at: l3 + ihl,
                frag_nexthdr_at: l3 + 9,
                frag: (offset != 0 || more).then_some(Frag {
                    offset,
                    more,
                    id: u32::from(be16(ip, 4)),
                }),
            })
        }
        ETH_P_IPV6 => {
            let ip = frame.get(l3..l3 + 40)?;
            if ip[0] >> 4 != 6 {
                return None;
            }
            let mut next = ip[6];
            let mut next_at = l3 + 6;
            let mut at = l3 + 40;
            let mut found_rhdr = false;
            let mut frag_at = None;
            let mut frag = None;
            loop {
                // ip6_find_1stfragopt: hop-by-hop and routing headers, and
                // destination options before a routing header, are not
                // fragmented.
                if frag_at.is_none() {
                    match next {
                        IPPROTO_HOPOPTS => {}
                        IPPROTO_ROUTING => found_rhdr = true,
                        IPPROTO_DSTOPTS if !found_rhdr => {}
                        _ => frag_at = Some((at, next_at)),
                    }
                }
                // The headers of a first fragment may go on past its end.
                let truncated = frag.is_some();
                let byte = |i: usize| match frame.get(i) {
                    Some(b) => Ok(usize::from(*b)),
                    None if truncated => Err(true),
                    None => Err(false),
                };
                let len = match next {
                    IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => match byte(at + 1) {
                        Ok(n) => (n + 1) * 8,
                        Err(true) => break,
                        Err(false) => return None,
                    },
                    IPPROTO_AH => match byte(at + 1) {
                        Ok(n) => (n + 2) * 4,
                        Err(true) => break,
                        Err(false) => return None,
                    },
                    IPPROTO_FRAGMENT => {
                        let Some(f) = frame.get(at..at + 8) else {
                            if truncated {
                                break;
                            }
                            return None;
                        };
                        let this = Frag {
                            offset: usize::from(be16(f, 2) & !7),
                            more: be16(f, 2) & 1 != 0,
                            id: be32(f, 4),
                        };
                        // The first fragment header is the packet's own.
                        frag.get_or_insert(this);
                        if this.offset != 0 {
                            // A later fragment: data follows, not headers
                            // (ipv6_skip_exthdr).
                            next = f[0];
                            at += 8;
                            break;
                        }
                        8
                    }
                    _ => break,
                };
                if frame.get(at..at + len).is_none() {
                    if truncated {
                        break;
                    }
                    return None;
                }
                next = frame[at];
                next_at = at;
                at += len;
            }
            let (frag_at, frag_nexthdr_at) = frag_at.unwrap_or((at, next_at));
            Some(Packet {
                l3,
                v6: true,
                l4: at,
                proto: next,
                frag_at,
                frag_nexthdr_at,
                frag,
            })
        }
        _ => None,
    }
}

/// The sum of the transport pseudo header (RFC 793, RFC 8200 8.1) for
/// `l4_len` bytes of transport data.
pub fn pseudo(frame: &[u8], p: &Packet, l4_len: usize) -> u64 {
    let addrs = if p.v6 {
        &frame[p.l3 + 8..p.l3 + 40]
    } else {
        &frame[p.l3 + 12..p.l3 + 20]
    };
    let addrs = u64::from(!checksum(addrs, 0));
    addrs + (l4_len as u64 >> 16) + (l4_len as u64 & 0xffff) + u64::from(p.proto)
}

/// Whether the transport checksum of `frame`, from its transport header to
/// its end, is correct.
pub fn l4_valid(frame: &[u8], p: &Packet) -> bool {
    checksum(&frame[p.l4..], pseudo(frame, p, frame.len() - p.l4)) == 0
}

/// Whether the IPv4 header checksum of `frame` is correct.
pub fn ipv4_valid(frame: &[u8], p: &Packet) -> bool {
    checksum(&frame[p.l3..p.l4], 0) == 0
}

/// Asserts that `a` and `b` are equal outside the byte ranges `skip`.
fn same_except(a: &[u8], b: &[u8], skip: &[std::ops::Range<usize>], what: &str) {
    assert_eq!(a.len(), b.len(), "{what}: length");
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    for r in skip {
        a[r.clone()].fill(0);
        b[r.clone()].fill(0);
    }
    if let Some(i) = (0..a.len()).find(|&i| a[i] != b[i]) {
        panic!("{what}: byte {i} changed");
    }
}

/// Checks what `vnet::segment(hdr, input, ..)` did: `result` is what it
/// returned and `out` the frames it sent. Panics if Linux would have sent
/// other frames, or if it accepted a frame Linux rejects in the same way.
pub fn check(hdr: &VnetHdr, input: &[u8], result: &io::Result<()>, out: &[Vec<u8>]) {
    let gso = hdr.gso_type & !GSO_ECN;
    if let Err(e) = result {
        assert_eq!(
            e.raw_os_error(),
            Some(libc::EINVAL),
            "error other than EINVAL: {e}"
        );
        return;
    }
    // The frame once its checksum is completed (skb_checksum_help), which
    // segmentation offloads do per segment instead.
    let mut whole = input.to_vec();
    if hdr.flags & F_NEEDS_CSUM != 0 {
        let start = usize::from(hdr.csum_start);
        let at = start + usize::from(hdr.csum_offset);
        assert!(
            at + 2 <= input.len(),
            "checksum field past the frame accepted"
        );
        if !matches!(gso, GSO_TCPV4 | GSO_TCPV6) {
            let csum = match checksum(&input[start..], 0) {
                0 => 0xffff,
                c => c,
            };
            whole[at..at + 2].copy_from_slice(&csum.to_be_bytes());
        }
    }
    // A guest has no reason to ask for segmentation of a frame that is an IP
    // fragment already; for those only the absence of a crash is checked.
    if gso != GSO_NONE && parse(&whole).is_some_and(|p| p.frag.is_some()) {
        return;
    }
    match gso {
        GSO_NONE => assert!(
            out.len() == 1 && out[0] == whole,
            "a frame without GSO not sent as it is, its checksum completed"
        ),
        GSO_TCPV4 | GSO_TCPV6 => {
            check_tso(&whole, usize::from(hdr.gso_size), gso == GSO_TCPV6, out)
        }
        GSO_UDP => check_ufo(&whole, usize::from(hdr.gso_size), out),
        _ => panic!("GSO type {gso} accepted"),
    }
}

fn check_tso(whole: &[u8], mss: usize, v6: bool, out: &[Vec<u8>]) {
    assert!(mss > 0, "TSO without a segment size accepted");
    let p = parse(whole).expect("a TSO frame that is not IP accepted");
    assert_eq!(p.v6, v6, "TSO of the other IP version accepted");
    assert_eq!(p.proto, IPPROTO_TCP, "TSO of protocol {} accepted", p.proto);
    let (l3, l4) = (p.l3, p.l4);
    assert!(whole.len() >= l4 + 20, "TSO without a TCP header accepted");
    let hdrs = l4 + usize::from(whole[l4 + 12] >> 4) * 4;
    assert!(
        hdrs >= l4 + 20 && hdrs <= whole.len(),
        "bad TCP data offset accepted"
    );
    let payload = &whole[hdrs..];
    let count = payload.len().div_ceil(mss).max(1);
    assert_eq!(out.len(), count, "segment count");
    let seq = be32(whole, l4 + 4);
    let flags = whole[l4 + 13];
    for (i, seg) in out.iter().enumerate() {
        let start = i * mss;
        let end = payload.len().min(start + mss);
        assert_eq!(seg.len(), hdrs + end - start, "segment {i} length");
        assert_eq!(&seg[hdrs..], &payload[start..end], "segment {i} payload");
        let sp = parse(seg).expect("a segment that is not IP");
        assert_eq!(
            (sp.l3, sp.l4, sp.proto),
            (l3, l4, IPPROTO_TCP),
            "segment {i} layers"
        );
        // Only the lengths, IPv4 ID, sequence number, flags and checksums change.
        let mut skip = vec![l4 + 4..l4 + 8, l4 + 13..l4 + 14, l4 + 16..l4 + 18];
        if v6 {
            skip.push(l3 + 4..l3 + 6);
            assert_eq!(
                usize::from(be16(seg, l3 + 4)),
                seg.len() - l3 - 40,
                "IPv6 length"
            );
        } else {
            skip.extend([l3 + 2..l3 + 6, l3 + 10..l3 + 12]);
            assert_eq!(
                usize::from(be16(seg, l3 + 2)),
                seg.len() - l3,
                "IPv4 length"
            );
            let id = be16(whole, l3 + 4).wrapping_add(i as u16);
            assert_eq!(be16(seg, l3 + 4), id, "IPv4 ID of segment {i}");
            assert!(ipv4_valid(seg, &sp), "IPv4 checksum of segment {i}");
        }
        same_except(&seg[..hdrs], &whole[..hdrs], &skip, "segment headers");
        assert_eq!(
            be32(seg, l4 + 4),
            seq.wrapping_add(start as u32),
            "sequence number"
        );
        let mut f = flags;
        if i + 1 < count {
            f &= !(TCP_FIN | TCP_PSH);
        }
        if i > 0 {
            f &= !TCP_CWR;
        }
        assert_eq!(seg[l4 + 13], f, "flags of segment {i}");
        assert!(l4_valid(seg, &sp), "TCP checksum of segment {i}");
    }
}

fn check_ufo(whole: &[u8], mss: usize, out: &[Vec<u8>]) {
    assert!(mss > 0, "UFO without a fragment size accepted");
    let p = parse(whole).expect("a UFO frame that is not IP accepted");
    assert_eq!(p.proto, IPPROTO_UDP, "UFO of protocol {} accepted", p.proto);
    let (l3, head) = (p.l3, p.frag_at);
    let data = &whole[head..];
    if data.len() <= mss {
        assert!(
            out.len() == 1 && out[0] == whole,
            "a datagram that fits not sent as it is"
        );
        return;
    }
    let step = mss & !7;
    assert!(step > 0, "UFO with fragments under 8 bytes accepted");
    assert_eq!(out.len(), data.len().div_ceil(step), "fragment count");
    let mut id = None;
    for (i, f) in out.iter().enumerate() {
        let start = i * step;
        let end = data.len().min(start + step);
        let more = end < data.len();
        let at = if p.v6 { head + 8 } else { head };
        assert_eq!(f.len(), at + end - start, "fragment {i} length");
        assert_eq!(&f[at..], &data[start..end], "fragment {i} data");
        let fp = parse(f).expect("a fragment that is not IP");
        let frag = fp.frag.expect("a fragment without fragment fields");
        assert_eq!(
            (frag.offset, frag.more),
            (start, more),
            "fragment {i} offset"
        );
        assert_eq!(*id.get_or_insert(frag.id), frag.id, "fragment {i} ID");
        if p.v6 {
            // The fragment header goes where ip6_find_1stfragopt says.
            assert_eq!(
                f[p.frag_nexthdr_at], IPPROTO_FRAGMENT,
                "fragment header not named"
            );
            assert_eq!(
                f[head], whole[p.frag_nexthdr_at],
                "fragment header's next header"
            );
            assert_eq!(f[head + 1], 0, "fragment header reserved byte");
            assert_eq!(
                usize::from(be16(f, l3 + 4)),
                f.len() - l3 - 40,
                "IPv6 length"
            );
            let skip = [l3 + 4..l3 + 6, p.frag_nexthdr_at..p.frag_nexthdr_at + 1];
            same_except(&f[..head], &whole[..head], &skip, "fragment headers");
        } else {
            assert_eq!(usize::from(be16(f, l3 + 2)), f.len() - l3, "IPv4 length");
            assert_eq!(frag.id, u32::from(be16(whole, l3 + 4)), "IPv4 ID changed");
            assert!(ipv4_valid(f, &fp), "IPv4 checksum of fragment {i}");
            let skip = [l3 + 2..l3 + 4, l3 + 6..l3 + 8, l3 + 10..l3 + 12];
            same_except(&f[..head], &whole[..head], &skip, "fragment headers");
        }
    }
}
