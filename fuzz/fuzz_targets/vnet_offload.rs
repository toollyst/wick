// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `vnet::segment` on the frames a guest's offloads produce: well-formed
//! Ethernet (with VLAN tags), IPv4 (with options) or IPv6 (with extension
//! headers), TCP (with options) or UDP, with a virtio-net header asking for
//! checksum completion, TSO or UFO the way Linux's virtio-net driver does.
//! Every such frame must be accepted, the frames sent must be those Linux
//! would send ([`wick_fuzz::frame::check`]), and their checksums must
//! verify: each TCP segment's, and the UDP checksum of the datagram the
//! fragments reassemble to. `vnet::tx_offload` takes every such frame and
//! hands over exactly the TCP superframes without ECN.
//!
//! The same frame, its checksum complete (or one payload byte off), as a
//! backend that coalesces TCP delivers it: `vnet::rx_offload` gives the
//! guest what a TAP gives it, by an expectation written here from Linux's
//! rules (`tcp_gro_complete`, `virtio_net_hdr_from_skb`, the host's own
//! `CHECKSUM_PARTIAL` sends): a GSO frame for a TCP superframe the offloads
//! take, `NEEDS_CSUM` for the host's own frames, the frame as it came
//! otherwise, segments of the MTU for a superframe the offloads do not
//! take, and nothing for what a TAP is never given.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fuzz::frame::{self, MAX_FRAME, checksum, parse, pseudo};
use wick_fuzz::vnet::{self, VnetHdr};

#[derive(Arbitrary, Debug)]
enum Ext {
    HopByHop(u8),
    Routing(u8),
    DestOpts(u8),
}

#[derive(Arbitrary, Debug)]
enum Ip {
    V4 {
        id: u16,
        flags_ttl: [u8; 3],
        /// 32-bit words of options (at most 10).
        options: u8,
        addrs: [u8; 8],
    },
    V6 {
        exts: Vec<Ext>,
        addrs: [u8; 32],
    },
}

#[derive(Arbitrary, Debug)]
enum L4 {
    Tcp {
        ports: [u8; 4],
        seq: u32,
        ack: u32,
        flags: u8,
        /// 32-bit words of options (at most 10).
        options: u8,
        window: u16,
    },
    Udp {
        ports: [u8; 4],
    },
}

#[derive(Arbitrary, Debug)]
enum Offload {
    /// Checksum offload only.
    Csum,
    /// TSO or UFO, with this segment size.
    Gso { size: u16, ecn: bool },
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// 802.1Q (false) or 802.1ad (true) tags, at most two.
    vlans: Vec<(bool, u16)>,
    ip: Ip,
    l4: L4,
    /// Payload bytes, shifted right by `shift % 8` (at most what a frame
    /// holds): an eighth of the runs have frames of up to 64 KiB, which are
    /// the slow ones.
    payload: u16,
    shift: u8,
    seed: u8,
    offload: Offload,
    rx: RxCase,
}

#[derive(Arbitrary, Debug)]
struct RxCase {
    /// The link's MTU, from 68.
    mtu: u16,
    data_valid: bool,
    /// `TUN_F_*` bits (the low four).
    offloads: u8,
    from_host: bool,
    /// One byte of the payload (or of the checksum) is flipped.
    corrupt: bool,
}

/// Builds the frame and returns it with the offset of its transport header.
fn build(input: &Input) -> Option<(Vec<u8>, usize)> {
    let mut f = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
    for (ad, tci) in input.vlans.iter().take(2) {
        let tpid = if *ad {
            frame::ETH_P_8021AD
        } else {
            frame::ETH_P_8021Q
        };
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&tci.to_be_bytes());
    }
    let (proto, l4_hdr) = match &input.l4 {
        L4::Tcp {
            ports,
            seq,
            ack,
            flags,
            options,
            window,
        } => {
            let words = usize::from(*options % 11);
            let mut t = ports.to_vec();
            t.extend_from_slice(&seq.to_be_bytes());
            t.extend_from_slice(&ack.to_be_bytes());
            t.push(((5 + words) as u8) << 4);
            t.push(*flags);
            t.extend_from_slice(&window.to_be_bytes());
            t.extend_from_slice(&[0, 0, 0, 0]);
            // NOP options.
            t.resize(20 + 4 * words, 1);
            (frame::IPPROTO_TCP, t)
        }
        L4::Udp { ports } => {
            let mut u = ports.to_vec();
            u.extend_from_slice(&[0, 0, 0, 0]);
            (frame::IPPROTO_UDP, u)
        }
    };
    let ip_start = f.len() + 2;
    let ip_hdr_len = match &input.ip {
        Ip::V4 {
            id,
            flags_ttl,
            options,
            addrs,
        } => {
            let words = usize::from(*options % 11);
            f.extend_from_slice(&frame::ETH_P_IP.to_be_bytes());
            f.push(0x45 + words as u8);
            f.push(0);
            f.extend_from_slice(&[0, 0]);
            f.extend_from_slice(&id.to_be_bytes());
            // DF and the reserved bit may be set; a GSO frame is not a fragment.
            f.extend_from_slice(&[flags_ttl[0] & 0xc0, 0, flags_ttl[1], proto, 0, 0]);
            f.extend_from_slice(addrs);
            // End-of-options list.
            f.resize(f.len() + 4 * words, 0);
            20 + 4 * words
        }
        Ip::V6 { exts, addrs } => {
            f.extend_from_slice(&frame::ETH_P_IPV6.to_be_bytes());
            f.extend_from_slice(&[0x60, 0, 0, 0, 0, 0]);
            let exts = &exts[..exts.len().min(4)];
            let code = |e: &Ext| match e {
                Ext::HopByHop(_) => frame::IPPROTO_HOPOPTS,
                Ext::Routing(_) => frame::IPPROTO_ROUTING,
                Ext::DestOpts(_) => frame::IPPROTO_DSTOPTS,
            };
            f.push(exts.first().map_or(proto, code));
            f.push(64);
            f.extend_from_slice(addrs);
            for (i, e) in exts.iter().enumerate() {
                let (Ext::HopByHop(n) | Ext::Routing(n) | Ext::DestOpts(n)) = e;
                let units = usize::from(*n % 4);
                let next = exts.get(i + 1).map_or(proto, code);
                let start = f.len();
                f.push(next);
                f.push(units as u8);
                // PadN over the rest.
                f.resize(start + 8 * (units + 1), 0);
                f[start + 2] = 1;
                f[start + 3] = (8 * (units + 1) - 4) as u8;
            }
            f.len() - ip_start
        }
    };
    let l4 = f.len();
    f.extend_from_slice(&l4_hdr);
    let room = MAX_FRAME.min(ip_start + 0xffff) - f.len();
    let payload = usize::from(input.payload >> (input.shift % 8)).min(room);
    f.extend((0..payload).map(|i| (i as u8).wrapping_mul(input.seed | 1)));
    // Lengths.
    let ip_len = f.len() - ip_start;
    if let Ip::V4 { .. } = input.ip {
        f[ip_start + 2..ip_start + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        let csum = checksum(&f[ip_start..ip_start + ip_hdr_len], 0);
        f[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());
    } else {
        let len = u16::try_from(ip_len - 40).ok()?;
        f[ip_start + 4..ip_start + 6].copy_from_slice(&len.to_be_bytes());
    }
    if proto == frame::IPPROTO_UDP {
        let len = u16::try_from(f.len() - l4).ok()?;
        f[l4 + 4..l4 + 6].copy_from_slice(&len.to_be_bytes());
    }
    Some((f, l4))
}

fuzz_target!(|input: Input| {
    let Some((mut f, l4)) = build(&input) else {
        return;
    };
    let p = parse(&f).expect("built frame parses");
    assert_eq!(p.l4, l4);
    let tcp = p.proto == frame::IPPROTO_TCP;
    let csum_offset: usize = if tcp { 16 } else { 6 };
    // What the guest's stack leaves for checksum offload: the folded sum of
    // the pseudo header in the checksum field.
    let seed = !checksum(&[], pseudo(&f, &p, f.len() - l4));
    f[l4 + csum_offset..l4 + csum_offset + 2].copy_from_slice(&seed.to_be_bytes());
    let mut hdr = VnetHdr {
        flags: vnet::F_NEEDS_CSUM,
        csum_start: l4 as u16,
        csum_offset: csum_offset as u16,
        ..Default::default()
    };
    let gso = match input.offload {
        Offload::Csum => None,
        Offload::Gso { size, ecn } => {
            hdr.gso_type = match (tcp, p.v6) {
                (true, false) => vnet::GSO_TCPV4,
                (true, true) => vnet::GSO_TCPV6,
                (false, _) => vnet::GSO_UDP,
            } | if ecn { vnet::GSO_ECN } else { 0 };
            // Linux's UFO needs room for 8 bytes in a fragment.
            hdr.gso_size = if tcp { size.max(1) } else { size.max(8) };
            hdr.hdr_len = (l4 + if tcp { 20 } else { 8 }) as u16;
            Some(usize::from(hdr.gso_size))
        }
    };
    // A backend that takes the header is handed the TCP superframes, with no
    // ECN bit, that are GSO for Linux; the rest is segmented.
    let tx = vnet::tx_offload(&hdr, &f).unwrap_or_else(|e| panic!("{hdr:?} refused: {e}"));
    let expect = match input.offload {
        Offload::Gso { ecn, .. }
            if tcp && !ecn && f.len() - l4 - 20 > usize::from(hdr.gso_size) =>
        {
            vnet::Tx::Offload
        }
        _ => vnet::Tx::Segment,
    };
    assert_eq!(tx, expect, "{hdr:?}");
    rx(&input, &f, &p);
    let input_frame = f.clone();
    let mut out = Vec::new();
    let result = vnet::segment(&hdr, &mut f, &mut Vec::new(), &mut |seg| {
        out.push(seg.to_vec());
        Ok(())
    });
    if let Err(e) = &result {
        panic!(
            "{gso:?} {:?} frame of {} bytes refused: {e}",
            p,
            input_frame.len()
        );
    }
    frame::check(&hdr, &input_frame, &result, &out);

    // The checksums verify.
    if tcp {
        for seg in &out {
            assert!(frame::l4_valid(seg, &parse(seg).unwrap()), "TCP checksum");
        }
        return;
    }
    // The UDP datagram the fragments reassemble to has a correct checksum.
    let mut datagram = out[0][..p.frag_at].to_vec();
    datagram[p.frag_nexthdr_at] = input_frame[p.frag_nexthdr_at];
    for frag in &out {
        let fp = parse(frag).unwrap();
        let at = if fp.v6 && fp.frag.is_some() {
            fp.frag_at + 8
        } else {
            fp.frag_at
        };
        datagram.extend_from_slice(&frag[at..]);
    }
    assert_eq!(datagram.len(), input_frame.len(), "reassembled length");
    assert!(
        frame::l4_valid(&datagram, &p),
        "UDP checksum of the datagram"
    );
});

/// Checks `vnet::rx_offload` and `vnet::rx_segment` on `f` (whose checksum
/// field holds the seed) as a frame a backend delivers.
fn rx(input: &Input, f: &[u8], p: &frame::Packet) {
    let case = &input.rx;
    let offloads = u32::from(case.offloads & 0x0f);
    if vnet::check_offload(offloads).is_err() {
        return;
    }
    let tcp = p.proto == frame::IPPROTO_TCP;
    let csum_at = p.l4 + if tcp { 16 } else { 6 };
    let thl = if tcp {
        usize::from(f[p.l4 + 12] >> 4) * 4
    } else {
        8
    };
    // The frame as sent: its checksum complete (RFC 768: 0xffff for a UDP
    // checksum of 0).
    let mut sent = f.to_vec();
    let seed = u16::from_be_bytes([f[csum_at], f[csum_at + 1]]);
    sent[csum_at..csum_at + 2].copy_from_slice(&[0, 0]);
    let mut c = checksum(&sent[p.l4..], pseudo(&sent, p, sent.len() - p.l4));
    if c == 0 && !tcp {
        c = 0xffff;
    }
    sent[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());
    assert!(frame::l4_valid(&sent, p));
    let mut delivered = sent.clone();
    if case.corrupt {
        let at = if sent.len() > p.l4 + thl {
            sent.len() - 1
        } else {
            csum_at
        };
        delivered[at] ^= 0x40;
    }
    let mtu = 68 + usize::from(case.mtu) % 9000;
    let ip_len = f.len() - p.l3;
    let src = if p.v6 {
        &f[p.l3 + 8..p.l3 + 24]
    } else {
        &f[p.l3 + 12..p.l3 + 16]
    };
    let host: std::net::IpAddr = if p.v6 {
        <[u8; 16]>::try_from(src).unwrap().into()
    } else {
        <[u8; 4]>::try_from(src).unwrap().into()
    };
    let from_host = |a: std::net::IpAddr| case.from_host && a == host;
    let csum = offloads & vnet::TUN_F_CSUM != 0;
    let valid = case.data_valid || !case.corrupt;

    let mut out = delivered.clone();
    let got = vnet::rx_offload(&mut out, case.data_valid, mtu, offloads, &from_host);
    let partial_of = |frame: &[u8]| {
        let mut x = frame.to_vec();
        x[csum_at..csum_at + 2].copy_from_slice(&seed.to_be_bytes());
        x
    };
    if ip_len > mtu {
        let hdrs = p.l4 - p.l3 + thl;
        if !tcp || mtu <= hdrs || !valid {
            assert_eq!(got, vnet::Rx::Drop, "{case:?}");
            return;
        }
        let mss = mtu - hdrs;
        let cwr = f[p.l4 + 13] & frame::TCP_CWR != 0;
        let tso = if p.v6 {
            vnet::TUN_F_TSO6
        } else {
            vnet::TUN_F_TSO4
        };
        if csum && offloads & tso != 0 && (!cwr || offloads & vnet::TUN_F_TSO_ECN != 0) {
            let want = VnetHdr {
                flags: vnet::F_NEEDS_CSUM,
                gso_type: if p.v6 {
                    vnet::GSO_TCPV6
                } else {
                    vnet::GSO_TCPV4
                } | if cwr { vnet::GSO_ECN } else { 0 },
                hdr_len: (p.l4 + thl) as u16,
                gso_size: mss as u16,
                csum_start: p.l4 as u16,
                csum_offset: 16,
            };
            assert_eq!(got, vnet::Rx::Frame(want), "{case:?}");
            assert_eq!(
                out,
                partial_of(&delivered),
                "the seed in the checksum field"
            );
            assert!(frame::tap_accepts(&want, &out));
            return;
        }
        assert_eq!(got, vnet::Rx::Segment, "{case:?}");
        let mut data = Vec::new();
        let mut segs = 0;
        vnet::rx_segment(&out, mtu, offloads, &mut Vec::new(), &mut |h, seg| {
            segs += 1;
            let sp = parse(seg).unwrap();
            assert!(seg.len() - sp.l3 <= mtu);
            assert!(seg.len() - sp.l4 - thl <= mss);
            let mut seg = seg.to_vec();
            if csum {
                assert_eq!(h.flags, vnet::F_NEEDS_CSUM);
                assert_eq!(usize::from(h.csum_start), p.l4);
                assert_eq!(h.csum_offset, 16);
                assert!(frame::tap_accepts(h, &seg));
                // The seed, which the guest completes as skb_checksum_help does.
                let field = u16::from_be_bytes([seg[csum_at], seg[csum_at + 1]]);
                assert_eq!(field, !checksum(&[], pseudo(&seg, &sp, seg.len() - sp.l4)));
                seg[csum_at..csum_at + 2].copy_from_slice(&[0, 0]);
                let c = checksum(&seg[sp.l4..], pseudo(&seg, &sp, seg.len() - sp.l4));
                seg[csum_at..csum_at + 2].copy_from_slice(&c.to_be_bytes());
            } else {
                assert_eq!(*h, VnetHdr::default());
            }
            assert!(frame::l4_valid(&seg, &sp), "segment checksum");
            data.extend_from_slice(&seg[sp.l4 + thl..]);
            Ok(())
        })
        .unwrap();
        assert_eq!(segs, (f.len() - p.l4 - thl).div_ceil(mss));
        assert_eq!(data, delivered[p.l4 + thl..]);
        return;
    }
    let none = vnet::Rx::Frame(VnetHdr::default());
    // A UDP datagram over IPv4 whose checksum field the corruption made 0:
    // one sent without a checksum.
    let udp4_none = !tcp && !p.v6 && delivered[csum_at..csum_at + 2] == [0, 0];
    if udp4_none {
        assert_eq!(got, none, "{case:?}");
        assert_eq!(out, delivered);
    } else if csum && case.from_host && valid {
        let want = VnetHdr {
            flags: vnet::F_NEEDS_CSUM,
            csum_start: p.l4 as u16,
            csum_offset: (csum_at - p.l4) as u16,
            ..Default::default()
        };
        assert_eq!(got, vnet::Rx::Frame(want), "{case:?}");
        assert_eq!(out, partial_of(&delivered));
        assert!(frame::tap_accepts(&want, &out));
    } else if case.data_valid {
        assert_eq!(got, none, "{case:?}");
        assert!(frame::l4_valid(&out, p), "checksum completed");
        let mut back = out.clone();
        back[csum_at..csum_at + 2].copy_from_slice(&delivered[csum_at..csum_at + 2]);
        assert_eq!(back, delivered, "only the checksum changed");
    } else {
        assert_eq!(got, none, "{case:?}");
        assert_eq!(out, delivered);
    }
}
