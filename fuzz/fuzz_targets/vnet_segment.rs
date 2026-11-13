// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `vnet::segment` on any bytes a guest can write to its virtio-net TX
//! queue: a virtio-net header and a frame of up to the device's maximum.
//! The frames sent must be those Linux's TUN driver would send
//! ([`wick_fuzz::frame::check`]), and `vnet::tx_offload` must refuse the
//! frame exactly when a TAP refuses it ([`wick_fuzz::frame::tap_accepts`]).
//! The same bytes as a frame a backend delivers, with the header's fields
//! read as the backend's checksum flag, the link's MTU, the device's
//! offloads and whether the source is the host's: `vnet::rx_offload` gives
//! the guest a header Linux's `virtio_net_hdr_to_skb` takes, changes no
//! byte but the checksum field it names, drops only frames over the MTU,
//! and asks to segment only TCP superframes that `vnet::rx_segment` splits
//! into packets of at most the MTU.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wick_fuzz::frame::{self, MAX_FRAME};
use wick_fuzz::vnet::{self, VnetHdr};

fuzz_target!(|data: &[u8]| {
    let Some(hdr) = VnetHdr::parse(data) else {
        return;
    };
    let input = &data[vnet::MIN_HDR_LEN..];
    // The tap refuses frames shorter than an Ethernet header, and the device
    // longer ones than it can hold.
    if input.len() < 14 || input.len() > MAX_FRAME {
        return;
    }
    // What a backend that takes the header is given: refused exactly when a
    // TAP refuses the write, and handed over only as a TCP superframe the
    // backend can complete.
    let tx = vnet::tx_offload(&hdr, input);
    assert_eq!(
        tx.is_ok(),
        frame::tap_accepts(&hdr, input),
        "{hdr:?} {tx:?}"
    );
    if let Ok(vnet::Tx::Offload) = tx {
        let p = frame::parse(input).expect("an offloaded frame parses");
        assert_eq!(p.proto, frame::IPPROTO_TCP);
        assert_eq!(usize::from(hdr.csum_start), p.l4);
        assert_eq!(hdr.csum_offset, 16);
        assert_eq!(hdr.flags & vnet::F_NEEDS_CSUM, vnet::F_NEEDS_CSUM);
        let gso = if p.v6 {
            vnet::GSO_TCPV6
        } else {
            vnet::GSO_TCPV4
        };
        assert_eq!(hdr.gso_type, gso);
        assert!(input.len() - p.l4 - 20 > usize::from(hdr.gso_size));
    }
    let mut buf = input.to_vec();
    let mut out = Vec::new();
    let result = vnet::segment(&hdr, &mut buf, &mut Vec::new(), &mut |seg| {
        out.push(seg.to_vec());
        Ok(())
    });
    frame::check(&hdr, input, &result, &out);

    rx(&hdr, input);
});

fn rx(hdr: &VnetHdr, input: &[u8]) {
    let data_valid = hdr.flags & 2 != 0;
    let mtu = 68 + usize::from(hdr.gso_size) % 9000;
    let offloads = u32::from(hdr.gso_type & 0x0f);
    let from_host = hdr.csum_offset & 1 != 0;
    if vnet::check_offload(offloads).is_err() {
        return;
    }
    let mut out = input.to_vec();
    match vnet::rx_offload(&mut out, data_valid, mtu, offloads, &|_| from_host) {
        vnet::Rx::Frame(h) => {
            if h == VnetHdr::default() {
                if !data_valid {
                    assert_eq!(out, input, "a frame with no flags is changed");
                }
                let changed: Vec<usize> = (0..out.len()).filter(|&i| out[i] != input[i]).collect();
                if let (Some(first), Some(last)) = (changed.first(), changed.last()) {
                    let p = frame::parse(input).expect("a changed frame parses");
                    assert!(
                        *first >= p.l4 && *last < p.l4 + 18,
                        "bytes {changed:?} changed"
                    );
                }
                return;
            }
            assert!(frame::tap_accepts(&h, &out), "{h:?} is refused by Linux");
            assert_eq!(h.flags, vnet::F_NEEDS_CSUM, "{h:?}");
            let at = usize::from(h.csum_start) + usize::from(h.csum_offset);
            for i in 0..out.len() {
                assert!(
                    out[i] == input[i] || i == at || i == at + 1,
                    "byte {i} changed"
                );
            }
            let p = frame::parse(input).expect("a NEEDS_CSUM frame parses");
            assert_eq!(usize::from(h.csum_start), p.l4);
            if h.gso_type != vnet::GSO_NONE {
                assert_eq!(p.proto, frame::IPPROTO_TCP);
                assert!(input.len() - p.l3 > mtu);
            }
        }
        vnet::Rx::Drop => {
            let l3 = frame::parse(input).map_or(14, |p| p.l3);
            assert!(input.len() > l3 + mtu, "a frame within the MTU is dropped");
        }
        vnet::Rx::Segment => {
            let p = frame::parse(input).expect("a superframe parses");
            assert_eq!(p.proto, frame::IPPROTO_TCP);
            let mut n = 0;
            vnet::rx_segment(&out, mtu, offloads, &mut Vec::new(), &mut |_, seg| {
                assert!(seg.len() - p.l3 <= mtu, "a segment of {} bytes", seg.len());
                n += 1;
                Ok(())
            })
            .expect("a superframe is segmented");
            assert!(n > 1);
        }
    }
}
