// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `vnet::segment` on any bytes a guest can write to its virtio-net TX
//! queue: a virtio-net header and a frame of up to the device's maximum.
//! The frames sent must be those Linux's TUN driver would send
//! ([`wick_fuzz::frame::check`]), and `vnet::tx_offload` must refuse the
//! frame exactly when a TAP refuses it ([`wick_fuzz::frame::tap_accepts`]).

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
});
