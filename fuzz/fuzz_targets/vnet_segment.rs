// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `vnet::segment` on any bytes a guest can write to its virtio-net TX
//! queue: a virtio-net header and a frame of up to the device's maximum.
//! The frames sent must be those Linux's TUN driver would send
//! ([`wick_fuzz::frame::check`]).

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
    let mut buf = input.to_vec();
    let mut out = Vec::new();
    let result = vnet::segment(&hdr, &mut buf, &mut Vec::new(), &mut |seg| {
        out.push(seg.to_vec());
        Ok(())
    });
    frame::check(&hdr, input, &result, &out);
});
