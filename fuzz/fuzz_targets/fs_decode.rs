// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `wick_fsd::fuse`, the FUSE decoder and guest names of wick-fsd
//! (docs/design-fs.md rows 1 and 6), on any request bytes a guest's chain
//! can hold: whole payloads as they come, and requests built around any
//! opcode and arguments with a right or wrong `len` and any `total_extlen`,
//! so the arguments' own checks are reached.
//!
//! Decoding must never panic. An accepted request must keep every rule the
//! decoder states: its header's `len` is the payload's; each name in it is
//! a `Name` (one component, none of the refused escape images); a write's
//! data is its size and at most `MAX_WRITE`; a batch forget's records are
//! its count; a symlink target or attribute name within its bound;
//! extensions only when negotiated, only on a creating opcode, and a chain
//! that tiles them exactly. A refusal has a header exactly when the payload
//! is at least one header long, and gives one of the errnos the decoder
//! documents.
//!
//! The escape mapping (`escape`/`unescape`) must round-trip in both
//! directions on any name and any host string.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wick_fsd::fuse::decode::{Op, Wire, decode};
use wick_fsd::fuse::name::{Name, escape, unescape};
use wick_fsd::fuse::{Errno, IN_HEADER_LEN, MAX_WRITE, PATH_MAX, XATTR_NAME_MAX, XATTR_SIZE_MAX};

#[derive(Arbitrary, Debug)]
struct Input {
    setxattr_ext: bool,
    extensions: bool,
    /// Taken as a whole payload.
    raw: Vec<u8>,
    /// A request built from parts.
    opcode: u16,
    total_extlen: u16,
    len_delta: i8,
    args: Vec<u8>,
    /// Any string, for the escape mapping.
    host: String,
}

fn built(input: &Input) -> Vec<u8> {
    let mut out = vec![0u8; IN_HEADER_LEN];
    let len = (IN_HEADER_LEN + input.args.len()) as i64 + i64::from(input.len_delta);
    out[0..4].copy_from_slice(&(len as u32).to_le_bytes());
    // Mostly the opcodes FUSE has (1..=53), sometimes any.
    let opcode = if input.opcode < 0xF000 {
        u32::from(input.opcode % 54)
    } else {
        u32::from(input.opcode)
    };
    out[4..8].copy_from_slice(&opcode.to_le_bytes());
    out[8..16].copy_from_slice(&1u64.to_le_bytes());
    out[36..38].copy_from_slice(&input.total_extlen.to_le_bytes());
    out.extend_from_slice(&input.args);
    out
}

fn check_name(name: &Name<'_>) {
    assert_eq!(Name::new(name.as_bytes()).ok().as_ref(), Some(name));
}

fn check(payload: &[u8], wire: &Wire) {
    match decode(payload, wire) {
        Ok(r) => {
            assert_eq!(r.header.len as usize, payload.len());
            let ext_len = usize::from(r.header.total_extlen) * 8;
            if ext_len == 0 {
                assert!(r.extensions.is_empty());
            } else {
                assert!(wire.extensions);
                assert!(matches!(
                    r.op,
                    Op::Create { .. } | Op::Mknod { .. } | Op::Mkdir { .. } | Op::Symlink { .. }
                ));
                let tiled: usize = r.extensions.iter().map(|(_, body)| 8 + body.len()).sum();
                assert_eq!(tiled, ext_len);
            }
            match r.op {
                Op::Lookup { name }
                | Op::Unlink { name }
                | Op::Rmdir { name }
                | Op::Mknod { name, .. }
                | Op::Mkdir { name, .. }
                | Op::Link { name, .. }
                | Op::Create { name, .. } => check_name(&name),
                Op::Rename { old, new, .. } => {
                    check_name(&old);
                    check_name(&new);
                }
                Op::Symlink { name, target } => {
                    check_name(&name);
                    assert!(!target.is_empty() && target.len() < PATH_MAX);
                    assert!(!target.contains(&0));
                }
                Op::Write { arg, data } => {
                    assert!(arg.size <= MAX_WRITE);
                    assert_eq!(arg.size as usize, data.len());
                }
                Op::BatchForget(forgets) => {
                    assert_eq!(forgets.iter().count(), forgets.len());
                    assert_eq!(
                        IN_HEADER_LEN + 8 + forgets.len() * 16 + ext_len,
                        payload.len()
                    );
                }
                Op::Setxattr { name, value, .. } => {
                    assert!(!name.as_bytes().is_empty() && name.as_bytes().len() <= XATTR_NAME_MAX);
                    assert!(!name.as_bytes().contains(&0));
                    assert!(value.len() <= XATTR_SIZE_MAX);
                }
                Op::Getxattr { name, .. } | Op::Removexattr { name } => {
                    assert!(!name.as_bytes().is_empty() && name.as_bytes().len() <= XATTR_NAME_MAX);
                    assert!(!name.as_bytes().contains(&0));
                }
                _ => {}
            }
        }
        Err(refused) => {
            assert_eq!(refused.header.is_some(), payload.len() >= IN_HEADER_LEN);
            let errno = refused.error.errno();
            assert!(
                [
                    Errno::ENOSYS,
                    Errno::EINVAL,
                    Errno::ENAMETOOLONG,
                    Errno::EILSEQ,
                    Errno::E2BIG
                ]
                .contains(&errno),
                "{errno:?}"
            );
        }
    }
}

fn check_escape(bytes: &[u8], host: &str) {
    if let Ok(name) = Name::new(bytes) {
        let escaped = escape(name);
        assert_eq!(unescape(&escaped).as_deref(), Ok(name.as_str()));
    }
    if let Ok(guest) = unescape(host) {
        let name = Name::new(guest.as_bytes()).expect("unescape gave a name");
        assert_eq!(escape(name), host);
    }
}

fuzz_target!(|input: Input| {
    let wire = Wire {
        setxattr_ext: input.setxattr_ext,
        extensions: input.extensions,
    };
    check(&input.raw, &wire);
    check(&built(&input), &wire);
    check_escape(&input.args, &input.host);
});
