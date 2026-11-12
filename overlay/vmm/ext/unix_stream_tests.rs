// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! How much an AF_UNIX stream made by Rust's std takes before a write would
//! block, against a peer that never reads: the sender's send buffer on both
//! kernels (Linux net/unix/af_unix.c unix_stream_sendmsg against
//! `sk_sndbuf`; xnu bsd/kern/uipc_usrreq.c uipc_send against
//! `so_snd.sb_hiwat`), which every socket starts at Linux's
//! `net.core.wmem_default` (the compatibility libc's `socket` and
//! `socketpair` on macOS).
#![cfg(test)]

use std::io::{ErrorKind, Write};
use std::os::unix::net::{UnixListener, UnixStream};

/// At least what Linux takes from 64 KiB writes: the first skb is always
/// allocated (sock_alloc_send_pskb waits only once `sk_wmem_alloc` reaches
/// `sk_sndbuf`, 0 at first) and carries min(64 KiB, sk_sndbuf / 2 - 64)
/// bytes, all of the write at the default 212992 (unix_stream_sendmsg).
const FLOOR: usize = 64 << 10;

/// Bytes written to `w` before a write would block.
fn taken(mut w: &UnixStream) -> usize {
    w.set_nonblocking(true).unwrap();
    let chunk = vec![0u8; 64 << 10];
    let mut n = 0;
    loop {
        match w.write(&chunk) {
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return n,
            Err(e) => panic!("write: {e}"),
        }
    }
}

#[test]
fn test_a_unix_stream_takes_linuxs_default_before_it_blocks() {
    let (a, _peer_a) = UnixStream::pair().unwrap();
    let pair = taken(&a);
    let dir = std::env::temp_dir().join(format!("wick-us-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let connected = UnixStream::connect(&path).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let (by_connect, by_accept) = (taken(&connected), taken(&accepted));
    std::fs::remove_dir_all(&dir).unwrap();
    println!("taken before blocking: pair {pair}, connected {by_connect}, accepted {by_accept}");
    for (what, n) in [("socketpair", pair), ("connect", by_connect), ("accept", by_accept)] {
        assert!(n >= FLOOR, "{what}: {n} bytes before blocking, under {FLOOR}");
    }
    #[cfg(target_os = "macos")]
    for s in [&a, &connected, &accepted] {
        let mut v: libc::c_int = 0;
        let mut l: libc::socklen_t = 4; // sizeof(int)
        // SAFETY: an int option into `v`.
        let r = unsafe {
            libc::getsockopt(
                std::os::unix::io::AsRawFd::as_raw_fd(s),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw mut v).cast(),
                &mut l,
            )
        };
        assert_eq!(r, 0);
        assert_eq!(v, libc::LINUX_WMEM_DEFAULT, "SO_SNDBUF read back");
    }
}
