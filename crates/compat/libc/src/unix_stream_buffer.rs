// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! AF_UNIX stream sockets with Linux's send buffer.
//!
//! A stream's sender can queue as much as its own send buffer before a
//! write blocks, on both kernels: Linux's unix_stream_sendmsg allocates
//! each skb against the sender's `sk_sndbuf` (net/unix/af_unix.c;
//! sock_alloc_send_pskb waits while `sk_wmem_alloc` is at it), and xnu's
//! uipc_send charges what sits in the peer's receive queue to the sender's
//! `so_snd.sb_hiwat` (bsd/kern/uipc_usrreq.c). Linux starts every socket at
//! `net.core.wmem_default` (sock_init_data), 212992 bytes unless an
//! administrator changed it (SK_WMEM_MAX, include/net/sock.h); xnu starts an
//! AF_UNIX stream at 8192 (PIPSIZ, `net.local.stream.sendspace`).
//! Measured on macOS 27.2 against a peer that never reads: 8192 bytes
//! before EAGAIN by default, 212992 with the sender's SO_SNDBUF at 212992,
//! 8192 with only the peer's SO_RCVBUF raised, for a socket pair and an
//! accepted and a connected socket alike
//! (`test_a_unix_stream_takes_linuxs_default_before_it_blocks`). With 8 KiB a
//! vsock connection whose host reader lags pushes the guest's data into
//! Firecracker's 64 KiB per-connection TX buffer (vsock csm/txbuf.rs), where
//! Linux's kernel queue takes it: in `test_vsock_epipe` 50 such buffers were
//! live at once, and the VMM's own memory peaked at 8.3 MiB (median of 10
//! microVMs) against 4.9 with this send buffer, with none.
//!
//! So every AF_UNIX stream socket made in this process starts with Linux's
//! default send buffer: `socket` and `socketpair` are defined here, and the
//! linker binds every reference in the binary to them, Rust std's included
//! (std is linked into the same image; it does not reach libSystem's through
//! this crate). A socket `accept` returns inherits its listener's buffers
//! (xnu sonewconn: soreserve with the listener's hiwat), as Linux's starts at
//! the default. The real calls are libSystem's, found with
//! `dlsym(RTLD_NEXT)` when the binary is loaded.

use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Linux's `net.core.wmem_default` as the kernel sets it (SK_WMEM_MAX).
pub const LINUX_WMEM_DEFAULT: c_int = 212_992;

type SocketFn = unsafe extern "C" fn(c_int, c_int, c_int) -> c_int;
type SocketpairFn = unsafe extern "C" fn(c_int, c_int, c_int, *mut c_int) -> c_int;

static REAL_SOCKET: AtomicUsize = AtomicUsize::new(0);
static REAL_SOCKETPAIR: AtomicUsize = AtomicUsize::new(0);

fn real(slot: &AtomicUsize, name: &std::ffi::CStr) -> usize {
    let mut f = slot.load(Ordering::Acquire);
    if f == 0 {
        // SAFETY: dlsym with a NUL-terminated name; RTLD_NEXT finds the
        // definition in the images loaded after this one (libSystem's).
        f = unsafe { upstream::dlsym(upstream::RTLD_NEXT, name.as_ptr()) } as usize;
        assert_ne!(f, 0, "{name:?} not found after this binary");
        slot.store(f, Ordering::Release);
    }
    f
}

/// Resolved when the binary is loaded, before any sandbox narrows what
/// the process may do.
extern "C" fn resolve() {
    real(&REAL_SOCKET, c"socket");
    real(&REAL_SOCKETPAIR, c"socketpair");
}

#[used]
#[link_section = "__DATA,__mod_init_func"]
static RESOLVE: extern "C" fn() = resolve;

/// Gives `fd` Linux's default send buffer. On failure `fd` is closed and
/// the error is the call's, so no stream is left with xnu's 8 KiB.
fn linux_send_buffer(fd: c_int) -> bool {
    let size = LINUX_WMEM_DEFAULT;
    // SAFETY: an int option on a descriptor this call made.
    let r = unsafe {
        upstream::setsockopt(
            fd,
            upstream::SOL_SOCKET,
            upstream::SO_SNDBUF,
            (&raw const size).cast::<c_void>(),
            std::mem::size_of::<c_int>() as upstream::socklen_t,
        )
    };
    if r != 0 {
        // SAFETY: errno is this thread's; the descriptor is ours.
        unsafe {
            let e = *upstream::__error();
            upstream::close(fd);
            *upstream::__error() = e;
        }
        return false;
    }
    true
}

fn is_unix_stream(domain: c_int, ty: c_int) -> bool {
    domain == upstream::AF_UNIX && ty == upstream::SOCK_STREAM
}

/// `socket(2)`, with Linux's default send buffer on an AF_UNIX stream.
///
/// # Safety
/// As `socket(2)`.
#[no_mangle]
pub unsafe extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    // SAFETY: the address dlsym gave for `socket`.
    let f: SocketFn = unsafe { std::mem::transmute(real(&REAL_SOCKET, c"socket")) };
    // SAFETY: as the caller's.
    let fd = unsafe { f(domain, ty, protocol) };
    if fd >= 0 && is_unix_stream(domain, ty) && !linux_send_buffer(fd) {
        return -1;
    }
    fd
}

/// `socketpair(2)`, with Linux's default send buffer on both ends of an
/// AF_UNIX stream pair.
///
/// # Safety
/// As `socketpair(2)`: `sv` points to two ints.
#[no_mangle]
pub unsafe extern "C" fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int {
    // SAFETY: the address dlsym gave for `socketpair`.
    let f: SocketpairFn = unsafe { std::mem::transmute(real(&REAL_SOCKETPAIR, c"socketpair")) };
    // SAFETY: as the caller's.
    let r = unsafe { f(domain, ty, protocol, sv) };
    if r == 0 && is_unix_stream(domain, ty) {
        // SAFETY: the call filled `sv`.
        let [a, b] = unsafe { [*sv, *sv.add(1)] };
        if !linux_send_buffer(a) {
            // SAFETY: the other end is ours too; errno kept.
            unsafe {
                let e = *upstream::__error();
                upstream::close(b);
                *upstream::__error() = e;
            }
            return -1;
        }
        if !linux_send_buffer(b) {
            // SAFETY: as above.
            unsafe {
                let e = *upstream::__error();
                upstream::close(a);
                *upstream::__error() = e;
            }
            return -1;
        }
    }
    r
}
