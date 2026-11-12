// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! SIGPIPE on the Unix sockets Firecracker makes, as on Linux.
//!
//! On Linux a write to a stream socket whose peer has closed fails with
//! `EPIPE` and raises SIGPIPE, which upstream's handler counts
//! (`signals.sigpipe`) before Firecracker goes on. On Apple systems Rust's
//! standard library sets `SO_NOSIGPIPE` on every socket it makes
//! (`Socket::new`, library/std/src/sys/net/connection/socket/unix.rs; not on
//! Linux), and xnu copies the flag to the connections a listener accepts
//! (`sonewconn`, bsd/kern/uipc_socket2.c), so the write fails without the
//! signal (`soo_write`, bsd/kern/sys_socket.c, and `sendit`,
//! bsd/kern/uipc_syscalls.c, raise it only without the flag).
//! [`sigpipe_as_linux`] clears the flag on a socket std made; on a listener,
//! before it accepts, it is cleared on every connection too.
//!
//! Where it is called: the API socket's listener (`ext::api_process`, before
//! the API process has it), the vsock device's listener and its connections
//! to the host's sockets (`VsockMuxer`), the connection to a page fault
//! handler (`persist`) and to a vhost-user backend (`vhost_user`). Wick's own
//! sockets keep what they have: the link to the API process is a socket pair,
//! which std makes without the flag; the userfaultfd channel sets the flag on
//! purpose, as Linux's userfaultfd is no socket and a write to it raises no
//! signal; the network device's endpoints are datagram sockets, where Linux's
//! TAP device has no `EPIPE` either.

#[cfg(target_os = "macos")]
use std::io;

/// `F_SETNOSIGPIPE` and `F_GETNOSIGPIPE` (<sys/fcntl.h>; not in the libc
/// crate).
#[cfg(target_os = "macos")]
const F_SETNOSIGPIPE: libc::c_int = 73;
#[cfg(all(test, target_os = "macos"))]
const F_GETNOSIGPIPE: libc::c_int = 74;

/// Lets `socket` raise SIGPIPE on a write after its peer has closed, as a
/// socket does on Linux, and returns it. `fcntl(F_SETNOSIGPIPE, 0)`: for a
/// socket xnu sets `SO_NOSIGPIPE` (bsd/kern/kern_descrip.c, `F_SETNOSIGPIPE`),
/// a command the run phase's sandbox allows (a vsock connection is made
/// then).
#[cfg(target_os = "macos")]
pub fn sigpipe_as_linux<S: std::os::fd::AsRawFd>(socket: S) -> io::Result<S> {
    // SAFETY: fcntl on a descriptor `socket` owns or names.
    if unsafe { libc::fcntl(socket.as_raw_fd(), F_SETNOSIGPIPE, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// Linux raises SIGPIPE already; Windows has no SIGPIPE.
#[cfg(not(target_os = "macos"))]
pub fn sigpipe_as_linux<S>(socket: S) -> std::io::Result<S> {
    Ok(socket)
}

/// For the tests of each place [`sigpipe_as_linux`] is called: a write
/// after the peer's close raises SIGPIPE and upstream's handler counts it.
/// The handlers are Firecracker's, so each case runs in a process of its
/// own (an ignored test the case's test starts).
#[cfg(all(test, unix))]
pub(crate) mod test_util {
    use crate::logger::{IncMetric, METRICS};

    /// Runs the ignored test `name` (its path in the vmm crate) in a
    /// process of its own and asserts that it counted the SIGPIPE.
    pub(crate) fn run_sigpipe_child(name: &str) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--ignored", "--nocapture", "--test-threads=1"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("SIGPIPE-COUNTED"),
            "{:?}\n--- stdout\n{stdout}\n--- stderr\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// In such a process: Firecracker's signal handlers, then `scenario`,
    /// which writes to a socket whose peer has closed; `signals.sigpipe`
    /// counts a SIGPIPE (xnu sends it to the process, which may take it on
    /// another thread: waited for up to a second).
    pub(crate) fn sigpipe_child(scenario: impl FnOnce()) {
        crate::signal_handler::register_signal_handlers().unwrap();
        let before = METRICS.signals.sigpipe.count();
        scenario();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while METRICS.signals.sigpipe.count() == before && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(METRICS.signals.sigpipe.count() > before, "no SIGPIPE counted");
        println!("SIGPIPE-COUNTED");
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};

    use super::*;

    /// Whether `F_GETNOSIGPIPE` reports the flag on `fd`.
    fn nosigpipe(fd: &impl std::os::fd::AsRawFd) -> bool {
        // SAFETY: fcntl on a descriptor of this process.
        let flag = unsafe { libc::fcntl(fd.as_raw_fd(), F_GETNOSIGPIPE) };
        assert!(flag >= 0, "{}", io::Error::last_os_error());
        flag != 0
    }

    // What the module documents, measured: std's sockets carry the flag and
    // a listener's connections inherit it; cleared on the listener, it is
    // clear on what the listener accepts, and on a connection it is cleared
    // on.
    #[test]
    fn test_std_sockets_and_a_cleared_listener() {
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let path = dir.as_path().join("s");
        let listener = UnixListener::bind(&path).unwrap();
        assert!(nosigpipe(&listener));
        let client = UnixStream::connect(&path).unwrap();
        assert!(nosigpipe(&client));
        let (accepted, _) = listener.accept().unwrap();
        assert!(nosigpipe(&accepted));
        let listener = sigpipe_as_linux(listener).unwrap();
        assert!(!nosigpipe(&listener));
        let client = sigpipe_as_linux(UnixStream::connect(&path).unwrap()).unwrap();
        assert!(!nosigpipe(&client));
        let (accepted, _) = listener.accept().unwrap();
        assert!(!nosigpipe(&accepted));
    }
}
