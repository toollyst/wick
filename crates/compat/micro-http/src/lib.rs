// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `micro_http` for wick.
//!
//! - Linux, macOS: the upstream crate, re-exported as is.
//! - Windows: the upstream source over `wick_os` (`AF_UNIX` sockets) and
//!   wick's epoll.

#[cfg(not(windows))]
pub use upstream::*;

#[cfg(windows)]
// Upstream code: lints capped as cargo caps them for upstream crates.
#[allow(warnings, clippy::all)]
#[path = "windows/mod.rs"]
mod windows;
#[cfg(windows)]
pub use windows::*;

// Upstream's test_kill_switch races the server's shutdown, so it is not
// generated for Windows (tools/gen-windows-sources.sh); this one checks the
// same behaviour without the race.
#[cfg(all(test, windows))]
mod tests {
    use std::io::Write;

    use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};
    use vmm_sys_util::tempfile::TempFile;
    use wick_os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn test_kill_switch() {
        let mut path = TempFile::new().unwrap();
        path.remove().unwrap();
        let mut server = HttpServer::new(path.as_path()).unwrap();
        let kill_switch = EventFd::new(EFD_NONBLOCK).unwrap();
        server
            .add_kill_switch(kill_switch.try_clone().unwrap())
            .unwrap();
        server.start_server().unwrap();
        // The kill switch, then a request: the shutdown is reported instead.
        kill_switch.write(1).unwrap();
        let mut socket = UnixStream::connect(path.as_path()).unwrap();
        socket
            .write_all(
                b"PATCH /machine-config HTTP/1.1\r\n\
                  Content-Length: 13\r\n\
                  Content-Type: application/json\r\n\r\nwhatever body",
            )
            .unwrap();
        assert_eq!(server.requests().unwrap_err(), ServerError::ShutdownEvent);
    }
}
