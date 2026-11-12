// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `RLIMIT_NOFILE` on Windows: the jailer's `--resource-limit no-file=`,
//! counted in handles of the process (a wick API, not part of `libc`).
//!
//! Tests first: what the limit must do, as Linux's `alloc_fd` does it.

#[cfg(test)]
mod tests {
    use std::io::Error;
    use std::process::{Command, Stdio};
    use std::string::{String, ToString};
    use std::vec::Vec;

    use windows_sys::Win32::Networking::WinSock as ws;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

    use crate::{
        accept, bind, c_int, close, dup, dup2, fcntl, getrlimit, getsockname, listen, memfd_create,
        pipe, poll, pollfd, read, rlimit, sockaddr_storage, socket, timerfd_create, write,
        wick_errno_from_win32, AF_INET, CLOCK_MONOTONIC, EBADF, EMFILE, F_DUPFD, F_DUPFD_CLOEXEC,
        F_GETFD, MFD_CLOEXEC, POLLIN, RLIMIT_NOFILE, SOCK_STREAM,
    };

    /// The variable the Windows jailer gives Firecracker the limit in
    /// (overlay/jailer/platform/windows, `NO_FILE_ENV`).
    const VAR: &str = "WICK_NO_FILE";
    /// Which child scenario [`nofile_child`] runs.
    const CHILD: &str = "WICK_NOFILE_CHILD";

    /// The process's handle count, as Windows keeps it.
    fn handles() -> u64 {
        let mut n = 0u32;
        // SAFETY: the current process's pseudo handle and an out-parameter.
        assert_ne!(unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) }, 0);
        u64::from(n)
    }

    fn errno() -> Option<c_int> {
        Error::last_os_error().raw_os_error()
    }

    fn nofile_limit() -> (u64, u64) {
        let mut r = rlimit::default();
        // SAFETY: a valid out-parameter.
        assert_eq!(unsafe { getrlimit(RLIMIT_NOFILE, &mut r) }, 0);
        (r.rlim_cur, r.rlim_max)
    }

    /// Runs [`nofile_child`] in a process of its own, where no other test
    /// makes handles meanwhile and the limit is read afresh: the limit and
    /// the count are the process's, which the tests of this crate share.
    fn child(mode: &str, limit: Option<&str>) {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "wick_nofile::tests::nofile_child", "--ignored", "--nocapture", "--test-threads=1"])
            .env(CHILD, mode)
            .env_remove(VAR)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(v) = limit {
            cmd.env(VAR, v);
        }
        let out = cmd.output().unwrap();
        let text = std::format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success() && text.contains(&std::format!("nofile child {mode}: ok")),
            "{mode}: exit {:?}: {text}",
            out.status.code()
        );
    }

    /// At the limit, as on Linux (`alloc_fd` fails the call with `EMFILE`
    /// when no number below `RLIMIT_NOFILE` is free, linux v6.12
    /// fs/file.c): every call that makes a descriptor fails with `EMFILE`
    /// and makes nothing; the calls that make none go on; after a close the
    /// next call succeeds; a pipe needs room for its two ends; `accept`
    /// fails before it takes a connection, which stays queued (Linux takes
    /// the descriptor number before `do_accept`, linux v6.12 net/socket.c
    /// `__sys_accept4_file`), so the listener stays readable.
    #[test]
    fn test_emfile_at_the_limit() {
        child("fill", None);
    }

    /// A limit below the descriptors already open fails the next one at
    /// once, as on Linux: no offset is added to the number given.
    #[test]
    fn test_a_limit_below_the_count_fails_at_once() {
        child("below", Some("1"));
    }

    /// A value that is no number limits every descriptor (fails closed).
    #[test]
    fn test_an_unreadable_limit_refuses_every_descriptor() {
        child("unreadable", Some("2048 handles"));
    }

    /// Without the variable (Firecracker not started by the jailer) nothing
    /// is limited but Windows' own maximum, which `getrlimit` reports.
    #[test]
    fn test_no_limit_without_the_variable() {
        child("none", None);
    }

    /// The scenarios, each in a process of its own ([`child`]).
    #[test]
    #[ignore = "run by the tests above, in a process of their own"]
    fn nofile_child() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        match mode.as_str() {
            "fill" => fill(),
            "below" => below(1),
            "unreadable" => below(0),
            "none" => none(),
            other => panic!("unknown scenario {other}"),
        }
        std::println!("nofile child {mode}: ok");
    }

    /// The call `what` is refused at the limit: -1, `EMFILE`, and no handle
    /// made.
    fn refused(what: &str, limit: u64, room: u64, call: impl FnOnce() -> c_int) {
        let before = handles();
        assert!(before + room > limit, "{what}: {before} handles leave room under {limit}");
        let r = call();
        let e = errno();
        assert_eq!(r, -1, "{what} at {before} handles of {limit} succeeded");
        assert_eq!(e, Some(EMFILE), "{what}: {}", Error::from_raw_os_error(e.unwrap_or(0)));
        assert_eq!(handles(), before, "{what}: the refused call made a handle");
    }

    fn fill() {
        // EMFILE is Winsock's WSAEMFILE through the errno table, so
        // `last_os_error` names it and upstream's comparisons match.
        assert_eq!(EMFILE, 10024);
        assert_eq!(wick_errno_from_win32(EMFILE), EMFILE);
        // Windows' first socket, connection and timer load what they need
        // once: warmed up with Windows' own calls, which no limit sees.
        crate::windows_fd::wick_wsa_startup();
        {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let _c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
            let _a = l.accept().unwrap();
            // SAFETY: a socket of our own, closed at once.
            unsafe {
                let s = ws::WSASocketW(AF_INET, SOCK_STREAM, 0, std::ptr::null(), 0, ws::WSA_FLAG_OVERLAPPED);
                assert_ne!(s, ws::INVALID_SOCKET);
                ws::closesocket(s);
            }
        }
        let limit = handles() + 40;
        std::env::set_var(VAR, limit.to_string());
        // SAFETY: calls on our own descriptors and buffers.
        unsafe {
            // A listener with a connection queued, and a pipe, under the limit.
            let listener = socket(AF_INET, SOCK_STREAM, 0);
            assert!(listener >= 0, "{}", Error::last_os_error());
            let mut a: sockaddr_storage = std::mem::zeroed();
            a.ss_family = u16::try_from(AF_INET).unwrap();
            let p = (&raw mut a).cast::<u8>();
            for (i, b) in [127u8, 0, 0, 1].into_iter().enumerate() {
                *p.add(4 + i) = b;
            }
            assert_eq!(bind(listener, (&raw const a).cast(), 16), 0, "{}", Error::last_os_error());
            assert_eq!(listen(listener, 4), 0);
            let mut n = 128u32;
            assert_eq!(getsockname(listener, (&raw mut a).cast(), &mut n), 0);
            let port = u16::from_be_bytes([*p.add(2), *p.add(3)]);
            let _client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut ends: [c_int; 2] = [0; 2];
            assert_eq!(pipe(ends.as_mut_ptr()), 0);
            assert_eq!(nofile_limit(), (limit, limit), "getrlimit");

            // Fill: each socket is made while one more handle fits, and the
            // first that does not fit is refused.
            let mut fillers: Vec<c_int> = Vec::new();
            loop {
                assert!(fillers.len() < 200, "no socket refused under a limit of {limit}");
                let before = handles();
                let fd = socket(AF_INET, SOCK_STREAM, 0);
                if before < limit {
                    assert!(fd >= 0, "socket refused at {before} handles of {limit}: {}", Error::last_os_error());
                    fillers.push(fd);
                } else {
                    assert_eq!(fd, -1, "socket made at {before} handles of {limit}");
                    assert_eq!(errno(), Some(EMFILE));
                    assert_eq!(handles(), before, "the refused socket made a handle");
                    break;
                }
            }
            assert_eq!(handles(), limit, "the sockets filled the limit exactly");

            // Every call that makes a descriptor is refused.
            let mut more: [c_int; 2] = [0; 2];
            refused("socket", limit, 1, || socket(AF_INET, SOCK_STREAM, 0));
            refused("accept", limit, 1, || accept(listener, std::ptr::null_mut(), std::ptr::null_mut()));
            refused("pipe", limit, 2, || pipe(more.as_mut_ptr()));
            refused("dup", limit, 1, || dup(listener));
            refused("F_DUPFD", limit, 1, || fcntl(listener, F_DUPFD, 0));
            refused("F_DUPFD_CLOEXEC", limit, 1, || fcntl(listener, F_DUPFD_CLOEXEC, 0));
            refused("memfd_create", limit, 1, || memfd_create(c"t".as_ptr(), MFD_CLOEXEC));
            refused("timerfd_create", limit, 1, || timerfd_create(CLOCK_MONOTONIC, 0));

            // The refused accept left the connection queued: the listener
            // is still readable.
            let mut pfd = pollfd { fd: listener, events: POLLIN, revents: 0 };
            assert_eq!(poll(&mut pfd, 1, 0), 1, "the listener is no longer readable");
            assert_ne!(pfd.revents & POLLIN, 0);

            // Only the calls that make descriptors fail.
            assert_eq!(write(ends[1], b"x".as_ptr().cast(), 1), 1);
            let mut byte = [0u8; 1];
            assert_eq!(read(ends[0], byte.as_mut_ptr().cast(), 1), 1);
            assert!(fcntl(listener, F_GETFD) >= 0);
            assert_eq!(nofile_limit(), (limit, limit));

            // After a close the next call succeeds: the queued connection
            // is accepted.
            assert_eq!(close(fillers.pop().unwrap()), 0);
            assert_eq!(handles() + 1, limit);
            let conn = accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
            assert!(conn >= 0, "accept after a close: {}", Error::last_os_error());
            // A pipe needs room for two descriptors.
            assert_eq!(close(fillers.pop().unwrap()), 0);
            refused("pipe with room for one", limit, 2, || pipe(more.as_mut_ptr()));
            assert_eq!(close(fillers.pop().unwrap()), 0);
            assert_eq!(pipe(more.as_mut_ptr()), 0, "pipe with room for two: {}", Error::last_os_error());

            for fd in fillers.into_iter().chain([conn, listener, more[0], more[1], ends[0], ends[1]]) {
                close(fd);
            }
        }
    }

    /// A limit below the count, `limit` (from the variable): the next
    /// descriptor fails at once.
    fn below(limit: u64) {
        assert_eq!(nofile_limit(), (limit, limit), "getrlimit");
        let mut ends: [c_int; 2] = [0; 2];
        // SAFETY: calls that make descriptors, refused.
        unsafe {
            refused("socket", limit, 1, || socket(AF_INET, SOCK_STREAM, 0));
            refused("pipe", limit, 2, || pipe(ends.as_mut_ptr()));
            refused("memfd_create", limit, 1, || memfd_create(c"t".as_ptr(), MFD_CLOEXEC));
            refused("timerfd_create", limit, 1, || timerfd_create(CLOCK_MONOTONIC, 0));
        }
        // dup2 onto a number at or past the limit fails with EBADF, as
        // Linux's dup3 does (linux v6.12 fs/file.c `ksys_dup3`). Last: were
        // it to succeed, standard error would be the binary.
        let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let fd = std::os::windows::io::AsRawHandle::as_raw_handle(&f) as isize as c_int;
        // SAFETY: duplicates our handle, refused.
        assert_eq!(unsafe { dup2(fd, 2) }, -1, "dup2 onto 2 under a limit of {limit}");
        assert_eq!(errno(), Some(EBADF));
    }

    /// No variable: Windows' maximum, 2^24 handles, and descriptors are made.
    fn none() {
        assert_eq!(nofile_limit(), (1 << 24, 1 << 24));
        // SAFETY: our new socket, closed.
        unsafe {
            let fd = socket(AF_INET, SOCK_STREAM, 0);
            assert!(fd >= 0, "{}", Error::last_os_error());
            assert_eq!(close(fd), 0);
        }
    }
}
