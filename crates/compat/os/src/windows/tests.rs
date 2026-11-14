// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::undocumented_unsafe_blocks)]

use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Shutdown;

use super::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, adopt_socket, dup, socket_fits};
use super::unix::ffi::{OsStrExt, OsStringExt};
use super::unix::fs::{FileExt, MetadataExt};
use super::unix::net::{UnixListener, UnixStream};

fn temp_path(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("wick-os-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn test_pair() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
    b.write_all(b"pong").unwrap();
    a.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"pong");
    a.shutdown(Shutdown::Write).unwrap();
    assert_eq!(b.read(&mut buf).unwrap(), 0);
}

// After shutdown, as on Linux: a write is EPIPE (BrokenPipe), a read of
// the side shut for reading is the end (0), where Winsock fails both with
// WSAESHUTDOWN.
#[test]
fn test_writes_and_reads_after_shutdown() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.shutdown(Shutdown::Write).unwrap();
    let err = a.write(b"x").unwrap_err();
    assert_eq!((err.raw_os_error(), err.kind()), (Some(109), std::io::ErrorKind::BrokenPipe));
    b.shutdown(Shutdown::Read).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(b.read(&mut buf).unwrap(), 0);
}

#[test]
fn test_listener() {
    let path = temp_path("listener.sock");
    let listener = UnixListener::bind(&path).unwrap();
    assert_eq!(listener.local_addr().unwrap().as_pathname(), Some(path.as_path()));
    let mut client = UnixStream::connect(&path).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    assert_eq!(client.peer_addr().unwrap().as_pathname(), Some(path.as_path()));
    assert_eq!(super::peer_pid(server.as_raw_fd()).unwrap(), std::process::id());
    client.write_all(b"hello").unwrap();
    let mut buf = [0u8; 5];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
    drop(listener);
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn test_connect_errors_are_linux_kinds() {
    // No socket file: ENOENT on Linux, NotFound here.
    let missing = temp_path("missing.sock");
    let e = UnixStream::connect(&missing).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    // A socket file nothing listens on any more: ECONNREFUSED on both.
    let path = temp_path("closed.sock");
    drop(UnixListener::bind(&path).unwrap());
    let e = UnixStream::connect(&path).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused, "{e}");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn test_nonblocking() {
    let (a, _b) = UnixStream::pair().unwrap();
    a.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 1];
    let err = (&a).read(&mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
}

// A socket made non-blocking and then closed is closed: its peer reads the
// end, as on Linux, where close drops the last reference to the open file
// and the peer's read returns 0. A socket pair's end and an accepted
// connection (the vsock muxer's and the network endpoint's), each set
// non-blocking before it is dropped; the peer's read waits at most 5 s.
// CI run 43616040593 (5e3727d): the muxer's and the endpoint's peers never
// saw the close, and vsock's handshake timed out.
#[test]
fn test_a_socket_made_non_blocking_and_closed_ends_its_peers_stream() {
    let ends_at_the_peer = |what: &str, a: UnixStream, mut b: UnixStream| {
        a.set_nonblocking(true).unwrap();
        a.set_nonblocking(false).unwrap();
        a.set_nonblocking(true).unwrap();
        drop(a);
        b.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 1];
        match b.read(&mut buf) {
            Ok(0) => {}
            other => panic!("{what}: the peer read {other:?}, not the end of the stream"),
        }
    };
    let (a, b) = UnixStream::pair().unwrap();
    ends_at_the_peer("a pair's end", a, b);
    let path = temp_path("closed-nonblocking.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let client = UnixStream::connect(&path).unwrap();
    let (server, _) = listener.accept().unwrap();
    ends_at_the_peer("an accepted connection", server, client);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_socket_values_that_are_no_descriptor() {
    // Kernel handles (multiples of 4 in 32 bits) are descriptors, as is
    // `INVALID_SOCKET`'s -1 for the callers that check it first.
    assert_eq!(socket_fits(0x1234), Some(0x1234));
    assert_eq!(socket_fits(usize::MAX), Some(-1));
    assert_eq!(socket_fits(0x7fff_fffc), Some(0x7fff_fffc));
    // A value past 32 bits, or 0, 1 or 2 (the standard handles), is not.
    for s in [0usize, 1, 2, 0x1_0000_0004, 0x8000_0000, 0xffff_ffff, usize::MAX - 0x1_0000_0000] {
        assert_eq!(socket_fits(s), None, "{s:#x}");
    }
    let err = std::panic::catch_unwind(|| super::fd::from_socket(0x1_0000_0004)).unwrap_err();
    assert!(err.downcast_ref::<String>().unwrap().contains("refused, not truncated"));
}

#[test]
fn test_a_socket_that_is_no_descriptor_is_refused_and_closed() {
    use std::os::windows::io::IntoRawSocket;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCK_STREAM, WSASocketW};
    super::net::startup();
    // A connected socket, whose peer sees its close: the end of the stream.
    // The refused value is not used again to prove it (closing it a second
    // time would close whatever socket another test thread got that value
    // for since: CI's run did, and that thread's test failed).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let s = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap().into_raw_socket() as usize;
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    // A real socket, judged as a layered provider's value would be.
    let err = adopt_socket(s, |_| None).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains(&format!("{s:#x}")), "{err}");
    // It was closed: its peer reads the end of the stream, where an open
    // socket would leave the read waiting until the timeout.
    let mut byte = [0u8; 1];
    assert_eq!(peer.read(&mut byte).unwrap(), 0, "the refused socket was not closed");
    // One that fits is the descriptor.
    // SAFETY: a new socket owned here.
    let s = unsafe { WSASocketW(i32::from(AF_INET), SOCK_STREAM, 0, std::ptr::null(), 0, 0) };
    let fd = super::fd::socket_fd(s).unwrap();
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
}

#[test]
fn test_socket_fd_round_trip() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let copy = dup(a.as_raw_fd()).unwrap();
    drop(a);
    let mut a = unsafe { UnixStream::from_raw_fd(copy) };
    a.write_all(b"x").unwrap();
    let mut buf = [0u8; 1];
    b.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"x");
    let fd: OwnedFd = a.into();
    let a = UnixStream::from(fd);
    let raw = a.into_raw_fd();
    drop(unsafe { OwnedFd::from_raw_fd(raw) });
}

#[test]
fn test_file_ext_keeps_position() {
    let path = temp_path("file");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(b"0123456789").unwrap();
    file.seek(SeekFrom::Start(2)).unwrap();
    let mut buf = [0u8; 3];
    file.read_exact_at(&mut buf, 5).unwrap();
    assert_eq!(&buf, b"567");
    file.write_all_at(b"ab", 0).unwrap();
    assert_eq!(file.stream_position().unwrap(), 2);
    assert_eq!(file.read_at(&mut buf, 10).unwrap(), 0);
    assert_eq!(file.read_at(&mut buf, 100).unwrap(), 0);
    let mut all = Vec::new();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_to_end(&mut all).unwrap();
    assert_eq!(all, b"ab23456789");
    assert_eq!(file.metadata().unwrap().size(), 10);
    let fd = file.into_raw_fd();
    drop(unsafe { std::fs::File::from_raw_fd(fd) });
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn test_os_str_bytes() {
    assert_eq!(OsStr::from_bytes(b"abc"), OsStr::new("abc"));
    assert_eq!(OsStr::new("ü").as_bytes(), "ü".as_bytes());
    assert_eq!(OsString::from_vec(b"xyz".to_vec()), OsString::from("xyz"));
    assert_eq!(OsString::from("é").into_vec(), "é".as_bytes());
}

#[test]
fn test_standard_descriptors() {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    let std = unsafe {
        [
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        ]
    };
    for (fd, h) in (0..).zip(std) {
        assert_eq!(super::fd::handle(fd), h);
    }
    // Other values are the handle itself.
    let f = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(super::fd::handle(f.as_raw_fd()), f.as_raw_handle() as HANDLE);
}

#[test]
fn test_socket_duplicated_while_a_receive_waits() {
    // A blocking receive must not hold up a duplication of its socket (the
    // vhost-user frontend sends its own channel while it waits for the ack).
    let (a, b) = UnixStream::pair().unwrap();
    let a2 = a.try_clone().unwrap();
    let waiter = std::thread::spawn(move || {
        let mut buf = [0u8; 1];
        (&a2).read_exact(&mut buf).unwrap();
        buf[0]
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let fd = a.as_raw_fd();
    std::thread::spawn(move || {
        let d = dup(fd).map(|d| unsafe { OwnedFd::from_raw_fd(d) });
        let _ = done_tx.send(d);
    });
    let Ok(dup) = done_rx.recv_timeout(std::time::Duration::from_secs(5)) else {
        // Closing the sockets would wait behind the receive as well.
        std::mem::forget((a, b));
        panic!("dup blocked behind a pending receive");
    };
    drop(dup.unwrap());
    (&b).write_all(&[7]).unwrap();
    assert_eq!(waiter.join().unwrap(), 7);
}

// `--resource-limit no-file=` (the Windows jailer gives it in `WICK_NO_FILE`;
// crates/compat/libc, `wick_nofile`): every call here that makes a
// descriptor fails with EMFILE once the process's handles leave no room for
// it, as past RLIMIT_NOFILE on Linux, and makes nothing. The API server
// (micro-http) and the vsock muxer accept through `UnixListener::accept`:
// refused before it takes a connection, which stays queued, as Linux takes
// the descriptor number before it accepts (linux v6.12 net/socket.c,
// `__sys_accept4_file`). A pair needs room for two. Run in a process of its
// own ([`nofile_child`]): the count and the limit are the process's.
#[test]
fn test_emfile_at_the_limit() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "windows::tests::nofile_child", "--ignored", "--nocapture", "--test-threads=1"])
        .env(NOFILE_CHILD, "1")
        .env_remove(NOFILE_VAR)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("nofile child: ok"), "exit {:?}: {text}", out.status.code());
}

/// The variable the jailer gives the limit in.
const NOFILE_VAR: &str = "WICK_NO_FILE";
const NOFILE_CHILD: &str = "WICK_NOFILE_CHILD";
/// `WSAEMFILE`, the compat libc's `EMFILE`.
const EMFILE: i32 = 10024;

fn handles() -> u64 {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut n = 0u32;
    assert_ne!(unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut n) }, 0);
    u64::from(n)
}

/// `r` failed with EMFILE and made no handle (`before`: the count before it).
#[track_caller]
fn refused<T: std::fmt::Debug>(what: &str, before: u64, r: std::io::Result<T>) {
    let err = r.expect_err(what);
    assert_eq!(err.raw_os_error(), Some(EMFILE), "{what}: {err}");
    assert_eq!(handles(), before, "{what}: the refused call made a handle");
}

#[test]
#[ignore = "run by test_emfile_at_the_limit, in a process of its own"]
fn nofile_child() {
    use windows_sys::Win32::Networking::WinSock::{AF_UNIX, SOCK_STREAM, WSASocketW, closesocket};
    if std::env::var_os(NOFILE_CHILD).is_none() {
        return;
    }
    // Winsock's first AF_UNIX socket loads what it needs once: warmed up
    // with Winsock itself, which no limit sees.
    super::net::startup();
    let s = unsafe { WSASocketW(i32::from(AF_UNIX), SOCK_STREAM, 0, std::ptr::null(), 0, 0) };
    assert_eq!(unsafe { closesocket(s) }, 0);
    let path = temp_path("nofile.sock");
    let other = temp_path("nofile-other.sock");
    let limit = handles() + 24;
    unsafe { std::env::set_var(NOFILE_VAR, limit.to_string()) };

    let listener = UnixListener::bind(&path).unwrap();
    let mut client = UnixStream::connect(&path).unwrap();
    // Fill: each clone is made while one more handle fits; the first that
    // does not fit is refused.
    let mut fillers = Vec::new();
    loop {
        assert!(fillers.len() < 100, "no clone refused under a limit of {limit}");
        let before = handles();
        let r = listener.try_clone();
        if before < limit {
            fillers.push(r.unwrap_or_else(|e| panic!("try_clone refused at {before} handles of {limit}: {e}")));
        } else {
            refused("try_clone at the limit", before, r);
            break;
        }
    }
    // Every call that makes a descriptor is refused.
    refused("accept", handles(), listener.accept());
    refused("connect", handles(), UnixStream::connect(&path));
    refused("bind", handles(), UnixListener::bind(&other));
    refused("pair", handles(), UnixStream::pair());
    refused("dup", handles(), dup(listener.as_raw_fd()));
    // After a close the next call succeeds: the refused accept left the
    // connection queued, and it is the client's.
    while handles() >= limit {
        drop(fillers.pop().expect("closing every clone left no room"));
    }
    let (mut server, _) = listener.accept().unwrap();
    client.write_all(b"q").unwrap();
    let mut byte = [0u8; 1];
    server.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"q");
    // A pair needs room for two descriptors (three handles a moment: it
    // listens, connects and accepts).
    while handles() >= limit {
        drop(fillers.pop().expect("closing every clone left no room"));
    }
    if handles() + 1 == limit {
        refused("pair with room for one", handles(), UnixStream::pair());
    }
    while handles() + 2 > limit {
        drop(fillers.pop().expect("closing every clone left no room"));
    }
    let (_a, _b) = UnixStream::pair().unwrap();
    drop((fillers, listener));
    let _ = std::fs::remove_file(&path);
    println!("nofile child: ok");
}
