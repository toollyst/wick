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
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, SOCK_STREAM, SOCKET_ERROR, WSAENOTSOCK, WSAGetLastError, WSASocketW, closesocket,
    };
    super::net::startup();
    // SAFETY: a new socket owned here.
    let s = unsafe { WSASocketW(i32::from(AF_INET), SOCK_STREAM, 0, std::ptr::null(), 0, 0) };
    assert_ne!(s, usize::MAX);
    // A real socket, judged as a layered provider's value would be.
    let err = adopt_socket(s, |_| None).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains(&format!("{s:#x}")), "{err}");
    // It was closed: closing it again finds no socket.
    // SAFETY: a value that names no socket now.
    assert_eq!(unsafe { closesocket(s) }, SOCKET_ERROR);
    // SAFETY: reads the thread's last Winsock error.
    assert_eq!(unsafe { WSAGetLastError() }, WSAENOTSOCK);
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
