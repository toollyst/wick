// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! gdbstub's `Connection` and `ConnectionExt` for [`UnixStream`], as gdbstub
//! implements them for std's on Unix (`gdbstub::conn::impls::unixstream`):
//! a blocking read of one byte, and a peek in non-blocking mode that says
//! `None` when nothing is waiting.

use std::io::{self, Read, Write};

use gdbstub::conn::{Connection, ConnectionExt};

use super::net::UnixStream;

impl Connection for UnixStream {
    type Error = io::Error;

    fn write(&mut self, byte: u8) -> io::Result<()> {
        Write::write_all(self, &[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        Write::write_all(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(self)
    }
}

impl ConnectionExt for UnixStream {
    fn read(&mut self) -> io::Result<u8> {
        self.set_nonblocking(false)?;
        let mut buf = [0u8];
        Read::read_exact(self, &mut buf)?;
        Ok(buf[0])
    }

    fn peek(&mut self) -> io::Result<Option<u8>> {
        self.set_nonblocking(true)?;
        let mut buf = [0u8];
        match UnixStream::peek(self, &mut buf) {
            Ok(_) => Ok(Some(buf[0])),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdbstub_connection() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        // Nothing waiting: None, without blocking.
        assert_eq!(ConnectionExt::peek(&mut b).unwrap(), None);
        Connection::write_all(&mut a, b"$g#67").unwrap();
        Connection::flush(&mut a).unwrap();
        // A peek leaves the byte to read; the read then blocks for the next.
        let mut seen = None;
        for _ in 0..1000 {
            seen = ConnectionExt::peek(&mut b).unwrap();
            if seen.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(seen, Some(b'$'));
        assert_eq!(ConnectionExt::peek(&mut b).unwrap(), Some(b'$'));
        let mut got = Vec::new();
        for _ in 0..5 {
            got.push(ConnectionExt::read(&mut b).unwrap());
        }
        assert_eq!(got, b"$g#67");
        Connection::write(&mut a, b'+').unwrap();
        assert_eq!(ConnectionExt::read(&mut b).unwrap(), b'+');
        drop(a);
        // The peer gone: a read fails, as std's read_exact at end of file.
        assert_eq!(ConnectionExt::read(&mut b).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
