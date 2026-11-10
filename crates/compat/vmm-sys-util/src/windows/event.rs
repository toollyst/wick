// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! `vmm_sys_util::event` on Windows: an event notifier and consumer pair,
//! with the upstream API. Linux makes both ends of one eventfd; so does this,
//! on the compatibility [`EventFd`], which epoll can wait for (the pipe that
//! upstream uses on other Unix hosts cannot be waited for on Windows).

use std::io;
use std::result::Result;

use wick_os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use crate::eventfd::{EventFd, EFD_NONBLOCK};

bitflags::bitflags! {
    /// Flags for [`new_event_consumer_and_notifier`].
    pub struct EventFlag: u8 {
        /// Non-blocking ends.
        const NONBLOCK = 1 << 0;
        /// Close-on-exec ends (Windows handles are not inherited unless
        /// asked for, so this is always so).
        const CLOEXEC = 1 << 1;
    }
}

/// The notifying end.
#[derive(Debug)]
pub struct EventNotifier {
    fd: EventFd,
}

impl EventNotifier {
    /// Notifies the consumer.
    pub fn notify(&self) -> Result<(), io::Error> {
        self.fd.write(1)
    }

    /// A new notifier for the same event.
    pub fn try_clone(&self) -> Result<EventNotifier, io::Error> {
        Ok(EventNotifier {
            fd: self.fd.try_clone()?,
        })
    }
}

impl AsRawFd for EventNotifier {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for EventNotifier {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        EventNotifier {
            // SAFETY: the caller's contract.
            fd: unsafe { EventFd::from_raw_fd(fd) },
        }
    }
}

impl IntoRawFd for EventNotifier {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

/// The consuming end.
#[derive(Debug)]
pub struct EventConsumer {
    fd: EventFd,
}

impl EventConsumer {
    /// Consumes the notifications so far (blocks for one unless non-blocking).
    pub fn consume(&self) -> Result<(), io::Error> {
        self.fd.read().map(|_| ())
    }

    /// A new consumer for the same event.
    pub fn try_clone(&self) -> Result<EventConsumer, io::Error> {
        Ok(EventConsumer {
            fd: self.fd.try_clone()?,
        })
    }
}

impl AsRawFd for EventConsumer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for EventConsumer {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        EventConsumer {
            // SAFETY: the caller's contract.
            fd: unsafe { EventFd::from_raw_fd(fd) },
        }
    }
}

impl IntoRawFd for EventConsumer {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

/// A consumer and a notifier of one event.
pub fn new_event_consumer_and_notifier(
    flags: EventFlag,
) -> Result<(EventConsumer, EventNotifier), io::Error> {
    let fd = EventFd::new(if flags.contains(EventFlag::NONBLOCK) { EFD_NONBLOCK } else { 0 })?;
    let notifier = EventNotifier { fd: fd.try_clone()? };
    Ok((EventConsumer { fd }, notifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_consume() {
        let (consumer, notifier) = new_event_consumer_and_notifier(EventFlag::NONBLOCK).unwrap();
        assert_eq!(consumer.consume().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        notifier.notify().unwrap();
        notifier.try_clone().unwrap().notify().unwrap();
        consumer.consume().unwrap();
        assert_eq!(consumer.consume().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        // Both ends are one event, as on Linux.
        notifier.notify().unwrap();
        consumer.try_clone().unwrap().consume().unwrap();
    }
}
