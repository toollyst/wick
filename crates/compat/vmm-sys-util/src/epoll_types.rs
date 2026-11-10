// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: BSD-3-Clause

//! The `vmm_sys_util::epoll` types, shared by the macOS and Windows `epoll`.

use std::ops::Deref;

use bitflags::bitflags;

/// Wrapper over `EPOLL_CTL_*` operations that can be performed on a file descriptor.
#[derive(Debug)]
#[repr(i32)]
pub enum ControlOperation {
    /// Add a file descriptor to the interest list.
    Add = 1,
    /// Change the settings associated with a file descriptor that is
    /// already in the interest list.
    Modify = 3,
    /// Remove a file descriptor from the interest list.
    Delete = 2,
}

// Values of the Linux EPOLL* constants, so EventSet bits are the same on both systems.
bitflags! {
    /// The type of events we can monitor a file descriptor for.
    pub struct EventSet: u32 {
        /// The associated file descriptor is available for read operations.
        const IN = 0x001;
        /// The associated file descriptor is available for write operations.
        const OUT = 0x004;
        /// Error condition happened on the associated file descriptor.
        const ERROR = 0x008;
        /// The peer closed its end of the channel.
        const READ_HANG_UP = 0x2000;
        /// Sets the Edge Triggered behavior for the associated file descriptor.
        const EDGE_TRIGGERED = 1 << 31;
        /// Hang up happened on the associated file descriptor.
        const HANG_UP = 0x010;
        /// There is an exceptional condition on the file descriptor (ignored on macOS and Windows).
        const PRIORITY = 0x002;
        /// Keep the system awake while processing the event (ignored on macOS and Windows).
        const WAKE_UP = 1 << 29;
        /// Sets the one-shot behavior for the associated file descriptor.
        const ONE_SHOT = 1 << 30;
        /// Exclusive wakeup mode (ignored on macOS and Windows).
        const EXCLUSIVE = 1 << 28;
    }
}

/// Layout-compatible stand-in for Linux `struct epoll_event`.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct epoll_event {
    /// Event bits (`EventSet`).
    pub events: u32,
    /// User data.
    pub u64: u64,
}

/// Wrapper over `epoll_event`.
#[repr(transparent)]
#[derive(Clone, Copy, Default)]
pub struct EpollEvent(epoll_event);

impl std::fmt::Debug for EpollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ events: {}, data: {} }}", self.events(), self.data())
    }
}

impl Deref for EpollEvent {
    type Target = epoll_event;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EpollEvent {
    /// Creates a new epoll event.
    pub fn new(events: EventSet, data: u64) -> Self {
        EpollEvent(epoll_event {
            events: events.bits(),
            u64: data,
        })
    }

    /// Returns the event bits.
    pub fn events(&self) -> u32 {
        self.0.events
    }

    /// Returns the event bits as an [`EventSet`], dropping unknown bits.
    pub fn event_set(&self) -> EventSet {
        EventSet::from_bits_truncate(self.events())
    }

    /// Returns the user data.
    pub fn data(&self) -> u64 {
        self.0.u64
    }

    /// Returns the user data as a file descriptor.
    #[allow(clippy::cast_possible_truncation)]
    pub fn fd(&self) -> i32 {
        self.data() as i32
    }
}

