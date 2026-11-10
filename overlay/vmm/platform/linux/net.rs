// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! [`TapDevice`] on Linux: the TUN/TAP device.

use std::io;
use std::os::raw::{c_int, c_uint};

use crate::devices::virtio::iovec::IoVecBuffer;
pub use crate::devices::virtio::net::tap::Tap;
use crate::platform::net::{TapDevice, TapError};

impl TapDevice for Tap {
    fn open_named(if_name: &str) -> Result<Self, TapError> {
        Tap::open_named(if_name)
    }

    fn if_name_as_str(&self) -> &str {
        Tap::if_name_as_str(self)
    }

    fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        Tap::set_offload(self, flags)
    }

    fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        Tap::set_vnet_hdr_size(self, size)
    }

    fn write_iovec(&mut self, buffer: &IoVecBuffer) -> io::Result<usize> {
        Tap::write_iovec(self, buffer)
    }

    fn read_iovec(&mut self, buffer: &mut [libc::iovec]) -> io::Result<usize> {
        Tap::read_iovec(self, buffer)
    }
}
