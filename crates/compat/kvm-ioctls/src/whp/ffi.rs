// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Thin, safe-ish wrappers over the Windows Hypervisor Platform (WHP) calls
//! this backend uses, plus the register-name table.
//!
//! WHP functions return an `HRESULT`. Here they are turned into the crate's
//! `Result` with a Linux-style errno, so the rest of the backend fails the
//! way KVM ioctls do.

#![allow(non_upper_case_globals)]

use std::sync::OnceLock;

use vmm_sys_util::errno::Error;
use windows_sys::Win32::Foundation::{HANDLE, S_OK};
use super::whv::{
    self as whv, WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
    WHV_RUN_VP_EXIT_CONTEXT,
};

use super::Result;

/// Turns an `HRESULT` into `Ok(())` or a Linux-style errno error.
pub(crate) fn hr(hres: i32) -> Result<()> {
    if hres == S_OK {
        Ok(())
    } else {
        Err(from_hresult(hres))
    }
}

/// Maps the WHP/Win32 `HRESULT` to the closest Linux errno, so callers see
/// the error values KVM would give. The raw `HRESULT` is kept as the error's
/// OS code for anything that wants the exact facility/code.
fn from_hresult(hres: i32) -> Error {
    use windows_sys::Win32::Foundation::{
        E_ACCESSDENIED, E_INVALIDARG, E_NOTIMPL, E_OUTOFMEMORY,
    };
    // WHP uses HRESULTs from FACILITY_WIN32 (0x8007xxxx) for Win32 errors, and
    // a few generic ones. Translate the ones that matter; keep the rest as a
    // generic EINVAL (what KVM returns for a rejected ioctl argument).
    const WIN32_FACILITY: i32 = 0x8007_0000u32 as i32;
    if (hres & 0xFFFF_0000u32 as i32) == WIN32_FACILITY {
        return Error::new(hres & 0xFFFF);
    }
    let errno = match hres {
        E_INVALIDARG => libc::EINVAL,
        E_ACCESSDENIED => libc::EACCES,
        E_OUTOFMEMORY => libc::ENOMEM,
        E_NOTIMPL => libc::ENOSYS,
        _ => libc::EINVAL,
    };
    Error::new(errno)
}

/// Whether WHP is present on this host (the hypervisor platform feature is
/// installed and enabled). Cached.
pub(crate) fn whp_present() -> bool {
    static PRESENT: OnceLock<bool> = OnceLock::new();
    *PRESENT.get_or_init(|| {
        let mut cap: whv::WHV_CAPABILITY = unsafe { std::mem::zeroed() };
        let mut written = 0u32;
        // SAFETY: valid output buffer of the given size.
        let hres = unsafe {
            whv::WHvGetCapability(
                whv::WHvCapabilityCodeHypervisorPresent,
                (&raw mut cap).cast(),
                u32::try_from(std::mem::size_of_val(&cap)).unwrap(),
                &mut written,
            )
        };
        hres == S_OK && written >= 1 && unsafe { cap.HypervisorPresent } != 0
    })
}

/// Creates a partition handle.
pub(crate) fn create_partition() -> Result<WHV_PARTITION_HANDLE> {
    let mut part: WHV_PARTITION_HANDLE = 0;
    // SAFETY: valid out-parameter.
    hr(unsafe { whv::WHvCreatePartition(&mut part) })?;
    Ok(part)
}

/// Sets a partition property from a value struct.
///
/// # Safety
/// `value` must be a valid property value of the kind `code` expects.
pub(crate) unsafe fn set_partition_property<T>(
    part: WHV_PARTITION_HANDLE,
    code: whv::WHV_PARTITION_PROPERTY_CODE,
    value: &T,
) -> Result<()> {
    // SAFETY: the caller's contract; `value` is valid for its size.
    hr(unsafe {
        whv::WHvSetPartitionProperty(
            part,
            code,
            (std::ptr::from_ref::<T>(value)).cast(),
            u32::try_from(std::mem::size_of::<T>()).unwrap(),
        )
    })
}

/// A register value aligned on 16 bytes. The header declares
/// `WHV_UINT128` (and so `WHV_REGISTER_VALUE`) `DECLSPEC_ALIGN(16)` and WHP
/// reads and writes the arrays with aligned SSE moves; `windows-sys`'s type
/// is only 8-aligned, and an array that happened to be misaligned faulted in
/// `WHvSetVirtualProcessorRegisters` (a snapshot restore's vCPU events).
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Aligned(WHV_REGISTER_VALUE);

/// Aligned room for `n` register values: on the stack for the usual few.
enum Room {
    Stack([Aligned; 64], usize),
    Heap(Vec<Aligned>),
}

impl Room {
    fn new(n: usize) -> Self {
        let zero = Aligned(reg64(0));
        if n <= 64 {
            Room::Stack([zero; 64], n)
        } else {
            Room::Heap(vec![zero; n])
        }
    }

    fn slice(&mut self) -> &mut [Aligned] {
        match self {
            Room::Stack(a, n) => &mut a[..*n],
            Room::Heap(v) => v,
        }
    }
}

/// Reads several registers of a vCPU.
pub(crate) fn get_registers(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    names: &[WHV_REGISTER_NAME],
    values: &mut [WHV_REGISTER_VALUE],
) -> Result<()> {
    debug_assert_eq!(names.len(), values.len());
    let mut room = Room::new(values.len());
    let aligned = room.slice();
    // SAFETY: both arrays have `names.len()` elements; `Aligned` is a
    // `WHV_REGISTER_VALUE` aligned as WHP requires.
    hr(unsafe {
        whv::WHvGetVirtualProcessorRegisters(
            part,
            vp,
            names.as_ptr(),
            u32::try_from(names.len()).unwrap(),
            aligned.as_mut_ptr().cast(),
        )
    })?;
    for (v, a) in values.iter_mut().zip(aligned.iter()) {
        *v = a.0;
    }
    Ok(())
}

/// Writes several registers of a vCPU.
pub(crate) fn set_registers(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    names: &[WHV_REGISTER_NAME],
    values: &[WHV_REGISTER_VALUE],
) -> Result<()> {
    debug_assert_eq!(names.len(), values.len());
    let mut room = Room::new(values.len());
    let aligned = room.slice();
    for (a, v) in aligned.iter_mut().zip(values) {
        *a = Aligned(*v);
    }
    // SAFETY: both arrays have `names.len()` elements, aligned (`Aligned`).
    hr(unsafe {
        whv::WHvSetVirtualProcessorRegisters(
            part,
            vp,
            names.as_ptr(),
            u32::try_from(names.len()).unwrap(),
            aligned.as_ptr().cast(),
        )
    })
}

/// Reads one register of a vCPU.
pub(crate) fn get_register(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    name: WHV_REGISTER_NAME,
) -> Result<WHV_REGISTER_VALUE> {
    let mut value: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
    get_registers(part, vp, &[name], std::slice::from_mut(&mut value))?;
    Ok(value)
}

/// Writes one register of a vCPU.
pub(crate) fn set_register(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    name: WHV_REGISTER_NAME,
    value: WHV_REGISTER_VALUE,
) -> Result<()> {
    set_registers(part, vp, &[name], &[value])
}

/// A 64-bit register value.
pub(crate) fn reg64(v: u64) -> WHV_REGISTER_VALUE {
    let mut value: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
    value.Reg64 = v;
    value
}

/// Reads the 64-bit field of a register value.
pub(crate) fn as_u64(value: &WHV_REGISTER_VALUE) -> u64 {
    // SAFETY: `Reg64` reads the low 64 bits of the union, valid for any value.
    unsafe { value.Reg64 }
}

/// Runs a vCPU until it exits, returning the exit context.
pub(crate) fn run_vp(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<WHV_RUN_VP_EXIT_CONTEXT> {
    // Aligned as the header's type (see `Aligned`).
    #[repr(C, align(16))]
    struct Exit(WHV_RUN_VP_EXIT_CONTEXT);
    // SAFETY: all-zero is a valid exit context.
    let mut ctx = Exit(unsafe { std::mem::zeroed() });
    // SAFETY: valid output buffer of the given size.
    hr(unsafe {
        whv::WHvRunVirtualProcessor(
            part,
            vp,
            (&raw mut ctx.0).cast(),
            u32::try_from(std::mem::size_of_val(&ctx.0)).unwrap(),
        )
    })?;
    Ok(ctx.0)
}

/// Asks a running vCPU to exit `WHvRunVirtualProcessor` as soon as possible.
pub(crate) fn cancel_run(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<()> {
    // SAFETY: plain call; harmless if the vCPU is not running.
    hr(unsafe { whv::WHvCancelRunVirtualProcessor(part, vp, 0) })
}

/// A Windows handle wrapper that closes on drop.
#[derive(Debug)]
pub(crate) struct OwnedHandle(pub HANDLE);

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: closes the handle this wrapper owns.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}
