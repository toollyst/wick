// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The WHP instruction emulator, used to complete the MMIO (and string/`rep`
//! port I/O) accesses that leave the guest through `WHvRunVirtualProcessor`.
//!
//! WHP reports a memory or I/O intercept but does not decode the faulting
//! instruction. `WHvEmulatorTryMmioEmulation` / `WHvEmulatorTryIoEmulation`
//! decode it and drive it through callbacks here. The device I/O itself lives
//! in Firecracker, reached only through `VcpuExit`, so the completion mirrors
//! KVM's re-execution model:
//! - a **write** is captured in the memory/I/O callback (which has the data),
//!   the emulator is allowed to finish so `RIP` advances, and the captured
//!   write is handed to Firecracker as `VcpuExit::Mmio*`/`Io*`;
//! - a **read** has no data yet, so the callback aborts the emulation (leaving
//!   `RIP` in place) and the access is handed to Firecracker; Firecracker fills
//!   the buffer, the instruction re-executes, and this time the callback has
//!   the data and the emulator finishes.
//!
//! The callbacks reach the vCPU through a `*mut EmuCtx` passed as the WHP
//! context pointer; `EmuCtx` carries the partition/vCPU, an 8-byte data
//! scratch (the `kvm_run` MMIO data area, so returned slices stay valid), and
//! the captured access.

use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{E_FAIL, S_OK};
use super::whv::{
    self as whv, WHV_EMULATOR_IO_ACCESS_INFO, WHV_EMULATOR_MEMORY_ACCESS_INFO,
    WHV_EMULATOR_STATUS, WHV_MEMORY_ACCESS_CONTEXT, WHV_PARTITION_HANDLE, WHV_REGISTER_NAME,
    WHV_REGISTER_VALUE, WHV_TRANSLATE_GVA_RESULT, WHV_VP_EXIT_CONTEXT,
    WHV_X64_IO_PORT_ACCESS_CONTEXT,
};

use super::ffi;
use super::Result;

/// The outcome of an emulation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A write was captured (its bytes are in the scratch buffer).
    Write { addr: u64, len: usize, mmio: bool },
    /// A read needs data from Firecracker before the instruction can finish.
    Read { addr: u64, len: usize, mmio: bool },
    /// The emulator finished the instruction (RIP advanced).
    Completed,
    /// The emulator could not make progress.
    Failed,
}

/// State shared with the WHP emulator callbacks for one emulation attempt.
#[repr(C)]
struct EmuCtx {
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    /// 8-byte scratch backing the access data (the `kvm_run` MMIO data area).
    data: *mut u8,
    /// `-1` none, `0` read, `1` write.
    exit_kind: i8,
    exit_len: u32,
    exit_addr: u64,
    exit_mmio: bool,
    /// Whether a read's completion data is already in `data`.
    have_completion: bool,
}

/// A send-safe wrapper over the process-wide emulator handle.
#[derive(Clone, Copy)]
struct EmuHandle(*mut core::ffi::c_void);
// SAFETY: the WHP emulator handle may be used from any thread.
unsafe impl Send for EmuHandle {}
unsafe impl Sync for EmuHandle {}

/// The process-wide emulator (its callbacks are stateless; per-call state is
/// passed as the context pointer).
fn emulator() -> Result<*mut core::ffi::c_void> {
    static EMU: OnceLock<Result<EmuHandle>> = OnceLock::new();
    EMU.get_or_init(|| {
        let callbacks = whv::WHV_EMULATOR_CALLBACKS {
            Size: u32::try_from(std::mem::size_of::<whv::WHV_EMULATOR_CALLBACKS>()).unwrap(),
            Reserved: 0,
            WHvEmulatorIoPortCallback: Some(io_cb),
            WHvEmulatorMemoryCallback: Some(mem_cb),
            WHvEmulatorGetVirtualProcessorRegisters: Some(get_regs_cb),
            WHvEmulatorSetVirtualProcessorRegisters: Some(set_regs_cb),
            WHvEmulatorTranslateGvaPage: Some(translate_cb),
        };
        let mut handle: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: valid callbacks and out-pointer.
        ffi::hr(unsafe { whv::WHvEmulatorCreateEmulator(&callbacks, &mut handle) })?;
        Ok(EmuHandle(handle))
    })
    .as_ref()
    .map(|h| h.0)
    .map_err(|e| *e)
}

/// Emulates the MMIO instruction that caused `mem`. `scratch` is an 8-byte
/// buffer holding, for a read completion, the data Firecracker supplied.
pub(crate) fn mmio(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    vpctx: &WHV_VP_EXIT_CONTEXT,
    mem: &WHV_MEMORY_ACCESS_CONTEXT,
    scratch: *mut u8,
    have_completion: bool,
) -> Result<Outcome> {
    let emu = emulator()?;
    let mut ctx = EmuCtx {
        part,
        vp,
        data: scratch,
        exit_kind: -1,
        exit_len: 0,
        exit_addr: 0,
        exit_mmio: true,
        have_completion,
    };
    let mut status: WHV_EMULATOR_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: valid emulator, context and exit structures.
    let hres = unsafe {
        whv::WHvEmulatorTryMmioEmulation(
            emu,
            (&raw mut ctx).cast(),
            vpctx,
            mem,
            &mut status,
        )
    };
    Ok(interpret(&ctx, hres))
}

/// Emulates the string/`rep` port-I/O instruction that caused `io`.
pub(crate) fn io(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    vpctx: &WHV_VP_EXIT_CONTEXT,
    io: &WHV_X64_IO_PORT_ACCESS_CONTEXT,
    scratch: *mut u8,
    have_completion: bool,
) -> Result<Outcome> {
    let emu = emulator()?;
    let mut ctx = EmuCtx {
        part,
        vp,
        data: scratch,
        exit_kind: -1,
        exit_len: 0,
        exit_addr: 0,
        exit_mmio: false,
        have_completion,
    };
    let mut status: WHV_EMULATOR_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: valid emulator, context and exit structures.
    let hres = unsafe {
        whv::WHvEmulatorTryIoEmulation(
            emu,
            (&raw mut ctx).cast(),
            vpctx,
            io,
            &mut status,
        )
    };
    Ok(interpret(&ctx, hres))
}

/// Turns the post-call context into an [`Outcome`].
fn interpret(ctx: &EmuCtx, hres: i32) -> Outcome {
    match ctx.exit_kind {
        1 => Outcome::Write {
            addr: ctx.exit_addr,
            len: ctx.exit_len as usize,
            mmio: ctx.exit_mmio,
        },
        0 => Outcome::Read {
            addr: ctx.exit_addr,
            len: ctx.exit_len as usize,
            mmio: ctx.exit_mmio,
        },
        _ if hres == S_OK => Outcome::Completed,
        _ => Outcome::Failed,
    }
}

// ---- callbacks ----

unsafe extern "system" fn mem_cb(
    context: *const core::ffi::c_void,
    access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
) -> i32 {
    // SAFETY: `context` is the `EmuCtx` passed to the Try*Emulation call.
    let ctx = unsafe { &mut *(context as *mut EmuCtx) };
    let a = unsafe { &mut *access };
    let size = (a.AccessSize as usize).min(8);
    if a.Direction == 1 {
        // Write: capture the bytes and let the emulator finish.
        unsafe { std::ptr::copy_nonoverlapping(a.Data.as_ptr(), ctx.data, size) };
        ctx.exit_kind = 1;
        ctx.exit_len = size as u32;
        ctx.exit_addr = a.GpaAddress;
        ctx.exit_mmio = true;
        S_OK
    } else if ctx.have_completion {
        // Read completion: hand the supplied data to the emulator.
        unsafe { std::ptr::copy_nonoverlapping(ctx.data, a.Data.as_mut_ptr(), size) };
        S_OK
    } else {
        // Read with no data yet: abort so RIP does not advance.
        ctx.exit_kind = 0;
        ctx.exit_len = size as u32;
        ctx.exit_addr = a.GpaAddress;
        ctx.exit_mmio = true;
        E_FAIL
    }
}

unsafe extern "system" fn io_cb(
    context: *const core::ffi::c_void,
    access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
) -> i32 {
    // SAFETY: `context` is the `EmuCtx` passed to the Try*Emulation call.
    let ctx = unsafe { &mut *(context as *mut EmuCtx) };
    let a = unsafe { &mut *access };
    let size = (a.AccessSize as usize).min(4);
    if a.Direction == 1 {
        let bytes = a.Data.to_le_bytes();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ctx.data, size) };
        ctx.exit_kind = 1;
        ctx.exit_len = size as u32;
        ctx.exit_addr = u64::from(a.Port);
        ctx.exit_mmio = false;
        S_OK
    } else if ctx.have_completion {
        let mut bytes = [0u8; 4];
        unsafe { std::ptr::copy_nonoverlapping(ctx.data, bytes.as_mut_ptr(), size) };
        a.Data = u32::from_le_bytes(bytes);
        S_OK
    } else {
        ctx.exit_kind = 0;
        ctx.exit_len = size as u32;
        ctx.exit_addr = u64::from(a.Port);
        ctx.exit_mmio = false;
        E_FAIL
    }
}

unsafe extern "system" fn get_regs_cb(
    context: *const core::ffi::c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *mut WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: context is the EmuCtx; the arrays have `count` elements.
    let ctx = unsafe { &*(context as *const EmuCtx) };
    unsafe {
        whv::WHvGetVirtualProcessorRegisters(ctx.part, ctx.vp, names, count, values)
    }
}

unsafe extern "system" fn set_regs_cb(
    context: *const core::ffi::c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *const WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: context is the EmuCtx; the arrays have `count` elements.
    let ctx = unsafe { &*(context as *const EmuCtx) };
    unsafe {
        whv::WHvSetVirtualProcessorRegisters(ctx.part, ctx.vp, names, count, values)
    }
}

unsafe extern "system" fn translate_cb(
    context: *const core::ffi::c_void,
    gva: u64,
    flags: whv::WHV_TRANSLATE_GVA_FLAGS,
    result_code: *mut whv::WHV_TRANSLATE_GVA_RESULT_CODE,
    gpa: *mut u64,
) -> i32 {
    // SAFETY: context is the EmuCtx; out-pointers are valid.
    let ctx = unsafe { &*(context as *const EmuCtx) };
    let mut result: WHV_TRANSLATE_GVA_RESULT = unsafe { std::mem::zeroed() };
    let hres = unsafe {
        whv::WHvTranslateGva(ctx.part, ctx.vp, gva, flags, &mut result, gpa)
    };
    if hres == S_OK {
        unsafe { *result_code = result.ResultCode };
    }
    hres
}
