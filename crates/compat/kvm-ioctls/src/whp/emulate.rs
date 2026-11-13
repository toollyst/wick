// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The WHP instruction emulator, used to complete the MMIO accesses that
//! leave the guest through `WHvRunVirtualProcessor`. (String port I/O is
//! done by the run loop itself, as KVM's emulator does it: `VcpuFd::string_io`.)
//!
//! WHP reports a memory intercept but does not decode the faulting
//! instruction. `WHvEmulatorTryMmioEmulation` decodes it and drives it
//! through callbacks here.
//!
//! The memory callback is called for every memory operand of the
//! instruction, not only the one that left the guest (Microsoft Learn,
//! "WHV_EMULATOR_MEMORY_ACCESS_INFO": the guest physical address, the
//! direction, a size of 1 to 8 bytes and the data, read or to write). An
//! address a memory slot backs is guest RAM and is read and written there
//! (`movs` between a device and RAM, a `push` of a device register): only
//! an address no slot backs, or a write to a read-only slot, is the
//! device's, as KVM's emulator reads and writes RAM through
//! `kvm_read_guest`/`kvm_write_guest` and exits only for the rest. Before,
//! every operand was taken for the device's: RAM read through a string was
//! asked of Firecracker as an MMIO read, and RAM written was handed to it
//! as an MMIO write and never reached the guest's memory. The device I/O itself lives
//! in Firecracker, reached only through `VcpuExit`, so the completion mirrors
//! KVM's re-execution model:
//! - a **write** is captured in the memory/I/O callback (which has the data),
//!   the emulator is allowed to finish so `RIP` advances, and the captured
//!   write is handed to Firecracker as `VcpuExit::Mmio*`/`Io*`;
//! - a **read** has no data yet, so the callback aborts the emulation (leaving
//!   `RIP` in place) and the access is handed to Firecracker. At the vCPU's
//!   next run, before any entry into the guest and before a kick is looked
//!   at, the instruction is emulated again from the same exit's contexts,
//!   now with the data of every device read it asked for, in order
//!   ([`DeviceRead`]), and finishes in the host, as KVM's
//!   `complete_emulated_mmio` finishes it (`kvm_arch_vcpu_ioctl_run` runs
//!   `complete_userspace_io` before its `immediate_exit` check; Linux v6.1
//!   arch/x86/kvm/x86.c). An instruction with a second device read (two
//!   operands, or an access the emulator splits) exits again for it, as
//!   KVM's does for each of its `mmio_fragments`. Before, the instruction
//!   re-executed in the guest and the data went to the first device read
//!   of whatever ran: an interrupt taken at the entry, or the same
//!   instruction's first read when it had two, which then asked for its
//!   second again on every run; and a kick before the entry lost the data,
//!   so the device was read twice.
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
    /// A device read other than the one the next of the given reads was
    /// for (the instruction's state changed between its exit and its
    /// completion): `asked`, and what the read given was for.
    Mismatch { asked: (u64, usize), given: (u64, usize) },
}

pub(crate) use super::exit::DeviceRead;

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
    /// The device reads already answered, handed out in order
    /// (`reads_len` of them at `reads`; `next_read` is the next one).
    reads: *const DeviceRead,
    reads_len: usize,
    next_read: usize,
    /// A device read that did not match the next given one: what was asked.
    mismatch: Option<(u64, usize)>,
    /// The VM's memory slots: what is RAM.
    ram: *const super::pvclock::Ram,
    /// Device writes of this instruction after its first, in order (a
    /// `rep movs` to a device, if the emulator does several elements in
    /// one call): the run loop hands them to Firecracker one exit each.
    more: *mut Vec<DeviceWrite>,
}

/// A write to a device captured after an instruction's first.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeviceWrite {
    pub addr: u64,
    pub len: usize,
    pub data: [u8; 8],
}

/// An emulator handle, destroyed with the thread that made it.
struct EmuHandle(*mut core::ffi::c_void);

impl Drop for EmuHandle {
    fn drop(&mut self) {
        // SAFETY: an emulator this thread created and no longer uses.
        unsafe { whv::WHvEmulatorDestroyEmulator(self.0) };
    }
}

/// This thread's emulator. An emulator instance holds the state of the
/// instruction it is emulating and is not safe to share: one per vCPU
/// thread, as QEMU's WHPX keeps one per vCPU. A process-wide one, shared by
/// two vCPUs emulating MMIO at once, completed one vCPU's instruction with
/// the other's state (a guest with 2 vCPUs and an Async drive had its
/// kernel memory corrupted within seconds; 1 vCPU never did). `vp` is the
/// vCPU the thread runs, for the trace.
fn emulator(vp: u32) -> Result<*mut core::ffi::c_void> {
    thread_local! {
        static EMU: OnceLock<Result<EmuHandle>> = const { OnceLock::new() };
    }
    EMU.with(|emu| emu.get_or_init(|| {
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
        #[cfg(any(test, feature = "whp-trace"))]
        let before = ffi::trace::stack();
        // SAFETY: valid callbacks and out-pointer.
        let hres = unsafe { whv::WHvEmulatorCreateEmulator(&callbacks, &mut handle) };
        #[cfg(any(test, feature = "whp-trace"))]
        ffi::trace::note("WHvEmulatorCreateEmulator", vp, &[], None, before, hres);
        #[cfg(not(any(test, feature = "whp-trace")))]
        let _ = vp;
        ffi::hr(hres)?;
        Ok(EmuHandle(handle))
    })
    .as_ref()
    .map(|h| h.0)
    .map_err(|e| *e))
}

/// Emulates the MMIO instruction that caused `mem`. `reads` are the device
/// reads of the instruction already answered, in the order the emulator
/// asks for them; a device read past them aborts the emulation
/// ([`Outcome::Read`]). `scratch` is an 8-byte buffer that takes the first
/// device write's data. `ram` is the VM's slot table; device writes after
/// the instruction's first are added to `more`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mmio(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    vpctx: &WHV_VP_EXIT_CONTEXT,
    mem: &WHV_MEMORY_ACCESS_CONTEXT,
    scratch: *mut u8,
    reads: &[DeviceRead],
    ram: &super::pvclock::Ram,
    more: &mut Vec<DeviceWrite>,
) -> Result<Outcome> {
    let emu = emulator(vp)?;
    let mut ctx = EmuCtx {
        part,
        vp,
        data: scratch,
        exit_kind: -1,
        exit_len: 0,
        exit_addr: 0,
        exit_mmio: true,
        reads: reads.as_ptr(),
        reads_len: reads.len(),
        next_read: 0,
        mismatch: None,
        ram,
        more,
    };
    let mut status: WHV_EMULATOR_STATUS = unsafe { std::mem::zeroed() };
    // Traced as one call, the callbacks' within it on their own: this
    // runs on the vCPU thread's stack, the emulator's frames and ours.
    #[cfg(any(test, feature = "whp-trace"))]
    let before = ffi::trace::stack();
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
    #[cfg(any(test, feature = "whp-trace"))]
    ffi::trace::note("WHvEmulatorTryMmioEmulation", vp, &[], None, before, hres);
    Ok(interpret(&ctx, hres))
}

/// Turns the post-call context into an [`Outcome`].
fn interpret(ctx: &EmuCtx, hres: i32) -> Outcome {
    if let Some(asked) = ctx.mismatch {
        // SAFETY: `next_read` < `reads_len` when a mismatch is recorded.
        let given = unsafe { &*ctx.reads.add(ctx.next_read) };
        return Outcome::Mismatch { asked, given: (given.addr, given.len) };
    }
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
    // SAFETY: the slot table the caller of `mmio` holds for the call.
    let ram = unsafe { &*ctx.ram };
    if a.Direction == 1 {
        // Guest RAM: written there (and marked dirty), nothing for a device.
        if super::guest_mem::write(&mut ram.lock().unwrap(), a.GpaAddress, &a.Data[..size]) {
            return S_OK;
        }
        if ctx.exit_kind == 1 {
            // A further device write of the same instruction.
            let mut data = [0u8; 8];
            data[..size].copy_from_slice(&a.Data[..size]);
            // SAFETY: the list the caller of `mmio` holds for the call.
            unsafe { &mut *ctx.more }.push(DeviceWrite { addr: a.GpaAddress, len: size, data });
            return S_OK;
        }
        // Write: capture the bytes and let the emulator finish.
        unsafe { std::ptr::copy_nonoverlapping(a.Data.as_ptr(), ctx.data, size) };
        ctx.exit_kind = 1;
        ctx.exit_len = size as u32;
        ctx.exit_addr = a.GpaAddress;
        ctx.exit_mmio = true;
        return S_OK;
    }
    // Guest RAM: read there.
    let mut bytes = [0u8; 8];
    if super::guest_mem::read(&mut ram.lock().unwrap(), a.GpaAddress, &mut bytes[..size]) {
        a.Data[..size].copy_from_slice(&bytes[..size]);
        return S_OK;
    }
    // SAFETY: the caller's slice of `reads_len` reads, held for the call.
    let reads = unsafe { std::slice::from_raw_parts(ctx.reads, ctx.reads_len) };
    match super::exit::answer_read(reads, &mut ctx.next_read, a.GpaAddress, size) {
        super::exit::ReadAnswer::Data(data) => {
            a.Data[..size].copy_from_slice(&data[..size]);
            S_OK
        }
        super::exit::ReadAnswer::Mismatch => {
            ctx.mismatch = Some((a.GpaAddress, size));
            E_FAIL
        }
        super::exit::ReadAnswer::Ask => {
            // Read with no data yet: abort so RIP does not advance.
            ctx.exit_kind = 0;
            ctx.exit_len = size as u32;
            ctx.exit_addr = a.GpaAddress;
            ctx.exit_mmio = true;
            E_FAIL
        }
    }
}

/// The emulator is given a port callback, and is never asked to emulate
/// port I/O (`VcpuFd::string_io` does the string instructions): an
/// instruction that reaches it is refused.
unsafe extern "system" fn io_cb(
    _context: *const core::ffi::c_void,
    _access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
) -> i32 {
    E_FAIL
}

unsafe extern "system" fn get_regs_cb(
    context: *const core::ffi::c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *mut WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: context is the EmuCtx; the arrays have `count` elements.
    let ctx = unsafe { &*(context as *const EmuCtx) };
    #[cfg(any(test, feature = "whp-trace"))]
    let before = super::ffi::trace::stack();
    let hres = unsafe {
        whv::WHvGetVirtualProcessorRegisters(ctx.part, ctx.vp, names, count, values)
    };
    #[cfg(any(test, feature = "whp-trace"))]
    super::ffi::trace::note(
        "the emulator's WHvGetVirtualProcessorRegisters",
        ctx.vp,
        // SAFETY: the emulator's array of `count` names.
        unsafe { std::slice::from_raw_parts(names, count as usize) },
        None,
        before,
        hres,
    );
    hres
}

unsafe extern "system" fn set_regs_cb(
    context: *const core::ffi::c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *const WHV_REGISTER_VALUE,
) -> i32 {
    // SAFETY: context is the EmuCtx; the arrays have `count` elements.
    let ctx = unsafe { &*(context as *const EmuCtx) };
    #[cfg(any(test, feature = "whp-trace"))]
    let before = super::ffi::trace::stack();
    let hres = unsafe {
        whv::WHvSetVirtualProcessorRegisters(ctx.part, ctx.vp, names, count, values)
    };
    #[cfg(any(test, feature = "whp-trace"))]
    super::ffi::trace::note(
        "the emulator's WHvSetVirtualProcessorRegisters",
        ctx.vp,
        // SAFETY: the emulator's arrays of `count` names and values.
        unsafe { std::slice::from_raw_parts(names, count as usize) },
        Some(unsafe { std::slice::from_raw_parts(values, count as usize) }),
        before,
        hres,
    );
    hres
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
    #[cfg(any(test, feature = "whp-trace"))]
    let before = super::ffi::trace::stack();
    let hres = unsafe {
        whv::WHvTranslateGva(ctx.part, ctx.vp, gva, flags, &mut result, gpa)
    };
    #[cfg(any(test, feature = "whp-trace"))]
    super::ffi::trace::note("the emulator's WHvTranslateGva", ctx.vp, &[], None, before, hres);
    if hres == S_OK {
        unsafe { *result_code = result.ResultCode };
    }
    hres
}
