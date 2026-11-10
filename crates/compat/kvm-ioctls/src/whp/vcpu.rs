// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The WHP virtual processor behind `VcpuFd`: the run loop and the vCPU state
//! accessors Firecracker drives.
//!
//! `run` enters the guest with `WHvRunVirtualProcessor` and turns each WHP
//! intercept into the KVM exit Firecracker expects:
//! - **port I/O**: a simple `IN`/`OUT` is completed from the exit context (its
//!   data is in `RAX`); the I/O-APIC-adjacent PIC/PIT/ELCR ports and matching
//!   `ioeventfd`s are consumed here, everything else becomes `VcpuExit::Io*`;
//!   string/`rep` I/O goes through the instruction emulator ([`super::emulate`]);
//! - **MMIO**: the instruction is decoded by the emulator; I/O APIC accesses
//!   and matching `ioeventfd`s are consumed here, everything else becomes
//!   `VcpuExit::Mmio*`. A read is completed on the instruction's re-execution,
//!   exactly as KVM does;
//! - **CPUID** and **MSR** intercepts are answered from the per-vCPU CPUID
//!   table Firecracker installed and from the register mapping in
//!   [`super::regs`];
//! - **HLT** becomes `VcpuExit::Hlt`; a cancelled run (the immediate-exit kick)
//!   becomes `EINTR`; triple faults and unrecoverable exits become
//!   `VcpuExit::Shutdown` / `VcpuExit::InternalError`.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};

use wick_os::fd::{AsRawFd, RawFd};
use kvm_bindings::{
    kvm_cpuid_entry2, kvm_debugregs, kvm_fpu, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_run,
    kvm_sregs, kvm_vcpu_events, kvm_xcrs, kvm_xsave, CpuId, Msrs, Xsave,
};
use vmm_sys_util::errno::Error;
use windows_sys::Win32::System::Hypervisor as whv;
use windows_sys::Win32::System::Hypervisor::WHV_PARTITION_HANDLE;

use super::vm::VmInner;
use super::{emulate, err, regs, Handle, IoEventAddress, Result, VcpuExit};

/// A heap-allocated `kvm_run`, shared (as KVM's `mmap` of the vCPU fd is)
/// through [`super::KvmRunWrapper`].
pub(crate) struct KvmRunPage(Box<UnsafeCell<kvm_run>>);

// SAFETY: access is synchronised by the owning vCPU's run loop and the single
// writer of the immediate-exit byte, matching KVM's shared-mapping model.
unsafe impl Send for KvmRunPage {}
unsafe impl Sync for KvmRunPage {}

impl KvmRunPage {
    fn new() -> Self {
        // SAFETY: `kvm_run` is plain data; a zeroed value is valid.
        KvmRunPage(Box::new(UnsafeCell::new(unsafe { std::mem::zeroed() })))
    }

    pub(crate) fn ptr(&self) -> *mut kvm_run {
        self.0.get()
    }
}

impl std::fmt::Debug for KvmRunPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvmRunPage").finish()
    }
}

/// A read deferred to the instruction's re-execution.
#[derive(Debug, Clone, Copy)]
enum Pending {
    /// An MMIO read: completed by the emulator on re-execution.
    Mmio,
    /// A port-I/O `IN`: completed directly by writing `RAX` and advancing.
    PioIn { len: usize, rip_after: u64, rax: u64 },
}

/// State shared between a vCPU's handles and its run loop.
pub(crate) struct VcpuShared {
    pub(crate) index: u32,
    pub(crate) part: WHV_PARTITION_HANDLE,
    handle: Handle,
    pub(crate) run: KvmRunPage,
    inner: Arc<VmInner>,
    cpuid: Mutex<Vec<kvm_cpuid_entry2>>,
    pending: Mutex<Option<Pending>>,
    tsc_khz: AtomicU64,
    /// Mirror of `kvm_run.immediate_exit`, written from any thread.
    immediate_exit: AtomicU8,
}

// SAFETY: the partition handle is thread-agnostic; everything else is behind a
// lock or an atomic.
unsafe impl Send for VcpuShared {}
unsafe impl Sync for VcpuShared {}

impl std::fmt::Debug for VcpuShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VcpuShared")
            .field("index", &self.index)
            .finish()
    }
}

/// The live vCPUs, so a `kvm_run` can be found from a descriptor.
static ALL_VCPUS: Mutex<Vec<Weak<VcpuShared>>> = Mutex::new(Vec::new());

/// Finds the shared state of the vCPU whose handle is `fd`.
pub(crate) fn vcpu_by_descriptor(fd: RawFd) -> Option<Arc<VcpuShared>> {
    let vcpus = ALL_VCPUS.lock().unwrap();
    vcpus
        .iter()
        .filter_map(Weak::upgrade)
        .find(|v| v.handle.as_raw_fd() == fd)
}

/// Creates vCPU `id` in `inner`'s partition.
pub(crate) fn create(inner: Arc<VmInner>, id: u64) -> Result<VcpuFd> {
    let index = u32::try_from(id).map_err(|_| Error::new(libc::EINVAL))?;
    // SAFETY: creates a virtual processor in this VM's partition.
    super::ffi::hr(unsafe { whv::WHvCreateVirtualProcessor(inner.part, index, 0) })?;
    let handle = Handle::new()?;
    let shared = Arc::new(VcpuShared {
        index,
        part: inner.part,
        handle,
        run: KvmRunPage::new(),
        inner: inner.clone(),
        cpuid: Mutex::new(Vec::new()),
        pending: Mutex::new(None),
        tsc_khz: AtomicU64::new(0),
        immediate_exit: AtomicU8::new(0),
    });
    {
        let mut vcpus = ALL_VCPUS.lock().unwrap();
        vcpus.retain(|w| w.strong_count() > 0);
        vcpus.push(Arc::downgrade(&shared));
    }
    inner.vcpus.lock().unwrap().push(Arc::downgrade(&shared));
    Ok(VcpuFd { shared })
}

/// Wrapper over a WHP virtual processor.
#[derive(Debug)]
pub struct VcpuFd {
    shared: Arc<VcpuShared>,
}

impl VcpuFd {
    fn part(&self) -> WHV_PARTITION_HANDLE {
        self.shared.part
    }
    fn vp(&self) -> u32 {
        self.shared.index
    }

    // ---- register state (delegated to `regs`) ----

    pub fn get_regs(&self) -> Result<kvm_regs> {
        regs::get_regs(self.part(), self.vp())
    }
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        regs::set_regs(self.part(), self.vp(), regs)
    }
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        regs::get_sregs(self.part(), self.vp())
    }
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        regs::set_sregs(self.part(), self.vp(), sregs)
    }
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        regs::get_fpu(self.part(), self.vp())
    }
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        regs::set_fpu(self.part(), self.vp(), fpu)
    }
    pub fn get_xcrs(&self) -> Result<kvm_xcrs> {
        regs::get_xcrs(self.part(), self.vp())
    }
    pub fn set_xcrs(&self, xcrs: &kvm_xcrs) -> Result<()> {
        regs::set_xcrs(self.part(), self.vp(), xcrs)
    }
    pub fn get_debug_regs(&self) -> Result<kvm_debugregs> {
        regs::get_debugregs(self.part(), self.vp())
    }
    pub fn set_debug_regs(&self, debug_regs: &kvm_debugregs) -> Result<()> {
        regs::set_debugregs(self.part(), self.vp(), debug_regs)
    }
    pub fn get_mp_state(&self) -> Result<kvm_mp_state> {
        regs::get_mp_state(self.part(), self.vp())
    }
    pub fn set_mp_state(&self, mp_state: kvm_mp_state) -> Result<()> {
        regs::set_mp_state(self.part(), self.vp(), mp_state)
    }

    /// # Safety
    /// Matches kvm-ioctls: the XSAVE region must be a valid XSAVE image.
    pub unsafe fn get_xsave(&self) -> Result<kvm_xsave> {
        regs::get_xsave(self.part(), self.vp())
    }
    /// # Safety
    /// As [`Self::get_xsave`].
    pub unsafe fn set_xsave(&self, xsave: &kvm_xsave) -> Result<()> {
        regs::set_xsave(self.part(), self.vp(), xsave)
    }
    /// # Safety
    /// As [`Self::get_xsave`].
    pub unsafe fn get_xsave2(&self, xsave: &mut Xsave) -> Result<()> {
        let got = regs::get_xsave(self.part(), self.vp())?;
        // SAFETY: the wrapper owns a `kvm_xsave2` header to write into.
        unsafe { (*xsave.as_mut_fam_struct_ptr()).xsave = got };
        Ok(())
    }
    /// # Safety
    /// As [`Self::get_xsave`].
    pub unsafe fn set_xsave2(&self, xsave: &Xsave) -> Result<()> {
        let inner = &xsave.as_fam_struct_ref().xsave;
        regs::set_xsave(self.part(), self.vp(), inner)
    }

    // ---- MSRs and CPUID ----

    pub fn get_msrs(&self, msrs: &mut Msrs) -> Result<usize> {
        regs::get_msrs(self.part(), self.vp(), msrs)
    }
    pub fn set_msrs(&self, msrs: &Msrs) -> Result<usize> {
        regs::set_msrs(self.part(), self.vp(), msrs)
    }

    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        *self.shared.cpuid.lock().unwrap() = cpuid.as_slice().to_vec();
        Ok(())
    }
    pub fn get_cpuid2(&self, num_entries: usize) -> Result<CpuId> {
        let entries = self.shared.cpuid.lock().unwrap();
        if entries.len() > num_entries {
            return err(libc::E2BIG);
        }
        CpuId::from_entries(&entries).map_err(|_| Error::new(libc::EINVAL))
    }

    // ---- TSC / clock ----

    pub fn get_tsc_khz(&self) -> Result<u32> {
        let v = self.shared.tsc_khz.load(Ordering::Relaxed);
        if v == 0 {
            // Not queryable from WHP; the caller treats this as "unknown".
            err(libc::ENOTSUP)
        } else {
            Ok(v as u32)
        }
    }
    pub fn set_tsc_khz(&self, freq: u32) -> Result<()> {
        // WHP runs the guest TSC at the host rate; the requested frequency is
        // recorded for `get_tsc_khz`. Cross-host TSC scaling is not applied.
        self.shared.tsc_khz.store(u64::from(freq), Ordering::Relaxed);
        Ok(())
    }

    /// No paravirtual clock to pause, so nothing to do.
    pub fn kvmclock_ctrl(&self) -> Result<()> {
        Ok(())
    }

    // ---- LAPIC ----

    /// Reads the local APIC register page. The xAPIC interrupt-controller
    /// state WHP returns is the architectural APIC register page, which is
    /// what `kvm_lapic_state` holds.
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut state = kvm_lapic_state { regs: [0; 1024] };
        let mut written = 0u32;
        // SAFETY: valid output buffer of the given size.
        super::ffi::hr(unsafe {
            whv::WHvGetVirtualProcessorInterruptControllerState(
                self.part(),
                self.vp(),
                state.regs.as_mut_ptr().cast(),
                1024,
                &mut written,
            )
        })?;
        Ok(state)
    }
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        // SAFETY: the register page is valid for its size.
        super::ffi::hr(unsafe {
            whv::WHvSetVirtualProcessorInterruptControllerState(
                self.part(),
                self.vp(),
                klapic.regs.as_ptr().cast(),
                1024,
            )
        })
    }

    // ---- vCPU events ----

    /// WHP delivers interrupts through its own local APIC, so at a quiescent
    /// save point there are no pending events to report.
    pub fn get_vcpu_events(&self) -> Result<kvm_vcpu_events> {
        // SAFETY: a zeroed `kvm_vcpu_events` is a valid "nothing pending".
        Ok(unsafe { std::mem::zeroed() })
    }
    pub fn set_vcpu_events(&self, _events: &kvm_vcpu_events) -> Result<()> {
        Ok(())
    }

    // ---- run control ----

    pub fn get_kvm_run(&mut self) -> &mut kvm_run {
        // SAFETY: the run loop and this accessor are on the owning thread.
        unsafe { &mut *self.shared.run.ptr() }
    }

    /// Sets the immediate-exit flag; a `1` also cancels an in-flight run so the
    /// kick works without a POSIX signal.
    pub fn set_kvm_immediate_exit(&mut self, val: u8) {
        self.shared.immediate_exit.store(val, Ordering::Release);
        // SAFETY: single-byte write to the shared `kvm_run`, as KVM's mmap.
        unsafe { (*self.shared.run.ptr()).immediate_exit = val };
        if val == 1 {
            let _ = super::ffi::cancel_run(self.part(), self.vp());
        }
    }

    /// Runs the vCPU until the next exit.
    pub fn run(&mut self) -> Result<VcpuExit<'_>> {
        let part = self.part();
        let vp = self.vp();
        let run_ptr = self.shared.run.ptr();
        // Scratch for exit data (the MMIO data area of `kvm_run`); all returned
        // byte slices point here and stay valid until the next `run`.
        let scratch = unsafe { (*run_ptr).__bindgen_anon_1.mmio.data.as_mut_ptr() };

        // Complete a read deferred from the previous exit.
        let mut mmio_completion = false;
        if let Some(pending) = self.shared.pending.lock().unwrap().take() {
            match pending {
                Pending::Mmio => mmio_completion = true,
                Pending::PioIn {
                    len,
                    rip_after,
                    rax,
                } => {
                    // Firecracker wrote the input bytes into the scratch slice.
                    let value = read_scratch(scratch, len);
                    let merged = merge_reg(rax, value, len);
                    regs::set_gpr_rax_rip(part, vp, merged, rip_after)?;
                }
            }
        }

        loop {
            if self.shared.immediate_exit.load(Ordering::Acquire) != 0 {
                return err(libc::EINTR);
            }
            let ctx = super::ffi::run_vp(part, vp)?;
            let instr_len = u64::from(ctx.VpContext._bitfield & 0x0f);
            let rip = ctx.VpContext.Rip;

            match ctx.ExitReason {
                whv::WHvRunVpExitReasonNone => continue,
                whv::WHvRunVpExitReasonCanceled => return err(libc::EINTR),
                whv::WHvRunVpExitReasonX64Halt => return Ok(VcpuExit::Hlt),

                whv::WHvRunVpExitReasonX64IoPortAccess => {
                    // SAFETY: the union arm matches the exit reason.
                    let io = unsafe { ctx.Anonymous.IoPortAccess };
                    // SAFETY: the access-info bitfield overlaps the u32.
                    let info = unsafe { io.AccessInfo.AsUINT32 };
                    let is_write = info & 1 != 0;
                    let size = ((info >> 1) & 0x7) as usize;
                    let string = (info >> 4) & 1 != 0;
                    let rep = (info >> 5) & 1 != 0;
                    let port = io.PortNumber;

                    if string || rep {
                        if let Some(exit) =
                            self.string_io(&ctx.VpContext, &io, scratch, &mut mmio_completion)?
                        {
                            return Ok(exit);
                        }
                        continue;
                    }

                    if is_write {
                        write_scratch(scratch, io.Rax, size);
                        // PIC/PIT/ELCR ports are consumed by the irqchip.
                        {
                            let mut chip = self.shared.inner.irqchip.lock().unwrap();
                            if chip.pio_handles(port) {
                                let data = unsafe { slice(scratch, size) };
                                chip.pio_write(port, data, &self.shared.inner);
                                drop(chip);
                                regs::set_rip(part, vp, rip + instr_len)?;
                                continue;
                            }
                        }
                        // A matching ioeventfd consumes the write.
                        let data = unsafe { slice(scratch, size) };
                        if self
                            .shared
                            .inner
                            .match_ioevent(&IoEventAddress::Pio(u64::from(port)), data)
                        {
                            regs::set_rip(part, vp, rip + instr_len)?;
                            continue;
                        }
                        regs::set_rip(part, vp, rip + instr_len)?;
                        let data = unsafe { slice(scratch, size) };
                        return Ok(VcpuExit::IoOut(port, data));
                    }

                    // IN
                    {
                        let mut chip = self.shared.inner.irqchip.lock().unwrap();
                        if chip.pio_handles(port) {
                            let buf = unsafe { slice_mut(scratch, size) };
                            chip.pio_read(port, buf);
                            drop(chip);
                            let value = read_scratch(scratch, size);
                            let merged = merge_reg(io.Rax, value, size);
                            regs::set_gpr_rax_rip(part, vp, merged, rip + instr_len)?;
                            continue;
                        }
                    }
                    *self.shared.pending.lock().unwrap() = Some(Pending::PioIn {
                        len: size,
                        rip_after: rip + instr_len,
                        rax: io.Rax,
                    });
                    let buf = unsafe { slice_mut(scratch, size) };
                    return Ok(VcpuExit::IoIn(port, buf));
                }

                whv::WHvRunVpExitReasonMemoryAccess => {
                    // SAFETY: the union arm matches the exit reason.
                    let mem = unsafe { ctx.Anonymous.MemoryAccess };
                    if let Some(exit) = self.mmio(&ctx.VpContext, &mem, scratch, mmio_completion)? {
                        return Ok(exit);
                    }
                    mmio_completion = false;
                    continue;
                }

                whv::WHvRunVpExitReasonX64Cpuid => {
                    // SAFETY: the union arm matches the exit reason.
                    let c = unsafe { ctx.Anonymous.CpuidAccess };
                    self.handle_cpuid(&c, rip + instr_len)?;
                    continue;
                }

                whv::WHvRunVpExitReasonX64MsrAccess => {
                    // SAFETY: the union arm matches the exit reason.
                    let m = unsafe { ctx.Anonymous.MsrAccess };
                    self.handle_msr(&m, rip + instr_len)?;
                    continue;
                }

                whv::WHvRunVpExitReasonX64InterruptWindow
                | whv::WHvRunVpExitReasonX64ApicEoi => continue,

                whv::WHvRunVpExitReasonUnrecoverableException => return Ok(VcpuExit::Shutdown),

                _ => return Ok(VcpuExit::InternalError),
            }
        }
    }

    /// Handles an MMIO intercept. Returns the exit to report to Firecracker, or
    /// `None` if the access was consumed (I/O APIC or `ioeventfd`).
    fn mmio(
        &self,
        vpctx: &whv::WHV_VP_EXIT_CONTEXT,
        mem: &whv::WHV_MEMORY_ACCESS_CONTEXT,
        scratch: *mut u8,
        completion: bool,
    ) -> Result<Option<VcpuExit<'_>>> {
        let part = self.part();
        let vp = self.vp();
        match emulate::mmio(part, vp, vpctx, mem, scratch, completion)? {
            emulate::Outcome::Completed | emulate::Outcome::Failed => Ok(None),
            emulate::Outcome::Write { addr, len, .. } => {
                let mut chip = self.shared.inner.irqchip.lock().unwrap();
                if chip.mmio_handles(addr) {
                    let data = unsafe { slice(scratch, len) };
                    let inject = chip.mmio_write(addr, data);
                    drop(chip);
                    if let Some((a, d)) = inject {
                        self.shared.inner.inject_msi(a, d);
                    }
                    return Ok(None);
                }
                drop(chip);
                let data = unsafe { slice(scratch, len) };
                if self
                    .shared
                    .inner
                    .match_ioevent(&IoEventAddress::Mmio(addr), data)
                {
                    return Ok(None);
                }
                let data = unsafe { slice(scratch, len) };
                Ok(Some(VcpuExit::MmioWrite(addr, data)))
            }
            emulate::Outcome::Read { addr, len, .. } => {
                let mut chip = self.shared.inner.irqchip.lock().unwrap();
                if chip.mmio_handles(addr) {
                    let buf = unsafe { slice_mut(scratch, len) };
                    chip.mmio_read(addr, buf);
                    drop(chip);
                    // Re-run the emulator with the data now in the scratch.
                    let _ = emulate::mmio(part, vp, vpctx, mem, scratch, true)?;
                    return Ok(None);
                }
                drop(chip);
                // Defer to the instruction's re-execution with Firecracker's data.
                *self.shared.pending.lock().unwrap() = Some(Pending::Mmio);
                let buf = unsafe { slice_mut(scratch, len) };
                Ok(Some(VcpuExit::MmioRead(addr, buf)))
            }
        }
    }

    /// Handles string/`rep` port I/O through the emulator.
    fn string_io(
        &self,
        vpctx: &whv::WHV_VP_EXIT_CONTEXT,
        io: &whv::WHV_X64_IO_PORT_ACCESS_CONTEXT,
        scratch: *mut u8,
        _completion: &mut bool,
    ) -> Result<Option<VcpuExit<'_>>> {
        let part = self.part();
        let vp = self.vp();
        match emulate::io(part, vp, vpctx, io, scratch, false)? {
            emulate::Outcome::Completed | emulate::Outcome::Failed => Ok(None),
            emulate::Outcome::Write { addr, len, .. } => {
                let port = addr as u16;
                let data = unsafe { slice(scratch, len) };
                if self
                    .shared
                    .inner
                    .match_ioevent(&IoEventAddress::Pio(u64::from(port)), data)
                {
                    return Ok(None);
                }
                let data = unsafe { slice(scratch, len) };
                Ok(Some(VcpuExit::IoOut(port, data)))
            }
            emulate::Outcome::Read { addr, len, .. } => {
                // One element at a time; complete on re-execution.
                *self.shared.pending.lock().unwrap() = Some(Pending::Mmio);
                let port = addr as u16;
                let buf = unsafe { slice_mut(scratch, len) };
                Ok(Some(VcpuExit::IoIn(port, buf)))
            }
        }
    }

    /// Answers a CPUID intercept from the installed table (or WHP's default).
    fn handle_cpuid(
        &self,
        c: &whv::WHV_X64_CPUID_ACCESS_CONTEXT,
        rip_after: u64,
    ) -> Result<()> {
        let function = c.Rax as u32;
        let index = c.Rcx as u32;
        let (eax, ebx, ecx, edx) = {
            let table = self.shared.cpuid.lock().unwrap();
            table
                .iter()
                .find(|e| {
                    e.function == function
                        && (e.flags & kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX == 0
                            || e.index == index)
                })
                .map(|e| (e.eax, e.ebx, e.ecx, e.edx))
                .unwrap_or((
                    c.DefaultResultRax as u32,
                    c.DefaultResultRbx as u32,
                    c.DefaultResultRcx as u32,
                    c.DefaultResultRdx as u32,
                ))
        };
        regs::set_cpuid_result(self.part(), self.vp(), eax, ebx, ecx, edx, rip_after)
    }

    /// Answers an MSR intercept. WHP only exits for MSRs it does not model, so
    /// an unknown read returns 0 and an unknown write is ignored, as KVM does
    /// with `ignore_msrs`.
    fn handle_msr(
        &self,
        m: &whv::WHV_X64_MSR_ACCESS_CONTEXT,
        rip_after: u64,
    ) -> Result<()> {
        // SAFETY: the access-info bitfield overlaps the u32.
        let is_write = unsafe { m.AccessInfo.AsUINT32 } & 1 != 0;
        if is_write {
            regs::set_rip(self.part(), self.vp(), rip_after)
        } else {
            regs::set_msr_result(self.part(), self.vp(), 0, rip_after)
        }
    }
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.shared.handle.as_raw_fd()
    }
}

// ---- small helpers ----

/// A byte slice over the scratch buffer with the lifetime of the borrow.
///
/// # Safety
/// `len <= 8` and the scratch outlives the slice.
unsafe fn slice<'a>(scratch: *mut u8, len: usize) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(scratch, len.min(8)) }
}

/// # Safety
/// As [`slice`].
unsafe fn slice_mut<'a>(scratch: *mut u8, len: usize) -> &'a mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(scratch, len.min(8)) }
}

fn read_scratch(scratch: *mut u8, len: usize) -> u64 {
    let mut buf = [0u8; 8];
    let n = len.min(8);
    // SAFETY: the scratch holds at least 8 bytes.
    unsafe { std::ptr::copy_nonoverlapping(scratch, buf.as_mut_ptr(), n) };
    u64::from_le_bytes(buf)
}

fn write_scratch(scratch: *mut u8, value: u64, len: usize) {
    let bytes = value.to_le_bytes();
    let n = len.min(8);
    // SAFETY: the scratch holds at least 8 bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), scratch, n) };
}

/// Merges an `IN` result of `len` bytes into the old `RAX` (byte/word preserve
/// the upper bits; a 4-byte read zero-extends, as x86 does).
fn merge_reg(old: u64, value: u64, len: usize) -> u64 {
    match len {
        1 => (old & !0xff) | (value & 0xff),
        2 => (old & !0xffff) | (value & 0xffff),
        4 => value & 0xffff_ffff,
        _ => value,
    }
}
