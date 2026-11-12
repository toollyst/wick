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
//! - **`IA32_TSC_DEADLINE`** is emulated here, as KVM does
//!   ([`super::tscdeadline`]);
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
use super::whv;
use super::whv::WHV_PARTITION_HANDLE;

use super::vm::VmInner;
use super::tscdeadline::{self, MSR_TSC_DEADLINE};
use super::{emulate, err, pvclock, regs, Handle, IoEventAddress, Result, VcpuExit};

/// Size of the xAPIC state WHP exchanges (the APIC register page).
const LAPIC_PAGE: usize = 4096;
/// Size of `kvm_lapic_state` (`KVM_APIC_REG_SIZE`).
const LAPIC_REGS: usize = 1024;
/// Longest a vCPU that WHP reported halted waits before it re-enters the
/// guest: WHP's local APIC timer fires inside the hypervisor without telling
/// the run loop, so the wait is bounded (see the `X64Halt` exit).
const HALT_POLL: std::time::Duration = std::time::Duration::from_millis(1);

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
    /// The last `MSR_KVM_SYSTEM_TIME_NEW` value.
    system_time_msr: AtomicU64,
    /// The clock generation (`pvclock::State::generation`) this vCPU's time
    /// info was last published under.
    clock_gen: AtomicU64,
    /// Mirror of `kvm_run.immediate_exit`, written from any thread.
    immediate_exit: AtomicU8,
    /// Odd while the run loop is between its last `immediate_exit` check
    /// and the return of `WHvRunVirtualProcessor`: a kick in that window
    /// cancels again until the run returns (see [`VcpuShared::kick`]).
    run_seq: AtomicU64,
    /// `IA32_TSC_DEADLINE` ([`tscdeadline`]): 0 when disarmed or fired.
    tsc_deadline: AtomicU64,
    /// `IA32_TSC_ADJUST` and `IA32_MISC_ENABLE` where the partition does not
    /// keep them ([`regs::software_msr`]), as KVM keeps them.
    tsc_adjust: AtomicU64,
    misc_enable: AtomicU64,
    /// Bumped by every write of `IA32_TSC_DEADLINE`, so that a timer armed
    /// by an earlier write cannot fire for a later one.
    deadline_gen: AtomicU64,
    /// The `deadline_gen` of a timer that fired and whose interrupt the run
    /// loop is to raise before it next enters the guest (0: none).
    deadline_fired: AtomicU64,
    /// Guest debugging for the gdb stub ([`super::debug`]); untouched
    /// without the `gdb` feature.
    debug: Mutex<super::debug::State>,
}

impl VcpuShared {
    /// KVM's kick: `immediate_exit` is already set; makes a run in flight,
    /// or one about to start, return.
    ///
    /// `WHvCancelRunVirtualProcessor` only stops a run that is in the
    /// hypervisor, so a cancel that lands between the run loop's check of
    /// `immediate_exit` and its entry into the guest would be lost and the
    /// vCPU would run on until its next exit (an idle guest may not exit for
    /// a long time: WHP handles its APIC timer and `HLT` itself). While the
    /// run loop is in that window the cancel is repeated until the run
    /// returns. Both sides use sequentially consistent operations: either
    /// the run loop sees `immediate_exit`, or the kick sees the window open.
    fn kick(&self) {
        self.leave_guest();
    }

    /// Makes a run in flight, or one about to start, return (see
    /// [`Self::kick`]), and wakes a vCPU that WHP reported halted. The run
    /// loop checks what the caller set (`immediate_exit`, `deadline_fired`)
    /// before it enters the guest.
    fn leave_guest(&self) {
        let _ = super::ffi::cancel_run(self.part, self.index);
        let seq = self.run_seq.load(Ordering::SeqCst);
        if seq % 2 == 1 {
            let mut spins = 0u32;
            while self.run_seq.load(Ordering::SeqCst) == seq {
                let _ = super::ffi::cancel_run(self.part, self.index);
                spins += 1;
                if spins < 64 {
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
            }
        }
        self.inner.wake_halted();
    }

    /// The TSC-deadline timer of generation `generation` fired (on the
    /// timer thread): the run loop raises its interrupt before it next
    /// enters the guest.
    fn deadline_expired(&self, generation: u64) {
        self.deadline_fired.store(generation, Ordering::SeqCst);
        self.leave_guest();
    }
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
    // An application processor waits for the guest's INIT/SIPI, which WHP's
    // local APIC handles, as KVM's APs do; only the BSP (vCPU 0) runs from
    // the registers Firecracker sets.
    if index != 0 {
        regs::startup_suspend(inner.part, index)?;
    }
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
        system_time_msr: AtomicU64::new(0),
        clock_gen: AtomicU64::new(0),
        immediate_exit: AtomicU8::new(0),
        run_seq: AtomicU64::new(0),
        tsc_deadline: AtomicU64::new(0),
        tsc_adjust: AtomicU64::new(0),
        misc_enable: AtomicU64::new(0),
        deadline_gen: AtomicU64::new(0),
        deadline_fired: AtomicU64::new(0),
        debug: Mutex::new(super::debug::State::default()),
    });
    {
        let mut vcpus = ALL_VCPUS.lock().unwrap();
        vcpus.retain(|w| w.strong_count() > 0);
        vcpus.push(Arc::downgrade(&shared));
    }
    inner.vcpus.lock().unwrap().push(Arc::downgrade(&shared));
    Ok(VcpuFd { shared, own: None })
}

/// KVM's `create_vcpu_from_rawfd` for a duplicate (`dup`) of a vCPU's
/// descriptor: another `VcpuFd` of the same vCPU, which owns `fd`.
/// Firecracker keeps one per vCPU thread to kick it (`immediate_exit`).
/// `EBADF` if `fd` is not a duplicate of one of this VM's vCPUs.
pub(crate) fn from_duplicate(inner: &VmInner, fd: RawFd) -> Result<VcpuFd> {
    use windows_sys::Win32::Foundation::{CompareObjectHandles, HANDLE};
    // Owned from here on: closed if no vCPU matches.
    let own = Handle(super::ffi::OwnedHandle(fd as isize as HANDLE));
    let shared = inner
        .vcpus
        .lock()
        .unwrap()
        .iter()
        .filter_map(Weak::upgrade)
        // SAFETY: plain call on two open handles.
        .find(|v| unsafe { CompareObjectHandles(v.handle.0.0, own.0.0) } != 0);
    match shared {
        Some(shared) => Ok(VcpuFd {
            shared,
            own: Some(own),
        }),
        None => err(libc::EBADF),
    }
}

/// Wrapper over a WHP virtual processor.
#[derive(Debug)]
pub struct VcpuFd {
    shared: Arc<VcpuShared>,
    /// The descriptor of a `VcpuFd` made from a duplicate
    /// ([`from_duplicate`]); `None` for the one `create_vcpu` returned.
    own: Option<Handle>,
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
        #[cfg_attr(not(feature = "gdb"), allow(unused_mut))]
        let mut r = regs::get_regs(self.part(), self.vp())?;
        // A single step's TF is gdb's, not the guest's (KVM hides it too).
        #[cfg(feature = "gdb")]
        {
            r.rflags = super::debug::guest_rflags(r.rflags, &self.shared.debug.lock().unwrap());
        }
        Ok(r)
    }
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        // A register write keeps gdb's single step going.
        #[cfg(feature = "gdb")]
        let regs = &kvm_regs {
            rflags: super::debug::vcpu_rflags(regs.rflags, &self.shared.debug.lock().unwrap()),
            ..*regs
        };
        regs::set_regs(self.part(), self.vp(), regs)
    }

    /// `KVM_TRANSLATE`: the guest physical address `gva` maps to in the
    /// vCPU's current paging mode, as KVM answers it
    /// ([`super::debug::translation`]): the address itself while paging is
    /// off, else `WHvTranslateGva`'s walk as KVM's
    /// ([`super::debug::TRANSLATE_FLAGS`]). A failed or refused walk is an
    /// invalid translation, not a failed call, as KVM's never fails; only
    /// reading CR0 can fail it.
    pub fn translate_gva(&self, gva: u64) -> Result<kvm_bindings::kvm_translation> {
        if self.register(whv::WHvX64RegisterCr0)? & super::debug::CR0_PG == 0 {
            return Ok(super::debug::translation(gva, None));
        }
        let walk = self.translate_walk(gva, super::debug::TRANSLATE_FLAGS).ok();
        Ok(super::debug::translation(gva, Some(walk)))
    }

    /// One `WHvTranslateGva` walk with `flags`: its result code and address.
    pub(crate) fn translate_walk(&self, gva: u64, flags: whv::WHV_TRANSLATE_GVA_FLAGS) -> Result<(i32, u64)> {
        // SAFETY: plain data; zero is a valid value.
        let mut result: whv::WHV_TRANSLATE_GVA_RESULT = unsafe { std::mem::zeroed() };
        let mut gpa = 0u64;
        // SAFETY: out-pointers valid for the call.
        super::ffi::hr(unsafe { whv::WHvTranslateGva(self.part(), self.vp(), gva, flags, &mut result, &mut gpa) })?;
        Ok((result.ResultCode, gpa))
    }

    /// `KVM_SET_GUEST_DEBUG` ([`super::debug`]): the partition's exception
    /// exits for #DB and #BP, gdb's hardware breakpoints in DR0-DR3 and DR7
    /// (the guest's own put back when it has none), `RFLAGS.TF` for a single
    /// step, a #BP for the guest at the next entry. Every WHP call that fails
    /// fails this with its errno; nothing is accepted that is not done.
    pub fn set_guest_debug(&self, dbg: &kvm_bindings::kvm_guest_debug) -> Result<()> {
        let plan = super::debug::plan(dbg.control)?;
        let part = self.part();
        let vp = self.vp();
        let mut state = self.shared.debug.lock().unwrap();
        if dbg.control & kvm_bindings::KVM_GUESTDBG_ENABLE != 0 || state.saved.is_some() || state.tf_owned {
            // SAFETY: a u64 value for ExceptionExitBitmap.
            unsafe {
                super::ffi::set_partition_property(part, whv::WHvPartitionPropertyCodeExceptionExitBitmap, &plan.bitmap)?;
            }
        }
        if plan.hw {
            if state.saved.is_none() {
                let d = regs::get_debugregs(part, vp)?;
                state.saved = Some([d.db[0], d.db[1], d.db[2], d.db[3], d.dr6, d.dr7]);
            }
            let r = &dbg.arch.debugreg;
            let hw = ([r[0], r[1], r[2], r[3]], r[7]);
            write_hw_breakpoints(part, vp, hw)?;
            state.hw = Some(hw);
        } else if let Some(s) = state.saved.take() {
            let d = kvm_debugregs { db: [s[0], s[1], s[2], s[3]], dr6: s[4], dr7: s[5], ..Default::default() };
            regs::set_debugregs(part, vp, &d)?;
            state.hw = None;
        }
        if plan.step || state.tf_owned {
            let rflags = super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvX64RegisterRflags)?);
            let new = super::debug::step_rflags(rflags, plan.step, &mut state);
            if new != rflags {
                super::ffi::set_register(part, vp, whv::WHvX64RegisterRflags, super::ffi::reg64(new))?;
            }
        }
        state.inject_bp = plan.inject_bp;
        Ok(())
    }

    /// What gdb's debugging needs before an entry into the guest: its
    /// hardware breakpoints again (the guest may have written DR7), `RF` to
    /// leave the instruction breakpoint the vCPU stopped on, a #BP for the
    /// guest's own `INT3`.
    #[cfg(feature = "gdb")]
    fn prepare_debug_entry(&self) -> Result<()> {
        let part = self.part();
        let vp = self.vp();
        let mut state = self.shared.debug.lock().unwrap();
        if let Some(hw) = state.hw {
            write_hw_breakpoints(part, vp, hw)?;
        }
        if std::mem::take(&mut state.resume_rf) {
            let rflags = super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvX64RegisterRflags)?);
            super::ffi::set_register(part, vp, whv::WHvX64RegisterRflags, super::ffi::reg64(rflags | super::debug::RFLAGS_RF))?;
        }
        if std::mem::take(&mut state.inject_bp) {
            // The exit left RIP at the INT3: the guest's #BP returns past it.
            let rip = super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvX64RegisterRip)?);
            super::ffi::set_register(part, vp, whv::WHvX64RegisterRip, super::ffi::reg64(rip + state.last_len))?;
            super::ffi::set_register(
                part,
                vp,
                whv::WHvRegisterPendingInterruption,
                super::ffi::reg64(super::debug::pending_bp()),
            )?;
        }
        Ok(())
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
        let n = regs::get_msrs(self.part(), self.vp(), msrs)?;
        // The kvm-clock MSRs and IA32_TSC_DEADLINE are this backend's (see
        // `pvclock`, `tscdeadline`).
        for e in msrs.as_mut_slice() {
            match e.index {
                pvclock::MSR_SYSTEM_TIME => e.data = self.shared.system_time_msr.load(Ordering::Acquire),
                pvclock::MSR_WALL_CLOCK => e.data = self.shared.inner.pvclock.lock().unwrap().wall_msr,
                MSR_TSC_DEADLINE => e.data = self.read_tsc_deadline()?,
                i if regs::software_msr(i) => e.data = self.software_msr(i).load(Ordering::Acquire),
                _ => {}
            }
        }
        Ok(n)
    }
    pub fn set_msrs(&self, msrs: &Msrs) -> Result<usize> {
        let n = regs::set_msrs(self.part(), self.vp(), msrs)?;
        for e in msrs.as_slice() {
            if e.index == MSR_TSC_DEADLINE {
                self.write_tsc_deadline(e.data)?;
            } else if regs::software_msr(e.index) {
                self.write_software_msr(e.index, e.data, true)?;
            } else {
                self.write_kvm_msr(e.index, e.data);
            }
        }
        Ok(n)
    }

    /// The vCPU's copy of a [`regs::software_msr`].
    fn software_msr(&self, index: u32) -> &AtomicU64 {
        if index == regs::MSR_IA32_TSC_ADJUST { &self.shared.tsc_adjust } else { &self.shared.misc_enable }
    }

    /// Writes a [`regs::software_msr`] as KVM's `kvm_set_msr_common` does
    /// (Linux 6.12): `IA32_TSC_ADJUST` is kept only when the guest's CPUID
    /// has TSC_ADJUST, and a guest's write moves its TSC by the change and
    /// publishes its kvm-clock again (`adjust_tsc_offset_guest`,
    /// `KVM_REQ_CLOCK_UPDATE`); a guest's write of `IA32_MISC_ENABLE` that
    /// changes a read-only PMU bit is refused with #GP and leaves EMON as it
    /// was (the MWAIT quirk is KVM's default, so MWAIT is a plain bit).
    /// Returns whether the write was taken.
    fn write_software_msr(&self, index: u32, data: u64, host: bool) -> Result<bool> {
        const EMON: u64 = 1 << 7;
        const PMU_RO_MASK: u64 = (1 << 11) | (1 << 12);
        let cell = self.software_msr(index);
        if index == regs::MSR_IA32_TSC_ADJUST {
            if !self.guest_has_tsc_adjust() {
                return Ok(true);
            }
            if !host {
                let adj = data.wrapping_sub(cell.load(Ordering::Acquire));
                let tsc = self.register(whv::WHvX64RegisterTsc)?;
                super::ffi::set_register(self.part(), self.vp(), whv::WHvX64RegisterTsc, super::ffi::reg64(tsc.wrapping_add(adj)))?;
                // Published again at the next entry (`update_clock`).
                self.shared.clock_gen.store(u64::MAX, Ordering::Release);
            }
            cell.store(data, Ordering::Release);
            return Ok(true);
        }
        let old = cell.load(Ordering::Acquire);
        let data = if host {
            data
        } else {
            if (old ^ data) & PMU_RO_MASK != 0 {
                return Ok(false);
            }
            (data & !EMON) | (old & EMON)
        };
        cell.store(data, Ordering::Release);
        Ok(true)
    }

    /// CPUID.(EAX=7,ECX=0):EBX bit 1, TSC_ADJUST, in the guest's CPUID.
    fn guest_has_tsc_adjust(&self) -> bool {
        self.shared.cpuid.lock().unwrap().iter().any(|e| e.function == 7 && e.index == 0 && e.ebx & (1 << 1) != 0)
    }

    /// `IA32_TSC_DEADLINE` as the guest reads it: 0 outside TSC-deadline
    /// mode, as on the processor and in KVM.
    fn read_tsc_deadline(&self) -> Result<u64> {
        let (page, _) = self.lapic_page()?;
        Ok(if tscdeadline::page_in_deadline_mode(&page[..]) {
            self.shared.tsc_deadline.load(Ordering::SeqCst)
        } else {
            0
        })
    }

    /// A write of `IA32_TSC_DEADLINE`, by the guest or a restore (after
    /// `IA32_TSC` and the local APIC, as upstream restores them): disarms
    /// the timer, and for a non-zero deadline in TSC-deadline mode arms it
    /// for when the guest TSC reaches it, or raises the interrupt at once
    /// if it already has. Outside TSC-deadline mode the write is ignored,
    /// as the processor ignores it.
    fn write_tsc_deadline(&self, value: u64) -> Result<()> {
        let shared = &self.shared;
        let generation = shared.deadline_gen.fetch_add(1, Ordering::SeqCst) + 1;
        shared.deadline_fired.store(0, Ordering::SeqCst);
        shared.inner.deadlines.disarm(self.vp());
        shared.tsc_deadline.store(0, Ordering::SeqCst);
        if value == 0 {
            return Ok(());
        }
        let (page, _) = self.lapic_page()?;
        if !tscdeadline::page_in_deadline_mode(&page[..]) {
            return Ok(());
        }
        shared.tsc_deadline.store(value, Ordering::SeqCst);
        let tsc = self.register(whv::WHvX64RegisterTsc)?;
        if value <= tsc {
            return self.raise_tsc_deadline();
        }
        // Without the guest TSC's frequency the deadline cannot be timed:
        // the vCPU fails rather than never taking its timer interrupt.
        let hz = pvclock::tsc_hz();
        if hz == 0 {
            return err(libc::ENOTSUP);
        }
        let due = std::time::Instant::now() + tscdeadline::time_to(value, tsc, hz);
        let vcpu = Arc::downgrade(&self.shared);
        shared.inner.deadlines.arm(
            self.vp(),
            due,
            Arc::new(move || {
                if let Some(v) = vcpu.upgrade() {
                    v.deadline_expired(generation);
                }
            }),
        );
        Ok(())
    }

    /// The deadline was reached: clears `IA32_TSC_DEADLINE` and requests the
    /// LVT timer entry's interrupt for this vCPU, unless the processor would
    /// raise none ([`tscdeadline::deadline_interrupt`]). On the vCPU's
    /// thread, while it is out of the guest.
    fn raise_tsc_deadline(&self) -> Result<()> {
        self.shared.tsc_deadline.store(0, Ordering::SeqCst);
        let (page, _) = self.lapic_page()?;
        if let Some((apic_id, vector)) = tscdeadline::deadline_interrupt(&page[..]) {
            // Fixed delivery, edge, physical destination: an MSI to the APIC.
            let address = 0xFEE0_0000 | (u64::from(apic_id & 0xff) << 12);
            self.shared.inner.inject_msi(address, u32::from(vector));
        }
        Ok(())
    }

    /// A write of a kvm-clock MSR, by the guest or a restore; other MSRs are
    /// left alone. Returns whether `index` is one.
    fn write_kvm_msr(&self, index: u32, value: u64) -> bool {
        let inner = &self.shared.inner;
        let now = || inner.irqchip.lock().unwrap().clock().clock;
        match index {
            pvclock::MSR_SYSTEM_TIME => {
                self.shared.system_time_msr.store(value, Ordering::Release);
                let generation = inner.pvclock.lock().unwrap().generation;
                self.shared.clock_gen.store(generation, Ordering::Release);
                pvclock::system_time(&inner.pvclock, self.part(), self.vp(), value, inner.ram(), now);
                true
            }
            pvclock::MSR_WALL_CLOCK => {
                pvclock::wall_clock(&inner.pvclock, value, inner.ram(), now());
                true
            }
            _ => false,
        }
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
        if v != 0 {
            return Ok(v as u32);
        }
        // The guest TSC runs at the host's frequency, which WHP reports.
        match pvclock::tsc_hz() / 1000 {
            0 => err(libc::ENOTSUP),
            khz => Ok(u32::try_from(khz).unwrap_or(u32::MAX)),
        }
    }
    pub fn set_tsc_khz(&self, freq: u32) -> Result<()> {
        // WHP runs the guest TSC at the host rate; the requested frequency is
        // recorded for `get_tsc_khz`. Cross-host TSC scaling is not applied.
        self.shared.tsc_khz.store(u64::from(freq), Ordering::Relaxed);
        Ok(())
    }

    /// `KVM_KVMCLOCK_CTRL`: tells the guest it was stopped by the host
    /// (`PVCLOCK_GUEST_STOPPED` in its kvm-clock time info), as Firecracker
    /// does on pause; `EINVAL` if the guest has no kvm-clock, as KVM.
    pub fn kvmclock_ctrl(&self) -> Result<()> {
        let value = self.shared.system_time_msr.load(Ordering::Acquire);
        let inner = &self.shared.inner;
        if pvclock::set_guest_stopped(value, inner.ram()) {
            Ok(())
        } else {
            err(libc::EINVAL)
        }
    }

    // ---- LAPIC ----

    /// The xAPIC state WHP exchanges: the architectural 4 KiB register page
    /// (each register at its MMIO offset, 16 bytes apart), of which
    /// `kvm_lapic_state` is the first KiB, the part that holds registers.
    fn lapic_page(&self) -> Result<(Box<[u8; LAPIC_PAGE]>, u32)> {
        let mut page = Box::new([0u8; LAPIC_PAGE]);
        let mut written = 0u32;
        // SAFETY: valid output buffer of the given size.
        super::ffi::hr(unsafe {
            whv::WHvGetVirtualProcessorInterruptControllerState(
                self.part(),
                self.vp(),
                page.as_mut_ptr().cast(),
                LAPIC_PAGE as u32,
                &mut written,
            )
        })?;
        // Anything shorter is not the register page this conversion assumes.
        if (written as usize) < LAPIC_REGS {
            return err(libc::EIO);
        }
        Ok((page, written))
    }

    /// Reads the local APIC registers.
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let (page, _) = self.lapic_page()?;
        let mut state = kvm_lapic_state {
            regs: [0; LAPIC_REGS],
        };
        for (dst, src) in state.regs.iter_mut().zip(page.iter()) {
            *dst = *src as std::os::raw::c_char;
        }
        Ok(state)
    }

    /// Writes the local APIC registers; the rest of the page WHP keeps is
    /// written back as it was.
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let (mut page, size) = self.lapic_page()?;
        for (dst, src) in page.iter_mut().zip(klapic.regs.iter()) {
            *dst = *src as u8;
        }
        // SAFETY: the register page is valid for `size` bytes.
        super::ffi::hr(unsafe {
            whv::WHvSetVirtualProcessorInterruptControllerState(
                self.part(),
                self.vp(),
                page.as_ptr().cast(),
                size,
            )
        })
    }

    // ---- vCPU events ----

    /// The event the vCPU is delivering, its interrupt shadow and NMI mask,
    /// from WHP's pending-interruption and interrupt-state registers (see
    /// `regs`).
    pub fn get_vcpu_events(&self) -> Result<kvm_vcpu_events> {
        regs::get_vcpu_events(self.part(), self.vp())
    }
    /// Restores what [`Self::get_vcpu_events`] returns.
    pub fn set_vcpu_events(&self, events: &kvm_vcpu_events) -> Result<()> {
        regs::set_vcpu_events(self.part(), self.vp(), events)
    }

    // ---- run control ----

    pub fn get_kvm_run(&mut self) -> &mut kvm_run {
        // SAFETY: the run loop and this accessor are on the owning thread.
        unsafe { &mut *self.shared.run.ptr() }
    }

    /// Sets the immediate-exit flag; a `1` also makes a run in flight return
    /// (the kick, without a POSIX signal; see [`VcpuShared::kick`]).
    pub fn set_kvm_immediate_exit(&mut self, val: u8) {
        self.shared.immediate_exit.store(val, Ordering::SeqCst);
        // SAFETY: single-byte write to the shared `kvm_run`, as KVM's mmap.
        unsafe { (*self.shared.run.ptr()).immediate_exit = val };
        if val == 1 {
            self.shared.kick();
        }
    }

    /// One `WHvRunVirtualProcessor`, unless a kick came first (`None`).
    fn enter(&self) -> Result<Option<whv::WHV_RUN_VP_EXIT_CONTEXT>> {
        let shared = &self.shared;
        shared.run_seq.fetch_add(1, Ordering::SeqCst);
        self.update_clock();
        let result = self.raise_fired_deadline().and_then(|()| {
            if shared.immediate_exit.load(Ordering::SeqCst) != 0 {
                Ok(None)
            } else {
                super::ffi::run_vp(self.part(), self.vp()).map(Some)
            }
        });
        shared.run_seq.fetch_add(1, Ordering::SeqCst);
        result
    }

    /// Publishes this vCPU's kvm-clock time info again if the VM clock was
    /// set since it was published (`pvclock`: a snapshot restore sets the
    /// clock after the vCPUs' MSRs), as KVM does on `KVM_REQ_CLOCK_UPDATE`.
    fn update_clock(&self) {
        let inner = &self.shared.inner;
        let generation = inner.pvclock.lock().unwrap().generation;
        if self.shared.clock_gen.swap(generation, Ordering::AcqRel) == generation {
            return;
        }
        let value = self.shared.system_time_msr.load(Ordering::Acquire);
        let now = || inner.irqchip.lock().unwrap().clock().clock;
        pvclock::system_time(&inner.pvclock, self.part(), self.vp(), value, inner.ram(), now);
    }

    /// Raises the interrupt of a TSC-deadline timer that fired since the
    /// last entry into the guest, unless the deadline was written again
    /// since.
    fn raise_fired_deadline(&self) -> Result<()> {
        let shared = &self.shared;
        let fired = shared.deadline_fired.swap(0, Ordering::SeqCst);
        if fired != 0 && fired == shared.deadline_gen.load(Ordering::SeqCst) {
            self.raise_tsc_deadline()?;
        }
        Ok(())
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
        let mut ram_retries = 0u32;
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
                    let merged = super::exit::in_result(rax, value, len);
                    regs::set_gpr_rax_rip(part, vp, merged, rip_after)?;
                }
            }
        }

        loop {
            #[cfg(feature = "gdb")]
            self.prepare_debug_entry()?;
            let Some(ctx) = self.enter()? else {
                return err(libc::EINTR);
            };
            let instr_len = super::exit::instruction_length(ctx.VpContext._bitfield);
            let rip = ctx.VpContext.Rip;

            match ctx.ExitReason {
                whv::WHvRunVpExitReasonNone => continue,
                // A kick (`immediate_exit`) is KVM's EINTR; a cancel from
                // a TSC-deadline timer only made the vCPU leave the guest to
                // take its interrupt (`enter`).
                whv::WHvRunVpExitReasonCanceled => {
                    if self.shared.immediate_exit.load(Ordering::SeqCst) != 0 {
                        return err(libc::EINTR);
                    }
                    continue;
                }
                // KVM's local APIC is in the kernel, and x86 Firecracker
                // treats an HLT exit as fatal: the vCPU waits here for an
                // interrupt instead. With its local APIC emulated, WHP
                // halts the vCPU itself (newer Windows builds never report
                // HLT); where it does report one, `RIP` is past the `HLT`,
                // so re-entering is a wake-up the guest's idle loop checks.
                // Re-entry waits for an interrupt request or a kick, or at
                // most `HALT_POLL`, since WHP's APIC timer fires unseen.
                whv::WHvRunVpExitReasonX64Halt => {
                    self.shared.inner.wait_halted(HALT_POLL);
                    continue;
                }

                whv::WHvRunVpExitReasonX64IoPortAccess => {
                    // SAFETY: the union arm matches the exit reason.
                    let io = unsafe { ctx.Anonymous.IoPortAccess };
                    // SAFETY: the access-info bitfield overlaps the u32.
                    let info = unsafe { io.AccessInfo.AsUINT32 };
                    // A size x86 port I/O does not have: never from WHP.
                    let Some(access) = super::exit::port_access(info) else {
                        return err(libc::EINVAL);
                    };
                    let super::exit::PortAccess { write: is_write, size, string, rep } = access;
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
                            let merged = super::exit::in_result(io.Rax, value, size);
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
                    // Guest RAM not committed yet (anonymous `MAP_NORESERVE`
                    // memory gets its pages at the first access, as on
                    // Linux): WHP exits at the access to such a page, which
                    // re-runs once it is committed (measured), as KVM resolves
                    // the stage-2 fault through the host page.
                    if let Some(host) = self.shared.inner.host_addr(mem.Gpa) {
                        #[allow(clippy::cast_possible_truncation)]
                        let write = super::exit::memory_write(unsafe { mem.AccessInfo.AsUINT32 });
                        match libc::wick_mm::commit_on_access(host as usize, write) {
                            libc::wick_mm::Access::Committed => continue,
                            libc::wick_mm::Access::Exhausted(err) => libc::wick_mm::out_of_memory(host as usize, err),
                            libc::wick_mm::Access::NotLazy => {}
                        }
                    }
                    // Guest RAM that is a missing userfaultfd page: WHP
                    // honours its host PAGE_NOACCESS and exits at the
                    // access, which re-runs once the handler filled it, as
                    // KVM resolves the stage-2 fault through the host page.
                    // A page filled between the exit and the check (by the
                    // handler, or for another vCPU) is not reported: the
                    // access re-runs, never as MMIO, which would read zeros.
                    if libc::wick_uffd::active() {
                        if let Some(host) = self.shared.inner.host_addr(mem.Gpa) {
                            // SAFETY: the access-info bitfield overlaps the u32.
                            let write = super::exit::memory_write(unsafe { mem.AccessInfo.AsUINT32 });
                            if libc::wick_uffd::fault(host, write) {
                                ram_retries = 0;
                                continue;
                            }
                            ram_retries += 1;
                            if ram_retries < 1_000_000 {
                                std::thread::yield_now();
                                continue;
                            }
                            eprintln!("whp: guest RAM at {:#x} stays inaccessible", mem.Gpa);
                        }
                    }
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

                whv::WHvRunVpExitReasonHypercall => {
                    // SAFETY: the union arm matches the exit reason.
                    let h = unsafe { ctx.Anonymous.Hypercall };
                    // SAFETY: plain 16-bit views of the exit context's bit fields.
                    let (state, cs) = unsafe { (ctx.VpContext.ExecutionState.AsUINT16, ctx.VpContext.Cs.Anonymous.Attributes) };
                    let wide = super::exit::long_mode_code(state, cs);
                    let result = self.kvm_hypercall(h.Rax, h.Rbx, h.Rcx, wide, super::exit::cpl(state));
                    regs::set_gpr_rax_rip(part, vp, super::exit::hypercall_rax(result, wide), rip + instr_len)?;
                    continue;
                }

                whv::WHvRunVpExitReasonX64InterruptWindow
                | whv::WHvRunVpExitReasonX64ApicEoi => continue,

                whv::WHvRunVpExitReasonUnrecoverableException => return Ok(VcpuExit::Shutdown),

                // #DB or #BP for the gdb stub (only a partition made with
                // the `gdb` feature has exception exits).
                #[cfg(feature = "gdb")]
                whv::WHvRunVpExitReasonException => {
                    // SAFETY: the union arm matches the exit reason.
                    let ex = unsafe { ctx.Anonymous.VpException };
                    let mut state = self.shared.debug.lock().unwrap();
                    let dr7 = state.hw.map_or(0, |(_, dr7)| dr7);
                    let Some(arch) = super::debug::debug_exit(ex.ExceptionType, rip, ex.ExceptionParameter, dr7)
                    else {
                        return Ok(VcpuExit::InternalError);
                    };
                    state.last_len = instr_len.max(1);
                    if ex.ExceptionType == super::debug::DB_VECTOR && super::debug::at_hw_breakpoint(rip, &state) {
                        state.resume_rf = true;
                    }
                    return Ok(VcpuExit::Debug(arch));
                }

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
        let (eax, mut ebx, mut ecx, edx) = {
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
        // The bits KVM computes from the vCPU's state at each CPUID
        // (kvm_update_cpuid_runtime): OSXSAVE and OSPKE follow CR4, and the
        // XSAVE area sizes follow XCR0 and IA32_XSS. A fixed value makes a
        // guest kernel find its XSAVE layout inconsistent and turn XSAVE off,
        // after which user space dies on XGETBV.
        match (function, index) {
            (0x1, _) | (0x7, 0) => {
                let cr4 = self.register(whv::WHvX64RegisterCr4)?;
                ecx = super::exit::cpuid_ecx(function, index, ecx, cr4);
            }
            (0xd, 0) => {
                let xcr0 = self.register(whv::WHvX64RegisterXCr0)?;
                ebx = regs::xsave_size(xcr0, false);
            }
            (0xd, 1) if eax & (1 << 3) != 0 => {
                let xcr0 = self.register(whv::WHvX64RegisterXCr0)?;
                let xss = self.register(whv::WHvX64RegisterXss).unwrap_or(0);
                ebx = regs::xsave_size(xcr0 | xss, true);
            }
            _ => {}
        }
        regs::set_cpuid_result(self.part(), self.vp(), eax, ebx, ecx, edx, rip_after)
    }

    /// A KVM hypercall (`kvm_emulate_hypercall`): `nr` in RAX, arguments in
    /// RBX, RCX; returns RAX. The ones KVM answers that a Firecracker guest
    /// makes: `KVM_HC_VAPIC_POLL_IRQ` (nothing to do) and
    /// `KVM_HC_CLOCK_PAIRING` (the host's wall clock with the guest TSC of
    /// the same moment, which ptp_kvm keeps the guest's time in step with);
    /// anything else is `-KVM_ENOSYS`, as KVM answers an unknown one. From a
    /// privilege level but 0, every one is `-KVM_EPERM`
    /// ([`super::exit::hypercall`]).
    fn kvm_hypercall(&self, nr: u64, a0: u64, a1: u64, op_64_bit: bool, cpl: u8) -> u64 {
        const KVM_EOPNOTSUPP: i64 = 95;
        const KVM_EFAULT: i64 = 14;
        let neg = |e: i64| (-e).cast_unsigned();
        match super::exit::hypercall(nr, a0, a1, op_64_bit, cpl) {
            super::exit::Hypercall::PollIrq => 0,
            super::exit::Hypercall::Error(rax) => rax,
            super::exit::Hypercall::ClockPairing { gpa } => {
                let Ok(tsc) = self.register(whv::WHvX64RegisterTsc) else {
                    return neg(KVM_EOPNOTSUPP);
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                // struct kvm_clock_pairing { s64 sec; s64 nsec; u64 tsc; u32 flags; u32 pad[9]; }
                let mut out = [0u8; 64];
                out[0..8].copy_from_slice(&now.as_secs().to_le_bytes());
                out[8..16].copy_from_slice(&u64::from(now.subsec_nanos()).to_le_bytes());
                out[16..24].copy_from_slice(&tsc.to_le_bytes());
                // KVM's kvm_pv_clock_pairing: kvm_write_guest, -KVM_EFAULT if
                // any of the 64 bytes is not writable guest RAM.
                if self.shared.inner.write_guest(gpa, &out) { 0 } else { neg(KVM_EFAULT) }
            }
        }
    }

    /// One 64-bit register of this vCPU.
    fn register(&self, name: whv::WHV_REGISTER_NAME) -> Result<u64> {
        Ok(super::ffi::as_u64(&super::ffi::get_register(self.part(), self.vp(), name)?))
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
        let (is_write, value) = super::exit::msr_access(unsafe { m.AccessInfo.AsUINT32 }, m.Rax, m.Rdx);
        let index = m.MsrNumber;
        if is_write {
            if index == MSR_TSC_DEADLINE {
                self.write_tsc_deadline(value)?;
            } else if regs::software_msr(index) {
                if !self.write_software_msr(index, value, false)? {
                    // #GP(0), RIP left at the WRMSR, as KVM's refused write.
                    return super::ffi::set_register(
                        self.part(),
                        self.vp(),
                        whv::WHvRegisterPendingInterruption,
                        super::ffi::reg64(super::debug::pending_gp()),
                    );
                }
            } else {
                self.write_kvm_msr(index, value);
            }
            regs::set_rip(self.part(), self.vp(), rip_after)
        } else {
            let value = match index {
                pvclock::MSR_SYSTEM_TIME => self.shared.system_time_msr.load(Ordering::Acquire),
                pvclock::MSR_WALL_CLOCK => self.shared.inner.pvclock.lock().unwrap().wall_msr,
                MSR_TSC_DEADLINE => self.read_tsc_deadline()?,
                i if regs::software_msr(i) => self.software_msr(i).load(Ordering::Acquire),
                _ => 0,
            };
            regs::set_msr_result(self.part(), self.vp(), value, rip_after)
        }
    }
}

/// gdb's hardware breakpoints into the vCPU's DR0-DR3 and DR7.
fn write_hw_breakpoints(part: WHV_PARTITION_HANDLE, vp: u32, (addrs, dr7): ([u64; 4], u64)) -> Result<()> {
    const NAMES: [whv::WHV_REGISTER_NAME; 5] = [
        whv::WHvX64RegisterDr0,
        whv::WHvX64RegisterDr1,
        whv::WHvX64RegisterDr2,
        whv::WHvX64RegisterDr3,
        whv::WHvX64RegisterDr7,
    ];
    let r = super::ffi::reg64;
    super::ffi::set_registers(part, vp, &NAMES, &[r(addrs[0]), r(addrs[1]), r(addrs[2]), r(addrs[3]), r(dr7)])
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.own.as_ref().unwrap_or(&self.shared.handle).as_raw_fd()
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

