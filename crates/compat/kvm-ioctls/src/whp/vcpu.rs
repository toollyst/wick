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
    /// Linux's image of the x87 and SSE state until the first `KVM_RUN`
    /// (`regs::BeforeRun`); `None` from then on.
    before_run: Mutex<Option<regs::BeforeRun>>,
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
    /// Bumped when a #BP window of this vCPU opens and when it closes: a
    /// window's generation is odd while it is open.
    window_gen: AtomicU64,
    /// The generation of a window that outlived [`super::debug::WINDOW_BOUND`].
    window_expired: AtomicU64,
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
        // A vCPU held out of the guest by another's #BP window sees the kick.
        self.inner.notify_bp_window();
    }

    /// Whether this vCPU has a #BP window open.
    fn in_bp_window(&self) -> bool {
        self.inner.bp_owner.load(Ordering::SeqCst) == i64::from(self.index)
    }

    /// Closes this vCPU's #BP window `w`: its DR0-DR3, DR6, DR7 and NMI mask
    /// as before it, gdb's exception exits back, the held vCPUs let go. The
    /// window is closed even if a register cannot be written, whose error is
    /// returned.
    #[cfg_attr(not(feature = "gdb"), allow(dead_code))]
    fn close_window(&self, w: &super::debug::Window) -> Result<()> {
        let s = w.saved;
        let d = kvm_debugregs { db: [s[0], s[1], s[2], s[3]], dr6: s[4], dr7: s[5], ..Default::default() };
        let dregs = regs::set_debugregs(self.part, self.index, &d);
        let nmi = super::ffi::get_register(self.part, self.index, whv::WHvRegisterInterruptState).and_then(|v| {
            let state = super::ffi::as_u64(&v);
            let state = if w.nmi_masked { state | INTERRUPT_STATE_NMI_MASKED } else { state & !INTERRUPT_STATE_NMI_MASKED };
            super::ffi::set_register(self.part, self.index, whv::WHvRegisterInterruptState, super::ffi::reg64(state))
        });
        self.window_gen.fetch_add(1, Ordering::SeqCst);
        let bitmap = self.inner.close_bp_window();
        dregs.and(nmi).and(bitmap)
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
        before_run: Mutex::new(Some(regs::BeforeRun::new())),
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
        window_gen: AtomicU64::new(0),
        window_expired: AtomicU64::new(0),
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
            // Written at once, or when an open #BP window closes.
            self.shared.inner.set_debug_bitmap(plan.bitmap)?;
        }
        // While this vCPU's #BP window is open its DRs are the window's, and
        // what it found there (`saved`) is what comes back at its end: gdb's
        // and the guest's values go there, and the next entry writes gdb's.
        if plan.hw {
            if state.saved.is_none() {
                let saved = match &state.window {
                    Some(w) => w.saved,
                    None => {
                        let d = regs::get_debugregs(part, vp)?;
                        [d.db[0], d.db[1], d.db[2], d.db[3], d.dr6, d.dr7]
                    }
                };
                state.saved = Some(saved);
            }
            let r = &dbg.arch.debugreg;
            let hw = ([r[0], r[1], r[2], r[3]], r[7]);
            if state.window.is_none() {
                write_hw_breakpoints(part, vp, hw)?;
            }
            state.hw = Some(hw);
        } else if let Some(s) = state.saved.take() {
            if let Some(w) = state.window.as_mut() {
                w.saved = s;
            } else {
                let d = kvm_debugregs { db: [s[0], s[1], s[2], s[3]], dr6: s[4], dr7: s[5], ..Default::default() };
                regs::set_debugregs(part, vp, &d)?;
            }
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
    /// leave the instruction breakpoint the vCPU stopped on, and for the
    /// guest's own `INT3` a #BP window ([`super::debug`]). While a window is
    /// open, its DRs stay.
    #[cfg(feature = "gdb")]
    fn prepare_debug_entry(&self) -> Result<()> {
        let part = self.part();
        let vp = self.vp();
        let mut state = self.shared.debug.lock().unwrap();
        if let (Some(hw), None) = (state.hw, &state.window) {
            write_hw_breakpoints(part, vp, hw)?;
        }
        if std::mem::take(&mut state.resume_rf) {
            let rflags = super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvX64RegisterRflags)?);
            super::ffi::set_register(part, vp, whv::WHvX64RegisterRflags, super::ffi::reg64(rflags | super::debug::RFLAGS_RF))?;
        }
        if state.inject_bp && state.window.is_none() {
            if let Some(w) = self.open_window()? {
                state.window = Some(w);
                state.inject_bp = false;
            }
        }
        Ok(())
    }

    /// Opens a #BP window for the guest's INT3 at RIP: the other vCPUs held
    /// out of the guest, DR0 on the #BP handler, NMIs masked, and the
    /// partition's exception exits without #BP. `None` if a kick came
    /// first: nothing opened, the #BP still to come, and the entry returns
    /// `EINTR`.
    #[cfg(feature = "gdb")]
    fn open_window(&self) -> Result<Option<super::debug::Window>> {
        use super::debug::{self, Window};
        let inner = &self.shared.inner;
        let (part, vp) = (self.part(), self.vp());
        if !inner.open_bp_window(vp, &self.shared.immediate_exit) {
            return Ok(None);
        }
        // First the others out of the guest, then the exits changed: never
        // a moment where another vCPU runs without #BP exits.
        self.hold_others();
        let found = (|| {
            let d = regs::get_debugregs(part, vp)?;
            let nmi = super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvRegisterInterruptState)?);
            Ok((d, nmi))
        })();
        let (d, nmi) = match found {
            Ok(found) => found,
            Err(e) => {
                let _ = inner.close_bp_window();
                return Err(e);
            }
        };
        let w = Window {
            saved: [d.db[0], d.db[1], d.db[2], d.db[3], d.dr6, d.dr7],
            nmi_masked: nmi & INTERRUPT_STATE_NMI_MASKED != 0,
            vector: debug::BP_VECTOR,
            handler: self.handler_of(debug::BP_VECTOR),
            faults: debug::DELIVERY_FAULTS,
            opened: std::time::Instant::now(),
        };
        self.shared.window_gen.fetch_add(1, Ordering::SeqCst);
        let armed = (|| {
            arm_window(part, vp, w.handler)?;
            super::ffi::set_register(part, vp, whv::WHvRegisterInterruptState, super::ffi::reg64(nmi | INTERRUPT_STATE_NMI_MASKED))?;
            inner.set_window_bitmap(debug::window_bitmap(w.faults))
        })();
        if let Err(e) = armed {
            let _ = self.shared.close_window(&w);
            return Err(e);
        }
        #[cfg(test)]
        eprintln!(
            "BPTEST window open: vCPU {vp}, #BP handler {:?}, NMIs masked before: {}",
            w.handler.map(|h| format!("{h:#x}")),
            w.nmi_masked
        );
        self.watch_window();
        Ok(Some(w))
    }

    /// Makes every other vCPU of the partition leave the guest
    /// ([`hold_vcpus`]).
    #[cfg(feature = "gdb")]
    fn hold_others(&self) {
        hold_vcpus(&self.shared.inner, Some(self.shared.index));
    }

    /// The last resort for a window whose end never comes (see
    /// [`super::debug::WINDOW_BOUND`]): after the bound, if the same window
    /// is still open, it is marked expired and the vCPU's run cancelled;
    /// the run loop then closes it and says so.
    #[cfg(feature = "gdb")]
    fn watch_window(&self) {
        // Weak: a vCPU (and its partition) dropped meanwhile is not kept.
        let shared = Arc::downgrade(&self.shared);
        let generation = self.shared.window_gen.load(Ordering::SeqCst);
        std::thread::spawn(move || {
            std::thread::sleep(super::debug::WINDOW_BOUND);
            let Some(shared) = shared.upgrade() else { return };
            if shared.window_gen.load(Ordering::SeqCst) == generation {
                shared.window_expired.store(generation, Ordering::SeqCst);
                shared.leave_guest();
            }
        });
    }

    /// Whether this vCPU's open window outlived its bound.
    fn window_expired(&self) -> bool {
        let generation = self.shared.window_gen.load(Ordering::SeqCst);
        generation % 2 == 1 && self.shared.window_expired.load(Ordering::SeqCst) == generation
    }

    /// Closes the window if it outlived its bound, with a warning.
    #[cfg(feature = "gdb")]
    fn end_expired_window(&self) -> Result<()> {
        if !self.window_expired() {
            return Ok(());
        }
        let mut state = self.shared.debug.lock().unwrap();
        let Some(w) = state.window.take() else { return Ok(()) };
        let reason = match w.handler {
            None => "no handler could be read from its gate, and no fault came",
            Some(_) => "the delivery did not reach the handler",
        };
        super::ffi::report(
            log::Level::Warn,
            &format!(
                "whp: warning: vCPU {}'s #BP window (vector {}, handler {:?}) closed after {:?}, its bound: \
                 {reason}; the other vCPUs were held until then",
                self.vp(),
                w.vector,
                w.handler.map(|h| format!("{h:#x}")),
                w.opened.elapsed()
            ),
        );
        super::debug::WINDOWS_EXPIRED.fetch_add(1, Ordering::SeqCst);
        self.shared.close_window(&w)
    }

    /// A round of the window for the fault `vector` its delivery raised:
    /// out of the intercepted faults, DR0 on its handler. The INT3 runs
    /// again and faults natively.
    #[cfg(feature = "gdb")]
    fn window_round(&self, w: &mut super::debug::Window, vector: u8) -> Result<()> {
        w.faults &= !(1u64 << vector);
        w.vector = vector;
        w.handler = self.handler_of(vector);
        arm_window(self.part(), self.vp(), w.handler)?;
        self.shared.inner.set_window_bitmap(super::debug::window_bitmap(w.faults))
    }

    /// The handler `vector`'s gate sends the CPU to, from the guest's IDT
    /// as the vCPU's registers name it; `None` if the gate sends nowhere or
    /// cannot be read (delivery through it faults).
    #[cfg(feature = "gdb")]
    fn handler_of(&self, vector: u8) -> Option<u64> {
        use super::debug::{self, Target};
        let s = self.get_sregs().ok()?;
        let mode = debug::table_mode(s.cr0, s.efer);
        let (at, size) = debug::gate_at(mode, s.idt.base, s.idt.limit, vector)?;
        let mut gate = [0u8; 16];
        self.read_linear(s.cr0, at, &mut gate[..size])?;
        match debug::gate_target(mode, &gate[..size])? {
            Target::Linear(handler) => Some(handler),
            Target::Segment { selector, offset } => {
                let (base, limit) = if selector & 4 != 0 {
                    (s.ldt.base, u64::from(s.ldt.limit))
                } else {
                    (s.gdt.base, u64::from(s.gdt.limit))
                };
                let at = u64::from(selector & !7);
                if at + 7 > limit {
                    return None;
                }
                let mut d = [0u8; 8];
                self.read_linear(s.cr0, base.wrapping_add(at), &mut d)?;
                Some(debug::descriptor_base(&d).wrapping_add(offset) & 0xFFFF_FFFF)
            }
        }
    }

    /// Reads guest memory at linear address `at` as the vCPU sees it (its
    /// page tables when paging is on, walked as `KVM_TRANSLATE` walks them),
    /// from guest RAM only.
    #[cfg(feature = "gdb")]
    fn read_linear(&self, cr0: u64, at: u64, buf: &mut [u8]) -> Option<()> {
        let mut done = 0;
        while done < buf.len() {
            let addr = at.wrapping_add(done as u64);
            let n = usize::try_from(0x1000 - (addr & 0xFFF)).unwrap().min(buf.len() - done);
            let gpa = if cr0 & super::debug::CR0_PG != 0 {
                match self.translate_walk(addr, super::debug::TRANSLATE_FLAGS) {
                    Ok((0, gpa)) => gpa,
                    _ => return None,
                }
            } else {
                addr
            };
            let host = self.shared.inner.host_addr(gpa)?;
            // The rest of the page is in the same slot: slots are whole
            // pages. SAFETY: guest RAM, mapped in this process while its
            // slot is.
            unsafe { std::ptr::copy_nonoverlapping(host as *const u8, buf[done..].as_mut_ptr(), n) };
            done += n;
        }
        Some(())
    }
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        regs::get_sregs(self.part(), self.vp())
    }
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        regs::set_sregs(self.part(), self.vp(), sregs)
    }
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        regs::get_fpu(self.part(), self.vp(), self.shared.before_run.lock().unwrap().as_ref())
    }
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        regs::set_fpu(self.part(), self.vp(), fpu, self.shared.before_run.lock().unwrap().as_mut())
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
    /// `KVM_GET_XSAVE`: `EINVAL` on a host whose state is larger than
    /// `struct kvm_xsave`, as on Linux (`regs::get_xsave`).
    pub unsafe fn get_xsave(&self) -> Result<kvm_xsave> {
        let mut out = kvm_xsave { region: [0; 1024], extra: Default::default() };
        // SAFETY: the region's 4096 bytes, as bytes.
        let bytes = unsafe { std::slice::from_raw_parts_mut(out.region.as_mut_ptr().cast::<u8>(), regs::KVM_XSAVE_LEN) };
        regs::get_xsave(self.part(), self.vp(), bytes)?;
        if let Some(image) = self.shared.before_run.lock().unwrap().as_ref() {
            image.as_linux_reads(bytes);
        }
        Ok(out)
    }
    /// # Safety
    /// As [`Self::get_xsave`].
    pub unsafe fn set_xsave(&self, xsave: &kvm_xsave) -> Result<()> {
        // SAFETY: the region's 4096 bytes, as bytes.
        let bytes = unsafe { std::slice::from_raw_parts(xsave.region.as_ptr().cast::<u8>(), regs::KVM_XSAVE_LEN) };
        self.set_xsave_bytes(bytes)
    }
    /// `KVM_SET_XSAVE`, and for a vCPU that has not run what it makes of
    /// Linux's image.
    fn set_xsave_bytes(&self, bytes: &[u8]) -> Result<()> {
        regs::set_xsave(self.part(), self.vp(), bytes)?;
        if let Some(image) = self.shared.before_run.lock().unwrap().as_mut() {
            image.set_xsave(bytes);
        }
        Ok(())
    }
    /// # Safety
    /// As [`Self::get_xsave`].
    /// `KVM_GET_XSAVE2`: into the whole of `xsave`, which its caller made
    /// of `KVM_CAP_XSAVE2`'s size; `EINVAL` if the state does not fit it.
    pub unsafe fn get_xsave2(&self, xsave: &mut Xsave) -> Result<()> {
        let p = xsave.as_mut_fam_struct_ptr();
        // SAFETY: the wrapper owns a `kvm_xsave2` followed by `len` entries
        // of 4 bytes, which continue its `xsave`'s region.
        let bytes = unsafe {
            let len = regs::KVM_XSAVE_LEN + 4 * (*p).len;
            std::slice::from_raw_parts_mut((&raw mut (*p).xsave).cast::<u8>(), len)
        };
        regs::get_xsave(self.part(), self.vp(), bytes)?;
        if let Some(image) = self.shared.before_run.lock().unwrap().as_ref() {
            image.as_linux_reads(bytes);
        }
        Ok(())
    }
    /// # Safety
    /// As [`Self::get_xsave`].
    /// `KVM_SET_XSAVE` with the whole of `xsave`.
    pub unsafe fn set_xsave2(&self, xsave: &Xsave) -> Result<()> {
        let p = xsave.as_fam_struct_ptr();
        // SAFETY: as in `get_xsave2`.
        let bytes = unsafe {
            let len = regs::KVM_XSAVE_LEN + 4 * (*p).len;
            std::slice::from_raw_parts((&raw const (*p).xsave).cast::<u8>(), len)
        };
        self.set_xsave_bytes(bytes)
    }

    /// The bytes WHP writes for this vCPU's XSAVE state now (the record of
    /// each host's size).
    #[cfg(test)]
    pub(crate) fn xsave_state_len(&self) -> Result<usize> {
        regs::read_xsave(self.part(), self.vp()).map(|(_, written)| written)
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
                self.write_kvm_msr(e.index, e.data)?;
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
    fn write_kvm_msr(&self, index: u32, value: u64) -> Result<bool> {
        let inner = &self.shared.inner;
        let now = || inner.irqchip.lock().unwrap().clock().clock;
        match index {
            pvclock::MSR_SYSTEM_TIME => {
                self.shared.system_time_msr.store(value, Ordering::Release);
                let generation = inner.pvclock.lock().unwrap().generation;
                self.shared.clock_gen.store(generation, Ordering::Release);
                pvclock::system_time(&inner.pvclock, self.part(), self.vp(), value, inner.ram(), now)?;
                Ok(true)
            }
            pvclock::MSR_WALL_CLOCK => {
                pvclock::wall_clock(&inner.pvclock, value, inner.ram(), now());
                Ok(true)
            }
            _ => Ok(false),
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
        #[cfg(test)]
        let before = super::ffi::trace::stack();
        // SAFETY: valid output buffer of the given size.
        let hres = unsafe {
            whv::WHvGetVirtualProcessorInterruptControllerState(
                self.part(),
                self.vp(),
                page.as_mut_ptr().cast(),
                LAPIC_PAGE as u32,
                &mut written,
            )
        };
        #[cfg(test)]
        super::ffi::trace::note("WHvGetVirtualProcessorInterruptControllerState", self.vp(), &[], None, before, hres);
        super::ffi::hr_of("WHvGetVirtualProcessorInterruptControllerState", hres, || format!("vp {}", self.vp()))?;
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
        #[cfg(test)]
        let before = super::ffi::trace::stack();
        // SAFETY: the register page is valid for `size` bytes.
        let hres = unsafe {
            whv::WHvSetVirtualProcessorInterruptControllerState(self.part(), self.vp(), page.as_ptr().cast(), size)
        };
        #[cfg(test)]
        super::ffi::trace::note("WHvSetVirtualProcessorInterruptControllerState", self.vp(), &[], None, before, hres);
        super::ffi::hr_of("WHvSetVirtualProcessorInterruptControllerState", hres, || format!("vp {}", self.vp()))
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

    /// One `WHvRunVirtualProcessor`, unless a kick came first. While
    /// another vCPU's #BP window is open this one waits out of the guest
    /// (and a kick still returns); while its own is, a kick waits for the
    /// window's end (one delivery), and a window that outlived its bound
    /// comes back for the run loop to close.
    fn enter(&self) -> Result<Entry> {
        let shared = &self.shared;
        let vp = self.vp();
        let own_window = loop {
            shared.run_seq.fetch_add(1, Ordering::SeqCst);
            let owner = shared.inner.bp_owner.load(Ordering::SeqCst);
            if owner < 0 || owner == i64::from(vp) {
                break owner >= 0;
            }
            shared.run_seq.fetch_add(1, Ordering::SeqCst);
            if !shared.inner.wait_bp_window(vp, &shared.immediate_exit) {
                return Ok(Entry::Kicked);
            }
        };
        let result = self.update_clock().and_then(|()| self.raise_fired_deadline()).and_then(|()| {
            if own_window && self.window_expired() {
                Ok(Entry::WindowExpired)
            } else if !own_window && shared.immediate_exit.load(Ordering::SeqCst) != 0 {
                Ok(Entry::Kicked)
            } else {
                super::ffi::run_vp(self.part(), vp).map(Entry::Ran)
            }
        });
        shared.run_seq.fetch_add(1, Ordering::SeqCst);
        result
    }

    /// Publishes this vCPU's kvm-clock time info again if the VM clock was
    /// set since it was published (`pvclock`: a snapshot restore sets the
    /// clock after the vCPUs' MSRs), as KVM does on `KVM_REQ_CLOCK_UPDATE`.
    fn update_clock(&self) -> Result<()> {
        let inner = &self.shared.inner;
        let generation = inner.pvclock.lock().unwrap().generation;
        if self.shared.clock_gen.swap(generation, Ordering::AcqRel) == generation {
            return Ok(());
        }
        let value = self.shared.system_time_msr.load(Ordering::Acquire);
        let now = || inner.irqchip.lock().unwrap().clock().clock;
        // Not published: still to be, at the next entry there is.
        pvclock::system_time(&inner.pvclock, self.part(), self.vp(), value, inner.ram(), now)
            .inspect_err(|_| self.shared.clock_gen.store(u64::MAX, Ordering::Release))
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
        #[cfg(feature = "gdb")]
        let shared = Arc::clone(&self.shared);
        let exit = self.run_loop();
        // A return with a #BP window open, at none of its ends: it closes
        // first, so that no other vCPU stays held.
        #[cfg(feature = "gdb")]
        {
            let open = shared.debug.lock().unwrap().window.take();
            if let Some(w) = open {
                #[cfg(test)]
                eprintln!(
                    "BPTEST window closed by the run's return ({}), delivering vector {}",
                    if exit.is_ok() { "an exit" } else { "an error" },
                    w.vector
                );
                if let Err(e) = shared.close_window(&w) {
                    if exit.is_ok() {
                        return Err(e);
                    }
                }
            }
        }
        exit
    }

    fn run_loop(&mut self) -> Result<VcpuExit<'_>> {
        // From its first KVM_RUN on, the vCPU's x87 and SSE state is the
        // one it runs with (`regs::BeforeRun`).
        *self.shared.before_run.lock().unwrap() = None;
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
            let ctx = match self.enter()? {
                Entry::Ran(ctx) => ctx,
                Entry::Kicked => return err(libc::EINTR),
                Entry::WindowExpired => {
                    #[cfg(feature = "gdb")]
                    self.end_expired_window()?;
                    continue;
                }
            };
            let instr_len = super::exit::instruction_length(ctx.VpContext._bitfield);
            let rip = ctx.VpContext.Rip;

            match ctx.ExitReason {
                whv::WHvRunVpExitReasonNone => continue,
                // A kick (`immediate_exit`) is KVM's EINTR; a cancel from
                // a TSC-deadline timer only made the vCPU leave the guest to
                // take its interrupt (`enter`).
                whv::WHvRunVpExitReasonCanceled => {
                    // In this vCPU's own #BP window a kick waits for the
                    // window's end (`enter`).
                    if self.shared.immediate_exit.load(Ordering::SeqCst) != 0 && !self.shared.in_bp_window() {
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
                            super::ffi::report(
                                log::Level::Error,
                                &format!("whp: guest RAM at {:#x} stays inaccessible", mem.Gpa),
                            );
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
                    if let Some(mut w) = state.window.take() {
                        let vector = ex.ExceptionType;
                        // The linear address DR0 compares: RIP in 64-bit
                        // code (every IA-32e handler), CS's base plus RIP
                        // otherwise.
                        // SAFETY: plain 16-bit views of the exit context's bit fields.
                        let (mode, cs) = unsafe { (ctx.VpContext.ExecutionState.AsUINT16, ctx.VpContext.Cs.Anonymous.Attributes) };
                        let at = if super::exit::long_mode_code(mode, cs) {
                            rip
                        } else {
                            ctx.VpContext.Cs.Base.wrapping_add(rip) & 0xFFFF_FFFF
                        };
                        // The sequence of a window's exits, for the tests on a
                        // WHP machine (`bp_tests`).
                        #[cfg(test)]
                        eprintln!(
                            "BPTEST window exit: vector {vector}, RIP {rip:#x} (linear {at:#x}), error code {:#x}, \
                             parameter {:#x}; delivering vector {} to handler {:?}, faults intercepted {:#x}",
                            ex.ErrorCode,
                            ex.ExceptionParameter,
                            w.vector,
                            w.handler.map(|h| format!("{h:#x}")),
                            w.faults
                        );
                        if vector == super::debug::DB_VECTOR && w.handler == Some(at) {
                            // The delivery reached its handler: the window's
                            // end. The guest goes on into the handler.
                            self.shared.close_window(&w)?;
                            continue;
                        }
                        if vector < 64 && w.faults & (1u64 << vector) != 0 {
                            // The delivery faulted: a round for that fault.
                            let round = self.window_round(&mut w, vector);
                            state.window = Some(w);
                            round?;
                            continue;
                        }
                        // Anything else (a #DB elsewhere: the guest's own
                        // TF or breakpoint): the window ends, and the exit
                        // is gdb's as any other.
                        self.shared.close_window(&w)?;
                    }
                    let dr7 = state.hw.map_or(0, |(_, dr7)| dr7);
                    let Some(arch) = super::debug::debug_exit(ex.ExceptionType, rip, ex.ExceptionParameter, dr7)
                    else {
                        return Ok(VcpuExit::InternalError);
                    };
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
                // IA32_XSS where the partition keeps it; where it keeps
                // none the guest cannot have set one (its WRMSR is an exit
                // that is ignored, `handle_msr`) and KVM's `ia32_xss` of a
                // vCPU without XSAVES is 0 as well. A read that fails where
                // the register is kept fails the run, as every other read
                // here: a size computed from a guessed 0 is not an answer.
                let xss = if regs::partition_keeps(whv::WHvX64RegisterXss) {
                    self.register(whv::WHvX64RegisterXss)?
                } else {
                    0
                };
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
                self.write_kvm_msr(index, value)?;
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

/// Makes every vCPU of `inner`'s partition but `except` leave the guest,
/// for one that has the exception exits (`VmInner::bp_owner`): its run is
/// cancelled until its run sequence is even. It cannot enter again until
/// they are let go: `enter` makes the sequence odd before it reads the
/// owner, which was stored before this reads the sequence (both
/// sequentially consistent), as the kick does.
pub(crate) fn hold_vcpus(inner: &VmInner, except: Option<u32>) {
    let others: Vec<Arc<VcpuShared>> = inner
        .vcpus
        .lock()
        .unwrap()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|s| Some(s.index) != except)
        .collect();
    for other in &others {
        let mut spins = 0u32;
        while other.run_seq.load(Ordering::SeqCst) % 2 == 1 {
            let _ = super::ffi::cancel_run(other.part, other.index);
            spins += 1;
            if spins < 64 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
        }
    }
}

/// What an entry into the guest came to ([`VcpuFd::enter`]).
enum Entry {
    Ran(whv::WHV_RUN_VP_EXIT_CONTEXT),
    /// `immediate_exit`: the run returns `EINTR`.
    Kicked,
    /// This vCPU's #BP window outlived its bound.
    WindowExpired,
}

/// `WHV_X64_INTERRUPT_STATE_REGISTER`'s NMI mask (bit 1).
const INTERRUPT_STATE_NMI_MASKED: u64 = 1 << 1;

/// A #BP window's DR0 and DR7: an instruction breakpoint on `handler`, or
/// none.
#[cfg(feature = "gdb")]
fn arm_window(part: WHV_PARTITION_HANDLE, vp: u32, handler: Option<u64>) -> Result<()> {
    let hw = match handler {
        Some(h) => ([h, 0, 0, 0], super::debug::WINDOW_DR7),
        None => ([0; 4], super::debug::DR7_NONE),
    };
    write_hw_breakpoints(part, vp, hw)
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

// The #BP window ([`super::debug`]) on a WHP machine, with small long-mode
// guests: the guest's own INT3 handed back as upstream's gdb stub asks
// (`KVM_GUESTDBG_INJECT_BP`, as for the kernel's `int3_selftest`, Linux
// v6.12 arch/x86/kernel/alternative.c, which the gdb stage's boot runs into).
// What led here, measured on an AMD host (bf52d6f): a pending #BP through
// `WHvRegisterPendingInterruption` (hardware exception or software
// exception, length 0 or 1) is refused with STATUS_HV_INVALID_PARAMETER,
// through `WHvRegisterPendingEvent` it gives an InternalError exit, and only
// the guest's INT3 run again with #BP out of the exception exits delivers it
// (the guest's handler ran, pushed RIP past the INT3). QEMU's WHPX never
// intercepts INT3 (whpx-all.c: "the WHPX API does not offer an easy way to
// pass the intercepted exception back to the guest").
#[cfg(all(test, feature = "gdb"))]
mod bp_tests {
    use super::*;
    use kvm_bindings::{
        kvm_guest_debug, kvm_mp_state, kvm_segment, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_INJECT_BP,
        KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP, KVM_MP_STATE_RUNNABLE,
    };
    use std::sync::atomic::AtomicBool;

    const MEM: usize = 4 << 20;
    /// vCPU 0: the guest's own INT3, `out 0x80, al`, a `nop` (where gdb
    /// puts a hardware breakpoint), gdb's INT3, `jmp $`.
    const CODE: u64 = 0x6000;
    /// vCPU 1: gdb's INT3, `jmp` back to it.
    const CODE1: u64 = 0x6100;
    /// vCPU 0 in the two-vCPU test: the guest's INT3, `out 0x80, al`, `jmp`
    /// back to the INT3.
    const LOOP0: u64 = 0x6200;
    /// The #BP handler: stores the RIP pushed, DR7 and DR0 as it reads them,
    /// counts itself, `iretq`.
    const HANDLER: u64 = 0x7000;
    /// The #NP handler: stores its error code and the RIP pushed, then
    /// `out 0x82, al` and `jmp $`.
    const NP_HANDLER: u64 = 0x7100;
    const PUSHED: u64 = 0x8000;
    const COUNT: u64 = 0x8008;
    const DR7_SEEN: u64 = 0x8010;
    const DR0_SEEN: u64 = 0x8018;
    const NP_ERR: u64 = 0x8020;
    const NP_RIP: u64 = 0x8028;
    const STACK: u64 = 0x9000;
    const STACK1: u64 = 0xA000;
    const GDT: u64 = 0x4000;
    const IDT: u64 = 0x5000;
    const PORT: u16 = 0x80;
    const NP_PORT: u16 = 0x82;
    /// The guest's own DR0 and DR7 (no breakpoint enabled: LE, GE, bit 10).
    const GUEST_DR0: u64 = 0x1234_5000;
    const GUEST_DR7: u64 = 0x700;
    /// `WHvCapabilityCodeExceptionExitBitmap`, `WHvCapabilityCodeProcessorVendor`.
    const CAP_EXCEPTION_EXIT_BITMAP: whv::WHV_CAPABILITY_CODE = 3;
    const CAP_PROCESSOR_VENDOR: whv::WHV_CAPABILITY_CODE = 0x1000;

    /// An interrupt gate (0x8E) to `handler` through selector 8.
    fn gate(m: *mut u8, vector: u64, handler: u64) {
        let low = (handler & 0xFFFF) | (8 << 16) | (0x8E << 40) | (((handler >> 16) & 0xFFFF) << 48);
        put(m, IDT + vector * 16, &low.to_le_bytes());
        put(m, IDT + vector * 16 + 8, &(handler >> 32).to_le_bytes());
    }

    fn put(m: *mut u8, at: u64, bytes: &[u8]) {
        // SAFETY: within the test's mapping.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), m.add(at as usize), bytes.len()) };
    }

    fn peek(m: *mut u8, at: u64) -> u64 {
        // SAFETY: within the test's mapping, 8-byte aligned.
        unsafe { std::ptr::read_volatile(m.add(at as usize).cast::<u64>()) }
    }

    /// Guest memory with long mode's tables (the first 2 MiB identity
    /// mapped), a GDT (64-bit code at 8, data at 0x10), an IDT with the #NP
    /// gate and, if `bp_gate`, the #BP gate, the code and the handlers.
    fn guest(bp_gate: bool) -> *mut u8 {
        // SAFETY: anonymous memory for the test, unmapped by the caller.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                MEM,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        let m = p.cast::<u8>();
        let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
        q(0x1000, 0x2000 | 3);
        q(0x2000, 0x3000 | 3);
        q(0x3000, 0x83);
        q(GDT + 8, 0x00AF_9A00_0000_FFFF);
        q(GDT + 16, 0x00CF_9200_0000_FFFF);
        if bp_gate {
            gate(m, 3, HANDLER);
        } else {
            // Absent: an interrupt gate (type 0xE) whose P bit is clear, so
            // that the INT3 raises #NP. An all-zero entry is not a gate type
            // at all, which raises #GP first (the INT instruction's checks
            // in order: type, then DPL, then P; SDM vol. 2A, INT n/INTO/INT3
            // operation); with no #GP gate that is #DF and then a triple
            // fault, as the first run on a WHP machine gave (578b04f).
            gate(m, 3, HANDLER);
            put(m, IDT + 3 * 16 + 5, &[0x0E]);
        }
        gate(m, 11, NP_HANDLER);
        put(m, CODE, &[0xCC, 0xE6, PORT as u8, 0x90, 0xCC, 0xEB, 0xFE]);
        put(m, CODE1, &[0xCC, 0xEB, 0xFD]);
        put(m, LOOP0, &[0xCC, 0xE6, PORT as u8, 0xEB, 0xFB]);
        put(
            m,
            HANDLER,
            &[
                0x48, 0x8B, 0x04, 0x24, // mov rax, [rsp]
                0x48, 0x89, 0x04, 0x25, 0x00, 0x80, 0x00, 0x00, // mov [PUSHED], rax
                0x0F, 0x21, 0xF8, // mov rax, dr7
                0x48, 0x89, 0x04, 0x25, 0x10, 0x80, 0x00, 0x00, // mov [DR7_SEEN], rax
                0x0F, 0x21, 0xC0, // mov rax, dr0
                0x48, 0x89, 0x04, 0x25, 0x18, 0x80, 0x00, 0x00, // mov [DR0_SEEN], rax
                0xF0, 0x48, 0xFF, 0x04, 0x25, 0x08, 0x80, 0x00, 0x00, // lock inc qword [COUNT]
                0x48, 0xCF, // iretq
            ],
        );
        put(
            m,
            NP_HANDLER,
            &[
                0x48, 0x8B, 0x04, 0x24, // mov rax, [rsp]: the error code
                0x48, 0x89, 0x04, 0x25, 0x20, 0x80, 0x00, 0x00, // mov [NP_ERR], rax
                0x48, 0x8B, 0x44, 0x24, 0x08, // mov rax, [rsp + 8]: the RIP
                0x48, 0x89, 0x04, 0x25, 0x28, 0x80, 0x00, 0x00, // mov [NP_RIP], rax
                0xE6, NP_PORT as u8, // out 0x82, al
                0xEB, 0xFE, // jmp $
            ],
        );
        m
    }

    fn segment(selector: u16, type_: u8, l: u8, db: u8) -> kvm_segment {
        kvm_segment {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector,
            type_,
            present: 1,
            dpl: 0,
            db,
            s: 1,
            l,
            g: 1,
            ..Default::default()
        }
    }

    /// A VM whose RAM is `guest(bp_gate)`.
    fn vm_with(bp_gate: bool) -> (super::super::VmFd, *mut u8) {
        let vm = super::super::VmFd::create().unwrap();
        let m = guest(bp_gate);
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: MEM as u64,
            userspace_addr: m as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        (vm, m)
    }

    fn unmap(m: *mut u8) {
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The vCPU in long mode at `rip`, #BP intercepted as gdb's software
    /// breakpoints are.
    fn start(vcpu: &VcpuFd, rip: u64, rsp: u64) {
        let mut s = vcpu.get_sregs().unwrap();
        s.cr0 = 0x8000_0031; // PG, NE, ET, PE
        s.cr3 = 0x1000;
        s.cr4 = 0x20; // PAE
        s.efer = 0x500; // LME, LMA
        s.cs = segment(8, 11, 1, 0);
        let data = segment(0x10, 3, 0, 1);
        (s.ds, s.es, s.fs, s.gs, s.ss) = (data, data, data, data, data);
        s.tr.type_ = 11;
        s.tr.present = 1;
        s.tr.s = 0;
        (s.gdt.base, s.gdt.limit) = (GDT, 23);
        (s.idt.base, s.idt.limit) = (IDT, 4095);
        vcpu.set_sregs(&s).unwrap();
        vcpu.set_regs(&kvm_regs { rip, rsp, rflags: 2, ..Default::default() }).unwrap();
        let control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
        vcpu.set_guest_debug(&kvm_guest_debug { control, ..Default::default() }).unwrap();
    }

    /// What upstream's `inject_bp_to_guest` does: `vcpu_inject_bp`.
    fn hand_back(vcpu: &VcpuFd, mut dbg: kvm_guest_debug) {
        dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_INJECT_BP;
        vcpu.set_guest_debug(&dbg).unwrap();
    }

    fn describe(exit: Result<VcpuExit<'_>>) -> String {
        match exit {
            Ok(VcpuExit::IoOut(port, _)) => format!("exit IoOut port {port:#x}"),
            Ok(VcpuExit::Debug(arch)) => format!("exit Debug vector {} pc {:#x}", arch.exception, arch.pc),
            Ok(VcpuExit::Shutdown) => "exit Shutdown".to_string(),
            Ok(VcpuExit::InternalError) => "exit InternalError".to_string(),
            Ok(_) => "exit (another)".to_string(),
            Err(e) if e.errno() == libc::EINTR => "kicked".to_string(),
            Err(e) => format!("run failed, errno {}", e.errno()),
        }
    }

    /// One `run`, kicked after 5 s if it has not returned, as a line.
    fn run_once(vcpu: &mut VcpuFd) -> String {
        let done = Arc::new(AtomicBool::new(false));
        let mut kicker = VcpuFd { shared: Arc::clone(&vcpu.shared), own: None };
        let watch = Arc::clone(&done);
        let watchdog = std::thread::spawn(move || {
            for _ in 0..500 {
                if watch.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            kicker.set_kvm_immediate_exit(1);
        });
        let line = describe(vcpu.run());
        done.store(true, Ordering::SeqCst);
        watchdog.join().unwrap();
        if line == "kicked" { "no exit within 5 s (kicked)".to_string() } else { line }
    }

    fn capability(code: whv::WHV_CAPABILITY_CODE) -> String {
        let mut buf = [0u64; 4];
        let mut written = 0u32;
        // SAFETY: a buffer of the size passed.
        let hres = unsafe { whv::WHvGetCapability(code, buf.as_mut_ptr().cast(), 32, &mut written) };
        format!("HRESULT {:#010x}, {written} bytes, {:#x}", hres.cast_unsigned(), buf[0])
    }

    fn expired() -> u64 {
        super::super::debug::WINDOWS_EXPIRED.load(Ordering::SeqCst)
    }

    /// The guest's own INT3, handed back: its handler runs with the RIP
    /// past the INT3 pushed and reads the guest's own DR7 and DR0 (the
    /// window's are gone before its first instruction), and #BP is gdb's
    /// again after it: gdb's INT3 that follows stops the vCPU.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_bp_handed_back_to_the_guest() {
        eprintln!("BPTEST exception exit bitmap capability: {}", capability(CAP_EXCEPTION_EXIT_BITMAP));
        eprintln!("BPTEST processor vendor (0 AMD, 1 Intel, 2 Hygon): {}", capability(CAP_PROCESSOR_VENDOR));
        let before = expired();
        let (vm, m) = vm_with(true);
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu, CODE, STACK);
        vcpu.set_debug_regs(&kvm_debugregs { db: [GUEST_DR0, 0, 0, 0], dr7: GUEST_DR7, ..Default::default() })
            .unwrap();
        assert_eq!(run_once(&mut vcpu), format!("exit Debug vector 3 pc {CODE:#x}"));
        hand_back(&vcpu, kvm_guest_debug::default());
        assert_eq!(run_once(&mut vcpu), format!("exit IoOut port {PORT:#x}"), "the handler ran and returned");
        assert_eq!(peek(m, COUNT), 1);
        assert_eq!(peek(m, PUSHED), CODE + 1, "the RIP pushed is past the INT3, as on hardware");
        assert_eq!(peek(m, DR7_SEEN), GUEST_DR7, "the handler reads the guest's DR7, not the window's");
        assert_eq!(peek(m, DR0_SEEN), GUEST_DR0, "the handler reads the guest's DR0, not the window's");
        assert_eq!(run_once(&mut vcpu), format!("exit Debug vector 3 pc {:#x}", CODE + 4), "#BP is gdb's again");
        assert_eq!(peek(m, COUNT), 1);
        let d = vcpu.get_debug_regs().unwrap();
        assert_eq!((d.db[0], d.dr7), (GUEST_DR0, GUEST_DR7));
        assert_eq!(expired(), before, "no window needed its bound");
        drop(vcpu);
        drop(vm);
        unmap(m);
    }

    /// vCPU 1 runs into gdb's INT3 again and again while vCPU 0's own INT3s
    /// are handed back: whether vCPU 1 was held during a window or ran
    /// between them, its INT3 always stops it and never reaches the guest's
    /// handler.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_bp_window_holds_the_other_vcpus() {
        const ROUNDS: u64 = 200;
        let before = expired();
        let (vm, m) = vm_with(true);
        let mut vcpu0 = vm.create_vcpu(0).unwrap();
        let mut vcpu1 = vm.create_vcpu(1).unwrap();
        start(&vcpu0, LOOP0, STACK);
        start(&vcpu1, CODE1, STACK1);
        // An application processor waits for a SIPI; this one runs at once.
        vcpu1.set_mp_state(kvm_mp_state { mp_state: KVM_MP_STATE_RUNNABLE }).unwrap();
        let mut kick1 = VcpuFd { shared: Arc::clone(&vcpu1.shared), own: None };
        let other = std::thread::spawn(move || {
            let mut stops = 0u64;
            loop {
                let line = describe(vcpu1.run());
                if line == format!("exit Debug vector 3 pc {CODE1:#x}") {
                    stops += 1;
                } else if line == "kicked" {
                    return Ok(stops);
                } else {
                    return Err(line);
                }
            }
        });
        for round in 0..ROUNDS {
            assert_eq!(run_once(&mut vcpu0), format!("exit Debug vector 3 pc {LOOP0:#x}"), "round {round}");
            hand_back(&vcpu0, kvm_guest_debug::default());
            assert_eq!(run_once(&mut vcpu0), format!("exit IoOut port {PORT:#x}"), "round {round}");
        }
        kick1.set_kvm_immediate_exit(1);
        let stops = other.join().unwrap().expect("vCPU 1 stops only at gdb's INT3");
        eprintln!("BPTEST vCPU 1 stopped at gdb's INT3 {stops} times during vCPU 0's {ROUNDS} windows");
        assert_eq!(peek(m, COUNT), ROUNDS, "only vCPU 0's own INT3s reached the guest's handler");
        assert!(stops > 0, "vCPU 1 ran meanwhile");
        assert_eq!(expired(), before, "no window needed its bound");
        drop(vcpu0);
        drop(kick1);
        drop(vm);
        unmap(m);
    }

    /// A #BP whose gate is absent: its delivery faults with #NP natively, as
    /// on hardware: the guest's #NP handler runs, with the error code that
    /// names IDT entry 3 (index 3, IDT bit; EXT clear for INT3) and the RIP
    /// of the INT3 (a fault).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_bp_delivery_fault_is_the_guests() {
        let before = expired();
        let (vm, m) = vm_with(false);
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu, CODE, STACK);
        assert_eq!(run_once(&mut vcpu), format!("exit Debug vector 3 pc {CODE:#x}"));
        hand_back(&vcpu, kvm_guest_debug::default());
        assert_eq!(run_once(&mut vcpu), format!("exit IoOut port {NP_PORT:#x}"), "the #NP handler ran");
        assert_eq!(peek(m, NP_ERR), (3 << 3) | 2);
        assert_eq!(peek(m, NP_RIP), CODE);
        assert_eq!(peek(m, COUNT), 0);
        assert_eq!(expired(), before, "no window needed its bound");
        drop(vcpu);
        drop(vm);
        unmap(m);
    }

    /// gdb's own breakpoints after a guest's INT3 was handed back: its
    /// hardware breakpoint (DR0, which the window borrowed) fires, then its
    /// INT3 stops the vCPU.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_gdb_breakpoints_after_a_handed_back_bp() {
        let before = expired();
        let (vm, m) = vm_with(true);
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu, CODE, STACK);
        // As upstream's vcpu_set_debug: DR0 on the `nop`, DR7's G0, GE and
        // bit 10.
        let mut dbg = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW_BP,
            ..Default::default()
        };
        dbg.arch.debugreg[0] = CODE + 3;
        dbg.arch.debugreg[7] = (1 << 10) | (1 << 9) | 0b10;
        vcpu.set_guest_debug(&dbg).unwrap();
        assert_eq!(run_once(&mut vcpu), format!("exit Debug vector 3 pc {CODE:#x}"));
        hand_back(&vcpu, dbg);
        assert_eq!(run_once(&mut vcpu), format!("exit IoOut port {PORT:#x}"), "the handler ran and returned");
        assert_eq!((peek(m, COUNT), peek(m, PUSHED)), (1, CODE + 1));
        assert_eq!(run_once(&mut vcpu), format!("exit Debug vector 1 pc {:#x}", CODE + 3), "gdb's hardware breakpoint");
        vcpu.set_guest_debug(&dbg).unwrap();
        assert_eq!(run_once(&mut vcpu), format!("exit Debug vector 3 pc {:#x}", CODE + 4), "gdb's INT3");
        assert_eq!(peek(m, COUNT), 1);
        assert_eq!(expired(), before, "no window needed its bound");
        drop(vcpu);
        drop(vm);
        unmap(m);
    }

    /// `WHvRegisterPendingEvent` (WinHvPlatformDefs.h).
    const PENDING_EVENT: whv::WHV_REGISTER_NAME = 0x8000_0002u32 as i32;

    /// `WHV_X64_PENDING_INTERRUPTION_REGISTER` for #BP: pending, `kind` (3
    /// exception; 6 Hyper-V's software exception, which WHP's header does not
    /// list), instruction length `len`, vector 3.
    fn pending_interruption(kind: u64, len: u64) -> u64 {
        1 | (kind << 1) | (len << 5) | (3 << 16)
    }

    /// The ways to hand a #BP back to the guest that 32fd94c tried, on
    /// record for each processor vendor (it prints, and asserts only its
    /// scaffold): from the exit at the guest's INT3, each way in a VM of its
    /// own, what its calls returned, the exit that followed, whether the
    /// guest's handler ran and the RIP it was given (the INT3 is at 0x6000;
    /// Linux's handler expects 0x6001). (i) is the backend's #BP window
    /// (`KVM_GUESTDBG_INJECT_BP`); before it, (i) was a pending exception
    /// #BP, which WHP refused with 0xc0350005 on an AMD host (578b04f).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_bp_ways_on_record() {
        eprintln!("BPTEST exception exit bitmap capability: {}", capability(CAP_EXCEPTION_EXIT_BITMAP));
        eprintln!("BPTEST processor vendor (0 AMD, 1 Intel, 2 Hygon): {}", capability(CAP_PROCESSOR_VENDOR));
        type Way = fn(&VcpuFd) -> Vec<String>;
        let ways: [(&str, Way); 5] = [
            ("i: the #BP window (INJECT_BP)", |v| {
                let control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_INJECT_BP;
                let r = v.set_guest_debug(&kvm_guest_debug { control, ..Default::default() });
                vec![format!("set_guest_debug(INJECT_BP): {:?}", r.map_err(|e| e.errno()))]
            }),
            ("ii-a: RIP at the INT3, PendingInterruption exception #BP, length 1", |v| {
                let r = super::super::ffi::set_register(
                    v.part(),
                    v.vp(),
                    whv::WHvRegisterPendingInterruption,
                    super::super::ffi::reg64(pending_interruption(3, 1)),
                );
                vec![format!("set PendingInterruption {:#x}: {:?}", pending_interruption(3, 1), r.map_err(|e| e.errno()))]
            }),
            ("ii-b: RIP at the INT3, PendingInterruption type 6 (software exception) #BP, length 1", |v| {
                let r = super::super::ffi::set_register(
                    v.part(),
                    v.vp(),
                    whv::WHvRegisterPendingInterruption,
                    super::super::ffi::reg64(pending_interruption(6, 1)),
                );
                vec![format!("set PendingInterruption {:#x}: {:?}", pending_interruption(6, 1), r.map_err(|e| e.errno()))]
            }),
            ("iii: RIP+1, PendingEvent exception event #BP", |v| {
                let rip = super::super::ffi::set_register(
                    v.part(),
                    v.vp(),
                    whv::WHvX64RegisterRip,
                    super::super::ffi::reg64(CODE + 1),
                );
                let event = 1 | (3 << 16);
                let r = super::super::ffi::set_register(v.part(), v.vp(), PENDING_EVENT, super::super::ffi::reg64(event));
                vec![
                    format!("set RIP {:#x}: {:?}", CODE + 1, rip.map_err(|e| e.errno())),
                    format!("set PendingEvent {event:#x}: {:?}", r.map_err(|e| e.errno())),
                ]
            }),
            ("iv: #BP out of the exit bitmap, RIP at the INT3, the guest runs it", |v| {
                let r = v.set_guest_debug(&kvm_guest_debug { control: KVM_GUESTDBG_ENABLE, ..Default::default() });
                vec![format!("set_guest_debug(ENABLE only: bitmap 0): {:?}", r.map_err(|e| e.errno()))]
            }),
        ];
        let mut scaffold = Vec::new();
        for (name, way) in ways {
            let (vm, m) = vm_with(true);
            let mut vcpu = vm.create_vcpu(0).unwrap();
            start(&vcpu, CODE, STACK);
            let first = run_once(&mut vcpu);
            eprintln!("BPTEST {name}: first {first}");
            if first == format!("exit Debug vector 3 pc {CODE:#x}") {
                for line in way(&vcpu) {
                    eprintln!("BPTEST {name}: {line}");
                }
                let then = run_once(&mut vcpu);
                let rip = vcpu.get_regs().map(|r| r.rip);
                eprintln!(
                    "BPTEST {name}: then {then}; handler ran {} time(s); pushed RIP {:#x}; RIP after {:?}",
                    peek(m, COUNT),
                    peek(m, PUSHED),
                    rip.map(|r| format!("{r:#x}"))
                );
            }
            scaffold.push((name, first));
            drop(vcpu);
            drop(vm);
            unmap(m);
        }
        // The scaffold itself: each VM stops at the guest's INT3 first.
        for (name, first) in scaffold {
            assert_eq!(first, format!("exit Debug vector 3 pc {CODE:#x}"), "{name}");
        }
    }
}

// KVM_SET_FPU and KVM_GET_FPU against a guest that says what it finds: the
// claim (a write to a vCPU whose guest has used x87 and SSE is what the
// guest finds, MXCSR excepted; regs.rs has Linux's source for both) and the
// record of what WHP holds before and after (FPUTEST lines), for the cases
// Linux's source decides by a header bit and nobody has measured on WHP: a
// vCPU that has not run, and an area written with a bit changed.
#[cfg(test)]
mod fpu_tests {
    use super::*;
    use kvm_bindings::{kvm_segment, Xsave};
    use std::sync::atomic::AtomicBool;

    const MEM: usize = 4 << 20;
    const GDT: u64 = 0x4000;
    /// The guest: stores its control word, status word, MXCSR, XMM3 and
    /// ST0, then leaves the initial x87 and SSE state for good (`fninit`,
    /// `fld1`; `pcmpeqd xmm5, xmm5`), `out 0x80, al`, `jmp $`.
    const CODE: u64 = 0x6000;
    const FCW: u64 = 0x8000;
    const MXCSR: u64 = 0x8010;
    const XMM3: u64 = 0x8020;
    const ST0: u64 = 0x8040;
    const PORT: u16 = 0x80;
    /// 1.5 and 2.5 as x87 registers hold them (80 bits, in 16 bytes).
    const ONE_AND_A_HALF: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0x3F, 0, 0, 0, 0, 0, 0];
    const TWO_AND_A_HALF: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0xA0, 0x00, 0x40, 0, 0, 0, 0, 0, 0];

    fn put(m: *mut u8, at: u64, bytes: &[u8]) {
        // SAFETY: within the test's mapping.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), m.add(at as usize), bytes.len()) };
    }

    fn bytes_at<const N: usize>(m: *mut u8, at: u64) -> [u8; N] {
        let mut b = [0u8; N];
        // SAFETY: within the test's mapping.
        unsafe { std::ptr::copy_nonoverlapping(m.add(at as usize), b.as_mut_ptr(), N) };
        b
    }

    /// Guest memory with long mode's tables (the first 2 MiB identity
    /// mapped), a GDT (64-bit code at 8, data at 0x10) and the code.
    fn guest() -> *mut u8 {
        // SAFETY: anonymous memory for the test, unmapped by the caller.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                MEM,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        let m = p.cast::<u8>();
        let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
        q(0x1000, 0x2000 | 3);
        q(0x2000, 0x3000 | 3);
        q(0x3000, 0x83);
        q(GDT + 8, 0x00AF_9A00_0000_FFFF);
        q(GDT + 16, 0x00CF_9200_0000_FFFF);
        put(
            m,
            CODE,
            &[
                0xD9, 0x3C, 0x25, 0x00, 0x80, 0x00, 0x00, // fnstcw [FCW]
                0xDD, 0x3C, 0x25, 0x08, 0x80, 0x00, 0x00, // fnstsw [FCW + 8]
                0x0F, 0xAE, 0x1C, 0x25, 0x10, 0x80, 0x00, 0x00, // stmxcsr [MXCSR]
                0x0F, 0x11, 0x1C, 0x25, 0x20, 0x80, 0x00, 0x00, // movups [XMM3], xmm3
                0xDB, 0x3C, 0x25, 0x40, 0x80, 0x00, 0x00, // fstp tword [ST0]
                0xDB, 0xE3, // fninit
                0xD9, 0xE8, // fld1
                0x66, 0x0F, 0x76, 0xED, // pcmpeqd xmm5, xmm5
                0xE6, PORT as u8, // out 0x80, al
                0xEB, 0xFE, // jmp $
            ],
        );
        m
    }

    fn segment(selector: u16, type_: u8, l: u8, db: u8) -> kvm_segment {
        kvm_segment {
            base: 0,
            limit: 0xFFFF_FFFF,
            selector,
            type_,
            present: 1,
            dpl: 0,
            db,
            s: 1,
            l,
            g: 1,
            ..Default::default()
        }
    }

    /// The vCPU in long mode at the code's start, with the operating
    /// system's say that SSE may be used (CR4.OSFXSR).
    fn start(vcpu: &VcpuFd) {
        let mut s = vcpu.get_sregs().unwrap();
        s.cr0 = 0x8000_0031; // PG, NE, ET, PE
        s.cr3 = 0x1000;
        s.cr4 = 0x220; // OSFXSR, PAE
        s.efer = 0x500; // LME, LMA
        s.cs = segment(8, 11, 1, 0);
        let data = segment(0x10, 3, 0, 1);
        (s.ds, s.es, s.fs, s.gs, s.ss) = (data, data, data, data, data);
        s.tr.type_ = 11;
        s.tr.present = 1;
        s.tr.s = 0;
        (s.gdt.base, s.gdt.limit) = (GDT, 23);
        vcpu.set_sregs(&s).unwrap();
        again(vcpu);
    }

    /// The vCPU back at the code's start.
    fn again(vcpu: &VcpuFd) {
        vcpu.set_regs(&kvm_regs { rip: CODE, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
    }

    /// One `run`, kicked after 5 s if it has not returned, as a line.
    fn run_once(vcpu: &mut VcpuFd) -> String {
        let done = Arc::new(AtomicBool::new(false));
        let mut kicker = VcpuFd { shared: Arc::clone(&vcpu.shared), own: None };
        let watch = Arc::clone(&done);
        let watchdog = std::thread::spawn(move || {
            for _ in 0..500 {
                if watch.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            kicker.set_kvm_immediate_exit(1);
        });
        let line = match vcpu.run() {
            Ok(VcpuExit::IoOut(port, _)) => format!("exit IoOut port {port:#x}"),
            Ok(VcpuExit::Shutdown) => "exit Shutdown".to_string(),
            Ok(_) => "exit (another)".to_string(),
            Err(e) if e.errno() == libc::EINTR => "no exit within 5 s (kicked)".to_string(),
            Err(e) => format!("run failed, errno {}", e.errno()),
        };
        done.store(true, Ordering::SeqCst);
        watchdog.join().unwrap();
        line
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The vCPU's XSAVE area through `KVM_GET_XSAVE2`.
    fn area_of(vcpu: &VcpuFd) -> Vec<u8> {
        let mut x = Xsave::new((regs::xsave_area_len() - 4096).div_ceil(4)).unwrap();
        // SAFETY: an area of the capability's size.
        unsafe { vcpu.get_xsave2(&mut x) }.unwrap();
        let p = x.as_fam_struct_ptr();
        // SAFETY: the wrapper's `kvm_xsave` and the `len` entries after it.
        unsafe { std::slice::from_raw_parts((&raw const (*p).xsave).cast::<u8>(), 4096 + 4 * (*p).len) }.to_vec()
    }

    fn xstate_bv(area: &[u8]) -> u64 {
        u64::from_le_bytes(area[512..520].try_into().unwrap())
    }

    /// What an XSAVE area holds of the fields `kvm_fpu` has.
    fn held(area: &[u8]) -> String {
        format!(
            "XSTATE_BV {:#x}, control word {:#x}, status word {:#x}, tags {:#x}, MXCSR {:#x}, ST0 {}, XMM3 {}",
            xstate_bv(area),
            u16::from_le_bytes([area[0], area[1]]),
            u16::from_le_bytes([area[2], area[3]]),
            u16::from_le_bytes([area[4], area[5]]),
            u32::from_le_bytes(area[24..28].try_into().unwrap()),
            hex(&area[32..42]),
            hex(&area[160 + 48..160 + 64]),
        )
    }

    fn got(fpu: &kvm_fpu) -> String {
        format!(
            "control word {:#x}, status word {:#x}, tags {:#x}, mxcsr {:#x}, ST0 {}, XMM3 {}",
            fpu.fcw,
            fpu.fsw,
            fpu.ftwx,
            fpu.mxcsr,
            hex(&fpu.fpr[0][..10]),
            hex(&fpu.xmm[3]),
        )
    }

    /// What the guest stored of its own state: control word, MXCSR, XMM3,
    /// ST0.
    fn seen(m: *mut u8) -> (u16, u32, [u8; 16], [u8; 10]) {
        (
            u16::from_le_bytes(bytes_at(m, FCW)),
            u32::from_le_bytes(bytes_at(m, MXCSR)),
            bytes_at(m, XMM3),
            bytes_at(m, ST0),
        )
    }

    /// `KVM_SET_FPU` of `fpu` with the lines of what the vCPU held before
    /// and after it, through `KVM_GET_XSAVE2` and `KVM_GET_FPU`. What
    /// `KVM_GET_FPU` returned after it.
    fn set_on_record(vcpu: &VcpuFd, name: &str, fpu: &kvm_fpu) -> kvm_fpu {
        eprintln!("FPUTEST {name}, before: area {}", held(&area_of(vcpu)));
        eprintln!("FPUTEST {name}, before: KVM_GET_FPU {}", got(&vcpu.get_fpu().unwrap()));
        eprintln!("FPUTEST {name}: KVM_SET_FPU {}", got(fpu));
        vcpu.set_fpu(fpu).unwrap();
        let back = vcpu.get_fpu().unwrap();
        eprintln!("FPUTEST {name}, after: area {}", held(&area_of(vcpu)));
        eprintln!("FPUTEST {name}, after: KVM_GET_FPU {}", got(&back));
        assert_eq!(back.mxcsr, 0, "KVM_GET_FPU returns no MXCSR (Linux: a zeroed struct, the field not written)");
        back
    }

    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_set_fpu_on_record() {
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: MEM as u64,
            userspace_addr: m as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);

        // A vCPU that has not run. Linux: its saved state has no component
        // in use, so its guest starts with the initial x87 and SSE state
        // whatever was written (control word 0x37f, MXCSR 0x1f80, XMM3
        // zero, no ST0: the store gives the indefinite value), and
        // KVM_GET_FPU returns what was written all the same. Asserted: the
        // backend keeps Linux's image until the first run
        // (`regs::BeforeRun`), since WHP's new area has the SSE bit and
        // gave the guest the XMM registers written (run 43374475718).
        // SAFETY (both `zeroed` below): an all-zero kvm_fpu is valid.
        let mut fpu: kvm_fpu = unsafe { std::mem::zeroed() };
        (fpu.fcw, fpu.ftwx, fpu.mxcsr) = (0x27f, 1, 0x9f80);
        fpu.fpr[0] = ONE_AND_A_HALF;
        fpu.xmm[3] = [0xA1; 16];
        let new = vcpu.get_fpu().unwrap();
        assert_eq!((new.fcw, new.xmm[3]), (0x37f, [0; 16]), "a new vCPU's KVM_GET_FPU: Linux's initial image");
        let back = set_on_record(&vcpu, "a vCPU that has not run", &fpu);
        assert_eq!((back.fcw, back.ftwx, back.fpr[0], back.xmm[3]), (0x27f, 1, ONE_AND_A_HALF, [0xA1; 16]), "KVM_GET_FPU reads what was written");
        let exit = run_once(&mut vcpu);
        let (fcw1, mxcsr1, xmm1, st1) = seen(m);
        eprintln!(
            "FPUTEST a vCPU that has not run: {exit}; its guest found control word {fcw1:#x}, MXCSR {mxcsr1:#x}, \
             ST0 {}, XMM3 {} (Linux, by its source: 0x37f, 0x1f80, the indefinite value 000000000000c0ffff, zeros)",
            hex(&st1),
            hex(&xmm1)
        );
        assert_eq!(exit, format!("exit IoOut port {PORT:#x}"));
        assert_ne!(mxcsr1, 0x9f80, "KVM_SET_FPU's mxcsr reached the guest, which Linux's never does");
        assert_eq!((fcw1, mxcsr1, xmm1), (0x37f, 0x1f80, [0; 16]), "the guest of a vCPU that had not run: the initial state, as on Linux");
        assert_eq!(&st1[7..], &[0xc0, 0xff, 0xff], "no ST0: the store gives the indefinite value");

        // The same vCPU, whose guest has now left the initial state of
        // both components (ST0 holds 1.0, XMM5 all ones): they are in use,
        // and a write to them is what the guest finds, on Linux and here.
        // MXCSR is the guest's own still.
        let in_use = xstate_bv(&area_of(&vcpu)) & 3 == 3;
        let mut fpu: kvm_fpu = unsafe { std::mem::zeroed() };
        (fpu.fcw, fpu.ftwx, fpu.mxcsr) = (0x7f, 1, 0x9f80);
        fpu.fpr[0] = TWO_AND_A_HALF;
        fpu.xmm[3] = [0xB2; 16];
        let back = set_on_record(&vcpu, "a vCPU whose guest has used x87 and SSE", &fpu);
        put(m, FCW, &[0; 0x50]);
        again(&vcpu);
        let exit = run_once(&mut vcpu);
        let (fcw2, mxcsr2, xmm2, st2) = seen(m);
        eprintln!(
            "FPUTEST a vCPU whose guest has used x87 and SSE (both in XSTATE_BV: {in_use}): {exit}; its guest \
             found control word {fcw2:#x}, MXCSR {mxcsr2:#x}, ST0 {}, XMM3 {}",
            hex(&st2),
            hex(&xmm2)
        );
        assert_eq!(exit, format!("exit IoOut port {PORT:#x}"));
        assert!(in_use, "x87 and SSE are not in XSTATE_BV after a guest that left their initial state");
        assert_eq!((back.fcw, back.ftwx, back.fpr[0], back.xmm[3]), (0x7f, 1, TWO_AND_A_HALF, [0xB2; 16]));
        assert_eq!((fcw2, xmm2, &st2[..]), (0x7f, [0xB2; 16], &TWO_AND_A_HALF[..10]), "what the guest found");
        assert_eq!(mxcsr2, mxcsr1, "the guest's MXCSR is its own after KVM_SET_FPU");

        // What WHP does with a header bit as written, on a vCPU of its
        // own: the area written back with x87 and SSE cleared in XSTATE_BV
        // and fields of both in its FXSAVE region, then with both set.
        // Not asserted. If WHP keeps a cleared bit and gives such a
        // component its initial state, a new vCPU's SSE bit can be cleared
        // to have Linux's new state exactly.
        let other = vm.create_vcpu(1).unwrap();
        let (mut area, written) = regs::read_xsave(other.part(), other.vp()).unwrap();
        eprintln!("FPUTEST an area written with header bits changed, new ({written} bytes): {}", held(&area));
        let bv = xstate_bv(&area);
        area[0..2].copy_from_slice(&0x27fu16.to_le_bytes());
        area[160 + 48..160 + 64].copy_from_slice(&[0xC3; 16]);
        for (name, bits) in [("x87 and SSE cleared", bv & !3), ("x87 and SSE set", bv | 3)] {
            area[512..520].copy_from_slice(&bits.to_le_bytes());
            let set = regs::set_xsave(other.part(), other.vp(), &area);
            let after = regs::read_xsave(other.part(), other.vp()).map(|(a, _)| held(&a));
            eprintln!(
                "FPUTEST an area written with {name} (XSTATE_BV {bits:#x}, control word 0x27f, XMM3 c3..): \
                 {set:?}; read back {after:?}"
            );
        }

        drop(other);
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// How much of the calling thread's stack is committed: the TEB's
    /// `StackBase` less its `StackLimit` (`NT_TIB`, at `gs:[8]` and
    /// `gs:[0x10]` on x86-64), in KiB. It only grows: Windows commits a
    /// stack's pages as they are first touched and keeps them.
    fn stack_committed() -> usize {
        let (base, limit): (usize, usize);
        // SAFETY: two reads of the thread's own TEB.
        unsafe {
            core::arch::asm!(
                "mov {0}, gs:[0x8]",
                "mov {1}, gs:[0x10]",
                out(reg) base,
                out(reg) limit,
                options(nostack, readonly, preserves_flags)
            );
        }
        (base - limit) / 1024
    }

    /// `step` on a thread of its own, made as Firecracker makes a vCPU's
    /// (2 MiB of stack reserved), with the line of what the thread's stack
    /// had committed before and after it.
    fn on_a_thread_of_its_own(vcpu: &mut VcpuFd, name: &str, step: impl FnOnce(&mut VcpuFd) -> String + Send) {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("fc_vcpu 0".to_string())
                .stack_size(2 << 20)
                .spawn_scoped(scope, || {
                    let before = stack_committed();
                    let what = step(vcpu);
                    let after = stack_committed();
                    eprintln!("STACKTEST {name}: {what}; the thread's stack: {before} KiB committed before, {after} after");
                })
                .unwrap();
        });
    }

    /// One `run` as a line; a guest that does not come back is kicked
    /// after 5 s.
    fn run_to_a_line(vcpu: &mut VcpuFd) -> String {
        let done = Arc::new(AtomicBool::new(false));
        let mut kicker = VcpuFd { shared: Arc::clone(&vcpu.shared), own: None };
        let watch = Arc::clone(&done);
        let watchdog = std::thread::spawn(move || {
            for _ in 0..500 {
                if watch.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            kicker.set_kvm_immediate_exit(1);
        });
        let line = match vcpu.run() {
            Ok(VcpuExit::IoOut(port, _)) => format!("exit IoOut port {port:#x}"),
            Ok(VcpuExit::MmioRead(address, _)) => format!("exit MmioRead {address:#x}"),
            Ok(VcpuExit::Hlt) => "exit Hlt".to_string(),
            Ok(VcpuExit::Shutdown) => "exit Shutdown".to_string(),
            Ok(_) => "exit (another)".to_string(),
            Err(e) if e.errno() == libc::EINTR => "no exit within 5 s (kicked)".to_string(),
            Err(e) => format!("run failed, errno {}", e.errno()),
        };
        done.store(true, Ordering::SeqCst);
        watchdog.join().unwrap();
        vcpu.set_kvm_immediate_exit(0);
        line
    }

    /// One step of [`test_the_stack_each_whp_call_commits_on_record`]'s
    /// guest: the runs until its `out 0x80` (at most 12 exits, and a kick
    /// 5 s after the first run began), as the exits the test saw. An `IN`
    /// and an MMIO read are answered with zeros.
    fn run_a_step(vcpu: &mut VcpuFd) -> String {
        let done = Arc::new(AtomicBool::new(false));
        let mut kicker = VcpuFd { shared: Arc::clone(&vcpu.shared), own: None };
        let watch = Arc::clone(&done);
        let watchdog = std::thread::spawn(move || {
            for _ in 0..500 {
                if watch.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            kicker.set_kvm_immediate_exit(1);
        });
        let mut exits = Vec::new();
        while exits.len() < 12 {
            let (line, more) = match vcpu.run() {
                Ok(VcpuExit::IoOut(PORT, _)) => (format!("IoOut {PORT:#x}"), false),
                Ok(VcpuExit::IoOut(port, _)) => (format!("IoOut {port:#x}"), true),
                Ok(VcpuExit::IoIn(port, data)) => {
                    data.fill(0);
                    (format!("IoIn {port:#x}"), true)
                }
                Ok(VcpuExit::MmioRead(address, data)) => {
                    data.fill(0);
                    (format!("MmioRead {address:#x}"), true)
                }
                Ok(VcpuExit::MmioWrite(address, _)) => (format!("MmioWrite {address:#x}"), true),
                Ok(VcpuExit::Hlt) => ("Hlt".to_string(), false),
                Ok(VcpuExit::Shutdown) => ("Shutdown".to_string(), false),
                Ok(_) => ("(another)".to_string(), false),
                Err(e) if e.errno() == libc::EINTR => ("none within 5 s (kicked)".to_string(), false),
                Err(e) => (format!("run failed, errno {}", e.errno()), false),
            };
            exits.push(line);
            if !more {
                break;
            }
        }
        done.store(true, Ordering::SeqCst);
        watchdog.join().unwrap();
        vcpu.set_kvm_immediate_exit(0);
        format!("exits {}", exits.join(", "))
    }

    /// [`run_a_step`] on a thread of its own, made as Firecracker makes a
    /// vCPU's (its name, 2 MiB of stack reserved), with the WHP calls the
    /// thread made (`ffi::trace`): one STACKTEST line of what the thread's
    /// stack had committed before and after the step, and one STACKCALL
    /// line for each call (past 40 calls, for those that left more of the
    /// stack committed than they found, or failed). Returns the calls.
    fn a_step_with_its_calls(vcpu: &mut VcpuFd, thread: &str, name: &str) -> Vec<super::super::ffi::trace::Call> {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name(thread.to_string())
                .stack_size(2 << 20)
                .spawn_scoped(scope, || {
                    let before = super::super::ffi::trace::stack();
                    super::super::ffi::trace::begin();
                    let what = run_a_step(vcpu);
                    let calls = super::super::ffi::trace::end();
                    let after = super::super::ffi::trace::stack();
                    let grew = |c: &super::super::ffi::trace::Call| c.after > c.before;
                    let by_calls: usize = calls.iter().map(|c| c.after - c.before).sum();
                    eprintln!(
                        "STACKTEST {thread}, {name}: {what}; the thread's stack: {} KiB committed before, {} after, \
                         {} of them within WHP calls; {} WHP calls, {} left more committed, {} failed",
                        before / 1024,
                        after / 1024,
                        by_calls / 1024,
                        calls.len(),
                        calls.iter().filter(|c| grew(c)).count(),
                        calls.iter().filter(|c| c.hres != 0).count()
                    );
                    for (i, c) in calls.iter().enumerate() {
                        if i < 40 || grew(c) || c.hres != 0 {
                            eprintln!("STACKCALL {thread}, {name}: #{} {}", i + 1, c.line());
                        }
                    }
                    calls
                })
                .unwrap()
                .join()
                .unwrap()
        })
    }

    /// A record of which WHP call commits a vCPU thread's stack, for what a
    /// booting Linux guest does and the runs of
    /// [`test_the_stack_each_call_commits_on_record`] did not do. That
    /// record (CI run 43385227122) showed 12 to 24 KiB for each of its
    /// runs, while a booted guest's vCPU threads keep 48 to 52 KiB, the
    /// pages below the live frames holding stale ones:
    /// `WHvSetVirtualProcessorRegisters` called from the run loop, and in
    /// WinHvPlatform.dll a C++ exception thrown and caught and a message
    /// looked up. The boots of that run reported no WHP call that failed
    /// (no `whp:` line on Firecracker's standard error, where every failed
    /// call of `ffi::hr_of` is reported), so the call is one that returns
    /// success; which one, only its stack tells. Here every WHP call of the
    /// thread is kept with the stack committed before and after it
    /// (`ffi::trace`), a step at a time, each step on a thread of its own:
    /// the CPUID leaves answered from the vCPU's state, RDMSR and WRMSR of
    /// MSRs the backend keeps, port input the irqchip answers and port
    /// input Firecracker answers, string I/O and an MMIO write (the
    /// emulator), the local APIC through its page, an application
    /// processor started with INIT and SIPI (on its own thread), an
    /// interrupt taken while running and one that ends a HLT, the
    /// TSC-deadline timer, and a KVM hypercall. The CPUID step asserts that
    /// no call failed: IA32_XSS is read only where the partition keeps it.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_the_stack_each_whp_call_commits_on_record() {
        const PROGRAM: u64 = 0xB000;
        const HANDLER: u64 = 0xB800;
        const AP_CODE: u64 = 0xC000;
        const IDT: u64 = 0x5000;
        const VECTOR: u64 = 0x41;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
        // A page 6 MiB up that no memory slot backs: an MMIO address.
        q(0x3018, 0x60_0000 | 0x83);
        // The local APIC's page, 0xFEE0_0000: the fourth GiB's directory at
        // 0xA000, its 2 MiB page 0x1f7.
        q(0x2018, 0xA000 | 3);
        q(0xA000 + 0x1f7 * 8, 0xFEE0_0000 | 0x83);
        // The interrupt gate of VECTOR (64-bit, code segment 8).
        q(IDT + VECTOR * 16, (HANDLER & 0xffff) | (8 << 16) | (0x8E << 40));
        q(IDT + VECTOR * 16 + 8, 0);
        put(
            m,
            HANDLER,
            &[
                0xE6, 0x81, // out 0x81, al
                0xC7, 0x83, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword [rbx + 0xB0], 0 (EOI)
                0x48, 0xCF, // iretq
            ],
        );
        // The application processor, in real mode where its SIPI starts it.
        put(m, AP_CODE, &[0xE6, PORT as u8, 0xF4, 0xEB, 0xFD]); // out 0x80, al; hlt; jmp to the hlt
        // KVM's hypercall instruction is the vendor's (VMMCALL on AMD).
        let amd = core::arch::x86_64::__cpuid(0).ebx == u32::from_le_bytes(*b"Auth");
        let apic = [0xBB, 0x00, 0x00, 0xE0, 0xFE]; // mov ebx, 0xFEE00000
        // mov dword [rbx + offset], value
        let apic_write = |offset: u32, value: u32| {
            let mut b = vec![0xC7, 0x83];
            b.extend_from_slice(&offset.to_le_bytes());
            b.extend_from_slice(&value.to_le_bytes());
            b
        };
        let steps: Vec<(&str, Vec<u8>)> = vec![
            (
                "CPUID leaves 1, 7, 0xd.0 and 0xd.1",
                vec![
                    0xB8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2, // mov eax, 1; xor ecx, ecx; cpuid
                    0xB8, 0x07, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2, // leaf 7
                    0xB8, 0x0D, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2, // leaf 0xd, subleaf 0
                    0xB8, 0x0D, 0x00, 0x00, 0x00, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2, // leaf 0xd, subleaf 1
                ],
            ),
            (
                "RDMSR of the kvm-clock system time MSR",
                vec![0xB9, 0x01, 0x4D, 0x56, 0x4B, 0x0F, 0x32], // mov ecx, 0x4b564d01; rdmsr
            ),
            (
                "WRMSR of the kvm-clock system time MSR (enabled, at 0x8100)",
                vec![
                    0xB9, 0x01, 0x4D, 0x56, 0x4B, // mov ecx, 0x4b564d01
                    0xB8, 0x01, 0x81, 0x00, 0x00, // mov eax, 0x8101
                    0x31, 0xD2, 0x0F, 0x30, // xor edx, edx; wrmsr
                ],
            ),
            (
                "WRMSR of IA32_TSC_ADJUST (0x1000)",
                vec![
                    0xB9, 0x3B, 0x00, 0x00, 0x00, // mov ecx, 0x3b
                    0xB8, 0x00, 0x10, 0x00, 0x00, // mov eax, 0x1000
                    0x31, 0xD2, 0x0F, 0x30, // xor edx, edx; wrmsr
                ],
            ),
            (
                "IN from a PIC port (the irqchip answers), then from port 0x60 (the VMM answers)",
                vec![0xE4, 0x21, 0xE4, 0x60], // in al, 0x21; in al, 0x60
            ),
            (
                "REP OUTSB of 2 bytes to port 0x82 (the emulator)",
                vec![
                    0xBE, 0x00, 0x83, 0x00, 0x00, // mov esi, 0x8300
                    0xB9, 0x02, 0x00, 0x00, 0x00, // mov ecx, 2
                    0x66, 0xBA, 0x82, 0x00, // mov dx, 0x82
                    0xF3, 0x6E, // rep outsb
                ],
            ),
            (
                "an MMIO write (the emulator)",
                vec![0xC7, 0x04, 0x25, 0x00, 0x00, 0x60, 0x00, 0x78, 0x56, 0x34, 0x12], // mov dword [0x600000], 0x12345678
            ),
            (
                "the local APIC enabled through its page (spurious vector register 0x1ff)",
                [apic.to_vec(), apic_write(0xF0, 0x1FF)].concat(),
            ),
            (
                "INIT, then SIPI (vector 0xc) to APIC 1",
                [apic.to_vec(), apic_write(0x310, 1 << 24), apic_write(0x300, 0x4500), apic_write(0x300, 0x460C)].concat(),
            ),
            (
                "STI and a fixed interrupt to itself, taken while it runs",
                [apic.to_vec(), vec![0xFB], apic_write(0x300, 0x4_0000 | VECTOR as u32), vec![0x90, 0x90, 0x90]].concat(),
            ),
            (
                "the APIC timer (one shot, 0x100000 counts) and HLT, ended by its interrupt",
                [
                    apic.to_vec(),
                    apic_write(0x320, VECTOR as u32),
                    apic_write(0x3E0, 0xB),
                    apic_write(0x380, 0x10_0000),
                    vec![0xF4], // hlt
                ]
                .concat(),
            ),
            (
                "the TSC-deadline timer (WRMSR 0x6e0, the TSC plus 0x10000000) and HLT, ended by its interrupt",
                [
                    apic.to_vec(),
                    apic_write(0x320, 0x4_0000 | VECTOR as u32),
                    vec![
                        0x0F, 0x31, // rdtsc
                        0x05, 0x00, 0x00, 0x00, 0x10, // add eax, 0x10000000
                        0x83, 0xD2, 0x00, // adc edx, 0
                        0xB9, 0xE0, 0x06, 0x00, 0x00, // mov ecx, 0x6e0
                        0x0F, 0x30, // wrmsr
                        0xF4, // hlt
                    ],
                ]
                .concat(),
            ),
            (
                "a KVM hypercall (KVM_HC_CLOCK_PAIRING, the structure at 0x8200)",
                vec![
                    0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9
                    0xBB, 0x00, 0x82, 0x00, 0x00, // mov ebx, 0x8200
                    0x31, 0xC9, // xor ecx, ecx
                    0x0F, 0x01, if amd { 0xD9 } else { 0xC1 }, // vmmcall or vmcall
                ],
            ),
        ];
        let mut program = Vec::new();
        for (_, code) in &steps {
            program.extend_from_slice(code);
            program.extend_from_slice(&[0xE6, PORT as u8]); // out 0x80, al: the step's end
        }
        program.extend_from_slice(&[0xF4, 0xEB, 0xFD]); // hlt; jmp to the hlt
        assert!(program.len() < (HANDLER - PROGRAM) as usize);
        put(m, PROGRAM, &program);

        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: MEM as u64,
            userspace_addr: m as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        let mut ap = vm.create_vcpu(1).unwrap();
        // The guest's CPUID has TSC_ADJUST (leaf 7, EBX bit 1), without
        // which a write of the MSR is dropped; the other leaves are WHP's.
        let leaf7 = kvm_cpuid_entry2 {
            function: 7,
            index: 0,
            flags: kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
            ebx: 1 << 1,
            ..Default::default()
        };
        vcpu.set_cpuid2(&CpuId::from_entries(&[leaf7]).unwrap()).unwrap();
        start(&vcpu);
        let mut s = vcpu.get_sregs().unwrap();
        (s.idt.base, s.idt.limit) = (IDT, 0xfff);
        vcpu.set_sregs(&s).unwrap();
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();

        let mut cpuid_failures = Vec::new();
        for (i, (name, _)) in steps.iter().enumerate() {
            let calls = if name.starts_with("INIT") {
                // The application processor's thread is in its run, waiting
                // for its start, while the boot processor sends it.
                std::thread::scope(|scope| {
                    let ap = &mut ap;
                    let waiting = scope.spawn(move || {
                        a_step_with_its_calls(ap, "fc_vcpu 1", "the application processor's first run, started by the SIPI")
                    });
                    let calls = a_step_with_its_calls(&mut vcpu, "fc_vcpu 0", name);
                    waiting.join().unwrap();
                    calls
                })
            } else {
                a_step_with_its_calls(&mut vcpu, "fc_vcpu 0", name)
            };
            if i == 0 {
                cpuid_failures = calls.iter().filter(|c| c.hres != 0).map(super::super::ffi::trace::Call::line).collect();
            }
        }

        drop(ap);
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        assert!(cpuid_failures.is_empty(), "a WHP call failed while CPUID was answered: {cpuid_failures:?}");
    }

    /// A record of what each call of the backend commits of the stack of
    /// the thread that makes it, each on a thread of its own. In a booted
    /// Linux guest every vCPU thread had 48 to 52 KiB of stack resident
    /// while its stack pointer was 15 KiB deep (CI run 43377614564,
    /// tools/windows/vmm-memory-record.py), the pages below holding stale
    /// frames of WinHvPlatform.dll raising and catching a C++ exception
    /// (`CxxThrowException`, `RaiseException`, the unwind) and formatting a
    /// message; the stale frames do not say which call of the backend's
    /// that was. The lines here do: the state calls Firecracker makes for a
    /// vCPU, and a run to each kind of exit the run loop handles.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_the_stack_each_call_commits_on_record() {
        const CODE2: u64 = 0x7000;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        // A page 6 MiB up that no memory slot backs: an MMIO address.
        put(m, 0x3018, &(0x60_0000u64 | 0x83).to_le_bytes());
        put(
            m,
            CODE2,
            &[
                0x0F, 0xA2, // cpuid
                0xE6, PORT as u8, // out 0x80, al
                0x8B, 0x04, 0x25, 0x00, 0x00, 0x60, 0x00, // mov eax, [0x600000]
                0xE6, PORT as u8, // out 0x80, al
                0xB9, 0x00, 0x4D, 0x56, 0x4B, // mov ecx, 0x4b564d00 (MSR_KVM_WALL_CLOCK_NEW)
                0x31, 0xC0, // xor eax, eax
                0x31, 0xD2, // xor edx, edx
                0x0F, 0x30, // wrmsr
                0xE6, PORT as u8, // out 0x80, al
                0xF4, // hlt
                0xEB, 0xFD, // jmp to the hlt
            ],
        );
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: MEM as u64,
            userspace_addr: m as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();

        on_a_thread_of_its_own(&mut vcpu, "nothing (the control)", |_| "no call".to_string());
        on_a_thread_of_its_own(&mut vcpu, "KVM_GET_SREGS, KVM_SET_SREGS, KVM_SET_REGS", |v| {
            start(v);
            v.set_regs(&kvm_regs { rip: CODE2, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
            "set".to_string()
        });
        on_a_thread_of_its_own(&mut vcpu, "KVM_GET_XSAVE2", |v| format!("{} bytes", area_of(v).len()));
        on_a_thread_of_its_own(&mut vcpu, "KVM_GET_FPU, KVM_SET_FPU", |v| {
            let fpu = v.get_fpu().unwrap();
            format!("{:?}", v.set_fpu(&fpu))
        });
        on_a_thread_of_its_own(&mut vcpu, "KVM_GET_LAPIC, KVM_SET_LAPIC", |v| {
            format!("{:?}", v.get_lapic().and_then(|l| v.set_lapic(&l)))
        });
        on_a_thread_of_its_own(&mut vcpu, "KVM_GET_VCPU_EVENTS, KVM_GET_MP_STATE, KVM_GET_XCRS, KVM_GET_DEBUGREGS", |v| {
            format!(
                "{} {} {} {}",
                v.get_vcpu_events().is_ok(),
                v.get_mp_state().is_ok(),
                v.get_xcrs().is_ok(),
                v.get_debug_regs().is_ok()
            )
        });
        for name in [
            "the vCPU's first run: cpuid, then a port write",
            "a run to an MMIO read",
            "a run that completes the MMIO read, to a port write",
            "a run through a wrmsr of the kvm-clock wall clock, to a port write",
            "a run to hlt with interrupts off, ended by a kick",
            "a run of a halted vCPU, ended by a kick",
        ] {
            on_a_thread_of_its_own(&mut vcpu, name, run_to_a_line);
        }

        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }
}
