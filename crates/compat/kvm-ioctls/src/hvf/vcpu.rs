// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! vCPU handle: lazy creation, register access, and the run loop
//! (MMIO decode, PSCI, WFI, virtual timer).

use std::collections::HashMap;
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use kvm_bindings::{
    KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC, KVM_MP_STATE_RUNNABLE, KVM_MP_STATE_STOPPED,
    KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN, RegList, kvm_device_attr, kvm_guest_debug,
    kvm_mp_state, kvm_run, kvm_vcpu_init,
};

use super::debug::{self, GuestDebug, Stopped};

use super::exit::{self, DebugRegs, Exit, Mmio, Psci, SysregAccess, SysregResult};
use super::ffi::*;
use super::firmware;
use super::gic::{CpuReg, GicCpu};
use super::idregs;
use super::pvtime;
use super::regs::{self, Reg, reg_size};
use super::trng;
use super::vm::VmInner;
use super::wait::{Ended, Waiter};
use super::{Error, Handle, Result, VcpuExit, err};

const NOT_CREATED: u64 = u64::MAX;

/// `PSTATE` for a CPU brought up by PSCI `CPU_ON`: EL1h with D, A, I and F masked.
const PSTATE_EL1H_DAIF: u64 = 0x3c5;

/// Longest a `WFI` waits before re-entering the guest. Interrupts raised by
/// other vCPUs (SGIs) are not seen by the waiting thread, so it polls.
const WFI_MAX_WAIT: Duration = Duration::from_millis(1);

// PSCI 0.2 return values (the calls are `exit::Psci`).
const PSCI_RET_SUCCESS: i64 = 0;
const PSCI_RET_NOT_SUPPORTED: i64 = -1;
const PSCI_RET_INVALID_PARAMS: i64 = -2;
const PSCI_RET_ALREADY_ON: i64 = -4;
const PSCI_RET_INTERNAL_FAILURE: i64 = -6;
/// "Trusted OS not present": no migration needed.
const PSCI_TOS_NOT_PRESENT_MP: i64 = 2;
/// PSCI_0_2_64BIT: the bit of a function id that makes it the SMC64 call.
const PSCI_0_2_64BIT: u32 = 0x4000_0000;

const MPIDR_AFFINITY_MASK: u64 = 0xff_00ff_ffff;
/// `kvm_run.system_event.data` of a PSCI SYSTEM_OFF or SYSTEM_RESET exit:
/// `ndata` 1, the flags 0 (KVM since Linux 5.18).
static SYSTEM_EVENT_DATA: [u64; 1] = [0];
/// And of a SYSTEM_RESET2 exit: `KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2`,
/// bit 0 (arch/arm64/include/uapi/asm/kvm.h; psci.c kvm_psci_system_reset2).
static SYSTEM_RESET2_EVENT_DATA: [u64; 1] = [1];

/// KVM's MPIDR for vCPU `id` (`reset_mpidr` in Linux arch/arm64/kvm/sys_regs.c).
fn kvm_mpidr(id: u64) -> u64 {
    (1 << 31) | (id & 0xf) | ((id >> 4) & 0xff) << 8 | ((id >> 12) & 0xff) << 16
}

fn timebase() -> mach_timebase_info_data_t {
    static TB: OnceLock<mach_timebase_info_data_t> = OnceLock::new();
    *TB.get_or_init(|| {
        let mut tb = mach_timebase_info_data_t::default();
        // SAFETY: writes the struct.
        unsafe { mach_timebase_info(&mut tb) };
        if tb.denom == 0 {
            tb = mach_timebase_info_data_t { numer: 1, denom: 1 };
        }
        tb
    })
}

fn ticks_to_ns(ticks: u64) -> u64 {
    let tb = timebase();
    (u128::from(ticks) * u128::from(tb.numer) / u128::from(tb.denom)).min(u64::MAX as u128) as u64
}

/// `ticks_to_ns`, for the PV time tests.
#[cfg(test)]
pub(crate) fn tests_ticks_to_ns(ticks: u64) -> u64 {
    ticks_to_ns(ticks)
}

/// `mach_absolute_time` in nanoseconds.
pub(crate) fn wall_ns() -> u64 {
    // SAFETY: plain call.
    ticks_to_ns(unsafe { mach_absolute_time() })
}

fn ticks_to_duration(ticks: u64) -> Duration {
    let tb = timebase();
    Duration::from_nanos(
        (u128::from(ticks) * u128::from(tb.numer) / u128::from(tb.denom)).min(u64::MAX as u128)
            as u64,
    )
}

#[derive(Debug, Default)]
struct Power {
    off: bool,
    /// Entry point and context id from PSCI `CPU_ON`, applied by the target vCPU.
    boot: Option<(u64, u64)>,
    /// Set by interrupt injection and kicks; consumed by `WFI`.
    wake: bool,
    /// Set while `WFI` waits on the vCPU's [`Waiter`]: a change of the power
    /// state then wakes it too ([`VcpuShared::notify`]).
    waiting: bool,
}

#[cfg(test)]
thread_local! {
    /// Tests: run by [`VcpuShared::wait_for_wake`] on its thread once it has
    /// decided to wait, before it waits.
    static BEFORE_WAIT: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
}

/// A `kvm_run` structure at a fixed address.
pub(crate) struct KvmRunPage(Box<std::cell::UnsafeCell<kvm_run>>);

// SAFETY: like KVM's mapped `kvm_run`, the page is shared between threads;
// the only field written concurrently (`immediate_exit`) is accessed atomically.
unsafe impl Send for KvmRunPage {}
// SAFETY: as above.
unsafe impl Sync for KvmRunPage {}

impl KvmRunPage {
    fn new() -> Self {
        KvmRunPage(Box::new(std::cell::UnsafeCell::new(kvm_run::default())))
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

/// Every vCPU of the process, to find one from a descriptor
/// (`KvmRunWrapper::mmap_from_fd`).
static ALL_VCPUS: Mutex<Vec<std::sync::Weak<VcpuShared>>> = Mutex::new(Vec::new());

/// The vCPU whose handle descriptor has identity `id`.
pub(crate) fn vcpu_by_identity(id: (u64, u64)) -> Option<Arc<VcpuShared>> {
    let mut all = ALL_VCPUS.lock().unwrap();
    all.retain(|v| v.strong_count() > 0);
    all.iter()
        .filter_map(std::sync::Weak::upgrade)
        .find(|v| v.handle.1 == id)
}

/// State shared by all handles of one vCPU.
#[derive(Debug)]
pub(crate) struct VcpuShared {
    pub index: u64,
    pub mpidr: u64,
    /// Descriptor and identity of the owner handle: finds this vCPU from a
    /// `dup`ed descriptor, and tells whether the handle has been closed.
    pub handle: (RawFd, (u64, u64)),
    hv: AtomicU64,
    /// The vCPU's `kvm_run` structure, shared by every handle and mapping of
    /// the vCPU (`get_kvm_run`, `KvmRunWrapper::mmap_from_fd`) like KVM's
    /// mapped page; `run()` reads `immediate_exit` from it.
    pub(crate) run: KvmRunPage,
    vtimer_masked: AtomicBool,
    /// OSLSR_EL1.OSLK, which the VMM emulates (see `sysreg_trap`); here, not
    /// in the owner handle, as `KVM_SET_ONE_REG` takes any handle.
    os_lock: AtomicBool,
    /// The `VmInner::vtimer_gen` whose offset the vCPU has (`u64::MAX`: none yet).
    vtimer_gen: AtomicU64,
    in_run: AtomicBool,
    power: Mutex<Power>,
    /// What a powered-off vCPU waits on ([`VcpuFd::wait_powered_on`]).
    cv: Condvar,
    /// What `WFI` waits on: a timer macOS does not coalesce
    /// ([`VcpuShared::wait_for_wake`]).
    waiter: Waiter,
    /// Tests: the times a power change woke the [`Waiter`].
    #[cfg(test)]
    triggers: AtomicU64,
    /// Register writes made before the Hypervisor.framework vCPU exists.
    pending: Mutex<Vec<(u64, Vec<u8>)>>,
    /// Set by `KVM_ARM_VCPU_INIT`; registers cannot be used before it.
    initialized: AtomicBool,
    /// GIC redistributor and CPU interface registers for other threads.
    gic: Mutex<GicCpu>,
    /// What user space asked for with `set_guest_debug`, from any handle;
    /// the owner applies it when it runs (`debug`).
    debug: Mutex<GuestDebug>,
    /// The registers of the vCPU while it is stopped, for its other handles
    /// (`debug::Stopped`).
    stopped: Mutex<Option<Stopped>>,
    // PV time (`super::pvtime`).
    /// The IPA of the vCPU's stolen-time structure (`KVM_ARM_VCPU_PVTIME_IPA`,
    /// set once, from any handle; `pvtime::NO_IPA`: none) and the owner's
    /// steal accounting. Only creating the vCPU clears the IPA, not
    /// `KVM_ARM_VCPU_INIT`, as KVM (arm.c kvm_arch_vcpu_create ->
    /// kvm_arm_pvtime_vcpu_init).
    pvtime: Arc<Mutex<pvtime::Steal>>,
    /// Whether the IPA is set: `run()` reads it alone, so a vCPU without PV
    /// time takes no lock and reads no clock for it.
    pvtime_on: AtomicBool,
}

impl VcpuShared {
    pub(crate) fn new(index: u64) -> Result<(Handle, Arc<Self>)> {
        let file = Handle::new()?;
        let shared = Arc::new(VcpuShared {
            index,
            mpidr: kvm_mpidr(index),
            handle: file.token(),
            hv: AtomicU64::new(NOT_CREATED),
            run: KvmRunPage::new(),
            vtimer_masked: AtomicBool::new(false),
            os_lock: AtomicBool::new(false),
            vtimer_gen: AtomicU64::new(u64::MAX),
            in_run: AtomicBool::new(false),
            power: Mutex::new(Power::default()),
            cv: Condvar::new(),
            waiter: Waiter::new().map_err(|e| Error::new(e.raw_os_error().unwrap_or(libc::EIO)))?,
            #[cfg(test)]
            triggers: AtomicU64::new(0),
            pending: Mutex::new(Vec::new()),
            initialized: AtomicBool::new(false),
            gic: Mutex::new(GicCpu::default()),
            debug: Mutex::new(GuestDebug::default()),
            stopped: Mutex::new(None),
            pvtime: Arc::new(Mutex::new(pvtime::Steal::default())),
            pvtime_on: AtomicBool::new(false),
        });
        ALL_VCPUS.lock().unwrap().push(Arc::downgrade(&shared));
        Ok((file, shared))
    }

    /// `kvm_run.immediate_exit`.
    pub(crate) fn immediate_exit(&self) -> &AtomicU8 {
        // SAFETY: the page lives as long as `self`; the field is a u8 that is
        // only accessed atomically.
        unsafe { AtomicU8::from_ptr(std::ptr::addr_of_mut!((*self.run.ptr()).immediate_exit)) }
    }

    fn hv(&self) -> Option<hv_vcpu_t> {
        match self.hv.load(Ordering::Acquire) {
            NOT_CREATED => None,
            hv => Some(hv),
        }
    }

    /// Whether the Hypervisor.framework vCPU exists.
    pub(crate) fn is_created(&self) -> bool {
        self.hv().is_some()
    }

    /// Wakes the vCPU if it waits in `WFI` or powered off.
    pub(crate) fn wake(&self) {
        let mut power = self.power.lock().unwrap();
        power.wake = true;
        self.notify(power);
    }

    /// Tells the vCPU of a change made to `power`: a powered-off vCPU waits
    /// on the condition variable, `WFI` on the [`Waiter`], which costs a
    /// system call and is woken only while `WFI` waits on it.
    fn notify(&self, power: MutexGuard<'_, Power>) {
        let waiting = power.waiting;
        drop(power);
        self.cv.notify_all();
        if waiting {
            #[cfg(test)]
            self.triggers.fetch_add(1, Ordering::Relaxed);
            self.waiter.wake();
        }
    }

    /// `WFI`'s wait: until a wake ([`VcpuShared::wake`]: an interrupt
    /// injected, a kick) or until `timeout` passed. Returns how long it
    /// waited and how the wait ended, or `None` if a wake or a kick was
    /// already there.
    ///
    /// No wake is lost: `waiting` is set under the power lock that a wake
    /// takes, so a wake made after the decision to wait triggers the
    /// [`Waiter`], whose trigger stays pending until the wait returns it,
    /// even if it came before the wait began. A wake that comes after the
    /// wait ended and before `waiting` is cleared leaves a trigger that ends
    /// the next wait at once: a WFI that ends with no interrupt, which the
    /// guest must expect, as Linux's idle loop does (it rechecks and waits
    /// again).
    fn wait_for_wake(&self, timeout: Duration) -> Option<(Duration, Ended)> {
        let mut power = self.power.lock().unwrap();
        if power.wake || self.immediate_exit().load(Ordering::Acquire) != 0 {
            power.wake = false;
            return None;
        }
        power.waiting = true;
        drop(power);
        #[cfg(test)]
        BEFORE_WAIT.with(|f| {
            if let Some(f) = f.borrow().as_ref() {
                f();
            }
        });
        let start = Instant::now();
        let ended = self.waiter.wait(Some(timeout));
        let waited = start.elapsed();
        let mut power = self.power.lock().unwrap();
        power.waiting = false;
        power.wake = false;
        Some((waited, ended))
    }

    fn cancel_run(&self) {
        if let Some(hv) = self.hv() {
            // SAFETY: valid vCPU id; may be called from any thread.
            unsafe { hv_vcpus_exit(&hv, 1) };
        }
    }

    /// Tests: masks or unmasks the virtual timer as a `VTIMER_ACTIVATED`
    /// exit and [`VcpuFd::update_vtimer`] do.
    #[cfg(test)]
    pub(crate) fn set_vtimer_masked(&self, vm: &VmInner, masked: bool) {
        self.vtimer_masked.store(masked, Ordering::Release);
        if masked {
            vm.vtimer_masked();
        }
    }

    /// Makes the vCPU exit if it runs with its virtual timer masked (the
    /// exit re-evaluates the mask). Returns whether the timer is masked.
    pub(crate) fn poke_if_vtimer_masked(&self) -> bool {
        let masked = self.vtimer_masked.load(Ordering::Acquire);
        if masked && self.in_run.load(Ordering::Acquire) {
            // Not in a signal handler (the vtimer thread), so it may wait.
            super::interrupting(|| self.cancel_run());
        }
        masked
    }

    fn powered_off(&self) -> bool {
        self.power.lock().unwrap().off
    }

    /// Reads (`write` is `None`) or writes a GIC register of this vCPU from
    /// any thread (see [`super::gic`]).
    pub(crate) fn gic_access(&self, vm: &VmInner, reg: CpuReg, write: Option<u64>) -> Result<u64> {
        let mut gic = self.gic.lock().unwrap();
        gic.access(
            reg,
            write,
            self.hv(),
            self.in_run.load(Ordering::Acquire),
            vm.gic_cpu_reset.get(),
        )
    }

    /// `GICR_PROPBASER` (`pend` false) or `GICR_PENDBASER`.
    pub(crate) fn lpi_base(&self, pend: bool, write: Option<u64>) -> u64 {
        let mut gic = self.gic.lock().unwrap();
        let reg = if pend {
            &mut gic.pendbaser
        } else {
            &mut gic.propbaser
        };
        if let Some(v) = write {
            *reg = v;
        }
        *reg
    }
}

/// Wrapper over a vCPU.
pub struct VcpuFd {
    /// Like a KVM vCPU descriptor, the handle keeps its VM alive.
    vm: Arc<VmInner>,
    shared: Arc<VcpuShared>,
    fd: Handle,
    /// True for the handle returned by `create_vcpu`: the one that creates and runs the vCPU.
    owner: bool,
    created_here: bool,
    exit: ExitPtr,
    mmio: [u8; 8],
    /// The MMIO load Firecracker is completing (`complete_mmio_read`).
    pending_read: Option<Mmio>,
    /// Guest debugging as the owner applies it.
    debug: debug::Owner,
}

/// Pointer to the exit information Hypervisor.framework fills in for this vCPU.
struct ExitPtr(*const hv_vcpu_exit_t);
// SAFETY: only dereferenced by the thread that owns the vCPU (the one running it).
unsafe impl Send for ExitPtr {}

impl std::fmt::Debug for VcpuFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VcpuFd")
            .field("index", &self.shared.index)
            .field("hv", &self.shared.hv())
            .field("owner", &self.owner)
            .finish()
    }
}

impl VcpuFd {
    pub(crate) fn new(vm: Arc<VmInner>, shared: Arc<VcpuShared>, fd: Handle, owner: bool) -> Self {
        VcpuFd {
            vm,
            shared,
            fd,
            owner,
            created_here: false,
            exit: ExitPtr(std::ptr::null()),
            mmio: [0; 8],
            pending_read: None,
            debug: debug::Owner::default(),
        }
    }

    fn vm(&self) -> Result<Arc<VmInner>> {
        Ok(self.vm.clone())
    }

    /// Creates the Hypervisor.framework vCPU on the calling thread.
    fn ensure_created(&mut self) -> Result<hv_vcpu_t> {
        if let Some(hv) = self.shared.hv() {
            return if self.created_here {
                Ok(hv)
            } else {
                err(libc::EBUSY)
            };
        }
        if !self.owner {
            return err(libc::EBUSY);
        }
        let vm = self.vm()?;
        let mut hv: hv_vcpu_t = 0;
        let mut exit: *const hv_vcpu_exit_t = std::ptr::null();
        // SAFETY: valid output pointers; a NULL config selects the defaults.
        check(super::creating(|| unsafe { hv_vcpu_create(&mut hv, &mut exit, std::ptr::null_mut()) }))?;
        self.exit = ExitPtr(exit);
        self.created_here = true;
        // SAFETY: `hv` was just created on this thread.
        unsafe {
            check(hv_vcpu_set_sys_reg(
                hv,
                HV_SYS_REG_MPIDR_EL1,
                self.shared.mpidr,
            ))?;
        }
        self.apply_vtimer_offset(hv, &vm)?;
        // The GIC registers exist once MPIDR_EL1 is set.
        let gic_created = vm.gic.lock().unwrap().created;
        if gic_created {
            super::gic::reroute_spis(super::gic::packed_affinity(self.shared.mpidr))?;
        }
        // The VM's ID registers, fixed from now on (`idregs`).
        vm.id_locked.store(true, Ordering::Release);
        // Every one the guest does not see as the host has it: written by
        // user space, or pointer authentication hidden.
        for r in idregs::ID_REGS {
            if self.host_id_reg(*r)?.is_none() {
                continue;
            }
            let v = self.id_reg(*r)?;
            let mut host = 0;
            // SAFETY: `hv` was just created on this thread.
            check(unsafe { hv_vcpu_get_sys_reg(hv, *r, &mut host) })?;
            if v != host {
                // SAFETY: as above.
                check(unsafe { hv_vcpu_set_sys_reg(hv, *r, v) })?;
            }
        }
        let pending = std::mem::take(&mut *self.shared.pending.lock().unwrap());
        for (id, data) in pending {
            self.set_reg_now(hv, id, &data)?;
        }
        let mut gic = self.shared.gic.lock().unwrap();
        gic.owned();
        if gic_created {
            let reset = gic.created(hv)?;
            let _ = vm.gic_cpu_reset.set(reset);
        }
        self.shared.hv.store(hv, Ordering::Release);
        drop(gic);
        vm.vcpu_created();
        Ok(hv)
    }

    /// The vCPU id if it exists and may be used from this handle.
    fn live(&self) -> Result<Option<hv_vcpu_t>> {
        match self.shared.hv() {
            None => Ok(None),
            Some(hv) if self.created_here => Ok(Some(hv)),
            Some(_) => err(libc::EBUSY),
        }
    }

    fn get_reg_now(&self, hv: hv_vcpu_t, id: u64, out: &mut [u8]) -> Result<()> {
        if let Some(reg) = regs::decode(id)
            && let Some(v) = self.fw_reg(reg)?
        {
            let n = out.len().min(8);
            out[..n].copy_from_slice(&v.to_le_bytes()[..n]);
            return Ok(());
        }
        read_reg(hv, id, out)
    }

    /// The value a register has before the Hypervisor.framework vCPU exists:
    /// the last write, else what a new vCPU starts with.
    fn get_reg_early(&self, id: u64, out: &mut [u8]) -> Result<()> {
        if let Some((_, v)) = self
            .shared
            .pending
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(r, _)| *r == id)
        {
            out.copy_from_slice(&v[..out.len()]);
            return Ok(());
        }
        let vm = self.vm()?;
        let v = match regs::decode(id) {
            Some(Reg::Sys(HV_SYS_REG_MPIDR_EL1)) => self.shared.mpidr,
            // SAFETY: plain call.
            Some(Reg::VirtualCount) => unsafe { mach_absolute_time() }
                .wrapping_sub(vm.vtimer_offset.load(Ordering::Acquire)),
            // SAFETY: plain call.
            Some(Reg::PhysicalCount) => unsafe { mach_absolute_time() },
            Some(reg) if reg.is_firmware() => self.fw_reg(reg)?.unwrap_or_default(),
            _ => {
                let reset = vm
                    .reset_regs
                    .get_or_init(probe_reset_regs)
                    .as_ref()
                    .map_err(|e| Error::new(*e))?;
                let v = reset.get(&id).ok_or_else(|| Error::new(libc::ENOENT))?;
                out.copy_from_slice(&v[..out.len()]);
                return Ok(());
            }
        };
        let n = out.len().min(8);
        out[..n].copy_from_slice(&v.to_le_bytes()[..n]);
        Ok(())
    }
}

/// Reads the reset value of every listed register from a scratch vCPU,
/// created and destroyed on a thread of its own.
fn probe_reset_regs() -> std::result::Result<HashMap<u64, Vec<u8>>, i32> {
    std::thread::spawn(|| {
        let mut hv: hv_vcpu_t = 0;
        let mut exit: *const hv_vcpu_exit_t = std::ptr::null();
        // SAFETY: valid output pointers; a NULL config selects the defaults.
        let ret = super::creating(|| unsafe { hv_vcpu_create(&mut hv, &mut exit, std::ptr::null_mut()) });
        if let Err(e) = check(ret) {
            return Err(e.errno());
        }
        let mut values = HashMap::new();
        let mut result = Ok(());
        for id in regs::reg_list() {
            let mut buf = vec![0u8; reg_size(id)];
            match read_reg(hv, id, &mut buf) {
                Ok(()) => {
                    values.insert(id, buf);
                }
                Err(e) => {
                    result = Err(e.errno());
                    break;
                }
            }
        }
        // The ID registers this Hypervisor.framework has (some are from
        // macOS 15.2 or 27): the others are left out.
        for r in idregs::ID_REGS {
            let id = regs::sys_id(*r);
            let mut buf = vec![0u8; 8];
            if read_reg(hv, id, &mut buf).is_ok() {
                values.insert(id, buf);
            }
        }
        // SAFETY: destroyed on the thread that created it.
        unsafe { hv_vcpu_destroy(hv) };
        result.map(|()| values)
    })
    .join()
    .unwrap_or(Err(libc::EIO))
}

/// Reads one register of a vCPU that belongs to the calling thread.
fn read_reg(hv: hv_vcpu_t, id: u64, out: &mut [u8]) -> Result<()> {
    {
        let reg = regs::decode(id).ok_or_else(|| Error::new(libc::ENOENT))?;
        let mut v: u64 = 0;
        // SAFETY: `hv` belongs to this thread; output pointers are valid.
        unsafe {
            match reg {
                Reg::Gp(r) | Reg::Fp(r) => check(hv_vcpu_get_reg(hv, r, &mut v))?,
                Reg::Sys(r) => check(hv_vcpu_get_sys_reg(hv, r, &mut v))?,
                Reg::Simd(i) => {
                    let mut q: hv_simd_fp_uchar16_t = [0; 16];
                    check(hv_vcpu_get_simd_fp_reg(hv, i, &mut q))?;
                    out[..16].copy_from_slice(&q);
                    return Ok(());
                }
                Reg::VirtualCount => {
                    let mut offset = 0;
                    check(hv_vcpu_get_vtimer_offset(hv, &mut offset))?;
                    v = mach_absolute_time().wrapping_sub(offset);
                }
                Reg::PhysicalCount => v = mach_absolute_time(),
                Reg::Aarch32Spsr => {}
                // A new VM's; the VM's own is read in get_reg_now.
                Reg::PsciVersion => v = regs::PSCI_VERSION_1_1,
                Reg::Workaround(_) => v = firmware::WORKAROUND_LEVEL,
                Reg::Bmap(bmap) => v = bmap.features(),
                // A new vCPU's: the lock clear, as KVM resets it.
                Reg::OsLock => v = exit::OSLSR_RESET,
            }
        }
        let n = out.len().min(8);
        out[..n].copy_from_slice(&v.to_le_bytes()[..n]);
        Ok(())
    }
}

impl VcpuFd {
    fn set_reg_now(&self, hv: hv_vcpu_t, id: u64, data: &[u8]) -> Result<()> {
        let reg = regs::decode(id).ok_or_else(|| Error::new(libc::ENOENT))?;
        let mut buf = [0u8; 8];
        let n = data.len().min(8);
        buf[..n].copy_from_slice(&data[..n]);
        let v = u64::from_le_bytes(buf);
        // SAFETY: `hv` belongs to this thread.
        unsafe {
            match reg {
                Reg::Gp(r) | Reg::Fp(r) => check(hv_vcpu_set_reg(hv, r, v)),
                Reg::Sys(r) => check(hv_vcpu_set_sys_reg(hv, r, v)),
                Reg::Simd(i) => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&data[..16]);
                    check(set_simd_fp_reg(hv, i, &bytes))
                }
                Reg::VirtualCount => {
                    let vm = self.vm()?;
                    vm.set_virtual_count(v);
                    self.apply_vtimer_offset(hv, &vm)
                }
                Reg::Aarch32Spsr if v == 0 => Ok(()),
                Reg::PsciVersion | Reg::Workaround(_) | Reg::Bmap(_) => self.set_fw_reg(reg, v),
                Reg::OsLock => self.set_os_lock(v),
                Reg::PhysicalCount | Reg::Aarch32Spsr => err(libc::EINVAL),
            }
        }
    }

    /// Sets OSLSR_EL1 as KVM's `set_oslsr_el1` does: only OSLK may differ
    /// from the reset value (`EINVAL`).
    fn set_os_lock(&self, v: u64) -> Result<()> {
        let mut debug = DebugRegs::default();
        if !debug.set_oslsr(v) {
            return err(libc::EINVAL);
        }
        self.shared.os_lock.store(debug.os_lock, Ordering::Relaxed);
        Ok(())
    }

    /// Sets the VM's PSCI version: 1.1, or 1.0 or 0.2 (a snapshot taken
    /// when that was the one offered), the three KVM takes
    /// (hypercalls.c kvm_arm_set_fw_reg).
    fn set_psci_version(&self, v: u64) -> Result<()> {
        if ![regs::PSCI_VERSION_0_2, regs::PSCI_VERSION_1_0, regs::PSCI_VERSION_1_1].contains(&v) {
            return err(libc::EINVAL);
        }
        self.vm()?.psci_version.store(v, Ordering::Relaxed);
        Ok(())
    }

    /// The value of a firmware pseudo-register (hypercalls.c
    /// `kvm_arm_get_fw_reg`): the VM's PSCI version and bitmaps of services,
    /// and the workaround levels. `None` for any other register.
    fn fw_reg(&self, reg: Reg) -> Result<Option<u64>> {
        Ok(Some(match reg {
            Reg::PsciVersion => self.vm()?.psci_version.load(Ordering::Relaxed),
            Reg::Workaround(_) => firmware::WORKAROUND_LEVEL,
            Reg::Bmap(bmap) => self.vm()?.smccc_features.lock().unwrap()[bmap as usize],
            _ => return Ok(None),
        }))
    }

    /// Writes a firmware pseudo-register (`kvm_arm_set_fw_reg`); `ENOENT`
    /// for any other register.
    fn set_fw_reg(&self, reg: Reg, v: u64) -> Result<()> {
        match reg {
            Reg::PsciVersion => self.set_psci_version(v),
            Reg::Workaround(n) if firmware::workaround_accepts(n, v, firmware::WORKAROUND_LEVEL) => Ok(()),
            Reg::Workaround(_) => err(libc::EINVAL),
            Reg::Bmap(bmap) => {
                let vm = self.vm()?;
                let mut features = vm.smccc_features.lock().unwrap();
                let ran_once = vm.ran_once.load(Ordering::Relaxed);
                let slot = &mut features[bmap as usize];
                *slot = firmware::bmap_write(bmap, *slot, v, ran_once).map_err(Error::new)?;
                Ok(())
            }
            _ => err(libc::ENOENT),
        }
    }

    /// Gives the vCPU the VM's counter offset if it changed since.
    fn apply_vtimer_offset(&self, hv: hv_vcpu_t, vm: &VmInner) -> Result<()> {
        let generation = vm.vtimer_gen.load(Ordering::Acquire);
        if self.shared.vtimer_gen.load(Ordering::Relaxed) == generation {
            return Ok(());
        }
        // SAFETY: `hv` belongs to this thread.
        check(unsafe { hv_vcpu_set_vtimer_offset(hv, vm.vtimer_offset.load(Ordering::Acquire)) })?;
        self.shared.vtimer_gen.store(generation, Ordering::Relaxed);
        Ok(())
    }

    /// Fails with `ENOEXEC` before `KVM_ARM_VCPU_INIT`, as KVM does.
    fn check_initialized(&self) -> Result<()> {
        if self.shared.initialized.load(Ordering::Acquire) {
            Ok(())
        } else {
            err(libc::ENOEXEC)
        }
    }

    /// Sets one register (`KVM_SET_ONE_REG`). Before the first `run()` the
    /// write is buffered and applied when the vCPU is created.
    pub fn set_one_reg(&self, reg_id: u64, data: &[u8]) -> Result<usize> {
        self.fd.check()?;
        self.check_initialized()?;
        let size = reg_size(reg_id);
        if data.len() < size {
            return err(libc::EINVAL);
        }
        let reg = regs::decode(reg_id).ok_or_else(|| Error::new(libc::ENOENT))?;
        self.check_visible(reg)?;
        if let Reg::Sys(r) = reg
            && idregs::is_id_reg(r)
        {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[..8]);
            self.set_id_reg(r, u64::from_le_bytes(buf))?;
            return Ok(size);
        }
        // The OS lock is the VMM's, with or without the vCPU.
        if reg == Reg::OsLock {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[..8]);
            self.set_os_lock(u64::from_le_bytes(buf))?;
            return Ok(size);
        }
        // So are the firmware registers: the VM's, from any of its vCPUs,
        // running or not (KVM takes them under the VM's lock).
        if reg.is_firmware() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[..8]);
            self.set_fw_reg(reg, u64::from_le_bytes(buf))?;
            return Ok(size);
        }
        let live = match self.live() {
            Ok(live) => live,
            // Another handle (a debugger's): only while the vCPU is stopped.
            Err(_) => {
                self.stopped_write(reg_id, reg, &data[..size])?;
                return Ok(size);
            }
        };
        match live {
            Some(hv) => {
                self.apply_remote_writes(hv)?;
                self.set_reg_now(hv, reg_id, &data[..size])?;
                if let Some(s) = self.shared.stopped.lock().unwrap().as_mut()
                    && let Some(v) = s.regs.get_mut(&reg_id)
                {
                    *v = data[..size].to_vec();
                }
            }
            // The counter is the VM's, and counts from the time of the write.
            None if reg == Reg::VirtualCount => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                self.vm()?.set_virtual_count(u64::from_le_bytes(buf));
            }
            None => {
                let mut pending = self.shared.pending.lock().unwrap();
                pending.retain(|(id, _)| *id != reg_id);
                pending.push((reg_id, data[..size].to_vec()));
            }
        }
        Ok(size)
    }

    /// Reads one register (`KVM_GET_ONE_REG`). Before the first `run()` the
    /// value is the last write, else the value a new vCPU starts with.
    pub fn get_one_reg(&self, reg_id: u64, data: &mut [u8]) -> Result<usize> {
        self.fd.check()?;
        self.check_initialized()?;
        let size = reg_size(reg_id);
        if data.len() < size {
            return err(libc::EINVAL);
        }
        let reg = regs::decode(reg_id).ok_or_else(|| Error::new(libc::ENOENT))?;
        self.check_visible(reg)?;
        if let Reg::Sys(r) = reg
            && idregs::is_id_reg(r)
        {
            let v = self.id_reg(r)?;
            data[..8].copy_from_slice(&v.to_le_bytes());
            return Ok(size);
        }
        if reg == Reg::OsLock {
            let debug = DebugRegs { os_lock: self.shared.os_lock.load(Ordering::Relaxed) };
            data[..8].copy_from_slice(&debug.oslsr().to_le_bytes());
            return Ok(size);
        }
        if let Some(v) = self.fw_reg(reg)? {
            data[..8].copy_from_slice(&v.to_le_bytes());
            return Ok(size);
        }
        match self.live() {
            Ok(Some(hv)) => {
                self.apply_remote_writes(hv)?;
                self.get_reg_now(hv, reg_id, &mut data[..size])?;
            }
            Ok(None) => self.get_reg_early(reg_id, &mut data[..size])?,
            // Another handle (a debugger's): only while the vCPU is stopped.
            Err(_) => self.stopped_read(reg_id, reg, &mut data[..size])?,
        }
        Ok(size)
    }

    /// Sets up guest debugging by user space (`KVM_SET_GUEST_DEBUG`), from
    /// any handle: stored, and applied by the vCPU when it next runs, as
    /// KVM applies it at the next `KVM_RUN` (`super::debug`).
    pub fn set_guest_debug(&self, debug_struct: &kvm_guest_debug) -> Result<()> {
        self.fd.check()?;
        self.shared.debug.lock().unwrap().set(debug_struct.control, &debug_struct.arch)
    }

    /// Publishes the registers of the stopped vCPU for its other handles
    /// (`debug::Stopped`); once per stop.
    fn publish(&self, hv: hv_vcpu_t) -> Result<()> {
        let mut stopped = self.shared.stopped.lock().unwrap();
        if stopped.is_some() {
            return Ok(());
        }
        let mut values = HashMap::new();
        for id in regs::reg_list() {
            // Read live from the VM by other handles.
            if matches!(
                regs::decode(id),
                Some(Reg::VirtualCount | Reg::PhysicalCount | Reg::OsLock)
            ) || regs::decode(id).is_some_and(Reg::is_firmware)
            {
                continue;
            }
            let mut buf = vec![0u8; reg_size(id)];
            self.get_reg_now(hv, id, &mut buf)?;
            values.insert(id, buf);
        }
        *stopped = Some(Stopped { regs: values, writes: Vec::new() });
        Ok(())
    }

    /// Applies, on the owner, the writes other handles made while the vCPU
    /// was stopped, in their order.
    fn apply_remote_writes(&self, hv: hv_vcpu_t) -> Result<()> {
        let writes = match self.shared.stopped.lock().unwrap().as_mut() {
            Some(s) => std::mem::take(&mut s.writes),
            None => return Ok(()),
        };
        for (id, data) in writes {
            self.set_reg_now(hv, id, &data)?;
        }
        Ok(())
    }

    /// A register of the stopped vCPU, for a handle that is not its owner;
    /// `EBUSY` while it runs, as before.
    fn stopped_read(&self, reg_id: u64, reg: Reg, out: &mut [u8]) -> Result<()> {
        let stopped = self.shared.stopped.lock().unwrap();
        let Some(s) = stopped.as_ref() else {
            return err(libc::EBUSY);
        };
        if matches!(reg, Reg::VirtualCount | Reg::PhysicalCount) || reg.is_firmware() {
            drop(stopped);
            return self.get_reg_early(reg_id, out);
        }
        let v = s.regs.get(&reg_id).ok_or_else(|| Error::new(libc::EBUSY))?;
        out.copy_from_slice(&v[..out.len()]);
        Ok(())
    }

    /// Writes a register of the stopped vCPU from a handle that is not its
    /// owner: read back at once, applied by the owner before it next uses
    /// the vCPU. `EBUSY` while it runs, as before.
    fn stopped_write(&self, reg_id: u64, reg: Reg, data: &[u8]) -> Result<()> {
        let mut stopped = self.shared.stopped.lock().unwrap();
        let Some(s) = stopped.as_mut() else {
            return err(libc::EBUSY);
        };
        let mut buf = [0u8; 8];
        let n = data.len().min(8);
        buf[..n].copy_from_slice(&data[..n]);
        let v = u64::from_le_bytes(buf);
        match reg {
            Reg::VirtualCount => {
                drop(stopped);
                self.vm()?.set_virtual_count(v);
                Ok(())
            }
            Reg::PsciVersion | Reg::Workaround(_) | Reg::Bmap(_) => {
                drop(stopped);
                self.set_fw_reg(reg, v)
            }
            Reg::Aarch32Spsr if v == 0 => Ok(()),
            Reg::PhysicalCount | Reg::Aarch32Spsr => err(libc::EINVAL),
            _ => {
                if let Some(slot) = s.regs.get_mut(&reg_id) {
                    *slot = data.to_vec();
                }
                s.writes.push((reg_id, data.to_vec()));
                Ok(())
            }
        }
    }

    /// Lists the registers that can be saved (`KVM_GET_REG_LIST`).
    pub fn get_reg_list(&self, reg_list: &mut RegList) -> Result<()> {
        self.fd.check()?;
        self.check_initialized()?;
        let mut ids = regs::reg_list();
        if self.ptrauth_hidden()? {
            ids.retain(|id| !matches!(regs::decode(*id), Some(Reg::Sys(r)) if idregs::is_ptrauth_key(r)));
        }
        let host = self.host_regs()?;
        ids.extend(
            idregs::ID_REGS
                .iter()
                .map(|r| regs::sys_id(*r))
                .filter(|id| host.contains_key(id)),
        );
        let capacity = reg_list.as_fam_struct_ref().n as usize;
        // SAFETY: only the header's `n` is written, like the kernel does.
        unsafe { (*reg_list.as_mut_fam_struct_ptr()).n = ids.len() as u64 };
        if capacity < ids.len() {
            return err(libc::E2BIG);
        }
        reg_list.as_mut_slice()[..ids.len()].copy_from_slice(&ids);
        Ok(())
    }

    /// Whether the vCPUs were given no pointer authentication, which hides
    /// its key registers, as on KVM.
    fn ptrauth_hidden(&self) -> Result<bool> {
        Ok(*self.vm()?.ptrauth.lock().unwrap() != Some(true))
    }

    /// `ENOENT` for a register KVM hides from this vCPU: the pointer
    /// authentication keys without `KVM_ARM_VCPU_PTRAUTH_ADDRESS` and
    /// `_GENERIC` (sys_regs.c `ptrauth_visibility`; `kvm_sys_reg_get_user`
    /// and `kvm_sys_reg_set_user` refuse a hidden register). A state that
    /// has them is refused by such a vCPU, as on KVM.
    fn check_visible(&self, reg: Reg) -> Result<()> {
        match reg {
            Reg::Sys(r) if idregs::is_ptrauth_key(r) && self.ptrauth_hidden()? => err(libc::ENOENT),
            _ => Ok(()),
        }
    }

    /// The register values of a new Hypervisor.framework vCPU.
    fn host_regs(&self) -> Result<HashMap<u64, Vec<u8>>> {
        let vm = self.vm()?;
        vm.reset_regs.get_or_init(probe_reset_regs).clone().map_err(Error::new)
    }

    /// The host's value of an ID register, `None` if this
    /// Hypervisor.framework does not have it; without pointer
    /// authentication in the vCPU features, with its fields 0, as KVM
    /// shows it.
    fn host_id_reg(&self, r: u16) -> Result<Option<u64>> {
        let vm = self.vm()?;
        let reset = vm
            .reset_regs
            .get_or_init(probe_reset_regs)
            .as_ref()
            .map_err(|e| Error::new(*e))?;
        let hidden = if *vm.ptrauth.lock().unwrap() == Some(true) { 0 } else { idregs::ptrauth_fields(r) };
        Ok(reset.get(&regs::sys_id(r)).map(|v| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&v[..8]);
            u64::from_le_bytes(buf) & !hidden
        }))
    }

    /// An ID register as the guest sees it: the VM's value if user space
    /// wrote one, else the host's; 0 for one the host does not have.
    fn id_reg(&self, r: u16) -> Result<u64> {
        if let Some(v) = self.vm()?.id_regs.lock().unwrap().get(&r) {
            return Ok(*v);
        }
        Ok(self.host_id_reg(r)?.unwrap_or(0))
    }

    /// Writes an ID register for the whole VM (`idregs`): `EBUSY` once a
    /// vCPU has run, unless unchanged; `EINVAL` for a field raised above the
    /// host's or one KVM does not let user space change.
    fn set_id_reg(&self, r: u16, v: u64) -> Result<()> {
        let vm = self.vm()?;
        let host = self.host_id_reg(r)?;
        let mut id_regs = vm.id_regs.lock().unwrap();
        let current = id_regs.get(&r).copied().unwrap_or(host.unwrap_or(0));
        if v == current {
            return Ok(());
        }
        if vm.id_locked.load(Ordering::Acquire) {
            return err(libc::EBUSY);
        }
        match host {
            // One the host does not have takes only 0 (above).
            None => return err(libc::EINVAL),
            Some(h) => idregs::check_write(r, h, v).map_err(|_| Error::new(libc::EINVAL))?,
        }
        id_regs.insert(r, v);
        Ok(())
    }

    /// Initializes the vCPU. Supported features: `POWER_OFF`, `PSCI_0_2`, and
    /// `PTRAUTH_ADDRESS` with `PTRAUTH_GENERIC`.
    pub fn vcpu_init(&self, kvi: &kvm_vcpu_init) -> Result<()> {
        self.fd.check()?;
        // The target must be the one `get_preferred_target` reports, as on KVM.
        if kvi.target != kvm_bindings::KVM_ARM_TARGET_GENERIC_V8 {
            return err(libc::EINVAL);
        }
        let ptrauth = (1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS) | (1 << KVM_ARM_VCPU_PTRAUTH_GENERIC);
        let allowed = (1 << KVM_ARM_VCPU_POWER_OFF) | (1 << KVM_ARM_VCPU_PSCI_0_2) | ptrauth;
        if kvi.features[0] & !allowed != 0 || kvi.features[1..].iter().any(|f| *f != 0) {
            return err(libc::EINVAL);
        }
        // Both pointer authentication features or neither, as KVM requires;
        // and the same for every vCPU of the VM.
        let has_ptrauth = match kvi.features[0] & ptrauth {
            0 => false,
            p if p == ptrauth => true,
            _ => return err(libc::EINVAL),
        };
        {
            let vm = self.vm()?;
            // A new vCPU's register values come from a scratch vCPU on a
            // thread of its own: read now, while the host sandbox still lets
            // a thread be made (Firecracker inits its vCPUs before it narrows
            // it), not in the run phase, which makes no thread
            // (SYS_bsdthread_create denied, as Linux's vCPU filter has no
            // clone): when a snapshot first lists the registers, or when a
            // vCPU the guest starts again (PSCI CPU_ON) is reset.
            let _ = vm.reset_regs.get_or_init(probe_reset_regs);
            let mut chosen = vm.ptrauth.lock().unwrap();
            if chosen.is_some_and(|c| c != has_ptrauth) {
                return err(libc::EINVAL);
            }
            *chosen = Some(has_ptrauth);
        }
        // KVM resets the vCPU: PSTATE and SCTLR_EL1 get their reset values
        // (other registers start as Hypervisor.framework creates them).
        let reset = [
            (regs::PSTATE_ID, regs::PSTATE_RESET),
            (regs::SCTLR_ID, regs::SCTLR_RESET),
        ];
        match self.live()? {
            Some(hv) => {
                for (id, v) in reset {
                    self.set_reg_now(hv, id, &v.to_le_bytes())?;
                }
            }
            None => {
                let mut pending = self.shared.pending.lock().unwrap();
                pending.clear();
                pending.extend(reset.map(|(id, v)| (id, v.to_le_bytes().to_vec())));
            }
        }
        let mut power = self.shared.power.lock().unwrap();
        power.off = kvi.features[0] & (1 << KVM_ARM_VCPU_POWER_OFF) != 0;
        power.boot = None;
        self.shared.initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// No feature needs finalizing (SVE is not offered): fails with `EINVAL`.
    pub fn vcpu_finalize(&self, _feature: &c_int) -> Result<()> {
        self.fd.check()?;
        err(libc::EINVAL)
    }

    /// Returns the power state.
    pub fn get_mp_state(&self) -> Result<kvm_mp_state> {
        self.fd.check()?;
        Ok(kvm_mp_state {
            mp_state: if self.shared.powered_off() {
                KVM_MP_STATE_STOPPED
            } else {
                KVM_MP_STATE_RUNNABLE
            },
        })
    }

    /// Sets the power state.
    pub fn set_mp_state(&self, mp_state: kvm_mp_state) -> Result<()> {
        self.fd.check()?;
        let off = match mp_state.mp_state {
            KVM_MP_STATE_RUNNABLE => false,
            KVM_MP_STATE_STOPPED => true,
            _ => return err(libc::EINVAL),
        };
        let mut power = self.shared.power.lock().unwrap();
        power.off = off;
        self.shared.notify(power);
        Ok(())
    }

    /// vCPU device attributes: PV time's IPA (`super::pvtime`); the PMU's and
    /// the timers' are not supported (`ENXIO`).
    pub fn has_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        pvtime::has_attr(device_attr)
    }

    /// Sets PV time's IPA, once (kvm_arm_pvtime_set_attr): a 64-byte aligned
    /// address in guest RAM. Other attributes are not supported (`ENXIO`).
    pub fn set_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        let ipa = pvtime::requested_ipa(device_attr)?;
        let mut steal = self.shared.pvtime.lock().unwrap();
        if steal.ipa != pvtime::NO_IPA {
            return err(libc::EEXIST);
        }
        if self.vm.ram_host_addr(ipa).is_none() {
            return err(libc::EINVAL);
        }
        steal.ipa = ipa;
        drop(steal);
        if let Some(kicker) = self.vm.pvtime_kicker.get() {
            kicker.register(&self.shared.pvtime);
        }
        self.shared.pvtime_on.store(true, Ordering::Release);
        Ok(())
    }

    /// Returns the `kvm_run` structure. Only `immediate_exit` is meaningful.
    pub fn get_kvm_run(&mut self) -> &mut kvm_run {
        // SAFETY: the shared page outlives the borrow of `self`; like KVM's
        // mapping, other mappings of it may write `immediate_exit`.
        unsafe { &mut *self.shared.run.ptr() }
    }

    /// Sets `immediate_exit`. Setting it to 1 also forces a running vCPU out
    /// of the guest, so the next (or current) `run()` returns `EINTR`.
    ///
    /// Clearing it on the owning thread is the vCPU taking the exit, which
    /// Firecracker also does without calling `run()` when it finds the flag
    /// already set (a kick that arrived between two runs): the vCPU then stops
    /// for its owner as when `run()` returns `EINTR`, so other threads may read
    /// its GIC registers (a snapshot right after a pause).
    pub fn set_kvm_immediate_exit(&mut self, val: u8) {
        self.shared.immediate_exit().store(val, Ordering::Release);
        if val != 0 {
            self.shared.cancel_run();
            self.shared.wake();
        } else if let Ok(Some(hv)) = self.live() {
            // A failure leaves the registers unreadable from other threads,
            // which then get EBUSY: reported there, never stale values.
            let _ = self.publish(hv);
            if self.vm().is_ok_and(|vm| vm.gic.lock().unwrap().created) {
                let _ = self.shared.gic.lock().unwrap().stop(hv);
            }
        }
    }

    fn reg(&self, hv: hv_vcpu_t, r: hv_reg_t) -> Result<u64> {
        let mut v = 0;
        // SAFETY: `hv` belongs to this thread.
        check(unsafe { hv_vcpu_get_reg(hv, r, &mut v) })?;
        Ok(v)
    }

    fn set_reg(&self, hv: hv_vcpu_t, r: hv_reg_t, v: u64) -> Result<()> {
        // SAFETY: `hv` belongs to this thread.
        check(unsafe { hv_vcpu_set_reg(hv, r, v) })
    }

    fn sys(&self, hv: hv_vcpu_t, r: hv_sys_reg_t) -> Result<u64> {
        let mut v = 0;
        // SAFETY: `hv` belongs to this thread.
        check(unsafe { hv_vcpu_get_sys_reg(hv, r, &mut v) })?;
        Ok(v)
    }

    fn advance_pc(&self, hv: hv_vcpu_t) -> Result<()> {
        let pc = self.reg(hv, HV_REG_PC)?;
        // A guest can run code in the last page of the address space.
        self.set_reg(hv, HV_REG_PC, pc.wrapping_add(4))
    }

    fn complete_mmio_read(&mut self, hv: hv_vcpu_t) -> Result<()> {
        let Some(p) = self.pending_read.take() else {
            return Ok(());
        };
        let v = p.load_value(&self.mmio);
        if p.srt != 31 {
            self.set_reg(hv, HV_REG_X0 + p.srt, v)?;
        }
        self.advance_pc(hv)
    }

    /// Waits until powered on. Returns false if a kick arrived first.
    /// The vCPU stops for its owner (`EINTR`, a pause): other threads may now
    /// read its GIC registers.
    fn stopped(&self, hv: hv_vcpu_t, gic: bool) -> Result<VcpuExit<'_>> {
        if gic {
            self.shared.gic.lock().unwrap().stop(hv)?;
        }
        self.publish(hv)?;
        err(libc::EINTR)
    }

    fn wait_powered_on(&mut self, hv: hv_vcpu_t) -> Result<bool> {
        let mut power = self.shared.power.lock().unwrap();
        loop {
            if !power.off {
                if let Some((entry, context)) = power.boot.take() {
                    drop(power);
                    self.reset_for_cpu_on(hv, entry, context)?;
                }
                return Ok(true);
            }
            if self.shared.immediate_exit().load(Ordering::Acquire) != 0 {
                return Ok(false);
            }
            let since = wall_ns();
            power = self.shared.cv.wait(power).unwrap();
            // Powered off: the guest's own wait (PSCI CPU_OFF), not steal.
            if self.shared.pvtime_on.load(Ordering::Acquire) {
                self.shared.pvtime.lock().unwrap().waited(wall_ns() - since);
            }
        }
    }

    /// Resets the vCPU that PSCI `CPU_ON` starts, as KVM does
    /// (arch/arm64/kvm/psci.c `kvm_psci_vcpu_on` asks for it, reset.c
    /// `kvm_reset_vcpu` does it), then starts it at `entry` with `context`
    /// in x0 (`kvm_reset_vcpu_psci`):
    /// - the core registers (kvm_emulate.h `kvm_reset_vcpu_core`): x0-x30,
    ///   SP_EL0, PC and the FP/SIMD registers, FPSR and FPCR to 0 (a new
    ///   Hypervisor.framework vCPU's values, `test_a_new_vcpu_has_kvms_reset_values`),
    ///   PSTATE EL1h with D, A, I and F masked;
    /// - the system registers (sys_regs.c `kvm_reset_sys_regs`), each the
    ///   vCPU keeps (`regs::reg_list`) to the value a new
    ///   Hypervisor.framework vCPU has: those KVM resets to a value
    ///   (`reset_val`) have it there, SCTLR_EL1 is written; those KVM
    ///   leaves UNKNOWN (`reset_unknown`) have the new vCPU's. SP_EL1,
    ///   ELR_EL1 and SPSR_EL1 keep theirs: KVM's have no reset;
    /// - the breakpoint and watchpoint registers to 0 (`reset_dbg_wb_reg`),
    ///   and the emulated debug registers as a new vCPU's;
    /// - the virtual timer (arch_timer.c `kvm_timer_vcpu_reset`, and
    ///   `TIMER_REG`'s `reset_val` 0): CNTV_CTL_EL0 and CNTV_CVAL_EL0 0,
    ///   unmasked; its offset is the VM's;
    /// - no MMIO load left to complete (`kvm_reset_vcpu_psci` clears what
    ///   was pending).
    ///
    /// They stay, as on KVM: MPIDR_EL1 and MIDR_EL1 (set at init), the
    /// counter (the VM's), the GIC redistributor (the vGIC is not reset).
    fn reset_for_cpu_on(&mut self, hv: hv_vcpu_t, entry: u64, context: u64) -> Result<()> {
        let vm = self.vm()?;
        let reset = vm.reset_regs.get_or_init(probe_reset_regs).as_ref().map_err(|e| Error::new(*e))?;
        for id in regs::reg_list() {
            match regs::decode(id) {
                Some(Reg::Sys(
                    HV_SYS_REG_MPIDR_EL1
                    | HV_SYS_REG_MIDR_EL1
                    | HV_SYS_REG_SP_EL1
                    | HV_SYS_REG_ELR_EL1
                    | HV_SYS_REG_SPSR_EL1,
                )) => continue,
                Some(Reg::VirtualCount | Reg::PhysicalCount) => continue,
                // The VM's, which no vCPU's reset touches.
                Some(reg) if reg.is_firmware() => continue,
                _ => {}
            }
            let v = reset.get(&id).ok_or_else(|| Error::new(libc::ENOENT))?;
            self.set_reg_now(hv, id, v)?;
        }
        self.set_reg_now(hv, regs::SCTLR_ID, &regs::SCTLR_RESET.to_le_bytes())?;
        // Breakpoints (DBGBVRn, DBGBCRn) and watchpoints (DBGWVRn,
        // DBGWCRn): every one the host has (its ID_AA64DFR0_EL1, not the
        // VM's, which a CPU template may lower), as KVM resets them all.
        let dfr0 = reset
            .get(&regs::sys_id(HV_SYS_REG_ID_AA64DFR0_EL1))
            .and_then(|v| v.as_slice().try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or_else(|| Error::new(libc::ENOENT))?;
        let breakpoints = ((dfr0 >> 12) & 0xf) + 1;
        let watchpoints = ((dfr0 >> 20) & 0xf) + 1;
        for n in 0..16u16 {
            // DBGBVRn, DBGBCRn (op2 4, 5); DBGWVRn, DBGWCRn (op2 6, 7).
            let mut op2s = Vec::new();
            if u64::from(n) < breakpoints {
                op2s.extend([4, 5]);
            }
            if u64::from(n) < watchpoints {
                op2s.extend([6, 7]);
            }
            for op2 in op2s {
                // SAFETY: `hv` belongs to this thread.
                check(unsafe { hv_vcpu_set_sys_reg(hv, 0x8000 | n << 3 | op2, 0) })?;
            }
        }
        // SAFETY: `hv` belongs to this thread.
        check(unsafe { hv_vcpu_set_vtimer_mask(hv, false) })?;
        self.shared.vtimer_masked.store(false, Ordering::Release);
        self.pending_read = None;
        self.set_reg(hv, HV_REG_PC, entry)?;
        self.set_reg(hv, HV_REG_X0, context)?;
        self.set_reg(hv, HV_REG_CPSR, PSTATE_EL1H_DAIF)
    }

    /// Unmasks the virtual timer once the guest no longer has it firing.
    fn update_vtimer(&self, hv: hv_vcpu_t) -> Result<()> {
        if !self.shared.vtimer_masked.load(Ordering::Acquire) {
            return Ok(());
        }
        let ctl = self.sys(hv, HV_SYS_REG_CNTV_CTL_EL0)?;
        let firing = ctl & 0b001 != 0 && ctl & 0b010 == 0 && ctl & 0b100 != 0;
        if !firing {
            // SAFETY: `hv` belongs to this thread.
            check(unsafe { hv_vcpu_set_vtimer_mask(hv, false) })?;
            self.shared.vtimer_masked.store(false, Ordering::Release);
        }
        Ok(())
    }

    /// A `WFI` exit's wait. With Hypervisor.framework's GIC, which
    /// Firecracker always makes (upstream's `setup_irqchip`, here
    /// `hv_gic_create`), a guest's WFI makes no exit: the framework waits in
    /// `hv_vcpu_run` (measured: no WFI exit in 15 guest waits of 20 ms). This
    /// is the wait of a VM without that GIC.
    fn wait_for_interrupt(&self, hv: hv_vcpu_t) -> Result<()> {
        let mut timeout = WFI_MAX_WAIT;
        let ctl = self.sys(hv, HV_SYS_REG_CNTV_CTL_EL0)?;
        if ctl & 0b001 != 0 && ctl & 0b010 == 0 {
            let cval = self.sys(hv, HV_SYS_REG_CNTV_CVAL_EL0)?;
            let mut offset = 0;
            // SAFETY: `hv` belongs to this thread.
            check(unsafe { hv_vcpu_get_vtimer_offset(hv, &mut offset) })?;
            // SAFETY: plain call.
            let now = unsafe { mach_absolute_time() }.wrapping_sub(offset);
            if cval <= now {
                return Ok(());
            }
            timeout = timeout.min(ticks_to_duration(cval - now));
        }
        if let Some((waited, _)) = self.shared.wait_for_wake(timeout) {
            self.waited_for_interrupt(waited);
        }
        Ok(())
    }

    /// Called with how long `WFI` (or PSCI `CPU_SUSPEND`) waited of the
    /// guest's own accord, which steal time leaves out (`pvtime::Steal`).
    /// With the framework's GIC it is not called ([`Self::wait_for_interrupt`]):
    /// the framework's own WFI time is read instead.
    fn waited_for_interrupt(&self, waited: Duration) {
        if self.shared.pvtime_on.load(Ordering::Acquire) {
            self.shared.pvtime.lock().unwrap().waited(waited.as_nanos() as u64);
        }
    }

    /// Handles a call through the SMCCC conduit (PSCI, SMCCC, the TRNG and
    /// KVM's vendor services). Returns a system event to report, if any,
    /// with its data.
    fn psci(&self, hv: hv_vcpu_t) -> Result<Option<(u32, &'static [u64; 1])>> {
        let id = self.reg(hv, HV_REG_X0)?;
        let call = Psci::decode(id);
        let x1 = self.reg(hv, HV_REG_X0 + 1)?;
        // The guest's PSCI version: 1.`minor`, or 0.2 (`None`).
        let version = self.vm()?.psci_version.load(Ordering::Relaxed);
        let minor = match version {
            regs::PSCI_VERSION_1_0 => Some(0),
            regs::PSCI_VERSION_1_1 => Some(1),
            _ => None,
        };
        // The services the VM's bitmaps leave the guest
        // (KVM_REG_ARM_STD_BMAP and the two beside it): a call whose bit is
        // clear is NOT_SUPPORTED with X1 to X3 0, before anything of it is
        // looked at (hypercalls.c kvm_hvc_call_handler: `val[4] =
        // {SMCCC_RET_NOT_SUPPORTED}`, `if (!kvm_hvc_call_allowed()) goto out`).
        let features = *self.vm()?.smccc_features.lock().unwrap();
        let words = match call {
            _ if !firmware::allowed(call, &features) => Some([PSCI_RET_NOT_SUPPORTED as u64, 0, 0, 0]),
            Psci::SmcccVersion => Some([exit::SMCCC_VERSION_1_1, 0, 0, 0]),
            // The TRNG service, whatever the PSCI version
            // (hypercalls.c kvm_hvc_call_handler, trng.c kvm_trng_call).
            Psci::TrngVersion => Some([trng::VERSION_1_0, 0, 0, 0]),
            Psci::TrngFeatures => Some([trng::features(x1), 0, 0, 0]),
            Psci::TrngGetUuid => Some(trng::UUID),
            // The number of bits is W1 (`u32 num_bits = smccc_get_arg1()`).
            Psci::TrngRnd32 => Some(trng::rnd(32, x1 as u32, trng::host_entropy)),
            Psci::TrngRnd64 => Some(trng::rnd(64, x1 as u32, trng::host_entropy)),
            // PV time's calls; no SMCCC_ARCH_WORKAROUND_* is implemented:
            // the guest relies on what its CPU features say, as on a host
            // whose firmware has none.
            Psci::SmcccArchFeatures => Some([
                pvtime::arch_feature(x1 as u32)
                    .filter(|_| firmware::pv_time_reported(&features))
                    .unwrap_or(PSCI_RET_NOT_SUPPORTED as u64),
                0,
                0,
                0,
            ]),
            Psci::VendorHypUid => Some(exit::KVM_UID),
            // The vendor bitmap itself (`val[0] = smccc_feat->vendor_hyp_bmap`).
            Psci::KvmFeatures => Some([features[regs::Bmap::VendorHyp as usize], 0, 0, 0]),
            Psci::KvmPtp => Some(self.kvm_ptp(hv, x1)?),
            Psci::PvTimeFeatures => {
                let ipa = self.shared.pvtime.lock().unwrap().ipa;
                let ret = if pvtime::features(x1 as u32, ipa) { PSCI_RET_SUCCESS } else { PSCI_RET_NOT_SUPPORTED };
                Some([ret as u64, 0, 0, 0])
            }
            Psci::PvTimeSt => Some([self.pv_time_st(hv), 0, 0, 0]),
            _ => None,
        };
        if let Some(words) = words {
            for (i, w) in words.into_iter().enumerate() {
                self.set_reg(hv, HV_REG_X0 + i as hv_reg_t, w)?;
            }
            return Ok(None);
        }
        // PSCI's own calls (psci.c kvm_psci_call). An SMC32 CPU_ON,
        // AFFINITY_INFO or SYSTEM_RESET2 takes the low 32 bits of its
        // arguments (kvm_psci_narrow_to_32bit).
        let narrow = id as u32 & PSCI_0_2_64BIT == 0;
        let arg = |n: hv_reg_t| -> Result<u64> {
            let v = self.reg(hv, HV_REG_X0 + n)?;
            Ok(if narrow { u64::from(v as u32) } else { v })
        };
        let mut event = None;
        let ret: i64 = match call {
            Psci::Version => version as i64,
            // The function asked about is a u32 (`u32 arg =
            // smccc_get_arg1()`): the upper half of X1 is not looked at.
            Psci::Features if minor.is_some_and(|minor| Psci::implemented(x1 as u32, minor)) => PSCI_RET_SUCCESS,
            Psci::Features => PSCI_RET_NOT_SUPPORTED,
            // PSCI 1.1 (kvm_psci_1_x_call): an architectural reset type up
            // to SYSTEM_WARM_RESET (0), or a vendor one (bit 31), is a reset
            // for the VMM, flagged as RESET2, with INTERNAL_FAILURE in X0
            // should the guest run on; another type is INVALID_PARAMS. KVM
            // keeps the type in a u32, for the SMC64 call as well. This one
            // return writes X0 alone (`vcpu_set_reg(vcpu, 0, ...)`): X1 to
            // X3 stay the guest's, narrowed in place for the SMC32 call.
            Psci::SystemReset2 if minor == Some(1) => {
                let reset_type = x1 as u32;
                if reset_type == 0 || reset_type >= 0x8000_0000 {
                    self.set_reg(hv, HV_REG_X0, PSCI_RET_INTERNAL_FAILURE as u64)?;
                    for n in 1..4 {
                        self.set_reg(hv, HV_REG_X0 + n, arg(n)?)?;
                    }
                    return Ok(Some((KVM_SYSTEM_EVENT_RESET, &SYSTEM_RESET2_EVENT_DATA)));
                }
                PSCI_RET_INVALID_PARAMS
            }
            Psci::SystemReset2 => PSCI_RET_NOT_SUPPORTED,
            Psci::CpuSuspend => {
                self.wait_for_interrupt(hv)?;
                PSCI_RET_SUCCESS
            }
            Psci::CpuOff => {
                self.shared.power.lock().unwrap().off = true;
                PSCI_RET_SUCCESS
            }
            Psci::CpuOn => {
                let (target, entry, context) = (arg(1)?, arg(2)?, arg(3)?);
                // kvm_psci_vcpu_on: a target with a bit outside the MPIDR's
                // affinity fields is INVALID_PARAMS (kvm_psci_valid_affinity),
                // as is one no vCPU has.
                match self.find_vcpu(target)? {
                    None => PSCI_RET_INVALID_PARAMS,
                    Some(target) => {
                        let mut power = target.power.lock().unwrap();
                        if !power.off {
                            PSCI_RET_ALREADY_ON
                        } else {
                            power.off = false;
                            power.boot = Some((entry, context));
                            target.notify(power);
                            PSCI_RET_SUCCESS
                        }
                    }
                }
            }
            Psci::AffinityInfo => self.affinity_info(arg(1)?, arg(2)?)?,
            Psci::MigrateInfoType => PSCI_TOS_NOT_PRESENT_MP,
            // The guest must not run on; should user space run the vCPU
            // again, the call has failed (kvm_psci_0_2_call: "we preload r0
            // (or x0) with PSCI return value INTERNAL_FAILURE").
            Psci::SystemOff => {
                event = Some((KVM_SYSTEM_EVENT_SHUTDOWN, &SYSTEM_EVENT_DATA));
                PSCI_RET_INTERNAL_FAILURE
            }
            Psci::SystemReset => {
                event = Some((KVM_SYSTEM_EVENT_RESET, &SYSTEM_EVENT_DATA));
                PSCI_RET_INTERNAL_FAILURE
            }
            Psci::NotSupported => PSCI_RET_NOT_SUPPORTED,
            Psci::SmcccVersion
            | Psci::TrngVersion
            | Psci::TrngFeatures
            | Psci::TrngGetUuid
            | Psci::TrngRnd32
            | Psci::TrngRnd64
            | Psci::SmcccArchFeatures
            | Psci::VendorHypUid
            | Psci::KvmFeatures
            | Psci::KvmPtp
            | Psci::PvTimeFeatures
            | Psci::PvTimeSt => unreachable!("answered above"),
        };
        // Every PSCI call returns through `smccc_set_retval(vcpu, val, 0,
        // 0, 0)` (psci.c kvm_psci_0_2_call, kvm_psci_1_x_call): X1 to X3
        // are 0 after it, CPU_OFF, SYSTEM_OFF and SYSTEM_RESET included.
        for (n, w) in [ret as u64, 0, 0, 0].into_iter().enumerate() {
            self.set_reg(hv, HV_REG_X0 + n as hv_reg_t, w)?;
        }
        Ok(event)
    }

    /// AFFINITY_INFO (psci.c kvm_psci_vcpu_affinity_info): ON (0) if a vCPU
    /// whose MPIDR matches `target` from affinity level `level` upwards is
    /// on, OFF (1) if all that match are off; INVALID_PARAMS for a target
    /// with a bit outside the affinity fields, a level over 3, or no match.
    fn affinity_info(&self, target: u64, level: u64) -> Result<i64> {
        if target & !MPIDR_AFFINITY_MASK != 0 || level > 3 {
            return Ok(PSCI_RET_INVALID_PARAMS);
        }
        // MPIDR_LEVEL_BITS is 8; level 3 is the field at bit 32.
        let mask = MPIDR_AFFINITY_MASK & !((1u64 << (level * 8)) - 1);
        let vm = self.vm()?;
        let vcpus = vm.vcpus.lock().unwrap();
        let mut matching = vcpus.iter().filter(|v| v.mpidr & mask == target & mask).peekable();
        if matching.peek().is_none() {
            return Ok(PSCI_RET_INVALID_PARAMS);
        }
        Ok(i64::from(matching.all(|v| v.powered_off())))
    }

    /// PV_TIME_ST (kvm_init_stolen_time): the IPA of the vCPU's stolen-time
    /// structure, zeroed (revision 0, attributes 0, no time stolen yet), or
    /// NOT_SUPPORTED when the vCPU has none. KVM's X0 is the IPA even if
    /// the write fails (a read-only slot): the guest then reads what is there.
    /// Steal is counted from this call on, as KVM counts it from the
    /// thread's run_delay at the call.
    fn pv_time_st(&self, hv: hv_vcpu_t) -> u64 {
        let mut steal = self.shared.pvtime.lock().unwrap();
        let ipa = steal.ipa;
        if ipa == pvtime::NO_IPA {
            return PSCI_RET_NOT_SUPPORTED as u64;
        }
        steal.start(wall_ns(), ticks_to_ns(pvtime::wfi_ticks(hv)));
        drop(steal);
        // SAFETY: STRUCT_SIZE bytes at the host address write_guest gives.
        self.vm.write_guest(ipa, pvtime::STRUCT_SIZE, |p| unsafe { std::ptr::write_bytes(p, 0, pvtime::STRUCT_SIZE) });
        ipa
    }

    /// Brings the guest's stolen time up to date, at most every
    /// millisecond (`pvtime::Steal`). Called by the owner, outside
    /// `hv_vcpu_run`, where the framework's WFI time can be read.
    fn pvtime_update(&self, hv: hv_vcpu_t) {
        if !self.shared.pvtime_on.load(Ordering::Acquire) {
            return;
        }
        let now = wall_ns();
        let mut steal = self.shared.pvtime.lock().unwrap();
        if !steal.due(now) {
            return;
        }
        let add = steal.update(now, ticks_to_ns(pvtime::wfi_ticks(hv)));
        let ipa = steal.ipa;
        drop(steal);
        if add > 0 {
            // `stolen_time`, le64 at offset 8 (8-byte aligned: the IPA is
            // 64-byte aligned, and so is its host address), read and written
            // with one access each, as kvm_get_guest/kvm_put_guest.
            self.vm.write_guest(ipa + 8, 8, |p| {
                // SAFETY: an aligned u64 in guest RAM, mapped while this runs.
                let word = unsafe { AtomicU64::from_ptr(p.cast::<u64>()) };
                let v = u64::from_le(word.load(Ordering::Relaxed)).wrapping_add(add);
                word.store(v.to_le(), Ordering::Relaxed);
            });
        }
    }

    /// KVM_PTP (kvm_ptp_get_time): the wall clock and the guest's virtual
    /// counter (`counter` 0, `CNTVCT_EL0`: `mach_absolute_time` less the
    /// vtimer offset, as Hypervisor.framework defines it) at the same
    /// moment. The wall clock is read between two counter reads, and the
    /// counter given is their midpoint. The physical counter (1) is
    /// NOT_SUPPORTED, as any other: Hypervisor.framework traps a guest's
    /// `CNTPCT_EL0` read (measured: `mrs x0, cntpct_el0` exits with
    /// EC 0x18) and [`VcpuFd::sysreg_trap`] makes it undefined, so the
    /// guest has no physical counter this could agree with; a Linux guest
    /// at EL1 asks for the virtual one (`ptp_kvm_arm`).
    fn kvm_ptp(&self, hv: hv_vcpu_t, counter: u64) -> Result<[u64; 4]> {
        if counter != 0 {
            return Ok([PSCI_RET_NOT_SUPPORTED as u64, 0, 0, 0]);
        }
        let mut offset = 0;
        // SAFETY: `hv` belongs to this thread.
        check(unsafe { hv_vcpu_get_vtimer_offset(hv, &mut offset) })?;
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: plain calls; `ts` is a valid timespec.
        let (before, after) = unsafe {
            let before = mach_absolute_time();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            (before, mach_absolute_time())
        };
        let realtime = (ts.tv_sec as u64)
            .wrapping_mul(1_000_000_000)
            .wrapping_add(ts.tv_nsec as u64);
        let now = before + (after - before) / 2;
        Ok(exit::ptp_words(realtime, now.wrapping_sub(offset)))
    }

    fn find_vcpu(&self, mpidr: u64) -> Result<Option<Arc<VcpuShared>>> {
        if mpidr & !MPIDR_AFFINITY_MASK != 0 {
            return Ok(None);
        }
        let vm = self.vm()?;
        let vcpus = vm.vcpus.lock().unwrap();
        Ok(vcpus
            .iter()
            .find(|v| v.mpidr & MPIDR_AFFINITY_MASK == mpidr & MPIDR_AFFINITY_MASK)
            .cloned())
    }

    /// Emulates a trapped system register access, as KVM does for the
    /// registers Hypervisor.framework leaves to the VMM (the OS lock and
    /// debug power registers). Any other trapped register raises an
    /// undefined instruction exception in the guest, like KVM does.
    fn sysreg_trap(&mut self, hv: hv_vcpu_t, access: SysregAccess) -> Result<()> {
        let value = if access.read || access.rt == 31 {
            0
        } else {
            self.reg(hv, HV_REG_X0 + access.rt)?
        };
        // While user space debugs with USE_HW, or the guest's OS lock is set,
        // the guest's debug register accesses trap, as KVM's (MDCR_EL2.TDA);
        // between runs the hardware holds the guest's own values (`debug`),
        // which they reach. One the host does not have is undefined.
        if let Some(r) = debug::trapped_register(access.encoding) {
            let done = if access.read {
                match self.sys(hv, r) {
                    Ok(v) if access.rt != 31 => self.set_reg(hv, HV_REG_X0 + access.rt, v).is_ok(),
                    Ok(_) => true,
                    Err(_) => false,
                }
            } else {
                // SAFETY: `hv` belongs to this thread.
                check(unsafe { hv_vcpu_set_sys_reg(hv, r, value) }).is_ok()
            };
            return if done { self.advance_pc(hv) } else { self.inject_undef(hv) };
        }
        let mut debug = DebugRegs { os_lock: self.shared.os_lock.load(Ordering::Relaxed) };
        let result = debug.access(access, value);
        self.shared.os_lock.store(debug.os_lock, Ordering::Relaxed);
        match result {
            SysregResult::Undefined => return self.inject_undef(hv),
            SysregResult::Read(v) if access.rt != 31 => self.set_reg(hv, HV_REG_X0 + access.rt, v)?,
            SysregResult::Read(_) | SysregResult::Written => {}
        }
        self.advance_pc(hv)
    }

    /// Raises an undefined instruction exception (ESR.EC = 0) at EL1, taken
    /// at the instruction that trapped.
    fn inject_undef(&self, hv: hv_vcpu_t) -> Result<()> {
        const ESR_IL: u64 = 1 << 25;
        let pc = self.reg(hv, HV_REG_PC)?;
        let cpsr = self.reg(hv, HV_REG_CPSR)?;
        let vbar = self.sys(hv, HV_SYS_REG_VBAR_EL1)?;
        let offset = exit::sync_vector_offset(cpsr);
        // SAFETY: `hv` belongs to this thread.
        unsafe {
            check(hv_vcpu_set_sys_reg(hv, HV_SYS_REG_ESR_EL1, ESR_IL))?;
            check(hv_vcpu_set_sys_reg(hv, HV_SYS_REG_ELR_EL1, pc))?;
            check(hv_vcpu_set_sys_reg(hv, HV_SYS_REG_SPSR_EL1, cpsr))?;
        }
        self.set_reg(hv, HV_REG_CPSR, PSTATE_EL1H_DAIF)?;
        self.set_reg(hv, HV_REG_PC, vbar + offset)
    }

    /// Runs the vCPU until an exit Firecracker must handle (`KVM_RUN`).
    pub fn run(&mut self) -> Result<VcpuExit<'_>> {
        // PV time accounts the thread while it is in here (`pvtime::Steal`).
        if !self.shared.pvtime_on.load(Ordering::Acquire) {
            return self.run_loop();
        }
        self.fd.check()?;
        let hv = self.ensure_created()?;
        let shared = Arc::clone(&self.shared);
        let kicker = self.vm.pvtime_kicker.get().cloned();
        shared.pvtime.lock().unwrap().enter(wall_ns(), hv);
        if let Some(kicker) = &kicker {
            kicker.entered();
        }
        let exit = self.run_loop();
        shared.pvtime.lock().unwrap().leave(wall_ns());
        if let Some(kicker) = &kicker {
            kicker.left();
        }
        exit
    }

    /// What another thread kicks this vCPU out of `run()` with, as
    /// [`VcpuFd::set_kvm_immediate_exit`]`(1)` does on a handle.
    #[cfg(test)]
    pub(crate) fn kick_for_test(&self) -> impl Fn() + Send + 'static {
        let shared = self.shared.clone();
        move || {
            shared.immediate_exit().store(1, Ordering::Release);
            shared.cancel_run();
            shared.wake();
        }
    }

    /// The framework's vCPU, for tests that read its counters on the owner thread.
    #[cfg(test)]
    pub(crate) fn hv_for_test(&self) -> Option<hv_vcpu_t> {
        self.shared.hv()
    }

    fn run_loop(&mut self) -> Result<VcpuExit<'_>> {
        self.fd.check()?;
        let hv = self.ensure_created()?;
        // What other handles wrote while it was stopped, then the debug
        // request in force, before anything else touches the vCPU.
        let stopped = self.shared.stopped.lock().unwrap().take();
        if let Some(stopped) = stopped {
            for (id, data) in stopped.writes {
                self.set_reg_now(hv, id, &data)?;
            }
        }
        self.debug.take(&mut self.shared.debug.lock().unwrap());
        self.complete_mmio_read(hv)?;
        let vm = self.vm()?;
        // The VM has run: its bitmaps of services stay as they are (arm.c
        // kvm_arch_vcpu_run_pid_change sets KVM_ARCH_FLAG_HAS_RAN_ONCE under
        // kvm->lock at a vCPU's first KVM_RUN).
        if !vm.ran_once.load(Ordering::Relaxed) {
            let _features = vm.smccc_features.lock().unwrap();
            vm.ran_once.store(true, Ordering::Relaxed);
        }
        let gic = vm.gic.lock().unwrap().created;
        if gic {
            self.shared.gic.lock().unwrap().flush(hv)?;
        }
        loop {
            if self.shared.immediate_exit().load(Ordering::Acquire) != 0 {
                return self.stopped(hv, gic);
            }
            if !self.wait_powered_on(hv)? {
                return self.stopped(hv, gic);
            }
            self.update_vtimer(hv)?;
            self.apply_vtimer_offset(hv, &vm)?;
            self.pvtime_update(hv);

            let saved = self.debug.enter(hv, self.shared.os_lock.load(Ordering::Relaxed))?;
            self.shared.in_run.store(true, Ordering::Release);
            // SAFETY: `hv` belongs to this thread.
            let ret = unsafe { hv_vcpu_run(hv) };
            self.shared.in_run.store(false, Ordering::Release);
            if let Some(saved) = saved {
                self.debug.leave(hv, saved)?;
            }
            check(ret)?;
            // SAFETY: Hypervisor.framework keeps the exit record valid for the vCPU's lifetime.
            let exit = unsafe { *self.exit.0 };

            match exit.reason {
                HV_EXIT_REASON_CANCELED => continue,
                HV_EXIT_REASON_VTIMER_ACTIVATED => {
                    // SAFETY: `hv` belongs to this thread; ISPENDR0 is write-1-to-set.
                    check(super::interrupting(|| unsafe {
                        hv_gic_set_redistributor_reg(
                            hv,
                            HV_GIC_REDISTRIBUTOR_REG_GICR_ISPENDR0,
                            1 << HV_GIC_INT_EL1_VIRTUAL_TIMER,
                        )
                    }))?;
                    self.shared.vtimer_masked.store(true, Ordering::Release);
                    vm.vtimer_masked();
                    continue;
                }
                HV_EXIT_REASON_EXCEPTION => {}
                _ => return Ok(VcpuExit::InternalError),
            }

            let esr = exit.exception.syndrome;
            match exit::decode(esr) {
                Exit::Abort { instruction, write } => {
                    let ipa = exit.exception.physical_address;
                    // Pages being replaced under the guest (a discard; see
                    // `vm::guest_replace`): wait for the new ones, then retry.
                    if vm.wait_mapped(ipa) {
                        continue;
                    }
                    // A page a userfaultfd has not filled: wait for it, as KVM
                    // does when it faults the host page in (get_user_pages).
                    if let Some(host) = vm.ram_host_addr(ipa)
                        && libc::wick_uffd::fault(host, write)
                    {
                        continue;
                    }
                    // A write to dirty-tracked memory: retry the instruction.
                    if write && vm.dirty_fault(ipa) {
                        continue;
                    }
                    if vm.stale_fault(ipa, write) {
                        continue;
                    }
                    if instruction {
                        return Ok(VcpuExit::Unsupported(esr as u32));
                    }
                    let Some(access) = Mmio::decode(esr) else {
                        return Ok(VcpuExit::Unsupported(esr as u32));
                    };
                    let len = access.len;
                    if access.write {
                        let v = if access.srt == 31 {
                            0
                        } else {
                            self.reg(hv, HV_REG_X0 + access.srt)?
                        };
                        self.advance_pc(hv)?;
                        self.mmio = access.store_bytes(v);
                        if vm.ioevent(ipa, &self.mmio[..len]) {
                            continue;
                        }
                        return Ok(VcpuExit::MmioWrite(ipa, &self.mmio[..len]));
                    }
                    self.pending_read = Some(access);
                    self.mmio = [0; 8];
                    return Ok(VcpuExit::MmioRead(ipa, &mut self.mmio[..len]));
                }
                call @ (Exit::Hvc | Exit::Smc) => {
                    // HVC leaves the PC past the call, SMC at it.
                    if call == Exit::Smc {
                        self.advance_pc(hv)?;
                    }
                    if let Some((event, data)) = self.psci(hv)? {
                        // As KVM since Linux 5.18 (kvm_prepare_system_event):
                        // one word of data, the event's flags, 0 for PSCI's
                        // SYSTEM_OFF and SYSTEM_RESET.
                        return Ok(VcpuExit::SystemEvent(event, data));
                    }
                }
                Exit::Wfi => {
                    self.advance_pc(hv)?;
                    self.wait_for_interrupt(hv)?;
                }
                Exit::Wfe => self.advance_pc(hv)?,
                Exit::Sysreg(access) => self.sysreg_trap(hv, access)?,
                // As KVM's kvm_handle_guest_debug: the PC stays at the
                // instruction; a step taken ends the active-pending state.
                Exit::Debug if self.debug.on() => {
                    if (esr >> 26) & 0x3f == exit::EC_SOFTWARE_STEP_LOWER {
                        self.debug.ss_active_pending = false;
                    }
                    let arch = debug::exit_arch(esr, exit.exception.virtual_address);
                    self.publish(hv)?;
                    return Ok(VcpuExit::Debug(arch));
                }
                Exit::Debug | Exit::Unsupported => return Ok(VcpuExit::Unsupported(esr as u32)),
            }
        }
    }
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for VcpuFd {
    fn drop(&mut self) {
        if let (true, Some(hv)) = (self.created_here, self.shared.hv()) {
            self.shared.hv.store(NOT_CREATED, Ordering::Release);
            // SAFETY: destroyed on the thread that created it.
            unsafe { hv_vcpu_destroy(hv) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KVM_PTP answers the virtual counter with the wall clock (the words
    // of kvm_ptp_get_time, KVM's own), and NOT_SUPPORTED for the physical
    // counter, which the guest cannot read here, and for any other.
    #[test]
    fn test_kvm_ptp_counters() {
        let vm = crate::Kvm::new().unwrap().create_vm().unwrap();
        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        let hv = vcpu.ensure_created().unwrap();
        for counter in [1, 2, u64::MAX] {
            assert_eq!(vcpu.kvm_ptp(hv, counter).unwrap(), [PSCI_RET_NOT_SUPPORTED as u64, 0, 0, 0]);
        }
        // SAFETY: plain calls.
        let (t0, mut ts) = unsafe { (mach_absolute_time(), libc::timespec { tv_sec: 0, tv_nsec: 0 }) };
        let words = vcpu.kvm_ptp(hv, 0).unwrap();
        // SAFETY: plain calls; `ts` is a valid timespec.
        let t1 = unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            mach_absolute_time()
        };
        let realtime = (words[0] << 32) | words[1];
        let count = (words[2] << 32) | words[3];
        let wall = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
        assert!(realtime <= wall && wall - realtime < 1_000_000_000, "{realtime} {wall}");
        let mut offset = 0;
        // SAFETY: `hv` belongs to this thread.
        check(unsafe { hv_vcpu_get_vtimer_offset(hv, &mut offset) }).unwrap();
        assert!(t0.wrapping_sub(offset) <= count && count <= t1.wrapping_sub(offset), "{t0} {count} {t1} {offset}");
    }

    // A wake made after WFI decided to wait and before it waits (here from
    // the waiting thread itself, at that point) ends the wait at once.
    #[test]
    fn test_a_wake_between_the_decision_and_the_wait_ends_it() {
        let (_handle, shared) = VcpuShared::new(0).unwrap();
        let other = shared.clone();
        BEFORE_WAIT.with(|f| *f.borrow_mut() = Some(Box::new(move || other.wake())));
        let ended = shared.wait_for_wake(Duration::from_secs(10));
        BEFORE_WAIT.with(|f| *f.borrow_mut() = None);
        assert_eq!(ended.map(|(_, e)| e), Some(Ended::Woken));
        assert_eq!(shared.triggers.load(Ordering::Relaxed), 1);
    }

    // A wake while WFI does not wait (interrupt injection's, for every vCPU)
    // costs no system call: WFI then sees it before it waits. A wake while
    // WFI waits ends the wait.
    #[test]
    fn test_a_wake_triggers_the_waiter_only_while_wfi_waits() {
        let (_handle, shared) = VcpuShared::new(0).unwrap();
        shared.wake();
        shared.wake();
        assert_eq!(shared.triggers.load(Ordering::Relaxed), 0);
        assert_eq!(shared.wait_for_wake(Duration::from_secs(10)), None);
        let start = Instant::now();
        let (_, ended) = shared.wait_for_wake(Duration::from_millis(20)).unwrap();
        assert_eq!(ended, Ended::Due);
        assert!(start.elapsed() >= Duration::from_millis(20));
        let other = shared.clone();
        let waker = std::thread::spawn(move || {
            while !other.power.lock().unwrap().waiting {
                std::thread::yield_now();
            }
            other.wake();
        });
        let (_, ended) = shared.wait_for_wake(Duration::from_secs(10)).unwrap();
        waker.join().unwrap();
        assert_eq!(ended, Ended::Woken);
        assert_eq!(shared.triggers.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_kvm_mpidr() {
        assert_eq!(kvm_mpidr(0), 0x8000_0000);
        assert_eq!(kvm_mpidr(1), 0x8000_0001);
        assert_eq!(kvm_mpidr(17), 0x8000_0101);
    }
}
