// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! vCPU handle: lazy creation, register access, and the run loop
//! (MMIO decode, PSCI, WFI, virtual timer).

use std::collections::HashMap;
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use kvm_bindings::{
    KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC, KVM_MP_STATE_RUNNABLE, KVM_MP_STATE_STOPPED,
    KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN, RegList, kvm_device_attr, kvm_mp_state,
    kvm_run, kvm_vcpu_init,
};

use super::exit::{self, DebugRegs, Exit, Mmio, Psci, SysregAccess, SysregResult};
use super::ffi::*;
use super::gic::{CpuReg, GicCpu};
use super::idregs;
use super::regs::{self, Reg, reg_size};
use super::vm::VmInner;
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
/// "Trusted OS not present": no migration needed.
const PSCI_TOS_NOT_PRESENT_MP: i64 = 2;

const MPIDR_AFFINITY_MASK: u64 = 0xff_00ff_ffff;
/// `kvm_run.system_event.data` of a PSCI SYSTEM_OFF or SYSTEM_RESET exit:
/// `ndata` 1, the flags 0 (KVM since Linux 5.18).
static SYSTEM_EVENT_DATA: [u64; 1] = [0];

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
    /// The `VmInner::vtimer_gen` whose offset the vCPU has (`u64::MAX`: none yet).
    vtimer_gen: AtomicU64,
    in_run: AtomicBool,
    power: Mutex<Power>,
    cv: Condvar,
    /// Register writes made before the Hypervisor.framework vCPU exists.
    pending: Mutex<Vec<(u64, Vec<u8>)>>,
    /// Set by `KVM_ARM_VCPU_INIT`; registers cannot be used before it.
    initialized: AtomicBool,
    /// GIC redistributor and CPU interface registers for other threads.
    gic: Mutex<GicCpu>,
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
            vtimer_gen: AtomicU64::new(u64::MAX),
            in_run: AtomicBool::new(false),
            power: Mutex::new(Power::default()),
            cv: Condvar::new(),
            pending: Mutex::new(Vec::new()),
            initialized: AtomicBool::new(false),
            gic: Mutex::new(GicCpu::default()),
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
        self.power.lock().unwrap().wake = true;
        self.cv.notify_all();
    }

    fn cancel_run(&self) {
        if let Some(hv) = self.hv() {
            // SAFETY: valid vCPU id; may be called from any thread.
            unsafe { hv_vcpus_exit(&hv, 1) };
        }
    }

    pub(crate) fn poke_if_vtimer_masked(&self) {
        if self.vtimer_masked.load(Ordering::Acquire) && self.in_run.load(Ordering::Acquire) {
            // Not in a signal handler (the vtimer thread), so it may wait.
            super::interrupting(|| self.cancel_run());
        }
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
    /// Debug registers emulated in user space (see `sysreg_trap`).
    debug: DebugRegs,
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
            debug: DebugRegs::default(),
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
        if regs::decode(id) == Some(Reg::PsciVersion) {
            let v = self.vm()?.psci_version.load(Ordering::Relaxed);
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
            Some(Reg::PsciVersion) => vm.psci_version.load(Ordering::Relaxed),
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
                Reg::PsciVersion => v = regs::PSCI_VERSION_1_0,
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
                Reg::PsciVersion => self.set_psci_version(v),
                Reg::PhysicalCount | Reg::Aarch32Spsr => err(libc::EINVAL),
            }
        }
    }

    /// Sets the VM's PSCI version: 1.0, or 0.2 (a snapshot taken when 0.2
    /// was the one offered). KVM also takes 1.1, which is not offered here.
    fn set_psci_version(&self, v: u64) -> Result<()> {
        if v != regs::PSCI_VERSION_0_2 && v != regs::PSCI_VERSION_1_0 {
            return err(libc::EINVAL);
        }
        self.vm()?.psci_version.store(v, Ordering::Relaxed);
        Ok(())
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
        match self.live()? {
            Some(hv) => self.set_reg_now(hv, reg_id, &data[..size])?,
            // The counter is the VM's, and counts from the time of the write.
            None if reg == Reg::VirtualCount => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                self.vm()?.set_virtual_count(u64::from_le_bytes(buf));
            }
            // So is the PSCI version.
            None if reg == Reg::PsciVersion => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                self.set_psci_version(u64::from_le_bytes(buf))?;
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
        match self.live()? {
            Some(hv) => self.get_reg_now(hv, reg_id, &mut data[..size])?,
            None => self.get_reg_early(reg_id, &mut data[..size])?,
        }
        Ok(size)
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
        self.shared.power.lock().unwrap().off = off;
        self.shared.cv.notify_all();
        Ok(())
    }

    /// vCPU device attributes (PMU, timers, PV time) are not supported (`ENXIO`).
    pub fn has_device_attr(&self, _device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        err(libc::ENXIO)
    }

    /// vCPU device attributes (PMU, timers, PV time) are not supported (`ENXIO`).
    pub fn set_device_attr(&self, _device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        err(libc::ENXIO)
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
        } else if let Ok(Some(hv)) = self.live()
            && self.vm().is_ok_and(|vm| vm.gic.lock().unwrap().created)
        {
            // A failure leaves the registers unreadable from other threads,
            // which then get EBUSY: reported there, never stale values.
            let _ = self.shared.gic.lock().unwrap().stop(hv);
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
            power = self.shared.cv.wait(power).unwrap();
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
                Some(Reg::VirtualCount | Reg::PhysicalCount | Reg::PsciVersion) => continue,
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
        self.debug = DebugRegs::default();
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
        let mut power = self.shared.power.lock().unwrap();
        if !power.wake && self.shared.immediate_exit().load(Ordering::Acquire) == 0 {
            power = self.shared.cv.wait_timeout(power, timeout).unwrap().0;
        }
        power.wake = false;
        Ok(())
    }

    /// Handles a call through the SMCCC conduit (PSCI, SMCCC, KVM's vendor
    /// services). Returns a system event to report, if any.
    fn psci(&self, hv: hv_vcpu_t) -> Result<Option<u32>> {
        let call = Psci::decode(self.reg(hv, HV_REG_X0)?);
        let x1 = self.reg(hv, HV_REG_X0 + 1)?;
        let psci_1_0 = self.vm()?.psci_version.load(Ordering::Relaxed) == regs::PSCI_VERSION_1_0;
        let words = match call {
            Psci::SmcccVersion => Some([exit::SMCCC_VERSION_1_1, 0, 0, 0]),
            // No SMCCC_ARCH_WORKAROUND_* (nor TRNG, PV time) is implemented:
            // the guest relies on what its CPU features say, as on a host
            // whose firmware has none.
            Psci::SmcccArchFeatures => Some([PSCI_RET_NOT_SUPPORTED as u64, 0, 0, 0]),
            Psci::VendorHypUid => Some(exit::KVM_UID),
            Psci::KvmFeatures => Some([exit::KVM_FEATURES, 0, 0, 0]),
            Psci::KvmPtp => Some(self.kvm_ptp(hv, x1)?),
            _ => None,
        };
        if let Some(words) = words {
            for (i, w) in words.into_iter().enumerate() {
                self.set_reg(hv, HV_REG_X0 + i as hv_reg_t, w)?;
            }
            return Ok(None);
        }
        let ret: i64 = match call {
            Psci::Version if psci_1_0 => regs::PSCI_VERSION_1_0 as i64,
            Psci::Version => regs::PSCI_VERSION_0_2 as i64,
            Psci::Features if psci_1_0 && Psci::implemented(x1) => PSCI_RET_SUCCESS,
            Psci::Features => PSCI_RET_NOT_SUPPORTED,
            Psci::CpuSuspend => {
                self.wait_for_interrupt(hv)?;
                PSCI_RET_SUCCESS
            }
            Psci::CpuOff => {
                self.shared.power.lock().unwrap().off = true;
                return Ok(None);
            }
            Psci::CpuOn => {
                let entry = self.reg(hv, HV_REG_X0 + 2)?;
                let context = self.reg(hv, HV_REG_X0 + 3)?;
                match self.find_vcpu(x1)? {
                    None => PSCI_RET_INVALID_PARAMS,
                    Some(target) => {
                        let mut power = target.power.lock().unwrap();
                        if !power.off {
                            PSCI_RET_ALREADY_ON
                        } else {
                            power.off = false;
                            power.boot = Some((entry, context));
                            drop(power);
                            target.cv.notify_all();
                            PSCI_RET_SUCCESS
                        }
                    }
                }
            }
            Psci::AffinityInfo => match self.find_vcpu(x1)? {
                None => PSCI_RET_INVALID_PARAMS,
                Some(target) => i64::from(target.powered_off()),
            },
            Psci::MigrateInfoType => PSCI_TOS_NOT_PRESENT_MP,
            Psci::SystemOff => return Ok(Some(KVM_SYSTEM_EVENT_SHUTDOWN)),
            Psci::SystemReset => return Ok(Some(KVM_SYSTEM_EVENT_RESET)),
            Psci::NotSupported => PSCI_RET_NOT_SUPPORTED,
            Psci::SmcccVersion
            | Psci::SmcccArchFeatures
            | Psci::VendorHypUid
            | Psci::KvmFeatures
            | Psci::KvmPtp => unreachable!("answered above"),
        };
        self.set_reg(hv, HV_REG_X0, ret as u64)?;
        Ok(None)
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
        match self.debug.access(access, value) {
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
        self.fd.check()?;
        let hv = self.ensure_created()?;
        self.complete_mmio_read(hv)?;
        let vm = self.vm()?;
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

            self.shared.in_run.store(true, Ordering::Release);
            // SAFETY: `hv` belongs to this thread.
            let ret = unsafe { hv_vcpu_run(hv) };
            self.shared.in_run.store(false, Ordering::Release);
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
                    if let Some(event) = self.psci(hv)? {
                        // As KVM since Linux 5.18 (kvm_prepare_system_event):
                        // one word of data, the event's flags, 0 for PSCI's
                        // SYSTEM_OFF and SYSTEM_RESET.
                        return Ok(VcpuExit::SystemEvent(event, &SYSTEM_EVENT_DATA));
                    }
                }
                Exit::Wfi => {
                    self.advance_pc(hv)?;
                    self.wait_for_interrupt(hv)?;
                }
                Exit::Wfe => self.advance_pc(hv)?,
                Exit::Sysreg(access) => self.sysreg_trap(hv, access)?,
                Exit::Unsupported => return Ok(VcpuExit::Unsupported(esr as u32)),
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

    #[test]
    fn test_kvm_mpidr() {
        assert_eq!(kvm_mpidr(0), 0x8000_0000);
        assert_eq!(kvm_mpidr(1), 0x8000_0001);
        assert_eq!(kvm_mpidr(17), 0x8000_0101);
    }
}
