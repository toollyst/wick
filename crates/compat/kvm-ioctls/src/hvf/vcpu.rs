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
    KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_MP_STATE_RUNNABLE, KVM_MP_STATE_STOPPED,
    KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN, RegList, kvm_device_attr, kvm_mp_state,
    kvm_run, kvm_vcpu_init,
};

use super::ffi::*;
use super::gic::{CpuReg, GicCpu};
use super::regs::{self, Reg, reg_size};
use super::vm::VmInner;
use super::{Error, Handle, Result, VcpuExit, err};

const NOT_CREATED: u64 = u64::MAX;

/// `PSTATE` for a CPU brought up by PSCI `CPU_ON`: EL1h with D, A, I and F masked.
const PSTATE_EL1H_DAIF: u64 = 0x3c5;

/// Longest a `WFI` waits before re-entering the guest. Interrupts raised by
/// other vCPUs (SGIs) are not seen by the waiting thread, so it polls.
const WFI_MAX_WAIT: Duration = Duration::from_millis(1);

// Exception classes (ESR_EL2.EC).
const EC_WFX: u64 = 0x01;
const EC_HVC64: u64 = 0x16;
const EC_SMC64: u64 = 0x17;
const EC_SYSREG: u64 = 0x18;
const EC_DATA_ABORT_LOWER: u64 = 0x24;
const EC_INST_ABORT_LOWER: u64 = 0x20;

// PSCI 0.2 function ids (SMC32 and SMC64 variants) and return values.
const PSCI_VERSION: u32 = 0x8400_0000;
const PSCI_CPU_SUSPEND: [u32; 2] = [0x8400_0001, 0xc400_0001];
const PSCI_CPU_OFF: u32 = 0x8400_0002;
const PSCI_CPU_ON: [u32; 2] = [0x8400_0003, 0xc400_0003];
const PSCI_AFFINITY_INFO: [u32; 2] = [0x8400_0004, 0xc400_0004];
const PSCI_MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;
const PSCI_RET_SUCCESS: i64 = 0;
const PSCI_RET_NOT_SUPPORTED: i64 = -1;
const PSCI_RET_INVALID_PARAMS: i64 = -2;
const PSCI_RET_ALREADY_ON: i64 = -4;
/// "Trusted OS not present": no migration needed.
const PSCI_TOS_NOT_PRESENT_MP: i64 = 2;
/// PSCI 0.2.
const PSCI_VERSION_0_2: i64 = 2;

const MPIDR_AFFINITY_MASK: u64 = 0xff_00ff_ffff;

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
            self.cancel_run();
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

struct PendingRead {
    srt: u32,
    len: usize,
    sign_extend: bool,
    sixty_four: bool,
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
    pending_read: Option<PendingRead>,
    // Debug registers emulated in user space (see `sysreg_trap`).
    os_lock: bool,
    os_double_lock: bool,
    dbg_power_request: bool,
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
            // The OS lock is set at reset.
            os_lock: true,
            os_double_lock: false,
            dbg_power_request: false,
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
        check(unsafe { hv_vcpu_create(&mut hv, &mut exit, std::ptr::null_mut()) })?;
        self.exit = ExitPtr(exit);
        self.created_here = true;
        // SAFETY: `hv` was just created on this thread.
        unsafe {
            check(hv_vcpu_set_sys_reg(
                hv,
                HV_SYS_REG_MPIDR_EL1,
                self.shared.mpidr,
            ))?;
            check(hv_vcpu_set_vtimer_offset(hv, vm.vtimer_offset))?;
        }
        // The GIC registers exist once MPIDR_EL1 is set.
        let gic_created = vm.gic.lock().unwrap().created;
        if gic_created {
            super::gic::reroute_spis(super::gic::packed_affinity(self.shared.mpidr))?;
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
            Some(Reg::VirtualCount) => {
                unsafe { mach_absolute_time() }.wrapping_sub(vm.vtimer_offset)
            }
            // SAFETY: plain call.
            Some(Reg::PhysicalCount) => unsafe { mach_absolute_time() },
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
        let ret = unsafe { hv_vcpu_create(&mut hv, &mut exit, std::ptr::null_mut()) };
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
                Reg::PsciVersion => v = regs::PSCI_VERSION_0_2,
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
                Reg::VirtualCount => check(hv_vcpu_set_vtimer_offset(
                    hv,
                    mach_absolute_time().wrapping_sub(v),
                )),
                Reg::Aarch32Spsr if v == 0 => Ok(()),
                Reg::PsciVersion if v == regs::PSCI_VERSION_0_2 => Ok(()),
                Reg::PhysicalCount | Reg::Aarch32Spsr | Reg::PsciVersion => err(libc::EINVAL),
            }
        }
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
        regs::decode(reg_id).ok_or_else(|| Error::new(libc::ENOENT))?;
        match self.live()? {
            Some(hv) => self.set_reg_now(hv, reg_id, &data[..size])?,
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
        regs::decode(reg_id).ok_or_else(|| Error::new(libc::ENOENT))?;
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
        let ids = regs::reg_list();
        let capacity = reg_list.as_fam_struct_ref().n as usize;
        // SAFETY: only the header's `n` is written, like the kernel does.
        unsafe { (*reg_list.as_mut_fam_struct_ptr()).n = ids.len() as u64 };
        if capacity < ids.len() {
            return err(libc::E2BIG);
        }
        reg_list.as_mut_slice()[..ids.len()].copy_from_slice(&ids);
        Ok(())
    }

    /// Initializes the vCPU. Supported features: `POWER_OFF` and `PSCI_0_2`.
    pub fn vcpu_init(&self, kvi: &kvm_vcpu_init) -> Result<()> {
        self.fd.check()?;
        // The target must be the one `get_preferred_target` reports, as on KVM.
        if kvi.target != kvm_bindings::KVM_ARM_TARGET_GENERIC_V8 {
            return err(libc::EINVAL);
        }
        let allowed = (1 << KVM_ARM_VCPU_POWER_OFF) | (1 << KVM_ARM_VCPU_PSCI_0_2);
        if kvi.features[0] & !allowed != 0 || kvi.features[1..].iter().any(|f| *f != 0) {
            return err(libc::EINVAL);
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
    pub fn set_kvm_immediate_exit(&mut self, val: u8) {
        self.shared.immediate_exit().store(val, Ordering::Release);
        if val != 0 {
            self.shared.cancel_run();
            self.shared.wake();
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
        self.set_reg(hv, HV_REG_PC, pc + 4)
    }

    fn complete_mmio_read(&mut self, hv: hv_vcpu_t) -> Result<()> {
        let Some(p) = self.pending_read.take() else {
            return Ok(());
        };
        let mut buf = [0u8; 8];
        buf[..p.len].copy_from_slice(&self.mmio[..p.len]);
        let mut v = u64::from_le_bytes(buf);
        if p.sign_extend && p.len < 8 {
            let shift = 64 - 8 * p.len as u32;
            v = (((v << shift) as i64) >> shift) as u64;
        }
        if !p.sixty_four {
            v &= 0xffff_ffff;
        }
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

    fn wait_powered_on(&self, hv: hv_vcpu_t) -> Result<bool> {
        let mut power = self.shared.power.lock().unwrap();
        loop {
            if !power.off {
                if let Some((entry, context)) = power.boot.take() {
                    drop(power);
                    self.set_reg(hv, HV_REG_PC, entry)?;
                    self.set_reg(hv, HV_REG_X0, context)?;
                    self.set_reg(hv, HV_REG_CPSR, PSTATE_EL1H_DAIF)?;
                }
                return Ok(true);
            }
            if self.shared.immediate_exit().load(Ordering::Acquire) != 0 {
                return Ok(false);
            }
            power = self.shared.cv.wait(power).unwrap();
        }
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

    /// Handles a PSCI call. Returns a system event to report, if any.
    fn psci(&self, hv: hv_vcpu_t) -> Result<Option<u32>> {
        let func = self.reg(hv, HV_REG_X0)? as u32;
        let x1 = self.reg(hv, HV_REG_X0 + 1)?;
        let ret: i64 = match func {
            PSCI_VERSION => PSCI_VERSION_0_2,
            f if PSCI_CPU_SUSPEND.contains(&f) => {
                self.wait_for_interrupt(hv)?;
                PSCI_RET_SUCCESS
            }
            PSCI_CPU_OFF => {
                self.shared.power.lock().unwrap().off = true;
                return Ok(None);
            }
            f if PSCI_CPU_ON.contains(&f) => {
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
            f if PSCI_AFFINITY_INFO.contains(&f) => match self.find_vcpu(x1)? {
                None => PSCI_RET_INVALID_PARAMS,
                Some(target) => i64::from(target.powered_off()),
            },
            PSCI_MIGRATE_INFO_TYPE => PSCI_TOS_NOT_PRESENT_MP,
            PSCI_SYSTEM_OFF => return Ok(Some(KVM_SYSTEM_EVENT_SHUTDOWN)),
            PSCI_SYSTEM_RESET => return Ok(Some(KVM_SYSTEM_EVENT_RESET)),
            _ => PSCI_RET_NOT_SUPPORTED,
        };
        self.set_reg(hv, HV_REG_X0, ret as u64)?;
        Ok(None)
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
    fn sysreg_trap(&mut self, hv: hv_vcpu_t, iss: u64) -> Result<()> {
        let is_read = iss & 1 != 0;
        let rt = ((iss >> 5) & 0x1f) as u32;
        let enc = (
            (iss >> 20) & 3,   // op0
            (iss >> 14) & 7,   // op1
            (iss >> 10) & 0xf, // CRn
            (iss >> 1) & 0xf,  // CRm
            (iss >> 17) & 7,   // op2
        );
        let value = if is_read || rt == 31 {
            0
        } else {
            self.reg(hv, HV_REG_X0 + rt)?
        };
        let read = match enc {
            // OSLAR_EL1 (write only): sets the OS lock.
            (2, 0, 1, 0, 4) if !is_read => {
                self.os_lock = value & 1 != 0;
                None
            }
            // OSLSR_EL1 (read only): OS lock implemented (OSLM = 0b10) and its state.
            (2, 0, 1, 1, 4) if is_read => Some(0b1000 | u64::from(self.os_lock) << 1),
            // OSDLR_EL1: double lock.
            (2, 0, 1, 3, 4) => {
                if is_read {
                    Some(u64::from(self.os_double_lock))
                } else {
                    self.os_double_lock = value & 1 != 0;
                    None
                }
            }
            // DBGPRCR_EL1: core power-down request.
            (2, 0, 1, 4, 4) => {
                if is_read {
                    Some(u64::from(self.dbg_power_request))
                } else {
                    self.dbg_power_request = value & 1 != 0;
                    None
                }
            }
            _ => return self.inject_undef(hv),
        };
        if let (Some(v), true) = (read, rt != 31) {
            self.set_reg(hv, HV_REG_X0 + rt, v)?;
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
        let from_el1 = (cpsr >> 2) & 3 == 1;
        let offset = match (from_el1, cpsr & 1 != 0) {
            (true, true) => 0x200,  // current EL with SP_ELx
            (true, false) => 0x000, // current EL with SP_EL0
            (false, _) => 0x400,    // lower EL, AArch64
        };
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
                    check(unsafe {
                        hv_gic_set_redistributor_reg(
                            hv,
                            HV_GIC_REDISTRIBUTOR_REG_GICR_ISPENDR0,
                            1 << HV_GIC_INT_EL1_VIRTUAL_TIMER,
                        )
                    })?;
                    self.shared.vtimer_masked.store(true, Ordering::Release);
                    continue;
                }
                HV_EXIT_REASON_EXCEPTION => {}
                _ => return Ok(VcpuExit::InternalError),
            }

            let esr = exit.exception.syndrome;
            let ec = (esr >> 26) & 0x3f;
            let iss = esr & 0x1ff_ffff;
            match ec {
                EC_DATA_ABORT_LOWER | EC_INST_ABORT_LOWER => {
                    let ipa = exit.exception.physical_address;
                    let write = ec == EC_DATA_ABORT_LOWER && iss & (1 << 6) != 0;
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
                    if ec == EC_INST_ABORT_LOWER {
                        return Ok(VcpuExit::Unsupported(esr as u32));
                    }
                    let isv = iss & (1 << 24) != 0;
                    let s1ptw = iss & (1 << 7) != 0;
                    if !isv || s1ptw {
                        return Ok(VcpuExit::Unsupported(esr as u32));
                    }
                    let len = 1usize << ((iss >> 22) & 0b11);
                    let srt = ((iss >> 16) & 0x1f) as u32;
                    let addr = exit.exception.physical_address;
                    if iss & (1 << 6) != 0 {
                        let v = if srt == 31 {
                            0
                        } else {
                            self.reg(hv, HV_REG_X0 + srt)?
                        };
                        self.advance_pc(hv)?;
                        self.mmio[..len].copy_from_slice(&v.to_le_bytes()[..len]);
                        if vm.ioevent(addr, &self.mmio[..len]) {
                            continue;
                        }
                        return Ok(VcpuExit::MmioWrite(addr, &self.mmio[..len]));
                    }
                    self.pending_read = Some(PendingRead {
                        srt,
                        len,
                        sign_extend: iss & (1 << 21) != 0,
                        sixty_four: iss & (1 << 15) != 0,
                    });
                    self.mmio = [0; 8];
                    return Ok(VcpuExit::MmioRead(addr, &mut self.mmio[..len]));
                }
                EC_HVC64 | EC_SMC64 => {
                    if ec == EC_SMC64 {
                        self.advance_pc(hv)?;
                    }
                    if let Some(event) = self.psci(hv)? {
                        return Ok(VcpuExit::SystemEvent(event, &[]));
                    }
                }
                EC_WFX => {
                    self.advance_pc(hv)?;
                    if iss & 1 == 0 {
                        self.wait_for_interrupt(hv)?;
                    }
                }
                EC_SYSREG => self.sysreg_trap(hv, iss)?,
                _ => return Ok(VcpuExit::Unsupported(esr as u32)),
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

    #[test]
    fn test_kvm_mpidr() {
        assert_eq!(kvm_mpidr(0), 0x8000_0000);
        assert_eq!(kvm_mpidr(1), 0x8000_0001);
        assert_eq!(kvm_mpidr(17), 0x8000_0101);
    }
}
