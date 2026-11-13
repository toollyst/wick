// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! VM handle: guest memory, ioeventfds, irqfds and interrupt routing.

use std::collections::HashMap;
use std::fs::File;
use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use kvm_bindings::{
    KVM_ARM_TARGET_GENERIC_V8, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI,
    KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY, KvmIrqRouting, kvm_create_device, kvm_device_attr,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_msi,
    kvm_userspace_memory_region, kvm_vcpu_init,
};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::{ConsumerId, EFD_NONBLOCK, EventFd};

use super::device::{DeviceFd, DeviceKind};
use super::ffi::*;
use super::vcpu::{VcpuFd, VcpuShared};
use super::wait::{Ended, Waiter};
use super::{Cap, Handle, IoEventAddress, Result, cap, err};

/// First SPI interrupt id; KVM maps legacy GSI `n` to `n + 32`.
const SPI_BASE: u32 = 32;

/// The live VM, if any (Hypervisor.framework allows one per process).
static CURRENT: Mutex<Weak<VmInner>> = Mutex::new(Weak::new());
/// Set when a VM went away while Hypervisor.framework still had vCPUs of it
/// (they belong to threads that had not exited): it is destroyed later.
static PENDING_DESTROY: AtomicBool = AtomicBool::new(false);

/// Largest IPA size the host supports, in bits.
pub(crate) fn max_ipa_bits() -> u32 {
    static BITS: OnceLock<u32> = OnceLock::new();
    *BITS.get_or_init(|| {
        let mut bits = 0;
        // SAFETY: writes one u32.
        if unsafe { hv_vm_config_get_max_ipa_size(&mut bits) } != HV_SUCCESS {
            bits = 36;
        }
        bits
    })
}

/// Maximum number of vCPUs per VM.
pub(crate) fn max_vcpus() -> usize {
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        let mut n = 0u32;
        // SAFETY: writes one u32. Only valid once a VM exists; fall back to the documented value.
        if unsafe { hv_vm_get_max_vcpu_count(&mut n) } != HV_SUCCESS || n == 0 {
            n = 64;
        }
        n as usize
    })
}

#[derive(Debug)]
struct IoEvent {
    addr: u64,
    /// Access size that matches; 0 matches any size.
    len: u32,
    datamatch: Option<u64>,
    fd: EventFd,
    id: (u64, u64),
}

#[derive(Debug, Clone, Copy)]
enum Route {
    /// Raise SPI `intid`.
    Spi(u32),
    /// Write `data` (the SPI) to the MSI frame doorbell at `address`.
    Msi { address: u64, data: u32 },
}

/// A guest memory slot.
#[derive(Debug)]
struct Slot {
    ipa: u64,
    size: u64,
    /// The host address of the slot's memory.
    host: u64,
    readonly: bool,
    /// Dirty page bitmap (one bit per host page) when the slot was registered
    /// with `KVM_MEM_LOG_DIRTY_PAGES`. Pages are mapped read-only until the
    /// guest writes them; the write fault marks the page and makes it writable.
    dirty: Option<Vec<std::sync::atomic::AtomicU64>>,
}

const RX: hv_memory_flags_t = HV_MEMORY_READ | HV_MEMORY_EXEC;
const RWX: hv_memory_flags_t = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;

/// Part of a slot unmapped from stage 2 while the libc replaces the pages
/// behind it (see [`guest_replace`]).
#[derive(Debug, Clone, Copy)]
struct Window {
    ipa: u64,
    size: u64,
    host: u64,
}

/// Guest memory: the slots, and the parts of them being replaced.
#[derive(Debug, Default)]
struct Memory {
    slots: HashMap<u32, Slot>,
    replacing: Vec<Window>,
}

impl Memory {
    fn slot_at(&self, ipa: u64) -> Option<&Slot> {
        self.slots
            .values()
            .find(|s| ipa >= s.ipa && ipa < s.ipa + s.size)
    }

    fn replacing(&self, ipa: u64) -> bool {
        self.replacing
            .iter()
            .any(|w| ipa >= w.ipa && ipa < w.ipa + w.size)
    }
}

fn host_page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

/// An irqfd: the VM's handle of the eventfd, and the consumer that raises
/// its interrupt when a thread of this process writes it.
#[derive(Debug)]
struct IrqFd {
    fd: EventFd,
    gsi: u32,
    consumer: ConsumerId,
}

impl Drop for IrqFd {
    /// The VM is going away: a consumer left behind (one running now, which
    /// may be what drops the VM) finds no VM and leaves the write counted.
    fn drop(&mut self) {
        self.fd.try_remove_consumer(self.consumer);
    }
}

#[derive(Debug, Default)]
struct IrqState {
    /// Explicit routes from `set_gsi_routing`; GSIs without one map to `gsi + 32`.
    routes: Option<HashMap<u32, Route>>,
    /// Registered irqfds, keyed by the descriptor of our clone (the epoll data).
    irqfds: HashMap<RawFd, IrqFd>,
}

#[derive(Debug, Default)]
pub(crate) struct GicConfig {
    pub dist: Option<u64>,
    pub redist: Option<u64>,
    /// GICv2m-style MSI frame (see `device::ADDR_TYPE_MSI_FRAME`).
    pub msi_frame: Option<u64>,
    /// `KVM_DEV_ARM_VGIC_GRP_NR_IRQS`: SGIs, PPIs and the wired SPIs. The SPIs
    /// above them are the MSI frame's.
    pub nr_irqs: Option<u32>,
    pub created: bool,
}

#[derive(Debug)]
pub(crate) struct VmInner {
    memory: Mutex<Memory>,
    /// Signalled when a [`Window`] closes (its pages are mapped again).
    remapped: Condvar,
    ioevents: RwLock<Vec<IoEvent>>,
    irq: Mutex<IrqState>,
    /// Shared with the irqfd thread, which waits on it without holding the VM.
    epoll: Arc<Epoll>,
    /// Wakes the irqfd thread when it has to exit.
    stop_evt: EventFd,
    stop: AtomicBool,
    /// The `VmFd` descriptor (see [`Handle::token`]).
    handle: (RawFd, (u64, u64)),
    torn_down: AtomicBool,
    pub(crate) vcpus: Mutex<Vec<Arc<VcpuShared>>>,
    pub(crate) gic: Mutex<GicConfig>,
    /// What the virtual timer thread waits on ([`vtimer_thread`]).
    vtimer_waiter: Arc<Waiter>,
    /// Tests: the rounds the virtual timer thread made.
    #[cfg(test)]
    vtimer_rounds: AtomicU64,
    /// Value of `mach_absolute_time()` at which the guest counter reads 0.
    /// One for the VM, as KVM's: writing a vCPU's `TIMER_CNT` sets it for all.
    pub(crate) vtimer_offset: AtomicU64,
    /// Incremented when `vtimer_offset` changes; vCPUs apply the new offset
    /// before they next run.
    pub(crate) vtimer_gen: AtomicU64,
    /// The PSCI version the guest is given (`KVM_REG_ARM_PSCI_VERSION`):
    /// [`regs::PSCI_VERSION_1_1`], or 1.0 or 0.2 once a snapshot of a VM
    /// given that one is restored. One for the VM, as KVM's.
    pub(crate) psci_version: AtomicU64,
    /// The bitmaps of the services the guest may call, indexed by
    /// [`regs::Bmap`] (`KVM_REG_ARM_STD_BMAP` and the two beside it): every
    /// service in a new VM. One set for the VM, as KVM's
    /// (`kvm->arch.smccc_feat`); the lock is also what makes a write and the
    /// first run exclude each other, as `kvm->lock` does.
    pub(crate) smccc_features: Mutex<[u64; 3]>,
    /// Whether a vCPU of the VM has run (`KVM_ARCH_FLAG_HAS_RAN_ONCE`):
    /// from then on the bitmaps cannot change. Written under
    /// `smccc_features`' lock.
    pub(crate) ran_once: AtomicBool,
    /// vCPUs created with `create_vcpu` whose Hypervisor.framework vCPU does
    /// not exist yet (it is created on the first `run()`).
    uncreated: AtomicUsize,
    /// SPIs raised while the vCPU they are routed to did not exist: made
    /// pending when it does (see [`VmInner::raise_spi`]).
    deferred_spis: Mutex<Vec<u32>>,
    /// SPIs restored active while the vCPU they are routed to did not exist:
    /// made active when it does (see [`VmInner::activate_spi`]).
    deferred_active: Mutex<Vec<u32>>,
    /// Register values of a freshly created Hypervisor.framework vCPU, read
    /// once from a scratch vCPU (see `VcpuFd::get_one_reg`).
    pub(crate) reset_regs: OnceLock<std::result::Result<HashMap<u64, Vec<u8>>, i32>>,
    /// ID registers user space wrote (`super::idregs`): the VM's, given to
    /// each vCPU when it is created.
    pub(crate) id_regs: Mutex<HashMap<u16, u64>>,
    /// Set when the first vCPU is created: the ID registers can no longer
    /// change, as on KVM once the VM has run.
    pub(crate) id_locked: AtomicBool,
    /// Whether the vCPUs have pointer authentication (`KVM_ARM_VCPU_INIT`'s
    /// PTRAUTH features): one choice for the VM, set by the first vCPU's
    /// init, as KVM requires every vCPU to have the same features.
    pub(crate) ptrauth: Mutex<Option<bool>>,
    /// GIC registers of a freshly created vCPU, read from the first one.
    pub(crate) gic_cpu_reset: OnceLock<HashMap<super::gic::CpuReg, u64>>,
    /// The PV time kicker, where PV time is offered (`super::pvtime::Kicker`).
    pub(crate) pvtime_kicker: OnceLock<Arc<super::pvtime::Kicker>>,
}

/// Identity of an eventfd that survives `dup` (the inode of its pipe).
pub(crate) fn fd_identity(fd: RawFd) -> Result<(u64, u64)> {
    // SAFETY: `stat` is plain data written by fstat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid output buffer; fstat reports bad descriptors.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(super::Error::last());
    }
    Ok((st.st_dev as u64, st.st_ino))
}

/// `libc::wick_uffd` stage-2 hook: pages of a userfaultfd became present (the
/// guest may access them, with the slot's permissions) or missing (guest
/// accesses fault, and are resolved with `wick_uffd::fault`).
fn uffd_stage2(host: u64, len: u64, present: bool) {
    let Some(vm) = CURRENT.lock().unwrap().upgrade() else {
        return;
    };
    let memory = vm.memory.lock().unwrap();
    let page = host_page_size();
    for slot in memory.slots.values() {
        let start = host.max(slot.host);
        let end = (host + len).min(slot.host + slot.size);
        let mut addr = start - (start - slot.host) % page;
        while addr < end {
            let ipa = slot.ipa + (addr - slot.host);
            // A page being replaced is mapped again with its permissions
            // when the replacement ends (`Slot::map`).
            if !memory.replacing(ipa) {
                let flags = if present { slot.flags(ipa) } else { 0 };
                // SAFETY: changes the permissions of one page of a slot we mapped.
                unsafe { hv_vm_protect(ipa, page as usize, flags) };
            }
            addr += page;
        }
    }
}

/// `libc::wick_guest` replace hook: the pages behind the host range
/// `[host, host + len)` are about to be replaced (`before`: a Linux
/// `MADV_DONTNEED`, a `MAP_FIXED` mapping), or have been.
///
/// Hypervisor.framework maps the physical pages behind a host range when
/// `hv_vm_map` is called, not the host address (measured: after a `MAP_FIXED`
/// mapping over guest memory the guest kept the old pages, the host read 0
/// where the guest had written; `test_madvise_dontneed_replaces_guest_pages`).
/// So what the range holds of guest memory is unmapped before the change
/// and mapped again after, with the permissions its pages had. A vCPU that
/// faults on it in between waits for the new pages
/// ([`VmInner::wait_mapped`]), as a KVM guest's access waits while the host
/// zaps the page. Returns, before, whether any guest memory was unmapped,
/// and after, whether all of it was mapped again.
fn guest_replace(host: u64, len: u64, before: bool) -> bool {
    let Some(vm) = CURRENT.lock().unwrap().upgrade() else {
        return false;
    };
    let end = host + len;
    let mut memory = vm.memory.lock().unwrap();
    if before {
        // A replacement of any of the same pages (another thread's
        // discard) ends first.
        while memory
            .replacing
            .iter()
            .any(|w| w.host < end && host < w.host + w.size)
        {
            memory = vm.remapped.wait(memory).unwrap();
        }
        let windows: Vec<Window> = memory
            .slots
            .values()
            .filter_map(|slot| {
                let start = host.max(slot.host);
                let stop = end.min(slot.host + slot.size);
                (start < stop).then(|| Window {
                    ipa: slot.ipa + (start - slot.host),
                    size: stop - start,
                    host: start,
                })
            })
            .collect();
        for w in &windows {
            // SAFETY: unmapping part of a slot we mapped.
            let ret = unsafe { hv_vm_unmap(w.ipa, w.size as usize) };
            if ret != HV_SUCCESS {
                // The guest would keep the old pages while the host uses
                // the new ones: silent corruption.
                eprintln!(
                    "wick: guest memory at {:#x}+{:#x} cannot be unmapped while its pages are \
                     replaced (hv_vm_unmap: {ret:#x})",
                    w.ipa, w.size
                );
                std::process::abort();
            }
        }
        let any = !windows.is_empty();
        memory.replacing.extend(windows);
        any
    } else {
        let (mine, rest): (Vec<Window>, Vec<Window>) = memory
            .replacing
            .drain(..)
            .partition(|w| w.host >= host && w.host + w.size <= end);
        memory.replacing = rest;
        let mut ok = true;
        for w in mine {
            // The slot is still there: `set_user_memory_region` waits for
            // open windows.
            if let Some(slot) = memory.slot_at(w.ipa) {
                // SAFETY: the slot's host range, valid while the slot exists.
                ok &= unsafe { slot.map(w.host, w.ipa, w.size) }.is_ok();
            }
        }
        vm.remapped.notify_all();
        ok
    }
}

impl Slot {
    /// Maps `[host, host + size)`, part of the slot's memory, at `ipa` with
    /// the permissions its pages have: the slot's, read-only until written
    /// for a dirty-tracked page not written yet, none for a page a
    /// userfaultfd has not filled.
    ///
    /// # Safety
    /// The host range must stay mapped while the slot exists.
    unsafe fn map(&self, host: u64, ipa: u64, size: u64) -> Result<()> {
        let base = if self.readonly || self.dirty.is_some() { RX } else { RWX };
        // SAFETY: the caller's contract.
        check(unsafe { hv_vm_map(host as *mut _, ipa, size as usize, base) })?;
        let page = host_page_size();
        // Runs of pages whose permissions differ from the slot's.
        let mut run: Option<(u64, hv_memory_flags_t)> = None;
        let mut off = 0;
        while off <= size {
            let flags = if off == size {
                base
            } else if libc::wick_uffd::is_missing(host + off) {
                0
            } else {
                self.flags(ipa + off)
            };
            if run.is_some_and(|(_, f)| f != flags) || (run.is_none() && flags != base) {
                if let Some((start, f)) = run.take() {
                    // SAFETY: changes the permissions of pages mapped above.
                    check(unsafe { hv_vm_protect(ipa + start, (off - start) as usize, f) })?;
                }
                if flags != base {
                    run = Some((off, flags));
                }
            }
            off += page;
        }
        Ok(())
    }

    /// The stage-2 permissions page `ipa` should have while present.
    fn flags(&self, ipa: u64) -> hv_memory_flags_t {
        if self.readonly {
            return RX;
        }
        match &self.dirty {
            Some(bitmap) => {
                let index = (ipa - self.ipa) / host_page_size();
                if bitmap[(index / 64) as usize].load(Ordering::Acquire) & (1 << (index % 64)) != 0
                {
                    RWX
                } else {
                    RX
                }
            }
            None => RWX,
        }
    }
}

impl VmInner {
    /// The host address of guest RAM at `ipa`.
    pub(crate) fn ram_host_addr(&self, ipa: u64) -> Option<u64> {
        let memory = self.memory.lock().unwrap();
        memory.slot_at(ipa).map(|s| s.host + (ipa - s.ipa))
    }

    /// The memory, once the pages at `ipa` are not being replaced.
    fn memory_mapped(&self, ipa: u64) -> MutexGuard<'_, Memory> {
        let mut memory = self.memory.lock().unwrap();
        while memory.replacing(ipa) {
            memory = self.remapped.wait(memory).unwrap();
        }
        memory
    }

    /// The memory, once no pages are being replaced.
    fn memory_settled(&self) -> MutexGuard<'_, Memory> {
        let mut memory = self.memory.lock().unwrap();
        while !memory.replacing.is_empty() {
            memory = self.remapped.wait(memory).unwrap();
        }
        memory
    }

    /// A guest fault on pages being replaced (`guest_replace`): waits until
    /// the new pages are mapped. Returns whether it waited (the access is
    /// then retried, and finds the new pages).
    pub(crate) fn wait_mapped(&self, ipa: u64) -> bool {
        if !self.memory.lock().unwrap().replacing(ipa) {
            return false;
        }
        drop(self.memory_mapped(ipa));
        true
    }

    /// A guest fault on RAM whose page allows the access (a permission change
    /// raced with the fault): restores the page's permissions. Returns false
    /// if `ipa` is not RAM or the access is not allowed (e.g. a write to a
    /// read-only slot, which is MMIO as on KVM).
    pub(crate) fn stale_fault(&self, ipa: u64, write: bool) -> bool {
        let memory = self.memory_mapped(ipa);
        let Some(slot) = memory.slot_at(ipa) else {
            return false;
        };
        let page = host_page_size();
        let ipa = ipa - (ipa - slot.ipa) % page;
        if libc::wick_uffd::is_missing(slot.host + (ipa - slot.ipa)) {
            return false;
        }
        let flags = slot.flags(ipa);
        if write && flags & HV_MEMORY_WRITE == 0 {
            return false;
        }
        // SAFETY: restores the permissions of one page of a slot we mapped.
        unsafe { hv_vm_protect(ipa, page as usize, flags) == HV_SUCCESS }
    }

    /// Handles a guest write fault on dirty-tracked memory: marks the page
    /// dirty and makes it writable. Returns false if `ipa` is not tracked memory.
    pub(crate) fn dirty_fault(&self, ipa: u64) -> bool {
        let memory = self.memory_mapped(ipa);
        let page = host_page_size();
        for slot in memory.slots.values() {
            let Some(bitmap) = &slot.dirty else { continue };
            if ipa < slot.ipa || ipa >= slot.ipa + slot.size {
                continue;
            }
            let index = (ipa - slot.ipa) / page;
            if libc::wick_uffd::is_missing(slot.host + index * page) {
                // Not filled yet: the userfaultfd resolves the fault first.
                return false;
            }
            bitmap[(index / 64) as usize].fetch_or(1 << (index % 64), Ordering::AcqRel);
            // SAFETY: re-protecting one page of a range we mapped.
            return unsafe { hv_vm_protect(slot.ipa + index * page, page as usize, RWX) }
                == HV_SUCCESS;
        }
        false
    }

    /// Writes guest RAM at `ipa` from the hypervisor's side, as KVM's
    /// kvm_write_guest/kvm_put_guest: `f` gets the host address of `len`
    /// bytes (within one page) while the memory lock keeps them mapped. A
    /// page a userfaultfd has not filled is waited for (KVM's copy_to_user
    /// faults it in), and a dirty-tracked page is marked dirty
    /// (mark_page_dirty). `None` if `ipa` is not writable RAM (a read-only
    /// slot: KVM_HVA_ERR_RO_BAD).
    pub(crate) fn write_guest<R>(&self, ipa: u64, len: usize, f: impl FnOnce(*mut u8) -> R) -> Option<R> {
        let page = host_page_size();
        debug_assert!(ipa % page + len as u64 <= page);
        loop {
            let memory = self.memory_mapped(ipa);
            let slot = memory.slot_at(ipa).filter(|s| !s.readonly)?;
            let host = slot.host + (ipa - slot.ipa);
            if libc::wick_uffd::is_missing(host) {
                drop(memory);
                libc::wick_uffd::fault(host, true);
                continue;
            }
            let r = f(host as *mut u8);
            if let Some(bitmap) = &slot.dirty {
                let index = (ipa - slot.ipa) / page;
                bitmap[(index / 64) as usize].fetch_or(1 << (index % 64), Ordering::AcqRel);
            }
            return Some(r);
        }
    }

    /// Signals the eventfd registered for an MMIO write, if any. Returns true if one matched.
    pub(crate) fn ioevent(&self, addr: u64, data: &[u8]) -> bool {
        let events = self.ioevents.read().unwrap();
        if events.is_empty() {
            return false;
        }
        let mut buf = [0u8; 8];
        buf[..data.len()].copy_from_slice(data);
        let value = u64::from_le_bytes(buf);
        for ev in events.iter() {
            if ev.addr != addr || (ev.len != 0 && ev.len as usize != data.len()) {
                continue;
            }
            if ev.datamatch.is_some_and(|d| d != value) {
                continue;
            }
            let _ = ev.fd.write(1);
            return true;
        }
        false
    }

    fn route(&self, gsi: u32) -> Option<Route> {
        let irq = self.irq.lock().unwrap();
        match &irq.routes {
            Some(routes) => routes.get(&gsi).copied(),
            None => Some(Route::Spi(gsi + SPI_BASE)),
        }
    }

    /// Raises the interrupt behind `gsi` and wakes waiting vCPUs.
    pub(crate) fn inject(&self, gsi: u32) {
        // Errors are not reported, as KVM's irqfd does not report them.
        let _ = match self.route(gsi) {
            Some(Route::Spi(intid)) => self.raise_spi(intid, || {
                // A pulse, like KVM's irqfd: an edge for edge-triggered SPIs, and a
                // level that is dropped again for level-triggered ones.
                // SAFETY: plain calls; invalid ids are reported as errors.
                super::interrupting(|| unsafe {
                    hv_gic_set_spi(intid, true);
                    hv_gic_set_spi(intid, false);
                });
                HV_SUCCESS
            }),
            Some(Route::Msi { address, data }) => self.raise_spi(data, || {
                // SAFETY: plain call; a bad address or SPI is reported as an error.
                super::interrupting(|| unsafe { hv_gic_send_msi(address, data) })
            }),
            None => HV_SUCCESS,
        };
        for vcpu in self.vcpus.lock().unwrap().iter() {
            vcpu.wake();
        }
    }

    /// Raises SPI `intid` with `raise`, as KVM would deliver it.
    ///
    /// Hypervisor.framework routes an SPI to the vCPU its `GICD_IROUTER`
    /// names only once that vCPU exists, and drops one raised before: on a
    /// snapshot restore the devices are kicked, and their interrupts raised,
    /// before the vCPUs first run. Such an SPI is recorded instead and made
    /// pending when its vCPU is created ([`Self::vcpu_created`]), where KVM
    /// keeps it pending in the distributor.
    pub(crate) fn raise_spi(&self, intid: u32, raise: impl FnOnce() -> hv_return_t) -> hv_return_t {
        if self.uncreated.load(Ordering::Acquire) == 0 {
            return raise();
        }
        let mut deferred = self.deferred_spis.lock().unwrap();
        if self.spi_target_exists(intid) {
            return raise();
        }
        if !deferred.contains(&intid) {
            deferred.push(intid);
        }
        HV_SUCCESS
    }

    /// Whether the vCPU SPI `intid` is routed to exists. An id the GIC does
    /// not have counts as routed, so that raising it reports the error.
    fn spi_target_exists(&self, intid: u32) -> bool {
        const IRM: u64 = 1 << 31;
        // `intid` can be any value a guest wrote as MSI data.
        let Some(reg) = intid.checked_mul(8).and_then(|o| o.checked_add(0x6000)) else {
            return true;
        };
        let mut route = 0;
        // SAFETY: plain call with a valid output.
        if unsafe { hv_gic_get_distributor_reg(reg, &mut route) } != HV_SUCCESS {
            return true;
        }
        let affinity = super::gic::packed_affinity(route);
        self.vcpus.lock().unwrap().iter().any(|v| {
            v.is_created()
                && (route & IRM != 0 || super::gic::packed_affinity(v.mpidr) == affinity)
        })
    }

    /// Clears SPI `intid` if it is waiting for its vCPU (`GICD_ICPENDR`).
    pub(crate) fn clear_deferred_spi(&self, intid: u32) {
        self.deferred_spis.lock().unwrap().retain(|&i| i != intid);
    }

    /// Makes SPI `intid` active with `activate` (`GICD_ISACTIVER`), as KVM
    /// keeps it.
    ///
    /// Hypervisor.framework dereferences the vCPU an SPI's `GICD_IROUTER`
    /// names when the SPI is made active, and crashes the process (a NULL
    /// object) if that vCPU does not exist yet: a snapshot taken while the
    /// guest handled an SPI restores it active before the vCPUs first run.
    /// Such an SPI is recorded instead and made active when its vCPU is
    /// created ([`Self::vcpu_created`]).
    pub(crate) fn activate_spi(&self, intid: u32, activate: impl FnOnce() -> hv_return_t) -> hv_return_t {
        if self.uncreated.load(Ordering::Acquire) == 0 {
            return activate();
        }
        // Under the pending list's lock, as vcpu_created applies both.
        let _deferred = self.deferred_spis.lock().unwrap();
        if self.spi_target_exists(intid) {
            return activate();
        }
        let mut active = self.deferred_active.lock().unwrap();
        if !active.contains(&intid) {
            active.push(intid);
        }
        HV_SUCCESS
    }

    /// Clears SPI `intid` if it waits for its vCPU to be made active
    /// (`GICD_ICACTIVER`).
    pub(crate) fn clear_deferred_active(&self, intid: u32) {
        self.deferred_active.lock().unwrap().retain(|&i| i != intid);
    }

    /// The SPIs of the 32 starting at `first` that wait for their vCPU to be
    /// made pending (`active` false) or active, as a register's bits: KVM
    /// reports them in `GICD_ISPENDR` and `GICD_ISACTIVER`.
    pub(crate) fn deferred_bits(&self, first: u32, active: bool) -> u32 {
        let list = if active {
            self.deferred_active.lock().unwrap()
        } else {
            self.deferred_spis.lock().unwrap()
        };
        list.iter()
            .filter(|&&i| (first..first + 32).contains(&i))
            .fold(0, |bits, &i| bits | 1 << (i - first))
    }

    /// A vCPU's Hypervisor.framework vCPU now exists, with the SPI routes that
    /// name it written again: makes pending the SPIs that waited for it.
    pub(crate) fn vcpu_created(&self) {
        let mut deferred = self.deferred_spis.lock().unwrap();
        self.uncreated.fetch_sub(1, Ordering::AcqRel);
        deferred.retain(|&intid| {
            if !self.spi_target_exists(intid) {
                return true;
            }
            // SAFETY: plain call; GICD_ISPENDR<n> is write-1-to-set.
            super::interrupting(|| unsafe {
                hv_gic_set_distributor_reg(0x200 + 4 * (intid / 32), 1 << (intid % 32))
            });
            false
        });
        self.deferred_active.lock().unwrap().retain(|&intid| {
            if !self.spi_target_exists(intid) {
                return true;
            }
            // SAFETY: plain call; GICD_ISACTIVER<n> is write-1-to-set.
            super::interrupting(|| unsafe {
                hv_gic_set_distributor_reg(0x300 + 4 * (intid / 32), 1 << (intid % 32))
            });
            false
        });
        drop(deferred);
        for vcpu in self.vcpus.lock().unwrap().iter() {
            vcpu.wake();
        }
    }

    /// Sets the guest counter of every vCPU to read `count` now.
    pub(crate) fn set_virtual_count(&self, count: u64) {
        // SAFETY: plain call.
        let offset = unsafe { mach_absolute_time() }.wrapping_sub(count);
        self.vtimer_offset.store(offset, Ordering::Release);
        self.vtimer_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Waits for irqfds and injects their interrupts: the writes made through
    /// a handle of another process (a vhost-user backend's), which the
    /// consumer of [`VmFd::register_irqfd`] does not see. The thread holds
    /// the VM only while it handles events, so dropping the `VmFd` (which
    /// stops and joins it) releases the VM at once.
    fn irqfd_thread(epoll: Arc<Epoll>, vm: Weak<VmInner>) {
        let mut events = vec![EpollEvent::default(); 64];
        loop {
            let n = match epoll.wait(-1, &mut events) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            let Some(vm) = vm.upgrade() else { return };
            if vm.stop.load(Ordering::Acquire) {
                return;
            }
            for ev in &events[..n] {
                let fd = ev.data() as RawFd;
                if fd == vm.stop_evt.as_raw_fd() {
                    return;
                }
                let gsi = {
                    let irq = vm.irq.lock().unwrap();
                    match irq.irqfds.get(&fd) {
                        // Consume the counter; the value does not matter.
                        Some(irqfd) => irqfd.fd.read().ok().map(|_| irqfd.gsi),
                        None => None,
                    }
                };
                if let Some(gsi) = gsi {
                    vm.inject(gsi);
                }
            }
        }
    }
}

impl VmInner {
    /// Stops the VM's threads, unmaps its memory and destroys the
    /// Hypervisor.framework VM. If vCPUs of it still exist, the destruction
    /// is left to the next `VmFd::create`.
    fn teardown(&self) {
        if self.torn_down.swap(true, Ordering::AcqRel) {
            return;
        }
        self.stop.store(true, Ordering::Release);
        let _ = self.stop_evt.write(1);
        self.vtimer_waiter.wake();
        if let Some(kicker) = self.pvtime_kicker.get() {
            kicker.stop();
        }
        for (_, slot) in self.memory.lock().unwrap().slots.drain() {
            // SAFETY: unmapping a range we mapped.
            unsafe { hv_vm_unmap(slot.ipa, slot.size as usize) };
        }
        // SAFETY: destroys the process VM; fails if vCPUs are still alive.
        if unsafe { hv_vm_destroy() } != HV_SUCCESS {
            PENDING_DESTROY.store(true, Ordering::Release);
        }
    }

    /// Whether KVM would have released this VM: its descriptor and those of
    /// its vCPUs are closed (a `VmFd` leaked after closing its descriptor).
    fn released(&self) -> bool {
        !super::is_open(self.handle)
            && self
                .vcpus
                .lock()
                .unwrap()
                .iter()
                .all(|v| !super::is_open(v.handle))
    }
}

impl Drop for VmInner {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Wrapper over a VM.
#[derive(Debug)]
pub struct VmFd {
    pub(crate) inner: Arc<VmInner>,
    /// The irqfd and virtual timer threads, joined on drop.
    threads: Vec<thread::JoinHandle<()>>,
    fd: Handle,
}

impl Drop for VmFd {
    /// If this is the last reference (no vCPU handle keeps the VM alive, as
    /// on KVM), stops the VM's threads and joins them, so that the VM is
    /// destroyed now and a new one can be created right away.
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) == 1 {
            self.inner.stop.store(true, Ordering::Release);
            let _ = self.inner.stop_evt.write(1);
            self.inner.vtimer_waiter.wake();
            if let Some(kicker) = self.inner.pvtime_kicker.get() {
                kicker.stop();
            }
            for handle in self.threads.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

impl VmFd {
    pub(crate) fn create() -> Result<VmFd> {
        let mut current = CURRENT.lock().unwrap();
        if let Some(old) = current.upgrade() {
            // Hypervisor.framework allows one VM per process. A VM whose
            // descriptors are all closed is gone for KVM, so release it.
            if !old.released() {
                return err(libc::EBUSY);
            }
            old.teardown();
            *current = Weak::new();
        }
        if PENDING_DESTROY.load(Ordering::Acquire) {
            // SAFETY: destroys the previous VM, whose vCPU threads have exited.
            if unsafe { hv_vm_destroy() } != HV_SUCCESS {
                return err(libc::EBUSY);
            }
            PENDING_DESTROY.store(false, Ordering::Release);
        }
        let handle = Handle::new()?;
        // SAFETY: the config object is created, used and released here.
        unsafe {
            let config = hv_vm_config_create();
            if config.is_null() {
                return err(libc::ENOMEM);
            }
            let ret = hv_vm_config_set_ipa_size(config, max_ipa_bits());
            let ret = if ret == HV_SUCCESS {
                hv_vm_create(config)
            } else {
                ret
            };
            os_release(config);
            check(ret)?;
        }
        let epoll = Arc::new(Epoll::new().map_err(io_err)?);
        let stop_evt = EventFd::new(EFD_NONBLOCK).map_err(io_err)?;
        epoll
            .ctl(
                ControlOperation::Add,
                stop_evt.as_raw_fd(),
                EpollEvent::new(EventSet::IN, stop_evt.as_raw_fd() as u64),
            )
            .map_err(io_err)?;
        let inner = Arc::new(VmInner {
            memory: Mutex::new(Memory::default()),
            remapped: Condvar::new(),
            ioevents: RwLock::new(Vec::new()),
            irq: Mutex::new(IrqState::default()),
            epoll: epoll.clone(),
            stop_evt,
            stop: AtomicBool::new(false),
            handle: handle.token(),
            torn_down: AtomicBool::new(false),
            vcpus: Mutex::new(Vec::new()),
            gic: Mutex::new(GicConfig::default()),
            vtimer_waiter: Arc::new(Waiter::new().map_err(io_err)?),
            #[cfg(test)]
            vtimer_rounds: AtomicU64::new(0),
            // SAFETY: plain call.
            vtimer_offset: AtomicU64::new(unsafe { mach_absolute_time() }),
            vtimer_gen: AtomicU64::new(0),
            psci_version: AtomicU64::new(super::regs::PSCI_VERSION_1_1),
            smccc_features: Mutex::new(super::regs::SMCCC_FEATURES),
            ran_once: AtomicBool::new(false),
            uncreated: AtomicUsize::new(0),
            deferred_spis: Mutex::new(Vec::new()),
            deferred_active: Mutex::new(Vec::new()),
            reset_regs: OnceLock::new(),
            id_regs: Mutex::new(HashMap::new()),
            id_locked: AtomicBool::new(false),
            ptrauth: Mutex::new(None),
            gic_cpu_reset: OnceLock::new(),
            pvtime_kicker: OnceLock::new(),
        });
        libc::wick_guest::set_hooks(libc::wick_guest::Hooks {
            stage2: uffd_stage2,
            replace: guest_replace,
        });
        let mut vm = VmFd {
            inner,
            threads: Vec::new(),
            fd: handle,
        };
        let weak = Arc::downgrade(&vm.inner);
        vm.threads.push(
            thread::Builder::new()
                .name("wick_hvf_irqfd".into())
                .spawn(move || VmInner::irqfd_thread(epoll, weak))
                .map_err(io_err)?,
        );
        let weak = Arc::downgrade(&vm.inner);
        let waiter = vm.inner.vtimer_waiter.clone();
        vm.threads.push(
            thread::Builder::new()
                .name("wick_hvf_vtimer".into())
                .spawn(move || vtimer_thread(&waiter, weak))
                .map_err(io_err)?,
        );
        if let Some((kicker, handle)) = super::pvtime::Kicker::start().map_err(io_err)? {
            let _ = vm.inner.pvtime_kicker.set(kicker);
            vm.threads.push(handle);
        }
        *current = Arc::downgrade(&vm.inner);
        Ok(vm)
    }

    /// Maps or unmaps guest memory. `memory_size == 0` removes the slot.
    ///
    /// # Safety
    /// `userspace_addr` must point to `memory_size` bytes that stay mapped while the slot exists.
    pub unsafe fn set_user_memory_region(&self, region: kvm_userspace_memory_region) -> Result<()> {
        self.fd.check()?;
        if region.flags & !(KVM_MEM_READONLY | KVM_MEM_LOG_DIRTY_PAGES) != 0 {
            return err(libc::EINVAL);
        }
        let mut memory = self.inner.memory_settled();
        if let Some(slot) = memory.slots.remove(&region.slot) {
            // SAFETY: unmapping a range we mapped.
            check(unsafe { hv_vm_unmap(slot.ipa, slot.size as usize) })?;
        }
        if region.memory_size == 0 {
            return Ok(());
        }
        let readonly = region.flags & KVM_MEM_READONLY != 0;
        // Dirty tracking only concerns writable memory (writes to read-only
        // slots exit as MMIO, as on KVM).
        let track = region.flags & KVM_MEM_LOG_DIRTY_PAGES != 0 && !readonly;
        let dirty = track.then(|| {
            let pages = region.memory_size.div_ceil(host_page_size());
            (0..pages.div_ceil(64))
                .map(|_| std::sync::atomic::AtomicU64::new(0))
                .collect()
        });
        let slot = Slot {
            ipa: region.guest_phys_addr,
            size: region.memory_size,
            host: region.userspace_addr,
            readonly,
            dirty,
        };
        // SAFETY: the caller guarantees the host range is valid for the slot's lifetime.
        unsafe { slot.map(region.userspace_addr, region.guest_phys_addr, region.memory_size) }?;
        memory.slots.insert(region.slot, slot);
        Ok(())
    }

    /// Registers an eventfd signalled on guest MMIO writes to `addr`.
    pub fn register_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        self.fd.check()?;
        let IoEventAddress::Mmio(addr) = *addr else {
            return err(libc::EINVAL);
        };
        let len = std::mem::size_of::<T>() as u32;
        let ev = IoEvent {
            addr,
            len,
            datamatch: (len > 0).then(|| datamatch.into()),
            id: fd_identity(fd.as_raw_fd())?,
            fd: fd.try_clone().map_err(io_err)?,
        };
        let mut events = self.inner.ioevents.write().unwrap();
        if events
            .iter()
            .any(|e| e.addr == ev.addr && e.len == ev.len && e.datamatch == ev.datamatch)
        {
            return err(libc::EEXIST);
        }
        events.push(ev);
        Ok(())
    }

    /// Removes an eventfd registered with [`Self::register_ioevent`].
    pub fn unregister_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        self.fd.check()?;
        let IoEventAddress::Mmio(addr) = *addr else {
            return err(libc::EINVAL);
        };
        let len = std::mem::size_of::<T>() as u32;
        let datamatch = (len > 0).then(|| datamatch.into());
        let id = fd_identity(fd.as_raw_fd())?;
        let mut events = self.inner.ioevents.write().unwrap();
        let before = events.len();
        events.retain(|e| {
            !(e.addr == addr && e.len == len && e.datamatch == datamatch && e.id == id)
        });
        if events.len() == before {
            return err(libc::ENOENT);
        }
        Ok(())
    }

    /// Returns and clears the dirty page bitmap of `slot` (one bit per host
    /// page), like `KVM_GET_DIRTY_LOG`. Reported pages are write-protected
    /// again. Fails with `ENOENT` if the slot does not track dirty pages.
    pub fn get_dirty_log(&self, slot: u32, memory_size: usize) -> Result<Vec<u64>> {
        self.fd.check()?;
        // Pages being replaced are protected again when mapped again.
        let memory = self.inner.memory_settled();
        let Some(s) = memory.slots.get(&slot) else {
            return err(libc::ENOENT);
        };
        let Some(bitmap) = &s.dirty else {
            return err(libc::ENOENT);
        };
        let page = host_page_size();
        let words = (memory_size as u64).div_ceil(page).div_ceil(64) as usize;
        let mut out = vec![0u64; words];
        for (i, word) in bitmap.iter().enumerate().take(words) {
            let mut bits = word.load(Ordering::Acquire);
            if bits == 0 {
                continue;
            }
            // Protect first, then clear: a write in between faults again and is reported next time.
            let mut b = bits;
            while b != 0 {
                let j = b.trailing_zeros() as u64;
                b &= b - 1;
                let offset = (i as u64 * 64 + j) * page;
                // A page a userfaultfd no longer has (released since) stays inaccessible.
                let flags = if libc::wick_uffd::is_missing(s.host + offset) {
                    0
                } else {
                    RX
                };
                // SAFETY: write-protecting one page of a range we mapped.
                check(unsafe { hv_vm_protect(s.ipa + offset, page as usize, flags) })?;
            }
            bits = word.fetch_and(!bits, Ordering::AcqRel) & bits;
            out[i] = bits;
        }
        Ok(out)
    }

    /// Raises the interrupt routed to `gsi` whenever `fd` is written.
    ///
    /// As KVM's irqfd does, a write by a thread of this process raises it in
    /// that thread, before the write returns: KVM hooks the eventfd's wait
    /// queue and injects an SPI there (Linux v6.1 virt/kvm/eventfd.c
    /// `irqfd_wakeup`, arch/arm64/kvm/vgic/vgic-irqfd.c
    /// `kvm_arch_set_irq_inatomic`), and here the eventfd's consumer does
    /// ([`EventFd::add_consumer`]). Hypervisor.framework's `hv_gic_set_spi`
    /// and `hv_gic_send_msi` are the VM's, not a vCPU's: unlike the calls
    /// that take a vCPU, their documentation sets no thread they must be
    /// called from (hv_gic.h, macOS 27.2 SDK). A write through a handle of
    /// another process (a vhost-user backend's) is counted in the
    /// descriptor, where the irqfd thread finds it and raises it.
    ///
    /// The consumer takes the locks of [`VmInner::inject`]: `irq`, then
    /// `deferred_spis`, `vcpus` and a vCPU's `power`, each after the one
    /// before or alone, the order the rest of the backend takes them in. No
    /// thread writes an eventfd while holding one of them (the backend's
    /// own writes are the ioeventfds', under `ioevents`, and its stop
    /// event's, under none), and none of them is held while a consumer is
    /// removed ([`Self::unregister_irqfd`]), which waits for its runs.
    ///
    /// An eventfd already registered with this VM fails with `EBUSY`, as on
    /// KVM (`kvm_irqfd_assign`).
    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.fd.check()?;
        let id = fd_identity(fd.as_raw_fd())?;
        let clone = fd.try_clone().map_err(io_err)?;
        let raw = clone.as_raw_fd();
        let mut irq = self.inner.irq.lock().unwrap();
        if irq.irqfds.keys().any(|r| fd_identity(*r).ok() == Some(id)) {
            return err(libc::EBUSY);
        }
        let vm = Arc::downgrade(&self.inner);
        let consumer = fd.add_consumer(Box::new(move || match vm.upgrade() {
            Some(vm) if !vm.stop.load(Ordering::Acquire) => {
                vm.inject(gsi);
                true
            }
            _ => false,
        }));
        irq.irqfds.insert(raw, IrqFd { fd: clone, gsi, consumer });
        drop(irq);
        if let Err(e) = self.inner.epoll.ctl(
            ControlOperation::Add,
            raw,
            EpollEvent::new(EventSet::IN, raw as u64),
        ) {
            let removed = self.inner.irq.lock().unwrap().irqfds.remove(&raw);
            if let Some(irqfd) = removed {
                irqfd.fd.remove_consumer(irqfd.consumer);
            }
            return Err(io_err(e));
        }
        Ok(())
    }

    /// Removes an irqfd registered with [`Self::register_irqfd`]. Once it
    /// returns, a write of the eventfd raises nothing, as KVM's deassignment
    /// waits for the injections under way (`kvm_irqfd_deassign`).
    pub fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.fd.check()?;
        let id = fd_identity(fd.as_raw_fd())?;
        let mut irq = self.inner.irq.lock().unwrap();
        let found = irq
            .irqfds
            .iter()
            .find(|(raw, i)| i.gsi == gsi && fd_identity(**raw).ok() == Some(id))
            .map(|(raw, _)| *raw);
        let Some(raw) = found else {
            return err(libc::ENOENT);
        };
        let _ = self
            .inner
            .epoll
            .ctl(ControlOperation::Delete, raw, EpollEvent::default());
        let irqfd = irq.irqfds.remove(&raw).expect("found above");
        // Not under `irq`, which a running consumer may wait for.
        drop(irq);
        irqfd.fd.remove_consumer(irqfd.consumer);
        Ok(())
    }

    /// Sets the GSI routing table (replaces the default `gsi -> SPI gsi + 32`).
    pub fn set_gsi_routing(&self, irq_routing: &KvmIrqRouting) -> Result<()> {
        self.fd.check()?;
        let mut routes = HashMap::new();
        for entry in irq_routing.as_slice() {
            let route = match entry.type_ {
                KVM_IRQ_ROUTING_IRQCHIP => {
                    // SAFETY: the union member matches the entry type.
                    let pin = unsafe { entry.u.irqchip.pin };
                    Route::Spi(pin + SPI_BASE)
                }
                // Delivered through the GICv2m-style MSI frame: `data` is the
                // SPI. A device ID (`KVM_MSI_VALID_DEVID`) is only meaningful to
                // an ITS and is ignored.
                KVM_IRQ_ROUTING_MSI => {
                    // SAFETY: the union member matches the entry type.
                    let msi = unsafe { entry.u.msi };
                    Route::Msi {
                        address: u64::from(msi.address_hi) << 32 | u64::from(msi.address_lo),
                        data: msi.data,
                    }
                }
                _ => return err(libc::EINVAL),
            };
            routes.insert(entry.gsi, route);
        }
        self.inner.irq.lock().unwrap().routes = Some(routes);
        Ok(())
    }

    /// Sets the level of an SPI (`irq` is a KVM `irq_type | vcpu | number` value;
    /// only SPIs are supported).
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        self.fd.check()?;
        const KVM_ARM_IRQ_TYPE_SHIFT: u32 = 24;
        const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;
        if irq >> KVM_ARM_IRQ_TYPE_SHIFT & 0xf != KVM_ARM_IRQ_TYPE_SPI {
            return err(libc::EINVAL);
        }
        // SAFETY: plain call.
        check(super::interrupting(|| unsafe { hv_gic_set_spi(irq & 0xffff, active) }))
    }

    /// Sends an MSI through the MSI frame (`data` is the SPI). Returns 1, as
    /// KVM does when the interrupt is delivered.
    pub fn signal_msi(&self, msi: kvm_msi) -> Result<c_int> {
        self.fd.check()?;
        let address = u64::from(msi.address_hi) << 32 | u64::from(msi.address_lo);
        // SAFETY: plain call; a bad address or SPI is reported as an error.
        check(self.inner.raise_spi(msi.data, || {
            super::interrupting(|| unsafe { hv_gic_send_msi(address, msi.data) })
        }))?;
        Ok(1)
    }

    /// Creates vCPU `id`. The Hypervisor.framework vCPU itself is created on the
    /// first `run()`, on the calling thread.
    pub fn create_vcpu(&self, id: u64) -> Result<VcpuFd> {
        self.fd.check()?;
        if id as usize >= max_vcpus() {
            return err(libc::EINVAL);
        }
        let mut vcpus = self.inner.vcpus.lock().unwrap();
        if vcpus.iter().any(|v| v.index == id) {
            return err(libc::EEXIST);
        }
        let (fd, shared) = VcpuShared::new(id)?;
        vcpus.push(shared.clone());
        self.inner.uncreated.fetch_add(1, Ordering::AcqRel);
        Ok(VcpuFd::new(self.inner.clone(), shared, fd, true))
    }

    /// Returns another handle to the vCPU behind `fd` (a duplicate of a `VcpuFd` descriptor).
    ///
    /// # Safety
    /// `fd` must be a valid descriptor; ownership moves to the returned handle.
    pub unsafe fn create_vcpu_from_rawfd(&self, fd: RawFd) -> Result<VcpuFd> {
        self.fd.check()?;
        // SAFETY: the caller transfers ownership of `fd`.
        let file = Handle::from_file(unsafe { File::from_raw_fd(fd) })?;
        let id = file.id();
        let vcpus = self.inner.vcpus.lock().unwrap();
        let shared = vcpus.iter().find(|v| v.handle.1 == id).cloned();
        drop(vcpus);
        match shared {
            Some(shared) => Ok(VcpuFd::new(self.inner.clone(), shared, file, false)),
            None => err(libc::EBADF),
        }
    }

    /// Creates an in-kernel device. Supported: GICv3 (no ITS: `ENODEV`).
    #[allow(non_upper_case_globals)]
    pub fn create_device(&self, device: &mut kvm_create_device) -> Result<DeviceFd> {
        self.fd.check()?;
        let kind = match device.type_ {
            kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3 => DeviceKind::Gic,
            // Hypervisor.framework's GIC has no ITS.
            kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS => return err(libc::ENODEV),
            _ => return err(libc::ENODEV),
        };
        let dev = DeviceFd::new(kind, Arc::downgrade(&self.inner))?;
        device.fd = dev.as_raw_fd() as u32;
        Ok(dev)
    }

    /// Returns the preferred vCPU target (generic ARMv8).
    pub fn get_preferred_target(&self, kvi: &mut kvm_vcpu_init) -> Result<()> {
        self.fd.check()?;
        *kvi = kvm_vcpu_init::default();
        kvi.target = KVM_ARM_TARGET_GENERIC_V8;
        Ok(())
    }

    /// VM device attributes are not supported (`ENXIO`).
    pub fn set_device_attr(&self, _device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        err(libc::ENXIO)
    }

    /// VM device attributes are not supported (`ENXIO`).
    pub fn has_device_attr(&self, _device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        err(libc::ENXIO)
    }

    /// Size of the `kvm_run` structure.
    pub fn run_size(&self) -> usize {
        std::mem::size_of::<kvm_bindings::kvm_run>()
    }

    /// Checks a raw `KVM_CAP_*` value.
    pub fn check_extension_raw(&self, c: c_ulong) -> i32 {
        cap::supported(c)
    }

    /// Checks a raw `KVM_CAP_*` value.
    pub fn check_extension_int(&self, c: Cap) -> i32 {
        self.check_extension_raw(c as c_ulong)
    }

    /// Checks a capability.
    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) > 0
    }
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl VmInner {
    /// A vCPU masked its virtual timer: the virtual timer thread starts its
    /// rounds.
    pub(crate) fn vtimer_masked(&self) {
        self.vtimer_waiter.wake();
    }
}

/// How often the virtual timer thread pokes vCPUs whose timer is masked.
const VTIMER_ROUND: Duration = Duration::from_millis(1);

/// Forces an exit from vCPUs whose virtual timer is masked, so that the mask is
/// re-evaluated (the guest's EOI of the timer interrupt is not trapped): a
/// round every [`VTIMER_ROUND`] while a vCPU's timer is masked, on a timer
/// macOS does not coalesce ([`Waiter`]). While none is, it waits untimed for
/// a vCPU to mask one ([`VmInner::vtimer_masked`]) and makes no wakeup.
/// With Hypervisor.framework's GIC, which Firecracker always makes, the
/// framework delivers the timer itself and no `VTIMER_ACTIVATED` exit comes
/// (measured: none from a guest whose timer fired for 100 ms), so no timer is
/// masked and the thread makes no round.
fn vtimer_thread(waiter: &Waiter, vm: Weak<VmInner>) {
    // The next round's time; `None` while no vCPU's timer is masked.
    let mut next: Option<Instant> = None;
    loop {
        let ended = waiter.wait(next.map(|n| n.saturating_duration_since(Instant::now())));
        let Some(vm) = vm.upgrade() else { return };
        if vm.stop.load(Ordering::Acquire) {
            return;
        }
        if ended != Ended::Due {
            // A vCPU masked its timer (or a signal came): a round within
            // VTIMER_ROUND, not sooner than one already due.
            next.get_or_insert_with(|| Instant::now() + VTIMER_ROUND);
            continue;
        }
        #[cfg(test)]
        vm.vtimer_rounds.fetch_add(1, Ordering::Relaxed);
        let mut masked = false;
        for vcpu in vm.vcpus.lock().unwrap().iter() {
            masked |= vcpu.poke_if_vtimer_masked();
        }
        next = masked.then(|| Instant::now() + VTIMER_ROUND);
    }
}

fn io_err(e: std::io::Error) -> super::Error {
    super::Error::new(e.raw_os_error().unwrap_or(libc::EIO))
}

// These tests create a VM: they need Hypervisor.framework and the hypervisor
// entitlement (tools/macos/test.sh); CI's macOS runners have neither.
#[cfg(test)]
mod tests {
    use kvm_bindings::{
        KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
        KVM_DEV_ARM_VGIC_GRP_DIST_REGS, KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
    };

    use super::*;
    use crate::Kvm;

    fn set_attr(dev: &DeviceFd, group: u32, attr: u64, value: u64) -> Result<()> {
        dev.set_device_attr(&kvm_device_attr {
            group,
            attr,
            addr: std::ptr::from_ref(&value) as u64,
            flags: 0,
        })
    }

    fn spi_pending(intid: u32) -> bool {
        let mut v = 0;
        // SAFETY: plain call with a valid output.
        check(unsafe { hv_gic_get_distributor_reg(0x200 + 4 * (intid / 32), &mut v) }).unwrap();
        v & (1 << (intid % 32)) != 0
    }

    fn spi_active(intid: u32) -> bool {
        let mut v = 0;
        // SAFETY: plain call with a valid output.
        check(unsafe { hv_gic_get_distributor_reg(0x300 + 4 * (intid / 32), &mut v) }).unwrap();
        v & (1 << (intid % 32)) != 0
    }

    /// A VM with a GIC and one vCPU that has not run yet.
    fn vm_with_gic() -> (VmFd, DeviceFd, VcpuFd) {
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let mut dev = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let gic = vm.create_device(&mut dev).unwrap();
        let dist = 0x4000_0000 - 0x1_0000;
        set_attr(&gic, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_DIST.into(), dist).unwrap();
        let redist = dist - (32 << 20);
        set_attr(&gic, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_REDIST.into(), redist)
            .unwrap();
        set_attr(&gic, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_CTRL_INIT.into(), 0).unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        (vm, gic, vcpu)
    }

    /// Runs `body` on the thread of the VM's vCPU 0 once its first run made
    /// it, with SPIs `edges` edge-triggered (`GICD_ICFGR`), as Firecracker's
    /// device tree makes a virtio device's.
    fn with_created_vcpu(edges: &[u32], body: impl FnOnce(VmFd) + Send + 'static) {
        let (vm, _gic, mut vcpu) = vm_with_gic();
        let edges = edges.to_vec();
        std::thread::spawn(move || {
            vcpu.set_kvm_immediate_exit(1);
            assert_eq!(vcpu.run().unwrap_err().errno(), libc::EINTR);
            for intid in edges {
                let reg = 0xc00 + 4 * (intid / 16);
                let mut v = 0;
                // SAFETY: plain calls with a valid output.
                check(unsafe { hv_gic_get_distributor_reg(reg, &mut v) }).unwrap();
                v |= 2 << (2 * (intid % 16));
                // SAFETY: as above.
                check(unsafe { hv_gic_set_distributor_reg(reg, v) }).unwrap();
            }
            body(vm);
            drop(vcpu);
        })
        .join()
        .unwrap();
    }

    /// Waits up to `limit` for `done`.
    fn within(limit: Duration, done: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        while !done() {
            if Instant::now() > deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    #[test]
    fn test_an_irqfd_write_raises_its_spi_before_it_returns() {
        // As KVM's irqfd, which injects an SPI in the writer's thread
        // (virt/kvm/eventfd.c irqfd_wakeup): with the irqfd thread stopped,
        // the write itself has made the SPI pending, and taken the count.
        with_created_vcpu(&[40], |mut vm| {
            let evt = EventFd::new(EFD_NONBLOCK).unwrap();
            vm.register_irqfd(&evt, 8).unwrap();
            vm.inner.stop_evt.write(1).unwrap();
            vm.threads.remove(0).join().unwrap();
            assert!(!spi_pending(40));
            evt.write(1).unwrap();
            assert!(spi_pending(40), "the write returned before its SPI was raised");
            assert_eq!(evt.read().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        });
    }

    #[test]
    fn test_an_irqfd_write_of_another_process_is_raised_by_the_irqfd_thread() {
        // A handle made from the descriptor, as another process (a
        // vhost-user backend) has it, counts its writes in the descriptor:
        // the irqfd thread raises them, a thread hand-off after the write
        // where KVM's irqfd_wakeup raises any writer's inline (the kernel's
        // eventfd is one object for every process). Prints how long the
        // SPI took to be pending after each kind of write.
        with_created_vcpu(&[41], |vm| {
            let evt = EventFd::new(EFD_NONBLOCK).unwrap();
            vm.register_irqfd(&evt, 9).unwrap();
            // SAFETY: a new descriptor of the eventfd, owned by the handle.
            let other = unsafe { EventFd::from_raw_fd(libc::dup(evt.as_raw_fd())) };
            other.write(1).unwrap();
            assert!(
                within(Duration::from_secs(10), || spi_pending(41)),
                "the irqfd thread did not raise another process's write in 10 s"
            );
            assert!(within(Duration::from_secs(10), || evt.read().is_err()), "the count was not taken");
            let clear = || {
                // SAFETY: plain call; GICD_ICPENDR1 is write-1-to-clear.
                check(unsafe { hv_gic_set_distributor_reg(0x284, 1 << (41 - 32)) }).unwrap();
                assert!(!spi_pending(41));
            };
            let us = |writer: &EventFd| {
                let mut v: Vec<u128> = (0..200)
                    .map(|_| {
                        clear();
                        let t = Instant::now();
                        writer.write(1).unwrap();
                        assert!(within(Duration::from_secs(10), || spi_pending(41)));
                        t.elapsed().as_micros()
                    })
                    .collect();
                v.sort_unstable();
                (v[v.len() / 2], v[v.len() * 9 / 10], v[v.len() - 1])
            };
            let (inline, handed) = (us(&evt), us(&other));
            eprintln!(
                "write to pending, 200 each (median, 90th, max us): this process {inline:?}, another process's handle {handed:?}; load {:.1}",
                load()
            );
        });
    }

    fn load() -> f64 {
        let mut avg = [0f64; 1];
        // SAFETY: one double written.
        unsafe { libc::getloadavg(avg.as_mut_ptr(), 1) };
        avg[0]
    }

    #[test]
    fn test_an_unregistered_irqfd_raises_nothing() {
        with_created_vcpu(&[42], |vm| {
            let evt = EventFd::new(EFD_NONBLOCK).unwrap();
            vm.register_irqfd(&evt, 10).unwrap();
            vm.unregister_irqfd(&evt, 10).unwrap();
            assert_eq!(vm.unregister_irqfd(&evt, 10).unwrap_err().errno(), libc::ENOENT);
            evt.write(1).unwrap();
            assert!(!spi_pending(42));
            assert_eq!(evt.read().unwrap(), 1);
        });
    }

    #[test]
    fn test_an_eventfd_is_one_irqfd_of_a_vm() {
        // kvm_irqfd_assign: "This fd is used for another irq already."
        let (vm, _gic, _vcpu) = vm_with_gic();
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        vm.register_irqfd(&evt, 8).unwrap();
        assert_eq!(vm.register_irqfd(&evt, 9).unwrap_err().errno(), libc::EBUSY);
        assert_eq!(vm.register_irqfd(&evt.try_clone().unwrap(), 8).unwrap_err().errno(), libc::EBUSY);
        vm.unregister_irqfd(&evt, 8).unwrap();
        vm.register_irqfd(&evt, 9).unwrap();
    }

    #[test]
    fn test_irqfd_writes_registrations_and_the_irqfd_thread_do_not_wait_for_each_other() {
        // Writers raising interrupts in their threads, registrations coming
        // and going, writes through another process's handle that the irqfd
        // thread reads under the VM's `irq` lock, and a thread that holds
        // `irq` and `vcpus` as the backend does: none may wait for another
        // forever. A removal under `irq` (which a running consumer waits
        // for) or a consumer called under the eventfd's own lock (which the
        // irqfd thread takes under `irq`) deadlocks here.
        // The threads are not scoped: a deadlocked one is left behind, and
        // the test fails by its name rather than waiting for it.
        with_created_vcpu(&[43], |vm| {
            let vm = Arc::new(vm);
            let evt = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
            // SAFETY: a new descriptor of the eventfd, owned by the handle.
            let other = unsafe { EventFd::from_raw_fd(libc::dup(evt.as_raw_fd())) };
            let stop = Arc::new(AtomicBool::new(false));
            let rounds = Arc::new(AtomicU64::new(0));
            let mut threads = Vec::new();
            for _ in 0..3 {
                let (evt, stop) = (evt.clone(), stop.clone());
                threads.push(std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        evt.write(1).unwrap();
                    }
                }));
            }
            let s = stop.clone();
            threads.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    other.write(1).unwrap();
                }
            }));
            let (v, e, s) = (vm.clone(), evt.clone(), stop.clone());
            threads.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    let _irq = v.inner.irq.lock().unwrap();
                    let _vcpus = v.inner.vcpus.lock().unwrap();
                    let _ = e.read();
                }
            }));
            let (tx, rx) = std::sync::mpsc::channel();
            let (v, e, r) = (vm.clone(), evt.clone(), rounds.clone());
            std::thread::spawn(move || {
                for _ in 0..2000 {
                    v.register_irqfd(&e, 11).unwrap();
                    v.unregister_irqfd(&e, 11).unwrap();
                    r.fetch_add(1, Ordering::Relaxed);
                }
                let _ = tx.send(());
            });
            let ended = rx.recv_timeout(Duration::from_secs(60)).is_ok();
            assert!(
                ended,
                "registrations stopped after {} of 2000 rounds: a lock order deadlock",
                rounds.load(Ordering::Relaxed)
            );
            stop.store(true, Ordering::Relaxed);
            for t in threads {
                t.join().unwrap();
            }
        });
    }

    #[test]
    fn test_msi_data_names_no_spi() {
        // MSI data is the SPI, and the guest writes it: a value that names no
        // SPI fails as Hypervisor.framework fails it, also while a vCPU has
        // not run yet, when its route is looked up first.
        let (vm, _gic, _vcpu) = vm_with_gic();
        for data in [0x2000_0000, 0xffff_f000, u32::MAX] {
            let msi = kvm_msi {
                address_lo: 0x1000,
                data,
                ..Default::default()
            };
            vm.signal_msi(msi).unwrap_err();
        }
    }

    #[test]
    fn test_spi_raised_before_its_vcpu_exists() {
        // Interrupts raised and pending state restored before the vCPU first
        // runs (a snapshot restore kicks the devices then) are not lost.
        let (vm, gic, mut vcpu) = vm_with_gic();

        // Raised: waits for vCPU 0, which SPI 40 is routed to.
        let raised = vm.inner.raise_spi(40, || panic!("raised before its vCPU exists"));
        assert_eq!(raised, HV_SUCCESS);
        // Restored pending, then cleared: forgotten. Restored pending: waits.
        let ispendr1 = u64::from(0x204u32);
        let icpendr1 = u64::from(0x284u32);
        let write = |offset: u64, value: u32| {
            gic.set_device_attr(&kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
                attr: offset,
                addr: std::ptr::from_ref(&value) as u64,
                flags: 0,
            })
            .unwrap()
        };
        write(ispendr1, 1 << (41 - 32));
        write(icpendr1, 1 << (41 - 32));
        write(ispendr1, 1 << (42 - 32));
        assert_eq!(*vm.inner.deferred_spis.lock().unwrap(), [40, 42]);
        assert!(!spi_pending(40) && !spi_pending(42));

        // The vCPU's first run creates it: both become pending.
        std::thread::spawn(move || {
            vcpu.set_kvm_immediate_exit(1);
            assert_eq!(vcpu.run().unwrap_err().errno(), libc::EINTR);
            assert!(vm.inner.deferred_spis.lock().unwrap().is_empty());
            assert!(spi_pending(40) && !spi_pending(41) && spi_pending(42));
            // Once every vCPU exists, interrupts are raised directly.
            let mut direct = false;
            vm.inner.raise_spi(43, || {
                direct = true;
                HV_SUCCESS
            });
            assert!(direct);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn test_spi_active_restored_before_its_vcpu_exists() {
        // A snapshot taken while the guest handled an SPI restores it active
        // before the vCPUs first run (the order of a real restore: the SPI's
        // GICD_IROUTER, then GICD_ISACTIVER). Hypervisor.framework crashes
        // the process if an SPI routed to a vCPU it has not created is made
        // active: the state waits for the vCPU, and reads report it as KVM
        // keeps it.
        let (vm, gic, mut vcpu) = vm_with_gic();
        let attr = |offset: u64, value: &u32| kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: offset,
            addr: std::ptr::from_ref(value) as u64,
            flags: 0,
        };
        let write = |offset: u64, value: u32| gic.set_device_attr(&attr(offset, &value)).unwrap();
        let read = |offset: u64| {
            let mut value = 0u32;
            let mut a = attr(offset, &value);
            a.addr = std::ptr::from_mut(&mut value) as u64;
            // SAFETY: `value` outlives the call and is the 4 bytes it fills.
            unsafe { gic.get_device_attr(&mut a).unwrap() };
            value
        };
        let (isactiver1, icactiver1) = (0x304u64, 0x384u64);
        write(0x6104, 0); // GICD_IROUTER32, upper half: vCPU 0.
        write(isactiver1, 1 << (32 - 32) | 1 << (33 - 32));
        write(icactiver1, 1 << (33 - 32));
        assert_eq!(*vm.inner.deferred_active.lock().unwrap(), [32]);
        assert_eq!(read(isactiver1), 1);
        assert_eq!(read(icactiver1), 1);
        assert!(!spi_active(32));

        // The vCPU's first run creates it: the SPI becomes active.
        std::thread::spawn(move || {
            vcpu.set_kvm_immediate_exit(1);
            assert_eq!(vcpu.run().unwrap_err().errno(), libc::EINTR);
            assert!(vm.inner.deferred_active.lock().unwrap().is_empty());
            assert!(spi_active(32) && !spi_active(33));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn test_signals_interrupt_run_as_on_kvm() {
        // A signal to a vCPU thread inside run() (Firecracker kicks vCPUs
        // with one) makes KVM_RUN return EINTR if the kick set
        // immediate_exit, and otherwise the vCPU just runs on: never an
        // internal error. The guest spins (`b .`).
        extern "C" fn nothing(_: libc::c_int) {}
        // SAFETY: a handler that does nothing.
        unsafe { libc::signal(libc::SIGUSR2, nothing as *const () as libc::sighandler_t) };
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let page = host_page_size() as usize;
        // SAFETY: an anonymous mapping of one page, kept for the test.
        let mem = unsafe {
            libc::mmap(std::ptr::null_mut(), page, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
        };
        assert_ne!(mem, libc::MAP_FAILED);
        // SAFETY: the page just mapped; `b .` is 0x14000000.
        unsafe { *mem.cast::<u32>() = 0x1400_0000 };
        let region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0x8000_0000,
            memory_size: page as u64,
            userspace_addr: mem as u64,
            flags: 0,
        };
        // SAFETY: the page stays mapped for the test.
        unsafe { vm.set_user_memory_region(region).unwrap() };
        let mut vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        const PC: u64 = 0x6030_0000_0010_0040;
        const PSTATE: u64 = 0x6030_0000_0010_0042;
        vcpu.set_one_reg(PC, &0x8000_0000u64.to_le_bytes()).unwrap();
        vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
        // The handle Firecracker kicks with (Vcpu::copy_kvm_vcpu_fd).
        // SAFETY: dup of the vCPU's descriptor, owned by the new handle.
        let mut kicker = unsafe {
            vm.create_vcpu_from_rawfd(libc::dup(std::os::unix::io::AsRawFd::as_raw_fd(&vcpu))).unwrap()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let kicks = 300;
        let runner = std::thread::spawn(move || {
            // SAFETY: plain call.
            tx.send(unsafe { libc::pthread_self() } as usize).unwrap();
            let mut results = Vec::new();
            for _ in 0..kicks {
                match vcpu.run() {
                    Err(e) if e.errno() == libc::EINTR => results.push("EINTR".to_owned()),
                    Ok(exit) => results.push(format!("{exit:?}")),
                    Err(e) => results.push(format!("error {e}")),
                }
                vcpu.set_kvm_immediate_exit(0);
            }
            results
        });
        let thread = rx.recv().unwrap() as libc::pthread_t;
        // Half the kicks set immediate_exit (as Firecracker's do), the others
        // are bare signals; both while the guest runs.
        for i in 0..kicks * 4 {
            std::thread::sleep(Duration::from_micros(500));
            if i % 2 == 0 {
                kicker.set_kvm_immediate_exit(1);
            }
            // SAFETY: a live thread of this process.
            unsafe { libc::pthread_kill(thread, libc::SIGUSR2) };
            if runner.is_finished() {
                break;
            }
        }
        while !runner.is_finished() {
            kicker.set_kvm_immediate_exit(1);
            std::thread::sleep(Duration::from_millis(1));
        }
        let results = runner.join().unwrap();
        let odd: Vec<_> = results.iter().filter(|r| *r != "EINTR").collect();
        assert!(odd.is_empty(), "{} of {} runs: {:?}", odd.len(), results.len(), &odd[..odd.len().min(5)]);
    }

    /// KVM core register ids of `X<n>` (`KVM_REG_ARM_CORE`, two words each).
    fn x_reg(n: u64) -> u64 {
        0x6030_0000_0010_0000 + 2 * n
    }
    const PC: u64 = 0x6030_0000_0010_0040;
    const PSTATE: u64 = 0x6030_0000_0010_0042;
    const GUEST_BASE: u64 = 0x8000_0000;
    /// An address no slot covers: a store to it exits as MMIO.
    const MMIO: u64 = 0x1000_0000;

    /// A VM with `mib` MiB of anonymous memory at [`GUEST_BASE`], the first
    /// page holding `code`, and a vCPU initialised to run it. Returns the
    /// memory's host address and size.
    fn vm_with_memory(mib: usize, code: &[u32]) -> (VmFd, VcpuFd, *mut libc::c_void, usize) {
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let len = mib << 20;
        // SAFETY: a fresh anonymous mapping, kept for the test.
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED);
        // SAFETY: the first page of the mapping.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), mem.cast::<u32>(), code.len()) };
        let region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: GUEST_BASE,
            memory_size: len as u64,
            userspace_addr: mem as u64,
            flags: 0,
        };
        // SAFETY: the mapping stays for the test.
        unsafe { vm.set_user_memory_region(region).unwrap() };
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        (vm, vcpu, mem, len)
    }

    /// The process's phys_footprint, what the jailer's memory limit (a
    /// jetsam limit) is checked against.
    fn phys_footprint() -> u64 {
        // SAFETY: plain data filled by the call.
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        // SAFETY: a V4 buffer for the V4 flavour.
        let r = unsafe {
            libc::proc_pid_rusage(libc::getpid(), libc::RUSAGE_INFO_V4, std::ptr::from_mut(&mut info).cast())
        };
        assert_eq!(r, 0);
        info.ri_phys_footprint
    }

    /// Guest program: writes X3 to every page from X1 to X2, then to X4
    /// (MMIO: the exit).
    const FILL: [u32; 6] = [0xf9000023, 0x91401021, 0xeb02003f, 0x54ffffa3, 0xf9000083, 0x14000000];

    /// Runs [`FILL`] with `value` over all pages but the code's.
    fn fill(vcpu: &mut VcpuFd, len: usize, value: u64) {
        let page = host_page_size();
        for (id, v) in [
            (PC, GUEST_BASE),
            (PSTATE, 0x3c5),
            (x_reg(1), GUEST_BASE + page),
            (x_reg(2), GUEST_BASE + len as u64),
            (x_reg(3), value),
            (x_reg(4), MMIO),
        ] {
            vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
        }
        match vcpu.run().unwrap() {
            crate::VcpuExit::MmioWrite(MMIO, data) => assert_eq!(data, &value.to_le_bytes()),
            other => panic!("{other:?}"),
        }
    }

    /// The pages of guest memory are replaced under the guest by `replace`
    /// (a Linux `MADV_DONTNEED`, a `MAP_FIXED` mapping): the guest and the
    /// host then use the new pages, which are released from the footprint
    /// and charged to it again when the guest writes them. Measured before
    /// the fix with a standalone probe: Hypervisor.framework kept the old
    /// pages (the host read 0 where the guest had written), and
    /// `MADV_FREE_REUSABLE` released nothing of them.
    fn replaced_pages(replace: impl Fn(*mut libc::c_void, usize)) {
        const MIB: usize = 64;
        let (_vm, mut vcpu, mem, len) = vm_with_memory(MIB, &FILL);
        let page = host_page_size() as usize;
        let at = |off: usize| -> u64 {
            // SAFETY: inside the mapping.
            unsafe { std::ptr::read_volatile(mem.cast::<u8>().add(off).cast::<u64>()) }
        };
        let idle = phys_footprint();
        fill(&mut vcpu, len, 0x5a5a);
        let written = phys_footprint();
        assert!(written - idle >= 60 << 20, "footprint {idle} -> {written} for {MIB} MiB written");
        assert_eq!(at(page), 0x5a5a);
        assert_eq!(at(len - page), 0x5a5a);

        // SAFETY: all pages of the mapping but the code's.
        replace(unsafe { mem.add(page) }, len - page);
        let discarded = phys_footprint();
        assert!(written - discarded >= 60 << 20, "footprint {written} -> {discarded} after the discard");
        assert_eq!(at(page), 0);
        assert_eq!(at(len - page), 0);

        // The guest writes the pages the host sees, and is charged for them.
        fill(&mut vcpu, len, 0x1234);
        assert_eq!(at(page), 0x1234, "the guest writes other pages than the host reads");
        assert_eq!(at(len - page), 0x1234);
        let again = phys_footprint();
        assert!(again - discarded >= 60 << 20, "footprint {discarded} -> {again} after the guest wrote again");
        println!(
            "phys_footprint KiB: idle {}, guest wrote {MIB} MiB {}, discarded {}, guest wrote again {}",
            idle >> 10,
            written >> 10,
            discarded >> 10,
            again >> 10
        );
    }

    #[test]
    fn test_madvise_dontneed_replaces_guest_pages() {
        replaced_pages(|ptr, len| {
            // SAFETY: a mapped range of the test's.
            assert_eq!(unsafe { libc::madvise(ptr, len, libc::MADV_DONTNEED) }, 0);
        });
    }

    #[test]
    fn test_map_fixed_replaces_guest_pages() {
        // Upstream's `discard_range` on memory restored from a file.
        replaced_pages(|ptr, len| {
            // SAFETY: over a mapped range of the test's.
            let p = unsafe {
                libc::mmap(
                    ptr,
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED | libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_eq!(p, ptr);
        });
    }

    /// Guest program: writes X3 to every page from X5 to X2, adds 1 to X3,
    /// forever.
    const COUNTER: [u32; 7] =
        [0xaa0503e1, 0xf9000023, 0x91401021, 0xeb02003f, 0x54ffffa3, 0x91000463, 0x17fffffa];

    /// A vCPU writing a range in a loop while another thread discards it:
    /// a write that lands while the range is unmapped waits for the new
    /// pages and lands on them; no exit is misread as MMIO, and once the
    /// discards stop every page holds what the guest last wrote.
    #[test]
    fn test_guest_writes_during_a_discard_wait_for_the_new_pages() {
        extern "C" fn nothing(_: libc::c_int) {}
        // SAFETY: a handler that does nothing.
        unsafe { libc::signal(libc::SIGUSR2, nothing as *const () as libc::sighandler_t) };
        const MIB: usize = 16;
        let (vm, mut vcpu, mem, len) = vm_with_memory(MIB, &COUNTER);
        let page = host_page_size() as usize;
        for (id, v) in [
            (PC, GUEST_BASE),
            (PSTATE, 0x3c5),
            (x_reg(5), GUEST_BASE + page as u64),
            (x_reg(2), GUEST_BASE + len as u64),
            (x_reg(3), 1),
        ] {
            vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
        }
        // SAFETY: dup of the vCPU's descriptor, owned by the new handle.
        let mut kicker = unsafe {
            vm.create_vcpu_from_rawfd(libc::dup(std::os::unix::io::AsRawFd::as_raw_fd(&vcpu))).unwrap()
        };
        // One thread runs the guest (Hypervisor.framework binds a vCPU's
        // registers to it): a phase ends when the thread is kicked, and
        // reports X3 (the round), X1 (the page being written) and whatever
        // else run() returned.
        let (to_main, from_runner) = std::sync::mpsc::channel::<(u64, u64, Vec<String>)>();
        let (to_runner, from_main) = std::sync::mpsc::channel::<bool>();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let runner = std::thread::spawn(move || {
            // SAFETY: plain call.
            tid_tx.send(unsafe { libc::pthread_self() } as usize).unwrap();
            let reg = |vcpu: &VcpuFd, id: u64| {
                let mut v = [0u8; 8];
                vcpu.get_one_reg(id, &mut v).unwrap();
                u64::from_le_bytes(v)
            };
            loop {
                vcpu.set_kvm_immediate_exit(0);
                let mut odd = Vec::new();
                loop {
                    match vcpu.run() {
                        Err(e) if e.errno() == libc::EINTR => break,
                        Ok(exit) => odd.push(format!("{exit:?}")),
                        Err(e) => odd.push(format!("error {e}")),
                    }
                    if odd.len() > 5 {
                        break;
                    }
                }
                to_main.send((reg(&vcpu, x_reg(3)), reg(&vcpu, x_reg(1)), odd)).unwrap();
                if !from_main.recv().unwrap() {
                    break;
                }
            }
        });
        let thread = tid_rx.recv().unwrap() as libc::pthread_t;
        let mut kick = || loop {
            kicker.set_kvm_immediate_exit(1);
            // SAFETY: a live thread of this process.
            unsafe { libc::pthread_kill(thread, libc::SIGUSR2) };
            if let Ok(report) = from_runner.recv_timeout(Duration::from_millis(1)) {
                return report;
            }
        };

        // 200 discards of the whole range while the guest writes it.
        for _ in 0..200 {
            // SAFETY: all pages of the mapping but the code's.
            assert_eq!(unsafe { libc::madvise(mem.add(page), len - page, libc::MADV_DONTNEED) }, 0);
            std::thread::sleep(Duration::from_micros(500));
        }
        let (rounds, _, odd) = kick();
        assert!(odd.is_empty(), "exits during the discards: {odd:?}");
        assert!(rounds >= 1, "the guest did not run");

        // Then the guest alone, for at least two whole rounds.
        to_runner.send(true).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let (round, next, odd) = kick();
        to_runner.send(false).unwrap();
        runner.join().unwrap();
        assert!(odd.is_empty(), "exits after the discards: {odd:?}");
        assert!(round >= rounds + 2, "{rounds} rounds during the discards, {round} after");
        // Pages before X1 hold the round being written, pages after it the
        // one before; the page at X1 is either (the store may just have
        // landed); a round just finished (X1 at the end) wrote the one before.
        let mut wrong = Vec::new();
        for off in (page..len).step_by(page) {
            // SAFETY: inside the mapping.
            let v = unsafe { std::ptr::read_volatile(mem.cast::<u8>().add(off).cast::<u64>()) };
            let ipa = GUEST_BASE + off as u64;
            let expected: &[u64] = if next >= GUEST_BASE + len as u64 || ipa > next {
                &[round - 1]
            } else if ipa < next {
                &[round]
            } else {
                &[round, round - 1]
            };
            if !expected.contains(&v) {
                wrong.push((ipa, v));
            }
        }
        assert!(
            wrong.is_empty(),
            "round {round}, at {next:#x}: {} pages hold other values, e.g. {:?}",
            wrong.len(),
            &wrong[..wrong.len().min(4)]
        );
    }

    /// The VM map entries inside `[start, start + len)`.
    fn map_entries(start: u64, len: u64) -> usize {
        unsafe extern "C" {
            fn mach_vm_region(
                task: u32,
                address: *mut u64,
                size: *mut u64,
                flavor: c_int,
                info: *mut c_int,
                count: *mut u32,
                object_name: *mut u32,
            ) -> c_int;
            static mach_task_self_: u32;
        }
        let (mut n, mut addr) = (0, start);
        while addr < start + len {
            let (mut at, mut size, mut object) = (addr, 0u64, 0u32);
            let mut info = [0 as c_int; 16];
            let mut count = 9u32;
            // SAFETY: valid output buffers for VM_REGION_BASIC_INFO_64 (9).
            let ret = unsafe {
                mach_vm_region(mach_task_self_, &mut at, &mut size, 9, info.as_mut_ptr(), &mut count, &mut object)
            };
            if ret != 0 || at >= start + len {
                break;
            }
            n += 1;
            addr = at + size;
        }
        n
    }

    /// Free page reporting and a 4 KiB-page balloon release scattered host
    /// pages, and each replaced piece is a VM map entry of its own (XNU
    /// merges adjacent entries only when they share one object; a fresh
    /// `MAP_FIXED` mapping has its own), so a large guest can come to tens
    /// of thousands of entries and as many `hv_vm_map` ranges. On a 1 GiB
    /// guest, three cycles of discarding every other host page (32768
    /// discards) and the guest writing every page again: no discard, stage-2
    /// mapping or guest access fails (a page left unmapped would exit as
    /// MMIO), the entries are counted and the time per discard measured
    /// (docs/PORTING.md, the `libc` row).
    #[test]
    fn test_scattered_discards_keep_the_guest_mapped() {
        // WICK_STRESS_MIB raises the guest size for a longer run by hand.
        let mib: usize = std::env::var("WICK_STRESS_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(1024);
        let (_vm, mut vcpu, mem, len) = vm_with_memory(mib, &FILL);
        let page = host_page_size() as usize;
        let at = |off: usize| -> u64 {
            // SAFETY: inside the mapping.
            unsafe { std::ptr::read_volatile(mem.cast::<u8>().add(off).cast::<u64>()) }
        };
        fill(&mut vcpu, len, 1);
        let entries = map_entries(mem as u64, len as u64);
        println!(
            "guest wrote {mib} MiB: {entries} entries, footprint {} KiB",
            phys_footprint() >> 10
        );
        // XNU maps anonymous memory in chunks of 128 MiB (ANON_CHUNK_SIZE).
        assert!(entries <= mib.div_ceil(128), "{entries} entries before any discard");
        for cycle in 1..=3u64 {
            let start = std::time::Instant::now();
            let (mut n, mut off) = (0u32, page);
            while off < len {
                // SAFETY: one page of the mapping.
                if unsafe { libc::madvise(mem.add(off), page, libc::MADV_DONTNEED) } != 0 {
                    panic!(
                        "cycle {cycle}: discard {n} at {off:#x} failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
                n += 1;
                off += 2 * page;
            }
            let per = start.elapsed() / n;
            let (discarded, footprint) = (map_entries(mem as u64, len as u64), phys_footprint());
            assert_eq!(at(page), 0);
            fill(&mut vcpu, len, cycle + 1);
            for off in [page, 2 * page, len / 2, len - 2 * page, len - page] {
                assert_eq!(at(off), cycle + 1, "page at {off:#x} after cycle {cycle}");
            }
            println!(
                "cycle {cycle}: {n} discards of one page, {per:?} each; {discarded} entries after them, {} after \
                 the guest wrote again; footprint {} KiB discarded, {} KiB written again",
                map_entries(mem as u64, len as u64),
                footprint >> 10,
                phys_footprint() >> 10
            );
        }
    }

    #[test]
    fn test_vcpu_init_reads_what_the_run_phase_needs() {
        // A new vCPU's register values come from a scratch vCPU on a thread
        // of its own (`probe_reset_regs`). The run phase may make no thread
        // (Firecracker's host sandbox, as Linux's vCPU filter has no clone),
        // and it needs them: a snapshot's register list, and a vCPU that
        // PSCI CPU_ON starts again, which is reset to them. So the first
        // vcpu_init, in the setup phase, reads them (a release build that
        // read them lazily died at a vCPU's first run: SYS_bsdthread_create
        // denied).
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        assert!(vm.inner.reset_regs.get().is_none());
        let vcpu = vm.create_vcpu(0).unwrap();
        assert!(vm.inner.reset_regs.get().is_none());
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        assert!(matches!(vm.inner.reset_regs.get(), Some(Ok(_))));
    }

    #[test]
    fn test_a_new_vcpu_has_kvms_reset_values() {
        // A vCPU that PSCI CPU_ON starts again is reset to a new vCPU's
        // values (`reset_for_cpu_on`). Where KVM's reset gives a register a
        // value, a new Hypervisor.framework vCPU has the same one: 0 for
        // x0-x30, SP_EL0, PC, the FP/SIMD registers, FPSR and FPCR
        // (arch/arm64/include/asm/kvm_emulate.h `kvm_reset_vcpu_core`), and
        // for MDSCR_EL1, CPACR_EL1, TCR_EL1, VBAR_EL1, CONTEXTIDR_EL1,
        // CNTKCTL_EL1, CNTV_CTL_EL0 and CNTV_CVAL_EL0 (their `reset_val`
        // in arch/arm64/kvm/sys_regs.c). SCTLR_EL1 and PSTATE differ, and
        // are written.
        use super::super::regs::{self, Reg};
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        let reset = vm.inner.reset_regs.get().unwrap().as_ref().unwrap();
        let zero_sys = [0x8012, 0xc082, 0xc102, 0xc600, 0xc681, 0xc708, 0xdf19, 0xdf02];
        let mut checked = 0;
        for id in regs::reg_list() {
            let kvm_zero = zero_sys.iter().any(|e| id == regs::sys_id(*e))
                || match regs::decode(id) {
                    Some(Reg::Gp(r)) => r <= HV_REG_PC,
                    Some(Reg::Simd(_) | Reg::Fp(_)) => true,
                    Some(Reg::Sys(r)) => r == HV_SYS_REG_SP_EL0,
                    _ => false,
                };
            if kvm_zero {
                assert!(reset[&id].iter().all(|b| *b == 0), "{id:#x}: {:?}", reset[&id]);
                checked += 1;
            }
        }
        // 31 + PC + SP_EL0, 32 V registers, FPSR, FPCR, 8 system registers.
        assert_eq!(checked, 33 + 32 + 2 + zero_sys.len());
    }

    #[test]
    fn test_virtual_count_is_the_vms() {
        // As on KVM, writing one vCPU's TIMER_CNT sets the counter of every
        // vCPU, from the time of the write (not the time a vCPU first runs):
        // one offset for the VM, which every vCPU is given, so their
        // counters read the same at any instant (Linux v6.1
        // arch/arm64/kvm/arch_timer.c `update_vtimer_cntvoff` sets the
        // written CNTVOFF on every vCPU). A restore writes each vCPU's saved
        // TIMER_CNT in turn: the last write is the VM's, on KVM and here.
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        let vcpus: Vec<_> = (0..2)
            .map(|i| {
                let v = vm.create_vcpu(i).unwrap();
                v.vcpu_init(&kvi).unwrap();
                v
            })
            .collect();
        let id = super::super::regs::sys_id(super::super::regs::KVM_TIMER_CNT);
        let start = 1u64 << 40;
        vcpus[0].set_one_reg(id, &start.to_le_bytes()).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let (counts, offsets): (Vec<u64>, Vec<u64>) = vcpus
            .into_iter()
            .map(|mut vcpu| {
                std::thread::spawn(move || {
                    vcpu.set_kvm_immediate_exit(1);
                    vcpu.run().unwrap_err();
                    let mut buf = [0u8; 8];
                    vcpu.get_one_reg(id, &mut buf).unwrap();
                    let hv = vcpu.ensure_created().unwrap();
                    let mut offset = 0;
                    // SAFETY: `hv` belongs to this thread.
                    check(unsafe { hv_vcpu_get_vtimer_offset(hv, &mut offset) }).unwrap();
                    (u64::from_le_bytes(buf), offset)
                })
                .join()
                .unwrap()
            })
            .unzip();
        let vms = vm.inner.vtimer_offset.load(Ordering::Acquire);
        assert_eq!(offsets, [vms, vms], "each vCPU's CNTVOFF is the VM's");
        let mut freq = 0u64;
        // SAFETY: reads CNTFRQ_EL0, readable at EL0.
        unsafe { std::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
        let elapsed = |c: u64| (c - start) as f64 / freq as f64;
        for c in &counts {
            assert!((0.1..2.0).contains(&elapsed(*c)), "{:.3}s", elapsed(*c));
        }
        assert!((elapsed(counts[1]) - elapsed(counts[0])).abs() < 0.05, "{counts:?}");
    }

    #[test]
    fn test_id_register_writes_reach_the_guest() {
        // As on KVM (Linux 6.7 and later): the ID registers are the VM's; a
        // write through one vCPU before the VM runs is what every vCPU's
        // guest reads with `mrs`; a field may be lowered, not raised, and
        // only those KVM lets user space change; once the VM has run a
        // different value is refused with EBUSY.
        use super::super::regs::{reg_list, sys_id};
        const ISAR0: u16 = 0xc030;
        const ISAR1: u16 = 0xc031;
        // mrs x0, ID_AA64ISAR0_EL1; str x0, [x4]; mrs x0, ID_AA64ISAR1_EL1;
        // str x0, [x4]; b .
        const CODE: [u32; 5] = [0xd5380600, 0xf9000080, 0xd5380620, 0xf9000080, 0x14000000];
        let (vm, vcpu0, _mem, _len) = vm_with_memory(1, &CODE);
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        let vcpu1 = vm.create_vcpu(1).unwrap();
        vcpu1.vcpu_init(&kvi).unwrap();
        let read = |v: &VcpuFd, r: u16| {
            let mut buf = [0u8; 8];
            v.get_one_reg(sys_id(r), &mut buf).unwrap();
            u64::from_le_bytes(buf)
        };
        let write = |v: &VcpuFd, r: u16, x: u64| v.set_one_reg(sys_id(r), &x.to_le_bytes()).map(|_| ());
        let isar0 = read(&vcpu0, ISAR0);
        let isar1 = read(&vcpu0, ISAR1);
        assert_ne!(isar0 & 0xf0, 0, "the host has AES: {isar0:#x}");
        // Listed for snapshots, as KVM lists them.
        let mut list = kvm_bindings::RegList::new(500).unwrap();
        vcpu0.get_reg_list(&mut list).unwrap();
        assert!(list.as_slice().contains(&sys_id(ISAR0)) && !reg_list().contains(&sys_id(ISAR0)));
        // AES off: lowered, through vCPU 0, read back through vCPU 1.
        let lowered = isar0 & !0xf0;
        write(&vcpu0, ISAR0, lowered).unwrap();
        assert_eq!(read(&vcpu1, ISAR0), lowered);
        // Raised above the host's: refused.
        let raised = (isar0 & !0xf0) | ((((isar0 >> 4) & 0xf) + 1) << 4);
        assert_eq!(write(&vcpu0, ISAR0, raised).unwrap_err().errno(), libc::EINVAL);
        // Without the PTRAUTH vCPU features, pointer authentication is
        // hidden (as KVM does), and not shown by a write either.
        assert_eq!(isar1 & super::super::idregs::ptrauth_fields(ISAR1), 0, "{isar1:#x}");
        assert_eq!(write(&vcpu0, ISAR1, isar1 | 0x200).unwrap_err().errno(), libc::EINVAL);
        // MIDR_EL1 is invariant.
        let midr = read(&vcpu0, 0xc000);
        assert_eq!(write(&vcpu0, 0xc000, midr ^ 0x10).unwrap_err().errno(), libc::EINVAL);
        write(&vcpu0, 0xc000, midr).unwrap();
        // An unallocated ID register: reads 0, takes only 0.
        assert_eq!(read(&vcpu0, 0xc03f), 0);
        write(&vcpu0, 0xc03f, 0).unwrap();
        assert_eq!(write(&vcpu0, 0xc03f, 1).unwrap_err().errno(), libc::EINVAL);
        // Both guests read the VM's values.
        let seen: Vec<(u64, u64)> = [vcpu0, vcpu1]
            .into_iter()
            .map(|mut vcpu| {
                std::thread::spawn(move || {
                    for (id, v) in [(PC, GUEST_BASE), (PSTATE, 0x3c5), (x_reg(4), MMIO)] {
                        vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
                    }
                    let mut got = [0u64; 2];
                    for g in &mut got {
                        match vcpu.run().unwrap() {
                            crate::VcpuExit::MmioWrite(MMIO, data) => {
                                *g = u64::from_le_bytes(data.try_into().unwrap());
                            }
                            other => panic!("{other:?}"),
                        }
                    }
                    // The VM has run: a different value is refused, the same taken.
                    assert_eq!(write(&vcpu, ISAR0, isar0).unwrap_err().errno(), libc::EBUSY);
                    write(&vcpu, ISAR0, lowered).unwrap();
                    assert_eq!(read(&vcpu, ISAR0), lowered);
                    (got[0], got[1])
                })
                .join()
                .unwrap()
            })
            .collect();
        assert_eq!(seen, vec![(lowered, isar1); 2]);
    }

    #[test]
    fn test_os_lock_is_a_register_as_on_kvm() {
        // OSLSR_EL1 as KVM has it (arch/arm64/kvm/sys_regs.c): listed by
        // KVM_GET_REG_LIST (it has set_user), so a snapshot keeps the OS
        // lock; reset to OSLSR_EL1_OSLM_IMPLEMENTED, the lock clear; only
        // OSLK may differ from that in a write (set_oslsr_el1, EINVAL). The
        // guest reads what was written and changes it with OSLAR_EL1, and
        // its change is what KVM_GET_ONE_REG reads after.
        use super::super::regs::sys_id;
        let oslsr = sys_id(0x808c);
        // mrs x0, OSLSR_EL1; str x0, [x4]; msr OSLAR_EL1, x1;
        // mrs x0, OSLSR_EL1; str x0, [x4]; b .
        const CODE: [u32; 6] = [0xd5301180, 0xf9000080, 0xd5101081, 0xd5301180, 0xf9000080, 0x14000000];
        let (_vm, mut vcpu, _mem, _len) = vm_with_memory(1, &CODE);
        let mut list = kvm_bindings::RegList::new(500).unwrap();
        vcpu.get_reg_list(&mut list).unwrap();
        assert!(list.as_slice().contains(&oslsr));
        let read = move |v: &VcpuFd| {
            let mut buf = [0u8; 8];
            v.get_one_reg(oslsr, &mut buf).unwrap();
            u64::from_le_bytes(buf)
        };
        assert_eq!(read(&vcpu), 0b1000);
        for bad in [0u64, 0b1001, 0b1100, 0b1_1010] {
            let e = vcpu.set_one_reg(oslsr, &bad.to_le_bytes()).unwrap_err().errno();
            assert_eq!(e, libc::EINVAL, "{bad:#b}");
        }
        vcpu.set_one_reg(oslsr, &0b1010u64.to_le_bytes()).unwrap();
        assert_eq!(read(&vcpu), 0b1010);
        let (seen, after) = std::thread::spawn(move || {
            for (id, v) in [(PC, GUEST_BASE), (PSTATE, 0x3c5), (x_reg(4), MMIO), (x_reg(1), 0)] {
                vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
            }
            let mut seen = [0u64; 2];
            for g in &mut seen {
                match vcpu.run().unwrap() {
                    crate::VcpuExit::MmioWrite(MMIO, data) => *g = u64::from_le_bytes(data.try_into().unwrap()),
                    other => panic!("{other:?}"),
                }
            }
            (seen, read(&vcpu))
        })
        .join()
        .unwrap();
        assert_eq!((seen, after), ([0b1010, 0b1000], 0b1000));
    }

    #[test]
    fn test_ptrauth_keys_are_hidden_without_ptrauth() {
        // As on KVM, the pointer authentication key registers (APIA, APIB,
        // APDA, APDB, APGA, LO and HI) belong to a vCPU given
        // KVM_ARM_VCPU_PTRAUTH_ADDRESS and _GENERIC only: without them they
        // are not in KVM_GET_REG_LIST, and KVM_GET_ONE_REG and
        // KVM_SET_ONE_REG fail with ENOENT (arch/arm64/kvm/sys_regs.c
        // ptrauth_visibility, REG_HIDDEN; walk_one_sys_reg,
        // kvm_sys_reg_get_user, kvm_sys_reg_set_user). So a state with keys
        // is refused by a vCPU without the features.
        use super::super::regs::sys_id;
        use kvm_bindings::{KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC};
        let keys = [0xc108u16, 0xc109, 0xc10a, 0xc10b, 0xc110, 0xc111, 0xc112, 0xc113, 0xc118, 0xc119];
        for ptrauth in [false, true] {
            let vm = Kvm::new().unwrap().create_vm().unwrap();
            let mut kvi = kvm_vcpu_init::default();
            vm.get_preferred_target(&mut kvi).unwrap();
            if ptrauth {
                kvi.features[0] |= (1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS) | (1 << KVM_ARM_VCPU_PTRAUTH_GENERIC);
            }
            let vcpu = vm.create_vcpu(0).unwrap();
            vcpu.vcpu_init(&kvi).unwrap();
            let mut list = kvm_bindings::RegList::new(500).unwrap();
            vcpu.get_reg_list(&mut list).unwrap();
            let mut buf = [0u8; 8];
            for k in keys {
                let id = sys_id(k);
                assert_eq!(list.as_slice().contains(&id), ptrauth, "{k:#x} listed, ptrauth {ptrauth}");
                let get = vcpu.get_one_reg(id, &mut buf).map_err(|e| e.errno());
                let set = vcpu.set_one_reg(id, &7u64.to_le_bytes()).map_err(|e| e.errno());
                if ptrauth {
                    assert!(get.is_ok() && set.is_ok(), "{k:#x}: {get:?} {set:?}");
                } else {
                    assert_eq!((get, set), (Err(libc::ENOENT), Err(libc::ENOENT)), "{k:#x}");
                }
            }
        }
    }

    #[test]
    fn test_ptrauth_is_a_vcpu_feature() {
        // KVM_ARM_VCPU_PTRAUTH_ADDRESS and _GENERIC, together, show pointer
        // authentication in ID_AA64ISAR1_EL1 (this host has it); one alone
        // is refused, and so is a vCPU whose features differ from the
        // first one's, as on KVM.
        use super::super::regs::sys_id;
        use kvm_bindings::{KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC};
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        let v0 = vm.create_vcpu(0).unwrap();
        let mut one = kvi;
        one.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
        assert_eq!(v0.vcpu_init(&one).unwrap_err().errno(), libc::EINVAL);
        let mut both = one;
        both.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
        v0.vcpu_init(&both).unwrap();
        let mut buf = [0u8; 8];
        v0.get_one_reg(sys_id(0xc031), &mut buf).unwrap();
        let isar1 = u64::from_le_bytes(buf);
        assert_ne!(isar1 & super::super::idregs::ptrauth_fields(0xc031), 0, "{isar1:#x}");
        let v1 = vm.create_vcpu(1).unwrap();
        assert_eq!(v1.vcpu_init(&kvi).unwrap_err().errno(), libc::EINVAL);
        v1.vcpu_init(&both).unwrap();
        assert!(vm.check_extension(crate::Cap::ArmPtrAuthAddress));
        assert!(vm.check_extension(crate::Cap::ArmPtrAuthGeneric));
        assert!(!vm.check_extension(crate::Cap::ArmSve));
    }

    #[test]
    fn test_psci_version_is_the_vms() {
        // A new VM's guest is given PSCI 1.1, KVM's default (SMCCC 1.1 and
        // KVM's services behind it); a snapshot of a VM given 1.0 or 0.2
        // restores that one, for the VM, as on KVM (kvm_arm_set_fw_reg takes
        // 0.2, 1.0 and 1.1); no other version is taken.
        use super::super::regs::{PSCI_VERSION_0_2, PSCI_VERSION_1_0, PSCI_VERSION_1_1, PSCI_VERSION_ID};
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        let vcpus: Vec<_> = (0..2)
            .map(|i| {
                let v = vm.create_vcpu(i).unwrap();
                v.vcpu_init(&kvi).unwrap();
                v
            })
            .collect();
        let read = |v: &VcpuFd| {
            let mut buf = [0u8; 8];
            v.get_one_reg(PSCI_VERSION_ID, &mut buf).unwrap();
            u64::from_le_bytes(buf)
        };
        assert_eq!(read(&vcpus[0]), PSCI_VERSION_1_1);
        for bad in [3u64, 1, 0x1_0002, 0x2_0000] {
            let err = vcpus[0].set_one_reg(PSCI_VERSION_ID, &bad.to_le_bytes()).unwrap_err();
            assert_eq!(err.errno(), libc::EINVAL, "{bad:#x}");
        }
        for version in [PSCI_VERSION_1_0, PSCI_VERSION_1_1] {
            vcpus[0].set_one_reg(PSCI_VERSION_ID, &version.to_le_bytes()).unwrap();
            assert_eq!(read(&vcpus[1]), version);
        }
        vcpus[0].set_one_reg(PSCI_VERSION_ID, &PSCI_VERSION_0_2.to_le_bytes()).unwrap();
        let mut v1 = vcpus.into_iter().nth(1).unwrap();
        let seen = std::thread::spawn(move || {
            v1.set_kvm_immediate_exit(1);
            v1.run().unwrap_err();
            read(&v1)
        })
        .join()
        .unwrap();
        assert_eq!(seen, PSCI_VERSION_0_2);
    }

    /// Sets this process's latency QoS to `LATENCY_QOS_TIER_3`
    /// (`TASK_BASE_LATENCY_QOS_POLICY`), with which macOS coalesces its
    /// timers by far more than the 1 ms of a foreground process (XNU
    /// osfmk/kern/timer_call.c `tcoal_qos_adjust`; measured: a 20 ms sleep
    /// ends a median 130 ms late, a `NOTE_CRITICAL` timer 30 us). Unlike a
    /// background policy it leaves CPU scheduling as it is, so a test sees
    /// timer coalescing alone. A VM test runs in a process of its own
    /// (tools/macos/test.sh; Hypervisor.framework has one VM per process).
    fn coalescing_tier() {
        unsafe extern "C" {
            fn task_policy_set(task: libc::mach_port_t, flavor: u32, info: *const i32, count: u32) -> i32;
        }
        const TASK_BASE_LATENCY_QOS_POLICY: u32 = 10;
        const LATENCY_QOS_TIER_3: i32 = (0xff << 16) | 4;
        // struct task_qos_policy: the latency tier, the throughput tier
        // (THROUGHPUT_QOS_TIER_UNSPECIFIED).
        let policy = [LATENCY_QOS_TIER_3, 0];
        #[allow(deprecated)]
        // SAFETY: this task's port and a task_qos_policy of two integers.
        let r = unsafe { task_policy_set(libc::mach_task_self(), TASK_BASE_LATENCY_QOS_POLICY, policy.as_ptr(), 2) };
        assert_eq!(r, 0);
    }

    /// Guest program: arms its virtual timer X0 ticks ahead, unmasked (PSTATE
    /// masks the interrupt), waits in `WFI` until the timer's condition is
    /// met (`CNTV_CTL_EL0.ISTATUS`), then writes to X4 (MMIO: the exit).
    const WFI_UNTIL_DUE: [u32; 9] = [
        0xd51be300, // msr cntv_tval_el0, x0
        0xd2800021, // mov x1, #1
        0xd51be321, // msr cntv_ctl_el0, x1
        0xd5033fdf, // isb
        0xd503207f, // 1: wfi
        0xd53be321, // mrs x1, cntv_ctl_el0
        0x3617ffc1, // tbz w1, #2, 1b
        0xf9000081, // str x1, [x4]
        0x14000000, // b .
    ];

    /// A VM with a GIC (a firing virtual timer is made pending in it), a page
    /// of memory at [`GUEST_BASE`] holding `code`, and a vCPU set to run it
    /// with interrupts masked.
    fn vm_with_gic_and_code(code: &[u32]) -> (VmFd, DeviceFd, VcpuFd) {
        let (vm, gic, vcpu) = vm_with_gic();
        let page = host_page_size() as usize;
        // SAFETY: an anonymous mapping of one page, kept for the test.
        let mem = unsafe {
            libc::mmap(std::ptr::null_mut(), page, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
        };
        assert_ne!(mem, libc::MAP_FAILED);
        // SAFETY: the page just mapped.
        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), mem.cast::<u32>(), code.len()) };
        let region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: GUEST_BASE,
            memory_size: page as u64,
            userspace_addr: mem as u64,
            flags: 0,
        };
        // SAFETY: the page stays mapped for the test.
        unsafe { vm.set_user_memory_region(region).unwrap() };
        vcpu.set_one_reg(PC, &GUEST_BASE.to_le_bytes()).unwrap();
        vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
        (vm, gic, vcpu)
    }

    /// Guest program: writes X3 to X4 (MMIO: an exit) for ever.
    const MMIO_FOR_EVER: [u32; 2] = [
        0xf9000083, // 1: str x3, [x4]
        0x17ffffff, // b 1b
    ];

    // The host's clocks, read on a vCPU's thread between its exits, never
    // read lower than the read before: Linux's CLOCK_MONOTONIC never goes
    // back (kernel/time/timekeeping.c), and Firecracker subtracts two of
    // its readings around each MMIO exit (logger/metrics.rs
    // LatencyMetricsRecorder). Each clock is read three times after every
    // exit; a lower reading is reported with the clock, which of the three
    // reads it was, and by how much.
    #[test]
    fn test_clocks_do_not_go_back_on_a_vcpu_thread() {
        unsafe extern "C" {
            fn mach_absolute_time() -> u64;
            fn mach_continuous_time() -> u64;
        }
        const NAMES: [&str; 7] = [
            "CLOCK_MONOTONIC",
            "CLOCK_REALTIME",
            "CLOCK_UPTIME_RAW",
            "CLOCK_MONOTONIC_RAW",
            "mach_absolute_time",
            "mach_continuous_time",
            "CNTVCT_EL0",
        ];
        fn clock(id: libc::clockid_t) -> u64 {
            let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: a timespec to fill.
            assert_eq!(unsafe { libc::clock_gettime(id, &mut t) }, 0);
            t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
        }
        fn read() -> [u64; 7] {
            let mut cntvct = 0u64;
            // SAFETY: reads the virtual counter, readable at EL0.
            unsafe { std::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct) };
            [
                clock(libc::CLOCK_MONOTONIC),
                clock(libc::CLOCK_REALTIME),
                clock(libc::CLOCK_UPTIME_RAW),
                clock(libc::CLOCK_MONOTONIC_RAW),
                // SAFETY: no arguments.
                unsafe { mach_absolute_time() },
                // SAFETY: no arguments.
                unsafe { mach_continuous_time() },
                cntvct,
            ]
        }
        let exits: usize = std::env::var("WICK_CLOCK_EXITS").ok().and_then(|v| v.parse().ok()).unwrap_or(300_000);
        let (_vm, _gic, mut vcpu) = vm_with_gic_and_code(&MMIO_FOR_EVER);
        for (id, v) in [(x_reg(3), 7u64), (x_reg(4), MMIO)] {
            vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
        }
        // [clock][which read after the exit]: how often lower, the most by.
        let mut back = [[(0u64, 0u64); 3]; 7];
        let mut first: Vec<String> = Vec::new();
        let mut last = read();
        let started = Instant::now();
        for exit in 0..exits {
            match vcpu.run().unwrap() {
                crate::VcpuExit::MmioWrite(MMIO, _) => {}
                other => panic!("{other:?}"),
            }
            for nth in 0..3 {
                let now = read();
                for c in 0..7 {
                    if now[c] < last[c] {
                        let by = last[c] - now[c];
                        back[c][nth].0 += 1;
                        back[c][nth].1 = back[c][nth].1.max(by);
                        if first.len() < 12 {
                            first.push(format!(
                                "exit {exit}, read {nth}: {} lower by {by} (before {:?}, now {:?})",
                                NAMES[c], last, now
                            ));
                        }
                    }
                }
                last = now;
            }
        }
        let mut report = format!("{exits} MMIO exits in {:?}, each clock read 3 times after each:\n", started.elapsed());
        for c in 0..7 {
            report.push_str(&format!(
                "  {:22} lower than the read before: {:?} times (1st, 2nd, 3rd read after an exit), the most by {:?}\n",
                NAMES[c],
                back[c].map(|b| b.0),
                back[c].map(|b| b.1)
            ));
        }
        for line in &first {
            report.push_str(&format!("  {line}\n"));
        }
        println!("{report}");
        assert!(back.iter().flatten().all(|b| b.0 == 0), "a clock went back on a vCPU's thread:\n{report}");
    }

    #[test]
    fn test_a_wfi_ends_when_its_timer_is_due() {
        // A guest waiting in WFI for its virtual timer, 20 ms ahead, runs
        // again when the timer is due, as on KVM, whose wait is an hrtimer
        // with no slack (arch/arm64/kvm/arch_timer.c): on macOS as near to
        // it as the vCPU thread's latency tier lets it (`latency`). The
        // guest's lateness is compared with a NOTE_CRITICAL kqueue timer's,
        // taken right after it in each round (the load of the machine at
        // that time), first on the thread as it is, then with the tier the
        // product gives a vCPU thread (`latency::vcpu_thread`), which is
        // what is asserted: a median under 3 ms.
        //
        // Why 3 ms. With tier 0 the kernel's leeway for this wait is
        // MIN(20 ms / 8, 1 ms), and up to as much again while the user is
        // idle: 2 ms at most (osfmk/kern/timer_call.c timer_call_slop,
        // osfmk/arm/arm_timer.c latency_qos_ns_max). Measured (M1 Pro, macOS
        // 27.2, load average 4, the user idle; three runs of this test):
        // medians 1.28, 1.35 and 1.66 ms. Without the tier (tier 1: 5 ms,
        // 10 ms idle), the same runs: medians 4.7, 6.1 and 9.5 ms. 3 ms is
        // 1 ms above the most the kernel adds with the tier and 1.7 ms under
        // the least measured without it. A median: with the tier one or two
        // rounds of 21 were up to 6.0 ms late.
        //
        // The tier in effect is the more coalesced of the thread's and the
        // task's (osfmk/kern/thread_policy.c), so this holds only in a
        // process that is not a background one: required first, by this
        // thread's own 20 ms sleeps (a foreground process's end at most
        // 10 ms late, a background one's 100 ms and more).
        const DUE: Duration = Duration::from_millis(20);
        const ROUNDS: usize = 21;
        let mut sleeps: Vec<Duration> = (0..5)
            .map(|_| {
                let start = Instant::now();
                thread::sleep(DUE);
                start.elapsed() - DUE
            })
            .collect();
        sleeps.sort_unstable();
        // <sys/resource.h>.
        const PRIO_DARWIN_PROCESS: libc::c_int = 4;
        // SAFETY: reads this process's Darwin background state.
        let darwin_bg = unsafe { libc::getpriority(PRIO_DARWIN_PROCESS, 0) };
        assert!(
            darwin_bg == 0 && sleeps[2] < Duration::from_millis(15),
            "this test needs a foreground launcher (a signed run from a terminal, tools/macos/test.sh): this \
             process is a background one, whose timers macOS coalesces whatever its threads ask for \
             (PRIO_DARWIN_PROCESS {darwin_bg}; 20 ms sleeps end {sleeps:?} late)"
        );
        let (_vm, _gic, mut vcpu) = vm_with_gic_and_code(&WFI_UNTIL_DUE);
        let mut freq = 0u64;
        // SAFETY: reads CNTFRQ_EL0, readable at EL0.
        unsafe { std::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
        let ticks = freq * DUE.as_micros() as u64 / 1_000_000;
        let control = Waiter::new().unwrap();
        // The guest's lateness less the control's, in microseconds, sorted.
        let rounds = |vcpu: &mut VcpuFd| {
            let mut later = Vec::new();
            for _ in 0..ROUNDS {
                for (id, v) in [(PC, GUEST_BASE), (x_reg(0), ticks), (x_reg(4), MMIO)] {
                    vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
                }
                let start = Instant::now();
                match vcpu.run().unwrap() {
                    crate::VcpuExit::MmioWrite(MMIO, _) => {}
                    other => panic!("{other:?}"),
                }
                let guest = start.elapsed();
                let start = Instant::now();
                assert_eq!(control.wait(Some(DUE)), Ended::Due);
                let controlled = start.elapsed();
                assert!(guest >= DUE, "the guest ran again early, after {guest:?}");
                later.push(guest.as_micros() as i128 - controlled.as_micros() as i128);
            }
            later.sort_unstable();
            later
        };
        let without = rounds(&mut vcpu);
        // SAFETY: no arguments.
        super::super::latency::vcpu_thread(unsafe { libc::pthread_self() }).unwrap();
        let with = rounds(&mut vcpu);
        println!(
            "a guest's {DUE:?} WFI, later than a NOTE_CRITICAL timer by (us, sorted): on the thread as it is, median {} \
             {without:?}; as a vCPU thread, median {} {with:?}",
            without[ROUNDS / 2],
            with[ROUNDS / 2]
        );
        assert!(
            with[ROUNDS / 2] < 3000,
            "as a vCPU thread the guest ran again a median {} us after the control: {with:?} (without the tier: {without:?})",
            with[ROUNDS / 2]
        );
    }

    #[test]
    fn test_the_vtimer_thread_runs_only_while_a_timer_is_masked() {
        // The thread that pokes vCPUs whose virtual timer is masked (the
        // guest's EOI is not trapped) makes no round while none is: an idle
        // VM costs no wakeup there (KVM has no such thread). While one is
        // masked, in a process whose timers macOS coalesces
        // ([`coalescing_tier`]), its rounds come every 1 ms, not when macOS
        // coalesces them: at least half the rounds of a 1 ms NOTE_CRITICAL
        // kqueue timer counted over the same 200 ms (the load of the machine
        // then); a coalesced 1 ms wait would make a few. Then none again
        // once the timer is unmasked. With Hypervisor.framework's GIC, as
        // Firecracker makes it, a vCPU's timer is never masked (no
        // VTIMER_ACTIVATED exit comes; measured), so the vCPU is marked
        // masked as such an exit marks it.
        const WINDOW: Duration = Duration::from_millis(200);
        coalescing_tier();
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        let shared = vm.inner.vcpus.lock().unwrap()[0].clone();
        let rounds = || vm.inner.vtimer_rounds.load(Ordering::Relaxed);
        let idle = |what: &str| {
            std::thread::sleep(Duration::from_millis(50));
            let before = rounds();
            std::thread::sleep(WINDOW);
            let n = rounds() - before;
            assert_eq!(n, 0, "the thread made {n} rounds in {WINDOW:?} with no timer masked ({what})");
        };
        idle("before");

        shared.set_vtimer_masked(&vm.inner, true);
        let control = super::super::wait::Waiter::new().unwrap();
        let before = rounds();
        let start = std::time::Instant::now();
        let mut controlled = 0;
        while start.elapsed() < WINDOW {
            assert_eq!(control.wait(Some(Duration::from_millis(1))), super::super::wait::Ended::Due);
            controlled += 1;
        }
        let masked = rounds() - before;
        println!("rounds in {WINDOW:?} while masked: {masked}, the control's {controlled}");
        assert!(2 * masked >= controlled, "{masked} rounds while masked, the control {controlled}");

        shared.set_vtimer_masked(&vm.inner, false);
        idle("after");
    }
}
