// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! VM handle: guest memory, ioeventfds, irqfds and interrupt routing.

use std::collections::HashMap;
use std::fs::File;
use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::thread;
use std::time::Duration;

use kvm_bindings::{
    KVM_ARM_TARGET_GENERIC_V8, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI,
    KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY, KvmIrqRouting, kvm_create_device, kvm_device_attr,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3, kvm_msi,
    kvm_userspace_memory_region, kvm_vcpu_init,
};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use super::device::{DeviceFd, DeviceKind};
use super::ffi::*;
use super::vcpu::{VcpuFd, VcpuShared};
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

fn host_page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

#[derive(Debug)]
struct IrqFd {
    fd: EventFd,
    gsi: u32,
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
    memory: Mutex<HashMap<u32, Slot>>,
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
    /// Value of `mach_absolute_time()` at which the guest counter reads 0.
    pub(crate) vtimer_offset: u64,
    /// Register values of a freshly created Hypervisor.framework vCPU, read
    /// once from a scratch vCPU (see `VcpuFd::get_one_reg`).
    pub(crate) reset_regs: OnceLock<std::result::Result<HashMap<u64, Vec<u8>>, i32>>,
    /// GIC registers of a freshly created vCPU, read from the first one.
    pub(crate) gic_cpu_reset: OnceLock<HashMap<super::gic::CpuReg, u64>>,
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
    for slot in memory.values() {
        let start = host.max(slot.host);
        let end = (host + len).min(slot.host + slot.size);
        let mut addr = start - (start - slot.host) % page;
        while addr < end {
            let ipa = slot.ipa + (addr - slot.host);
            let flags = if present { slot.flags(ipa) } else { 0 };
            // SAFETY: changes the permissions of one page of a slot we mapped.
            unsafe { hv_vm_protect(ipa, page as usize, flags) };
            addr += page;
        }
    }
}

impl Slot {
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
        memory
            .values()
            .find(|s| ipa >= s.ipa && ipa < s.ipa + s.size)
            .map(|s| s.host + (ipa - s.ipa))
    }

    /// A guest fault on RAM whose page allows the access (a permission change
    /// raced with the fault): restores the page's permissions. Returns false
    /// if `ipa` is not RAM or the access is not allowed (e.g. a write to a
    /// read-only slot, which is MMIO as on KVM).
    pub(crate) fn stale_fault(&self, ipa: u64, write: bool) -> bool {
        let memory = self.memory.lock().unwrap();
        let Some(slot) = memory
            .values()
            .find(|s| ipa >= s.ipa && ipa < s.ipa + s.size)
        else {
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
        let memory = self.memory.lock().unwrap();
        let page = host_page_size();
        for slot in memory.values() {
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
        match self.route(gsi) {
            Some(Route::Spi(intid)) => {
                // A pulse, like KVM's irqfd: an edge for edge-triggered SPIs, and a
                // level that is dropped again for level-triggered ones.
                // SAFETY: plain calls; invalid ids are reported as errors.
                unsafe {
                    hv_gic_set_spi(intid, true);
                    hv_gic_set_spi(intid, false);
                }
            }
            Some(Route::Msi { address, data }) => {
                // SAFETY: plain call; a bad address or SPI is reported as an error.
                unsafe { hv_gic_send_msi(address, data) };
            }
            None => {}
        }
        for vcpu in self.vcpus.lock().unwrap().iter() {
            vcpu.wake();
        }
    }

    /// Waits for irqfds and injects their interrupts. The thread holds the VM
    /// only while it handles events, so dropping the `VmFd` (which stops and
    /// joins it) releases the VM at once.
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
        for (_, slot) in self.memory.lock().unwrap().drain() {
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
            memory: Mutex::new(HashMap::new()),
            ioevents: RwLock::new(Vec::new()),
            irq: Mutex::new(IrqState::default()),
            epoll: epoll.clone(),
            stop_evt,
            stop: AtomicBool::new(false),
            handle: handle.token(),
            torn_down: AtomicBool::new(false),
            vcpus: Mutex::new(Vec::new()),
            gic: Mutex::new(GicConfig::default()),
            // SAFETY: plain call.
            vtimer_offset: unsafe { mach_absolute_time() },
            reset_regs: OnceLock::new(),
            gic_cpu_reset: OnceLock::new(),
        });
        libc::wick_uffd::set_stage2_hook(uffd_stage2);
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
        vm.threads.push(
            thread::Builder::new()
                .name("wick_hvf_vtimer".into())
                .spawn(move || vtimer_thread(weak))
                .map_err(io_err)?,
        );
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
        let mut memory = self.inner.memory.lock().unwrap();
        if let Some(slot) = memory.remove(&region.slot) {
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
        let flags = if readonly || track { RX } else { RWX };
        // SAFETY: the caller guarantees the host range is valid for the slot's lifetime.
        check(unsafe {
            hv_vm_map(
                region.userspace_addr as *mut _,
                region.guest_phys_addr,
                region.memory_size as usize,
                flags,
            )
        })?;
        let dirty = track.then(|| {
            let pages = region.memory_size.div_ceil(host_page_size());
            (0..pages.div_ceil(64))
                .map(|_| std::sync::atomic::AtomicU64::new(0))
                .collect()
        });
        // Pages a userfaultfd has not filled yet fault in stage 2.
        libc::wick_uffd::for_each_missing(region.userspace_addr, region.memory_size, |host, len| {
            let ipa = region.guest_phys_addr + (host - region.userspace_addr);
            // SAFETY: removes access to pages of the range mapped above.
            unsafe { hv_vm_protect(ipa, len as usize, 0) };
        });
        memory.insert(
            region.slot,
            Slot {
                ipa: region.guest_phys_addr,
                size: region.memory_size,
                host: region.userspace_addr,
                readonly,
                dirty,
            },
        );
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
        let memory = self.inner.memory.lock().unwrap();
        let Some(s) = memory.get(&slot) else {
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
    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        self.fd.check()?;
        let clone = fd.try_clone().map_err(io_err)?;
        let raw = clone.as_raw_fd();
        self.inner
            .irq
            .lock()
            .unwrap()
            .irqfds
            .insert(raw, IrqFd { fd: clone, gsi });
        if let Err(e) = self.inner.epoll.ctl(
            ControlOperation::Add,
            raw,
            EpollEvent::new(EventSet::IN, raw as u64),
        ) {
            self.inner.irq.lock().unwrap().irqfds.remove(&raw);
            return Err(io_err(e));
        }
        Ok(())
    }

    /// Removes an irqfd registered with [`Self::register_irqfd`].
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
        irq.irqfds.remove(&raw);
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
        check(unsafe { hv_gic_set_spi(irq & 0xffff, active) })
    }

    /// Sends an MSI through the MSI frame (`data` is the SPI). Returns 1, as
    /// KVM does when the interrupt is delivered.
    pub fn signal_msi(&self, msi: kvm_msi) -> Result<c_int> {
        self.fd.check()?;
        let address = u64::from(msi.address_hi) << 32 | u64::from(msi.address_lo);
        // SAFETY: plain call; a bad address or SPI is reported as an error.
        check(unsafe { hv_gic_send_msi(address, msi.data) })?;
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

/// Forces an exit from vCPUs whose virtual timer is masked, so that the mask is
/// re-evaluated (the guest's EOI of the timer interrupt is not trapped).
fn vtimer_thread(vm: Weak<VmInner>) {
    loop {
        thread::sleep(Duration::from_millis(1));
        let Some(vm) = vm.upgrade() else { return };
        if vm.stop.load(Ordering::Acquire) {
            return;
        }
        for vcpu in vm.vcpus.lock().unwrap().iter() {
            vcpu.poke_if_vtimer_masked();
        }
    }
}

fn io_err(e: std::io::Error) -> super::Error {
    super::Error::new(e.raw_os_error().unwrap_or(libc::EIO))
}
