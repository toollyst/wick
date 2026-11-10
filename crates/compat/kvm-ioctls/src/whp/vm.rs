// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The WHP partition behind `VmFd`.
//!
//! A partition is created with the local APIC emulated by WHP and the CPUID
//! and MSR exits Firecracker needs, its processor count set to the maximum up
//! front (WHP fixes it before the partition is set up; fewer vCPUs may be
//! created). Guest RAM is mapped with `WHvMapGpaRange`. The I/O APIC, the
//! 8259 PICs and the 8254 PIT live in [`super::irqchip`]; GSIs raised by
//! devices (through `irqfd`s) or by `set_irq_line` are routed by it to the
//! local APIC with `WHvRequestInterrupt`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};

use wick_os::fd::{AsRawFd, RawFd};
use kvm_bindings::{
    kvm_clock_data, kvm_irqchip, kvm_pit_config, kvm_pit_state2, kvm_userspace_memory_region,
    KvmIrqRouting, KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY,
};
use vmm_sys_util::errno::Error;
use vmm_sys_util::eventfd::EventFd;
use super::whv;
use super::whv::WHV_PARTITION_HANDLE;

use super::ffi;
use super::irqchip::Irqchip;
use super::vcpu::{VcpuFd, VcpuShared};
use super::{err, Cap, DeviceFd, Handle, IoEventAddress, Result};

/// Largest number of vCPUs a partition is set up for.
pub(crate) const MAX_VCPUS: usize = 32;

/// One mapped guest-memory slot.
#[derive(Debug)]
struct Slot {
    guest_phys: u64,
    size: u64,
    /// The host address mapped at `guest_phys`.
    host: u64,
    log_dirty: bool,
}

/// A registered ioeventfd.
#[derive(Debug)]
struct IoEvent {
    addr: IoEventAddress,
    len: u32,
    datamatch: Option<u64>,
    /// The eventfd's descriptor, to match on unregister (the duplicate's
    /// differs).
    fd: RawFd,
    /// A duplicate of the eventfd, signalled on a match.
    eventfd: EventFd,
}

impl IoEvent {
    fn matches(&self, addr: &IoEventAddress, data: &[u8]) -> bool {
        if self.addr != *addr {
            return false;
        }
        if self.len != 0 && self.len as usize != data.len() {
            return false;
        }
        match self.datamatch {
            None => true,
            Some(want) => {
                let mut buf = [0u8; 8];
                buf[..data.len().min(8)].copy_from_slice(&data[..data.len().min(8)]);
                u64::from_le_bytes(buf) == want
            }
        }
    }
}

/// An irqfd: an eventfd whose signal raises `gsi`.
#[derive(Debug)]
struct IrqFd {
    gsi: u32,
    /// The eventfd's descriptor, to match on unregister.
    fd: RawFd,
    eventfd: EventFd,
}

/// The partition and everything attached to it.
#[derive(Debug)]
pub(crate) struct VmInner {
    pub(crate) part: WHV_PARTITION_HANDLE,
    memory: Mutex<HashMap<u32, Slot>>,
    ioevents: RwLock<Vec<IoEvent>>,
    irqfds: Mutex<Vec<IrqFd>>,
    pub(crate) irqchip: Mutex<Irqchip>,
    /// kvm-clock: the VM-wide reference and the wall clock MSR.
    pub(crate) pvclock: Mutex<super::pvclock::State>,
    /// Whether the partition has a TSC-deadline local APIC timer
    /// (`TscDeadlineTmrSupport`, processor features bank 1 bit 17).
    pub(crate) tsc_deadline: bool,
    pub(crate) vcpus: Mutex<Vec<Weak<VcpuShared>>>,
    /// The irqfd watcher thread wakes on this to stop (with `stop` set) or
    /// to watch the irqfds registered since it last looked.
    stop_evt: EventFd,
    stop: AtomicBool,
    watcher: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Set once `create_irq_chip` has run.
    pub(crate) has_irqchip: AtomicBool,
    /// Bumped on every interrupt request and kick, for vCPUs that WHP
    /// reported halted (see `WHvRunVpExitReasonX64Halt` in the run loop).
    halt_wake: (Mutex<u64>, Condvar),
    /// The last `WHvRequestInterrupt` failure reported, so each kind is
    /// reported once.
    request_failure: AtomicI32,
}

// SAFETY: the partition handle is an opaque value WHP accepts from any thread;
// all mutable state is behind locks.
unsafe impl Send for VmInner {}
// SAFETY: as above.
unsafe impl Sync for VmInner {}

impl Drop for VmInner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.stop_evt.write(1);
        if let Some(h) = self.watcher.lock().unwrap().take() {
            let _ = h.join();
        }
        // SAFETY: deletes the partition this VM owns, after its vCPUs are gone.
        unsafe { whv::WHvDeletePartition(self.part) };
    }
}

impl VmInner {
    /// The host address of guest RAM at `gpa`, if a slot maps it.
    pub(crate) fn host_addr(&self, gpa: u64) -> Option<u64> {
        let memory = self.memory.lock().unwrap();
        memory
            .values()
            .find(|s| gpa >= s.guest_phys && gpa < s.guest_phys + s.size)
            .map(|s| s.host + (gpa - s.guest_phys))
    }

    /// If a guest access at `addr` of `data` matches an ioeventfd, signals it
    /// and returns true (the access is consumed, no exit to Firecracker).
    pub(crate) fn match_ioevent(&self, addr: &IoEventAddress, data: &[u8]) -> bool {
        let ioevents = self.ioevents.read().unwrap();
        for ev in ioevents.iter() {
            if ev.matches(addr, data) {
                let _ = ev.eventfd.write(1);
                return true;
            }
        }
        false
    }

    /// Raises `gsi`: the irqchip routes it to the local APIC.
    pub(crate) fn raise_gsi(&self, gsi: u32, level: bool) {
        let msi = self.irqchip.lock().unwrap().raise_gsi(gsi, level);
        if let Some(msi) = msi {
            self.inject_msi(msi.0, msi.1);
        }
    }

    /// Injects an interrupt described by an MSI address/data pair.
    ///
    /// WHP's local APIC takes the request whether or not the target vCPU is
    /// running, and keeps it as KVM's in-kernel APIC does (vCPUs exist from
    /// `create_vcpu`, before any device can raise an interrupt). A request
    /// WHP refuses is lost, as KVM loses an MSI to an APIC that does not
    /// exist; there is no caller to return the error to (irqfds, the PIT),
    /// so it is reported on standard error, once per error code.
    pub(crate) fn inject_msi(&self, address: u64, data: u32) {
        let control = super::irqchip::interrupt_control(address, data);
        // SAFETY: a valid interrupt control of its size.
        let hres = unsafe {
            whv::WHvRequestInterrupt(
                self.part,
                &control,
                u32::try_from(std::mem::size_of_val(&control)).unwrap(),
            )
        };
        if hres != 0 && self.request_failure.swap(hres, Ordering::Relaxed) != hres {
            eprintln!(
                "wick: WHvRequestInterrupt(destination {}, vector {:#x}) failed: HRESULT {:#010x}; \
                 the interrupt is lost",
                control.Destination, control.Vector, hres as u32
            );
        }
        self.wake_halted();
    }

    /// Wakes vCPUs waiting in [`Self::wait_halted`].
    pub(crate) fn wake_halted(&self) {
        let (lock, cv) = &self.halt_wake;
        *lock.lock().unwrap() += 1;
        cv.notify_all();
    }

    /// Waits for the next [`Self::wake_halted`], at most `timeout`.
    pub(crate) fn wait_halted(&self, timeout: std::time::Duration) {
        let (lock, cv) = &self.halt_wake;
        let guard = lock.lock().unwrap();
        let seen = *guard;
        let _unused = cv
            .wait_timeout_while(guard, timeout, |n| *n == seen)
            .unwrap();
    }
}

/// Finds a mapped VM's inner state from any live VM (for the vCPU thread's
/// ioeventfd/irqchip callbacks, which are reached through the VcpuShared).
impl VmFd {
    pub(crate) fn create() -> Result<VmFd> {
        let part = ffi::create_partition()?;
        let inner = VmInner::setup(part).inspect_err(|_| {
            // SAFETY: cleans up the partition we just created on failure.
            unsafe { whv::WHvDeletePartition(part) };
        })?;
        let fd = Handle::new()?;
        Ok(VmFd {
            inner: Arc::new(inner),
            fd,
        })
    }
}

impl VmInner {
    fn setup(part: WHV_PARTITION_HANDLE) -> Result<VmInner> {
        // Processor count must be set before the partition is set up.
        let count = u32::try_from(MAX_VCPUS).unwrap();
        // SAFETY: a u32 property value for ProcessorCount.
        unsafe {
            ffi::set_partition_property(
                part,
                whv::WHvPartitionPropertyCodeProcessorCount,
                &count,
            )?;
        }
        // The speculation controls (IA32_SPEC_CTRL, IA32_PRED_CMD: IBRS,
        // STIBP, IBPB, SSBD), which a partition's default processor features
        // lack (measured on WHP): KVM gives a guest the host's, and a Linux
        // guest that CPUID tells about IBPB takes a #GP on its first IBPB
        // without them. They make every VM exit costlier, which only matters
        // to a guest that times itself against exits (TSC calibration against
        // the PIT); a guest with kvm-clock (`pvclock`) does not.
        const SPECULATION_CONTROLS: u64 = (1 << 44) | (1 << 45) | (1 << 46) | (1 << 48);
        let mut written = 0u32;
        let mut cap: whv::WHV_PROCESSOR_FEATURES_BANKS = whv::WHV_PROCESSOR_FEATURES_BANKS::default();
        let mut banks: whv::WHV_PROCESSOR_FEATURES_BANKS = whv::WHV_PROCESSOR_FEATURES_BANKS::default();
        let size = u32::try_from(core::mem::size_of_val(&banks)).unwrap();
        // SAFETY: output buffers of the size passed.
        let got = unsafe {
            whv::WHvGetCapability(
                whv::WHvCapabilityCodeProcessorFeaturesBanks,
                (&raw mut cap).cast(),
                size,
                &mut written,
            ) >= 0
                && whv::WHvGetPartitionProperty(
                    part,
                    whv::WHvPartitionPropertyCodeProcessorFeaturesBanks,
                    (&raw mut banks).cast(),
                    size,
                    &mut written,
                ) >= 0
        };
        // SAFETY: plain data; bank 1 is the second word.
        let tsc_deadline =
            got && banks.BanksCount > 1 && unsafe { banks.Anonymous.AsUINT64[1] } & (1 << 17) != 0;
        if got && banks.BanksCount > 0 {
            // SAFETY: plain data; bank 0 is the first word of both.
            unsafe {
                banks.Anonymous.AsUINT64[0] |= cap.Anonymous.AsUINT64[0] & SPECULATION_CONTROLS;
            }
            // SAFETY: the structure read from the partition, with bits added.
            unsafe {
                ffi::set_partition_property(
                    part,
                    whv::WHvPartitionPropertyCodeProcessorFeaturesBanks,
                    &banks,
                )?;
            }
        }
        // Likewise every XSAVE state component WHP supports.
        let mut xsave: u64 = 0;
        // SAFETY: an output buffer of the size passed.
        let got = unsafe {
            whv::WHvGetCapability(
                whv::WHvCapabilityCodeProcessorXsaveFeatures,
                (&raw mut xsave).cast(),
                8,
                &mut written,
            )
        };
        if got >= 0 && xsave != 0 {
            // SAFETY: a u64 property value for ProcessorXsaveFeatures.
            unsafe {
                ffi::set_partition_property(part, whv::WHvPartitionPropertyCodeProcessorXsaveFeatures, &xsave)?;
            }
        }
        // Emulate the local APIC in WHP (xAPIC).
        let apic_mode: i32 = whv::WHvX64LocalApicEmulationModeXApic;
        // SAFETY: an i32 property value for LocalApicEmulationMode.
        unsafe {
            ffi::set_partition_property(
                part,
                whv::WHvPartitionPropertyCodeLocalApicEmulationMode,
                &apic_mode,
            )?;
        }
        // Exit on CPUID and MSR accesses so the backend can answer them
        // (X64CpuidExit | X64MsrExit), and on hypercalls (HypercallExit), so
        // a guest's VMCALL/VMMCALL gets KVM's answers instead of #UD.
        let mut exits_bits: u64 = (1 << 0) | (1 << 1);
        let mut supported: u64 = 0;
        let mut n = 0u32;
        // SAFETY: an output buffer of the size passed.
        if unsafe {
            whv::WHvGetCapability(
                whv::WHvCapabilityCodeExtendedVmExits,
                (&raw mut supported).cast(),
                8,
                &mut n,
            )
        } >= 0
        {
            exits_bits |= supported & (1 << 5);
        }
        // SAFETY: a u64 value for ExtendedVmExits.
        unsafe {
            ffi::set_partition_property(
                part,
                whv::WHvPartitionPropertyCodeExtendedVmExits,
                &exits_bits,
            )?;
        }
        // The CPUID leaves the backend intercepts (to apply Firecracker's
        // configured CPUID); others use WHP's own virtualised values.
        const CPUID_EXITS: &[u32] = &[
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0xa, 0xb, 0xd, 0xf, 0x10, 0x14, 0x15, 0x16,
            0x1f, 0x4000_0000, 0x4000_0001, 0x8000_0000, 0x8000_0001, 0x8000_0002, 0x8000_0003,
            0x8000_0004, 0x8000_0005, 0x8000_0006, 0x8000_0007, 0x8000_0008, 0x8000_001d,
            0x8000_001e,
        ];
        // SAFETY: an array of u32 CPUID function numbers.
        ffi::hr(unsafe {
            whv::WHvSetPartitionProperty(
                part,
                whv::WHvPartitionPropertyCodeCpuidExitList,
                CPUID_EXITS.as_ptr().cast(),
                u32::try_from(std::mem::size_of_val(CPUID_EXITS)).unwrap(),
            )
        })?;
        // SAFETY: completes partition setup.
        ffi::hr(unsafe { whv::WHvSetupPartition(part) })?;

        let stop_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(io_err)?;
        Ok(VmInner {
            part,
            memory: Mutex::new(HashMap::new()),
            ioevents: RwLock::new(Vec::new()),
            irqfds: Mutex::new(Vec::new()),
            irqchip: Mutex::new(Irqchip::new()),
            pvclock: Mutex::new(super::pvclock::State::default()),
            tsc_deadline,
            vcpus: Mutex::new(Vec::new()),
            stop_evt,
            stop: AtomicBool::new(false),
            watcher: Mutex::new(None),
            has_irqchip: AtomicBool::new(false),
            halt_wake: (Mutex::new(0), Condvar::new()),
            request_failure: AtomicI32::new(0),
        })
    }
}

fn io_err(e: std::io::Error) -> Error {
    Error::new(e.raw_os_error().unwrap_or(libc::EINVAL))
}

/// Wrapper over a WHP partition.
#[derive(Debug)]
pub struct VmFd {
    inner: Arc<VmInner>,
    fd: Handle,
}

impl VmFd {
    /// Maps, remaps or unmaps a guest-memory slot (a zero `memory_size`
    /// unmaps the slot).
    ///
    /// # Safety
    /// `region.userspace_addr` must point to `region.memory_size` bytes of
    /// valid host memory that stays mapped while the region is registered.
    pub unsafe fn set_user_memory_region(
        &self,
        region: kvm_userspace_memory_region,
    ) -> Result<()> {
        let mut memory = self.inner.memory.lock().unwrap();
        // Remove a previous mapping in this slot.
        if let Some(old) = memory.remove(&region.slot) {
            // SAFETY: unmaps a range this VM mapped.
            ffi::hr(unsafe {
                whv::WHvUnmapGpaRange(self.inner.part, old.guest_phys, old.size)
            })?;
        }
        if region.memory_size == 0 {
            return Ok(());
        }
        let readonly = region.flags & KVM_MEM_READONLY != 0;
        let log_dirty = region.flags & KVM_MEM_LOG_DIRTY_PAGES != 0;
        let mut flags = whv::WHvMapGpaRangeFlagRead | whv::WHvMapGpaRangeFlagExecute;
        if !readonly {
            flags |= whv::WHvMapGpaRangeFlagWrite;
        }
        if log_dirty {
            flags |= whv::WHvMapGpaRangeFlagTrackDirtyPages;
        }
        // SAFETY: the caller's contract for `userspace_addr`/`memory_size`.
        ffi::hr(unsafe {
            whv::WHvMapGpaRange(
                self.inner.part,
                region.userspace_addr as *const core::ffi::c_void,
                region.guest_phys_addr,
                region.memory_size,
                flags,
            )
        })?;
        memory.insert(
            region.slot,
            Slot {
                guest_phys: region.guest_phys_addr,
                size: region.memory_size,
                host: region.userspace_addr,
                log_dirty,
            },
        );
        Ok(())
    }

    /// The dirty-page bitmap of a slot (one bit per guest page), cleared by
    /// the query.
    pub fn get_dirty_log(&self, slot: u32, memory_size: usize) -> Result<Vec<u64>> {
        let memory = self.inner.memory.lock().unwrap();
        let s = memory.get(&slot).ok_or_else(|| Error::new(libc::ENOENT))?;
        if !s.log_dirty {
            return err(libc::EINVAL);
        }
        let page = 4096usize;
        let pages = memory_size.div_ceil(page);
        let words = pages.div_ceil(64);
        let mut bitmap = vec![0u64; words];
        // SAFETY: a bitmap buffer of `words` u64s for `memory_size` bytes.
        ffi::hr(unsafe {
            whv::WHvQueryGpaRangeDirtyBitmap(
                self.inner.part,
                s.guest_phys,
                memory_size as u64,
                bitmap.as_mut_ptr(),
                u32::try_from(words * 8).unwrap(),
            )
        })?;
        Ok(bitmap)
    }

    /// Registers an eventfd that is signalled on a matching guest I/O write.
    pub fn register_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        let datamatch_val = datamatch.into();
        let has_datamatch = std::mem::size_of::<T>() > 0;
        let eventfd = fd.try_clone().map_err(io_err)?;
        self.inner.ioevents.write().unwrap().push(IoEvent {
            addr: *addr,
            len: 0,
            datamatch: has_datamatch.then_some(datamatch_val),
            fd: fd.as_raw_fd(),
            eventfd,
        });
        Ok(())
    }

    /// Removes an eventfd registered with [`Self::register_ioevent`].
    pub fn unregister_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        let datamatch_val = datamatch.into();
        let has_datamatch = std::mem::size_of::<T>() > 0;
        let want = has_datamatch.then_some(datamatch_val);
        let mut ioevents = self.inner.ioevents.write().unwrap();
        let before = ioevents.len();
        ioevents
            .retain(|ev| !(ev.addr == *addr && ev.datamatch == want && ev.fd == fd.as_raw_fd()));
        if ioevents.len() == before {
            return err(libc::ENOENT);
        }
        Ok(())
    }

    /// Routes `fd` to raise `gsi` when signalled.
    pub fn register_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        let eventfd = fd.try_clone().map_err(io_err)?;
        self.inner.irqfds.lock().unwrap().push(IrqFd {
            gsi,
            fd: fd.as_raw_fd(),
            eventfd,
        });
        self.ensure_watcher();
        // The watcher waits on the irqfds it knew of: it looks again now,
        // so a signal right after registration is delivered at once.
        let _ = self.inner.stop_evt.write(1);
        Ok(())
    }

    /// Stops routing `fd` to `gsi`.
    pub fn unregister_irqfd(&self, fd: &EventFd, gsi: u32) -> Result<()> {
        let mut irqfds = self.inner.irqfds.lock().unwrap();
        let before = irqfds.len();
        irqfds.retain(|i| !(i.gsi == gsi && i.fd == fd.as_raw_fd()));
        if irqfds.len() == before {
            return err(libc::ENOENT);
        }
        drop(irqfds);
        let _ = self.inner.stop_evt.write(1);
        Ok(())
    }

    /// Sets the GSI routing table (legacy IOAPIC pins and MSI entries).
    pub fn set_gsi_routing(&self, irq_routing: &KvmIrqRouting) -> Result<()> {
        self.inner
            .irqchip
            .lock()
            .unwrap()
            .set_gsi_routing(irq_routing.as_slice());
        Ok(())
    }

    /// Raises or lowers a legacy IRQ line.
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        self.inner.raise_gsi(irq, active);
        Ok(())
    }

    /// Reports an MSI as a direct interrupt request.
    pub fn signal_msi(&self, msi: kvm_bindings::kvm_msi) -> Result<std::os::raw::c_int> {
        self.inner.inject_msi(u64::from(msi.address_lo) | (u64::from(msi.address_hi) << 32), msi.data);
        Ok(1)
    }

    /// Creates vCPU `id`.
    pub fn create_vcpu(&self, id: u64) -> Result<VcpuFd> {
        super::vcpu::create(self.inner.clone(), id)
    }

    /// Another handle of the vCPU whose descriptor `fd` duplicates (Firecracker
    /// makes one per vCPU thread, from `dup`, to kick it); `EBADF` for any
    /// other descriptor.
    ///
    /// # Safety
    /// `fd` must be a valid descriptor; ownership moves to the returned handle
    /// (it is closed on error too).
    pub unsafe fn create_vcpu_from_rawfd(&self, fd: RawFd) -> Result<VcpuFd> {
        super::vcpu::from_duplicate(&self.inner, fd)
    }

    /// Accepted: WHP manages the TSS/identity map itself, so there is nothing
    /// to place (the guest's page tables use whatever Firecracker set up).
    pub fn set_tss_address(&self, _offset: usize) -> Result<()> {
        Ok(())
    }

    /// Accepted, like `set_tss_address`.
    pub fn set_identity_map_address(&self, _address: u64) -> Result<()> {
        Ok(())
    }

    /// Creates the userspace I/O APIC, PICs and (later) PIT.
    pub fn create_irq_chip(&self) -> Result<()> {
        self.inner.irqchip.lock().unwrap().enable();
        self.inner.has_irqchip.store(true, Ordering::Release);
        Ok(())
    }

    /// Creates the 8254 PIT.
    pub fn create_pit2(&self, pit_config: kvm_pit_config) -> Result<()> {
        self.inner.irqchip.lock().unwrap().create_pit(pit_config, &self.inner);
        Ok(())
    }

    /// The PIT state.
    pub fn get_pit2(&self) -> Result<kvm_pit_state2> {
        Ok(self.inner.irqchip.lock().unwrap().pit_state())
    }

    /// Restores the PIT state.
    pub fn set_pit2(&self, pitstate: &kvm_pit_state2) -> Result<()> {
        self.inner
            .irqchip
            .lock()
            .unwrap()
            .set_pit_state(pitstate, &self.inner);
        Ok(())
    }

    /// The guest clock (reference time).
    pub fn get_clock(&self) -> Result<kvm_clock_data> {
        Ok(self.inner.irqchip.lock().unwrap().clock())
    }

    /// Restores the guest clock.
    pub fn set_clock(&self, clock: &kvm_clock_data) -> Result<()> {
        self.inner.irqchip.lock().unwrap().set_clock(clock);
        self.inner.pvclock.lock().unwrap().reset();
        Ok(())
    }

    /// The state of one interrupt chip (PIC master/slave or IOAPIC).
    pub fn get_irqchip(&self, irqchip: &mut kvm_irqchip) -> Result<()> {
        self.inner.irqchip.lock().unwrap().get_chip(irqchip);
        Ok(())
    }

    /// Restores the state of one interrupt chip.
    pub fn set_irqchip(&self, irqchip: &kvm_irqchip) -> Result<()> {
        self.inner.irqchip.lock().unwrap().set_chip(irqchip);
        Ok(())
    }

    /// Not supported on x86_64.
    pub fn create_device(
        &self,
        _device: &mut kvm_bindings::kvm_create_device,
    ) -> Result<DeviceFd> {
        DeviceFd::unsupported()
    }

    /// Size of the `kvm_run` area.
    pub fn run_size(&self) -> usize {
        std::mem::size_of::<kvm_bindings::kvm_run>()
    }

    pub fn check_extension_raw(&self, c: u64) -> i32 {
        super::cap::supported(c)
    }

    pub fn check_extension_int(&self, c: Cap) -> i32 {
        self.check_extension_raw(u64::from(c as u32))
    }

    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) > 0
    }

    /// Starts the thread that waits on registered irqfds and raises their
    /// GSIs, if it is not already running.
    fn ensure_watcher(&self) {
        let mut watcher = self.inner.watcher.lock().unwrap();
        if watcher.is_some() {
            return;
        }
        let inner = self.inner.clone();
        *watcher = Some(std::thread::spawn(move || watch_irqfds(&inner)));
    }
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Waits on every registered irqfd; when one signals, raises its GSI. Woken
/// by `stop_evt` to exit (`stop` set) or to pick up the irqfds registered or
/// removed since.
fn watch_irqfds(inner: &Arc<VmInner>) {
    use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
    // Without it no device interrupt would ever be delivered.
    let epoll = Epoll::new().expect("wick: the irqfd watcher cannot create its epoll");
    let mut registered: HashMap<RawFd, (u32, u64)> = HashMap::new();
    let stop_fd = inner.stop_evt.as_raw_fd();
    let _ = epoll.ctl(
        ControlOperation::Add,
        stop_fd,
        EpollEvent::new(EventSet::IN, stop_fd as u64),
    );
    while !inner.stop.load(Ordering::Acquire) {
        // Reconcile the registered set with the current irqfds.
        {
            let irqfds = inner.irqfds.lock().unwrap();
            let current: HashMap<RawFd, (u32, u64)> = irqfds
                .iter()
                .map(|i| (i.eventfd.as_raw_fd(), (i.gsi, i.eventfd.as_raw_fd() as u64)))
                .collect();
            for fd in registered.keys().copied().collect::<Vec<_>>() {
                if !current.contains_key(&fd) {
                    let _ = epoll.ctl(ControlOperation::Delete, fd, EpollEvent::default());
                    registered.remove(&fd);
                }
            }
            for (&fd, &(gsi, _)) in &current {
                if let std::collections::hash_map::Entry::Vacant(e) = registered.entry(fd) {
                    let _ = epoll.ctl(
                        ControlOperation::Add,
                        fd,
                        EpollEvent::new(EventSet::IN, fd as u64),
                    );
                    e.insert((gsi, fd as u64));
                }
            }
        }
        let mut events = [EpollEvent::default(); 16];
        let n = match epoll.wait(1000, &mut events) {
            Ok(n) => n,
            Err(_) => continue,
        };
        for ev in &events[..n] {
            let fd = ev.data() as RawFd;
            if fd == stop_fd {
                let _ = inner.stop_evt.read();
                // Stopping, or the irqfd set changed: the loop looks again.
                continue;
            }
            // Drain the eventfd and raise its GSI (edge: raise then lower).
            if let Some(&(gsi, _)) = registered.get(&fd) {
                // Clear the signal (the eventfd keeps a counter) through the
                // eventfd itself: a Windows eventfd is a counter in a section
                // and an event, which a plain `read` of the descriptor does not
                // reach, and an uncleared eventfd stays readable, so the GSI
                // would be raised again and again (an interrupt storm the
                // guest reports as "nobody cared").
                let cleared = {
                    let irqfds = inner.irqfds.lock().unwrap();
                    irqfds
                        .iter()
                        .find(|i| i.eventfd.as_raw_fd() == fd)
                        .map(|i| i.eventfd.read().is_ok())
                };
                if cleared == Some(true) {
                    inner.raise_gsi(gsi, true);
                    inner.raise_gsi(gsi, false);
                }
            }
        }
    }
}
