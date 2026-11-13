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
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};

use wick_os::fd::{AsRawFd, RawFd};
use kvm_bindings::{
    kvm_clock_data, kvm_irqchip, kvm_pit_config, kvm_pit_state2, kvm_userspace_memory_region,
    KvmIrqRouting, KVM_CLOCK_HOST_TSC, KVM_CLOCK_REALTIME, KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY,
};
use vmm_sys_util::errno::Error;
use vmm_sys_util::eventfd::EventFd;
use super::whv;
use super::whv::{WHV_PARTITION_HANDLE, WHV_REGISTER_NAME};

use super::ffi;
use super::guest_mem::{self, Slot};
use super::irqchip::Irqchip;
use super::vcpu::{VcpuFd, VcpuShared};
use super::{err, Cap, DeviceFd, Handle, IoEventAddress, Result};

/// Largest number of vCPUs a partition is set up for.
pub(crate) const MAX_VCPUS: usize = 32;

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

/// Whether an ioeventfd at `addr` of `len` bytes (0: any) with `datamatch`
/// (None: any value) collides with `ev`, by KVM's rule (virt/kvm/eventfd.c,
/// ioeventfd_check_collision, which kvm_assign_ioeventfd_idx answers with
/// -EEXIST): the same bus and address, and either length 0, or the same
/// length and either without a datamatch or the same datamatch.
fn collides(ev: &IoEvent, addr: &IoEventAddress, len: u32, datamatch: Option<u64>) -> bool {
    ev.addr == *addr
        && (ev.len == 0
            || len == 0
            || (ev.len == len
                && (ev.datamatch.is_none() || datamatch.is_none() || ev.datamatch == datamatch)))
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
    /// Unregistered irqfds whose eventfd the watcher may still have in its
    /// epoll: kept open until the watcher has taken them out of it, as
    /// KVM's irqfd holds its eventfd until it is deassigned (see
    /// [`retire_irqfd`]). Locked after `irqfds`.
    retired_irqfds: Mutex<Vec<IrqFd>>,
    pub(crate) irqchip: Mutex<Irqchip>,
    /// kvm-clock: the VM-wide reference and the wall clock MSR.
    pub(crate) pvclock: Mutex<super::pvclock::State>,
    /// The vCPUs' TSC-deadline timers (`tscdeadline`).
    pub(crate) deadlines: super::tscdeadline::Timers,
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
    /// The partition's exception exits ([`Exits`]) and the condvar the
    /// vCPUs held out of the guest wait on. A leaf lock: nothing else is
    /// locked while it is held, so it is in no lock-order cycle.
    bp_window: (Mutex<Exits>, Condvar),
    /// Who has the exception exits, with every other vCPU held out of the
    /// guest: a vCPU's index (its #BP window), [`OWNER_ALL`] (a change of
    /// gdb's), -1 nobody. Read by every entry.
    pub(crate) bp_owner: AtomicI64,
}

/// The partition's exception exits (`ExceptionExitBitmap`), which are
/// changed only with every vCPU out of the guest, as QEMU changes them
/// ("whpx_set_exception_exit_bitmap() cannot be called if one or more VCPUs
/// are already running", target/i386/whpx/whpx-all.c, v9.2.0). In
/// `test_bp_window_holds_the_other_vcpus` at 578b04f, where the test's
/// set_guest_debug of vCPU 0 changed them while vCPU 1 ran, vCPU 1's run
/// failed with WHV_E_INVALID_VP_STATE (0x80370308; measured on an AMD host,
/// the cause read from the code and QEMU's note).
#[derive(Debug, Default)]
struct Exits {
    /// gdb's, from the last `KVM_SET_GUEST_DEBUG`.
    gdb: u64,
    /// What the partition has, if known.
    written: Option<u64>,
}

/// [`VmInner::bp_owner`] for a change of gdb's exception exits: no vCPU
/// enters the guest.
const OWNER_ALL: i64 = i64::MAX;

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
            // The irqfd watcher holds the VM only while it handles a wake, so
            // the last reference can be its own: it then returns after this
            // drop, without another wait, and must not be waited for here.
            if h.thread().id() != std::thread::current().id() {
                let _ = h.join();
            }
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

    /// The slot table, for what the backend writes into guest RAM as KVM
    /// does (`pvclock`, `guest_mem`).
    pub(crate) fn ram(&self) -> &super::pvclock::Ram {
        &self.memory
    }

    /// Writes `data` into guest RAM at `gpa` as KVM's `kvm_write_guest`
    /// does ([`guest_mem::write`]): false (`-EFAULT`) at a page no slot maps
    /// or a read-only one. The slot table stays locked for the copy, so a
    /// slot is not unmapped under it.
    pub(crate) fn write_guest(&self, gpa: u64, data: &[u8]) -> bool {
        guest_mem::write(&mut self.memory.lock().unwrap(), gpa, data)
    }

    /// Reads guest RAM at `gpa` into `buf` as KVM's `kvm_read_guest` does
    /// ([`guest_mem::read`]): false at a page no slot maps.
    pub(crate) fn read_guest(&self, gpa: u64, buf: &mut [u8]) -> bool {
        guest_mem::read(&mut self.memory.lock().unwrap(), gpa, buf)
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
        #[cfg(any(test, feature = "whp-trace"))]
        let before = ffi::trace::stack();
        // SAFETY: a valid interrupt control of its size.
        let hres = unsafe {
            whv::WHvRequestInterrupt(
                self.part,
                &control,
                u32::try_from(std::mem::size_of_val(&control)).unwrap(),
            )
        };
        #[cfg(any(test, feature = "whp-trace"))]
        ffi::trace::note("WHvRequestInterrupt", control.Destination, &[], None, before, hres);
        if hres != 0 && self.request_failure.swap(hres, Ordering::Relaxed) != hres {
            ffi::report(
                log::Level::Error,
                &format!(
                    "wick: WHvRequestInterrupt(destination {}, vector {:#x}) failed: HRESULT {:#010x}; \
                     the interrupt is lost",
                    control.Destination, control.Vector, hres as u32
                ),
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

    /// Writes `bitmap` as the partition's exception exits, unless it has
    /// them. The caller has every vCPU out of the guest ([`Exits`]).
    fn write_exits(&self, exits: &mut Exits, bitmap: u64) -> Result<()> {
        if exits.written == Some(bitmap) {
            return Ok(());
        }
        // SAFETY: a u64 value for ExceptionExitBitmap.
        unsafe { ffi::set_partition_property(self.part, whv::WHvPartitionPropertyCodeExceptionExitBitmap, &bitmap) }?;
        exits.written = Some(bitmap);
        Ok(())
    }

    /// Takes the exception exits for `owner` once nobody has them: from then
    /// on no other vCPU enters the guest. `false`, with nothing taken, if
    /// `immediate_exit` (a vCPU's) is set meanwhile.
    fn take_exits(&self, owner: i64, immediate_exit: Option<&AtomicU8>) -> bool {
        let (lock, cv) = &self.bp_window;
        let mut exits = lock.lock().unwrap();
        loop {
            if immediate_exit.is_some_and(|flag| flag.load(Ordering::SeqCst) != 0) {
                return false;
            }
            if self.bp_owner.load(Ordering::SeqCst) < 0 {
                break;
            }
            exits = cv.wait(exits).unwrap();
        }
        self.bp_owner.store(owner, Ordering::SeqCst);
        true
    }

    /// Sets gdb's exception exits to `bitmap`: with every vCPU held out of
    /// the guest for the write, or, while a #BP window or another change
    /// has them, at its end (which writes gdb's under the same lock).
    pub(crate) fn set_debug_bitmap(&self, bitmap: u64) -> Result<()> {
        let (lock, cv) = &self.bp_window;
        {
            let mut exits = lock.lock().unwrap();
            exits.gdb = bitmap;
            if self.bp_owner.load(Ordering::SeqCst) >= 0 || exits.written == Some(bitmap) {
                return Ok(());
            }
        }
        self.take_exits(OWNER_ALL, None);
        super::vcpu::hold_vcpus(self, None);
        let mut exits = lock.lock().unwrap();
        let gdb = exits.gdb;
        let result = self.write_exits(&mut exits, gdb);
        self.bp_owner.store(-1, Ordering::SeqCst);
        drop(exits);
        cv.notify_all();
        result
    }

    /// Makes vCPU `vp` the owner of the #BP window, once nobody has the
    /// exception exits: from then on no other vCPU enters the guest. They
    /// are its to change ([`Self::set_window_bitmap`]) once the others are
    /// out. `false`, with nothing taken, if `immediate_exit` is set
    /// meanwhile.
    #[cfg_attr(not(feature = "gdb"), allow(dead_code))]
    pub(crate) fn open_bp_window(&self, vp: u32, immediate_exit: &AtomicU8) -> bool {
        self.take_exits(i64::from(vp), Some(immediate_exit))
    }

    /// Sets the window's exception exits to `bitmap` (a new round).
    #[cfg_attr(not(feature = "gdb"), allow(dead_code))]
    pub(crate) fn set_window_bitmap(&self, bitmap: u64) -> Result<()> {
        let mut exits = self.bp_window.0.lock().unwrap();
        self.write_exits(&mut exits, bitmap)
    }

    /// Closes the open #BP window: gdb's exception exits back, the held
    /// vCPUs let go. The owner is released even if the bitmap cannot be
    /// written, whose error is returned.
    #[cfg_attr(not(feature = "gdb"), allow(dead_code))]
    pub(crate) fn close_bp_window(&self) -> Result<()> {
        let (lock, cv) = &self.bp_window;
        let mut exits = lock.lock().unwrap();
        let gdb = exits.gdb;
        let result = self.write_exits(&mut exits, gdb);
        self.bp_owner.store(-1, Ordering::SeqCst);
        drop(exits);
        cv.notify_all();
        result
    }

    /// Waits while another vCPU than `vp` has a #BP window open. `false` if
    /// `immediate_exit` is set (the kick: the run returns).
    pub(crate) fn wait_bp_window(&self, vp: u32, immediate_exit: &AtomicU8) -> bool {
        let (lock, cv) = &self.bp_window;
        let mut gdb = lock.lock().unwrap();
        loop {
            if immediate_exit.load(Ordering::SeqCst) != 0 {
                return false;
            }
            let owner = self.bp_owner.load(Ordering::SeqCst);
            if owner < 0 || owner == i64::from(vp) {
                return true;
            }
            gdb = cv.wait(gdb).unwrap();
        }
    }

    /// Wakes the vCPUs waiting on the window, to see a kick: taken after
    /// the kick's flag is set, so a waiter checks it or is woken.
    pub(crate) fn notify_bp_window(&self) {
        drop(self.bp_window.0.lock().unwrap());
        self.bp_window.1.notify_all();
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
        // What a vCPU's thread would otherwise do at its first use, here,
        // before the VM's own partition is made: the probe of the registers
        // a partition keeps, whose refused calls cost the calling thread
        // 32 KiB of stack for good (`regs::probe_partition`).
        super::regs::probe_partition();
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

/// Which of `names` a partition configured as a VM's ([`configure`]) lets
/// vCPU 0 read and write back: a throwaway partition with no memory, made
/// and deleted here. All false if WHP cannot make one.
pub(crate) fn probe_registers(names: &[WHV_REGISTER_NAME]) -> Vec<bool> {
    let mut ok = vec![false; names.len()];
    let Ok(part) = ffi::create_partition() else { return ok };
    // SAFETY: vCPU 0 of the partition just configured.
    if configure(part).is_ok() && ffi::hr(unsafe { whv::WHvCreateVirtualProcessor(part, 0, 0) }).is_ok() {
        for (i, &name) in names.iter().enumerate() {
            ok[i] = ffi::quietly(|| {
                ffi::get_register(part, 0, name).is_ok_and(|v| ffi::set_register(part, 0, name, v).is_ok())
            });
        }
    }
    // SAFETY: the partition made above, deleted with its vCPU.
    unsafe { whv::WHvDeletePartition(part) };
    ok
}

/// Sets a new partition's properties and sets it up, as every VM's.
fn configure(part: WHV_PARTITION_HANDLE) -> Result<()> {
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
        // WHP's own TSC-deadline timer (`TscDeadlineTmrSupport`, bank 1 bit
        // 17) is left out: `IA32_TSC_DEADLINE` is emulated here, as KVM
        // emulates it (`tscdeadline`), which needs every access to exit, and
        // its value to be saved with a snapshot, which WHP's would not be.
        const TSC_DEADLINE_TMR: u64 = 1 << 17;
        if got && banks.BanksCount > 0 {
            // SAFETY: plain data; bank 0 is the first word of both.
            unsafe {
                banks.Anonymous.AsUINT64[0] |= cap.Anonymous.AsUINT64[0] & SPECULATION_CONTROLS;
            }
            if banks.BanksCount > 1 {
                // SAFETY: plain data; bank 1 is the second word.
                unsafe { banks.Anonymous.AsUINT64[1] &= !TSC_DEADLINE_TMR };
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
        // a guest's VMCALL/VMMCALL gets KVM's answers instead of #UD; with
        // the `gdb` feature, on exceptions too (ExceptionExit), for the gdb
        // stub's #DB and #BP (`debug`).
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
        } < 0
        {
            supported = 0;
        }
        let exits_bits = super::debug::extended_vm_exits(supported);
        // SAFETY: a u64 value for ExtendedVmExits.
        unsafe {
            ffi::set_partition_property(
                part,
                whv::WHvPartitionPropertyCodeExtendedVmExits,
                &exits_bits,
            )?;
        }
        // The CPUID leaves the backend intercepts, to answer with Firecracker's
        // configured CPUID as KVM does (a leaf not configured gets WHP's own
        // value): every basic and extended leaf, and KVM's two. A leaf left
        // to WHP showed the guest a value the configuration did not have
        // (0x8000001a: cpu-template-helper's dump against the guest).
        let cpuid_exits: Vec<u32> = (0x0..=0x24)
            .chain([0x4000_0000, 0x4000_0001])
            .chain(0x8000_0000..=0x8000_0028)
            .collect();
        // SAFETY: an array of u32 CPUID function numbers.
        ffi::hr(unsafe {
            whv::WHvSetPartitionProperty(
                part,
                whv::WHvPartitionPropertyCodeCpuidExitList,
                cpuid_exits.as_ptr().cast(),
                u32::try_from(std::mem::size_of_val(cpuid_exits.as_slice())).unwrap(),
            )
        })?;
        // SAFETY: completes partition setup.
        ffi::hr(unsafe { whv::WHvSetupPartition(part) })
}

impl VmInner {
    fn setup(part: WHV_PARTITION_HANDLE) -> Result<VmInner> {
        configure(part)?;

        let stop_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(io_err)?;
        Ok(VmInner {
            part,
            memory: Mutex::new(HashMap::new()),
            ioevents: RwLock::new(Vec::new()),
            irqfds: Mutex::new(Vec::new()),
            retired_irqfds: Mutex::new(Vec::new()),
            irqchip: Mutex::new(Irqchip::new()),
            pvclock: Mutex::new(super::pvclock::State::default()),
            deadlines: super::tscdeadline::Timers::new().map_err(io_err)?,
            vcpus: Mutex::new(Vec::new()),
            stop_evt,
            stop: AtomicBool::new(false),
            watcher: Mutex::new(None),
            has_irqchip: AtomicBool::new(false),
            halt_wake: (Mutex::new(0), Condvar::new()),
            request_failure: AtomicI32::new(0),
            bp_window: (Mutex::new(Exits::default()), Condvar::new()),
            bp_owner: AtomicI64::new(-1),
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
        let map = || {
            ffi::hr(unsafe {
                whv::WHvMapGpaRange(
                    self.inner.part,
                    region.userspace_addr as *const core::ffi::c_void,
                    region.guest_phys_addr,
                    region.memory_size,
                    flags,
                )
            })
        };
        // WHP maps guest memory for one partition of a process at a time: while
        // another VM of the process has memory mapped, this fails with
        // ERROR_INVALID_PARAMETER whatever the addresses (measured:
        // test_one_partition_of_a_process_maps_memory). KVM has no such limit;
        // Firecracker makes one VM per process.
        map()?;
        memory.insert(
            region.slot,
            Slot::new(region.guest_phys_addr, region.memory_size, region.userspace_addr, readonly, log_dirty),
        );
        Ok(())
    }

    /// The dirty-page bitmap of a slot (one bit per guest page), cleared by
    /// the query: the pages the guest wrote (WHP's) and those the backend
    /// wrote for it (`write_guest`), as KVM's log has both.
    pub fn get_dirty_log(&self, slot: u32, memory_size: usize) -> Result<Vec<u64>> {
        let mut memory = self.inner.memory.lock().unwrap();
        let s = memory.get_mut(&slot).ok_or_else(|| Error::new(libc::ENOENT))?;
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
        s.take_host_dirty(&mut bitmap);
        Ok(bitmap)
    }

    /// Registers an eventfd that is signalled on a matching guest I/O write.
    ///
    /// As KVM_IOEVENTFD: the length is the datamatch's size (kvm-ioctls'
    /// register_ioevent: `size_of::<T>()`, 0 for NoDatamatch, which
    /// matches a write of any length), and one that collides with a
    /// registered one is refused with EEXIST ([`collides`]).
    pub fn register_ioevent<T: Into<u64>>(
        &self,
        fd: &EventFd,
        addr: &IoEventAddress,
        datamatch: T,
    ) -> Result<()> {
        let len = u32::try_from(std::mem::size_of::<T>()).unwrap();
        let datamatch = (len > 0).then(|| datamatch.into());
        let mut ioevents = self.inner.ioevents.write().unwrap();
        if ioevents.iter().any(|ev| collides(ev, addr, len, datamatch)) {
            return err(libc::EEXIST);
        }
        let eventfd = fd.try_clone().map_err(io_err)?;
        ioevents.push(IoEvent {
            addr: *addr,
            len,
            datamatch,
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
        let len = u32::try_from(std::mem::size_of::<T>()).unwrap();
        let want = (len > 0).then(|| datamatch.into());
        let mut ioevents = self.inner.ioevents.write().unwrap();
        let before = ioevents.len();
        ioevents.retain(|ev| {
            !(ev.addr == *addr && ev.len == len && ev.datamatch == want && ev.fd == fd.as_raw_fd())
        });
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
        let mut retired = self.inner.retired_irqfds.lock().unwrap();
        if !retire_irqfd(&mut irqfds, &mut retired, fd.as_raw_fd(), gsi) {
            return err(libc::ENOENT);
        }
        drop(retired);
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

    /// The guest clock: once the guest has kvm-clock, the guest's kvm-clock
    /// at the guest TSC returned with it (`host_tsc`, `pvclock`), as KVM
    /// returns its kvm-clock; before, the VM clock. With the host's wall
    /// clock at the same moment (`realtime`, `KVM_CLOCK_REALTIME`), which a
    /// restore with that flag advances the guest clock by.
    pub fn get_clock(&self) -> Result<kvm_clock_data> {
        let mut clock = self.inner.irqchip.lock().unwrap().clock();
        clock.realtime = realtime_ns();
        clock.flags |= KVM_CLOCK_REALTIME;
        // vCPU 0's TSC, which every vCPU's follows (`pvclock`); none before
        // vCPU 0 is made, an answer, not an error.
        if let Ok(value) = ffi::quietly(|| ffi::get_register(self.inner.part, 0, whv::WHvX64RegisterTsc)) {
            let tsc = ffi::as_u64(&value);
            if let Some(ns) = self.inner.pvclock.lock().unwrap().clock_at(tsc) {
                clock.clock = ns;
            }
            clock.host_tsc = tsc;
            clock.flags |= KVM_CLOCK_HOST_TSC;
        }
        Ok(clock)
    }

    /// Restores the guest clock; with the guest TSC it was saved with
    /// (`host_tsc`, [`Self::get_clock`]), the restored guest's kvm-clock goes
    /// on from its TSC as before the snapshot. Upstream overwrites `flags`
    /// before the call, so a non-zero `host_tsc` is what tells. With
    /// `KVM_CLOCK_REALTIME`, as KVM: the clock goes on from `clock` plus the
    /// wall-clock time since `realtime` (the time a snapshot spent on disk).
    pub fn set_clock(&self, clock: &kvm_clock_data) -> Result<()> {
        let mut clock = *clock;
        clock.clock = restored_clock(&clock, realtime_ns());
        self.inner.irqchip.lock().unwrap().set_clock(&clock);
        let mut pvclock = self.inner.pvclock.lock().unwrap();
        pvclock.reset();
        if clock.host_tsc != 0 {
            pvclock.pin(clock.host_tsc, clock.clock);
        }
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
        // Weak: the watcher does not keep the VM alive (its partition, and
        // the guest memory WHP maps for it) once nothing else does.
        let vm = Arc::downgrade(&self.inner);
        let stop_fd = self.inner.stop_evt.as_raw_fd();
        *watcher = Some(std::thread::spawn(move || watch_irqfds(&vm, stop_fd)));
    }
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Moves the irqfds of `fd` and `gsi` from `irqfds` to `retired`, where
/// their eventfd stays open until the watcher has taken it out of its epoll
/// and drops them: closing it at once would leave a closed handle in an
/// epoll that waits on it, which strict handle checks (the sandbox) end the
/// process for (`STATUS_INVALID_HANDLE`, measured: boot-test pci, an MSI-X
/// irqfd unregistered at the guest's reset). Whether any was registered.
fn retire_irqfd(irqfds: &mut Vec<IrqFd>, retired: &mut Vec<IrqFd>, fd: RawFd, gsi: u32) -> bool {
    let before = retired.len();
    let mut i = 0;
    while i < irqfds.len() {
        if irqfds[i].gsi == gsi && irqfds[i].fd == fd {
            retired.push(irqfds.remove(i));
        } else {
            i += 1;
        }
    }
    retired.len() > before
}

/// Waits on every registered irqfd; when one signals, raises its GSI. Woken
/// by `stop_evt` (`stop_fd`) to exit (`stop` set) or to pick up the irqfds
/// registered or removed since.
///
/// It holds the VM only while it handles a wake: a strong reference across
/// the wait, which only the VM's drop ended, kept a VM that had registered an
/// irqfd (its partition, and the guest memory WHP maps for it) to the
/// process's end, and the next VM of the process could not map its memory
/// (`test_a_vm_with_an_irqfd_is_dropped_with_its_last_reference`).
fn watch_irqfds(vm: &Weak<VmInner>, stop_fd: RawFd) {
    use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
    // Without it no device interrupt would ever be delivered.
    let epoll = Epoll::new().expect("wick: the irqfd watcher cannot create its epoll");
    let mut registered: HashMap<RawFd, (u32, u64)> = HashMap::new();
    let _ = epoll.ctl(
        ControlOperation::Add,
        stop_fd,
        EpollEvent::new(EventSet::IN, stop_fd as u64),
    );
    let mut events = [EpollEvent::default(); 16];
    let mut n = 0;
    loop {
        // Gone (its drop has begun): its drop does not wait for this thread
        // if it runs here, and has the eventfds open until it returns if it
        // runs elsewhere.
        let Some(inner) = vm.upgrade() else { return };
        if inner.stop.load(Ordering::Acquire) {
            return;
        }
        // What the last wait returned, against the set it waited on.
        for ev in &events[..n] {
            let fd = ev.data() as RawFd;
            if fd == stop_fd {
                let _ = inner.stop_evt.read();
                // Stopping, or the irqfd set changed: looked at below.
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
            // Every retired irqfd was unregistered before `current` was
            // taken (both under the `irqfds` lock), so it is out of the
            // epoll now, or never was in it: its eventfd may close.
            inner.retired_irqfds.lock().unwrap().clear();
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
        drop(inner);
        // That was the last reference: the VM was dropped here, its eventfds
        // closed; no wait on them.
        if vm.strong_count() == 0 {
            return;
        }
        n = epoll.wait(1000, &mut events).unwrap_or(0);
    }
}

/// The host's wall clock, in nanoseconds since the Unix epoch (Linux's
/// CLOCK_REALTIME, which KVM reads for `KVM_CLOCK_REALTIME`).
fn realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// The guest clock `set_clock` restores at wall-clock time `now`: `clock`,
/// plus the wall time since `realtime` when the flag asks for it (a clock
/// does not go back for a wall clock set back).
fn restored_clock(clock: &kvm_clock_data, now: u64) -> u64 {
    if clock.flags & KVM_CLOCK_REALTIME != 0 {
        clock.clock + now.saturating_sub(clock.realtime)
    } else {
        clock.clock
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::GetHandleInformation;

    // One process may make VMs one after another (cpu-template-helper's
    // tests build one per test), each with its guest memory.
    // The guest-memory tests take addresses another could get between a
    // munmap and a MAP_FIXED: one at a time.
    static GUEST_MEMORY: Mutex<()> = Mutex::new(());

    #[test]
    fn test_vms_one_after_another_map_their_memory() {
        let _one = GUEST_MEMORY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for round in 0..3 {
            let vm = VmFd::create().unwrap();
            let len = 64usize << 20;
            // SAFETY: anonymous memory for the test, unmapped below.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_ne!(p, libc::MAP_FAILED);
            let region = kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: len as u64,
                userspace_addr: p as u64,
            };
            // SAFETY: the memory stays mapped while the VM has it.
            let r = unsafe { vm.set_user_memory_region(region) };
            assert!(r.is_ok(), "round {round}: {r:?}");
            drop(vm);
            // SAFETY: our mapping.
            assert_eq!(unsafe { libc::munmap(p, len) }, 0);
        }
    }

    // WHP maps guest memory for one partition of a process at a time
    // (measured on Windows 11 26H2): while one VM has memory mapped, a map in
    // another fails, whatever the addresses; once the first has none, the
    // other maps. If Windows lifts this, the test says so.
    #[test]
    fn test_one_partition_of_a_process_maps_memory() {
        let _one = GUEST_MEMORY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = 16usize << 20;
        let mem = || {
            // SAFETY: anonymous memory for the test, left to the process's end.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_ne!(p, libc::MAP_FAILED);
            p as u64
        };
        let region = |gpa: u64, host: u64, size: u64| kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: host,
        };
        let (a, b) = (VmFd::create().unwrap(), VmFd::create().unwrap());
        let (ma, mb) = (mem(), mem());
        // SAFETY: the memory outlives the VMs.
        unsafe {
            a.set_user_memory_region(region(0, ma, len as u64)).unwrap();
            assert_eq!(
                b.set_user_memory_region(region(1 << 32, mb, len as u64)).unwrap_err().errno(),
                87,
                "a second partition mapped memory: WHP's limit is gone"
            );
            a.set_user_memory_region(region(0, ma, 0)).unwrap();
            b.set_user_memory_region(region(1 << 32, mb, len as u64)).unwrap();
        }
    }

    /// Anonymous memory of `len` bytes for a test's VM, left to the test to
    /// unmap.
    fn anon(len: usize) -> u64 {
        // SAFETY: anonymous memory for the test.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        p as u64
    }

    /// Maps `len` bytes at `host` as slot 0 at guest address 0.
    fn map0(vm: &VmFd, host: u64, len: usize) -> Result<()> {
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: len as u64,
            userspace_addr: host,
        };
        // SAFETY: the tests keep the memory mapped while a VM has it.
        unsafe { vm.set_user_memory_region(region) }
    }

    fn unanon(host: u64, len: usize) {
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(host as *mut core::ffi::c_void, len) }, 0);
    }

    // What the runner (CI's WHP step) and the PC report about WHP, for the
    // record of both processor vendors: each capability's HRESULT and value
    // (WHV_CAPABILITY_CODE, WinHvPlatformDefs.h).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_print_whp_capabilities() {
        let codes: [(&str, whv::WHV_CAPABILITY_CODE); 14] = [
            ("HypervisorPresent", 0),
            ("Features", 1),
            ("ExtendedVmExits", 2),
            ("ExceptionExitBitmap", 3),
            ("X64MsrExitBitmap", 4),
            ("GpaRangePopulateFlags", 5),
            ("SchedulerFeatures", 6),
            ("ProcessorVendor (0 AMD, 1 Intel, 2 Hygon)", 0x1000),
            ("ProcessorFeatures", 0x1001),
            ("ProcessorClFlushSize", 0x1002),
            ("ProcessorXsaveFeatures", 0x1003),
            ("ProcessorClockFrequency", 0x1004),
            ("InterruptClockFrequency", 0x1005),
            ("ProcessorFeaturesBanks", 0x1006),
        ];
        let mut present = 0;
        for (name, code) in codes {
            let mut buf = [0u64; 4];
            let mut written = 0u32;
            // SAFETY: a buffer of the size passed.
            let hres = unsafe { whv::WHvGetCapability(code, buf.as_mut_ptr().cast(), 32, &mut written) };
            eprintln!(
                "WHPCAP {name} ({code:#x}): HRESULT {:#010x}, {written} bytes, {:#x} {:#x} {:#x} {:#x}",
                hres.cast_unsigned(),
                buf[0],
                buf[1],
                buf[2],
                buf[3]
            );
            if code == 0 {
                present = buf[0] & 0xFFFF_FFFF;
            }
        }
        assert_eq!(present, 1, "WHvCapabilityCodeHypervisorPresent");
    }

    // A vCPU's XSAVE state is read and written whole on every host: into
    // an area of the size `KVM_CAP_XSAVE2` reports, as upstream does it,
    // the state written back reading the same; `KVM_GET_XSAVE`, whose area
    // is 4096 bytes, gives the same bytes where the state fits them and
    // EINVAL where it does not (a processor with AMX: CI run 43359525691,
    // where Firecracker did not start). The XSAVETEST lines are each run's
    // record of its processor: WHP's XSAVE features (bit 27 is AMX tile:
    // WHV_PROCESSOR_XSAVE_FEATURES), CPUID leaf 0xD's sizes, and the bytes
    // WHP wrote; then what WHP does with an area three pages longer than
    // the capability's (not asserted: no caller makes one).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_xsave_state_fits_the_area_the_capability_reports() {
        use core::arch::x86_64::__cpuid_count;
        use kvm_bindings::Xsave;
        use super::super::regs;
        let bytes_of = |x: &Xsave| -> Vec<u8> {
            let p = x.as_fam_struct_ptr();
            // SAFETY: the wrapper's `kvm_xsave` and the `len` entries after it.
            unsafe { std::slice::from_raw_parts((&raw const (*p).xsave).cast::<u8>(), 4096 + 4 * (*p).len) }.to_vec()
        };
        let vm = VmFd::create().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let cap = usize::try_from(vm.check_extension_int(Cap::Xsave2)).unwrap();
        let mut features = 0u64;
        let mut n = 0u32;
        // SAFETY: a buffer of the size passed.
        let hres = unsafe { whv::WHvGetCapability(0x1003, (&raw mut features).cast(), 8, &mut n) };
        let (d0, d1) = (__cpuid_count(0xd, 0), __cpuid_count(0xd, 1));
        let (user, supervisor) = regs::host_xfeatures();
        let written = vcpu.xsave_state_len().unwrap();
        eprintln!(
            "XSAVETEST WHP XSAVE features {features:#x} (HRESULT {:#010x}), AMX tile {}; CPUID 0xD.0 XCR0 bits \
             {user:#x}, EBX {} ECX {}; 0xD.1 EAX {:#x}, XSS bits {supervisor:#x}, EBX {}; standard {} compacted \
             {} bytes; KVM_CAP_XSAVE2 {cap}; WHP wrote {written} bytes",
            hres.cast_unsigned(),
            features >> 27 & 1,
            d0.ebx,
            d0.ecx,
            d1.eax,
            d1.ebx,
            regs::xsave_size(user, false),
            regs::xsave_size(user | supervisor, true),
        );
        assert!(cap >= 4096 && cap % 4096 == 0 && written <= cap, "{written} bytes for an area of {cap}");
        // The guest's CPUID leaf 0xD is the processor's, and its partition
        // has what WHP offers: the two agree on AMX.
        assert_eq!(features >> 27 & 1, user >> 18 & 1, "AMX tile data: WHP's XSAVE features and CPUID leaf 0xD");
        let len = (cap - 4096).div_ceil(4);
        let mut first = Xsave::new(len).unwrap();
        // SAFETY: an area of the capability's size.
        unsafe { vcpu.get_xsave2(&mut first) }.unwrap();
        let header = |at: usize| u64::from_le_bytes(bytes_of(&first)[at..at + 8].try_into().unwrap());
        eprintln!(
            "XSAVETEST a new vCPU's area: XSTATE_BV {:#x}, XCOMP_BV {:#x} (bit 63: the compacted format)",
            header(512),
            header(520)
        );
        // SAFETY: the state just read.
        unsafe { vcpu.set_xsave2(&first) }.unwrap();
        let mut again = Xsave::new(len).unwrap();
        // SAFETY: as above.
        unsafe { vcpu.get_xsave2(&mut again) }.unwrap();
        assert!(bytes_of(&first) == bytes_of(&again), "the state written back reads otherwise");
        // SAFETY: plain calls.
        let legacy = unsafe { vcpu.get_xsave() };
        if written <= 4096 {
            let legacy = legacy.unwrap();
            // SAFETY: the region's 4096 bytes.
            let bytes = unsafe { std::slice::from_raw_parts(legacy.region.as_ptr().cast::<u8>(), 4096) };
            assert!(bytes == &bytes_of(&first)[..4096], "KVM_GET_XSAVE reads otherwise than KVM_GET_XSAVE2");
            // SAFETY: the state just read.
            unsafe { vcpu.set_xsave(&legacy) }.unwrap();
        } else {
            assert_eq!(legacy.unwrap_err().errno(), libc::EINVAL, "KVM_GET_XSAVE of a state of {written} bytes");
        }
        // An area smaller than the state is refused, not overrun: one
        // without its flexible array on a host whose state passes 4096.
        if written > 4096 {
            let mut small = Xsave::new(0).unwrap();
            // SAFETY: the refusal is what is tested.
            assert_eq!(unsafe { vcpu.get_xsave2(&mut small) }.unwrap_err().errno(), libc::EINVAL);
        }
        let mut long = Xsave::new(len + 3 * 1024).unwrap();
        // SAFETY: an area larger than the capability's.
        let got = unsafe { vcpu.get_xsave2(&mut long) };
        let same = got.is_ok() && bytes_of(&long)[..cap] == bytes_of(&first)[..];
        // SAFETY: the state just read, in the longer area.
        let set = got.as_ref().ok().map(|()| unsafe { vcpu.set_xsave2(&long) });
        eprintln!("XSAVETEST an area of {} bytes: read {got:?} (the same bytes: {same}), written back {set:?}", cap + 12288);
    }

    // The kvm-clock's reference is a TSC WHP gave. A VM that has no vCPU
    // gives none: publishing fails (the MSR write's error, or the run's),
    // and makes no reference, which one of a TSC of 0 would be for every
    // vCPU from then on. With the MSR's enable bit off there is nothing to
    // read or to publish.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_no_clock_reference_is_made_of_a_tsc_that_was_not_read() {
        let vm = VmFd::create().unwrap();
        let inner = &vm.inner;
        let publish = |value: u64| {
            ffi::quietly(|| super::super::pvclock::system_time(&inner.pvclock, inner.part, 0, value, inner.ram(), || 7))
        };
        assert!(publish(0x10000).is_ok());
        let published = publish(0x10000 | 1);
        let hz = super::super::pvclock::tsc_hz();
        eprintln!("CLOCKTEST kvm-clock published for vCPU 0 of a VM that has none: {published:?} (TSC frequency {hz} Hz)");
        // Without a TSC frequency there is no kvm-clock, and no read for one.
        assert_eq!(published.is_err(), hz != 0);
        assert_eq!(inner.pvclock.lock().unwrap().clock_at(0), None);
    }

    // CI run 43277608081: from a point on, every map of vmm's process failed
    // with ERROR_INVALID_PARAMETER (87). Two causes give that: WHP keeping
    // something of a refused map, or of a VM, after it is gone; or a VM kept
    // alive by a reference. These two tests tell them apart, each in a
    // process of its own (CI's WHP step runs them so), as a process left
    // unable to map would spoil the tests after it. Run 43292883636: both
    // pass, so it was a VM kept alive: the irqfd watcher's (fixed in 28e7fb8;
    // test_a_vm_with_an_irqfd_is_dropped_with_its_last_reference), and the
    // map failures of vmm's tests that were left are each a test keeping a
    // VM (tools/windows/unit-test-differences.txt).
    //
    // Firecracker's need, asserted: once both are gone, a third VM maps.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture, alone"]
    fn test_maps_after_a_refused_map_once_both_vms_are_gone() {
        let _one = GUEST_MEMORY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = 16usize << 20;
        let (ha, hb, hc) = (anon(len), anon(len), anon(len));
        let a = VmFd::create().unwrap();
        map0(&a, ha, len).unwrap();
        let b = VmFd::create().unwrap();
        let refused = map0(&b, hb, len).map_err(|e| e.errno());
        eprintln!("MAPTEST B's map beside A's memory: {refused:?}");
        assert_eq!(refused, Err(87), "WHP's one-partition limit is gone");
        drop(b);
        drop(a);
        let c = VmFd::create().unwrap();
        let r = map0(&c, hc, len).map_err(|e| e.errno());
        eprintln!("MAPTEST C's map after A and B were dropped: {r:?}");
        assert_eq!(r, Ok(()), "a VM after a refused map, once both VMs are gone");
        drop(c);
        for h in [ha, hb, hc] {
            unanon(h, len);
        }
    }

    // The second cause, made on purpose: the first VM kept alive by a
    // reference (as a vCPU or a thread of the backend holds one) keeps its
    // memory mapped, so a third VM's map is refused while it lives and
    // succeeds once it is gone.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture, alone"]
    fn test_a_vm_kept_alive_keeps_later_maps_refused() {
        let _one = GUEST_MEMORY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = 16usize << 20;
        let (ha, hb, hc) = (anon(len), anon(len), anon(len));
        let a = VmFd::create().unwrap();
        map0(&a, ha, len).unwrap();
        let b = VmFd::create().unwrap();
        assert_eq!(map0(&b, hb, len).map_err(|e| e.errno()), Err(87));
        drop(b);
        let kept = Arc::clone(&a.inner);
        drop(a);
        let c = VmFd::create().unwrap();
        let r = map0(&c, hc, len).map_err(|e| e.errno());
        eprintln!("MAPTEST C's map while A's partition is kept: {r:?}");
        assert_eq!(r, Err(87), "A, kept, still has its memory mapped");
        drop(kept);
        let r = map0(&c, hc, len).map_err(|e| e.errno());
        eprintln!("MAPTEST C's map once A is gone: {r:?}");
        assert_eq!(r, Ok(()));
        drop(c);
        for h in [ha, hb, hc] {
            unanon(h, len);
        }
    }

    // A VM that registered an irqfd is dropped with its last reference, and
    // the next VM of the process maps its memory: the irqfd watcher holds the
    // VM only while it handles a wake (a strong reference across its waits,
    // ended only by the VM's drop, kept such a VM to the process's end).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture, alone"]
    fn test_a_vm_with_an_irqfd_is_dropped_with_its_last_reference() {
        let _one = GUEST_MEMORY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = 16usize << 20;
        let (ha, hc) = (anon(len), anon(len));
        let a = VmFd::create().unwrap();
        map0(&a, ha, len).unwrap();
        let irq = EventFd::new(0).unwrap();
        a.register_irqfd(&irq, 5).unwrap();
        let weak = Arc::downgrade(&a.inner);
        drop(a);
        // The watcher may be handling the wake register_irqfd gave it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while weak.strong_count() > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(weak.strong_count(), 0, "the VM outlived its last reference");
        let c = VmFd::create().unwrap();
        assert_eq!(map0(&c, hc, len).map_err(|e| e.errno()), Ok(()), "the next VM maps its memory");
        drop(c);
        drop(irq);
        unanon(ha, len);
        unanon(hc, len);
    }

    // KVM_TRANSLATE on WHP (the PC; `cargo test -- --ignored`), with a vCPU
    // as gdb meets it: at the PVH entry (protected mode, paging off) and at
    // `start_kernel` (long mode, 4-level paging, the kernel's half, a 2 MiB
    // supervisor page). Paging off is KVM's identity (nonpaging_gva_to_gpa:
    // the whole 64-bit address, where WHP's walk truncates it to 32 bits),
    // valid even where no memory is; paging on is KVM's supervisor read
    // (debug::TRANSLATE_FLAGS). Prints what each WHvTranslateGva flag set
    // returns in both modes. Measured on a WHP machine (Ryzen 9 7900): every
    // set without a validate flag is refused (E_INVALIDARG); with read, write
    // or execute, the entry gives the address truncated to 32 bits and long
    // mode the page's address or PageNotPresent.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored"]
    fn test_translate_as_kvm_at_the_entry_and_in_long_mode() {
        use super::super::debug::INVALID_GPA;
        let _one = GUEST_MEMORY.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let vm = VmFd::create().unwrap();
        let len = 4usize << 20;
        // SAFETY: anonymous memory for the test, unmapped below.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        let mem = p.cast::<u64>();
        // PML4 at 0x1000, PDPT at 0x2000, PD at 0x3000: 0xffffffff80000000
        // (PML4 511, PDPT 510, PD 0) is the 2 MiB supervisor page at
        // 0x200000, and 0xffffffff80200000 (PD 1) the same page as a user
        // page.
        // SAFETY: within the mapping, 8-byte aligned.
        unsafe {
            *mem.add(0x1000 / 8 + 511) = 0x2000 | 7;
            *mem.add(0x2000 / 8 + 510) = 0x3000 | 7;
            *mem.add(0x3000 / 8) = 0x20_0000 | 0x83;
            *mem.add(0x3000 / 8 + 1) = 0x20_0000 | 0x87;
        }
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: len as u64,
            userspace_addr: p as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let (mapped, user, unmapped) = (0xffff_ffff_8000_1234_u64, 0xffff_ffff_8020_1234_u64, 0xffff_ffff_82ed_2098_u64);
        let flag_sets: [(&str, whv::WHV_TRANSLATE_GVA_FLAGS); 8] = [
            ("none", whv::WHvTranslateGvaFlagNone),
            ("read", whv::WHvTranslateGvaFlagValidateRead),
            ("write", whv::WHvTranslateGvaFlagValidateWrite),
            ("execute", whv::WHvTranslateGvaFlagValidateExecute),
            ("exempt", whv::WHvTranslateGvaFlagPrivilegeExempt),
            ("read+exempt", whv::WHvTranslateGvaFlagValidateRead | whv::WHvTranslateGvaFlagPrivilegeExempt),
            ("write+exempt", whv::WHvTranslateGvaFlagValidateWrite | whv::WHvTranslateGvaFlagPrivilegeExempt),
            ("read+write", whv::WHvTranslateGvaFlagValidateRead | whv::WHvTranslateGvaFlagValidateWrite),
        ];
        let report = |mode: &str| {
            for gva in [0x10_0000, mapped, user, unmapped] {
                for (name, flags) in flag_sets {
                    match vcpu.translate_walk(gva, flags) {
                        Ok((code, gpa)) => eprintln!("{mode} {gva:#x} {name}: S_OK, result {code}, gpa {gpa:#x}"),
                        Err(e) => eprintln!("{mode} {gva:#x} {name}: failed, errno {}", e.errno()),
                    }
                }
            }
        };

        // The PVH entry: protected mode, paging off.
        let mut s = vcpu.get_sregs().unwrap();
        s.cr0 = 0x11; // PE, ET
        s.cr4 = 0;
        s.efer = 0;
        s.cs.l = 0;
        s.cs.db = 1;
        vcpu.set_sregs(&s).unwrap();
        report("entry");
        for gva in [0x10_0000, unmapped] {
            let t = vcpu.translate_gva(gva).unwrap();
            assert_eq!((t.physical_address, t.valid, t.writeable), (gva, 1, 1), "paging off: {gva:#x}");
        }

        // start_kernel: long mode, 4-level paging.
        s.cr0 = 0x8000_0011; // PG, ET, PE
        s.cr3 = 0x1000;
        s.cr4 = 0x20; // PAE
        s.efer = 0x500; // LME, LMA
        s.cs.l = 1;
        s.cs.db = 0;
        vcpu.set_sregs(&s).unwrap();
        report("long");
        let t = vcpu.translate_gva(mapped).unwrap();
        assert_eq!((t.physical_address, t.valid, t.writeable), (0x20_1234, 1, 1), "the kernel's page");
        let t = vcpu.translate_gva(unmapped).unwrap();
        assert_eq!((t.physical_address, t.valid, t.writeable), (INVALID_GPA, 0, 1), "no page: invalid, as KVM");
        // A user page: KVM's supervisor read finds it too (no SMAP here).
        let t = vcpu.translate_gva(user).unwrap();
        assert_eq!((t.physical_address, t.valid, t.writeable), (0x20_1234, 1, 1), "a user page");

        drop(vcpu);
        drop(vm);
        // SAFETY: our mapping.
        assert_eq!(unsafe { libc::munmap(p, len) }, 0);
    }

    // On WHP (the PC; `cargo test -- --ignored`): the MSRs a snapshot
    // carries round-trip through a vCPU on any host. KVM keeps
    // IA32_TSC_ADJUST and IA32_MISC_ENABLE in software on Intel and AMD
    // alike; where the partition has no register for one (an AMD host's has
    // neither, measured on a Ryzen 9 7900) the vCPU keeps it, so both are
    // listed and restored as saved everywhere. TSC_ADJUST is kept only for a
    // guest whose CPUID has TSC_ADJUST, as KVM; IA32_TSC moves with the host
    // while the vCPU has not run, by the few milliseconds the calls took;
    // MISC_ENABLE and the MTRR default type take Firecracker's boot values.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored"]
    fn test_tsc_and_its_adjust_restore_as_saved() {
        use kvm_bindings::{CpuId, Msrs, kvm_cpuid_entry2, kvm_msr_entry};
        let present = super::super::regs::msr_index_list().unwrap();
        let listed: Vec<u32> = present.as_slice().to_vec();
        eprintln!("MSRs listed: {listed:x?}");
        for need in [0x3b, 0x1a0] {
            assert!(listed.contains(&need), "{need:#x} not listed, which KVM lists on every host");
        }
        let vm = VmFd::create().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let tsc_adjust_cpuid = kvm_cpuid_entry2 { function: 7, index: 0, ebx: 1 << 1, ..Default::default() };
        // With the host's leaf 0xD, without which the table is refused
        // (`set_cpuid2`: its XSAVE components left out).
        let leaf_d = super::super::regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap()
            .as_slice()
            .iter()
            .copied()
            .find(|e| e.function == 0xd && e.index == 0)
            .unwrap();
        vcpu.set_cpuid2(&CpuId::from_entries(&[tsc_adjust_cpuid, leaf_d]).unwrap()).unwrap();
        let (tsc, adjust) = (0x1234_5678_9abc_u64, 0x10_0000_u64);
        let entry = |index, data| kvm_msr_entry { index, data, ..Default::default() };
        let mut msrs = Msrs::from_entries(&[entry(0x10, tsc), entry(0x3b, adjust)]).unwrap();
        assert_eq!(vcpu.set_msrs(&msrs).unwrap(), 2);
        assert_eq!(vcpu.get_msrs(&mut msrs).unwrap(), 2);
        let got = msrs.as_slice();
        assert_eq!(got[1].data, adjust, "TSC_ADJUST read back");
        assert!(got[0].data >= tsc && got[0].data - tsc < 1 << 32, "TSC {:#x}, {tsc:#x} written", got[0].data);
        let boot = [(0x1a0, 1u64), (0x2ff, (1 << 11) | 6)];
        let mut m = Msrs::from_entries(&boot.map(|(index, data)| entry(index, data))).unwrap();
        assert_eq!(vcpu.set_msrs(&m).unwrap(), 2);
        assert_eq!(vcpu.get_msrs(&mut m).unwrap(), 2);
        for (e, (index, data)) in m.as_slice().iter().zip(boot) {
            assert_eq!(e.data & data, data, "{index:#x} read back {:#x}", e.data);
        }
        // Without TSC_ADJUST in the guest's CPUID a host's write is not
        // kept, as KVM's (x86.c, kvm_set_msr_common).
        let vcpu1 = vm.create_vcpu(1).unwrap();
        let mut a = Msrs::from_entries(&[entry(0x3b, adjust)]).unwrap();
        assert_eq!(vcpu1.set_msrs(&a).unwrap(), 1);
        assert_eq!(vcpu1.get_msrs(&mut a).unwrap(), 1);
        if super::super::regs::software_msr(0x3b) {
            assert_eq!(a.as_slice()[0].data, 0, "TSC_ADJUST kept for a guest without it");
        }
    }

    #[test]
    fn test_clock_realtime_advances_by_the_wall_time_since() {
        // SAFETY: an all-zero kvm_clock_data is valid.
        let mut c: kvm_clock_data = unsafe { std::mem::zeroed() };
        c.clock = 5_000;
        c.realtime = 1_000_000;
        assert_eq!(restored_clock(&c, 3_000_000), 5_000, "without the flag: as saved");
        c.flags = KVM_CLOCK_REALTIME;
        assert_eq!(restored_clock(&c, 3_000_000), 2_005_000);
        assert_eq!(restored_clock(&c, 10), 5_000, "a wall clock set back does not take it back");
    }

    fn open(fd: RawFd) -> bool {
        let mut flags = 0u32;
        // SAFETY: queries a handle value; a closed one fails.
        unsafe { GetHandleInformation(wick_os::fd::handle(fd), &mut flags) != 0 }
    }

    // An unregistered irqfd's eventfd stays open (the watcher may still
    // wait on it) until the retired list is dropped, which the watcher does
    // only after taking it out of its epoll.
    #[test]
    fn test_an_unregistered_irqfd_stays_open_until_retired() {
        let device = EventFd::new(0).unwrap();
        let other = EventFd::new(0).unwrap();
        let mut irqfds = vec![
            IrqFd { gsi: 5, fd: device.as_raw_fd(), eventfd: device.try_clone().unwrap() },
            IrqFd { gsi: 6, fd: other.as_raw_fd(), eventfd: other.try_clone().unwrap() },
        ];
        let watched = irqfds[0].eventfd.as_raw_fd();
        let mut retired = Vec::new();
        assert!(!retire_irqfd(&mut irqfds, &mut retired, device.as_raw_fd(), 6), "a gsi it was not registered for");
        assert!(retire_irqfd(&mut irqfds, &mut retired, device.as_raw_fd(), 5));
        assert_eq!(irqfds.len(), 1);
        assert_eq!(irqfds[0].gsi, 6);
        assert!(open(watched), "the watcher's eventfd closed while it may still be in the epoll");
        assert!(!retire_irqfd(&mut irqfds, &mut retired, device.as_raw_fd(), 5), "unregistered twice");
        retired.clear();
        assert!(!open(watched), "the retired eventfd was not closed");
        assert!(open(device.as_raw_fd()), "the caller's eventfd is the caller's");
    }

    // KVM's collision rule for ioeventfds, which register_ioevent refuses
    // with EEXIST: vmm's test_bar_relocation and _refused register a probe
    // where a device's notification ioeventfd is, and expect the refusal.
    #[test]
    fn test_an_ioeventfd_that_collides_is_refused() {
        let ev = |addr, len, datamatch| {
            let e = EventFd::new(0).unwrap();
            IoEvent { addr, len, datamatch, fd: e.as_raw_fd(), eventfd: e }
        };
        let m = IoEventAddress::Mmio(0x1000);
        let queue1 = ev(m, 4, Some(1));
        // The same registration again.
        assert!(collides(&queue1, &m, 4, Some(1)));
        // Without a datamatch, or of any length: it covers the other.
        assert!(collides(&queue1, &m, 0, None));
        assert!(collides(&ev(m, 0, None), &m, 8, Some(5)));
        // Virtio-MMIO's queues share the notify address, one value each.
        assert!(!collides(&queue1, &m, 4, Some(2)));
        // Another length, address or bus.
        assert!(!collides(&queue1, &m, 2, Some(1)));
        assert!(!collides(&queue1, &IoEventAddress::Mmio(0x1004), 4, Some(1)));
        assert!(!collides(&queue1, &IoEventAddress::Pio(0x1000), 4, Some(1)));
    }
}
