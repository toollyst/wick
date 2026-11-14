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
//!   `VcpuExit::Mmio*`. A read's instruction is finished in the host at the
//!   next run, with Firecracker's data, before the guest is entered or a
//!   kick looked at, as KVM's `complete_userspace_io` finishes it;
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

/// The logical destination register of x2APIC ID `id`: its cluster (bits
/// 31:4 of the ID) in bits 31:16, one bit of its 16 in bits 15:0, as KVM's
/// `kvm_apic_calc_x2apic_ldr` (Linux v6.1 arch/x86/kvm/lapic.c 363-366).
fn x2apic_ldr(id: u32) -> u32 {
    ((id >> 4) << 16) | (1 << (id & 0xf))
}

/// Whether a CPUID table has a flag (leaf, sub-leaf, register: 1 EBX,
/// 2 ECX, 3 EDX; bit), its entry found as the guest's CPUID exit finds it
/// (`handle_cpuid`); a leaf the table lacks has none, as KVM's
/// `guest_cpuid_has`.
fn cpuid_has(table: &[kvm_cpuid_entry2], leaf: u32, index: u32, register: u8, bit: u32) -> bool {
    table
        .iter()
        .find(|e| e.function == leaf && (e.flags & kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX == 0 || e.index == index))
        .is_some_and(|e| {
            let value = match register {
                1 => e.ebx,
                2 => e.ecx,
                _ => e.edx,
            };
            value >> bit & 1 == 1
        })
}

/// KVM's `cr4_reserved_bits` here: those of the supported CPUID, the
/// host's capabilities (`cr4`), computed once.
fn host_cr4_reserved() -> u64 {
    static RESERVED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *RESERVED.get_or_init(|| match regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES) {
        Ok(c) => super::cr4::reserved_bits(|l, i, r, b| cpuid_has(c.as_slice(), l, i, r, b)),
        // No CPUID: every gated bit reserved, as for a host with none.
        Err(_) => super::cr4::reserved_bits(|_, _, _, _| false),
    })
}

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

/// A read whose data Firecracker gives at the next run, which completes
/// it before anything else (KVM's `complete_userspace_io`).
enum Pending {
    /// An MMIO read: the instruction is emulated again from its exit, with
    /// this read's data and the reads' before it, and finishes in the host.
    Mmio(Box<MmioRead>),
    /// A port-I/O `IN`: completed directly by writing `RAX` and advancing.
    PioIn { len: usize, rip_after: u64, rax: u64 },
    /// An `INS`: the elements Firecracker put in the string buffer are
    /// written to the guest's memory at the next run.
    StringIn(StringIn),
}

/// An MMIO instruction waiting for a device read's data: its exit's
/// contexts, the device reads already answered, and the one asked for.
struct MmioRead {
    vpctx: whv::WHV_VP_EXIT_CONTEXT,
    mem: whv::WHV_MEMORY_ACCESS_CONTEXT,
    reads: Vec<emulate::DeviceRead>,
    addr: u64,
    len: usize,
}

/// An `INS` waiting for its data (`VcpuFd::string_io`).
#[derive(Debug, Clone, Copy)]
struct StringIn {
    /// Bytes an element, and how many elements were asked of the port.
    size: usize,
    n: usize,
    rep: bool,
    /// The address size, the direction flag, the mode, the width of a
    /// linear address in 64-bit code, privilege level 3.
    wide: u8,
    down: bool,
    mode: super::exit::CodeMode,
    va_bits: u32,
    user: bool,
    /// `ES` as the exit had it.
    es: super::exit::SegmentView,
    /// `RIP` and RFLAGS once the elements are written.
    rip: u64,
    rflags: u64,
}

/// RFLAGS.RF (bit 16), which KVM's emulator sets while a `REP` string
/// instruction is not done and clears at the end of an instruction.
const RFLAGS_RF: u64 = 1 << 16;

/// A fault a string instruction's memory access takes.
#[derive(Debug, Clone, Copy)]
enum Fault {
    Page(GuestFault),
    Segment(super::exit::SegmentFault),
}

/// A segment register as [`super::exit::linearize`] reads it.
fn segment_view(s: &whv::WHV_X64_SEGMENT_REGISTER) -> super::exit::SegmentView {
    // SAFETY: the attributes' 16-bit view of the bit field.
    super::exit::SegmentView { base: s.Base, limit: s.Limit, attributes: unsafe { s.Anonymous.Attributes } }
}

/// A page fault the guest is to take for an access the backend made for it.
#[derive(Debug, Clone, Copy)]
struct GuestFault {
    address: u64,
    code: u32,
}

/// The size of the buffer an `INS`'s data is read into, KVM's
/// (`struct read_cache`, arch/x86/kvm/kvm_emulate.h: `u8 data[1024]`).
const STRING_DATA: usize = 1024;

/// State shared between a vCPU's handles and its run loop.
pub(crate) struct VcpuShared {
    pub(crate) index: u32,
    pub(crate) part: WHV_PARTITION_HANDLE,
    handle: Handle,
    pub(crate) run: KvmRunPage,
    inner: Arc<VmInner>,
    cpuid: Mutex<Vec<kvm_cpuid_entry2>>,
    /// The CR4 bits the CPUID of the last `KVM_SET_CPUID2` reserves, as
    /// KVM's `cr4_guest_rsvd_bits` (`cr4`): none before one, as KVM's.
    cr4_guest_rsvd: AtomicU64,
    pending: Mutex<Option<Pending>>,
    /// The data of an `INS` between its exit and the next run, as KVM's
    /// `pio_data` page is: Firecracker writes it through the slice the exit
    /// gave it, the run loop reads it after.
    string_data: Box<UnsafeCell<[u8; STRING_DATA]>>,
    /// Device writes of an emulated instruction after its first
    /// (`emulate::mmio`), handed to Firecracker one run each before the
    /// guest is entered again.
    device_writes: Mutex<Vec<emulate::DeviceWrite>>,
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
    /// `IA32_TSC_ADJUST` as it was at the host's last write of this vCPU's
    /// TSC or TSC_ADJUST: what it has moved since is what the guest moved
    /// the TSC by (a guest's write of either moves both, as on the
    /// processor), which KVM's generation offset does not have
    /// ([`VcpuShared::take_offset_of`]).
    tsc_adjust_base: AtomicU64,
    /// The machine-check MSRs, as KVM keeps them for each vCPU (`mce`).
    mce: Mutex<super::mce::Mce>,
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

/// The monotonic time KVM's TSC matching measures the time between writes
/// by (`get_kvmclock_base_ns`), in ns from the first use in the process: each
/// VM's matching starts from no write ([`super::tscsync::TscSync::new`]).
fn monotonic_ns() -> u64 {
    static BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    u64::try_from(BASE.get_or_init(std::time::Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Whether the host's TSC is invariant (CPUID.80000007H:EDX bit 8), which
/// KVM's `kvm_check_tsc_unstable` stands for here: a host kernel marks its
/// TSC unstable when it is not.
fn host_tsc_stable() -> bool {
    use core::arch::x86_64::__cpuid_count;
    __cpuid_count(0x8000_0000, 0).eax >= 0x8000_0007 && __cpuid_count(0x8000_0007, 0).edx & (1 << 8) != 0
}

impl VcpuShared {
    /// The rate of this vCPU's TSC as KVM's `virtual_tsc_khz`: the one
    /// `KVM_SET_TSC_KHZ` set, else the host's (0 if WHP does not report it).
    fn virtual_tsc_khz(&self) -> u32 {
        match self.tsc_khz.load(Ordering::Relaxed) {
            0 => u32::try_from(pvclock::tsc_hz() / 1000).unwrap_or(u32::MAX),
            khz => u32::try_from(khz).unwrap_or(u32::MAX),
        }
    }

    /// This vCPU's `IA32_TSC_ADJUST`: the partition's register, or the
    /// vCPU's copy where the partition does not keep it.
    fn tsc_adjust_now(&self) -> Result<u64> {
        if regs::software_msr(regs::MSR_IA32_TSC_ADJUST) {
            return Ok(self.tsc_adjust.load(Ordering::Acquire));
        }
        Ok(super::ffi::as_u64(&super::ffi::get_register(self.part, self.index, whv::WHvX64RegisterTscAdjust)?))
    }

    /// A host's write of `data` to this vCPU's `IA32_TSC`, as KVM's
    /// `kvm_synchronize_tsc` makes it (Linux v6.1 x86.c:2665-2718; the
    /// decision is [`super::tscsync::TscSync::write`]): a write matched to
    /// the current generation gives the vCPU the generation's offset, that of
    /// the vCPU that began it ([`Self::take_offset_of`]); any other is
    /// written as it is and begins a new generation; on a host whose TSC is
    /// not invariant a matched write is the value plus the time since the
    /// last write. Under the VM's lock, as KVM's `tsc_write_lock`; the state
    /// changes only when the write is made.
    pub(crate) fn synchronize_tsc(&self, data: u64) -> Result<()> {
        use super::tscsync::TscWrite;
        let inner = &self.inner;
        let mut sync = inner.tsc_sync.lock().unwrap();
        let mut next = *sync;
        let write = next.write(self.index, data, monotonic_ns(), self.virtual_tsc_khz(), host_tsc_stable());
        match write {
            TscWrite::New { value } | TscWrite::MatchedUnstable { value } => {
                super::ffi::set_register(self.part, self.index, whv::WHvX64RegisterTsc, super::ffi::reg64(value))?;
            }
            TscWrite::Matched { reference } => {
                let Some(r) = inner.vcpu(reference) else {
                    super::ffi::report(
                        log::Level::Error,
                        &format!("wick: vCPU {}'s TSC cannot take the offset of vCPU {reference}, which is gone", self.index),
                    );
                    return err(libc::EINVAL);
                };
                self.take_offset_of(&r)?;
            }
        }
        // A host's write sets the offset whole: the guest has moved nothing
        // since.
        self.tsc_adjust_base.store(self.tsc_adjust_now()?, Ordering::Release);
        *sync = next;
        Ok(())
    }

    /// Gives this vCPU the TSC offset of the generation `reference` began:
    /// `reference`'s TSC less what its guest has moved it by since its own
    /// host write ([`Self::tsc_adjust_base`]), written to this vCPU while
    /// partition time stands still, so that both TSCs are one offset from
    /// the host's, as KVM's `offset = kvm->arch.cur_tsc_offset`. Partition
    /// time stands still before a partition first runs if WHP keeps it so
    /// (two reads of the TSC 20 us apart are equal), else it is suspended
    /// for the copy (`WHvSuspendPartitionTime`, which Learn says no running
    /// vCPU allows) and resumed after it. A refusal fails the write, naming
    /// it, rather than writing an offset of its own.
    fn take_offset_of(&self, reference: &VcpuShared) -> Result<()> {
        let part = self.part;
        let tsc = |vp: u32| -> Result<u64> {
            Ok(super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvX64RegisterTsc)?))
        };
        let first = tsc(reference.index)?;
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_micros(20) {
            std::hint::spin_loop();
        }
        let suspend = tsc(reference.index)? != first;
        if suspend {
            // SAFETY: the VM's partition.
            let hres = unsafe { whv::WHvSuspendPartitionTime(part) };
            super::ffi::hr_of("WHvSuspendPartitionTime", hres, || {
                format!(
                    "for vCPU {} to take vCPU {}'s TSC offset, as KVM's TSC matching does; refused while a vCPU runs",
                    self.index, reference.index
                )
            })?;
        }
        let copied = (|| {
            let moved = reference.tsc_adjust_now()?.wrapping_sub(reference.tsc_adjust_base.load(Ordering::Acquire));
            let value = tsc(reference.index)?.wrapping_sub(moved);
            super::ffi::set_register(part, self.index, whv::WHvX64RegisterTsc, super::ffi::reg64(value))
        })();
        if suspend {
            // SAFETY: the VM's partition, whose time this call suspended.
            let hres = unsafe { whv::WHvResumePartitionTime(part) };
            super::ffi::hr_of("WHvResumePartitionTime", hres, String::new)?;
        }
        copied
    }

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
        cr4_guest_rsvd: AtomicU64::new(0),
        before_run: Mutex::new(Some(regs::BeforeRun::new())),
        pending: Mutex::new(None),
        string_data: Box::new(UnsafeCell::new([0; STRING_DATA])),
        device_writes: Mutex::new(Vec::new()),
        tsc_khz: AtomicU64::new(0),
        system_time_msr: AtomicU64::new(0),
        clock_gen: AtomicU64::new(0),
        immediate_exit: AtomicU8::new(0),
        run_seq: AtomicU64::new(0),
        tsc_deadline: AtomicU64::new(0),
        tsc_adjust: AtomicU64::new(0),
        misc_enable: AtomicU64::new(0),
        tsc_adjust_base: AtomicU64::new(0),
        mce: Mutex::new(super::mce::Mce::default()),
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
    // KVM writes 0 to a new vCPU's TSC, matched to the vCPUs made before it
    // (x86.c:11951, kvm_arch_vcpu_postcreate).
    shared.synchronize_tsc(0)?;
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
        if state.inject_bp
            && state.window.is_none()
            && let Some(w) = self.open_window()?
        {
            state.window = Some(w);
            state.inject_bp = false;
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
    /// Refused (`EINVAL`, as KVM's `kvm_is_valid_sregs`) when CR4 has a bit
    /// KVM would refuse: one it does not know, or one whose CPUID flag the
    /// host's supported CPUID or the vCPU's own lacks (`cr4`), named in a
    /// `whp:` line, before WHP is asked.
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        let guest = self.shared.cr4_guest_rsvd.load(Ordering::Acquire);
        if let Some((bits, lacking)) = super::cr4::refused(sregs.cr4, host_cr4_reserved(), guest) {
            let whose = match lacking {
                super::cr4::Lacking::Host => {
                    "this host's supported CPUID (its root partition's) lacks the flag, as KVM refuses on a host without the feature"
                }
                super::cr4::Lacking::Guest => "the vCPU's CPUID (KVM_SET_CPUID2) lacks the flag, as KVM refuses",
            };
            super::ffi::report(
                log::Level::Error,
                &format!("whp: KVM_SET_SREGS refused: CR4 {:#x} has {}: {whose}", sregs.cr4, super::cr4::names(bits)),
            );
            return err(libc::EINVAL);
        }
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
    /// As Linux v6.1's `kvm_vcpu_ioctl_x86_set_xcrs` (x86.c): `EINVAL` for
    /// flags or more than `KVM_MAX_XCRS` (16) entries; the first entry for
    /// XCR0 is written if `__kvm_set_xcr` takes it against the vCPU's CPUID
    /// ([`super::xcr::refused`]), else `EINVAL`; without one nothing is.
    pub fn set_xcrs(&self, xcrs: &kvm_xcrs) -> Result<()> {
        const KVM_MAX_XCRS: u32 = 16;
        if xcrs.flags != 0 || xcrs.nr_xcrs > KVM_MAX_XCRS {
            return err(libc::EINVAL);
        }
        let Some(xcr0) = xcrs.xcrs.iter().take(xcrs.nr_xcrs as usize).find(|e| e.xcr == 0).map(|e| e.value) else {
            return Ok(());
        };
        if super::xcr::refused(xcr0, self.guest_supported_xcr0()) {
            return err(libc::EINVAL);
        }
        regs::set_xcr0(self.part(), self.vp(), xcr0)
    }

    /// KVM's `guest_supported_xcr0` for this vCPU's CPUID: its leaf 0xD's
    /// components that KVM supports and the host has (`kvm_caps.supported_xcr0`
    /// is the host's XCR0 and `KVM_SUPPORTED_XCR0`; here the host's CPUID
    /// leaf 0xD, as the backend's supported CPUID is the host's); 0 before
    /// `KVM_SET_CPUID2`, as KVM's.
    fn guest_supported_xcr0(&self) -> u64 {
        let table = self.shared.cpuid.lock().unwrap();
        let leaf = table.iter().find(|e| e.function == 0xd && e.index == 0).map(|e| (e.eax, e.edx));
        super::xcr::guest_supported(leaf, regs::host_xfeatures().0 & super::xcr::KVM_SUPPORTED)
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
        let mce = self.shared.mce.lock().unwrap();
        // The kvm-clock MSRs, IA32_TSC_DEADLINE and the machine-check MSRs
        // are this backend's (see `pvclock`, `tscdeadline`, `mce`); a read
        // KVM refuses ends the call there, as in `__msr_io`.
        for (i, e) in msrs.as_mut_slice().iter_mut().take(n).enumerate() {
            if super::mce::is_mce(e.index) {
                match mce.get(e.index, true) {
                    Some(v) => e.data = v,
                    None => return Ok(i),
                }
                continue;
            }
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
        // As KVM's `__msr_io`: the entries up to the first one refused are
        // written, a machine-check MSR's write refused as `set_msr_mce`
        // refuses it (`mce`), and nothing after it.
        // The machine-check ones are kept only for the entries the call
        // wrote (`n`), so that a call WHP ends earlier keeps none after it.
        let entries = msrs.as_slice();
        let mut mce = self.shared.mce.lock().unwrap();
        let mut trial = mce.clone();
        let mut count = 0;
        for e in entries {
            if !regs::has_msr(e.index) || (super::mce::is_mce(e.index) && !trial.set(e.index, e.data, true, false)) {
                break;
            }
            count += 1;
        }
        let head = Msrs::from_entries(&entries[..count]).map_err(|_| super::Error::new(libc::EINVAL))?;
        let n = regs::set_msrs(self.part(), self.vp(), &head)?;
        for e in entries.iter().take(n).filter(|e| super::mce::is_mce(e.index)) {
            mce.set(e.index, e.data, true, false);
        }
        drop(mce);
        for e in msrs.as_slice().iter().take(n) {
            if e.index == regs::MSR_IA32_TSC {
                self.shared.synchronize_tsc(e.data)?;
            } else if e.index == MSR_TSC_DEADLINE {
                self.write_tsc_deadline(e.data)?;
            } else if regs::software_msr(e.index) {
                self.write_software_msr(e.index, e.data, true)?;
            } else {
                self.write_kvm_msr(e.index, e.data)?;
            }
        }
        // A host's write of TSC_ADJUST moves no TSC (KVM's are independent),
        // so what it holds now is the guest's starting point.
        if msrs.as_slice().iter().take(n).any(|e| e.index == regs::MSR_IA32_TSC_ADJUST) {
            let now = self.shared.tsc_adjust_now()?;
            self.shared.tsc_adjust_base.store(now, Ordering::Release);
        }
        Ok(n)
    }

    /// The vCPU's copy of a [`regs::software_msr`].
    fn software_msr(&self, index: u32) -> &AtomicU64 {
        if index == regs::MSR_IA32_TSC_ADJUST { &self.shared.tsc_adjust } else { &self.shared.misc_enable }
    }

    /// Writes a [`regs::software_msr`] as KVM's `kvm_set_msr_common` does
    /// (Linux 6.12): `IA32_TSC_ADJUST` is kept only when the guest's CPUID
    /// has TSC_ADJUST (a guest's write of it, which moves the TSC, is
    /// [`Self::guest_tsc_write`]'s); a guest's write of `IA32_MISC_ENABLE` that
    /// changes a read-only PMU bit is refused with #GP and leaves EMON as it
    /// was (the MWAIT quirk is KVM's default, so MWAIT is a plain bit).
    /// Returns whether the write was taken.
    fn write_software_msr(&self, index: u32, data: u64, host: bool) -> Result<bool> {
        const EMON: u64 = 1 << 7;
        const PMU_RO_MASK: u64 = (1 << 11) | (1 << 12);
        let cell = self.software_msr(index);
        if index == regs::MSR_IA32_TSC_ADJUST {
            // A guest's write, which moves the TSC, is `guest_tsc_write`'s;
            // a host's is taken as it is (x86.c:3618, `host_initiated`).
            if self.guest_has_tsc_adjust() {
                cell.store(data, Ordering::Release);
            }
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

    /// Whether a guest's WRMSR of `index` moves its TSC here
    /// ([`Self::guest_tsc_write`]): where the vCPU keeps `IA32_TSC_ADJUST`,
    /// a write of it with TSC_ADJUST in the guest's CPUID (KVM ignores one
    /// without, x86.c:3617), and a write of `IA32_TSC`, which exits there
    /// (`vm::tsc_write_exit`). Where the partition keeps TSC_ADJUST, WHP
    /// makes both writes itself, as the processor does.
    fn guest_moves_tsc(&self, index: u32) -> bool {
        regs::software_msr(regs::MSR_IA32_TSC_ADJUST)
            && (index == regs::MSR_IA32_TSC || index == regs::MSR_IA32_TSC_ADJUST && self.guest_has_tsc_adjust())
    }

    /// A guest's WRMSR of `IA32_TSC_ADJUST` or `IA32_TSC` where the vCPU
    /// keeps TSC_ADJUST, as KVM makes it (Linux v6.1 x86.c): TSC_ADJUST's
    /// write moves the TSC by its change (:3616-3627,
    /// `adjust_tsc_offset_guest`) and has kvm-clock published again
    /// (`KVM_REQ_CLOCK_UPDATE`; here at the next entry, `update_clock`);
    /// the TSC's sets the TSC and adds its change to TSC_ADJUST
    /// (:3661-3667). Exact: the TSC is read and written while partition
    /// time stands still ([`super::vm::VmInner::with_time_stopped`]), where
    /// a read and a write of a running TSC lost the time between them (a
    /// 1048576-tick move came to 1031279 on the PC, 1010122 on CI's EPYC:
    /// TSCADJREC at 43832df). The
    /// cost is every vCPU's TSC behind the host's by the time it stood
    /// (TSCADJREC prints it), where KVM's offset loses nothing; Linux writes
    /// TSC_ADJUST only when a CPU's differs from the boot CPU's, or after a
    /// failed warp test (arch/x86/kernel/tsc_sync.c:231-233, :529). `false`
    /// if the vCPU was kicked while it waited for the vCPUs: nothing is
    /// written, and the WRMSR is made again.
    fn guest_tsc_write(&self, index: u32, value: u64) -> Result<bool> {
        let shared = &self.shared;
        let adjust = &shared.tsc_adjust;
        let tsc = || self.register(whv::WHvX64RegisterTsc);
        let set = |v: u64| super::ffi::set_register(self.part(), self.vp(), whv::WHvX64RegisterTsc, super::ffi::reg64(v));
        let done = shared.inner.with_time_stopped(&shared.immediate_exit, || {
            let now = tsc()?;
            if index == regs::MSR_IA32_TSC_ADJUST {
                set(now.wrapping_add(value.wrapping_sub(adjust.load(Ordering::Acquire))))?;
                adjust.store(value, Ordering::Release);
            } else {
                set(value)?;
                adjust.store(adjust.load(Ordering::Acquire).wrapping_add(value.wrapping_sub(now)), Ordering::Release);
            }
            Ok(())
        });
        match done {
            None => Ok(false),
            Some(r) => {
                r?;
                if index == regs::MSR_IA32_TSC_ADJUST {
                    shared.clock_gen.store(u64::MAX, Ordering::Release);
                }
                Ok(true)
            }
        }
    }

    /// CPUID.(EAX=7,ECX=0):EBX bit 1, TSC_ADJUST, in the guest's CPUID.
    fn guest_has_tsc_adjust(&self) -> bool {
        self.shared.cpuid.lock().unwrap().iter().any(|e| e.function == 7 && e.index == 0 && e.ebx & (1 << 1) != 0)
    }

    /// `IA32_TSC_DEADLINE` as the guest reads it: 0 outside TSC-deadline
    /// mode, as on the processor and in KVM.
    fn read_tsc_deadline(&self) -> Result<u64> {
        let (page, _) = self.lapic_page()?;
        let apic_base = self.register(whv::WHvX64RegisterApicBase)?;
        Ok(if tscdeadline::page_in_deadline_mode(&page[..], apic_base) {
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
        let apic_base = self.register(whv::WHvX64RegisterApicBase)?;
        if tscdeadline::lost_xapic_deadline(&page[..], apic_base) {
            super::ffi::report(
                log::Level::Error,
                &format!(
                    "whp: vCPU {}'s IA32_TSC_DEADLINE write refused: its local APIC is in xAPIC mode, where WHP drops \
                     the guest's write of the LVT timer entry that selects TSC-deadline mode and with it the vector \
                     (the entry is {:#x}), so the timer's interrupt would never come. KVM takes that write in either \
                     mode; here a guest in TSC-deadline mode needs x2APIC mode (Linux turns it on when CPUID offers \
                     x2APIC, unless booted with nox2apic)",
                    self.vp(),
                    u32::from_le_bytes(page[0x320..0x324].try_into().unwrap())
                ),
            );
            return err(libc::ENOTSUP);
        }
        if !tscdeadline::page_in_deadline_mode(&page[..], apic_base) {
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
    /// raise none ([`tscdeadline::deadline_interrupt`]), at the APIC ID its
    /// mode has (`IA32_APIC_BASE`'s EXTD). On the vCPU's thread, while it is
    /// out of the guest.
    fn raise_tsc_deadline(&self) -> Result<()> {
        self.shared.tsc_deadline.store(0, Ordering::SeqCst);
        let (page, _) = self.lapic_page()?;
        let apic_base = self.register(whv::WHvX64RegisterApicBase)?;
        if let Some((apic_id, vector)) = tscdeadline::deadline_interrupt(&page[..], apic_base) {
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

    /// Keeps the table the backend answers the guest's CPUID from. Refused
    /// (`ENOTSUP`, the reason reported) when its leaf 0xD leaves out a state
    /// component a guest of this partition can enable all the same: KVM
    /// keeps a guest's XSETBV and `KVM_SET_XCRS` to the table's components
    /// (`__kvm_set_xcr`), and WHP neither exits on XSETBV nor takes a
    /// partition's components after it is set up, at `KVM_CREATE_VM`
    /// (`xcr`). What a partition lets a guest enable is bounded by the
    /// host's own leaf 0xD; every XSAVE feature WHP offers is given to the
    /// partition (`vm::configure`). Refused as well (`ENOTSUP`, the bit
    /// named) when its leaf 1 offers x2APIC, which this partition's local
    /// APIC, an xAPIC, does not have (`apicmode`): a Linux guest that is
    /// offered it turns it on, ignores the refused APIC_BASE write and
    /// drives an x2APIC that is not there.
    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        let table = cpuid.as_slice();
        let leaf1 = table.iter().find(|e| e.function == 1).map(|e| e.ecx);
        if super::apicmode::refuses_leaf1_ecx(self.shared.inner.apic, leaf1) {
            super::ffi::report(
                log::Level::Error,
                "whp: KVM_SET_CPUID2 refused: the CPUID offers x2APIC (leaf 1 ECX bit 21), and this partition's local \
                 APIC is an xAPIC (WHvX64LocalApicEmulationModeXApic), which refuses a guest's switch to x2APIC \
                 (APIC_BASE bit 10): a Linux guest offered the bit turns x2APIC on all the same and its timer and \
                 IPIs then reach no APIC. KVM emulates an x2APIC on any host; this backend offers none yet, so the \
                 supported CPUID leaves the bit out and a table or CPU template that sets it, or a snapshot made on \
                 KVM, is refused",
            );
            return err(libc::ENOTSUP);
        }
        let leaf = table.iter().find(|e| e.function == 0xd && e.index == 0).map(|e| (e.eax, e.edx));
        let host = regs::host_xfeatures().0;
        let guest = super::xcr::guest_supported(leaf, host & super::xcr::KVM_SUPPORTED);
        let unenforced = super::xcr::unenforced(host, guest);
        if unenforced != 0 {
            super::ffi::report(
                log::Level::Error,
                &format!(
                    "whp: KVM_SET_CPUID2 refused: the CPUID's leaf 0xD leaves out the XSAVE state components {} ({unenforced:#x}), \
                     which this host's partition lets a guest enable with XSETBV all the same (WHP has no XSETBV exit, and a \
                     partition's components are fixed when the VM is made), where KVM refuses a guest the components its CPUID \
                     leaves out; a CPU template that clears them is refused on this host",
                    super::xcr::names(unenforced)
                ),
            );
            return err(libc::ENOTSUP);
        }
        self.shared.cr4_guest_rsvd.store(super::cr4::reserved_bits(|l, i, r, b| cpuid_has(table, l, i, r, b)), Ordering::Release);
        *self.shared.cpuid.lock().unwrap() = table.to_vec();
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
        #[cfg(any(test, feature = "whp-trace"))]
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
        #[cfg(any(test, feature = "whp-trace"))]
        super::ffi::trace::note("WHvGetVirtualProcessorInterruptControllerState", self.vp(), &[], None, before, hres);
        super::ffi::hr_of("WHvGetVirtualProcessorInterruptControllerState", hres, || format!("vp {}", self.vp()))?;
        // Anything shorter is not the register page this conversion assumes.
        if (written as usize) < LAPIC_REGS {
            return err(libc::EIO);
        }
        Ok((page, written))
    }

    /// Reads the local APIC registers. In x2APIC mode the ID register is
    /// given in KVM's legacy format, the x2APIC ID in bits 31:24, as KVM
    /// gives it to a VMM that has not enabled `KVM_CAP_X2APIC_API`, which
    /// Firecracker does not (`kvm_apic_state_fixup`, Linux v6.1
    /// arch/x86/kvm/lapic.c 2692-2730); WHP's page holds the 32-bit ID as
    /// it is (X2E0REC c).
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let (mut page, _) = self.lapic_page()?;
        if self.register(whv::WHvX64RegisterApicBase)? & tscdeadline::APIC_BASE_EXTD != 0 {
            let id = u32::from_le_bytes(page[0x20..0x24].try_into().unwrap());
            page[0x20..0x24].copy_from_slice(&(id << 24).to_le_bytes());
        }
        let mut state = kvm_lapic_state {
            regs: [0; LAPIC_REGS],
        };
        for (dst, src) in state.regs.iter_mut().zip(page.iter()) {
            *dst = *src as std::os::raw::c_char;
        }
        Ok(state)
    }

    /// Writes the local APIC registers; the rest of the page WHP keeps is
    /// written back as it was. In x2APIC mode (APIC_BASE, as `KVM_SET_SREGS`
    /// left it) the ID register is taken in KVM's legacy format (bits 31:24)
    /// and the logical destination register made from it, as KVM's
    /// `kvm_apic_state_fixup` makes them (`kvm_apic_calc_x2apic_ldr`). The
    /// LVT timer entry is written as given, TSC-deadline mode included,
    /// which WHP keeps from this page in x2APIC mode (X2E0REC g): a
    /// snapshot made on KVM (APIC_BASE 0xfee00d00, LVT timer 0x400ec)
    /// restores as it was. The page's get and set here lose an interrupt
    /// requested between them (X2RMWREC), as KVM's `kvm_apic_set_state`
    /// replaces every register, the requests (IRR) too, with the caller's
    /// (`memcpy`, Linux v6.1 arch/x86/kvm/lapic.c 2760), so one requested
    /// after the caller's `KVM_GET_LAPIC` is lost there too; Firecracker
    /// sets a vCPU's local APIC before it first runs (`set_lint`) and at a
    /// restore, before it resumes. The run loop never sets the page
    /// ([`Self::write_x2apic_lvtt`]).
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let (mut page, size) = self.lapic_page()?;
        for (dst, src) in page.iter_mut().zip(klapic.regs.iter()) {
            *dst = *src as u8;
        }
        if self.register(whv::WHvX64RegisterApicBase)? & tscdeadline::APIC_BASE_EXTD != 0 {
            let id = u32::from_le_bytes(page[0x20..0x24].try_into().unwrap()) >> 24;
            page[0x20..0x24].copy_from_slice(&id.to_le_bytes());
            page[0xd0..0xd4].copy_from_slice(&x2apic_ldr(id).to_le_bytes());
        }
        #[cfg(any(test, feature = "whp-trace"))]
        let before = super::ffi::trace::stack();
        // SAFETY: the register page is valid for `size` bytes.
        let hres = unsafe {
            whv::WHvSetVirtualProcessorInterruptControllerState(self.part(), self.vp(), page.as_ptr().cast(), size)
        };
        #[cfg(any(test, feature = "whp-trace"))]
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
                if let Err(e) = shared.close_window(&w)
                    && exit.is_ok()
                {
                    return Err(e);
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

        // The device writes an instruction made after its first: each is
        // an exit of its own, as KVM's.
        loop {
            let next = {
                let mut queued = self.shared.device_writes.lock().unwrap();
                if queued.is_empty() { None } else { Some(queued.remove(0)) }
            };
            let Some(write) = next else { break };
            // SAFETY: at most 8 bytes into the 8-byte data area.
            unsafe { std::ptr::copy_nonoverlapping(write.data.as_ptr(), scratch, write.len.min(8)) };
            if let Some(exit) = self.device_write(write.addr, write.len.min(8), scratch) {
                return Ok(exit);
            }
        }

        // Complete a read deferred from the previous exit, before any entry
        // and before a kick is looked at, as KVM's KVM_RUN runs
        // `complete_userspace_io` before its `immediate_exit` check.
        let mut ram_retries = 0u32;
        let pending = self.shared.pending.lock().unwrap().take();
        if let Some(pending) = pending {
            match pending {
                Pending::Mmio(read) => {
                    let MmioRead { vpctx, mem, mut reads, addr, len } = *read;
                    let mut data = [0u8; 8];
                    // SAFETY: Firecracker's `len` (at most 8) bytes in the scratch.
                    unsafe { std::ptr::copy_nonoverlapping(scratch, data.as_mut_ptr(), len) };
                    reads.push(emulate::DeviceRead { addr, len, data });
                    if let Some(exit) = self.emulate_mmio(&vpctx, &mem, reads, scratch)? {
                        return Ok(exit);
                    }
                }
                Pending::StringIn(ins) => self.complete_string_in(&ins)?,
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
                    // Each way below finishes the instruction (or, for a
                    // REP string, an element of it, after which KVM's
                    // emulator ends the shadow too).
                    self.end_shadow(&ctx.VpContext, false)?;
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

                    // A string instruction only: a REP prefix on a plain IN
                    // or OUT does nothing, and KVM looks at the string bit
                    // alone (vmx.c handle_io, svm.c io_interception).
                    if string {
                        if let Some(exit) =
                            self.string_io(&ctx.VpContext, &io, is_write, size, rep, scratch, rip + instr_len)?
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
                    // A write's first access commits its block (a 4 KiB
                    // page, or all of a transparent huge page: memory
                    // advised `MADV_HUGEPAGE`) and has WHP map it before
                    // the re-run, as Linux's fault maps what it charged
                    // (`VmInner::populate_committed`); a read commits its
                    // page only and leaves it to WHP's fault (`wick_mm`:
                    // Linux's huge zero page).
                    #[cfg(test)]
                    let looked_up = std::time::Instant::now();
                    if let Some(host) = self.shared.inner.host_addr(mem.Gpa) {
                        #[cfg(test)]
                        let committing = std::time::Instant::now();
                        #[allow(clippy::cast_possible_truncation)]
                        let write = super::exit::memory_write(unsafe { mem.AccessInfo.AsUINT32 });
                        match libc::wick_mm::commit_block_on_access(host as usize, write) {
                            (libc::wick_mm::Access::Committed, block) => {
                                #[cfg(test)]
                                let populating = std::time::Instant::now();
                                #[cfg(test)]
                                let small = !super::vm::POPULATE_ONLY_HUGE_PAGES_FOR_TESTS.get();
                                #[cfg(not(test))]
                                let small = true;
                                if write && (small || block.len() >= libc::wick_mm::HUGE_PAGE) {
                                    self.shared.inner.populate_committed(mem.Gpa, block);
                                }
                                #[cfg(test)]
                                super::ffi::trace::split_lazy(looked_up, committing, populating);
                                continue;
                            }
                            (libc::wick_mm::Access::Exhausted(err), _) => libc::wick_mm::out_of_memory(host as usize, err),
                            (libc::wick_mm::Access::NotLazy, _) => {}
                        }
                    }
                    // Guest RAM that is a missing userfaultfd page: WHP
                    // honours its host PAGE_NOACCESS and exits at the
                    // access, which re-runs once the handler filled it, as
                    // KVM resolves the stage-2 fault through the host page.
                    // A page filled between the exit and the check (by the
                    // handler, or for another vCPU) is not reported: the
                    // access re-runs, never as MMIO, which would read zeros.
                    if libc::wick_uffd::active()
                        && let Some(host) = self.shared.inner.host_addr(mem.Gpa)
                    {
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
                    if let Some(exit) = self.emulate_mmio(&ctx.VpContext, &mem, Vec::new(), scratch)? {
                        return Ok(exit);
                    }
                    continue;
                }

                whv::WHvRunVpExitReasonX64Cpuid => {
                    // SAFETY: the union arm matches the exit reason.
                    let c = unsafe { ctx.Anonymous.CpuidAccess };
                    self.end_shadow(&ctx.VpContext, false)?;
                    self.handle_cpuid(&c, rip + instr_len)?;
                    continue;
                }

                whv::WHvRunVpExitReasonX64MsrAccess => {
                    // SAFETY: the union arm matches the exit reason.
                    let m = unsafe { ctx.Anonymous.MsrAccess };
                    self.end_shadow(&ctx.VpContext, false)?;
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
                    self.end_shadow(&ctx.VpContext, false)?;
                    regs::set_gpr_rax_rip(part, vp, super::exit::hypercall_rax(result, wide), rip + instr_len)?;
                    continue;
                }

                whv::WHvRunVpExitReasonX64InterruptWindow
                | whv::WHvRunVpExitReasonX64ApicEoi => continue,

                whv::WHvRunVpExitReasonUnrecoverableException => return Ok(VcpuExit::Shutdown),

                // A guest #GP on an x2APIC partition (`gp`), or #DB or #BP
                // for the gdb stub (a partition made with the `gdb`
                // feature).
                whv::WHvRunVpExitReasonException => {
                    // SAFETY: the union arm matches the exit reason.
                    let ex = unsafe { ctx.Anonymous.VpException };
                    #[cfg(feature = "gdb")]
                    {
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
                        // A #GP is the run loop's, below.
                        if ex.ExceptionType != super::gp::GP_VECTOR {
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
                    }
                    if ex.ExceptionType != super::gp::GP_VECTOR {
                        return Ok(VcpuExit::InternalError);
                    }
                    match self.gp_exit(&ctx.VpContext, &ex)? {
                        Some(exit) => return Ok(exit),
                        None => continue,
                    }
                }

                _ => return Ok(VcpuExit::InternalError),
            }
        }
    }

    /// A guest #GP that WHP handed the run loop (`gp`): the guest's x2APIC
    /// write of the LVT timer entry is finished as KVM finishes it
    /// ([`Self::write_x2apic_lvtt`]); any other #GP goes back to the guest,
    /// merged with the event WHP was delivering ([`super::gp::give_back`]),
    /// or ends as a triple fault (`VcpuExit::Shutdown`). Per vCPU only: the
    /// exit context and this vCPU's registers, no lock another vCPU or the
    /// VMM's thread waits on, no allocation and no log line, so that a
    /// guest's storm of #GPs costs only its own vCPU's thread, under the
    /// jail's CPU limit like any guest work.
    fn gp_exit(&self, vpctx: &whv::WHV_VP_EXIT_CONTEXT, ex: &whv::WHV_VP_EXCEPTION_CONTEXT) -> Result<Option<VcpuExit<'static>>> {
        let (part, vp) = (self.part(), self.vp());
        // SAFETY: plain 16-bit views of the exit context's bit fields.
        let (state, cs) = unsafe { (vpctx.ExecutionState.AsUINT16, vpctx.Cs.Anonymous.Attributes) };
        let cpl = super::exit::cpl(state);
        // `WHV_X64_VP_EXECUTION_STATE.InterruptionPending`, bit 6.
        let delivering = state >> 6 & 1 == 1;
        let long = super::exit::long_mode_code(state, cs);
        let bytes = &ex.InstructionBytes[..usize::from(ex.InstructionByteCount).min(ex.InstructionBytes.len())];
        if super::gp::may_emulate(cpl, delivering, bytes, long) {
            let apic_base = self.register(whv::WHvX64RegisterApicBase)?;
            #[allow(clippy::cast_possible_truncation)]
            let (ecx, eax) = (self.register(whv::WHvX64RegisterRcx)? as u32, self.register(whv::WHvX64RegisterRax)? as u32);
            let x2apic = apic_base & tscdeadline::APIC_BASE_EXTD != 0;
            if let super::gp::Decision::LvttWrite { length, eax } = super::gp::decide(cpl, delivering, bytes, long, x2apic, ecx, eax) {
                self.write_x2apic_lvtt(eax)?;
                self.end_shadow(vpctx, false)?;
                regs::set_rip(part, vp, vpctx.Rip + u64::from(length))?;
                return Ok(None);
            }
        }
        let pending = if delivering {
            super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvRegisterPendingInterruption)?)
        } else {
            0
        };
        match super::gp::give_back(pending, ex.ErrorCode) {
            super::gp::GiveBack::Event(event) => {
                super::ffi::set_register(part, vp, whv::WHvRegisterPendingInterruption, super::ffi::reg64(event))?;
                Ok(None)
            }
            super::gp::GiveBack::Shutdown => Ok(Some(VcpuExit::Shutdown)),
        }
    }

    /// The guest's x2APIC write of the LVT timer entry (MSR 0x832's low 32
    /// bits `eax`), which WHP refuses in TSC-deadline mode, as KVM's
    /// `kvm_lapic_reg_write` takes it (`gp::lvtt_write`): the entry gets
    /// KVM's value, and a change into or out of TSC-deadline mode cancels
    /// the timer, zeroes the initial count and the deadline, as
    /// `apic_update_lvtt` (Linux v6.1 arch/x86/kvm/lapic.c 1583-1599). The
    /// entry is written through `WHvX64RegisterApicLvtTimer` and read back,
    /// and a value WHP does not keep that way fails the vCPU (`ENOTSUP`),
    /// named: that is every TSC-deadline-mode value (the register refuses
    /// 0x400ec with errno 87 once EXTD is set and takes 0x100ec and 0xec:
    /// X2E0REC c, CI runs 43521200989 and 43524342863), so option E's
    /// x2APIC partition has no TSC-deadline timer yet, and its partitions
    /// are tests' only (`vm::X2APIC_PARTITIONS`).
    ///
    /// The one other way WHP keeps that mode, the APIC register page's get
    /// and set (KVM_SET_LAPIC's, X2E0REC g, CI run 43528910212), is never
    /// taken while the guest runs: it is a read-modify-write of the whole
    /// APIC, and an interrupt requested between the get and the set is lost
    /// (X2RMWREC, PC step 15a at 305a806, a Ryzen 9 7900: an MSI injected
    /// from another thread and vCPU 1's IPI, each lost at its first round),
    /// while an irqfd's writer, the MSI hook or another vCPU may request one
    /// at any time. A guest that hangs is worse than one that fails, so this
    /// function has no page set at all, and
    /// `test_a_page_set_loses_interrupts_and_the_lvt_timer_write_makes_none`
    /// asserts both: the loss, and that this write sets no page.
    fn write_x2apic_lvtt(&self, eax: u32) -> Result<()> {
        let (part, vp) = (self.part(), self.vp());
        let sw_enabled = self.register(whv::WHvX64RegisterApicSpurious)? & (1 << 8) != 0;
        let deadline_cpuid = cpuid_has(&self.shared.cpuid.lock().unwrap(), 1, 0, 2, 24);
        let value = super::gp::lvtt_write(eax, sw_enabled, deadline_cpuid);
        #[allow(clippy::cast_possible_truncation)]
        let old = self.register(whv::WHvX64RegisterApicLvtTimer)? as u32;
        if super::gp::tsc_deadline_mode(old) != super::gp::tsc_deadline_mode(value) {
            let shared = &self.shared;
            shared.deadline_gen.fetch_add(1, Ordering::SeqCst);
            shared.deadline_fired.store(0, Ordering::SeqCst);
            shared.inner.deadlines.disarm(vp);
            shared.tsc_deadline.store(0, Ordering::SeqCst);
            super::ffi::set_register(part, vp, whv::WHvX64RegisterApicInitCount, super::ffi::reg64(0))?;
        }
        let kept = |this: &Self| -> Result<bool> { Ok(this.register(whv::WHvX64RegisterApicLvtTimer)? as u32 == value) };
        if super::ffi::set_register(part, vp, whv::WHvX64RegisterApicLvtTimer, super::ffi::reg64(u64::from(value))).is_ok() && kept(self)? {
            return Ok(());
        }
        super::ffi::report(
            log::Level::Error,
            &format!(
                "whp: vCPU {vp}'s x2APIC write of the LVT timer entry ({value:#x}) is refused: \
                 WHvX64RegisterApicLvtTimer does not keep it (TSC-deadline mode is refused there in x2APIC mode, \
                 X2E0REC c), and the APIC register page's get and set, the one other way, lose an interrupt \
                 requested between them (X2RMWREC, PC step 15a at 305a806): the guest's timer would not be its own"
            ),
        );
        err(libc::ENOTSUP)
    }

    /// Leaves the interrupt shadow as KVM leaves it after an instruction the
    /// VMM finished ([`super::exit::shadow_after`]): a WHP call only when
    /// the exit had a shadow (the instruction right after STI or MOV SS) or
    /// the instruction loads SS, so that an interrupt requested meanwhile
    /// is taken at the next entry, before the next instruction.
    fn end_shadow(&self, vpctx: &whv::WHV_VP_EXIT_CONTEXT, loads_ss: bool) -> Result<()> {
        // SAFETY: the 16-bit view of the execution state's bit fields.
        let had = unsafe { vpctx.ExecutionState.AsUINT16 } >> 12 & 1 == 1;
        let Some(shadow) = super::exit::shadow_after(had, loads_ss) else {
            return Ok(());
        };
        let (part, vp) = (self.part(), self.vp());
        let state = super::ffi::as_u64(&super::ffi::get_register(part, vp, whv::WHvRegisterInterruptState)?);
        super::ffi::set_register(part, vp, whv::WHvRegisterInterruptState, super::ffi::reg64((state & !1) | u64::from(shadow)))
    }

    /// Emulates the MMIO instruction of an exit (`vpctx`, `mem`), its device
    /// reads before `reads` answered with their data. Returns the exit to
    /// report to Firecracker, or `None` if the instruction finished with
    /// nothing for it (an I/O APIC access, an `ioeventfd`'s write, guest
    /// RAM). A device read past `reads` that the irqchip does not answer
    /// is asked of Firecracker (`VcpuExit::MmioRead`) and the instruction
    /// waits for the next run ([`Pending::Mmio`]), which finishes it in the
    /// host before entering the guest.
    fn emulate_mmio(
        &self,
        vpctx: &whv::WHV_VP_EXIT_CONTEXT,
        mem: &whv::WHV_MEMORY_ACCESS_CONTEXT,
        mut reads: Vec<emulate::DeviceRead>,
        scratch: *mut u8,
    ) -> Result<Option<VcpuExit<'_>>> {
        let part = self.part();
        let vp = self.vp();
        let ram = self.shared.inner.ram();
        loop {
            let mut more = Vec::new();
            let outcome = emulate::mmio(part, vp, vpctx, mem, scratch, &reads, ram, &mut more)?;
            let ended = match outcome {
                emulate::Outcome::Completed => super::exit::Emulated::Completed,
                emulate::Outcome::Failed => super::exit::Emulated::Failed,
                emulate::Outcome::Mismatch { .. } => super::exit::Emulated::Mismatch,
                emulate::Outcome::Read { addr, len, .. } => super::exit::Emulated::Read { addr, len },
                emulate::Outcome::Write { .. } => super::exit::Emulated::Write,
            };
            let step = super::exit::mmio_step(ended, reads.len());
            if matches!(step, super::exit::MmioStep::Done | super::exit::MmioStep::Write) {
                // The instruction is finished: its shadow, as KVM's
                // emulator leaves it.
                let bytes = &mem.InstructionBytes[..usize::from(mem.InstructionByteCount).min(16)];
                // SAFETY: plain 16-bit views of the exit context's bit fields.
                let (state, cs) = unsafe { (vpctx.ExecutionState.AsUINT16, vpctx.Cs.Anonymous.Attributes) };
                self.end_shadow(vpctx, super::exit::loads_ss(bytes, super::exit::long_mode_code(state, cs)))?;
            }
            match step {
                super::exit::MmioStep::Done => {
                    self.shared.device_writes.lock().unwrap().append(&mut more);
                    return Ok(None);
                }
                super::exit::MmioStep::Write => {
                    let emulate::Outcome::Write { addr, len, .. } = outcome else { unreachable!() };
                    self.shared.device_writes.lock().unwrap().append(&mut more);
                    return Ok(self.device_write(addr, len, scratch));
                }
                // Entering the guest would run the instruction again and
                // ask its devices again: refused, as KVM's emulator failure
                // is an internal error.
                super::exit::MmioStep::Stop => {
                    let why = match outcome {
                        emulate::Outcome::Mismatch { asked, given } => format!(
                            "asked for a read of {} bytes at {:#x} where the data given was for {} bytes at {:#x}",
                            asked.1, asked.0, given.1, given.0
                        ),
                        _ => format!("did not finish after {} device reads", reads.len()),
                    };
                    super::ffi::report(log::Level::Error, &format!("whp: the MMIO instruction at {:#x} {why}", vpctx.Rip));
                    return Ok(Some(VcpuExit::InternalError));
                }
                // Device writes before an aborted read are not kept: the
                // emulation that finishes the instruction makes them again.
                super::exit::MmioStep::Ask { addr, len } => {
                    let mut chip = self.shared.inner.irqchip.lock().unwrap();
                    if chip.mmio_handles(addr) {
                        let mut data = [0u8; 8];
                        chip.mmio_read(addr, &mut data[..len]);
                        drop(chip);
                        reads.push(emulate::DeviceRead { addr, len, data });
                        continue;
                    }
                    drop(chip);
                    *self.shared.pending.lock().unwrap() =
                        Some(Pending::Mmio(Box::new(MmioRead { vpctx: *vpctx, mem: *mem, reads, addr, len })));
                    let buf = unsafe { slice_mut(scratch, len) };
                    return Ok(Some(VcpuExit::MmioRead(addr, buf)));
                }
            }
        }
    }

    /// A write of the `len` bytes in `scratch` to the device at `addr`: the
    /// irqchip's, an ioeventfd's, or an exit to Firecracker.
    fn device_write(&self, addr: u64, len: usize, scratch: *mut u8) -> Option<VcpuExit<'_>> {
        let mut chip = self.shared.inner.irqchip.lock().unwrap();
        if chip.mmio_handles(addr) {
            let data = unsafe { slice(scratch, len) };
            let inject = chip.mmio_write(addr, data);
            drop(chip);
            if let Some((a, d)) = inject {
                self.shared.inner.inject_msi(a, d);
            }
            return None;
        }
        drop(chip);
        let data = unsafe { slice(scratch, len) };
        if self.shared.inner.match_ioevent(&IoEventAddress::Mmio(addr), data) {
            return None;
        }
        let data = unsafe { slice(scratch, len) };
        Some(VcpuExit::MmioWrite(addr, data))
    }

    /// `INS` and `OUTS`, with or without `REP`, done as KVM's emulator does
    /// them (Linux v6.1 arch/x86/kvm/emulate.c: `em_out`, `em_in`,
    /// `pio_in_emulated`, `__linearize`, `x86_emulate_insn`; both vendors'
    /// string port exits go to it), so that Firecracker sees KVM's exits and
    /// the guest KVM's registers and faults:
    ///
    /// - `OUTS` is one `KVM_EXIT_IO` an element (`em_out` passes a count of
    ///   1): the element is read from the guest's memory at the source
    ///   segment's `RSI`, `RSI` moves by its size, `RCX` goes down by one
    ///   with `REP`.
    /// - `INS` asks the port for several elements at once
    ///   ([`super::exit::ins_read_ahead`]), one `KVM_EXIT_IO` with that
    ///   count; at the next run they are written to `ES:RDI` and the
    ///   registers move by as many ([`VcpuFd::complete_string_in`]).
    /// - Without `REP`, `RIP` passes the instruction and RFLAGS.RF is
    ///   cleared. With it, `RIP` stays at the instruction and RF is set
    ///   after every element, also the last: KVM ends a `REP` instruction
    ///   only when it finds `RCX` at 0 (the guest's next entry runs it
    ///   again with nothing left, and the processor, or the `count == 0`
    ///   case here if the processor exits for it, passes it).
    /// - `REP` with nothing left passes the instruction, RF cleared, and on
    ///   a guest whose CPUID names Intel, with 32-bit addresses, `RCX`
    ///   becomes 0 whole (`string_registers_quirk`).
    ///
    /// The address is checked as KVM's emulator checks it
    /// ([`super::exit::linearize`]: canonical in 64-bit code; the
    /// segment's presence, type and limit elsewhere), a failure being the
    /// guest's #GP(0), or #SS(0) through SS. The guest's memory is then
    /// reached as the processor would reach it: each page translated with
    /// the access's right at the guest's privilege level
    /// (`WHvTranslateGva`), a refusal delivered as the page fault it is.
    /// After a fault nothing of the element is done and `RIP` and RFLAGS
    /// stay. The registers and the segment are used at the instruction's
    /// address size and segment prefix ([`super::exit::string_addressing`]).
    /// The I/O permission bitmap is not checked here: the processor checks
    /// it before it exits (Intel SDM vol. 3C 26.1.1, the general-protection
    /// exceptions based on the TSS's I/O permission bits come before a VM
    /// exit).
    ///
    /// Not as KVM: a string operand whose guest physical address no memory
    /// slot backs fails the run with `EFAULT` and a report, where KVM's
    /// emulator makes MMIO exits for it.
    ///
    /// Before, the instruction went to WHP's emulator, whose memory
    /// callback took the string's own memory for a device's: an `OUTS`
    /// asked Firecracker for an `IN` from "port" `RSI` and never completed
    /// (CI run 43392627996, a `REP OUTSB` from 0x8300: twelve `IoIn 0x8300`
    /// in a row), and an `INS` was never given its data.
    #[allow(clippy::too_many_arguments)]
    fn string_io(
        &self,
        vpctx: &whv::WHV_VP_EXIT_CONTEXT,
        io: &whv::WHV_X64_IO_PORT_ACCESS_CONTEXT,
        write: bool,
        size: usize,
        rep: bool,
        scratch: *mut u8,
        rip_after: u64,
    ) -> Result<Option<VcpuExit<'_>>> {
        use super::exit;
        use super::ffi::reg64;
        let (part, vp) = (self.part(), self.vp());
        // SAFETY: plain 16-bit views of the exit context's bit fields.
        let (state, cs) = unsafe { (vpctx.ExecutionState.AsUINT16, vpctx.Cs.Anonymous.Attributes) };
        let mode = exit::code_mode(state, vpctx.Rflags, cs);
        let long = mode == exit::CodeMode::Prot64;
        let bytes = &io.InstructionBytes[..usize::from(io.InstructionByteCount).min(16)];
        // The default address size outside 64-bit code is CS.D's, in real
        // and virtual-8086 mode too (emulate.c, `x86_decode_insn`).
        let addressing = exit::string_addressing(bytes, long, cs >> 14 & 1 == 1);
        let wide = addressing.address_bytes;
        let down = vpctx.Rflags >> 10 & 1 == 1;
        let user = exit::cpl(state) == 3;
        let port = io.PortNumber;
        let count = exit::string_count(rep, io.Rcx, wide);
        if count == 0 {
            // REP with nothing left: the instruction does nothing.
            let mut names = vec![whv::WHvX64RegisterRip, whv::WHvX64RegisterRflags];
            let mut values = vec![reg64(rip_after), reg64(vpctx.Rflags & !RFLAGS_RF)];
            if wide == 4 && self.guest_vendor_intel() {
                names.push(whv::WHvX64RegisterRcx);
                values.push(reg64(0));
            }
            super::ffi::set_registers(part, vp, &names, &values)?;
            return Ok(None);
        }
        let va_bits = if long { self.virtual_address_bits()? } else { 48 };
        // RFLAGS and RIP once an element is done.
        let rflags = if rep { vpctx.Rflags | RFLAGS_RF } else { vpctx.Rflags & !RFLAGS_RF };
        let rip = if rep { vpctx.Rip } else { rip_after };

        if write {
            let segment = addressing.segment.unwrap_or(exit::Segment::Ds);
            let view = self.string_segment(segment, io)?;
            let offset = exit::string_offset(io.Rsi, wide);
            let at = match exit::linearize(segment, view, offset, size as u64, false, mode, va_bits) {
                Ok(at) => at,
                Err(fault) => {
                    self.segment_fault(fault)?;
                    return Ok(None);
                }
            };
            let mut element = [0u8; 4];
            if let Some(fault) = self.read_guest_va(at, &mut element[..size], user)? {
                self.page_fault(fault)?;
                return Ok(None);
            }
            let names = [whv::WHvX64RegisterRsi, whv::WHvX64RegisterRip, whv::WHvX64RegisterRflags, whv::WHvX64RegisterRcx];
            let values = [
                reg64(exit::string_advance(io.Rsi, wide, size as u64, down)),
                reg64(rip),
                reg64(rflags),
                reg64(exit::string_advance(io.Rcx, wide, 1, true)),
            ];
            let n = if rep { 4 } else { 3 };
            super::ffi::set_registers(part, vp, &names[..n], &values[..n])?;
            // SAFETY: at most 4 bytes into the 8-byte data area.
            unsafe { std::ptr::copy_nonoverlapping(element.as_ptr(), scratch, size) };
            {
                let mut chip = self.shared.inner.irqchip.lock().unwrap();
                if chip.pio_handles(port) {
                    let data = unsafe { slice(scratch, size) };
                    chip.pio_write(port, data, &self.shared.inner);
                    return Ok(None);
                }
            }
            let data = unsafe { slice(scratch, size) };
            if self.shared.inner.match_ioevent(&IoEventAddress::Pio(u64::from(port)), data) {
                return Ok(None);
            }
            let data = unsafe { slice(scratch, size) };
            return Ok(Some(VcpuExit::IoOut(port, data)));
        }

        let n = exit::ins_read_ahead(size, io.Rdi, count, down);
        let ins = StringIn {
            size,
            n,
            rep,
            wide,
            down,
            mode,
            va_bits,
            user,
            es: segment_view(&io.Es),
            rip,
            rflags,
        };
        // SAFETY: `n * size` is at most the buffer (`ins_read_ahead`); the
        // buffer is the vCPU's, used by its run loop and, between two runs,
        // by the holder of this exit.
        let buf = unsafe { std::slice::from_raw_parts_mut(self.shared.string_data.get().cast::<u8>(), n * size) };
        {
            let mut chip = self.shared.inner.irqchip.lock().unwrap();
            if chip.pio_handles(port) {
                for element in buf.chunks_mut(size) {
                    chip.pio_read(port, element);
                }
                drop(chip);
                self.complete_string_in(&ins)?;
                return Ok(None);
            }
        }
        *self.shared.pending.lock().unwrap() = Some(Pending::StringIn(ins));
        Ok(Some(VcpuExit::IoIn(port, buf)))
    }

    /// The elements an `INS` was given, written to `ES:RDI`; `RDI` moves
    /// and `RCX` goes down by as many, and `RIP` and RFLAGS become what
    /// [`VcpuFd::string_io`] says. As KVM's emulator writes them
    /// (emulate.c, `pio_in_emulated`, `writeback`): with `REP` and the
    /// direction flag clear, all of them in one write (`OP_MEM_STR`), its
    /// address checked for all of them at once; a fault anywhere in it
    /// moves no register (the pages before the faulting one keep what was
    /// written in them). Otherwise one element after the other, a fault
    /// keeping those before it written and counted and dropping the rest.
    fn complete_string_in(&self, ins: &StringIn) -> Result<()> {
        use super::exit;
        use super::ffi::{as_u64, reg64};
        let (part, vp) = (self.part(), self.vp());
        let names = [whv::WHvX64RegisterRdi, whv::WHvX64RegisterRcx, whv::WHvX64RegisterRip, whv::WHvX64RegisterRflags];
        let mut values = [reg64(0); 2];
        super::ffi::get_registers(part, vp, &names[..2], &mut values)?;
        let (mut rdi, mut rcx) = (as_u64(&values[0]), as_u64(&values[1]));
        // SAFETY: the vCPU's buffer, which Firecracker filled through the
        // exit's slice and no longer holds (it called `run` again).
        let data = unsafe { std::slice::from_raw_parts(self.shared.string_data.get().cast::<u8>(), ins.n * ins.size) };
        let whole = ins.rep && !ins.down;
        let element = if whole { data.len() } else { ins.size };
        let mut fault = None;
        let mut done = 0u64;
        for piece in data.chunks(element) {
            let offset = exit::string_offset(rdi, ins.wide);
            let at = match exit::linearize(exit::Segment::Es, ins.es, offset, piece.len() as u64, true, ins.mode, ins.va_bits) {
                Ok(at) => at,
                Err(f) => {
                    fault = Some(Fault::Segment(f));
                    break;
                }
            };
            if let Some(f) = self.write_guest_va(at, piece, ins.user)? {
                fault = Some(Fault::Page(f));
                break;
            }
            let elements = (piece.len() / ins.size) as u64;
            rdi = exit::string_advance(rdi, ins.wide, elements * ins.size as u64, ins.down);
            if ins.rep {
                rcx = exit::string_advance(rcx, ins.wide, elements, true);
            }
            done += elements;
        }
        if done > 0 {
            // The registers of the elements done; RIP and RFLAGS only if
            // none faulted (a fault is not a trap: KVM writes neither).
            let n = if fault.is_none() { 4 } else { 2 };
            let values = [reg64(rdi), reg64(rcx), reg64(ins.rip), reg64(ins.rflags)];
            super::ffi::set_registers(part, vp, &names[..n], &values[..n])?;
        }
        match fault {
            Some(Fault::Page(f)) => self.page_fault(f),
            Some(Fault::Segment(f)) => self.segment_fault(f),
            None => Ok(()),
        }
    }

    /// The segment an `OUTS` reads through: DS's and ES's from the exit,
    /// another one read.
    fn string_segment(&self, segment: super::exit::Segment, io: &whv::WHV_X64_IO_PORT_ACCESS_CONTEXT) -> Result<super::exit::SegmentView> {
        use super::exit::Segment;
        let name = match segment {
            Segment::Ds => return Ok(segment_view(&io.Ds)),
            Segment::Es => return Ok(segment_view(&io.Es)),
            Segment::Fs => whv::WHvX64RegisterFs,
            Segment::Gs => whv::WHvX64RegisterGs,
            Segment::Cs => whv::WHvX64RegisterCs,
            Segment::Ss => whv::WHvX64RegisterSs,
        };
        // SAFETY: a segment register's value.
        Ok(segment_view(&unsafe { super::ffi::get_register(self.part(), self.vp(), name)?.Segment }))
    }

    /// The width of a linear address in 64-bit code: 57 bits with CR4.LA57
    /// (bit 12), 48 without (emulate.c, `ctxt_virt_addr_bits`).
    fn virtual_address_bits(&self) -> Result<u32> {
        let cr4 = super::ffi::as_u64(&super::ffi::get_register(self.part(), self.vp(), whv::WHvX64RegisterCr4)?);
        Ok(if cr4 >> 12 & 1 == 1 { 57 } else { 48 })
    }

    /// Whether the guest's CPUID leaf 0, as the table set on this vCPU has
    /// it, names Intel (KVM's `vendor_intel` reads the guest's CPUID; no
    /// leaf 0 is no vendor).
    fn guest_vendor_amd_or_hygon(&self) -> bool {
        let table = self.shared.cpuid.lock().unwrap();
        table
            .iter()
            .find(|e| e.function == 0)
            .is_some_and(|e| super::exit::guest_vendor_amd_or_hygon(e.ebx, e.ecx, e.edx))
    }

    fn guest_vendor_intel(&self) -> bool {
        let table = self.shared.cpuid.lock().unwrap();
        table
            .iter()
            .find(|e| e.function == 0)
            .is_some_and(|e| super::exit::guest_vendor_intel(e.ebx, e.ecx, e.edx))
    }

    /// Leaves the guest the #GP(0) or #SS(0) a segment check gives, to take
    /// at its next entry. `RIP` stays at the instruction.
    fn segment_fault(&self, fault: super::exit::SegmentFault) -> Result<()> {
        let pending = match fault {
            super::exit::SegmentFault::Gp => super::debug::pending_gp(),
            super::exit::SegmentFault::Ss => super::debug::pending_ss(),
        };
        super::ffi::set_register(self.part(), self.vp(), whv::WHvRegisterPendingInterruption, super::ffi::reg64(pending))
    }

    /// The guest physical address of the guest's linear address `gva` for
    /// a read or a write at the guest's privilege level, as the processor's
    /// own access would find it (the accessed and dirty bits set, SMAP
    /// enforced); the page fault that access would take; or, for a page the
    /// guest's tables put where there is no access for another reason
    /// (`WHV_TRANSLATE_GVA_RESULT_CODE`: an address outside the guest's
    /// physical memory, an intercept), `EFAULT` with a report: the run
    /// fails rather than the access be made up.
    fn gpa_of(&self, gva: u64, write: bool, user: bool) -> Result<std::result::Result<u64, GuestFault>> {
        let right = if write { whv::WHvTranslateGvaFlagValidateWrite } else { whv::WHvTranslateGvaFlagValidateRead };
        let flags = right | whv::WHvTranslateGvaFlagSetPageTableBits | whv::WHvTranslateGvaFlagEnforceSmap;
        let (code, gpa) = self.translate_walk(gva, flags)?;
        match code {
            whv::WHvTranslateGvaResultSuccess => Ok(Ok(gpa)),
            whv::WHvTranslateGvaResultPageNotPresent
            | whv::WHvTranslateGvaResultPrivilegeViolation
            | whv::WHvTranslateGvaResultInvalidPageTableFlags => Ok(Err(GuestFault {
                address: gva,
                code: super::exit::page_fault_code(
                    code == whv::WHvTranslateGvaResultPrivilegeViolation,
                    write,
                    user,
                    code == whv::WHvTranslateGvaResultInvalidPageTableFlags,
                ),
            })),
            other => {
                super::ffi::report(
                    log::Level::Error,
                    &format!("whp: a string instruction's memory at {gva:#x}: WHvTranslateGva result {other}, no access the backend can make"),
                );
                err(libc::EFAULT)
            }
        }
    }

    /// Reads the guest's memory at the linear address `gva`, page by page;
    /// `Some` for the page fault the read takes (nothing is then used).
    fn read_guest_va(&self, gva: u64, buf: &mut [u8], user: bool) -> Result<Option<GuestFault>> {
        let mut done = 0;
        while done < buf.len() {
            let at = gva.wrapping_add(done as u64);
            #[allow(clippy::cast_possible_truncation)]
            let piece = ((4096 - at % 4096) as usize).min(buf.len() - done);
            let gpa = match self.gpa_of(at, false, user)? {
                Ok(gpa) => gpa,
                Err(fault) => return Ok(Some(fault)),
            };
            if !self.shared.inner.read_guest(gpa, &mut buf[done..done + piece]) {
                super::ffi::report(log::Level::Error, &format!("whp: a string instruction reads {gpa:#x}, which no memory slot backs"));
                return err(libc::EFAULT);
            }
            done += piece;
        }
        Ok(None)
    }

    /// Writes the guest's memory at the linear address `gva`, page by page;
    /// `Some` for the page fault the write takes.
    fn write_guest_va(&self, gva: u64, data: &[u8], user: bool) -> Result<Option<GuestFault>> {
        let mut done = 0;
        while done < data.len() {
            let at = gva.wrapping_add(done as u64);
            #[allow(clippy::cast_possible_truncation)]
            let piece = ((4096 - at % 4096) as usize).min(data.len() - done);
            let gpa = match self.gpa_of(at, true, user)? {
                Ok(gpa) => gpa,
                Err(fault) => return Ok(Some(fault)),
            };
            if !self.shared.inner.write_guest(gpa, &data[done..done + piece]) {
                super::ffi::report(
                    log::Level::Error,
                    &format!("whp: a string instruction writes {gpa:#x}, which no memory slot backs or a read-only one does"),
                );
                return err(libc::EFAULT);
            }
            done += piece;
        }
        Ok(None)
    }

    /// Leaves the guest a page fault to take at its next entry: the address
    /// in CR2, the exception pending. `RIP` stays at the instruction.
    fn page_fault(&self, fault: GuestFault) -> Result<()> {
        super::ffi::set_registers(
            self.part(),
            self.vp(),
            &[whv::WHvX64RegisterCr2, whv::WHvRegisterPendingInterruption],
            &[super::ffi::reg64(fault.address), super::ffi::reg64(super::debug::pending_pf(fault.code))],
        )
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
                // A table without leaf 1 answers with WHP's default, the
                // host's: its x2APIC bit is not the partition's either.
                if function == 1 {
                    ecx = super::apicmode::offered_leaf1_ecx(self.shared.inner.apic, ecx);
                }
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

    /// Answers an MSR intercept. WHP only exits for MSRs it does not model.
    /// An x2APIC register's MSR outside x2APIC mode is #GP(0), as KVM's
    /// (`apicmode::x2apic_msr_exit`). Any other MSR the backend does not
    /// keep is read as 0 and its write ignored, as KVM does only with
    /// `ignore_msrs`, which is off by default (KVM gives #GP(0) for an MSR
    /// it has no case for): not KVM's yet (docs/COMPATIBILITY.md, the Guest
    /// MSRs row).
    fn handle_msr(
        &self,
        m: &whv::WHV_X64_MSR_ACCESS_CONTEXT,
        rip_after: u64,
    ) -> Result<()> {
        #[cfg(test)]
        MSR_INTERCEPTS.with(|c| c.set(c.get() + 1));
        // SAFETY: the access-info bitfield overlaps the u32.
        let (is_write, value) = super::exit::msr_access(unsafe { m.AccessInfo.AsUINT32 }, m.Rax, m.Rdx);
        let index = m.MsrNumber;
        // An x2APIC register's MSR (`apicmode::x2apic_msr_exit`): #GP(0)
        // outside x2APIC mode, RIP left at the instruction, as KVM's; in
        // x2APIC mode WHP's own, so an exit fails the vCPU, named.
        if super::apicmode::X2APIC_MSRS.contains(&index) {
            let apic_base = self.register(whv::WHvX64RegisterApicBase)?;
            if super::apicmode::x2apic_msr_exit(index, apic_base) == Some(super::apicmode::X2ApicMsrExit::Gp) {
                return super::ffi::set_register(
                    self.part(),
                    self.vp(),
                    whv::WHvRegisterPendingInterruption,
                    super::ffi::reg64(super::debug::pending_gp()),
                );
            }
            super::ffi::report(
                log::Level::Error,
                &format!(
                    "whp: vCPU {}'s {} of x2APIC MSR {index:#x} in x2APIC mode (APIC_BASE {apic_base:#x}) exited to \
                     the backend, where WHP's x2APIC answers it itself (GPEXITREC): the backend has no value of the \
                     guest's APIC for it, and fails the vCPU rather than make one up",
                    self.vp(),
                    if is_write { "WRMSR" } else { "RDMSR" }
                ),
            );
            return err(libc::EIO);
        }
        if super::mce::whp_answers(index) {
            // Measured to be answered by WHP itself, with no exit; one that
            // exits is answered as KVM would from the vCPU's value, which
            // `KVM_GET_MSRS` does not read (`mce::whp_answers`): said once.
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| {
                super::ffi::report(
                    log::Level::Warn,
                    &format!(
                        "whp: a guest's {} of MSR {index:#x} exited to the backend, which the WHP measured answers \
                         itself; answered as KVM answers it, from a value KVM_GET_MSRS and a snapshot do not have",
                        if is_write { "WRMSR" } else { "RDMSR" }
                    ),
                );
            });
        }
        if super::mce::is_mce(index) {
            // As KVM's `set_msr_mce`, `get_msr_mce` and its HWCR case for
            // the guest: a bank's STATUS other than 0 only with HWCR's
            // McStatusWrEn on an AMD or Hygon guest (`can_set_mci_status`).
            let amd = self.guest_vendor_amd_or_hygon();
            let mut mce = self.shared.mce.lock().unwrap();
            let answer = if is_write { mce.set(index, value, false, amd).then_some(None) } else { mce.get(index, false).map(Some) };
            drop(mce);
            return match answer {
                Some(None) => regs::set_rip(self.part(), self.vp(), rip_after),
                Some(Some(v)) => regs::set_msr_result(self.part(), self.vp(), v, rip_after),
                // #GP(0), RIP left at the instruction, as KVM's refusal.
                None => super::ffi::set_register(
                    self.part(),
                    self.vp(),
                    whv::WHvRegisterPendingInterruption,
                    super::ffi::reg64(super::debug::pending_gp()),
                ),
            };
        }
        if is_write && self.guest_moves_tsc(index) {
            if !self.guest_tsc_write(index, value)? {
                // Kicked while it waited to hold the vCPUs: RIP stays at the
                // WRMSR, which is made again at the next run.
                return Ok(());
            }
            return regs::set_rip(self.part(), self.vp(), rip_after);
        }
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
            } else if !self.write_kvm_msr(index, value)? {
                say_unkept_msr(self.vp(), index, Some(value));
            }
            regs::set_rip(self.part(), self.vp(), rip_after)
        } else {
            let value = match index {
                pvclock::MSR_SYSTEM_TIME => self.shared.system_time_msr.load(Ordering::Acquire),
                pvclock::MSR_WALL_CLOCK => self.shared.inner.pvclock.lock().unwrap().wall_msr,
                MSR_TSC_DEADLINE => self.read_tsc_deadline()?,
                i if regs::software_msr(i) => self.software_msr(i).load(Ordering::Acquire),
                _ => {
                    say_unkept_msr(self.vp(), index, None);
                    0
                }
            };
            regs::set_msr_result(self.part(), self.vp(), value, rip_after)
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Option E-ii's one test seam: when set, run on the vCPU's thread
    /// between the APIC page's get and set of a held LVT timer write
    /// (`write_x2apic_lvtt`), with every requester held off
    /// (`test_a_held_lvt_timer_write_loses_no_interrupt`). Not called yet:
    /// the write is refused until E-ii is written.
    static PAGE_WINDOW: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

/// How many MSRs [`say_unkept_msr`] names in a process: a guest probing
/// MSRs in a loop makes one line each, up to this, then one more.
const UNKEPT_NAMED: usize = 64;

/// What [`unkept_line`] says of an access.
#[derive(Debug, PartialEq, Eq)]
enum Unkept {
    /// The first access of its kind (the MSR, read or written): named.
    First,
    /// The first past [`UNKEPT_NAMED`]: the line that says the rest are not
    /// named.
    Past,
    /// Said before, or past the bound.
    Said,
}

/// Whether the access of `index` (a write if `write`) is new to `seen`,
/// the accesses named so far, which it joins.
fn unkept_line(seen: &mut Vec<(u32, bool)>, index: u32, write: bool) -> Unkept {
    if seen.contains(&(index, write)) {
        return Unkept::Said;
    }
    match seen.len() {
        n if n < UNKEPT_NAMED => {
            seen.push((index, write));
            Unkept::First
        }
        n if n == UNKEPT_NAMED => {
            seen.push((u32::MAX, false));
            Unkept::Past
        }
        _ => Unkept::Said,
    }
}

/// Names, once a process, an MSR access that exited to the backend for an
/// MSR neither WHP nor the backend keeps (`value`: the write's, or a read),
/// which is read as 0 or its write ignored, where KVM gives #GP(0) for an
/// MSR it has no case for (`ignore_msrs` off, Linux v6.1 x86.c 143,
/// 1866-1876, 1911-1923): the record for the Guest MSRs row, which MSRs a
/// guest's boot and upstream's tests reach this way, and a `whp:` line for
/// the gap where it happens. At most [`UNKEPT_NAMED`] lines and one more.
fn say_unkept_msr(vp: u32, index: u32, value: Option<u64>) {
    static SEEN: std::sync::Mutex<Vec<(u32, bool)>> = std::sync::Mutex::new(Vec::new());
    let said = unkept_line(&mut SEEN.lock().unwrap(), index, value.is_some());
    let line = match (said, value) {
        (Unkept::Said, _) => return,
        (Unkept::Past, _) => format!(
            "whp: more than {UNKEPT_NAMED} MSR accesses the backend does not keep: those past them are not named"
        ),
        (Unkept::First, Some(v)) => format!(
            "whp: an MSR the backend does not keep: vCPU {vp}'s WRMSR of {index:#x} ({v:#x}) is ignored, where KVM \
             gives #GP(0) for an MSR it has no case for (docs/COMPATIBILITY.md, the Guest MSRs row)"
        ),
        (Unkept::First, None) => format!(
            "whp: an MSR the backend does not keep: vCPU {vp}'s RDMSR of {index:#x} reads 0, where KVM gives #GP(0) \
             for an MSR it has no case for (docs/COMPATIBILITY.md, the Guest MSRs row)"
        ),
    };
    super::ffi::report(log::Level::Warn, &line);
}

/// The record tests' kick of a vCPU whose `run` has not come back 5 s
/// after [`Watchdog::arm`]: a thread that waits on a channel and sets the
/// immediate exit when the wait times out. Dropping it ends the wait at
/// once and joins the thread. (The thread polled a flag every 10 ms
/// before, and joining it held each run for that sleep: the ~10.5 ms a
/// step of the stack record took on a PC at 03f4bfe, all but tens of
/// microseconds of it the test's own wait.)
#[cfg(test)]
pub(crate) struct Watchdog {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl Watchdog {
    pub(crate) fn arm(vcpu: &VcpuFd) -> Self {
        let (stop, wait) = std::sync::mpsc::channel::<()>();
        let mut kicker = VcpuFd { shared: Arc::clone(&vcpu.shared), own: None };
        let thread = std::thread::spawn(move || {
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = wait.recv_timeout(std::time::Duration::from_secs(5)) {
                kicker.set_kvm_immediate_exit(1);
            }
        });
        Watchdog { stop: Some(stop), thread: Some(thread) }
    }
}

#[cfg(test)]
impl Drop for Watchdog {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

#[cfg(test)]
thread_local! {
    /// The MSR intercepts this thread's runs have answered: a record test
    /// reads it around a guest's RDMSR to say whether the access came to
    /// the backend or WHP answered it.
    static MSR_INTERCEPTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
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

/// What an entry into the guest came to ([`VcpuFd::enter`]). The exit
/// context is returned by value, as WHP writes it, rather than boxed: one
/// entry is made per exit, and a box would be a heap allocation each.
#[allow(clippy::large_enum_variant)]
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
        let watchdog = super::Watchdog::arm(vcpu);
        let line = describe(vcpu.run());
        drop(watchdog);
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
                // Each way's outcome is an exit (the handler's port, #BP or
                // #DB to gdb, an internal error); no exit in 5 s measured
                // nothing.
                assert!(!then.contains("kicked"), "{name}: the second run came back only by the kick: {then}");
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
        let watchdog = super::Watchdog::arm(vcpu);
        let line = match vcpu.run() {
            Ok(VcpuExit::IoOut(port, _)) => format!("exit IoOut port {port:#x}"),
            Ok(VcpuExit::Shutdown) => "exit Shutdown".to_string(),
            Ok(_) => "exit (another)".to_string(),
            Err(e) if e.errno() == libc::EINTR => "no exit within 5 s (kicked)".to_string(),
            Err(e) => format!("run failed, errno {}", e.errno()),
        };
        drop(watchdog);
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
        assert_eq!(exit, format!("exit IoOut port {PORT:#x}"), "a vCPU that has not run: the guest did not reach its end");
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
        assert_eq!(exit, format!("exit IoOut port {PORT:#x}"), "a vCPU whose guest has used x87 and SSE: the guest did not reach its end");
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
        let watchdog = super::Watchdog::arm(vcpu);
        let line = match vcpu.run() {
            Ok(VcpuExit::IoOut(port, _)) => format!("exit IoOut port {port:#x}"),
            Ok(VcpuExit::MmioRead(address, _)) => format!("exit MmioRead {address:#x}"),
            Ok(VcpuExit::Hlt) => "exit Hlt".to_string(),
            Ok(VcpuExit::Shutdown) => "exit Shutdown".to_string(),
            Ok(_) => "exit (another)".to_string(),
            Err(e) if e.errno() == libc::EINTR => "no exit within 5 s (kicked)".to_string(),
            Err(e) => format!("run failed, errno {}", e.errno()),
        };
        drop(watchdog);
        vcpu.set_kvm_immediate_exit(0);
        line
    }

    /// One step of [`test_the_stack_each_whp_call_commits_on_record`]'s
    /// guest: the runs until its `out 0x80` (at most 12 exits, and a kick
    /// 5 s after the first run began), as the exits the test saw. An `IN`
    /// and an MMIO read are answered with zeros.
    fn run_a_step(vcpu: &mut VcpuFd) -> String {
        let watchdog = super::Watchdog::arm(vcpu);
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
            if exits.len() == 12 {
                exits.push("the cap of 12 exits reached".to_string());
            }
        }
        drop(watchdog);
        vcpu.set_kvm_immediate_exit(0);
        format!("exits {}", exits.join(", "))
    }

    /// The time and exceptions of a step of
    /// [`test_the_stack_each_whp_call_commits_on_record`] (`took`
    /// microseconds, its WHP calls `calls`): the run calls' time; the
    /// first-chance exceptions raised within WHP calls (a C++ exception is
    /// WinHvPlatform's own, thrown and caught); and, for the memory exits of
    /// guest RAM that is mapped (lazy RAM not yet committed), each one's
    /// run call and the backend's time before the next run call (the
    /// commit), and what that comes to for a 256 MiB guest touching all of
    /// its RAM in the 4 KiB pages the backend commits.
    fn step_time(calls: &[super::super::ffi::trace::Call], took: f64) -> String {
        let runs: Vec<(usize, &super::super::ffi::trace::Call)> =
            calls.iter().enumerate().filter(|(_, c)| c.micros().is_some()).collect();
        let in_runs: f64 = runs.iter().filter_map(|(_, c)| c.micros()).sum();
        let raised = calls.iter().fold(super::super::ffi::trace::Raised::default(), |a, c| a.add(c.raised));
        let raised = if raised.text().is_empty() { "none".to_string() } else { raised.text() };
        let mut line = format!(
            "the step {took:.1} us, {} run calls {in_runs:.1} us of it; first-chance exceptions within WHP calls: {raised}",
            runs.len()
        );
        let lazy = lazy_exits(calls);
        if !lazy.is_empty() {
            let n = lazy.len() as f64;
            let (run, ours) = (lazy.iter().map(|l| l.0).sum::<f64>() / n, lazy.iter().map(|l| l.1).sum::<f64>() / n);
            line += &format!(
                "; {} memory exits of mapped guest RAM: each {run:.1} us in its run call (entry, the guest's access, \
                 the exit) and {ours:.1} us in the backend before the next (the commit); 65536 of them, a 256 MiB \
                 guest touching all its RAM in 4 KiB pages: {:.1} ms",
                lazy.len(),
                65536.0 * (run + ours) / 1000.0
            );
        }
        line
    }

    /// The memory exits of mapped guest RAM (lazy RAM not yet committed)
    /// among a thread's WHP `calls`: each one's run call and the backend's
    /// time before the next run call (the commit), in microseconds.
    fn lazy_exits(calls: &[super::super::ffi::trace::Call]) -> Vec<(f64, f64)> {
        calls
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                c.micros().is_some()
                    && c.exit == Some(whv::WHvRunVpExitReasonMemoryAccess)
                    && !c.detail.contains("unmapped")
            })
            .filter_map(|(i, c)| {
                let next = calls[i + 1..].iter().find_map(|n| n.began)?;
                Some((c.micros()?, next.duration_since(c.ended).as_secs_f64() * 1e6))
            })
            .collect()
    }

    /// The process's commit charge (`PagefileUsage`, which the job's
    /// memory limit counts) and working set, in bytes.
    fn process_memory() -> Option<(usize, usize)> {
        #[repr(C)]
        #[derive(Default)]
        struct Counters {
            cb: u32,
            page_faults: u32,
            peak_working_set: usize,
            working_set: usize,
            quota_peak_paged: usize,
            quota_paged: usize,
            quota_peak_non_paged: usize,
            quota_non_paged: usize,
            pagefile: usize,
            peak_pagefile: usize,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn K32GetProcessMemoryInfo(process: windows_sys::Win32::Foundation::HANDLE, counters: *mut Counters, cb: u32) -> i32;
        }
        let mut c = Counters { cb: std::mem::size_of::<Counters>() as u32, ..Default::default() };
        // SAFETY: an output buffer of the size given.
        let ok =
            unsafe { K32GetProcessMemoryInfo(windows_sys::Win32::System::Threading::GetCurrentProcess(), &mut c, c.cb) };
        if ok != 0 { Some((c.pagefile, c.working_set)) } else { None }
    }

    /// The bytes of `[addr, addr + len)` that are committed (`VirtualQuery`).
    fn committed_bytes(addr: usize, len: usize) -> usize {
        use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
        let (mut at, end, mut total) = (addr, addr + len, 0);
        while at < end {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            if unsafe { VirtualQuery(at as *const _, &mut mbi, std::mem::size_of_val(&mbi)) } == 0 {
                break;
            }
            let next = (mbi.BaseAddress as usize + mbi.RegionSize).min(end);
            if mbi.State == MEM_COMMIT {
                total += next - at;
            }
            at = next;
        }
        total
    }

    /// The 4 KiB pages of `[addr, addr + len)` in the process's working set
    /// (`QueryWorkingSetEx`, the Valid bit): Linux's Rss of the range.
    fn resident_bytes(addr: usize, len: usize) -> usize {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Entry {
            address: usize,
            attributes: usize,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn K32QueryWorkingSetEx(process: windows_sys::Win32::Foundation::HANDLE, info: *mut Entry, cb: u32) -> i32;
        }
        let mut entries: Vec<Entry> =
            (0..len / 4096).map(|i| Entry { address: addr + i * 4096, attributes: 0 }).collect();
        // SAFETY: a buffer of the entries given, each with its address set.
        let ok = unsafe {
            K32QueryWorkingSetEx(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                entries.as_mut_ptr(),
                std::mem::size_of_val(entries.as_slice()) as u32,
            )
        };
        assert_ne!(ok, 0, "QueryWorkingSetEx: {}", std::io::Error::last_os_error());
        entries.iter().filter(|e| e.attributes & 1 != 0).count() * 4096
    }

    /// `WHvAdviseGpaRange(Populate)` for a write, no flags, of the `size`
    /// bytes of guest RAM at `gpa`: its HRESULT.
    fn populate(part: whv::WHV_PARTITION_HANDLE, gpa: u64, size: u64) -> i32 {
        let range = whv::WHV_MEMORY_RANGE_ENTRY { GuestAddress: gpa, SizeInBytes: size };
        let advice = whv::WHV_ADVISE_GPA_RANGE_POPULATE {
            Flags: whv::WHV_ADVISE_GPA_RANGE_POPULATE_FLAGS { AsUINT32: 0 },
            AccessType: whv::WHvMemoryAccessWrite,
        };
        // SAFETY: one range and an advice buffer of the size given.
        unsafe {
            whv::WHvAdviseGpaRange(
                part,
                &range,
                1,
                whv::WHvAdviseGpaRangeCodePopulate,
                (&raw const advice).cast(),
                std::mem::size_of_val(&advice) as u32,
            )
        }
    }

    /// `WHvAdviseGpaRange(Populate)` for a write to the `size` bytes of
    /// guest RAM at `gpa`, whose host memory is at `host`: its HRESULT, the
    /// host memory's state before and after it (`VirtualQuery`), and the
    /// process's commit charge (`PagefileUsage`) and working set before
    /// and after.
    fn populate_on_record(part: whv::WHV_PARTITION_HANDLE, host: usize, gpa: u64, size: u64) -> String {
        let charge = process_memory;
        let state = || {
            // SAFETY: an all-zero MEMORY_BASIC_INFORMATION is valid; queries our memory.
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: as above.
            let n = unsafe {
                windows_sys::Win32::System::Memory::VirtualQuery(host as *const _, &mut mbi, std::mem::size_of_val(&mbi))
            };
            match (n, mbi.State) {
                (0, _) => "not queried".to_string(),
                (_, windows_sys::Win32::System::Memory::MEM_COMMIT) => format!("committed, {} KiB of it", mbi.RegionSize / 1024),
                (_, windows_sys::Win32::System::Memory::MEM_RESERVE) => format!("reserved, {} KiB of it", mbi.RegionSize / 1024),
                (_, s) => format!("state {s:#x}"),
            }
        };
        let (was, charged) = (state(), charge());
        let hres = populate(part, gpa, size);
        let (now, after) = (state(), charge());
        let delta = match (charged, after) {
            (Some(a), Some(b)) => format!(
                "{:+} KiB, its working set {:+} KiB",
                (b.0 as i64 - a.0 as i64) / 1024,
                (b.1 as i64 - a.1 as i64) / 1024
            ),
            _ => "not read".to_string(),
        };
        format!(
            "WHvAdviseGpaRange(Populate, a write, no flags) of the {} KiB at {gpa:#x}: HRESULT {:#010x}; its host \
             memory {was} before, {now} after; the process's commit charge {delta}",
            size / 1024,
            hres.cast_unsigned()
        )
    }

    /// What a vCPU thread's stack may have committed after any step of
    /// [`test_the_stack_each_whp_call_commits_on_record`], in bytes. Run
    /// 43392627996 (this test build, Windows Server 2025): a step that made
    /// no refused call left 16 to 24 KiB committed (the run loop's frames,
    /// WHvRunVirtualProcessor's, the emulator's, the test's own lines),
    /// and the one thread on which WHP refused a call 52 (the refusal alone
    /// from 20 to 52). 40 KiB is 16 above the deepest of the first and 12
    /// below the second: a thread past it has had a call refused, or a new
    /// path as deep as that. A bound on this backend's own behaviour (no
    /// call WHP refuses is made on a vCPU's thread), not the tests' budget.
    const STACK_BOUND: usize = 40 << 10;

    /// [`run_a_step`] on a thread of its own, made as Firecracker makes a
    /// vCPU's (its name, 2 MiB of stack reserved), with the WHP calls the
    /// thread made (`ffi::trace`): one STACKTEST line of what the thread's
    /// stack had committed before and after the step, and one STACKCALL
    /// line for each call (past 40 calls, for those that left more of the
    /// stack committed than they found, or failed). The calls the emulator
    /// makes through its callbacks are lines of their own and are not
    /// added to the stack within WHP calls, which the emulator's call they
    /// are made in already counts (`trace::Call::nested`). Returns what is
    /// wrong with the step: each WHP call that failed, and a stack
    /// committed past [`STACK_BOUND`].
    fn a_step_with_its_calls(vcpu: &mut VcpuFd, thread: &str, name: &str) -> Vec<String> {
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name(thread.to_string())
                .stack_size(2 << 20)
                .spawn_scoped(scope, || {
                    let before = super::super::ffi::trace::stack();
                    super::super::ffi::trace::begin();
                    let began = std::time::Instant::now();
                    let what = run_a_step(vcpu);
                    let took = began.elapsed().as_secs_f64() * 1e6;
                    let calls = super::super::ffi::trace::end();
                    let after = super::super::ffi::trace::stack();
                    let (faults, deepest) = libc::wick_mm::host_faults_on_this_thread();
                    let grew = |c: &super::super::ffi::trace::Call| c.after > c.before;
                    let by_calls: usize = calls.iter().filter(|c| !c.nested()).map(|c| c.after - c.before).sum();
                    eprintln!(
                        "STACKTEST {thread}, {name}: {what}; the thread's stack: {} KiB committed before, {} after, \
                         {} of them within WHP calls; {} WHP calls ({} of them the emulator's, within its own), \
                         {} left more committed, {} failed; the thread's own accesses to lazy guest RAM that \
                         the exception handler committed: {faults} (the stack at most {} KiB committed at its entry)",
                        before / 1024,
                        after / 1024,
                        by_calls / 1024,
                        calls.len(),
                        calls.iter().filter(|c| c.nested()).count(),
                        calls.iter().filter(|c| grew(c)).count(),
                        calls.iter().filter(|c| c.hres != 0).count(),
                        deepest / 1024
                    );
                    for (i, c) in calls.iter().enumerate() {
                        if i < 40 || grew(c) || c.hres != 0 {
                            eprintln!("STACKCALL {thread}, {name}: #{} {}", i + 1, c.line());
                        }
                    }
                    eprintln!("STACKTIME {thread}, {name}: {}", step_time(&calls, took));
                    let mut wrong: Vec<String> =
                        calls.iter().filter(|c| c.hres != 0).map(|c| format!("{thread}, {name}: {}", c.line())).collect();
                    // Every step ends at its `out 0x80`: one that did not
                    // (kicked, its cap reached, another end) measured
                    // nothing, and fails the test, printed record or not.
                    if !what.ends_with(&format!("IoOut {PORT:#x}")) {
                        wrong.push(format!("{thread}, {name}: the step did not reach its end: {what}"));
                    }
                    if after > STACK_BOUND {
                        wrong.push(format!(
                            "{thread}, {name}: {} KiB of the stack committed, over {}",
                            after / 1024,
                            STACK_BOUND / 1024
                        ));
                    }
                    wrong
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
    /// input Firecracker answers, string I/O, an MMIO write and an MMIO
    /// read (the emulator), the first writes to `MAP_NORESERVE` guest RAM
    /// (committed at the access, as Firecracker's), the local APIC through its page, an application
    /// processor started with INIT and SIPI (on its own thread), an
    /// interrupt taken while running and one that ends a HLT, the
    /// TSC-deadline timer, and a KVM hypercall. Asserted for every step:
    /// no WHP call of the vCPU's thread fails (IA32_XSS is read only where
    /// the partition keeps it, and which registers it keeps is found out
    /// when the VM is made, not on this thread), and the thread's stack
    /// stays within [`STACK_BOUND`].
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_the_stack_each_whp_call_commits_on_record() {
        const FRESH_PAGES: &str = "a write to each 4 KiB page from 2 MiB to 4 MiB, which nothing wrote before";
        const MMIO_READ: &str = "an MMIO read (the emulator), the thread's first exit";
        const LAZY_RAM: &str = "a write to each of four 64 KiB blocks of MAP_NORESERVE guest RAM at 8 MiB, \
                                which nothing touched before, the thread's first exits";
        const POPULATED: &str = "a write to a 64 KiB block of MAP_NORESERVE guest RAM at 8.25 MiB that \
                                 WHvAdviseGpaRange was asked to populate first";
        // Steps printed, whose stack is not bounded (a failed call still is wrong).
        const RECORDED: [&str; 4] = [FRESH_PAGES, MMIO_READ, LAZY_RAM, POPULATED];
        // The lazy slot: 2 MiB at 8 MiB, committed by nothing before the guest.
        const LAZY_GPA: u64 = 0x80_0000;
        const LAZY_LEN: usize = 2 << 20;
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
        // The lazy slot's 2 MiB page.
        q(0x3020, LAZY_GPA | 0x83);
        // The second 2 MiB of the slot, which nothing on the host writes.
        q(0x3008, 0x20_0000 | 0x83);
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
            // A booted guest's vCPU thread: one WHvRunVirtualProcessor took
            // its stack from 16 or 20 to 52 KiB on a PC (81f7970's traced
            // boot, every vCPU; nothing else grew it), which no step below
            // did. A booting guest touches memory nothing touched before;
            // whether WHP's handling of that, inside the run call, is what
            // commits it: printed, not bounded (`FRESH_PAGES`).
            (
                FRESH_PAGES,
                vec![
                    0xBF, 0x00, 0x00, 0x20, 0x00, // mov edi, 0x200000
                    0xB9, 0x00, 0x02, 0x00, 0x00, // mov ecx, 512
                    0xC6, 0x07, 0x01, // mov byte [rdi], 1
                    0x81, 0xC7, 0x00, 0x10, 0x00, 0x00, // add edi, 0x1000
                    0xFF, 0xC9, // dec ecx
                    0x75, 0xF3, // jnz to the mov
                ],
            ),
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
                "an MMIO write (the emulator)",
                vec![0xC7, 0x04, 0x25, 0x00, 0x00, 0x60, 0x00, 0x78, 0x56, 0x34, 0x12], // mov dword [0x600000], 0x12345678
            ),
            // A booted guest's run call that commits its thread's stack
            // returns a memory access exit (9af0b63's traced boot, exit
            // reason 1, on every vCPU): of guest RAM that is not committed
            // yet (Firecracker's is `MAP_NORESERVE`), or of MMIO. Each, as
            // the first exit of a fresh thread; the run call's line names
            // the access (`trace::exit_detail`). Printed, not bounded.
            (
                MMIO_READ,
                vec![0x8B, 0x04, 0x25, 0x00, 0x00, 0x60, 0x00], // mov eax, [0x600000]
            ),
            (
                LAZY_RAM,
                vec![
                    0xBF, 0x00, 0x00, 0x80, 0x00, // mov edi, 0x800000
                    0xB9, 0x04, 0x00, 0x00, 0x00, // mov ecx, 4
                    0xC6, 0x07, 0x01, // mov byte [rdi], 1
                    0x81, 0xC7, 0x00, 0x00, 0x01, 0x00, // add edi, 0x10000
                    0xFF, 0xC9, // dec ecx
                    0x75, 0xF3, // jnz to the mov
                ],
            ),
            // Whether WHP's Populate advice commits guest RAM that is only
            // reserved, ahead of the guest, and so spares it the exit
            // (Microsoft Learn, WHvAdviseGpaRange: it "commits the backing
            // memory for the specified ranges ahead of access"). Printed.
            (
                POPULATED,
                vec![0xC6, 0x04, 0x25, 0x00, 0x00, 0x84, 0x00, 0x01], // mov byte [0x840000], 1
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
            // Read back after the step (a STACKTEST line): run 43397419784's
            // TSC-deadline step, right after the one-shot one, got no
            // interrupt, and its deadline was not armed: the backend took
            // the LVT timer for one-shot with a count (TMICT 0x100000 left
            // by the step before), which is how a TSC-deadline entry reads
            // if WHP keeps no such mode. KVM clears TMICT when the timer
            // enters TSC-deadline mode (lapic.c, apic_update_lvtt).
            (
                "the LVT timer set to TSC-deadline mode after the one-shot count",
                [apic.to_vec(), apic_write(0x320, 0x4_0000 | VECTOR as u32)].concat(),
            ),
            // TMICT cleared first, as KVM's switch to the mode leaves it.
            (
                "the TSC-deadline timer (WRMSR 0x6e0, the TSC plus 0x10000000) and HLT, ended by its interrupt",
                [
                    apic.to_vec(),
                    apic_write(0x380, 0),
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
            // Last: run 43392627996 never got past it (the backend's string
            // output did not complete then; `string_io` now does it).
            (
                "REP OUTSB of 2 bytes to port 0x82",
                vec![
                    0xBE, 0x00, 0x83, 0x00, 0x00, // mov esi, 0x8300
                    0xB9, 0x02, 0x00, 0x00, 0x00, // mov ecx, 2
                    0x66, 0xBA, 0x82, 0x00, // mov dx, 0x82
                    0xF3, 0x6E, // rep outsb
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
        // SAFETY: anonymous memory for the test, unmapped at its end.
        let lazy = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LAZY_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, libc::MAP_FAILED);
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 1,
            flags: 0,
            guest_phys_addr: LAZY_GPA,
            memory_size: LAZY_LEN as u64,
            userspace_addr: lazy as u64,
        };
        // SAFETY: as the first slot's.
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
        // With the host's leaf 0xD, without which the table is refused
        // (`set_cpuid2`: its XSAVE components left out).
        let leaf_d = regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap()
            .as_slice()
            .iter()
            .copied()
            .find(|e| e.function == 0xd && e.index == 0)
            .unwrap();
        vcpu.set_cpuid2(&CpuId::from_entries(&[leaf7, leaf_d]).unwrap()).unwrap();
        start(&vcpu);
        let mut s = vcpu.get_sregs().unwrap();
        (s.idt.base, s.idt.limit) = (IDT, 0xfff);
        vcpu.set_sregs(&s).unwrap();
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();

        let mut wrong = Vec::new();
        for (name, _) in &steps {
            if *name == POPULATED {
                eprintln!("STACKTEST populate: {}", populate_on_record(vcpu.part(), lazy as usize + 0x4_0000, LAZY_GPA + 0x4_0000, 0x1_0000));
            }
            let of_the_step = if name.starts_with("INIT") {
                // The application processor's thread is in its run, waiting
                // for its start, while the boot processor sends it.
                std::thread::scope(|scope| {
                    let ap = &mut ap;
                    let waiting = scope.spawn(move || {
                        a_step_with_its_calls(ap, "fc_vcpu 1", "the application processor's first run, started by the SIPI")
                    });
                    let mut both = a_step_with_its_calls(&mut vcpu, "fc_vcpu 0", name);
                    both.extend(waiting.join().unwrap());
                    both
                })
            } else {
                a_step_with_its_calls(&mut vcpu, "fc_vcpu 0", name)
            };
            // A record, not bounded: a failed call still is wrong.
            let of_the_step: Vec<String> = if RECORDED.contains(name) {
                of_the_step.into_iter().filter(|w| !w.contains(" KiB of the stack committed, over ")).collect()
            } else {
                of_the_step
            };
            if name.starts_with("the LVT timer set to TSC-deadline mode") {
                let page = vcpu.get_lapic().unwrap();
                let reg = |offset: usize| {
                    u32::from_le_bytes(std::array::from_fn(|i| page.regs[offset + i].cast_unsigned()))
                };
                eprintln!(
                    "STACKTEST the LVT timer after the guest wrote {:#x} (TSC-deadline mode), a one-shot count of 0x100000 run out before: \
                     LVTT {:#x}, TMICT {:#x}, TMCCT {:#x}; the backend takes it for TSC-deadline mode: {}",
                    0x4_0000 | VECTOR as u32,
                    reg(0x320),
                    reg(0x380),
                    reg(0x390),
                    super::super::tscdeadline::deadline_mode(reg(0x320), reg(0x380))
                );
            }
            wrong.extend(of_the_step);
        }

        drop(ap);
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mappings, no VM left using them.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::munmap(lazy, LAZY_LEN) }, 0);
        assert!(wrong.is_empty(), "on a vCPU's thread: {wrong:#?}");
    }

    /// What the process's heaps hold, from `HeapWalk` of each heap
    /// (`GetProcessHeaps`) under its lock: the busy blocks' sizes and the
    /// heaps' committed bytes (their regions' `dwCommittedSize`). Rust's
    /// allocator on Windows is the process heap's (`HeapAlloc`).
    struct HeapCensus {
        heaps: usize,
        /// (busy block size in bytes, blocks), by size.
        busy: Vec<(u32, u64)>,
        committed: u64,
        /// Busy blocks past the room set aside.
        missed: u64,
    }

    /// The room a census works in, allocated before the first: what the
    /// census itself holds is then the same in every census, and cancels.
    struct CensusRoom {
        handles: Vec<windows_sys::Win32::Foundation::HANDLE>,
        sizes: Vec<u32>,
        results: Vec<Vec<(u32, u64)>>,
    }

    impl CensusRoom {
        fn new(censuses: usize) -> Self {
            CensusRoom {
                handles: vec![std::ptr::null_mut(); 256],
                sizes: Vec::with_capacity(1 << 19),
                results: (0..censuses).map(|_| Vec::with_capacity(1 << 14)).collect(),
            }
        }

        /// A census, into the next result room; nothing is allocated from a
        /// heap while it is locked, or before the result is made.
        fn take(&mut self) -> HeapCensus {
            use windows_sys::Win32::System::Memory::{GetProcessHeaps, HeapLock, HeapUnlock, HeapWalk, PROCESS_HEAP_ENTRY};
            // PROCESS_HEAP_REGION and PROCESS_HEAP_ENTRY_BUSY (winbase.h).
            const REGION: u16 = 1;
            const BUSY: u16 = 4;
            // SAFETY: room for 256 handles.
            let n = unsafe { GetProcessHeaps(256, self.handles.as_mut_ptr()) } as usize;
            self.sizes.clear();
            let (mut committed, mut missed) = (0u64, 0u64);
            for &h in &self.handles[..n.min(256)] {
                // SAFETY: a heap of this process; the walk allocates nothing.
                unsafe {
                    if HeapLock(h) == 0 {
                        continue;
                    }
                    let mut e: PROCESS_HEAP_ENTRY = std::mem::zeroed();
                    while HeapWalk(h, &mut e) != 0 {
                        if e.wFlags & REGION != 0 {
                            committed += u64::from(e.Anonymous.Region.dwCommittedSize);
                        } else if e.wFlags & BUSY != 0 {
                            if self.sizes.len() < self.sizes.capacity() {
                                self.sizes.push(e.cbData);
                            } else {
                                missed += 1;
                            }
                        }
                    }
                    HeapUnlock(h);
                }
            }
            self.sizes.sort_unstable();
            let mut busy = self.results.pop().expect("a census more than the room was made for");
            for &z in &self.sizes {
                if let Some((last, c)) = busy.last_mut()
                    && *last == z
                {
                    *c += 1;
                } else if busy.len() < busy.capacity() {
                    busy.push((z, 1));
                } else {
                    missed += 1;
                }
            }
            HeapCensus { heaps: n, busy, committed, missed }
        }
    }

    impl HeapCensus {
        fn line(&self) -> String {
            let blocks: u64 = self.busy.iter().map(|b| b.1).sum();
            let bytes: u64 = self.busy.iter().map(|(z, c)| u64::from(*z) * c).sum();
            format!(
                "heaps {}, busy blocks {blocks} ({:.1} KiB), committed {:.1} KiB{}",
                self.heaps,
                bytes as f64 / 1024.0,
                self.committed as f64 / 1024.0,
                if self.missed > 0 { format!(", {} blocks not counted", self.missed) } else { String::new() }
            )
        }

        /// What `later` holds more than `self`, for each of `n` vCPUs: the
        /// blocks, their bytes and the committed bytes, and the sizes whose
        /// blocks grew most in bytes (size x blocks a vCPU).
        fn per_vcpu(&self, later: &HeapCensus, n: u64) -> String {
            let before: std::collections::BTreeMap<u32, u64> = self.busy.iter().copied().collect();
            let after: std::collections::BTreeMap<u32, u64> = later.busy.iter().copied().collect();
            let mut grown: Vec<(u32, i64)> = before
                .keys()
                .chain(after.keys())
                .copied()
                .collect::<std::collections::BTreeSet<u32>>()
                .into_iter()
                .map(|z| (z, *after.get(&z).unwrap_or(&0) as i64 - *before.get(&z).unwrap_or(&0) as i64))
                .filter(|(_, d)| *d != 0)
                .collect();
            let blocks: i64 = grown.iter().map(|g| g.1).sum();
            let bytes: i64 = grown.iter().map(|(z, d)| i64::from(*z) * d).sum();
            grown.sort_by_key(|(z, d)| std::cmp::Reverse(i64::from(*z) * d));
            let top: Vec<String> =
                grown.iter().take(16).map(|(z, d)| format!("{z} x {:.2}", *d as f64 / n as f64)).collect();
            format!(
                "each vCPU adds {:.2} busy blocks, {:.1} KiB of them, {:.1} KiB committed, heaps {:+}; by size \
                 (bytes x blocks a vCPU), most bytes first: {}",
                blocks as f64 / n as f64,
                bytes as f64 / 1024.0 / n as f64,
                (later.committed as f64 - self.committed as f64) / 1024.0 / n as f64,
                later.heaps as i64 - self.heaps as i64,
                top.join(", ")
            )
        }
    }

    /// A record of the process heap a vCPU takes, for the 62.1 KiB of heap
    /// each vCPU added in a PC's traced boot at 861d365 (VMMGROW: in later
    /// segments of the process heap), whose owner nothing named: a census
    /// of every heap (`CensusRoom::take`) taken with the VM made, after
    /// `create_vcpu` of 4 vCPUs, after a thread for each (made as
    /// Firecracker makes a vCPU's, and kept until the end), after each
    /// vCPU's first run on its thread, and after an MMIO read on each (the
    /// emulator is made at a vCPU's first MMIO exit): HEAPTEST lines, the
    /// growth per vCPU by block size. This is the backend's and WHP's part;
    /// what the VMM above adds for a vCPU is not here. A debug test build:
    /// the backend's allocations are of the same types in a release build,
    /// WHP's are WHP's. Printed, not asserted.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_the_heap_a_vcpu_takes_on_record() {
        const N: usize = 4;
        const MMIO_CODE: u64 = 0x6100;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        // A 2 MiB page at 6 MiB that no slot backs: an MMIO address.
        put(m, 0x3018, &(0x60_0000u64 | 0x83).to_le_bytes());
        put(
            m,
            MMIO_CODE,
            &[
                0x8B, 0x04, 0x25, 0x00, 0x00, 0x60, 0x00, // mov eax, [0x600000]
                0xE6, PORT as u8, // out 0x80, al
                0xEB, 0xFE, // jmp $
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
        let mut room = CensusRoom::new(5);
        // The first line on standard error made before the first census.
        eprintln!("HEAPTEST {N} vCPUs");
        let made = room.take();
        eprintln!("HEAPTEST the VM made: {}", made.line());
        let mut vcpus: Vec<VcpuFd> = (0..N).map(|i| vm.create_vcpu(i as u64).unwrap()).collect();
        for v in &vcpus {
            start(v);
            // Runnable, so each runs its code: vCPUs 1 to 3 are made waiting
            // for a SIPI, as KVM makes an AP (`regs::startup_suspend`), and
            // at 03f4bfe ran nothing (each run kicked after 5 s), which
            // made the first-run and MMIO rows vCPU 0's divided by four.
            v.set_mp_state(kvm_bindings::kvm_mp_state { mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE }).unwrap();
        }
        let created = room.take();
        eprintln!("HEAPTEST after create_vcpu of {N}: {}", created.line());
        let barrier = std::sync::Barrier::new(N + 1);
        let exits: Vec<String> = std::thread::scope(|scope| {
            let workers: Vec<_> = vcpus
                .iter_mut()
                .enumerate()
                .map(|(i, vcpu)| {
                    let barrier = &barrier;
                    std::thread::Builder::new()
                        .name(format!("fc_vcpu {i}"))
                        .stack_size(2 << 20)
                        .spawn_scoped(scope, move || {
                            barrier.wait();
                            barrier.wait();
                            let first = run_once(vcpu);
                            barrier.wait();
                            barrier.wait();
                            vcpu.set_regs(&kvm_regs { rip: MMIO_CODE, rsp: 0x9000, rflags: 2, ..Default::default() })
                                .unwrap();
                            let mut mmio = vec![run_once(vcpu)];
                            while mmio.len() < 3 && !mmio.last().unwrap().contains("IoOut") {
                                mmio.push(run_once(vcpu));
                            }
                            barrier.wait();
                            barrier.wait();
                            format!("fc_vcpu {i}: first run {first}; MMIO read {}", mmio.join(", "))
                        })
                        .unwrap()
                })
                .collect();
            barrier.wait();
            let threads = room.take();
            eprintln!("HEAPTEST after a thread for each: {}", threads.line());
            barrier.wait();
            barrier.wait();
            let ran = room.take();
            eprintln!("HEAPTEST after each one's first run: {}", ran.line());
            barrier.wait();
            barrier.wait();
            let emulated = room.take();
            eprintln!("HEAPTEST after an MMIO read on each: {}", emulated.line());
            let n = N as u64;
            eprintln!("HEAPTEST create_vcpu: {}", made.per_vcpu(&created, n));
            eprintln!("HEAPTEST its thread: {}", created.per_vcpu(&threads, n));
            eprintln!("HEAPTEST its first run: {}", threads.per_vcpu(&ran, n));
            eprintln!("HEAPTEST its first MMIO exit: {}", ran.per_vcpu(&emulated, n));
            eprintln!("HEAPTEST all of it: {}", made.per_vcpu(&emulated, n));
            barrier.wait();
            workers.into_iter().map(|w| w.join().unwrap()).collect()
        });
        for e in &exits {
            eprintln!("HEAPTEST {e}");
        }
        // The rows are each vCPU's only if each ran its code to its `out`.
        let ran = |e: &String| e.contains("first run exit IoOut") && e.ends_with("exit IoOut port 0x80");
        assert!(exits.iter().all(ran), "a vCPU did not run its code, so the rows are not per vCPU: {exits:#?}");
        drop(vcpus);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The exits of a guest until its `out 0x80`, as Firecracker sees
    /// them, each with its bytes: an `IN` and an MMIO read are answered
    /// from `feed`, in order (a read with nothing left is answered with
    /// 0xEE). With `registers`, each exit also has the RIP and RFLAGS.RF
    /// that `KVM_GET_REGS` gives at it. At most 40 exits, and a kick 5 s
    /// after the first run began.
    ///
    /// A guest that does not reach its end (kicked, or its 40th exit not
    /// the end) has measured nothing: the test fails, naming `step`.
    fn exits_with_their_bytes(
        vcpu: &mut VcpuFd,
        feed: &mut std::collections::VecDeque<Vec<u8>>,
        registers: bool,
        step: &str,
    ) -> Vec<String> {
        let watchdog = super::Watchdog::arm(vcpu);
        let mut answer = |data: &mut [u8]| {
            let given = feed.pop_front().unwrap_or_default();
            for (i, b) in data.iter_mut().enumerate() {
                *b = given.get(i).copied().unwrap_or(0xEE);
            }
        };
        let mut exits = Vec::new();
        while exits.len() < 40 {
            let (line, more) = match vcpu.run() {
                Ok(VcpuExit::IoOut(PORT, _)) => ("the end".to_string(), false),
                Ok(VcpuExit::IoOut(FAULT_PORT, data)) => (fault_line(data), false),
                Ok(VcpuExit::IoOut(port, data)) => (format!("out {port:#x} {data:02x?}"), true),
                Ok(VcpuExit::IoIn(port, data)) => {
                    answer(data);
                    (format!("in {port:#x} x{}", data.len()), true)
                }
                Ok(VcpuExit::MmioRead(address, data)) => {
                    answer(data);
                    (format!("read {address:#x} x{}", data.len()), true)
                }
                Ok(VcpuExit::MmioWrite(address, data)) => (format!("write {address:#x} {data:02x?}"), true),
                Ok(VcpuExit::Shutdown) => ("Shutdown (a triple fault)".to_string(), false),
                Ok(_) => ("(another)".to_string(), false),
                Err(e) if e.errno() == libc::EINTR => ("none within 5 s (kicked)".to_string(), false),
                Err(e) => (format!("run failed, errno {}", e.errno()), false),
            };
            let line = if registers {
                let r = vcpu.get_regs().unwrap();
                format!("{line} rip {:#x} rf {}", r.rip, r.rflags >> 16 & 1)
            } else {
                line
            };
            exits.push(line);
            if !more {
                break;
            }
        }
        drop(watchdog);
        vcpu.set_kvm_immediate_exit(0);
        assert!(
            exits.last().is_some_and(|l| l.starts_with("the end")),
            "{step}: the guest did not reach its end within 40 exits: {exits:?}"
        );
        exits
    }

    /// Where the MMIO tests' guest code starts, and the vector and handler
    /// of the interrupt they take: the handler does `out 0x81, al`, writes
    /// the local APIC's EOI (at 0xFEE000B0, RBX kept) and returns.
    const MMIO_PROGRAM: u64 = 0xB000;
    const MMIO_HANDLER: u64 = 0xB800;
    const MMIO_IDT: u64 = 0x5000;
    const MMIO_VECTOR: u64 = 0x41;
    /// Where the MMIO tests' exception gates (vectors 0-31) go: each does
    /// `out FAULT_PORT, <vector>` over and over, so a fault the test did
    /// not mean names itself instead of ending as a triple fault (a
    /// `Shutdown` exit, after which the vector is lost). A test that
    /// handles an exception writes its own gate over its vector's.
    const MMIO_FAULTS: u64 = 0xBC00;
    const FAULT_PORT: u16 = 0x8F;

    /// A fault gate's `out`, as a line: the exception's vector and name.
    fn fault_line(data: &[u8]) -> String {
        let vector = data.first().copied().unwrap_or(0xff);
        let name = match vector {
            0 => "#DE",
            1 => "#DB",
            3 => "#BP",
            6 => "#UD",
            8 => "#DF",
            12 => "#SS",
            13 => "#GP",
            14 => "#PF",
            17 => "#AC",
            18 => "#MC",
            _ => "",
        };
        format!("fault: exception {vector} {name}")
    }

    /// A VM of the MMIO tests: `guest()`'s memory, a device's 2 MiB at
    /// 6 MiB (no slot backs it), RAM from 2 to 4 MiB mapped and the 2 MiB
    /// above it a device's too (from 4 MiB, where the slot ends), the local
    /// APIC's page, an IDT with `MMIO_VECTOR`'s gate, and `program` at
    /// `MMIO_PROGRAM`, each exception's gate a `MMIO_FAULTS` stub; the
    /// vCPU in long mode there.
    fn mmio_guest(program: &[u8]) -> (super::super::VmFd, VcpuFd, *mut u8) {
        mmio_guest_with(program, |_| {})
    }

    /// The supported CPUID with TSC_DEADLINE (leaf 1 ECX bit 24), as
    /// Firecracker gives every guest (src/vmm/src/cpu_config/x86_64/cpuid/
    /// normalize.rs, `set_bit(&mut leaf_1.result.ecx, 24, true)`): the
    /// supported table is the host's, and an AMD processor has no
    /// TSC-deadline timer, so it leaves the bit out there. Without it a
    /// guest's LVT timer entry keeps one mode bit, as KVM keeps it
    /// (`gp::lvtt_write`), and has no TSC-deadline mode.
    fn cpuid_with_tsc_deadline() -> CpuId {
        let mut c = regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
        for e in c.as_mut_slice().iter_mut().filter(|e| e.function == 1) {
            e.ecx |= 1 << 24;
        }
        c
    }

    /// [`mmio_guest`], with `prepare` run on the guest's memory once it is
    /// written and before the VM maps it.
    fn mmio_guest_with(program: &[u8], prepare: impl FnOnce(*mut u8)) -> (super::super::VmFd, VcpuFd, *mut u8) {
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
        q(0x3008, 0x20_0000 | 0x83);
        q(0x3010, 0x40_0000 | 0x83);
        q(0x3018, 0x60_0000 | 0x83);
        q(0x2018, 0xA000 | 3);
        q(0xA000 + 0x1f7 * 8, 0xFEE0_0000 | 0x83);
        for vector in 0..32u64 {
            let stub = MMIO_FAULTS + vector * 8;
            // mov al, vector; out FAULT_PORT, al; jmp to the out
            put(m, stub, &[0xB0, vector as u8, 0xE6, FAULT_PORT as u8, 0xEB, 0xFC]);
            q(MMIO_IDT + vector * 16, (stub & 0xffff) | (8 << 16) | (0x8E << 40));
            q(MMIO_IDT + vector * 16 + 8, 0);
        }
        q(MMIO_IDT + MMIO_VECTOR * 16, (MMIO_HANDLER & 0xffff) | (8 << 16) | (0x8E << 40));
        q(MMIO_IDT + MMIO_VECTOR * 16 + 8, 0);
        put(
            m,
            MMIO_HANDLER,
            // RBX is the handler's own: an instruction before the interrupt
            // may have changed it (CPUID writes EBX; on a PC at 4999ff6 the
            // EOI went to the vendor string's address, a #PF with no gate
            // for it, and the guest triple faulted).
            &[
                0xE6, 0x81, // out 0x81, al
                0x53, // push rbx
                0xBB, 0x00, 0x00, 0xE0, 0xFE, // mov ebx, 0xFEE00000
                0xC7, 0x83, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword [rbx + 0xB0], 0 (EOI)
                0x5B, // pop rbx
                0x48, 0xCF, // iretq
            ],
        );
        put(m, MMIO_PROGRAM, program);
        prepare(m);
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: MEM as u64,
            userspace_addr: m as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);
        let mut s = vcpu.get_sregs().unwrap();
        (s.idt.base, s.idt.limit) = (MMIO_IDT, 0xfff);
        vcpu.set_sregs(&s).unwrap();
        vcpu.set_regs(&kvm_regs { rip: MMIO_PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
        (vm, vcpu, m)
    }

    /// The local APIC enabled (RBX its base, spurious vector register
    /// 0x1ff) and interrupts on: the start of a program that takes
    /// `MMIO_VECTOR`.
    const APIC_ON: [u8; 16] = [
        0xBB, 0x00, 0x00, 0xE0, 0xFE, // mov ebx, 0xFEE00000
        0xC7, 0x83, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x00, // mov dword [rbx + 0xF0], 0x1ff
        0xFB, // sti
    ];
    /// `mov eax, [0x600000]`: a device read of 4 bytes.
    const READ_DEVICE: [u8; 7] = [0x8B, 0x04, 0x25, 0x00, 0x00, 0x60, 0x00];

    /// What a run returned, as a line, with an MMIO read answered with
    /// `answer`'s bytes and counted in `reads`.
    fn one_run(vcpu: &mut VcpuFd, answer: &[u8], reads: &mut usize) -> String {
        match vcpu.run() {
            Ok(VcpuExit::MmioRead(address, data)) => {
                *reads += 1;
                for (i, b) in data.iter_mut().enumerate() {
                    *b = answer.get(i).copied().unwrap_or(0xEE);
                }
                format!("read {address:#x} x{}", data.len())
            }
            Ok(VcpuExit::MmioWrite(address, data)) => format!("write {address:#x} {data:02x?}"),
            Ok(VcpuExit::IoOut(FAULT_PORT, data)) => fault_line(data),
            Ok(VcpuExit::IoOut(port, data)) => format!("out {port:#x} {data:02x?}"),
            Ok(VcpuExit::InternalError) => "InternalError".to_string(),
            Ok(VcpuExit::Shutdown) => "Shutdown (a triple fault)".to_string(),
            Ok(VcpuExit::Hlt) => "Hlt".to_string(),
            Ok(_) => "(another)".to_string(),
            Err(e) if e.errno() == libc::EINTR => "EINTR".to_string(),
            Err(e) => format!("run failed, errno {}", e.errno()),
        }
    }

    /// An MMIO read's instruction is finished at the next run before the
    /// guest is entered and before a kick is looked at, as KVM's KVM_RUN
    /// runs `complete_userspace_io` before its `immediate_exit` check
    /// (Linux v6.1 arch/x86/kvm/x86.c, `kvm_arch_vcpu_ioctl_run`):
    /// - a run with the immediate exit set returns `EINTR` with the
    ///   instruction done: EAX holds the device's data and RIP is past it;
    ///   the run after goes on to the next instruction, and the device was
    ///   asked once (before, the kick lost the data and the instruction ran
    ///   again, asking the device a second time);
    /// - an interrupt requested between the read's exit and the next run is
    ///   taken after the instruction, with its data: the handler's `out`
    ///   has the device's byte in AL, and the program goes on after it,
    ///   with no second read (before, the instruction re-executed in the
    ///   guest and the data went to whichever device read came first). The
    ///   read is the instruction right after STI, in its interrupt shadow,
    ///   which ends with the instruction as KVM ends it (`end_shadow`; on
    ///   kit f35e353 the shadow was left and the interrupt came one
    ///   instruction late, after the `out 0x80`);
    /// - likewise an interrupt pending when STI runs, with a CPUID (which
    ///   the run finishes) or an OUT (which the run returns) in STI's
    ///   shadow: taken right after it, before the `out 0x80`;
    /// - MOVSD from a device to a device: one read, then one write of the
    ///   read's bytes, RSI and RDI past them (the instruction finishes in
    ///   the host from the read's exit and its write is the next exit).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_an_mmio_read_finishes_in_the_host_at_the_next_run() {
        let data = [0x44, 0x33, 0x22, 0x11];
        // Kicked.
        let program = [READ_DEVICE.to_vec(), vec![0xE6, PORT as u8, 0xEB, 0xFE]].concat();
        let (vm, mut vcpu, m) = mmio_guest(&program);
        let watchdog = super::Watchdog::arm(&vcpu);
        let mut reads = 0;
        let first = one_run(&mut vcpu, &data, &mut reads);
        vcpu.set_kvm_immediate_exit(1);
        let kicked = one_run(&mut vcpu, &data, &mut reads);
        let r = vcpu.get_regs().unwrap();
        vcpu.set_kvm_immediate_exit(0);
        let then = one_run(&mut vcpu, &data, &mut reads);
        drop(watchdog);
        eprintln!(
            "MMIOTEST kicked: {first}; the kicked run {kicked}, EAX {:#x}, RIP {:#x}; then {then}; device reads {reads}",
            r.rax & 0xffff_ffff,
            r.rip
        );
        assert_eq!(first, "read 0x600000 x4");
        assert_eq!(kicked, "EINTR");
        assert_eq!((r.rax & 0xffff_ffff, r.rip), (0x1122_3344, MMIO_PROGRAM + READ_DEVICE.len() as u64));
        assert_eq!(then, "out 0x80 [44]");
        assert_eq!(reads, 1);
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);

        // An interrupt requested between the exit and the next run.
        let program = [APIC_ON.to_vec(), READ_DEVICE.to_vec(), vec![0xE6, PORT as u8, 0xF4, 0xEB, 0xFD]].concat();
        let (vm, mut vcpu, m) = mmio_guest(&program);
        let watchdog = super::Watchdog::arm(&vcpu);
        let mut reads = 0;
        let mut exits = vec![one_run(&mut vcpu, &data, &mut reads)];
        vcpu.shared.inner.inject_msi(0xFEE0_0000, MMIO_VECTOR as u32);
        for _ in 0..2 {
            exits.push(one_run(&mut vcpu, &data, &mut reads));
        }
        drop(watchdog);
        eprintln!("MMIOTEST an interrupt between: {exits:?}; device reads {reads}");
        assert_eq!(exits, ["read 0x600000 x4", "out 0x81 [44]", "out 0x80 [44]"]);
        assert_eq!(reads, 1);
        drop(vcpu);
        drop(vm);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);

        // An interrupt requested while interrupts are off, then STI and an
        // instruction the VMM finishes, in STI's shadow: a CPUID (finished
        // within the run), an OUT (finished before the run returns it).
        // KVM ends the shadow with the instruction (`skip_emulated_instruction`),
        // so the interrupt is taken before the next instruction, OUT 0x80.
        for (name, finished) in [("CPUID", vec![0x0F, 0xA2]), ("OUT 0x82", vec![0xE6, 0x82])] {
            let program = [
                APIC_ON[..APIC_ON.len() - 1].to_vec(), // the APIC on, interrupts still off
                vec![0xE6, 0x83],                      // out 0x83: the test requests the interrupt
                vec![0xFB],                            // sti
                finished,
                vec![0xE6, PORT as u8, 0xF4, 0xEB, 0xFD],
            ]
            .concat();
            let (vm, mut vcpu, m) = mmio_guest(&program);
            let watchdog = super::Watchdog::arm(&vcpu);
            let mut reads = 0;
            let mut exits = vec![one_run(&mut vcpu, &data, &mut reads)];
            vcpu.shared.inner.inject_msi(0xFEE0_0000, MMIO_VECTOR as u32);
            while exits.len() < 5 && !exits.last().unwrap().starts_with("out 0x80") {
                exits.push(one_run(&mut vcpu, &data, &mut reads));
            }
            drop(watchdog);
            eprintln!("MMIOTEST an interrupt pending at STI, then {name} in its shadow: {exits:?}");
            let expected: Vec<&str> = if name == "CPUID" {
                vec!["out 0x83", "out 0x81", "out 0x80"]
            } else {
                vec!["out 0x83", "out 0x82", "out 0x81", "out 0x80"]
            };
            let ports: Vec<&str> = exits.iter().map(|e| &e[..e.find(" [").unwrap_or(e.len())]).collect();
            assert_eq!(ports, expected, "{name} in STI's shadow");
            if name == "CPUID" {
                // EAX was 0 at `out 0x83`; CPUID leaf 0 sets it to the
                // highest basic leaf. The handler's AL is the program's AL
                // at its end: the CPUID finished before the interrupt, as
                // KVM's skip_emulated_instruction ends the shadow after it.
                let al = |e: &str| e.rsplit_once(" [").map(|(_, d)| d.trim_end_matches(']').to_string());
                assert_ne!(al(&exits[2]).as_deref(), Some("00"), "CPUID leaf 0 left EAX 0: the check proves nothing: {exits:?}");
                assert_eq!(al(&exits[1]), al(&exits[2]), "the interrupt came before the CPUID finished: {exits:?}");
            }
            drop(vcpu);
            drop(vm);
            // SAFETY: as above.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }

        // MOVSD from a device to a device.
        let program = [
            vec![0xBE, 0x00, 0x00, 0x60, 0x00], // mov esi, 0x600000
            vec![0xBF, 0x00, 0x10, 0x60, 0x00], // mov edi, 0x601000
            vec![0xFC, 0xA5],                   // cld; movsd
            vec![0xE6, PORT as u8, 0xEB, 0xFE],
        ]
        .concat();
        let (vm, mut vcpu, m) = mmio_guest(&program);
        let watchdog = super::Watchdog::arm(&vcpu);
        let mut reads = 0;
        let exits: Vec<String> = (0..3).map(|_| one_run(&mut vcpu, &data, &mut reads)).collect();
        let r = vcpu.get_regs().unwrap();
        drop(watchdog);
        eprintln!("MMIOTEST MOVSD device to device: {exits:?}; RSI {:#x} RDI {:#x}", r.rsi, r.rdi);
        // AL is untouched: the program's OUT has the 0 RAX began with.
        assert_eq!(exits, ["read 0x600000 x4", "write 0x601000 [44, 33, 22, 11]", "out 0x80 [00]"]);
        assert_eq!((r.rsi, r.rdi), (0x60_0004, 0x60_1004));
        drop(vcpu);
        drop(vm);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// On record (MMIOREC lines), what this backend's devices are asked for
    /// an access that KVM splits (`emulator_read_write`: at a page
    /// boundary, each part of a device's an exit of its own, its
    /// `mmio_fragments`), and what WHP does at an entry with an interrupt
    /// pending and an MMIO instruction not finished:
    /// - an 8-byte read across two pages of a device (0x600ffc): KVM asks
    ///   for 4 bytes at 0x600ffc, then 4 at 0x601000;
    /// - an 8-byte read across RAM and a device (0x3ffffc, the slot ends at
    ///   4 MiB): KVM reads the RAM's 4 bytes itself and asks the device for
    ///   4 at 0x400000;
    /// - with WHP's own calls, not the backend's run: after the memory exit
    ///   of `mov eax, [0x600000]` with interrupts on, an interrupt is
    ///   requested and the vCPU entered again without the instruction
    ///   finished, as the backend did before it finished an MMIO read in
    ///   the host: whether the next exit is the handler's `out 0x81`
    ///   (WHP delivers the interrupt before the instruction runs again) or
    ///   the same memory exit.
    ///
    /// Each guest is asserted only to reach its end within six exits.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_split_mmio_accesses_and_an_interrupt_at_reentry_on_record() {
        let answers: [[u8; 8]; 3] = [[0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7], [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7], [0xC0; 8]];
        for (name, address) in [("across two pages of a device", 0x60_0FFCu32), ("across RAM and a device", 0x3F_FFFC)] {
            let mut program = vec![0x48, 0x8B, 0x04, 0x25]; // mov rax, [address]
            program.extend_from_slice(&address.to_le_bytes());
            program.extend_from_slice(&[0xE6, PORT as u8, 0xEB, 0xFE]);
            let (vm, mut vcpu, m) = mmio_guest(&program);
            put(m, 0x3F_FFFC, &[0x01, 0x02, 0x03, 0x04]);
            let watchdog = super::Watchdog::arm(&vcpu);
            let mut reads = 0;
            let mut exits = Vec::new();
            while exits.len() < 6 {
                let answer = answers[reads.min(2)];
                let line = one_run(&mut vcpu, &answer, &mut reads);
                let end = line.starts_with("out 0x80") || line == "EINTR" || line.starts_with("run failed") || line == "InternalError";
                exits.push(line);
                if end {
                    break;
                }
            }
            let r = vcpu.get_regs().unwrap();
            drop(watchdog);
            eprintln!("MMIOREC an 8-byte read {name} ({address:#x}): {exits:?}; RAX {:#018x}", r.rax);
            assert!(exits.last().unwrap().starts_with("out 0x80"), "{name}: {exits:?}");
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }

        // WHP's own calls.
        let program = [APIC_ON.to_vec(), READ_DEVICE.to_vec(), vec![0xE6, PORT as u8, 0xF4, 0xEB, 0xFD]].concat();
        let (vm, vcpu, m) = mmio_guest(&program);
        let exit_line = |c: &whv::WHV_RUN_VP_EXIT_CONTEXT| -> String {
            match c.ExitReason {
                // SAFETY: the union arm matches the exit reason.
                whv::WHvRunVpExitReasonMemoryAccess => {
                    format!("memory access at {:#x}, RIP {:#x}", unsafe { c.Anonymous.MemoryAccess.Gpa }, c.VpContext.Rip)
                }
                // SAFETY: as above.
                whv::WHvRunVpExitReasonX64IoPortAccess => {
                    format!("port {:#x}, RIP {:#x}", unsafe { c.Anonymous.IoPortAccess.PortNumber }, c.VpContext.Rip)
                }
                r => format!("exit reason {r:#x}, RIP {:#x}", c.VpContext.Rip),
            }
        };
        let mut lines = Vec::new();
        match super::super::ffi::run_vp(vcpu.part(), vcpu.vp()) {
            Ok(c) => lines.push(exit_line(&c)),
            Err(e) => lines.push(format!("run failed, errno {}", e.errno())),
        }
        vcpu.shared.inner.inject_msi(0xFEE0_0000, MMIO_VECTOR as u32);
        for _ in 0..3 {
            match super::super::ffi::run_vp(vcpu.part(), vcpu.vp()) {
                Ok(c) => {
                    let line = exit_line(&c);
                    let done = c.ExitReason != whv::WHvRunVpExitReasonX64IoPortAccess;
                    lines.push(line);
                    // The handler's OUT, run on past (RIP after it).
                    if !done {
                        let next = c.VpContext.Rip + super::super::exit::instruction_length(c.VpContext._bitfield);
                        regs::set_rip(vcpu.part(), vcpu.vp(), next).unwrap();
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    lines.push(format!("run failed, errno {}", e.errno()));
                    break;
                }
            }
        }
        eprintln!(
            "MMIOREC WHP's entry with an interrupt requested after an MMIO exit, the instruction not finished: {lines:?} \
             (the handler's port is 0x81; the instruction is at {:#x})",
            MMIO_PROGRAM + APIC_ON.len() as u64
        );
        drop(vcpu);
        drop(vm);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// A record (MMIOSHADOW lines) for the PC's MMIOTEST failure on
    /// f35e353: an interrupt requested after the exit of `mov eax,
    /// [device]` was taken after the next instruction (`out 0x80`), not at
    /// the entry after the host finished the read, where KVM takes it. The
    /// read is the instruction after `sti` (the end of `APIC_ON`), so it is
    /// in STI's interrupt shadow (Intel SDM vol. 3 "Interruptibility state":
    /// blocking by STI lasts until the instruction after STI completes),
    /// which WHP keeps in `WHvRegisterInterruptState` bit 0 and reports in
    /// the exit's `ExecutionState.InterruptShadow` (bit 12). If finishing
    /// the instruction in the host leaves the shadow set, the entry blocks
    /// the interrupt for one more instruction. KVM clears the shadow when
    /// it finishes an instruction (Linux v6.1): the emulator's writeback
    /// calls `toggle_interruptibility` with the instruction's own shadow,
    /// none for a MOV (arch/x86/kvm/x86.c:8263-8280, 8955), which a device
    /// read reaches from `complete_emulated_mmio` (x86.c:11034); an
    /// instruction skipped rather than emulated clears it in
    /// `skip_emulated_instruction` (vmx/vmx.c:1636) and
    /// `__svm_skip_emulated_instruction` (svm/svm.c:403).
    ///
    /// With WHP's own calls, for an MMIO read, a CPUID and an `out` right
    /// after `sti`, and for an MMIO read one `nop` after it (no shadow):
    /// the shadow at the exit (exit context and register), then the
    /// instruction finished as the host does (RIP past it; the read's RAX),
    /// an interrupt requested (`inject_msi`), and the next exits, once with
    /// the shadow as the exit left it and once with it cleared first.
    /// Printed, not asserted, but for each case's own end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_the_interrupt_shadow_after_a_host_finished_instruction_on_record() {
        use super::super::ffi;
        // (name, the code after APIC_ON up to the exit, its length, the
        // exit's RAX if the host gives one)
        let cases: [(&str, Vec<u8>, u64, Option<u64>); 4] = [
            ("an MMIO read right after sti", READ_DEVICE.to_vec(), 7, Some(0x1122_3344)),
            ("an MMIO read one nop after sti", [vec![0x90], READ_DEVICE.to_vec()].concat(), 7, Some(0x1122_3344)),
            ("CPUID right after sti", vec![0x0F, 0xA2], 2, None),
            ("an out to port 0x82 right after sti", vec![0xE6, 0x82], 2, None),
        ];
        let exit_line = |c: &whv::WHV_RUN_VP_EXIT_CONTEXT| -> String {
            match c.ExitReason {
                // SAFETY: the union arm matches the exit reason.
                whv::WHvRunVpExitReasonX64IoPortAccess => format!("port {:#x}", unsafe { c.Anonymous.IoPortAccess.PortNumber }),
                whv::WHvRunVpExitReasonMemoryAccess => format!("memory access, RIP {:#x}", c.VpContext.Rip),
                r => format!("exit reason {r:#x}, RIP {:#x}", c.VpContext.Rip),
            }
        };
        for (name, code, len, rax) in cases {
            for clear in [false, true] {
                let program = [APIC_ON.to_vec(), code.clone(), vec![0xE6, PORT as u8, 0xF4, 0xEB, 0xFD]].concat();
                let (vm, vcpu, m) = mmio_guest(&program);
                let (part, vp) = (vcpu.part(), vcpu.vp());
                let first = ffi::run_vp(part, vp).unwrap();
                // SAFETY: the 16-bit view of the execution state's bit fields.
                let at_exit = unsafe { first.VpContext.ExecutionState.AsUINT16 } >> 12 & 1;
                let register = ffi::get_register(part, vp, whv::WHvRegisterInterruptState).map(|v| ffi::as_u64(&v));
                let rip = first.VpContext.Rip + len;
                match rax {
                    Some(rax) => regs::set_gpr_rax_rip(part, vp, rax, rip).unwrap(),
                    None => regs::set_rip(part, vp, rip).unwrap(),
                }
                let after_rip = ffi::get_register(part, vp, whv::WHvRegisterInterruptState).map(|v| ffi::as_u64(&v));
                if clear {
                    let state = after_rip.as_ref().copied().unwrap_or(0);
                    ffi::set_register(part, vp, whv::WHvRegisterInterruptState, ffi::reg64(state & !1)).unwrap();
                }
                vcpu.shared.inner.inject_msi(0xFEE0_0000, MMIO_VECTOR as u32);
                let mut next = Vec::new();
                for _ in 0..3 {
                    match ffi::run_vp(part, vp) {
                        Ok(c) => {
                            next.push(exit_line(&c));
                            if c.ExitReason != whv::WHvRunVpExitReasonX64IoPortAccess {
                                break;
                            }
                            // SAFETY: the union arm matches the exit reason.
                            let port = unsafe { c.Anonymous.IoPortAccess.PortNumber };
                            regs::set_rip(part, vp, c.VpContext.Rip + 2).unwrap();
                            if port == PORT {
                                break;
                            }
                        }
                        Err(e) => {
                            next.push(format!("run failed, errno {}", e.errno()));
                            break;
                        }
                    }
                }
                eprintln!(
                    "MMIOSHADOW {name}: the exit {}, its ExecutionState.InterruptShadow {at_exit}, WHvRegisterInterruptState {register:?}, \
                     after RIP set {after_rip:?}; the shadow {}; then {next:?} (the handler's port is 0x81)",
                    exit_line(&first),
                    if clear { "cleared" } else { "left" }
                );
                assert!(next.iter().any(|l| l == "port 0x80"), "{name}: the guest did not reach its out 0x80: {next:?}");
                drop(vcpu);
                drop(vm);
                // SAFETY: the test's mapping, no VM left using it.
                assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
            }
        }
    }

    /// KVM's CR4 rule (`cr4`) against what WHP takes, on this host (CR4TEST
    /// lines): with the supported CPUID set on the vCPU, each CR4 bit KVM
    /// knows set alone on a vCPU in long mode through `KVM_SET_SREGS`. A bit
    /// the rule refuses is refused with `EINVAL` before WHP is asked; a bit
    /// the rule allows must be taken by WHP, and one WHP refuses is a
    /// finding, named, that fails the test. Then the measured side of the
    /// host's CPUID: the guest's own CPUID leaf 1 and leaf 7 (from a CPUID
    /// exit) against the table, for each gated flag. A Linux snapshot's CR4
    /// 0x370eb0 is tried last.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_cr4_bits_kvm_takes_are_taken_by_whp() {
        use super::super::cr4;
        let program = [
            vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2], // mov eax, 1; xor ecx, ecx; cpuid
            vec![0x89, 0x0C, 0x25, 0x00, 0x71, 0x00, 0x00],             // mov [0x7100], ecx
            vec![0x89, 0x14, 0x25, 0x04, 0x71, 0x00, 0x00],             // mov [0x7104], edx
            vec![0xB8, 0x07, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2], // mov eax, 7; xor ecx, ecx; cpuid
            vec![0x89, 0x1C, 0x25, 0x08, 0x71, 0x00, 0x00],             // mov [0x7108], ebx
            vec![0x89, 0x0C, 0x25, 0x0C, 0x71, 0x00, 0x00],             // mov [0x710c], ecx
            vec![0xE6, PORT as u8, 0xEB, 0xFE],
        ]
        .concat();
        let (vm, mut vcpu, m) = mmio_guest(&program);
        let supported = regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
        let table = supported.as_slice().to_vec();
        vcpu.set_cpuid2(&supported).unwrap();
        let has = |l: u32, i: u32, r: u8, b: u32| super::cpuid_has(&table, l, i, r, b);
        let reserved = cr4::reserved_bits(has);
        let base = vcpu.get_sregs().unwrap();
        let mut findings = Vec::new();
        for n in 0..23u32 {
            let bit = 1u64 << n;
            if cr4::KNOWN & bit == 0 || base.cr4 & bit != 0 {
                continue;
            }
            let mut s = base;
            s.cr4 |= bit;
            let allowed = cr4::refused(s.cr4, reserved, reserved).is_none();
            let got = vcpu.set_sregs(&s).map_err(|e| e.errno());
            vcpu.set_sregs(&base).unwrap();
            let name = cr4::names(bit);
            eprintln!(
                "CR4TEST {name}: KVM's rule {}; KVM_SET_SREGS {got:?}",
                if allowed { "takes it" } else { "refuses it" }
            );
            if allowed && got.is_err() {
                findings.push(format!("{name}: KVM takes it, WHP refused it ({got:?})"));
            }
            if !allowed {
                assert_eq!(got, Err(libc::EINVAL), "{name}: refused by the rule, so EINVAL before WHP");
            }
        }
        let mut snap = base;
        snap.cr4 = 0x37_0eb0;
        eprintln!(
            "CR4TEST a Linux snapshot's CR4 0x370eb0: KVM's rule {:?}; KVM_SET_SREGS {:?}",
            cr4::refused(snap.cr4, reserved, reserved).map(|(b, w)| (cr4::names(b), w)),
            vcpu.set_sregs(&snap).map_err(|e| e.errno())
        );
        vcpu.set_sregs(&base).unwrap();
        let watchdog = super::Watchdog::arm(&vcpu);
        let mut reads = 0;
        let end = one_run(&mut vcpu, &[], &mut reads);
        drop(watchdog);
        let word = |at: u64| u32::from_le_bytes(bytes_at::<4>(m, at));
        let guest = [(1u32, 2u8, word(0x7100)), (1, 3, word(0x7104)), (7, 1, word(0x7108)), (7, 2, word(0x710c))];
        for (bit, name, (leaf, index, register, flag), feature) in cr4::GATED {
            let in_table = has(leaf, index, register, flag);
            let seen = guest.iter().find(|g| g.0 == leaf && g.1 == register).map(|g| g.2 >> flag & 1 == 1);
            eprintln!(
                "CR4TEST CPUID {feature} (CR4 {name}, bit {}): the supported table {in_table}, the guest's CPUID {seen:?}",
                bit.trailing_zeros()
            );
        }
        assert!(end.starts_with("out 0x80"), "the guest did not reach its end: {end}");
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        assert!(findings.is_empty(), "CR4 bits KVM's rule takes and WHP refuses on this host: {findings:#?}");
    }

    /// A record (SREGSREC lines) for CI run 43442912128's linux-snapshot
    /// stage, where WHP refused (0xc0350005, an invalid parameter) the
    /// special registers of a Linux guest's snapshot made on KVM: CR0
    /// 0x80050033, CR4 0x370eb0, EFER 0xd01, APIC_BASE 0xfee00d00 (bit 10:
    /// x2APIC enabled), the GDT's limit 0x7f and the IDT's 0xfff, set in
    /// one call. Which value WHP refuses, on a vCPU in long mode: each of
    /// CR0, EFER and CR4 alone, then each bit of that CR4 beyond the
    /// vCPU's alone; APIC_BASE with xAPIC (0xfee00900) and with x2APIC
    /// (0xfee00d00); then the snapshot's whole set through KVM_SET_SREGS,
    /// with each APIC_BASE. With the x2APIC bit of CPUID leaf 1 (ECX bit
    /// 21) as the host has it and as the backend's supported CPUID gives
    /// it, and the partition's local APIC mode (xAPIC, `vm.rs`). Each
    /// refusal's HRESULT is on the `whp:` line before it. Printed, not
    /// asserted.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_linux_guests_special_registers_on_record() {
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
        let vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);
        let (part, vp) = (vcpu.part(), vcpu.vp());
        let one = |name: whv::WHV_REGISTER_NAME, value: u64| match super::super::ffi::set_registers(
            part,
            vp,
            &[name],
            &[super::super::ffi::reg64(value)],
        ) {
            Ok(()) => "taken".to_string(),
            Err(e) => format!("refused (errno {})", e.errno()),
        };
        let mut lines = Vec::new();
        let host = core::arch::x86_64::__cpuid(1).ecx >> 21 & 1;
        let given = regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap()
            .as_slice()
            .iter()
            .find(|e| e.function == 1)
            .map_or(2, |e| e.ecx >> 21 & 1);
        lines.push(format!(
            "x2APIC in CPUID leaf 1: the host {host}, the backend's supported CPUID {given}; the partition's local APIC: xAPIC"
        ));
        let base = vcpu.get_sregs().unwrap();
        lines.push(format!("the vCPU in long mode: CR0 {:#x} CR4 {:#x} EFER {:#x} APIC_BASE {:#x}", base.cr0, base.cr4, base.efer, base.apic_base));
        lines.push(format!("CR0 0x80050033: {}", one(whv::WHvX64RegisterCr0, 0x8005_0033)));
        lines.push(format!("EFER 0xd01: {}", one(whv::WHvX64RegisterEfer, 0xd01)));
        for bit in 0..32 {
            let b = 1u64 << bit;
            if 0x37_0eb0 & b != 0 && base.cr4 & b == 0 {
                let r = one(whv::WHvX64RegisterCr4, base.cr4 | b);
                lines.push(format!("CR4 bit {bit} ({:#x}) alone: {r}", base.cr4 | b));
                let _ = one(whv::WHvX64RegisterCr4, base.cr4);
            }
        }
        lines.push(format!("CR4 0x370eb0: {}", one(whv::WHvX64RegisterCr4, 0x37_0eb0)));
        lines.push(format!("APIC_BASE 0xfee00900 (xAPIC): {}", one(whv::WHvX64RegisterApicBase, 0xFEE0_0900)));
        lines.push(format!("APIC_BASE 0xfee00d00 (x2APIC): {}", one(whv::WHvX64RegisterApicBase, 0xFEE0_0D00)));
        for apic_base in [0xFEE0_0D00u64, 0xFEE0_0900] {
            let mut s = base;
            (s.cr0, s.cr4, s.efer, s.apic_base) = (0x8005_0033, 0x37_0eb0, 0xd01, apic_base);
            (s.gdt.limit, s.idt.limit) = (0x7f, 0xfff);
            let r = match vcpu.set_sregs(&s) {
                Ok(()) => "taken".to_string(),
                Err(e) => format!("refused (errno {})", e.errno()),
            };
            lines.push(format!("the snapshot's set through KVM_SET_SREGS with APIC_BASE {apic_base:#x}: {r}"));
        }
        for l in &lines {
            eprintln!("SREGSREC {l}");
        }
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The guest's x2APIC as KVM's for a guest whose CPUID lacks it, the
    /// only CPUID this backend's xAPIC partition keeps (`apicmode`; CI run
    /// 43452122814, where an Intel runner's guests were offered x2APIC and
    /// froze). The VMs are xAPIC partitions, as on a host other than AMD:
    /// - the supported CPUID has no x2APIC (leaf 1 ECX bit 21), as every
    ///   host's partitions are xAPICs (`vm::X2APIC_PARTITIONS`; once AMD
    ///   hosts' are x2APICs it has it there, and the tables here are the
    ///   supported one less the bit);
    /// - `KVM_SET_CPUID2` of a table with it is refused (`ENOTSUP`) and
    ///   keeps nothing;
    /// - with the supported table, and with a table that has no leaf 1
    ///   (answered from WHP's default, the host's leaf), the guest's
    ///   `CPUID` leaf 1 has no x2APIC either;
    /// - the guest's `RDMSR` of APIC_BASE (0x1b) reads xAPIC mode, its
    ///   `WRMSR` with EXTD (bit 10) set faults (#GP), as KVM's
    ///   `kvm_set_apic_base` refuses a guest without the CPUID bit (Linux
    ///   v6.1 arch/x86/kvm/x86.c:475-483: X2APIC_ENABLE reserved), and
    ///   APIC_BASE reads as it was after it.
    ///
    /// The guest: a #GP handler that counts and steps over the 2-byte
    /// instruction; `rdmsr`, the value kept; `or eax, 0x400; wrmsr`;
    /// `rdmsr` again, kept; `cpuid` leaf 1, ECX kept; `out 0x80`.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_guest_without_x2apic_in_its_cpuid_is_refused_x2apic_as_kvm() {
        const GP_HANDLER: u64 = 0xBA00;
        const GP_COUNT: u64 = 0x7100;
        const BASE_BEFORE: u64 = 0x7108;
        const BASE_AFTER: u64 = 0x7110;
        const LEAF1_ECX: u64 = 0x7118;
        use super::super::apicmode::LocalApic;
        let x2apic = super::super::apicmode::LEAF1_ECX_X2APIC;
        let supported = regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
        let leaf1 = supported.as_slice().iter().find(|e| e.function == 1).map(|e| e.ecx).unwrap();
        let host = core::arch::x86_64::__cpuid(1).ecx;
        let partitions = super::super::vm::host_local_apic();
        eprintln!(
            "X2APICTEST leaf 1 ECX x2APIC: the host {}, the supported CPUID {}, this host's partitions {partitions:?}",
            host & x2apic != 0,
            leaf1 & x2apic != 0
        );
        // On a host whose partitions are xAPICs the supported CPUID has no
        // x2APIC; on one whose are x2APICs it has, and this test makes its
        // VMs xAPICs, as those hosts' are, with the supported table less
        // the bit.
        assert_eq!(leaf1 & x2apic != 0, partitions == LocalApic::X2Apic, "the supported CPUID against the partitions' APIC");
        let mut without: Vec<_> = supported.as_slice().to_vec();
        for e in without.iter_mut().filter(|e| e.function == 1) {
            e.ecx &= !x2apic;
        }
        let leaf_d: Vec<_> = supported.as_slice().iter().filter(|e| e.function == 0xd).copied().collect();
        let tables: [(&str, Vec<kvm_bindings::kvm_cpuid_entry2>); 2] =
            [("the supported table", without), ("a table without leaf 1", leaf_d)];
        for (name, table) in tables {
            let a = |addr: u64| (addr as u32).to_le_bytes();
            let mut program = vec![0xB9, 0x1B, 0x00, 0x00, 0x00, 0x0F, 0x32]; // mov ecx, 0x1b; rdmsr
            program.extend([0x89, 0x04, 0x25]); // mov [BASE_BEFORE], eax
            program.extend(a(BASE_BEFORE));
            program.extend([0x89, 0x14, 0x25]); // mov [BASE_BEFORE + 4], edx
            program.extend(a(BASE_BEFORE + 4));
            program.extend([0x0D, 0x00, 0x04, 0x00, 0x00, 0x0F, 0x30]); // or eax, 0x400; wrmsr
            program.extend([0x0F, 0x32, 0x89, 0x04, 0x25]); // rdmsr; mov [BASE_AFTER], eax
            program.extend(a(BASE_AFTER));
            program.extend([0x89, 0x14, 0x25]); // mov [BASE_AFTER + 4], edx
            program.extend(a(BASE_AFTER + 4));
            program.extend([0xB8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2]); // mov eax, 1; xor ecx, ecx; cpuid
            program.extend([0x89, 0x0C, 0x25]); // mov [LEAF1_ECX], ecx
            program.extend(a(LEAF1_ECX));
            program.extend([0xE6, PORT as u8, 0xEB, 0xFE]);
            super::super::vm::APIC_MODE_FOR_TESTS.set(Some(whv::WHvX64LocalApicEmulationModeXApic));
            let (vm, mut vcpu, m) = mmio_guest(&program);
            super::super::vm::APIC_MODE_FOR_TESTS.set(None);
            let mut handler = vec![0x48, 0x83, 0xC4, 0x08, 0x48, 0x83, 0x04, 0x24, 0x02, 0x48, 0xFF, 0x04, 0x25]; // add rsp, 8; add qword [rsp], 2; inc qword [GP_COUNT]
            handler.extend(a(GP_COUNT));
            handler.extend([0x48, 0xCF]); // iretq
            put(m, GP_HANDLER, &handler);
            let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
            q(MMIO_IDT + 13 * 16, (GP_HANDLER & 0xffff) | (8 << 16) | (0x8E << 40));
            q(MMIO_IDT + 13 * 16 + 8, 0);
            let mut with = table.clone();
            for e in with.iter_mut().filter(|e| e.function == 1) {
                e.ecx |= x2apic;
            }
            if with.iter().any(|e| e.function == 1) {
                let refused = vcpu.set_cpuid2(&CpuId::from_entries(&with).unwrap());
                eprintln!("X2APICTEST {name} with x2APIC set: KVM_SET_CPUID2 {:?}", refused.as_ref().map_err(|e| e.errno()));
                assert_eq!(refused.map_err(|e| e.errno()), Err(libc::ENOTSUP), "{name}: a CPUID with x2APIC was taken");
                assert!(vcpu.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap().as_slice().is_empty(), "the refused table was kept");
            }
            vcpu.set_cpuid2(&CpuId::from_entries(&table).unwrap()).unwrap();
            let watchdog = super::Watchdog::arm(&vcpu);
            let mut reads = 0;
            let mut exits = Vec::new();
            while exits.len() < 10 && !exits.last().is_some_and(|e: &String| e.starts_with("out") || e.contains("fail") || e == "EINTR") {
                exits.push(one_run(&mut vcpu, &[], &mut reads));
            }
            drop(watchdog);
            let r = |at: u64| u64::from_le_bytes(bytes_at::<8>(m, at));
            let (gp, before, after, ecx) = (r(GP_COUNT), r(BASE_BEFORE), r(BASE_AFTER), r(LEAF1_ECX) as u32);
            eprintln!(
                "X2APICTEST {name}: exits {exits:?}; APIC_BASE read {before:#x}; the WRMSR of {:#x}: {gp} #GP; APIC_BASE after it {after:#x}; the guest's leaf 1 ECX {ecx:#x} (x2APIC {})",
                before | 0x400,
                ecx & x2apic != 0
            );
            assert!(exits.last().is_some_and(|e| e.starts_with("out 0x80")), "{name}: the guest did not reach its end");
            assert_eq!(before & 0xC00, 0x800, "{name}: APIC_BASE is not in xAPIC mode");
            assert_eq!(gp, 1, "{name}: the guest's switch to x2APIC was not refused");
            assert_eq!(after, before, "{name}: APIC_BASE changed");
            assert_eq!(ecx & x2apic, 0, "{name}: the guest's CPUID offers x2APIC");
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }
    }

    /// A CPU going offline writes a deadline with its APIC software-disabled
    /// and its LVT timer entry masked with vector 0 (Linux v6.1
    /// arch/x86/kernel/smpboot.c 1690, `native_cpu_disable`'s
    /// `apic_soft_disable`: apic/apic.c 1181 and 1216-1218; then, idle until
    /// it is dead, `lapic_next_deadline`, 483-494). On an xAPIC-mode vCPU the
    /// write is taken (`IA32_TSC_DEADLINE` through `KVM_SET_MSRS`, the same
    /// path as the guest's WRMSR exit), as KVM takes it and raises nothing;
    /// with the APIC enabled the same entry is refused still, the case of a
    /// write of the mode that WHP dropped with its vector
    /// (`tscdeadline::lost_xapic_deadline`). Refused, the first ended a VMM
    /// in `boot-test.ps1 smp`'s CPU offline and online cycles (PC step 14g at
    /// acdec89).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_deadline_written_with_the_apic_software_disabled_is_taken() {
        let (vm, vcpu, m) = mmio_guest(&[0xF4]);
        let lapic = |svr: u32, lvtt: u32| {
            let mut l = vcpu.get_lapic().unwrap();
            for (at, v) in [(0xf0, svr), (0x320, lvtt)] {
                for (i, b) in v.to_le_bytes().into_iter().enumerate() {
                    l.regs[at + i] = b as std::os::raw::c_char;
                }
            }
            vcpu.set_lapic(&l).unwrap();
        };
        // Far ahead, so that nothing fires while the test runs.
        let deadline = || {
            let msrs = Msrs::from_entries(&[kvm_bindings::kvm_msr_entry { index: 0x6E0, data: 1 << 62, ..Default::default() }]).unwrap();
            vcpu.set_msrs(&msrs).map_err(|e| e.errno())
        };
        lapic(0xff, 0x1_0000);
        let disabled = deadline();
        lapic(0x1ff, 0x1_0000);
        let enabled = deadline();
        eprintln!("DEADLINEOFF the entry 0x10000: APIC software-disabled {disabled:?}, enabled {enabled:?}");
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        assert_eq!(disabled, Ok(1), "a deadline written with the APIC software-disabled");
        assert_eq!(enabled, Err(libc::ENOTSUP), "a deadline with the vector lost and the APIC enabled");
    }

    /// The x2APIC partition's LVT timer in TSC-deadline mode is refused,
    /// and outside x2APIC mode the write is a #GP as KVM's, on an AMD host's
    /// x2APIC partition made as option E makes one
    /// (`X2APIC_PARTITION_FOR_TESTS`; elsewhere the test says so and
    /// passes). Each case a VM of its own, with the supported CPUID (x2APIC
    /// and TSC_DEADLINE), the guest at CPL 0 turning x2APIC mode on
    /// (APIC_BASE |= EXTD) and its APIC on (SVR 0x1ff by WRMSR 0x80F):
    /// - WRMSR 0x832 of 0x400ec, which WHP refuses with #GP and its
    ///   register refuses too: the vCPU fails (`ENOTSUP`) and no APIC page
    ///   is set (`write_x2apic_lvtt`: the page's get and set lose an
    ///   interrupt requested between them, X2RMWREC, PC step 15a at
    ///   305a806); before, the page took it and the guest's RDMSR read
    ///   0x400ec and its deadline's interrupt came (PC step 15b);
    /// - the same entry masked (0x500ec): the same;
    /// - WRMSR 0x832 in xAPIC mode (EXTD clear): the guest's own #GP
    ///   (its gate's fault line), as KVM's `kvm_x2apic_msr_write` gives
    ///   (`apicmode::x2apic_msr_exit`; PC step 15b: the write was ignored);
    /// - the same with the IDT cut below #GP's gate: the #GP raised
    ///   delivering it is merged into a #DF (#DF's gate runs), and with
    ///   the IDT cut below #DF's too, a triple fault (`Shutdown`), as KVM's
    ///   `kvm_multiple_exception`.
    ///
    /// The CPUID has TSC_DEADLINE as Firecracker's has it
    /// ([`cpuid_with_tsc_deadline`]): without it the entry keeps one mode
    /// bit, as KVM's does (PC step 14c-1 at acdec89, a Ryzen 9 7900: the
    /// guest's RDMSR read 0xec and its TMICT write counted down), and the
    /// register takes it. Printed (TSCDLTEST lines).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_the_x2apic_lvt_timer_in_tsc_deadline_mode_is_refused() {
        use super::super::apicmode::LocalApic;
        const GATE: u64 = 0xB900;
        const LVTT_READ: u64 = 0x7100;
        const TMCCT_READ: u64 = 0x7108;
        super::super::vm::X2APIC_PARTITION_FOR_TESTS.set(true);
        if super::super::vm::host_local_apic() != LocalApic::X2Apic {
            eprintln!("TSCDLTEST not an AMD host, where option E's x2APIC partition is measured: nothing to test");
            return;
        }
        let imm = |v: u32| v.to_le_bytes();
        let wrmsr = |ecx: u32, eax: u32| [&[0xB9][..], &imm(ecx), &[0xB8], &imm(eax), &[0x31, 0xD2, 0x0F, 0x30]].concat();
        // mov ecx, ecx; rdmsr; mov [at], eax
        let rdmsr = |ecx: u32, at: u64| [&[0xB9][..], &imm(ecx), &[0x0F, 0x32, 0x89, 0x04, 0x25], &imm(at as u32)].concat();
        // rdmsr 0x1b; or eax, 0xc00; wrmsr
        let x2apic_on = [&[0xB9][..], &imm(0x1B), &[0x0F, 0x32, 0x0D], &imm(0xC00), &[0x0F, 0x30]].concat();
        // rdtsc; rax = edx:eax + 0x10000; rdx = rax >> 32; wrmsr 0x6e0
        let deadline_ahead = [
            &[0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0, 0x48, 0x05][..],
            &imm(0x1_0000),
            &[0x48, 0x89, 0xC2, 0x48, 0xC1, 0xEA, 0x20, 0xB9],
            &imm(0x6E0),
            &[0x0F, 0x30],
        ]
        .concat();
        let halt = [0xFB, 0xF4, 0xEB, 0xFD]; // sti; hlt; jmp to the hlt
        let run = |program: Vec<u8>, idt_gates: Option<u64>| {
            let (vm, mut vcpu, m) = mmio_guest(&program);
            vcpu.set_cpuid2(&cpuid_with_tsc_deadline()).unwrap();
            put(m, GATE, &[0xB0, 0xEC, 0xE6, 0x82, 0xEB, 0xFE]);
            put(m, MMIO_IDT + 0xEC * 16, &((GATE & 0xffff) | (8 << 16) | (0x8E << 40)).to_le_bytes());
            put(m, MMIO_IDT + 0xEC * 16 + 8, &0u64.to_le_bytes());
            if let Some(gates) = idt_gates {
                let mut s = vcpu.get_sregs().unwrap();
                s.idt.limit = u16::try_from(gates * 16 - 1).unwrap();
                vcpu.set_sregs(&s).unwrap();
            }
            let watchdog = super::Watchdog::arm(&vcpu);
            let mut reads = 0;
            let mut exits = Vec::new();
            while exits.len() < 10 && !exits.last().is_some_and(|e: &String| e.starts_with("out") || e.starts_with("fault") || e.contains("fail") || e == "EINTR" || e.starts_with("Shutdown")) {
                exits.push(one_run(&mut vcpu, &[], &mut reads));
            }
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            let r = |at: u64| u64::from_le_bytes(bytes_at::<8>(m, at));
            let read = (r(LVTT_READ), r(TMCCT_READ));
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
            (exits, read)
        };
        let on = [x2apic_on.clone(), wrmsr(0x80F, 0x1FF)].concat();
        // TSC-deadline mode, read back, a deadline ahead, interrupts on: the
        // vCPU fails at the write, with no page set; masked, the same.
        let refused = format!("run failed, errno {}", libc::ENOTSUP);
        for (name, entry) in [("TSC-deadline mode", 0x4_00EC), ("masked", 0x5_00EC)] {
            super::super::ffi::trace::begin();
            let (exits, (lvtt, _)) =
                run([on.clone(), wrmsr(0x832, entry), rdmsr(0x832, LVTT_READ), deadline_ahead.clone(), halt.to_vec()].concat(), None);
            let page_sets =
                super::super::ffi::trace::end().iter().filter(|c| c.call == "WHvSetVirtualProcessorInterruptControllerState").count();
            eprintln!("TSCDLTEST {name} ({entry:#x}): exits {exits:?}; APIC page sets {page_sets}; the guest's RDMSR 0x832 {lvtt:#x}");
            assert_eq!(exits.last(), Some(&refused), "{name}: the write was not refused");
            assert_eq!(page_sets, 0, "{name}: the APIC page was set");
            assert_eq!(lvtt, 0, "{name}: the guest went on past the write");
        }
        // xAPIC mode: the guest's #GP.
        let (exits, _) = run([wrmsr(0x832, 0x4_00EC), vec![0xE6, PORT as u8, 0xEB, 0xFE]].concat(), None);
        eprintln!("TSCDLTEST xAPIC mode: exits {exits:?}");
        assert!(exits.last().is_some_and(|e| e.starts_with("fault: exception 13")), "no #GP in xAPIC mode");
        // #GP's gate past the IDT: a #DF; #DF's too: a triple fault.
        let (exits, _) = run([wrmsr(0x832, 0x4_00EC), vec![0xE6, PORT as u8, 0xEB, 0xFE]].concat(), Some(13));
        eprintln!("TSCDLTEST #GP's gate past the IDT's limit: exits {exits:?}");
        assert!(exits.last().is_some_and(|e| e.starts_with("fault: exception 8")), "no #DF");
        let (exits, _) = run([wrmsr(0x832, 0x4_00EC), vec![0xE6, PORT as u8, 0xEB, 0xFE]].concat(), Some(8));
        eprintln!("TSCDLTEST #GP's and #DF's gates past it: exits {exits:?}");
        assert!(exits.last().is_some_and(|e| e.starts_with("Shutdown")), "no triple fault");
    }

    /// A guest's `RDMSR` or `WRMSR` of an x2APIC register's MSR (0x800 to
    /// 0x8ff) on the product's partition, an xAPIC (`vm::X2APIC_PARTITIONS`),
    /// is the guest's own #GP, as KVM's `kvm_x2apic_msr_read` and
    /// `kvm_x2apic_msr_write` give it outside x2APIC mode
    /// (`apicmode::x2apic_msr_exit`): WHP hands each to the backend as an
    /// MSR exit, which had answered it as an unknown MSR, the write ignored
    /// and the read 0 (TSCDLTEST, PC step 15b at 305a806). Each access a VM
    /// of its own, the instruction then `out 0x80`; the guest's fault line
    /// for vector 13, and the instruction not done (its RIP's `out` never
    /// reached). Printed (X2MSRGP lines).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_an_x2apic_msr_outside_x2apic_mode_is_a_gp_as_kvm() {
        let imm = |v: u32| v.to_le_bytes();
        let wrmsr = |ecx: u32, eax: u32| [&[0xB9][..], &imm(ecx), &[0xB8], &imm(eax), &[0x31, 0xD2, 0x0F, 0x30]].concat();
        let rdmsr = |ecx: u32| [&[0xB9][..], &imm(ecx), &[0x0F, 0x32]].concat();
        let cases: [(&str, Vec<u8>); 5] = [
            ("WRMSR 0x832 of 0x400ec (the LVT timer, TSC-deadline mode)", wrmsr(0x832, 0x4_00EC)),
            ("WRMSR 0x80b of 0 (EOI)", wrmsr(0x80B, 0)),
            ("WRMSR 0x830 of 0x40ec (a self-IPI by the ICR)", wrmsr(0x830, 0x40EC)),
            ("RDMSR 0x802 (the ID)", rdmsr(0x802)),
            ("RDMSR 0x8ff (the range's last)", rdmsr(0x8FF)),
        ];
        let mut wrong = Vec::new();
        for (name, instruction) in cases {
            super::super::vm::APIC_MODE_FOR_TESTS.set(Some(whv::WHvX64LocalApicEmulationModeXApic));
            let (vm, mut vcpu, m) = mmio_guest(&[instruction, vec![0xE6, PORT as u8, 0xEB, 0xFE]].concat());
            super::super::vm::APIC_MODE_FOR_TESTS.set(None);
            let watchdog = super::Watchdog::arm(&vcpu);
            let mut reads = 0;
            let mut exits = Vec::new();
            while exits.len() < 5 && !exits.last().is_some_and(|e: &String| e.starts_with("out") || e.starts_with("fault") || e.contains("fail") || e == "EINTR") {
                exits.push(one_run(&mut vcpu, &[], &mut reads));
            }
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            eprintln!("X2MSRGP {name}: exits {exits:?}");
            if !exits.last().is_some_and(|e| e.starts_with("fault: exception 13")) {
                wrong.push(name);
            }
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }
        assert!(wrong.is_empty(), "no #GP for {wrong:?}");
    }

    /// A local APIC state in KVM's x2APIC-mode format restores and reads
    /// back as on KVM (`get_lapic`, `set_lapic`), on an AMD host's x2APIC
    /// partition (`X2APIC_PARTITION_FOR_TESTS`): vCPU 1 with APIC_BASE 0xfee00c00 by
    /// `KVM_SET_SREGS`, then `KVM_SET_LAPIC` with the ID in KVM's legacy
    /// format (0x1000000), SVR 0x1ff and the LVT timer 0x400ec: WHP's x2APIC
    /// ID register reads 1, `KVM_GET_LAPIC` gives the ID 0x1000000, the
    /// logical destination 0x2 (KVM's `kvm_apic_calc_x2apic_ldr` of 1) and
    /// the LVT timer 0x400ec.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_kvm_lapic_state_in_x2apic_mode_restores() {
        use super::super::apicmode::LocalApic;
        super::super::vm::X2APIC_PARTITION_FOR_TESTS.set(true);
        if super::super::vm::host_local_apic() != LocalApic::X2Apic {
            eprintln!("X2LAPICTEST not an AMD host, where option E's x2APIC partition is measured: nothing to test");
            return;
        }
        let vm = super::super::VmFd::create().unwrap();
        let _zero = vm.create_vcpu(0).unwrap();
        let one = vm.create_vcpu(1).unwrap();
        let mut s = one.get_sregs().unwrap();
        s.apic_base = 0xFEE0_0C00;
        one.set_sregs(&s).unwrap();
        let word = |l: &kvm_lapic_state, at: usize| u32::from_le_bytes(std::array::from_fn(|i| l.regs[at + i].cast_unsigned()));
        let mut l = one.get_lapic().unwrap();
        for (at, v) in [(0x20usize, 0x100_0000u32), (0xf0, 0x1ff), (0x320, 0x4_00ec)] {
            for (i, b) in v.to_le_bytes().into_iter().enumerate() {
                l.regs[at + i] = b as std::os::raw::c_char;
            }
        }
        one.set_lapic(&l).unwrap();
        let id = super::super::ffi::as_u64(&super::super::ffi::get_register(one.part(), one.vp(), whv::WHvX64RegisterApicId).unwrap());
        let back = one.get_lapic().unwrap();
        let (got_id, ldr, lvtt) = (word(&back, 0x20), word(&back, 0xd0), word(&back, 0x320));
        eprintln!("X2LAPICTEST WHvX64RegisterApicId {id:#x}; KVM_GET_LAPIC: ID {got_id:#x}, LDR {ldr:#x}, LVT timer {lvtt:#x}");
        assert_eq!((id, got_id, ldr, lvtt), (1, 0x100_0000, 0x2, 0x4_00ec));
    }

    /// Option E-ii's audit of the interrupt sources inside WHP, on record:
    /// a partition as `vm::configure` makes it, an xAPIC and (on an AMD
    /// host, `X2APIC_PARTITION_FOR_TESTS`) an x2APIC, has neither a PMU
    /// (`WHvPartitionPropertyCodeProcessorPerfmonFeatures`, `PmuSupport`,
    /// bit 0) nor the synthetic interrupt controller or synthetic timers
    /// (`WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks`, bank 0's
    /// `AccessSynicRegs` bit 4, `AccessSyntheticTimerRegs` bit 5,
    /// `DirectSyntheticTimers` bit 22: WinHvPlatformDefs.h), so none of
    /// them can raise an interrupt of a vCPU while the APIC page is read and
    /// set (the E-ii design: the page's get and set with every requester
    /// held off). Printed with what the host offers (`WHvGetCapability` of
    /// the same codes) and the property calls' HRESULTs (X2HOLDREC lines);
    /// asserted, the partition's bits off.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_partition_has_no_pmu_or_synthetic_interrupts_on_record() {
        use super::super::apicmode::LocalApic;
        const PMU: u64 = 1;
        const SYNIC: u64 = 1 << 4;
        const STIMERS: u64 = 1 << 5;
        const DIRECT_STIMERS: u64 = 1 << 22;
        let mut sources = Vec::new();
        for x2apic in [false, true] {
            super::super::vm::X2APIC_PARTITION_FOR_TESTS.set(x2apic);
            if x2apic && super::super::vm::host_local_apic() != LocalApic::X2Apic {
                eprintln!("X2HOLDREC not an AMD host: no x2APIC partition to read");
                continue;
            }
            let kind = if x2apic { "x2APIC" } else { "xAPIC" };
            let vm = super::super::VmFd::create().unwrap();
            let v = vm.create_vcpu(0).unwrap();
            let read = |code: i32, cap: bool| -> (i32, [u64; 2]) {
                let mut out = [0u64; 2];
                let mut written = 0u32;
                let size = u32::try_from(core::mem::size_of_val(&out)).unwrap();
                // SAFETY: an output buffer of the size passed.
                let hres = unsafe {
                    if cap {
                        whv::WHvGetCapability(code, out.as_mut_ptr().cast(), size, &mut written)
                    } else {
                        whv::WHvGetPartitionProperty(v.part(), code, out.as_mut_ptr().cast(), size, &mut written)
                    }
                };
                (hres, out)
            };
            let (perf_cap_hr, perf_cap) = read(whv::WHvCapabilityCodeProcessorPerfmonFeatures, true);
            let (perf_hr, perf) = read(whv::WHvPartitionPropertyCodeProcessorPerfmonFeatures, false);
            // WHV_SYNTHETIC_PROCESSOR_FEATURES_BANKS: the count and a reserved
            // word, then bank 0.
            let (syn_cap_hr, syn_cap) = read(whv::WHvCapabilityCodeSyntheticProcessorFeaturesBanks, true);
            let (syn_hr, syn) = read(whv::WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks, false);
            let (offered, given) = (syn_cap[1], syn[1]);
            eprintln!(
                "X2HOLDREC {kind} partition: perfmon offered {:#x} ({perf_cap_hr:#010x}), given {:#x} ({perf_hr:#010x}); \
                 synthetic features banks offered {:#x}: bank 0 {offered:#x} ({syn_cap_hr:#010x}), given {:#x}: bank 0 \
                 {given:#x} ({syn_hr:#010x}); given: PMU {}, SynIC {}, synthetic timers {}, direct synthetic timers {}",
                perf_cap[0],
                perf[0],
                syn_cap[0] & 0xffff_ffff,
                syn[0] & 0xffff_ffff,
                perf[0] & PMU != 0,
                given & SYNIC != 0,
                given & STIMERS != 0,
                given & DIRECT_STIMERS != 0,
            );
            if perf_hr < 0 || perf[0] & PMU != 0 {
                sources.push(format!("{kind}: a PMU ({perf_hr:#010x}, {:#x})", perf[0]));
            }
            if syn_hr < 0 || given & (SYNIC | STIMERS | DIRECT_STIMERS) != 0 {
                sources.push(format!("{kind}: synthetic interrupts ({syn_hr:#010x}, bank 0 {given:#x})"));
            }
            drop(v);
            drop(vm);
        }
        super::super::vm::X2APIC_PARTITION_FOR_TESTS.set(false);
        assert!(sources.is_empty(), "interrupt sources inside WHP, or unread: {sources:?}");
    }

    /// The APIC register page's get and set lose an interrupt requested of
    /// the vCPU between them, and the guest's x2APIC LVT timer write in
    /// TSC-deadline mode (`write_x2apic_lvtt`: WHP's register refuses that
    /// mode, errno 87, X2E0REC c in CI runs 43521200989 and 43524342863)
    /// sets no page, on an AMD host's x2APIC partition made as option E
    /// makes one (`X2APIC_PARTITION_FOR_TESTS`; no product partition is
    /// one, `vm::X2APIC_PARTITIONS`). An irqfd's writer, the MSI hook or
    /// another vCPU's IPI may request an interrupt at any time, so a page
    /// set while the guest runs would hang it. Vector 0xe1, whose gate
    /// EOIs (WRMSR 0x80b) and does `out 0x82`; vCPU 0 halted with
    /// interrupts on, stopped at its last exit while each case's steps are
    /// made, then run:
    /// - control: an MSI injected (`inject_msi`, the irqfd writer's call),
    ///   no page set;
    /// - the MSI, then the page's get and set (the LVT timer 0x400e0);
    /// - the page's get, the MSI injected from another thread, the set of
    ///   the page as read before it: the race's own order;
    /// - the page's get, vCPU 1 run to its fixed IPI of 0xe1 to APIC 0
    ///   (WRMSR 0x830, which WHP takes itself), the set: an IPI there;
    /// - the MSI, then `write_x2apic_lvtt(0x400e0)` itself (the run loop's
    ///   path), counting the page sets in the trace.
    ///
    /// Each case 50 rounds, a round's interrupt taken (`out 0x82 [e1]`)
    /// before its run is kicked after 5 s; a case stops at its first lost
    /// one. Asserted: the control and the MSI before the get keep every
    /// interrupt; the MSI and the IPI between the get and the set are lost
    /// at their first round (PC step 15a at 305a806, a Ryzen 9 7900, debug
    /// and release builds alike; if WHP ever keeps them, the reason for
    /// `write_x2apic_lvtt`'s refusal is gone and the test says so); and
    /// `write_x2apic_lvtt` is refused (`ENOTSUP`), sets no page, and every
    /// MSI is taken. Printed (X2RMWREC lines), with both of WHP's formats of
    /// the page read after the first request of each case
    /// (`lapic_formats`).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_page_set_loses_interrupts_and_the_lvt_timer_write_makes_none() {
        use super::super::apicmode::LocalApic;
        use super::super::ffi;
        const V: u8 = 0xE1;
        const GATE: u64 = 0xB900;
        const IPI_PROGRAM: u64 = 0xBA00;
        const MSI: u64 = 0xFEE0_0000;
        const LVTT: u32 = 0x4_00E0;
        const ROUNDS: usize = 50;
        super::super::vm::X2APIC_PARTITION_FOR_TESTS.set(true);
        if super::super::vm::host_local_apic() != LocalApic::X2Apic {
            eprintln!("X2RMWREC not an AMD host, where option E's x2APIC partition is measured: nothing to test");
            return;
        }
        let imm = |v: u32| v.to_le_bytes();
        let wrmsr = |ecx: u32, eax: u32| [&[0xB9][..], &imm(ecx), &[0xB8], &imm(eax), &[0x31, 0xD2, 0x0F, 0x30]].concat();
        // rdmsr 0x1b; or eax, 0xc00; wrmsr; then SVR 0x1ff.
        let on = [&[0xB9][..], &imm(0x1B), &[0x0F, 0x32, 0x0D], &imm(0xC00), &[0x0F, 0x30], &wrmsr(0x80F, 0x1FF)].concat();
        let push = [0x50u8, 0x51, 0x52];
        let pop_iret = [0x5Au8, 0x59, 0x58, 0x48, 0xCF];
        let taken = format!("out 0x82 [{V:02x}]");
        let vm_with = |program: &[u8], gate: &[u8]| {
            let (vm, vcpu, m) = mmio_guest(program);
            vcpu.set_cpuid2(&cpuid_with_tsc_deadline()).unwrap();
            put(m, GATE, gate);
            put(m, MMIO_IDT + u64::from(V) * 16, &((GATE & 0xffff) | (8 << 16) | (0x8E << 40)).to_le_bytes());
            put(m, MMIO_IDT + u64::from(V) * 16 + 8, &0u64.to_le_bytes());
            (vm, vcpu, m)
        };
        // Runs `v` until the gate's `out 0x82`, a kick after 5 s, or a
        // fifth exit; the last exit.
        let run_to_taken = |v: &mut VcpuFd| {
            let watchdog = super::Watchdog::arm(v);
            let mut reads = 0;
            let mut exits = Vec::new();
            loop {
                let e = one_run(v, &[], &mut reads);
                let end = e == taken || e == "EINTR" || e.starts_with("fault") || e.contains("fail") || exits.len() >= 4;
                exits.push(e);
                if end {
                    break;
                }
            }
            drop(watchdog);
            v.set_kvm_immediate_exit(0);
            exits.join(", ")
        };
        let set_page = |v: &VcpuFd, page: &mut [u8], size: u32| {
            page[0x320..0x324].copy_from_slice(&LVTT.to_le_bytes());
            // SAFETY: the register page, valid for `size` bytes.
            let hres = unsafe { whv::WHvSetVirtualProcessorInterruptControllerState(v.part(), v.vp(), page.as_ptr().cast(), size) };
            assert_eq!(hres, 0, "the page's set");
        };

        // The rounds, each the vCPU halted with interrupts on. `out 0x84`
        // once its APIC is on: an interrupt requested before is dropped, as
        // KVM drops a fixed interrupt to a software-disabled APIC
        // (`__apic_accept_irq`; PC step 14a at acdec89, the warm-up MSI
        // injected before the guest ran: EINTR).
        let gate = [&push[..], &wrmsr(0x80B, 0), &[0xB0, V, 0xE6, 0x82], &pop_iret].concat();
        let (vm, mut zero, m) = vm_with(&[on.clone(), vec![0xE6, 0x84, 0xFB, 0xF4, 0xEB, 0xFD]].concat(), &gate);
        // vCPU 1: a fixed IPI of V to APIC 0 (ICR 0x4000 | V, EDX 0), `out
        // 0x83`, again.
        put(m, IPI_PROGRAM, &[wrmsr(0x830, 0x4000 | u32::from(V)), vec![0xE6, 0x83, 0xEB, 0xEE]].concat());
        let mut one = vm.create_vcpu(1).unwrap();
        // Runnable: an AP is made waiting for a SIPI, as KVM makes one
        // (`regs::startup_suspend`), and would run nothing.
        one.set_mp_state(kvm_bindings::kvm_mp_state { mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE }).unwrap();
        one.set_cpuid2(&cpuid_with_tsc_deadline()).unwrap();
        one.set_sregs(&zero.get_sregs().unwrap()).unwrap();
        one.set_regs(&kvm_regs { rip: IPI_PROGRAM, rsp: 0x8800, rflags: 2, ..Default::default() }).unwrap();
        ffi::set_register(one.part(), one.vp(), whv::WHvX64RegisterApicBase, ffi::reg64(0xFEE0_0C00)).unwrap();
        let mut l = one.get_lapic().unwrap();
        for (i, b) in 0x1ffu32.to_le_bytes().into_iter().enumerate() {
            l.regs[0xf0 + i] = b as std::os::raw::c_char;
        }
        one.set_lapic(&l).unwrap();
        let inner = Arc::clone(&zero.shared.inner);
        let inject = || inner.inject_msi(MSI, u32::from(V));
        let mut reads = 0;
        let watchdog = super::Watchdog::arm(&zero);
        let on_line = one_run(&mut zero, &[], &mut reads);
        drop(watchdog);
        zero.set_kvm_immediate_exit(0);
        assert!(on_line.starts_with("out 0x84"), "the guest did not turn its APIC on: {on_line}");
        inject();
        let warm = run_to_taken(&mut zero);
        eprintln!("X2RMWREC the guest's first interrupt (x2APIC on, SVR 0x1ff, STI, HLT): {warm}");
        assert!(warm.ends_with(&taken), "the guest took no interrupt: the test has no guest ({warm})");
        let cases = [
            "control, no page set",
            "the MSI, then the page's get and set",
            "the page's get, the MSI from another thread, the page's set",
            "the page's get, vCPU 1's IPI, the page's set",
            "the MSI, then write_x2apic_lvtt",
        ];
        let mut lost = Vec::new();
        for (case, name) in cases.iter().enumerate() {
            let (mut delivered, mut page_sets) = (0usize, 0usize);
            let mut first_lost = None;
            for round in 0..ROUNDS {
                let formats = |what: &str| {
                    if round == 0 {
                        for line in lapic_formats(&format!("X2RMWREC {name}: {what}"), zero.part(), zero.vp()) {
                            eprintln!("{line}");
                        }
                    }
                };
                match case {
                    0 => {
                        inject();
                        formats("after the MSI");
                    }
                    1 => {
                        inject();
                        formats("after the MSI");
                        let (mut page, size) = zero.lapic_page().unwrap();
                        set_page(&zero, &mut page[..], size);
                    }
                    2 => {
                        let (mut page, size) = zero.lapic_page().unwrap();
                        std::thread::scope(|s| {
                            s.spawn(inject);
                        });
                        formats("after the MSI, the page read before it");
                        set_page(&zero, &mut page[..], size);
                    }
                    3 => {
                        let (mut page, size) = zero.lapic_page().unwrap();
                        let mut reads = 0;
                        let watchdog = super::Watchdog::arm(&one);
                        let sent = one_run(&mut one, &[], &mut reads);
                        drop(watchdog);
                        one.set_kvm_immediate_exit(0);
                        assert!(sent.starts_with("out 0x83"), "{name}: vCPU 1's IPI: {sent}");
                        formats("after the IPI, the page read before it");
                        set_page(&zero, &mut page[..], size);
                    }
                    _ => {
                        inject();
                        formats("after the MSI");
                        ffi::trace::begin();
                        let written = zero.write_x2apic_lvtt(LVTT);
                        page_sets += ffi::trace::end()
                            .iter()
                            .filter(|c| c.call == "WHvSetVirtualProcessorInterruptControllerState")
                            .count();
                        assert_eq!(written.map_err(|e| e.errno()), Err(libc::ENOTSUP), "write_x2apic_lvtt was not refused");
                    }
                }
                let end = run_to_taken(&mut zero);
                if end.ends_with(&taken) {
                    delivered += 1;
                } else {
                    first_lost = Some(format!("round {round}'s was not: {end}"));
                    break;
                }
            }
            let sets = if case == 4 { format!("; the page set {page_sets} times") } else { String::new() };
            eprintln!(
                "X2RMWREC {name}: {delivered} of the {} interrupts requested taken{sets}{}",
                first_lost.as_ref().map_or(ROUNDS, |_| delivered + 1),
                first_lost.as_ref().map_or(String::new(), |l| format!("; {l}"))
            );
            if first_lost.is_some() {
                lost.push(*name);
            }
            assert_eq!(page_sets, 0, "{name}: write_x2apic_lvtt set the APIC page");
        }
        // `inject` holds the VM too (its `inner`): the partition, and its
        // mapping of `m`, last until it goes (PC step 15a at 305a806: the
        // test's next VM was refused its memory, errno 87, a process's one
        // partition with memory mapped being this one).
        drop(inner);
        drop(one);
        drop(zero);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        assert_eq!(
            lost,
            [cases[2], cases[3]],
            "the cases that lost an interrupt: the control, the MSI before the get and write_x2apic_lvtt keep \
             every one, and an MSI or IPI between the page's get and set is lost (PC step 15a at 305a806); if \
             WHP now keeps those, the reason for write_x2apic_lvtt's refusal is gone: say so at \
             vm::X2APIC_PARTITIONS"
        );
    }

    /// Option E-ii (the E design: the APIC page's get and set with every
    /// requester held off): a guest's x2APIC LVT timer write in
    /// TSC-deadline mode is taken and loses no interrupt, on an AMD host's
    /// x2APIC partition (`X2APIC_PARTITION_FOR_TESTS`; elsewhere the test
    /// says so and passes). Vector 0xe1, whose gate counts (`lock inc
    /// [TAKEN]`), EOIs and returns; vCPU 0's guest writes 0x400e0 to the LVT
    /// timer in a loop (each write a #GP exit and a held page write), with
    /// interrupts on. Each part a VM of its own:
    /// - a: the window itself: [`PAGE_WINDOW`], the one test seam, runs
    ///   between the page's get and set, and starts a thread that injects
    ///   an MSI then (`inject_msi`, the irqfd writer's call), 2 ms before
    ///   the set; 50 such writes, every MSI taken;
    /// - b: vCPU 1, on its own thread, sends 2000 fixed IPIs of 0xe1 to
    ///   vCPU 0 (WRMSR 0x830, WHP's own), each once the one before was
    ///   taken or a bound of spins passed (counted lost), against vCPU 0's
    ///   loop: none lost;
    /// - c: vCPU 0's own one-shot APIC timer expired before the write (TMICT
    ///   1, divide by 1, interrupts off, a spin): its interrupt, pending in
    ///   the page the write reads, is taken once interrupts are on, as KVM
    ///   keeps a pending timer interrupt across `apic_update_lvtt`'s cancel;
    /// - e: the cost of a held write, 1000 in a loop, with 0, 1 and 15 other
    ///   vCPUs halted with interrupts on (idle CPUs: the NOHZ path's two
    ///   writes per idle period, kernel/time/tick-oneshot.c 27-41, each cost
    ///   this), printed (X2HOLDREC);
    /// - f: 2000 MSIs injected from another thread, each once the last was
    ///   taken, against vCPU 0's loop: every one taken.
    ///
    /// An event WHP is delivering when the #GP is raised never reaches the
    /// page path: `gp::decide` gives such a #GP back (its `delivering` rule,
    /// unit-tested in fuzz `whp_gp`). Today's backend refuses the write
    /// (`ENOTSUP`, f42dd60): the test fails at part a's first write until
    /// E-ii is written.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_held_lvt_timer_write_loses_no_interrupt() {
        use super::super::apicmode::LocalApic;
        use super::super::ffi;
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        const V: u8 = 0xE1;
        const GATE: u64 = 0xB900;
        const IPI_PROGRAM: u64 = 0xBA00;
        const HALT_PROGRAM: u64 = 0xBB00;
        const TAKEN: u64 = 0x7200;
        const LOOPS: u64 = 0x7208;
        const SENT: u64 = 0x7210;
        const LOST: u64 = 0x7218;
        const MSI: u64 = 0xFEE0_0000;
        const LVTT: u32 = 0x4_00E0;
        const WINDOWS: u32 = 50;
        const IPIS: u32 = 2000;
        const MSIS: u32 = 2000;
        const COST_WRITES: u32 = 1000;
        super::super::vm::X2APIC_PARTITION_FOR_TESTS.set(true);
        if super::super::vm::host_local_apic() != LocalApic::X2Apic {
            eprintln!("X2HOLD not an AMD host, where option E's x2APIC partition is measured: nothing to test");
            return;
        }
        let imm = |v: u32| v.to_le_bytes();
        let wrmsr = |ecx: u32, eax: u32| [&[0xB9][..], &imm(ecx), &[0xB8], &imm(eax), &[0x31, 0xD2, 0x0F, 0x30]].concat();
        // rdmsr 0x1b; or eax, 0xc00; wrmsr; then SVR 0x1ff.
        let on = [&[0xB9][..], &imm(0x1B), &[0x0F, 0x32, 0x0D], &imm(0xC00), &[0x0F, 0x30], &wrmsr(0x80F, 0x1FF)].concat();
        // push rax, rcx, rdx; lock inc dword [TAKEN]; EOI; pop; iretq.
        let gate = [
            &[0x50u8, 0x51, 0x52][..],
            &[0xF0, 0xFF, 0x04, 0x25, 0x00, 0x72, 0x00, 0x00],
            &wrmsr(0x80B, 0),
            &[0x5A, 0x59, 0x58, 0x48, 0xCF],
        ]
        .concat();
        // sti; then the LVT timer write and inc dword [LOOPS], again.
        let lvt_loop = [on.clone(), vec![0xFB], wrmsr(0x832, LVTT), vec![0xFF, 0x04, 0x25, 0x08, 0x72, 0x00, 0x00, 0xEB, 0xE9]].concat();
        let vm_with = |program: &[u8]| {
            let (vm, vcpu, m) = mmio_guest(program);
            vcpu.set_cpuid2(&cpuid_with_tsc_deadline()).unwrap();
            put(m, GATE, &gate);
            put(m, MMIO_IDT + u64::from(V) * 16, &((GATE & 0xffff) | (8 << 16) | (0x8E << 40)).to_le_bytes());
            put(m, MMIO_IDT + u64::from(V) * 16 + 8, &0u64.to_le_bytes());
            put(m, HALT_PROGRAM, &[0xFB, 0xF4, 0xEB, 0xFD]);
            (vm, vcpu, m)
        };
        let reader = |m: *mut u8| {
            let at = m as usize;
            // SAFETY: guest memory, mapped while the test's VM has it; the
            // guest writes it.
            move |off: u64| unsafe { std::ptr::read_volatile((at + usize::try_from(off).unwrap()) as *const u32) }
        };
        // A vCPU of `vm` runnable at `rip`, with vCPU 0's special registers
        // and the CPUID; x2APIC mode on (`x2apic`).
        let ap = |vm: &super::super::VmFd, zero: &VcpuFd, id: u64, rip: u64, x2apic: bool| {
            let v = vm.create_vcpu(id).unwrap();
            v.set_mp_state(kvm_bindings::kvm_mp_state { mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE }).unwrap();
            v.set_cpuid2(&cpuid_with_tsc_deadline()).unwrap();
            v.set_sregs(&zero.get_sregs().unwrap()).unwrap();
            v.set_regs(&kvm_regs { rip, rsp: 0x8800 - id * 0x40, rflags: 2, ..Default::default() }).unwrap();
            if x2apic {
                ffi::set_register(v.part(), v.vp(), whv::WHvX64RegisterApicBase, ffi::reg64(0xFEE0_0C00)).unwrap();
                let mut l = v.get_lapic().unwrap();
                for (i, b) in 0x1ffu32.to_le_bytes().into_iter().enumerate() {
                    l.regs[0xf0 + i] = b as std::os::raw::c_char;
                }
                v.set_lapic(&l).unwrap();
            }
            v
        };
        // Runs `v` until a kick (EINTR), a failure or `out` `port`; the exits.
        let run_until = |v: &mut VcpuFd, port: Option<u16>| {
            let mut reads = 0;
            let mut exits = Vec::new();
            loop {
                let e = one_run(v, &[], &mut reads);
                let end = e == "EINTR" || e.contains("fail") || e.starts_with("fault") || port.is_some_and(|p| e.starts_with(&format!("out {p:#x}"))) || exits.len() >= 8;
                exits.push(e);
                if end {
                    break;
                }
            }
            v.set_kvm_immediate_exit(0);
            exits
        };
        let unmap = |m: *mut u8| {
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        };
        let mut wrong: Vec<String> = Vec::new();

        // a: an MSI requested inside the window.
        {
            let (vm, mut zero, m) = vm_with(&lvt_loop);
            let read = reader(m);
            let inner = Arc::clone(&zero.shared.inner);
            let requested = Arc::new(AtomicU64::new(0));
            let (hook_inner, hook_requested) = (Arc::clone(&inner), Arc::clone(&requested));
            PAGE_WINDOW.with(|w| {
                *w.borrow_mut() = Some(Box::new(move || {
                    if hook_requested.load(Ordering::SeqCst) < u64::from(WINDOWS) {
                        let i = Arc::clone(&hook_inner);
                        std::thread::spawn(move || i.inject_msi(MSI, u32::from(V)));
                        hook_requested.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }));
            });
            let mut kicker = VcpuFd { shared: Arc::clone(&zero.shared), own: None };
            let watch_requested = Arc::clone(&requested);
            let watcher = std::thread::spawn(move || {
                let begun = Instant::now();
                while begun.elapsed() < Duration::from_secs(20)
                    && !(watch_requested.load(Ordering::SeqCst) >= u64::from(WINDOWS) && u64::from(read(TAKEN)) >= u64::from(WINDOWS))
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                // The last ones' time to be taken.
                std::thread::sleep(Duration::from_millis(50));
                kicker.set_kvm_immediate_exit(1);
                (read(TAKEN), read(LOOPS), begun.elapsed())
            });
            let exits = run_until(&mut zero, None);
            let (taken, loops, took) = watcher.join().unwrap();
            PAGE_WINDOW.with(|w| *w.borrow_mut() = None);
            let asked = requested.load(Ordering::SeqCst);
            eprintln!("X2HOLD a: {asked} MSIs requested inside the page's window, {taken} taken; the guest's writes {loops}, in {took:?}; exits {exits:?}");
            if asked < u64::from(WINDOWS) || u64::from(taken) != asked || exits.last().map(String::as_str) != Some("EINTR") {
                wrong.push(format!("a: {asked} requested, {taken} taken, exits {exits:?}"));
            }
            drop((inner, zero, vm));
            unmap(m);
        }

        // b: vCPU 1's IPIs against vCPU 0's loop.
        {
            let (vm, mut zero, m) = vm_with(&lvt_loop);
            let read = reader(m);
            // mov ebx, [TAKEN]; the IPI; lock inc [SENT]; mov ecx, 1 << 24;
            // spin until [TAKEN] moves or ecx runs out (lock inc [LOST]);
            // again until [SENT] is IPIS; out 0x83.
            let ipi = [
                &[0x8Bu8, 0x1C, 0x25, 0x00, 0x72, 0x00, 0x00][..],
                &wrmsr(0x830, 0x4000 | u32::from(V)),
                &[0xF0, 0xFF, 0x04, 0x25, 0x10, 0x72, 0x00, 0x00],
                &[0xB9],
                &imm(1 << 24),
                &[0x3B, 0x1C, 0x25, 0x00, 0x72, 0x00, 0x00, 0x75, 0x0E, 0xF3, 0x90, 0xFF, 0xC9, 0x75, 0xF1],
                &[0xF0, 0xFF, 0x04, 0x25, 0x18, 0x72, 0x00, 0x00],
                &[0x81, 0x3C, 0x25, 0x10, 0x72, 0x00, 0x00],
                &imm(IPIS),
                &[0x72, 0xBA, 0xE6, 0x83, 0xEB, 0xFE],
            ]
            .concat();
            assert_eq!(ipi.len(), 74, "the IPI program's jumps are for 74 bytes");
            put(m, IPI_PROGRAM, &ipi);
            let mut one = ap(&vm, &zero, 1, IPI_PROGRAM, true);
            let mut kicker = VcpuFd { shared: Arc::clone(&zero.shared), own: None };
            let sender = std::thread::spawn(move || {
                let begun = Instant::now();
                let watchdog = super::Watchdog::arm(&one);
                let mut exits = Vec::new();
                let mut reads = 0;
                while begun.elapsed() < Duration::from_secs(60) {
                    let e = one_run(&mut one, &[], &mut reads);
                    let end = e.starts_with("out 0x83") || e == "EINTR" || e.contains("fail") || e.starts_with("fault");
                    exits.push(e);
                    if end {
                        break;
                    }
                }
                drop(watchdog);
                std::thread::sleep(Duration::from_millis(50));
                kicker.set_kvm_immediate_exit(1);
                (exits, begun.elapsed(), one)
            });
            let exits = run_until(&mut zero, None);
            let (sent_exits, took, one) = sender.join().unwrap();
            let (sent, taken, lost, loops) = (read(SENT), read(TAKEN), read(LOST), read(LOOPS));
            eprintln!(
                "X2HOLD b: vCPU 1 sent {sent} IPIs, {taken} taken, {lost} not taken within the spin bound, in {took:?}; \
                 vCPU 0's writes {loops}; vCPU 1's exits {sent_exits:?}, vCPU 0's {exits:?}"
            );
            if sent != IPIS || taken != IPIS || lost != 0 || loops < 10 {
                wrong.push(format!("b: {sent} sent, {taken} taken, {lost} lost, {loops} writes"));
            }
            drop((one, zero, vm));
            unmap(m);
        }

        // c: the vCPU's own timer, expired before the write.
        {
            let program = [
                on.clone(),
                vec![0xFA],
                wrmsr(0x83E, 0xB),
                wrmsr(0x832, u32::from(V)),
                wrmsr(0x838, 1),
                [&[0xB9][..], &imm(0x10_0000), &[0xF3, 0x90, 0xFF, 0xC9, 0x75, 0xFA]].concat(),
                wrmsr(0x832, LVTT),
                vec![0xFB, 0x90, 0x90, 0xE6, 0x85, 0xEB, 0xFE],
            ]
            .concat();
            let (vm, mut zero, m) = vm_with(&program);
            let read = reader(m);
            let watchdog = super::Watchdog::arm(&zero);
            let exits = run_until(&mut zero, Some(0x85));
            drop(watchdog);
            let taken = read(TAKEN);
            eprintln!("X2HOLD c: the one-shot timer expired before the write: exits {exits:?}; its interrupt taken {taken} times");
            if exits.last().is_none_or(|e| !e.starts_with("out 0x85")) || taken != 1 {
                wrong.push(format!("c: exits {exits:?}, taken {taken}"));
            }
            drop((zero, vm));
            unmap(m);
        }

        // e: the cost, with 0, 1 and 15 other vCPUs halted.
        for others in [0u64, 1, 15] {
            // The writes, counted in [LOOPS], to COST_WRITES; out 0x86.
            let program = [
                on.clone(),
                wrmsr(0x832, LVTT),
                vec![0xFF, 0x04, 0x25, 0x08, 0x72, 0x00, 0x00, 0x81, 0x3C, 0x25, 0x08, 0x72, 0x00, 0x00],
                imm(COST_WRITES).to_vec(),
                vec![0x72, 0xDE, 0xE6, 0x86, 0xEB, 0xFE],
            ]
            .concat();
            let (vm, mut zero, m) = vm_with(&program);
            let read = reader(m);
            let stop = Arc::new(AtomicBool::new(false));
            let idlers: Vec<_> = (1..=others)
                .map(|id| {
                    let mut v = ap(&vm, &zero, id, HALT_PROGRAM, false);
                    let stop = Arc::clone(&stop);
                    let mut kick = VcpuFd { shared: Arc::clone(&v.shared), own: None };
                    let thread = std::thread::spawn(move || {
                        let mut reads = 0;
                        while !stop.load(Ordering::SeqCst) {
                            let _ = one_run(&mut v, &[], &mut reads);
                            v.set_kvm_immediate_exit(0);
                        }
                        v
                    });
                    (thread, move || kick.set_kvm_immediate_exit(1))
                })
                .collect();
            let watchdog = super::Watchdog::arm(&zero);
            let begun = Instant::now();
            let exits = run_until(&mut zero, Some(0x86));
            let took = begun.elapsed();
            drop(watchdog);
            stop.store(true, Ordering::SeqCst);
            let mut halted = Vec::new();
            for (thread, mut kick) in idlers {
                kick();
                halted.push(thread.join().unwrap());
            }
            let writes = read(LOOPS);
            eprintln!(
                "X2HOLDREC e: {writes} held LVT timer writes with {others} other vCPUs halted: {took:?}, {} us a write; exits {exits:?}",
                took.as_micros() / u128::from(writes.max(1))
            );
            if writes != COST_WRITES {
                wrong.push(format!("e ({others} others): {writes} writes, exits {exits:?}"));
            }
            drop((halted, zero, vm));
            unmap(m);
        }

        // f: MSIs from another thread against the loop.
        {
            let (vm, mut zero, m) = vm_with(&lvt_loop);
            let read = reader(m);
            let inner = Arc::clone(&zero.shared.inner);
            let mut kicker = VcpuFd { shared: Arc::clone(&zero.shared), own: None };
            let writer = std::thread::spawn(move || {
                let begun = Instant::now();
                while read(LOOPS) < 10 && begun.elapsed() < Duration::from_secs(10) {
                    std::thread::yield_now();
                }
                let (mut requested, mut lost) = (0u32, 0u32);
                if read(LOOPS) >= 10 {
                    while requested < MSIS && lost < 3 {
                        let before = read(TAKEN);
                        inner.inject_msi(MSI, u32::from(V));
                        requested += 1;
                        let asked = Instant::now();
                        while read(TAKEN) == before {
                            if asked.elapsed() > Duration::from_secs(1) {
                                lost += 1;
                                break;
                            }
                            std::hint::spin_loop();
                        }
                    }
                }
                let out = (requested, lost, read(TAKEN), read(LOOPS), begun.elapsed());
                kicker.set_kvm_immediate_exit(1);
                drop(inner);
                out
            });
            let exits = run_until(&mut zero, None);
            let (requested, lost, taken, loops, took) = writer.join().unwrap();
            eprintln!(
                "X2HOLD f: {requested} MSIs injected from another thread, {taken} taken, {lost} not taken within 1 s; the \
                 guest's held writes {loops}, in {took:?}; exits {exits:?}"
            );
            if (requested, taken, lost) != (MSIS, MSIS, 0) || loops < 10 {
                wrong.push(format!("f: {requested} requested, {taken} taken, {lost} lost, {loops} writes"));
            }
            drop((zero, vm));
            unmap(m);
        }
        assert!(wrong.is_empty(), "{wrong:?}");
    }

    /// A 2 MiB chunk of userfaultfd-registered guest RAM discarded whole,
    /// its section swapped (`libc::windows_mm::uffd_swap_chunk`), while a
    /// vCPU and a host thread use it: neither ever sees memory that is not
    /// the handler's fill or the writer's own, and the writer's write reads
    /// back. The guest's RAM (4 MiB) registered before the VM maps it, as
    /// Firecracker registers it; a handler thread fills each faulted page
    /// with qwords `0xF << 60 | round`; the host writer writes `0xA << 60 |
    /// seq` to the first qword of pages of the chunk and reads it back
    /// (checked when no discard overlapped the two); the guest, asked by
    /// round through a mailbox, reads every page's first qword of the chunk
    /// (GPA 2-4 MiB) and counts those that are neither (`bad`), and the
    /// least fill round it saw. Each of `ROUNDS` rounds: the fill round set,
    /// the scan asked for, and the chunk discarded at once, racing the scan
    /// and the writer; then `bad` 0 and the least round at least the one
    /// before. Last, with the writer stopped, a discard and a scan that see
    /// only this round's fill. Asserted; SWAPSTRESS lines.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_chunk_swapped_under_a_vcpu_and_a_host_writer_keeps_their_memory() {
        use std::sync::atomic::{AtomicBool, AtomicU64};
        const MAILBOX: u64 = 0x7000;
        const CHUNK: u64 = 2 << 20;
        const ROUNDS: u64 = 100;
        const FILL: u64 = 0xF << 60;
        const WRITE: u64 = 0xA << 60;
        // The scan (see the doc), at MMIO_PROGRAM; `out 0x85` after each,
        // `out 0x86` once the mailbox says to quit.
        const SCAN: [u8; 147] = [
            0x48, 0x8B, 0x04, 0x25, 0x28, 0x70, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x04, 0xE6, 0x86, 0xEB, 0xFC, 0x48,
            0x8B, 0x04, 0x25, 0x00, 0x70, 0x00, 0x00, 0x48, 0x3B, 0x04, 0x25, 0x08, 0x70, 0x00, 0x00, 0x74, 0xDD, 0xBB,
            0x00, 0x00, 0x20, 0x00, 0x31, 0xC9, 0x45, 0x31, 0xC0, 0x48, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x8B,
            0x33, 0x48, 0x89, 0xF7, 0x48, 0xC1, 0xEF, 0x3C, 0x83, 0xFF, 0x0F, 0x75, 0x0C, 0x89, 0xF7, 0x48, 0x39, 0xD7,
            0x73, 0x12, 0x48, 0x89, 0xFA, 0xEB, 0x0D, 0x83, 0xFF, 0x0A, 0x75, 0x05, 0x49, 0xFF, 0xC0, 0xEB, 0x03, 0x48,
            0xFF, 0xC1, 0x48, 0x81, 0xC3, 0x00, 0x10, 0x00, 0x00, 0x48, 0x81, 0xFB, 0x00, 0x00, 0x40, 0x00, 0x72, 0xC8,
            0x48, 0x89, 0x0C, 0x25, 0x10, 0x70, 0x00, 0x00, 0x48, 0x89, 0x14, 0x25, 0x18, 0x70, 0x00, 0x00, 0x4C, 0x89,
            0x04, 0x25, 0x20, 0x70, 0x00, 0x00, 0x48, 0x89, 0x04, 0x25, 0x08, 0x70, 0x00, 0x00, 0xE6, 0x85, 0xE9, 0x6D,
            0xFF, 0xFF, 0xFF,
        ];
        let say = |l: String| eprintln!("SWAPSTRESS {l}");
        let mut uffd = None;
        let (vm, vcpu, m) = mmio_guest_with(&SCAN, |m| {
            // The mailbox resident (written), so it is not missing.
            put(m, MAILBOX, &[0u8; 64]);
            let (ctx, user) = libc::wick_uffd::create(0, false, true).unwrap();
            libc::wick_uffd::register(ctx, m as u64, MEM as u64).unwrap();
            uffd = Some((ctx, user));
        });
        let (ctx, user) = uffd.unwrap();
        let at = m as usize;
        let chunk = at as u64 + CHUNK;
        // SAFETY: guest memory, mapped until the end.
        let mailbox = move |i: u64| unsafe { &*((at + (MAILBOX + 8 * i) as usize) as *const AtomicU64) };
        let fill_round = Arc::new(AtomicU64::new(0));
        // Odd while a discard runs.
        let discards = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        // The handler: each page fault filled with this round's qwords.
        let handler = {
            let fill_round = Arc::clone(&fill_round);
            std::thread::spawn(move || {
                let mut faults = 0u64;
                let mut rec = [0u8; libc::wick_uffd::proto::RECORD];
                loop {
                    let mut got = 0;
                    while got < rec.len() {
                        // SAFETY: a buffer of the length given.
                        let n = unsafe { libc::read(user, rec[got..].as_mut_ptr().cast(), rec.len() - got) };
                        if n <= 0 {
                            return faults;
                        }
                        got += n.unsigned_abs();
                    }
                    let word = |i: usize| u64::from_le_bytes(rec[i * 8..i * 8 + 8].try_into().unwrap());
                    if word(0) != libc::wick_uffd::proto::EVENT_PAGEFAULT {
                        continue;
                    }
                    let page = word(1) & !0xfff;
                    let v = FILL | fill_round.load(Ordering::SeqCst);
                    let data: Vec<u8> = std::iter::repeat_n(v.to_le_bytes(), 512).flatten().collect();
                    // SAFETY: a page-sized buffer; EEXIST if another fill came first.
                    let _ = unsafe { libc::wick_uffd::copy(ctx, data.as_ptr(), page, 4096, true) };
                    faults += 1;
                }
            })
        };
        // The host writer.
        let writer = {
            let (discards, stop) = (Arc::clone(&discards), Arc::clone(&stop));
            std::thread::spawn(move || {
                let (mut writes, mut lost) = (0u64, Vec::new());
                let mut seq = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    seq += 1;
                    let page = chunk + (seq * 37 % 512) * 4096;
                    let before = discards.load(Ordering::SeqCst);
                    let v = WRITE | seq;
                    // SAFETY: guest RAM, mapped until the end; a missing page
                    // faults and waits for the handler's fill.
                    let back = unsafe {
                        std::ptr::write_volatile(page as *mut u64, v);
                        std::ptr::read_volatile(page as *const u64)
                    };
                    writes += 1;
                    if before % 2 == 0 && discards.load(Ordering::SeqCst) == before && back != v && lost.len() < 8 {
                        lost.push(format!("{:#x}: wrote {v:#x}, read {back:#x}", page - chunk));
                    }
                }
                (writes, lost)
            })
        };
        // The vCPU, scanning when asked.
        let runner = std::thread::spawn(move || {
            let mut vcpu = vcpu;
            let mut reads = 0;
            loop {
                let e = one_run(&mut vcpu, &[], &mut reads);
                if !e.starts_with("out 0x85") {
                    return e;
                }
            }
        });
        let discard = || {
            discards.fetch_add(1, Ordering::SeqCst);
            // SAFETY: the chunk of guest RAM, discarded.
            let r = unsafe { libc::madvise(chunk as *mut libc::c_void, CHUNK as usize, libc::MADV_DONTNEED) };
            discards.fetch_add(1, Ordering::SeqCst);
            assert_eq!(r, 0, "the chunk's discard");
        };
        // A scan of round `r`, asked for, with the chunk discarded at once if
        // `race`: (bad, least fill round, the writer's values seen).
        let scan = |r: u64, race: bool| {
            fill_round.store(r, Ordering::SeqCst);
            mailbox(0).store(r, Ordering::SeqCst);
            if race {
                discard();
            }
            let asked = std::time::Instant::now();
            while mailbox(1).load(Ordering::SeqCst) != r {
                assert!(asked.elapsed() < std::time::Duration::from_secs(20), "round {r}: the guest's scan did not end");
                std::thread::yield_now();
            }
            (mailbox(2).load(Ordering::SeqCst), mailbox(3).load(Ordering::SeqCst), mailbox(4).load(Ordering::SeqCst))
        };
        let begun = std::time::Instant::now();
        let mut problems = Vec::new();
        let mut written = 0;
        for r in 1..=ROUNDS {
            let (bad, least, seen) = scan(r, true);
            written += seen;
            if bad != 0 || least < r - 1 {
                problems.push(format!("round {r}: {bad} pages neither filled nor written, least fill round {least}"));
            }
        }
        stop.store(true, Ordering::SeqCst);
        let (writes, lost) = writer.join().unwrap();
        // Alone: a discard, then a scan that sees this round's fill only.
        discard();
        let (bad, least, seen) = scan(ROUNDS + 1, false);
        say(format!(
            "{ROUNDS} rounds in {:?}: the guest saw the writer's values {written} times, the writer wrote {writes} times, \
             its write not read back {} times {lost:?}; problems {problems:?}; alone: bad {bad}, least round {least}, the \
             writer's values {seen}",
            begun.elapsed(),
            lost.len()
        ));
        mailbox(5).store(1, Ordering::SeqCst);
        let end = runner.join().unwrap();
        // SAFETY: closes the user end: the handler's receive ends.
        unsafe { libc::close(user) };
        let faults = handler.join().unwrap();
        say(format!("the vCPU's last exit {end}; the handler filled {faults} faults"));
        assert!(problems.is_empty() && lost.is_empty(), "{problems:?} {lost:?}");
        assert_eq!((bad, least, seen), (0, ROUNDS + 1, 0), "the scan alone");
        assert!(end.starts_with("out 0x86"), "the vCPU ended with {end}");
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The local APIC state of `vp` in both of WHP's formats, as lines: the
    /// one the backend reads (`WHvGetVirtualProcessorInterruptControllerState`,
    /// which Learn calls deprecated, "a legacy format that packs the
    /// interrupt-request, in-service, and trigger-mode vectors differently
    /// from the standard external state format and does not include the
    /// processor priority register") and the standard one
    /// (`WHvGetVirtualProcessorState` of
    /// `WHvVirtualProcessorStateTypeInterruptControllerState2`): each call's
    /// HRESULT and size, the words `KVM_GET_LAPIC` carries at ID, TPR, PPR,
    /// SVR, ICR and LVT timer, the ISR, TMR and IRR words, and the
    /// offsets in the first KiB where the two differ.
    fn lapic_formats(what: &str, part: whv::WHV_PARTITION_HANDLE, vp: u32) -> Vec<String> {
        let mut legacy = vec![0u8; 4096];
        let mut legacy_size = 0u32;
        // SAFETY: an output buffer of the size passed.
        let legacy_hres = unsafe {
            whv::WHvGetVirtualProcessorInterruptControllerState(part, vp, legacy.as_mut_ptr().cast(), 4096, &mut legacy_size)
        };
        let mut need = 0u32;
        // SAFETY: a zero-sized query of the size needed.
        let _ = unsafe {
            whv::WHvGetVirtualProcessorState(
                part,
                vp,
                whv::WHvVirtualProcessorStateTypeInterruptControllerState2,
                std::ptr::null_mut(),
                0,
                &mut need,
            )
        };
        let mut two = vec![0u8; (need as usize).max(4096)];
        let mut two_size = 0u32;
        // SAFETY: an output buffer of the size passed.
        let two_hres = unsafe {
            whv::WHvGetVirtualProcessorState(
                part,
                vp,
                whv::WHvVirtualProcessorStateTypeInterruptControllerState2,
                two.as_mut_ptr().cast(),
                u32::try_from(two.len()).unwrap(),
                &mut two_size,
            )
        };
        let word = |b: &[u8], at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let eight = |b: &[u8], at: usize| (0..8).map(|i| format!("{:#x}", word(b, at + i * 16))).collect::<Vec<_>>().join(" ");
        let mut lines = vec![format!(
            "LAPICFMT {what}: legacy HRESULT {:#010x}, {legacy_size} bytes; InterruptControllerState2 HRESULT {:#010x}, {two_size} bytes (asked for {need})",
            legacy_hres.cast_unsigned(),
            two_hres.cast_unsigned()
        )];
        for (at, name) in [(0x20, "ID"), (0x30, "version"), (0x80, "TPR"), (0xA0, "PPR"), (0xF0, "SVR"), (0x300, "ICR low"), (0x310, "ICR high"), (0x320, "LVT timer")] {
            lines.push(format!("LAPICFMT {what}: {name} ({at:#x}): legacy {:#x}, State2 {:#x}", word(&legacy, at), word(&two, at)));
        }
        for (at, name) in [(0x100, "ISR"), (0x180, "TMR"), (0x200, "IRR")] {
            lines.push(format!("LAPICFMT {what}: {name} ({at:#x}..): legacy [{}], State2 [{}]", eight(&legacy, at), eight(&two, at)));
        }
        let differ: Vec<String> = (0..0x400).step_by(4).filter(|&at| word(&legacy, at) != word(&two, at)).map(|at| format!("{at:#x}")).collect();
        lines.push(format!("LAPICFMT {what}: the formats differ at {differ:?}"));
        lines
    }

    /// A record (X2APICREC lines) of what a partition whose local APIC WHP
    /// emulates as an x2APIC (`WHvX64LocalApicEmulationModeX2Apic`) gives a
    /// guest, for the choice between it and today's xAPIC partition (a
    /// Linux guest's KVM snapshot holds an x2APIC, APIC_BASE 0xfee00d00):
    /// - whether the partition is made, and APIC_BASE before and after the
    ///   guest sets x2APIC mode (WRMSR 0x1b of 0xfee00d00), through RDMSR
    ///   and KVM_GET_SREGS, and KVM_SET_SREGS of 0xfee00d00;
    /// - for each x2APIC register MSR the guest reads or writes (ID 0x802,
    ///   version 0x803, SVR 0x80f, TPR 0x808, LVT timer 0x832, TMICT 0x838,
    ///   TDCR 0x83e): done or #GP, the value read, and whether the access
    ///   came to the backend (an MSR exit) or WHP answered it;
    /// - interrupts: a self-IPI (0x83f), a fixed IPI to itself through the
    ///   ICR (0x830), the APIC timer in one-shot mode and HLT, the
    ///   TSC-deadline timer (LVT 0x40000|vector, WRMSR 0x6e0) and HLT, and an
    ///   MSI the backend injects: the exits until the program's end, the
    ///   handler's `out 0x81` for each interrupt taken, its EOI by WRMSR
    ///   0x80b;
    /// - KVM_GET_LAPIC in x2APIC mode: the ID (0x20), version (0x30), SVR
    ///   (0xf0), LVT timer (0x320) and ICR (0x300, 0x310) words, to compare
    ///   with KVM's format (Linux v6.1 lapic.c `kvm_apic_state_fixup`:
    ///   without KVM_X2APIC_API_USE_32BIT_IDS the x2APIC ID is kept as an
    ///   xAPIC ID, shifted to bits 24-31; the ICR's high half at 0x310), and
    ///   KVM_SET_LAPIC of what it read, read back.
    ///
    /// - the local APIC's state in both of WHP's formats (`lapic_formats`)
    ///   with an interrupt pending, here and on an xAPIC partition, first.
    ///
    /// Each line is printed as it is made. A program step that does not
    /// reach its end (`out 0x80`) is printed with where it stopped (a
    /// fault's vector, the instruction it was raised at and the registers;
    /// or the RIP a kick found), its timers are disarmed and the next step
    /// goes on: nothing here is asserted but the test's own setup. Both
    /// formats are read with the interrupt just requested and again after
    /// the vCPU ran (interrupts off), as WHP may show a request in the IRR
    /// only once the processor ran. Also printed: whether WHP offers its
    /// own TSC-deadline timer (`TscDeadlineTmrSupport`), which partitions
    /// are made without (`tscdeadline`), and what the guest's write of a
    /// TSC-deadline LVT timer entry does on the x2APIC partition; the exits
    /// WHP offers (`ExtendedVmExits`: its APIC write traps); this host's
    /// own CPUID (TSC-deadline and x2APIC in leaf 1, the hypervisor's
    /// frequency MSRs); and `WHvX64RegisterTscDeadline` read on the
    /// partition. First, on an xAPIC partition: who answers a guest's
    /// RDMSR and WRMSR of the x2APIC ID, EOI and LVT timer MSRs, with
    /// APIC_BASE.EXTD clear and after the guest's write of EXTD came to the
    /// backend through the `ApicBaseMsrWrite` exit (x2APIC mode kept by the
    /// backend: the B plan's option C). Then, on an x2APIC partition whose
    /// MSR action list holds the LVT timer (0x832) and the initial count
    /// (0x838), both actions Exit (the B plan's option B): who answers the
    /// guest's RDMSR and WRMSR of them, the TSC-deadline mode write among
    /// them, and of EOI and TDCR, left out of the list; and how much more a
    /// WRMSR the list traps takes than one WHP answers, over a guest loop.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_an_x2apic_partition_on_record() {
        {
            // An xAPIC partition, its APIC on and interrupts off, then
            // vector 0x41 requested and pending.
            // Read once right after the request and once after the vCPU
            // ran again (interrupts still off, to its `out 0x84`): whether
            // WHP shows a requested interrupt in the IRR before the
            // processor next runs.
            let (vm, mut vcpu, m) = mmio_guest(&[APIC_ON[..APIC_ON.len() - 1].to_vec(), vec![0xE6, PORT as u8, 0xE6, 0x84, 0xEB, 0xFE]].concat());
            let mut reads = 0;
            let end = one_run(&mut vcpu, &[], &mut reads);
            vcpu.shared.inner.inject_msi(0xFEE0_0000, 0x41);
            for l in lapic_formats(&format!("xAPIC partition, requested, not run since (run: {end})"), vcpu.part(), vcpu.vp()) {
                eprintln!("X2APICREC {l}");
            }
            let after = one_run(&mut vcpu, &[], &mut reads);
            for l in lapic_formats(&format!("xAPIC partition, requested, then run (run: {after})"), vcpu.part(), vcpu.vp()) {
                eprintln!("X2APICREC {l}");
            }
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }
        {
            // Option C's question (x2APIC mode kept by the backend on an
            // xAPIC partition): who answers a guest's x2APIC register MSRs
            // there, with APIC_BASE.EXTD clear, and after the guest's write
            // of EXTD came to the backend through the ApicBaseMsrWrite exit
            // (WHV_X64_MSR_EXIT_BITMAP bit 3), which the backend takes
            // without changing WHP's APIC_BASE.
            let vm = super::super::VmFd::create().unwrap();
            let m = guest();
            probes(m);
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
            vcpu.set_cpuid2(&regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap()).unwrap();
            start(&vcpu);
            let mut s = vcpu.get_sregs().unwrap();
            (s.idt.base, s.idt.limit) = (IDT, 16 * 14 - 1);
            vcpu.set_sregs(&s).unwrap();
            let came = || MSR_INTERCEPTS.with(std::cell::Cell::get);
            // As `probe`, but an end other than done, #GP or #UD is printed,
            // not a panic, so the records after it still run.
            let msr = |vcpu: &mut VcpuFd, index: u32, write: Option<u64>| -> String {
                let before = came();
                let (at, rax, rdx) = match write {
                    Some(v) => (WRMSR_AT, v & 0xFFFF_FFFF, v >> 32),
                    None => (RDMSR_AT, 0, 0),
                };
                vcpu.set_regs(&kvm_regs { rip: at, rsp: 0x9000, rflags: 2, rax, rcx: u64::from(index), rdx, ..Default::default() }).unwrap();
                let how = match run_to_a_line(vcpu).as_str() {
                    "exit IoOut port 0x80" => "done".to_string(),
                    "exit IoOut port 0x8d" => "#GP".to_string(),
                    "exit IoOut port 0x86" => "#UD".to_string(),
                    other => format!("ended by {other}"),
                };
                let r = vcpu.get_regs().unwrap();
                let by = if came() > before { "the backend (an MSR exit)" } else { "WHP" };
                match write {
                    Some(v) => format!("WRMSR {index:#x} of {v:#x}: {how}, answered by {by}"),
                    None => format!("RDMSR {index:#x}: {how}, {:#x}, answered by {by}", (r.rdx << 32) | (r.rax & 0xFFFF_FFFF)),
                }
            };
            let x2apic_msrs = |vcpu: &mut VcpuFd, when: &str| {
                for (index, write) in [(0x802u32, None), (0x80b, Some(0u64)), (0x832, None), (0x832, Some(0x1_0041u64))] {
                    eprintln!("X2APICREC xAPIC partition, {when}: {}", msr(vcpu, index, write));
                }
            };
            eprintln!("X2APICREC xAPIC partition: {}", msr(&mut vcpu, 0x1B, None));
            x2apic_msrs(&mut vcpu, "EXTD clear");
            let mut bitmap = 0u64;
            let mut written = 0u32;
            // SAFETY: a u64 output buffer of the size passed.
            let got = unsafe {
                whv::WHvGetPartitionProperty(vcpu.part(), whv::WHvPartitionPropertyCodeX64MsrExitBitmap, (&raw mut bitmap).cast(), 8, &mut written)
            };
            let with = bitmap | 1 << 3;
            // SAFETY: a u64 property value.
            let set = unsafe { super::super::ffi::set_partition_property(vcpu.part(), whv::WHvPartitionPropertyCodeX64MsrExitBitmap, &with) };
            eprintln!(
                "X2APICREC xAPIC partition: X64MsrExitBitmap read {:#010x} {bitmap:#x}, set with ApicBaseMsrWrite {with:#x}: {:?}",
                got.cast_unsigned(),
                set.map_err(|e| e.errno())
            );
            eprintln!("X2APICREC xAPIC partition: {}", msr(&mut vcpu, 0x1B, Some(0xFEE0_0D00)));
            eprintln!("X2APICREC xAPIC partition, after: {}", msr(&mut vcpu, 0x1B, None));
            x2apic_msrs(&mut vcpu, "EXTD written through the exit");
            // Option C's price: every x2APIC EOI (WRMSR 0x80b) is an MSR exit
            // the backend answers, where today's xAPIC EOI is WHP's. Timed
            // over a guest loop, against a WRMSR WHP answers on this
            // partition (PAT, 0x277): `mov ebx, ROUNDS; 1: mov ecx, index;
            // mov eax, value; xor edx, edx; wrmsr; dec ebx; jnz 1b; out; jmp $`.
            {
                const LOOP_AT: u64 = 0x7900;
                const ROUNDS: u32 = 1000;
                let mut timed = |index: u32, value: u32| -> (f64, u64, String) {
                    let mut code = vec![0xBB];
                    code.extend_from_slice(&ROUNDS.to_le_bytes());
                    code.push(0xB9);
                    code.extend_from_slice(&index.to_le_bytes());
                    code.push(0xB8);
                    code.extend_from_slice(&value.to_le_bytes());
                    code.extend_from_slice(&[0x31, 0xD2, 0x0F, 0x30, 0xFF, 0xCB, 0x75, 0xEE, 0xE6, PORT as u8, 0xEB, 0xFE]);
                    put(m, LOOP_AT, &code);
                    let (mut best, mut exits, mut end) = (f64::MAX, 0, String::new());
                    for _ in 0..5 {
                        vcpu.set_regs(&kvm_regs { rip: LOOP_AT, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                        let before = came();
                        let t = std::time::Instant::now();
                        end = run_to_a_line(&mut vcpu);
                        best = best.min(t.elapsed().as_secs_f64() * 1e6 / f64::from(ROUNDS));
                        exits = came() - before;
                    }
                    (best, exits, end)
                };
                let (eoi, eoi_exits, eoi_end) = timed(0x80B, 0);
                let (pat, pat_exits, pat_end) = timed(0x277, 0x0007_0406);
                eprintln!(
                    "X2APICREC xAPIC partition, option C's EOI: {ROUNDS} WRMSRs in a guest loop, the least of 5 runs: of 0x80b \
                     {eoi:.3} us each, {eoi_exits} MSR exits, {eoi_end}; of 0x277 (WHP's) {pat:.3} us each, {pat_exits} MSR exits, \
                     {pat_end}; an EOI through the backend costs {:.3} us more",
                    eoi - pat
                );
            }
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }
        {
            // Option B's question: MSRACTION took 0x832, 0x838 and 0x80b in an
            // x2APIC partition's MSR action list on the PC (43832df). With the
            // LVT timer (0x832) and the initial count (0x838) in the list,
            // both actions Exit, who answers a guest's RDMSR and WRMSR of
            // them, the TSC-deadline mode write WHP's x2APIC refuses with #GP
            // among them, and what a WRMSR the list traps costs against one
            // WHP answers (TDCR, 0x83e). EOI (0x80b) is left out: Linux writes
            // it at the end of every interrupt, which an exit would slow.
            const LOOP_AT: u64 = 0x7900;
            const ROUNDS: u32 = 1000;
            super::super::vm::APIC_MODE_FOR_TESTS.set(Some(whv::WHvX64LocalApicEmulationModeX2Apic));
            super::super::vm::MSR_ACTIONS_FOR_TESTS.set(&[0x832, 0x838]);
            let made = super::super::VmFd::create();
            super::super::vm::MSR_ACTIONS_FOR_TESTS.set(&[]);
            super::super::vm::APIC_MODE_FOR_TESTS.set(None);
            match made {
                Err(e) => eprintln!(
                    "X2APICREC listed: the x2APIC partition with 0x832 and 0x838 in its MSR action list is not made: errno {} \
                     (the whp: line above has the HRESULT)",
                    e.errno()
                ),
                Ok(vm) => {
                    let m = guest();
                    probes(m);
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
                    vcpu.set_cpuid2(&regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap()).unwrap();
                    start(&vcpu);
                    let mut s = vcpu.get_sregs().unwrap();
                    (s.idt.base, s.idt.limit) = (IDT, 16 * 14 - 1);
                    vcpu.set_sregs(&s).unwrap();
                    let came = || MSR_INTERCEPTS.with(std::cell::Cell::get);
                    let msr = |vcpu: &mut VcpuFd, index: u32, write: Option<u64>| -> String {
                        let before = came();
                        let (at, rax, rdx) = match write {
                            Some(v) => (WRMSR_AT, v & 0xFFFF_FFFF, v >> 32),
                            None => (RDMSR_AT, 0, 0),
                        };
                        vcpu.set_regs(&kvm_regs { rip: at, rsp: 0x9000, rflags: 2, rax, rcx: u64::from(index), rdx, ..Default::default() })
                            .unwrap();
                        let how = match run_to_a_line(vcpu).as_str() {
                            "exit IoOut port 0x80" => "done".to_string(),
                            "exit IoOut port 0x8d" => "#GP".to_string(),
                            "exit IoOut port 0x86" => "#UD".to_string(),
                            other => format!("ended by {other}"),
                        };
                        let r = vcpu.get_regs().unwrap();
                        let by = if came() > before { "the backend (an MSR exit)" } else { "WHP" };
                        match write {
                            Some(v) => format!("WRMSR {index:#x} of {v:#x}: {how}, answered by {by}"),
                            None => format!("RDMSR {index:#x}: {how}, {:#x}, answered by {by}", (r.rdx << 32) | (r.rax & 0xFFFF_FFFF)),
                        }
                    };
                    for (index, write) in [
                        (0x1Bu32, None),
                        (0x1B, Some(0xFEE0_0D00u64)),
                        (0x1B, None),
                        (0x832, None),
                        (0x832, Some(0x4_0041)),
                        (0x832, None),
                        (0x832, Some(0x1_0041)),
                        (0x832, None),
                        (0x838, None),
                        (0x838, Some(0x1000)),
                        (0x838, None),
                        (0x839, None),
                        (0x80B, Some(0)),
                        (0x83E, Some(0xB)),
                        (0x83E, None),
                    ] {
                        eprintln!("X2APICREC listed: {}", msr(&mut vcpu, index, write));
                    }
                    // `mov ebx, ROUNDS; 1: mov ecx, index; mov eax, value;
                    // xor edx, edx; wrmsr; dec ebx; jnz 1b; out PORT, al; jmp $`
                    let timed = |vcpu: &mut VcpuFd, index: u32, value: u32| -> (f64, u64, String) {
                        let mut code = vec![0xBB];
                        code.extend_from_slice(&ROUNDS.to_le_bytes());
                        code.push(0xB9);
                        code.extend_from_slice(&index.to_le_bytes());
                        code.push(0xB8);
                        code.extend_from_slice(&value.to_le_bytes());
                        code.extend_from_slice(&[0x31, 0xD2, 0x0F, 0x30, 0xFF, 0xCB, 0x75, 0xEE, 0xE6, PORT as u8, 0xEB, 0xFE]);
                        put(m, LOOP_AT, &code);
                        let mut best = f64::MAX;
                        let mut exits = 0;
                        let mut end = String::new();
                        for _ in 0..5 {
                            vcpu.set_regs(&kvm_regs { rip: LOOP_AT, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                            let before = came();
                            let t = std::time::Instant::now();
                            end = run_to_a_line(vcpu);
                            let us = t.elapsed().as_secs_f64() * 1e6 / f64::from(ROUNDS);
                            exits = came() - before;
                            best = best.min(us);
                        }
                        (best, exits, end)
                    };
                    let (listed, listed_exits, listed_end) = timed(&mut vcpu, 0x832, 0x1_0041);
                    let (whp, whp_exits, whp_end) = timed(&mut vcpu, 0x83E, 0xB);
                    eprintln!(
                        "X2APICREC listed: {ROUNDS} WRMSRs in a guest loop, the least of 5 runs: of 0x832 (listed) {listed:.3} us each, \
                         {listed_exits} MSR exits, {listed_end}; of 0x83e (WHP's) {whp:.3} us each, {whp_exits} MSR exits, {whp_end}; \
                         a listed WRMSR costs {:.3} us more",
                        listed - whp
                    );
                    drop(vcpu);
                    drop(vm);
                    // SAFETY: the test's mapping, no VM left using it.
                    assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
                }
            }
        }
        const VECTOR: u32 = 0x41;
        const HANDLER: u64 = 0x7A00;
        const PROGRAM: u64 = 0x7B00;
        // Each line is printed as it is made, so a later step that fails
        // or hangs leaves the earlier ones.
        let say = |l: String| eprintln!("X2APICREC {l}");
        super::super::vm::APIC_MODE_FOR_TESTS.set(Some(whv::WHvX64LocalApicEmulationModeX2Apic));
        let made = super::super::VmFd::create();
        super::super::vm::APIC_MODE_FOR_TESTS.set(None);
        let vm = match made {
            Ok(vm) => vm,
            Err(e) => {
                eprintln!("X2APICREC the x2APIC partition is not made: errno {} (the whp: line above has the HRESULT)", e.errno());
                return;
            }
        };
        say("the x2APIC partition is made".to_string());
        // Whether this host's WHP offers its own TSC-deadline timer
        // (`TscDeadlineTmrSupport`, bank 1 bit 17), which every partition
        // is made without (`tscdeadline`).
        {
            let mut cap = whv::WHV_PROCESSOR_FEATURES_BANKS::default();
            let mut written = 0u32;
            // SAFETY: an output buffer of the size passed.
            let hres = unsafe {
                whv::WHvGetCapability(
                    whv::WHvCapabilityCodeProcessorFeaturesBanks,
                    (&raw mut cap).cast(),
                    u32::try_from(core::mem::size_of_val(&cap)).unwrap(),
                    &mut written,
                )
            };
            // SAFETY: plain data.
            let bank1 = unsafe { cap.Anonymous.AsUINT64[1] };
            say(format!(
                "WHvGetCapability(ProcessorFeaturesBanks): HRESULT {:#010x}, {} banks, TscDeadlineTmrSupport {}",
                hres.cast_unsigned(),
                cap.BanksCount,
                bank1 >> 17 & 1
            ));
            // The exits WHP can be asked for: the APIC write traps it has
            // (Learn, WHV_EXTENDED_VM_EXITS: LINT0, LINT1, SVR, LDR, DFR;
            // none for the LVT timer).
            let mut exits = 0u64;
            // SAFETY: a u64 output buffer of the size passed.
            let hres = unsafe { whv::WHvGetCapability(whv::WHvCapabilityCodeExtendedVmExits, (&raw mut exits).cast(), 8, &mut written) };
            let names = [
                "X64CpuidExit", "X64MsrExit", "ExceptionExit", "X64RdtscExit", "X64ApicSmiExitTrap", "HypercallExit",
                "X64ApicInitSipiExitTrap", "X64ApicWriteLint0ExitTrap", "X64ApicWriteLint1ExitTrap", "X64ApicWriteSvrExitTrap",
                "UnknownSynicConnection", "RetargetUnknownVpciDevice", "X64ApicWriteLdrExitTrap", "X64ApicWriteDfrExitTrap",
                "GpaAccessFaultExit",
            ];
            let set: Vec<&str> = names.iter().enumerate().filter(|(i, _)| exits >> i & 1 != 0).map(|(_, n)| *n).collect();
            say(format!("WHvGetCapability(ExtendedVmExits): HRESULT {:#010x}, {exits:#x}: {set:?}", hres.cast_unsigned()));
            // What this host's own partition is given by its hypervisor: on
            // a PC the root partition, on a cloud runner a guest of Hyper-V
            // (whether Hyper-V offers its guests the TSC-deadline timer, and
            // the frequency MSRs Linux reads the APIC timer's rate from on
            // Hyper-V, arch/x86/kernel/cpu/mshyperv.c:355-366 at v6.1).
            use core::arch::x86_64::__cpuid;
            let leaf1 = __cpuid(1).ecx;
            let hv = __cpuid(0x4000_0000);
            let vendor: Vec<u8> = [hv.ebx, hv.ecx, hv.edx].iter().flat_map(|r| r.to_le_bytes()).collect();
            let privileges = if hv.eax >= 0x4000_0003 { Some(__cpuid(0x4000_0003)) } else { None };
            say(format!(
                "this host's own CPUID: leaf 1 ECX TSC-deadline (bit 24) {}, x2APIC (bit 21) {}; hypervisor {:?}; \
                 leaf 0x40000003 AccessFrequencyMsrs (EAX bit 11) {:?}, frequencies available (EDX bit 8) {:?}",
                leaf1 >> 24 & 1,
                leaf1 >> 21 & 1,
                String::from_utf8_lossy(&vendor),
                privileges.map(|p| p.eax >> 11 & 1),
                privileges.map(|p| p.edx >> 8 & 1)
            ));
        }
        let m = guest();
        probes(m);
        let wrmsr = |index: u32, value: u64| {
            let mut b = vec![0xB9];
            b.extend_from_slice(&index.to_le_bytes()); // mov ecx, index
            b.push(0xB8);
            b.extend_from_slice(&(value as u32).to_le_bytes()); // mov eax, low
            b.push(0xBA);
            b.extend_from_slice(&((value >> 32) as u32).to_le_bytes()); // mov edx, high
            b.extend_from_slice(&[0x0F, 0x30]); // wrmsr
            b
        };
        // The handler: `out 0x81, al`, EOI through the x2APIC MSR, return.
        put(
            m,
            HANDLER,
            &[
                vec![0x50, 0x51, 0x52, 0xE6, 0x81], // push rax, rcx, rdx; out 0x81, al
                wrmsr(0x80B, 0),
                vec![0x5A, 0x59, 0x58, 0x48, 0xCF], // pop rdx, rcx, rax; iretq
            ]
            .concat(),
        );
        let gate = (HANDLER & 0xFFFF) | (8 << 16) | (0x8E << 40) | (((HANDLER >> 16) & 0xFFFF) << 48);
        put(m, IDT + u64::from(VECTOR) * 16, &gate.to_le_bytes());
        put(m, IDT + u64::from(VECTOR) * 16 + 8, &(HANDLER >> 32).to_le_bytes());
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
        // The supported CPUID: WHP never sees the table (every guest CPUID
        // is an exit the backend answers), so what WHP does with a guest's
        // EXTD below is the partition's alone; a table with x2APIC is
        // refused on today's xAPIC partitions (`apicmode`).
        vcpu.set_cpuid2(&regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap()).unwrap();
        start(&vcpu);
        let mut s = vcpu.get_sregs().unwrap();
        (s.idt.base, s.idt.limit) = (IDT, (u64::from(VECTOR) * 16 + 15) as u16);
        vcpu.set_sregs(&s).unwrap();
        say(format!("APIC_BASE through KVM_GET_SREGS at the start: {:#x}", vcpu.get_sregs().unwrap().apic_base));

        let came = || MSR_INTERCEPTS.with(std::cell::Cell::get);
        let msr = |vcpu: &mut VcpuFd, what: &str, index: u32, write: Option<u64>| -> String {
            let before = came();
            let (how, r) = match write {
                Some(v) => probe(vcpu, WRMSR_AT, v & 0xFFFF_FFFF, u64::from(index), v >> 32),
                None => probe(vcpu, RDMSR_AT, 0, u64::from(index), 0),
            };
            let value = (r.rdx << 32) | (r.rax & 0xFFFF_FFFF);
            let by = if came() > before { "the backend (an MSR exit)" } else { "WHP" };
            match write {
                Some(v) => format!("WRMSR {index:#x} ({what}) of {v:#x}: {how}, answered by {by}"),
                None => format!("RDMSR {index:#x} ({what}): {how}, {value:#x}, answered by {by}"),
            }
        };
        say(msr(&mut vcpu, "APIC_BASE", 0x1B, None));
        say(msr(&mut vcpu, "APIC_BASE, x2APIC on", 0x1B, Some(0xFEE0_0D00)));
        say(msr(&mut vcpu, "APIC_BASE", 0x1B, None));
        say(format!("APIC_BASE through KVM_GET_SREGS after: {:#x}", vcpu.get_sregs().unwrap().apic_base));
        let mut s = vcpu.get_sregs().unwrap();
        s.apic_base = 0xFEE0_0D00;
        say(format!("KVM_SET_SREGS with APIC_BASE 0xfee00d00: {:?}", vcpu.set_sregs(&s).map_err(|e| e.errno())));
        say(msr(&mut vcpu, "ID", 0x802, None));
        say(msr(&mut vcpu, "version", 0x803, None));
        say(msr(&mut vcpu, "SVR", 0x80F, None));
        say(msr(&mut vcpu, "SVR, enabled", 0x80F, Some(0x1FF)));
        say(msr(&mut vcpu, "TPR", 0x808, Some(0)));
        say(msr(&mut vcpu, "TPR", 0x808, None));
        say(msr(&mut vcpu, "TDCR", 0x83E, Some(0xB)));
        say(msr(&mut vcpu, "TDCR", 0x83E, None));
        say(msr(&mut vcpu, "LVT timer, one-shot", 0x832, Some(u64::from(VECTOR))));
        say(msr(&mut vcpu, "LVT timer, TSC-deadline mode", 0x832, Some(0x4_0000 | u64::from(VECTOR))));
        say(msr(&mut vcpu, "LVT timer", 0x832, None));
        say(msr(&mut vcpu, "IA32_TSC_DEADLINE, 0", 0x6E0, Some(0)));
        say(msr(&mut vcpu, "IA32_TSC_DEADLINE", 0x6E0, None));
        // The register a WHP TSC-deadline timer's deadline would be saved
        // and restored through (WinHvPlatformDefs.h's
        // WHvX64RegisterTscDeadline, 0x2095), on this partition made
        // without the timer.
        say(format!(
            "WHvX64RegisterTscDeadline: {:?}",
            super::super::ffi::get_register(vcpu.part(), vcpu.vp(), whv::WHvX64RegisterTscDeadline)
                .map(|v| super::super::ffi::as_u64(&v))
                .map_err(|e| e.errno())
        ));

        // Interrupts, each a program to its `out 0x80`.
        let end = [0xE6, PORT as u8, 0xEB, 0xFE];
        let programs: Vec<(&str, Vec<u8>)> = vec![
            ("a self-IPI (0x83f)", [vec![0xFB], wrmsr(0x83F, u64::from(VECTOR)), vec![0x90, 0x90], end.to_vec()].concat()),
            ("a fixed IPI to itself through the ICR (0x830, destination 0)", [vec![0xFB], wrmsr(0x830, u64::from(VECTOR)), vec![0x90, 0x90], end.to_vec()].concat()),
            (
                "the APIC timer, one shot of 0x10000 counts, and HLT",
                [vec![0xFB], wrmsr(0x832, u64::from(VECTOR)), wrmsr(0x838, 0x1_0000), vec![0xF4], end.to_vec()].concat(),
            ),
            (
                "the TSC-deadline timer (LVT 0x40000|vector, WRMSR 0x6e0 of the TSC plus 0x1000000) and HLT",
                [
                    vec![0xFB],
                    wrmsr(0x838, 0),
                    wrmsr(0x832, 0x4_0000 | u64::from(VECTOR)),
                    vec![
                        0x0F, 0x31, // rdtsc
                        0x05, 0x00, 0x00, 0x00, 0x01, // add eax, 0x1000000
                        0x83, 0xD2, 0x00, // adc edx, 0
                        0xB9, 0xE0, 0x06, 0x00, 0x00, // mov ecx, 0x6e0
                        0x0F, 0x30, // wrmsr
                        0xF4, // hlt
                    ],
                    end.to_vec(),
                ]
                .concat(),
            ),
            ("an MSI the backend injects, then HLT", [vec![0xFB, 0xF4], end.to_vec()].concat()),
        ];
        for (name, code) in &programs {
            put(m, PROGRAM, code);
            vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
            let watchdog = super::Watchdog::arm(&vcpu);
            let mut reads = 0;
            let mut exits = Vec::new();
            if name.starts_with("an MSI") {
                vcpu.shared.inner.inject_msi(0xFEE0_0000, VECTOR);
            }
            while exits.len() < 8 {
                let line = one_run(&mut vcpu, &[], &mut reads);
                let done = line.starts_with("out 0x80") || line == "EINTR" || line.starts_with("run failed") || line == "InternalError";
                exits.push(line);
                if done {
                    break;
                }
            }
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            say(format!("{name}: exits {exits:?}"));
            if exits.last().unwrap().starts_with("out 0x80") {
                continue;
            }
            // Not to its end: where it stopped, then the next step on a
            // vCPU with no timer left armed. The #GP handler (`probes`)
            // spins at its `out`, so the frame is the fault's: RSP was
            // 0x9000, so the error code is at 0x8fd0 and RIP at 0x8fd8.
            let r = vcpu.get_regs().unwrap();
            let fault = exits.iter().any(|e| e.starts_with("out 0x8d") || e.starts_with("out 0x86"));
            let at = if fault {
                let rip = u64::from_le_bytes(bytes_at::<8>(m, 0x8FD8));
                format!(
                    "a fault ({}): RIP pushed {rip:#x} (the program's byte {:#x}, {:02x?}), error code {:#x}, RAX {:#x} RCX {:#x} RDX {:#x}",
                    if exits.iter().any(|e| e.starts_with("out 0x8d")) { "#GP" } else { "#UD" },
                    rip.wrapping_sub(PROGRAM),
                    if rip < MEM as u64 - 2 { bytes_at::<2>(m, rip) } else { [0xEE; 2] },
                    u64::from_le_bytes(bytes_at::<8>(m, 0x8FD0)),
                    r.rax,
                    r.rcx,
                    r.rdx
                )
            } else {
                format!("RIP {:#x} (the program's byte {:#x}), RFLAGS {:#x}", r.rip, r.rip.wrapping_sub(PROGRAM), r.rflags)
            };
            say(format!("{name}: did not reach its end; stopped at {at}"));
            say(msr(&mut vcpu, "IA32_TSC_DEADLINE, disarmed", 0x6E0, Some(0)));
            say(msr(&mut vcpu, "TMICT, stopped", 0x838, Some(0)));
            say(msr(&mut vcpu, "LVT timer, masked", 0x832, Some(0x1_0000 | u64::from(VECTOR))));
        }

        // KVM_GET_LAPIC in x2APIC mode, and KVM_SET_LAPIC of it.
        let word = |page: &kvm_bindings::kvm_lapic_state, offset: usize| {
            u32::from_le_bytes(std::array::from_fn(|i| page.regs[offset + i].cast_unsigned()))
        };
        match vcpu.get_lapic() {
            Ok(page) => {
                say(format!(
                    "KVM_GET_LAPIC: ID {:#x}, version {:#x}, SVR {:#x}, LVT timer {:#x}, ICR {:#x} {:#x}",
                    word(&page, 0x20),
                    word(&page, 0x30),
                    word(&page, 0xF0),
                    word(&page, 0x320),
                    word(&page, 0x300),
                    word(&page, 0x310)
                ));
                let set = vcpu.set_lapic(&page).map_err(|e| e.errno());
                let back = vcpu.get_lapic().map(|b| b.regs == page.regs).map_err(|e| e.errno());
                say(format!("KVM_SET_LAPIC of it: {set:?}; read back the same: {back:?}"));
            }
            Err(e) => say(format!("KVM_GET_LAPIC: errno {}", e.errno())),
        }
        // Both state formats, with vector VECTOR pending (interrupts off,
        // the vCPU not run after the request).
        let mut r = vcpu.get_regs().unwrap();
        r.rflags = 2;
        vcpu.set_regs(&r).unwrap();
        vcpu.shared.inner.inject_msi(0xFEE0_0000, VECTOR);
        for l in lapic_formats("x2APIC partition, requested, not run since", vcpu.part(), vcpu.vp()) {
            say(l);
        }
        put(m, PROGRAM, &[0xE6, 0x84, 0xEB, 0xFE]);
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
        let watchdog = super::Watchdog::arm(&vcpu);
        let after = one_run(&mut vcpu, &[], &mut 0);
        drop(watchdog);
        vcpu.set_kvm_immediate_exit(0);
        for l in lapic_formats(&format!("x2APIC partition, requested, then run (run: {after})"), vcpu.part(), vcpu.vp()) {
            say(l);
        }
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The record for the B plan's option E (GPEXITREC lines): an x2APIC
    /// partition (as KVM's, which a Linux guest's snapshot needs) where
    /// WHP's own x2APIC refuses the TSC-deadline mode of the LVT timer with
    /// #GP (X2APICREC: WRMSR 0x832 of 0x40041 is #GP, answered by WHP, and
    /// an MSR action list for 0x832 is taken but never exits, the PC and CI
    /// at 87d0328). E would take the guest's #GP as an exception exit
    /// (`ExtendedVmExits` ExceptionExit, vector 13 in the exception exit
    /// bitmap), emulate that one WRMSR, and give every other #GP back to
    /// the guest unchanged, as KVM gives back an exception it intercepts.
    ///
    /// Until 81072df this record never set APIC_BASE.EXTD, which
    /// X2APICREC's guest writes first (0xfee00d00), so its WRMSR 0x832 was
    /// one with the local APIC in xAPIC mode: WHP gave it to the backend as
    /// an MSR exit (reason 0x1000, `WHvRunVpExitReasonX64MsrAccess`, not
    /// an exception's 0x1002), which skipped it, and the loop's "#GP"s were
    /// MSR exits, 9.8 us each with the bitmap empty or not (the PC at
    /// 81072df). Now a matrix, a partition each: APIC_BASE.EXTD clear or
    /// set by the guest, ExceptionExit off or on, vector 13 in the bitmap
    /// or not (only with ExceptionExit). Printed for each cell:
    /// - who answers the guest's WRMSR 0x832 of 0x40041 (WHP or the
    ///   backend, by the backend's MSR exit count) and how it ends (done,
    ///   the guest's #GP handler, or an exception exit), with WHP's exits;
    /// - where it is an exception exit: that #GP given back
    ///   (`WHvRegisterPendingInterruption`, an exception with its error
    ///   code, RIP at the WRMSR), the next run's exits and the error code
    ///   on the handler's stack;
    /// - the cost: 1000 such WRMSRs in a guest loop whose #GP handler skips
    ///   the WRMSR and returns, each exception exit given back as above:
    ///   the time a WRMSR, the MSR exits and the exception exits.
    ///
    /// Nothing is asserted but the test's own setup.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_gp_exits_on_an_x2apic_partition_on_record() {
        const EXCEPTION_EXIT: u64 = 1 << 2;
        const GP: u64 = 13;
        const LOOP_AT: u64 = 0x7900;
        const SKIP_AT: u64 = 0x7880;
        const ROUNDS: u32 = 1000;
        let say = |l: String| eprintln!("GPEXITREC {l}");
        let mut offered = 0u64;
        let mut n = 0u32;
        // SAFETY: a u64 output buffer of the size passed.
        let hres = unsafe { whv::WHvGetCapability(whv::WHvCapabilityCodeExtendedVmExits, (&raw mut offered).cast(), 8, &mut n) };
        say(format!("ExtendedVmExits offered {:#010x} {offered:#x}: ExceptionExit {}", hres.cast_unsigned(), offered >> 2 & 1));
        let came = || MSR_INTERCEPTS.with(std::cell::Cell::get);
        // A #GP given back: pending, an exception (type 3) with its error
        // code (bit 4), the vector at bits 16-31, the code at 32-63.
        let give_back = |vcpu: &VcpuFd, code: u32| {
            let event = 1 | (3 << 1) | (1 << 4) | (GP << 16) | (u64::from(code) << 32);
            let r = super::super::ffi::set_register(vcpu.part(), vcpu.vp(), whv::WHvRegisterPendingInterruption, super::super::ffi::reg64(event));
            (event, r.map_err(|e| e.errno()))
        };
        for (extd, exception_exit, bitmap) in
            [(false, false, false), (false, true, false), (false, true, true), (true, false, false), (true, true, false), (true, true, true)]
        {
            let cell = format!(
                "APIC_BASE.EXTD {}, ExceptionExit {}, vector 13 {}in the bitmap",
                if extd { "set" } else { "clear" },
                if exception_exit { "on" } else { "off" },
                if bitmap { "" } else { "not " }
            );
            if exception_exit && offered & EXCEPTION_EXIT == 0 {
                say(format!("{cell}: ExceptionExit not offered, not run"));
                continue;
            }
            super::super::vm::APIC_MODE_FOR_TESTS.set(Some(whv::WHvX64LocalApicEmulationModeX2Apic));
            super::super::vm::EXTRA_EXITS_FOR_TESTS.set(if exception_exit { EXCEPTION_EXIT } else { 0 });
            let made = super::super::VmFd::create();
            super::super::vm::EXTRA_EXITS_FOR_TESTS.set(0);
            super::super::vm::APIC_MODE_FOR_TESTS.set(None);
            let vm = match made {
                Ok(vm) => vm,
                Err(e) => {
                    say(format!("{cell}: the x2APIC partition is not made: errno {}", e.errno()));
                    continue;
                }
            };
            let m = guest();
            probes(m);
            // #GP's other handler: drop the error code, step over the 2-byte
            // WRMSR, return (`add rsp, 8; add qword [rsp], 2; iretq`).
            put(m, SKIP_AT, &[0x48, 0x83, 0xC4, 0x08, 0x48, 0x83, 0x04, 0x24, 0x02, 0x48, 0xCF]);
            // SAFETY: the memory stays mapped while the VM has it.
            unsafe {
                vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                    slot: 0,
                    flags: 0,
                    guest_phys_addr: 0,
                    memory_size: MEM as u64,
                    userspace_addr: m as u64,
                })
            }
            .unwrap();
            let mut vcpu = vm.create_vcpu(0).unwrap();
            vcpu.set_cpuid2(&regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap()).unwrap();
            start(&vcpu);
            let mut s = vcpu.get_sregs().unwrap();
            (s.idt.base, s.idt.limit) = (IDT, 16 * 14 - 1);
            vcpu.set_sregs(&s).unwrap();
            let part = vcpu.part();
            if bitmap {
                let value: u64 = 1 << GP;
                // SAFETY: a u64 value for ExceptionExitBitmap; no vCPU runs.
                let r = unsafe { super::super::ffi::set_partition_property(part, whv::WHvPartitionPropertyCodeExceptionExitBitmap, &value) };
                if let Err(e) = r {
                    say(format!("{cell}: ExceptionExitBitmap {value:#x} refused: errno {}", e.errno()));
                }
            }
            if extd {
                // The guest's own WRMSR of APIC_BASE, as X2APICREC's and
                // Linux's x2apic_enable.
                vcpu.set_regs(&kvm_regs { rip: WRMSR_AT, rsp: 0x9000, rflags: 2, rax: 0xFEE0_0D00, rcx: 0x1B, ..Default::default() }).unwrap();
                let end = run_once(&mut vcpu);
                if end != "exit IoOut port 0x80" {
                    say(format!("{cell}: the guest's WRMSR of APIC_BASE 0xfee00d00 ended by {end}"));
                }
            }
            // The exits of one run, with their details, and how it ended.
            let traced = |vcpu: &mut VcpuFd| -> (String, Vec<String>) {
                super::super::ffi::trace::begin();
                let line = run_once(vcpu);
                let calls = super::super::ffi::trace::end();
                let exits = calls.iter().filter_map(|c| c.exit.map(|e| format!("reason {e:#x} ({})", c.detail))).collect();
                (line, exits)
            };
            let before = came();
            vcpu.set_regs(&kvm_regs { rip: WRMSR_AT, rsp: 0x9000, rflags: 2, rax: 0x4_0041, rcx: 0x832, ..Default::default() }).unwrap();
            let (line, exits) = traced(&mut vcpu);
            let by = if came() > before { "the backend (an MSR exit)" } else { "WHP" };
            let how = match line.as_str() {
                "exit IoOut port 0x80" => "done",
                "exit IoOut port 0x8d" => "the guest's #GP handler ran",
                "exit (another)" => "the run returned another exit (an exception exit is InternalError)",
                _ => "ended otherwise",
            };
            say(format!("{cell}: WRMSR 0x832 of 0x40041: {how} [{line}], answered by {by}; WHP's exits {exits:?}"));
            if extd && !bitmap {
                // The timer's other writes a Linux guest makes: one-shot and
                // periodic, TSC-deadline masked (lapic_timer_shutdown), the
                // initial count, the deadline.
                for (index, value) in [(0x832u32, 0x4_0041u64 | 1 << 16), (0x832, 0x0_0041), (0x832, 0x2_0041), (0x838, 0x1000), (0x6E0, 0)] {
                    let before = came();
                    vcpu.set_regs(&kvm_regs {
                        rip: WRMSR_AT,
                        rsp: 0x9000,
                        rflags: 2,
                        rax: value & 0xFFFF_FFFF,
                        rcx: u64::from(index),
                        rdx: value >> 32,
                        ..Default::default()
                    })
                    .unwrap();
                    let line = run_once(&mut vcpu);
                    let by = if came() > before { "the backend (an MSR exit)" } else { "WHP" };
                    say(format!("{cell}: WRMSR {index:#x} of {value:#x}: [{line}] (0x8d is the guest's #GP handler), answered by {by}"));
                }
            }
            if line == "exit (another)" {
                let r = vcpu.get_regs().unwrap();
                let (event, set) = give_back(&vcpu, 0);
                let (line, exits) = traced(&mut vcpu);
                let after = vcpu.get_regs().unwrap();
                // SAFETY: the stack page is the test's mapping; the
                // handler's frame is the error code then RIP.
                let (code, rip) = unsafe { (*(m.add(after.rsp as usize) as *const u64), *(m.add(after.rsp as usize + 8) as *const u64)) };
                say(format!(
                    "{cell}: at the exit RIP {:#x}; the #GP given back (PendingInterruption {event:#x}: {set:?}): the run gave \
                     [{line}] (out 0x8d is the guest's #GP handler); WHP's exits {exits:?}; the handler's frame: error code \
                     {code:#x}, RIP {rip:#x}",
                    r.rip
                ));
            }
            // The cost of such a WRMSR in a loop.
            let mut code = vec![0xBB];
            code.extend_from_slice(&ROUNDS.to_le_bytes());
            code.extend_from_slice(&[0xB9, 0x32, 0x08, 0x00, 0x00, 0xB8, 0x41, 0x00, 0x04, 0x00]);
            code.extend_from_slice(&[0x31, 0xD2, 0x0F, 0x30, 0xFF, 0xCB, 0x75, 0xEE, 0xE6, PORT as u8, 0xEB, 0xFE]);
            put(m, LOOP_AT, &code);
            let low = (SKIP_AT & 0xFFFF) | (8 << 16) | (0x8E << 40) | (((SKIP_AT >> 16) & 0xFFFF) << 48);
            put(m, IDT + GP * 16, &low.to_le_bytes());
            put(m, IDT + GP * 16 + 8, &(SKIP_AT >> 32).to_le_bytes());
            let mut best = f64::MAX;
            let (mut exceptions, mut msr_exits, mut end) = (0u32, 0u64, String::new());
            for _ in 0..3 {
                vcpu.set_regs(&kvm_regs { rip: LOOP_AT, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                let watchdog = super::Watchdog::arm(&vcpu);
                let msr_before = came();
                let t = std::time::Instant::now();
                exceptions = 0;
                end = loop {
                    match vcpu.run() {
                        Ok(VcpuExit::IoOut(PORT, _)) => break "the loop's end".to_string(),
                        Ok(VcpuExit::InternalError) if exceptions <= 2 * ROUNDS => {
                            exceptions += 1;
                            if let (_, Err(e)) = give_back(&vcpu, 0) {
                                break format!("the #GP not given back: errno {e}");
                            }
                        }
                        Ok(VcpuExit::IoOut(port, _)) => break format!("IoOut {port:#x}"),
                        Ok(VcpuExit::Shutdown) => break "Shutdown".to_string(),
                        Ok(_) => break "another exit".to_string(),
                        Err(e) if e.errno() == libc::EINTR => break "none within 5 s (kicked)".to_string(),
                        Err(e) => break format!("run failed, errno {}", e.errno()),
                    }
                };
                best = best.min(t.elapsed().as_secs_f64() * 1e6 / f64::from(ROUNDS));
                msr_exits = came() - msr_before;
                drop(watchdog);
                vcpu.set_kvm_immediate_exit(0);
                if end != "the loop's end" {
                    break;
                }
            }
            say(format!(
                "{cell}: {ROUNDS} WRMSRs 0x832 of 0x40041 in a guest loop (its #GP handler skips the WRMSR): the least of 3 \
                 runs {best:.3} us a WRMSR, {msr_exits} MSR exits, {exceptions} exception exits (each given back), ended by \
                 {end}"
            ));
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }
    }

    /// An expired TSC deadline's interrupt goes to its own vCPU, in x2APIC
    /// mode as in xAPIC mode: KVM raises it in the vCPU's own APIC (Linux
    /// v6.1 arch/x86/kvm/lapic.c, `kvm_apic_local_deliver`). WHP's register
    /// page holds an x2APIC-mode vCPU's ID as it is (X2E0REC c, CI run
    /// 43521200989: vCPU 1's read `0x1000000` in xAPIC mode and `0x1` once
    /// EXTD was set), so reading it in the xAPIC format (`>> 24`) sent
    /// vCPU 1's interrupt to APIC 0. On an x2APIC partition, a VM for each
    /// mode of vCPU 1 (made runnable), both vCPUs halted with interrupts on: a deadline
    /// already reached on vCPU 1 raises the LVT timer's vector, which vCPU
    /// 1 takes (its gate's `out 0x82` of the vector) and vCPU 0 does not
    /// (its run is kicked after 5 s). Seen by the guest taking it, as WHP
    /// shows no requested interrupt in the IRR of its page, before or after
    /// a run (X2APICREC's "requested" lines; CI run 43528910212 read
    /// neither vCPU's IRR set here).
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_deadline_interrupt_goes_to_its_own_vcpu_in_x2apic_mode() {
        use super::super::ffi;
        // Each vector's gate: `mov al, vector; out 0x82, al; jmp $`.
        const GATE: u64 = 0xB900;
        let set = |l: &mut kvm_lapic_state, at: usize, v: u32| {
            for (i, b) in v.to_le_bytes().into_iter().enumerate() {
                l.regs[at + i] = b as std::os::raw::c_char;
            }
        };
        // Software-enabled; for vCPU 1 the timer in TSC-deadline mode at
        // `vector`: in x2APIC mode as written (KVM_SET_LAPIC keeps the mode
        // in WHP's entry: X2E0REC g), in xAPIC mode as WHP shows it there
        // (one-shot with no count, `tscdeadline::deadline_mode`).
        let enable = |v: &VcpuFd, lvtt: Option<u32>| {
            let mut l = v.get_lapic().unwrap();
            set(&mut l, 0xf0, 0x1ff);
            if let Some(lvtt) = lvtt {
                set(&mut l, 0x320, lvtt);
                set(&mut l, 0x380, 0);
            }
            v.set_lapic(&l).unwrap();
        };
        for (x2apic, vector) in [(false, 0xecu32), (true, 0xed)] {
            // sti; hlt; jmp to the hlt
            super::super::vm::APIC_MODE_FOR_TESTS.set(Some(whv::WHvX64LocalApicEmulationModeX2Apic));
            let (vm, mut zero, m) = mmio_guest(&[0xFB, 0xF4, 0xEB, 0xFD]);
            super::super::vm::APIC_MODE_FOR_TESTS.set(None);
            let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
            #[allow(clippy::cast_possible_truncation)]
            put(m, GATE, &[0xB0, vector as u8, 0xE6, 0x82, 0xEB, 0xFE]);
            q(MMIO_IDT + u64::from(vector) * 16, (GATE & 0xffff) | (8 << 16) | (0x8E << 40));
            q(MMIO_IDT + u64::from(vector) * 16 + 8, 0);
            let mut one = vm.create_vcpu(1).unwrap();
            // Runnable: an AP is made waiting for a SIPI, as KVM makes one
            // (`regs::startup_suspend`; Linux v6.1 x86.c 11839-11842), and
            // takes no interrupt there; at f300dc7 its run entered no guest
            // and was kicked after 5 s (CI run 43534301411).
            one.set_mp_state(kvm_bindings::kvm_mp_state { mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE }).unwrap();
            // vCPU 0's state (long mode, the IDT) before EXTD: KVM_SET_SREGS
            // writes APIC_BASE.
            one.set_sregs(&zero.get_sregs().unwrap()).unwrap();
            one.set_regs(&kvm_regs { rip: MMIO_PROGRAM, rsp: 0x8800, rflags: 2, ..Default::default() }).unwrap();
            if x2apic {
                ffi::set_register(one.part(), one.vp(), whv::WHvX64RegisterApicBase, ffi::reg64(0xFEE0_0C00)).unwrap();
            }
            enable(&zero, None);
            enable(&one, Some(if x2apic { vector | 0x4_0000 } else { vector }));
            one.write_tsc_deadline(1).unwrap();
            let mut reads = 0;
            let watchdog = super::Watchdog::arm(&one);
            let by_one = one_run(&mut one, &[], &mut reads);
            drop(watchdog);
            one.set_kvm_immediate_exit(0);
            let watchdog = super::Watchdog::arm(&zero);
            let by_zero = one_run(&mut zero, &[], &mut reads);
            drop(watchdog);
            zero.set_kvm_immediate_exit(0);
            let taken = format!("out 0x82 [{vector:02x}]");
            eprintln!("DEADLINEID x2APIC mode {x2apic}: vector {vector:#x}: vCPU 1's run {by_one}; vCPU 0's run {by_zero}");
            assert!(
                by_one == taken && by_zero != taken,
                "x2APIC mode {x2apic}: vector {vector:#x}: vCPU 1's run {by_one}, vCPU 0's run {by_zero}"
            );
            drop(one);
            drop(zero);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }
    }

    /// The records E0 of option E (agent-state's x2apic-e-plan.md), before
    /// its code: an x2APIC partition whose #GPs leave the hypervisor
    /// (ExceptionExit, vector 13 in the exception exit bitmap), each case
    /// driven by `WHvRunVirtualProcessor` alone, so each exit's context is
    /// read as WHP gave it (X2E0REC lines). Printed:
    /// - e: the host's processor (CPUID vendor, brand, leaf 1 EAX), so a
    ///   run on an Intel host answers whether E holds there;
    /// - b: a #GP with an error code (DS loaded with a selector past the
    ///   GDT's limit; INT 0x41 past the IDT's limit), and what the guest's
    ///   handler finds when it is given back with the exit's error code;
    /// - a: a #GP raised while WHP delivers an event: an external interrupt
    ///   past the IDT's limit; a #GP past it (a #DF on a processor); and
    ///   then the #DF past it too (a triple fault): the exit's execution
    ///   state (InterruptionPending) and `WHvRegisterPendingInterruption`,
    ///   so whether the event being delivered is shown (KVM merges two
    ///   faults as `kvm_multiple_exception` does, Linux v6.1
    ///   arch/x86/kvm/x86.c:697-712); what giving back the #GP alone does,
    ///   and the #DF KVM would make of two contributory faults;
    /// - c: with APIC_BASE.EXTD clear, the guest's MMIO write of the LVT
    ///   timer in TSC-deadline mode and its read back, and an x2APIC MSR's
    ///   RDMSR; with EXTD set, the LVT timer written by the host through
    ///   `WHvX64RegisterApicLvtTimer` and through `KVM_SET_LAPIC`, read back
    ///   both ways and by the guest's RDMSR; and vCPU 1's APIC ID register
    ///   in the page the backend reads (`lapic_page`) and in
    ///   `WHvX64RegisterApicId`, in xAPIC mode and in x2APIC mode, as
    ///   `tscdeadline::deadline_interrupt` takes the destination from the
    ///   page in the xAPIC format (`>> 24`);
    /// - f: with EXTD clear, the guest's MMIO write of the LVT timer in each
    ///   mode (one-shot, masked, periodic, TSC-deadline) and its read, since
    ///   c's TSC-deadline write read back as the reset value, its vector
    ///   lost: what an xAPIC-mode guest of option E would get;
    /// - g: with EXTD set, the LVT timer in TSC-deadline mode with no initial
    ///   count written through `KVM_SET_LAPIC` (which c found taken, and
    ///   the guest's RDMSR then reads mode 10), the guest spinning for 5 s:
    ///   whether WHP's own timer raised the vector or counts, the guest's
    ///   read after, and the page's cost a write against the register's;
    /// - d: E's path for the TSC-deadline write: 1000 WRMSRs of 0x832 in
    ///   TSC-deadline mode in a guest loop, each exception exit answered
    ///   with the registers read (one call) and the LVT timer written in
    ///   one-shot mode with RIP past the WRMSR (one call), the least of 3
    ///   runs a WRMSR.
    ///
    /// Nothing is asserted but the test's own setup. CI runs it in a debug
    /// and in a release build.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_gp_exits_for_option_e_on_record() {
        use super::super::ffi;
        const GP: u64 = 13;
        const DF: u64 = 8;
        const DF_AT: u64 = 0x7860;
        const PROGRAM: u64 = 0x7A00;
        const LOOP_AT: u64 = 0x7900;
        const ROUNDS: u32 = 1000;
        let build = if cfg!(debug_assertions) { "debug build" } else { "release build" };
        let say = |l: String| eprintln!("X2E0REC {build}: {l}");

        /// An x2APIC partition with ExceptionExit and vector 13 in its
        /// exception exit bitmap; the probes' guest with a #DF handler
        /// (`out 0x88`) and the local APIC's page mapped; an IDT of
        /// `vectors` gates; the vCPU in long mode, after the guest's own
        /// write of APIC_BASE.EXTD if `extd`.
        fn e0_vm(extd: bool, vectors: u64) -> std::result::Result<(super::super::VmFd, VcpuFd, *mut u8), String> {
            super::super::vm::APIC_MODE_FOR_TESTS.set(Some(whv::WHvX64LocalApicEmulationModeX2Apic));
            super::super::vm::EXTRA_EXITS_FOR_TESTS.set(1 << 2);
            let made = super::super::VmFd::create();
            super::super::vm::EXTRA_EXITS_FOR_TESTS.set(0);
            super::super::vm::APIC_MODE_FOR_TESTS.set(None);
            let vm = made.map_err(|e| format!("the partition is not made: errno {}", e.errno()))?;
            let m = guest();
            probes(m);
            put(m, DF_AT, &[0xE6, 0x88, 0xEB, 0xFE]);
            let gate = (DF_AT & 0xFFFF) | (8 << 16) | (0x8E << 40) | (((DF_AT >> 16) & 0xFFFF) << 48);
            put(m, IDT + DF * 16, &gate.to_le_bytes());
            put(m, IDT + DF * 16 + 8, &(DF_AT >> 32).to_le_bytes());
            // The local APIC's page at 0xfee00000, a 2 MiB page.
            put(m, 0x2018, &(0xA000u64 | 3).to_le_bytes());
            put(m, 0xA000 + 0x1F7 * 8, &(0xFEE0_0000u64 | 0x83).to_le_bytes());
            let region = kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: MEM as u64,
                userspace_addr: m as u64,
            };
            // SAFETY: the memory stays mapped while the VM has it.
            unsafe { vm.set_user_memory_region(region) }.map_err(|e| format!("the slot is refused: errno {}", e.errno()))?;
            let mut vcpu = vm.create_vcpu(0).map_err(|e| format!("the vCPU is not made: errno {}", e.errno()))?;
            vcpu.set_cpuid2(&regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap()).unwrap();
            let value: u64 = 1 << GP;
            // SAFETY: a u64 value for ExceptionExitBitmap; no vCPU runs.
            unsafe { ffi::set_partition_property(vcpu.part(), whv::WHvPartitionPropertyCodeExceptionExitBitmap, &value) }
                .map_err(|e| format!("ExceptionExitBitmap {value:#x} refused: errno {}", e.errno()))?;
            start(&vcpu);
            let mut s = vcpu.get_sregs().unwrap();
            (s.idt.base, s.idt.limit) = (IDT, u16::try_from(vectors * 16 - 1).unwrap());
            vcpu.set_sregs(&s).unwrap();
            if extd {
                vcpu.set_regs(&kvm_regs { rip: WRMSR_AT, rsp: 0x9000, rflags: 2, rax: 0xFEE0_0D00, rcx: 0x1B, ..Default::default() }).unwrap();
                let end = run_once(&mut vcpu);
                if end != "exit IoOut port 0x80" {
                    return Err(format!("the guest's WRMSR of APIC_BASE 0xfee00d00 ended by {end}"));
                }
            }
            Ok((vm, vcpu, m))
        }

        /// One `WHvRunVirtualProcessor`, kicked after 5 s: the exit as a
        /// line (an exception's details, the execution state and
        /// `WHvRegisterPendingInterruption` after it) and an exception
        /// exit's vector and error code.
        fn raw_once(vcpu: &mut VcpuFd) -> (String, Option<(u8, u32)>) {
            let (part, vp) = (vcpu.part(), vcpu.vp());
            let watchdog = super::Watchdog::arm(vcpu);
            let ran = ffi::run_vp(part, vp);
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            let ctx = match ran {
                Ok(c) => c,
                Err(e) => return (format!("run failed, errno {}", e.errno()), None),
            };
            let mut exception = None;
            let what = match ctx.ExitReason {
                whv::WHvRunVpExitReasonException => {
                    // SAFETY: the union arm matches the exit reason; the
                    // information's bit field overlaps the u32.
                    let (ex, info) = unsafe { (ctx.Anonymous.VpException, ctx.Anonymous.VpException.ExceptionInfo.AsUINT32) };
                    exception = Some((ex.ExceptionType, ex.ErrorCode));
                    format!(
                        "an exception exit: vector {}, error code {:#x} (ErrorCodeValid {}, SoftwareException {}), parameter \
                         {:#x}, instruction bytes {:02x?}",
                        ex.ExceptionType,
                        ex.ErrorCode,
                        info & 1,
                        info >> 1 & 1,
                        ex.ExceptionParameter,
                        &ex.InstructionBytes[..usize::from(ex.InstructionByteCount).min(16)]
                    )
                }
                // SAFETY: as above.
                whv::WHvRunVpExitReasonX64IoPortAccess => format!("out {:#x}", unsafe { ctx.Anonymous.IoPortAccess.PortNumber }),
                // SAFETY: as above.
                whv::WHvRunVpExitReasonX64MsrAccess => format!("an MSR exit of {:#x}", unsafe { ctx.Anonymous.MsrAccess.MsrNumber }),
                reason => format!("exit reason {reason:#x}"),
            };
            // SAFETY: a plain 16-bit view of the execution state's bit field.
            let state = unsafe { ctx.VpContext.ExecutionState.AsUINT16 };
            let pending = match ffi::get_register(part, vp, whv::WHvRegisterPendingInterruption) {
                Ok(v) => format!("{:#x}", ffi::as_u64(&v)),
                Err(e) => format!("not read: errno {}", e.errno()),
            };
            (
                format!(
                    "{what} (RIP {:#x}, CPL {}, InterruptionPending {}, InterruptShadow {}; PendingInterruption {pending})",
                    ctx.VpContext.Rip,
                    state & 3,
                    state >> 6 & 1,
                    state >> 12 & 1
                ),
                exception,
            )
        }

        /// The event given back for an exception: pending, a hardware
        /// exception (type 3), its error code if it has one (bit 4).
        fn event(vector: u64, code: Option<u32>) -> u64 {
            1 | (3 << 1) | (u64::from(code.is_some()) << 4) | (vector << 16) | (u64::from(code.unwrap_or(0)) << 32)
        }

        fn give(vcpu: &VcpuFd, event: u64) -> String {
            match ffi::set_register(vcpu.part(), vcpu.vp(), whv::WHvRegisterPendingInterruption, ffi::reg64(event)) {
                Ok(()) => format!("PendingInterruption {event:#x} set"),
                Err(e) => format!("PendingInterruption {event:#x} refused: errno {}", e.errno()),
            }
        }

        /// The error code and RIP on a handler's stack.
        fn frame(vcpu: &VcpuFd, m: *mut u8) -> String {
            let rsp = vcpu.get_regs().unwrap().rsp;
            if rsp + 16 > MEM as u64 {
                return format!("RSP {rsp:#x} outside the guest's memory");
            }
            // SAFETY: within the test's mapping.
            let (code, rip) = unsafe { (*(m.add(rsp as usize) as *const u64), *(m.add(rsp as usize + 8) as *const u64)) };
            format!("the handler's frame: error code {code:#x}, RIP {rip:#x}")
        }

        fn lvtt_of(vcpu: &VcpuFd) -> String {
            match vcpu.get_lapic() {
                Ok(l) => {
                    let b: Vec<u8> = l.regs[0x320..0x324].iter().map(|&c| c as u8).collect();
                    format!("{:#x}", u32::from_le_bytes(b.try_into().unwrap()))
                }
                Err(e) => format!("not read: errno {}", e.errno()),
            }
        }

        fn timer_register(vcpu: &VcpuFd) -> String {
            match ffi::get_register(vcpu.part(), vcpu.vp(), whv::WHvX64RegisterApicLvtTimer) {
                Ok(v) => format!("{:#x}", ffi::as_u64(&v)),
                Err(e) => format!("not read: errno {}", e.errno()),
            }
        }

        fn done(vcpu: VcpuFd, vm: super::super::VmFd, m: *mut u8) {
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }

        // e: the host's processor.
        {
            use core::arch::x86_64::__cpuid;
            let l0 = __cpuid(0);
            let vendor: Vec<u8> = [l0.ebx, l0.edx, l0.ecx].iter().flat_map(|r| r.to_le_bytes()).collect();
            let brand: Vec<u8> = (0x8000_0002u32..=0x8000_0004)
                .flat_map(|leaf| {
                    let r = __cpuid(leaf);
                    [r.eax, r.ebx, r.ecx, r.edx]
                })
                .flat_map(u32::to_le_bytes)
                .collect();
            let l1 = __cpuid(1).eax;
            let mut offered = 0u64;
            let mut n = 0u32;
            // SAFETY: a u64 output buffer of the size passed.
            let hres = unsafe { whv::WHvGetCapability(whv::WHvCapabilityCodeExtendedVmExits, (&raw mut offered).cast(), 8, &mut n) };
            say(format!(
                "e: host {} \"{}\", leaf 1 EAX {l1:#x} (family {:#x}, model {:#x}, stepping {}); ExtendedVmExits {:#010x} \
                 {offered:#x}: ExceptionExit {}",
                String::from_utf8_lossy(&vendor),
                String::from_utf8_lossy(&brand).trim_matches(char::from(0)).trim(),
                ((l1 >> 8) & 0xF) + if (l1 >> 8) & 0xF == 0xF { (l1 >> 20) & 0xFF } else { 0 },
                ((l1 >> 4) & 0xF) | if matches!((l1 >> 8) & 0xF, 6 | 0xF) { (l1 >> 12) & 0xF0 } else { 0 },
                l1 & 0xF,
                hres.cast_unsigned(),
                offered >> 2 & 1
            ));
            if offered & (1 << 2) == 0 {
                say("ExceptionExit not offered: nothing else is run".to_string());
                return;
            }
        }

        // b: error codes.
        match e0_vm(true, 14) {
            Err(e) => say(format!("b: {e}")),
            Ok((vm, mut vcpu, m)) => {
                for (what, code) in [
                    ("mov ds of selector 0x1234 (past the GDT's limit)", &[0x66, 0xB8, 0x34, 0x12, 0x8E, 0xD8][..]),
                    ("int 0x41 (past the IDT's limit of 14 gates)", &[0xCD, 0x41][..]),
                ] {
                    let mut p = code.to_vec();
                    p.extend_from_slice(&[0xE6, PORT as u8, 0xEB, 0xFE]);
                    put(m, PROGRAM, &p);
                    vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                    let (first, ex) = raw_once(&mut vcpu);
                    let mut l = format!("b: {what}: {first}");
                    if let Some((13, code)) = ex {
                        let given = give(&vcpu, event(GP, Some(code)));
                        let (next, _) = raw_once(&mut vcpu);
                        l += &format!("; given back with its error code ({given}): {next}");
                        if next.starts_with("out 0x8d") {
                            l += &format!("; {}", frame(&vcpu, m));
                        }
                    }
                    say(l);
                }
                done(vcpu, vm, m);
            }
        }

        // a: an external interrupt past the IDT's limit.
        match e0_vm(true, 14) {
            Err(e) => say(format!("a, an external interrupt: {e}")),
            Ok((vm, mut vcpu, m)) => {
                // The local APIC on (WRMSR 0x80f of 0x1ff), `out 0x80`; then
                // `sti; jmp $`.
                put(
                    m,
                    PROGRAM,
                    &[0xB9, 0x0F, 0x08, 0, 0, 0xB8, 0xFF, 0x01, 0, 0, 0x31, 0xD2, 0x0F, 0x30, 0xE6, PORT as u8, 0xFB, 0xEB, 0xFE],
                );
                vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                let (first, _) = raw_once(&mut vcpu);
                if first.starts_with(&format!("out {PORT:#x}")) {
                    regs::set_rip(vcpu.part(), vcpu.vp(), PROGRAM + 16).unwrap();
                    vm.signal_msi(kvm_bindings::kvm_msi { address_lo: 0xFEE0_0000, data: 0x41, ..Default::default() }).unwrap();
                    let (second, ex) = raw_once(&mut vcpu);
                    let mut l = format!("a: vector 0x41 requested, the guest's IDT 14 gates long: {second}");
                    if let Some((13, code)) = ex {
                        let given = give(&vcpu, event(GP, Some(code)));
                        let (next, _) = raw_once(&mut vcpu);
                        l += &format!("; the #GP given back alone ({given}): {next}");
                        if next.starts_with("out 0x8d") {
                            l += &format!("; {}", frame(&vcpu, m));
                        }
                    }
                    say(l);
                } else {
                    say(format!("a: the local APIC not turned on: {first}"));
                }
                done(vcpu, vm, m);
            }
        }

        // a: a #GP past the IDT's limit, and then a #DF past it.
        for (case, vectors) in [("a: #GP's gate past the IDT's limit (13 gates, #DF's among them)", 13u64), ("a: #GP's and #DF's gates past it (8 gates)", 8)] {
            match e0_vm(true, vectors) {
                Err(e) => say(format!("{case}: {e}")),
                Ok((vm, mut vcpu, m)) => {
                    vcpu.set_regs(&kvm_regs { rip: WRMSR_AT, rsp: 0x9000, rflags: 2, rax: 0x4_0041, rcx: 0x832, ..Default::default() })
                        .unwrap();
                    let (first, ex) = raw_once(&mut vcpu);
                    let mut l = format!("{case}: WRMSR 0x832 of 0x40041: {first}");
                    if let Some((13, code)) = ex {
                        let given = give(&vcpu, event(GP, Some(code)));
                        let (second, ex) = raw_once(&mut vcpu);
                        l += &format!("; the #GP given back ({given}): {second}");
                        if let Some((13, _)) = ex {
                            // Two contributory faults: KVM makes them a #DF.
                            let given = give(&vcpu, event(DF, Some(0)));
                            let (third, ex) = raw_once(&mut vcpu);
                            l += &format!("; a #DF given ({given}): {third}");
                            if third.starts_with("out 0x88") {
                                l += &format!("; {}", frame(&vcpu, m));
                            } else if ex.is_some() {
                                l += " (KVM's answer: a triple fault, KVM_EXIT_SHUTDOWN)";
                            }
                        } else if second.starts_with("out 0x88") {
                            l += &format!("; {}", frame(&vcpu, m));
                        }
                    }
                    say(l);
                    done(vcpu, vm, m);
                }
            }
        }

        // c: EXTD clear.
        match e0_vm(false, 14) {
            Err(e) => say(format!("c, EXTD clear: {e}")),
            Ok((vm, mut vcpu, m)) => {
                // mov ebx, 0xfee00000; the spurious vector register 0x1ff;
                // the LVT timer 0x400ec; mov eax, [rbx + 0x320].
                put(
                    m,
                    PROGRAM,
                    &[
                        0xBB, 0x00, 0x00, 0xE0, 0xFE, 0xC7, 0x83, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x00, 0xC7, 0x83, 0x20,
                        0x03, 0x00, 0x00, 0xEC, 0x00, 0x04, 0x00, 0x8B, 0x83, 0x20, 0x03, 0x00, 0x00, 0xE6, PORT as u8, 0xEB, 0xFE,
                    ],
                );
                vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                let (line, _) = raw_once(&mut vcpu);
                say(format!(
                    "c: EXTD clear: the guest's MMIO write of the LVT timer 0x400ec and its read: {line}; the guest read {:#x}; \
                     KVM_GET_LAPIC's LVT timer {}",
                    vcpu.get_regs().unwrap().rax,
                    lvtt_of(&vcpu)
                ));
                vcpu.set_regs(&kvm_regs { rip: RDMSR_AT, rsp: 0x9000, rflags: 2, rcx: 0x802, ..Default::default() }).unwrap();
                let (line, _) = raw_once(&mut vcpu);
                say(format!("c: EXTD clear: the guest's RDMSR 0x802 (the x2APIC ID): {line}"));
                // f: the guest's MMIO write of each timer mode in xAPIC
                // mode, and its read: whether only the TSC-deadline mode is
                // dropped, and whole (the vector too), as an xAPIC-mode
                // guest of option E would write it.
                let svr = vcpu.get_lapic().map(|l| format!("{:#x}", u32::from_le_bytes(std::array::from_fn(|i| l.regs[0xF0 + i] as u8))));
                say(format!("f: EXTD clear: the spurious vector register after the guest's MMIO write of 0x1ff: {}", svr.unwrap_or_else(|e| format!("not read: errno {}", e.errno()))));
                for value in [0x00ECu32, 0x1_00EC, 0x2_00EC, 0x4_00EC, 0x00ED] {
                    let mut code = vec![0xBB, 0x00, 0x00, 0xE0, 0xFE, 0xC7, 0x83, 0x20, 0x03, 0x00, 0x00];
                    code.extend_from_slice(&value.to_le_bytes());
                    code.extend_from_slice(&[0x8B, 0x83, 0x20, 0x03, 0x00, 0x00, 0xE6, PORT as u8, 0xEB, 0xFE]);
                    put(m, PROGRAM, &code);
                    vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                    let (line, _) = raw_once(&mut vcpu);
                    say(format!(
                        "f: EXTD clear: the guest's MMIO write of the LVT timer {value:#x} and its read: {line}; the guest read {:#x}; \
                         KVM_GET_LAPIC's LVT timer {}",
                        vcpu.get_regs().unwrap().rax,
                        lvtt_of(&vcpu)
                    ));
                }
                done(vcpu, vm, m);
            }
        }

        // c: EXTD set, the LVT timer written by the host.
        match e0_vm(true, 14) {
            Err(e) => say(format!("c, EXTD set: {e}")),
            Ok((vm, mut vcpu, m)) => {
                vcpu.set_regs(&kvm_regs { rip: WRMSR_AT, rsp: 0x9000, rflags: 2, rax: 0x1FF, rcx: 0x80F, ..Default::default() }).unwrap();
                let (on, _) = raw_once(&mut vcpu);
                say(format!("c: EXTD set: the guest's WRMSR 0x80f of 0x1ff: {on}"));
                let guest_reads = |vcpu: &mut VcpuFd| {
                    vcpu.set_regs(&kvm_regs { rip: RDMSR_AT, rsp: 0x9000, rflags: 2, rcx: 0x832, ..Default::default() }).unwrap();
                    let (line, _) = raw_once(vcpu);
                    let r = vcpu.get_regs().unwrap();
                    format!("{line}, EDX:EAX {:#x}", (r.rdx << 32) | (r.rax & 0xFFFF_FFFF))
                };
                for value in [0x4_00ECu64, 0x1_00EC, 0x00EC] {
                    let set = match ffi::set_register(vcpu.part(), vcpu.vp(), whv::WHvX64RegisterApicLvtTimer, ffi::reg64(value)) {
                        Ok(()) => "taken".to_string(),
                        Err(e) => format!("refused: errno {}", e.errno()),
                    };
                    let (register, lapic) = (timer_register(&vcpu), lvtt_of(&vcpu));
                    let guest = guest_reads(&mut vcpu);
                    say(format!(
                        "c: EXTD set: WHvX64RegisterApicLvtTimer of {value:#x}: {set}; read back {register}; KVM_GET_LAPIC's LVT \
                         timer {lapic}; the guest's RDMSR 0x832: {guest}"
                    ));
                }
                let set = vcpu.get_lapic().and_then(|mut l| {
                    for (i, b) in 0x4_00ECu32.to_le_bytes().into_iter().enumerate() {
                        l.regs[0x320 + i] = b as std::os::raw::c_char;
                    }
                    vcpu.set_lapic(&l)
                });
                let set = match set {
                    Ok(()) => "taken".to_string(),
                    Err(e) => format!("refused: errno {}", e.errno()),
                };
                let (register, lapic) = (timer_register(&vcpu), lvtt_of(&vcpu));
                let guest = guest_reads(&mut vcpu);
                say(format!(
                    "c: EXTD set: KVM_SET_LAPIC with the LVT timer 0x400ec: {set}; WHvX64RegisterApicLvtTimer {register}; \
                     KVM_GET_LAPIC's {lapic}; the guest's RDMSR 0x832: {guest}"
                ));
                // g: the LVT timer in TSC-deadline mode through the page,
                // as option E could write its substitute (the guest's read
                // keeps mode 10): unmasked, no initial count, the guest
                // spinning with interrupts off until the 5 s kick; whether
                // WHP's own timer raised the vector (IRR) or counts; and
                // what writing the page costs, against the register.
                let set = vcpu.get_lapic().and_then(|mut l| {
                    for (at, v) in [(0x320usize, 0x4_00ECu32), (0x380, 0)] {
                        for (i, b) in v.to_le_bytes().into_iter().enumerate() {
                            l.regs[at + i] = b as std::os::raw::c_char;
                        }
                    }
                    vcpu.set_lapic(&l)
                });
                put(m, PROGRAM, &[0xEB, 0xFE]);
                vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                let (line, _) = raw_once(&mut vcpu);
                let regs = vcpu.lapic_page().map(|(p, _)| {
                    let r = |at: usize| u32::from_le_bytes(p[at..at + 4].try_into().unwrap());
                    format!(
                        "LVT timer {:#x}, initial count {:#x}, current count {:#x}, vector 0xec in the IRR {}, in the ISR {}",
                        r(0x320),
                        r(0x380),
                        r(0x390),
                        r(0x270) >> 12 & 1,
                        r(0x170) >> 12 & 1
                    )
                });
                say(format!(
                    "g: EXTD set: KVM_SET_LAPIC with the LVT timer 0x400ec and no initial count: {}; the guest spun: {line}; then {}",
                    set.map_or_else(|e| format!("refused: errno {}", e.errno()), |()| "taken".to_string()),
                    regs.unwrap_or_else(|e| format!("not read: errno {}", e.errno()))
                ));
                let guest = guest_reads(&mut vcpu);
                say(format!("g: EXTD set: then the guest's RDMSR 0x832: {guest}"));
                const PAIRS: u32 = 1000;
                let start = std::time::Instant::now();
                for _ in 0..PAIRS {
                    let l = vcpu.get_lapic().unwrap();
                    vcpu.set_lapic(&l).unwrap();
                }
                let page = start.elapsed().as_secs_f64() * 1e6 / f64::from(PAIRS);
                let start = std::time::Instant::now();
                for _ in 0..PAIRS {
                    ffi::set_register(vcpu.part(), vcpu.vp(), whv::WHvX64RegisterApicLvtTimer, ffi::reg64(0xEC)).unwrap();
                }
                let register = start.elapsed().as_secs_f64() * 1e6 / f64::from(PAIRS);
                say(format!(
                    "g: the LVT timer written through the page (KVM_GET_LAPIC and KVM_SET_LAPIC, which reads the page first) \
                     {page:.3} us a write, through WHvX64RegisterApicLvtTimer {register:.3} us, {PAIRS} each"
                ));
                // The APIC ID register as the backend reads it (the legacy
                // page, `lapic_page`, which `tscdeadline::deadline_interrupt`
                // takes the destination from as `>> 24`) on vCPU 1, in xAPIC
                // mode and after APIC_BASE.EXTD is set by the host.
                match vm.create_vcpu(1) {
                    Err(e) => say(format!("c: vCPU 1 not made: errno {}", e.errno())),
                    Ok(one) => {
                        let id = |v: &VcpuFd| {
                            let page = v.lapic_page().map(|(p, _)| format!("{:#x}", u32::from_le_bytes(p[0x20..0x24].try_into().unwrap())));
                            let register = ffi::get_register(v.part(), v.vp(), whv::WHvX64RegisterApicId).map(|r| format!("{:#x}", ffi::as_u64(&r)));
                            let base = ffi::get_register(v.part(), v.vp(), whv::WHvX64RegisterApicBase).map(|r| format!("{:#x}", ffi::as_u64(&r)));
                            format!(
                                "APIC_BASE {}, the legacy page's ID register {}, WHvX64RegisterApicId {}",
                                base.unwrap_or_else(|e| format!("not read: errno {}", e.errno())),
                                page.unwrap_or_else(|e| format!("not read: errno {}", e.errno())),
                                register.unwrap_or_else(|e| format!("not read: errno {}", e.errno()))
                            )
                        };
                        let before = id(&one);
                        let set = ffi::set_register(one.part(), one.vp(), whv::WHvX64RegisterApicBase, ffi::reg64(0xFEE0_0C00))
                            .map_or_else(|e| format!("refused: errno {}", e.errno()), |()| "taken".to_string());
                        say(format!("c: vCPU 1 in xAPIC mode: {before}; APIC_BASE 0xfee00c00 (EXTD) written by the host: {set}; then {}", id(&one)));
                        drop(one);
                    }
                }
                done(vcpu, vm, m);
            }
        }

        // d: E's path for the TSC-deadline write.
        match e0_vm(true, 14) {
            Err(e) => say(format!("d: {e}")),
            Ok((vm, mut vcpu, m)) => {
                vcpu.set_regs(&kvm_regs { rip: WRMSR_AT, rsp: 0x9000, rflags: 2, rax: 0x1FF, rcx: 0x80F, ..Default::default() }).unwrap();
                let _ = raw_once(&mut vcpu);
                let mut code = vec![0xBB];
                code.extend_from_slice(&ROUNDS.to_le_bytes());
                code.extend_from_slice(&[0xB9, 0x32, 0x08, 0x00, 0x00, 0xB8, 0xEC, 0x00, 0x04, 0x00]);
                code.extend_from_slice(&[0x31, 0xD2, 0x0F, 0x30, 0xFF, 0xCB, 0x75, 0xEE, 0xE6, PORT as u8, 0xEB, 0xFE]);
                put(m, LOOP_AT, &code);
                let (part, vp) = (vcpu.part(), vcpu.vp());
                let mut best = f64::MAX;
                let (mut exits, mut end) = (0u32, String::new());
                for _ in 0..3 {
                    vcpu.set_regs(&kvm_regs { rip: LOOP_AT, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                    let watchdog = super::Watchdog::arm(&vcpu);
                    let t = std::time::Instant::now();
                    exits = 0;
                    end = loop {
                        if vcpu.shared.immediate_exit.load(Ordering::SeqCst) != 0 {
                            break "none within 5 s (kicked)".to_string();
                        }
                        let ctx = match ffi::run_vp(part, vp) {
                            Ok(c) => c,
                            Err(e) => break format!("run failed, errno {}", e.errno()),
                        };
                        match ctx.ExitReason {
                            whv::WHvRunVpExitReasonException => {
                                // SAFETY: plain zeroed register values.
                                let mut v: [whv::WHV_REGISTER_VALUE; 3] = unsafe { std::mem::zeroed() };
                                let names = [whv::WHvX64RegisterRcx, whv::WHvX64RegisterRax, whv::WHvX64RegisterRdx];
                                if let Err(e) = ffi::get_registers(part, vp, &names, &mut v) {
                                    break format!("the registers not read, errno {}", e.errno());
                                }
                                let (rcx, rax) = (ffi::as_u64(&v[0]), ffi::as_u64(&v[1]));
                                if rcx != 0x832 {
                                    break format!("a #GP at another WRMSR, ECX {rcx:#x}");
                                }
                                let one_shot = rax & 0xFFFF_FFFF & !(0b11 << 17);
                                let names = [whv::WHvX64RegisterApicLvtTimer, whv::WHvX64RegisterRip];
                                if let Err(e) = ffi::set_registers(part, vp, &names, &[ffi::reg64(one_shot), ffi::reg64(ctx.VpContext.Rip + 2)]) {
                                    break format!("the LVT timer and RIP not written, errno {}", e.errno());
                                }
                                exits += 1;
                                if exits > 2 * ROUNDS {
                                    break "more exits than WRMSRs".to_string();
                                }
                            }
                            whv::WHvRunVpExitReasonX64IoPortAccess => {
                                // SAFETY: the union arm matches the exit reason.
                                let port = unsafe { ctx.Anonymous.IoPortAccess.PortNumber };
                                break if port == PORT { "the loop's end".to_string() } else { format!("out {port:#x}") };
                            }
                            reason => break format!("exit reason {reason:#x} at RIP {:#x}", ctx.VpContext.Rip),
                        }
                    };
                    best = best.min(t.elapsed().as_secs_f64() * 1e6 / f64::from(ROUNDS));
                    drop(watchdog);
                    vcpu.set_kvm_immediate_exit(0);
                    if end != "the loop's end" {
                        break;
                    }
                }
                say(format!(
                    "d: E's path: {ROUNDS} WRMSRs 0x832 of 0x400ec in a guest loop, each exception exit answered by the registers \
                     read and the LVT timer (one-shot) and RIP written: the least of 3 runs {best:.3} us a WRMSR, {exits} exception \
                     exits, ended by {end}; the LVT timer after: {}",
                    timer_register(&vcpu)
                ));
                done(vcpu, vm, m);
            }
        }
    }

    /// Record A of lazy-ram-options.md (COMMITTEST lines; no WHP): what
    /// `VirtualAlloc(MEM_COMMIT)` of reserved memory takes for 4 KiB,
    /// 64 KiB and 2 MiB (64 of each, the median, least and most), what the
    /// backend's commit of `MAP_NORESERVE` memory at a first access
    /// (`commit_on_access`, a page where no `MADV_HUGEPAGE` is) takes, and what the host's own
    /// first write to each 4 KiB page of committed memory takes after it.
    /// Printed, not asserted.
    #[test]
    #[ignore = "a record: run on Windows with --ignored --nocapture"]
    fn test_what_a_commit_takes_by_size_on_record() {
        use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};
        const N: usize = 64;
        let spread = |mut t: Vec<f64>| {
            t.sort_by(f64::total_cmp);
            format!("median {:.1} us (least {:.1}, most {:.1})", t[t.len() / 2], t[0], t[t.len() - 1])
        };
        let mut lines = Vec::new();
        for size in [4usize << 10, 64 << 10, 2 << 20] {
            // SAFETY: a reservation of the process's own, released below.
            let base = unsafe { VirtualAlloc(std::ptr::null(), size * N, MEM_RESERVE, PAGE_READWRITE) }.cast::<u8>();
            assert!(!base.is_null());
            let mut commit = Vec::new();
            let mut touch = Vec::new();
            for i in 0..N {
                // SAFETY: within the reservation.
                let at = unsafe { base.add(i * size) };
                let t = std::time::Instant::now();
                // SAFETY: as above.
                let p = unsafe { VirtualAlloc(at.cast(), size, MEM_COMMIT, PAGE_READWRITE) };
                commit.push(t.elapsed().as_secs_f64() * 1e6);
                assert!(!p.is_null());
                let t = std::time::Instant::now();
                for page in (0..size).step_by(4096) {
                    // SAFETY: committed above.
                    unsafe { at.add(page).write_volatile(1) };
                }
                touch.push(t.elapsed().as_secs_f64() * 1e6 / (size / 4096) as f64);
            }
            // SAFETY: the reservation made above.
            assert_ne!(unsafe { VirtualFree(base.cast(), 0, MEM_RELEASE) }, 0);
            lines.push(format!(
                "{} KiB: the commit {}; the host's first write to a page after it {}",
                size / 1024,
                spread(commit),
                spread(touch)
            ));
        }
        // The backend's path for lazy guest RAM.
        let len = 64 * 0x1_0000;
        // SAFETY: anonymous memory for the test, unmapped below.
        let lazy = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, libc::MAP_FAILED);
        let mut times = Vec::new();
        let mut outcomes = std::collections::BTreeSet::new();
        for i in 0..64 {
            let t = std::time::Instant::now();
            let a = libc::wick_mm::commit_on_access(lazy as usize + i * 0x1_0000, true);
            times.push(t.elapsed().as_secs_f64() * 1e6);
            outcomes.insert(match a {
                libc::wick_mm::Access::Committed => "committed",
                libc::wick_mm::Access::NotLazy => "not lazy",
                libc::wick_mm::Access::Exhausted(_) => "exhausted",
            });
        }
        // SAFETY: the mapping made above.
        assert_eq!(unsafe { libc::munmap(lazy, len) }, 0);
        lines.push(format!("the backend's commit_on_access of MAP_NORESERVE memory, 64 first accesses: {} ({outcomes:?})", spread(times)));
        for l in &lines {
            eprintln!("COMMITTEST {l}");
        }
    }

    /// Record B of lazy-ram-options.md (POPULATETEST lines): whether
    /// `WHvAdviseGpaRange(Populate)` of committed guest RAM that nothing has
    /// touched maps it ahead of the guest, and so spares the guest's first
    /// write to each page the fault WHP takes for it inside the run call
    /// (14.5 us a page on a PC at 03f4bfe): its HRESULT, the working set
    /// and commit charge it moves, and the run call of a guest writing each
    /// 4 KiB page of 2 MiB that was populated, against 2 MiB that was not
    /// (that one first). Printed, not asserted.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_populate_of_committed_guest_ram_on_record() {
        const GPA: u64 = 0xA0_0000;
        const LEN: usize = 4 << 20;
        let touch = |at: u32| {
            let mut b = vec![0xBF];
            b.extend_from_slice(&at.to_le_bytes()); // mov edi, at
            b.extend_from_slice(&[
                0xB9, 0x00, 0x02, 0x00, 0x00, // mov ecx, 512
                0xC6, 0x07, 0x01, // mov byte [rdi], 1
                0x81, 0xC7, 0x00, 0x10, 0x00, 0x00, // add edi, 0x1000
                0xFF, 0xC9, // dec ecx
                0x75, 0xF3, // jnz to the mov
                0xE6, PORT as u8,
            ]);
            b
        };
        let program = [vec![0xE6, PORT as u8], touch(0xC0_0000), touch(0xA0_0000), vec![0xF4, 0xEB, 0xFD]].concat();
        let (vm, mut vcpu, m) = mmio_guest(&program);
        put(m, 0x3028, &(0xA0_0000u64 | 0x83).to_le_bytes());
        put(m, 0x3030, &(0xC0_0000u64 | 0x83).to_le_bytes());
        // SAFETY: anonymous memory for the test (committed: no MAP_NORESERVE), unmapped below.
        let ram = unsafe {
            libc::mmap(std::ptr::null_mut(), LEN, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(ram, libc::MAP_FAILED);
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 1,
            flags: 0,
            guest_phys_addr: GPA,
            memory_size: LEN as u64,
            userspace_addr: ram as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        let populate = populate_on_record(vcpu.part(), ram as usize, GPA, 2 << 20);
        let watchdog = super::Watchdog::arm(&vcpu);
        let mut reads = 0;
        let mut timed = Vec::new();
        for _ in 0..3 {
            let t = std::time::Instant::now();
            let line = one_run(&mut vcpu, &[], &mut reads);
            timed.push((line, t.elapsed().as_secs_f64() * 1e6));
        }
        drop(watchdog);
        eprintln!("POPULATETEST {populate}");
        eprintln!(
            "POPULATETEST the guest's first write to each of 512 pages: not populated (0xc00000) {} {:.1} us, \
             {:.2} us a page; populated (0xa00000) {} {:.1} us, {:.2} us a page (the first run, {} {:.1} us, warms up)",
            timed[1].0,
            timed[1].1,
            timed[1].1 / 512.0,
            timed[2].0,
            timed[2].1,
            timed[2].1 / 512.0,
            timed[0].0,
            timed[0].1
        );
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mappings, no VM left using them.
        assert_eq!(unsafe { libc::munmap(ram, LEN) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The record for the lazy-RAM grain (LAZYGRAIN lines; O4 of
    /// lazy-ram-options.md): what guest RAM mapped as Firecracker maps it
    /// (`MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE`) is charged and
    /// resident after the guest touches it, and what the exits cost, when
    /// the backend commits 4 KiB (its grain where no `MADV_HUGEPAGE` is),
    /// 64 KiB (its grain before) or 2 MiB (a write's, where one is) at a
    /// first access (`wick_mm::record_grain`, set on this test's mappings
    /// only; a guest write's 2 MiB block is populated as the backend does
    /// for a transparent huge page, `VmInner::populate_committed`, so the
    /// 2 MiB slot's numbers are `huge_pages: Transparent`'s). Each grain has a slot of its own, 2 MiB aligned on the host as
    /// a transparent huge page needs, and the guest's same two steps in it:
    /// - sparse: one byte written in each 2 MiB of 64 MiB (32 writes);
    /// - dense: a byte written in each 4 KiB page of the next 4 MiB (1024).
    ///
    /// After each: the slot's commit (`VirtualQuery`; the job's memory limit
    /// counts commit) and its pages in the working set (`QueryWorkingSetEx`,
    /// Linux's Rss), the process's commit and working set (with this
    /// record's own allocations), the exits of guest RAM with each one's run
    /// call and the backend's time after it, and the step's time. Linux's
    /// numbers for the same guest addresses and steps are
    /// tools/linux/guest-ram-grain.c's (LINUXGRAIN lines), under the THP
    /// setting it prints. Then `WHvAdviseGpaRange(Populate)` of 2 MiB of
    /// committed guest RAM nothing touched, 8 times: its own time and the
    /// working set it adds (the option of a 2 MiB commit populated at once).
    /// The guest's first lazy exit on the thread is a warm-up step of its
    /// own (0.9 to 7.1 ms on a PC's application processors at f35e353).
    /// Printed, not asserted, but for each step reaching its end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_lazy_guest_ram_by_grain_on_record() {
        const PROGRAM: u64 = 0xB000;
        // A 2 MiB slot for the warm-up write.
        const WARM: u64 = 0x80_0000;
        const SLOT_LEN: usize = 68 << 20;
        const DENSE_AT: u32 = 64 << 20;
        const GRAINS: [(usize, u64); 3] = [(4 << 10, 0x200_0000), (64 << 10, 0x700_0000), (2 << 20, 0xC00_0000)];
        const POPULATED: u64 = 0x1200_0000;
        const POPULATED_LEN: usize = 16 << 20;
        const MIB2: usize = 2 << 20;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        // 2 MiB pages, identity mapped, from 8 MiB to the end of the last slot.
        let mut gpa = WARM;
        while gpa < POPULATED + POPULATED_LEN as u64 {
            put(m, 0x3000 + (gpa >> 21) * 8, &(gpa | 0x83).to_le_bytes());
            gpa += MIB2 as u64;
        }
        // mov edi, base; mov ecx, count; then a byte written at rdi and rdi
        // moved by stride, count times; out 0x80, al.
        let touch = |base: u32, count: u32, stride: u32| {
            let mut b = vec![0xBF];
            b.extend_from_slice(&base.to_le_bytes());
            b.push(0xB9);
            b.extend_from_slice(&count.to_le_bytes());
            b.extend_from_slice(&[0xC6, 0x07, 0x01, 0x81, 0xC7]); // mov byte [rdi], 1; add edi, stride
            b.extend_from_slice(&stride.to_le_bytes());
            b.extend_from_slice(&[0xFF, 0xC9, 0x75, 0xF3, 0xE6, PORT as u8]); // dec ecx; jnz to the mov; out
            b
        };
        let mut program = touch(WARM as u32, 1, 0x1000);
        for (_, base) in GRAINS {
            program.extend(touch(base as u32, 32, MIB2 as u32));
            program.extend(touch(base as u32 + DENSE_AT, 1024, 0x1000));
        }
        program.extend_from_slice(&[0xF4, 0xEB, 0xFD]);
        put(m, PROGRAM, &program);
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe {
            vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: MEM as u64,
                userspace_addr: m as u64,
            })
        }
        .unwrap();
        let lazy = |len: usize| {
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
            p as usize
        };
        let warm = lazy(MIB2);
        // Each grain's mapping, 2 MiB more than its slot, which starts at
        // the first 2 MiB boundary in it.
        let maps: Vec<usize> = GRAINS.iter().map(|_| lazy(SLOT_LEN + MIB2)).collect();
        let slots: Vec<usize> = maps.iter().map(|&p| p.next_multiple_of(MIB2)).collect();
        // SAFETY: anonymous memory for the test (committed: no MAP_NORESERVE), unmapped below.
        let populated = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                POPULATED_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(populated, libc::MAP_FAILED);
        let regions = [(WARM, warm, MIB2), (POPULATED, populated as usize, POPULATED_LEN)]
            .into_iter()
            .chain(GRAINS.iter().zip(&slots).map(|(&(_, gpa), &host)| (gpa, host, SLOT_LEN)));
        for (slot, (gpa, host, len)) in (1..).zip(regions) {
            // SAFETY: the memory stays mapped while the VM has it.
            unsafe {
                vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                    slot,
                    flags: 0,
                    guest_phys_addr: gpa,
                    memory_size: len as u64,
                    userspace_addr: host as u64,
                })
            }
            .unwrap();
        }
        for (&(grain, _), &p) in GRAINS.iter().zip(&maps) {
            libc::wick_mm::record_grain(p, SLOT_LEN + MIB2, grain);
        }
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();

        let mut lines = Vec::new();
        let mut wrong = Vec::new();
        // One step of the program, to its `out`: what it ended with, the
        // lazy exits, and the step's time.
        let mut step = |vcpu: &mut VcpuFd, name: &str| {
            super::super::ffi::trace::begin();
            let t = std::time::Instant::now();
            let what = run_a_step(vcpu);
            let took = t.elapsed().as_secs_f64() * 1e6;
            let calls = super::super::ffi::trace::end();
            if !what.ends_with(&format!("IoOut {PORT:#x}")) {
                wrong.push(format!("{name}: the step did not reach its end: {what}"));
            }
            (lazy_exits(&calls), took)
        };
        let exits_text = |exits: &[(f64, f64)]| {
            if exits.is_empty() {
                return "no exits of guest RAM".to_string();
            }
            let n = exits.len() as f64;
            format!(
                "{} exits of guest RAM, each {:.1} us in its run call and {:.1} us in the backend after it",
                exits.len(),
                exits.iter().map(|e| e.0).sum::<f64>() / n,
                exits.iter().map(|e| e.1).sum::<f64>() / n
            )
        };
        let (exits, took) = step(&mut vcpu, "warm-up");
        lines.push(format!("warm-up, the thread's first write to lazy guest RAM: {}; the step {took:.1} us", exits_text(&exits)));
        for (&(grain, _), &slot) in GRAINS.iter().zip(&slots) {
            let mut per_page = 0.0;
            for (name, pages) in [
                ("sparse, a byte in each 2 MiB of 64 MiB (32 writes)", 32.0),
                ("dense, a byte in each 4 KiB page of 4 MiB (1024 writes)", 1024.0),
            ] {
                let before = process_memory();
                let (exits, took) = step(&mut vcpu, name);
                let after = process_memory();
                let process = match (before, after) {
                    (Some(a), Some(b)) => format!(
                        "the process's commit {:+} KiB, working set {:+} KiB",
                        (b.0 as i64 - a.0 as i64) / 1024,
                        (b.1 as i64 - a.1 as i64) / 1024
                    ),
                    _ => "the process's counters not read".to_string(),
                };
                lines.push(format!(
                    "grain {} KiB, {name}: {}; the step {took:.1} us, {:.2} us a write; the slot after it: committed {} KiB, \
                     resident {} KiB; {process}",
                    grain / 1024,
                    exits_text(&exits),
                    took / pages,
                    committed_bytes(slot, SLOT_LEN) / 1024,
                    resident_bytes(slot, SLOT_LEN) / 1024
                ));
                per_page = took / pages;
            }
            lines.push(format!(
                "grain {} KiB: 256 MiB touched page by page, at the dense step's time a page: {:.0} ms, {} exits",
                grain / 1024,
                per_page * 65536.0 / 1000.0,
                (256 << 20) / grain
            ));
        }
        // Populate of committed guest RAM nothing touched, 2 MiB at a time.
        let mut timed = Vec::new();
        let mut added = Vec::new();
        let mut results = std::collections::BTreeSet::new();
        for i in 0..(POPULATED_LEN / MIB2) as u64 {
            let host = populated as usize + i as usize * MIB2;
            let was = resident_bytes(host, MIB2);
            let t = std::time::Instant::now();
            let hres = populate(vcpu.part(), POPULATED + i * MIB2 as u64, MIB2 as u64);
            timed.push(t.elapsed().as_secs_f64() * 1e6);
            added.push((resident_bytes(host, MIB2) - was) / 1024);
            results.insert(format!("{:#010x}", hres.cast_unsigned()));
        }
        timed.sort_by(f64::total_cmp);
        lines.push(format!(
            "WHvAdviseGpaRange(Populate, a write) of 2 MiB of committed guest RAM nothing touched, {} times: HRESULT {results:?}; \
             the call median {:.1} us (least {:.1}, most {:.1}); the range's working set after it {added:?} KiB",
            timed.len(),
            timed[timed.len() / 2],
            timed[0],
            timed[timed.len() - 1]
        ));
        for l in &lines {
            eprintln!("LAZYGRAIN {l}");
        }
        drop(vcpu);
        drop(vm);
        for &p in &maps {
            libc::wick_mm::record_grain(p, SLOT_LEN + MIB2, 0);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(p as *mut _, SLOT_LEN + MIB2) }, 0);
        }
        // SAFETY: as above.
        unsafe {
            assert_eq!(libc::munmap(warm as *mut _, MIB2), 0);
            assert_eq!(libc::munmap(populated, POPULATED_LEN), 0);
            assert_eq!(libc::munmap(m.cast(), MEM), 0);
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// The record for the zero-page parity item (ZEROREAD lines). On Linux a
    /// guest's read of untouched anonymous guest RAM is given the shared
    /// zero page and charged nothing: KVM's read fault takes the page
    /// without FOLL_WRITE (v6.1 virt/kvm/kvm_main.c `hva_to_pfn_slow`,
    /// 2514-2546), and mm/memory.c `do_anonymous_page` maps the zero page
    /// for a read (4088-4091), in a private anonymous mapping as
    /// Firecracker's guest memory is. Here a read exit commits the page.
    /// Printed, on a lazy slot (`MAP_NORESERVE`, a page's grain):
    /// - the guest reading a byte of each 4 KiB page of 4 MiB: exits, the
    ///   slot's commit and working set, the process's commit; then writing
    ///   the same pages;
    /// - what a read-only zero page at the guest's addresses would take
    ///   instead: one host page mapped read-only (`WHvMapGpaRange`, Read) at
    ///   each of 1024 4 KiB guest pages (each call's time, and whether WHP
    ///   takes so many mappings of one page); the guest reading them (exits,
    ///   time); a guest write to one (the exit it makes); and, for 64 pages,
    ///   swapping a page's mapping for a writable one (`WHvUnmapGpaRange`
    ///   then `WHvMapGpaRange`), each one's time.
    ///
    /// Then a guest write to memory WHP maps read only, without and with
    /// the `GpaAccessFaultExit` exit ([`guest_writes_to_read_only_memory`]).
    ///
    /// Linux's lines for the same steps are tools/linux/guest-ram-grain.c's
    /// (LINUXGRAIN read steps). Printed, not asserted, but for each step
    /// reaching its end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_guest_read_of_untouched_ram_on_record() {
        use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};
        const PROGRAM: u64 = 0xB000;
        const LAZY_GPA: u64 = 0x200_0000;
        const LAZY_LEN: usize = 8 << 20;
        const ZERO_GPA: u64 = 0x300_0000;
        const PAGES: u32 = 1024;
        const MIB2: u64 = 2 << 20;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        let mut gpa = LAZY_GPA;
        while gpa < ZERO_GPA + MIB2 * 2 {
            put(m, 0x3000 + (gpa >> 21) * 8, &(gpa | 0x83).to_le_bytes());
            gpa += MIB2;
        }
        // mov edi, base; mov ecx, count; a byte read (or written) at rdi and
        // rdi moved a page on, count times; out 0x80, al.
        let pass = |base: u32, write: bool| {
            let mut b = vec![0xBF];
            b.extend_from_slice(&base.to_le_bytes());
            b.push(0xB9);
            b.extend_from_slice(&PAGES.to_le_bytes());
            if write {
                b.extend_from_slice(&[0xC6, 0x07, 0x01]); // mov byte [rdi], 1
            } else {
                b.extend_from_slice(&[0x8A, 0x07, 0x90]); // mov al, [rdi]; nop
            }
            b.extend_from_slice(&[0x81, 0xC7, 0x00, 0x10, 0x00, 0x00, 0xFF, 0xC9, 0x75, 0xF3, 0xE6, PORT as u8]);
            b
        };
        let program = [
            pass(LAZY_GPA as u32, false),
            pass(LAZY_GPA as u32, true),
            pass(ZERO_GPA as u32, false),
            // mov byte [ZERO_GPA], 1; out. Its address was written out by
            // hand until 87d0328 as 0x0030_0000 (3 MiB) for ZERO_GPA's
            // 0x0300_0000 (48 MiB): a linear address these page tables do
            // not map (the PD has 2 MiB pages from 0 and from LAZY_GPA up)
            // and no handler in the IDT, so a #PF, then #DF and a triple
            // fault: the "exits Shutdown" of the PC's 87d0328 run, not a
            // write of the zero page.
            [&[0xC6, 0x04, 0x25][..], &(ZERO_GPA as u32).to_le_bytes(), &[0x01, 0xE6, PORT as u8]].concat(),
            vec![0xF4, 0xEB, 0xFD],
        ]
        .concat();
        put(m, PROGRAM, &program);
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe {
            vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: MEM as u64,
                userspace_addr: m as u64,
            })
        }
        .unwrap();
        // SAFETY: anonymous memory for the test, unmapped below.
        let lazy = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LAZY_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, libc::MAP_FAILED);
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe {
            vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 1,
                flags: 0,
                guest_phys_addr: LAZY_GPA,
                memory_size: LAZY_LEN as u64,
                userspace_addr: lazy as u64,
            })
        }
        .unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
        let part = vcpu.part();
        let mut lines = Vec::new();
        let mut wrong = Vec::new();
        let mut step = |vcpu: &mut VcpuFd, name: &str| {
            super::super::ffi::trace::begin();
            let t = std::time::Instant::now();
            let what = run_a_step(vcpu);
            let took = t.elapsed().as_secs_f64() * 1e6;
            let calls = super::super::ffi::trace::end();
            if !what.ends_with(&format!("IoOut {PORT:#x}")) {
                wrong.push(format!("{name}: the step did not reach its end: {what}"));
            }
            (lazy_exits(&calls).len(), took, what)
        };
        let host = lazy as usize;
        for (name, write) in [("read", false), ("then written", true)] {
            let before = process_memory();
            let (exits, took, _) = step(&mut vcpu, name);
            let after = process_memory();
            let process = match (before, after) {
                (Some(a), Some(b)) => format!("the process's commit {:+} KiB", (b.0 as i64 - a.0 as i64) / 1024),
                _ => "the process's commit not read".to_string(),
            };
            lines.push(format!(
                "lazy RAM, each 4 KiB page of 4 MiB {name} ({} accesses): {exits} exits of guest RAM; the step {took:.1} us; \
                 the slot committed {} KiB, resident {} KiB; {process}",
                if write { "1024 writes" } else { "1024 reads" },
                committed_bytes(host, LAZY_LEN) / 1024,
                resident_bytes(host, LAZY_LEN) / 1024
            ));
        }
        // One zero page, read only, at each of 1024 guest pages.
        // SAFETY: allocates a committed page, released below.
        let zero = unsafe { VirtualAlloc(std::ptr::null(), 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
        assert!(!zero.is_null());
        let mut map_times = Vec::new();
        let mut results = std::collections::BTreeMap::<String, u32>::new();
        for i in 0..u64::from(PAGES) {
            let t = std::time::Instant::now();
            // SAFETY: the page stays allocated while mapped; unmapped below.
            let hres = unsafe { whv::WHvMapGpaRange(part, zero, ZERO_GPA + i * 4096, 4096, whv::WHvMapGpaRangeFlagRead) };
            map_times.push(t.elapsed().as_secs_f64() * 1e6);
            *results.entry(format!("{:#010x}", hres.cast_unsigned())).or_default() += 1;
        }
        let spread = |mut t: Vec<f64>| {
            t.sort_by(f64::total_cmp);
            format!("median {:.1} us (least {:.1}, most {:.1})", t[t.len() / 2], t[0], t[t.len() - 1])
        };
        lines.push(format!(
            "one host page mapped read only at each of {PAGES} guest pages: HRESULTs {results:?}; each call {}",
            spread(map_times)
        ));
        let (exits, took, _) = step(&mut vcpu, "zero pages read");
        lines.push(format!("the zero-mapped pages read ({PAGES} reads): {exits} exits of guest RAM; the step {took:.1} us"));
        let (_, _, what) = step(&mut vcpu, "a write to a zero-mapped page");
        lines.push(format!("a guest write to a zero-mapped page: {what}"));
        // A page's mapping swapped for a writable one, as a write would
        // have it: unmapped, then the slot's own page mapped writable.
        let (mut unmaps, mut maps) = (Vec::new(), Vec::new());
        let mut swaps = std::collections::BTreeMap::<String, u32>::new();
        for i in 0..64u64 {
            let at = ZERO_GPA + i * 4096;
            let t = std::time::Instant::now();
            // SAFETY: a range mapped above.
            let a = unsafe { whv::WHvUnmapGpaRange(part, at, 4096) };
            unmaps.push(t.elapsed().as_secs_f64() * 1e6);
            let t = std::time::Instant::now();
            // SAFETY: a page of the lazy slot's memory, committed by the
            // write step, which stays mapped while the VM has it.
            let b = unsafe {
                whv::WHvMapGpaRange(
                    part,
                    (host + i as usize * 4096) as *const _,
                    at,
                    4096,
                    whv::WHvMapGpaRangeFlagRead | whv::WHvMapGpaRangeFlagWrite | whv::WHvMapGpaRangeFlagExecute,
                )
            };
            maps.push(t.elapsed().as_secs_f64() * 1e6);
            *swaps.entry(format!("{:#010x} {:#010x}", a.cast_unsigned(), b.cast_unsigned())).or_default() += 1;
        }
        lines.push(format!(
            "64 pages swapped to writable: HRESULTs (unmap, map) {swaps:?}; WHvUnmapGpaRange {}; WHvMapGpaRange {}",
            spread(unmaps),
            spread(maps)
        ));
        for l in &lines {
            eprintln!("ZEROREAD {l}");
        }
        // SAFETY: the ranges mapped above, unmapped before the VM goes.
        unsafe { whv::WHvUnmapGpaRange(part, ZERO_GPA, u64::from(PAGES) * 4096) };
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's memory, no VM left using it.
        unsafe {
            VirtualFree(zero, 0, MEM_RELEASE);
            assert_eq!(libc::munmap(lazy, LAZY_LEN), 0);
            assert_eq!(libc::munmap(m.cast(), MEM), 0);
        }
        for l in guest_writes_to_read_only_memory() {
            eprintln!("ZEROREAD {l}");
        }
        assert!(wrong.iter().all(|w| w.starts_with("a write to a zero-mapped page")), "{wrong:#?}");
    }

    /// The record for the per-page cost of lazy guest RAM (FIRSTTOUCH
    /// lines): what a guest's first write to a 4 KiB page of lazy guest RAM
    /// (anonymous `MAP_NORESERVE`, committed a page at a time) costs, set
    /// against Linux's 10.40 us a page (LINUXGRAIN, the linux-boot job:
    /// one 4 KiB page charged an anonymous fault, with the mTHP sizes the
    /// GUESTRAM host line prints), and what each way to make it cheaper
    /// that still charges the touched page only would cost. Each line names
    /// its build (CI runs this record in a debug and in a release build)
    /// and whether the WHP calls were traced (each kept,
    /// [`super::super::ffi::trace::begin`]); untraced, a step's run calls
    /// and lazy exits are only summed ([`super::super::ffi::trace::Split`]).
    /// 1024 accesses a step:
    /// - without L1 (the path before L1 was taken, "today's path" in the
    ///   lines made before it), `run` committing each page at its exit
    ///   (`commit_block_on_access`) and leaving its mapping to WHP's fault
    ///   in the re-run ([`super::super::vm::POPULATE_ONLY_HUGE_PAGES_FOR_TESTS`]),
    ///   untraced and then traced: the time a write; each lazy exit's run
    ///   call, the slot's lookup, the commit and the rest of the backend's
    ///   time; the commit and working set;
    /// - L1, the backend's path since: the same with WHP made to map each
    ///   page the exit committed (`WHvAdviseGpaRange(Populate)` of 4 KiB,
    ///   as of a huge page, `VmInner::populate_committed`) before the
    ///   re-run, which takes WHP's fault in the run on committed memory it
    ///   has not mapped (POPULATETEST) out of the run;
    /// - exit baselines: an `out` that exits, through `run` and through
    ///   `WHvRunVirtualProcessor` alone, the RIP set past it;
    /// - the path without L1 driven by `WHvRunVirtualProcessor` alone, the
    ///   commit and the re-run only: the least that path could take a page;
    /// - L3: guest pages not mapped in WHP at all, each exit committing
    ///   its host page and mapping it (`WHvMapGpaRange`, 4 KiB): the run
    ///   call, the commit and the map; then the same pages again (no exits
    ///   expected) and the `out` baseline again, after 1024 such mappings.
    ///
    /// Printed, not asserted, but for each step reaching its end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_first_touch_of_lazy_ram_by_way_on_record() {
        use super::super::ffi::trace;
        use std::time::Instant;
        use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};
        const PROGRAM: u64 = 0xB000;
        const PAGES: u32 = 1024;
        const PART: usize = 4 << 20;
        // Lazy guest RAM, a 4 MiB part a step (the sixth for the warm-up).
        const LAZY_GPA: u64 = 0x100_0000;
        const LAZY_LEN: usize = 6 * PART;
        // Guest RAM WHP does not map until an exit has it mapped (L3).
        const UNMAPPED_GPA: u64 = 0x400_0000;
        const UNMAPPED_LEN: usize = PART;
        const OTHER_PORT: u16 = 0x81;
        fn us(since: Instant) -> f64 {
            since.elapsed().as_secs_f64() * 1e6
        }
        fn spread(t: &[f64]) -> String {
            let mut t = t.to_vec();
            t.sort_by(f64::total_cmp);
            match t.len() {
                0 => "none".to_string(),
                n => format!("median {:.2} us (least {:.2}, most {:.2})", t[n / 2], t[0], t[n - 1]),
            }
        }
        fn each(total: f64, n: u32) -> f64 {
            if n == 0 { 0.0 } else { total / f64::from(n) }
        }
        let build = if cfg!(debug_assertions) { "debug build" } else { "release build" };
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        let mut gpa = LAZY_GPA;
        while gpa < UNMAPPED_GPA + UNMAPPED_LEN as u64 {
            put(m, 0x3000 + (gpa >> 21) * 8, &(gpa | 0x83).to_le_bytes());
            gpa += 2 << 20;
        }
        // mov edi, base; mov ecx, count; a byte written at rdi and rdi
        // moved a page on, count times; out 0x80, al.
        let writes = |base: u64, count: u32| {
            let mut b = vec![0xBF];
            b.extend_from_slice(&u32::try_from(base).unwrap().to_le_bytes());
            b.push(0xB9);
            b.extend_from_slice(&count.to_le_bytes());
            b.extend_from_slice(&[0xC6, 0x07, 0x01, 0x81, 0xC7, 0x00, 0x10, 0x00, 0x00, 0xFF, 0xC9, 0x75, 0xF3, 0xE6, PORT as u8]);
            b
        };
        // mov ecx, 1024; out 0x81, al, 1024 times; out 0x80, al.
        let outs = || {
            let mut b = vec![0xB9];
            b.extend_from_slice(&PAGES.to_le_bytes());
            b.extend_from_slice(&[0xE6, OTHER_PORT as u8, 0xFF, 0xC9, 0x75, 0xFA, 0xE6, PORT as u8]);
            b
        };
        let part_gpa = |i: usize| LAZY_GPA + (i * PART) as u64;
        let program = [
            writes(part_gpa(5), 1),
            outs(),
            writes(part_gpa(0), PAGES),
            writes(part_gpa(1), PAGES),
            writes(part_gpa(2), PAGES),
            writes(part_gpa(3), PAGES),
            outs(),
            writes(part_gpa(4), PAGES),
            writes(UNMAPPED_GPA, PAGES),
            writes(UNMAPPED_GPA, PAGES),
            outs(),
            vec![0xF4, 0xEB, 0xFD],
        ]
        .concat();
        put(m, PROGRAM, &program);
        // SAFETY: anonymous memory for the test, unmapped below.
        let lazy = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LAZY_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(lazy, libc::MAP_FAILED);
        for (slot, gpa, len, host) in [(0, 0, MEM, m as u64), (1, LAZY_GPA, LAZY_LEN, lazy as u64)] {
            // SAFETY: the memory stays mapped while the VM has it.
            unsafe {
                vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                    slot,
                    flags: 0,
                    guest_phys_addr: gpa,
                    memory_size: len as u64,
                    userspace_addr: host,
                })
            }
            .unwrap();
        }
        // SAFETY: reserved memory for the test, released below.
        let unmapped_host = unsafe { VirtualAlloc(std::ptr::null(), UNMAPPED_LEN, MEM_RESERVE, PAGE_READWRITE) } as usize;
        assert_ne!(unmapped_host, 0);
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
        let part = vcpu.part();
        let host = lazy as usize;
        let mut lines = Vec::new();
        let mut wrong = Vec::new();

        // A step through `run`, to the guest's `out 0x80`: the `out 0x81`s
        // on the way, what ended it if not that `out`, and its time.
        let through_run = |vcpu: &mut VcpuFd| {
            let watchdog = super::Watchdog::arm(vcpu);
            let t = Instant::now();
            let mut outs = 0u32;
            let end = loop {
                match vcpu.run() {
                    Ok(VcpuExit::IoOut(PORT, _)) => break None,
                    Ok(VcpuExit::IoOut(OTHER_PORT, _)) => outs += 1,
                    Ok(VcpuExit::IoOut(port, _)) => break Some(format!("IoOut {port:#x}")),
                    Ok(VcpuExit::Hlt) => break Some("Hlt".to_string()),
                    Ok(VcpuExit::Shutdown) => break Some("Shutdown".to_string()),
                    Ok(_) => break Some("another exit".to_string()),
                    Err(e) if e.errno() == libc::EINTR => break Some("none within 5 s (kicked)".to_string()),
                    Err(e) => break Some(format!("run failed, errno {}", e.errno())),
                }
            };
            let took = us(t);
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            (outs, end, took)
        };
        // A step driven by `WHvRunVirtualProcessor` alone: each run call's
        // time by its exit (an `out 0x81`, a memory exit), the test's time
        // after each (the RIP set past an `out`, `memory`'s for a memory
        // exit), what ended it if not the `out 0x80`, and its time.
        #[derive(Default)]
        struct Raw {
            out_runs: Vec<f64>,
            memory_runs: Vec<f64>,
            unmapped: u32,
            out_after: f64,
            memory_after: f64,
            end: Option<String>,
            took: f64,
        }
        let raw = |vcpu: &mut VcpuFd, memory: &mut dyn FnMut(u64, bool, bool) -> std::result::Result<(), String>| {
            let watchdog = super::Watchdog::arm(vcpu);
            let (part, vp) = (vcpu.part(), vcpu.vp());
            let mut r = Raw::default();
            let t = Instant::now();
            let end = loop {
                if r.out_runs.len() + r.memory_runs.len() > 4 * PAGES as usize {
                    break Some("more exits than the step has accesses".to_string());
                }
                if vcpu.shared.immediate_exit.load(Ordering::SeqCst) != 0 {
                    break Some("none within 5 s (kicked)".to_string());
                }
                let t0 = Instant::now();
                let ctx = match super::super::ffi::run_vp(part, vp) {
                    Ok(c) => c,
                    Err(e) => break Some(format!("run failed, errno {}", e.errno())),
                };
                let run = us(t0);
                let t1 = Instant::now();
                match ctx.ExitReason {
                    whv::WHvRunVpExitReasonX64IoPortAccess => {
                        // SAFETY: the union arm matches the exit reason.
                        let port = unsafe { ctx.Anonymous.IoPortAccess.PortNumber };
                        let next = ctx.VpContext.Rip + super::super::exit::instruction_length(ctx.VpContext._bitfield);
                        if let Err(e) = regs::set_rip(part, vp, next) {
                            break Some(format!("the RIP not set, errno {}", e.errno()));
                        }
                        if port == PORT {
                            break None;
                        }
                        if port != OTHER_PORT {
                            break Some(format!("IoOut {port:#x}"));
                        }
                        r.out_runs.push(run);
                        r.out_after += us(t1);
                    }
                    whv::WHvRunVpExitReasonMemoryAccess => {
                        // SAFETY: as above; the access-info bitfield overlaps the u32.
                        let (gpa, info) = unsafe { (ctx.Anonymous.MemoryAccess.Gpa, ctx.Anonymous.MemoryAccess.AccessInfo.AsUINT32) };
                        // `WHV_MEMORY_ACCESS_INFO`: AccessType in bits 0-1, GpaUnmapped bit 2.
                        let unmapped = info & 4 != 0;
                        if let Err(e) = memory(gpa, info & 3 == 1, unmapped) {
                            break Some(e);
                        }
                        r.memory_runs.push(run);
                        r.unmapped += u32::from(unmapped);
                        r.memory_after += us(t1);
                    }
                    reason => break Some(format!("exit reason {reason:#x} at RIP {:#x}", ctx.VpContext.Rip)),
                }
            };
            r.end = end;
            r.took = us(t);
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            r
        };
        let mut ended = |name: &str, end: Option<String>| {
            if let Some(e) = end {
                wrong.push(format!("{name}: the step did not reach its end: {e}"));
            }
        };

        // The thread's first lazy exit is a warm-up of its own (0.9 to 7.1
        // ms on a PC, LAZYGRAIN).
        let (_, end, took) = through_run(&mut vcpu);
        ended("warm-up", end);
        lines.push(format!("{build}, untraced: warm-up, the thread's first write to lazy guest RAM, the step {took:.1} us"));
        let (outs, end, took) = through_run(&mut vcpu);
        ended("out through run", end);
        lines.push(format!(
            "{build}, untraced: an out that exits, through run, {} times: {:.2} us a round trip",
            outs + 1,
            took / f64::from(outs + 1)
        ));
        for (way, first, populate) in [("without L1, the path before it", 0, false), ("L1, each page populated before the re-run", 2, true)] {
            for (traced, i) in [(false, first), (true, first + 1)] {
                let at = host + i * PART;
                let before = process_memory();
                super::super::vm::POPULATE_ONLY_HUGE_PAGES_FOR_TESTS.set(!populate);
                if traced {
                    trace::begin();
                }
                trace::split_begin();
                let (_, end, took) = through_run(&mut vcpu);
                let s = trace::split_end();
                let calls = if traced { trace::end() } else { Vec::new() };
                super::super::vm::POPULATE_ONLY_HUGE_PAGES_FOR_TESTS.set(false);
                let after = process_memory();
                ended(way, end);
                let process = match (before, after) {
                    (Some(a), Some(b)) => format!("the process's commit {:+} KiB", (b.0 as i64 - a.0 as i64) / 1024),
                    _ => "the process's commit not read".to_string(),
                };
                let rest = took - s.run_us - s.lookup_us - s.commit_us - s.populate_us;
                let mut line = format!(
                    "{build}, {}: {way}, a write to each of {PAGES} untouched pages through run: {:.2} us a write; \
                     {} run calls, {:.2} us each; {} lazy exits, each: the slot's lookup {:.2} us, the commit {:.2} \
                     us, the populate {:.2} us, the rest of the backend {:.2} us; the part committed {} KiB, resident \
                     {} KiB; {process}",
                    if traced { "traced" } else { "untraced" },
                    took / f64::from(PAGES),
                    s.runs,
                    each(s.run_us, s.runs),
                    s.lazy,
                    each(s.lookup_us, s.lazy),
                    each(s.commit_us, s.lazy),
                    each(s.populate_us, s.lazy),
                    each(rest, s.lazy),
                    committed_bytes(at, PART) / 1024,
                    resident_bytes(at, PART) / 1024
                );
                if traced {
                    let exits = lazy_exits(&calls);
                    let n = exits.len().max(1) as f64;
                    line += &format!(
                        "; the trace's {} lazy exits, each {:.2} us in its run call and {:.2} us in the backend after it",
                        exits.len(),
                        exits.iter().map(|e| e.0).sum::<f64>() / n,
                        exits.iter().map(|e| e.1).sum::<f64>() / n
                    );
                }
                lines.push(line);
            }
        }
        let mut no_memory = |gpa: u64, _: bool, _: bool| -> std::result::Result<(), String> { Err(format!("a memory exit at {gpa:#x}")) };
        let out_line = |r: &Raw, when: &str| {
            format!(
                "{build}, untraced: an out that exits, WHvRunVirtualProcessor alone, {} times{when}: the run call {}; \
                 the RIP set after it {:.2} us; {:.2} us a round trip",
                r.out_runs.len() + 1,
                spread(&r.out_runs),
                each(r.out_after, r.out_runs.len() as u32),
                r.took / (r.out_runs.len() + 1) as f64
            )
        };
        let r = raw(&mut vcpu, &mut no_memory);
        ended("out, WHvRunVirtualProcessor alone", r.end.clone());
        lines.push(out_line(&r, ""));
        let mut commit_today = |gpa: u64, write: bool, unmapped: bool| {
            if unmapped || !(LAZY_GPA..LAZY_GPA + LAZY_LEN as u64).contains(&gpa) {
                return Err(format!("a memory exit at {gpa:#x} outside lazy guest RAM"));
            }
            match libc::wick_mm::commit_block_on_access(host + (gpa - LAZY_GPA) as usize, write) {
                (libc::wick_mm::Access::Committed, _) => Ok(()),
                _ => Err(format!("{gpa:#x} not committed")),
            }
        };
        let r = raw(&mut vcpu, &mut commit_today);
        ended("without L1, WHvRunVirtualProcessor alone", r.end.clone());
        lines.push(format!(
            "{build}, untraced: without L1, a write to each of {PAGES} untouched pages, WHvRunVirtualProcessor alone \
             with the commit: {:.2} us a write; {} memory exits, the run call {}, the commit after it {:.2} us; the part \
             committed {} KiB, resident {} KiB",
            r.took / f64::from(PAGES),
            r.memory_runs.len(),
            spread(&r.memory_runs),
            each(r.memory_after, r.memory_runs.len() as u32),
            committed_bytes(host + 4 * PART, PART) / 1024,
            resident_bytes(host + 4 * PART, PART) / 1024
        ));
        let (mut commits, mut maps, mut results) = (Vec::new(), Vec::new(), std::collections::BTreeMap::<String, u32>::new());
        let mut commit_and_map = |gpa: u64, _: bool, unmapped: bool| {
            if !unmapped || !(UNMAPPED_GPA..UNMAPPED_GPA + UNMAPPED_LEN as u64).contains(&gpa) {
                return Err(format!("a memory exit at {gpa:#x}, unmapped {unmapped}"));
            }
            let page = gpa & !0xFFF;
            let t = Instant::now();
            // SAFETY: a page of the reservation above, released below.
            let p = unsafe { VirtualAlloc((unmapped_host + (page - UNMAPPED_GPA) as usize) as *const _, 4096, MEM_COMMIT, PAGE_READWRITE) };
            commits.push(us(t));
            if p.is_null() {
                return Err(format!("the commit for {page:#x} failed"));
            }
            let t = Instant::now();
            // SAFETY: a committed page that stays so while the VM has it;
            // unmapped below.
            let hres = unsafe {
                whv::WHvMapGpaRange(
                    part,
                    p,
                    page,
                    4096,
                    whv::WHvMapGpaRangeFlagRead | whv::WHvMapGpaRangeFlagWrite | whv::WHvMapGpaRangeFlagExecute,
                )
            };
            maps.push(us(t));
            *results.entry(format!("{:#010x}", hres.cast_unsigned())).or_default() += 1;
            if hres != 0 {
                return Err(format!("WHvMapGpaRange of {page:#x}: {:#010x}", hres.cast_unsigned()));
            }
            Ok(())
        };
        let l3 = raw(&mut vcpu, &mut commit_and_map);
        ended("L3", l3.end.clone());
        let again = raw(&mut vcpu, &mut no_memory);
        ended("L3's pages again", again.end.clone());
        let after = raw(&mut vcpu, &mut no_memory);
        ended("out after L3", after.end.clone());
        let tail = maps.len().saturating_sub(64);
        lines.push(format!(
            "{build}, untraced: L3, guest pages not mapped in WHP, a write to each of {PAGES}, WHvRunVirtualProcessor \
             alone with a commit and a 4 KiB WHvMapGpaRange at each exit: {:.2} us a write; {} memory exits ({} of \
             them of an unmapped GPA), the run call {}, the commit {}, the map {} (the first 64 {}, the last 64 {}), \
             HRESULTs {results:?}, the test's time after the run call {:.2} us; the range committed {} KiB, resident \
             {} KiB",
            l3.took / f64::from(PAGES),
            l3.memory_runs.len(),
            l3.unmapped,
            spread(&l3.memory_runs),
            spread(&commits),
            spread(&maps),
            spread(&maps[..maps.len().min(64)]),
            spread(&maps[tail..]),
            each(l3.memory_after, l3.memory_runs.len() as u32),
            committed_bytes(unmapped_host, UNMAPPED_LEN) / 1024,
            resident_bytes(unmapped_host, UNMAPPED_LEN) / 1024
        ));
        lines.push(format!(
            "{build}, untraced: L3's {PAGES} pages written again: {} memory exits, {:.2} us a write",
            again.memory_runs.len(),
            again.took / f64::from(PAGES)
        ));
        lines.push(out_line(&after, ", after the 1024 mappings of 4 KiB"));
        for l in &lines {
            eprintln!("FIRSTTOUCH {l}");
        }
        // SAFETY: the ranges mapped above, unmapped before the VM goes.
        unsafe { whv::WHvUnmapGpaRange(part, UNMAPPED_GPA, UNMAPPED_LEN as u64) };
        drop(vcpu);
        drop(vm);
        // SAFETY: the test's memory, no VM left using it.
        unsafe {
            VirtualFree(unmapped_host as *mut _, 0, MEM_RELEASE);
            assert_eq!(libc::munmap(lazy, LAZY_LEN), 0);
            assert_eq!(libc::munmap(m.cast(), MEM), 0);
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// The guest's side of the section records (SECTREC-a WHP and SECTREC-c
    /// WHP lines; libc's `windows_sectrec` has the host's): guest RAM in a
    /// view of a section, as Layer 1 of the section charge would have it.
    /// - a pagefile-backed section made `SEC_RESERVE`, its view mapped in
    ///   WHP (`WHvMapGpaRange`) with no page committed: the HRESULT; then
    ///   the guest writing 16 of its pages: the exit each makes (its kind,
    ///   and whether WHP calls the GPA unmapped), the page committed on the
    ///   view (`VirtualAlloc`) and the run again;
    /// - a file section (wick's memfd, a temporary file deleted on close),
    ///   its view made no-access and mapped in WHP: the same, with the page
    ///   opened (`VirtualProtect`, read-write) at each exit, and the writes
    ///   read through another view of the file.
    ///
    /// Each: the exits' run calls and the test's handling, and the view's
    /// commit after. Printed, not asserted, but for each step's end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_guest_ram_in_sections_on_record() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use std::time::Instant;
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualProtect, FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS,
            MEM_COMMIT, PAGE_NOACCESS, PAGE_READWRITE, SEC_RESERVE,
        };
        const PROGRAM: u64 = 0xB000;
        const LEN: usize = 4 << 20;
        const SECTION_GPA: u64 = 0x400_0000;
        const FILE_GPA: u64 = 0x500_0000;
        const PAGES: u32 = 16;
        fn us(since: Instant) -> f64 {
            since.elapsed().as_secs_f64() * 1e6
        }
        fn spread(t: &[f64]) -> String {
            let mut t = t.to_vec();
            t.sort_by(f64::total_cmp);
            match t.len() {
                0 => "none".to_string(),
                n => format!("median {:.2} us (least {:.2}, most {:.2})", t[n / 2], t[0], t[n - 1]),
            }
        }
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        for gpa in [SECTION_GPA, SECTION_GPA + (2 << 20), FILE_GPA, FILE_GPA + (2 << 20)] {
            put(m, 0x3000 + (gpa >> 21) * 8, &(gpa | 0x83).to_le_bytes());
        }
        // mov edi, base; mov ecx, 16; a byte written at rdi and rdi moved
        // a page on, 16 times; out 0x80, al.
        let writes = |base: u64| {
            let mut b = vec![0xBF];
            b.extend_from_slice(&u32::try_from(base).unwrap().to_le_bytes());
            b.push(0xB9);
            b.extend_from_slice(&PAGES.to_le_bytes());
            b.extend_from_slice(&[0xC6, 0x07, 0x01, 0x81, 0xC7, 0x00, 0x10, 0x00, 0x00, 0xFF, 0xC9, 0x75, 0xF3, 0xE6, PORT as u8]);
            b
        };
        put(m, PROGRAM, &[writes(SECTION_GPA), writes(FILE_GPA), vec![0xF4, 0xEB, 0xFD]].concat());
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe {
            vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: MEM as u64,
                userspace_addr: m as u64,
            })
        }
        .unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
        let (part, vp) = (vcpu.part(), vcpu.vp());
        let view = |s: windows_sys::Win32::Foundation::HANDLE| {
            // SAFETY: maps the test's section anywhere; checked.
            let v = unsafe { MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, LEN) }.Value as usize;
            assert_ne!(v, 0, "MapViewOfFile: {}", std::io::Error::last_os_error());
            v
        };
        let rwx = whv::WHvMapGpaRangeFlagRead | whv::WHvMapGpaRangeFlagWrite | whv::WHvMapGpaRangeFlagExecute;
        // SAFETY: an unnamed pagefile-backed section, closed below.
        let section = unsafe {
            CreateFileMappingW(windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE | SEC_RESERVE, 0, LEN as u32, std::ptr::null())
        };
        assert!(!section.is_null());
        let reserved = view(section);
        let path = std::env::temp_dir().join(format!("wick-sectrec-whp-{}.tmp", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .attributes(0x100) // FILE_ATTRIBUTE_TEMPORARY
            .custom_flags(0x0400_0000) // FILE_FLAG_DELETE_ON_CLOSE
            .open(&path)
            .unwrap();
        file.set_len(LEN as u64).unwrap();
        // SAFETY: a section of the whole file, closed below.
        let file_section = unsafe { CreateFileMappingW(file.as_raw_handle(), std::ptr::null(), PAGE_READWRITE, 0, 0, std::ptr::null()) };
        assert!(!file_section.is_null());
        let (noaccess, reader) = (view(file_section), view(file_section));
        let mut old = 0;
        // SAFETY: the test's view.
        let protected = unsafe { VirtualProtect(noaccess as *const _, LEN, PAGE_NOACCESS, &mut old) } != 0;
        let mut lines = Vec::new();
        let mut wrong = Vec::new();
        for (name, gpa, host) in [("SECTREC-a WHP, a SEC_RESERVE section's view", SECTION_GPA, reserved), ("SECTREC-c WHP, a memfd's no-access view", FILE_GPA, noaccess)] {
            // SAFETY: the view stays mapped while the VM has it; unmapped below.
            let hres = unsafe { whv::WHvMapGpaRange(part, host as *const _, gpa, LEN as u64, rwx) };
            let mut line = format!(
                "{name}: WHvMapGpaRange of its 4 MiB {:#010x}{}",
                hres.cast_unsigned(),
                if gpa == FILE_GPA { format!(" (the view made no-access: {protected})") } else { String::new() }
            );
            if hres != 0 {
                lines.push(line + "; not run");
                // The guest's pass over it would not end: step past it.
                let past = writes(0).len() as u64 * if gpa == SECTION_GPA { 1 } else { 2 };
                vcpu.set_regs(&kvm_regs { rip: PROGRAM + past, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
                continue;
            }
            let watchdog = super::Watchdog::arm(&vcpu);
            let (mut runs, mut handling, mut kinds) = (Vec::new(), Vec::new(), std::collections::BTreeMap::<String, u32>::new());
            let end = loop {
                if runs.len() > 4 * PAGES as usize {
                    break "more exits than the step has writes".to_string();
                }
                if vcpu.shared.immediate_exit.load(Ordering::SeqCst) != 0 {
                    break "none within 5 s (kicked)".to_string();
                }
                let t = Instant::now();
                let ctx = match super::super::ffi::run_vp(part, vp) {
                    Ok(c) => c,
                    Err(e) => break format!("run failed, errno {}", e.errno()),
                };
                runs.push(us(t));
                let t = Instant::now();
                match ctx.ExitReason {
                    whv::WHvRunVpExitReasonX64IoPortAccess => {
                        let next = ctx.VpContext.Rip + super::super::exit::instruction_length(ctx.VpContext._bitfield);
                        regs::set_rip(part, vp, next).unwrap();
                        runs.pop();
                        break "its out".to_string();
                    }
                    whv::WHvRunVpExitReasonMemoryAccess => {
                        // SAFETY: the union arm matches the exit reason; the access-info bitfield overlaps the u32.
                        let (at, info) = unsafe { (ctx.Anonymous.MemoryAccess.Gpa, ctx.Anonymous.MemoryAccess.AccessInfo.AsUINT32) };
                        let kind = format!(
                            "a memory access, {}{}",
                            ["read", "write", "execute", "type 3"][(info & 3) as usize],
                            if info & 4 != 0 { ", the GPA unmapped" } else { "" }
                        );
                        *kinds.entry(kind).or_default() += 1;
                        if !(gpa..gpa + LEN as u64).contains(&at) {
                            break format!("a memory exit at {at:#x}, outside the view");
                        }
                        let page = host + ((at - gpa) & !0xFFF) as usize;
                        let done = if gpa == SECTION_GPA {
                            // SAFETY: a page of the test's view.
                            !unsafe { VirtualAlloc(page as *const _, 4096, MEM_COMMIT, PAGE_READWRITE) }.is_null()
                        } else {
                            // SAFETY: as above.
                            let opened = unsafe { VirtualProtect(page as *const _, 4096, PAGE_READWRITE, &mut old) };
                            opened != 0
                        };
                        handling.push(us(t));
                        if !done {
                            break format!("the page at {page:#x} not opened: {}", std::io::Error::last_os_error());
                        }
                    }
                    reason => break format!("exit reason {reason:#x} at RIP {:#x}", ctx.VpContext.Rip),
                }
            };
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            if end != "its out" {
                wrong.push(format!("{name}: {end}"));
            }
            line += &format!(
                "; the guest's {PAGES} writes: ended by {end}; {} exits {kinds:?}, the run call {}, the test's {} after it {}",
                runs.len(),
                spread(&runs),
                if gpa == SECTION_GPA { "commit (VirtualAlloc on the view)" } else { "open (VirtualProtect)" },
                spread(&handling)
            );
            if gpa == SECTION_GPA {
                line += &format!("; the view committed after: {} KiB", committed_bytes(reserved, LEN) / 1024);
            } else {
                let seen = (0..PAGES as usize)
                    // SAFETY: a page of the test's other view, read-write.
                    .filter(|&i| unsafe { ((reader + i * 4096) as *const u8).read_volatile() } == 1)
                    .count();
                line += &format!("; the other view reads {seen} of the {PAGES} writes");
            }
            lines.push(line);
        }
        for l in &lines {
            eprintln!("{l}");
        }
        // SAFETY: the ranges mapped above, unmapped before the VM goes;
        // then the test's views and sections.
        unsafe {
            whv::WHvUnmapGpaRange(part, SECTION_GPA, LEN as u64);
            whv::WHvUnmapGpaRange(part, FILE_GPA, LEN as u64);
        }
        drop(vcpu);
        drop(vm);
        // SAFETY: as above.
        unsafe {
            for v in [reserved, noaccess, reader] {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: v as *mut _ });
            }
            windows_sys::Win32::Foundation::CloseHandle(section);
            windows_sys::Win32::Foundation::CloseHandle(file_section);
            assert_eq!(libc::munmap(m.cast(), MEM), 0);
        }
        drop(file);
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// UFFDCHUNK (a), for the W2 plan's "Discarded userfaultfd pages" part
    /// (2): whether WHP follows the host's virtual addresses when the
    /// section under a mapped GPA range is swapped, or keeps the pages it
    /// was given at `WHvMapGpaRange`, and what a remap costs. Two 2 MiB
    /// chunks of a 4 MiB placeholder (`VirtualAlloc2`
    /// `MEM_RESERVE_PLACEHOLDER`, split by `VirtualFree(MEM_RELEASE |
    /// MEM_PRESERVE_PLACEHOLDER)`), each a pagefile section of its own
    /// (A filled 0xAA, B 0xBB) mapped with `MapViewOfFile3`
    /// (`MEM_REPLACE_PLACEHOLDER`), each section also mapped elsewhere for
    /// the host to look through; the 4 MiB mapped in WHP read, write and
    /// execute with dirty tracking, in one call (its HRESULT; per chunk if
    /// it is refused). Then the guest's reads and writes, each the guest's
    /// own step ending at an `out`, or the exit it makes instead:
    /// 1. chunk 0's and chunk 1's first byte;
    /// 2. chunk 0's view unmapped back to its placeholder
    ///    (`UnmapViewOfFile2(MEM_PRESERVE_PLACEHOLDER)`; its result): chunk
    ///    0's first byte;
    /// 3. a new section C (0xCC) mapped into the placeholder, nothing told
    ///    WHP: chunk 0's first byte;
    /// 4. a write of 0x5A at chunk 0 + 8 and chunk 1's first byte: where the
    ///    write landed (A's and C's other views), and the dirty bitmap;
    /// 5. chunk 0 mapped again in WHP (`WHvMapGpaRange` over the mapping,
    ///    which Learn says "replaces any previous mappings for the
    ///    specified GPA pages"; its time and HRESULT, and an unmap first if
    ///    it is refused): chunk 0's first byte and chunk 0 + 8;
    /// 6. a write of 0x6B at chunk 0 + 16, read back: where it landed, and
    ///    the dirty bitmap;
    ///
    /// then 100 swaps of chunk 0 (the view unmapped to its placeholder, a
    /// new section mapped into it, its handle closed) each followed by its
    /// remap in WHP, both timed, and the guest's read of the last one's
    /// byte. Printed, not asserted, but for each step's end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_a_replaced_backing_under_mapped_guest_ram_on_record() {
        use std::time::Instant;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, MapViewOfFile, MapViewOfFile3, UnmapViewOfFile, UnmapViewOfFile2, VirtualAlloc2, VirtualFree,
            FILE_MAP_ALL_ACCESS, MEMORY_MAPPED_VIEW_ADDRESS, MEM_PRESERVE_PLACEHOLDER, MEM_RELEASE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE,
            MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, PAGE_READWRITE,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        const PROGRAM: u64 = 0xB000;
        const CHUNK: usize = 2 << 20;
        const GPA: u64 = 0x400_0000;
        fn us(since: Instant) -> f64 {
            since.elapsed().as_secs_f64() * 1e6
        }
        fn spread(t: &[f64]) -> String {
            let mut t = t.to_vec();
            t.sort_by(f64::total_cmp);
            match t.len() {
                0 => "none".to_string(),
                n => format!("median {:.2} us (least {:.2}, most {:.2})", t[n / 2], t[0], t[n - 1]),
            }
        }
        let err = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // SAFETY: plain call.
        let me = unsafe { GetCurrentProcess() };
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        for gpa in [GPA, GPA + CHUNK as u64] {
            put(m, 0x3000 + (gpa >> 21) * 8, &(gpa | 0x83).to_le_bytes());
        }
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe {
            vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: MEM as u64,
                userspace_addr: m as u64,
            })
        }
        .unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        start(&vcpu);
        let (part, vp) = (vcpu.part(), vcpu.vp());
        // A section of a chunk, filled with `fill`, and a view of it for the host.
        let section = |fill: u8| -> (HANDLE, usize) {
            // SAFETY: an unnamed pagefile-backed section, committed; mapped anywhere and checked.
            unsafe {
                let s = CreateFileMappingW(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE, 0, CHUNK as u32, std::ptr::null());
                assert!(!s.is_null(), "CreateFileMappingW: error {}", err());
                let v = MapViewOfFile(s, FILE_MAP_ALL_ACCESS, 0, 0, CHUNK).Value as usize;
                assert_ne!(v, 0, "MapViewOfFile: error {}", err());
                std::ptr::write_bytes(v as *mut u8, fill, CHUNK);
                (s, v)
            }
        };
        let place = |s: HANDLE, at: usize| {
            // SAFETY: maps the test's section into the test's placeholder.
            let v = unsafe { MapViewOfFile3(s, me, at as *const _, 0, CHUNK, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, std::ptr::null_mut(), 0) };
            assert_eq!(v.Value as usize, at, "MapViewOfFile3: error {}", err());
        };
        let unplace = |at: usize| {
            // SAFETY: the test's view, back to its placeholder.
            let ok = unsafe { UnmapViewOfFile2(me, MEMORY_MAPPED_VIEW_ADDRESS { Value: at as *mut _ }, MEM_PRESERVE_PLACEHOLDER) } != 0;
            if ok { "done".to_string() } else { format!("refused, error {}", err()) }
        };
        // SAFETY: a placeholder of the test's own, split at its middle.
        let base = unsafe { VirtualAlloc2(me, std::ptr::null(), 2 * CHUNK, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, std::ptr::null_mut(), 0) } as usize;
        assert_ne!(base, 0, "VirtualAlloc2: error {}", err());
        // SAFETY: as above.
        assert_ne!(unsafe { VirtualFree(base as *mut _, CHUNK, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) }, 0, "split: error {}", err());
        let (a, a_view) = section(0xAA);
        let (b, b_view) = section(0xBB);
        place(a, base);
        place(b, base + CHUNK);
        let rwx = whv::WHvMapGpaRangeFlagRead | whv::WHvMapGpaRangeFlagWrite | whv::WHvMapGpaRangeFlagExecute | whv::WHvMapGpaRangeFlagTrackDirtyPages;
        let map = |host: usize, gpa: u64, len: usize| {
            // SAFETY: the test's views stay mapped while the range is (unmapped below).
            unsafe { whv::WHvMapGpaRange(part, host as *const _, gpa, len as u64, rwx) }
        };
        let mut lines = Vec::new();
        let mut wrong = Vec::new();
        let whole = map(base, GPA, 2 * CHUNK);
        let mut line = format!("WHvMapGpaRange of the 4 MiB over two views in one call {:#010x}", whole.cast_unsigned());
        if whole != 0 {
            let (h0, h1) = (map(base, GPA, CHUNK), map(base + CHUNK, GPA + CHUNK as u64, CHUNK));
            line += &format!("; a chunk a call {:#010x}, {:#010x}", h0.cast_unsigned(), h1.cast_unsigned());
        }
        lines.push(line);
        // One guest step: `code` then `out PORT, al`, run until its out or
        // another exit: AL at the out, or the exit.
        let mut step = |code: &[u8]| -> String {
            put(m, PROGRAM, &[code, &[0xE6, PORT as u8, 0xF4]].concat());
            vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
            let watchdog = super::Watchdog::arm(&vcpu);
            let end = match super::super::ffi::run_vp(part, vp) {
                Err(e) => format!("run failed, errno {}", e.errno()),
                Ok(ctx) => match ctx.ExitReason {
                    whv::WHvRunVpExitReasonX64IoPortAccess => {
                        // SAFETY: the union arm matches the exit reason.
                        format!("AL {:#04x}", unsafe { ctx.Anonymous.IoPortAccess.Rax } & 0xff)
                    }
                    whv::WHvRunVpExitReasonMemoryAccess => {
                        // SAFETY: the union arm matches the exit reason; the access-info bitfield overlaps the u32.
                        let (at, info) = unsafe { (ctx.Anonymous.MemoryAccess.Gpa, ctx.Anonymous.MemoryAccess.AccessInfo.AsUINT32) };
                        format!(
                            "a memory access exit at {at:#x}, {}{}",
                            ["read", "write", "execute", "type 3"][(info & 3) as usize],
                            if info & 4 != 0 { ", the GPA unmapped" } else { "" }
                        )
                    }
                    whv::WHvRunVpExitReasonCanceled => "none within 5 s (kicked)".to_string(),
                    reason => format!("exit reason {reason:#x} at RIP {:#x}", ctx.VpContext.Rip),
                },
            };
            drop(watchdog);
            vcpu.set_kvm_immediate_exit(0);
            end
        };
        let at = |off: u64| u32::try_from(GPA + off).unwrap().to_le_bytes();
        // mov al, [addr]
        let read = |off: u64| [&[0x8A, 0x04, 0x25][..], &at(off)].concat();
        // mov byte [addr], v
        let write = |off: u64, v: u8| [&[0xC6, 0x04, 0x25][..], &at(off), &[v]].concat();
        let dirty = || {
            let mut bitmap = [0u64; 16];
            // SAFETY: a bitmap of 1024 pages' bits for the 4 MiB.
            let h = unsafe { whv::WHvQueryGpaRangeDirtyBitmap(part, GPA, 2 * CHUNK as u64, bitmap.as_mut_ptr(), 128) };
            let pages: Vec<usize> = (0..1024).filter(|i| bitmap[i / 64] & (1 << (i % 64)) != 0).collect();
            format!("dirty bitmap {:#010x}: pages {pages:?}", h.cast_unsigned())
        };
        let host = |v: usize, off: usize| {
            // SAFETY: a byte of one of the test's host views.
            unsafe { ((v + off) as *const u8).read_volatile() }
        };
        let base_dirty = dirty();
        lines.push(format!(
            "1: chunk 0 reads {}, chunk 1 reads {} (A was filled 0xaa, B 0xbb); before it, {base_dirty}",
            step(&read(0)),
            step(&read(CHUNK as u64))
        ));
        let unmapped = unplace(base);
        lines.push(format!("2: chunk 0's view unmapped to its placeholder: {unmapped}; chunk 0 reads {}", step(&read(0))));
        if unmapped != "done" {
            // The rest swaps a view WHP holds: not run.
            for l in &lines {
                eprintln!("UFFDCHUNK {l}");
            }
            panic!("UFFDCHUNK chunk 0's view not unmapped while WHP maps it: {unmapped}");
        }
        let (c, c_view) = section(0xCC);
        place(c, base);
        lines.push(format!("3: section C (0xcc) mapped into the placeholder, WHP not told: chunk 0 reads {}", step(&read(0))));
        let wrote = step(&[write(8, 0x5A), read(CHUNK as u64)].concat());
        lines.push(format!(
            "4: 0x5a written at chunk 0 + 8, then chunk 1 read: {wrote}; A's other view reads {:#04x} there, C's {:#04x}; {}",
            host(a_view, 8),
            host(c_view, 8),
            dirty()
        ));
        let t = Instant::now();
        let mut remap = map(base, GPA, CHUNK);
        let remap_us = us(t);
        let mut line = format!("5: chunk 0 mapped again over its mapping: {:#010x} in {remap_us:.1} us", remap.cast_unsigned());
        if remap != 0 {
            let t = Instant::now();
            // SAFETY: the test's range.
            let u = unsafe { whv::WHvUnmapGpaRange(part, GPA, CHUNK as u64) };
            remap = map(base, GPA, CHUNK);
            line += &format!("; unmapped ({:#010x}) and mapped ({:#010x}) in {:.1} us", u.cast_unsigned(), remap.cast_unsigned(), us(t));
        }
        lines.push(format!("{line}; chunk 0 reads {}, chunk 0 + 8 reads {}", step(&read(0)), step(&read(8))));
        let wrote = step(&[write(16, 0x6B), read(16)].concat());
        lines.push(format!(
            "6: 0x6b written at chunk 0 + 16 and read back: {wrote}; A's other view reads {:#04x} there, C's {:#04x}; {}",
            host(a_view, 16),
            host(c_view, 16),
            dirty()
        ));
        // SAFETY: the test's own section handle; C's views keep it.
        unsafe { CloseHandle(c) };
        let (mut swaps, mut remaps, mut refused) = (Vec::new(), Vec::new(), 0);
        let mut last = 0;
        for i in 0..100u8 {
            let t = Instant::now();
            let unmapped = unplace(base);
            assert_eq!(unmapped, "done", "swap {i}");
            // SAFETY: an unnamed pagefile-backed section; checked; its handle closed once mapped.
            let s = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, std::ptr::null(), PAGE_READWRITE, 0, CHUNK as u32, std::ptr::null()) };
            assert!(!s.is_null(), "CreateFileMappingW: error {}", err());
            place(s, base);
            // SAFETY: as above.
            unsafe { CloseHandle(s) };
            swaps.push(us(t));
            // SAFETY: the new view, read-write.
            unsafe { (base as *mut u8).write_volatile(i) };
            last = i;
            let t = Instant::now();
            if map(base, GPA, CHUNK) != 0 {
                refused += 1;
            }
            remaps.push(us(t));
        }
        lines.push(format!(
            "100 swaps of chunk 0's section: the swap {}, its remap in WHP {} ({refused} refused); chunk 0 then reads {} (the last section's byte {last:#04x})",
            spread(&swaps),
            spread(&remaps),
            step(&read(0))
        ));
        for l in &lines {
            eprintln!("UFFDCHUNK {l}");
        }
        for (n, l) in lines.iter().enumerate().skip(1) {
            if l.contains("run failed") || l.contains("kicked") || l.contains("exit reason") {
                wrong.push(format!("line {n}: {l}"));
            }
        }
        // SAFETY: the range mapped above, unmapped before the VM goes; then
        // the test's views, placeholders and sections.
        unsafe {
            whv::WHvUnmapGpaRange(part, GPA, 2 * CHUNK as u64);
        }
        drop(vcpu);
        drop(vm);
        // SAFETY: as above.
        unsafe {
            for v in [base, base + CHUNK, a_view, b_view, c_view] {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: v as *mut _ });
            }
            CloseHandle(a);
            CloseHandle(b);
            assert_eq!(libc::munmap(m.cast(), MEM), 0);
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// ZEROREAD's lines on a guest write to memory WHP maps read only, on a
    /// partition without and then with the `GpaAccessFaultExit` extended
    /// exit (Learn, WHV_EXTENDED_VM_EXITS: "WHvRunVpExitReasonMemoryAccess
    /// supported for second-level page faults"), where WHP offers it: a
    /// page mapped read only outside any slot (a zero page at the guest's
    /// addresses) and a `KVM_MEM_READONLY` slot (Firecracker's read-only
    /// pmem, devices/virtio/pmem/device.rs), whose write KVM gives
    /// Firecracker as an MMIO exit (v6.1 virt/kvm/kvm_main.c
    /// `__gfn_to_pfn_memslot` refuses a write to a read-only slot with
    /// KVM_PFN_ERR_RO_FAULT, which x86 handles as emulated MMIO). For each,
    /// a read then a write by the guest: the WHP run calls' exits (reason,
    /// address, access type) and what `run` gave.
    fn guest_writes_to_read_only_memory() -> Vec<String> {
        use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};
        const PROGRAM: u64 = 0xB000;
        // Both in the 2 MiB page at 2 MiB, which the tables map below; the
        // read-only slot's pages are the test mapping's at its address.
        const ZERO_GPA: u64 = 0x30_0000;
        const RO_GPA: u64 = 0x34_0000;
        const GPA_ACCESS_FAULT_EXIT: u64 = 1 << 14;
        let mut lines = Vec::new();
        let mut offered = 0u64;
        let mut n = 0u32;
        // SAFETY: a u64 output buffer of the size passed.
        let hres = unsafe { whv::WHvGetCapability(whv::WHvCapabilityCodeExtendedVmExits, (&raw mut offered).cast(), 8, &mut n) };
        lines.push(format!(
            "ExtendedVmExits offered {:#010x} {offered:#x}: GpaAccessFaultExit {}",
            hres.cast_unsigned(),
            offered >> 14 & 1
        ));
        for extra in [0, GPA_ACCESS_FAULT_EXIT] {
            let with = if extra == 0 { "without GpaAccessFaultExit" } else { "with GpaAccessFaultExit" };
            if extra & offered != extra {
                lines.push(format!("{with}: not offered, not run"));
                continue;
            }
            super::super::vm::EXTRA_EXITS_FOR_TESTS.set(extra);
            let made = super::super::VmFd::create();
            super::super::vm::EXTRA_EXITS_FOR_TESTS.set(0);
            let vm = match made {
                Ok(vm) => vm,
                Err(e) => {
                    lines.push(format!("{with}: the partition is not made: errno {}", e.errno()));
                    continue;
                }
            };
            let m = guest();
            put(m, 0x3008, &(0x20_0000u64 | 0x83).to_le_bytes());
            // `mov al, [addr]; out; mov byte [addr], 1; out`, per address.
            let access = |addr: u32| {
                let mut b = vec![0x8A, 0x04, 0x25];
                b.extend_from_slice(&addr.to_le_bytes());
                b.extend_from_slice(&[0xE6, PORT as u8, 0xC6, 0x04, 0x25]);
                b.extend_from_slice(&addr.to_le_bytes());
                b.extend_from_slice(&[0x01, 0xE6, PORT as u8]);
                b
            };
            put(m, PROGRAM, &[access(ZERO_GPA as u32), access(RO_GPA as u32), vec![0xF4, 0xEB, 0xFD]].concat());
            // SAFETY: the memory stays mapped while the VM has it.
            unsafe {
                vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                    slot: 0,
                    flags: 0,
                    guest_phys_addr: 0,
                    memory_size: 0x30_0000,
                    userspace_addr: m as u64,
                })
            }
            .unwrap();
            // SAFETY: as above: the slot's pages are the test's mapping.
            unsafe {
                vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
                    slot: 1,
                    flags: kvm_bindings::KVM_MEM_READONLY,
                    guest_phys_addr: RO_GPA,
                    memory_size: 4096,
                    userspace_addr: m as u64 + RO_GPA,
                })
            }
            .unwrap();
            let mut vcpu = vm.create_vcpu(0).unwrap();
            // SAFETY: allocates a committed page, released below.
            let zero = unsafe { VirtualAlloc(std::ptr::null(), 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
            assert!(!zero.is_null());
            // SAFETY: the page stays allocated while mapped; unmapped below.
            let mapped = unsafe { whv::WHvMapGpaRange(vcpu.part(), zero, ZERO_GPA, 4096, whv::WHvMapGpaRangeFlagRead) };
            lines.push(format!("{with}: the zero page mapped read only: HRESULT {:#010x}", mapped.cast_unsigned()));
            start(&vcpu);
            vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
            for name in [
                "the guest's read of the zero page",
                "its write of the zero page",
                "its read of the KVM_MEM_READONLY slot",
                "its write of the KVM_MEM_READONLY slot",
            ] {
                super::super::ffi::trace::begin();
                let what = run_a_step(&mut vcpu);
                let calls = super::super::ffi::trace::end();
                let exits: Vec<String> = calls
                    .iter()
                    .filter_map(|c| c.exit.map(|e| format!("reason {e:#x} ({})", c.detail)))
                    .collect();
                lines.push(format!("{with}: {name}: the run gave [{what}]; WHP's exits {exits:?}"));
                if !what.ends_with(&format!("IoOut {PORT:#x}")) {
                    lines.push(format!("{with}: the steps after it are not run"));
                    break;
                }
            }
            // SAFETY: the range mapped above.
            unsafe { whv::WHvUnmapGpaRange(vcpu.part(), ZERO_GPA, 4096) };
            drop(vcpu);
            drop(vm);
            // SAFETY: the test's memory, no VM left using it.
            unsafe {
                VirtualFree(zero, 0, MEM_RELEASE);
                assert_eq!(libc::munmap(m.cast(), MEM), 0);
            }
        }
        lines
    }

    // String port I/O and device memory with a second operand in RAM, as
    // Firecracker's devices see them and as the guest's memory and
    // registers are left. Asserted, each as KVM does it (Linux v6.1
    // arch/x86/kvm/emulate.c):
    // - REP OUTSB of "abc": three exits of one byte (em_out: a count of 1),
    //   RSI past the string, RCX 0; OUTSW: one exit of two bytes.
    // - REP INSB of 3: one exit that asks for 3 bytes (pio_in_emulated's
    //   read-ahead), all three in the guest's memory after, RDI past them,
    //   RCX 0; INSD: one exit of four bytes; REP INSB of 2 with the
    //   direction flag set: one exit of 2, written downwards.
    // - MOVSB from a device to RAM: one read of the device, the byte in
    //   RAM; MOVSB from RAM to a device: one write to the device with the
    //   byte from RAM, and no read asked of Firecracker for it.
    // - REP MOVSB of 2 from a device to RAM: one read exit of one byte for
    //   each element, each answered once, both bytes in RAM; from RAM to a
    //   device: one write exit for each element with its byte from RAM,
    //   and no read asked of Firecracker (KVM's emulator does a string
    //   instruction with a device operand an element at a time). Printed
    //   on record first (how many elements WHP's emulator does in one call
    //   is not documented): the PC (Ryzen 9 7900, kit f35e353) and CI run
    //   43467381837 (AMD EPYC 9V74) gave these exits.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_string_io_and_device_memory_beside_ram() {
        const PROGRAM: u64 = 0xB000;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        // A page 6 MiB up that no memory slot backs: a device's.
        put(m, 0x3018, &(0x60_0000u64 | 0x83).to_le_bytes());
        put(m, 0x8300, b"abc");
        put(m, 0x8310, b"12");
        let store = |reg: u8, at: u32| {
            // mov [at], reg (rsi 0x34, rcx 0x0c, rdi 0x3c)
            let mut b = vec![0x48, 0x89, reg, 0x25];
            b.extend_from_slice(&at.to_le_bytes());
            b
        };
        let (rsi, rcx, rdi) = (0x34, 0x0C, 0x3C);
        let program: Vec<u8> = [
            // REP OUTSB of 3 from 0x8300 to port 0x82.
            vec![0xBE, 0x00, 0x83, 0x00, 0x00, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x66, 0xBA, 0x82, 0x00, 0xFC, 0xF3, 0x6E],
            store(rsi, 0x8600),
            store(rcx, 0x8608),
            // OUTSW from 0x8310 to port 0x84.
            vec![0xBE, 0x10, 0x83, 0x00, 0x00, 0x66, 0xBA, 0x84, 0x00, 0x66, 0x6F],
            // REP INSB of 3 to 0x8400 from port 0x86.
            vec![0xBF, 0x00, 0x84, 0x00, 0x00, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x66, 0xBA, 0x86, 0x00, 0xF3, 0x6C],
            store(rdi, 0x8610),
            store(rcx, 0x8618),
            // INSD to 0x8410 from port 0x88.
            vec![0xBF, 0x10, 0x84, 0x00, 0x00, 0x66, 0xBA, 0x88, 0x00, 0x6D],
            // STD; REP INSB of 2 to 0x8421 from port 0x8a; CLD.
            vec![0xFD, 0xBF, 0x21, 0x84, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x66, 0xBA, 0x8A, 0x00, 0xF3, 0x6C, 0xFC],
            store(rdi, 0x8620),
            // MOVSB from the device at 0x600000 to 0x8500.
            vec![0xBE, 0x00, 0x00, 0x60, 0x00, 0xBF, 0x00, 0x85, 0x00, 0x00, 0xA4],
            // MOVSB from 0x8300 to the device at 0x600004.
            vec![0xBE, 0x00, 0x83, 0x00, 0x00, 0xBF, 0x04, 0x00, 0x60, 0x00, 0xA4],
            vec![0xE6, PORT as u8],
            // REP MOVSB of 2 from the device to 0x8510, then from 0x8300
            // to the device at 0x600008.
            vec![0xBE, 0x00, 0x00, 0x60, 0x00, 0xBF, 0x10, 0x85, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x00, 0xF3, 0xA4],
            vec![0xE6, PORT as u8],
            vec![0xBE, 0x00, 0x83, 0x00, 0x00, 0xBF, 0x08, 0x00, 0x60, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x00, 0xF3, 0xA4],
            vec![0xE6, PORT as u8, 0xF4, 0xEB, 0xFD],
        ]
        .concat();
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
        start(&vcpu);
        vcpu.set_regs(&kvm_regs { rip: PROGRAM, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();

        let mut feed: std::collections::VecDeque<Vec<u8>> =
            [vec![1, 2, 3], vec![0x44, 0x33, 0x22, 0x11], vec![9, 8], vec![0x5A]].into();
        let exits = exits_with_their_bytes(&mut vcpu, &mut feed, false, "the string I/O and MOVSB with a device");
        let word = |at: u64| u64::from_le_bytes(bytes_at::<8>(m, at));
        let memory = format!(
            "after REP OUTSB RSI {:#x} RCX {:#x}; after REP INSB RDI {:#x} RCX {:#x}, memory {:02x?}; INSD {:02x?}; \
             REP INSB downwards {:02x?}, RDI {:#x}; MOVSB from the device {:02x?}",
            word(0x8600),
            word(0x8608),
            word(0x8610),
            word(0x8618),
            bytes_at::<3>(m, 0x8400),
            bytes_at::<4>(m, 0x8410),
            bytes_at::<2>(m, 0x8420),
            word(0x8620),
            bytes_at::<1>(m, 0x8500)
        );
        eprintln!("STRTEST exits: {exits:?}");
        eprintln!("STRTEST {memory}");
        let wanted = [
            "out 0x82 [61]",
            "out 0x82 [62]",
            "out 0x82 [63]",
            "out 0x84 [31, 32]",
            "in 0x86 x3",
            "in 0x88 x4",
            "in 0x8a x2",
            "read 0x600000 x1",
            "write 0x600004 [61]",
            "the end",
        ];

        // The two REP MOVSB with a device, asserted below.
        let mut feed: std::collections::VecDeque<Vec<u8>> = [vec![0xA1], vec![0xA2]].into();
        let from_device = exits_with_their_bytes(&mut vcpu, &mut feed, false, "REP MOVSB of 2 from a device to RAM");
        let from_device_memory = bytes_at::<2>(m, 0x8510);
        eprintln!(
            "STRTEST REP MOVSB of 2 from a device to RAM (device reads answered a1, then a2): exits {from_device:?}; memory {from_device_memory:02x?}"
        );
        let to_device = exits_with_their_bytes(&mut vcpu, &mut feed, false, "REP MOVSB of 2 from RAM to a device");
        eprintln!("STRTEST REP MOVSB of 2 (\"ab\") from RAM to a device: exits {to_device:?}");

        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        assert_eq!(exits, wanted);
        assert_eq!(from_device, ["read 0x600000 x1", "read 0x600001 x1", "the end"], "REP MOVSB of 2 from a device to RAM");
        assert_eq!(from_device_memory, [0xA1, 0xA2], "REP MOVSB of 2 from a device: the bytes in RAM");
        assert_eq!(to_device, ["write 0x600008 [61]", "write 0x600009 [62]", "the end"], "REP MOVSB of 2 from RAM to a device");
        assert_eq!(
            memory,
            "after REP OUTSB RSI 0x8303 RCX 0x0; after REP INSB RDI 0x8403 RCX 0x0, memory [01, 02, 03]; INSD [44, 33, 22, 11]; \
             REP INSB downwards [08, 09], RDI 0x841f; MOVSB from the device [5a]"
        );
    }

    // What KVM's emulator does beyond the data of INS and OUTS (Linux v6.1
    // arch/x86/kvm/emulate.c), asserted:
    // - A REP prefix on a plain OUT is no string instruction: one exit with
    //   AL (vmx.c handle_io, svm.c io_interception read the string bit only).
    // - REP OUTSB: at each element's exit RIP is still the instruction's and
    //   RFLAGS.RF is set (`x86_emulate_insn`: RF while a REP string
    //   instruction runs; it ends when it finds RCX at 0); at the next
    //   instruction's exit RF is clear. Without REP: RIP past it, RF clear.
    // - OUTSB from a non-canonical RSI in 64-bit code: #GP(0) at the
    //   instruction (`__linearize`), no exit for the port.
    // - REP INSW of 16 words at 0x200ff0, the page above not present: one
    //   exit asks for 16 words (`pio_in_emulated` counts the bytes left in
    //   the page as elements), written in one write that faults at
    //   0x201000: #PF with a write's error code (2), CR2 0x201000, RDI and
    //   RCX as they were before the instruction, the first page's 16 bytes
    //   written.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_string_io_checks_and_flags_as_kvm() {
        const PROGRAM: u64 = 0xB000;
        const IDT: u64 = 0x5000;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
        // 2 MiB to 4 MiB through a page table at 0xD000: its first page
        // present, the second not.
        q(0x3008, 0xD000 | 3);
        q(0xD000, 0x20_0000 | 3);
        q(0xD008, 0);
        put(m, 0x8300, b"ab");
        let gate = |vector: u64, handler: u64| {
            let low = (handler & 0xFFFF) | (8 << 16) | (0x8E << 40) | (((handler >> 16) & 0xFFFF) << 48);
            q(IDT + vector * 16, low);
            q(IDT + vector * 16 + 8, handler >> 32);
        };
        // Assembled with clang (x86_64, Intel syntax); offsets from PROGRAM.
        let program: Vec<u8> = [
            // 0x00: mov al, 0x5a; mov esi, 0x8300; mov dx, 0x8c; rep out dx, al
            &[0xB0, 0x5A, 0xBE, 0x00, 0x83, 0x00, 0x00, 0x66, 0xBA, 0x8C, 0x00, 0xF3, 0xEE][..],
            // 0x0d: mov esi, 0x8300; mov ecx, 2; mov dx, 0x82; cld; rep outsb (at 0x1c)
            &[0xBE, 0x00, 0x83, 0x00, 0x00, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x66, 0xBA, 0x82, 0x00, 0xFC, 0xF3, 0x6E],
            // 0x1e: out 0x84, al; mov esi, 0x8300; outsb (at 0x25); out 0x80, al; hlt
            &[0xE6, 0x84, 0xBE, 0x00, 0x83, 0x00, 0x00, 0x6E, 0xE6, 0x80, 0xF4],
            // 0x29: mov rsi, 0x8000000000000000; mov dx, 0x82; outsb (at 0x37); hlt
            &[0x48, 0xBE, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x66, 0xBA, 0x82, 0x00, 0x6E, 0xF4],
            // 0x39, #GP: pop rax; mov [0x8700], rax; pop rax; mov [0x8708], rax;
            // out 0x80, al; hlt; jmp 0x39
            &[0x58, 0x48, 0x89, 0x04, 0x25, 0x00, 0x87, 0x00, 0x00, 0x58, 0x48, 0x89, 0x04, 0x25, 0x08, 0x87, 0x00, 0x00],
            &[0xE6, 0x80, 0xF4, 0xEB, 0xE9],
            // 0x50: mov edi, 0x200ff0; mov ecx, 16; mov dx, 0x8a; cld; rep insw; hlt
            &[0xBF, 0xF0, 0x0F, 0x20, 0x00, 0xB9, 0x10, 0x00, 0x00, 0x00, 0x66, 0xBA, 0x8A, 0x00, 0xFC, 0xF3, 0x66, 0x6D, 0xF4],
            // 0x63, #PF: pop rax; mov [0x8710], rax; mov rax, cr2; mov [0x8718], rax;
            // mov [0x8720], rdi; mov [0x8728], rcx; out 0x80, al; hlt; jmp 0x63
            &[0x58, 0x48, 0x89, 0x04, 0x25, 0x10, 0x87, 0x00, 0x00, 0x0F, 0x20, 0xD0],
            &[0x48, 0x89, 0x04, 0x25, 0x18, 0x87, 0x00, 0x00, 0x48, 0x89, 0x3C, 0x25, 0x20, 0x87, 0x00, 0x00],
            &[0x48, 0x89, 0x0C, 0x25, 0x28, 0x87, 0x00, 0x00, 0xE6, 0x80, 0xF4, 0xEB, 0xD7],
        ]
        .concat();
        assert_eq!(program.len(), 0x8c);
        put(m, PROGRAM, &program);
        gate(13, PROGRAM + 0x39);
        gate(14, PROGRAM + 0x63);
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
        let mut s = vcpu.get_sregs().unwrap();
        (s.idt.base, s.idt.limit) = (IDT, 4095);
        vcpu.set_sregs(&s).unwrap();
        let at = |vcpu: &VcpuFd, offset: u64| {
            vcpu.set_regs(&kvm_regs { rip: PROGRAM + offset, rsp: 0x9000, rflags: 2, ..Default::default() }).unwrap();
        };
        let word = |at: u64| u64::from_le_bytes(bytes_at::<8>(m, at));

        at(&vcpu, 0);
        let mut feed = std::collections::VecDeque::new();
        let plain = exits_with_their_bytes(&mut vcpu, &mut feed, true, "REP OUT, REP OUTSB of 2, OUT, OUTSB");
        eprintln!("STRTEST REP OUT, REP OUTSB of 2, OUT, OUTSB: exits {plain:?}");
        at(&vcpu, 0x29);
        let canonical = exits_with_their_bytes(&mut vcpu, &mut feed, false, "OUTSB from a non-canonical RSI");
        let gp = format!("error code {:#x}, RIP pushed {:#x}", word(0x8700), word(0x8708));
        eprintln!("STRTEST OUTSB from a non-canonical RSI: exits {canonical:?}; #GP {gp}");
        at(&vcpu, 0x50);
        let mut feed: std::collections::VecDeque<Vec<u8>> = [(0x40..0x60).collect()].into();
        let crossing = exits_with_their_bytes(&mut vcpu, &mut feed, false, "REP INSW across into a page not present");
        let pf = format!(
            "error code {:#x}, CR2 {:#x}, RDI {:#x}, RCX {:#x}, first page {:02x?}",
            word(0x8710),
            word(0x8718),
            word(0x8720),
            word(0x8728),
            bytes_at::<16>(m, 0x20_0ff0)
        );
        eprintln!("STRTEST REP INSW across into a page not present: exits {crossing:?}; #PF {pf}");

        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        assert_eq!(
            plain,
            [
                "out 0x8c [5a] rip 0xb00d rf 0",
                "out 0x82 [61] rip 0xb01c rf 1",
                "out 0x82 [62] rip 0xb01c rf 1",
                "out 0x84 [5a] rip 0xb020 rf 0",
                "out 0x82 [61] rip 0xb026 rf 0",
                "the end rip 0xb028 rf 0",
            ]
        );
        assert_eq!(canonical, ["the end"]);
        assert_eq!(gp, "error code 0x0, RIP pushed 0xb037");
        assert_eq!(crossing, ["in 0x8a x32", "the end"]);
        let first: Vec<u8> = (0x40..0x50).collect();
        assert_eq!(pf, format!("error code 0x2, CR2 0x201000, RDI 0x200ff0, RCX 0x10, first page {first:02x?}"));
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
        // Each run with the end it is for; any other fails the test.
        for (name, end) in [
            ("the vCPU's first run: cpuid, then a port write", "exit IoOut port 0x80"),
            ("a run to an MMIO read", "exit MmioRead 0x600000"),
            ("a run that completes the MMIO read, to a port write", "exit IoOut port 0x80"),
            ("a run through a wrmsr of the kvm-clock wall clock, to a port write", "exit IoOut port 0x80"),
            ("a run to hlt with interrupts off, ended by a kick", "no exit within 5 s (kicked)"),
            ("a run of a halted vCPU, ended by a kick", "no exit within 5 s (kicked)"),
        ] {
            on_a_thread_of_its_own(&mut vcpu, name, |v| {
                let line = run_to_a_line(v);
                assert_eq!(line, end, "{name}: not the end this run is for");
                line
            });
        }

        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// Code a record test enters with the registers it has set: one
    /// instruction, then `out 0x80, al; jmp $`.
    const CPUID_AT: u64 = 0x7800;
    const RDMSR_AT: u64 = 0x7810;
    const WRMSR_AT: u64 = 0x7820;
    const XSETBV_AT: u64 = 0x7830;
    /// The #GP and #UD handlers: `out 0x8d, al` and `out 0x86, al`.
    const GP_AT: u64 = 0x7840;
    const UD_AT: u64 = 0x7850;
    const IDT: u64 = 0x5000;

    fn probes(m: *mut u8) {
        put(m, CPUID_AT, &[0x0F, 0xA2, 0xE6, PORT as u8, 0xEB, 0xFE]);
        put(m, RDMSR_AT, &[0x0F, 0x32, 0xE6, PORT as u8, 0xEB, 0xFE]);
        put(m, WRMSR_AT, &[0x0F, 0x30, 0xE6, PORT as u8, 0xEB, 0xFE]);
        put(m, XSETBV_AT, &[0x0F, 0x01, 0xD1, 0xE6, PORT as u8, 0xEB, 0xFE]);
        put(m, GP_AT, &[0xE6, 0x8D, 0xEB, 0xFE]);
        put(m, UD_AT, &[0xE6, 0x86, 0xEB, 0xFE]);
        // 64-bit interrupt gates (type 0xE, present, code segment 8).
        for (vector, handler) in [(6u64, UD_AT), (13, GP_AT)] {
            let gate = (handler & 0xFFFF) | (8 << 16) | (0x8E << 40) | (((handler >> 16) & 0xFFFF) << 48);
            put(m, IDT + vector * 16, &gate.to_le_bytes());
            put(m, IDT + vector * 16 + 8, &(handler >> 32).to_le_bytes());
        }
    }

    /// The vCPU entered at `at` with `rax`, `rcx` and `rdx`: how the run
    /// ended (the instruction done, #GP, #UD, or the exit's line) and the
    /// registers then.
    fn probe(vcpu: &mut VcpuFd, at: u64, rax: u64, rcx: u64, rdx: u64) -> (String, kvm_regs) {
        vcpu.set_regs(&kvm_regs { rip: at, rsp: 0x9000, rflags: 2, rax, rcx, rdx, ..Default::default() }).unwrap();
        let how = match run_to_a_line(vcpu).as_str() {
            "exit IoOut port 0x80" => "done".to_string(),
            "exit IoOut port 0x8d" => "#GP".to_string(),
            "exit IoOut port 0x86" => "#UD".to_string(),
            other => panic!("the probe at {at:#x} (RAX {rax:#x}, RCX {rcx:#x}, RDX {rdx:#x}) ended neither done nor by #GP or #UD: {other}"),
        };
        (how, vcpu.get_regs().unwrap())
    }

    /// A record of what a CPU template's changes come to on WHP, for the
    /// leaves and the MSR upstream's templates modify
    /// (tests/data/custom_cpu_templates: CPUID 0x1, 0x7, 0xd, 0x80000001,
    /// 0x80000008, and on Sapphire Rapids 0x1d, 0x1e; MSR 0x10a in T2S and
    /// T2CL):
    ///
    /// - CPUID: a table with bits flipped in each of those leaves, set with
    ///   KVM_SET_CPUID2, against what the guest's CPUID returns. EAX and
    ///   EDX are asserted (the backend answers the intercept from the
    ///   table); EBX and ECX are printed, with the bits that follow the
    ///   vCPU's state (OSXSAVE, the XSAVE sizes).
    /// - XCR0: a table with AVX cleared in its leaf 0xd is refused
    ///   (`set_cpuid2`: run 43397419784 showed a guest's XSETBV of AVX
    ///   taken under such a table, where KVM gives #GP: Linux v6.1 x86.c,
    ///   `__kvm_set_xcr`); asserted. What WHP lets a guest enable, which
    ///   the refusal takes to be the host's leaf 0xd: a guest's XSETBV of
    ///   each group of state components the host has, and of all of them
    ///   together; printed.
    /// - MSRs: for 0x10a and a few others no WHP register holds (0xce,
    ///   0x8b, 2) and one that has a register (0x48), what KVM_GET_MSRS
    ///   and KVM_SET_MSRS return, what a guest's RDMSR gets, and whether
    ///   that RDMSR came to the backend. A guest's read of 0x10a that
    ///   comes to the backend can be given a vCPU's own value, as KVM
    ///   keeps one (`vcpu->arch.arch_capabilities`); one WHP answers
    ///   cannot.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_what_a_cpu_template_changes_on_record() {
        use core::arch::x86_64::__cpuid;
        let vm = super::super::VmFd::create().unwrap();
        let m = guest();
        probes(m);
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
        let mut s = vcpu.get_sregs().unwrap();
        s.cr4 |= 1 << 18; // OSXSAVE, for XSETBV
        (s.idt.base, s.idt.limit) = (IDT, 16 * 14 - 1);
        vcpu.set_sregs(&s).unwrap();

        let v = __cpuid(0);
        let vendor: Vec<u8> = [v.ebx, v.edx, v.ecx].iter().flat_map(|r| r.to_le_bytes()).collect();
        let fms = __cpuid(1).eax;
        eprintln!("TMPLTEST host: {} family/model/stepping {fms:#x}", String::from_utf8_lossy(&vendor));

        // CPUID.
        let supported = regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
        let mut table = supported.as_slice().to_vec();
        let leaves = [(0x1u32, 0u32), (0x7, 0), (0x7, 1), (0xd, 0), (0xd, 1), (0x8000_0001, 0), (0x8000_0008, 0), (0x1d, 0), (0x1e, 0)];
        let host_xcr0 = regs::host_xfeatures().0;
        // A table without AVX in its leaf 0xd, on a host that has it:
        // refused, nothing kept.
        if host_xcr0 & super::super::xcr::YMM != 0 {
            let mut no_avx = table.clone();
            for e in no_avx.iter_mut().filter(|e| e.function == 0xd && e.index == 0) {
                e.eax &= !4;
            }
            let refused = vcpu.set_cpuid2(&CpuId::from_entries(&no_avx).unwrap());
            eprintln!("TMPLTEST cpuid 0xd.0 without AVX, which this host has: KVM_SET_CPUID2 {refused:?}");
            assert!(refused.is_err(), "a table without AVX was taken");
            assert!(vcpu.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap().as_slice().is_empty(), "the refused table was kept");
        }
        // Bits flipped in each leaf: in 0xd.0, components the host does
        // not have (bit 8, a supervisor one, and bit 61), which leaves out
        // none it has.
        for e in &mut table {
            if leaves.contains(&(e.function, e.index)) {
                (e.eax, e.ebx, e.ecx, e.edx) = (e.eax ^ 0x100, e.ebx ^ 0x8, e.ecx ^ 0x40_0000, e.edx ^ 0x2000_0000);
            }
        }
        vcpu.set_cpuid2(&CpuId::from_entries(&table).unwrap()).unwrap();
        for (function, index) in leaves {
            let Some(e) = table.iter().find(|e| e.function == function && e.index == index) else {
                eprintln!("TMPLTEST cpuid {function:#x}.{index}: not among the supported leaves of this host");
                continue;
            };
            let (how, r) = probe(&mut vcpu, CPUID_AT, u64::from(function), u64::from(index), 0);
            let (a, b, c, d) = (r.rax as u32, r.rbx as u32, r.rcx as u32, r.rdx as u32);
            eprintln!(
                "TMPLTEST cpuid {function:#x}.{index}: {how}; the table {:#x} {:#x} {:#x} {:#x}, the guest {a:#x} {b:#x} {c:#x} \
                 {d:#x}; EBX differs in {:#x}, ECX in {:#x}",
                e.eax,
                e.ebx,
                e.ecx,
                e.edx,
                e.ebx ^ b,
                e.ecx ^ c
            );
            assert_eq!(how, "done", "cpuid {function:#x}.{index}");
            assert_eq!((a, d), (e.eax, e.edx), "cpuid {function:#x}.{index}: EAX and EDX are the table's");
        }

        // What WHP lets a guest enable: each group of components the
        // host's leaf 0xd has, with x87 and SSE (and AVX, which AVX-512
        // needs), then all of them.
        {
            use super::super::xcr::{AVX512, BNDCSR, BNDREGS, FP, KVM_SUPPORTED, PKRU, SSE, XTILE, YMM, names};
            eprintln!("TMPLTEST xsetbv: the host's leaf 0xd XCR0 components {host_xcr0:#x} ({})", names(host_xcr0));
            let all = host_xcr0 & KVM_SUPPORTED;
            for group in [YMM, BNDREGS | BNDCSR, YMM | AVX512, PKRU, XTILE, all] {
                if host_xcr0 & group != group {
                    eprintln!("TMPLTEST xsetbv of {}: the host has not all of it; not probed", names(group));
                    continue;
                }
                let xcr0 = FP | SSE | group;
                let (how, _) = probe(&mut vcpu, XSETBV_AT, xcr0 & 0xFFFF_FFFF, 0, xcr0 >> 32);
                let now = vcpu.get_xcrs().map(|x| x.xcrs[0].value);
                eprintln!("TMPLTEST xsetbv of {xcr0:#x} ({}): {how}; XCR0 then {now:x?}", names(xcr0));
            }
        }

        // MSRs.
        for (index, name) in [
            (0x10au32, "IA32_ARCH_CAPABILITIES"),
            (0xce, "MSR_PLATFORM_INFO"),
            (0x8b, "IA32_BIOS_SIGN_ID"),
            (0x2, "MSR 2"),
            (0x48, "IA32_SPEC_CTRL"),
        ] {
            let entry = |data| Msrs::from_entries(&[kvm_bindings::kvm_msr_entry { index, data, ..Default::default() }]).unwrap();
            let mut one = entry(0);
            let got = vcpu.get_msrs(&mut one).map(|n| (n, one.as_slice()[0].data));
            let set = vcpu.set_msrs(&entry(0));
            let before = MSR_INTERCEPTS.with(std::cell::Cell::get);
            let (how, r) = probe(&mut vcpu, RDMSR_AT, 0, u64::from(index), 0);
            let read_came = MSR_INTERCEPTS.with(std::cell::Cell::get) - before;
            let value = (r.rdx << 32) | (r.rax & 0xFFFF_FFFF);
            let before = MSR_INTERCEPTS.with(std::cell::Cell::get);
            let (wrote, _) = probe(&mut vcpu, WRMSR_AT, r.rax & 0xFFFF_FFFF, u64::from(index), r.rdx & 0xFFFF_FFFF);
            let write_came = MSR_INTERCEPTS.with(std::cell::Cell::get) - before;
            eprintln!(
                "TMPLTEST msr {index:#x} ({name}): KVM_GET_MSRS {got:x?}, KVM_SET_MSRS of 0 {set:?}; a guest's rdmsr: {how}, \
                 value {value:#x}, intercepts at the backend {read_came}; its wrmsr of that value: {wrote}, intercepts \
                 {write_came}"
            );
            if matches!(index, 0x10a | 0xce | 0x8b | 0x2) {
                assert_eq!((got.map(|g| g.0).ok(), set.ok()), (Some(0), Some(0)), "{index:#x}: an MSR kept nowhere ends the call");
            }
        }

        // The machine-check MSRs (`mce`): what a guest's RDMSR gets and
        // its WRMSR does, whether each came to the backend, and what
        // KVM_GET_MSRS reads after; KVM's answer in each line. On record:
        // whether these reach the backend is WHP's.
        for (index, write, kvm) in [
            (0x179u32, 32u64, "rdmsr 32, wrmsr #GP; here WHP's, the backend's call ends at it"),
            (0x17a, 0x5, "rdmsr 0, wrmsr kept: 0x5; here WHP's, the backend's call ends at it"),
            (0x17b, 0, "rdmsr #GP, wrmsr #GP"),
            (0x400, u64::MAX, "rdmsr 0, wrmsr kept: all ones"),
            (0x401, 0xbe00_0000_0000_0000, "rdmsr 0, wrmsr #GP (non-zero STATUS without McStatusWrEn)"),
            (0x402, 0x1234, "rdmsr 0, wrmsr kept: 0x1234"),
            (0x47f, 0x7, "rdmsr 0, wrmsr kept: 0x7"),
            (0x280, 0, "rdmsr #GP, wrmsr #GP (no CMCI)"),
            (0x0, 0, "rdmsr 0, wrmsr #GP"),
            (0xc001_0015, 1 << 18, "HWCR: rdmsr KVM's msr_hwcr, wrmsr of McStatusWrEn kept"),
        ] {
            let before = MSR_INTERCEPTS.with(std::cell::Cell::get);
            let (read, r) = probe(&mut vcpu, RDMSR_AT, 0, u64::from(index), 0);
            let read_came = MSR_INTERCEPTS.with(std::cell::Cell::get) - before;
            let value = (r.rdx << 32) | (r.rax & 0xFFFF_FFFF);
            let before = MSR_INTERCEPTS.with(std::cell::Cell::get);
            let (wrote, _) = probe(&mut vcpu, WRMSR_AT, write & 0xFFFF_FFFF, u64::from(index), write >> 32);
            let write_came = MSR_INTERCEPTS.with(std::cell::Cell::get) - before;
            let mut one = Msrs::from_entries(&[kvm_bindings::kvm_msr_entry { index, ..Default::default() }]).unwrap();
            let after = vcpu.get_msrs(&mut one).map(|n| (n, one.as_slice()[0].data));
            eprintln!(
                "TMPLTEST mce msr {index:#x}: a guest's rdmsr: {read}, value {value:#x}, intercepts {read_came}; its wrmsr of \
                 {write:#x}: {wrote}, intercepts {write_came}; KVM_GET_MSRS after {after:x?} (KVM: {kvm})"
            );
        }
        // SRSO (Linux v6.1.188 arch/x86/kernel/cpu/bugs.c,
        // srso_select_mitigation; amd.c, cpu_has_ibpb_brtype_microcode): a
        // family 0x19 guest without IBPB_BRTYPE (leaf 0x80000021 EAX bit 28)
        // writes SBPB (bit 7) to IA32_PRED_CMD, and a #GP there is "no
        // microcode" and the WARNING notice. KVM v6.1 refuses that write
        // (svm.c, svm_set_msr: `data & ~PRED_CMD_IBPB`) and lists neither
        // bit (cpuid.c); from 6.7 it lists them where its host has them.
        // What this host's leaf has, and what a guest's write of SBPB and of
        // IBPB gets. Printed, not asserted.
        {
            let max = core::arch::x86_64::__cpuid(0x8000_0000).eax;
            let eax = if max >= 0x8000_0021 { core::arch::x86_64::__cpuid_count(0x8000_0021, 0).eax } else { 0 };
            let (sbpb, _) = probe(&mut vcpu, WRMSR_AT, 0x80, 0x49, 0);
            let (ibpb, _) = probe(&mut vcpu, WRMSR_AT, 0x1, 0x49, 0);
            eprintln!(
                "TMPLTEST srso: host leaf 0x80000021 EAX {eax:#x} (max extended leaf {max:#x}; SBPB {}, IBPB_BRTYPE {}, \
                 SRSO_NO {}); a guest's wrmsr of IA32_PRED_CMD with SBPB: {sbpb}; with IBPB: {ibpb} (KVM v6.1: #GP, taken)",
                eax >> 27 & 1,
                eax >> 28 & 1,
                eax >> 29 & 1
            );
        }
        // The VMM's writes and reads of them, which are the backend's own:
        // what KVM's `set_msr_mce` keeps, a refused write ending the call.
        let entries = [(0x400, u64::MAX), (0x401, 0xbe00_0000_0000_0000), (0x402, 0x1234), (0x404, 0x99)];
        let msrs = Msrs::from_entries(
            &entries.map(|(index, data)| kvm_bindings::kvm_msr_entry { index, data, ..Default::default() }),
        )
        .unwrap();
        assert_eq!(vcpu.set_msrs(&msrs).unwrap(), 3, "a bank's CTL other than 0 or all ones ends KVM_SET_MSRS");
        let mut back = Msrs::from_entries(
            &[0x17b, 0x400, 0x401, 0x402, 0x404, 0x280].map(|index| kvm_bindings::kvm_msr_entry { index, ..Default::default() }),
        )
        .unwrap();
        assert_eq!(vcpu.get_msrs(&mut back).unwrap(), 6);
        let values: Vec<u64> = back.as_slice().iter().map(|e| e.data).collect();
        assert_eq!(values, [0, u64::MAX, 0xbe00_0000_0000_0000, 0x1234, 0, 0]);
        // IA32_MCG_CAP and IA32_MCG_STATUS, which WHP keeps: both calls end
        // at them (`mce::whp_answers`).
        for index in [0x179, 0x17a] {
            let one = || Msrs::from_entries(&[kvm_bindings::kvm_msr_entry { index, data: 0, ..Default::default() }]).unwrap();
            assert_eq!(vcpu.get_msrs(&mut one()).unwrap(), 0, "{index:#x}: KVM_GET_MSRS");
            assert_eq!(vcpu.set_msrs(&one()).unwrap(), 0, "{index:#x}: KVM_SET_MSRS");
        }

        drop(vcpu);
        drop(vm);
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The TSC of vCPU `vp` as WHP reads it.
    fn tsc_of(part: WHV_PARTITION_HANDLE, vp: u32) -> u64 {
        super::super::ffi::as_u64(&super::super::ffi::get_register(part, vp, whv::WHvX64RegisterTsc).unwrap())
    }

    fn spin(d: std::time::Duration) {
        let start = std::time::Instant::now();
        while start.elapsed() < d {
            std::hint::spin_loop();
        }
    }

    /// vCPU 1's TSC less vCPU 0's, from reads in both orders (0 then 1, 1
    /// then 0), so that the time between two reads cancels out: the median
    /// of 9 pairs, with the longest time between two reads (in cycles).
    fn tsc_skew(part: WHV_PARTITION_HANDLE) -> (i64, u64) {
        let mut skews = Vec::new();
        let mut gap = 0u64;
        for _ in 0..9 {
            let (a0, a1) = (tsc_of(part, 0), tsc_of(part, 1));
            let (b1, b0) = (tsc_of(part, 1), tsc_of(part, 0));
            let (ab, ba) = (a1.wrapping_sub(a0).cast_signed(), b1.wrapping_sub(b0).cast_signed());
            // The time between two reads: half the difference of the two
            // orders' differences.
            gap = gap.max((i128::from(ab) - i128::from(ba)).unsigned_abs().div_ceil(2).try_into().unwrap_or(u64::MAX));
            skews.push(((i128::from(ab) + i128::from(ba)) / 2) as i64);
        }
        skews.sort_unstable();
        (skews[4], gap)
    }

    /// Both vCPUs' TSCs read while partition time is suspended
    /// (`WHvSuspendPartitionTime`), or `None` if it is refused; with
    /// whether vCPU 0's TSC stood still between two reads 1 ms apart.
    fn tscs_held(part: WHV_PARTITION_HANDLE) -> Option<(u64, u64, bool)> {
        // SAFETY: the test's partition.
        if unsafe { whv::WHvSuspendPartitionTime(part) } != 0 {
            return None;
        }
        let first = tsc_of(part, 0);
        spin(std::time::Duration::from_millis(1));
        let (t0, t1) = (tsc_of(part, 0), tsc_of(part, 1));
        // SAFETY: the test's partition, whose time this suspended.
        assert_eq!(unsafe { whv::WHvResumePartitionTime(part) }, 0, "WHvResumePartitionTime");
        Some((t0, t1, first == t0))
    }

    /// A VM of two vCPUs over the test's guest memory.
    fn two_vcpus(m: *mut u8) -> (super::super::VmFd, VcpuFd, VcpuFd) {
        let vm = super::super::VmFd::create().unwrap();
        let region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: MEM as u64,
            userspace_addr: m as u64,
        };
        // SAFETY: the memory stays mapped while the VM has it.
        unsafe { vm.set_user_memory_region(region) }.unwrap();
        let v0 = vm.create_vcpu(0).unwrap();
        let v1 = vm.create_vcpu(1).unwrap();
        (vm, v0, v1)
    }

    fn write_tsc(vcpu: &VcpuFd, value: u64) -> Result<usize> {
        vcpu.set_msrs(&Msrs::from_entries(&[kvm_bindings::kvm_msr_entry { index: 0x10, data: value, ..Default::default() }]).unwrap())
    }

    fn read_tsc(vcpu: &VcpuFd) -> u64 {
        let mut m = Msrs::from_entries(&[kvm_bindings::kvm_msr_entry { index: 0x10, ..Default::default() }]).unwrap();
        assert_eq!(vcpu.get_msrs(&mut m).unwrap(), 1);
        m.as_slice()[0].data
    }

    /// A record (TSCSYNC lines) of what WHP does with the vCPUs' TSCs, for
    /// KVM's TSC matching (`VcpuShared::synchronize_tsc`), after a PC's
    /// guests restored from a snapshot found their TSCs 5k-193k cycles apart
    /// ("TSC warp between CPUs", c2042da): whether a TSC runs before the
    /// partition's first run; the skew of two vCPUs after writes of the same
    /// value 300 us apart made straight to WHP (0, as a boot writes; a saved
    /// value, as a restore writes) and through KVM_SET_MSRS (matched); what
    /// `WHvSuspendPartitionTime` and `WHvResumePartitionTime` return before
    /// and after a first run, whether a TSC stands still while suspended, and
    /// what a suspension of 50 ms costs the guest's clocks after a run: its
    /// TSC, the partition's reference time (`WHvPartitionPropertyCodeReferenceTime`)
    /// and its local APIC timer's count, each against the same 50 ms
    /// without a suspension; and a suspension asked for while a vCPU runs.
    /// Printed, not asserted, but for each step's own end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_tsc_matching_and_partition_time_on_record() {
        let mut lines = Vec::new();
        let m = guest();
        let (vm, mut v0, v1) = two_vcpus(m);
        let part = v0.part();
        let hz = pvclock::tsc_hz();
        lines.push(format!("TSC {hz} Hz; host TSC invariant: {}", host_tsc_stable()));
        let raw = |vp: u32, v: u64| {
            super::super::ffi::set_register(part, vp, whv::WHvX64RegisterTsc, super::super::ffi::reg64(v)).unwrap();
        };
        let a = tsc_of(part, 0);
        spin(std::time::Duration::from_millis(1));
        let b = tsc_of(part, 0);
        lines.push(format!("before a first run, vCPU 0's TSC over 1 ms of host time: +{}", b.wrapping_sub(a)));
        lines.push(format!("after create_vcpu of both (KVM's matched writes of 0): skew {:?} (skew, longest read gap)", tsc_skew(part)));
        let gap = std::time::Duration::from_micros(300);
        raw(0, 0);
        spin(gap);
        raw(1, 0);
        lines.push(format!("0 written straight to WHP, vCPU 1 300 us after vCPU 0: skew {:?}", tsc_skew(part)));
        let saved = 7_000 * hz;
        raw(0, saved);
        spin(gap);
        raw(1, saved);
        lines.push(format!("{saved:#x} written straight to WHP, 300 us apart: skew {:?}", tsc_skew(part)));
        write_tsc(&v0, saved).unwrap();
        spin(gap);
        write_tsc(&v1, saved + hz / 20_000).unwrap();
        lines.push(format!("through KVM_SET_MSRS, vCPU 1's 50 us later than vCPU 0's, 300 us apart (matched): skew {:?}", tsc_skew(part)));
        lines.push(format!("held before a first run: {:?} (vCPU 0, vCPU 1, vCPU 0 still over 1 ms)", tscs_held(part)));
        // SAFETY: the test's partition.
        let suspend = unsafe { whv::WHvSuspendPartitionTime(part) };
        // SAFETY: the test's partition.
        let again = unsafe { whv::WHvSuspendPartitionTime(part) };
        // SAFETY: the test's partition.
        let resume = unsafe { whv::WHvResumePartitionTime(part) };
        // SAFETY: the test's partition.
        let resume_again = unsafe { whv::WHvResumePartitionTime(part) };
        lines.push(format!(
            "before a first run: Suspend {:#010x}, Suspend again {:#010x}, Resume {:#010x}, Resume again {:#010x}",
            suspend.cast_unsigned(),
            again.cast_unsigned(),
            resume.cast_unsigned(),
            resume_again.cast_unsigned()
        ));

        start(&v0);
        let first = run_once(&mut v0);
        lines.push(format!("vCPU 0's first run: {first}"));
        assert_eq!(first, "exit IoOut port 0x80", "the first run did not reach its `out`");
        let a = tsc_of(part, 0);
        spin(std::time::Duration::from_millis(1));
        let b = tsc_of(part, 0);
        lines.push(format!("after a run, vCPU 0's TSC over 1 ms: +{}; skew {:?}", b.wrapping_sub(a), tsc_skew(part)));
        raw(1, tsc_of(part, 0));
        lines.push(format!("vCPU 0's TSC read and written to vCPU 1 straight, time running: skew {:?}", tsc_skew(part)));
        write_tsc(&v1, read_tsc(&v0)).unwrap();
        lines.push(format!("the same through KVM_SET_MSRS (matched): skew {:?}", tsc_skew(part)));
        lines.push(format!("held after a run: {:?}", tscs_held(part)));

        // What 50 ms of suspended partition time costs each clock, against
        // 50 ms without.
        let mut page = v0.get_lapic().unwrap();
        let set = |page: &mut kvm_bindings::kvm_lapic_state, at: usize, v: u32| {
            for (i, b) in v.to_le_bytes().into_iter().enumerate() {
                page.regs[at + i] = b.cast_signed();
            }
        };
        set(&mut page, 0xF0, 0x1FF);
        set(&mut page, 0x320, 0x1_0041);
        set(&mut page, 0x3E0, 0xB);
        set(&mut page, 0x380, u32::MAX);
        v0.set_lapic(&page).unwrap();
        let count = |v: &VcpuFd| {
            let p = v.get_lapic().unwrap();
            u32::from_le_bytes(std::array::from_fn(|i| p.regs[0x390 + i].cast_unsigned()))
        };
        let reference = || {
            let mut t = 0u64;
            let mut written = 0u32;
            // SAFETY: an 8-byte buffer for the 8-byte property.
            let hres = unsafe {
                whv::WHvGetPartitionProperty(part, whv::WHvPartitionPropertyCodeReferenceTime, (&raw mut t).cast(), 8, &mut written)
            };
            if hres == 0 { Some(t) } else { None }
        };
        let clocks = |v: &VcpuFd| (std::time::Instant::now(), tsc_of(part, 0), reference(), count(v));
        for suspended in [false, true] {
            let before = clocks(&v0);
            if suspended {
                // SAFETY: the test's partition.
                let hres = unsafe { whv::WHvSuspendPartitionTime(part) };
                lines.push(format!("Suspend after a run: {:#010x}", hres.cast_unsigned()));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            if suspended {
                // SAFETY: the test's partition.
                let hres = unsafe { whv::WHvResumePartitionTime(part) };
                lines.push(format!("Resume: {:#010x}", hres.cast_unsigned()));
            }
            let after = clocks(&v0);
            let wall = after.0 - before.0;
            lines.push(format!(
                "{} {:.3} ms of host time: TSC +{} ({:.3} ms at {hz} Hz), reference time {:?} -> {:?}, APIC timer count {:#x} -> {:#x} (-{})",
                if suspended { "suspended for" } else { "running for" },
                wall.as_secs_f64() * 1e3,
                after.1.wrapping_sub(before.1),
                after.1.wrapping_sub(before.1) as f64 / hz as f64 * 1e3,
                before.2,
                after.2,
                before.3,
                after.3,
                before.3.wrapping_sub(after.3)
            ));
        }

        // A suspension, and a matched host write, while vCPU 0 runs (`jmp $`
        // after its `out`).
        let mut kicker = VcpuFd { shared: Arc::clone(&v0.shared), own: None };
        let running = std::thread::spawn(move || {
            let line = run_once(&mut v0);
            (v0, line)
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        // SAFETY: the test's partition.
        let hres = unsafe { whv::WHvSuspendPartitionTime(part) };
        if hres == 0 {
            // SAFETY: the test's partition.
            unsafe { whv::WHvResumePartitionTime(part) };
        }
        let write = write_tsc(&v1, saved).map_err(|e| e.errno());
        kicker.set_kvm_immediate_exit(1);
        let (v0, line) = running.join().unwrap();
        lines.push(format!(
            "while vCPU 0 runs: Suspend {:#010x}; vCPU 1's matched KVM_SET_MSRS {write:?}; vCPU 0's run: {line}",
            hres.cast_unsigned()
        ));
        assert_eq!(line, "no exit within 5 s (kicked)", "vCPU 0 was not running in `jmp $`");
        for l in &lines {
            eprintln!("TSCSYNC {l}");
        }
        drop((v0, v1, vm));
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// A record (TSCADJREC lines) for offering `TSC_ADJUST` to the guest as
    /// KVM does (Linux v6.1 cpuid.c:648-649 sets CPUID.7.0:EBX bit 1 on every
    /// host; upstream's tests expect it in the guest, test_cpu_features_*):
    /// the bit in the host's CPUID, in the supported table and in what the
    /// guest's CPUID returns with the bit offered; the guest's RDMSR and
    /// WRMSR of 0x3b (done or #GP, and whether the backend answered), and by
    /// how much a write moved the vCPU's TSC against vCPU 1's (KVM: by the
    /// change, exactly, `adjust_tsc_offset_guest`); the guest's WRMSR of
    /// IA32_TSC, whether the backend sees it, and what TSC_ADJUST reads
    /// after (KVM adds the change to it, x86.c:3664-3667); KVM_GET_MSRS of
    /// 0x3b after. Asserted where the vCPU keeps TSC_ADJUST (the partition
    /// does not): the guest's write of TSC_ADJUST moves its TSC by exactly
    /// the change, and its write of the TSC moves it by exactly what
    /// TSC_ADJUST changes by, both read with partition time suspended; with
    /// how far the vCPUs' TSCs fell behind the host's across the write
    /// (`VmInner::with_time_stopped`'s cost). Then, for an exact move and for the TSC write's exit:
    /// `WHvX64RegisterTscVirtualOffset` read and written plus the change,
    /// with the skew it made and after a run; whether WHP offers the
    /// `TscMsrWrite` exit, and whether a guest's WRMSR 0x10 comes to the
    /// backend with it set. Printed, not asserted, but for each step's end.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_tsc_adjust_offered_to_the_guest_on_record() {
        use core::arch::x86_64::__cpuid_count;
        let mut lines = Vec::new();
        let m = guest();
        probes(m);
        let (vm, mut v0, v1) = two_vcpus(m);
        let part = v0.part();
        let supported = regs::supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
        let bit = |ebx: u32| ebx & (1 << 1) != 0;
        let offered = supported.as_slice().iter().find(|e| e.function == 7 && e.index == 0).map(|e| bit(e.ebx));
        lines.push(format!(
            "host CPUID.7.0:EBX[1] {}; in the supported table {offered:?}; the partition keeps IA32_TSC_ADJUST: {}",
            bit(__cpuid_count(7, 0).ebx),
            !regs::software_msr(regs::MSR_IA32_TSC_ADJUST)
        ));
        let mut table = supported.as_slice().to_vec();
        for e in table.iter_mut().filter(|e| e.function == 7 && e.index == 0) {
            e.ebx |= 1 << 1;
        }
        v0.set_cpuid2(&CpuId::from_entries(&table).unwrap()).unwrap();
        start(&v0);
        let mut s = v0.get_sregs().unwrap();
        (s.idt.base, s.idt.limit) = (IDT, 16 * 14 - 1);
        v0.set_sregs(&s).unwrap();
        let (how, r) = probe(&mut v0, CPUID_AT, 7, 0, 0);
        lines.push(format!("the guest's CPUID.7.0 with the bit offered: {how}, EBX[1] {}", bit(r.rbx as u32)));
        let came = || MSR_INTERCEPTS.with(std::cell::Cell::get);
        let msr = |v0: &mut VcpuFd, what: &str, index: u32, write: Option<u64>| -> (String, u64) {
            let before = came();
            let (how, r) = match write {
                Some(v) => probe(v0, WRMSR_AT, v & 0xFFFF_FFFF, u64::from(index), v >> 32),
                None => probe(v0, RDMSR_AT, 0, u64::from(index), 0),
            };
            let by = if came() > before { "the backend" } else { "WHP" };
            let value = (r.rdx << 32) | (r.rax & 0xFFFF_FFFF);
            let line = match write {
                Some(v) => format!("WRMSR {index:#x} ({what}) of {v:#x}: {how}, answered by {by}"),
                None => format!("RDMSR {index:#x} ({what}): {how}, {value:#x}, answered by {by}"),
            };
            (line, value)
        };
        let software = regs::software_msr(regs::MSR_IA32_TSC_ADJUST);
        // vCPU 0's TSC less vCPU 1's, read with partition time suspended:
        // exact, as both stand still.
        let held_skew = || {
            let (t0, t1, _) = tscs_held(part).expect("WHvSuspendPartitionTime refused");
            t0.wrapping_sub(t1).cast_signed()
        };
        // vCPU 1's TSC against the host's: the least of 9 differences,
        // which a suspension of partition time lowers by the time it stood.
        let behind_host = || {
            (0..9)
                .map(|_| {
                    // SAFETY: RDTSC has no preconditions.
                    let host = unsafe { core::arch::x86_64::_rdtsc() };
                    tsc_of(part, 1).wrapping_sub(host).cast_signed()
                })
                .min()
                .unwrap()
        };
        let hz = pvclock::tsc_hz();
        let (l, adjust) = msr(&mut v0, "TSC_ADJUST", 0x3B, None);
        lines.push(l);
        let before = tsc_skew(part);
        let held_before = held_skew();
        let host_before = behind_host();
        let by = 0x10_0000u64;
        let (l, _) = msr(&mut v0, "TSC_ADJUST", 0x3B, Some(adjust.wrapping_add(by)));
        lines.push(l);
        let host_after = behind_host();
        let held_after = held_skew();
        let after = tsc_skew(part);
        let lag = host_before - host_after;
        lines.push(format!(
            "vCPU 0's TSC against vCPU 1's: {before:?} before, {after:?} after (skew, read gap); moved by {} for {by} written \
             (KVM: exactly); read with partition time suspended: moved by {}; vCPU 1's TSC fell behind the host's by {lag} ticks \
             ({:.1} us) across the write",
            before.0 - after.0,
            held_after - held_before,
            lag as f64 * 1e6 / hz.max(1) as f64
        ));
        if software {
            assert_eq!(held_after - held_before, by.cast_signed(), "a guest's TSC_ADJUST write did not move its TSC by its change");
        }
        lines.push(msr(&mut v0, "TSC_ADJUST", 0x3B, None).0);
        let (l, tsc) = msr(&mut v0, "TSC", 0x10, None);
        lines.push(l);
        let target = tsc.wrapping_add(0x1000_0000);
        let (_, adjust_before) = msr(&mut v0, "TSC_ADJUST", 0x3B, None);
        let held_before = held_skew();
        lines.push(msr(&mut v0, "TSC", 0x10, Some(target)).0);
        let held_after = held_skew();
        let (l, adjust_after) = msr(&mut v0, "TSC_ADJUST after the guest's TSC write", 0x3B, None);
        let change = adjust_after.wrapping_sub(adjust_before).cast_signed();
        lines.push(format!(
            "{l} (KVM: the earlier value plus the change, about 0x1000_0000): changed by {change:#x}; vCPU 0's TSC against \
             vCPU 1's, read with partition time suspended, moved by {:#x} (KVM: the same)",
            held_after - held_before
        ));
        if software {
            assert_eq!(held_after - held_before, change, "a guest's TSC write moved its TSC by other than its TSC_ADJUST's change");
            assert!(change > 0 && change <= 0x1000_0000, "a guest's TSC write of 0x1000_0000 ahead changed TSC_ADJUST by {change:#x}");
        }
        let mut host = Msrs::from_entries(&[kvm_bindings::kvm_msr_entry { index: 0x3B, ..Default::default() }]).unwrap();
        let n = v0.get_msrs(&mut host).unwrap();
        lines.push(format!("KVM_GET_MSRS of 0x3b: {n} entries, {:#x}", host.as_slice()[0].data));
        // An exact move of the TSC, as KVM's offset change: vCPU 0's
        // WHvX64RegisterTscVirtualOffset (0x2087 in WinHvPlatformDefs.h;
        // what it holds is not documented) read, written plus `by`, and the
        // skew against vCPU 1 before, after, and after a run of vCPU 0.
        let get = |name| super::super::ffi::get_register(part, v0.vp(), name).map(|v| super::super::ffi::as_u64(&v)).map_err(|e| e.errno());
        let offset = get(whv::WHvX64RegisterTscVirtualOffset);
        lines.push(format!("WHvX64RegisterTscVirtualOffset of vCPU 0: {offset:?}; its TSC {:?}", get(whv::WHvX64RegisterTsc)));
        if let Ok(offset) = offset {
            let before = tsc_skew(part);
            let set = super::super::ffi::set_register(part, v0.vp(), whv::WHvX64RegisterTscVirtualOffset, super::super::ffi::reg64(offset.wrapping_add(by)))
                .map_err(|e| e.errno());
            let after = tsc_skew(part);
            let read = get(whv::WHvX64RegisterTscVirtualOffset);
            let (how, _) = probe(&mut v0, CPUID_AT, 0, 0, 0);
            let ran = tsc_skew(part);
            lines.push(format!(
                "WHvX64RegisterTscVirtualOffset written plus {by}: {set:?}, read back {read:?}; vCPU 0's TSC against vCPU 1's \
                 {before:?} before, {after:?} after: moved by {} (exact: {by}); after a run ({how}) {ran:?}: moved by {} since",
                before.0 - after.0,
                after.0 - ran.0
            ));
        }
        // The guest's TSC write as an exit: whether WHP offers TscMsrWrite
        // (WHV_X64_MSR_EXIT_BITMAP bit 1), and whether a guest's WRMSR 0x10
        // then comes to the backend (KVM adds its change to TSC_ADJUST).
        let mut offered = 0u64;
        let mut written = 0u32;
        // SAFETY: a u64 output buffer of the size passed.
        let cap = unsafe { whv::WHvGetCapability(whv::WHvCapabilityCodeX64MsrExitBitmap, (&raw mut offered).cast(), 8, &mut written) };
        let mut bitmap = 0u64;
        // SAFETY: as above.
        let got = unsafe { whv::WHvGetPartitionProperty(part, whv::WHvPartitionPropertyCodeX64MsrExitBitmap, (&raw mut bitmap).cast(), 8, &mut written) };
        lines.push(format!(
            "WHvGetCapability(X64MsrExitBitmap): {:#010x}, {offered:#x} (TscMsrWrite {}); the partition's: {:#010x}, {bitmap:#x}",
            cap.cast_unsigned(),
            offered >> 1 & 1,
            got.cast_unsigned()
        ));
        let with = bitmap | 1 << 1;
        // SAFETY: a u64 property value.
        let set = unsafe { super::super::ffi::set_partition_property(part, whv::WHvPartitionPropertyCodeX64MsrExitBitmap, &with) };
        lines.push(format!("X64MsrExitBitmap set with TscMsrWrite ({with:#x}): {:?}", set.map_err(|e| e.errno())));
        let (l, tsc) = msr(&mut v0, "TSC", 0x10, None);
        lines.push(l);
        lines.push(msr(&mut v0, "TSC, with TscMsrWrite", 0x10, Some(tsc.wrapping_add(0x1000_0000))).0);
        lines.push(msr(&mut v0, "TSC after it", 0x10, None).0);
        // SAFETY: as above, the partition's bitmap as it was.
        let back = unsafe { super::super::ffi::set_partition_property(part, whv::WHvPartitionPropertyCodeX64MsrExitBitmap, &bitmap) };
        lines.push(format!("X64MsrExitBitmap set back: {:?}", back.map_err(|e| e.errno())));
        for l in &lines {
            eprintln!("TSCADJREC {l}");
        }
        drop((v0, v1, vm));
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// KVM's TSC matching on WHP: after a boot's writes of 0 and a restore's
    /// writes of each vCPU's saved TSC, saved at different moments and
    /// written 300 us apart, both vCPUs' TSCs are one offset from the
    /// host's, as KVM gives them (x86.c:2665-2718, `cur_tsc_offset`): read
    /// equal while partition time is suspended where that holds a TSC still,
    /// else within the longest time between two reads. Saved again (vCPU 1
    /// 40 us after vCPU 0) and restored into a new VM twice, as upstream's
    /// save and a restore in a new process: each save's TSCs differ by the
    /// save's gap alone, and each restore matches again. A host write while
    /// a vCPU runs fails, with a whp: line, rather than writing an offset of
    /// its own.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture"]
    fn test_restored_vcpus_take_one_tsc_offset_as_kvm() {
        let m = guest();
        let hz = pvclock::tsc_hz();
        let one_offset = |part: WHV_PARTITION_HANDLE, step: &str| {
            let held = tscs_held(part).unwrap_or_else(|| panic!("{step}: WHvSuspendPartitionTime refused"));
            let (skew, gap) = tsc_skew(part);
            eprintln!("TSCMATCH {step}: held {held:?}; skew {skew}, longest read gap {gap}");
            if held.2 {
                assert_eq!(held.0, held.1, "{step}: the vCPUs' TSCs differ while partition time stands still");
            } else {
                assert!(skew.unsigned_abs() <= gap, "{step}: skew {skew} beyond the read gap {gap}");
            }
        };
        let (vm, v0, v1) = two_vcpus(m);
        let part = v0.part();
        one_offset(part, "created");
        write_tsc(&v0, 0).unwrap();
        spin(std::time::Duration::from_micros(300));
        write_tsc(&v1, 0).unwrap();
        one_offset(part, "a boot's writes of 0, 300 us apart");
        let saved = 7_000 * hz;
        let gap = hz / 20_000;
        write_tsc(&v0, saved).unwrap();
        spin(std::time::Duration::from_micros(300));
        write_tsc(&v1, saved + gap).unwrap();
        one_offset(part, "a restore's writes, vCPU 1's saved 50 us later");
        // Each round's VM is gone before the next maps the memory, as a
        // restore in a new process follows the old one's end: WHP refuses a
        // second partition's map of memory another partition of the process
        // has mapped (ERROR_INVALID_PARAMETER, a PC at 4999ff6).
        let mut current = (vm, v0, v1);
        for round in 1..=2 {
            let s0 = read_tsc(&current.1);
            let between = std::time::Instant::now();
            spin(std::time::Duration::from_micros(40));
            let s1 = read_tsc(&current.2);
            let apart = between.elapsed();
            let most = super::super::tscsync::ns_to_cycles(u64::try_from(apart.as_nanos()).unwrap(), (hz / 1000) as u32) + hz / 10_000;
            eprintln!("TSCMATCH save {round}: {s0:#x} {s1:#x}, {} apart in {apart:?}", s1.wrapping_sub(s0));
            assert!(s1 >= s0 && s1 - s0 <= most, "save {round}: the TSCs differ by more than the save's gap");
            drop(current);
            let (vm, n0, n1) = two_vcpus(m);
            write_tsc(&n0, s0).unwrap();
            spin(std::time::Duration::from_micros(300));
            write_tsc(&n1, s1).unwrap();
            one_offset(n0.part(), &format!("restore {round} into a new VM"));
            current = (vm, n0, n1);
        }
        let (vm, mut v0, v1) = current;
        start(&v0);
        assert_eq!(run_once(&mut v0), "exit IoOut port 0x80");
        let mut kicker = VcpuFd { shared: Arc::clone(&v0.shared), own: None };
        let running = std::thread::spawn(move || {
            let line = run_once(&mut v0);
            (v0, line)
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let near = read_tsc(&v1);
        let write = write_tsc(&v1, near);
        kicker.set_kvm_immediate_exit(1);
        let (v0, line) = running.join().unwrap();
        assert_eq!(line, "no exit within 5 s (kicked)", "vCPU 0 was not running");
        assert!(write.is_err(), "a matched host write while vCPU 0 runs was made: {write:?}");
        drop((v0, v1, vm));
        // SAFETY: the test's mapping, no VM left using it.
        assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
    }

    /// The MSI trigger record's guest memory: each handler's count, each
    /// vCPU's (at `TRIG_PER_CPU` + 8 x its APIC ID) and the stop flag.
    const TRIG_COUNT_A: u64 = 0x7000;
    const TRIG_COUNT_B: u64 = 0x7008;
    const TRIG_STOP: u64 = 0x7010;
    const TRIG_PER_CPU: u64 = 0x7020;
    /// The second handler's vector and code (the first is `MMIO_VECTOR`'s,
    /// at `MMIO_HANDLER`).
    const TRIG_VECTOR_B: u64 = 0x42;
    const TRIG_HANDLER_B: u64 = 0xB900;
    /// The MSI address of APIC ID 0, physical destination mode.
    const TRIG_MSI: u64 = 0xFEE0_0000;

    fn trig_read(m: *mut u8, at: u64) -> u64 {
        // SAFETY: within the test's mapping, 8-byte aligned; the guest
        // writes it with locked instructions.
        unsafe { std::ptr::read_volatile(m.add(at as usize).cast::<u64>()) }
    }

    fn trig_now() -> u64 {
        // SAFETY: RDTSC, which every x86-64 CPU has.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    /// A handler that adds one at `count` and at its CPU's slot (from the
    /// local APIC's ID register; RBX holds the APIC's base), writes the EOI
    /// and returns; RAX kept.
    fn trig_handler(count: u64) -> Vec<u8> {
        let mut h = vec![
            0x50, // push rax
            0x8B, 0x43, 0x20, // mov eax, [rbx + 0x20] (APIC ID)
            0xC1, 0xE8, 0x18, // shr eax, 24
            0xF0, 0x48, 0xFF, 0x04, 0xC5, // lock inc qword [rax * 8 + TRIG_PER_CPU]
        ];
        h.extend_from_slice(&(TRIG_PER_CPU as u32).to_le_bytes());
        h.extend_from_slice(&[0xF0, 0x48, 0xFF, 0x04, 0x25]); // lock inc qword [count]
        h.extend_from_slice(&(count as u32).to_le_bytes());
        h.extend_from_slice(&[
            0x58, // pop rax
            0xC7, 0x83, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword [rbx + 0xB0], 0 (EOI)
            0x48, 0xCF, // iretq
        ]);
        h
    }

    /// The record's VM: two vCPUs, each with its local APIC on and
    /// interrupts on, in a loop that spins (`pause`) or halts (`hlt`) until
    /// the stop flag is set, then `out 0x80`; vector `MMIO_VECTOR` counts at
    /// `TRIG_COUNT_A`, `TRIG_VECTOR_B` at `TRIG_COUNT_B`.
    fn trig_guest(halted: bool) -> (super::super::VmFd, VcpuFd, VcpuFd, *mut u8) {
        let mut program = APIC_ON.to_vec();
        // loop: cmp qword [TRIG_STOP], 0
        program.extend_from_slice(&[0x48, 0x83, 0x3C, 0x25]);
        program.extend_from_slice(&(TRIG_STOP as u32).to_le_bytes());
        program.push(0x00);
        if halted {
            program.extend_from_slice(&[0x75, 0x03, 0xF4, 0xEB, 0xF2]); // jne out; hlt; jmp loop
        } else {
            program.extend_from_slice(&[0x75, 0x04, 0xF3, 0x90, 0xEB, 0xF1]); // jne out; pause; jmp loop
        }
        program.extend_from_slice(&[0xE6, PORT as u8, 0xEB, 0xFE]); // out: out 0x80, al; jmp $
        let (vm, v0, m) = mmio_guest(&program);
        put(m, MMIO_HANDLER, &trig_handler(TRIG_COUNT_A));
        put(m, TRIG_HANDLER_B, &trig_handler(TRIG_COUNT_B));
        let q = |at: u64, v: u64| put(m, at, &v.to_le_bytes());
        q(MMIO_IDT + TRIG_VECTOR_B * 16, (TRIG_HANDLER_B & 0xffff) | (8 << 16) | (0x8E << 40));
        q(MMIO_IDT + TRIG_VECTOR_B * 16 + 8, 0);
        let v1 = vm.create_vcpu(1).unwrap();
        start(&v1);
        let mut s = v1.get_sregs().unwrap();
        (s.idt.base, s.idt.limit) = (MMIO_IDT, 0xfff);
        v1.set_sregs(&s).unwrap();
        v1.set_regs(&kvm_regs { rip: MMIO_PROGRAM, rsp: 0x8800, rflags: 2, ..Default::default() }).unwrap();
        // Runnable: an AP is made waiting for a SIPI, as KVM makes one.
        v1.set_mp_state(kvm_bindings::kvm_mp_state { mp_state: kvm_bindings::KVM_MP_STATE_RUNNABLE }).unwrap();
        (vm, v0, v1, m)
    }

    /// Runs `vcpu` on a thread of its own, its WHP calls traced, until its
    /// `out 0x80` (the guest's stop), a kick, an error or 20 other exits:
    /// the vCPU, what the runs returned, and its `WHvRunVirtualProcessor`
    /// calls counted by exit reason.
    #[allow(clippy::type_complexity)]
    fn trig_spawn(vcpu: VcpuFd) -> std::thread::JoinHandle<(VcpuFd, Vec<String>, String)> {
        std::thread::spawn(move || {
            let mut vcpu = vcpu;
            let mut exits = Vec::new();
            let mut reads = 0;
            super::super::ffi::trace::begin();
            loop {
                let e = one_run(&mut vcpu, &[], &mut reads);
                let end = e.starts_with("out 0x80") || e == "EINTR" || e.starts_with("run failed") || exits.len() >= 20;
                exits.push(e);
                if end {
                    break;
                }
            }
            let mut reasons = std::collections::BTreeMap::new();
            for c in super::super::ffi::trace::end() {
                if let (true, Some(exit)) = (c.call == "WHvRunVirtualProcessor", c.exit) {
                    *reasons.entry(exit).or_insert(0u64) += 1;
                }
            }
            let runs: Vec<String> = reasons.iter().map(|(r, n)| format!("{n} with exit reason {r:#x}")).collect();
            (vcpu, exits, runs.join(", "))
        })
    }

    /// One delivery: waits `settle`, calls `signal`, and gives the TSC
    /// ticks until the guest's count at `at` moved, `None` after `limit`.
    fn trig_once(m: *mut u8, at: u64, settle: std::time::Duration, limit: u64, signal: &dyn Fn()) -> Option<u64> {
        spin(settle);
        let before = trig_read(m, at);
        let t0 = trig_now();
        signal();
        loop {
            if trig_read(m, at) != before {
                return Some(trig_now() - t0);
            }
            if trig_now() - t0 > limit {
                return None;
            }
            std::hint::spin_loop();
        }
    }

    /// Latencies as a line, in microseconds.
    fn trig_line(ticks: &[Option<u64>], per_us: f64) -> String {
        let lost = ticks.iter().filter(|t| t.is_none()).count();
        let mut got: Vec<u64> = ticks.iter().flatten().copied().collect();
        got.sort_unstable();
        if got.is_empty() {
            return format!("none of {} seen within 50 ms", ticks.len());
        }
        let at = |q: f64| got[((got.len() - 1) as f64 * q) as usize] as f64 / per_us;
        format!(
            "median {:.1} us, p90 {:.1}, p99 {:.1}, min {:.1}, max {:.1}; {lost} of {} not seen within 50 ms",
            at(0.5),
            at(0.9),
            at(0.99),
            at(0.0),
            at(1.0),
            ticks.len()
        )
    }

    /// A trigger's parameters for the MSI `address`/`data` as the backend
    /// would make them: `WHvTriggerTypeInterrupt` with the control
    /// `inject_msi` requests (`irqchip::interrupt_control`).
    fn trig_params(address: u64, data: u32) -> whv::WHV_TRIGGER_PARAMETERS {
        whv::WHV_TRIGGER_PARAMETERS {
            TriggerType: whv::WHvTriggerTypeInterrupt,
            Reserved: 0,
            Anonymous: whv::WHV_TRIGGER_PARAMETERS_0 { Interrupt: super::super::irqchip::interrupt_control(address, data) },
        }
    }

    /// A record (TRIGREC lines) of WHP's triggers for an MSI route
    /// (`WHvCreateTrigger`, Windows 10 20H2 and later on x64: an event
    /// handle whose signal WHP turns into the interrupt itself), the
    /// equivalent of KVM's injection of an MSI irqfd in the signaller's
    /// context (Linux v6.1 virt/kvm/eventfd.c:186-210, `irqfd_wakeup` calls
    /// `kvm_arch_set_irq_inatomic`, arch/x86/kvm/irq_comm.c:157-191, which
    /// delivers an MSI there and then), against the ways this backend has:
    /// an irqfd's write taken by its consumer, which injects in the
    /// writer's thread (`VmInner::inject_irqfd_in_place`); the irqfd
    /// watcher thread, for an irqfd whose consumer is removed (an eventfd
    /// write, the watcher's wake-up, `raise_gsi`, `WHvRequestInterrupt`,
    /// `wake_halted`), the way of a write the consumer leaves and of
    /// another process's; and a direct `inject_msi` from the signalling
    /// thread. With the guest's two vCPUs spinning, then halted:
    /// - `WHvCreateTrigger` of the MSI's interrupt control: HRESULT,
    ///   handles;
    /// - what `WHvRequestInterrupt` returns for an MSI to an APIC ID no
    ///   vCPU has (a request the consumer leaves to the watcher if refused);
    /// - the latency of each way, seen from the signalling thread (the
    ///   signal to the guest handler's count moving in guest RAM), 300 each,
    ///   in turn: the consumer's should match the direct inject's;
    /// - the vCPU threads' runs by exit reason (whether a halted vCPU comes
    ///   back to the backend's run loop: Halt exits, after which a trigger's
    ///   interrupt waits for the loop's `HALT_POLL` re-entry, as
    ///   `wake_halted` is not called);
    /// - after a delivered signal, whether the event still reads signalled;
    /// - coalescing: 1000 signals back to back, and 200 50 us apart, the
    ///   deliveries counted for each way;
    /// - `WHvUpdateTriggerParameters` on a route change: to vector B, to
    ///   APIC ID 1, back; then 500 updates while another thread signals
    ///   every 20 us (failed updates, deliveries to each vector and CPU),
    ///   and the route that a signal after the last update takes;
    /// - `WHvDeleteTrigger`, then a signal of its event, and the event's
    ///   state after two waits (auto or manual reset).
    ///
    /// Printed, not asserted, but for each step's own end: the direct way
    /// delivers at all, and each vCPU stops at its `out 0x80`.
    #[test]
    #[ignore = "needs WHP: run on a WHP machine with --ignored --nocapture, alone"]
    fn test_msi_triggers_against_the_irqfd_watcher_on_record() {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::Threading::{SetEvent, WaitForSingleObject};
        let ms = std::time::Duration::from_millis;
        let us = std::time::Duration::from_micros;
        let (i0, t0) = (std::time::Instant::now(), trig_now());
        spin(ms(50));
        let per_us = (trig_now() - t0) as f64 / i0.elapsed().as_secs_f64() / 1e6;
        let limit = (per_us * 50_000.0) as u64;
        eprintln!("TRIGREC host TSC {per_us:.1} ticks per us; the vCPU threads' WHP calls traced");
        for halted in [false, true] {
            let mode = if halted { "halted" } else { "spinning" };
            let settle = if halted { us(300) } else { us(50) };
            let (vm, v0, v1, m) = trig_guest(halted);
            let inner = Arc::clone(&v0.shared.inner);
            let part = v0.part();
            // The consumer's way: an irqfd on GSI 24, routed to the MSI;
            // the watcher's: one on GSI 25, the same MSI, without its
            // consumer.
            vm.create_irq_chip().unwrap();
            let route = |gsi| {
                let mut entry = kvm_bindings::kvm_irq_routing_entry { gsi, type_: kvm_bindings::KVM_IRQ_ROUTING_MSI, ..Default::default() };
                entry.u.msi = kvm_bindings::kvm_irq_routing_msi { address_lo: TRIG_MSI as u32, data: MMIO_VECTOR as u32, ..Default::default() };
                entry
            };
            vm.set_gsi_routing(&kvm_bindings::KvmIrqRouting::from_entries(&[route(24), route(25)]).unwrap()).unwrap();
            let irqfd = vmm_sys_util::eventfd::EventFd::new(0).unwrap();
            vm.register_irqfd(&irqfd, 24).unwrap();
            let watched = vmm_sys_util::eventfd::EventFd::new(0).unwrap();
            vm.register_irqfd(&watched, 25).unwrap();
            vm.leave_irqfd_to_the_watcher(&watched);
            // The trigger's way.
            let mut trigger: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut event: HANDLE = std::ptr::null_mut();
            let params = trig_params(TRIG_MSI, MMIO_VECTOR as u32);
            // SAFETY: valid parameters and out pointers.
            let created = unsafe { whv::WHvCreateTrigger(part, &params, &mut trigger, &mut event) };
            eprintln!(
                "TRIGREC {mode}: WHvCreateTrigger(interrupt, the MSI's control: vector {MMIO_VECTOR:#x}, APIC ID 0): HRESULT {:#010x}, trigger {trigger:p}, event {event:p}",
                created.cast_unsigned()
            );
            let triggered = created == 0 && !event.is_null();
            let kickers = [VcpuFd { shared: Arc::clone(&v0.shared), own: None }, VcpuFd { shared: Arc::clone(&v1.shared), own: None }];
            let threads = [trig_spawn(v0), trig_spawn(v1)];
            let direct = || inner.inject_msi(TRIG_MSI, MMIO_VECTOR as u32);
            let consumer = || irqfd.write(1).unwrap();
            let watcher = || watched.write(1).unwrap();
            let event_at = event as usize;
            let signal = move || {
                // SAFETY: the trigger's event, open until the end.
                unsafe { SetEvent(event_at as HANDLE) };
            };
            // Both guests in their loop: a delivery to each.
            let warm = trig_once(m, TRIG_COUNT_A, ms(5), limit, &direct);
            let warm1 = trig_once(m, TRIG_PER_CPU + 8, ms(5), limit, &|| inner.inject_msi(TRIG_MSI | 1 << 12, MMIO_VECTOR as u32));
            eprintln!("TRIGREC {mode}: a first direct delivery to vCPU 0 {warm:?} ticks, to vCPU 1 {warm1:?}");
            assert!(warm.is_some(), "{mode}: the guest took no direct interrupt: the record has no guest");
            let nobody = inner.request_interrupt(TRIG_MSI | 200 << 12, MMIO_VECTOR as u32);
            eprintln!(
                "TRIGREC {mode}: WHvRequestInterrupt of the MSI to APIC ID 200 (no such vCPU): HRESULT {:#010x}",
                nobody.cast_unsigned()
            );
            let mut ways: Vec<(&str, &dyn Fn())> =
                vec![("direct inject_msi", &direct), ("irqfd write, its consumer", &consumer), ("irqfd watcher", &watcher)];
            if triggered {
                ways.push(("trigger", &signal));
            }
            let mut ticks = vec![Vec::new(); ways.len()];
            for _ in 0..300 {
                for (i, (_, way)) in ways.iter().enumerate() {
                    ticks[i].push(trig_once(m, TRIG_COUNT_A, settle, limit, *way));
                }
            }
            for (i, (name, _)) in ways.iter().enumerate() {
                eprintln!("TRIGREC {mode}: latency, {name}: {}", trig_line(&ticks[i], per_us));
            }
            if triggered {
                let got = trig_once(m, TRIG_COUNT_A, settle, limit, &signal);
                spin(ms(1));
                // SAFETY: the trigger's event.
                let state = unsafe { WaitForSingleObject(event, 0) };
                eprintln!("TRIGREC {mode}: after a delivered signal ({got:?} ticks) the event reads {state:#x} (0 signalled, 0x102 not)");
            }
            for (name, way) in &ways {
                let before = trig_read(m, TRIG_COUNT_A);
                for _ in 0..1000 {
                    way();
                }
                spin(ms(20));
                let burst = trig_read(m, TRIG_COUNT_A) - before;
                let before = trig_read(m, TRIG_COUNT_A);
                for _ in 0..200 {
                    way();
                    spin(us(50));
                }
                spin(ms(20));
                let spaced = trig_read(m, TRIG_COUNT_A) - before;
                eprintln!("TRIGREC {mode}: coalescing, {name}: 1000 back to back gave {burst} deliveries, 200 50 us apart gave {spaced}");
            }
            if triggered {
                let counts = || [TRIG_COUNT_A, TRIG_COUNT_B, TRIG_PER_CPU, TRIG_PER_CPU + 8].map(|at| trig_read(m, at));
                let update = |address: u64, vector: u64| {
                    let p = trig_params(address, vector as u32);
                    // SAFETY: valid parameters for the live trigger.
                    unsafe { whv::WHvUpdateTriggerParameters(part, &p, trigger) }
                };
                for (what, address, vector) in [
                    ("to vector B", TRIG_MSI, TRIG_VECTOR_B),
                    ("to APIC ID 1", TRIG_MSI | 1 << 12, MMIO_VECTOR),
                    ("back to vector A, APIC ID 0", TRIG_MSI, MMIO_VECTOR),
                ] {
                    let hres = update(address, vector);
                    let before = counts();
                    signal();
                    spin(ms(20));
                    let after = counts();
                    let moved: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
                    eprintln!(
                        "TRIGREC {mode}: WHvUpdateTriggerParameters {what}: HRESULT {:#010x}; one signal then moved vector A {}, B {}, vCPU 0 {}, vCPU 1 {}",
                        hres.cast_unsigned(),
                        moved[0],
                        moved[1],
                        moved[2],
                        moved[3]
                    );
                }
                let before = counts();
                let stop = std::sync::atomic::AtomicBool::new(false);
                let (failed, first, signals) = std::thread::scope(|scope| {
                    let signaller = scope.spawn(|| {
                        let mut n = 0u64;
                        while !stop.load(Ordering::Relaxed) {
                            signal();
                            n += 1;
                            spin(us(20));
                        }
                        n
                    });
                    let (mut failed, mut first) = (0, 0);
                    for i in 0..500 {
                        let hres = if i % 2 == 0 { update(TRIG_MSI | 1 << 12, TRIG_VECTOR_B) } else { update(TRIG_MSI, MMIO_VECTOR) };
                        if hres != 0 {
                            failed += 1;
                            if first == 0 {
                                first = hres;
                            }
                        }
                        spin(us(200));
                    }
                    stop.store(true, Ordering::Relaxed);
                    (failed, first, signaller.join().unwrap())
                });
                spin(ms(20));
                let after = counts();
                let moved: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
                eprintln!(
                    "TRIGREC {mode}: 500 updates (vector B to APIC ID 1, then vector A to APIC ID 0, in turn) while another thread signalled {signals} times: \
                     {failed} failed (first HRESULT {:#010x}); delivered vector A {}, B {}, vCPU 0 {}, vCPU 1 {}",
                    first.cast_unsigned(),
                    moved[0],
                    moved[1],
                    moved[2],
                    moved[3]
                );
                let before = counts();
                signal();
                spin(ms(20));
                let after = counts();
                let moved: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
                eprintln!(
                    "TRIGREC {mode}: a signal after the last update (vector A, APIC ID 0): vector A {}, B {}, vCPU 0 {}, vCPU 1 {}",
                    moved[0], moved[1], moved[2], moved[3]
                );
                // SAFETY: the live trigger, deleted once.
                let deleted = unsafe { whv::WHvDeleteTrigger(part, trigger) };
                let before = trig_read(m, TRIG_COUNT_A);
                signal();
                spin(ms(20));
                let after_delete = trig_read(m, TRIG_COUNT_A) - before;
                // SAFETY: the event, still open.
                let (w1, w2) = unsafe { (WaitForSingleObject(event, 0), WaitForSingleObject(event, 0)) };
                // SAFETY: the event handle WHvCreateTrigger gave, closed once.
                let closed = unsafe { CloseHandle(event) };
                eprintln!(
                    "TRIGREC {mode}: WHvDeleteTrigger HRESULT {:#010x}; a signal after it delivered {after_delete}; then two waits read {w1:#x}, {w2:#x}; CloseHandle {closed}",
                    deleted.cast_unsigned()
                );
            }
            // SAFETY: within the test's mapping.
            unsafe { std::ptr::write_volatile(m.add(TRIG_STOP as usize).cast::<u64>(), 1) };
            for id in 0..2u64 {
                inner.inject_msi(TRIG_MSI | id << 12, MMIO_VECTOR as u32);
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while threads.iter().any(|t| !t.is_finished()) && std::time::Instant::now() < deadline {
                std::thread::sleep(ms(1));
            }
            let mut kickers = kickers;
            for (k, t) in kickers.iter_mut().zip(&threads) {
                if !t.is_finished() {
                    k.set_kvm_immediate_exit(1);
                }
            }
            let ended: Vec<(VcpuFd, Vec<String>, String)> = threads.into_iter().map(|t| t.join().unwrap()).collect();
            for (i, (_, exits, runs)) in ended.iter().enumerate() {
                eprintln!("TRIGREC {mode}: vCPU {i}: runs returned {exits:?}; WHvRunVirtualProcessor calls: {runs}");
            }
            for (i, (_, exits, _)) in ended.iter().enumerate() {
                assert!(
                    exits.last().is_some_and(|e| e.starts_with("out 0x80")),
                    "{mode}: vCPU {i} did not stop at its out 0x80: {exits:?}"
                );
            }
            drop(kickers);
            drop(ended);
            drop(irqfd);
            drop(watched);
            // The partition goes with the VM's last reference, this one.
            drop(inner);
            drop(vm);
            // SAFETY: the test's mapping, no VM left using it.
            assert_eq!(unsafe { libc::munmap(m.cast(), MEM) }, 0);
        }
    }
}

#[cfg(test)]
mod lapic_format_tests {
    #[test]
    fn test_the_x2apic_ldr_is_kvms() {
        // kvm_apic_calc_x2apic_ldr: cluster in 31:16, one bit of 16.
        assert_eq!(super::x2apic_ldr(0), 0x1);
        assert_eq!(super::x2apic_ldr(1), 0x2);
        assert_eq!(super::x2apic_ldr(15), 0x8000);
        assert_eq!(super::x2apic_ldr(16), 0x1_0001);
        assert_eq!(super::x2apic_ldr(35), 0x2_0008);
    }

    #[test]
    fn test_an_unkept_msr_is_named_once_and_the_names_are_bounded() {
        use super::{UNKEPT_NAMED, Unkept, unkept_line};
        let mut seen = Vec::new();
        assert_eq!(unkept_line(&mut seen, 0xc001_0015, false), Unkept::First);
        assert_eq!(unkept_line(&mut seen, 0xc001_0015, false), Unkept::Said, "the same read again");
        assert_eq!(unkept_line(&mut seen, 0xc001_0015, true), Unkept::First, "its write is another access");
        for index in 1..u32::try_from(UNKEPT_NAMED).unwrap() - 1 {
            assert_eq!(unkept_line(&mut seen, index, false), Unkept::First, "{index:#x}");
        }
        assert_eq!(seen.len(), UNKEPT_NAMED);
        assert_eq!(unkept_line(&mut seen, 0x9999, false), Unkept::Past, "the first past the bound");
        for index in 0x1_0000..0x1_0100 {
            assert_eq!(unkept_line(&mut seen, index, true), Unkept::Said, "past the bound: {index:#x}");
        }
        assert_eq!(seen.len(), UNKEPT_NAMED + 1, "what is kept stays bounded");
    }
}
