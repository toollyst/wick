// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! PV time (stolen time, aarch64): KVM's `KVM_ARM_VCPU_PVTIME_CTRL` vCPU
//! attribute and the SMCCC calls of Arm DEN0057A a guest finds it by, as KVM
//! has them (Linux arch/arm64/kvm/pvtime.c, hypercalls.c; the guest's side:
//! arch/arm64/kernel/paravirt.c).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread;
use std::time::Duration;

use kvm_bindings::{KVM_ARM_VCPU_PVTIME_CTRL, KVM_ARM_VCPU_PVTIME_IPA, kvm_device_attr};

use super::ffi::{hv_return_t, hv_vcpu_t, hv_vcpus_exit};
use super::{Result, err};

pub(crate) use super::exit::{PV_TIME_FEATURES, PV_TIME_ST};
/// `struct pvclock_vcpu_stolen_time` (le32 revision, le32 attributes, le64
/// stolen_time, padding): 64 bytes, the alignment KVM requires of its IPA.
pub(crate) const STRUCT_SIZE: usize = 64;
/// No IPA set: KVM's `INVALID_GPA`.
pub(crate) const NO_IPA: u64 = u64::MAX;

/// `hv_vcpu_get_wait_for_interrupt_time` (macOS 27): the time a vCPU waited
/// in `WFI` inside `hv_vcpu_run`, in `mach_absolute_time` units.
type WfiTime = unsafe extern "C" fn(hv_vcpu_t, *mut u64) -> hv_return_t;

/// The framework's `hv_vcpu_get_wait_for_interrupt_time`, looked up rather
/// than linked, so the binary runs on a macOS without it.
fn wfi_time_fn() -> Option<WfiTime> {
    static F: OnceLock<usize> = OnceLock::new();
    let f = *F.get_or_init(|| {
        // SAFETY: dlsym with a NUL-terminated name.
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"hv_vcpu_get_wait_for_interrupt_time".as_ptr()) as usize }
    });
    // SAFETY: the address of the framework's function of that signature
    // (hv_vcpu.h).
    (f != 0).then(|| unsafe { std::mem::transmute::<usize, WfiTime>(f) })
}

#[cfg(test)]
thread_local! {
    /// Tests force the path of a macOS without the WFI figure, on their
    /// own thread only: another test in the same process (cargo's
    /// threads, or check-unit-tests.py's one thread after it) keeps the
    /// host's answer.
    pub(crate) static FORCE_UNSUPPORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether PV time is offered: only where the vCPU's steal can be told
/// from its guest idling. With the framework's GIC a guest's `WFI` waits
/// inside `hv_vcpu_run` (`VcpuFd::wait_for_interrupt`), so the time a vCPU
/// spends there is the guest's own idle, the host's work, or the host
/// keeping it off a CPU, and only `hv_vcpu_get_wait_for_interrupt_time`
/// (macOS 27) gives the first apart; before it no interface does (thread
/// times count no run-queue wait, `ri_runnable_time` is the process's).
/// KVM likewise offers PV time only where it can account steal
/// (pvtime.c kvm_arm_pvtime_supported: `sched_info_on()`; otherwise
/// kvm_arm_pvtime_has_attr and set_attr are `ENXIO`), and Firecracker then
/// gives the guest none (builder.rs: "steal time will not be reported").
pub(crate) fn supported() -> bool {
    #[cfg(test)]
    if FORCE_UNSUPPORTED.with(std::cell::Cell::get) {
        return false;
    }
    wfi_time_fn().is_some()
}

/// `KVM_HAS_DEVICE_ATTR` on a vCPU, for the groups this backend has: PV time's
/// IPA where it is [`supported`] (kvm_arm_pvtime_has_attr); anything else
/// `ENXIO`, as KVM answers a group it does not know (kvm_arm_vcpu_arch_has_attr).
pub(crate) fn has_attr(attr: &kvm_device_attr) -> Result<()> {
    if attr.group == KVM_ARM_VCPU_PVTIME_CTRL && attr.attr == u64::from(KVM_ARM_VCPU_PVTIME_IPA) && supported() {
        Ok(())
    } else {
        err(libc::ENXIO)
    }
}

/// The IPA a `KVM_SET_DEVICE_ATTR` of PV time's group asks for, checked as
/// kvm_arm_pvtime_set_attr checks it before it looks at the vCPU: another
/// attribute, or PV time not [`supported`], is `ENXIO`, an unreadable
/// pointer `EFAULT`, an IPA not 64-byte
/// aligned `EINVAL`. The caller then refuses a second IPA (`EEXIST`) and one
/// outside guest memory (`EINVAL`), in that order.
pub(crate) fn requested_ipa(attr: &kvm_device_attr) -> Result<u64> {
    if attr.group != KVM_ARM_VCPU_PVTIME_CTRL
        || attr.attr != u64::from(KVM_ARM_VCPU_PVTIME_IPA)
        || !supported()
    {
        return err(libc::ENXIO);
    }
    if attr.addr == 0 {
        return err(libc::EFAULT);
    }
    // SAFETY: KVM reads a u64 from the caller's `addr` (get_user); the
    // caller passes the address of one, as every KVM attribute does.
    let ipa = unsafe { std::ptr::read_unaligned(attr.addr as *const u64) };
    if ipa % STRUCT_SIZE as u64 != 0 {
        return err(libc::EINVAL);
    }
    Ok(ipa)
}

/// SMCCC_ARCH_FEATURES of `feature`, for PV time's calls: `Some(0)`
/// (SUCCESS) for PV_TIME_FEATURES, which KVM reports by its standard
/// hypervisor services' bitmap, PV time in by default, whether or not the
/// vCPU has an IPA (kvm_smccc_call_handler; KVM_ARM_SMCCC_STD_HYP_FEATURES).
pub(crate) fn arch_feature(feature: u32) -> Option<u64> {
    (feature == PV_TIME_FEATURES).then_some(0)
}

/// PV_TIME_FEATURES of `feature` (kvm_hypercall_pv_features): SUCCESS for
/// PV_TIME_FEATURES and PV_TIME_ST once the vCPU has an IPA.
pub(crate) fn features(feature: u32, ipa: u64) -> bool {
    matches!(feature, PV_TIME_FEATURES | PV_TIME_ST) && ipa != NO_IPA
}

/// The calling thread's CPU time, in nanoseconds (user and system: what
/// the kernel ran it for, guest execution included).
fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: plain call into a valid timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// One millisecond: how often the guest's figure is brought up to date at
/// most (KVM brings it up to date when the vCPU thread is scheduled in
/// again, KVM_REQ_RECORD_STEAL: at most once per scheduling period).
const UPDATE_NS: u64 = 1_000_000;

/// A vCPU's PV time: its IPA and its steal accounting.
///
/// KVM's steal is the vCPU thread's `sched_info.run_delay`: the time it was
/// runnable and not running (pvtime.c kvm_update_stolen_time). Here the
/// vCPU's thread is accounted while it is in `run()` (Firecracker's
/// `KVM_RUN`): its wall time less its CPU time (guest execution and the
/// framework's and this backend's work count as running, as on KVM) less
/// the time it waited of the guest's own accord: in `WFI` inside
/// `hv_vcpu_run` (`hv_vcpu_get_wait_for_interrupt_time`), in this
/// backend's own waits (`VcpuFd::wait_powered_on`, a no-GIC `WFI`).
/// Two differences from run_delay remain:
/// - time outside `run()` is not accounted: Firecracker's vCPU thread
///   then handles an exit or waits paused, and the two cannot be told
///   apart, so a preemption while it handles an exit is not counted
///   (KVM counts it);
/// - a block inside `run()` that is not one of those waits counts as
///   steal (KVM would not count a sleeping thread): a userfaultfd page
///   wait, a wait for guest pages being replaced, a contended lock.
///
/// A vCPU that stays in `hv_vcpu_run` (a guest that computes, or idles in
/// `WFI` with the framework's GIC, which never leaves it) would have its
/// steal brought up to date only at its next exit: the [`Kicker`] makes it
/// leave when it has been off its CPU for long enough.
#[derive(Debug)]
pub(crate) struct Steal {
    /// `KVM_ARM_VCPU_PVTIME_IPA`, or `NO_IPA`.
    pub(crate) ipa: u64,
    /// Accounting has a starting point (after the IPA is set, at the
    /// guest's PV_TIME_ST, which restarts it as kvm_init_stolen_time does).
    started: bool,
    /// The start of the `run()` interval being accounted: wall and CPU ns.
    window: Option<(u64, u64)>,
    /// Steal of the intervals closed since the last update, before the
    /// framework's WFI time is taken off (ns, may be negative).
    pending: i64,
    /// `hv_vcpu_get_wait_for_interrupt_time` at the last update.
    wfi: u64,
    /// Wall ns of the last update.
    updated: u64,
    /// Steal accounted since the start, and the part the guest has.
    total: i64,
    reported: i64,
    /// While the owner thread is in `run()`: its Mach thread port and its
    /// vCPU, for the [`Kicker`]. Set and cleared by the owner under this
    /// lock, which the kicker holds while it uses them: the port names a
    /// live thread, the vCPU exists.
    running: Option<(libc::mach_port_t, hv_vcpu_t)>,
    /// Changes when the accounting moves on (an update, a new `run()`): the
    /// kicker then measures from there.
    seq: u64,
}

impl Default for Steal {
    fn default() -> Self {
        Steal {
            ipa: NO_IPA,
            started: false,
            window: None,
            pending: 0,
            wfi: 0,
            updated: 0,
            total: 0,
            reported: 0,
            running: None,
            seq: 0,
        }
    }
}

impl Steal {
    /// Opens the interval of a `run()` call (only with an IPA: no cost
    /// otherwise), made by the calling thread on `hv`.
    pub(crate) fn enter(&mut self, wall_ns: u64, hv: hv_vcpu_t) {
        if self.ipa != NO_IPA {
            self.window = Some((wall_ns, thread_cpu_ns()));
            // SAFETY: plain call on this thread.
            self.running = Some((unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) }, hv));
            self.seq += 1;
        }
    }

    /// Closes the interval so far into `pending`.
    fn close(&mut self, wall_ns: u64) {
        if let Some((wall, cpu)) = self.window {
            let now_cpu = thread_cpu_ns();
            self.pending += (wall_ns - wall) as i64 - (now_cpu - cpu) as i64;
            self.window = Some((wall_ns, now_cpu));
        }
    }

    /// Ends the interval of a `run()` call.
    pub(crate) fn leave(&mut self, wall_ns: u64) {
        self.close(wall_ns);
        self.window = None;
        self.running = None;
        self.seq += 1;
    }

    /// A wait of the guest's own accord inside `run()` (ns).
    pub(crate) fn waited(&mut self, ns: u64) {
        if self.window.is_some() {
            self.pending -= ns as i64;
        }
    }

    /// Restarts the accounting (the IPA newly in use, or the guest's
    /// PV_TIME_ST); `wfi` is the framework's WFI time now.
    pub(crate) fn start(&mut self, wall_ns: u64, wfi: u64) {
        self.started = true;
        self.pending = 0;
        self.total = 0;
        self.reported = 0;
        self.wfi = wfi;
        self.updated = wall_ns;
        self.seq += 1;
        if self.window.is_some() {
            self.window = Some((wall_ns, thread_cpu_ns()));
        }
    }

    /// Whether an update is due (at most every `UPDATE_NS`).
    pub(crate) fn due(&self, wall_ns: u64) -> bool {
        self.ipa != NO_IPA && (!self.started || wall_ns - self.updated >= UPDATE_NS)
    }

    /// Brings the accounting up to `wall_ns`, `wfi_ns` being the
    /// framework's WFI time now in ns. Returns the steal (ns) to add to the
    /// guest's figure, which only grows.
    pub(crate) fn update(&mut self, wall_ns: u64, wfi_ns: u64) -> u64 {
        if !self.started {
            self.start(wall_ns, wfi_ns);
            return 0;
        }
        self.close(wall_ns);
        self.total += self.pending - (wfi_ns - self.wfi) as i64;
        self.pending = 0;
        self.wfi = wfi_ns;
        self.updated = wall_ns;
        self.seq += 1;
        if self.total > self.reported {
            let add = self.total - self.reported;
            self.reported = self.total;
            add as u64
        } else {
            0
        }
    }
}

/// The framework's WFI time of `hv` (the owner thread's vCPU), in
/// `mach_absolute_time` units; 0 where it does not exist (PV time is then
/// not offered, [`supported`]).
pub(crate) fn wfi_ticks(hv: hv_vcpu_t) -> u64 {
    let mut t = 0;
    if let Some(f) = wfi_time_fn() {
        // SAFETY: `hv` belongs to the calling thread, as the call requires.
        unsafe { f(hv, &mut t) };
    }
    t
}

/// How often the kicker looks at the vCPUs in `run()`: 2 ms, whatever the
/// guest does. A vCPU that ends a `WFI` stays in `hv_vcpu_run` (the
/// framework's GIC), so nothing else tells the kicker a guest went from
/// idle to busy: a longer period while every vCPU waits would make the
/// update later by that much, and only for some guests' states. Measured
/// cost (macOS 27.2, `boot-test pvtime` under load): 3.2 to 6.3 ms of one
/// CPU per second per microVM while a vCPU is in `run()`, the idle guest's
/// included; nothing while none is (paused, or before the start).
pub(crate) const KICK_PERIOD: Duration = Duration::from_millis(2);
/// A vCPU off its CPU for more than 1 ms since its last update is made to
/// leave `hv_vcpu_run`, so that its owner adds that steal: KVM adds it
/// when the thread is scheduled in again. Another thread's CPU time, as
/// `thread_info` gives it, lags the thread's own by 72 µs at most
/// (measured on macOS 27.2: one thread spinning, another reading it, mean
/// 2 µs), and a reading whose two clock reads
/// are more than [`KICK_BRACKET_NS`] apart is dropped: the figure the
/// kicker compares is within about 120 µs, well under the threshold.
const KICK_NS: i64 = 1_000_000;
/// The most a reading may take (the kicker itself held up in between).
const KICK_BRACKET_NS: u64 = 50_000;
/// How often the kicker reports its kicks (a debug line).
const KICK_LOG_NS: u64 = 10_000_000_000;

/// The microVM's PV time kicker: a thread that makes a vCPU leave
/// `hv_vcpu_run` when its thread has been off its CPU, outside the guest's
/// own waits, for more than [`KICK_NS`] since its steal was last brought
/// up to date, so that the owner brings it up to date (`VcpuFd::run` takes
/// the exit, `HV_EXIT_REASON_CANCELED`, and runs the vCPU again: neither
/// the guest nor Firecracker sees it). It reads the vCPU threads with
/// `thread_info` (THREAD_BASIC_INFO: run state, CPU time), the one view of
/// another thread's time the framework leaves: its own counters
/// (`hv_vcpu_get_exec_time`, `hv_vcpu_get_wait_for_interrupt_time`) answer
/// only the vCPU's thread (HV_BAD_ARGUMENT from another, measured). A
/// vCPU whose thread is not running (in `WFI`, or blocked) is not kicked.
/// It exists only where PV time is offered ([`supported`]), one per VM,
/// and is joined when the VM is dropped.
#[derive(Debug, Default)]
pub(crate) struct Kicker {
    vcpus: Mutex<Vec<Weak<Mutex<Steal>>>>,
    /// vCPUs in `run()`; the thread sleeps while there are none.
    inside: AtomicUsize,
    wake: Mutex<()>,
    cv: Condvar,
    stop: AtomicBool,
    /// Kicks so far, for the tests and the debug line.
    pub(crate) kicks: AtomicU64,
}

impl Kicker {
    /// The VM's kicker and its thread, where PV time is offered.
    pub(crate) fn start() -> std::io::Result<Option<(Arc<Kicker>, thread::JoinHandle<()>)>> {
        if !supported() {
            return Ok(None);
        }
        let kicker = Arc::new(Kicker::default());
        let k = kicker.clone();
        let handle = thread::Builder::new().name("wick_hvf_pvtime".into()).spawn(move || k.run())?;
        Ok(Some((kicker, handle)))
    }

    /// Adds a vCPU whose PV time is set.
    pub(crate) fn register(&self, steal: &Arc<Mutex<Steal>>) {
        self.vcpus.lock().unwrap().push(Arc::downgrade(steal));
    }

    /// A vCPU's thread entered `run()`.
    pub(crate) fn entered(&self) {
        if self.inside.fetch_add(1, Ordering::AcqRel) == 0 {
            let _g = self.wake.lock().unwrap();
            self.cv.notify_one();
        }
    }

    /// A vCPU's thread left `run()`.
    pub(crate) fn left(&self) {
        self.inside.fetch_sub(1, Ordering::AcqRel);
    }

    /// Ends the thread (the VM is going).
    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        let _g = self.wake.lock().unwrap();
        self.cv.notify_one();
    }

    fn run(&self) {
        // Per vCPU (by its index in `vcpus`): the reading the kicker
        // measures from, with the accounting's `seq` it was taken in.
        let mut from: Vec<Option<(u64, u64, u64)>> = Vec::new();
        let mut logged = (now_ns(), 0, thread_cpu_ns());
        while !self.stop.load(Ordering::Acquire) {
            if self.inside.load(Ordering::Acquire) == 0 {
                let g = self.wake.lock().unwrap();
                if self.inside.load(Ordering::Acquire) == 0 && !self.stop.load(Ordering::Acquire) {
                    drop(self.cv.wait_timeout(g, Duration::from_secs(1)).unwrap());
                }
                from.clear();
                continue;
            }
            let vcpus: Vec<_> = self.vcpus.lock().unwrap().clone();
            from.resize(vcpus.len(), None);
            for (vcpu, from) in vcpus.iter().zip(from.iter_mut()) {
                let Some(steal) = vcpu.upgrade() else {
                    *from = None;
                    continue;
                };
                let steal = steal.lock().unwrap();
                if self.look(&steal, from) {
                    let (_, hv) = steal.running.expect("looked at a vCPU in run()");
                    // SAFETY: the vCPU exists while its owner is in `run()`,
                    // which it cannot leave while this lock is held.
                    unsafe { hv_vcpus_exit(&hv, 1) };
                    self.kicks.fetch_add(1, Ordering::Relaxed);
                    *from = None;
                }
            }
            let now = now_ns();
            if now - logged.0 >= KICK_LOG_NS {
                let (kicks, cpu) = (self.kicks.load(Ordering::Relaxed), thread_cpu_ns());
                log::debug!(
                    "pvtime: {} vCPU exits for steal time in {:.1} s; the kicker's own CPU time {:.1} ms",
                    kicks - logged.1,
                    (now - logged.0) as f64 / 1e9,
                    (cpu - logged.2) as f64 / 1e6
                );
                logged = (now, kicks, cpu);
            }
            thread::sleep(KICK_PERIOD);
        }
    }

    /// Reads `steal`'s thread; whether it is due a kick. `from` is where
    /// the kicker measures from, for that vCPU.
    fn look(&self, steal: &Steal, from: &mut Option<(u64, u64, u64)>) -> bool {
        let Some((port, _)) = steal.running else {
            *from = None;
            return false;
        };
        let before = now_ns();
        let Some((running, cpu)) = thread_state(port) else {
            *from = None;
            return false;
        };
        let wall = now_ns();
        if wall - before > KICK_BRACKET_NS {
            return false;
        }
        if !running {
            // In WFI or blocked: not runnable, so not stolen from.
            *from = None;
            return false;
        }
        match *from {
            Some((seq, w0, c0)) if seq == steal.seq => (wall - w0) as i64 - (cpu as i64 - c0 as i64) > KICK_NS,
            _ => {
                *from = Some((steal.seq, wall, cpu));
                false
            }
        }
    }
}

/// `mach_absolute_time` in ns.
fn now_ns() -> u64 {
    super::vcpu::wall_ns()
}

/// Whether the thread of `port` is running (TH_STATE_RUNNING: on a CPU or
/// waiting for one), and its CPU time (ns, µs resolution), by
/// `thread_info(THREAD_BASIC_INFO)`.
fn thread_state(port: libc::mach_port_t) -> Option<(bool, u64)> {
    // SAFETY: a zeroed plain-data structure.
    let mut info: libc::thread_basic_info = unsafe { std::mem::zeroed() };
    let mut count = libc::THREAD_BASIC_INFO_COUNT;
    // SAFETY: a thread port of this task and a buffer of `count` words.
    let ret = unsafe {
        libc::thread_info(port, libc::THREAD_BASIC_INFO as libc::thread_flavor_t, std::ptr::from_mut(&mut info).cast(), &mut count)
    };
    if ret != libc::KERN_SUCCESS {
        return None;
    }
    let us = |t: libc::time_value_t| t.seconds as u64 * 1_000_000 + t.microseconds as u64;
    Some((info.run_state == libc::TH_STATE_RUNNING, (us(info.user_time) + us(info.system_time)) * 1000))
}

#[cfg(test)]
mod tests {
    use kvm_bindings::{kvm_device_attr, kvm_userspace_memory_region, kvm_vcpu_init};

    use crate::{Kvm, VcpuExit, VcpuFd, VmFd};

    const PVTIME_CTRL: u32 = 2; // KVM_ARM_VCPU_PVTIME_CTRL
    const PVTIME_IPA: u64 = 0; // KVM_ARM_VCPU_PVTIME_IPA
    const RAM: u64 = 0x8000_0000;
    /// Where the tests put a vCPU's stolen-time structure: in RAM, 64-byte aligned.
    const ST: u64 = RAM + 0x2000;
    const PC: u64 = 0x6030_0000_0010_0040;
    const PSTATE: u64 = 0x6030_0000_0010_0042;
    const X9: u64 = 0x6030_0000_0010_0012;
    /// SMCCC NOT_SUPPORTED as the 64-bit X0 the guest reads.
    const NOT_SUPPORTED: u64 = u64::MAX;

    fn attr(group: u32, attr: u64, value: &u64) -> kvm_device_attr {
        kvm_device_attr { group, attr, addr: std::ptr::from_ref(value) as u64, flags: 0 }
    }

    /// A VM with one page of RAM at `RAM` (slot 0, with `flags`) holding
    /// `code`; the page's host address (filled with 0xaa past the code) and
    /// the VM.
    fn vm_with_code(code: &[u32], flags: u32) -> (VmFd, *mut u8) {
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        // SAFETY: plain call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        // SAFETY: an anonymous mapping of one page, kept for the test.
        let mem = unsafe {
            libc::mmap(std::ptr::null_mut(), page, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE, -1, 0)
        };
        assert_ne!(mem, libc::MAP_FAILED);
        let mem = mem.cast::<u8>();
        // SAFETY: the page just mapped, larger than the code.
        unsafe {
            std::ptr::write_bytes(mem, 0xaa, page);
            std::ptr::copy_nonoverlapping(code.as_ptr().cast::<u8>(), mem, code.len() * 4);
        }
        let region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: RAM,
            memory_size: page as u64,
            userspace_addr: mem as u64,
            flags,
        };
        // SAFETY: the page stays mapped for the test.
        unsafe { vm.set_user_memory_region(region).unwrap() };
        (vm, mem)
    }

    fn new_vcpu(vm: &VmFd, id: u64) -> VcpuFd {
        let vcpu = vm.create_vcpu(id).unwrap();
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        vcpu
    }

    #[test]
    fn test_the_attribute_is_enxio_where_pv_time_is_not_offered() {
        // No VM needed: KVM_HAS_DEVICE_ATTR and KVM_SET_DEVICE_ATTR of PV
        // time's IPA are answered from the host's capability before any
        // vCPU is looked at. Where the framework has no WFI figure (macOS
        // 15 and 26, CI's runners among them) both are ENXIO, as on a KVM
        // that cannot account steal (pvtime.c kvm_arm_pvtime_has_attr,
        // kvm_arm_pvtime_set_attr); where it has one (macOS 27) the
        // attribute exists, and forcing the other path on this thread
        // gives ENXIO there too.
        let ipa = ST;
        let a = attr(PVTIME_CTRL, PVTIME_IPA, &ipa);
        let errno = |r: crate::Result<()>| r.map_err(|e| e.errno()).err();
        let set = |a: &kvm_device_attr| super::requested_ipa(a).map(|_| ());
        let offered = super::wfi_time_fn().is_some();
        if offered {
            assert_eq!(errno(super::has_attr(&a)), None);
            assert_eq!(errno(set(&a)), None);
        }
        {
            let _forced = Forced::new();
            assert!(!super::supported());
            assert_eq!(errno(super::has_attr(&a)), Some(libc::ENXIO));
            assert_eq!(errno(set(&a)), Some(libc::ENXIO));
        }
        assert_eq!(super::supported(), offered);
        println!("the framework's WFI figure: {}", if offered { "present (macOS 27)" } else { "absent" });
    }

    /// The path of a macOS without the WFI figure, on this thread, until
    /// dropped (a test that runs after this one on the same thread, as
    /// libtest may with one test thread, keeps the host's answer).
    struct Forced;

    impl Forced {
        fn new() -> Self {
            super::FORCE_UNSUPPORTED.with(|f| f.set(true));
            Forced
        }
    }

    impl Drop for Forced {
        fn drop(&mut self) {
            super::FORCE_UNSUPPORTED.with(|f| f.set(false));
        }
    }

    /// Makes a VM and a vCPU (so that a host without Hypervisor.framework
    /// fails here, as every test that needs one does); where PV time is
    /// not offered, checks that its attribute is refused (ENXIO) and says
    /// so. Whether PV time is offered.
    fn offered_or_refused() -> bool {
        let (vm, _) = vm_with_code(&[0x1400_0000], 0);
        let vcpu = new_vcpu(&vm, 0);
        if super::supported() {
            return true;
        }
        let e = vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ST)).map_err(|e| e.errno()).err();
        assert_eq!(e, Some(libc::ENXIO));
        println!("PV time is not offered on this macOS (no hv_vcpu_get_wait_for_interrupt_time): its attribute is ENXIO");
        false
    }

    #[test]
    fn test_pvtime_attribute_as_on_kvm() {
        // KVM's KVM_ARM_VCPU_PVTIME_CTRL (arch/arm64/kvm/pvtime.c
        // kvm_arm_pvtime_has_attr/set_attr): the IPA attribute exists;
        // setting it takes a 64-byte aligned guest RAM address, once per
        // vCPU (a reset by KVM_ARM_VCPU_INIT keeps it: only vCPU creation
        // clears it, arm.c kvm_arch_vcpu_create -> kvm_arm_pvtime_vcpu_init);
        // any other attribute or group is ENXIO.
        if !offered_or_refused() {
            return;
        }
        let (vm, _) = vm_with_code(&[0x1400_0000], 0);
        let vcpu = new_vcpu(&vm, 0);
        let errno = |r: crate::Result<()>| r.map_err(|e| e.errno()).err();
        let ipa = ST;
        assert_eq!(errno(vcpu.has_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ipa))), None);
        assert_eq!(errno(vcpu.has_device_attr(&attr(PVTIME_CTRL, 1, &ipa))), Some(libc::ENXIO));
        assert_eq!(errno(vcpu.has_device_attr(&attr(7, PVTIME_IPA, &ipa))), Some(libc::ENXIO));
        assert_eq!(errno(vcpu.set_device_attr(&attr(PVTIME_CTRL, 1, &ipa))), Some(libc::ENXIO));
        let unaligned = ST + 8;
        assert_eq!(errno(vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &unaligned))), Some(libc::EINVAL));
        let outside = RAM - 0x1000;
        assert_eq!(errno(vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &outside))), Some(libc::EINVAL));
        let null = kvm_device_attr { group: PVTIME_CTRL, attr: PVTIME_IPA, addr: 0, flags: 0 };
        assert_eq!(errno(vcpu.set_device_attr(&null)), Some(libc::EFAULT));
        assert_eq!(errno(vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ipa))), None);
        assert_eq!(errno(vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ipa))), Some(libc::EEXIST));
        let mut kvi = kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(errno(vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ipa))), Some(libc::EEXIST));
        // Another vCPU has its own.
        let other = new_vcpu(&vm, 1);
        let next = ST + 64;
        assert_eq!(errno(other.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &next))), None);
    }

    /// Runs `vcpu` on a thread of its own until the guest has stored `n`
    /// values to MMIO; the values.
    fn mmio_values(mut vcpu: VcpuFd, n: usize) -> Vec<u64> {
        std::thread::spawn(move || {
            vcpu.set_one_reg(PC, &RAM.to_le_bytes()).unwrap();
            vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
            vcpu.set_one_reg(X9, &0x1000u64.to_le_bytes()).unwrap();
            let mut values = Vec::new();
            while values.len() < n {
                match vcpu.run().unwrap() {
                    VcpuExit::MmioWrite(0x1000, data) => {
                        values.push(u64::from_le_bytes(data.try_into().unwrap()));
                    }
                    other => panic!("unexpected exit {other:?}"),
                }
            }
            values
        })
        .join()
        .unwrap()
    }

    #[test]
    fn test_pv_time_calls_as_on_kvm() {
        // The calls a Linux guest finds PV time by (arch/arm64/kernel/
        // paravirt.c has_pv_steal_clock, stolen_time_cpu_online), answered
        // as KVM answers them (arch/arm64/kvm/hypercalls.c
        // kvm_smccc_call_handler, pvtime.c): SMCCC_ARCH_FEATURES of
        // PV_TIME_FEATURES is SUCCESS (the standard hypervisor services'
        // default bitmap has PV time); PV_TIME_FEATURES of PV_TIME_FEATURES
        // or PV_TIME_ST is SUCCESS only for a vCPU given an IPA, any other
        // feature NOT_SUPPORTED; PV_TIME_ST gives the IPA, with the structure
        // zeroed (kvm_init_stolen_time), or NOT_SUPPORTED without one; the
        // SMC32 id of PV_TIME_ST is no call. Each answer is X0, which the
        // guest stores to MMIO:
        //   x0 = 0x80000001, x1 = 0xc5000020; hvc #0; str x0, [x9]
        //   x0 = 0xc5000020, x1 = 0xc5000021; hvc #0; str x0, [x9]
        //   x0 = 0xc5000020, x1 = 0xc5000022; hvc #0; str x0, [x9]
        //   x0 = 0xc5000021;                  hvc #0; str x0, [x9]
        //   x0 = 0x85000021;                  hvc #0; str x0, [x9]
        //   b .
        if !offered_or_refused() {
            return;
        }
        let code = [
            0xd280_0020, 0xf2b0_0000, 0xd280_0401, 0xf2b8_a001, 0xd400_0002, 0xf900_0120,
            0xd280_0400, 0xf2b8_a000, 0xd280_0421, 0xf2b8_a001, 0xd400_0002, 0xf900_0120,
            0xd280_0400, 0xf2b8_a000, 0xd280_0441, 0xf2b8_a001, 0xd400_0002, 0xf900_0120,
            0xd280_0420, 0xf2b8_a000, 0xd400_0002, 0xf900_0120,
            0xd280_0420, 0xf2b0_a000, 0xd400_0002, 0xf900_0120,
            0x1400_0000,
        ];
        // Dirty-tracked, as during a diff snapshot: the hypervisor's write
        // marks the page (KVM: kvm_write_guest -> mark_page_dirty); the
        // guest itself writes no RAM (its stores are MMIO, and code
        // fetches dirty nothing).
        let (vm, mem) = vm_with_code(&code, kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES);
        let with = new_vcpu(&vm, 0);
        with.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ST)).unwrap();
        assert_eq!(mmio_values(with, 5), [0, 0, NOT_SUPPORTED, ST, NOT_SUPPORTED]);
        // SAFETY: the structure lies in the test's page.
        let st = unsafe { std::slice::from_raw_parts(mem.add((ST - RAM) as usize), 64) };
        assert_eq!(st, [0u8; 64], "PV_TIME_ST zeroes the structure");
        // SAFETY: plain call.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(vm.get_dirty_log(0, page).unwrap(), [1], "the structure's page is dirty");
        let without = new_vcpu(&vm, 1);
        assert_eq!(mmio_values(without, 5), [0, NOT_SUPPORTED, NOT_SUPPORTED, NOT_SUPPORTED, NOT_SUPPORTED]);
    }

    #[test]
    fn test_pv_time_is_not_offered_without_the_wfi_figure() {
        // Before macOS 27 (forced here: the switch takes the path of a
        // framework without hv_vcpu_get_wait_for_interrupt_time) PV time is
        // not offered, as KVM offers none where it cannot account steal
        // (pvtime.c kvm_arm_pvtime_supported): the attribute is ENXIO and
        // the guest's calls find no structure. SMCCC_ARCH_FEATURES of
        // PV_TIME_FEATURES stays SUCCESS, as KVM's bitmap answers it.
        let _forced = Forced::new();
        let code = [
            0xd280_0020, 0xf2b0_0000, 0xd280_0401, 0xf2b8_a001, 0xd400_0002, 0xf900_0120,
            0xd280_0400, 0xf2b8_a000, 0xd280_0421, 0xf2b8_a001, 0xd400_0002, 0xf900_0120,
            0xd280_0420, 0xf2b8_a000, 0xd400_0002, 0xf900_0120,
            0x1400_0000,
        ];
        let (vm, _) = vm_with_code(&code, 0);
        let vcpu = new_vcpu(&vm, 0);
        let e = |r: crate::Result<()>| r.map_err(|e| e.errno()).err();
        assert_eq!(e(vcpu.has_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ST))), Some(libc::ENXIO));
        assert_eq!(e(vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ST))), Some(libc::ENXIO));
        assert_eq!(mmio_values(vcpu, 3), [0, NOT_SUPPORTED, NOT_SUPPORTED]);
    }

    unsafe extern "C" {
        fn hv_vcpu_get_exec_time(vcpu: u64, time: *mut u64) -> i32;
    }

    fn thread_cpu() -> u64 {
        super::thread_cpu_ns()
    }

    /// What one vCPU's run shows: (wall ns spent in run(), thread CPU ns in
    /// run(), the framework's exec ns, its WFI ns, the guest's stolen_time).
    /// The GIC Firecracker always makes: with it a guest's WFI waits in the
    /// framework, which then has a WFI figure. Kept while the VM runs.
    fn with_gic(vm: &VmFd) -> crate::DeviceFd {
        let mut dev = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let gic = vm.create_device(&mut dev).unwrap();
        let set = |group: u32, attr: u64, value: u64| {
            gic.set_device_attr(&kvm_device_attr { group, attr, addr: std::ptr::from_ref(&value) as u64, flags: 0 })
                .unwrap();
        };
        let dist = 0x4000_0000 - 0x1_0000;
        set(kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR, kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST.into(), dist);
        set(kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR, kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST.into(), dist - (32 << 20));
        set(kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL, kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT.into(), 0);
        gic
    }

    /// Threads spinning on the host's CPUs until the flag is set.
    fn hogs_on(n: usize) -> (std::sync::Arc<std::sync::atomic::AtomicBool>, Vec<std::thread::JoinHandle<()>>) {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hogs = (0..n)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();
        (stop, hogs)
    }

    /// x0 = PV_TIME_ST; hvc; str x0, [x9] (an MMIO store at 0x1000), then
    /// `b .` (spin: never leaves the guest) or `wfi; b .-4` (wait: never
    /// leaves the framework, which has the GIC).
    const SPIN_FOREVER: [u32; 5] = [0xd280_0420, 0xf2b8_a000, 0xd400_0002, 0xf900_0120, 0x1400_0000];
    const WAIT_FOREVER: [u32; 6] = [0xd280_0420, 0xf2b8_a000, 0xd400_0002, 0xf900_0120, 0xd503_207f, 0x17ff_ffff];

    /// Runs `code` (one of the two above) on a vCPU with PV time, under
    /// `hogs` spinning threads, for `run_for` in one `run()` call; returns
    /// the guest's stolen time and the VM's kicks read while that call was
    /// still running, then ends it.
    fn steal_inside_one_run(code: &[u32], hogs: usize, run_for: std::time::Duration) -> (u64, u64) {
        let (vm, mem) = vm_with_code(code, 0);
        let mem = mem as usize;
        let _gic = with_gic(&vm);
        let mut vcpu = new_vcpu(&vm, 0);
        vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ST)).unwrap();
        // SAFETY: dup of the vCPU's descriptor, owned by the new handle.
        let mut other = unsafe { vm.create_vcpu_from_rawfd(libc::dup(std::os::unix::io::AsRawFd::as_raw_fd(&vcpu))).unwrap() };
        let (stop, hog) = hogs_on(hogs);
        let returned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = returned.clone();
        let runner = std::thread::spawn(move || {
            vcpu.set_one_reg(PC, &RAM.to_le_bytes()).unwrap();
            vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
            vcpu.set_one_reg(X9, &0x1000u64.to_le_bytes()).unwrap();
            match vcpu.run().unwrap() {
                VcpuExit::MmioWrite(_, d) => assert_eq!(u64::from_le_bytes(d.try_into().unwrap()), ST),
                other => panic!("{other:?}"),
            }
            let e = vcpu.run().map(|_| ()).unwrap_err();
            r.store(true, std::sync::atomic::Ordering::Release);
            assert_eq!(e.errno(), libc::EINTR);
        });
        let kicker = vm.inner.pvtime_kicker.get().unwrap().clone();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let kicks0 = kicker.kicks.load(std::sync::atomic::Ordering::Relaxed);
        std::thread::sleep(run_for);
        // SAFETY: stolen_time, le64 at ST + 8 in the test's page.
        let stolen = u64::from_le(unsafe { std::ptr::read_volatile((mem + (ST - RAM) as usize + 8) as *const u64) });
        let kicks = kicker.kicks.load(std::sync::atomic::Ordering::Relaxed) - kicks0;
        assert!(!returned.load(std::sync::atomic::Ordering::Acquire), "run() returned before it was ended");
        other.set_kvm_immediate_exit(1);
        runner.join().unwrap();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        hog.into_iter().for_each(|h| h.join().unwrap());
        println!("hogs {hogs}: stolen {:.1} ms in {:?}, {kicks} kicks", stolen as f64 / 1e6, run_for);
        (stolen, kicks)
    }

    #[test]
    fn test_a_vcpu_kept_off_its_cpu_has_its_steal_updated_while_it_runs() {
        // A guest that computes and never exits stays in one run() call:
        // KVM brings its stolen time up to date each time its thread is
        // scheduled in again (KVM_REQ_RECORD_STEAL, kvm_arch_vcpu_load), so
        // the guest sees it at its next tick. Here the kicker makes the
        // vCPU leave hv_vcpu_run once its thread was off its CPU for 1 ms,
        // and run() takes that exit itself: the guest's figure grows while
        // the call goes on. Under 2 hogs per CPU the thread loses a large
        // part of its time (measured: 30 to 70%, test_steal_time_is_what_
        // the_host_kept_from_the_vcpu).
        if !offered_or_refused() {
            return;
        }
        let ncpu = std::thread::available_parallelism().unwrap().get();
        let run = std::time::Duration::from_millis(1500);
        let (stolen, kicks) = steal_inside_one_run(&SPIN_FOREVER, 2 * ncpu, run);
        assert!(stolen > run.as_nanos() as u64 / 5, "stolen {stolen} ns in {run:?} under hogs, inside one run()");
        assert!(kicks > 0, "no kick");
    }

    #[test]
    fn test_the_kicker_leaves_a_waiting_vcpu_alone() {
        // A guest idle in WFI waits inside the framework, its thread
        // blocked, not runnable: no time is stolen from it, hogs or not, and
        // the kicker leaves it there.
        if !offered_or_refused() {
            return;
        }
        let ncpu = std::thread::available_parallelism().unwrap().get();
        let (stolen, kicks) = steal_inside_one_run(&WAIT_FOREVER, 2 * ncpu, std::time::Duration::from_millis(1000));
        assert_eq!(kicks, 0);
        assert_eq!(stolen, 0);
    }

    #[test]
    fn test_the_kicker_ends_with_its_vm_and_outlives_paused_vcpus() {
        // Three VMs in turn, as a restore makes a new one: each vCPU spins
        // under hogs and is paused and resumed (an immediate exit, then
        // run() again) every 10 ms while the kicker reads and kicks it, then
        // is dropped, then the VM. The kicker uses a vCPU only while its
        // thread is in run() (Steal::running, under the vCPU's lock), so
        // none of this gives it a stale thread port or a destroyed vCPU; its
        // thread is joined with the VM, holding the last reference to it.
        if !offered_or_refused() {
            return;
        }
        let ncpu = std::thread::available_parallelism().unwrap().get();
        let (stop, hog) = hogs_on(2 * ncpu);
        for _ in 0..3 {
            let (vm, _mem) = vm_with_code(&SPIN_FOREVER, 0);
            let gic = with_gic(&vm);
            let mut vcpu = new_vcpu(&vm, 0);
            vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ST)).unwrap();
            // SAFETY: dup of the vCPU's descriptor, owned by the new handle.
            let mut other =
                unsafe { vm.create_vcpu_from_rawfd(libc::dup(std::os::unix::io::AsRawFd::as_raw_fd(&vcpu))).unwrap() };
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let d = done.clone();
            // The pauses start once the guest has made its first exit: an
            // immediate exit before it would end that first run() instead.
            let (started_tx, started) = std::sync::mpsc::channel();
            let runner = std::thread::spawn(move || {
                vcpu.set_one_reg(PC, &RAM.to_le_bytes()).unwrap();
                vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
                vcpu.set_one_reg(X9, &0x1000u64.to_le_bytes()).unwrap();
                assert!(matches!(vcpu.run().unwrap(), VcpuExit::MmioWrite(..)));
                started_tx.send(()).unwrap();
                let mut pauses = 0;
                while !d.load(std::sync::atomic::Ordering::Acquire) {
                    let e = vcpu.run().map(|_| ()).unwrap_err();
                    assert_eq!(e.errno(), libc::EINTR);
                    vcpu.set_kvm_immediate_exit(0);
                    pauses += 1;
                }
                pauses
            });
            started.recv().unwrap();
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(10));
                other.set_kvm_immediate_exit(1);
            }
            done.store(true, std::sync::atomic::Ordering::Release);
            other.set_kvm_immediate_exit(1);
            let pauses = runner.join().unwrap();
            assert!(pauses > 10, "{pauses} pauses");
            let kicker = std::sync::Arc::downgrade(vm.inner.pvtime_kicker.get().unwrap());
            drop(other);
            drop(gic);
            drop(vm);
            assert!(kicker.upgrade().is_none(), "the kicker outlived its VM");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        hog.into_iter().for_each(|h| h.join().unwrap());
    }

    fn measure(guest_entry: u64, hogs: usize, run_for: std::time::Duration) -> (u64, u64, u64, u64, u64) {
        // x0 = PV_TIME_ST; hvc; str x0, [x9]; then a spin of ~1M iterations
        // and an MMIO store, again and again (spin, at 0), or WFI forever
        // (at 0x28).
        let code = [
            0xd280_0420, 0xf2b8_a000, 0xd400_0002, 0xf900_0120, 0xd280_0002, 0xf2a0_0202,
            0xf100_0442, 0x54ff_ffe1, 0xf900_0120, 0x17ff_fffb,
            0xd280_0420, 0xf2b8_a000, 0xd400_0002, 0xf900_0120, 0xd503_207f, 0x17ff_ffff,
        ];
        let (vm, mem) = vm_with_code(&code, 0);
        let mem = mem as usize;
        let _gic = with_gic(&vm);
        let mut vcpu = new_vcpu(&vm, 0);
        vcpu.set_device_attr(&attr(PVTIME_CTRL, PVTIME_IPA, &ST)).unwrap();
        // SAFETY: dup of the vCPU's descriptor, owned by the new handle.
        let mut kicker = unsafe {
            vm.create_vcpu_from_rawfd(libc::dup(std::os::unix::io::AsRawFd::as_raw_fd(&vcpu))).unwrap()
        };
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hog: Vec<_> = (0..hogs)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();
        let runner = std::thread::spawn(move || {
            vcpu.set_one_reg(PC, &(RAM + guest_entry).to_le_bytes()).unwrap();
            vcpu.set_one_reg(PSTATE, &0x3c5u64.to_le_bytes()).unwrap();
            vcpu.set_one_reg(X9, &0x1000u64.to_le_bytes()).unwrap();
            // The PV_TIME_ST answer.
            match vcpu.run().unwrap() {
                VcpuExit::MmioWrite(_, d) => assert_eq!(u64::from_le_bytes(d.try_into().unwrap()), ST),
                other => panic!("{other:?}"),
            }
            let hv = vcpu.hv_for_test().unwrap();
            let read = |f: unsafe extern "C" fn(u64, *mut u64) -> i32| {
                let mut t = 0;
                // SAFETY: `hv` is this thread's.
                assert_eq!(unsafe { f(hv, &mut t) }, 0);
                super::super::vcpu::tests_ticks_to_ns(t)
            };
            let wfi_fn = super::wfi_time_fn().unwrap();
            let (exec0, wfi0) = (read(hv_vcpu_get_exec_time), read(wfi_fn));
            let (mut wall, mut cpu) = (0u64, 0u64);
            let end = std::time::Instant::now() + run_for;
            loop {
                let (w, c) = (std::time::Instant::now(), thread_cpu());
                let r = vcpu.run();
                wall += w.elapsed().as_nanos() as u64;
                cpu += thread_cpu() - c;
                match r {
                    Ok(VcpuExit::MmioWrite(..)) => {}
                    Err(e) if e.errno() == libc::EINTR => {
                        vcpu.set_kvm_immediate_exit(0);
                        if std::time::Instant::now() >= end {
                            break;
                        }
                    }
                    other => panic!("{:?}", other.map(|_| ())),
                }
            }
            let (exec, wfi) = (read(hv_vcpu_get_exec_time) - exec0, read(wfi_fn) - wfi0);
            // One more entry brings the guest's figure up to date (the
            // update runs before the guest is entered); it ends at the next
            // MMIO store or kick, which no figure here counts.
            let _ = vcpu.run();
            (wall, cpu, exec, wfi)
        });
        let t0 = std::time::Instant::now();
        while t0.elapsed() < run_for + std::time::Duration::from_millis(300) {
            // WFI never exits: kick it out every 50 ms, as a host does.
            std::thread::sleep(std::time::Duration::from_millis(50));
            kicker.set_kvm_immediate_exit(1);
        }
        let (wall, cpu, exec, wfi) = runner.join().unwrap();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        hog.into_iter().for_each(|h| h.join().unwrap());
        // SAFETY: stolen_time, le64 at ST + 8 in the test's page.
        let stolen = u64::from_le(unsafe { std::ptr::read_volatile((mem + (ST - RAM) as usize + 8) as *const u64) });
        println!(
            "entry {guest_entry:#x} hogs {hogs}: wall {:.1} ms, cpu {:.1}, exec {:.1}, wfi {:.1}, stolen {:.1}",
            wall as f64 / 1e6, cpu as f64 / 1e6, exec as f64 / 1e6, wfi as f64 / 1e6, stolen as f64 / 1e6
        );
        (wall, cpu, exec, wfi, stolen)
    }

    #[test]
    fn test_steal_time_is_what_the_host_kept_from_the_vcpu() {
        // KVM's steal is the vCPU thread's run delay (pvtime.c
        // kvm_update_stolen_time): here the time in run() the thread was
        // neither on a CPU nor waiting in the guest's WFI (`Steal`). A
        // spinning guest on a host with 20 threads spinning on its CPUs
        // loses a large part of its time, which the guest reads; on the host
        // as it is about what a spinning thread beside it loses (the
        // control: the host may be loaded by anything else); a guest that only waits in WFI loses nothing, hogs
        // or not (its time is idle, not stolen). Each figure stays within
        // the framework's own accounting: wall in run() less exec time less
        // WFI time, which also counts the framework's work as lost, so the
        // guest's figure is at most that and at least that less the CPU
        // time the thread spent outside the guest.
        if !offered_or_refused() {
            return;
        }
        let run = std::time::Duration::from_millis(1000);
        let ncpu = std::thread::available_parallelism().unwrap().get();
        for (entry, hogs) in [(0u64, 0usize), (0, 2 * ncpu), (0x28, 0), (0x28, 2 * ncpu)] {
            // The control: a thread spinning beside the vCPU over the same
            // time, and the share of it the host's scheduler kept from it.
            let control = std::thread::spawn(move || {
                let (t0, c0) = (std::time::Instant::now(), thread_cpu());
                while t0.elapsed() < run + std::time::Duration::from_millis(300) {
                    std::hint::spin_loop();
                }
                let wall = t0.elapsed().as_nanos() as u64;
                (wall.saturating_sub(thread_cpu() - c0), wall)
            });
            let (wall, cpu, exec, wfi, stolen) = measure(entry, hogs, run);
            let (lost, of) = control.join().unwrap();
            let control = (u128::from(lost) * u128::from(wall) / u128::from(of)) as u64;
            println!("control: a spinning thread lost {:.1} ms of {:.1}", lost as f64 / 1e6, of as f64 / 1e6);
            let framework = wall.saturating_sub(exec + wfi);
            let lost_outside_guest = cpu.saturating_sub(exec);
            // The test's own wall time includes its calls around run(),
            // outside what is accounted, where a contended thread is kept
            // off a CPU as often as anywhere: 1% of the wall time (measured
            // up to 3.3 ms of 1020, 0.3%, under 20 hogs on a quiet host),
            // plus 2 ms, plus a twentieth of what the host kept from the
            // control (measured: 21 ms short with the control losing 676 ms
            // under 20 hogs at load 60; the calls around run() are a few
            // percent of the time and lose their share of it).
            let slack = 2_000_000 + wall / 100 + control / 20;
            assert!(stolen <= framework + slack, "stolen {stolen} over the framework's {framework}");
            assert!(
                stolen + lost_outside_guest + slack >= framework,
                "stolen {stolen} under the framework's {framework} less the thread's own work {lost_outside_guest}"
            );
            match (entry, hogs) {
                // The host as it is: what its scheduler kept from the
                // control, twice over for the spread between two spinning
                // threads, plus the 5% the framework's own work in run()
                // counts as lost (above).
                (0, 0) => assert!(stolen < 2 * control + wall / 20, "host as it is: {stolen} of {wall}, control {control}"),
                (0, _) => assert!(stolen > wall / 5, "contended host: {stolen} of {wall}"),
                _ => assert!(stolen < wall / 50, "a guest in WFI: {stolen} of {wall}"),
            }
        }
    }
}
