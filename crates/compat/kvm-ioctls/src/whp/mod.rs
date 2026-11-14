// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Windows Hypervisor Platform (WHP) backend with the `kvm-ioctls` API
//! (Windows, x86_64 guest).
//!
//! Firecracker drives this module exactly like KVM. What the KVM kernel does
//! is done here with WHP and, where WHP has no equivalent, in user space:
//! - memory: guest RAM is mapped with `WHvMapGpaRange`; dirty-page tracking
//!   uses `WHvQueryGpaRangeDirtyBitmap`;
//! - MMIO and port I/O: the guest's accesses leave through
//!   `WHvRunVirtualProcessor`, are completed by the WHP instruction emulator
//!   ([`emulate`]), and are handed to Firecracker as `VcpuExit::Mmio*` /
//!   `VcpuExit::Io*`; `ioeventfd` writes are matched before the exit is
//!   reported;
//! - interrupts: the local APIC is WHP's (an x2APIC on AMD hosts, an xAPIC
//!   elsewhere: [`apicmode`]), its TSC-deadline mode emulated here as KVM
//!   does ([`tscdeadline`], [`gp`]);
//!   the I/O APIC, the 8259 PICs and the 8254 PIT are emulated here
//!   ([`irqchip`]); `irqfd`s are served by a wait registered on the eventfd
//!   that raises the routed GSI;
//! - CPUID and MSRs the guest reads that WHP exits on are answered here.
//!
//! The handle types ([`Kvm`], [`VmFd`], [`VcpuFd`], [`DeviceFd`]) each own a
//! Windows event whose handle value is their descriptor, so `AsRawFd` works
//! and a vCPU can be found from a descriptor
//! ([`KvmRunWrapper::mmap_from_fd`]). See `docs/ROADMAP.md` for what is
//! not supported.

#![allow(clippy::missing_safety_doc)]

mod apicmode;
pub mod cap;
mod cr4;
mod debug;
mod emulate;
mod exit;
mod gp;
mod ffi;
mod guest_mem;
mod irqchip;
mod mce;
mod pvclock;
mod regs;
mod tscdeadline;
mod tscsync;
mod vcpu;
mod xcr;
// The record and the tests read WinHvPlatformDefs.h with it.
#[cfg(test)]
mod xsave_features;
mod vm;
mod whv;

use wick_os::fd::{AsRawFd, RawFd};
use windows_sys::Win32::System::Threading::CreateEventW;

pub use cap::Cap;
pub use vcpu::VcpuFd;
pub use vm::VmFd;
pub use vmm_sys_util::errno::Error;

/// A specialized `Result` type for KVM ioctls.
pub type Result<T> = std::result::Result<T, Error>;

/// `KVM_API_VERSION` from the Linux headers.
const KVM_API_VERSION: i32 = 12;

/// Number of memory slots reported (Linux's `KVM_USER_MEM_SLOTS` on x86_64).
const NR_MEMSLOTS: usize = 509;

/// The descriptor of a KVM-like handle (system, VM, vCPU, device).
///
/// It owns a Windows event whose handle value is the descriptor. Windows does
/// not reuse a handle value while it is open, so the value is a stable
/// identity for the object's lifetime, which lets a vCPU be found from a
/// descriptor and lets operations notice a descriptor that has been closed
/// (`EBADF`), as KVM ioctls on a closed descriptor do.
#[derive(Debug)]
pub(crate) struct Handle(ffi::OwnedHandle);

impl Handle {
    pub(crate) fn new() -> Result<Self> {
        // SAFETY: creates an unnamed, manual-reset, unsignalled event.
        let h = unsafe {
            CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
        };
        if h.is_null() {
            return Err(Error::last());
        }
        Ok(Handle(ffi::OwnedHandle(h)))
    }
}

impl AsRawFd for Handle {
    #[allow(clippy::cast_possible_truncation)]
    fn as_raw_fd(&self) -> RawFd {
        // Kernel handle values fit in 32 bits (sign-extended as a RawFd).
        self.0.0 as isize as RawFd
    }
}

/// Wrapper over the "KVM system" handle. Checks nothing until a VM is created.
#[derive(Debug)]
pub struct Kvm {
    fd: Handle,
}

impl Kvm {
    /// Opens the hypervisor. Fails with `ENODEV` if WHP is not available
    /// (the Windows Hypervisor Platform feature is not installed or enabled).
    pub fn new() -> Result<Self> {
        if !ffi::whp_present() {
            return Err(Error::new(libc::ENODEV));
        }
        Ok(Kvm { fd: Handle::new()? })
    }

    /// Same as `new`; the path is ignored.
    pub fn new_with_path<P>(_kvm_path: P) -> Result<Self> {
        Self::new()
    }

    /// The KVM API version this backend emulates.
    pub fn get_api_version(&self) -> i32 {
        KVM_API_VERSION
    }

    /// Checks a raw `KVM_CAP_*` value. See [`cap::supported`].
    ///
    /// Takes a `u64` (not `c_ulong`) so the value Firecracker passes —
    /// `u64::from(cap)` — matches on Windows, where `c_ulong` is 32-bit.
    pub fn check_extension_raw(&self, c: u64) -> i32 {
        cap::supported(c)
    }

    /// Checks a capability, as an integer.
    pub fn check_extension_int(&self, c: Cap) -> i32 {
        self.check_extension_raw(u64::from(c as u32))
    }

    /// Checks a capability.
    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) > 0
    }

    /// Size of the `kvm_run` area (the struct size here; nothing is mapped).
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        Ok(std::mem::size_of::<kvm_bindings::kvm_run>())
    }

    /// Recommended number of vCPUs.
    pub fn get_nr_vcpus(&self) -> usize {
        vm::MAX_VCPUS
    }

    /// Maximum number of vCPUs.
    pub fn get_max_vcpus(&self) -> usize {
        vm::MAX_VCPUS
    }

    /// Maximum vCPU id.
    pub fn get_max_vcpu_id(&self) -> usize {
        vm::MAX_VCPUS
    }

    /// Number of memory slots.
    pub fn get_nr_memslots(&self) -> usize {
        NR_MEMSLOTS
    }

    /// The host CPUID leaves the guest may use, filtered to what WHP exposes.
    pub fn get_supported_cpuid(
        &self,
        num_entries: usize,
    ) -> Result<kvm_bindings::CpuId> {
        regs::supported_cpuid(num_entries)
    }

    /// The MSRs that can be got and set (the ones this backend maps).
    pub fn get_msr_index_list(&self) -> Result<kvm_bindings::MsrList> {
        regs::msr_index_list()
    }

    /// The MSRs with host feature values.
    pub fn get_msr_feature_index_list(&self) -> Result<kvm_bindings::MsrList> {
        regs::msr_feature_index_list()
    }

    /// Reads host values for a set of MSRs (the feature MSRs).
    pub fn get_msrs(&self, msrs: &mut kvm_bindings::Msrs) -> Result<usize> {
        regs::get_host_msrs(msrs)
    }

    /// Creates the VM.
    pub fn create_vm(&self) -> Result<VmFd> {
        VmFd::create()
    }

    /// Same as `create_vm`; the machine type is ignored.
    pub fn create_vm_with_type(&self, _vm_type: u64) -> Result<VmFd> {
        self.create_vm()
    }
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// An address either belonging to an MMIO or a PIO bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoEventAddress {
    /// A programmable I/O address.
    Pio(u64),
    /// A memory mapped I/O address.
    Mmio(u64),
}

/// Helper structure for disabling datamatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoDatamatch;

impl From<NoDatamatch> for u64 {
    fn from(_: NoDatamatch) -> u64 {
        0
    }
}

/// Information about a hypercall exit (kept for API compatibility; never produced).
#[derive(Debug)]
pub struct HypercallExit<'a> {
    /// The hypercall number.
    pub nr: u64,
    /// The arguments for the hypercall.
    pub args: [u64; 6],
    /// The return code indicated to the guest.
    pub ret: &'a mut u64,
    /// Whether the hypercall ran in long mode.
    pub longmode: u32,
}

/// Reasons for vCPU exits (the subset of `kvm_ioctls::VcpuExit` Firecracker
/// handles on x86_64).
#[derive(Debug)]
pub enum VcpuExit<'a> {
    /// An out-port instruction ran on the given port with the given data.
    IoOut(u16, &'a [u8]),
    /// An in-port instruction ran on the given port; fill the buffer.
    IoIn(u16, &'a mut [u8]),
    /// A read against the given MMIO address; fill the buffer.
    MmioRead(u64, &'a mut [u8]),
    /// A write against the given MMIO address with the given data.
    MmioWrite(u64, &'a [u8]),
    /// `KVM_EXIT_UNKNOWN`.
    Unknown,
    /// `KVM_EXIT_EXCEPTION`.
    Exception,
    /// `KVM_EXIT_HYPERCALL`.
    Hypercall(HypercallExit<'a>),
    /// `KVM_EXIT_DEBUG`.
    Debug(kvm_bindings::kvm_debug_exit_arch),
    /// `KVM_EXIT_HLT`.
    Hlt,
    /// `KVM_EXIT_IRQ_WINDOW_OPEN`.
    IrqWindowOpen,
    /// `KVM_EXIT_SHUTDOWN`.
    Shutdown,
    /// `KVM_EXIT_FAIL_ENTRY`.
    FailEntry(u64, u32),
    /// `KVM_EXIT_INTR`.
    Intr,
    /// `KVM_EXIT_INTERNAL_ERROR`.
    InternalError,
    /// `KVM_EXIT_SYSTEM_EVENT`.
    SystemEvent(u32, &'a [u64]),
    /// `KVM_EXIT_MEMORY_FAULT`.
    MemoryFault {
        /// flags
        flags: u64,
        /// gpa
        gpa: u64,
        /// size
        size: u64,
    },
}

/// A mapping of a vCPU's `kvm_run` structure, shared with the vCPU's handles
/// as KVM's `mmap` of the vCPU descriptor is.
#[derive(Debug)]
pub struct KvmRunWrapper(std::sync::Arc<vcpu::VcpuShared>);

impl KvmRunWrapper {
    /// Maps the `kvm_run` structure of the vCPU behind `fd` (a `VcpuFd`
    /// descriptor). Fails with `EBADF` for other descriptors and `EINVAL`
    /// for a size larger than `VmFd::run_size()`.
    pub fn mmap_from_fd<F: AsRawFd>(fd: &F, size: usize) -> Result<KvmRunWrapper> {
        if size > std::mem::size_of::<kvm_bindings::kvm_run>() {
            return Err(Error::new(libc::EINVAL));
        }
        vcpu::vcpu_by_descriptor(fd.as_raw_fd())
            .map(KvmRunWrapper)
            .ok_or_else(|| Error::new(libc::EBADF))
    }

    /// The mapped structure.
    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> &kvm_bindings::kvm_run {
        // SAFETY: the page lives as long as the vCPU state this wrapper holds.
        unsafe { &*self.0.run.ptr() }
    }

    /// The mapped structure, writable.
    pub fn as_mut_ref(&mut self) -> &mut kvm_bindings::kvm_run {
        // SAFETY: as above; writes are visible to the vCPU like KVM's mapping.
        unsafe { &mut *self.0.run.ptr() }
    }
}

/// A device handle. Firecracker creates KVM devices only on aarch64 (the
/// GIC); on x86_64 nothing calls this, so creating one fails loudly rather
/// than pretend to be a device.
#[derive(Debug)]
pub struct DeviceFd {
    fd: Handle,
}

impl DeviceFd {
    pub(crate) fn unsupported() -> Result<Self> {
        Err(Error::new(libc::ENOTSUP))
    }
}

impl AsRawFd for DeviceFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Errno helper.
pub(crate) fn err<T>(errno: i32) -> Result<T> {
    Err(Error::new(errno))
}
