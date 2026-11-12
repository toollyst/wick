// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Hypervisor.framework backend with the `kvm-ioctls` API (macOS on Apple silicon).
//!
//! Firecracker drives this module exactly like KVM. What KVM does in the
//! kernel is done here in user space:
//! - MMIO: data aborts are decoded into `VcpuExit::MmioRead`/`MmioWrite`;
//!   `ioeventfd` writes are matched before returning to the caller;
//! - interrupts: Hypervisor.framework's GICv3 (`hv_gic_*`, macOS 15+); `irqfd`s are
//!   served by a thread that turns eventfd writes into `hv_gic_set_spi`;
//! - PSCI 0.2 (`HVC`/`SMC`) for CPU on/off, system off and reset;
//! - `WFI` waits in user space until the virtual timer deadline or a wake-up;
//! - the virtual timer interrupt is made pending in the redistributor on
//!   `HV_EXIT_REASON_VTIMER_ACTIVATED`.
//!
//! Hypervisor.framework allows one VM per process and binds each vCPU to the
//! thread that created it. vCPUs are therefore created on the first `run()`
//! (Firecracker calls it from the vCPU thread); register writes made before
//! that are buffered and applied at creation. See
//! `docs/ROADMAP.md` for what is not supported.

#![allow(missing_docs)]

pub mod cap;
mod device;
mod exit;
mod ffi;
mod gic;
mod idregs;
mod regs;
mod vcpu;
mod vm;

/// Serialises vCPU creation with the calls that make interrupts pending.
///
/// Hypervisor.framework deadlocks when one thread creates a vCPU
/// (`hv_vcpu_create`) while another makes a GIC interrupt pending, which
/// interrupts the vCPUs (`Hv::Vm::interrupt_cpus`): the two take two internal
/// locks in opposite orders. vCPUs are created on their own threads, so on a
/// restore one vCPU making its deferred SPIs pending raced the next vCPU's
/// creation and hung the VM (about one restore in fifteen). Creating a vCPU
/// holds this exclusively ([`creating`]); every GIC write and vCPU poke made
/// outside a signal handler holds it shared ([`interrupting`]), so they still
/// run concurrently with each other. Process-wide, as the VM is.
static CREATE_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// Runs `f`, a `hv_vcpu_create`, with no interrupt being made pending.
pub(crate) fn creating<T>(f: impl FnOnce() -> T) -> T {
    let _guard = CREATE_LOCK.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    f()
}

/// Runs `f`, one Hypervisor.framework call that can interrupt vCPUs, with no
/// vCPU being created. `f` must not call [`interrupting`] or [`creating`].
pub(crate) fn interrupting<T>(f: impl FnOnce() -> T) -> T {
    let _guard = CREATE_LOCK.read().unwrap_or_else(std::sync::PoisonError::into_inner);
    f()
}

use std::fs::File;
use std::os::raw::c_ulong;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

pub use cap::Cap;
pub use device::{DeviceFd, KVM_VGIC_V3_ADDR_TYPE_MSI_FRAME};
pub use regs::reg_size;
pub use vcpu::VcpuFd;
pub use vm::VmFd;
pub use vmm_sys_util::errno::Error;

/// A specialized `Result` type for KVM ioctls.
pub type Result<T> = std::result::Result<T, Error>;

/// `KVM_API_VERSION` from the Linux headers.
const KVM_API_VERSION: i32 = 12;

/// Number of memory slots reported (Linux's `KVM_USER_MEM_SLOTS` on arm64).
const NR_MEMSLOTS: usize = 32764;

/// Wrapper over the "KVM system" handle. On macOS this checks nothing until a VM is created.
#[derive(Debug)]
pub struct Kvm {
    fd: Handle,
}

impl Kvm {
    /// Opens the hypervisor.
    pub fn new() -> Result<Self> {
        Ok(Kvm { fd: Handle::new()? })
    }

    /// Same as `new`; the path is ignored.
    pub fn new_with_path<P>(_kvm_path: P) -> Result<Self> {
        Self::new()
    }

    /// Returns the KVM API version this backend emulates.
    pub fn get_api_version(&self) -> i32 {
        KVM_API_VERSION
    }

    /// Guest physical address size supported, in bits.
    pub fn get_host_ipa_limit(&self) -> i32 {
        vm::max_ipa_bits() as i32
    }

    /// Checks a raw `KVM_CAP_*` value. See [`cap::supported`].
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

    /// Size of the `kvm_run` area (the struct size here; nothing is mapped).
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        Ok(std::mem::size_of::<kvm_bindings::kvm_run>())
    }

    /// Recommended number of vCPUs.
    pub fn get_nr_vcpus(&self) -> usize {
        vm::max_vcpus()
    }

    /// Maximum number of vCPUs.
    pub fn get_max_vcpus(&self) -> usize {
        vm::max_vcpus()
    }

    /// Maximum vCPU id.
    pub fn get_max_vcpu_id(&self) -> usize {
        vm::max_vcpus()
    }

    /// Number of memory slots.
    pub fn get_nr_memslots(&self) -> usize {
        NR_MEMSLOTS
    }

    /// Creates the VM. Hypervisor.framework allows one VM per process: this
    /// fails with `EBUSY` while another `VmFd` is alive.
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
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
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
    /// The return code to be indicated to the guest.
    pub ret: &'a mut u64,
    /// Whether the hypercall was executed in long mode.
    pub longmode: u32,
}

/// Reasons for vCPU exits (the subset of `kvm_ioctls::VcpuExit` that exists on arm64).
#[derive(Debug)]
pub enum VcpuExit<'a> {
    /// An out port instruction was run on the given port with the given data.
    IoOut(u16, &'a [u8]),
    /// An in port instruction was run on the given port.
    IoIn(u16, &'a mut [u8]),
    /// A read instruction was run against the given MMIO address. Fill the buffer.
    MmioRead(u64, &'a mut [u8]),
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite(u64, &'a [u8]),
    /// Corresponds to `KVM_EXIT_UNKNOWN`.
    Unknown,
    /// Corresponds to `KVM_EXIT_EXCEPTION`.
    Exception,
    /// Corresponds to `KVM_EXIT_HYPERCALL`.
    Hypercall(HypercallExit<'a>),
    /// Corresponds to `KVM_EXIT_DEBUG`.
    Debug(kvm_bindings::kvm_debug_exit_arch),
    /// Corresponds to `KVM_EXIT_HLT`.
    Hlt,
    /// Corresponds to `KVM_EXIT_IRQ_WINDOW_OPEN`.
    IrqWindowOpen,
    /// Corresponds to `KVM_EXIT_SHUTDOWN`.
    Shutdown,
    /// Corresponds to `KVM_EXIT_FAIL_ENTRY`.
    FailEntry(u64, u32),
    /// Corresponds to `KVM_EXIT_INTR`.
    Intr,
    /// Corresponds to `KVM_EXIT_INTERNAL_ERROR`.
    InternalError,
    /// Corresponds to `KVM_EXIT_SYSTEM_EVENT`.
    SystemEvent(u32, &'a [u64]),
    /// Corresponds to `KVM_EXIT_MEMORY_FAULT`.
    MemoryFault {
        /// flags
        flags: u64,
        /// gpa
        gpa: u64,
        /// size
        size: u64,
    },
    /// A guest exception this backend does not handle; the value is the
    /// exception syndrome (`ESR_EL2`, low 32 bits).
    Unsupported(u32),
}

/// A mapping of a vCPU's `kvm_run` structure, shared with the vCPU's handles
/// as KVM's `mmap` of the vCPU descriptor is.
#[derive(Debug)]
pub struct KvmRunWrapper(std::sync::Arc<vcpu::VcpuShared>);

impl KvmRunWrapper {
    /// Maps the `kvm_run` structure of the vCPU behind `fd` (a `VcpuFd`
    /// descriptor). Fails with `EBADF` for other descriptors and `EINVAL` for
    /// a size larger than `VmFd::run_size()`.
    pub fn mmap_from_fd<F: AsRawFd>(fd: &F, size: usize) -> Result<KvmRunWrapper> {
        if size > std::mem::size_of::<kvm_bindings::kvm_run>() {
            return err(libc::EINVAL);
        }
        let id = vm::fd_identity(fd.as_raw_fd())?;
        vcpu::vcpu_by_identity(id)
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

/// The file descriptor of a KVM-like handle (system, VM, vCPU, device).
///
/// It is the read end of a pipe, so it has an identity (device and inode) no
/// other open file shares. The handle also keeps the write end, so the pipe,
/// and with it the identity, lives on if the descriptor is closed behind the
/// handle's back (macOS reuses the inode numbers of freed pipes). Operations
/// check the descriptor first: once it has been closed, they fail with
/// `EBADF`, as KVM ioctls on a closed descriptor do, and a VM whose
/// descriptors are gone can be released (see `VmFd::create`).
#[derive(Debug)]
pub(crate) struct Handle {
    file: File,
    _peer: Option<File>,
    id: (u64, u64),
}

impl Handle {
    pub(crate) fn new() -> Result<Self> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: room for two descriptors.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(Error::last());
        }
        // SAFETY: fresh descriptors from pipe(), owned from here on.
        let (file, peer) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
        let id = vm::fd_identity(file.as_raw_fd())?;
        Ok(Handle {
            file,
            _peer: Some(peer),
            id,
        })
    }

    /// Takes over a descriptor (a `dup` of another handle's, whose handle
    /// keeps the pipe alive).
    pub(crate) fn from_file(file: File) -> Result<Self> {
        let id = vm::fd_identity(file.as_raw_fd())?;
        Ok(Handle {
            file,
            _peer: None,
            id,
        })
    }

    pub(crate) fn id(&self) -> (u64, u64) {
        self.id
    }

    /// The descriptor number and identity, to check later whether it is open.
    pub(crate) fn token(&self) -> (RawFd, (u64, u64)) {
        (self.file.as_raw_fd(), self.id)
    }

    /// Fails with `EBADF` if the descriptor has been closed.
    pub(crate) fn check(&self) -> Result<()> {
        if is_open(self.token()) {
            Ok(())
        } else {
            err(libc::EBADF)
        }
    }
}

/// Whether the descriptor of a [`Handle::token`] is still open (and not
/// reused for another file).
pub(crate) fn is_open((fd, id): (RawFd, (u64, u64))) -> bool {
    vm::fd_identity(fd).is_ok_and(|now| now == id)
}

impl AsRawFd for Handle {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// Errno helper.
fn err<T>(errno: i32) -> Result<T> {
    Err(Error::new(errno))
}
