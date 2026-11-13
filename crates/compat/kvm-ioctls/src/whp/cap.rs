// Copied verbatim from kvm-ioctls 0.25.0 (src/cap.rs): the KVM_CAP_* numbers, which are a stable kernel ABI and identical on every host.
// SPDX-License-Identifier: Apache-2.0 OR MIT
use kvm_bindings::*;

/// Capabilities exposed by KVM.
///
/// The capabilities list can be used in conjunction with
/// [Kvm::check_extension()](struct.Kvm.html#method.check_extension) to check if a particular
/// capability is available.
///
/// The list of capabilities is based on the the KVM_CAP_* defines from the
/// [Linux KVM header](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/kvm.h).
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
// We are allowing docs to be missing here because this enum is a wrapper
// over auto-generated code.
#[allow(missing_docs)]
#[derive(PartialEq, Eq)]
pub enum Cap {
    Irqchip = KVM_CAP_IRQCHIP,
    Hlt = KVM_CAP_HLT,
    MmuShadowCacheControl = KVM_CAP_MMU_SHADOW_CACHE_CONTROL,
    UserMemory = KVM_CAP_USER_MEMORY,
    SetTssAddr = KVM_CAP_SET_TSS_ADDR,
    Vapic = KVM_CAP_VAPIC,
    ExtCpuid = KVM_CAP_EXT_CPUID,
    Clocksource = KVM_CAP_CLOCKSOURCE,
    NrVcpus = KVM_CAP_NR_VCPUS,
    NrMemslots = KVM_CAP_NR_MEMSLOTS,
    Pit = KVM_CAP_PIT,
    NopIoDelay = KVM_CAP_NOP_IO_DELAY,
    PvMmu = KVM_CAP_PV_MMU,
    MpState = KVM_CAP_MP_STATE,
    CoalescedMmio = KVM_CAP_COALESCED_MMIO,
    SyncMmu = KVM_CAP_SYNC_MMU,
    Iommu = KVM_CAP_IOMMU,
    DestroyMemoryRegionWorks = KVM_CAP_DESTROY_MEMORY_REGION_WORKS,
    UserNmi = KVM_CAP_USER_NMI,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "s390x"))]
    SetGuestDebug = KVM_CAP_SET_GUEST_DEBUG,
    #[cfg(target_arch = "x86_64")]
    ReinjectControl = KVM_CAP_REINJECT_CONTROL,
    IrqRouting = KVM_CAP_IRQ_ROUTING,
    IrqInjectStatus = KVM_CAP_IRQ_INJECT_STATUS,
    AssignDevIrq = KVM_CAP_ASSIGN_DEV_IRQ,
    JoinMemoryRegionsWorks = KVM_CAP_JOIN_MEMORY_REGIONS_WORKS,
    #[cfg(target_arch = "x86_64")]
    Mce = KVM_CAP_MCE,
    Irqfd = KVM_CAP_IRQFD,
    #[cfg(target_arch = "x86_64")]
    Pit2 = KVM_CAP_PIT2,
    SetBootCpuId = KVM_CAP_SET_BOOT_CPU_ID,
    #[cfg(target_arch = "x86_64")]
    PitState2 = KVM_CAP_PIT_STATE2,
    Ioeventfd = KVM_CAP_IOEVENTFD,
    SetIdentityMapAddr = KVM_CAP_SET_IDENTITY_MAP_ADDR,
    #[cfg(target_arch = "x86_64")]
    XenHvm = KVM_CAP_XEN_HVM,
    AdjustClock = KVM_CAP_ADJUST_CLOCK,
    InternalErrorData = KVM_CAP_INTERNAL_ERROR_DATA,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    VcpuEvents = KVM_CAP_VCPU_EVENTS,
    S390Psw = KVM_CAP_S390_PSW,
    PpcSegstate = KVM_CAP_PPC_SEGSTATE,
    Hyperv = KVM_CAP_HYPERV,
    HypervVapic = KVM_CAP_HYPERV_VAPIC,
    HypervSpin = KVM_CAP_HYPERV_SPIN,
    PciSegment = KVM_CAP_PCI_SEGMENT,
    PpcPairedSingles = KVM_CAP_PPC_PAIRED_SINGLES,
    IntrShadow = KVM_CAP_INTR_SHADOW,
    #[cfg(target_arch = "x86_64")]
    Debugregs = KVM_CAP_DEBUGREGS,
    X86RobustSinglestep = KVM_CAP_X86_ROBUST_SINGLESTEP,
    PpcOsi = KVM_CAP_PPC_OSI,
    PpcUnsetIrq = KVM_CAP_PPC_UNSET_IRQ,
    EnableCap = KVM_CAP_ENABLE_CAP,
    #[cfg(target_arch = "x86_64")]
    Xsave = KVM_CAP_XSAVE,
    #[cfg(target_arch = "x86_64")]
    Xsave2 = KVM_CAP_XSAVE2,
    #[cfg(target_arch = "x86_64")]
    Xcrs = KVM_CAP_XCRS,
    PpcGetPvinfo = KVM_CAP_PPC_GET_PVINFO,
    PpcIrqLevel = KVM_CAP_PPC_IRQ_LEVEL,
    AsyncPf = KVM_CAP_ASYNC_PF,
    TscControl = KVM_CAP_TSC_CONTROL,
    GetTscKhz = KVM_CAP_GET_TSC_KHZ,
    PpcBookeSregs = KVM_CAP_PPC_BOOKE_SREGS,
    SpaprTce = KVM_CAP_SPAPR_TCE,
    PpcSmt = KVM_CAP_PPC_SMT,
    PpcRma = KVM_CAP_PPC_RMA,
    MaxVcpus = KVM_CAP_MAX_VCPUS,
    MaxVcpuId = KVM_CAP_MAX_VCPU_ID,
    PpcHior = KVM_CAP_PPC_HIOR,
    PpcPapr = KVM_CAP_PPC_PAPR,
    SwTlb = KVM_CAP_SW_TLB,
    OneReg = KVM_CAP_ONE_REG,
    S390Gmap = KVM_CAP_S390_GMAP,
    TscDeadlineTimer = KVM_CAP_TSC_DEADLINE_TIMER,
    S390Ucontrol = KVM_CAP_S390_UCONTROL,
    SyncRegs = KVM_CAP_SYNC_REGS,
    Pci23 = KVM_CAP_PCI_2_3,
    KvmclockCtrl = KVM_CAP_KVMCLOCK_CTRL,
    SignalMsi = KVM_CAP_SIGNAL_MSI,
    PpcGetSmmuInfo = KVM_CAP_PPC_GET_SMMU_INFO,
    S390Cow = KVM_CAP_S390_COW,
    PpcAllocHtab = KVM_CAP_PPC_ALLOC_HTAB,
    ReadonlyMem = KVM_CAP_READONLY_MEM,
    IrqfdResample = KVM_CAP_IRQFD_RESAMPLE,
    PpcBookeWatchdog = KVM_CAP_PPC_BOOKE_WATCHDOG,
    PpcHtabFd = KVM_CAP_PPC_HTAB_FD,
    S390CssSupport = KVM_CAP_S390_CSS_SUPPORT,
    PpcEpr = KVM_CAP_PPC_EPR,
    ArmPsci = KVM_CAP_ARM_PSCI,
    ArmSetDeviceAddr = KVM_CAP_ARM_SET_DEVICE_ADDR,
    DeviceCtrl = KVM_CAP_DEVICE_CTRL,
    IrqMpic = KVM_CAP_IRQ_MPIC,
    PpcRtas = KVM_CAP_PPC_RTAS,
    IrqXics = KVM_CAP_IRQ_XICS,
    ArmEl132bit = KVM_CAP_ARM_EL1_32BIT,
    SpaprMultitce = KVM_CAP_SPAPR_MULTITCE,
    ExtEmulCpuid = KVM_CAP_EXT_EMUL_CPUID,
    HypervTime = KVM_CAP_HYPERV_TIME,
    IoapicPolarityIgnored = KVM_CAP_IOAPIC_POLARITY_IGNORED,
    EnableCapVm = KVM_CAP_ENABLE_CAP_VM,
    S390Irqchip = KVM_CAP_S390_IRQCHIP,
    IoeventfdNoLength = KVM_CAP_IOEVENTFD_NO_LENGTH,
    VmAttributes = KVM_CAP_VM_ATTRIBUTES,
    ArmPsci02 = KVM_CAP_ARM_PSCI_0_2,
    PpcFixupHcall = KVM_CAP_PPC_FIXUP_HCALL,
    PpcEnableHcall = KVM_CAP_PPC_ENABLE_HCALL,
    CheckExtensionVm = KVM_CAP_CHECK_EXTENSION_VM,
    S390UserSigp = KVM_CAP_S390_USER_SIGP,
    #[cfg(target_arch = "x86_64")]
    X86Smm = KVM_CAP_X86_SMM,
    #[cfg(target_arch = "x86_64")]
    SplitIrqchip = KVM_CAP_SPLIT_IRQCHIP,
    ArmPmuV3 = KVM_CAP_ARM_PMU_V3,
    ImmediateExit = KVM_CAP_IMMEDIATE_EXIT,
    ArmVmIPASize = KVM_CAP_ARM_VM_IPA_SIZE,
    MsiDevid = KVM_CAP_MSI_DEVID,
    HypervSynic = KVM_CAP_HYPERV_SYNIC,
    HypervSynic2 = KVM_CAP_HYPERV_SYNIC2,
    DebugHwBps = KVM_CAP_GUEST_DEBUG_HW_BPS,
    DebugHwWps = KVM_CAP_GUEST_DEBUG_HW_WPS,
    GetMsrFeatures = KVM_CAP_GET_MSR_FEATURES,
    CoalescedPio = KVM_CAP_COALESCED_PIO,
    #[cfg(target_arch = "aarch64")]
    ArmSve = KVM_CAP_ARM_SVE,
    #[cfg(target_arch = "aarch64")]
    ArmPtrAuthAddress = KVM_CAP_ARM_PTRAUTH_ADDRESS,
    #[cfg(target_arch = "aarch64")]
    ArmPtrAuthGeneric = KVM_CAP_ARM_PTRAUTH_GENERIC,
    #[cfg(target_arch = "x86_64")]
    X86UserSpaceMsr = KVM_CAP_X86_USER_SPACE_MSR,
    #[cfg(target_arch = "x86_64")]
    X86MsrFilter = KVM_CAP_X86_MSR_FILTER,
    #[cfg(target_arch = "x86_64")]
    ExitHypercall = KVM_CAP_EXIT_HYPERCALL,
    #[cfg(target_arch = "x86_64")]
    MemoryFaultInfo = KVM_CAP_MEMORY_FAULT_INFO,
    CounterOffset = KVM_CAP_COUNTER_OFFSET,
    UserMemory2 = KVM_CAP_USER_MEMORY2,
    GuestMemfd = KVM_CAP_GUEST_MEMFD,
    MemoryAttributes = KVM_CAP_MEMORY_ATTRIBUTES,
    #[cfg(target_arch = "x86_64")]
    NestedState = KVM_CAP_NESTED_STATE,
    #[cfg(target_arch = "x86_64")]
    X2ApicApi = KVM_CAP_X2APIC_API,
    DirtyLogRing = KVM_CAP_DIRTY_LOG_RING,
}

/// `check_extension_raw`: 1 (or a count) for the capabilities Firecracker
/// needs on x86_64 that WHP provides, 0 otherwise. The local APIC, PIT and
/// PICs are provided (WHP's APIC plus the userspace chips in `irqchip`), so
/// the irqchip capabilities report supported.
#[allow(irrefutable_let_patterns)]
pub(crate) fn supported(c: u64) -> i32 {
    // `KVM_CAP_*` values fit in 32 bits; an out-of-range value is unsupported.
    let Ok(c) = u32::try_from(c) else {
        return 0;
    };
    match c {
        KVM_CAP_IRQCHIP
        | KVM_CAP_IOEVENTFD
        | KVM_CAP_IOEVENTFD_ANY_LENGTH
        | KVM_CAP_IRQFD
        | KVM_CAP_USER_MEMORY
        | KVM_CAP_READONLY_MEM
        | KVM_CAP_SET_TSS_ADDR
        | KVM_CAP_PIT2
        | KVM_CAP_PIT_STATE2
        | KVM_CAP_ADJUST_CLOCK
        | KVM_CAP_DEBUGREGS
        | KVM_CAP_MP_STATE
        | KVM_CAP_VCPU_EVENTS
        | KVM_CAP_XCRS
        | KVM_CAP_XSAVE
        | KVM_CAP_EXT_CPUID
        | KVM_CAP_TSC_CONTROL
        | KVM_CAP_GET_TSC_KHZ
        | KVM_CAP_TSC_DEADLINE_TIMER
        | KVM_CAP_IMMEDIATE_EXIT => 1,
        KVM_CAP_NR_VCPUS | KVM_CAP_MAX_VCPUS | KVM_CAP_MAX_VCPU_ID => {
            i32::try_from(super::vm::MAX_VCPUS).unwrap_or(i32::MAX)
        }
        KVM_CAP_NR_MEMSLOTS => i32::try_from(super::NR_MEMSLOTS).unwrap_or(i32::MAX),
        // The size of a vCPU's XSAVE area on this host, at least `struct
        // kvm_xsave`'s 4096 as on Linux (5.17 and later): past it on a
        // processor with AMX (`regs::xsave_area_len`).
        KVM_CAP_XSAVE2 => i32::try_from(super::regs::xsave_area_len()).unwrap_or(i32::MAX),
        _ => 0,
    }
}
