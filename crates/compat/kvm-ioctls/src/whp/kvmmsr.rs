// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! KVM's answer to a guest's RDMSR and WRMSR, and to the VMM's
//! `KVM_GET_MSRS` and `KVM_SET_MSRS`, for the MSRs no WHP register holds,
//! transcribed from Linux v6.1 for a VM made as Firecracker makes it, so
//! that the backend's MSR exit (`vcpu.rs`, `handle_msr`) answers every MSR
//! WHP hands it as KVM does: the value, the write's check, or #GP(0) where
//! KVM's default gives it (`ignore_msrs` off, v6.1 x86.c:143; an MSR KVM has
//! no case for ends as `KVM_MSR_RET_INVALID`, x86.c:3882/4239, which
//! `kvm_{get,set}_msr_ignored_check` turns into #GP, x86.c:1866-1876 and
//! 1911-1923, via `kvm_complete_insn_gp`, x86.c:748, 2016-2064).
//!
//! The order is KVM's: the vendor's `vmx_get_msr`/`vmx_set_msr` (v6.1
//! arch/x86/kvm/vmx/vmx.c:1865-2012, 2044-2378) or `svm_get_msr`/
//! `svm_set_msr` (arch/x86/kvm/svm/svm.c:2720-2817, 2858-3061) first, then
//! `kvm_get_msr_common`/`kvm_set_msr_common` (x86.c:3938-4242,
//! 3541-3885), then the PMU (pmu.c:438-442) ([`answer`]). What KVM keeps
//! for a vCPU and the backend keeps here is [`Kept`]: the guest's access
//! of it ([`Kept::guest_read`], [`Kept::guest_write`]) and the VMM's
//! ([`Kept::host_get`], [`Kept::host_set`], listed by [`listed`]).
//!
//! The VM as Firecracker makes it (vmm arch/x86_64/msr.rs, vstate): no
//! `KVM_X86_SETUP_MCE` (mcg_cap = 32 banks, x86.c:11883), no
//! `KVM_CAP_ENFORCE_PV_FEATURE_CPUID` (`guest_pv_has` is always true,
//! cpuid.h:226-233), no Hyper-V CPUID signature (`hyperv_enabled` false,
//! cpuid.c:314-321, 358-359, hyperv.c:1658/1679), no `KVM_XEN_HVM_CONFIG`
//! (x86.c:3547), no MSR filter, no `KVM_CAP_X86_USER_SPACE_MSR`, the LAPIC
//! in the kernel, the quirks KVM has by default (MISC_ENABLE_NO_MWAIT on,
//! x86.h:273-276), `guest_can_read_msr_platform_info` true (x86.c:12406).
//! The PMU is OFF: KVM with KVM_CAP_PMU_CAPABILITY DISABLE
//! (`kvm->arch.enable_pmu` false, svm/pmu.c:42-43, vmx/pmu_intel.c:529-531),
//! which is also what an Intel guest whose CPUID leaf 0xA is zeroed
//! (Firecracker) has (pmu_intel.c:535-537). The host facts KVM reads that a
//! Windows process cannot are [`Guest`]'s, each set by the backend as its
//! field says (docs/COMPATIBILITY.md, the Guest MSRs row).
//!
//! Uses `core` only, so the fuzz crate compiles it from source and its
//! tests run on any host (`whp_kvmmsr`).

/// The host's vendor, which picks KVM's vendor module (`kvm_intel` or
/// `kvm_amd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vendor {
    Intel,
    Amd,
}

/// What the rows test: the guest's CPUID (as `guest_cpuid_has` reads it,
/// from the vCPU's last `KVM_SET_CPUID2`), a few values the VMM sets with
/// `KVM_SET_MSRS`, and host facts. The backend fills it at run time; this
/// module decides no bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Guest {
    // ---- Guest CPUID ----
    /// Leaf 0 is "GenuineIntel" (`guest_cpuid_is_intel`, cpuid.h:120-126).
    pub intel_guest: bool,
    /// Leaf 0 is "AuthenticAMD" or "HygonGenuine"
    /// (`guest_cpuid_is_amd_or_hygon`, cpuid.h:110-118).
    pub amd_or_hygon_guest: bool,
    /// Leaf 1 EAX's family and model as `guest_cpuid_family`/`_model` give
    /// them (cpuid.h:128-150); `None` without a leaf 1.
    pub family_model: Option<(u32, u32)>,
    /// 1.ECX[5] VMX.
    pub vmx: bool,
    /// 1.ECX[15] PDCM.
    pub pdcm: bool,
    /// 1.EDX[21] DS.
    pub ds: bool,
    /// 7.0.EBX[1] TSC_ADJUST.
    pub tsc_adjust: bool,
    /// 7.0.EBX[2] SGX.
    pub sgx: bool,
    /// 7.0.EBX[14] MPX.
    pub mpx: bool,
    /// 7.0.ECX[5] WAITPKG (with the host's: `vmx_has_waitpkg`, vmx.h:706-710).
    pub waitpkg: bool,
    /// 7.0.ECX[22] RDPID.
    pub rdpid: bool,
    /// 7.0.ECX[30] SGX_LC.
    pub sgx_lc: bool,
    /// 7.0.EDX[26] SPEC_CTRL (IBRS/IBPB).
    pub spec_ctrl: bool,
    /// 7.0.EDX[29] ARCH_CAPABILITIES.
    pub arch_capabilities: bool,
    /// 0xD.1.EAX[3] XSAVES.
    pub xsaves: bool,
    /// 0xD.1.EAX[4] XFD.
    pub xfd: bool,
    /// 0x8000_0001.ECX[9] OSVW.
    pub osvw: bool,
    /// 0x8000_0001.EDX[27] RDTSCP.
    pub rdtscp: bool,
    /// 0x8000_0008.EBX[12] AMD_IBPB, [14] AMD_IBRS, [15] AMD_STIBP,
    /// [24] AMD_SSBD, [25] VIRT_SSBD.
    pub amd_ibpb: bool,
    pub amd_ibrs: bool,
    pub amd_stibp: bool,
    pub amd_ssbd: bool,
    pub virt_ssbd: bool,
    /// 0x8000_000A.EDX[4] TSCRATEMSR (only with SVM in the guest).
    pub tscratemsr: bool,
    /// 0x4000_0001.EAX is "Hv#1" (`kvm_cpuid_has_hyperv`, cpuid.c:314-321).
    pub hyperv: bool,
    /// The guest's dynamic XSAVE features, `guest_supported_xcr0 &
    /// XFEATURE_MASK_USER_DYNAMIC` (`kvm_guest_supported_xfd`, x86.c:1039-1042).
    pub guest_xfd_mask: u64,
    /// `vcpu->arch.reserved_gpa_bits` (the bits above the guest's
    /// MAXPHYADDR, cpuid.c `cpuid_query_maxphyaddr`).
    pub reserved_gpa_bits: u64,

    // ---- Values the VMM sets (KVM_SET_MSRS) that a row's check reads ----
    /// The vCPU's IA32_ARCH_CAPABILITIES (`vcpu->arch.arch_capabilities`):
    /// its TSX_CTRL_MSR bit (7) gates IA32_TSX_CTRL (vmx.c:1885-1889).
    pub arch_capabilities_value: u64,
    /// The vCPU's MSR_PLATFORM_INFO (`msr_platform_info`, default
    /// CPUID_FAULT, x86.c:11917): its bit 31 gates
    /// MISC_FEATURES_ENABLES.CPUID_FAULT (cpuid.h:180-183).
    pub platform_info: u64,
    /// The vCPU's IA32_PERF_CAPABILITIES (`vcpu->arch.perf_capabilities`).
    pub perf_capabilities: u64,

    // ---- Host facts (module parameters at their defaults) ----
    /// `cpu_feature_enabled(X86_FEATURE_LFENCE_RDTSC)` (svm.c:2708): a Linux
    /// host sets it on every AMD CPU with SSE2 (arch/x86/kernel/cpu/amd.c:959-971).
    pub host_lfence_rdtsc: bool,
    /// `boot_cpu_has(X86_FEATURE_IBPB)` (vmx.c:2200, svm.c:2938).
    pub host_ibpb: bool,
    /// `kvm_mpx_supported()` (x86.h:317-321).
    pub host_mpx: bool,
    /// `lbrv` (svm.c:212-213, cleared without the host's LBRV, 5030-5033).
    pub host_lbrv: bool,
    /// `tsc_scaling` (svm.c:215-216, cleared without the host's TSCRATEMSR, 4938).
    pub host_tsc_scaling: bool,
    /// `nested` (vmx.c:116-117, default on).
    pub nested: bool,
    /// `sched_info_on()` (include/linux/sched/stat.h:25-28: CONFIG_SCHED_INFO).
    pub host_sched_info: bool,
    /// `boot_cpu_has(X86_FEATURE_BUS_LOCK_DETECT)` (vmx.c:2028) and the
    /// guest's 7.0.ECX[24].
    pub bus_lock_detect: bool,
}

/// What KVM does with the access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// A read gives this constant; nothing is kept.
    Read(u64),
    /// A write is accepted and nothing is kept.
    Ignore,
    /// A per-vCPU (or per-VM) value KVM keeps: a read gives it
    /// (`Check::Read`); a write is made after the check.
    State(StateKey, Check),
    /// #GP(0), the instruction not done.
    Gp,
    /// Another subsystem's (wick has it, or names what it lacks).
    Delegated(Delegate),
}

/// The values KVM keeps that the backend keeps nowhere yet, or keeps
/// where WHP has no register for them (see kvm-msr-table.md (a)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateKey {
    UcodeRev,
    ArchCapabilities,
    PerfCapabilities,
    PowerCtl,
    SmiCount,
    Smbase,
    PlatformInfo,
    MiscFeaturesEnables,
    OsvwIdLength,
    OsvwStatus,
    Xss,
    Xfd,
    XfdErr,
    TscAux,
    SpecCtrl,
    // AMD
    DeCfg,
    VmHsavePa,
    VmCr,
    VirtSpecCtrl,
    TscRatio,
    DebugCtl,
    LastBranchFromIp,
    LastBranchToIp,
    LastIntFromIp,
    LastIntToIp,
    // Intel
    FeatCtl,
    Bndcfgs,
    UmwaitControl,
    TsxCtrl,
    SgxLePubKeyHash(u8),
    /// The nested VMX capability MSRs (0x480-0x491), from the host's
    /// VMX capabilities (`vmx->nested.msrs`): read-only to the guest.
    VmxCapability(u32),
    /// IA32_DS_AREA of the Intel PMU (`pmu->ds_area`).
    DsArea,
    // KVM's paravirtual MSRs
    KvmAsyncPfEn,
    KvmAsyncPfInt,
    KvmStealTime,
    KvmPvEoiEn,
    KvmPollControl,
}

/// A write's check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Check {
    /// A read.
    Read,
    /// Any value, kept as written.
    Any,
    /// #GP if `data & mask != 0`, else kept.
    Reserved(u64),
    /// #GP unless `data` is exactly this value.
    Exactly(u64),
    /// Kept as `data as u32` (bits 63:32 dropped, no #GP).
    Low32,
    /// A check that needs the vCPU's own state or guest memory.
    Rule(Rule),
}

/// The checks that are more than a mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// IA32_FEATURE_CONTROL: #GP if `data & !valid`, or if the kept value
    /// has LOCKED (bit 0) (vmx.c:2243-2254).
    FeatCtl { valid: u64 },
    /// VM_CR (svm.c:2833-2856): #GP if `data & !0x1f`; LOCK and SVM_DIS
    /// keep their value once SVM_DIS is set; #GP (after the change is
    /// kept) if SVM_DIS ends set while EFER.SVME is.
    VmCr,
    /// MSR_KVM_ASYNC_PF_EN (x86.c:3335-3372): #GP if `data & 0x30`; kept;
    /// then, if bits 0 and 3 are both set, #GP if the 64-bit area at
    /// `data & !0x3f` is not guest RAM (`kvm_gfn_to_hva_cache_init`).
    AsyncPfEn,
    /// MSR_KVM_PV_EOI_EN (lapic.c:2997-3019): #GP if bits 2:1 are set (the
    /// address is not 4-aligned) or, with bit 0, if the byte is not guest
    /// RAM; else kept.
    PvEoi,
    /// IA32_SPEC_CTRL: #GP if the host refuses the value on its own WRMSR
    /// (`kvm_spec_ctrl_test_value`, x86.c:13352-13374).
    SpecCtrlHostTest,
    /// IA32_BNDCFGS (vmx.c:2137-2139): #GP if `data & 0xffc`, or if
    /// `data & PAGE_MASK` is not canonical.
    Bndcfgs,
    /// IA32_DEBUGCTL on Intel (vmx.c:2107-2131): bits outside `supported`
    /// that are BTF (1) or LBR (0) are dropped without a #GP; any other
    /// is #GP.
    DebugctlIntel { supported: u64 },
    /// SGX launch-enclave hash (vmx.c:2255-2274): #GP if FEATURE_CONTROL is
    /// LOCKED without SGX_LC_ENABLED (bit 17).
    SgxLeHash,
    /// #GP if not canonical (pmu_intel.c:440-446).
    Canonical,
}

/// The subsystems KVM hands an access to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delegate {
    /// `set_msr_mce`/`get_msr_mce` and HWCR (x86.c:3256-3326, 3888-3936,
    /// 3585-3598, 4217-4219): wick's `mce.rs`.
    Mce,
    /// `kvm_x2apic_msr_read`/`_write` (lapic.c:2956-2979): wick's
    /// `apicmode.rs` (#GP outside x2APIC mode) and WHP's x2APIC.
    X2Apic,
    /// kvm-clock (x86.c:3689-3714, 4086-4109, `kvm_write_system_time`
    /// 2302-2327): wick's `pvclock.rs` has the two NEW MSRs only.
    KvmClock(KvmClock),
    /// IA32_TSC: read with the TSC offset (x86.c:4011-4033), a guest's
    /// write moves the offset and TSC_ADJUST (x86.c:3661-3669): WHP's
    /// register, wick's `guest_tsc_write` where TSC_ADJUST is the vCPU's.
    Tsc,
    /// IA32_TSC_DEADLINE (x86.c:3613-3615, 4060-4062; lapic.c:2335-2355):
    /// wick's `write_tsc_deadline`/`read_tsc_deadline`.
    TscDeadline,
    /// IA32_TSC_ADJUST (x86.c:3616-3628, 4063-4065): WHP's register where
    /// the partition has it, else wick's `write_software_msr`.
    TscAdjust,
    /// IA32_MISC_ENABLE (x86.c:3629-3652, 4066-4068): WHP's register where
    /// the partition has it, else wick's `write_software_msr`.
    MiscEnable,
    /// IA32_PRED_CMD = IBPB (vmx.c:2193-2219, svm.c:2931-2945): a
    /// write-only command, no state.
    Ibpb,
    /// An MSR WHP keeps in a register (regs.rs `msr_register`,
    /// `msr_segment_base`): EFER, the SYSCALL/SYSENTER MSRs, FS/GS/KERNEL_GS
    /// base, IA32_APIC_BASE. An exit for one is not expected.
    WhpRegister,
    /// The MTRRs and IA32_PAT (`kvm_mtrr_get_msr`/`_set_msr`,
    /// mtrr.c:372-433, `kvm_mtrr_valid` 54-89): WHP's registers.
    Mtrr,
    /// Intel's PMU with a counter-less leaf 0xA still owns IA32_PEBS_ENABLE
    /// and IA32_PEBS_DATA_CFG when PDCM and the PEBS format say so
    /// (pmu_intel.c:201-211); never for a Firecracker guest (PDCM cleared,
    /// vmm cpuid/normalize.rs:241-244). wick has no PMU.
    IntelPmu,
    /// Hyper-V's synthetic MSRs, with a Hyper-V CPUID signature only
    /// (hyperv.c:1654-1694). wick has none.
    HyperV,
}

/// The kvm-clock MSRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KvmClock {
    /// MSR_KVM_WALL_CLOCK (0x11): as WALL_CLOCK_NEW.
    WallClock,
    /// MSR_KVM_SYSTEM_TIME (0x12): as SYSTEM_TIME_NEW, with
    /// `old_msr` true: vCPU 0's write turns the master clock off
    /// (`boot_vcpu_runs_old_kvmclock`, x86.c:2306-2312, 2921).
    SystemTime,
    /// 0x4b564d00.
    WallClockNew,
    /// 0x4b564d01.
    SystemTimeNew,
}

// ---- Indices (v6.1 arch/x86/include/asm/msr-index.h, uapi kvm_para.h) ----

pub(crate) const P5_MC_ADDR: u32 = 0x0;
pub(crate) const P5_MC_TYPE: u32 = 0x1;
pub(crate) const IA32_TSC: u32 = 0x10;
pub(crate) const KVM_WALL_CLOCK: u32 = 0x11;
pub(crate) const KVM_SYSTEM_TIME: u32 = 0x12;
pub(crate) const IA32_PLATFORM_ID: u32 = 0x17;
pub(crate) const IA32_APICBASE: u32 = 0x1b;
pub(crate) const IA32_EBL_CR_POWERON: u32 = 0x2a;
pub(crate) const EBC_FREQUENCY_ID: u32 = 0x2c;
pub(crate) const SMI_COUNT: u32 = 0x34;
pub(crate) const IA32_FEAT_CTL: u32 = 0x3a;
pub(crate) const IA32_TSC_ADJUST: u32 = 0x3b;
pub(crate) const IA32_SPEC_CTRL: u32 = 0x48;
pub(crate) const IA32_PRED_CMD: u32 = 0x49;
pub(crate) const IA32_UCODE_WRITE: u32 = 0x79;
pub(crate) const IA32_UCODE_REV: u32 = 0x8b;
pub(crate) const IA32_SGXLEPUBKEYHASH0: u32 = 0x8c;
pub(crate) const IA32_SMBASE: u32 = 0x9e;
pub(crate) const P6_PERFCTR0: u32 = 0xc1;
pub(crate) const P6_PERFCTR1: u32 = 0xc2;
pub(crate) const FSB_FREQ: u32 = 0xcd;
pub(crate) const PLATFORM_INFO: u32 = 0xce;
pub(crate) const IA32_UMWAIT_CONTROL: u32 = 0xe1;
pub(crate) const MTRRCAP: u32 = 0xfe;
pub(crate) const IA32_ARCH_CAPABILITIES: u32 = 0x10a;
pub(crate) const IA32_BBL_CR_CTL3: u32 = 0x11e;
pub(crate) const IA32_TSX_CTRL: u32 = 0x122;
pub(crate) const MISC_FEATURES_ENABLES: u32 = 0x140;
pub(crate) const IA32_SYSENTER_CS: u32 = 0x174;
pub(crate) const IA32_SYSENTER_ESP: u32 = 0x175;
pub(crate) const IA32_SYSENTER_EIP: u32 = 0x176;
pub(crate) const IA32_MCG_CAP: u32 = 0x179;
pub(crate) const IA32_MCG_CTL: u32 = 0x17b;
pub(crate) const P6_EVNTSEL0: u32 = 0x186;
pub(crate) const P6_EVNTSEL1: u32 = 0x187;
pub(crate) const IA32_PERF_STATUS: u32 = 0x198;
pub(crate) const IA32_PERF_CTL: u32 = 0x199;
pub(crate) const IA32_MISC_ENABLE: u32 = 0x1a0;
pub(crate) const IA32_XFD: u32 = 0x1c4;
pub(crate) const IA32_XFD_ERR: u32 = 0x1c5;
pub(crate) const IA32_DEBUGCTL: u32 = 0x1d9;
pub(crate) const LASTBRANCHFROMIP: u32 = 0x1db;
pub(crate) const LASTBRANCHTOIP: u32 = 0x1dc;
pub(crate) const LASTINTFROMIP: u32 = 0x1dd;
pub(crate) const LASTINTTOIP: u32 = 0x1de;
pub(crate) const IA32_POWER_CTL: u32 = 0x1fc;
pub(crate) const IA32_CR_PAT: u32 = 0x277;
pub(crate) const MC0_CTL2: u32 = 0x280;
pub(crate) const MTRR_DEF_TYPE: u32 = 0x2ff;
pub(crate) const IA32_PERF_CAPABILITIES: u32 = 0x345;
pub(crate) const IA32_PEBS_ENABLE: u32 = 0x3f1;
pub(crate) const PEBS_DATA_CFG: u32 = 0x3f2;
pub(crate) const MC0_CTL: u32 = 0x400;
pub(crate) const IA32_VMX_BASIC: u32 = 0x480;
pub(crate) const IA32_VMX_VMFUNC: u32 = 0x491;
pub(crate) const IA32_MCG_EXT_CTL: u32 = 0x4d0;
pub(crate) const IA32_RTIT_OUTPUT_BASE: u32 = 0x560;
pub(crate) const IA32_RTIT_OUTPUT_MASK: u32 = 0x561;
pub(crate) const IA32_RTIT_CTL: u32 = 0x570;
pub(crate) const IA32_RTIT_STATUS: u32 = 0x571;
pub(crate) const IA32_RTIT_CR3_MATCH: u32 = 0x572;
pub(crate) const IA32_RTIT_ADDR0_A: u32 = 0x580;
pub(crate) const IA32_RTIT_ADDR3_B: u32 = 0x587;
pub(crate) const IA32_DS_AREA: u32 = 0x600;
pub(crate) const RAPL_POWER_UNIT: u32 = 0x606;
pub(crate) const PKG_ENERGY_STATUS: u32 = 0x611;
pub(crate) const DRAM_ENERGY_STATUS: u32 = 0x619;
pub(crate) const PP0_ENERGY_STATUS: u32 = 0x639;
pub(crate) const PP1_ENERGY_STATUS: u32 = 0x641;
pub(crate) const IA32_TSC_DEADLINE: u32 = 0x6e0;
pub(crate) const X2APIC_FIRST: u32 = 0x800;
pub(crate) const X2APIC_LAST: u32 = 0x8ff;
pub(crate) const IA32_BNDCFGS: u32 = 0xd90;
pub(crate) const IA32_XSS: u32 = 0xda0;
pub(crate) const EFER: u32 = 0xc000_0080;
pub(crate) const STAR: u32 = 0xc000_0081;
pub(crate) const LSTAR: u32 = 0xc000_0082;
pub(crate) const CSTAR: u32 = 0xc000_0083;
pub(crate) const SYSCALL_MASK: u32 = 0xc000_0084;
pub(crate) const FS_BASE: u32 = 0xc000_0100;
pub(crate) const GS_BASE: u32 = 0xc000_0101;
pub(crate) const KERNEL_GS_BASE: u32 = 0xc000_0102;
pub(crate) const TSC_AUX: u32 = 0xc000_0103;
pub(crate) const AMD64_TSC_RATIO: u32 = 0xc000_0104;
pub(crate) const K7_EVNTSEL0: u32 = 0xc001_0000;
pub(crate) const K7_EVNTSEL3: u32 = 0xc001_0003;
pub(crate) const K7_PERFCTR0: u32 = 0xc001_0004;
pub(crate) const K7_PERFCTR3: u32 = 0xc001_0007;
pub(crate) const AMD64_SYSCFG: u32 = 0xc001_0010;
pub(crate) const K7_HWCR: u32 = 0xc001_0015;
pub(crate) const K7_CLK_CTL: u32 = 0xc001_001b;
pub(crate) const AMD64_NB_CFG: u32 = 0xc001_001f;
pub(crate) const AMD64_PATCH_LOADER: u32 = 0xc001_0020;
pub(crate) const K8_INT_PENDING_MSG: u32 = 0xc001_0055;
pub(crate) const FAM10H_MMIO_CONF_BASE: u32 = 0xc001_0058;
pub(crate) const K8_TSEG_ADDR: u32 = 0xc001_0112;
pub(crate) const K8_TSEG_MASK: u32 = 0xc001_0113;
pub(crate) const VM_CR: u32 = 0xc001_0114;
pub(crate) const VM_IGNNE: u32 = 0xc001_0115;
pub(crate) const VM_HSAVE_PA: u32 = 0xc001_0117;
pub(crate) const AMD64_VIRT_SPEC_CTRL: u32 = 0xc001_011f;
pub(crate) const AMD64_OSVW_ID_LENGTH: u32 = 0xc001_0140;
pub(crate) const AMD64_OSVW_STATUS: u32 = 0xc001_0141;
pub(crate) const F15H_PERF_CTL0: u32 = 0xc001_0200;
pub(crate) const F15H_PERF_CTR5: u32 = 0xc001_020b;
pub(crate) const F15H_IC_CFG: u32 = 0xc001_1021;
pub(crate) const AMD64_DC_CFG: u32 = 0xc001_1022;
pub(crate) const AMD64_DE_CFG: u32 = 0xc001_1029;
pub(crate) const AMD64_BU_CFG2: u32 = 0xc001_102a;
pub(crate) const F15H_EX_CFG: u32 = 0xc001_102c;
pub(crate) const KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
pub(crate) const KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
pub(crate) const KVM_ASYNC_PF_EN: u32 = 0x4b56_4d02;
pub(crate) const KVM_STEAL_TIME: u32 = 0x4b56_4d03;
pub(crate) const KVM_PV_EOI_EN: u32 = 0x4b56_4d04;
pub(crate) const KVM_POLL_CONTROL: u32 = 0x4b56_4d05;
pub(crate) const KVM_ASYNC_PF_INT: u32 = 0x4b56_4d06;
pub(crate) const KVM_ASYNC_PF_ACK: u32 = 0x4b56_4d07;

/// MSR_AMD64_DE_CFG_LFENCE_SERIALIZE (msr-index.h:540-541).
const DE_CFG_LFENCE_SERIALIZE: u64 = 1 << 1;
/// MSR_PLATFORM_INFO_CPUID_FAULT (msr-index.h:67-68).
const PLATFORM_INFO_CPUID_FAULT: u64 = 1 << 31;
/// ARCH_CAP_TSX_CTRL_MSR (msr-index.h:117).
const ARCH_CAP_TSX_CTRL_MSR: u64 = 1 << 7;
/// FEAT_CTL bits (msr-index.h:728-733).
const FEAT_CTL_LOCKED: u64 = 1 << 0;
const FEAT_CTL_VMX_INSIDE_SMX: u64 = 1 << 1;
const FEAT_CTL_VMX_OUTSIDE_SMX: u64 = 1 << 2;
const FEAT_CTL_SGX_LC_ENABLED: u64 = 1 << 17;
const FEAT_CTL_SGX_ENABLED: u64 = 1 << 18;
/// SPEC_CTRL_SSBD (msr-index.h:53).
const SPEC_CTRL_SSBD: u64 = 1 << 2;
/// SVM_TSC_RATIO_RSVD (arch/x86/include/asm/svm.h:227).
const SVM_TSC_RATIO_RSVD: u64 = 0xffff_ff00_0000_0000;
/// DEBUGCTL_RESERVED_BITS on AMD (svm.h:537).
const AMD_DEBUGCTL_RESERVED: u64 = !0x3f;
/// DEBUGCTLMSR_BUS_LOCK_DETECT (msr-index.h:330).
const DEBUGCTL_BUS_LOCK_DETECT: u64 = 1 << 2;
/// DEBUGCTLMSR_LBR, DEBUGCTLMSR_BTF (msr-index.h:327-329).
const DEBUGCTL_LBR: u64 = 1 << 0;
const DEBUGCTL_BTF: u64 = 1 << 1;
/// PERF_CAP_PEBS_FORMAT (msr-index.h), the PEBS record format field.
const PERF_CAP_PEBS_FORMAT: u64 = 0xf00;
/// PERF_CAP_PEBS_BASELINE.
const PERF_CAP_PEBS_BASELINE: u64 = 1 << 14;
/// KVM_STEAL_RESERVED_MASK (uapi kvm_para.h:83-85).
const KVM_STEAL_RESERVED_MASK: u64 = ((1 << 5) - 1) << 1;
/// MSR_MTRRcap's value: WC, FIX, 8 variable ranges (mtrr.c:398-406,
/// KVM_NR_VAR_MTRR 8, kvm_host.h:151).
const MTRRCAP_VALUE: u64 = 0x500 | 8;

/// Whether a read or write of `index` is one WHP's own registers answer
/// in the MTRR range (`msr_mtrr_valid`, mtrr.c:27-47).
fn mtrr_valid(index: u32) -> bool {
    matches!(index, 0x200..=0x20f | 0x250 | 0x258 | 0x259 | 0x268..=0x26f | MTRR_DEF_TYPE | IA32_CR_PAT)
}

/// The Hyper-V MSRs KVM has a case for (x86.c:3803-3811, 4173-4181;
/// hyperv-tlfs.h, kvm/hyperv.h:46-51).
fn hyperv_case(index: u32) -> bool {
    matches!(
        index,
        0x4000_0000..=0x4000_009f // GUEST_OS_ID ... SINT15
            | 0x4000_00b0..=0x4000_00b7 // STIMER0_CONFIG ... STIMER3_COUNT
            | 0x4000_00f1..=0x4000_00f5 // SYNDBG_CONTROL ... PENDING_BUFFER
            | 0x4000_00ff // SYNDBG_OPTIONS
            | 0x4000_0100..=0x4000_0105 // CRASH_P0..P4, CRASH_CTL
            | 0x4000_0106..=0x4000_0108 // REENLIGHTENMENT, TSC_EMULATION_CONTROL/STATUS
    )
}

/// The machine-check MSRs KVM hands `get_msr_mce`/`set_msr_mce`, and HWCR
/// (wick's `mce::is_mce`).
fn mce_case(index: u32) -> bool {
    matches!(index, P5_MC_ADDR | P5_MC_TYPE | IA32_MCG_CAP..=IA32_MCG_CTL | K7_HWCR)
        || (MC0_CTL2..MC0_CTL2 + 32).contains(&index)
        || (MC0_CTL..MC0_CTL + 4 * 32).contains(&index)
}

/// KVM's answer to the guest's RDMSR (`write` None) or WRMSR (`write`
/// Some(data)) of `index` on a `vendor` host.
pub(crate) fn answer(vendor: Vendor, index: u32, write: Option<u64>, guest: &Guest) -> Answer {
    // __kvm_get_msr / __kvm_set_msr's TSC_AUX check comes before the vendor
    // (x86.c:1834-1856, 1891-1899).
    if index == TSC_AUX {
        if !guest.rdtscp && !guest.rdpid {
            return Answer::Gp; // v6.1 x86.c:1838-1841, 1895-1898
        }
        return match write {
            None => Answer::State(StateKey::TscAux, Check::Read), // v6.1 vmx.c:2003-2006 (uret), svm.c:2760-2762
            // v6.1 x86.c:1852-1855: Intel guests #GP on 63:32, others keep the low half.
            Some(_) if guest.intel_guest => Answer::State(StateKey::TscAux, Check::Reserved(0xffff_ffff_0000_0000)),
            Some(_) => Answer::State(StateKey::TscAux, Check::Low32),
        };
    }
    let vendor_answer = match vendor {
        Vendor::Intel => vmx(index, write, guest),
        Vendor::Amd => svm(index, write, guest),
    };
    if let Some(a) = vendor_answer {
        return a;
    }
    match write {
        None => get_common(vendor, index, guest),
        Some(data) => set_common(vendor, index, data, guest),
    }
}

/// `vmx_get_msr`/`vmx_set_msr`'s own cases; `None` where they hand the MSR
/// to `kvm_*_msr_common` (their `default:` and the cases that call it).
fn vmx(index: u32, write: Option<u64>, guest: &Guest) -> Option<Answer> {
    let read = write.is_none();
    Some(match index {
        // v6.1 vmx.c:1873-1881, 2058-2068 (canonical: x86.c:1810-1817); vmx.c:2088-2106 (x86.c:1818-1833).
        FS_BASE | GS_BASE | KERNEL_GS_BASE | IA32_SYSENTER_CS | IA32_SYSENTER_EIP | IA32_SYSENTER_ESP => {
            Answer::Delegated(Delegate::WhpRegister)
        }
        // v6.1 vmx.c:2002-2008, 2365-2370: the user-return MSRs (vmx.c:8170-8176).
        STAR | LSTAR | CSTAR | SYSCALL_MASK => Answer::Delegated(Delegate::WhpRegister),
        IA32_TSX_CTRL => {
            if guest.arch_capabilities_value & ARCH_CAP_TSX_CTRL_MSR == 0 {
                Answer::Gp // v6.1 vmx.c:1885-1888, 2186-2189
            } else if read {
                Answer::State(StateKey::TsxCtrl, Check::Read) // v6.1 vmx.c:1889, 2003-2006
            } else {
                Answer::State(StateKey::TsxCtrl, Check::Reserved(!0b11)) // v6.1 vmx.c:2190-2192
            }
        }
        IA32_UMWAIT_CONTROL => {
            if !guest.waitpkg {
                Answer::Gp // v6.1 vmx.c:1891-1892, 2149-2150
            } else if read {
                Answer::State(StateKey::UmwaitControl, Check::Read) // v6.1 vmx.c:1894
            } else {
                Answer::State(StateKey::UmwaitControl, Check::Reserved((1 << 1) | 0xffff_ffff_0000_0000)) // v6.1 vmx.c:2152-2156
            }
        }
        IA32_SPEC_CTRL => spec_ctrl(read, guest), // v6.1 vmx.c:1896-1902, 2158-2185
        IA32_BNDCFGS => {
            if !guest.host_mpx || !guest.mpx {
                Answer::Gp // v6.1 vmx.c:1913-1916, 2133-2136
            } else if read {
                Answer::State(StateKey::Bndcfgs, Check::Read) // v6.1 vmx.c:1917
            } else {
                Answer::State(StateKey::Bndcfgs, Check::Rule(Rule::Bndcfgs)) // v6.1 vmx.c:2137-2146
            }
        }
        // FEAT_CTL.LMCE_ENABLED is a valid bit only with MCG_LMCE_P in
        // mcg_cap (vmx.c:7899-7907), which needs KVM_X86_SETUP_MCE:
        // never set for a Firecracker VM, so the gate is always closed.
        IA32_MCG_EXT_CTL => Answer::Gp, // v6.1 vmx.c:1919-1923, 2235-2240
        IA32_FEAT_CTL => {
            if read {
                Answer::State(StateKey::FeatCtl, Check::Read) // v6.1 vmx.c:1926-1928
            } else {
                // v6.1 vmx.c:2243-2254, with the bits of vmx.c:4723, 7623-7666.
                Answer::State(StateKey::FeatCtl, Check::Rule(Rule::FeatCtl { valid: feat_ctl_valid(guest) }))
            }
        }
        0x8c..=0x8f => {
            let n = (index - IA32_SGXLEPUBKEYHASH0) as u8;
            if !guest.sgx_lc {
                Answer::Gp // v6.1 vmx.c:1930-1932, 2267-2271
            } else if read {
                Answer::State(StateKey::SgxLePubKeyHash(n), Check::Read) // v6.1 vmx.c:1933-1935
            } else {
                Answer::State(StateKey::SgxLePubKeyHash(n), Check::Rule(Rule::SgxLeHash)) // v6.1 vmx.c:2267-2274
            }
        }
        IA32_VMX_BASIC..=IA32_VMX_VMFUNC => {
            if read && guest.nested && guest.vmx {
                Answer::State(StateKey::VmxCapability(index), Check::Read) // v6.1 vmx.c:1936-1952
            } else {
                Answer::Gp // v6.1 vmx.c:1937-1938, 2275-2277 (read-only)
            }
        }
        // pt_mode is PT_MODE_SYSTEM by default (vmx.c:213-214), so
        // vmx_pt_mode_is_host_guest() is false (capabilities.h:388-391).
        IA32_RTIT_CTL | IA32_RTIT_STATUS | IA32_RTIT_CR3_MATCH | IA32_RTIT_OUTPUT_BASE | IA32_RTIT_OUTPUT_MASK
        | IA32_RTIT_ADDR0_A..=IA32_RTIT_ADDR3_B => Answer::Gp, // v6.1 vmx.c:1953-1997, 2281-2339
        IA32_DEBUGCTL => {
            if read {
                Answer::State(StateKey::DebugCtl, Check::Read) // v6.1 vmx.c:1998-2000
            } else {
                // v6.1 vmx.c:2024-2037: BUS_LOCK_DETECT with the host's and the
                // guest's; LBR and FREEZE_LBRS_ON_PMI only with guest LBRs,
                // which a counter-less PMU never has (pmu_intel.c:588-593).
                let supported = if guest.bus_lock_detect { DEBUGCTL_BUS_LOCK_DETECT } else { 0 };
                Answer::State(StateKey::DebugCtl, Check::Rule(Rule::DebugctlIntel { supported })) // v6.1 vmx.c:2107-2131
            }
        }
        IA32_PRED_CMD => pred_cmd(write, guest), // v6.1 vmx.c:2193-2219 (no read case: x86.c:4236-4239)
        // v6.1 vmx.c:2220-2234: kvm_pat_valid, then WHP's register.
        IA32_CR_PAT if !read => Answer::Delegated(Delegate::Mtrr),
        IA32_PERF_CAPABILITIES if !read => Answer::Gp, // v6.1 vmx.c:2340-2361 then x86.c:3572-3573
        IA32_XFD if !read => return None, // v6.1 vmx.c:2069-2086: kvm_set_msr_common
        _ => return None,                  // v6.1 vmx.c:2001-2008, 2364-2371
    })
}

/// `svm_get_msr`/`svm_set_msr`'s own cases; `None` where they hand the MSR
/// to `kvm_*_msr_common`.
fn svm(index: u32, write: Option<u64>, guest: &Guest) -> Option<Answer> {
    let read = write.is_none();
    Some(match index {
        AMD64_TSC_RATIO => {
            // v6.1 svm.c:4129: tsc_scaling_enabled.
            if !(guest.host_tsc_scaling && guest.tscratemsr) {
                Answer::Gp // v6.1 svm.c:2726-2727, 2868-2871
            } else if read {
                Answer::State(StateKey::TscRatio, Check::Read) // v6.1 svm.c:2728
            } else {
                Answer::State(StateKey::TscRatio, Check::Reserved(SVM_TSC_RATIO_RSVD)) // v6.1 svm.c:2885-2893
            }
        }
        // v6.1 svm.c:2730-2759, 2956-2990 (the VMCB; FS/GS base are not
        // intercepted on SVM and never reach svm_get_msr).
        STAR | LSTAR | CSTAR | KERNEL_GS_BASE | SYSCALL_MASK | IA32_SYSENTER_CS | IA32_SYSENTER_EIP
        | IA32_SYSENTER_ESP | FS_BASE | GS_BASE => Answer::Delegated(Delegate::WhpRegister),
        IA32_DEBUGCTL => {
            if !guest.host_lbrv {
                // v6.1 svm.c:3006-3010: the write is a nop; the VMCB's
                // DEBUGCTL stays 0, so a read gives 0 (svm.c:2763-2768).
                if read { Answer::Read(0) } else { Answer::Ignore }
            } else if read {
                Answer::State(StateKey::DebugCtl, Check::Read) // v6.1 svm.c:2763-2769
            } else {
                Answer::State(StateKey::DebugCtl, Check::Reserved(AMD_DEBUGCTL_RESERVED)) // v6.1 svm.c:3011-3021
            }
        }
        LASTBRANCHFROMIP | LASTBRANCHTOIP | LASTINTFROMIP | LASTINTTOIP => {
            if !read {
                return None; // v6.1 svm.c:3057-3058 -> x86.c:3879-3882: #GP
            }
            let key = match index {
                LASTBRANCHFROMIP => StateKey::LastBranchFromIp,
                LASTBRANCHTOIP => StateKey::LastBranchToIp,
                LASTINTFROMIP => StateKey::LastIntFromIp,
                _ => StateKey::LastIntToIp,
            };
            // v6.1 svm.c:2764-2768, 943-966: the VMCB's, written only by
            // the processor with LBR virtualization on.
            if guest.host_lbrv { Answer::State(key, Check::Read) } else { Answer::Read(0) }
        }
        VM_HSAVE_PA => {
            if read {
                Answer::State(StateKey::VmHsavePa, Check::Read) // v6.1 svm.c:2770-2772
            } else {
                // v6.1 svm.c:3022-3033: page_address_valid (cpuid.h:61-64).
                Answer::State(StateKey::VmHsavePa, Check::Reserved(guest.reserved_gpa_bits | 0xfff))
            }
        }
        VM_CR => {
            if read {
                Answer::State(StateKey::VmCr, Check::Read) // v6.1 svm.c:2773-2775
            } else {
                Answer::State(StateKey::VmCr, Check::Rule(Rule::VmCr)) // v6.1 svm.c:3034-3035, 2833-2856
            }
        }
        VM_IGNNE if !read => Answer::Ignore, // v6.1 svm.c:3036-3038 (a read: x86.c:4236-4239, #GP)
        IA32_SPEC_CTRL => spec_ctrl(read, guest), // v6.1 svm.c:2776-2785, 2903-2930
        IA32_PRED_CMD if !read => pred_cmd(write, guest), // v6.1 svm.c:2931-2945
        AMD64_VIRT_SPEC_CTRL => {
            if !guest.virt_ssbd {
                Answer::Gp // v6.1 svm.c:2787-2789, 2947-2949
            } else if read {
                Answer::State(StateKey::VirtSpecCtrl, Check::Read) // v6.1 svm.c:2791
            } else {
                Answer::State(StateKey::VirtSpecCtrl, Check::Reserved(!SPEC_CTRL_SSBD)) // v6.1 svm.c:2951-2955
            }
        }
        F15H_IC_CFG if read => match guest.family_model {
            None => return None, // v6.1 svm.c:2800-2801 -> x86.c:4236-4239: #GP
            Some((0x15, model)) if (0x2..0x20).contains(&model) => Answer::Read(0x1e), // v6.1 svm.c:2805-2807
            Some(_) => Answer::Read(0), // v6.1 svm.c:2803
        },
        AMD64_DE_CFG => {
            if read {
                Answer::State(StateKey::DeCfg, Check::Read) // v6.1 svm.c:2810-2811
            } else {
                // v6.1 svm.c:3039-3055 with svm_get_msr_feature (2702-2718): the
                // supported value is LFENCE_SERIALIZE on a host with
                // LFENCE_RDTSC; a guest may write exactly it.
                let supported = if guest.host_lfence_rdtsc { DE_CFG_LFENCE_SERIALIZE } else { 0 };
                Answer::State(StateKey::DeCfg, Check::Exactly(supported))
            }
        }
        // v6.1 svm.c:2894-2902: kvm_mtrr_valid, then the VMCB's g_pat.
        IA32_CR_PAT if !read => Answer::Delegated(Delegate::Mtrr),
        _ => return None, // v6.1 svm.c:2813-2814, 3057-3058
    })
}

/// IA32_SPEC_CTRL on either vendor (vmx.c:1896-1902, 2158-2185; svm.c
/// 2776-2785, 2903-2930).
fn spec_ctrl(read: bool, guest: &Guest) -> Answer {
    // cpuid.h:166-172, guest_has_spec_ctrl_msr.
    if !(guest.spec_ctrl || guest.amd_stibp || guest.amd_ibrs || guest.amd_ssbd) {
        Answer::Gp
    } else if read {
        Answer::State(StateKey::SpecCtrl, Check::Read)
    } else {
        Answer::State(StateKey::SpecCtrl, Check::Rule(Rule::SpecCtrlHostTest))
    }
}

/// IA32_PRED_CMD on either vendor (vmx.c:2193-2219, svm.c:2931-2945): a
/// write-only command; it has no read case anywhere (x86.c:4236-4239: #GP).
fn pred_cmd(write: Option<u64>, guest: &Guest) -> Answer {
    match write {
        None => Answer::Gp,
        // cpuid.h:174-178 guest_has_pred_cmd_msr; then bits other than IBPB;
        // then the host's IBPB, which a write of 0 needs too.
        Some(data) if !(guest.spec_ctrl || guest.amd_ibpb) || data & !1 != 0 || !guest.host_ibpb => Answer::Gp,
        Some(0) => Answer::Ignore,                    // v6.1 vmx.c:2202-2203, svm.c:2940-2941
        Some(_) => Answer::Delegated(Delegate::Ibpb), // v6.1 vmx.c:2205, svm.c:2943
    }
}

/// `kvm_get_msr_common` (x86.c:3938-4242) for the guest.
fn get_common(vendor: Vendor, index: u32, guest: &Guest) -> Answer {
    match index {
        // v6.1 x86.c:3941-3970: read as 0, "do not conditionalize this on CPUID".
        IA32_PLATFORM_ID | IA32_EBL_CR_POWERON | LASTBRANCHFROMIP | LASTBRANCHTOIP | LASTINTFROMIP | LASTINTTOIP
        | AMD64_SYSCFG | K8_TSEG_ADDR | K8_TSEG_MASK | VM_HSAVE_PA | K8_INT_PENDING_MSG | AMD64_NB_CFG
        | FAM10H_MMIO_CONF_BASE | AMD64_BU_CFG2 | IA32_PERF_CTL | AMD64_DC_CFG | F15H_EX_CFG | RAPL_POWER_UNIT
        | PP0_ENERGY_STATUS | PP1_ENERGY_STATUS | PKG_ENERGY_STATUS | DRAM_ENERGY_STATUS => Answer::Read(0),
        IA32_PEBS_ENABLE | IA32_DS_AREA | PEBS_DATA_CFG | F15H_PERF_CTL0..=F15H_PERF_CTR5 => {
            match intel_pmu_owns(vendor, index, guest) {
                Some(a) => a,     // v6.1 x86.c:3975-3976, pmu_intel.c:359-367
                None => Answer::Gp, // v6.1 x86.c:3981-3982
            }
        }
        // v6.1 x86.c:3985-3992 with the PMU off (svm/pmu.c:42-43) or a
        // counter-less Intel PMU (pmu_intel.c:535-537): read as 0.
        K7_EVNTSEL0..=K7_EVNTSEL3 | K7_PERFCTR0..=K7_PERFCTR3 | P6_PERFCTR0 | P6_PERFCTR1 | P6_EVNTSEL0
        | P6_EVNTSEL1 => Answer::Read(0),
        IA32_UCODE_REV => Answer::State(StateKey::UcodeRev, Check::Read), // v6.1 x86.c:3993-3995
        IA32_ARCH_CAPABILITIES => {
            if guest.arch_capabilities {
                Answer::State(StateKey::ArchCapabilities, Check::Read) // v6.1 x86.c:4000
            } else {
                Answer::Gp // v6.1 x86.c:3997-3999
            }
        }
        IA32_PERF_CAPABILITIES => {
            if guest.pdcm {
                Answer::State(StateKey::PerfCapabilities, Check::Read) // v6.1 x86.c:4006
            } else {
                Answer::Gp // v6.1 x86.c:4003-4005
            }
        }
        IA32_POWER_CTL => Answer::State(StateKey::PowerCtl, Check::Read), // v6.1 x86.c:4008-4010
        IA32_TSC => Answer::Delegated(Delegate::Tsc),                     // v6.1 x86.c:4011-4033
        MTRRCAP => Answer::Read(MTRRCAP_VALUE),                           // v6.1 x86.c:4034, mtrr.c:398-406
        // v6.1 x86.c:4035-4037, mtrr.c:409-410: the MTRR range minus the CTL2s.
        0x200..=0x27f | 0x2a0..=0x2ff => {
            if mtrr_valid(index) { Answer::Delegated(Delegate::Mtrr) } else { Answer::Gp }
        }
        FSB_FREQ => Answer::Read(3),                 // v6.1 x86.c:4038-4040
        EBC_FREQUENCY_ID => Answer::Read(1 << 24),   // v6.1 x86.c:4052-4054
        IA32_APICBASE => Answer::Delegated(Delegate::WhpRegister), // v6.1 x86.c:4055-4057
        X2APIC_FIRST..=X2APIC_LAST => Answer::Delegated(Delegate::X2Apic), // v6.1 x86.c:4058-4059
        IA32_TSC_DEADLINE => Answer::Delegated(Delegate::TscDeadline), // v6.1 x86.c:4060-4062
        IA32_TSC_ADJUST => Answer::Delegated(Delegate::TscAdjust),     // v6.1 x86.c:4063-4065 (no CPUID check)
        IA32_MISC_ENABLE => Answer::Delegated(Delegate::MiscEnable),   // v6.1 x86.c:4066-4068
        IA32_SMBASE => Answer::Gp,                                     // v6.1 x86.c:4069-4073
        SMI_COUNT => Answer::State(StateKey::SmiCount, Check::Read),   // v6.1 x86.c:4074-4076
        IA32_PERF_STATUS => Answer::Read(1000 | (4 << 40)),           // v6.1 x86.c:4077-4082
        EFER => Answer::Delegated(Delegate::WhpRegister),              // v6.1 x86.c:4083-4085
        // v6.1 x86.c:4086-4109: guest_pv_has is true without PV CPUID enforcement.
        KVM_WALL_CLOCK => Answer::Delegated(Delegate::KvmClock(KvmClock::WallClock)),
        KVM_WALL_CLOCK_NEW => Answer::Delegated(Delegate::KvmClock(KvmClock::WallClockNew)),
        KVM_SYSTEM_TIME => Answer::Delegated(Delegate::KvmClock(KvmClock::SystemTime)),
        KVM_SYSTEM_TIME_NEW => Answer::Delegated(Delegate::KvmClock(KvmClock::SystemTimeNew)),
        KVM_ASYNC_PF_EN => Answer::State(StateKey::KvmAsyncPfEn, Check::Read), // v6.1 x86.c:4110-4115
        KVM_ASYNC_PF_INT => Answer::State(StateKey::KvmAsyncPfInt, Check::Read), // v6.1 x86.c:4116-4121
        KVM_ASYNC_PF_ACK => Answer::Read(0),                                    // v6.1 x86.c:4122-4127
        KVM_STEAL_TIME => Answer::State(StateKey::KvmStealTime, Check::Read),   // v6.1 x86.c:4128-4133
        KVM_PV_EOI_EN => Answer::State(StateKey::KvmPvEoiEn, Check::Read),      // v6.1 x86.c:4134-4139
        KVM_POLL_CONTROL => Answer::State(StateKey::KvmPollControl, Check::Read), // v6.1 x86.c:4140-4145
        i if mce_case(i) => Answer::Delegated(Delegate::Mce), // v6.1 x86.c:4146-4154, 4217-4219
        IA32_XSS => {
            if guest.xsaves {
                Answer::State(StateKey::Xss, Check::Read) // v6.1 x86.c:4159
            } else {
                Answer::Gp // v6.1 x86.c:4156-4158
            }
        }
        K7_CLK_CTL => Answer::Read(0x2000_0000), // v6.1 x86.c:4161-4172
        i if hyperv_case(i) => {
            if guest.hyperv { Answer::Delegated(Delegate::HyperV) } else { Answer::Gp } // v6.1 x86.c:4173-4184, hyperv.c:1679-1680
        }
        IA32_BBL_CR_CTL3 => Answer::Read(0xbe70_2111), // v6.1 x86.c:4185-4197
        AMD64_OSVW_ID_LENGTH | AMD64_OSVW_STATUS => {
            if !guest.osvw {
                Answer::Gp // v6.1 x86.c:4199-4200, 4204-4205
            } else if index == AMD64_OSVW_ID_LENGTH {
                Answer::State(StateKey::OsvwIdLength, Check::Read) // v6.1 x86.c:4201
            } else {
                Answer::State(StateKey::OsvwStatus, Check::Read) // v6.1 x86.c:4206
            }
        }
        // v6.1 x86.c:4208-4213: guest_can_read_msr_platform_info is true by
        // default (x86.c:12406); KVM_CAP_MSR_PLATFORM_INFO, which Firecracker
        // does not use, can clear it.
        PLATFORM_INFO => Answer::State(StateKey::PlatformInfo, Check::Read),
        MISC_FEATURES_ENABLES => Answer::State(StateKey::MiscFeaturesEnables, Check::Read), // v6.1 x86.c:4214-4216
        IA32_XFD | IA32_XFD_ERR => {
            if !guest.xfd {
                Answer::Gp // v6.1 x86.c:4222-4224, 4229-4231
            } else if index == IA32_XFD {
                Answer::State(StateKey::Xfd, Check::Read) // v6.1 x86.c:4226
            } else {
                Answer::State(StateKey::XfdErr, Check::Read) // v6.1 x86.c:4233
            }
        }
        // v6.1 x86.c:4236-4239: the PMU's last, then KVM_MSR_RET_INVALID: #GP.
        _ => Answer::Gp,
    }
}

/// `kvm_set_msr_common` (x86.c:3541-3885) for the guest.
fn set_common(vendor: Vendor, index: u32, data: u64, guest: &Guest) -> Answer {
    match index {
        // v6.1 x86.c:3551-3558: dropped.
        AMD64_NB_CFG | IA32_UCODE_WRITE | VM_HSAVE_PA | AMD64_PATCH_LOADER | AMD64_BU_CFG2 | AMD64_DC_CFG
        | F15H_EX_CFG => Answer::Ignore,
        IA32_UCODE_REV => Answer::Ignore, // v6.1 x86.c:3560-3563: kept only from the host
        IA32_ARCH_CAPABILITIES => Answer::Gp, // v6.1 x86.c:3564-3566
        IA32_PERF_CAPABILITIES => Answer::Gp, // v6.1 x86.c:3572-3573
        EFER => Answer::Delegated(Delegate::WhpRegister), // v6.1 x86.c:3583-3584, set_efer 1716-1747
        K7_HWCR => Answer::Delegated(Delegate::Mce),       // v6.1 x86.c:3585-3598
        FAM10H_MMIO_CONF_BASE => {
            if data == 0 { Answer::Ignore } else { Answer::Gp } // v6.1 x86.c:3599-3605
        }
        // v6.1 x86.c:3606-3608, mtrr.c:372-391.
        0x200..=0x27f | 0x2a0..=0x2ff => {
            if mtrr_valid(index) { Answer::Delegated(Delegate::Mtrr) } else { Answer::Gp }
        }
        IA32_APICBASE => Answer::Delegated(Delegate::WhpRegister), // v6.1 x86.c:3609-3610, 475-492
        X2APIC_FIRST..=X2APIC_LAST => Answer::Delegated(Delegate::X2Apic), // v6.1 x86.c:3611-3612
        IA32_TSC_DEADLINE => Answer::Delegated(Delegate::TscDeadline), // v6.1 x86.c:3613-3615
        // v6.1 x86.c:3616-3628: kept (and the TSC moved) only with
        // TSC_ADJUST in the guest's CPUID, else dropped without a #GP.
        IA32_TSC_ADJUST => {
            if guest.tsc_adjust { Answer::Delegated(Delegate::TscAdjust) } else { Answer::Ignore }
        }
        IA32_MISC_ENABLE => Answer::Delegated(Delegate::MiscEnable), // v6.1 x86.c:3629-3652
        IA32_SMBASE => Answer::Gp,                                   // v6.1 x86.c:3653-3655
        IA32_POWER_CTL => Answer::State(StateKey::PowerCtl, Check::Any), // v6.1 x86.c:3658-3660
        IA32_TSC => Answer::Delegated(Delegate::Tsc),                // v6.1 x86.c:3661-3669
        IA32_XSS => {
            if guest.xsaves {
                // v6.1 x86.c:3679-3683: kvm_caps.supported_xss is 0 on v6.1
                // (vmx.c:7706, svm.c:4854): only 0 is taken.
                Answer::State(StateKey::Xss, Check::Reserved(u64::MAX))
            } else {
                Answer::Gp // v6.1 x86.c:3671-3673
            }
        }
        SMI_COUNT => Answer::Gp, // v6.1 x86.c:3684-3686
        KVM_WALL_CLOCK_NEW => Answer::Delegated(Delegate::KvmClock(KvmClock::WallClockNew)), // v6.1 x86.c:3689-3695
        KVM_WALL_CLOCK => Answer::Delegated(Delegate::KvmClock(KvmClock::WallClock)),       // v6.1 x86.c:3696-3702
        KVM_SYSTEM_TIME_NEW => Answer::Delegated(Delegate::KvmClock(KvmClock::SystemTimeNew)), // v6.1 x86.c:3703-3708
        KVM_SYSTEM_TIME => Answer::Delegated(Delegate::KvmClock(KvmClock::SystemTime)),     // v6.1 x86.c:3709-3714
        KVM_ASYNC_PF_EN => Answer::State(StateKey::KvmAsyncPfEn, Check::Rule(Rule::AsyncPfEn)), // v6.1 x86.c:3715-3721
        KVM_ASYNC_PF_INT => Answer::State(StateKey::KvmAsyncPfInt, Check::Reserved(!0xff)), // v6.1 x86.c:3722-3728, 3374-3388
        KVM_ASYNC_PF_ACK => Answer::Ignore, // v6.1 x86.c:3729-3736: bit 0 asks for "page ready" events; none kept
        KVM_STEAL_TIME => {
            if guest.host_sched_info {
                Answer::State(StateKey::KvmStealTime, Check::Reserved(KVM_STEAL_RESERVED_MASK)) // v6.1 x86.c:3744-3754
            } else {
                Answer::Gp // v6.1 x86.c:3741-3742
            }
        }
        KVM_PV_EOI_EN => Answer::State(StateKey::KvmPvEoiEn, Check::Rule(Rule::PvEoi)), // v6.1 x86.c:3755-3761
        KVM_POLL_CONTROL => Answer::State(StateKey::KvmPollControl, Check::Reserved(!1)), // v6.1 x86.c:3763-3772
        // v6.1 x86.c:3774-3778 (MCG_CTL, MCG_STATUS, the banks, the CTL2s);
        // P5_MC_ADDR/TYPE and MCG_CAP have no write case (#GP, x86.c:3879-3882),
        // which wick's mce.rs gives too.
        i if mce_case(i) => Answer::Delegated(Delegate::Mce),
        // v6.1 x86.c:3780-3792: the PMU off, so dropped (vcpu_unimpl only).
        K7_PERFCTR0..=K7_PERFCTR3 | P6_PERFCTR0 | P6_PERFCTR1 | K7_EVNTSEL0..=K7_EVNTSEL3 | P6_EVNTSEL0
        | P6_EVNTSEL1 => Answer::Ignore,
        K7_CLK_CTL => Answer::Ignore, // v6.1 x86.c:3793-3802
        i if hyperv_case(i) => {
            if guest.hyperv { Answer::Delegated(Delegate::HyperV) } else { Answer::Gp } // v6.1 x86.c:3803-3813, hyperv.c:1658-1659
        }
        IA32_BBL_CR_CTL3 => Answer::Ignore, // v6.1 x86.c:3814-3821
        AMD64_OSVW_ID_LENGTH | AMD64_OSVW_STATUS => {
            if !guest.osvw {
                Answer::Gp // v6.1 x86.c:3823-3824, 3828-3829
            } else if index == AMD64_OSVW_ID_LENGTH {
                Answer::State(StateKey::OsvwIdLength, Check::Any) // v6.1 x86.c:3825
            } else {
                Answer::State(StateKey::OsvwStatus, Check::Any) // v6.1 x86.c:3830
            }
        }
        PLATFORM_INFO => Answer::Gp, // v6.1 x86.c:3832-3836
        MISC_FEATURES_ENABLES => {
            // v6.1 x86.c:3839-3845: only CPUID_FAULT (bit 0), and that only
            // with PLATFORM_INFO's CPUID_FAULT (cpuid.h:180-183).
            let allowed = if guest.platform_info & PLATFORM_INFO_CPUID_FAULT != 0 { 1 } else { 0 };
            Answer::State(StateKey::MiscFeaturesEnables, Check::Reserved(!allowed))
        }
        IA32_XFD | IA32_XFD_ERR => {
            if !guest.xfd {
                Answer::Gp // v6.1 x86.c:3848-3850, 3858-3860
            } else if index == IA32_XFD {
                Answer::State(StateKey::Xfd, Check::Reserved(!guest.guest_xfd_mask)) // v6.1 x86.c:3852-3856
            } else {
                Answer::State(StateKey::XfdErr, Check::Reserved(!guest.guest_xfd_mask)) // v6.1 x86.c:3862-3866
            }
        }
        IA32_PEBS_ENABLE | IA32_DS_AREA | PEBS_DATA_CFG | F15H_PERF_CTL0..=F15H_PERF_CTR5 => {
            match intel_pmu_owns(vendor, index, guest) {
                Some(Answer::State(k, _)) => Answer::State(k, Check::Rule(Rule::Canonical)), // v6.1 pmu_intel.c:440-446
                Some(a) => a,       // v6.1 x86.c:3872-3873
                None => Answer::Gp, // v6.1 x86.c:3878: `!host_initiated || data`
            }
        }
        // v6.1 x86.c:3879-3882: the PMU's last, then KVM_MSR_RET_INVALID: #GP.
        _ => Answer::Gp,
    }
}

/// Whether Intel's PMU, counter-less as Firecracker's leaf 0xA makes it,
/// still owns one of the PMU MSRs that `kvm_*_msr_common` asks it about
/// (`intel_is_valid_msr`, pmu_intel.c:188-221): IA32_DS_AREA with DS in the
/// guest's CPUID (pmu_intel.c:204-206; KVM never offers DS, cpuid.c:608),
/// PEBS_ENABLE/PEBS_DATA_CFG with PDCM and a PEBS format. AMD's PMU, off,
/// owns none (svm/pmu.c:42-43, 103-107).
fn intel_pmu_owns(vendor: Vendor, index: u32, guest: &Guest) -> Option<Answer> {
    if vendor != Vendor::Intel {
        return None;
    }
    let caps = if guest.pdcm { guest.perf_capabilities } else { 0 }; // pmu_intel.c:149-155
    match index {
        IA32_DS_AREA if guest.ds => Some(Answer::State(StateKey::DsArea, Check::Read)),
        IA32_PEBS_ENABLE if caps & PERF_CAP_PEBS_FORMAT != 0 => Some(Answer::Delegated(Delegate::IntelPmu)),
        PEBS_DATA_CFG if caps & PERF_CAP_PEBS_BASELINE != 0 && (caps & PERF_CAP_PEBS_FORMAT) > 0x300 => {
            Some(Answer::Delegated(Delegate::IntelPmu))
        }
        _ => None,
    }
}

/// The value a write of `data` keeps under `check`, or `None` for #GP;
/// also `None` for a [`Check::Rule`] that needs the vCPU's state or guest
/// memory, which the state's owner checks.
pub(crate) fn takes(check: Check, data: u64) -> Option<u64> {
    match check {
        Check::Read => None,
        Check::Any => Some(data),
        Check::Reserved(mask) => (data & mask == 0).then_some(data),
        Check::Exactly(v) => (data == v).then_some(data),
        Check::Low32 => Some(u64::from(data as u32)),
        // v6.1 vmx.c:2110-2120: BTF and LBR outside `supported` dropped, any other bit #GP.
        Check::Rule(Rule::DebugctlIntel { supported }) => {
            let quiet = (DEBUGCTL_BTF | DEBUGCTL_LBR) & !supported;
            let invalid = data & !supported & !quiet;
            (invalid == 0).then_some(data & !quiet)
        }
        Check::Rule(_) => None,
    }
}

/// The value KVM gives a state at vCPU creation, before the VMM writes it,
/// where KVM's is not the host's (`None` there: kvm-msr-table.md (b)).
pub(crate) fn initial(vendor: Vendor, key: StateKey) -> Option<u64> {
    Some(match key {
        StateKey::UcodeRev => match vendor {
            Vendor::Intel => 0x1_0000_0000, // v6.1 vmx.c:4722
            Vendor::Amd => 0x0100_0065,     // v6.1 svm.c:1325
        },
        StateKey::PlatformInfo => PLATFORM_INFO_CPUID_FAULT, // v6.1 x86.c:11917
        StateKey::KvmPollControl => 1,                       // v6.1 x86.c:11954-11955
        StateKey::TscRatio => 1 << 32,                       // v6.1 svm.c:1326, x86.c:12307 (SVM: 32 fraction bits)
        // v6.1 x86.c:11916 kvm_get_arch_capabilities (host MSR and bugs, 1593-1649);
        // svm.c:500-507 (host OSVW, 609-628); vmx->nested.msrs (host VMX caps);
        // vmx_get_perf_capabilities (capabilities.h:398-420, host PERF_CAPABILITIES).
        StateKey::ArchCapabilities | StateKey::OsvwIdLength | StateKey::OsvwStatus | StateKey::VmxCapability(_) => {
            return None;
        }
        StateKey::PerfCapabilities => match vendor {
            Vendor::Amd => 0,          // v6.1 svm.c:2711-2712 (the feature value; never set otherwise)
            Vendor::Intel => return None, // v6.1 pmu_intel.c:634 (0 with enable_pmu off, capabilities.h:404-405)
        },
        // Every other state starts at 0 (kzalloc'd vCPU, x86.c:12065-12074 at reset).
        _ => 0,
    })
}

/// IA32_SMBASE at reset (x86.c:12057, `kvm_vcpu_reset`).
const SMBASE_RESET: u64 = 0x3_0000;
/// VM_CR's bits (svm.h `SVM_VM_CR_VALID_MASK`, `_SVM_LOCK_MASK`, `_SVM_DIS_MASK`).
const VM_CR_VALID: u64 = 0x1f;
const VM_CR_SVM_LOCK: u64 = 1 << 3;
const VM_CR_SVM_DIS: u64 = 1 << 4;

/// What a guest's write of a value KVM keeps comes to ([`Kept::guest_write`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Write {
    /// Taken, and kept as KVM keeps it.
    Taken,
    /// #GP(0); for VM_CR and MSR_KVM_ASYNC_PF_EN after the change KVM
    /// keeps all the same (svm.c:2846-2853; x86.c:3354, 3362-3364).
    Gp,
    /// A value KVM keeps whose effect is the processor's or the host's
    /// (SPEC_CTRL, TSC_AUX, the XSAVE and MPX MSRs, DEBUGCTL with LBRs, the
    /// VMX capabilities, ARCH_CAPABILITIES, ...): WHP keeps those in its
    /// registers where the partition has them and does not hand them over;
    /// one that is handed over the backend cannot make work, so the vCPU
    /// fails, named, rather than keep a value that does nothing.
    NotKept,
}

/// What `KVM_SET_MSRS` of one of [`Kept`]'s comes to ([`Kept::host_set`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostSet {
    /// Taken.
    Taken,
    /// Refused as KVM refuses it: the call ends there.
    Refused,
    /// Refused here where KVM takes it, for the reason given (a feature the
    /// backend does not have): the call ends there, and the reason is said.
    Unsupported(&'static str),
}

/// The values KVM keeps for a vCPU that no WHP register holds, kept by the
/// backend for each vCPU, from KVM's values at vCPU creation
/// ([`Kept::new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Kept {
    /// IA32_POWER_CTL (x86.c:3658-3660, 4008-4010).
    pub(crate) power_ctl: u64,
    /// MSR_SMI_COUNT: KVM counts the SMIs it injects; this backend injects
    /// none (x86.c:3684-3688, 4074-4076).
    pub(crate) smi_count: u64,
    /// IA32_SMBASE, the host's only (x86.c:3653-3657, 4069-4073).
    pub(crate) smbase: u64,
    /// MSR_PLATFORM_INFO (x86.c:3832-3838, 4208-4213).
    pub(crate) platform_info: u64,
    /// MSR_MISC_FEATURES_ENABLES (x86.c:3839-3845, 4214-4216).
    pub(crate) misc_features_enables: u64,
    /// IA32_UCODE_REV (x86.c:3560-3563, 3993-3995).
    pub(crate) ucode_rev: u64,
    /// MSR_AMD64_OSVW_ID_LENGTH and _STATUS (x86.c:3822-3831, 4198-4207).
    pub(crate) osvw_length: u64,
    pub(crate) osvw_status: u64,
    /// MSR_AMD64_DE_CFG (svm.c:2810-2811, 3039-3056).
    pub(crate) de_cfg: u64,
    /// MSR_VM_HSAVE_PA on AMD (svm.c:2770-2772, 3022-3033).
    pub(crate) vm_hsave_pa: u64,
    /// MSR_VM_CR (svm.c:2773-2775, 2833-2856).
    pub(crate) vm_cr: u64,
    /// IA32_FEAT_CTL on Intel (vmx.c:1926-1928, 2243-2254).
    pub(crate) feat_ctl: u64,
    /// KVM's paravirtual MSRs (x86.c:3715-3772, 4110-4145).
    pub(crate) async_pf_en: u64,
    pub(crate) async_pf_int: u64,
    pub(crate) steal_time: u64,
    pub(crate) pv_eoi_en: u64,
    pub(crate) poll_control: u64,
}

/// KVM_STEAL_TIME's enable bit (`KVM_MSR_ENABLED`, uapi kvm_para.h).
const KVM_MSR_ENABLED: u64 = 1;

impl Kept {
    /// KVM's values at vCPU creation on a `vendor` host, but for
    /// MSR_PLATFORM_INFO: KVM's has CPUID_FAULT (x86.c:11917), which lets
    /// the guest turn CPUID faulting on (MISC_FEATURES_ENABLES bit 0), a
    /// CPUID at CPL > 0 then being #GP (cpuid.c:1500-1501); the backend's
    /// CPUID exit has no faulting (WHP hands it only the leaves of the
    /// partition's CPUID exit list), so the bit is clear, as a VMM that
    /// clears it with `KVM_SET_MSRS` has it on KVM, and the guest cannot
    /// turn faulting on. `host_osvw` is the host's CPUID 0x8000_0001 ECX
    /// bit 9: KVM's OSVW length is the host's, capped at 4 and at least 3
    /// (svm.c:73, 500-507, 609-628), 3 without OSVW; a Windows process
    /// cannot read the host's (an RDMSR), so the length is 4 where the host
    /// has OSVW, and the status 0: KVM clears bits 1 and 2 (errata 400 and
    /// 415, svm.c:507), and 0 and 3 (errata 298 and 383) are family 10h's.
    pub(crate) fn new(vendor: Vendor, host_osvw: bool) -> Self {
        Self {
            power_ctl: 0,
            smi_count: 0,
            smbase: SMBASE_RESET,
            platform_info: 0,
            misc_features_enables: 0,
            ucode_rev: initial(vendor, StateKey::UcodeRev).unwrap_or(0),
            osvw_length: match vendor {
                Vendor::Amd if host_osvw => 4,
                Vendor::Amd => 3,
                Vendor::Intel => 0,
            },
            osvw_status: 0,
            de_cfg: 0,
            vm_hsave_pa: 0,
            vm_cr: 0,
            feat_ctl: 0,
            async_pf_en: 0,
            async_pf_int: 0,
            steal_time: 0,
            pv_eoi_en: 0,
            poll_control: initial(vendor, StateKey::KvmPollControl).unwrap_or(1),
        }
    }

    /// The place of `key`, or `None` for one the backend keeps nowhere.
    fn slot(&mut self, key: StateKey) -> Option<&mut u64> {
        Some(match key {
            StateKey::PowerCtl => &mut self.power_ctl,
            StateKey::SmiCount => &mut self.smi_count,
            StateKey::Smbase => &mut self.smbase,
            StateKey::PlatformInfo => &mut self.platform_info,
            StateKey::MiscFeaturesEnables => &mut self.misc_features_enables,
            StateKey::UcodeRev => &mut self.ucode_rev,
            StateKey::OsvwIdLength => &mut self.osvw_length,
            StateKey::OsvwStatus => &mut self.osvw_status,
            StateKey::DeCfg => &mut self.de_cfg,
            StateKey::VmHsavePa => &mut self.vm_hsave_pa,
            StateKey::VmCr => &mut self.vm_cr,
            StateKey::FeatCtl => &mut self.feat_ctl,
            StateKey::KvmAsyncPfEn => &mut self.async_pf_en,
            StateKey::KvmAsyncPfInt => &mut self.async_pf_int,
            StateKey::KvmStealTime => &mut self.steal_time,
            StateKey::KvmPvEoiEn => &mut self.pv_eoi_en,
            StateKey::KvmPollControl => &mut self.poll_control,
            _ => return None,
        })
    }

    /// A guest's read of `key` ([`Answer::State`] with [`Check::Read`]), or
    /// `None` for one the backend keeps nowhere ([`Write::NotKept`]).
    /// IA32_PERF_CAPABILITIES, which the guest reaches only with PDCM in its
    /// CPUID, reads 0: KVM's with its PMU off (`enable_pmu` 0,
    /// vmx/capabilities.h:404-405; AMD: svm.c:2711-2712).
    pub(crate) fn guest_read(&self, key: StateKey) -> Option<u64> {
        if key == StateKey::PerfCapabilities {
            return Some(0);
        }
        let mut copy = *self;
        copy.slot(key).map(|v| *v)
    }

    /// A guest's write of `data` to `key` under `check` ([`answer`]).
    /// `efer_svme` is EFER.SVME (VM_CR's rule); `ram(gpa, len)` whether
    /// `len` bytes at `gpa` are guest RAM, as KVM's
    /// `kvm_gfn_to_hva_cache_init` finds them in a memory slot.
    pub(crate) fn guest_write(
        &mut self,
        key: StateKey,
        check: Check,
        data: u64,
        efer_svme: bool,
        ram: &dyn Fn(u64, u64) -> bool,
    ) -> Write {
        let feat_ctl = self.feat_ctl;
        let Some(slot) = self.slot(key) else {
            return Write::NotKept;
        };
        match check {
            // v6.1 vmx.c:2243-2254 (`is_vmx_feature_control_msr_valid`,
            // vmx.c:1820-1835): a guest cannot write it once LOCKED.
            Check::Rule(Rule::FeatCtl { valid }) => {
                if feat_ctl & FEAT_CTL_LOCKED != 0 || data & !valid != 0 {
                    return Write::Gp;
                }
                *slot = data;
                Write::Taken
            }
            Check::Rule(Rule::VmCr) => vm_cr(slot, data, efer_svme),
            Check::Rule(Rule::AsyncPfEn) => async_pf_en(slot, data, ram),
            Check::Rule(Rule::PvEoi) => pv_eoi(slot, data, ram),
            Check::Rule(_) | Check::Read => Write::NotKept,
            check => match takes(check, data) {
                Some(v) => {
                    *slot = v;
                    Write::Taken
                }
                None => Write::Gp,
            },
        }
    }

    /// The MSR KVM_GET_MSRS reads here (`host_index`), or `None`.
    pub(crate) fn host_get(&self, vendor: Vendor, index: u32, guest: &Guest) -> Option<u64> {
        let key = host_key(vendor, index, guest)?;
        if index == KVM_ASYNC_PF_ACK {
            return Some(0); // v6.1 x86.c:4122-4127
        }
        let mut copy = *self;
        copy.slot(key).map(|v| *v)
    }

    /// KVM_SET_MSRS of `data` to `index` (`msr_info->host_initiated`), as
    /// KVM takes it; `None` for an index that is not one of these.
    pub(crate) fn host_set(
        &mut self,
        vendor: Vendor,
        index: u32,
        data: u64,
        guest: &Guest,
        ram: &dyn Fn(u64, u64) -> bool,
    ) -> Option<HostSet> {
        let key = host_key(vendor, index, guest)?;
        let take = |slot: &mut u64, v: u64| {
            *slot = v;
            HostSet::Taken
        };
        if index == KVM_ASYNC_PF_ACK {
            // v6.1 x86.c:3729-3736: bit 0 asks for "page ready" events, of
            // which there are none; nothing is kept.
            return Some(HostSet::Taken);
        }
        let platform = self.platform_info;
        let slot = self.slot(key)?;
        Some(match index {
            // v6.1 x86.c:3832-3838: a value without CPUID_FAULT is refused
            // only while faulting is on, which it never is here; one with it
            // would let the guest turn faulting on, which the backend's
            // CPUID exit does not have (`Kept::new`).
            PLATFORM_INFO if data & PLATFORM_INFO_CPUID_FAULT != 0 => HostSet::Unsupported(
                "MSR_PLATFORM_INFO with CPUID_FAULT (bit 31): CPUID faulting, which the backend's CPUID exit does \
                 not have (WHP exits only for the leaves of the partition's CPUID exit list)",
            ),
            PLATFORM_INFO => take(slot, data),
            // v6.1 x86.c:3839-3845, with no host exemption.
            MISC_FEATURES_ENABLES => {
                let allowed = if platform & PLATFORM_INFO_CPUID_FAULT != 0 { 1 } else { 0 };
                if data & !allowed != 0 { HostSet::Refused } else { take(slot, data) }
            }
            // v6.1 x86.c:3560-3563, 3653-3660, 3684-3688: kept as given.
            IA32_UCODE_REV | IA32_SMBASE | SMI_COUNT | IA32_POWER_CTL => take(slot, data),
            // v6.1 x86.c:3822-3831: kept, with OSVW in the guest's CPUID.
            AMD64_OSVW_ID_LENGTH | AMD64_OSVW_STATUS => take(slot, data),
            // v6.1 svm.c:3039-3056: the supported bits only (a host write
            // may leave one clear).
            AMD64_DE_CFG => {
                let supported = if guest.host_lfence_rdtsc { DE_CFG_LFENCE_SERIALIZE } else { 0 };
                if data & !supported != 0 { HostSet::Refused } else { take(slot, data) }
            }
            // v6.1 svm.c:3022-3033: no check for the host; kept page-aligned.
            VM_HSAVE_PA => take(slot, data & !0xfff),
            VM_CR => match vm_cr(slot, data, false) {
                Write::Taken => HostSet::Taken,
                _ => HostSet::Refused,
            },
            // v6.1 vmx.c:1820-1835, 2243-2254: the valid bits, LOCKED or not.
            IA32_FEAT_CTL => {
                if data & !feat_ctl_valid(guest) != 0 { HostSet::Refused } else { take(slot, data) }
            }
            KVM_ASYNC_PF_EN => match async_pf_en(slot, data, ram) {
                Write::Taken => HostSet::Taken,
                _ => HostSet::Refused,
            },
            KVM_ASYNC_PF_INT => {
                if data >> 8 != 0 { HostSet::Refused } else { take(slot, data) } // v6.1 x86.c:3374-3388
            }
            // v6.1 x86.c:3737-3754: KVM refuses every value on a host
            // kernel without CONFIG_SCHED_INFO, as the guest's write is
            // here; a value that leaves steal time off is taken (KVM on any
            // other host takes it, and it changes nothing the guest sees),
            // one that turns it on is refused, named: the backend does not
            // account steal time.
            KVM_STEAL_TIME if data & KVM_STEAL_RESERVED_MASK != 0 => HostSet::Refused,
            KVM_STEAL_TIME if data & KVM_MSR_ENABLED != 0 => HostSet::Unsupported(
                "MSR_KVM_STEAL_TIME enabled: steal time, which the backend does not account (its guest CPUID does not \
                 offer KVM_FEATURE_STEAL_TIME)",
            ),
            KVM_STEAL_TIME => take(slot, data),
            KVM_PV_EOI_EN => match pv_eoi(slot, data, ram) {
                Write::Taken => HostSet::Taken,
                _ => HostSet::Refused,
            },
            KVM_POLL_CONTROL => {
                if data & !1 != 0 { HostSet::Refused } else { take(slot, data) } // v6.1 x86.c:3763-3772
            }
            _ => return None,
        })
    }
}

/// [`Kept`]'s place for `KVM_GET_MSRS` and `KVM_SET_MSRS` of `index` on a
/// `vendor` host, as KVM's host-initiated access reaches it, or `None`.
fn host_key(vendor: Vendor, index: u32, guest: &Guest) -> Option<StateKey> {
    Some(match index {
        IA32_POWER_CTL => StateKey::PowerCtl,
        SMI_COUNT => StateKey::SmiCount,
        IA32_SMBASE => StateKey::Smbase,
        PLATFORM_INFO => StateKey::PlatformInfo,
        MISC_FEATURES_ENABLES => StateKey::MiscFeaturesEnables,
        IA32_UCODE_REV => StateKey::UcodeRev,
        // v6.1 x86.c:3823-3824, 4199-4200: with OSVW in the guest's CPUID,
        // for the host too.
        AMD64_OSVW_ID_LENGTH if guest.osvw => StateKey::OsvwIdLength,
        AMD64_OSVW_STATUS if guest.osvw => StateKey::OsvwStatus,
        AMD64_DE_CFG if vendor == Vendor::Amd => StateKey::DeCfg,
        VM_HSAVE_PA if vendor == Vendor::Amd => StateKey::VmHsavePa,
        VM_CR if vendor == Vendor::Amd => StateKey::VmCr,
        IA32_FEAT_CTL if vendor == Vendor::Intel => StateKey::FeatCtl,
        KVM_ASYNC_PF_EN => StateKey::KvmAsyncPfEn,
        KVM_ASYNC_PF_INT | KVM_ASYNC_PF_ACK => StateKey::KvmAsyncPfInt,
        KVM_STEAL_TIME => StateKey::KvmStealTime,
        KVM_PV_EOI_EN => StateKey::KvmPvEoiEn,
        KVM_POLL_CONTROL => StateKey::KvmPollControl,
        _ => return None,
    })
}

/// IA32_FEAT_CTL's bits a write may have (vmx.c:4723, 7623-7666): LOCKED,
/// VMX inside and outside SMX with nested VMX and VMX in the guest's CPUID,
/// SGX_ENABLED with SGX, SGX_LC_ENABLED with SGX_LC; LMCE_ENABLED only with
/// MCG_LMCE_P, which needs `KVM_X86_SETUP_MCE` (vmx.c:7899-7907).
fn feat_ctl_valid(guest: &Guest) -> u64 {
    let mut valid = FEAT_CTL_LOCKED;
    if guest.nested && guest.vmx {
        valid |= FEAT_CTL_VMX_INSIDE_SMX | FEAT_CTL_VMX_OUTSIDE_SMX;
    }
    if guest.sgx {
        valid |= FEAT_CTL_SGX_ENABLED;
    }
    if guest.sgx_lc {
        valid |= FEAT_CTL_SGX_LC_ENABLED;
    }
    valid
}

/// MSR_VM_CR's write (`svm_set_vm_cr`, svm.c:2833-2856): #GP on a bit
/// outside the valid mask; once SVM_DIS is set, LOCK and SVM_DIS keep their
/// value; the change is kept, then #GP if SVM_DIS is set while EFER.SVME is.
fn vm_cr(slot: &mut u64, data: u64, efer_svme: bool) -> Write {
    if data & !VM_CR_VALID != 0 {
        return Write::Gp;
    }
    let mut change = VM_CR_VALID;
    if *slot & VM_CR_SVM_DIS != 0 {
        change &= !(VM_CR_SVM_LOCK | VM_CR_SVM_DIS);
    }
    *slot = (*slot & !change) | (data & change);
    if *slot & VM_CR_SVM_DIS != 0 && efer_svme { Write::Gp } else { Write::Taken }
}

/// MSR_KVM_ASYNC_PF_EN's write (`kvm_pv_enable_async_pf`, x86.c:3335-3372,
/// `guest_pv_has` true): #GP on bits 5:4; kept; then, with ENABLED (bit 0)
/// and DELIVERY_AS_INT (bit 3) both set, #GP if the 8 bytes at
/// `data & !0x3f` are not guest RAM, the value staying kept.
fn async_pf_en(slot: &mut u64, data: u64, ram: &dyn Fn(u64, u64) -> bool) -> Write {
    const ENABLED_AS_INT: u64 = 1 | (1 << 3);
    if data & 0x30 != 0 {
        return Write::Gp;
    }
    *slot = data;
    if data & ENABLED_AS_INT != ENABLED_AS_INT || ram(data & !0x3f, 8) { Write::Taken } else { Write::Gp }
}

/// MSR_KVM_PV_EOI_EN's write (`kvm_lapic_set_pv_eoi`, lapic.c:2997-3021,
/// one byte): #GP if the address (`data & !1`) is not 4-aligned, or, with
/// bit 0, if its byte is not guest RAM; else kept.
fn pv_eoi(slot: &mut u64, data: u64, ram: &dyn Fn(u64, u64) -> bool) -> Write {
    let addr = data & !1;
    if addr & 3 != 0 || (data & 1 != 0 && !ram(addr, 1)) {
        return Write::Gp;
    }
    *slot = data;
    Write::Taken
}

/// The MSRs of [`Kept`] that `KVM_GET_MSR_INDEX_LIST` lists on a `vendor`
/// host, as KVM lists them (x86.c `msrs_to_save_all` 1426-1469, kept where
/// the host has them, and `emulated_msrs_all` 1474-1537): SMI_COUNT,
/// SMBASE, PLATFORM_INFO, MISC_FEATURES_ENABLES, POWER_CTL, UCODE_REV, the
/// paravirtual MSRs; FEAT_CTL on Intel, VM_HSAVE_PA on AMD. Not
/// MSR_KVM_STEAL_TIME, which KVM lists: listed, a snapshot of a guest that
/// turned it on could not be restored here ([`Kept::host_set`]).
pub(crate) fn listed(vendor: Vendor) -> impl Iterator<Item = u32> {
    [
        SMI_COUNT,
        IA32_SMBASE,
        PLATFORM_INFO,
        MISC_FEATURES_ENABLES,
        IA32_POWER_CTL,
        IA32_UCODE_REV,
        KVM_ASYNC_PF_EN,
        KVM_PV_EOI_EN,
        KVM_ASYNC_PF_INT,
        KVM_ASYNC_PF_ACK,
        KVM_POLL_CONTROL,
    ]
    .into_iter()
    .chain(match vendor {
        Vendor::Intel => Some(IA32_FEAT_CTL),
        Vendor::Amd => Some(VM_HSAVE_PA),
    })
}

/// Whether `KVM_GET_MSRS` and `KVM_SET_MSRS` have `index` in [`Kept`] on a
/// `vendor` host for a guest with `guest`'s CPUID.
pub(crate) fn host_has(vendor: Vendor, index: u32, guest: &Guest) -> bool {
    host_key(vendor, index, guest).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Firecracker guest on an AMD host with the PMU off, as the PC's
    /// MSRREC guest had it (Zen 4, OSVW offered: the guest read 0xc0010140).
    fn amd_guest() -> Guest {
        Guest {
            amd_or_hygon_guest: true,
            family_model: Some((0x19, 0x61)),
            tsc_adjust: false,
            osvw: true,
            rdtscp: true,
            rdpid: true,
            amd_ibpb: true,
            amd_ibrs: true,
            amd_stibp: true,
            amd_ssbd: true,
            xsaves: true,
            reserved_gpa_bits: !0u64 << 48,
            platform_info: PLATFORM_INFO_CPUID_FAULT,
            host_lfence_rdtsc: true,
            host_ibpb: true,
            host_sched_info: true,
            nested: true,
            ..Guest::default()
        }
    }

    /// A Firecracker guest on an Intel host: leaf 0xA zeroed, PDCM cleared.
    fn intel_guest() -> Guest {
        Guest {
            intel_guest: true,
            family_model: Some((6, 0x8f)),
            tsc_adjust: true,
            arch_capabilities: true,
            spec_ctrl: true,
            rdtscp: true,
            xsaves: true,
            reserved_gpa_bits: !0u64 << 46,
            platform_info: PLATFORM_INFO_CPUID_FAULT,
            host_ibpb: true,
            host_sched_info: true,
            nested: true,
            ..Guest::default()
        }
    }

    const R: Option<u64> = None;

    // Every index of the PC's MSRREC (df0bf87, step 16i), answered as KVM
    // answers it on an AMD host with the PMU off.
    #[test]
    fn test_msrrec_on_amd() {
        let g = amd_guest();
        let a = |i, w| answer(Vendor::Amd, i, w, &g);
        // OSVW: kept per vCPU, offered by the guest's CPUID.
        assert_eq!(a(0xc001_0140, R), Answer::State(StateKey::OsvwIdLength, Check::Read));
        assert_eq!(a(0xc001_0141, R), Answer::State(StateKey::OsvwStatus, Check::Read));
        assert_eq!(a(0xc001_0140, Some(5)), Answer::State(StateKey::OsvwIdLength, Check::Any));
        // DE_CFG: read the vCPU's (0 at creation); the guest's write of 0x2
        // (amd.c:959-971) is the supported value and kept; another is #GP.
        assert_eq!(a(0xc001_1029, R), Answer::State(StateKey::DeCfg, Check::Read));
        assert_eq!(initial(Vendor::Amd, StateKey::DeCfg), Some(0));
        let w = a(0xc001_1029, Some(0x2));
        assert_eq!(w, Answer::State(StateKey::DeCfg, Check::Exactly(0x2)));
        let Answer::State(_, check) = w else { unreachable!() };
        assert_eq!(takes(check, 0x2), Some(0x2));
        assert_eq!(takes(check, 0x0), None);
        assert_eq!(takes(check, 0x6), None);
        // K7 EVNTSEL0-3, PERFCTR3: the PMU off: read 0, writes dropped.
        for i in 0xc001_0000..=0xc001_0003 {
            assert_eq!(a(i, R), Answer::Read(0), "{i:#x}");
        }
        assert_eq!(a(0xc001_0007, R), Answer::Read(0));
        assert_eq!(a(0xc001_0007, Some(0xffff)), Answer::Ignore);
        // NB_CFG: read 0, write dropped.
        assert_eq!(a(0xc001_001f, R), Answer::Read(0));
        assert_eq!(a(0xc001_001f, Some(0x4000_0000_0000)), Answer::Ignore);
        // AMD's RAPL MSRs: no case in v6.1, #GP.
        assert_eq!(a(0xc001_029b, R), Answer::Gp);
        assert_eq!(a(0xc001_0299, R), Answer::Gp);
    }

    // Without OSVW in the guest's CPUID, both OSVW MSRs are #GP; DE_CFG on
    // a host without LFENCE_RDTSC takes only 0.
    #[test]
    fn test_amd_conditions() {
        let g = Guest { osvw: false, host_lfence_rdtsc: false, ..amd_guest() };
        assert_eq!(answer(Vendor::Amd, 0xc001_0140, R, &g), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, 0xc001_0141, Some(0), &g), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, 0xc001_1029, Some(2), &g), Answer::State(StateKey::DeCfg, Check::Exactly(0)));
        // DE_CFG is AMD's: on Intel it has no case.
        assert_eq!(answer(Vendor::Intel, 0xc001_1029, R, &intel_guest()), Answer::Gp);
    }

    // An index KVM has no case for: #GP on both vendors, both ways.
    #[test]
    fn test_unknown_is_gp() {
        for (v, g) in [(Vendor::Amd, amd_guest()), (Vendor::Intel, intel_guest())] {
            assert_eq!(answer(v, 0xc001_1234, R, &g), Answer::Gp);
            assert_eq!(answer(v, 0xc001_1234, Some(0), &g), Answer::Gp);
        }
    }

    // READ_CONST / WRITE_IGNORED rows.
    #[test]
    fn test_constants() {
        let g = intel_guest();
        let a = |v, i, w| answer(v, i, w, &g);
        assert_eq!(a(Vendor::Intel, MTRRCAP, R), Answer::Read(0x508));
        assert_eq!(a(Vendor::Intel, MTRRCAP, Some(0)), Answer::Gp);
        assert_eq!(a(Vendor::Intel, IA32_PERF_STATUS, R), Answer::Read(1000 | (4 << 40)));
        assert_eq!(a(Vendor::Amd, K7_CLK_CTL, R), Answer::Read(0x2000_0000));
        assert_eq!(a(Vendor::Amd, K7_CLK_CTL, Some(7)), Answer::Ignore);
        assert_eq!(a(Vendor::Intel, IA32_BBL_CR_CTL3, R), Answer::Read(0xbe70_2111));
        assert_eq!(a(Vendor::Intel, FSB_FREQ, R), Answer::Read(3));
        assert_eq!(a(Vendor::Intel, EBC_FREQUENCY_ID, R), Answer::Read(1 << 24));
        // Intel RAPL: read 0, but no write case.
        assert_eq!(a(Vendor::Intel, RAPL_POWER_UNIT, R), Answer::Read(0));
        assert_eq!(a(Vendor::Intel, PKG_ENERGY_STATUS, Some(0)), Answer::Gp);
        // Read 0 but #GP on a write: SYSCFG, PERF_CTL.
        assert_eq!(a(Vendor::Amd, AMD64_SYSCFG, R), Answer::Read(0));
        assert_eq!(a(Vendor::Amd, AMD64_SYSCFG, Some(0)), Answer::Gp);
        assert_eq!(a(Vendor::Intel, IA32_PERF_CTL, Some(0)), Answer::Gp);
        // Write-only: UCODE_WRITE dropped, its read #GP.
        assert_eq!(a(Vendor::Intel, IA32_UCODE_WRITE, Some(1)), Answer::Ignore);
        assert_eq!(a(Vendor::Intel, IA32_UCODE_WRITE, R), Answer::Gp);
        // MMIO_CONF_BASE: 0 taken, anything else #GP.
        assert_eq!(a(Vendor::Amd, FAM10H_MMIO_CONF_BASE, Some(0)), Answer::Ignore);
        assert_eq!(a(Vendor::Amd, FAM10H_MMIO_CONF_BASE, Some(1)), Answer::Gp);
        // VM_HSAVE_PA: Intel's common case reads 0 and drops a write.
        assert_eq!(a(Vendor::Intel, VM_HSAVE_PA, R), Answer::Read(0));
        assert_eq!(a(Vendor::Intel, VM_HSAVE_PA, Some(0x1000)), Answer::Ignore);
        // The Intel PMU, counter-less: P6 counters read 0, the rest #GP.
        assert_eq!(a(Vendor::Intel, P6_PERFCTR0, R), Answer::Read(0));
        assert_eq!(a(Vendor::Intel, P6_EVNTSEL1, Some(0x43_003c)), Answer::Ignore);
        assert_eq!(a(Vendor::Intel, 0xc3, R), Answer::Gp, "PERFCTR2");
        assert_eq!(a(Vendor::Intel, 0x38f, R), Answer::Gp, "PERF_GLOBAL_CTRL");
        assert_eq!(a(Vendor::Intel, K7_PERFCTR0, R), Answer::Read(0), "K7 on Intel: the common case");
    }

    // STATE rows and their checks.
    #[test]
    fn test_state() {
        let g = intel_guest();
        assert_eq!(answer(Vendor::Intel, IA32_POWER_CTL, Some(u64::MAX), &g), Answer::State(StateKey::PowerCtl, Check::Any));
        assert_eq!(answer(Vendor::Intel, IA32_UCODE_REV, R, &g), Answer::State(StateKey::UcodeRev, Check::Read));
        assert_eq!(answer(Vendor::Intel, IA32_UCODE_REV, Some(1), &g), Answer::Ignore);
        assert_eq!(initial(Vendor::Intel, StateKey::UcodeRev), Some(0x1_0000_0000));
        assert_eq!(initial(Vendor::Amd, StateKey::UcodeRev), Some(0x0100_0065));
        assert_eq!(initial(Vendor::Amd, StateKey::KvmPollControl), Some(1));
        // PLATFORM_INFO: the guest reads it, never writes it.
        assert_eq!(answer(Vendor::Amd, PLATFORM_INFO, R, &amd_guest()), Answer::State(StateKey::PlatformInfo, Check::Read));
        assert_eq!(answer(Vendor::Amd, PLATFORM_INFO, Some(0), &amd_guest()), Answer::Gp);
        // MISC_FEATURES_ENABLES: CPUID faulting only with PLATFORM_INFO's bit.
        let Answer::State(_, c) = answer(Vendor::Intel, MISC_FEATURES_ENABLES, Some(1), &g) else { panic!() };
        assert_eq!((takes(c, 1), takes(c, 2)), (Some(1), None));
        let g0 = Guest { platform_info: 0, ..g };
        let Answer::State(_, c) = answer(Vendor::Intel, MISC_FEATURES_ENABLES, Some(1), &g0) else { panic!() };
        assert_eq!(takes(c, 1), None);
        // XSS: only 0 on v6.1; #GP without XSAVES.
        let Answer::State(_, c) = answer(Vendor::Amd, IA32_XSS, Some(0), &amd_guest()) else { panic!() };
        assert_eq!((takes(c, 0), takes(c, 1 << 11)), (Some(0), None));
        assert_eq!(answer(Vendor::Amd, IA32_XSS, R, &Guest { xsaves: false, ..amd_guest() }), Answer::Gp);
        // TSC_AUX: an AMD guest's high half dropped, an Intel guest's #GP.
        let Answer::State(_, c) = answer(Vendor::Amd, TSC_AUX, Some(1 << 40 | 3), &amd_guest()) else { panic!() };
        assert_eq!(takes(c, 1 << 40 | 3), Some(3));
        let Answer::State(_, c) = answer(Vendor::Intel, TSC_AUX, Some(1 << 40), &g) else { panic!() };
        assert_eq!(takes(c, 1 << 40), None);
        assert_eq!(answer(Vendor::Intel, TSC_AUX, R, &Guest { rdtscp: false, rdpid: false, ..g }), Answer::Gp);
        // Intel DEBUGCTL: BTF/LBR dropped quietly, other bits #GP.
        let Answer::State(_, c) = answer(Vendor::Intel, IA32_DEBUGCTL, Some(3), &g) else { panic!() };
        assert_eq!((takes(c, 0b11), takes(c, 1 << 6)), (Some(0), None));
        // AMD DEBUGCTL without LBRV: a nop write, a 0 read.
        assert_eq!(answer(Vendor::Amd, IA32_DEBUGCTL, Some(1), &amd_guest()), Answer::Ignore);
        assert_eq!(answer(Vendor::Amd, LASTBRANCHFROMIP, R, &amd_guest()), Answer::Read(0));
        assert_eq!(answer(Vendor::Amd, LASTBRANCHFROMIP, Some(0), &amd_guest()), Answer::Gp);
        // Intel's LBR-IP MSRs: the common case reads 0, a write #GP.
        assert_eq!(answer(Vendor::Intel, LASTINTTOIP, R, &g), Answer::Read(0));
        assert_eq!(answer(Vendor::Intel, LASTINTTOIP, Some(0), &g), Answer::Gp);
        // VM_HSAVE_PA on AMD: page-aligned and within MAXPHYADDR.
        let Answer::State(_, c) = answer(Vendor::Amd, VM_HSAVE_PA, Some(0x1000), &amd_guest()) else { panic!() };
        assert_eq!((takes(c, 0x1000), takes(c, 0x1008), takes(c, 1 << 50)), (Some(0x1000), None, None));
        // FEAT_CTL (Intel): LOCKED only, with no VMX/SGX in the guest.
        assert_eq!(
            answer(Vendor::Intel, IA32_FEAT_CTL, Some(1), &g),
            Answer::State(StateKey::FeatCtl, Check::Rule(Rule::FeatCtl { valid: 1 }))
        );
        assert_eq!(answer(Vendor::Amd, IA32_FEAT_CTL, R, &amd_guest()), Answer::Gp);
        // KVM's PV MSRs, with no PV CPUID enforcement.
        assert_eq!(answer(Vendor::Amd, KVM_POLL_CONTROL, Some(2), &amd_guest()), Answer::State(StateKey::KvmPollControl, Check::Reserved(!1)));
        assert_eq!(answer(Vendor::Amd, KVM_ASYNC_PF_ACK, R, &amd_guest()), Answer::Read(0));
        assert_eq!(answer(Vendor::Amd, KVM_STEAL_TIME, Some(0x1001), &Guest { host_sched_info: false, ..amd_guest() }), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, 0x4b56_4d08, R, &amd_guest()), Answer::Gp, "MIGRATION_CONTROL: no case");
    }

    // GP rows, by condition.
    #[test]
    fn test_gp() {
        let g = intel_guest();
        assert_eq!(answer(Vendor::Intel, IA32_SMBASE, R, &g), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, SMI_COUNT, Some(0), &g), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, IA32_ARCH_CAPABILITIES, Some(0), &g), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, IA32_ARCH_CAPABILITIES, R, &g), Answer::State(StateKey::ArchCapabilities, Check::Read));
        assert_eq!(answer(Vendor::Amd, IA32_ARCH_CAPABILITIES, R, &amd_guest()), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, IA32_PERF_CAPABILITIES, R, &g), Answer::Gp, "PDCM cleared");
        assert_eq!(answer(Vendor::Intel, IA32_MCG_EXT_CTL, R, &g), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, IA32_RTIT_CTL, R, &g), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, IA32_VMX_BASIC, R, &g), Answer::Gp, "no VMX in the guest");
        assert_eq!(answer(Vendor::Intel, IA32_TSX_CTRL, R, &g), Answer::Gp, "no TSX_CTRL_MSR in ARCH_CAPABILITIES");
        assert_eq!(answer(Vendor::Intel, IA32_PRED_CMD, R, &g), Answer::Gp, "write-only");
        assert_eq!(answer(Vendor::Intel, IA32_PRED_CMD, Some(1), &g), Answer::Delegated(Delegate::Ibpb));
        assert_eq!(answer(Vendor::Intel, IA32_PRED_CMD, Some(0), &g), Answer::Ignore);
        assert_eq!(answer(Vendor::Intel, IA32_PRED_CMD, Some(2), &g), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, IA32_PRED_CMD, Some(0), &Guest { host_ibpb: false, ..amd_guest() }), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, F15H_PERF_CTL0, R, &amd_guest()), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, F15H_PERF_CTR5, Some(0), &amd_guest()), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, IA32_DS_AREA, R, &g), Answer::Gp, "no DS");
        assert_eq!(answer(Vendor::Amd, VM_IGNNE, R, &amd_guest()), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, VM_IGNNE, Some(1), &amd_guest()), Answer::Ignore);
        assert_eq!(answer(Vendor::Amd, AMD64_TSC_RATIO, R, &amd_guest()), Answer::Gp, "no TSCRATEMSR in the guest");
        assert_eq!(answer(Vendor::Intel, AMD64_TSC_RATIO, R, &g), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, F15H_IC_CFG, R, &amd_guest()), Answer::Read(0));
        assert_eq!(answer(Vendor::Amd, F15H_IC_CFG, Some(0), &amd_guest()), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, F15H_IC_CFG, R, &Guest { family_model: Some((0x15, 0x2)), ..amd_guest() }), Answer::Read(0x1e));
        // Unimplemented MTRRs past KVM's 8 variable ranges.
        assert_eq!(answer(Vendor::Intel, 0x210, R, &g), Answer::Gp);
        assert_eq!(answer(Vendor::Intel, 0x20f, R, &g), Answer::Delegated(Delegate::Mtrr));
        // Hyper-V's MSRs without a Hyper-V signature.
        assert_eq!(answer(Vendor::Amd, 0x4000_0000, Some(1), &amd_guest()), Answer::Gp);
        assert_eq!(answer(Vendor::Amd, 0x4000_0000, R, &Guest { hyperv: true, ..amd_guest() }), Answer::Delegated(Delegate::HyperV));
    }

    // DELEGATED rows: the subsystems wick has.
    #[test]
    fn test_delegated() {
        let g = amd_guest();
        let a = |i, w| answer(Vendor::Amd, i, w, &g);
        assert_eq!(a(0x401, Some(0)), Answer::Delegated(Delegate::Mce));
        assert_eq!(a(IA32_MCG_CTL, R), Answer::Delegated(Delegate::Mce));
        assert_eq!(a(K7_HWCR, Some(1 << 18)), Answer::Delegated(Delegate::Mce));
        assert_eq!(a(P5_MC_ADDR, Some(0)), Answer::Delegated(Delegate::Mce), "mce.rs refuses it, as KVM");
        assert_eq!(a(0x832, Some(0)), Answer::Delegated(Delegate::X2Apic));
        assert_eq!(a(IA32_TSC_DEADLINE, R), Answer::Delegated(Delegate::TscDeadline));
        assert_eq!(a(IA32_MISC_ENABLE, Some(1)), Answer::Delegated(Delegate::MiscEnable));
        assert_eq!(a(IA32_TSC, Some(0)), Answer::Delegated(Delegate::Tsc));
        // TSC_ADJUST: read always; a write without the CPUID bit dropped.
        assert_eq!(a(IA32_TSC_ADJUST, R), Answer::Delegated(Delegate::TscAdjust));
        assert_eq!(a(IA32_TSC_ADJUST, Some(5)), Answer::Ignore);
        assert_eq!(answer(Vendor::Amd, IA32_TSC_ADJUST, Some(5), &Guest { tsc_adjust: true, ..g }), Answer::Delegated(Delegate::TscAdjust));
        // kvm-clock: the old pair as well as the new.
        assert_eq!(a(KVM_SYSTEM_TIME, Some(1)), Answer::Delegated(Delegate::KvmClock(KvmClock::SystemTime)));
        assert_eq!(a(KVM_WALL_CLOCK_NEW, R), Answer::Delegated(Delegate::KvmClock(KvmClock::WallClockNew)));
        assert_eq!(a(EFER, R), Answer::Delegated(Delegate::WhpRegister));
        assert_eq!(a(IA32_CR_PAT, Some(0x0007_0406_0007_0406)), Answer::Delegated(Delegate::Mtrr));
    }

    /// RAM at 0x1000..0x9000 only.
    fn ram(gpa: u64, len: u64) -> bool {
        gpa >= 0x1000 && gpa + len <= 0x9000
    }

    // Kept: KVM's values at vCPU creation, but PLATFORM_INFO's CPUID_FAULT.
    #[test]
    fn test_kept_starts_as_kvm() {
        let k = Kept::new(Vendor::Amd, true);
        assert_eq!((k.osvw_length, k.osvw_status, k.ucode_rev, k.poll_control, k.smbase), (4, 0, 0x0100_0065, 1, 0x3_0000));
        assert_eq!(k.platform_info, 0, "no CPUID faulting: bit 31 clear");
        assert_eq!(Kept::new(Vendor::Amd, false).osvw_length, 3);
        assert_eq!(Kept::new(Vendor::Intel, false).ucode_rev, 0x1_0000_0000);
        assert_eq!(k.guest_read(StateKey::PerfCapabilities), Some(0));
        assert_eq!(k.guest_read(StateKey::SpecCtrl), None, "kept nowhere here");
    }

    // The guest's writes, through answer()'s checks.
    #[test]
    fn test_kept_guest_writes() {
        let g = amd_guest();
        let mut k = Kept::new(Vendor::Amd, true);
        let write = |k: &mut Kept, i: u32, data: u64| match answer(Vendor::Amd, i, Some(data), &g) {
            Answer::State(key, check) => k.guest_write(key, check, data, false, &ram),
            other => panic!("{i:#x}: {other:?}"),
        };
        assert_eq!(write(&mut k, AMD64_DE_CFG, 2), Write::Taken);
        assert_eq!(k.de_cfg, 2);
        assert_eq!(write(&mut k, AMD64_DE_CFG, 4), Write::Gp);
        assert_eq!(k.de_cfg, 2);
        assert_eq!(write(&mut k, IA32_POWER_CTL, 0x55), Write::Taken);
        assert_eq!(write(&mut k, KVM_POLL_CONTROL, 0), Write::Taken);
        assert_eq!(write(&mut k, KVM_POLL_CONTROL, 2), Write::Gp);
        // ASYNC_PF_EN: bits 5:4 #GP, nothing kept; enabled with delivery as
        // an interrupt outside RAM: kept, then #GP.
        assert_eq!(write(&mut k, KVM_ASYNC_PF_EN, 0x10), Write::Gp);
        assert_eq!(k.async_pf_en, 0);
        assert_eq!(write(&mut k, KVM_ASYNC_PF_EN, 0x2000 | 0b1001), Write::Taken);
        assert_eq!(write(&mut k, KVM_ASYNC_PF_EN, 0x10_0000 | 0b1001), Write::Gp);
        assert_eq!(k.async_pf_en, 0x10_0000 | 0b1001, "kept before the #GP, as KVM");
        assert_eq!(write(&mut k, KVM_ASYNC_PF_EN, 0x10_0000 | 1), Write::Taken, "not as an interrupt: no RAM check");
        assert_eq!(write(&mut k, KVM_ASYNC_PF_INT, 0xf3), Write::Taken);
        assert_eq!(write(&mut k, KVM_ASYNC_PF_INT, 0x100), Write::Gp);
        // PV EOI: 4-aligned, and in RAM when enabled.
        assert_eq!(write(&mut k, KVM_PV_EOI_EN, 0x2002 | 1), Write::Gp);
        assert_eq!(write(&mut k, KVM_PV_EOI_EN, 0x10_0000 | 1), Write::Gp);
        assert_eq!(write(&mut k, KVM_PV_EOI_EN, 0x10_0000), Write::Taken, "off: no RAM check");
        assert_eq!(write(&mut k, KVM_PV_EOI_EN, 0x2004 | 1), Write::Taken);
        // MISC_FEATURES_ENABLES: CPUID faulting refused, PLATFORM_INFO's bit
        // being clear (Kept::new).
        let g0 = Guest { platform_info: k.platform_info, ..g };
        let Answer::State(key, check) = answer(Vendor::Amd, MISC_FEATURES_ENABLES, Some(1), &g0) else { panic!() };
        assert_eq!(k.guest_write(key, check, 1, false, &ram), Write::Gp);
        // VM_CR: SVM_DIS sticks with LOCK; set while EFER.SVME is, #GP after the change.
        let Answer::State(key, check) = answer(Vendor::Amd, VM_CR, Some(0x18), &g) else { panic!() };
        assert_eq!(k.guest_write(key, check, 0x18, false, &ram), Write::Taken);
        assert_eq!(k.guest_write(key, check, 0x0, false, &ram), Write::Taken);
        assert_eq!(k.vm_cr, 0x18, "LOCK and SVM_DIS keep their value once SVM_DIS is set");
        let mut fresh = Kept::new(Vendor::Amd, true);
        assert_eq!(fresh.guest_write(key, check, 0x10, true, &ram), Write::Gp);
        assert_eq!(fresh.vm_cr, 0x10, "kept before the #GP, as KVM");
        assert_eq!(fresh.guest_write(key, check, 0x20, false, &ram), Write::Gp);
        // A value KVM keeps that has no place here.
        assert_eq!(k.guest_write(StateKey::SpecCtrl, Check::Any, 1, false, &ram), Write::NotKept);
    }

    // KVM_GET_MSRS and KVM_SET_MSRS of Kept's, and the index list.
    #[test]
    fn test_kept_host() {
        let g = amd_guest();
        let mut k = Kept::new(Vendor::Amd, true);
        let set = |k: &mut Kept, i, d| k.host_set(Vendor::Amd, i, d, &g, &ram);
        assert_eq!(set(&mut k, SMI_COUNT, 3), Some(HostSet::Taken));
        assert_eq!(set(&mut k, IA32_SMBASE, 0xa_0000), Some(HostSet::Taken));
        assert_eq!(set(&mut k, PLATFORM_INFO, 0), Some(HostSet::Taken));
        assert!(matches!(set(&mut k, PLATFORM_INFO, PLATFORM_INFO_CPUID_FAULT), Some(HostSet::Unsupported(_))));
        assert_eq!(set(&mut k, MISC_FEATURES_ENABLES, 1), Some(HostSet::Refused));
        assert_eq!(set(&mut k, MISC_FEATURES_ENABLES, 0), Some(HostSet::Taken));
        assert_eq!(set(&mut k, KVM_STEAL_TIME, 0x2000), Some(HostSet::Taken), "off: taken");
        assert!(matches!(set(&mut k, KVM_STEAL_TIME, 0x2001), Some(HostSet::Unsupported(_))));
        assert_eq!(set(&mut k, KVM_STEAL_TIME, 0x2002), Some(HostSet::Refused));
        assert_eq!(set(&mut k, KVM_ASYNC_PF_ACK, 1), Some(HostSet::Taken));
        assert_eq!(set(&mut k, KVM_POLL_CONTROL, 0), Some(HostSet::Taken));
        assert_eq!(set(&mut k, AMD64_DE_CFG, 4), Some(HostSet::Refused));
        assert_eq!(set(&mut k, AMD64_DE_CFG, 0), Some(HostSet::Taken), "a host write may leave the bit clear");
        assert_eq!(set(&mut k, VM_HSAVE_PA, 0x1234), Some(HostSet::Taken));
        assert_eq!(set(&mut k, IA32_FEAT_CTL, 1), None, "Intel's");
        assert_eq!(set(&mut k, IA32_SPEC_CTRL, 1), None, "WHP's register, not Kept's");
        let get = |k: &Kept, i| k.host_get(Vendor::Amd, i, &g);
        assert_eq!((get(&k, SMI_COUNT), get(&k, IA32_SMBASE), get(&k, VM_HSAVE_PA)), (Some(3), Some(0xa_0000), Some(0x1000)));
        assert_eq!((get(&k, KVM_POLL_CONTROL), get(&k, KVM_ASYNC_PF_ACK), get(&k, KVM_STEAL_TIME)), (Some(0), Some(0), Some(0x2000)));
        assert_eq!(get(&k, AMD64_OSVW_ID_LENGTH), Some(4));
        assert_eq!(Kept::new(Vendor::Amd, true).host_get(Vendor::Amd, AMD64_OSVW_ID_LENGTH, &Guest { osvw: false, ..g }), None);
        // Listed: KVM's, but STEAL_TIME; each one KVM_GET_MSRS has.
        let amd: [u32; 12] = core::array::from_fn({
            let mut it = listed(Vendor::Amd);
            move |_| it.next().unwrap()
        });
        assert!(amd.contains(&VM_HSAVE_PA) && !amd.contains(&IA32_FEAT_CTL) && !amd.contains(&KVM_STEAL_TIME));
        assert!(amd.iter().all(|&i| host_has(Vendor::Amd, i, &g)), "{amd:x?}");
        assert!(listed(Vendor::Intel).any(|i| i == IA32_FEAT_CTL));
        assert!(listed(Vendor::Intel).all(|i| host_has(Vendor::Intel, i, &intel_guest())));
        // Intel FEAT_CTL: the host writes the valid bits, LOCKED or not; the
        // guest only while unlocked.
        let gi = intel_guest();
        let mut ki = Kept::new(Vendor::Intel, false);
        assert_eq!(ki.host_set(Vendor::Intel, IA32_FEAT_CTL, 1, &gi, &ram), Some(HostSet::Taken));
        assert_eq!(ki.host_set(Vendor::Intel, IA32_FEAT_CTL, 4, &gi, &ram), Some(HostSet::Refused), "no VMX in the guest");
        let Answer::State(key, check) = answer(Vendor::Intel, IA32_FEAT_CTL, Some(1), &gi) else { panic!() };
        assert_eq!(ki.guest_write(key, check, 1, false, &ram), Write::Gp, "locked");
    }

}
