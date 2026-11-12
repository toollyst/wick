// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Guest debugging by user space (`KVM_SET_GUEST_DEBUG`, `KVM_EXIT_DEBUG`),
//! as Linux v6.1's KVM does it on arm64 (arch/arm64/kvm/guest.c
//! `kvm_arch_vcpu_ioctl_set_guest_debug`, debug.c `kvm_arm_setup_debug` and
//! `kvm_arm_clear_debug`, handle_exit.c `kvm_handle_guest_debug`).
//!
//! - The ioctl only stores the request; the vCPU's owner applies it when it
//!   next runs (KVM holds the vCPU mutex during `KVM_RUN`, so its ioctl never
//!   changes a running vCPU either).
//! - While it is on, every debug exception exits to the host
//!   (`hv_vcpu_set_trap_debug_exceptions`, KVM's `MDCR_EL2.TDE`). Measured
//!   (agent-state probe `hvf_debug.c`, macOS 27.2): BRK (EC 0x3C), a
//!   breakpoint (0x30), a software step (0x32) and a watchpoint (0x34) all
//!   exit with it, none without it.
//! - Around each run the guest's MDSCR_EL1 and PSTATE.SS are kept and the
//!   debug bits set (`save_guest_debug_regs`, `restore_guest_debug_regs`):
//!   `SINGLESTEP` sets MDSCR_EL1.SS and PSTATE.SS before every run (after a
//!   step exit PSTATE.SS is clear, and running again then exits at once at
//!   the same PC: the active-pending state, which `ss_active_pending`
//!   tracks as KVM's `DBG_SS_ACTIVE_PENDING`).
//! - `USE_HW`: KVM points the world switch at user space's breakpoints
//!   (`external_debug_state`) and keeps the guest's in `vcpu_debug_state`,
//!   which the guest's trapped accesses (`MDCR_EL2.TDA`) and
//!   `KVM_GET_ONE_REG` reach. Here user space's are written to the
//!   hardware just before each run and the guest's put back right after,
//!   so between runs the hardware always holds the guest's values: a
//!   register read at a stop (a snapshot), a trapped guest access
//!   (`hv_vcpu_set_trap_debug_reg_accesses`) and a PSCI `CPU_ON` reset all
//!   see and change the guest's own, as on KVM.

use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_HW, KVM_GUESTDBG_USE_SW_BP,
    kvm_debug_exit_arch, kvm_guest_debug_arch,
};

use super::exit::EC_WATCHPOINT_LOWER;
use super::ffi::*;
use super::{Result, err};

/// The control flags arm64 KVM takes (`KVM_GUESTDBG_VALID_MASK`).
pub const VALID: u32 = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW;

/// MDSCR_EL1.SS: software step enabled.
pub const MDSCR_SS: u64 = 1;
/// MDSCR_EL1.MDE: breakpoints and watchpoints enabled.
pub const MDSCR_MDE: u64 = 1 << 15;
/// PSTATE.SS (`DBG_SPSR_SS`).
pub const PSTATE_SS: u64 = 1 << 21;
/// MDSCR_EL1's Hypervisor.framework id.
pub const MDSCR_EL1: hv_sys_reg_t = 0x8012;

// Hypervisor.framework's debug calls (hv_vcpu.h, hv_vcpu_config.h; macOS 11).
// The framework is linked by ffi.rs.
unsafe extern "C" {
    fn hv_vcpu_set_trap_debug_exceptions(vcpu: hv_vcpu_t, value: bool) -> hv_return_t;
    fn hv_vcpu_get_trap_debug_reg_accesses(vcpu: hv_vcpu_t, value: *mut bool) -> hv_return_t;
    fn hv_vcpu_set_trap_debug_reg_accesses(vcpu: hv_vcpu_t, value: bool) -> hv_return_t;
    fn hv_vcpu_config_create() -> hv_object_t;
    fn hv_vcpu_config_get_feature_reg(config: hv_object_t, reg: u32, value: *mut u64) -> hv_return_t;
}
/// `HV_FEATURE_REG_ID_AA64DFR0_EL1`, the first of `hv_feature_reg_t`.
const HV_FEATURE_REG_ID_AA64DFR0_EL1: u32 = 0;

/// The host's breakpoints and watchpoints (ID_AA64DFR0_EL1 BRPs + 1 and
/// WRPs + 1, KVM's `get_num_brps`/`get_num_wrps`), read without a VM;
/// `None` if Hypervisor.framework cannot say.
pub fn host_counts() -> Option<(usize, usize)> {
    static COUNTS: std::sync::OnceLock<Option<(usize, usize)>> = std::sync::OnceLock::new();
    *COUNTS.get_or_init(|| {
        // SAFETY: plain calls; the configuration is released after use.
        unsafe {
            let config = hv_vcpu_config_create();
            if config.is_null() {
                return None;
            }
            let mut dfr0 = 0;
            let ret = hv_vcpu_config_get_feature_reg(config, HV_FEATURE_REG_ID_AA64DFR0_EL1, &mut dfr0);
            os_release(config);
            (ret == HV_SUCCESS).then(|| counts(dfr0))
        }
    })
}

/// Breakpoints and watchpoints an ID_AA64DFR0_EL1 value gives.
pub fn counts(dfr0: u64) -> (usize, usize) {
    ((((dfr0 >> 12) & 0xf) + 1) as usize, (((dfr0 >> 20) & 0xf) + 1) as usize)
}

/// DBGBVRn_EL1 (`op2` 4), DBGBCRn_EL1 (5), DBGWVRn_EL1 (6), DBGWCRn_EL1 (7):
/// Hypervisor.framework's ids are the system register encodings
/// (op0 2, op1 0, CRn 0, CRm n).
pub fn dbg_reg(n: usize, op2: u16) -> hv_sys_reg_t {
    0x8000 | (n as u16) << 3 | op2
}

/// The register a trapped guest access to a debug register reaches while
/// user space debugs with `USE_HW` (`hv_vcpu_set_trap_debug_reg_accesses`
/// traps DBGB{V,C}Rn, DBGW{V,C}Rn and MDSCR_EL1): KVM's `trap_bvr`,
/// `trap_bcr`, `trap_wvr`, `trap_wcr` and `trap_debug_regs`. `encoding` is
/// (op0, op1, CRn, CRm, op2).
pub fn trapped_register(encoding: (u64, u64, u64, u64, u64)) -> Option<hv_sys_reg_t> {
    match encoding {
        (2, 0, 0, n, op2 @ 4..=7) => Some(dbg_reg(n as usize, op2 as u16)),
        (2, 0, 0, 2, 2) => Some(MDSCR_EL1),
        _ => None,
    }
}

/// `kvm_run.debug.arch` for a debug exception (`kvm_handle_guest_debug`):
/// the syndrome's two halves, and for a watchpoint the faulting address
/// (measured: the address of the access, the same register KVM reads as
/// `far_el2`).
pub fn exit_arch(esr: u64, virtual_address: u64) -> kvm_debug_exit_arch {
    let watchpoint = (esr >> 26) & 0x3f == EC_WATCHPOINT_LOWER;
    kvm_debug_exit_arch {
        hsr: esr as u32,
        hsr_high: (esr >> 32) as u32,
        far: if watchpoint { virtual_address } else { 0 },
    }
}

/// What user space asked for (`KVM_SET_GUEST_DEBUG`), shared by the vCPU's
/// handles.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestDebug {
    /// `guest_debug`: 0 when off.
    pub control: u32,
    /// `external_debug_state`: user space's breakpoints and watchpoints.
    pub arch: kvm_guest_debug_arch,
    /// Set by a request that turns debugging off, which clears the
    /// active-pending step state (`DBG_SS_ACTIVE_PENDING`); the owner
    /// clears its own when it takes the request.
    pub cleared: bool,
}

impl GuestDebug {
    /// Takes a request as KVM's ioctl does: `EINVAL` for an unknown flag,
    /// with nothing stored.
    pub fn set(&mut self, control: u32, arch: &kvm_guest_debug_arch) -> Result<()> {
        if control & !VALID != 0 {
            return err(libc::EINVAL);
        }
        if control & KVM_GUESTDBG_ENABLE != 0 {
            self.control = control;
            if control & KVM_GUESTDBG_USE_HW != 0 {
                self.arch = *arch;
            }
        } else {
            self.control = 0;
            self.cleared = true;
        }
        Ok(())
    }
}

/// The owner's side: the request it applies, and what it changed.
#[derive(Debug, Default)]
pub struct Owner {
    /// The request in force (taken at each `run()`).
    pub debug: GuestDebug,
    /// `DBG_SS_ACTIVE_PENDING`.
    pub ss_active_pending: bool,
    /// The traps set (debug exceptions, debug register accesses); `None`
    /// while never changed.
    traps: Option<(bool, bool)>,
    /// The debug register trap as the vCPU had it before.
    regs_before: Option<bool>,
}

/// The guest's state kept over one run.
#[derive(Debug)]
pub struct Saved {
    mdscr: u64,
    pstate_ss: bool,
    /// The guest's DBGBVRn, DBGBCRn, DBGWVRn, DBGWCRn while user space's are
    /// in the hardware.
    hw: Option<Box<[[u64; 16]; 4]>>,
}

fn sys(hv: hv_vcpu_t, r: hv_sys_reg_t) -> Result<u64> {
    let mut v = 0;
    // SAFETY: `hv` belongs to the calling thread (the owner).
    check(unsafe { hv_vcpu_get_sys_reg(hv, r, &mut v) })?;
    Ok(v)
}

fn set_sys(hv: hv_vcpu_t, r: hv_sys_reg_t, v: u64) -> Result<()> {
    // SAFETY: as above.
    check(unsafe { hv_vcpu_set_sys_reg(hv, r, v) })
}

fn cpsr(hv: hv_vcpu_t) -> Result<u64> {
    let mut v = 0;
    // SAFETY: as above.
    check(unsafe { hv_vcpu_get_reg(hv, HV_REG_CPSR, &mut v) })?;
    Ok(v)
}

fn set_cpsr(hv: hv_vcpu_t, v: u64) -> Result<()> {
    // SAFETY: as above.
    check(unsafe { hv_vcpu_set_reg(hv, HV_REG_CPSR, v) })
}

impl Owner {
    /// Takes the request in force at a `run()`.
    pub fn take(&mut self, shared: &mut GuestDebug) {
        if std::mem::take(&mut shared.cleared) {
            self.ss_active_pending = false;
        }
        self.debug = *shared;
        self.debug.cleared = false;
    }

    /// Whether user space debugs this vCPU.
    pub fn on(&self) -> bool {
        self.debug.control & KVM_GUESTDBG_ENABLE != 0
    }

    /// Whether user space's breakpoints are in use (`USE_HW`).
    pub fn hw(&self) -> bool {
        self.on() && self.debug.control & KVM_GUESTDBG_USE_HW != 0
    }

    /// Sets the traps (`kvm_arm_setup_mdcr_el2`): debug exceptions while
    /// user space debugs (TDE); debug register accesses while it uses the
    /// hardware (`USE_HW`) or the guest's OS lock is set (TDA), else as the
    /// vCPU had them.
    fn traps(&mut self, hv: hv_vcpu_t, os_lock: bool) -> Result<()> {
        let exceptions = self.on();
        let regs = self.hw() || os_lock;
        if self.traps.is_none() && !exceptions && !regs {
            return Ok(());
        }
        let before = match self.regs_before {
            Some(b) => b,
            None => {
                let mut b = false;
                // SAFETY: `hv` belongs to the calling thread; `b` is written.
                check(unsafe { hv_vcpu_get_trap_debug_reg_accesses(hv, &mut b) })?;
                self.regs_before = Some(b);
                b
            }
        };
        let want = (exceptions, regs || before);
        if self.traps != Some(want) {
            // SAFETY: as above.
            unsafe {
                check(hv_vcpu_set_trap_debug_exceptions(hv, want.0))?;
                check(hv_vcpu_set_trap_debug_reg_accesses(hv, want.1))?;
            }
            self.traps = Some(want);
        }
        Ok(())
    }

    /// Before a run (`kvm_arm_setup_debug`), while user space debugs or the
    /// guest's OS lock (`os_lock`) is set: the OS lock blocks the guest's
    /// own debug exceptions, so MDSCR_EL1.MDE is cleared in the hardware
    /// unless user space uses it (and MDSCR_EL1.SS unless it steps).
    pub fn enter(&mut self, hv: hv_vcpu_t, os_lock: bool) -> Result<Option<Saved>> {
        self.traps(hv, os_lock)?;
        if !self.on() && !os_lock {
            return Ok(None);
        }
        let mdscr = sys(hv, MDSCR_EL1)?;
        let mut pstate = cpsr(hv)?;
        let mut saved = Saved { mdscr, pstate_ss: pstate & PSTATE_SS != 0, hw: None };
        let mut m = mdscr;
        if self.debug.control & KVM_GUESTDBG_SINGLESTEP != 0 {
            if self.ss_active_pending {
                pstate &= !PSTATE_SS;
            } else {
                pstate |= PSTATE_SS;
            }
            set_cpsr(hv, pstate)?;
            m |= MDSCR_SS;
        } else {
            m &= !MDSCR_SS;
        }
        if self.hw() {
            m |= MDSCR_MDE;
            let (brps, wrps) = host_counts().ok_or_else(|| super::Error::new(libc::EIO))?;
            let mut guest = Box::new([[0u64; 16]; 4]);
            let arch = &self.debug.arch;
            let ours = [&arch.dbg_bvr, &arch.dbg_bcr, &arch.dbg_wvr, &arch.dbg_wcr];
            for (i, op2) in (4..=7u16).enumerate() {
                let count = if op2 < 6 { brps } else { wrps };
                for n in 0..count {
                    guest[i][n] = sys(hv, dbg_reg(n, op2))?;
                    set_sys(hv, dbg_reg(n, op2), ours[i][n])?;
                }
            }
            saved.hw = Some(guest);
        } else if os_lock {
            m &= !MDSCR_MDE;
        }
        set_sys(hv, MDSCR_EL1, m)?;
        Ok(Some(saved))
    }

    /// After a run (`kvm_arm_clear_debug`): the guest's values back.
    pub fn leave(&mut self, hv: hv_vcpu_t, saved: Saved) -> Result<()> {
        let mut pstate = cpsr(hv)?;
        if self.debug.control & KVM_GUESTDBG_SINGLESTEP != 0 && pstate & PSTATE_SS == 0 {
            self.ss_active_pending = true;
        }
        set_sys(hv, MDSCR_EL1, saved.mdscr)?;
        pstate = (pstate & !PSTATE_SS) | if saved.pstate_ss { PSTATE_SS } else { 0 };
        set_cpsr(hv, pstate)?;
        if let Some(guest) = saved.hw {
            let (brps, wrps) = host_counts().ok_or_else(|| super::Error::new(libc::EIO))?;
            for (i, op2) in (4..=7u16).enumerate() {
                let count = if op2 < 6 { brps } else { wrps };
                for n in 0..count {
                    set_sys(hv, dbg_reg(n, op2), guest[i][n])?;
                }
            }
        }
        Ok(())
    }
}

/// A stopped vCPU's registers for its other handles (a debugger's): the
/// owner publishes them when it stops (an `EINTR` or a debug exit) and
/// applies the writes others made when it runs again; Hypervisor.framework
/// lets only the owning thread touch the vCPU.
#[derive(Debug, Default)]
pub struct Stopped {
    /// Every register `regs::reg_list` names, as the vCPU stopped (the
    /// counters and the PSCI version are read live instead).
    pub regs: std::collections::HashMap<u64, Vec<u8>>,
    /// Writes made through other handles, in order.
    pub writes: Vec<(u64, Vec<u8>)>,
}

#[cfg(test)]
mod tests {
    use kvm_bindings::{kvm_guest_debug, kvm_userspace_memory_region, kvm_vcpu_init};

    use super::super::exit::{EC_BREAKPOINT_LOWER, EC_BRK64, EC_SOFTWARE_STEP_LOWER};
    use super::*;
    use crate::{Kvm, VcpuExit, VcpuFd, VmFd};

    #[test]
    fn test_debug_exit_arch_splits_the_syndrome() {
        let esr = (EC_WATCHPOINT_LOWER << 26) | (1 << 25) | 0x62 | (0xab << 32);
        let a = exit_arch(esr, 0x4_4018);
        assert_eq!((a.hsr, a.hsr_high, a.far), (esr as u32, 0xab, 0x4_4018));
        // Only a watchpoint has an address.
        let a = exit_arch(EC_BRK64 << 26, 0x1234);
        assert_eq!((a.hsr, a.hsr_high, a.far), ((EC_BRK64 << 26) as u32, 0, 0));
    }

    #[test]
    fn test_trapped_debug_register_accesses_reach_their_registers() {
        // DBGBVR3_EL1 (2,0,0,3,4), DBGWCR0_EL1 (2,0,0,0,7), DBGBCR15_EL1:
        // Hypervisor.framework's ids (hv_vcpu_types.h: DBGBVR0 0x8004,
        // DBGBCR0 0x8005, DBGWVR0 0x8006, DBGWCR0 0x8007, 8 apart).
        assert_eq!(trapped_register((2, 0, 0, 3, 4)), Some(0x801c));
        assert_eq!(trapped_register((2, 0, 0, 0, 7)), Some(0x8007));
        assert_eq!(trapped_register((2, 0, 0, 15, 5)), Some(0x807d));
        assert_eq!(trapped_register((2, 0, 0, 2, 2)), Some(MDSCR_EL1));
        // The OS lock's and others are not these (exit::DebugRegs has them).
        assert_eq!(trapped_register((2, 0, 1, 0, 4)), None);
        assert_eq!(trapped_register((2, 0, 0, 2, 0)), None);
        assert_eq!(trapped_register((3, 0, 0, 0, 4)), None);
    }

    #[test]
    fn test_set_guest_debug_takes_kvms_flags() {
        let mut d = GuestDebug::default();
        let mut arch = kvm_guest_debug_arch::default();
        arch.dbg_bvr[0] = 0x1000;
        // guest.c: any flag outside KVM_GUESTDBG_VALID_MASK is EINVAL,
        // nothing stored.
        for bad in [1 << 2, 1 << 3, 1 << 20, KVM_GUESTDBG_ENABLE | 1 << 31] {
            assert_eq!(d.set(bad, &arch).unwrap_err().errno(), libc::EINVAL, "{bad:#x}");
            assert_eq!(d.control, 0);
        }
        d.set(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP, &arch).unwrap();
        // The breakpoints are taken only with USE_HW.
        assert_eq!((d.control, d.arch.dbg_bvr[0]), (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP, 0));
        d.set(KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW, &arch).unwrap();
        assert_eq!(d.arch.dbg_bvr[0], 0x1000);
        // Without ENABLE everything is off, whatever else is set.
        d.set(KVM_GUESTDBG_SINGLESTEP, &arch).unwrap();
        assert_eq!((d.control, d.cleared), (0, true));
    }

    // --- Guests (Hypervisor.framework; one VM per test process). ---

    const PC: u64 = 0x6030_0000_0010_0040;
    const PSTATE: u64 = 0x6030_0000_0010_0042;
    const GUEST_BASE: u64 = 0x8000_0000;
    /// No slot covers it: a store to it exits as MMIO, the guest's report.
    const MMIO: u64 = 0x1000_0000;
    /// The guest's vectors (VBAR_EL1), 2 KiB in.
    const VECTORS: u64 = GUEST_BASE + 0x800;
    /// Data the watchpoint test writes, 4 KiB in.
    const DATA: u64 = GUEST_BASE + 0x1000;

    const NOP: u32 = 0xd503_201f;
    const BRK0: u32 = 0xd420_0000;
    const ADD_X0_1: u32 = 0x9100_0400;
    const STR_X0_X4: u32 = 0xf900_0080;
    const STR_X3_X5: u32 = 0xf900_00a3;
    const B_SELF: u32 = 0x1400_0000;
    /// mrs x0, ESR_EL1 (3, 0, 5, 2, 0).
    const MRS_X0_ESR: u32 = 0xd538_5200;
    /// msr DBGBVR0_EL1, x1 (2, 0, 0, 0, 4).
    const MSR_DBGBVR0_X1: u32 = 0xd510_0081;
    /// mrs x0, DBGBVR0_EL1.
    const MRS_X0_DBGBVR0: u32 = 0xd530_0080;
    /// mrs x0, MDSCR_EL1 (2, 0, 0, 2, 2).
    const MRS_X0_MDSCR: u32 = 0xd530_0240;

    /// msr DBGBCR0_EL1, x2 (2, 0, 0, 0, 5).
    const MSR_DBGBCR0_X2: u32 = 0xd510_00a2;
    /// msr MDSCR_EL1, x3.
    const MSR_MDSCR_X3: u32 = 0xd510_0243;
    /// msr OSLAR_EL1, x5 (2, 0, 1, 0, 4).
    const MSR_OSLAR_X5: u32 = 0xd510_1085;
    /// msr DAIFClr, #8: debug exceptions unmasked.
    const MSR_DAIFCLR_D: u32 = 0xd503_48ff;
    const ISB: u32 = 0xd503_3fdf;

    /// msr DBGBVR1_EL1, x1 (2, 0, 0, 1, 4).
    const MSR_DBGBVR1_X1: u32 = 0xd510_0181;
    /// mrs x0, DBGBVR1_EL1.
    const MRS_X0_DBGBVR1: u32 = 0xd530_0180;

    /// DBGBCR as Firecracker's gdb stub writes it (gdb/arch/aarch64.rs
    /// `set_kvm_debug`): enabled, EL1 and EL0, all four bytes.
    const BCR: u64 = 0b1 | (0b11 << 1) | (0b1111 << 5);
    /// DBGWCR: enabled, EL1 and EL0 (PAC 0b11), stores (LSC 0b10), all eight
    /// bytes (BAS 0xff).
    const WCR: u64 = 0b1 | (0b11 << 1) | (0b10 << 3) | (0xff << 5);

    fn x_reg(n: u64) -> u64 {
        0x6030_0000_0010_0000 + 2 * n
    }

    fn sys_id(r: hv_sys_reg_t) -> u64 {
        super::super::regs::sys_id(r)
    }

    /// A VM with 1 MiB at [`GUEST_BASE`] holding `code`, `vectors` at
    /// [`VECTORS`] (VBAR_EL1), and an initialised vCPU at the code, EL1h
    /// with DAIF masked, X4 = [`MMIO`].
    fn guest(code: &[u32], vectors: &[u32]) -> (VmFd, VcpuFd) {
        let vm = Kvm::new().unwrap().create_vm().unwrap();
        let len = 1usize << 20;
        // SAFETY: a fresh anonymous mapping, kept for the test.
        let mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mem, libc::MAP_FAILED);
        // SAFETY: both within the first 4 KiB of the mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), mem.cast::<u32>(), code.len());
            std::ptr::copy_nonoverlapping(vectors.as_ptr(), mem.cast::<u32>().add(0x800 / 4), vectors.len());
        }
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
        for (id, v) in [(PC, GUEST_BASE), (PSTATE, 0x3c5), (x_reg(4), MMIO), (sys_id(0xc600), VECTORS)] {
            vcpu.set_one_reg(id, &v.to_le_bytes()).unwrap();
        }
        (vm, vcpu)
    }

    fn get(v: &VcpuFd, id: u64) -> u64 {
        let mut buf = [0u8; 8];
        v.get_one_reg(id, &mut buf).unwrap();
        u64::from_le_bytes(buf)
    }

    fn set(v: &VcpuFd, id: u64, value: u64) {
        v.set_one_reg(id, &value.to_le_bytes()).unwrap();
    }

    fn debug(v: &VcpuFd, control: u32, arch: kvm_guest_debug_arch) {
        v.set_guest_debug(&kvm_guest_debug { control, pad: 0, arch }).unwrap();
    }

    /// The exception class of a debug exit, else a panic with the exit.
    fn debug_exit(v: &mut VcpuFd) -> (u64, kvm_debug_exit_arch) {
        match v.run().unwrap() {
            VcpuExit::Debug(arch) => ((u64::from(arch.hsr) >> 26) & 0x3f, arch),
            other => panic!("{other:?}"),
        }
    }

    /// The value the guest stores to [`MMIO`], else a panic with the exit.
    fn reported(v: &mut VcpuFd) -> u64 {
        match v.run().unwrap() {
            VcpuExit::MmioWrite(MMIO, data) => u64::from_le_bytes(data.try_into().unwrap()),
            other => panic!("{other:?}"),
        }
    }

    /// A handle of `v` made as Firecracker's gdb stub makes its own
    /// (`copy_kvm_vcpu_fd`: a `dup` of the descriptor).
    fn dup_handle(vm: &VmFd, v: &VcpuFd) -> VcpuFd {
        // SAFETY: a new descriptor, owned by the returned handle.
        unsafe { vm.create_vcpu_from_rawfd(libc::dup(std::os::unix::io::AsRawFd::as_raw_fd(v))).unwrap() }
    }

    /// Vectors whose current-EL synchronous entry (SP_ELx, 0x200) reports
    /// ESR_EL1: the guest took the exception itself.
    fn reporting_vectors() -> Vec<u32> {
        let mut v = vec![B_SELF; 0x200 / 4];
        v.extend([MRS_X0_ESR, STR_X0_X4, B_SELF]);
        v
    }

    #[test]
    fn test_brk_exits_as_kvm_debug_with_guest_debugging() {
        let (_vm, mut vcpu) = guest(&[NOP, BRK0, STR_X0_X4, B_SELF], &[]);
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP, Default::default());
        let (ec, arch) = debug_exit(&mut vcpu);
        assert_eq!((ec, arch.far), (EC_BRK64, 0));
        // As KVM: the PC at the BRK, which user space steps over.
        assert_eq!(get(&vcpu, PC), GUEST_BASE + 4);
        set(&vcpu, PC, GUEST_BASE + 8);
        set(&vcpu, x_reg(0), 7);
        assert_eq!(reported(&mut vcpu), 7);
    }

    #[test]
    fn test_brk_is_the_guests_without_guest_debugging() {
        // No guest debugging: the guest's own vector takes the BRK (ESR_EL1
        // EC 0x3c), as on KVM without guest_debug (no TDE).
        let (_vm, mut vcpu) = guest(&[BRK0, B_SELF], &reporting_vectors());
        assert_eq!(reported(&mut vcpu) >> 26, EC_BRK64);
        // And after debugging was on and is off again.
        let (_vm, mut vcpu) = (_vm, vcpu);
        set(&vcpu, PC, GUEST_BASE);
        set(&vcpu, PSTATE, 0x3c5);
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP, Default::default());
        assert_eq!(debug_exit(&mut vcpu).0, EC_BRK64);
        debug(&vcpu, 0, Default::default());
        assert_eq!(reported(&mut vcpu) >> 26, EC_BRK64);
    }

    #[test]
    fn test_set_guest_debug_rejects_unknown_flags() {
        let (_vm, mut vcpu) = guest(&[BRK0, B_SELF], &reporting_vectors());
        let bad = kvm_guest_debug { control: KVM_GUESTDBG_ENABLE | (1 << 3), ..Default::default() };
        assert_eq!(vcpu.set_guest_debug(&bad).unwrap_err().errno(), libc::EINVAL);
        // Nothing stored: the guest takes its BRK.
        assert_eq!(reported(&mut vcpu) >> 26, EC_BRK64);
    }

    #[test]
    fn test_hw_breakpoint_exits_at_its_address() {
        let (_vm, mut vcpu) = guest(&[ADD_X0_1, ADD_X0_1, NOP, STR_X0_X4, B_SELF], &[]);
        let mut arch = kvm_guest_debug_arch::default();
        arch.dbg_bvr[0] = GUEST_BASE + 8;
        arch.dbg_bcr[0] = BCR;
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW | KVM_GUESTDBG_USE_SW_BP, arch);
        assert_eq!(debug_exit(&mut vcpu).0, EC_BREAKPOINT_LOWER);
        // Stopped before the third instruction; the first two ran.
        assert_eq!((get(&vcpu, PC), get(&vcpu, x_reg(0))), (GUEST_BASE + 8, 2));
        debug(&vcpu, 0, Default::default());
        assert_eq!(reported(&mut vcpu), 2);
    }

    #[test]
    fn test_single_step_exits_after_one_instruction() {
        let (_vm, mut vcpu) = guest(&[ADD_X0_1, ADD_X0_1, ADD_X0_1, STR_X0_X4, B_SELF], &[]);
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP, Default::default());
        for i in 1..=3u64 {
            assert_eq!(debug_exit(&mut vcpu).0, EC_SOFTWARE_STEP_LOWER);
            assert_eq!((get(&vcpu, PC), get(&vcpu, x_reg(0))), (GUEST_BASE + 4 * i, i));
            // The guest's PSTATE.SS, not the step's.
            assert_eq!(get(&vcpu, PSTATE) & PSTATE_SS, 0);
        }
        debug(&vcpu, 0, Default::default());
        assert_eq!(reported(&mut vcpu), 3);
    }

    #[test]
    fn test_watchpoint_exit_gives_the_address() {
        let (_vm, mut vcpu) = guest(&[NOP, STR_X3_X5, STR_X0_X4, B_SELF], &[]);
        set(&vcpu, x_reg(3), 0x1122_3344_5566_7788);
        set(&vcpu, x_reg(5), DATA + 0x18);
        let mut arch = kvm_guest_debug_arch::default();
        arch.dbg_wvr[0] = DATA + 0x18;
        arch.dbg_wcr[0] = WCR;
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW, arch);
        let (ec, exit) = debug_exit(&mut vcpu);
        assert_eq!((ec, exit.far, get(&vcpu, PC)), (EC_WATCHPOINT_LOWER, DATA + 0x18, GUEST_BASE + 4));
    }

    #[test]
    fn test_guest_debug_registers_stay_the_guests() {
        // The guest writes its own DBGBVR0, user space has its breakpoint in
        // the same register: at the stop, a read (a snapshot's) gives the
        // guest's value and the guest's MDSCR_EL1 (no MDE); the guest's
        // trapped read gives its own value too; user space's breakpoint
        // fires all the same.
        const GUEST_VALUE: u64 = 0x1234_5000;
        let (vm, mut vcpu) =
            guest(&[MSR_DBGBVR0_X1, NOP, MRS_X0_DBGBVR0, STR_X0_X4, MRS_X0_MDSCR, STR_X0_X4, B_SELF], &[]);
        set(&vcpu, x_reg(1), GUEST_VALUE);
        let mut arch = kvm_guest_debug_arch::default();
        arch.dbg_bvr[0] = GUEST_BASE + 4;
        arch.dbg_bcr[0] = BCR;
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW, arch);
        assert_eq!(debug_exit(&mut vcpu).0, EC_BREAKPOINT_LOWER);
        assert_eq!(get(&vcpu, PC), GUEST_BASE + 4);
        let dbgbvr0 = sys_id(dbg_reg(0, 4));
        let mdscr = sys_id(MDSCR_EL1);
        assert_eq!((get(&vcpu, dbgbvr0), get(&vcpu, mdscr) & MDSCR_MDE), (GUEST_VALUE, 0));
        // From another handle (the gdb stub's), the same.
        let other = dup_handle(&vm, &vcpu);
        assert_eq!(get(&other, mdscr) & MDSCR_MDE, 0);
        // User space moves its breakpoint away: the guest's reads trap
        // (USE_HW) and see its own values.
        arch.dbg_bvr[0] = GUEST_BASE + 0x400;
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW, arch);
        assert_eq!(reported(&mut vcpu), GUEST_VALUE);
        assert_eq!(reported(&mut vcpu) & MDSCR_MDE, 0);
    }

    #[test]
    fn test_a_stopped_vcpu_reads_and_writes_from_a_dup_handle() {
        let (vm, mut vcpu) = guest(&[BRK0, STR_X0_X4, B_SELF], &[]);
        set(&vcpu, x_reg(1), 0x55);
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP, Default::default());
        assert_eq!(debug_exit(&mut vcpu).0, EC_BRK64);
        let other = dup_handle(&vm, &vcpu);
        assert_eq!((get(&other, PC), get(&other, x_reg(1)), get(&other, PSTATE)), (GUEST_BASE, 0x55, 0x3c5));
        // TCR_EL1 and TTBR1_EL1, which the stub's page walk reads.
        get(&other, sys_id(0xc102));
        get(&other, sys_id(0xc101));
        // Writes: read back at once, applied by the owner at its next run.
        set(&other, PC, GUEST_BASE + 4);
        set(&other, x_reg(0), 7);
        assert_eq!((get(&other, PC), get(&other, x_reg(0))), (GUEST_BASE + 4, 7));
        // The owner sees them too, before it runs.
        assert_eq!(get(&vcpu, x_reg(0)), 7);
        other.set_guest_debug(&kvm_guest_debug::default()).unwrap();
        assert_eq!(reported(&mut vcpu), 7);
        // After an EINTR stop as well.
        vcpu.set_kvm_immediate_exit(1);
        assert_eq!(vcpu.run().unwrap_err().errno(), libc::EINTR);
        vcpu.set_kvm_immediate_exit(0);
        assert_eq!(get(&other, PC), GUEST_BASE + 8);
    }

    #[test]
    fn test_a_running_vcpu_is_busy_for_a_dup_handle() {
        let (vm, mut vcpu) = guest(&[B_SELF], &[]);
        let mut other = dup_handle(&vm, &vcpu);
        let runner = std::thread::spawn(move || {
            let r = vcpu.run().map(|_| ()).map_err(|e| e.errno());
            vcpu.set_kvm_immediate_exit(0);
            (vcpu, r)
        });
        // Created and running: EBUSY for reads and writes, until it stops.
        let mut buf = [0u8; 8];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match other.get_one_reg(PC, &mut buf) {
                Err(e) if e.errno() == libc::EBUSY => break,
                _ => assert!(std::time::Instant::now() < deadline, "never busy"),
            }
        }
        assert_eq!(other.set_one_reg(PC, &0u64.to_le_bytes()).unwrap_err().errno(), libc::EBUSY);
        other.set_kvm_immediate_exit(1);
        let (vcpu, r) = runner.join().unwrap();
        assert_eq!(r, Err(libc::EINTR));
        assert_eq!(get(&other, PC), GUEST_BASE);
        drop(vcpu);
    }

    #[test]
    fn test_set_guest_debug_from_a_dup_handle_applies_at_the_next_run() {
        let (vm, mut vcpu) = guest(&[NOP, BRK0, B_SELF], &reporting_vectors());
        vcpu.set_kvm_immediate_exit(1);
        assert_eq!(vcpu.run().unwrap_err().errno(), libc::EINTR);
        vcpu.set_kvm_immediate_exit(0);
        let other = dup_handle(&vm, &vcpu);
        debug(&other, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP, Default::default());
        assert_eq!(debug_exit(&mut vcpu).0, EC_BRK64);
        assert_eq!(get(&other, PC), GUEST_BASE + 4);
    }

    #[test]
    fn test_guest_debug_before_the_vcpu_exists() {
        // Firecracker's vCPU 0 is paused at the entry point before its first
        // run (gdb/target.rs): the request made then is honoured by it.
        let (_vm, mut vcpu) = guest(&[ADD_X0_1, ADD_X0_1, B_SELF], &[]);
        debug(&vcpu, KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP, Default::default());
        assert_eq!(debug_exit(&mut vcpu).0, EC_SOFTWARE_STEP_LOWER);
        assert_eq!(get(&vcpu, PC), GUEST_BASE + 4);
    }

    #[test]
    fn test_the_guests_os_lock_blocks_its_own_breakpoints() {
        // KVM clears MDSCR_EL1.MDE in the hardware while the guest's OS lock
        // is set, with or without user space debugging (debug.c
        // kvm_arm_setup_debug: "The OS Lock blocks debug exceptions in all
        // ELs when it is enabled"), and traps its debug register accesses
        // then (kvm_arm_setup_mdcr_el2), so it reads back its own MDSCR_EL1.
        // The guest sets its own EL1 breakpoint on the NOP (MDE and KDE, D
        // unmasked), then the OS lock: nothing fires, and it reports its
        // MDSCR_EL1 with MDE. Again with the lock released: its breakpoint
        // fires into its own vector (ESR_EL1 EC 0x31).
        const MDE_KDE: u64 = MDSCR_MDE | (1 << 13);
        const NOP_AT: u64 = GUEST_BASE + 6 * 4;
        let (_vm, mut vcpu) = guest(
            &[MSR_DBGBVR0_X1, MSR_DBGBCR0_X2, MSR_MDSCR_X3, MSR_OSLAR_X5, MSR_DAIFCLR_D, ISB, NOP, MRS_X0_MDSCR,
                STR_X0_X4, B_SELF],
            &reporting_vectors(),
        );
        for (id, v) in [(x_reg(1), NOP_AT), (x_reg(2), BCR), (x_reg(3), MDE_KDE), (x_reg(5), 1)] {
            set(&vcpu, id, v);
        }
        assert_eq!(reported(&mut vcpu), MDE_KDE);
        for (id, v) in [(PC, GUEST_BASE), (PSTATE, 0x3c5), (x_reg(5), 0)] {
            set(&vcpu, id, v);
        }
        assert_eq!(reported(&mut vcpu) >> 26, 0x31);
    }

    #[test]
    fn test_debug_registers_are_listed_and_restored_as_kvms() {
        // KVM_GET_REG_LIST lists DBGB{V,C}R0-15 and DBGW{V,C}R0-15 whatever
        // the host has (sys_regs.c DBG_BCR_BVR_WCR_WVR_EL1(0..15)), reset to
        // 0, and keeps each one's value (get_bvr/set_bvr), so a snapshot
        // carries the guest's own and a restore gives them back.
        let (_vm, mut vcpu) = guest(&[MSR_DBGBVR1_X1, STR_X0_X4, MRS_X0_DBGBVR1, STR_X0_X4, B_SELF], &[]);
        let mut list = kvm_bindings::RegList::new(500).unwrap();
        vcpu.get_reg_list(&mut list).unwrap();
        let ids: Vec<u64> = (0..16).flat_map(|n| (4..=7).map(move |op2| sys_id(dbg_reg(n, op2)))).collect();
        for id in &ids {
            assert!(list.as_slice().contains(id), "{id:#x} not listed");
            assert_eq!(get(&vcpu, *id), 0, "{id:#x} not reset to 0");
        }
        // Above the host's count too (KVM keeps all 16).
        let last = sys_id(dbg_reg(15, 6));
        set(&vcpu, last, 0x1234_5000);
        assert_eq!(get(&vcpu, last), 0x1234_5000);
        // The guest writes its own DBGBVR1; a snapshot of every listed
        // register is taken; the register is changed, the snapshot
        // restored, and the guest reads its own value back.
        set(&vcpu, x_reg(1), 0xffff_8000_0812_3400);
        reported(&mut vcpu);
        let snapshot: Vec<(u64, Vec<u8>)> = list
            .as_slice()
            .iter()
            .map(|id| {
                let mut buf = vec![0u8; super::super::regs::reg_size(*id)];
                vcpu.get_one_reg(*id, &mut buf).unwrap();
                (*id, buf)
            })
            .collect();
        let bvr1 = sys_id(dbg_reg(1, 4));
        set(&vcpu, bvr1, 0);
        set(&vcpu, last, 0);
        for (id, value) in &snapshot {
            vcpu.set_one_reg(*id, value).unwrap_or_else(|e| panic!("{id:#x}: {e}"));
        }
        assert_eq!((get(&vcpu, bvr1), get(&vcpu, last)), (0xffff_8000_0812_3400, 0x1234_5000));
        assert_eq!(reported(&mut vcpu), 0xffff_8000_0812_3400);
    }

    #[test]
    fn test_debug_capabilities_answer_as_kvms() {
        use crate::Cap;
        // Without a VM, as KVM answers them from the host.
        let kvm = Kvm::new().unwrap();
        assert_eq!(kvm.check_extension_int(Cap::SetGuestDebug), 1);
        let (brps, wrps) = host_counts().map_or((0, 0), |(b, w)| (b as i32, w as i32));
        assert_eq!(kvm.check_extension_int(Cap::DebugHwBps), brps);
        assert_eq!(kvm.check_extension_int(Cap::DebugHwWps), wrps);
        // Where Hypervisor.framework runs (kern.hv_support), it gives the
        // counts: Arm requires at least 2 of each (ID_AA64DFR0_EL1.BRPs,
        // WRPs). Where it does not, as on GitHub's runners, there is no VM
        // to debug, as Linux without KVM.
        if hv_support() {
            assert!(brps >= 2 && wrps >= 2, "{brps} {wrps}");
        }
    }

    /// `kern.hv_support`: whether this host runs Hypervisor.framework VMs.
    fn hv_support() -> bool {
        let mut v: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: a NUL-terminated name and an int-sized output.
        let r = unsafe {
            libc::sysctlbyname(c"kern.hv_support".as_ptr(), (&raw mut v).cast(), &mut len, std::ptr::null_mut(), 0)
        };
        r == 0 && v == 1
    }

    #[test]
    fn test_debug_capabilities_are_a_vcpus_counts() {
        use crate::Cap;
        let kvm = Kvm::new().unwrap();
        // The counts a vCPU's ID_AA64DFR0_EL1 gives.
        let (_vm, vcpu) = guest(&[B_SELF], &[]);
        let (brps, wrps) = counts(get(&vcpu, sys_id(HV_SYS_REG_ID_AA64DFR0_EL1)));
        assert_eq!(kvm.check_extension_int(Cap::DebugHwBps), brps as i32);
        assert_eq!(kvm.check_extension_int(Cap::DebugHwWps), wrps as i32);
    }
}
