// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! GIC register state through the KVM device-attribute groups
//! (`KVM_DEV_ARM_VGIC_GRP_DIST_REGS`, `_REDIST_REGS`, `_CPU_SYSREGS`).
//!
//! Distributor registers go straight to `hv_gic_{get,set}_distributor_reg`.
//! Redistributor and CPU interface registers belong to a vCPU, and
//! Hypervisor.framework only lets the thread that owns the vCPU touch them,
//! while KVM lets any thread do so while the vCPUs are stopped. So, per vCPU:
//! - on its owning thread, registers are read and written directly;
//! - when the vCPU stops for its owner (`run()` returning `EINTR`: a pause),
//!   its registers are read into a copy that other threads read while it
//!   stays stopped;
//! - writes from other threads are queued and made by the owner, in order,
//!   before the vCPU next runs (or when it is created);
//! - before the vCPU exists, reads see the last queued write or the value a
//!   new vCPU starts with (read from the first vCPU created, or the values of
//!   current hosts until then);
//! - while the vCPU runs, other threads get `EBUSY`, as with KVM.
//!
//! The registers Hypervisor.framework does not have are those of LPIs, which
//! its GIC does not implement: `GICR_CTLR`, `GICR_STATUSR` and `GICR_WAKER`
//! read as zero and ignore writes (as KVM's `GICR_WAKER`); `GICR_PROPBASER`
//! and `GICR_PENDBASER` keep what is written. `GICD_STATUSR` reads as zero.

use std::collections::HashMap;
use std::thread::ThreadId;

use super::ffi::*;
use super::{Result, err};

/// A per-vCPU GIC register Hypervisor.framework has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CpuReg {
    /// A redistributor register, by offset (the SGI frame at `0x10000`).
    Redist(u32),
    /// A CPU interface register, by system register encoding.
    Icc(u16),
}

/// Redistributor registers (`hv_gic_redistributor_reg_t`), with the value a
/// new vCPU has.
const REDIST: &[(u32, u64)] = &[
    (0x1_0080, 0), // GICR_IGROUPR0
    (0x1_0100, 0), // GICR_ISENABLER0
    (0x1_0180, 0), // GICR_ICENABLER0
    (0x1_0200, 0), // GICR_ISPENDR0
    (0x1_0280, 0), // GICR_ICPENDR0
    (0x1_0300, 0), // GICR_ISACTIVER0
    (0x1_0380, 0), // GICR_ICACTIVER0
    (0x1_0400, 0), // GICR_IPRIORITYR0..7
    (0x1_0404, 0),
    (0x1_0408, 0),
    (0x1_040c, 0),
    (0x1_0410, 0),
    (0x1_0414, 0),
    (0x1_0418, 0),
    (0x1_041c, 0),
    (0x1_0c00, 0), // GICR_ICFGR0
    (0x1_0c04, 0), // GICR_ICFGR1
];

/// CPU interface registers (`hv_gic_icc_reg_t`, system register encodings as
/// in `KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS`), with the value a new vCPU has on
/// current hosts.
const ICC: &[(u16, u64)] = &[
    (0xc230, 0),       // ICC_PMR_EL1
    (0xc643, 2),       // ICC_BPR0_EL1
    (0xc644, 0),       // ICC_AP0R0_EL1
    (0xc648, 0),       // ICC_AP1R0_EL1
    (0xc65b, 0xff),    // ICC_RPR_EL1
    (0xc663, 3),       // ICC_BPR1_EL1
    (0xc664, 0x40400), // ICC_CTLR_EL1
    (0xc665, 7),       // ICC_SRE_EL1
    (0xc666, 0),       // ICC_IGRPEN0_EL1
    (0xc667, 0),       // ICC_IGRPEN1_EL1
];

fn all() -> impl Iterator<Item = (CpuReg, u64)> {
    REDIST
        .iter()
        .map(|&(o, v)| (CpuReg::Redist(o), v))
        .chain(ICC.iter().map(|&(r, v)| (CpuReg::Icc(r), v)))
}

/// Reads a register of `hv`, which belongs to the calling thread.
fn hv_get(hv: hv_vcpu_t, reg: CpuReg) -> Result<u64> {
    let mut v = 0;
    // SAFETY: `hv` belongs to the calling thread; `v` is a valid output.
    check(unsafe {
        match reg {
            CpuReg::Redist(o) => hv_gic_get_redistributor_reg(hv, o, &mut v),
            CpuReg::Icc(r) => hv_gic_get_icc_reg(hv, r, &mut v),
        }
    })?;
    Ok(v)
}

/// Writes a register of `hv`, which belongs to the calling thread.
fn hv_set(hv: hv_vcpu_t, reg: CpuReg, v: u64) -> Result<()> {
    // SAFETY: `hv` belongs to the calling thread.
    check(unsafe {
        match reg {
            CpuReg::Redist(o) => hv_gic_set_redistributor_reg(hv, o, v),
            CpuReg::Icc(r) => hv_gic_set_icc_reg(hv, r, v),
        }
    })
}

/// The per-vCPU GIC state kept for other threads.
#[derive(Debug, Default)]
pub(crate) struct GicCpu {
    /// The thread that owns the Hypervisor.framework vCPU, once created.
    owner: Option<ThreadId>,
    /// The registers, read when the vCPU last stopped for its owner; dropped
    /// when it runs again.
    stopped: Option<HashMap<CpuReg, u64>>,
    /// Writes from other threads, in order, for the owner to make.
    queued: Vec<(CpuReg, u64)>,
    /// `GICR_PROPBASER`, `GICR_PENDBASER`.
    pub(crate) propbaser: u64,
    pub(crate) pendbaser: u64,
}

impl GicCpu {
    /// The calling thread created the vCPU and owns it.
    pub(crate) fn owned(&mut self) {
        self.owner = Some(std::thread::current().id());
    }

    /// The owner created the vCPU `hv` in a VM with a GIC: makes the queued
    /// writes. Returns the values a new vCPU has, read before the writes.
    pub(crate) fn created(&mut self, hv: hv_vcpu_t) -> Result<HashMap<CpuReg, u64>> {
        let reset = all()
            .map(|(reg, _)| hv_get(hv, reg).map(|v| (reg, v)))
            .collect::<Result<HashMap<_, _>>>()?;
        self.flush(hv)?;
        Ok(reset)
    }

    /// The owner is about to run the vCPU: makes the queued writes.
    pub(crate) fn flush(&mut self, hv: hv_vcpu_t) -> Result<()> {
        self.stopped = None;
        for (reg, v) in std::mem::take(&mut self.queued) {
            hv_set(hv, reg, v)?;
        }
        Ok(())
    }

    /// The vCPU stopped for its owner: keeps its registers for other threads.
    pub(crate) fn stop(&mut self, hv: hv_vcpu_t) -> Result<()> {
        self.flush(hv)?;
        let regs = all()
            .map(|(reg, _)| hv_get(hv, reg).map(|v| (reg, v)))
            .collect::<Result<HashMap<_, _>>>()?;
        self.stopped = Some(regs);
        Ok(())
    }

    /// Reads (`write` is `None`) or writes a register.
    ///
    /// * `hv` - the vCPU, if created.
    /// * `running` - whether the vCPU is in `hv_vcpu_run`.
    /// * `reset` - the values a new vCPU has, if known.
    pub(crate) fn access(
        &mut self,
        reg: CpuReg,
        write: Option<u64>,
        hv: Option<hv_vcpu_t>,
        running: bool,
        reset: Option<&HashMap<CpuReg, u64>>,
    ) -> Result<u64> {
        let Some(default) = all().find(|(r, _)| *r == reg).map(|(_, v)| v) else {
            return err(libc::ENXIO);
        };
        let here = self.owner == Some(std::thread::current().id());
        match (hv, write) {
            (Some(hv), None) if here => hv_get(hv, reg),
            (Some(hv), Some(v)) if here => {
                hv_set(hv, reg, v)?;
                if let Some(stopped) = self.stopped.as_mut() {
                    stopped.insert(reg, hv_get(hv, reg)?);
                }
                Ok(v)
            }
            (Some(_), _) if running || self.stopped.is_none() => err(libc::EBUSY),
            (Some(_), None) => Ok(self
                .stopped
                .as_ref()
                .and_then(|s| s.get(&reg).copied())
                .unwrap_or(default)),
            (Some(_), Some(v)) => {
                self.queued.push((reg, v));
                Ok(v)
            }
            (None, None) => Ok(self
                .queued
                .iter()
                .rev()
                .find(|(r, _)| *r == reg)
                .map(|(_, v)| *v)
                .or_else(|| reset.and_then(|r| r.get(&reg).copied()))
                .unwrap_or(default)),
            (None, Some(v)) => {
                self.queued.push((reg, v));
                Ok(v)
            }
        }
    }
}

/// How a `KVM_DEV_ARM_VGIC_GRP_REDIST_REGS` offset is served.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedistReg {
    Hv(CpuReg),
    /// Reads as zero, ignores writes.
    RazWi,
    /// Half (0: low, 1: high) of `GICR_PROPBASER` or `GICR_PENDBASER`.
    PropBase(u32),
    PendBase(u32),
}

pub(crate) fn redist_reg(offset: u64) -> Option<RedistReg> {
    match offset {
        0x0 | 0x10 | 0x14 => Some(RedistReg::RazWi),
        0x70 | 0x74 => Some(RedistReg::PropBase(u32::from(offset == 0x74))),
        0x78 | 0x7c => Some(RedistReg::PendBase(u32::from(offset == 0x7c))),
        _ => {
            let o = u32::try_from(offset).ok()?;
            REDIST
                .iter()
                .any(|(r, _)| *r == o)
                .then_some(RedistReg::Hv(CpuReg::Redist(o)))
        }
    }
}

pub(crate) fn icc_reg(attr: u64) -> Option<CpuReg> {
    // The low 16 bits are the system register encoding.
    let enc = u16::try_from(attr & 0xffff).ok()?;
    ICC.iter()
        .any(|(r, _)| *r == enc)
        .then_some(CpuReg::Icc(enc))
}

/// `GICD_IROUTER<n>`, 64 bits each.
const IROUTER: std::ops::Range<u64> = 0x6000..0x8000;
const GICD_STATUSR: u64 = 0x10;

/// Reads the 32-bit distributor register at `offset`.
pub(crate) fn dist_get(offset: u64) -> Result<u32> {
    if offset == GICD_STATUSR {
        return Ok(0);
    }
    let (reg, shift) = dist_reg(offset)?;
    let mut v = 0;
    // SAFETY: plain call with a valid output.
    check(unsafe { hv_gic_get_distributor_reg(reg, &mut v) })?;
    // Truncation to the 32-bit half addressed.
    #[allow(clippy::cast_possible_truncation)]
    Ok((v >> shift) as u32)
}

/// Writes the 32-bit distributor register at `offset`.
pub(crate) fn dist_set(offset: u64, value: u32) -> Result<()> {
    if offset == GICD_STATUSR {
        return Ok(());
    }
    let (reg, shift) = dist_reg(offset)?;
    let v = if IROUTER.contains(&offset) {
        let mut cur = 0;
        // SAFETY: plain call with a valid output.
        check(unsafe { hv_gic_get_distributor_reg(reg, &mut cur) })?;
        (cur & !(0xffff_ffff << shift)) | (u64::from(value) << shift)
    } else {
        u64::from(value)
    };
    // SAFETY: plain call.
    check(unsafe { hv_gic_set_distributor_reg(reg, v) })
}

/// The Hypervisor.framework register and the bit position of `offset`'s
/// 32-bit half in it.
fn dist_reg(offset: u64) -> Result<(u32, u32)> {
    if !offset.is_multiple_of(4) {
        return err(libc::EINVAL);
    }
    let (base, shift) = if IROUTER.contains(&offset) {
        (offset & !7, if offset & 4 != 0 { 32 } else { 0 })
    } else {
        (offset, 0)
    };
    let reg = u32::try_from(base).map_err(|_| super::Error::new(libc::ENXIO))?;
    Ok((reg, shift))
}

/// Hypervisor.framework resolves `GICD_IROUTER<n>` when it is written: one
/// written before its target vCPU existed (a snapshot being restored, or
/// routing set up before the vCPUs first run) routes its interrupt nowhere,
/// where KVM routes it to the vCPU once it exists. So a new vCPU writes again
/// the routes that name it, and those to any CPU.
pub(crate) fn reroute_spis(affinity: u64) -> Result<()> {
    const IRM: u64 = 1 << 31;
    let (mut base, mut count) = (0u32, 0u32);
    // SAFETY: writes two u32.
    check(unsafe { hv_gic_get_spi_interrupt_range(&mut base, &mut count) })?;
    for intid in base..base + count {
        let reg = 0x6000 + 8 * intid;
        let mut route = 0;
        // SAFETY: plain call with a valid output.
        check(unsafe { hv_gic_get_distributor_reg(reg, &mut route) })?;
        if route & IRM != 0 || packed_affinity(route) == affinity {
            // SAFETY: plain call.
            check(unsafe { hv_gic_set_distributor_reg(reg, route) })?;
        }
    }
    Ok(())
}

/// The affinity of `MPIDR_EL1` as `KVM_DEV_ARM_VGIC_V3_MPIDR` packs it
/// (`Aff3.Aff2.Aff1.Aff0`).
pub(crate) fn packed_affinity(mpidr: u64) -> u64 {
    (mpidr & 0xff_ffff) | ((mpidr >> 32) & 0xff) << 24
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        assert_eq!(redist_reg(0x14), Some(RedistReg::RazWi));
        assert_eq!(redist_reg(0x74), Some(RedistReg::PropBase(1)));
        assert_eq!(redist_reg(0x78), Some(RedistReg::PendBase(0)));
        assert_eq!(
            redist_reg(0x1_0404),
            Some(RedistReg::Hv(CpuReg::Redist(0x1_0404)))
        );
        assert_eq!(redist_reg(0x1_0420), None);
        // ICC_PMR_EL1: op0 3, op1 0, CRn 4, CRm 6, op2 0.
        assert_eq!(icc_reg((5 << 32) | 0xc230), Some(CpuReg::Icc(0xc230)));
        assert_eq!(icc_reg(0xc645), None);
        assert_eq!(dist_reg(0x6104).unwrap(), (0x6100, 32));
        assert_eq!(dist_reg(0x400).unwrap(), (0x400, 0));
        dist_reg(0x401).unwrap_err();
        assert_eq!(
            packed_affinity((1 << 31) | (2 << 32) | 0x030405),
            0x0203_0405
        );
    }

    #[test]
    fn test_access_from_other_threads() {
        let mut gic = GicCpu::default();
        let reg = CpuReg::Icc(0xc230);
        // Before the vCPU exists: writes queue, reads see them or the reset value.
        assert_eq!(gic.access(reg, None, None, false, None).unwrap(), 0);
        gic.access(reg, Some(0xf0), None, false, None).unwrap();
        assert_eq!(gic.access(reg, None, None, false, None).unwrap(), 0xf0);
        assert_eq!(gic.queued.len(), 1);
        // A vCPU owned by another thread, running or not stopped: busy.
        gic.owner = None;
        let e = gic.access(reg, None, Some(1), true, None).unwrap_err();
        assert_eq!(e.errno(), libc::EBUSY);
        let e = gic.access(reg, None, Some(1), false, None).unwrap_err();
        assert_eq!(e.errno(), libc::EBUSY);
        // Stopped: reads see the copy, writes queue.
        gic.stopped = Some(HashMap::from([(reg, 0x80)]));
        assert_eq!(gic.access(reg, None, Some(1), false, None).unwrap(), 0x80);
        gic.access(reg, Some(0x40), Some(1), false, None).unwrap();
        assert_eq!(gic.queued.last(), Some(&(reg, 0x40)));
        // Registers it does not have.
        let e = gic
            .access(CpuReg::Icc(0xc645), None, None, false, None)
            .unwrap_err();
        assert_eq!(e.errno(), libc::ENXIO);
    }
}
