// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! In-kernel devices: GICv3, backed by `hv_gic_*`.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Weak;

use kvm_bindings::{
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
    KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
    KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES,
    KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST, kvm_device_attr,
};

use super::ffi::*;
use super::gic::{self, RedistReg};
use super::vcpu::VcpuShared;
use super::vm::VmInner;
use super::{Handle, Result, err};

/// `KVM_DEV_ARM_VGIC_GRP_ADDR` type of the GICv2m-style MSI frame (a
/// `u64` guest address). Hypervisor.framework's GIC has no ITS; MSIs go
/// through this frame instead. Not a KVM value: KVM's GICv3 rejects it
/// (`ENXIO`), which is how a VMM tells the two apart.
pub const KVM_VGIC_V3_ADDR_TYPE_MSI_FRAME: u64 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceKind {
    Gic,
}

/// Wrapper over a device created with `VmFd::create_device`.
#[derive(Debug)]
pub struct DeviceFd {
    kind: DeviceKind,
    vm: Weak<VmInner>,
    fd: Handle,
}

impl DeviceFd {
    pub(crate) fn new(kind: DeviceKind, vm: Weak<VmInner>) -> Result<Self> {
        Ok(DeviceFd {
            kind,
            vm,
            fd: Handle::new()?,
        })
    }

    fn supported(&self, attr: &kvm_device_attr) -> bool {
        match (self.kind, attr.group) {
            (DeviceKind::Gic, KVM_DEV_ARM_VGIC_GRP_ADDR) => {
                attr.attr == u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST)
                    || attr.attr == u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST)
                    || attr.attr == KVM_VGIC_V3_ADDR_TYPE_MSI_FRAME
            }
            (DeviceKind::Gic, KVM_DEV_ARM_VGIC_GRP_NR_IRQS) => true,
            (DeviceKind::Gic, KVM_DEV_ARM_VGIC_GRP_DIST_REGS) => true,
            (DeviceKind::Gic, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS) => true,
            (DeviceKind::Gic, KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS) => true,
            (_, KVM_DEV_ARM_VGIC_GRP_CTRL) => {
                attr.attr == u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT)
                    || attr.attr == u64::from(KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES)
            }
            _ => false,
        }
    }

    /// Tests whether the device supports an attribute.
    pub fn has_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        if self.supported(device_attr) {
            Ok(())
        } else {
            err(libc::ENXIO)
        }
    }

    /// Sets a device attribute.
    ///
    /// For the GIC: the distributor, redistributor and MSI frame
    /// ([`KVM_VGIC_V3_ADDR_TYPE_MSI_FRAME`]) addresses, the number of
    /// interrupts (the SPIs above them are given to the MSI frame),
    /// `CTRL_INIT`, which creates the Hypervisor.framework GIC,
    /// register state (see [`gic`]), and `SAVE_PENDING_TABLES`, which has
    /// nothing to write: the GIC has no LPIs.
    /// The redistributor region must have the size Hypervisor.framework wants
    /// (`hv_gic_get_redistributor_region_size`, 32 MiB on current hosts), so it
    /// must not overlap the distributor.
    pub fn set_device_attr(&self, device_attr: &kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        if !self.supported(device_attr) {
            return err(libc::ENXIO);
        }
        let Some(vm) = self.vm.upgrade() else {
            return err(libc::ENODEV);
        };
        if let Some(result) = self.reg_access(&vm, device_attr, true) {
            return result;
        }
        let mut gic = vm.gic.lock().unwrap();
        match device_attr.group {
            KVM_DEV_ARM_VGIC_GRP_ADDR => {
                if gic.created {
                    return err(libc::EBUSY);
                }
                // SAFETY: KVM's contract: `addr` points to a u64 holding the address.
                let addr = unsafe { std::ptr::read_unaligned(device_attr.addr as *const u64) };
                if device_attr.attr == u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST) {
                    gic.dist = Some(addr);
                } else if device_attr.attr == u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST) {
                    gic.redist = Some(addr);
                } else {
                    let mut align = 0usize;
                    // SAFETY: writes one usize.
                    check(unsafe { hv_gic_get_msi_region_base_alignment(&mut align) })?;
                    if align == 0 || addr % align as u64 != 0 {
                        return err(libc::EINVAL);
                    }
                    gic.msi_frame = Some(addr);
                }
                Ok(())
            }
            KVM_DEV_ARM_VGIC_GRP_NR_IRQS => {
                // SAFETY: KVM's contract: `addr` points to a u32.
                let nr = unsafe { std::ptr::read_unaligned(device_attr.addr as *const u32) };
                let (mut base, mut count) = (0u32, 0u32);
                // SAFETY: writes two u32.
                check(unsafe { hv_gic_get_spi_interrupt_range(&mut base, &mut count) })?;
                if nr < 64 || nr > base + count {
                    return err(libc::EINVAL);
                }
                gic.nr_irqs = Some(nr);
                Ok(())
            }
            KVM_DEV_ARM_VGIC_GRP_CTRL
                if device_attr.attr == u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT) =>
            {
                if gic.created {
                    return err(libc::EBUSY);
                }
                let (Some(dist), Some(redist)) = (gic.dist, gic.redist) else {
                    return err(libc::ENXIO);
                };
                let msi = match gic.msi_frame {
                    Some(frame) => Some((frame, msi_spis(gic.nr_irqs)?)),
                    None => None,
                };
                // SAFETY: the config object is created, used and released here.
                unsafe {
                    let config = hv_gic_config_create();
                    if config.is_null() {
                        return err(libc::ENOMEM);
                    }
                    let mut ret = hv_gic_config_set_distributor_base(config, dist);
                    if ret == HV_SUCCESS {
                        ret = hv_gic_config_set_redistributor_base(config, redist);
                    }
                    if let Some((frame, (first, count))) = msi
                        && ret == HV_SUCCESS
                    {
                        ret = hv_gic_config_set_msi_region_base(config, frame);
                        if ret == HV_SUCCESS {
                            ret = hv_gic_config_set_msi_interrupt_range(config, first, count);
                        }
                    }
                    if ret == HV_SUCCESS {
                        ret = hv_gic_create(config);
                    }
                    os_release(config);
                    check(ret)?;
                }
                gic.created = true;
                Ok(())
            }
            KVM_DEV_ARM_VGIC_GRP_CTRL => {
                if !gic.created {
                    return err(libc::ENXIO);
                }
                Ok(())
            }
            _ => err(libc::ENXIO),
        }
    }

    /// Reads a device attribute: GIC register state (see [`gic`]).
    ///
    /// # Safety
    /// Same contract as `kvm_ioctls::DeviceFd::get_device_attr`.
    pub unsafe fn get_device_attr(&self, device_attr: &mut kvm_device_attr) -> Result<()> {
        self.fd.check()?;
        let Some(vm) = self.vm.upgrade() else {
            return err(libc::ENODEV);
        };
        self.reg_access(&vm, device_attr, false)
            .unwrap_or_else(|| err(libc::ENXIO))
    }

    /// Serves the register groups; `None` for other groups.
    fn reg_access(&self, vm: &VmInner, attr: &kvm_device_attr, write: bool) -> Option<Result<()>> {
        let group = attr.group;
        if !matches!(
            group,
            KVM_DEV_ARM_VGIC_GRP_DIST_REGS
                | KVM_DEV_ARM_VGIC_GRP_REDIST_REGS
                | KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS
        ) || self.kind != DeviceKind::Gic
        {
            return None;
        }
        Some((|| {
            if !vm.gic.lock().unwrap().created {
                return err(libc::ENXIO);
            }
            let addr = attr.addr;
            // KVM's contract: `addr` points to a u32 (u64 for CPU registers).
            // SAFETY: as above.
            let get32 = || unsafe { std::ptr::read_unaligned(addr as *const u32) };
            // SAFETY: as above.
            let put32 = |v: u32| unsafe { std::ptr::write_unaligned(addr as *mut u32, v) };
            if group == KVM_DEV_ARM_VGIC_GRP_DIST_REGS {
                let offset = attr.attr & 0xffff_ffff;
                return if write {
                    dist_write(vm, offset, get32())
                } else {
                    gic::dist_get(offset).map(put32)
                };
            }
            let vcpu = vcpu_by_affinity(vm, attr.attr >> 32)?;
            if group == KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS {
                let reg = gic::icc_reg(attr.attr).ok_or_else(|| super::Error::new(libc::ENXIO))?;
                // SAFETY: as above.
                let value = write.then(|| unsafe { std::ptr::read_unaligned(addr as *const u64) });
                let v = vcpu.gic_access(vm, reg, value)?;
                if !write {
                    // SAFETY: as above.
                    unsafe { std::ptr::write_unaligned(addr as *mut u64, v) };
                }
                return Ok(());
            }
            let offset = attr.attr & 0xffff_ffff;
            let value = write.then(get32);
            let v = match gic::redist_reg(offset).ok_or_else(|| super::Error::new(libc::ENXIO))? {
                RedistReg::RazWi => 0,
                RedistReg::Hv(reg) => {
                    let v = vcpu.gic_access(vm, reg, value.map(u64::from))?;
                    // The registers are 32 bits wide.
                    #[allow(clippy::cast_possible_truncation)]
                    let v = v as u32;
                    v
                }
                RedistReg::PropBase(half) | RedistReg::PendBase(half) => {
                    let pend = matches!(gic::redist_reg(offset), Some(RedistReg::PendBase(_)));
                    let shift = half * 32;
                    let cur = vcpu.lpi_base(pend, None);
                    let new =
                        value.map(|v| (cur & !(0xffff_ffff << shift)) | (u64::from(v) << shift));
                    let full = vcpu.lpi_base(pend, new);
                    // The 32-bit half addressed.
                    #[allow(clippy::cast_possible_truncation)]
                    let v = (full >> shift) as u32;
                    v
                }
            };
            if !write {
                put32(v);
            }
            Ok(())
        })())
    }
}

/// The SPIs of the MSI frame, `(first, count)`: the ones above the wired
/// interrupts (`nr_irqs`, 64 when unset, as KVM's default), up to SPI 1018.
/// `ENOSPC` when none are left.
fn msi_spis(nr_irqs: Option<u32>) -> Result<(u32, u32)> {
    // Guests' GICv2m drivers (Linux: `is_msi_spi_valid`) reject frames whose
    // SPIs reach 1019.
    const END: u32 = 1019;
    let (mut base, mut count) = (0u32, 0u32);
    // SAFETY: writes two u32.
    check(unsafe { hv_gic_get_spi_interrupt_range(&mut base, &mut count) })?;
    let first = nr_irqs.unwrap_or(64).max(base);
    match (base + count).min(END).checked_sub(first) {
        Some(n) if n > 0 => Ok((first, n)),
        _ => err(libc::ENOSPC),
    }
}

/// The vCPU whose affinity is `aff` (`KVM_DEV_ARM_VGIC_V3_MPIDR`), or `EINVAL`.
fn vcpu_by_affinity(vm: &VmInner, aff: u64) -> Result<std::sync::Arc<VcpuShared>> {
    vm.vcpus
        .lock()
        .unwrap()
        .iter()
        .find(|v| gic::packed_affinity(v.mpidr) == aff)
        .cloned()
        .ok_or_else(|| super::Error::new(libc::EINVAL))
}

impl AsRawFd for DeviceFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Writes distributor register `offset`. Pending SPIs restored while the
/// vCPU they are routed to does not exist yet wait for it, as interrupts
/// raised then do (see `VmInner::raise_spi`).
fn dist_write(vm: &VmInner, offset: u64, value: u32) -> Result<()> {
    const ISPENDR_SPIS: std::ops::Range<u64> = 0x204..0x280;
    const ICPENDR_SPIS: std::ops::Range<u64> = 0x284..0x300;
    let set_bits = || (0..32u32).filter(move |b| value & (1 << b) != 0);
    if ISPENDR_SPIS.contains(&offset) {
        let first = u32::try_from(offset - 0x200).unwrap() * 8;
        let reg = u32::try_from(offset).unwrap();
        for bit in set_bits() {
            // SAFETY: plain call; GICD_ISPENDR<n> is write-1-to-set.
            check(vm.raise_spi(first + bit, || unsafe {
                hv_gic_set_distributor_reg(reg, 1 << bit)
            }))?;
        }
        return Ok(());
    }
    if ICPENDR_SPIS.contains(&offset) {
        let first = u32::try_from(offset - 0x280).unwrap() * 8;
        for bit in set_bits() {
            vm.clear_deferred_spi(first + bit);
        }
    }
    gic::dist_set(offset, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msi_spis() {
        let (mut base, mut count) = (0u32, 0u32);
        // SAFETY: writes two u32.
        check(unsafe { hv_gic_get_spi_interrupt_range(&mut base, &mut count) }).unwrap();
        let end = (base + count).min(1019);
        // The SPIs above the wired ones, up to SPI 1018.
        assert_eq!(msi_spis(Some(160)).unwrap(), (160, end - 160));
        // KVM's default of 64 interrupts when NR_IRQS is not set.
        assert_eq!(msi_spis(None).unwrap(), (64, end - 64));
        // None left.
        assert_eq!(msi_spis(Some(end)).unwrap_err().errno(), libc::ENOSPC);
    }
}
