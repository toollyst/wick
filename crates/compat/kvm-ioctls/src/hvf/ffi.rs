// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Hypervisor.framework declarations (macOS 15+, Apple silicon).
//!
//! Values are taken from the macOS SDK headers (`Hypervisor/hv_*.h`).

#![allow(non_camel_case_types, dead_code)]

use std::ffi::c_void;

pub type hv_return_t = i32;
pub type hv_vcpu_t = u64;
pub type hv_ipa_t = u64;
pub type hv_memory_flags_t = u64;
pub type hv_reg_t = u32;
pub type hv_sys_reg_t = u16;
pub type hv_simd_fp_reg_t = u32;
pub type hv_gic_redistributor_reg_t = u32;
pub type hv_gic_intid_t = u16;
pub type hv_exit_reason_t = u32;
/// `os_object` handles (`hv_vm_config_t`, `hv_gic_config_t`, `hv_vcpu_config_t`).
pub type hv_object_t = *mut c_void;

pub const HV_SUCCESS: hv_return_t = 0;
pub const HV_ERROR: hv_return_t = 0xfae9_4001_u32 as i32;
pub const HV_BUSY: hv_return_t = 0xfae9_4002_u32 as i32;
pub const HV_BAD_ARGUMENT: hv_return_t = 0xfae9_4003_u32 as i32;
pub const HV_ILLEGAL_GUEST_STATE: hv_return_t = 0xfae9_4004_u32 as i32;
pub const HV_NO_RESOURCES: hv_return_t = 0xfae9_4005_u32 as i32;
pub const HV_NO_DEVICE: hv_return_t = 0xfae9_4006_u32 as i32;
pub const HV_DENIED: hv_return_t = 0xfae9_4007_u32 as i32;
pub const HV_UNSUPPORTED: hv_return_t = 0xfae9_400f_u32 as i32;

pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

pub const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
pub const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;
pub const HV_EXIT_REASON_UNKNOWN: hv_exit_reason_t = 3;

/// `HV_REG_X0`; `HV_REG_X<n>` is `n`, `HV_REG_FP` is 29 and `HV_REG_LR` is 30.
pub const HV_REG_X0: hv_reg_t = 0;
pub const HV_REG_PC: hv_reg_t = 31;
pub const HV_REG_FPCR: hv_reg_t = 32;
pub const HV_REG_FPSR: hv_reg_t = 33;
pub const HV_REG_CPSR: hv_reg_t = 34;

pub const HV_SYS_REG_MIDR_EL1: hv_sys_reg_t = 0xc000;
pub const HV_SYS_REG_MPIDR_EL1: hv_sys_reg_t = 0xc005;
pub const HV_SYS_REG_ID_AA64DFR0_EL1: hv_sys_reg_t = 0xc028;
pub const HV_SYS_REG_SPSR_EL1: hv_sys_reg_t = 0xc200;
pub const HV_SYS_REG_ELR_EL1: hv_sys_reg_t = 0xc201;
pub const HV_SYS_REG_SP_EL0: hv_sys_reg_t = 0xc208;
pub const HV_SYS_REG_SP_EL1: hv_sys_reg_t = 0xe208;
pub const HV_SYS_REG_ESR_EL1: hv_sys_reg_t = 0xc290;
pub const HV_SYS_REG_VBAR_EL1: hv_sys_reg_t = 0xc600;
pub const HV_SYS_REG_CNTV_CTL_EL0: hv_sys_reg_t = 0xdf19;
pub const HV_SYS_REG_CNTV_CVAL_EL0: hv_sys_reg_t = 0xdf1a;

pub const HV_GIC_REDISTRIBUTOR_REG_GICR_ISPENDR0: hv_gic_redistributor_reg_t = 0x10200;

pub const HV_GIC_INT_EL1_VIRTUAL_TIMER: hv_gic_intid_t = 27;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_exception_t {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: hv_ipa_t,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_t {
    pub reason: hv_exit_reason_t,
    pub exception: hv_vcpu_exit_exception_t,
}

/// 128-bit SIMD register value (`hv_simd_fp_uchar16_t`), as bytes in memory.
pub type hv_simd_fp_uchar16_t = [u8; 16];

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct mach_timebase_info_data_t {
    pub numer: u32,
    pub denom: u32,
}

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    pub fn hv_vm_config_create() -> hv_object_t;
    pub fn hv_vm_config_get_max_ipa_size(ipa_bit_length: *mut u32) -> hv_return_t;
    pub fn hv_vm_config_set_ipa_size(config: hv_object_t, ipa_bit_length: u32) -> hv_return_t;
    pub fn hv_vm_create(config: hv_object_t) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_get_max_vcpu_count(max_vcpu_count: *mut u32) -> hv_return_t;
    pub fn hv_vm_map(
        addr: *mut c_void,
        ipa: hv_ipa_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;
    pub fn hv_vm_unmap(ipa: hv_ipa_t, size: usize) -> hv_return_t;
    pub fn hv_vm_protect(ipa: hv_ipa_t, size: usize, flags: hv_memory_flags_t) -> hv_return_t;

    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut *const hv_vcpu_exit_t,
        config: hv_object_t,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: hv_simd_fp_reg_t,
        value: *mut hv_simd_fp_uchar16_t,
    ) -> hv_return_t;
    /// Takes the value in a SIMD register (clang vector type), which Rust
    /// cannot express in FFI on stable: call [`set_simd_fp_reg`] instead.
    #[link_name = "hv_vcpu_set_simd_fp_reg"]
    fn hv_vcpu_set_simd_fp_reg_raw();
    pub fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpus_exit(vcpus: *const hv_vcpu_t, vcpu_count: u32) -> hv_return_t;
    pub fn hv_vcpu_set_vtimer_mask(vcpu: hv_vcpu_t, vtimer_is_masked: bool) -> hv_return_t;
    pub fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpu_t, vtimer_offset: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, vtimer_offset: u64) -> hv_return_t;

    pub fn hv_gic_config_create() -> hv_object_t;
    pub fn hv_gic_config_set_distributor_base(config: hv_object_t, base: hv_ipa_t) -> hv_return_t;
    pub fn hv_gic_config_set_redistributor_base(config: hv_object_t, base: hv_ipa_t)
    -> hv_return_t;
    pub fn hv_gic_create(config: hv_object_t) -> hv_return_t;
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> hv_return_t;
    pub fn hv_gic_get_redistributor_region_size(size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_spi_interrupt_range(base: *mut u32, count: *mut u32) -> hv_return_t;
    pub fn hv_gic_get_msi_region_size(size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_msi_region_base_alignment(alignment: *mut usize) -> hv_return_t;
    pub fn hv_gic_set_redistributor_reg(
        vcpu: hv_vcpu_t,
        reg: hv_gic_redistributor_reg_t,
        value: u64,
    ) -> hv_return_t;
    pub fn hv_gic_get_redistributor_reg(
        vcpu: hv_vcpu_t,
        reg: hv_gic_redistributor_reg_t,
        value: *mut u64,
    ) -> hv_return_t;
    pub fn hv_gic_config_set_msi_region_base(config: hv_object_t, base: hv_ipa_t) -> hv_return_t;
    pub fn hv_gic_config_set_msi_interrupt_range(
        config: hv_object_t,
        base: u32,
        count: u32,
    ) -> hv_return_t;
    pub fn hv_gic_send_msi(address: hv_ipa_t, intid: u32) -> hv_return_t;
    pub fn hv_gic_get_distributor_reg(reg: u32, value: *mut u64) -> hv_return_t;
    pub fn hv_gic_set_distributor_reg(reg: u32, value: u64) -> hv_return_t;
    pub fn hv_gic_get_icc_reg(vcpu: hv_vcpu_t, reg: u16, value: *mut u64) -> hv_return_t;
    pub fn hv_gic_set_icc_reg(vcpu: hv_vcpu_t, reg: u16, value: u64) -> hv_return_t;

    pub fn mach_absolute_time() -> u64;
    pub fn mach_timebase_info(info: *mut mach_timebase_info_data_t) -> i32;
    pub fn os_release(object: hv_object_t);
}

/// `hv_vcpu_set_simd_fp_reg(vcpu, reg, value)`.
///
/// The value argument is a 16-byte clang vector, passed in `q0` by the AArch64
/// procedure call standard, so the call is made from assembly.
///
/// # Safety
/// `vcpu` must belong to the calling thread.
pub unsafe fn set_simd_fp_reg(
    vcpu: hv_vcpu_t,
    reg: hv_simd_fp_reg_t,
    value: &hv_simd_fp_uchar16_t,
) -> hv_return_t {
    let func = hv_vcpu_set_simd_fp_reg_raw as *const () as usize;
    let ret: u64;
    // SAFETY: a standard C call: x0 = vcpu, w1 = reg, q0 = value, result in w0.
    // `clobber_abi("C")` tells the compiler every caller-saved register is lost.
    unsafe {
        std::arch::asm!(
            "ldr q0, [{value}]",
            "blr {func}",
            value = in(reg) value.as_ptr(),
            func = in(reg) func,
            inout("x0") vcpu => ret,
            in("x1") u64::from(reg),
            clobber_abi("C"),
        );
    }
    ret as u32 as hv_return_t
}

/// Converts a Hypervisor.framework status into an errno-style error.
pub fn check(ret: hv_return_t) -> crate::Result<()> {
    if ret == HV_SUCCESS {
        return Ok(());
    }
    let errno = match ret {
        HV_BUSY => libc::EBUSY,
        HV_BAD_ARGUMENT => libc::EINVAL,
        HV_NO_RESOURCES => libc::ENOMEM,
        HV_NO_DEVICE => libc::ENODEV,
        HV_DENIED => libc::EPERM,
        HV_UNSUPPORTED => libc::ENOTSUP,
        _ => libc::EIO,
    };
    Err(crate::Error::new(errno))
}
