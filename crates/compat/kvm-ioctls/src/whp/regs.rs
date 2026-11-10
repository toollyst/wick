// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Conversions between the `kvm_bindings` register structures Firecracker
//! uses and the Windows Hypervisor Platform register names and values.
//!
//! WHP names each register (`WHvX64Register*`) and reads/writes it as a
//! `WHV_REGISTER_VALUE`. KVM groups registers into structures
//! (`kvm_regs`, `kvm_sregs`, ...). These functions translate between the two,
//! field by field, so the rest of the backend speaks the KVM structures.

use kvm_bindings::{
    kvm_debugregs, kvm_dtable, kvm_fpu, kvm_regs, kvm_segment, kvm_sregs, kvm_xcrs, kvm_xsave,
    CpuId, Msrs, MsrList,
};
// kvm_bindings is imported as `kb` only where constants are needed.
use super::whv;
use super::whv::{WHV_PARTITION_HANDLE, WHV_REGISTER_NAME};

use super::ffi::{self, as_u64, reg64};
use super::{err, Error, Result};

// ---- general purpose registers (kvm_regs) ----

/// The GPRs plus RIP and RFLAGS, in `kvm_regs` field order.
const GPR_NAMES: [WHV_REGISTER_NAME; 18] = [
    whv::WHvX64RegisterRax,
    whv::WHvX64RegisterRbx,
    whv::WHvX64RegisterRcx,
    whv::WHvX64RegisterRdx,
    whv::WHvX64RegisterRsi,
    whv::WHvX64RegisterRdi,
    whv::WHvX64RegisterRsp,
    whv::WHvX64RegisterRbp,
    whv::WHvX64RegisterR8,
    whv::WHvX64RegisterR9,
    whv::WHvX64RegisterR10,
    whv::WHvX64RegisterR11,
    whv::WHvX64RegisterR12,
    whv::WHvX64RegisterR13,
    whv::WHvX64RegisterR14,
    whv::WHvX64RegisterR15,
    whv::WHvX64RegisterRip,
    whv::WHvX64RegisterRflags,
];

pub(crate) fn get_regs(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<kvm_regs> {
    let mut values = [unsafe { std::mem::zeroed() }; GPR_NAMES.len()];
    ffi::get_registers(part, vp, &GPR_NAMES, &mut values)?;
    let v: Vec<u64> = values.iter().map(as_u64).collect();
    Ok(kvm_regs {
        rax: v[0], rbx: v[1], rcx: v[2], rdx: v[3],
        rsi: v[4], rdi: v[5], rsp: v[6], rbp: v[7],
        r8: v[8], r9: v[9], r10: v[10], r11: v[11],
        r12: v[12], r13: v[13], r14: v[14], r15: v[15],
        rip: v[16], rflags: v[17],
    })
}

pub(crate) fn set_regs(part: WHV_PARTITION_HANDLE, vp: u32, r: &kvm_regs) -> Result<()> {
    let fields = [
        r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rsp, r.rbp,
        r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rip, r.rflags,
    ];
    let values: Vec<_> = fields.iter().map(|&x| reg64(x)).collect();
    ffi::set_registers(part, vp, &GPR_NAMES, &values)
}

/// Sets RIP.
pub(crate) fn set_rip(part: WHV_PARTITION_HANDLE, vp: u32, rip: u64) -> Result<()> {
    ffi::set_register(part, vp, whv::WHvX64RegisterRip, reg64(rip))
}

/// Sets RAX and RIP together (completes an `IN`).
pub(crate) fn set_gpr_rax_rip(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    rax: u64,
    rip: u64,
) -> Result<()> {
    ffi::set_registers(
        part,
        vp,
        &[whv::WHvX64RegisterRax, whv::WHvX64RegisterRip],
        &[reg64(rax), reg64(rip)],
    )
}

/// Sets the CPUID result registers (`EAX..EDX`) and advances RIP.
pub(crate) fn set_cpuid_result(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    rip: u64,
) -> Result<()> {
    let names = [
        whv::WHvX64RegisterRax,
        whv::WHvX64RegisterRbx,
        whv::WHvX64RegisterRcx,
        whv::WHvX64RegisterRdx,
        whv::WHvX64RegisterRip,
    ];
    let values = [
        reg64(u64::from(eax)),
        reg64(u64::from(ebx)),
        reg64(u64::from(ecx)),
        reg64(u64::from(edx)),
        reg64(rip),
    ];
    ffi::set_registers(part, vp, &names, &values)
}

/// Sets an `RDMSR` result (`EDX:EAX`) and advances RIP.
pub(crate) fn set_msr_result(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    value: u64,
    rip: u64,
) -> Result<()> {
    let names = [
        whv::WHvX64RegisterRax,
        whv::WHvX64RegisterRdx,
        whv::WHvX64RegisterRip,
    ];
    let values = [reg64(value & 0xffff_ffff), reg64(value >> 32), reg64(rip)];
    ffi::set_registers(part, vp, &names, &values)
}

// ---- segment and table registers ----

/// Unpacks a WHP segment attribute word into the `kvm_segment` bitfields.
fn segment_from_whp(name: WHV_REGISTER_NAME, value: &whv::WHV_REGISTER_VALUE) -> kvm_segment {
    let _ = name;
    // SAFETY: the value was read for a segment register, so `Segment` is valid.
    let seg = unsafe { value.Segment };
    // SAFETY: the attribute bitfield overlaps the `Attributes` u16.
    let attr = unsafe { seg.Anonymous.Attributes };
    let present = u8::from(attr >> 7 & 1 != 0);
    kvm_segment {
        base: seg.Base,
        limit: seg.Limit,
        selector: seg.Selector,
        type_: (attr & 0xf) as u8,
        s: (attr >> 4 & 1) as u8,
        dpl: (attr >> 5 & 3) as u8,
        present,
        avl: (attr >> 12 & 1) as u8,
        l: (attr >> 13 & 1) as u8,
        db: (attr >> 14 & 1) as u8,
        g: (attr >> 15 & 1) as u8,
        unusable: u8::from(present == 0),
        padding: 0,
    }
}

/// Packs a `kvm_segment` into a WHP segment register value.
fn segment_to_whp(s: &kvm_segment) -> whv::WHV_REGISTER_VALUE {
    let attr: u16 = u16::from(s.type_ & 0xf)
        | u16::from(s.s & 1) << 4
        | u16::from(s.dpl & 3) << 5
        | u16::from(s.present & 1) << 7
        | u16::from(s.avl & 1) << 12
        | u16::from(s.l & 1) << 13
        | u16::from(s.db & 1) << 14
        | u16::from(s.g & 1) << 15;
    let mut seg: whv::WHV_X64_SEGMENT_REGISTER = unsafe { std::mem::zeroed() };
    seg.Base = s.base;
    seg.Limit = s.limit;
    seg.Selector = s.selector;
    seg.Anonymous.Attributes = attr;
    let mut value: whv::WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
    value.Segment = seg;
    value
}

fn table_from_whp(value: &whv::WHV_REGISTER_VALUE) -> kvm_dtable {
    // SAFETY: the value was read for a table register.
    let t = unsafe { value.Table };
    kvm_dtable { base: t.Base, limit: t.Limit, padding: [0; 3] }
}

fn table_to_whp(t: &kvm_dtable) -> whv::WHV_REGISTER_VALUE {
    let mut table: whv::WHV_X64_TABLE_REGISTER = unsafe { std::mem::zeroed() };
    table.Base = t.base;
    table.Limit = t.limit;
    let mut value: whv::WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
    value.Table = table;
    value
}

/// The segment registers of `kvm_sregs`, in order, with their WHP names.
const SEG_NAMES: [WHV_REGISTER_NAME; 8] = [
    whv::WHvX64RegisterCs,
    whv::WHvX64RegisterDs,
    whv::WHvX64RegisterEs,
    whv::WHvX64RegisterFs,
    whv::WHvX64RegisterGs,
    whv::WHvX64RegisterSs,
    whv::WHvX64RegisterTr,
    whv::WHvX64RegisterLdtr,
];

/// The control registers of `kvm_sregs`, in order, with their WHP names.
const CTRL_NAMES: [WHV_REGISTER_NAME; 7] = [
    whv::WHvX64RegisterCr0,
    whv::WHvX64RegisterCr2,
    whv::WHvX64RegisterCr3,
    whv::WHvX64RegisterCr4,
    whv::WHvX64RegisterCr8,
    whv::WHvX64RegisterEfer,
    whv::WHvX64RegisterApicBase,
];

pub(crate) fn get_sregs(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<kvm_sregs> {
    let mut names = Vec::with_capacity(17);
    names.extend_from_slice(&SEG_NAMES);
    names.push(whv::WHvX64RegisterGdtr);
    names.push(whv::WHvX64RegisterIdtr);
    names.extend_from_slice(&CTRL_NAMES);
    let mut values = vec![unsafe { std::mem::zeroed() }; names.len()];
    ffi::get_registers(part, vp, &names, &mut values)?;

    let seg = |i: usize| segment_from_whp(names[i], &values[i]);
    let ctrl = 10; // index where control registers begin
    Ok(kvm_sregs {
        cs: seg(0), ds: seg(1), es: seg(2), fs: seg(3),
        gs: seg(4), ss: seg(5), tr: seg(6), ldt: seg(7),
        gdt: table_from_whp(&values[8]),
        idt: table_from_whp(&values[9]),
        cr0: as_u64(&values[ctrl]),
        cr2: as_u64(&values[ctrl + 1]),
        cr3: as_u64(&values[ctrl + 2]),
        cr4: as_u64(&values[ctrl + 3]),
        cr8: as_u64(&values[ctrl + 4]),
        efer: as_u64(&values[ctrl + 5]),
        apic_base: as_u64(&values[ctrl + 6]),
        interrupt_bitmap: [0; 4],
    })
}

pub(crate) fn set_sregs(part: WHV_PARTITION_HANDLE, vp: u32, s: &kvm_sregs) -> Result<()> {
    let mut names = Vec::with_capacity(17);
    let mut values = Vec::with_capacity(17);
    for (i, seg) in [s.cs, s.ds, s.es, s.fs, s.gs, s.ss, s.tr, s.ldt].iter().enumerate() {
        names.push(SEG_NAMES[i]);
        values.push(segment_to_whp(seg));
    }
    names.push(whv::WHvX64RegisterGdtr);
    values.push(table_to_whp(&s.gdt));
    names.push(whv::WHvX64RegisterIdtr);
    values.push(table_to_whp(&s.idt));
    for (i, v) in [s.cr0, s.cr2, s.cr3, s.cr4, s.cr8, s.efer, s.apic_base]
        .iter()
        .enumerate()
    {
        names.push(CTRL_NAMES[i]);
        values.push(reg64(*v));
    }
    ffi::set_registers(part, vp, &names, &values)
}

// ---- debug registers ----

const DEBUG_NAMES: [WHV_REGISTER_NAME; 6] = [
    whv::WHvX64RegisterDr0,
    whv::WHvX64RegisterDr1,
    whv::WHvX64RegisterDr2,
    whv::WHvX64RegisterDr3,
    whv::WHvX64RegisterDr6,
    whv::WHvX64RegisterDr7,
];

pub(crate) fn get_debugregs(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<kvm_debugregs> {
    let mut values = [unsafe { std::mem::zeroed() }; 6];
    ffi::get_registers(part, vp, &DEBUG_NAMES, &mut values)?;
    Ok(kvm_debugregs {
        db: [as_u64(&values[0]), as_u64(&values[1]), as_u64(&values[2]), as_u64(&values[3])],
        dr6: as_u64(&values[4]),
        dr7: as_u64(&values[5]),
        flags: 0,
        reserved: [0; 9],
    })
}

pub(crate) fn set_debugregs(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    d: &kvm_debugregs,
) -> Result<()> {
    let values = [
        reg64(d.db[0]), reg64(d.db[1]), reg64(d.db[2]), reg64(d.db[3]),
        reg64(d.dr6), reg64(d.dr7),
    ];
    ffi::set_registers(part, vp, &DEBUG_NAMES, &values)
}

// ---- XCRs (only XCR0 is meaningful) ----

pub(crate) fn get_xcrs(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<kvm_xcrs> {
    let xcr0 = as_u64(&ffi::get_register(part, vp, whv::WHvX64RegisterXCr0)?);
    let mut out = kvm_xcrs {
        nr_xcrs: 1,
        flags: 0,
        xcrs: unsafe { std::mem::zeroed() },
        padding: [0; 16],
    };
    out.xcrs[0].xcr = 0;
    out.xcrs[0].value = xcr0;
    Ok(out)
}

pub(crate) fn set_xcrs(part: WHV_PARTITION_HANDLE, vp: u32, x: &kvm_xcrs) -> Result<()> {
    let xcr0 = x
        .xcrs
        .iter()
        .take(x.nr_xcrs as usize)
        .find(|e| e.xcr == 0)
        .map_or(1, |e| e.value);
    ffi::set_register(part, vp, whv::WHvX64RegisterXCr0, reg64(xcr0))
}

// ---- XSAVE and FPU ----

/// The XSAVE area size WHP uses (the full area; 4 KiB covers current CPUs).
const XSAVE_AREA_LEN: usize = std::mem::size_of::<kvm_xsave>();

pub(crate) fn get_xsave(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<kvm_xsave> {
    let mut out = kvm_xsave { region: [0; 1024], extra: Default::default() };
    let mut written = 0u32;
    // SAFETY: valid output buffer of the given size.
    ffi::hr(unsafe {
        whv::WHvGetVirtualProcessorXsaveState(
            part,
            vp,
            out.region.as_mut_ptr().cast(),
            u32::try_from(XSAVE_AREA_LEN).unwrap(),
            &mut written,
        )
    })?;
    Ok(out)
}

pub(crate) fn set_xsave(part: WHV_PARTITION_HANDLE, vp: u32, x: &kvm_xsave) -> Result<()> {
    // SAFETY: the region is valid for its size.
    ffi::hr(unsafe {
        whv::WHvSetVirtualProcessorXsaveState(
            part,
            vp,
            x.region.as_ptr().cast(),
            u32::try_from(XSAVE_AREA_LEN).unwrap(),
        )
    })
}

/// `kvm_fpu` is the legacy FXSAVE region at the start of the XSAVE area.
pub(crate) fn get_fpu(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<kvm_fpu> {
    let xsave = get_xsave(part, vp)?;
    // SAFETY: the first 512 bytes of the XSAVE area are the FXSAVE region,
    // whose layout matches `kvm_fpu`'s leading fields; read it as bytes.
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(xsave.region.as_ptr().cast::<u8>(), 512)
    };
    Ok(fpu_from_fxsave(bytes))
}

pub(crate) fn set_fpu(part: WHV_PARTITION_HANDLE, vp: u32, fpu: &kvm_fpu) -> Result<()> {
    let mut xsave = get_xsave(part, vp)?;
    // SAFETY: overwrite the 512-byte FXSAVE region at the start of the area.
    let bytes: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(xsave.region.as_mut_ptr().cast::<u8>(), 512)
    };
    fxsave_from_fpu(fpu, bytes);
    set_xsave(part, vp, &xsave)
}

/// Reads a `kvm_fpu` out of a 512-byte FXSAVE area.
fn fpu_from_fxsave(b: &[u8]) -> kvm_fpu {
    let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
    let u64_at = |o: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[o..o + 8]);
        u64::from_le_bytes(x)
    };
    let mut fpu = kvm_fpu {
        fpr: [[0; 16]; 8],
        fcw: u16_at(0),
        fsw: u16_at(2),
        ftwx: b[4],
        pad1: 0,
        last_opcode: u16_at(6),
        last_ip: u64_at(8),
        last_dp: u64_at(16),
        xmm: [[0; 16]; 16],
        mxcsr: {
            let mut x = [0u8; 4];
            x.copy_from_slice(&b[24..28]);
            u32::from_le_bytes(x)
        },
        pad2: 0,
    };
    for (i, fpr) in fpu.fpr.iter_mut().enumerate() {
        fpr.copy_from_slice(&b[32 + i * 16..32 + i * 16 + 16]);
    }
    for (i, xmm) in fpu.xmm.iter_mut().enumerate() {
        xmm.copy_from_slice(&b[160 + i * 16..160 + i * 16 + 16]);
    }
    fpu
}

/// Writes a `kvm_fpu` into a 512-byte FXSAVE area.
fn fxsave_from_fpu(fpu: &kvm_fpu, b: &mut [u8]) {
    b[0..2].copy_from_slice(&fpu.fcw.to_le_bytes());
    b[2..4].copy_from_slice(&fpu.fsw.to_le_bytes());
    b[4] = fpu.ftwx;
    b[6..8].copy_from_slice(&fpu.last_opcode.to_le_bytes());
    b[8..16].copy_from_slice(&fpu.last_ip.to_le_bytes());
    b[16..24].copy_from_slice(&fpu.last_dp.to_le_bytes());
    b[24..28].copy_from_slice(&fpu.mxcsr.to_le_bytes());
    for (i, fpr) in fpu.fpr.iter().enumerate() {
        b[32 + i * 16..32 + i * 16 + 16].copy_from_slice(fpr);
    }
    for (i, xmm) in fpu.xmm.iter().enumerate() {
        b[160 + i * 16..160 + i * 16 + 16].copy_from_slice(xmm);
    }
}

// ---- MP state ----

/// `WHV_INTERNAL_ACTIVITY_REGISTER.StartupSuspend`: the vCPU waits for a
/// start-up IPI (an application processor after reset).
pub(crate) const ACTIVITY_STARTUP_SUSPEND: u64 = 1 << 0;
/// `WHV_INTERNAL_ACTIVITY_REGISTER.HaltSuspend`: the vCPU executed `HLT`.
pub(crate) const ACTIVITY_HALT_SUSPEND: u64 = 1 << 1;

/// The KVM MP state of an internal activity register value.
pub(crate) fn mp_state_from_activity(activity: u64) -> u32 {
    if activity & ACTIVITY_STARTUP_SUSPEND != 0 {
        // KVM's state for a vCPU that waits for a SIPI.
        kvm_bindings::KVM_MP_STATE_INIT_RECEIVED
    } else if activity & ACTIVITY_HALT_SUSPEND != 0 {
        kvm_bindings::KVM_MP_STATE_HALTED
    } else {
        kvm_bindings::KVM_MP_STATE_RUNNABLE
    }
}

/// The internal activity register value for a KVM MP state. `EINVAL` for
/// the states KVM rejects on x86 and for the transient `SIPI_RECEIVED`,
/// which WHP has no equivalent of.
pub(crate) fn activity_from_mp_state(mp_state: u32) -> Result<u64> {
    match mp_state {
        kvm_bindings::KVM_MP_STATE_RUNNABLE => Ok(0),
        kvm_bindings::KVM_MP_STATE_UNINITIALIZED | kvm_bindings::KVM_MP_STATE_INIT_RECEIVED => {
            Ok(ACTIVITY_STARTUP_SUSPEND)
        }
        kvm_bindings::KVM_MP_STATE_HALTED => Ok(ACTIVITY_HALT_SUSPEND),
        _ => Err(Error::new(libc::EINVAL)),
    }
}

pub(crate) fn get_mp_state(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
) -> Result<kvm_bindings::kvm_mp_state> {
    let value = ffi::get_register(part, vp, whv::WHvRegisterInternalActivityState)?;
    Ok(kvm_bindings::kvm_mp_state {
        mp_state: mp_state_from_activity(as_u64(&value)),
    })
}

pub(crate) fn set_mp_state(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    state: kvm_bindings::kvm_mp_state,
) -> Result<()> {
    let activity = activity_from_mp_state(state.mp_state)?;
    ffi::set_register(
        part,
        vp,
        whv::WHvRegisterInternalActivityState,
        reg64(activity),
    )
}

/// Puts application processor `vp` in the wait-for-SIPI state, KVM's state
/// for a vCPU other than the BSP after creation: it starts where the guest's
/// SIPI says, whatever its registers hold. Left alone if WHP created it so.
pub(crate) fn startup_suspend(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<()> {
    let value = ffi::get_register(part, vp, whv::WHvRegisterInternalActivityState)?;
    let activity = as_u64(&value);
    if activity & ACTIVITY_STARTUP_SUSPEND != 0 {
        return Ok(());
    }
    ffi::set_register(
        part,
        vp,
        whv::WHvRegisterInternalActivityState,
        reg64(activity | ACTIVITY_STARTUP_SUSPEND),
    )
}

// ---- vCPU events (kvm_vcpu_events) ----
//
// KVM keeps the event a vCPU is about to deliver (an exception, an NMI or an
// external interrupt already taken from the interrupt controller) and its
// interrupt shadow and NMI mask in `kvm_vcpu_events`. WHP keeps the same in
// two registers:
//
// - `WHvRegisterPendingInterruption` (`WHV_X64_PENDING_INTERRUPTION_REGISTER`):
//   bit 0 pending, bits 1-3 type (0 external interrupt, 2 NMI, 3 hardware
//   exception, 4 software interrupt, 5-6 software exceptions, VMX's
//   encoding), bit 4 error code valid, bits 16-31 vector, bits 32-63 error
//   code;
// - `WHvRegisterInterruptState` (`WHV_X64_INTERRUPT_STATE_REGISTER`): bit 0
//   interrupt shadow (after `STI` or `MOV SS`), bit 1 NMIs masked.
//
// An NMI that is pending but not yet being delivered has no WHP register
// (WHP delivers NMIs through the LAPIC at once), so `nmi.pending` reads as 0;
// one restored from a KVM snapshot is delivered as the pending event when no
// other event is.

const PI_PENDING: u64 = 1;
const PI_TYPE_SHIFT: u32 = 1;
const PI_DELIVER_ERROR_CODE: u64 = 1 << 4;
const PI_VECTOR_SHIFT: u32 = 16;
const PI_ERROR_CODE_SHIFT: u32 = 32;
const PI_TYPE_INTERRUPT: u64 = 0;
const PI_TYPE_NMI: u64 = 2;
const PI_TYPE_EXCEPTION: u64 = 3;
const PI_TYPE_SOFTWARE_INTERRUPT: u64 = 4;
const IS_INTERRUPT_SHADOW: u64 = 1;
const IS_NMI_MASKED: u64 = 1 << 1;
const NMI_VECTOR: u64 = 2;

/// `kvm_vcpu_events` from the two WHP registers.
pub(crate) fn events_from_whp(pending: u64, state: u64) -> kvm_bindings::kvm_vcpu_events {
    // SAFETY: plain data, all zeros is "no event".
    let mut e: kvm_bindings::kvm_vcpu_events = unsafe { std::mem::zeroed() };
    if pending & PI_PENDING != 0 {
        #[allow(clippy::cast_possible_truncation)]
        let vector = (pending >> PI_VECTOR_SHIFT) as u8;
        match (pending >> PI_TYPE_SHIFT) & 0x7 {
            PI_TYPE_INTERRUPT => {
                e.interrupt.injected = 1;
                e.interrupt.nr = vector;
            }
            PI_TYPE_SOFTWARE_INTERRUPT => {
                e.interrupt.injected = 1;
                e.interrupt.nr = vector;
                e.interrupt.soft = 1;
            }
            PI_TYPE_NMI => e.nmi.injected = 1,
            // Hardware and software exceptions.
            _ => {
                e.exception.injected = 1;
                e.exception.nr = vector;
                e.exception.has_error_code = u8::from(pending & PI_DELIVER_ERROR_CODE != 0);
                #[allow(clippy::cast_possible_truncation)]
                {
                    e.exception.error_code = (pending >> PI_ERROR_CODE_SHIFT) as u32;
                }
            }
        }
    }
    if state & IS_INTERRUPT_SHADOW != 0 {
        #[allow(clippy::cast_possible_truncation)]
        {
            e.interrupt.shadow = kvm_bindings::KVM_X86_SHADOW_INT_STI as u8;
        }
    }
    e.nmi.masked = u8::from(state & IS_NMI_MASKED != 0);
    e.flags = kvm_bindings::KVM_VCPUEVENT_VALID_SHADOW | kvm_bindings::KVM_VCPUEVENT_VALID_NMI_PENDING;
    e
}

/// The two WHP register values (pending interruption, interrupt state) for
/// `kvm_vcpu_events`. SMM and triple fault state is not representable;
/// `EINVAL` if it is set, as KVM rejects what it does not support.
pub(crate) fn events_to_whp(e: &kvm_bindings::kvm_vcpu_events) -> Result<(u64, u64)> {
    if (e.flags & kvm_bindings::KVM_VCPUEVENT_VALID_SMM != 0 && (e.smi.smm != 0 || e.smi.pending != 0))
        || (e.flags & kvm_bindings::KVM_VCPUEVENT_VALID_TRIPLE_FAULT != 0 && e.triple_fault.pending != 0)
    {
        return Err(Error::new(libc::EINVAL));
    }
    let pending = if e.exception.injected != 0 || e.exception.pending != 0 {
        PI_PENDING
            | (PI_TYPE_EXCEPTION << PI_TYPE_SHIFT)
            | if e.exception.has_error_code != 0 { PI_DELIVER_ERROR_CODE } else { 0 }
            | (u64::from(e.exception.nr) << PI_VECTOR_SHIFT)
            | (u64::from(e.exception.error_code) << PI_ERROR_CODE_SHIFT)
    } else if e.nmi.injected != 0
        || (e.flags & kvm_bindings::KVM_VCPUEVENT_VALID_NMI_PENDING != 0 && e.nmi.pending != 0)
    {
        PI_PENDING | (PI_TYPE_NMI << PI_TYPE_SHIFT) | (NMI_VECTOR << PI_VECTOR_SHIFT)
    } else if e.interrupt.injected != 0 {
        let kind = if e.interrupt.soft != 0 { PI_TYPE_SOFTWARE_INTERRUPT } else { PI_TYPE_INTERRUPT };
        PI_PENDING | (kind << PI_TYPE_SHIFT) | (u64::from(e.interrupt.nr) << PI_VECTOR_SHIFT)
    } else {
        0
    };
    let mut state = 0;
    if e.flags & kvm_bindings::KVM_VCPUEVENT_VALID_SHADOW != 0 && e.interrupt.shadow != 0 {
        state |= IS_INTERRUPT_SHADOW;
    }
    if e.nmi.masked != 0 {
        state |= IS_NMI_MASKED;
    }
    Ok((pending, state))
}

const EVENT_NAMES: [WHV_REGISTER_NAME; 2] =
    [whv::WHvRegisterPendingInterruption, whv::WHvRegisterInterruptState];

pub(crate) fn get_vcpu_events(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
) -> Result<kvm_bindings::kvm_vcpu_events> {
    let mut values = [unsafe { std::mem::zeroed() }; 2];
    ffi::get_registers(part, vp, &EVENT_NAMES, &mut values)?;
    Ok(events_from_whp(as_u64(&values[0]), as_u64(&values[1])))
}

pub(crate) fn set_vcpu_events(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    e: &kvm_bindings::kvm_vcpu_events,
) -> Result<()> {
    let (pending, state) = events_to_whp(e)?;
    ffi::set_registers(part, vp, &EVENT_NAMES, &[reg64(pending), reg64(state)])
}

// ---- CPUID ----

/// The CPUID leaves the guest may use: the host's, without what a WHP guest
/// does not get, as KVM's `GET_SUPPORTED_CPUID` is the host's without what
/// KVM does not virtualize ([`mask_unsupported`]). Firecracker builds the
/// guest's CPUID from this; WHP answers the guest's CPUID exits with it.
pub(crate) fn supported_cpuid(num_entries: usize) -> Result<CpuId> {
    let mut leaves = crate::whp::regs::host_cpuid_entries();
    for e in &mut leaves {
        mask_unsupported(e);
    }
    leaves.extend(kvm_leaves());
    if leaves.len() > num_entries {
        return err(libc::E2BIG);
    }
    CpuId::from_entries(&leaves).map_err(|_| super::Error::new(libc::EINVAL))
}

/// The hypervisor leaves KVM's `GET_SUPPORTED_CPUID` has: the `KVMKVMKVM`
/// signature at 0x40000000 and, at 0x40000001, the paravirtual features this
/// backend implements: kvm-clock (`pvclock`), stable.
fn kvm_leaves() -> [kvm_bindings::kvm_cpuid_entry2; 2] {
    let sig = |s: &[u8; 4]| u32::from_le_bytes(*s);
    let entry = |function, eax, ebx, ecx, edx| kvm_bindings::kvm_cpuid_entry2 {
        function,
        index: 0,
        flags: 0,
        eax,
        ebx,
        ecx,
        edx,
        padding: [0; 3],
    };
    [
        entry(0x4000_0000, 0x4000_0001, sig(b"KVMK"), sig(b"VMKV"), sig(b"M\0\0\0")),
        entry(
            0x4000_0001,
            super::pvclock::FEATURE_CLOCKSOURCE2 | super::pvclock::FEATURE_CLOCKSOURCE_STABLE,
            0,
            0,
            0,
        ),
    ]
}

/// Clears what KVM's `kvm_set_cpu_caps` leaves out of `GET_SUPPORTED_CPUID`
/// and WHP does not give a guest either: `MONITOR`/`MWAIT` and AMD's
/// `MONITORX`/`MWAITX` (a WHP guest gets `#UD` for them: a Linux guest that
/// sees them idles with `MWAIT` and dies at boot), nested virtualization
/// (VMX, SMX, SVM, SKINIT), the processor's power and thermal management
/// (EST, TM/TM2, leaves 5 and 6), debug stores and the performance
/// monitoring unit (leaf 0xA, `PDCM`, AMD's core and northbridge counters,
/// IBS), and `WAITPKG` (`UMWAIT`/`TPAUSE`).
pub(crate) fn mask_unsupported(e: &mut kvm_bindings::kvm_cpuid_entry2) {
    const fn bits(list: &[u32]) -> u32 {
        let mut m = 0;
        let mut i = 0;
        while i < list.len() {
            m |= 1 << list[i];
            i += 1;
        }
        m
    }
    match (e.function, e.index) {
        (0x1, _) => {
            // ECX: DTES64, MONITOR, DS_CPL, VMX, SMX, EST, TM2, xTPR, PDCM,
            // and TSC_DEADLINE: WHP's emulated local APIC has no TSC-deadline
            // mode (a write of IA32_TSC_DEADLINE arms nothing), so a guest
            // that used it would have no local timer; without it, Linux uses
            // the APIC timer's one-shot mode.
            e.ecx &= !bits(&[2, 3, 4, 5, 6, 7, 8, 14, 15, 24]);
            // EDX: DS, ACPI (thermal), TM, PBE.
            e.edx &= !bits(&[21, 22, 29, 31]);
        }
        (0x5 | 0x6 | 0xa, _) | (0x8000_000a, _) => {
            e.eax = 0;
            e.ebx = 0;
            e.ecx = 0;
            e.edx = 0;
        }
        (0x7, 0) => {
            // ECX: WAITPKG.
            e.ecx &= !bits(&[5]);
        }
        (0x8000_0001, _) => {
            // ECX: SVM, IBS, SKINIT, WDT, PERFCTR_CORE, PERFCTR_NB, MWAITX.
            e.ecx &= !bits(&[2, 10, 12, 13, 23, 24, 29]);
        }
        _ => {}
    }
}

/// The size of an XSAVE area holding the state components of `mask`, as
/// CPUID leaf 0xD reports it: the standard format (`compacted` false, leaf
/// 0xD.0 EBX: the end of the last component at its fixed offset) or the
/// compacted one of `XSAVEC`/`XSAVES` (leaf 0xD.1 EBX: the components in
/// order, each aligned to 64 bytes if leaf 0xD.i ECX bit 1 says so). Both
/// start after the 512-byte legacy area and the 64-byte header; the
/// components' sizes and offsets are the processor's (leaf 0xD.i).
pub(crate) fn xsave_size(mask: u64, compacted: bool) -> u32 {
    use core::arch::x86_64::__cpuid_count;
    const START: u32 = 512 + 64;
    let mut size = START;
    for i in 2..64u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let r = __cpuid_count(0xd, i);
        if r.eax == 0 {
            continue;
        }
        if compacted {
            if r.ecx & 2 != 0 {
                size = size.div_ceil(64) * 64;
            }
            size += r.eax;
        } else {
            size = size.max(r.ebx + r.eax);
        }
    }
    size
}

/// Queries the host CPUID leaves Firecracker's templates expect, with their
/// sub-leaves.
fn host_cpuid_entries() -> Vec<kvm_bindings::kvm_cpuid_entry2> {
    use core::arch::x86_64::__cpuid_count;
    let mut out = Vec::new();
    let mut push = |function: u32, index: u32, flags: u32| {
        let r = __cpuid_count(function, index);
        out.push(kvm_bindings::kvm_cpuid_entry2 {
            function,
            index,
            flags,
            eax: r.eax,
            ebx: r.ebx,
            ecx: r.ecx,
            edx: r.edx,
            padding: [0; 3],
        });
    };
    // Standard and extended leaves, with the sub-leaf ranges that have them.
    let max_std = __cpuid_count(0, 0).eax;
    let max_ext = __cpuid_count(0x8000_0000, 0).eax;
    const SIGNIFICANT_INDEX: u32 = kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    for function in 0..=max_std {
        match function {
            // Leaves with meaningful sub-leaves.
            0x4 => {
                for index in 0..8 {
                    let r = __cpuid_count(function, index);
                    if r.eax & 0x1f == 0 {
                        break;
                    }
                    push(function, index, SIGNIFICANT_INDEX);
                }
            }
            0x7 => {
                let max_sub = __cpuid_count(0x7, 0).eax;
                for index in 0..=max_sub {
                    push(function, index, SIGNIFICANT_INDEX);
                }
            }
            0xb => {
                for index in 0..8 {
                    let r = __cpuid_count(function, index);
                    push(function, index, SIGNIFICANT_INDEX);
                    if r.ecx & 0xff00 == 0 {
                        break;
                    }
                }
            }
            0xd => {
                for index in 0..64 {
                    let r = __cpuid_count(function, index);
                    if index >= 2 && r.eax == 0 && r.ebx == 0 && r.ecx == 0 && r.edx == 0 {
                        continue;
                    }
                    push(function, index, SIGNIFICANT_INDEX);
                }
            }
            _ => push(function, 0, 0),
        }
    }
    for function in 0x8000_0000..=max_ext {
        push(function, 0, 0);
    }
    out
}

// ---- MSRs ----

/// MSR index to WHP register name, for the MSRs Firecracker reads and writes.
fn msr_register(index: u32) -> Option<WHV_REGISTER_NAME> {
    Some(match index {
        0x1b => whv::WHvX64RegisterApicBase,          // IA32_APIC_BASE
        0xc000_0080 => whv::WHvX64RegisterEfer,       // EFER
        0x174 => whv::WHvX64RegisterSysenterCs,       // SYSENTER_CS
        0x175 => whv::WHvX64RegisterSysenterEsp,      // SYSENTER_ESP
        0x176 => whv::WHvX64RegisterSysenterEip,      // SYSENTER_EIP
        0xc000_0081 => whv::WHvX64RegisterStar,
        0xc000_0082 => whv::WHvX64RegisterLstar,
        0xc000_0083 => whv::WHvX64RegisterCstar,
        0xc000_0084 => whv::WHvX64RegisterSfmask,
        0xc000_0102 => whv::WHvX64RegisterKernelGsBase,
        0x277 => whv::WHvX64RegisterPat,              // IA32_PAT
        0x10 => whv::WHvX64RegisterTsc,               // IA32_TSC
        _ => return None,
    })
}

/// FS_BASE (0xc000_0100) and GS_BASE (0xc000_0101) are the base of the FS/GS
/// segment registers. Returns the WHP segment register name for those MSRs.
fn msr_segment_base(index: u32) -> Option<WHV_REGISTER_NAME> {
    match index {
        0xc000_0100 => Some(whv::WHvX64RegisterFs),
        0xc000_0101 => Some(whv::WHvX64RegisterGs),
        _ => None,
    }
}

/// Reads MSRs into `msrs`, from the WHP registers they map to. MSRs with no
/// WHP register are left at 0 (their reset value), as a guest MSR read of an
/// unmodelled MSR would see.
pub(crate) fn get_msrs(part: WHV_PARTITION_HANDLE, vp: u32, msrs: &mut Msrs) -> Result<usize> {
    let entries = msrs.as_mut_slice();
    let mut count = 0;
    for e in entries.iter_mut() {
        if let Some(name) = msr_register(e.index) {
            e.data = as_u64(&ffi::get_register(part, vp, name)?);
        } else if let Some(seg) = msr_segment_base(e.index) {
            // SAFETY: a segment register value; read its base.
            e.data = unsafe { ffi::get_register(part, vp, seg)?.Segment }.Base;
        } else {
            e.data = 0;
        }
        count += 1;
    }
    Ok(count)
}

/// Writes MSRs to the WHP registers they map to; unmapped MSRs are ignored
/// (WHP models the architectural MSRs itself), as KVM ignores writes to MSRs
/// it has no state for when they match the reset value.
pub(crate) fn set_msrs(part: WHV_PARTITION_HANDLE, vp: u32, msrs: &Msrs) -> Result<usize> {
    let entries = msrs.as_slice();
    let mut count = 0;
    for e in entries {
        if let Some(name) = msr_register(e.index) {
            ffi::set_register(part, vp, name, reg64(e.data))?;
        } else if let Some(seg) = msr_segment_base(e.index) {
            let mut value = ffi::get_register(part, vp, seg)?;
            value.Segment.Base = e.data;
            ffi::set_register(part, vp, seg, value)?;
        }
        count += 1;
    }
    Ok(count)
}

/// The MSR indices this backend can get and set.
pub(crate) fn msr_index_list() -> Result<MsrList> {
    let indices: Vec<u32> = [
        0x1b, 0x10, 0x174, 0x175, 0x176, 0x277,
        0xc000_0080, 0xc000_0081, 0xc000_0082, 0xc000_0083, 0xc000_0084,
        0xc000_0100, 0xc000_0101, 0xc000_0102,
        // kvm-clock (pvclock).
        super::pvclock::MSR_WALL_CLOCK, super::pvclock::MSR_SYSTEM_TIME,
    ]
    .to_vec();
    MsrList::from_entries(&indices).map_err(|_| super::Error::new(libc::EINVAL))
}

/// Feature MSRs with host values (none modelled yet; an empty list, which
/// Firecracker treats as "no feature MSRs to save").
pub(crate) fn msr_feature_index_list() -> Result<MsrList> {
    MsrList::from_entries(&[]).map_err(|_| super::Error::new(libc::EINVAL))
}

/// Host values for feature MSRs (none).
pub(crate) fn get_host_msrs(_msrs: &mut Msrs) -> Result<usize> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_roundtrip() {
        let s = kvm_segment {
            base: 0xdead_0000,
            limit: 0xfffff,
            selector: 0x10,
            type_: 0xb,
            s: 1,
            dpl: 0,
            present: 1,
            avl: 0,
            l: 1,
            db: 0,
            g: 1,
            unusable: 0,
            padding: 0,
        };
        let v = segment_to_whp(&s);
        let back = segment_from_whp(whv::WHvX64RegisterCs, &v);
        assert_eq!(back.base, s.base);
        assert_eq!(back.limit, s.limit);
        assert_eq!(back.type_, s.type_);
        assert_eq!(back.l, s.l);
        assert_eq!(back.g, s.g);
        assert_eq!(back.present, 1);
    }

    #[test]
    fn test_mp_state_mapping() {
        use kvm_bindings::{
            KVM_MP_STATE_HALTED, KVM_MP_STATE_INIT_RECEIVED, KVM_MP_STATE_RUNNABLE,
            KVM_MP_STATE_SIPI_RECEIVED, KVM_MP_STATE_UNINITIALIZED,
        };
        assert_eq!(mp_state_from_activity(0), KVM_MP_STATE_RUNNABLE);
        assert_eq!(
            mp_state_from_activity(ACTIVITY_STARTUP_SUSPEND),
            KVM_MP_STATE_INIT_RECEIVED
        );
        assert_eq!(mp_state_from_activity(ACTIVITY_HALT_SUSPEND), KVM_MP_STATE_HALTED);
        // Waiting for a SIPI comes first, as in KVM.
        assert_eq!(
            mp_state_from_activity(ACTIVITY_STARTUP_SUSPEND | ACTIVITY_HALT_SUSPEND),
            KVM_MP_STATE_INIT_RECEIVED
        );
        for state in [KVM_MP_STATE_RUNNABLE, KVM_MP_STATE_INIT_RECEIVED, KVM_MP_STATE_HALTED] {
            let activity = activity_from_mp_state(state).unwrap();
            assert_eq!(mp_state_from_activity(activity), state);
        }
        assert_eq!(
            activity_from_mp_state(KVM_MP_STATE_UNINITIALIZED).unwrap(),
            ACTIVITY_STARTUP_SUSPEND
        );
        assert_eq!(
            activity_from_mp_state(KVM_MP_STATE_SIPI_RECEIVED).unwrap_err().errno(),
            libc::EINVAL
        );
        assert_eq!(activity_from_mp_state(99).unwrap_err().errno(), libc::EINVAL);
    }

    #[test]
    fn test_xsave_size() {
        use core::arch::x86_64::{__cpuid_count, _xgetbv};
        // x87 and SSE only: the legacy area and the header.
        assert_eq!(xsave_size(0x3, false), 576);
        assert_eq!(xsave_size(0x3, true), 576);
        // The host's own XCR0: what the processor reports for it.
        // SAFETY: XGETBV of XCR0 on a host that has XSAVE (every x86_64 Windows host).
        let xcr0 = unsafe { _xgetbv(0) };
        assert_eq!(xsave_size(xcr0, false), __cpuid_count(0xd, 0).ebx);
    }

    #[test]
    fn test_supported_cpuid_has_no_mwait_or_nested_virt() {
        let cpuid = supported_cpuid(256).unwrap();
        for e in cpuid.as_slice() {
            match (e.function, e.index) {
                (0x1, _) => {
                    assert_eq!(e.ecx & (1 << 3), 0, "MONITOR");
                    assert_eq!(e.ecx & (1 << 5), 0, "VMX");
                }
                (0x5 | 0x6 | 0xa | 0x8000_000a, _) => {
                    assert_eq!((e.eax, e.ebx, e.ecx, e.edx), (0, 0, 0, 0), "leaf {:#x}", e.function);
                }
                (0x8000_0001, _) => {
                    assert_eq!(e.ecx & (1 << 29), 0, "MWAITX");
                    assert_eq!(e.ecx & (1 << 2), 0, "SVM");
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_vcpu_events_roundtrip() {
        use kvm_bindings::{kvm_vcpu_events, KVM_VCPUEVENT_VALID_NMI_PENDING, KVM_VCPUEVENT_VALID_SHADOW};
        let zero: kvm_vcpu_events = unsafe { std::mem::zeroed() };

        // Nothing pending.
        assert_eq!(events_to_whp(&zero).unwrap(), (0, 0));
        let e = events_from_whp(0, 0);
        assert_eq!((e.exception.injected, e.interrupt.injected, e.nmi.injected), (0, 0, 0));
        assert_eq!(e.flags, KVM_VCPUEVENT_VALID_SHADOW | KVM_VCPUEVENT_VALID_NMI_PENDING);

        // A page fault with its error code, an interrupt shadow, NMIs masked.
        let mut pf = zero;
        pf.exception.injected = 1;
        pf.exception.nr = 14;
        pf.exception.has_error_code = 1;
        pf.exception.error_code = 0x6;
        pf.interrupt.shadow = 1;
        pf.nmi.masked = 1;
        pf.flags = KVM_VCPUEVENT_VALID_SHADOW;
        let (pending, state) = events_to_whp(&pf).unwrap();
        assert_eq!(pending, 1 | (3 << 1) | (1 << 4) | (14 << 16) | (0x6 << 32));
        assert_eq!(state, 0b11);
        let back = events_from_whp(pending, state);
        assert_eq!(
            (back.exception.injected, back.exception.nr, back.exception.has_error_code, back.exception.error_code),
            (1, 14, 1, 0x6)
        );
        assert_ne!(back.interrupt.shadow, 0);
        assert_eq!(back.nmi.masked, 1);

        // An external interrupt taken from the LAPIC, and a software one.
        for soft in [0u8, 1] {
            let mut irq = zero;
            irq.interrupt.injected = 1;
            irq.interrupt.nr = 0xec;
            irq.interrupt.soft = soft;
            let (pending, state) = events_to_whp(&irq).unwrap();
            assert_eq!(pending, 1 | (if soft == 1 { 4 << 1 } else { 0 }) | (0xec << 16));
            assert_eq!(state, 0);
            let back = events_from_whp(pending, state);
            assert_eq!((back.interrupt.injected, back.interrupt.nr, back.interrupt.soft), (1, 0xec, soft));
        }

        // An NMI being delivered, and one only pending in a KVM snapshot.
        let mut nmi = zero;
        nmi.nmi.injected = 1;
        let (pending, _) = events_to_whp(&nmi).unwrap();
        assert_eq!(pending, 1 | (2 << 1) | (2 << 16));
        assert_eq!(events_from_whp(pending, 0).nmi.injected, 1);
        let mut queued = zero;
        queued.nmi.pending = 1;
        queued.flags = KVM_VCPUEVENT_VALID_NMI_PENDING;
        assert_eq!(events_to_whp(&queued).unwrap().0, pending);

        // SMM is not representable.
        let mut smm = zero;
        smm.flags = kvm_bindings::KVM_VCPUEVENT_VALID_SMM;
        smm.smi.smm = 1;
        assert_eq!(events_to_whp(&smm).unwrap_err().errno(), libc::EINVAL);
    }

    #[test]
    fn test_fpu_roundtrip() {
        let mut fpu: kvm_fpu = unsafe { std::mem::zeroed() };
        fpu.fcw = 0x37f;
        fpu.mxcsr = 0x1f80;
        fpu.xmm[3][0] = 0xAB;
        fpu.fpr[1][2] = 0xCD;
        let mut b = [0u8; 512];
        fxsave_from_fpu(&fpu, &mut b);
        let back = fpu_from_fxsave(&b);
        assert_eq!(back.fcw, 0x37f);
        assert_eq!(back.mxcsr, 0x1f80);
        assert_eq!(back.xmm[3][0], 0xAB);
        assert_eq!(back.fpr[1][2], 0xCD);
    }
}
