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

/// Writes XCR0, checked by the caller as KVM checks it (`VcpuFd::set_xcrs`).
pub(crate) fn set_xcr0(part: WHV_PARTITION_HANDLE, vp: u32, xcr0: u64) -> Result<()> {
    ffi::set_register(part, vp, whv::WHvX64RegisterXCr0, reg64(xcr0))
}

// ---- XSAVE and FPU ----

// How large a vCPU's XSAVE state is depends on the processor. `struct
// kvm_xsave` is 4096 bytes, which held every state until Intel AMX: its tile
// data alone is 8192 bytes (CPUID leaf 0xD, sub-leaf 18), and a processor
// with it has an area of 11008. A fixed 4096-byte buffer made
// `WHvGetVirtualProcessorXsaveState` fail there with
// `WHV_E_INSUFFICIENT_BUFFER` (0x80370301: "If the buffer is not large
// enough ... `BytesWritten` receives the required buffer size", Microsoft
// Learn), at the first read of a vCPU's state: Firecracker did not start on
// an Intel Xeon 6973P-C (CI run 43359525691; every host before was AMD).
//
// Linux: `KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2)` is the size a vCPU's state
// needs, at least 4096 (arch/x86/kvm/x86.c: `xstate_required_size` of the
// supported XCR0 the process may use for guests, by CPUID leaf 0xD);
// `KVM_GET_XSAVE2` copies that many bytes; `KVM_GET_XSAVE` fails with
// `EINVAL` when the state is larger than `struct kvm_xsave`; `KVM_SET_XSAVE`
// reads that many bytes and fails with `EINVAL` for a state component the
// host does not have (arch/x86/kernel/fpu/core.c,
// `fpu_copy_uabi_to_guest_fpstate`). Upstream asks for the size once and
// uses the `XSAVE2` calls with it; it also asks Linux for AMX for its
// guests (`arch_prctl(ARCH_REQ_XCOMP_GUEST_PERM)`,
// src/vmm/src/arch/x86_64/xstate.rs), so its guests have AMX on such a
// host and their state is the large one. The partition here has every
// XSAVE feature WHP offers (`vm.rs`), AMX among them: the same.

/// `sizeof(struct kvm_xsave)`: the area without its flexible array.
pub(crate) const KVM_XSAVE_LEN: usize = std::mem::size_of::<kvm_xsave>();

/// `WHV_E_INSUFFICIENT_BUFFER` (WinHvPlatformDefs.h).
const WHV_E_INSUFFICIENT_BUFFER: i32 = 0x8037_0301u32 as i32;

/// The state components an XSAVE area's header may name on this host:
/// CPUID leaf 0xD's XCR0 bits (sub-leaf 0, EDX:EAX) and IA32_XSS bits
/// (sub-leaf 1, EDX:ECX).
pub(crate) fn host_xfeatures() -> (u64, u64) {
    use core::arch::x86_64::__cpuid_count;
    let (user, supervisor) = (__cpuid_count(0xd, 0), __cpuid_count(0xd, 1));
    (
        u64::from(user.edx) << 32 | u64::from(user.eax),
        u64::from(supervisor.edx) << 32 | u64::from(supervisor.ecx),
    )
}

/// The size `KVM_CAP_XSAVE2` reports for a processor whose largest XSAVE
/// area is `standard` bytes in the standard format and `compacted` in the
/// compacted one: the larger (WHP does not say which format its buffer
/// has), at least `struct kvm_xsave`'s 4096, in whole pages (4096 was
/// taken, read and written, on every AMD host; whether WHP takes a buffer
/// that ends inside a page is not measured).
pub(crate) fn xsave_area_len_of(standard: u32, compacted: u32) -> usize {
    (standard.max(compacted) as usize).max(KVM_XSAVE_LEN).next_multiple_of(KVM_XSAVE_LEN)
}

/// The size of the XSAVE area a vCPU's state is read into and written from
/// on this host: what `KVM_CHECK_EXTENSION(KVM_CAP_XSAVE2)` returns.
pub(crate) fn xsave_area_len() -> usize {
    static LEN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LEN.get_or_init(|| {
        let (user, supervisor) = host_xfeatures();
        xsave_area_len_of(xsave_size(user, false), xsave_size(user | supervisor, true))
    })
}

/// One `WHvGetVirtualProcessorXsaveState` into `out`: the call's result and
/// the bytes written, or needed when the result is
/// `WHV_E_INSUFFICIENT_BUFFER`.
fn xsave_state(part: WHV_PARTITION_HANDLE, vp: u32, out: &mut [u8]) -> (i32, usize) {
    let mut written = 0u32;
    // SAFETY: an output buffer of the size passed.
    let hres = unsafe {
        whv::WHvGetVirtualProcessorXsaveState(
            part,
            vp,
            out.as_mut_ptr().cast(),
            u32::try_from(out.len()).unwrap_or(u32::MAX),
            &mut written,
        )
    };
    (hres, written as usize)
}

/// `KVM_GET_XSAVE` and `KVM_GET_XSAVE2`: the vCPU's XSAVE state into `out`,
/// the caller's `struct kvm_xsave` with its flexible array. The bytes
/// written. `EINVAL` when the state does not fit, as `KVM_GET_XSAVE` for a
/// state larger than `struct kvm_xsave` (Linux's `KVM_GET_XSAVE2` trusts
/// its caller's buffer to be `KVM_CAP_XSAVE2`'s size).
pub(crate) fn get_xsave(part: WHV_PARTITION_HANDLE, vp: u32, out: &mut [u8]) -> Result<usize> {
    let (hres, written) = xsave_state(part, vp, out);
    if hres == WHV_E_INSUFFICIENT_BUFFER {
        ffi::report(
            log::Level::Error,
            &format!(
                "whp: the XSAVE state of vp {vp} is {written} bytes and the buffer given for it {} \
                 (KVM_CAP_XSAVE2 reports {})",
                out.len(),
                xsave_area_len()
            ),
        );
        return err(libc::EINVAL);
    }
    ffi::hr_of("WHvGetVirtualProcessorXsaveState", hres, || format!("vp {vp}, {} bytes", out.len()))?;
    Ok(written)
}

/// The XSAVE header's `XSTATE_BV` (bytes 512 to 519 of an area, in both
/// formats: Intel SDM volume 1, 13.4.2), or `None` for an area that ends
/// before its header does.
fn xstate_bv(area: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(area.get(512..520)?.try_into().ok()?))
}

/// The XSAVE header's `XCOMP_BV` (bytes 520 to 527): bit 63 says the area
/// is in the compacted format, and the other bits which components it then
/// has room for, in order (Intel SDM volume 1, 13.4.2). WHP's areas are
/// compacted, with the supervisor components (measured: `XCOMP_BV`
/// 0x8000000000001807 on an AMD EPYC 7763, 872 bytes, CI run 43363585319);
/// KVM's are in the standard format.
fn xcomp_bv(area: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(area.get(520..528)?.try_into().ok()?))
}

/// What `KVM_SET_XSAVE` refuses with `EINVAL`: an area whose header names a
/// state component outside `supported` (arch/x86/kernel/fpu/core.c,
/// `fpu_copy_uabi_to_guest_fpstate`: `xfeatures & ~xcr0`), which a snapshot
/// of a host with other processor features has; and an area too short to
/// have a header. A compacted area that has room for such a component
/// (`XCOMP_BV`) is refused as well, whether or not the component is in use:
/// the place of every component after it depends on it.
fn check_xsave_area(area: &[u8], supported: u64) -> Result<()> {
    const COMPACTED: u64 = 1 << 63;
    match (xstate_bv(area), xcomp_bv(area)) {
        (Some(bv), Some(comp)) if bv & !supported == 0 && (comp & COMPACTED == 0 || comp & !COMPACTED & !supported == 0) => {
            Ok(())
        }
        _ => err(libc::EINVAL),
    }
}

/// `area` as `KVM_SET_XSAVE` reads it: `len` bytes, this host's size,
/// whatever size its maker had. Linux reads that many from the caller's
/// address, past the end of an area made on a host with a smaller state
/// (upstream restores a snapshot's area as it is: "Safe unless the snapshot
/// is corrupted"); here the bytes such an area does not have are zero,
/// which is what the components its header does not name are.
fn xsave_area_of_len(area: &[u8], len: usize) -> std::borrow::Cow<'_, [u8]> {
    if area.len() >= len {
        return std::borrow::Cow::Borrowed(area);
    }
    let mut whole = vec![0u8; len];
    whole[..area.len()].copy_from_slice(area);
    std::borrow::Cow::Owned(whole)
}

/// `KVM_SET_XSAVE`: the vCPU's XSAVE state from `area`, the caller's
/// `struct kvm_xsave` with its flexible array, whole.
pub(crate) fn set_xsave(part: WHV_PARTITION_HANDLE, vp: u32, area: &[u8]) -> Result<()> {
    let (user, supervisor) = host_xfeatures();
    check_xsave_area(area, user | supervisor)?;
    let area = &*xsave_area_of_len(area, xsave_area_len());
    // SAFETY: a buffer valid for the size passed.
    let hres = unsafe {
        whv::WHvSetVirtualProcessorXsaveState(
            part,
            vp,
            area.as_ptr().cast(),
            u32::try_from(area.len()).unwrap_or(u32::MAX),
        )
    };
    ffi::hr_of("WHvSetVirtualProcessorXsaveState", hres, || format!("vp {vp}, {} bytes", area.len()))
}

/// The vCPU's XSAVE state in a buffer of this module's own: of
/// [`xsave_area_len`], or, should WHP need more than CPUID led to, of the
/// size it then reports, in whole pages. The buffer and the bytes written.
pub(crate) fn read_xsave(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<(Vec<u8>, usize)> {
    let mut area = vec![0u8; xsave_area_len()];
    let (mut hres, mut written) = xsave_state(part, vp, &mut area);
    if hres == WHV_E_INSUFFICIENT_BUFFER && written > area.len() {
        area = vec![0u8; written.next_multiple_of(KVM_XSAVE_LEN)];
        (hres, written) = xsave_state(part, vp, &mut area);
    }
    ffi::hr_of("WHvGetVirtualProcessorXsaveState", hres, || format!("vp {vp}, {} bytes", area.len()))?;
    Ok((area, written))
}

// `KVM_GET_FPU` and `KVM_SET_FPU`, as Linux has them (v6.1,
// arch/x86/kvm/x86.c, `kvm_arch_vcpu_ioctl_get_fpu` and `_set_fpu`): they
// copy the x87 fields and the XMM registers between `struct kvm_fpu` and the
// FXSAVE region at the start of the vCPU's saved state, and nothing else:
//
// - not MXCSR. Neither function names `mxcsr`: a write leaves the vCPU's
//   MXCSR as it was, and a read returns 0 in it (virt/kvm/kvm_main.c,
//   `KVM_GET_FPU`: the struct is `kzalloc`ed). Upstream's `setup_fpu` passes
//   0x1f80 and its test notes that this "does not influence anything".
// - not the state's header. The fields are written into the saved image
//   whatever its `xfeatures` (`XSTATE_BV`) say, and the bits stay as they
//   were. The image is loaded with XRSTOR(S) (arch/x86/kernel/fpu/core.c,
//   `restore_fpregs_from_fpstate`), which takes a component's registers
//   from the image only where its bit is set and gives the others their
//   initial values (Intel SDM volume 1, 13.8 and 13.12). A new vCPU's image
//   has no bit set (`fpu_alloc_guest_fpstate`: `vzalloc`, then
//   `fpstate_init_user`, which writes the control word and MXCSR but not
//   `xfeatures`), so what `KVM_SET_FPU` writes to a vCPU that has not run
//   does not reach its guest: the guest starts with the initial x87 and SSE
//   state. Once the guest has run, the bits are the processor's (XSAVES at
//   the exit: set for a component not in its initial state), and a write to
//   a component in use is what the guest finds.
//
// Here the saved image is WHP's XSAVE area, and the same is done to it: the
// same fields replaced, MXCSR and the header left.
//
// A vCPU that has not run is where WHP's area is not Linux's image. A new
// vCPU's header has the SSE bit where Linux's has none (`XSTATE_BV` 0x1802
// on an AMD EPYC 7763, CI run 43363585319; 0x2 on an Intel Xeon Platinum
// 8573C, run 43374475718), WHP does not keep the bit cleared (an area
// written with `XSTATE_BV` 0 reads back 0x2 with the initial values), and
// it reads the x87 fields of an area whose x87 bit is clear as zeros. So,
// measured in run 43374475718 (FPUTEST lines), XMM registers written by
// `KVM_SET_FPU` to a vCPU that had not run reached its guest, where Linux's
// guest finds zeros, and `KVM_GET_FPU` read a control word of 0 from a new
// vCPU, where Linux reads the 0x37f of its image.
//
// Until a vCPU's first `KVM_RUN` Linux's image is known exactly, whatever
// the processor: `xfeatures` is 0 from `fpu_alloc_guest_fpstate`, and the
// one call that changes it before a run is `KVM_SET_XSAVE`, which sets the
// user components' bits to the header it is given and copies the
// components that header names (arch/x86/kernel/fpu/xstate.c,
// `copy_uabi_to_xstate`: `xsave->header.xfeatures &=
// XFEATURE_MASK_SUPERVISOR_ALL`, then `|= hdr.xfeatures`); `KVM_SET_FPU`,
// `KVM_SET_SREGS`, `KVM_SET_MSRS`, `KVM_SET_XCRS` and `KVM_SET_LAPIC` do
// not touch it (arch/x86/kvm/x86.c: the image is named in
// `kvm_arch_vcpu_ioctl_get_fpu`, `_set_fpu`, the two XSAVE ioctls and the
// reset of the MPX components on INIT). So that image is kept here
// ([`BeforeRun`]) for as long as the vCPU has not run: `KVM_GET_FPU` reads
// it, and `KVM_SET_FPU` writes it and gives WHP only the component whose
// bit Linux's header has, which is the component the guest would be given.
// From the first `KVM_RUN` on, the header is the processor's on Linux
// (XSAVES at the end of every run, with the bits of the components the
// processor holds as in use, which the SDM leaves to the processor) and
// WHP's here.

/// `XFEATURE_MASK_FP` and `XFEATURE_MASK_SSE`: the two components
/// `struct kvm_fpu` has fields of.
const XFEATURE_FP: u64 = 1 << 0;
const XFEATURE_SSE: u64 = 1 << 1;
/// `XFEATURE_MASK_YMM`: AVX, whose MXCSR is the region's too.
const XFEATURE_YMM: u64 = 1 << 2;

/// Linux's saved image of the x87 and SSE state of a vCPU that has not run
/// yet: its FXSAVE region and the two components' bits in its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BeforeRun {
    /// `fpstate->regs.xsave.header.xfeatures`, the x87 and SSE bits.
    bits: u64,
    /// `fpstate->regs.fxsave`.
    fxsave: [u8; 512],
}

impl BeforeRun {
    /// A new vCPU's: no component in use, and the control word and MXCSR
    /// `fpstate_init_fxstate` writes (0x37f, 0x1f80).
    pub(crate) fn new() -> BeforeRun {
        let mut fxsave = [0u8; 512];
        fxsave[0..2].copy_from_slice(&0x37fu16.to_le_bytes());
        fxsave[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        BeforeRun { bits: 0, fxsave }
    }

    /// `KVM_GET_FPU`: the image's fields.
    pub(crate) fn get_fpu(&self) -> kvm_fpu {
        fpu_from_fxsave(&self.fxsave)
    }

    /// `KVM_SET_XSAVE` of `area`, already accepted: the header's bits, and
    /// the components it names (`copy_uabi_to_xstate`: x87 is the region's
    /// first 160 bytes, MXCSR and its mask among them; SSE the XMM
    /// registers; MXCSR and its mask also with SSE or AVX and no x87).
    pub(crate) fn set_xsave(&mut self, area: &[u8]) {
        let bv = xstate_bv(area).unwrap_or(0);
        if bv & XFEATURE_FP != 0 {
            self.fxsave[..160].copy_from_slice(&area[..160]);
        } else if bv & (XFEATURE_SSE | XFEATURE_YMM) != 0 {
            self.fxsave[24..32].copy_from_slice(&area[24..32]);
        }
        if bv & XFEATURE_SSE != 0 {
            self.fxsave[160..416].copy_from_slice(&area[160..416]);
        }
        self.bits = bv & (XFEATURE_FP | XFEATURE_SSE);
    }

    /// `KVM_SET_FPU`: the fields into the image, and into `area`, WHP's,
    /// those of the components Linux's header has, which are what the guest
    /// is given when it first runs. Whether `area` was changed.
    fn set_fpu(&mut self, fpu: &kvm_fpu, area: &mut [u8]) -> bool {
        fxsave_from_fpu(fpu, &mut self.fxsave);
        if self.bits & XFEATURE_FP != 0 {
            area[..24].copy_from_slice(&self.fxsave[..24]);
            area[32..160].copy_from_slice(&self.fxsave[32..160]);
        }
        if self.bits & XFEATURE_SSE != 0 {
            area[160..416].copy_from_slice(&self.fxsave[160..416]);
        }
        self.bits != 0
    }

    /// `KVM_GET_XSAVE` of a vCPU that has not run: Linux's header bits for
    /// the two components in `area`, WHP's (which has the SSE bit from the
    /// start), and for an x87 not in use the initial control word, which
    /// Linux copies out for it (`__copy_xstate_to_uabi_buf`: a component
    /// that is not in the header is copied from the initial state).
    pub(crate) fn as_linux_reads(&self, area: &mut [u8]) {
        let Some(bv) = xstate_bv(area) else { return };
        let bv = (bv & !(XFEATURE_FP | XFEATURE_SSE)) | self.bits;
        area[512..520].copy_from_slice(&bv.to_le_bytes());
        if self.bits & XFEATURE_FP == 0 {
            area[0..2].copy_from_slice(&0x37fu16.to_le_bytes());
        }
    }
}

/// `KVM_GET_FPU`: the x87 fields and XMM registers of the FXSAVE region at
/// the start of the XSAVE area; `mxcsr` is 0, as Linux returns it.
/// For a vCPU that has not run, Linux's image (`before_run`).
pub(crate) fn get_fpu(part: WHV_PARTITION_HANDLE, vp: u32, before_run: Option<&BeforeRun>) -> Result<kvm_fpu> {
    if let Some(image) = before_run {
        return Ok(image.get_fpu());
    }
    let (area, _) = read_xsave(part, vp)?;
    Ok(fpu_from_fxsave(&area[..512]))
}

/// `KVM_SET_FPU`: the whole state as it is, with the x87 fields and XMM
/// registers of its FXSAVE region replaced. For a vCPU that has not run
/// (`before_run`), Linux's image takes them, and WHP those of the
/// components the guest would be given.
pub(crate) fn set_fpu(part: WHV_PARTITION_HANDLE, vp: u32, fpu: &kvm_fpu, before_run: Option<&mut BeforeRun>) -> Result<()> {
    let (mut area, _) = read_xsave(part, vp)?;
    match before_run {
        Some(image) => {
            if !image.set_fpu(fpu, &mut area) {
                return Ok(());
            }
        }
        None => fxsave_from_fpu(fpu, &mut area[..512]),
    }
    set_xsave(part, vp, &area)
}

/// What `KVM_GET_FPU` reads out of a 512-byte FXSAVE region: every field
/// of `kvm_fpu` but `mxcsr`, which Linux leaves 0.
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
        // `fpu->ftwx = fxsave->twd`: the low byte of the 16-bit field.
        ftwx: b[4],
        pad1: 0,
        last_opcode: u16_at(6),
        last_ip: u64_at(8),
        last_dp: u64_at(16),
        xmm: [[0; 16]; 16],
        mxcsr: 0,
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

/// What `KVM_SET_FPU` writes into a 512-byte FXSAVE region: every field of
/// `kvm_fpu` but `mxcsr`; bytes 24 to 31 (MXCSR and its mask) and those
/// from 416 on stay as they were.
fn fxsave_from_fpu(fpu: &kvm_fpu, b: &mut [u8]) {
    b[0..2].copy_from_slice(&fpu.fcw.to_le_bytes());
    b[2..4].copy_from_slice(&fpu.fsw.to_le_bytes());
    // `fxsave->twd = fpu->ftwx`: the 16-bit field takes the byte, its high
    // byte 0.
    b[4..6].copy_from_slice(&u16::from(fpu.ftwx).to_le_bytes());
    b[6..8].copy_from_slice(&fpu.last_opcode.to_le_bytes());
    b[8..16].copy_from_slice(&fpu.last_ip.to_le_bytes());
    b[16..24].copy_from_slice(&fpu.last_dp.to_le_bytes());
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
        // x2APIC as this host's partitions' local APIC has it (`apicmode`).
        if e.function == 1 {
            e.ecx = super::apicmode::offered_leaf1_ecx(super::vm::host_local_apic(), e.ecx);
        }
        // TSC_ADJUST (leaf 7 EBX bit 1) on every host, as KVM offers it
        // ("TSC_ADJUST and ARCH_CAPABILITIES are emulated in software",
        // Linux v6.1 arch/x86/kvm/cpuid.c:648-649): the vCPU keeps the MSR
        // where the partition does not, and a guest's write moves the TSC
        // exactly (`VcpuFd::guest_tsc_write`).
        if e.function == 7 && e.index == 0 {
            e.ebx |= 1 << 1;
        }
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
            // ECX: DTES64, MONITOR, DS_CPL, VMX, SMX, EST, TM2, xTPR, PDCM.
            // TSC_DEADLINE stays, as KVM emulates the mode (`tscdeadline`).
            e.ecx &= !bits(&[2, 3, 4, 5, 6, 7, 8, 14, 15]);
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
    // The APIC ID of the host processor the query ran on: no vCPU's, and not
    // the same from one call to the next (measured: cpu-template-helper's
    // fingerprints of one host differed in 0x80000026 EDX). Firecracker
    // writes each vCPU's own into leaves 1, 0xB, 0x1F and 0x8000001E.
    match e.function {
        0x1 => e.ebx &= 0x00ff_ffff,
        0xb | 0x1f | 0x8000_0026 => e.edx = 0,
        0x8000_001e => e.eax = 0,
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
    xsave_size_by(mask, compacted, |i| {
        let r = __cpuid_count(0xd, i);
        (r.eax, r.ebx, r.ecx)
    })
}

/// [`xsave_size`] for a processor whose CPUID leaf 0xD, sub-leaf `i`, is
/// `leaf(i)`: EAX (the component's size), EBX (its offset in the standard
/// format) and ECX (bit 1: aligned to 64 bytes in the compacted format).
/// Linux's `xstate_required_size` (arch/x86/kvm/cpuid.c).
fn xsave_size_by(mask: u64, compacted: bool, leaf: impl Fn(u32) -> (u32, u32, u32)) -> u32 {
    const START: u32 = 512 + 64;
    let mut size = START;
    for i in 2..64u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let (eax, ebx, ecx) = leaf(i);
        if eax == 0 {
            continue;
        }
        if compacted {
            if ecx & 2 != 0 {
                size = size.div_ceil(64) * 64;
            }
            size += eax;
        } else {
            size = size.max(ebx + eax);
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
            // Leaves with meaningful sub-leaves. The caches, as KVM lists
            // them (kvm/cpuid.c): sub-leaf 0 always, then each next one while
            // the one before described a cache, the terminating null one
            // included (an AMD host's leaf 4 is that one alone).
            0x4 => cache_subleaves(&mut push, function),
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
        if function == 0x8000_001d {
            // AMD's caches, listed as leaf 4.
            cache_subleaves(&mut push, function);
        } else {
            push(function, 0, 0);
        }
    }
    out
}

/// KVM's cache leaves (4, 0x8000001D): sub-leaf 0, then the next while the
/// one before has a cache type (EAX[4:0]).
fn cache_subleaves(push: &mut impl FnMut(u32, u32, u32), function: u32) {
    use core::arch::x86_64::__cpuid_count;
    for index in 0..64 {
        push(function, index, kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX);
        if __cpuid_count(function, index).eax & 0x1f == 0 {
            break;
        }
    }
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
        _ => return partition_msrs().iter().find(|&&(i, _)| i == index).map(|&(_, n)| n),
    })
}

/// `WHvX64RegisterMsrIa32MiscEnable` (winhvplatformdefs.h, 0x20A0), which
/// windows-sys 0.61 does not name.
const MISC_ENABLE_REGISTER: WHV_REGISTER_NAME = 0x0000_20A0;

/// MSRs KVM lists for saving (KVM_GET_MSR_INDEX_LIST: x86.c's
/// msrs_to_save_base, kept where the host has them, kvm_probe_msr_to_save,
/// and emulated_msrs_all) that WHP keeps in a register, which a partition
/// has or not by the host's processor and the Windows build: listed and
/// mapped where it has them ([`partition_msrs`]). IA32_XSS, which KVM 6.12
/// does not list but upstream saves when listed (msr.rs: without it a
/// restored guest's XRSTORS of supervisor state takes #GP), is among them.
const LISTED_WHERE_PRESENT: &[(u32, WHV_REGISTER_NAME)] = &[
    (0x3b, whv::WHvX64RegisterTscAdjust),       // IA32_TSC_ADJUST
    (0x48, whv::WHvX64RegisterSpecCtrl),        // IA32_SPEC_CTRL
    (0x122, whv::WHvX64RegisterTsxCtrl),        // IA32_TSX_CTRL
    (0x1a0, MISC_ENABLE_REGISTER),              // IA32_MISC_ENABLE
    (0xe1, whv::WHvX64RegisterUmwaitControl),   // IA32_UMWAIT_CONTROL
    (0x1c4, whv::WHvX64RegisterXfd),            // IA32_XFD
    (0x1c5, whv::WHvX64RegisterXfdErr),         // IA32_XFD_ERR
    (0xda0, whv::WHvX64RegisterXss),            // IA32_XSS
    (0xd90, whv::WHvX64RegisterBndcfgs),        // IA32_BNDCFGS
    (0xc000_0103, whv::WHvX64RegisterTscAux),   // IA32_TSC_AUX
];

/// The MTRRs, which KVM gets and sets (kvm_mtrr_get_msr, kvm_mtrr_set_msr)
/// without listing them, and Firecracker's boot sets IA32_MTRR_DEF_TYPE of
/// (create_boot_msr_entries: enabled, write-back): the WHP register of
/// each, where WHP has one (16 variable pairs, the fixed ranges).
fn mtrr_register(index: u32) -> Option<WHV_REGISTER_NAME> {
    #[allow(clippy::cast_possible_wrap)]
    let n = |base: WHV_REGISTER_NAME, k: u32| base + k as WHV_REGISTER_NAME;
    Some(match index {
        0x2ff => whv::WHvX64RegisterMsrMtrrDefType,
        // IA32_MTRR_PHYSBASEn at 0x200 + 2n, IA32_MTRR_PHYSMASKn after it.
        0x200..=0x21f if index.is_multiple_of(2) => n(whv::WHvX64RegisterMsrMtrrPhysBase0, (index - 0x200) / 2),
        0x200..=0x21f => n(whv::WHvX64RegisterMsrMtrrPhysMask0, (index - 0x201) / 2),
        0x250 => whv::WHvX64RegisterMsrMtrrFix64k00000,
        0x258 => whv::WHvX64RegisterMsrMtrrFix16k80000,
        0x259 => whv::WHvX64RegisterMsrMtrrFix16kA0000,
        0x268..=0x26f => n(whv::WHvX64RegisterMsrMtrrFix4kC0000, index - 0x268),
        _ => return None,
    })
}

/// `IA32_TSC`.
pub(crate) const MSR_IA32_TSC: u32 = 0x10;
/// `IA32_TSC_ADJUST`.
pub(crate) const MSR_IA32_TSC_ADJUST: u32 = 0x3b;
/// `IA32_MISC_ENABLE`.
pub(crate) const MSR_IA32_MISC_ENABLE: u32 = 0x1a0;

/// The MSRs KVM keeps in software on every host (`ia32_tsc_adjust_msr`,
/// `ia32_misc_enable_msr`, x86.c `kvm_set_msr_common`, listed in
/// `emulated_msrs_all`), which a partition may lack as a register (an AMD
/// host's has neither, measured): the vCPU keeps them then
/// ([`software_msr`]), as KVM does.
const KVM_SOFTWARE_MSRS: [u32; 2] = [MSR_IA32_TSC_ADJUST, MSR_IA32_MISC_ENABLE];

/// Whether `index` is one of [`KVM_SOFTWARE_MSRS`] that this host's
/// partitions do not keep, so the vCPU keeps it.
pub(crate) fn software_msr(index: u32) -> bool {
    KVM_SOFTWARE_MSRS.contains(&index) && !partition_msrs().iter().any(|&(i, _)| i == index)
}

/// The candidates of [`LISTED_WHERE_PRESENT`] and the MTRRs.
fn candidates() -> Vec<(u32, WHV_REGISTER_NAME)> {
    let mut all = LISTED_WHERE_PRESENT.to_vec();
    for index in (0x200..=0x21f).chain([0x250, 0x258, 0x259, 0x2ff]).chain(0x268..=0x26f) {
        all.push((index, mtrr_register(index).unwrap()));
    }
    all
}

/// Those of [`candidates`] that a VM's partition lets a vCPU read and
/// write ([`super::vm::probe_registers`], once per process), or the errno
/// of the probe's failure: no VM is made then ([`probe_partition`]).
fn probe() -> &'static std::result::Result<Vec<(u32, WHV_REGISTER_NAME)>, i32> {
    static PRESENT: std::sync::OnceLock<std::result::Result<Vec<(u32, WHV_REGISTER_NAME)>, i32>> =
        std::sync::OnceLock::new();
    PRESENT.get_or_init(|| {
        let all = candidates();
        let names: Vec<WHV_REGISTER_NAME> = all.iter().map(|&(_, n)| n).collect();
        let ok = super::vm::probe_registers(&names).map_err(|e| e.errno())?;
        Ok(all.into_iter().zip(ok).filter_map(|(c, ok)| ok.then_some(c)).collect())
    })
}

/// [`probe`]'s registers; none where the probe failed, where no VM is
/// made.
fn partition_msrs() -> &'static [(u32, WHV_REGISTER_NAME)] {
    probe().as_deref().unwrap_or(&[])
}

/// Whether a VM's partition keeps `name`, one of the registers of
/// [`candidates`] (read and written back on a partition of its own, once
/// per process).
pub(crate) fn partition_keeps(name: WHV_REGISTER_NAME) -> bool {
    partition_msrs().iter().any(|&(_, n)| n == name)
}

/// Finds out which registers a VM's partition keeps ([`partition_msrs`]),
/// if this process has not yet: on the thread that makes a VM, never on a
/// vCPU's. The probe asks WHP for registers a partition may lack, and the
/// first call WHP refuses a thread commits 32 KiB of that thread's stack
/// for the thread's life (WinHvPlatform.dll raises and catches a C++
/// exception and looks a message up; CI run 43392627996, STACKCALL lines:
/// `WHvGetVirtualProcessorRegisters(0x2096)`, 0xc0350005, the stack from
/// 20 to 52 KiB). Left to its first use, the probe ran on whichever thread
/// first asked, which a vCPU's can be (an MSR exit, CPUID leaf 0xd). A
/// probe that could not make its partition is the VM's error: answered as
/// none, it would have every VM keep those MSRs nowhere without a word
/// (at 5386efc on a PC, whose set-up refused every partition).
pub(crate) fn probe_partition() -> Result<()> {
    probe().as_ref().map(|_| ()).map_err(|&e| super::Error::new(e))
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

/// The machine-check MSRs (the P5 pair, IA32_MCG_CAP, _STATUS and _CTL, 32
/// banks' CTL2 and four registers each) and HWCR, which the vCPU keeps as KVM keeps
/// them ([`super::mce`]): `KVM_GET_MSRS` and `KVM_SET_MSRS` have them, and
/// a write KVM refuses ends the call there (`VcpuFd::set_msrs`). Upstream
/// saves 0x400 to 0x47f of every guest whose CPUID has MCE
/// (cpu_config/x86_64/cpuid/common.rs, `msrs_to_save_by_cpuid`), which is
/// every guest: a call that ended at 0x400 failed every vCPU's save (CI run
/// 43392627996, vmm's `test_vcpu_save_state_events`). Not IA32_MCG_CAP
/// and IA32_MCG_STATUS, which WHP keeps itself ([`super::mce::whp_answers`]).
fn mce_msr(index: u32) -> bool {
    super::mce::is_mce(index) && !super::mce::whp_answers(index)
}

/// Whether `KVM_GET_MSRS` and `KVM_SET_MSRS` have `index` here: an MSR with
/// a WHP register or a segment's base, one the vCPU keeps (kvm-clock's two,
/// IA32_TSC_DEADLINE, [`KVM_SOFTWARE_MSRS`]), or one of KVM's that a
/// partition has only on some hosts ([`LISTED_WHERE_PRESENT`], the MTRRs),
/// which stays as it was where the partition lacks it: read as 0, a write
/// dropped (Firecracker's boot writes IA32_MTRR_DEF_TYPE on every host);
/// or a machine-check MSR, kept by the vCPU ([`mce_msr`]).
///
/// Any other MSR is one this backend keeps nowhere, so a value written to
/// it would reach no guest: it ends the call, as an MSR KVM does not have
/// ends KVM's.
pub(crate) fn has_msr(index: u32) -> bool {
    msr_register(index).is_some()
        || msr_segment_base(index).is_some()
        || LISTED_WHERE_PRESENT.iter().any(|&(i, _)| i == index)
        || mtrr_register(index).is_some()
        || mce_msr(index)
        || matches!(
            index,
            super::pvclock::MSR_WALL_CLOCK | super::pvclock::MSR_SYSTEM_TIME | super::tscdeadline::MSR_TSC_DEADLINE
        )
}

/// Reads MSRs into `msrs`, from the WHP registers they map to, up to the
/// first one the backend does not have ([`has_msr`]); returns how many
/// were read, as KVM does (Linux v6.1 arch/x86/kvm/x86.c, `__msr_io`: the
/// loop breaks at the first MSR `do_get_msr` fails for and returns its
/// position, and `kvm_get_msr_ignored_check` fails for one KVM has no case
/// for unless the module was loaded with `ignore_msrs`). Upstream reports
/// the MSR at that position (`KvmVcpuError::VcpuGetMsr`). Before, every MSR
/// counted, so a CPU template's modifier of an MSR kept nowhere (0x10a,
/// IA32_ARCH_CAPABILITIES, in T2S and T2CL) was read as 0, modified, and
/// dropped at the write without a word.
pub(crate) fn get_msrs(part: WHV_PARTITION_HANDLE, vp: u32, msrs: &mut Msrs) -> Result<usize> {
    let entries = msrs.as_mut_slice();
    let mut count = 0;
    for e in entries.iter_mut() {
        if !has_msr(e.index) {
            break;
        }
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

/// Writes MSRs to the WHP registers they map to, up to the first one the
/// backend does not have ([`has_msr`]), and returns how many that is, as
/// KVM's `__msr_io` does ([`get_msrs`]); upstream fails on a count short of
/// the list (`VcpuSetMsrsIncomplete`, `MsrError::SetMsrsIncomplete`).
///
/// IA32_TSC is not written here: the vCPU writes it after the others, by
/// KVM's TSC matching (`VcpuShared::synchronize_tsc`). KVM takes the host's
/// writes of IA32_TSC and IA32_TSC_ADJUST as independent (x86.c,
/// kvm_set_msr_common: only a guest's write of either moves the other), and
/// a restore writes both in the list's order, the TSC first. Whether WHP
/// moves the TSC at a write of its TscAdjust register is not documented, so
/// the TSC is written after it, and the guest gets the saved TSC either way
/// (`test_tsc_and_its_adjust_restore_as_saved`, on WHP).
pub(crate) fn set_msrs(part: WHV_PARTITION_HANDLE, vp: u32, msrs: &Msrs) -> Result<usize> {
    let count = msrs.as_slice().iter().take_while(|e| has_msr(e.index)).count();
    let entries = &msrs.as_slice()[..count];
    for e in entries.iter().filter(|e| e.index != MSR_IA32_TSC) {
        if let Some(name) = msr_register(e.index) {
            ffi::set_register(part, vp, name, reg64(e.data))?;
        } else if let Some(seg) = msr_segment_base(e.index) {
            let mut value = ffi::get_register(part, vp, seg)?;
            value.Segment.Base = e.data;
            ffi::set_register(part, vp, seg, value)?;
        }
    }
    Ok(count)
}

/// The MSR indices this backend can get and set.
pub(crate) fn msr_index_list() -> Result<MsrList> {
    // As KVM's KVM_GET_MSR_INDEX_LIST, without EFER, FS_BASE and GS_BASE,
    // which are kvm_sregs' (a snapshot saves them there); listed, they were
    // dumped by cpu-template-helper as MSRs of the template, at their value
    // before the guest ran.
    let indices: Vec<u32> = [
        0x1b, 0x10, 0x174, 0x175, 0x176, 0x277,
        0xc000_0081, 0xc000_0082, 0xc000_0083, 0xc000_0084,
        0xc000_0102,
        // kvm-clock (pvclock).
        super::pvclock::MSR_WALL_CLOCK, super::pvclock::MSR_SYSTEM_TIME,
        // IA32_TSC_DEADLINE (tscdeadline).
        super::tscdeadline::MSR_TSC_DEADLINE,
        // IA32_MCG_CTL and HWCR, in KVM's emulated list (x86.c,
        // `emulated_msrs_all`) and kept by the vCPU (mce). Not
        // IA32_MCG_STATUS, which KVM lists too: WHP keeps it, and the
        // backend can neither read nor write it (`mce::whp_answers`).
        super::mce::MCG_CTL, super::mce::HWCR,
    ]
    .into_iter()
    // KVM's others that this partition keeps (the MTRRs are not listed),
    // and those KVM keeps in software, kept by the vCPU where the partition
    // does not.
    .chain(
        LISTED_WHERE_PRESENT
            .iter()
            .map(|&(i, _)| i)
            .filter(|i| KVM_SOFTWARE_MSRS.contains(i) || partition_msrs().iter().any(|&(p, _)| p == *i)),
    )
    .collect();
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

    // Each candidate MSR names the WHP register the header gives it
    // (winhvplatformdefs.h): the variable MTRRs in pairs, base then mask,
    // the fixed ones in order; nothing else maps.
    #[test]
    fn test_mtrr_registers() {
        assert_eq!(mtrr_register(0x200), Some(whv::WHvX64RegisterMsrMtrrPhysBase0));
        assert_eq!(mtrr_register(0x201), Some(whv::WHvX64RegisterMsrMtrrPhysMask0));
        assert_eq!(mtrr_register(0x21e), Some(whv::WHvX64RegisterMsrMtrrPhysBaseF));
        assert_eq!(mtrr_register(0x21f), Some(whv::WHvX64RegisterMsrMtrrPhysMaskF));
        assert_eq!(mtrr_register(0x20b), Some(whv::WHvX64RegisterMsrMtrrPhysMask5));
        assert_eq!(mtrr_register(0x268), Some(whv::WHvX64RegisterMsrMtrrFix4kC0000));
        assert_eq!(mtrr_register(0x26f), Some(whv::WHvX64RegisterMsrMtrrFix4kF8000));
        assert_eq!(mtrr_register(0x2ff), Some(whv::WHvX64RegisterMsrMtrrDefType));
        for none in [0x1ff, 0x220, 0x251, 0x25a, 0x267, 0x270, 0xfe] {
            assert_eq!(mtrr_register(none), None, "{none:#x}");
        }
        assert_eq!(MISC_ENABLE_REGISTER, 0x20A0);
        // No index twice among the candidates.
        let c = candidates();
        let mut idx: Vec<u32> = c.iter().map(|&(i, _)| i).collect();
        idx.sort_unstable();
        idx.dedup();
        assert_eq!(idx.len(), c.len());
    }

    // KVM_GET_MSRS and KVM_SET_MSRS end at an MSR kept nowhere: 2 to 4,
    // which upstream's tests take for MSRs KVM lacks, and 0x10a
    // (IA32_ARCH_CAPABILITIES), the one MSR upstream's templates modify
    // (T2S, T2CL), which KVM keeps per vCPU and no WHP register holds.
    // What Firecracker's boot and a restore write stays: the boot entries
    // (arch/x86_64/msr.rs, create_boot_msr_entries) and kvm-clock's.
    // Every MSR upstream saves of a guest by its CPUID
    // (cpu_config/x86_64/cpuid/common.rs, msrs_to_save_by_cpuid: IA32_BNDCFGS
    // with MPX; the MTRRs, IA32_PAT and IA32_MTRR_DEF_TYPE with MTRR; 32
    // machine-check banks with MCE) is one KVM_GET_MSRS has here: a call
    // that ended at one of them would fail every snapshot.
    #[test]
    fn test_what_upstream_saves_by_cpuid_is_had() {
        let mtrr = (0x200..0x210).chain([0x250, 0x258, 0x259]).chain(0x268..=0x26f).chain([0x277, 0x2ff]);
        for saved in [0xd90].into_iter().chain(mtrr).chain(0x400..0x480) {
            assert!(has_msr(saved), "{saved:#x}");
        }
        // KVM's other machine-check MSRs, and what is past the banks;
        // not the two WHP keeps itself.
        assert!(!has_msr(0x179) && !has_msr(0x17a) && has_msr(0x17b));
        assert!(has_msr(0) && has_msr(1) && has_msr(0x280) && has_msr(0x29f));
        assert!(!has_msr(0x480) && !has_msr(0x3ff) && !has_msr(0x2a0));
    }

    #[test]
    fn test_msrs_kept_nowhere_end_the_call() {
        for kept_nowhere in [2, 3, 4, 0x10a, 0xce, 0x8b] {
            assert!(!has_msr(kept_nowhere), "{kept_nowhere:#x}");
        }
        let boot = [0x174, 0x175, 0x176, 0xc000_0081, 0xc000_0083, 0xc000_0102, 0xc000_0084, 0xc000_0082, 0x10, 0x1a0, 0x2ff];
        for kept in boot.into_iter().chain([0x4b56_4d00, 0x4b56_4d01, 0x6e0, 0x3b, 0x48, 0xc000_0100, 0xc000_0080]) {
            assert!(has_msr(kept), "{kept:#x}");
        }
    }

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

    /// CPUID leaf 0xD's sub-leaves of an Intel processor with AVX-512,
    /// PKRU, CET and AMX (Intel SDM volume 1, 13.5; Linux's
    /// Documentation/arch/x86/xstate.rst gives the same total, 11008): EAX
    /// size, EBX offset in the standard format, ECX (bit 0 supervisor, bit
    /// 1 aligned to 64 bytes when compacted).
    fn amx_leaf(i: u32) -> (u32, u32, u32) {
        match i {
            2 => (256, 576, 0),     // AVX
            5 => (64, 1088, 0),     // opmask
            6 => (512, 1152, 0),    // ZMM_Hi256
            7 => (1024, 1664, 0),   // Hi16_ZMM
            9 => (8, 2688, 0),      // PKRU
            11 => (16, 0, 1),       // CET_U
            12 => (24, 0, 1),       // CET_S
            17 => (64, 2752, 2),    // AMX TILECFG
            18 => (8192, 2816, 6),  // AMX TILEDATA
            _ => (0, 0, 0),
        }
    }

    /// The same without AMX: the largest state before it.
    fn avx512_leaf(i: u32) -> (u32, u32, u32) {
        if i >= 17 { (0, 0, 0) } else { amx_leaf(i) }
    }

    // The area's size on a processor with AMX, where it passes `struct
    // kvm_xsave`'s 4096 bytes (the host of CI run 43359525691, on which
    // Firecracker did not start), and on one without: computed from the
    // processor's leaf 0xD, so on any host.
    #[test]
    fn test_xsave_area_of_a_processor_with_amx() {
        let user = 0b110_0000_0010_1110_0111u64;
        let supervisor = (1 << 11) | (1 << 12);
        assert_eq!(xsave_size_by(user, false, amx_leaf), 11008);
        // Compacted: 2440 after PKRU, CET_U and CET_S to 2480, TILECFG
        // aligned to 2496, TILEDATA from 2560.
        assert_eq!(xsave_size_by(user | supervisor, true, amx_leaf), 10752);
        assert_eq!(xsave_area_len_of(11008, 10752), 12288);
        assert_eq!(xsave_size_by(user, false, avx512_leaf), 2696);
        assert_eq!(xsave_size_by(user | supervisor, true, avx512_leaf), 2480);
        assert_eq!(xsave_area_len_of(2696, 2480), 4096);
        // x87 and SSE alone, and an area of exactly a page or just past it.
        assert_eq!(xsave_area_len_of(576, 576), 4096);
        assert_eq!(xsave_area_len_of(4096, 0), 4096);
        assert_eq!(xsave_area_len_of(4097, 0), 8192);
        // This host's is what the capability reports: whole pages that hold
        // its largest area in either format.
        let (user, supervisor) = host_xfeatures();
        let len = xsave_area_len();
        assert_eq!(len % 4096, 0);
        assert!(len >= 4096 && len >= xsave_size(user, false) as usize);
        assert!(len >= xsave_size(user | supervisor, true) as usize);
        assert_eq!(super::super::cap::supported(u64::from(kvm_bindings::KVM_CAP_XSAVE2)), i32::try_from(len).unwrap());
    }

    // An area is refused, as `KVM_SET_XSAVE` refuses it with EINVAL, when
    // its header names a state component the host does not have (a
    // snapshot of a processor with AMX on one without), or when it has no
    // header.
    #[test]
    fn test_an_xsave_area_of_another_processor_is_refused() {
        let host = 0xe7u64;
        let mut area = vec![0u8; 12288];
        check_xsave_area(&area, host).unwrap();
        area[512..520].copy_from_slice(&0xe7u64.to_le_bytes());
        check_xsave_area(&area, host).unwrap();
        area[512..520].copy_from_slice(&(0xe7u64 | 1 << 18).to_le_bytes());
        assert_eq!(check_xsave_area(&area, host).unwrap_err().errno(), libc::EINVAL);
        check_xsave_area(&area, host | 3 << 17).unwrap();
        assert_eq!(check_xsave_area(&area[..527], u64::MAX).unwrap_err().errno(), libc::EINVAL);
        check_xsave_area(&area[..528], u64::MAX).unwrap();
        // WHP's areas are compacted: one with room for a component the
        // host lacks is refused though the component is not in use, and
        // the same bits mean nothing in a standard area (bit 63 clear).
        area[512..520].copy_from_slice(&0x1802u64.to_le_bytes());
        area[520..528].copy_from_slice(&(1u64 << 63 | 0x1807).to_le_bytes());
        check_xsave_area(&area, 0x1807).unwrap();
        area[520..528].copy_from_slice(&(1u64 << 63 | 0x1807 | 1 << 18).to_le_bytes());
        assert_eq!(check_xsave_area(&area, 0x1807).unwrap_err().errno(), libc::EINVAL);
        check_xsave_area(&area, 0x1807 | 3 << 17).unwrap();
        area[520..528].copy_from_slice(&(0x1807u64 | 1 << 18).to_le_bytes());
        check_xsave_area(&area, 0x1807).unwrap();
    }

    // An area of a host with a smaller state (a snapshot made without AMX,
    // restored with it) is written as one of this host's size, the rest
    // zero; one of this size or longer as it is.
    #[test]
    fn test_a_shorter_xsave_area_is_written_whole() {
        let area: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let whole = xsave_area_of_len(&area, 12288);
        assert_eq!(whole.len(), 12288);
        assert!(whole[..4096] == area[..] && whole[4096..].iter().all(|&b| b == 0));
        assert!(matches!(xsave_area_of_len(&area, 4096), std::borrow::Cow::Borrowed(_)));
        assert_eq!(xsave_area_of_len(&whole, 4096).len(), 12288);
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
                // TSC_ADJUST on every host, as KVM (cpuid.c:648-649).
                (0x7, 0) => assert_ne!(e.ebx & (1 << 1), 0, "TSC_ADJUST"),
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

    // `KVM_SET_FPU` writes Linux's fields into the saved state and leaves
    // the rest: MXCSR and its mask, the bytes after the XMM registers, and
    // the header, whose `XSTATE_BV` decides what of the region the guest is
    // given (arch/x86/kvm/x86.c, `kvm_arch_vcpu_ioctl_set_fpu`).
    // `KVM_GET_FPU` reads the same fields back and 0 for MXCSR.
    // A vCPU that has not run, as Linux has it: KVM_GET_FPU reads the
    // image (control word 0x37f from the start, then what KVM_SET_FPU
    // wrote), and WHP is given the fields of a component only once
    // KVM_SET_XSAVE has put the component in the header.
    #[test]
    fn test_a_vcpu_that_has_not_run_has_linuxs_image() {
        let mut image = BeforeRun::new();
        let new = image.get_fpu();
        assert_eq!((new.fcw, new.mxcsr, new.xmm[3]), (0x37f, 0, [0; 16]));
        // SAFETY: an all-zero kvm_fpu is valid.
        let mut fpu: kvm_fpu = unsafe { std::mem::zeroed() };
        (fpu.fcw, fpu.mxcsr) = (0x27f, 0x9f80);
        fpu.fpr[0] = [7; 16];
        fpu.xmm[3] = [0xA1; 16];
        // WHP's area for a new vCPU: the SSE bit, everything initial.
        let mut area = vec![0u8; 4096];
        area[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        area[512..520].copy_from_slice(&2u64.to_le_bytes());
        let before = area.clone();
        assert!(!image.set_fpu(&fpu, &mut area), "nothing is in use: nothing is WHP's to take");
        assert_eq!(area, before);
        let back = image.get_fpu();
        assert_eq!((back.fcw, back.fpr[0], back.xmm[3], back.mxcsr), (0x27f, [7; 16], [0xA1; 16], 0));
        // What KVM_GET_XSAVE gives of it: no component in use, the initial
        // control word.
        let mut read = before.clone();
        image.as_linux_reads(&mut read);
        assert_eq!((xstate_bv(&read), &read[0..2]), (Some(0), &0x37fu16.to_le_bytes()[..]));

        // KVM_SET_XSAVE with SSE alone in its header: SSE is in use, and
        // its registers and MXCSR are the area's; x87 stays as it was.
        let mut given = vec![0u8; 4096];
        given[512..520].copy_from_slice(&2u64.to_le_bytes());
        given[24..28].copy_from_slice(&0x1fa0u32.to_le_bytes());
        given[160 + 48..160 + 64].copy_from_slice(&[0xC3; 16]);
        image.set_xsave(&given);
        let back = image.get_fpu();
        assert_eq!((back.fcw, back.fpr[0], back.xmm[3]), (0x27f, [7; 16], [0xC3; 16]));
        assert_eq!(&image.fxsave[24..28], &0x1fa0u32.to_le_bytes());
        fpu.xmm[3] = [0xB2; 16];
        fpu.fcw = 0x7f;
        let mut area = given.clone();
        assert!(image.set_fpu(&fpu, &mut area));
        assert_eq!(&area[160 + 48..160 + 64], &[0xB2; 16], "SSE is in use: its registers are the guest's");
        assert_eq!((&area[0..2], &area[32..48]), (&[0u8; 2][..], &[0u8; 16][..]), "x87 is not: WHP keeps its own");
        assert_eq!(&area[24..28], &0x1fa0u32.to_le_bytes(), "MXCSR is not KVM_SET_FPU's");
        let mut read = given.clone();
        image.as_linux_reads(&mut read);
        assert_eq!(xstate_bv(&read), Some(2));

        // With x87 in the header too, both are written.
        given[512..520].copy_from_slice(&3u64.to_le_bytes());
        given[0..2].copy_from_slice(&0x17fu16.to_le_bytes());
        image.set_xsave(&given);
        assert_eq!(image.get_fpu().fcw, 0x17f);
        let mut area = given.clone();
        assert!(image.set_fpu(&fpu, &mut area));
        assert_eq!((&area[0..2], &area[32..48]), (&0x7fu16.to_le_bytes()[..], &[7u8; 16][..]));
    }

    #[test]
    fn test_set_fpu_leaves_mxcsr_and_the_header() {
        // An area as WHP gives one for a new vCPU: compacted, SSE and CET
        // in `XSTATE_BV`, x87 not.
        let mut area: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8 | 1).collect();
        area[512..520].copy_from_slice(&0x1802u64.to_le_bytes());
        area[520..528].copy_from_slice(&(1u64 << 63 | 0x1807).to_le_bytes());
        area[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        let before = area.clone();
        // SAFETY: an all-zero kvm_fpu is valid.
        let mut fpu: kvm_fpu = unsafe { std::mem::zeroed() };
        fpu.fcw = 0x27f;
        fpu.fsw = 0x3800;
        fpu.ftwx = 0x81;
        fpu.last_opcode = 0x1d8;
        fpu.last_ip = 0x1122_3344_5566_7788;
        fpu.last_dp = 0x99aa_bbcc_ddee_ff00;
        fpu.mxcsr = 0x9fc0;
        fpu.fpr[0] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xff, 0x3f, 0, 0, 0, 0, 0, 0];
        fpu.fpr[7][2] = 0xCD;
        fpu.xmm[3] = [0xAB; 16];
        fpu.xmm[15][15] = 0xEF;
        fxsave_from_fpu(&fpu, &mut area[..512]);
        assert_eq!(area[0..8], [0x7f, 0x02, 0x00, 0x38, 0x81, 0x00, 0xd8, 0x01]);
        assert_eq!(area[8..16], fpu.last_ip.to_le_bytes());
        assert_eq!(area[16..24], fpu.last_dp.to_le_bytes());
        assert!(area[24..32] == before[24..32], "MXCSR and its mask");
        assert!(area[32..48] == fpu.fpr[0] && area[32 + 7 * 16 + 2] == 0xCD);
        assert!(area[160 + 3 * 16..160 + 4 * 16] == [0xAB; 16] && area[160 + 15 * 16 + 15] == 0xEF);
        assert!(area[416..] == before[416..], "the region's end, the header and the components after it");
        assert_eq!((xstate_bv(&area), xcomp_bv(&area)), (Some(0x1802), Some(1 << 63 | 0x1807)));

        let back = fpu_from_fxsave(&area[..512]);
        assert_eq!((back.fcw, back.fsw, back.ftwx, back.last_opcode), (0x27f, 0x3800, 0x81, 0x1d8));
        assert_eq!((back.last_ip, back.last_dp), (fpu.last_ip, fpu.last_dp));
        assert!(back.fpr == fpu.fpr && back.xmm == fpu.xmm);
        assert_eq!(back.mxcsr, 0, "KVM_GET_FPU returns no MXCSR");
        assert_eq!((back.pad1, back.pad2), (0, 0));
        // The tag byte's neighbour is the 16-bit field's high byte: 0.
        area[5] = 0xff;
        fxsave_from_fpu(&fpu, &mut area[..512]);
        assert_eq!(area[5], 0);
    }
}
