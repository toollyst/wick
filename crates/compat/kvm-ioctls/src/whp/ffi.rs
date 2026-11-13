// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Thin, safe-ish wrappers over the Windows Hypervisor Platform (WHP) calls
//! this backend uses, plus the register-name table.
//!
//! WHP functions return an `HRESULT`. Here they are turned into the crate's
//! `Result` with a Linux-style errno, so the rest of the backend fails the
//! way KVM ioctls do.

#![allow(non_upper_case_globals)]

use std::cell::Cell;
use std::sync::OnceLock;

use vmm_sys_util::errno::Error;
use windows_sys::Win32::Foundation::{HANDLE, S_OK};
use super::whv::{
    self as whv, WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE,
    WHV_RUN_VP_EXIT_CONTEXT,
};

use super::Result;

/// Turns an `HRESULT` into `Ok(())` or a Linux-style errno error.
pub(crate) fn hr(hres: i32) -> Result<()> {
    if hres == S_OK {
        Ok(())
    } else {
        Err(from_hresult(hres))
    }
}

thread_local! {
    /// Set while a probe runs, whose failed calls are its answers.
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` without reporting the WHP calls that fail in it ([`hr_of`]): a
/// probe's failures are its answers, not errors.
pub(crate) fn quietly<T>(f: impl FnOnce() -> T) -> T {
    let was = QUIET.replace(true);
    let out = f();
    QUIET.set(was);
    out
}

/// [`hr`] for the WHP call `call`, which on a failure also reports
/// ([`report`]) the call, what it was given (`detail`: the vCPU, the
/// registers and values) and its `HRESULT`. The errno a failure becomes
/// names neither the call nor the register (an `os error 87` is any
/// `E_INVALIDARG` and every `WHV_E_*`), and Firecracker logs only that.
pub(crate) fn hr_of(call: &str, hres: i32, detail: impl FnOnce() -> String) -> Result<()> {
    if hres != S_OK && !QUIET.get() {
        report(
            log::Level::Error,
            &format!("whp: {call}({}) failed: HRESULT {:#010x}", detail(), hres.cast_unsigned()),
        );
    }
    hr(hres)
}

/// Reports what the backend found wrong: on standard error, the only output
/// before Firecracker's logger is set up (and the one a test sees), and
/// through the `log` facade, which is Firecracker's logger: its log file
/// holds the line too, with its time and thread.
pub(crate) fn report(level: log::Level, line: &str) {
    eprintln!("{line}");
    log::log!(level, "{line}");
}

/// The registers of a call, `name` or `name=value` (the low 64 bits).
fn registers(names: &[WHV_REGISTER_NAME], values: Option<&[WHV_REGISTER_VALUE]>) -> String {
    let mut out = Vec::with_capacity(names.len());
    for (i, n) in names.iter().enumerate() {
        out.push(match values {
            Some(v) => format!("{n:#x}={:#x}", as_u64(&v[i])),
            None => format!("{n:#x}"),
        });
    }
    out.join(", ")
}

/// `WHV_E_VP_ALREADY_EXISTS` (winhvplatformdefs.h).
const WHV_E_VP_ALREADY_EXISTS: i32 = 0x8037_0306u32 as i32;

/// Maps a WHP `HRESULT` to the errno KVM gives for the same failure, in
/// the compat libc's errno values (each `libc::E*` is a Win32 code,
/// `windows_errno.rs`). A Win32 error (`FACILITY_WIN32`, `0x8007xxxx`:
/// `E_INVALIDARG`, `E_ACCESSDENIED`, `E_OUTOFMEMORY` among them) is its
/// code through [`libc::wick_errno_from_win32`], so a synonym of a
/// constant gives that constant; `E_NOTIMPL` is `ENOSYS`; a vCPU that
/// exists already is `EEXIST`, as `KVM_CREATE_VCPU` answers; every other
/// `HRESULT` (WHP's own `WHV_E_*`, the generic ones) is `EINVAL`, what KVM
/// returns for an argument it rejects.
pub(crate) fn from_hresult(hres: i32) -> Error {
    use windows_sys::Win32::Foundation::E_NOTIMPL;
    const WIN32_FACILITY: i32 = 0x8007_0000u32 as i32;
    if (hres & 0xFFFF_0000u32 as i32) == WIN32_FACILITY {
        return Error::new(libc::wick_errno_from_win32(hres & 0xFFFF));
    }
    Error::new(match hres {
        E_NOTIMPL => libc::ENOSYS,
        WHV_E_VP_ALREADY_EXISTS => libc::EEXIST,
        _ => libc::EINVAL,
    })
}

/// Whether WHP is present on this host (the hypervisor platform feature is
/// installed and enabled). Cached.
pub(crate) fn whp_present() -> bool {
    static PRESENT: OnceLock<bool> = OnceLock::new();
    *PRESENT.get_or_init(|| {
        let mut cap: whv::WHV_CAPABILITY = unsafe { std::mem::zeroed() };
        let mut written = 0u32;
        // SAFETY: valid output buffer of the given size.
        let hres = unsafe {
            whv::WHvGetCapability(
                whv::WHvCapabilityCodeHypervisorPresent,
                (&raw mut cap).cast(),
                u32::try_from(std::mem::size_of_val(&cap)).unwrap(),
                &mut written,
            )
        };
        hres == S_OK && written >= 1 && unsafe { cap.HypervisorPresent } != 0
    })
}

/// Creates a partition handle.
pub(crate) fn create_partition() -> Result<WHV_PARTITION_HANDLE> {
    let mut part: WHV_PARTITION_HANDLE = 0;
    // SAFETY: valid out-parameter.
    hr_of("WHvCreatePartition", unsafe { whv::WHvCreatePartition(&mut part) }, String::new)?;
    Ok(part)
}

/// Sets a partition property from a value struct.
///
/// # Safety
/// `value` must be a valid property value of the kind `code` expects.
pub(crate) unsafe fn set_partition_property<T>(
    part: WHV_PARTITION_HANDLE,
    code: whv::WHV_PARTITION_PROPERTY_CODE,
    value: &T,
) -> Result<()> {
    // SAFETY: the caller's contract; `value` is valid for its size.
    let hres = unsafe {
        whv::WHvSetPartitionProperty(
            part,
            code,
            (std::ptr::from_ref::<T>(value)).cast(),
            u32::try_from(std::mem::size_of::<T>()).unwrap(),
        )
    };
    hr_of("WHvSetPartitionProperty", hres, || format!("{code:#x}"))
}

/// A register value aligned on 16 bytes. The header declares
/// `WHV_UINT128` (and so `WHV_REGISTER_VALUE`) `DECLSPEC_ALIGN(16)` and WHP
/// reads and writes the arrays with aligned SSE moves; `windows-sys`'s type
/// is only 8-aligned, and an array that happened to be misaligned faulted in
/// `WHvSetVirtualProcessorRegisters` (a snapshot restore's vCPU events).
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Aligned(WHV_REGISTER_VALUE);

/// Aligned room for `n` register values: on the stack for the usual few.
/// The stack variant's size is the point (no heap allocation per call).
#[allow(clippy::large_enum_variant)]
enum Room {
    Stack([Aligned; 64], usize),
    Heap(Vec<Aligned>),
}

impl Room {
    fn new(n: usize) -> Self {
        let zero = Aligned(reg64(0));
        if n <= 64 {
            Room::Stack([zero; 64], n)
        } else {
            Room::Heap(vec![zero; n])
        }
    }

    fn slice(&mut self) -> &mut [Aligned] {
        match self {
            Room::Stack(a, n) => &mut a[..*n],
            Room::Heap(v) => v,
        }
    }
}

/// Reads several registers of a vCPU.
pub(crate) fn get_registers(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    names: &[WHV_REGISTER_NAME],
    values: &mut [WHV_REGISTER_VALUE],
) -> Result<()> {
    debug_assert_eq!(names.len(), values.len());
    let mut room = Room::new(values.len());
    let aligned = room.slice();
    #[cfg(any(test, feature = "whp-trace"))]
    let before = trace::stack();
    // SAFETY: both arrays have `names.len()` elements; `Aligned` is a
    // `WHV_REGISTER_VALUE` aligned as WHP requires.
    let hres = unsafe {
        whv::WHvGetVirtualProcessorRegisters(
            part,
            vp,
            names.as_ptr(),
            u32::try_from(names.len()).unwrap(),
            aligned.as_mut_ptr().cast(),
        )
    };
    #[cfg(any(test, feature = "whp-trace"))]
    trace::note("WHvGetVirtualProcessorRegisters", vp, names, None, before, hres);
    hr_of("WHvGetVirtualProcessorRegisters", hres, || format!("vp {vp}: {}", registers(names, None)))?;
    for (v, a) in values.iter_mut().zip(aligned.iter()) {
        *v = a.0;
    }
    Ok(())
}

/// Writes several registers of a vCPU.
pub(crate) fn set_registers(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    names: &[WHV_REGISTER_NAME],
    values: &[WHV_REGISTER_VALUE],
) -> Result<()> {
    debug_assert_eq!(names.len(), values.len());
    let mut room = Room::new(values.len());
    let aligned = room.slice();
    for (a, v) in aligned.iter_mut().zip(values) {
        *a = Aligned(*v);
    }
    #[cfg(any(test, feature = "whp-trace"))]
    let before = trace::stack();
    // SAFETY: both arrays have `names.len()` elements, aligned (`Aligned`).
    let hres = unsafe {
        whv::WHvSetVirtualProcessorRegisters(
            part,
            vp,
            names.as_ptr(),
            u32::try_from(names.len()).unwrap(),
            aligned.as_ptr().cast(),
        )
    };
    #[cfg(any(test, feature = "whp-trace"))]
    trace::note("WHvSetVirtualProcessorRegisters", vp, names, Some(values), before, hres);
    hr_of("WHvSetVirtualProcessorRegisters", hres, || format!("vp {vp}: {}", registers(names, Some(values))))
}

/// Reads one register of a vCPU.
pub(crate) fn get_register(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    name: WHV_REGISTER_NAME,
) -> Result<WHV_REGISTER_VALUE> {
    let mut value: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
    get_registers(part, vp, &[name], std::slice::from_mut(&mut value))?;
    Ok(value)
}

/// Writes one register of a vCPU.
pub(crate) fn set_register(
    part: WHV_PARTITION_HANDLE,
    vp: u32,
    name: WHV_REGISTER_NAME,
    value: WHV_REGISTER_VALUE,
) -> Result<()> {
    set_registers(part, vp, &[name], &[value])
}

/// A 64-bit register value.
pub(crate) fn reg64(v: u64) -> WHV_REGISTER_VALUE {
    let mut value: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
    value.Reg64 = v;
    value
}

/// Reads the 64-bit field of a register value.
pub(crate) fn as_u64(value: &WHV_REGISTER_VALUE) -> u64 {
    // SAFETY: `Reg64` reads the low 64 bits of the union, valid for any value.
    unsafe { value.Reg64 }
}

/// Runs a vCPU until it exits, returning the exit context.
pub(crate) fn run_vp(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<WHV_RUN_VP_EXIT_CONTEXT> {
    // Aligned as the header's type (see `Aligned`).
    #[repr(C, align(16))]
    struct Exit(WHV_RUN_VP_EXIT_CONTEXT);
    // SAFETY: all-zero is a valid exit context.
    let mut ctx = Exit(unsafe { std::mem::zeroed() });
    #[cfg(any(test, feature = "whp-trace"))]
    let before = trace::start();
    #[cfg(any(test, feature = "whp-trace"))]
    let faults = libc::wick_mm::host_faults_on_this_thread().0;
    // SAFETY: valid output buffer of the given size.
    let hres = unsafe {
        whv::WHvRunVirtualProcessor(
            part,
            vp,
            (&raw mut ctx.0).cast(),
            u32::try_from(std::mem::size_of_val(&ctx.0)).unwrap(),
        )
    };
    #[cfg(any(test, feature = "whp-trace"))]
    trace::note_exit("WHvRunVirtualProcessor", vp, &[], None, before, hres, Some(ctx.0.ExitReason), || {
        trace::exit_detail(&ctx.0, faults)
    });
    hr_of("WHvRunVirtualProcessor", hres, || format!("vp {vp}"))?;
    Ok(ctx.0)
}

/// Asks a running vCPU to exit `WHvRunVirtualProcessor` as soon as possible.
pub(crate) fn cancel_run(part: WHV_PARTITION_HANDLE, vp: u32) -> Result<()> {
    // SAFETY: plain call; harmless if the vCPU is not running.
    hr_of("WHvCancelRunVirtualProcessor", unsafe { whv::WHvCancelRunVirtualProcessor(part, vp, 0) }, || {
        format!("vp {vp}")
    })
}

/// A Windows handle wrapper that closes on drop.
#[derive(Debug)]
pub(crate) struct OwnedHandle(pub HANDLE);

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: closes the handle this wrapper owns.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

/// For a test: the WHP calls a thread makes, each with its `HRESULT` and
/// with how much of the thread's stack was committed before and after it.
/// A call that leaves more committed than it found is the one whose pages
/// stay resident in that thread's stack for the thread's life (Windows
/// commits a stack's pages as they are first touched and keeps them). The
/// calls are kept as they were given and made into lines by the test, after
/// it has read the stack for the last time, so that no line's making is in
/// what it measures.
///
/// With the `whp-trace` feature (a build for a record, never a release),
/// every such call during which the thread's committed stack grew by
/// [`trace::GREW`] or more is also printed on standard error as it
/// returns, a `WHPTRACE` line: which call it is that commits a booted
/// guest's vCPU thread's stack, which the record test's steps do not show.
#[cfg(any(test, feature = "whp-trace"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod trace {
    use std::cell::{Cell, RefCell};
    use std::time::Instant;

    use super::{WHV_REGISTER_NAME, WHV_REGISTER_VALUE};

    /// One WHP call.
    pub(crate) struct Call {
        pub call: &'static str,
        pub vp: u32,
        pub names: Vec<WHV_REGISTER_NAME>,
        /// The low 64 bits of each value written; none for a read.
        pub values: Option<Vec<u64>>,
        pub hres: i32,
        /// Bytes of the thread's stack committed before and after the call.
        pub before: usize,
        pub after: usize,
        /// For `WHvRunVirtualProcessor`, the exit reason it returned.
        pub exit: Option<i32>,
        /// What else the call is known by ([`exit_detail`] for a run).
        pub detail: String,
        /// When a timed call ([`start`]) began, and when each call ended.
        pub began: Option<Instant>,
        pub ended: Instant,
        /// The first-chance exceptions raised on the thread since its
        /// previous traced call ended ([`count_exceptions`]): within this call, as no
        /// code of ours between two calls raises one but the lazy-RAM
        /// faults the memory module resolves before any later handler.
        pub raised: Raised,
    }

    /// First-chance exceptions counted on a thread by [`count_exceptions`]'
    /// handler: C++ exceptions (`0xE06D7363`, MSVC's `_CxxThrowException`)
    /// and the others, with the last other code.
    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct Raised {
        pub cxx: u32,
        pub other: u32,
        pub last_other: u32,
    }

    impl Raised {
        fn since(self, earlier: Raised) -> Raised {
            Raised {
                cxx: self.cxx - earlier.cxx,
                other: self.other - earlier.other,
                last_other: if self.other != earlier.other { self.last_other } else { 0 },
            }
        }

        /// `N C++, M other (last 0x..)`, or empty for none.
        pub(crate) fn text(self) -> String {
            match (self.cxx, self.other) {
                (0, 0) => String::new(),
                (c, 0) => format!("{c} C++ (0xe06d7363)"),
                (c, o) => format!("{c} C++ (0xe06d7363), {o} other (last {:#010x})", self.last_other),
            }
        }

        pub(crate) fn add(self, other: Raised) -> Raised {
            Raised {
                cxx: self.cxx + other.cxx,
                other: self.other + other.other,
                last_other: if other.other != 0 { other.last_other } else { self.last_other },
            }
        }
    }

    /// The fields of `EXCEPTION_RECORD` and `EXCEPTION_POINTERS` read here.
    #[repr(C)]
    struct ExceptionRecord {
        code: u32,
    }
    #[repr(C)]
    struct ExceptionPointers {
        record: *const ExceptionRecord,
        _context: *mut core::ffi::c_void,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
        ) -> *mut core::ffi::c_void;
    }

    thread_local! {
        static RAISED: Cell<Raised> = const { Cell::new(Raised { cxx: 0, other: 0, last_other: 0 }) };
        static LAST_RAISED: Cell<Raised> = const { Cell::new(Raised { cxx: 0, other: 0, last_other: 0 }) };
        static STARTED: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    /// Counts each first-chance exception on its thread and lets it go on
    /// (`EXCEPTION_CONTINUE_SEARCH`): last in the chain, so what a handler
    /// before it resolves is not counted.
    unsafe extern "system" fn counter(info: *mut ExceptionPointers) -> i32 {
        // SAFETY: the system passes a valid EXCEPTION_POINTERS with its record.
        let code = unsafe { (*(*info).record).code };
        RAISED.set({
            let r = RAISED.get();
            if code == 0xE06D_7363 {
                Raised { cxx: r.cxx + 1, ..r }
            } else {
                Raised { other: r.other + 1, last_other: code, ..r }
            }
        });
        0
    }

    /// Installs [`counter`] once in the process.
    pub(crate) fn count_exceptions() {
        static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            // SAFETY: a handler that only counts; never removed.
            let h = unsafe { AddVectoredExceptionHandler(0, counter) };
            assert!(!h.is_null(), "AddVectoredExceptionHandler failed");
        });
    }

    /// [`stack`] for a call that is also timed: its line gives how long it
    /// took.
    pub(crate) fn start() -> usize {
        STARTED.set(Some(Instant::now()));
        stack()
    }

    /// How a call the emulator makes through its callbacks, within
    /// `WHvEmulatorTryMmioEmulation` (traced itself), is named: a nested
    /// call, whose stack is the outer call's too.
    pub(crate) const NESTED: &str = "the emulator's ";

    impl Call {
        /// `call(vp n: name=value, ..)`.
        pub(crate) fn line(&self) -> String {
            let mut registers = Vec::with_capacity(self.names.len());
            for (i, n) in self.names.iter().enumerate() {
                registers.push(match &self.values {
                    Some(v) => format!("{n:#x}={:#x}", v[i]),
                    None => format!("{n:#x}"),
                });
            }
            let registers = if registers.is_empty() { String::new() } else { format!(": {}", registers.join(", ")) };
            let exit = self.exit.map_or(String::new(), |e| format!(", exit reason {e:#x}"));
            let detail = if self.detail.is_empty() { String::new() } else { format!(" ({})", self.detail) };
            let took = self.micros().map_or(String::new(), |us| format!(", {us:.1} us"));
            let raised = self.raised.text();
            let raised = if raised.is_empty() { raised } else { format!(", first-chance exceptions {raised}") };
            format!(
                "{}(vp {}{registers}) HRESULT {:#010x}{exit}{detail}, stack {} -> {} KiB{took}{raised}",
                self.call,
                self.vp,
                self.hres.cast_unsigned(),
                self.before / 1024,
                self.after / 1024
            )
        }

        /// How long a timed call took, in microseconds.
        pub(crate) fn micros(&self) -> Option<f64> {
            self.began.map(|b| self.ended.duration_since(b).as_secs_f64() * 1e6)
        }

        /// Whether the call was made within another traced one ([`NESTED`]).
        pub(crate) fn nested(&self) -> bool {
            self.call.starts_with(NESTED)
        }
    }

    /// What a run's exit was about: for a memory access, its GPA, kind and
    /// GVA; the RIP; and the accesses of the thread's own to lazy guest RAM
    /// that the exception handler committed during the call
    /// (`wick_mm::host_faults_on_this_thread`), with the most of the stack
    /// committed at the handler's entry. `faults` is their count before the
    /// call.
    pub(crate) fn exit_detail(ctx: &super::WHV_RUN_VP_EXIT_CONTEXT, faults: u64) -> String {
        let mut d = Vec::new();
        if ctx.ExitReason == super::whv::WHvRunVpExitReasonMemoryAccess {
            // SAFETY: the union arm matches the exit reason; the
            // access-info bitfield overlaps the u32.
            let (mem, info) = unsafe { (ctx.Anonymous.MemoryAccess, ctx.Anonymous.MemoryAccess.AccessInfo.AsUINT32) };
            // `WHV_MEMORY_ACCESS_INFO`: AccessType in bits 0-1, GpaUnmapped
            // bit 2, GvaValid bit 3.
            let kind = ["read", "write", "execute", "access type 3"][(info & 3) as usize];
            let unmapped = if info & 4 != 0 { ", unmapped" } else { "" };
            d.push(format!("gpa {:#x} {kind}{unmapped}", mem.Gpa));
            if info & 8 != 0 {
                d.push(format!("gva {:#x}", mem.Gva));
            }
        }
        if ctx.ExitReason == super::whv::WHvRunVpExitReasonException {
            // SAFETY: the union arm matches the exit reason.
            let ex = unsafe { ctx.Anonymous.VpException };
            let bytes = &ex.InstructionBytes[..usize::from(ex.InstructionByteCount).min(16)];
            d.push(format!(
                "exception vector {}, error code {:#x}, parameter {:#x}, instruction bytes {bytes:02x?}",
                ex.ExceptionType, ex.ErrorCode, ex.ExceptionParameter
            ));
        }
        d.push(format!("rip {:#x}", ctx.VpContext.Rip));
        let (now, deepest) = libc::wick_mm::host_faults_on_this_thread();
        if now != faults {
            d.push(format!(
                "the thread's own accesses to lazy guest RAM that the exception handler committed during the call: {} \
                 (the thread's stack at most {} KiB committed at the handler's entry)",
                now - faults,
                deepest / 1024
            ));
        }
        d.join(", ")
    }

    /// What a call must commit of its thread's stack for a `WHPTRACE`
    /// line: the first refused call on a thread commits 32 KiB (CI run
    /// 43392627996), any other at most 4 (run 43397419784).
    #[cfg(feature = "whp-trace")]
    pub(crate) const GREW: usize = 16 * 1024;

    thread_local! {
        /// The calls of this thread since [`begin`]; none kept before it.
        static CALLS: RefCell<Option<Vec<Call>>> = const { RefCell::new(None) };
    }

    /// How much of the calling thread's stack is committed, in bytes: the
    /// TEB's `StackBase` less its `StackLimit` (`NT_TIB`, at `gs:[8]` and
    /// `gs:[0x10]` on x86-64).
    pub(crate) fn stack() -> usize {
        let (base, limit): (usize, usize);
        // SAFETY: two reads of the thread's own TEB.
        unsafe {
            core::arch::asm!(
                "mov {0}, gs:[0x8]",
                "mov {1}, gs:[0x10]",
                out(reg) base,
                out(reg) limit,
                options(nostack, readonly, preserves_flags)
            );
        }
        base - limit
    }

    /// From here the calling thread's WHP calls are kept, with the
    /// first-chance exceptions raised during each ([`count_exceptions`]).
    pub(crate) fn begin() {
        count_exceptions();
        LAST_RAISED.set(RAISED.get());
        CALLS.set(Some(Vec::new()));
    }

    /// The calls kept since [`begin`], which keeps no more.
    pub(crate) fn end() -> Vec<Call> {
        CALLS.take().unwrap_or_default()
    }

    /// Keeps a call just made, if the thread keeps its calls.
    pub(crate) fn note(
        call: &'static str,
        vp: u32,
        names: &[WHV_REGISTER_NAME],
        values: Option<&[WHV_REGISTER_VALUE]>,
        before: usize,
        hres: i32,
    ) {
        note_exit(call, vp, names, values, before, hres, None, String::new);
    }

    /// [`note`] for `WHvRunVirtualProcessor`, with the exit reason it
    /// returned: which exit it is whose handling inside WHP commits a
    /// vCPU thread's stack (a booted guest's, on a PC: 16 or 20 to 52 KiB
    /// in one run call with exit reason 1, a memory access, 9af0b63's traced
    /// boot). `detail` is made only for a call that is kept or printed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn note_exit(
        call: &'static str,
        vp: u32,
        names: &[WHV_REGISTER_NAME],
        values: Option<&[WHV_REGISTER_VALUE]>,
        before: usize,
        hres: i32,
        exit: Option<i32>,
        detail: impl FnOnce() -> String,
    ) {
        let after = stack();
        let ended = Instant::now();
        let began = STARTED.take();
        let now = RAISED.get();
        let raised = now.since(LAST_RAISED.replace(now));
        #[cfg(feature = "whp-trace")]
        let print = after >= before + GREW;
        #[cfg(not(feature = "whp-trace"))]
        let print = false;
        let keep = CALLS.with_borrow(Option::is_some);
        if !print && !keep {
            return;
        }
        let call = Call {
            call,
            vp,
            names: names.to_vec(),
            values: values.map(|v| v.iter().map(super::as_u64).collect()),
            hres,
            before,
            after,
            exit,
            detail: detail(),
            began,
            ended,
            raised,
        };
        if print {
            let thread = std::thread::current();
            eprintln!("WHPTRACE thread '{}': {}", thread.name().unwrap_or("(unnamed)"), call.line());
        }
        if keep {
            CALLS.with_borrow_mut(|calls| {
                if let Some(calls) = calls {
                    calls.push(call);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The HRESULTs WHP calls return, each as the errno KVM gives for that
    // failure (in the compat libc's values): the Win32 ones through the one
    // table, so E_INVALIDARG is EINVAL and E_OUTOFMEMORY (ERROR_OUTOFMEMORY,
    // 14) ENOMEM, not its raw code.
    #[test]
    fn test_hresults_are_kvms_errnos() {
        let errno = |h: u32| from_hresult(h as i32).errno();
        assert_eq!(errno(0x8007_0057), libc::EINVAL, "E_INVALIDARG");
        assert_eq!(errno(0x8007_0005), libc::EACCES, "E_ACCESSDENIED");
        assert_eq!(errno(0x8007_000E), libc::ENOMEM, "E_OUTOFMEMORY");
        assert_eq!(errno(0x8007_0008), libc::ENOMEM, "ERROR_NOT_ENOUGH_MEMORY");
        assert_eq!(errno(0x8007_05AF), libc::ENOMEM, "ERROR_COMMITMENT_LIMIT");
        assert_eq!(errno(0x8007_007E), libc::ENOENT, "ERROR_MOD_NOT_FOUND (no WHP)");
        assert_eq!(errno(0x8007_00AA), libc::EBUSY, "ERROR_BUSY");
        assert_eq!(errno(0x8000_4001), libc::ENOSYS, "E_NOTIMPL");
        assert_eq!(errno(0x8037_0306), libc::EEXIST, "WHV_E_VP_ALREADY_EXISTS");
        // WHP's other own codes and the generic ones: EINVAL.
        for h in [0x8037_0300u32, 0x8037_0302, 0x8037_0305, 0x8037_0307, 0x8037_0308, 0x8037_0309, 0x8000_4005] {
            assert_eq!(errno(h), libc::EINVAL, "{h:#x}");
        }
        assert!(hr(S_OK).is_ok());
    }

    // A failed call's report names each register, with the value written.
    #[test]
    fn test_a_failure_names_its_registers() {
        let names = [whv::WHvRegisterPendingInterruption, whv::WHvX64RegisterRip];
        assert_eq!(registers(&names, None), "0x80000000, 0x10");
        assert_eq!(registers(&names, Some(&[reg64(0x3_0007), reg64(0x1000)])), "0x80000000=0x30007, 0x10=0x1000");
        assert_eq!(hr_of("WHvRunVirtualProcessor", 0x8007_0057u32 as i32, || "vp 0".into()).unwrap_err().errno(), libc::EINVAL);
        assert!(quietly(|| hr_of("WHvRunVirtualProcessor", 0x8037_0305u32 as i32, || unreachable!())).is_err());
    }
}
