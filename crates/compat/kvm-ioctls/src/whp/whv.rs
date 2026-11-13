// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Windows Hypervisor Platform API, loaded when first used.
//!
//! `WinHvPlatform.dll` and `WinHvEmulation.dll` exist only where the Windows
//! Hypervisor Platform feature is turned on (their dependencies are missing
//! otherwise). Linked statically, as `windows-sys` declares them, a binary
//! that uses them does not start at all on a host without the feature
//! (`STATUS_DLL_NOT_FOUND`, before `main`): not even `--version` works, and
//! nothing says why. So this module re-exports the WHP types and constants of
//! `windows-sys` and replaces the functions the backend calls with ones of
//! the same signature that load the DLL from System32 on first use. When it
//! cannot be loaded they return the load error as an `HRESULT`, so
//! [`super::Kvm::new`] fails with `ENODEV` as KVM does without `/dev/kvm`.

#![allow(non_snake_case, clippy::too_many_arguments)]

use std::ffi::CStr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{GetLastError, HMODULE};
pub(crate) use windows_sys::Win32::System::Hypervisor::*;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::HRESULT;

/// The DLLs of the API.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Dll {
    Platform,
    Emulation,
}

/// A loaded module, or the Win32 error loading it gave.
type Loaded = Result<usize, u32>;

fn module(dll: Dll) -> Loaded {
    static PLATFORM: OnceLock<Loaded> = OnceLock::new();
    static EMULATION: OnceLock<Loaded> = OnceLock::new();
    let (cell, name) = match dll {
        Dll::Platform => (&PLATFORM, "WinHvPlatform.dll"),
        Dll::Emulation => (&EMULATION, "WinHvEmulation.dll"),
    };
    *cell.get_or_init(|| {
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        // SAFETY: a NUL-terminated name; only System32 is searched, so no
        // other copy of the DLL can be picked up.
        let h: HMODULE = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if h.is_null() {
            // SAFETY: plain call.
            Err(unsafe { GetLastError() })
        } else {
            Ok(h as usize)
        }
    })
}

/// The address of `name` in `dll`, if both load.
fn proc_address(dll: Dll, name: &CStr) -> Option<usize> {
    let h = module(dll).ok()?;
    // SAFETY: a loaded module (never unloaded) and a NUL-terminated name.
    unsafe { GetProcAddress(h as HMODULE, name.as_ptr().cast()) }.map(|f| f as usize)
}

/// The `HRESULT` of a call into `dll` that could not be made: the error that
/// loading it gave, or `ERROR_PROC_NOT_FOUND` when the function is missing.
fn unavailable(dll: Dll) -> HRESULT {
    const ERROR_PROC_NOT_FOUND: u32 = 127;
    let code = module(dll).err().unwrap_or(ERROR_PROC_NOT_FOUND);
    // HRESULT_FROM_WIN32.
    #[allow(clippy::cast_possible_wrap)]
    let hr = (0x8007_0000 | (code & 0xFFFF)) as HRESULT;
    hr
}

/// `WHvCancelRunVirtualProcessor` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvCancelRunVirtualProcessor(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    flags: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE, u32, u32) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvCancelRunVirtualProcessor")) {
        // SAFETY: the address of `WHvCancelRunVirtualProcessor`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(partition, vpindex, flags) },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvCreatePartition` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvCreatePartition(partition: *mut WHV_PARTITION_HANDLE) -> HRESULT {
    type F = unsafe extern "system" fn(*mut WHV_PARTITION_HANDLE) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvCreatePartition")) {
        // SAFETY: the address of `WHvCreatePartition`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(partition) },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvCreateVirtualProcessor` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvCreateVirtualProcessor(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    flags: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE, u32, u32) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvCreateVirtualProcessor")) {
        // SAFETY: the address of `WHvCreateVirtualProcessor`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(partition, vpindex, flags) },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvDeletePartition` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvDeletePartition(partition: WHV_PARTITION_HANDLE) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvDeletePartition")) {
        // SAFETY: the address of `WHvDeletePartition`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(partition) },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvEmulatorCreateEmulator` from `winhvemulation.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvEmulatorCreateEmulator(
    callbacks: *const WHV_EMULATOR_CALLBACKS,
    emulator: *mut *mut core::ffi::c_void,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        *const WHV_EMULATOR_CALLBACKS,
        *mut *mut core::ffi::c_void,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Emulation, c"WHvEmulatorCreateEmulator")) {
        // SAFETY: the address of `WHvEmulatorCreateEmulator`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(callbacks, emulator) },
        None => unavailable(Dll::Emulation),
    }
}

/// `WHvEmulatorDestroyEmulator` from `winhvemulation.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvEmulatorDestroyEmulator(emulator: *mut core::ffi::c_void) -> HRESULT {
    type F = unsafe extern "system" fn(*mut core::ffi::c_void) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Emulation, c"WHvEmulatorDestroyEmulator")) {
        // SAFETY: the address of `WHvEmulatorDestroyEmulator`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(emulator) },
        None => unavailable(Dll::Emulation),
    }
}

/// `WHvEmulatorTryMmioEmulation` from `winhvemulation.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvEmulatorTryMmioEmulation(
    emulator: *const core::ffi::c_void,
    context: *const core::ffi::c_void,
    vpcontext: *const WHV_VP_EXIT_CONTEXT,
    mmioinstructioncontext: *const WHV_MEMORY_ACCESS_CONTEXT,
    emulatorreturnstatus: *mut WHV_EMULATOR_STATUS,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        *const core::ffi::c_void,
        *const core::ffi::c_void,
        *const WHV_VP_EXIT_CONTEXT,
        *const WHV_MEMORY_ACCESS_CONTEXT,
        *mut WHV_EMULATOR_STATUS,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Emulation, c"WHvEmulatorTryMmioEmulation")) {
        // SAFETY: the address of `WHvEmulatorTryMmioEmulation`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                emulator,
                context,
                vpcontext,
                mmioinstructioncontext,
                emulatorreturnstatus,
            )
        },
        None => unavailable(Dll::Emulation),
    }
}

/// `WHvGetCapability` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvGetCapability(
    capabilitycode: WHV_CAPABILITY_CODE,
    capabilitybuffer: *mut core::ffi::c_void,
    capabilitybuffersizeinbytes: u32,
    writtensizeinbytes: *mut u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_CAPABILITY_CODE,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvGetCapability")) {
        // SAFETY: the address of `WHvGetCapability`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                capabilitycode,
                capabilitybuffer,
                capabilitybuffersizeinbytes,
                writtensizeinbytes,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvGetVirtualProcessorInterruptControllerState` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvGetVirtualProcessorInterruptControllerState(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    state: *mut core::ffi::c_void,
    statesize: u32,
    writtensize: *mut u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| {
        proc_address(
            Dll::Platform,
            c"WHvGetVirtualProcessorInterruptControllerState",
        )
    }) {
        // SAFETY: the address of `WHvGetVirtualProcessorInterruptControllerState`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(partition, vpindex, state, statesize, writtensize)
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvGetVirtualProcessorRegisters` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvGetVirtualProcessorRegisters(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    registernames: *const WHV_REGISTER_NAME,
    registercount: u32,
    registervalues: *mut WHV_REGISTER_VALUE,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        *const WHV_REGISTER_NAME,
        u32,
        *mut WHV_REGISTER_VALUE,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvGetVirtualProcessorRegisters")) {
        // SAFETY: the address of `WHvGetVirtualProcessorRegisters`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                vpindex,
                registernames,
                registercount,
                registervalues,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvGetVirtualProcessorState` from `winhvplatform.dll`, loaded at first
/// use. Only the x2APIC record reads the local APIC's state with it
/// (`WHvVirtualProcessorStateTypeInterruptControllerState2`, against the
/// format the backend reads today); the backend does not.
///
/// # Safety
/// As the Windows function.
#[cfg(test)]
pub(crate) unsafe fn WHvGetVirtualProcessorState(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    statetype: WHV_VIRTUAL_PROCESSOR_STATE_TYPE,
    buffer: *mut core::ffi::c_void,
    buffersizeinbytes: u32,
    byteswritten: *mut u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        WHV_VIRTUAL_PROCESSOR_STATE_TYPE,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvGetVirtualProcessorState")) {
        // SAFETY: the address of `WHvGetVirtualProcessorState`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(partition, vpindex, statetype, buffer, buffersizeinbytes, byteswritten)
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvGetVirtualProcessorXsaveState` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvGetVirtualProcessorXsaveState(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    buffer: *mut core::ffi::c_void,
    buffersizeinbytes: u32,
    byteswritten: *mut u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvGetVirtualProcessorXsaveState")) {
        // SAFETY: the address of `WHvGetVirtualProcessorXsaveState`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                vpindex,
                buffer,
                buffersizeinbytes,
                byteswritten,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvMapGpaRange` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvMapGpaRange(
    partition: WHV_PARTITION_HANDLE,
    sourceaddress: *const core::ffi::c_void,
    guestaddress: u64,
    sizeinbytes: u64,
    flags: WHV_MAP_GPA_RANGE_FLAGS,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        *const core::ffi::c_void,
        u64,
        u64,
        WHV_MAP_GPA_RANGE_FLAGS,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvMapGpaRange")) {
        // SAFETY: the address of `WHvMapGpaRange`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                sourceaddress,
                guestaddress,
                sizeinbytes,
                flags,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvQueryGpaRangeDirtyBitmap` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvQueryGpaRangeDirtyBitmap(
    partition: WHV_PARTITION_HANDLE,
    guestaddress: u64,
    rangesizeinbytes: u64,
    bitmap: *mut u64,
    bitmapsizeinbytes: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE, u64, u64, *mut u64, u32) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvQueryGpaRangeDirtyBitmap")) {
        // SAFETY: the address of `WHvQueryGpaRangeDirtyBitmap`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                guestaddress,
                rangesizeinbytes,
                bitmap,
                bitmapsizeinbytes,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvRequestInterrupt` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvRequestInterrupt(
    partition: WHV_PARTITION_HANDLE,
    interrupt: *const WHV_INTERRUPT_CONTROL,
    interruptcontrolsize: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        *const WHV_INTERRUPT_CONTROL,
        u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvRequestInterrupt")) {
        // SAFETY: the address of `WHvRequestInterrupt`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(partition, interrupt, interruptcontrolsize)
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvResumePartitionTime` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvResumePartitionTime(partition: WHV_PARTITION_HANDLE) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvResumePartitionTime")) {
        // SAFETY: the address of `WHvResumePartitionTime`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(partition) },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvRunVirtualProcessor` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvRunVirtualProcessor(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    exitcontext: *mut core::ffi::c_void,
    exitcontextsizeinbytes: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        *mut core::ffi::c_void,
        u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvRunVirtualProcessor")) {
        // SAFETY: the address of `WHvRunVirtualProcessor`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                vpindex,
                exitcontext,
                exitcontextsizeinbytes,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvSetPartitionProperty` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvSetPartitionProperty(
    partition: WHV_PARTITION_HANDLE,
    propertycode: WHV_PARTITION_PROPERTY_CODE,
    propertybuffer: *const core::ffi::c_void,
    propertybuffersizeinbytes: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        WHV_PARTITION_PROPERTY_CODE,
        *const core::ffi::c_void,
        u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvSetPartitionProperty")) {
        // SAFETY: the address of `WHvSetPartitionProperty`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                propertycode,
                propertybuffer,
                propertybuffersizeinbytes,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvGetPartitionProperty` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvGetPartitionProperty(
    partition: WHV_PARTITION_HANDLE,
    propertycode: WHV_PARTITION_PROPERTY_CODE,
    propertybuffer: *mut core::ffi::c_void,
    propertybuffersizeinbytes: u32,
    writtensizeinbytes: *mut u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        WHV_PARTITION_PROPERTY_CODE,
        *mut core::ffi::c_void,
        u32,
        *mut u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvGetPartitionProperty")) {
        // SAFETY: the address of `WHvGetPartitionProperty`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                propertycode,
                propertybuffer,
                propertybuffersizeinbytes,
                writtensizeinbytes,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvSetVirtualProcessorInterruptControllerState` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvSetVirtualProcessorInterruptControllerState(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    state: *const core::ffi::c_void,
    statesize: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        *const core::ffi::c_void,
        u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| {
        proc_address(
            Dll::Platform,
            c"WHvSetVirtualProcessorInterruptControllerState",
        )
    }) {
        // SAFETY: the address of `WHvSetVirtualProcessorInterruptControllerState`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(partition, vpindex, state, statesize)
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvSetVirtualProcessorRegisters` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvSetVirtualProcessorRegisters(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    registernames: *const WHV_REGISTER_NAME,
    registercount: u32,
    registervalues: *const WHV_REGISTER_VALUE,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        *const WHV_REGISTER_NAME,
        u32,
        *const WHV_REGISTER_VALUE,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvSetVirtualProcessorRegisters")) {
        // SAFETY: the address of `WHvSetVirtualProcessorRegisters`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                vpindex,
                registernames,
                registercount,
                registervalues,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvSetVirtualProcessorXsaveState` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvSetVirtualProcessorXsaveState(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    buffer: *const core::ffi::c_void,
    buffersizeinbytes: u32,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        *const core::ffi::c_void,
        u32,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvSetVirtualProcessorXsaveState")) {
        // SAFETY: the address of `WHvSetVirtualProcessorXsaveState`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(partition, vpindex, buffer, buffersizeinbytes)
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvSetupPartition` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvSetupPartition(partition: WHV_PARTITION_HANDLE) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvSetupPartition")) {
        // SAFETY: the address of `WHvSetupPartition`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(partition) },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvSuspendPartitionTime` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvSuspendPartitionTime(partition: WHV_PARTITION_HANDLE) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvSuspendPartitionTime")) {
        // SAFETY: the address of `WHvSuspendPartitionTime`, whose signature `F` is.
        Some(p) => unsafe { std::mem::transmute::<usize, F>(p)(partition) },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvTranslateGva` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvTranslateGva(
    partition: WHV_PARTITION_HANDLE,
    vpindex: u32,
    gva: u64,
    translateflags: WHV_TRANSLATE_GVA_FLAGS,
    translationresult: *mut WHV_TRANSLATE_GVA_RESULT,
    gpa: *mut u64,
) -> HRESULT {
    type F = unsafe extern "system" fn(
        WHV_PARTITION_HANDLE,
        u32,
        u64,
        WHV_TRANSLATE_GVA_FLAGS,
        *mut WHV_TRANSLATE_GVA_RESULT,
        *mut u64,
    ) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvTranslateGva")) {
        // SAFETY: the address of `WHvTranslateGva`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(
                partition,
                vpindex,
                gva,
                translateflags,
                translationresult,
                gpa,
            )
        },
        None => unavailable(Dll::Platform),
    }
}

/// `WHvUnmapGpaRange` from `winhvplatform.dll`, loaded at first use.
///
/// # Safety
/// As the Windows function.
pub(crate) unsafe fn WHvUnmapGpaRange(
    partition: WHV_PARTITION_HANDLE,
    guestaddress: u64,
    sizeinbytes: u64,
) -> HRESULT {
    type F = unsafe extern "system" fn(WHV_PARTITION_HANDLE, u64, u64) -> HRESULT;
    static P: OnceLock<Option<usize>> = OnceLock::new();
    match *P.get_or_init(|| proc_address(Dll::Platform, c"WHvUnmapGpaRange")) {
        // SAFETY: the address of `WHvUnmapGpaRange`, whose signature `F` is.
        Some(p) => unsafe {
            std::mem::transmute::<usize, F>(p)(partition, guestaddress, sizeinbytes)
        },
        None => unavailable(Dll::Platform),
    }
}
