// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The partition a Firecracker process makes before it needs one: parked.
//!
//! A jailed Firecracker drops to the jail's lockdown token first thing, and
//! a token whose only restricting SID is the jail's own cannot open WHP's
//! device, so no partition can be set up after that (`fs-probe whp-token`,
//! `jail-own-sid-p`: a second partition's `WHvSetupPartition` refused,
//! 0x80070005, in CI run 44215902795), while one set up before the drop
//! keeps working: memory maps, vCPUs, runs and every call a running VM makes
//! (the same record). Everything the backend sets before
//! `WHvSetupPartition` comes from the host, none of it from the VM's
//! configuration ([`super::vm`], `configure`), so the partition can be made
//! before Firecracker knows its VM: [`park_partition`] makes it, with the
//! register probe of [`super::regs`], and the VM takes it
//! ([`super::VmFd`]'s create, [`take`]).
//!
//! Upstream lets a start that failed be tried again in the same process
//! (`PrebootApiController::start_microvm` keeps the controller: a failed
//! `InstanceStart` is answered, and the next one builds a new VM), so a VM
//! dropped gives its partition back ([`recycle`]): its vCPUs deleted, its
//! memory unmapped, partition time running, and the four properties that
//! may change after set-up written back as they were parked. Then every
//! property the partition answers is read back and compared with what it
//! answered when parked (the reference time aside, a clock), and its memory
//! counters must say no page is mapped. A step that fails, or a difference,
//! deletes the partition and marks the process: the next VM is an error
//! that says to start the process again, as a jailed process can make no
//! other partition.
//!
//! What a partition keeps that WHP does not expose (the hypervisor's
//! translation caches and objects of its own) cannot be read back. A parked
//! partition is only ever used again by the same Firecracker process, for
//! the same jail, the same operator-given guest images and devices and the
//! same principal; it is never handed to another process or jail. So what
//! the hypervisor keeps in it stays within one trust domain: an unknown of
//! correctness, not of isolation (SECURITY.md).
//!
//! A process with nothing parked makes its partition when the VM is made, as
//! before: kvm-ioctls' own tests and every other binary.

use std::sync::Mutex;

use super::ffi;
use super::whv::{self, WHV_PARTITION_HANDLE};
use super::{Error, Result};

/// The property codes a partition is read back by ([`Properties`]):
/// every code of `WHV_PARTITION_PROPERTY_CODE` on x64 (WinHvPlatformDefs.h;
/// Microsoft Learn, "Partition Property Data Types"), with its name.
/// `PhysicalAddressWidth` (0x1011) is newer than windows-sys' list.
pub(crate) const PROPERTIES: [(whv::WHV_PARTITION_PROPERTY_CODE, &str); 30] = [
    (whv::WHvPartitionPropertyCodeExtendedVmExits, "ExtendedVmExits"),
    (whv::WHvPartitionPropertyCodeExceptionExitBitmap, "ExceptionExitBitmap"),
    (whv::WHvPartitionPropertyCodeSeparateSecurityDomain, "SeparateSecurityDomain"),
    (whv::WHvPartitionPropertyCodeNestedVirtualization, "NestedVirtualization"),
    (whv::WHvPartitionPropertyCodeX64MsrExitBitmap, "X64MsrExitBitmap"),
    (whv::WHvPartitionPropertyCodePrimaryNumaNode, "PrimaryNumaNode"),
    (whv::WHvPartitionPropertyCodeCpuReserve, "CpuReserve"),
    (whv::WHvPartitionPropertyCodeCpuCap, "CpuCap"),
    (whv::WHvPartitionPropertyCodeCpuWeight, "CpuWeight"),
    (whv::WHvPartitionPropertyCodeCpuGroupId, "CpuGroupId"),
    (whv::WHvPartitionPropertyCodeProcessorFrequencyCap, "ProcessorFrequencyCap"),
    (whv::WHvPartitionPropertyCodeAllowDeviceAssignment, "AllowDeviceAssignment"),
    (whv::WHvPartitionPropertyCodeDisableSmt, "DisableSmt"),
    (whv::WHvPartitionPropertyCodeProcessorFeatures, "ProcessorFeatures"),
    (whv::WHvPartitionPropertyCodeProcessorClFlushSize, "ProcessorClFlushSize"),
    (whv::WHvPartitionPropertyCodeCpuidExitList, "CpuidExitList"),
    (whv::WHvPartitionPropertyCodeCpuidResultList, "CpuidResultList"),
    (whv::WHvPartitionPropertyCodeLocalApicEmulationMode, "LocalApicEmulationMode"),
    (whv::WHvPartitionPropertyCodeProcessorXsaveFeatures, "ProcessorXsaveFeatures"),
    (whv::WHvPartitionPropertyCodeProcessorClockFrequency, "ProcessorClockFrequency"),
    (whv::WHvPartitionPropertyCodeInterruptClockFrequency, "InterruptClockFrequency"),
    (whv::WHvPartitionPropertyCodeApicRemoteReadSupport, "ApicRemoteReadSupport"),
    (whv::WHvPartitionPropertyCodeProcessorFeaturesBanks, "ProcessorFeaturesBanks"),
    (whv::WHvPartitionPropertyCodeReferenceTime, "ReferenceTime"),
    (whv::WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks, "SyntheticProcessorFeaturesBanks"),
    (whv::WHvPartitionPropertyCodeCpuidResultList2, "CpuidResultList2"),
    (whv::WHvPartitionPropertyCodeProcessorPerfmonFeatures, "ProcessorPerfmonFeatures"),
    (whv::WHvPartitionPropertyCodeMsrActionList, "MsrActionList"),
    (whv::WHvPartitionPropertyCodeUnimplementedMsrAction, "UnimplementedMsrAction"),
    (0x1011, "PhysicalAddressWidth"),
];

/// The properties set up may still change ([`super::vm`]: `tsc_write_exit`,
/// the exception exits of gdb and of an x2APIC partition), which
/// [`recycle`] writes back as they were parked; WHP refuses a write of the
/// others after set-up (0x80070057, `jail-own-sid-p`).
const AFTER_SETUP: [whv::WHV_PARTITION_PROPERTY_CODE; 4] = [
    whv::WHvPartitionPropertyCodeExtendedVmExits,
    whv::WHvPartitionPropertyCodeCpuidExitList,
    whv::WHvPartitionPropertyCodeExceptionExitBitmap,
    whv::WHvPartitionPropertyCodeX64MsrExitBitmap,
];

/// What a partition answers for each of [`PROPERTIES`]: the bytes written,
/// or the HRESULT of a refusal (a code this host's WHP does not know, or
/// one it does not read back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Properties(pub(crate) Vec<std::result::Result<Vec<u8>, i32>>);

impl Properties {
    /// Reads every property of `part`.
    pub(crate) fn of(part: WHV_PARTITION_HANDLE) -> Properties {
        Properties(
            PROPERTIES
                .iter()
                .map(|&(code, _)| {
                    let mut buf = vec![0u8; 4096];
                    let mut written = 0u32;
                    // SAFETY: a buffer of the size passed and an out-pointer.
                    let hres = unsafe {
                        whv::WHvGetPartitionProperty(part, code, buf.as_mut_ptr().cast(), 4096, &mut written)
                    };
                    if hres == 0 {
                        buf.truncate(written as usize);
                        Ok(buf)
                    } else {
                        Err(hres)
                    }
                })
                .collect(),
        )
    }

    /// The properties in which `self` and `other` differ, by name, the
    /// reference time left out (a clock: it runs on a parked partition too).
    pub(crate) fn differences(&self, other: &Properties) -> Vec<String> {
        PROPERTIES
            .iter()
            .zip(self.0.iter().zip(&other.0))
            .filter(|&(&(code, _), (a, b))| code != whv::WHvPartitionPropertyCodeReferenceTime && a != b)
            .map(|(&(_, name), (a, b))| format!("{name}: {} against {}", shown(a), shown(b)))
            .collect()
    }

    /// The bytes of `code`, if the partition answered it.
    fn bytes(&self, code: whv::WHV_PARTITION_PROPERTY_CODE) -> Option<&[u8]> {
        let i = PROPERTIES.iter().position(|&(c, _)| c == code)?;
        self.0[i].as_deref().ok()
    }
}

/// A property's answer as a line shows it.
fn shown(v: &std::result::Result<Vec<u8>, i32>) -> String {
    match v {
        Ok(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
        Err(h) => format!("HRESULT {:#010x}", h.cast_unsigned()),
    }
}

/// The pages `part` maps, 4 KiB, 2 MiB and 1 GiB (`WHvGetPartitionCounters`,
/// `WHvPartitionCounterSetMemory`), or the HRESULT of a refusal.
pub(crate) fn mapped_pages(part: WHV_PARTITION_HANDLE) -> std::result::Result<[u64; 3], i32> {
    let mut c = whv::WHV_PARTITION_MEMORY_COUNTERS { Mapped4KPageCount: 0, Mapped2MPageCount: 0, Mapped1GPageCount: 0 };
    let mut written = 0u32;
    // SAFETY: a counter structure of the size passed and an out-pointer.
    let hres = unsafe {
        whv::WHvGetPartitionCounters(
            part,
            whv::WHvPartitionCounterSetMemory,
            (&raw mut c).cast(),
            u32::try_from(std::mem::size_of_val(&c)).unwrap(),
            &mut written,
        )
    };
    if hres == 0 { Ok([c.Mapped4KPageCount, c.Mapped2MPageCount, c.Mapped1GPageCount]) } else { Err(hres) }
}

/// A partition made and set up as every VM's, and what it answered then.
#[derive(Debug)]
struct Parked {
    part: WHV_PARTITION_HANDLE,
    apic: super::apicmode::LocalApic,
    reference: Properties,
}

/// The process's parked partition.
#[derive(Debug)]
enum State {
    /// Nothing parked: a VM makes its partition (kvm-ioctls' own tests,
    /// every binary but Firecracker).
    Unparked,
    /// Parked, for the next VM.
    Parked(Parked),
    /// A VM has it.
    InUse(Parked),
    /// It could not be given back as it was parked, and was deleted: why.
    Spoiled(String),
    /// [`park_partition`] failed, with this errno (its call reported).
    Failed(i32),
}

static STATE: Mutex<State> = Mutex::new(State::Unparked);

/// Makes and parks the partition the process's VM will take: the register
/// probe ([`super::regs`]) first, as a VM's creation does, then a partition
/// configured and set up as every VM's. Once per process; again is a no-op.
///
/// Where WHP is absent it reports nothing and parks nothing (`ENODEV`):
/// [`super::Kvm::new`] says so, with how to turn it on, when a VM is
/// asked for, as before. Another failure is reported by the failing call's
/// name and kept: the VM is that error.
pub fn park_partition() -> Result<()> {
    let mut state = STATE.lock().unwrap();
    match *state {
        State::Unparked => {}
        State::Failed(errno) => return Err(Error::new(errno)),
        _ => return Ok(()),
    }
    if ffi::whp_absent().is_some() {
        return Err(Error::new(libc::ENODEV));
    }
    let made = super::regs::probe_partition().and_then(|()| super::vm::make_partition());
    match made {
        Ok((part, apic)) => {
            let reference = Properties::of(part);
            *state = State::Parked(Parked { part, apic, reference });
            Ok(())
        }
        Err(e) => {
            *state = State::Failed(e.errno());
            Err(e)
        }
    }
}

/// Whether a partition is parked or in use in this process.
pub fn partition_parked() -> bool {
    matches!(*STATE.lock().unwrap(), State::Parked(_) | State::InUse(_))
}

/// The parked partition for a new VM, or none where nothing is parked (the
/// VM makes its own). A process whose partition a live VM has, or whose
/// partition could not be given back, makes no other: an error, reported
/// with what to do.
pub(crate) fn take() -> Result<Option<(WHV_PARTITION_HANDLE, super::apicmode::LocalApic)>> {
    let mut state = STATE.lock().unwrap();
    match std::mem::replace(&mut *state, State::Unparked) {
        State::Unparked => Ok(None),
        State::Parked(p) => {
            let out = (p.part, p.apic);
            *state = State::InUse(p);
            Ok(Some(out))
        }
        State::InUse(p) => {
            *state = State::InUse(p);
            ffi::report(
                log::Level::Error,
                "wick: whp: this process's VM still has the partition it made at its start (made before the jail's \
                 token, which can make no other): a second VM at once is not made; start the process again",
            );
            Err(Error::new(libc::EBUSY))
        }
        State::Spoiled(why) => {
            ffi::report(
                log::Level::Error,
                &format!(
                    "wick: whp: this process's partition, made at its start, could not be given back as it was made \
                     ({why}) and was deleted; no other can be made in this process: start it again"
                ),
            );
            *state = State::Spoiled(why);
            Err(Error::new(libc::EBUSY))
        }
        State::Failed(errno) => {
            *state = State::Failed(errno);
            Err(Error::new(errno))
        }
    }
}

/// Whether `part` is this process's parked partition, which a VM has.
pub(crate) fn is_parked(part: WHV_PARTITION_HANDLE) -> bool {
    matches!(&*STATE.lock().unwrap(), State::InUse(p) if p.part == part)
}

/// Gives the parked partition back after its VM: deletes `vcpus`, unmaps
/// `ranges` (guest physical address and size), lets partition time run if
/// `time_suspended`, writes back the properties set up may change, then
/// reads every property and the memory counters and compares them with the
/// partition as parked. Any step that fails, or any difference, deletes it
/// and spoils the process ([`take`]); the line names which.
pub(crate) fn recycle(part: WHV_PARTITION_HANDLE, vcpus: &[u32], ranges: &[(u64, u64)], time_suspended: bool) {
    let mut state = STATE.lock().unwrap();
    let parked = match std::mem::replace(&mut *state, State::Unparked) {
        State::InUse(p) if p.part == part => p,
        other => {
            *state = other;
            // Not the parked partition: deleted as any VM's.
            // SAFETY: the VM's own partition, which nothing else has.
            unsafe { whv::WHvDeletePartition(part) };
            return;
        }
    };
    match give_back(&parked, vcpus, ranges, time_suspended) {
        Ok(()) => *state = State::Parked(parked),
        Err(why) => {
            // SAFETY: the partition, which no VM has any more.
            unsafe { whv::WHvDeletePartition(part) };
            ffi::report(
                log::Level::Warn,
                &format!("wick: whp: the partition made at this process's start was deleted after its VM: {why}"),
            );
            *state = State::Spoiled(why);
        }
    }
}

/// [`recycle`]'s steps and checks; the first that fails, as a line.
fn give_back(p: &Parked, vcpus: &[u32], ranges: &[(u64, u64)], time_suspended: bool) -> std::result::Result<(), String> {
    let call = |what: String, hres: i32| {
        if hres == 0 { Ok(()) } else { Err(format!("{what} failed: HRESULT {:#010x}", hres.cast_unsigned())) }
    };
    for &index in vcpus {
        // SAFETY: a vCPU of the partition, whose VM is gone.
        call(format!("WHvDeleteVirtualProcessor({index})"), unsafe { whv::WHvDeleteVirtualProcessor(p.part, index) })?;
    }
    for &(gpa, size) in ranges {
        // SAFETY: a range the VM mapped, whose memory it no longer uses.
        call(format!("WHvUnmapGpaRange({gpa:#x}, {size:#x})"), unsafe { whv::WHvUnmapGpaRange(p.part, gpa, size) })?;
    }
    if time_suspended {
        // SAFETY: the partition, with no vCPU left to run.
        call("WHvResumePartitionTime".into(), unsafe { whv::WHvResumePartitionTime(p.part) })?;
    }
    for code in AFTER_SETUP {
        let Some(bytes) = p.reference.bytes(code) else { continue };
        // SAFETY: the bytes the partition answered for this code when parked.
        let hres = unsafe {
            whv::WHvSetPartitionProperty(p.part, code, bytes.as_ptr().cast(), u32::try_from(bytes.len()).unwrap())
        };
        call(format!("WHvSetPartitionProperty({code:#x}) back as parked"), hres)?;
    }
    let now = Properties::of(p.part);
    let diff = now.differences(&p.reference);
    if !diff.is_empty() {
        return Err(format!("its properties differ from the parked partition's: {}", diff.join("; ")));
    }
    match mapped_pages(p.part) {
        Ok([0, 0, 0]) => Ok(()),
        Ok(n) => Err(format!("it still maps pages (4 KiB, 2 MiB, 1 GiB: {n:?})")),
        Err(h) => Err(format!("WHvGetPartitionCounters(memory) failed: HRESULT {:#010x}", h.cast_unsigned())),
    }
}

/// Gives a parked partition that its VM took and did not keep (the VM's
/// set-up failed) back as [`recycle`] does.
pub(crate) fn untake(part: WHV_PARTITION_HANDLE) {
    recycle(part, &[], &[], false);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Where WHP is absent a park is ENODEV and parks nothing, and says
    // nothing: `Kvm::new` says it, with the cause and the fix, when a VM is
    // asked for, as before (ffi.rs, `test_an_absent_platform_is_said_with_its_cause_and_its_fix`,
    // `test_kvm_new_fails_with_enodev_where_the_platform_is_absent`). Where
    // WHP is there this test parks nothing: the crate's other tests share
    // the process, and a park is the process's (CI's WHP step parks, alone:
    // `test_a_recycled_partition_is_as_a_fresh_one`).
    #[test]
    fn test_a_park_where_the_platform_is_absent_parks_nothing() {
        match ffi::whp_absent() {
            Some(cause) => {
                assert_eq!(park_partition().map_err(|e| e.errno()), Err(libc::ENODEV));
                assert!(!partition_parked());
                assert!(matches!(*STATE.lock().unwrap(), State::Unparked), "{cause}");
            }
            None => eprintln!("PARKABSENT not run here: WHP is present"),
        }
    }

    // The properties a partition is read back by: each code once, the four
    // a recycle writes back among them, and the reference time, which a
    // comparison leaves out, by its code.
    #[test]
    fn test_the_properties_read_back_are_every_code_once() {
        let mut codes: Vec<_> = PROPERTIES.iter().map(|&(c, _)| c).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), PROPERTIES.len());
        for code in AFTER_SETUP {
            assert!(codes.contains(&code));
        }
        let a = Properties(PROPERTIES.iter().map(|_| Ok(vec![1])).collect());
        let mut b = a.clone();
        let time = PROPERTIES.iter().position(|&(c, _)| c == whv::WHvPartitionPropertyCodeReferenceTime).unwrap();
        b.0[time] = Ok(vec![2]);
        assert!(a.differences(&b).is_empty(), "the reference time is a clock");
        b.0[0] = Err(0x8007_0057u32.cast_signed());
        assert_eq!(a.differences(&b), vec!["ExtendedVmExits: 01 against HRESULT 0x80070057".to_string()]);
    }
}
