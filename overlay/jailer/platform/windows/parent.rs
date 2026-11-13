// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! `--parent-cgroup` on Windows: a named Job Object that holds the jails'
//! jobs.
//!
//! On Linux a jail's cgroup is `<base>/<parent>/<id>` (upstream's cgroup.rs,
//! `CgroupV1::new`, `CgroupV2::new`): the jailer writes the jail's limits to
//! the leaf, and the parent's own limits, which the operator writes, bound
//! every jail under it together. Upstream reads the parent in two places
//! (env.rs): with `--cgroup`, where the leaf is made under it, missing
//! directories with it (`create_dir_all`); and with `--cgroup-version 2` and
//! no `--cgroup`, where the jailer joins the parent itself if it exists and
//! does nothing if it does not. With version 1 and no `--cgroup` the parent
//! is not read.
//!
//! Here the parent is the Job Object `Local\wick-cgroup-<parent>`, and a
//! jail's processes are put in it and then in the jail's own job, which is
//! thereby nested in it: Windows bounds a nested job by its parent's memory
//! limit, CPU rate and processors (Microsoft Learn, "Nested Jobs"; measured
//! on Windows Server 2025 build 26100, `test_nested_jobs_on_record`). A
//! parent of several levels (`a/b`, as upstream's own test names one) is a
//! job for each level, `...-a` and `...-a/b`: a process is put in them from
//! the top down, so each is nested in the one above, and every level's
//! limits hold what is under it, as every directory's do on Linux
//! (`cgroup_values`, "A parent cgroup"). The same two places read it:
//!
//! - with `--cgroup` and a parent named on the command line, the job of
//!   every level is opened, or made if there is none, without limits, as
//!   Linux makes the directories (`create_dir_all`);
//! - with `--cgroup` and upstream's default parent (the exec file's name),
//!   and with `--cgroup-version 2` and no `--cgroup`, the job is joined if it
//!   exists and nothing is done if it does not (a parent whose last level
//!   exists while one above it does not is no directory tree: the jailer
//!   stops). The default parent is not
//!   made: a parent without limits bounds nothing, and making one would nest
//!   every jail's job on every start. Its limits come first, then its jails
//!   (the difference from Linux, where limits written later to the default
//!   parent's directory bound the jails already under it).
//!
//! The operator writes a parent's limits with tools/windows/jail-parent.rs,
//! the counterpart of `mkdir` and `echo` into the parent's directory.
//!
//! **How long a parent lasts.** A cgroup directory lasts until it is
//! removed, and cannot be removed while a cgroup is under it (`rmdir`:
//! `EBUSY`). A Job Object's name lasts as long as a handle to it is open
//! (measured: with no handle left the name is gone even while processes
//! are in the job; the job itself and its limits last as long as its
//! processes). So two things hold a parent, every level of it: the
//! operator's tool, for as long as it runs, which is what keeps an empty
//! parent and its limits; and
//! each jailer, which keeps its handles until its jail ends, so that a
//! parent with a jail in it cannot go away, name and limits, whatever
//! becomes of the tool. With neither, the parent is gone and the next jail
//! that names it makes a new one without limits: the one difference from
//! Linux, where the directory would still be there.
//!
//! **Whose job it is.** The name is in the session's object namespace, where
//! a jailed process could make a job of that name first, for later jails to
//! join. A job the jailer did not make itself is used only when it is owned
//! by the jailer's account, the administrators or the system and is not
//! labelled below medium integrity, which what a jailed process makes is
//! (`cgroup_values::trusted_parent`); otherwise the jailer stops. Every
//! level is checked.
//!
//! **What is never done.** If Windows refuses to put a process in the
//! parent's job, or in the jail's job once it is in the parent's (Microsoft
//! Learn says a job with UI limits, as a jail's is, is not nested; build
//! 26100 nests it; Windows 10, 11 and Server 2022 are not measured), the
//! jailer fails with Windows's error. It never starts the jail outside the
//! parent it was given, nor under some of its levels only.

use std::ffi::OsStr;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_OWNER, TOKEN_QUERY, TokenOwner,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    JOB_OBJECT_LIMIT_AFFINITY, JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JobObjectBasicLimitInformation, JobObjectCpuRateControlInformation, JobObjectGroupInformationEx, OpenJobObjectW,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::cgroup_values::{
    PARENT_JOB_PREFIX, cpus_of_levels, cpus_under_parent, parent_job_names, rate_of_levels, rate_under_parent, trusted_parent,
};
use super::{GroupAffinity, HostError, Limits, last_error, sid_string, token_info, user_sid, wide};

/// `JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY | READ_CONTROL`: what the
/// jailer needs of a parent's job, its owner and label among it.
const JAILER_ACCESS: u32 = 0x1 | 0x4 | 0x0002_0000;
/// `SYSTEM_MANDATORY_LABEL_ACE_TYPE` (winnt.h).
const MANDATORY_LABEL_ACE: u8 = 0x11;

/// What the command line says of the parent cgroup, kept from where
/// upstream makes its cgroup builder to where the jail's processes start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// `--cgroup-version`.
    pub version: u8,
    /// The parent: `--parent-cgroup`'s value, or the exec file's name.
    pub parent: String,
    /// Whether `--parent-cgroup` is on the command line.
    pub named: bool,
    /// Whether a `--cgroup` is.
    pub with_cgroup: bool,
}

static PLAN: Mutex<Option<Plan>> = Mutex::new(None);

/// The plan of a jailer's command line (`args`, the program first;
/// Firecracker's arguments, after `--`, are not the jailer's), for the
/// cgroup version upstream parsed. `None` when the command line names no
/// exec file to take the default parent from (upstream has refused that
/// before). Upstream's parser takes `--name value` only, and no value that
/// starts with `--`.
pub(crate) fn plan_of<S: AsRef<OsStr>>(version: u8, args: impl IntoIterator<Item = S>) -> Result<Option<Plan>, HostError> {
    let args: Vec<String> = args
        .into_iter()
        .skip(1)
        .map(|a| a.as_ref().to_string_lossy().into_owned())
        .take_while(|a| a != "--")
        .collect();
    let value_of = |name: &str| args.iter().position(|a| a == name).and_then(|at| args.get(at + 1)).cloned();
    let named = value_of("--parent-cgroup");
    let default = value_of("--exec-file")
        .and_then(|exe| Path::new(&exe).file_name().map(|name| name.to_string_lossy().into_owned()));
    let Some(parent) = named.clone().or(default) else {
        return Ok(None);
    };
    let plan = Plan { version, parent, named: named.is_some(), with_cgroup: args.iter().any(|a| a == "--cgroup") };
    // A named parent that cannot be a job's name is refused here, at the
    // argument, not when the jail starts.
    if plan.named {
        parent_job_names(&plan.parent).map_err(|why| HostError::Unsupported("parent-cgroup", why))?;
    }
    Ok(Some(plan))
}

/// Keeps the plan of this jailer's own command line.
pub(crate) fn set_plan(version: u8) -> Result<(), HostError> {
    *PLAN.lock().unwrap() = plan_of(version, std::env::args_os())?;
    Ok(())
}

/// The parent of the jail this jailer starts, if it has one: opened, or
/// made, as the plan says (the module's description).
pub(crate) fn for_jail() -> Result<Option<Parent>, HostError> {
    match PLAN.lock().unwrap().clone() {
        Some(plan) => Parent::of(&plan),
        None => Ok(None),
    }
}

/// A parent cgroup's jobs, one for each level of its path, the top first,
/// held open for as long as the jail lives.
#[derive(Debug)]
pub(crate) struct Parent {
    jobs: Vec<OwnedHandle>,
    /// The parent as the command line has it.
    name: String,
    version: u8,
    /// Whether this jailer made the last level's job (there was none of
    /// the name).
    pub(crate) created: bool,
}

impl Parent {
    pub(crate) fn of(plan: &Plan) -> Result<Option<Parent>, HostError> {
        let fail = |why: String| HostError::Parent(plan.parent.clone(), why);
        // The default parent's name is a file's name: it has one level.
        let names = parent_job_names(&plan.parent).map_err(|why| fail(why.to_string()))?;
        let make = plan.named && plan.with_cgroup;
        let mut jobs = Vec::new();
        let mut created = false;
        let mut missing = None;
        for name in &names {
            let level = name.strip_prefix(PARENT_JOB_PREFIX).unwrap_or(name);
            let (job, made) = if make {
                create_or_open(name).map_err(|e| fail(format!("the job of {name} could not be made or opened: {e}")))?
            } else {
                match open(name).map_err(|e| fail(format!("the job of {name} could not be opened: {e}")))? {
                    Some(job) => (job, false),
                    None => {
                        missing.get_or_insert(level);
                        continue;
                    }
                }
            };
            if let Some(above) = missing {
                // A level that exists under one that does not: Linux has no
                // such tree, and the limits of the level above would not
                // hold the jail.
                return Err(fail(format!("the job of {name} exists and that of {above}, above it, does not")));
            }
            if !made {
                let (owner, label) =
                    owner_and_label(&job).map_err(|e| fail(format!("the owner and label of the job of {name} could not be read: {e}")))?;
                let mine = [user_sid(), token_owner_sid()].into_iter().collect::<io::Result<Vec<String>>>();
                let mine = mine.map_err(|e| fail(format!("this process's account could not be read: {e}")))?;
                trusted_parent(&owner, label, &mine).map_err(|why| fail(format!("{name}: {why}")))?;
            }
            created = made;
            jobs.push(job);
        }
        if missing.is_some() {
            return Ok(None);
        }
        Ok(Some(Parent { jobs, name: plan.parent.clone(), version: plan.version, created }))
    }

    /// The job of the parent's last level, which a jail's own job is put
    /// under.
    pub(crate) fn job(&self) -> &OwnedHandle {
        self.jobs.last().expect("a parent has a level")
    }

    /// The jail's limits as its job under this parent takes them: the CPU
    /// rate as a share of what the parent's levels come to and the
    /// processors within theirs, by Linux's rule for the cgroup version
    /// (`cgroup_values::rate_under_parent`, `cpus_under_parent`,
    /// `rate_of_levels`, `cpus_of_levels`), which refuses with cgroup v1
    /// what Windows would narrow without a word. A limit the jail does not
    /// ask for, or no level of the parent has, is left as it is; the memory
    /// limit is the jail's own under any parent, as on Linux.
    pub(crate) fn limits(&self, limits: &Limits) -> Result<Limits, HostError> {
        let fail = |what: &str, e: io::Error| HostError::Parent(self.name.clone(), format!("its jobs' {what} could not be read: {e}"));
        let mut out = limits.clone();
        if let Some(asked) = limits.cpu_rate {
            let caps = self.jobs.iter().map(hard_cap).collect::<io::Result<Vec<_>>>().map_err(|e| fail("CPU rate", e))?;
            if let Some(parent) = rate_of_levels(&caps) {
                let file = if self.version == 1 { "cpu.cfs_quota_us" } else { "cpu.max" };
                let rate = rate_under_parent(self.version, asked, parent)
                    .map_err(|why| HostError::CgroupValue(format!("{file} under --parent-cgroup {}", self.name), why))?;
                out.cpu_rate = Some(rate);
            }
        }
        if let Some(asked) = &limits.cpus {
            let levels = self.jobs.iter().map(processors).collect::<io::Result<Vec<_>>>().map_err(|e| fail("processors", e))?;
            if let Some(parent) = cpus_of_levels(&levels) {
                let cpus = cpus_under_parent(self.version, asked, &parent)
                    .map_err(|why| HostError::CgroupValue(format!("cpuset.cpus under --parent-cgroup {}", self.name), why))?;
                out.cpus = Some(cpus);
            }
        }
        Ok(out)
    }
}

/// Puts a process of the jail, suspended still, in its jobs: the parent's
/// first, if the jail has one, from its top level down, then the jail's own
/// (the order Microsoft Learn gives for nested jobs). A refusal is Windows's error, named by the
/// step; the process is then in no job of the jail's and the caller ends
/// it.
pub(crate) fn enter(parent: Option<&Parent>, job: &OwnedHandle, process: HANDLE) -> Result<(), (&'static str, io::Error)> {
    for (level, job) in parent.iter().flat_map(|parent| parent.jobs.iter().enumerate()) {
        // SAFETY: handles the caller and the parent own.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process) } == 0 {
            let step = if level == 0 {
                "AssignProcessToJobObject: the job of the parent cgroup's first level"
            } else {
                "AssignProcessToJobObject: the job of a lower level of the parent cgroup, for a process in the level \
                 above's (this Windows did not nest the two; the jail is not started under a part of its parent)"
            };
            return Err((step, last_error()));
        }
    }
    // SAFETY: handles the caller owns.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process) } == 0 {
        let step = if parent.is_some() {
            "AssignProcessToJobObject: the jail's job, for a process in the parent cgroup's job (this Windows \
             did not nest the two; the jail is not started outside its parent)"
        } else {
            "AssignProcessToJobObject"
        };
        return Err((step, last_error()));
    }
    Ok(())
}

/// The job of the name, or `None` when there is none.
fn open(name: &str) -> io::Result<Option<OwnedHandle>> {
    // SAFETY: a NUL-terminated name.
    let h = unsafe { OpenJobObjectW(JAILER_ACCESS, 0, wide(name).as_ptr()) };
    if h.is_null() {
        let err = last_error();
        return if err.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.cast_signed()) { Ok(None) } else { Err(err) };
    }
    // SAFETY: a handle we own.
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(h) }))
}

/// The job of the name, made if there is none (and whether it was): one
/// call, so that of two jailers that start together one makes it and the
/// other opens it. A new job has no limits and does not end its processes
/// when its handles close; it grants the system and this user, and nothing
/// to a jail's SIDs.
fn create_or_open(name: &str) -> io::Result<(OwnedHandle, bool)> {
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", user_sid()?);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and an out-pointer.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&sddl).as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) }
        == 0
    {
        return Err(last_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    // SAFETY: the attributes above and a NUL-terminated name. An existing
    // job is opened and the last error says so (`CreateJobObjectW`).
    let (h, err) = unsafe {
        let h = CreateJobObjectW(&attributes, wide(name).as_ptr());
        (h, GetLastError())
    };
    // SAFETY: allocated by the conversion.
    unsafe { LocalFree(sd) };
    if h.is_null() {
        return Err(io::Error::from_raw_os_error(err.cast_signed()));
    }
    // SAFETY: a handle we own.
    Ok((unsafe { OwnedHandle::from_raw_handle(h) }, err != ERROR_ALREADY_EXISTS))
}

/// The owner of this process's token, as text: what a new object's owner
/// is (the administrators, for an elevated administrator).
fn token_owner_sid() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: our own token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error());
    }
    // SAFETY: a token handle we own.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let owner = token_info(token.as_raw_handle(), TokenOwner).map_err(io::Error::other)?;
    // SAFETY: the buffer holds a TOKEN_OWNER.
    sid_string(unsafe { (*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner })
}

/// The job's owner, as text, and the integrity level of its mandatory
/// label (`None` when it has none, which is medium).
pub(crate) fn owner_and_label(job: &OwnedHandle) -> io::Result<(String, Option<u32>)> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut owner: PSID = std::ptr::null_mut();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: a handle opened with READ_CONTROL and out-pointers.
    let rc = unsafe {
        GetSecurityInfo(
            job.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sacl,
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let read = || -> io::Result<(String, Option<u32>)> {
        let owner = sid_string(owner)?;
        let mut label = None;
        if !sacl.is_null() {
            // SAFETY: an ACL in `sd`: its header, then `AceCount` entries,
            // each a header (type, flags, size) and, for a mandatory
            // label, a mask and the label's SID.
            unsafe {
                let mut ace = sacl.cast::<u8>().add(std::mem::size_of::<ACL>());
                for _ in 0..(*sacl).AceCount {
                    let size = usize::from(ace.add(2).cast::<u16>().read_unaligned());
                    if *ace == MANDATORY_LABEL_ACE {
                        let sid = sid_string(ace.add(8).cast())?;
                        label = sid.rsplit('-').next().and_then(|level| level.parse().ok());
                    }
                    ace = ace.add(size);
                }
            }
        }
        Ok((owner, label))
    };
    let result = read();
    // SAFETY: allocated by GetSecurityInfo; `owner` and `sacl` point into it.
    unsafe { LocalFree(sd) };
    result
}

/// One information class of a job, read whole.
fn query<T>(job: &OwnedHandle, class: i32) -> io::Result<T> {
    // SAFETY: the classes read here are plain data, valid all zero.
    let mut info: T = unsafe { std::mem::zeroed() };
    // SAFETY: a structure of the size passed, for this class.
    let ok = unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            class,
            (&raw mut info).cast(),
            u32::try_from(std::mem::size_of::<T>()).unwrap(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 { Err(last_error()) } else { Ok(info) }
}

/// The job's CPU rate hard cap, in hundredths of a percent of the host's
/// processors, or `None` when it has none (no rate control, or a weight).
pub(crate) fn hard_cap(job: &OwnedHandle) -> io::Result<Option<u32>> {
    let cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = query(job, JobObjectCpuRateControlInformation)?;
    let capped = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    // SAFETY: a union of two 32-bit numbers; it is the rate with these flags.
    let rate = unsafe { cpu.Anonymous.CpuRate };
    Ok((cpu.ControlFlags & capped == capped).then_some(rate))
}

/// The processors the job's processes may run on, `(group, mask)` each:
/// its affinity when it has one (processors of the first group), else the
/// affinities by processor group Windows reports for it. `None` when
/// Windows reports no group.
pub(crate) fn processors(job: &OwnedHandle) -> io::Result<Option<Vec<(u16, u64)>>> {
    let basic: JOBOBJECT_BASIC_LIMIT_INFORMATION = query(job, JobObjectBasicLimitInformation)?;
    if basic.LimitFlags & JOB_OBJECT_LIMIT_AFFINITY != 0 {
        return Ok(Some(vec![(0, basic.Affinity as u64)]));
    }
    let mut groups = [GroupAffinity::default(); 64];
    let mut len = 0u32;
    // SAFETY: an array of the size passed, and the size written to `len`.
    let ok = unsafe {
        QueryInformationJobObject(
            job.as_raw_handle(),
            JobObjectGroupInformationEx,
            groups.as_mut_ptr().cast(),
            u32::try_from(std::mem::size_of_val(&groups)).unwrap(),
            &mut len,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    let count = (len as usize / std::mem::size_of::<GroupAffinity>()).min(groups.len());
    let found: Vec<(u16, u64)> = groups[..count].iter().map(|g| (g.group, g.mask as u64)).collect();
    Ok((!found.is_empty()).then_some(found))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Held, held_process, set_job};
    use super::*;
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    };
    use windows_sys::Win32::System::Threading::GetProcessAffinityMask;

    const MIB: usize = 1 << 20;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAllocEx(process: HANDLE, address: *const std::ffi::c_void, size: usize, kind: u32, protect: u32) -> *mut std::ffi::c_void;
    }

    fn args(extra: &[&str]) -> Vec<String> {
        ["jailer", "--id", "a", "--exec-file", r"C:\bin\firecracker.exe", "--cgroup-version", "2"]
            .iter()
            .chain(extra)
            .map(|s| (*s).to_string())
            .collect()
    }

    // What the command line says of the parent, as upstream reads it: the
    // value of --parent-cgroup, else the exec file's name; a
    // --parent-cgroup among Firecracker's arguments is not the jailer's.
    #[test]
    fn test_the_parent_is_the_named_one_or_the_exec_files_name() {
        let plan = |extra: &[&str]| plan_of(2, args(extra)).unwrap().unwrap();
        assert_eq!(plan(&[]), Plan { version: 2, parent: "firecracker.exe".into(), named: false, with_cgroup: false });
        assert_eq!(
            plan(&["--cgroup", "memory.max=1073741824", "--parent-cgroup", "tenants"]),
            Plan { version: 2, parent: "tenants".into(), named: true, with_cgroup: true }
        );
        assert!(!plan(&["--parent-cgroup", "tenants"]).with_cgroup);
        let after = plan(&["--", "--parent-cgroup", "x", "--cgroup", "y"]);
        assert_eq!((after.parent.as_str(), after.named, after.with_cgroup), ("firecracker.exe", false, false));
        assert_eq!(plan_of(1, args(&[])).unwrap().unwrap().version, 1);
        assert_eq!(plan_of(2, ["jailer", "--id", "a"]).unwrap(), None);
    }

    // A parent of several levels is kept as it is named, upstream's own
    // test's among them; one that names no level is refused at the argument.
    #[test]
    fn test_a_parent_of_several_levels_is_read() {
        let plan = plan_of(2, args(&["--parent-cgroup", "custom_cgroup/group2"])).unwrap().unwrap();
        assert_eq!((plan.parent.as_str(), plan.named), ("custom_cgroup/group2", true));
        let text = plan_of(2, args(&["--parent-cgroup", "/"])).unwrap_err().to_string();
        assert!(text.starts_with("--parent-cgroup is not supported on Windows: an empty name"), "{text}");
    }

    /// A parent's name no other test or run uses.
    fn fresh(what: &str) -> String {
        format!("wick-test-{what}-{}", std::process::id())
    }

    fn plan(parent: &str, version: u8, named: bool, with_cgroup: bool) -> Plan {
        Plan { version, parent: parent.to_string(), named, with_cgroup }
    }

    /// What the operator's tool does to a parent: its limits, through a
    /// handle of its own.
    fn tool(parent: &str) -> OwnedHandle {
        let names = parent_job_names(parent).unwrap();
        names.iter().map(|name| create_or_open(name).unwrap().0).last().unwrap()
    }

    fn extended(flags: u32, memory: usize, affinity: usize) -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        // SAFETY: plain data.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = flags;
        info.BasicLimitInformation.Affinity = affinity;
        info.JobMemoryLimit = memory;
        info
    }

    fn commit(p: &Held, bytes: usize) -> Result<(), i32> {
        // SAFETY: our suspended child; the system chooses the address.
        let at = unsafe { VirtualAllocEx(p.process.as_raw_handle(), std::ptr::null(), bytes, 0x3000, 4) };
        if at.is_null() { Err(last_error().raw_os_error().unwrap_or(0)) } else { Ok(()) }
    }

    fn mask_of(p: &Held) -> usize {
        let (mut own, mut system) = (0usize, 0usize);
        // SAFETY: our child; out-parameters.
        assert_ne!(unsafe { GetProcessAffinityMask(p.process.as_raw_handle(), &mut own, &mut system) }, 0, "{}", last_error());
        own
    }

    /// A process as the jailer starts one of a jail: suspended, in the
    /// parent's job and then in a jail's job with `limits`, by the
    /// jailer's own steps.
    fn jailed(parent: Option<&Parent>, limits: &Limits) -> (Held, OwnedHandle, Result<(), (&'static str, io::Error)>) {
        let (p, job) = (held_process(), super::super::job(limits).unwrap());
        let entered = enter(parent, &job, p.process.as_raw_handle());
        (p, job, entered)
    }

    // The rule a parent cgroup is for: its memory limit bounds the jails
    // under it together. A parent of 64 MiB, two jails whose own limit is
    // 48 MiB each (jobs as the jailer makes them, UI limits and all): 40
    // MiB fits in the first and is refused in the second, which alone
    // would have had the room. The first jailer makes the parent, the
    // second finds it and checks whose it is.
    #[test]
    #[ignore = "makes named jobs and processes: run alone by CI's windows job, with --nocapture"]
    fn test_a_parent_bounds_its_jails_together() {
        let name = fresh("together");
        let with = plan(&name, 2, true, true);
        let first = Parent::of(&with).unwrap().unwrap();
        assert!(first.created, "no job of the name before the first jailer");
        let limit = extended(JOB_OBJECT_LIMIT_JOB_MEMORY, 64 * MIB, 0);
        let set = set_job(&tool(&name), JobObjectExtendedLimitInformation, &limit);
        let second = Parent::of(&with).unwrap().unwrap();
        assert!(!second.created);
        let whose = owner_and_label(second.job());
        println!("PARENTTEST a parent made by one jailer, limited to 64 MiB ({set:?}), found by the next: owner and label {whose:?}");
        assert_eq!(set, Ok(()));

        let jail = Limits { memory_bytes: Some(48 << 20), ..Limits::default() };
        let (pa, _ja, a) = jailed(Some(&first), &jail);
        let (pb, _jb, b) = jailed(Some(&second), &jail);
        let (in_first, in_second) = (commit(&pa, 40 * MIB), commit(&pb, 40 * MIB));
        println!(
            "PARENTTEST two jails of 48 MiB under it (nested: {a:?}, {b:?}): 40 MiB in the first {in_first:?}, in the \
             second {in_second:?} (1455: the commit limit)"
        );
        assert!(a.is_ok() && b.is_ok(), "a jail's job was not nested under its parent");
        assert_eq!(in_first, Ok(()));
        assert!(in_second.is_err(), "the parent's limit did not bound the second jail");

        // With cgroup v2 and no --cgroup the jailer joins a parent that
        // exists and makes none; with v1 and no --cgroup upstream does not
        // read the parent, and no plan is kept (`cgroup`).
        assert!(Parent::of(&plan(&name, 2, true, false)).unwrap().is_some_and(|p| !p.created));
        assert!(Parent::of(&plan(&fresh("none"), 2, true, false)).unwrap().is_none());
        assert!(Parent::of(&plan(&fresh("none"), 2, false, true)).unwrap().is_none(), "the default parent is never made");
    }

    // What keeps a parent: the tool while it runs, and every jailer while
    // its jail lives. With the tool gone and a jailer left, the parent is
    // found by its name with its limit; with neither, it is gone, and the
    // next jail that names it has a new one without limits (stated as the
    // difference from a cgroup directory). The last two are Windows's
    // answers, printed; the first is the jailer's rule, asserted.
    #[test]
    #[ignore = "makes named jobs and processes: run alone by CI's windows job, with --nocapture"]
    fn test_a_parent_lasts_while_a_jail_holds_it() {
        let name = fresh("lasts");
        let with = plan(&name, 2, true, true);
        let read = |job: &OwnedHandle| query::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(job, JobObjectExtendedLimitInformation).map(|i| i.JobMemoryLimit / MIB);
        let operator = tool(&name);
        set_job(&operator, JobObjectExtendedLimitInformation, &extended(JOB_OBJECT_LIMIT_JOB_MEMORY, 64 * MIB, 0)).unwrap();
        let jailer = Parent::of(&with).unwrap().unwrap();
        assert!(!jailer.created);
        let (p, _job, entered) = jailed(Some(&jailer), &Limits::default());
        drop(operator);
        let found = Parent::of(&plan(&name, 2, true, false)).unwrap();
        let limit = found.as_ref().map(|parent| read(parent.job()));
        println!("PARENTTEST the tool gone, a jailer with a jail ({entered:?}) left: found by name {}, its limit {limit:?} MiB", found.is_some());
        entered.unwrap();
        assert!(matches!(limit, Some(Ok(64))), "a jailer's handle did not keep the parent and its limit");
        drop(found);

        // The jailer's handle gone while its process is in the job still
        // (a jailer that was killed): the name.
        drop(jailer);
        let unheld = Parent::of(&plan(&name, 2, true, false)).unwrap().is_some();
        drop(p);
        let again = Parent::of(&with).unwrap().unwrap();
        println!(
            "PARENTTEST no handle left and a process in the job still: found by name {unheld}; after it, the next \
             jailer made a new one: {}, its limit {:?} MiB",
            again.created,
            read(again.job())
        );
    }

    // No narrowing without a word, and Linux's rules by cgroup version: a
    // parent on processor 0, a jail that asks for processor 1 or for 0 and
    // 1. cgroup v1 refuses both (EACCES on Linux); v2 runs the jail on
    // what the two have in common, or on the parent's. A parent capped at
    // half the host: a jail that asks for a quarter gets half of the
    // parent's, one that asks for three quarters is refused by v1 (EINVAL)
    // and gets all of the parent's by v2.
    #[test]
    #[ignore = "makes named jobs and processes: run alone by CI's windows job, with --nocapture"]
    fn test_a_jail_under_a_parent_has_linuxs_cpus_and_rate() {
        use super::super::cgroup_values::{CPUS_OUTSIDE_PARENT, RATE_ABOVE_PARENT};
        let name = fresh("cpus");
        let operator = tool(&name);
        let parent = |version| Parent::of(&plan(&name, version, true, true)).unwrap().unwrap();
        let asking = |cpus: Option<Vec<(u16, u64)>>, cpu_rate| Limits { cpus, cpu_rate, ..Limits::default() };

        // A parent without limits of its own: what Windows reports for it,
        // and a jail's values are its own.
        let (rate, cpus) = (hard_cap(&operator), processors(&operator));
        println!("PARENTTEST a parent without limits: CPU rate {rate:?}, processors {cpus:x?}");
        assert!(matches!(rate, Ok(None)), "a job without a rate reads as one with a hard cap, or not at all");
        let asked = asking(Some(vec![(0, 0b1)]), Some(2500));
        for version in [1, 2] {
            assert_eq!(parent(version).limits(&asked).unwrap(), asked, "cgroup v{version}, a parent without limits");
        }

        if std::thread::available_parallelism().map_or(1, std::num::NonZero::get) >= 2 {
            set_job(&operator, JobObjectExtendedLimitInformation, &extended(JOB_OBJECT_LIMIT_AFFINITY, 0, 0b01)).unwrap();
            assert_eq!(processors(&operator).unwrap(), Some(vec![(0, 0b01)]));
            for (cpus, v2) in [(0b10u64, 0b01u64), (0b11, 0b01), (0b01, 0b01)] {
                let asked = asking(Some(vec![(0, cpus)]), None);
                let v1 = parent(1).limits(&asked);
                let under = parent(2);
                let given = under.limits(&asked).unwrap();
                let (p, _job, entered) = jailed(Some(&under), &given);
                println!(
                    "PARENTTEST a parent on processor 0, a jail that asks for mask {cpus:#b}: cgroup v1 {:?}; v2 is given \
                     {:x?} (nested {entered:?}) and its process runs on mask {:#b}",
                    v1.as_ref().map(|l| l.cpus.clone()).map_err(ToString::to_string),
                    given.cpus,
                    mask_of(&p)
                );
                if cpus == 0b01 {
                    assert_eq!(v1.unwrap().cpus, Some(vec![(0, 0b01)]));
                } else {
                    assert!(v1.unwrap_err().to_string().ends_with(CPUS_OUTSIDE_PARENT));
                }
                assert_eq!(given.cpus, Some(vec![(0, v2)]));
                entered.unwrap();
                assert_eq!(mask_of(&p), usize::try_from(v2).unwrap(), "the jail's process is not on the processors it was given");
            }
            // A jail that asks for no processors has the parent's.
            let (p, _job, entered) = jailed(Some(&parent(2)), &Limits::default());
            entered.unwrap();
            assert_eq!(mask_of(&p), 0b01);
        } else {
            println!("PARENTTEST processors: one processor, not run");
        }

        // SAFETY: plain data.
        let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.Anonymous.CpuRate = 5000;
        set_job(&operator, JobObjectCpuRateControlInformation, &cpu).unwrap();
        assert_eq!(hard_cap(&operator).unwrap(), Some(5000));
        let quarter = parent(1).limits(&asking(None, Some(2500))).unwrap();
        assert_eq!(quarter.cpu_rate, Some(5000), "a quarter of the host is half of a parent of half");
        assert_eq!(parent(2).limits(&asking(None, Some(2500))).unwrap().cpu_rate, Some(5000));
        assert!(parent(1).limits(&asking(None, Some(7500))).unwrap_err().to_string().ends_with(RATE_ABOVE_PARENT));
        assert_eq!(parent(2).limits(&asking(None, Some(7500))).unwrap().cpu_rate, Some(10_000));
        let under = parent(2);
        let (_p, job, entered) = jailed(Some(&under), &quarter);
        println!(
            "PARENTTEST a parent capped at 5000, a jail that asks for 2500 of the host: its job is given {:?} of the \
             parent's (nested {entered:?}) and reads back {:?}",
            quarter.cpu_rate,
            hard_cap(&job)
        );
        entered.unwrap();
        assert_eq!(hard_cap(&job).unwrap(), Some(5000));
    }

    // A parent of two levels, as upstream's own test names one: a job for
    // each, and every level's limits hold what is under it. Memory, the
    // least limit along the path: the top at 64 MiB and the level under it
    // at 32, a jail under both is refused 40 MiB that the top alone would
    // have given, and takes 24; a jail under the top alone is then refused
    // 48 (24 and 48 are above 64) and takes 32. The CPU rate: the top at
    // half the host and the level under it asked for a quarter of the host,
    // which is half of the top's; the two come to a quarter of the host, a
    // jail that asks for an eighth is given half of the level's, and cgroup
    // v1 refuses one that asks for more than the quarter. Processors: the
    // top on 0 and 1, the level under it on 1; a jail that asks for 0 is
    // refused by cgroup v1 and runs on 1 with v2.
    #[test]
    #[ignore = "makes named jobs and processes: run alone by CI's windows job, with --nocapture"]
    fn test_a_parent_of_several_levels_bounds_by_each() {
        use super::super::cgroup_values::{CPUS_OUTSIDE_PARENT, RATE_ABOVE_PARENT};
        let top = fresh("levels");
        let both = format!("{top}/group2");
        // The jailer makes every level that is missing, the top first.
        let under_both = Parent::of(&plan(&both, 2, true, true)).unwrap().unwrap();
        assert!(under_both.created && under_both.jobs.len() == 2);
        let under_top = Parent::of(&plan(&top, 2, true, false)).unwrap().unwrap();
        assert!(!under_top.created, "the top level was not made with the level under it");
        let (first, second) = (tool(&top), tool(&both));
        let set = (
            set_job(&first, JobObjectExtendedLimitInformation, &extended(JOB_OBJECT_LIMIT_JOB_MEMORY, 64 * MIB, 0)),
            set_job(&second, JobObjectExtendedLimitInformation, &extended(JOB_OBJECT_LIMIT_JOB_MEMORY, 32 * MIB, 0)),
        );
        let (pa, _ja, a) = jailed(Some(&under_both), &Limits::default());
        let (pb, _jb, b) = jailed(Some(&under_top), &Limits::default());
        let low = (commit(&pa, 40 * MIB), commit(&pa, 24 * MIB));
        let high = (commit(&pb, 48 * MIB), commit(&pb, 32 * MIB));
        println!(
            "PARENTTEST two levels, 64 MiB and under it 32 MiB ({set:?}): a jail under both (nested {a:?}) 40 MiB, then \
             24: {low:?}; a jail under the top alone (nested {b:?}) 48 MiB, then 32: {high:?}"
        );
        assert_eq!(set, (Ok(()), Ok(())));
        assert!(a.is_ok() && b.is_ok(), "a jail's job was not nested under every level of its parent");
        assert!(low.0.is_err() && low.1.is_ok(), "the lower level's limit did not hold: {low:?}");
        assert!(high.0.is_err() && high.1.is_ok(), "the top level's limit did not hold the two together: {high:?}");
        drop((pa, pb));

        // The CPU rate, as the operator's tool writes a level's: a share of
        // what the levels above come to.
        // SAFETY: plain data.
        let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.Anonymous.CpuRate = 5000;
        let top_rate = set_job(&first, JobObjectCpuRateControlInformation, &cpu);
        cpu.Anonymous.CpuRate = rate_under_parent(2, 2500, 5000).unwrap();
        let level_rate = set_job(&second, JobObjectCpuRateControlInformation, &cpu);
        let asking = |cpus: Option<Vec<(u16, u64)>>, cpu_rate| Limits { cpus, cpu_rate, ..Limits::default() };
        let parent = |version| Parent::of(&plan(&both, version, true, true)).unwrap().unwrap();
        let eighth = parent(1).limits(&asking(None, Some(1250)));
        let (_p, job, entered) = jailed(Some(&under_both), eighth.as_ref().unwrap_or(&Limits::default()));
        println!(
            "PARENTTEST two levels capped at 5000 ({top_rate:?}) and, for a quarter of the host, 5000 of that \
             ({level_rate:?}): a jail that asks for 1250 of the host is given {:?} (nested {entered:?}) and reads back {:?}",
            eighth.as_ref().map(|l| l.cpu_rate).map_err(ToString::to_string),
            hard_cap(&job)
        );
        assert_eq!((top_rate, level_rate), (Ok(()), Ok(())));
        assert_eq!(eighth.unwrap().cpu_rate, Some(5000), "an eighth of the host is half of two levels that come to a quarter");
        entered.unwrap();
        assert!(parent(1).limits(&asking(None, Some(4000))).unwrap_err().to_string().ends_with(RATE_ABOVE_PARENT));
        assert_eq!(parent(2).limits(&asking(None, Some(4000))).unwrap().cpu_rate, Some(10_000));

        if std::thread::available_parallelism().map_or(1, std::num::NonZero::get) >= 2 {
            set_job(&first, JobObjectExtendedLimitInformation, &extended(JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_AFFINITY, 64 * MIB, 0b11))
                .unwrap();
            set_job(&second, JobObjectExtendedLimitInformation, &extended(JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_AFFINITY, 32 * MIB, 0b10))
                .unwrap();
            let asked = asking(Some(vec![(0, 0b01)]), None);
            let v1 = parent(1).limits(&asked);
            let given = parent(2).limits(&asked).unwrap();
            let (p, _job, entered) = jailed(Some(&under_both), &given);
            println!(
                "PARENTTEST two levels on processors 0-1 and 1, a jail that asks for processor 0: cgroup v1 {:?}; v2 is \
                 given {:x?} (nested {entered:?}) and its process runs on mask {:#b}",
                v1.as_ref().map(|l| l.cpus.clone()).map_err(ToString::to_string),
                given.cpus,
                mask_of(&p)
            );
            assert!(v1.unwrap_err().to_string().ends_with(CPUS_OUTSIDE_PARENT));
            assert_eq!(given.cpus, Some(vec![(0, 0b10)]));
            entered.unwrap();
            assert_eq!(mask_of(&p), 0b10);
        } else {
            println!("PARENTTEST levels' processors: one processor, not run");
        }

        // A level that exists under one that does not is no tree: a jailer
        // that would join it stops.
        let orphan = fresh("orphan");
        let lower = create_or_open(&parent_job_names(&format!("{orphan}/x")).unwrap()[1]).unwrap().0;
        let refused = Parent::of(&plan(&format!("{orphan}/x"), 2, true, false)).unwrap_err().to_string();
        println!("PARENTTEST a level whose level above has no job: {refused}");
        assert!(refused.contains("above it, does not"), "{refused}");
        drop(lower);
    }

    // A job of the parent's name that a jailed process could have made (it
    // carries that process's integrity level, below medium) is not joined:
    // the jailer stops, with the reason.
    #[test]
    #[ignore = "makes named jobs and processes: run alone by CI's windows job, with --nocapture"]
    fn test_a_parent_made_below_medium_integrity_is_refused() {
        let name = fresh("label");
        let squatted = tool(&name);
        let before = owner_and_label(&squatted);
        let labelled = super::super::set_security_of(squatted.as_raw_handle(), "S:(ML;;NW;;;S-1-16-6144)", true);
        let after = owner_and_label(&squatted);
        println!("PARENTTEST a job as this process makes it: owner and label {before:?}; labelled as a jail's ({labelled:?}): {after:?}");
        labelled.unwrap();
        assert!(matches!(before, Ok((_, None | Some(0x2000..)))), "a new job of this process is below medium integrity");
        assert_eq!(after.unwrap().1, Some(0x1800));
        for with_cgroup in [true, false] {
            let refused = Parent::of(&plan(&name, 2, true, with_cgroup)).unwrap_err().to_string();
            assert!(refused.contains("integrity level 0x1800, below medium"), "{refused}");
            assert!(refused.starts_with(&format!("--parent-cgroup {name:?}: ")), "{refused}");
        }
    }
}
